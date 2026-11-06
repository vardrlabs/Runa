//! Removing someone from a room and changing its link (PROTOCOL.md
//! amendment K).
//!
//! The clear part of an EVICT_COMMIT is the only payload past a header the
//! server reads, apart from SNAPSHOT's index. It is a fixed binary layout so
//! the server needs no CBOR parser, and the tail after it is never read.
//! Everything here is pure, so it is unit-tested and fuzzed; the room applies
//! the result under its locks (`Room::commit_eviction`).

use std::collections::HashSet;

use sha2::{Digest, Sha256};

pub const STATEMENT_DOMAIN: &[u8] = b"runa/v1/evict";
pub const MAX_VOTES: usize = 32;
pub const SIG_LEN: usize = 64;
const NO_PEER: [u8; 16] = [0; 16];
const NO_KEY: [u8; 32] = [0; 32];
/// The clear part's fixed fields: ids, the target's key digest, verifier,
/// salt, the config length and the vote count.
const FIXED_LEN: usize = 16 + 16 + 32 + 32 + 16 + 4 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub voter: [u8; 16],
    pub sig: [u8; SIG_LEN],
}

/// Who a commit removes. The server learns peer ids, and a person can hold
/// several connections under one signing key, so the votes name the key too:
/// "the target" is the named connection and every other connection holding
/// that key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub peer_id: [u8; 16],
    /// SHA-256 of the target's signing key, as raw bytes exactly as it sent
    /// them in its JOIN (32 for Ed25519, 65 for uncompressed P-256).
    pub key_digest: [u8; 32],
}

impl Target {
    /// Whether a connection is the target: the one named, or any other
    /// holding the same signing key.
    pub fn covers(&self, peer_id: &[u8; 16], pubkey: Option<&[u8]>) -> bool {
        *peer_id == self.peer_id || pubkey.is_some_and(|k| key_digest(k) == self.key_digest)
    }
}

/// SHA-256 of a signing key's raw bytes: how a vote names the target's key.
pub fn key_digest(pubkey: &[u8]) -> [u8; 32] {
    Sha256::digest(pubkey).into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitClear<'a> {
    pub request_id: [u8; 16],
    /// None when the commit only changes the link.
    pub target: Option<Target>,
    pub new_verifier: [u8; 32],
    pub new_salt: [u8; 16],
    pub config_blob: &'a [u8],
    pub votes: Vec<Vote>,
    /// The members' wraps, for them alone. Never read here.
    pub tail: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    /// One of the target's peer id and key digest is all zero and the other
    /// is not. Both are zero for a link change and neither is otherwise.
    MalformedTarget,
    NoVotes,
    TooManyVotes,
    BadSignatureLength,
    NoTail,
}

/// Why the room refused a commit. Every refusal is silent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The votes were signed for an epoch the room is not at.
    WrongEpoch,
    /// The room is at `u32::MAX` and cannot move.
    LastEpoch,
    /// The commit's sender is not one of its voters. Checked by the room,
    /// which knows the sender: the person being removed sees every vote go by
    /// and could otherwise send a commit with no wraps, moving the room to a
    /// way in nobody was given.
    SenderNotVoter,
    /// The sender has no EVICT_REQUEST on record within the last hour (and a
    /// minute for the commit), so there is no cohort to count against.
    /// Checked by the room.
    NoOpenRequest,
    NoVotes,
    /// The named connection is still connected but holds a different signing
    /// key from the one the votes name, or none. Honest voters check the
    /// key against their roster, so this commit was not made by them.
    TargetKeyMismatch,
    /// A voter is the named connection or holds the target's signing key.
    TargetVoted,
    DuplicateVoter,
    VoterAbsent,
    /// The voter's connection holds a different signing key from the one its
    /// signature was checked against.
    VoterKeyChanged,
    /// The voter joined after the request was relayed, so it was not one of
    /// the people the request was put to.
    VoterAfterRequest,
    BelowFloor,
}

/// A connected peer as the decision sees it.
pub struct PeerView<'a> {
    pub peer_id: [u8; 16],
    pub pubkey: Option<&'a [u8]>,
    pub joined_at_seq: u64,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.0.len() < n {
            return Err(ParseError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

/// `id (16) || target (16) || target key digest (32) || verifier (32)
/// || salt (16) || config_len (u32 BE) || config || n (u8)
/// || n * (voter (16) || sig_len (u8) || sig) || tail`.
pub fn parse_commit(body: &[u8]) -> Result<CommitClear<'_>, ParseError> {
    let mut r = Reader(body);
    let request_id = r.array::<16>()?;
    let target_peer = r.array::<16>()?;
    let target_key = r.array::<32>()?;
    let target = match (target_peer == NO_PEER, target_key == NO_KEY) {
        (true, true) => None,
        (false, false) => Some(Target { peer_id: target_peer, key_digest: target_key }),
        _ => return Err(ParseError::MalformedTarget),
    };
    let new_verifier = r.array::<32>()?;
    let new_salt = r.array::<16>()?;
    let config_len = u32::from_be_bytes(r.array::<4>()?) as usize;
    let config_blob = r.take(config_len)?;
    let [n] = r.array::<1>()?;
    let n = usize::from(n);
    if n == 0 {
        return Err(ParseError::NoVotes);
    }
    if n > MAX_VOTES {
        return Err(ParseError::TooManyVotes);
    }
    let mut votes = Vec::with_capacity(n);
    for _ in 0..n {
        let voter = r.array::<16>()?;
        let [len] = r.array::<1>()?;
        if usize::from(len) != SIG_LEN {
            return Err(ParseError::BadSignatureLength);
        }
        let sig = r.array::<SIG_LEN>()?;
        votes.push(Vote { voter, sig });
    }
    if r.0.is_empty() {
        return Err(ParseError::NoTail);
    }
    Ok(CommitClear { request_id, target, new_verifier, new_salt, config_blob, votes, tail: r.0 })
}

/// The clear part's bytes exactly as `parse_commit` reads them, without the
/// tail. Used by tests and the fuzz target, always with a config and a vote
/// count that `parse_commit` produced or that fit their length fields.
pub fn encode_clear(c: &CommitClear<'_>) -> Vec<u8> {
    debug_assert!(u32::try_from(c.config_blob.len()).is_ok(), "a config length is a u32");
    debug_assert!(u8::try_from(c.votes.len()).is_ok(), "a vote count is a u8");
    let mut out = Vec::with_capacity(FIXED_LEN + c.config_blob.len() + c.votes.len() * (16 + 1 + SIG_LEN));
    out.extend_from_slice(&c.request_id);
    out.extend_from_slice(c.target.as_ref().map_or(&NO_PEER, |t| &t.peer_id));
    out.extend_from_slice(c.target.as_ref().map_or(&NO_KEY, |t| &t.key_digest));
    out.extend_from_slice(&c.new_verifier);
    out.extend_from_slice(&c.new_salt);
    out.extend_from_slice(&(c.config_blob.len() as u32).to_be_bytes());
    out.extend_from_slice(c.config_blob);
    out.push(c.votes.len() as u8);
    for v in &c.votes {
        out.extend_from_slice(&v.voter);
        out.push(SIG_LEN as u8);
        out.extend_from_slice(&v.sig);
    }
    out
}

/// What every vote signs:
/// `"runa/v1/evict" || room_id || request_id || epoch (u32 BE) || target
/// peer id || target key digest || voter || new_verifier`, with the target's
/// two fields all zero for a link change.
///
/// The new verifier is inside it, so a commit cannot swap in a different way
/// into the room after people voted; the epoch is, so a vote cannot be
/// replayed after any rotation; and the target's key digest is, so the
/// server can recognise every connection the target holds.
pub fn statement(
    room_id: &[u8; 16],
    request_id: &[u8; 16],
    epoch: u32,
    target: Option<&Target>,
    voter: &[u8; 16],
    new_verifier: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(STATEMENT_DOMAIN.len() + 132);
    m.extend_from_slice(STATEMENT_DOMAIN);
    m.extend_from_slice(room_id);
    m.extend_from_slice(request_id);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(target.map_or(&NO_PEER, |t| &t.peer_id));
    m.extend_from_slice(target.map_or(&NO_KEY, |t| &t.key_digest));
    m.extend_from_slice(voter);
    m.extend_from_slice(new_verifier);
    m
}

/// A vote's signature under the signing key its voter joined with: 32 bytes
/// is Ed25519, checked strictly; 65 is an uncompressed P-256 point, with the
/// signature in WebCrypto's r||s form over SHA-256. A high s is accepted:
/// WebCrypto does not normalise it, so half of honest P-256 votes have one.
pub fn verify_vote(pubkey: &[u8], message: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    match pubkey.len() {
        32 => {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(pubkey);
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&raw) else {
                return false;
            };
            key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()
        }
        65 => {
            use p256::ecdsa::signature::Verifier;
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey) else {
                return false;
            };
            let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            // Normalised first, so acceptance does not depend on whether the
            // verifier itself tolerates a high s.
            let sig = sig.normalize_s();
            key.verify(message, &sig).is_ok()
        }
        _ => false,
    }
}

/// The room's rules for a commit whose signatures have already been checked
/// against `voters`' keys. `peers` is everyone connected, read under the same
/// lock that applies the result.
///
/// Only the cohort counts: peers that joined before the sender's request was
/// relayed (`joined_at_seq < since`), as amendment A's purge cohort does for
/// a shred. Connections opened after a vote started can neither vote nor
/// hold the floor down. The target is every connection `Target::covers`: the
/// named one and any other holding the signing key the votes name. None of
/// them may vote, and none counts toward the floor, which is more than half
/// of the rest of the cohort. A target with no connection left leaves the
/// whole cohort in the floor.
pub fn decide(
    target: Option<Target>,
    voters: &[([u8; 16], Vec<u8>)],
    peers: &[PeerView<'_>],
    since: u64,
) -> Result<(), Refusal> {
    if voters.is_empty() {
        return Err(Refusal::NoVotes);
    }
    // A named target that is no longer connected is not a refusal: the room
    // re-roots anyway, and a connection the target opens again is never
    // wrapped, so reconnecting does not dodge the removal. One that is still
    // connected must hold the key the votes name.
    if let Some(t) = target {
        if let Some(named) = peers.iter().find(|p| p.peer_id == t.peer_id) {
            if named.pubkey.map(key_digest) != Some(t.key_digest) {
                return Err(Refusal::TargetKeyMismatch);
            }
        }
    }
    let mut seen = HashSet::with_capacity(voters.len());
    for (voter, key) in voters {
        if target.is_some_and(|t| t.covers(voter, Some(key))) {
            return Err(Refusal::TargetVoted);
        }
        if !seen.insert(*voter) {
            return Err(Refusal::DuplicateVoter);
        }
        let Some(p) = peers.iter().find(|p| p.peer_id == *voter) else {
            return Err(Refusal::VoterAbsent);
        };
        if p.pubkey != Some(key.as_slice()) {
            return Err(Refusal::VoterKeyChanged);
        }
        if p.joined_at_seq >= since {
            return Err(Refusal::VoterAfterRequest);
        }
    }
    let others = peers
        .iter()
        .filter(|p| p.joined_at_seq < since && !target.is_some_and(|t| t.covers(&p.peer_id, p.pubkey)))
        .count();
    if voters.len() * 2 <= others {
        return Err(Refusal::BelowFloor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn seq<const N: usize>(start: u8) -> [u8; N] {
        let mut a = [0u8; N];
        for (i, b) in a.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        a
    }

    fn sig(s: &str) -> [u8; 64] {
        h(s).try_into().unwrap()
    }

    // Known answers computed independently with node:crypto (SHA-256 of the
    // target key, Ed25519 from the fixed seed 01..20, ECDSA P-256 from the
    // fixed scalar 21..40), not by the crates that verify them here.
    // `node web/scripts/kat-evict.mjs` (Task 5) must print these same values;
    // the client's statement test pins the same bytes. The P-256 signature
    // came from one run (its nonce is random); the high-S form is n - s.
    /// SHA-256 of the target's key, 32 bytes of 0x33.
    const TARGET_KEY_DIGEST: &str = "deb0e38ced1e41de6f92e70e80c418d2d356afaaa99e26f5939dbc7d3ef4772a";
    /// SHA-256 of `P256_PUB`, the 65-byte form a P-256 key is digested in.
    const P256_PUB_DIGEST: &str = "f6140efc538823718229c03b61bdac222543e69b5d0cba12d9dcf917284fa5a6";
    const STATEMENT: &str = "72756e612f76312f6576696374b0b1b2b3b4b5b6b7b8b9babbbcbdbebf606162636465666768696a6b6c6d6e6f0000000733333333333333333333333333333333deb0e38ced1e41de6f92e70e80c418d2d356afaaa99e26f5939dbc7d3ef4772a11111111111111111111111111111111808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const LINK_STATEMENT: &str = "72756e612f76312f6576696374b0b1b2b3b4b5b6b7b8b9babbbcbdbebf606162636465666768696a6b6c6d6e6f0000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const ED_PUB: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const ED_SIG: &str = "1cc9f86534d1255a8df79323d67a68df723a4279c2240f8a7f7b6155d24fd5f3ba59b38c9665af59cd4444b9b89929cf58634bff02b722ceae49a3c205a42009";
    const P256_PUB: &str = "041f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9eec995a08b1fa7704df3dcc0b50a9665263fb7711f95f9f8a449c5096e47c892b";
    const P256_SIG_LOW_S: &str = "e84ef5f1c8cd99840b9c8864c5e0ac0e10b232cdc9b49abf20ffd5d11205b51307f48ce4e9de0b948dadcfe582ea3a049347428a59f0303dd3713ffc978a57e1";
    /// The same signature with s replaced by n - s.
    const P256_SIG_HIGH_S: &str = "e84ef5f1c8cd99840b9c8864c5e0ac0e10b232cdc9b49abf20ffd5d11205b513f80b731a1621f46c7252301a7d15c5fb299fb8234d276e4720488ac664d8cd70";

    fn kat_target() -> Target {
        Target { peer_id: [0x33; 16], key_digest: key_digest(&[0x33; 32]) }
    }

    fn kat_statement() -> Vec<u8> {
        statement(&seq::<16>(0xb0), &seq::<16>(0x60), 7, Some(&kat_target()), &[0x11; 16], &seq::<32>(0x80))
    }

    #[test]
    fn a_key_digest_is_sha256_of_the_raw_key() {
        assert_eq!(hex::encode(key_digest(&[0x33; 32])), TARGET_KEY_DIGEST);
        assert_eq!(hex::encode(key_digest(&h(P256_PUB))), P256_PUB_DIGEST);
    }

    #[test]
    fn the_statement_is_the_fixed_layout() {
        assert_eq!(hex::encode(kat_statement()), STATEMENT);
        assert_eq!(kat_statement().len(), 145);
    }

    #[test]
    fn a_link_change_names_no_peer_and_no_key() {
        let s = statement(&seq::<16>(0xb0), &seq::<16>(0x60), 7, None, &[0x11; 16], &seq::<32>(0x80));
        assert_eq!(hex::encode(&s), LINK_STATEMENT);
        assert_eq!(&s[49..97], &[0u8; 48]);
        assert_eq!(s.len(), 145);
    }

    #[test]
    fn an_ed25519_vote_made_elsewhere_verifies_strictly() {
        assert!(verify_vote(&h(ED_PUB), &kat_statement(), &sig(ED_SIG)));
        let mut bad = sig(ED_SIG);
        bad[0] ^= 1;
        assert!(!verify_vote(&h(ED_PUB), &kat_statement(), &bad));
        let mut other = kat_statement();
        other[20] ^= 1;
        assert!(!verify_vote(&h(ED_PUB), &other, &sig(ED_SIG)));
        // A vote names the target's key: another key, same peer id, fails.
        let mut other_key = kat_statement();
        other_key[70] ^= 1;
        assert!(!verify_vote(&h(ED_PUB), &other_key, &sig(ED_SIG)));
    }

    #[test]
    fn a_p256_vote_verifies_whichever_s_it_carries() {
        // WebCrypto never normalises s, so about half of real votes are high-S.
        assert!(verify_vote(&h(P256_PUB), &kat_statement(), &sig(P256_SIG_LOW_S)));
        assert!(verify_vote(&h(P256_PUB), &kat_statement(), &sig(P256_SIG_HIGH_S)));
        let mut bad = sig(P256_SIG_LOW_S);
        bad[40] ^= 1;
        assert!(!verify_vote(&h(P256_PUB), &kat_statement(), &bad));
    }

    #[test]
    fn keys_of_any_other_shape_never_verify_and_never_panic() {
        for len in [0usize, 31, 33, 64, 66] {
            assert!(!verify_vote(&vec![4u8; len], b"x", &[0u8; 64]));
        }
        assert!(!verify_vote(&[0u8; 32], b"x", &[0u8; 64]));
        let mut not_on_curve = vec![0x04u8; 65];
        not_on_curve[1] = 0xff;
        assert!(!verify_vote(&not_on_curve, b"x", &[1u8; 64]));
    }

    fn sample(tail: &[u8]) -> Vec<u8> {
        let c = CommitClear {
            request_id: [1; 16],
            target: Some(Target { peer_id: [2; 16], key_digest: [9; 32] }),
            new_verifier: [3; 32],
            new_salt: [4; 16],
            config_blob: b"cfg",
            votes: vec![Vote { voter: [5; 16], sig: [6; 64] }, Vote { voter: [7; 16], sig: [8; 64] }],
            tail: &[],
        };
        let mut b = encode_clear(&c);
        b.extend_from_slice(tail);
        b
    }

    /// Offsets in `sample`: 112 bytes of ids, the target's key digest,
    /// verifier and salt, then the 4-byte length, 3 bytes of config, and the
    /// vote count.
    const CONFIG_LEN_AT: usize = 112;
    const COUNT_AT: usize = 119;

    #[test]
    fn a_commit_round_trips_and_its_tail_is_left_alone() {
        let b = sample(b"opaque");
        let c = parse_commit(&b).unwrap();
        assert_eq!(c.request_id, [1; 16]);
        assert_eq!(c.target, Some(Target { peer_id: [2; 16], key_digest: [9; 32] }));
        assert_eq!(c.new_verifier, [3; 32]);
        assert_eq!(c.new_salt, [4; 16]);
        assert_eq!(c.config_blob, b"cfg");
        assert_eq!(c.votes.len(), 2);
        assert_eq!(c.votes[1], Vote { voter: [7; 16], sig: [8; 64] });
        assert_eq!(c.tail, b"opaque");
        let mut again = encode_clear(&c);
        again.extend_from_slice(c.tail);
        assert_eq!(again, b);
    }

    #[test]
    fn a_zero_target_is_a_link_change() {
        let mut b = sample(b"t");
        b[16..64].copy_from_slice(&[0; 48]);
        assert_eq!(parse_commit(&b).unwrap().target, None);
    }

    #[test]
    fn a_target_is_named_by_both_its_peer_id_and_its_key_or_by_neither() {
        let mut no_key = sample(b"t");
        no_key[32..64].copy_from_slice(&[0; 32]);
        assert_eq!(parse_commit(&no_key), Err(ParseError::MalformedTarget));
        let mut no_peer = sample(b"t");
        no_peer[16..32].copy_from_slice(&[0; 16]);
        assert_eq!(parse_commit(&no_peer), Err(ParseError::MalformedTarget));
    }

    #[test]
    fn every_truncation_is_refused() {
        let b = sample(b"t");
        let clear = b.len() - 1;
        for n in 0..clear {
            assert!(parse_commit(&b[..n]).is_err(), "accepted {n} bytes");
        }
        assert_eq!(parse_commit(&b[..clear]), Err(ParseError::NoTail));
    }

    #[test]
    fn a_commit_carries_one_to_thirty_two_votes() {
        let mut none = sample(b"t")[..COUNT_AT].to_vec();
        none.push(0);
        none.extend_from_slice(b"t");
        assert_eq!(parse_commit(&none), Err(ParseError::NoVotes));
        let mut many = sample(b"t")[..COUNT_AT].to_vec();
        many.push(33);
        many.extend_from_slice(&[0u8; 33 * 81]);
        many.extend_from_slice(b"t");
        assert_eq!(parse_commit(&many), Err(ParseError::TooManyVotes));
    }

    #[test]
    fn a_signature_is_sixty_four_bytes() {
        let mut b = sample(b"t");
        b[COUNT_AT + 1 + 16] = 63;
        assert_eq!(parse_commit(&b), Err(ParseError::BadSignatureLength));
    }

    #[test]
    fn a_config_length_past_the_end_is_truncated() {
        let mut b = sample(b"t");
        b[CONFIG_LEN_AT..CONFIG_LEN_AT + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_commit(&b), Err(ParseError::Truncated));
    }

    /// Voter n, holding the key peer n has in `room` by default.
    fn v(n: u8) -> ([u8; 16], Vec<u8>) {
        ([n; 16], vec![n; 32])
    }

    /// Peer n named as the target, holding the key it has by default.
    fn t(n: u8) -> Option<Target> {
        Some(Target { peer_id: [n; 16], key_digest: key_digest(&[n; 32]) })
    }

    /// Peer n has id [n; 16], key keys[n - 1] and join sequence number n.
    fn room(keys: &[Vec<u8>]) -> Vec<PeerView<'_>> {
        keys.iter()
            .enumerate()
            .map(|(i, k)| PeerView { peer_id: [i as u8 + 1; 16], pubkey: Some(k.as_slice()), joined_at_seq: i as u64 + 1 })
            .collect()
    }

    /// A request relayed after everyone in these rooms joined.
    const ALL: u64 = u64::MAX;

    #[test]
    fn everyone_else_signing_removes_the_target() {
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        assert_eq!(decide(t(3), &[v(1), v(2)], &room(&keys), ALL), Ok(()));
    }

    #[test]
    fn only_people_there_when_the_request_was_relayed_vote_or_count() {
        // Five connected; the request was relayed when the next peer would
        // have been number 4, so peers 4 and 5 arrived after it.
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32], vec![4u8; 32], vec![5u8; 32]];
        let p = room(&keys);
        // Of the cohort {1, 2, 3}, the target 3 is left out: 1 and 2 are all.
        assert_eq!(decide(t(3), &[v(1), v(2)], &p, 4), Ok(()));
        // Counted against all five, two of four others would not be enough.
        assert_eq!(decide(t(3), &[v(1), v(2)], &p, ALL), Err(Refusal::BelowFloor));
        // A late arrival's signature does not count, so it cannot pad the vote.
        assert_eq!(decide(t(3), &[v(1), v(4)], &p, 4), Err(Refusal::VoterAfterRequest));
    }

    #[test]
    fn each_rule_has_its_refusal() {
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32], vec![4u8; 32]];
        let p = room(&keys);
        assert_eq!(decide(t(4), &[], &p, ALL), Err(Refusal::NoVotes));
        assert_eq!(decide(t(4), &[v(1), v(4)], &p, ALL), Err(Refusal::TargetVoted));
        assert_eq!(decide(t(4), &[v(1), v(1), v(2)], &p, ALL), Err(Refusal::DuplicateVoter));
        assert_eq!(decide(t(4), &[v(1), v(9)], &p, ALL), Err(Refusal::VoterAbsent));
        assert_eq!(decide(t(4), &[v(1), ([2; 16], vec![7; 32])], &p, ALL), Err(Refusal::VoterKeyChanged));
        // Three others; one signature is not more than half of them.
        assert_eq!(decide(t(4), &[v(1)], &p, ALL), Err(Refusal::BelowFloor));
        assert_eq!(decide(t(4), &[v(1), v(2)], &p, ALL), Ok(()));
    }

    #[test]
    fn the_targets_older_connection_does_not_hold_the_floor_down() {
        // A room of two: A, and the target T (peer 3), which also left an
        // older connection T0 (peer 2) open under the same signing key. T0 is
        // in the cohort, but it is the target too, so A alone is the floor.
        let keys = vec![vec![1u8; 32], vec![3u8; 32], vec![3u8; 32]];
        let p = room(&keys);
        assert_eq!(decide(t(3), &[v(1)], &p, ALL), Ok(()));
        // Naming the older connection instead changes nothing.
        let t0 = Some(Target { peer_id: [2; 16], key_digest: key_digest(&[3; 32]) });
        assert_eq!(decide(t0, &[v(1)], &p, ALL), Ok(()));
    }

    #[test]
    fn a_connection_holding_the_target_key_cannot_vote() {
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32], vec![3u8; 32]];
        let p = room(&keys);
        // Peer 4 holds the key of peer 3, the one named.
        assert_eq!(decide(t(3), &[v(1), v(2), ([4; 16], vec![3; 32])], &p, ALL), Err(Refusal::TargetVoted));
        assert_eq!(decide(t(3), &[v(1), v(2)], &p, ALL), Ok(()));
    }

    #[test]
    fn a_target_whose_named_connection_has_gone_is_still_known_by_its_key() {
        // A, and a connection holding the target's key; the one the votes
        // named has gone.
        let keys = vec![vec![1u8; 32], vec![3u8; 32]];
        let p = room(&keys);
        let gone = Some(Target { peer_id: [9; 16], key_digest: key_digest(&[3; 32]) });
        // Counted, the sibling would make A's one vote half of two.
        assert_eq!(decide(gone, &[v(1)], &p, ALL), Ok(()));
        assert_eq!(decide(gone, &[v(1), ([2; 16], vec![3; 32])], &p, ALL), Err(Refusal::TargetVoted));
    }

    #[test]
    fn a_named_target_still_here_must_hold_the_key_the_votes_name() {
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let p = room(&keys);
        let wrong = Some(Target { peer_id: [3; 16], key_digest: key_digest(&[8; 32]) });
        assert_eq!(decide(wrong, &[v(1), v(2)], &p, ALL), Err(Refusal::TargetKeyMismatch));
        let keyless = vec![
            PeerView { peer_id: [1; 16], pubkey: Some(&keys[0]), joined_at_seq: 1 },
            PeerView { peer_id: [3; 16], pubkey: None, joined_at_seq: 2 },
        ];
        assert_eq!(decide(t(3), &[v(1)], &keyless, ALL), Err(Refusal::TargetKeyMismatch));
    }

    #[test]
    fn a_target_who_has_gone_does_not_stop_the_commit() {
        // Decided 2026-11-06: the room re-roots whether or not the target is
        // still connected, so reconnecting under a new peer id dodges nothing.
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let p = room(&keys);
        assert_eq!(decide(t(9), &[v(1), v(2), v(3)], &p, ALL), Ok(()));
        // With no connection holding the target's key, the whole cohort
        // counts toward the floor.
        assert_eq!(decide(t(9), &[v(1)], &p, ALL), Err(Refusal::BelowFloor));
    }

    #[test]
    fn a_link_change_counts_everyone_connected() {
        let keys = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let p = room(&keys);
        assert_eq!(decide(None, &[v(1)], &p, ALL), Err(Refusal::BelowFloor));
        assert_eq!(decide(None, &[v(1), v(2)], &p, ALL), Ok(()));
    }

    #[test]
    fn a_peer_without_a_signing_key_cannot_vote() {
        let p = vec![
            PeerView { peer_id: [1; 16], pubkey: None, joined_at_seq: 1 },
            PeerView { peer_id: [2; 16], pubkey: None, joined_at_seq: 2 },
        ];
        assert_eq!(decide(None, &[v(1), v(2)], &p, ALL), Err(Refusal::VoterKeyChanged));
    }
}
