#![no_main]
//! The clear part of an EVICT_COMMIT (PROTOCOL.md amendment K): the one
//! payload past a header the server reads, apart from SNAPSHOT's index.
//! Whatever the parser accepts must re-encode to exactly the bytes it read,
//! with the tail untouched; the statements and signature checks it feeds, and
//! the decision after them, must never panic.
use libfuzzer_sys::fuzz_target;
use runa_server::runar::evict::{
    decide, encode_clear, key_digest, parse_commit, statement, verify_vote, PeerView, Target, MAX_VOTES,
};

/// A valid uncompressed P-256 key, so input-derived signatures reach the
/// curve arithmetic instead of stopping at a point that is not on the curve.
const P256_PUB: [u8; 65] = [
    0x04, 0x1f, 0x14, 0x01, 0x46, 0xbf, 0xb1, 0xb2, 0x51, 0xf8, 0x4f, 0x4d, 0xdb, 0xe0, 0xd4, 0xcd, 0xcf, 0xd7, 0x7a,
    0xfd, 0x98, 0x4a, 0x95, 0x20, 0xe3, 0x57, 0x94, 0x02, 0x1f, 0x83, 0x12, 0xbb, 0x9e, 0xec, 0x99, 0x5a, 0x08, 0xb1,
    0xfa, 0x77, 0x04, 0xdf, 0x3d, 0xcc, 0x0b, 0x50, 0xa9, 0x66, 0x52, 0x63, 0xfb, 0x77, 0x11, 0xf9, 0x5f, 0x9f, 0x8a,
    0x44, 0x9c, 0x50, 0x96, 0xe4, 0x7c, 0x89, 0x2b,
];

fuzz_target!(|data: &[u8]| {
    let Ok(c) = parse_commit(data) else {
        return;
    };
    assert!(!c.votes.is_empty() && c.votes.len() <= MAX_VOTES);
    assert!(!c.tail.is_empty());
    let mut again = encode_clear(&c);
    again.extend_from_slice(c.tail);
    assert_eq!(again, data);

    // Every vote's statement, checked under keys taken from the input: 32
    // bytes as Ed25519, 65 as P-256 (0x04 and the signature itself), and the
    // valid P-256 key above. The first few votes are enough to cover the
    // paths, and keep each run quick.
    let room_id = c.new_salt;
    let root = u32::from_be_bytes([c.new_verifier[0], c.new_verifier[1], c.new_verifier[2], c.new_verifier[3]]);
    for v in c.votes.iter().take(4) {
        let msg = statement(&room_id, &c.request_id, root, c.target.as_ref(), &v.voter, &c.new_verifier);
        assert_eq!(msg.len(), 145);
        let mut p256 = [0x04u8; 65];
        p256[1..].copy_from_slice(&v.sig);
        let _ = verify_vote(&v.sig[..32], &msg, &v.sig);
        let _ = verify_vote(&p256, &msg, &v.sig);
        let _ = verify_vote(&P256_PUB, &msg, &v.sig);
    }

    // A room of everyone who voted plus one peer with no key, each voter's
    // key being its own id: the decision runs on whatever was parsed. A
    // digest from the input names no key anyone holds, so the target's key
    // is replaced by one built from the input, and the salt's second byte
    // decides whether the named connection, a second connection holding its
    // key, and a voter holding its key are in the room.
    let target_key = c.request_id.to_vec();
    let flags = c.new_salt[1];
    let target = c.target.map(|t| Target { key_digest: key_digest(&target_key), ..t });
    let mut keys: Vec<Vec<u8>> = c.votes.iter().map(|v| v.voter.to_vec()).collect();
    if flags & 4 != 0 {
        keys[0] = target_key.clone();
    }
    let mut peers: Vec<PeerView<'_>> = c
        .votes
        .iter()
        .zip(&keys)
        .enumerate()
        .map(|(i, (v, k))| PeerView { peer_id: v.voter, pubkey: Some(k.as_slice()), joined_at_seq: i as u64 + 1 })
        .collect();
    peers.push(PeerView { peer_id: c.request_id, pubkey: None, joined_at_seq: 0 });
    if let Some(t) = target {
        if flags & 1 != 0 {
            peers.push(PeerView { peer_id: t.peer_id, pubkey: Some(&target_key), joined_at_seq: 0 });
        }
        if flags & 2 != 0 {
            peers.push(PeerView { peer_id: c.new_salt, pubkey: Some(&target_key), joined_at_seq: 0 });
        }
    }
    let voters: Vec<([u8; 16], Vec<u8>)> = c.votes.iter().zip(&keys).map(|(v, k)| (v.voter, k.clone())).collect();
    // The cohort boundary comes from the input too, so both sides of it run.
    let since = u64::from(c.new_salt[0]);
    let _ = decide(target, &voters, &peers, since);
});
