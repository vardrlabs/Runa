#![no_main]
//! The clear part of an EVICT_COMMIT (PROTOCOL.md amendment K): the one
//! payload past a header the server reads, apart from SNAPSHOT's index.
//! Whatever the parser accepts must re-encode to exactly the bytes it read,
//! with the tail untouched, and the decision it feeds must never panic.
use libfuzzer_sys::fuzz_target;
use runa_server::runar::evict::{decide, encode_clear, parse_commit, PeerView, MAX_VOTES};

fuzz_target!(|data: &[u8]| {
    let Ok(c) = parse_commit(data) else {
        return;
    };
    assert!(!c.votes.is_empty() && c.votes.len() <= MAX_VOTES);
    assert!(!c.tail.is_empty());
    let mut again = encode_clear(&c);
    again.extend_from_slice(c.tail);
    assert_eq!(again, data);

    // A room of everyone who voted plus one peer with no key, each voter's
    // key being its own id: the decision runs on whatever was parsed.
    let keys: Vec<Vec<u8>> = c.votes.iter().map(|v| v.voter.to_vec()).collect();
    let mut peers: Vec<PeerView<'_>> = c
        .votes
        .iter()
        .zip(&keys)
        .enumerate()
        .map(|(i, (v, k))| PeerView { peer_id: v.voter, pubkey: Some(k.as_slice()), joined_at_seq: i as u64 + 1 })
        .collect();
    peers.push(PeerView { peer_id: c.request_id, pubkey: None, joined_at_seq: 0 });
    let voters: Vec<([u8; 16], Vec<u8>)> = c.votes.iter().map(|v| (v.voter, v.voter.to_vec())).collect();
    // The cohort boundary comes from the input too, so both sides of it run.
    let since = u64::from(c.new_salt[0]);
    let _ = decide(c.target, &voters, &peers, since);
});
