//! PROTOCOL.md amendment K: removing someone and changing the link, as the
//! server enforces it.
use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use runa_server::build_router;
use runa_server::runar::evict;
use runa_server::sha2::{Digest, Sha256};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

fn cfg() -> runa_server::config::Config {
    runa_server::config::Config {
        auth_floor: Duration::from_millis(10),
        dist_dir: "/nonexistent".into(),
        ..Default::default()
    }
}

async fn spawn(cfg: runa_server::config::Config) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(runa_server::AppState::new(cfg));
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap();
    b
}

fn verifier(auth: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(auth).into()
}

struct Keys {
    hex: String,
    id: [u8; 16],
    auth: [u8; 32],
}

impl Keys {
    fn new(room_hex: &str, auth: [u8; 32]) -> Keys {
        Keys { hex: room_hex.to_string(), id: hex::decode(room_hex).unwrap().try_into().unwrap(), auth }
    }
}

async fn create(server: &str) -> Keys {
    let auth = rand32();
    let r = reqwest::Client::new()
        .post(format!("{server}/api/rooms/unlisted"))
        .json(&json!({
            "verifier": B64.encode(verifier(&auth)),
            "kdf": {"m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(rand16())},
            "ttl": {"kind": "idle-peers", "secs": 3600},
            "config_blob": B64.encode(b"sealed-config"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let body: Value = r.json().await.unwrap();
    Keys::new(body["room_id"].as_str().unwrap(), auth)
}

async fn create_named(server: &str, name: &str) -> Keys {
    let auth = rand32();
    let r = reqwest::Client::new()
        .post(format!("{server}/api/rooms/named"))
        .json(&json!({
            "name": name,
            "suffix": false,
            "verifier": B64.encode(verifier(&auth)),
            "kdf": {"m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(rand16())},
            "ttl": {"kind": "idle-peers", "secs": 3600},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let body: Value = r.json().await.unwrap();
    Keys::new(body["room_id"].as_str().unwrap(), auth)
}

fn frame(room_hex: &str, ft: u8, epoch: u32, body: &[u8]) -> Message {
    let mut f: Vec<u8> = vec![0x52, 0x55, 0x01, ft];
    f.extend_from_slice(&hex::decode(room_hex).unwrap());
    f.extend_from_slice(&epoch.to_be_bytes());
    f.extend_from_slice(&[1, 2, 3, 4]);
    f.extend_from_slice(&[0u8; 4]);
    f.extend_from_slice(body);
    Message::Binary(f.into())
}

async fn connect(server: &str, hex: &str) -> Ws {
    let url = format!("{}/socket/{hex}", server.replacen("http://", "ws://", 1));
    tokio_tungstenite::connect_async(url.into_client_request().unwrap()).await.unwrap().0
}

async fn next_ft(ws: &mut Ws, ft: u8) -> Vec<u8> {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timeout")
            .expect("closed")
            .unwrap();
        if let Message::Binary(b) = m {
            if b.len() >= 4 && b[3] == ft {
                return b.to_vec();
            }
        }
    }
}

fn json_body(f: &[u8]) -> Value {
    serde_json::from_slice(&f[32..]).unwrap()
}

/// Every frame of one type that arrives within `ms`.
async fn frames_of(ws: &mut Ws, ft: u8, ms: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => {
                if b.len() >= 4 && b[3] == ft {
                    out.push(b.to_vec());
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => return out,
        }
    }
}

async fn close_code(ws: &mut Ws) -> u16 {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timeout waiting for a close")
            .expect("stream ended without a close frame")
            .unwrap();
        if let Message::Close(Some(c)) = m {
            return u16::from(c.code);
        }
    }
}

fn kx_pub() -> Vec<u8> {
    let mut p = vec![0x04u8];
    p.extend_from_slice(&rand32());
    p.extend_from_slice(&rand32());
    p
}

/// A member's signing key: Ed25519, or the ECDSA P-256 fallback. Cloned
/// when a test opens a second connection under the same key.
#[derive(Clone)]
enum Signer {
    Ed(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Signer {
    fn ed() -> Signer {
        Signer::Ed(ed25519_dalek::SigningKey::from_bytes(&rand32()))
    }

    fn p256() -> Signer {
        loop {
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&rand32()) {
                return Signer::P256(k);
            }
        }
    }

    fn public(&self) -> Vec<u8> {
        match self {
            Signer::Ed(k) => k.verifying_key().to_bytes().to_vec(),
            Signer::P256(k) => k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
        }
    }

    /// `high_s` turns a P-256 signature into its high-S twin, the form
    /// WebCrypto produces about half the time.
    fn sign(&self, msg: &[u8], high_s: bool) -> [u8; 64] {
        match self {
            Signer::Ed(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(msg).to_bytes()
            }
            Signer::P256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let s: p256::ecdsa::Signature = k.sign(msg);
                let mut out = [0u8; 64];
                out.copy_from_slice(&s.to_bytes());
                if high_s {
                    to_high_s(&mut out);
                }
                out
            }
        }
    }
}

/// Replace a low s with n - s, so the signature is the high-S one.
fn to_high_s(sig: &mut [u8; 64]) {
    let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    let mut neg = [0u8; 32];
    let mut borrow = 0i16;
    for ((out, &ni), &si) in neg.iter_mut().zip(&n).zip(&s).rev() {
        let d = i16::from(ni) - i16::from(si) - borrow;
        borrow = i16::from(d < 0);
        *out = (d + 256 * borrow) as u8;
    }
    if neg > s {
        sig[32..].copy_from_slice(&neg);
    }
}

struct Member {
    ws: Ws,
    id: [u8; 16],
    key: Signer,
}

async fn join(server: &str, k: &Keys, key: Signer) -> Member {
    let mut ws = connect(server, &k.hex).await;
    let body = json!({
        "auth_key": B64.encode(k.auth),
        "pubkey": B64.encode(key.public()),
        "kx_pubkey": B64.encode(kx_pub()),
        "kx_sig": B64.encode([7u8; 64]),
    });
    ws.send(frame(&k.hex, 0x01, 0, body.to_string().as_bytes())).await.unwrap();
    let ack = json_body(&next_ft(&mut ws, 0x02).await);
    let id = B64.decode(ack["peer_id"].as_str().unwrap()).unwrap().try_into().unwrap();
    Member { ws, id, key }
}

/// Joins with `auth` and returns the JOIN_ACK, or the ERROR's code.
async fn try_join(server: &str, hex: &str, auth: [u8; 32]) -> Result<Value, u64> {
    let mut ws = connect(server, hex).await;
    let body = json!({"auth_key": B64.encode(auth), "pubkey": B64.encode(rand32())});
    ws.send(frame(hex, 0x01, 0, body.to_string().as_bytes())).await.unwrap();
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timeout")
            .expect("closed")
            .unwrap();
        if let Message::Binary(b) = m {
            match b[3] {
                0x02 => return Ok(json_body(&b)),
                0x30 => return Err(json_body(&b)["code"].as_u64().unwrap()),
                _ => {}
            }
        }
    }
}

/// The target as the votes name it: the member's peer id and the digest of
/// the signing key it joined with.
fn named(m: &Member) -> Option<evict::Target> {
    Some(evict::Target { peer_id: m.id, key_digest: evict::key_digest(&m.key.public()) })
}

/// What a commit asks for, and the key the new verifier is the hash of.
struct Commit {
    request_id: [u8; 16],
    epoch: u32,
    target: Option<evict::Target>,
    verifier: [u8; 32],
    salt: [u8; 16],
    config: Vec<u8>,
    new_auth: [u8; 32],
}

impl Commit {
    fn new(epoch: u32, target: Option<evict::Target>) -> Commit {
        let new_auth = rand32();
        Commit {
            request_id: rand16(),
            epoch,
            target,
            verifier: verifier(&new_auth),
            salt: rand16(),
            config: b"sealed-again".to_vec(),
            new_auth,
        }
    }

    fn body(&self, room: &[u8; 16], voters: &[(&Signer, [u8; 16])], high_s: bool) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.request_id);
        b.extend_from_slice(&self.target.map_or([0; 16], |t| t.peer_id));
        b.extend_from_slice(&self.target.map_or([0; 32], |t| t.key_digest));
        b.extend_from_slice(&self.verifier);
        b.extend_from_slice(&self.salt);
        b.extend_from_slice(&(self.config.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.config);
        b.push(voters.len() as u8);
        for (key, voter) in voters {
            let msg = evict::statement(room, &self.request_id, self.epoch, self.target.as_ref(), voter, &self.verifier);
            b.extend_from_slice(voter);
            b.push(64);
            b.extend_from_slice(&key.sign(&msg, high_s));
        }
        b.extend_from_slice(b"opaque tail");
        b
    }

    /// Where the first vote's signature starts in `body`: 116 bytes of ids,
    /// the target's key digest, verifier, salt and config length, then the
    /// config, the count, the voter and the signature's length.
    fn first_sig_at(&self) -> usize {
        116 + self.config.len() + 1 + 16 + 1
    }
}

/// The room did not move: nothing was relayed to `sender`, and the old key
/// still opens it at epoch 0.
async fn assert_refused(server: &str, k: &Keys, sender: &mut Member) {
    assert!(frames_of(&mut sender.ws, 0x23, 400).await.is_empty(), "a refused commit was relayed");
    let ack = try_join(server, &k.hex, k.auth).await.expect("the old key still opens the room");
    assert_eq!(ack["epoch"], 0);
    assert_eq!(ack["root_epoch"], 0);
}

/// What a proposer does: an EVICT_REQUEST first, which the server notes before
/// relaying (the cohort the commit is counted against), then the commit. Both
/// go over one connection, so the server handles them in that order.
async fn propose_and_commit(k: &Keys, m: &mut Member, epoch: u32, body: &[u8]) {
    m.ws.send(frame(&k.hex, 0x24, 0, b"sealed request")).await.unwrap();
    m.ws.send(frame(&k.hex, 0x23, epoch, body)).await.unwrap();
}

#[tokio::test]
async fn a_commit_removes_the_target_and_swaps_the_way_in() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::p256()).await;
    let mut t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;

    // Everyone but the target gets it, the sender included, enveloped.
    let to_a = next_ft(&mut a.ws, 0x23).await;
    let to_b = next_ft(&mut b.ws, 0x23).await;
    assert_eq!(&to_a[32..48], &a.id);
    assert_eq!(&to_a[48..], &body[..]);
    assert_eq!(to_a, to_b);
    // The target is told why and closed with 4014, and the others see it leave
    // with that reason.
    assert_eq!(json_body(&next_ft(&mut t.ws, 0x30).await)["code"], 4014);
    assert_eq!(close_code(&mut t.ws).await, 4014);
    assert_eq!(json_body(&next_ft(&mut b.ws, 0x08).await)["reason"], 4014);

    // The old key is refused like a wrong one; the new key opens the room at
    // the new root, with the new salt and config.
    assert_eq!(try_join(&s, &k.hex, k.auth).await.unwrap_err(), 4001);
    let ack = try_join(&s, &k.hex, c.new_auth).await.unwrap();
    assert_eq!(ack["epoch"], 1);
    assert_eq!(ack["root_epoch"], 1);
    assert_eq!(ack["kdf"]["salt"], B64.encode(c.salt));
    assert_eq!(ack["config_blob"], B64.encode(&c.config));
}

#[tokio::test]
async fn a_link_change_names_nobody_and_closes_nobody() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, None);
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    next_ft(&mut a.ws, 0x23).await;
    next_ft(&mut b.ws, 0x23).await;
    assert!(frames_of(&mut b.ws, 0x08, 300).await.is_empty(), "nobody was closed");
    assert_eq!(try_join(&s, &k.hex, k.auth).await.unwrap_err(), 4001);
    assert_eq!(try_join(&s, &k.hex, c.new_auth).await.unwrap()["root_epoch"], 1);
}

#[tokio::test]
async fn metadata_and_name_resolution_serve_the_new_salt() {
    let s = spawn(cfg()).await;
    let k = create_named(&s, "tin-harbour-7f3a").await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, None);
    let body = c.body(&k.id, &[(&a.key, a.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    next_ft(&mut a.ws, 0x23).await;

    let client = reqwest::Client::new();
    let resolved: Value = client
        .post(format!("{s}/api/names/resolve"))
        .json(&json!({ "name": "tin-harbour-7f3a" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resolved["kdf"]["salt"], B64.encode(c.salt));
    let meta: Value = client.get(format!("{s}/api/meta/id/{}", k.hex)).send().await.unwrap().json().await.unwrap();
    assert_eq!(meta["kdf"]["salt"], B64.encode(c.salt));
}

#[tokio::test]
async fn a_high_s_p256_vote_is_accepted() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::p256()).await;
    let mut b = join(&s, &k, Signer::p256()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], true);
    propose_and_commit(&k, &mut a, 0, &body).await;
    next_ft(&mut a.ws, 0x23).await;
    next_ft(&mut b.ws, 0x23).await;
}

#[tokio::test]
async fn a_bad_signature_is_refused() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let mut body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    body[c.first_sig_at()] ^= 1;
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

#[tokio::test]
async fn the_target_cannot_vote() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id), (&t.key, t.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

/// The target is every connection holding its key, not only the one named:
/// the server knows the key from the digest every vote signs.
#[tokio::test]
async fn the_targets_other_connections_are_closed_and_do_not_hold_the_vote_down() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    // The target's older connection, still open, and the one a names.
    let key = Signer::p256();
    let mut t0 = join(&s, &k, key.clone()).await;
    let mut t = join(&s, &k, key).await;
    let c = Commit::new(0, named(&t));
    // Counted, t0 would make a's one signature half of two.
    let body = c.body(&k.id, &[(&a.key, a.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_eq!(&next_ft(&mut a.ws, 0x23).await[48..], &body[..]);
    for ws in [&mut t0.ws, &mut t.ws] {
        assert_eq!(json_body(&next_ft(ws, 0x30).await)["code"], 4014);
        assert_eq!(close_code(ws).await, 4014);
    }
    assert_eq!(try_join(&s, &k.hex, c.new_auth).await.unwrap()["root_epoch"], 1);
}

#[tokio::test]
async fn a_connection_under_the_targets_key_cannot_vote() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let b = join(&s, &k, Signer::ed()).await;
    let key = Signer::ed();
    let t = join(&s, &k, key.clone()).await;
    let t2 = join(&s, &k, key).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id), (&t2.key, t2.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

#[tokio::test]
async fn votes_naming_a_key_the_target_does_not_hold_are_refused() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let wrong = Some(evict::Target { peer_id: t.id, key_digest: evict::key_digest(&Signer::ed().public()) });
    let c = Commit::new(0, wrong);
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

#[tokio::test]
async fn a_voter_counts_once() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let _b = join(&s, &k, Signer::ed()).await;
    let _c = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&a.key, a.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

#[tokio::test]
async fn half_the_room_is_not_enough() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let _b = join(&s, &k, Signer::ed()).await;
    let _c = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

#[tokio::test]
async fn votes_for_another_epoch_are_refused() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(1, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    propose_and_commit(&k, &mut a, 1, &body).await;
    assert_refused(&s, &k, &mut a).await;
}

/// Decided 2026-11-06: a target that has left (or reconnected under a new peer
/// id) does not stop the commit. The room re-roots, nobody is closed, and the
/// old key stops working.
#[tokio::test]
async fn a_target_that_has_left_is_still_removed() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let gone = named(&t);
    drop(t);
    // Wait until the room has seen it go, so the commit meets a room without it.
    next_ft(&mut b.ws, 0x08).await;
    let c = Commit::new(0, gone);
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    propose_and_commit(&k, &mut a, 0, &body).await;
    assert_eq!(&next_ft(&mut a.ws, 0x23).await[48..], &body[..]);
    assert_eq!(&next_ft(&mut b.ws, 0x23).await[48..], &body[..]);
    assert!(frames_of(&mut b.ws, 0x08, 300).await.is_empty(), "nobody else was closed");
    assert_eq!(try_join(&s, &k.hex, k.auth).await.unwrap_err(), 4001);
    let ack = try_join(&s, &k.hex, c.new_auth).await.unwrap();
    assert_eq!(ack["epoch"], 1);
    assert_eq!(ack["root_epoch"], 1);
}

#[tokio::test]
async fn garbage_in_the_clear_part_is_dropped() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    propose_and_commit(&k, &mut a, 0, b"not a commit").await;
    assert_refused(&s, &k, &mut a).await;
}

#[tokio::test]
async fn connections_opened_after_the_request_do_not_hold_the_vote_down() {
    let s = spawn(runa_server::config::Config {
        auth_attempts_per_room_per_min: 100,
        auth_attempts_per_ip_per_min: 100,
        max_conns_per_ip: 64,
        ..cfg()
    })
    .await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    a.ws.send(frame(&k.hex, 0x24, 0, b"sealed request")).await.unwrap();
    // The server notes the request before relaying it, so once b has it the
    // cohort is fixed.
    next_ft(&mut b.ws, 0x24).await;
    // The target opens three more connections with the old link. Counted,
    // they would make two signatures out of five others too few.
    let mut extra = Vec::new();
    for _ in 0..3 {
        extra.push(join(&s, &k, Signer::ed()).await);
    }
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    a.ws.send(frame(&k.hex, 0x23, 0, &body)).await.unwrap();
    assert_eq!(&next_ft(&mut a.ws, 0x23).await[48..], &body[..]);
    assert_eq!(try_join(&s, &k.hex, c.new_auth).await.unwrap()["root_epoch"], 1);
    drop(extra);
}

#[tokio::test]
async fn a_commit_without_its_senders_request_is_refused() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    let mut t = join(&s, &k, Signer::ed()).await;
    // Only the target asks; that opens nothing for a.
    t.ws.send(frame(&k.hex, 0x24, 0, b"sealed request")).await.unwrap();
    next_ft(&mut b.ws, 0x24).await;
    let c = Commit::new(0, named(&t));
    a.ws.send(frame(&k.hex, 0x23, 0, &c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false))).await.unwrap();
    assert_refused(&s, &k, &mut a).await;
}

enum Outcome {
    Committed,
    Removed,
}

async fn outcome(ws: &mut Ws) -> Outcome {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timeout")
            .expect("closed")
            .unwrap();
        if let Message::Binary(b) = m {
            if b[3] == 0x23 {
                return Outcome::Committed;
            }
            if b[3] == 0x30 && json_body(&b)["code"] == 4014 {
                return Outcome::Removed;
            }
        }
    }
}

#[tokio::test]
async fn in_a_room_of_two_the_first_commit_wins() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    let remove_b = Commit::new(0, named(&b));
    let remove_a = Commit::new(0, named(&a));
    let fa = frame(&k.hex, 0x23, 0, &remove_b.body(&k.id, &[(&a.key, a.id)], false));
    let fb = frame(&k.hex, 0x23, 0, &remove_a.body(&k.id, &[(&b.key, b.id)], false));
    // Both ask first, as proposers do; then both commits race.
    a.ws.send(frame(&k.hex, 0x24, 0, b"sealed request")).await.unwrap();
    b.ws.send(frame(&k.hex, 0x24, 0, b"sealed request")).await.unwrap();
    next_ft(&mut a.ws, 0x24).await;
    next_ft(&mut b.ws, 0x24).await;
    let (ra, rb) = tokio::join!(a.ws.send(fa), b.ws.send(fb));
    ra.unwrap();
    rb.unwrap();
    let (oa, ob) = (outcome(&mut a.ws).await, outcome(&mut b.ws).await);
    assert!(
        matches!((oa, ob), (Outcome::Committed, Outcome::Removed) | (Outcome::Removed, Outcome::Committed)),
        "exactly one of the two must win"
    );
}

#[tokio::test]
async fn evict_frames_are_relayed_to_the_others_and_held_to_the_epoch() {
    let s = spawn(runa_server::config::Config {
        epoch_overlap: Duration::from_millis(1),
        epoch_min_interval: Duration::ZERO,
        ..cfg()
    })
    .await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    for ft in [0x24u8, 0x25, 0x26] {
        a.ws.send(frame(&k.hex, ft, 0, b"sealed")).await.unwrap();
        let got = next_ft(&mut b.ws, ft).await;
        assert_eq!(&got[32..48], &a.id);
        assert_eq!(&got[48..], b"sealed");
    }
    assert!(frames_of(&mut a.ws, 0x24, 300).await.is_empty(), "the sender does not get its own");

    // After a step and the overlap, a vote from the old epoch is refused.
    a.ws.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    next_ft(&mut b.ws, 0x20).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    b.ws.send(frame(&k.hex, 0x25, 0, b"late-vote")).await.unwrap();
    assert_eq!(json_body(&next_ft(&mut b.ws, 0x30).await)["code"], 4006);
}

/// A connection the room has just removed keeps reading until its 4014 error
/// has gone out. The target writes without pause across the commit; whatever it
/// got in before the commit was applied is relayed, and nothing after it is.
#[tokio::test]
async fn nothing_a_removed_connection_sends_after_the_commit_is_relayed() {
    let s = spawn(cfg()).await;
    let k = create(&s).await;
    let mut a = join(&s, &k, Signer::ed()).await;
    let mut b = join(&s, &k, Signer::ed()).await;
    let t = join(&s, &k, Signer::ed()).await;
    let c = Commit::new(0, named(&t));
    let body = c.body(&k.id, &[(&a.key, a.id), (&b.key, b.id)], false);
    a.ws.send(frame(&k.hex, 0x24, 0, b"sealed request")).await.unwrap();
    next_ft(&mut b.ws, 0x24).await;
    // b reads from the start, so the flood never fills its queue.
    let collector = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut left = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut until = deadline;
        // Read until the target's departure has been announced, then a little
        // longer for anything still in flight.
        while let Ok(Some(Ok(m))) = tokio::time::timeout_at(until, b.ws.next()).await {
            if let Message::Binary(f) = m {
                if f[3] == 0x08 && !left {
                    left = true;
                    until = tokio::time::Instant::now() + Duration::from_millis(500);
                }
                seen.push(f[3]);
            }
        }
        seen
    });
    let hex = k.hex.clone();
    let mut tws = t.ws;
    let writer = tokio::spawn(async move {
        for _ in 0..20_000 {
            for ft in [0x03u8, 0x06, 0x24] {
                if tws.send(frame(&hex, ft, 0, b"late")).await.is_err() {
                    return;
                }
            }
            tokio::task::yield_now().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    a.ws.send(frame(&k.hex, 0x23, 0, &body)).await.unwrap();
    let seen = collector.await.unwrap();
    writer.abort();
    let commit_at = seen.iter().position(|&t| t == 0x23).expect("b never got the commit");
    let late: Vec<u8> = seen[commit_at..].iter().copied().filter(|t| [0x03, 0x06, 0x24].contains(t)).collect();
    assert!(late.is_empty(), "frames from a removed connection were relayed after the commit: {late:?}");
}
