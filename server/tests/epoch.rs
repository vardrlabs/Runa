//! PROTOCOL.md amendment J: the server's epoch rules, end to end.
use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use runa_server::build_router;
use runa_server::sha2::{Digest, Sha256};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

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

fn cfg_with(overlap_ms: u64, min_ms: u64) -> runa_server::config::Config {
    runa_server::config::Config {
        auth_floor: Duration::from_millis(10),
        dist_dir: "/nonexistent".into(),
        epoch_overlap: Duration::from_millis(overlap_ms),
        epoch_min_interval: Duration::from_millis(min_ms),
        ..Default::default()
    }
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

struct Keys {
    hex: String,
    auth: [u8; 32],
}

async fn create(server: &str) -> Keys {
    let auth = rand32();
    let h: [u8; 32] = Sha256::digest(auth).into();
    let r = reqwest::Client::new()
        .post(format!("{server}/api/rooms/unlisted"))
        .json(&json!({
            "verifier": B64.encode(h),
            "kdf": {"m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(rand16())},
            "ttl": {"kind": "idle-peers", "secs": 3600},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let body: Value = r.json().await.unwrap();
    Keys { hex: body["room_id"].as_str().unwrap().to_string(), auth }
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

fn epoch_of(f: &[u8]) -> u32 {
    u32::from_be_bytes([f[20], f[21], f[22], f[23]])
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

/// Joins with a well-formed dummy key-agreement key (the server checks lengths
/// only), so the peer can be handed an epoch key. `extra` overrides any field.
async fn join_with(server: &str, k: &Keys, extra: Value) -> (Ws, Value) {
    let mut body = json!({"kx_pubkey": B64.encode(kx_pub()), "kx_sig": B64.encode([7u8; 64])});
    for (key, v) in extra.as_object().unwrap() {
        body[key] = v.clone();
    }
    join_bare(server, k, body).await
}

/// Joins with exactly the fields given: no key agreement unless `extra` has it.
async fn join_bare(server: &str, k: &Keys, extra: Value) -> (Ws, Value) {
    let mut ws = join_raw(server, k, extra).await;
    let ack = next_ft(&mut ws, 0x02).await;
    (ws, json_body(&ack))
}

/// Sends the JOIN and returns without waiting for the answer.
async fn join_raw(server: &str, k: &Keys, extra: Value) -> Ws {
    let mut ws = connect(server, &k.hex).await;
    let mut body = json!({"auth_key": B64.encode(k.auth), "pubkey": B64.encode(rand32())});
    for (key, v) in extra.as_object().unwrap() {
        body[key] = v.clone();
    }
    ws.send(frame(&k.hex, 0x01, 0, body.to_string().as_bytes())).await.unwrap();
    ws
}

/// The close code the server ends the connection with, skipping other frames.
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

#[tokio::test]
async fn join_ack_reports_the_epoch_and_root_epoch() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (_a, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["epoch"], 0);
    assert_eq!(ack["root_epoch"], 0);
}

#[tokio::test]
async fn an_accepted_step_reaches_every_peer_including_its_sender() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step-one")).await.unwrap();
    let echo = next_ft(&mut a, 0x20).await;
    let relayed = next_ft(&mut b, 0x20).await;
    assert_eq!(epoch_of(&echo), 1);
    assert_eq!(&echo[48..], b"step-one", "relayed with the 16-byte sender envelope");
    assert_eq!(echo, relayed, "the sender gets the same copy as everyone else");
    let (_c, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["epoch"], 1);
}

#[tokio::test]
async fn a_step_that_skips_an_epoch_goes_nowhere() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 2, b"skip")).await.unwrap();
    assert!(frames_of(&mut b, 0x20, 300).await.is_empty());
    assert!(frames_of(&mut a, 0x20, 100).await.is_empty());
    let (_c, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["epoch"], 0);
}

#[tokio::test]
async fn steps_closer_than_the_minimum_interval_go_nowhere() {
    let s = spawn(cfg_with(30_000, 5_000)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"one")).await.unwrap();
    let _ = next_ft(&mut b, 0x20).await;
    b.send(frame(&k.hex, 0x20, 2, b"two")).await.unwrap();
    let seen = frames_of(&mut a, 0x20, 300).await;
    assert!(seen.iter().all(|f| epoch_of(f) != 2), "a step inside the interval was relayed");
    let (_c, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["epoch"], 1);
}

#[tokio::test]
async fn a_handover_reaches_the_others_but_not_its_sender() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 0, b"handover")).await.unwrap();
    let got = next_ft(&mut b, 0x20).await;
    assert_eq!(&got[48..], b"handover");
    assert!(frames_of(&mut a, 0x20, 300).await.is_empty());
}

#[tokio::test]
async fn the_previous_epoch_is_accepted_inside_the_overlap() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({"acks": true})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    a.send(frame(&k.hex, 0x03, 0, &[0u8; 64])).await.unwrap();
    let ack = json_body(&next_ft(&mut a, 0x09).await);
    assert_eq!(ack["ok"], true);
}

#[tokio::test]
async fn stale_frames_are_refused_once_the_overlap_has_passed() {
    let s = spawn(cfg_with(100, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({"acks": true})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    let _ = next_ft(&mut b, 0x20).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    a.send(frame(&k.hex, 0x03, 0, &[0u8; 64])).await.unwrap();
    let ack = json_body(&next_ft(&mut a, 0x09).await);
    assert_eq!(ack, json!({"ok": false, "epoch": 1}));

    a.send(frame(&k.hex, 0x06, 0, &[0u8; 64])).await.unwrap();
    let err = json_body(&next_ft(&mut a, 0x30).await);
    assert_eq!(err["code"], 4006);
    assert!(frames_of(&mut b, 0x06, 300).await.is_empty(), "stale presence was relayed");
    assert!(frames_of(&mut b, 0x03, 100).await.is_empty(), "a stale update was relayed");
}

#[tokio::test]
async fn frames_from_an_epoch_the_room_has_not_reached_are_refused() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({"acks": true})).await;
    a.send(frame(&k.hex, 0x03, 5, &[0u8; 64])).await.unwrap();
    let ack = json_body(&next_ft(&mut a, 0x09).await);
    assert_eq!(ack, json!({"ok": false, "epoch": 0}));
}

#[tokio::test]
async fn frames_without_ciphertext_are_never_refused_for_their_epoch() {
    let s = spawn(cfg_with(50, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({"heartbeat": true})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    a.send(frame(&k.hex, 0x17, 0, b"{}")).await.unwrap();
    let _pong = next_ft(&mut a, 0x18).await;
}

#[tokio::test]
async fn a_snapshot_from_an_epoch_the_room_has_not_reached_is_refused() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    let mut body = 0u64.to_be_bytes().to_vec();
    body.extend_from_slice(&[0u8; 64]);
    a.send(frame(&k.hex, 0x21, 5, &body)).await.unwrap();
    let err = json_body(&next_ft(&mut a, 0x30).await);
    assert_eq!(err["code"], 4006);
}

#[tokio::test]
async fn key_agreement_keys_travel_in_the_roster_and_peer_join() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (pa, sa) = (kx_pub(), [9u8; 64]);
    let (mut a, _) = join_with(&s, &k, json!({"kx_pubkey": B64.encode(&pa), "kx_sig": B64.encode(sa)})).await;
    let (pb, sb) = (kx_pub(), [8u8; 64]);
    let (_b, ack) = join_with(&s, &k, json!({"kx_pubkey": B64.encode(&pb), "kx_sig": B64.encode(sb)})).await;
    let first = &ack["roster"][0];
    assert_eq!(first["kx_pubkey"], B64.encode(&pa));
    assert_eq!(first["kx_sig"], B64.encode(sa));
    // A's own PEER_JOIN comes first (it is not excluded); B's is the second.
    let _own = next_ft(&mut a, 0x07).await;
    let join = json_body(&next_ft(&mut a, 0x07).await);
    assert_eq!(join["kx_pubkey"], B64.encode(&pb));
    assert_eq!(join["kx_sig"], B64.encode(sb));
}

#[tokio::test]
async fn malformed_key_agreement_keys_are_dropped() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    // 64 bytes is not an uncompressed point; a 63-byte signature is no signature.
    let (_a, _) = join_with(&s, &k, json!({"kx_pubkey": B64.encode([4u8; 64]), "kx_sig": B64.encode([1u8; 64])})).await;
    let (_b, _) = join_with(&s, &k, json!({"kx_pubkey": B64.encode(kx_pub()), "kx_sig": B64.encode([1u8; 63])})).await;
    let (_c, ack) = join_bare(&s, &k, json!({})).await;
    for entry in ack["roster"].as_array().unwrap() {
        assert!(entry.get("kx_pubkey").is_none(), "kept a malformed key: {entry}");
    }
}

#[tokio::test]
async fn purge_keeps_epoch_zero_after_the_room_has_stepped() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step-one")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    let _ = next_ft(&mut b, 0x20).await;

    a.send(frame(&k.hex, 0x14, 1, json!({"request_id": "r1"}).to_string().as_bytes())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    b.send(frame(&k.hex, 0x14, 1, json!({"request_id": "r1"}).to_string().as_bytes())).await.unwrap();

    let purge = next_ft(&mut a, 0x13).await;
    assert_eq!(&purge[20..24], &[0, 0, 0, 0], "server-authored frames carry epoch 0");
}

#[tokio::test]
async fn a_room_restored_from_a_ticket_keeps_its_epoch() {
    use runa_server::runar::room::{Room, RoomClass, Ttl, TtlKind};
    use runa_server::runar::ticket::{issue, RestartKey};
    let key_bytes = [5u8; 32];
    let mut cfg = cfg_with(30_000, 0);
    cfg.restart_key = Some(RestartKey(key_bytes));
    let s = spawn(cfg).await;

    let auth = rand32();
    let verifier: [u8; 32] = Sha256::digest(auth).into();
    let id = rand16();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let old = Room::new(
        id,
        RoomClass::Unlisted,
        now,
        Ttl { kind: TtlKind::IdlePeers, secs: 3600 },
        false,
        Some(verifier),
        65536,
        3,
        1,
        rand16(),
        None,
        1 << 20,
        5,
        32,
    );
    old.restore_epochs(3, 0);
    let ticket = issue(&RestartKey(key_bytes), &old, now).unwrap();
    let r = reqwest::Client::new()
        .post(format!("{s}/api/rooms/restore"))
        .json(&json!({ "ticket": ticket }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let k = Keys { hex: hex::encode(id), auth };
    let (_a, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["epoch"], 3);
    assert_eq!(ack["root_epoch"], 0);
}

#[tokio::test]
async fn a_client_without_key_agreement_is_refused_a_rotated_room() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;

    let mut old = join_raw(&s, &k, json!({})).await;
    let err = json_body(&next_ft(&mut old, 0x30).await);
    assert_eq!(err["code"], 4005);
    assert_eq!(close_code(&mut old).await, 4005);

    let (_c, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["roster"].as_array().unwrap().len(), 2, "the refused join was on the roster");
    // Nobody was told the refused client had joined: a sees only c's PEER_JOIN
    // (its own was skipped while waiting for the echo).
    assert_eq!(frames_of(&mut a, 0x07, 300).await.len(), 1);
}

#[tokio::test]
async fn a_client_without_key_agreement_still_joins_a_room_that_never_rotated() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (_a, ack) = join_bare(&s, &k, json!({})).await;
    assert_eq!(ack["epoch"], 0);
    let (_b, ack) = join_bare(&s, &k, json!({})).await;
    assert_eq!(ack["roster"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_client_without_key_agreement_is_closed_when_a_step_is_accepted() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    let (mut old, _) = join_bare(&s, &k, json!({})).await;

    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    assert_eq!(epoch_of(&next_ft(&mut a, 0x20).await), 1);
    assert_eq!(epoch_of(&next_ft(&mut b, 0x20).await), 1);
    let err = json_body(&next_ft(&mut old, 0x30).await);
    assert_eq!(err["code"], 4005);
    assert_eq!(close_code(&mut old).await, 4005);

    // It left the roster, and the others were told.
    let leaves = frames_of(&mut b, 0x08, 500).await;
    assert_eq!(leaves.len(), 1);
    let (_c, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["roster"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn a_stale_update_from_a_connection_that_did_not_ask_for_acks_gets_4006() {
    let s = spawn(cfg_with(100, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    a.send(frame(&k.hex, 0x03, 0, &[0u8; 64])).await.unwrap();
    let err = json_body(&next_ft(&mut a, 0x30).await);
    assert_eq!(err["code"], 4006);
}

#[tokio::test]
async fn a_snapshot_from_the_epoch_just_left_is_dropped_quietly() {
    let s = spawn(cfg_with(400, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    a.send(frame(&k.hex, 0x20, 1, b"step")).await.unwrap();
    let _ = next_ft(&mut a, 0x20).await;
    let _ = next_ft(&mut b, 0x20).await;
    let mut body = 0u64.to_be_bytes().to_vec();
    body.extend_from_slice(&[0u8; 64]);

    a.send(frame(&k.hex, 0x21, 0, &body)).await.unwrap();
    assert!(frames_of(&mut a, 0x30, 300).await.is_empty(), "an overlap snapshot got an error");
    assert!(frames_of(&mut b, 0x21, 100).await.is_empty(), "an overlap snapshot was relayed");
    let (_c, ack) = join_with(&s, &k, json!({})).await;
    assert_eq!(ack["has_snapshot"], false, "an overlap snapshot was stored");

    tokio::time::sleep(Duration::from_millis(300)).await;
    a.send(frame(&k.hex, 0x21, 0, &body)).await.unwrap();
    let err = json_body(&next_ft(&mut a, 0x30).await);
    assert_eq!(err["code"], 4006);
}

/// A peer that cannot keep up is dropped when its queue overflows: its
/// connection closes once it has drained what was queued, and the others are
/// told it left. The connection must not outlive its place in the room (a
/// second long-lived sender would keep the writer waiting for more frames
/// forever, leaving a peer that is connected, off the roster, and deaf).
#[tokio::test]
async fn a_backlogged_peer_is_closed_and_announced_as_gone() {
    let mut cfg = cfg_with(30_000, 0);
    cfg.max_queued_bytes_per_conn = 256 * 1024;
    cfg.frames_per_conn_per_sec = 100_000;
    cfg.bytes_per_conn_per_sec = 1 << 30;
    let s = spawn(cfg).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    let (mut slow, ack) = join_with(&s, &k, json!({})).await;
    let slow_id = ack["peer_id"].as_str().unwrap().to_string();

    // The slow peer reads one frame per 20 ms and then waits for the stream
    // to end, which it only does if the server closes the connection.
    let slow_reader = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            match slow.next().await {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(_)) => {}
            }
        }
    });

    let hex = k.hex.clone();
    let flood = tokio::spawn(async move {
        let payload = vec![0xAAu8; 32 * 1024];
        for _ in 0..4000 {
            if a.send(frame(&hex, 0x06, 0, &payload)).await.is_err() {
                break;
            }
            // Paced, so B (which reads at full speed) keeps up.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        a
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let leave = loop {
        match tokio::time::timeout_at(deadline, b.next()).await {
            Ok(Some(Ok(Message::Binary(m)))) if m.len() >= 4 && m[3] == 0x08 => break m,
            Ok(Some(Ok(_))) => {}
            other => panic!("no PEER_LEAVE for the backlogged peer: {other:?}"),
        }
    };
    assert_eq!(json_body(&leave)["peer_id"].as_str().unwrap(), slow_id);
    flood.abort();

    let closed = tokio::time::timeout(Duration::from_secs(30), slow_reader).await;
    assert!(closed.is_ok(), "the backlogged peer's connection stayed open");
}

/// Two members step the room to the same next epoch at the same moment, many
/// times over. Whichever the server decides first wins, and every member must
/// see that step first: nobody may be wrapped in the one that lost.
#[tokio::test]
async fn racing_steps_reach_every_peer_in_the_order_the_server_decided() {
    let s = spawn(cfg_with(30_000, 0)).await;
    let k = create(&s).await;
    let (mut a, _) = join_with(&s, &k, json!({})).await;
    let (mut b, _) = join_with(&s, &k, json!({})).await;
    let (mut c, _) = join_with(&s, &k, json!({})).await;
    for round in 1u32..=60 {
        let (fa, fb) = (
            frame(&k.hex, 0x20, round, format!("{round}-a").as_bytes()),
            frame(&k.hex, 0x20, round, format!("{round}-b").as_bytes()),
        );
        let _ = tokio::join!(a.send(fa), b.send(fb));
        let mut firsts = Vec::new();
        for ws in [&mut a, &mut b, &mut c] {
            let seen = frames_of(ws, 0x20, 40).await;
            let mine: Vec<&Vec<u8>> = seen.iter().filter(|f| epoch_of(f) == round).collect();
            assert!(!mine.is_empty(), "round {round}: a peer saw no step");
            firsts.push(mine[0][48..].to_vec());
        }
        assert!(
            firsts.iter().all(|f| f == &firsts[0]),
            "round {round}: peers saw different steps first: {firsts:?}"
        );
    }
}
