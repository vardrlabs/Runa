//! The per-connection frame-rate and byte-rate limits, over a real websocket.
//!
//! Both limiters hold a single key in a table of one, and until this was
//! fixed eviction emptied that table on every call: each frame got a full
//! bucket and neither limit ever refused anything. These tests pin that a
//! connection flooding past either limit is closed with 4002, and that one
//! inside its limits is left alone.
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

const FT_JOIN: u8 = 0x01;
const FT_JOIN_ACK: u8 = 0x02;
const FT_PING: u8 = 0x17;
const FT_PONG: u8 = 0x18;
const RATE_LIMITED: u16 = 4002;

async fn spawn(cfg: runa_server::config::Config) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = runa_server::AppState::new(cfg);
    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

/// Small limits, so a test can cross them with a few frames: 10 frames a
/// second with a burst of 20, and 16 KiB a second with a burst of 32 KiB.
fn small_limits() -> runa_server::config::Config {
    runa_server::config::Config {
        auth_floor: Duration::from_millis(10),
        dist_dir: "/nonexistent".into(),
        frames_per_conn_per_sec: 10,
        bytes_per_conn_per_sec: 16 * 1024,
        ..Default::default()
    }
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

fn header(room_hex: &str, ft: u8) -> Vec<u8> {
    [0x52u8, 0x55, 0x01, ft]
        .into_iter()
        .chain(hex::decode(room_hex).unwrap())
        .chain([0u8; 4])
        .chain([1u8, 2, 3, 4])
        .chain([0u8; 4])
        .collect()
}

/// A PING padded with `pad` bytes the server ignores, so one frame can cost
/// as many bytes as a test needs.
fn ping(room_hex: &str, pad: usize) -> Message {
    let mut f = header(room_hex, FT_PING);
    f.resize(f.len() + pad, 0);
    Message::Binary(f.into())
}

/// Creates a room and joins one peer that asked for PONGs.
async fn joined_peer(server: &str) -> (Ws, String) {
    let auth_key: [u8; 32] = rand_bytes();
    let salt: [u8; 16] = rand_bytes();
    let verifier: [u8; 32] = Sha256::digest(auth_key).into();
    let resp = reqwest::Client::new()
        .post(format!("{server}/api/rooms/unlisted"))
        .json(&json!({
            "verifier": B64.encode(verifier),
            "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
            "ttl": { "kind": "idle-peers", "secs": 3600 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    let room = body["room_id"].as_str().unwrap().to_string();

    let url = format!("{}/socket/{room}", server.replacen("http://", "ws://", 1));
    let (mut ws, _) =
        tokio_tungstenite::connect_async(url.into_client_request().unwrap()).await.unwrap();
    let mut join = header(&room, FT_JOIN);
    let pubkey: [u8; 32] = rand_bytes();
    let body = json!({
        "auth_key": B64.encode(auth_key),
        "pubkey": B64.encode(pubkey),
        "heartbeat": true,
    });
    join.extend_from_slice(body.to_string().as_bytes());
    ws.send(Message::Binary(join.into())).await.unwrap();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for JOIN_ACK")
            .expect("stream ended before JOIN_ACK")
            .unwrap();
        if let Message::Binary(b) = msg {
            assert_eq!(b[3], FT_JOIN_ACK, "expected JOIN_ACK, got {:#x}", b[3]);
            return (ws, room);
        }
    }
}

/// Sends up to `n` padded PINGs one at a time, each after the PONG for the
/// one before, and stops at the first close. Returns the PONG count and the
/// close code.
///
/// Lockstep is still a flood: on loopback a round trip takes well under a
/// millisecond, so this runs at thousands of frames a second. It also means
/// the server never closes with frames of ours still unread, which would make
/// the kernel reset the connection and could discard the close frame before
/// it is read. Waiting for an expected close is bounded by a timeout.
async fn send_and_watch(mut ws: Ws, room: &str, n: usize, pad: usize) -> (usize, Option<u16>) {
    let frame = ping(room, pad);
    let mut pongs = 0;
    for _ in 0..n {
        if ws.send(frame.clone()).await.is_err() {
            break;
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                Err(_) => panic!("neither a PONG nor a close within 5s, after {pongs} PONGs"),
                Ok(Some(Ok(Message::Binary(b)))) if b[3] == FT_PONG => {
                    pongs += 1;
                    break;
                }
                Ok(Some(Ok(Message::Close(c)))) => return (pongs, c.map(|c| u16::from(c.code))),
                Ok(None) | Ok(Some(Err(_))) => return (pongs, None),
                Ok(Some(Ok(_))) => {}
            }
        }
    }
    (pongs, None)
}

#[tokio::test]
async fn a_connection_flooding_past_its_frame_limit_is_closed_with_4002() {
    let server = spawn(small_limits()).await;
    let (ws, room) = joined_peer(&server).await;
    // 200 empty frames: ten times the burst of 20, and 6.4 KB, far under the
    // byte burst, so only the frame limit can be what refuses.
    let (pongs, code) = send_and_watch(ws, &room, 200, 0).await;
    assert_eq!(code, Some(RATE_LIMITED), "flood was not closed as rate limited");
    // The burst is honoured and the flood is cut off early. How many frames
    // past the burst get through depends on how fast the machine refills.
    assert!((20..100).contains(&pongs), "{pongs} of 200 frames answered against a burst of 20");
}

#[tokio::test]
async fn a_connection_flooding_past_its_byte_limit_is_closed_with_4002() {
    let server = spawn(small_limits()).await;
    let (ws, room) = joined_peer(&server).await;
    // Fifteen 4 KiB frames: under the frame burst of 20, and 60 KiB against
    // a byte burst of 32 KiB, so only the byte limit can be what refuses.
    let (pongs, code) = send_and_watch(ws, &room, 15, 4096).await;
    assert_eq!(code, Some(RATE_LIMITED), "byte flood was not closed as rate limited");
    assert!((7..15).contains(&pongs), "{pongs} of 15 frames of 4 KiB answered against a burst of 32 KiB");
}

#[tokio::test]
async fn a_connection_inside_its_limits_is_left_open() {
    let server = spawn(small_limits()).await;
    let (ws, room) = joined_peer(&server).await;
    let (mut sink, mut stream) = ws.split();
    // Fifteen frames of 1 KiB at once, inside both bursts, then a steady
    // five a second for two seconds, half the sustained frame rate and well
    // under the byte rate.
    for _ in 0..15 {
        sink.send(ping(&room, 1024)).await.unwrap();
    }
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        sink.send(ping(&room, 1024)).await.unwrap();
    }
    let mut pongs = 0;
    while pongs < 25 {
        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
            Err(_) => panic!("only {pongs} of 25 PONGs arrived"),
            Ok(Some(Ok(Message::Binary(b)))) if b[3] == FT_PONG => pongs += 1,
            Ok(Some(Ok(Message::Close(c)))) => panic!("closed inside its limits: {c:?}"),
            Ok(None) | Ok(Some(Err(_))) => panic!("socket ended inside its limits"),
            Ok(Some(Ok(_))) => {}
        }
    }
    // Nothing more is expected: a fixed window only to show no close comes.
    match tokio::time::timeout(Duration::from_millis(300), stream.next()).await {
        Err(_) => {}
        Ok(Some(Ok(Message::Close(c)))) => panic!("closed inside its limits: {c:?}"),
        Ok(other) => panic!("unexpected frame after the last PONG: {other:?}"),
    }
    drop(sink);
}
