use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use runa_server::build_router;
use runa_server::sha2::{Digest, Sha256};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn spawn_server() -> String {
    spawn_server_with(test_config()).await
}

async fn spawn_server_with(cfg: runa_server::config::Config) -> String {
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

fn test_config() -> runa_server::config::Config {
    runa_server::config::Config {
        auth_floor: Duration::from_millis(120),
        dist_dir: "/nonexistent".into(),
        ..runa_server::config::Config::default()
    }
}

fn random_room_id() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap();
    b
}

struct RoomKeys {
    room_id_hex: String,
    auth_key: [u8; 32],
    salt: [u8; 16],
}

fn verifier_for(key: &[u8; 32]) -> String {
    let h: [u8; 32] = Sha256::digest(key).into();
    B64.encode(h)
}

async fn create_room(server: &str) -> RoomKeys {
    let client = reqwest::Client::new();
    let auth_key: [u8; 32] = rand_bytes_32();
    let salt: [u8; 16] = {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).unwrap();
        s
    };
    let resp = client
        .post(format!("{server}/api/rooms/unlisted"))
        .json(&json!({
            "verifier": verifier_for(&auth_key),
            "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
            "ttl": { "kind": "idle-peers", "secs": 3600 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "room creation failed: {}", resp.status());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    // Unlisted ids are assigned by the server so creation cannot be used to
    // probe which ids are live.
    RoomKeys { room_id_hex: body["room_id"].as_str().unwrap().to_string(), auth_key, salt }
}

fn rand_bytes_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

fn join_frame(room_hex: &str, auth_key: Option<&[u8; 32]>, pubkey: &[u8; 32]) -> Message {
    let header = [
        0x52u8, 0x55, 0x01, 0x01,
    ]
    .iter()
    .copied()
    .chain(hex::decode(room_hex).unwrap())
    .chain([0u8; 4])
    .chain([1u8, 2, 3, 4])
    .chain([0u8; 4])
    .collect::<Vec<u8>>();
    let body = json!({
        "auth_key": auth_key.map(|k| B64.encode(k)),
        "pubkey": B64.encode(pubkey),
    });
    let mut frame = header;
    frame.extend_from_slice(body.to_string().as_bytes());
    Message::Binary(frame.into())
}

fn doc_update_frame(room_hex: &str, payload: &[u8]) -> Message {
    let header = [
        0x52u8, 0x55, 0x01, 0x03,
    ]
    .iter()
    .copied()
    .chain(hex::decode(room_hex).unwrap())
    .chain(0u32.to_be_bytes())
    .chain([9u8, 9, 9, 9])
    .chain(1u32.to_be_bytes())
    .collect::<Vec<u8>>();
    let mut frame = header;
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&[0xAB; 16]);
    Message::Binary(frame.into())
}


async fn next_frame_of(ws: &mut Ws, ft: u8) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for frame type {ft:#x}");
        }
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out")
            .expect("stream ended")
            .unwrap();
        if let Message::Binary(bytes) = msg {
            if bytes.len() >= 4 && bytes[3] == ft {
                return bytes.to_vec();
            }
        }
    }
}

async fn connect(server: &str, room_hex: &str) -> Ws {
    let url = format!("{}/socket/{room_hex}", server.replacen("http://", "ws://", 1));
    let request = url.into_client_request().unwrap();
    let (ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws
}

async fn recv_json(ws: &mut Ws) -> (u8, Value) {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for frame")
            .expect("stream ended")
            .unwrap();
        match msg {
            Message::Binary(bytes) => {
                assert_eq!(&bytes[..2], b"RU");
                let ft = bytes[3];
                let v: Value =
                    serde_json::from_slice(&bytes[32..]).unwrap_or(Value::Null);
                return (ft, v);
            }
            Message::Close(_) => panic!("unexpected close"),
            _ => continue,
        }
    }
}

#[tokio::test]
async fn join_requires_correct_auth_key_and_fails_generically() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;

    let wrong: [u8; 32] = rand_bytes_32();
    let mut ws = connect(&server, &keys.room_id_hex).await;
    let start = Instant::now();
    ws.send(join_frame(&keys.room_id_hex, Some(&wrong), &[7u8; 32]))
        .await
        .unwrap();
    let (ft, v) = recv_json(&mut ws).await;
    let elapsed = start.elapsed();
    assert_eq!(ft, 0x30);
    assert_eq!(v["code"], 4001);

    let missing_room = hex::encode(random_room_id());
    let mut ws2 = connect(&server, &missing_room).await;
    ws2.send(join_frame(&missing_room, Some(&wrong), &[7u8; 32]))
        .await
        .unwrap();
    let started = Instant::now();
    let (ft2, v2) = recv_json(&mut ws2).await;
    let elapsed_missing = started.elapsed();
    assert_eq!(ft2, 0x30);
    assert_eq!(v2["code"], 4001);
    assert!(
        elapsed >= Duration::from_millis(100) && elapsed_missing >= Duration::from_millis(100),
        "auth floor violated: existing={elapsed:?} missing={elapsed_missing:?}"
    );
}

#[tokio::test]
async fn join_ack_contains_roster_kdf_and_ttl() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;
    let mut ws = connect(&server, &keys.room_id_hex).await;
    let pubkey: [u8; 32] = rand_bytes_32();
    ws.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &pubkey))
        .await
        .unwrap();
    let (ft, v) = recv_json(&mut ws).await;
    assert_eq!(ft, 0x02);
    assert_eq!(v["epoch"], 0);
    assert_eq!(v["log_len"], 0);
    assert_eq!(v["base_index"], 0);
    assert_eq!(v["ttl"]["kind"], "idle-peers");
    assert_eq!(v["kdf"]["m_kib"], 65536);
    assert_eq!(v["kdf"]["salt"], B64.encode(keys.salt));
    let roster = v["roster"].as_array().unwrap();
    assert_eq!(roster.len(), 1);
    assert_eq!(roster[0]["pubkey"], B64.encode(pubkey));
}

#[tokio::test]
async fn frames_relay_between_peers_with_sender_envelope() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;

    let mut a = connect(&server, &keys.room_id_hex).await;
    a.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[1u8; 32]))
        .await
        .unwrap();
    let (_, ack_a) = recv_json(&mut a).await;
    let peer_a = ack_a["peer_id"].as_str().unwrap().to_string();

    let mut b = connect(&server, &keys.room_id_hex).await;
    b.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[2u8; 32]))
        .await
        .unwrap();
    let (_, ack_b) = recv_json(&mut b).await;
    let peer_b = ack_b["peer_id"].as_str().unwrap().to_string();
    assert_ne!(peer_a, peer_b);

    let (ft_join, _) = recv_json(&mut a).await;
    assert_eq!(ft_join, 0x07, "peer A should see PEER_JOIN");

    let payload = b"ciphertext-not-inspected-by-server";
    b.send(doc_update_frame(&keys.room_id_hex, payload)).await.unwrap();

    let bytes = next_frame_of(&mut a, 0x03).await;
    assert_eq!(bytes[3], 0x03);
    use base64::Engine as _;
    let sender_decoded = B64.decode(peer_b.as_bytes()).unwrap();
    assert_eq!(&bytes[32..48], sender_decoded.as_slice(), "envelope must carry sender id");
    assert_eq!(&bytes[48..56], &(payload.len() as u64).to_be_bytes());
    assert_eq!(&bytes[56..56 + payload.len()], payload);
}

#[tokio::test]
async fn late_joiner_syncs_from_log_and_snapshot_truncates() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;

    let mut writer = connect(&server, &keys.room_id_hex).await;
    writer
        .send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[3u8; 32]))
        .await
        .unwrap();
    let _ = recv_json(&mut writer).await;

    for i in 0..3u8 {
        writer.send(doc_update_frame(&keys.room_id_hex, &[i; 40])).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    let snapshot_header = [
        0x52u8, 0x55, 0x01, 0x21,
    ]
    .iter()
    .copied()
    .chain(hex::decode(&keys.room_id_hex).unwrap())
    .chain(0u32.to_be_bytes())
    .chain([9u8, 9, 9, 9])
    .chain(0u32.to_be_bytes())
    .collect::<Vec<u8>>();
    let mut snap = snapshot_header;
    snap.extend_from_slice(&3u64.to_be_bytes());
    snap.extend_from_slice(b"SNAPSHOT-BLOB-SUPERCEDING-0-TO-3-XXXXXXXXXXXX");
    writer.send(Message::Binary(snap.into())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    writer.send(doc_update_frame(&keys.room_id_hex, &[99; 20])).await.unwrap();

    let mut late = connect(&server, &keys.room_id_hex).await;
    late.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[4u8; 32]))
        .await
        .unwrap();
    let (_, ack) = recv_json(&mut late).await;
    assert_eq!(ack["has_snapshot"], true);
    assert_eq!(ack["log_len"], 4);
    assert_eq!(ack["base_index"], 3);

    late.send(Message::Binary(
        {
            let h = [
                0x52u8, 0x55, 0x01, 0x04,
            ]
            .iter()
            .copied()
            .chain(hex::decode(&keys.room_id_hex).unwrap())
            .chain([0u8; 12])
            .collect::<Vec<u8>>();
            let mut f = h;
            f.extend_from_slice(br#"{"from_index":0}"#);
            f
        }
        .into(),
    ))
    .await
    .unwrap();

    let snap_bytes = next_frame_of(&mut late, 0x21).await;
    let covers = u64::from_be_bytes([
        snap_bytes[48], snap_bytes[49], snap_bytes[50], snap_bytes[51],
        snap_bytes[52], snap_bytes[53], snap_bytes[54], snap_bytes[55],
    ]);
    assert_eq!(covers, 3, "snapshot must carry covers=3");

    let tail_bytes = next_frame_of(&mut late, 0x03).await;
    assert_eq!(&tail_bytes[56..76], &[99u8; 20], "tail update content");
    assert!(snap_bytes.windows(10).any(|w| w == b"SNAPSHOT-B"));
}

#[tokio::test]
async fn named_room_without_passphrase_is_refused_at_api() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    let salt: [u8; 16] = {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).unwrap();
        s
    };
    let resp = client
        .post(format!("{server}/api/rooms/named"))
        .json(&json!({
            "name": "copper-lantern",
            "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
            "ttl": { "kind": "idle-peers", "secs": 3600 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 422, "named rooms MUST require a passphrase");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "PASSPHRASE_REQUIRED");
}

#[tokio::test]
async fn named_room_lifecycle_with_passphrase() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    // The server never sees a passphrase: the browser stretches it with
    // Argon2id and sends only the verifier of the resulting auth key. A random
    // key is what reaches the server. Hashing a passphrase with one SHA-256
    // here modelled nothing real, and read as weak password hashing.
    let auth_key: [u8; 32] = {
        let mut k = [0u8; 32];
        getrandom::fill(&mut k).unwrap();
        k
    };
    let salt: [u8; 16] = {
        let mut s = [0u8; 16];
        getrandom::fill(&mut s).unwrap();
        s
    };
    let resp = client
        .post(format!("{server}/api/rooms/named"))
        .json(&json!({
            "name": "copper-lantern",
            "suffix": false,
            "verifier": verifier_for(&auth_key),
            "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
            "ttl": { "kind": "idle-peers", "secs": 3600 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["name"], "copper-lantern");

    let resolve: Value = client
        .post(format!("{server}/api/names/resolve"))
        .json(&json!({ "name": "Copper-Lantern" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resolve["found"], true);
    assert_eq!(resolve["room_id"], created["room_id"]);
    assert_eq!(resolve["kdf"]["salt"], B64.encode(salt));

    let dup = client
        .post(format!("{server}/api/rooms/named"))
        .json(&json!({
            "name": "copper-lantern",
            "suffix": false,
            "verifier": verifier_for(&rand_bytes_32()),
            "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
            "ttl": { "kind": "idle-peers", "secs": 3600 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 409);
    assert_eq!(dup.json::<Value>().await.unwrap()["code"], 4012);

    let single_word = client
        .post(format!("{server}/api/rooms/named"))
        .json(&json!({
            "name": "standup",
            "verifier": verifier_for(&rand_bytes_32()),
            "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
            "ttl": { "kind": "idle-peers", "secs": 3600 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(single_word.status(), 400);

    let squatter_auth: [u8; 32] = rand_bytes_32();
    let mut ws = connect(&server, resolve["room_id"].as_str().unwrap()).await;
    ws.send(join_frame(resolve["room_id"].as_str().unwrap(), Some(&squatter_auth), &[9u8; 32]))
        .await
        .unwrap();
    let (ft, v) = recv_json(&mut ws).await;
    assert_eq!(ft, 0x30);
    assert_eq!(v["code"], 4001, "squatter must fail auth, never silently join");
}

#[tokio::test]
async fn meta_endpoint_hides_existence_shape_and_content() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    let keys = create_room(&server).await;

    let real: Value = client
        .get(format!("{server}/api/meta/id/{}", keys.room_id_hex))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(real["exists"], true);
    assert_eq!(real["requires_auth"], true);
    assert_eq!(real["kdf"]["salt"], B64.encode(keys.salt));

    let ghost_id = hex::encode(random_room_id());
    let ghost: Value = client
        .get(format!("{server}/api/meta/id/{ghost_id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ghost.as_object().unwrap().keys().collect::<Vec<_>>(),
        real.as_object().unwrap().keys().collect::<Vec<_>>(),
        "identical response shape required"
    );
    assert_eq!(ghost["exists"], true);
    assert_ne!(ghost["kdf"]["salt"], real["kdf"]["salt"]);

    let short: Value = client
        .get(format!("{server}/api/meta/id/tooshort"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(short["exists"], true, "even malformed ids get the same shape");
}

#[tokio::test]
async fn oversized_frame_is_closed_with_4004() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;
    let mut ws = connect(&server, &keys.room_id_hex).await;
    ws.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[5u8; 32]))
        .await
        .unwrap();
    let _ = recv_json(&mut ws).await;

    // Sized from the config rather than hardcoded: this used to be 300 KiB
    // against a 256 KiB cap, so raising the cap for snapshot headroom made a
    // correctness test silently start passing an oversized frame as normal.
    let cap = test_config().max_frame_bytes;
    let big_payload = vec![0xEE; cap + 4096];
    ws.send(doc_update_frame(&keys.room_id_hex, &big_payload)).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(m) = ws.next().await {
            if let Ok(Message::Close(f)) = m {
                return f.map(|f| f.code);
            }
        }
        None
    })
    .await
    .unwrap();
    assert_eq!(result, Some(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(4004)));
}

// The peer cap (max_peers_per_room) is enforced by Room::add_peer and
// unit-tested in room.rs's purge_ack_tests module. A full end-to-end test
// would require spawning 33 WebSocket connections, which adds complexity
// without testing anything the unit test doesn't already cover.

/// Deploying behind a reverse proxy makes every request arrive from the
/// loopback address. Without `trusted_proxy`, every per-IP limit therefore
/// collapses into a single shared bucket and the server stops serving new
/// users long before it should. These two tests pin both directions.
mod behind_a_reverse_proxy {
    use super::*;

    fn proxied_config(trusted_proxy: bool) -> runa_server::config::Config {
        runa_server::config::Config {
            auth_floor: Duration::from_millis(1),
            dist_dir: "/nonexistent".into(),
            rooms_created_per_ip_per_hour: 3,
            trusted_proxy,
            ..runa_server::config::Config::default()
        }
    }

    async fn create_as(server: &str, forwarded_for: &str) -> reqwest::StatusCode {
        let auth_key: [u8; 32] = rand_bytes_32();
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).unwrap();
        reqwest::Client::new()
            .post(format!("{server}/api/rooms/unlisted"))
            .header("X-Forwarded-For", forwarded_for)
            .json(&json!({
                "id": hex::encode(random_room_id()),
                "verifier": verifier_for(&auth_key),
                "kdf": { "m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode(salt) },
                "ttl": { "kind": "idle-peers", "secs": 3600 },
            }))
            .send()
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn distinct_clients_get_distinct_buckets() {
        let server = spawn_server_with(proxied_config(true)).await;
        // The limit is 3 per client per hour. Six different clients, two
        // requests each, must all succeed: nobody has exceeded their own bar.
        for client in 0..6u8 {
            let ip = format!("203.0.113.{client}");
            for attempt in 0..2 {
                let status = create_as(&server, &ip).await;
                assert_eq!(
                    status, 201,
                    "client {ip} attempt {attempt} was refused; buckets are shared"
                );
            }
        }
    }

    #[tokio::test]
    async fn one_client_still_hits_its_own_limit() {
        let server = spawn_server_with(proxied_config(true)).await;
        for _ in 0..3 {
            assert_eq!(create_as(&server, "198.51.100.7").await, 201);
        }
        assert_eq!(
            create_as(&server, "198.51.100.7").await,
            429,
            "a single client must still be limited"
        );
        // A forged prefix must not mint a fresh bucket: the proxy-appended
        // address is the rightmost entry and that is what we key on.
        assert_eq!(
            create_as(&server, "1.2.3.4, 198.51.100.7").await,
            429,
            "prepending a fake hop bypassed the limiter"
        );
        // An unrelated client is unaffected.
        assert_eq!(create_as(&server, "198.51.100.8").await, 201);
    }

    #[tokio::test]
    async fn header_is_ignored_when_no_proxy_is_declared() {
        let server = spawn_server_with(proxied_config(false)).await;
        for _ in 0..3 {
            assert_eq!(create_as(&server, "203.0.113.1").await, 201);
        }
        assert_eq!(
            create_as(&server, "203.0.113.99").await,
            429,
            "X-Forwarded-For must be ignored unless RUNA_TRUSTED_PROXY is set"
        );
    }
}

/// A room that exists and a room that does not must be indistinguishable from
/// their metadata.
///
/// What this can and cannot show: with creation pinned to the canonical
/// parameters, no room can diverge from the ghost branch, so this passes
/// whether or not the pin is in place. It is the invariant, not the proof —
/// `creation_refuses_non_canonical_kdf_parameters` is the test that fails when
/// the pin is removed. Kept because it states what the two branches owe each
/// other, and because the existing meta test compares the response *shape*,
/// key names only, which is exactly how a difference in the values went
/// unnoticed. The endpoint already matches the shape, the delay and the
/// salt — a deterministic HMAC under a boot-time key, so the ghost salt cannot
/// be computed offline — but it echoed the room's own KDF parameters while the
/// ghost branch answered with hardcoded defaults, and creation accepted a
/// range rather than a constant. Any room not on the stock parameters was then
/// distinguishable from a missing one by its own metadata.
#[tokio::test]
async fn unlisted_meta_cannot_distinguish_a_real_room_from_a_missing_one() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;
    let client = reqwest::Client::new();

    let real: Value = client
        .get(format!("{server}/api/meta/id/{}", keys.room_id_hex))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ghost: Value = client
        .get(format!("{server}/api/meta/id/{}", "f".repeat(32)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(real["exists"], ghost["exists"], "existence flag must match");
    assert_eq!(real["requires_auth"], ghost["requires_auth"]);
    for field in ["alg", "m_kib", "t", "p"] {
        assert_eq!(
            real["kdf"][field], ghost["kdf"][field],
            "kdf.{field} differs between a real room and a ghost, which discloses existence",
        );
    }
    // The salts must differ — a shared one would be its own giveaway — but
    // both must be 16 bytes so length cannot separate them either.
    assert_ne!(real["kdf"]["salt"], ghost["kdf"]["salt"]);
    for v in [&real, &ghost] {
        let salt = B64.decode(v["kdf"]["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salt.len(), 16);
    }
}

/// Creation takes the canonical parameters and nothing else. A room created
/// with anything different would answer differently from a ghost, which is the
/// oracle above.
#[tokio::test]
async fn creation_refuses_non_canonical_kdf_parameters() {
    let server = spawn_server().await;
    let client = reqwest::Client::new();
    // Inside the range the server used to accept, and still not allowed.
    for (m, t, p) in [(131_072u32, 3u32, 1u32), (65_536, 4, 1), (65_536, 3, 2)] {
        let res = client
            .post(format!("{server}/api/rooms/unlisted"))
            .json(&json!({
                // A real-looking verifier. An all-identical one is refused by
                // plausible_verifier, which would make this pass on a 400 that
                // has nothing to do with the KDF parameters under test.
                "verifier": verifier_for(&rand_bytes_32()),
                "kdf": { "m_kib": m, "t": t, "p": p, "salt": B64.encode(&rand_bytes_32()[..16]) },
                "ttl": { "kind": "idle-peers", "secs": 3600 },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            400,
            "m_kib={m} t={t} p={p} was accepted; it would then be distinguishable from a ghost",
        );
    }
}

fn join_frame_with_acks(room_hex: &str, auth_key: &[u8; 32], pubkey: &[u8; 32]) -> Message {
    let mut frame = [0x52u8, 0x55, 0x01, 0x01]
        .iter()
        .copied()
        .chain(hex::decode(room_hex).unwrap())
        .chain([0u8; 4])
        .chain([1u8, 2, 3, 4])
        .chain([0u8; 4])
        .collect::<Vec<u8>>();
    let body = json!({
        "auth_key": B64.encode(auth_key),
        "pubkey": B64.encode(pubkey),
        "acks": true,
    });
    frame.extend_from_slice(&serde_json::to_vec(&body).unwrap());
    Message::Binary(frame.into())
}

/// An edit is only safe once the server has stored it. Without an ack the
/// client cannot tell a frame that arrived from one written into a connection
/// that had already died, so it could never know what to send again.
#[tokio::test]
async fn doc_updates_are_acknowledged_to_their_sender_in_order_when_asked() {
    let server = spawn_server().await;
    let keys = create_room(&server).await;

    let mut a = connect(&server, &keys.room_id_hex).await;
    a.send(join_frame_with_acks(&keys.room_id_hex, &keys.auth_key, &[1u8; 32]))
        .await
        .unwrap();
    let (ft, ack) = recv_json(&mut a).await;
    assert_eq!(ft, 0x02);
    assert_eq!(ack["acks"], true);
    let cfg = test_config();
    assert_eq!(ack["limits"]["max_frame_bytes"], cfg.max_frame_bytes as u64);
    assert_eq!(ack["limits"]["frames_per_sec"], cfg.frames_per_conn_per_sec as u64);
    assert_eq!(ack["limits"]["bytes_per_sec"], cfg.bytes_per_conn_per_sec);

    // A client that did not ask is told nothing and sent nothing new.
    let mut b = connect(&server, &keys.room_id_hex).await;
    b.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[2u8; 32]))
        .await
        .unwrap();
    let (_, ack_b) = recv_json(&mut b).await;
    assert!(ack_b.get("acks").is_none(), "acks advertised to a client that never asked");
    assert!(ack_b.get("limits").is_none());

    for i in 0..3u8 {
        a.send(doc_update_frame(&keys.room_id_hex, &[i; 40])).await.unwrap();
    }
    let mut indices = Vec::new();
    for _ in 0..3 {
        let bytes = next_frame_of(&mut a, 0x09).await;
        assert_eq!(&bytes[20..24], &[0u8; 4], "server-authored frames carry epoch 0");
        let v: Value = serde_json::from_slice(&bytes[32..]).expect("DOC_ACK is unenveloped JSON");
        assert_eq!(v["ok"], true);
        indices.push(v["index"].as_u64().expect("a stored update reports its log index"));
    }
    assert!(
        indices.windows(2).all(|w| w[1] == w[0] + 1),
        "acks must arrive in send order: {indices:?}"
    );

    // The other peer receives the updates themselves, never the acks.
    for _ in 0..3 {
        let _ = next_frame_of(&mut b, 0x03).await;
    }
    b.send(doc_update_frame(&keys.room_id_hex, &[9; 40])).await.unwrap();
    let _ = next_frame_of(&mut a, 0x03).await;
    let b_got_ack = tokio::time::timeout(Duration::from_millis(600), async {
        while let Some(Ok(msg)) = b.next().await {
            if let Message::Binary(bytes) = msg {
                if bytes.len() >= 4 && bytes[3] == 0x09 {
                    return true;
                }
            }
        }
        false
    })
    .await;
    assert!(!matches!(b_got_ack, Ok(true)), "DOC_ACK sent to a client that never asked for it");
}

/// A full log refused the update with an ERROR frame the client could not tie
/// to any particular edit. The ack says which one, so the client can stop
/// retrying something that will never be stored.
#[tokio::test]
async fn an_update_the_log_cannot_hold_is_acknowledged_as_not_stored() {
    let cfg = runa_server::config::Config { max_log_bytes: 8192, ..test_config() };
    let server = spawn_server_with(cfg).await;
    let keys = create_room(&server).await;
    let mut a = connect(&server, &keys.room_id_hex).await;
    a.send(join_frame_with_acks(&keys.room_id_hex, &keys.auth_key, &[3u8; 32]))
        .await
        .unwrap();
    let _ = recv_json(&mut a).await;

    let mut refused = false;
    for i in 0..32u8 {
        a.send(doc_update_frame(&keys.room_id_hex, &[i; 1024])).await.unwrap();
        let bytes = next_frame_of(&mut a, 0x09).await;
        let v: Value = serde_json::from_slice(&bytes[32..]).unwrap();
        if v["ok"] == false {
            assert!(v.get("index").is_none(), "an update that was not stored has no index");
            refused = true;
            break;
        }
    }
    assert!(refused, "a full log must say the update was not stored");
}

async fn spawn_server_state(cfg: runa_server::config::Config) -> (String, runa_server::AppState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = runa_server::AppState::new(cfg);
    let app = build_router(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    (format!("http://{addr}"), state)
}

async fn close_code(ws: &mut Ws) -> Option<u16> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(m) = ws.next().await {
            match m {
                Ok(Message::Close(f)) => return f.map(|f| u16::from(f.code)),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
        None
    })
    .await
    .unwrap_or(None)
}

/// A refused connection used to open and drop without a word, so the page
/// retried forever and nobody could see why. The cap is also on connections
/// held, not ever made.
#[tokio::test]
async fn a_connection_over_the_per_address_limit_is_refused_with_a_code_the_page_can_show() {
    let cfg = runa_server::config::Config { max_conns_per_ip: 2, ..test_config() };
    let server = spawn_server_with(cfg).await;
    let keys = create_room(&server).await;
    let mut held = Vec::new();
    for pk in [1u8, 2] {
        let mut ws = connect(&server, &keys.room_id_hex).await;
        ws.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[pk; 32]))
            .await
            .unwrap();
        let (ft, _) = recv_json(&mut ws).await;
        assert_eq!(ft, 0x02);
        held.push(ws);
    }
    let mut extra = connect(&server, &keys.room_id_hex).await;
    assert_eq!(
        close_code(&mut extra).await,
        Some(4007),
        "a connection past the per-address limit must be refused, and say why"
    );

    let mut first = held.remove(0);
    first.close(None).await.unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut again = connect(&server, &keys.room_id_hex).await;
    again
        .send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[3u8; 32]))
        .await
        .unwrap();
    let (ft, _) = recv_json(&mut again).await;
    assert_eq!(ft, 0x02, "a slot freed by a closed connection must be usable again");
}

#[tokio::test]
async fn a_connection_over_the_server_ceiling_is_refused_with_its_own_code() {
    let cfg = runa_server::config::Config { max_connections: 1, ..test_config() };
    let server = spawn_server_with(cfg).await;
    let keys = create_room(&server).await;
    let mut a = connect(&server, &keys.room_id_hex).await;
    a.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[1u8; 32]))
        .await
        .unwrap();
    let (ft, _) = recv_json(&mut a).await;
    assert_eq!(ft, 0x02);
    let mut b = connect(&server, &keys.room_id_hex).await;
    assert_eq!(close_code(&mut b).await, Some(4008));
}

/// Rooms live only in memory, so a restart ends every one. It used to do so
/// in silence, mid-session.
#[tokio::test]
async fn a_restart_warns_open_rooms_and_new_joins_and_stops_creating_rooms() {
    let (server, state) = spawn_server_state(test_config()).await;
    let keys = create_room(&server).await;
    let mut a = connect(&server, &keys.room_id_hex).await;
    a.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[1u8; 32]))
        .await
        .unwrap();
    let _ = recv_json(&mut a).await;

    assert_eq!(state.begin_restart(Duration::from_secs(30)).await, 1);
    let bytes = next_frame_of(&mut a, 0x15).await;
    assert_eq!(&bytes[20..24], &[0u8; 4], "server-authored frames carry epoch 0");
    let v: Value = serde_json::from_slice(&bytes[32..]).expect("the notice is unenveloped JSON");
    let secs = v["in_secs"].as_u64().unwrap();
    assert!((1..=30).contains(&secs), "in_secs={secs}");

    let mut b = connect(&server, &keys.room_id_hex).await;
    b.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[2u8; 32]))
        .await
        .unwrap();
    let (ft, _) = recv_json(&mut b).await;
    assert_eq!(ft, 0x02);
    let joined = next_frame_of(&mut b, 0x15).await;
    let v: Value = serde_json::from_slice(&joined[32..]).unwrap();
    assert!(v["in_secs"].as_u64().unwrap() <= 30, "someone joining mid-countdown is told at once");

    let r = reqwest::Client::new()
        .post(format!("{server}/api/rooms/unlisted"))
        .json(&json!({
            "verifier": B64.encode(rand_bytes_32()),
            "kdf": {"m_kib": 65536, "t": 3, "p": 1, "salt": B64.encode([0u8; 16])},
            "ttl": {"kind": "idle-peers", "secs": 60},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["code"], "RESTARTING");
}

/// The per-address join limit exists to slow guessing. It used to charge every
/// join, so the 31st connection in a minute from one shared address — an
/// office reconnecting after a blip — was refused with 4001, which the page
/// has to read as "this room is gone". Only failures may count.
#[tokio::test]
async fn successful_joins_do_not_use_up_the_per_address_guess_limit() {
    let cfg = runa_server::config::Config { auth_attempts_per_ip_per_min: 3, ..test_config() };
    let server = spawn_server_with(cfg).await;
    let keys = create_room(&server).await;
    for pk in 1u8..=6 {
        let mut ws = connect(&server, &keys.room_id_hex).await;
        ws.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[pk; 32]))
            .await
            .unwrap();
        let (ft, body) = recv_json(&mut ws).await;
        assert_eq!(ft, 0x02, "join {pk} of 6 with the right key was refused: {body}");
        ws.close(None).await.ok();
    }

    // Guessing is still limited: three wrong keys use the budget up, and
    // after that even the right key waits.
    for pk in 10u8..13 {
        let mut ws = connect(&server, &keys.room_id_hex).await;
        ws.send(join_frame(&keys.room_id_hex, Some(&rand_bytes_32()), &[pk; 32]))
            .await
            .unwrap();
        let (_, body) = recv_json(&mut ws).await;
        assert_eq!(body["code"], 4001);
    }
    let mut ws = connect(&server, &keys.room_id_hex).await;
    ws.send(join_frame(&keys.room_id_hex, Some(&keys.auth_key), &[20u8; 32]))
        .await
        .unwrap();
    let (_, body) = recv_json(&mut ws).await;
    assert_eq!(body["code"], 4001, "three failed guesses must still exhaust the budget");
}
