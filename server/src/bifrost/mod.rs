pub mod frame;
pub mod http;
pub mod limits;
pub mod onion;
pub mod router;

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::bifrost::frame::*;
use crate::runar::epoch::{Admit, Offer};
use crate::runar::room::{PeerKx, TtlKind};
use crate::error::WireCode;
use crate::gjallarhorn;
use crate::heimdall::ratelimit::RateLimiter;
use crate::heimdall::verifier;
use crate::runar::log::LogEntry;
use crate::runar::room::{
    JoinError, PurgeAckStatus, Room, RoomState,
};
use crate::surtr;
use crate::AppState;

const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Slot count only. The real bound on a peer's outbound queue is
/// `max_queued_bytes_per_conn`, enforced by `PeerTx` — 512 slots of
/// `max_frame_bytes` each would be 128 MiB that nothing accounts for.
const OUTBOUND_CAPACITY: usize = 512;

fn json_frame(room_id: [u8; 16], frame_type: u8, body: &impl Serialize) -> Bytes {
    let header = Header::new(frame_type, room_id, 0, [0; 4], 0);
    let mut raw = header.encode();
    raw.extend_from_slice(&serde_json::to_vec(body).expect("json serialisation cannot fail"));
    Bytes::from(raw)
}

/// A server-authored RESTART_NOTICE for one room (amendment F).
pub fn restart_notice(room_id: [u8; 16], body: &serde_json::Value) -> Bytes {
    json_frame(room_id, FT_RESTART_NOTICE, body)
}

fn error_frame(room_id: [u8; 16], code: WireCode) -> Bytes {
    json_frame(room_id, FT_ERROR, &serde_json::json!({ "code": u16::from(code) }))
}

async fn floor_delay(floor: Duration) {
    tokio::time::sleep(floor).await;
}

#[derive(Deserialize, Default)]
struct JoinBody {
    #[serde(default)]
    auth_key: Option<String>,
    #[serde(default)]
    pubkey: Option<String>,
    /// Ask for a DOC_ACK after every DOC_UPDATE this connection sends.
    #[serde(default)]
    acks: bool,
    /// Ask for the log index of every DOC_UPDATE relayed to this connection
    /// (amendment H).
    #[serde(default)]
    indexed: bool,
    /// This connection will send PING and wants PONG (amendment G).
    #[serde(default)]
    heartbeat: bool,
    /// This session's ECDH P-256 key and the session's signature over it
    /// (amendment J). Kept only when both are well formed.
    #[serde(default)]
    kx_pubkey: Option<String>,
    #[serde(default)]
    kx_sig: Option<String>,
}

/// What one connection negotiated in its JOIN. Each is off for a client that
/// did not ask, which then never receives a frame or field it does not know.
#[derive(Clone, Copy)]
struct Caps {
    acks: bool,
    heartbeat: bool,
}

#[derive(Serialize)]
struct RosterJson {
    peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pubkey: Option<String>,
    joined_at_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    kx_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kx_sig: Option<String>,
}

/// The limits a connection is held to, sent to a client that resends its
/// backlog so it can pace itself under them. Without this, a client coming
/// back from a long outage with hundreds of queued edits sends them at once,
/// trips the per-connection rate limit, is disconnected, reconnects, and sends
/// them all again — forever.
#[derive(Serialize)]
struct LimitsJson {
    max_frame_bytes: usize,
    frames_per_sec: u32,
    bytes_per_sec: u64,
}

#[derive(Serialize)]
struct JoinAck {
    peer_id: String,
    epoch: u32,
    root_epoch: u32,
    log_len: u64,
    base_index: u64,
    has_snapshot: bool,
    ttl: TtlJson,
    /// How long this room has been alive.
    ///
    /// For an absolute TTL the `ttl.secs` above is the time *remaining*, which
    /// is necessarily less than the duration the room was created with. The
    /// client holds that original duration in its AEAD-protected config blob
    /// and compared the two directly, so every 24-hour room reported the
    /// server as contradicting its own config within seconds of being made.
    ///
    /// With this the client reconstructs the total the server is claiming —
    /// remaining plus elapsed — and compares like with like. It is sent rather
    /// than derived from the client's own clock so that a difference between
    /// the two clocks cannot masquerade as tampering.
    elapsed_secs: u64,
    ceiling_optout: bool,
    kdf: KdfJson,
    /// True only when the JOIN asked for acks. A client that predates them
    /// never sees the field, and never receives a frame type it does not know.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    acks: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<LimitsJson>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    indexed: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    heartbeat: bool,
    /// Which log this is. A room brought back after a restart keeps its id
    /// and starts a new log, and a member that sees this change sends its
    /// whole copy again instead of resuming (amendment I).
    log_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_blob: Option<String>,
    roster: Vec<RosterJson>,
}

#[derive(Serialize)]
struct TtlJson {
    kind: &'static str,
    secs: u64,
}

#[derive(Serialize)]
struct KdfJson {
    alg: &'static str,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

/// Seconds left before the scheduler will sweep this room, from now. For
/// absolute TTLs that is the deadline minus elapsed time; for idle TTLs it is
/// the length of the window the next activity restarts.
fn remaining_secs(room: &Room) -> u64 {
    match room.ttl.kind {
        TtlKind::None => 0,
        TtlKind::Absolute => {
            let elapsed = crate::runar::room::unix_now().saturating_sub(room.created_unix);
            room.effective_ttl_secs().saturating_sub(elapsed)
        }
        _ => room.effective_ttl_secs(),
    }
}

fn ttl_json(room: &Room) -> TtlJson {
    let kind = match room.ttl.kind {
        crate::runar::room::TtlKind::Absolute => "absolute",
        crate::runar::room::TtlKind::IdleEdit => "idle-edit",
        crate::runar::room::TtlKind::IdlePeers => "idle-peers",
        crate::runar::room::TtlKind::None => "none",
    };
    TtlJson { kind, secs: remaining_secs(room) }
}

struct ConnLimits {
    frames: RateLimiter<()>,
    bytes: RateLimiter<()>,
}

impl ConnLimits {
    fn new(cfg: &crate::config::Config) -> Self {
        ConnLimits {
            frames: RateLimiter::new(cfg.frames_per_conn_per_sec * 2, Duration::from_secs(2), 1),
            bytes: RateLimiter::new(
                (cfg.bytes_per_conn_per_sec.saturating_mul(2)).min(u32::MAX as u64) as u32,
                Duration::from_secs(2),
                1,
            ),
        }
    }

    fn allow(&self, len: usize) -> bool {
        self.frames.check(&()) && self.bytes.check_n(&(), len.max(1) as u32)
    }
}

pub async fn handle_socket(mut socket: WebSocket, state: AppState, room_hex: String, ip: String) {
    // Process-wide first: the per-IP guard bounds one address, not the sum.
    let max = state.cfg.max_connections;
    if state
        .live_conns
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |n| (n < max).then_some(n + 1),
        )
        .is_err()
    {
        tracing::warn!(max, "connection ceiling reached; refusing socket");
        refuse(&mut socket, WireCode::ServerFull).await;
        return;
    }
    let _conn_slot = ConnSlot(state.live_conns.clone());

    if !state.conn_guard.acquire(&ip) {
        tracing::info!(
            limit = state.cfg.max_conns_per_ip,
            "per-address connection limit reached; refusing socket"
        );
        refuse(&mut socket, WireCode::TooManyConnections).await;
        return;
    }
    let ip_for_release = ip.clone();
    let result =
        run_connection(socket, state.clone(), room_hex, cfg_of(&state), ip).await;
    state.conn_guard.release(&ip_for_release);
    if let Err(code) = result {
        tracing::debug!(closed_by = u16::from(code), "socket closed");
    }
}

/// Close a socket that is being turned away, with a code that says why.
///
/// Both refusals used to return without a word. The browser saw a connection
/// open and drop at once, retried on its backoff forever, and nobody was ever
/// told anything. A close code is the only thing a page can read here:
/// browsers do not expose the status of a refused WebSocket upgrade, which is
/// why the refusal waits until after it.
async fn refuse(socket: &mut WebSocket, code: WireCode) {
    let _ = socket
        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
            code: u16::from(code),
            reason: "".into(),
        })))
        .await;
}

/// Returns the process-wide connection slot on every exit path, including
/// the early returns above.
struct ConnSlot(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| Some(n.saturating_sub(1)),
            )
            .ok();
    }
}

fn cfg_of(state: &AppState) -> std::sync::Arc<crate::config::Config> {
    state.cfg.clone()
}

type ConnResult = Result<(), WireCode>;

async fn run_connection(
    socket: WebSocket,
    state: AppState,
    room_hex: String,
    cfg: std::sync::Arc<crate::config::Config>,
    ip: String,
) -> ConnResult {
    let _ = &ip;
    let (mut sink, mut stream) = socket.split();
    let Some(room_id) = http::parse_room_hex(&room_hex) else {
        return Err(WireCode::ProtocolError);
    };

    // Read the first frame BEFORE revealing whether the room exists: a
    // probe that connects and sends nothing must be indistinguishable from
    // one aimed at a live room (both wait up to JOIN_TIMEOUT in silence).
    let first = match timeout(JOIN_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Binary(b)))) => b,
        _ => {
            // Identical silence-then-close for existing and missing rooms.
            if state.rooms.get(&room_id).is_none() {
                floor_delay(cfg.auth_floor).await;
                let _ = sink
                    .send(Message::Binary(error_frame(room_id, WireCode::AuthFailed)))
                    .await;
                return Err(WireCode::AuthFailed);
            }
            return Err(WireCode::ProtocolError);
        }
    };
    let header = Header::decode(&first);
    let valid_join_header = matches!(
        header,
        Some(ref h) if h.version == VERSION && h.frame_type == FT_JOIN && h.room_id == room_id
    );

    let Some(room) = state.rooms.get(&room_id) else {
        floor_delay(cfg.auth_floor).await;
        let _ = sink
            .send(Message::Binary(error_frame(room_id, WireCode::AuthFailed)))
            .await;
        return Err(WireCode::AuthFailed);
    };

    if !valid_join_header {
        floor_delay(cfg.auth_floor).await;
        let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
        return Err(WireCode::AuthFailed);
    }
    let header = header.expect("validated above");
        #[allow(unused_variables)]
        let header_ref = &header;

    // A room mid-purge is, from outside, indistinguishable from one that was
    // never here. Peers already inside learn about the purge over their live
    // socket; a new connection gets the same answer as any bad id.
    match room.current_state() {
        RoomState::Active | RoomState::Draining => {}
        _ => {
            floor_delay(cfg.auth_floor).await;
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
            return Err(WireCode::AuthFailed);
        }
    }
    if first.len() > cfg.max_frame_bytes {
        let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::FrameTooLarge))).await;
        return Err(WireCode::FrameTooLarge);
    }
    let header = Header::decode(&first).ok_or(WireCode::ProtocolError)?;
    if header.version != VERSION || header.frame_type != FT_JOIN || header.room_id != room_id {
        let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::ProtocolError))).await;
        return Err(WireCode::ProtocolError);
    }

    let join: JoinBody = serde_json::from_slice(&first[HEADER_LEN..]).unwrap_or_default();
    let wants_acks = join.acks;
    let caps = Caps { acks: join.acks, heartbeat: join.heartbeat };

    // A throttled room must not answer differently from a room that does not
    // exist. Returning 4002 here was a clean existence oracle: five bad
    // guesses at a real room id flipped the code to RateLimited, while a
    // missing id answered 4001 forever. Same code, same delay, either way.
    if !room.auth_allowed(&ip) {
        floor_delay(cfg.auth_floor).await;
        let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
        return Err(WireCode::AuthFailed);
    }

    let presented = join.auth_key.as_deref().unwrap_or("");
    let presented_bytes = B64.decode(presented).unwrap_or_default();
    let auth_ok = verifier::verify(room.verifier_ref(), &presented_bytes);
    drop(presented_bytes);

    if !state.auth_per_ip.check(&ip) {
        floor_delay(cfg.auth_floor).await;
        let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
        return Err(WireCode::AuthFailed);
    }

    if !auth_ok {
        let backoff = room.record_auth_failure();
        tracing::info!(backoff_secs = backoff.as_secs(), "auth failed");
        floor_delay(cfg.auth_floor).await;
        let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
        return Err(WireCode::AuthFailed);
    }
    room.auth_success(&ip);
    // Only guesses count against an address. Charging successful joins too
    // meant that the 31st connection in a minute from one office, school or
    // carrier address — people reconnecting after a network blip, or after a
    // restart — was refused with 4001, which is indistinguishable from "this
    // room does not exist" by design, and so was shown "this room is gone".
    state.auth_per_ip.refund(&ip, 1);

    let session_pubkey: Option<Vec<u8>> = join
        .pubkey
        .as_deref()
        .and_then(|k| B64.decode(k).ok())
        .filter(|v| v.len() == 32 || v.len() == 65);

    let kx = match (join.kx_pubkey.as_deref(), join.kx_sig.as_deref()) {
        (Some(p), Some(s)) => match (B64.decode(p), B64.decode(s)) {
            (Ok(p), Ok(s)) if p.len() == 65 && p[0] == 0x04 && s.len() == 64 => {
                Some(PeerKx { pubkey: p, sig: s })
            }
            _ => None,
        },
        _ => None,
    };

    let (tx, mut rx) = mpsc::channel::<Bytes>(OUTBOUND_CAPACITY);
    let peer_tx = crate::runar::room::PeerTx::new(tx, cfg.max_queued_bytes_per_conn)
        .with_indexes(join.indexed);
    let queue_meter = peer_tx.meter();
    let entry = match room.add_peer(session_pubkey.clone(), kx, peer_tx) {
        Ok(e) => e,
        Err(JoinError::Full) => {
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::RoomFull))).await;
            return Err(WireCode::RoomFull);
        }
        Err(JoinError::AuthLockedOut(_)) => {
            floor_delay(cfg.auth_floor).await;
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
            return Err(WireCode::AuthFailed);
        }
    };
    let peer_id = entry.peer_id;

    {
        let ack = JoinAck {
            peer_id: B64.encode(peer_id),
            epoch: room.epoch(),
            root_epoch: room.root_epoch(),
            log_len: room.log.read().unwrap().log_len(),
            base_index: room.log.read().unwrap().base_index(),
            has_snapshot: room.log.read().unwrap().has_snapshot(),
            ttl: ttl_json(&room),
            elapsed_secs: crate::runar::room::unix_now().saturating_sub(room.created_unix),
            ceiling_optout: room.ceiling_optout,
            kdf: KdfJson {
                alg: "argon2id",
                m_kib: room.kdf_m_kib,
                t: room.kdf_t,
                p: room.kdf_p,
                salt: B64.encode(room.salt),
            },
            acks: wants_acks,
            limits: wants_acks.then(|| LimitsJson {
                max_frame_bytes: cfg.max_frame_bytes,
                frames_per_sec: cfg.frames_per_conn_per_sec,
                bytes_per_sec: cfg.bytes_per_conn_per_sec,
            }),
            indexed: join.indexed,
            heartbeat: join.heartbeat,
            log_id: hex::encode(room.log_id),
            config_blob: room.config_blob.as_ref().map(|b| B64.encode(b)),
            roster: roster_json(&room),
        };
        let frame = json_frame(room_id, FT_JOIN_ACK, &ack);
        if sink.send(Message::Binary(frame)).await.is_err() {
            room.remove_peer(&peer_id);
            return Err(WireCode::ProtocolError);
        }
    }

    // Joining during a restart countdown: say so at once, rather than let
    // someone start writing into a room with seconds left.
    if let Some(in_secs) = state.restart_in_secs() {
        let notice = restart_notice(room_id, &state.restart_notice_body(in_secs));
        if sink.send(Message::Binary(notice)).await.is_err() {
            room.remove_peer(&peer_id);
            return Err(WireCode::ProtocolError);
        }
    }

    let join_evt = json_frame(
        room_id,
        FT_PEER_JOIN,
        &serde_json::json!({
            "peer_id": B64.encode(peer_id),
            "pubkey": session_pubkey.map(|k| B64.encode(k)),
            "joined_at_seq": entry.joined_at_seq,
            "kx_pubkey": entry.kx.as_ref().map(|k| B64.encode(&k.pubkey)),
            "kx_sig": entry.kx.as_ref().map(|k| B64.encode(&k.sig)),
        }),
    );
    room.broadcast_event(&join_evt, None).await;

    if room.current_state() == RoomState::Draining {
        // Somebody came back before the grace window closed.
        room.mark_state(RoomState::Active);
    }

    let limits = ConnLimits::new(&cfg);
    let mut conn_ok: ConnResult = Ok(());
    // One sync replay in flight per connection. Each DOC_SYNC_REQ can pull the
    // whole room log, so letting them queue turns one small frame into an
    // unbounded fan-out of spawned tasks and egress.
    let sync_slot = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    // Frames answering this connection's own requests: DOC_ACK and PONG.
    let mut direct: Vec<Bytes> = Vec::new();

    loop {
        tokio::select! {
            inbound = stream.next() => {
                match inbound {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > cfg.max_frame_bytes {
                            conn_ok = Err(WireCode::FrameTooLarge);
                            break;
                        }
                        if !limits.allow(data.len()) {
                            conn_ok = Err(WireCode::RateLimited);
                            break;
                        }
                        match process_frame(&state, &room, peer_id, &data, &sync_slot, caps, &mut direct).await {
                            Ok(()) => {}
                            Err(Some(code)) => { conn_ok = Err(code); break; }
                            Err(None) => {}
                        }
                        // Written straight to this socket, in order, rather
                        // than through the peer's outbound queue. That queue
                        // refuses a frame when it is full and the peer is
                        // dropped, and during a large log replay it is full:
                        // a client typing through its own sync would be
                        // dropped, reconnect, replay, and be dropped again.
                        // Awaiting the write also paces this reader to its
                        // own socket, which is the backpressure it should
                        // have.
                        let mut direct_write_failed = false;
                        for frame in direct.drain(..) {
                            if sink.send(Message::Binary(frame)).await.is_err() {
                                direct_write_failed = true;
                                break;
                            }
                        }
                        if direct_write_failed {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(_))) => {
                        conn_ok = Err(WireCode::ProtocolError);
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(bytes) => {
                        let is_purge = bytes.len() >= HEADER_LEN && bytes[3] == FT_PURGE;
                        let is_ticket = bytes.len() >= HEADER_LEN && bytes[3] == FT_RESTART_TICKET;
                        let n = bytes.len();
                        let sent = sink.send(Message::Binary(bytes)).await;
                        // Quota returns once the frame is off our hands.
                        queue_meter.release(n);
                        if sent.is_err() {
                            break;
                        }
                        if is_purge {
                            conn_ok = Err(WireCode::Purged);
                            break;
                        }
                        // The process is stopping and this connection now
                        // holds its room's ticket: close it as a restart, so
                        // the member comes back to the new process with it.
                        if is_ticket {
                            conn_ok = Err(WireCode::ServiceRestart);
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    if let Err(code) = conn_ok {
        let _ = sink
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: u16::from(code),
                reason: "".into(),
            })))
            .await;
    }

    room.remove_peer(&peer_id);
    let leave = json_frame(
        room_id,
        FT_PEER_LEAVE,
        &serde_json::json!({
            "peer_id": B64.encode(peer_id),
            "reason": conn_ok.err().map(u16::from),
        }),
    );
    room.broadcast_event(&leave, Some(peer_id)).await;
    if room.peer_count() == 0 && room.current_state() == RoomState::Active {
        room.mark_state(RoomState::Draining);
    }
    conn_ok
}

/// Returns Ok on handled, Err(Some(code)) to close, Err(None) silently ignored.
/// Frames whose bodies are ciphertext under an epoch's content key. Only these
/// are held to the room's epoch; control frames carry nothing to protect.
fn carries_ciphertext(frame_type: u8) -> bool {
    matches!(
        frame_type,
        FT_DOC_UPDATE | FT_SNAPSHOT | FT_AWARENESS | FT_SHRED_REQUEST | FT_SHRED_VOTE | FT_SHRED_CANCEL
    )
}

async fn process_frame(
    state: &AppState,
    room: &std::sync::Arc<Room>,
    sender: [u8; 16],
    data: &[u8],
    sync_slot: &std::sync::Arc<tokio::sync::Semaphore>,
    caps: Caps,
    direct: &mut Vec<Bytes>,
) -> Result<(), Option<WireCode>> {
    let Some(header) = Header::decode(data) else {
        return Err(Some(WireCode::ProtocolError));
    };
    if header.version != VERSION || header.room_id != room.id {
        return Err(Some(WireCode::ProtocolError));
    }
    if data.len() < HEADER_LEN {
        return Err(Some(WireCode::ProtocolError));
    }
    let frame_bytes = Bytes::copy_from_slice(data);

    // Amendment J: ciphertext from an epoch the room has left is refused once
    // the overlap has passed, and so is ciphertext from one it has not
    // reached. A snapshot rebases history, so it must be current.
    if carries_ciphertext(header.frame_type) {
        let admit = room.admit_epoch(header.epoch, std::time::Instant::now(), state.cfg.epoch_overlap);
        let refuse = match admit {
            Admit::Current => false,
            Admit::Overlap => header.frame_type == FT_SNAPSHOT,
            Admit::Stale => true,
        };
        if refuse {
            if header.frame_type == FT_DOC_UPDATE && caps.acks {
                let body = serde_json::json!({ "ok": false, "epoch": room.epoch() });
                direct.push(json_frame(room.id, FT_DOC_ACK, &body));
            } else {
                direct.push(error_frame(room.id, WireCode::EpochStale));
            }
            return Ok(());
        }
    }

    match header.frame_type {
        FT_DOC_UPDATE => {
            room.touch();
            let append_result = {
                let mut log = room.log.write().unwrap();
                log.append(sender, FT_DOC_UPDATE, header.epoch, frame_bytes.clone())
            };
            match append_result {
                Ok(index) => {
                    room.broadcast_update(&frame_bytes, sender, index).await;
                    // The client keeps every update until this comes back, and
                    // sends it again on its next connection if it never does.
                    // That is what makes an edit typed into a connection that
                    // has silently died recoverable: the browser reports such
                    // a socket as open until TCP gives up, and nothing sent in
                    // that time arrives anywhere.
                    if caps.acks {
                        let body = serde_json::json!({ "ok": true, "index": index });
                        direct.push(json_frame(room.id, FT_DOC_ACK, &body));
                    }
                }
                Err(_) => {
                    send_direct(room, sender, error_frame(room.id, WireCode::FrameTooLarge));
                    if caps.acks {
                        let body = serde_json::json!({ "ok": false });
                        direct.push(json_frame(room.id, FT_DOC_ACK, &body));
                    }
                }
            }
            Ok(())
        }

        FT_AWARENESS => {
            room.broadcast(&frame_bytes, Some(sender)).await;
            Ok(())
        }

        FT_SNAPSHOT => {
            if frame_bytes.len() < HEADER_LEN + 8 {
                return Err(None);
            }
            // Deterministic election (spec §5.8): only the lowest
            // joined_at_seq peer currently in the room may compact the log.
            // Anything else is refused before it can truncate history.
            let min_seq = room
                .peers
                .lock()
                .unwrap()
                .iter()
                .map(|p| p.joined_at_seq)
                .min();
            let sender_seq = room
                .peers
                .lock()
                .unwrap()
                .iter()
                .find(|p| p.peer_id == sender)
                .map(|p| p.joined_at_seq);
            if sender_seq != min_seq || sender_seq.is_none() {
                send_direct(
                    room,
                    sender,
                    error_frame(room.id, WireCode::ProtocolError),
                );
                return Ok(());
            }
            let covers = u64::from_be_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]);
            let entry = LogEntry {
                sender,
                frame_type: FT_SNAPSHOT,
                epoch: header.epoch,
                frame: frame_bytes.clone(),
            };
            let applied = {
                let mut log = room.log.write().unwrap();
                log.apply_snapshot(covers, entry)
            };
            if applied {
                room.touch();
                room.broadcast(&frame_bytes, Some(sender)).await;
            } else {
                send_direct(room, sender, error_frame(room.id, WireCode::ProtocolError));
            }
            Ok(())
        }

        FT_DOC_SYNC_REQ => {
            let from_index: u64 = serde_json::from_slice::<serde_json::Value>(&data[HEADER_LEN..])
                .ok()
                .and_then(|v| v.get("from_index").and_then(|x| x.as_u64()))
                .unwrap_or(0);
            let chunk = {
                let log = room.log.read().unwrap();
                log.tail_from(from_index)
            };
            if let Some(tx) = room.sender_for(&sender) {
                // Spawn off the connection's critical path so `send().await`
                // exerts real backpressure; the select loop is free to drain
                // rx concurrently because process_frame has already returned.
                // The permit caps this at one replay per connection: without
                // it, a peer could fire sync requests at the frame limit and
                // have the server clone and push the whole log for each one.
                let Ok(permit) = sync_slot.clone().try_acquire_owned() else {
                    return Ok(());
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(snapshot) = chunk.snapshot {
                        if tx.send_backpressured(envelop_entry(&snapshot, None)).await.is_err() {
                            return;
                        }
                    }
                    for (i, entry) in chunk.entries.into_iter().enumerate() {
                        let index = (tx.indexed && entry.frame_type == FT_DOC_UPDATE)
                            .then_some(chunk.first_index + i as u64);
                        if tx.send_backpressured(envelop_entry(&entry, index)).await.is_err() {
                            break;
                        }
                    }
                });
            }
            Ok(())
        }

        FT_EPOCH_KEY => {
            let now = std::time::Instant::now();
            match room.offer_epoch_key(header.epoch, now, state.cfg.epoch_min_interval) {
                Offer::Advanced => room.broadcast_to_all(&frame_bytes, sender).await,
                Offer::Handover => gjallarhorn::relay(room, &frame_bytes, sender).await,
                Offer::Refused => {}
            }
            Ok(())
        }

        FT_SHRED_REQUEST | FT_SHRED_VOTE | FT_SHRED_CANCEL => {
            if header.frame_type == FT_SHRED_REQUEST {
                room.note_shred_request();
            }
            gjallarhorn::relay(room, &frame_bytes, sender).await;
            Ok(())
        }

        FT_TTL_EXTEND => {
            let add_secs = serde_json::from_slice::<serde_json::Value>(&data[HEADER_LEN..])
                .ok()
                .and_then(|v| v.get("add_secs").and_then(|x| x.as_u64()));
            if let Some(add) = add_secs {
                if !(1..=720 * 3600).contains(&add) {
                    return Err(None);
                }
                let _total_ext = room.extend_ttl(add);
                room.touch();
                let effective = match room.ttl.kind {
                    TtlKind::None => 0,
                    _ => room.effective_ttl_secs(),
                };
                // The server clamps extensions at a ceiling, so `add_secs` is
                // a request, not a result. Clients must re-anchor on a value
                // the server computed — otherwise the extender's local clock
                // drifts past the real deadline (and double-counts its own
                // request on top of the broadcast).
                let remaining = remaining_secs(room);
                let evt = json_frame(
                    room.id,
                    FT_TTL_EXTEND,
                    &serde_json::json!({
                        "added_by": B64.encode(sender),
                        "add_secs": add,
                        "effective_secs": effective,
                        "remaining_secs": remaining,
                        "kind": match room.ttl.kind {
                            TtlKind::Absolute => "absolute",
                            TtlKind::IdleEdit => "idle-edit",
                            TtlKind::IdlePeers => "idle-peers",
                            TtlKind::None => "none",
                        },
                    }),
                );
                room.broadcast_event(&evt, None).await;
            }
            Ok(())
        }

        FT_PURGE_ACK => {
            let request_id = serde_json::from_slice::<serde_json::Value>(&data[HEADER_LEN..])
                .ok()
                .and_then(|v| v.get("request_id").and_then(|x| x.as_str()).map(str::to_string));
            if let Some(request_id) = request_id {
                if request_id.len() > crate::runar::room::MAX_PURGE_REQUEST_ID_LEN {
                    return Err(None);
                }
                match room.note_purge_ack(&request_id, sender) {
                    PurgeAckStatus::Pending => {}
                    PurgeAckStatus::AllAcked(id) => {
                        tracing::info!(request = %id, "all connected peers acked; purging");
                        surtr::purge(&state.rooms, &room.id, "shred-consensus").await;
                    }
                }
            }
            Ok(())
        }

        // Answered straight to this socket, like DOC_ACK, so a queue full of
        // relay traffic cannot make a live connection look dead. The roster
        // rides along: it is taken here, in the task that writes it, so no
        // earlier view of it can arrive after a later one (amendment G).
        FT_PING if caps.heartbeat => {
            direct.push(json_frame(
                room.id,
                FT_PONG,
                &serde_json::json!({ "roster": roster_json(room) }),
            ));
            Ok(())
        }

        _ => Err(Some(WireCode::ProtocolError)),
    }
}

fn roster_json(room: &Room) -> Vec<RosterJson> {
    room.roster()
        .into_iter()
        .map(|p| RosterJson {
            peer_id: B64.encode(p.peer_id),
            pubkey: p.pubkey.map(|k| B64.encode(k)),
            joined_at_seq: p.joined_at_seq,
            kx_pubkey: p.kx.as_ref().map(|k| B64.encode(&k.pubkey)),
            kx_sig: p.kx.as_ref().map(|k| B64.encode(&k.sig)),
        })
        .collect()
}

/// The frame that carries a room's restart ticket to one of its members, just
/// before the connection is closed (amendment I).
pub fn restart_ticket(room_id: [u8; 16], ticket: &str) -> Bytes {
    json_frame(room_id, FT_RESTART_TICKET, &serde_json::json!({ "ticket": ticket }))
}

fn send_direct(room: &Room, target: [u8; 16], payload: Bytes) {
    let peers = room.peers.lock().unwrap();
    if let Some(p) = peers.iter().find(|p| p.peer_id == target) {
        let _ = p.tx.try_send(payload);
    }
}

fn envelop_entry(entry: &LogEntry, index: Option<u64>) -> Bytes {
    let frame = &entry.frame;
    if frame.len() < HEADER_LEN {
        return frame.clone();
    }
    match index {
        Some(i) => crate::runar::room::envelop_indexed(frame, entry.sender, i),
        None => crate::runar::room::envelop(frame, entry.sender),
    }
}
