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
use crate::runar::epoch::Admit;
use crate::heimdall::verifier;
use crate::runar::evict;
use crate::runar::room::{PeerKx, TtlKind};
use crate::error::WireCode;
use crate::gjallarhorn;
use crate::heimdall::ratelimit::RateLimiter;
use crate::runar::log::LogEntry;
use crate::runar::room::{
    JoinError, PurgeAckStatus, ReRoot, Room, RoomState,
};
use crate::surtr;
use crate::AppState;

const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Slot count only. The real bound on a peer's outbound queue is
/// `max_queued_bytes_per_conn`, enforced by `PeerTx`: 512 slots of
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
/// them all again, forever.
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
    /// With this the client reconstructs the total the server is claiming,
    /// remaining plus elapsed, and compares like with like. It is sent rather
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

/// How many EVICT_COMMIT vote signatures one connection may have verified
/// per second, on average: one full commit's worth.
const VOTE_CHECKS_PER_SEC: u32 = evict::MAX_VOTES as u32;

/// The most it may have verified at once: four full commits, which is a
/// proposer's first send and the three times it may send the commit again
/// after a step (amendment K), all inside a second.
const VOTE_CHECKS_BURST: u32 = 4 * evict::MAX_VOTES as u32;

/// A connection's budget for vote signatures (review I1). Each signature
/// costs up to about 160 microseconds for P-256, and a commit carries up to
/// 32 of them, so without a budget one connection could keep a worker busy
/// at the frame rate. A commit is charged one token per vote, after the cheap
/// checks pass and before any signature is verified, and one the budget
/// cannot pay for is dropped without an answer, like any refused commit.
/// Counting signatures rather than commits lets an honest proposer send its
/// commit again at once after a step, which a one-commit-per-second limit
/// would refuse.
fn vote_budget() -> RateLimiter<()> {
    let window = Duration::from_secs(u64::from(VOTE_CHECKS_BURST / VOTE_CHECKS_PER_SEC));
    // Room for more keys than the one it holds, so the table is never full
    // and `RateLimiter::evict` never runs on it.
    RateLimiter::new(VOTE_CHECKS_BURST, window, 2)
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
    // The generation the key was checked at, so a commit between this check
    // and the insert below refuses the join (amendment K).
    let auth = room.check_auth(&presented_bytes);
    let auth_ok = auth.is_some();
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
    // carrier address (people reconnecting after a network blip, or after a
    // restart) was refused with 4001, which is indistinguishable from "this
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
    let final_error = peer_tx.close_flag();
    let generation = auth.expect("checked above");
    let (entry, view) = match room.join(generation, session_pubkey.clone(), kx, peer_tx) {
        Ok(joined) => joined,
        Err(JoinError::Full) => {
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::RoomFull))).await;
            return Err(WireCode::RoomFull);
        }
        // Amendment J: a client that sent no key-agreement key cannot be
        // handed the key of a rotated room, and would write under a key
        // someone who left holds. `add_peer` decides this under the room's
        // locks, so a step on another thread cannot slip between the check
        // and the insert.
        Err(JoinError::Rotated) => {
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::ProtocolError))).await;
            let _ = sink
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: u16::from(WireCode::ProtocolError),
                    reason: "".into(),
                })))
                .await;
            return Err(WireCode::ProtocolError);
        }
        // The room's link changed between the key check and now: the key
        // this JOIN presented no longer opens it.
        Err(JoinError::Rekeyed) => {
            floor_delay(cfg.auth_floor).await;
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
            return Err(WireCode::AuthFailed);
        }
        Err(JoinError::AuthLockedOut(_)) => {
            floor_delay(cfg.auth_floor).await;
            let _ = sink.send(Message::Binary(error_frame(room_id, WireCode::AuthFailed))).await;
            return Err(WireCode::AuthFailed);
        }
    };
    let peer_id = entry.peer_id;

    {
        // One read guard, dropped before anything else is locked. These three
        // used to be separate `room.log.read()` calls inside the literal below,
        // and temporaries live to the end of the statement, so the first guard
        // was still held when the second was asked for. std's RwLock (futex on
        // Linux, the queue lock on macOS) makes a new reader wait behind a
        // waiting writer, and that writer waits for the first guard: the two
        // worker threads would wait on each other for good, and every later
        // write to the room would take another worker with it. It also held
        // the log lock while `roster_json` took the peers lock.
        let (log_len, base_index, has_snapshot) = {
            let log = room.log.read().unwrap();
            (log.log_len(), log.base_index(), log.has_snapshot())
        };
        let ack = JoinAck {
            peer_id: B64.encode(peer_id),
            epoch: view.epoch,
            root_epoch: view.root_epoch,
            log_len,
            base_index,
            has_snapshot,
            ttl: ttl_json(&room),
            elapsed_secs: crate::runar::room::unix_now().saturating_sub(room.created_unix),
            ceiling_optout: room.ceiling_optout,
            kdf: KdfJson {
                alg: "argon2id",
                m_kib: room.kdf_m_kib,
                t: room.kdf_t,
                p: room.kdf_p,
                salt: B64.encode(view.salt),
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
            config_blob: view.config_blob.as_ref().map(|b| B64.encode(b)),
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
    let vote_budget = vote_budget();
    // Frames answering this connection's own requests: DOC_ACK and PONG.
    let mut direct: Vec<Bytes> = Vec::new();

    loop {
        tokio::select! {
            inbound = stream.next() => {
                match inbound {
                    Some(Ok(Message::Binary(data))) => {
                        // This connection's last frame is queued (ERROR 4005
                        // or 4014): nothing it sends now is acted on, so a
                        // peer the room has just removed cannot slip one
                        // more edit in under the epoch it held.
                        if final_error.get().is_some() {
                            continue;
                        }
                        if data.len() > cfg.max_frame_bytes {
                            conn_ok = Err(WireCode::FrameTooLarge);
                            break;
                        }
                        if !limits.allow(data.len()) {
                            conn_ok = Err(WireCode::RateLimited);
                            break;
                        }
                        match process_frame(&state, &room, peer_id, &data, &sync_slot, &vote_budget, caps, &mut direct).await {
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
                        let closing = if bytes.len() >= HEADER_LEN && bytes[3] == FT_ERROR {
                            final_error.get()
                        } else {
                            None
                        };
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
                        // The last frame this connection gets: ERROR 4005
                        // for a client that cannot be handed the room's new
                        // key, ERROR 4014 for a peer the room removed.
                        if let Some(code) = closing {
                            conn_ok = Err(code);
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

/// Frames whose bodies are ciphertext under an epoch's content key. Only these
/// are held to the room's epoch; control frames carry nothing to protect.
fn carries_ciphertext(frame_type: u8) -> bool {
    matches!(
        frame_type,
        FT_DOC_UPDATE
            | FT_SNAPSHOT
            | FT_AWARENESS
            | FT_SHRED_REQUEST
            | FT_SHRED_VOTE
            | FT_SHRED_CANCEL
            | FT_EVICT_REQUEST
            | FT_EVICT_VOTE
            | FT_EVICT_CANCEL
    )
}

/// Returns Ok on handled, Err(Some(code)) to close, Err(None) silently ignored.
#[allow(clippy::too_many_arguments)]
async fn process_frame(
    state: &AppState,
    room: &std::sync::Arc<Room>,
    sender: [u8; 16],
    data: &[u8],
    sync_slot: &std::sync::Arc<tokio::sync::Semaphore>,
    vote_budget: &RateLimiter<()>,
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
    // A connection the room has removed or is closing (ERROR 4014 or 4005
    // queued) can still be reading while its last error drains. Nothing it
    // sends is relayed, logged or applied. That is not checked here: a check
    // made on its own lock could pass and then be overtaken by a commit on
    // another worker thread before the frame is acted on. Each action below
    // decides it under the `peers` guard the action itself takes, which is
    // the guard a commit or a step closes a connection under (`live` in
    // room.rs). What a closing connection is still sent directly (an
    // EPOCH_STALE error, a PONG) goes only to itself.
    let frame_bytes = Bytes::copy_from_slice(data);

    // Amendment J: ciphertext from an epoch the room has left is refused once
    // the overlap has passed, and so is ciphertext from one it has not
    // reached. A snapshot rebases history, so it must be current.
    if carries_ciphertext(header.frame_type) {
        let admit = room.admit_epoch(header.epoch, std::time::Instant::now(), state.cfg.epoch_overlap);
        match admit {
            Admit::Current => {}
            // A snapshot rebases history, so it must be current. One from the
            // epoch just left is dropped without an answer: the member that
            // rotated is usually the snapshotter, and must not be made to
            // reconnect for a snapshot sent between its step and the echo.
            Admit::Overlap if header.frame_type == FT_SNAPSHOT => return Ok(()),
            Admit::Overlap => {}
            Admit::Stale => {
                if header.frame_type == FT_DOC_UPDATE && caps.acks {
                    let body = serde_json::json!({ "ok": false, "epoch": room.epoch() });
                    direct.push(json_frame(room.id, FT_DOC_ACK, &body));
                } else {
                    direct.push(error_frame(room.id, WireCode::EpochStale));
                }
                return Ok(());
            }
        }
    }

    match header.frame_type {
        FT_DOC_UPDATE => {
            // Stored and relayed under one `peers` guard with the check that
            // the sender is still a member (`Room::append_update`). None: it
            // was removed or is being closed, so nothing is stored, relayed
            // or acknowledged.
            match room.append_update(&frame_bytes, sender, header.epoch) {
                None => {}
                Some(Ok(index)) => {
                    room.touch();
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
                Some(Err(_)) => {
                    room.touch();
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
            let covers = u64::from_be_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]);
            // Deterministic election (spec §5.8): only the lowest
            // joined_at_seq peer currently in the room may compact the log.
            // Anything else is refused before it can truncate history. The
            // election, the membership check and the write are one critical
            // section in the room.
            match room.apply_snapshot_from(&frame_bytes, sender, header.epoch, covers) {
                None => {}
                Some(true) => room.touch(),
                Some(false) => send_direct(room, sender, error_frame(room.id, WireCode::ProtocolError)),
            }
            Ok(())
        }

        FT_DOC_SYNC_REQ => {
            let from_index: u64 = serde_json::from_slice::<serde_json::Value>(&data[HEADER_LEN..])
                .ok()
                .and_then(|v| v.get("from_index").and_then(|x| x.as_u64()))
                .unwrap_or(0);
            // The permit caps this at one replay per connection, and is taken
            // before the log is cloned: without it, a peer could fire sync
            // requests at the frame limit and have the server clone the whole
            // log for each one, even while a replay is still running.
            let Ok(permit) = sync_slot.clone().try_acquire_owned() else {
                return Ok(());
            };
            // Cloned before `sender_for` sees the sender live, so the chunk
            // holds nothing written after a commit that removed it. A
            // connection that is closing never gets here twice: its reader
            // skips every frame once its last error is queued.
            let chunk = {
                let log = room.log.read().unwrap();
                log.tail_from(from_index)
            };
            if let Some(tx) = room.sender_for(&sender) {
                // Spawn off the connection's critical path so `send().await`
                // exerts real backpressure; the select loop is free to drain
                // rx concurrently because process_frame has already returned.
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
            // Decision and fan-out are one critical section in the room, so
            // every peer sees steps in the order the server decided them.
            let _ = room.step_epoch(
                header.epoch,
                now,
                state.cfg.epoch_min_interval,
                &frame_bytes,
                sender,
                &error_frame(room.id, WireCode::ProtocolError),
            );
            Ok(())
        }

        FT_SHRED_REQUEST | FT_SHRED_VOTE | FT_SHRED_CANCEL => {
            // A request is relayed and its cohort noted in one critical
            // section with the sender's membership check.
            if header.frame_type == FT_SHRED_REQUEST {
                room.relay_shred_request(&frame_bytes, sender);
            } else {
                gjallarhorn::relay(room, &frame_bytes, sender).await;
            }
            Ok(())
        }

        // Amendment K: sealed under the room's content key and relayed like
        // the shred frames. The server reads none of it; it only notes when a
        // request or a cancel passed, and the commit is where it checks the
        // votes.
        FT_EVICT_REQUEST | FT_EVICT_VOTE | FT_EVICT_CANCEL => {
            // Before relaying, as for SHRED_REQUEST: who could see this
            // request is the cohort its sender's commit is counted against,
            // and the request holds key changes in the room. A cancel from
            // the same sender ends that hold.
            match header.frame_type {
                FT_EVICT_REQUEST => room.note_evict_request(sender),
                FT_EVICT_CANCEL => room.note_evict_cancel(sender),
                _ => {}
            }
            gjallarhorn::relay(room, &frame_bytes, sender).await;
            Ok(())
        }

        // Amendment K. Every refusal is silent, like a refused step: a
        // proposer whose commit is not echoed gives up on its own.
        FT_EVICT_COMMIT => {
            let Ok(clear) = evict::parse_commit(&data[HEADER_LEN..]) else {
                return Ok(());
            };
            if clear.config_blob.len() > state.cfg.max_config_blob_bytes
                || !verifier::plausible_verifier(&clear.new_verifier)
            {
                return Ok(());
            }
            // Every cheap check first, under the room's locks: the header
            // epoch, the sender among the voters, its recorded request, and
            // the voters distinct and exactly its cohort. A frame that fails
            // one costs no signature work. This also gives the room's root,
            // which every vote names, and each voter's signing key.
            let now = std::time::Instant::now();
            let voter_ids: Vec<[u8; 16]> = clear.votes.iter().map(|v| v.voter).collect();
            let Ok((root, voters)) = room.admit_commit(header.epoch, clear.target, &voter_ids, sender, now) else {
                return Ok(());
            };
            // Then the work is paid for: one token per signature, from this
            // connection's own budget (`VOTE_CHECKS_PER_SEC`).
            if !vote_budget.check_n(&(), voters.len() as u32) {
                return Ok(());
            }
            // Signatures are checked outside the room's locks, against the
            // keys the voters joined with. `commit_eviction` then checks
            // everything again under the locks, the root among it, and that
            // every voter is still connected with that key.
            for (v, (_, key)) in clear.votes.iter().zip(&voters) {
                // The statement names the target's peer id and key digest
                // exactly as the clear part gives them; the room then treats
                // every connection holding that key as the target.
                let msg = evict::statement(
                    &room.id,
                    &clear.request_id,
                    root,
                    clear.target.as_ref(),
                    &v.voter,
                    &clear.new_verifier,
                );
                room.count_vote_check();
                if !evict::verify_vote(key, &msg, &v.sig) {
                    return Ok(());
                }
            }
            let reroot = ReRoot {
                at_epoch: header.epoch,
                root,
                target: clear.target,
                voters,
                verifier: clear.new_verifier,
                salt: clear.new_salt,
                config_blob: (!clear.config_blob.is_empty()).then(|| Bytes::copy_from_slice(clear.config_blob)),
            };
            match room.commit_eviction(
                &reroot,
                now,
                &frame_bytes,
                sender,
                &error_frame(room.id, WireCode::Evicted),
                &error_frame(room.id, WireCode::ProtocolError),
            ) {
                Ok(epoch) => tracing::info!(epoch, "room re-rooted by an eviction or link change"),
                Err(why) => tracing::debug!(?why, "eviction commit refused"),
            }
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
                // Applied only while the sender is a live member, decided under
                // the `peers` guard with the extension itself.
                if room.extend_ttl_from(sender, add).is_none() {
                    return Ok(());
                }
                room.touch();
                let effective = match room.ttl.kind {
                    TtlKind::None => 0,
                    _ => room.effective_ttl_secs(),
                };
                // The server clamps extensions at a ceiling, so `add_secs` is
                // a request, not a result. Clients must re-anchor on a value
                // the server computed. Otherwise the extender's local clock
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

/// What a connection the room has removed or is closing can still send while
/// its last error drains. These call `process_frame` directly, with no socket
/// and no timing: each state is set up first, then every kind of frame is
/// processed as that sender, and nothing may reach anyone else, the log, the
/// epoch or the room's timers.
#[cfg(test)]
mod closing_sender_tests {
    use super::*;
    use crate::config::Config;
    use crate::heimdall::verifier::hash_auth_key;
    use crate::runar::evict::{key_digest, Target};
    use crate::runar::room::{test_salt, unix_now, CloseFlag, PeerTx, RoomClass, Ttl};

    const ROOM: [u8; 16] = [0x7A; 16];

    struct Peer {
        id: [u8; 16],
        flag: CloseFlag,
        rx: mpsc::Receiver<Bytes>,
    }

    fn state() -> AppState {
        // No step interval, so a step the guard missed would be applied and
        // show up as a moved epoch rather than be refused for being early.
        AppState::new(Config { epoch_min_interval: Duration::ZERO, ..Default::default() })
    }

    fn room() -> std::sync::Arc<Room> {
        std::sync::Arc::new(Room::new(
            ROOM,
            RoomClass::Unlisted,
            unix_now(),
            Ttl::default(),
            false,
            Some(hash_auth_key(&[0x11; 32])),
            65536,
            3,
            1,
            test_salt(),
            None,
            1 << 20,
            5,
            32,
        ))
    }

    fn key(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    fn peer(r: &Room, n: u8, with_kx: bool) -> Peer {
        let (tx, rx) = mpsc::channel(64);
        let tx = PeerTx::new(tx, 1 << 20);
        let flag = tx.close_flag();
        let kx = with_kx.then(|| PeerKx { pubkey: vec![4u8; 65], sig: vec![1u8; 64] });
        let id = r.add_peer(Some(key(n)), kx, tx).unwrap().peer_id;
        Peer { id, flag, rx }
    }

    fn frame(ft: u8, epoch: u32, body: &[u8]) -> Vec<u8> {
        let mut f = Header::new(ft, ROOM, epoch, [1, 2, 3, 4], 0).encode();
        f.extend_from_slice(body);
        f
    }

    async fn process(state: &AppState, r: &std::sync::Arc<Room>, sender: [u8; 16], data: &[u8]) {
        let slot = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let mut direct = Vec::new();
        let caps = Caps { acks: true, heartbeat: true };
        let _ = process_frame(state, r, sender, data, &slot, &vote_budget(), caps, &mut direct).await;
    }

    fn drain(p: &mut Peer) -> Vec<Bytes> {
        let mut out = Vec::new();
        while let Ok(f) = p.rx.try_recv() {
            out.push(f);
        }
        out
    }

    fn commit(r: &Room, sender: [u8; 16], voters: &[(&Peer, u8)], target: Option<Target>) -> u32 {
        let rr = ReRoot {
            at_epoch: r.epoch(),
            root: r.root_epoch(),
            target,
            voters: voters.iter().map(|(p, n)| (p.id, key(*n))).collect(),
            verifier: hash_auth_key(&[0x22; 32]),
            salt: [0x33; 16],
            config_blob: None,
        };
        r.note_evict_request(sender);
        r.commit_eviction(
            &rr,
            std::time::Instant::now(),
            &Bytes::from(frame(FT_EVICT_COMMIT, rr.at_epoch, b"commit")),
            sender,
            &error_frame(ROOM, WireCode::Evicted),
            &error_frame(ROOM, WireCode::ProtocolError),
        )
        .expect("the commit is applied")
    }

    /// Every frame a member can send, at the room's current epoch (a step at
    /// the next), processed as `sender`. Afterwards nobody else has been sent
    /// anything, and the log, the epoch and the room's timer are unchanged.
    async fn assert_nothing_lands(state: &AppState, r: &std::sync::Arc<Room>, sender: [u8; 16], others: &mut [&mut Peer]) {
        let epoch = r.epoch();
        let probes: [(&str, Vec<u8>); 8] = [
            ("DOC_UPDATE", frame(FT_DOC_UPDATE, epoch, b"late edit")),
            ("AWARENESS", frame(FT_AWARENESS, epoch, b"late cursor")),
            ("EVICT_REQUEST", frame(FT_EVICT_REQUEST, epoch, b"late request")),
            ("EVICT_VOTE", frame(FT_EVICT_VOTE, epoch, b"late vote")),
            ("SHRED_REQUEST", frame(FT_SHRED_REQUEST, epoch, b"late shred")),
            ("EPOCH_KEY", frame(FT_EPOCH_KEY, epoch + 1, b"late step")),
            ("SNAPSHOT", frame(FT_SNAPSHOT, epoch, &0u64.to_be_bytes())),
            ("TTL_EXTEND", frame(FT_TTL_EXTEND, 0, br#"{"add_secs":600}"#)),
        ];
        for (name, data) in probes {
            let (len, snap) = {
                let log = r.log.read().unwrap();
                (log.log_len(), log.has_snapshot())
            };
            let ttl = r.effective_ttl_secs();
            process(state, r, sender, &data).await;
            for o in others.iter_mut() {
                let got = drain(o);
                assert!(got.is_empty(), "{name} from a closing sender reached another member: {} frame(s)", got.len());
            }
            let log = r.log.read().unwrap();
            assert_eq!(log.log_len(), len, "{name} from a closing sender was logged");
            assert_eq!(log.has_snapshot(), snap, "{name} from a closing sender rebased the log");
            drop(log);
            assert_eq!(r.epoch(), epoch, "{name} from a closing sender moved the epoch");
            assert_eq!(r.effective_ttl_secs(), ttl, "{name} from a closing sender extended the room");
        }
    }

    /// The control: the same frames from a member are relayed, so the
    /// assertions above are not passing because nothing is ever relayed.
    #[tokio::test]
    async fn the_probes_from_a_member_do_land() {
        let s = state();
        let r = room();
        let a = peer(&r, 1, true);
        let mut b = peer(&r, 2, true);
        // The request's hold would keep the step below from landing; the
        // sender's own cancel ends it.
        for ft in [FT_DOC_UPDATE, FT_AWARENESS, FT_EVICT_REQUEST, FT_EVICT_CANCEL, FT_SHRED_REQUEST] {
            process(&s, &r, a.id, &frame(ft, 0, b"x")).await;
            assert_eq!(drain(&mut b).len(), 1, "frame {ft:#x} from a member is relayed");
        }
        assert_eq!(r.log.read().unwrap().log_len(), 1);
        process(&s, &r, a.id, &frame(FT_EPOCH_KEY, 1, b"step")).await;
        assert_eq!(r.epoch(), 1);
    }

    /// H1, end to end through the frame handler: an EVICT_REQUEST holds every
    /// step, a handover still passes, and the sender's EVICT_CANCEL lets the
    /// next step through.
    #[tokio::test]
    async fn a_request_holds_steps_until_its_sender_cancels() {
        let s = state();
        let r = room();
        let a = peer(&r, 1, true);
        let mut b = peer(&r, 2, true);
        let t = peer(&r, 3, true);
        process(&s, &r, a.id, &frame(FT_EVICT_REQUEST, 0, b"request")).await;
        drain(&mut b);
        process(&s, &r, t.id, &frame(FT_EPOCH_KEY, 1, b"step")).await;
        assert_eq!(r.epoch(), 0, "a step was applied while a request was open");
        assert!(drain(&mut b).is_empty(), "a held step was relayed");
        process(&s, &r, t.id, &frame(FT_EPOCH_KEY, 0, b"handover")).await;
        assert_eq!(drain(&mut b).len(), 1, "a handover was held");
        // Someone else's cancel does not end a's hold.
        process(&s, &r, t.id, &frame(FT_EVICT_CANCEL, 0, b"cancel")).await;
        process(&s, &r, t.id, &frame(FT_EPOCH_KEY, 1, b"step")).await;
        assert_eq!(r.epoch(), 0);
        process(&s, &r, a.id, &frame(FT_EVICT_CANCEL, 0, b"cancel")).await;
        drain(&mut b);
        process(&s, &r, t.id, &frame(FT_EPOCH_KEY, 1, b"step")).await;
        assert_eq!(r.epoch(), 1);
        assert_eq!(drain(&mut b).len(), 1);
    }

    #[tokio::test]
    async fn after_a_commit_nothing_the_target_sends_lands() {
        let s = state();
        let r = room();
        let mut t = peer(&r, 3, true);
        let mut a = peer(&r, 1, true);
        let mut b = peer(&r, 2, true);
        let target = Some(Target { peer_id: t.id, key_digest: key_digest(&key(3)) });
        assert_eq!(commit(&r, a.id, &[(&a, 1), (&b, 2)], target), 1);
        assert_eq!(drain(&mut a).len(), 1);
        assert_eq!(drain(&mut b).len(), 1, "b has the commit and nothing else");
        assert_eq!(t.flag.get(), Some(WireCode::Evicted));
        assert_eq!(drain(&mut t).len(), 1, "the target has its error");
        assert_nothing_lands(&s, &r, t.id, &mut [&mut a, &mut b]).await;
    }

    /// The window the review found: the target's close flag is set and it is
    /// still in the room's list. Before the fix, its frames passed a
    /// membership check made on a separate lock and were relayed.
    #[tokio::test]
    async fn a_connection_whose_close_flag_is_set_is_not_heard_while_still_listed() {
        let s = state();
        let r = room();
        // Joined first, so it would also be the one elected to snapshot.
        let t = peer(&r, 3, true);
        let mut a = peer(&r, 1, true);
        let mut b = peer(&r, 2, true);
        t.flag.set(WireCode::Evicted);
        assert!(r.roster().iter().any(|p| p.peer_id == t.id), "the test needs it listed");
        assert_nothing_lands(&s, &r, t.id, &mut [&mut a, &mut b]).await;
    }

    #[tokio::test]
    async fn a_peer_a_step_closes_with_4005_is_not_heard_and_leaves_the_roster() {
        let s = state();
        let r = room();
        let mut k = peer(&r, 3, false);
        let mut a = peer(&r, 1, true);
        let mut b = peer(&r, 2, true);
        process(&s, &r, a.id, &frame(FT_EPOCH_KEY, 1, b"step")).await;
        assert_eq!(r.epoch(), 1);
        assert_eq!(k.flag.get(), Some(WireCode::ProtocolError));
        assert!(!drain(&mut k).is_empty(), "the peer without a key has its error");
        drain(&mut a);
        drain(&mut b);
        assert!(!r.roster().iter().any(|p| p.peer_id == k.id), "a peer closed with 4005 is out of the roster at once");
        assert_eq!(r.peer_count(), 2);
        assert_nothing_lands(&s, &r, k.id, &mut [&mut a, &mut b]).await;
    }

    /// Review I1: a connection pays one token per vote before any signature
    /// is verified. Each of these commits passes the cheap checks and stops
    /// at its first signature, which is bad, and is charged for both votes:
    /// the burst of 128 tokens pays for 64 of them, and the 200 frames sent
    /// here, far faster than the budget refills, get little more than that.
    #[tokio::test]
    async fn a_connection_pays_for_the_signatures_its_commits_ask_for() {
        let s = state();
        let r = room();
        let a = peer(&r, 1, true);
        let b = peer(&r, 2, true);
        r.note_evict_request(a.id);
        let mut new_verifier = [0u8; 32];
        for (i, x) in new_verifier.iter_mut().enumerate() {
            *x = i as u8 + 1;
        }
        let clear = evict::CommitClear {
            request_id: [9; 16],
            target: None,
            new_verifier,
            new_salt: [3; 16],
            config_blob: b"",
            votes: vec![evict::Vote { voter: a.id, sig: [0; 64] }, evict::Vote { voter: b.id, sig: [0; 64] }],
            tail: &[],
        };
        let mut body = evict::encode_clear(&clear);
        body.extend_from_slice(b"tail");
        let data = frame(FT_EVICT_COMMIT, 0, &body);
        let budget = vote_budget();
        let slot = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let caps = Caps { acks: true, heartbeat: true };
        let mut direct = Vec::new();
        for _ in 0..200 {
            let _ = process_frame(&s, &r, a.id, &data, &slot, &budget, caps, &mut direct).await;
        }
        let checked = r.vote_checks();
        assert!(checked >= 64, "the burst pays for 64 frames, {checked} were checked");
        assert!(checked < 100, "{checked} signatures were checked for 200 frames");
        assert_eq!(r.epoch(), 0);
    }

    #[tokio::test]
    async fn a_peer_a_commit_closes_with_4005_is_not_heard_and_leaves_the_roster() {
        let s = state();
        let r = room();
        let mut k = peer(&r, 3, false);
        let mut a = peer(&r, 1, true);
        let mut b = peer(&r, 2, true);
        // k is in the cohort, so it votes; the commit then closes it.
        assert_eq!(commit(&r, a.id, &[(&a, 1), (&b, 2), (&k, 3)], None), 1);
        assert_eq!(k.flag.get(), Some(WireCode::ProtocolError));
        assert!(!drain(&mut k).is_empty(), "the peer without a key has its error");
        drain(&mut a);
        drain(&mut b);
        assert!(!r.roster().iter().any(|p| p.peer_id == k.id), "a peer closed with 4005 is out of the roster at once");
        assert_eq!(r.peer_count(), 2);
        assert_nothing_lands(&s, &r, k.id, &mut [&mut a, &mut b]).await;
    }
}
