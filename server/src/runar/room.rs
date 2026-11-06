use std::sync::atomic::{AtomicU64, Ordering};

use crate::runar::epoch::{Admit, EpochState, Offer};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use secrecy::{ExposeSecret, SecretBox as Secret};
use tokio::sync::mpsc;

use crate::bifrost::frame::Header;
use crate::runar::log::{LogBudget, RoomLog};
use crate::runar::names;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtlKind {
    Absolute,
    IdleEdit,
    IdlePeers,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ttl {
    pub kind: TtlKind,
    pub secs: u64,
}

impl Default for Ttl {
    fn default() -> Self {
        Ttl { kind: TtlKind::IdlePeers, secs: 3600 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomClass {
    Unlisted,
    Named(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomState {
    Active,
    Draining,
    Purging,
    Dead,
}

/// A peer's key-agreement key and the peer's signature over it (amendment J).
/// Opaque to the server, which checks only their lengths; peers verify the
/// signature against the peer's signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKx {
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RosterEntry {
    pub peer_id: [u8; 16],
    /// Raw public key bytes: 32 B Ed25519 or 65 B uncompressed ECDSA P-256.
    pub pubkey: Option<Vec<u8>>,
    pub kx: Option<PeerKx>,
    pub joined_at_seq: u64,
}

pub struct ConnectedPeer {
    pub peer_id: [u8; 16],
    pub pubkey: Option<Vec<u8>>,
    pub kx: Option<PeerKx>,
    pub joined_at_seq: u64,
    pub tx: PeerTx,
}

/// A peer's outbound queue, bounded in **bytes** rather than frames.
///
/// A plain 512-slot channel of `Bytes` sounds bounded and is not: each slot
/// may hold a whole `max_frame_bytes` frame, so one peer that stops reading
/// can park 512 × 256 KiB = 128 MiB that no per-room or process log budget
/// accounts for. Frames in flight are not retained history, so the log budget
/// never sees them. Counting bytes here is what makes the process ceiling in
/// `LogBudget` an actual ceiling rather than an estimate.
#[derive(Clone)]
pub struct PeerTx {
    tx: mpsc::Sender<Bytes>,
    queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max_bytes: usize,
    /// This connection asked for the log index of every DOC_UPDATE relayed to
    /// it (amendment H).
    pub indexed: bool,
    /// Set when the next ERROR frame queued for this connection is its last:
    /// the writer closes the connection after sending it, the way it does
    /// after a PURGE or RESTART_TICKET.
    close_after_error: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl PeerTx {
    pub fn new(tx: mpsc::Sender<Bytes>, max_bytes: usize) -> Self {
        PeerTx {
            tx,
            queued: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_bytes,
            indexed: false,
            close_after_error: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Queue `error` and close the connection once the writer has sent it.
    pub fn send_final_error(&self, error: Bytes) -> Result<(), PeerBacklogged> {
        self.close_after_error.store(true, Ordering::SeqCst);
        self.try_send(error)
    }

    /// The flag `send_final_error` sets. The connection's writer holds this
    /// and never a `PeerTx`: a second `Sender` kept alive for the
    /// connection's life would stop `recv()` from returning `None` when the
    /// room drops a backlogged peer, and that peer would stay connected.
    pub fn close_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.close_after_error.clone()
    }

    /// Relay DOC_UPDATEs to this connection with their log index.
    pub fn with_indexes(mut self, indexed: bool) -> Self {
        self.indexed = indexed;
        self
    }

    /// A handle the reader uses to give bytes back as it drains them.
    pub fn meter(&self) -> QueueMeter {
        QueueMeter { queued: self.queued.clone() }
    }

    /// Non-blocking. `Err` means the peer is not keeping up and should be
    /// dropped — the same contract the raw channel's `try_send` had.
    pub fn try_send(&self, frame: Bytes) -> Result<(), PeerBacklogged> {
        let n = frame.len();
        if self.queued.fetch_add(n, Ordering::SeqCst) + n > self.max_bytes {
            self.queued.fetch_sub(n, Ordering::SeqCst);
            return Err(PeerBacklogged);
        }
        if self.tx.try_send(frame).is_err() {
            self.queued.fetch_sub(n, Ordering::SeqCst);
            return Err(PeerBacklogged);
        }
        Ok(())
    }

    /// Waits for room, so a log replay exerts real backpressure instead of
    /// dropping history on the floor. Gives up once the reader has clearly
    /// stopped draining.
    pub async fn send_backpressured(&self, frame: Bytes) -> Result<(), PeerBacklogged> {
        for _ in 0..600 {
            match self.try_send(frame.clone()) {
                Ok(()) => return Ok(()),
                Err(_) if self.tx.is_closed() => return Err(PeerBacklogged),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        Err(PeerBacklogged)
    }

    #[cfg(test)]
    pub fn queued_bytes(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }
}

/// The peer is not keeping up and should be dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct PeerBacklogged;

/// Held by the connection's read loop; returns quota as frames are written
/// out to the socket.
pub struct QueueMeter {
    queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl QueueMeter {
    pub fn release(&self, n: usize) {
        self.queued
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                Some(cur.saturating_sub(n))
            })
            .ok();
    }
}

/// Per-room attempt limiter.
///
/// A sliding window, and deliberately nothing more. `record_failure` computes
/// an escalating backoff that is reported but never armed, and that is the
/// right call rather than an oversight:
///
/// The credential the server checks is SHA-256 over a 32-byte HKDF output, so
/// there is nothing here to brute-force directly. An attacker guessing
/// *passphrases* pays 64 MiB of Argon2id per attempt in their own browser
/// before they can even send one, and the window already caps them at five
/// per minute. An escalating lockout would therefore buy almost nothing
/// against an attacker — while handing anyone who knows a room id a way to
/// lock its actual occupants out for a quarter of an hour by failing auth on
/// purpose. The window is per room, so that cost lands on the wrong people.
/// Per-room authentication throttle, keyed by caller.
///
/// It used to be one sliding window for the whole room, shared by everyone,
/// and it consumed a slot on every attempt rather than only on failures. Five
/// attempts a minute between all comers meant anybody who knew a room's name
/// could spend them and keep every legitimate join failing — indefinitely, for
/// as long as they cared to. Named rooms are the exposed case by construction:
/// the names are readable, shared and often guessable.
///
/// That mattered more here than the shape of it suggests. Established sockets
/// survive such an attack; reconnects do not, and reconnects are constant —
/// switching tabs, a laptop sleeping, a network blip. The symptom would have
/// been "I got dropped and cannot get back in", which is also exactly what a
/// wrong passphrase looks like.
///
/// Keyed by caller, one attacker can only exhaust their own budget. The global
/// per-IP limiter in `AppState` still caps the total across all rooms, and the
/// table is bounded and evicts by fullness, so a flood of fresh keys cannot
/// push a throttled one out and hand it a fresh allowance.
///
/// This does lower the whole-room brute-force ceiling: an attacker with many
/// addresses now gets a budget per address. That is an acceptable trade here
/// and only here, because the verifier is a SHA-256 over a 256-bit
/// random-equivalent value — online guessing was never the threat the room
/// window was holding back, and the threat model says so in as many words.
struct AuthGuard {
    per_caller: crate::heimdall::ratelimit::RateLimiter<String>,
}

/// Enough callers per room that a legitimate crowd never evicts one another,
/// small enough that a room cannot be used as an allocation primitive.
const AUTH_CALLERS_TRACKED: usize = 4096;

impl AuthGuard {
    fn new(max_per_min: u32) -> Self {
        AuthGuard {
            per_caller: crate::heimdall::ratelimit::RateLimiter::new(
                max_per_min,
                Duration::from_secs(60),
                AUTH_CALLERS_TRACKED,
            ),
        }
    }

    fn allow(&self, caller: &str) -> bool {
        self.per_caller.check(&caller.to_string())
    }

    /// Advisory only. Reported so operators can see pressure on a room in the
    /// logs; it gates nothing. A lockout would hand anyone who knows a room id
    /// the power to lock out its occupants, which buys little against an
    /// attacker already paying 64 MiB of Argon2id per guess.
    fn record_failure(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn reset(&self, caller: &str) {
        self.per_caller.reset(&caller.to_string());
    }

    fn sweep(&self) {
        self.per_caller.sweep();
    }
}

pub struct Room {
    pub max_peers: usize,
    pub id: [u8; 16],
    pub class: RoomClass,
    pub state: Mutex<RoomState>,
    pub created_unix: u64,
    pub ttl: Ttl,
    pub ceiling_optout: bool,
    pub last_edit: Mutex<Instant>,
    pub last_peer_left: Mutex<Instant>,
    pub verifier: Option<Secret<[u8; 32]>>,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
    pub salt: [u8; 16],
    pub config_blob: Option<Bytes>,
    pub log: std::sync::RwLock<RoomLog>,
    pub peers: Mutex<Vec<ConnectedPeer>>,
    pub next_seq: AtomicU64,
    /// The room's epoch and the epoch of its current root (amendment J).
    epochs: Mutex<EpochState>,
    pub ttl_extension_secs: AtomicU64,
    /// Random per `Room` value, and so per log. A room brought back after a
    /// restart has the same id and a new, empty log; this is how a member
    /// tells the two apart and knows to send its whole copy again rather than
    /// resume from an index that no longer means anything (amendment I).
    pub log_id: [u8; 8],
    auth_guard: AuthGuard,
    purge_acks: Mutex<std::collections::HashMap<String, PurgeAckSet>>,
    /// When the latest SHRED_REQUEST was relayed, and the join sequence number
    /// the next peer would have had then. Everyone who joined before it could
    /// have seen the request; nobody who joined after it could.
    shred_opened: Mutex<Option<(Instant, u64)>>,
}

/// Acks for one request id, with the instant they were first seen so the
/// ledger can be swept. Unbounded growth here was a remote memory-exhaustion
/// vector: one peer could mint a new entry per frame, forever.
struct PurgeAckSet {
    peers: std::collections::HashSet<[u8; 16]>,
    /// The peers connected when this request's FIRST ack arrived.
    ///
    /// Quorum is measured against this, not against whoever happens to be
    /// connected when the last ack lands. Every peer wipes and disconnects
    /// immediately after acking, so a live-set comparison shrinks as the acks
    /// arrive and is satisfied by whoever happens to ack last — which is one
    /// peer, not consensus. Freezing the cohort also denies the inverse
    /// attack: a hostile peer cannot shrink the denominator by dropping
    /// sockets, because the honest peers are already in the cohort and still
    /// have to ack.
    cohort: std::collections::HashSet<[u8; 16]>,
    opened: Instant,
}

/// Hard caps on the purge-ack ledger. A request id is a client-chosen string;
/// nothing about it is trusted.
pub const MAX_PURGE_REQUEST_IDS: usize = 16;
pub const MAX_PURGE_REQUEST_ID_LEN: usize = 128;
/// How long a partial set of purge acks is kept. Every member acks the moment
/// its own copy of the vote reaches a decision, and they all see the same
/// votes at once, so a real set completes within a round trip or two. One
/// still open after this is stale — a stray ack from a local timer, say — and
/// kept longer it would hold a cohort that no longer matches the room over the
/// next real decision.
const PURGE_ACK_TTL: Duration = Duration::from_secs(30);

/// How long after a SHRED_REQUEST its snapshot of who was present decides the
/// purge cohort. Covers the longest vote a client will accept (one hour).
const SHRED_REQUEST_WINDOW: Duration = Duration::from_secs(3600);

/// A room may never be extended past this, no matter how many peers ask.
/// Without it a single peer could pin a room — and its log — in memory
/// forever by replaying TTL_EXTEND, which defeats the entire expiry model.
pub const MAX_TTL_EXTENSION_SECS: u64 = 720 * 3600;

#[derive(Debug, PartialEq, Eq)]
pub enum JoinError {
    Full,
    /// The room has stepped to a new epoch and this peer sent no
    /// key-agreement key, so it cannot be handed the key (amendment J).
    Rotated,
    AuthLockedOut(Duration),
}

impl Room {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: [u8; 16],
        class: RoomClass,
        created_unix: u64,
        ttl: Ttl,
        ceiling_optout: bool,
        verifier: Option<[u8; 32]>,
        kdf_m_kib: u32,
        kdf_t: u32,
        kdf_p: u32,
        salt: [u8; 16],
        config_blob: Option<Bytes>,
        log_max_bytes: u64,
        auth_max_per_min: u32,
        max_peers: usize,
    ) -> Self {
        Room::with_budget(
            id, class, created_unix, ttl, ceiling_optout, verifier, kdf_m_kib, kdf_t, kdf_p,
            salt, config_blob, log_max_bytes, auth_max_per_min, max_peers,
            LogBudget::unlimited(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_budget(
        id: [u8; 16],
        class: RoomClass,
        created_unix: u64,
        ttl: Ttl,
        ceiling_optout: bool,
        verifier: Option<[u8; 32]>,
        kdf_m_kib: u32,
        kdf_t: u32,
        kdf_p: u32,
        salt: [u8; 16],
        config_blob: Option<Bytes>,
        log_max_bytes: u64,
        auth_max_per_min: u32,
        max_peers: usize,
        budget: std::sync::Arc<LogBudget>,
    ) -> Self {
        let now = Instant::now();
        Room {
            id,
            class,
            state: Mutex::new(RoomState::Active),
            created_unix,
            ttl,
            ceiling_optout,
            last_edit: Mutex::new(now),
            last_peer_left: Mutex::new(now),
            verifier: verifier.map(|v| Secret::new(Box::new(v))),
            kdf_m_kib,
            kdf_t,
            kdf_p,
            salt,
            config_blob,
            log: std::sync::RwLock::new(RoomLog::with_budget(log_max_bytes, budget)),
            peers: Mutex::new(Vec::new()),
            max_peers,
            next_seq: AtomicU64::new(1),
            epochs: Mutex::new(EpochState::new(0, 0)),
            ttl_extension_secs: AtomicU64::new(0),
            log_id: {
                let mut b = [0u8; 8];
                getrandom::fill(&mut b).expect("system RNG unavailable");
                b
            },
            auth_guard: AuthGuard::new(auth_max_per_min),
            purge_acks: Mutex::new(std::collections::HashMap::new()),
            shred_opened: Mutex::new(None),
        }
    }

    pub fn verifier_ref(&self) -> Option<&[u8; 32]> {
        self.verifier.as_ref().map(|s| s.expose_secret())
    }

    pub fn auth_allowed(&self, caller: &str) -> bool {
        self.auth_guard.allow(caller)
    }

    /// Forget callers whose join budget has fully refilled. See
    /// `RateLimiter::sweep`.
    pub fn forget_idle_callers(&self) {
        self.auth_guard.sweep();
    }

    pub fn record_auth_failure(&self) -> Duration {
        self.auth_guard.record_failure()
    }

    pub fn auth_success(&self, caller: &str) {
        self.auth_guard.reset(caller);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    pub fn touch(&self) {
        *self.last_edit.lock().unwrap() = Instant::now();
    }

    pub fn add_peer(
        &self,
        pubkey: Option<Vec<u8>>,
        kx: Option<PeerKx>,
        tx: PeerTx,
    ) -> Result<RosterEntry, JoinError> {
        // Lock order, everywhere: `epochs`, then `peers`. The rotated-room
        // check and the insert are one critical section against
        // `step_epoch`, which advances the epoch and closes the peers
        // without a key under the same two locks: a joiner is either in the
        // list when the step closes the kx-less peers, or sees the new epoch.
        let epochs = self.epochs.lock().unwrap();
        let mut peers = self.peers.lock().unwrap();
        if peers.len() >= self.max_peers {
            return Err(JoinError::Full);
        }
        if kx.is_none() && epochs.epoch() != epochs.root_epoch() {
            return Err(JoinError::Rotated);
        }
        // No authentication check here. The caller has already authenticated
        // and already spent a slot doing it; checking again spent a second one
        // for the same join, so a successful connection cost two of the five a
        // caller gets in a minute.
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let entry = RosterEntry {
            peer_id: generate_peer_id(seq),
            pubkey: pubkey.clone(),
            kx: kx.clone(),
            joined_at_seq: seq,
        };
        peers.push(ConnectedPeer { peer_id: entry.peer_id, pubkey, kx, joined_at_seq: seq, tx });
        Ok(entry)
    }

    pub fn remove_peer(&self, peer_id: &[u8; 16]) -> bool {
        let mut peers = self.peers.lock().unwrap();
        let before = peers.len();
        peers.retain(|p| p.peer_id != *peer_id);
        if peers.len() != before && peers.is_empty() {
            *self.last_peer_left.lock().unwrap() = Instant::now();
        }
        peers.len() != before
    }

    pub fn sender_for(&self, peer_id: &[u8; 16]) -> Option<PeerTx> {
        self.peers.lock().unwrap()
            .iter().find(|p| p.peer_id == *peer_id)
            .map(|p| p.tx.clone())
    }

    pub fn roster(&self) -> Vec<RosterEntry> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .map(|p| RosterEntry {
                peer_id: p.peer_id,
                pubkey: p.pubkey.clone(),
                kx: p.kx.clone(),
                joined_at_seq: p.joined_at_seq,
            })
            .collect()
    }

    pub fn epoch(&self) -> u32 {
        self.epochs.lock().unwrap().epoch()
    }

    pub fn root_epoch(&self) -> u32 {
        self.epochs.lock().unwrap().root_epoch()
    }

    /// Decide an EPOCH_KEY and enqueue it, in one critical section.
    ///
    /// The decision (`EpochState::offer`) and the fan-out happen while the
    /// epochs lock is held, so two steps racing for the same epoch reach every
    /// peer in the order the room decided them: the winner's copy is queued
    /// before any relay of a loser's, and no peer is wrapped in a step the
    /// room has already superseded. The fan-out is `try_send`, so nothing
    /// awaits under the lock.
    ///
    /// Lock order is `epochs` then `peers` (see `add_peer`).
    ///
    /// * `Advanced`: peers without a key-agreement key get `kx_less_error`
    ///   and are closed after it (they cannot be handed the new key); then
    ///   every peer, the sender included, gets the frame with the sender
    ///   envelope, so a sender learns its step won the way everyone does.
    /// * `Handover`: every peer except the sender gets it, enveloped.
    /// * `Refused`: nothing is sent.
    pub fn step_epoch(
        &self,
        header_epoch: u32,
        now: Instant,
        min_interval: Duration,
        frame: &Bytes,
        sender: [u8; 16],
        kx_less_error: &Bytes,
    ) -> Offer {
        let mut epochs = self.epochs.lock().unwrap();
        let offer = epochs.offer(header_epoch, now, min_interval);
        if offer == Offer::Refused {
            return offer;
        }
        let outbound = envelop(frame, sender);
        let mut dead = Vec::new();
        {
            let peers = self.peers.lock().unwrap();
            if offer == Offer::Advanced {
                for p in peers.iter().filter(|p| p.kx.is_none()) {
                    if p.tx.send_final_error(kx_less_error.clone()).is_err() {
                        dead.push(p.peer_id);
                    }
                }
            }
            for p in peers.iter() {
                if offer == Offer::Handover && p.peer_id == sender {
                    continue;
                }
                if p.tx.try_send(outbound.clone()).is_err() {
                    dead.push(p.peer_id);
                }
            }
        }
        drop(epochs);
        for id in dead {
            self.remove_peer(&id);
        }
        offer
    }

    pub fn admit_epoch(&self, frame_epoch: u32, now: Instant, overlap: Duration) -> Admit {
        self.epochs.lock().unwrap().admit(frame_epoch, now, overlap)
    }

    /// Set a room brought back from a restart ticket to the epochs it had.
    pub fn restore_epochs(&self, epoch: u32, root_epoch: u32) {
        *self.epochs.lock().unwrap() = EpochState::new(epoch, root_epoch);
    }

    /// Fan out a **server-authored** frame verbatim. PROTOCOL.md amendment C
    /// is explicit that JOIN_ACK, PEER_JOIN, PEER_LEAVE, PURGE, ERROR and
    /// TTL_EXTEND are never enveloped — receivers read their JSON straight
    /// out of the body. `broadcast` would prepend 16 sender bytes and make
    /// that JSON unparseable, so event frames must come through here.
    pub async fn broadcast_event(&self, frame: &Bytes, exclude: Option<[u8; 16]>) {
        let peers = self.peers.lock().unwrap();
        let mut dead = Vec::new();
        for p in peers.iter() {
            if Some(p.peer_id) == exclude {
                continue;
            }
            if p.tx.try_send(frame.clone()).is_err() {
                dead.push(p.peer_id);
            }
        }
        drop(peers);
        for id in dead {
            self.remove_peer(&id);
        }
    }

    /// Fan out a relayed peer frame to every connected peer except the origin.
    /// The outbound copy carries a 16-byte sender envelope between header and
    /// body so that receivers can rebuild their AEAD (amendment C).
    pub async fn broadcast(&self, frame: &Bytes, sender: Option<[u8; 16]>) {
        let peers = self.peers.lock().unwrap();
        let mut dead = Vec::new();
        for p in peers.iter() {
            if Some(p.peer_id) == sender {
                continue;
            }
            let outbound = match sender {
                Some(sid) => envelop(frame, sid),
                None => frame.clone(),
            };
            if p.tx.try_send(outbound).is_err() {
                dead.push(p.peer_id);
            }
        }
        drop(peers);
        for id in dead {
            self.remove_peer(&id);
        }
    }

    /// Fan out a stored DOC_UPDATE. Connections that asked for indexes get the
    /// entry's log index between the sender envelope and the body (amendment
    /// H); the rest get the ordinary envelope.
    pub async fn broadcast_update(&self, frame: &Bytes, sender: [u8; 16], index: u64) {
        let peers = self.peers.lock().unwrap();
        let mut dead = Vec::new();
        let mut plain: Option<Bytes> = None;
        let mut indexed: Option<Bytes> = None;
        for p in peers.iter() {
            if p.peer_id == sender {
                continue;
            }
            let outbound = if p.tx.indexed {
                indexed.get_or_insert_with(|| envelop_indexed(frame, sender, index)).clone()
            } else {
                plain.get_or_insert_with(|| envelop(frame, sender)).clone()
            };
            if p.tx.try_send(outbound).is_err() {
                dead.push(p.peer_id);
            }
        }
        drop(peers);
        for id in dead {
            self.remove_peer(&id);
        }
    }

    /// A purge executes only when every currently-connected peer has
    /// acknowledged the same request id. There is deliberately no timeout:
    /// a lone hostile peer must never be able to destroy the shared copy,
    /// and the server holds no keys that would make premature destruction
    /// "safe". Fail-closed means fail-forever until real consensus.
    /// A SHRED_REQUEST is being relayed. Remember who could have seen it.
    pub fn note_shred_request(&self) {
        *self.shred_opened.lock().unwrap() =
            Some((Instant::now(), self.next_seq.load(Ordering::SeqCst)));
    }

    pub fn note_purge_ack(&self, request_id: &str, peer_id: [u8; 16]) -> PurgeAckStatus {
        self.note_purge_ack_at(request_id, peer_id, Instant::now())
    }

    fn note_purge_ack_at(&self, request_id: &str, peer_id: [u8; 16], now: Instant) -> PurgeAckStatus {
        if request_id.is_empty() || request_id.len() > MAX_PURGE_REQUEST_ID_LEN {
            return PurgeAckStatus::Pending;
        }
        // The quorum is measured against the peers connected *right now*, and
        // an ack only counts while its peer is still one of them. Previously
        // the ledger kept every ack forever and compared its size against a
        // live count, so one peer could bank acks from throwaway connections,
        // drop them to shrink the denominator, and purge a room whose other
        // occupants had never agreed to anything.
        let peers: Vec<([u8; 16], u64)> =
            self.peers.lock().unwrap().iter().map(|p| (p.peer_id, p.joined_at_seq)).collect();
        if !peers.iter().any(|(id, _)| *id == peer_id) {
            return PurgeAckStatus::Pending;
        }
        // Who has to agree. Everyone connected, except anyone who joined after
        // the latest shred request: the vote was sent before they arrived and
        // is never replayed, so they can neither see it nor vote in it, and
        // the voters' own clients count them out too (the roster is frozen
        // into the request). Counting them here meant one person arriving
        // mid-vote stopped the purge: every voter wiped and left believing
        // the room destroyed, and it stayed open to anyone with the link.
        //
        // This gives nobody new power. The snapshot is taken by the server
        // when the request passes through, not claimed by anyone, so a member
        // cannot shrink it after the fact; a member who sent a request while
        // alone could equally have purged the room while alone.
        let since = self
            .shred_opened
            .lock()
            .unwrap()
            .filter(|(at, _)| now.saturating_duration_since(*at) < SHRED_REQUEST_WINDOW)
            .map(|(_, seq)| seq);
        let live: std::collections::HashSet<[u8; 16]> = peers
            .iter()
            .filter(|(_, joined)| since.is_none_or(|seq| *joined < seq))
            .map(|(id, _)| *id)
            .collect();

        let mut acks = self.purge_acks.lock().unwrap();
        acks.retain(|_, set| now.saturating_duration_since(set.opened) < PURGE_ACK_TTL);
        if !acks.contains_key(request_id) && acks.len() >= MAX_PURGE_REQUEST_IDS {
            // Full of unresolved votes: drop the oldest rather than grow.
            if let Some(oldest) =
                acks.iter().min_by_key(|(_, s)| s.opened).map(|(k, _)| k.clone())
            {
                acks.remove(&oldest);
            }
        }
        let set = acks.entry(request_id.to_string()).or_insert_with(|| PurgeAckSet {
            peers: std::collections::HashSet::new(),
            cohort: live.clone(),
            opened: now,
        });
        set.peers.insert(peer_id);
        if !set.cohort.is_empty() && set.cohort.is_subset(&set.peers) {
            PurgeAckStatus::AllAcked(request_id.to_string())
        } else {
            PurgeAckStatus::Pending
        }
    }

    /// Any single peer may extend the timer (spec §5.9.4). Extension pushes
    /// the effective deadline out without ever shortening it.
    pub fn extend_ttl(&self, add_secs: u64) -> u64 {
        // Clamp against the ceiling before mutating anything, so replaying the
        // frame cannot push the deadline out without limit.
        let mut granted = 0u64;
        let total = self
            .ttl_extension_secs
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                granted = add_secs.min(MAX_TTL_EXTENSION_SECS.saturating_sub(cur));
                Some(cur.saturating_add(granted))
            })
            .map(|prev| prev.saturating_add(granted))
            .unwrap_or(0);
        if granted == 0 {
            return total;
        }
        match self.ttl.kind {
            TtlKind::IdleEdit => {
                let mut last = self.last_edit.lock().unwrap();
                *last = last
                    .checked_add(Duration::from_secs(granted.min(86_400)))
                    .unwrap_or(*last);
            }
            TtlKind::IdlePeers => {
                let mut last = self.last_peer_left.lock().unwrap();
                *last = Instant::now()
                    .checked_add(Duration::from_secs(granted.min(86_400)))
                    .unwrap_or(*last);
            }
            _ => {}
        }
        total
    }

    pub fn effective_ttl_secs(&self) -> u64 {
        self.ttl.secs.saturating_add(self.ttl_extension_secs.load(Ordering::SeqCst))
    }

    pub fn mark_state(&self, s: RoomState) {
        *self.state.lock().unwrap() = s;
    }

    pub fn current_state(&self) -> RoomState {
        *self.state.lock().unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PurgeAckStatus {
    AllAcked(String),
    Pending,
}

/// Peer ids are server-assigned and untrusted by clients (spec §5.3). A boot
/// nonce mixed with a monotonic counter keeps them unique without a global
/// allocator lock.
static BOOT_NONCE: std::sync::LazyLock<[u8; 8]> = std::sync::LazyLock::new(|| {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("system RNG unavailable");
    b
});

pub fn generate_peer_id(seq: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&*BOOT_NONCE);
    id[8..].copy_from_slice(&seq.to_be_bytes());
    id
}

pub fn envelop(frame: &Bytes, sender: [u8; 16]) -> Bytes {
    let mut out = Vec::with_capacity(frame.len() + 16);
    out.extend_from_slice(&frame[..32.min(frame.len())]);
    out.extend_from_slice(&sender);
    out.extend_from_slice(&frame[32.min(frame.len())..]);
    Bytes::from(out)
}

/// `header(32) || sender(16) || index(8, big-endian) || body`: the ordinary
/// envelope with the entry's log index added. The index is written by the
/// server and is outside the AEAD; a client uses it only to decide what a
/// snapshot may claim to cover. A server that lied about it could have a
/// snapshot cover entries the client never saw, and those would be lost — no
/// new power, since the server holds the log and can drop any entry anyway
/// (amendment H).
pub fn envelop_indexed(frame: &Bytes, sender: [u8; 16], index: u64) -> Bytes {
    let split = 32.min(frame.len());
    let mut out = Vec::with_capacity(frame.len() + 24);
    out.extend_from_slice(&frame[..split]);
    out.extend_from_slice(&sender);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&frame[split..]);
    Bytes::from(out)
}

pub fn parse_header(buf: &[u8]) -> Option<Header> {
    Header::decode(buf)
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateError {
    IdUnavailable,
    NameTaken,
    NameInvalid(names::NameError),
    PassphraseRequired,
    /// The process-wide room budget is full. Rooms are pure RAM, so this is
    /// the backstop that keeps a shared host from being driven into the OOM
    /// killer by anyone who can reach the create endpoint.
    AtCapacity,
}

pub enum RestoreOutcome {
    Restored(std::sync::Arc<Room>),
    /// The room is already back, restored by another of its members.
    AlreadyLive,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// Shredded or expired in this process.
    Retired,
    /// Somebody else created a room by this name in the seconds between the
    /// old process stopping and the ticket arriving.
    NameTaken,
    NameInvalid,
    AtCapacity,
}

pub struct RoomRegistry {
    rooms: DashMap<[u8; 16], std::sync::Arc<Room>>,
    names: DashMap<String, [u8; 16]>,
    retired: DashMap<[u8; 16], std::time::Instant>,
    max_rooms: usize,
    max_retired: usize,
    log_budget: std::sync::Arc<LogBudget>,
}

impl Default for RoomRegistry {
    fn default() -> Self {
        RoomRegistry::with_limits(
            crate::config::DEFAULT_MAX_ROOMS,
            crate::config::DEFAULT_TOTAL_LOG_BYTES,
        )
    }
}

impl RoomRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_rooms: usize) -> Self {
        RoomRegistry::with_limits(max_rooms, crate::config::DEFAULT_TOTAL_LOG_BYTES)
    }

    pub fn with_limits(max_rooms: usize, total_log_bytes: u64) -> Self {
        RoomRegistry {
            rooms: DashMap::new(),
            names: DashMap::new(),
            retired: DashMap::new(),
            log_budget: std::sync::Arc::new(LogBudget::new(total_log_bytes)),
            max_rooms: max_rooms.max(1),
            // Retired ids exist only to stop id reuse; bound the tombstones
            // so they cannot become their own memory leak.
            max_retired: max_rooms.saturating_mul(8).max(1024),
        }
    }

    pub fn max_rooms(&self) -> usize {
        self.max_rooms
    }

    /// Live ciphertext held across every room, and the ceiling it is measured
    /// against. Exposed so operators can see the real number rather than
    /// reason about `max_rooms × max_log_bytes`.
    pub fn log_bytes_used(&self) -> u64 {
        self.log_budget.used()
    }

    pub fn log_bytes_max(&self) -> u64 {
        self.log_budget.max()
    }

    pub fn get(&self, id: &[u8; 16]) -> Option<std::sync::Arc<Room>> {
        self.rooms.get(id).map(|r| r.clone())
    }

    /// Every live room, for the rare message that goes to all of them.
    pub fn all(&self) -> Vec<std::sync::Arc<Room>> {
        self.rooms.iter().map(|r| r.value().clone()).collect()
    }

    pub fn exists(&self, id: &[u8; 16]) -> bool {
        self.rooms.contains_key(id) || self.retired.contains_key(id)
    }

    #[cfg(test)]
    pub fn retired_contains(&self, id: &[u8; 16]) -> bool {
        self.retired.contains_key(id)
    }

    /// Unlisted room ids are **server-assigned**. Letting the caller name the
    /// id turned this endpoint into an existence oracle — 409 meant "that room
    /// is live", 201 meant "it is not" — which undid the care taken to hide
    /// exactly that on `/api/meta/id/{id}`. It also allowed squatting an id
    /// somebody else was about to use.
    #[allow(clippy::too_many_arguments)]
    pub fn create_unlisted(
        &self,
        ttl: Ttl,
        ceiling_optout: bool,
        verifier: [u8; 32],
        kdf_m: u32,
        kdf_t: u32,
        kdf_p: u32,
        salt: [u8; 16],
        config_blob: Option<Bytes>,
        log_max_bytes: u64,
        auth_max: u32,
        max_peers: usize,
    ) -> Result<std::sync::Arc<Room>, CreateError> {
        if self.rooms.len() >= self.max_rooms {
            return Err(CreateError::AtCapacity);
        }
        let mut id = random_room_id();
        for _ in 0..8 {
            if !self.exists(&id) {
                break;
            }
            id = random_room_id();
        }
        if self.exists(&id) {
            return Err(CreateError::IdUnavailable);
        }
        let room = std::sync::Arc::new(Room::with_budget(
            id,
            RoomClass::Unlisted,
            unix_now(),
            ttl,
            ceiling_optout,
            Some(verifier),
            kdf_m,
            kdf_t,
            kdf_p,
            salt,
            config_blob,
            log_max_bytes,
            auth_max,
            max_peers,
            self.log_budget.clone(),
        ));
        self.rooms.insert(id, room.clone());
        Ok(room)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_named(
        &self,
        name: &str,
        suffix: bool,
        ttl: Ttl,
        ceiling_optout: bool,
        verifier: [u8; 32],
        kdf_m: u32,
        kdf_t: u32,
        kdf_p: u32,
        salt: [u8; 16],
        config_blob: Option<Bytes>,
        log_max_bytes: u64,
        auth_max: u32,
        max_peers: usize,
    ) -> Result<(std::sync::Arc<Room>, String), CreateError> {
        let normalized = names::normalize(name);
        names::validate(&normalized).map_err(CreateError::NameInvalid)?;
        if self.rooms.len() >= self.max_rooms {
            return Err(CreateError::AtCapacity);
        }
        let final_name = if suffix {
            // Bounded search: the suffix space is 16 bits, so an unbounded
            // loop here is a request that never returns once it saturates.
            let mut found = None;
            for _ in 0..64 {
                let candidate = format!("{}-{}", normalized, random_suffix());
                if !self.names.contains_key(&candidate) {
                    found = Some(candidate);
                    break;
                }
            }
            match found {
                Some(c) => c,
                None => return Err(CreateError::NameTaken),
            }
        } else if self.names.contains_key(&normalized) {
            return Err(CreateError::NameTaken);
        } else {
            normalized.clone()
        };
        let id = random_room_id();
        let room = std::sync::Arc::new(Room::with_budget(
            id,
            RoomClass::Named(final_name.clone()),
            unix_now(),
            ttl,
            ceiling_optout,
            Some(verifier),
            kdf_m,
            kdf_t,
            kdf_p,
            salt,
            config_blob,
            log_max_bytes,
            auth_max,
            max_peers,
            self.log_budget.clone(),
        ));
        self.rooms.insert(id, room.clone());
        self.names.insert(final_name.clone(), id);
        Ok((room, final_name))
    }

    /// Recreate a room the previous process vouched for in a restart ticket,
    /// under its old id and name, with an empty log (amendment I).
    ///
    /// Only this process's tombstones can refuse it: a room shredded or
    /// expired here stays gone. One shredded before the restart never got a
    /// ticket, because tickets are issued only for rooms alive at the moment
    /// the old process stopped.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        &self,
        id: [u8; 16],
        name: Option<&str>,
        created_unix: u64,
        ttl: Ttl,
        ttl_extension_secs: u64,
        ceiling_optout: bool,
        verifier: [u8; 32],
        kdf_m: u32,
        kdf_t: u32,
        kdf_p: u32,
        salt: [u8; 16],
        config_blob: Option<Bytes>,
        log_max_bytes: u64,
        auth_max: u32,
        max_peers: usize,
        epoch: u32,
        root_epoch: u32,
    ) -> Result<RestoreOutcome, RestoreError> {
        if let Some(n) = name {
            names::validate(n).map_err(|_| RestoreError::NameInvalid)?;
        }
        if self.rooms.contains_key(&id) {
            return Ok(RestoreOutcome::AlreadyLive);
        }
        if self.retired.contains_key(&id) {
            return Err(RestoreError::Retired);
        }
        // Checked before any entry is held: DashMap's len() takes every
        // shard's lock, and would deadlock against an entry we held.
        if self.rooms.len() >= self.max_rooms {
            return Err(RestoreError::AtCapacity);
        }
        let dashmap::mapref::entry::Entry::Vacant(slot) = self.rooms.entry(id) else {
            // Another member's ticket got here first.
            return Ok(RestoreOutcome::AlreadyLive);
        };
        let class = match name {
            Some(n) => match self.names.entry(n.to_string()) {
                dashmap::mapref::entry::Entry::Occupied(_) => return Err(RestoreError::NameTaken),
                dashmap::mapref::entry::Entry::Vacant(v) => {
                    v.insert(id);
                    RoomClass::Named(n.to_string())
                }
            },
            None => RoomClass::Unlisted,
        };
        let room = std::sync::Arc::new(Room::with_budget(
            id,
            class,
            created_unix,
            ttl,
            ceiling_optout,
            Some(verifier),
            kdf_m,
            kdf_t,
            kdf_p,
            salt,
            config_blob,
            log_max_bytes,
            auth_max,
            max_peers,
            self.log_budget.clone(),
        ));
        room.ttl_extension_secs
            .store(ttl_extension_secs.min(MAX_TTL_EXTENSION_SECS), Ordering::SeqCst);
        room.restore_epochs(epoch, root_epoch);
        slot.insert(room.clone());
        Ok(RestoreOutcome::Restored(room))
    }

    pub fn resolve_name(&self, name: &str) -> Option<(String, std::sync::Arc<Room>)> {
        let key = names::normalize(name);
        let id = *self.names.get(&key)?;
        let room = self.get(&id)?;
        Some((key, room))
    }

    /// Run `Room::forget_idle_callers` on every live room.
    pub fn forget_idle_callers(&self) {
        for entry in self.rooms.iter() {
            entry.value().forget_idle_callers();
        }
    }

    pub fn sweep_candidates(
        &self,
        drain_grace: Duration,
        idle_ceiling: Duration,
    ) -> Vec<(std::sync::Arc<Room>, &'static str)> {
        let cutoff = std::time::Instant::now() - Duration::from_secs(7 * 24 * 3600);
        self.retired.retain(|_, t| *t > cutoff);
        let mut out = Vec::new();
        for entry in self.rooms.iter() {
            let room = entry.value();
            if matches!(room.current_state(), RoomState::Purging | RoomState::Dead) {
                continue;
            }
            let reason = match room.ttl.kind {
                TtlKind::Absolute => {
                    let deadline = room
                        .created_unix
                        .saturating_add(room.effective_ttl_secs());
                    (unix_now() >= deadline).then_some("ttl-expired")
                }
                TtlKind::IdleEdit => {
                    let idle = room.last_edit.lock().unwrap().elapsed();
                    (idle >= Duration::from_secs(room.effective_ttl_secs()))
                        .then_some("idle-expired")
                }
                TtlKind::IdlePeers => {
                    if room.peer_count() == 0 {
                        let idle = room.last_peer_left.lock().unwrap().elapsed();
                        let minimum = Duration::from_secs(room.effective_ttl_secs())
                            .max(drain_grace);
                        (idle >= minimum).then_some("idle-expired")
                    } else {
                        None
                    }
                }
                TtlKind::None => {
                    if !room.ceiling_optout
                        && room.peer_count() == 0
                        && room.last_edit.lock().unwrap().elapsed() >= idle_ceiling.max(drain_grace)
                    {
                        Some("idle-ceiling")
                    } else {
                        None
                    }
                }
            };
            if let Some(reason) = reason {
                out.push((room.clone(), reason));
            }
        }
        out
    }

    pub fn remove_room(&self, id: &[u8; 16]) -> Option<(std::sync::Arc<Room>, Option<String>)> {
        let removed = self.rooms.remove(id).map(|(_, r)| r);
        let name = removed.as_ref().and_then(|room| match &room.class {
            RoomClass::Named(n) => Some(n.clone()),
            RoomClass::Unlisted => None,
        });
        if let Some(n) = &name {
            self.names.remove(n);
        }
        if self.retired.len() >= self.max_retired {
            let cutoff = std::time::Instant::now() - Duration::from_secs(24 * 3600);
            self.retired.retain(|_, t| *t > cutoff);
        }
        self.retired.insert(*id, std::time::Instant::now());
        removed.map(|r| (r, name))
    }

    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    pub fn name_count(&self) -> usize {
        self.names.len()
    }
}

fn random_room_id() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("system RNG unavailable");
    b
}

fn random_suffix() -> String {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).expect("system RNG unavailable");
    format!("{:x}{:x}{:x}{:x}", b[0] >> 4, b[0] & 0xF, b[1] >> 4, b[1] & 0xF)
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A KDF salt for tests, drawn at random like a real one. Tests used fixed
/// literals, which no test ever asserted on, and which read to a scanner as
/// exactly what they would be in production code: a hard-coded salt.
#[cfg(test)]
pub(crate) fn test_salt() -> [u8; 16] {
    let mut s = [0u8; 16];
    getrandom::fill(&mut s).expect("system RNG unavailable");
    s
}

#[cfg(test)]
mod auth_throttle_tests {
    use super::*;

    fn guard() -> AuthGuard {
        AuthGuard::new(5)
    }

    #[test]
    fn one_caller_cannot_spend_another_callers_budget() {
        // The reported fault: the window was shared by the whole room, so
        // anyone who knew a room's name could burn it and keep every other
        // join failing for as long as they liked.
        let g = guard();
        for _ in 0..5 {
            assert!(g.allow("198.51.100.7"), "the attacker's own budget should last five");
        }
        assert!(!g.allow("198.51.100.7"), "and then run out");
        assert!(g.allow("203.0.113.9"), "a different caller must be unaffected");
    }

    #[test]
    fn a_flood_of_callers_cannot_restore_an_exhausted_one() {
        // Eviction by fullness is what makes this hold: evicting the oldest
        // would let an attacker with addresses to spare reset their own bucket.
        let g = guard();
        for _ in 0..5 {
            assert!(g.allow("198.51.100.7"));
        }
        assert!(!g.allow("198.51.100.7"));
        for n in 0..9000u32 {
            g.allow(&format!("10.{}.{}.{}", n / 65536, (n / 256) % 256, n % 256));
        }
        assert!(!g.allow("198.51.100.7"), "an evicted bucket would come back full");
    }

    #[test]
    fn success_clears_only_that_caller() {
        let g = guard();
        for _ in 0..5 {
            g.allow("198.51.100.7");
        }
        for _ in 0..5 {
            g.allow("203.0.113.9");
        }
        assert!(!g.allow("198.51.100.7"));
        assert!(!g.allow("203.0.113.9"));
        g.reset("198.51.100.7");
        assert!(g.allow("198.51.100.7"), "proving the key refills this caller");
        assert!(!g.allow("203.0.113.9"), "and only this caller");
    }

    #[test]
    fn joining_no_longer_spends_two_slots() {
        // add_peer used to run its own auth check after the join path had
        // already run one, so a single successful connection cost two of the
        // five a caller gets in a minute.
        let room = Room::new(
            [9u8; 16],
            RoomClass::Unlisted,
            unix_now(),
            Ttl { kind: TtlKind::None, secs: 0 },
            false,
            Some([1u8; 32]),
            65536,
            3,
            1,
            crate::runar::room::test_salt(),
            None,
            32 * 1024 * 1024,
            5,
            32,
        );
        let before = {
            let mut n = 0;
            while room.auth_allowed("198.51.100.7") {
                n += 1;
            }
            n
        };
        room.auth_success("198.51.100.7");
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        room.add_peer(None, None, PeerTx::new(tx, 1 << 20)).expect("join");
        let after = {
            let mut n = 0;
            while room.auth_allowed("198.51.100.7") {
                n += 1;
            }
            n
        };
        assert_eq!(before, after, "adding a peer must not spend authentication budget");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room_with_ttl(kind: TtlKind, secs: u64) -> Room {
        Room::new(
            [9u8; 16],
            RoomClass::Unlisted,
            unix_now() - secs / 2,
            Ttl { kind, secs },
            false,
            Some([1u8; 32]),
            65536,
            3,
            1,
            crate::runar::room::test_salt(),
            None,
            32 * 1024 * 1024,
            5,
            32,
        )
    }

    #[test]
    fn extend_grows_effective_ttl_and_never_shrinks() {
        let r = room_with_ttl(TtlKind::Absolute, 3600);
        assert_eq!(r.effective_ttl_secs(), 3600);
        let after = r.extend_ttl(600);
        assert_eq!(after, 600);
        assert_eq!(r.effective_ttl_secs(), 4200);
        let after = r.extend_ttl(60);
        assert_eq!(after, 660);
        assert_eq!(r.effective_ttl_secs(), 4260);
    }

    #[test]
    fn idle_peers_extension_pushes_last_peer_left_forward() {
        let r = room_with_ttl(TtlKind::IdlePeers, 60);
        let before = *r.last_peer_left.lock().unwrap();
        r.extend_ttl(300);
        let after = *r.last_peer_left.lock().unwrap();
        assert!(after > before + Duration::from_secs(299));
        assert_eq!(r.peer_count(), 0);
        let registry = RoomRegistry::new();
        assert!(registry.sweep_candidates(Duration::from_secs(5), Duration::from_secs(12 * 3600)).is_empty());
    }
}

#[cfg(test)]
mod purge_ack_tests {
    use super::*;

    fn room() -> Room {
        Room::new(
            [3u8; 16],
            RoomClass::Unlisted,
            unix_now(),
            Ttl { kind: TtlKind::IdlePeers, secs: 3600 },
            false,
            Some([2u8; 32]),
            65536,
            3,
            1,
            crate::runar::room::test_salt(),
            None,
            32 * 1024 * 1024,
            5,
            32,
        )
    }

    fn connect(room: &Room) -> [u8; 16] {
        let (tx, rx) = mpsc::channel(8);
        // Hold the receiver open for the lifetime of the test.
        std::mem::forget(rx);
        room.add_peer(None, None, PeerTx::new(tx, 1 << 20)).unwrap().peer_id
    }

    fn kx() -> Option<PeerKx> {
        Some(PeerKx { pubkey: vec![4u8; 65], sig: vec![1u8; 64] })
    }

    #[test]
    fn a_rotated_room_refuses_a_joiner_without_a_key_and_takes_one_with() {
        let r = room();
        let (tx, _rx) = mpsc::channel(8);
        assert!(r.add_peer(None, None, PeerTx::new(tx, 1 << 20)).is_ok(), "epoch 0 admits it");
        r.restore_epochs(1, 0);
        let (tx, _rx) = mpsc::channel(8);
        assert_eq!(
            r.add_peer(None, None, PeerTx::new(tx, 1 << 20)).unwrap_err(),
            JoinError::Rotated
        );
        assert_eq!(r.peer_count(), 1, "a refused joiner is not left in the list");
        let (tx, _rx) = mpsc::channel(8);
        assert!(r.add_peer(None, kx(), PeerTx::new(tx, 1 << 20)).is_ok());
    }

    #[tokio::test]
    async fn a_step_closes_peers_without_a_key_and_queues_in_decision_order() {
        let r = room();
        let t = Instant::now();
        let none = Duration::ZERO;
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        let (tx_c, mut rx_c) = mpsc::channel(8);
        let a = r.add_peer(None, kx(), PeerTx::new(tx_a, 1 << 20)).unwrap().peer_id;
        let b = r.add_peer(None, kx(), PeerTx::new(tx_b, 1 << 20)).unwrap().peer_id;
        r.add_peer(None, None, PeerTx::new(tx_c, 1 << 20)).unwrap();
        let err = Bytes::from_static(b"ERR");
        let win = Bytes::from(vec![0u8; 32]);
        let lose = Bytes::from(vec![1u8; 32]);

        assert_eq!(r.step_epoch(1, t, none, &win, a, &err), Offer::Advanced);
        // The same-epoch step that lost is only ever a handover, after it.
        assert_eq!(r.step_epoch(1, t, none, &lose, b, &err), Offer::Handover);

        // A (the winner's sender) gets its own step, then the loser's relay.
        assert_eq!(rx_a.recv().await.unwrap()[0], 0);
        assert_eq!(rx_a.recv().await.unwrap()[0], 1);
        // B gets the winner's step, and never its own loser as a relay.
        assert_eq!(rx_b.recv().await.unwrap()[0], 0);
        assert!(rx_b.try_recv().is_err());
        // C had no key: the error comes first and then the step it lost.
        assert_eq!(&rx_c.recv().await.unwrap()[..], b"ERR");
        assert!(rx_c.try_recv().is_ok());
    }

    #[test]
    fn lone_peer_can_never_trigger_purge_via_deadline_or_fake_ids() {
        let r = room();
        let hostile = connect(&r);
        let _honest = connect(&r);
        for _ in 0..50 {
            match r.note_purge_ack("invented-id", hostile) {
                PurgeAckStatus::Pending => {}
                PurgeAckStatus::AllAcked(_) => panic!("single ack must never satisfy quorum"),
            }
        }
    }

    #[test]
    fn purge_fires_only_when_every_connected_peer_acks_same_id() {
        let r = room();
        let a = connect(&r);
        let b = connect(&r);
        assert_eq!(r.note_purge_ack("req", a), PurgeAckStatus::Pending);
        assert_eq!(
            r.note_purge_ack("other-req", b),
            PurgeAckStatus::Pending,
            "different request id must not count"
        );
        assert_eq!(r.note_purge_ack("req", b), PurgeAckStatus::AllAcked("req".into()));
    }

    /// The bug this pins: acks used to be banked forever and compared against
    /// a live peer count taken at ack time, so one peer could approve from
    /// throwaway sockets, drop them to shrink the denominator, and destroy a
    /// room its remaining occupants had never voted on.
    #[test]
    fn banked_acks_from_departed_peers_do_not_form_a_quorum() {
        let r = room();
        let honest = connect(&r);
        let mut throwaways = Vec::new();
        for _ in 0..4 {
            throwaways.push(connect(&r));
        }
        for id in &throwaways {
            assert_eq!(r.note_purge_ack("consensus", *id), PurgeAckStatus::Pending);
        }
        // The attacker drops every socket but one.
        for id in throwaways.iter().skip(1) {
            r.remove_peer(id);
        }
        assert_eq!(
            r.note_purge_ack("consensus", throwaways[0]),
            PurgeAckStatus::Pending,
            "stale acks must not stand in for the honest peer's vote"
        );
        // Only the honest peer's own ack completes it.
        assert_eq!(
            r.note_purge_ack("consensus", honest),
            PurgeAckStatus::AllAcked("consensus".into())
        );
    }

    /// Reported shape: everyone votes to shred, someone opens the link during
    /// the vote, every voter's page wipes itself — and the room stays up,
    /// because the newcomer, who never saw the request, never acked.
    #[test]
    fn someone_who_joins_during_the_vote_cannot_stop_the_purge() {
        let r = room();
        let a = connect(&r);
        let b = connect(&r);
        r.note_shred_request();
        let _late = connect(&r);
        assert_eq!(r.note_purge_ack("consensus", a), PurgeAckStatus::Pending);
        assert_eq!(r.note_purge_ack("consensus", b), PurgeAckStatus::AllAcked("consensus".into()));
    }

    #[test]
    fn with_no_shred_request_in_flight_everyone_connected_must_ack() {
        let r = room();
        let a = connect(&r);
        let b = connect(&r);
        let c = connect(&r);
        assert_eq!(r.note_purge_ack("consensus", a), PurgeAckStatus::Pending);
        assert_eq!(r.note_purge_ack("consensus", b), PurgeAckStatus::Pending);
        assert_eq!(r.note_purge_ack("consensus", c), PurgeAckStatus::AllAcked("consensus".into()));
    }

    #[test]
    fn a_request_long_past_no_longer_decides_who_counts() {
        let r = room();
        let a = connect(&r);
        r.note_shred_request();
        let later = connect(&r);
        let now = Instant::now() + SHRED_REQUEST_WINDOW + Duration::from_secs(1);
        assert_eq!(r.note_purge_ack_at("consensus", a, now), PurgeAckStatus::Pending);
        assert_eq!(
            r.note_purge_ack_at("consensus", later, now),
            PurgeAckStatus::AllAcked("consensus".into())
        );
    }

    /// A stray ack — a local timer running ahead, say — must not leave its
    /// cohort waiting for the next real decision to complete it.
    #[test]
    fn a_partial_set_of_acks_goes_stale_quickly() {
        let r = room();
        let a = connect(&r);
        let b = connect(&r);
        let t0 = Instant::now();
        assert_eq!(r.note_purge_ack_at("consensus", a, t0), PurgeAckStatus::Pending);
        // Absolute times, not offsets from the constant: a test measured
        // against PURGE_ACK_TTL would pass whatever the constant said.
        assert_eq!(
            r.note_purge_ack_at("consensus", b, t0 + Duration::from_secs(31)),
            PurgeAckStatus::Pending,
            "b alone, half a minute later, is not the room agreeing"
        );
        assert_eq!(
            r.note_purge_ack_at("consensus", a, t0 + Duration::from_secs(32)),
            PurgeAckStatus::AllAcked("consensus".into())
        );
    }

    #[test]
    fn acks_from_peers_who_are_not_connected_are_ignored() {
        let r = room();
        let _a = connect(&r);
        assert_eq!(r.note_purge_ack("req", [0xEE; 16]), PurgeAckStatus::Pending);
    }

    #[test]
    fn request_id_ledger_is_bounded() {
        let r = room();
        let a = connect(&r);
        let _b = connect(&r);
        for i in 0..(MAX_PURGE_REQUEST_IDS * 8) {
            let _ = r.note_purge_ack(&format!("id-{i}"), a);
        }
        assert!(
            r.purge_acks.lock().unwrap().len() <= MAX_PURGE_REQUEST_IDS,
            "ledger must not grow without bound"
        );
        let long = "x".repeat(MAX_PURGE_REQUEST_ID_LEN + 1);
        assert_eq!(r.note_purge_ack(&long, a), PurgeAckStatus::Pending);
        assert!(!r.purge_acks.lock().unwrap().contains_key(&long));
    }

    #[test]
    fn ttl_extension_stops_at_the_ceiling() {
        let r = room();
        for _ in 0..100 {
            r.extend_ttl(MAX_TTL_EXTENSION_SECS);
        }
        assert_eq!(
            r.ttl_extension_secs.load(Ordering::SeqCst),
            MAX_TTL_EXTENSION_SECS,
            "extension must saturate, not accumulate"
        );
    }
}

#[cfg(test)]
mod scheduler_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn expired_absolute_ttl_room_is_swept_and_actually_removed() {
        let registry = RoomRegistry::new();
        let room = registry
            .create_unlisted(
                Ttl { kind: TtlKind::Absolute, secs: 0 },
                false,
                [1u8; 32],
                65536,
                3,
                1,
                crate::runar::room::test_salt(),
                None,
                1024 * 1024,
                5,
                32,
            )
            .unwrap();

        // The bug this pins: marking Purging before purge() made surtr
        // early-return forever, so rooms leaked until process restart.
        let candidates = registry.sweep_candidates(Duration::from_secs(60), Duration::from_secs(12 * 3600));
        assert_eq!(candidates.len(), 1);

        crate::surtr::purge(&registry, &room.id, "ttl-expired").await;
        assert!(registry.get(&room.id).is_none(), "room must be removed from the registry");
        assert!(registry.retired_contains(&room.id), "id must never be reissued");
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    #[tokio::test]
    async fn the_outbound_queue_is_bounded_in_bytes_not_frames() {
        let (tx, rx) = mpsc::channel(512);
        let peer = PeerTx::new(tx, 4096);
        // Four 1 KiB frames fit; the fifth does not, even though the channel
        // has 508 free slots.
        for _ in 0..4 {
            assert!(peer.try_send(Bytes::from(vec![0u8; 1024])).is_ok());
        }
        assert!(peer.try_send(Bytes::from(vec![0u8; 1024])).is_err());
        assert_eq!(peer.queued_bytes(), 4096);

        // Draining returns quota.
        let meter = peer.meter();
        meter.release(2048);
        assert!(peer.try_send(Bytes::from(vec![0u8; 1024])).is_ok());
        drop(rx);
    }

    #[tokio::test]
    async fn a_closed_peer_stops_accepting_immediately() {
        let (tx, rx) = mpsc::channel(4);
        let peer = PeerTx::new(tx, 1 << 20);
        drop(rx);
        assert!(peer.try_send(Bytes::from_static(b"x")).is_err());
        assert!(peer.send_backpressured(Bytes::from_static(b"x")).await.is_err());
    }
}
