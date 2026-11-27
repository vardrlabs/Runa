//! RÚNA server: an ephemeral, blind relay for end-to-end encrypted
//! collaborative documents. Forked from Rustpad; the operational transform
//! engine was removed and replaced with an encrypted CRDT relay.

#![deny(unsafe_code)]

pub mod bifrost;
pub mod config;
pub mod error;
pub mod gjallarhorn;
pub mod heimdall;
pub mod memguard;
pub mod runar;
pub mod surtr;

use std::sync::Arc;
use std::time::Duration;

use crate::bifrost::limits::ConnGuard;
use crate::config::Config;
use crate::heimdall::ratelimit::RateLimiter;
use crate::runar::RoomRegistry;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    /// Boot-time secret used to derive unpredictable placeholder salts for
    /// missing rooms (existence-oracle defence, spec §5.7).
    pub ghost_key: Arc<[u8; 32]>,
    pub rooms: Arc<RoomRegistry>,
    pub started_at: u64,
    pub conn_guard: Arc<ConnGuard>,
    /// Process-wide live connection count, against `cfg.max_connections`.
    pub live_conns: Arc<std::sync::atomic::AtomicUsize>,
    /// When a restart announced by `begin_restart` will stop the process.
    pub restart_deadline: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    pub auth_per_ip: Arc<RateLimiter<String>>,
    pub rooms_created: Arc<RateLimiter<String>>,
    pub named_created: Arc<RateLimiter<String>>,
    pub name_lookup_ip: Arc<RateLimiter<String>>,
    pub name_lookup_global: Arc<RateLimiter<String>>,
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        let started_at = runar::room::unix_now();
        let ghost_key = Arc::new({
            let mut k = [0u8; 32];
            getrandom::fill(&mut k).expect("system RNG unavailable");
            k
        });
        AppState {
            cfg: Arc::new(cfg.clone()),
            ghost_key,
            rooms: Arc::new(RoomRegistry::with_limits(cfg.max_rooms, cfg.max_total_log_bytes)),
            started_at,
            conn_guard: Arc::new(ConnGuard::new(cfg.max_conns_per_ip, Duration::from_secs(300))),
            live_conns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            restart_deadline: Arc::new(std::sync::Mutex::new(None)),
            auth_per_ip: Arc::new(RateLimiter::new(cfg.auth_attempts_per_ip_per_min, Duration::from_secs(60), 100_000)),
            rooms_created: Arc::new(RateLimiter::new(cfg.rooms_created_per_ip_per_hour, Duration::from_secs(3600), 100_000)),
            named_created: Arc::new(RateLimiter::new(cfg.named_rooms_created_per_ip_per_hour, Duration::from_secs(3600), 100_000)),
            name_lookup_ip: Arc::new(RateLimiter::new(cfg.name_lookups_per_ip_per_min, Duration::from_secs(60), 100_000)),
            name_lookup_global: Arc::new(RateLimiter::new(cfg.name_lookups_global_per_min, Duration::from_secs(60), 8)),
        }
    }
}

/// How often per-client limiter state that no longer limits anything is
/// dropped. Short beside every window it serves (a minute to an hour), so a
/// visit is remembered for at most about one window after it ends.
pub const FORGET_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

impl AppState {
    /// Drop every per-client entry that no longer affects a decision: full
    /// buckets, expired blocks, refilled per-room join budgets. Before this,
    /// nothing was removed until a table reached its cap, which a quiet server
    /// never does — so it held a pseudonym for everyone since boot.
    pub fn forget_idle_clients(&self) {
        for limiter in [
            &self.auth_per_ip,
            &self.rooms_created,
            &self.named_created,
            &self.name_lookup_ip,
            &self.name_lookup_global,
        ] {
            limiter.sweep();
        }
        self.conn_guard.sweep();
        self.rooms.forget_idle_callers();
    }

    /// Runs `forget_idle_clients` every `FORGET_INTERVAL`, for the life of
    /// the process.
    pub async fn run_forgetting(self) {
        let mut tick = tokio::time::interval(FORGET_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            self.forget_idle_clients();
        }
    }

    /// Live websocket connections, process-wide.
    pub fn live_connections(&self) -> usize {
        self.live_conns.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Seconds left before an announced restart, if one has been announced.
    pub fn restart_in_secs(&self) -> Option<u64> {
        let deadline = (*self.restart_deadline.lock().unwrap())?;
        Some(deadline.saturating_duration_since(std::time::Instant::now()).as_secs())
    }

    pub fn is_restarting(&self) -> bool {
        self.restart_deadline.lock().unwrap().is_some()
    }

    /// What a RESTART_NOTICE says: the seconds left, and whether rooms will
    /// be handed tickets to carry them over (amendment I), so the page can
    /// tell people which of the two is about to happen.
    pub fn restart_notice_body(&self, in_secs: u64) -> serde_json::Value {
        serde_json::json!({ "in_secs": in_secs, "handover": self.cfg.restart_key.is_some() })
    }

    /// Warn every open room that the process stops in `grace`, and stop
    /// creating rooms that could not outlive it.
    ///
    /// Rooms live only in memory, so a restart without a restart key ends
    /// every one of them. It used to do that without a word: a redeploy in the
    /// middle of someone's session took their document with it. This is the
    /// minute they get to export. Returns how many rooms were told.
    pub async fn begin_restart(&self, grace: Duration) -> usize {
        *self.restart_deadline.lock().unwrap() = Some(std::time::Instant::now() + grace);
        let body = self.restart_notice_body(grace.as_secs());
        let rooms = self.rooms.all();
        for room in &rooms {
            let frame = crate::bifrost::restart_notice(room.id, &body);
            room.broadcast_event(&frame, None).await;
        }
        rooms.len()
    }

    /// Hand every member of every live room its room's restart ticket, which
    /// also closes their connection as a restart (amendment I). Returns how
    /// many rooms got one; zero without a restart key.
    ///
    /// Issued at the very end, not with the warning: a room shredded during
    /// the countdown must not leave its members holding a way to bring it
    /// back. Sent with backpressure rather than dropped on a full queue — a
    /// member who misses theirs can still rejoin once another has restored
    /// the room, but a room nobody got a ticket for is gone.
    pub async fn hand_over(&self) -> usize {
        let Some(key) = self.cfg.restart_key.as_ref() else {
            return 0;
        };
        let now = runar::room::unix_now();
        let mut handed = 0;
        for room in self.rooms.all() {
            if !matches!(room.current_state(), runar::room::RoomState::Active) {
                continue;
            }
            // Issued first: issuing stops the room's epoch and way in from
            // moving (`Room::ticket_access`, under `epochs` alone), so no
            // commit or step can land while the ticket is on its way and
            // leave the members holding a ticket for a room that has moved
            // on. The peers are read after that, under `peers` alone, and
            // the guard is dropped before anything is awaited.
            let Some(ticket) = runar::ticket::issue(key, &room, now) else {
                continue;
            };
            let peers: Vec<_> = room.peers.lock().unwrap().iter().map(|p| p.tx.clone()).collect();
            if peers.is_empty() {
                continue;
            }
            let frame = crate::bifrost::restart_ticket(room.id, &ticket);
            for tx in peers {
                let _ = tokio::time::timeout(Duration::from_secs(2), tx.send_backpressured(frame.clone())).await;
            }
            handed += 1;
        }
        handed
    }
}

pub fn build_router(state: AppState) -> axum::Router {
    crate::bifrost::router::build_router(state)
}

pub use sha2;
/// Re-exported so the fuzz crate can build a LogEntry without taking its own
/// dependency on a version that might drift from this one.
pub use bytes;

