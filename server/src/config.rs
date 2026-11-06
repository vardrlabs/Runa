use std::time::Duration;

/// Rooms are pure RAM. Every one of these is a ceiling on how much of the
/// host a stranger can claim, which is what makes the process safe to run
/// next to other services.
pub const DEFAULT_MAX_ROOMS: usize = 512;

/// Process-wide ceiling on retained ciphertext, across every room. This, not
/// `max_rooms × max_log_bytes`, is the number that bounds the process — the
/// product of the two per-unit limits is 16 GiB at the shipped defaults,
/// which is not a budget anyone can plan a host around.
pub const DEFAULT_TOTAL_LOG_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub bind_addr: String,
    pub dist_dir: String,
    pub allow_insecure_ws: bool,
    /// Trust `X-Forwarded-For` for per-IP rate limiting. Off unless a reverse
    /// proxy terminates connections, because otherwise the header is forgeable.
    pub trusted_proxy: bool,
    /// A second, loopback-only listener for a Tor onion service (see
    /// `bifrost::onion`). Unset, there is none.
    pub onion_bind: Option<String>,
    /// This server's onion address, `http://<56 base32>.onion`. Advertised to
    /// Tor Browser on clearnet pages with `Onion-Location`.
    pub onion_url: Option<String>,
    pub max_frame_bytes: usize,
    pub max_log_bytes: u64,
    pub max_peers_per_room: usize,
    pub drain_grace: Duration,
    pub default_idle_ceiling: Duration,
    pub auth_floor: Duration,
    pub auth_attempts_per_room_per_min: u32,
    pub auth_attempts_per_ip_per_min: u32,
    /// Concurrent websocket connections one address may hold. Offices, schools
    /// and mobile carriers put many people behind a single address, so this sits
    /// well above what one person uses; `max_connections` is what bounds memory.
    pub max_conns_per_ip: usize,
    /// How long open rooms are warned before the process stops on SIGTERM.
    /// Rooms live only in memory, so a restart ends every one of them, and this
    /// is the time people get to export. Zero stops at once.
    pub shutdown_grace: Duration,
    /// How long after a room moves to a new epoch frames from the epoch it
    /// left are still accepted, so edits already in flight land
    /// (PROTOCOL.md amendment J).
    pub epoch_overlap: Duration,
    /// The shortest time between two epoch steps in one room.
    pub epoch_min_interval: Duration,
    pub frames_per_conn_per_sec: u32,
    pub bytes_per_conn_per_sec: u64,
    pub rooms_created_per_ip_per_hour: u32,
    pub named_rooms_created_per_ip_per_hour: u32,
    pub name_lookups_per_ip_per_min: u32,
    pub name_lookups_global_per_min: u32,
    /// Hard ceiling on live rooms. Creation returns 503 past this.
    pub max_rooms: usize,
    /// Hard ceiling on ciphertext retained across all rooms combined.
    pub max_total_log_bytes: u64,
    /// Bytes a single connection may have queued but not yet written to its
    /// socket. Frames in flight are not retained history, so nothing else
    /// accounts for them.
    pub max_queued_bytes_per_conn: usize,
    /// Hard ceiling on concurrent websocket connections, process-wide. The
    /// per-IP limit bounds one address, not the sum of all of them, and each
    /// live connection carries an outbound queue — so without this the memory
    /// ceiling has no closed form.
    pub max_connections: usize,
    /// Ceiling on the encrypted room-config blob a client may park on the
    /// server. Bounded separately from the body limit because it is retained
    /// for the room's whole life.
    pub max_config_blob_bytes: usize,
    /// Allow clients to opt a room out of the idle ceiling (`ttl: none` +
    /// `ceiling_optout`). Off by default: an immortal, never-swept room is a
    /// permanent memory reservation that any anonymous caller could make.
    pub allow_ceiling_optout: bool,
    /// Signs the tickets that let rooms outlive a restart (amendment I). Both
    /// the stopping and the starting process must have the same one. Unset,
    /// no tickets are issued and a restart ends every room.
    pub restart_key: Option<crate::runar::ticket::RestartKey>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:3000".into(),
            dist_dir: "dist".into(),
            allow_insecure_ws: false,
            trusted_proxy: false,
            onion_bind: None,
            onion_url: None,
            // Sized for SNAPSHOT, not for keystrokes. A snapshot carries the
            // whole document state and has to fit in one frame or the log can
            // never be compacted — at 256 KiB that ceiling was around 4,000
            // lines, past which the elected snapshotter was disconnected for
            // an oversized frame every ten minutes, forever. 1 MiB puts the
            // ceiling near 17,000 lines.
            max_frame_bytes: 1024 * 1024,
            max_log_bytes: 32 * 1024 * 1024,
            max_peers_per_room: 32,
            drain_grace: Duration::from_secs(60),
            default_idle_ceiling: Duration::from_secs(12 * 3600),
            auth_floor: Duration::from_millis(250),
            auth_attempts_per_room_per_min: 5,
            auth_attempts_per_ip_per_min: 30,
            max_conns_per_ip: 64,
            shutdown_grace: Duration::from_secs(60),
            epoch_overlap: Duration::from_secs(30),
            epoch_min_interval: Duration::from_secs(5),
            frames_per_conn_per_sec: 100,
            bytes_per_conn_per_sec: 1024 * 1024,
            rooms_created_per_ip_per_hour: 20,
            named_rooms_created_per_ip_per_hour: 5,
            name_lookups_per_ip_per_min: 20,
            name_lookups_global_per_min: 200,
            max_rooms: DEFAULT_MAX_ROOMS,
            max_total_log_bytes: DEFAULT_TOTAL_LOG_BYTES,
            max_queued_bytes_per_conn: 4 * 1024 * 1024,
            max_connections: 1024,
            max_config_blob_bytes: 4096,
            allow_ceiling_optout: false,
            restart_key: None,
        }
    }
}

fn env<T: std::str::FromStr>(key: &str, fallback: T) -> T {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(fallback)
}

impl Config {
    pub fn from_env() -> Self {
        let mut c = Config::default();
        c.bind_addr = std::env::var("RUNA_BIND").unwrap_or(c.bind_addr);
        c.dist_dir = std::env::var("RUNA_DIST").unwrap_or(c.dist_dir);
        c.allow_insecure_ws = std::env::var("RUNA_ALLOW_INSECURE").is_ok_and(|v| v == "1");
        c.trusted_proxy = std::env::var("RUNA_TRUSTED_PROXY").is_ok_and(|v| v == "1");
        c.onion_bind = std::env::var("RUNA_ONION_BIND").ok().filter(|v| !v.is_empty());
        c.onion_url = std::env::var("RUNA_ONION_URL").ok().and_then(|v| onion_url(&v));
        c.max_frame_bytes = env("RUNA_MAX_FRAME", c.max_frame_bytes);
        c.max_log_bytes = env("RUNA_MAX_LOG", c.max_log_bytes);
        c.max_peers_per_room = env("RUNA_MAX_PEERS", c.max_peers_per_room);
        if let Some(secs) = std::env::var("RUNA_DRAIN_GRACE").ok().and_then(|v| v.parse().ok()) {
            c.drain_grace = Duration::from_secs(secs);
        }
        if let Some(secs) = std::env::var("RUNA_IDLE_CEILING").ok().and_then(|v| v.parse().ok()) {
            c.default_idle_ceiling = Duration::from_secs(secs);
        }
        if let Some(ms) = std::env::var("RUNA_AUTH_FLOOR_MS").ok().and_then(|v| v.parse().ok()) {
            c.auth_floor = Duration::from_millis(ms);
        }
        c.frames_per_conn_per_sec = env("RUNA_FRAME_RATE", c.frames_per_conn_per_sec);
        c.bytes_per_conn_per_sec = env("RUNA_BYTE_RATE", c.bytes_per_conn_per_sec);
        c.rooms_created_per_ip_per_hour = env("RUNA_ROOMS_PER_HR", c.rooms_created_per_ip_per_hour);
        c.named_rooms_created_per_ip_per_hour =
            env("RUNA_NAMED_PER_HR", c.named_rooms_created_per_ip_per_hour);
        c.name_lookups_per_ip_per_min =
            env("RUNA_NAME_LOOKUP_IP_MIN", c.name_lookups_per_ip_per_min);
        c.name_lookups_global_per_min =
            env("RUNA_NAME_LOOKUP_GLOBAL_MIN", c.name_lookups_global_per_min);
        c.max_rooms = env::<usize>("RUNA_MAX_ROOMS", c.max_rooms).max(1);
        // Expressed in MiB: nobody wants to write a byte count in a unit file.
        if let Some(mb) = std::env::var("RUNA_MAX_TOTAL_LOG_MB").ok().and_then(|v| v.parse::<u64>().ok()) {
            c.max_total_log_bytes = mb.saturating_mul(1024 * 1024).max(1024 * 1024);
        }
        c.max_config_blob_bytes = env("RUNA_MAX_CONFIG_BLOB", c.max_config_blob_bytes);
        if let Some(kb) = std::env::var("RUNA_MAX_QUEUE_KB").ok().and_then(|v| v.parse::<usize>().ok()) {
            c.max_queued_bytes_per_conn = kb.saturating_mul(1024);
        }
        c.max_connections = env::<usize>("RUNA_MAX_CONNECTIONS", c.max_connections).max(1);
        // One address may take at most a quarter of the connection ceiling, so
        // no single office, carrier or attacker can fill it alone.
        let per_ip_default = c.max_conns_per_ip.min((c.max_connections / 4).max(1));
        c.max_conns_per_ip =
            env("RUNA_MAX_CONNS_PER_IP", per_ip_default).clamp(1, c.max_connections);
        if let Some(secs) =
            std::env::var("RUNA_SHUTDOWN_GRACE_SECS").ok().and_then(|v| v.parse::<u64>().ok())
        {
            c.shutdown_grace = Duration::from_secs(secs.min(600));
        }
        c.allow_ceiling_optout =
            std::env::var("RUNA_ALLOW_CEILING_OPTOUT").is_ok_and(|v| v == "1");
        c.restart_key = std::env::var("RUNA_RESTART_KEY")
            .ok()
            .and_then(|v| crate::runar::ticket::RestartKey::from_hex(&v));
        // A zero rate would brick the endpoint it guards rather than throttle
        // it, and the frame limiter multiplies by two, so keep both in range.
        c.frames_per_conn_per_sec = c.frames_per_conn_per_sec.clamp(1, u32::MAX / 2);
        c.bytes_per_conn_per_sec = c.bytes_per_conn_per_sec.clamp(1, u64::from(u32::MAX) / 2);
        c.max_frame_bytes = c.max_frame_bytes.clamp(1024, 8 * 1024 * 1024);
        c.max_peers_per_room = c.max_peers_per_room.max(1);
        // A queue smaller than one frame could never accept anything.
        c.max_queued_bytes_per_conn = c.max_queued_bytes_per_conn.max(c.max_frame_bytes * 2);
        c
    }
}

/// An onion address as `Onion-Location` needs it: scheme, a v3 address (56
/// base32 characters), and nothing else. Anything looser is refused rather
/// than advertised, since the header tells Tor Browser where to send people.
fn onion_url(v: &str) -> Option<String> {
    let v = v.trim().trim_end_matches('/');
    let host = v.strip_prefix("http://").or_else(|| v.strip_prefix("https://"))?;
    let label = host.strip_suffix(".onion")?;
    let ok = label.len() == 56 && label.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    if !ok {
        tracing::warn!("RUNA_ONION_URL is not a v3 onion address; not advertising it");
        return None;
    }
    Some(v.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_v3_onion_address_is_advertised() {
        let good = format!("http://{}.onion", "a".repeat(52) + "2345");
        assert_eq!(super::onion_url(&good), Some(good.clone()));
        assert_eq!(super::onion_url(&format!("{good}/")), Some(good.clone()));
        assert_eq!(super::onion_url("http://example.com"), None);
        assert_eq!(super::onion_url(&format!("http://{}.onion", "a".repeat(16))), None, "v2 is gone");
        assert_eq!(super::onion_url(&format!("http://{}.onion/x", "a".repeat(56))), None);
        assert_eq!(super::onion_url(&format!("ftp://{}.onion", "a".repeat(56))), None);
    }
}
