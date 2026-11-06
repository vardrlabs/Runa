use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::WireCode;
use crate::heimdall::clientip::rate_limit_key;
use crate::heimdall::verifier;
use crate::runar::names;
use crate::runar::room::{unix_now, CreateError, RestoreError, RestoreOutcome, Ttl, TtlKind};
use crate::AppState;

/// The only KDF parameters a room may be created with.
///
/// They used to be a range — m_kib anywhere in 8192..=262144, t in 1..=10, p
/// in 1..=4 — while `meta_unlisted` answered for a room that does not exist
/// with these exact defaults. So a room created with anything else was
/// distinguishable from a missing one by its own metadata, which is precisely
/// the question that endpoint goes to some length not to answer: same shape,
/// same delay on both paths, and a deterministic ghost salt under a boot-time
/// key so it cannot be computed offline.
///
/// The official client has only ever sent these three values, so pinning them
/// costs nothing today and closes the gap. Widening the range again is a
/// protocol decision, and it needs the ghost branch to widen with it — the
/// test below fails if the two ever drift apart.
pub const KDF_M_KIB: u32 = 65536;
pub const KDF_T: u32 = 3;
pub const KDF_P: u32 = 1;

pub fn parse_room_hex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s).ok().and_then(|v| <[u8; 16]>::try_from(v).ok())
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    (status, Json(value)).into_response()
}

fn code_response(status: StatusCode, code: &str) -> Response {
    json_response(status, serde_json::json!({ "code": code }))
}

fn wire_code_response(status: StatusCode, code: WireCode) -> Response {
    json_response(status, serde_json::json!({ "code": u16::from(code) }))
}

/// Deterministic within a process (so the same missing room always sees the
/// same fake salt) but unpredictable across processes and to outsiders:
/// HMAC-SHA-256 under a boot-time secret key over the room id. A bare hash
/// of the id would let anyone compute it offline and probe existence.
pub fn dummy_salt_for(hmac_key: &[u8; 32], room_id: &[u8; 16]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(hmac_key)
        .expect("HMAC accepts any key length");
    mac.update(room_id);
    let tag = mac.finalize().into_bytes();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&tag[..16]);
    salt
}

#[derive(Serialize)]
struct MetaResponse {
    exists: bool,
    requires_auth: bool,
    kdf: KdfMeta,
}

#[derive(Serialize)]
struct KdfMeta {
    alg: &'static str,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

/// Unlisted-room metadata is existence-hidden: a missing room returns the
/// identical shape filled with deterministic values derived from the id.
pub async fn meta_unlisted(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(room_hex): Path<String>,
) -> Response {
    // Every call parks a task for `auth_floor`; unmetered, that is a cheap way
    // to hold a lot of them open at once.
    let ip = rate_limit_key(state.cfg.trusted_proxy, &headers, addr);
    if !state.name_lookup_ip.check(&ip) {
        // Same shape as a hit, so throttling is not itself an oracle.
        tokio::time::sleep(state.cfg.auth_floor).await;
        return wire_code_response(StatusCode::TOO_MANY_REQUESTS, WireCode::RateLimited);
    }
    tokio::time::sleep(state.cfg.auth_floor).await;
    let meta = match parse_room_hex(&room_hex).and_then(|id| state.rooms.get(&id)) {
        Some(room) => MetaResponse {
            exists: true,
            requires_auth: true,
            kdf: KdfMeta {
                alg: "argon2id",
                m_kib: room.kdf_m_kib,
                t: room.kdf_t,
                p: room.kdf_p,
                salt: B64.encode(room.salt),
            },
        },
        None => {
            let id = parse_room_hex(&room_hex).unwrap_or([0u8; 16]);
            MetaResponse {
                exists: true,
                requires_auth: true,
                kdf: KdfMeta {
                    alg: "argon2id",
                    m_kib: KDF_M_KIB,
                    t: KDF_T,
                    p: KDF_P,
                    salt: B64.encode(dummy_salt_for(&state.ghost_key, &id)),
                },
            }
        }
    };
    (StatusCode::OK, Json(meta)).into_response()
}

#[derive(Deserialize)]
pub struct ResolveBody {
    pub name: String,
}

pub async fn names_resolve(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ResolveBody>,
) -> Response {
    let ip = rate_limit_key(state.cfg.trusted_proxy, &headers, addr);
    if !state.name_lookup_ip.check(&ip) || !state.name_lookup_global.check(&"__global__".to_string()) {
        return wire_code_response(StatusCode::TOO_MANY_REQUESTS, WireCode::RateLimited);
    }
    if names::validate(&body.name).is_err() {
        return wire_code_response(StatusCode::BAD_REQUEST, WireCode::NameInvalid);
    }
    match state.rooms.resolve_name(&body.name) {
        Some((final_name, room)) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "found": true,
                "name": final_name,
                "room_id": hex::encode(room.id),
                "requires_auth": true,
                "kdf": {
                    "alg": "argon2id",
                    "m_kib": room.kdf_m_kib,
                    "t": room.kdf_t,
                    "p": room.kdf_p,
                    "salt": B64.encode(room.salt),
                },
            }),
        ),
        None => json_response(StatusCode::OK, serde_json::json!({ "found": false })),
    }
}

#[derive(Deserialize)]
pub struct CreateRoomBody {
    /// Accepted for wire compatibility and ignored: unlisted ids are assigned
    /// by the server so that creation cannot be used to probe for live rooms.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub suffix: Option<bool>,
    pub verifier: Option<String>,
    pub kdf: KdfBody,
    pub ttl: TtlBody,
    #[serde(default)]
    pub ceiling_optout: bool,
    #[serde(default)]
    pub config_blob: Option<String>,
}

#[derive(Deserialize)]
pub struct KdfBody {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Deserialize)]
pub struct TtlBody {
    pub kind: String,
    #[serde(default)]
    pub secs: u64,
}

/// Public so it can be fuzzed. The request validation is the interesting part
/// of the create path — the JSON parse belongs to serde — and a fuzz target
/// cannot reach it while it is private.
pub struct ValidParams {
    pub verifier_key: [u8; 32],
    pub ceiling_optout: bool,
    pub salt: [u8; 16],
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub ttl: Ttl,
    pub config_blob: Option<Vec<u8>>,
}

pub fn validate_params(
    body: &CreateRoomBody,
    cfg: &crate::config::Config,
) -> Result<ValidParams, Box<Response>> {
    let ttl = Ttl {
        kind: match body.ttl.kind.as_str() {
            "absolute" => TtlKind::Absolute,
            "idle-edit" => TtlKind::IdleEdit,
            "idle-peers" => TtlKind::IdlePeers,
            "none" => TtlKind::None,
            _ => return Err(Box::new(code_response(StatusCode::BAD_REQUEST, "TTL_INVALID"))),
        },
        secs: body.ttl.secs,
    };
    let max_secs: u64 = 720 * 3600;
    if ttl.kind != TtlKind::None && (body.ttl.secs == 0 || body.ttl.secs > max_secs) {
        return Err(Box::new(code_response(StatusCode::BAD_REQUEST, "TTL_INVALID")));
    }
    // Exactly these, not a range. See KDF_M_KIB.
    if body.kdf.m_kib != KDF_M_KIB || body.kdf.t != KDF_T || body.kdf.p != KDF_P {
        return Err(Box::new(code_response(StatusCode::BAD_REQUEST, "KDF_INVALID")));
    }
    let salt: [u8; 16] = B64
        .decode(&body.kdf.salt)
        .ok()
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
        .ok_or_else(|| Box::new(code_response(StatusCode::BAD_REQUEST, "KDF_INVALID")))?;
    let raw = body
        .verifier
        .as_deref()
        .and_then(|v| B64.decode(v).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| Box::new(code_response(StatusCode::UNPROCESSABLE_ENTITY, "PASSPHRASE_REQUIRED")))?;
    if !verifier::plausible_verifier(&raw) {
        return Err(Box::new(code_response(StatusCode::BAD_REQUEST, "KDF_INVALID")));
    }
    let config_blob = body
        .config_blob
        .as_deref()
        .map(|c| B64.decode(c))
        .transpose()
        .map_err(|_| Box::new(code_response(StatusCode::BAD_REQUEST, "CONFIG_INVALID")))?;
    // The blob is opaque to the server and held for the room's whole life, so
    // it needs its own ceiling independent of the request body limit.
    if config_blob.as_ref().is_some_and(|b| b.len() > cfg.max_config_blob_bytes) {
        return Err(Box::new(code_response(StatusCode::PAYLOAD_TOO_LARGE, "CONFIG_TOO_LARGE")));
    }
    // `ttl: none` plus `ceiling_optout` is an immortal room: never swept, even
    // with nobody in it. That is a permanent allocation an anonymous caller
    // should not be able to make on a shared host, so honour the flag only
    // when the operator has enabled it.
    let ceiling_optout = body.ceiling_optout && cfg.allow_ceiling_optout;
    Ok(ValidParams {
        verifier_key: raw,
        ceiling_optout,
        salt,
        m: body.kdf.m_kib,
        t: body.kdf.t,
        p: body.kdf.p,
        ttl,
        config_blob,
    })
}

pub async fn create_unlisted(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CreateRoomBody>,
) -> Response {
    // A room created during a restart countdown would be gone within the
    // minute. Say that, rather than hand out a room with seconds to live.
    if state.is_restarting() {
        return code_response(StatusCode::SERVICE_UNAVAILABLE, "RESTARTING");
    }
    let ip = rate_limit_key(state.cfg.trusted_proxy, &headers, addr);
    if !state.rooms_created.check(&ip) {
        return wire_code_response(StatusCode::TOO_MANY_REQUESTS, WireCode::RateLimited);
    }
    let params = match validate_params(&body, &state.cfg) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match state.rooms.create_unlisted(
        params.ttl,
        params.ceiling_optout,
        params.verifier_key,
        params.m,
        params.t,
        params.p,
        params.salt,
        params.config_blob.map(bytes::Bytes::from),
        state.cfg.max_log_bytes,
        state.cfg.auth_attempts_per_room_per_min,
        state.cfg.max_peers_per_room,
    ) {
        Ok(room) => json_response(
            StatusCode::CREATED,
            serde_json::json!({ "ok": true, "room_id": hex::encode(room.id) }),
        ),
        Err(CreateError::IdUnavailable) | Err(CreateError::NameTaken) => {
            code_response(StatusCode::CONFLICT, "UNAVAILABLE")
        }
        Err(CreateError::PassphraseRequired) | Err(CreateError::NameInvalid(_)) => {
            code_response(StatusCode::BAD_REQUEST, "PARAMS_INVALID")
        }
        Err(CreateError::AtCapacity) => {
            tracing::warn!(max = state.rooms.max_rooms(), "room budget exhausted");
            code_response(StatusCode::SERVICE_UNAVAILABLE, "AT_CAPACITY")
        }
    }
}

pub async fn create_named(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CreateRoomBody>,
) -> Response {
    // A room created during a restart countdown would be gone within the
    // minute. Say that, rather than hand out a room with seconds to live.
    if state.is_restarting() {
        return code_response(StatusCode::SERVICE_UNAVAILABLE, "RESTARTING");
    }
    let ip = rate_limit_key(state.cfg.trusted_proxy, &headers, addr);
    if !state.named_created.check(&ip) {
        return wire_code_response(StatusCode::TOO_MANY_REQUESTS, WireCode::RateLimited);
    }

    // The hard rule: a named room cannot exist without a
    // passphrase-derived verifier — the name is public by construction,
    // so the passphrase is the only key. Enforced at the API with a test.
    let Some(raw_name) = body.name.as_deref().map(names::normalize) else {
        return wire_code_response(StatusCode::BAD_REQUEST, WireCode::NameInvalid);
    };
    if names::validate(&raw_name).is_err() {
        return wire_code_response(StatusCode::BAD_REQUEST, WireCode::NameInvalid);
    }
    if body.verifier.is_none() {
        return code_response(StatusCode::UNPROCESSABLE_ENTITY, "PASSPHRASE_REQUIRED");
    }
    let params = match validate_params(&body, &state.cfg) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match state.rooms.create_named(
        &raw_name,
        body.suffix.unwrap_or(true),
        params.ttl,
        params.ceiling_optout,
        params.verifier_key,
        params.m,
        params.t,
        params.p,
        params.salt,
        params.config_blob.map(bytes::Bytes::from),
        state.cfg.max_log_bytes,
        state.cfg.auth_attempts_per_room_per_min,
        state.cfg.max_peers_per_room,
    ) {
        Ok((room, final_name)) => json_response(
            StatusCode::CREATED,
            serde_json::json!({
                "ok": true,
                "room_id": hex::encode(room.id),
                "name": final_name,
            }),
        ),
        Err(CreateError::NameTaken) | Err(CreateError::IdUnavailable) => {
            wire_code_response(StatusCode::CONFLICT, WireCode::NameTaken)
        }
        Err(CreateError::NameInvalid(_)) | Err(CreateError::PassphraseRequired) => {
            wire_code_response(StatusCode::BAD_REQUEST, WireCode::NameInvalid)
        }
        Err(CreateError::AtCapacity) => {
            tracing::warn!(max = state.rooms.max_rooms(), "room budget exhausted");
            code_response(StatusCode::SERVICE_UNAVAILABLE, "AT_CAPACITY")
        }
    }
}

#[derive(Deserialize)]
pub struct RestoreBody {
    pub ticket: String,
}

/// Bring back a room the previous process vouched for (amendment I).
///
/// The ticket is the whole authority here: it is signed with the restart key,
/// names the room's id, name and settings, and expires minutes after the old
/// process stopped. Its contents are then held to exactly the rules a new room
/// is, under today's configuration, so a ticket cannot carry anything a create
/// request could not.
///
/// 201 restored, 200 already restored by another member — both mean "join
/// now". 400 and 410 mean the room is not coming back; 409 means its name was
/// taken in the meantime; 429 and 503 are worth retrying.
pub async fn restore_room(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RestoreBody>,
) -> Response {
    if state.is_restarting() {
        return code_response(StatusCode::SERVICE_UNAVAILABLE, "RESTARTING");
    }
    let Some(key) = state.cfg.restart_key.as_ref() else {
        return code_response(StatusCode::GONE, "NO_HANDOVER");
    };
    let ip = rate_limit_key(state.cfg.trusted_proxy, &headers, addr);
    if !state.auth_per_ip.check(&ip) {
        return wire_code_response(StatusCode::TOO_MANY_REQUESTS, WireCode::RateLimited);
    }
    let now = unix_now();
    let Ok(ticket) = crate::runar::ticket::open(key, &body.ticket, now) else {
        return code_response(StatusCode::BAD_REQUEST, "TICKET_INVALID");
    };
    let Some(id) = parse_room_hex(&ticket.id) else {
        return code_response(StatusCode::BAD_REQUEST, "TICKET_INVALID");
    };
    if ticket.root_epoch > ticket.epoch {
        return code_response(StatusCode::BAD_REQUEST, "TICKET_INVALID");
    }
    let as_create = CreateRoomBody {
        id: None,
        name: ticket.name.clone(),
        suffix: Some(false),
        verifier: Some(ticket.verifier.clone()),
        kdf: KdfBody { m_kib: ticket.m_kib, t: ticket.t, p: ticket.p, salt: ticket.salt.clone() },
        ttl: TtlBody { kind: ticket.ttl_kind.clone(), secs: ticket.ttl_secs },
        ceiling_optout: ticket.optout,
        config_blob: ticket.config_blob.clone(),
    };
    let params = match validate_params(&as_create, &state.cfg) {
        Ok(p) => p,
        Err(_) => return code_response(StatusCode::BAD_REQUEST, "TICKET_INVALID"),
    };
    // An absolute room whose time ran out while the process was down stays
    // ended; bringing it back would hand it time nobody gave it.
    if params.ttl.kind == TtlKind::Absolute
        && ticket
            .created
            .saturating_add(params.ttl.secs)
            .saturating_add(ticket.ttl_ext.min(crate::runar::room::MAX_TTL_EXTENSION_SECS))
            <= now
    {
        return code_response(StatusCode::GONE, "EXPIRED");
    }
    match state.rooms.restore(
        id,
        ticket.name.as_deref(),
        ticket.created,
        params.ttl,
        ticket.ttl_ext,
        params.ceiling_optout,
        params.verifier_key,
        params.m,
        params.t,
        params.p,
        params.salt,
        params.config_blob.map(bytes::Bytes::from),
        state.cfg.max_log_bytes,
        state.cfg.auth_attempts_per_room_per_min,
        state.cfg.max_peers_per_room,
        ticket.epoch,
        ticket.root_epoch,
    ) {
        Ok(RestoreOutcome::Restored(_)) => {
            // A valid ticket is not a guess; see the refund after a join.
            state.auth_per_ip.refund(&ip, 1);
            tracing::info!("room restored from a restart ticket");
            json_response(StatusCode::CREATED, serde_json::json!({ "ok": true, "restored": true }))
        }
        Ok(RestoreOutcome::AlreadyLive) => {
            state.auth_per_ip.refund(&ip, 1);
            json_response(StatusCode::OK, serde_json::json!({ "ok": true, "restored": false }))
        }
        Err(RestoreError::Retired) => code_response(StatusCode::GONE, "GONE"),
        Err(RestoreError::NameTaken) => wire_code_response(StatusCode::CONFLICT, WireCode::NameTaken),
        Err(RestoreError::NameInvalid) => code_response(StatusCode::BAD_REQUEST, "TICKET_INVALID"),
        Err(RestoreError::AtCapacity) => {
            tracing::warn!(max = state.rooms.max_rooms(), "room budget exhausted during restore");
            code_response(StatusCode::SERVICE_UNAVAILABLE, "AT_CAPACITY")
        }
    }
}

pub async fn version(State(state): State<AppState>) -> Response {
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "commit": option_env!("RUNA_COMMIT").unwrap_or("dev"),
            "bundle_sha256": option_env!("RUNA_BUNDLE_SHA256").unwrap_or("dev"),
            "server_started": state.started_at,
            "now": unix_now(),
        }),
    )
}
