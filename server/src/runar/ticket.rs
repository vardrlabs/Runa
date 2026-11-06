//! Restart tickets (PROTOCOL.md amendment I).
//!
//! Rooms live only in this process's memory, so replacing the process used to
//! end every one of them. The people in a room still hold everything that
//! matters — the document, and the key to it — but the new process would not
//! let them back in: it had never heard of the room, and a client that could
//! simply declare one into existence could squat any id or name it liked, or
//! bring back a room its members had shredded.
//!
//! A ticket is the old process vouching for a room at the moment it stopped:
//! this room existed, it had not been shredded, and these were its settings.
//! It is handed to every connected member just before their connection is
//! closed, and the new process recreates the room from it — empty, since the
//! server never held anything it could read, for the members to refill from
//! their own copies.
//!
//! Tickets are signed with `RUNA_RESTART_KEY`, which both processes read from
//! their environment. Without one, none are issued and a restart ends every
//! room as it always did. Nothing here is written to disk: the key is
//! configuration, and the tickets live in the members' tabs.

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64U};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};

use crate::runar::room::{Room, RoomClass, TtlKind};

const DOMAIN: &[u8] = b"runa/v1/restart-ticket\0";

/// How long after the old process stops a ticket is still accepted. Members
/// reconnect within seconds of a restart; this is room for a slow one, not a
/// way to bring a room back days later.
pub const TICKET_LIFETIME_SECS: u64 = 600;

/// Longer than any honest ticket: its largest part is a config blob, which
/// room creation caps far below this.
pub const MAX_TICKET_LEN: usize = 64 * 1024;

/// The restart key. Debug is written by hand so the key never reaches a log
/// line through the config it rides in.
#[derive(Clone)]
pub struct RestartKey(pub [u8; 32]);

impl std::fmt::Debug for RestartKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RestartKey(..)")
    }
}

impl RestartKey {
    /// 64 hex characters. Anything else is refused rather than stretched, so
    /// a truncated or mistyped key is noticed at boot instead of producing
    /// tickets the next process cannot read.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s.trim()).ok()?;
        <[u8; 32]>::try_from(bytes).ok().map(RestartKey)
    }
}

/// What the new process needs to recreate a room exactly as it was.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub v: u8,
    /// Room id, hex.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub created: u64,
    pub ttl_kind: String,
    pub ttl_secs: u64,
    pub ttl_ext: u64,
    pub optout: bool,
    /// Base64, like every other binary field on this API.
    pub verifier: String,
    pub salt: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_blob: Option<String>,
    /// The room's epoch and the epoch of its current root (amendment J). A
    /// ticket from a process that predates them has neither and restores the
    /// room at 0. Covered by the HMAC like every other field.
    #[serde(default)]
    pub epoch: u32,
    #[serde(default)]
    pub root_epoch: u32,
    pub issued: u64,
    pub expires: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TicketError {
    Malformed,
    BadSignature,
    Expired,
}

fn mac(key: &RestartKey, body: &[u8]) -> Hmac<sha2::Sha256> {
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    m.update(DOMAIN);
    m.update(body);
    m
}

pub fn ttl_kind_name(kind: TtlKind) -> &'static str {
    match kind {
        TtlKind::Absolute => "absolute",
        TtlKind::IdleEdit => "idle-edit",
        TtlKind::IdlePeers => "idle-peers",
        TtlKind::None => "none",
    }
}

/// A ticket for `room` as it stands. None for a room with no verifier, which
/// nothing the server creates today lacks, and which could not be rejoined.
pub fn issue(key: &RestartKey, room: &Room, now: u64) -> Option<String> {
    let verifier = room.verifier_ref()?;
    let body = Ticket {
        v: 1,
        id: hex::encode(room.id),
        name: match &room.class {
            RoomClass::Named(n) => Some(n.clone()),
            RoomClass::Unlisted => None,
        },
        created: room.created_unix,
        ttl_kind: ttl_kind_name(room.ttl.kind).to_string(),
        ttl_secs: room.ttl.secs,
        ttl_ext: room.ttl_extension_secs.load(std::sync::atomic::Ordering::SeqCst),
        optout: room.ceiling_optout,
        verifier: B64.encode(verifier),
        salt: B64.encode(room.salt),
        m_kib: room.kdf_m_kib,
        t: room.kdf_t,
        p: room.kdf_p,
        config_blob: room.config_blob.as_ref().map(|b| B64.encode(b)),
        epoch: room.epoch(),
        root_epoch: room.root_epoch(),
        issued: now,
        expires: now.saturating_add(TICKET_LIFETIME_SECS),
    };
    let json = serde_json::to_vec(&body).ok()?;
    let tag = mac(key, &json).finalize().into_bytes();
    Some(format!("{}.{}", B64U.encode(&json), B64U.encode(tag)))
}

/// Check a ticket's signature and lifetime, and return what it vouches for.
/// The contents still have to pass the same validation as a new room.
pub fn open(key: &RestartKey, ticket: &str, now: u64) -> Result<Ticket, TicketError> {
    if ticket.len() > MAX_TICKET_LEN {
        return Err(TicketError::Malformed);
    }
    let (body_b64, tag_b64) = ticket.split_once('.').ok_or(TicketError::Malformed)?;
    let json = B64U.decode(body_b64).map_err(|_| TicketError::Malformed)?;
    let tag = B64U.decode(tag_b64).map_err(|_| TicketError::Malformed)?;
    // Constant-time, and before anything in the body is believed.
    mac(key, &json).verify_slice(&tag).map_err(|_| TicketError::BadSignature)?;
    let body: Ticket = serde_json::from_slice(&json).map_err(|_| TicketError::Malformed)?;
    if body.v != 1 {
        return Err(TicketError::Malformed);
    }
    // A ticket from the future means the clocks disagree or it was not made
    // by `issue`; either way it is not honoured.
    if now >= body.expires || body.issued > now.saturating_add(60) {
        return Err(TicketError::Expired);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runar::room::Ttl;

    fn room(class: RoomClass) -> Room {
        Room::new(
            [7u8; 16],
            class,
            1_000,
            Ttl { kind: TtlKind::Absolute, secs: 3600 },
            false,
            Some([9u8; 32]),
            65536,
            3,
            1,
            crate::runar::room::test_salt(),
            Some(bytes::Bytes::from_static(b"blob")),
            1 << 20,
            5,
            8,
        )
    }

    const KEY: RestartKey = RestartKey([1u8; 32]);

    #[test]
    fn a_ticket_carries_the_rooms_epochs() {
        let r = room(RoomClass::Unlisted);
        r.restore_epochs(7, 2);
        let now = 1_800_000_000;
        let t = issue(&KEY, &r, now).expect("ticket");
        let opened = open(&KEY, &t, now).expect("opens");
        assert_eq!((opened.epoch, opened.root_epoch), (7, 2));
    }

    #[test]
    fn a_ticket_from_before_epochs_restores_at_zero() {
        let json = r#"{"v":1,"id":"00","created":1,"ttl_kind":"none","ttl_secs":0,"ttl_ext":0,"optout":false,"verifier":"","salt":"","m_kib":1,"t":1,"p":1,"issued":1,"expires":2}"#;
        let t: Ticket = serde_json::from_str(json).unwrap();
        assert_eq!((t.epoch, t.root_epoch), (0, 0));
    }

    #[test]
    fn a_ticket_opens_under_its_own_key_and_carries_the_room() {
        let r = room(RoomClass::Named("meow-1".into()));
        r.extend_ttl(600);
        let t = issue(&KEY, &r, 2_000).expect("issued");
        let body = open(&KEY, &t, 2_010).expect("opens");
        assert_eq!(body.id, hex::encode([7u8; 16]));
        assert_eq!(body.name.as_deref(), Some("meow-1"));
        assert_eq!(body.created, 1_000);
        assert_eq!(body.ttl_ext, 600);
        assert_eq!(B64.decode(&body.verifier).unwrap(), vec![9u8; 32]);
        assert_eq!(B64.decode(body.config_blob.unwrap()).unwrap(), b"blob");
    }

    #[test]
    fn another_key_cannot_open_it() {
        let t = issue(&KEY, &room(RoomClass::Unlisted), 2_000).unwrap();
        assert_eq!(open(&RestartKey([2u8; 32]), &t, 2_010), Err(TicketError::BadSignature));
    }

    #[test]
    fn any_change_to_what_it_vouches_for_breaks_it() {
        let t = issue(&KEY, &room(RoomClass::Unlisted), 2_000).unwrap();
        let (body, tag) = t.split_once('.').unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&B64U.decode(body).unwrap()).unwrap();
        json["ttl_secs"] = serde_json::json!(720 * 3600);
        let forged = format!("{}.{}", B64U.encode(serde_json::to_vec(&json).unwrap()), tag);
        assert_eq!(open(&KEY, &forged, 2_010), Err(TicketError::BadSignature));
    }

    #[test]
    fn it_expires() {
        let t = issue(&KEY, &room(RoomClass::Unlisted), 2_000).unwrap();
        assert!(open(&KEY, &t, 2_000 + TICKET_LIFETIME_SECS - 1).is_ok());
        assert_eq!(open(&KEY, &t, 2_000 + TICKET_LIFETIME_SECS), Err(TicketError::Expired));
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        for t in ["", ".", "x.y", "aGk.aGk", &"a".repeat(MAX_TICKET_LEN + 1)] {
            assert!(open(&KEY, t, 0).is_err(), "{t:.20}");
        }
    }

    #[test]
    fn the_key_is_never_printed() {
        let k = RestartKey::from_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(format!("{k:?}"), "RestartKey(..)");
        assert!(RestartKey::from_hex(&"ab".repeat(31)).is_none());
        assert!(RestartKey::from_hex("not hex").is_none());
    }
}
