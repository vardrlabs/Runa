use bytes::Bytes;

use crate::bifrost::frame::{Header, FT_PURGE};
use crate::runar::room::{RoomRegistry, RoomState};

/// The one code path that ends a room's life, whatever the trigger: manual
/// shred, consensus shred, timer expiry, idle ceiling, or drain completion.
/// There is no second destruction path (spec §5.9.7).
///
/// The verifier (`Secret<[u8;32]>`) zeroizes on drop with the room. Ciphertext
/// buffers are not secret (spec §6.5) and are dropped promptly.
pub async fn purge(registry: &RoomRegistry, room_id: &[u8; 16], reason: &str) -> bool {
    let Some(room) = registry.get(room_id) else {
        return false;
    };
    let state = room.current_state();
    if state == RoomState::Purging || state == RoomState::Dead {
        return false;
    }
    room.mark_state(RoomState::Purging);

    let header =
        Header::new(FT_PURGE, *room_id, room.epoch(), [0; 4], 0);
    let body = serde_json::json!({ "reason": reason }).to_string();
    let mut raw = header.encode();
    raw.extend_from_slice(body.as_bytes());
    let frame = Bytes::from(raw);

    room.broadcast(&frame, None).await;

    {
        let mut log = room.log.write().unwrap();
        log.drain_and_drop();
    }
    drop(room);

    registry.remove_room(room_id).is_some()
}
