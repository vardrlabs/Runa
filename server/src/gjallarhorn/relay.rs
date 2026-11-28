use bytes::Bytes;

use crate::bifrost::frame;
use crate::runar::room::Room;

/// The horn relays signed shred and eviction traffic verbatim. It counts nothing, decides
/// nothing, and holds no state: consensus is computed at the edges. If you
/// are tempted to inspect the payload here, stop: that is the failure
/// condition for the whole architecture.
pub async fn relay(room: &Room, frame: &Bytes, sender: [u8; 16]) {
    debug_assert!(matches!(
        frame.get(3),
        Some(&frame::FT_SHRED_REQUEST)
            | Some(&frame::FT_SHRED_VOTE)
            | Some(&frame::FT_SHRED_CANCEL)
            | Some(&frame::FT_EPOCH_KEY)
            | Some(&frame::FT_EVICT_REQUEST)
            | Some(&frame::FT_EVICT_VOTE)
            | Some(&frame::FT_EVICT_CANCEL)
    ));
    room.broadcast(frame, Some(sender)).await;
}
