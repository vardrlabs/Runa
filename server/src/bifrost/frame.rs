pub const MAGIC: [u8; 2] = [0x52, 0x55];
pub const VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 32;

pub const FT_JOIN: u8 = 0x01;
pub const FT_JOIN_ACK: u8 = 0x02;
pub const FT_DOC_UPDATE: u8 = 0x03;
pub const FT_DOC_SYNC_REQ: u8 = 0x04;
pub const FT_DOC_SYNC_RESP: u8 = 0x05;
pub const FT_AWARENESS: u8 = 0x06;
pub const FT_PEER_JOIN: u8 = 0x07;
pub const FT_PEER_LEAVE: u8 = 0x08;
pub const FT_DOC_ACK: u8 = 0x09;
pub const FT_SHRED_REQUEST: u8 = 0x10;
pub const FT_SHRED_VOTE: u8 = 0x11;
pub const FT_SHRED_CANCEL: u8 = 0x12;
pub const FT_PURGE: u8 = 0x13;
pub const FT_PURGE_ACK: u8 = 0x14;
pub const FT_RESTART_NOTICE: u8 = 0x15;
pub const FT_RESTART_TICKET: u8 = 0x16;
pub const FT_PING: u8 = 0x17;
pub const FT_PONG: u8 = 0x18;
pub const FT_EPOCH_KEY: u8 = 0x20;
pub const FT_EVICT_COMMIT: u8 = 0x23;
pub const FT_EVICT_REQUEST: u8 = 0x24;
pub const FT_EVICT_VOTE: u8 = 0x25;
pub const FT_EVICT_CANCEL: u8 = 0x26;
pub const FT_TTL_EXTEND: u8 = 0x22;
pub const FT_SNAPSHOT: u8 = 0x21;
pub const FT_ERROR: u8 = 0x30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub frame_type: u8,
    pub room_id: [u8; 16],
    pub epoch: u32,
    pub nonce_sess: [u8; 4],
    pub flags: u32,
}

impl Header {
    pub fn new(frame_type: u8, room_id: [u8; 16], epoch: u32, nonce_sess: [u8; 4], flags: u32) -> Self {
        Header { version: VERSION, frame_type, room_id, epoch, nonce_sess, flags }
    }

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&MAGIC);
        buf.push(self.version);
        buf.push(self.frame_type);
        buf.extend_from_slice(&self.room_id);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.nonce_sess);
        buf.extend_from_slice(&self.flags.to_be_bytes());
        debug_assert_eq!(buf.len() % HEADER_LEN, 0);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        self.encode_into(&mut v);
        v
    }

    pub fn decode(buf: &[u8]) -> Option<Header> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
            return None;
        }
        let mut room_id = [0u8; 16];
        room_id.copy_from_slice(&buf[4..20]);
        let mut nonce_sess = [0u8; 4];
        nonce_sess.copy_from_slice(&buf[24..28]);
        Some(Header {
            version: buf[2],
            frame_type: buf[3],
            room_id,
            epoch: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
            nonce_sess,
            flags: u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    Complete,
    Partial,
    Bad,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header::new(
            FT_DOC_UPDATE,
            [7u8; 16],
            9,
            [1, 2, 3, 4],
            0b101,
        )
    }

    #[test]
    fn roundtrip() {
        let h = sample();
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(Header::decode(&bytes), Some(h));
    }

    #[test]
    fn rejects_short_and_bad_magic() {
        let mut b = sample().encode();
        b.truncate(31);
        assert_eq!(Header::decode(&b), None);
        let mut full = sample().encode();
        full[0] ^= 0xFF;
        assert_eq!(Header::decode(&full), None);
    }

    #[test]
    fn field_offsets_match_spec_5_2() {
        let bytes = sample().encode();
        assert_eq!(&bytes[0..2], &[0x52, 0x55]);
        assert_eq!(bytes[2], 0x01);
        assert_eq!(bytes[3], FT_DOC_UPDATE);
        assert_eq!(&bytes[4..20], &[7u8; 16]);
        assert_eq!(bytes[20..24], 9u32.to_be_bytes());
        assert_eq!(bytes[24..28], [1, 2, 3, 4]);
        assert_eq!(bytes[28..32], 0b101u32.to_be_bytes());
    }

    /// The invariant `server/fuzz/fuzz_targets/frame_header.rs` asserts. It
    /// only ran in a weekly cron, one that had never once succeeded, so it
    /// is checked here on every run as well.
    #[test]
    fn decode_encode_roundtrips_for_any_accepted_input() {
        let mut seed = 0x243F6A8885A308D3u64;
        let mut accepted = 0u32;
        for len in [0usize, 1, 31, 32, 33, 64, 200, 1024] {
            for _ in 0..2000 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let mut data: Vec<u8> = (0..len)
                    .map(|i| ((seed >> ((i % 8) * 8)) as u8) ^ (i as u8))
                    .collect();
                // Force valid magic half the time so decode actually accepts.
                if len >= 2 && seed & 1 == 0 {
                    data[0] = MAGIC[0];
                    data[1] = MAGIC[1];
                }
                if let Some(h) = Header::decode(&data) {
                    accepted += 1;
                    assert_eq!(
                        &h.encode()[..],
                        &data[..HEADER_LEN],
                        "re-encoding a decoded header must reproduce its bytes"
                    );
                }
            }
        }
        assert!(accepted > 1000, "test did not exercise the accepting path");
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut seed = 0x12345678u64;
        for len in [0usize, 1, 15, 31, 32, 33, 64, 255, 256, 1024] {
            for _ in 0..200 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let bytes: Vec<u8> = (0..len)
                    .map(|i| ((seed >> (i % 8 * 8)) as u8) ^ (i as u8))
                    .collect();
                let _ = Header::decode(&bytes);
            }
        }
    }
}
