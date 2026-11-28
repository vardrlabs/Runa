use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[repr(u16)]
pub enum WireCode {
    AuthFailed = 4001,
    RateLimited = 4002,
    RoomFull = 4003,
    FrameTooLarge = 4004,
    ProtocolError = 4005,
    EpochStale = 4006,
    /// This address already holds as many connections as one address may.
    /// Sent as a WebSocket close code.
    TooManyConnections = 4007,
    /// The process-wide connection ceiling is full. Sent as a close code.
    ServerFull = 4008,
    Purged = 4010,
    Expired = 4011,
    NameTaken = 4012,
    NameInvalid = 4013,
    /// The room removed this peer (amendment K). Sent as an ERROR, then as
    /// the close code of its connection.
    Evicted = 4014,
    /// The process is stopping to be replaced, and has handed each room a
    /// ticket to come back with (amendment I). The standard WebSocket code for
    /// it, so a client that knows nothing of tickets still reads a restart.
    ServiceRestart = 1012,
}

impl WireCode {
    pub fn close_code(self) -> u16 {
        self as u16
    }
}

impl From<WireCode> for u16 {
    fn from(c: WireCode) -> Self {
        c as u16
    }
}
