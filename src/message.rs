use crate::control::{ControlBuf, ControlTooLong};

/// A complete WebSocket message. Fragmented data messages arrive already
/// reassembled; control messages are surfaced as they come.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    /// The pong is queued automatically; it goes out on the next
    /// [`send`](crate::WebSocket::send) or [`flush`](crate::WebSocket::flush).
    Ping(ControlBuf),
    Pong(ControlBuf),
    /// The peer started or answered the closing handshake. The reply, if one
    /// is due, is queued like a pong.
    Close(Option<CloseFrame>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: u16,
    pub reason: String,
}

impl Message {
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    pub fn binary(b: impl Into<Vec<u8>>) -> Self {
        Self::Binary(b.into())
    }

    /// Payload bytes: what a message costs in a queue.
    pub fn payload_len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Binary(data) => data.len(),
            Self::Ping(payload) | Self::Pong(payload) => payload.len(),
            Self::Close(frame) => frame.as_ref().map_or(0, |f| 2 + f.reason.len()),
        }
    }

    /// A ping carrying `payload`, which must fit 125 bytes.
    pub fn ping(payload: &[u8]) -> Result<Self, ControlTooLong> {
        ControlBuf::try_from(payload).map(Self::Ping)
    }

    /// An unsolicited pong carrying `payload`, which must fit 125 bytes.
    pub fn pong(payload: &[u8]) -> Result<Self, ControlTooLong> {
        ControlBuf::try_from(payload).map(Self::Pong)
    }
}
