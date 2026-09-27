//! Control-frame payloads (ping, pong, close): at most 125 bytes (§5.5), held
//! in buffers recycled through a per-thread pool, so they cost no allocation
//! once the pool is warm.

use std::cell::RefCell;

use runtime::net::IoBuf;

use crate::frame::{MAX_CONTROL_PAYLOAD, OpCode, apply_mask};

/// Room in front of the payload for the longest control-frame header: two
/// bytes, plus the four-byte mask a client adds. The length never needs an
/// extended field, 125 fitting in the second byte.
const HEADROOM: usize = 6;
const CAPACITY: usize = HEADROOM + MAX_CONTROL_PAYLOAD;

/// Buffers kept per thread beyond that are freed instead; bounds what a burst
/// of pings leaves behind.
const POOL_LIMIT: usize = 1024;

type Storage = Box<[u8; CAPACITY]>;

thread_local! {
    static POOL: RefCell<Vec<Storage>> = const { RefCell::new(Vec::new()) };
}

/// Payload of a ping, pong or close frame: up to 125 bytes, from the pool
/// and back to it on drop.
pub struct ControlBuf {
    /// `None` only inside `Drop`.
    storage: Option<Storage>,
    len: u8,
    /// Where the bytes to send begin: `HEADROOM` for a bare payload, earlier
    /// once a frame header was written in front of it.
    start: u8,
}

/// The payload does not fit a control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlTooLong;

impl std::fmt::Display for ControlTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control payload over {MAX_CONTROL_PAYLOAD} bytes")
    }
}

impl std::error::Error for ControlTooLong {}

impl ControlBuf {
    /// An empty payload, from the pool when it has one.
    pub fn new() -> Self {
        let storage = POOL
            .with_borrow_mut(Vec::pop)
            .unwrap_or_else(|| Box::new([0; CAPACITY]));
        Self {
            storage: Some(storage),
            len: 0,
            start: HEADROOM as u8,
        }
    }

    fn storage(&self) -> &[u8; CAPACITY] {
        self.storage.as_ref().expect("taken only in Drop")
    }

    fn storage_mut(&mut self) -> &mut [u8; CAPACITY] {
        self.storage.as_mut().expect("taken only in Drop")
    }

    /// Append `src`, returning the bytes just written. The caller has
    /// checked the frame length, so this cannot overflow.
    pub(crate) fn extend(&mut self, src: &[u8]) -> &mut [u8] {
        let at = HEADROOM + self.len as usize;
        assert!(at + src.len() <= CAPACITY, "control payload overflow");
        self.len += src.len() as u8;
        let written = &mut self.storage_mut()[at..at + src.len()];
        written.copy_from_slice(src);
        written
    }

    /// Turn the payload into a complete frame in place: the header goes into
    /// the headroom and the payload is masked if `mask` is given. What
    /// [`IoBuf`] then exposes is the whole frame, ready to send.
    pub(crate) fn into_frame(mut self, opcode: OpCode, mask: Option<[u8; 4]>) -> Self {
        let len = self.len as usize;
        let header_len = 2 + if mask.is_some() { 4 } else { 0 };
        let start = HEADROOM - header_len;
        let storage = self.storage_mut();
        storage[start] = 0x80 | opcode as u8;
        storage[start + 1] = (mask.is_some() as u8) << 7 | len as u8;
        if let Some(key) = mask {
            storage[start + 2..HEADROOM].copy_from_slice(&key);
            apply_mask(&mut storage[HEADROOM..HEADROOM + len], key, 0);
        }
        self.start = start as u8;
        self
    }
}

impl Default for ControlBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ControlBuf {
    fn drop(&mut self) {
        let Some(storage) = self.storage.take() else {
            return;
        };
        // `try_with`: during thread teardown the pool may already be gone.
        let _ = POOL.try_with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < POOL_LIMIT {
                pool.push(storage);
            }
        });
    }
}

impl std::ops::Deref for ControlBuf {
    type Target = [u8];

    /// The payload, never the header written in front of it.
    fn deref(&self) -> &[u8] {
        &self.storage()[HEADROOM..HEADROOM + self.len as usize]
    }
}

impl TryFrom<&[u8]> for ControlBuf {
    type Error = ControlTooLong;

    fn try_from(payload: &[u8]) -> Result<Self, ControlTooLong> {
        if payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(ControlTooLong);
        }
        let mut buf = Self::new();
        buf.extend(payload);
        Ok(buf)
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for ControlBuf {
    type Error = ControlTooLong;

    fn try_from(payload: &[u8; N]) -> Result<Self, ControlTooLong> {
        Self::try_from(&payload[..])
    }
}

impl Clone for ControlBuf {
    /// Another pooled buffer with the same payload.
    fn clone(&self) -> Self {
        let mut buf = Self::new();
        buf.extend(self);
        buf
    }
}

impl PartialEq for ControlBuf {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for ControlBuf {}

impl std::fmt::Debug for ControlBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ControlBuf").field(&&**self).finish()
    }
}

// SAFETY: the bytes live in the boxed storage, which neither moves nor
// changes while `self` is held; `start..HEADROOM + len` lies within it.
unsafe impl IoBuf for ControlBuf {
    fn stable_ptr(&self) -> *const u8 {
        self.storage()[self.start as usize..].as_ptr()
    }

    fn bytes_init(&self) -> usize {
        HEADROOM + self.len as usize - self.start as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_buffers_are_reused() {
        let first = ControlBuf::try_from(b"ping").unwrap();
        let ptr = first.storage().as_ptr();
        drop(first);
        let second = ControlBuf::new();
        assert_eq!(second.storage().as_ptr(), ptr);
        assert!(second.is_empty());
    }

    #[test]
    fn rejects_over_125_bytes() {
        assert!(ControlBuf::try_from(&[0; 125][..]).is_ok());
        assert_eq!(ControlBuf::try_from(&[0; 126][..]), Err(ControlTooLong));
    }

    #[test]
    fn framed_in_place() {
        let frame = ControlBuf::try_from(b"hi")
            .unwrap()
            .into_frame(OpCode::Pong, None);
        let bytes = unsafe { std::slice::from_raw_parts(frame.stable_ptr(), frame.bytes_init()) };
        assert_eq!(bytes, [0x8A, 2, b'h', b'i']);

        let key = [1, 2, 3, 4];
        let frame = ControlBuf::try_from(b"hi")
            .unwrap()
            .into_frame(OpCode::Ping, Some(key));
        let bytes = unsafe { std::slice::from_raw_parts(frame.stable_ptr(), frame.bytes_init()) };
        assert_eq!(bytes, [0x89, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]);
    }
}
