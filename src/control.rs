//! Control-frame payloads (ping, pong, close): at most 125 bytes (§5.5), held
//! in buffers recycled through a per-thread pool, so receiving them costs no
//! allocation once the pool is warm.

use std::cell::RefCell;

use crate::frame::MAX_CONTROL_PAYLOAD;

const CAPACITY: usize = MAX_CONTROL_PAYLOAD;

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
        }
    }

    #[cfg(test)]
    fn storage(&self) -> &[u8; CAPACITY] {
        self.storage.as_ref().expect("taken only in Drop")
    }

    fn storage_mut(&mut self) -> &mut [u8; CAPACITY] {
        self.storage.as_mut().expect("taken only in Drop")
    }

    /// Append `src`, returning the bytes just written. The caller has
    /// checked the frame length, so this cannot overflow.
    pub(crate) fn extend(&mut self, src: &[u8]) -> &mut [u8] {
        let at = self.len as usize;
        assert!(at + src.len() <= CAPACITY, "control payload overflow");
        self.len += src.len() as u8;
        let written = &mut self.storage_mut()[at..at + src.len()];
        written.copy_from_slice(src);
        written
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

    fn deref(&self) -> &[u8] {
        let storage = self.storage.as_ref().expect("taken only in Drop");
        &storage[..self.len as usize]
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
}
