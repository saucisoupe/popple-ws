//! What the targets share: an in-memory transport and a way to run its
//! futures, which never wait.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use popple_ws::{Transport, TransportRead, TransportWrite};
use popple_ws::frame::{Decoder, ProtocolError};
use popple_ws::Message;
use runtime::net::IoBuf;

/// Delivers `incoming` chunk by chunk then ends; records every write in
/// `written`, which the caller keeps a handle on.
#[derive(Default)]
pub struct Wire {
    pub incoming: VecDeque<Vec<u8>>,
    pub written: Rc<RefCell<Vec<u8>>>,
}

pub struct WireIn(VecDeque<Vec<u8>>);
pub struct WireOut(Rc<RefCell<Vec<u8>>>);

impl Transport for Wire {
    type Reader = WireIn;
    type Writer = WireOut;

    fn into_split(self) -> (WireIn, WireOut) {
        (WireIn(self.incoming), WireOut(self.written))
    }
}

fn bytes<B: IoBuf>(buf: &B) -> &[u8] {
    // SAFETY: an `IoBuf` promises `bytes_init` readable bytes at `stable_ptr`.
    unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) }
}

impl TransportRead for WireIn {
    type Chunk = Vec<u8>;

    fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Option<io::Result<Vec<u8>>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
}

impl TransportWrite for WireOut {
    async fn send<B: IoBuf>(&mut self, buf: B) -> (io::Result<()>, B) {
        self.0.borrow_mut().extend_from_slice(bytes(&buf));
        (Ok(()), buf)
    }

    async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>) {
        let mut written = self.0.borrow_mut();
        bufs.iter().for_each(|b| written.extend_from_slice(bytes(b)));
        (Ok(()), bufs)
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Run a future over a `Wire` to completion: it never waits.
pub fn now<F: Future>(f: F) -> F::Output {
    match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("a Wire never waits"),
    }
}

/// Cut `data` at the given sizes, the rest in one last piece.
pub fn cut(mut data: &[u8], sizes: &[u16]) -> Vec<Vec<u8>> {
    let mut pieces = Vec::new();
    for &size in sizes {
        if data.is_empty() {
            break;
        }
        let at = (size as usize).clamp(1, data.len());
        pieces.push(data[..at].to_vec());
        data = &data[at..];
    }
    if !data.is_empty() {
        pieces.push(data.to_vec());
    }
    pieces
}

/// Decode `pieces` in order; what a peer would make of our writes.
pub fn decode(decoder: &mut Decoder, pieces: &[Vec<u8>]) -> Result<Vec<Message>, ProtocolError> {
    let mut messages = Vec::new();
    for piece in pieces {
        let mut input = &piece[..];
        while !input.is_empty() {
            let (n, message) = decoder.feed(input)?;
            messages.extend(message);
            input = &input[n..];
        }
    }
    Ok(messages)
}
