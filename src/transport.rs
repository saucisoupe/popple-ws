//! The byte pipes a WebSocket runs over: plain TCP, or TLS offloaded to the
//! kernel. Both receive through a multishot recv on a provided buffer ring.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use popple_tls::{Frame as TlsFrame, KtlsMessages};
use runtime::io_driver::DEFAULT_QUEUE_SIZE;
use runtime::io_driver::operations::sockets::multi_recv::{CompletionError, Continuation};
use runtime::net::{
    BorrowedBuffer, BufRingSpec, IoBuf, MultiRecv, OwnedReadHalf, OwnedWriteHalf, SocketWrapper,
    send_all, send_vectored_all,
};
use runtime_streams::Stream;

/// A connected, reliable byte stream.
///
/// `poll_recv` must be cancel-safe: whatever arrived and was not yet handed
/// out stays queued for the next call. An `Err` of kind
/// [`WouldBlock`](io::ErrorKind::WouldBlock) means the buffer ring was empty,
/// not that the connection failed: call again once buffers were released.
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Chunk: AsRef<[u8]>;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Self::Chunk>>>;

    async fn send<B: IoBuf>(&mut self, buf: B) -> (io::Result<()>, B);

    async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>);

    /// End our direction of the stream; receiving keeps working.
    async fn shutdown(&mut self) -> io::Result<()>;
}

/// Plain TCP. The socket is split so the multishot recv owns the read half
/// outright while sends and the half-close go through the write half.
///
/// `QUEUE` is how many received buffers may wait for this connection before
/// the recv pauses: buffers the rest of the thread cannot use meanwhile. Size
/// the ring above the sum of the queues of the connections sharing it, or a
/// few slow readers starve all the others (`WouldBlock`).
pub struct Plain<R: BufRingSpec, const QUEUE: usize = DEFAULT_QUEUE_SIZE> {
    recv: MultiRecv<R, OwnedReadHalf, QUEUE>,
    /// `None` once shut down.
    write: Option<OwnedWriteHalf>,
}

impl<R: BufRingSpec, const QUEUE: usize> Plain<R, QUEUE> {
    pub fn new(socket: SocketWrapper) -> Self {
        let (read, write) = socket.into_split();
        Self {
            recv: MultiRecv::with_queue_size(read),
            write: Some(write),
        }
    }

    pub fn socket(&self) -> &SocketWrapper {
        self.recv.socket()
    }

    fn writer(&self) -> io::Result<&SocketWrapper> {
        self.write
            .as_ref()
            .map(OwnedWriteHalf::socket)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "write side shut down"))
    }
}

impl<R: BufRingSpec, const QUEUE: usize> Transport for Plain<R, QUEUE> {
    type Chunk = BorrowedBuffer<R>;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Self::Chunk>>> {
        Pin::new(&mut self.recv)
            .poll_next(cx)
            .map(|item| item.map(|r| r.map_err(completion_to_io)))
    }

    async fn send<B: IoBuf>(&mut self, buf: B) -> (io::Result<()>, B) {
        match self.writer() {
            Ok(socket) => send_all(socket, buf).await,
            Err(e) => (Err(e), buf),
        }
    }

    async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>) {
        match self.writer() {
            Ok(socket) => send_vectored_all(socket, bufs).await,
            Err(e) => (Err(e), bufs),
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if let Some(write) = self.write.take() {
            write.sync_shutdown();
        }
        Ok(())
    }
}

fn completion_to_io(e: CompletionError) -> io::Error {
    if matches!(e.continuation(), Continuation::ContinueLater) {
        return io::Error::new(
            io::ErrorKind::WouldBlock,
            "buffer ring empty; the recv is armable still",
        );
    }
    match e {
        CompletionError::ConnectionReset => io::ErrorKind::ConnectionReset.into(),
        CompletionError::BrokenPipe => io::ErrorKind::BrokenPipe.into(),
        CompletionError::Cancelled => io::ErrorKind::Interrupted.into(),
        CompletionError::Eof { .. } => io::ErrorKind::UnexpectedEof.into(),
        CompletionError::Other(code) => io::Error::from_raw_os_error(-code),
    }
}

/// TLS 1.3 through kTLS: records are decrypted by the kernel straight into
/// the ring buffers, and key updates and alerts are handled by popple-tls.
/// `D` is `ServerConnectionData` on accepted connections and
/// `ClientConnectionData` on dialed ones.
pub struct Tls<R: BufRingSpec, D> {
    stream: KtlsMessages<R, D>,
}

impl<R: BufRingSpec, D> Tls<R, D> {
    pub fn new(stream: KtlsMessages<R, D>) -> Self {
        Self { stream }
    }

    pub fn get_ref(&self) -> &KtlsMessages<R, D> {
        &self.stream
    }
}

impl<R: BufRingSpec, D> Transport for Tls<R, D> {
    type Chunk = TlsFrame<R>;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Self::Chunk>>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }

    async fn send<B: IoBuf>(&mut self, buf: B) -> (io::Result<()>, B) {
        self.stream.send(buf).await
    }

    async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>) {
        self.stream.send_vectored(bufs).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.close().await
    }
}
