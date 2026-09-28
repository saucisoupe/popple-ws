use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use runtime::runtime::time::Sleep;

use runtime_streams::Stream;

use crate::control::ControlBuf;
use crate::frame::{Decoder, MAX_CONTROL_PAYLOAD, MAX_HEADER_LEN, OpCode, ProtocolError};
use crate::frame::{apply_mask, encode_header, valid_close_code};
use crate::message::{CloseFrame, Message};
use crate::shutdown::{Shutdown, Tracked};
use crate::transport::{Transport, TransportRead, TransportWrite};

/// Payloads up to this size are copied into the inline segment, behind their
/// header; larger ones go out as segments of their own, uncopied.
const INLINE_PAYLOAD: usize = 4096;

/// `feed` writes once this much is pending, so a caller that never flushes
/// still holds a bounded amount.
const FLUSH_THRESHOLD: usize = 64 << 10;

/// Emptied segments kept per connection, and the capacity each keeps: enough
/// for a burst of small frames, little across ten thousand connections.
const MAX_SPARES: usize = 2;

/// Pongs owed at most, each up to 125 bytes.
const MAX_PENDING_PONGS: usize = 16;
const SPARE_CAPACITY: usize = 16 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Masks what it sends, rejects masked frames.
    Client,
    /// Rejects unmasked frames, sends unmasked.
    Server,
}

/// Longest timer the runtime serves (`async_timers::MAX_DURATION`, not
/// re-exported); a longer sleep panics on its first poll.
const MAX_TIMER: Duration = Duration::from_secs(60 * 60);

/// Every duration is up to one hour, the longest timer the runtime serves.
/// The defaults suit a server facing untrusted peers; each size limit is also
/// memory a single connection may pin.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Largest single data frame accepted; a bigger one fails the connection
    /// with close code 1009 as soon as its header is read. Default 1 MiB.
    pub max_frame_size: usize,
    /// Largest reassembled message accepted, across all its fragments; a
    /// bigger one fails the connection with close code 1009. Default 4 MiB.
    pub max_message_size: usize,
    /// One deadline for the whole HTTP upgrade, not per read, so a peer
    /// dripping bytes cannot stretch it. Default 5 s, also the runtime's
    /// cheapest timer.
    pub handshake_timeout: Duration,
    /// A connection that receives nothing for this long fails with
    /// `TimedOut`, and the peer is sent close code 1001. `None` keeps silent
    /// peers forever. Default 60 s.
    pub idle_timeout: Option<Duration>,
    /// With [`split`](WebSocket::split), a ping goes out after this long
    /// without receiving anything, so a live but quiet peer answers and
    /// stays under `idle_timeout`. Default 20 s.
    pub ping_interval: Option<Duration>,
    /// How long to wait for the peer's close frame once ours is sent, before
    /// dropping the connection. Default 5 s.
    pub close_timeout: Duration,
    /// A write the peer does not take in this long fails the connection
    /// with `TimedOut`: a peer that stops reading cannot hold it open. The
    /// timer is armed only once a write has to wait. Default 30 s.
    pub write_timeout: Duration,
    /// With [`split`](WebSocket::split), payload bytes queued for a peer that
    /// does not read them; past this, sends are refused. Default 4 MiB.
    pub max_outbound_bytes: usize,
    /// Servers: when not empty, the upgrade is refused with 403 unless the
    /// request's `Origin` is one of these, compared case-insensitively, e.g.
    /// `"https://example.com"`. A request without `Origin` does not come from
    /// a browser and is let through. Default: every origin.
    pub allowed_origins: &'static [&'static str],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_frame_size: 1 << 20,
            max_message_size: 4 << 20,
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(60)),
            ping_interval: Some(Duration::from_secs(20)),
            close_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(30),
            max_outbound_bytes: 4 << 20,
            allowed_origins: &[],
        }
    }
}

impl Config {
    /// Check the settings the runtime would otherwise reject mid-connection.
    /// The handshakes call it too, but calling it at startup fails earlier.
    pub fn validate(&self) -> Result<(), InvalidConfig> {
        let timer = |d: Duration| !d.is_zero() && d <= MAX_TIMER;
        if !timer(self.handshake_timeout)
            || !timer(self.close_timeout)
            || !timer(self.write_timeout)
        {
            return Err(InvalidConfig("a timeout is zero or over one hour"));
        }
        if !self.idle_timeout.is_none_or(timer) || !self.ping_interval.is_none_or(timer) {
            return Err(InvalidConfig("a timeout is zero or over one hour"));
        }
        if let (Some(ping), Some(idle)) = (self.ping_interval, self.idle_timeout)
            && ping >= idle
        {
            return Err(InvalidConfig("ping_interval must be under idle_timeout"));
        }
        if self.max_frame_size == 0 || self.max_message_size == 0 || self.max_outbound_bytes == 0 {
            return Err(InvalidConfig("a size limit is zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidConfig(pub &'static str);

impl std::fmt::Display for InvalidConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid websocket config: {}", self.0)
    }
}

impl std::error::Error for InvalidConfig {}

/// A full-duplex WebSocket over any [`Transport`].
///
/// Reading is the [`Stream`] impl: `next().await` yields reassembled
/// messages and is cancel-safe, so it can sit in a `select` next to
/// whatever produces outgoing messages. Reading never writes; the pongs and
/// the close reply it owes are queued and go out on the next
/// [`send`](Self::send), [`flush`](Self::flush) or [`close`](Self::close).
///
/// Writing is not cancel-safe: a send dropped mid-flight may leave half a
/// frame on the wire, and every later send fails with `BrokenPipe`.
///
/// The two directions are separate halves: [`split`](Self::split) hands the
/// socket to a task that keeps reading while a write is in flight, and lets
/// other tasks read and write through it.
pub struct WebSocket<T: Transport> {
    read: ReadSide<T::Reader>,
    /// Only the `split` driver borrows it through the cell, to keep a write
    /// in flight while it reads; everything else goes through `&mut self`.
    write: RefCell<WriteSide<T::Writer>>,
    shared: Shared,
    config: Config,
    role: Role,
    /// Set by [`watch`](Self::watch): the connection counts until dropped.
    shutdown: Option<(Shutdown, Tracked)>,
}

impl<T: Transport> Unpin for WebSocket<T> {}

/// A socket's read half, write half and shared state, borrowed apart.
pub(crate) type Parts<'a, T> = (
    &'a mut ReadSide<<T as Transport>::Reader>,
    &'a RefCell<WriteSide<<T as Transport>::Writer>>,
    &'a Shared,
);

/// What each half leaves for the other: the frames reading owes the peer,
/// and how far the closing handshake got.
#[derive(Default)]
pub(crate) struct Shared {
    close_sent: Cell<bool>,
    close_received: Cell<bool>,
    /// Pongs owed, one per ping, oldest first; past `MAX_PENDING_PONGS` the
    /// oldest are dropped, as §5.5.3 allows, so a ping flood stays bounded.
    pending_pongs: RefCell<VecDeque<ControlBuf>>,
    /// Close frame owed to the peer: the echo of theirs, or our protocol
    /// error, or going away.
    pending_close: RefCell<Option<Option<CloseFrame>>>,
}

impl Shared {
    /// Frames reading left for the writer to send.
    pub(crate) fn owes(&self) -> bool {
        !self.pending_pongs.borrow().is_empty() || self.pending_close.borrow().is_some()
    }

    pub(crate) fn close_sent(&self) -> bool {
        self.close_sent.get()
    }
}

impl<T: Transport> WebSocket<T> {
    /// Wrap a transport whose HTTP upgrade is already done. `leftover` is
    /// whatever was read past the end of the upgrade headers.
    pub fn from_upgraded(transport: T, role: Role, leftover: Vec<u8>, config: Config) -> Self {
        let (reader, writer) = transport.into_split();
        Self::from_halves(reader, writer, role, leftover, config)
    }

    pub(crate) fn from_halves(
        reader: T::Reader,
        writer: T::Writer,
        role: Role,
        leftover: Vec<u8>,
        config: Config,
    ) -> Self {
        Self {
            read: ReadSide::new(reader, role, leftover, &config),
            write: RefCell::new(WriteSide::new(writer, role, config.write_timeout)),
            shared: Shared::default(),
            config,
            role,
            shutdown: None,
        }
    }

    /// Count this connection in `shutdown` until it is dropped, and with
    /// [`split`](Self::split), close it with 1001 once `shutdown` triggers.
    /// Driving it by hand, `select` on [`Shutdown::triggered`] instead.
    pub fn watch(&mut self, shutdown: &Shutdown) {
        self.shutdown = Some((shutdown.clone(), shutdown.track()));
    }

    pub(crate) fn watched(&self) -> Option<&Shutdown> {
        self.shutdown.as_ref().map(|(shutdown, _)| shutdown)
    }

    /// The halves, borrowed apart: the `split` driver reads through one
    /// while a write holds the other.
    pub(crate) fn parts(&mut self) -> Parts<'_, T> {
        (&mut self.read, &self.write, &self.shared)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// How long the connection has been quiet: zero while data is still
    /// being read, and before the first poll.
    pub fn idle_for(&self) -> Duration {
        self.read.idle_for()
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Our close frame is out: nothing else may be sent.
    pub fn is_closing(&self) -> bool {
        self.shared.close_sent.get()
    }

    /// Both sides have sent their close frame.
    pub fn is_closed(&self) -> bool {
        self.shared.close_sent.get() && self.shared.close_received.get()
    }

    /// Whether `next()` has a message, or the error that ended reading,
    /// already decoded: then it returns without waiting. An echo or a proxy
    /// feeds replies while this holds and flushes once it no longer does, so
    /// what one read brought in goes back out in one write.
    pub fn has_ready(&self) -> bool {
        self.read.has_ready()
    }

    /// Queue a message behind those fed before it. Nothing is written until
    /// [`flush`](Self::flush), or until `FLUSH_THRESHOLD` bytes are pending,
    /// so a burst of messages leaves in one write, and with kTLS in as few
    /// TLS records. A [`Message::Close`] starts the closing handshake.
    pub async fn feed(&mut self, message: Message) -> io::Result<()> {
        self.write.get_mut().feed(&self.shared, message).await
    }

    /// Write everything fed so far, with the pong and close reply reading
    /// left owed, in a single write.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.write.get_mut().flush(&self.shared).await
    }

    /// Feed then flush: the message, and whatever was fed before it, leave
    /// in one write.
    pub async fn send(&mut self, message: Message) -> io::Result<()> {
        let write = self.write.get_mut();
        write.feed(&self.shared, message).await?;
        write.flush(&self.shared).await
    }

    /// Send a binary message and get its buffer back to fill the next one.
    /// It comes back empty, capacity kept, whatever the outcome: a client
    /// masks the payload in place, so the bytes are no longer what was sent.
    pub async fn send_binary(&mut self, data: Vec<u8>) -> (io::Result<()>, Vec<u8>) {
        let write = self.write.get_mut();
        let (result, mut data) = write.send_data(&self.shared, OpCode::Binary, data).await;
        data.clear();
        (result, data)
    }

    /// [`send_binary`](Self::send_binary) for text: the `String` comes back
    /// empty, capacity kept.
    pub async fn send_text(&mut self, text: String) -> (io::Result<()>, String) {
        let write = self.write.get_mut();
        let bytes = text.into_bytes();
        let (result, mut bytes) = write.send_data(&self.shared, OpCode::Text, bytes).await;
        bytes.clear();
        let text = String::from_utf8(bytes).expect("an empty buffer is valid UTF-8");
        (result, text)
    }

    /// Start the closing handshake, or finish it if the peer started it.
    /// Keep reading until `None` to see the peer's reply. Idempotent.
    pub async fn close(&mut self, frame: Option<CloseFrame>) -> io::Result<()> {
        self.write.get_mut().close(&self.shared, frame).await
    }
}

impl<T: Transport> Stream for WebSocket<T> {
    type Item = io::Result<Message>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.read.poll_next(&this.shared, cx)
    }
}

/// Everything reading needs: the transport's read half, the decoder, and
/// the deadlines that end a quiet connection or an unanswered close.
pub(crate) struct ReadSide<R: TransportRead> {
    transport: R,
    decoder: Decoder,
    /// What the HTTP upgrade read past its headers, decoded first.
    leftover: Option<Vec<u8>>,
    /// Messages decoded from chunks already given back to the ring, then the
    /// error that stopped decoding, if one did.
    ready: VecDeque<Message>,
    failed: Option<ProtocolError>,
    read_done: bool,
    idle_timeout: Option<Duration>,
    close_timeout: Duration,
    /// When the connection last went quiet: stamped once reading runs out
    /// of data, not per chunk, so the hot path never reads the clock.
    last_received: Option<SystemTime>,
    /// Data came in since `last_received` was stamped.
    received: bool,
    /// When our close frame went out, as first seen by a poll.
    closing_since: Option<SystemTime>,
    /// Armed for the nearest deadline; when it fires the deadline is worked
    /// out again, so incoming data never re-arms it.
    timer: Option<Sleep>,
}

impl<R: TransportRead> ReadSide<R> {
    fn new(transport: R, role: Role, leftover: Vec<u8>, config: &Config) -> Self {
        Self {
            transport,
            decoder: Decoder::new(
                role == Role::Server,
                config.max_frame_size,
                config.max_message_size,
            ),
            leftover: (!leftover.is_empty()).then_some(leftover),
            ready: VecDeque::new(),
            failed: None,
            read_done: false,
            idle_timeout: config.idle_timeout,
            close_timeout: config.close_timeout,
            last_received: None,
            received: false,
            closing_since: None,
            timer: None,
        }
    }

    pub(crate) fn idle_for(&self) -> Duration {
        match self.received {
            true => Duration::ZERO,
            false => self.last_received.map_or(Duration::ZERO, elapsed_since),
        }
    }

    pub(crate) fn has_ready(&self) -> bool {
        !self.ready.is_empty() || self.failed.is_some() || self.leftover.is_some()
    }

    pub(crate) fn poll_next(
        &mut self,
        shared: &Shared,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Message>>> {
        loop {
            if let Some(message) = self.ready.pop_front() {
                self.on_message(shared, &message);
                return Poll::Ready(Some(Ok(message)));
            }
            if let Some(e) = self.failed.take() {
                self.on_protocol_error(shared, e);
                return Poll::Ready(Some(Err(e.into())));
            }
            if self.read_done {
                return Poll::Ready(None);
            }
            if let Some(bytes) = self.leftover.take() {
                self.decode(&bytes);
                continue;
            }
            let received = match self.transport.poll_recv(cx) {
                Poll::Ready(received) => received,
                Poll::Pending => return self.poll_deadline(shared, cx),
            };
            match received {
                // Decoded whole, then dropped here: the ring buffer is back
                // with the kernel before any message is handed out.
                Some(Ok(chunk)) => {
                    self.received = true;
                    self.decode(chunk.as_ref());
                }
                // Ring pressure, not a failure: the caller polls again later.
                Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Ready(Some(Err(e)));
                }
                Some(Err(e)) => {
                    self.read_done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                None => {
                    self.read_done = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed without a close frame",
                    ))));
                }
            }
        }
    }

    /// Record what a received message obliges us to send back.
    fn on_message(&mut self, shared: &Shared, message: &Message) {
        match message {
            Message::Ping(payload) if !shared.close_sent.get() => {
                let mut pongs = shared.pending_pongs.borrow_mut();
                if pongs.len() == MAX_PENDING_PONGS {
                    pongs.pop_front();
                }
                pongs.push_back(payload.clone());
            }
            Message::Close(frame) => {
                shared.close_received.set(true);
                self.read_done = true;
                if !shared.close_sent.get() {
                    // Echo the status code (§5.5.1); no code means none back.
                    *shared.pending_close.borrow_mut() = Some(frame.as_ref().map(|f| CloseFrame {
                        code: f.code,
                        reason: String::new(),
                    }));
                }
            }
            _ => {}
        }
    }

    /// Decode all of `data`, so the buffer it lives in can go back to the
    /// ring right away, whatever the message boundaries. Stops at a close
    /// frame, since nothing may follow it, and at the first protocol error.
    fn decode(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.decoder.feed(data) {
                Ok((consumed, message)) => {
                    data = &data[consumed..];
                    if let Some(message) = message {
                        let close = matches!(message, Message::Close(_));
                        self.ready.push_back(message);
                        if close {
                            return;
                        }
                    }
                }
                Err(e) => {
                    self.failed = Some(e);
                    return;
                }
            }
        }
    }

    fn on_protocol_error(&mut self, shared: &Shared, e: ProtocolError) {
        self.read_done = true;
        shared.pending_pongs.borrow_mut().clear();
        if !shared.close_sent.get() {
            *shared.pending_close.borrow_mut() = Some(Some(CloseFrame {
                code: e.code,
                reason: e.reason.to_owned(),
            }));
        }
    }

    /// Nothing to read: wait for the nearest deadline, and end the stream
    /// with `TimedOut` once it passes.
    fn poll_deadline(
        &mut self,
        shared: &Shared,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Message>>> {
        let now = now();
        // Reading just ran out of data: that is when the quiet began.
        if std::mem::take(&mut self.received) {
            self.last_received = Some(now);
        }
        let last_received = *self.last_received.get_or_insert(now);
        let closing = shared.close_sent.get() && !shared.close_received.get();
        if closing && self.closing_since.is_none() {
            self.closing_since = Some(now);
            // Sooner than whatever the timer waits for: arm it again.
            self.timer = None;
        }
        let idle = self.idle_timeout.map(|d| (last_received + d, false));
        let close = self
            .closing_since
            .filter(|_| closing)
            .map(|at| (at + self.close_timeout, true));
        let Some((deadline, waiting_for_close)) = [idle, close].into_iter().flatten().min() else {
            self.timer = None;
            return Poll::Pending;
        };
        let left = deadline.duration_since(now).unwrap_or(Duration::ZERO);
        if left.is_zero() {
            return Poll::Ready(Some(Err(self.time_out(shared, waiting_for_close))));
        }
        // The wheel ticks every 10 ms; a shorter sleep would only spin.
        let timer = self
            .timer
            .get_or_insert_with(|| Sleep::during(left.max(Duration::from_millis(10))));
        match Pin::new(timer).poll(cx) {
            Poll::Pending => Poll::Pending,
            // Fired: work the deadline out again, as data may have moved it
            // since the timer was armed; the wheel may also fire a tick early.
            Poll::Ready(()) => {
                self.timer = None;
                self.poll_deadline(shared, cx)
            }
        }
    }

    fn time_out(&mut self, shared: &Shared, waiting_for_close: bool) -> io::Error {
        self.read_done = true;
        self.timer = None;
        if waiting_for_close {
            return io::Error::new(io::ErrorKind::TimedOut, "no close frame from the peer");
        }
        if !shared.close_sent.get() {
            // Going away: queued like any close, sent on the next flush.
            *shared.pending_close.borrow_mut() = Some(Some(CloseFrame {
                code: 1001,
                reason: "idle timeout".to_owned(),
            }));
        }
        io::Error::new(io::ErrorKind::TimedOut, "idle timeout")
    }
}

/// Where [`WriteSide::queue_data`] put a payload.
enum Queued {
    /// Copied into the inline segment: the buffer is free, handed back.
    Copied(Vec<u8>),
    /// A segment of its own, at this index of `out`, until written.
    Segment(usize),
}

/// Everything writing needs: the transport's write half and the frames fed
/// and not yet written.
pub(crate) struct WriteSide<W: TransportWrite> {
    transport: W,
    role: Role,
    write_timeout: Duration,
    /// Set while a frame is being written; still set means one was cancelled.
    writing: bool,
    /// Frames fed and not yet written, in order. Small frames and the
    /// headers of large ones are packed into inline segments; a large payload
    /// is a segment of its own, never copied.
    out: Vec<Vec<u8>>,
    /// Whether the last segment of `out` is inline: small frames join it.
    inline_open: bool,
    /// Bytes in `out`.
    out_bytes: usize,
    /// Emptied segments, reused for the next frames.
    spare: Vec<Vec<u8>>,
    /// Our side was shut down once the closing handshake completed.
    shut_down: bool,
}

impl<W: TransportWrite> WriteSide<W> {
    fn new(transport: W, role: Role, write_timeout: Duration) -> Self {
        Self {
            transport,
            role,
            write_timeout,
            writing: false,
            out: Vec::new(),
            inline_open: false,
            out_bytes: 0,
            spare: Vec::new(),
            shut_down: false,
        }
    }

    pub(crate) async fn feed(&mut self, shared: &Shared, message: Message) -> io::Result<()> {
        if let Message::Close(frame) = &message {
            check_close(frame)?;
        }
        self.ready_to_feed(shared)?;
        match message {
            // The payload is the message's: whether copied or queued, it is
            // not handed back.
            Message::Text(text) => drop(self.queue_data(OpCode::Text, text.into_bytes())),
            Message::Binary(data) => drop(self.queue_data(OpCode::Binary, data)),
            Message::Ping(payload) => self.queue_inline(OpCode::Ping, &payload),
            Message::Pong(payload) => self.queue_inline(OpCode::Pong, &payload),
            Message::Close(frame) => self.queue_close(shared, frame),
        }
        if self.out_bytes >= FLUSH_THRESHOLD {
            self.write_out(None).await.0?;
        }
        Ok(())
    }

    pub(crate) async fn flush(&mut self, shared: &Shared) -> io::Result<()> {
        self.queue_owed(shared);
        self.write_out(None).await.0?;
        // Both close frames are out: the handshake is over, so is our side.
        if shared.close_sent.get() && shared.close_received.get() && !self.shut_down {
            self.shut_down = true;
            self.transport.shutdown().await?;
        }
        Ok(())
    }

    async fn send_data(
        &mut self,
        shared: &Shared,
        opcode: OpCode,
        payload: Vec<u8>,
    ) -> (io::Result<()>, Vec<u8>) {
        if let Err(e) = self.ready_to_feed(shared) {
            return (Err(e), payload);
        }
        match self.queue_data(opcode, payload) {
            // The caller's buffer is free already.
            Queued::Copied(payload) => {
                let result = self.flush(shared).await;
                (result, payload)
            }
            // It comes back with the write.
            Queued::Segment(segment) => {
                self.queue_owed(shared);
                let (result, payload) = self.write_out(Some(segment)).await;
                let payload = payload.expect("the kept segment comes back");
                match result {
                    Ok(()) => (self.flush(shared).await, payload),
                    Err(e) => (Err(e), payload),
                }
            }
        }
    }

    pub(crate) async fn close(
        &mut self,
        shared: &Shared,
        frame: Option<CloseFrame>,
    ) -> io::Result<()> {
        check_close(&frame)?;
        self.queue_owed(shared);
        if !shared.close_sent.get() {
            self.queue_close(shared, frame);
        }
        self.flush(shared).await
    }

    /// Queue what reading left owed, then check we may still send.
    fn ready_to_feed(&mut self, shared: &Shared) -> io::Result<()> {
        self.ensure_intact()?;
        self.queue_owed(shared);
        if shared.close_sent.get() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "close frame already sent",
            ));
        }
        Ok(())
    }

    /// The pongs owed, then the close reply or protocol-error close, which
    /// must come last.
    fn queue_owed(&mut self, shared: &Shared) {
        while let Some(payload) = shared.pending_pongs.borrow_mut().pop_front() {
            self.queue_inline(OpCode::Pong, &payload);
        }
        if let Some(frame) = shared.pending_close.borrow_mut().take() {
            self.queue_close(shared, frame);
        }
    }

    fn ensure_intact(&self) -> io::Result<()> {
        if self.writing {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "an earlier send was cancelled mid-frame",
            ));
        }
        Ok(())
    }

    fn queue_close(&mut self, shared: &Shared, frame: Option<CloseFrame>) {
        let mut payload = ControlBuf::new();
        if let Some(CloseFrame { code, reason }) = frame {
            // The reason is cut on a char boundary to fit the 125 bytes.
            let mut end = reason.len().min(MAX_CONTROL_PAYLOAD - 2);
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            payload.extend(&code.to_be_bytes());
            payload.extend(&reason.as_bytes()[..end]);
        }
        self.queue_inline(OpCode::Close, &payload);
        // Past our close frame nothing else may be sent, a pong included.
        shared.close_sent.set(true);
        shared.pending_pongs.borrow_mut().clear();
    }

    /// Queue a data frame. A small payload is copied into the inline segment
    /// and handed back; a large one becomes a segment of its own, uncopied,
    /// whose index comes back instead.
    fn queue_data(&mut self, opcode: OpCode, mut payload: Vec<u8>) -> Queued {
        if payload.len() <= INLINE_PAYLOAD {
            self.queue_inline(opcode, &payload);
            return Queued::Copied(payload);
        }
        let mask = (self.role == Role::Client).then(random_mask);
        let mut header = [0; MAX_HEADER_LEN];
        let n = encode_header(&mut header, true, opcode, payload.len(), mask);
        self.inline_segment().extend_from_slice(&header[..n]);
        if let Some(key) = mask {
            apply_mask(&mut payload, key, 0);
        }
        self.out_bytes += n + payload.len();
        self.out.push(payload);
        // What follows cannot join a segment the caller owns.
        self.inline_open = false;
        Queued::Segment(self.out.len() - 1)
    }

    /// Copy a whole frame into the inline segment, masked there when we are
    /// a client: the caller's bytes are left as they were.
    fn queue_inline(&mut self, opcode: OpCode, payload: &[u8]) {
        let mask = (self.role == Role::Client).then(random_mask);
        let mut header = [0; MAX_HEADER_LEN];
        let n = encode_header(&mut header, true, opcode, payload.len(), mask);
        let segment = self.inline_segment();
        segment.extend_from_slice(&header[..n]);
        let start = segment.len();
        segment.extend_from_slice(payload);
        if let Some(key) = mask {
            apply_mask(&mut segment[start..], key, 0);
        }
        self.out_bytes += n + payload.len();
    }

    /// The segment small frames are packed into, opened from the spares if
    /// the last one is not inline.
    fn inline_segment(&mut self) -> &mut Vec<u8> {
        if !self.inline_open {
            self.out.push(self.spare.pop().unwrap_or_default());
            self.inline_open = true;
        }
        self.out.last_mut().expect("just opened")
    }

    /// Write every pending segment in one operation, within `write_timeout`.
    /// Emptied segments are kept for the next frames, except `keep`, the
    /// caller's own buffer, handed back.
    async fn write_out(&mut self, keep: Option<usize>) -> (io::Result<()>, Option<Vec<u8>>) {
        if self.out.is_empty() {
            return (Ok(()), None);
        }
        if let Err(e) = self.ensure_intact() {
            let kept = keep.map(|i| std::mem::take(&mut self.out[i]));
            return (Err(e), kept);
        }
        let mut out = std::mem::take(&mut self.out);
        self.inline_open = false;
        self.out_bytes = 0;
        // Lent to the write and handed back with its result; a write dropped
        // mid-flight keeps them, and poisons the socket anyway.
        self.writing = true;
        let limit = self.write_timeout;
        let transport = &mut self.transport;
        let written = within(limit, async {
            if out.len() == 1 {
                let segment = out.pop().expect("one segment");
                let (result, segment) = transport.send(segment).await;
                out.push(segment);
                (result, out)
            } else {
                transport.send_vectored(out).await
            }
        })
        .await;
        let Some((result, mut out)) = written else {
            // Cancelled mid-frame: `writing` stays set, the socket is spent.
            let error = io::Error::new(io::ErrorKind::TimedOut, "the peer does not read");
            return (Err(error), None);
        };
        self.writing = false;
        let kept = keep.map(|i| std::mem::take(&mut out[i]));
        for mut segment in out.drain(..) {
            if self.spare.len() < MAX_SPARES {
                segment.clear();
                // A caller's large payload or a big batch is not worth
                // holding on to for every connection.
                segment.shrink_to(SPARE_CAPACITY);
                self.spare.push(segment);
            }
        }
        // The list itself is kept too, for its capacity.
        self.out = out;
        (result, kept)
    }
}

/// Refuse a close code the peer would have to reject (§7.4): 0 to 999, and
/// those reserved for reporting only, such as 1005 and 1006.
fn check_close(frame: &Option<CloseFrame>) -> io::Result<()> {
    match frame {
        Some(f) if !valid_close_code(f.code) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "close code may not be sent",
        )),
        _ => Ok(()),
    }
}

/// Run `fut`, giving up after `limit`. The timer is armed only once `fut`
/// has to wait, so a write the kernel takes at once costs no timer.
async fn within<F: Future>(limit: Duration, fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut timer: Option<Sleep> = None;
    std::future::poll_fn(|cx| {
        if let Poll::Ready(output) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(output));
        }
        let timer = timer.get_or_insert_with(|| Sleep::during(limit));
        Pin::new(timer).poll(cx).map(|()| None)
    })
    .await
}

fn random_mask() -> [u8; 4] {
    let mut key = [0; 4];
    aws_lc_rs::rand::fill(&mut key).expect("system RNG");
    key
}

/// The runtime's clock: a thread-local read, cached once per loop turn.
fn now() -> SystemTime {
    runtime::runtime::now()
}

fn elapsed_since(at: SystemTime) -> Duration {
    now().duration_since(at).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::task::Waker;

    use runtime::net::IoBuf;
    use runtime_streams::StreamExt;

    use super::*;

    /// A transport that never receives, and records what is sent.
    struct Pipe;

    impl Transport for Pipe {
        type Reader = Silent;
        type Writer = Wire;

        fn into_split(self) -> (Silent, Wire) {
            (Silent, Wire::default())
        }
    }

    struct Silent;

    impl TransportRead for Silent {
        type Chunk = Vec<u8>;

        fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Option<io::Result<Vec<u8>>>> {
            Poll::Pending
        }
    }

    /// Records what is sent, and in how many writes.
    #[derive(Default)]
    struct Wire {
        written: Vec<u8>,
        writes: usize,
    }

    fn bytes<B: IoBuf>(buf: &B) -> &[u8] {
        unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) }
    }

    impl TransportWrite for Wire {
        async fn send<B: IoBuf>(&mut self, buf: B) -> (io::Result<()>, B) {
            self.written.extend_from_slice(bytes(&buf));
            self.writes += 1;
            (Ok(()), buf)
        }

        async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>) {
            bufs.iter()
                .for_each(|b| self.written.extend_from_slice(bytes(b)));
            self.writes += 1;
            (Ok(()), bufs)
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// What `ws` wrote so far.
    fn sent_by(ws: &mut WebSocket<Pipe>) -> &mut Wire {
        &mut ws.write.get_mut().transport
    }

    /// `Wire` never waits, so one poll finishes any send.
    fn now<F: Future>(f: F) -> F::Output {
        match pin!(f).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(out) => out,
            Poll::Pending => unreachable!("Wire never waits"),
        }
    }

    #[test]
    fn caller_gets_its_payload_buffer_back() {
        for role in [Role::Server, Role::Client] {
            let mut ws = WebSocket::from_upgraded(Pipe, role, vec![], Config::default());
            let mut sent = Vec::new();
            // Big enough for both paths: copied behind the header, then gathered.
            let mut data = Vec::with_capacity(20_000);
            let ptr = data.as_ptr();
            for len in [10, 20_000, 300, 20_000] {
                data.resize(len, len as u8);
                sent.push(Message::Binary(data.clone()));
                let (result, back) = now(ws.send_binary(data));
                result.unwrap();
                assert_eq!(back.as_ptr(), ptr, "{role:?}: reallocated");
                assert!(back.is_empty() && back.capacity() >= 20_000);
                data = back;
            }
            let mut text = String::with_capacity(64);
            let text_ptr = text.as_ptr();
            text.push_str("héllo");
            sent.push(Message::text("héllo"));
            let (result, text) = now(ws.send_text(text));
            result.unwrap();
            assert_eq!((text.as_ptr(), text.len()), (text_ptr, 0));

            // What went out is what was sent, masked or not.
            assert_eq!(
                decode_wire(&sent_by(&mut ws).written, role == Role::Client),
                sent,
                "{role:?}"
            );
        }
    }

    fn decode_wire(wire: &[u8], masked: bool) -> Vec<Message> {
        let mut decoder = Decoder::new(masked, 1 << 20, 1 << 20);
        let mut wire = wire;
        let mut received = Vec::new();
        while !wire.is_empty() {
            let (n, message) = decoder.feed(wire).unwrap();
            received.extend(message);
            wire = &wire[n..];
        }
        received
    }

    #[test]
    fn fed_messages_leave_in_one_write() {
        for role in [Role::Server, Role::Client] {
            let mut ws = WebSocket::from_upgraded(Pipe, role, vec![], Config::default());
            // Small ones packed together, a large one uncopied in between,
            // a control frame, and the pong reading left owed.
            ws.shared
                .pending_pongs
                .borrow_mut()
                .push_back(ControlBuf::try_from(b"owed").unwrap());
            let mut sent = vec![Message::pong(b"owed").unwrap()];
            sent.extend((0..16).map(|i| Message::binary(vec![i; 64])));
            sent.push(Message::binary(vec![0xAB; 20_000]));
            sent.push(Message::text("after the large one"));
            sent.push(Message::ping(b"p").unwrap());
            for message in sent[1..].iter().cloned() {
                now(ws.feed(message)).unwrap();
            }
            assert_eq!(sent_by(&mut ws).writes, 0, "{role:?}: feed wrote");
            now(ws.flush()).unwrap();
            assert_eq!(sent_by(&mut ws).writes, 1, "{role:?}: not one write");
            assert_eq!(
                decode_wire(&sent_by(&mut ws).written, role == Role::Client),
                sent
            );
        }
    }

    #[test]
    fn one_pong_per_ping_up_to_the_cap() {
        // Twenty masked pings in one read, as a client sends them.
        let mut wire = Vec::new();
        for i in 0..20u8 {
            let mut header = [0; MAX_HEADER_LEN];
            let key = [9, 8, 7, 6];
            let n = encode_header(&mut header, true, OpCode::Ping, 1, Some(key));
            wire.extend_from_slice(&header[..n]);
            wire.push(i ^ key[0]);
        }
        let mut ws = WebSocket::from_upgraded(Pipe, Role::Server, wire, Config::default());
        for i in 0..20u8 {
            assert_eq!(
                now(ws.next()).unwrap().unwrap(),
                Message::ping(&[i]).unwrap()
            );
        }
        now(ws.flush()).unwrap();
        assert_eq!(sent_by(&mut ws).writes, 1);
        // The last sixteen, in order: older ones may go unanswered (§5.5.3).
        let pongs: Vec<_> = (4..20u8).map(|i| Message::pong(&[i]).unwrap()).collect();
        assert_eq!(decode_wire(&sent_by(&mut ws).written, false), pongs);
    }

    #[test]
    fn refuses_close_codes_the_peer_would_reject() {
        let mut ws = WebSocket::from_upgraded(Pipe, Role::Server, vec![], Config::default());
        for code in [0, 999, 1004, 1005, 1006, 1015, 2999, 5000] {
            let frame = Some(CloseFrame {
                code,
                reason: String::new(),
            });
            let error = now(ws.send(Message::Close(frame.clone()))).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{code}");
            assert_eq!(
                now(ws.close(frame)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        // Nothing went out, and the socket is still usable.
        assert!(sent_by(&mut ws).written.is_empty() && !ws.is_closing());
        now(ws.close(Some(CloseFrame {
            code: 4000,
            reason: "app".into(),
        })))
        .unwrap();
        assert!(ws.is_closing());
    }

    #[test]
    fn feed_writes_past_the_threshold() {
        let mut ws = WebSocket::from_upgraded(Pipe, Role::Server, vec![], Config::default());
        // 64-byte frames: the threshold is crossed after about a thousand.
        for _ in 0..2000 {
            now(ws.feed(Message::binary(vec![1; 62]))).unwrap();
        }
        assert!(sent_by(&mut ws).writes >= 1, "never wrote");
        assert!(ws.write.get_mut().out_bytes < FLUSH_THRESHOLD);
        now(ws.flush()).unwrap();
        assert_eq!(decode_wire(&sent_by(&mut ws).written, false).len(), 2000);
    }

    #[test]
    fn segments_are_reused() {
        let mut ws = WebSocket::from_upgraded(Pipe, Role::Server, vec![], Config::default());
        now(ws.send(Message::binary(vec![1; 100]))).unwrap();
        let segment = ws.write.get_mut().spare[0].as_ptr();
        for message in [Message::text("small"), Message::binary(vec![2; 10])] {
            now(ws.send(message)).unwrap();
            // The inline segment comes back to the spares, not reallocated.
            assert_eq!(ws.write.get_mut().spare.last().unwrap().as_ptr(), segment);
        }
        // Spares stay few and small, whatever went through them.
        now(ws.send(Message::binary(vec![3; 1 << 20]))).unwrap();
        assert!(ws.write.get_mut().spare.len() <= MAX_SPARES);
        assert!(
            ws.write
                .get_mut()
                .spare
                .iter()
                .all(|s| s.capacity() <= SPARE_CAPACITY)
        );
    }
}
