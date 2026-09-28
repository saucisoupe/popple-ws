use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use runtime::runtime::time::Sleep;

use runtime_streams::Stream;

use crate::control::ControlBuf;
use crate::frame::{Decoder, MAX_CONTROL_PAYLOAD, MAX_HEADER_LEN, OpCode, ProtocolError};
use crate::frame::{apply_mask, encode_header};
use crate::message::{CloseFrame, Message};
use crate::transport::Transport;

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
        if !timer(self.handshake_timeout) || !timer(self.close_timeout) {
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
/// To read and write from different tasks, see [`split`](Self::split).
pub struct WebSocket<T: Transport> {
    transport: T,
    role: Role,
    decoder: Decoder,
    /// What the HTTP upgrade read past its headers, decoded first.
    leftover: Option<Vec<u8>>,
    /// Messages decoded from chunks already given back to the ring, then the
    /// error that stopped decoding, if one did.
    ready: VecDeque<Message>,
    failed: Option<ProtocolError>,
    /// Pongs owed, one per ping, oldest first; past `MAX_PENDING_PONGS` the
    /// oldest are dropped, as §5.5.3 allows, so a ping flood stays bounded.
    pending_pongs: VecDeque<ControlBuf>,
    /// Close frame owed to the peer: the echo of theirs, or our protocol error.
    pending_close: Option<Option<CloseFrame>>,
    close_sent: bool,
    close_received: bool,
    read_done: bool,
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
    config: Config,
    /// When data last came in; stamped on the first poll, since the clock is
    /// only readable inside the runtime.
    last_received: Option<SystemTime>,
    /// When our close frame went out, as first seen by a poll.
    closing_since: Option<SystemTime>,
    /// Armed for the nearest deadline; when it fires the deadline is worked
    /// out again, so incoming data never re-arms it.
    timer: Option<Sleep>,
}

impl<T: Transport> Unpin for WebSocket<T> {}

/// Where [`WebSocket::queue_data`] put a payload.
enum Queued {
    /// Copied into the inline segment: the buffer is free, handed back.
    Copied(Vec<u8>),
    /// A segment of its own, at this index of `out`, until written.
    Segment(usize),
}

impl<T: Transport> WebSocket<T> {
    /// Wrap a transport whose HTTP upgrade is already done. `leftover` is
    /// whatever was read past the end of the upgrade headers.
    pub fn from_upgraded(transport: T, role: Role, leftover: Vec<u8>, config: Config) -> Self {
        Self {
            transport,
            role,
            decoder: Decoder::new(
                role == Role::Server,
                config.max_frame_size,
                config.max_message_size,
            ),
            leftover: (!leftover.is_empty()).then_some(leftover),
            ready: VecDeque::new(),
            failed: None,
            pending_pongs: VecDeque::new(),
            pending_close: None,
            close_sent: false,
            close_received: false,
            read_done: false,
            writing: false,
            out: Vec::new(),
            inline_open: false,
            out_bytes: 0,
            spare: Vec::new(),
            shut_down: false,
            config,
            last_received: None,
            closing_since: None,
            timer: None,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// How long since data last came in. Zero before the first poll.
    pub fn idle_for(&self) -> Duration {
        self.last_received.map_or(Duration::ZERO, elapsed_since)
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Our close frame is out: nothing else may be sent.
    pub fn is_closing(&self) -> bool {
        self.close_sent
    }

    /// Both sides have sent their close frame.
    pub fn is_closed(&self) -> bool {
        self.close_sent && self.close_received
    }

    /// Whether `next()` has a message, or the error that ended reading,
    /// already decoded: then it returns without waiting. An echo or a proxy
    /// feeds replies while this holds and flushes once it no longer does, so
    /// what one read brought in goes back out in one write.
    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty() || self.failed.is_some() || self.leftover.is_some()
    }

    /// Queue a message behind those fed before it. Nothing is written until
    /// [`flush`](Self::flush), or until `FLUSH_THRESHOLD` bytes are pending,
    /// so a burst of messages leaves in one write, and with kTLS in as few
    /// TLS records. A [`Message::Close`] starts the closing handshake.
    pub async fn feed(&mut self, message: Message) -> io::Result<()> {
        self.ready_to_feed()?;
        match message {
            // The payload is the message's: whether copied or queued, it is
            // not handed back.
            Message::Text(text) => drop(self.queue_data(OpCode::Text, text.into_bytes())),
            Message::Binary(data) => drop(self.queue_data(OpCode::Binary, data)),
            Message::Ping(payload) => self.queue_inline(OpCode::Ping, &payload),
            Message::Pong(payload) => self.queue_inline(OpCode::Pong, &payload),
            Message::Close(frame) => self.queue_close(frame),
        }
        if self.out_bytes >= FLUSH_THRESHOLD {
            self.write_out(None).await.0?;
        }
        Ok(())
    }

    /// Write everything fed so far, with the pong and close reply reading
    /// left owed, in a single write.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.queue_owed();
        self.write_out(None).await.0?;
        // Both close frames are out: the handshake is over, so is our side.
        if self.close_sent && self.close_received && !self.shut_down {
            self.shut_down = true;
            self.transport.shutdown().await?;
        }
        Ok(())
    }

    /// Feed then flush: the message, and whatever was fed before it, leave
    /// in one write.
    pub async fn send(&mut self, message: Message) -> io::Result<()> {
        self.feed(message).await?;
        self.flush().await
    }

    /// Send a binary message and get its buffer back to fill the next one.
    /// It comes back empty, capacity kept, whatever the outcome: a client
    /// masks the payload in place, so the bytes are no longer what was sent.
    pub async fn send_binary(&mut self, data: Vec<u8>) -> (io::Result<()>, Vec<u8>) {
        let (result, mut data) = self.send_data(OpCode::Binary, data).await;
        data.clear();
        (result, data)
    }

    /// [`send_binary`](Self::send_binary) for text: the `String` comes back
    /// empty, capacity kept.
    pub async fn send_text(&mut self, text: String) -> (io::Result<()>, String) {
        let (result, mut bytes) = self.send_data(OpCode::Text, text.into_bytes()).await;
        bytes.clear();
        let text = String::from_utf8(bytes).expect("an empty buffer is valid UTF-8");
        (result, text)
    }

    async fn send_data(&mut self, opcode: OpCode, payload: Vec<u8>) -> (io::Result<()>, Vec<u8>) {
        if let Err(e) = self.ready_to_feed() {
            return (Err(e), payload);
        }
        match self.queue_data(opcode, payload) {
            // The caller's buffer is free already.
            Queued::Copied(payload) => {
                let result = self.flush().await;
                (result, payload)
            }
            // It comes back with the write.
            Queued::Segment(segment) => {
                self.queue_owed();
                let (result, payload) = self.write_out(Some(segment)).await;
                let payload = payload.expect("the kept segment comes back");
                match result {
                    Ok(()) => (self.flush().await, payload),
                    Err(e) => (Err(e), payload),
                }
            }
        }
    }

    /// Start the closing handshake, or finish it if the peer started it.
    /// Keep reading until `None` to see the peer's reply. Idempotent.
    pub async fn close(&mut self, frame: Option<CloseFrame>) -> io::Result<()> {
        self.queue_owed();
        if !self.close_sent {
            self.queue_close(frame);
        }
        self.flush().await
    }

    /// Queue what reading left owed, then check we may still send.
    fn ready_to_feed(&mut self) -> io::Result<()> {
        self.ensure_intact()?;
        self.queue_owed();
        if self.close_sent {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "close frame already sent",
            ));
        }
        Ok(())
    }

    /// The pong to the latest ping, then the close reply or protocol-error
    /// close, which must come last.
    fn queue_owed(&mut self) {
        while let Some(payload) = self.pending_pongs.pop_front() {
            self.queue_inline(OpCode::Pong, &payload);
        }
        if let Some(frame) = self.pending_close.take() {
            self.queue_close(frame);
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

    fn queue_close(&mut self, frame: Option<CloseFrame>) {
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
        self.close_sent = true;
        self.pending_pongs.clear();
        // The close deadline is sooner than whatever the timer waits for.
        self.timer = None;
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

    /// Write every pending segment in one operation. Emptied segments are
    /// kept for the next frames, except `keep`, the caller's own buffer,
    /// handed back.
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
        let result = if out.len() == 1 {
            let segment = out.pop().expect("one segment");
            let (result, segment) = self.transport.send(segment).await;
            out.push(segment);
            result
        } else {
            let (result, back) = self.transport.send_vectored(out).await;
            out = back;
            result
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

    /// Record what a received message obliges us to send back.
    fn on_message(&mut self, message: &Message) {
        match message {
            Message::Ping(payload) if !self.close_sent => {
                if self.pending_pongs.len() == MAX_PENDING_PONGS {
                    self.pending_pongs.pop_front();
                }
                self.pending_pongs.push_back(payload.clone());
            }
            Message::Close(frame) => {
                self.close_received = true;
                self.read_done = true;
                if !self.close_sent {
                    // Echo the status code (§5.5.1); no code means none back.
                    self.pending_close = Some(frame.as_ref().map(|f| CloseFrame {
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

    fn on_protocol_error(&mut self, e: ProtocolError) {
        self.read_done = true;
        self.pending_pongs.clear();
        if !self.close_sent {
            self.pending_close = Some(Some(CloseFrame {
                code: e.code,
                reason: e.reason.to_owned(),
            }));
        }
    }
}

fn random_mask() -> [u8; 4] {
    let mut key = [0; 4];
    aws_lc_rs::rand::fill(&mut key).expect("system RNG");
    key
}

impl<T: Transport> Stream for WebSocket<T> {
    type Item = io::Result<Message>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(message) = this.ready.pop_front() {
                this.on_message(&message);
                return Poll::Ready(Some(Ok(message)));
            }
            if let Some(e) = this.failed.take() {
                this.on_protocol_error(e);
                return Poll::Ready(Some(Err(e.into())));
            }
            if this.read_done {
                return Poll::Ready(None);
            }
            if let Some(bytes) = this.leftover.take() {
                this.decode(&bytes);
                continue;
            }
            let received = match this.transport.poll_recv(cx) {
                Poll::Ready(received) => received,
                Poll::Pending => return this.poll_deadline(cx),
            };
            match received {
                // Decoded whole, then dropped here: the ring buffer is back
                // with the kernel before any message is handed out.
                Some(Ok(chunk)) => {
                    this.last_received = Some(now());
                    this.decode(chunk.as_ref());
                }
                // Ring pressure, not a failure: the caller polls again later.
                Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Ready(Some(Err(e)));
                }
                Some(Err(e)) => {
                    this.read_done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                None => {
                    this.read_done = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed without a close frame",
                    ))));
                }
            }
        }
    }
}

impl<T: Transport> WebSocket<T> {
    /// Nothing to read: wait for the nearest deadline, and end the stream
    /// with `TimedOut` once it passes.
    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Message>>> {
        let now = now();
        let last_received = *self.last_received.get_or_insert(now);
        let closing = self.close_sent && !self.close_received;
        if closing {
            self.closing_since.get_or_insert(now);
        }
        let idle = self.config.idle_timeout.map(|d| (last_received + d, false));
        let close = self
            .closing_since
            .filter(|_| closing)
            .map(|at| (at + self.config.close_timeout, true));
        let Some((deadline, waiting_for_close)) = [idle, close].into_iter().flatten().min() else {
            self.timer = None;
            return Poll::Pending;
        };
        let left = deadline.duration_since(now).unwrap_or(Duration::ZERO);
        if left.is_zero() {
            return Poll::Ready(Some(Err(self.time_out(waiting_for_close))));
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
                self.poll_deadline(cx)
            }
        }
    }

    fn time_out(&mut self, waiting_for_close: bool) -> io::Error {
        self.read_done = true;
        self.timer = None;
        if waiting_for_close {
            return io::Error::new(io::ErrorKind::TimedOut, "no close frame from the peer");
        }
        if !self.close_sent {
            // Going away: queued like any close, sent on the next flush.
            self.pending_close = Some(Some(CloseFrame {
                code: 1001,
                reason: "idle timeout".to_owned(),
            }));
        }
        io::Error::new(io::ErrorKind::TimedOut, "idle timeout")
    }
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

    /// Records what is sent, and in how many writes; never receives.
    #[derive(Default)]
    struct Wire(Vec<u8>, usize);

    fn bytes<B: IoBuf>(buf: &B) -> &[u8] {
        unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) }
    }

    impl Transport for Wire {
        type Chunk = Vec<u8>;

        fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Option<io::Result<Vec<u8>>>> {
            Poll::Pending
        }

        async fn send<B: IoBuf>(&mut self, buf: B) -> (io::Result<()>, B) {
            self.0.extend_from_slice(bytes(&buf));
            self.1 += 1;
            (Ok(()), buf)
        }

        async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>) {
            bufs.iter().for_each(|b| self.0.extend_from_slice(bytes(b)));
            self.1 += 1;
            (Ok(()), bufs)
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
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
            let mut ws = WebSocket::from_upgraded(Wire::default(), role, vec![], Config::default());
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
                decode_wire(&ws.transport.0, role == Role::Client),
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
            let mut ws = WebSocket::from_upgraded(Wire::default(), role, vec![], Config::default());
            // Small ones packed together, a large one uncopied in between,
            // a control frame, and the pong reading left owed.
            ws.pending_pongs
                .push_back(ControlBuf::try_from(b"owed").unwrap());
            let mut sent = vec![Message::pong(b"owed").unwrap()];
            sent.extend((0..16).map(|i| Message::binary(vec![i; 64])));
            sent.push(Message::binary(vec![0xAB; 20_000]));
            sent.push(Message::text("after the large one"));
            sent.push(Message::ping(b"p").unwrap());
            for message in sent[1..].iter().cloned() {
                now(ws.feed(message)).unwrap();
            }
            assert_eq!(ws.transport.1, 0, "{role:?}: feed wrote");
            now(ws.flush()).unwrap();
            assert_eq!(ws.transport.1, 1, "{role:?}: not one write");
            assert_eq!(decode_wire(&ws.transport.0, role == Role::Client), sent);
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
        let mut ws =
            WebSocket::from_upgraded(Wire::default(), Role::Server, wire, Config::default());
        for i in 0..20u8 {
            assert_eq!(
                now(ws.next()).unwrap().unwrap(),
                Message::ping(&[i]).unwrap()
            );
        }
        now(ws.flush()).unwrap();
        assert_eq!(ws.transport.1, 1);
        // The last sixteen, in order: older ones may go unanswered (§5.5.3).
        let pongs: Vec<_> = (4..20u8).map(|i| Message::pong(&[i]).unwrap()).collect();
        assert_eq!(decode_wire(&ws.transport.0, false), pongs);
    }

    #[test]
    fn feed_writes_past_the_threshold() {
        let mut ws =
            WebSocket::from_upgraded(Wire::default(), Role::Server, vec![], Config::default());
        // 64-byte frames: the threshold is crossed after about a thousand.
        for _ in 0..2000 {
            now(ws.feed(Message::binary(vec![1; 62]))).unwrap();
        }
        assert!(ws.transport.1 >= 1, "never wrote");
        assert!(ws.out_bytes < FLUSH_THRESHOLD);
        now(ws.flush()).unwrap();
        assert_eq!(decode_wire(&ws.transport.0, false).len(), 2000);
    }

    #[test]
    fn segments_are_reused() {
        let mut ws =
            WebSocket::from_upgraded(Wire::default(), Role::Server, vec![], Config::default());
        now(ws.send(Message::binary(vec![1; 100]))).unwrap();
        let segment = ws.spare[0].as_ptr();
        for message in [Message::text("small"), Message::binary(vec![2; 10])] {
            now(ws.send(message)).unwrap();
            // The inline segment comes back to the spares, not reallocated.
            assert_eq!(ws.spare.last().unwrap().as_ptr(), segment);
        }
        // Spares stay few and small, whatever went through them.
        now(ws.send(Message::binary(vec![3; 1 << 20]))).unwrap();
        assert!(ws.spare.len() <= MAX_SPARES);
        assert!(ws.spare.iter().all(|s| s.capacity() <= SPARE_CAPACITY));
    }
}
