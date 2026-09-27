use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use runtime_streams::Stream;

use crate::control::ControlBuf;
use crate::frame::{Decoder, MAX_CONTROL_PAYLOAD, MAX_HEADER_LEN, OpCode, ProtocolError};
use crate::frame::{apply_mask, encode_header};
use crate::message::{CloseFrame, Message};
use crate::transport::Transport;

/// Payloads up to this size are copied behind their header and sent in one
/// buffer; larger ones go out as a two-buffer gather send, uncopied.
const INLINE_PAYLOAD: usize = 4096;

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

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Largest single data frame accepted; a bigger one fails the connection
    /// with close code 1009 as soon as its header is read.
    pub max_frame_size: usize,
    /// Largest reassembled message accepted, across all its fragments; a
    /// bigger one fails the connection with close code 1009.
    pub max_message_size: usize,
    /// One deadline for the whole HTTP upgrade, not per read, so a peer
    /// dripping bytes cannot stretch it. Up to one hour; the 5 s default is
    /// also the runtime's cheapest timer.
    pub handshake_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_frame_size: 16 << 20,
            max_message_size: 64 << 20,
            handshake_timeout: Duration::from_secs(5),
        }
    }
}

impl Config {
    /// Check the settings the runtime would otherwise reject mid-connection.
    /// The handshakes call it too, but calling it at startup fails earlier.
    pub fn validate(&self) -> Result<(), InvalidConfig> {
        if self.handshake_timeout > MAX_TIMER {
            return Err(InvalidConfig("handshake_timeout is over one hour"));
        }
        if self.handshake_timeout.is_zero() {
            return Err(InvalidConfig("handshake_timeout is zero"));
        }
        if self.max_frame_size == 0 || self.max_message_size == 0 {
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
    pending_pong: Option<ControlBuf>,
    /// Close frame owed to the peer: the echo of theirs, or our protocol error.
    pending_close: Option<Option<CloseFrame>>,
    close_sent: bool,
    close_received: bool,
    read_done: bool,
    /// Set while a frame is being written; still set means one was cancelled.
    writing: bool,
    /// Reused by every data frame: the whole frame when it is small, its
    /// header alone otherwise. Never grows past `INLINE_PAYLOAD` plus a header.
    send_buf: Vec<u8>,
    /// Reused chunk list for gather sends: `[header, payload]`, emptied after.
    send_bufs: Vec<Vec<u8>>,
}

impl<T: Transport> Unpin for WebSocket<T> {}

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
            pending_pong: None,
            pending_close: None,
            close_sent: false,
            close_received: false,
            read_done: false,
            writing: false,
            send_buf: Vec::new(),
            send_bufs: Vec::with_capacity(2),
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Both sides have sent their close frame.
    pub fn is_closed(&self) -> bool {
        self.close_sent && self.close_received
    }

    /// Send a message, after any pong or close reply still owed. Sending a
    /// [`Message::Close`] starts the closing handshake like [`close`](Self::close).
    pub async fn send(&mut self, message: Message) -> io::Result<()> {
        self.ready_to_send().await?;
        match message {
            Message::Text(text) => self.write_frame(OpCode::Text, text.into_bytes()).await.0,
            Message::Binary(data) => self.write_frame(OpCode::Binary, data).await.0,
            Message::Ping(data) => self.write_control(OpCode::Ping, data).await,
            Message::Pong(data) => self.write_control(OpCode::Pong, data).await,
            Message::Close(frame) => self.write_close(frame).await,
        }
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
        match self.ready_to_send().await {
            Ok(()) => self.write_frame(opcode, payload).await,
            Err(e) => (Err(e), payload),
        }
    }

    /// Flush what is owed, then check we may still send.
    async fn ready_to_send(&mut self) -> io::Result<()> {
        self.flush().await?;
        if self.close_sent {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "close frame already sent",
            ));
        }
        Ok(())
    }

    /// Send what reading left owed: the pong to the latest ping, and the
    /// close reply or protocol-error close.
    pub async fn flush(&mut self) -> io::Result<()> {
        if let Some(payload) = self.pending_pong.take() {
            self.write_control(OpCode::Pong, payload).await?;
        }
        if let Some(frame) = self.pending_close.take() {
            self.write_close(frame).await?;
        }
        Ok(())
    }

    /// Start the closing handshake, or finish it if the peer started it.
    /// Keep reading until `None` to see the peer's reply. Idempotent.
    pub async fn close(&mut self, frame: Option<CloseFrame>) -> io::Result<()> {
        self.flush().await?;
        if self.close_sent {
            return Ok(());
        }
        self.write_close(frame).await
    }

    /// Frame the pooled payload in place and send that very buffer: no
    /// allocation, no copy. It goes back to the pool once the send is done.
    async fn write_control(&mut self, opcode: OpCode, payload: ControlBuf) -> io::Result<()> {
        self.ensure_intact()?;
        let mask = (self.role == Role::Client).then(random_mask);
        let frame = payload.into_frame(opcode, mask);
        self.writing = true;
        let result = self.transport.send(frame).await.0;
        self.writing = false;
        result
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

    async fn write_close(&mut self, frame: Option<CloseFrame>) -> io::Result<()> {
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
        // Past our close frame nothing else may be sent, a pong included.
        self.close_sent = true;
        self.pending_pong = None;
        self.write_control(OpCode::Close, payload).await?;
        if self.close_received {
            self.transport.shutdown().await?;
        }
        Ok(())
    }

    /// Send one data frame; the payload buffer comes back with the result.
    async fn write_frame(
        &mut self,
        opcode: OpCode,
        mut payload: Vec<u8>,
    ) -> (io::Result<()>, Vec<u8>) {
        if let Err(e) = self.ensure_intact() {
            return (Err(e), payload);
        }
        let mask = (self.role == Role::Client).then(random_mask);
        let mut header = [0; MAX_HEADER_LEN];
        let n = encode_header(&mut header, true, opcode, payload.len(), mask);
        if let Some(key) = mask {
            apply_mask(&mut payload, key, 0);
        }
        // Both buffers are lent to the send and come back with its result;
        // a send cancelled mid-flight keeps them, and poisons the socket anyway.
        let mut buf = std::mem::take(&mut self.send_buf);
        buf.clear();
        buf.extend_from_slice(&header[..n]);
        self.writing = true;
        let (result, payload) = if payload.len() <= INLINE_PAYLOAD {
            buf.extend_from_slice(&payload);
            let (result, buf) = self.transport.send(buf).await;
            self.send_buf = buf;
            (result, payload)
        } else {
            // `buf` carries just the header; the payload goes out uncopied.
            let mut bufs = std::mem::take(&mut self.send_bufs);
            bufs.push(buf);
            bufs.push(payload);
            let (result, mut bufs) = self.transport.send_vectored(bufs).await;
            let payload = bufs.pop().expect("payload comes back");
            self.send_buf = bufs.pop().expect("header buffer comes back");
            self.send_bufs = bufs;
            (result, payload)
        };
        self.writing = false;
        (result, payload)
    }

    /// Record what a received message obliges us to send back.
    fn on_message(&mut self, message: &Message) {
        match message {
            Message::Ping(payload) if !self.close_sent => {
                self.pending_pong = Some(payload.clone());
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
        self.pending_pong = None;
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
            match ready!(this.transport.poll_recv(cx)) {
                // Decoded whole, then dropped here: the ring buffer is back
                // with the kernel before any message is handed out.
                Some(Ok(chunk)) => this.decode(chunk.as_ref()),
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

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::task::Waker;

    use runtime::net::IoBuf;

    use super::*;

    /// Records what is sent; never receives.
    #[derive(Default)]
    struct Wire(Vec<u8>);

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
            (Ok(()), buf)
        }

        async fn send_vectored<B: IoBuf>(&mut self, bufs: Vec<B>) -> (io::Result<()>, Vec<B>) {
            bufs.iter().for_each(|b| self.0.extend_from_slice(bytes(b)));
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
            let mut decoder = Decoder::new(role == Role::Client, 1 << 20, 1 << 20);
            let mut wire = &ws.transport.0[..];
            let mut received = Vec::new();
            while !wire.is_empty() {
                let (n, message) = decoder.feed(wire).unwrap();
                received.extend(message);
                wire = &wire[n..];
            }
            assert_eq!(received, sent, "{role:?}");
        }
    }

    #[test]
    fn send_buffers_are_reused() {
        let mut ws =
            WebSocket::from_upgraded(Wire::default(), Role::Server, vec![], Config::default());
        let sent = [
            Message::binary(vec![1; 100]),
            Message::text("small"),
            Message::binary(vec![2; 20_000]),
            Message::binary(vec![3; 30_000]),
            Message::binary(vec![4; 10]),
        ];
        let mut addresses = Vec::new();
        for message in sent.iter().cloned() {
            now(ws.send(message)).unwrap();
            addresses.push((ws.send_buf.as_ptr(), ws.send_bufs.as_ptr()));
        }
        // First send allocates; every later one, small or gathered, reuses.
        assert!(addresses.windows(2).all(|w| w[0] == w[1]), "{addresses:?}");
        assert!(ws.send_bufs.is_empty());

        let mut decoder = Decoder::new(false, 1 << 20, 1 << 20);
        let mut wire = &ws.transport.0[..];
        let mut received = Vec::new();
        while !wire.is_empty() {
            let (n, message) = decoder.feed(wire).unwrap();
            received.extend(message);
            wire = &wire[n..];
        }
        assert_eq!(received, sent);
    }
}
