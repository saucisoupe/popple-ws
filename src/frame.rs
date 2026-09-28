//! RFC 6455 §5 framing: header encoding, masking, and an incremental decoder
//! that copies each payload byte once, straight into its message.

use crate::control::ControlBuf;
use crate::message::{CloseFrame, Message};

/// Largest possible frame header: 2 fixed bytes, 8 bytes of extended length,
/// 4 bytes of masking key.
pub const MAX_HEADER_LEN: usize = 14;

/// Control frames carry at most 125 bytes of payload (§5.5).
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// What a message buffer starts with, at most: one TLS record's worth. A
/// frame header alone never makes the decoder allocate more than this.
const INITIAL_CAPACITY: usize = 16 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl OpCode {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    pub fn is_control(self) -> bool {
        self as u8 & 0x8 != 0
    }
}

/// Close status codes this crate sends on its own (§7.4.1).
pub mod close_code {
    pub const NORMAL: u16 = 1000;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const INVALID_PAYLOAD: u16 = 1007;
    pub const TOO_BIG: u16 = 1009;
}

/// A violation of the framing rules. Carries the close code to answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: u16,
    pub reason: &'static str,
}

impl ProtocolError {
    const fn new(code: u16, reason: &'static str) -> Self {
        Self { code, reason }
    }

    const fn protocol(reason: &'static str) -> Self {
        Self::new(close_code::PROTOCOL_ERROR, reason)
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "websocket protocol error {}: {}", self.code, self.reason)
    }
}

impl std::error::Error for ProtocolError {}

impl From<ProtocolError> for std::io::Error {
    fn from(e: ProtocolError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

/// Write a frame header into `out`; returns how many bytes of it are used.
pub fn encode_header(
    out: &mut [u8; MAX_HEADER_LEN],
    fin: bool,
    opcode: OpCode,
    len: usize,
    mask: Option<[u8; 4]>,
) -> usize {
    out[0] = (fin as u8) << 7 | opcode as u8;
    let mask_bit = (mask.is_some() as u8) << 7;
    let mut n = match len {
        0..=125 => {
            out[1] = mask_bit | len as u8;
            2
        }
        126..=0xFFFF => {
            out[1] = mask_bit | 126;
            out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            4
        }
        _ => {
            out[1] = mask_bit | 127;
            out[2..10].copy_from_slice(&(len as u64).to_be_bytes());
            10
        }
    };
    if let Some(key) = mask {
        out[n..n + 4].copy_from_slice(&key);
        n += 4;
    }
    n
}

/// XOR `buf` with `mask`, where `buf[0]` sits at position `offset` of the
/// masked payload. Masking and unmasking are the same operation.
pub fn apply_mask(buf: &mut [u8], mask: [u8; 4], offset: usize) {
    let key: [u8; 4] = std::array::from_fn(|i| mask[(i + offset) % 4]);
    // Memory order in, memory order out: the XOR is endian-agnostic.
    let word = u64::from_ne_bytes(std::array::from_fn(|i| key[i % 4]));
    let mut chunks = buf.chunks_exact_mut(8);
    for chunk in &mut chunks {
        let v = u64::from_ne_bytes(chunk.try_into().unwrap()) ^ word;
        chunk.copy_from_slice(&v.to_ne_bytes());
    }
    chunks
        .into_remainder()
        .iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(b, k)| *b ^= k);
}

/// Total header length announced by the second header byte.
fn header_len(b1: u8) -> usize {
    let ext = match b1 & 0x7F {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    2 + ext + if b1 & 0x80 != 0 { 4 } else { 0 }
}

enum State {
    Header {
        buf: [u8; MAX_HEADER_LEN],
        filled: usize,
    },
    Payload {
        remaining: usize,
        mask: Option<[u8; 4]>,
        offset: usize,
    },
}

/// Incremental frame decoder and message reassembler. Feed it whatever the
/// transport delivered; it reports how much it consumed and, when a message
/// completed, the message.
pub struct Decoder {
    /// Servers require masked frames, clients require unmasked ones (§5.1).
    expect_masked: bool,
    max_frame_size: usize,
    max_message_size: usize,
    state: State,
    /// Opcode and FIN bit of the frame being read.
    frame: (OpCode, bool),
    /// Opcode of the data message being assembled, if one is in progress.
    message_op: Option<OpCode>,
    message: Vec<u8>,
    /// For a text message, how much of `message` is known valid UTF-8: up to
    /// the last complete character, so a character cut between chunks or
    /// fragments is checked once its end arrives.
    utf8_checked: usize,
    /// Payload of the control frame being read, from the pool.
    control: Option<ControlBuf>,
    /// The first error: every later `feed` returns it, since the state it
    /// left behind (a half-counted frame) must not be decoded any further.
    failed: Option<ProtocolError>,
}

const EMPTY_HEADER: State = State::Header {
    buf: [0; MAX_HEADER_LEN],
    filled: 0,
};

impl Decoder {
    /// Data frames over `max_frame_size`, or reassembled messages over
    /// `max_message_size`, fail with close code 1009 as soon as their header
    /// is read, before any of their payload is buffered.
    pub fn new(expect_masked: bool, max_frame_size: usize, max_message_size: usize) -> Self {
        Self {
            expect_masked,
            max_frame_size,
            max_message_size,
            state: EMPTY_HEADER,
            frame: (OpCode::Binary, true),
            message_op: None,
            message: Vec::new(),
            utf8_checked: 0,
            control: None,
            failed: None,
        }
    }

    /// Consume from `input` up to the end of the next complete message.
    /// Returns the bytes consumed and that message, if one completed. After
    /// an error the decoder is spent: it returns that error from then on.
    pub fn feed(&mut self, input: &[u8]) -> Result<(usize, Option<Message>), ProtocolError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let result = self.decode(input);
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }

    fn decode(&mut self, input: &[u8]) -> Result<(usize, Option<Message>), ProtocolError> {
        let mut pos = 0;
        loop {
            match &mut self.state {
                State::Header { buf, filled } => {
                    // The first two bytes announce how long the rest is.
                    let need = if *filled < 2 { 2 } else { header_len(buf[1]) };
                    if *filled < need {
                        if pos == input.len() {
                            return Ok((pos, None));
                        }
                        let take = (need - *filled).min(input.len() - pos);
                        buf[*filled..*filled + take].copy_from_slice(&input[pos..pos + take]);
                        *filled += take;
                        pos += take;
                        continue;
                    }
                    let header = *buf;
                    // `start_frame` moves on to the payload, if there is one.
                    self.state = EMPTY_HEADER;
                    if let Some(message) = self.start_frame(&header[..need])? {
                        return Ok((pos, Some(message)));
                    }
                }
                State::Payload {
                    remaining,
                    mask,
                    offset,
                } => {
                    let take = (*remaining).min(input.len() - pos);
                    let src = &input[pos..pos + take];
                    let (opcode, fin) = self.frame;
                    let written = if opcode.is_control() {
                        // `start_frame` checked the length against the 125.
                        self.control
                            .as_mut()
                            .expect("armed by start_frame")
                            .extend(src)
                    } else {
                        let room = if opcode != OpCode::Continuation && fin {
                            // A whole message in one frame: its size is known.
                            self.message.len() + *remaining
                        } else {
                            // Fragmented: the size is not known until the end.
                            self.max_message_size
                        };
                        let message = &mut self.message;
                        if message.capacity() - message.len() < take {
                            // Double, as `Vec` would, but never past what the
                            // message can still grow to; `room - len >= take`.
                            message
                                .reserve_exact(message.len().max(take).min(room - message.len()));
                        }
                        let start = message.len();
                        message.extend_from_slice(src);
                        &mut message[start..]
                    };
                    if let Some(key) = *mask {
                        apply_mask(written, key, *offset);
                    }
                    // Fail fast: invalid text is refused as soon as it arrives,
                    // not once the whole message is in.
                    if !opcode.is_control() && self.message_op == Some(OpCode::Text) {
                        check_utf8(&self.message, &mut self.utf8_checked)?;
                    }
                    pos += take;
                    *remaining -= take;
                    *offset += take;
                    if *remaining > 0 {
                        return Ok((pos, None));
                    }
                    self.state = EMPTY_HEADER;
                    if let Some(message) = self.finish_frame()? {
                        return Ok((pos, Some(message)));
                    }
                }
            }
        }
    }

    /// Validate a complete header and move to its payload. An empty frame
    /// completes on the spot.
    fn start_frame(&mut self, h: &[u8]) -> Result<Option<Message>, ProtocolError> {
        if h[0] & 0x70 != 0 {
            return Err(ProtocolError::protocol(
                "reserved bits set without extension",
            ));
        }
        let fin = h[0] & 0x80 != 0;
        let opcode =
            OpCode::from_bits(h[0] & 0x0F).ok_or(ProtocolError::protocol("unknown opcode"))?;
        let masked = h[1] & 0x80 != 0;
        if masked != self.expect_masked {
            return Err(ProtocolError::protocol(if masked {
                "masked frame from server"
            } else {
                "unmasked frame from client"
            }));
        }
        let (len, rest) = match h[1] & 0x7F {
            126 => (u16::from_be_bytes([h[2], h[3]]) as u64, &h[4..]),
            127 => (u64::from_be_bytes(h[2..10].try_into().unwrap()), &h[10..]),
            n => (n as u64, &h[2..]),
        };
        let mask = masked.then(|| rest[..4].try_into().unwrap());

        if opcode.is_control() {
            if !fin {
                return Err(ProtocolError::protocol("fragmented control frame"));
            }
            if len > MAX_CONTROL_PAYLOAD as u64 {
                return Err(ProtocolError::protocol("control frame too long"));
            }
            self.control = Some(ControlBuf::new());
        } else {
            match (opcode, self.message_op) {
                (OpCode::Continuation, None) => {
                    return Err(ProtocolError::protocol("continuation without a message"));
                }
                (OpCode::Continuation, Some(_)) => {}
                (_, Some(_)) => {
                    return Err(ProtocolError::protocol(
                        "new message inside a fragmented one",
                    ));
                }
                (op, None) => self.message_op = Some(op),
            }
            if len > self.max_frame_size as u64 {
                return Err(ProtocolError::new(close_code::TOO_BIG, "frame too big"));
            }
            if len > (self.max_message_size - self.message.len()) as u64 {
                return Err(ProtocolError::new(close_code::TOO_BIG, "message too big"));
            }
            // A header costs the peer a few bytes; memory must cost it the
            // payload itself. Past this, the buffer grows as bytes arrive.
            // Continuations reserve nothing: growth there must stay amortized.
            if opcode != OpCode::Continuation {
                self.message
                    .reserve_exact((len as usize).min(INITIAL_CAPACITY));
            }
        }

        self.frame = (opcode, fin);
        if len == 0 {
            return self.finish_frame();
        }
        self.state = State::Payload {
            remaining: len as usize,
            mask,
            offset: 0,
        };
        Ok(None)
    }

    fn take_control(&mut self) -> ControlBuf {
        self.control.take().expect("armed by start_frame")
    }

    fn finish_frame(&mut self) -> Result<Option<Message>, ProtocolError> {
        let (opcode, fin) = self.frame;
        let message = match opcode {
            // The pooled payload moves into the message: no copy.
            OpCode::Ping => Message::Ping(self.take_control()),
            OpCode::Pong => Message::Pong(self.take_control()),
            OpCode::Close => Message::Close(parse_close(&self.take_control())?),
            _ if !fin => return Ok(None),
            _ => {
                let payload = std::mem::take(&mut self.message);
                let checked = std::mem::take(&mut self.utf8_checked);
                match self.message_op.take() {
                    // Everything but a character cut by the end of the message
                    // was validated on arrival.
                    Some(OpCode::Text) if checked != payload.len() => {
                        return Err(invalid_utf8());
                    }
                    // SAFETY: `check_utf8` validated all of it, as it arrived.
                    Some(OpCode::Text) => {
                        Message::Text(unsafe { String::from_utf8_unchecked(payload) })
                    }
                    _ => Message::Binary(payload),
                }
            }
        };
        Ok(Some(message))
    }
}

/// Validate the text of `message` past `checked`, moving `checked` up to the
/// last complete character. A character cut at the end may still be completed
/// by the next bytes; any other invalid sequence fails the message now.
fn check_utf8(message: &[u8], checked: &mut usize) -> Result<(), ProtocolError> {
    match std::str::from_utf8(&message[*checked..]) {
        Ok(_) => *checked = message.len(),
        Err(e) if e.error_len().is_none() => *checked += e.valid_up_to(),
        Err(_) => return Err(invalid_utf8()),
    }
    Ok(())
}

fn invalid_utf8() -> ProtocolError {
    ProtocolError::new(close_code::INVALID_PAYLOAD, "invalid UTF-8 text")
}

fn parse_close(payload: &[u8]) -> Result<Option<CloseFrame>, ProtocolError> {
    match payload {
        [] => Ok(None),
        [_] => Err(ProtocolError::protocol("close payload of one byte")),
        [hi, lo, reason @ ..] => {
            let code = u16::from_be_bytes([*hi, *lo]);
            if !valid_close_code(code) {
                return Err(ProtocolError::protocol("invalid close code"));
            }
            let reason = std::str::from_utf8(reason).map_err(|_| {
                ProtocolError::new(close_code::INVALID_PAYLOAD, "invalid UTF-8 close reason")
            })?;
            Ok(Some(CloseFrame {
                code,
                reason: reason.to_owned(),
            }))
        }
    }
}

/// Codes a peer may put on the wire (§7.4.1, §7.4.2).
pub(crate) fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(fin: bool, op: OpCode, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut header = [0; MAX_HEADER_LEN];
        let n = encode_header(&mut header, fin, op, payload.len(), mask);
        let mut out = header[..n].to_vec();
        let start = out.len();
        out.extend_from_slice(payload);
        if let Some(key) = mask {
            apply_mask(&mut out[start..], key, 0);
        }
        out
    }

    fn decode_all(dec: &mut Decoder, mut input: &[u8]) -> Vec<Message> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let (n, msg) = dec.feed(input).expect("valid");
            out.extend(msg);
            input = &input[n..];
        }
        out
    }

    #[test]
    fn mask_matches_bytewise_at_any_offset() {
        let key = [0x12, 0x34, 0x56, 0x78];
        let data: Vec<u8> = (0..37).collect();
        for offset in 0..8 {
            let mut fast = data.clone();
            apply_mask(&mut fast, key, offset);
            let slow: Vec<u8> = data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[(i + offset) % 4])
                .collect();
            assert_eq!(fast, slow, "offset {offset}");
        }
    }

    #[test]
    fn header_lengths() {
        let mut h = [0; MAX_HEADER_LEN];
        assert_eq!(encode_header(&mut h, true, OpCode::Text, 125, None), 2);
        assert_eq!(encode_header(&mut h, true, OpCode::Text, 126, None), 4);
        assert_eq!(encode_header(&mut h, true, OpCode::Text, 70_000, None), 10);
        assert_eq!(
            encode_header(&mut h, true, OpCode::Text, 70_000, Some([1; 4])),
            14
        );
    }

    #[test]
    fn masked_text_byte_by_byte() {
        let wire = frame(true, OpCode::Text, "héllo".as_bytes(), Some([9, 8, 7, 6]));
        let mut dec = Decoder::new(true, 1 << 20, 1 << 20);
        let mut got = Vec::new();
        for b in &wire {
            let (n, msg) = dec.feed(std::slice::from_ref(b)).unwrap();
            assert_eq!(n, 1);
            got.extend(msg);
        }
        assert_eq!(got, vec![Message::Text("héllo".into())]);
    }

    #[test]
    fn fragments_with_interleaved_ping_and_large_lengths() {
        let big = vec![0xAB; 70_000];
        let mut wire = frame(false, OpCode::Binary, &big[..200], None);
        wire.extend(frame(true, OpCode::Ping, b"p", None));
        wire.extend(frame(true, OpCode::Continuation, &big[200..], None));
        wire.extend(frame(true, OpCode::Close, &[0x03, 0xE8, b'o', b'k'], None));
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        let got = decode_all(&mut dec, &wire);
        assert_eq!(
            got,
            vec![
                Message::ping(b"p").unwrap(),
                Message::Binary(big),
                Message::Close(Some(CloseFrame {
                    code: 1000,
                    reason: "ok".into()
                })),
            ]
        );
    }

    #[test]
    fn oversized_frame_fails_on_its_header_alone() {
        let wire = frame(true, OpCode::Binary, &[0; 2000], None);
        let mut dec = Decoder::new(false, 1024, 1 << 20);
        // Header only: 2 bytes + 2 of extended length, no payload yet.
        let err = dec.feed(&wire[..4]).unwrap_err();
        assert_eq!((err.code, err.reason), (1009, "frame too big"));
    }

    #[test]
    fn fragments_under_frame_limit_still_bound_the_message() {
        let mut wire = frame(false, OpCode::Binary, &[0; 600], None);
        wire.extend(frame(true, OpCode::Continuation, &[0; 600], None));
        let mut dec = Decoder::new(false, 1024, 1000);
        let err = dec.feed(&wire).unwrap_err();
        assert_eq!((err.code, err.reason), (1009, "message too big"));
    }

    #[test]
    fn header_alone_does_not_allocate_its_length() {
        let mut header = [0; MAX_HEADER_LEN];
        let n = encode_header(&mut header, true, OpCode::Binary, 512 << 20, None);
        let mut dec = Decoder::new(false, 1 << 30, 1 << 30);
        assert_eq!(dec.feed(&header[..n]).unwrap(), (n, None));
        assert!(dec.message.capacity() <= INITIAL_CAPACITY);
    }

    #[test]
    fn buffer_starts_small_and_never_outgrows_the_message() {
        let capacity_after = |len: usize| {
            let wire = frame(true, OpCode::Binary, &vec![7; len], Some([1, 2, 3, 4]));
            let mut dec = Decoder::new(true, 1 << 20, 1 << 20);
            // Ring-buffer-sized pieces, as the transport delivers them.
            let got = wire
                .chunks(4096)
                .filter_map(|chunk| dec.feed(chunk).unwrap().1)
                .next();
            match got {
                Some(Message::Binary(data)) => {
                    assert_eq!(data, vec![7; len]);
                    data.capacity()
                }
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(capacity_after(20), 20);
        assert_eq!(capacity_after(100_000), 100_000);
    }

    #[test]
    fn many_small_fragments_grow_amortized() {
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        let mut growths = 0;
        let mut capacity = 0;
        for i in 0..5000 {
            let op = if i == 0 {
                OpCode::Binary
            } else {
                OpCode::Continuation
            };
            let msg = dec.feed(&frame(i == 4999, op, &[1; 10], None)).unwrap().1;
            if dec.message.capacity() != capacity {
                capacity = dec.message.capacity();
                growths += 1;
            }
            if let Some(Message::Binary(data)) = msg {
                assert_eq!(data.len(), 50_000);
                assert!(data.capacity() < 2 * 50_000);
            }
        }
        // Doubling from 10 bytes to 50 000 is ~13 steps; once per fragment
        // would be 5000, and quadratic copying.
        assert!(growths <= 16, "{growths} reallocations");
    }

    #[test]
    fn invalid_text_fails_fast() {
        // A bad fragment is refused on arrival, the message still unfinished.
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        let mut wire = frame(false, OpCode::Text, b"hello", None);
        wire.extend(frame(false, OpCode::Continuation, &[b'a', 0xFF], None));
        assert_eq!(dec.feed(&wire).unwrap_err().code, 1007);

        // Mid-frame too: the rest of this frame has not arrived yet.
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        let mut payload = vec![b'a'; 100];
        payload[10] = 0xFF;
        let wire = frame(true, OpCode::Text, &payload, None);
        assert_eq!(dec.feed(&wire[..20]).unwrap_err().code, 1007);
    }

    #[test]
    fn character_cut_between_fragments() {
        // "é" is C3 A9: split across two fragments, it is fine.
        let mut wire = frame(false, OpCode::Text, &[b'x', 0xC3], None);
        wire.extend(frame(true, OpCode::Continuation, &[0xA9, b'y'], None));
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        assert_eq!(decode_all(&mut dec, &wire), vec![Message::text("xéy")]);

        // Left cut by the end of the message, it is not.
        let wire = frame(true, OpCode::Text, &[b'x', 0xC3], None);
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        assert_eq!(dec.feed(&wire).unwrap_err().code, 1007);
    }

    #[test]
    fn spent_after_an_error() {
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        let err = dec
            .feed(&frame(true, OpCode::Text, &[0xFF], None))
            .unwrap_err();
        // Valid input no longer gets through: the state is not trusted.
        let valid = frame(true, OpCode::Text, b"ok", None);
        assert_eq!(dec.feed(&valid).unwrap_err(), err);
    }

    #[test]
    fn empty_frames() {
        let mut wire = frame(true, OpCode::Ping, b"", None);
        wire.extend(frame(true, OpCode::Binary, b"", None));
        wire.extend(frame(true, OpCode::Text, b"after", None));
        let mut dec = Decoder::new(false, 1 << 20, 1 << 20);
        assert_eq!(
            decode_all(&mut dec, &wire),
            vec![
                Message::ping(&[]).unwrap(),
                Message::Binary(vec![]),
                Message::text("after"),
            ]
        );
    }

    #[test]
    fn rejects_violations() {
        let cases: &[(Vec<u8>, bool, u16)] = &[
            (frame(true, OpCode::Text, b"x", None), true, 1002),
            (frame(true, OpCode::Text, b"x", Some([1; 4])), false, 1002),
            (frame(false, OpCode::Ping, b"", None), false, 1002),
            (frame(true, OpCode::Continuation, b"x", None), false, 1002),
            (frame(true, OpCode::Text, &[0xFF], None), false, 1007),
            (frame(true, OpCode::Binary, &[0; 65], None), false, 1009),
            (frame(true, OpCode::Close, &[0x03, 0xED], None), false, 1002),
            (vec![0xC1, 0x00], false, 1002),
        ];
        for (wire, masked, code) in cases {
            let mut dec = Decoder::new(*masked, 64, 64);
            let err = dec.feed(wire).unwrap_err();
            assert_eq!(err.code, *code, "{wire:?}");
        }
    }
}
