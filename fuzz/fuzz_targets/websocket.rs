//! The whole WebSocket: arbitrary frames and garbage coming in, in arbitrary
//! pieces, interleaved with arbitrary sends. Whatever we write must be valid
//! to the peer, and nothing may follow our close frame.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use popple_ws::frame::Decoder;
use popple_ws::{CloseFrame, Config, Message, Role, WebSocket};

#[path = "common.rs"]
mod common;
use common::{Wire, cut, now};

/// A frame as the peer might send it, well-formed or not.
#[derive(Arbitrary, Debug)]
struct Frame {
    fin: bool,
    rsv: u8,
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload: Vec<u8>,
}

impl Frame {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push((self.fin as u8) << 7 | (self.rsv & 7) << 4 | self.opcode & 0xF);
        let bit = (self.mask.is_some() as u8) << 7;
        match self.payload.len() {
            n @ 0..=125 => out.push(bit | n as u8),
            n @ 126..=0xFFFF => {
                out.push(bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match self.mask {
            Some(key) => {
                out.extend_from_slice(&key);
                out.extend(self.payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => out.extend_from_slice(&self.payload),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Piece {
    Frame(Frame),
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
enum Action {
    Next,
    Flush,
    Feed(Vec<u8>),
    Send(Vec<u8>),
    SendText(String),
    SendBinary(Vec<u8>),
    Ping(Vec<u8>),
    Close(Option<(u16, String)>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    server: bool,
    small_limits: bool,
    /// The first piece arrives as upgrade leftover.
    leftover: bool,
    incoming: Vec<Piece>,
    cuts: Vec<u16>,
    actions: Vec<Action>,
}

fuzz_target!(|input: Input| {
    let mut bytes = Vec::new();
    for piece in &input.incoming {
        match piece {
            Piece::Frame(frame) => frame.encode(&mut bytes),
            Piece::Raw(raw) => bytes.extend_from_slice(raw),
        }
    }
    let mut pieces = cut(&bytes, &input.cuts);
    let leftover = match input.leftover && !pieces.is_empty() {
        true => pieces.remove(0),
        false => Vec::new(),
    };
    let role = if input.server { Role::Server } else { Role::Client };
    let config = match input.small_limits {
        true => Config {
            max_frame_size: 64,
            max_message_size: 256,
            ..Config::default()
        },
        false => Config::default(),
    };
    let wire = Wire {
        incoming: pieces.into(),
        written: Default::default(),
    };
    let written = wire.written.clone();
    let mut ws = WebSocket::from_upgraded(wire, role, leftover, config);

    for action in input.actions {
        let _ = match action {
            Action::Next => {
                let _ = now(ws.next_message());
                Ok(())
            }
            Action::Flush => now(ws.flush()),
            Action::Feed(data) => now(ws.feed(Message::Binary(data))),
            Action::Send(data) => now(ws.send(Message::Binary(data))),
            Action::SendText(text) => now(ws.send_text(text)).0,
            Action::SendBinary(data) => now(ws.send_binary(data)).0,
            Action::Ping(payload) => match Message::ping(&payload) {
                Ok(ping) => now(ws.send(ping)),
                Err(_) => Ok(()),
            },
            Action::Close(frame) => {
                now(ws.close(frame.map(|(code, reason)| CloseFrame { code, reason })))
            }
        };
    }
    // Read what is left, then answer what it owes.
    while now(ws.next_message()).is_some() {}
    let _ = now(ws.flush());

    // As the peer: every frame valid, and nothing after our close.
    let mut peer = Decoder::new(!input.server, usize::MAX >> 1, usize::MAX >> 1);
    let written = written.borrow();
    let mut written = &written[..];
    while !written.is_empty() {
        let (n, message) = peer.feed(written).expect("the peer refuses what we wrote");
        written = &written[n..];
        if let Some(Message::Close(_)) = message {
            assert!(written.is_empty(), "frames after our close");
        }
    }
});

/// `StreamExt::next` without the import dance.
trait NextMessage {
    fn next_message(&mut self) -> impl Future<Output = Option<std::io::Result<Message>>>;
}

impl<T: popple_ws::Transport> NextMessage for WebSocket<T> {
    fn next_message(&mut self) -> impl Future<Output = Option<std::io::Result<Message>>> {
        runtime_streams::StreamExt::next(self)
    }
}
