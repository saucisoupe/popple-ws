//! Arbitrary messages through our writer, then the peer's decoder, in
//! arbitrary pieces: what arrives must be what was sent.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use popple_ws::frame::Decoder;
use popple_ws::{CloseFrame, Config, Message, Role, WebSocket};

#[path = "common.rs"]
mod common;
use common::{Wire, cut, decode, now};

#[derive(Arbitrary, Debug)]
enum Msg {
    Text(String),
    Binary(Vec<u8>),
    /// Past the inline threshold: a segment of its own.
    Large(u8, u16),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    client: bool,
    /// Each message, and whether to flush after it.
    messages: Vec<(Msg, bool)>,
    cuts: Vec<u16>,
}

fn control(payload: &[u8]) -> &[u8] {
    &payload[..payload.len().min(125)]
}

/// The close reason as it goes out: cut on a char boundary to fit.
fn truncated(reason: &str) -> String {
    let mut end = reason.len().min(123);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

fuzz_target!(|input: Input| {
    let role = if input.client { Role::Client } else { Role::Server };
    let config = Config {
        max_frame_size: 1 << 20,
        max_message_size: 1 << 20,
        ..Config::default()
    };
    let wire = Wire::default();
    let written = wire.written.clone();
    let mut ws = WebSocket::from_upgraded(wire, role, vec![], config);
    let mut expected = Vec::new();
    for (msg, flush) in input.messages {
        let message = match msg {
            Msg::Text(text) => Message::Text(text),
            Msg::Binary(data) => Message::Binary(data),
            Msg::Large(byte, extra) => Message::Binary(vec![byte; 4097 + extra as usize]),
            Msg::Ping(payload) => Message::ping(control(&payload)).unwrap(),
            Msg::Pong(payload) => Message::pong(control(&payload)).unwrap(),
            Msg::Close(frame) => {
                Message::Close(frame.map(|(code, reason)| CloseFrame { code, reason }))
            }
        };
        let arrives = match &message {
            Message::Close(Some(f)) => Message::Close(Some(CloseFrame {
                code: f.code,
                reason: truncated(&f.reason),
            })),
            other => other.clone(),
        };
        // Refused after our close, or when invalid: then it must not go out.
        if now(ws.feed(message)).is_ok() {
            expected.push(arrives);
        }
        if flush {
            now(ws.flush()).unwrap();
        }
    }
    now(ws.flush()).unwrap();

    let pieces = cut(&written.borrow(), &input.cuts);
    let mut peer = Decoder::new(input.client, 1 << 20, 1 << 20);
    let received = decode(&mut peer, &pieces).expect("the peer refuses what we wrote");
    assert_eq!(received, expected);
});
