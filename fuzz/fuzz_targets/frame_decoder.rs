//! Arbitrary bytes, in arbitrary pieces, into the frame decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;
use popple_ws::Message;
use popple_ws::frame::Decoder;

fuzz_target!(|data: &[u8]| {
    let [flags, stride, rest @ ..] = data else { return };
    let masked = flags & 1 != 0;
    let (max_frame, max_message) = match flags & 2 {
        0 => (64, 256),
        _ => (1 << 20, 4 << 20),
    };
    let mut decoder = Decoder::new(masked, max_frame, max_message);
    for piece in rest.chunks((*stride as usize).max(1)) {
        let mut input = piece;
        while !input.is_empty() {
            match decoder.feed(input) {
                Ok((n, message)) => {
                    assert!(n <= input.len());
                    // Short of a message, everything given is taken.
                    assert!(message.is_some() || n == input.len());
                    match &message {
                        // Built without re-validation: check it here.
                        Some(Message::Text(text)) => {
                            assert!(std::str::from_utf8(text.as_bytes()).is_ok());
                            assert!(text.len() <= max_message);
                        }
                        Some(Message::Binary(data)) => assert!(data.len() <= max_message),
                        Some(Message::Ping(p) | Message::Pong(p)) => assert!(p.len() <= 125),
                        _ => {}
                    }
                    input = &input[n..];
                }
                Err(e) => {
                    // Spent: the same error, whatever comes next.
                    assert_eq!(decoder.feed(b"\x81\x80").unwrap_err(), e);
                    return;
                }
            }
        }
    }
});
