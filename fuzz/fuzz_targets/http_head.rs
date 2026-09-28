//! Arbitrary bytes as an HTTP head: parsed and checked, and read out of
//! arbitrary pieces.

#![no_main]

use libfuzzer_sys::fuzz_target;
use popple_ws::handshake::fuzz;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    fuzz::head(data);
    let [stride, rest @ ..] = data else { return };
    fuzz::read(common::cut(rest, &vec![*stride as u16; rest.len()]));
});
