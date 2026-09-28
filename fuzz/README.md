# Fuzzing

The runtime turns a panic in a worker into an abort: one panic a peer can
reach takes down every connection. These targets feed popple-ws what a peer
controls, and check more than the absence of a panic.

| Target | Input | Checks |
|---|---|---|
| `frame_decoder` | bytes, in pieces, into `Decoder` | all input taken short of a message; limits held; text valid UTF-8; spent after an error |
| `roundtrip` | messages through our writer, then the peer's decoder, in pieces | what arrives is what was sent, masked or not |
| `websocket` | frames and garbage in, in pieces, sends interleaved | everything written is valid to the peer; nothing after our close |
| `http_head` | bytes as an HTTP head, parsed and read out of pieces | no control character survives parsing; head and leftover lose nothing |

```sh
cargo install cargo-fuzz                      # needs a nightly toolchain
cargo +nightly fuzz run websocket -- -max_total_time=900 -max_len=65536
cargo +nightly fuzz run websocket corpus/websocket -- -runs=0   # replay the corpus
```

The parser entry points `http_head` drives are built only under `cargo fuzz`
(`cfg(fuzzing)`), outside the public API.
