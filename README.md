# popple-ws

WebSocket ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)) for the
[`runtime`](https://github.com/saucisoupe/runtime) io_uring runtime, over plain
TCP or TLS offloaded to the kernel by
[`popple-tls`](https://github.com/saucisoupe/popple-tls).

- **Multishot receive.** Frames are decoded straight out of the kernel's
  provided-buffer ring; each ring buffer goes back to the kernel as soon as it
  is decoded, before any message is handed out.
- **One copy per byte.** Each payload byte is copied once, from the ring into
  its message, and unmasked in place.
- **No allocation on the hot path** once a connection is warm: send buffers are
  reused, ping/pong/close payloads come from a per-thread pool, and
  `send_binary`/`send_text` hand the caller's buffer back.
- **Hardened against peers:** frame and message size limits checked on the
  header, allocation that grows only as bytes arrive, a single deadline over
  the HTTP upgrade, UTF-8 validated as it arrives.

## Server

```rust
use popple_ws::{Config, Message, Plain, Upgrade};
use runtime::net::MultiAccept;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 1024);

runtime::main_thread_with::<Ring, _>(async {
    let mut accept = MultiAccept::new(9001).unwrap();
    while let Some(Ok(socket)) = accept.next().await {
        runtime::spawn(async move {
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), Config::default()).await?;
            // Path, headers, Origin, cookies: check them here, or `upgrade.reject(401, ..)`.
            let mut ws = upgrade.accept().await?;
            while let Some(Ok(message)) = ws.next().await {
                if let Message::Text(_) | Message::Binary(_) = message {
                    ws.send(message).await?;
                } else {
                    ws.flush().await?; // pongs and the close reply are queued by reading
                }
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        });
    }
});
```

For TLS, build the transport from the handshaken socket instead:

```rust
let ktls = popple_tls::handshake(socket, tls_config, Duration::from_secs(5)).await?;
let upgrade = Upgrade::read(Tls::new(ktls.into_messages::<Ring>()), Config::default()).await?;
```

## Client

```rust
let (mut ws, _response) = popple_ws::connect::<Ring>(addr, "example.com", "/chat", Config::default()).await?;
// or: popple_ws::connect_tls::<Ring>(addr, server_name, tls_client_config, "/chat", config)
ws.send(Message::text("hello")).await?;
```

## Reading and writing from different tasks

`next()` is cancel-safe, so a single task can `select` it against its own
events. To read and write from different tasks, `split` the socket: a driver
task then answers pings, completes the closing handshake and interleaves both
directions.

```rust
let (tx, rx) = ws.split(32);      // at most 32 incoming messages wait for `rx`
tx.send(Message::text("hi"));     // never waits
while let Some(message) = rx.recv().await { /* ... */ }
```

## Configuration

`Config` sets `max_frame_size` (16 MiB), `max_message_size` (64 MiB) and
`handshake_timeout` (5 s, up to one hour). `Config::validate` checks it
up front.

## Testing

```sh
cargo test                 # unit tests and loopback, plain and kTLS
autobahn/run.sh server     # Autobahn|Testsuite against examples/echo_server
autobahn/run.sh client     # examples/autobahn_client against Autobahn
```

`run.sh` uses a native `wstest` (`$WSTEST`, `~/.local/autobahn/pypy/bin/wstest`
or `PATH`), else the docker/podman image, which is amd64 only. Latest results,
permessage-deflate cases (12.\*, 13.\*) excluded:

| Mode   | OK  | Non-strict | Informational | Failed |
|--------|-----|------------|---------------|--------|
| Client | 298 | 0          | 3             | 0      |
| Server | 291 | 7          | 3             | 0      |

The server's non-strict cases come from `split`: on a protocol error right
after a valid message, the connection closes before the application's echo
goes out.

## Status

Experimental, like the runtime it builds on: Linux only, kernel 6.1 or later,
and `modprobe tls` for kTLS. Not supported yet: permessage-deflate, idle and
keepalive timeouts, a bound on `split`'s outgoing queue, and a true split of
TLS connections (writes go through the driver task).
