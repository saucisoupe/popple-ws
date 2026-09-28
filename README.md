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
- **Batched writes.** `feed` queues frames, small ones packed together and
  large ones uncopied; `flush` writes them all in one operation, and with
  kTLS in as few records.
- **No allocation on the hot path** once a connection is warm: write buffers
  are reused, ping/pong/close payloads come from a per-thread pool, and
  `send_binary`/`send_text` hand the caller's buffer back.
- **Hardened against peers:** size limits checked on the frame header,
  allocation that grows only as bytes arrive, deadlines on the upgrade, on
  idle connections and on the closing handshake, a bounded outgoing queue,
  strict header parsing, and an optional `Origin` allow-list.

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
                    ws.feed(message).await?; // queued, not written yet
                }
                // Once what one read brought in is handled, one write for all
                // the echoes, with the pongs and close reply reading owes.
                if !ws.has_ready() {
                    ws.flush().await?;
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
task then answers pings, completes the closing handshake, and runs both
directions at once, plain or TLS: it keeps reading while a write waits on a
slow peer.

```rust
let (tx, rx) = ws.split(32);      // at most 32 incoming messages wait for `rx`
tx.send(Message::text("hi"))?;    // never waits; `SendError::Full` past the budget
while let Some(message) = rx.recv().await { /* ... */ }
```

The driver feeds a whole batch of outgoing messages before flushing, so they
leave in one write. It also pings a quiet peer every `ping_interval`, so live connections
stay under `idle_timeout`. Driving the socket yourself, send your own pings
(`ws.idle_for()` tells how long it has been quiet), and call `flush` after
reading: pongs and the close reply only go out then.

## Graceful shutdown

Under `thread_per_core`, SIGTERM and SIGINT end every `MultiAccept` stream
polled from a worker's root future. A `Shutdown` per worker then closes the
live connections with 1001 and waits for them:

```rust
let shutdown = Shutdown::new();
while let Some(Ok(socket)) = accept.next().await {   // None on SIGTERM
    let shutdown = shutdown.clone();
    let alive = shutdown.track();                    // counted from the accept
    spawn(async move {
        let mut ws = /* upgrade */;
        ws.watch(&shutdown);                          // split() closes it with 1001
        let (tx, rx) = ws.split(32);
        /* ... */
        drop(alive);
    });
}
drop(accept);               // refuse new clients instead of queueing them
shutdown.trigger();
shutdown.drained().await;   // each connection bounded by close_timeout
```

Driving a socket by hand, `select` on `shutdown.triggered()` and call
`ws.close(..)`. The runtime exits the process 30 s after the signal whatever
is left, so keep `close_timeout` and `handshake_timeout` well below that.
`examples/echo_server.rs` does all of this.

## Configuration

The defaults suit a server facing untrusted peers. Every size limit is also
memory a single connection may hold, and every duration is up to one hour.

| Field | Default | |
|---|---|---|
| `max_frame_size` | 1 MiB | larger frames close the connection with 1009 |
| `max_message_size` | 4 MiB | across all fragments of a message |
| `handshake_timeout` | 5 s | one deadline over the whole HTTP upgrade |
| `idle_timeout` | 60 s | nothing received: close with 1001, `TimedOut` |
| `ping_interval` | 20 s | keepalive pings from `split` |
| `close_timeout` | 5 s | wait for the peer's close frame, then drop it |
| `write_timeout` | 30 s | a write the peer does not take fails the connection |
| `max_outbound_bytes` | 4 MiB | `split`'s queue for a peer that does not read |
| `allowed_origins` | any | browser `Origin` allow-list, else 403 |

Servers that authenticate with cookies should set `allowed_origins`: without
it, any web page can open a socket with the user's cookies. `Config::validate`
checks a configuration up front.

Each connection may hold up to its receive queue in ring buffers (`Plain<R, 32>`
by default) while it is not read. Size the buffer ring above the sum of those
queues, or a few slow connections starve the others on the same thread.

## Testing

```sh
cargo test                 # unit tests and loopback, plain and kTLS
cargo +nightly fuzz run websocket   # and frame_decoder, roundtrip, http_head: fuzz/README.md
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
and `modprobe tls` for kTLS. Not supported yet: permessage-deflate, and a
configurable receive queue for TLS connections (fixed by popple-tls).
