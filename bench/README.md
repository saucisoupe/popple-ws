# Load tests

`bench/run.sh` runs `examples/bench_client` against three echo servers and
prints a markdown table:

- **popple**: `examples/bench_server`, popple-ws on io_uring, TLS through kTLS;
- **tungstenite** and **fastwebsockets**: `bench/tokio-echo`, on a
  multi-threaded tokio runtime, TLS through tokio-rustls in userspace.

The client is popple-ws in every case, so only the server changes. It opens
its connections one at a time per worker, keeps `depth` binary messages of
`size` bytes in flight on each, and times every round-trip from a timestamp
carried in the payload. Server and client are pinned to disjoint cores. The
server's CPU time over the measured window gives the messages it echoes per
CPU-second: at equal throughput, the lighter server wins.

```sh
bench/run.sh                                   # everything, ~4 min
IMPLS="popple fastwebsockets" TLS=plain CASES="100:16:64" bench/run.sh
```

## Results

Apple silicon, 10 cores, under Linux 7.0 (aarch64); server on 4 cores, client
on 6; loopback; rustc 1.96, release builds; 5 s measured after 3 s warmup.
tokio-tungstenite 0.30, fastwebsockets 0.10, tokio 1.53. The popple-ws rows
were measured after write batching, the others in the run before it.

| server | tls | conns | depth | size | msg/s | MiB/s | p50 µs | p99 µs | p99.9 µs | server cores | k msg/CPU-s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| popple | plain | 100 | 1 | 64 | 913,567 | 55.8 | 92 | 311 | 590 | 3.49 | 261 |
| tungstenite | plain | 100 | 1 | 64 | 384,249 | 23.5 | 250 | 557 | 737 | 2.88 | 134 |
| fastwebsockets | plain | 100 | 1 | 64 | 428,798 | 26.2 | 225 | 524 | 721 | 2.61 | 164 |
| popple | plain | 100 | 16 | 64 | 1,920,500 | 117.2 | 770 | 1737 | 3539 | 3.97 | 484 |
| tungstenite | plain | 100 | 16 | 64 | 1,655,432 | 101.0 | 950 | 1868 | 2228 | 3.97 | 417 |
| fastwebsockets | plain | 100 | 16 | 64 | 1,771,444 | 108.1 | 868 | 1802 | 4194 | 3.97 | 446 |
| popple | plain | 100 | 1 | 4096 | 777,108 | 3,035.6 | 111 | 344 | 483 | 3.74 | 208 |
| tungstenite | plain | 100 | 1 | 4096 | 359,409 | 1,403.9 | 262 | 590 | 852 | 3.01 | 119 |
| fastwebsockets | plain | 100 | 1 | 4096 | 390,320 | 1,524.7 | 242 | 590 | 901 | 2.78 | 141 |
| popple | plain | 100 | 1 | 65536 | 149,122 | 9,320.1 | 623 | 1376 | 1769 | 3.99 | 37 |
| tungstenite | plain | 100 | 1 | 65536 | 154,728 | 9,670.5 | 623 | 1180 | 1540 | 3.82 | 40 |
| fastwebsockets | plain | 100 | 1 | 65536 | 212,950 | 13,309.4 | 434 | 1032 | 2097 | 3.70 | 58 |
| popple | plain | 10000 | 1 | 64 | 774,554 | 47.3 | 10224 | 12845 | 22544 | 4.00 | 194 |
| tungstenite | plain | 10000 | 1 | 64 | 574,570 | 35.1 | 1180 | 28836 | 34603 | 3.96 | 145 |
| fastwebsockets | plain | 10000 | 1 | 64 | 833,986 | 50.9 | 836 | 25166 | 28312 | 3.96 | 210 |
| popple | tls | 100 | 1 | 64 | 785,286 | 47.9 | 111 | 344 | 483 | 3.85 | 204 |
| tungstenite | tls | 100 | 1 | 64 | 350,901 | 21.4 | 270 | 606 | 950 | 3.04 | 115 |
| fastwebsockets | tls | 100 | 1 | 64 | 389,027 | 23.7 | 246 | 573 | 803 | 2.80 | 139 |
| popple | tls | 100 | 16 | 64 | 1,313,979 | 80.2 | 1114 | 2425 | 2949 | 3.98 | 330 |
| tungstenite | tls | 100 | 16 | 64 | 1,383,463 | 84.4 | 1114 | 2359 | 2884 | 3.96 | 350 |
| fastwebsockets | tls | 100 | 16 | 64 | 1,463,583 | 89.3 | 1032 | 2294 | 3015 | 3.95 | 370 |
| popple | tls | 100 | 1 | 4096 | 492,025 | 1,922.0 | 184 | 492 | 737 | 3.96 | 124 |
| tungstenite | tls | 100 | 1 | 4096 | 247,763 | 967.8 | 385 | 803 | 1049 | 3.38 | 73 |
| fastwebsockets | tls | 100 | 1 | 4096 | 267,060 | 1,043.2 | 360 | 737 | 967 | 3.29 | 81 |
| popple | tls | 100 | 1 | 65536 | 61,954 | 3,872.1 | 1442 | 3539 | 4325 | 4.00 | 15 |
| tungstenite | tls | 100 | 1 | 65536 | 60,299 | 3,768.7 | 1638 | 3015 | 4063 | 3.88 | 16 |
| fastwebsockets | tls | 100 | 1 | 65536 | 66,214 | 4,138.4 | 1475 | 2818 | 4194 | 3.89 | 17 |
| popple | tls | 10000 | 1 | 64 | 499,689 | 30.5 | 10224 | 13631 | 16515 | 4.01 | 125 |
| tungstenite | tls | 10000 | 1 | 64 | 429,528 | 26.2 | 1573 | 28836 | 33554 | 3.98 | 108 |
| fastwebsockets | tls | 10000 | 1 | 64 | 607,145 | 37.1 | 1114 | 26214 | 32506 | 3.98 | 152 |

Where popple-ws stands, as measured here:

- **Request/response** (one message in flight per connection) is where
  io_uring pays: about twice the throughput of both tokio servers at half the
  latency, plain or TLS, and 1.5 to 1.6 times the messages per CPU-second.
- **10 000 connections**: 7% behind fastwebsockets in plain, 18% in TLS,
  but a far tighter tail: p99 13 ms against 25 ms. The
  higher p50 is fairness, not slowness: with 10 000 messages in flight,
  Little's law puts the mean round-trip near 12 ms for everyone; popple-ws
  serves every connection at that pace, while the tokio servers serve some
  fast and starve the others.
- **Pipelining** (16 messages in flight): with `feed`/`flush`, the echoes of
  one read leave in one write, and with kTLS in as few records. Plain, it
  moved from 25% behind fastwebsockets to 8% ahead, and ahead in messages per
  CPU-second too; TLS, from 38% behind to 10%. Before, each message was its
  own write, awaited before the next one.
- **64 KiB messages** in plain are 31% behind fastwebsockets, likely the copy
  from ring buffers into the message, which fastwebsockets avoids by reading
  into its own buffer. In TLS, where decryption dominates, all three are
  level.

These are hypotheses: profiling needs `perf`, which Ubuntu restricts
(`sudo sysctl kernel.perf_event_paranoid=1`).
