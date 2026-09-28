//! Load client: opens `--conns` connections spread over one worker per core,
//! keeps `--depth` binary messages of `--size` bytes in flight on each, and
//! reports the echo throughput and round-trip latency. Each payload carries
//! its send time, so latency is measured per message.
//!
//!   cargo run --release --example bench_client -- \
//!       [--addr 127.0.0.1:9100] [--conns 100] [--depth 1] [--size 64] \
//!       [--secs 10] [--warmup 2] [--tls]
//!
//! Only round-trips sent after the warmup and done before the end count.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use popple_tls::{ServerName, client_config_dangerous_no_verification};
use popple_ws::{Config, Message, Transport, WebSocket, connect, connect_tls};
use runtime::spawn;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 4096);

const CONFIG: Config = Config {
    max_frame_size: 16 << 20,
    max_message_size: 16 << 20,
    handshake_timeout: Duration::from_secs(30),
    idle_timeout: None,
    ping_interval: None,
    close_timeout: Duration::from_secs(5),
    write_timeout: Duration::from_secs(30),
    max_outbound_bytes: 16 << 20,
    allowed_origins: &[],
};

#[derive(Clone)]
struct Args {
    addr: SocketAddr,
    conns: usize,
    depth: usize,
    size: usize,
    secs: u64,
    warmup: u64,
    tls: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        addr: "127.0.0.1:9100".parse().unwrap(),
        conns: 100,
        depth: 1,
        size: 64,
        secs: 10,
        warmup: 2,
        tls: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| panic!("{arg} needs a value"));
        match arg.as_str() {
            "--addr" => a.addr = value().parse().expect("--addr host:port"),
            "--conns" => a.conns = value().parse().expect("--conns N"),
            "--depth" => a.depth = value().parse().expect("--depth N"),
            "--size" => a.size = value().parse().expect("--size N"),
            "--secs" => a.secs = value().parse().expect("--secs N"),
            "--warmup" => a.warmup = value().parse().expect("--warmup N"),
            "--tls" => a.tls = true,
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(a.size >= 8, "--size must hold the 8-byte timestamp");
    a
}

/// Latency histogram: 32 buckets per power of two of nanoseconds, so each
/// bucket is within ~3% of its values. Fixed size, merged across workers.
struct Histogram {
    buckets: Vec<u64>,
    count: u64,
    max: u64,
}

const SUB_BITS: u32 = 5;
const SUB: u64 = 1 << SUB_BITS;

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: vec![0; 64 * SUB as usize],
            count: 0,
            max: 0,
        }
    }

    fn index(v: u64) -> usize {
        if v < SUB {
            return v as usize;
        }
        let exp = 63 - v.leading_zeros();
        let mantissa = (v >> (exp - SUB_BITS)) & (SUB - 1);
        ((exp - SUB_BITS + 1) as u64 * SUB + mantissa) as usize
    }

    /// Lower bound of the values in bucket `i`.
    fn value(i: usize) -> u64 {
        let i = i as u64;
        if i < SUB {
            return i;
        }
        let exp = i / SUB + SUB_BITS as u64 - 1;
        (SUB + i % SUB) << (exp - SUB_BITS as u64)
    }

    fn record(&mut self, nanos: u64) {
        self.buckets[Self::index(nanos)] += 1;
        self.count += 1;
        self.max = self.max.max(nanos);
    }

    fn merge(&mut self, other: &Histogram) {
        self.buckets
            .iter_mut()
            .zip(&other.buckets)
            .for_each(|(a, b)| *a += b);
        self.count += other.count;
        self.max = self.max.max(other.max);
    }

    fn quantile(&self, q: f64) -> Duration {
        let target = ((self.count as f64) * q).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (i, n) in self.buckets.iter().enumerate() {
            seen += n;
            if seen >= target {
                return Duration::from_nanos(Self::value(i));
            }
        }
        Duration::from_nanos(self.max)
    }
}

struct Stats {
    latency: Histogram,
    errors: u64,
    connected: u64,
}

impl Stats {
    fn new() -> Self {
        Self {
            latency: Histogram::new(),
            errors: 0,
            connected: 0,
        }
    }
}

/// The window, as offsets from the common start, shared by every thread.
#[derive(Clone, Copy)]
struct Window {
    start: Instant,
    warm: Duration,
    end: Duration,
}

fn stamp(buf: &mut [u8], window: &Window) {
    let now = window.start.elapsed().as_nanos() as u64;
    buf[..8].copy_from_slice(&now.to_le_bytes());
}

/// Keep `depth` messages in flight until the window ends.
async fn drive<T: Transport>(
    mut ws: WebSocket<T>,
    args: &Args,
    window: Window,
    stats: &RefCell<Stats>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(args.size);
    for _ in 0..args.depth {
        buf.resize(args.size, 0xA5);
        stamp(&mut buf, &window);
        let (sent, back) = ws.send_binary(buf).await;
        sent?;
        buf = back;
    }
    while let Some(message) = ws.next().await {
        let Message::Binary(mut data) = message? else {
            continue;
        };
        let now = window.start.elapsed();
        if now >= window.end {
            break;
        }
        let sent = Duration::from_nanos(u64::from_le_bytes(data[..8].try_into().unwrap()));
        if sent >= window.warm {
            stats
                .borrow_mut()
                .latency
                .record((now - sent).as_nanos() as u64);
        }
        stamp(&mut data, &window);
        ws.send_binary(data).await.0?;
    }
    Ok(())
}

// Lives only between opening a connection and spawning its task.
#[allow(clippy::large_enum_variant)]
enum Conn {
    Plain(WebSocket<popple_ws::Plain<Ring>>),
    Tls(WebSocket<popple_ws::Tls<Ring, rustls::client::ClientConnectionData>>),
}

async fn open(args: &Args) -> Result<Conn, popple_ws::HandshakeError> {
    if args.tls {
        let tls = client_config_dangerous_no_verification(None).expect("client config");
        let name = ServerName::try_from("localhost").unwrap();
        let (ws, _) = connect_tls::<Ring>(args.addr, name, tls, "/", CONFIG).await?;
        Ok(Conn::Tls(ws))
    } else {
        let (ws, _) = connect::<Ring>(args.addr, "localhost", "/", CONFIG).await?;
        Ok(Conn::Plain(ws))
    }
}

async fn run<T: Transport>(
    ws: WebSocket<T>,
    args: Rc<Args>,
    window: Window,
    stats: Rc<RefCell<Stats>>,
) {
    if let Err(e) = drive(ws, &args, window, &stats).await {
        failed(&stats, &e);
    }
}

fn failed(stats: &RefCell<Stats>, e: &dyn std::fmt::Display) {
    let mut stats = stats.borrow_mut();
    if stats.errors == 0 {
        eprintln!("connection error: {e}");
    }
    stats.errors += 1;
}

fn main() {
    let args = parse_args();
    if args.tls {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let window = Window {
        start: Instant::now(),
        warm: Duration::from_secs(args.warmup),
        end: Duration::from_secs(args.warmup + args.secs),
    };
    let results: Arc<Mutex<Vec<Stats>>> = Arc::default();
    let shared = (args.clone(), results.clone());

    runtime::thread_per_core_with::<Ring, _>(move |worker| {
        let (args, results) = shared.clone();
        Box::pin(async move {
            // Connections are dealt round-robin over the workers.
            let mine = (worker.thread_id..args.conns)
                .step_by(worker.num_threads)
                .count();
            let args = Rc::new(args);
            let stats = Rc::new(RefCell::new(Stats::new()));
            // One connection at a time per worker: opening them all at once
            // would overflow the server's accept queue, and measure that.
            let mut tasks = Vec::with_capacity(mine);
            for _ in 0..mine {
                let (args, stats) = (args.clone(), stats.clone());
                match open(&args).await {
                    Ok(Conn::Plain(ws)) => {
                        stats.borrow_mut().connected += 1;
                        tasks.push(spawn(run(ws, args, window, stats)));
                    }
                    Ok(Conn::Tls(ws)) => {
                        stats.borrow_mut().connected += 1;
                        tasks.push(spawn(run(ws, args, window, stats)));
                    }
                    Err(e) => failed(&stats, &e),
                }
            }
            for task in tasks {
                task.await;
            }
            let stats = Rc::try_unwrap(stats).ok().expect("tasks done").into_inner();
            results.lock().unwrap().push(stats);
        })
    });

    let mut total = Stats::new();
    for stats in results.lock().unwrap().iter() {
        total.latency.merge(&stats.latency);
        total.errors += stats.errors;
        total.connected += stats.connected;
    }
    let secs = args.secs as f64;
    let rate = total.latency.count as f64 / secs;
    println!(
        "{} conns ({} up, {} errors), depth {}, {} B{}: {:.0} msg/s, {:.1} MiB/s each way",
        args.conns,
        total.connected,
        total.errors,
        args.depth,
        args.size,
        if args.tls { ", TLS" } else { "" },
        rate,
        rate * args.size as f64 / (1 << 20) as f64,
    );
    let h = &total.latency;
    println!(
        "latency: p50 {:?}  p99 {:?}  p99.9 {:?}  max {:?}",
        h.quantile(0.50),
        h.quantile(0.99),
        h.quantile(0.999),
        Duration::from_nanos(h.max),
    );
    // For bench/run.sh.
    println!(
        "RESULT msgs={} secs={secs} errors={} p50_us={:.0} p99_us={:.0} p999_us={:.0}",
        h.count,
        total.errors,
        h.quantile(0.50).as_secs_f64() * 1e6,
        h.quantile(0.99).as_secs_f64() * 1e6,
        h.quantile(0.999).as_secs_f64() * 1e6,
    );
}
