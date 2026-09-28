//! Talk to a public echo server over the real network, with the server's
//! certificate verified against Mozilla's roots: popple-ws against someone
//! else's WebSocket and TLS stacks.
//!
//!   cargo run --example public_echo                          # wss://echo.websocket.org
//!   cargo run --example public_echo -- wss://ws.ifelse.io
//!
//! TLS is 1.3 only, as popple-tls is: a server that stops at TLS 1.2, such
//! as wss://ws.postman-echo.com/raw, closes the handshake.
//! Sends text, UTF-8 text, binary, 64 KiB, a ping, then closes, and checks
//! every echo. Messages that are not the awaited echo, such as a greeting,
//! are shown and skipped.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use popple_tls::{ClientSettings, ServerName, client_config};
use popple_ws::{CloseFrame, Config, Message, Transport, WebSocket, connect, connect_tls};
use runtime::runtime::time::timeout;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 256);

struct Url {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Url {
    let (tls, rest) = match url.split_once("://") {
        Some(("wss", rest)) => (true, rest),
        Some(("ws", rest)) => (false, rest),
        _ => panic!("expected ws:// or wss://, got {url}"),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().expect("port")),
        None => (authority, if tls { 443 } else { 80 }),
    };
    Url {
        tls,
        host: host.to_owned(),
        port,
        path: path.to_owned(),
    }
}

/// The server's address, IPv4 first: fewer surprises on hosts whose IPv6
/// route is missing.
fn resolve(url: &Url) -> SocketAddr {
    let addrs: Vec<SocketAddr> = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .expect("resolve")
        .collect();
    *addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .expect("no address")
}

/// Send `message` and wait for it to come back, skipping whatever else the
/// server sends meanwhile.
async fn echo<T: Transport>(ws: &mut WebSocket<T>, what: &str, message: Message) -> bool {
    let started = Instant::now();
    let expected = match &message {
        Message::Ping(payload) => Message::Pong(payload.clone()),
        other => other.clone(),
    };
    if let Err(e) = ws.send(message).await {
        println!("  {what:<22} send failed: {e}");
        return false;
    }
    loop {
        match timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(got))) if got == expected => {
                println!(
                    "  {what:<22} ok  {:>7.1} ms",
                    started.elapsed().as_secs_f64() * 1e3
                );
                return true;
            }
            Ok(Some(Ok(other))) => {
                println!("  {what:<22} (skipped {})", summary(&other));
                // A ping of theirs: answer it before going on waiting.
                let _ = ws.flush().await;
            }
            Ok(Some(Err(e))) => {
                println!("  {what:<22} failed: {e}");
                return false;
            }
            Ok(None) => {
                println!("  {what:<22} failed: connection ended");
                return false;
            }
            Err(()) => {
                println!("  {what:<22} failed: no echo within 10 s");
                return false;
            }
        }
    }
}

fn summary(message: &Message) -> String {
    match message {
        Message::Text(text) if text.len() <= 60 => format!("text {text:?}"),
        Message::Text(text) => format!("text of {} bytes", text.len()),
        Message::Binary(data) => format!("binary of {} bytes", data.len()),
        Message::Ping(_) => "ping".into(),
        Message::Pong(_) => "pong".into(),
        Message::Close(frame) => format!("close {frame:?}"),
    }
}

async fn exercise<T: Transport>(mut ws: WebSocket<T>) -> bool {
    let big: Vec<u8> = (0..64 << 10).map(|i: u32| (i * 7) as u8).collect();
    let mut ok = true;
    ok &= echo(&mut ws, "text", Message::text("hello from popple-ws")).await;
    ok &= echo(&mut ws, "UTF-8 text", Message::text("héllo wörld ✓ 🦀")).await;
    ok &= echo(&mut ws, "binary", Message::binary(vec![0, 1, 2, 254, 255])).await;
    ok &= echo(&mut ws, "binary, 64 KiB", Message::Binary(big)).await;
    ok &= echo(&mut ws, "ping", Message::ping(b"are you there").unwrap()).await;

    let started = Instant::now();
    let bye = CloseFrame {
        code: 1000,
        reason: "done".into(),
    };
    if let Err(e) = ws.close(Some(bye)).await {
        println!("  {:<22} failed: {e}", "close");
        return false;
    }
    // Their close frame, after whatever they still had in flight.
    loop {
        match timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(Message::Close(frame)))) => {
                let ms = started.elapsed().as_secs_f64() * 1e3;
                println!("  {:<22} ok  {ms:>7.1} ms  {frame:?}", "close");
                return ok;
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => println!("  {:<22} ended with: {e}", "close"),
            Ok(None) => println!("  {:<22} ended without a close frame", "close"),
            Err(()) => println!("  {:<22} no close frame within 10 s", "close"),
        }
        return false;
    }
}

fn main() {
    let arg = std::env::args().nth(1);
    let url = parse(arg.as_deref().unwrap_or("wss://echo.websocket.org"));
    let addr = resolve(&url);
    println!(
        "{}://{}{} at {addr}",
        if url.tls { "wss" } else { "ws" },
        url.host,
        url.path
    );

    let ok = runtime::main_thread_with::<Ring, _>(async move {
        let started = Instant::now();
        if url.tls {
            if !popple_tls::ktls_available() {
                eprintln!("kTLS is not available here: sudo modprobe tls");
                return false;
            }
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = client_config(ClientSettings {
                roots,
                // Offered alone, so a CDN in front does not pick HTTP/2.
                alpn_protocols: Some(&[b"http/1.1"]),
            })
            .expect("client config");
            let name = ServerName::try_from(url.host.clone()).expect("server name");
            match connect_tls::<Ring>(addr, name, tls, &url.path, Config::default()).await {
                Ok((ws, response)) => {
                    let ms = started.elapsed().as_secs_f64() * 1e3;
                    println!("  {:<22} ok  {ms:>7.1} ms  (TLS 1.3 via kTLS)", "connect");
                    if let Some(server) = response.header("server") {
                        println!("  {:<22} {server}", "server");
                    }
                    exercise(ws).await
                }
                Err(e) => {
                    println!("  connect failed: {e}");
                    false
                }
            }
        } else {
            match connect::<Ring>(addr, &url.host, &url.path, Config::default()).await {
                Ok((ws, _)) => {
                    let ms = started.elapsed().as_secs_f64() * 1e3;
                    println!("  {:<22} ok  {ms:>7.1} ms", "connect");
                    exercise(ws).await
                }
                Err(e) => {
                    println!("  connect failed: {e}");
                    false
                }
            }
        }
    });
    println!("{}", if ok { "all echoes ok" } else { "FAILED" });
    std::process::exit(if ok { 0 } else { 1 });
}
