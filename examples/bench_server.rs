//! Echo server for load tests: one worker per core the process may run on,
//! each accepting on the same port (`SO_REUSEPORT`), driving its sockets
//! directly. Pin it with `taskset` to leave cores to the load client.
//!
//!   cargo run --release --example bench_server -- [--port 9100] [--tls]

use std::time::Duration;

use popple_tls::{ServerSettings, server_config};
use popple_ws::{Config, Message, Transport, Upgrade, WebSocket};
use rcgen::{CertificateParams, KeyPair};
use runtime::net::MultiAccept;
use runtime::spawn;
use runtime_streams::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 4096);

/// Load tests send what they like, and keep connections open as long as
/// they like: no limit should get in the way of the measure.
const CONFIG: Config = Config {
    max_frame_size: 16 << 20,
    max_message_size: 16 << 20,
    handshake_timeout: Duration::from_secs(30),
    idle_timeout: None,
    ping_interval: None,
    close_timeout: Duration::from_secs(5),
    max_outbound_bytes: 16 << 20,
    allowed_origins: &[],
};

async fn echo<T: Transport>(transport: T) {
    let Ok(upgrade) = Upgrade::read(transport, CONFIG).await else {
        return;
    };
    let Ok(mut ws): Result<WebSocket<T>, _> = upgrade.accept().await else {
        return;
    };
    while let Some(Ok(message)) = ws.next().await {
        if let Message::Binary(_) | Message::Text(_) = message
            && ws.feed(message).await.is_err()
        {
            return;
        }
        // Everything one read brought in goes back in one write.
        if !ws.has_ready() && ws.flush().await.is_err() {
            return;
        }
    }
    let _ = ws.flush().await;
}

fn main() {
    let mut port = 9100;
    let mut tls = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = args.next().and_then(|p| p.parse().ok()).expect("--port N"),
            "--tls" => tls = true,
            other => panic!("unknown argument {other}"),
        }
    }
    let tls = tls.then(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        server_config(ServerSettings {
            certs: vec![CertificateDer::from(cert.der().to_vec())],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            alpn_protocols: None,
        })
        .expect("server config")
    });
    println!(
        "bench_server on {}://127.0.0.1:{port}",
        if tls.is_some() { "wss" } else { "ws" }
    );

    runtime::thread_per_core_with::<Ring, _>(move |_worker| {
        let tls = tls.clone();
        Box::pin(async move {
            let addr = ([127, 0, 0, 1], port).into();
            let mut accept = MultiAccept::bind(addr).expect("bind");
            while let Some(socket) = accept.next().await {
                let Ok(socket) = socket else { continue };
                match &tls {
                    None => {
                        spawn(echo(popple_ws::Plain::<Ring>::new(socket)));
                    }
                    Some(cfg) => {
                        let cfg = cfg.clone();
                        spawn(async move {
                            let deadline = Duration::from_secs(30);
                            if let Ok(ktls) = popple_tls::handshake(socket, cfg, deadline).await {
                                echo(popple_ws::Tls::new(ktls.into_messages::<Ring>())).await;
                            }
                        });
                    }
                }
            }
        })
    });
}
