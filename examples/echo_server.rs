//! Echo server, plain or TLS.
//!
//!   cargo run --example echo_server            # ws://127.0.0.1:9001
//!   cargo run --example echo_server -- --tls   # wss://127.0.0.1:9001, self-signed
//!
//! Try it with `wscat -c ws://127.0.0.1:9001` (add `-n` for wss).

use std::time::Duration;

use popple_tls::{ServerSettings, server_config};
use popple_ws::{Config, Message, Plain, Tls, Transport, Upgrade};
use rcgen::{CertificateParams, KeyPair};
use runtime::net::MultiAccept;
use runtime::spawn;
use runtime_streams::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 1024);

async fn serve<T: Transport + 'static>(transport: T) {
    // Autobahn's 9.* cases send up to 16 MiB: above the defaults, sized for
    // untrusted peers.
    let config = Config {
        max_frame_size: 16 << 20,
        max_message_size: 64 << 20,
        max_outbound_bytes: 64 << 20,
        ..Config::default()
    };
    let upgrade = match Upgrade::read(transport, config).await {
        Ok(upgrade) => upgrade,
        Err(e) => return eprintln!("upgrade: {e}"),
    };
    println!("upgrade to {}", upgrade.path());
    let Ok(ws) = upgrade.accept().await else {
        return;
    };
    let (tx, rx) = ws.split(32);
    while let Some(message) = rx.recv().await {
        match message {
            Ok(m @ (Message::Text(_) | Message::Binary(_))) => {
                let _ = tx.send(m);
            }
            Ok(Message::Close(frame)) => println!("closed by peer: {frame:?}"),
            Ok(_) => {}
            Err(e) => eprintln!("connection: {e}"),
        }
    }
}

fn main() {
    let tls = std::env::args().any(|a| a == "--tls").then(|| {
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
        "listening on {}://127.0.0.1:9001",
        if tls.is_some() { "wss" } else { "ws" }
    );

    runtime::main_thread_with::<Ring, _>(async move {
        let mut accept = MultiAccept::bind("127.0.0.1:9001".parse().unwrap()).expect("bind");
        while let Some(socket) = accept.next().await {
            let Ok(socket) = socket else { continue };
            match &tls {
                None => {
                    spawn(serve(Plain::<Ring>::new(socket)));
                }
                Some(cfg) => {
                    let cfg = cfg.clone();
                    spawn(async move {
                        match popple_tls::handshake(socket, cfg, Duration::from_secs(5)).await {
                            Ok(ktls) => serve(Tls::new(ktls.into_messages::<Ring>())).await,
                            Err(e) => eprintln!("TLS handshake: {e}"),
                        }
                    });
                }
            }
        }
    });
}
