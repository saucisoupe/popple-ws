//! Reference echo servers on tokio, for comparing popple-ws's bench_server
//! under the same load. Multi-threaded, one worker per core the process may
//! run on; TLS through tokio-rustls, in userspace.
//!
//!   cargo run --release -- --impl tungstenite|fastwebsockets [--port 9100] [--tls]

use std::sync::Arc;

use fastwebsockets::{FragmentCollector, OpCode, WebSocketError, upgrade};
use futures_util::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

#[derive(Clone, Copy)]
enum Impl {
    Tungstenite,
    FastWebSockets,
}

const MAX: usize = 16 << 20;

async fn tungstenite<S: AsyncRead + AsyncWrite + Unpin>(stream: S) {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX))
        .max_frame_size(Some(MAX));
    let Ok(mut ws) = tokio_tungstenite::accept_async_with_config(stream, Some(config)).await else {
        return;
    };
    while let Some(Ok(message)) = ws.next().await {
        if (message.is_binary() || message.is_text()) && ws.send(message).await.is_err() {
            return;
        }
    }
}

async fn fastwebsockets_echo(fut: upgrade::UpgradeFut) -> Result<(), WebSocketError> {
    let mut ws = fut.await?;
    ws.set_max_message_size(MAX);
    let mut ws = FragmentCollector::new(ws);
    loop {
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Close => return Ok(()),
            OpCode::Text | OpCode::Binary => ws.write_frame(frame).await?,
            _ => {}
        }
    }
}

async fn fastwebsockets_upgrade(
    mut req: Request<Incoming>,
) -> Result<Response<Empty<Bytes>>, WebSocketError> {
    let (response, fut) = upgrade::upgrade(&mut req)?;
    // As fastwebsockets' own echo server does.
    tokio::spawn(tokio::task::unconstrained(fastwebsockets_echo(fut)));
    Ok(response)
}

async fn fastwebsockets<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let _ = http1::Builder::new()
        .serve_connection(io, service_fn(fastwebsockets_upgrade))
        .with_upgrades()
        .await;
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(which: Impl, stream: S) {
    match which {
        Impl::Tungstenite => tungstenite(stream).await,
        Impl::FastWebSockets => fastwebsockets(stream).await,
    }
}

fn tls_acceptor() -> TlsAcceptor {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server config");
    TlsAcceptor::from(Arc::new(config))
}

#[tokio::main]
async fn main() {
    let mut which = None;
    let mut port = 9100;
    let mut tls = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--impl" => {
                which = match args.next().as_deref() {
                    Some("tungstenite") => Some(Impl::Tungstenite),
                    Some("fastwebsockets") => Some(Impl::FastWebSockets),
                    other => panic!("unknown --impl {other:?}"),
                }
            }
            "--port" => port = args.next().and_then(|p| p.parse().ok()).expect("--port N"),
            "--tls" => tls = true,
            other => panic!("unknown argument {other}"),
        }
    }
    let which = which.expect("--impl tungstenite|fastwebsockets");
    let acceptor = tls.then(tls_acceptor);
    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    println!("tokio-echo on 127.0.0.1:{port}");
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                None => serve(which, stream).await,
                Some(acceptor) => {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        serve(which, stream).await;
                    }
                }
            }
        });
    }
}
