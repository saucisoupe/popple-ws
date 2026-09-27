use std::net::SocketAddr;
use std::time::Duration;

use popple_tls::{
    ServerName, ServerSettings, client_config_dangerous_no_verification, server_config,
};
use popple_ws::{
    CloseFrame, Config, HandshakeError, Message, Plain, Tls, Transport, Upgrade, WebSocket,
    connect, connect_tls,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::net::{BufRingSpec, MultiAccept};
use runtime::runtime::time::Sleep;
use runtime::spawn;
use runtime_streams::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

// Small buffers, so large messages span many recv completions.
runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 4096, ring_size = 256);

/// Echo data messages back through the split halves until the peer closes.
async fn echo<T: Transport + 'static>(ws: WebSocket<T>) {
    let (tx, rx) = ws.split(8);
    while let Some(Ok(message)) = rx.recv().await {
        if matches!(message, Message::Text(_) | Message::Binary(_)) {
            tx.send(message).unwrap();
        }
    }
}

/// Echo, ping, then close, driving the client socket directly.
async fn exercise<T: Transport>(mut ws: WebSocket<T>) {
    ws.send(Message::text("hello")).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("hello"));

    // Over the inline threshold and many ring buffers long.
    let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    ws.send(Message::Binary(big.clone())).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::Binary(big));

    ws.send(Message::ping(b"are you there").unwrap())
        .await
        .unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::pong(b"are you there").unwrap()
    );

    let bye = CloseFrame {
        code: 1000,
        reason: "bye".into(),
    };
    ws.close(Some(bye)).await.unwrap();
    match ws.next().await.unwrap().unwrap() {
        Message::Close(Some(frame)) => assert_eq!(frame.code, 1000),
        other => panic!("expected close, got {other:?}"),
    }
    assert!(ws.next().await.is_none());
    assert!(ws.is_closed());
}

fn listener() -> (MultiAccept, SocketAddr) {
    let accept = MultiAccept::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = accept.local_addr().unwrap();
    (accept, addr)
}

#[test]
fn plain_echo() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), Config::default())
                .await
                .unwrap();
            assert_eq!(upgrade.path(), "/echo");
            echo(upgrade.accept().await.unwrap()).await;
        });

        let (ws, _) = connect::<Ring>(addr, "localhost", "/echo", Config::default())
            .await
            .unwrap();
        exercise(ws).await;
        server.await;
    });
}

#[test]
fn tls_echo() {
    if !popple_tls::ktls_available() {
        eprintln!("kTLS unavailable (modprobe tls); skipping");
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (cert, key) = self_signed();
    let server_tls = server_config(ServerSettings {
        certs: vec![cert],
        key,
        alpn_protocols: None,
    })
    .unwrap();
    let client_tls = client_config_dangerous_no_verification(None).unwrap();

    runtime::main_thread_with::<Ring, _>(async move {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let ktls = popple_tls::handshake(socket, server_tls, Duration::from_secs(5))
                .await
                .unwrap();
            let transport = Tls::new(ktls.into_messages::<Ring>());
            let upgrade = Upgrade::read(transport, Config::default()).await.unwrap();
            echo(upgrade.accept().await.unwrap()).await;
        });

        let name = ServerName::try_from("localhost").unwrap();
        let (ws, _) = connect_tls::<Ring>(addr, name, client_tls, "/", Config::default())
            .await
            .unwrap();
        exercise(ws).await;
        server.await;
    });
}

#[test]
fn rejects_plain_http() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            assert!(
                Upgrade::read(Plain::<Ring>::new(socket), Config::default())
                    .await
                    .is_err()
            );
        });

        let socket = runtime::net::connect_tcp(addr).await.unwrap();
        let mut client = Plain::<Ring>::new(socket);
        client
            .send(&b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..])
            .await
            .0
            .unwrap();
        let reply = std::future::poll_fn(|cx| client.poll_recv(cx))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.as_ref().starts_with(b"HTTP/1.1 400"));
        server.await;
    });
}

/// A client dripping a byte every 50 ms never trips a per-read timeout; the
/// single deadline over the whole upgrade must still cut it off.
#[test]
fn upgrade_deadline_stops_slowloris() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let config = Config {
                handshake_timeout: Duration::from_millis(300),
                ..Config::default()
            };
            let started = std::time::Instant::now();
            let result = Upgrade::read(Plain::<Ring>::new(socket), config).await;
            assert!(matches!(result, Err(HandshakeError::Timeout)));
            started.elapsed()
        });

        let socket = runtime::net::connect_tcp(addr).await.unwrap();
        let mut client = Plain::<Ring>::new(socket);
        // Stops on its own once the server has dropped the connection.
        for byte in b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: "
            .iter()
            .cycle()
            .take(60)
        {
            if client.send(vec![*byte]).await.0.is_err() {
                break;
            }
            Sleep::during(Duration::from_millis(50)).await;
        }
        let elapsed = server.await;
        assert!(
            elapsed >= Duration::from_millis(280) && elapsed < Duration::from_secs(1),
            "timed out after {elapsed:?}"
        );
    });
}

/// The server refuses a frame over its limit and tells the client why.
#[test]
fn oversized_frame_is_closed_with_1009() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let config = Config {
                max_frame_size: 1024,
                ..Config::default()
            };
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), config)
                .await
                .unwrap();
            echo(upgrade.accept().await.unwrap()).await;
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        ws.send(Message::Binary(vec![0; 1024])).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::Binary(vec![0; 1024])
        );
        ws.send(Message::Binary(vec![0; 1025])).await.unwrap();
        match ws.next().await.unwrap().unwrap() {
            Message::Close(Some(frame)) => assert_eq!(frame.code, 1009),
            other => panic!("expected close 1009, got {other:?}"),
        }
        server.await;
    });
}

/// Three frames in one ring buffer: the buffer must be back with the kernel
/// before the first message is handed out, not held until the last one.
#[test]
fn ring_buffer_released_before_message_is_returned() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            // A bare server, to control exactly how bytes hit the wire.
            let socket = accept.next().await.unwrap().unwrap();
            let mut transport = Plain::<Ring>::new(socket);
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let chunk = std::future::poll_fn(|cx| transport.poll_recv(cx))
                    .await
                    .unwrap()
                    .unwrap();
                request.extend_from_slice(chunk.as_ref());
            }
            let request = String::from_utf8(request).unwrap();
            let key = request
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap();
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                popple_ws::handshake::accept_key(key)
            );
            transport.send(response.into_bytes()).await.0.unwrap();
            // Apart from the response, so the frames are not upgrade leftover.
            Sleep::during(Duration::from_millis(50)).await;
            let frames = [b"a", b"b", b"c"]
                .iter()
                .flat_map(|p| [0x81, 0x01, p[0]])
                .collect::<Vec<u8>>();
            transport.send(frames).await.0.unwrap();
            Sleep::during(Duration::from_millis(200)).await;
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("a"));
        assert_eq!(Ring::usage().in_flight, 0, "ring buffer still borrowed");
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("b"));
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("c"));
        server.await;
    });
}

#[test]
fn out_of_range_timeout_is_an_error_not_a_panic() {
    let config = Config {
        handshake_timeout: Duration::from_secs(2 * 60 * 60),
        ..Config::default()
    };
    assert!(config.validate().is_err());
    runtime::main_thread_with::<Ring, _>(async move {
        let (_accept, addr) = listener();
        let result = connect::<Ring>(addr, "localhost", "/", config).await;
        assert!(matches!(result, Err(HandshakeError::Config(_))));
    });
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}
