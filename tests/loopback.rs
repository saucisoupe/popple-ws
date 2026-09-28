use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use popple_tls::{
    ServerName, ServerSettings, client_config_dangerous_no_verification, server_config,
};
use popple_ws::{
    CloseFrame, Config, HandshakeError, Message, Plain, SendError, Shutdown, Tls, Transport,
    TransportRead, TransportWrite, Upgrade, WebSocket, connect, connect_tls,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::net::{BufRingSpec, MultiAccept};
use runtime::runtime::time::{Sleep, timeout};
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
        let (mut client_rx, mut client) = Plain::<Ring>::new(socket).into_split();
        client
            .send(&b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..])
            .await
            .0
            .unwrap();
        let reply = std::future::poll_fn(|cx| client_rx.poll_recv(cx))
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
        let (_client_rx, mut client) = Plain::<Ring>::new(socket).into_split();
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
            let (mut transport_rx, mut transport) = Plain::<Ring>::new(socket).into_split();
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let chunk = std::future::poll_fn(|cx| transport_rx.poll_recv(cx))
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

/// Accept one upgrade by hand, answering with `extra` headers in the 101.
async fn bare_upgrade(
    accept: &mut MultiAccept,
    extra: &str,
) -> (impl TransportRead, impl TransportWrite) {
    let socket = accept.next().await.unwrap().unwrap();
    let (mut transport_rx, mut transport) = Plain::<Ring>::new(socket).into_split();
    let mut request = Vec::new();
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let chunk = std::future::poll_fn(|cx| transport_rx.poll_recv(cx))
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
         Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{extra}\r\n",
        popple_ws::handshake::accept_key(key)
    );
    transport.send(response.into_bytes()).await.0.unwrap();
    (transport_rx, transport)
}

fn quiet(idle: Duration, ping: Option<Duration>) -> Config {
    Config {
        idle_timeout: Some(idle),
        ping_interval: ping,
        ..Config::default()
    }
}

/// A silent peer is dropped after `idle_timeout`, and told why (1001).
#[test]
fn silent_peer_times_out() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let config = quiet(Duration::from_millis(300), None);
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), config)
                .await
                .unwrap();
            let (_tx, rx) = upgrade.accept().await.unwrap().split(8);
            let started = Instant::now();
            let error = rx.recv().await.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            started.elapsed()
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        match ws.next().await.unwrap().unwrap() {
            Message::Close(Some(frame)) => assert_eq!(frame.code, 1001),
            other => panic!("expected close 1001, got {other:?}"),
        }
        let elapsed = server.await;
        assert!(
            (Duration::from_millis(280)..Duration::from_secs(1)).contains(&elapsed),
            "{elapsed:?}"
        );
    });
}

/// With `split`, a quiet but live peer is pinged and kept past `idle_timeout`.
#[test]
fn keepalive_pings_hold_a_quiet_peer() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let config = quiet(Duration::from_millis(500), Some(Duration::from_millis(100)));
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), config)
                .await
                .unwrap();
            let (_tx, rx) = upgrade.accept().await.unwrap().split(8);
            // Ends on the client's close, not on a timeout.
            while let Some(message) = rx.recv().await {
                message.unwrap();
            }
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        let started = Instant::now();
        let mut pings = 0;
        // Sends nothing but pongs, for over twice the server's idle timeout.
        while started.elapsed() < Duration::from_millis(1200) {
            match timeout(Duration::from_millis(100), ws.next()).await {
                Ok(Some(Ok(Message::Ping(_)))) => {
                    pings += 1;
                    ws.flush().await.unwrap();
                }
                Ok(other) => panic!("{other:?}"),
                Err(()) => {}
            }
        }
        assert!(pings >= 3, "{pings} pings");
        ws.close(None).await.unwrap();
        // A keepalive ping may still be in flight ahead of the close reply.
        loop {
            match ws.next().await {
                Some(Ok(Message::Ping(_))) => continue,
                Some(Ok(Message::Close(_))) => break,
                other => panic!("expected the close reply, got {other:?}"),
            }
        }
        server.await;
    });
}

/// A peer that never answers our close frame is dropped after `close_timeout`.
#[test]
fn unanswered_close_times_out() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            // Upgrades, then never reads: our close frame gets no answer.
            let _transport = bare_upgrade(&mut accept, "").await;
            Sleep::during(Duration::from_secs(1)).await;
        });

        let config = Config {
            close_timeout: Duration::from_millis(200),
            ..Config::default()
        };
        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", config)
            .await
            .unwrap();
        ws.close(None).await.unwrap();
        let started = Instant::now();
        let error = ws.next().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_millis(180)..Duration::from_millis(900)).contains(&elapsed),
            "{elapsed:?}"
        );
        server.await;
    });
}

/// `split` refuses to queue past `max_outbound_bytes`.
#[test]
fn outbound_budget_is_enforced() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let config = Config {
                max_outbound_bytes: 1000,
                ..Config::default()
            };
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), config)
                .await
                .unwrap();
            let (tx, rx) = upgrade.accept().await.unwrap().split(8);
            // The driver has not run yet: both messages would sit in the queue.
            tx.send(Message::Binary(vec![1; 600])).unwrap();
            match tx.send(Message::Binary(vec![2; 600])) {
                Err(SendError::Full(Message::Binary(back))) => assert_eq!(back.len(), 600),
                other => panic!("expected Full, got {other:?}"),
            }
            assert_eq!(tx.queued_bytes(), 600);
            drop(tx);
            while rx.recv().await.is_some() {}
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::Binary(vec![1; 600])
        );
        assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));
        // Reading only queues the close reply; without this flush the
        // server would wait out its close timeout.
        ws.flush().await.unwrap();
        server.await;
    });
}

/// A server may only name a subprotocol the client offered.
#[test]
fn subprotocol_must_be_offered() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), Config::default())
                .await
                .unwrap();
            assert!(matches!(
                upgrade.accept_with_protocol(Some("chat")).await,
                Err(HandshakeError::Invalid(_))
            ));
        });
        assert!(
            connect::<Ring>(addr, "localhost", "/", Config::default())
                .await
                .is_err()
        );
        server.await;
    });
}

/// The client refuses a server enabling an extension it never offered.
#[test]
fn client_refuses_unoffered_extension() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let _transport = bare_upgrade(
                &mut accept,
                "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            )
            .await;
            Sleep::during(Duration::from_millis(200)).await;
        });
        let result = connect::<Ring>(addr, "localhost", "/", Config::default()).await;
        assert!(matches!(result, Err(HandshakeError::Invalid(_))));
        server.await;
    });
}

/// Serve one connection the way a graceful server does: tracked from the
/// accept, watched once upgraded, split, echoing until the end.
async fn serve_watched(accept: &mut MultiAccept, shutdown: Shutdown, config: Config) {
    let socket = accept.next().await.unwrap().unwrap();
    let _alive = shutdown.track();
    let upgrade = Upgrade::read(Plain::<Ring>::new(socket), config)
        .await
        .unwrap();
    let mut ws = upgrade.accept().await.unwrap();
    ws.watch(&shutdown);
    let (tx, rx) = ws.split(8);
    while let Some(Ok(message)) = rx.recv().await {
        if matches!(message, Message::Text(_) | Message::Binary(_)) {
            // Refused once the shutdown began: nothing may follow our close.
            let _ = tx.send(message);
        }
    }
}

/// On shutdown, a watched connection is told to go away (1001), and the
/// worker is drained as soon as the peer answers.
#[test]
fn shutdown_closes_with_1001_and_drains() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let shutdown = Shutdown::new();
        let server = spawn({
            let shutdown = shutdown.clone();
            async move { serve_watched(&mut accept, shutdown, Config::default()).await }
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        ws.send(Message::text("before")).await.unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("before"));

        shutdown.trigger();
        match ws.next().await.unwrap().unwrap() {
            Message::Close(Some(frame)) => assert_eq!(frame.code, 1001),
            other => panic!("expected close 1001, got {other:?}"),
        }
        ws.flush().await.unwrap(); // our close reply
        assert!(ws.next().await.is_none());

        let started = Instant::now();
        timeout(Duration::from_secs(2), shutdown.drained())
            .await
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(shutdown.live(), 0);
        server.await;
    });
}

/// A peer that never answers the 1001 does not hold the shutdown past
/// `close_timeout`.
#[test]
fn shutdown_does_not_wait_past_close_timeout() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let shutdown = Shutdown::new();
        let config = Config {
            close_timeout: Duration::from_millis(300),
            ..Config::default()
        };
        let server = spawn({
            let shutdown = shutdown.clone();
            async move { serve_watched(&mut accept, shutdown, config).await }
        });

        let (mut ws, _) = connect::<Ring>(addr, "localhost", "/", Config::default())
            .await
            .unwrap();
        // The server is upgraded once it echoes.
        ws.send(Message::text("ready?")).await.unwrap();
        ws.next().await.unwrap().unwrap();
        shutdown.trigger();
        // Reads the close, but never flushes the reply.
        assert!(matches!(ws.next().await, Some(Ok(Message::Close(_)))));

        let started = Instant::now();
        timeout(Duration::from_secs(3), shutdown.drained())
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_millis(250)..Duration::from_secs(1)).contains(&elapsed),
            "{elapsed:?}"
        );
        server.await;
    });
}

/// Large enough to fill both sides' socket buffers, and block a write.
const JAM: usize = 16 << 20;

fn jam_config() -> Config {
    Config {
        max_frame_size: 32 << 20,
        max_message_size: 32 << 20,
        max_outbound_bytes: 64 << 20,
        ..Config::default()
    }
}

/// The server echoes a message too large for the client, who does not read,
/// to take: its write stays stuck. It must still read what comes next.
async fn reads_while_writing<T: Transport + 'static>(ws: WebSocket<T>) {
    let (tx, rx) = ws.split(8);
    let jam = rx.recv().await.unwrap().unwrap();
    assert_eq!(jam.payload_len(), JAM);
    // Not `unwrap`: its error holds the 16 MiB message.
    assert!(tx.send(jam).is_ok(), "connection over before the echo");
    // With reads and writes taking turns, this would wait on the echo.
    let next = timeout(Duration::from_secs(2), rx.recv()).await;
    let next = next.expect("no read while the write was stuck");
    assert_eq!(next.unwrap().unwrap(), Message::text("still there?"));
}

/// Returns the socket, to keep it open until the server is done.
async fn jam_then_talk<T: Transport>(mut ws: WebSocket<T>) -> WebSocket<T> {
    ws.send(Message::Binary(vec![7; JAM])).await.unwrap();
    // Never read: the echo fills our buffers, then the server's.
    ws.send(Message::text("still there?")).await.unwrap();
    ws
}

#[test]
fn reads_go_on_while_a_write_is_stuck() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), jam_config()).await;
            reads_while_writing(upgrade.unwrap().accept().await.unwrap()).await;
        });
        let (ws, _) = connect::<Ring>(addr, "localhost", "/", jam_config())
            .await
            .unwrap();
        let _open = jam_then_talk(ws).await;
        server.await;
    });
}

#[test]
fn tls_reads_go_on_while_a_write_is_stuck() {
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
            let deadline = Duration::from_secs(5);
            let ktls = popple_tls::handshake(socket, server_tls, deadline)
                .await
                .unwrap();
            let transport = Tls::new(ktls.into_messages::<Ring>());
            let upgrade = Upgrade::read(transport, jam_config()).await.unwrap();
            reads_while_writing(upgrade.accept().await.unwrap()).await;
        });
        let name = ServerName::try_from("localhost").unwrap();
        let (ws, _) = connect_tls::<Ring>(addr, name, client_tls, "/", jam_config())
            .await
            .unwrap();
        let _open = jam_then_talk(ws).await;
        server.await;
    });
}

/// A peer that stops reading does not hold the connection past
/// `write_timeout`.
#[test]
fn a_peer_that_does_not_read_times_out() {
    runtime::main_thread_with::<Ring, _>(async {
        let (mut accept, addr) = listener();
        let server = spawn(async move {
            let socket = accept.next().await.unwrap().unwrap();
            let config = Config {
                write_timeout: Duration::from_millis(300),
                ..jam_config()
            };
            let upgrade = Upgrade::read(Plain::<Ring>::new(socket), config).await;
            let (tx, rx) = upgrade.unwrap().accept().await.unwrap().split(8);
            let started = Instant::now();
            tx.send(Message::Binary(vec![1; JAM])).unwrap();
            let error = rx.recv().await.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            started.elapsed()
        });
        // Connects, then never reads.
        let (_ws, _) = connect::<Ring>(addr, "localhost", "/", jam_config())
            .await
            .unwrap();
        let elapsed = server.await;
        assert!(
            (Duration::from_millis(280)..Duration::from_secs(2)).contains(&elapsed),
            "{elapsed:?}"
        );
    });
}

#[test]
fn config_rejects_ping_slower_than_idle() {
    let config = quiet(Duration::from_secs(10), Some(Duration::from_secs(10)));
    assert!(config.validate().is_err());
    assert!(Config::default().validate().is_ok());
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
