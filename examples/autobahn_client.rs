//! Client side of the Autobahn conformance suite: plays every case the
//! fuzzing server offers, echoing what it receives. Driven by
//! `autobahn/run.sh client`, which starts the server on 127.0.0.1:9002.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use popple_ws::{Config, Message, Plain, WebSocket, connect};
use runtime::runtime::time::Sleep;
use runtime_streams::StreamExt;

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 16384, ring_size = 1024);

const AGENT: &str = "popple-ws";
const HOST: &str = "127.0.0.1:9002";

async fn open(path: &str) -> io::Result<WebSocket<Plain<Ring>>> {
    let addr: SocketAddr = HOST.parse().unwrap();
    // Autobahn's 9.* cases send up to 16 MiB: above the defaults.
    let config = Config {
        max_frame_size: 16 << 20,
        max_message_size: 64 << 20,
        ..Config::default()
    };
    connect::<Ring>(addr, HOST, path, config)
        .await
        .map(|(ws, _)| ws)
        .map_err(io::Error::other)
}

/// Echo data messages until the connection ends, answering pings and the
/// close as they come: the WebSocket driven by hand, no `split`.
async fn echo(mut ws: WebSocket<Plain<Ring>>) {
    while let Some(message) = ws.next().await {
        match message {
            Ok(m @ (Message::Text(_) | Message::Binary(_))) => {
                if ws.send(m).await.is_err() {
                    return;
                }
            }
            // Pongs and the close reply are queued by reading; send them now.
            Ok(_) => {
                if ws.flush().await.is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Sleep::during(Duration::from_millis(1)).await;
            }
            Err(_) => {
                // A protocol error queued its close frame: send it, then stop.
                let _ = ws.flush().await;
                return;
            }
        }
    }
}

fn main() {
    runtime::main_thread_with::<Ring, _>(async {
        let mut ws = open("/getCaseCount").await.expect("fuzzing server on 9002");
        let count: u32 = match ws.next().await {
            Some(Ok(Message::Text(n))) => n.parse().expect("case count"),
            other => panic!("expected the case count, got {other:?}"),
        };
        let _ = ws.close(None).await;
        println!("running {count} cases");

        for case in 1..=count {
            match open(&format!("/runCase?case={case}&agent={AGENT}")).await {
                Ok(ws) => echo(ws).await,
                Err(e) => eprintln!("case {case}: {e}"),
            }
        }

        let mut ws = open(&format!("/updateReports?agent={AGENT}"))
            .await
            .expect("update reports");
        let _ = ws.close(None).await;
        while ws.next().await.is_some() {}
        println!("reports written");
    });
}
