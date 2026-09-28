use std::cell::Cell;
use std::io;
use std::rc::Rc;
use std::time::Duration;

use runtime::channels::{
    BoundedReceiver, BoundedSender, Receiver, Sender, bounded_channel, unbounded_channel,
};
use runtime::runtime::select::{SelectResult3, select3};
use runtime::runtime::time::Sleep;
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::control::ControlBuf;
use crate::message::Message;
use crate::socket::WebSocket;
use crate::transport::Transport;

/// Queues outgoing messages for the connection task. Sending never waits;
/// a [`Message::Close`] starts the closing handshake. Dropping the sender
/// closes the connection with 1000 once what was queued is out.
pub struct WsSender {
    tx: Sender<Message>,
    shared: Rc<Shared>,
}

/// What the sender and the connection task both see.
struct Shared {
    done: Cell<bool>,
    /// Payload bytes queued and not yet sent.
    queued: Cell<usize>,
    budget: usize,
}

/// Why [`WsSender::send`] handed the message back.
#[derive(Debug)]
pub enum SendError {
    /// The connection is over.
    Closed(Message),
    /// `Config::max_outbound_bytes` are already queued: the peer is not
    /// reading. Retry later, or drop the connection.
    Full(Message),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Closed(_) => "websocket closed",
            Self::Full(_) => "websocket outbound queue full",
        })
    }
}

impl std::error::Error for SendError {}

impl WsSender {
    /// Queue a message, within the outbound budget.
    pub fn send(&self, message: Message) -> Result<(), SendError> {
        let shared = &self.shared;
        if shared.done.get() {
            return Err(SendError::Closed(message));
        }
        let queued = shared.queued.get() + message.payload_len();
        if queued > shared.budget {
            return Err(SendError::Full(message));
        }
        shared.queued.set(queued);
        self.tx.send(message);
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.shared.done.get()
    }

    /// Payload bytes waiting to go out.
    pub fn queued_bytes(&self) -> usize {
        self.shared.queued.get()
    }
}

/// Incoming messages, delivered by the connection task. Pings are already
/// answered by the time they show up here. Yields `None` after the close
/// handshake, or after the error that ended the connection.
pub struct WsReceiver {
    rx: BoundedReceiver<io::Result<Message>>,
}

impl WsReceiver {
    pub async fn recv(&self) -> Option<io::Result<Message>> {
        self.rx.recv().await
    }
}

impl<T: Transport + 'static> WebSocket<T> {
    /// Hand the connection to a task of its own and talk to it from anywhere
    /// on this thread: the task answers pings, pings a quiet peer every
    /// `Config::ping_interval`, completes the closing handshake, and
    /// interleaves reads and writes.
    ///
    /// At most `inbound_capacity` messages wait for the receiver; past that
    /// the task stops reading, and the multishot recv's own backpressure
    /// throttles the peer through TCP. Outgoing, at most
    /// `Config::max_outbound_bytes` wait for a peer that does not read.
    pub fn split(self, inbound_capacity: usize) -> (WsSender, WsReceiver) {
        let (out_tx, out_rx) = unbounded_channel();
        let (in_tx, in_rx) = bounded_channel(inbound_capacity.max(1));
        let shared = Rc::new(Shared {
            done: Cell::new(false),
            queued: Cell::new(0),
            budget: self.config().max_outbound_bytes,
        });
        spawn(drive(self, out_rx, in_tx, shared.clone()));
        (WsSender { tx: out_tx, shared }, WsReceiver { rx: in_rx })
    }
}

async fn drive<T: Transport>(
    mut ws: WebSocket<T>,
    outbound: Receiver<Message>,
    inbound: BoundedSender<io::Result<Message>>,
    shared: Rc<Shared>,
) {
    let result = pump(&mut ws, &outbound, &inbound, &shared).await;
    shared.done.set(true);
    if let Err(e) = result {
        // Best effort: the peer may be gone, and so may the receiver.
        let _ = ws.flush().await;
        let _ = inbound.send(Err(e)).await;
    }
    drop(outbound);
}

async fn pump<T: Transport>(
    ws: &mut WebSocket<T>,
    outbound: &Receiver<Message>,
    inbound: &BoundedSender<io::Result<Message>>,
    shared: &Shared,
) -> io::Result<()> {
    let ping_interval = ws.config().ping_interval;
    let mut keepalive = ping_interval.map(Sleep::during);
    let mut outbound_open = true;
    loop {
        // `next` is cancel-safe, so losing the race to the others costs nothing.
        let event = select3(
            ws.next(),
            async {
                match outbound_open {
                    true => outbound.recv_all().await,
                    false => std::future::pending().await,
                }
            },
            async {
                match keepalive.as_mut() {
                    Some(tick) => tick.await,
                    None => std::future::pending().await,
                }
            },
        )
        .await;
        match event {
            SelectResult3::First(Some(Ok(message))) => {
                // Pongs owed by what one read brought in leave together, once
                // its last message is out.
                if !ws.has_ready() {
                    ws.flush().await?;
                }
                if inbound.send(Ok(message)).await.is_err() {
                    // Nobody listens any more.
                    return ws.close(None).await;
                }
            }
            SelectResult3::First(Some(Err(e))) if e.kind() == io::ErrorKind::WouldBlock => {
                // The ring is drained by other holders on this thread.
                Sleep::during(Duration::from_millis(1)).await;
            }
            SelectResult3::First(Some(Err(e))) => return Err(e),
            SelectResult3::First(None) => return ws.flush().await,
            SelectResult3::Second(Some(messages)) => {
                // The whole batch in one write.
                for message in messages {
                    let size = message.payload_len();
                    let fed = ws.feed(message).await;
                    shared.queued.set(shared.queued.get() - size);
                    fed?;
                }
                ws.flush().await?;
            }
            SelectResult3::Second(None) => {
                outbound_open = false;
                ws.close(None).await?;
            }
            SelectResult3::Third(()) => {
                let interval = ping_interval.expect("ticks only with an interval");
                keepalive = Some(Sleep::during(interval));
                // Only a quiet peer is pinged; its pong resets the idle clock.
                if ws.idle_for() >= interval && !ws.is_closing() {
                    ws.send(Message::Ping(ControlBuf::new())).await?;
                }
            }
        }
    }
}
