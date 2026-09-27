use std::cell::Cell;
use std::io;
use std::rc::Rc;
use std::time::Duration;

use runtime::channels::{
    BoundedReceiver, BoundedSender, Receiver, Sender, bounded_channel, unbounded_channel,
};
use runtime::runtime::select::{SelectResult, select};
use runtime::runtime::time::Sleep;
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::message::Message;
use crate::socket::WebSocket;
use crate::transport::Transport;

/// Queues outgoing messages for the connection task. Sending never waits;
/// a [`Message::Close`] starts the closing handshake. Dropping the sender
/// closes the connection with 1000 once what was queued is out.
pub struct WsSender {
    tx: Sender<Message>,
    done: Rc<Cell<bool>>,
}

impl WsSender {
    /// Queue a message. Hands it back if the connection is already over.
    pub fn send(&self, message: Message) -> Result<(), Message> {
        if self.done.get() {
            return Err(message);
        }
        self.tx.send(message);
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.done.get()
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
    /// on this thread: the task answers pings, completes the closing
    /// handshake, and interleaves reads and writes.
    ///
    /// At most `inbound_capacity` messages wait for the receiver; past that
    /// the task stops reading, and the multishot recv's own backpressure
    /// throttles the peer through TCP.
    pub fn split(self, inbound_capacity: usize) -> (WsSender, WsReceiver) {
        let (out_tx, out_rx) = unbounded_channel();
        let (in_tx, in_rx) = bounded_channel(inbound_capacity.max(1));
        let done = Rc::new(Cell::new(false));
        spawn(drive(self, out_rx, in_tx, done.clone()));
        (WsSender { tx: out_tx, done }, WsReceiver { rx: in_rx })
    }
}

async fn drive<T: Transport>(
    mut ws: WebSocket<T>,
    outbound: Receiver<Message>,
    inbound: BoundedSender<io::Result<Message>>,
    done: Rc<Cell<bool>>,
) {
    let result = pump(&mut ws, &outbound, &inbound).await;
    done.set(true);
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
) -> io::Result<()> {
    let mut outbound_open = true;
    loop {
        // `next` is cancel-safe, so losing the race to outbound costs nothing.
        let event = if outbound_open {
            select(ws.next(), outbound.recv_all()).await
        } else {
            SelectResult::First(ws.next().await)
        };
        match event {
            SelectResult::First(Some(Ok(message))) => {
                ws.flush().await?;
                if inbound.send(Ok(message)).await.is_err() {
                    // Nobody listens any more.
                    return ws.close(None).await;
                }
            }
            SelectResult::First(Some(Err(e))) if e.kind() == io::ErrorKind::WouldBlock => {
                // The ring is drained by other holders on this thread.
                Sleep::during(Duration::from_millis(1)).await;
            }
            SelectResult::First(Some(Err(e))) => return Err(e),
            SelectResult::First(None) => return ws.flush().await,
            SelectResult::Second(Some(messages)) => {
                for message in messages {
                    ws.send(message).await?;
                }
            }
            SelectResult::Second(None) => {
                outbound_open = false;
                ws.close(None).await?;
            }
        }
    }
}
