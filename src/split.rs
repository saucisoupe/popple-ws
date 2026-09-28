use std::cell::Cell;
use std::future::poll_fn;
use std::io;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::time::Duration;

use runtime::channels::{
    BoundedReceiver, BoundedSender, Receiver, Sender, bounded_channel, unbounded_channel,
};
use runtime::runtime::select::{SelectResult5, select5};
use runtime::runtime::time::Sleep;
use runtime::spawn;

use crate::control::ControlBuf;
use crate::message::{CloseFrame, Message};
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

/// What one write carries: messages from the senders, a keepalive ping, a
/// close; always followed by the pongs and close reply reading owes.
struct Job {
    batch: Vec<Message>,
    ping: bool,
    close: Option<Option<CloseFrame>>,
}

// The write half is borrowed across awaits on purpose: by the write in
// flight, its only holder, and on the way out once `finish` has ended it.
#[allow(clippy::await_holding_refcell_ref)]
async fn pump<T: Transport>(
    ws: &mut WebSocket<T>,
    outbound: &Receiver<Message>,
    inbound: &BoundedSender<io::Result<Message>>,
    shared: &Shared,
) -> io::Result<()> {
    let ping_interval = ws.config().ping_interval;
    let mut keepalive = ping_interval.map(Sleep::during);
    // Built once and kept: a select loop re-polls it without re-registering.
    let mut stop = ws.watched().map(|shutdown| Box::pin(shutdown.triggered()));
    let (read, write, state) = ws.parts();

    // One write at a time, kept in flight across turns of the loop, so the
    // socket is read while the peer takes its time with what we send.
    let run = |job: Job| async move {
        let mut writer = write.borrow_mut();
        let size: usize = job.batch.iter().map(Message::payload_len).sum();
        shared.queued.set(shared.queued.get() - size);
        for message in job.batch {
            // Nothing may follow our close frame: what was queued is dropped.
            if state.close_sent() {
                break;
            }
            writer.feed(state, message).await?;
        }
        if job.ping && !state.close_sent() {
            writer.feed(state, Message::Ping(ControlBuf::new())).await?;
        }
        match job.close {
            Some(frame) if !state.close_sent() => writer.close(state, frame).await,
            _ => writer.flush(state).await,
        }
    };
    let mut writing = pin!(None);
    let mut close_next: Option<Option<CloseFrame>> = None;
    let mut ping_next = false;
    let mut outbound_open = true;

    loop {
        let busy = writing.is_some();
        // `next` is cancel-safe, so losing the race to the others costs nothing.
        let event = select5(
            poll_fn(|cx| read.poll_next(state, cx)),
            async {
                // Taken only when the writer is free: the rest waits in the
                // channel, within the senders' budget.
                match outbound_open && !busy {
                    true => outbound.recv_all().await,
                    false => std::future::pending().await,
                }
            },
            async {
                match writing.as_mut().as_pin_mut() {
                    Some(job) => job.await,
                    None => std::future::pending().await,
                }
            },
            async {
                match keepalive.as_mut() {
                    Some(tick) => tick.await,
                    None => std::future::pending().await,
                }
            },
            async {
                match stop.as_mut() {
                    Some(triggered) => triggered.await,
                    None => std::future::pending().await,
                }
            },
        )
        .await;
        match event {
            SelectResult5::First(Some(Ok(message))) => {
                if inbound.send(Ok(message)).await.is_err() {
                    // Nobody listens any more.
                    finish(writing.as_mut()).await;
                    return write.borrow_mut().close(state, None).await;
                }
            }
            SelectResult5::First(Some(Err(e))) if e.kind() == io::ErrorKind::WouldBlock => {
                // The ring is drained by other holders on this thread.
                Sleep::during(Duration::from_millis(1)).await;
            }
            SelectResult5::First(Some(Err(e))) => {
                // The close it owes goes out with `drive`'s last flush.
                finish(writing.as_mut()).await;
                return Err(e);
            }
            SelectResult5::First(None) => {
                finish(writing.as_mut()).await;
                return write.borrow_mut().flush(state).await;
            }
            SelectResult5::Second(Some(batch)) => {
                writing.set(Some(run(Job {
                    batch,
                    ping: false,
                    close: None,
                })));
            }
            SelectResult5::Second(None) => {
                outbound_open = false;
                close_next.get_or_insert(None);
            }
            SelectResult5::Third(result) => {
                writing.set(None);
                result?;
            }
            SelectResult5::Fourth(()) => {
                let interval = ping_interval.expect("ticks only with an interval");
                keepalive = Some(Sleep::during(interval));
                // Only a quiet peer is pinged; its pong resets the idle clock.
                ping_next = read.idle_for() >= interval;
            }
            SelectResult5::Fifth(()) => {
                // Once only: the future stays ready.
                stop = None;
                // Refuse new messages, say goodbye, and keep reading until the
                // peer answers our close or `close_timeout` passes.
                shared.done.set(true);
                close_next = Some(Some(CloseFrame {
                    code: 1001,
                    reason: "server shutting down".to_owned(),
                }));
            }
        }
        // The writer is free: send what is due, and the pongs of what one
        // read brought in once it is all read.
        let owed = state.owes() && !read.has_ready();
        if writing.is_none() && (close_next.is_some() || ping_next || owed) {
            writing.set(Some(run(Job {
                batch: Vec::new(),
                ping: std::mem::take(&mut ping_next),
                close: close_next.take(),
            })));
        }
    }
}

/// Let a write in flight complete: dropping it mid-frame would spend the
/// socket. Its error, if any, shows on the next write.
async fn finish<F: Future<Output = io::Result<()>>>(mut writing: Pin<&mut Option<F>>) {
    if let Some(job) = writing.as_mut().as_pin_mut() {
        let _ = job.await;
        writing.set(None);
    }
}
