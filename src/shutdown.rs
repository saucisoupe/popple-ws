//! Graceful shutdown for one worker: stop taking connections, tell the live
//! ones to go away (close 1001), and wait for them to finish.
//!
//! Under `thread_per_core`, SIGTERM and SIGINT already end every
//! `MultiAccept` stream polled from a worker's root future. A server then
//! reads:
//!
//! ```ignore
//! let shutdown = Shutdown::new();
//! while let Some(socket) = accept.next().await {   // None on SIGTERM
//!     let shutdown = shutdown.clone();
//!     spawn(async move {
//!         let _alive = shutdown.track();            // counts from the start
//!         let mut ws = /* upgrade */;
//!         ws.watch(&shutdown);
//!         let (tx, rx) = ws.split(32);              // closes with 1001 on trigger
//!         /* ... */
//!     });
//! }
//! shutdown.trigger();
//! shutdown.drained().await;                         // each bounded by close_timeout
//! ```
//!
//! The runtime exits the process 30 s after the signal whatever is left, so
//! `close_timeout` and `handshake_timeout` must stay well below that.

use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

/// Wakers of the futures waiting on one event. Each future keeps its slot
/// for its whole life, so polling it again costs no allocation.
#[derive(Default)]
struct Waiters {
    slots: Vec<Option<Waker>>,
    free: Vec<usize>,
}

impl Waiters {
    fn register(&mut self, slot: &mut Option<usize>, waker: &Waker) {
        match *slot {
            Some(i) => match &mut self.slots[i] {
                Some(w) if w.will_wake(waker) => {}
                w => *w = Some(waker.clone()),
            },
            None => {
                let i = self.free.pop().unwrap_or_else(|| {
                    self.slots.push(None);
                    self.slots.len() - 1
                });
                self.slots[i] = Some(waker.clone());
                *slot = Some(i);
            }
        }
    }

    fn remove(&mut self, slot: usize) {
        self.slots[slot] = None;
        self.free.push(slot);
    }

    fn wake_all(&mut self) {
        self.slots
            .iter_mut()
            .filter_map(Option::take)
            .for_each(Waker::wake);
    }
}

#[derive(Default)]
struct Inner {
    triggered: Cell<bool>,
    live: Cell<usize>,
    on_trigger: RefCell<Waiters>,
    on_drain: RefCell<Waiters>,
}

/// One worker's shutdown switch and the connections that must finish before
/// it returns. Cheap to clone; not `Send`: create one per worker.
#[derive(Clone, Default)]
pub struct Shutdown(Rc<Inner>);

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask every watched connection to close. Idempotent.
    pub fn trigger(&self) {
        if !self.0.triggered.replace(true) {
            self.0.on_trigger.borrow_mut().wake_all();
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.0.triggered.get()
    }

    /// Resolves once [`trigger`](Self::trigger) is called: `select` on it to
    /// close a connection driven by hand.
    pub fn triggered(&self) -> Triggered {
        Triggered {
            inner: self.0.clone(),
            slot: None,
        }
    }

    /// Count a connection until the guard drops: [`drained`](Self::drained)
    /// waits for it. Take it as soon as the connection is accepted, so one
    /// still in its handshake counts too.
    pub fn track(&self) -> Tracked {
        self.0.live.set(self.0.live.get() + 1);
        Tracked(self.0.clone())
    }

    /// Connections tracked and not finished yet.
    pub fn live(&self) -> usize {
        self.0.live.get()
    }

    /// Resolves once no tracked connection is left.
    pub fn drained(&self) -> Drained {
        Drained {
            inner: self.0.clone(),
            slot: None,
        }
    }
}

/// Keeps a connection counted by [`Shutdown::drained`] while it lives.
pub struct Tracked(Rc<Inner>);

impl Drop for Tracked {
    fn drop(&mut self) {
        let live = self.0.live.get() - 1;
        self.0.live.set(live);
        if live == 0 {
            self.0.on_drain.borrow_mut().wake_all();
        }
    }
}

/// Future of [`Shutdown::triggered`].
pub struct Triggered {
    inner: Rc<Inner>,
    slot: Option<usize>,
}

impl Future for Triggered {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.inner.triggered.get() {
            return Poll::Ready(());
        }
        this.inner
            .on_trigger
            .borrow_mut()
            .register(&mut this.slot, cx.waker());
        Poll::Pending
    }
}

impl Drop for Triggered {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            self.inner.on_trigger.borrow_mut().remove(slot);
        }
    }
}

/// Future of [`Shutdown::drained`].
pub struct Drained {
    inner: Rc<Inner>,
    slot: Option<usize>,
}

impl Future for Drained {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.inner.live.get() == 0 {
            return Poll::Ready(());
        }
        this.inner
            .on_drain
            .borrow_mut()
            .register(&mut this.slot, cx.waker());
        Poll::Pending
    }
}

impl Drop for Drained {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            self.inner.on_drain.borrow_mut().remove(slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;

    use super::*;

    fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
        f.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn trigger_and_drain() {
        let shutdown = Shutdown::new();
        let a = shutdown.track();
        let b = shutdown.track();
        let mut triggered = pin!(shutdown.triggered());
        let mut drained = pin!(shutdown.drained());
        // Polled again and again, as in a select loop: one slot each.
        for _ in 0..3 {
            assert!(poll(triggered.as_mut()).is_pending());
            assert!(poll(drained.as_mut()).is_pending());
        }
        assert_eq!(shutdown.0.on_trigger.borrow().slots.len(), 1);
        shutdown.trigger();
        assert!(poll(triggered.as_mut()).is_ready());
        drop(a);
        assert!(poll(drained.as_mut()).is_pending());
        drop(b);
        assert_eq!(shutdown.live(), 0);
        assert!(poll(drained.as_mut()).is_ready());
    }
}
