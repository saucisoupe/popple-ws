//! WebSocket (RFC 6455) on the io_uring runtime, over plain TCP or kTLS.
//!
//! Frames are read through a multishot recv on a provided buffer ring and
//! decoded straight from the kernel's buffers: each payload byte is copied
//! once, into the message it belongs to.
//!
//! Server side:
//!
//! ```ignore
//! let upgrade = Upgrade::read(Plain::<Ring>::new(socket), Config::default()).await?;
//! let ws = upgrade.accept().await?;
//! ```
//!
//! With TLS, build the transport from the handshaken socket instead:
//! `Tls::new(popple_tls::handshake(socket, cfg, deadline).await?.into_messages::<Ring>())`.
//!
//! Then either drive the [`WebSocket`] from one task, `select`ing
//! `ws.next()` against your own events, or [`split`](WebSocket::split) it
//! into a [`WsSender`] and a [`WsReceiver`] usable from different tasks.

mod connect;
mod control;
pub mod frame;
pub mod handshake;
mod message;
pub mod shutdown;
mod socket;
mod split;
pub mod transport;

pub use connect::{connect, connect_tls};
pub use control::{ControlBuf, ControlTooLong};
pub use handshake::{HandshakeError, Head, Upgrade};
pub use message::{CloseFrame, Message};
pub use shutdown::Shutdown;
pub use socket::{Config, InvalidConfig, Role, WebSocket};
pub use split::{SendError, WsReceiver, WsSender};
pub use transport::{Plain, Tls, Transport};
