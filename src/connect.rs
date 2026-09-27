use std::net::SocketAddr;

use popple_tls::{ClientConfig, ServerName};
use runtime::net::{BufRingSpec, connect_tcp};
use rustls::client::ClientConnectionData;

use crate::handshake::{self, HandshakeError, Head};
use crate::socket::{Config, WebSocket};
use crate::transport::{Plain, Tls};

/// Dial `ws://host/path` at `addr`.
pub async fn connect<R: BufRingSpec>(
    addr: SocketAddr,
    host: &str,
    path: &str,
    config: Config,
) -> Result<(WebSocket<Plain<R>>, Head), HandshakeError> {
    let socket = connect_tcp(addr).await?;
    handshake::client(Plain::new(socket), host, path, &[], config).await
}

/// Dial `wss://server_name/path` at `addr`, with TLS offloaded to the kernel.
/// The TLS handshake and the upgrade each get `config.handshake_timeout`.
pub async fn connect_tls<R: BufRingSpec>(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    tls: ClientConfig,
    path: &str,
    config: Config,
) -> Result<(WebSocket<Tls<R, ClientConnectionData>>, Head), HandshakeError> {
    // Before the TLS deadline is armed: out of range, it would panic.
    config.validate()?;
    let host = match &server_name {
        ServerName::DnsName(name) => name.as_ref().to_owned(),
        _ => addr.ip().to_string(),
    };
    let ktls = popple_tls::connect(addr, server_name, tls, config.handshake_timeout).await?;
    let transport = Tls::new(ktls.into_messages::<R>());
    handshake::client(transport, &host, path, &[], config).await
}
