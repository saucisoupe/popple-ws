//! The HTTP/1.1 upgrade (RFC 6455 §4), run over the same transport the
//! WebSocket then uses: whatever arrives past the headers is handed on to the
//! frame decoder, not lost.

use std::io;
use std::time::Duration;

use runtime::runtime::time::{Sleep, timeout};

use crate::socket::{Config, InvalidConfig, Role, WebSocket};
use crate::transport::Transport;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Largest request or response head accepted.
const MAX_HEAD: usize = 16 << 10;

#[derive(Debug)]
pub enum HandshakeError {
    Io(io::Error),
    Tls(popple_tls::HandshakeError),
    /// The peer's head is not a valid WebSocket upgrade.
    Invalid(&'static str),
    /// The server answered with a status other than 101.
    Status(u16),
    /// The upgrade did not complete within `Config::handshake_timeout`.
    Timeout,
    Config(InvalidConfig),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "websocket handshake I/O: {e}"),
            Self::Tls(e) => write!(f, "TLS handshake: {e}"),
            Self::Invalid(why) => write!(f, "invalid websocket handshake: {why}"),
            Self::Status(code) => write!(f, "server refused the upgrade with status {code}"),
            Self::Timeout => write!(f, "websocket handshake timed out"),
            Self::Config(e) => e.fmt(f),
        }
    }
}

impl From<InvalidConfig> for HandshakeError {
    fn from(e: InvalidConfig) -> Self {
        Self::Config(e)
    }
}

/// Run `f` under the config's handshake deadline, checked first so an
/// out-of-range duration is an error rather than a timer panic.
async fn within<F, X>(config: &Config, f: F) -> Result<X, HandshakeError>
where
    F: Future<Output = Result<X, HandshakeError>>,
{
    config.validate()?;
    timeout(config.handshake_timeout, f)
        .await
        .unwrap_or(Err(HandshakeError::Timeout))
}

impl std::error::Error for HandshakeError {}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<popple_tls::HandshakeError> for HandshakeError {
    fn from(e: popple_tls::HandshakeError) -> Self {
        Self::Tls(e)
    }
}

/// A parsed request or response head.
#[derive(Debug, Clone)]
pub struct Head {
    /// `GET /path HTTP/1.1` or `HTTP/1.1 101 Switching Protocols`.
    pub start_line: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    fn parse(raw: &[u8]) -> Result<Self, HandshakeError> {
        let text =
            std::str::from_utf8(raw).map_err(|_| HandshakeError::Invalid("non UTF-8 head"))?;
        let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
        let start_line = lines
            .next()
            .ok_or(HandshakeError::Invalid("empty head"))?
            .to_owned();
        let headers = lines
            .map(|line| {
                line.split_once(':')
                    .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
                    .ok_or(HandshakeError::Invalid("malformed header line"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            start_line,
            headers,
        })
    }

    /// First value of a header, by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether a comma-separated header lists `token`, case-insensitively.
    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }
}

/// A WebSocket upgrade request, read and validated but not answered yet:
/// inspect the path and headers, then [`accept`](Self::accept) or
/// [`reject`](Self::reject).
pub struct Upgrade<T: Transport> {
    transport: T,
    head: Head,
    key: String,
    leftover: Vec<u8>,
    config: Config,
}

impl<T: Transport> Upgrade<T> {
    /// Read the client's upgrade request, within `config.handshake_timeout`;
    /// on timeout the transport is dropped, which closes the connection. A
    /// request that is not a valid upgrade is answered (400, or 426 for an
    /// unsupported version) before the error is returned.
    pub async fn read(mut transport: T, config: Config) -> Result<Self, HandshakeError> {
        let (raw, leftover) = within(&config, read_head(&mut transport)).await?;
        let head = Head::parse(&raw)?;
        match validate_request(&head) {
            Ok(key) => Ok(Self {
                transport,
                key: key.to_owned(),
                head,
                leftover,
                config,
            }),
            Err((status, why)) => {
                let extra = if status == 426 {
                    "Sec-WebSocket-Version: 13\r\n"
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 {status} {}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n",
                    if status == 426 {
                        "Upgrade Required"
                    } else {
                        "Bad Request"
                    },
                );
                let _ = transport.send(response.into_bytes()).await;
                let _ = transport.shutdown().await;
                Err(HandshakeError::Invalid(why))
            }
        }
    }

    pub fn head(&self) -> &Head {
        &self.head
    }

    /// Request target, e.g. `/chat?room=1`.
    pub fn path(&self) -> &str {
        self.head.start_line.split(' ').nth(1).unwrap_or("/")
    }

    /// Subprotocols the client offered, in its order of preference.
    pub fn protocols(&self) -> impl Iterator<Item = &str> {
        self.head
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-protocol"))
            .flat_map(|(_, v)| v.split(','))
            .map(str::trim)
    }

    pub async fn accept(self) -> Result<WebSocket<T>, HandshakeError> {
        self.accept_with_protocol(None).await
    }

    /// Accept, naming the subprotocol picked from [`protocols`](Self::protocols).
    pub async fn accept_with_protocol(
        mut self,
        protocol: Option<&str>,
    ) -> Result<WebSocket<T>, HandshakeError> {
        let protocol = protocol
            .map(|p| format!("Sec-WebSocket-Protocol: {p}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n{protocol}\r\n",
            accept_key(&self.key),
        );
        self.transport.send(response.into_bytes()).await.0?;
        Ok(WebSocket::from_upgraded(
            self.transport,
            Role::Server,
            self.leftover,
            self.config,
        ))
    }

    /// Refuse the upgrade with an HTTP status, e.g. 401 or 404.
    pub async fn reject(mut self, status: u16, reason: &str) -> io::Result<()> {
        let response =
            format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        self.transport.send(response.into_bytes()).await.0?;
        self.transport.shutdown().await
    }
}

/// On failure, the status to answer with and why.
fn validate_request(head: &Head) -> Result<&str, (u16, &'static str)> {
    let mut start = head.start_line.split(' ');
    if start.next() != Some("GET") {
        return Err((400, "method is not GET"));
    }
    if start.nth(1) != Some("HTTP/1.1") {
        return Err((400, "not HTTP/1.1"));
    }
    if !head.has_token("upgrade", "websocket") {
        return Err((400, "missing Upgrade: websocket"));
    }
    if !head.has_token("connection", "upgrade") {
        return Err((400, "missing Connection: Upgrade"));
    }
    if head.header("sec-websocket-version") != Some("13") {
        return Err((426, "unsupported Sec-WebSocket-Version"));
    }
    // 16 random bytes in base64.
    match head.header("sec-websocket-key") {
        Some(key) if key.len() == 24 => Ok(key),
        _ => Err((400, "missing or malformed Sec-WebSocket-Key")),
    }
}

/// Run the client side of the upgrade over a connected transport, within
/// `config.handshake_timeout`. `headers` are sent as is, e.g.
/// `[("Sec-WebSocket-Protocol", "chat")]`.
pub async fn client<T: Transport>(
    mut transport: T,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    config: Config,
) -> Result<(WebSocket<T>, Head), HandshakeError> {
    let (head, leftover) = within(
        &config,
        client_exchange(&mut transport, host, path, headers),
    )
    .await?;
    let ws = WebSocket::from_upgraded(transport, Role::Client, leftover, config);
    Ok((ws, head))
}

/// Send the upgrade request and check the response; returns the response
/// head and what followed it.
async fn client_exchange<T: Transport>(
    transport: &mut T,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(Head, Vec<u8>), HandshakeError> {
    let mut nonce = [0; 16];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| io::Error::other("system RNG"))?;
    let key = base64(&nonce);
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    transport.send(request.into_bytes()).await.0?;

    let (raw, leftover) = read_head(transport).await?;
    let head = Head::parse(&raw)?;
    let status = head
        .start_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(HandshakeError::Invalid("malformed status line"))?;
    if status != 101 {
        return Err(HandshakeError::Status(status));
    }
    if !head.has_token("upgrade", "websocket") || !head.has_token("connection", "upgrade") {
        return Err(HandshakeError::Invalid(
            "response does not upgrade to websocket",
        ));
    }
    if head.header("sec-websocket-accept") != Some(accept_key(&key).as_str()) {
        return Err(HandshakeError::Invalid("wrong Sec-WebSocket-Accept"));
    }
    Ok((head, leftover))
}

/// Read up to the blank line ending an HTTP head. Returns the head and the
/// bytes that followed it.
async fn read_head<T: Transport>(transport: &mut T) -> Result<(Vec<u8>, Vec<u8>), HandshakeError> {
    let mut buf = Vec::new();
    loop {
        let chunk = match std::future::poll_fn(|cx| transport.poll_recv(cx)).await {
            Some(Ok(chunk)) => chunk,
            Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                Sleep::during(Duration::from_millis(1)).await;
                continue;
            }
            Some(Err(e)) => return Err(e.into()),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during the upgrade",
                )
                .into());
            }
        };
        // The terminator may straddle the previous chunk.
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(chunk.as_ref());
        drop(chunk);
        if let Some(i) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let leftover = buf.split_off(from + i + 4);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD {
            return Err(HandshakeError::Invalid("head too large"));
        }
    }
}

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key` (§4.2.2).
pub fn accept_key(key: &str) -> String {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(key.as_bytes());
    ctx.update(GUID.as_bytes());
    base64(ctx.finish().as_ref())
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        let n = group
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        (0..4).for_each(|i| {
            out.push(if i <= group.len() {
                ALPHABET[(n >> (18 - 6 * i) & 0x3F) as usize] as char
            } else {
                '='
            })
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_accept_key() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn base64_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn validates_request() {
        let head = Head::parse(
            b"GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: WebSocket\r\n\
              Connection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .unwrap();
        assert_eq!(validate_request(&head), Ok("dGhlIHNhbXBsZSBub25jZQ=="));

        let old = Head::parse(
            b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\
              Sec-WebSocket-Version: 8\r\n\r\n",
        )
        .unwrap();
        assert_eq!(validate_request(&old).unwrap_err().0, 426);
    }
}
