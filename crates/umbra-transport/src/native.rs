//! The native L1 stack of Part 14 §14.2.8: TLS 1.3 through rustls on the
//! aws-lc-rs provider, QUIC through quinn, both on tokio.
//!
//! The client configuration is one shape for every client (Part 3 §3.8):
//! `X25519MLKEM768` first and `X25519` second as the only groups
//! (`NET-214`, `NET-215`), TLS 1.3 only (`IMP-068`), no resumption and no
//! early data (`NET-073`), and GREASE ECH.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::{
    client::{EchGreaseConfig, EchMode, Resumption},
    crypto::{
        aws_lc_rs::{self, hpke, kx_group},
        hpke::Hpke,
    },
    pki_types::ServerName,
    RootCertStore,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use crate::{
    race::{Plan, Wire},
    upgrade, websocket, Dial, Error,
};

/// The ALPN of the QUIC transport. The TCP transport negotiates none,
/// because the HTTP/1.1 upgrade names the stream.
pub const QUIC_ALPN: &[u8] = b"umbra.v1";
/// The largest capsule the stack reads.
pub const MAX_CAPSULE: usize = 32_786;

/// A native connection error.
#[derive(Debug)]
pub enum NativeError {
    /// The TLS configuration or handshake failed.
    Tls(rustls::Error),
    /// The socket failed.
    Io(std::io::Error),
    /// QUIC failed.
    Quic(String),
    /// The upgrade or a frame was refused or malformed.
    Protocol(Error),
    /// No transport completed in time.
    Timeout,
}

impl From<rustls::Error> for NativeError {
    fn from(e: rustls::Error) -> Self {
        NativeError::Tls(e)
    }
}

impl From<std::io::Error> for NativeError {
    fn from(e: std::io::Error) -> Self {
        NativeError::Io(e)
    }
}

impl From<Error> for NativeError {
    fn from(e: Error) -> Self {
        NativeError::Protocol(e)
    }
}

impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NativeError::Tls(e) => write!(f, "tls: {e}"),
            NativeError::Io(e) => write!(f, "io: {e}"),
            NativeError::Quic(e) => write!(f, "quic: {e}"),
            NativeError::Protocol(e) => write!(f, "protocol: {e}"),
            NativeError::Timeout => f.write_str("no transport completed"),
        }
    }
}

impl std::error::Error for NativeError {}

pub use rustls::ClientConfig;

/// The one TLS client configuration of every native client, under the
/// public web roots.
pub fn tls_config() -> Result<Arc<ClientConfig>, NativeError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tls_config_under(roots)
}

/// The same configuration under the given roots alone, in DER. A
/// development network and a test put their own authority here. A shipped
/// client uses [`tls_config`].
pub fn tls_config_with_roots(roots_der: &[Vec<u8>]) -> Result<Arc<ClientConfig>, NativeError> {
    let mut roots = RootCertStore::empty();
    for der in roots_der {
        roots.add(rustls::pki_types::CertificateDer::from(der.clone()))?;
    }
    tls_config_under(roots)
}

/// The same configuration under each certificate of a PEM file.
pub fn tls_config_with_root_file(path: &str) -> Result<Arc<ClientConfig>, NativeError> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = RootCertStore::empty();
    let found = CertificateDer::pem_file_iter(path).map_err(|_| Error::Refused)?;
    for certificate in found {
        roots.add(certificate.map_err(|_| Error::Refused)?)?;
    }
    tls_config_under(roots)
}

fn tls_config_under(roots: RootCertStore) -> Result<Arc<ClientConfig>, NativeError> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![kx_group::X25519MLKEM768, kx_group::X25519];
    // The GREASE placeholder needs one HPKE suite and a throwaway key.
    let suite = hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (placeholder, _) = suite.generate_key_pair()?;
    // ECH fixes the versions to TLS 1.3 alone, which IMP-068 asks for.
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_ech(EchMode::Grease(EchGreaseConfig::new(suite, placeholder)))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// How long a dial waits for one address before it turns to the next one.
/// The callers give a dial 10 s or more. Thus the address of the second
/// family keeps the larger part for its connect, its handshake, and its
/// upgrade.
const FAMILY_WAIT: Duration = Duration::from_secs(4);

/// The addresses of a dial in the order of their use: IPv4 first, then
/// IPv6, each one that the descriptor holds.
fn socket_addrs(dial: &Dial) -> impl Iterator<Item = SocketAddr> {
    let v4 = dial
        .addr_v4
        .map(|a| SocketAddr::from((std::net::Ipv4Addr::from(a), dial.port)));
    let v6 = dial
        .addr_v6
        .map(|a| SocketAddr::from((std::net::Ipv6Addr::from(a), dial.port)));
    v4.into_iter().chain(v6)
}

/// Connects to the first address of the dial that answers. A relay with
/// two address families stays in reach on a network that carries one of
/// them. An address that refuses, or that stays silent for `FAMILY_WAIT`,
/// gives its turn to the next one. The last address waits for the deadline
/// of the caller alone. One address is in use at a time, thus the relay
/// sees one address of the client.
async fn connect_tcp(dial: &Dial) -> Result<TcpStream, NativeError> {
    let mut addrs = socket_addrs(dial).peekable();
    let mut failed: NativeError = Error::Refused.into();
    while let Some(addr) = addrs.next() {
        let connected = if addrs.peek().is_some() {
            match timeout(FAMILY_WAIT, TcpStream::connect(addr)).await {
                Ok(connected) => connected,
                Err(_) => {
                    failed = NativeError::Timeout;
                    continue;
                }
            }
        } else {
            TcpStream::connect(addr).await
        };
        match connected {
            Ok(tcp) => return Ok(tcp),
            Err(error) => failed = error.into(),
        }
    }
    Err(failed)
}

/// The path of the relay manifest at an HTTPS carrier (Part 3 §3.10).
pub const MANIFEST_PATH: &str = "/.well-known/umbra/manifest";
/// The largest manifest that a client reads: 3 000 proven entries are below
/// 18 MiB (Part 10 §10.5.5).
pub const MANIFEST_MAX: usize = 32 << 20;
/// The path of the challenges of the relays, beside the manifest (Part 13
/// `ABU-104`).
pub const CHALLENGES_PATH: &str = "/.well-known/umbra/challenges";
/// The largest bundle of challenges that a client reads: one challenge of
/// 3 387 bytes for each of 3 000 relays is below 10 MiB.
pub const CHALLENGES_MAX: usize = 16 << 20;
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The path of the key chain of the directory, beside the manifest (Part 10
/// `REL-199`).
pub const KEYCHAIN_PATH: &str = "/.well-known/umbra/keychain";
/// The largest key chain that a client reads (`REL-199`).
pub const KEYCHAIN_MAX: usize = 1 << 20;

/// The head of a response to a manifest request, for a carrier that holds
/// `len` bytes.
pub fn manifest_response_head(len: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n"
    )
}

/// Whether a complete request head asks for the relay manifest.
pub fn asks_manifest(head: &[u8]) -> bool {
    head.starts_with(format!("GET {MANIFEST_PATH} HTTP/1.1\r\n").as_bytes())
}

/// Whether the head of a request asks for the key chain (Part 10
/// `REL-199`).
pub fn asks_keychain(head: &[u8]) -> bool {
    head.starts_with(format!("GET {KEYCHAIN_PATH} HTTP/1.1\r\n").as_bytes())
}

/// Whether the head of a request asks for the challenges of the relays.
pub fn asks_challenges(head: &[u8]) -> bool {
    head.starts_with(format!("GET {CHALLENGES_PATH} HTTP/1.1\r\n").as_bytes())
}

/// Reads the challenges of the relays from the carrier of the manifest, on
/// the path of the manifest fetch (`ABU-065`, `ABU-105`). Each challenge is
/// under the signature of its relay, thus the caller verifies them and
/// trusts this carrier with nothing.
pub async fn fetch_challenges(
    dial: &Dial,
    config: Arc<ClientConfig>,
) -> Result<Vec<u8>, NativeError> {
    timeout(
        MANIFEST_TIMEOUT,
        fetch_carried(dial, config, CHALLENGES_PATH, CHALLENGES_MAX),
    )
    .await
    .map_err(|_| NativeError::Timeout)?
}

/// Reads the relay manifest from an HTTPS carrier. The bytes are under the
/// signatures of the directory, thus the caller verifies them and trusts
/// this carrier with nothing (Part 10 §10.5).
pub async fn fetch_manifest(
    dial: &Dial,
    config: Arc<ClientConfig>,
) -> Result<Vec<u8>, NativeError> {
    timeout(
        MANIFEST_TIMEOUT,
        fetch_carried(dial, config, MANIFEST_PATH, MANIFEST_MAX),
    )
    .await
    .map_err(|_| NativeError::Timeout)?
}

/// Reads the key chain of the directory from an HTTPS carrier (Part 10
/// `REL-199`), under the deadline of a manifest.
pub async fn fetch_keychain(
    dial: &Dial,
    config: Arc<ClientConfig>,
) -> Result<Vec<u8>, NativeError> {
    timeout(
        MANIFEST_TIMEOUT,
        fetch_carried(dial, config, KEYCHAIN_PATH, KEYCHAIN_MAX),
    )
    .await
    .map_err(|_| NativeError::Timeout)?
}

/// One `GET` of `path` from an HTTPS carrier, with a body of `max` bytes at
/// most.
async fn fetch_carried(
    dial: &Dial,
    config: Arc<ClientConfig>,
    path: &str,
    max: usize,
) -> Result<Vec<u8>, NativeError> {
    let tcp = connect_tcp(dial).await?;
    let name = ServerName::try_from(dial.host.clone()).map_err(|_| Error::Refused)?;
    let mut stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/octet-stream\r\n\
         Connection: close\r\n\r\n",
        dial.host
    );
    stream.write_all(request.as_bytes()).await?;
    let mut inbound = Vec::with_capacity(65_536);
    let mut chunk = vec![0u8; 16_384];
    loop {
        // A carrier that closes with no TLS close is at its end too, and the
        // length of the head tests what came.
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        if inbound.len() > max {
            return Err(Error::Refused.into());
        }
    }
    read_carried(&inbound)
}

/// The body of the answer of a carrier. The status is `200`, and a
/// `Content-Length` that equals what came proves that the body is whole.
/// The read takes a cut connection as the end of the stream. Thus a body
/// that the close alone delimits can be a body cut short, and the call
/// refuses it.
fn read_carried(inbound: &[u8]) -> Result<Vec<u8>, NativeError> {
    let head_end = inbound
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(Error::Refused)?;
    let head =
        core::str::from_utf8(inbound.get(..head_end).unwrap_or(&[])).map_err(|_| Error::Refused)?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 200") {
        return Err(Error::Refused.into());
    }
    let body = inbound.get(head_end.saturating_add(4)..).unwrap_or(&[]);
    let mut is_whole = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        // This client reads a body of a plain length alone.
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(Error::Refused.into());
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            if value.trim().parse::<usize>().ok() != Some(body.len()) {
                return Err(Error::Refused.into());
            }
            is_whole = true;
        }
    }
    if !is_whole {
        return Err(Error::Refused.into());
    }
    Ok(body.to_vec())
}

/// A TCP connection after the TLS handshake and the upgrade. Each capsule
/// travels in one masked WebSocket frame.
pub struct TcpLink {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    inbound: Vec<u8>,
    mask: [u8; 4],
    counter: u64,
}

impl TcpLink {
    /// Connects, handshakes, and upgrades. `key` and `mask_seed` come from
    /// the CSPRNG of the caller.
    pub async fn connect(
        dial: &Dial,
        config: Arc<ClientConfig>,
        key: [u8; 16],
        mask_seed: [u8; 4],
    ) -> Result<Self, NativeError> {
        let tcp = connect_tcp(dial).await?;
        tcp.set_nodelay(true)?;
        let name = ServerName::try_from(dial.host.clone()).map_err(|_| Error::Refused)?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let mut stream = connector.connect(name, tcp).await?;
        stream
            .write_all(upgrade::request(&dial.host, &key).as_bytes())
            .await?;
        let mut inbound = Vec::with_capacity(4_096);
        let mut chunk = [0u8; 2_048];
        let used = loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Refused.into());
            }
            inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            if let Some(used) = upgrade::parse_response(&inbound, &key)? {
                break used;
            }
            if inbound.len() > 8_192 {
                return Err(Error::Refused.into());
            }
        };
        inbound.drain(..used);
        Ok(TcpLink {
            stream,
            inbound,
            mask: mask_seed,
            counter: 0,
        })
    }

    fn next_mask(&mut self) -> [u8; 4] {
        // A fresh mask for each frame, from the seed and a counter. The mask
        // hides nothing from TLS; RFC 6455 wants it different for each frame.
        self.counter = self.counter.wrapping_add(1);
        let c = self.counter.to_le_bytes();
        [
            self.mask[0] ^ c[0],
            self.mask[1] ^ c[1],
            self.mask[2] ^ c[2],
            self.mask[3] ^ c[3],
        ]
    }

    /// Sends one capsule.
    pub async fn send(&mut self, capsule: &[u8]) -> Result<(), NativeError> {
        let mask = self.next_mask();
        let mut frame = vec![0u8; websocket::frame_len(capsule.len(), true)];
        let n = websocket::encode(capsule, Some(&mask), &mut frame)?;
        frame.truncate(n);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receives one capsule.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        let mut out = vec![0u8; MAX_CAPSULE];
        loop {
            if let Some((len, used)) = websocket::decode(&self.inbound, false, &mut out)? {
                self.inbound.drain(..used);
                out.truncate(len);
                return Ok(out);
            }
            let mut chunk = [0u8; 4_096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Refused.into());
            }
            self.inbound
                .extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }
}

impl TcpLink {
    /// The two halves of the link, for a party that sends and receives at
    /// the same time: the measurer of Part 10 §10.3 sends at its rate
    /// while the echoes come back.
    pub fn split(self) -> (TcpReader, TcpWriter) {
        let (read, write) = tokio::io::split(self.stream);
        (
            TcpReader {
                stream: read,
                inbound: self.inbound,
                scratch: vec![0u8; MAX_CAPSULE],
            },
            TcpWriter {
                stream: write,
                mask: self.mask,
                counter: self.counter,
            },
        )
    }
}

/// The receiving half of a [`TcpLink`].
pub struct TcpReader {
    stream: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    inbound: Vec<u8>,
    scratch: Vec<u8>,
}

impl TcpReader {
    /// Receives one capsule.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        let mut consumed = 0usize;
        loop {
            let rest = self.inbound.get(consumed..).unwrap_or(&[]);
            if let Some((len, used)) = websocket::decode(rest, false, &mut self.scratch)? {
                self.inbound.drain(..consumed.saturating_add(used));
                return Ok(self.scratch.get(..len).unwrap_or(&[]).to_vec());
            }
            self.inbound.drain(..consumed);
            consumed = 0;
            let mut chunk = [0u8; 16_384];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Refused.into());
            }
            self.inbound
                .extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }
}

/// The sending half of a [`TcpLink`].
pub struct TcpWriter {
    stream: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    mask: [u8; 4],
    counter: u64,
}

impl TcpWriter {
    /// Sends each capsule of `capsules`, one frame for each, in one write.
    pub async fn send_all(&mut self, capsules: &[Vec<u8>]) -> Result<(), NativeError> {
        let mut frames = Vec::new();
        for capsule in capsules {
            self.counter = self.counter.wrapping_add(1);
            let c = self.counter.to_le_bytes();
            let mask = [
                self.mask[0] ^ c[0],
                self.mask[1] ^ c[1],
                self.mask[2] ^ c[2],
                self.mask[3] ^ c[3],
            ];
            let start = frames.len();
            let len = websocket::frame_len(capsule.len(), true);
            frames.resize(start.saturating_add(len), 0);
            let n = websocket::encode(
                capsule,
                Some(&mask),
                frames.get_mut(start..).unwrap_or(&mut []),
            )?;
            frames.truncate(start.saturating_add(n));
        }
        self.stream.write_all(&frames).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// A QUIC connection with one bidirectional stream that carries capsules
/// back to back.
pub struct QuicLink {
    _connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    inbound: Vec<u8>,
}

impl QuicLink {
    /// Connects over QUIC with the same TLS configuration.
    pub async fn connect(dial: &Dial, config: Arc<ClientConfig>) -> Result<Self, NativeError> {
        // No caller dials QUIC in v1, thus the dial takes the first address
        // alone and has no turn to the second family.
        let addr = socket_addrs(dial).next().ok_or(Error::Refused)?;
        let mut tls = (*config).clone();
        tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| NativeError::Quic(e.to_string()))?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_config));
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().map_err(|_| Error::Refused)?
        } else {
            "0.0.0.0:0".parse().map_err(|_| Error::Refused)?
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(client_config);
        let connecting = endpoint
            .connect(addr, &dial.host)
            .map_err(|e| NativeError::Quic(e.to_string()))?;
        let connection = connecting
            .await
            .map_err(|e| NativeError::Quic(e.to_string()))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| NativeError::Quic(e.to_string()))?;
        Ok(QuicLink {
            _connection: connection,
            send,
            recv,
            inbound: Vec::with_capacity(4_096),
        })
    }

    /// Sends one capsule.
    pub async fn send(&mut self, capsule: &[u8]) -> Result<(), NativeError> {
        self.send
            .write_all(capsule)
            .await
            .map_err(|e| NativeError::Quic(e.to_string()))
    }

    /// Receives one capsule, delimited by its own header. The capsule
    /// comes whole, with that header, as [`TcpLink::recv`] gives it: each
    /// caller parses the capsule again.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        loop {
            if let Some(capsule) = take_capsule(&mut self.inbound) {
                return Ok(capsule);
            }
            let mut chunk = [0u8; 4_096];
            let n = self
                .recv
                .read(&mut chunk)
                .await
                .map_err(|e| NativeError::Quic(e.to_string()))?
                .ok_or(Error::Refused)?;
            self.inbound
                .extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            if self.inbound.len() > MAX_CAPSULE.saturating_mul(2) {
                return Err(Error::Malformed.into());
            }
        }
    }
}

/// Takes the first capsule from the front of a QUIC stream, header
/// included, or `None` while the stream holds no whole capsule.
fn take_capsule(inbound: &mut Vec<u8>) -> Option<Vec<u8>> {
    let (_, _, used) = umbra_wire::capsule::parse(inbound).ok()?;
    Some(inbound.drain(..used).collect())
}

/// One connected transport.
pub enum Link {
    /// The TCP transport.
    Tcp(Box<TcpLink>),
    /// The QUIC transport.
    Quic(QuicLink),
}

impl Link {
    /// The transport of this link.
    pub fn wire(&self) -> Wire {
        match self {
            Link::Tcp(_) => Wire::Tcp,
            Link::Quic(_) => Wire::Quic,
        }
    }

    /// Sends one capsule.
    pub async fn send(&mut self, capsule: &[u8]) -> Result<(), NativeError> {
        match self {
            Link::Tcp(l) => l.send(capsule).await,
            Link::Quic(l) => l.send(capsule).await,
        }
    }

    /// Receives one capsule.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        match self {
            Link::Tcp(l) => l.recv().await,
            Link::Quic(l) => l.recv().await,
        }
    }
}

/// Connects under a plan of the race policy: one transport, or TCP with
/// QUIC started after the head start, the first to complete wins.
pub async fn connect(
    dial: &Dial,
    config: Arc<ClientConfig>,
    plan: Plan,
    key: [u8; 16],
    mask_seed: [u8; 4],
    overall: Duration,
) -> Result<Link, NativeError> {
    let tcp = async {
        TcpLink::connect(dial, config.clone(), key, mask_seed)
            .await
            .map(|l| Link::Tcp(Box::new(l)))
    };
    let quic = |after: u64| {
        let config = config.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(after)).await;
            QuicLink::connect(dial, config).await.map(Link::Quic)
        }
    };
    let raced = async {
        match plan {
            Plan::Only(Wire::Tcp) => tcp.await,
            Plan::Only(Wire::Quic) => quic(0).await,
            Plan::Race { quic_after_ms } => {
                tokio::pin!(tcp);
                let quic = quic(quic_after_ms);
                tokio::pin!(quic);
                let mut tcp_done: Option<NativeError> = None;
                let mut quic_done: Option<NativeError> = None;
                loop {
                    tokio::select! {
                        r = &mut tcp, if tcp_done.is_none() => match r {
                            Ok(link) => return Ok(link),
                            Err(e) => tcp_done = Some(e),
                        },
                        r = &mut quic, if quic_done.is_none() => match r {
                            Ok(link) => return Ok(link),
                            Err(e) => quic_done = Some(e),
                        },
                    }
                    if tcp_done.is_some() && quic_done.is_some() {
                        return Err(tcp_done.take().unwrap_or(NativeError::Timeout));
                    }
                }
            }
        }
    };
    timeout(overall, raced)
        .await
        .map_err(|_| NativeError::Timeout)?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_quic_stream_gives_each_capsule_whole_with_its_header() {
        let mut first = [0u8; 64];
        let n = umbra_wire::capsule::encode(
            umbra_wire::capsule::CapsuleType::Session,
            &[0x03, 1, 2, 3, 4, 5, 6, 7, 8],
            &mut first,
        )
        .unwrap();
        let capsule = first.get(..n).unwrap();
        let mut inbound = capsule.to_vec();
        inbound.extend_from_slice(capsule.get(..n - 1).unwrap());
        // The caller parses what it takes, thus the header stays.
        let taken = take_capsule(&mut inbound).unwrap();
        assert_eq!(taken, capsule);
        assert!(umbra_wire::capsule::parse(&taken).is_ok());
        // A capsule that is not whole waits for the rest of the stream.
        assert_eq!(take_capsule(&mut inbound), None);
        assert_eq!(inbound.len(), n - 1);
        inbound.extend_from_slice(capsule.get(n - 1..).unwrap());
        assert_eq!(take_capsule(&mut inbound).unwrap(), capsule);
        assert!(inbound.is_empty());
    }

    #[test]
    fn a_carried_body_that_the_close_alone_ends_is_refused() {
        let whole = format!("{}{}", manifest_response_head(2), "ok");
        assert_eq!(read_carried(whole.as_bytes()).unwrap(), b"ok");
        // A cut connection gives the same bytes as a whole answer here.
        let open = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok";
        assert!(read_carried(open).is_err());
        let short = format!("{}{}", manifest_response_head(9), "ok");
        assert!(read_carried(short.as_bytes()).is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(read_carried(chunked).is_err());
        let absent = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(read_carried(absent).is_err());
    }

    #[test]
    fn a_dial_holds_its_addresses_with_ipv4_first() {
        let mut dial = Dial {
            host: "relay.example".into(),
            addr_v4: Some([192, 0, 2, 1]),
            addr_v6: Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            port: 443,
        };
        let both: Vec<SocketAddr> = socket_addrs(&dial).collect();
        assert_eq!(both.len(), 2);
        assert!(both.first().unwrap().is_ipv4());
        assert!(both.last().unwrap().is_ipv6());
        dial.addr_v4 = None;
        assert!(socket_addrs(&dial).next().unwrap().is_ipv6());
        dial.addr_v6 = None;
        assert_eq!(socket_addrs(&dial).next(), None);
    }

    #[tokio::test]
    async fn a_dial_turns_to_ipv6_when_ipv4_refuses() {
        // A machine with no IPv6 loopback cannot run this test.
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        // Nothing listens at the IPv4 loopback on that port.
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
            return;
        }
        let mut dial = Dial {
            host: "relay.example".into(),
            addr_v4: Some([127, 0, 0, 1]),
            addr_v6: Some(std::net::Ipv6Addr::LOCALHOST.octets()),
            port,
        };
        let tcp = connect_tcp(&dial).await.unwrap();
        assert!(tcp.peer_addr().unwrap().is_ipv6());
        // With one family alone, the refusal is the answer.
        dial.addr_v6 = None;
        assert!(matches!(connect_tcp(&dial).await, Err(NativeError::Io(_))));
        dial.addr_v4 = None;
        assert!(matches!(
            connect_tcp(&dial).await,
            Err(NativeError::Protocol(Error::Refused))
        ));
    }

    #[test]
    fn the_client_configuration_builds_with_the_two_groups_and_no_resumption() {
        let config = tls_config().unwrap();
        assert!(!config.enable_early_data);
        assert_eq!(config.crypto_provider().kx_groups.len(), 2);
        assert_eq!(
            config.crypto_provider().kx_groups.first().map(|g| g.name()),
            Some(rustls::NamedGroup::X25519MLKEM768)
        );
    }
}
