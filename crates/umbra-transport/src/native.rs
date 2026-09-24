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

fn socket_addr(dial: &Dial, prefer_v6: bool) -> Option<SocketAddr> {
    let v6 = dial
        .addr_v6
        .map(|a| SocketAddr::from((std::net::Ipv6Addr::from(a), dial.port)));
    let v4 = dial
        .addr_v4
        .map(|a| SocketAddr::from((std::net::Ipv4Addr::from(a), dial.port)));
    if prefer_v6 {
        v6.or(v4)
    } else {
        v4.or(v6)
    }
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

/// One `GET` of `path` from an HTTPS carrier, with a body of `max` bytes at
/// most.
async fn fetch_carried(
    dial: &Dial,
    config: Arc<ClientConfig>,
    path: &str,
    max: usize,
) -> Result<Vec<u8>, NativeError> {
    let addr = socket_addr(dial, false).ok_or(Error::Refused)?;
    let tcp = TcpStream::connect(addr).await?;
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
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        // This client reads a body of a plain length alone.
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(Error::Refused.into());
        }
        if name.eq_ignore_ascii_case("Content-Length")
            && value.trim().parse::<usize>().ok() != Some(body.len())
        {
            return Err(Error::Refused.into());
        }
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
        let addr = socket_addr(dial, false).ok_or(Error::Refused)?;
        let tcp = TcpStream::connect(addr).await?;
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
        let addr = socket_addr(dial, false).ok_or(Error::Refused)?;
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

    /// Receives one capsule, delimited by its own header.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        loop {
            if let Ok((_, value, used)) = umbra_wire::capsule::parse(&self.inbound) {
                let out = value.to_vec();
                self.inbound.drain(..used);
                return Ok(out);
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
