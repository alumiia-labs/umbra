//! The native L1 stack of Part 14 §14.2.8: TLS 1.3 through rustls on the
//! aws-lc-rs provider, QUIC through quinn, both on tokio.
//!
//! The client configuration is one shape for every client (Part 3 §3.8):
//! `X25519MLKEM768` first and `X25519` second as the only groups
//! (`NET-214`, `NET-215`), TLS 1.3 only (`IMP-068`), no resumption and no
//! early data (`NET-073`), and GREASE ECH.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
    time::Duration,
};

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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
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
    // A TLS stream can hold a written record until its flush.
    stream.flush().await?;

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

/// The bytes that a [`Coalesced`] stream holds before it writes. A group of
/// frames stays at or below it. A TLS session seals only part of a write when
/// its own buffer holds 64 KiB, and the rest then takes another record. With
/// this bound no frame waits for the socket in the middle of a group, thus
/// that buffer stays empty, and each frame takes its own record under
/// backpressure too (`WIR-225`).
pub const WRITE_HELD: usize = 64 << 10;
/// The capacity of its buffer that a [`Coalesced`] stream keeps after a
/// write. A link that had a burst then costs the relay little while it idles.
const HELD_KEPT: usize = 4 << 10;
/// The plain bytes of one TLS record (RFC 8446 §5.1).
const RECORD_PLAIN: usize = 16 << 10;
/// What one TLS record adds: the header, the content type, and the tag.
const RECORD_ADDS: usize = 22;
/// The bytes that a [`Coalesced`] stream asks of its socket in one read. The
/// TLS session reads 4 KiB at a time. A `B3` cell then took nine reads.
const READ_AHEAD: usize = 32 << 10;
/// The room for one read in a buffer of capsules.
pub const READ_ROOM: usize = 16 << 10;

/// The bytes on the socket for a capsule of `capsule_len` bytes, in a masked
/// frame. An unmasked frame takes 4 bytes less.
pub const fn wire_len(capsule_len: usize) -> usize {
    let frame = websocket::frame_len(capsule_len, true);
    frame + frame.div_ceil(RECORD_PLAIN) * RECORD_ADDS
}

/// What a writer of a link and the [`Coalesced`] stream under its TLS session
/// share.
#[derive(Debug, Default)]
pub struct WriteState {
    holding: AtomicBool,
    reads_ahead: AtomicBool,
    sent: AtomicUsize,
}

impl WriteState {
    /// The stream holds each write from now on, until the next flush.
    pub fn hold(&self) {
        self.holding.store(true, Ordering::Relaxed);
    }

    /// The stream reads ahead from now on. A socket before its upgrade
    /// holds no buffer for it (`NET-333`).
    pub fn read_ahead(&self) {
        self.reads_ahead.store(true, Ordering::Relaxed);
    }

    /// The bytes that the socket took so far. The count wraps.
    pub fn sent(&self) -> usize {
        self.sent.load(Ordering::Relaxed)
    }
}

/// The socket under a TLS session. Between a [`WriteState::hold`] and the
/// next flush it holds what the session writes, thus the records of a group
/// of capsules take one write of the socket. Each other write goes straight
/// through, thus the handshake and an alert keep their place on the wire. An
/// alert that the session seals while a group is held waits for that group,
/// and it is lost when the link ends first.
///
/// A TLS session seals one record at each write to it while its own buffer
/// holds room. A group at or below [`WRITE_HELD`] keeps that buffer empty,
/// thus each frame takes its own record (`WIR-225`, `WIR-227`). No byte
/// waits for a later byte: a caller holds only the capsules that wait, and
/// it flushes after them. After [`WriteState::read_ahead`] the stream also
/// reads ahead, thus some records take one read of the socket.
pub struct Coalesced<S> {
    stream: S,
    state: Arc<WriteState>,
    held: Vec<u8>,
    written: usize,
    ahead: Vec<u8>,
    ahead_used: usize,
    ahead_filled: usize,
}

impl<S> Coalesced<S> {
    /// The stream over `stream`.
    pub fn new(stream: S) -> Self {
        Coalesced {
            stream,
            state: Arc::default(),
            held: Vec::new(),
            written: 0,
            ahead: Vec::new(),
            ahead_used: 0,
            ahead_filled: 0,
        }
    }

    /// What this stream shares with the writer of its link.
    pub fn state(&self) -> Arc<WriteState> {
        self.state.clone()
    }
}

impl<S: AsyncWrite + Unpin> Coalesced<S> {
    /// Writes each byte that waits to the socket.
    fn write_held(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(rest) = self
            .held
            .get(self.written..)
            .filter(|rest| !rest.is_empty())
        {
            let count = ready!(Pin::new(&mut self.stream).poll_write(cx, rest))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }

            self.written = self.written.saturating_add(count);
            self.state.sent.fetch_add(count, Ordering::Relaxed);
        }

        self.written = 0;
        self.held.clear();
        if self.held.capacity() > HELD_KEPT {
            self.held = Vec::new();
        }

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Coalesced<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.ahead.is_empty() {
            if !this.state.reads_ahead.load(Ordering::Relaxed) {
                return Pin::new(&mut this.stream).poll_read(cx, out);
            }

            this.ahead = vec![0u8; READ_AHEAD];
        }

        if this.ahead_used == this.ahead_filled {
            let mut room = ReadBuf::new(&mut this.ahead);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut room))?;
            this.ahead_filled = room.filled().len();
            this.ahead_used = 0;
        }

        let waiting = this
            .ahead
            .get(this.ahead_used..this.ahead_filled)
            .unwrap_or(&[]);
        let count = waiting.len().min(out.remaining());
        out.put_slice(waiting.get(..count).unwrap_or(&[]));
        this.ahead_used = this.ahead_used.saturating_add(count);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Coalesced<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.state.holding.load(Ordering::Relaxed) {
            ready!(this.write_held(cx))?;
            let count = ready!(Pin::new(&mut this.stream).poll_write(cx, bytes))?;
            this.state.sent.fetch_add(count, Ordering::Relaxed);
            return Poll::Ready(Ok(count));
        }

        if this.held.len() >= WRITE_HELD {
            ready!(this.write_held(cx))?;
        }

        this.held.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    // A frame that goes alone takes its records in one write of the socket,
    // as with no stream here. A `B3` frame is three records.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.state.holding.load(Ordering::Relaxed) {
            ready!(this.write_held(cx))?;
            let count = ready!(Pin::new(&mut this.stream).poll_write_vectored(cx, bufs))?;
            this.state.sent.fetch_add(count, Ordering::Relaxed);
            return Poll::Ready(Ok(count));
        }

        let first = bufs.iter().find(|buf| !buf.is_empty());
        Pin::new(this).poll_write(cx, first.map_or(&[], |buf| &**buf))
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.write_held(cx))?;
        this.state.holding.store(false, Ordering::Relaxed);
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.write_held(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

/// The TLS stream of a [`TcpLink`].
type LinkStream = tokio_rustls::client::TlsStream<Coalesced<TcpStream>>;

/// The mask of frame number `counter` from the seed of a link.
fn mask_of(seed: &[u8; 4], counter: u64) -> [u8; 4] {
    // A fresh mask for each frame, from the seed and a counter. The mask
    // hides nothing from TLS; RFC 6455 wants it different for each frame.
    let c = counter.to_le_bytes();
    [
        seed[0] ^ c[0],
        seed[1] ^ c[1],
        seed[2] ^ c[2],
        seed[3] ^ c[3],
    ]
}

/// Writes `capsule` as one masked frame, thus in one TLS record when it
/// fits one (`WIR-225`). The caller flushes.
async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    capsule: &[u8],
    mask: &[u8; 4],
    frame: &mut Vec<u8>,
) -> Result<(), NativeError> {
    frame.resize(websocket::frame_len(capsule.len(), true), 0);
    let used = websocket::encode(capsule, Some(mask), frame)?;
    stream.write_all(frame.get(..used).unwrap_or(&[])).await?;
    Ok(())
}

/// The stream, the mask, and the buffer of the frames of one link.
struct FrameWriter<W> {
    stream: W,
    state: Arc<WriteState>,
    frame: Vec<u8>,
    mask: [u8; 4],
    counter: u64,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Sends each capsule of `capsules` in its own frame and its own TLS
    /// record. Frames share one write of the socket up to `WRITE_HELD`
    /// bytes. A larger group flushes between two frames, thus no frame
    /// waits for the socket with the session in the middle of a group. A
    /// frame that goes alone has nothing to share a write with, and the
    /// stream holds no copy of it.
    async fn write_group<C: AsRef<[u8]>>(&mut self, capsules: &[C]) -> Result<(), NativeError> {
        let mut waiting = 0usize;
        if capsules.len() > 1 {
            self.state.hold();
        }

        for capsule in capsules {
            let capsule = capsule.as_ref();
            let wire = wire_len(capsule.len());

            if waiting > 0 && waiting.saturating_add(wire) > WRITE_HELD {
                self.stream.flush().await?;
                self.state.hold();
                waiting = 0;
            }

            self.counter = self.counter.wrapping_add(1);
            let mask = mask_of(&self.mask, self.counter);
            write_frame(&mut self.stream, capsule, &mask, &mut self.frame).await?;
            waiting = waiting.saturating_add(wire);
        }

        self.stream.flush().await?;
        Ok(())
    }
}

/// A TCP connection after the TLS handshake and the upgrade. Each capsule
/// travels in one masked WebSocket frame.
pub struct TcpLink {
    writer: FrameWriter<LinkStream>,
    inbound: Vec<u8>,
    /// The bytes of `inbound` that earlier capsules took.
    taken: usize,
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
        let socket = Coalesced::new(tcp);
        let state = socket.state();
        let mut stream = connector.connect(name, socket).await?;

        stream
            .write_all(upgrade::request(&dial.host, &key).as_bytes())
            .await?;
        // A TLS stream can hold a written record until its flush.
        stream.flush().await?;

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
        state.read_ahead();
        Ok(TcpLink {
            writer: FrameWriter {
                stream,
                state,
                frame: Vec::new(),
                mask: mask_seed,
                counter: 0,
            },
            inbound,
            taken: 0,
        })
    }

    /// Sends one capsule.
    pub async fn send(&mut self, capsule: &[u8]) -> Result<(), NativeError> {
        self.writer
            .write_group(core::slice::from_ref(&capsule))
            .await
    }

    /// Receives one capsule. A caller may drop this call while it waits:
    /// the bytes of a frame stay in `inbound`.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        loop {
            let rest = self.inbound.get(self.taken..).unwrap_or(&[]);
            if let Some((capsule, used)) = websocket::decode_owned(rest, false, MAX_CAPSULE)? {
                self.taken = self.taken.saturating_add(used);
                return Ok(capsule);
            }

            self.inbound.drain(..self.taken);
            self.taken = 0;
            self.inbound.reserve(READ_ROOM);

            let n = self.writer.stream.read_buf(&mut self.inbound).await?;
            if n == 0 {
                return Err(Error::Refused.into());
            }
        }
    }
}

impl TcpLink {
    /// The two halves of the link, for a party that sends and receives at
    /// the same time: the measurer of Part 10 §10.3 sends at its rate
    /// while the echoes come back.
    pub fn split(self) -> (TcpReader, TcpWriter) {
        let writer = self.writer;
        let (read, write) = tokio::io::split(writer.stream);
        (
            TcpReader {
                stream: read,
                inbound: self.inbound,
                taken: self.taken,
            },
            TcpWriter(FrameWriter {
                stream: write,
                state: writer.state,
                frame: writer.frame,
                mask: writer.mask,
                counter: writer.counter,
            }),
        )
    }
}

/// The receiving half of a [`TcpLink`].
pub struct TcpReader {
    stream: tokio::io::ReadHalf<LinkStream>,
    inbound: Vec<u8>,
    /// The bytes of `inbound` that earlier capsules took.
    taken: usize,
}

impl TcpReader {
    /// Receives one capsule.
    pub async fn recv(&mut self) -> Result<Vec<u8>, NativeError> {
        loop {
            let rest = self.inbound.get(self.taken..).unwrap_or(&[]);
            if let Some((capsule, used)) = websocket::decode_owned(rest, false, MAX_CAPSULE)? {
                self.taken = self.taken.saturating_add(used);
                return Ok(capsule);
            }

            self.inbound.drain(..self.taken);
            self.taken = 0;
            self.inbound.reserve(READ_ROOM);

            let n = self.stream.read_buf(&mut self.inbound).await?;
            if n == 0 {
                return Err(Error::Refused.into());
            }
        }
    }
}

/// The sending half of a [`TcpLink`].
pub struct TcpWriter(FrameWriter<tokio::io::WriteHalf<LinkStream>>);

impl TcpWriter {
    /// Sends each capsule of `capsules` in its own frame and its own TLS
    /// record, in as few writes of the socket as `WRITE_HELD` gives.
    pub async fn send_all(&mut self, capsules: &[Vec<u8>]) -> Result<(), NativeError> {
        self.0.write_group(capsules).await
    }

    /// What this writer shares with the socket of its link.
    pub fn state(&self) -> Arc<WriteState> {
        self.0.state.clone()
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::Mutex;

    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use tokio::io::DuplexStream;

    use super::*;

    /// A socket that keeps each write that reaches it.
    struct Recorder {
        stream: DuplexStream,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_read(cx, out)
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let count = ready!(Pin::new(&mut this.stream).poll_write(cx, bytes))?;
            let taken = bytes.get(..count).unwrap().to_vec();
            this.writes.lock().unwrap().push(taken);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
        }
    }

    /// A socket that keeps its writes, and the writes it keeps.
    fn recorder() -> (Recorder, DuplexStream, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (stream, peer) = tokio::io::duplex(1 << 20);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let socket = Recorder {
            stream,
            writes: writes.clone(),
        };
        (socket, peer, writes)
    }

    #[tokio::test]
    async fn a_coalesced_stream_writes_at_a_flush_and_at_its_bound() {
        let (socket, mut peer, writes) = recorder();
        let mut stream = Coalesced::new(socket);
        let state = stream.state();

        // With no group, each write goes straight through.
        stream.write_all(b"first").await.unwrap();
        assert_eq!(*writes.lock().unwrap(), [b"first".to_vec()]);
        assert_eq!(state.sent(), 5);
        writes.lock().unwrap().clear();

        state.hold();
        stream.write_all(b"one").await.unwrap();
        stream.write_all(b"two").await.unwrap();
        assert!(writes.lock().unwrap().is_empty());

        stream.flush().await.unwrap();
        assert_eq!(*writes.lock().unwrap(), [b"onetwo".to_vec()]);

        // What waits stays below the bound, whatever a caller writes
        // before its flush.
        state.hold();
        let block = vec![0x5A; 40 << 10];
        for _ in 0..3 {
            stream.write_all(&block).await.unwrap();
        }
        assert_eq!(writes.lock().unwrap().len(), 2);

        stream.flush().await.unwrap();
        assert_eq!(writes.lock().unwrap().len(), 3);
        assert!(stream.held.capacity() <= HELD_KEPT);

        // A socket before its upgrade holds no buffer of a read.
        peer.write_all(b"before").await.unwrap();
        let mut taken = [0u8; 6];
        stream.read_exact(&mut taken).await.unwrap();
        assert_eq!(&taken, b"before");
        assert!(stream.ahead.is_empty());

        // A read takes what the peer wrote, in its order, across the reads
        // of a TLS session.
        state.read_ahead();
        peer.write_all(&vec![7; READ_AHEAD + 10]).await.unwrap();
        let mut taken = vec![0u8; READ_AHEAD + 10];
        stream.read_exact(&mut taken).await.unwrap();
        assert_eq!(taken, vec![7; READ_AHEAD + 10]);
        assert_eq!(stream.ahead.len(), READ_AHEAD);

        // A shutdown writes what waits.
        state.hold();
        stream.write_all(b"end").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(writes.lock().unwrap().last().unwrap(), b"end");
    }

    /// The lengths of the application records in `wire`.
    fn record_lengths(wire: &[u8]) -> Vec<usize> {
        let mut lengths = Vec::new();
        let mut rest = wire;
        while let Some((head, tail)) = rest.split_first_chunk::<5>() {
            assert_eq!(head[0], 23);
            let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
            lengths.push(len);
            rest = tail.get(len..).unwrap();
        }

        assert!(rest.is_empty());
        lengths
    }

    fn fixture(name: &str) -> String {
        format!(
            "{}/../../tests/fixtures/tls/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    fn server_config() -> Arc<rustls::ServerConfig> {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(fixture("leaf.pem"))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_file(fixture("leaf.key")).unwrap();
        let provider = Arc::new(aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        Arc::new(config)
    }

    type Writes = Arc<Mutex<Vec<Vec<u8>>>>;
    type Client = tokio_rustls::client::TlsStream<Coalesced<Recorder>>;
    type Server = tokio_rustls::server::TlsStream<DuplexStream>;

    /// The two ends of a TLS session over a socket that holds `capacity`
    /// bytes, under the default send bound of the session.
    async fn tls_pair(capacity: usize) -> (Client, Server, Writes) {
        let (stream, peer) = tokio::io::duplex(capacity);
        let writes = Writes::default();
        let socket = Recorder {
            stream,
            writes: writes.clone(),
        };

        let connector = tokio_rustls::TlsConnector::from(
            tls_config_with_root_file(&fixture("ca.pem")).unwrap(),
        );
        let name = ServerName::try_from("localhost").unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config());

        let (client, server) = tokio::join!(
            connector.connect(name, Coalesced::new(socket)),
            acceptor.accept(peer)
        );

        writes.lock().unwrap().clear();
        (client.unwrap(), server.unwrap(), writes)
    }

    fn frame_writer(client: Client) -> FrameWriter<Client> {
        let state = client.get_ref().0.state();
        FrameWriter {
            stream: client,
            state,
            frame: Vec::new(),
            mask: [1, 2, 3, 4],
            counter: 0,
        }
    }

    /// How a run of frames of `capsule_len` bytes took its records.
    fn frames_off_count(wire: &[u8], capsule_len: usize) -> (usize, usize) {
        let frame_len = websocket::frame_len(capsule_len, true);
        let count = frame_len.div_ceil(RECORD_PLAIN);
        let mut plain: Vec<usize> = record_lengths(wire).iter().map(|len| len - 17).collect();
        // The `close_notify` of the shutdown.
        plain.pop();

        let (mut frames, mut off) = (0usize, 0usize);
        let (mut in_frame, mut records) = (0usize, 0usize);

        for len in plain {
            in_frame += len;
            records += 1;
            assert!(in_frame <= frame_len, "two frames share a record");

            if in_frame == frame_len {
                frames += 1;
                off += usize::from(records != count);
                in_frame = 0;
                records = 0;
            }
        }

        assert_eq!(in_frame, 0);
        (frames, off)
    }

    /// Drains the far end slowly, thus the socket of a run stays full.
    fn slow_reader(mut server: Server) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut chunk = vec![0u8; 1_024];
            while matches!(server.read(&mut chunk).await, Ok(n) if n > 0) {
                tokio::task::yield_now().await;
            }
        })
    }

    /// The bucket capsules, with the frames of one group and the groups of
    /// one run: a group is 132 KB, 255 KB, or 230 KB, above each default of
    /// the stack.
    const BURSTS: [(usize, usize, usize); 6] = [
        (530, 64, 6),
        (2_066, 64, 6),
        (8_210, 31, 3),
        (32_786, 7, 3),
        (530, 1, 64),
        (32_786, 1, 16),
    ];

    #[tokio::test]
    async fn each_frame_keeps_its_record_on_a_socket_that_stays_full() {
        for (capsule_len, frames, groups) in BURSTS {
            let (client, server, writes) = tls_pair(4 << 10).await;
            let reader = slow_reader(server);
            let mut writer = frame_writer(client);
            let capsules = vec![vec![0xA5u8; capsule_len]; frames];

            for _ in 0..groups {
                writer.write_group(&capsules).await.unwrap();
            }

            // A frame that goes alone leaves no copy in the stream.
            if frames == 1 {
                assert_eq!(writer.stream.get_ref().0.held.capacity(), 0);
            }

            writer.stream.shutdown().await.unwrap();
            drop(writer);
            reader.await.unwrap();

            let wire = writes.lock().unwrap().concat();
            let (whole, off) = frames_off_count(&wire, capsule_len);
            assert_eq!((whole, off), (frames * groups, 0), "{capsule_len}");
        }
    }

    /// One group of `frames` frames with no flush between them, on a socket
    /// that stays full. The result is the count of the frames that took
    /// another count of records than `WIR-225` and `WIR-226` give.
    async fn one_held_group(capsule_len: usize, frames: usize) -> usize {
        let (client, server, writes) = tls_pair(4 << 10).await;
        let reader = slow_reader(server);
        let mut writer = frame_writer(client);
        let capsule = vec![0xA5u8; capsule_len];
        let mut frame = Vec::new();

        writer.state.hold();
        for _ in 0..frames {
            write_frame(&mut writer.stream, &capsule, &[1, 2, 3, 4], &mut frame)
                .await
                .unwrap();
        }

        writer.stream.flush().await.unwrap();
        writer.stream.shutdown().await.unwrap();
        drop(writer);
        reader.await.unwrap();

        let wire = writes.lock().unwrap().concat();
        let (whole, off) = frames_off_count(&wire, capsule_len);
        assert_eq!(whole, frames);
        off
    }

    #[tokio::test]
    async fn a_held_group_stays_whole_up_to_the_bound_of_one_write() {
        // WIR-225: a group of 260 KB splits a frame under the default send
        // bound. This shows that the test finds that fault.
        assert!(one_held_group(2_066, 124).await > 0);

        // The largest group of each bucket inside `WRITE_HELD`.
        for (capsule_len, frames) in [(530, 64), (2_066, 31), (8_210, 7), (32_786, 1)] {
            assert!(frames * wire_len(capsule_len) <= WRITE_HELD);
            assert_eq!(
                one_held_group(capsule_len, frames).await,
                0,
                "{capsule_len}"
            );
        }
    }

    /// What a peer gets for a broken `ClientHello`.
    async fn answer_to_a_broken_hello<S>(ours: S, mut peer: DuplexStream) -> Vec<u8>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let bad = [
            0x16u8, 0x03, 0x03, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0xFF, 0xFF,
        ];
        peer.write_all(&bad).await.unwrap();

        let accept =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), ours);
        assert!(accept.await.is_err());

        let mut got = Vec::new();
        let _ = peer.read_to_end(&mut got).await;
        got
    }

    #[tokio::test]
    async fn an_alert_of_a_handshake_reaches_the_wire_as_on_a_plain_socket() {
        let (ours, peer) = tokio::io::duplex(1 << 16);
        let plain = answer_to_a_broken_hello(ours, peer).await;
        assert_eq!(plain[..3], [0x15, 0x03, 0x03]);

        let (ours, peer) = tokio::io::duplex(1 << 16);
        let coalesced = answer_to_a_broken_hello(Coalesced::new(ours), peer).await;
        assert_eq!(coalesced, plain);
    }

    #[tokio::test]
    async fn a_b3_frame_that_goes_alone_takes_one_write_of_its_three_records() {
        let (client, _server, writes) = tls_pair(1 << 20).await;
        let mut writer = frame_writer(client);

        writer.write_group(&[vec![0xA5u8; 32_786]]).await.unwrap();

        let writes = writes.lock().unwrap();
        let wire = writes.concat();
        assert_eq!(record_lengths(&wire).len(), 3);
        assert_eq!(wire.len(), wire_len(32_786));
    }

    #[tokio::test]
    async fn each_frame_keeps_its_own_record_and_a_group_takes_one_write() {
        let (client, _server, writes) = tls_pair(1 << 20).await;
        let mut writer = frame_writer(client);

        // Two `B0` capsules and one `B3` capsule.
        let capsules = [vec![0xA5u8; 530], vec![0xA5; 530], vec![0xA5; 32_786]];
        writer.write_group(&capsules).await.unwrap();

        // WIR-225, WIR-226, WIR-227: each record holds one frame or a part
        // of the one frame that fits no record. The inner content type and
        // the tag add 17 bytes to each record, and the header adds 5.
        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1);

        let lengths = record_lengths(&writes[0]);
        let plain: Vec<usize> = lengths.iter().map(|len| len - 17).collect();
        assert_eq!(plain.len(), 5);
        assert_eq!(plain[..2], [538, 538]);
        assert_eq!(plain[2..].iter().sum::<usize>(), 32_794);
    }

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
        // The port must be free at the IPv4 loopback, thus a dial there is
        // refused.
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
