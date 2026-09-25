//! The runtime of the relay over tokio: one task owns the node, and each
//! connection is a task that moves capsules between its socket and that
//! task. The node stays a plain state machine, thus this file holds the
//! clock, the random source, and the sockets, and no protocol rule.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use umbra_core::{abuse::POW_CHALLENGE_PERIOD, group::backoff::exponential};
use umbra_crypto::{
    rand_core::{TryCryptoRng, TryRng},
    secret::Secret,
};
use umbra_transport::{
    https, native,
    ndr::{self, NdrRoute},
    race::{Plan, Wire},
    Dial,
};
use umbra_transport::{upgrade, websocket};
use umbra_wire::ndr::NdrResponse;

use crate::{
    circuits::{CircuitKey, LinkId},
    node::{Output, RelayNode},
    service::queue::NdrPush,
    store::RelayStore,
};

/// The mean of the pacing clock of a circuit, in milliseconds (Part 3
/// §3.9).
pub const PACING_MEAN_MS: u64 = 1_000;
/// The period of the housekeeping sweep, in seconds.
pub const SWEEP_PERIOD: u64 = 60;
/// The largest capsule: a `B3` cell with its frame and its header.
pub const MAX_CAPSULE: usize = 32_768 + 12 + 6;

/// The entropy of the operating system. A relay that cannot draw a random
/// value stops, because each identifier and each key of a circuit needs
/// one.
pub struct OsRng;

impl TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if getrandom::fill(dst).is_err() {
            std::process::abort();
        }
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

/// What a connection task and the dialer tell the node task.
pub enum Input {
    /// A connection opened. The node task writes its capsules to `writer`.
    Opened {
        /// The link.
        link: LinkId,
        /// The capsules to write.
        writer: mpsc::UnboundedSender<Vec<u8>>,
    },
    /// The dialer reached a relay of the next layer.
    Dialed {
        /// The link.
        link: LinkId,
        /// The relay.
        relay_id: [u8; 32],
        /// The capsules to write.
        writer: mpsc::UnboundedSender<Vec<u8>>,
    },
    /// One capsule arrived.
    Capsule {
        /// The link.
        link: LinkId,
        /// The capsule bytes.
        bytes: Vec<u8>,
    },
    /// The connection closed.
    Closed {
        /// The link.
        link: LinkId,
    },
    /// The NDR answered `gone` for a handle of a push of this relay.
    NdrGone {
        /// The handle.
        handle: [u8; 16],
    },
}

/// What the node task asks of the process around it.
pub enum Request {
    /// Dial a relay of the next layer.
    Dial([u8; 32]),
    /// Send one capsule to another relay: a chunk copy or a deposit.
    Push {
        /// The relay that takes the copy.
        relay_id: [u8; 32],
        /// One `UMBRA_REPLICA` capsule.
        capsule: Vec<u8>,
    },
    /// Send one `NPUSH` to the NDR.
    NdrPush(NdrPush),
    /// The newest challenge of each relay moved, for the carrier to serve
    /// (`ABU-104`).
    Challenges(Vec<u8>),
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs the node until each sender of `inputs` closes, or until the store
/// fails. `store` takes the changes of each call of the node before an
/// output of that call leaves (`NET-298`). A relay that cannot write stops,
/// because it can acknowledge nothing.
pub async fn run_node(
    mut node: RelayNode,
    mut inputs: mpsc::Receiver<Input>,
    requests: mpsc::UnboundedSender<Request>,
    pacing_mean_ms: u64,
    mut store: Box<dyn RelayStore>,
) {
    let mut rng = OsRng;
    let mut writers: BTreeMap<LinkId, mpsc::UnboundedSender<Vec<u8>>> = BTreeMap::new();
    let mut next_tick: BTreeMap<CircuitKey, tokio::time::Instant> = BTreeMap::new();
    let mut clock =
        tokio::time::interval(Duration::from_millis((pacing_mean_ms / 20).clamp(1, 50)));
    let mut last_sweep = unix_now();
    let mut last_push_tick = last_sweep;
    // ABU-057: the first challenge at the start, and a new one at each
    // period.
    let mut last_challenge: Option<u64> = None;
    loop {
        let outputs = tokio::select! {
            input = inputs.recv() => match input {
                None => return,
                Some(Input::Opened { link, writer }) => {
                    writers.insert(link, writer);
                    Vec::new()
                }
                Some(Input::Dialed { link, relay_id, writer }) => {
                    writers.insert(link, writer);
                    let mut session_id = [0u8; 8];
                    let mut secret = [0u8; 32];
                    let _ = rng.try_fill_bytes(&mut session_id);
                    let _ = rng.try_fill_bytes(&mut secret);
                    node.dialed(link, relay_id, session_id, Secret::new(secret), unix_now(), &mut rng)
                }
                Some(Input::Capsule { link, bytes }) => {
                    node.on_capsule(link, &bytes, unix_now(), &mut rng)
                }
                Some(Input::Closed { link }) => {
                    writers.remove(&link);
                    node.link_closed(link, unix_now())
                }
                Some(Input::NdrGone { handle }) => {
                    node.ndr_gone(&handle);
                    Vec::new()
                }
            },
            _ = clock.tick() => {
                let now = unix_now();
                let instant = tokio::time::Instant::now();
                let mut outputs = Vec::new();
                // NET-035, NET-036: a Poisson clock for each circuit, which
                // no arrival moves.
                let paced: Vec<CircuitKey> = node.paced_circuits().copied().collect();
                next_tick.retain(|circuit, _| paced.contains(circuit));
                for circuit in paced {
                    let due = next_tick.entry(circuit).or_insert(instant);
                    if *due <= instant {
                        outputs.extend(node.pacing_tick(&circuit, now, &mut rng));
                        let mut draw = [0u8; 4];
                        let _ = rng.try_fill_bytes(&mut draw);
                        let wait = exponential(pacing_mean_ms, u32::from_le_bytes(draw));
                        *due = instant + Duration::from_millis(wait.max(1));
                    }
                }
                // NTF-049, NTF-066: the end of a coalescing window and
                // each re-push, once each second.
                if now > last_push_tick {
                    last_push_tick = now;
                    outputs.extend(node.push_tick(now, &mut rng));
                }
                if now.saturating_sub(last_sweep) >= SWEEP_PERIOD {
                    last_sweep = now;
                    outputs.extend(node.sweep(now, &mut rng));
                }
                if last_challenge.is_none_or(|at| now.saturating_sub(at) >= POW_CHALLENGE_PERIOD) {
                    last_challenge = Some(now);
                    outputs.extend(node.issue_challenge(now, &mut rng));
                }
                outputs
            }
        };
        if store.commit(&node.take_changes()).is_err() {
            eprintln!("the store took no commit, and the relay stops");
            return;
        }
        if let Some(bundle) = node.take_challenge_bundle(unix_now()) {
            let _ = requests.send(Request::Challenges(bundle));
        }
        for output in outputs {
            match output {
                Output::Send { link, capsule } => {
                    if let Some(writer) = writers.get(&link) {
                        let _ = writer.send(capsule);
                    }
                }
                Output::Close { link } => {
                    writers.remove(&link);
                }
                Output::Dial { relay_id } => {
                    let _ = requests.send(Request::Dial(relay_id));
                }
                Output::Push { relay_id, capsule } => {
                    let _ = requests.send(Request::Push { relay_id, capsule });
                }
                Output::NdrPush(push) => {
                    let _ = requests.send(Request::NdrPush(push));
                }
            }
        }
    }
}

/// Sends one copy of a chunk on a connection of its own, and ends that
/// connection (`WIR-211`). A copy that does not arrive gets no second send:
/// the uploader finds it with its sample, and it names another relay
/// (`ATT-113`, `ATT-118`).
async fn push_copy(target: Dial, tls: Arc<rustls::ClientConfig>, capsule: Vec<u8>) {
    let mut rng = OsRng;
    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    if let Ok(mut connection) =
        native::connect(&target, tls, plan, key, mask, Duration::from_secs(10)).await
    {
        let _ = connection.send(&capsule).await;
    }
}

/// The path of the OHTTP relay of Part 8 §8.2 (`NTF-127`).
pub const OHTTP_PATH: &str = "/ohttp";
/// The longest encapsulated request: the header, the encapsulation, one
/// NDR request, and the tag.
const OHTTP_REQUEST_MAX: usize = 4_096;
/// The longest encapsulated response.
const OHTTP_RESPONSE_MAX: usize = 256;
/// The wait for the gateway, which waits for the provider in turn.
const OHTTP_WAIT: Duration = Duration::from_secs(15);

/// The gateway that the OHTTP relay role posts to.
pub struct OhttpForward {
    /// The URL of the gateway of the NDR.
    pub gateway: https::Url,
    /// The configuration that this relay trusts the gateway under.
    pub tls: Arc<rustls::ClientConfig>,
}

/// What a relay carries over HTTPS beside the upgrade: the manifest of
/// The limits of the connections of one relay (Part 3 `NET-333` to
/// `NET-335`).
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// `RELAY_CONN_MAX`: the connections that the relay holds at once.
    pub max_connections: usize,
    /// `RELAY_CONN_PER_IP`: the connections of one address at once, or 0
    /// for none. An ingress relay sets it; a loopback address is exempt.
    pub per_ip_max: usize,
    /// `RELAY_HANDSHAKES_MAX`: the TLS handshakes that run at once.
    pub handshakes_max: usize,
    /// `RELAY_HANDSHAKE_TIMEOUT`: the time from the accept to the upgrade.
    pub handshake_timeout: Duration,
}

impl ConnectionLimits {
    /// `RELAY_CONN_MAX` of Part 3 §3.13.
    pub const CONN_MAX: usize = 20_000;
    /// `RELAY_CONN_PER_IP` of Part 3 §3.13.
    pub const CONN_PER_IP: usize = 32;
    /// `RELAY_HANDSHAKES_MAX` of Part 3 §3.13.
    pub const HANDSHAKES_MAX: usize = 512;
    /// `RELAY_HANDSHAKE_TIMEOUT` of Part 3 §3.13.
    pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        ConnectionLimits {
            max_connections: Self::CONN_MAX,
            per_ip_max: 0,
            handshakes_max: Self::HANDSHAKES_MAX,
            handshake_timeout: Self::HANDSHAKE_TIMEOUT,
        }
    }
}

/// The connections of each address that the per-address cap counts.
type PerIp = Arc<Mutex<BTreeMap<IpAddr, usize>>>;

/// One held connection: it counts against the limits until it drops.
struct Held {
    open: Arc<AtomicUsize>,
    per_ip: Option<(PerIp, IpAddr)>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
        if let Some((per_ip, ip)) = &self.per_ip {
            if let Ok(mut held) = per_ip.lock() {
                if let Some(count) = held.get_mut(ip) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        held.remove(ip);
                    }
                }
            }
        }
    }
}

/// Part 3 §3.10, the OHTTP relay role of Part 8 §8.2, and the route of the
/// pushes of its own queues.
#[derive(Default)]
pub struct Carried {
    /// The manifest, for a client that asks for it.
    pub manifest: Option<Vec<u8>>,
    /// The gateway, for a relay with the OHTTP relay role.
    pub ohttp: Option<OhttpForward>,
    /// The route to the NDR that a queue relay pins (`NTF-127`), and the
    /// configuration it trusts the OHTTP relay under. A relay with none
    /// sends no push.
    pub ndr: Option<(NdrRoute, Arc<rustls::ClientConfig>)>,
    /// The newest challenge of each relay, which a carrier of the manifest
    /// serves beside it (`ABU-104`). The node moves it.
    pub challenges: std::sync::Mutex<Vec<u8>>,
    /// The limits of the connections (`NET-333` to `NET-335`).
    pub limits: ConnectionLimits,
}

/// Forwards one encapsulated request to the gateway and gives its answer
/// back (`NTF-127`). The relay reads no byte of either, it keeps neither,
/// and the gateway sees this relay alone.
async fn relay_ohttp<S>(stream: &mut S, inbound: &mut Vec<u8>, forward: Option<&OhttpForward>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let answer = match (
        forward,
        https::read_request(stream, inbound, OHTTP_REQUEST_MAX).await,
    ) {
        (Some(forward), Ok(request)) if request.method == "POST" => https::post(
            &forward.gateway,
            "message/ohttp-req",
            &[],
            &request.body,
            forward.tls.clone(),
            OHTTP_RESPONSE_MAX,
            OHTTP_WAIT,
        )
        .await
        .ok()
        .filter(|(status, _)| *status == 200)
        .map(|(_, body)| body),
        _ => None,
    };
    let _ = match answer {
        Some(body) => https::respond(stream, 200, "message/ohttp-res", &body).await,
        None => https::respond(stream, 502, "text/plain", &[]).await,
    };
}

/// Serves one accepted connection: the HTTP upgrade of Part 6 §6.2.1, and
/// then one capsule in each WebSocket frame, in both directions. The
/// function returns when either side closes.
///
/// A request for the relay manifest gets the manifest and the end of the
/// connection (Part 3 §3.10). In a deployment the co-tenant site of Part 3
/// §3.8 serves that path, and the relay sees no such request. A `POST` to
/// `OHTTP_PATH` goes to the gateway of the NDR.
pub async fn serve_connection<S>(
    mut stream: S,
    link: LinkId,
    node: mpsc::Sender<Input>,
    carried: Arc<Carried>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut inbound: Vec<u8> = Vec::with_capacity(4_096);
    let mut chunk = vec![0u8; 16_384];
    // NET-335: a peer that sends no complete request in time is closed.
    let deadline = tokio::time::Instant::now() + carried.limits.handshake_timeout;
    let request = loop {
        if inbound.starts_with(format!("POST {OHTTP_PATH} ").as_bytes()) {
            relay_ohttp(&mut stream, &mut inbound, carried.ohttp.as_ref()).await;
            return;
        }
        if native::asks_challenges(&inbound) && inbound.windows(4).any(|w| w == b"\r\n\r\n") {
            let bundle = carried
                .challenges
                .lock()
                .map(|held| held.clone())
                .unwrap_or_default();
            let head = native::manifest_response_head(bundle.len());
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&bundle).await;
            let _ = stream.shutdown().await;
            return;
        }
        if native::asks_manifest(&inbound) && inbound.windows(4).any(|w| w == b"\r\n\r\n") {
            let _ = match &carried.manifest {
                Some(bytes) => {
                    let head = native::manifest_response_head(bytes.len());
                    let _ = stream.write_all(head.as_bytes()).await;
                    stream.write_all(bytes).await
                }
                None => {
                    stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                        .await
                }
            };
            let _ = stream.shutdown().await;
            return;
        }
        match upgrade::parse_request(&inbound) {
            Ok(Some((request, used))) => {
                inbound.drain(..used);
                break request;
            }
            Ok(None) if inbound.len() <= 8_192 => {}
            _ => return,
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            _ => return,
        }
    };
    if stream
        .write_all(upgrade::response(&request.key).as_bytes())
        .await
        .is_err()
    {
        return;
    }

    let (writer, mut outbound) = mpsc::unbounded_channel::<Vec<u8>>();
    if node.send(Input::Opened { link, writer }).await.is_err() {
        return;
    }
    let mut capsule = vec![0u8; MAX_CAPSULE];
    'connection: loop {
        // Each complete frame in the buffer is one capsule.
        loop {
            match websocket::decode(&inbound, true, &mut capsule) {
                Ok(Some((len, used))) => {
                    inbound.drain(..used);
                    let bytes = capsule.get(..len).unwrap_or(&[]).to_vec();
                    if node.send(Input::Capsule { link, bytes }).await.is_err() {
                        break 'connection;
                    }
                }
                Ok(None) => break,
                Err(_) => break 'connection,
            }
        }
        tokio::select! {
            read = stream.read(&mut chunk) => match read {
                Ok(n) if n > 0 => inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                _ => break 'connection,
            },
            next = outbound.recv() => {
                let Some(bytes) = next else {
                    break 'connection;
                };
                let mut frame = vec![0u8; websocket::frame_len(bytes.len(), false)];
                let Ok(used) = websocket::encode(&bytes, None, &mut frame) else {
                    break 'connection;
                };
                if stream.write_all(frame.get(..used).unwrap_or(&[])).await.is_err() {
                    break 'connection;
                }
            }
        }
    }
    let _ = node.send(Input::Closed { link }).await;
}

/// The TLS 1.3 acceptor of a relay, from a certificate chain and a key in
/// PEM files.
pub fn tls_acceptor(cert_path: &str, key_path: &str) -> Option<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .ok()?
        .collect::<Result<_, _>>()
        .ok()?;
    let key = PrivateKeyDer::from_pem_file(key_path).ok()?;
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .ok()?;
    Some(TlsAcceptor::from(Arc::new(config)))
}

/// Accepts connections until the listener fails. Accepted links take the
/// even identifiers, and dialed links take the odd ones.
pub async fn accept_loop(
    listener: TcpListener,
    tls: TlsAcceptor,
    node: mpsc::Sender<Input>,
    carried: Arc<Carried>,
) {
    let mut link: LinkId = 2;
    let limits = carried.limits;
    let open = Arc::new(AtomicUsize::new(0));
    let per_ip: PerIp = Arc::new(Mutex::new(BTreeMap::new()));
    let handshakes = Arc::new(tokio::sync::Semaphore::new(limits.handshakes_max));
    loop {
        let Ok((tcp, address)) = listener.accept().await else {
            return;
        };
        // NET-333: a relay at its cap closes a new connection at once.
        if open.load(Ordering::Relaxed) >= limits.max_connections {
            continue;
        }
        // NET-334: one address holds at most its share at an ingress relay.
        let ip = address.ip();
        let counted = limits.per_ip_max > 0 && !ip.is_loopback();
        if counted {
            let Ok(mut held) = per_ip.lock() else {
                continue;
            };
            let count = held.entry(ip).or_insert(0);
            if *count >= limits.per_ip_max {
                continue;
            }
            *count += 1;
        }
        open.fetch_add(1, Ordering::Relaxed);
        let held = Held {
            open: open.clone(),
            per_ip: counted.then(|| (per_ip.clone(), ip)),
        };
        // NET-335: the TLS handshakes that run at once are bounded, thus a
        // flood of them costs the relay a fixed amount of work.
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let tls = tls.clone();
        let node = node.clone();
        let carried = carried.clone();
        let this_link = link;
        link = link.saturating_add(2);
        tokio::spawn(async move {
            let _held = held;
            let accepted = tokio::time::timeout(limits.handshake_timeout, tls.accept(tcp)).await;
            drop(permit);
            if let Ok(Ok(stream)) = accepted {
                serve_connection(stream, this_link, node, carried).await;
            }
        });
    }
}

/// Dials one relay of the next layer, and moves its capsules until the
/// link closes.
pub async fn dial_next(
    relay_id: [u8; 32],
    target: Dial,
    link: LinkId,
    tls: Arc<rustls::ClientConfig>,
    node: mpsc::Sender<Input>,
) {
    let mut rng = OsRng;
    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let Ok(mut connection) =
        native::connect(&target, tls, plan, key, mask, Duration::from_secs(10)).await
    else {
        return;
    };
    let (writer, mut outbound) = mpsc::unbounded_channel::<Vec<u8>>();
    let opened = Input::Dialed {
        link,
        relay_id,
        writer,
    };
    if node.send(opened).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            received = connection.recv() => match received {
                Ok(bytes) => {
                    if node.send(Input::Capsule { link, bytes }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            next = outbound.recv() => match next {
                Some(bytes) if connection.send(&bytes).await.is_ok() => {}
                _ => break,
            },
        }
    }
    let _ = node.send(Input::Closed { link }).await;
}

/// Runs one relay: the node task, the dialer of the next layer, and the
/// accept loop. `next_hops` names each relay of the next layer, and
/// `client_tls` is the configuration that the dialer trusts them under. A
/// deployment passes [`PACING_MEAN_MS`] (`NET-077`), and a test passes less.
/// `carried` gives what the relay serves over HTTPS beside the upgrade.
/// `replicas` names each other relay with the attachment role, for the
/// copies of Part 12 §12.4.1.
#[allow(clippy::too_many_arguments)]
pub async fn run_relay(
    node: RelayNode,
    listener: TcpListener,
    tls: TlsAcceptor,
    next_hops: BTreeMap<[u8; 32], Dial>,
    replicas: BTreeMap<[u8; 32], Dial>,
    client_tls: Arc<rustls::ClientConfig>,
    pacing_mean_ms: u64,
    store: Box<dyn RelayStore>,
    carried: Carried,
) {
    let carried_ndr = carried.ndr.clone();
    let carried = Arc::new(carried);
    let carried_challenges = carried.clone();
    let (inputs, node_inputs) = mpsc::channel::<Input>(1_024);
    let (requests, mut node_requests) = mpsc::unbounded_channel::<Request>();
    let node_task = tokio::spawn(run_node(node, node_inputs, requests, pacing_mean_ms, store));

    let dial_inputs = inputs.clone();
    tokio::spawn(async move {
        let mut link: LinkId = 1;
        // Each relay of the next layer gets a link at the start, thus the
        // first circuit of a client does not wait for a dial.
        for (relay_id, target) in &next_hops {
            let tls = client_tls.clone();
            tokio::spawn(dial_next(
                *relay_id,
                target.clone(),
                link,
                tls,
                dial_inputs.clone(),
            ));
            link = link.saturating_add(2);
        }
        while let Some(request) = node_requests.recv().await {
            match request {
                Request::Dial(relay_id) => {
                    if let Some(target) = next_hops.get(&relay_id) {
                        let tls = client_tls.clone();
                        tokio::spawn(dial_next(
                            relay_id,
                            target.clone(),
                            link,
                            tls,
                            dial_inputs.clone(),
                        ));
                        link = link.saturating_add(2);
                    }
                }
                // ATT-105: a relay that the set does not name gets no copy.
                Request::Push { relay_id, capsule } => {
                    // A chunk copy goes to a relay with the attachment role,
                    // and a deposit to a queue relay (`WIR-526`).
                    if let Some(target) = replicas.get(&relay_id) {
                        tokio::spawn(push_copy(target.clone(), client_tls.clone(), capsule));
                    }
                }
                Request::Challenges(bundle) => {
                    if let Ok(mut held) = carried_challenges.challenges.lock() {
                        *held = bundle;
                    }
                }
                Request::NdrPush(push) => {
                    let Some((route, tls)) = carried_ndr.clone() else {
                        continue;
                    };
                    let inputs = dial_inputs.clone();
                    tokio::spawn(async move {
                        let answer = ndr::call(&route, &push.request, tls, &mut OsRng).await;
                        // NTF-125: a gone token stops the pushes of its
                        // handle. Any other failure waits for the re-push.
                        if matches!(answer, Ok(NdrResponse::Gone)) {
                            let _ = inputs
                                .send(Input::NdrGone {
                                    handle: push.handle,
                                })
                                .await;
                        }
                    });
                }
            }
        }
    });
    // The node task ends when the store fails, and the relay ends with it.
    tokio::select! {
        () = accept_loop(listener, tls, inputs, carried) => {}
        _ = node_task => {}
    }
}
