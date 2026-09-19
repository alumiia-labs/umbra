//! The runtime of the relay over tokio: one task owns the node, and each
//! connection is a task that moves capsules between its socket and that
//! task. The node stays a plain state machine, thus this file holds the
//! clock, the random source, and the sockets, and no protocol rule.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use umbra_core::group::backoff::exponential;
use umbra_crypto::{
    rand_core::{TryCryptoRng, TryRng},
    secret::Secret,
};
use umbra_transport::{
    native,
    race::{Plan, Wire},
    Dial,
};
use umbra_transport::{upgrade, websocket};

use crate::{
    circuits::{CircuitKey, LinkId},
    node::{Output, RelayNode},
    service::community::DigestDue,
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
}

/// What the node task asks of the process around it.
pub enum Request {
    /// Dial a relay of the next layer.
    Dial([u8; 32]),
    /// Write a digest into a notify queue, as a sender.
    Digest(DigestDue),
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
                    node.dialed(link, relay_id, session_id, Secret::new(secret))
                }
                Some(Input::Capsule { link, bytes }) => {
                    node.on_capsule(link, &bytes, unix_now(), &mut rng)
                }
                Some(Input::Closed { link }) => {
                    writers.remove(&link);
                    node.link_closed(link, unix_now())
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
                if now.saturating_sub(last_sweep) >= SWEEP_PERIOD {
                    last_sweep = now;
                    outputs.extend(node.sweep(now));
                }
                outputs
            }
        };
        if store.commit(&node.take_changes()).is_err() {
            eprintln!("the store took no commit, and the relay stops");
            return;
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
                Output::Digest(digest) => {
                    let _ = requests.send(Request::Digest(digest));
                }
            }
        }
    }
}

/// Serves one accepted connection: the HTTP upgrade of Part 6 §6.2.1, and
/// then one capsule in each WebSocket frame, in both directions. The
/// function returns when either side closes.
pub async fn serve_connection<S>(mut stream: S, link: LinkId, node: mpsc::Sender<Input>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut inbound: Vec<u8> = Vec::with_capacity(4_096);
    let mut chunk = vec![0u8; 16_384];
    let request = loop {
        match upgrade::parse_request(&inbound) {
            Ok(Some((request, used))) => {
                inbound.drain(..used);
                break request;
            }
            Ok(None) if inbound.len() <= 8_192 => {}
            _ => return,
        }
        match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
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
pub async fn accept_loop(listener: TcpListener, tls: TlsAcceptor, node: mpsc::Sender<Input>) {
    let mut link: LinkId = 2;
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let _ = tcp.set_nodelay(true);
        let tls = tls.clone();
        let node = node.clone();
        let this_link = link;
        link = link.saturating_add(2);
        tokio::spawn(async move {
            if let Ok(stream) = tls.accept(tcp).await {
                serve_connection(stream, this_link, node).await;
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
pub async fn run_relay(
    node: RelayNode,
    listener: TcpListener,
    tls: TlsAcceptor,
    next_hops: BTreeMap<[u8; 32], Dial>,
    client_tls: Arc<rustls::ClientConfig>,
    pacing_mean_ms: u64,
    store: Box<dyn RelayStore>,
) {
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
                // The write of a digest needs a circuit of this relay to the
                // queue relay of the subscriber. That sender is not built
                // yet, thus the digest stops here.
                Request::Digest(_) => {}
            }
        }
    });
    // The node task ends when the store fails, and the relay ends with it.
    tokio::select! {
        () = accept_loop(listener, tls, inputs) => {}
        _ = node_task => {}
    }
}
