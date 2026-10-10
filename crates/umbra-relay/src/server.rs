//! The runtime of the relay over tokio: one task owns the node, and each
//! connection is a task that moves capsules between its socket and that
//! task. The node stays a plain state machine, thus this file holds the
//! clock, the random source, and the sockets, and no protocol rule.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    sync::{mpsc, oneshot},
};
use tokio_rustls::TlsAcceptor;
use umbra_core::{
    abuse::POW_CHALLENGE_PERIOD,
    directory::{
        receipt::{ReceiptQuery, RECEIPT_QUERY_LEN},
        root::DirectoryKeySet,
        stat::{StatQuery, STAT_QUERY_LEN},
    },
    group::backoff::exponential,
};
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
    node::{
        clock_ms, Backlog, Output, QueryAnswer, RelayNode, DEPOSITS_PER_MINUTE, LINK_OPEN_TIMEOUT,
    },
    placement::Placement,
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

/// The bytes above the bound of a link that wait for the capsules that the
/// node does not count before it makes them. Those capsules are the end of
/// a circuit, a receipt, and a hello. A cell takes none of the bytes, thus
/// the capsule that tells a neighbor of a circuit that a full link lost
/// finds room (`NET-349`).
const BACKLOG_SLACK: usize = 256 << 10;

/// The sending half of one link, and the bytes that wait in it. The bound
/// is in bytes, thus no link holds more of the memory of the relay than its
/// bound. The node reads the count before it frames a cell, and a link at
/// its bound loses the circuit of that cell (`NET-349`). A peer that reads
/// nothing ends its link at `LINK_WRITE_TIMEOUT`.
pub struct LinkWriter {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    limit: usize,
}

/// The count of the backlog of each link, which the node reads.
#[derive(Clone, Default)]
struct Gauges(Arc<Mutex<BTreeMap<LinkId, Gauge>>>);

/// The bytes that wait on one link, and its bound.
type Gauge = (Arc<AtomicUsize>, usize);

impl Gauges {
    fn insert(&self, link: LinkId, writer: &LinkWriter) {
        if let Ok(mut held) = self.0.lock() {
            held.insert(link, (writer.queued.clone(), writer.limit));
        }
    }

    fn remove(&self, link: LinkId) {
        if let Ok(mut held) = self.0.lock() {
            held.remove(&link);
        }
    }
}

impl Backlog for Gauges {
    fn of(&self, link: LinkId) -> Option<(usize, usize)> {
        let held = self.0.lock().ok()?;
        let (queued, limit) = held.get(&link)?;
        Some((queued.load(Ordering::Relaxed), *limit))
    }
}

impl LinkWriter {
    /// A link that holds at most `limit` bytes, with the receiving half and
    /// the count that the writing task lowers after each write.
    fn new(limit: usize) -> (Self, mpsc::UnboundedReceiver<Vec<u8>>, Arc<AtomicUsize>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        (
            LinkWriter {
                sender,
                queued: Arc::clone(&queued),
                limit,
            },
            receiver,
            queued,
        )
    }

    /// Queues one capsule. False when the link holds its bound and the
    /// slack above it, or when its connection ended.
    fn queue(&self, capsule: Vec<u8>) -> bool {
        let len = capsule.len();
        // The count rises before the send, thus the writing task never
        // lowers it below zero.
        let held = self.queued.fetch_add(len, Ordering::Relaxed);
        let bound = self.limit.saturating_add(BACKLOG_SLACK);
        if held.saturating_add(len) > bound || self.sender.send(capsule).is_err() {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            return false;
        }
        true
    }
}

/// What a connection task and the dialer tell the node task.
pub enum Input {
    /// A connection opened. The node task writes its capsules to `writer`.
    Opened {
        /// The link.
        link: LinkId,
        /// The capsules to write.
        writer: LinkWriter,
        /// The address of the peer, cut as the caps of one address cut it,
        /// or none for a stream with no address. The node counts the
        /// circuits of one address together (`NET-331`).
        source: Option<[u8; 16]>,
    },
    /// The dialer reached a relay of the next layer.
    Dialed {
        /// The link.
        link: LinkId,
        /// The relay.
        relay_id: [u8; 32],
        /// The capsules to write.
        writer: LinkWriter,
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
    /// The key of the cross-relay issuer of one epoch, from the log.
    IssuerKey {
        /// The epoch.
        epoch: u32,
        /// The key.
        key: Box<umbra_crypto::rsabssa::PublicKey2048>,
    },
    /// The NDR answered `gone` for a handle of a push of this relay.
    NdrGone {
        /// The handle.
        handle: [u8; 16],
    },
    /// A receipt query of an authority that verified (Part 10 `REL-179`).
    ReceiptQuery {
        /// The query.
        query: ReceiptQuery,
        /// The encoded `ReceiptAnswer`, or why the node gave none.
        reply: oneshot::Sender<QueryAnswer<Vec<u8>>>,
    },
    /// A query of an aggregator that verified (Part 10 `REL-192`).
    StatQuery {
        /// The query.
        query: StatQuery,
        /// The encoded `StatAnswer`, or why the node gave none.
        reply: oneshot::Sender<QueryAnswer<Vec<u8>>>,
    },
    /// The dial of a relay of the next layer opened no link (`NET-319`).
    DialFailed {
        /// The relay.
        relay_id: [u8; 32],
    },
    /// A newer manifest that verified places this relay (`NET-167`).
    Placed(Box<Placed>),
}

/// What a newer relay set gives the node of a relay that runs.
pub struct Placed {
    /// The layer of this relay in that set.
    pub layer: u8,
    /// The relays of the next layer (`NET-167`).
    pub next_layer: BTreeSet<[u8; 32]>,
    /// The relays of the layer before (`REL-174`).
    pub previous_layer: BTreeSet<[u8; 32]>,
    /// The static key of each queue relay (`WIR-526`).
    pub queue_relays: BTreeMap<[u8; 32], [u8; 32]>,
    /// The identity key of each relay (`ABU-103`, `REL-174`).
    pub identities: BTreeMap<[u8; 32], Vec<u8>>,
    /// The carriers of the manifest (`ABU-102`).
    pub carriers: Vec<[u8; 32]>,
}

impl Placed {
    /// What the node takes of a place.
    pub fn of(placement: &Placement) -> Self {
        Placed {
            layer: placement.layer,
            next_layer: placement.next.keys().copied().collect(),
            previous_layer: placement.previous.clone(),
            queue_relays: placement
                .queue_relays
                .iter()
                .map(|(relay_id, (_, key))| (*relay_id, *key))
                .collect(),
            identities: placement.identities.clone(),
            carriers: placement.carriers.keys().copied().collect(),
        }
    }
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
    let mut writers: BTreeMap<LinkId, LinkWriter> = BTreeMap::new();
    // NET-349: the node reads the backlog of a link before it frames a cell.
    let gauges = Gauges::default();
    node.set_backlog(Box::new(gauges.clone()));
    let mut next_tick: BTreeMap<CircuitKey, tokio::time::Instant> = BTreeMap::new();
    let mut clock =
        tokio::time::interval(Duration::from_millis((pacing_mean_ms / 20).clamp(1, 50)));
    // The periods run on a clock that never steps back, thus a change of the
    // wall clock holds no sweep and no push back.
    let mut last_sweep = tokio::time::Instant::now();
    let mut last_push_tick = last_sweep;
    // ABU-057: the first challenge at the start, and a new one at each
    // period.
    let mut last_challenge: Option<tokio::time::Instant> = None;
    loop {
        let outputs = tokio::select! {
            input = inputs.recv() => match input {
                None => return,
                Some(Input::Opened { link, writer, source }) => {
                    gauges.insert(link, &writer);
                    writers.insert(link, writer);
                    node.opened(link, unix_now());
                    if let Some(source) = source {
                        node.set_source(link, source);
                    }
                    Vec::new()
                }
                Some(Input::DialFailed { relay_id }) => {
                    node.dial_failed(relay_id, unix_now());
                    Vec::new()
                }
                Some(Input::Placed(placed)) => {
                    // A relay takes its layer at its start. A set that moves
                    // it ends this run, and the supervisor starts the next
                    // one in the new layer.
                    if placed.layer != node.layer() {
                        eprintln!("the relay set gives this relay another layer, and the relay stops");
                        return;
                    }
                    let placed = *placed;
                    node.set_next_layer(placed.next_layer);
                    node.set_previous_layer(placed.previous_layer);
                    node.set_queue_relays(placed.queue_relays);
                    node.set_relay_identities(placed.identities);
                    node.set_carriers(placed.carriers);
                    // REL-174: the link of a relay that left the layer
                    // before closes.
                    node.close_strangers(unix_now())
                }
                Some(Input::Dialed { link, relay_id, writer }) => {
                    gauges.insert(link, &writer);
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
                    gauges.remove(link);
                    node.link_closed(link, unix_now())
                }
                Some(Input::NdrGone { handle }) => {
                    node.ndr_gone(&handle);
                    Vec::new()
                }
                Some(Input::IssuerKey { epoch, key }) => {
                    node.set_issuer_key(epoch, *key);
                    Vec::new()
                }
                Some(Input::ReceiptQuery { query, reply }) => {
                    match node.receipt_answer(&query, unix_now()) {
                        // An answer that does not encode gives no reply,
                        // and the connection answers 503 (`REL-179`).
                        QueryAnswer::Given(answer) => {
                            if let Ok(body) = answer.encode() {
                                let _ = reply.send(QueryAnswer::Given(body));
                            }
                        }
                        QueryAnswer::Above => {
                            let _ = reply.send(QueryAnswer::Above);
                        }
                        QueryAnswer::Elsewhere => {
                            let _ = reply.send(QueryAnswer::Elsewhere);
                        }
                    }
                    Vec::new()
                }
                Some(Input::StatQuery { query, reply }) => {
                    let answer = match node.stat_answer(&query, unix_now()) {
                        QueryAnswer::Given(answer) => QueryAnswer::Given(answer.encode().to_vec()),
                        QueryAnswer::Above => QueryAnswer::Above,
                        QueryAnswer::Elsewhere => QueryAnswer::Elsewhere,
                    };
                    let _ = reply.send(answer);
                    Vec::new()
                }
            },
            _ = clock.tick() => {
                let now = unix_now();
                let instant = tokio::time::Instant::now();
                let mut outputs = Vec::new();
                // NET-035, NET-036: a Poisson clock for each circuit, which
                // no arrival moves.
                // The endpoints come in their order, thus a search finds
                // each one in log time.
                let paced: Vec<CircuitKey> = node.paced_circuits().copied().collect();
                next_tick.retain(|circuit, _| paced.binary_search(circuit).is_ok());
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
                // NET-037: the next step of each drain.
                outputs.extend(node.drain_tick(now, &mut rng));
                // Part 3 §3.9: each forward cell whose per-hop delay ended.
                outputs.extend(node.release_delayed(clock_ms(), now, &mut rng));
                // NTF-049, NTF-066: the end of a coalescing window and
                // each re-push, once each second.
                if instant.duration_since(last_push_tick) >= Duration::from_secs(1) {
                    last_push_tick = instant;
                    outputs.extend(node.push_tick(now, &mut rng));
                }
                if instant.duration_since(last_sweep) >= Duration::from_secs(SWEEP_PERIOD) {
                    last_sweep = instant;
                    outputs.extend(node.sweep(now, &mut rng));
                }
                let period = Duration::from_secs(POW_CHALLENGE_PERIOD);
                if last_challenge.is_none_or(|at| instant.duration_since(at) >= period) {
                    last_challenge = Some(instant);
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
                    // NET-349: the node framed no cell for a link at its
                    // bound. A capsule that finds no room here is thus one
                    // above the slack of a peer that reads nothing. It goes
                    // nowhere, and the link ends at its write timeout: a
                    // full backlog never closes a link that circuits share.
                    if let Some(writer) = writers.get(&link) {
                        let _ = writer.queue(capsule);
                    }
                }
                Output::Close { link } => {
                    writers.remove(&link);
                    gauges.remove(link);
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
        node.flushed();
    }
}

/// The pushes of chunk copies that run at once. It stays
/// below `RELAY_CONN_PER_IP`, thus an ingress relay that holds a role of
/// the pushes takes each one of one pushing relay (`NET-334`). Relays that
/// share one address can pass that cap together, and a copy it refuses is
/// one that the sample of the uploader finds (`ATT-113`).
const PUSHES_RUNNING: usize = 16;
/// The time that one push takes at most: a relay that takes the
/// connection and reads nothing holds no place of another push.
const PUSH_TIMEOUT: Duration = Duration::from_secs(20);
/// The pushes that wait or run at once. A push above it goes nowhere, as a
/// copy that did not arrive does.
const PUSHES_HELD: usize = 1_024;

/// The deposits of digests and the challenges that wait for one relay.
/// They have places of their own, apart from the chunk copies. A burst of
/// digests then holds no copy back, and a row of large copies holds no
/// digest back. One more than this drops the oldest that waits for that
/// relay. A digest is a hint to wake, and a challenge has a period. The
/// next digest of the group and the next challenge carry what a dropped one
/// did, thus the loss ends at the next one.
const LANE_HELD: usize = 1_024;
/// The connections that one relay takes at once for the deposits and the
/// challenges of this one. With the chunk copies they stay below what one
/// address of the relay set opens at once (`NET-334`).
const LANE_WORKERS: usize = 2;
/// The capsules that go on one such connection: the deposits that the
/// receiver takes of one link in a minute. The receiver closes a link with
/// no session at `LINK_OPEN_TIMEOUT`, and one connection is far shorter.
const LANE_BATCH: usize = DEPOSITS_PER_MINUTE as usize;
/// The time that a connection to another relay has to open.
const CONNECT_TIME: Duration = Duration::from_secs(10);
/// The same time for a relay whose last connection did not open. A relay
/// that is down, or that takes the connection and stalls, then costs each
/// try this time and not the whole of `CONNECT_TIME`.
const CONNECT_TIME_AFTER_FAILURE: Duration = Duration::from_secs(2);
/// The wait after a connection that did not open, before the next try to
/// that relay. It doubles at each further one, up to `LANE_HOLD_OFF_MAX`.
const LANE_HOLD_OFF: Duration = Duration::from_secs(1);
const LANE_HOLD_OFF_MAX: Duration = Duration::from_secs(60);

/// What waits for one relay, and how its last connections went.
#[derive(Default)]
struct LaneState {
    /// The deposits and the challenges that wait, the oldest first.
    waiting: VecDeque<Vec<u8>>,
    /// The tasks that send them.
    workers: usize,
    /// The connections in a row that did not open.
    failures: u32,
    /// The time before which no connection to the relay starts.
    closed_until: Option<tokio::time::Instant>,
}

/// The pushes to one relay. Each relay has a lane of its own, thus a relay
/// that is down holds back the pushes for itself alone. Before this, eight
/// places served the deposits for all relays. Eight deposits for one dead
/// relay then stopped each digest and each challenge of this relay.
#[derive(Default)]
struct Lane(Mutex<LaneState>);

impl Lane {
    /// Queues one capsule, and drops the oldest above `LANE_HELD`. The
    /// result is whether the lane needs one more worker, which the caller
    /// starts.
    fn queue(&self, capsule: Vec<u8>) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        state.waiting.push_back(capsule);
        while state.waiting.len() > LANE_HELD {
            state.waiting.pop_front();
        }
        if state.workers < LANE_WORKERS && state.workers < state.waiting.len() {
            state.workers += 1;
            return true;
        }
        false
    }

    /// The next capsule that waits.
    fn take(&self) -> Option<Vec<u8>> {
        self.0.lock().ok()?.waiting.pop_front()
    }

    /// Whether a worker ends because nothing waits. The lane then counts
    /// it no more, in the same step: a capsule that arrives after it starts
    /// a worker.
    fn rests(&self) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return true;
        };
        if state.waiting.is_empty() {
            state.workers = state.workers.saturating_sub(1);
            return true;
        }
        false
    }

    /// A worker ends with capsules left, because the relay set names the
    /// relay no more: they go nowhere.
    fn close(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.waiting.clear();
            state.workers = state.workers.saturating_sub(1);
        }
    }

    /// The time before which no connection starts, and the time that the
    /// next one has to open.
    fn budget(&self) -> (Option<tokio::time::Instant>, Duration) {
        let Ok(state) = self.0.lock() else {
            return (None, CONNECT_TIME_AFTER_FAILURE);
        };
        let time = if state.failures == 0 {
            CONNECT_TIME
        } else {
            CONNECT_TIME_AFTER_FAILURE
        };
        (state.closed_until, time)
    }

    /// A connection opened, or it did not, at `now`.
    fn connected(&self, opened: bool, now: tokio::time::Instant) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if opened {
            state.failures = 0;
            state.closed_until = None;
            return;
        }
        let doubled = LANE_HOLD_OFF.saturating_mul(1u32 << state.failures.min(16));
        state.failures = state.failures.saturating_add(1);
        state.closed_until = Some(now + doubled.min(LANE_HOLD_OFF_MAX));
    }
}

/// Opens one connection to `target` inside `time`.
async fn connect_push(
    target: &Dial,
    tls: Arc<rustls::ClientConfig>,
    time: Duration,
) -> Option<native::Link> {
    let mut rng = OsRng;
    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    native::connect(target, tls, plan, key, mask, time)
        .await
        .ok()
}

/// Sends the deposits and the challenges that wait for one relay, up to
/// `LANE_BATCH` on each connection, until none waits. The connection is
/// one of Part 6 §6.2.1 with no session, as `WIR-526` gives for a deposit.
/// It serves each deposit that waits for that relay. A connection that
/// does not open sends nothing and holds each capsule. The next one waits
/// for the hold-off of the lane, and what arrives in that time pushes the
/// oldest out above `LANE_HELD`. The lane loses a capsule whose write
/// fails.
async fn run_lane(
    relay_id: [u8; 32],
    lane: Arc<Lane>,
    routes: Arc<Mutex<Routes>>,
    tls: Arc<rustls::ClientConfig>,
) {
    loop {
        if lane.rests() {
            return;
        }
        let (closed_until, time) = lane.budget();
        if let Some(until) = closed_until {
            tokio::time::sleep_until(until).await;
        }
        let target = routes
            .lock()
            .ok()
            .and_then(|held| held.replicas.get(&relay_id).cloned());
        // ATT-105: a relay that the set names no more gets nothing.
        let Some(target) = target else {
            lane.close();
            return;
        };
        let connection = connect_push(&target, tls.clone(), time).await;
        lane.connected(connection.is_some(), tokio::time::Instant::now());
        let Some(mut connection) = connection else {
            continue;
        };
        for _ in 0..LANE_BATCH {
            let Some(capsule) = lane.take() else {
                break;
            };
            let sent = tokio::time::timeout(PUSH_TIMEOUT, connection.send(&capsule)).await;
            if !matches!(sent, Ok(Ok(()))) {
                break;
            }
        }
    }
}

/// Sends one copy of a chunk on a connection of its own, and ends that
/// connection (`WIR-211`). A copy that does not arrive gets no second send:
/// the uploader finds it with its sample, and it names another relay
/// (`ATT-113`, `ATT-118`). The lane of the relay gives the time of the
/// connection and takes its result. A relay that is down thus holds a
/// place of the copies for `CONNECT_TIME_AFTER_FAILURE` at the most.
async fn push_copy(
    target: Dial,
    tls: Arc<rustls::ClientConfig>,
    capsule: Vec<u8>,
    lane: Arc<Lane>,
) {
    let (_, time) = lane.budget();
    let connection = connect_push(&target, tls, time).await;
    lane.connected(connection.is_some(), tokio::time::Instant::now());
    if let Some(mut connection) = connection {
        let _ = connection.send(&capsule).await;
    }
}

/// The bytes that wait for one accepted link. A peer that reads nothing
/// fills them, and the relay closes that link. An accepted link can be the
/// link of a relay of the layer before, which carries the circuits of many
/// clients, and a `SUB` replays up to `QUEUE_QUOTA` records of up to one
/// capsule each at once, thus the bound holds such a burst. A peer that
/// reads keeps its backlog near empty.
const LINK_BACKLOG: usize = 32 << 20;
/// The bytes that wait for one link to a relay of the next layer, which
/// carries the circuits of many clients.
const RELAY_LINK_BACKLOG: usize = 64 << 20;
/// The time that one write to a link may take before the link closes.
const LINK_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The time that a POST has for its answer after the deadline of its
/// request (`NET-335`).
const POST_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// The answer to a request for a file that this relay does not hold. It
/// states its length, as a fetch of Part 14 needs of each answer.
const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The path of the OHTTP relay of Part 8 §8.2 (`NTF-127`).
pub const OHTTP_PATH: &str = "/ohttp";
/// The path of the OHTTP relay of the directory and the issuer of Part 9
/// §9.4 and Part 13 §13.9 (`DIS-162`).
pub const DIRECTORY_PATH: &str = "/directory";
/// The longest encapsulated request and response of the directory: the
/// padded sizes of Part 9 §9.12, the header, the encapsulation, and the tag.
const DIRECTORY_REQUEST_MAX: usize = 16_384;
const DIRECTORY_RESPONSE_MAX: usize = 131_072;
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
    /// for none. A loopback address is exempt, and the address of a relay
    /// of the set holds `RELAY_PEER_PART` times as many until
    /// `LINK_OPEN_TIMEOUT`.
    pub per_ip_max: usize,
    /// `RELAY_HANDSHAKES_MAX`: the TLS handshakes that run at once.
    pub handshakes_max: usize,
    /// `RELAY_HANDSHAKES_PER_IP`: the TLS handshakes of one address at once,
    /// or 0 for none. A loopback address is exempt, and the address of a
    /// relay of the set runs `RELAY_PEER_PART` times as many.
    pub handshakes_per_ip: usize,
    /// `RELAY_HANDSHAKES_PER_NET`: the TLS handshakes of one network at
    /// once, or 0 for none. A network is the first 24 bits of an IPv4
    /// address, or the first 48 bits of an IPv6 address. A loopback address
    /// and the address of a relay of the set are exempt.
    pub handshakes_per_net: usize,
    /// `RELAY_HANDSHAKE_TIMEOUT`: the time from the accept to the upgrade.
    pub handshake_timeout: Duration,
    /// `RELAY_FIRST_BYTES_TIMEOUT`: the time from the accept to the whole
    /// `ClientHello`.
    pub first_bytes_timeout: Duration,
    /// `RELAY_HANDSHAKE_END_TIMEOUT`: the time from the whole `ClientHello`
    /// to the end of the TLS handshake.
    pub handshake_end_timeout: Duration,
    /// Whether a loopback address is exempt from the caps of one address. A
    /// test of those caps runs on one machine and sets it off.
    pub loopback_exempt: bool,
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
    /// `RELAY_HANDSHAKES_PER_IP` of Part 3 §3.13.
    pub const HANDSHAKES_PER_IP: usize = 4;
    /// `RELAY_HANDSHAKES_PER_NET` of Part 3 §3.13.
    pub const HANDSHAKES_PER_NET: usize = 16;
    /// `RELAY_FIRST_BYTES_TIMEOUT` of Part 3 §3.13: the time from the accept
    /// to the whole `ClientHello` of the TLS handshake.
    pub const FIRST_BYTES_TIMEOUT: Duration = Duration::from_secs(3);
    /// `RELAY_HANDSHAKE_END_TIMEOUT` of Part 3 §3.13.
    pub const HANDSHAKE_END_TIMEOUT: Duration = Duration::from_secs(3);
    /// `RELAY_PEER_PART` of Part 3 §3.13: the address of a relay of the set
    /// holds this many times the connections and the handshakes of another
    /// address.
    pub const PEER_PART: usize = 4;
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        ConnectionLimits {
            max_connections: Self::CONN_MAX,
            per_ip_max: 0,
            handshakes_max: Self::HANDSHAKES_MAX,
            handshakes_per_ip: Self::HANDSHAKES_PER_IP,
            handshakes_per_net: Self::HANDSHAKES_PER_NET,
            handshake_timeout: Self::HANDSHAKE_TIMEOUT,
            first_bytes_timeout: Self::FIRST_BYTES_TIMEOUT,
            handshake_end_timeout: Self::HANDSHAKE_END_TIMEOUT,
            loopback_exempt: true,
        }
    }
}

/// The address of a peer as the caps of one address count it. It is an
/// IPv4 address whole, or the first 64 bits of an IPv6 address. One host
/// holds each address below those bits.
fn address_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => {
            let mut key = v6.octets();
            key[8..].fill(0);
            key
        }
    }
}

/// The network of a peer: the first 24 bits of an IPv4 address, or the
/// first 48 bits of an IPv6 address.
fn net_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut key = v4.to_ipv6_mapped().octets();
            key[15] = 0;
            key
        }
        IpAddr::V6(v6) => {
            let mut key = v6.octets();
            key[6..].fill(0);
            key
        }
    }
}

/// The connections of each address that the per-address cap counts.
type PerIp = Arc<Mutex<BTreeMap<[u8; 16], usize>>>;

/// One place of an address in a count, which it gives back when it drops.
struct Place(PerIp, [u8; 16]);

impl Place {
    /// Takes one place of `ip` in `counts`, or none when the address holds
    /// `max` of them.
    fn take(counts: &PerIp, ip: [u8; 16], max: usize) -> Option<Self> {
        let mut held = counts.lock().ok()?;
        let count = held.entry(ip).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Place(counts.clone(), ip))
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0.lock() {
            if let Some(count) = held.get_mut(&self.1) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(&self.1);
                }
            }
        }
    }
}

/// One held connection: it counts against the limits until it drops.
struct Held {
    open: Arc<AtomicUsize>,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Part 3 §3.10, the OHTTP relay role of Part 8 §8.2, and the route of the
/// pushes of its own queues.
#[derive(Default)]
pub struct Carried {
    /// The manifest, for a client that asks for it. A newer one that the
    /// file gives takes its place (see [`ManifestSource`]).
    pub manifest: std::sync::Mutex<Option<Vec<u8>>>,
    /// The file of the manifest and what a new one must verify against.
    pub manifest_source: Option<ManifestSource>,
    /// The key chain of the signer, which this relay carries beside the
    /// manifest (Part 10 `REL-199`), or none before the first rotation.
    pub keychain: std::sync::Mutex<Option<Vec<u8>>>,
    /// The gateway, for a relay with the OHTTP relay role.
    pub ohttp: Option<OhttpForward>,
    /// The gateway of the directory and the issuer, for a relay with that
    /// OHTTP relay role.
    pub directory: Option<OhttpForward>,
    /// The route to the NDR that a queue relay pins (`NTF-127`), and the
    /// configuration it trusts the OHTTP relay under. A relay with none
    /// sends no push.
    pub ndr: Option<(NdrRoute, Arc<rustls::ClientConfig>)>,
    /// The newest challenge of each relay, which a carrier of the manifest
    /// serves beside it (`ABU-104`). The node moves it.
    pub challenges: std::sync::Mutex<Vec<u8>>,
    /// The limits of the connections (`NET-333` to `NET-335`).
    pub limits: ConnectionLimits,
    /// The address of each relay of the set, which holds more connections
    /// than another address until `LINK_OPEN_TIMEOUT` (`NET-334`). A relay
    /// opens connections for the chunk copies and the digest deposits that
    /// it pushes. A newer manifest moves it.
    pub relay_addresses: std::sync::Mutex<BTreeSet<IpAddr>>,
    /// The address of a test network that names this machine. The dialer
    /// reaches a relay that the manifest lists there at the loopback
    /// address.
    pub host_alias: Option<[u8; 4]>,
    /// The pinned route to the log, from which the relay takes the key of
    /// the cross-relay issuer of each epoch (Part 13 §13.5).
    pub issuer_reader: std::sync::Mutex<Option<crate::issuer_keys::IssuerReader>>,
}

/// The file that the authorities write each new manifest to, with the key
/// set and the identity that a new manifest must place (Part 10 §10.5.5).
pub struct ManifestSource {
    /// The file of the manifest.
    pub path: std::path::PathBuf,
    /// The key set of the authorities.
    pub keyset: std::sync::Mutex<Vec<u8>>,
    /// The file of the key set, which a rotation of `REL-200` writes.
    pub keyset_path: std::path::PathBuf,
    /// The identifier of this relay.
    pub relay_id: [u8; 32],
    /// The static key of this relay.
    pub s: [u8; 32],
    /// The HTTPS carrier that serves each new manifest, as the signer of
    /// the directory does, or none for a file that another process writes.
    pub fetch: Option<Dial>,
}

/// How often a relay reads the file of the manifest again.
const MANIFEST_READ_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);
/// The reads of the file between two fetches from the carrier: one fetch
/// each five minutes, thus a root of three hours reaches each relay long
/// before it ends.
const MANIFEST_FETCH_EVERY: u32 = 5;

/// The epoch of the root of a manifest, and whether that root still holds
/// at `now`, `CONSENSUS_VALIDITY` and `CLOCK_SKEW` after its start.
fn manifest_epoch(bytes: &[u8], now: u64) -> Option<(u64, bool)> {
    use umbra_core::directory::{
        manifest::RelayManifest, root::DirectoryRoot, CLOCK_SKEW, CONSENSUS_VALIDITY,
    };
    let manifest = RelayManifest::parse(bytes).ok()?;
    let root = DirectoryRoot::parse(manifest.root).ok()?;
    let ends = root
        .epoch_start_unix
        .saturating_add(CONSENSUS_VALIDITY)
        .saturating_add(CLOCK_SKEW);
    Some((root.epoch, now <= ends))
}

/// Whether `fresh` may take the place of `held`: a root that holds at `now`,
/// and not older than the one held. An operator that copies an old manifest
/// or a carrier that serves one moves no relay back.
fn is_newer(fresh: &[u8], held: Option<&[u8]>, now: u64) -> bool {
    let Some((epoch, holds)) = manifest_epoch(fresh, now) else {
        return false;
    };
    let held_epoch = held
        .and_then(|held| manifest_epoch(held, now))
        .map(|(e, _)| e);
    holds && held_epoch.is_none_or(|held| epoch >= held)
}

/// The file of the key chain, beside the file of the manifest.
fn keychain_path(source: &ManifestSource) -> std::path::PathBuf {
    source.path.with_file_name("keychain.bin")
}

/// Fetches the key chain of the carrier and keeps it, in RAM and on the
/// disk, to serve it beside the manifest (`REL-199`). A chain that does
/// not parse takes no place; each client verifies each link itself.
async fn fetch_keychain_into(
    carried: &Carried,
    source: &ManifestSource,
    dial: &Dial,
    tls: Arc<rustls::ClientConfig>,
) -> Option<Vec<u8>> {
    let chain = native::fetch_keychain(dial, tls).await.ok()?;
    umbra_core::directory::keychain::links(&chain).ok()?;
    let held = carried.keychain.lock().ok()?.clone();
    if held.as_deref() != Some(chain.as_slice()) {
        let _ = write_atomically(&keychain_path(source), &chain);
        if let Ok(mut slot) = carried.keychain.lock() {
            *slot = Some(chain.clone());
        }
    }
    Some(chain)
}

/// Fetches the manifest of the carrier, and writes it over the file when it
/// verifies and still places this relay. A manifest that does not verify
/// never takes the place of one that does.
async fn fetch_manifest_into(
    carried: &Carried,
    source: &ManifestSource,
    dial: &Dial,
    tls: Arc<rustls::ClientConfig>,
    now: u64,
) {
    let chain = fetch_keychain_into(carried, source, dial, tls.clone()).await;
    let Ok(fresh) = native::fetch_manifest(dial, tls.clone()).await else {
        return;
    };
    let held = std::fs::read(&source.path).ok();
    if held.as_deref() == Some(fresh.as_slice()) || !is_newer(&fresh, held.as_deref(), now) {
        return;
    }
    let Some(keyset) = source.keyset() else {
        return;
    };
    let placed = |keyset: &[u8]| {
        crate::placement::placement(&fresh, keyset, &source.relay_id, &source.s, now).is_ok()
    };
    let part = source.path.with_extension("part");
    if !placed(&keyset) {
        // REL-200: a manifest under another key set takes the key chain of
        // the carrier, walked from the set this relay holds.
        let Some(chain) = chain else {
            return;
        };
        let Ok(next) = umbra_core::directory::keychain::advance(&keyset, &chain) else {
            return;
        };
        if next == keyset || !placed(&next) {
            return;
        }
        // The manifest waits beside its file first, thus a stop between
        // the two renames leaves a pair that a start can mend.
        if std::fs::write(&part, &fresh).is_err() {
            eprintln!("relay: the manifest of the new key set does not write");
            return;
        }
        if !write_atomically(&source.keyset_path, &next) {
            eprintln!("relay: the key set file does not write; a rotation waits");
            return;
        }
        if let Ok(mut held) = source.keyset.lock() {
            *held = next;
        }
        let _ = std::fs::rename(&part, &source.path);
        return;
    }
    if std::fs::write(&part, &fresh).is_ok() {
        let _ = std::fs::rename(&part, &source.path);
    }
}

/// Writes `bytes` to `path` under another name, then renames it.
fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> bool {
    let part = path.with_extension("part");
    std::fs::write(&part, bytes).is_ok() && std::fs::rename(&part, path).is_ok()
}

impl ManifestSource {
    /// The key set that this relay holds now.
    pub fn keyset(&self) -> Option<Vec<u8>> {
        self.keyset.lock().ok().map(|held| held.clone())
    }
}

/// Where the dialer reaches each relay that the node names.
#[derive(Default)]
struct Routes {
    /// Each relay of the next layer.
    next_hops: BTreeMap<[u8; 32], Dial>,
    /// Each relay that takes a push: a chunk copy, a deposit, a challenge.
    replicas: BTreeMap<[u8; 32], Dial>,
}

/// Puts the loopback address in the place of the alias of this machine.
pub fn dial_at_alias(dials: &mut BTreeMap<[u8; 32], Dial>, alias: Option<[u8; 4]>) {
    let Some(alias) = alias else {
        return;
    };
    for dial in dials.values_mut() {
        if dial.addr_v4 == Some(alias) {
            dial.addr_v4 = Some([127, 0, 0, 1]);
        }
    }
}

/// Gives the place of a newer manifest to the relay that runs. The place
/// holds the routes of the dialer, the addresses that the caps exempt, and
/// the relay set of the node. Before this, a relay served the newer
/// manifest and kept the next layer of its start. It thus dropped the
/// `EXTEND` of a client that selected a new relay from that manifest
/// (`NET-167`).
async fn adopt(
    carried: &Carried,
    placed: &Placement,
    routes: &Mutex<Routes>,
    node: &mpsc::Sender<Input>,
) {
    if let Ok(mut held) = carried.relay_addresses.lock() {
        *held = placed.addresses.clone();
    }
    let mut next_hops = placed.next.clone();
    let mut replicas = placed.pushes();
    dial_at_alias(&mut next_hops, carried.host_alias);
    dial_at_alias(&mut replicas, carried.host_alias);
    if let Ok(mut held) = routes.lock() {
        held.next_hops = next_hops;
        held.replicas = replicas;
    }
    let _ = node.send(Input::Placed(Box::new(Placed::of(placed)))).await;
}

/// Reads the file of the manifest again at each period, and takes a new
/// manifest that verifies and still places this relay. The relay serves
/// it, and its node and its dialer take the relay set of it. A set that
/// gives the relay another layer ends the run.
async fn reload_manifest(
    carried: Arc<Carried>,
    tls: Arc<rustls::ClientConfig>,
    routes: Arc<Mutex<Routes>>,
    node: mpsc::Sender<Input>,
) {
    let Some(source) = carried.manifest_source.as_ref() else {
        return;
    };
    // The chain of the last run serves until a fetch gives a newer one.
    if let Ok(chain) = std::fs::read(keychain_path(source)) {
        if umbra_core::directory::keychain::links(&chain).is_ok() {
            if let Ok(mut slot) = carried.keychain.lock() {
                *slot = Some(chain);
            }
        }
    }
    let mut reads: u32 = 0;
    loop {
        tokio::time::sleep(MANIFEST_READ_PERIOD).await;
        if let Some(dial) = &source.fetch {
            if reads.is_multiple_of(MANIFEST_FETCH_EVERY) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |at| at.as_secs());
                fetch_manifest_into(&carried, source, dial, tls.clone(), now).await;
            }
            reads = reads.wrapping_add(1);
        }
        let Ok(fresh) = std::fs::read(&source.path) else {
            continue;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |at| at.as_secs());
        let served = carried
            .manifest
            .lock()
            .map(|held| {
                held.as_deref() == Some(fresh.as_slice()) || !is_newer(&fresh, held.as_deref(), now)
            })
            .unwrap_or(true);
        if served {
            continue;
        }
        let Some(keyset) = source.keyset() else {
            continue;
        };
        let Ok(placed) =
            crate::placement::placement(&fresh, &keyset, &source.relay_id, &source.s, now)
        else {
            continue;
        };
        adopt(&carried, &placed, &routes, &node).await;
        if let Ok(mut held) = carried.manifest.lock() {
            *held = Some(fresh);
        }
    }
}

/// Forwards one encapsulated request to the gateway and gives its answer
/// back (`NTF-127`). The relay reads no byte of either, it keeps neither,
/// and the gateway sees this relay alone.
/// The path of the receipt query of an authority (Part 10 `REL-179`).
pub const RECEIPT_PATH: &str = "/receipt";

/// Answers a receipt query of an authority: a query that verifies under the
/// key set of this relay gets the answer of the node, and each other gets
/// 403 with no body (`REL-179`, `REL-180`).
async fn answer_receipt_query<S>(
    stream: &mut S,
    inbound: &mut Vec<u8>,
    node: &mpsc::Sender<Input>,
    carried: &Carried,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = https::read_request(stream, inbound, RECEIPT_QUERY_LEN).await;
    let keyset = carried
        .manifest_source
        .as_ref()
        .and_then(ManifestSource::keyset);
    let query = match (request, keyset.as_deref()) {
        (Ok(request), Some(keyset)) if request.method == "POST" => DirectoryKeySet::parse(keyset)
            .ok()
            .and_then(|(set, _)| ReceiptQuery::verify(&request.body, &set).ok()),
        _ => None,
    };
    let Some(query) = query else {
        let _ = https::respond(stream, 403, "text/plain", &[]).await;
        return;
    };
    let (reply, answer) = oneshot::channel();
    let answer = match node.send(Input::ReceiptQuery { query, reply }).await {
        Ok(()) => answer.await.ok(),
        Err(_) => None,
    };
    respond_answer(stream, answer).await;
}

/// The answer of the node to a query: the body, 429 above the bound of
/// `REL-187`, 403 with no body for a query that names another relay
/// (`REL-180`, `REL-192`), or 503 when the node gave none.
async fn respond_answer<S>(stream: &mut S, answer: Option<QueryAnswer<Vec<u8>>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = match answer {
        Some(QueryAnswer::Given(body)) => {
            https::respond(stream, 200, "application/octet-stream", &body).await
        }
        Some(QueryAnswer::Above) => https::respond(stream, 429, "text/plain", &[]).await,
        Some(QueryAnswer::Elsewhere) => https::respond(stream, 403, "text/plain", &[]).await,
        None => https::respond(stream, 503, "text/plain", &[]).await,
    };
}

/// The path of the query of an aggregator (Part 10 `REL-192`).
pub const STAT_PATH: &str = "/stat";

/// Answers a query of an aggregator: a query that verifies under the key
/// set of this relay gets the share of that aggregator, and each other gets
/// 403 with no body (`REL-192`).
async fn answer_stat_query<S>(
    stream: &mut S,
    inbound: &mut Vec<u8>,
    node: &mpsc::Sender<Input>,
    carried: &Carried,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = https::read_request(stream, inbound, STAT_QUERY_LEN).await;
    let keyset = carried
        .manifest_source
        .as_ref()
        .and_then(ManifestSource::keyset);
    let query = match (request, keyset.as_deref()) {
        (Ok(request), Some(keyset)) if request.method == "POST" => DirectoryKeySet::parse(keyset)
            .ok()
            .and_then(|(set, _)| StatQuery::verify(&request.body, &set).ok()),
        _ => None,
    };
    let Some(query) = query else {
        let _ = https::respond(stream, 403, "text/plain", &[]).await;
        return;
    };
    let (reply, answer) = oneshot::channel();
    let answer = match node.send(Input::StatQuery { query, reply }).await {
        Ok(()) => answer.await.ok(),
        Err(_) => None,
    };
    respond_answer(stream, answer).await;
}

async fn relay_ohttp<S>(
    stream: &mut S,
    inbound: &mut Vec<u8>,
    forward: Option<&OhttpForward>,
    (request_max, response_max): (usize, usize),
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let answer = match (
        forward,
        https::read_request(stream, inbound, request_max).await,
    ) {
        (Some(forward), Ok(request)) if request.method == "POST" => https::post(
            &forward.gateway,
            "message/ohttp-req",
            &[],
            &request.body,
            forward.tls.clone(),
            response_max,
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
    stream: S,
    link: LinkId,
    node: mpsc::Sender<Input>,
    carried: Arc<Carried>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + carried.limits.handshake_timeout;
    serve_connection_until(stream, link, node, carried, deadline, None).await;
}

/// [`serve_connection`] under a deadline that the accept set: the TLS
/// handshake and the request share `RELAY_HANDSHAKE_TIMEOUT` (`NET-335`).
/// `source` is the address of the peer as the caps count it.
pub async fn serve_connection_until<S>(
    mut stream: S,
    link: LinkId,
    node: mpsc::Sender<Input>,
    carried: Arc<Carried>,
    deadline: tokio::time::Instant,
    source: Option<[u8; 16]>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut inbound: Vec<u8> = Vec::with_capacity(4_096);
    let mut chunk = vec![0u8; 16_384];
    // NET-335: a POST reads its request and gets its answer by the deadline
    // and a grace for the answer, thus a peer that stalls holds no slot.
    let post_end = deadline + POST_GRACE;
    let request = loop {
        if inbound.starts_with(format!("POST {OHTTP_PATH} ").as_bytes()) {
            let limits = (OHTTP_REQUEST_MAX, OHTTP_RESPONSE_MAX);
            let _ = tokio::time::timeout_at(
                post_end,
                relay_ohttp(&mut stream, &mut inbound, carried.ohttp.as_ref(), limits),
            )
            .await;
            return;
        }
        if inbound.starts_with(format!("POST {DIRECTORY_PATH} ").as_bytes()) {
            let limits = (DIRECTORY_REQUEST_MAX, DIRECTORY_RESPONSE_MAX);
            let _ = tokio::time::timeout_at(
                post_end,
                relay_ohttp(
                    &mut stream,
                    &mut inbound,
                    carried.directory.as_ref(),
                    limits,
                ),
            )
            .await;
            return;
        }
        if inbound.starts_with(format!("POST {RECEIPT_PATH} ").as_bytes()) {
            let _ = tokio::time::timeout_at(
                post_end,
                answer_receipt_query(&mut stream, &mut inbound, &node, &carried),
            )
            .await;
            return;
        }
        if inbound.starts_with(format!("POST {STAT_PATH} ").as_bytes()) {
            let _ = tokio::time::timeout_at(
                post_end,
                answer_stat_query(&mut stream, &mut inbound, &node, &carried),
            )
            .await;
            return;
        }
        if native::asks_challenges(&inbound) && inbound.windows(4).any(|w| w == b"\r\n\r\n") {
            let bundle = carried
                .challenges
                .lock()
                .map(|held| held.clone())
                .unwrap_or_default();
            let head = native::manifest_response_head(bundle.len());
            // NET-335: a peer that reads nothing holds the task no longer
            // than a POST.
            let _ = tokio::time::timeout_at(post_end, async {
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(&bundle).await?;
                stream.shutdown().await
            })
            .await;
            return;
        }
        if native::asks_keychain(&inbound) && inbound.windows(4).any(|w| w == b"\r\n\r\n") {
            // REL-199: the key chain, or 404 before the first rotation.
            let chain = carried
                .keychain
                .lock()
                .map(|held| held.clone())
                .unwrap_or_default();
            let _ = tokio::time::timeout_at(post_end, async {
                match &chain {
                    Some(bytes) => {
                        let head = native::manifest_response_head(bytes.len());
                        stream.write_all(head.as_bytes()).await?;
                        stream.write_all(bytes).await?;
                    }
                    None => {
                        stream.write_all(NOT_FOUND).await?;
                    }
                }
                stream.shutdown().await
            })
            .await;
            return;
        }
        if native::asks_manifest(&inbound) && inbound.windows(4).any(|w| w == b"\r\n\r\n") {
            let manifest = carried
                .manifest
                .lock()
                .map(|held| held.clone())
                .unwrap_or_default();
            let _ = tokio::time::timeout_at(post_end, async {
                match &manifest {
                    Some(bytes) => {
                        let head = native::manifest_response_head(bytes.len());
                        stream.write_all(head.as_bytes()).await?;
                        stream.write_all(bytes).await?;
                    }
                    None => {
                        stream.write_all(NOT_FOUND).await?;
                    }
                }
                stream.shutdown().await
            })
            .await;
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

    let (writer, mut outbound, queued) = LinkWriter::new(LINK_BACKLOG);
    let opened = Input::Opened {
        link,
        writer,
        source,
    };
    if node.send(opened).await.is_err() {
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
                // A peer that reads nothing holds no task: the write ends at
                // its bound, and the link closes.
                let write = stream.write_all(frame.get(..used).unwrap_or(&[]));
                if !matches!(tokio::time::timeout(LINK_WRITE_TIMEOUT, write).await, Ok(Ok(()))) {
                    break 'connection;
                }
                queued.fetch_sub(bytes.len(), Ordering::Relaxed);
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
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .ok()?;
    // A relay link resumes no TLS session and takes no early data: the
    // relay issues no ticket and keeps no session.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Some(TlsAcceptor::from(Arc::new(config)))
}

/// The wait after an accept that failed. The causes pass: the process is
/// out of descriptors, or a peer reset its connection in the queue.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Accepts connections with no end. Accepted links take the even
/// identifiers, and dialed links take the odd ones.
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
    let shaking: PerIp = Arc::new(Mutex::new(BTreeMap::new()));
    let shaking_nets: PerIp = Arc::new(Mutex::new(BTreeMap::new()));
    // The connections of the address of each relay of the set, inside
    // `LINK_OPEN_TIMEOUT`.
    let per_peer: PerIp = Arc::new(Mutex::new(BTreeMap::new()));
    loop {
        // NET-333: an accept that fails ends no relay. It writes no line,
        // because the cause can come from a peer at will.
        let Ok((tcp, address)) = listener.accept().await else {
            tokio::time::sleep(ACCEPT_RETRY).await;
            continue;
        };
        // NET-333: a relay at its cap closes a new connection at once.
        if open.load(Ordering::Relaxed) >= limits.max_connections {
            continue;
        }
        // NET-334: one address holds at most its share. A relay of the set
        // opens connections for its pushes, thus its address holds more of
        // them, in a count of its own, until `LINK_OPEN_TIMEOUT`. A push
        // ends before it. Before this, the caps counted no connection of
        // such an address. Each host at the address of a listed relay then
        // held connections and handshakes with no bound.
        let ip = address.ip().to_canonical();
        let source = address_key(ip);
        let is_exempt = limits.loopback_exempt && ip.is_loopback();
        let is_peer = !is_exempt
            && carried
                .relay_addresses
                .lock()
                .is_ok_and(|relays| relays.contains(&ip));
        let counted = limits.per_ip_max > 0 && !is_exempt;
        let mut place = None;
        let mut peer_place = None;
        if counted && is_peer {
            let max = limits
                .per_ip_max
                .saturating_mul(ConnectionLimits::PEER_PART);
            let Some(taken) = Place::take(&per_peer, source, max) else {
                continue;
            };
            peer_place = Some(taken);
        } else if counted {
            let Some(taken) = Place::take(&per_ip, source, limits.per_ip_max) else {
                continue;
            };
            place = Some(taken);
        }
        open.fetch_add(1, Ordering::Relaxed);
        let held = Held { open: open.clone() };
        let handshakes = handshakes.clone();
        let shaking = shaking.clone();
        let shaking_nets = shaking_nets.clone();
        let per_ip = per_ip.clone();
        let _ = tcp.set_nodelay(true);
        let tls = tls.clone();
        let node = node.clone();
        let carried = carried.clone();
        let this_link = link;
        link = link.saturating_add(2);
        // NET-335: one deadline from the accept covers the TLS handshake and
        // the request.
        let accepted_at = tokio::time::Instant::now();
        let deadline = accepted_at + limits.handshake_timeout;
        tokio::spawn(async move {
            let _held = held;
            let mut place = place;
            // NET-335: a connection takes no handshake before its whole
            // `ClientHello`. The relay reads it with no key operation, and
            // one that is not whole at RELAY_FIRST_BYTES_TIMEOUT ends. A set
            // of silent sockets thus holds no handshake back. Before this,
            // one byte took a place among the handshakes for the whole of
            // RELAY_HANDSHAKE_TIMEOUT.
            let first = deadline.min(accepted_at + limits.first_bytes_timeout);
            let hello =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
            let Ok(Ok(start)) = tokio::time::timeout_at(first, hello).await else {
                return;
            };
            // NET-335: one address and one network run at most their share
            // of the handshakes.
            let mut mine = None;
            let mut ours = None;
            if !is_exempt && limits.handshakes_per_ip > 0 {
                let max = if is_peer {
                    limits
                        .handshakes_per_ip
                        .saturating_mul(ConnectionLimits::PEER_PART)
                } else {
                    limits.handshakes_per_ip
                };
                let Some(taken) = Place::take(&shaking, source, max) else {
                    return;
                };
                mine = Some(taken);
            }
            if !is_exempt && !is_peer && limits.handshakes_per_net > 0 {
                let Some(taken) =
                    Place::take(&shaking_nets, net_key(ip), limits.handshakes_per_net)
                else {
                    return;
                };
                ours = Some(taken);
            }
            // NET-335: a bound holds the TLS handshakes that run at once,
            // thus a flood of them costs the relay a fixed amount of work.
            // A connection above the bound waits for a place until its
            // deadline.
            let Ok(Ok(permit)) =
                tokio::time::timeout_at(deadline, handshakes.acquire_owned()).await
            else {
                return;
            };
            // The rest of the handshake is one flight of each side, and a
            // peer that holds its own back gives the place up at
            // RELAY_HANDSHAKE_END_TIMEOUT.
            let end = deadline.min(tokio::time::Instant::now() + limits.handshake_end_timeout);
            let accepted =
                tokio::time::timeout_at(end, start.into_stream(tls.config().clone())).await;
            drop(permit);
            drop(mine);
            drop(ours);
            let Ok(Ok(stream)) = accepted else {
                return;
            };
            let serve =
                serve_connection_until(stream, this_link, node, carried, deadline, Some(source));
            tokio::pin!(serve);
            if let Some(until_open) = peer_place {
                // NET-334: the address of a relay of the set holds its
                // larger count until the time of the `Open` and the hello
                // ended. A push is over by then. A link that lives on is
                // the link of a relay of the layer before, or the link of
                // a client at that address. It takes a place of the address
                // as each other connection does, and it closes when the
                // address holds none.
                let window = deadline + Duration::from_secs(LINK_OPEN_TIMEOUT);
                tokio::select! {
                    () = &mut serve => return,
                    () = tokio::time::sleep_until(window) => {}
                }
                drop(until_open);
                let Some(taken) = Place::take(&per_ip, source, limits.per_ip_max) else {
                    return;
                };
                place = Some(taken);
            }
            serve.await;
            drop(place);
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
        // NET-319: the node dials again while a body waits for this relay.
        let _ = node.send(Input::DialFailed { relay_id }).await;
        return;
    };
    let (writer, mut outbound, queued) = LinkWriter::new(RELAY_LINK_BACKLOG);
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
                Some(bytes) => {
                    let sent = tokio::time::timeout(LINK_WRITE_TIMEOUT, connection.send(&bytes)).await;
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                    queued.fetch_sub(bytes.len(), Ordering::Relaxed);
                }
                None => break,
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
    mut node: RelayNode,
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
    // A newer manifest moves the routes of the dialer while the relay runs.
    let routes = Arc::new(Mutex::new(Routes {
        next_hops: next_hops.clone(),
        replicas,
    }));
    tokio::spawn(reload_manifest(
        carried.clone(),
        client_tls.clone(),
        routes.clone(),
        inputs.clone(),
    ));
    // NET-167: the relays that the dialer reaches are the next layer.
    node.set_next_layer(next_hops.keys().copied().collect());
    let node_task = tokio::spawn(run_node(node, node_inputs, requests, pacing_mean_ms, store));
    // ABU-099: the keys of the issuer come from the log, on a thread of
    // their own, since each read blocks.
    let reader = carried
        .issuer_reader
        .lock()
        .ok()
        .and_then(|mut held| held.take());
    if let Some(reader) = reader {
        let key_inputs = inputs.clone();
        tokio::task::spawn_blocking(move || crate::issuer_keys::keep_reading(reader, key_inputs));
    }

    let dial_inputs = inputs.clone();
    tokio::spawn(async move {
        let mut link: LinkId = 1;
        let pushes_held = Arc::new(tokio::sync::Semaphore::new(PUSHES_HELD));
        let pushes_running = Arc::new(tokio::sync::Semaphore::new(PUSHES_RUNNING));
        let mut lanes: BTreeMap<[u8; 32], Arc<Lane>> = BTreeMap::new();
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
                    let target = routes
                        .lock()
                        .ok()
                        .and_then(|held| held.next_hops.get(&relay_id).cloned());
                    if let Some(target) = target {
                        let tls = client_tls.clone();
                        tokio::spawn(dial_next(relay_id, target, link, tls, dial_inputs.clone()));
                        link = link.saturating_add(2);
                    }
                }
                // ATT-105: a relay that the set does not name gets no copy.
                Request::Push { relay_id, capsule } => {
                    // A chunk copy goes to a relay with the attachment role,
                    // and a deposit to a queue relay (`WIR-526`).
                    let target = routes
                        .lock()
                        .ok()
                        .and_then(|held| held.replicas.get(&relay_id).cloned());
                    if let Some(target) = target {
                        // The lanes of the relays that left the set go.
                        if !lanes.contains_key(&relay_id) {
                            if let Ok(held) = routes.lock() {
                                lanes.retain(|id, _| held.replicas.contains_key(id));
                            }
                        }
                        let lane = lanes.entry(relay_id).or_default().clone();
                        // A chunk copy is large and slow, and a deposit or a
                        // challenge is small: each kind has its places.
                        let is_copy = matches!(
                            umbra_wire::capsule::parse(&capsule),
                            Ok((umbra_wire::capsule::CapsuleType::Replica, _, _))
                        );
                        if !is_copy {
                            // WIR-526: the deposits and the challenges of one
                            // relay wait in its lane.
                            if lane.queue(capsule) {
                                let routes = routes.clone();
                                let tls = client_tls.clone();
                                tokio::spawn(run_lane(relay_id, lane, routes, tls));
                            }
                            continue;
                        }
                        let Ok(held) = pushes_held.clone().try_acquire_owned() else {
                            continue;
                        };
                        let running = pushes_running.clone();
                        let tls = client_tls.clone();
                        tokio::spawn(async move {
                            let _held = held;
                            let Ok(_running) = running.acquire_owned().await else {
                                return;
                            };
                            let copy = push_copy(target, tls, capsule, lane);
                            let _ = tokio::time::timeout(PUSH_TIMEOUT, copy).await;
                        });
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
    // The node task ends when the store fails or when a newer relay set
    // gives the relay another layer, and the relay ends with it.
    tokio::select! {
        () = accept_loop(listener, tls, inputs, carried) => {}
        _ = node_task => {}
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// The bytes that one answer of the node puts on the connection.
    fn sent(answer: Option<QueryAnswer<Vec<u8>>>) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut near, mut far) = tokio::io::duplex(4_096);
            respond_answer(&mut near, answer).await;
            let mut read = Vec::new();
            far.read_to_end(&mut read).await.unwrap();
            String::from_utf8(read).unwrap()
        })
    }

    #[test]
    fn a_lane_drops_its_oldest_capsule_and_a_dead_relay_waits_longer_each_time() {
        let lane = Lane::default();
        // The first capsules start the workers of the lane, and no more.
        assert!(lane.queue(vec![0]));
        assert!(lane.queue(vec![1]));
        assert!(!lane.queue(vec![2]));
        // One more than `LANE_HELD` drops the oldest that waits.
        for index in 3..=LANE_HELD {
            assert!(!lane.queue(index.to_be_bytes().to_vec()));
        }
        assert_eq!(lane.take(), Some(vec![1]));
        assert_eq!(lane.take(), Some(vec![2]));
        assert!(!lane.rests());

        // A connection that opens has the whole of `CONNECT_TIME`, and the
        // lane holds nothing back.
        let now = tokio::time::Instant::now();
        assert_eq!(lane.budget(), (None, CONNECT_TIME));
        // One that does not open gives the next try a short time, after a
        // wait that doubles up to `LANE_HOLD_OFF_MAX`.
        lane.connected(false, now);
        assert_eq!(
            lane.budget(),
            (Some(now + LANE_HOLD_OFF), CONNECT_TIME_AFTER_FAILURE)
        );
        lane.connected(false, now);
        assert_eq!(lane.budget().0, Some(now + 2 * LANE_HOLD_OFF));
        for _ in 0..40 {
            lane.connected(false, now);
        }
        assert_eq!(lane.budget().0, Some(now + LANE_HOLD_OFF_MAX));
        lane.connected(true, now);
        assert_eq!(lane.budget(), (None, CONNECT_TIME));

        // A worker that finds nothing ends, and the next capsule starts one.
        let empty = Lane::default();
        assert!(empty.queue(vec![7]));
        assert_eq!(empty.take(), Some(vec![7]));
        assert!(empty.rests());
        assert!(empty.queue(vec![8]));
        // A relay that left the set takes nothing more.
        empty.close();
        assert!(empty.queue(vec![9]));
        assert_eq!(empty.take(), Some(vec![9]));
        assert_eq!(empty.take(), None);
    }

    #[test]
    fn the_caps_count_an_address_by_its_host_and_by_its_network() {
        let v4 = |d: u8| IpAddr::from([203, 0, 113, d]);
        // NET-334: an IPv4 address counts whole, and its network is its
        // first 24 bits.
        assert_ne!(address_key(v4(1)), address_key(v4(2)));
        assert_eq!(net_key(v4(1)), net_key(v4(2)));
        assert_ne!(net_key(v4(1)), net_key(IpAddr::from([203, 0, 114, 1])));
        // One host holds each IPv6 address below its first 64 bits, and
        // the network is the first 48 bits.
        let v6 = |subnet: u16, host: u16| IpAddr::from([0x2001, 0xdb8, 0x1, subnet, 0, 0, 0, host]);
        assert_eq!(address_key(v6(1, 1)), address_key(v6(1, 2)));
        assert_ne!(address_key(v6(1, 1)), address_key(v6(2, 1)));
        assert_eq!(net_key(v6(1, 1)), net_key(v6(2, 1)));
        assert_ne!(
            net_key(v6(1, 1)),
            net_key(IpAddr::from([0x2001, 0xdb8, 0x2, 1, 0, 0, 0, 1]))
        );
        // An IPv4 address and the IPv6 address that maps it are one.
        let mapped = IpAddr::from([0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7101]).to_canonical();
        assert_eq!(address_key(mapped), address_key(v4(1)));
    }

    #[test]
    fn a_query_that_names_another_relay_gets_403_with_no_body() {
        // REL-180, REL-192: the refusal is 403 with a length of 0, and it
        // is not the 429 of a query above the bound.
        let elsewhere = sent(Some(QueryAnswer::Elsewhere));
        assert!(elsewhere.starts_with("HTTP/1.1 403 "));
        assert!(elsewhere.contains("\r\nContent-Length: 0\r\n"));
        assert!(elsewhere.ends_with("\r\n\r\n"));

        // REL-187: the bound keeps its own status.
        let above = sent(Some(QueryAnswer::Above));
        assert!(above.starts_with("HTTP/1.1 429 "));
        assert!(above.ends_with("\r\n\r\n"));

        let given = sent(Some(QueryAnswer::Given(vec![b'a', b'b'])));
        assert!(given.starts_with("HTTP/1.1 200 "));
        assert!(given.ends_with("\r\n\r\nab"));
        assert!(sent(None).starts_with("HTTP/1.1 503 "));
    }
}
