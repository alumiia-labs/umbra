//! One relay as a state machine: the session links of Part 6 §6.2, the
//! circuits of Part 3 §3.4, the services at the end of a circuit, and the
//! paced delivery of Part 3 §3.5.2.
//!
//! The node draws no random value and opens no socket, and it reads one
//! clock: the one of the per-hop delay. The runtime gives it the bytes of
//! each link, the ticks of each pacing clock, and the time, and it sends
//! what the node returns.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::Bound,
};

/// The clock of the per-hop delay of Part 3 §3.9: the milliseconds since
/// its first read. It never steps back, thus a change of the wall clock
/// holds no cell and releases none early (`NET-339`).
pub fn clock_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let elapsed = START.get_or_init(std::time::Instant::now).elapsed();
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

use umbra_core::{
    abuse::{
        admission::{Accepts, RelayGate},
        pow::{ChallengeBook, PowChallenge},
    },
    attach::command::{CrputPayload, CRPUT_LEN},
    directory::{
        measure::{
            verify_open, MeasurerTrust, MEAS_ATTEMPT_BURST, MEAS_ATTEMPT_PERIOD, MEAS_CIRCUITS_MAX,
            MEAS_SESSIONS_MAX, MEAS_SESSION_MAX,
        },
        receipt,
        stat::{StatAnswer, StatQuery},
        EPOCH_SECONDS,
    },
    notify::digest::NotifyDigest,
    session::{
        batch::{unpack, Range},
        channel::Outbound as ChannelOutbound,
    },
};
use umbra_crypto::{
    handshake::nk::RelayStatic, rand_core::CryptoRng, rsabssa::PublicKey2048, secret::Secret,
    x25519::StaticSecret,
};
use umbra_onion::CIRCUIT_BUILD_TIMEOUT;
use umbra_queue::{relay::session::Session, Reject};
use umbra_transport::link::{ClientLink, RelayLink, ResumeFault};
use umbra_wire::{
    address::QueueAddress,
    bucket::Bucket,
    capsule::{self, CapsuleType, Link as CapsuleLink},
    cell::CellCommand,
    command::{Cmd, Command},
    queue::L6Kind,
    session::SessionControl,
};

use crate::{
    circuits::{Action, CircuitKey, CircuitTable, Holder, LinkId, Origin},
    loops::Loops,
    receipts::{Asked, ReceiptBook},
    service::{
        chunk::{ChunkService, Push},
        group::GroupService,
        nack,
        queue::{NdrPush, QueueService},
        DigestDue, Drains, Outbound, Reply,
    },
    store::{Loaded, StoreChange},
};

/// What a relay does with a query of an authority that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryAnswer<T> {
    /// The answer.
    Given(T),
    /// The authority is above its bound (`REL-187`).
    Above,
    /// The query names another relay. It gets no body, and it counts
    /// toward no bound (`REL-180`, `REL-192`).
    Elsewhere,
}

impl<T> QueryAnswer<T> {
    /// The answer, when the relay gave one.
    pub fn given(self) -> Option<T> {
        match self {
            QueryAnswer::Given(answer) => Some(answer),
            QueryAnswer::Above | QueryAnswer::Elsewhere => None,
        }
    }
}

/// The notification key of a queue relay, from its static secret under a
/// label of its own (`NTF-112`). A relay of another layer holds no queue.
fn notify_pair(config: &Config) -> Option<umbra_crypto::kem::KeyPair> {
    (config.layer == 3).then(|| {
        // `Zeroizing` wipes the copy of the static secret after the derivation.
        let secret = umbra_crypto::zeroize::Zeroizing::new(config.static_secret.to_bytes());
        umbra_core::notify::seeded_pair(umbra_crypto::labels::RELAY_NTF, &secret)
    })
}

/// `DRAIN_THRESHOLD`: above this count the answer to a `SUB` goes in one
/// unpaced response (`NET-037`).
pub const DRAIN_THRESHOLD: usize = 60;

/// What the node asks of the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Write these capsule bytes to a link.
    Send {
        /// The link.
        link: LinkId,
        /// One capsule.
        capsule: Vec<u8>,
    },
    /// The node holds no link to a relay of the next layer. The runtime
    /// dials it, and each `EXTEND` that waits for it goes on the link that
    /// opens (`NET-319`).
    Dial {
        /// The relay.
        relay_id: [u8; 32],
    },
    /// Send one `NPUSH` to the NDR over OHTTP (Part 8 §8.2.7). The runtime
    /// gives an answer `gone` back through [`RelayNode::ndr_gone`].
    NdrPush(NdrPush),
    /// Send one capsule to another relay, on a connection with no session:
    /// the copy of a chunk (`WIR-211`) or the deposit of a digest
    /// (`WIR-526`). The runtime keeps nothing of it after the send.
    Push {
        /// The relay that takes the copy.
        relay_id: [u8; 32],
        /// One `UMBRA_REPLICA` capsule.
        capsule: Vec<u8>,
    },
    /// Close the link.
    Close {
        /// The link.
        link: LinkId,
    },
    /// A resume bound the session of `as_link` to the connection of `link`
    /// (`WIR-241`). From now on the runtime serves that connection under
    /// the identifier `as_link`, and it closes the connection that held
    /// that identifier before, if one is open (`WIR-242`). The node names
    /// `link` no more.
    Adopt {
        /// The connection that sent the resume.
        link: LinkId,
        /// The identifier of the session that it continues.
        as_link: LinkId,
    },
}

/// One capsule of `kind` for `link`.
fn capsule_output(link: LinkId, kind: CapsuleType, value: &[u8]) -> Option<Output> {
    let mut capsule = vec![0u8; capsule::HEADER_LEN + value.len()];
    let used = capsule::encode(kind, value, &mut capsule).ok()?;
    capsule.truncate(used);
    Some(Output::Send { link, capsule })
}

/// The session capsule that tells a neighbor that the circuit of
/// `circ_id` on their link ended (`NET-322`).
fn destroy_output(link: LinkId, circ_id: [u8; 16]) -> Option<Output> {
    let mut control = [0u8; 17];
    let used = SessionControl::Destroy { circ_id }
        .encode(&mut control)
        .ok()?;
    let mut capsule = vec![0u8; capsule::HEADER_LEN + used];
    let used = capsule::encode(CapsuleType::Session, control.get(..used)?, &mut capsule).ok()?;
    capsule.truncate(used);
    Some(Output::Send { link, capsule })
}

/// The session capsule that tells the next hop that the client of the
/// circuit of `circ_id` on their link paused its session (`WIR-545`).
fn pause_output(link: LinkId, circ_id: [u8; 16]) -> Option<Output> {
    let mut control = [0u8; 17];
    let used = SessionControl::CircuitPause { circ_id }
        .encode(&mut control)
        .ok()?;
    capsule_output(link, CapsuleType::Session, control.get(..used)?)
}

/// The byte of a `CRPUT` (Part 12 §12.3.3).
const CRPUT: u8 = 0x77;

/// The capsule of one copy. The header carries no authenticator, because
/// the token of the payload authorizes a copy (`ATT-107`, `ATT-108`).
fn push_output(push: &Push) -> Option<Output> {
    let mut payload = vec![0u8; CRPUT_LEN];
    CrputPayload {
        storage_token: push.target.storage_token,
        chunk: &push.chunk,
    }
    .encode(&mut payload)
    .ok()?;
    let command = Command {
        cmd: Cmd::Attachment(CRPUT),
        // No answer names this value, and a fixed one keeps a relay from a
        // draw that it does not need.
        corr_id: [0; 16],
        queue_id: push.chunk_id,
        auth: [0; 32],
        payload: &payload,
    };
    let mut encoded = vec![0u8; command.len()];
    command.encode(&mut encoded).ok()?;
    let mut capsule = vec![0u8; capsule::HEADER_LEN + encoded.len()];
    let used = capsule::encode(CapsuleType::Replica, &encoded, &mut capsule).ok()?;
    capsule.truncate(used);
    Some(Output::Push {
        relay_id: push.target.relay_id,
        capsule,
    })
}

/// The settings of one relay.
pub struct Config {
    /// The static key and the identifier of the descriptor.
    pub relay: RelayStatic,
    /// The private half of the static key.
    pub static_secret: StaticSecret,
    /// The layer of the relay, from 1 to 3.
    pub layer: u8,
    /// The bytes of the chunk store of Part 12, or zero for a relay with no
    /// attachment role.
    pub chunk_capacity: u64,
}

enum Framing {
    /// A session that a client or a relay of the layer before opened.
    Accepted(RelayLink),
    /// A session that this relay opened to a relay of the next layer.
    Dialed(ClientLink),
}

struct Endpoint {
    session: Session,
    range: Option<Range>,
    outbox: VecDeque<Outbound>,
    /// The drains of the circuit (`NET-037`), whose records leave in steps
    /// at each clock tick, thus one drain fills no link backlog. A drain
    /// holds no record.
    drains: Drains,
    loops: u32,
    /// The client of the circuit paused its session (`WIR-546`). The
    /// pacing clock of the circuit stops until the next forward cell of
    /// that client.
    paused: bool,
}

/// The signature checks of challenges and relay hellos that one link may
/// ask for in a minute.
const VERIFIES_PER_MINUTE: u32 = 32;

/// The deposits that one link may send in a minute. A deposit for a known
/// queue costs one X25519 agreement and one MAC, and no session gates it.
/// A relay sends at most this many deposits on one connection (`WIR-526`),
/// and that connection ends long before its minute. An honest link thus
/// stays inside the bound.
pub const DEPOSITS_PER_MINUTE: u32 = 32;

/// The answers that wait for the pacing clock of one circuit. The clock
/// sends one cell each second (`NET-291`), thus a circuit that asks for
/// more loses the newest: a record leaves its queue only at its `ACK`, and
/// a command that took no answer goes again.
const OUTBOX_MAX: usize = 1_024;
/// The bytes of the answers that one tick of the pacing clock sends on one
/// attachment circuit (`NET-360`).
const ANSWER_STEP: usize = 256 << 10;
/// The bytes of a drain that one clock tick sends on one circuit. The
/// records of one step are the one copy of a backlog that the relay makes.
/// They go to their link in the same call. The drains of a link thus
/// hold at most what `DRAIN_CALM_PART` leaves them of its backlog, and a
/// drain that waits holds nothing.
const DRAIN_STEP: usize = 256 << 10;
/// The share of the backlog of a link above which no drain takes a step on
/// it: one part in this many (`NET-349`).
const DRAIN_CALM_PART: usize = 4;
/// The bytes that the frame and the capsule add to a cell.
const FRAME_ROOM: usize = 32;
/// The part of the bound of a link that stays free: one part in this many
/// (`NET-349`). It serves the cells of the circuits that did not fill the
/// link. A cell that reaches into it ends the circuit that holds the most
/// of the backlog.
const SHED_MARK_PART: usize = 8;
/// A circuit below this share of the bound of a link never counts as the
/// one that filled it. The share is one part in this many, some cells of
/// the largest bucket.
const SHED_FLOOR_PART: usize = 256;

/// The cells that wait on one link in the order of their framing, and the
/// bytes of each circuit among them (`NET-349`). The runtime writes the
/// capsules of a link in their order, thus the bytes that wait are those of
/// the last cells.
#[derive(Default)]
struct Waits {
    cells: VecDeque<([u8; 16], usize)>,
    total: usize,
    by_circuit: BTreeMap<[u8; 16], usize>,
    /// The same counts in their order, thus the node finds the circuit that
    /// holds the most with no scan.
    ranked: BTreeSet<(usize, [u8; 16])>,
}

impl Waits {
    /// Moves the bytes of one circuit, when the link still counts it.
    fn moved(&mut self, circ_id: [u8; 16], len: usize, up: bool) {
        let Some(before) = self.by_circuit.get(&circ_id).copied() else {
            return;
        };
        let after = if up {
            before.saturating_add(len)
        } else {
            before.saturating_sub(len)
        };
        self.ranked.remove(&(before, circ_id));
        if after == 0 {
            self.by_circuit.remove(&circ_id);
        } else {
            self.by_circuit.insert(circ_id, after);
            self.ranked.insert((after, circ_id));
        }
    }

    /// Counts one framed cell of `len` bytes.
    fn add(&mut self, circ_id: [u8; 16], len: usize) {
        self.cells.push_back((circ_id, len));
        self.total = self.total.saturating_add(len);
        self.by_circuit.entry(circ_id).or_insert(0);
        self.moved(circ_id, len, true);
    }

    /// Drops the cells that left: the link holds `waiting` bytes.
    fn trim(&mut self, waiting: usize) {
        while let Some((circ_id, len)) = self.cells.front().copied() {
            if self.total.saturating_sub(len) < waiting {
                break;
            }
            self.cells.pop_front();
            self.total = self.total.saturating_sub(len);
            self.moved(circ_id, len, false);
        }
    }

    /// The bytes of `circ_id` that wait.
    fn of(&self, circ_id: &[u8; 16]) -> usize {
        self.by_circuit.get(circ_id).copied().unwrap_or(0)
    }

    /// The circuit other than `circ_id` that holds the most, with its
    /// bytes.
    fn heaviest_but(&self, circ_id: &[u8; 16]) -> Option<([u8; 16], usize)> {
        self.ranked
            .iter()
            .rev()
            .find(|(_, held)| held != circ_id)
            .map(|(bytes, held)| (*held, *bytes))
    }

    /// A circuit ended. Its cells still wait, and it holds no rank.
    fn forget(&mut self, circ_id: &[u8; 16]) {
        if let Some(bytes) = self.by_circuit.remove(circ_id) {
            self.ranked.remove(&(bytes, *circ_id));
        }
    }
}

impl Endpoint {
    /// Puts one answer on the pacing clock, at the front for a `NACK`
    /// (`WIR-322`).
    fn post(&mut self, outbound: Outbound, first: bool) {
        if self.outbox.len() >= OUTBOX_MAX {
            return;
        }
        if first {
            self.outbox.push_front(outbound);
        } else {
            self.outbox.push_back(outbound);
        }
    }
}

/// The bytes that wait on each link, which the runtime counts (`NET-349`).
/// The node asks before it frames a cell, thus a link near its bound loses
/// the circuit that filled it and stays.
pub trait Backlog: Send {
    /// The bytes that wait on `link` and the bytes that it holds at most,
    /// or none for a link that the runtime does not know.
    fn of(&self, link: LinkId) -> Option<(usize, usize)>;
}

/// The time that an accepted link has for the capsule that makes it a link
/// of this relay (`NET-335`). That capsule is the `Open` of a session. At a
/// relay of layer 2 or 3, the hello of a relay of the layer before serves
/// too.
pub const LINK_OPEN_TIMEOUT: u64 = 10;
/// The time that a client link holds no circuit before an ingress relay
/// closes it (`NET-335`).
pub const LINK_IDLE_TIMEOUT: u64 = 600;
/// The time that a dial has before the node asks for a new one. The dial of
/// the runtime gives up before it.
const DIAL_TIMEOUT: u64 = 15;
/// The time between a dial that failed and the next one (`NET-319`).
const DIAL_HOLD_OFF: u64 = 1;
/// `EXTEND_WAITING_MAX`: the `EXTEND` bodies that wait for the link to one
/// relay of the next layer (`NET-319`). A body above it ends its circuit.
pub const EXTEND_WAITING_MAX: usize = 8_192;
/// `RELAY_DELAYED_MAX`: the forward cells that wait for their per-hop
/// delay at one relay (`NET-362`). A cell above it ends its circuit.
pub const RELAY_DELAYED_MAX: usize = 1 << 17;

/// The last dial of a relay of the next layer that opened no link.
#[derive(Clone, Copy)]
struct Dialing {
    at: u64,
    failed: bool,
}

/// Whether `len` more bytes fit on `link`, below the share `part` of its
/// bound, with the `framed` bytes that the runtime did not count yet.
fn fits(
    backlog: Option<&dyn Backlog>,
    framed: &BTreeMap<LinkId, usize>,
    link: LinkId,
    len: usize,
    part: usize,
) -> bool {
    let Some((held, limit)) = backlog.and_then(|backlog| backlog.of(link)) else {
        return true;
    };
    let waiting = framed.get(&link).copied().unwrap_or(0);
    held.saturating_add(waiting).saturating_add(len) <= limit / part.max(1)
}

/// The addresses whose measurement attempts a relay counts at once. An
/// address above this count holds no attempt.
const MEAS_ATTEMPT_SOURCES_MAX: usize = 4_096;
/// The part of the bound of a link that the echoes of a measurement
/// session fill at most: one part in this many. An echo above it drops
/// (`REL-204`).
const ECHO_PART: usize = 2;

/// One measurement session: the circuits of one measurer (`REL-202`).
struct MeasureSession {
    until: u64,
    circuits: BTreeSet<CircuitKey>,
}

/// The measurement attempts that one address spent (`REL-069`).
#[derive(Clone, Copy)]
struct Attempts {
    spent: u32,
    since: u64,
}

impl Attempts {
    /// Gives back one attempt for each `MEAS_ATTEMPT_PERIOD` since the
    /// last one came back.
    fn refill(&mut self, now: u64) {
        let back = now.saturating_sub(self.since) / MEAS_ATTEMPT_PERIOD;
        if back > 0 {
            self.spent = self
                .spent
                .saturating_sub(u32::try_from(back).unwrap_or(u32::MAX));
            self.since = self
                .since
                .saturating_add(back.saturating_mul(MEAS_ATTEMPT_PERIOD));
        }
    }
}

/// One `EXTEND` body that waits for a link to its next relay.
struct Waiting {
    /// The held circuit that the body extends.
    from: CircuitKey,
    body: Vec<u8>,
    arrived_at: u64,
}

impl Waiting {
    /// Whether the client still waits, under `CIRCUIT_BUILD_TIMEOUT`.
    fn is_live(&self, now: u64) -> bool {
        now.saturating_sub(self.arrived_at) < CIRCUIT_BUILD_TIMEOUT
    }
}

/// One relay.
pub struct RelayNode {
    /// The key of the cross-relay issuer of each epoch, from the log
    /// (Part 13 §13.5).
    issuer_keys: BTreeMap<u32, PublicKey2048>,
    links: BTreeMap<LinkId, Framing>,
    /// The accepted link of each session, by `session_id` (`WIR-233`). A
    /// `SessionResume` finds its session here.
    sessions: BTreeMap<[u8; 8], LinkId>,
    /// The client links of an ingress relay that hold no connection: their
    /// client paused the session, or the connection closed with no
    /// `SessionClose` (`WIR-541`, `WIR-542`). Each one holds the `circ_id`
    /// of each circuit that ended since, for the `CircuitDestroy` after
    /// the resume (`WIR-543`).
    parked: BTreeMap<LinkId, Vec<[u8; 16]>>,
    next_hops: BTreeMap<[u8; 32], LinkId>,
    /// The `EXTEND` bodies that wait for a link to their next relay
    /// (`NET-319`).
    extending: BTreeMap<[u8; 32], Vec<Waiting>>,
    /// The actions of forward cells that wait for the per-hop delay of
    /// their circuit, by release time and arrival (Part 3 §3.9).
    delayed: BTreeMap<(u64, u64), (CircuitKey, Action)>,
    delayed_seq: u64,
    circuits: CircuitTable,
    endpoints: BTreeMap<CircuitKey, Endpoint>,
    gate: RelayGate,
    queues: QueueService,
    groups: GroupService,
    chunks: ChunkService,
    /// The identifier and the static key of this relay, for a deposit that
    /// a relay writes into one of its own queues and for the auth of each
    /// deposit it takes (`WIR-526`).
    relay: RelayStatic,
    static_secret: StaticSecret,
    /// The static key of each queue relay of the relay set, for a deposit.
    queue_relays: BTreeMap<[u8; 32], [u8; 32]>,
    /// The identity key that signs the challenges of this relay.
    pow_key: Option<umbra_crypto::sign::SigningKey>,
    /// The carriers of the relay manifest, which serve the challenge of
    /// this relay beside it (`ABU-102`).
    carriers: Vec<[u8; 32]>,
    /// The identity key of each relay of the set, for a challenge that
    /// this relay carries (`ABU-103`).
    identities: BTreeMap<[u8; 32], Vec<u8>>,
    /// The newest challenge of each relay, when this relay carries the
    /// manifest.
    challenges: ChallengeBook,
    /// Whether the book moved since the last read of it.
    challenges_moved: bool,
    /// The signature checks that each link asked for in the minute that
    /// runs: a challenge or a relay hello costs one ML-DSA verification on
    /// the task that serves each circuit, and no session gates it.
    verifies: BTreeMap<LinkId, (u64, u32)>,
    /// The deposits that each link sent in the minute that runs.
    deposits: BTreeMap<LinkId, (u64, u32)>,
    /// The relays of the next layer that this relay may dial; empty for a
    /// node that takes each named relay, as a test does (`NET-167`).
    next_layer: BTreeSet<[u8; 32]>,
    /// The relays of the layer before, when the relay set gives them: a
    /// hello that names another relay names no peer (`REL-174`).
    previous_layer: Option<BTreeSet<[u8; 32]>>,
    /// The link receipts (Part 10 §10.4.2).
    receipts: ReceiptBook,
    /// The layer of this relay.
    layer: u8,
    /// The last dial of each relay of the next layer that opened no link
    /// yet (`NET-319`).
    dials: BTreeMap<[u8; 32], Dialing>,
    /// The accepted links that sent no `Open` yet, with the time of their
    /// first sight (`NET-335`). At a relay of layer 2 or 3, a hello that
    /// verified counts as an `Open`.
    fresh: BTreeMap<LinkId, u64>,
    /// The client links that held no circuit at a sweep, with the time of
    /// that sweep (`NET-335`).
    quiet: BTreeMap<LinkId, u64>,
    /// The backlog of each link (`NET-349`).
    backlog: Option<Box<dyn Backlog>>,
    /// The bytes of the cells that the node framed for each link since the
    /// runtime took its outputs.
    framed: BTreeMap<LinkId, usize>,
    /// The cells that wait on each link, by circuit (`NET-349`).
    waits: BTreeMap<LinkId, Waits>,
    /// The circuits that hold a drain.
    draining: BTreeSet<CircuitKey>,
    /// The last circuit whose drain took a step. The next tick starts after
    /// it, thus the drains of one link take its room in turns.
    drain_turn: Option<CircuitKey>,
    /// The count of the chains that this relay opened, for a test.
    builds_seen: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// The key set and the revoked list of the current root, under which
    /// a `MeasurerCert` verifies (`REL-066`). A relay that holds none opens
    /// no measurement session.
    measure_trust: Option<MeasurerTrust>,
    /// The open measurement sessions, by `measurer_id` (`REL-202`).
    measure_sessions: BTreeMap<[u8; 16], MeasureSession>,
    /// The measurement attempts of each address (`REL-069`).
    measure_attempts: BTreeMap<Holder, Attempts>,
    /// The address of each link, as the runtime cut it.
    sources: BTreeMap<LinkId, [u8; 16]>,
    /// The loop chains of this relay (`NET-069`).
    loops: Loops,
    /// Whether the circuits take their time from the clock of the per-hop
    /// delay, which never steps back, in place of the time of each call.
    monotonic: bool,
    /// The circuits whose pacing clock started since the runtime last
    /// asked: a new endpoint, or one whose client woke it (`NET-035`).
    paced_new: BTreeSet<CircuitKey>,
}

impl RelayNode {
    /// A relay with no link and no circuit.
    pub fn new(config: Config) -> Self {
        let relay_id = config.relay.relay_id;
        let relay = RelayStatic {
            s: config.relay.s,
            relay_id,
        };
        let static_secret = config.static_secret.clone();
        let layer = config.layer;
        let mut queues = QueueService::default();
        if let Some(pair) = notify_pair(&config) {
            queues.set_notify_key(pair);
        }
        RelayNode {
            issuer_keys: BTreeMap::new(),
            links: BTreeMap::new(),
            sessions: BTreeMap::new(),
            parked: BTreeMap::new(),
            next_hops: BTreeMap::new(),
            extending: BTreeMap::new(),
            delayed: BTreeMap::new(),
            delayed_seq: 0,
            circuits: CircuitTable::new(config.relay, config.static_secret, config.layer),
            endpoints: BTreeMap::new(),
            gate: RelayGate::new(relay_id),
            queues,
            groups: GroupService::default(),
            chunks: ChunkService::new(config.chunk_capacity),
            relay,
            static_secret,
            queue_relays: BTreeMap::new(),
            pow_key: None,
            carriers: Vec::new(),
            identities: BTreeMap::new(),
            challenges: ChallengeBook::default(),
            challenges_moved: false,
            verifies: BTreeMap::new(),
            deposits: BTreeMap::new(),
            next_layer: BTreeSet::new(),
            previous_layer: None,
            receipts: ReceiptBook::default(),
            layer,
            dials: BTreeMap::new(),
            fresh: BTreeMap::new(),
            quiet: BTreeMap::new(),
            backlog: None,
            framed: BTreeMap::new(),
            waits: BTreeMap::new(),
            draining: BTreeSet::new(),
            drain_turn: None,
            builds_seen: None,
            measure_trust: None,
            measure_sessions: BTreeMap::new(),
            measure_attempts: BTreeMap::new(),
            sources: BTreeMap::new(),
            loops: Loops::new(layer),
            monotonic: false,
            paced_new: BTreeSet::new(),
        }
    }

    /// The circuits take their time from a clock that never steps back
    /// from now on: their age and the refill of each build budget
    /// (`NET-320`, `NET-332`). A step of the wall clock then ends no
    /// circuit early and holds no build back. The runtime calls it, and a
    /// test that moves the time of each call does not.
    pub fn use_monotonic_clock(&mut self) {
        self.monotonic = true;
    }

    /// The time of the circuit table for a call at `now`.
    fn table_now(&self, now: u64) -> u64 {
        if self.monotonic {
            clock_ms() / 1_000
        } else {
            now
        }
    }

    /// The relays of the layers after this one, by `relay_id`, with the
    /// layer and the static key of each, from the relay set. A relay of
    /// layer 1 or 2 builds its loop chains through them (`NET-363`).
    pub fn set_loop_relays(&mut self, relays: &BTreeMap<[u8; 32], (u8, [u8; 32])>) {
        self.loops.set_relays(relays);
    }

    /// The loops that this relay sent and those that came back.
    pub fn loop_counts(&self) -> (u64, u64) {
        self.loops.counts()
    }

    /// The circuits whose pacing clock started since the last call. The
    /// runtime draws the first tick of each one (`NET-036`).
    pub fn take_paced_new(&mut self) -> Vec<CircuitKey> {
        core::mem::take(&mut self.paced_new).into_iter().collect()
    }

    /// Whether the pacing clock of `circuit` runs.
    pub fn is_paced(&self, circuit: &CircuitKey) -> bool {
        self.endpoints
            .get(circuit)
            .is_some_and(|endpoint| !endpoint.paused)
    }

    /// The key set and the revoked list of the root that this relay holds
    /// (`REL-066`, `REL-104`). The runtime gives them at each relay set.
    pub fn set_measurer_trust(&mut self, trust: MeasurerTrust) {
        self.measure_trust = Some(trust);
    }

    /// The open measurement sessions, for a test.
    #[doc(hidden)]
    pub fn measure_sessions(&self) -> usize {
        self.measure_sessions.len()
    }

    /// The party whose measurement attempts `link` spends: its address, or
    /// the link for a stream with no address.
    fn attempt_holder(&self, link: LinkId) -> Holder {
        self.sources
            .get(&link)
            .map_or(Holder::Link(link), |source| Holder::Source(*source))
    }

    /// Whether the party of `link` holds a measurement attempt at `now`
    /// (`REL-069`).
    fn attempt_left(&mut self, link: LinkId, now: u64) -> bool {
        let holder = self.attempt_holder(link);
        match self.measure_attempts.get_mut(&holder) {
            Some(attempts) => {
                attempts.refill(now);
                attempts.spent < MEAS_ATTEMPT_BURST
            }
            None => self.measure_attempts.len() < MEAS_ATTEMPT_SOURCES_MAX,
        }
    }

    /// Spends one measurement attempt of the party of `link`.
    fn attempt_take(&mut self, link: LinkId, now: u64) {
        let holder = self.attempt_holder(link);
        let attempts = self.measure_attempts.entry(holder).or_insert(Attempts {
            spent: 0,
            since: now,
        });
        if attempts.spent == 0 {
            attempts.since = now;
        }
        attempts.spent = attempts.spent.saturating_add(1);
    }

    /// Gives one measurement attempt back: its `MEAS_OPEN` verified.
    fn attempt_give(&mut self, link: LinkId) {
        let holder = self.attempt_holder(link);
        if let Some(attempts) = self.measure_attempts.get_mut(&holder) {
            attempts.spent = attempts.spent.saturating_sub(1);
            if attempts.spent == 0 {
                self.measure_attempts.remove(&holder);
            }
        }
    }

    /// Takes the content of a `MEAS_OPEN` cell on `circuit` (§10.3.1). A
    /// content that verifies opens the session of its measurer on that
    /// circuit, or adds the circuit to it. Each other content ends the
    /// circuit, and its attempt stays spent (`REL-069`).
    fn on_meas_open(&mut self, circuit: CircuitKey, content: &[u8], now: u64) -> Vec<Action> {
        // A candidate spent its attempt at its build.
        if !self.circuits.is_candidate(&circuit) {
            // REL-069: above the rate the relay verifies nothing and gives
            // no sign.
            if !self.attempt_left(circuit.link, now) {
                return Vec::new();
            }
            self.attempt_take(circuit.link, now);
        }
        let own = self.relay.relay_id;
        let measurer_id = self.measure_trust.as_ref().and_then(|trust| {
            verify_open(content, trust, now / EPOCH_SECONDS, &own, &circuit.circ_id).ok()
        });
        let Some(measurer_id) = measurer_id else {
            return self.circuits.end_now(circuit, Some(circuit.link));
        };
        // REL-202: one session for each measurer, and a small count of
        // each.
        self.measure_sessions
            .retain(|_, session| session.until > now);
        let count = self.measure_sessions.len();
        let until = match self.measure_sessions.get_mut(&measurer_id) {
            Some(session) if session.circuits.len() < MEAS_CIRCUITS_MAX => {
                session.circuits.insert(circuit);
                Some(session.until)
            }
            Some(_) => None,
            None if count < MEAS_SESSIONS_MAX => {
                let until = now.saturating_add(MEAS_SESSION_MAX);
                self.measure_sessions.insert(
                    measurer_id,
                    MeasureSession {
                        until,
                        circuits: [circuit].into(),
                    },
                );
                Some(until)
            }
            None => None,
        };
        // The table counts the end of the session on its own clock.
        let table_until = until.map(|until| {
            self.table_now(now)
                .saturating_add(until.saturating_sub(now))
        });
        match table_until {
            Some(until) if self.circuits.open_measure(&circuit, until) => {
                self.attempt_give(circuit.link);
                // NET-335: the link of a measurer holds its place for the
                // session.
                self.fresh.remove(&circuit.link);
                Vec::new()
            }
            _ => {
                self.measure_closed(&circuit, now);
                self.circuits.end_now(circuit, Some(circuit.link))
            }
        }
    }

    /// A circuit ended: the measurement session that held it holds it no
    /// more, and a session with no circuit ends.
    fn measure_closed(&mut self, circuit: &CircuitKey, now: u64) {
        if self.measure_sessions.is_empty() {
            return;
        }
        let mut was_measured = false;
        self.measure_sessions.retain(|_, session| {
            was_measured |= session.circuits.remove(circuit);
            !session.circuits.is_empty()
        });
        // NET-335: at a relay of layer 2 or 3, the link of a measurer
        // whose session ended holds its place for `LINK_OPEN_TIMEOUT`.
        if was_measured
            && self.layer != 1
            && self.knows_relays()
            && self.receipts.peer(circuit.link).is_none()
            && self.links.contains_key(&circuit.link)
        {
            self.fresh.entry(circuit.link).or_insert(now);
        }
    }

    /// The echo of one `MEAS_ECHO` cell, when its link holds room for it
    /// (`REL-204`). The room is tested before the backward layer runs,
    /// thus an echo that drops moves no chaining value.
    fn echo(&mut self, circuit: CircuitKey, content: &[u8]) -> Option<Output> {
        let len = Bucket::B0.cell_len().saturating_add(FRAME_ROOM);
        if self.parked.contains_key(&circuit.link)
            || !fits(
                self.backlog.as_deref(),
                &self.framed,
                circuit.link,
                len,
                ECHO_PART,
            )
        {
            return None;
        }
        let Action::Send { link, cell } = self.circuits.echo(&circuit, content)? else {
            return None;
        };
        let framed = self.framed.entry(link).or_insert(0);
        *framed = framed.saturating_add(len);
        self.frame(link, &cell)
    }

    /// The layer of this relay.
    pub fn layer(&self) -> u8 {
        self.layer
    }

    /// The relays of the layer before this one, from the relay set
    /// (`REL-174`).
    pub fn set_previous_layer(&mut self, relays: BTreeSet<[u8; 32]>) {
        self.previous_layer = Some(relays);
    }

    /// Closes each accepted link of a relay that the relay set names in the
    /// layer before no more (`REL-174`). The runtime calls it after a newer
    /// set. Before this, a relay that a newer set took out of the layer
    /// before kept the link of its hello. It built circuits on that link
    /// until the link dropped.
    pub fn close_strangers(&mut self, now: u64) -> Vec<Output> {
        let Some(previous) = self.previous_layer.as_ref() else {
            return Vec::new();
        };
        let strangers: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(link, framing)| {
                matches!(framing, Framing::Accepted(_))
                    && self
                        .receipts
                        .peer(**link)
                        .is_some_and(|peer| !previous.contains(&peer))
            })
            .map(|(link, _)| *link)
            .collect();
        let mut outputs = Vec::new();
        for link in strangers {
            outputs.extend(self.drop_link(link, now));
        }
        outputs
    }

    /// The carriers of the manifest, when a newer relay set names others
    /// (`ABU-102`).
    pub fn set_carriers(&mut self, carriers: Vec<[u8; 32]>) {
        self.carriers = carriers;
    }

    /// The count of the backlog of each link, from the runtime (`NET-349`).
    pub fn set_backlog(&mut self, backlog: Box<dyn Backlog>) {
        self.backlog = Some(backlog);
    }

    /// The runtime took the outputs of each call so far, and its count of
    /// each backlog holds them.
    pub fn flushed(&mut self) {
        self.framed.clear();
    }

    /// The runtime accepted the connection of `link` at `now`.
    pub fn opened(&mut self, link: LinkId, now: u64) {
        self.fresh.entry(link).or_insert(now);
    }

    /// The address that the connection of `link` came from, as the runtime
    /// cut it. At an ingress relay the circuits of each link of one address
    /// count together for the share of the table (`NET-331`). A relay of
    /// another layer takes its circuits from relays, and it names them by
    /// their hello.
    pub fn set_source(&mut self, link: LinkId, source: [u8; 16]) {
        self.sources.insert(link, source);
        // NET-332: the builds of one address count together in each layer.
        self.circuits.set_source(link, source);
        if self.layer == 1 {
            self.circuits.set_holder(link, Holder::Source(source));
        }
    }

    /// The circuits that this relay holds, for a test.
    #[doc(hidden)]
    pub fn circuits_held(&self) -> usize {
        self.circuits.len()
    }

    /// Sets the circuits that this relay holds at most, for a test.
    #[doc(hidden)]
    pub fn set_circuits_max(&mut self, held_max: usize) {
        self.circuits.set_held_max(held_max);
    }

    /// Whether this relay holds a relay set, and thus tells a relay link
    /// from a client link.
    fn knows_relays(&self) -> bool {
        !self.identities.is_empty()
    }

    /// Who builds on `link` (`NET-331`, `NET-332`). A link that this relay
    /// dialed builds nothing. An ingress relay takes each accepted link as a
    /// client link. A relay of layer 2 or 3 takes the builds of a relay of
    /// the layer before alone. One that holds no relay set, as in a test
    /// network, cannot tell. It gives each link the budget of a relay.
    /// A link that named no relay builds a measurement candidate while its
    /// address holds a measurement attempt (`NET-353`, `REL-069`).
    fn origin(&mut self, link: LinkId, now: u64) -> Origin {
        if !matches!(self.links.get(&link), Some(Framing::Accepted(_))) {
            return Origin::Barred;
        }
        if self.layer == 1 {
            return Origin::Client;
        }
        if self.receipts.peer(link).is_some() || !self.knows_relays() {
            Origin::Relay
        } else if self.measure_trust.is_some() && self.attempt_left(link, now) {
            Origin::Measurer
        } else {
            Origin::Barred
        }
    }

    /// Whether a new dial of `relay_id` may start at `now` (`NET-319`).
    fn may_dial(&self, relay_id: &[u8; 32], now: u64) -> bool {
        self.dials.get(relay_id).is_none_or(|dial| {
            let wait = if dial.failed {
                DIAL_HOLD_OFF
            } else {
                DIAL_TIMEOUT
            };
            now.saturating_sub(dial.at) >= wait
        })
    }

    /// The dial of `relay_id` opened no link (`NET-319`). The next dial
    /// starts after `DIAL_HOLD_OFF`, while a body waits for that relay.
    pub fn dial_failed(&mut self, relay_id: [u8; 32], now: u64) {
        if !self.next_hops.contains_key(&relay_id) {
            self.dials.insert(
                relay_id,
                Dialing {
                    at: now,
                    failed: true,
                },
            );
        }
    }

    /// The identity key that signs the challenges of this relay, and the
    /// carriers of the manifest that take them (`ABU-057`, `ABU-102`).
    pub fn set_challenge_signer(
        &mut self,
        key: umbra_crypto::sign::SigningKey,
        carriers: Vec<[u8; 32]>,
    ) {
        self.pow_key = Some(key);
        self.carriers = carriers;
    }

    /// The relays of the next layer that this relay may dial (`NET-167`).
    pub fn set_next_layer(&mut self, relays: BTreeSet<[u8; 32]>) {
        self.next_layer = relays;
    }

    /// The receipts of this relay go on `shelf` (`REL-073`).
    pub fn set_receipt_shelf(&mut self, shelf: Box<dyn crate::receipts::ReceiptShelf>) {
        self.receipts.set_shelf(shelf);
    }

    /// The identity key of each relay of the set, by `relay_id`: a carrier
    /// takes a challenge under the key of its relay alone (`ABU-103`).
    pub fn set_relay_identities(&mut self, identities: BTreeMap<[u8; 32], Vec<u8>>) {
        self.identities = identities;
    }

    /// Issues the challenge of the period from the admissions of the last
    /// one, signs it, and hands it to each carrier of the manifest
    /// (`ABU-057`, `ABU-060`, `ABU-092`, `ABU-102`). A relay that carries
    /// the manifest keeps its own. The runtime calls this at each
    /// `POW_CHALLENGE_PERIOD`.
    pub fn issue_challenge<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) -> Vec<Output> {
        let Some(key) = self.pow_key.as_ref() else {
            return Vec::new();
        };
        let backlog = self.gate.take_backlog();
        let Ok(mut challenge) = self.gate.pow.issue(backlog, now, rng) else {
            return Vec::new();
        };
        if challenge.sign(key, rng).is_err() {
            return Vec::new();
        }
        let mut encoded = vec![0u8; capsule::CHALLENGE_LEN];
        if challenge.encode(&mut encoded).is_err() {
            return Vec::new();
        }
        let mut outputs = Vec::new();
        for carrier in self.carriers.clone() {
            if carrier == self.relay.relay_id {
                let identity = key.verifying_key();
                if let Ok(moved) = self.challenges.take(challenge.clone(), &identity, now) {
                    self.challenges_moved |= moved;
                }
                continue;
            }
            let mut capsule = vec![0u8; capsule::HEADER_LEN + encoded.len()];
            if let Ok(used) = capsule::encode(CapsuleType::Challenge, &encoded, &mut capsule) {
                capsule.truncate(used);
                outputs.push(Output::Push {
                    relay_id: carrier,
                    capsule,
                });
            }
        }
        outputs
    }

    /// Takes the challenge of another relay, when this relay carries the
    /// manifest and the challenge verifies under the identity key of that
    /// relay (`ABU-103`).
    fn take_challenge(&mut self, value: &[u8], now: u64) {
        let Ok(challenge) = PowChallenge::parse(value) else {
            return;
        };
        let Some(identity) = self
            .identities
            .get(&challenge.verifier_id)
            .and_then(|bytes| umbra_crypto::sign::VerifyingKey::from_bytes(bytes).ok())
        else {
            return;
        };
        if let Ok(moved) = self.challenges.take(challenge, &identity, now) {
            self.challenges_moved |= moved;
        }
    }

    /// The newest challenge of each relay as one bundle, when the book
    /// moved since the last call, for the carrier to serve beside the
    /// manifest (`ABU-104`).
    pub fn take_challenge_bundle(&mut self, now: u64) -> Option<Vec<u8>> {
        if !core::mem::take(&mut self.challenges_moved) {
            return None;
        }
        self.challenges.expire(now);
        self.challenges.encode(now).ok()
    }

    /// The static key of each queue relay of the relay set, which the
    /// manifest gives, for the deposit of a digest (`WIR-526`).
    pub fn set_queue_relays(&mut self, relays: BTreeMap<[u8; 32], [u8; 32]>) {
        self.queue_relays = relays;
    }

    /// Hands each digest to its notify queue (Part 8 `NTF-096`): into a
    /// queue of this relay at once, and to another queue
    /// relay as an `UMBRA_DEPOSIT` capsule on a connection with no session.
    fn deliver_digests<R: CryptoRng + ?Sized>(
        &mut self,
        digests: Vec<DigestDue>,
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut outputs = Vec::new();
        for due in digests {
            let Ok(address) = QueueAddress::parse(&due.queue) else {
                continue;
            };
            let mut inner = [0u8; 34];
            let digest = NotifyDigest {
                id: due.id,
                post_count: due.post_count,
            };
            let Ok(used) = digest.encode(&mut inner) else {
                continue;
            };
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);
            let Ok(sealed) = ChannelOutbound::new(&address).seal_record(
                L6Kind::NotifyDigest,
                inner.get(..used).unwrap_or_default(),
                nonce,
            ) else {
                continue;
            };
            let mut corr_id = [0u8; 16];
            rng.fill_bytes(&mut corr_id);
            if address.relay_id == self.relay.relay_id {
                let Ok(encoded) = sealed.sign(&self.relay.s, corr_id) else {
                    continue;
                };
                outputs.extend(self.take_deposit(&encoded, now, rng));
                continue;
            }
            let Some(static_key) = self.queue_relays.get(&address.relay_id) else {
                continue;
            };
            let Ok(encoded) = sealed.sign(static_key, corr_id) else {
                continue;
            };
            let mut capsule = vec![0u8; capsule::HEADER_LEN + encoded.len()];
            if let Ok(used) = capsule::encode(CapsuleType::Deposit, &encoded, &mut capsule) {
                capsule.truncate(used);
                outputs.push(Output::Push {
                    relay_id: address.relay_id,
                    capsule,
                });
            }
        }
        outputs
    }

    /// Takes one deposit into a queue of this relay (`WIR-526`): the `MSG`
    /// of a live subscription goes to its circuit, and a push follows an
    /// arrival that no subscription took.
    fn take_deposit<R: CryptoRng + ?Sized>(
        &mut self,
        encoded: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        let Ok((command, _)) = Command::parse(encoded, Bucket::B0) else {
            return Vec::new();
        };
        if let Some(reply) = self.queues.deposit(&command, &self.static_secret, now, rng) {
            if let Some(endpoint) = self.endpoints.get_mut(&reply.circuit) {
                endpoint.post(reply.outbound, false);
            }
        }
        self.queues
            .take_ndr_pushes()
            .into_iter()
            .map(Output::NdrPush)
            .collect()
    }

    /// A node that continues the queues and the invitations of an earlier
    /// run. Each circuit, each session, and each subscription of that run
    /// is gone, and the clients build them again.
    pub fn restored(config: Config, mut loaded: Loaded) -> Self {
        let chunks = ChunkService::restore(config.chunk_capacity, &mut loaded);
        let mut node = RelayNode::new(config);
        node.chunks = chunks;
        for (epoch, nonce) in &loaded.spent {
            node.gate.spent.restore(*epoch, *nonce);
        }
        node.groups = GroupService::restore(&loaded);
        let mut queues = QueueService::restore(loaded);
        queues.keep_notify_of(&mut node.queues);
        node.queues = queues;
        node
    }

    /// The pushes due at `now`: the end of a coalescing window and each
    /// re-push. The runtime calls it about once each second.
    pub fn push_tick<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) -> Vec<Output> {
        self.queues.push_tick(now, rng);
        // NTF-146: the wake at the end of the window of a watch.
        for reply in self.queues.take_wakes() {
            if let Some(endpoint) = self.endpoints.get_mut(&reply.circuit) {
                endpoint.post(reply.outbound, false);
            }
        }
        let mut outputs: Vec<Output> = self
            .queues
            .take_ndr_pushes()
            .into_iter()
            .map(Output::NdrPush)
            .collect();
        // NTF-098: each digest whose gap ended, and each one that waited for
        // its turn under the rate of the group service.
        let due = self.groups.digest_tick(now);
        outputs.extend(self.deliver_digests(due, now, rng));
        // NET-069: the loops of this relay, and the chains that carry them.
        outputs.extend(self.loop_tick(now, rng));
        // NET-319: a dial that failed starts again while a body waits.
        let again: Vec<[u8; 32]> = self
            .extending
            .iter()
            .filter(|(relay_id, waiting)| {
                !self.next_hops.contains_key(*relay_id)
                    && waiting.iter().any(|held| held.is_live(now))
                    && self.may_dial(relay_id, now)
            })
            .map(|(relay_id, _)| *relay_id)
            .collect();
        for relay_id in again {
            self.dials.insert(
                relay_id,
                Dialing {
                    at: now,
                    failed: false,
                },
            );
            outputs.push(Output::Dial { relay_id });
        }
        // NET-335: a link that sent no `Open` holds no place. At a relay of
        // layer 2 or 3, a link that named no relay of the layer before
        // holds none too.
        let late: Vec<LinkId> = self
            .fresh
            .iter()
            .filter(|(_, since)| now.saturating_sub(**since) >= LINK_OPEN_TIMEOUT)
            .map(|(link, _)| *link)
            .collect();
        for link in late {
            outputs.extend(self.drop_link(link, now));
        }
        // REL-074, REL-176: the windows of an ended epoch close, and an old
        // receipt goes.
        let built = self.circuits.take_builds();
        if let Some(seen) = &self.builds_seen {
            seen.fetch_add(built, std::sync::atomic::Ordering::Relaxed);
        }
        self.receipts.count_chains(built, now, rng);
        if let Some(key) = self.pow_key.as_ref() {
            let own = self.relay.relay_id;
            for (link, signed) in self.receipts.tick(&own, key, now, rng) {
                outputs.extend(capsule_output(link, CapsuleType::Receipt, &signed));
            }
        }
        outputs
    }

    /// One tick of the loop chains (`NET-069`, `NET-363`). The runtime
    /// calls it about once each second, with [`RelayNode::push_tick`].
    fn loop_tick<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) -> Vec<Output> {
        let at = self.table_now(now);
        let cells = self.loops.tick(at, &self.next_hops, &self.circuits, rng);
        self.send_loop_cells(cells, now, rng)
    }

    /// Frames the cells of the loop chains as each other cell of a link,
    /// under the backlog bound of `NET-349`.
    fn send_loop_cells<R: CryptoRng + ?Sized>(
        &mut self,
        cells: Vec<(LinkId, Vec<u8>)>,
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        if cells.is_empty() {
            return Vec::new();
        }
        let actions = cells
            .into_iter()
            .map(|(link, cell)| Action::Send { link, cell })
            .collect();
        self.run(actions, now, rng)
    }

    /// The receipts that this relay issued and took, for a test.
    #[doc(hidden)]
    pub fn receipts_held(&self) -> (usize, usize) {
        self.receipts.held()
    }

    /// The answer to a receipt query that verified (`REL-179`).
    pub fn receipt_answer(
        &mut self,
        query: &receipt::ReceiptQuery,
        now: u64,
    ) -> QueryAnswer<receipt::ReceiptAnswer> {
        // REL-180: a query that asks another relay gets no answer, and it
        // counts toward no bound. A relay that took the query of its
        // neighbor can thus spend no query of that authority here.
        if !query.asks(&self.relay.relay_id) {
            return QueryAnswer::Elsewhere;
        }
        // REL-186: one authority asks at most RECEIPT_QUERY_MAX times.
        let asked = self
            .receipts
            .admit_query(query.authority_index, query.epoch, false, now);
        match asked {
            Asked::Fresh => QueryAnswer::Given(self.receipts.answer(query)),
            // REL-179: no receipt of an epoch outside the retention, and
            // such a query costs no search and counts toward no bound.
            Asked::Outside => QueryAnswer::Given(receipt::ReceiptAnswer::none()),
            Asked::Above => QueryAnswer::Above,
        }
    }

    /// The answer to a query of an aggregator that verified (`REL-192`).
    pub fn stat_answer(&mut self, query: &StatQuery, now: u64) -> QueryAnswer<StatAnswer> {
        // REL-192: the share goes to the query that asks this relay and to
        // no other one. A query for another relay counts toward no bound.
        if !query.asks(&self.relay.relay_id) {
            return QueryAnswer::Elsewhere;
        }
        let asked = self
            .receipts
            .admit_query(query.authority_index, query.epoch, true, now);
        match asked {
            Asked::Fresh => QueryAnswer::Given(StatAnswer {
                share: self.receipts.share(query.authority_index, query.epoch),
            }),
            // REL-191: an epoch that runs, or one past the retention, has no
            // share.
            Asked::Outside => QueryAnswer::Given(StatAnswer { share: None }),
            Asked::Above => QueryAnswer::Above,
        }
    }

    /// The NDR answered `gone` for a handle (`NTF-125`).
    pub fn ndr_gone(&mut self, handle: &[u8; 16]) {
        self.queues.ndr_gone(handle);
    }

    /// The changes of the stored state since the last call. The process
    /// commits them before it sends an output of the same call (`NET-298`).
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        let mut changes = self.queues.take_changes();
        changes.append(&mut self.groups.take_changes());
        changes.append(&mut self.chunks.take_changes());
        // ABU-114: a restart spends no token a second time.
        changes.extend(
            self.gate
                .take_spent()
                .into_iter()
                .map(|(epoch, nonce)| StoreChange::Spent { epoch, nonce }),
        );
        changes
    }

    /// The gate, for the effort that the runtime sets under load.
    pub fn gate_mut(&mut self) -> &mut RelayGate {
        &mut self.gate
    }

    /// The circuits that end here, each of which holds a pacing clock
    /// (`NET-035`).
    pub fn paced_circuits(&self) -> impl Iterator<Item = &CircuitKey> {
        // WIR-546: the clock of a paused circuit stops.
        self.endpoints
            .iter()
            .filter(|(_, endpoint)| !endpoint.paused)
            .map(|(circuit, _)| circuit)
    }

    /// Adds each chain that this relay opens to `counter` at each
    /// [`RelayNode::push_tick`], for a test.
    #[doc(hidden)]
    pub fn count_builds_into(&mut self, counter: std::sync::Arc<std::sync::atomic::AtomicU64>) {
        self.builds_seen = Some(counter);
    }

    /// The parked sessions that this relay holds, for a test.
    #[doc(hidden)]
    pub fn sessions_parked(&self) -> usize {
        self.parked.len()
    }

    /// The runtime dialed a relay of the next layer on `link`. The result
    /// is the capsule that opens the session (`WIR-229`), and then each
    /// `EXTEND` that waited for this link (`NET-319`).
    pub fn dialed<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        relay_id: [u8; 32],
        session_id: [u8; 8],
        session_secret: Secret<32>,
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        self.dials.remove(&relay_id);
        // NET-319: a second dial that ended after the first one gives a link
        // that nothing needs.
        if self.next_hops.contains_key(&relay_id) {
            return vec![Output::Close { link }];
        }
        let mut capsule = vec![0u8; 64];
        let Ok((client, used)) = ClientLink::open(session_id, session_secret, &mut capsule) else {
            return Vec::new();
        };
        capsule.truncate(used);
        self.links.insert(link, Framing::Dialed(client));
        self.next_hops.insert(relay_id, link);
        self.receipts.set_peer(link, relay_id);
        let mut outputs = vec![Output::Send { link, capsule }];
        // REL-173: the next hop learns which relay dialed it.
        if let Some(key) = self.pow_key.as_ref() {
            let hello =
                receipt::relay_hello(&self.relay.relay_id, &relay_id, &session_id, key, rng);
            outputs.extend(
                hello
                    .ok()
                    .and_then(|hello| capsule_output(link, CapsuleType::RelayHello, &hello)),
            );
        }
        let mut actions = Vec::new();
        for waiting in self.extending.remove(&relay_id).unwrap_or_default() {
            // The client ended a build older than its timeout.
            if waiting.is_live(now) {
                actions.extend(self.bind_extend(waiting.from, link, &waiting.body, now, rng));
            }
        }
        outputs.extend(self.run(actions, now, rng));
        outputs
    }

    /// Binds a held circuit to a new circuit on the link to its next
    /// relay, and gives the build cell for it (`NET-163`, `NET-198`).
    fn bind_extend<R: CryptoRng + ?Sized>(
        &mut self,
        from: CircuitKey,
        next_link: LinkId,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<Action> {
        let mut next = CircuitKey {
            link: next_link,
            circ_id: [0; 16],
        };
        // NET-154, NET-155.
        loop {
            rng.fill_bytes(&mut next.circ_id);
            if self.circuits.is_free(&next) && !self.loops.owns(next.link, next.circ_id) {
                break;
            }
        }
        let at = self.table_now(now);
        self.circuits.bind_next(from, next, body, at)
    }

    /// Takes the bytes of one capsule from a link.
    pub fn on_capsule<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        bytes: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        // WIR-538: a client link carries no capsule between two relays. An
        // accepted link at an ingress relay is the link of a client, and
        // each other link is the link of a relay.
        let kind_of_link =
            if self.layer == 1 && !matches!(self.links.get(&link), Some(Framing::Dialed(_))) {
                CapsuleLink::Client
            } else {
                CapsuleLink::Relays
            };
        // A capsule that does not parse, that its link does not carry, or
        // that holds bytes after its value is a fault of the peer. The
        // session ends, and it does not park (`WIR-542`).
        let parsed = capsule::parse_on(bytes, kind_of_link)
            .ok()
            .filter(|(_, _, used)| *used == bytes.len());
        let Some((kind, value, _)) = parsed else {
            return self.drop_link(link, now);
        };
        // NET-335: the time of a link that holds no session runs from its
        // first sight.
        if !self.links.contains_key(&link) {
            self.fresh.entry(link).or_insert(now);
        }
        match kind {
            CapsuleType::Session => self.on_control(link, value, now),
            CapsuleType::Replica => {
                // ATT-107: the token of the payload is the one authority of
                // a copy, thus the link needs no session. The pushing relay
                // gets no answer, and the sample of the uploader finds a
                // copy that did not arrive (`ATT-113`).
                if let Ok((command, _)) = Command::parse(value, Bucket::B3) {
                    if command.cmd == Cmd::Attachment(CRPUT) {
                        let _ = self
                            .chunks
                            .replica_put(command.queue_id, command.payload, now);
                    }
                }
                Vec::new()
            }
            // WIR-526: the digest of another relay, on a connection that
            // holds no session. A deposit above the budget of its link
            // drops with no sign, as a deposit that does not verify does.
            CapsuleType::Deposit => {
                if self.may_deposit(link, now) {
                    self.take_deposit(value, now, rng)
                } else {
                    Vec::new()
                }
            }
            // ABU-103: the challenge of another relay, for a carrier.
            CapsuleType::Challenge => {
                if self.may_verify(link, now) {
                    self.take_challenge(value, now);
                }
                Vec::new()
            }
            // REL-174: the relay that dialed this link names itself, once.
            CapsuleType::RelayHello => {
                if self.receipts.peer(link).is_some() || !self.may_verify(link, now) {
                    return Vec::new();
                }
                if let Some(Framing::Accepted(framing)) = self.links.get(&link) {
                    let session_id = framing.session_id();
                    let identities = &self.identities;
                    let own = self.relay.relay_id;
                    // A relay outside the layer before dials no circuit
                    // here, thus its hello names no peer.
                    let previous = self.previous_layer.as_ref();
                    let named = receipt::verify_relay_hello(value, &own, &session_id, |id| {
                        previous
                            .is_none_or(|layer| layer.contains(id))
                            .then(|| identities.get(id).cloned())
                            .flatten()
                    });
                    if let Ok(relay_id) = named {
                        self.receipts.set_peer(link, relay_id);
                        self.fresh.remove(&link);
                        // NET-331: each link of one relay counts together.
                        self.circuits.set_holder(link, Holder::Relay(relay_id));
                    }
                }
                Vec::new()
            }
            // REL-178: the receipt of the cells that this relay sent.
            CapsuleType::Receipt => {
                if let Some(identity) = self
                    .receipts
                    .peer(link)
                    .and_then(|peer| self.identities.get(&peer))
                    .filter(|_| self.verifies_left(link, now))
                {
                    let identity = identity.clone();
                    let own = self.relay.relay_id;
                    // A receipt that the book drops counts as one signature
                    // check of the link. A peer that sends receipts that
                    // fail thus costs this relay a bounded number of them.
                    if !self
                        .receipts
                        .receipt_taken(link, value, &own, &identity, now)
                    {
                        self.may_verify(link, now);
                    }
                }
                Vec::new()
            }
            CapsuleType::Cell => {
                let cell = match self.links.get_mut(&link) {
                    Some(Framing::Accepted(framing)) => framing.receive(value),
                    Some(Framing::Dialed(framing)) => framing.receive(value),
                    None => return self.drop_link(link, now),
                };
                match cell {
                    Ok(Some(cell)) => {
                        let cell = cell.to_vec();
                        // REL-175: a cell of a relay link counts for its
                        // receipt.
                        let mut outputs = Vec::new();
                        if let Some(key) = self.pow_key.as_ref() {
                            let own = self.relay.relay_id;
                            for signed in self.receipts.cell_taken(link, &cell, &own, key, now, rng)
                            {
                                outputs.extend(capsule_output(link, CapsuleType::Receipt, &signed));
                            }
                        }
                        // NET-363: a cell of a loop chain of this relay.
                        if let Some(circ_id) = cell.first_chunk::<16>() {
                            if self.loops.owns(link, *circ_id) {
                                let at = self.table_now(now);
                                let cells = self.loops.on_cell(link, &cell, at, rng);
                                outputs.extend(self.send_loop_cells(cells, now, rng));
                                return outputs;
                            }
                        }
                        self.circuits.set_clock_ms(clock_ms());
                        let origin = self.origin(link, now);
                        let at = self.table_now(now);
                        let actions = self.circuits.on_cell(link, &cell, origin, at, rng);
                        outputs.extend(self.run(actions, now, rng));
                        outputs
                    }
                    // WIR-141: a frame that the link accepted before.
                    Ok(None) => Vec::new(),
                    // WIR-542: a frame fault ends the session, and it does
                    // not park.
                    Err(_) => self.drop_link(link, now),
                }
            }
        }
    }

    fn on_control(&mut self, link: LinkId, value: &[u8], now: u64) -> Vec<Output> {
        let Ok(control) = SessionControl::parse(value) else {
            return self.drop_link(link, now);
        };
        let held = self.links.contains_key(&link);
        match &control {
            // WIR-233: a session identifier that a session of this relay
            // holds opens no second one.
            SessionControl::Open { session_id, .. } if !held => {
                let session_id = *session_id;
                if self.sessions.contains_key(&session_id) {
                    return self.drop_link(link, now);
                }
                match RelayLink::open(control) {
                    Ok(framing) => {
                        self.links.insert(link, Framing::Accepted(framing));
                        self.sessions.insert(session_id, link);
                        // NET-335: at a relay of layer 2 or 3 that holds a
                        // relay set, the link has until its hello.
                        if self.layer == 1 || !self.knows_relays() {
                            self.fresh.remove(&link);
                        }
                        Vec::new()
                    }
                    Err(_) => self.drop_link(link, now),
                }
            }
            SessionControl::Resume { session_id, .. } if !held => {
                let session_id = *session_id;
                self.on_resume(link, session_id, &control, now)
            }
            // NET-322: a neighbor ended a circuit on this link.
            SessionControl::Destroy { circ_id } if held => {
                // NET-363: a relay ended a loop chain of this relay.
                let at = self.table_now(now);
                if self.loops.on_destroy(link, *circ_id, at) {
                    return Vec::new();
                }
                self.circuits.set_clock_ms(clock_ms());
                let actions = self.circuits.on_destroy(link, *circ_id);
                self.finish(actions, now)
            }
            // WIR-545: the client of a circuit on this link paused.
            SessionControl::CircuitPause { circ_id } if held => {
                self.circuits.set_clock_ms(clock_ms());
                let actions = self.circuits.on_pause(link, *circ_id);
                self.run_pause(actions, now)
            }
            SessionControl::Pause { .. } if held && self.layer == 1 => {
                self.on_pause(link, &control, now)
            }
            _ => self.drop_link(link, now),
        }
    }

    /// Takes the `SessionPause` of a client (`WIR-541`): each circuit of
    /// the link gets its `CircuitPause`, the client gets the
    /// `SessionPaused`, and the link takes no further frame.
    fn on_pause(&mut self, link: LinkId, control: &SessionControl, now: u64) -> Vec<Output> {
        let mut paused = vec![0u8; 32];
        let answered = match self.links.get_mut(&link) {
            Some(Framing::Accepted(framing)) => framing.pause(control, now, &mut paused),
            _ => return self.drop_link(link, now),
        };
        let Ok(used) = answered else {
            return self.drop_link(link, now);
        };
        paused.truncate(used);
        let answer = Output::Send {
            link,
            capsule: paused,
        };
        // A session with no circuit has nothing to keep, and a relay
        // that parked each such session would hold them with no bound.
        if self.circuits.circuits_on(link) == 0 {
            let mut outputs = vec![answer];
            outputs.extend(self.drop_link(link, now));
            return outputs;
        }
        let mut outputs = self.park(link, now);
        outputs.push(answer);
        outputs
    }

    /// Parks the session of a client link (`WIR-541`, `WIR-542`): the
    /// link, its circuits, and each count of it stay under its identifier,
    /// and each circuit gets its `CircuitPause`.
    fn park(&mut self, link: LinkId, now: u64) -> Vec<Output> {
        self.parked.entry(link).or_default();
        self.quiet.remove(&link);
        self.framed.remove(&link);
        self.waits.remove(&link);
        self.circuits.set_clock_ms(clock_ms());
        let actions = self.circuits.pause_link(link);
        self.run_pause(actions, now)
    }

    /// Takes a `SessionResume` as the first capsule of the connection of
    /// `link` (`WIR-237` to `WIR-242`, `WIR-544`).
    fn on_resume(
        &mut self,
        link: LinkId,
        session_id: [u8; 8],
        control: &SessionControl,
        now: u64,
    ) -> Vec<Output> {
        // WIR-548: a session between two relays does not resume.
        let target = self
            .sessions
            .get(&session_id)
            .copied()
            .filter(|_| self.layer == 1);
        let resumed = match target.and_then(|target| self.links.get_mut(&target)) {
            Some(Framing::Accepted(framing)) => framing.resume(control, now),
            _ => Err(ResumeFault::Refused),
        };
        let mut outputs = self.drop_link(link, now);
        match (resumed, target) {
            (Ok(()), Some(target)) => {
                // The node holds nothing under the identifier of the new
                // connection, thus the close above goes nowhere.
                outputs.clear();
                outputs.push(Output::Adopt {
                    link,
                    as_link: target,
                });
                // WIR-543: each circuit that ended while no connection
                // held the session.
                for circ_id in self.parked.remove(&target).unwrap_or_default() {
                    outputs.extend(destroy_output(target, circ_id));
                }
            }
            // WIR-544: a frame is lost, thus each circuit is broken.
            (Err(ResumeFault::Lost), Some(target)) => {
                outputs.extend(self.drop_link(target, now));
            }
            // WIR-239, WIR-240: the connection closes with no cause.
            _ => {}
        }
        outputs
    }

    /// Runs the actions of a pause. None of them builds a circuit or
    /// serves a command, thus the call takes no random source.
    fn run_pause(&mut self, actions: Vec<Action>, now: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        let mut work: VecDeque<Action> = actions.into();
        while let Some(action) = work.pop_front() {
            match action {
                Action::Pause { key } => work.extend(self.circuits.pause_now(key)),
                Action::PauseNext { link, circ_id } => {
                    outputs.extend(pause_output(link, circ_id));
                }
                Action::Paused { circuit } => self.endpoint_paused(&circuit, now),
                Action::Delayed {
                    at_ms,
                    circuit,
                    action,
                } => {
                    self.delayed_seq = self.delayed_seq.wrapping_add(1);
                    self.delayed
                        .insert((at_ms, self.delayed_seq), (circuit, *action));
                }
                _ => {}
            }
        }
        outputs
    }

    /// The client of a circuit that ends here paused its session
    /// (`WIR-546`). The subscriptions of the circuit end, thus a new record
    /// of its queues takes its push. The circuit and its session stay.
    fn endpoint_paused(&mut self, circuit: &CircuitKey, now: u64) {
        self.queues.circuit_paused(circuit, now);
        self.groups.circuit_paused(circuit);
        self.draining.remove(circuit);
        if let Some(endpoint) = self.endpoints.get_mut(circuit) {
            endpoint.paused = true;
            endpoint.drains.end_all();
        }
    }

    fn frame(&mut self, link: LinkId, cell: &[u8]) -> Option<Output> {
        let mut capsule = vec![0u8; cell.len().saturating_add(32)];
        let sent = match self.links.get_mut(&link)? {
            Framing::Accepted(framing) => framing.send(cell, &mut capsule),
            Framing::Dialed(framing) => framing.send(cell, &mut capsule),
        };
        // WIR-139: a session whose `seq` ran out closes, and a cell that
        // it cannot carry ends its link rather than going nowhere.
        let Ok(used) = sent else {
            return Some(Output::Close { link });
        };
        capsule.truncate(used);
        self.receipts.cell_sent(link, cell);
        Some(Output::Send { link, capsule })
    }

    /// Finds the place of one cell on `link` (`NET-349`): whether the link
    /// takes it, and the circuits of that link that end for it.
    ///
    /// A cell that leaves the last part of the bound free goes. A cell that
    /// reaches into that part ends the circuit that holds the most of the
    /// backlog. That circuit must hold `SHED_FLOOR_PART` of the bound or
    /// more. When that is another circuit, the cell still goes. When it is
    /// the circuit of the cell, the cell does not go. A cell that finds no
    /// room under the bound ends its circuit. Before this, a full link
    /// ended the circuit of each cell that arrived, thus one circuit that
    /// filled a link of many clients ended theirs. The node cannot tell the
    /// circuits of a party that fills a link with many of them, each below
    /// the floor, from the others. A link at its bound thus still ends the
    /// circuit of each cell.
    fn place_cell(&mut self, link: LinkId, cell: &[u8]) -> (bool, [Option<[u8; 16]>; 2]) {
        let len = cell.len().saturating_add(FRAME_ROOM);
        let Some((held, limit)) = self.backlog.as_deref().and_then(|backlog| backlog.of(link))
        else {
            return (true, [None, None]);
        };
        let framed = self.framed.entry(link).or_insert(0);
        let waiting = held.saturating_add(*framed);
        let after = waiting.saturating_add(len);
        let Some(circ_id) = cell.first_chunk::<16>().copied() else {
            return (after <= limit, [None, None]);
        };
        let waits = self.waits.entry(link).or_default();
        waits.trim(waiting);
        let mut takes = after <= limit;
        let mut other = None;
        if after > limit.saturating_sub(limit / SHED_MARK_PART) {
            let mine = waits.of(&circ_id).saturating_add(len);
            let floor = limit / SHED_FLOOR_PART;
            // A circuit that ended holds no rank.
            let heaviest = loop {
                match waits.heaviest_but(&circ_id) {
                    Some((ended, _)) if !self.circuits.holds(link, ended) => {
                        waits.forget(&ended);
                    }
                    found => break found,
                }
            };
            match heaviest {
                Some((heavy, bytes)) if bytes > mine && bytes >= floor => {
                    waits.forget(&heavy);
                    other = Some(heavy);
                }
                _ if mine >= floor => takes = false,
                _ => {}
            }
        }
        if takes {
            waits.add(circ_id, len);
            *framed = framed.saturating_add(len);
            (true, [other, None])
        } else {
            waits.forget(&circ_id);
            (false, [other, Some(circ_id)])
        }
    }

    fn run<R: CryptoRng + ?Sized>(
        &mut self,
        actions: Vec<Action>,
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut outputs = Vec::new();
        let mut work: VecDeque<Action> = actions.into();
        while let Some(action) = work.pop_front() {
            match action {
                // WIR-543: a parked link carries no cell, and each onion
                // layer chains on the cell before it. The circuit of the
                // cell thus ends, and each other circuit of the link stays.
                Action::Send { link, cell } if self.parked.contains_key(&link) => {
                    if let Some(circ_id) = cell.first_chunk::<16>() {
                        // NET-339: the end of the circuit can wait behind a
                        // forward cell, and a resume can come before that
                        // end. The session thus keeps the `circ_id` now, and
                        // that resume names the circuit.
                        if self.circuits.holds(link, *circ_id) {
                            self.keep_ended(link, *circ_id);
                        }
                        work.extend(self.circuits.shed(link, *circ_id));
                    }
                }
                Action::Send { link, cell } => {
                    // NET-349: a link near its bound loses the circuit that
                    // filled it, and each other circuit on it stays.
                    let (takes, shed) = self.place_cell(link, &cell);
                    for circ_id in shed.into_iter().flatten() {
                        work.extend(self.circuits.shed(link, circ_id));
                    }
                    if takes {
                        outputs.extend(self.frame(link, &cell));
                    }
                }
                // NET-167: a relay that is not of the next layer takes no
                // body, and the body goes at once.
                Action::Extend { relay_id, .. }
                    if !self.next_layer.is_empty() && !self.next_layer.contains(&relay_id) => {}
                Action::Extend {
                    from,
                    relay_id,
                    body,
                } => match self.next_hops.get(&relay_id).copied() {
                    // NET-319: the body waits for the link, and one dial
                    // serves each body that waits for that relay. A dial
                    // that opened no link in its time, or that failed, gives
                    // way to a new one, thus steady arrivals hold no dial
                    // back.
                    None => {
                        if self.may_dial(&relay_id, now) {
                            self.dials.insert(
                                relay_id,
                                Dialing {
                                    at: now,
                                    failed: false,
                                },
                            );
                            outputs.push(Output::Dial { relay_id });
                        }
                        // NET-319: the bodies for one relay have a bound. A
                        // body above it ends its circuit, and its client
                        // builds again on another chain.
                        let waiting = self.extending.entry(relay_id).or_default();
                        if waiting.len() >= EXTEND_WAITING_MAX {
                            waiting.retain(|held| held.is_live(now));
                        }
                        if waiting.len() >= EXTEND_WAITING_MAX {
                            work.extend(self.circuits.shed(from.link, from.circ_id));
                        } else {
                            waiting.push(Waiting {
                                from,
                                body,
                                arrived_at: now,
                            });
                        }
                    }
                    Some(next_link) => {
                        work.extend(self.bind_extend(from, next_link, &body, now, rng));
                    }
                },
                Action::Serve {
                    circuit,
                    bucket,
                    content,
                } => {
                    self.wake_endpoint(&circuit);
                    let (paced, digests) = self.serve(circuit, bucket, &content, now, rng);
                    outputs.extend(self.deliver_digests(digests, now, rng));
                    // ATT-102: one copy for each target of a `CREP`.
                    outputs.extend(self.chunks.take_pushes().iter().filter_map(push_output));
                    outputs.extend(
                        self.queues
                            .take_ndr_pushes()
                            .into_iter()
                            .map(Output::NdrPush),
                    );
                    for reply in paced {
                        if let Some(endpoint) = self.endpoints.get_mut(&reply.circuit) {
                            endpoint.post(reply.outbound, false);
                        }
                    }
                    // NET-360: an answer of an attachment circuit follows
                    // the command of its own client, thus it waits for no
                    // tick. One step goes, and the clock sends the rest.
                    if self.is_prompt(&circuit) {
                        work.extend(self.answers(&circuit));
                    }
                }
                Action::Loop { circuit } => {
                    self.ensure_endpoint(circuit);
                    self.wake_endpoint(&circuit);
                    if let Some(endpoint) = self.endpoints.get_mut(&circuit) {
                        endpoint.loops = endpoint.loops.saturating_add(1);
                    }
                }
                Action::Candidate { circuit } => self.attempt_take(circuit.link, now),
                Action::MeasOpen { circuit, content } => {
                    work.extend(self.on_meas_open(circuit, &content, now));
                }
                Action::Echo { circuit, content } => {
                    outputs.extend(self.echo(circuit, &content));
                }
                Action::Destroy { link, circ_id } => outputs.extend(self.destroy(link, circ_id)),
                Action::Closed { circuit } => self.endpoint_closed(&circuit, now),
                Action::Pause { key } => work.extend(self.circuits.pause_now(key)),
                Action::PauseNext { link, circ_id } => {
                    outputs.extend(pause_output(link, circ_id));
                }
                Action::Paused { circuit } => self.endpoint_paused(&circuit, now),
                // NET-339: the end of a circuit after its delayed cells.
                Action::End { key, from } => work.extend(self.circuits.end_now(key, from)),
                // Part 3 §3.9: the cell waits for the per-hop delay of its
                // circuit. NET-362: a cell above the bound of the relay
                // ends its circuit. The end of a circuit and a pause always
                // wait, because they hold no cell.
                Action::Delayed {
                    at_ms,
                    circuit,
                    action,
                } => {
                    let is_cell = matches!(
                        *action,
                        Action::Send { .. } | Action::Serve { .. } | Action::Loop { .. }
                    );
                    if is_cell && self.delayed.len() >= RELAY_DELAYED_MAX {
                        self.circuits.released(&circuit);
                        work.extend(self.circuits.shed(circuit.link, circuit.circ_id));
                    } else {
                        self.delayed_seq = self.delayed_seq.wrapping_add(1);
                        self.delayed
                            .insert((at_ms, self.delayed_seq), (circuit, *action));
                    }
                }
            }
        }
        outputs
    }

    /// A circuit ended: the services drop what they held for it.
    fn endpoint_closed(&mut self, circuit: &CircuitKey, now: u64) {
        self.measure_closed(circuit, now);
        self.endpoints.remove(circuit);
        self.paced_new.remove(circuit);
        self.queues.circuit_closed(circuit, now);
        self.groups.circuit_closed(circuit);
    }

    /// The `CircuitDestroy` for `link`, or none for a parked link, which
    /// keeps the `circ_id` until its session resumes (`WIR-543`).
    fn destroy(&mut self, link: LinkId, circ_id: [u8; 16]) -> Option<Output> {
        if self.keep_ended(link, circ_id) {
            None
        } else {
            destroy_output(link, circ_id)
        }
    }

    /// Keeps the `circ_id` of a circuit of a parked link that ended, one
    /// time, for the `CircuitDestroy` after the resume (`WIR-543`). False
    /// for a link that is not parked.
    fn keep_ended(&mut self, link: LinkId, circ_id: [u8; 16]) -> bool {
        let Some(ended) = self.parked.get_mut(&link) else {
            return false;
        };
        if !ended.contains(&circ_id) {
            ended.push(circ_id);
        }
        true
    }

    /// The endpoint serves a forward cell of the client of `circuit`, thus
    /// the pacing clock of a paused circuit starts again (`WIR-546`).
    fn wake_endpoint(&mut self, circuit: &CircuitKey) {
        if let Some(endpoint) = self.endpoints.get_mut(circuit) {
            if endpoint.paused {
                self.paced_new.insert(*circuit);
            }
            endpoint.paused = false;
        }
    }

    /// Takes the key of the cross-relay issuer of `epoch` from the log.
    /// The keys of epochs before the one before `epoch` leave, since no
    /// token answers them (`ABU-095`).
    pub fn set_issuer_key(&mut self, epoch: u32, key: PublicKey2048) {
        self.issuer_keys.insert(epoch, key);
        let floor = crate::issuer_floor(epoch);
        self.issuer_keys.retain(|held, _| *held >= floor);
    }

    /// Whether a forward cell waits for its per-hop delay.
    pub fn has_delayed(&self) -> bool {
        !self.delayed.is_empty()
    }

    /// Runs each delayed action whose time came at `now_ms`, in the order
    /// of its time (Part 3 §3.9).
    pub fn release_delayed<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        let mut due = Vec::new();
        while let Some(entry) = self.delayed.first_entry() {
            if entry.key().0 > now_ms {
                break;
            }
            let (circuit, action) = entry.remove();
            self.circuits.released(&circuit);
            due.push(action);
        }
        if due.is_empty() {
            return Vec::new();
        }
        self.run(due, now, rng)
    }

    /// Makes the endpoint state of a circuit that ends here, at its first
    /// cell. The session of its commands is the circuit (`NET-287`).
    fn ensure_endpoint(&mut self, circuit: CircuitKey) -> bool {
        if self.endpoints.contains_key(&circuit) {
            return true;
        }
        let Some(secret) = self.circuits.session_secret(&circuit).cloned() else {
            return false;
        };
        self.endpoints.insert(
            circuit,
            Endpoint {
                session: Session::for_circuit(&circuit.circ_id, secret),
                range: None,
                outbox: VecDeque::new(),
                drains: Drains::default(),
                loops: 0,
                paused: false,
            },
        );
        self.paced_new.insert(circuit);
        true
    }

    /// Serves the commands of one `DATA` cell. The result holds the paced
    /// replies and the digests. A `SUB` or a `GSUB` of a backlog above
    /// `DRAIN_THRESHOLD` gives no reply. Its service leaves a drain at the
    /// circuit, and the records leave in the steps of the clock
    /// (`NET-037`). A drain that the service refused gets its `NACK` with
    /// the reason `LIMIT` as each rejected command does. The service left
    /// no subscription for it and copied no record.
    fn serve<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        bucket: Bucket,
        content: &[u8],
        now: u64,
        rng: &mut R,
    ) -> (Vec<Reply>, Vec<DigestDue>) {
        // WIR-318: a cell whose commands do not parse gets no answer.
        let Ok(commands) = unpack(content, bucket) else {
            return (Vec::new(), Vec::new());
        };
        let mut paced = Vec::new();
        let mut digests = Vec::new();
        for command in &commands {
            let outcome = self.serve_one(circuit, command, now, rng);
            match outcome {
                Ok((replies, due)) => {
                    digests.extend(due);
                    paced.extend(replies);
                }
                Err(reject) => {
                    // WIR-322: a NACK goes before each pending MSG.
                    if let Some(endpoint) = self.endpoints.get_mut(&circuit) {
                        endpoint.post(nack(circuit, command, reject).outbound, true);
                    }
                }
            }
        }
        // NET-037: the clock steps through each drain that a command left.
        if self
            .endpoints
            .get(&circuit)
            .is_some_and(|endpoint| !endpoint.drains.is_empty())
        {
            self.draining.insert(circuit);
        }
        (paced, digests)
    }

    fn serve_one<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<(Vec<Reply>, Vec<DigestDue>), Reject> {
        let range = Range::of(command.cmd);
        if !self.ensure_endpoint(circuit) {
            return Err(Reject::Rejected);
        }
        let accepts = Accepts::CrossRelay(&self.issuer_keys);
        let endpoint = self.endpoints.get_mut(&circuit).ok_or(Reject::Rejected)?;
        // WIR-107, WIR-363: one circuit carries one range.
        if *endpoint.range.get_or_insert(range) != range {
            return Err(Reject::Rejected);
        }
        match range {
            Range::Queue => self
                .queues
                .handle(
                    circuit,
                    &mut endpoint.session,
                    &mut endpoint.drains,
                    &mut self.gate,
                    &accepts,
                    command,
                    now,
                    rng,
                )
                .map(|replies| (replies, Vec::new())),
            Range::Attachment => self
                .chunks
                .handle(
                    circuit,
                    &mut endpoint.session,
                    &mut self.gate,
                    &accepts,
                    command,
                    now,
                    rng,
                )
                .map(|replies| (replies, Vec::new())),
            Range::Group => self.groups.handle(
                circuit,
                &mut endpoint.session,
                &mut endpoint.drains,
                &mut self.gate,
                &accepts,
                command,
                now,
                rng,
            ),
        }
    }

    /// The cells of the answers that wait on a circuit. An attachment
    /// circuit sends each one that waits, up to one step, while its link is
    /// calm (`NET-360`). Each other circuit sends one cell.
    fn answers(&mut self, circuit: &CircuitKey) -> Vec<Action> {
        let Some(endpoint) = self.endpoints.get_mut(circuit) else {
            return Vec::new();
        };
        let is_bulk = endpoint.range == Some(Range::Attachment);
        let has_room = is_bulk
            && fits(
                self.backlog.as_deref(),
                &self.framed,
                circuit.link,
                ANSWER_STEP,
                DRAIN_CALM_PART,
            );
        let mut actions = Vec::new();
        let mut sent = 0usize;
        let mut next = endpoint.outbox.pop_front();
        while let Some(outbound) = next.take() {
            let bucket = outbound.bucket;
            let mut content = outbound.encoded;
            while endpoint.outbox.front().is_some_and(|more| {
                is_bulk && content.len().saturating_add(more.encoded.len()) <= bucket.command_area()
            }) {
                if let Some(more) = endpoint.outbox.pop_front() {
                    content.extend(more.encoded);
                }
            }
            let Some(action) =
                self.circuits
                    .originate(circuit, bucket, CellCommand::Data, &content)
            else {
                // NET-321: an answer that the circuit cannot carry ends
                // it at once, thus the client builds again with no wait
                // for the sweep.
                actions.extend(self.circuits.shed(circuit.link, circuit.circ_id));
                return actions;
            };
            actions.push(action);
            sent = sent.saturating_add(bucket.cell_len());
            let has_step = endpoint
                .outbox
                .front()
                .is_some_and(|more| sent.saturating_add(more.bucket.cell_len()) <= ANSWER_STEP);
            if has_room && has_step {
                next = endpoint.outbox.pop_front();
            }
        }
        actions
    }

    /// Whether the answers of a circuit go with no wait for its clock: an
    /// attachment circuit with a calm link (`NET-360`).
    fn is_prompt(&self, circuit: &CircuitKey) -> bool {
        self.endpoints
            .get(circuit)
            .is_some_and(|endpoint| !endpoint.paused && endpoint.range == Some(Range::Attachment))
            && fits(
                self.backlog.as_deref(),
                &self.framed,
                circuit.link,
                ANSWER_STEP,
                DRAIN_CALM_PART,
            )
    }

    /// One tick of the pacing clock of a circuit (`NET-035`, `NET-036`):
    /// the next command that waits, a reflected loop cell, or a `B0` cover
    /// cell. The schedule does not depend on the arrival of a message.
    pub fn pacing_tick<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: &CircuitKey,
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        let Some(endpoint) = self
            .endpoints
            .get_mut(circuit)
            .filter(|endpoint| !endpoint.paused)
        else {
            return Vec::new();
        };
        if !endpoint.outbox.is_empty() {
            let actions = self.answers(circuit);
            return self.run(actions, now, rng);
        }
        let action = if endpoint.loops > 0 {
            endpoint.loops = endpoint.loops.saturating_sub(1);
            self.circuits
                .originate(circuit, Bucket::B0, CellCommand::Loop, &[])
        } else {
            // WIR-015: a COVER of the shape of a B0 MSG.
            let mut corr_id = [0u8; 16];
            rng.fill_bytes(&mut corr_id);
            let payload = vec![0u8; Bucket::B0.l5_payload()];
            let cover = Command {
                cmd: Cmd::Cover,
                corr_id,
                queue_id: [0; 32],
                auth: [0; 32],
                payload: &payload,
            };
            let mut encoded = vec![0u8; cover.len()];
            cover.encode(&mut encoded).ok().and_then(|_| {
                self.circuits
                    .originate(circuit, Bucket::B0, CellCommand::Data, &encoded)
            })
        };
        self.run(action.into_iter().collect(), now, rng)
    }

    /// Sends the next step of each drain that waits (`NET-037`). The
    /// runtime calls it at each tick of its clock. Each step reads its
    /// records from the queue of its drain. The relay thus copies at most
    /// `DRAIN_STEP` of a backlog for one circuit at one tick. A drain that
    /// its link holds back costs nothing.
    pub fn drain_tick<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) -> Vec<Output> {
        let mut actions = Vec::new();
        let mut cut = Vec::new();
        // The bytes that this tick put on each link.
        let mut stepped: BTreeMap<LinkId, usize> = BTreeMap::new();
        // The circuits take their steps in turns, from the one after the
        // last that took one. Before this, the circuits of the lowest
        // identifiers took the room of a link at each tick. A drain of a
        // high one waited until theirs ended.
        let order: Vec<CircuitKey> = match self.drain_turn {
            Some(turn) => self
                .draining
                .range((Bound::Excluded(turn), Bound::Unbounded))
                .chain(self.draining.range(..=turn))
                .copied()
                .collect(),
            None => self.draining.iter().copied().collect(),
        };
        for circuit in &order {
            let Some(endpoint) = self
                .endpoints
                .get_mut(circuit)
                .filter(|endpoint| !endpoint.drains.is_empty())
            else {
                self.draining.remove(circuit);
                continue;
            };
            // NET-349: the drains of one link share its backlog. A drain
            // waits while the link holds more than a part of its bound. The
            // drains of some circuits thus fill no link of the others.
            let ahead = stepped.get(&circuit.link).copied().unwrap_or(0);
            let calm = fits(
                self.backlog.as_deref(),
                &self.framed,
                circuit.link,
                ahead.saturating_add(DRAIN_STEP),
                DRAIN_CALM_PART,
            );
            if !calm {
                continue;
            }
            self.drain_turn = Some(*circuit);
            let mut sent = 0usize;
            'step: while sent < DRAIN_STEP {
                let Some(drain) = endpoint.drains.first_mut() else {
                    break;
                };
                let room = DRAIN_STEP.saturating_sub(sent);
                let (records, ended) = match endpoint.range {
                    Some(Range::Queue) => self.queues.drain_step(circuit, drain, room, rng),
                    Some(Range::Group) => self.groups.drain_step(drain, room, rng),
                    Some(Range::Attachment) | None => (Vec::new(), true),
                };
                if ended {
                    endpoint.drains.end_first();
                }
                for outbound in records {
                    sent = sent.saturating_add(outbound.encoded.len());
                    let cell = self.circuits.originate(
                        circuit,
                        outbound.bucket,
                        CellCommand::Data,
                        &outbound.encoded,
                    );
                    // NET-321: a drain longer than the cells of its circuit
                    // ends the circuit at once. The client asks again from
                    // its cursor on a new one.
                    let Some(cell) = cell else {
                        cut.push(*circuit);
                        break 'step;
                    };
                    actions.push(cell);
                }
            }
            if endpoint.drains.is_empty() {
                self.draining.remove(circuit);
            }
            let total = stepped.entry(circuit.link).or_insert(0);
            *total = total.saturating_add(sent);
        }
        for circuit in cut {
            actions.extend(self.circuits.shed(circuit.link, circuit.circ_id));
        }
        if actions.is_empty() {
            return Vec::new();
        }
        self.run(actions, now, rng)
    }

    /// Whether one more signature check fits the budget of `link` in the
    /// minute of `now`.
    fn may_verify(&mut self, link: LinkId, now: u64) -> bool {
        let minute = now / 60;
        let held = self.verifies.entry(link).or_insert((minute, 0));
        if held.0 != minute {
            *held = (minute, 0);
        }
        if held.1 >= VERIFIES_PER_MINUTE {
            return false;
        }
        held.1 = held.1.saturating_add(1);
        true
    }

    /// Whether one more deposit fits the budget of `link` in the minute of
    /// `now`. Each deposit counts, with or without a queue that it names.
    fn may_deposit(&mut self, link: LinkId, now: u64) -> bool {
        let minute = now / 60;
        let held = self.deposits.entry(link).or_insert((minute, 0));
        if held.0 != minute {
            *held = (minute, 0);
        }
        if held.1 >= DEPOSITS_PER_MINUTE {
            return false;
        }
        held.1 = held.1.saturating_add(1);
        true
    }

    /// Whether the budget of `link` holds one more signature check in the
    /// minute of `now`. It takes none.
    fn verifies_left(&self, link: LinkId, now: u64) -> bool {
        self.verifies
            .get(&link)
            .is_none_or(|held| held.0 != now / 60 || held.1 < VERIFIES_PER_MINUTE)
    }

    /// The connection of a link closed. A client link of an ingress relay
    /// that holds a circuit parks its session (`WIR-542`): the client can
    /// resume it on a new connection. On each other link each circuit ends.
    pub fn link_closed(&mut self, link: LinkId, now: u64) -> Vec<Output> {
        // The connection of a session that its client paused.
        if self.parked.contains_key(&link) {
            return Vec::new();
        }
        let parks = self.layer == 1 && self.circuits.circuits_on(link) > 0;
        match self.links.get_mut(&link) {
            Some(Framing::Accepted(framing)) if parks => {
                framing.connection_lost(now);
                self.park(link, now)
            }
            _ => self.drop_link(link, now),
        }
    }

    /// Ends a link and its session: each circuit on it ends, and each
    /// neighbor of each one gets its `CircuitDestroy` (`NET-322`).
    fn drop_link(&mut self, link: LinkId, now: u64) -> Vec<Output> {
        if let Some(Framing::Accepted(framing)) = self.links.remove(&link) {
            let session_id = framing.id();
            if self.sessions.get(&session_id) == Some(&link) {
                self.sessions.remove(&session_id);
            }
        }
        self.parked.remove(&link);
        self.verifies.remove(&link);
        self.deposits.remove(&link);
        self.fresh.remove(&link);
        self.quiet.remove(&link);
        self.framed.remove(&link);
        self.waits.remove(&link);
        self.sources.remove(&link);
        self.receipts.link_closed(link);
        self.next_hops.retain(|_, held| *held != link);
        self.loops.link_closed(link);
        self.circuits.set_clock_ms(clock_ms());
        let actions = self.circuits.link_closed(link);
        let mut outputs = self.finish(actions, now);
        outputs.push(Output::Close { link });
        outputs
    }

    /// Takes the end of circuits: the services drop what they held for
    /// each, and each neighbor gets its `Destroy` (`NET-322`).
    fn finish(&mut self, actions: Vec<Action>, now: u64) -> Vec<Output> {
        let mut outputs = Vec::new();
        for action in actions {
            match action {
                Action::Closed { circuit } => self.endpoint_closed(&circuit, now),
                Action::Destroy { link, circ_id } => {
                    outputs.extend(self.destroy(link, circ_id));
                }
                // NET-339: an end that waits for the delayed cells of its
                // circuit.
                Action::Delayed {
                    at_ms,
                    circuit,
                    action,
                } => {
                    self.delayed_seq = self.delayed_seq.wrapping_add(1);
                    self.delayed
                        .insert((at_ms, self.delayed_seq), (circuit, *action));
                }
                _ => {}
            }
        }
        outputs
    }

    /// The periodic work: aged circuits, expired records, idle queues, the
    /// retention of each cache, and the digests that a budget held back.
    pub fn sweep<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) -> Vec<Output> {
        // NET-319: a dial that never opened a link holds no body past the
        // timeout of the client.
        for waiting in self.extending.values_mut() {
            waiting.retain(|held| held.is_live(now));
        }
        self.extending.retain(|_, waiting| !waiting.is_empty());
        self.dials
            .retain(|_, dial| now.saturating_sub(dial.at) < DIAL_TIMEOUT);
        self.circuits.set_clock_ms(clock_ms());
        let aged = self.circuits.expire(self.table_now(now));
        let mut ended = self.finish(aged, now);
        // REL-069: an address whose attempts each came back leaves the
        // count.
        self.measure_attempts.retain(|_, attempts| {
            attempts.refill(now);
            attempts.spent > 0
        });
        self.measure_sessions
            .retain(|_, session| session.until > now);
        // NET-335: a client link that held no circuit for LINK_IDLE_TIMEOUT
        // gives its place back. A client of ordinary use holds a circuit
        // while it holds its link.
        if self.layer == 1 {
            // WIR-244: a parked session ends with its window. One whose
            // last circuit ended has nothing to resume, and it ends too.
            let over: Vec<LinkId> = self
                .parked
                .keys()
                .filter(|link| {
                    self.circuits.circuits_on(**link) == 0
                        || !matches!(
                            self.links.get(*link),
                            Some(Framing::Accepted(framing)) if !framing.expired(now)
                        )
                })
                .copied()
                .collect();
            for link in over {
                ended.extend(self.drop_link(link, now));
            }
            // A parked link holds no connection, thus it is not idle.
            let idle: Vec<LinkId> = self
                .links
                .iter()
                .filter(|(link, framing)| {
                    matches!(framing, Framing::Accepted(_))
                        && !self.parked.contains_key(*link)
                        && self.circuits.circuits_on(**link) == 0
                })
                .map(|(link, _)| *link)
                .collect();
            self.quiet
                .retain(|link, _| idle.binary_search(link).is_ok());
            for link in idle {
                let since = *self.quiet.entry(link).or_insert(now);
                if now.saturating_sub(since) >= LINK_IDLE_TIMEOUT {
                    ended.extend(self.drop_link(link, now));
                }
            }
        }
        self.queues.sweep(now);
        // ATT-046, ATT-168: a chunk past its erase time leaves, and the
        // store trims to its target.
        self.chunks.sweep(now);
        let due = self.groups.sweep(now);
        ended.extend(self.deliver_digests(due, now, rng));
        ended
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
    use umbra_core::attach::{command::ReplicaTarget, CHUNK_SIZE};
    use umbra_crypto::x25519::PublicKey as XPublic;

    struct Rng;
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(4)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(4)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(4);
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    #[test]
    fn a_copy_is_one_replica_capsule_and_a_relay_takes_it_with_no_session() {
        let push = Push {
            chunk_id: [0xC7; 32],
            target: ReplicaTarget {
                relay_id: [0xB1; 32],
                storage_token: [0xB2; 32],
            },
            chunk: vec![0x3C; CHUNK_SIZE],
        };
        let Some(Output::Push { relay_id, capsule }) = push_output(&push) else {
            panic!("no capsule");
        };
        assert_eq!(relay_id, [0xB1; 32]);
        let (kind, value, used) = capsule::parse(&capsule).unwrap();
        assert_eq!((kind, used), (CapsuleType::Replica, capsule.len()));
        assert_eq!(value.len(), capsule::REPLICA_LEN);
        let (command, _) = Command::parse(value, Bucket::B3).unwrap();
        assert_eq!(command.cmd, Cmd::Attachment(CRPUT));
        assert_eq!(command.queue_id, [0xC7; 32]);
        let copy = CrputPayload::parse(command.payload).unwrap();
        assert_eq!(copy.storage_token, [0xB2; 32]);
        assert_eq!(copy.chunk, push.chunk);

        // A relay that holds no registration for the chunk drops the copy.
        // It gives no answer, and it keeps the link (`ATT-107`).
        let static_secret = StaticSecret::from([7; 32]);
        let mut node = RelayNode::new(Config {
            relay: RelayStatic {
                s: *XPublic::from(&static_secret).as_bytes(),
                relay_id: [0xB1; 32],
            },
            static_secret,
            layer: 3,
            chunk_capacity: 1 << 24,
        });
        assert!(node.on_capsule(2, &capsule, 1_000, &mut Rng).is_empty());
        assert_eq!(node.chunks.held_count(), 0);
        // A capsule of that type with another length does not parse, and the
        // link ends.
        let outputs = node.on_capsule(2, &capsule[..capsule.len() - 1], 1_000, &mut Rng);
        assert!(matches!(outputs[..], [Output::Close { link: 2 }]));
    }

    fn relay_config(seed: u8) -> Config {
        let static_secret = StaticSecret::from([seed; 32]);
        Config {
            relay: RelayStatic {
                s: *XPublic::from(&static_secret).as_bytes(),
                relay_id: [seed; 32],
            },
            static_secret,
            layer: 3,
            chunk_capacity: 0,
        }
    }

    /// One `UMBRA_SESSION` capsule.
    fn session_capsule(control: &SessionControl) -> Vec<u8> {
        let mut record = [0u8; 64];
        let used = control.encode(&mut record).unwrap();
        let mut capsule = vec![0u8; capsule::HEADER_LEN + used];
        let len = capsule::encode(CapsuleType::Session, &record[..used], &mut capsule).unwrap();
        capsule.truncate(len);
        capsule
    }

    #[test]
    fn a_resume_that_names_no_session_closes_and_a_relay_link_parks_none() {
        let mut node = RelayNode::new(relay_config(7));
        let secret = Secret::new([0x61; 32]);
        let resume = session_capsule(&SessionControl::resume(&secret, [0x62; 8], 1, 0, 0));

        // WIR-239, WIR-240: a resume that names no session of this relay
        // closes its connection, and the close names no cause.
        let outputs = node.on_capsule(2, &resume, 1_000, &mut Rng);
        assert!(matches!(outputs[..], [Output::Close { link: 2 }]));
        assert!(node.links.is_empty());

        // WIR-548: a relay of layer 2 or 3 parks no session, thus the state
        // of a session ends with its connection there. A resume with the
        // correct `auth` on a new connection finds no session to bind.
        let open = session_capsule(&SessionControl::Open {
            session_id: [0x62; 8],
            session_secret: Secret::new([0x61; 32]),
        });
        assert!(node.on_capsule(3, &open, 1_000, &mut Rng).is_empty());
        assert_eq!(node.links.len(), 1);
        // WIR-233: a second open of that identifier closes its connection,
        // and the first session stays.
        let outputs = node.on_capsule(5, &open, 1_000, &mut Rng);
        assert!(matches!(outputs[..], [Output::Close { link: 5 }]));
        assert_eq!(node.sessions.get(&[0x62; 8]), Some(&3));
        // A live session at such a relay binds no resume either.
        let outputs = node.on_capsule(6, &resume, 1_000, &mut Rng);
        assert!(matches!(outputs[..], [Output::Close { link: 6 }]));
        assert_eq!(node.links.len(), 1);
        node.link_closed(3, 1_001);
        assert!(node.links.is_empty() && node.sessions.is_empty());
        assert_eq!(node.sessions_parked(), 0);
        let outputs = node.on_capsule(4, &resume, 1_002, &mut Rng);
        assert!(matches!(outputs[..], [Output::Close { link: 4 }]));
        assert!(node.links.is_empty());
    }

    #[test]
    fn a_link_deposits_its_budget_in_a_minute_and_no_more() {
        let now = 1_800_000_000;
        let (mut relay_b, _, capsule) = deposit_bench(now);
        let stored = |node: &mut RelayNode| {
            node.take_changes()
                .iter()
                .any(|change| matches!(change, StoreChange::Record { .. }))
        };
        // A deposit that names no queue of this relay counts all the same.
        let mut unknown = capsule.clone();
        let last = unknown.len() - 1;
        unknown[last] ^= 1;
        for _ in 0..DEPOSITS_PER_MINUTE {
            assert!(relay_b.on_capsule(4, &unknown, now, &mut Rng).is_empty());
        }
        // The deposit above the budget drops before any key agreement: it
        // gives no answer, it stores nothing, and the link stays.
        assert!(relay_b.on_capsule(4, &capsule, now, &mut Rng).is_empty());
        assert!(!stored(&mut relay_b));
        // The next minute gives the budget back, and each link has its own.
        assert!(!relay_b.may_deposit(4, now));
        assert!(relay_b.may_deposit(4, now + 60));
        assert!(relay_b.on_capsule(5, &capsule, now, &mut Rng).is_empty());
        assert!(stored(&mut relay_b));
        // A closed link leaves no count.
        relay_b.link_closed(4, now);
        assert!(!relay_b.deposits.contains_key(&4));
    }

    /// Relay B with the notify queue of a reader, and the address of that
    /// queue. The last value is the deposit of one digest that relay A
    /// signed for B.
    fn deposit_bench(now: u64) -> (RelayNode, QueueAddress, Vec<u8>) {
        use umbra_crypto::stored::Writer;
        use umbra_queue::relay::queue::{Queue, QueueKeys};
        // Relay B holds the notify queue of a reader.
        let qs = StaticSecret::from([0x51; 32]);
        let keys = QueueKeys {
            recipient_id: [0x52; 32],
            sender_id: [0x53; 32],
            qr_auth_pk: [0x54; 32],
            qs_auth_pk: *XPublic::from(&qs).as_bytes(),
        };
        let mut head = Writer::new();
        Queue::new(keys, now).export_head(&mut head);
        let mut loaded = Loaded::default();
        loaded.queues.insert(
            [0x52; 32],
            crate::store::StoredQueue {
                head: head.finish().to_vec(),
                records: Vec::new(),
            },
        );
        let b = relay_config(0xB5);
        let b_id = b.relay.relay_id;
        let b_key = b.relay.s;
        let relay_b = RelayNode::restored(b, loaded);

        // Relay A holds the group queue and the registration of that queue.
        let mut relay_a = RelayNode::new(relay_config(0xA5));
        relay_a.set_queue_relays(BTreeMap::from([(b_id, b_key)]));
        let address = QueueAddress {
            relay_id: b_id,
            sender_id: [0x53; 32],
            qs_auth_sk: Secret::new([0x51; 32]),
            qe: Secret::new([0x55; 32]),
        };
        let mut queue = [0u8; umbra_wire::address::LEN];
        address.encode(&mut queue).unwrap();
        let due = DigestDue {
            id: [0x56; 32],
            queue,
            post_count: 3,
        };
        let outputs = relay_a.deliver_digests(vec![due], now, &mut Rng);
        let [Output::Push { relay_id, capsule }] = &outputs[..] else {
            panic!("no deposit");
        };
        assert_eq!(*relay_id, b_id);
        let (kind, value, _) = capsule::parse(capsule).unwrap();
        assert_eq!(kind, CapsuleType::Deposit);
        assert_eq!(value.len(), capsule::DEPOSIT_LEN);
        (relay_b, address, capsule.clone())
    }

    #[test]
    fn a_digest_goes_to_the_queue_relay_of_its_notify_queue_as_one_deposit() {
        use umbra_crypto::queue::QueueKey;
        use umbra_wire::queue::open;
        let now = 1_800_000_000;
        let (mut relay_b, address, capsule) = deposit_bench(now);
        let b_id = address.relay_id;
        let capsule = &capsule;

        // A deposit signed for another relay does not verify at B. It comes
        // first, thus no `corr_id` of B holds it back.
        let mut other = relay_config(0xC5);
        other.relay.relay_id = [0xC5; 32];
        let mut relay_c = RelayNode::new(other);
        relay_c.set_queue_relays(BTreeMap::from([(b_id, [0x77; 32])]));
        let mut queue = [0u8; umbra_wire::address::LEN];
        address.encode(&mut queue).unwrap();
        let forged = relay_c.deliver_digests(
            vec![DigestDue {
                id: [0x56; 32],
                queue,
                post_count: 1,
            }],
            now,
            &mut Rng,
        );
        let [Output::Push {
            capsule: forged, ..
        }] = &forged[..]
        else {
            panic!("no deposit");
        };
        relay_b.on_capsule(4, forged, now, &mut Rng);
        assert!(!relay_b
            .take_changes()
            .iter()
            .any(|change| matches!(change, StoreChange::Record { .. })));

        // WIR-526: relay B takes it with no session and gives no answer, and
        // the reader opens a digest that names the group queue.
        assert!(relay_b.on_capsule(4, capsule, now, &mut Rng).is_empty());
        let changes = relay_b.take_changes();
        let record = changes
            .iter()
            .find_map(|change| match change {
                StoreChange::Record { record, .. } => Some(record.bytes.clone()),
                _ => None,
            })
            .expect("a stored record");
        let key = QueueKey::derive(&Secret::new([0x55; 32]), &[0x53; 32]);
        let mut inner = vec![0u8; Bucket::B0.l6_record()];
        let (kind, used) = open(&key, &[0x53; 32], &record, Bucket::B0, &mut inner).unwrap();
        assert_eq!(kind, L6Kind::NotifyDigest);
        let digest = NotifyDigest::parse(&inner[..used]).unwrap();
        assert_eq!((digest.id, digest.post_count), ([0x56; 32], 3));

        // WIR-527: the same capsule again is a repeat, and it stores nothing.
        relay_b.on_capsule(4, capsule, now, &mut Rng);
        assert!(!relay_b
            .take_changes()
            .iter()
            .any(|change| matches!(change, StoreChange::Record { .. })));
    }
}
