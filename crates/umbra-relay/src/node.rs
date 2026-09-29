//! One relay as a state machine: the session links of Part 6 §6.2, the
//! circuits of Part 3 §3.4, the services at the end of a circuit, and the
//! paced delivery of Part 3 §3.5.2.
//!
//! The node reads no clock, draws no random value, and opens no socket.
//! The runtime gives it the bytes of each link, the ticks of each pacing
//! clock, and the time, and it sends what the node returns.

use std::collections::{BTreeMap, VecDeque};

/// The wall clock in milliseconds, for the per-hop delay of Part 3 §3.9.
fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

use umbra_core::{
    abuse::{
        admission::{Accepts, RelayGate},
        pow::{ChallengeBook, PowChallenge},
    },
    attach::command::{CrputPayload, CRPUT_LEN},
    directory::{
        receipt,
        stat::{StatAnswer, StatQuery},
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
use umbra_transport::link::{ClientLink, RelayLink};
use umbra_wire::{
    address::QueueAddress,
    bucket::Bucket,
    capsule::{self, CapsuleType},
    cell::CellCommand,
    command::{Cmd, Command},
    group::GroupCmd,
    queue::L6Kind,
    session::SessionControl,
};

use crate::{
    circuits::{Action, CircuitKey, CircuitTable, LinkId},
    receipts::ReceiptBook,
    service::{
        chunk::{ChunkService, Push},
        group::GroupService,
        nack,
        queue::{NdrPush, QueueService},
        DigestDue, Outbound, Reply,
    },
    store::{Loaded, StoreChange},
};

/// The notification key of a queue relay, from its static secret under a
/// label of its own (`NTF-112`). A relay of another layer holds no queue.
fn notify_pair(config: &Config) -> Option<umbra_crypto::kem::KeyPair> {
    (config.layer == 3).then(|| {
        umbra_core::notify::seeded_pair(b"umbra/v1/relay-ntf", &config.static_secret.to_bytes())
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
    /// Send one capsule to another relay, on a connection of its own: the
    /// copy of a chunk (`WIR-211`) or the deposit of a digest (`WIR-526`).
    /// The runtime keeps nothing of it after the send.
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
    loops: u32,
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
    /// The link receipts (Part 10 §10.4.2).
    receipts: ReceiptBook,
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
        let mut queues = QueueService::default();
        if let Some(pair) = notify_pair(&config) {
            queues.set_notify_key(pair);
        }
        RelayNode {
            issuer_keys: BTreeMap::new(),
            links: BTreeMap::new(),
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
            receipts: ReceiptBook::default(),
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
    /// relay as an `UMBRA_DEPOSIT` capsule on a connection of its own.
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
                endpoint.outbox.push_back(reply.outbound);
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
    pub fn restored(config: Config, loaded: Loaded) -> Self {
        let chunks = ChunkService::restore(config.chunk_capacity, &loaded);
        let mut node = RelayNode::new(config);
        node.chunks = chunks;
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
        let mut outputs: Vec<Output> = self
            .queues
            .take_ndr_pushes()
            .into_iter()
            .map(Output::NdrPush)
            .collect();
        // REL-074, REL-176: the windows of an ended epoch close, and an old
        // receipt goes.
        let built = self.circuits.take_builds();
        self.receipts.count_chains(built, now, rng);
        if let Some(key) = self.pow_key.as_ref() {
            let own = self.relay.relay_id;
            for (link, signed) in self.receipts.tick(&own, key, now, rng) {
                outputs.extend(capsule_output(link, CapsuleType::Receipt, &signed));
            }
        }
        outputs
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
    ) -> Option<receipt::ReceiptAnswer> {
        // REL-186: one authority asks at most RECEIPT_QUERY_MAX times.
        if !self.receipts.admit(query.authority_index, now) {
            return None;
        }
        Some(self.receipts.answer(query))
    }

    /// The answer to a query of an aggregator that verified (`REL-192`), or
    /// none above the bound of `REL-186`.
    pub fn stat_answer(&mut self, query: &StatQuery, now: u64) -> Option<StatAnswer> {
        if !self.receipts.admit(query.authority_index, now) {
            return None;
        }
        Some(StatAnswer {
            share: self.receipts.share(query.authority_index, query.epoch),
        })
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
        changes
    }

    /// The gate, for the effort that the runtime sets under load.
    pub fn gate_mut(&mut self) -> &mut RelayGate {
        &mut self.gate
    }

    /// The circuits that end here, each of which holds a pacing clock
    /// (`NET-035`).
    pub fn paced_circuits(&self) -> impl Iterator<Item = &CircuitKey> {
        self.endpoints.keys()
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
            let hello = receipt::relay_hello(&self.relay.relay_id, &session_id, key, rng);
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
                actions.extend(self.bind_extend(waiting.from, link, &waiting.body, rng));
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
        rng: &mut R,
    ) -> Vec<Action> {
        let mut next = CircuitKey {
            link: next_link,
            circ_id: [0; 16],
        };
        // NET-154, NET-155.
        loop {
            rng.fill_bytes(&mut next.circ_id);
            if self.circuits.is_free(&next) {
                break;
            }
        }
        self.circuits.bind_next(from, next, body)
    }

    /// Takes the bytes of one capsule from a link.
    pub fn on_capsule<R: CryptoRng + ?Sized>(
        &mut self,
        link: LinkId,
        bytes: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<Output> {
        let Ok((kind, value, _)) = capsule::parse(bytes) else {
            return vec![Output::Close { link }];
        };
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
            // holds no session.
            CapsuleType::Deposit => self.take_deposit(value, now, rng),
            // ABU-103: the challenge of another relay, for a carrier.
            CapsuleType::Challenge => {
                self.take_challenge(value, now);
                Vec::new()
            }
            // REL-174: the relay that dialed this link names itself.
            CapsuleType::RelayHello => {
                if let Some(Framing::Accepted(framing)) = self.links.get(&link) {
                    let session_id = framing.session_id();
                    let identities = &self.identities;
                    let named = receipt::verify_relay_hello(value, &session_id, |id| {
                        identities.get(id).cloned()
                    });
                    if let Ok(relay_id) = named {
                        self.receipts.set_peer(link, relay_id);
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
                {
                    let identity = identity.clone();
                    self.receipts
                        .receipt_taken(link, value, &self.relay.relay_id, &identity, now);
                }
                Vec::new()
            }
            CapsuleType::Cell => {
                let cell = match self.links.get_mut(&link) {
                    Some(Framing::Accepted(framing)) => framing.receive(value),
                    Some(Framing::Dialed(framing)) => framing.receive(value),
                    None => return vec![Output::Close { link }],
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
                        self.circuits.set_clock_ms(unix_now_ms());
                        let actions = self.circuits.on_cell(link, &cell, now, rng);
                        outputs.extend(self.run(actions, now, rng));
                        outputs
                    }
                    // WIR-141: a frame that the link accepted before.
                    Ok(None) => Vec::new(),
                    Err(_) => vec![Output::Close { link }],
                }
            }
        }
    }

    fn on_control(&mut self, link: LinkId, value: &[u8], now: u64) -> Vec<Output> {
        let Ok(control) = SessionControl::parse(value) else {
            return vec![Output::Close { link }];
        };
        match (&control, self.links.remove(&link)) {
            (SessionControl::Open { .. }, None) => match RelayLink::open(control) {
                Ok(framing) => {
                    self.links.insert(link, Framing::Accepted(framing));
                    Vec::new()
                }
                Err(_) => vec![Output::Close { link }],
            },
            // NET-322: a neighbor ended a circuit on this link.
            (SessionControl::Destroy { circ_id }, Some(framing)) => {
                let circ_id = *circ_id;
                self.links.insert(link, framing);
                self.circuits.set_clock_ms(unix_now_ms());
                let actions = self.circuits.on_destroy(link, circ_id);
                self.finish(actions, now)
            }
            (SessionControl::Resume { .. }, Some(Framing::Accepted(mut framing))) => {
                let resumed = framing.resume(&control, now).is_ok();
                self.links.insert(link, Framing::Accepted(framing));
                if resumed {
                    Vec::new()
                } else {
                    vec![Output::Close { link }]
                }
            }
            _ => self.link_closed(link, now),
        }
    }

    fn frame(&mut self, link: LinkId, cell: &[u8]) -> Option<Output> {
        let mut capsule = vec![0u8; cell.len().saturating_add(32)];
        let used = match self.links.get_mut(&link)? {
            Framing::Accepted(framing) => framing.send(cell, &mut capsule).ok()?,
            Framing::Dialed(framing) => {
                let used = framing.send(cell, &mut capsule).ok()?;
                // The relay keeps no resend window toward the next hop: a
                // lost link ends its circuits, and each client builds again.
                framing.drained(framing.next_seq().saturating_sub(1));
                used
            }
        };
        capsule.truncate(used);
        self.receipts.cell_sent(link, cell);
        Some(Output::Send { link, capsule })
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
                Action::Send { link, cell } => outputs.extend(self.frame(link, &cell)),
                Action::Extend {
                    from,
                    relay_id,
                    body,
                } => match self.next_hops.get(&relay_id).copied() {
                    // NET-167: only a relay of the next layer holds a link
                    // here. NET-319: the body waits for the link, and one
                    // dial serves each body that waits for that relay.
                    None => {
                        let waiting = self.extending.entry(relay_id).or_default();
                        waiting.retain(|held| held.is_live(now));
                        if waiting.is_empty() {
                            outputs.push(Output::Dial { relay_id });
                        }
                        waiting.push(Waiting {
                            from,
                            body,
                            arrived_at: now,
                        });
                    }
                    Some(next_link) => work.extend(self.bind_extend(from, next_link, &body, rng)),
                },
                Action::Serve {
                    circuit,
                    bucket,
                    content,
                } => {
                    let (paced, unpaced, digests) = self.serve(circuit, bucket, &content, now, rng);
                    outputs.extend(self.deliver_digests(digests, now, rng));
                    // ATT-102: one copy for each target of a `CREP`.
                    outputs.extend(self.chunks.take_pushes().iter().filter_map(push_output));
                    outputs.extend(
                        self.queues
                            .take_ndr_pushes()
                            .into_iter()
                            .map(Output::NdrPush),
                    );
                    for reply in unpaced {
                        work.extend(self.circuits.originate(
                            &reply.circuit,
                            reply.outbound.bucket,
                            CellCommand::Data,
                            &reply.outbound.encoded,
                        ));
                    }
                    for reply in paced {
                        if let Some(endpoint) = self.endpoints.get_mut(&reply.circuit) {
                            endpoint.outbox.push_back(reply.outbound);
                        }
                    }
                }
                Action::Loop { circuit } => {
                    self.ensure_endpoint(circuit);
                    if let Some(endpoint) = self.endpoints.get_mut(&circuit) {
                        endpoint.loops = endpoint.loops.saturating_add(1);
                    }
                }
                Action::Destroy { link, circ_id } => outputs.extend(destroy_output(link, circ_id)),
                Action::Closed { circuit } => {
                    self.endpoints.remove(&circuit);
                    self.queues.circuit_closed(&circuit, now);
                    self.groups.circuit_closed(&circuit);
                }
                // NET-339: the end of a circuit after its delayed cells.
                Action::End { key, from } => work.extend(self.circuits.end_now(key, from)),
                // Part 3 §3.9: the cell waits for the per-hop delay of its
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
            }
        }
        outputs
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
                loops: 0,
            },
        );
        true
    }

    /// Serves the commands of one `DATA` cell. The result holds the paced
    /// replies, the replies of an unpaced drain, and the digests.
    fn serve<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        bucket: Bucket,
        content: &[u8],
        now: u64,
        rng: &mut R,
    ) -> (Vec<Reply>, Vec<Reply>, Vec<DigestDue>) {
        // WIR-318: a cell whose commands do not parse gets no answer.
        let Ok(commands) = unpack(content, bucket) else {
            return (Vec::new(), Vec::new(), Vec::new());
        };
        let mut paced = Vec::new();
        let mut unpaced = Vec::new();
        let mut digests = Vec::new();
        for command in &commands {
            let outcome = self.serve_one(circuit, command, now, rng);
            match outcome {
                Ok((replies, due)) => {
                    digests.extend(due);
                    // NET-037: a drain above the threshold goes at once.
                    let is_drain = matches!(command.cmd, Cmd::Sub | Cmd::Group(GroupCmd::Gsub))
                        && replies.len() > DRAIN_THRESHOLD;
                    if is_drain {
                        unpaced.extend(replies);
                    } else {
                        paced.extend(replies);
                    }
                }
                Err(reject) => {
                    // WIR-322: a NACK goes before each pending MSG.
                    if let Some(endpoint) = self.endpoints.get_mut(&circuit) {
                        endpoint
                            .outbox
                            .push_front(nack(circuit, command, reject).outbound);
                    }
                }
            }
        }
        (paced, unpaced, digests)
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
        // WIR-309, WIR-363: one circuit carries one range.
        if *endpoint.range.get_or_insert(range) != range {
            return Err(Reject::Rejected);
        }
        match range {
            Range::Queue => self
                .queues
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
                &mut self.gate,
                &accepts,
                command,
                now,
                rng,
            ),
        }
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
        let Some(endpoint) = self.endpoints.get_mut(circuit) else {
            return Vec::new();
        };
        let action = if let Some(outbound) = endpoint.outbox.pop_front() {
            self.circuits.originate(
                circuit,
                outbound.bucket,
                CellCommand::Data,
                &outbound.encoded,
            )
        } else if endpoint.loops > 0 {
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

    /// A link closed. Each circuit on it ends.
    pub fn link_closed(&mut self, link: LinkId, now: u64) -> Vec<Output> {
        self.links.remove(&link);
        self.receipts.link_closed(link);
        self.next_hops.retain(|_, held| *held != link);
        self.circuits.set_clock_ms(unix_now_ms());
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
                Action::Closed { circuit } => {
                    self.endpoints.remove(&circuit);
                    self.queues.circuit_closed(&circuit, now);
                    self.groups.circuit_closed(&circuit);
                }
                Action::Destroy { link, circ_id } => {
                    outputs.extend(destroy_output(link, circ_id));
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
        self.circuits.set_clock_ms(unix_now_ms());
        let aged = self.circuits.expire(now);
        let mut ended = self.finish(aged, now);
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

    #[test]
    fn a_digest_goes_to_the_queue_relay_of_its_notify_queue_as_one_deposit() {
        use umbra_crypto::{queue::QueueKey, stored::Writer};
        use umbra_queue::relay::queue::{Queue, QueueKeys};
        use umbra_wire::queue::open;
        let now = 1_800_000_000;
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
        let mut relay_b = RelayNode::restored(b, loaded);

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
