//! One relay as a state machine: the session links of Part 6 §6.2, the
//! circuits of Part 3 §3.4, the services at the end of a circuit, and the
//! paced delivery of Part 3 §3.5.2.
//!
//! The node reads no clock, draws no random value, and opens no socket.
//! The runtime gives it the bytes of each link, the ticks of each pacing
//! clock, and the time, and it sends what the node returns.

use std::collections::{BTreeMap, VecDeque};

use umbra_core::{
    abuse::admission::{Accepts, RelayGate},
    attach::command::{CrputPayload, CRPUT_LEN},
    session::batch::{unpack, Range},
};
use umbra_crypto::{
    handshake::nk::RelayStatic, rand_core::CryptoRng, rsabssa::PublicKey2048, secret::Secret,
    x25519::StaticSecret,
};
use umbra_onion::CIRCUIT_BUILD_TIMEOUT;
use umbra_queue::{relay::session::Session, Reject};
use umbra_transport::link::{ClientLink, RelayLink};
use umbra_wire::{
    bucket::Bucket,
    capsule::{self, CapsuleType},
    cell::CellCommand,
    command::{Cmd, Command},
    group::GroupCmd,
    session::SessionControl,
};

use crate::{
    circuits::{Action, CircuitKey, CircuitTable, LinkId},
    service::{
        chunk::{ChunkService, Push},
        community::CommunityService,
        group::GroupService,
        nack,
        queue::QueueService,
        DigestDue, Outbound, Reply,
    },
    store::{Loaded, StoreChange},
};

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
    /// Write a digest into a notify queue, as a sender.
    Digest(DigestDue),
    /// Send one copy of a chunk to a replica relay, on a connection of its
    /// own (`WIR-211`). The runtime keeps nothing of it after the send.
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

/// The byte of a `CRPUT` (Part 13 §13.3.3).
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
    /// The key of the token issuer for the current epoch.
    pub issuer_key: PublicKey2048,
    /// The bytes of post records that each community cache holds.
    pub community_capacity: usize,
    /// The bytes of the chunk store of Part 13, or zero for a relay with no
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
    issuer_key: PublicKey2048,
    links: BTreeMap<LinkId, Framing>,
    next_hops: BTreeMap<[u8; 32], LinkId>,
    /// The `EXTEND` bodies that wait for a link to their next relay
    /// (`NET-319`).
    extending: BTreeMap<[u8; 32], Vec<Waiting>>,
    circuits: CircuitTable,
    endpoints: BTreeMap<CircuitKey, Endpoint>,
    gate: RelayGate,
    queues: QueueService,
    communities: CommunityService,
    groups: GroupService,
    chunks: ChunkService,
}

impl RelayNode {
    /// A relay with no link and no circuit.
    pub fn new(config: Config) -> Self {
        let relay_id = config.relay.relay_id;
        RelayNode {
            issuer_key: config.issuer_key,
            links: BTreeMap::new(),
            next_hops: BTreeMap::new(),
            extending: BTreeMap::new(),
            circuits: CircuitTable::new(config.relay, config.static_secret, config.layer),
            endpoints: BTreeMap::new(),
            gate: RelayGate::new(relay_id),
            queues: QueueService::default(),
            communities: CommunityService::new(config.community_capacity),
            groups: GroupService::default(),
            chunks: ChunkService::new(config.chunk_capacity),
        }
    }

    /// A node that continues the queues and the invitations of an earlier
    /// run. Each circuit, each session, and each subscription of that run
    /// is gone, and the clients build them again.
    pub fn restored(config: Config, loaded: Loaded) -> Self {
        let mut node = RelayNode::new(config);
        node.groups = GroupService::restore(&loaded);
        node.queues = QueueService::restore(loaded);
        node
    }

    /// The changes of the stored state since the last call. The process
    /// commits them before it sends an output of the same call (`NET-298`).
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        let mut changes = self.queues.take_changes();
        changes.append(&mut self.groups.take_changes());
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
        let mut outputs = vec![Output::Send { link, capsule }];
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
            CapsuleType::Cell => {
                let cell = match self.links.get_mut(&link) {
                    Some(Framing::Accepted(framing)) => framing.receive(value),
                    Some(Framing::Dialed(framing)) => framing.receive(value),
                    None => return vec![Output::Close { link }],
                };
                match cell {
                    Ok(Some(cell)) => {
                        let cell = cell.to_vec();
                        let actions = self.circuits.on_cell(link, &cell, now, rng);
                        self.run(actions, now, rng)
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
                    outputs.extend(digests.into_iter().map(Output::Digest));
                    // ATT-102: one copy for each target of a `CREP`.
                    outputs.extend(self.chunks.take_pushes().iter().filter_map(push_output));
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
                Action::Closed { circuit } => {
                    self.endpoints.remove(&circuit);
                    self.queues.circuit_closed(&circuit, now);
                    self.groups.circuit_closed(&circuit);
                }
            }
        }
        outputs
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
        let accepts = Accepts::CrossRelay(&self.issuer_key);
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
            Range::Community => self.communities.handle(
                circuit,
                &mut endpoint.session,
                &mut self.gate,
                &accepts,
                command,
                now,
            ),
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
        self.next_hops.retain(|_, held| *held != link);
        let actions = self.circuits.link_closed(link);
        for action in actions {
            if let Action::Closed { circuit } = action {
                self.endpoints.remove(&circuit);
                self.queues.circuit_closed(&circuit, now);
                self.groups.circuit_closed(&circuit);
            }
        }
        vec![Output::Close { link }]
    }

    /// The periodic work: aged circuits, expired records, idle queues, the
    /// retention of each cache, and the digests that a budget held back.
    pub fn sweep(&mut self, now: u64) -> Vec<Output> {
        // NET-319: a dial that never opened a link holds no body past the
        // timeout of the client.
        for waiting in self.extending.values_mut() {
            waiting.retain(|held| held.is_live(now));
        }
        self.extending.retain(|_, waiting| !waiting.is_empty());
        for action in self.circuits.expire(now) {
            if let Action::Closed { circuit } = action {
                self.endpoints.remove(&circuit);
                self.queues.circuit_closed(&circuit, now);
                self.groups.circuit_closed(&circuit);
            }
        }
        self.queues.sweep(now);
        let mut due = self.communities.sweep(now);
        due.extend(self.groups.sweep(now));
        due.into_iter().map(Output::Digest).collect()
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
            issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
            community_capacity: 1 << 20,
            chunk_capacity: 1 << 24,
        });
        assert!(node.on_capsule(2, &capsule, 1_000, &mut Rng).is_empty());
        assert_eq!(node.chunks.held_count(), 0);
        // A capsule of that type with another length does not parse, and the
        // link ends.
        let outputs = node.on_capsule(2, &capsule[..capsule.len() - 1], 1_000, &mut Rng);
        assert!(matches!(outputs[..], [Output::Close { link: 2 }]));
    }
}
