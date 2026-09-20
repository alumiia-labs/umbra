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
    session::batch::{unpack, Range},
};
use umbra_crypto::{
    handshake::nk::RelayStatic, rand_core::CryptoRng, rsabssa::PublicKey2048, secret::Secret,
    x25519::StaticSecret,
};
use umbra_queue::{relay::session::Session, Reject};
use umbra_transport::link::{ClientLink, RelayLink};
use umbra_wire::{
    bucket::Bucket,
    capsule::{self, CapsuleType},
    cell::CellCommand,
    command::{Cmd, Command},
    session::SessionControl,
};

use crate::{
    circuits::{Action, CircuitKey, CircuitTable, LinkId},
    service::{
        chunk::ChunkService,
        community::{CommunityService, DigestDue},
        nack,
        queue::QueueService,
        Outbound, Reply,
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
    /// dials it, and the client builds its circuit again.
    Dial {
        /// The relay.
        relay_id: [u8; 32],
    },
    /// Write a digest into a notify queue, as a sender.
    Digest(DigestDue),
    /// Close the link.
    Close {
        /// The link.
        link: LinkId,
    },
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

/// One relay.
pub struct RelayNode {
    issuer_key: PublicKey2048,
    links: BTreeMap<LinkId, Framing>,
    next_hops: BTreeMap<[u8; 32], LinkId>,
    circuits: CircuitTable,
    endpoints: BTreeMap<CircuitKey, Endpoint>,
    gate: RelayGate,
    queues: QueueService,
    communities: CommunityService,
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
            circuits: CircuitTable::new(config.relay, config.static_secret, config.layer),
            endpoints: BTreeMap::new(),
            gate: RelayGate::new(relay_id),
            queues: QueueService::default(),
            communities: CommunityService::new(config.community_capacity),
            chunks: ChunkService::new(config.chunk_capacity),
        }
    }

    /// A node that continues the queues and the invitations of an earlier
    /// run. Each circuit, each session, and each subscription of that run
    /// is gone, and the clients build them again.
    pub fn restored(config: Config, loaded: Loaded) -> Self {
        let mut node = RelayNode::new(config);
        node.queues = QueueService::restore(loaded);
        node
    }

    /// The changes of the stored state since the last call. The process
    /// commits them before it sends an output of the same call (`NET-298`).
    pub fn take_changes(&mut self) -> Vec<StoreChange> {
        self.queues.take_changes()
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
    /// is the capsule that opens the session (`WIR-229`).
    pub fn dialed(
        &mut self,
        link: LinkId,
        relay_id: [u8; 32],
        session_id: [u8; 8],
        session_secret: Secret<32>,
    ) -> Vec<Output> {
        let mut capsule = vec![0u8; 64];
        let Ok((client, used)) = ClientLink::open(session_id, session_secret, &mut capsule) else {
            return Vec::new();
        };
        capsule.truncate(used);
        self.links.insert(link, Framing::Dialed(client));
        self.next_hops.insert(relay_id, link);
        vec![Output::Send { link, capsule }]
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
                } => match self.next_hops.get(&relay_id) {
                    // NET-167: only a relay of the next layer holds a link here.
                    None => outputs.push(Output::Dial { relay_id }),
                    Some(next_link) => {
                        let mut next = CircuitKey {
                            link: *next_link,
                            circ_id: [0; 16],
                        };
                        // NET-154, NET-155.
                        loop {
                            rng.fill_bytes(&mut next.circ_id);
                            if self.circuits.is_free(&next) {
                                break;
                            }
                        }
                        work.extend(self.circuits.bind_next(from, next, &body));
                    }
                },
                Action::Serve {
                    circuit,
                    bucket,
                    content,
                } => {
                    let (paced, unpaced, digests) = self.serve(circuit, bucket, &content, now, rng);
                    outputs.extend(digests.into_iter().map(Output::Digest));
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
                    let is_drain = command.cmd == Cmd::Sub && replies.len() > DRAIN_THRESHOLD;
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
            // The group queues attach here in the same manner. Until they
            // do, the relay serves no command of that range.
            Range::Group => Err(Reject::Rejected),
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
            }
        }
        vec![Output::Close { link }]
    }

    /// The periodic work: aged circuits, expired records, idle queues, the
    /// retention of each cache, and the digests that a budget held back.
    pub fn sweep(&mut self, now: u64) -> Vec<Output> {
        for action in self.circuits.expire(now) {
            if let Action::Closed { circuit } = action {
                self.endpoints.remove(&circuit);
                self.queues.circuit_closed(&circuit, now);
            }
        }
        self.queues.sweep(now);
        self.communities
            .sweep(now)
            .into_iter()
            .map(Output::Digest)
            .collect()
    }
}
