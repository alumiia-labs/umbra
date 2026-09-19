//! One client as a state machine: the session link to its guard, the
//! build of one circuit through three relays, the queues that it makes,
//! the contact setup of [`super::contact`], and the pairwise channels.
//!
//! The node reads no clock, draws no random value, and opens no socket.
//! The runtime gives it each capsule that arrives and sends each capsule
//! that [`ClientNode::take_capsules`] returns.
//!
//! This revision runs each queue of the client on one circuit. The rules
//! that put a send and a subscription on different circuits belong to the
//! path selection of Part 3 §3.4.6, which the runtime adds over this type.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};

use umbra_crypto::{
    handshake::{nk::RelayStatic, xk::SessionKeys},
    hierarchy::RootIdentity,
    kem::KeyPair,
    rand_core::CryptoRng,
    ratchet::{braid::Ratchet, codeword::Width, dr::Role},
    secret::Secret,
    x25519::StaticSecret,
};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::CircuitBuild,
    HOPS,
};
use umbra_queue::Reject;
use umbra_transport::link::ClientLink;
use umbra_wire::{
    address::QueueAddress,
    bucket::Bucket,
    capsule,
    cell::{Cell, CellCommand},
    command::{Cmd, IdsPayload},
    queue::L6Kind,
};

use super::{
    batch::Range,
    channel::{new_queue_command, Inbound, Opened, Outbound, PairwiseChannel, Received},
    circuit::{CircuitSession, Event as CircuitEvent},
    contact::{Invitee, Inviter},
};
use crate::{identity::invitation::Bundle, Error};

/// A contact of this client, by the `RecipientId` of the queue that the
/// client reads for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContactId(pub [u8; 32]);

/// What the node tells the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// The circuit holds its three hops, and commands can go.
    CircuitReady,
    /// An invitation is ready. The user gives the bundle to the other
    /// party out of band.
    Invitation {
        /// The handle of the call that asked for it.
        handle: u64,
        /// The encoded bundle of Part 5 §5.4.1.
        bundle: Vec<u8>,
    },
    /// The handshake with a contact finished on this side.
    ContactReady {
        /// The contact.
        contact: ContactId,
        /// The static X25519 key of the peer, for the verification of
        /// Part 4 §4.5.
        peer_static: [u8; 32],
    },
    /// An application record arrived. The runtime commits it and then
    /// calls [`ClientNode::acknowledge`] (`WIR-115`).
    Message {
        /// The contact.
        contact: ContactId,
        /// The `AppMessage` bytes.
        app: Vec<u8>,
    },
    /// A relay acknowledged a record of [`ClientNode::send`].
    Accepted {
        /// The handle of the send.
        handle: u64,
    },
    /// A relay rejected a command.
    Rejected {
        /// The handle of the call.
        handle: u64,
        /// The reason of the `NACK`.
        reason: Reject,
    },
    /// The circuit failed its check or its build, and the runtime builds a
    /// new one.
    CircuitLost,
}

enum Circuit {
    None,
    Building {
        build: Box<CircuitBuild>,
        pending: Box<Pending>,
    },
    Ready(Box<CircuitSession>),
}

/// Why the client made a queue.
enum Purpose {
    Invite,
    Accept { bundle: Vec<u8> },
}

/// The keys of a queue between its `NEW` and its `IDS`.
struct QueueKeys {
    qr_auth: StaticSecret,
    qs_auth: [u8; 32],
    queue_secret: [u8; 32],
    salt: [u8; 16],
    purpose: Purpose,
    handle: u64,
}

/// What a command of this node waits for.
enum Waiting {
    Queue(Box<QueueKeys>),
    UserSend(u64),
    Other,
}

enum Setup {
    Inviting(Box<Inviter>),
    Accepting(Box<Invitee>),
}

struct Half {
    identity: KeyPair,
    inbound: Inbound,
    setup: Setup,
    outbound: Option<Outbound>,
    /// The static key of the inviter, which the bundle gave the invitee.
    peer_static: [u8; 32],
}

/// One client.
pub struct ClientNode {
    relays: [RelayStatic; HOPS],
    root: RootIdentity,
    link: Option<ClientLink>,
    circuit: Circuit,
    capsules: VecDeque<Vec<u8>>,
    next_handle: u64,
    waiting: BTreeMap<u64, Waiting>,
    /// The contacts whose handshake runs, by `RecipientId`.
    halves: BTreeMap<[u8; 32], Half>,
    contacts: BTreeMap<[u8; 32], PairwiseChannel>,
}

fn random<const N: usize, R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn copy_static(relay: &RelayStatic) -> RelayStatic {
    RelayStatic {
        s: relay.s,
        relay_id: relay.relay_id,
    }
}

impl ClientNode {
    /// A client that reaches its queues through `relays`, hop 1 first.
    /// Each pairwise identity comes from `root` (Part 5 §5.2).
    pub fn new(relays: [RelayStatic; HOPS], root: RootIdentity) -> Self {
        ClientNode {
            relays,
            root,
            link: None,
            circuit: Circuit::None,
            capsules: VecDeque::new(),
            next_handle: 1,
            waiting: BTreeMap::new(),
            halves: BTreeMap::new(),
            contacts: BTreeMap::new(),
        }
    }

    /// The capsules to write to the link, in order.
    pub fn take_capsules(&mut self) -> Vec<Vec<u8>> {
        self.capsules.drain(..).collect()
    }

    /// Whether the circuit holds its three hops.
    pub fn is_ready(&self) -> bool {
        matches!(self.circuit, Circuit::Ready(_))
    }

    /// The contacts whose handshake finished.
    pub fn contacts(&self) -> impl Iterator<Item = ContactId> + '_ {
        self.contacts.keys().map(|id| ContactId(*id))
    }

    fn handle(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle = handle.saturating_add(1);
        handle
    }

    fn send_cell(&mut self, cell: &[u8]) -> Result<(), Error> {
        let link = self.link.as_mut().ok_or(Error::NoPath)?;
        let mut capsule = alloc::vec![0u8; cell.len().saturating_add(32)];
        let used = link.send(cell, &mut capsule).map_err(|_| Error::NoPath)?;
        capsule.truncate(used);
        self.capsules.push_back(capsule);
        Ok(())
    }

    /// The connection to the guard opened. The node opens the session and
    /// starts the build of the circuit (`WIR-229`, `NET-150`).
    pub fn connected<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let mut capsule = alloc::vec![0u8; 64];
        let (link, used) = ClientLink::open(random(rng), Secret::new(random(rng)), &mut capsule)
            .map_err(|_| Error::NoPath)?;
        capsule.truncate(used);
        self.capsules.push_back(capsule);
        self.link = Some(link);
        let build = CircuitBuild::new(random(rng));
        self.extend(build, rng)
    }

    /// Sends the `EXTEND` cell for the next hop of `build`.
    fn extend<R: CryptoRng + ?Sized>(
        &mut self,
        mut build: CircuitBuild,
        rng: &mut R,
    ) -> Result<(), Error> {
        let relay = self.relays.get(build.built()).ok_or(Error::NoPath)?;
        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(relay, rng, &mut hello).map_err(|_| Error::NoPath)?;
        let mut body = alloc::vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).map_err(|_| Error::NoPath)?;
        let tag = build.seal(&mut body).map_err(|_| Error::NoPath)?;
        let cell = [build.circ_id().as_slice(), &tag, &body].concat();
        self.circuit = Circuit::Building {
            build: Box::new(build),
            pending: Box::new(pending),
        };
        self.send_cell(&cell)
    }

    /// Moves each ready command of the circuit into a cell.
    fn pump(&mut self) -> Result<(), Error> {
        loop {
            let Circuit::Ready(session) = &mut self.circuit else {
                return Ok(());
            };
            let Some(cell) = session.next_cell()? else {
                return Ok(());
            };
            self.send_cell(&cell)?;
        }
    }

    fn queue_command(&mut self, encoded: Vec<u8>, waiting: Waiting) -> Result<u64, Error> {
        let handle = self.handle();
        let Circuit::Ready(session) = &mut self.circuit else {
            return Err(Error::NoPath);
        };
        session.queue(encoded, handle)?;
        self.waiting.insert(handle, waiting);
        Ok(handle)
    }

    fn session_pk(&self) -> Result<[u8; 32], Error> {
        match &self.circuit {
            Circuit::Ready(session) => Ok(*session.relay_session_pk()),
            _ => Err(Error::NoPath),
        }
    }

    fn make_queue<R: CryptoRng + ?Sized>(
        &mut self,
        purpose: Purpose,
        rng: &mut R,
    ) -> Result<u64, Error> {
        let user_handle = self.handle();
        let qr_auth = StaticSecret::from(random::<32, _>(rng));
        let qs_auth: [u8; 32] = random(rng);
        let encoded = new_queue_command(
            &qr_auth,
            &StaticSecret::from(qs_auth),
            &self.session_pk()?,
            random(rng),
        )?;
        let keys = QueueKeys {
            qr_auth,
            qs_auth,
            queue_secret: random(rng),
            salt: random(rng),
            purpose,
            handle: user_handle,
        };
        self.queue_command(encoded, Waiting::Queue(Box::new(keys)))?;
        self.pump()?;
        Ok(user_handle)
    }

    /// Starts one invitation. A [`ClientEvent::Invitation`] with the same
    /// handle carries the bundle after the relay made the queue
    /// (`NET-170`).
    pub fn invite<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<u64, Error> {
        self.make_queue(Purpose::Invite, rng)
    }

    /// Accepts the bundle of an inviter. A [`ClientEvent::ContactReady`]
    /// follows after flight 2 arrives.
    pub fn accept<R: CryptoRng + ?Sized>(
        &mut self,
        bundle: Vec<u8>,
        rng: &mut R,
    ) -> Result<u64, Error> {
        self.make_queue(Purpose::Accept { bundle }, rng)
    }

    /// Sends one application record to a contact. A
    /// [`ClientEvent::Accepted`] with the same handle follows the `QUOTA`
    /// of the relay.
    pub fn send<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &ContactId,
        app: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<u64, Error> {
        let session_pk = self.session_pk()?;
        let channel = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        let (_, encoded) = channel.send(app, &session_pk, random(rng), random(rng), now, rng)?;
        let user_handle = self.handle();
        self.queue_command(encoded, Waiting::UserSend(user_handle))?;
        self.pump()?;
        Ok(user_handle)
    }

    /// Acknowledges each record of a contact that the runtime committed.
    pub fn acknowledge<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &ContactId,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let session_pk = self.session_pk()?;
        let channel = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        if let Some((point, encoded)) = channel.acknowledge(&session_pk, random(rng), now)? {
            channel.acknowledged(point);
            self.queue_command(encoded, Waiting::Other)?;
            self.pump()?;
        }
        Ok(())
    }

    /// Takes one capsule from the link.
    pub fn on_capsule<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let (_, value, _) = capsule::parse(bytes)?;
        let link = self.link.as_mut().ok_or(Error::NoPath)?;
        let Some(cell) = link.receive(value).map_err(|_| Error::Unverified)? else {
            return Ok(Vec::new());
        };
        let cell = cell.to_vec();
        match core::mem::replace(&mut self.circuit, Circuit::None) {
            Circuit::None => Ok(Vec::new()),
            Circuit::Building { build, pending } => {
                self.on_build_cell(*build, *pending, &cell, rng)
            }
            Circuit::Ready(mut session) => {
                let received = session.receive_cell(&cell);
                self.circuit = Circuit::Ready(session);
                match received {
                    Ok(events) => self.on_events(events, now, rng),
                    // NET-115: a failed check ends the circuit.
                    Err(_) => {
                        self.circuit = Circuit::None;
                        Ok(alloc::vec![ClientEvent::CircuitLost])
                    }
                }
            }
        }
    }

    fn on_build_cell<R: CryptoRng + ?Sized>(
        &mut self,
        mut build: CircuitBuild,
        pending: Pending,
        cell: &[u8],
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let lost = Ok(alloc::vec![ClientEvent::CircuitLost]);
        let Ok((parsed, _)) = Cell::parse(cell) else {
            return lost;
        };
        let mut body = parsed.body.to_vec();
        if build.open(parsed.tag, &mut body).is_err() {
            return lost;
        }
        let Ok((CellCommand::Extended, reply)) = read_cell_body(&body) else {
            return lost;
        };
        let last = build.built().saturating_add(1) == HOPS;
        if !last {
            let Ok(ss_hop) = pending.finish(reply) else {
                return lost;
            };
            build.push(&ss_hop).map_err(|_| Error::NoPath)?;
            self.extend(build, rng)?;
            return Ok(Vec::new());
        }
        // NET-284: the session key of the circuit is the `er` of hop 3.
        let Ok((ss_hop, relay_session_pk)) = pending.finish_at_queue_relay(reply) else {
            return lost;
        };
        build.push(&ss_hop).map_err(|_| Error::NoPath)?;
        let circuit = build.finish().map_err(|_| Error::NoPath)?;
        self.circuit = Circuit::Ready(Box::new(CircuitSession::new(
            circuit,
            relay_session_pk,
            Range::Queue,
        )));
        Ok(alloc::vec![ClientEvent::CircuitReady])
    }

    fn on_events<R: CryptoRng + ?Sized>(
        &mut self,
        events: Vec<CircuitEvent>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let mut out = Vec::new();
        for event in events {
            match event {
                CircuitEvent::Answered {
                    handle,
                    cmd,
                    payload,
                } => match (self.waiting.remove(&handle), cmd) {
                    (Some(Waiting::Queue(keys)), Cmd::Ids) => {
                        out.extend(self.on_ids(*keys, &payload, rng)?);
                    }
                    // WIR-496: the QUOTA is the relay acknowledgment.
                    (Some(Waiting::UserSend(user)), Cmd::Quota) => {
                        out.push(ClientEvent::Accepted { handle: user });
                    }
                    _ => {}
                },
                CircuitEvent::Rejected { handle, reason } => {
                    let user = match self.waiting.remove(&handle) {
                        Some(Waiting::Queue(keys)) => keys.handle,
                        Some(Waiting::UserSend(user)) => user,
                        _ => handle,
                    };
                    out.push(ClientEvent::Rejected {
                        handle: user,
                        reason,
                    });
                }
                CircuitEvent::Message {
                    queue_id,
                    bucket,
                    payload,
                } => out.extend(self.on_message(queue_id, bucket, &payload, now, rng)?),
                CircuitEvent::Relay { .. } => {}
            }
        }
        self.pump()?;
        Ok(out)
    }

    /// The relay made a queue. The client subscribes to it, and then it
    /// issues the invitation or sends flight 1.
    fn on_ids<R: CryptoRng + ?Sized>(
        &mut self,
        keys: QueueKeys,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let ids = IdsPayload::parse(payload)?;
        let session_pk = self.session_pk()?;
        // NET-288.
        if ids.relay_session_pk != session_pk {
            return Err(Error::Unverified);
        }
        let queue_relay = self.relays.last().ok_or(Error::NoPath)?.relay_id;
        let own_address = || QueueAddress {
            relay_id: queue_relay,
            sender_id: ids.sender_id,
            qs_auth_sk: Secret::new(keys.qs_auth),
            qe: Secret::new(keys.queue_secret),
        };
        let inbound = Inbound::new(
            ids.recipient_id,
            ids.sender_id,
            keys.qr_auth,
            &Secret::new(keys.queue_secret),
            0,
        );
        let subscribe = inbound.subscribe(&session_pk, random(rng))?;
        self.queue_command(subscribe, Waiting::Other)?;
        let identity = self.root.pairwise_identity(&keys.salt);

        let mut out = Vec::new();
        let (setup, outbound, peer_static) = match keys.purpose {
            Purpose::Invite => {
                let (inviter, bundle) = Inviter::issue(&identity, own_address(), rng)?;
                out.push(ClientEvent::Invitation {
                    handle: keys.handle,
                    bundle,
                });
                (Setup::Inviting(Box::new(inviter)), None, [0u8; 32])
            }
            Purpose::Accept { bundle } => {
                let peer_static = Bundle::parse(&bundle)?.responder_static_x25519;
                let (invitee, flight1, to) = Invitee::accept(&bundle, &own_address(), rng)?;
                let outbound = Outbound::new(&to);
                let (_, encoded) = outbound.send_record(
                    L6Kind::Handshake,
                    &flight1,
                    &session_pk,
                    random(rng),
                    random(rng),
                )?;
                self.queue_command(encoded, Waiting::Other)?;
                (
                    Setup::Accepting(Box::new(invitee)),
                    Some(outbound),
                    peer_static,
                )
            }
        };
        self.halves.insert(
            ids.recipient_id,
            Half {
                identity,
                inbound,
                setup,
                outbound,
                peer_static,
            },
        );
        Ok(out)
    }

    fn on_message<R: CryptoRng + ?Sized>(
        &mut self,
        queue_id: [u8; 32],
        bucket: Bucket,
        payload: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        if let Some(channel) = self.contacts.get_mut(&queue_id) {
            return Ok(match channel.receive(payload, bucket, now, rng)? {
                Received::App { bytes, .. } => alloc::vec![ClientEvent::Message {
                    contact: ContactId(queue_id),
                    app: bytes,
                }],
                Received::Duplicate | Received::Undecryptable { .. } => Vec::new(),
            });
        }
        let Some(mut half) = self.halves.remove(&queue_id) else {
            return Ok(Vec::new());
        };
        let opened = half.inbound.open(payload, bucket, now)?;
        let Opened::Record {
            kind: L6Kind::Handshake,
            inner,
            ..
        } = opened
        else {
            self.halves.insert(queue_id, half);
            return Ok(Vec::new());
        };
        let session_pk = self.session_pk()?;
        // A flight that the device read needs no second delivery.
        if let Some((point, encoded)) = half.inbound.acknowledge(&session_pk, random(rng), now)? {
            half.inbound.acknowledged(point);
            self.queue_command(encoded, Waiting::Other)?;
        }
        let finished = match half.setup {
            Setup::Inviting(mut inviter) => match inner.first() {
                Some(1) => {
                    // A flight 1 that does not verify leaves the invitation
                    // spent, because its prekey served one try (`CRY-055`).
                    let Ok((flight2, reply_to)) = inviter.on_flight1(&half.identity, &inner, rng)
                    else {
                        return Ok(Vec::new());
                    };
                    let outbound = Outbound::new(reply_to);
                    let (_, encoded) = outbound.send_record(
                        L6Kind::Handshake,
                        &flight2,
                        &session_pk,
                        random(rng),
                        random(rng),
                    )?;
                    self.queue_command(encoded, Waiting::Other)?;
                    half.setup = Setup::Inviting(inviter);
                    self.halves.insert(queue_id, half);
                    return Ok(Vec::new());
                }
                _ => {
                    let Ok((keys, peer_static, reply_to)) = inviter.on_flight3(&inner) else {
                        return Ok(Vec::new());
                    };
                    // NET-175: the queue of the invitee is the outbound
                    // queue from this point.
                    (keys, peer_static, Outbound::new(&reply_to), Role::Responder)
                }
            },
            Setup::Accepting(invitee) => {
                let Ok((keys, flight3)) = invitee.on_flight2(&half.identity, &inner) else {
                    return Ok(Vec::new());
                };
                let outbound = half.outbound.take().ok_or(Error::NoPath)?;
                let (_, encoded) = outbound.send_record(
                    L6Kind::Handshake,
                    &flight3,
                    &session_pk,
                    random(rng),
                    random(rng),
                )?;
                self.queue_command(encoded, Waiting::Other)?;
                (keys, half.peer_static, outbound, Role::Initiator)
            }
        };
        let (keys, peer_static, outbound, role): (SessionKeys, [u8; 32], Outbound, Role) = finished;
        let ratchet = Ratchet::new(keys, role, Width::W64, now, rng)?;
        self.contacts.insert(
            queue_id,
            PairwiseChannel::new(ratchet, outbound, half.inbound),
        );
        Ok(alloc::vec![ClientEvent::ContactReady {
            contact: ContactId(queue_id),
            peer_static,
        }])
    }

    /// The relays of the circuit, for a runtime that dials the guard.
    pub fn guard(&self) -> RelayStatic {
        self.relays.first().map_or(
            RelayStatic {
                s: [0; 32],
                relay_id: [0; 32],
            },
            copy_static,
        )
    }
}
