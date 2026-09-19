//! One client as a state machine: the session link to its guard, the
//! build of one circuit through three relays, the queues that it makes,
//! the contact setup of [`super::contact`], and the pairwise channels.
//!
//! The node reads no clock, draws no random value, and opens no socket.
//! The runtime gives it each capsule that arrives and sends each capsule
//! that [`ClientNode::take_capsules`] returns.
//!
//! One circuit serves at most `MAX_QUEUES_PER_SESSION` inbound queues
//! (`NET-022`), thus the node builds one more circuit when each one is full,
//! and it divides the stored queues again at each run (`NET-024`). Each
//! circuit of this revision takes the one path that the caller gave. The
//! relay chains that differ (`NET-023`) come with the path selection of
//! Part 3 §3.4.6, which reads the relay directory.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use umbra_crypto::{
    handshake::{nk::RelayStatic, xk::SessionKeys},
    hierarchy::RootIdentity,
    kem::KeyPair,
    rand_core::CryptoRng,
    ratchet::{braid::Ratchet, codeword::Width, dr::Role},
    secret::Secret,
    stored::{Reader, Writer},
    x25519::StaticSecret,
    zeroize::Zeroizing,
};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::CircuitBuild,
    HOPS,
};
use umbra_queue::{params::MAX_QUEUES_PER_SESSION, Reject};
use umbra_transport::link::ClientLink;
use umbra_wire::{
    address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN},
    app::{AppKind, AppMessage, Channel},
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
    contact::{Invitee, Inviter, FLIGHT_1, FLIGHT_2},
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

/// One circuit, and the inbound queues that its session serves.
struct Slot {
    circuit: Circuit,
    queues: BTreeSet<[u8; 32]>,
    /// The `NEW` commands of this circuit that wait for their `IDS`.
    reserved: usize,
}

impl Slot {
    fn empty() -> Self {
        Slot {
            circuit: Circuit::None,
            queues: BTreeSet::new(),
            reserved: 0,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(self.circuit, Circuit::Ready(_))
    }

    fn has_room(&self) -> bool {
        self.queues.len().saturating_add(self.reserved) < MAX_QUEUES_PER_SESSION
    }

    fn circ_id(&self) -> Option<[u8; 16]> {
        match &self.circuit {
            Circuit::None => None,
            Circuit::Building { build, .. } => Some(build.circ_id()),
            Circuit::Ready(session) => Some(session.circ_id()),
        }
    }
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
    /// The circuit that carries the `NEW`.
    slot: usize,
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
    /// The salt of the pairwise identity (Part 5 §5.2).
    salt: [u8; 16],
    identity: KeyPair,
    inbound: Inbound,
    setup: Setup,
    outbound: Option<Outbound>,
    /// The static key of the inviter, which the bundle gave the invitee.
    peer_static: [u8; 32],
    /// The bundle of an invitation that this device issued.
    bundle: Vec<u8>,
    /// The encoded `QueueAddress` of an invitee, which goes again as its
    /// first ratchet record (`NET-292`). An inviter holds none.
    opening: Vec<u8>,
}

struct Contact {
    channel: PairwiseChannel,
    peer_static: [u8; 32],
    salt: [u8; 16],
    /// The records of the user that wait for the sending chain, each with
    /// its handle. An inviter holds no chain before the first record of
    /// the invitee arrives.
    waiting_sends: VecDeque<(Vec<u8>, u64)>,
}

/// A change of the state that a client keeps between two runs. The runtime
/// commits each change of one call before it writes a capsule of that call
/// to the link, and in one batch with the records that the call gave. A
/// record that left the device under a state that the store does not hold
/// would let a restart seal a second record under the same key.
pub enum StateChange {
    /// A contact is new, or its channel moved.
    Contact {
        /// The contact.
        contact: ContactId,
        /// The stored form, which holds each key of the channel.
        state: Zeroizing<Vec<u8>>,
    },
    /// An invitation waits for its flight 1.
    Invitation {
        /// The `RecipientId` of the queue of the invitation.
        queue: [u8; 32],
        /// The stored form, which holds the prekey.
        state: Zeroizing<Vec<u8>>,
    },
    /// An invitation ended: a flight 1 consumed its prekey.
    InvitationEnded {
        /// The `RecipientId` of the queue of the invitation.
        queue: [u8; 32],
    },
}

/// The version byte of a stored contact and of a stored invitation.
const STORED_VERSION: u8 = 0x01;

/// One client.
pub struct ClientNode {
    relays: [RelayStatic; HOPS],
    root: RootIdentity,
    link: Option<ClientLink>,
    slots: Vec<Slot>,
    /// The circuit of the call that runs. Each command of that call goes
    /// to it, under its `RelaySession_pk`.
    current: usize,
    /// The queues that wait for a circuit with room.
    deferred: VecDeque<(Purpose, u64)>,
    capsules: VecDeque<Vec<u8>>,
    next_handle: u64,
    waiting: BTreeMap<u64, Waiting>,
    /// The contacts whose handshake runs, by `RecipientId`.
    halves: BTreeMap<[u8; 32], Half>,
    contacts: BTreeMap<[u8; 32], Contact>,
    /// The contacts whose channel moved since the last
    /// [`ClientNode::take_changes`].
    moved: BTreeSet<[u8; 32]>,
    changes: Vec<StateChange>,
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
            slots: Vec::new(),
            current: 0,
            deferred: VecDeque::new(),
            capsules: VecDeque::new(),
            next_handle: 1,
            waiting: BTreeMap::new(),
            halves: BTreeMap::new(),
            contacts: BTreeMap::new(),
            moved: BTreeSet::new(),
            changes: Vec::new(),
        }
    }

    /// The changes of the state since the last call, for the store.
    pub fn take_changes(&mut self) -> Result<Vec<StateChange>, Error> {
        let mut changes = core::mem::take(&mut self.changes);
        for id in core::mem::take(&mut self.moved) {
            let Some(contact) = self.contacts.get(&id) else {
                continue;
            };
            let mut writer = Writer::new();
            writer.u8(STORED_VERSION);
            writer.bytes(&contact.salt);
            writer.bytes(&contact.peer_static);
            writer.var(&contact.channel.export()?)?;
            changes.push(StateChange::Contact {
                contact: ContactId(id),
                state: writer.finish(),
            });
        }
        Ok(changes)
    }

    /// Takes a contact of an earlier run from its stored form. The node
    /// subscribes to its queue when the circuit is ready.
    pub fn restore_contact(&mut self, state: &[u8]) -> Result<ContactId, Error> {
        let mut reader = Reader::new(state);
        if reader.u8()? != STORED_VERSION {
            return Err(Error::Malformed);
        }
        let salt = reader.array()?;
        let peer_static = reader.array()?;
        let channel = PairwiseChannel::restore(reader.var()?)?;
        reader.end()?;
        let id = *channel.inbound().recipient_id();
        self.assign(id);
        self.contacts.insert(
            id,
            Contact {
                channel,
                peer_static,
                salt,
                waiting_sends: VecDeque::new(),
            },
        );
        Ok(ContactId(id))
    }

    /// Takes an invitation of an earlier run from its stored form, and
    /// returns its bundle.
    pub fn restore_invitation(&mut self, state: &[u8]) -> Result<Vec<u8>, Error> {
        let mut reader = Reader::new(state);
        if reader.u8()? != STORED_VERSION {
            return Err(Error::Malformed);
        }
        let salt = reader.array()?;
        let bundle = reader.var()?.to_vec();
        let inbound = Inbound::restore(&mut reader)?;
        let inviter = Inviter::from_prekey_seed(Secret::new(reader.array()?));
        reader.end()?;
        self.assign(*inbound.recipient_id());
        self.halves.insert(
            *inbound.recipient_id(),
            Half {
                salt,
                identity: self.root.pairwise_identity(&salt),
                inbound,
                setup: Setup::Inviting(Box::new(inviter)),
                outbound: None,
                peer_static: [0; 32],
                bundle: bundle.clone(),
                opening: Vec::new(),
            },
        );
        Ok(bundle)
    }

    /// Records the stored form of an invitation that waits for flight 1.
    fn invitation_changed(&mut self, queue: [u8; 32], half: &Half) -> Result<(), Error> {
        let Setup::Inviting(inviter) = &half.setup else {
            return Ok(());
        };
        let Some(seed) = inviter.prekey_seed()? else {
            return Ok(());
        };
        let mut writer = Writer::new();
        writer.u8(STORED_VERSION);
        writer.bytes(&half.salt);
        writer.var(&half.bundle)?;
        half.inbound.export(&mut writer)?;
        writer.bytes(seed.expose());
        self.changes.push(StateChange::Invitation {
            queue,
            state: writer.finish(),
        });
        Ok(())
    }

    /// Gives a stored queue to a circuit with room, and adds a circuit when
    /// each one is full (`NET-022`). The division runs again at each run
    /// (`NET-024`), thus the store holds no circuit of a queue.
    fn assign(&mut self, queue: [u8; 32]) {
        let slot = match self.slots.iter_mut().find(|slot| slot.has_room()) {
            Some(slot) => slot,
            None => {
                self.slots.push(Slot::empty());
                match self.slots.last_mut() {
                    Some(slot) => slot,
                    None => return,
                }
            }
        };
        slot.queues.insert(queue);
    }

    /// Subscribes to each stored queue of the current circuit. The `ACK`
    /// of the last run can be lost with its link, thus it goes again
    /// (`IMP-134`).
    fn subscribe_stored<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let session_pk = self.session_pk()?;
        let queues = &self.slot()?.queues;
        let mut commands = Vec::new();
        let contacts = self
            .contacts
            .values()
            .map(|contact| contact.channel.inbound());
        let stored = contacts.chain(self.halves.values().map(|half| &half.inbound));
        for inbound in stored.filter(|inbound| queues.contains(inbound.recipient_id())) {
            commands.push(inbound.subscribe(&session_pk, random(rng))?);
            commands.extend(inbound.acknowledge_again(&session_pk, random(rng))?);
        }
        for command in commands {
            self.queue_command(command, Waiting::Other)?;
        }
        self.pump()
    }

    /// The capsules to write to the link, in order.
    pub fn take_capsules(&mut self) -> Vec<Vec<u8>> {
        self.capsules.drain(..).collect()
    }

    /// Whether a circuit holds its three hops.
    pub fn is_ready(&self) -> bool {
        self.slots.iter().any(Slot::is_ready)
    }

    fn slot(&self) -> Result<&Slot, Error> {
        self.slots.get(self.current).ok_or(Error::NoPath)
    }

    fn slot_mut(&mut self) -> Result<&mut Slot, Error> {
        self.slots.get_mut(self.current).ok_or(Error::NoPath)
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
        if self.slots.is_empty() {
            self.slots.push(Slot::empty());
        }
        // The builds run side by side, and the `circ_id` of a cell names
        // its circuit.
        for slot in 0..self.slots.len() {
            self.current = slot;
            self.extend(CircuitBuild::new(random(rng)), rng)?;
        }
        Ok(())
    }

    /// Adds one circuit, and starts its build.
    fn add_circuit<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.slots.push(Slot::empty());
        self.current = self.slots.len().saturating_sub(1);
        self.extend(CircuitBuild::new(random(rng)), rng)
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
        self.slot_mut()?.circuit = Circuit::Building {
            build: Box::new(build),
            pending: Box::new(pending),
        };
        self.send_cell(&cell)
    }

    /// Moves each ready command of each circuit into a cell.
    fn pump(&mut self) -> Result<(), Error> {
        for slot in 0..self.slots.len() {
            while let Some(cell) = self.next_cell_of(slot)? {
                self.send_cell(&cell)?;
            }
        }
        Ok(())
    }

    fn next_cell_of(&mut self, slot: usize) -> Result<Option<Vec<u8>>, Error> {
        match self.slots.get_mut(slot).map(|slot| &mut slot.circuit) {
            Some(Circuit::Ready(session)) => session.next_cell(),
            _ => Ok(None),
        }
    }

    /// Puts a command on the current circuit.
    fn queue_command(&mut self, encoded: Vec<u8>, waiting: Waiting) -> Result<u64, Error> {
        let handle = self.handle();
        let Circuit::Ready(session) = &mut self.slot_mut()?.circuit else {
            return Err(Error::NoPath);
        };
        session.queue(encoded, handle)?;
        self.waiting.insert(handle, waiting);
        Ok(handle)
    }

    /// `RelaySession_pk` of the current circuit.
    fn session_pk(&self) -> Result<[u8; 32], Error> {
        match &self.slot()?.circuit {
            Circuit::Ready(session) => Ok(*session.relay_session_pk()),
            _ => Err(Error::NoPath),
        }
    }

    /// Makes a queue on a circuit with room. With no such circuit the
    /// queue waits, and one more circuit starts (`NET-022`).
    fn make_queue<R: CryptoRng + ?Sized>(
        &mut self,
        purpose: Purpose,
        rng: &mut R,
    ) -> Result<u64, Error> {
        let user_handle = self.handle();
        let with_room = |slot: &Slot| slot.is_ready() && slot.has_room();
        let Some(slot) = self.slots.iter().position(with_room) else {
            self.deferred.push_back((purpose, user_handle));
            let is_building = |slot: &Slot| matches!(slot.circuit, Circuit::Building { .. });
            if !self.slots.iter().any(is_building) {
                self.add_circuit(rng)?;
            }
            return Ok(user_handle);
        };
        self.current = slot;
        self.make_queue_here(purpose, user_handle, rng)?;
        Ok(user_handle)
    }

    /// Sends the `NEW` of a queue on the current circuit.
    fn make_queue_here<R: CryptoRng + ?Sized>(
        &mut self,
        purpose: Purpose,
        user_handle: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
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
            slot: self.current,
        };
        self.queue_command(encoded, Waiting::Queue(Box::new(keys)))?;
        let slot = self.slot_mut()?;
        slot.reserved = slot.reserved.saturating_add(1);
        self.pump()
    }

    /// The circuit that serves an inbound queue.
    fn slot_of(&self, queue: &[u8; 32]) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.queues.contains(queue))
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
        Invitee::check(&bundle)?;
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
        let user_handle = self.handle();
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        if !held.channel.can_send() {
            // The first record of the invitee opens the chain (`NET-292`).
            held.waiting_sends.push_back((app.to_vec(), user_handle));
            return Ok(user_handle);
        }
        self.send_now(contact.0, app, Waiting::UserSend(user_handle), now, rng)?;
        Ok(user_handle)
    }

    /// Seals one application record for a contact and puts its `SEND` on a
    /// circuit.
    fn send_now<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        app: &[u8],
        waiting: Waiting,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // A `SEND` binds no queue to a session. It goes on a circuit that
        // does not serve the inbound queue of the contact when one is
        // ready, thus one session shows a relay one queue of the pair.
        let inbound = self.slot_of(&contact);
        let ready = |(index, slot): (usize, &Slot)| slot.is_ready().then_some(index);
        let mut candidates = self.slots.iter().enumerate().filter_map(ready);
        let other = candidates.clone().find(|index| Some(*index) != inbound);
        self.current = other.or_else(|| candidates.next()).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
        let (_, encoded) =
            held.channel
                .send(app, &session_pk, random(rng), random(rng), now, rng)?;
        self.moved.insert(contact);
        self.queue_command(encoded, waiting)?;
        self.pump()
    }

    /// Acknowledges each record of a contact that the runtime committed.
    pub fn acknowledge<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &ContactId,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // The `ACK` goes to the session that serves the queue.
        self.current = self.slot_of(&contact.0).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        let channel = &mut held.channel;
        if let Some((point, encoded)) = channel.acknowledge(&session_pk, random(rng), now)? {
            channel.acknowledged(point);
            self.moved.insert(contact.0);
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
        // The `circ_id` of the cell names its circuit. A cell of no circuit
        // of this node drops.
        let circ_id = cell.get(..16);
        let of_cell = |slot: &Slot| slot.circ_id().as_ref().map(<[u8; 16]>::as_slice) == circ_id;
        let Some(index) = self.slots.iter().position(of_cell) else {
            return Ok(Vec::new());
        };
        self.current = index;
        let circuit = core::mem::replace(&mut self.slot_mut()?.circuit, Circuit::None);
        match circuit {
            Circuit::None => Ok(Vec::new()),
            Circuit::Building { build, pending } => {
                self.on_build_cell(*build, *pending, &cell, rng)
            }
            Circuit::Ready(mut session) => {
                let received = session.receive_cell(&cell);
                self.slot_mut()?.circuit = Circuit::Ready(session);
                match received {
                    Ok(events) => self.on_events(events, now, rng),
                    // NET-115: a failed check ends the circuit.
                    Err(_) => {
                        self.slot_mut()?.circuit = Circuit::None;
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
        self.slot_mut()?.circuit = Circuit::Ready(Box::new(CircuitSession::new(
            circuit,
            relay_session_pk,
            Range::Queue,
        )));
        let ready = self.current;
        self.subscribe_stored(rng)?;
        // Each queue that waited for room goes to this circuit.
        while self.slot()?.has_room() {
            let Some((purpose, user_handle)) = self.deferred.pop_front() else {
                break;
            };
            self.make_queue_here(purpose, user_handle, rng)?;
        }
        if !self.deferred.is_empty() {
            self.add_circuit(rng)?;
        }
        // The runtime learns of the first circuit, which takes its commands.
        let is_first = !self
            .slots
            .iter()
            .enumerate()
            .any(|(index, slot)| index != ready && slot.is_ready());
        Ok(if is_first {
            alloc::vec![ClientEvent::CircuitReady]
        } else {
            Vec::new()
        })
    }

    fn on_events<R: CryptoRng + ?Sized>(
        &mut self,
        events: Vec<CircuitEvent>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let mut out = Vec::new();
        let arrival = self.current;
        for event in events {
            // A reply to one event can go to a second circuit. The next
            // event belongs to the circuit of the cell again.
            self.current = arrival;
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
                        Some(Waiting::Queue(keys)) => {
                            if let Some(slot) = self.slots.get_mut(keys.slot) {
                                slot.reserved = slot.reserved.saturating_sub(1);
                            }
                            keys.handle
                        }
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
        // The session of the circuit serves the queue from its `NEW`.
        if let Some(slot) = self.slots.get_mut(keys.slot) {
            slot.reserved = slot.reserved.saturating_sub(1);
            slot.queues.insert(ids.recipient_id);
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
        let mut opening = Vec::new();
        let (setup, outbound, peer_static, issued) = match keys.purpose {
            Purpose::Invite => {
                let (inviter, bundle) = Inviter::issue(&identity, own_address(), rng)?;
                out.push(ClientEvent::Invitation {
                    handle: keys.handle,
                    bundle: bundle.clone(),
                });
                (Setup::Inviting(Box::new(inviter)), None, [0u8; 32], bundle)
            }
            Purpose::Accept { bundle } => {
                opening = alloc::vec![0u8; QUEUE_ADDRESS_LEN];
                own_address().encode(&mut opening)?;
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
                    Vec::new(),
                )
            }
        };
        let half = Half {
            salt: keys.salt,
            identity,
            inbound,
            setup,
            outbound,
            peer_static,
            bundle: issued,
            opening,
        };
        self.invitation_changed(ids.recipient_id, &half)?;
        self.halves.insert(ids.recipient_id, half);
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
        if let Some(held) = self.contacts.get_mut(&queue_id) {
            // Each outcome moves the cursor of the queue.
            self.moved.insert(queue_id);
            let mut out = Vec::new();
            if let Received::App { bytes, .. } = held.channel.receive(payload, bucket, now, rng)? {
                let address = AppMessage::parse(&bytes, Channel::Pairwise)
                    .ok()
                    .filter(|parsed| parsed.kind == AppKind::QueueAddress)
                    .map(|parsed| QueueAddress::parse(parsed.body));
                match address {
                    // NET-179, WIR-330: the receiving chain gave the address.
                    Some(Ok(address)) => held.channel.accept_address(&address),
                    Some(Err(_)) => {}
                    None => out.push(ClientEvent::Message {
                        contact: ContactId(queue_id),
                        app: bytes,
                    }),
                }
            }
            // The record opened the sending chain of an inviter.
            let waiting = if held.channel.can_send() {
                core::mem::take(&mut held.waiting_sends)
            } else {
                VecDeque::new()
            };
            for (app, user_handle) in waiting {
                self.send_now(queue_id, &app, Waiting::UserSend(user_handle), now, rng)?;
            }
            return Ok(out);
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
            // The cursor of the queue moved.
            self.invitation_changed(queue_id, &half)?;
            self.halves.insert(queue_id, half);
            return Ok(Vec::new());
        };
        // WIR-503: a flight with a number that the queue does not wait for
        // ends no handshake. A second holder of the bundle makes such a
        // flight 1.
        let awaited = match &half.setup {
            Setup::Inviting(inviter) => inviter.awaits(),
            Setup::Accepting(_) => FLIGHT_2,
        };
        let session_pk = self.session_pk()?;
        // A flight that the device read needs no second delivery.
        if let Some((point, encoded)) = half.inbound.acknowledge(&session_pk, random(rng), now)? {
            half.inbound.acknowledged(point);
            self.queue_command(encoded, Waiting::Other)?;
        }
        if inner.first() != Some(&awaited) {
            self.invitation_changed(queue_id, &half)?;
            self.halves.insert(queue_id, half);
            return Ok(Vec::new());
        }
        let finished = match half.setup {
            Setup::Inviting(mut inviter) => match awaited {
                FLIGHT_1 => {
                    let Ok((flight2, reply_to)) = inviter.on_flight1(&half.identity, &inner, rng)
                    else {
                        // A flight 1 that names the prekey and does not
                        // verify spends it (`CRY-089`), and the invitation
                        // ends. A flight that names a second prekey spends
                        // nothing.
                        if inviter.awaits() == FLIGHT_1 {
                            half.setup = Setup::Inviting(inviter);
                            self.invitation_changed(queue_id, &half)?;
                            self.halves.insert(queue_id, half);
                        } else {
                            self.changes
                                .push(StateChange::InvitationEnded { queue: queue_id });
                        }
                        return Ok(Vec::new());
                    };
                    // The prekey served, thus the stored invitation ends. A
                    // handshake between its flight 1 and its flight 3 has
                    // no stored form.
                    self.changes
                        .push(StateChange::InvitationEnded { queue: queue_id });
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
            Contact {
                channel: PairwiseChannel::new(ratchet, outbound, half.inbound),
                peer_static,
                salt: half.salt,
                waiting_sends: VecDeque::new(),
            },
        );
        self.moved.insert(queue_id);
        if !half.opening.is_empty() {
            // NET-292: the first ratchet record of the invitee opens the
            // sending chain of the inviter, and it gives the address of
            // flight 1 again under the complete session.
            let record = AppMessage {
                kind: AppKind::QueueAddress,
                msg_id: random(rng),
                sent_at: now.saturating_mul(1_000),
                body: &half.opening,
            };
            let mut app = alloc::vec![0u8; record.len()];
            record.encode(&mut app)?;
            self.send_now(queue_id, &app, Waiting::Other, now, rng)?;
        }
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
