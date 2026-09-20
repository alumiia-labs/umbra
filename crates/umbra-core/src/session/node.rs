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
    auth::CommandAuthKey,
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
    admission::Admission,
    app::{AppKind, AppMessage, Channel},
    bucket::Bucket,
    capsule,
    cell::{Cell, CellCommand},
    command::{iblob_parse, Cmd, Command, IdsPayload, LINK_ID_LEN},
    queue::L6Kind,
};

use super::{
    batch::Range,
    channel::{
        get_blob_command, new_queue_command, Inbound, Opened, Outbound, PairwiseChannel, Received,
        Sealed,
    },
    circuit::{CircuitSession, Event as CircuitEvent},
    contact::{Invitee, Inviter, FLIGHT_1, FLIGHT_2},
};
use crate::{
    attach::{
        command::{ChunkCmd, CrepPayload, RegisterPayload, ReplicaTarget, PROOF_LEN, TOKEN_LEN},
        seal::{self, relay_hint},
        CHUNK_SIZE,
    },
    directory::{
        bloc::BlocId,
        path::{select, Candidate},
    },
    identity::{
        invitation::{Bundle, Fragment, FRAGMENT_LEN},
        verify::Ceremony,
    },
    Error,
};

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
    /// The relay holds the blob of an invitation. The user gives the link
    /// of this fragment to the other party (Part 4 §4.3.1).
    InvitationLink {
        /// The handle of the call that asked for it.
        handle: u64,
        /// The 68 bytes of the fragment.
        fragment: Vec<u8>,
    },
    /// The relay holds no blob for a link: a second party fetched it
    /// first, it passed `INVITE_TTL`, or it does not open under the link.
    /// The user learns it, because a fetch by a second party is an attack
    /// that the two parties detect (`IDN-023`).
    InvitationGone {
        /// The handle of the call that gave the link.
        handle: u64,
    },
    /// The two nonces of a verification ceremony are here, and the two
    /// users compare this code (Part 4 §4.5.2). The code alone verifies
    /// nothing (`IDN-148`).
    VerificationCode {
        /// The contact.
        contact: ContactId,
        /// The six-digit code.
        code: u32,
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
    /// The answer to a chunk command of [`ClientNode::chunk`].
    Chunk {
        /// The handle of the call.
        handle: u64,
        /// What the relay did.
        outcome: ChunkOutcome,
    },
    /// The circuit failed its check or its build, and the runtime builds a
    /// new one.
    CircuitLost,
}

/// One chunk command of Part 13 §13.3.3 for one relay.
pub enum ChunkJob {
    /// `CNEW`, or `BNEW` for a chunk of the backup class.
    Register {
        /// `cred_sk` of the chunk (`ATT-034`).
        cred: StaticSecret,
        /// The public half of `read_sk` (`ATT-037`).
        read_pk: [u8; 32],
        /// Whether the chunk is of the backup class (`ATT-131`).
        is_backup: bool,
    },
    /// `CPUT`.
    Put {
        /// `cred_sk` of the chunk.
        cred: StaticSecret,
        /// The token that the `CID` of this relay gave (`ATT-042`).
        storage_token: [u8; TOKEN_LEN],
        /// The chunk, `CHUNK_SIZE` bytes.
        chunk: Vec<u8>,
    },
    /// `CREP`, to the relay that took the `CPUT` (`ATT-098`).
    Replicate {
        /// `cred_sk` of the chunk.
        cred: StaticSecret,
        /// Each other replica relay with its token (`ATT-100`).
        targets: Vec<ReplicaTarget>,
        /// The chunk, for the proof of the answer (`ATT-188`).
        chunk: Vec<u8>,
    },
    /// `CVFY`. The node draws the nonce (`ATT-114`).
    Verify {
        /// `cred_sk` of the chunk.
        cred: StaticSecret,
        /// The chunk, for the proof that the relay must give (`ATT-117`).
        chunk: Vec<u8>,
    },
    /// `CGET`.
    Fetch {
        /// `read_sk` of the chunk.
        read: StaticSecret,
    },
    /// `CRNW`. It has no answer (`ATT-126`), thus no event follows.
    Renew {
        /// `read_sk` of the chunk.
        read: StaticSecret,
    },
    /// `CDEL`.
    Erase {
        /// `cred_sk` of the chunk.
        cred: StaticSecret,
    },
}

/// What a relay did with a chunk command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// The relay registered the chunk, and this is its `storage_token`.
    Registered([u8; TOKEN_LEN]),
    /// The relay holds the bytes of the `CPUT`, and its proof is right.
    Stored,
    /// The relay took the `CREP`, and its proof is right.
    Replicated,
    /// The proof of a `CVFY` is right.
    Verified,
    /// The chunk of a `CGET`. The caller opens it under the file key.
    Fetched(Vec<u8>),
    /// The relay erased the chunk.
    Erased,
    /// The proof of the relay differs from the one of this device
    /// (`ATT-118`, `ATT-188`).
    WrongProof,
    /// The relay refused the command. `WIR-317` gives one reason for an
    /// unknown chunk and for a wrong credential.
    Refused(Reject),
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
    /// The relay at which the chain must end, for a circuit that serves a
    /// queue of a known relay. A circuit with none ends at each relay of
    /// layer 3.
    exit: Option<[u8; 32]>,
    /// The three relays of the chain, from the first build of this run.
    chain: Option<[[u8; 32]; HOPS]>,
}

/// A relay that a client can put into a chain: the facts that the
/// invariants of Part 3 §3.4.6 test, and the static key of the handshake.
pub struct RelayInfo {
    /// The facts of the directory entry.
    pub candidate: Candidate,
    /// The static key and the identifier.
    pub key: RelayStatic,
}

/// The relay of a stored queue whose form names none. Such a queue comes
/// from a store of version `0x01`, and it goes to each exit.
const ANY_RELAY: [u8; 32] = [0; 32];

impl Slot {
    fn empty(exit: Option<[u8; 32]>) -> Self {
        Slot {
            circuit: Circuit::None,
            queues: BTreeSet::new(),
            reserved: 0,
            exit,
            chain: None,
        }
    }

    /// Whether this circuit can serve a queue at `relay`.
    fn ends_at(&self, relay: &[u8; 32]) -> bool {
        match (self.chain, self.exit) {
            _ if *relay == ANY_RELAY => true,
            (Some(chain), _) => chain.last() == Some(relay),
            (None, Some(exit)) => exit == *relay,
            (None, None) => true,
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

/// Reads the answer to a chunk command against what the command expects.
fn chunk_outcome(expect: ChunkExpect, cmd: u8, payload: Vec<u8>) -> ChunkOutcome {
    let refused = ChunkOutcome::Refused(Reject::Rejected);
    match (expect, ChunkCmd::from_byte(cmd)) {
        (ChunkExpect::Token, Ok(ChunkCmd::Cid)) => payload
            .as_slice()
            .try_into()
            .map_or(refused, ChunkOutcome::Registered),
        (ChunkExpect::Proof(proof, outcome), Ok(ChunkCmd::Cprf)) => {
            if umbra_crypto::ct_eq(&proof, &payload) {
                outcome
            } else {
                ChunkOutcome::WrongProof
            }
        }
        (ChunkExpect::Data, Ok(ChunkCmd::Cdat)) if payload.len() == CHUNK_SIZE => {
            ChunkOutcome::Fetched(payload)
        }
        _ => refused,
    }
}

/// A link that the user accepted, before its first fetch.
struct LinkFetch {
    fragment: Fragment,
    /// The relay that holds the blob.
    relay: [u8; 32],
    /// The handle of the caller.
    handle: u64,
}

/// Why the client made a queue.
enum Purpose {
    /// The bundle goes to the caller.
    Invite,
    /// The bundle goes to the relay as a blob, and a link goes to the
    /// caller.
    InviteLink,
    Accept {
        bundle: Vec<u8>,
        /// The lock key of the first fetch, which writes to the queue of
        /// the inviter in the place of the `QS_auth` of the bundle.
        lock: Option<[u8; 32]>,
    },
}

/// The fetch of a blob between its `IGET` and its `IBLOB`.
struct BlobWait {
    fragment: Fragment,
    lock: [u8; 32],
    handle: u64,
}

/// The store of a blob between the `IDS` of its queue and the second
/// `ILINK`.
struct LinkSetup {
    handle: u64,
    fragment: Option<Fragment>,
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
/// What the answer to a chunk command must hold.
enum ChunkExpect {
    Token,
    /// A `CPRF` with this proof, and the outcome of a right one.
    Proof([u8; PROOF_LEN], ChunkOutcome),
    Data,
}

struct ChunkWait {
    /// The handle of the caller.
    handle: u64,
    expect: ChunkExpect,
}

/// A chunk command that waits for a circuit to its relay.
struct HeldChunk {
    relay: [u8; 32],
    chunk_id: [u8; 32],
    handle: u64,
    job: ChunkJob,
}

enum Waiting {
    Chunk(Box<ChunkWait>),
    Queue(Box<QueueKeys>),
    UserSend(u64),
    /// An `IRES` or an `IPUT` of the invitation on this queue.
    Link([u8; 32]),
    Blob(Box<BlobWait>),
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
    /// The store of the blob, while it runs.
    link: Option<LinkSetup>,
    /// The relay of the inbound queue.
    inbound_relay: [u8; 32],
}

struct Contact {
    channel: PairwiseChannel,
    /// The relay of the inbound queue. The channel stores the relay of the
    /// outbound one.
    inbound_relay: [u8; 32],
    peer_static: [u8; 32],
    salt: [u8; 16],
    /// The records of the user that wait for the sending chain, each with
    /// its handle. An inviter holds no chain before the first record of
    /// the invitee arrives.
    waiting_sends: VecDeque<(Vec<u8>, Option<u64>)>,
    /// The verification ceremony of this run. A ceremony has no stored
    /// form, because its nonce serves one comparison (`IDN-145`).
    ceremony: Option<Ceremony>,
}

/// The two pairwise identity keys of a stored contact: the key of this
/// device and the key of the peer. The safety number and the verification
/// state rest on them, and they need no network and no node.
pub fn stored_contact_keys(
    state: &[u8],
    root: &RootIdentity,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let mut reader = Reader::new(state);
    stored_version(&mut reader)?;
    let salt: [u8; 16] = reader.array()?;
    let peer_static: [u8; 32] = reader.array()?;
    Ok((root.pairwise_identity(&salt).x25519_public(), peer_static))
}

/// Reads the version byte of a stored form, and says whether the form names
/// the relay of its inbound queue. Version `0x01` names none.
fn stored_version(reader: &mut Reader<'_>) -> Result<bool, Error> {
    match reader.u8()? {
        STORED_VERSION => Ok(true),
        0x01 => Ok(false),
        _ => Err(Error::Malformed),
    }
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

/// What one slot of the cover clock carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverSlot {
    /// An `ACK` that was due.
    Acknowledgment,
    /// The batch of receipts that the caller gave.
    Receipt,
    /// A loop cell, which comes back and measures the path (`NET-060`).
    Loop,
    /// A `COVER` command.
    Cover,
    /// No cell: the client is in the background, or no circuit is ready.
    Nothing,
}

/// A loop is a cover cell with a first random byte below this value, which
/// is about 20 % of the cells (`NET-063`).
const LOOP_SHARE: u8 = 51;

/// The version byte of a stored contact and of a stored invitation.
const STORED_VERSION: u8 = 0x02;

/// One client.
pub struct ClientNode {
    /// The pinned ingress relay, which is hop 1 of each chain.
    ingress: RelayInfo,
    /// The relays of layer 2 and of layer 3.
    relays: Vec<RelayInfo>,
    root: RootIdentity,
    link: Option<ClientLink>,
    slots: Vec<Slot>,
    /// The circuit of the call that runs. Each command of that call goes
    /// to it, under its `RelaySession_pk`.
    current: usize,
    /// The queues that wait for a circuit with room.
    deferred: VecDeque<(Purpose, u64)>,
    /// The handshake records that wait for a circuit to the relay of their
    /// queue.
    held_records: Vec<Sealed>,
    /// The links that wait for a circuit to the relay of their blob.
    held_fetches: Vec<LinkFetch>,
    /// The chunk commands that wait for a circuit to their relay.
    held_chunks: Vec<HeldChunk>,
    /// The range of each circuit of this node (`WIR-309`). A node for
    /// attachments carries no queue command (Part 13 §13.8).
    range: Range,
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

/// `ClientNode::new` takes an array of three, thus this path never runs. It
/// gives a node with no relay, which builds no chain, in the place of a
/// panic.
fn unreachable_ingress(root: RootIdentity) -> ClientNode {
    let nowhere = RelayInfo {
        candidate: Candidate {
            relay_id: ANY_RELAY,
            operator_id: ANY_RELAY,
            family_id: ANY_RELAY,
            bloc: BlocId::Own([0; 2]),
            asn: 0,
            v4_prefix: None,
            v6_prefix: None,
            ingress: false,
            chain: false,
            queue: false,
            layer: 0,
        },
        key: RelayStatic {
            s: [0; 32],
            relay_id: ANY_RELAY,
        },
    };
    ClientNode::with_relays(nowhere, Vec::new(), root)
}

fn copy_static(relay: &RelayStatic) -> RelayStatic {
    RelayStatic {
        s: relay.s,
        relay_id: relay.relay_id,
    }
}

impl ClientNode {
    /// A client with one chain: `relays`, hop 1 first. The three count as
    /// three operators in three blocs, thus the chain obeys each invariant.
    /// Each pairwise identity comes from `root` (Part 5 §5.2).
    pub fn new(relays: [RelayStatic; HOPS], root: RootIdentity) -> Self {
        let mut infos = relays.into_iter().zip(1u8..).map(|(key, layer)| RelayInfo {
            candidate: Candidate {
                relay_id: key.relay_id,
                operator_id: key.relay_id,
                family_id: key.relay_id,
                bloc: BlocId::Own([b'A', layer]),
                asn: u32::from(layer),
                v4_prefix: None,
                v6_prefix: None,
                ingress: layer == 1,
                chain: layer != 1,
                queue: layer == 3,
                layer,
            },
            key,
        });
        let ingress = infos.next();
        let rest = infos.collect();
        // The array holds three relays, thus the first one is there.
        match ingress {
            Some(ingress) => Self::with_relays(ingress, rest, root),
            None => unreachable_ingress(root),
        }
    }

    /// A client that builds each chain from `ingress` and two of `relays`
    /// under the invariants of Part 3 §3.4.6. The caller gives the relays of
    /// a verified directory.
    pub fn with_relays(ingress: RelayInfo, relays: Vec<RelayInfo>, root: RootIdentity) -> Self {
        ClientNode {
            ingress,
            relays,
            root,
            link: None,
            slots: Vec::new(),
            current: 0,
            deferred: VecDeque::new(),
            held_records: Vec::new(),
            held_fetches: Vec::new(),
            held_chunks: Vec::new(),
            range: Range::Queue,
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
            writer.bytes(&contact.inbound_relay);
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
        let names_relay = stored_version(&mut reader)?;
        let salt = reader.array()?;
        let peer_static = reader.array()?;
        let inbound_relay = if names_relay {
            reader.array()?
        } else {
            ANY_RELAY
        };
        let channel = PairwiseChannel::restore(reader.var()?)?;
        reader.end()?;
        // A store of version 0x01 came from a network with one queue relay,
        // thus the two queues of its contact live at one relay, and the
        // channel names the relay of the outbound one.
        let inbound_relay = if names_relay {
            inbound_relay
        } else {
            *channel.outbound().relay_id()
        };
        let id = *channel.inbound().recipient_id();
        self.assign(id, inbound_relay);
        self.contacts.insert(
            id,
            Contact {
                channel,
                inbound_relay,
                peer_static,
                salt,
                waiting_sends: VecDeque::new(),
                ceremony: None,
            },
        );
        Ok(ContactId(id))
    }

    /// Takes an invitation of an earlier run from its stored form, and
    /// returns its bundle.
    pub fn restore_invitation(&mut self, state: &[u8]) -> Result<Vec<u8>, Error> {
        let mut reader = Reader::new(state);
        let names_relay = stored_version(&mut reader)?;
        let salt = reader.array()?;
        let inbound_relay = if names_relay {
            reader.array()?
        } else {
            ANY_RELAY
        };
        let bundle = reader.var()?.to_vec();
        let inbound = Inbound::restore(&mut reader)?;
        let inviter = Inviter::from_prekey_seed(Secret::new(reader.array()?));
        reader.end()?;
        // The bundle of an invitation names the relay of its queue.
        let inbound_relay = if names_relay {
            inbound_relay
        } else {
            Bundle::parse(&bundle)?.queue_address.relay_id
        };
        self.assign(*inbound.recipient_id(), inbound_relay);
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
                link: None,
                inbound_relay,
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
        writer.bytes(&half.inbound_relay);
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
    fn assign(&mut self, queue: [u8; 32], relay: [u8; 32]) {
        let serves = |slot: &&mut Slot| slot.has_room() && slot.ends_at(&relay);
        let slot = match self.slots.iter_mut().find(serves) {
            Some(slot) => slot,
            None => {
                self.slots.push(Slot::empty(None));
                match self.slots.last_mut() {
                    Some(slot) => slot,
                    None => return,
                }
            }
        };
        // The chain of this circuit ends at the relay of its queues.
        if relay != ANY_RELAY {
            slot.exit = Some(relay);
        }
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
            self.slots.push(Slot::empty(None));
        }
        // A new run builds each chain again (`NET-024`). The builds run side
        // by side, and the `circ_id` of a cell names its circuit.
        for slot in &mut self.slots {
            slot.chain = None;
        }
        let mut built = 0usize;
        for slot in 0..self.slots.len() {
            self.current = slot;
            // A circuit to a relay that left the relay set, or to one that
            // no conformant chain reaches, builds nothing (`NET-033`). Its
            // queues are out of reach in this run. That must not end the
            // run, because each other circuit serves its own contacts.
            if self.choose_chain(rng).is_err() {
                continue;
            }
            self.extend(CircuitBuild::new(random(rng)), rng)?;
            built = built.saturating_add(1);
        }
        if built > 0 {
            return Ok(());
        }
        // With no circuit the client cannot make a queue for a new contact,
        // thus it builds one that can end at each relay. A circuit of that
        // kind that found no chain above finds none now.
        if self.slots.iter().any(|slot| slot.exit.is_none()) {
            return Err(Error::NoPath);
        }
        self.add_circuit(None, rng)?;
        match self.slot()?.chain {
            Some(_) => Ok(()),
            None => Err(Error::NoPath),
        }
    }

    /// Adds one circuit, and starts its build. `exit` is the relay at which
    /// the chain must end, or none.
    fn add_circuit<R: CryptoRng + ?Sized>(
        &mut self,
        exit: Option<[u8; 32]>,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.slots.push(Slot::empty(exit));
        self.current = self.slots.len().saturating_sub(1);
        // With no conformant chain the circuit stays with no build, and
        // what waits for it waits (`NET-033`). The slot stays, thus a later
        // call for the same relay does not select again in this run.
        if self.choose_chain(rng).is_err() {
            return Ok(());
        }
        self.extend(CircuitBuild::new(random(rng)), rng)
    }

    /// Gives the current circuit its chain (Part 3 §3.4.6): the pinned
    /// ingress, then one relay of layer 2, then one of layer 3, under each
    /// invariant. The order of the candidates is random, and a relay that
    /// no other circuit of this client uses comes first, thus the circuits
    /// take chains that differ where the relay set permits it (`NET-023`).
    /// With no conformant chain the build fails closed (`NET-033`).
    fn choose_chain<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let exit = self.slot()?.exit;
        let uses = |relay: &[u8; 32]| {
            self.slots
                .iter()
                .filter_map(|slot| slot.chain)
                .filter(|chain| chain.contains(relay))
                .count()
        };
        let mut order: Vec<(usize, u32, Candidate)> = self
            .relays
            .iter()
            .map(|relay| relay.candidate)
            .filter(|candidate| {
                !candidate.is_exit() || exit.is_none_or(|exit| exit == candidate.relay_id)
            })
            .map(|candidate| {
                let draw = u32::from_be_bytes(random(rng));
                (uses(&candidate.relay_id), draw, candidate)
            })
            .collect();
        order.sort_by_key(|(used, draw, _)| (*used, *draw));
        let candidates: Vec<Candidate> = order.into_iter().map(|(_, _, c)| c).collect();
        let chain = select(&self.ingress.candidate, &candidates)?;
        self.slot_mut()?.chain = Some(chain.hops);
        Ok(())
    }

    /// A circuit that holds its three hops and ends at `relay`. One that
    /// does not serve `avoid` comes first, thus one session shows a relay
    /// one queue of a pair where the circuits permit it.
    fn ready_slot_to(&self, relay: &[u8; 32], avoid: Option<usize>) -> Option<usize> {
        let ends_here = |(index, slot): (usize, &Slot)| {
            let exit = slot.chain.and_then(|chain| chain.last().copied());
            (slot.is_ready() && exit == Some(*relay)).then_some(index)
        };
        let mut found = self.slots.iter().enumerate().filter_map(ends_here);
        let other = found.clone().find(|index| Some(*index) != avoid);
        other.or_else(|| found.next())
    }

    /// Starts a circuit that ends at `relay`, when no circuit of this client
    /// ends there or will end there.
    fn circuit_to<R: CryptoRng + ?Sized>(
        &mut self,
        relay: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let ends_there = |slot: &Slot| match slot.chain {
            Some(chain) => chain.last() == Some(&relay),
            None => slot.exit == Some(relay),
        };
        if self.slots.iter().any(ends_there) {
            return Ok(());
        }
        let current = self.current;
        let started = self.add_circuit(Some(relay), rng);
        self.current = current;
        started
    }

    /// Sends a sealed handshake record on a circuit that ends at the relay
    /// of its queue. With no such circuit the record waits, and the circuit
    /// starts.
    fn send_sealed<R: CryptoRng + ?Sized>(
        &mut self,
        sealed: Sealed,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(slot) = self.ready_slot_to(sealed.relay_id(), None) else {
            let relay = *sealed.relay_id();
            self.held_records.push(sealed);
            return self.circuit_to(relay, rng);
        };
        let current = self.current;
        self.current = slot;
        let sent = self
            .session_pk()
            .and_then(|session_pk| sealed.sign(&session_pk, random(rng)))
            .and_then(|encoded| self.queue_command(encoded, Waiting::Other));
        self.current = current;
        sent?;
        self.pump()
    }

    /// The static key of a relay of the set.
    fn key_of(&self, relay_id: &[u8; 32]) -> Option<&RelayStatic> {
        core::iter::once(&self.ingress)
            .chain(&self.relays)
            .map(|relay| &relay.key)
            .find(|key| key.relay_id == *relay_id)
    }

    /// The relay at the end of the chain of a circuit, which holds its queues.
    fn exit_of(&self, slot: usize) -> Result<[u8; 32], Error> {
        let chain = self.slots.get(slot).and_then(|slot| slot.chain);
        chain
            .and_then(|chain| chain.last().copied())
            .ok_or(Error::NoPath)
    }

    /// Sends the `EXTEND` cell for the next hop of `build`.
    fn extend<R: CryptoRng + ?Sized>(
        &mut self,
        mut build: CircuitBuild,
        rng: &mut R,
    ) -> Result<(), Error> {
        let chain = self.slot()?.chain.ok_or(Error::NoPath)?;
        let hop = chain.get(build.built()).ok_or(Error::NoPath)?;
        let relay = self.key_of(hop).ok_or(Error::NoPath)?;
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
        if session.queue(encoded, handle)? {
            self.waiting.insert(handle, waiting);
        }
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
                self.add_circuit(None, rng)?;
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

    /// Starts one invitation with a link (Part 4 §4.3.1). The relay holds
    /// the sealed bundle, and a [`ClientEvent::InvitationLink`] with the
    /// same handle carries the fragment of the link.
    pub fn invite_link<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<u64, Error> {
        self.make_queue(Purpose::InviteLink, rng)
    }

    /// Accepts the bundle of an inviter. A [`ClientEvent::ContactReady`]
    /// follows after flight 2 arrives.
    pub fn accept<R: CryptoRng + ?Sized>(
        &mut self,
        bundle: Vec<u8>,
        rng: &mut R,
    ) -> Result<u64, Error> {
        Invitee::check(&bundle)?;
        self.make_queue(Purpose::Accept { bundle, lock: None }, rng)
    }

    /// Accepts the link of an inviter, by the 68 bytes of its fragment. The
    /// node makes the first fetch of the blob, which locks the queue of the
    /// inviter to a key of this device (`IDN-023`). A
    /// [`ClientEvent::ContactReady`] follows, or a
    /// [`ClientEvent::InvitationGone`] with the same handle.
    pub fn accept_link<R: CryptoRng + ?Sized>(
        &mut self,
        fragment: &[u8],
        rng: &mut R,
    ) -> Result<u64, Error> {
        let bytes: &[u8; FRAGMENT_LEN] = fragment.try_into().map_err(|_| Error::Malformed)?;
        let fragment = Fragment::from_bytes(bytes)?;
        // The hint names the relay of the blob among the relays of layer 3.
        // A link to a relay that the set does not hold leads nowhere.
        let relay = self
            .relays
            .iter()
            .map(|relay| relay.candidate)
            .find(|candidate| {
                candidate.is_exit() && relay_hint(&candidate.relay_id) == fragment.relay_ref
            })
            .ok_or(Error::NoPath)?
            .relay_id;
        let handle = self.handle();
        let fetch = LinkFetch {
            fragment,
            relay,
            handle,
        };
        // A circuit that ends at that relay carries the fetch (`NET-308`),
        // and with none the fetch waits for one.
        if self.ready_slot_to(&relay, None).is_some() {
            self.fetch_link(fetch, rng)?;
        } else {
            self.held_fetches.push(fetch);
            self.circuit_to(relay, rng)?;
        }
        Ok(handle)
    }

    /// A node for the transfer of attachments. Part 13 §13.8 puts them on a
    /// connection of their own, thus a client runs this node beside the one
    /// of its queues. Each circuit of it carries the attachment range alone.
    pub fn for_transfers(ingress: RelayInfo, relays: Vec<RelayInfo>, root: RootIdentity) -> Self {
        let mut node = Self::with_relays(ingress, relays, root);
        node.range = Range::Attachment;
        node
    }

    /// Sends one chunk command to `relay` on a circuit that ends there. With
    /// no such circuit the command waits, and the circuit starts. A
    /// [`ClientEvent::Chunk`] with the handle follows the answer.
    pub fn chunk<R: CryptoRng + ?Sized>(
        &mut self,
        relay: [u8; 32],
        chunk_id: [u8; 32],
        job: ChunkJob,
        rng: &mut R,
    ) -> Result<u64, Error> {
        if self.range != Range::Attachment {
            return Err(Error::Malformed);
        }
        if let ChunkJob::Put { chunk, .. }
        | ChunkJob::Replicate { chunk, .. }
        | ChunkJob::Verify { chunk, .. } = &job
        {
            if chunk.len() != CHUNK_SIZE {
                return Err(Error::Malformed);
            }
        }
        let handle = self.handle();
        let held = HeldChunk {
            relay,
            chunk_id,
            handle,
            job,
        };
        if self.ready_slot_to(&relay, None).is_some() {
            self.start_chunk(held, rng)?;
        } else {
            self.held_chunks.push(held);
            self.circuit_to(relay, rng)?;
        }
        Ok(handle)
    }

    /// Signs a chunk command for the session of a circuit to its relay, and
    /// queues it.
    fn start_chunk<R: CryptoRng + ?Sized>(
        &mut self,
        held: HeldChunk,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.current = self.ready_slot_to(&held.relay, None).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        let corr_id: [u8; 16] = random(rng);
        let mut bind = [0u8; TOKEN_LEN];
        let (cmd, signer, payload, expect) = match held.job {
            ChunkJob::Register {
                cred,
                read_pk,
                is_backup,
            } => {
                let register = RegisterPayload {
                    cred_pk: *umbra_crypto::x25519::PublicKey::from(&cred).as_bytes(),
                    read_pk,
                    admission: Admission::NONE,
                };
                let mut payload = alloc::vec![0u8; 64usize.saturating_add(Admission::NONE.len())];
                let used = register.encode(&mut payload)?;
                payload.truncate(used);
                let cmd = if is_backup {
                    ChunkCmd::Bnew
                } else {
                    ChunkCmd::Cnew
                };
                (cmd, cred, payload, Some(ChunkExpect::Token))
            }
            ChunkJob::Put {
                cred,
                storage_token,
                chunk,
            } => {
                bind = storage_token;
                let expect =
                    ChunkExpect::Proof(seal::proof(&corr_id, &chunk), ChunkOutcome::Stored);
                (ChunkCmd::Cput, cred, chunk, Some(expect))
            }
            ChunkJob::Replicate {
                cred,
                targets,
                chunk,
            } => {
                let targets = CrepPayload { targets };
                let mut payload = alloc::vec![0u8; targets.len()];
                targets.encode(&mut payload)?;
                let expect =
                    ChunkExpect::Proof(seal::proof(&corr_id, &chunk), ChunkOutcome::Replicated);
                (ChunkCmd::Crep, cred, payload, Some(expect))
            }
            ChunkJob::Verify { cred, chunk } => {
                let nonce: [u8; 16] = random(rng);
                let expect =
                    ChunkExpect::Proof(seal::proof(&nonce, &chunk), ChunkOutcome::Verified);
                (ChunkCmd::Cvfy, cred, nonce.to_vec(), Some(expect))
            }
            ChunkJob::Fetch { read } => (ChunkCmd::Cget, read, Vec::new(), Some(ChunkExpect::Data)),
            ChunkJob::Renew { read } => (ChunkCmd::Crnw, read, Vec::new(), None),
            ChunkJob::Erase { cred } => {
                let expect = ChunkExpect::Proof([0; PROOF_LEN], ChunkOutcome::Erased);
                (ChunkCmd::Cdel, cred, Vec::new(), Some(expect))
            }
        };
        let is_put = cmd == ChunkCmd::Cput;
        let mut command = Command {
            cmd: Cmd::Attachment(cmd.to_byte()),
            corr_id,
            queue_id: held.chunk_id,
            auth: [0; 32],
            payload: &payload,
        };
        let key = CommandAuthKey::derive(&signer, &session_pk).map_err(|_| Error::Unverified)?;
        // ATT-042: the authorized bytes of a `CPUT` hold the token.
        command.sign(&key, if is_put { bind.as_slice() } else { &[] })?;
        let mut encoded = alloc::vec![0u8; command.len()];
        command.encode(&mut encoded)?;
        let waiting = match expect {
            Some(expect) => Waiting::Chunk(Box::new(ChunkWait {
                handle: held.handle,
                expect,
            })),
            None => Waiting::Other,
        };
        self.queue_command(encoded, waiting)?;
        self.pump()
    }

    /// Sends the first fetch of a link on a circuit to the relay of its blob.
    fn fetch_link<R: CryptoRng + ?Sized>(
        &mut self,
        fetch: LinkFetch,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.current = self
            .ready_slot_to(&fetch.relay, None)
            .ok_or(Error::NoPath)?;
        let lock: [u8; 32] = random(rng);
        let command = get_blob_command(
            &fetch.fragment.link_id,
            &StaticSecret::from(lock),
            &self.session_pk()?,
            random(rng),
        )?;
        let wait = BlobWait {
            fragment: fetch.fragment,
            lock,
            handle: fetch.handle,
        };
        self.queue_command(command, Waiting::Blob(Box::new(wait)))?;
        self.pump()
    }

    /// The relay answered the `IRES` or the `IPUT` of an invitation.
    fn on_link<R: CryptoRng + ?Sized>(
        &mut self,
        queue: [u8; 32],
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let link_id: [u8; LINK_ID_LEN] = payload.try_into().map_err(|_| Error::Malformed)?;
        let session_pk = self.session_pk()?;
        let queue_relay = self.exit_of(self.current)?;
        let Some(half) = self.halves.get_mut(&queue) else {
            return Ok(Vec::new());
        };
        let Some(link) = &mut half.link else {
            return Ok(Vec::new());
        };
        let Some(fragment) = &link.fragment else {
            // The relay drew the identifier, thus the seal can bind it
            // (`IDN-160`).
            let fragment = Fragment {
                key: random(rng),
                link_id,
                relay_ref: relay_hint(&queue_relay),
            };
            let blob = Bundle::parse(&half.bundle)?.seal(&fragment, random(rng))?;
            let command = half
                .inbound
                .put_blob(&link_id, &blob, &session_pk, random(rng))?;
            link.fragment = Some(fragment);
            self.queue_command(command, Waiting::Link(queue))?;
            return Ok(Vec::new());
        };
        if fragment.link_id != link_id {
            return Err(Error::Unverified);
        }
        // The relay holds the blob. The store keeps the fragment in the
        // place of the bundle, because the user gives out the fragment.
        let shared = fragment.to_bytes().to_vec();
        let handle = link.handle;
        half.bundle = shared.clone();
        half.link = None;
        if let Some(half) = self.halves.remove(&queue) {
            self.invitation_changed(queue, &half)?;
            self.halves.insert(queue, half);
        }
        Ok(alloc::vec![ClientEvent::InvitationLink {
            handle,
            fragment: shared,
        }])
    }

    /// The relay gave the blob of a link.
    fn on_blob<R: CryptoRng + ?Sized>(
        &mut self,
        wait: BlobWait,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let gone = alloc::vec![ClientEvent::InvitationGone {
            handle: wait.handle
        }];
        let mut bundle = Vec::new();
        let opens = iblob_parse(payload)
            .map_err(Error::from)
            .and_then(|blob| Bundle::open(&wait.fragment, blob, &mut bundle).map(|_| ()));
        // IDN-161: a blob that does not open under the fragment is refused.
        if opens.is_err() || Invitee::check(&bundle).is_err() {
            return Ok(gone);
        }
        let lock = Some(wait.lock);
        self.make_queue(Purpose::Accept { bundle, lock }, rng)?;
        Ok(Vec::new())
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
        let held = self.contacts.get(&contact.0).ok_or(Error::NoPath)?;
        let relay = *held.channel.outbound().relay_id();
        let has_circuit = self.ready_slot_to(&relay, None).is_some();
        if !held.channel.can_send() || !has_circuit {
            // The first record of the invitee opens the chain (`NET-292`),
            // and a record goes on a circuit to the relay of its queue.
            let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
            held.waiting_sends
                .push_back((app.to_vec(), Some(user_handle)));
            if !has_circuit {
                self.circuit_to(relay, rng)?;
            }
            return Ok(user_handle);
        }
        self.send_now(contact.0, app, Waiting::UserSend(user_handle), now, rng)?;
        Ok(user_handle)
    }

    /// Sends one record of a kind that the node makes itself.
    fn send_control<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        kind: AppKind,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let record = AppMessage {
            kind,
            msg_id: random(rng),
            sent_at: now.saturating_mul(1_000),
            body,
        };
        let mut app = alloc::vec![0u8; record.len()];
        record.encode(&mut app)?;
        self.send_now(contact, &app, Waiting::Other, now, rng)
    }

    /// Starts a verification ceremony with a contact (Part 4 §4.5.2): a
    /// fresh nonce, and its commit to the peer. A ceremony that ran before
    /// ends, and its code shows no more (`IDN-145`, `IDN-146`). A
    /// [`ClientEvent::VerificationCode`] follows the two reveals.
    pub fn start_verification<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &ContactId,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        if !held.channel.can_send() {
            return Err(Error::NoPath);
        }
        let mut ceremony = Ceremony::new(random(rng));
        let commit = ceremony.commit_to_send();
        held.ceremony = Some(ceremony);
        // A commit that answers nothing is a start.
        let body = [commit, [0; 32]].concat();
        self.send_control(contact.0, AppKind::VerifyCommit, &body, now, rng)
    }

    /// The user says that the two codes match (`IDN-147`). The result is
    /// the pairwise identity key of the peer, which the verification state
    /// names. With no complete ceremony it is an error, because the
    /// exchange alone sets no state and no exchange sets none (`IDN-148`).
    pub fn confirm_verification(&mut self, contact: &ContactId) -> Result<[u8; 32], Error> {
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        let ceremony = held.ceremony.as_mut().ok_or(Error::Unverified)?;
        ceremony.user_confirmed()?;
        held.ceremony = None;
        Ok(held.peer_static)
    }

    /// A `VerifyCommit` or a `VerifyReveal` of the peer arrived. `answers`
    /// is the second field of a commit, and it is zero for a reveal.
    fn on_verification<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        kind: AppKind,
        value: [u8; 32],
        answers: [u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let own_pk = {
            let held = self.contacts.get(&contact).ok_or(Error::NoPath)?;
            self.root.pairwise_identity(&held.salt).x25519_public()
        };
        let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
        if kind == AppKind::VerifyCommit {
            let waiting = held
                .ceremony
                .as_ref()
                .filter(|ceremony| ceremony.awaits_commit())
                .map(Ceremony::own_commit);
            let mut own_commit = None;
            if answers == [0; 32] {
                // The two clients started at one time. The lower commit
                // stays a start, and the client of the other one answers.
                if waiting.is_some_and(|own| own < value) {
                    return Ok(Vec::new());
                }
                let mut ceremony = Ceremony::new(random(rng));
                own_commit = Some(ceremony.commit_to_send());
                held.ceremony = Some(ceremony);
            } else if waiting != Some(answers) {
                // An answer to a start that this client replaced.
                return Ok(Vec::new());
            }
            let ceremony = held.ceremony.as_mut().ok_or(Error::Unverified)?;
            ceremony.peer_committed(value);
            // IDN-143: the reveal goes after the commit of the peer is here.
            let reveal = ceremony.reveal_to_send()?;
            if let Some(commit) = own_commit {
                let body = [commit, value].concat();
                self.send_control(contact, AppKind::VerifyCommit, &body, now, rng)?;
            }
            self.send_control(contact, AppKind::VerifyReveal, &reveal, now, rng)?;
            return Ok(Vec::new());
        }
        let Some(ceremony) = held.ceremony.as_mut() else {
            return Ok(Vec::new());
        };
        // IDN-144: a reveal that does not match the commit gives no code. The
        // ceremony stays, because a reveal of an earlier ceremony can be late.
        if ceremony.code(&own_pk, &held.peer_static).is_some()
            || ceremony.peer_revealed(value).is_err()
        {
            return Ok(Vec::new());
        }
        let code = ceremony.code(&own_pk, &held.peer_static);
        Ok(code
            .map(|code| ClientEvent::VerificationCode {
                contact: ContactId(contact),
                code,
            })
            .into_iter()
            .collect())
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
        // A `SEND` binds no queue to a session. It goes on a circuit to the
        // relay of the queue, and on one that does not serve the inbound
        // queue of the contact when one is ready.
        let relay = *self
            .contacts
            .get(&contact)
            .ok_or(Error::NoPath)?
            .channel
            .outbound()
            .relay_id();
        let Some(slot) = self.ready_slot_to(&relay, self.slot_of(&contact)) else {
            // No circuit ends at the relay of the queue. The record waits
            // for one, in its order, and the call is no fault: a record
            // that arrives must never end a run for the lack of a circuit.
            let user_handle = match waiting {
                Waiting::UserSend(handle) => Some(handle),
                _ => None,
            };
            let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
            held.waiting_sends.push_back((app.to_vec(), user_handle));
            return self.circuit_to(relay, rng);
        };
        self.current = slot;
        let session_pk = self.session_pk()?;
        let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
        let (_, encoded) =
            held.channel
                .send(app, &session_pk, random(rng), random(rng), now, rng)?;
        self.moved.insert(contact);
        self.queue_command(encoded, waiting)?;
        self.pump()
    }

    /// One slot of the cover clock (Part 3 §3.6.2). An acknowledgment that
    /// is due takes the slot (`NET-064`). With none, a client in the
    /// foreground makes a cover cell, and about one in five is a loop
    /// (`NET-063`). A client in the background makes no cover cell.
    /// `receipt` is a batch that is due for one contact, as an application
    /// record. It takes the slot when no `ACK` is due (`NET-065`), and the
    /// result says so, thus the caller erases it then and at no other time.
    pub fn on_cover_slot<R: CryptoRng + ?Sized>(
        &mut self,
        makes_cover: bool,
        receipt: Option<(&ContactId, &[u8])>,
        now: u64,
        rng: &mut R,
    ) -> Result<CoverSlot, Error> {
        let contacts: Vec<[u8; 32]> = self.contacts.keys().copied().collect();
        for contact in contacts {
            if self.slot_of(&contact).is_some()
                && self.acknowledge(&ContactId(contact), now, rng)?
            {
                return Ok(CoverSlot::Acknowledgment);
            }
        }
        if let Some((contact, app)) = receipt {
            let can_send = self
                .contacts
                .get(&contact.0)
                .is_some_and(|held| held.channel.can_send());
            if can_send && self.slot_of(&contact.0).is_some() {
                self.send_now(contact.0, app, Waiting::Other, now, rng)?;
                return Ok(CoverSlot::Receipt);
            }
        }
        let ready = self
            .slots
            .iter()
            .position(|slot| matches!(slot.circuit, Circuit::Ready(_)));
        let (true, Some(ready)) = (makes_cover, ready) else {
            return Ok(CoverSlot::Nothing);
        };
        let is_loop = random::<1, R>(rng) < [LOOP_SHARE];
        let corr_id = random(rng);
        let Some(Circuit::Ready(session)) = self.slots.get_mut(ready).map(|slot| &mut slot.circuit)
        else {
            return Ok(CoverSlot::Nothing);
        };
        if is_loop {
            let cell = session.cover_cell(Bucket::B0)?;
            self.send_cell(&cell)?;
            return Ok(CoverSlot::Loop);
        }
        session.queue_cover(corr_id)?;
        self.pump()?;
        Ok(CoverSlot::Cover)
    }

    /// Acknowledges the records of a contact that the runtime committed and
    /// that are older than `RECEIPT_MIN_DELAY` (`NET-050`). The result says
    /// whether an `ACK` left.
    pub fn acknowledge<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &ContactId,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        // The `ACK` goes to the session that serves the queue.
        self.current = self.slot_of(&contact.0).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        let channel = &mut held.channel;
        let Some((point, encoded)) = channel.acknowledge(&session_pk, random(rng), now)? else {
            return Ok(false);
        };
        channel.acknowledged(point);
        self.moved.insert(contact.0);
        self.queue_command(encoded, Waiting::Other)?;
        self.pump()?;
        Ok(true)
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
                self.on_build_cell(*build, *pending, &cell, now, rng)
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

    /// Sends what waited for a circuit to the relay at the end of the
    /// current one: the handshake records, and the records of the user.
    fn flush_to_exit<R: CryptoRng + ?Sized>(&mut self, now: u64, rng: &mut R) -> Result<(), Error> {
        let exit = self.exit_of(self.current)?;
        let (due, held): (Vec<Sealed>, Vec<Sealed>) = core::mem::take(&mut self.held_records)
            .into_iter()
            .partition(|sealed| *sealed.relay_id() == exit);
        self.held_records = held;
        for sealed in due {
            self.send_sealed(sealed, rng)?;
        }
        let (due, held): (Vec<LinkFetch>, Vec<LinkFetch>) = core::mem::take(&mut self.held_fetches)
            .into_iter()
            .partition(|fetch| fetch.relay == exit);
        self.held_fetches = held;
        let ready = self.current;
        for fetch in due {
            self.fetch_link(fetch, rng)?;
        }
        let (due, held): (Vec<HeldChunk>, Vec<HeldChunk>) = core::mem::take(&mut self.held_chunks)
            .into_iter()
            .partition(|held| held.relay == exit);
        self.held_chunks = held;
        for held in due {
            self.start_chunk(held, rng)?;
        }
        self.current = ready;
        let waiting: Vec<[u8; 32]> = self
            .contacts
            .iter()
            .filter(|(_, held)| {
                held.channel.can_send()
                    && !held.waiting_sends.is_empty()
                    && *held.channel.outbound().relay_id() == exit
            })
            .map(|(id, _)| *id)
            .collect();
        for contact in waiting {
            self.send_waiting(contact, now, rng)?;
        }
        Ok(())
    }

    /// Sends each record that waits for a contact, in its order, when the
    /// chain of the ratchet is open. A record with no circuit to the relay
    /// of its queue goes back into the wait.
    fn send_waiting<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(held) = self.contacts.get_mut(&contact) else {
            return Ok(());
        };
        if !held.channel.can_send() {
            return Ok(());
        }
        for (app, user_handle) in core::mem::take(&mut held.waiting_sends) {
            let waiting = user_handle.map_or(Waiting::Other, Waiting::UserSend);
            self.send_now(contact, &app, waiting, now, rng)?;
        }
        Ok(())
    }

    fn on_build_cell<R: CryptoRng + ?Sized>(
        &mut self,
        mut build: CircuitBuild,
        pending: Pending,
        cell: &[u8],
        now: u64,
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
        let range = self.range;
        self.slot_mut()?.circuit = Circuit::Ready(Box::new(CircuitSession::new(
            circuit,
            relay_session_pk,
            range,
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
            self.add_circuit(None, rng)?;
        }
        self.current = ready;
        self.flush_to_exit(now, rng)?;
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
                    (Some(Waiting::Link(queue)), Cmd::Ilink) => {
                        out.extend(self.on_link(queue, &payload, rng)?);
                    }
                    (Some(Waiting::Blob(wait)), Cmd::Iblob) => {
                        out.extend(self.on_blob(*wait, &payload, rng)?);
                    }
                    (Some(Waiting::Chunk(wait)), Cmd::Attachment(byte)) => {
                        out.push(ClientEvent::Chunk {
                            handle: wait.handle,
                            outcome: chunk_outcome(wait.expect, byte, payload),
                        });
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
                        Some(Waiting::Link(queue)) => {
                            let setup = self.halves.get(&queue).and_then(|half| half.link.as_ref());
                            setup.map_or(handle, |link| link.handle)
                        }
                        // WIR-317 gives one reason for each cause, and each
                        // cause means that this party gets no blob.
                        Some(Waiting::Blob(wait)) => {
                            out.push(ClientEvent::InvitationGone {
                                handle: wait.handle,
                            });
                            continue;
                        }
                        Some(Waiting::Chunk(wait)) => {
                            out.push(ClientEvent::Chunk {
                                handle: wait.handle,
                                outcome: ChunkOutcome::Refused(reason),
                            });
                            continue;
                        }
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
        // The queue lives at the end of the chain that carried its `NEW`.
        let queue_relay = self.exit_of(keys.slot)?;
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
        let mut link = None;
        let (setup, outbound, peer_static, issued) = match keys.purpose {
            Purpose::InviteLink => {
                let (inviter, bundle) = Inviter::issue(&identity, own_address(), rng)?;
                let reserve = inbound.reserve_link(&session_pk, random(rng))?;
                self.queue_command(reserve, Waiting::Link(ids.recipient_id))?;
                link = Some(LinkSetup {
                    handle: keys.handle,
                    fragment: None,
                });
                (Setup::Inviting(Box::new(inviter)), None, [0u8; 32], bundle)
            }
            Purpose::Invite => {
                let (inviter, bundle) = Inviter::issue(&identity, own_address(), rng)?;
                out.push(ClientEvent::Invitation {
                    handle: keys.handle,
                    bundle: bundle.clone(),
                });
                (Setup::Inviting(Box::new(inviter)), None, [0u8; 32], bundle)
            }
            Purpose::Accept { bundle, lock } => {
                opening = alloc::vec![0u8; QUEUE_ADDRESS_LEN];
                own_address().encode(&mut opening)?;
                let peer_static = Bundle::parse(&bundle)?.responder_static_x25519;
                let (invitee, flight1, to) = Invitee::accept(&bundle, &own_address(), rng)?;
                let outbound = match lock {
                    Some(lock) => Outbound::locked(&to, StaticSecret::from(lock)),
                    None => Outbound::new(&to),
                };
                let sealed = outbound.seal_record(L6Kind::Handshake, &flight1, random(rng))?;
                self.send_sealed(sealed, rng)?;
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
            link,
            inbound_relay: queue_relay,
        };
        // An invitation with a link waits for the store of its blob.
        if half.link.is_none() {
            self.invitation_changed(ids.recipient_id, &half)?;
        }
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
            let mut ceremony_record = None;
            if let Received::App { bytes, .. } = held.channel.receive(payload, bucket, now, rng)? {
                let parsed = AppMessage::parse(&bytes, Channel::Pairwise).ok();
                match parsed.as_ref().map(|parsed| parsed.kind) {
                    // NET-179, WIR-330: the receiving chain gave the address.
                    Some(AppKind::QueueAddress) => {
                        let address =
                            parsed.and_then(|parsed| QueueAddress::parse(parsed.body).ok());
                        if let Some(address) = address {
                            held.channel.accept_address(&address);
                        }
                    }
                    // The records of a ceremony are for the node, and the
                    // conversation shows none of them.
                    Some(kind @ (AppKind::VerifyCommit | AppKind::VerifyReveal)) => {
                        let field = |at: usize| -> Option<[u8; 32]> {
                            let body = parsed.as_ref()?.body;
                            body.get(at..at.checked_add(32)?)?.try_into().ok()
                        };
                        let answers = field(32).unwrap_or([0; 32]);
                        ceremony_record = field(0).map(|value| (kind, value, answers));
                    }
                    _ => out.push(ClientEvent::Message {
                        contact: ContactId(queue_id),
                        app: bytes,
                    }),
                }
            }
            if let Some((kind, value, answers)) = ceremony_record {
                out.extend(self.on_verification(queue_id, kind, value, answers, now, rng)?);
            }
            // The record opened the sending chain of an inviter.
            self.send_waiting(queue_id, now, rng)?;
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
                    let sealed = outbound.seal_record(L6Kind::Handshake, &flight2, random(rng))?;
                    self.send_sealed(sealed, rng)?;
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
                let sealed = outbound.seal_record(L6Kind::Handshake, &flight3, random(rng))?;
                self.send_sealed(sealed, rng)?;
                (keys, half.peer_static, outbound, Role::Initiator)
            }
        };
        let (keys, peer_static, outbound, role): (SessionKeys, [u8; 32], Outbound, Role) = finished;
        let ratchet = Ratchet::new(keys, role, Width::W64, now, rng)?;
        self.contacts.insert(
            queue_id,
            Contact {
                channel: PairwiseChannel::new(ratchet, outbound, half.inbound),
                inbound_relay: half.inbound_relay,
                peer_static,
                salt: half.salt,
                waiting_sends: VecDeque::new(),
                ceremony: None,
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

    /// The chain of each circuit that holds its three hops.
    pub fn chains(&self) -> Vec<[[u8; 32]; HOPS]> {
        self.slots
            .iter()
            .filter(|slot| slot.is_ready())
            .filter_map(|slot| slot.chain)
            .collect()
    }

    /// The relays of the circuit, for a runtime that dials the guard.
    pub fn guard(&self) -> RelayStatic {
        copy_static(&self.ingress.key)
    }
}
