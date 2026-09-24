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
    dead::DeadChannel,
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
    CIRCUIT_BUILD_TIMEOUT, CIRCUIT_MAX_AGE, CIRCUIT_MAX_CELLS, HOPS,
};
use umbra_queue::{params::MAX_QUEUES_PER_SESSION, Reject};
use umbra_transport::link::ClientLink;
use umbra_wire::{
    address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN},
    admission::Admission,
    app::{AppKind, AppMessage, Channel},
    bucket::{Bucket, COMMAND_HEADER},
    capsule,
    cell::{pad_body, Cell, CellCommand},
    command::{iblob_parse, Cmd, Command, IdsPayload, LINK_ID_LEN},
    group::{
        encode_gsub, split_gmsg, GkeyPayload, GnewPayload, GroupCmd, GseqPayload, GKEY_LEN,
        GNEW_NONE_LEN, NOTIFY_REGISTRATION_LEN,
    },
    queue::L6Kind,
    session::SessionControl,
};

use super::{
    batch::{smallest_bucket, Range},
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
    /// The answer to a group-queue command of [`ClientNode::group`].
    Group {
        /// The handle of the call.
        handle: u64,
        /// What the relay did.
        outcome: GroupOutcome,
    },
    /// One record of a group queue that this device subscribed to. The
    /// relay gives it at the `GSUB` and at each later post (`WIR-387`,
    /// `WIR-388`).
    GroupRecord {
        /// The group queue that carried it.
        group_queue_id: [u8; 32],
        /// The sequence of that replica. It is no order across replicas
        /// and no message identifier (`WIR-382`, `WIR-383`).
        seq: u32,
        /// The `GroupQueueRecord` bytes.
        record: Vec<u8>,
    },
    /// The circuit failed its check or its build, and the runtime builds a
    /// new one.
    CircuitLost,
    /// A notify queue of Part 8 §8.5.2 exists at its relay. The caller
    /// registers `address` with each replica of its group by `GNREG`.
    NotifyQueue {
        /// The handle that [`ClientNode::make_notify_queue`] gave.
        handle: u64,
        /// The `RecipientId` of the queue.
        recipient_id: [u8; 32],
        /// The encoded `QueueAddress` that a relay writes to.
        address: Vec<u8>,
    },
    /// A report queue of Part 12 §12.5.3 exists at its relay. The caller
    /// puts `address` in the `RosterEntry` of its role.
    ReportQueue {
        /// The handle that [`ClientNode::make_report_queue`] gave.
        handle: u64,
        /// The `RecipientId` of the queue.
        recipient_id: [u8; 32],
        /// The encoded `QueueAddress` that a member writes to.
        address: Vec<u8>,
    },
    /// A report record arrived on a report queue (§12.5.3). It stays sealed
    /// to the report key of the role.
    Report {
        /// The report queue.
        recipient_id: [u8; 32],
        /// The `ReportRecord`.
        record: Vec<u8>,
    },
    /// A digest arrived on a notify queue (`NTF-107`): the records of a
    /// group queue since the last digest.
    Digest {
        /// The notify queue.
        recipient_id: [u8; 32],
        /// The `GroupQueueId`, or the `community_id` (`NTF-099`).
        id: [u8; 32],
        /// The records since the last digest.
        post_count: u8,
    },
    /// The relay of an inbound queue answered its `NKEY` with its
    /// notification key (`NTF-112`). The caller seals the binding of the
    /// queue to it and sends it with [`ClientNode::bind_queue`].
    NotifyKey {
        /// The queue.
        recipient_id: [u8; 32],
        /// The `UMBRA-KEM` public key of the relay.
        relay_ntf_pk: Vec<u8>,
    },
    /// A circuit came near `CIRCUIT_MAX_AGE` or `CIRCUIT_MAX_CELLS`, at
    /// which each relay of it ends it with no cell (`NET-320`, `NET-321`).
    /// The runtime ends the run and starts a new one at once, and nothing
    /// failed.
    CircuitAged,
    /// A renewal replaced the channel of a contact (Part 3 §3.2.6). Each
    /// record with no delivery receipt goes again.
    ChannelRenewed {
        /// The contact.
        contact: ContactId,
    },
    /// The peer gave a new address in a record of kind `0x33`, thus a
    /// dead channel lives again (`NET-176`, `NET-191`).
    PeerMoved {
        /// The contact.
        contact: ContactId,
    },
    /// A relay refused a `SEND` to a contact with `REJECTED`: the queue of
    /// the peer is gone, and the channel is dead (Part 3 §3.2.6).
    ChannelDead {
        /// The contact.
        contact: ContactId,
    },
    /// A contact reads a new inbound queue, and its address went to the
    /// peer. The dead-channel blob of `NET-183` names it.
    QueueRotated {
        /// The contact.
        contact: ContactId,
        /// The encoded `QueueAddress` of the new queue.
        address: Vec<u8>,
    },
    /// An inbound queue of a contact ended at the end of its rotation
    /// (`NET-178`). Its push binding goes with it.
    QueueEnded {
        /// The `RecipientId` of the queue.
        queue: [u8; 32],
    },
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

/// One group-queue command of Part 6 §6.4.5 for one relay. Each command
/// carries the credential that authorizes it (`NET-229`).
pub enum GroupJob {
    /// A command of a community of Part 12, on a node of the community
    /// range ([`ClientNode::community`]).
    Community(CommunityJob),
    /// `GNEW`. The creator signs it under the `own_sk` of its own payload
    /// (`WIR-517`), and the relay draws the `GroupQueueId`.
    Create {
        /// The reader credential of epoch 1.
        read_pk: [u8; 32],
        /// The writer credential of epoch 1.
        write_pk: [u8; 32],
        /// The owner credential, which the creator drew (`NET-231`).
        own: StaticSecret,
    },
    /// `GPOST`.
    Post {
        /// `write_sk` of the epoch.
        write: StaticSecret,
        /// One `GroupQueueRecord`, filled to its bucket (`WIR-370`).
        record: Vec<u8>,
    },
    /// `GSUB`. The relay emits each record above `from_seq`, and then each
    /// record that it accepts while the session lives.
    Subscribe {
        /// `read_sk` of the epoch.
        read: StaticSecret,
        /// The cursor of this device for this replica (`NET-236`).
        from_seq: u32,
    },
    /// `GUNSUB`.
    Unsubscribe {
        /// `read_sk` of the epoch.
        read: StaticSecret,
    },
    /// `GKEY`, which an admin sends at a rotation.
    Rotate {
        /// `own_sk`, which authorizes the command.
        own: StaticSecret,
        /// The owner credential after the command, or none to keep the
        /// present one (`WIR-522`).
        next_own_pk: Option<[u8; 32]>,
        /// The reader credential of the new epoch.
        read_pk: [u8; 32],
        /// The writer credential of the new epoch.
        write_pk: [u8; 32],
    },
    /// `GDEL`, which an admin sends to close the group.
    Delete {
        /// `own_sk`.
        own: StaticSecret,
    },
    /// `GNREG` or `GNUNREG` of the notify queue of this device (`NTF-093`).
    Notify {
        /// `read_sk` of the epoch.
        read: StaticSecret,
        /// The encoded `QueueAddress` of the notify queue.
        queue: Vec<u8>,
        /// Whether the registration starts or ends.
        on: bool,
    },
}

/// What a relay did with a group-queue command. A `GSUB`, a `GUNSUB`, a
/// `GKEY`, a `GDEL`, and the two notify commands have no answer of their
/// own, thus only a `NACK` of one of them gives an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupOutcome {
    /// The relay made the group queue, and this is its `GroupQueueId`.
    Created([u8; 32]),
    /// The relay holds the record under this `seq`. The same bytes again
    /// give the `seq` that it holds (`NET-239`).
    Posted(u32),
    /// The `PAGE` that answers a community `PULL`, as a `PullResponse`.
    Page(Vec<u8>),
    /// The relay holds a community record under this `seq` (`PUBACK`).
    Published(u64),
    /// The relay refused the command. `WIR-317` gives one reason for an
    /// unknown group queue and for a wrong credential.
    Refused(Reject),
    /// No circuit reached the relay of the command within
    /// `CIRCUIT_BUILD_TIMEOUT`. The command did not leave this device.
    Unreachable,
}

/// One command of a community of Part 12 §12.3.3. Each one is signed
/// under `pull_sk` of its community (`COM-175`), and one circuit serves one
/// community (`COM-173`).
pub enum CommunityJob {
    /// `PULL` with an encoded `PullRequest`. A `PAGE` answers it.
    Pull {
        /// The request.
        request: Vec<u8>,
    },
    /// `PUB` of one record with its `Admission` trailer. A `PUBACK`
    /// answers it.
    Publish {
        /// The record and the encoded `Admission` after it.
        payload: Vec<u8>,
    },
    /// `NREG` or `NUNREG` of a `NotifyRegistration`. It has no answer.
    Notify {
        /// The encoded registration.
        registration: Vec<u8>,
        /// An `NREG`, or an `NUNREG`.
        on: bool,
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
    /// The first tick that saw the build of this circuit run.
    building_since: Option<u64>,
    /// The first tick that saw this circuit build or serve, from which its
    /// age counts.
    born: Option<u64>,
}

/// The time before `CIRCUIT_MAX_AGE` at which a client ends a circuit
/// (`NET-320`). The age counts from a tick, not from the first `EXTEND`,
/// and a relay sweeps on its own period.
pub const CIRCUIT_AGE_MARGIN: u64 = 60;

/// The cells before `CIRCUIT_MAX_CELLS` at which a client ends a circuit
/// (`NET-321`). A relay paces about one cell each second toward the
/// client, and the client ticks once each second.
pub const CIRCUIT_CELL_MARGIN: u32 = 64;

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
            building_since: None,
            born: None,
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

/// The record of a `GMSG`, in the bucket that its payload length gives.
/// A payload of another length belongs to no bucket and drops.
fn group_record(group_queue_id: [u8; 32], payload: &[u8]) -> Option<ClientEvent> {
    let bucket = smallest_bucket(payload.len().saturating_add(COMMAND_HEADER))
        .filter(|bucket| bucket.l5_payload() == payload.len())?;
    let (seq, record) = split_gmsg(payload, bucket).ok()?;
    Some(ClientEvent::GroupRecord {
        group_queue_id,
        seq,
        record: record.to_vec(),
    })
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
    /// The notify queue of a group (Part 8 §8.5.2).
    Notify,
    /// The report queue of a role of a community (Part 12 §12.5.3).
    Report,
    /// The queue and the bundle of a channel renewal that this device
    /// offers, as the responder (Part 3 §3.2.6).
    Renew {
        /// The contact.
        contact: [u8; 32],
    },
    /// The queue of this device for a channel renewal that the peer
    /// offered in `bundle`, as the initiator.
    RenewAccept {
        /// The contact.
        contact: [u8; 32],
        /// The bundle of the peer.
        bundle: Vec<u8>,
    },
    /// The new inbound queue of a contact (Part 3 §3.2.6, `NET-176`).
    Rotate {
        /// The contact.
        contact: [u8; 32],
        /// The time of the call, which starts the grace of `NET-177`.
        now: u64,
    },
}

/// A queue of this device that no contact writes to: a notify queue of
/// Part 8 §8.5.2, where a group-queue relay deposits its digests, or a
/// report queue of Part 12 §12.5.3, where a member writes a report.
struct NotifyQueue {
    inbound: Inbound,
    relay: [u8; 32],
    is_report: bool,
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

struct HeldGroup {
    relay: [u8; 32],
    group_queue_id: [u8; 32],
    handle: u64,
    job: GroupJob,
}

/// What a group-queue command waits for.
struct GroupWait {
    handle: u64,
    /// Whether the answer is a `GIDS` or a `GSEQ`.
    creates: bool,
}

enum Waiting {
    Chunk(Box<ChunkWait>),
    Group(Box<GroupWait>),
    Queue(Box<QueueKeys>),
    UserSend(u64),
    /// A `SEND` to a contact, with the handle of the user when a user
    /// record rides in it.
    Contact {
        contact: [u8; 32],
        user: Option<u64>,
    },
    /// The `NKEY` of this inbound queue.
    Notify([u8; 32]),
    /// The `SUB` of this inbound queue.
    Subscribe([u8; 32]),
    /// An `IRES` or an `IPUT` of the invitation on this queue.
    Link([u8; 32]),
    Blob(Box<BlobWait>),
    Other,
}

enum Setup {
    Inviting(Box<Inviter>),
    Accepting(Box<Invitee>),
}

/// The parts of a handshake half that a renewal takes into the channel.
struct Taken {
    inbound: Inbound,
    inbound_relay: [u8; 32],
    opening: Vec<u8>,
}

/// The result of a handshake, for a renewal that replaces a channel.
struct Finished {
    keys: SessionKeys,
    peer_static: [u8; 32],
    outbound: Outbound,
    role: Role,
    own_address: Option<Zeroizing<Vec<u8>>>,
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
    /// The contact that this handshake renews (Part 3 §3.2.6), or none for
    /// a new contact.
    renews: Option<[u8; 32]>,
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
    /// The time the inbound queue was made, or 0 when a store of an
    /// earlier version gave none; the next check starts it then.
    since: u64,
    /// The relay of the inbound queue that a rotation replaced.
    previous_relay: [u8; 32],
    /// The time of the rotation that runs, which starts `ROTATE_GRACE`.
    rotated_at: u64,
    /// The encoded `QueueAddress` of the inbound queue, which goes to the
    /// peer again after a dead channel (`NET-191`). A store of an earlier
    /// form holds none, and a rotation gives one.
    own_address: Option<Zeroizing<Vec<u8>>>,
    /// Whether the ratchet is stale, as after a restore: the channel sends
    /// nothing on it until a renewal replaces it (`NET-325`).
    stale: bool,
}

/// The two pairwise identity keys of a stored contact: the key of this
/// device and the key of the peer. The safety number and the verification
/// state rest on them, and they need no network and no node.
pub fn stored_contact_keys(
    state: &[u8],
    root: &RootIdentity,
) -> Result<([u8; 32], [u8; 32]), Error> {
    let mut reader = Reader::new(state);
    contact_version(&mut reader)?;
    let salt: [u8; 16] = reader.array()?;
    let peer_static: [u8; 32] = reader.array()?;
    Ok((root.pairwise_identity(&salt).x25519_public(), peer_static))
}

/// The dead-channel secret of a stored contact (Part 3 §3.2.6), with the
/// pairwise key of this device and the one of the peer. The first names
/// the handle of this device as a writer, and the second the one of the
/// peer.
pub fn stored_dead_channel(
    state: &[u8],
    root: &RootIdentity,
) -> Result<(DeadChannel, [u8; 32], [u8; 32]), Error> {
    let mut reader = Reader::new(state);
    contact_version(&mut reader)?;
    let salt: [u8; 16] = reader.array()?;
    let peer_static: [u8; 32] = reader.array()?;
    let own = root.pairwise_identity(&salt);
    let secret = DeadChannel::new(&own, &peer_static)?;
    Ok((secret, own.x25519_public(), peer_static))
}

/// Reads the version byte of a stored contact: `0x01`, `0x02`, or
/// [`CONTACT_STORED_VERSION`].
fn contact_version(reader: &mut Reader<'_>) -> Result<u8, Error> {
    match reader.u8()? {
        version @ (0x01 | STORED_VERSION | CONTACT_ROTATION_VERSION | CONTACT_STORED_VERSION) => {
            Ok(version)
        }
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
    /// A notify queue is new, or its cursor moved.
    NotifyQueue {
        /// The `RecipientId` of the queue.
        queue: [u8; 32],
        /// The stored form, which holds the keys of the queue.
        state: Zeroizing<Vec<u8>>,
    },
    /// A notify queue ended: its group closed, or a new one replaced it.
    NotifyQueueEnded {
        /// The `RecipientId` of the queue.
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

/// The version byte of a stored invitation, and of a stored contact of
/// an earlier form.
const STORED_VERSION: u8 = 0x02;

/// The version byte of a stored contact that added the contact
/// identifier, the time of the inbound queue, the state of a rotation, and
/// the address of the own queue to version `0x02`.
const CONTACT_ROTATION_VERSION: u8 = 0x03;

/// The version byte of a stored contact. It adds the stale flag of a
/// channel renewal (Part 3 §3.2.6) to version `0x03`.
const CONTACT_STORED_VERSION: u8 = 0x04;

/// The version byte of a stored invitation that renews a contact: version
/// `0x02` and then the contact.
const RENEWAL_STORED_VERSION: u8 = 0x03;

/// `ROTATE_AFTER` of Part 3 §3.2.4: the age of a queue, in seconds.
pub const ROTATE_AFTER: u64 = 90 * 86_400;
/// `ROTATE_AFTER` of Part 3 §3.2.4: the count of records of a queue.
pub const ROTATE_AFTER_RECORDS: u32 = 10_000;
/// `ROTATE_GRACE` of Part 3 §3.2.4: how long an owner reads the replaced
/// queue, in seconds.
pub const ROTATE_GRACE: u64 = 7 * 86_400;
/// `ROTATE_JITTER` of Part 3 §3.2.4, in parts of a thousand.
const ROTATE_JITTER_PERMILLE: u64 = 200;

/// The age at which the queue `queue` rotates: `ROTATE_AFTER` moved by a
/// jitter of ±20 %. The draw comes from the pairwise salt of the contact
/// and the queue identifier, thus each queue takes its own value, no two
/// queues rotate together (`NET-018`, `NET-019`), and no relay can
/// predict the time (`NET-323`).
fn rotate_age(salt: &[u8; 16], queue: &[u8; 32]) -> u64 {
    let hash = umbra_crypto::hash::sha3_256(&[umbra_crypto::labels::ROTATE_JITTER, salt, queue]);
    let draw = u64::from(u16::from_be_bytes([hash[0], hash[1]]));
    let permille = 1_000 - ROTATE_JITTER_PERMILLE + draw % (2 * ROTATE_JITTER_PERMILLE + 1);
    ROTATE_AFTER / 1_000 * permille
}

/// The version of the stored form of a notify queue: the version, the relay,
/// and the queue end.
const NOTIFY_STORED_VERSION: u8 = 0x01;
/// The version of the stored form of a report queue, in the same layout.
const REPORT_STORED_VERSION: u8 = 0x02;

fn notify_state(held: &NotifyQueue) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut writer = Writer::new();
    writer.u8(if held.is_report {
        REPORT_STORED_VERSION
    } else {
        NOTIFY_STORED_VERSION
    });
    writer.bytes(&held.relay);
    held.inbound.export(&mut writer)?;
    Ok(writer.finish())
}

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
    /// The group-queue commands that wait for a circuit to their relay.
    held_groups: Vec<HeldGroup>,
    /// The range of each circuit of this node (`WIR-309`). A node for
    /// attachments carries no queue command (Part 13 §13.8).
    range: Range,
    capsules: VecDeque<Vec<u8>>,
    next_handle: u64,
    waiting: BTreeMap<u64, Waiting>,
    /// The contacts whose handshake runs, by `RecipientId`.
    halves: BTreeMap<[u8; 32], Half>,
    contacts: BTreeMap<[u8; 32], Contact>,
    /// The notify queues of Part 8 §8.5.2, by `RecipientId`.
    notify: BTreeMap<[u8; 32], NotifyQueue>,
    /// The contacts whose new queue the relay makes now.
    rotating: BTreeSet<[u8; 32]>,
    /// The contacts with a renewal handshake that runs, in either role.
    renewing: BTreeSet<[u8; 32]>,
    /// The contacts that take a new queue at the next check, whatever the
    /// age of their queue: a dead channel (`NET-182`), or a peer that moved
    /// while this device holds no address of its own queue (`NET-191`).
    forced: BTreeSet<[u8; 32]>,
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

/// The `DESTROY` cell of a circuit under build, sealed for the hops that
/// answered, thus the last of them ends its part (`NET-169`).
fn destroy_cell(build: &mut CircuitBuild) -> Option<Vec<u8>> {
    let mut body = alloc::vec![0u8; BUILD_BUCKET.body_len()];
    // A build cell carries `EXTEND` or `EXTENDED` alone (`NET-157`), thus a
    // `DESTROY` takes the plain body of its bucket.
    pad_body(BUILD_BUCKET, CellCommand::Destroy, &[], &mut body).ok()?;
    let tag = build.seal(&mut body).ok()?;
    Some([build.circ_id().as_slice(), &tag, &body].concat())
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
            held_groups: Vec::new(),
            range: Range::Queue,
            capsules: VecDeque::new(),
            next_handle: 1,
            waiting: BTreeMap::new(),
            halves: BTreeMap::new(),
            contacts: BTreeMap::new(),
            rotating: BTreeSet::new(),
            renewing: BTreeSet::new(),
            forced: BTreeSet::new(),
            notify: BTreeMap::new(),
            moved: BTreeSet::new(),
            changes: Vec::new(),
        }
    }

    /// The changes of the state since the last call, for the store.
    pub fn take_changes(&mut self) -> Result<Vec<StateChange>, Error> {
        let mut changes = core::mem::take(&mut self.changes);
        for id in core::mem::take(&mut self.moved) {
            if let Some(held) = self.notify.get(&id) {
                changes.push(StateChange::NotifyQueue {
                    queue: id,
                    state: notify_state(held)?,
                });
                continue;
            }
            let Some(contact) = self.contacts.get(&id) else {
                continue;
            };
            let mut writer = Writer::new();
            writer.u8(CONTACT_STORED_VERSION);
            writer.bytes(&contact.salt);
            writer.bytes(&contact.peer_static);
            writer.bytes(&contact.inbound_relay);
            writer.var(&contact.channel.export()?)?;
            writer.bytes(&id);
            writer.u64(contact.since);
            writer.bytes(&contact.previous_relay);
            writer.u64(contact.rotated_at);
            match &contact.own_address {
                Some(address) => {
                    writer.u8(1);
                    writer.bytes(address);
                }
                None => writer.u8(0),
            }
            writer.u8(u8::from(contact.stale));
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
        let version = contact_version(&mut reader)?;
        let salt = reader.array()?;
        let peer_static = reader.array()?;
        let inbound_relay = if version == 0x01 {
            ANY_RELAY
        } else {
            reader.array()?
        };
        let channel = PairwiseChannel::restore(reader.var()?)?;
        // A form of version 0x03 names the contact, which stays the first
        // queue after a rotation, and the state of the rotation.
        let has_tail = version == CONTACT_ROTATION_VERSION || version == CONTACT_STORED_VERSION;
        let (id, since, previous_relay, rotated_at) = if has_tail {
            (
                reader.array()?,
                reader.u64()?,
                reader.array()?,
                reader.u64()?,
            )
        } else {
            (*channel.inbound().recipient_id(), 0, ANY_RELAY, 0)
        };
        let own_address = if has_tail && reader.u8()? == 1 {
            Some(Zeroizing::new(reader.take(QUEUE_ADDRESS_LEN)?.to_vec()))
        } else {
            None
        };
        let stale = version == CONTACT_STORED_VERSION && reader.u8()? == 1;
        reader.end()?;
        // A store of version 0x01 came from a network with one queue relay,
        // thus the two queues of its contact live at one relay, and the
        // channel names the relay of the outbound one.
        let inbound_relay = if version == 0x01 {
            *channel.outbound().relay_id()
        } else {
            inbound_relay
        };
        self.assign(*channel.inbound().recipient_id(), inbound_relay);
        if let Some(previous) = channel.previous() {
            self.assign(*previous.recipient_id(), previous_relay);
        }
        self.contacts.insert(
            id,
            Contact {
                channel,
                inbound_relay,
                peer_static,
                salt,
                waiting_sends: VecDeque::new(),
                ceremony: None,
                since,
                previous_relay,
                rotated_at,
                own_address,
                stale,
            },
        );
        Ok(ContactId(id))
    }

    /// Takes an invitation of an earlier run from its stored form, and
    /// returns its bundle.
    /// A report queue comes back the same way.
    pub fn restore_notify_queue(&mut self, state: &[u8]) -> Result<[u8; 32], Error> {
        let mut reader = Reader::new(state);
        let is_report = match reader.u8()? {
            NOTIFY_STORED_VERSION => false,
            REPORT_STORED_VERSION => true,
            _ => return Err(Error::Malformed),
        };
        let relay = reader.array()?;
        let inbound = Inbound::restore(&mut reader)?;
        reader.end()?;
        let id = *inbound.recipient_id();
        self.assign(id, relay);
        self.notify.insert(
            id,
            NotifyQueue {
                inbound,
                relay,
                is_report,
            },
        );
        Ok(id)
    }

    /// Ends a notify queue (`NTF-133`): a `DEL` goes to its relay
    /// when a circuit serves it, and the node holds it no more. A relay that
    /// gets no `DEL` ends the queue at its idle lifetime.
    pub fn end_notify_queue<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(held) = self.notify.remove(recipient_id) else {
            return Ok(());
        };
        self.changes.push(StateChange::NotifyQueueEnded {
            queue: *recipient_id,
        });
        self.moved.remove(recipient_id);
        if let Some(slot) = self.slot_of(recipient_id) {
            self.current = slot;
            if let Ok(session_pk) = self.session_pk() {
                let command = held.inbound.delete(&session_pk, random(rng))?;
                self.queue_command(command, Waiting::Other)?;
                self.pump()?;
            }
            if let Some(slot) = self.slots.get_mut(slot) {
                slot.queues.remove(recipient_id);
            }
        }
        Ok(())
    }

    /// The contact that reads `queue`. Its first queue names it, and a
    /// rotation gives it a second one (Part 3 §3.2.6).
    fn contact_of(&self, queue: &[u8; 32]) -> Option<[u8; 32]> {
        if self
            .contacts
            .get(queue)
            .is_some_and(|held| held.channel.reads(queue))
        {
            return Some(*queue);
        }
        self.contacts
            .iter()
            .find(|(_, held)| held.channel.reads(queue))
            .map(|(id, _)| *id)
    }

    /// Each inbound queue of a contact: the current one, and the one that a
    /// rotation replaced.
    fn queues_of(&self, contact: &[u8; 32]) -> Vec<[u8; 32]> {
        self.contacts
            .get(contact)
            .map(|held| {
                core::iter::once(held.channel.inbound())
                    .chain(held.channel.previous())
                    .map(|inbound| *inbound.recipient_id())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The operator of a relay of the set.
    fn operator_of(&self, relay_id: &[u8; 32]) -> Option<[u8; 32]> {
        core::iter::once(&self.ingress)
            .chain(&self.relays)
            .find(|relay| relay.candidate.relay_id == *relay_id)
            .map(|relay| relay.candidate.operator_id)
    }

    /// Starts and ends the queue rotations that are due at `now` (Part 3
    /// §3.2.6). A rotation ends at `ROTATE_GRACE` when no record arrived
    /// on the new queue before (`NET-177`). A queue rotates at its age of
    /// `ROTATE_AFTER` with its own jitter, or at `ROTATE_AFTER_RECORDS`
    /// records (§3.2.4). One call starts one rotation at most, thus the
    /// rotations of a store that comes back after a long pause spread over
    /// the checks.
    pub fn rotate_due<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let mut ended = Vec::new();
        let mut due = None;
        let mut stale = Vec::new();
        for (id, held) in &mut self.contacts {
            if held.since == 0 {
                held.since = now;
                self.moved.insert(*id);
            }
            if held.stale {
                if !self.renewing.contains(id) {
                    stale.push(*id);
                }
                continue;
            }
            if held.channel.previous().is_some() {
                if now.saturating_sub(held.rotated_at) >= ROTATE_GRACE {
                    ended.push(*id);
                }
                continue;
            }
            let inbound = held.channel.inbound();
            let is_old =
                now.saturating_sub(held.since) >= rotate_age(&held.salt, inbound.recipient_id());
            let is_full = inbound.cursor().acked() >= ROTATE_AFTER_RECORDS;
            // The address travels on the ratchet, thus a contact with no
            // sending chain waits.
            if due.is_none()
                && (is_old || is_full || self.forced.contains(id))
                && held.channel.can_send()
                && !self.rotating.contains(id)
            {
                due = Some(*id);
            }
        }
        let mut out = Vec::new();
        for contact in ended {
            out.extend(self.end_rotation(contact, rng)?);
        }
        if let Some(contact) = due {
            self.start_rotation(contact, now, rng)?;
        }
        // NET-325: a stale channel with no renewal that runs starts one.
        for contact in stale {
            self.start_renewal(contact, rng)?;
        }
        Ok(out)
    }

    /// Marks the channel of a contact stale, as a restore does (`NET-325`):
    /// it sends nothing on its ratchet, and a renewal starts at the next
    /// check.
    pub fn mark_stale(&mut self, contact: &ContactId) -> Result<(), Error> {
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        held.stale = true;
        self.moved.insert(contact.0);
        Ok(())
    }

    /// Whether the channel of a contact waits for its renewal.
    pub fn is_stale(&self, contact: &ContactId) -> bool {
        self.contacts.get(&contact.0).is_some_and(|held| held.stale)
    }

    /// Starts the renewal of a stale channel, as the responder, when none
    /// runs (`NET-326`).
    fn start_renewal<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.renewing.contains(&contact) {
            return Ok(());
        }
        self.renewing.insert(contact);
        self.make_queue(Purpose::Renew { contact }, rng)?;
        Ok(())
    }

    /// Sends the bundle of the renewal that this device offers for a
    /// contact to the newest queue of the peer, or starts one (`NET-330`).
    fn offer_renewal<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let offered = self.halves.values().find_map(|half| {
            (half.renews == Some(contact) && matches!(half.setup, Setup::Inviting(_)))
                .then(|| half.bundle.clone())
        });
        let Some(bundle) = offered else {
            self.renewing.remove(&contact);
            return self.start_renewal(contact, rng);
        };
        let sealed = self
            .contacts
            .get(&contact)
            .ok_or(Error::NoPath)?
            .channel
            .outbound()
            .seal_record(L6Kind::Renewal, &bundle, random(rng))?;
        self.send_sealed(sealed, rng)
    }

    /// A renewal bundle of the peer arrived (`NET-327`). Its static key
    /// must be the one that the contact holds. When both channels are
    /// stale, the party with the lower static key answers, and the other
    /// one waits for that answer (`NET-328`).
    fn on_renewal<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        bundle: &[u8],
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let Some(held) = self.contacts.get(&contact) else {
            return Ok(Vec::new());
        };
        let Ok(parsed) = Bundle::parse(bundle) else {
            return Ok(Vec::new());
        };
        if parsed.responder_static_x25519 != held.peer_static || Invitee::check(bundle).is_err() {
            return Ok(Vec::new());
        }
        let is_answering = self
            .halves
            .values()
            .any(|half| half.renews == Some(contact) && matches!(half.setup, Setup::Accepting(_)));
        if is_answering {
            return Ok(Vec::new());
        }
        if held.stale {
            let own = self.root.pairwise_identity(&held.salt).x25519_public();
            if own > held.peer_static {
                return Ok(Vec::new());
            }
        }
        self.renewing.insert(contact);
        self.make_queue(
            Purpose::RenewAccept {
                contact,
                bundle: bundle.to_vec(),
            },
            rng,
        )?;
        Ok(Vec::new())
    }

    /// The renewal of a contact completed: the new channel replaces the
    /// old one, each queue of the old one takes a `DEL`, and each other
    /// renewal of the contact ends (`NET-329`). A peer whose static key is
    /// not the one that the contact holds replaces nothing.
    fn on_renewed<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        half: Taken,
        finished: Finished,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let Some(held) = self.contacts.get(&contact) else {
            return Ok(Vec::new());
        };
        if held.peer_static != finished.peer_static {
            self.renewing.remove(&contact);
            return Ok(Vec::new());
        }
        let ratchet = Ratchet::new(finished.keys, finished.role, Width::W64, now, rng)?;
        let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
        let old = core::mem::replace(
            &mut held.channel,
            PairwiseChannel::new(ratchet, finished.outbound, half.inbound),
        );
        held.inbound_relay = half.inbound_relay;
        held.since = now;
        held.previous_relay = ANY_RELAY;
        held.rotated_at = 0;
        held.own_address = finished.own_address;
        held.stale = false;
        self.moved.insert(contact);
        self.renewing.remove(&contact);
        self.rotating.remove(&contact);
        self.forced.remove(&contact);
        let mut ended: Vec<Inbound> = Vec::new();
        let others: Vec<[u8; 32]> = self
            .halves
            .iter()
            .filter(|(_, other)| other.renews == Some(contact))
            .map(|(queue, _)| *queue)
            .collect();
        for queue in others {
            if let Some(other) = self.halves.remove(&queue) {
                self.changes.push(StateChange::InvitationEnded { queue });
                ended.push(other.inbound);
            }
        }
        let mut events = Vec::new();
        let (inbound, previous) = old.into_inbounds();
        ended.push(inbound);
        ended.extend(previous);
        for inbound in ended {
            let queue = *inbound.recipient_id();
            self.drop_queue(&inbound, rng)?;
            events.push(ClientEvent::QueueEnded { queue });
        }
        if !half.opening.is_empty() {
            // NET-292: the first ratchet record of the initiator opens the
            // sending chain of the responder.
            let record = AppMessage {
                kind: AppKind::QueueAddress,
                msg_id: random(rng),
                sent_at: now.saturating_mul(1_000),
                body: &half.opening,
            };
            let mut app = alloc::vec![0u8; record.len()];
            record.encode(&mut app)?;
            self.send_now(contact, &app, Waiting::Other, now, rng)?;
        }
        self.send_waiting(contact, now, rng)?;
        events.push(ClientEvent::ChannelRenewed {
            contact: ContactId(contact),
        });
        Ok(events)
    }

    /// Sends the `DEL` of a queue on the circuit that serves it, and the
    /// circuit serves it no more. A queue that no circuit serves ends at
    /// `QUEUE_IDLE_TTL`.
    fn drop_queue<R: CryptoRng + ?Sized>(
        &mut self,
        inbound: &Inbound,
        rng: &mut R,
    ) -> Result<(), Error> {
        let queue = *inbound.recipient_id();
        let Some(slot) = self.slot_of(&queue) else {
            return Ok(());
        };
        let current = self.current;
        self.current = slot;
        if let Ok(session_pk) = self.session_pk() {
            let command = inbound.delete(&session_pk, random(rng))?;
            self.queue_command(command, Waiting::Other)?;
            self.pump()?;
        }
        self.current = current;
        if let Some(slot) = self.slots.get_mut(slot) {
            slot.queues.remove(&queue);
        }
        Ok(())
    }

    /// Makes a new queue for a contact at the next rotation check, whatever
    /// the age of the current one (`NET-182`). A [`ClientEvent::QueueRotated`]
    /// gives its address. A rotation that runs serves already.
    pub fn rotate_now(&mut self, contact: &ContactId) -> Result<(), Error> {
        let held = self.contacts.get(&contact.0).ok_or(Error::NoPath)?;
        if held.channel.previous().is_none() && !self.rotating.contains(&contact.0) {
            self.forced.insert(contact.0);
        }
        Ok(())
    }

    /// The peer moved to `address`, which its dead-channel blob gave
    /// (`NET-190`): later records go there, and the address of the inbound
    /// queue of this device goes to the peer on the ratchet (`NET-191`).
    /// With no address of its own this device makes a new queue, whose
    /// address goes the same way.
    pub fn peer_moved<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &ContactId,
        address: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let parsed = QueueAddress::parse(address)?;
        let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
        held.channel.accept_address(&parsed);
        let own = held.own_address.clone();
        let is_stale = held.stale;
        self.moved.insert(contact.0);
        // A stale channel sends nothing, and its renewal gives the peer the
        // queue of this device: the bundle goes again to the new address.
        if is_stale {
            return self.offer_renewal(contact.0, rng);
        }
        match own {
            Some(own) => self.send_control(contact.0, AppKind::QueueAddress, &own, now, rng),
            None => self.rotate_now(contact),
        }
    }

    /// Makes the new queue of a contact at a relay of another operator
    /// than the relay of its inbound queue (Part 3 §3.2.4). With no ready
    /// circuit to such a relay a circuit starts, and a later check makes
    /// the queue. A set with no other operator gives no rotation.
    fn start_rotation<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let old_relay = self
            .contacts
            .get(&contact)
            .ok_or(Error::NoPath)?
            .inbound_relay;
        let old_operator = self.operator_of(&old_relay);
        let is_other = |relay: &[u8; 32], operator: Option<[u8; 32]>| {
            *relay != old_relay && (old_operator.is_none() || operator != old_operator)
        };
        let ready = self.slots.iter().position(|slot| {
            let exit = slot.chain.and_then(|chain| chain.last().copied());
            slot.is_ready()
                && slot.has_room()
                && exit.is_some_and(|exit| is_other(&exit, self.operator_of(&exit)))
        });
        if let Some(slot) = ready {
            self.rotating.insert(contact);
            self.current = slot;
            let handle = self.handle();
            return self.make_queue_here(Purpose::Rotate { contact, now }, handle, rng);
        }
        let targets: Vec<[u8; 32]> = self
            .relays
            .iter()
            .filter(|relay| relay.candidate.queue)
            .filter(|relay| is_other(&relay.candidate.relay_id, Some(relay.candidate.operator_id)))
            .map(|relay| relay.candidate.relay_id)
            .collect();
        if targets.is_empty() {
            return Ok(());
        }
        let draw = usize::from(u16::from_be_bytes(random(rng)));
        match targets.get(draw % targets.len()) {
            Some(target) => self.circuit_to(*target, rng),
            None => Ok(()),
        }
    }

    /// The relay made the new queue of a contact: the channel reads it,
    /// and its address goes to the peer on the ratchet as a record of kind
    /// `0x33` (`NET-176`). A contact that is gone, or that rotates
    /// already, takes no second queue, and the new one ends.
    fn on_rotated<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        inbound: Inbound,
        relay: [u8; 32],
        address: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let Some(held) = self
            .contacts
            .get_mut(&contact)
            .filter(|held| held.channel.previous().is_none())
        else {
            let queue = *inbound.recipient_id();
            let command = inbound.delete(&self.session_pk()?, random(rng))?;
            for slot in &mut self.slots {
                slot.queues.remove(&queue);
            }
            self.queue_command(command, Waiting::Other)?;
            return Ok(Vec::new());
        };
        held.channel.rotate(inbound)?;
        held.previous_relay = core::mem::replace(&mut held.inbound_relay, relay);
        held.since = now;
        held.rotated_at = now;
        held.own_address = Some(Zeroizing::new(address.to_vec()));
        self.forced.remove(&contact);
        self.moved.insert(contact);
        self.send_control(contact, AppKind::QueueAddress, address, now, rng)?;
        Ok(alloc::vec![ClientEvent::QueueRotated {
            contact: ContactId(contact),
            address: address.to_vec(),
        }])
    }

    /// Ends the rotation of a contact: the replaced queue takes a `DEL`
    /// when a circuit serves it (`NET-177`, `NET-178`), and the channel
    /// reads it no more. A relay that gets no `DEL` ends the queue at
    /// `QUEUE_IDLE_TTL`.
    fn end_rotation<R: CryptoRng + ?Sized>(
        &mut self,
        contact: [u8; 32],
        rng: &mut R,
    ) -> Result<Vec<ClientEvent>, Error> {
        let Some(held) = self.contacts.get_mut(&contact) else {
            return Ok(Vec::new());
        };
        let Some(previous) = held.channel.end_previous() else {
            return Ok(Vec::new());
        };
        held.rotated_at = 0;
        held.previous_relay = ANY_RELAY;
        self.moved.insert(contact);
        let queue = *previous.recipient_id();
        if let Some(slot) = self.slot_of(&queue) {
            let current = self.current;
            self.current = slot;
            if let Ok(session_pk) = self.session_pk() {
                let command = previous.delete(&session_pk, random(rng))?;
                self.queue_command(command, Waiting::Other)?;
                self.pump()?;
            }
            self.current = current;
            if let Some(slot) = self.slots.get_mut(slot) {
                slot.queues.remove(&queue);
            }
        }
        Ok(alloc::vec![ClientEvent::QueueEnded { queue }])
    }

    /// Makes a notify queue of Part 8 §8.5.2 (`NTF-090`). A
    /// [`ClientEvent::NotifyQueue`] with the same handle follows.
    pub fn make_notify_queue<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<u64, Error> {
        self.make_queue(Purpose::Notify, rng)
    }

    /// Makes a report queue of Part 12 §12.5.3 for a role of a community.
    /// A [`ClientEvent::ReportQueue`] with the same handle follows. The
    /// node ends it as a notify queue, with
    /// [`ClientNode::end_notify_queue`].
    pub fn make_report_queue<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<u64, Error> {
        self.make_queue(Purpose::Report, rng)
    }

    /// Takes an invitation of an earlier run from its stored form.
    pub fn restore_invitation(&mut self, state: &[u8]) -> Result<Vec<u8>, Error> {
        let mut reader = Reader::new(state);
        let version = reader.u8()?;
        let names_relay = match version {
            0x01 => false,
            STORED_VERSION | RENEWAL_STORED_VERSION => true,
            _ => return Err(Error::Malformed),
        };
        let salt = reader.array()?;
        let inbound_relay = if names_relay {
            reader.array()?
        } else {
            ANY_RELAY
        };
        let bundle = reader.var()?.to_vec();
        let inbound = Inbound::restore(&mut reader)?;
        let inviter = Inviter::from_prekey_seed(Secret::new(reader.array()?));
        let renews = if version == RENEWAL_STORED_VERSION {
            Some(reader.array()?)
        } else {
            None
        };
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
                renews,
            },
        );
        // A renewal is no invitation of the user, and no view shows it.
        if let Some(contact) = renews {
            self.renewing.insert(contact);
            return Ok(Vec::new());
        }
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
        writer.u8(match half.renews {
            Some(_) => RENEWAL_STORED_VERSION,
            None => STORED_VERSION,
        });
        writer.bytes(&half.salt);
        writer.bytes(&half.inbound_relay);
        writer.var(&half.bundle)?;
        half.inbound.export(&mut writer)?;
        writer.bytes(seed.expose());
        if let Some(contact) = half.renews {
            writer.bytes(&contact);
        }
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
        let contacts = self.contacts.values().flat_map(|contact| {
            core::iter::once(contact.channel.inbound()).chain(contact.channel.previous())
        });
        let stored = contacts
            .chain(self.halves.values().map(|half| &half.inbound))
            .chain(self.notify.values().map(|held| &held.inbound));
        for inbound in stored.filter(|inbound| queues.contains(inbound.recipient_id())) {
            let queue = *inbound.recipient_id();
            commands.push((
                inbound.subscribe(&session_pk, random(rng))?,
                Waiting::Subscribe(queue),
            ));
            if let Some(command) = inbound.acknowledge_again(&session_pk, random(rng))? {
                commands.push((command, Waiting::Other));
            }
        }
        for (command, waiting) in commands {
            self.queue_command(command, waiting)?;
        }
        self.pump()
    }

    /// Ends each circuit whose build ran past `CIRCUIT_BUILD_TIMEOUT` with
    /// a `DESTROY` cell (`NET-169`). The first tick that sees a build
    /// stamps it, thus the end comes at most one tick late. A relay that
    /// drops an `EXTEND` sends nothing back, and without this the build
    /// waits for ever.
    ///
    /// A group node fails the commands that waited for a circuit to one
    /// relay: a replica on a relay that is down is the case that the
    /// second replica exists for (`GRP-390`). The session runs on while
    /// another circuit builds or serves, thus one relay that is down stops
    /// no other contact and no other group. With none left the node gives
    /// `CircuitLost`, which the runtime reads as a build that failed.
    ///
    /// A ready circuit near `CIRCUIT_MAX_AGE` gives `CircuitAged`
    /// (`NET-320`).
    pub fn on_tick(&mut self, now: u64) -> Vec<ClientEvent> {
        let mut has_ended = false;
        let mut has_aged = false;
        let mut unreachable = Vec::new();
        let mut destroys = Vec::new();
        let is_group = matches!(self.range, Range::Group | Range::Community);
        let old = CIRCUIT_MAX_AGE.saturating_sub(CIRCUIT_AGE_MARGIN);
        for slot in &mut self.slots {
            if matches!(slot.circuit, Circuit::None) {
                slot.born = None;
            } else {
                let born = *slot.born.get_or_insert(now);
                has_aged |= slot.is_ready() && now.saturating_sub(born) >= old;
                if let Circuit::Ready(session) = &slot.circuit {
                    let (sent, received) = session.cells();
                    let full = CIRCUIT_MAX_CELLS.saturating_sub(CIRCUIT_CELL_MARGIN);
                    has_aged |= sent >= full || received >= full;
                }
            }
            if !matches!(slot.circuit, Circuit::Building { .. }) {
                slot.building_since = None;
                continue;
            }
            let since = *slot.building_since.get_or_insert(now);
            if now.saturating_sub(since) < CIRCUIT_BUILD_TIMEOUT {
                continue;
            }
            if let Circuit::Building { mut build, .. } =
                core::mem::replace(&mut slot.circuit, Circuit::None)
            {
                destroys.extend(destroy_cell(&mut build));
            }
            slot.building_since = None;
            has_ended = true;
            // A circuit of another range to one relay stays empty, and the
            // next run builds it again (`NET-024`).
            if let Some(relay) = slot.exit.filter(|_| is_group) {
                unreachable.push(relay);
            }
        }
        for cell in destroys {
            // A link that is gone carries no cell, and the relay ends the
            // circuit with it.
            let _ = self.send_cell(&cell);
        }
        let mut events = Vec::new();
        for relay in unreachable {
            events.extend(self.release_held_groups(&relay));
        }
        let is_left = self
            .slots
            .iter()
            .any(|slot| !matches!(slot.circuit, Circuit::None));
        if has_ended && !is_left {
            events.push(ClientEvent::CircuitLost);
        }
        if has_aged {
            events.push(ClientEvent::CircuitAged);
        }
        events
    }

    /// Fails each group command that waits for a circuit to `relay`, when
    /// no circuit to it builds or runs any more.
    fn release_held_groups(&mut self, relay: &[u8; 32]) -> Vec<ClientEvent> {
        let is_live =
            |slot: &Slot| slot.exit == Some(*relay) && !matches!(slot.circuit, Circuit::None);
        if self.slots.iter().any(is_live) {
            return Vec::new();
        }
        let (gone, kept): (Vec<HeldGroup>, Vec<HeldGroup>) = core::mem::take(&mut self.held_groups)
            .into_iter()
            .partition(|held| held.relay == *relay);
        self.held_groups = kept;
        gone.into_iter()
            .map(|held| ClientEvent::Group {
                handle: held.handle,
                outcome: GroupOutcome::Unreachable,
            })
            .collect()
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

    /// The inbound queue of a contact, the relay that holds it, and
    /// whether the channel still reads the queue that a rotation replaced.
    pub fn inbound_queue(&self, contact: &ContactId) -> Option<([u8; 32], [u8; 32], bool)> {
        self.contacts.get(&contact.0).map(|held| {
            (
                *held.channel.inbound().recipient_id(),
                held.inbound_relay,
                held.channel.previous().is_some(),
            )
        })
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
        self.build_current(rng)
    }

    /// Chooses a chain for the current circuit and sends its first
    /// `EXTEND`.
    fn build_current<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.slot_mut()?.chain = None;
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
        // A new circuit in an old slot has an age of its own.
        if build.built() == 0 {
            self.slot_mut()?.born = None;
        }
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

    /// Each inbound queue that a ready circuit serves, with the relay that
    /// holds it: the queues that a push can wake (Part 8 §8.2.1).
    pub fn inbound_queues(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.slots
            .iter()
            .filter(|slot| slot.is_ready())
            .filter_map(|slot| {
                let relay = slot.chain?.last().copied()?;
                Some(slot.queues.iter().map(move |queue| (*queue, relay)))
            })
            .flatten()
            .collect()
    }

    /// The inbound end of a stored queue: of a contact, or of a
    /// handshake that runs.
    fn inbound_of(&self, recipient_id: &[u8; 32]) -> Option<&Inbound> {
        self.contacts
            .values()
            .flat_map(|contact| {
                core::iter::once(contact.channel.inbound()).chain(contact.channel.previous())
            })
            .chain(self.halves.values().map(|half| &half.inbound))
            .chain(self.notify.values().map(|held| &held.inbound))
            .find(|inbound| inbound.recipient_id() == recipient_id)
    }

    /// Sends the `NKEY` of an inbound queue on the circuit that serves it
    /// (`NTF-112`). A [`ClientEvent::NotifyKey`] carries the answer.
    pub fn notify_queue<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        self.current = self.slot_of(recipient_id).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        // The notifier key of §8.2.4 serves no party of this revision: the
        // relay pushes, and no NDR subscribes. A fresh value names nothing.
        let notifier_pk: [u8; 32] = random(rng);
        let command = self
            .inbound_of(recipient_id)
            .ok_or(Error::NoPath)?
            .notifier_key(&session_pk, random(rng), &notifier_pk)?;
        self.queue_command(command, Waiting::Notify(*recipient_id))?;
        self.pump()
    }

    /// Sends the `NBIND` of an inbound queue: the binding sealed to the
    /// notification key of its relay (`NTF-113`).
    pub fn bind_queue<R: CryptoRng + ?Sized>(
        &mut self,
        recipient_id: &[u8; 32],
        sealed: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        self.current = self.slot_of(recipient_id).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        let command = self.inbound_of(recipient_id).ok_or(Error::NoPath)?.bind(
            &session_pk,
            random(rng),
            sealed,
        )?;
        self.queue_command(command, Waiting::Other)?;
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

    /// A node that carries group-queue commands alone (`GRP-186`). One
    /// circuit of it serves one group queue (`GRP-187`).
    pub fn for_groups(ingress: RelayInfo, relays: Vec<RelayInfo>, root: RootIdentity) -> Self {
        let mut node = Self::with_relays(ingress, relays, root);
        node.range = Range::Group;
        node
    }

    /// A node that carries community commands alone (`WIR-309`). One
    /// circuit of it serves one community (`COM-173`).
    pub fn for_communities(ingress: RelayInfo, relays: Vec<RelayInfo>, root: RootIdentity) -> Self {
        let mut node = Self::with_relays(ingress, relays, root);
        node.range = Range::Community;
        node
    }

    /// Sends one community command to `relay` on a circuit that serves this
    /// community and no other (`COM-173`). With no such circuit the command
    /// waits, and a circuit starts. A [`ClientEvent::Group`] with the handle
    /// follows a `PAGE`, a `PUBACK`, or a refusal; an `NREG` gives none.
    pub fn community<R: CryptoRng + ?Sized>(
        &mut self,
        relay: [u8; 32],
        community_id: [u8; 32],
        job: CommunityJob,
        rng: &mut R,
    ) -> Result<u64, Error> {
        if self.range != Range::Community {
            return Err(Error::Malformed);
        }
        self.bound_command(relay, community_id, GroupJob::Community(job), rng)
    }

    /// Sends one group-queue command to `relay` on a circuit that serves
    /// this group queue and no other. With no such circuit the command
    /// waits, and a circuit starts. A [`ClientEvent::Group`] with the
    /// handle follows an answer or a refusal.
    ///
    /// `group_queue_id` is zero for a `GroupJob::Create`, because the relay
    /// draws that value (`NET-224`).
    pub fn group<R: CryptoRng + ?Sized>(
        &mut self,
        relay: [u8; 32],
        group_queue_id: [u8; 32],
        job: GroupJob,
        rng: &mut R,
    ) -> Result<u64, Error> {
        if self.range != Range::Group || matches!(job, GroupJob::Community(_)) {
            return Err(Error::Malformed);
        }
        self.bound_command(relay, group_queue_id, job, rng)
    }

    /// Sends a command of a range where one circuit serves one queue: a
    /// group queue, or a community.
    fn bound_command<R: CryptoRng + ?Sized>(
        &mut self,
        relay: [u8; 32],
        group_queue_id: [u8; 32],
        job: GroupJob,
        rng: &mut R,
    ) -> Result<u64, Error> {
        let handle = self.handle();
        let held = HeldGroup {
            relay,
            group_queue_id,
            handle,
            job,
        };
        if self.group_slot(&relay, &group_queue_id).is_some() {
            self.start_group(held, rng)?;
        } else {
            self.held_groups.push(held);
            // A command that no circuit can reach does not wait for ever.
            if let Err(error) = self.circuit_for_group(relay, rng) {
                self.held_groups.retain(|held| held.handle != handle);
                return Err(error);
            }
        }
        Ok(handle)
    }

    /// A ready circuit that ends at `relay` and that serves this group
    /// queue or none at all (`GRP-187`).
    fn group_slot(&self, relay: &[u8; 32], group_queue_id: &[u8; 32]) -> Option<usize> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let exit = slot.chain.and_then(|chain| chain.last().copied());
            let free = slot.queues.is_empty() && slot.reserved == 0;
            let serves = free || slot.queues.contains(group_queue_id);
            (slot.is_ready() && exit == Some(*relay) && serves).then_some(index)
        })
    }

    /// Starts a circuit for a group queue at `relay`, when no circuit of
    /// this client is free for it.
    fn circuit_for_group<R: CryptoRng + ?Sized>(
        &mut self,
        relay: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let free_for_it = |slot: &Slot| {
            let ends_there = match slot.chain {
                Some(chain) => chain.last() == Some(&relay),
                None => slot.exit == Some(relay),
            };
            let is_live = !matches!(slot.circuit, Circuit::None);
            ends_there && is_live && slot.queues.is_empty() && slot.reserved == 0
        };
        if self.slots.iter().any(free_for_it) {
            return Ok(());
        }
        let current = self.current;
        // A circuit to this relay whose build ended builds again in its own
        // slot, thus the dead slot does not hold its commands for ever.
        let dead = |slot: &Slot| slot.exit == Some(relay) && matches!(slot.circuit, Circuit::None);
        let started = match self.slots.iter().position(dead) {
            Some(index) => {
                self.current = index;
                self.build_current(rng)
            }
            None => self.add_circuit(Some(relay), rng),
        };
        let is_building = !matches!(self.slot().map(|slot| &slot.circuit), Ok(Circuit::None));
        self.current = current;
        started?;
        // NET-033: no conformant chain reaches the relay in this run.
        if is_building {
            Ok(())
        } else {
            Err(Error::NoPath)
        }
    }

    /// Signs a group-queue command for the session of its circuit, and
    /// queues it.
    fn start_group<R: CryptoRng + ?Sized>(
        &mut self,
        held: HeldGroup,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.current = self
            .group_slot(&held.relay, &held.group_queue_id)
            .ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        if let GroupJob::Community(job) = held.job {
            return self.start_community(held.group_queue_id, held.handle, job, &session_pk, rng);
        }
        let (cmd, signer, payload) = match held.job {
            // The community path returned above.
            GroupJob::Community(_) => return Err(Error::Malformed),
            GroupJob::Create {
                read_pk,
                write_pk,
                own,
            } => {
                let new = GnewPayload {
                    read_pk,
                    write_pk,
                    own_pk: *umbra_crypto::x25519::PublicKey::from(&own).as_bytes(),
                    admission: Admission::NONE,
                };
                let mut payload = alloc::vec![0u8; GNEW_NONE_LEN];
                let used = new.encode(&mut payload)?;
                payload.truncate(used);
                (GroupCmd::Gnew, own, payload)
            }
            GroupJob::Post { write, record } => {
                // WIR-370: the record fills the row of its bucket.
                if smallest_bucket(record.len().saturating_add(COMMAND_HEADER))
                    .is_none_or(|bucket| bucket.group_record() != record.len())
                {
                    return Err(Error::Malformed);
                }
                (GroupCmd::Gpost, write, record)
            }
            GroupJob::Subscribe { read, from_seq } => {
                let mut payload = alloc::vec![0u8; 4];
                encode_gsub(from_seq, &mut payload)?;
                (GroupCmd::Gsub, read, payload)
            }
            GroupJob::Unsubscribe { read } => (GroupCmd::Gunsub, read, Vec::new()),
            GroupJob::Rotate {
                own,
                next_own_pk,
                read_pk,
                write_pk,
            } => {
                let own_pk =
                    next_own_pk.unwrap_or(*umbra_crypto::x25519::PublicKey::from(&own).as_bytes());
                let mut payload = alloc::vec![0u8; GKEY_LEN];
                GkeyPayload {
                    read_pk,
                    write_pk,
                    own_pk,
                }
                .encode(&mut payload)?;
                (GroupCmd::Gkey, own, payload)
            }
            GroupJob::Delete { own } => (GroupCmd::Gdel, own, Vec::new()),
            GroupJob::Notify { read, queue, on } => {
                if queue.len() != NOTIFY_REGISTRATION_LEN.saturating_sub(1) {
                    return Err(Error::Malformed);
                }
                let mut payload = alloc::vec![0x01u8];
                payload.extend_from_slice(&queue);
                let cmd = if on {
                    GroupCmd::Gnreg
                } else {
                    GroupCmd::Gnunreg
                };
                (cmd, read, payload)
            }
        };
        let creates = cmd == GroupCmd::Gnew;
        // GRP-187: the circuit serves this group queue from here on.
        if let Some(slot) = self.slots.get_mut(self.current) {
            if creates {
                slot.reserved = slot.reserved.saturating_add(1);
            } else {
                slot.queues.insert(held.group_queue_id);
            }
        }
        let mut command = Command {
            cmd: Cmd::Group(cmd),
            corr_id: random(rng),
            queue_id: held.group_queue_id,
            auth: [0; 32],
            payload: &payload,
        };
        let key = CommandAuthKey::derive(&signer, &session_pk).map_err(|_| Error::Unverified)?;
        command.sign(&key, &[])?;
        let mut encoded = alloc::vec![0u8; command.len()];
        command.encode(&mut encoded)?;
        let waiting = if creates || cmd == GroupCmd::Gpost {
            Waiting::Group(Box::new(GroupWait {
                handle: held.handle,
                creates,
            }))
        } else {
            Waiting::Other
        };
        self.queue_command(encoded, waiting)?;
        self.pump()
    }

    /// Signs a community command under `pull_sk` of its community and
    /// queues it on the current circuit, which serves that community from
    /// here on (`COM-173`, `COM-175`, `COM-176`).
    fn start_community<R: CryptoRng + ?Sized>(
        &mut self,
        community_id: [u8; 32],
        handle: u64,
        job: CommunityJob,
        session_pk: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        use crate::community::pull::{CMD_NREG, CMD_NUNREG, CMD_PUB, CMD_PULL};
        let (byte, payload, is_answered) = match job {
            CommunityJob::Pull { request } => (CMD_PULL, request, true),
            CommunityJob::Publish { payload } => (CMD_PUB, payload, true),
            CommunityJob::Notify { registration, on } => {
                (if on { CMD_NREG } else { CMD_NUNREG }, registration, false)
            }
        };
        if let Some(slot) = self.slots.get_mut(self.current) {
            slot.queues.insert(community_id);
        }
        let mut command = Command {
            cmd: Cmd::Community(byte),
            corr_id: random(rng),
            queue_id: community_id,
            auth: [0; 32],
            payload: &payload,
        };
        let signer = StaticSecret::from(*crate::community::pull_secret(&community_id).expose());
        let key = CommandAuthKey::derive(&signer, session_pk).map_err(|_| Error::Unverified)?;
        command.sign(&key, &[])?;
        let mut encoded = alloc::vec![0u8; command.len()];
        command.encode(&mut encoded)?;
        let waiting = if is_answered {
            Waiting::Group(Box::new(GroupWait {
                handle,
                creates: false,
            }))
        } else {
            Waiting::Other
        };
        self.queue_command(encoded, waiting)?;
        self.pump()
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
        // NET-325: a stale channel holds each record until its renewal.
        if held.stale {
            let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
            held.waiting_sends
                .push_back((app.to_vec(), Some(user_handle)));
            self.start_renewal(contact.0, rng)?;
            return Ok(user_handle);
        }
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
        let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
        // NET-325: nothing goes on a stale ratchet.
        if held.stale {
            let user_handle = match waiting {
                Waiting::UserSend(handle) => Some(handle),
                _ => None,
            };
            held.waiting_sends.push_back((app.to_vec(), user_handle));
            return Ok(());
        }
        let channel = &self.contacts.get(&contact).ok_or(Error::NoPath)?.channel;
        let relay = *channel.outbound().relay_id();
        let inbound_slot = self.slot_of(channel.inbound().recipient_id());
        let Some(slot) = self.ready_slot_to(&relay, inbound_slot) else {
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
        let user = match waiting {
            Waiting::UserSend(handle) => Some(handle),
            _ => None,
        };
        self.queue_command(encoded, Waiting::Contact { contact, user })?;
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
            let is_served = self
                .queues_of(&contact)
                .iter()
                .any(|queue| self.slot_of(queue).is_some());
            if is_served && self.acknowledge(&ContactId(contact), now, rng)? {
                return Ok(CoverSlot::Acknowledgment);
            }
        }
        let notify: Vec<[u8; 32]> = self.notify.keys().copied().collect();
        for queue in notify {
            if self.slot_of(&queue).is_some() && self.acknowledge_notify(&queue, now, rng)? {
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
        // The `ACK` goes to the session that serves the queue. During a
        // rotation the contact has two queues, and each one takes its own.
        let queues = self.queues_of(&contact.0);
        let mut served = false;
        for queue in queues {
            let Some(slot) = self.slot_of(&queue) else {
                continue;
            };
            served = true;
            self.current = slot;
            let session_pk = self.session_pk()?;
            let held = self.contacts.get_mut(&contact.0).ok_or(Error::NoPath)?;
            let channel = &mut held.channel;
            let Some((point, encoded)) =
                channel.acknowledge_on(&queue, &session_pk, random(rng), now)?
            else {
                continue;
            };
            channel.acknowledged_on(&queue, point);
            self.moved.insert(contact.0);
            self.queue_command(encoded, Waiting::Other)?;
            self.pump()?;
            return Ok(true);
        }
        if served {
            Ok(false)
        } else {
            Err(Error::NoPath)
        }
    }

    /// Acknowledges the digests of a notify queue under the floor of
    /// `NET-050`, as for a contact.
    fn acknowledge_notify<R: CryptoRng + ?Sized>(
        &mut self,
        queue: &[u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        self.current = self.slot_of(queue).ok_or(Error::NoPath)?;
        let session_pk = self.session_pk()?;
        let held = self.notify.get_mut(queue).ok_or(Error::NoPath)?;
        let Some((point, encoded)) = held.inbound.acknowledge(&session_pk, random(rng), now)?
        else {
            return Ok(false);
        };
        held.inbound.acknowledged(point);
        self.moved.insert(*queue);
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
        let (kind, value, _) = capsule::parse(bytes)?;
        if kind == capsule::CapsuleType::Session {
            return Ok(self.on_destroy(value));
        }
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
        // GRP-187: one circuit takes one group queue, thus a second group
        // at this relay waits for a circuit of its own.
        let mut waits = Vec::new();
        for held in core::mem::take(&mut self.held_groups) {
            if held.relay == exit && self.group_slot(&exit, &held.group_queue_id).is_some() {
                self.start_group(held, rng)?;
            } else {
                waits.push(held);
            }
        }
        self.held_groups = waits;
        for relay in self
            .held_groups
            .iter()
            .map(|held| held.relay)
            .collect::<Vec<_>>()
        {
            self.circuit_for_group(relay, rng)?;
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

    /// The guard ended a circuit of this client (`NET-322`): a relay of
    /// its chain lost a link, or aged it out. The node holds it no more,
    /// and the runtime builds again. Any other session control from a
    /// relay names nothing that a client does.
    fn on_destroy(&mut self, value: &[u8]) -> Vec<ClientEvent> {
        let Ok(SessionControl::Destroy { circ_id }) = SessionControl::parse(value) else {
            return Vec::new();
        };
        let of_circuit = |slot: &Slot| slot.circ_id() == Some(circ_id);
        let Some(slot) = self.slots.iter_mut().find(|slot| of_circuit(slot)) else {
            return Vec::new();
        };
        slot.circuit = Circuit::None;
        alloc::vec![ClientEvent::CircuitLost]
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
                    (Some(Waiting::UserSend(user)), Cmd::Quota)
                    | (
                        Some(Waiting::Contact {
                            user: Some(user), ..
                        }),
                        Cmd::Quota,
                    ) => {
                        out.push(ClientEvent::Accepted { handle: user });
                    }
                    // NTF-112: the `NPK` comes first. The `NID` after it
                    // names no command that waits, and it drops.
                    (Some(Waiting::Notify(recipient_id)), Cmd::Npk) => {
                        out.push(ClientEvent::NotifyKey {
                            recipient_id,
                            relay_ntf_pk: payload,
                        });
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
                    (Some(Waiting::Group(wait)), Cmd::Group(byte)) => {
                        out.extend(self.on_group_answer(*wait, byte, &payload)?);
                    }
                    (Some(Waiting::Group(wait)), Cmd::Community(byte)) => {
                        use crate::community::pull::{CMD_PAGE, CMD_PUBACK};
                        let outcome = match byte {
                            CMD_PAGE => Some(GroupOutcome::Page(payload)),
                            CMD_PUBACK => <[u8; 8]>::try_from(payload.as_slice())
                                .ok()
                                .map(|seq| GroupOutcome::Published(u64::from_be_bytes(seq))),
                            // WIR-494: an answer of another kind belongs to
                            // no command.
                            _ => None,
                        };
                        out.extend(outcome.map(|outcome| ClientEvent::Group {
                            handle: wait.handle,
                            outcome,
                        }));
                    }
                    _ => {}
                },
                CircuitEvent::Rejected { handle, reason } => {
                    let user = match self.waiting.remove(&handle) {
                        Some(Waiting::Queue(keys)) => {
                            if let Some(slot) = self.slots.get_mut(keys.slot) {
                                slot.reserved = slot.reserved.saturating_sub(1);
                            }
                            // A rotation that the relay refused runs again
                            // at a later check.
                            if let Purpose::Rotate { contact, .. } = keys.purpose {
                                self.rotating.remove(&contact);
                                continue;
                            }
                            keys.handle
                        }
                        Some(Waiting::UserSend(user)) => user,
                        // A `SUB` of the current queue of a contact that the
                        // relay does not hold: the queue is gone, thus the
                        // peer cannot write to it, and the contact takes a
                        // new one (Part 3 §3.2.6, `NET-324`).
                        Some(Waiting::Subscribe(queue)) => {
                            if reason == Reject::Rejected {
                                if let Some(contact) = self.contact_of(&queue) {
                                    let is_current =
                                        self.contacts.get(&contact).is_some_and(|held| {
                                            held.channel.inbound().recipient_id() == &queue
                                        });
                                    if is_current {
                                        self.forced.insert(contact);
                                    }
                                }
                            }
                            continue;
                        }
                        // NET-182: a `REJECTED` for a `SEND` under the
                        // newest address of a contact makes the channel dead.
                        Some(Waiting::Contact { contact, user }) => {
                            if reason == Reject::Rejected {
                                out.push(ClientEvent::ChannelDead {
                                    contact: ContactId(contact),
                                });
                            }
                            match user {
                                Some(user) => user,
                                None => continue,
                            }
                        }
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
                        Some(Waiting::Group(wait)) => {
                            out.push(ClientEvent::Group {
                                handle: wait.handle,
                                outcome: GroupOutcome::Refused(reason),
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
                // A `GMSG` carries a `corr_id` of the relay, thus it names
                // no command of this session.
                CircuitEvent::Relay {
                    cmd,
                    queue_id,
                    payload,
                } => {
                    if cmd == Cmd::Group(GroupCmd::Gmsg) {
                        out.extend(group_record(queue_id, &payload));
                    }
                }
            }
        }
        self.pump()?;
        Ok(out)
    }

    /// The relay answered a `GNEW` or a `GPOST`.
    fn on_group_answer(
        &mut self,
        wait: GroupWait,
        byte: GroupCmd,
        payload: &[u8],
    ) -> Result<Vec<ClientEvent>, Error> {
        let outcome = match (wait.creates, byte) {
            (true, GroupCmd::Gids) => {
                let group_queue_id: [u8; 32] = payload.try_into().map_err(|_| Error::Malformed)?;
                // The circuit that carried the `GNEW` serves this queue.
                if let Some(slot) = self.slots.get_mut(self.current) {
                    slot.reserved = slot.reserved.saturating_sub(1);
                    slot.queues.insert(group_queue_id);
                }
                GroupOutcome::Created(group_queue_id)
            }
            (false, GroupCmd::Gseq) => GroupOutcome::Posted(GseqPayload::parse(payload)?.seq),
            // WIR-494: an answer of another kind belongs to no command.
            _ => return Ok(Vec::new()),
        };
        Ok(alloc::vec![ClientEvent::Group {
            handle: wait.handle,
            outcome,
        }])
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
        if matches!(keys.purpose, Purpose::Notify | Purpose::Report) {
            let mut address = alloc::vec![0u8; QUEUE_ADDRESS_LEN];
            own_address().encode(&mut address)?;
            let is_report = matches!(keys.purpose, Purpose::Report);
            let held = NotifyQueue {
                inbound,
                relay: queue_relay,
                is_report,
            };
            self.changes.push(StateChange::NotifyQueue {
                queue: ids.recipient_id,
                state: notify_state(&held)?,
            });
            self.notify.insert(ids.recipient_id, held);
            let event = if is_report {
                ClientEvent::ReportQueue {
                    handle: keys.handle,
                    recipient_id: ids.recipient_id,
                    address,
                }
            } else {
                ClientEvent::NotifyQueue {
                    handle: keys.handle,
                    recipient_id: ids.recipient_id,
                    address,
                }
            };
            return Ok(alloc::vec![event]);
        }
        if let Purpose::Rotate { contact, now } = keys.purpose {
            self.rotating.remove(&contact);
            let mut address = alloc::vec![0u8; QUEUE_ADDRESS_LEN];
            own_address().encode(&mut address)?;
            return self.on_rotated(contact, inbound, queue_relay, &address, now, rng);
        }
        // A renewal keeps the pairwise identity of the contact, thus the
        // static key that the peer holds (Part 3 §3.2.6).
        let (salt, renews) = match &keys.purpose {
            Purpose::Renew { contact } | Purpose::RenewAccept { contact, .. } => {
                let Some(held) = self.contacts.get(contact) else {
                    // The contact left while the relay made the queue.
                    self.renewing.remove(contact);
                    let command = inbound.delete(&session_pk, random(rng))?;
                    self.queue_command(command, Waiting::Other)?;
                    return Ok(Vec::new());
                };
                (held.salt, Some(*contact))
            }
            _ => (keys.salt, None),
        };
        let identity = self.root.pairwise_identity(&salt);

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
            // The notify queue, the report queue, and the rotation took
            // their paths above.
            Purpose::Notify | Purpose::Report | Purpose::Rotate { .. } => {
                return Err(Error::Malformed)
            }
            // NET-326: the bundle goes to the queue of the peer.
            Purpose::Renew { .. } => {
                let (inviter, bundle) = Inviter::issue(&identity, own_address(), rng)?;
                (Setup::Inviting(Box::new(inviter)), None, [0u8; 32], bundle)
            }
            Purpose::RenewAccept { bundle, .. } => {
                opening = alloc::vec![0u8; QUEUE_ADDRESS_LEN];
                own_address().encode(&mut opening)?;
                let peer_static = Bundle::parse(&bundle)?.responder_static_x25519;
                let (invitee, flight1, to) = Invitee::accept(&bundle, &own_address(), rng)?;
                let outbound = Outbound::new(&to);
                let sealed = outbound.seal_record(L6Kind::Handshake, &flight1, random(rng))?;
                self.send_sealed(sealed, rng)?;
                (
                    Setup::Accepting(Box::new(invitee)),
                    Some(outbound),
                    peer_static,
                    Vec::new(),
                )
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
            salt,
            identity,
            inbound,
            setup,
            outbound,
            peer_static,
            bundle: issued,
            opening,
            link,
            inbound_relay: queue_relay,
            renews,
        };
        // An invitation with a link waits for the store of its blob.
        if half.link.is_none() {
            self.invitation_changed(ids.recipient_id, &half)?;
        }
        // NET-326: the bundle of a renewal goes to the queue of the peer,
        // under the queue end-to-end layer alone.
        let offered = match (&half.setup, half.renews) {
            (Setup::Inviting(_), Some(contact)) => Some((contact, half.bundle.clone())),
            _ => None,
        };
        self.halves.insert(ids.recipient_id, half);
        if let Some((contact, bundle)) = offered {
            let sealed = self
                .contacts
                .get(&contact)
                .ok_or(Error::NoPath)?
                .channel
                .outbound()
                .seal_record(L6Kind::Renewal, &bundle, random(rng))?;
            self.send_sealed(sealed, rng)?;
        }
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
        if let Some(held) = self.notify.get_mut(&queue_id) {
            self.moved.insert(queue_id);
            let is_report = held.is_report;
            let opened = held.inbound.open(payload, bucket, now)?;
            // COM-266: a member writes a report record to the queue that
            // the roster names.
            if is_report {
                if let Opened::Record {
                    kind: L6Kind::Report,
                    inner,
                    ..
                } = opened
                {
                    return Ok(alloc::vec![ClientEvent::Report {
                        recipient_id: queue_id,
                        record: inner,
                    }]);
                }
                return Ok(Vec::new());
            }
            // NTF-107: a digest names the group queue that holds records.
            if let Opened::Record {
                kind: L6Kind::NotifyDigest,
                inner,
                ..
            } = opened
            {
                if let Ok(digest) = crate::notify::digest::NotifyDigest::parse(&inner) {
                    return Ok(alloc::vec![ClientEvent::Digest {
                        recipient_id: queue_id,
                        id: digest.id,
                        post_count: digest.post_count,
                    }]);
                }
            }
            return Ok(Vec::new());
        }
        if let Some(contact) = self.contact_of(&queue_id) {
            let held = self.contacts.get_mut(&contact).ok_or(Error::NoPath)?;
            // Each outcome moves the cursor of the queue.
            self.moved.insert(contact);
            // NET-177: a record on the new queue shows that the peer took
            // its address, thus the replaced queue ends.
            let rotated = held.channel.previous().is_some()
                && held.channel.inbound().recipient_id() == &queue_id;
            let mut out = Vec::new();
            let mut ceremony_record = None;
            let received = held
                .channel
                .receive_on(&queue_id, payload, bucket, now, rng)?;
            if let Received::Renewal { bundle, .. } = &received {
                out.extend(self.on_renewal(contact, bundle, rng)?);
                return Ok(out);
            }
            if let Received::App { bytes, .. } = received {
                let parsed = AppMessage::parse(&bytes, Channel::Pairwise).ok();
                match parsed.as_ref().map(|parsed| parsed.kind) {
                    // NET-179, WIR-330: the receiving chain gave the address.
                    Some(AppKind::QueueAddress) => {
                        let address =
                            parsed.and_then(|parsed| QueueAddress::parse(parsed.body).ok());
                        if let Some(address) = address {
                            held.channel.accept_address(&address);
                            out.push(ClientEvent::PeerMoved {
                                contact: ContactId(contact),
                            });
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
                        contact: ContactId(contact),
                        app: bytes,
                    }),
                }
            }
            if let Some((kind, value, answers)) = ceremony_record {
                out.extend(self.on_verification(contact, kind, value, answers, now, rng)?);
            }
            // The record opened the sending chain of an inviter.
            self.send_waiting(contact, now, rng)?;
            if rotated {
                out.extend(self.end_rotation(contact, rng)?);
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
        // The address of the first queue of this device: the invitee gave it
        // in flight 1, and the bundle of the inviter holds it.
        let own_address = if half.opening.is_empty() {
            Bundle::parse(&half.bundle).ok().and_then(|bundle| {
                let mut out = Zeroizing::new(alloc::vec![0u8; QUEUE_ADDRESS_LEN]);
                bundle.queue_address.encode(&mut out).ok().map(|_| out)
            })
        } else {
            Some(Zeroizing::new(half.opening.clone()))
        };
        if let Some(contact) = half.renews {
            let finished = Finished {
                keys,
                peer_static,
                outbound,
                role,
                own_address,
            };
            let taken = Taken {
                inbound: half.inbound,
                inbound_relay: half.inbound_relay,
                opening: half.opening,
            };
            return self.on_renewed(contact, taken, finished, now, rng);
        }
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
                since: now,
                previous_relay: ANY_RELAY,
                rotated_at: 0,
                own_address,
                stale: false,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;

    #[test]
    fn a_build_that_no_relay_answers_ends_after_the_build_timeout() {
        let relay = |number: u8| RelayStatic {
            s: [number; 32],
            relay_id: [number; 32],
        };
        let mut node = ClientNode::new(
            [relay(1), relay(2), relay(3)],
            RootIdentity::new(Secret::new([7; 32])),
        );
        node.connected(&mut Rng(3)).unwrap();
        // The session opens, and the `EXTEND` of hop 1 leaves.
        assert_eq!(node.take_capsules().len(), 2);
        let start = 1_000;
        assert!(node.on_tick(start).is_empty());
        assert!(node.on_tick(start + CIRCUIT_BUILD_TIMEOUT - 1).is_empty());
        assert_eq!(
            node.on_tick(start + CIRCUIT_BUILD_TIMEOUT),
            alloc::vec![ClientEvent::CircuitLost]
        );
        // NET-169: the circuit ends with a `DESTROY` cell.
        assert_eq!(node.take_capsules().len(), 1);
        // The circuit is gone, thus a later tick ends nothing more.
        assert!(node.on_tick(start + 60).is_empty());
        assert!(!node.is_ready());
    }

    fn candidate(number: u8, layer: u8) -> RelayInfo {
        RelayInfo {
            candidate: Candidate {
                relay_id: [number; 32],
                operator_id: [number; 32],
                family_id: [number; 32],
                bloc: BlocId::Own([b'Z', number]),
                asn: 64_500 + u32::from(number),
                v4_prefix: Some([127, number]),
                v6_prefix: None,
                ingress: layer == 1,
                chain: true,
                queue: layer == 3,
                layer,
            },
            key: RelayStatic {
                s: [number; 32],
                relay_id: [number; 32],
            },
        }
    }

    #[test]
    fn a_replica_that_no_build_reaches_fails_its_commands_and_builds_again() {
        let mut node = ClientNode::for_groups(
            candidate(1, 1),
            alloc::vec![candidate(2, 2), candidate(3, 3), candidate(4, 3)],
            RootIdentity::new(Secret::new([7; 32])),
        );
        let mut rng = Rng(5);
        node.connected(&mut rng).unwrap();
        // The first circuit ends at one of the two exits, and the replica
        // sits at the other one, thus it takes a circuit of its own.
        let first_exit = node.slots[0].chain.unwrap()[2];
        let replica = if first_exit == [3; 32] {
            [4; 32]
        } else {
            [3; 32]
        };
        let subscribe = || GroupJob::Subscribe {
            read: StaticSecret::from([4; 32]),
            from_seq: 0,
        };
        let handle = node.group(replica, [9; 32], subscribe(), &mut rng).unwrap();
        assert_eq!(node.slots.len(), 2);
        let start = 1_000;
        assert!(node.on_tick(start).is_empty());
        // The circuit to the replica fails its command alone. The first
        // circuit of the session carries no replica, and its end is the end
        // of the session.
        let events = node.on_tick(start + CIRCUIT_BUILD_TIMEOUT);
        assert!(events.contains(&ClientEvent::Group {
            handle,
            outcome: GroupOutcome::Unreachable,
        }));
        assert!(events.contains(&ClientEvent::CircuitLost));
        // The next command to that relay builds again in the same slot,
        // and does not wait behind the dead one.
        node.group(replica, [9; 32], subscribe(), &mut rng).unwrap();
        assert_eq!(node.slots.len(), 2);
        assert!(node
            .slots
            .iter()
            .any(|slot| matches!(slot.circuit, Circuit::Building { .. })));
        // A relay that no conformant chain reaches refuses the command at
        // once, and holds nothing.
        assert_eq!(
            node.group([8; 32], [9; 32], subscribe(), &mut rng),
            Err(Error::NoPath)
        );
        assert_eq!(node.held_groups.len(), 1);
    }
}
