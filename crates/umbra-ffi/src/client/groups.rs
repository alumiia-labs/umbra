//! The private groups of Part 11 in the store of one device.
//!
//! A group is a conversation beside a contact. Its row holds the stored
//! form of [`Group`], and its `GroupRosterSeed_g` sits in the local
//! identity table of Part 4 §4.7.2 (`GRP-055`), thus the group row alone
//! opens nothing.
//!
//! A group starts with no group queue. The two `GNEW` commands of
//! `GRP-191` wait in a work list, and each answer of a relay fills one
//! replica. The group is ready when both answered.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use umbra_core::{
    group::{
        join::{accept_admit, Admitted, KeyRequestRate},
        presence::{presence_due, Eviction, PresenceTracker},
        receive::Outcome,
        roster::Applied,
        state::{ChunkedEpoch, EpochCarrier, Group, WantedChunk},
        GROUP_REPLICAS, GROUP_SILENT_EVICT, ROSTER_RATE_LIMIT,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{group::MemberKeys, hash::sha3_256, rand_core::CryptoRng, secret::Secret};
use umbra_wire::{
    app::{
        keys::{KeyRequest, KeyScope, KeySupply, SupplyStatus},
        AppKind, AppMessage,
    },
    group::control::{
        ControlType, GrantingEpoch, GroupControl, GroupInvitation, InvitationStage, JoinRecord,
        PlainEpoch, PlainOp, ReplicaRef, Role,
    },
};
use zeroize::Zeroizing;

use super::{stored_message, Client, MESSAGE_PREFIX, OUTBOX};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The state byte of a group row: open.
const OPEN: u8 = 0;
/// The fetches of chunked epoch-key records of one epoch of one group
/// that wait at once.
pub(crate) const EPOCH_CHUNKS_MAX: usize = 4;
/// The state byte of a group whose two replicas refused it (`GRP-210`).
const CLOSED: u8 = 1;
/// The state byte of a group that this device can no longer reach: it
/// lacks the current epoch, and the relay refused its request (`GRP-297`).
const LAPSED: u8 = 2;

/// The byte of an offer that waits for the user.
const OFFERED: u8 = 1;
/// The byte of an offer that this device answered with a `JoinRecord`.
const WAITING: u8 = 2;
/// The byte of a `JoinRecord` that waits for an admin of this device.
const ASKED: u8 = 3;
/// The byte of an admit that waits for the snapshot it names.
const ADMITTED: u8 = 4;
/// The byte of a joiner that an admin added and did not admit yet. The
/// snapshot is on its way to the chunk path, and a second press adds no
/// second member.
const ADDED: u8 = 5;
/// The byte of an admit that this admin sent. The row stays while the add
/// is the head of the roster, thus an epoch that displaces the add finds
/// its joiner (`GRP-420`).
const SENT: u8 = 6;
/// The byte of a group that this device joined. The row stays while its
/// add is the head of the roster, thus a second admit of that admin takes
/// the place of the group (`GRP-421`).
const JOINED: u8 = 7;
/// The byte of such a second admit, which waits for its snapshot.
const READMITTED: u8 = 8;
/// An admit whose snapshot this device rejected (`GRP-327`). The row holds
/// the name of the group for the view (`GRP-328`).
const REFUSED: u8 = 9;

/// The length of `GroupRosterKey_g.pk`, an ML-DSA-65 verifying key.
const ROSTER_PK_LEN: usize = 1_952;

/// One row of the join table.
enum JoinEntry {
    Offer {
        from: ConversationId,
        group_id: [u8; 32],
        creator_roster_pk: Vec<u8>,
        name: String,
    },
    /// The row key names the group, thus these two hold none.
    Waiting {
        creator_roster_pk: Vec<u8>,
        name: String,
    },
    Admitted {
        from: ConversationId,
        creator_roster_pk: Vec<u8>,
        admit: Vec<u8>,
        name: String,
        /// A second admit of `GRP-421`, which replaces the held group.
        again: bool,
    },
    /// An admit that this admin sent, while its add is the head.
    Sent {
        from: ConversationId,
        group_id: [u8; 32],
        index: u16,
        add_epoch: u32,
    },
    /// An admit whose snapshot failed a check (`GRP-327`, `GRP-328`).
    Refused {
        from: ConversationId,
        group_id: [u8; 32],
        name: String,
    },
    /// A group that this device joined, while its add is the head.
    Joined {
        group_id: [u8; 32],
        add_epoch: u32,
        creator_roster_pk: Vec<u8>,
        name: String,
    },
    Asked {
        from: ConversationId,
        group_id: [u8; 32],
        record: Vec<u8>,
    },
    Added {
        from: ConversationId,
        group_id: [u8; 32],
        index: u16,
        /// The snapshot at the roster epoch of the add (`GRP-323`). A row
        /// of an earlier build holds none.
        snapshot: Vec<u8>,
    },
}

/// The offer of §11.9.1 step 1, as a device that got one holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOffer {
    /// The pairwise conversation that carried it.
    pub from: ConversationId,
    /// The group.
    pub group_id: [u8; 32],
    /// The name of the group, as the inviting admin gave it.
    pub name: String,
}

/// What an admin must do after it added a joiner (§11.9.1 step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAdmission {
    /// The `RosterSnapshot` to put on the chunk path (`GRP-323`).
    pub snapshot: Vec<u8>,
    /// The member index that the admin gave the joiner.
    pub index: u16,
}

/// An admit that waits for the snapshot it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAdmitWaiting {
    /// The pairwise conversation that carried it.
    pub from: ConversationId,
    /// The group.
    pub group_id: [u8; 32],
    /// The `FileDescriptor` of the `RosterSnapshot` (`GRP-323`).
    pub descriptor: Vec<u8>,
}

/// A joiner that asked to come in, as the inviting admin holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupJoiner {
    /// The pairwise conversation that carried the record.
    pub from: ConversationId,
    /// The group.
    pub group_id: [u8; 32],
    /// Whether the admin added it already and the admit is on its way.
    pub is_added: bool,
}

/// The stored form of a group: its roster, its epochs, and its replicas.
pub(super) const GROUP: TableId = TableId(0x12);
/// The group queues that a creator asked for and that no relay named yet.
/// A row holds the `group_id`, the replica index, and the relay.
pub(super) const GROUP_QUEUE: TableId = TableId(0x13);
/// The offers that this device got and that the user did not answer, and
/// the join records that an admin of this device did not act on. A row
/// holds the `group_id` and then the `JoinRecord`, or nothing for an
/// offer. The owner column names the pairwise conversation.
pub(super) const GROUP_JOIN: TableId = TableId(0x14);
/// The last roster object that this device posted to a group, under the
/// group conversation. An epoch of another member can take its place under
/// the order of `GRP-117`, and this device then posts it again against the
/// new head (`GRP-119`).
const OWN_EPOCH: TableId = TableId(0x2F);
/// The contact behind a member index, for each member that an admin of
/// this device brought in. The roster names no contact, thus a member that
/// another admin added has no row here and the view shows its index alone.
/// A row holds the pairwise conversation, and its owner column names the
/// group.
pub(super) const GROUP_MEMBER: TableId = TableId(0x15);
/// The activity clocks of §11.9.7: for each member that an admin of this
/// device watches, the time of its last record or presence record, and for
/// each group, the time of the last record of this device. A row holds a
/// `BE64` of seconds, and its owner column names the group.
pub(super) const GROUP_PRESENCE: TableId = TableId(0x16);
/// For each group, the member indices that held the owner credentials of
/// this device when it last took or drew them (`GRP-401`). A member that
/// leaves that set leaves with credentials that the relay still takes,
/// thus its departure calls for new ones. The owner column names the
/// group.
pub(super) const GROUP_OWNERS: TableId = TableId(0x17);
/// The granting epochs on the authority path to a current role
/// (`GRP-068`). A row holds one `GroupControl`, under the group and the
/// `epoch_index` of the grant, and its owner column names the group. A
/// grant on no path leaves when the next snapshot is built (`GRP-069`).
pub(super) const GROUP_GRANTS: TableId = TableId(0x18);
/// The notify queue of each group of Part 8 §8.5.2: its `RecipientId`, its
/// encoded `QueueAddress`, the time of the last `GNREG` at each of the two
/// replicas, the time the queue was made, and the queue that it replaces
/// until that one leaves (`NTF-105`).
pub(super) const GROUP_NOTIFY: TableId = TableId(0x1C);
/// The mark of each message of a group that names this member
/// (Part 11 §11.11), under the row of the message. The mention list itself
/// stays in the record, and no view shows it (`GRP-141`).
pub(super) const MENTIONED: TableId = TableId(0x38);
/// Each record of this device that no replica accepted yet, as it was
/// sealed, with its credentials, its message, and its place in the order
/// of the posts. The next session sends the same bytes (`GRP-392`). A
/// roster object moves the group of this device at its seal, thus a lost
/// one splits the group. A presence is no such record.
const GROUP_UNSENT: TableId = TableId(0x41);
/// The add of each joiner whose admit waits for the `GSEQ` of the add at
/// each replica (`GRP-311`), under the row of the kept record of the add:
/// the row of the join, the joiner, the group, the index, the relay of each
/// replica that the add went to, the replicas that answered, the `seq` at
/// each, then the descriptor of the snapshot once it uploaded.
const ADD_SEQ: TableId = TableId(0x53);
/// The version of an `ADD_SEQ` row (`IMP-130`).
const ADD_SEQ_VERSION: u8 = 0x01;
/// An `ADD_SEQ` row up to its descriptor.
const ADD_SEQ_HEAD: usize = 1 + 16 + 16 + 32 + 2 + 64 + 1 + 4 + 4;

/// One `ADD_SEQ` row.
struct AddSeq {
    join_row: RowId,
    from: ConversationId,
    group_id: [u8; 32],
    index: u16,
    /// The relay of each replica that the add went to.
    relays: [[u8; 32]; GROUP_REPLICAS],
    /// Bit `i` is set when replica `i` returned its `GSEQ`.
    answered: u8,
    seqs: [u32; 2],
    descriptor: Option<Vec<u8>>,
}

impl AddSeq {
    fn encode(&self) -> Vec<u8> {
        let descriptor = self.descriptor.as_deref().unwrap_or_default();
        let mut out = Vec::with_capacity(ADD_SEQ_HEAD.saturating_add(descriptor.len()));
        out.push(ADD_SEQ_VERSION);
        out.extend_from_slice(&self.join_row);
        out.extend_from_slice(&self.from.0);
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        for relay in &self.relays {
            out.extend_from_slice(relay);
        }
        out.push(self.answered);
        out.extend_from_slice(&self.seqs[0].to_be_bytes());
        out.extend_from_slice(&self.seqs[1].to_be_bytes());
        out.extend_from_slice(descriptor);
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (head, descriptor) = bytes
            .split_at_checked(ADD_SEQ_HEAD)
            .ok_or(Error::Integrity)?;
        let mut r = umbra_wire::codec::Reader::new(head);
        if r.u8()? != ADD_SEQ_VERSION {
            return Err(Error::Integrity);
        }
        let join_row: RowId = r.take(16)?.try_into().map_err(|_| Error::Integrity)?;
        let from = ConversationId(r.take(16)?.try_into().map_err(|_| Error::Integrity)?);
        let group_id: [u8; 32] = r.take(32)?.try_into().map_err(|_| Error::Integrity)?;
        let index = r.u16()?;
        let relays = [
            r.take(32)?.try_into().map_err(|_| Error::Integrity)?,
            r.take(32)?.try_into().map_err(|_| Error::Integrity)?,
        ];
        let answered = r.u8()?;
        let seqs = [r.u32()?, r.u32()?];
        Ok(Self {
            join_row,
            from,
            group_id,
            index,
            relays,
            answered,
            seqs,
            descriptor: (!descriptor.is_empty()).then(|| descriptor.to_vec()),
        })
    }
}
/// The version of a `GkeyRow` (`IMP-130`).
const GKEY_ROW_VERSION: u8 = 0x01;

/// What this device knows of the `GKEY` commands of one group, in a row of
/// `GROUP_OWNERS` beside the admins of that group. A `GKEY` has no answer,
/// thus the row holds what the device still sends.
#[derive(Default)]
struct GkeyRow {
    /// For each replica, `write_pk` of the epoch whose `GKEY` arrived
    /// there, or none (`GRP-361`, `GRP-363`).
    taken: [Option<[u8; 32]>; GROUP_REPLICAS],
    /// For each replica, each owner credential that the current one
    /// replaced and whose `GKEY` did not arrive yet, the oldest first. The
    /// replica holds the `own_pk` of one of them, or of the current one
    /// (`GRP-401`, `WIR-522`).
    replaced: [Vec<Secret<32>>; GROUP_REPLICAS],
}

impl GkeyRow {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![GKEY_ROW_VERSION]);
        for (taken, replaced) in self.taken.iter().zip(&self.replaced) {
            out.push(u8::from(taken.is_some()));
            out.extend_from_slice(&taken.unwrap_or_default());
            out.push(u8::try_from(replaced.len()).unwrap_or(u8::MAX));
            for before in replaced.iter().take(usize::from(u8::MAX)) {
                out.extend_from_slice(before.expose());
            }
        }
        out
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let mut r = umbra_wire::codec::Reader::new(bytes);
        if r.u8().ok()? != GKEY_ROW_VERSION {
            return None;
        }
        let mut held = GkeyRow::default();
        for (taken, replaced) in held.taken.iter_mut().zip(&mut held.replaced) {
            let is_taken = r.u8().ok()? == 1;
            let write_pk: [u8; 32] = r.take(32).ok()?.try_into().ok()?;
            *taken = is_taken.then_some(write_pk);
            for _ in 0..r.u8().ok()? {
                replaced.push(Secret::new(r.take(32).ok()?.try_into().ok()?));
            }
        }
        Some(held)
    }
}

const GROUP_NOTIFY_LEN_V1: usize = 32 + umbra_wire::address::LEN + 16;
const GROUP_NOTIFY_LEN: usize = GROUP_NOTIFY_LEN_V1 + 8 + 1 + 32 + umbra_wire::address::LEN;
/// A registration lives 7 days plus `CLOCK_SKEW` at a group-queue relay
/// (`NTF-102`), thus a device registers again after 6 days.
pub const NOTIFY_REREGISTER: u64 = 6 * 86_400;

/// A `RecipientId` of a queue, with the conversation of that queue.
pub type QueueOf = ([u8; 32], [u8; 16]);

/// The notify queue of one group, as its row holds it.
struct NotifyRow {
    queue: [u8; 32],
    address: Vec<u8>,
    /// The time of the last `GNREG` at each replica, or 0.
    times: [u64; 2],
    /// The time the queue was made, or 0 for a row of the first form.
    created_at: u64,
    /// The queue that this one replaces, until its `GNUNREG` leaves.
    previous: Option<([u8; 32], Vec<u8>)>,
}

impl NotifyRow {
    fn encode(&self) -> Vec<u8> {
        let (flag, prev_queue, prev_address) = match &self.previous {
            Some((queue, address)) => (1u8, *queue, address.clone()),
            None => (0u8, [0u8; 32], vec![0u8; umbra_wire::address::LEN]),
        };
        [
            self.queue.as_slice(),
            &self.address,
            &self.times[0].to_be_bytes(),
            &self.times[1].to_be_bytes(),
            &self.created_at.to_be_bytes(),
            &[flag],
            &prev_queue,
            &prev_address,
        ]
        .concat()
    }
}

/// The end of one notify queue: the `GNUNREG` at each replica that the
/// device can still sign, and the queue that the run ends.
pub struct NotifyEnding {
    /// The group.
    pub conversation: ConversationId,
    /// The `GNUNREG` commands.
    pub unregistrations: Vec<NotifyRegistration>,
    /// The notify queues that end.
    pub queues: Vec<[u8; 32]>,
}

/// One `GNREG` that is due at one replica (`NTF-093`).
pub struct NotifyRegistration {
    /// The group.
    pub conversation: ConversationId,
    /// Which replica, 0 or 1.
    pub which: usize,
    /// A `GNREG`, or a `GNUNREG`.
    pub on: bool,
    /// The relay.
    pub relay: [u8; 32],
    /// The group queue at that relay.
    pub group_queue_id: [u8; 32],
    /// `read_sk` of the epoch.
    pub read: Secret<32>,
    /// The encoded `QueueAddress` of the notify queue.
    pub queue: Vec<u8>,
}

const QUEUE_ROW_LEN: usize = 32 + 1 + 32;

/// The longest name of a group on this device.
pub const GROUP_NAME_MAX: usize = 64;

/// What a client shows of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    /// The conversation.
    pub conversation: ConversationId,
    /// The group identifier, which no relay reads (`GRP-151`).
    pub group_id: [u8; 32],
    /// The index of this device in the roster.
    pub own_index: u16,
    /// The active members.
    pub members: u32,
    /// The group epoch.
    pub epoch: u32,
    /// Whether both replicas hold a group queue. Until then no record goes
    /// out (`GRP-191`).
    pub is_ready: bool,
    /// Whether each replica refused the group queue, thus the group is
    /// closed and this device sends nothing more (`GRP-210`).
    pub is_closed: bool,
    /// Whether this device lacks the current epoch and the relay refused
    /// its request, thus it needs a new invitation (`GRP-297`).
    pub is_lapsed: bool,
    /// Whether the roster still holds this device. A removal and a
    /// self-removal both take it away (`GRP-067`, `GRP-382`).
    pub is_member: bool,
    /// Whether no replica of the group answered its last session, thus
    /// the view shows the line of `GRP-199`.
    pub is_unreachable: bool,
    /// Whether a record waits for a clock check (`GRP-229`).
    pub is_clock_suspect: bool,
}

/// One `GNEW` that waits for a circuit to its relay.
pub struct GroupQueueJob {
    /// The group.
    pub group_id: [u8; 32],
    /// The replica, 0 or 1.
    pub replica: u8,
    /// The relay that takes the `GNEW`.
    pub relay: [u8; 32],
    /// `read_pk` of epoch 1.
    pub read_pk: [u8; 32],
    /// `write_pk` of epoch 1.
    pub write_pk: [u8; 32],
    /// The owner credential of this replica (`GRP-190`).
    pub own: Secret<32>,
}

/// One `GSUB` that a group needs, at one replica (`GRP-203`).
pub struct GroupSubscription {
    /// The conversation of the group.
    pub conversation: ConversationId,
    /// The relay.
    pub relay: [u8; 32],
    /// The group queue at that relay.
    pub group_queue_id: [u8; 32],
    /// `read_sk` of the epoch.
    pub read: Secret<32>,
    /// `read_sk` of the previous epoch inside its grace (`GRP-398`).
    pub fallback: Option<Secret<32>>,
    /// The cursor of this device at that replica (`GRP-202`).
    pub from_seq: u32,
}

/// One member of a group, as the member list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    /// The member index.
    pub index: u16,
    /// The role.
    pub role: Role,
    /// Whether the index is this device.
    pub is_self: bool,
    /// The contact behind the member, where this device knows it.
    pub contact: Option<ConversationId>,
}

/// What an admin does about a member that stayed silent (§11.9.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    /// Remove the member with a plain epoch (`GRP-133`).
    Remove,
    /// Take the role of a moderator first (`GRP-166`). The removal follows
    /// after `ROSTER_RATE_LIMIT`.
    Demote,
}

/// One replica of a group queue, as a post names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupReplica {
    /// The relay.
    pub relay: [u8; 32],
    /// The group queue at that relay.
    pub group_queue_id: [u8; 32],
}

/// One record that waits for the run of the group queues. The same bytes
/// go to each replica (`GRP-194`).
pub struct GroupPost {
    /// The message of this device that the record carries, or none for a
    /// roster object, which no view shows.
    pub message: Option<MsgRef>,
    /// The conversation.
    pub conversation: ConversationId,
    /// The two replicas.
    pub replicas: [GroupReplica; GROUP_REPLICAS],
    /// `write_sk` of the epoch.
    pub write: Secret<32>,
    /// `write_sk` of the previous epoch inside its grace. The relay takes
    /// the pair of an epoch only at a `GKEY` (`GRP-398`).
    pub fallback: Option<Secret<32>>,
    /// The sealed `GroupQueueRecord`.
    pub record: Vec<u8>,
    /// Whether the record starts an epoch. A `GKEY` follows it at the
    /// replica that accepted it, and never before (`GRP-362`).
    pub is_rotation: bool,
    /// The row that keeps the record until each replica accepted it or
    /// gave up.
    pub unsent: Option<[u8; 16]>,
    /// The replicas that still take the record: a replica that accepted it
    /// or gave up takes it no more (`NET-258`, `NET-271`).
    pub pending: [bool; GROUP_REPLICAS],
}

/// The ARQ of one replica of a kept record (`NET-271`): whether it
/// accepted or gave up, the count of its sends, and the time of its first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReplicaArq {
    state: u8,
    attempts: u32,
    first: u64,
}

/// A replica that still takes the record.
const REPLICA_PENDING: u8 = 0;
/// A replica that returned a `GSEQ`.
const REPLICA_ACCEPTED: u8 = 1;
/// A replica whose ARQ ended under `NET-220`.
const REPLICA_GAVE_UP: u8 = 2;

impl ReplicaArq {
    /// Ends the ARQ at `SEND_MAX_ATTEMPTS` sends or at `SEND_GIVE_UP` after
    /// the first one.
    fn check(&mut self, now: u64) {
        let ran_out = self.attempts >= umbra_queue::params::SEND_MAX_ATTEMPTS
            || (self.first != 0
                && now.saturating_sub(self.first) >= umbra_queue::params::SEND_GIVE_UP);
        if self.state == REPLICA_PENDING && ran_out {
            self.state = REPLICA_GAVE_UP;
        }
    }
}

/// One `GKEY` at one replica, which moves that replica to the credentials
/// of the epoch this device holds (`GRP-361`, `GRP-363`).
pub struct GroupRekey {
    /// The relay.
    pub relay: [u8; 32],
    /// The group queue at that relay.
    pub group_queue_id: [u8; 32],
    /// The owner credential of that replica, which authorizes the `GKEY`.
    pub own: Secret<32>,
    /// The owner credential after the `GKEY`, or none to keep `own`
    /// (`WIR-522`).
    pub next_own_pk: Option<[u8; 32]>,
    /// `read_pk` of the epoch.
    pub read_pk: [u8; 32],
    /// `write_pk` of the epoch.
    pub write_pk: [u8; 32],
}

/// The group work that waits for the run of the group queues.
#[derive(Default)]
pub(super) struct GroupQueues {
    pub creations: VecDeque<GroupQueueJob>,
    pub posts: VecDeque<GroupPost>,
    pub rekeys: VecDeque<GroupRekey>,
    /// The instant at which each group may answer its trigger, with the
    /// roster epoch of that trigger (§11.4.1). The backoff lives with the
    /// run, thus a restart draws a new delay.
    pub backoff: BTreeMap<ConversationId, (u32, u64)>,
    /// The instant at which this admin may remove each silent member. Two
    /// admins that count one silence draw two delays, and the removal of
    /// the first reaches the second before its own (`GRP-133`).
    pub evictions: BTreeMap<(ConversationId, u16), u64>,
    /// The member that this admin removes for its silence now, thus the
    /// note of the removal says why (`GRP-050`).
    pub evicting: Option<(ConversationId, u16)>,
    /// Each group with a new note of its roster, for one event after the
    /// others.
    pub noted: BTreeSet<ConversationId>,
    /// The instant at which this admin may draw new owner credentials for
    /// each group that owes them, after the backoff of `GRP-358`.
    pub owner_backoff: BTreeMap<ConversationId, u64>,
    /// The epoch requests of this device for each group, and the time of
    /// the last one (`GRP-295`).
    pub key_requests: BTreeMap<ConversationId, (KeyRequestRate, Option<u64>)>,
    /// The requests of other members that this device answers, with the
    /// instant after the backoff (`GRP-375`).
    pub key_answers: BTreeMap<(ConversationId, u16), u64>,
    /// The requests that this device took in, which drop above the rate
    /// (`GRP-378`). The table holds the epoch requests for each member of
    /// each group, and under no member the snapshot requests of the group.
    /// The rate of `GRP-295` is the rate of one member, thus one member
    /// that asks above it spends the answers of no other member.
    pub key_answers_rate: BTreeMap<(ConversationId, Option<u16>), KeyRequestRate>,
    /// The slot objects of rotations that wait for the chunk path, whose
    /// records follow the upload (`GRP-283`).
    pub epoch_uploads: VecDeque<EpochUpload>,
    /// The groups that showed the `clock` state at the last sweep
    /// (`GRP-229`), thus a change of it draws a list event.
    pub clock_suspect: BTreeSet<ConversationId>,
    /// The time of the last sweep of the held records, in seconds.
    pub swept_at: u64,
    /// The chunks of chunked epoch-key records that this device fetches
    /// (`GRP-284`).
    pub epoch_chunks: VecDeque<(ConversationId, WantedChunk)>,
    /// The groups whose state upload runs (`DEV-298`).
    pub state_out: std::collections::BTreeSet<ConversationId>,
    /// The group states that this device fetches, by the subject of each
    /// group.
    pub state_in: VecDeque<([u8; 32], Box<umbra_wire::descriptor::FileDescriptor>)>,
    /// The groups for which this admin writes a snapshot for a member
    /// behind the roster, with the roster epoch of that member (`GRP-330`).
    pub snapshot_jobs: VecDeque<(ConversationId, u32)>,
    /// The replica that the next `GSUB` of each group takes. The choice
    /// moves to the store when the `GSUB` goes, and not before
    /// (`GRP-204`).
    pub picked: BTreeMap<ConversationId, usize>,
    /// What this device knows of the subscription of each group in this
    /// session (`GRP-396`). A lock ends each one.
    pub watch: BTreeMap<ConversationId, Watch>,
    /// The replicas whose `GNREG` goes again with the `GSUB` of this
    /// session: a relay that started again holds no registration
    /// (`NTF-093`).
    pub notify_again: BTreeSet<(ConversationId, usize)>,
    /// The time of the last send of each kept record to each replica in
    /// this run, for the wait before the next one (`GRP-196`).
    pub resent: BTreeMap<([u8; 16], usize), u64>,
    /// The time of the last look at the kept records that wait.
    pub resend_swept: u64,
    /// The replicas that got a `GKEY` in this session. Each one holds
    /// `write_pk` of the epoch that the `GKEY` carried, and the kept
    /// records that left for it after that. The `GSEQ` of such a record
    /// tells that the `GKEY` before it arrived (`GRP-361`).
    pub gkey_sent: BTreeMap<(ConversationId, usize), GkeySent>,
    /// The groups that this session sent to the other replica for a gap
    /// (`GRP-205`).
    pub repaired: BTreeSet<ConversationId>,
    /// Whether the caller took the subscriptions of a pump and asked for no
    /// other work of it yet. Each read that it names then is a `GSUB` that
    /// goes.
    pub offered: bool,
    /// Whether a run of the group queues asked for the subscriptions of
    /// this device since the unlock. Such a run holds a session for each
    /// group that it reads, and silence then counts in a session alone
    /// (`GRP-396`).
    pub driven: bool,
}

/// The `GKEY` commands that one replica of a group got in this session.
#[derive(Default)]
pub(super) struct GkeySent {
    /// `write_pk` of the epoch that they carried.
    write_pk: [u8; 32],
    /// The kept records that left for that replica after them.
    after: BTreeSet<[u8; 16]>,
}

/// The subscription of one group in one session, as far as this device can
/// tell: a `GSUB` has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Watch {
    /// The replica of the `GSUB`.
    which: usize,
    /// The time of the `GSUB`, in seconds.
    since: u64,
    /// The time of the last record of that replica, or of the `GSUB`.
    last_record: u64,
    /// Whether that replica answered in this session, with a record or
    /// with a `GSEQ`.
    answered: bool,
    /// Whether a record of the current slot came, thus the backlog ended.
    live: bool,
    /// Whether the backlog of the subscription arrived: a record of the
    /// current slot came, or none came for `WATCH_QUIET`.
    caught_up: bool,
    /// The time of the last tick that named this group as read.
    beat: u64,
    /// The time up to which the store counts this group as watched.
    stored: u64,
    /// Whether this session asked the replica for an answer already.
    probed: bool,
}

impl Watch {
    /// The watch of a `GSUB` that goes to replica `which` at `now`.
    const fn start(which: usize, now: u64) -> Self {
        Watch {
            which,
            since: now,
            last_record: now,
            answered: false,
            live: false,
            caught_up: false,
            beat: now,
            stored: 0,
            probed: false,
        }
    }

    /// Whether the device did not run between the last tick and `now`: a
    /// step of more than `CLOCK_SKEW`, or a clock that went back
    /// (`SCP-019`). The subscription may have ended in that time.
    const fn has_hole(&self, now: u64) -> bool {
        now < self.beat || now - self.beat > umbra_core::directory::CLOCK_SKEW
    }

    /// Starts the watch again at `now` after such a hole: the backlog
    /// counts as unread, and the replica must answer again.
    const fn lapse(&mut self, now: u64) {
        self.since = now;
        self.last_record = now;
        self.answered = false;
        self.live = false;
        self.caught_up = false;
        self.probed = false;
    }
}

/// The time with no record after which the backlog of a `GSUB` counts as
/// read. It is above `CIRCUIT_BUILD_TIMEOUT` and above each wait before a
/// second `GSUB` after a `LIMIT`.
const WATCH_QUIET: u64 = 120;
/// The least time between two writes of the watched time of a group. It is
/// also the least gap in that time that moves the clock of each member.
const WATCH_STEP: u64 = 600;
/// The first wait before a kept record goes again to a replica that gave
/// no `GSEQ`. Each send doubles it, up to `RESEND_MAX`.
const RESEND_FIRST: u64 = 30;
/// The longest wait before a kept record goes again: `SEND_MAX_ATTEMPTS`
/// sends then span about four days of the seven of `SEND_GIVE_UP`.
const RESEND_MAX: u64 = 12 * 3_600;
/// The least time between two looks at the kept records that wait.
const RESEND_SWEEP: u64 = 5;
/// The rows of the join table that one contact holds at most (`GRP-170`).
const JOIN_ROWS_MAX: usize = 32;
/// The owner credentials of one replica that wait for their `GKEY` at
/// most. A rotation above it drops the oldest one.
const OWNER_HELD_MAX: usize = 4;

/// The facts of a group before an arrival, which tell what it changed.
pub(super) struct Before {
    epoch: u32,
    /// The rotator of the current secret: a lower index of the same epoch
    /// takes its place (`GRP-273`).
    rotator: Option<u16>,
    owners: Option<[u8; 32]>,
}

impl Before {
    pub(super) fn of(group: &Group) -> Self {
        Before {
            epoch: group.epoch(),
            rotator: group.epoch_rotator(),
            owners: group.owner(0).map(|held| *held.expose()),
        }
    }
}

/// A rotation whose slots go on the chunk path, and whose record follows
/// the upload (`GRP-281` to `GRP-283`).
pub struct EpochUpload {
    /// The group.
    pub conversation: ConversationId,
    /// The epoch that the rotation starts.
    pub epoch: u32,
    /// The slots and the facts of their record.
    pub chunked: ChunkedEpoch,
    /// `write_sk` of the epoch before, under which the record goes.
    pub write: Secret<32>,
    /// The pair before that, when no `GKEY` moved the relay yet.
    pub fallback: Option<Secret<32>>,
    /// The uploads that failed. Past `EPOCH_UPLOAD_TRIES` the members
    /// that lack the epoch ask for it (`GRP-406`).
    pub tries: u8,
}

/// The uploads of one slot object before the rotation gives it up.
const EPOCH_UPLOAD_TRIES: u8 = 3;

/// The key of the clock of the last record of this device in a group.
/// The mark of an epoch that a key supply gave (`WIR-462`).
fn recovered_key(conversation: ConversationId, epoch: u32) -> Vec<u8> {
    [
        conversation.0.as_slice(),
        b"recovered",
        &epoch.to_be_bytes(),
    ]
    .concat()
}

fn sent_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), b"sent"].concat()
}

/// The key of the clock of a re-key of this member that waits for another
/// try, with the time of the first one. Zero means that none waits.
fn rekey_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), b"rekeys"].concat()
}

/// The key of the clock of the time up to which an admin of this device
/// watched a group (`GRP-396`).
fn watch_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), b"watch"].concat()
}

fn queue_row(group_id: &[u8; 32], replica: u8, relay: &[u8; 32]) -> Vec<u8> {
    let mut row = Vec::with_capacity(QUEUE_ROW_LEN);
    row.extend_from_slice(group_id);
    row.push(replica);
    row.extend_from_slice(relay);
    row
}

fn read_queue_row(row: &[u8]) -> Result<([u8; 32], u8, [u8; 32]), Error> {
    let bytes: [u8; QUEUE_ROW_LEN] = row.try_into().map_err(|_| Error::Integrity)?;
    let (group_id, rest) = bytes.split_at(32);
    let (replica, relay) = rest.split_at(1);
    Ok((
        group_id.try_into().map_err(|_| Error::Integrity)?,
        *replica.first().ok_or(Error::Integrity)?,
        relay.try_into().map_err(|_| Error::Integrity)?,
    ))
}

/// The key of the row of the local identity table that holds the seed of
/// a group before a re-key (Part 11 §11.12).
pub(super) fn previous_seed_key(group_id: &[u8; 32]) -> Vec<u8> {
    [group_id.as_slice(), b"previous"].concat()
}

/// The key of the row that holds the seed of a re-key that a rival took
/// the place of (`GRP-369`). Its keys go to an admin on a pairwise channel
/// (`GRP-370`).
pub(super) fn lost_seed_key(group_id: &[u8; 32]) -> Vec<u8> {
    [group_id.as_slice(), b"lost"].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The conversation of a group: the surrogate of its identifier under
    /// the store key, as a contact has one.
    pub fn conversation_of_group(&self, group_id: &[u8; 32]) -> Result<ConversationId, Error> {
        let store = &self.open_ref()?.store;
        Ok(ConversationId(store.row_id(GROUP, group_id)))
    }

    /// The groups of this device, as conversations.
    pub fn group_conversations(&self) -> Result<Vec<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .list(GROUP, None)?
            .into_iter()
            .map(|(row, plain)| {
                drop(Zeroizing::new(plain));
                ConversationId(row)
            })
            .collect())
    }

    /// Whether a conversation names a group.
    pub fn is_group(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        Ok(store.get(GROUP, &conversation.0)?.is_some())
    }

    /// Makes a group with this device as its owner, and asks two relays of
    /// different operators and blocs for a group queue (`GRP-151`,
    /// `GRP-191`). The group is not ready until both answered.
    pub fn create_group<R: CryptoRng + umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        name: &str,
        relays: [[u8; 32]; GROUP_REPLICAS],
        now: u64,
        rng: &mut R,
    ) -> Result<ConversationId, Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        let name = name.trim();
        if name.len() > GROUP_NAME_MAX {
            return Err(Error::TooLong);
        }
        if relays[0] == relays[1] {
            return Err(Error::Malformed);
        }
        // GRP-151, GRP-052: both come from the device CSPRNG, and neither
        // comes from the other.
        let mut group_id = [0u8; 32];
        rng.fill_bytes(&mut group_id);
        let mut seed = Secret::<32>::zeroed();
        rng.fill_bytes(seed.expose_mut());
        let group = Group::create(group_id, &seed, now, rng).map_err(|_| Error::Malformed)?;
        let credentials = group.credentials().ok_or(Error::Malformed)?;
        let (read_pk, write_pk) = (credentials.read_public(), credentials.write_public());
        let mut jobs = Vec::new();
        for (replica, relay) in relays.iter().enumerate() {
            let replica = u8::try_from(replica).map_err(|_| Error::Malformed)?;
            jobs.push(GroupQueueJob {
                group_id,
                replica,
                relay: *relay,
                read_pk,
                write_pk,
                own: Secret::new(
                    *group
                        .owner(usize::from(replica))
                        .ok_or(Error::Malformed)?
                        .expose(),
                ),
            });
        }

        let stored = Self::group_row(&group, OPEN)?;
        let open = self.open_mut()?;
        let conversation = ConversationId(open.store.row_id(GROUP, &group_id));
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, &group_id);
        let queue_rows: Vec<RowId> = jobs
            .iter()
            .map(|job| {
                open.store
                    .row_id(GROUP_QUEUE, &[&group_id[..], &[job.replica]].concat())
            })
            .collect();
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &stored, rng)?;
        batch.put(TableId::LOCAL_IDENTITY, seed_row, None, seed.expose(), rng)?;
        for (job, row) in jobs.iter().zip(queue_rows) {
            batch.put(
                GROUP_QUEUE,
                row,
                Some(conversation.0),
                &queue_row(&group_id, job.replica, &job.relay),
                rng,
            )?;
        }
        batch.commit()?;
        self.put_conversation_meta(conversation, 0, name, rng)?;
        for job in jobs {
            self.groups.creations.push_back(job);
        }
        self.start_group_alert(conversation, 1, rng)?;
        Ok(conversation)
    }

    /// The group of a conversation, with the seed of its identity row.
    pub fn group_of(&self, conversation: ConversationId) -> Result<Group, Error> {
        let store = &self.open_ref()?.store;
        let row = Zeroizing::new(store.get(GROUP, &conversation.0)?.ok_or(Error::NotFound)?);
        let (group_id, stored) = row.split_at_checked(33).ok_or(Error::Integrity)?;
        let group_id: [u8; 32] = group_id
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let seed_row = store.row_id(TableId::LOCAL_IDENTITY, &group_id);
        let seed = Zeroizing::new(
            store
                .get(TableId::LOCAL_IDENTITY, &seed_row)?
                .ok_or(Error::Integrity)?,
        );
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
        // GRP-372: the seed before a re-key, while the group reads with it.
        let previous_row = store.row_id(TableId::LOCAL_IDENTITY, &previous_seed_key(&group_id));
        let previous = store
            .get(TableId::LOCAL_IDENTITY, &previous_row)?
            .map(Zeroizing::new)
            .map(|bytes| -> Result<Secret<32>, Error> {
                Ok(Secret::new(
                    bytes.as_slice().try_into().map_err(|_| Error::Integrity)?,
                ))
            })
            .transpose()?;
        Group::restore_with_previous(stored, &Secret::new(seed), previous.as_ref())
            .map_err(|_| Error::Integrity)
    }

    /// Moves the member to new keys in each group of the user, after a
    /// device of the set was removed (Part 11 §11.12, `GRP-345`,
    /// `GRP-365`). The record goes out under the index that stands, and the
    /// member then takes its new index. A group that sends nothing takes no
    /// re-key. A group that fails stops no other group: each one holds keys
    /// that the removed device held, and the answer gives the first fault.
    pub fn rekey_groups<R: CryptoRng + umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut fault = None;
        for conversation in self.group_conversations()? {
            if let Err(error) = self.rekey_group(conversation, now_ms, rng) {
                fault.get_or_insert(error);
            }
        }
        fault.map_or(Ok(()), Err)
    }

    /// Moves the member to new keys in one group. A closed group and a
    /// group that no longer holds the member take no re-key. A rate of the
    /// roster chain can hold a re-key back (`GRP-076`). A re-key can also
    /// wait for the index of the group after a snapshot (`GRP-329`). Either
    /// one gives `Busy`, and [`Client::expire_group_holds`] tries it again.
    /// Until it goes, the device that left the set holds keys of the group.
    fn rekey_group<R: CryptoRng + umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.group_closed(conversation)? {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
        if !group
            .roster()
            .member(group.own_index())
            .is_some_and(|member| member.active)
        {
            return Ok(());
        }
        let fresh = umbra_core::group::join::JoinKeys::make(rng).map_err(|_| Error::Malformed)?;
        let object = match group.rekey_object(&fresh, rng) {
            Ok(object) => object,
            Err(_) if group.roster().index_is_open() => {
                self.put_clock(conversation, rekey_key(conversation), now_ms / 1_000, rng)?;
                return Err(Error::Busy);
            }
            Err(_) => return Err(Error::Malformed),
        };
        drop(group);
        match self.post_group_control(conversation, &object, now_ms, rng) {
            Err(Error::Busy) => {
                self.put_clock(conversation, rekey_key(conversation), now_ms / 1_000, rng)?;
                return Err(Error::Busy);
            }
            other => other?,
        }
        if self.rekey_waits(conversation)? {
            self.put_clock(conversation, rekey_key(conversation), 0, rng)?;
        }
        let mut group = self.group_of(conversation)?;
        let group_id = *group.group_id();
        group
            .adopt_rekey(&object, &fresh.seed, now_ms / 1_000)
            .map_err(|_| Error::Malformed)?;
        self.store_rekeyed(conversation, &group, &fresh.seed, rng)?;
        // DEV-300: each other device of the set moves with this one.
        self.publish_group_rekey(&group_id, &fresh.seed, &object, rng)
    }

    /// Whether a re-key of this member in a group waits for another try.
    fn rekey_waits(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self
            .clock(&rekey_key(conversation))?
            .is_some_and(|at| at != 0))
    }

    /// Posts again a roster object of this device that an epoch of another
    /// member displaced under the order of `GRP-117` (`GRP-119`), against the
    /// new head. An object whose change the roster holds already goes no
    /// more. An add goes back to its joiner, and the admin admits it again.
    fn repost_displaced<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        displaced: umbra_core::group::roster::Displaced,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? {
            return Ok(());
        }
        let row = self.open_ref()?.store.row_id(OWN_EPOCH, &conversation.0);
        let Some(object) = self.open_ref()?.store.get(OWN_EPOCH, &row)? else {
            return Ok(());
        };
        let control = GroupControl::parse(&object)?;
        if control.epoch_hash() != displaced.hash {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(OWN_EPOCH, row);
        batch.commit()?;
        let group = self.group_of(conversation)?;
        match control.control_type {
            ControlType::Rekey => {
                drop(group);
                match self.rekey_group(conversation, now_ms, rng) {
                    // The sweep tries a re-key that waits again.
                    Err(Error::Busy) => Ok(()),
                    other => other,
                }
            }
            ControlType::PlainEpoch => match PlainEpoch::parse(control.payload)?.op {
                PlainOp::Remove { index } => {
                    let active = group.roster().member(index).is_some_and(|m| m.active);
                    drop(group);
                    if active {
                        self.remove_from_group(conversation, index, now_ms, rng)?;
                    }
                    Ok(())
                }
                PlainOp::SelfRemoval => {
                    let active = group.own_role().is_some();
                    drop(group);
                    if active {
                        self.leave_group(conversation, now_ms, rng)?;
                    }
                    Ok(())
                }
                PlainOp::Add { index, keys } => {
                    let group_id = *group.group_id();
                    let held = group
                        .roster()
                        .active()
                        .any(|member| member.roster_pk_hash == keys.roster_pk_hash);
                    drop(group);
                    if held {
                        return Ok(());
                    }
                    let join = JoinRecord {
                        group_id,
                        keys: keys.clone(),
                    };
                    self.ask_again(conversation, &group_id, index, &join, rng)
                }
            },
            ControlType::GrantingEpoch => {
                let grant = GrantingEpoch::parse(control.payload)?;
                let stands = group
                    .roster()
                    .member(grant.grantee_index)
                    .is_some_and(|member| member.active && member.role != grant.role);
                drop(group);
                if stands {
                    self.set_group_role(
                        conversation,
                        grant.grantee_index,
                        grant.role,
                        now_ms,
                        rng,
                    )?;
                }
                Ok(())
            }
            // GRP-119: a moderation epoch that the order did not select goes
            // again, with each of its acts, while this member holds a role
            // that moderates.
            ControlType::ModerationEpoch => {
                let epoch = umbra_wire::group::control::ModerationEpoch::parse(control.payload)?;
                let acts: Vec<(u8, [u8; 16])> = epoch
                    .actions
                    .iter()
                    .map(|act| (act.action, act.target))
                    .collect();
                let Ok(object) = group.moderate(&acts, rng) else {
                    return Ok(());
                };
                drop(group);
                self.post_group_control(conversation, &object, now_ms, rng)?;
                self.apply_own_roster_object(conversation, &object, now_ms, rng)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Puts a joiner whose add another epoch displaced back into the list
    /// of joiners, thus the admin adds it again under a new index and sends
    /// the admit of that add (§11.9.1).
    fn ask_again<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group_id: &[u8; 32],
        index: u16,
        join: &JoinRecord<'_>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut found = None;
        for row in self.join_rows()? {
            // GRP-420: an add whose admit went out finds its joiner too.
            let (from, held, added) = match self.join_entry(&row)? {
                Some(JoinEntry::Added {
                    from,
                    group_id,
                    index,
                    ..
                }) => (from, group_id, index),
                Some(JoinEntry::Sent {
                    from,
                    group_id,
                    index,
                    ..
                }) => (from, group_id, index),
                _ => continue,
            };
            if held == *group_id && added == index {
                found = Some((row, from));
            }
        }
        let Some((row, from)) = found else {
            return Ok(());
        };
        let mut payload = vec![0u8; 1_400];
        let used = join.encode(&mut payload)?;
        payload.truncate(used);
        let mut entry = vec![ASKED];
        entry.extend_from_slice(&from.0);
        entry.extend_from_slice(group_id);
        entry.extend_from_slice(&payload);
        let open = self.open_mut()?;
        let member = open
            .store
            .row_id(GROUP_MEMBER, &Self::member_key(conversation, index));
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
        batch.delete(GROUP_MEMBER, member);
        batch.commit()?;
        self.events.push_back(Event::GroupJoiner { from });
        Ok(())
    }

    /// Keeps a group after a re-key of the member: the new row, the new
    /// seed, and the seed before it for the grace of `GRP-372`.
    pub(super) fn store_rekeyed<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        seed: &Secret<32>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let group_id = *group.group_id();
        let row = Self::group_row(group, self.group_state(conversation)?)?;
        let open = self.open_mut()?;
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, &group_id);
        let previous_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, &previous_seed_key(&group_id));
        let old = Zeroizing::new(
            open.store
                .get(TableId::LOCAL_IDENTITY, &seed_row)?
                .ok_or(Error::Integrity)?,
        );
        let mut batch = open.store.begin();
        batch.put(TableId::LOCAL_IDENTITY, previous_row, None, &old, rng)?;
        batch.put(TableId::LOCAL_IDENTITY, seed_row, None, seed.expose(), rng)?;
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        Ok(batch.commit()?)
    }

    /// The row of a group: its identifier, thus the row names the seed
    /// that opens it (`IMP-121`), a byte of the state that the group has
    /// at this device, and then its stored form.
    fn group_row(group: &Group, state: u8) -> Result<Zeroizing<Vec<u8>>, Error> {
        let stored = group.export().map_err(|_| Error::Malformed)?;
        let mut row = Zeroizing::new(Vec::with_capacity(stored.len().saturating_add(33)));
        row.extend_from_slice(group.group_id());
        row.push(state);
        row.extend_from_slice(&stored);
        Ok(row)
    }

    /// Whether each replica of a group refused its queue (`GRP-210`).
    /// A lapsed group sends nothing either.
    pub fn group_closed(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self.group_state(conversation)? != OPEN)
    }

    /// Whether this device lacks the current epoch of a group and no
    /// member can supply it, thus it needs a new invitation (`GRP-297`).
    pub fn group_lapsed(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self.group_state(conversation)? == LAPSED)
    }

    fn group_state(&self, conversation: ConversationId) -> Result<u8, Error> {
        let store = &self.open_ref()?.store;
        let row = Zeroizing::new(store.get(GROUP, &conversation.0)?.ok_or(Error::NotFound)?);
        Ok(row.get(32).copied().unwrap_or(OPEN))
    }

    /// Marks a group closed. Each record of it stays in the store, and
    /// this device sends nothing more to its queues.
    pub fn close_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.group_closed(conversation)? {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
        // GRP-297: a member that lacks the epoch is refused as a queue
        // that is gone is, and it is its membership that ended.
        let state = if group.lacks_epoch().is_some() {
            LAPSED
        } else {
            CLOSED
        };
        let row = Self::group_row(&group, state)?;
        // GRP-363: each replica refused the pair of the epoch that this
        // device holds, although this device knew of a `GKEY` of it there.
        // A `GKEY` of an older epoch can have moved a replica back, and a
        // replica in that state refuses as one with no queue does. The
        // mark of that `GKEY` goes, thus it goes again after the next
        // backlog, and a replica that still holds the queue takes it.
        if state == CLOSED && group.owner(0).is_some() {
            let mut held = self.gkey_row(conversation)?;
            if held.taken.iter().any(Option::is_some) {
                held.taken = [None; GROUP_REPLICAS];
                self.put_gkey_row(conversation, &held, rng)?;
            }
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        batch.commit()?;
        // Each record that waited for a queue that is gone leaves the
        // work list. The store keeps the message, and the user sees that
        // it did not go: a message that no replica took fails.
        let mut waited = Vec::new();
        for post in &self.groups.posts {
            if post.conversation != conversation {
                continue;
            }
            let Some(message) = post.message else {
                continue;
            };
            if self.open_ref()?.store.get(OUTBOX, &message.0)?.is_some() {
                waited.push(message);
            }
        }
        self.groups
            .posts
            .retain(|post| post.conversation != conversation);
        for message in waited {
            self.fail(&message, crate::FailureCause::Refused, rng)?;
        }
        Ok(())
    }

    /// Shows a group as open again. The epoch that a lapsed member lacked
    /// arrived (`GRP-405`), or a replica of a group that this device showed
    /// as closed answered (`GRP-210`).
    fn reopen_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let row = Self::group_row(&self.group_of(conversation)?, OPEN)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        batch.commit()?;
        self.groups.key_requests.remove(&conversation);
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    /// Writes a group back after a change of it.
    pub fn save_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        rng: &mut R,
    ) -> Result<(), Error> {
        let state = self.group_state(conversation).unwrap_or(OPEN);
        let row = Self::group_row(group, state)?;
        let open = self.open_mut()?;
        let group_id = group.group_id();
        let previous_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, &previous_seed_key(group_id));
        let previous = if group.has_previous() {
            None
        } else {
            open.store
                .get(TableId::LOCAL_IDENTITY, &previous_row)?
                .map(Zeroizing::new)
        };
        // The member reads with the keys before its re-key again: a rival
        // took its place (GRP-369), or an epoch of another member came first
        // (GRP-117). The seed before is the seed of the group again, and
        // after a rival the seed of the re-key waits for the pairwise channel
        // (GRP-370). Otherwise a slot for the new index ended the seed
        // before (GRP-372).
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, group_id);
        let lost_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, &lost_seed_key(group_id));
        let went_back = previous.as_ref().is_some_and(|seed| {
            <[u8; 32]>::try_from(seed.as_slice())
                .is_ok_and(|seed| group.reads_with(&Secret::new(seed)))
        });
        let fresh = if went_back && group.lost_rekey() {
            Some(Zeroizing::new(
                open.store
                    .get(TableId::LOCAL_IDENTITY, &seed_row)?
                    .ok_or(Error::Integrity)?,
            ))
        } else {
            None
        };
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        if let Some(previous) = previous {
            batch.delete(TableId::LOCAL_IDENTITY, previous_row);
            if went_back {
                batch.put(TableId::LOCAL_IDENTITY, seed_row, None, &previous, rng)?;
            }
            if let Some(fresh) = fresh {
                batch.put(TableId::LOCAL_IDENTITY, lost_row, None, &fresh, rng)?;
            }
        }
        Ok(batch.commit()?)
    }

    /// What a view shows of a group.
    pub fn group_info(&self, conversation: ConversationId) -> Result<GroupInfo, Error> {
        let group = self.group_of(conversation)?;
        let store = &self.open_ref()?.store;
        let is_ready = store.list(GROUP_QUEUE, Some(&conversation.0))?.is_empty();
        Ok(GroupInfo {
            conversation,
            group_id: *group.group_id(),
            own_index: group.own_index(),
            members: u32::try_from(group.roster().active_count()).unwrap_or(u32::MAX),
            epoch: group.epoch(),
            is_ready,
            is_closed: self.group_closed(conversation)?,
            is_lapsed: self.group_lapsed(conversation)?,
            is_member: group
                .roster()
                .member(group.own_index())
                .is_some_and(|member| member.active),
            is_unreachable: group.replicas().is_some_and(|held| held.unreachable()),
            is_clock_suspect: group.holds_clock_suspect(super::unix_now_seconds()),
        })
    }

    /// A record of the group queue `group_queue_id` arrived, thus its
    /// replica answers (`GRP-200`).
    pub fn group_queue_reached<R: CryptoRng + ?Sized>(
        &mut self,
        group_queue_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(conversation) = self.conversation_of_queue(group_queue_id)? else {
            return Ok(());
        };
        let group = self.group_of(conversation)?;
        let relay = group.replicas().and_then(|replicas| {
            (0..GROUP_REPLICAS)
                .filter_map(|index| replicas.reference(index))
                .find(|held| held.group_queue_id == *group_queue_id)
                .map(|held| held.relay_id)
        });
        match relay {
            Some(relay) => self.group_replica_reached(conversation, &relay, true, rng),
            None => Ok(()),
        }
    }

    /// A session to the replica of `relay` answered, or none could reach
    /// it. The line of `GRP-199` shows while no replica answers, and it
    /// ends at the first answer (`GRP-200`).
    pub fn group_replica_reached<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        relay: &[u8; 32],
        reached: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut group = self.group_of(conversation)?;
        let Some(replicas) = group.replicas_mut() else {
            return Ok(());
        };
        let Some(which) = (0..GROUP_REPLICAS).find(|index| {
            replicas
                .reference(*index)
                .is_some_and(|held| held.relay_id == *relay)
        }) else {
            return Ok(());
        };
        if reached {
            // GRP-396: the replica of this session answered.
            if let Some(watch) = self.groups.watch.get_mut(&conversation) {
                watch.answered |= watch.which == which;
            }
            // GRP-210: a replica that answers under the credentials of this
            // device holds the group queue. Thus the group is not gone, and
            // a group that this device showed as closed opens again.
            if self.group_state(conversation)? == CLOSED {
                self.reopen_group(conversation, rng)?;
            }
        }
        let Some(replicas) = group.replicas_mut() else {
            return Ok(());
        };
        if replicas.is_reachable(which) == reached {
            return Ok(());
        }
        let before = replicas.unreachable();
        replicas.set_reachable(which, reached);
        let moved = replicas.unreachable() != before;
        self.save_group(conversation, &group, rng)?;
        if moved {
            self.events.push_back(super::Event::Conversations);
        }
        Ok(())
    }

    /// The next `GNEW` that waits for the run of the group queues.
    pub fn take_group_creation(&mut self) -> Option<GroupQueueJob> {
        self.groups.creations.pop_front()
    }

    /// A relay named the group queue of one replica. The group is ready
    /// when the second one answered.
    pub fn group_queue_made<R: CryptoRng + ?Sized>(
        &mut self,
        group_id: &[u8; 32],
        replica: u8,
        relay: [u8; 32],
        group_queue_id: [u8; 32],
        rng: &mut R,
    ) -> Result<bool, Error> {
        let conversation = self.conversation_of_group(group_id)?;
        let row = {
            let store = &self.open_ref()?.store;
            store.row_id(GROUP_QUEUE, &[&group_id[..], &[replica]].concat())
        };
        self.put_made_queue(conversation, row, replica, relay, group_queue_id, rng)
    }

    fn put_made_queue<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        row: RowId,
        replica: u8,
        relay: [u8; 32],
        group_queue_id: [u8; 32],
        rng: &mut R,
    ) -> Result<bool, Error> {
        // The made queue holds its relay and its identifier until the
        // second one arrives, and then the group row holds both.
        let open = self.open_mut()?;
        let mut plain = queue_row(&[0; 32], replica, &relay);
        plain.extend_from_slice(&group_queue_id);
        let mut batch = open.store.begin();
        batch.put(GROUP_QUEUE, row, Some(conversation.0), &plain, rng)?;
        batch.commit()?;

        let store = &self.open_ref()?.store;
        let mut made = Vec::new();
        for (row, plain) in store.list(GROUP_QUEUE, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            if plain.len() != QUEUE_ROW_LEN.saturating_add(32) {
                return Ok(false);
            }
            let (head, id) = plain.split_at(QUEUE_ROW_LEN);
            let (_, replica, relay) = read_queue_row(head)?;
            let id: [u8; 32] = id.try_into().map_err(|_| Error::Integrity)?;
            made.push((row, replica, relay, id));
        }
        if made.len() != GROUP_REPLICAS {
            return Ok(false);
        }
        made.sort_by_key(|(_, replica, _, _)| *replica);
        let refs = [
            ReplicaRef {
                relay_id: made.first().ok_or(Error::Integrity)?.2,
                group_queue_id: made.first().ok_or(Error::Integrity)?.3,
                seq_of_add: 0,
            },
            ReplicaRef {
                relay_id: made.get(1).ok_or(Error::Integrity)?.2,
                group_queue_id: made.get(1).ok_or(Error::Integrity)?.3,
                seq_of_add: 0,
            },
        ];
        let mut group = self.group_of(conversation)?;
        group.set_replicas(refs);
        self.save_group(conversation, &group, rng)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for (row, _, _, _) in made {
            batch.delete(GROUP_QUEUE, row);
        }
        batch.commit()?;
        // Each record that waited for the second queue goes now.
        self.requeue_group_posts(rng)?;
        // DEV-298: the group is whole, and it goes to the other devices.
        self.group_state_due(conversation, rng)?;
        Ok(true)
    }

    /// Sends one `GroupControl` on the pairwise channel of a contact. The
    /// record is no message of that conversation.
    fn send_pairwise_control<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.send_pairwise_app(conversation, AppKind::GroupControl, body, now_ms, rng)
    }

    /// Sends one `AppMessage` of `kind` that no view shows on a pairwise
    /// channel.
    pub(super) fn send_pairwise_app<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        kind: AppKind,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.is_group(conversation)? {
            return Err(Error::Malformed);
        }
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind,
            msg_id,
            sent_at: now_ms,
            body,
        };
        let mut app = Zeroizing::new(vec![0u8; record.len()]);
        record.encode(&mut app)?;
        let open = self.open_mut()?;
        let reference = super::msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let stored = stored_message(
            super::OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            &app,
        );
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &stored, rng)?;
        batch.put(OUTBOX, row, None, &super::outbox_row(), rng)?;
        batch.commit()?;
        self.push_outgoing(MsgRef(row), conversation, app.to_vec());
        Ok(())
    }

    /// Step 1 of §11.9.1: an admin of `group` offers it to a contact. The
    /// offer carries the name, the roster key of this admin, and the
    /// roster key of the creator.
    pub fn offer_group<R: CryptoRng + ?Sized>(
        &mut self,
        group: ConversationId,
        to: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        let held = self.group_of(group)?;
        let own = held
            .roster()
            .member(held.own_index())
            .ok_or(Error::Integrity)?;
        if own.role < Role::Admin {
            return Err(Error::Malformed);
        }
        // A member that joined and became an admin holds the hash of its key
        // in the roster alone.
        let admin_roster_pk = held.own_roster_pk();
        let creator_roster_pk = held
            .roster()
            .member(0)
            .and_then(|creator| creator.roster_pk.clone())
            .ok_or(Error::Integrity)?;
        let (_, name) = self.conversation_meta(group)?;
        let invitation = GroupInvitation {
            group_id: *held.group_id(),
            stage: InvitationStage::Offer {
                name: &name,
                admin_roster_pk: &admin_roster_pk,
                creator_roster_pk: &creator_roster_pk,
            },
        };
        let mut payload = vec![0u8; 4_096];
        let used = invitation.encode(&mut payload)?;
        payload.truncate(used);
        let control = GroupControl {
            control_type: ControlType::Invitation,
            payload: &payload,
        };
        let mut body = vec![0u8; payload.len().saturating_add(8)];
        let used = control.encode(&mut body)?;
        body.truncate(used);
        self.send_pairwise_control(to, &body, now_ms, rng)
    }

    /// Step 2 of §11.9.1: the user accepted an offer, thus this device
    /// makes `GroupRosterSeed_g` and sends its `JoinRecord` (`GRP-309`).
    pub fn accept_group_offer<R: CryptoRng + ?Sized>(
        &mut self,
        offer: &GroupOffer,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        // GRP-153: this device refuses an offer to a group that it is a
        // member of. A membership that ended takes a new invitation (Part
        // 11 §11.12, `GRP-297`, `GRP-374`).
        let conversation = self.conversation_of_group(&offer.group_id)?;
        if self.holds_membership(conversation)? {
            return Err(Error::Malformed);
        }
        let row = self.join_row(offer.from, &offer.group_id)?;
        let held = self.join_entry(&row)?.ok_or(Error::NotFound)?;
        let JoinEntry::Offer {
            creator_roster_pk,
            name,
            ..
        } = held
        else {
            return Err(Error::Malformed);
        };
        // The row of a membership that ended still opens under its own
        // seed. Thus the seed of the new join waits beside it, under the
        // key of `GRP-370`, until the admit takes the place of the row.
        let seed_key = if self.is_group(conversation)? {
            lost_seed_key(&offer.group_id)
        } else {
            offer.group_id.to_vec()
        };
        // GRP-052: the seed comes from the device CSPRNG, and it stays in
        // the local identity table until the admit arrives. A join of this
        // group that waits already keeps its seed, thus the admit of each
        // contact that this device asked finds the same keys.
        let waiting = {
            let store = &self.open_ref()?.store;
            let seed_row = store.row_id(TableId::LOCAL_IDENTITY, &seed_key);
            store
                .get(TableId::LOCAL_IDENTITY, &seed_row)?
                .map(Zeroizing::new)
        };
        let seed = match waiting {
            Some(bytes) => Secret::new(bytes.as_slice().try_into().map_err(|_| Error::Integrity)?),
            None => {
                let mut seed = Secret::<32>::zeroed();
                rng.fill_bytes(seed.expose_mut());
                seed
            }
        };
        let keys = MemberKeys::from_seed(&seed);
        let kem_pk = keys.kem().public().to_bytes();
        let record = JoinRecord {
            group_id: offer.group_id,
            keys: umbra_wire::group::control::MemberKeys {
                pair_pk: keys.pair_public(),
                roster_pk_hash: sha3_256(&[&keys.roster().verifying_key().to_bytes()]),
                kem_pk: &kem_pk,
            },
        };
        let mut payload = vec![0u8; 1_400];
        let used = record.encode(&mut payload)?;
        payload.truncate(used);
        let control = GroupControl {
            control_type: ControlType::Join,
            payload: &payload,
        };
        let mut body = vec![0u8; payload.len().saturating_add(8)];
        let used = control.encode(&mut body)?;
        body.truncate(used);
        self.send_pairwise_control(offer.from, &body, now_ms, rng)?;

        let open = self.open_mut()?;
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, &seed_key);
        let mut entry = vec![WAITING];
        entry.extend_from_slice(&offer.from.0);
        entry.extend_from_slice(&offer.group_id);
        entry.extend_from_slice(&creator_roster_pk);
        entry.extend_from_slice(name.as_bytes());
        let mut batch = open.store.begin();
        batch.put(TableId::LOCAL_IDENTITY, seed_row, None, seed.expose(), rng)?;
        batch.put(GROUP_JOIN, row, Some(offer.from.0), &entry, rng)?;
        batch.commit()?;
        Ok(())
    }

    /// Whether this device is a member of a group that it holds, thus an
    /// invitation to that group is none (`GRP-153`). A membership that
    /// ended holds nothing. The member left or an admin removed it, a rival
    /// took its index (`GRP-374`), it lapsed (`GRP-297`), or each replica
    /// refused the group here (`GRP-210`). A new invitation then takes the
    /// place of the row, in the conversation that it held (Part 11 §11.12).
    pub(super) fn holds_membership(&self, conversation: ConversationId) -> Result<bool, Error> {
        if !self.is_group(conversation)? || self.group_state(conversation)? != OPEN {
            return Ok(false);
        }
        Ok(self.group_of(conversation)?.own_role().is_some())
    }

    /// Each row that belongs to one membership of a group and to no later
    /// one. The rows are the owner credentials and their admins, the
    /// grants, and the roster object with each record that waited. The
    /// clocks of the members and the epoch keys that waited are such rows
    /// too. The messages, the notes, the contacts behind the members, and
    /// the read time of `GRP-208` stay with the conversation.
    pub(super) fn membership_rows(
        &self,
        conversation: ConversationId,
    ) -> Result<Vec<(TableId, RowId)>, Error> {
        let store = &self.open_ref()?.store;
        let read = store.row_id(
            GROUP_PRESENCE,
            &[conversation.0.as_slice(), b"read"].concat(),
        );
        let mut rows = vec![
            (OWN_EPOCH, store.row_id(OWN_EPOCH, &conversation.0)),
            (
                GROUP_OWNERS,
                store.row_id(GROUP_OWNERS, &Self::gkey_key(conversation)),
            ),
        ];
        for table in [
            GROUP_OWNERS,
            GROUP_GRANTS,
            GROUP_UNSENT,
            GROUP_PRESENCE,
            super::group_sync::EPOCH_HELD,
        ] {
            for (row, plain) in store.list(table, Some(&conversation.0))? {
                drop(Zeroizing::new(plain));
                if (table, row) != (GROUP_PRESENCE, read) {
                    rows.push((table, row));
                }
            }
        }
        Ok(rows)
    }

    /// Drops the work of one membership of a group that waits in the
    /// memory of this run.
    pub(super) fn forget_group_work(&mut self, conversation: ConversationId) {
        let groups = &mut self.groups;
        groups
            .posts
            .retain(|post| post.conversation != conversation);
        groups.backoff.remove(&conversation);
        groups
            .evictions
            .retain(|(held, _), _| *held != conversation);
        groups.owner_backoff.remove(&conversation);
        groups.key_requests.remove(&conversation);
        groups
            .key_answers
            .retain(|(held, _), _| *held != conversation);
        groups
            .key_answers_rate
            .retain(|(held, _), _| *held != conversation);
        groups
            .epoch_uploads
            .retain(|upload| upload.conversation != conversation);
        groups
            .epoch_chunks
            .retain(|(held, _)| *held != conversation);
        groups.clock_suspect.remove(&conversation);
        groups.picked.remove(&conversation);
        groups.watch.remove(&conversation);
        groups
            .gkey_sent
            .retain(|(held, _), _| *held != conversation);
        groups.repaired.remove(&conversation);
    }

    /// An admit of stage `0x02`. The joiner keeps it until it fetched the
    /// snapshot that it names (`GRP-313`).
    fn on_admit<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        invitation: &GroupInvitation<'_>,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let InvitationStage::Admit(_) = &invitation.stage else {
            return Ok(());
        };
        let row = self.join_row(from, &invitation.group_id)?;
        // An admit to a group that this device did not ask for is no admit.
        // GRP-421: a second admit of the admin of a join whose add is the
        // head takes the place of the group.
        let (creator_roster_pk, name, again) = match self.join_entry(&row)? {
            Some(JoinEntry::Waiting {
                creator_roster_pk,
                name,
            }) => (creator_roster_pk, name, false),
            Some(JoinEntry::Joined {
                creator_roster_pk,
                name,
                ..
            }) => (creator_roster_pk, name, true),
            _ => return Ok(()),
        };
        let mut entry = vec![if again { READMITTED } else { ADMITTED }];
        entry.extend_from_slice(&from.0);
        entry.extend_from_slice(&invitation.group_id);
        entry.extend_from_slice(&creator_roster_pk);
        let control = GroupControl {
            control_type: ControlType::Invitation,
            payload,
        };
        let mut admit = vec![0u8; payload.len().saturating_add(8)];
        let used = control.encode(&mut admit)?;
        entry.extend_from_slice(
            &u32::try_from(used)
                .map_err(|_| Error::Malformed)?
                .to_be_bytes(),
        );
        entry.extend_from_slice(admit.get(..used).ok_or(Error::Malformed)?);
        entry.extend_from_slice(name.as_bytes());
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
        batch.commit()?;
        self.events.push_back(Event::GroupAdmit { from });
        Ok(())
    }

    /// One `GroupControl` that a pairwise channel carried (`GRP-170`,
    /// `GRP-310`). An object that does not parse changes nothing.
    pub(super) fn on_pairwise_control<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Ok(control) = GroupControl::parse(body) else {
            return Ok(());
        };
        match control.control_type {
            ControlType::Invitation => {
                let Ok(invitation) = GroupInvitation::parse(control.payload) else {
                    return Ok(());
                };
                let InvitationStage::Offer {
                    name,
                    admin_roster_pk,
                    creator_roster_pk,
                } = invitation.stage
                else {
                    return self.on_admit(from, &invitation, control.payload, rng);
                };
                // GRP-153: an offer to a group that this device is a member
                // of is no offer. A membership that ended takes one (Part 11
                // §11.12).
                let conversation = self.conversation_of_group(&invitation.group_id)?;
                if self.holds_membership(conversation)? {
                    return Ok(());
                }
                let row = self.join_row(from, &invitation.group_id)?;
                // GRP-170: a join that runs keeps its row, thus a second
                // offer ends no wait for an admit. One contact holds no
                // more than `JOIN_ROWS_MAX` rows here.
                match self.join_entry(&row)? {
                    Some(JoinEntry::Waiting { .. } | JoinEntry::Admitted { .. }) => return Ok(()),
                    Some(_) => {}
                    None => {
                        let store = &self.open_ref()?.store;
                        if store.list(GROUP_JOIN, Some(&from.0))?.len() >= JOIN_ROWS_MAX {
                            return Ok(());
                        }
                    }
                }
                let name: String = name.chars().take(GROUP_NAME_MAX).collect();
                let mut entry = vec![OFFERED];
                entry.extend_from_slice(&from.0);
                entry.extend_from_slice(&invitation.group_id);
                entry.extend_from_slice(creator_roster_pk);
                entry.extend_from_slice(name.as_bytes());
                let open = self.open_mut()?;
                // The admin that offers is the contact that sent the offer,
                // thus the group can name it once this device holds the
                // roster. The key of that admin stays with its own offer:
                // an offer of another contact names another admin.
                let admin_row = open
                    .store
                    .row_id(GROUP_MEMBER, &Self::offer_key(conversation, from));
                let mut batch = open.store.begin();
                batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
                batch.put(
                    GROUP_MEMBER,
                    admin_row,
                    Some(conversation.0),
                    &sha3_256(&[admin_roster_pk]),
                    rng,
                )?;
                batch.commit()?;
                self.events.push_back(Event::GroupOffer { from });
                Ok(())
            }
            ControlType::Join => {
                let Ok(record) = JoinRecord::parse(control.payload) else {
                    return Ok(());
                };
                // A join record for a group that this device does not hold,
                // or holds below `admin`, names no group of any admin here
                // (`GRP-382`).
                let conversation = self.conversation_of_group(&record.group_id)?;
                if !self.holds_membership(conversation)? {
                    return Ok(());
                }
                let group = self.group_of(conversation)?;
                if group.own_role().is_none_or(|role| role < Role::Admin) {
                    return Ok(());
                }
                let row = self.join_row(from, &record.group_id)?;
                // GRP-306: an add that runs keeps its row, and the same
                // keys again add no second member. A contact that comes
                // back under new keys asks again.
                match self.join_entry(&row)? {
                    Some(JoinEntry::Added { .. }) => return Ok(()),
                    Some(JoinEntry::Sent { index, .. })
                        if group.roster().member(index).is_some_and(|member| {
                            member.active && member.pair_pk == record.keys.pair_pk
                        }) =>
                    {
                        return Ok(());
                    }
                    Some(_) => {}
                    None => {
                        let store = &self.open_ref()?.store;
                        if store.list(GROUP_JOIN, Some(&from.0))?.len() >= JOIN_ROWS_MAX {
                            return Ok(());
                        }
                    }
                }
                drop(group);
                let mut entry = vec![ASKED];
                entry.extend_from_slice(&from.0);
                entry.extend_from_slice(&record.group_id);
                entry.extend_from_slice(control.payload);
                let open = self.open_mut()?;
                let mut batch = open.store.begin();
                batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
                batch.commit()?;
                self.events.push_back(Event::GroupJoiner { from });
                Ok(())
            }
            ControlType::Rekey => self.on_pairwise_rekey(from, control.payload, now_ms, rng),
            _ => Ok(()),
        }
    }

    /// A `RekeyRecord` on a pairwise channel from a member whose re-key a
    /// rival replaced (`GRP-370`). An admin verifies it under the roster
    /// key of the index that it names (`GRP-348`). The admin discards one
    /// whose index no rival re-key moved (`GRP-349`). The roster shows two
    /// re-keys of one index as a fork under that index (`GRP-072`). With no
    /// such fork the index that follows it holds the keys of the member
    /// itself. The admin first takes a role at `moderator` or above from
    /// the index that the rival holds now, which no plain epoch removes
    /// (`GRP-166`). The admin then removes that index with a rotation
    /// (`GRP-371`). The member waits as a joiner with its new keys, and the
    /// admin admits it as each joiner (§11.9.1).
    fn on_pairwise_rekey<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        payload: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? {
            return Ok(());
        }
        let Ok(record) = umbra_wire::group::control::RekeyRecord::parse(payload) else {
            return Ok(());
        };
        if !record.chain_is_zero() {
            return Ok(());
        }
        let group_id = record.chain.group_id;
        let conversation = self.conversation_of_group(&group_id)?;
        if !self.is_group(conversation)? || self.group_closed(conversation)? {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
        if group.own_role().is_none_or(|role| role < Role::Admin) {
            return Ok(());
        }
        let Some(old) = group.roster().member(record.old_index) else {
            return Ok(());
        };
        if old.active || record.verify(&old.roster_pk_hash).is_err() {
            return Ok(());
        }
        // GRP-349: a record whose index no rival re-key moved is no record.
        let has_rival = group
            .roster()
            .forks()
            .iter()
            .any(|fork| fork.named == Some(record.old_index));
        let Some(rival) = group
            .roster()
            .successor_of(record.old_index)
            .filter(|_| has_rival)
        else {
            return Ok(());
        };
        let Some(held) = group.roster().member(rival) else {
            return Ok(());
        };
        // The keys of the record are the keys that lost. The member that
        // holds the index asks for nothing.
        if held.pair_pk == record.new_keys.pair_pk {
            return Ok(());
        }
        let (is_active, role) = (held.active, held.role);
        drop(group);
        let join = JoinRecord {
            group_id,
            keys: record.new_keys.clone(),
        };
        let mut join_payload = vec![0u8; 1_400];
        let used = join.encode(&mut join_payload)?;
        join_payload.truncate(used);
        let mut entry = vec![ASKED];
        entry.extend_from_slice(&from.0);
        entry.extend_from_slice(&group_id);
        entry.extend_from_slice(&join_payload);
        let row = self.join_row(from, &group_id)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
        batch.commit()?;
        self.events.push_back(Event::GroupJoiner { from });
        if !is_active {
            return Ok(());
        }
        // GRP-351: no party uses the removed index again, and GRP-264
        // rotates with the removal. The joiner waits already, thus a
        // removal that the roster refuses loses no request. The floor of
        // `GRP-051` holds an owner, and the group then needs another owner
        // first (`GRP-184`).
        let removed = if role >= Role::Moderator {
            self.set_group_role(conversation, rival, Role::Member, now_ms, rng)
                .and_then(|()| self.remove_from_group(conversation, rival, now_ms, rng))
        } else {
            self.remove_from_group(conversation, rival, now_ms, rng)
        };
        match removed {
            Ok(()) | Err(Error::Malformed | Error::NotFound | Error::Busy) => Ok(()),
            Err(fault) => Err(fault),
        }
    }

    /// Whether the roster of a group takes a roster object of this member
    /// now. The object goes out before it applies here (`GRP-389`), thus
    /// one that the roster refuses must not go. Each member would discard
    /// it, and the act would end with a record that changes nothing.
    fn roster_takes(
        &self,
        conversation: ConversationId,
        object: &[u8],
        now_ms: u64,
    ) -> Result<bool, Error> {
        let mut scratch = self.group_of(conversation)?;
        let control = GroupControl::parse(object)?;
        let own = scratch.own_index();
        Ok(scratch.apply_control(&control, own, now_ms / 1_000).is_ok())
    }

    /// Asks an admin to add this member again, after a rival re-key took
    /// its index (`GRP-370`). The device that owns the channels sends the
    /// `RekeyRecord` with zero chain fields to the contact that brought the
    /// member in, else to another contact in the group, and it waits for
    /// the admit as a joiner. A member with no such contact needs a new
    /// invitation (`GRP-374`).
    pub(super) fn ask_to_return<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
        if !group.lost_rekey() {
            return Ok(());
        }
        let group_id = *group.group_id();
        let Some(admin) = self.return_contact(conversation)? else {
            return Ok(());
        };
        let row = self.join_row(admin, &group_id)?;
        if self.join_pending(&row)? {
            return Ok(());
        }
        let creator_roster_pk = group
            .roster()
            .member(0)
            .and_then(|creator| creator.roster_pk.clone())
            .ok_or(Error::Integrity)?;
        // GRP-411: the seed of the re-key that lost, or a fresh one when the
        // rival came first.
        let lost_row = self
            .open_ref()?
            .store
            .row_id(TableId::LOCAL_IDENTITY, &lost_seed_key(&group_id));
        let held = self
            .open_ref()?
            .store
            .get(TableId::LOCAL_IDENTITY, &lost_row)?
            .map(Zeroizing::new);
        let seed = match held {
            Some(bytes) => Secret::new(bytes.as_slice().try_into().map_err(|_| Error::Integrity)?),
            None => {
                let mut seed = Secret::<32>::zeroed();
                rng.fill_bytes(seed.expose_mut());
                seed
            }
        };
        let fresh = umbra_core::group::join::JoinKeys {
            seed: Secret::new(*seed.expose()),
            keys: MemberKeys::from_seed(&seed),
        };
        let object = group
            .pairwise_rekey_object(&fresh, rng)
            .map_err(|_| Error::Malformed)?;
        drop(group);
        self.send_pairwise_control(admin, &object, now_ms, rng)?;
        let (_, name) = self.conversation_meta(conversation)?;
        let mut entry = vec![WAITING];
        entry.extend_from_slice(&admin.0);
        entry.extend_from_slice(&group_id);
        entry.extend_from_slice(&creator_roster_pk);
        entry.extend_from_slice(name.as_bytes());
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(TableId::LOCAL_IDENTITY, lost_row, None, seed.expose(), rng)?;
        batch.put(GROUP_JOIN, row, Some(admin.0), &entry, rng)?;
        Ok(batch.commit()?)
    }

    /// The contact that a member asks to come back: the one that brought it
    /// in, else another contact in the group.
    fn return_contact(
        &self,
        conversation: ConversationId,
    ) -> Result<Option<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        let via = store.row_id(GROUP_MEMBER, &[conversation.0.as_slice(), b"via"].concat());
        if let Some(bytes) = store.get(GROUP_MEMBER, &via)? {
            if let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) {
                return Ok(Some(ConversationId(id)));
            }
        }
        Ok(self.contacts_in(conversation)?.into_iter().next())
    }

    /// Whether a member whose index a rival took waits for an admit
    /// (`GRP-373`), or needs a new invitation because it holds no contact
    /// in the group (`GRP-374`). The first value is the wait, the second the
    /// need.
    pub fn return_state(&self, conversation: ConversationId) -> Result<(bool, bool), Error> {
        let group = self.group_of(conversation)?;
        if !group.lost_rekey() {
            return Ok((false, false));
        }
        let Some(admin) = self.return_contact(conversation)? else {
            return Ok((false, true));
        };
        let row = self.join_row(admin, group.group_id())?;
        Ok((self.join_pending(&row)?, false))
    }

    /// Whether a join row waits for an act: the rows of `GRP-420` and
    /// `GRP-421` wait for none.
    fn join_pending(&self, row: &RowId) -> Result<bool, Error> {
        Ok(!matches!(
            self.join_entry(row)?,
            None | Some(JoinEntry::Sent { .. } | JoinEntry::Joined { .. })
        ))
    }

    /// Step 3 of §11.9.1: the admin adds the joiner and posts the plain
    /// epoch that carries the add to each replica. The result holds the
    /// snapshot that the admin puts on the chunk path (`GRP-323`), which
    /// the admit of step 4 then names.
    pub fn add_joiner<R: CryptoRng + ?Sized>(
        &mut self,
        joiner: &GroupJoiner,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<GroupAdmission, Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        let conversation = self.conversation_of_group(&joiner.group_id)?;
        let row = self.join_row(joiner.from, &joiner.group_id)?;
        let group = self.group_of(conversation)?;
        let own = group
            .roster()
            .member(group.own_index())
            .ok_or(Error::Integrity)?;
        if own.role < Role::Admin {
            return Err(Error::Malformed);
        }
        let record = match self.join_entry(&row)? {
            Some(JoinEntry::Asked { record, .. }) => record,
            // GRP-306: the roster holds the member once. A second call
            // gives the snapshot again for a second try of the admit.
            // GRP-323: the joiner verifies the snapshot against the add it
            // read, thus a second try sends the snapshot of that add and not
            // one of a roster that moved since.
            Some(JoinEntry::Added {
                index, snapshot, ..
            }) if !snapshot.is_empty() => {
                return Ok(GroupAdmission { snapshot, index });
            }
            Some(JoinEntry::Added { index, .. }) => {
                let path = self.authority_path(conversation, &group)?;
                let snapshot = group.snapshot(&path).map_err(|_| Error::Malformed)?;
                return Ok(GroupAdmission { snapshot, index });
            }
            _ => return Err(Error::NotFound),
        };
        let parsed = JoinRecord::parse(&record)?;
        // GRP-329: a roster from a snapshot builds no add before an object
        // of another member gave it the index of the group.
        let add = group.add_object(&parsed).map_err(|_| {
            if group.roster().index_is_open() {
                Error::Busy
            } else {
                Error::Malformed
            }
        })?;
        // GRP-310, GRP-389: the add goes to each replica first, thus its
        // record names the roster epoch that every member holds.
        let queued = self.groups.posts.len();
        self.post_group_control(conversation, &add, now_ms, rng)?;
        // GRP-311: the kept record of the add takes the `GSEQ` of each
        // replica, and the admit names them.
        let add_row = if self.groups.posts.len() > queued {
            self.groups
                .posts
                .back()
                .and_then(|post| Some((post.unsent?, post.replicas.map(|replica| replica.relay))))
        } else {
            None
        };
        let index = self.apply_own_roster_object(conversation, &add, now_ms, rng)?;
        let Applied::Added(index) = index else {
            return Err(Error::Malformed);
        };
        // GRP-324: the snapshot carries the authority path of each role.
        let group = self.group_of(conversation)?;
        let path = self.authority_path(conversation, &group)?;
        let snapshot = group.snapshot(&path).map_err(|_| Error::Malformed)?;
        self.note_member_contact(conversation, index, joiner.from, rng)?;
        // A row of an earlier add of this join is stale now.
        let stale: Vec<RowId> = self
            .add_seqs()?
            .into_iter()
            .filter(|(_, earlier)| earlier.join_row == row)
            .map(|(stale, _)| stale)
            .collect();
        let mut entry = vec![ADDED];
        entry.extend_from_slice(&joiner.from.0);
        entry.extend_from_slice(&joiner.group_id);
        entry.extend_from_slice(&index.to_be_bytes());
        entry.extend_from_slice(&snapshot);
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(joiner.from.0), &entry, rng)?;
        for stale in stale {
            batch.delete(ADD_SEQ, stale);
        }
        if let Some((add_row, relays)) = add_row {
            let held = AddSeq {
                join_row: row,
                from: joiner.from,
                group_id: joiner.group_id,
                index,
                relays,
                answered: 0,
                seqs: [0; 2],
                descriptor: None,
            };
            batch.put(ADD_SEQ, add_row, None, &held.encode(), rng)?;
        }
        batch.commit()?;
        Ok(GroupAdmission { snapshot, index })
    }

    /// Step 4 of §11.9.1: after each replica took the add, the admin sends
    /// the admit with the descriptor of the snapshot (`GRP-311`,
    /// `GRP-312`).
    pub fn admit_joiner<R: CryptoRng + ?Sized>(
        &mut self,
        joiner: &GroupJoiner,
        index: u16,
        descriptor: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        let row = self.join_row(joiner.from, &joiner.group_id)?;
        // GRP-311: the admit waits for the `GSEQ` of the add at each
        // replica, and the descriptor waits with it.
        let waiting = self
            .add_seqs()?
            .into_iter()
            .find(|(_, held)| held.join_row == row);
        if let Some((add_row, mut held)) = waiting {
            held.descriptor = Some(descriptor.to_vec());
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            batch.put(ADD_SEQ, add_row, None, &held.encode(), rng)?;
            batch.commit()?;
            return self.pump_admits(now_ms, rng);
        }
        // A join row of an earlier build kept no add, thus the joiner
        // subscribes from the start of each replica.
        self.send_admit(
            joiner.from,
            &joiner.group_id,
            index,
            descriptor,
            [0; 2],
            now_ms,
            rng,
        )
    }

    /// Each held `ADD_SEQ` row under the row of its add.
    fn add_seqs(&self) -> Result<Vec<(RowId, AddSeq)>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (row, plain) in store.list(ADD_SEQ, None)? {
            if let Ok(held) = AddSeq::parse(&plain) {
                out.push((row, held));
            }
        }
        Ok(out)
    }

    /// A replica returned the `GSEQ` of a kept record. When the record is
    /// the add of a joiner, the `seq` goes into its admit (`GRP-311`).
    pub fn add_answered<R: CryptoRng + ?Sized>(
        &mut self,
        row: &RowId,
        relay: &[u8; 32],
        seq: u32,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(plain) = self.open_ref()?.store.get(ADD_SEQ, row)? else {
            return Ok(());
        };
        let mut held = AddSeq::parse(&plain)?;
        // The replicas that the add went to, which the group may have
        // replaced since.
        if let Some(which) = held.relays.iter().position(|held| held == relay) {
            if let Some(slot) = held.seqs.get_mut(which) {
                *slot = seq;
                held.answered |= 1 << which;
            }
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            batch.put(ADD_SEQ, *row, None, &held.encode(), rng)?;
            batch.commit()?;
        }
        self.pump_admits(now_ms, rng)
    }

    /// Sends each admit whose snapshot uploaded and whose add each replica
    /// answered, or whose add no replica takes any more: a replica that
    /// gave up gives no `seq`, and the joiner reads it from its start
    /// (`GRP-424`). A
    /// row of a join that left goes.
    pub fn pump_admits<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut done = Vec::new();
        for (add_row, held) in self.add_seqs()? {
            // A join that was asked again or that left, and a group that
            // closed or is gone, take no admit of this add.
            let current = matches!(
                self.join_entry(&held.join_row)?,
                Some(JoinEntry::Added { index, .. }) if index == held.index
            );
            let open_group = match self.conversation_of_group(&held.group_id) {
                Ok(conversation) => !self.group_closed(conversation)?,
                Err(_) => false,
            };
            if !current || !open_group {
                done.push(add_row);
                continue;
            }
            let Some(descriptor) = held.descriptor.as_deref() else {
                continue;
            };
            let ended = self
                .open_ref()?
                .store
                .get(GROUP_UNSENT, &add_row)?
                .is_none();
            if held.answered != 0b11 && !ended {
                continue;
            }
            // Each `seq` goes to the replica of the admit with the same
            // relay, and a replica that came since takes 0.
            let seqs = self.seqs_of_admit(&held)?;
            // A fault of one admit ends its row, and no other row.
            let _ = self.send_admit(
                held.from,
                &held.group_id,
                held.index,
                descriptor,
                seqs,
                now_ms,
                rng,
            );
            done.push(add_row);
        }
        if done.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in done {
            batch.delete(ADD_SEQ, row);
        }
        Ok(batch.commit()?)
    }

    /// The `seq` of the add at each replica of the group as it stands, in
    /// the order of its references.
    fn seqs_of_admit(&self, held: &AddSeq) -> Result<[u32; 2], Error> {
        let conversation = self.conversation_of_group(&held.group_id)?;
        let group = self.group_of(conversation)?;
        let mut seqs = [0u32; 2];
        for (index, seq) in seqs.iter_mut().enumerate() {
            let Some(relay) = group
                .replicas()
                .and_then(|replicas| replicas.reference(index))
                .map(|reference| reference.relay_id)
            else {
                continue;
            };
            if let Some(at) = held.relays.iter().position(|held| *held == relay) {
                if held.answered & (1 << at) != 0 {
                    *seq = held.seqs.get(at).copied().unwrap_or(0);
                }
            }
        }
        Ok(seqs)
    }

    /// Step 4 of §11.9.1: the admit on the pairwise channel (`GRP-312`).
    #[allow(clippy::too_many_arguments)]
    fn send_admit<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        group_id: &[u8; 32],
        index: u16,
        descriptor: &[u8],
        seqs: [u32; 2],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let joiner = GroupJoiner {
            from,
            group_id: *group_id,
            is_added: true,
        };
        let conversation = self.conversation_of_group(&joiner.group_id)?;
        let group = self.group_of(conversation)?;
        let row = self.join_row(joiner.from, &joiner.group_id)?;
        // GRP-323: the admit names the roster epoch of the add, which the
        // kept snapshot holds; the roster may have moved since.
        let roster_epoch = match self.join_entry(&row)? {
            Some(JoinEntry::Added { snapshot, .. }) if !snapshot.is_empty() => {
                umbra_wire::group::control::RosterSnapshot::parse(&snapshot)?.roster_epoch
            }
            _ => group.roster().epoch_index(),
        };
        let body = group
            .admit_at(index, roster_epoch, descriptor, seqs, now_ms / 1_000)
            .map_err(|_| Error::Malformed)?;
        self.send_pairwise_control(joiner.from, &body, now_ms, rng)?;
        // GRP-420: the row stays while the add is the head, thus an epoch
        // that displaces the add finds the joiner.
        let mut entry = vec![SENT];
        entry.extend_from_slice(&joiner.from.0);
        entry.extend_from_slice(&joiner.group_id);
        entry.extend_from_slice(&roster_epoch.to_be_bytes());
        entry.extend_from_slice(&index.to_be_bytes());
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(joiner.from.0), &entry, rng)?;
        Ok(batch.commit()?)
    }

    /// Drops the rows of `GRP-420` and `GRP-421` of a group whose roster moved past the
    /// add that they name: no epoch displaces that add any more.
    fn drop_passed_adds(&mut self, conversation: ConversationId) -> Result<(), Error> {
        let group = self.group_of(conversation)?;
        let (group_id, head) = (*group.group_id(), group.roster().epoch_index());
        drop(group);
        let mut gone = Vec::new();
        for row in self.join_rows()? {
            let passed = match self.join_entry(&row)? {
                Some(JoinEntry::Sent {
                    group_id: held,
                    add_epoch,
                    ..
                }) => held == group_id && add_epoch < head,
                Some(JoinEntry::Joined {
                    group_id: held,
                    add_epoch,
                    ..
                }) => held == group_id && add_epoch < head,
                _ => false,
            };
            if passed {
                gone.push(row);
            }
        }
        if gone.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in gone {
            batch.delete(GROUP_JOIN, row);
        }
        Ok(batch.commit()?)
    }

    /// Step 5 of §11.9.1: the joiner fetched the snapshot that its admit
    /// named, and this call verifies the two and stores the group
    /// (`GRP-313`, `GRP-326`).
    pub fn accept_group_admit<R: CryptoRng + ?Sized>(
        &mut self,
        from: ConversationId,
        group_id: &[u8; 32],
        snapshot: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<ConversationId, Error> {
        let row = self.join_row(from, group_id)?;
        let Some(JoinEntry::Admitted {
            creator_roster_pk,
            admit,
            name,
            again,
            ..
        }) = self.join_entry(&row)?
        else {
            return Err(Error::NotFound);
        };
        // GRP-421: a second admit takes the place of the group only while
        // the add of this member is the head of its roster. Else an admit
        // to a group that this device is a member of is no admit
        // (`GRP-153`). Its row leaves, thus no fetch asks for its snapshot
        // again.
        let conversation = self.conversation_of_group(group_id)?;
        if self.holds_membership(conversation)? {
            let held = self.group_of(conversation)?;
            let is_head = held.roster().epoch_index() == held.roster().admission_epoch();
            if !again || !is_head {
                let open = self.open_mut()?;
                let mut batch = open.store.begin();
                batch.delete(GROUP_JOIN, row);
                batch.commit()?;
                return Err(Error::Malformed);
            }
        }
        let seed = {
            let store = &self.open_ref()?.store;
            // GRP-370: a member that comes back after a rival re-key joins
            // under the seed that it sent to the admin. So does a member
            // that takes a new invitation after its membership ended.
            let lost_row = store.row_id(TableId::LOCAL_IDENTITY, &lost_seed_key(group_id));
            let seed_row = store.row_id(TableId::LOCAL_IDENTITY, group_id);
            let seed = Zeroizing::new(match store.get(TableId::LOCAL_IDENTITY, &lost_row)? {
                Some(lost) => lost,
                None => store
                    .get(TableId::LOCAL_IDENTITY, &seed_row)?
                    .ok_or(Error::Integrity)?,
            });
            let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
            Secret::new(seed)
        };
        let control = GroupControl::parse(&admit)?;
        let invitation = GroupInvitation::parse(control.payload)?;
        // GRP-326: the snapshot verifies against the hash of the add and
        // the roster key of the creator, which the offer carried.
        let checked = umbra_wire::group::control::RosterSnapshot::parse(snapshot)
            .map_err(Error::from)
            .and_then(|snapshot| {
                let add_hash = Self::add_hash_of(&invitation, &snapshot)?;
                // The entry at the index of the admit holds the keys of
                // this device, or the admission fails here.
                accept_admit(&invitation, &snapshot, &add_hash, &creator_roster_pk, now)
                    .and_then(|admitted| admitted.for_seed(&seed))
                    .map(|admitted| (admitted, snapshot))
                    .map_err(|_| Error::Integrity)
            });
        let (admitted, snapshot) = match checked {
            Ok(checked) => checked,
            // GRP-327, GRP-328: the snapshot does not verify, thus this
            // device is in no group, and the view shows a failed admission.
            Err(error) => {
                self.refuse_admit(&row, from, group_id, &name, rng)?;
                return Err(error);
            }
        };
        let add_epoch = snapshot.roster_epoch;
        let conversation = self.adopt_group(admitted, &seed, &name, again, rng)?;
        // GRP-290: the contact that brought this device in is a member it
        // can ask on a pairwise channel when the group queue refuses it.
        self.note_contact_in(conversation, b"via", from, rng)?;
        // That admin shows under the name of the contact. It is the member
        // whose roster key the offer of this same contact named, when the
        // snapshot gives it `admin` or above. An offer of another contact
        // names nobody here (`GRP-244`).
        if let Some(index) = self.offering_admin(conversation, from)? {
            self.note_contact_in(conversation, &index.to_be_bytes(), from, rng)?;
        }
        self.end_other_joins(conversation, group_id, row)?;
        // GRP-068: this member may build a snapshot later, thus it keeps
        // the path that admitted it.
        for grant in umbra_core::group::roster::split_path(snapshot.path)? {
            self.note_grant(conversation, grant, rng)?;
        }
        // GRP-421: the row stays while the add is the head, thus a second
        // admit of this admin takes the place of the group.
        let mut entry = vec![JOINED];
        entry.extend_from_slice(&from.0);
        entry.extend_from_slice(group_id);
        entry.extend_from_slice(&add_epoch.to_be_bytes());
        entry.extend_from_slice(&creator_roster_pk);
        entry.extend_from_slice(name.as_bytes());
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
        batch.commit()?;
        // DEV-298: the group goes to the other devices of the set.
        self.group_state_due(conversation, rng)?;
        let members = self.group_of(conversation)?.roster().active_count();
        self.start_group_alert(conversation, members, rng)?;
        Ok(conversation)
    }

    /// The hash of the add record that the snapshot describes. The
    /// snapshot carries it, and `accept_admit` tests the two against each
    /// other (`GRP-326`).
    fn add_hash_of(
        invitation: &GroupInvitation<'_>,
        snapshot: &umbra_wire::group::control::RosterSnapshot<'_>,
    ) -> Result<[u8; 32], Error> {
        let InvitationStage::Admit(admit) = &invitation.stage else {
            return Err(Error::Malformed);
        };
        if admit.roster_epoch != snapshot.roster_epoch {
            return Err(Error::Integrity);
        }
        Ok(snapshot.chain_hash)
    }

    /// The offers that wait for the user (`GRP-170`).
    pub fn group_offers(&self) -> Result<Vec<GroupOffer>, Error> {
        let mut out = Vec::new();
        for row in self.join_rows()? {
            if let Some(JoinEntry::Offer {
                from,
                group_id,
                name,
                ..
            }) = self.join_entry(&row)?
            {
                out.push(GroupOffer {
                    from,
                    group_id,
                    name,
                });
            }
        }
        Ok(out)
    }

    /// Keeps an admit whose snapshot failed a check, in place of the admit
    /// that waited. No fetch asks for its snapshot again.
    fn refuse_admit<R: CryptoRng + ?Sized>(
        &mut self,
        row: &RowId,
        from: ConversationId,
        group_id: &[u8; 32],
        name: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut entry = vec![REFUSED];
        entry.extend_from_slice(&from.0);
        entry.extend_from_slice(group_id);
        entry.extend_from_slice(name.as_bytes());
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, *row, Some(from.0), &entry, rng)?;
        batch.commit()?;
        self.events.push_back(Event::GroupOffer { from });
        Ok(())
    }

    /// Each admission that failed because its snapshot did not verify
    /// (`GRP-328`).
    pub fn failed_admissions(&self) -> Result<Vec<GroupOffer>, Error> {
        let mut out = Vec::new();
        for row in self.join_rows()? {
            if let Some(JoinEntry::Refused {
                from,
                group_id,
                name,
            }) = self.join_entry(&row)?
            {
                out.push(GroupOffer {
                    from,
                    group_id,
                    name,
                });
            }
        }
        Ok(out)
    }

    /// The user saw a failed admission, and it leaves the store.
    pub fn dismiss_failed_admission(
        &mut self,
        from: ConversationId,
        group_id: &[u8; 32],
    ) -> Result<(), Error> {
        let row = self.join_row(from, group_id)?;
        if !matches!(self.join_entry(&row)?, Some(JoinEntry::Refused { .. })) {
            return Err(Error::NotFound);
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(GROUP_JOIN, row);
        Ok(batch.commit()?)
    }

    /// The joiners that wait for an admin of this device (`GRP-310`).
    pub fn group_joiners(&self) -> Result<Vec<GroupJoiner>, Error> {
        let mut out = Vec::new();
        for row in self.join_rows()? {
            match self.join_entry(&row)? {
                Some(JoinEntry::Asked { from, group_id, .. }) => out.push(GroupJoiner {
                    from,
                    group_id,
                    is_added: false,
                }),
                Some(JoinEntry::Added { from, group_id, .. }) => out.push(GroupJoiner {
                    from,
                    group_id,
                    is_added: true,
                }),
                _ => {}
            }
        }
        Ok(out)
    }

    /// The admits that wait for the snapshot they name (`GRP-313`). The
    /// caller fetches each descriptor on the chunk path and then calls
    /// [`Client::accept_group_admit`].
    pub fn group_admits(&self) -> Result<Vec<GroupAdmitWaiting>, Error> {
        let mut out = Vec::new();
        for row in self.join_rows()? {
            let Some(JoinEntry::Admitted { from, admit, .. }) = self.join_entry(&row)? else {
                continue;
            };
            let Ok(control) = GroupControl::parse(&admit) else {
                continue;
            };
            let Ok(invitation) = GroupInvitation::parse(control.payload) else {
                continue;
            };
            let InvitationStage::Admit(stage) = &invitation.stage else {
                continue;
            };
            out.push(GroupAdmitWaiting {
                from,
                group_id: invitation.group_id,
                descriptor: stage.descriptor.to_vec(),
            });
        }
        Ok(out)
    }

    fn join_row(&self, from: ConversationId, group_id: &[u8; 32]) -> Result<RowId, Error> {
        let store = &self.open_ref()?.store;
        Ok(store.row_id(GROUP_JOIN, &[from.0.as_slice(), group_id].concat()))
    }

    /// Each row of the join table. Each entry names its own conversation.
    fn join_rows(&self) -> Result<Vec<RowId>, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .list(GROUP_JOIN, None)?
            .into_iter()
            .map(|(row, plain)| {
                drop(Zeroizing::new(plain));
                row
            })
            .collect())
    }

    fn join_entry(&self, row: &RowId) -> Result<Option<JoinEntry>, Error> {
        let store = &self.open_ref()?.store;
        let Some(plain) = store.get(GROUP_JOIN, row)? else {
            return Ok(None);
        };
        let plain = Zeroizing::new(plain);
        let kind = *plain.first().ok_or(Error::Integrity)?;
        let from: [u8; 16] = plain
            .get(1..17)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let from = ConversationId(from);
        let group_id: [u8; 32] = plain
            .get(17..49)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let rest = plain.get(49..).ok_or(Error::Integrity)?;
        Ok(Some(match kind {
            REFUSED => JoinEntry::Refused {
                from,
                group_id,
                name: core::str::from_utf8(rest)
                    .map_err(|_| Error::Integrity)?
                    .to_owned(),
            },
            OFFERED => {
                let (key, name) = rest
                    .split_at_checked(ROSTER_PK_LEN)
                    .ok_or(Error::Integrity)?;
                JoinEntry::Offer {
                    from,
                    group_id,
                    creator_roster_pk: key.to_vec(),
                    name: core::str::from_utf8(name)
                        .map_err(|_| Error::Integrity)?
                        .to_owned(),
                }
            }
            WAITING => {
                let (key, name) = rest
                    .split_at_checked(ROSTER_PK_LEN)
                    .ok_or(Error::Integrity)?;
                JoinEntry::Waiting {
                    creator_roster_pk: key.to_vec(),
                    name: core::str::from_utf8(name)
                        .map_err(|_| Error::Integrity)?
                        .to_owned(),
                }
            }
            ADMITTED | READMITTED => {
                let (key, rest) = rest
                    .split_at_checked(ROSTER_PK_LEN)
                    .ok_or(Error::Integrity)?;
                let (len, rest) = rest.split_at_checked(4).ok_or(Error::Integrity)?;
                let len = usize::try_from(u32::from_be_bytes(
                    len.try_into().map_err(|_| Error::Integrity)?,
                ))
                .map_err(|_| Error::Integrity)?;
                let (admit, name) = rest.split_at_checked(len).ok_or(Error::Integrity)?;
                JoinEntry::Admitted {
                    from,
                    creator_roster_pk: key.to_vec(),
                    admit: admit.to_vec(),
                    name: core::str::from_utf8(name)
                        .map_err(|_| Error::Integrity)?
                        .to_owned(),
                    again: kind == READMITTED,
                }
            }
            SENT => {
                let (epoch, index) = rest.split_at_checked(4).ok_or(Error::Integrity)?;
                JoinEntry::Sent {
                    from,
                    group_id,
                    index: u16::from_be_bytes(index.try_into().map_err(|_| Error::Integrity)?),
                    add_epoch: u32::from_be_bytes(epoch.try_into().map_err(|_| Error::Integrity)?),
                }
            }
            JOINED => {
                let (epoch, rest) = rest.split_at_checked(4).ok_or(Error::Integrity)?;
                let (key, name) = rest
                    .split_at_checked(ROSTER_PK_LEN)
                    .ok_or(Error::Integrity)?;
                JoinEntry::Joined {
                    group_id,
                    add_epoch: u32::from_be_bytes(epoch.try_into().map_err(|_| Error::Integrity)?),
                    creator_roster_pk: key.to_vec(),
                    name: core::str::from_utf8(name)
                        .map_err(|_| Error::Integrity)?
                        .to_owned(),
                }
            }
            ASKED => JoinEntry::Asked {
                from,
                group_id,
                record: rest.to_vec(),
            },
            ADDED => {
                let (index, snapshot) = rest.split_at_checked(2).ok_or(Error::Integrity)?;
                JoinEntry::Added {
                    from,
                    group_id,
                    index: u16::from_be_bytes(index.try_into().map_err(|_| Error::Integrity)?),
                    snapshot: snapshot.to_vec(),
                }
            }
            _ => return Err(Error::Integrity),
        }))
    }

    /// Stores the group of an admit that a pairwise channel carried
    /// (`GRP-313`). The joiner holds the two queues from the admit, thus
    /// the group is ready at once.
    pub fn adopt_group<R: CryptoRng + ?Sized>(
        &mut self,
        admitted: Admitted,
        seed: &Secret<32>,
        name: &str,
        replaces: bool,
        rng: &mut R,
    ) -> Result<ConversationId, Error> {
        let name = name.trim();
        if name.len() > GROUP_NAME_MAX {
            return Err(Error::TooLong);
        }
        let group = Group::joined(admitted, seed).map_err(|_| Error::Malformed)?;
        let group_id = *group.group_id();
        // GRP-153: a second admit to a group that this device is a member
        // of is no group. A member whose membership ended comes back under
        // the admit (`GRP-414`, Part 11 §11.12). The new group takes the
        // place of the one it held, in the conversation that it held. So
        // does the second admit of `GRP-421`.
        let conversation = self.conversation_of_group(&group_id)?;
        if !replaces && self.holds_membership(conversation)? {
            return Err(Error::Malformed);
        }
        // The rows of the membership before leave with it. A record that it
        // sealed, and the owner credentials and the clocks that it held,
        // belong to an index that the roster holds no more.
        let stale = if self.is_group(conversation)? {
            self.forget_group_work(conversation);
            self.membership_rows(conversation)?
        } else {
            Vec::new()
        };
        let row = Self::group_row(&group, OPEN)?;
        let open = self.open_mut()?;
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, &group_id);
        let lost_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, &lost_seed_key(&group_id));
        let previous_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, &previous_seed_key(&group_id));
        let mut batch = open.store.begin();
        for (table, stale) in stale {
            batch.delete(table, stale);
        }
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        batch.put(TableId::LOCAL_IDENTITY, seed_row, None, seed.expose(), rng)?;
        batch.delete(TableId::LOCAL_IDENTITY, lost_row);
        batch.delete(TableId::LOCAL_IDENTITY, previous_row);
        batch.commit()?;
        // The conversation keeps its read mark over a new membership.
        let (read_up_to, _) = self.conversation_meta(conversation)?;
        self.put_conversation_meta(conversation, read_up_to, name, rng)?;
        Ok(conversation)
    }

    /// Seals one `AppMessage` for a group and queues it for each replica.
    /// A group whose two queues are not there yet stores the message and
    /// posts nothing, and the next unlock or the second `GIDS` sends it.
    pub(super) fn post_to_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        msg_id: [u8; 16],
        app: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let open = self.open_mut()?;
        let reference = super::msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open
            .store
            .row_id(umbra_core::store::record::TableId::MESSAGE, &natural);
        let plain = stored_message(
            super::OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            app,
        );
        let mut batch = open.store.begin();
        batch.put(
            umbra_core::store::record::TableId::MESSAGE,
            row,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        batch.put(OUTBOX, row, None, &super::outbox_row(), rng)?;
        batch.commit()?;
        let message = MsgRef(row);
        // DEV-245: the period of a record of this device runs from its send,
        // and the sync copy carries it.
        let kind = AppMessage::parse(app, umbra_wire::app::Channel::Group)?.kind;
        self.stamp_deadline(conversation, message, kind, now_ms / 1_000, rng)?;
        self.queue_group_post(conversation, Some(message), app, now_ms, rng)?;
        Ok(message)
    }

    /// Builds the record of one stored message and queues it, when the
    /// group holds both of its queues.
    pub(super) fn queue_group_post<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: Option<MsgRef>,
        app: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.queue_group_post_at(conversation, message, app, None, now_ms, rng)
    }

    /// As [`Client::queue_group_post`], under `roster_epoch` when one is
    /// given (`GRP-330`).
    pub(super) fn queue_group_post_at<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: Option<MsgRef>,
        app: &[u8],
        roster_epoch: Option<u32>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338, GRP-340: the device that owns the channels posts each
        // record of the member. Another device hands a record of the user to
        // it, and makes no record of the group itself.
        if !self.owns_channels()? {
            let kind = AppMessage::parse(app, umbra_wire::app::Channel::Group)?.kind;
            if kind != AppKind::GroupControl {
                self.publish_sync(conversation, app, true, message, now_ms / 1_000, rng)?;
            }
            return Ok(());
        }
        // GRP-210: a group whose two queues are gone takes no record, and
        // the view shows that the message did not go (`IMP-076`). The user
        // sends it again when the group opens.
        if self.group_closed(conversation)? {
            if let Some(message) = message {
                self.fail(&message, crate::FailureCause::Refused, rng)?;
            }
            return Ok(());
        }
        let mut group = self.group_of(conversation)?;
        // GRP-422: a key that reaches a removed party carries no record but
        // a roster object, thus this device rotates first. A rotation that
        // this device may not make leaves the post under the current key.
        // A rotation that fails sends nothing under that key: the message
        // shows that it did not go, as in a closed group.
        if group.withholds()
            && AppMessage::parse(app, umbra_wire::app::Channel::Group)?.kind
                != AppKind::GroupControl
        {
            if let Err(fault) = self.rotate_group(conversation, now_ms, rng) {
                let Some(message) = message else {
                    return Err(fault);
                };
                self.fail(&message, crate::FailureCause::Refused, rng)?;
                return Ok(());
            }
            group = self.group_of(conversation)?;
        }
        let Some(replicas) = group.replicas() else {
            return Ok(());
        };
        let replicas = [
            GroupReplica {
                relay: replicas.reference(0).ok_or(Error::Integrity)?.relay_id,
                group_queue_id: replicas
                    .reference(0)
                    .ok_or(Error::Integrity)?
                    .group_queue_id,
            },
            GroupReplica {
                relay: replicas.reference(1).ok_or(Error::Integrity)?.relay_id,
                group_queue_id: replicas
                    .reference(1)
                    .ok_or(Error::Integrity)?
                    .group_queue_id,
            },
        ];
        // GRP-076: each member discards a roster object above a rate of
        // the roster chain, thus this device posts none and the act fails.
        if group.rate_bars(app, now_ms / 1_000) {
            return Err(Error::Busy);
        }
        // GRP-246: the counter of this device moves with the record, thus
        // the group goes back to the store before the record leaves.
        let record = match roster_epoch {
            Some(held) => group.post_at_roster(app, held, now_ms / 1_000, rng),
            None => group.post(app, now_ms / 1_000, rng),
        }
        .map_err(|_| Error::Malformed)?;
        let write = group.credentials().ok_or(Error::Integrity)?.write_secret();
        let fallback = group.previous_credentials().map(|held| held.write_secret());
        self.save_group(conversation, &group, rng)?;
        self.keep_post(
            GroupPost {
                message,
                conversation,
                replicas,
                write,
                fallback,
                record,
                is_rotation: false,
                unsent: None,
                pending: [true; GROUP_REPLICAS],
            },
            rng,
        )?;
        self.put_clock(conversation, sent_key(conversation), now_ms / 1_000, rng)?;
        // A record of the member carries no tag for its own index, thus
        // another device of the set cannot read it on the group queue. It
        // takes the record on the sync channel (DEV-296).
        self.publish_sync(conversation, app, true, None, now_ms / 1_000, rng)
    }

    /// Takes a record of a group that another device of the set synced
    /// (DEV-296). The device that owns the channels posts a record that a
    /// peer handed to it (GRP-340). Another device applies a roster object
    /// of the member, and keeps each other record as one of the user.
    pub(super) fn apply_synced_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        app: &[u8],
        expires_in: u32,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let parsed = AppMessage::parse(app, umbra_wire::app::Channel::Group)?;
        // DEV-248: a device of an admin sets the timer, and no other.
        let timer = if parsed.kind == AppKind::ConversationTimer {
            let group = self.group_of(conversation)?;
            if group.own_role().is_none_or(|role| role < Role::Admin) {
                return Ok(());
            }
            let Some(seconds) = super::timers::timer_body(parsed.body) else {
                return Ok(());
            };
            Some(seconds)
        } else {
            None
        };
        // DEV-325: a device of an admin sets the forward policy, and no
        // other.
        let policy = if parsed.kind == AppKind::ForwardPolicy {
            let group = self.group_of(conversation)?;
            if group.own_role().is_none_or(|role| role < Role::Admin) {
                return Ok(());
            }
            let Ok(policy) = umbra_wire::app::signal::ForwardPolicy::parse(parsed.body) else {
                return Ok(());
            };
            Some(policy)
        } else {
            None
        };
        let open = self.open_ref()?;
        let reference = super::msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let message = MsgRef(
            open.store
                .row_id(umbra_core::store::record::TableId::MESSAGE, &natural),
        );
        // A second copy moves no timer and no deadline.
        if open
            .store
            .get(umbra_core::store::record::TableId::MESSAGE, &message.0)?
            .is_some()
        {
            return Ok(());
        }
        // An edit and a deletion of the user from another device change the
        // message here, and the owner of the channels posts them.
        if matches!(parsed.kind, AppKind::Edit | AppKind::Delete) {
            if self.owns_channels()? {
                self.post_to_group(conversation, parsed.msg_id, app, now_ms, rng)?;
            }
            self.take_group_change(conversation, None, &parsed, now_ms, rng)?;
            return Ok(());
        }
        // A vote of the user from another device moves the count here.
        if parsed.kind == AppKind::PollVote {
            if self.owns_channels()? {
                self.post_to_group(conversation, parsed.msg_id, app, now_ms, rng)?;
            }
            self.take_vote(
                conversation,
                parsed.body,
                super::polls::VOTER_SELF,
                now_ms,
                now_ms / 1_000,
                rng,
            )?;
            return Ok(());
        }
        // DEV-323: an older policy changes nothing and is no row.
        if let Some(policy) = policy {
            if !self.take_group_forward_policy(conversation, &policy, rng)? {
                return Ok(());
            }
        }
        self.store_synced_group(conversation, app, now_ms, rng)?;
        if parsed.kind == AppKind::Poll {
            let open_seconds =
                umbra_wire::app::poll::Poll::parse(parsed.body).map_or(0, |poll| poll.open_seconds);
            self.open_poll(conversation, message, open_seconds, now_ms / 1_000, rng)?;
        }
        if let Some(seconds) = timer {
            self.put_timer(conversation, seconds, now_ms, true, rng)?;
        } else if expires_in > 0 && super::timers::is_timed_kind(parsed.kind) {
            // DEV-244: the sync copy carries the deadline, and the owner of
            // the channels takes it from there (DEV-245).
            let deadline =
                umbra_core::devset::edits::Deadline::from_sync(now_ms / 1_000, expires_in);
            self.put_deadline(conversation, message, deadline, rng)?;
        }
        Ok(())
    }

    /// The store and the post of [`Client::apply_synced_group`].
    fn store_synced_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        app: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let parsed = AppMessage::parse(app, umbra_wire::app::Channel::Group)?;
        let open = self.open_ref()?;
        let reference = super::msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open
            .store
            .row_id(umbra_core::store::record::TableId::MESSAGE, &natural);
        if open
            .store
            .get(umbra_core::store::record::TableId::MESSAGE, &row)?
            .is_some()
        {
            return Ok(());
        }
        if self.owns_channels()? {
            if parsed.kind != AppKind::GroupControl {
                self.post_to_group(conversation, parsed.msg_id, app, now_ms, rng)?;
            }
            return Ok(());
        }
        if parsed.kind == AppKind::GroupControl {
            // A re-key of the member moves the device that made it alone,
            // since only it holds the new seed.
            let is_rekey = GroupControl::parse(parsed.body).is_ok_and(|control| {
                control.control_type == umbra_wire::group::control::ControlType::Rekey
            });
            // GRP-076: the rates count on the slot of the record that the
            // owner of the channels built. They count at the time that its
            // `AppMessage` names, and not at the time of this arrival.
            if !is_rekey {
                self.apply_roster_object_of(
                    conversation,
                    parsed.body,
                    parsed.sent_at,
                    now_ms,
                    rng,
                )?;
            }
            return Ok(());
        }
        let limit = self.download_limit_now()?;
        let open = self.open_mut()?;
        let mut kept = Zeroizing::new(app.to_vec());
        if super::keep_reply_as_reference(&mut kept, &open.device_set_key).is_err() {
            return Ok(());
        }
        let plain = stored_message(
            super::OUTGOING,
            Delivery::Accepted,
            conversation,
            open.stamp.next(now_ms),
            &kept,
        );
        let mut batch = open.store.begin();
        batch.put(
            umbra_core::store::record::TableId::MESSAGE,
            row,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        let mut wanted = None;
        if parsed.kind == AppKind::Attachment {
            let (state, descriptor) = super::files::incoming_state_row(parsed.body, limit);
            batch.put(
                super::files::FILE_STATE,
                row,
                Some(conversation.0),
                &state,
                rng,
            )?;
            wanted = descriptor;
        }
        batch.commit()?;
        let message = MsgRef(row);
        if let Some(descriptor) = wanted {
            self.files.downloads.push_back(super::files::DownloadJob {
                message,
                descriptor: Box::new(descriptor),
            });
        }
        self.events.push_back(crate::Event::Delivery {
            message,
            delivery: Delivery::Accepted,
        });
        Ok(())
    }

    /// The two replicas of a group, or none before both `GNEW` answers.
    fn group_replicas_of(group: &Group) -> Result<Option<[GroupReplica; GROUP_REPLICAS]>, Error> {
        let Some(replicas) = group.replicas() else {
            return Ok(None);
        };
        let mut out = [GroupReplica {
            relay: [0; 32],
            group_queue_id: [0; 32],
        }; GROUP_REPLICAS];
        for (which, slot) in out.iter_mut().enumerate() {
            let reference = replicas.reference(which).ok_or(Error::Integrity)?;
            *slot = GroupReplica {
                relay: reference.relay_id,
                group_queue_id: reference.group_queue_id,
            };
        }
        Ok(Some(out))
    }

    /// Removes a member and rotates in the same action (`GRP-264`). The
    /// roster object goes out under the epoch that stands, and the
    /// epoch-key record after it.
    pub fn remove_from_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        let object = self
            .group_of(conversation)?
            .remove_object(index)
            .map_err(|_| Error::Malformed)?;
        if !self.roster_takes(conversation, &object, now_ms)? {
            return Err(Error::Malformed);
        }
        self.post_group_control(conversation, &object, now_ms, rng)?;
        self.apply_own_roster_object(conversation, &object, now_ms, rng)?;
        self.rotate_group(conversation, now_ms, rng)
    }

    /// Gives a role to a member (§11.9.2). The granting epoch goes out
    /// before it applies here (`GRP-389`). A member that rises to `admin`
    /// takes the owner credentials in the record after it (`GRP-298`), and
    /// a member that falls below `admin` leaves with credentials that the
    /// relay still takes, thus this admin draws new ones (`GRP-401`).
    pub fn set_group_role<R: CryptoRng + umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        role: Role,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        let group = self.group_of(conversation)?;
        let held = group
            .roster()
            .member(index)
            .filter(|member| member.active)
            .ok_or(Error::NotFound)?
            .role;
        if index == group.own_index() {
            return Err(Error::Malformed);
        }
        if held == role {
            return Ok(());
        }
        // The owner credentials travel with the admin roles, thus a device
        // that holds none gives no such role.
        if (held >= Role::Admin || role >= Role::Admin) && group.owner(0).is_none() {
            return Err(Error::Malformed);
        }
        let object = group
            .grant(index, role, rng)
            .map_err(|_| Error::Malformed)?;
        drop(group);
        // GRP-304, GRP-051: a grant above `ROLE_HOLDER_MAX` or below the
        // owner floor applies at no member.
        if !self.roster_takes(conversation, &object, now_ms)? {
            return Err(Error::Malformed);
        }
        self.post_group_control(conversation, &object, now_ms, rng)?;
        self.apply_own_roster_object(conversation, &object, now_ms, rng)?;
        if held < Role::Admin && role >= Role::Admin {
            let group = self.group_of(conversation)?;
            let record = group
                .owner_delivery(index, rng)
                .map_err(|_| Error::Malformed)?;
            self.queue_group_record(conversation, &group, record, now_ms, rng)?;
            self.note_owners(conversation, &group, rng)?;
        } else if held >= Role::Admin && role < Role::Admin {
            self.rotate_owners(conversation, now_ms, rng)?;
        }
        Ok(())
    }

    /// Queues one record that this group built for each replica.
    fn queue_group_record<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        record: Vec<u8>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(replicas) = Self::group_replicas_of(group)? else {
            return Ok(());
        };
        let write = group.credentials().ok_or(Error::Integrity)?.write_secret();
        let fallback = group.previous_credentials().map(|held| held.write_secret());
        self.keep_post(
            GroupPost {
                message: None,
                conversation,
                replicas,
                write,
                fallback,
                record,
                is_rotation: false,
                unsent: None,
                pending: [true; GROUP_REPLICAS],
            },
            rng,
        )?;
        self.put_clock(conversation, sent_key(conversation), now_ms / 1_000, rng)
    }

    /// Draws new owner credentials, moves each replica to them with a
    /// `GKEY` under the ones they replace, and hands them to each other
    /// admin (`GRP-401`, `WIR-522`, `GRP-400`).
    pub fn rotate_owners<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels does the work of the
        // member in each group.
        if !self.owns_channels()? {
            return Ok(());
        }
        self.groups.owner_backoff.remove(&conversation);
        if self.group_closed(conversation)? {
            return Ok(());
        }
        let mut group = self.group_of(conversation)?;
        if Self::group_replicas_of(&group)?.is_none() {
            return Ok(());
        }
        let old = group.replace_owners(rng).map_err(|_| Error::Malformed)?;
        // GRP-401: the credentials that the new ones replace authorize the
        // `GKEY` that carries the new `own_pk`, and no other party holds
        // them for this device. They go to the store before the group row
        // loses them. They stay until that `GKEY` arrived at each replica,
        // thus a run that ends first sends it again.
        let mut held = self.gkey_row(conversation)?;
        for (replaced, before) in held.replaced.iter_mut().zip(&old) {
            replaced.push(Secret::new(*before.expose()));
            let excess = replaced.len().saturating_sub(OWNER_HELD_MAX);
            replaced.drain(..excess);
        }
        self.put_gkey_row(conversation, &held, rng)?;
        self.save_group(conversation, &group, rng)?;
        self.queue_gkeys(conversation, &group, true)?;
        let admins: Vec<u16> = group
            .roster()
            .active()
            .filter(|member| member.role >= Role::Admin && member.index != group.own_index())
            .map(|member| member.index)
            .collect();
        for index in admins {
            let record = group
                .owner_delivery(index, rng)
                .map_err(|_| Error::Malformed)?;
            self.queue_group_record(conversation, &group, record, now_ms, rng)?;
        }
        self.note_owners(conversation, &group, rng)
    }

    /// Whether this device is an owner and an owner stayed silent for
    /// `GROUP_SILENT_EVICT` while the group holds no more than `OWNER_MIN`
    /// owners, thus the group needs another owner before that one can go
    /// (`GRP-168`, `GRP-184`).
    pub fn owner_needed(&self, conversation: ConversationId, now_ms: u64) -> Result<bool, Error> {
        let group = self.group_of(conversation)?;
        let now = now_ms / 1_000;
        if group.own_role() != Some(Role::Owner) {
            return Ok(false);
        }
        let roster = group.roster();
        let owners = roster.owner_count();
        for member in roster.active() {
            if member.role != Role::Owner || member.index == group.own_index() {
                continue;
            }
            let seen = self.clock(&Self::member_key(conversation, member.index))?;
            let is_silent = seen.is_some_and(|at| now.saturating_sub(at) >= GROUP_SILENT_EVICT);
            if is_silent
                && PresenceTracker::eviction(member.role, roster.active_count(), owners)
                    == Eviction::HoldForOwners
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Keeps one granting epoch of a group (`GRP-068`).
    fn note_grant<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        control: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let parsed = GroupControl::parse(control)?;
        let grant = umbra_wire::group::control::GrantingEpoch::parse(parsed.payload)?;
        let key = [
            conversation.0.as_slice(),
            &grant.chain.epoch_index.to_be_bytes(),
        ]
        .concat();
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_GRANTS, &key);
        let mut batch = open.store.begin();
        batch.put(GROUP_GRANTS, row, Some(conversation.0), control, rng)?;
        Ok(batch.commit()?)
    }

    /// The authority path of the current roles of a group, from the grants
    /// that this device keeps. Each grant on no path leaves (`GRP-069`).
    pub(crate) fn authority_path(
        &mut self,
        conversation: ConversationId,
        group: &Group,
    ) -> Result<Vec<u8>, Error> {
        let store = &self.open_ref()?.store;
        let mut rows = Vec::new();
        for (row, _) in store.list(GROUP_GRANTS, Some(&conversation.0))? {
            if let Some(bytes) = store.get(GROUP_GRANTS, &row)? {
                rows.push((row, bytes));
            }
        }
        let grants: Vec<&[u8]> = rows.iter().map(|(_, bytes)| bytes.as_slice()).collect();
        let (path, kept) = group
            .roster()
            .authority_path(&grants)
            .map_err(|_| Error::Integrity)?;
        let gone: Vec<RowId> = rows
            .iter()
            .enumerate()
            .filter(|(position, _)| !kept.contains(position))
            .map(|(_, (row, _))| *row)
            .collect();
        if !gone.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for row in gone {
                batch.delete(GROUP_GRANTS, row);
            }
            batch.commit()?;
        }
        Ok(path)
    }

    /// The admins of a group now, which hold its owner credentials.
    fn admins_of(group: &Group) -> Vec<u16> {
        group
            .roster()
            .active()
            .filter(|member| member.role >= Role::Admin)
            .map(|member| member.index)
            .collect()
    }

    /// Records the admins that hold the owner credentials of this device.
    fn note_owners<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        rng: &mut R,
    ) -> Result<(), Error> {
        let set: Vec<u8> = Self::admins_of(group)
            .iter()
            .flat_map(|index| index.to_be_bytes())
            .collect();
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_OWNERS, &conversation.0);
        let mut batch = open.store.begin();
        batch.put(GROUP_OWNERS, row, Some(conversation.0), &set, rng)?;
        Ok(batch.commit()?)
    }

    /// Each group whose owner credentials a member holds that is no admin
    /// now, when this device is the admin of the lowest index, after its
    /// backoff (`GRP-402`). A group seen for the first time records its
    /// admins and owes nothing.
    pub fn groups_owing_owners<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Vec<ConversationId>, Error> {
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            if self.group_closed(conversation)? {
                continue;
            }
            let group = self.group_of(conversation)?;
            if group.owner(0).is_none() || group.own_role().is_none_or(|role| role < Role::Admin) {
                continue;
            }
            let row = {
                let store = &self.open_ref()?.store;
                let key = store.row_id(GROUP_OWNERS, &conversation.0);
                store.get(GROUP_OWNERS, &key)?
            };
            let Some(held) = row else {
                self.note_owners(conversation, &group, rng)?;
                continue;
            };
            let admins = Self::admins_of(&group);
            let gone: Vec<u16> = held
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .filter(|index| !admins.contains(index))
                .collect();
            // GRP-402: one admin acts, the one of the lowest index, thus two
            // admins draw no two sets for one departure.
            if gone.is_empty() || admins.first() != Some(&group.own_index()) {
                self.groups.owner_backoff.remove(&conversation);
                continue;
            }
            // A member that fell below `admin` has an admin that took the
            // role and draws new credentials at once (`GRP-401`). This admin
            // waits for its record, and acts only when none came.
            let roster = group.roster();
            let was_demoted = gone
                .iter()
                .all(|index| roster.member(*index).is_some_and(|member| member.active));
            match self.groups.owner_backoff.get(&conversation) {
                Some(at) if now >= *at => due.push(conversation),
                Some(_) => {}
                None => {
                    let wait = if was_demoted { ROSTER_RATE_LIMIT } else { 0 };
                    let at = now
                        .saturating_add(wait)
                        .saturating_add(group.rotation_delay(rng));
                    self.groups.owner_backoff.insert(conversation, at);
                }
            }
        }
        Ok(due)
    }

    /// Leaves a group (`GRP-067`). The member that leaves rotates nothing,
    /// because `GRP-356` bars the index each trigger excludes.
    pub fn leave_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels acts for the member in
        // each group.
        if !self.owns_channels()? {
            return Err(Error::NotFound);
        }
        // GRP-067: the last owner of a group that holds another member
        // gives `owner` to one of them first. This call refuses its
        // self-removal as it refuses each act that the roles forbid.
        let object = self
            .group_of(conversation)?
            .leave_object()
            .map_err(|_| Error::Malformed)?;
        if !self.roster_takes(conversation, &object, now_ms)? {
            return Err(Error::Malformed);
        }
        self.post_group_control(conversation, &object, now_ms, rng)?;
        self.apply_own_roster_object(conversation, &object, now_ms, rng)?;
        Ok(())
    }

    /// Applies a roster object that this device made, after the record
    /// that carries it went to the work list (`GRP-389`).
    pub(super) fn apply_own_roster_object<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        object: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Applied, Error> {
        self.apply_roster_object_of(conversation, object, now_ms, now_ms, rng)
    }

    /// Applies a roster object of this member whose record a device of the
    /// set built at `built_ms`. The rates of `GRP-076` count on the slot of
    /// that record, which each other member reads from its header.
    fn apply_roster_object_of<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        object: &[u8],
        built_ms: u64,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Applied, Error> {
        let mut group = self.group_of(conversation)?;
        let control = GroupControl::parse(object)?;
        let forks = group.roster().forks().len();
        let slot = group.slot_of_record(built_ms / 1_000);
        let applied = group.apply_control_at(&control, group.own_index(), slot, now_ms / 1_000);
        self.note_forks(conversation, &group, forks, now_ms, rng)?;
        let applied = applied.map_err(|_| Error::Malformed)?;
        self.save_group(conversation, &group, rng)?;
        if matches!(applied, Applied::Granted { .. }) {
            self.note_grant(conversation, object, rng)?;
        }
        self.roster_moved(conversation, &applied, now_ms / 1_000, rng)?;
        self.drop_passed_adds(conversation)?;
        // DEV-301: a re-key item that waited for this roster object
        // applies now, and DEV-303: a key that waited installs now.
        self.retry_rekey_items(now_ms, rng)?;
        self.retry_epoch_keys(conversation, now_ms, rng)?;
        Ok(applied)
    }

    /// Starts the next epoch of a group and queues its epoch-key record
    /// for each replica (§11.4.1). A group with no queue yet, a closed
    /// group, and a group this device may no longer rotate give no record.
    /// A rotation that fails for another cause leaves a trigger with no
    /// answer, and the caller hears of it.
    pub fn rotate_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels does the work of the
        // member in each group.
        if !self.owns_channels()? {
            return Ok(());
        }
        self.groups.backoff.remove(&conversation);
        if self.group_closed(conversation)? {
            return Ok(());
        }
        let mut group = self.group_of(conversation)?;
        let Some(replicas) = Self::group_replicas_of(&group)? else {
            return Ok(());
        };
        // The relay may not hold the pair of the epoch that ends either,
        // when no admin sent its `GKEY` yet.
        let fallback = group.previous_credentials().map(|held| held.write_secret());
        let rotation = match group.rotate(now_ms / 1_000, rng) {
            Ok(rotation) => rotation,
            // GRP-356: an index that left the active set rotates nothing.
            // GRP-422: a rotation waits for the KEM key of each member.
            Err(_) if group.own_role().is_none() || group.lacks_member_key() => return Ok(()),
            Err(_) => return Err(Error::Malformed),
        };
        self.save_group(conversation, &group, rng)?;
        match rotation.carrier {
            EpochCarrier::Inline(record) => self.keep_post(
                GroupPost {
                    message: None,
                    conversation,
                    replicas,
                    write: rotation.write,
                    fallback,
                    record,
                    is_rotation: true,
                    unsent: None,
                    pending: [true; GROUP_REPLICAS],
                },
                rng,
            )?,
            // GRP-283: the slots go on the chunk path, and the record that
            // names them follows the upload.
            EpochCarrier::Chunked(chunked) => self.groups.epoch_uploads.push_back(EpochUpload {
                conversation,
                epoch: rotation.epoch,
                chunked,
                write: rotation.write,
                fallback,
                tries: 0,
            }),
        }
        self.put_clock(conversation, sent_key(conversation), now_ms / 1_000, rng)
    }

    /// The next slot object that waits for the chunk path.
    pub fn take_epoch_upload(&mut self) -> Option<EpochUpload> {
        self.groups.offered = false;
        self.groups.epoch_uploads.pop_front()
    }

    /// Posts the epoch-key record of a chunked rotation, after its slot
    /// object reached the chunk path under `descriptor` (`GRP-283`). A
    /// `GKEY` follows it, as after an inline record (`GRP-406`).
    pub fn post_chunked_epoch<R: CryptoRng + ?Sized>(
        &mut self,
        upload: &EpochUpload,
        descriptor: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let group = self.group_of(upload.conversation)?;
        let Some(replicas) = Self::group_replicas_of(&group)? else {
            return Ok(());
        };
        let record = group
            .chunked_record(upload.epoch, &upload.chunked, descriptor)
            .map_err(|_| Error::Malformed)?;
        self.keep_post(
            GroupPost {
                message: None,
                conversation: upload.conversation,
                replicas,
                write: Secret::new(*upload.write.expose()),
                fallback: upload
                    .fallback
                    .as_ref()
                    .map(|held| Secret::new(*held.expose())),
                record,
                is_rotation: true,
                unsent: None,
                pending: [true; GROUP_REPLICAS],
            },
            rng,
        )?;
        self.put_clock(
            upload.conversation,
            sent_key(upload.conversation),
            now_ms / 1_000,
            rng,
        )
    }

    /// Takes back a slot object whose upload failed, below the limit.
    pub fn epoch_upload_failed(&mut self, mut upload: EpochUpload) {
        upload.tries = upload.tries.saturating_add(1);
        if upload.tries < EPOCH_UPLOAD_TRIES {
            self.groups.epoch_uploads.push_back(upload);
        }
    }

    /// The next chunk of a chunked epoch-key record to fetch.
    pub fn take_epoch_chunk(&mut self) -> Option<(ConversationId, WantedChunk)> {
        self.groups.offered = false;
        self.groups.epoch_chunks.pop_front()
    }

    /// Installs an epoch from the one chunk that holds the slot of this
    /// member (`GRP-284`), and takes each record that waited for it.
    pub fn install_epoch_chunk<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        wanted: &WantedChunk,
        block: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Option<MsgRef>, Error> {
        let mut group = self.group_of(conversation)?;
        let before = Before::of(&group);
        group
            .install_chunk(wanted, block, now_ms / 1_000)
            .map_err(|_| Error::Integrity)?;
        let released: VecDeque<Outcome> = group.retry_held(now_ms / 1_000).into();
        self.take_outcomes(conversation, group, released, before, true, now_ms, rng)
    }

    /// The `GKEY` that follows an accepted epoch-key record at one replica
    /// (`GRP-361`). A rotator that holds no owner credential sends none,
    /// and an admin sends it under `GRP-363` instead.
    pub fn group_rekey_for(
        &self,
        conversation: ConversationId,
        relay: &[u8; 32],
    ) -> Result<Option<GroupRekey>, Error> {
        let group = self.group_of(conversation)?;
        let Some(replicas) = Self::group_replicas_of(&group)? else {
            return Ok(None);
        };
        let Some(which) = replicas.iter().position(|held| held.relay == *relay) else {
            return Ok(None);
        };
        let (Some(own), Some(credentials), Some(reference)) =
            (group.owner(which), group.credentials(), replicas.get(which))
        else {
            return Ok(None);
        };
        Ok(Some(GroupRekey {
            relay: *relay,
            group_queue_id: reference.group_queue_id,
            own: Secret::new(*own.expose()),
            next_own_pk: None,
            read_pk: credentials.read_public(),
            write_pk: credentials.write_public(),
        }))
    }

    /// Whether this device holds the owner credential of the replica at
    /// `relay` and knows of no `GKEY` of the current epoch that arrived
    /// there (`GRP-361`, `GRP-363`). Until that `GKEY` arrives the replica
    /// refuses the pair of the epoch, and that refusal closes no group
    /// (`GRP-210`).
    pub fn group_owes_rekey(
        &self,
        conversation: ConversationId,
        relay: &[u8; 32],
    ) -> Result<bool, Error> {
        let Some(job) = self.group_rekey_for(conversation, relay)? else {
            return Ok(false);
        };
        let group = self.group_of(conversation)?;
        let which = Self::group_replicas_of(&group)?
            .and_then(|replicas| replicas.iter().position(|held| held.relay == *relay));
        let taken = which
            .and_then(|which| self.gkey_row(conversation).ok()?.taken.get(which).copied())
            .flatten();
        Ok(taken != Some(job.write_pk))
    }

    /// The upload of the snapshot of a join failed. The view reads the
    /// joiner list again and offers the press that sends it again.
    pub fn snapshot_failed(&mut self, from: ConversationId) {
        self.events.push_back(Event::GroupJoiner { from });
    }

    /// The active members of a group in index order (§11.9).
    pub fn group_members(&self, conversation: ConversationId) -> Result<Vec<GroupMember>, Error> {
        let group = self.group_of(conversation)?;
        let store = &self.open_ref()?.store;
        let mut members = Vec::new();
        for member in group.roster().active() {
            let row = store.row_id(GROUP_MEMBER, &Self::member_key(conversation, member.index));
            let contact = store
                .get(GROUP_MEMBER, &row)?
                .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                .map(ConversationId);
            members.push(GroupMember {
                index: member.index,
                role: member.role,
                is_self: member.index == group.own_index(),
                contact,
            });
        }
        Ok(members)
    }

    fn member_key(conversation: ConversationId, index: u16) -> Vec<u8> {
        let mut key = Vec::with_capacity(18);
        key.extend_from_slice(&conversation.0);
        key.extend_from_slice(&index.to_be_bytes());
        key
    }

    /// The key of the row that holds the hash of the roster key that the
    /// offer of one contact named as its admin.
    fn offer_key(conversation: ConversationId, from: ConversationId) -> Vec<u8> {
        [conversation.0.as_slice(), b"offer-admin", from.0.as_slice()].concat()
    }

    /// The index of the admin whose offer brought this device into a group.
    /// The hash of the roster key that the offer of `from` carried names
    /// it. A member below `admin` offers no group, thus such an entry names
    /// nobody.
    fn offering_admin(
        &self,
        conversation: ConversationId,
        from: ConversationId,
    ) -> Result<Option<u16>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(GROUP_MEMBER, &Self::offer_key(conversation, from));
        let Some(hash) = store.get(GROUP_MEMBER, &row)? else {
            return Ok(None);
        };
        let group = self.group_of(conversation)?;
        let index = group
            .roster()
            .active()
            .find(|member| {
                member.role >= Role::Admin
                    && member.index != group.own_index()
                    && member.roster_pk_hash.as_slice() == hash.as_slice()
            })
            .map(|member| member.index);
        Ok(index)
    }

    /// Ends what the join of a group leaves behind once this device is a
    /// member. That is the key of the admin of each offer, and each offer
    /// and each wait of another contact for that group. `GRP-153` would
    /// refuse such an offer and such a wait.
    fn end_other_joins(
        &mut self,
        conversation: ConversationId,
        group_id: &[u8; 32],
        joined: RowId,
    ) -> Result<(), Error> {
        let mut gone = Vec::new();
        for row in self.join_rows()? {
            if row == joined {
                continue;
            }
            let ended = match self.join_entry(&row) {
                Ok(Some(JoinEntry::Offer { group_id: held, .. })) => held == *group_id,
                Ok(Some(JoinEntry::Waiting { .. } | JoinEntry::Admitted { .. })) => {
                    self.join_group_id(&row)? == Some(*group_id)
                }
                _ => false,
            };
            if ended {
                gone.push((GROUP_JOIN, row));
            }
        }
        let store = &self.open_ref()?.store;
        for (row, value) in store.list(GROUP_MEMBER, Some(&conversation.0))? {
            // A contact behind a member is 16 bytes, and a key hash is 32.
            if value.len() == 32 {
                gone.push((GROUP_MEMBER, row));
            }
        }
        if gone.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for (table, row) in gone {
            batch.delete(table, row);
        }
        Ok(batch.commit()?)
    }

    /// The group that a row of the join table names.
    fn join_group_id(&self, row: &RowId) -> Result<Option<[u8; 32]>, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .get(GROUP_JOIN, row)?
            .map(Zeroizing::new)
            .and_then(|plain| plain.get(17..49)?.try_into().ok()))
    }

    /// Keeps a contact that is a member of a group under a key of its own.
    pub(crate) fn note_contact_in<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        tag: &[u8],
        contact: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let key = [conversation.0.as_slice(), tag].concat();
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_MEMBER, &key);
        let mut batch = open.store.begin();
        batch.put(GROUP_MEMBER, row, Some(conversation.0), &contact.0, rng)?;
        Ok(batch.commit()?)
    }

    /// The contacts of this device that are members of a group, as far as
    /// this device knows them: the one that brought it in, and the ones
    /// that an admin of this device added.
    pub(super) fn contacts_in(
        &self,
        conversation: ConversationId,
    ) -> Result<Vec<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (_, value) in store.list(GROUP_MEMBER, Some(&conversation.0))? {
            if let Ok(id) = <[u8; 16]>::try_from(value.as_slice()) {
                let contact = ConversationId(id);
                if !out.contains(&contact) {
                    out.push(contact);
                }
            }
        }
        Ok(out)
    }

    /// Names the contact behind a member index that an admin of this
    /// device added.
    fn note_member_contact<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        contact: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open
            .store
            .row_id(GROUP_MEMBER, &Self::member_key(conversation, index));
        let mut batch = open.store.begin();
        batch.put(GROUP_MEMBER, row, Some(conversation.0), &contact.0, rng)?;
        Ok(batch.commit()?)
    }

    /// The next `GKEY` that waits for the run of the group queues.
    pub fn take_group_rekey(&mut self) -> Option<GroupRekey> {
        self.groups.offered = false;
        self.groups.rekeys.pop_front()
    }

    /// Drops each held record of each group that waited past its bound,
    /// and shows the gap, though no record of that group arrived since
    /// (`GRP-253`, `GRP-254`).
    pub fn expire_group_holds<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.groups.offered = false;
        let now = now_ms / 1_000;
        // GRP-196: each kept record that a replica did not take goes again
        // after its wait.
        self.resend_group_posts(now, rng)?;
        // One sweep a minute: a hold ends at its hour, and the window moves
        // by the slot. A clock check forces one (`clock_check`).
        let swept_at = self.groups.swept_at;
        if (swept_at..swept_at.saturating_add(60)).contains(&now) {
            return Ok(());
        }
        self.groups.swept_at = now;
        let mut released_any = false;
        for conversation in self.group_conversations()? {
            // A group that fails here stops no other group.
            let Ok(mut group) = self.group_of(conversation) else {
                continue;
            };
            if group.expire_held(now) > 0 {
                let _ = self.save_group(conversation, &group, rng);
                let _ = self.delivery_gap(conversation, now_ms, rng);
            }
            // GRP-229: a held record whose slot came inside the window
            // opens now, after a clock movement or as the window moved.
            if group.holds_openable(now) {
                let before = Before::of(&group);
                let released: VecDeque<Outcome> = group.retry_held(now).into();
                if !released.is_empty() {
                    released_any = true;
                    let _ = self.take_outcomes(
                        conversation,
                        group,
                        released,
                        before,
                        false,
                        now_ms,
                        rng,
                    );
                    let Ok(stored) = self.group_of(conversation) else {
                        continue;
                    };
                    group = stored;
                }
            }
            // GRP-345: a re-key that a rate or an open index held back goes
            // again. A fault of it stops no other group.
            if self.rekey_waits(conversation).unwrap_or(false)
                && self.owns_channels().unwrap_or(false)
            {
                let _ = self.rekey_group(conversation, now_ms, rng);
                let Ok(stored) = self.group_of(conversation) else {
                    continue;
                };
                group = stored;
            }
            // IMP-080: the `clock` line leaves with its condition.
            let suspect = group.holds_clock_suspect(now);
            let changed = if suspect {
                self.groups.clock_suspect.insert(conversation)
            } else {
                self.groups.clock_suspect.remove(&conversation)
            };
            if changed {
                self.events.push_back(Event::Conversations);
            }
        }
        // DEV-309: a roster object that a retry released can be the one that
        // a held re-key item waits for.
        if released_any {
            let _ = self.retry_rekey_items(now_ms, rng);
        }
        Ok(())
    }

    /// The clock check of `GRP-229` after a clock movement: a sweep of the
    /// held records at once.
    pub fn clock_check<R: CryptoRng + ?Sized>(&mut self, now_ms: u64, rng: &mut R) {
        self.groups.swept_at = 0;
        let _ = self.expire_group_holds(now_ms, rng);
        // GRP-396: no silence counts across the movement.
        let _ = self.restart_silence(now_ms / 1_000, rng);
    }

    /// Each group whose backoff passed and whose trigger no record
    /// answered (`GRP-358`, `GRP-359`). A group seen for the first time
    /// draws its delay here and answers at a later call.
    pub fn groups_to_rotate<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Vec<ConversationId>, Error> {
        self.groups.offered = false;
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            let group = self.group_of(conversation)?;
            let Some(trigger) = group.owes_rotation(now) else {
                self.groups.backoff.remove(&conversation);
                continue;
            };
            match self.groups.backoff.get(&conversation) {
                Some((roster_epoch, at)) if *roster_epoch == trigger.roster_epoch => {
                    if now >= *at {
                        due.push(conversation);
                    }
                }
                _ => {
                    let delay = group.rotation_delay(rng);
                    self.groups.backoff.insert(
                        conversation,
                        (trigger.roster_epoch, now.saturating_add(delay)),
                    );
                }
            }
        }
        Ok(due)
    }

    /// Seals one roster object for a group and queues it for each replica.
    /// It carries no message row, thus no view shows it.
    pub(super) fn post_group_control<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-119: a roster object of this device can lose its place.
        if GroupControl::parse(body).is_ok_and(|control| {
            matches!(
                control.control_type,
                ControlType::PlainEpoch
                    | ControlType::GrantingEpoch
                    | ControlType::ModerationEpoch
                    | ControlType::Rekey
            )
        }) {
            let open = self.open_mut()?;
            let row = open.store.row_id(OWN_EPOCH, &conversation.0);
            let mut batch = open.store.begin();
            batch.put(OWN_EPOCH, row, Some(conversation.0), body, rng)?;
            batch.commit()?;
        }
        self.post_group_app(conversation, AppKind::GroupControl, body, now_ms, rng)
    }

    /// Seals one `AppMessage` of `kind` that no view shows, and queues it.
    pub(super) fn post_group_app<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        kind: AppKind,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind,
            msg_id,
            sent_at: now_ms,
            body,
        };
        let mut app = Zeroizing::new(vec![0u8; record.len()]);
        record.encode(&mut app)?;
        self.queue_group_post(conversation, None, &app, now_ms, rng)
    }

    /// Each group that lacks its current epoch and may ask for it now: at
    /// most once in each `GROUP_SLOT`, and inside `KEY_REQUEST_RATE`
    /// (`GRP-289`, `GRP-295`).
    pub fn groups_lacking_epoch(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<(ConversationId, u32)>, Error> {
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            if self.group_closed(conversation)? {
                continue;
            }
            let group = self.group_of(conversation)?;
            let Some(epoch) = group.lacks_epoch() else {
                continue;
            };
            if group.own_role().is_none() || group.replicas().is_none() {
                continue;
            }
            let entry = self.groups.key_requests.entry(conversation).or_default();
            if entry
                .1
                .is_some_and(|at| now.saturating_sub(at) < umbra_core::group::GROUP_SLOT)
            {
                continue;
            }
            if entry.0.allow(now) {
                entry.1 = Some(now);
                due.push((conversation, epoch));
            }
        }
        Ok(due)
    }

    /// Posts a `KeyRequest` of scope `0x02` for `epoch` as a group record
    /// under the epoch this device holds (`GRP-289`).
    pub fn request_epoch<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        epoch: u32,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels does the work of the
        // member in each group.
        if !self.owns_channels()? {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
        let request = KeyRequest {
            scope: KeyScope::GroupEpoch,
            id: *group.group_id(),
            epoch,
            index: 0,
        };
        let mut body = [0u8; 64];
        let n = request.encode(&mut body)?;
        let body = body.get(..n).ok_or(Error::Malformed)?;
        self.post_group_app(conversation, AppKind::KeyRequest, body, now_ms, rng)
    }

    /// A `KeyRequest` that a group record carried from `sender`. A member
    /// that may supply the epoch answers after its backoff, and a request
    /// above the rate of the group drops (`GRP-375`, `GRP-378`).
    fn on_key_request<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        sender: u16,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) {
        let Ok(request) = KeyRequest::parse(body) else {
            return;
        };
        // GRP-330: a member behind the roster asks for a snapshot.
        if request.scope == KeyScope::RosterSnapshot {
            self.on_snapshot_request(conversation, group, &request, now);
            return;
        }
        // WIR-523: 0 names the sender, and any other value names the
        // member that another member carries the request for.
        let target = match request.index {
            0 => Some(sender),
            carried => u16::try_from(carried - 1).ok(),
        };
        let Some(target) = target else {
            return;
        };
        if request.scope != KeyScope::GroupEpoch
            || request.id != *group.group_id()
            || !group.may_supply(target, request.epoch)
        {
            return;
        }
        let rate = self
            .groups
            .key_answers_rate
            .entry((conversation, Some(target)))
            .or_default();
        if !rate.allow(now) {
            return;
        }
        let at = now.saturating_add(group.rotation_delay(rng));
        self.groups
            .key_answers
            .entry((conversation, target))
            .or_insert(at);
    }

    /// Each lapsed group that lacks its epoch and may ask on a pairwise
    /// channel now, inside the rate of `GRP-295` (`GRP-290`).
    pub fn groups_to_ask_pairwise(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<(ConversationId, u32)>, Error> {
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            if !self.group_lapsed(conversation)? {
                continue;
            }
            let group = self.group_of(conversation)?;
            let Some(epoch) = group.lacks_epoch() else {
                continue;
            };
            let entry = self.groups.key_requests.entry(conversation).or_default();
            if entry
                .1
                .is_some_and(|at| now.saturating_sub(at) < umbra_core::group::GROUP_SLOT)
            {
                continue;
            }
            if entry.0.allow(now) {
                entry.1 = Some(now);
                due.push((conversation, epoch));
            }
        }
        Ok(due)
    }

    /// Asks each contact of this device in a group for `epoch` on the
    /// pairwise channel, and names this member by `index` (`GRP-290`,
    /// `WIR-523`).
    pub fn request_epoch_pairwise<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        epoch: u32,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<usize, Error> {
        // GRP-338: the device that owns the channels does the work of the
        // member in each group.
        if !self.owns_channels()? {
            return Ok(0);
        }
        let group = self.group_of(conversation)?;
        let request = KeyRequest {
            scope: KeyScope::GroupEpoch,
            id: *group.group_id(),
            epoch,
            index: u32::from(group.own_index()) + 1,
        };
        let mut body = [0u8; 64];
        let n = request.encode(&mut body)?;
        let body = body.get(..n).ok_or(Error::Malformed)?.to_vec();
        let contacts = self.contacts_in(conversation)?;
        for contact in &contacts {
            self.send_pairwise_app(*contact, AppKind::KeyRequest, &body, now_ms, rng)?;
        }
        Ok(contacts.len())
    }

    /// A `KeyRequest` of scope `0x02` that a pairwise channel carried. A
    /// member that holds the epoch supplies it at once, because no other
    /// member read the request; one that cannot posts it on the group queue
    /// with the index of the member that lacks it, thus another member can
    /// (`GRP-376`, `WIR-523`). The supply is sealed to the key of the member
    /// that the index names, thus a false index gains nothing.
    pub(super) fn on_pairwise_key_request<R: CryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Ok(request) = KeyRequest::parse(body) else {
            return Ok(());
        };
        // GRP-329: a contact behind the roster of a group asks for a
        // snapshot on the pairwise channel.
        if request.scope == KeyScope::RosterSnapshot {
            let conversation = self.conversation_of_group(&request.id)?;
            if self.is_group(conversation)? && !self.group_closed(conversation)? {
                let group = self.group_of(conversation)?;
                self.on_snapshot_request(conversation, &group, &request, now_ms / 1_000);
            }
            return Ok(());
        }
        if request.scope != KeyScope::GroupEpoch || request.index == 0 {
            return Ok(());
        }
        let conversation = self.conversation_of_group(&request.id)?;
        if !self.is_group(conversation)? || self.group_closed(conversation)? {
            return Ok(());
        }
        let Ok(target) = u16::try_from(request.index - 1) else {
            return Ok(());
        };
        let group = self.group_of(conversation)?;
        // GRP-377: a request for an index that the roster does not hold
        // takes no answer, and it counts against no rate.
        if !group
            .roster()
            .member(target)
            .is_some_and(|member| member.active)
        {
            return Ok(());
        }
        let rate = self
            .groups
            .key_answers_rate
            .entry((conversation, Some(target)))
            .or_default();
        if !rate.allow(now_ms / 1_000) {
            return Ok(());
        }
        if group.may_supply(target, request.epoch) {
            return self.answer_key_request(conversation, target, now_ms, rng);
        }
        if group.own_role().is_some() {
            let mut carried = [0u8; 64];
            let n = request.encode(&mut carried)?;
            let carried = carried.get(..n).ok_or(Error::Malformed)?.to_vec();
            self.post_group_app(conversation, AppKind::KeyRequest, &carried, now_ms, rng)?;
        }
        Ok(())
    }

    /// Each request whose backoff passed with no supply for its member
    /// (`GRP-375`).
    pub fn key_answers_due(&mut self, now_ms: u64) -> Vec<(ConversationId, u16)> {
        let now = now_ms / 1_000;
        let due: Vec<(ConversationId, u16)> = self
            .groups
            .key_answers
            .iter()
            .filter(|(_, at)| now >= **at)
            .map(|(key, _)| *key)
            .collect();
        for key in &due {
            self.groups.key_answers.remove(key);
        }
        due
    }

    /// Posts the one-slot record that supplies the current epoch to the
    /// member at `index`, and then a `KeySupply` of status `0x01`
    /// (`GRP-375`).
    pub fn answer_key_request<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels does the work of the
        // member in each group.
        if !self.owns_channels()? {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
        let Ok(record) = group.key_supply(index, rng) else {
            return Ok(());
        };
        let epoch = group.epoch();
        self.queue_group_record(conversation, &group, record, now_ms, rng)?;
        let supply = KeySupply {
            request: KeyRequest {
                scope: KeyScope::GroupEpoch,
                id: *group.group_id(),
                epoch,
                index: 0,
            },
            status: SupplyStatus::Posted,
            body: &[],
        };
        let mut body = [0u8; 64];
        let n = supply.encode(&mut body)?;
        let body = body.get(..n).ok_or(Error::Malformed)?;
        self.post_group_app(conversation, AppKind::KeySupply, body, now_ms, rng)
    }

    /// One `GSUB` for each group that holds its queues. A reader takes one
    /// replica in each session and alternates across sessions (`GRP-203`,
    /// `GRP-204`). The call changes no group. The caller sends the `GSUB`
    /// of a group that it does not read yet and tells
    /// [`Client::group_reads`], which moves the choice to the store. The
    /// next `GSUB` of that group then takes the other replica. That is in
    /// the same session after a `GSUB` that found no circuit (`GRP-391`),
    /// and in the next session else.
    pub fn group_subscriptions<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<GroupSubscription>, Error> {
        self.groups.driven = true;
        self.groups.offered = true;
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            // A group that does not open stops no other group.
            let Ok(mut group) = self.group_of(conversation) else {
                continue;
            };
            let Some(credentials) = group.credentials().map(|held| held.read_secret()) else {
                continue;
            };
            let fallback = group.previous_credentials().map(|held| held.read_secret());
            let Some(replicas) = group.replicas_mut() else {
                continue;
            };
            // The first `GSUB` of a group takes a random replica, and the
            // draw stands until that `GSUB` goes.
            let coin = match self.groups.picked.get(&conversation) {
                Some(which) => *which == 1,
                None => rng.next_u32() & 1 == 1,
            };
            let which = replicas.pick(coin);
            self.groups.picked.insert(conversation, which);
            let Some(reference) = replicas.reference(which) else {
                continue;
            };
            out.push(GroupSubscription {
                conversation,
                relay: reference.relay_id,
                group_queue_id: reference.group_queue_id,
                read: credentials,
                fallback,
                from_seq: replicas.cursor(which),
            });
        }
        Ok(out)
    }

    /// The `GSUB` of a group goes now, at the replica that
    /// [`Client::group_subscriptions`] gave. The choice moves to the store
    /// (`GRP-204`), and the watch of this session starts (`GRP-396`). The
    /// `GNREG` of that replica goes with it (`NTF-093`).
    pub(super) fn group_read_started<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut group = self.group_of(conversation)?;
        let coin = self.groups.picked.remove(&conversation) == Some(1);
        let Some(replicas) = group.replicas_mut() else {
            return Ok(());
        };
        let which = replicas.pick(coin);
        self.save_group(conversation, &group, rng)?;
        self.groups
            .watch
            .insert(conversation, Watch::start(which, now));
        self.groups.repaired.remove(&conversation);
        // A relay that started again holds no registration, and a `GNREG`
        // that it holds already changes nothing and counts for no circuit.
        if self.group_notify_row(conversation)?.is_some() {
            self.groups.notify_again.insert((conversation, which));
        }
        Ok(())
    }

    /// One `GSUB` at the other replica for each group that needs a repair
    /// (`GRP-205`, `GRP-255`). The reader of such a group saw a gap in the
    /// counter of one sender for `GROUP_GAP_TIMEOUT`. Or it holds a record
    /// for a roster object that the replica of this session did not give. A
    /// group takes one in each session, after the backlog of its own
    /// replica. A record that came ahead of its roster object in one drain
    /// is no gap. The caller sends each one as a `GroupCommand::Repair`,
    /// whose loss ends no subscription.
    pub fn group_gap_repairs(&mut self, now_ms: u64) -> Result<Vec<GroupSubscription>, Error> {
        let now = now_ms / 1_000;
        let watched: Vec<(ConversationId, Watch)> = self
            .groups
            .watch
            .iter()
            .map(|(conversation, watch)| (*conversation, *watch))
            .collect();
        let mut out = Vec::new();
        for (conversation, watch) in watched {
            let quiet =
                now.saturating_sub(watch.last_record) >= umbra_core::group::GROUP_GAP_TIMEOUT;
            if self.groups.repaired.contains(&conversation) || !(watch.live || quiet) {
                continue;
            }
            let Ok(group) = self.group_of(conversation) else {
                continue;
            };
            if !group.needs_other_replica(now) {
                continue;
            }
            let Some(read) = group.credentials().map(|held| held.read_secret()) else {
                continue;
            };
            let Some(replicas) = group.replicas() else {
                continue;
            };
            let other = watch.which.saturating_add(1) % GROUP_REPLICAS;
            let Some(reference) = replicas.reference(other) else {
                continue;
            };
            out.push(GroupSubscription {
                conversation,
                relay: reference.relay_id,
                group_queue_id: reference.group_queue_id,
                read,
                fallback: group.previous_credentials().map(|held| held.read_secret()),
                from_seq: replicas.cursor(other),
            });
            self.groups.repaired.insert(conversation);
        }
        Ok(out)
    }

    /// The subscription of a group ended with no other one in its place.
    /// Its `GSUB` found no circuit at either replica (`GRP-391`), or its
    /// session ended. The watch of the group ends with it (`GRP-396`).
    pub fn group_read_ended(&mut self, conversation: ConversationId) {
        self.groups.watch.remove(&conversation);
    }

    /// The groups that a subscription reads at this tick. A watch whose
    /// group is not among them ended, and each other one takes the tick as
    /// its sign of life. A watch that saw no tick for more than
    /// `CLOCK_SKEW` did not run in that time, and it starts again
    /// (`GRP-396`, `SCP-019`).
    pub(super) fn group_reads_live(&mut self, conversations: &[ConversationId], now: u64) {
        self.groups
            .watch
            .retain(|conversation, _| conversations.contains(conversation));
        for watch in self.groups.watch.values_mut() {
            if watch.has_hole(now) {
                watch.lapse(now);
            }
            watch.beat = now;
        }
    }

    /// A record of replica `which` of a group arrived at `now`, in the
    /// slot `slot` when it opened as a content record. The backlog of a
    /// `GSUB` ends with a record of the current slot, or with a time of
    /// `WATCH_QUIET` in which none came.
    fn watch_record(
        &mut self,
        conversation: ConversationId,
        which: usize,
        slot: Option<u32>,
        now: u64,
    ) {
        let Some(watch) = self.groups.watch.get_mut(&conversation) else {
            return;
        };
        if watch.which != which {
            return;
        }
        watch.answered = true;
        watch.last_record = now;
        let current = umbra_core::group::slot_of(now);
        if slot.is_some_and(|slot| slot.saturating_add(1) >= current) {
            watch.live = true;
        }
    }

    /// Whether this admin watches a group at `now`, thus the silence of its
    /// members counts (`GRP-396`). It watches while a subscription of this
    /// session read its backlog and no tick is missing. This admin did not
    /// watch the time between two watches. Thus the clock of each member
    /// moves forward by that time when a watch starts. A member is silent
    /// only for the time in which this admin read the group. An admin that
    /// was away for `GROUP_SILENT_EVICT` thus starts each silence again.
    fn watches<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        // A caller that asked for no subscription holds no session, and
        // each of its looks counts as watched. The run of the group queues
        // asks for the subscriptions before each look.
        if !self.groups.driven {
            return Ok(true);
        }
        let Some(mut watch) = self.groups.watch.get(&conversation).copied() else {
            return Ok(false);
        };
        if watch.has_hole(now) {
            watch.lapse(now);
            self.groups.watch.insert(conversation, watch);
            return Ok(false);
        }
        if !watch.caught_up {
            let quiet = now.saturating_sub(watch.last_record) >= WATCH_QUIET;
            if !watch.live && !quiet {
                return Ok(false);
            }
            self.resume_watch(conversation, group, now, rng)?;
            watch.caught_up = true;
            watch.stored = now;
            // GRP-361, GRP-401: each `GKEY` that a replica still owes goes
            // again now, and not before. A device that did not read its
            // backlog can hold an epoch that the group left. Its `GKEY`
            // would move a replica back to that epoch.
            if group.lacks_epoch().is_none() {
                self.queue_gkeys(conversation, group, false)?;
            }
        } else if now.saturating_sub(watch.stored) >= WATCH_STEP {
            self.put_clock(conversation, watch_key(conversation), now, rng)?;
            watch.stored = now;
        }
        self.groups.watch.insert(conversation, watch);
        Ok(true)
    }

    /// Whether the replica of the subscription of a group answered in this
    /// session, with a record or with a `GSEQ`. Before the first answer
    /// this admin posts one presence record, once in the session.
    fn watch_answered<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        if !self.groups.driven {
            return Ok(true);
        }
        let Some(watch) = self.groups.watch.get_mut(&conversation) else {
            return Ok(false);
        };
        if watch.answered {
            return Ok(true);
        }
        if !watch.probed {
            watch.probed = true;
            self.post_presence(conversation, now_ms, rng)?;
        }
        Ok(false)
    }

    /// Starts a watch at `now`: the clock of each member moves forward by
    /// the time since the last watch, and never above `now`. A group that
    /// this admin never watched starts each clock here.
    fn resume_watch<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let gap = match self.clock(&watch_key(conversation))? {
            Some(watched) => now.saturating_sub(watched),
            None => u64::MAX,
        };
        if gap >= WATCH_STEP {
            self.shift_silence(conversation, group, gap, now, rng)?;
        }
        self.put_clock(conversation, watch_key(conversation), now, rng)
    }

    /// Moves the clock of each member of a group forward by `gap`, up to
    /// `now` (`GRP-396`). Each backoff of an eviction ends with it.
    fn shift_silence<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        gap: u64,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.groups
            .evictions
            .retain(|(held, _), _| *held != conversation);
        let mut moved = Vec::new();
        for member in group.roster().active() {
            let key = Self::member_key(conversation, member.index);
            if let Some(seen) = self.clock(&key)? {
                let at = seen.saturating_add(gap).min(now);
                if at != seen {
                    moved.push((key, at));
                }
            }
        }
        if moved.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let moved: Vec<(RowId, u64)> = moved
            .into_iter()
            .map(|(key, at)| (open.store.row_id(GROUP_PRESENCE, &key), at))
            .collect();
        let mut batch = open.store.begin();
        for (row, at) in moved {
            batch.put(
                GROUP_PRESENCE,
                row,
                Some(conversation.0),
                &at.to_be_bytes(),
                rng,
            )?;
        }
        Ok(batch.commit()?)
    }

    /// Starts the silence of each member of each group again at `now`,
    /// after a movement of the clock (`SCP-019`). A time that this device
    /// measured across the movement is no time that it watched (`GRP-396`).
    fn restart_silence<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.groups.evictions.clear();
        for conversation in self.group_conversations()? {
            let Ok(group) = self.group_of(conversation) else {
                continue;
            };
            if group.own_role().is_none_or(|role| role < Role::Admin) {
                continue;
            }
            self.shift_silence(conversation, &group, u64::MAX, now, rng)?;
            self.put_clock(conversation, watch_key(conversation), now, rng)?;
            if let Some(watch) = self.groups.watch.get_mut(&conversation) {
                watch.beat = now;
                watch.stored = now;
            }
        }
        Ok(())
    }

    /// Each open group that holds no notify queue yet, while the device
    /// holds a push token or watches its queues, thus it is in Instant
    /// mode or in Direct mode (`NTF-090`, `NTF-106`).
    /// A group whose notify queue is older than `ROTATE_INTERVAL` gets a new
    /// one too, which replaces it after its registration (`NTF-104`).
    pub fn groups_without_notify(&self, now: u64) -> Result<Vec<ConversationId>, Error> {
        if !self.binds()? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            if !self.notify_wanted(conversation)? {
                continue;
            }
            let due = match self.group_notify_row(conversation)? {
                None => true,
                Some(row) => {
                    row.previous.is_none()
                        && now.saturating_sub(row.created_at) >= umbra_core::notify::ROTATE_INTERVAL
                }
            };
            if due {
                out.push(conversation);
            }
        }
        Ok(out)
    }

    /// Each notify queue that a group row names, as its own queue or as
    /// the one that it replaces. Any other one that the store holds is
    /// left from a run that ended before its row was written.
    pub fn group_notify_queues(&self) -> Result<Vec<[u8; 32]>, Error> {
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            if let Some(row) = self.group_notify_row(conversation)? {
                out.push(row.queue);
                out.extend(row.previous.map(|(queue, _)| queue));
            }
        }
        Ok(out)
    }

    /// Each notify queue of a group with the group (Part 8 `NTF-135`): the
    /// queue of its row and the one that it replaces.
    pub fn group_notify_conversations(&self) -> Result<Vec<QueueOf>, Error> {
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            if let Some(row) = self.group_notify_row(conversation)? {
                out.push((row.queue, conversation.0));
                out.extend(row.previous.map(|(queue, _)| (queue, conversation.0)));
            }
        }
        Ok(out)
    }

    /// Whether a group wants a notify queue: it is open, and this device
    /// is a member of it. A device that left or was removed holds none
    /// (`NTF-132`).
    fn notify_wanted(&self, conversation: ConversationId) -> Result<bool, Error> {
        if self.group_closed(conversation)? {
            return Ok(false);
        }
        Ok(self
            .group_of(conversation)
            .is_ok_and(|group| group.own_role().is_some()))
    }

    /// Each notify queue that ends: each one of a group that this device
    /// no longer serves, and each one that a new queue replaced once both replicas took the new
    /// `GNREG` (`NTF-105`, `NTF-132`).
    pub fn notify_endings_due(&self) -> Result<Vec<NotifyEnding>, Error> {
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            let Some(row) = self.group_notify_row(conversation)? else {
                continue;
            };
            let gone = !self.notify_wanted(conversation)?;
            let mut ended: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            if gone {
                ended.push((row.queue, row.address.clone()));
                ended.extend(row.previous.clone());
            } else if let Some(previous) = row.previous.clone() {
                if row.times.iter().all(|at| *at != 0) {
                    ended.push(previous);
                }
            }
            if ended.is_empty() {
                continue;
            }
            // A group that holds no read key can send no `GNUNREG`; its
            // registrations leave with the relay life of `NTF-102`.
            let group = self.group_of(conversation).ok();
            let read = group
                .as_ref()
                .and_then(|group| group.credentials().map(|held| held.read_secret()));
            let mut unregistrations = Vec::new();
            if let (Some(read), Some(replicas)) =
                (read, group.as_ref().and_then(|group| group.replicas()))
            {
                for (_, address) in &ended {
                    for which in 0..2 {
                        let Some(reference) = replicas.reference(which) else {
                            continue;
                        };
                        unregistrations.push(NotifyRegistration {
                            conversation,
                            which,
                            on: false,
                            relay: reference.relay_id,
                            group_queue_id: reference.group_queue_id,
                            read: Secret::new(*read.expose()),
                            queue: address.clone(),
                        });
                    }
                }
            }
            out.push(NotifyEnding {
                conversation,
                unregistrations,
                queues: ended.into_iter().map(|(queue, _)| queue).collect(),
            });
        }
        Ok(out)
    }

    /// The endings of a group went out: a group that wants no notify queue
    /// holds none, and any other one holds its new queue alone.
    pub fn notify_ended<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut row) = self.group_notify_row(conversation)? else {
            return Ok(());
        };
        let gone = !self.notify_wanted(conversation)?;
        let open = self.open_mut()?;
        let key = open.store.row_id(GROUP_NOTIFY, &conversation.0);
        let mut batch = open.store.begin();
        if gone {
            batch.delete(GROUP_NOTIFY, key);
        } else {
            row.previous = None;
            batch.put(GROUP_NOTIFY, key, None, &row.encode(), rng)?;
        }
        batch.commit()?;
        self.wake_changed();
        Ok(())
    }

    /// Keeps the notify queue that the run made for a group. Its `GNREG`
    /// at each replica is due at once.
    pub fn set_group_notify<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        recipient_id: [u8; 32],
        address: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if address.len() != umbra_wire::address::LEN {
            return Err(Error::Malformed);
        }
        // NTF-105: the queue that this one replaces leaves after the new
        // one registered.
        let previous = self
            .group_notify_row(conversation)?
            .map(|row| (row.queue, row.address));
        let value = NotifyRow {
            queue: recipient_id,
            address: address.to_vec(),
            times: [0, 0],
            created_at: now,
            previous,
        }
        .encode();
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_NOTIFY, &conversation.0);
        let mut batch = open.store.begin();
        batch.put(GROUP_NOTIFY, row, None, &value, rng)?;
        batch.commit()?;
        self.wake_changed();
        Ok(())
    }

    fn group_notify_row(&self, conversation: ConversationId) -> Result<Option<NotifyRow>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(GROUP_NOTIFY, &conversation.0);
        let Some(value) = store.get(GROUP_NOTIFY, &row)? else {
            return Ok(None);
        };
        if value.len() != GROUP_NOTIFY_LEN && value.len() != GROUP_NOTIFY_LEN_V1 {
            return Err(Error::Integrity);
        }
        let (queue, rest) = value.split_at(32);
        let (address, rest) = rest.split_at(umbra_wire::address::LEN);
        let at = |range: core::ops::Range<usize>| -> Result<u64, Error> {
            Ok(u64::from_be_bytes(
                rest.get(range)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Integrity)?,
            ))
        };
        let (created_at, previous) = if value.len() == GROUP_NOTIFY_LEN {
            let flag = rest.get(24).copied().ok_or(Error::Integrity)?;
            let prev_queue: [u8; 32] = rest
                .get(25..57)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            let prev_address = rest.get(57..).ok_or(Error::Integrity)?.to_vec();
            (
                at(16..24)?,
                (flag == 1).then_some((prev_queue, prev_address)),
            )
        } else {
            (0, None)
        };
        Ok(Some(NotifyRow {
            queue: queue.try_into().map_err(|_| Error::Integrity)?,
            address: address.to_vec(),
            times: [at(0..8)?, at(8..16)?],
            created_at,
            previous,
        }))
    }

    /// Each `GNREG` that is due (`NTF-093`, `NTF-102`). One is due for a
    /// notify queue that a replica does not hold, or holds for longer than
    /// `NOTIFY_REREGISTER`. One is due for the replica that the `GSUB` of
    /// this session went to. A relay that started again holds no
    /// registration and tells no reader, thus the registration goes with
    /// each `GSUB`. A `GNREG` that the relay holds already changes nothing
    /// there. One circuit carries one for each `GSUB` of a group, which is
    /// inside the count of new registrations that a relay takes from one
    /// circuit.
    pub fn notify_registrations_due(&self, now: u64) -> Result<Vec<NotifyRegistration>, Error> {
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            if !self.notify_wanted(conversation)? {
                continue;
            }
            let Some(NotifyRow { address, times, .. }) = self.group_notify_row(conversation)?
            else {
                continue;
            };
            let group = self.group_of(conversation)?;
            let Some(read) = group.credentials().map(|held| held.read_secret()) else {
                continue;
            };
            let Some(replicas) = group.replicas() else {
                continue;
            };
            for (which, at) in times.iter().enumerate() {
                let again = self.groups.notify_again.contains(&(conversation, which));
                if *at != 0 && now.saturating_sub(*at) < NOTIFY_REREGISTER && !again {
                    continue;
                }
                let Some(reference) = replicas.reference(which) else {
                    continue;
                };
                out.push(NotifyRegistration {
                    conversation,
                    which,
                    on: true,
                    relay: reference.relay_id,
                    group_queue_id: reference.group_queue_id,
                    read: Secret::new(*read.expose()),
                    queue: address.clone(),
                });
            }
        }
        Ok(out)
    }

    /// The `GNREG` of one replica left at `now`. It has no answer.
    pub fn notify_registered<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        which: usize,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.groups.notify_again.remove(&(conversation, which));
        let Some(mut row) = self.group_notify_row(conversation)? else {
            return Ok(());
        };
        if let Some(at) = row.times.get_mut(which) {
            *at = now;
        }
        let value = row.encode();
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_NOTIFY, &conversation.0);
        let mut batch = open.store.begin();
        batch.put(GROUP_NOTIFY, row, None, &value, rng)?;
        batch.commit()?;
        Ok(())
    }

    /// The next record that waits for the run of the group queues.
    pub fn take_group_post(&mut self) -> Option<GroupPost> {
        self.groups.offered = false;
        self.groups.posts.pop_front()
    }

    /// Queues a record for the run of the group queues. A record with no
    /// message stays in the store until a replica accepts it, thus a new
    /// run or a new start sends it again in its order.
    fn keep_post<R: CryptoRng + ?Sized>(
        &mut self,
        mut post: GroupPost,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut order = 0u64;
        let mut replaced = Vec::new();
        for (row, plain) in open.store.list(GROUP_UNSENT, None)? {
            let Some((held, earlier)) = read_unsent_row(&plain, row) else {
                continue;
            };
            order = order.max(held.saturating_add(1));
            // A message that goes again under a new seal (`IMP-075`) takes
            // the place of its earlier seal.
            if post.message.is_some() && earlier.message == post.message {
                replaced.push(row);
            }
        }
        let mut row = [0u8; 16];
        rng.fill_bytes(&mut row);
        let value = unsent_row(order, &post, &[ReplicaArq::default(); GROUP_REPLICAS]);
        let mut batch = open.store.begin();
        for earlier in replaced {
            batch.delete(GROUP_UNSENT, earlier);
        }
        batch.put(GROUP_UNSENT, row, Some(post.conversation.0), &value, rng)?;
        batch.commit()?;
        post.unsent = Some(row);
        self.groups.posts.push_back(post);
        Ok(())
    }

    /// A replica accepted a record that the store kept (`GRP-195`). The
    /// record stays for the other replica until it accepts or gives up,
    /// thus a new run sends it there again (`NET-258`).
    pub fn group_post_accepted<R: CryptoRng + ?Sized>(
        &mut self,
        row: &[u8; 16],
        relay: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let place = self.update_unsent(row, relay, rng, |replica| {
            replica.state = REPLICA_ACCEPTED;
        })?;
        if let Some((post, which)) = place {
            self.groups.resent.remove(&(*row, which));
            // GRP-361, GRP-401: the `GSEQ` of a record that left after a
            // `GKEY` tells that the `GKEY` arrived.
            self.gkey_arrived(post.conversation, which, row, rng)?;
        }
        Ok(())
    }

    /// One send of a kept record to the replica at `relay`, which counts
    /// against its ARQ (`NET-271`).
    pub fn group_post_sent<R: CryptoRng + ?Sized>(
        &mut self,
        row: &[u8; 16],
        relay: &[u8; 32],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.groups.offered = false;
        let place = self.update_unsent(row, relay, rng, |replica| {
            replica.attempts = replica.attempts.saturating_add(1);
            if replica.first == 0 {
                replica.first = now.max(1);
            }
        })?;
        if let Some((post, which)) = place {
            self.groups.resent.insert((*row, which), now);
            // The record tells of the `GKEY` before it when the replica can
            // take it under the credentials of that `GKEY` alone. The
            // replica then holds no pair of the epoch before (`GRP-398`),
            // and its pair is the one that the `GKEY` carried.
            let write_pk = *umbra_crypto::x25519::PublicKey::from(
                &umbra_crypto::x25519::StaticSecret::from(*post.write.expose()),
            )
            .as_bytes();
            if let Some(sent) = self.groups.gkey_sent.get_mut(&(post.conversation, which)) {
                if post.fallback.is_none() && sent.write_pk == write_pk {
                    sent.after.insert(*row);
                }
            }
        }
        Ok(())
    }

    /// Changes the ARQ of one replica of a kept record, and ends the row
    /// when no replica takes it more. The answer holds the record and the
    /// place of the replica in it.
    fn update_unsent<R: CryptoRng + ?Sized>(
        &mut self,
        row: &[u8; 16],
        relay: &[u8; 32],
        rng: &mut R,
        change: impl FnOnce(&mut ReplicaArq),
    ) -> Result<Option<(GroupPost, usize)>, Error> {
        let open = self.open_mut()?;
        let Some(plain) = open.store.get(GROUP_UNSENT, row)? else {
            return Ok(None);
        };
        let plain = Zeroizing::new(plain);
        let Some((order, post, mut arq)) = read_unsent(&plain, *row) else {
            return Ok(None);
        };
        let Some(index) = post.replicas.iter().position(|held| held.relay == *relay) else {
            return Ok(None);
        };
        let Some(replica) = arq.get_mut(index) else {
            return Ok(None);
        };
        change(replica);
        let mut batch = open.store.begin();
        if arq.iter().all(|replica| replica.state != REPLICA_PENDING) {
            batch.delete(GROUP_UNSENT, *row);
        } else {
            let value = unsent_row(order, &post, &arq);
            batch.put(GROUP_UNSENT, *row, Some(post.conversation.0), &value, rng)?;
        }
        batch.commit()?;
        Ok(Some((post, index)))
    }

    /// One record that a `GMSG` carried. A record of this device, a
    /// duplicate, and a record that waits for a roster give no message.
    pub fn on_group_record<R: CryptoRng + ?Sized>(
        &mut self,
        group_queue_id: &[u8; 32],
        seq: u32,
        record: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Option<MsgRef>, Error> {
        let Some(conversation) = self.conversation_of_queue(group_queue_id)? else {
            return Ok(None);
        };
        let mut group = self.group_of(conversation)?;
        // GRP-253, GRP-254: a record that waited past GROUP_ROSTER_WAIT
        // for its roster leaves, and the conversation shows a gap.
        let expired = group.expire_held(now_ms / 1_000);
        let outcome = group.receive(record, now_ms / 1_000);
        // GRP-202: the cursor of that replica moves to the record.
        let which = (0..GROUP_REPLICAS).find(|index| {
            group
                .replicas()
                .and_then(|held| held.reference(*index))
                .is_some_and(|held| held.group_queue_id == *group_queue_id)
        });
        if let Some((which, replicas)) = which.zip(group.replicas_mut()) {
            let is_epoch_key = matches!(outcome, Ok(Outcome::EpochKey { .. }));
            replicas.arrived(which, seq, is_epoch_key);
            // GRP-396: a record of the replica of this session is its
            // answer, and one of the current slot ends its backlog.
            let slot = match &outcome {
                Ok(Outcome::Content { slot, .. }) => Some(*slot),
                _ => None,
            };
            self.watch_record(conversation, which, slot, now_ms / 1_000);
        }
        let before = Before::of(&group);
        let outcomes: VecDeque<Outcome> = outcome.into_iter().collect();
        let taken =
            self.take_outcomes(conversation, group, outcomes, before, false, now_ms, rng)?;
        if expired > 0 {
            self.delivery_gap(conversation, now_ms, rng)?;
        }
        // DEV-309: a roster object of another member can be the one that a
        // held re-key item waits for.
        self.retry_rekey_items(now_ms, rng)?;
        Ok(taken)
    }

    /// Takes the outcomes of one arrival in their order, with each record
    /// that an epoch key or a roster object releases, and stores the group.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn take_outcomes<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        mut group: Group,
        mut outcomes: VecDeque<Outcome>,
        before: Before,
        mut installed: bool,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Option<MsgRef>, Error> {
        let now = now_ms / 1_000;
        let mut first = None;
        let mut displaced = Vec::new();
        while let Some(outcome) = outcomes.pop_front() {
            match outcome {
                Outcome::EpochKey {
                    epoch,
                    start_slot,
                    body,
                } => {
                    // GRP-375: a supply for a member that this device
                    // meant to answer came first, thus it stands down.
                    if epoch == group.epoch() {
                        for index in group.slot_indices(&body) {
                            self.groups.key_answers.remove(&(conversation, index));
                        }
                    }
                    // GRP-284: the slot of a chunked record waits on the
                    // chunk path, and this device fetches its one chunk.
                    if let Ok(Some(wanted)) = group.wanted_chunk(epoch, start_slot, &body, now) {
                        // Each replica carries the record, and one fetch
                        // serves both. A record of the same epoch that
                        // names another chunk takes a fetch of its own,
                        // thus a false one that came first hides no true
                        // one; `EPOCH_CHUNKS_MAX` bounds them.
                        let mut same_epoch =
                            self.groups.epoch_chunks.iter().filter(|(held, other)| {
                                *held == conversation && other.epoch == wanted.epoch
                            });
                        let fetching = same_epoch.clone().any(|(_, other)| *other == wanted);
                        if !fetching && same_epoch.nth(EPOCH_CHUNKS_MAX.saturating_sub(1)).is_none()
                        {
                            self.groups.epoch_chunks.push_back((conversation, wanted));
                        }
                        continue;
                    }
                    let before = group.epoch();
                    let is_one_slot = group.slot_indices(&body).len() == 1;
                    if group
                        .install_epoch_key(epoch, start_slot, &body, now)
                        .is_ok()
                    {
                        installed = true;
                        // WIR-462: a one-slot record that brings the next
                        // epoch is a key supply for a rotation that this
                        // device missed. A delivery of owner credentials
                        // names the epoch that the device holds.
                        if is_one_slot && epoch == before.saturating_add(1) {
                            let key = recovered_key(conversation, epoch);
                            self.put_clock(conversation, key, now, rng)?;
                        }
                        // GRP-252: a record of the new epoch that arrived
                        // before its key waited, and it opens now.
                        outcomes.extend(group.retry_held(now));
                    } else if epoch == group.epoch().saturating_add(1) && !self.owns_channels()? {
                        // DEV-303: the roster object that calls for this
                        // epoch comes on the sync channel, and it can come
                        // after the key.
                        self.hold_epoch_key(conversation, epoch, start_slot, &body, rng)?;
                    }
                }
                Outcome::Presence { sender } => {
                    self.note_seen(conversation, &group, sender, now, rng)?;
                }
                Outcome::Content {
                    sender,
                    app,
                    counter,
                    epoch,
                    slot,
                    repeated,
                    ..
                } => {
                    self.note_seen(conversation, &group, sender, now, rng)?;
                    // GRP-251: a record whose app does not parse is one
                    // silent drop; it ends no other outcome of the arrival.
                    let Ok(parsed) =
                        umbra_wire::app::AppMessage::parse(&app, umbra_wire::app::Channel::Group)
                    else {
                        continue;
                    };
                    // A request of a member that lacks the epoch, and the
                    // notice that one was answered, are no messages.
                    if parsed.kind == AppKind::KeyRequest {
                        self.on_key_request(conversation, &group, sender, parsed.body, now, rng);
                        continue;
                    }
                    if parsed.kind == AppKind::KeySupply {
                        continue;
                    }
                    // A roster object moves the roster and is no message
                    // (`GRP-318`), and a record that waited for it opens.
                    if parsed.kind == AppKind::GroupControl {
                        if let Ok(control) = GroupControl::parse(parsed.body) {
                            // GRP-330: a notice names a snapshot, and it
                            // moves no roster.
                            if control.control_type == ControlType::SnapshotNotice {
                                self.on_snapshot_notice(
                                    conversation,
                                    &group,
                                    sender,
                                    control.payload,
                                    rng,
                                )?;
                                continue;
                            }
                            let forks = group.roster().forks().len();
                            // GRP-076: the rates of the chain count on the
                            // slot of the record that carried the object.
                            let applied = group.apply_control_at(&control, sender, slot, now);
                            // GRP-070, GRP-071: a fork shows, and the member
                            // picks no successor in silence.
                            self.note_forks(conversation, &group, forks, now_ms, rng)?;
                            if let Ok(applied) = applied {
                                if let Some(head) = group.take_displaced() {
                                    displaced.push(head);
                                }
                                if matches!(applied, Applied::Granted { .. }) {
                                    self.note_grant(conversation, parsed.body, rng)?;
                                }
                                self.roster_moved(conversation, &applied, now, rng)?;
                                outcomes.extend(group.retry_held(now));
                            }
                        }
                        continue;
                    }
                    // ABU-036, ABU-038: a record of a blocked member goes,
                    // and the view counts it.
                    if self.is_member_blocked(conversation, sender)? {
                        // GRP-206: each replica gives the record, and the
                        // view counts it once.
                        if !repeated {
                            self.count_discarded(conversation, rng)?;
                        }
                        continue;
                    }
                    // GRP-206, GRP-259: a record under a counter that this
                    // device took already is a copy. The other replica gave
                    // it, or a replica kept it. A message drops at its
                    // `msg_id` in the store. An edit, a deletion and a vote
                    // enter no row of their own, thus the mark of the
                    // receiver drops their copy here. An edit that applied
                    // again would count one more revision, and it would put
                    // its text over the text of an edit after it. The one
                    // record that goes with a copy is the second record of
                    // two devices under one counter (`GRP-342`). The
                    // counter cannot tell it from a copy.
                    if repeated
                        && matches!(
                            parsed.kind,
                            AppKind::Edit | AppKind::Delete | AppKind::PollVote
                        )
                    {
                        continue;
                    }
                    // An edit and a deletion of an author name a message of
                    // that member alone (Part 11 §11.9.6).
                    if matches!(parsed.kind, AppKind::Edit | AppKind::Delete) {
                        self.take_group_change(conversation, Some(sender), &parsed, now_ms, rng)?;
                        continue;
                    }
                    // GRP-336: a vote is one group record, and each member
                    // counts it in the order of its sender (WIR-190). The
                    // order is the index, then the epoch, then the counter,
                    // which starts again in each epoch (GRP-246). A re-key
                    // moves a member to a higher index in the epoch that
                    // stands and starts its counter again. Thus the index
                    // comes first: the vote after the re-key is the later
                    // one.
                    if parsed.kind == AppKind::PollVote {
                        // The position holds 16 bits of the epoch. An epoch
                        // above them takes the highest value, thus the
                        // order never runs back.
                        let position = (u64::from(sender) << 48)
                            | (u64::from(epoch).min(0xFFFF) << 32)
                            | u64::from(counter);
                        self.take_vote(conversation, parsed.body, sender, position, now, rng)?;
                        continue;
                    }
                    // WIR-075, GRP-299, GRP-300: a group stores the kinds of
                    // a message alone. A receipt, a typing indicator, and
                    // each kind of the pairwise channel make no row and no
                    // alert. Part 11 gives a reaction no rule in a group,
                    // and the view offers none, thus it goes as well.
                    if !matches!(
                        parsed.kind,
                        AppKind::Text
                            | AppKind::Attachment
                            | AppKind::Rich
                            | AppKind::Poll
                            | AppKind::ConversationTimer
                            | AppKind::ForwardPolicy
                    ) {
                        continue;
                    }
                    // A record that does not parse under the layout of a
                    // group goes (WIR-163, WIR-180).
                    // DEV-174: a rich record takes its class from the kind
                    // that it goes around. This client goes around a text
                    // alone, as on a pairwise channel. One around a kind
                    // that is no message would else enter the conversation
                    // as one.
                    let is_invalid = match parsed.kind {
                        AppKind::Rich => umbra_wire::app::rich::RichRecord::parse(
                            parsed.body,
                            umbra_wire::app::Channel::Group,
                        )
                        .map_or(true, |rich| {
                            rich.inner_kind != AppKind::Text
                                || core::str::from_utf8(rich.inner_body).is_err()
                        }),
                        AppKind::Poll => umbra_wire::app::poll::Poll::parse(parsed.body).is_err(),
                        _ => false,
                    };
                    if is_invalid {
                        continue;
                    }
                    // DEV-093, DEV-102: a deletion of its author came first.
                    // The view shows nothing at that position, and no alert
                    // goes. The entry stays, thus the copy of the other
                    // replica stays out too.
                    if self.held_group_deletion(conversation, &parsed.msg_id, sender, now_ms)? {
                        continue;
                    }
                    // DEV-249: a timer record of a member below admin goes.
                    let timer = if parsed.kind == AppKind::ConversationTimer {
                        let is_admin = group
                            .roster()
                            .member(sender)
                            .is_some_and(|member| member.role >= Role::Admin);
                        match super::timers::timer_body(parsed.body) {
                            Some(seconds) if is_admin => Some(seconds),
                            _ => continue,
                        }
                    } else {
                        None
                    };
                    // DEV-325: a policy record of a member below admin
                    // goes, and so does one that is older than the policy
                    // of the group (`DEV-323`).
                    if parsed.kind == AppKind::ForwardPolicy {
                        let is_admin = group
                            .roster()
                            .member(sender)
                            .is_some_and(|member| member.role >= Role::Admin);
                        let Ok(policy) = umbra_wire::app::signal::ForwardPolicy::parse(parsed.body)
                        else {
                            continue;
                        };
                        if !is_admin
                            || !self.take_group_forward_policy(conversation, &policy, rng)?
                        {
                            continue;
                        }
                    }
                    let stored = self.store_group_message(conversation, &app, now_ms, rng)?;
                    if let Some(message) = stored {
                        let is_recovered =
                            self.clock(&recovered_key(conversation, epoch))?.is_some();
                        self.put_group_sender(conversation, message, sender, is_recovered, rng)?;
                        self.after_group_store(conversation, &group, message, &app, now, rng)?;
                        match timer {
                            Some(seconds) => {
                                self.put_timer(conversation, seconds, now_ms, false, rng)?
                            }
                            None => {
                                self.stamp_deadline(conversation, message, parsed.kind, now, rng)?
                            }
                        }
                        // DEV-093: an edit of its author that a replica gave
                        // first applies now.
                        self.take_held_group_change(
                            conversation,
                            message,
                            &parsed.msg_id,
                            sender,
                            now_ms,
                            rng,
                        )?;
                    }
                    first = first.or(stored);
                }
                // GRP-229: the list shows the `clock` state. A record of an
                // epoch that this member lacks waits too, and it names no
                // clock (`GRP-289`).
                Outcome::ClockSuspect => {
                    if group.holds_clock_suspect(now)
                        && self.groups.clock_suspect.insert(conversation)
                    {
                        self.events.push_back(Event::Conversations);
                    }
                }
                // GRP-357: an epoch whose slot waited for its roster object
                // installed in the group. The records that waited for its
                // key follow in the same list.
                Outcome::EpochInstalled { .. } => installed = true,
                Outcome::Held | Outcome::Duplicate => {}
            }
        }
        // The counters, the held records and the roster moved.
        self.save_group(conversation, &group, rng)?;
        // GRP-400: another admin drew the owner credentials that this
        // device holds now, and that admin moves each replica to them.
        // What this device knew of its own `GKEY` commands names
        // credentials that it holds no more.
        let owners_moved = group.owner(0).map(|held| *held.expose()) != before.owners;
        if owners_moved && before.owners.is_some() {
            self.put_gkey_row(conversation, &GkeyRow::default(), rng)?;
            self.groups
                .gkey_sent
                .retain(|(held, _), _| *held != conversation);
        }
        // GRP-370: a rival re-key took the index of this member.
        if group.lost_rekey() {
            self.ask_to_return(conversation, now_ms, rng)?;
        }
        for head in displaced {
            self.repost_displaced(conversation, head, now_ms, rng)?;
        }
        self.drop_passed_adds(conversation)?;
        // GRP-363: an admin that installs an epoch it did not credential
        // moves each replica to it. A delivery of owner credentials alone
        // installs no epoch. GRP-364: a switch to the secret of a lower
        // rotator of the same epoch moves each replica too. A device that
        // reads the backlog of its `GSUB` installs each epoch that the
        // group left on its way. A `GKEY` of one would move a replica back
        // to it (§11.4.1). Thus the `GKEY` waits for the end of the
        // backlog, where `Client::watches` sends the one of the epoch that
        // stands.
        if installed && (group.epoch() != before.epoch || group.epoch_rotator() != before.rotator) {
            let read_backlog = !self.groups.driven
                || self
                    .groups
                    .watch
                    .get(&conversation)
                    .is_some_and(|watch| watch.caught_up);
            if read_backlog && group.lacks_epoch().is_none() {
                self.queue_gkeys(conversation, &group, false)?;
            }
            // GRP-405: the epoch that a lapsed member lacked arrived, and
            // the credentials of it take its records again. GRP-210: a
            // group that each replica refused takes a new epoch, thus its
            // queue is not gone, and the next command tells again.
            if self.group_closed(conversation)? {
                self.reopen_group(conversation, rng)?;
            }
        }
        // GRP-402: owner credentials from another admin answer the call for
        // them, thus this admin stands down.
        if group.owner(0).map(|held| *held.expose()) != before.owners {
            self.groups.owner_backoff.remove(&conversation);
            self.note_owners(conversation, &group, rng)?;
        }
        Ok(first)
    }

    /// Stores one message of a group that arrived, and raises its event.
    /// The second copy of one record drops at its `msg_id` (`WIR-065`).
    fn store_group_message<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        app: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Option<MsgRef>, Error> {
        let parsed = umbra_wire::app::AppMessage::parse(app, umbra_wire::app::Channel::Group)?;
        // IMP-167, IMP-168: a file above this size waits for a tap.
        let limit = self.download_limit_now()?;
        let open = self.open_mut()?;
        let reference = super::msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open
            .store
            .row_id(umbra_core::store::record::TableId::MESSAGE, &natural);
        if open
            .store
            .get(umbra_core::store::record::TableId::MESSAGE, &row)?
            .is_some()
        {
            return Ok(None);
        }
        // GRP-142: the answer resolves inside this group, as a reference.
        let mut kept = Zeroizing::new(app.to_vec());
        if super::keep_reply_as_reference(&mut kept, &open.device_set_key).is_err() {
            return Ok(None);
        }
        let plain = stored_message(
            super::INCOMING,
            Delivery::Delivered,
            conversation,
            open.stamp.next(now_ms),
            &kept,
        );
        let mut batch = open.store.begin();
        batch.put(
            umbra_core::store::record::TableId::MESSAGE,
            row,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        // IMP-163: a file of a group takes the same download as a file of a
        // pairwise channel.
        let mut wanted = None;
        if parsed.kind == umbra_wire::app::AppKind::Attachment {
            let (state, descriptor) = super::files::incoming_state_row(parsed.body, limit);
            batch.put(
                super::files::FILE_STATE,
                row,
                Some(conversation.0),
                &state,
                rng,
            )?;
            wanted = descriptor;
        }
        batch.commit()?;
        let message = MsgRef(row);
        if let Some(descriptor) = wanted {
            self.files.downloads.push_back(super::files::DownloadJob {
                message,
                descriptor: Box::new(descriptor),
            });
        }
        self.events.push_back(Event::Message {
            conversation,
            message,
        });
        Ok(Some(message))
    }

    /// What a stored message of a group gives beside its row: the mark of a
    /// mention of this member, and the close time of a poll.
    fn after_group_store<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        message: MsgRef,
        app: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // A message that arrived after its removal leaves at once.
        self.enforce_moderation(conversation, message, rng)?;
        let parsed = AppMessage::parse(app, umbra_wire::app::Channel::Group)?;
        match parsed.kind {
            AppKind::Rich => {
                let rich = umbra_wire::app::rich::RichRecord::parse(
                    parsed.body,
                    umbra_wire::app::Channel::Group,
                )?;
                // GRP-335: the pair key of the roster entry. This device
                // tests its own identifier alone, thus a mention of no
                // member names nobody here (GRP-140).
                let own = group.roster().member(group.own_index()).map(|member| {
                    umbra_wire::app::rich::mention_id(group.group_id(), &member.pair_pk)
                });
                if own.is_some_and(|own| rich.mentions.contains(&own)) {
                    let open = self.open_mut()?;
                    let mut batch = open.store.begin();
                    batch.put(MENTIONED, message.0, Some(conversation.0), &[1], rng)?;
                    batch.commit()?;
                }
            }
            AppKind::Poll => {
                let open_seconds = umbra_wire::app::poll::Poll::parse(parsed.body)
                    .map_or(0, |poll| poll.open_seconds);
                self.open_poll(conversation, message, open_seconds, now, rng)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// The mention identifiers of members of a group, from their roster
    /// indices, in the order of `WIR-166` (`GRP-334`).
    pub(super) fn mention_ids(
        &self,
        conversation: ConversationId,
        members: &[u16],
    ) -> Result<Vec<[u8; 16]>, Error> {
        let group = self.group_of(conversation)?;
        let mut ids = Vec::with_capacity(members.len());
        for index in members {
            let member = group
                .roster()
                .member(*index)
                .filter(|member| member.active)
                .ok_or(Error::NotFound)?;
            ids.push(umbra_wire::app::rich::mention_id(
                group.group_id(),
                &member.pair_pk,
            ));
        }
        ids.sort_unstable();
        ids.dedup();
        if ids.len() > umbra_core::group::MENTION_MAX {
            return Err(Error::TooLong);
        }
        Ok(ids)
    }

    /// Writes one activity clock of §11.9.7.
    pub(super) fn put_clock<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        key: Vec<u8>,
        at: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_PRESENCE, &key);
        let mut batch = open.store.begin();
        batch.put(
            GROUP_PRESENCE,
            row,
            Some(conversation.0),
            &at.to_be_bytes(),
            rng,
        )?;
        Ok(batch.commit()?)
    }

    /// Reads one activity clock of §11.9.7.
    pub(super) fn clock(&self, key: &[u8]) -> Result<Option<u64>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(GROUP_PRESENCE, key);
        Ok(store
            .get(GROUP_PRESENCE, &row)?
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(u64::from_be_bytes))
    }

    /// A record or a presence record of `sender` at `now` (`GRP-132`). An
    /// admin alone counts silence, thus no other device writes the clock.
    fn note_seen<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        sender: u16,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if group.own_role().is_none_or(|role| role < Role::Admin) {
            return Ok(());
        }
        self.groups.evictions.remove(&(conversation, sender));
        self.put_clock(
            conversation,
            Self::member_key(conversation, sender),
            now,
            rng,
        )
    }

    /// A member that joined starts its silence at the join, and a member
    /// that left takes its clock with it.
    fn roster_moved<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        applied: &Applied,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let at_ms = now.saturating_mul(1_000);
        let note = match applied {
            Applied::Added(index) => Some((super::NOTE_JOINED, *index, 0)),
            Applied::Removed(umbra_core::group::roster::Trigger {
                excluded: Some(index),
                ..
            }) => {
                let kind = if self.groups.evicting == Some((conversation, *index)) {
                    super::NOTE_EVICTED
                } else {
                    super::NOTE_LEFT
                };
                Some((kind, *index, 0))
            }
            Applied::Granted { index, role } => Some((super::NOTE_ROLE, *index, *role as u8)),
            _ => None,
        };
        if let Some((kind, index, role)) = note {
            self.put_roster_note(
                conversation,
                super::RosterNote {
                    at_ms,
                    kind,
                    index,
                    role,
                },
                rng,
            )?;
        }
        match applied {
            Applied::Added(index) => self.put_clock(
                conversation,
                Self::member_key(conversation, *index),
                now,
                rng,
            ),
            // A member that moved to new keys keeps its block.
            Applied::Rekeyed { old, new, .. } => {
                self.move_member_block(conversation, *old, *new, rng)
            }
            Applied::Moderated {
                actor_role,
                actions,
            } => self.apply_moderation(
                conversation,
                *actor_role,
                actions,
                now.saturating_mul(1_000),
                rng,
            ),
            Applied::Removed(trigger) => {
                if let Some(index) = trigger.excluded {
                    self.groups.evictions.remove(&(conversation, index));
                    let open = self.open_mut()?;
                    let row = open
                        .store
                        .row_id(GROUP_PRESENCE, &Self::member_key(conversation, index));
                    let mut batch = open.store.begin();
                    batch.delete(GROUP_PRESENCE, row);
                    batch.commit()?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Each group that owes a `GroupPresence`: this device sent no record
    /// to it in a `PRESENCE_INTERVAL` (`GRP-128`). A group seen for the
    /// first time starts its clock here and owes nothing yet.
    pub fn groups_owing_presence<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Vec<ConversationId>, Error> {
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            if self.group_closed(conversation)? {
                continue;
            }
            let group = self.group_of(conversation)?;
            if group.own_role().is_none() || group.replicas().is_none() {
                continue;
            }
            match self.clock(&sent_key(conversation))? {
                None => self.put_clock(conversation, sent_key(conversation), now, rng)?,
                Some(at) if presence_due(Some(at), now) => due.push(conversation),
                Some(_) => {}
            }
        }
        Ok(due)
    }

    /// Posts one `GroupPresence` to each replica of a group (§11.9.7).
    pub fn post_presence<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels does the work of the
        // member in each group.
        if !self.owns_channels()? {
            return Ok(());
        }
        let mut group = self.group_of(conversation)?;
        let Some(replicas) = Self::group_replicas_of(&group)? else {
            return Ok(());
        };
        let record = group
            .presence(now_ms / 1_000, rng)
            .map_err(|_| Error::Malformed)?;
        let write = group.credentials().ok_or(Error::Integrity)?.write_secret();
        let fallback = group.previous_credentials().map(|held| held.write_secret());
        self.save_group(conversation, &group, rng)?;
        // A presence is a signal of activity alone, and a later one takes
        // its place, thus no row keeps it.
        self.groups.posts.push_back(GroupPost {
            message: None,
            conversation,
            replicas,
            write,
            fallback,
            record,
            is_rotation: false,
            unsent: None,
            pending: [true; GROUP_REPLICAS],
        });
        self.put_clock(conversation, sent_key(conversation), now_ms / 1_000, rng)
    }

    /// Each member that this admin must remove for its silence, after the
    /// backoff of this device (`GRP-132`, `GRP-133`, `GRP-397`). A member
    /// with no clock starts one here, thus a device that became an admin
    /// never removes a member on a silence it did not watch (`GRP-396`).
    ///
    /// A silent moderator, admin, or owner loses its role first
    /// (`GRP-166`), and the owner credentials rotate after it. A removal
    /// that would leave fewer than two owners waits for a grant of `owner`
    /// (`GRP-168`), and [`Client::owner_needed`] shows it.
    pub fn members_to_evict<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Vec<(ConversationId, u16, Silence)>, Error> {
        self.groups.offered = false;
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            let group = self.group_of(conversation)?;
            if group.own_role().is_none_or(|role| role < Role::Admin) {
                continue;
            }
            // GRP-396, GRP-134: silence counts while this admin reads the
            // group with no backlog, and no removal comes before that. A
            // closed group removes nobody; the `GKEY` that its replicas
            // owe still goes at the end of its backlog (`GRP-363`).
            let watches = self.watches(conversation, &group, now, rng)?;
            if !watches || self.group_closed(conversation)? {
                continue;
            }
            let roster = group.roster();
            let (active, owners) = (roster.active_count(), roster.owner_count());
            let watched: Vec<(u16, Role)> = roster
                .active()
                .filter(|member| member.index != group.own_index())
                .map(|member| (member.index, member.role))
                .collect();
            for (index, role) in watched {
                let key = Self::member_key(conversation, index);
                let Some(seen) = self.clock(&key)? else {
                    self.put_clock(conversation, key, now, rng)?;
                    continue;
                };
                // GRP-063, GRP-166: only an owner takes the role of an
                // owner, thus an admin leaves a silent owner to the owners.
                let own_role = group.own_role();
                let action = match PresenceTracker::eviction(role, active, owners) {
                    Eviction::Remove => Some(Silence::Remove),
                    Eviction::DemoteFirst
                        if role < Role::Owner || own_role == Some(Role::Owner) =>
                    {
                        Some(Silence::Demote)
                    }
                    _ => None,
                };
                let Some(action) =
                    action.filter(|_| now.saturating_sub(seen) >= GROUP_SILENT_EVICT)
                else {
                    self.groups.evictions.remove(&(conversation, index));
                    continue;
                };
                match self.groups.evictions.get(&(conversation, index)) {
                    Some(at) if now >= *at => {
                        // A `GSUB` has no answer, thus a replica that this
                        // session heard nothing of may read nothing. One
                        // presence record asks it for a `GSEQ`, and the
                        // removal waits for it.
                        if !self.watch_answered(conversation, now_ms, rng)? {
                            continue;
                        }
                        due.push((conversation, index, action));
                        // GRP-076: the removal after a demotion waits for
                        // the rate of one epoch of this admin.
                        let next = now
                            .saturating_add(ROSTER_RATE_LIMIT)
                            .saturating_add(group.rotation_delay(rng));
                        self.groups.evictions.insert((conversation, index), next);
                    }
                    Some(_) => {}
                    None => {
                        let at = now.saturating_add(group.rotation_delay(rng));
                        self.groups.evictions.insert((conversation, index), at);
                    }
                }
            }
        }
        Ok(due)
    }

    /// Queues each `GKEY` that a replica of a group still owes, when this
    /// device holds the owner credentials. One carries a new `own_pk` under
    /// each credential that it replaced (`GRP-401`). One moves the replica
    /// to the credentials of the epoch that this device holds (`GRP-361`,
    /// `GRP-363`). A `GKEY` has no answer, thus each one goes again in each
    /// session of the group, once its backlog arrived. It goes until a
    /// `GSEQ` of that replica follows it in one session. A second `GKEY`
    /// with the same keys changes nothing there (§11.4.1). With `drew` this
    /// device drew the owner credentials just now: no replica holds them
    /// yet, thus no `GKEY` under them goes.
    fn queue_gkeys(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        drew: bool,
    ) -> Result<(), Error> {
        // GRP-338: the device that owns the channels sends each command of
        // the member.
        if !self.owns_channels()? {
            return Ok(());
        }
        let Some(replicas) = Self::group_replicas_of(group)? else {
            return Ok(());
        };
        let Some(credentials) = group.credentials() else {
            return Ok(());
        };
        let (read_pk, write_pk) = (credentials.read_public(), credentials.write_public());
        let held = self.gkey_row(conversation)?;
        // GRP-362: a replica takes no `GKEY` before it accepted the
        // epoch-key record of this device.
        let waits = self.rotation_waits(conversation)?;
        let each = replicas
            .iter()
            .zip(held.taken)
            .zip(held.replaced)
            .zip(waits);
        for (which, (((replica, taken), replaced), waits)) in each.enumerate() {
            let Some(own) = group.owner(which) else {
                continue;
            };
            if waits {
                continue;
            }
            let job = |own: &Secret<32>, next_own_pk| GroupRekey {
                relay: replica.relay,
                group_queue_id: replica.group_queue_id,
                own: Secret::new(*own.expose()),
                next_own_pk,
                read_pk,
                write_pk,
            };
            let next = *umbra_crypto::x25519::PublicKey::from(
                &umbra_crypto::x25519::StaticSecret::from(*own.expose()),
            )
            .as_bytes();
            // A rotation that never reached the group row replaced nothing.
            let replaced: Vec<&Secret<32>> = replaced
                .iter()
                .filter(|before| before.expose() != own.expose())
                .collect();
            if replaced.is_empty() && taken == Some(write_pk) {
                continue;
            }
            for before in replaced {
                self.groups.rekeys.push_back(job(before, Some(next)));
            }
            if !drew {
                self.groups.rekeys.push_back(job(own, None));
            }
            let sent = GkeySent {
                write_pk,
                after: BTreeSet::new(),
            };
            self.groups.gkey_sent.insert((conversation, which), sent);
        }
        Ok(())
    }

    /// For each replica of a group, whether an epoch-key record of this
    /// device still waits for its `GSEQ` there (`GRP-362`).
    fn rotation_waits(
        &self,
        conversation: ConversationId,
    ) -> Result<[bool; GROUP_REPLICAS], Error> {
        let uploads = &self.groups.epoch_uploads;
        if uploads.iter().any(|held| held.conversation == conversation) {
            return Ok([true; GROUP_REPLICAS]);
        }
        let mut waits = [false; GROUP_REPLICAS];
        let store = &self.open_ref()?.store;
        for (row, plain) in store.list(GROUP_UNSENT, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            let Some((_, post, arq)) = read_unsent(&plain, row) else {
                continue;
            };
            if !post.is_rotation {
                continue;
            }
            for (waits, replica) in waits.iter_mut().zip(arq) {
                *waits |= replica.state == REPLICA_PENDING;
            }
        }
        Ok(waits)
    }

    fn gkey_key(conversation: ConversationId) -> Vec<u8> {
        [conversation.0.as_slice(), b"gkey"].concat()
    }

    /// What the store holds of the `GKEY` commands of a group.
    fn gkey_row(&self, conversation: ConversationId) -> Result<GkeyRow, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(GROUP_OWNERS, &Self::gkey_key(conversation));
        Ok(store
            .get(GROUP_OWNERS, &row)?
            .map(Zeroizing::new)
            .and_then(|plain| GkeyRow::parse(&plain))
            .unwrap_or_default())
    }

    fn put_gkey_row<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        held: &GkeyRow,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open
            .store
            .row_id(GROUP_OWNERS, &Self::gkey_key(conversation));
        let mut batch = open.store.begin();
        // The row names no owner, thus it stays on this device: a linked
        // device sends no `GKEY` (`GRP-340`).
        batch.put(GROUP_OWNERS, row, None, &held.encode(), rng)?;
        Ok(batch.commit()?)
    }

    /// A replica returned the `GSEQ` of a kept record that left after the
    /// `GKEY` commands of this session, on the circuit that carried them.
    /// Thus those commands arrived. The replica holds the credentials of
    /// the epoch, and the owner credentials before the current ones leave
    /// the store (`GRP-401`).
    fn gkey_arrived<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        which: usize,
        row: &[u8; 16],
        rng: &mut R,
    ) -> Result<(), Error> {
        let key = (conversation, which);
        let Some(sent) = self.groups.gkey_sent.get(&key) else {
            return Ok(());
        };
        if !sent.after.contains(row) {
            return Ok(());
        }
        let write_pk = sent.write_pk;
        self.groups.gkey_sent.remove(&key);
        let mut held = self.gkey_row(conversation)?;
        if let Some(taken) = held.taken.get_mut(which) {
            *taken = Some(write_pk);
        }
        if let Some(replaced) = held.replaced.get_mut(which) {
            replaced.clear();
        }
        self.put_gkey_row(conversation, &held, rng)
    }

    /// The conversation of a group queue, or none when this device holds
    /// no group with that queue.
    pub fn conversation_of_queue(
        &self,
        group_queue_id: &[u8; 32],
    ) -> Result<Option<ConversationId>, Error> {
        for conversation in self.group_conversations()? {
            let group = self.group_of(conversation)?;
            let Some(replicas) = group.replicas() else {
                continue;
            };
            let holds = (0..GROUP_REPLICAS).any(|index| {
                replicas
                    .reference(index)
                    .is_some_and(|held| held.group_queue_id == *group_queue_id)
            });
            if holds {
                return Ok(Some(conversation));
            }
        }
        Ok(None)
    }

    /// Puts each `GNEW` and each record that waits into the work list.
    /// The run of the group queues calls it at its start, because a
    /// record takes a fresh nonce and a counter of this device.
    pub fn resume_group_work<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.requeue_group_creations()?;
        self.requeue_group_posts(rng)
    }

    /// Asks an admin of each group whose index a rival re-key took and that
    /// waits for no admit yet (`GRP-370`).
    pub fn ask_lost_groups<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        for conversation in self.group_conversations()? {
            self.ask_to_return(conversation, now_ms, rng)?;
        }
        Ok(())
    }

    /// Puts each kept record back into the work list for each replica that
    /// gave no `GSEQ` and whose wait ran out (`GRP-196`, `NET-218`). This
    /// run sent it there, and a `LIMIT`, a refusal of another kind, or a
    /// circuit that no build reached left it with no answer. The wait
    /// doubles with each send, from `RESEND_FIRST` up to `RESEND_MAX`. No
    /// timer fires for it: the next pump after the wait carries the record
    /// (`NET-071`). A record that the task still holds goes twice, and the
    /// relay answers the second one with the `seq` that it holds
    /// (`NET-239`). The ARQ of a replica ends here as it ends at a new run
    /// (`NET-271`), and a message that no replica took then fails
    /// (`NET-272`).
    fn resend_group_posts<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let swept = self.groups.resend_swept;
        if self.groups.resent.is_empty()
            || (swept..swept.saturating_add(RESEND_SWEEP)).contains(&now)
        {
            return Ok(());
        }
        self.groups.resend_swept = now;
        let mut held = BTreeSet::new();
        let mut again = Vec::new();
        let mut changed = Vec::new();
        let mut ended = Vec::new();
        let mut failed = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(GROUP_UNSENT, None)? {
            let plain = Zeroizing::new(plain);
            let Some((order, mut post, mut arq)) = read_unsent(&plain, row) else {
                continue;
            };
            held.insert(row);
            // A record in the work list goes from there, and a group that
            // closed takes none.
            let waits = self
                .groups
                .posts
                .iter()
                .any(|post| post.unsent == Some(row));
            if waits || self.group_closed(post.conversation).unwrap_or(true) {
                continue;
            }
            let before = arq;
            let mut due = [false; GROUP_REPLICAS];
            for (which, (replica, due)) in arq.iter_mut().zip(&mut due).enumerate() {
                let Some(sent) = self.groups.resent.get(&(row, which)) else {
                    continue;
                };
                let wait = RESEND_FIRST
                    .checked_shl(replica.attempts.saturating_sub(1))
                    .map_or(RESEND_MAX, |wait| wait.min(RESEND_MAX));
                if replica.state != REPLICA_PENDING || now.saturating_sub(*sent) < wait {
                    continue;
                }
                replica.check(now);
                *due = replica.state == REPLICA_PENDING;
            }
            if arq.iter().all(|replica| replica.state != REPLICA_PENDING) {
                let accepted = arq.iter().any(|replica| replica.state == REPLICA_ACCEPTED);
                if let Some(message) = post.message.filter(|_| !accepted) {
                    failed.push(message);
                }
                ended.push(row);
                continue;
            }
            if arq != before {
                changed.push((row, post.conversation, unsent_row(order, &post, &arq)));
            }
            if due.contains(&true) {
                post.pending = due;
                again.push((order, post));
            }
        }
        self.groups.resent.retain(|(row, _), _| held.contains(row));
        if !changed.is_empty() || !ended.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for (row, conversation, value) in changed {
                batch.put(GROUP_UNSENT, row, Some(conversation.0), &value, rng)?;
            }
            for row in ended {
                batch.delete(GROUP_UNSENT, row);
            }
            batch.commit()?;
        }
        for message in failed {
            self.fail(&message, crate::FailureCause::NoReplica, rng)?;
        }
        again.sort_by_key(|(order, _)| *order);
        for (_, post) in again {
            // The next send sets the time of this replica again.
            for (which, pending) in post.pending.iter().enumerate() {
                if *pending {
                    if let Some(row) = post.unsent {
                        self.groups.resent.remove(&(row, which));
                    }
                }
            }
            self.groups.posts.push_back(post);
        }
        Ok(())
    }

    /// Puts each record of a group that no replica accepted back into the
    /// work list.
    fn requeue_group_posts<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.groups.posts.clear();
        self.groups.resent.clear();
        // GRP-392: each sealed record goes again as it was, in the order of
        // its seal. A group that is gone or closed takes none, and a message
        // that no longer waits in the outbox takes none.
        let mut kept = Vec::new();
        let mut dropped = Vec::new();
        let mut ended = Vec::new();
        let mut failed = Vec::new();
        let mut sealed = BTreeSet::new();
        let now = super::unix_now_seconds();
        for (row, plain) in self.open_ref()?.store.list(GROUP_UNSENT, None)? {
            let plain = Zeroizing::new(plain);
            let Some((order, mut post, mut arq)) = read_unsent(&plain, row) else {
                dropped.push(row);
                continue;
            };
            let store = &self.open_ref()?.store;
            let is_held = store.get(GROUP, &post.conversation.0)?.is_some();
            // NET-258: a record that one replica accepted left the outbox,
            // and it still goes to the other one.
            let accepted = arq.iter().any(|replica| replica.state == REPLICA_ACCEPTED);
            let waits = match post.message {
                Some(message) => accepted || store.get(OUTBOX, &message.0)?.is_some(),
                None => true,
            };
            if !is_held || !waits || self.group_closed(post.conversation)? {
                dropped.push(row);
                continue;
            }
            // NET-271: each replica ends its own ARQ, and NET-272 fails the
            // message only when no replica accepted it.
            for replica in &mut arq {
                replica.check(now);
            }
            post.pending = [
                arq[0].state == REPLICA_PENDING,
                arq[1].state == REPLICA_PENDING,
            ];
            if !post.pending.iter().any(|pending| *pending) {
                if !accepted {
                    if let Some(message) = post.message {
                        failed.push(message);
                    }
                }
                ended.push(row);
                continue;
            }
            if let Some(message) = post.message {
                sealed.insert(message);
            }
            kept.push((order, post));
        }
        if !dropped.is_empty() || !ended.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for row in dropped.into_iter().chain(ended) {
                batch.delete(GROUP_UNSENT, row);
            }
            batch.commit()?;
        }
        // NET-272, IMP-074: no replica took the record before its ARQ gave up.
        for message in failed {
            self.fail(&message, crate::FailureCause::NoReplica, rng)?;
        }
        kept.sort_by_key(|(order, _)| *order);
        self.groups
            .posts
            .extend(kept.into_iter().map(|(_, post)| post));
        let store = &self.open_ref()?.store;
        let mut waiting = Vec::new();
        for (row, _) in store.list(OUTBOX, None)? {
            let Some(plain) = store.get(umbra_core::store::record::TableId::MESSAGE, &row)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            let conversation = super::conversation_of(&plain)?;
            if store.get(GROUP, &conversation.0)?.is_none() || sealed.contains(&MsgRef(row)) {
                continue;
            }
            let info = super::info_of(&plain)?;
            waiting.push((
                info.stored_at_ms,
                conversation,
                MsgRef(row),
                Zeroizing::new(
                    plain
                        .get(MESSAGE_PREFIX..)
                        .ok_or(Error::Integrity)?
                        .to_vec(),
                ),
            ));
        }
        waiting.sort_by_key(|(stored_at, _, _, _)| *stored_at);
        // GRP-246: a record that no seal took yet takes the slot of the last
        // tick, as a send then would. GRP-415: one that cannot be sealed any
        // more fails alone, and the rest go.
        let tick_ms = self.clock.saturating_mul(1_000);
        for (stored_at, conversation, message, app) in waiting {
            if self
                .queue_group_post(
                    conversation,
                    Some(message),
                    &app,
                    stored_at.max(tick_ms),
                    rng,
                )
                .is_err()
            {
                self.fail(&message, crate::FailureCause::NoPath, rng)?;
            }
        }
        Ok(())
    }

    /// Puts each `GNEW` that no relay answered back into the work list, at
    /// an unlock or after a run of the group queues ended.
    pub(super) fn requeue_group_creations(&mut self) -> Result<(), Error> {
        self.groups.creations.clear();
        let store = &self.open_ref()?.store;
        let mut jobs = Vec::new();
        for (_, plain) in store.list(GROUP_QUEUE, None)? {
            let plain = Zeroizing::new(plain);
            // A row that carries its identifier is done.
            if plain.len() != QUEUE_ROW_LEN {
                continue;
            }
            let (group_id, replica, relay) = read_queue_row(&plain)?;
            jobs.push((group_id, replica, relay));
        }
        for (group_id, replica, relay) in jobs {
            let conversation = self.conversation_of_group(&group_id)?;
            let group = self.group_of(conversation)?;
            let credentials = group.credentials().ok_or(Error::Integrity)?;
            let own = group.owner(usize::from(replica)).ok_or(Error::Integrity)?;
            self.groups.creations.push_back(GroupQueueJob {
                group_id,
                replica,
                relay,
                read_pk: credentials.read_public(),
                write_pk: credentials.write_public(),
                own: Secret::new(*own.expose()),
            });
        }
        Ok(())
    }
}

/// The row of a kept record: its order, the conversation, whether it
/// starts an epoch, the credentials, the two replicas, and the record.
fn unsent_row(
    order: u64,
    post: &GroupPost,
    arq: &[ReplicaArq; GROUP_REPLICAS],
) -> Zeroizing<Vec<u8>> {
    let mut value = Zeroizing::new(Vec::with_capacity(
        UNSENT_HEAD + GROUP_REPLICAS * REPLICA_ARQ_LEN + post.record.len(),
    ));
    value.push(UNSENT_ARQ_VERSION);
    value.extend_from_slice(&order.to_be_bytes());
    value.extend_from_slice(&post.conversation.0);
    value.push(u8::from(post.is_rotation));
    value.push(u8::from(post.fallback.is_some()));
    value.extend_from_slice(post.write.expose());
    value.extend_from_slice(
        post.fallback
            .as_ref()
            .map_or(&[0u8; 32], |held| held.expose()),
    );
    for replica in &post.replicas {
        value.extend_from_slice(&replica.relay);
        value.extend_from_slice(&replica.group_queue_id);
    }
    value.push(u8::from(post.message.is_some()));
    value.extend_from_slice(&post.message.map_or([0u8; 16], |message| message.0));
    for replica in arq {
        value.push(replica.state);
        value.extend_from_slice(&replica.attempts.to_be_bytes());
        value.extend_from_slice(&replica.first.to_be_bytes());
    }
    value.extend_from_slice(&post.record);
    value
}

/// The first byte of a kept record that names its message. A row of the
/// first form starts with its order, whose first byte is zero.
const UNSENT_VERSION: u8 = 2;

/// The first byte of a kept record that holds the ARQ of each replica
/// after the message.
const UNSENT_ARQ_VERSION: u8 = 3;

/// The width of the ARQ of one replica: its state, its sends, and the time
/// of its first send.
const REPLICA_ARQ_LEN: usize = 1 + 4 + 8;

/// The fixed part of a kept record ahead of the record.
const UNSENT_HEAD: usize = 1 + 8 + 16 + 1 + 1 + 32 + 32 + GROUP_REPLICAS * 64 + 1 + 16;

/// The fixed part of a row of the first form, which names no message.
const UNSENT_HEAD_V1: usize = 8 + 16 + 1 + 1 + 32 + 32 + GROUP_REPLICAS * 64;

fn read_unsent_row(plain: &[u8], row: [u8; 16]) -> Option<(u64, GroupPost)> {
    read_unsent(plain, row).map(|(order, post, _)| (order, post))
}

/// A kept record with the ARQ of each replica. A row of an earlier form
/// holds none, and each replica then takes the record.
fn read_unsent(
    plain: &[u8],
    row: [u8; 16],
) -> Option<(u64, GroupPost, [ReplicaArq; GROUP_REPLICAS])> {
    let has_arq = plain.first() == Some(&UNSENT_ARQ_VERSION);
    let (body, head) = if plain.first() == Some(&UNSENT_VERSION) || has_arq {
        (plain.get(1..)?, UNSENT_HEAD - 1)
    } else {
        (plain, UNSENT_HEAD_V1)
    };
    let mut arq = [ReplicaArq::default(); GROUP_REPLICAS];
    let head = if has_arq {
        for (index, replica) in arq.iter_mut().enumerate() {
            let at = head + index * REPLICA_ARQ_LEN;
            replica.state = *body.get(at)?;
            replica.attempts = u32::from_be_bytes(body.get(at + 1..at + 5)?.try_into().ok()?);
            replica.first = u64::from_be_bytes(body.get(at + 5..at + 13)?.try_into().ok()?);
        }
        head + GROUP_REPLICAS * REPLICA_ARQ_LEN
    } else {
        head
    };
    let take = |from: usize| -> Option<[u8; 32]> { body.get(from..from + 32)?.try_into().ok() };
    let order = u64::from_be_bytes(body.get(..8)?.try_into().ok()?);
    let conversation = ConversationId(body.get(8..24)?.try_into().ok()?);
    let is_rotation = *body.get(24)? == 1;
    let has_fallback = *body.get(25)? == 1;
    let write = Secret::new(take(26)?);
    let fallback = has_fallback.then(|| take(58)).flatten().map(Secret::new);
    let replica = |at: usize| -> Option<GroupReplica> {
        Some(GroupReplica {
            relay: take(at)?,
            group_queue_id: take(at + 32)?,
        })
    };
    let replicas = [replica(90)?, replica(154)?];
    let message = if head == UNSENT_HEAD_V1 {
        None
    } else {
        let has_message = *body.get(218)? == 1;
        let id: [u8; 16] = body.get(219..235)?.try_into().ok()?;
        has_message.then_some(MsgRef(id))
    };
    let record = body.get(head..)?.to_vec();
    if record.is_empty() {
        return None;
    }
    let pending = [
        arq[0].state == REPLICA_PENDING,
        arq[1].state == REPLICA_PENDING,
    ];
    Some((
        order,
        GroupPost {
            message,
            conversation,
            replicas,
            write,
            fallback,
            record,
            is_rotation,
            unsent: Some(row),
            pending,
        },
        arq,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use umbra_core::{
        session::node::ContactId,
        store::{
            engine::MemoryBackend,
            wrap::{Cost, SecureElement},
        },
        Error as CoreError,
    };
    use umbra_crypto::{
        hmac::{digest::KeyInit, Hmac, Mac},
        rand_core::{TryCryptoRng, TryRng},
        sha2::Sha256,
    };

    use super::*;

    struct Rng(u64);

    impl TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Ok(self.0 >> 11 ^ self.0 << 7)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for Rng {}

    #[derive(Clone)]
    struct Element([u8; 32]);

    impl SecureElement for Element {
        fn keyed(&self, input: &[u8]) -> Result<[u8; 32], CoreError> {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| CoreError::Malformed)?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().into())
        }
    }

    type Device = Client<MemoryBackend, Element>;

    const CHEAP: Cost = Cost { m_kib: 64, t: 1 };
    const RELAYS: [[u8; 32]; 2] = [[0xA1; 32], [0xB2; 32]];
    const QUEUES: [[u8; 32]; 2] = [[0xC3; 32], [0xD4; 32]];
    const T0: u64 = 1_700_000_000;
    const DAY: u64 = 86_400;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn new_client(rng: &mut Rng) -> Device {
        Client::create(
            MemoryBackend::default(),
            Element([1; 32]),
            &units("correct horse"),
            CHEAP,
            1_000,
            rng,
        )
        .unwrap()
    }

    /// A group of `admin` with both of its queues.
    fn new_group(admin: &mut Device, rng: &mut Rng) -> ConversationId {
        let group = admin.create_group("Summit", RELAYS, T0, rng).unwrap();
        let group_id = admin.group_info(group).unwrap().group_id;
        for (replica, (relay, queue)) in RELAYS.into_iter().zip(QUEUES).enumerate() {
            admin
                .group_queue_made(&group_id, replica as u8, relay, queue, rng)
                .unwrap();
        }
        while admin.take_group_creation().is_some() {}
        group
    }

    /// Puts one record of a contact into a client, as the network would.
    fn deliver(client: &mut Device, from: &ContactId, app: &[u8], now_ms: u64, rng: &mut Rng) {
        client
            .commit_network(&[], &[(*from, app.to_vec())], now_ms, rng)
            .unwrap();
    }

    /// Each waiting post of `from` goes, each replica answers it, and each
    /// device of `to` reads it from the first replica.
    fn carry(from: &mut Device, to: &mut [&mut Device], seq: &mut u32, now: u64, rng: &mut Rng) {
        while let Some(post) = from.take_group_post() {
            if let Some(row) = post.unsent {
                for (replica, at) in post.replicas.iter().zip([7, 9]) {
                    from.group_post_sent(&row, &replica.relay, now, rng)
                        .unwrap();
                    from.group_post_accepted(&row, &replica.relay, rng).unwrap();
                    from.add_answered(&row, &replica.relay, at, now * 1_000, rng)
                        .unwrap();
                }
            }
            *seq += 1;
            for reader in to.iter_mut() {
                reader
                    .on_group_record(&QUEUES[0], *seq, &post.record, now * 1_000, rng)
                    .unwrap();
            }
        }
    }

    /// Brings `joiner` into `group` of `admin` with the offer, the join
    /// record, the add and the admit of §11.9.1. `peers` names the joiner at
    /// the admin and the admin at the joiner.
    fn invite(
        admin: &mut Device,
        joiner: &mut Device,
        group: ConversationId,
        peers: (ContactId, ContactId),
        now: u64,
        rng: &mut Rng,
    ) -> ConversationId {
        let at_admin = admin.conversation_for(&peers.0 .0).unwrap();
        let at_joiner = joiner.conversation_for(&peers.1 .0).unwrap();
        let group_id = admin.group_info(group).unwrap().group_id;
        admin
            .offer_group(group, at_admin, now * 1_000, rng)
            .unwrap();
        let offer = admin.take_outgoing().unwrap();
        deliver(joiner, &peers.1, &offer.app, now * 1_000 + 100, rng);
        let offers = joiner.group_offers().unwrap();
        let held = offers
            .iter()
            .find(|offer| offer.from == at_joiner && offer.group_id == group_id)
            .unwrap();
        joiner
            .accept_group_offer(held, now * 1_000 + 200, rng)
            .unwrap();
        let asked = joiner.take_outgoing().unwrap();
        deliver(admin, &peers.0, &asked.app, now * 1_000 + 300, rng);
        let joiners = admin.group_joiners().unwrap();
        let waiting = joiners
            .iter()
            .find(|held| held.from == at_admin && held.group_id == group_id)
            .unwrap();
        let admission = admin.add_joiner(waiting, now * 1_000 + 400, rng).unwrap();
        carry(admin, &mut [], &mut 0, now, rng);
        admin
            .admit_joiner(
                waiting,
                admission.index,
                b"a descriptor",
                now * 1_000 + 500,
                rng,
            )
            .unwrap();
        let admit = admin.take_outgoing().unwrap();
        deliver(joiner, &peers.1, &admit.app, now * 1_000 + 600, rng);
        let member = joiner
            .accept_group_admit(at_joiner, &group_id, &admission.snapshot, now + 1, rng)
            .unwrap();
        while admin.next_event().is_some() {}
        while joiner.next_event().is_some() {}
        member
    }

    /// One pump of the run of the group queues at `now`, as the bindings
    /// make it. The pump makes the subscriptions, the `GSUB` of each group
    /// that `reading` does not hold, and the look at the silent members.
    /// The tick that names each group that a subscription reads comes last.
    fn pump(
        client: &mut Device,
        reading: &mut BTreeSet<ConversationId>,
        now: u64,
        rng: &mut Rng,
    ) -> Vec<(ConversationId, u16, Silence)> {
        for subscription in client.group_subscriptions(rng).unwrap() {
            if reading.insert(subscription.conversation) {
                client
                    .group_reads(&[subscription.conversation], now * 1_000, rng)
                    .unwrap();
            }
        }
        while client.take_epoch_upload().is_some() {}
        let silent = client.members_to_evict(now * 1_000, rng).unwrap();
        let read: Vec<ConversationId> = reading.iter().copied().collect();
        client.group_reads(&read, now * 1_000, rng).unwrap();
        silent
    }

    fn say(
        client: &mut Device,
        conversation: ConversationId,
        text: &str,
        now: u64,
        rng: &mut Rng,
    ) -> MsgRef {
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units(text)).unwrap();
        client.send_draft(draft, now * 1_000, rng).unwrap()
    }

    const AT_ADMIN: ContactId = ContactId([0x51; 32]);
    const AT_JOINER: ContactId = ContactId([0x52; 32]);

    #[test]
    fn a_member_that_left_takes_a_new_invitation_into_the_conversation_it_held() {
        let mut rng = Rng(301);
        let mut admin = new_client(&mut rng);
        let mut joiner = new_client(&mut rng);
        let group = new_group(&mut admin, &mut rng);
        let group_id = admin.group_info(group).unwrap().group_id;
        let peers = (AT_ADMIN, AT_JOINER);
        let member = invite(&mut admin, &mut joiner, group, peers, T0 + 1, &mut rng);
        assert_eq!(joiner.group_info(member).unwrap().own_index, 1);
        let before = joiner.group_state_object(member, T0 + 2).unwrap();
        let subject = umbra_core::devset::sync::group_subject(
            &joiner.open_ref().unwrap().device_set_key,
            &group_id,
        );
        let mut seq = 20;
        say(&mut admin, group, "before", T0 + 10, &mut rng);
        carry(&mut admin, &mut [&mut joiner], &mut seq, T0 + 10, &mut rng);
        assert_eq!(joiner.messages(member).unwrap().len(), 1);

        // GRP-153: an offer to a group that this device is a member of is
        // no offer.
        let at_admin = admin.conversation_for(&AT_ADMIN.0).unwrap();
        admin
            .offer_group(group, at_admin, (T0 + 11) * 1_000, &mut rng)
            .unwrap();
        let again = admin.take_outgoing().unwrap();
        deliver(
            &mut joiner,
            &AT_JOINER,
            &again.app,
            (T0 + 12) * 1_000,
            &mut rng,
        );
        assert!(joiner.group_offers().unwrap().is_empty());

        // The member leaves, and the row of its membership stays.
        joiner
            .leave_group(member, (T0 + 20) * 1_000, &mut rng)
            .unwrap();
        carry(&mut joiner, &mut [&mut admin], &mut seq, T0 + 20, &mut rng);
        assert!(!joiner.group_info(member).unwrap().is_member);
        assert_eq!(admin.group_info(group).unwrap().members, 1);
        admin
            .rotate_group(group, (T0 + 21) * 1_000, &mut rng)
            .unwrap();
        carry(&mut admin, &mut [], &mut seq, T0 + 21, &mut rng);
        assert_eq!(admin.group_info(group).unwrap().epoch, 2);

        // Part 11 §11.12: a membership that ended takes a new invitation.
        // The group of its admit takes the place of the row, in the
        // conversation that the device held.
        let back = invite(&mut admin, &mut joiner, group, peers, T0 + 30, &mut rng);
        assert_eq!(back, member);
        let info = joiner.group_info(member).unwrap();
        assert!(info.is_member && !info.is_closed);
        assert_eq!((info.own_index, info.members), (2, 2));
        assert_eq!(joiner.messages(member).unwrap().len(), 1);
        joiner.lock();
        joiner.unlock(&units("correct horse"), T0 + 40).unwrap();
        assert_eq!(joiner.group_info(member).unwrap().own_index, 2);
        say(&mut admin, group, "after", T0 + 50, &mut rng);
        carry(&mut admin, &mut [&mut joiner], &mut seq, T0 + 50, &mut rng);
        assert_eq!(joiner.messages(member).unwrap().len(), 2);

        // GRP-414: the state of an earlier admission that arrives late at
        // a device of the set replaces nothing.
        let now = joiner.group_state_object(member, T0 + 60).unwrap();
        joiner
            .apply_group_state(&subject, &before, &mut rng)
            .unwrap();
        assert_eq!(joiner.group_info(member).unwrap().own_index, 2);
        // The state of a membership takes the place of a row whose own
        // membership ended.
        joiner
            .leave_group(member, (T0 + 70) * 1_000, &mut rng)
            .unwrap();
        while joiner.take_group_post().is_some() {}
        assert!(!joiner.group_info(member).unwrap().is_member);
        joiner.apply_group_state(&subject, &now, &mut rng).unwrap();
        let info = joiner.group_info(member).unwrap();
        assert!(info.is_member);
        assert_eq!(info.own_index, 2);
        assert_eq!(joiner.messages(member).unwrap().len(), 2);
    }

    #[test]
    fn the_admin_of_an_offer_is_the_one_that_the_contact_of_the_admit_named() {
        let mut rng = Rng(302);
        let mut admin = new_client(&mut rng);
        let mut insider = new_client(&mut rng);
        let mut invited = new_client(&mut rng);
        let group = new_group(&mut admin, &mut rng);
        let group_id = admin.group_info(group).unwrap().group_id;
        let inside = invite(
            &mut admin,
            &mut insider,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );

        // The admin offers the group. A member that is a contact of the
        // invited device then sends an offer of its own for the same group.
        // That offer names the roster key of the member as the key of the
        // admin.
        let peers = (ContactId([0x61; 32]), ContactId([0x62; 32]));
        let insider_at_invited = ContactId([0x63; 32]);
        let at_admin = admin.conversation_for(&peers.0 .0).unwrap();
        let admin_at_invited = invited.conversation_for(&peers.1 .0).unwrap();
        admin
            .offer_group(group, at_admin, (T0 + 10) * 1_000, &mut rng)
            .unwrap();
        let offer = admin.take_outgoing().unwrap();
        deliver(
            &mut invited,
            &peers.1,
            &offer.app,
            (T0 + 11) * 1_000,
            &mut rng,
        );
        let held = insider.group_of(inside).unwrap();
        let own_pk = held.own_roster_pk();
        let creator_pk = held.roster().member(0).unwrap().roster_pk.clone().unwrap();
        let invitation = GroupInvitation {
            group_id,
            stage: InvitationStage::Offer {
                name: "Summit",
                admin_roster_pk: &own_pk,
                creator_roster_pk: &creator_pk,
            },
        };
        let mut payload = vec![0u8; 4_096];
        let used = invitation.encode(&mut payload).unwrap();
        let control = GroupControl {
            control_type: ControlType::Invitation,
            payload: &payload[..used],
        };
        let mut body = vec![0u8; used + 8];
        let used = control.encode(&mut body).unwrap();
        let forged = AppMessage {
            kind: AppKind::GroupControl,
            msg_id: [0x77; 16],
            sent_at: (T0 + 12) * 1_000,
            body: &body[..used],
        };
        let mut app = vec![0u8; forged.len()];
        forged.encode(&mut app).unwrap();
        deliver(
            &mut invited,
            &insider_at_invited,
            &app,
            (T0 + 12) * 1_000,
            &mut rng,
        );
        assert_eq!(invited.group_offers().unwrap().len(), 2);

        // The invited device takes the offer of the admin, and the admin
        // admits it.
        let offers = invited.group_offers().unwrap();
        let taken = offers
            .iter()
            .find(|offer| offer.from == admin_at_invited)
            .unwrap();
        invited
            .accept_group_offer(taken, (T0 + 13) * 1_000, &mut rng)
            .unwrap();
        let asked = invited.take_outgoing().unwrap();
        deliver(
            &mut admin,
            &peers.0,
            &asked.app,
            (T0 + 14) * 1_000,
            &mut rng,
        );
        let joiners = admin.group_joiners().unwrap();
        let admission = admin
            .add_joiner(&joiners[0], (T0 + 15) * 1_000, &mut rng)
            .unwrap();
        carry(&mut admin, &mut [], &mut 0, T0 + 15, &mut rng);
        admin
            .admit_joiner(
                &joiners[0],
                admission.index,
                b"a descriptor",
                (T0 + 16) * 1_000,
                &mut rng,
            )
            .unwrap();
        let admit = admin.take_outgoing().unwrap();
        deliver(
            &mut invited,
            &peers.1,
            &admit.app,
            (T0 + 17) * 1_000,
            &mut rng,
        );
        let member = invited
            .accept_group_admit(
                admin_at_invited,
                &group_id,
                &admission.snapshot,
                T0 + 18,
                &mut rng,
            )
            .unwrap();

        // GRP-244: the contact of the admit shows at the index that its own
        // offer named. It shows at no index that the offer of another
        // contact named.
        let members = invited.group_members(member).unwrap();
        let contact_of = |index: u16| {
            members
                .iter()
                .find(|held| held.index == index)
                .unwrap()
                .contact
        };
        assert_eq!(contact_of(0), Some(admin_at_invited));
        assert_eq!(contact_of(1), None);
        // The offer of the other contact left with the join.
        assert!(invited.group_offers().unwrap().is_empty());
    }

    #[test]
    fn an_admin_counts_silence_over_the_time_that_it_read_the_group_alone() {
        let mut rng = Rng(303);
        let mut admin = new_client(&mut rng);
        let mut second = new_client(&mut rng);
        let mut third = new_client(&mut rng);
        let group = new_group(&mut admin, &mut rng);
        invite(
            &mut admin,
            &mut second,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        invite(
            &mut admin,
            &mut third,
            group,
            (ContactId([0x53; 32]), ContactId([0x54; 32])),
            T0 + 2,
            &mut rng,
        );
        let mut reading = BTreeSet::new();
        let start = T0 + 100;

        // GRP-396: a `GSUB` that just left read no backlog yet, and nobody
        // is silent before the watch starts.
        assert!(pump(&mut admin, &mut reading, start, &mut rng).is_empty());
        let watched = start + WATCH_QUIET;
        assert!(pump(&mut admin, &mut reading, watched, &mut rng).is_empty());
        // Each hour a tick names the group as read, for thirty days.
        let silent = watched + GROUP_SILENT_EVICT;
        let mut at = watched;
        while at < silent {
            at += 3_600;
            admin.group_reads(&[group], at * 1_000, &mut rng).unwrap();
        }
        // GRP-397: the backoff comes first. GRP-134: the replica of this
        // session gave no answer yet, thus one presence record asks it for
        // a `GSEQ`. No removal comes before that answer.
        assert!(pump(&mut admin, &mut reading, silent, &mut rng).is_empty());
        assert!(pump(&mut admin, &mut reading, silent + 3_600, &mut rng).is_empty());
        let probe = admin.take_group_post().unwrap();
        assert!(probe.message.is_none() && probe.unsent.is_none());
        assert!(pump(&mut admin, &mut reading, silent + 3_601, &mut rng).is_empty());
        assert!(admin.take_group_post().is_none());
        for relay in RELAYS {
            admin
                .group_replica_reached(group, &relay, true, &mut rng)
                .unwrap();
        }
        assert_eq!(
            pump(&mut admin, &mut reading, silent + 3_602, &mut rng),
            vec![(group, 1, Silence::Remove), (group, 2, Silence::Remove)]
        );

        // The device is off for 31 days. At its return each member is as
        // silent as before on the clock, and the admin watched none of that
        // time. No removal comes before the backlog arrived, and none after
        // it.
        admin.lock();
        let back = silent + 31 * DAY;
        admin.unlock(&units("correct horse"), back).unwrap();
        reading.clear();
        assert!(pump(&mut admin, &mut reading, back, &mut rng).is_empty());
        assert!(pump(&mut admin, &mut reading, back + WATCH_QUIET, &mut rng).is_empty());
        assert!(pump(
            &mut admin,
            &mut reading,
            back + WATCH_QUIET + 3_600,
            &mut rng
        )
        .is_empty());
        assert!(pump(
            &mut admin,
            &mut reading,
            back + WATCH_QUIET + 7_200,
            &mut rng
        )
        .is_empty());

        // A tick that is missing for more than `CLOCK_SKEW` ends the watch,
        // and the time of the hole counts for no silence.
        let hole = back + 40 * DAY;
        assert!(pump(&mut admin, &mut reading, hole, &mut rng).is_empty());
        assert!(pump(&mut admin, &mut reading, hole + WATCH_QUIET, &mut rng).is_empty());
        assert!(pump(
            &mut admin,
            &mut reading,
            hole + WATCH_QUIET + 3_600,
            &mut rng
        )
        .is_empty());

        // SCP-019: a movement of the clock starts each silence again.
        let moved = hole + 40 * DAY;
        admin.clock_check(moved * 1_000, &mut rng);
        assert!(pump(&mut admin, &mut reading, moved, &mut rng).is_empty());
        assert!(pump(&mut admin, &mut reading, moved + 3_600, &mut rng).is_empty());

        // A subscription that ended watches nothing.
        reading.clear();
        admin
            .group_reads(&[], (moved + 3_601) * 1_000, &mut rng)
            .unwrap();
        let far = moved + 60 * DAY;
        assert!(admin
            .members_to_evict(far * 1_000, &mut rng)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn the_gkey_of_new_owner_credentials_goes_again_until_a_gseq_follows_it() {
        let mut rng = Rng(304);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        invite(
            &mut client,
            &mut other,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        let mut seq = 20;
        let owners = |client: &Device| -> [[u8; 32]; 2] {
            let held = client.group_of(group).unwrap();
            [
                *held.owner(0).unwrap().expose(),
                *held.owner(1).unwrap().expose(),
            ]
        };
        client
            .set_group_role(group, 1, Role::Admin, (T0 + 10) * 1_000, &mut rng)
            .unwrap();
        carry(&mut client, &mut [&mut other], &mut seq, T0 + 10, &mut rng);
        while client.take_group_rekey().is_some() {}
        let old = owners(&client);

        // GRP-401: the demotion draws new owner credentials, and the `GKEY`
        // of each replica goes under the ones that they replace.
        client
            .set_group_role(group, 1, Role::Member, (T0 + 20) * 1_000, &mut rng)
            .unwrap();
        let new = owners(&client);
        assert_ne!(new, old);
        let first: Vec<GroupRekey> = core::iter::from_fn(|| client.take_group_rekey()).collect();
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|job| job.next_own_pk.is_some()));

        // The run ends before either `GKEY` left. The credentials before
        // are in the store, and the next session sends each `GKEY` again,
        // once it read its backlog.
        client.lock();
        client.unlock(&units("correct horse"), T0 + 100).unwrap();
        assert!(client.take_group_rekey().is_none());
        let mut reading = BTreeSet::new();
        pump(&mut client, &mut reading, T0 + 100, &mut rng);
        assert!(client.take_group_rekey().is_none());
        pump(&mut client, &mut reading, T0 + 100 + WATCH_QUIET, &mut rng);
        let again: Vec<GroupRekey> = core::iter::from_fn(|| client.take_group_rekey()).collect();
        for (which, relay) in RELAYS.iter().enumerate() {
            let carried: Vec<&GroupRekey> = again
                .iter()
                .filter(|job| job.relay == *relay && job.next_own_pk.is_some())
                .collect();
            assert_eq!(carried.len(), 1);
            assert_eq!(*carried[0].own.expose(), old[which]);
            assert!(again.iter().any(|job| job.relay == *relay
                && job.next_own_pk.is_none()
                && *job.own.expose() == new[which]));
        }

        let held = client.gkey_row(group).unwrap();
        assert!(held.replaced.iter().all(|before| before.len() == 1));
        // A record that leaves after them takes its `GSEQ` at each replica:
        // each `GKEY` arrived, and the credentials before leave the store.
        say(&mut client, group, "after the rotation", T0 + 300, &mut rng);
        carry(&mut client, &mut [&mut other], &mut seq, T0 + 300, &mut rng);
        let held = client.gkey_row(group).unwrap();
        assert!(held.replaced.iter().all(Vec::is_empty));
        assert!(held.taken.iter().all(Option::is_some));
        client.lock();
        client.unlock(&units("correct horse"), T0 + 1_000).unwrap();
        reading.clear();
        pump(&mut client, &mut reading, T0 + 1_000, &mut rng);
        pump(
            &mut client,
            &mut reading,
            T0 + 1_000 + WATCH_QUIET,
            &mut rng,
        );
        assert!(client.take_group_rekey().is_none());
    }

    #[test]
    fn a_closed_group_fails_a_message_and_opens_when_a_replica_answers() {
        let mut rng = Rng(305);
        let mut client = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        client.close_group(group, &mut rng).unwrap();
        assert!(client.group_info(group).unwrap().is_closed);
        // GRP-210: the message did not go, and the view shows it.
        let message = say(&mut client, group, "into a closed group", T0 + 10, &mut rng);
        assert!(client.take_group_post().is_none());
        assert_eq!(client.info(&message).unwrap().delivery, Delivery::Failed);
        while client.next_event().is_some() {}
        // A replica that answers under the credentials of this device holds
        // the group queue, thus the group is not gone.
        client.group_queue_reached(&QUEUES[1], &mut rng).unwrap();
        assert!(!client.group_info(group).unwrap().is_closed);
        assert_eq!(client.next_event(), Some(Event::Conversations));
        client
            .send_again(&message, (T0 + 20) * 1_000, &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_some());
    }

    #[test]
    fn a_subscription_moves_the_replica_when_its_gsub_goes_and_not_before() {
        let mut rng = Rng(306);
        let mut client = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let relay_of = |client: &mut Device| {
            let held = client.group_subscriptions(&mut Rng(1)).unwrap();
            assert_eq!(held.len(), 1);
            held[0].relay
        };
        // GRP-204: a pump that sends no `GSUB` changes nothing.
        let stored = client.group_of(group).unwrap().export().unwrap();
        let first = relay_of(&mut client);
        assert_eq!(relay_of(&mut client), first);
        assert_eq!(client.group_of(group).unwrap().export().unwrap(), stored);
        // The `GSUB` goes, and the next one takes the other replica. That
        // is in the same session after a `GSUB` that found no circuit
        // (`GRP-391`), and in the next session else.
        client
            .group_reads(&[group], (T0 + 10) * 1_000, &mut rng)
            .unwrap();
        while client.take_epoch_upload().is_some() {}
        let second = relay_of(&mut client);
        assert_ne!(second, first);
        assert_eq!(relay_of(&mut client), second);
        client
            .group_reads(&[group], (T0 + 20) * 1_000, &mut rng)
            .unwrap();
        while client.take_epoch_upload().is_some() {}
        assert_eq!(relay_of(&mut client), first);
        // A tick that names the group as read sends no `GSUB`.
        while client.take_epoch_upload().is_some() {}
        client
            .group_reads(&[group], (T0 + 21) * 1_000, &mut rng)
            .unwrap();
        assert_eq!(relay_of(&mut client), first);

        // NTF-093: the `GNREG` of the replica of a `GSUB` goes with it, and
        // no other one before its time.
        while client.take_epoch_upload().is_some() {}
        client
            .set_group_notify(
                group,
                [9; 32],
                &[7; umbra_wire::address::LEN],
                T0 + 30,
                &mut rng,
            )
            .unwrap();
        for due in client.notify_registrations_due(T0 + 30).unwrap() {
            client
                .notify_registered(group, due.which, T0 + 30, &mut rng)
                .unwrap();
        }
        assert!(client.notify_registrations_due(T0 + 31).unwrap().is_empty());
        let next = relay_of(&mut client);
        client
            .group_reads(&[group], (T0 + 40) * 1_000, &mut rng)
            .unwrap();
        let due = client.notify_registrations_due(T0 + 40).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].relay, next);
        client
            .notify_registered(group, due[0].which, T0 + 40, &mut rng)
            .unwrap();
        assert!(client.notify_registrations_due(T0 + 41).unwrap().is_empty());
    }

    #[test]
    fn a_record_that_a_replica_did_not_take_goes_again_inside_the_run() {
        let mut rng = Rng(307);
        let mut client = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let sent = T0 + 10;
        say(&mut client, group, "hello", sent, &mut rng);
        let post = client.take_group_post().unwrap();
        let row = post.unsent.unwrap();
        for relay in RELAYS {
            client
                .group_post_sent(&row, &relay, sent, &mut rng)
                .unwrap();
        }
        // GRP-196: no replica answered, and no wait ran out yet.
        client
            .expire_group_holds((sent + RESEND_FIRST - 1) * 1_000, &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_none());
        // The same bytes go again to each replica after the first wait.
        let again = sent + RESEND_FIRST + RESEND_SWEEP;
        client.expire_group_holds(again * 1_000, &mut rng).unwrap();
        let second = client.take_group_post().unwrap();
        assert_eq!(second.record, post.record);
        assert_eq!(second.unsent, Some(row));
        assert_eq!(second.pending, [true, true]);
        assert!(client.take_group_post().is_none());
        // One replica takes it, and the other one alone gets it once more,
        // after twice the wait.
        for relay in RELAYS {
            client
                .group_post_sent(&row, &relay, again, &mut rng)
                .unwrap();
        }
        client
            .group_post_accepted(&row, &RELAYS[0], &mut rng)
            .unwrap();
        client
            .expire_group_holds((again + RESEND_FIRST + RESEND_SWEEP) * 1_000, &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_none());
        client
            .expire_group_holds((again + 2 * RESEND_FIRST + RESEND_SWEEP) * 1_000, &mut rng)
            .unwrap();
        let third = client.take_group_post().unwrap();
        assert_eq!(third.pending, [false, true]);
    }

    #[test]
    fn a_deletion_that_came_before_its_target_and_one_after_a_rekey_both_apply() {
        let mut rng = Rng(308);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let member = invite(
            &mut client,
            &mut other,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        let ms = |seconds: u64| seconds * 1_000;

        // DEV-093: one replica gives the deletion before the message. The
        // deletion waits. DEV-102: the client never held the message, thus
        // the view shows nothing at that position and no alert goes.
        let mine = say(&mut other, member, "a secret", T0 + 10, &mut rng);
        let message = other.take_group_post().unwrap();
        other
            .delete_for_everyone(&mine, ms(T0 + 11), &mut rng)
            .unwrap();
        let deletion = other.take_group_post().unwrap();
        assert!(client
            .on_group_record(&QUEUES[0], 31, &deletion.record, ms(T0 + 12), &mut rng)
            .unwrap()
            .is_none());
        assert!(client.messages(group).unwrap().is_empty());
        while client.next_event().is_some() {}
        assert!(client
            .on_group_record(&QUEUES[0], 30, &message.record, ms(T0 + 13), &mut rng)
            .unwrap()
            .is_none());
        // The copy of the other replica stays out as well.
        assert!(client
            .on_group_record(&QUEUES[1], 30, &message.record, ms(T0 + 14), &mut rng)
            .unwrap()
            .is_none());
        assert!(client.messages(group).unwrap().is_empty());
        while let Some(event) = client.next_event() {
            assert!(!matches!(event, Event::Message { .. }));
        }

        // An edit waits in the same way.
        let mine = say(&mut other, member, "meet at 8", T0 + 20, &mut rng);
        let message = other.take_group_post().unwrap();
        let mut draft = other.new_draft(member);
        draft.set_text(&units("meet at 9")).unwrap();
        other.edit(&mine, draft, ms(T0 + 21), &mut rng).unwrap();
        let edit = other.take_group_post().unwrap();
        client
            .on_group_record(&QUEUES[0], 33, &edit.record, ms(T0 + 22), &mut rng)
            .unwrap();
        let held = client
            .on_group_record(&QUEUES[0], 32, &message.record, ms(T0 + 23), &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(client.info(&held).unwrap().revisions, 1);

        // Part 11 §11.12: a re-key moves the member to a new index, and it
        // keeps its messages. Its deletion after the re-key applies to a
        // message that it sent before.
        let mut seq = 40;
        let mine = say(&mut other, member, "from the old index", T0 + 30, &mut rng);
        let post = other.take_group_post().unwrap();
        let held = client
            .on_group_record(&QUEUES[0], 34, &post.record, ms(T0 + 31), &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(client.info(&held).unwrap().sender, Some(1));
        other.rekey_groups(ms(T0 + 40), &mut rng).unwrap();
        carry(&mut other, &mut [&mut client], &mut seq, T0 + 40, &mut rng);
        assert_eq!(other.group_info(member).unwrap().own_index, 2);
        other
            .delete_for_everyone(&mine, ms(T0 + 50), &mut rng)
            .unwrap();
        carry(&mut other, &mut [&mut client], &mut seq, T0 + 50, &mut rng);
        assert!(client.info(&held).unwrap().deleted);
    }

    #[test]
    fn a_kind_that_is_no_message_of_a_group_makes_no_row_and_no_alert() {
        let mut rng = Rng(311);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let member = invite(
            &mut client,
            &mut other,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        while client.next_event().is_some() {}
        // WIR-075, GRP-299, GRP-300: a receipt, a typing indicator, a
        // reaction, and a kind of the pairwise channel.
        let commit = [0x11u8; 64];
        let reveal = [0x22u8; 32];
        let kinds: [(AppKind, &[u8]); 6] = [
            (AppKind::Reaction, b"\x01\x02"),
            (AppKind::DeliveryReceipt, b"\x01"),
            (AppKind::ReadReceipt, b"\x01"),
            (AppKind::Typing, b"\x01"),
            (AppKind::VerifyCommit, &commit),
            (AppKind::VerifyReveal, &reveal),
        ];
        for (place, (kind, body)) in kinds.into_iter().enumerate() {
            let record = AppMessage {
                kind,
                msg_id: [0x60 + u8::try_from(place).unwrap(); 16],
                sent_at: (T0 + 10) * 1_000,
                body,
            };
            let mut app = vec![0u8; record.len()];
            record.encode(&mut app).unwrap();
            assert!(AppMessage::parse(&app, umbra_wire::app::Channel::Group).is_ok());
            let mut posting = other.group_of(member).unwrap();
            let sealed = posting.post(&app, T0 + 10, &mut rng).unwrap();
            other.save_group(member, &posting, &mut rng).unwrap();
            assert!(client
                .on_group_record(&QUEUES[0], 30, &sealed, (T0 + 11) * 1_000, &mut rng)
                .unwrap()
                .is_none());
        }
        assert!(client.messages(group).unwrap().is_empty());
        while let Some(event) = client.next_event() {
            assert!(!matches!(event, Event::Message { .. }));
        }
    }

    #[test]
    fn a_rich_record_around_no_text_is_no_message_of_a_group() {
        let mut rng = Rng(309);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let member = invite(
            &mut client,
            &mut other,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        // DEV-174: a rich record takes its class from the kind that it goes
        // around, and one around a vote is no message.
        let rich = umbra_wire::app::rich::RichRecord {
            reply_target: [0; 16],
            thread_root: [0; 16],
            forward_depth: 0,
            mentions: Vec::new(),
            inner_kind: AppKind::PollVote,
            inner_body: b"no text at all",
        };
        let mut body = vec![0u8; rich.len()];
        rich.encode(umbra_wire::app::Channel::Group, &mut body)
            .unwrap();
        let record = AppMessage {
            kind: AppKind::Rich,
            msg_id: [0x42; 16],
            sent_at: (T0 + 10) * 1_000,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app).unwrap();
        let sealed = other
            .group_of(member)
            .unwrap()
            .post(&app, T0 + 10, &mut rng)
            .unwrap();
        assert!(client
            .on_group_record(&QUEUES[0], 30, &sealed, (T0 + 11) * 1_000, &mut rng)
            .unwrap()
            .is_none());
        assert!(client.messages(group).unwrap().is_empty());
    }

    #[test]
    fn a_rekey_record_for_an_index_that_no_rival_moved_removes_nobody() {
        let mut rng = Rng(310);
        let mut admin = new_client(&mut rng);
        let mut joiner = new_client(&mut rng);
        let group = new_group(&mut admin, &mut rng);
        let member = invite(
            &mut admin,
            &mut joiner,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        // The member moves to new keys after it lost a device, and no rival
        // re-key ever came.
        let mut stolen = joiner.group_of(member).unwrap();
        joiner.rekey_groups((T0 + 10) * 1_000, &mut rng).unwrap();
        let rekey = joiner.take_group_post().unwrap();
        admin
            .on_group_record(&QUEUES[0], 21, &rekey.record, (T0 + 11) * 1_000, &mut rng)
            .unwrap();
        let moved = admin.group_of(group).unwrap().roster().successor_of(1);
        assert_eq!(moved, Some(2));
        while admin.take_group_post().is_some() {}
        // The lost device reads the same record, and its index left the
        // roster.
        let Outcome::Content {
            app, sender, slot, ..
        } = stolen.receive(&rekey.record, T0 + 11).unwrap()
        else {
            panic!("the lost device read no re-key");
        };
        let parsed = AppMessage::parse(&app, umbra_wire::app::Channel::Group).unwrap();
        stolen
            .apply_control_at(
                &GroupControl::parse(parsed.body).unwrap(),
                sender,
                slot,
                T0 + 11,
            )
            .unwrap();

        // GRP-349: the holder of the lost device signs a record for the old
        // index under its roster key, and sends it to the admin. No rival
        // moved that index, thus the admin discards the record: the index
        // that follows it holds the keys of the member itself.
        let fresh = umbra_core::group::join::JoinKeys::make(&mut rng).unwrap();
        let object = stolen.pairwise_rekey_object(&fresh, &mut rng).unwrap();
        let forged = AppMessage {
            kind: AppKind::GroupControl,
            msg_id: [0x66; 16],
            sent_at: (T0 + 20) * 1_000,
            body: &object,
        };
        let mut app = vec![0u8; forged.len()];
        forged.encode(&mut app).unwrap();
        deliver(&mut admin, &AT_ADMIN, &app, (T0 + 20) * 1_000, &mut rng);
        let held = admin.group_of(group).unwrap();
        assert!(held.roster().member(2).unwrap().active);
        assert!(admin.group_joiners().unwrap().is_empty());
        assert!(admin.take_group_post().is_none());
    }

    #[derive(Default)]
    struct View(Vec<u16>);

    impl crate::Sink for View {
        fn put(&mut self, code_units: &[u16]) {
            self.0 = code_units.to_vec();
        }
    }

    #[test]
    fn an_edit_that_each_replica_gives_applies_once_and_its_late_copy_changes_nothing() {
        let mut rng = Rng(311);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let member = invite(
            &mut client,
            &mut other,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        let ms = |seconds: u64| seconds * 1_000;
        let text = |client: &Device, message: &MsgRef| {
            let mut view = View::default();
            client.render(message, &mut view).unwrap();
            String::from_utf16(&view.0).unwrap()
        };
        let mine = say(&mut other, member, "meet at 8", T0 + 10, &mut rng);
        let message = other.take_group_post().unwrap();
        let held = client
            .on_group_record(&QUEUES[0], 30, &message.record, ms(T0 + 11), &mut rng)
            .unwrap()
            .unwrap();
        let mut edit = |to: &str, at: u64, rng: &mut Rng| {
            let mut draft = other.new_draft(member);
            draft.set_text(&units(to)).unwrap();
            other.edit(&mine, draft, ms(at), rng).unwrap();
            other.take_group_post().unwrap()
        };

        // GRP-206: a reader takes each record from each replica in turn.
        // The second copy of an edit counts no second revision.
        let first = edit("meet at 9", T0 + 12, &mut rng);
        for queue in &QUEUES {
            client
                .on_group_record(queue, 31, &first.record, ms(T0 + 13), &mut rng)
                .unwrap();
        }
        assert_eq!(client.info(&held).unwrap().revisions, 1);
        assert_eq!(text(&client, &held), "meet at 9");

        // The second replica never took the second edit. A later session
        // there gives the first one again, and the newer text stays.
        let second = edit("meet at 10", T0 + 14, &mut rng);
        client
            .on_group_record(&QUEUES[0], 32, &second.record, ms(T0 + 15), &mut rng)
            .unwrap();
        assert_eq!(client.info(&held).unwrap().revisions, 2);
        client
            .on_group_record(&QUEUES[1], 31, &first.record, ms(T0 + 600), &mut rng)
            .unwrap();
        assert_eq!(client.info(&held).unwrap().revisions, 2);
        assert_eq!(text(&client, &held), "meet at 10");
        // A copy of the message itself drops at its `msg_id`.
        assert!(client
            .on_group_record(&QUEUES[1], 30, &message.record, ms(T0 + 601), &mut rng)
            .unwrap()
            .is_none());
        assert_eq!(client.messages(group).unwrap().len(), 1);
    }

    #[test]
    fn an_epoch_of_the_backlog_sends_no_gkey_before_the_backlog_ends() {
        let mut rng = Rng(312);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let member = invite(
            &mut client,
            &mut other,
            group,
            (AT_ADMIN, AT_JOINER),
            T0 + 1,
            &mut rng,
        );
        let ms = |seconds: u64| seconds * 1_000;
        while client.take_group_rekey().is_some() {}
        // GRP-360: the epoch is aged, and the plain member rotates while
        // the admin is away.
        let later = T0 + 31 * DAY;
        other.rotate_group(member, ms(later), &mut rng).unwrap();
        let rotation = other.take_group_post().unwrap();
        assert!(rotation.is_rotation);

        // The admin comes back, and the record of its backlog installs the
        // epoch. The group can hold a later epoch that this backlog gives
        // next, thus no `GKEY` goes yet (§11.4.1).
        let mut reading = BTreeSet::new();
        pump(&mut client, &mut reading, later + 10, &mut rng);
        client
            .on_group_record(&QUEUES[0], 40, &rotation.record, ms(later + 11), &mut rng)
            .unwrap();
        assert_eq!(client.group_of(group).unwrap().epoch(), 2);
        assert!(client.take_group_rekey().is_none());
        // The backlog ended: the `GKEY` of the epoch that stands goes to
        // each replica.
        pump(
            &mut client,
            &mut reading,
            later + 11 + WATCH_QUIET,
            &mut rng,
        );
        let write_pk = client
            .group_of(group)
            .unwrap()
            .credentials()
            .unwrap()
            .write_public();
        let jobs: Vec<GroupRekey> = core::iter::from_fn(|| client.take_group_rekey()).collect();
        assert_eq!(jobs.len(), GROUP_REPLICAS);
        assert!(jobs.iter().all(|job| job.write_pk == write_pk));

        // A record that leaves after them, and after the grace of the
        // epoch before, goes under the pair of the new epoch alone. Its
        // `GSEQ` tells that each `GKEY` arrived (`GRP-398`).
        let mut seq = 50;
        let after = later + 2 * DAY;
        say(&mut client, group, "under the new epoch", after, &mut rng);
        carry(&mut client, &mut [], &mut seq, after, &mut rng);
        assert!(client
            .gkey_row(group)
            .unwrap()
            .taken
            .iter()
            .all(|taken| *taken == Some(write_pk)));
        // GRP-363: each replica then refuses that pair, as after a `GKEY`
        // of an older epoch moved it back. The mark of the `GKEY` goes. The
        // next session sends it again after its backlog, to a group that
        // this device shows as closed too.
        client.close_group(group, &mut rng).unwrap();
        assert!(client
            .gkey_row(group)
            .unwrap()
            .taken
            .iter()
            .all(Option::is_none));
        client.lock();
        client
            .unlock(&units("correct horse"), after + 1_000)
            .unwrap();
        reading.clear();
        pump(&mut client, &mut reading, after + 1_000, &mut rng);
        assert!(client.take_group_rekey().is_none());
        pump(
            &mut client,
            &mut reading,
            after + 1_000 + WATCH_QUIET,
            &mut rng,
        );
        let again: Vec<GroupRekey> = core::iter::from_fn(|| client.take_group_rekey()).collect();
        assert_eq!(again.len(), GROUP_REPLICAS);
        assert!(again.iter().all(|job| job.write_pk == write_pk));
    }

    #[test]
    fn a_rekey_that_a_rate_holds_back_goes_again_when_the_rate_takes_it() {
        let mut rng = Rng(313);
        let mut client = new_client(&mut rng);
        let group = new_group(&mut client, &mut rng);
        let ms = |seconds: u64| seconds * 1_000;
        // GRP-076: four re-keys of one member in a day, and the fifth
        // waits. The device that left the set holds keys of the group
        // until it goes.
        for step in 0..u64::from(umbra_core::group::REKEY_RATE_DAY) {
            client.rekey_groups(ms(T0 + 10 + step), &mut rng).unwrap();
        }
        let index = client.group_info(group).unwrap().own_index;
        assert_eq!(index, 4);
        assert!(matches!(
            client.rekey_groups(ms(T0 + 20), &mut rng),
            Err(Error::Busy)
        ));
        while client.take_group_post().is_some() {}
        // A sweep inside the day posts nothing, and the re-key still waits.
        client.expire_group_holds(ms(T0 + 100), &mut rng).unwrap();
        assert_eq!(client.group_info(group).unwrap().own_index, index);
        // The rate takes it a day later, and the sweep posts it.
        let later = T0 + 25 * 3_600;
        client.expire_group_holds(ms(later), &mut rng).unwrap();
        assert_eq!(client.group_info(group).unwrap().own_index, index + 1);
        // It goes once.
        client
            .expire_group_holds(ms(later + 120), &mut rng)
            .unwrap();
        assert_eq!(client.group_info(group).unwrap().own_index, index + 1);
    }
}
