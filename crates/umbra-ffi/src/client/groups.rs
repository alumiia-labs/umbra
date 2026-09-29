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
const GROUP_NOTIFY_LEN_V1: usize = 32 + umbra_wire::address::LEN + 16;
const GROUP_NOTIFY_LEN: usize = GROUP_NOTIFY_LEN_V1 + 8 + 1 + 32 + umbra_wire::address::LEN;
/// A registration lives 7 days plus `CLOCK_SKEW` at a group-queue relay
/// (`NTF-102`), thus a device registers again after 6 days.
pub const NOTIFY_REREGISTER: u64 = 6 * 86_400;

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
    /// The row that keeps the record until a replica accepts it, for a
    /// record that carries no message.
    pub unsent: Option<[u8; 16]>,
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
    /// The requests of each group that this device took in, which drop
    /// above the rate (`GRP-378`).
    pub key_answers_rate: BTreeMap<ConversationId, KeyRequestRate>,
    /// The slot objects of rotations that wait for the chunk path, whose
    /// records follow the upload (`GRP-283`).
    pub epoch_uploads: VecDeque<EpochUpload>,
    /// The chunks of chunked epoch-key records that this device fetches
    /// (`GRP-284`).
    pub epoch_chunks: VecDeque<(ConversationId, WantedChunk)>,
    /// The groups whose state upload runs (`DEV-298`).
    pub state_out: std::collections::BTreeSet<ConversationId>,
    /// The group states that this device fetches, by the subject of each
    /// group.
    pub state_in: VecDeque<([u8; 32], Box<umbra_wire::descriptor::FileDescriptor>)>,
}

/// The facts of a group before an arrival, which tell what it changed.
pub(super) struct Before {
    epoch: u32,
    owners: Option<[u8; 32]>,
}

impl Before {
    pub(super) fn of(group: &Group) -> Self {
        Before {
            epoch: group.epoch(),
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
fn sent_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), b"sent"].concat()
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
    /// re-key.
    pub fn rekey_groups<R: CryptoRng + umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        for conversation in self.group_conversations()? {
            self.rekey_group(conversation, now_ms, rng)?;
        }
        Ok(())
    }

    /// Moves the member to new keys in one group. A closed group and a
    /// group that no longer holds the member take no re-key.
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
        let object = group
            .rekey_object(&fresh, rng)
            .map_err(|_| Error::Malformed)?;
        drop(group);
        self.post_group_control(conversation, &object, now_ms, rng)?;
        let mut group = self.group_of(conversation)?;
        let group_id = *group.group_id();
        group
            .adopt_rekey(&object, &fresh.seed, now_ms / 1_000)
            .map_err(|_| Error::Malformed)?;
        self.store_rekeyed(conversation, &group, &fresh.seed, rng)?;
        // DEV-300: each other device of the set moves with this one.
        self.publish_group_rekey(&group_id, &fresh.seed, &object, rng)
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
                self.rekey_group(conversation, now_ms, rng)
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
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        batch.commit()?;
        // Each record that waited for a queue that is gone leaves the
        // work list. The store keeps the message, and the user sees that
        // it did not go.
        self.groups
            .posts
            .retain(|post| post.conversation != conversation);
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
        })
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
    fn send_pairwise_app<R: CryptoRng + ?Sized>(
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
            now_ms,
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
        // GRP-153: an offer to a group that this device holds is refused.
        let conversation = self.conversation_of_group(&offer.group_id)?;
        if self.is_group(conversation)? {
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
        // GRP-052: the seed comes from the device CSPRNG, and it stays in
        // the local identity table until the admit arrives.
        let mut seed = Secret::<32>::zeroed();
        rng.fill_bytes(seed.expose_mut());
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
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, &offer.group_id);
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
                // GRP-153: an offer to a group that this device holds is
                // no offer.
                let conversation = self.conversation_of_group(&invitation.group_id)?;
                if self.is_group(conversation)? {
                    return Ok(());
                }
                let name: String = name.chars().take(GROUP_NAME_MAX).collect();
                let mut entry = vec![OFFERED];
                entry.extend_from_slice(&from.0);
                entry.extend_from_slice(&invitation.group_id);
                entry.extend_from_slice(creator_roster_pk);
                entry.extend_from_slice(name.as_bytes());
                let row = self.join_row(from, &invitation.group_id)?;
                let open = self.open_mut()?;
                // The admin that offers is the contact that sent the offer,
                // thus the group can name it once this device holds the
                // roster.
                let admin_row = open
                    .store
                    .row_id(GROUP_MEMBER, &Self::admin_key(conversation));
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
                // A join record for a group that this device does not hold
                // names no group of any admin here.
                let conversation = self.conversation_of_group(&record.group_id)?;
                if !self.is_group(conversation)? {
                    return Ok(());
                }
                let mut entry = vec![ASKED];
                entry.extend_from_slice(&from.0);
                entry.extend_from_slice(&record.group_id);
                entry.extend_from_slice(control.payload);
                let row = self.join_row(from, &record.group_id)?;
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
    /// rival replaced (`GRP-370`). An admin verifies it under the roster key
    /// of the index that it names (`GRP-348`, `GRP-349`), and removes the
    /// index that the rival holds now, with a rotation (`GRP-371`). The
    /// member then waits as a joiner with its new keys, and the admin admits
    /// it as each joiner (§11.9.1).
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
        let Some(rival) = group.roster().successor_of(record.old_index) else {
            return Ok(());
        };
        drop(group);
        // GRP-351: the removed index is not used again, and GRP-264 rotates
        // with the removal.
        if self
            .group_of(conversation)?
            .roster()
            .member(rival)
            .is_some_and(|member| member.active)
        {
            self.remove_from_group(conversation, rival, now_ms, rng)?;
        }
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
        Ok(())
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
        let add = group.add_object(&parsed).map_err(|_| Error::Malformed)?;
        // GRP-310, GRP-389: the add goes to each replica first, thus its
        // record names the roster epoch that every member holds.
        self.post_group_control(conversation, &add, now_ms, rng)?;
        let index = self.apply_own_roster_object(conversation, &add, now_ms, rng)?;
        let Applied::Added(index) = index else {
            return Err(Error::Malformed);
        };
        // GRP-324: the snapshot carries the authority path of each role.
        let group = self.group_of(conversation)?;
        let path = self.authority_path(conversation, &group)?;
        let snapshot = group.snapshot(&path).map_err(|_| Error::Malformed)?;
        self.note_member_contact(conversation, index, joiner.from, rng)?;
        let mut entry = vec![ADDED];
        entry.extend_from_slice(&joiner.from.0);
        entry.extend_from_slice(&joiner.group_id);
        entry.extend_from_slice(&index.to_be_bytes());
        entry.extend_from_slice(&snapshot);
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP_JOIN, row, Some(joiner.from.0), &entry, rng)?;
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
            .admit_at(index, roster_epoch, 0, descriptor, now_ms / 1_000)
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
        let seed = {
            let store = &self.open_ref()?.store;
            // GRP-370: a member that comes back after a rival re-key joins
            // under the seed that it sent to the admin.
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
                accept_admit(&invitation, &snapshot, &add_hash, &creator_roster_pk, now)
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
        // That admin shows under the name of the contact.
        if let Some(index) = self.offering_admin(conversation)? {
            self.note_contact_in(conversation, &index.to_be_bytes(), from, rng)?;
        }
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
        // GRP-153: a second admit to a group that this device holds is no
        // group. A member whose index a rival took comes back under the
        // admit, and the new group takes the place of the one it held. So
        // does the second admit of `GRP-421`.
        let conversation = self.conversation_of_group(&group_id)?;
        if !replaces && self.is_group(conversation)? && !self.group_of(conversation)?.lost_rekey() {
            return Err(Error::Malformed);
        }
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
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        batch.put(TableId::LOCAL_IDENTITY, seed_row, None, seed.expose(), rng)?;
        batch.delete(TableId::LOCAL_IDENTITY, lost_row);
        batch.delete(TableId::LOCAL_IDENTITY, previous_row);
        batch.commit()?;
        self.put_conversation_meta(conversation, 0, name, rng)?;
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
        let plain = stored_message(super::OUTGOING, Delivery::Queued, conversation, now_ms, app);
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
        // GRP-210: a group whose two queues are gone takes no record.
        if self.group_closed(conversation)? {
            return Ok(());
        }
        let mut group = self.group_of(conversation)?;
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
        // GRP-246: the counter of this device moves with the record, thus
        // the group goes back to the store before the record leaves.
        let record = group
            .post(app, now_ms / 1_000, rng)
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
            if !is_rekey {
                self.apply_own_roster_object(conversation, parsed.body, now_ms, rng)?;
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
            now_ms,
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
        let Some(replicas) = Self::group_replicas_of(&group)? else {
            return Ok(());
        };
        let old = group.replace_owners(rng).map_err(|_| Error::Malformed)?;
        self.save_group(conversation, &group, rng)?;
        let credentials = group.credentials().ok_or(Error::Integrity)?;
        for (which, replica) in replicas.iter().enumerate() {
            let (Some(own), Some(next)) = (old.get(which), group.owner(which)) else {
                continue;
            };
            let next_own_pk = *umbra_crypto::x25519::PublicKey::from(
                &umbra_crypto::x25519::StaticSecret::from(*next.expose()),
            )
            .as_bytes();
            self.groups.rekeys.push_back(GroupRekey {
                relay: replica.relay,
                group_queue_id: replica.group_queue_id,
                own: Secret::new(*own.expose()),
                next_own_pk: Some(next_own_pk),
                read_pk: credentials.read_public(),
                write_pk: credentials.write_public(),
            });
        }
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
        let object = self
            .group_of(conversation)?
            .leave_object()
            .map_err(|_| Error::Malformed)?;
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
        let mut group = self.group_of(conversation)?;
        let control = GroupControl::parse(object)?;
        let forks = group.roster().forks().len();
        let applied = group.apply_control(&control, group.own_index(), now_ms / 1_000);
        self.note_forks(conversation, &group, forks, now_ms, rng)?;
        let applied = applied.map_err(|_| Error::Malformed)?;
        self.save_group(conversation, &group, rng)?;
        if matches!(applied, Applied::Granted { .. }) {
            self.note_grant(conversation, object, rng)?;
        }
        self.roster_moved(conversation, &applied, now_ms / 1_000, rng)?;
        self.drop_passed_adds(conversation)?;
        // DEV-303: a key that waited for this roster object installs now.
        self.retry_epoch_keys(conversation, now_ms, rng)?;
        Ok(applied)
    }

    /// Starts the next epoch of a group and queues its epoch-key record
    /// for each replica (§11.4.1). A group with no queue yet, a closed
    /// group, and a group this device may no longer rotate give no record.
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
        let Ok(rotation) = group.rotate(now_ms / 1_000, rng) else {
            return Ok(());
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

    fn admin_key(conversation: ConversationId) -> Vec<u8> {
        [conversation.0.as_slice(), b"offer-admin"].concat()
    }

    /// The index of the admin whose offer brought this device into a
    /// group, by the hash of its roster key.
    fn offering_admin(&self, conversation: ConversationId) -> Result<Option<u16>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(GROUP_MEMBER, &Self::admin_key(conversation));
        let Some(hash) = store.get(GROUP_MEMBER, &row)? else {
            return Ok(None);
        };
        let group = self.group_of(conversation)?;
        let index = group
            .roster()
            .active()
            .find(|member| member.roster_pk_hash.as_slice() == hash.as_slice())
            .map(|member| member.index);
        Ok(index)
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
    fn contacts_in(&self, conversation: ConversationId) -> Result<Vec<ConversationId>, Error> {
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
        self.groups.rekeys.pop_front()
    }

    /// Each group whose backoff passed and whose trigger no record
    /// answered (`GRP-358`, `GRP-359`). A group seen for the first time
    /// draws its delay here and answers at a later call.
    pub fn groups_to_rotate<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Vec<ConversationId>, Error> {
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
    fn post_group_app<R: CryptoRng + ?Sized>(
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
            .entry(conversation)
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
        let rate = self
            .groups
            .key_answers_rate
            .entry(conversation)
            .or_default();
        if !rate.allow(now_ms / 1_000) {
            return Ok(());
        }
        let group = self.group_of(conversation)?;
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

    /// One `GSUB` for each group that holds its queues. A reader takes
    /// one replica in each session and alternates across sessions
    /// (`GRP-203`, `GRP-204`).
    pub fn group_subscriptions<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<GroupSubscription>, Error> {
        let mut out = Vec::new();
        for conversation in self.group_conversations()? {
            let mut group = self.group_of(conversation)?;
            let Some(credentials) = group.credentials().map(|held| held.read_secret()) else {
                continue;
            };
            let fallback = group.previous_credentials().map(|held| held.read_secret());
            let Some(replicas) = group.replicas_mut() else {
                continue;
            };
            let which = replicas.pick(rng.next_u32() & 1 == 1);
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
            self.save_group(conversation, &group, rng)?;
        }
        Ok(out)
    }

    /// Each open group that holds no notify queue yet, while the device
    /// holds a push token, thus it is in Instant mode (`NTF-090`,
    /// `NTF-106`).
    /// A group whose notify queue is older than `ROTATE_INTERVAL` gets a new
    /// one too, which replaces it after its registration (`NTF-104`).
    pub fn groups_without_notify(&self, now: u64) -> Result<Vec<ConversationId>, Error> {
        if self.push_token()?.is_none() {
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

    /// Each `GNREG` that is due: a notify queue that a replica does not
    /// hold, or holds for longer than `NOTIFY_REREGISTER` (`NTF-093`,
    /// `NTF-102`).
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
                if *at != 0 && now.saturating_sub(*at) < NOTIFY_REREGISTER {
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
        let value = unsent_row(order, &post);
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

    /// A replica accepted a record that the store kept (`GRP-195`).
    pub fn group_post_accepted(&mut self, row: &[u8; 16]) -> Result<(), Error> {
        let open = self.open_mut()?;
        if open.store.get(GROUP_UNSENT, row)?.is_none() {
            return Ok(());
        }
        let mut batch = open.store.begin();
        batch.delete(GROUP_UNSENT, *row);
        Ok(batch.commit()?)
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
        }
        let before = Before::of(&group);
        let outcomes: VecDeque<Outcome> = outcome.into_iter().collect();
        self.take_outcomes(conversation, group, outcomes, before, false, now_ms, rng)
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
                        // serves both.
                        let fetching = self.groups.epoch_chunks.iter().any(|(held, other)| {
                            *held == conversation && other.epoch == wanted.epoch
                        });
                        if !fetching {
                            self.groups.epoch_chunks.push_back((conversation, wanted));
                        }
                        continue;
                    }
                    if group
                        .install_epoch_key(epoch, start_slot, &body, now)
                        .is_ok()
                    {
                        installed = true;
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
                    ..
                } => {
                    self.note_seen(conversation, &group, sender, now, rng)?;
                    let parsed =
                        umbra_wire::app::AppMessage::parse(&app, umbra_wire::app::Channel::Group)?;
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
                            let forks = group.roster().forks().len();
                            let applied = group.apply_control(&control, sender, now);
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
                        self.count_discarded(conversation, rng)?;
                        continue;
                    }
                    // An edit and a deletion of an author name a message of
                    // that member alone (Part 11 §11.9.6).
                    if matches!(parsed.kind, AppKind::Edit | AppKind::Delete) {
                        self.take_group_change(conversation, Some(sender), &parsed, now_ms, rng)?;
                        continue;
                    }
                    // GRP-336: a vote is one group record, and each member
                    // counts it in the order of its sender (WIR-190).
                    if parsed.kind == AppKind::PollVote {
                        self.take_vote(
                            conversation,
                            parsed.body,
                            sender,
                            u64::from(counter),
                            now,
                            rng,
                        )?;
                        continue;
                    }
                    // A record that does not parse under the layout of a
                    // group goes (WIR-163, WIR-180).
                    let is_invalid = match parsed.kind {
                        AppKind::Rich => umbra_wire::app::rich::RichRecord::parse(
                            parsed.body,
                            umbra_wire::app::Channel::Group,
                        )
                        .is_err(),
                        AppKind::Poll => umbra_wire::app::poll::Poll::parse(parsed.body).is_err(),
                        _ => false,
                    };
                    if is_invalid {
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
                    let stored = self.store_group_message(conversation, &app, now_ms, rng)?;
                    if let Some(message) = stored {
                        self.put_group_sender(conversation, message, sender, rng)?;
                        self.after_group_store(conversation, &group, message, &app, now, rng)?;
                        match timer {
                            Some(seconds) => {
                                self.put_timer(conversation, seconds, now_ms, false, rng)?
                            }
                            None => {
                                self.stamp_deadline(conversation, message, parsed.kind, now, rng)?
                            }
                        }
                    }
                    first = first.or(stored);
                }
                Outcome::Held | Outcome::ClockSuspect | Outcome::Duplicate => {}
            }
        }
        // The counters, the held records and the roster moved.
        self.save_group(conversation, &group, rng)?;
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
        // installs no epoch.
        if installed && group.epoch() != before.epoch {
            self.queue_rekeys(&group)?;
            // GRP-405: the epoch that a lapsed member lacked arrived, and
            // the credentials of it take its records again.
            if self.group_lapsed(conversation)? {
                let row = Self::group_row(&group, OPEN)?;
                let open = self.open_mut()?;
                let mut batch = open.store.begin();
                batch.put(GROUP, conversation.0, None, &row, rng)?;
                batch.commit()?;
                self.groups.key_requests.remove(&conversation);
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
            now_ms,
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
    fn put_clock<R: CryptoRng + ?Sized>(
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
    fn clock(&self, key: &[u8]) -> Result<Option<u64>, Error> {
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
        let now = now_ms / 1_000;
        let mut due = Vec::new();
        for conversation in self.group_conversations()? {
            if self.group_closed(conversation)? {
                continue;
            }
            let group = self.group_of(conversation)?;
            if group.own_role().is_none_or(|role| role < Role::Admin) {
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
                let action = match PresenceTracker::eviction(role, active, owners) {
                    Eviction::Remove => Some(Silence::Remove),
                    Eviction::DemoteFirst => Some(Silence::Demote),
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

    /// Moves each replica to the credentials of the epoch this device
    /// installed, when this device holds the owner credentials and did
    /// not make that epoch (`GRP-363`).
    fn queue_rekeys(&mut self, group: &Group) -> Result<(), Error> {
        let Some(replicas) = Self::group_replicas_of(group)? else {
            return Ok(());
        };
        let Some(credentials) = group.credentials() else {
            return Ok(());
        };
        for (which, replica) in replicas.iter().enumerate() {
            let Some(own) = group.owner(which) else {
                continue;
            };
            self.groups.rekeys.push_back(GroupRekey {
                relay: replica.relay,
                group_queue_id: replica.group_queue_id,
                own: Secret::new(*own.expose()),
                next_own_pk: None,
                read_pk: credentials.read_public(),
                write_pk: credentials.write_public(),
            });
        }
        Ok(())
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

    /// Puts each record of a group that no replica accepted back into the
    /// work list.
    fn requeue_group_posts<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.groups.posts.clear();
        // GRP-392: each sealed record goes again as it was, in the order of
        // its seal. A group that is gone or closed takes none, and a message
        // that no longer waits in the outbox takes none.
        let mut kept = Vec::new();
        let mut dropped = Vec::new();
        let mut sealed = BTreeSet::new();
        for (row, plain) in self.open_ref()?.store.list(GROUP_UNSENT, None)? {
            let plain = Zeroizing::new(plain);
            let Some((order, post)) = read_unsent_row(&plain, row) else {
                dropped.push(row);
                continue;
            };
            let store = &self.open_ref()?.store;
            let is_held = store.get(GROUP, &post.conversation.0)?.is_some();
            let waits = match post.message {
                Some(message) => store.get(OUTBOX, &message.0)?.is_some(),
                None => true,
            };
            if !is_held || !waits || self.group_closed(post.conversation)? {
                dropped.push(row);
                continue;
            }
            if let Some(message) = post.message {
                sealed.insert(message);
            }
            kept.push((order, post));
        }
        if !dropped.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for row in dropped {
                batch.delete(GROUP_UNSENT, row);
            }
            batch.commit()?;
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
        for (stored_at, conversation, message, app) in waiting {
            self.queue_group_post(conversation, Some(message), &app, stored_at, rng)?;
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
fn unsent_row(order: u64, post: &GroupPost) -> Zeroizing<Vec<u8>> {
    let mut value = Zeroizing::new(Vec::with_capacity(UNSENT_HEAD + post.record.len()));
    value.push(UNSENT_VERSION);
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
    value.extend_from_slice(&post.record);
    value
}

/// The first byte of a kept record that names its message. A row of the
/// first form starts with its order, whose first byte is zero.
const UNSENT_VERSION: u8 = 2;

/// The fixed part of a kept record ahead of the record.
const UNSENT_HEAD: usize = 1 + 8 + 16 + 1 + 1 + 32 + 32 + GROUP_REPLICAS * 64 + 1 + 16;

/// The fixed part of a row of the first form, which names no message.
const UNSENT_HEAD_V1: usize = 8 + 16 + 1 + 1 + 32 + 32 + GROUP_REPLICAS * 64;

fn read_unsent_row(plain: &[u8], row: [u8; 16]) -> Option<(u64, GroupPost)> {
    let (body, head) = if plain.first() == Some(&UNSENT_VERSION) {
        (plain.get(1..)?, UNSENT_HEAD - 1)
    } else {
        (plain, UNSENT_HEAD_V1)
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
        },
    ))
}
