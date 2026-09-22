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

use std::collections::{BTreeMap, VecDeque};

use umbra_core::{
    group::{
        join::{accept_admit, Admitted},
        receive::Outcome,
        roster::Applied,
        state::Group,
        GROUP_REPLICAS,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{group::MemberKeys, hash::sha3_256, rand_core::CryptoRng, secret::Secret};
use umbra_wire::{
    app::{AppKind, AppMessage},
    group::control::{
        ControlType, GroupControl, GroupInvitation, InvitationStage, JoinRecord, ReplicaRef, Role,
    },
};
use zeroize::Zeroizing;

use super::{stored_message, Client, MESSAGE_PREFIX, OUTBOX};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

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
/// The contact behind a member index, for each member that an admin of
/// this device brought in. The roster names no contact, thus a member that
/// another admin added has no row here and the view shows its index alone.
/// A row holds the pairwise conversation, and its owner column names the
/// group.
pub(super) const GROUP_MEMBER: TableId = TableId(0x15);

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
    /// The sealed `GroupQueueRecord`.
    pub record: Vec<u8>,
    /// Whether the record starts an epoch. A `GKEY` follows it at the
    /// replica that accepted it, and never before (`GRP-362`).
    pub is_rotation: bool,
}

/// One `GKEY` at one replica, which moves that replica to the credentials
/// of the epoch this device holds (`GRP-361`, `GRP-363`).
pub struct GroupRekey {
    /// The relay.
    pub relay: [u8; 32],
    /// The group queue at that relay.
    pub group_queue_id: [u8; 32],
    /// The owner credential of that replica.
    pub own: Secret<32>,
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

        let stored = Self::group_row(&group, false)?;
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
        Group::restore(stored, &Secret::new(seed)).map_err(|_| Error::Integrity)
    }

    /// The row of a group: its identifier, thus the row names the seed
    /// that opens it (`IMP-121`), a byte of the state that the group has
    /// at this device, and then its stored form.
    fn group_row(group: &Group, is_closed: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
        let stored = group.export().map_err(|_| Error::Malformed)?;
        let mut row = Zeroizing::new(Vec::with_capacity(stored.len().saturating_add(33)));
        row.extend_from_slice(group.group_id());
        row.push(u8::from(is_closed));
        row.extend_from_slice(&stored);
        Ok(row)
    }

    /// Whether each replica of a group refused its queue (`GRP-210`).
    pub fn group_closed(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = Zeroizing::new(store.get(GROUP, &conversation.0)?.ok_or(Error::NotFound)?);
        Ok(row.get(32) == Some(&1))
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
        let row = Self::group_row(&group, true)?;
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
        let is_closed = self.group_closed(conversation).unwrap_or(false);
        let row = Self::group_row(group, is_closed)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &row, rng)?;
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
        if self.is_group(conversation)? {
            return Err(Error::Malformed);
        }
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::GroupControl,
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
        let held = self.group_of(group)?;
        let own = held
            .roster()
            .member(held.own_index())
            .ok_or(Error::Integrity)?;
        if own.role < Role::Admin {
            return Err(Error::Malformed);
        }
        let admin_roster_pk = own.roster_pk.clone().ok_or(Error::Integrity)?;
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
        let Some(JoinEntry::Waiting {
            creator_roster_pk,
            name,
        }) = self.join_entry(&row)?
        else {
            return Ok(());
        };
        let mut entry = vec![ADMITTED];
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
                    creator_roster_pk,
                    ..
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
                let mut batch = open.store.begin();
                batch.put(GROUP_JOIN, row, Some(from.0), &entry, rng)?;
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
            _ => Ok(()),
        }
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
            Some(JoinEntry::Added { index, .. }) => {
                let snapshot = group.snapshot(&[]).map_err(|_| Error::Malformed)?;
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
        let snapshot = self
            .group_of(conversation)?
            .snapshot(&[])
            .map_err(|_| Error::Malformed)?;
        self.note_member_contact(conversation, index, joiner.from, rng)?;
        let mut entry = vec![ADDED];
        entry.extend_from_slice(&joiner.from.0);
        entry.extend_from_slice(&joiner.group_id);
        entry.extend_from_slice(&index.to_be_bytes());
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
        let conversation = self.conversation_of_group(&joiner.group_id)?;
        let group = self.group_of(conversation)?;
        let body = group
            .admit_for(index, 0, descriptor, now_ms / 1_000)
            .map_err(|_| Error::Malformed)?;
        self.send_pairwise_control(joiner.from, &body, now_ms, rng)?;
        let row = self.join_row(joiner.from, &joiner.group_id)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(GROUP_JOIN, row);
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
            ..
        }) = self.join_entry(&row)?
        else {
            return Err(Error::NotFound);
        };
        let seed = {
            let store = &self.open_ref()?.store;
            let seed_row = store.row_id(TableId::LOCAL_IDENTITY, group_id);
            let seed = Zeroizing::new(
                store
                    .get(TableId::LOCAL_IDENTITY, &seed_row)?
                    .ok_or(Error::Integrity)?,
            );
            let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
            Secret::new(seed)
        };
        let control = GroupControl::parse(&admit)?;
        let invitation = GroupInvitation::parse(control.payload)?;
        let snapshot = umbra_wire::group::control::RosterSnapshot::parse(snapshot)?;
        // GRP-326: the snapshot verifies against the hash of the add and
        // the roster key of the creator, which the offer carried.
        let add_hash = Self::add_hash_of(&invitation, &snapshot)?;
        let admitted = accept_admit(&invitation, &snapshot, &add_hash, &creator_roster_pk, now)
            .map_err(|_| Error::Integrity)?;
        let conversation = self.adopt_group(admitted, &seed, &name, rng)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(GROUP_JOIN, row);
        batch.commit()?;
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
            ADMITTED => {
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
                }
            }
            ASKED => JoinEntry::Asked {
                from,
                group_id,
                record: rest.to_vec(),
            },
            ADDED => JoinEntry::Added {
                from,
                group_id,
                index: u16::from_be_bytes(rest.try_into().map_err(|_| Error::Integrity)?),
            },
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
        rng: &mut R,
    ) -> Result<ConversationId, Error> {
        let name = name.trim();
        if name.len() > GROUP_NAME_MAX {
            return Err(Error::TooLong);
        }
        let group = Group::joined(admitted, seed).map_err(|_| Error::Malformed)?;
        let group_id = *group.group_id();
        // GRP-153: a second admit to a group that this device holds is no
        // group.
        let conversation = self.conversation_of_group(&group_id)?;
        if self.is_group(conversation)? {
            return Err(Error::Malformed);
        }
        let row = Self::group_row(&group, false)?;
        let open = self.open_mut()?;
        let seed_row = open.store.row_id(TableId::LOCAL_IDENTITY, &group_id);
        let mut batch = open.store.begin();
        batch.put(GROUP, conversation.0, None, &row, rng)?;
        batch.put(TableId::LOCAL_IDENTITY, seed_row, None, seed.expose(), rng)?;
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
        self.queue_group_post(conversation, Some(message), app, now_ms, rng)?;
        Ok(message)
    }

    /// Builds the record of one stored message and queues it, when the
    /// group holds both of its queues.
    fn queue_group_post<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: Option<MsgRef>,
        app: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
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
        let write = group.credentials().ok_or(Error::Integrity)?.write_secret();
        // GRP-246: the counter of this device moves with the record, thus
        // the group goes back to the store before the record leaves.
        let record = group
            .post(app, now_ms / 1_000, rng)
            .map_err(|_| Error::Malformed)?;
        self.save_group(conversation, &group, rng)?;
        self.groups.posts.push_back(GroupPost {
            message,
            conversation,
            replicas,
            write,
            record,
            is_rotation: false,
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
        let object = self
            .group_of(conversation)?
            .remove_object(index)
            .map_err(|_| Error::Malformed)?;
        self.post_group_control(conversation, &object, now_ms, rng)?;
        self.apply_own_roster_object(conversation, &object, now_ms, rng)?;
        self.rotate_group(conversation, now_ms, rng)
    }

    /// Leaves a group (`GRP-067`). The member that leaves rotates nothing,
    /// because `GRP-356` bars the index each trigger excludes.
    pub fn leave_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
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
    fn apply_own_roster_object<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        object: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Applied, Error> {
        let mut group = self.group_of(conversation)?;
        let control = GroupControl::parse(object)?;
        let applied = group
            .apply_control(&control, group.own_index(), now_ms / 1_000)
            .map_err(|_| Error::Malformed)?;
        self.save_group(conversation, &group, rng)?;
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
        self.groups.backoff.remove(&conversation);
        if self.group_closed(conversation)? {
            return Ok(());
        }
        let mut group = self.group_of(conversation)?;
        let Some(replicas) = Self::group_replicas_of(&group)? else {
            return Ok(());
        };
        let Ok(rotation) = group.rotate(now_ms / 1_000, rng) else {
            return Ok(());
        };
        self.save_group(conversation, &group, rng)?;
        self.groups.posts.push_back(GroupPost {
            message: None,
            conversation,
            replicas,
            write: rotation.write,
            record: rotation.record,
            is_rotation: true,
        });
        Ok(())
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
            read_pk: credentials.read_public(),
            write_pk: credentials.write_public(),
        }))
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
    fn post_group_control<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::GroupControl,
            msg_id,
            sent_at: now_ms,
            body,
        };
        let mut app = Zeroizing::new(vec![0u8; record.len()]);
        record.encode(&mut app)?;
        self.queue_group_post(conversation, None, &app, now_ms, rng)
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
                from_seq: replicas.cursor(which),
            });
            self.save_group(conversation, &group, rng)?;
        }
        Ok(out)
    }

    /// The next record that waits for the run of the group queues.
    pub fn take_group_post(&mut self) -> Option<GroupPost> {
        self.groups.posts.pop_front()
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
        let mut installed = false;
        if let Ok(Outcome::EpochKey {
            epoch,
            start_slot,
            body,
        }) = &outcome
        {
            installed = group
                .install_epoch_key(*epoch, *start_slot, body, now_ms / 1_000)
                .is_ok();
            if installed {
                // A record of the new epoch that arrived before its key
                // waited; it opens now (`GRP-252`).
                group.retry_held(now_ms / 1_000);
            }
        }
        // The counters and the held records moved, whatever the outcome.
        self.save_group(conversation, &group, rng)?;
        if installed {
            self.queue_rekeys(&group)?;
        }
        let Ok(Outcome::Content { sender, app, .. }) = outcome else {
            return Ok(None);
        };
        let parsed = umbra_wire::app::AppMessage::parse(&app, umbra_wire::app::Channel::Group)?;
        // A roster object moves the roster and is no message (`GRP-318`).
        if parsed.kind == AppKind::GroupControl {
            let Ok(control) = GroupControl::parse(parsed.body) else {
                return Ok(None);
            };
            if group
                .apply_control(&control, sender, now_ms / 1_000)
                .is_ok()
            {
                self.save_group(conversation, &group, rng)?;
            }
            return Ok(None);
        }
        let open = self.open_mut()?;
        let reference = super::msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open
            .store
            .row_id(umbra_core::store::record::TableId::MESSAGE, &natural);
        // WIR-065: the second copy of one record drops at its `msg_id`.
        if open
            .store
            .get(umbra_core::store::record::TableId::MESSAGE, &row)?
            .is_some()
        {
            return Ok(None);
        }
        let plain = stored_message(
            super::INCOMING,
            Delivery::Delivered,
            conversation,
            now_ms,
            &app,
        );
        let mut batch = open.store.begin();
        batch.put(
            umbra_core::store::record::TableId::MESSAGE,
            row,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        batch.commit()?;
        let message = MsgRef(row);
        self.events.push_back(Event::Message {
            conversation,
            message,
        });
        Ok(Some(message))
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
                read_pk: credentials.read_public(),
                write_pk: credentials.write_public(),
            });
        }
        Ok(())
    }

    /// The conversation of a group queue, or none when this device holds
    /// no group with that queue.
    fn conversation_of_queue(
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

    /// Puts each record of a group that no replica accepted back into the
    /// work list.
    fn requeue_group_posts<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.groups.posts.clear();
        let store = &self.open_ref()?.store;
        let mut waiting = Vec::new();
        for (row, _) in store.list(OUTBOX, None)? {
            let Some(plain) = store.get(umbra_core::store::record::TableId::MESSAGE, &row)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            let conversation = super::conversation_of(&plain)?;
            if store.get(GROUP, &conversation.0)?.is_none() {
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
