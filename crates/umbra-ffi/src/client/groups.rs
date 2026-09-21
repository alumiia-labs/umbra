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

use std::collections::VecDeque;

use umbra_core::{
    group::{state::Group, GROUP_REPLICAS},
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{rand_core::CryptoRng, secret::Secret};
use umbra_wire::group::control::ReplicaRef;
use zeroize::Zeroizing;

use super::Client;
use crate::{ConversationId, Error};

/// The stored form of a group: its roster, its epochs, and its replicas.
pub(super) const GROUP: TableId = TableId(0x12);
/// The group queues that a creator asked for and that no relay named yet.
/// A row holds the `group_id`, the replica index, and the relay.
pub(super) const GROUP_QUEUE: TableId = TableId(0x13);

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

/// The group work that waits for the run of the group queues.
#[derive(Default)]
pub(super) struct GroupQueues {
    pub creations: VecDeque<GroupQueueJob>,
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

        let stored = Self::group_row(&group)?;
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
    pub(super) fn group_of(&self, conversation: ConversationId) -> Result<Group, Error> {
        let store = &self.open_ref()?.store;
        let row = Zeroizing::new(store.get(GROUP, &conversation.0)?.ok_or(Error::NotFound)?);
        let (group_id, stored) = row.split_at_checked(32).ok_or(Error::Integrity)?;
        let group_id: [u8; 32] = group_id.try_into().map_err(|_| Error::Integrity)?;
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
    /// that opens it (`IMP-121`), and then its stored form.
    fn group_row(group: &Group) -> Result<Zeroizing<Vec<u8>>, Error> {
        let stored = group.export().map_err(|_| Error::Malformed)?;
        let mut row = Zeroizing::new(Vec::with_capacity(stored.len().saturating_add(32)));
        row.extend_from_slice(group.group_id());
        row.extend_from_slice(&stored);
        Ok(row)
    }

    /// Writes a group back after a change of it.
    pub(super) fn save_group<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        rng: &mut R,
    ) -> Result<(), Error> {
        let row = Self::group_row(group)?;
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
        Ok(true)
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
