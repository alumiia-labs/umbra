//! The history sync of Part 7 §7.5 in the store of one device.
//!
//! The device that owns the channels publishes each record that it takes
//! from a contact and each record that it sends. A linked device hands each
//! record that the user composes on it to the owner, which sends it under
//! the same `msg_id` (`DEV-047`, `DEV-048`). Each record names its
//! conversation by the blinded subject of `DEV-226`, which each device of
//! the set derives from the stored contact (`DEV-292`).
//!
//! The sending device is the durable log of the set (`DEV-013`): the body of
//! each published record stays in the store until each peer acknowledges
//! its counter, and a new run sends again each one that no peer
//! acknowledged.

use std::collections::BTreeMap;

use umbra_core::{
    devset::{
        engine::{SyncEngine, Taken},
        roster::{ClaimScope, OwnerClaim, Roster},
        sync::{
            group_subject, restamp_expires_in, IdentityEntry, Origin, SyncedRecord, AUTHOR_PEER,
            AUTHOR_USER, ITEM_CONTACT_NAME, ITEM_DELIVERY, ITEM_GROUP_REKEY, ITEM_GROUP_STATE,
            ITEM_IDENTITY_ENTRY, SCOPE_GROUP, SCOPE_PAIRWISE,
        },
        DeviceId,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    devset::{ControlType, DeviceSetBody},
    AppKind, AppMessage,
};
use zeroize::Zeroizing;

use super::{devices::DEVICE_PEERS, Client};
use crate::{ConversationId, Error, Event, MsgRef};

/// An item of mutable state that the owner of the channels publishes again:
/// its row, its key, its value, its Lamport counter, and its writer
/// (`DEV-308`).
type RelayItem = (u8, Vec<u8>, Vec<u8>, u64, DeviceId);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The stored form of the sync engine.
pub(super) const SYNC_STATE: TableId = TableId(0x24);
/// The body of each published record, by its counter, until each peer
/// acknowledged it.
pub(super) const SYNC_SENT: TableId = TableId(0x25);

const ENGINE_KEY: &[u8] = b"engine";
/// Each synced record of a conversation whose identity entry did not come
/// yet, under a random row: the subject, the order of its arrival, its
/// deadline or 0, whether the user wrote it, then the record (`DEV-294`).
const PAIRWISE_HELD: TableId = TableId(0x51);
/// Each record that the engine took and the store did not take yet, in the
/// commit of the engine (`DEV-013`).
const SYNC_INBOX: TableId = TableId(0x52);
/// The records that a device holds while their entries wait.
const PAIRWISE_HELD_MAX: usize = 1_024;
/// The time that a held record waits for its entry, in seconds.
const PAIRWISE_HELD_AGE: u64 = 30 * 86_400;

/// One record for a sync channel: the conversation of the channel, and the
/// encoded `AppMessage` of kind `0x20`.
pub struct SyncSend {
    /// The sync channel.
    pub peer: ConversationId,
    /// The encoded `AppMessage`.
    pub app: Vec<u8>,
    /// The message of this device that the record hands to the owner, whose
    /// delivery state follows the send of the record.
    pub message: Option<MsgRef>,
}

/// A conversation record that the sync channel gave, for the commit path.
pub(super) struct Synced {
    pub conversation: ConversationId,
    /// The source device and its causal counter (`DEV-015`).
    pub origin: (DeviceId, u64),
    pub app: Vec<u8>,
    pub from_user: bool,
    /// Whether the conversation is a private group (`DEV-296`).
    pub is_group: bool,
    /// The remaining period of a timed record, or zero (`DEV-244`).
    pub expires_in: u32,
}

/// The stored form of a synced record in the inbox: the conversation, the
/// source device, its counter, whether the user wrote it, whether it is of
/// a group, its remaining period, then the record.
fn encode_synced(synced: &Synced) -> Vec<u8> {
    [
        synced.conversation.0.as_slice(),
        &synced.origin.0,
        &synced.origin.1.to_be_bytes(),
        &[u8::from(synced.from_user), u8::from(synced.is_group)],
        &synced.expires_in.to_be_bytes(),
        &synced.app,
    ]
    .concat()
}

fn decode_synced(bytes: &[u8]) -> Option<Synced> {
    Some(Synced {
        conversation: ConversationId(bytes.get(..16)?.try_into().ok()?),
        origin: (
            bytes.get(16..32)?.try_into().ok()?,
            u64::from_be_bytes(bytes.get(32..40)?.try_into().ok()?),
        ),
        from_user: *bytes.get(40)? == 1,
        is_group: *bytes.get(41)? == 1,
        expires_in: u32::from_be_bytes(bytes.get(42..46)?.try_into().ok()?),
        app: bytes.get(46..)?.to_vec(),
    })
}

pub(super) fn counter_key(counter: u64) -> [u8; 8] {
    counter.to_be_bytes()
}

fn counter_ref(counter: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[8..].copy_from_slice(&counter.to_be_bytes());
    out
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The sync channel of each other device, by its `device_id`.
    pub(super) fn peer_channels(&self) -> Result<BTreeMap<DeviceId, ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = BTreeMap::new();
        for (row, value) in store.list(DEVICE_PEERS, None)? {
            let device: DeviceId = value
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            out.insert(device, ConversationId(row));
        }
        Ok(out)
    }

    /// The engine of this device, or none while the set holds this device
    /// alone. A device that joined the roster since the last store becomes
    /// a peer.
    pub(super) fn sync_engine(&self) -> Result<Option<SyncEngine>, Error> {
        let Some(identity) = self.device_identity()? else {
            return Ok(None);
        };
        let Some(roster) = self.roster_bytes()? else {
            return Ok(None);
        };
        let roster = Roster::parse(&roster)?;
        // DEV-308: the channels form a star around the device that owns
        // them, thus a peer is a device with a sync channel to this one.
        let channels = self.peer_channels()?;
        let others: Vec<DeviceId> = roster
            .devices
            .iter()
            .map(|entry| entry.device_id)
            .filter(|device| *device != identity.device_id && channels.contains_key(device))
            .collect();
        // A device whose link the user confirmed takes each record from
        // then on, and its sync channel sends them when it opens. The
        // snapshot holds the records before (`DEV-004`).
        let mut others = others;
        if let Some(pending) = self.pending_peer()? {
            if pending != identity.device_id && !others.contains(&pending) {
                others.push(pending);
            }
        }
        if others.is_empty() {
            return Ok(None);
        }
        let store = &self.open_ref()?.store;
        let row = store.row_id(SYNC_STATE, ENGINE_KEY);
        let stored = store.get(SYNC_STATE, &row)?;
        let is_fresh = stored.is_none();
        let mut engine = match stored {
            Some(bytes) => SyncEngine::restore(&Zeroizing::new(bytes))?,
            // DEV-019: a restored store takes the watermarks of its backup.
            None => {
                let mut fresh = SyncEngine::new(identity.device_id, &[])?;
                self.seed_watermarks(&mut fresh)?;
                fresh
            }
        };
        // A device that left the roster leaves the engine, with its
        // retained records (`DEV-257`).
        let gone: Vec<DeviceId> = engine
            .peers()
            .filter(|peer| !others.contains(peer))
            .copied()
            .collect();
        for device in gone {
            engine.remove_peer(&device);
        }
        for device in others {
            engine.add_peer(device)?;
        }
        // DEV-311: a new device takes the records of its link from the
        // snapshot, and the counter of the existing device starts there.
        if is_fresh {
            if let Some(floor) = self.setting(super::devices::LINK_FLOOR_SETTING)? {
                let device = floor.get(..16).and_then(|id| <[u8; 16]>::try_from(id).ok());
                let counter = floor
                    .get(16..24)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes);
                if let (Some(device), Some(counter)) = (device, counter) {
                    engine.start_peer_at(&device, counter);
                }
            }
        }
        Ok(Some(engine))
    }

    /// The causal counter of this device, or 0 before its first record.
    pub fn sync_counter(&self) -> Result<u64, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SYNC_STATE, ENGINE_KEY);
        Ok(match store.get(SYNC_STATE, &row)? {
            Some(bytes) => SyncEngine::restore(&Zeroizing::new(bytes))?.counter(),
            None => 0,
        })
    }

    pub(super) fn put_engine<R: CryptoRng + ?Sized>(
        &mut self,
        engine: &SyncEngine,
        sent: Option<(u64, &[u8])>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let sent: Vec<(u64, Vec<u8>)> = sent
            .map(|(counter, body)| (counter, body.to_vec()))
            .into_iter()
            .collect();
        self.put_engine_all(engine, &sent, &[], rng).map(|_| ())
    }

    /// Stores the engine and each body that it published, in one commit.
    fn put_engine_all<R: CryptoRng + ?Sized>(
        &mut self,
        engine: &SyncEngine,
        sent: &[(u64, Vec<u8>)],
        inbox: &[Vec<u8>],
        rng: &mut R,
    ) -> Result<Vec<RowId>, Error> {
        let bytes = Zeroizing::new(engine.export()?);
        let open = self.open_mut()?;
        let row = open.store.row_id(SYNC_STATE, ENGINE_KEY);
        let sent_rows: Vec<RowId> = sent
            .iter()
            .map(|(counter, _)| open.store.row_id(SYNC_SENT, &counter_key(*counter)))
            .collect();
        let inbox_rows: Vec<RowId> = inbox
            .iter()
            .map(|value| {
                let digest = umbra_crypto::hash::sha3_256(&[value]);
                open.store.row_id(SYNC_INBOX, &digest)
            })
            .collect();
        let mut batch = open.store.begin();
        batch.put(SYNC_STATE, row, None, &bytes, rng)?;
        for ((counter, body), sent_row) in sent.iter().zip(sent_rows) {
            // The row holds its counter, thus a prune reads it.
            let value = Zeroizing::new([counter_key(*counter).as_slice(), body].concat());
            batch.put(SYNC_SENT, sent_row, None, &value, rng)?;
        }
        for (value, row) in inbox.iter().zip(&inbox_rows) {
            batch.put(SYNC_INBOX, *row, None, &Zeroizing::new(value.clone()), rng)?;
        }
        batch.commit()?;
        Ok(inbox_rows)
    }

    /// The blinded subject of a pairwise conversation (`DEV-226`), or none
    /// for a conversation that is no contact.
    pub(super) fn subject_of(
        &mut self,
        conversation: ConversationId,
    ) -> Result<Option<[u8; 32]>, Error> {
        if let Some(subject) = self.subjects.get(&conversation) {
            return Ok(Some(*subject));
        }
        if self.is_group(conversation)? {
            let group = self.group_of(conversation)?;
            let subject = group_subject(&self.open_ref()?.device_set_key, group.group_id());
            self.subjects.insert(conversation, subject);
            return Ok(Some(subject));
        }
        let open = self.open_ref()?;
        let Some(row) = open.store.get(TableId::CONTACT, &conversation.0)? else {
            return Ok(None);
        };
        let row = Zeroizing::new(row);
        let state = row.get(32..).ok_or(Error::Integrity)?;
        let salt = umbra_core::session::node::stored_contact_salt(state)?;
        let key = self.root_identity()?.pairwise_identity(&salt);
        let open = self.open_ref()?;
        let subject = OwnerClaim::subject(
            &open.device_set_key,
            ClaimScope::Pairwise,
            &key.public().to_bytes(),
        );
        self.subjects.insert(conversation, subject);
        Ok(Some(subject))
    }

    /// The contact conversation that `subject` names on this device.
    pub(super) fn conversation_of_subject(
        &mut self,
        subject: &[u8; 32],
    ) -> Result<Option<ConversationId>, Error> {
        if let Some((conversation, _)) = self.subjects.iter().find(|(_, held)| *held == subject) {
            return Ok(Some(*conversation));
        }
        let peers = self.device_peers()?;
        let rows: Vec<RowId> = self
            .open_ref()?
            .store
            .list(TableId::CONTACT, None)?
            .into_iter()
            .map(|(row, plain)| {
                drop(Zeroizing::new(plain));
                row
            })
            .collect();
        let groups = self.group_conversations()?;
        let candidates = rows.into_iter().map(ConversationId).chain(groups);
        for conversation in candidates.collect::<Vec<_>>() {
            if peers.contains(&conversation) {
                continue;
            }
            if self.subject_of(conversation)?.as_ref() == Some(subject) {
                return Ok(Some(conversation));
            }
        }
        Ok(None)
    }

    /// Whether a record of the user in `conversation` goes to the owner of
    /// the channels, since this device owns none (`DEV-287`).
    pub fn hands_off(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(!self.owns_channels()?
            && !self.is_device_peer(conversation)?
            && !self.is_group(conversation)?)
    }

    /// Publishes one conversation record to each device of the set
    /// (`DEV-268`). A set with this device alone publishes nothing.
    pub fn publish_sync<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        app: &[u8],
        from_user: bool,
        message: Option<MsgRef>,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(());
        };
        let Some(subject) = self.subject_of(conversation)? else {
            return Ok(());
        };
        let is_group = self.is_group(conversation)?;
        let channel = if is_group {
            umbra_wire::app::Channel::Group
        } else {
            umbra_wire::app::Channel::Pairwise
        };
        let parsed = AppMessage::parse(app, channel)?;
        // A request for an epoch and its answer belong to the reader of the
        // group, and each device reads the group itself (GRP-343).
        let is_group_request = matches!(parsed.kind, AppKind::KeyRequest | AppKind::KeySupply);
        if !umbra_core::devset::engine::carried_on_sync(parsed.kind) || is_group_request {
            return Ok(());
        }
        let origin = Origin {
            scope: if is_group {
                SCOPE_GROUP
            } else {
                SCOPE_PAIRWISE
            },
            subject,
            author: if from_user { AUTHOR_USER } else { AUTHOR_PEER },
        };
        // DEV-242: a timed record carries the rest of its period.
        let expires_in = self.expires_in_of(conversation, app, now)?;
        let counter = engine.counter().saturating_add(1);
        let published = engine.publish(app, origin, counter_ref(counter), expires_in, now)?;
        self.put_engine(&engine, Some((published.counter, &published.body)), rng)?;
        let channels = self.peer_channels()?;
        let mut first = message;
        for peer in engine.peers() {
            if let Some(channel) = channels.get(peer) {
                self.queue_sync(*channel, &published.body, first.take(), rng)?;
            }
        }
        Ok(())
    }

    /// Publishes the identity entry of each contact that the engine holds
    /// none of, at the start of a run: an entry that a run lost before it
    /// left goes now, and a linked device holds each conversation
    /// (`DEV-011`, `DEV-294`).
    pub fn ensure_identity_entries<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? {
            return Ok(());
        }
        let Some(engine) = self.sync_engine()? else {
            return Ok(());
        };
        if engine.peers().next().is_none() {
            return Ok(());
        }
        let groups = self.group_conversations()?;
        for conversation in self.conversations()? {
            if groups.contains(&conversation) {
                continue;
            }
            let Some(subject) = self.subject_of(conversation)? else {
                continue;
            };
            if !engine.holds_mutable(ITEM_IDENTITY_ENTRY, &subject) {
                self.publish_identity_entry(conversation, rng)?;
            }
        }
        Ok(())
    }

    /// Keeps a synced record of a conversation whose identity entry did not
    /// come yet (`DEV-294`).
    fn hold_pairwise_record<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        app: &[u8],
        from_user: bool,
        expires_in: u32,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let order = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
            });
        let at = if expires_in > 0 {
            umbra_core::devset::edits::Deadline::from_sync(now, expires_in).at
        } else {
            0
        };
        let open = self.open_mut()?;
        if open.store.list(PAIRWISE_HELD, None)?.len() >= PAIRWISE_HELD_MAX {
            return Ok(());
        }
        // One record holds one row, thus a record that comes again takes
        // no second place.
        let digest = umbra_crypto::hash::sha3_256(&[subject.as_slice(), app]);
        let row = open.store.row_id(PAIRWISE_HELD, &digest);
        let value = Zeroizing::new(
            [
                subject.as_slice(),
                &order.to_be_bytes(),
                &at.to_be_bytes(),
                &[u8::from(from_user)],
                app,
            ]
            .concat(),
        );
        let mut batch = open.store.begin();
        batch.put(PAIRWISE_HELD, row, None, &value, rng)?;
        Ok(batch.commit()?)
    }

    /// Stores the held records of each conversation that this device holds
    /// by now, at the start of a run, and drops each one past
    /// `PAIRWISE_HELD_AGE` (`DEV-294`).
    pub fn replay_held_pairwise<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), Error> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
            });
        let mut subjects = std::collections::BTreeSet::new();
        let mut old = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(PAIRWISE_HELD, None)? {
            let plain = Zeroizing::new(plain);
            let order = plain
                .get(32..40)
                .and_then(|bytes| bytes.try_into().ok())
                .map_or(0, u64::from_be_bytes);
            if now_ns.saturating_sub(order) / 1_000_000_000 > PAIRWISE_HELD_AGE {
                old.push(row);
                continue;
            }
            if let Some(subject) = plain
                .get(..32)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            {
                subjects.insert(subject);
            }
        }
        if !old.is_empty() {
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for row in old {
                batch.delete(PAIRWISE_HELD, row);
            }
            batch.commit()?;
        }
        for subject in subjects {
            if let Some(conversation) = self.conversation_of_subject(&subject)? {
                self.replay_pairwise_records(&subject, conversation, rng)?;
            }
        }
        Ok(())
    }

    /// Stores each held record of a conversation whose identity entry came,
    /// in order.
    fn replay_pairwise_records<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut held: Vec<(u64, RowId, super::Record)> = Vec::new();
        let now = super::unix_now_seconds();
        for (row, plain) in self.open_ref()?.store.list(PAIRWISE_HELD, None)? {
            let plain = Zeroizing::new(plain);
            if plain.get(..32) != Some(subject.as_slice()) {
                continue;
            }
            let field = |range: core::ops::Range<usize>| plain.get(range).ok_or(Error::Integrity);
            let order =
                u64::from_be_bytes(field(32..40)?.try_into().map_err(|_| Error::Integrity)?);
            let at = u64::from_be_bytes(field(40..48)?.try_into().map_err(|_| Error::Integrity)?);
            let from_user = field(48..49)? == [1];
            let app = plain.get(49..).ok_or(Error::Integrity)?.to_vec();
            // A timed record whose period ended stays gone (DEV-210).
            if at != 0 && at <= now {
                held.push((
                    order,
                    row,
                    super::Record {
                        conversation,
                        app: Vec::new(),
                        from_user,
                        synced: true,
                        expires_in: 0,
                    },
                ));
                continue;
            }
            let expires_in = if at == 0 {
                0
            } else {
                u32::try_from(at.saturating_sub(now)).unwrap_or(u32::MAX)
            };
            held.push((
                order,
                row,
                super::Record {
                    conversation,
                    app,
                    from_user,
                    synced: true,
                    expires_in,
                },
            ));
        }
        if held.is_empty() {
            return Ok(());
        }
        held.sort_by_key(|(order, _, _)| *order);
        let rows: Vec<RowId> = held.iter().map(|(_, row, _)| *row).collect();
        let records: Vec<super::Record> = held
            .into_iter()
            .map(|(_, _, record)| record)
            .filter(|record| !record.app.is_empty())
            .collect();
        if !records.is_empty() {
            self.commit_records(&[], &records, now.saturating_mul(1_000), rng)?;
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in rows {
            batch.delete(PAIRWISE_HELD, row);
        }
        Ok(batch.commit()?)
    }

    /// Publishes one item of mutable state to each device of the set
    /// (`DEV-197`).
    pub(super) fn publish_mutable<R: CryptoRng + ?Sized>(
        &mut self,
        item: u8,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(());
        };
        let counter = engine.counter().saturating_add(1);
        let published =
            engine.publish_mutable(item, key, value, counter_ref(counter), unix_now())?;
        self.put_engine(&engine, Some((published.counter, &published.body)), rng)?;
        let channels = self.peer_channels()?;
        for peer in engine.peers() {
            if let Some(channel) = channels.get(peer) {
                self.queue_sync(*channel, &published.body, None, rng)?;
            }
        }
        Ok(())
    }

    /// Publishes the entry of the local identity table of a new contact, thus
    /// each device of the set holds its conversation (`DEV-011`, `DEV-294`).
    pub fn publish_identity_entry<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.is_device_peer(conversation)? {
            return Ok(());
        }
        let Some(subject) = self.subject_of(conversation)? else {
            return Ok(());
        };
        let row = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::CONTACT, &conversation.0)?
                .ok_or(Error::NotFound)?,
        );
        let entry = IdentityEntry {
            salt: umbra_core::session::node::stored_contact_salt(
                row.get(32..).ok_or(Error::Integrity)?,
            )?,
            conversation: row
                .get(..32)
                .and_then(|key| key.try_into().ok())
                .ok_or(Error::Integrity)?,
        };
        self.publish_mutable(ITEM_IDENTITY_ENTRY, &subject, &entry.encode(), rng)
    }

    /// Publishes the delivery state of a message that this device sent, to
    /// each other device of the set (`DEV-304`): a message that another
    /// device handed to it, and one of its own, whose copy the other devices
    /// hold.
    pub(super) fn publish_delivery<R: CryptoRng + ?Sized>(
        &mut self,
        message: &RowId,
        delivery: crate::Delivery,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? {
            return Ok(());
        }
        self.publish_mutable(ITEM_DELIVERY, message, &[delivery as u8], rng)
    }

    /// Takes the delivery state of a message that the owner of the channels
    /// sent. A state goes up only, and a failure ends a message that no
    /// receipt reached.
    fn apply_delivery_item<R: CryptoRng + ?Sized>(
        &mut self,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.owns_channels()? {
            return Ok(());
        }
        let row: RowId = key.try_into().map_err(|_| Error::Malformed)?;
        let reported = value
            .first()
            .copied()
            .and_then(crate::Delivery::from_byte)
            .ok_or(Error::Malformed)?;
        let open = self.open_mut()?;
        let Some(plain) = open.store.get(TableId::MESSAGE, &row)? else {
            return Ok(());
        };
        let mut plain = Zeroizing::new(plain);
        let info = super::info_of(&plain)?;
        let moves = match reported {
            crate::Delivery::Failed => {
                matches!(
                    info.delivery,
                    crate::Delivery::Queued | crate::Delivery::Accepted
                )
            }
            _ => info.delivery.is_below(reported),
        };
        if !info.outgoing || !moves {
            return Ok(());
        }
        let conversation = super::conversation_of(&plain)?;
        *plain.get_mut(1).ok_or(Error::Integrity)? = reported as u8;
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.commit()?;
        self.events.push_back(Event::Delivery {
            message: MsgRef(row),
            delivery: reported,
        });
        Ok(())
    }

    /// Publishes the name that the user gave a contact.
    pub(super) fn publish_contact_name<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        name: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(subject) = self.subject_of(conversation)? else {
            return Ok(());
        };
        self.publish_mutable(ITEM_CONTACT_NAME, &subject, name.as_bytes(), rng)
    }

    /// Applies one item of mutable state that won (`DEV-270`). An entry of
    /// the local identity table makes the conversation of a contact whose
    /// channel another device owns (`DEV-294`).
    fn apply_mutable<R: CryptoRng + ?Sized>(
        &mut self,
        item: u8,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if item == ITEM_DELIVERY {
            return self.apply_delivery_item(key, value, rng);
        }
        if item == umbra_core::devset::sync::ITEM_BLOCK {
            return self.apply_block_item(key, value, rng);
        }
        let subject: [u8; 32] = key.try_into().map_err(|_| Error::Malformed)?;
        match item {
            ITEM_IDENTITY_ENTRY => {
                let entry = IdentityEntry::parse(value)?;
                // The subject must name the salt, thus a peer names no
                // conversation of another identity.
                let pairwise = self.root_identity()?.pairwise_identity(&entry.salt);
                let open = self.open_mut()?;
                let named = OwnerClaim::subject(
                    &open.device_set_key,
                    ClaimScope::Pairwise,
                    &pairwise.public().to_bytes(),
                );
                if named != subject {
                    return Err(Error::Integrity);
                }
                let row = open.store.row_id(TableId::CONTACT, &entry.conversation);
                if open.store.get(TableId::CONTACT, &row)?.is_none() {
                    let state = umbra_core::session::node::shadow_contact_state(&entry.salt);
                    let plain = Zeroizing::new([entry.conversation.as_slice(), &state].concat());
                    let mut batch = open.store.begin();
                    batch.put(TableId::CONTACT, row, None, &plain, rng)?;
                    batch.commit()?;
                    self.subjects.insert(ConversationId(row), subject);
                    self.events.push_back(Event::Conversations);
                }
                // DEV-294: each record that came before its entry takes its
                // place now, and one that an earlier try left too.
                self.replay_pairwise_records(&subject, ConversationId(row), rng)?;
            }
            ITEM_CONTACT_NAME => {
                let name = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
                if let Some(conversation) = self.conversation_of_subject(&subject)? {
                    self.apply_contact_name(conversation, name, rng)?;
                    self.events.push_back(Event::Conversations);
                }
            }
            ITEM_GROUP_STATE => self.on_group_state_item(subject, value)?,
            super::alerts::ITEM_ALERT => self.apply_alert_item(&subject, value, rng)?,
            super::drafts::ITEM_DRAFT => self.apply_draft_item(&subject, value, rng)?,
            super::ITEM_READ_MARKER | super::ITEM_VERIFICATION => {
                self.apply_converged_item(item, &subject, value, rng)?
            }
            ITEM_GROUP_REKEY => {
                self.on_group_rekey_item(subject, value, unix_now() * 1_000, rng)?
            }
            // An item that this build does not apply changes nothing.
            _ => {}
        }
        Ok(())
    }

    pub(super) fn queue_sync<R: CryptoRng + ?Sized>(
        &mut self,
        peer: ConversationId,
        body: &[u8],
        message: Option<MsgRef>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::DeviceSet,
            msg_id,
            sent_at: 0,
            body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        self.sync_out.push_back(SyncSend { peer, app, message });
        Ok(())
    }

    /// Whether a peer handed this record to this device. That peer
    /// publishes it, thus its send here publishes nothing.
    pub fn was_handed(&mut self, message: &MsgRef) -> bool {
        self.synced_out.remove(message)
    }

    /// The next record for a sync channel.
    pub fn take_sync_send(&mut self) -> Option<SyncSend> {
        self.sync_out.pop_front()
    }

    /// Each sync acknowledgment that is due at `now` (`DEV-056`, `DEV-057`).
    pub fn queue_sync_acks<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(());
        };
        let due = engine.acknowledgments(now)?;
        if due.is_empty() {
            return Ok(());
        }
        self.put_engine(&engine, None, rng)?;
        let channels = self.peer_channels()?;
        for (peer, body) in due {
            if let Some(channel) = channels.get(&peer) {
                self.queue_sync(*channel, &body, None, rng)?;
            }
        }
        Ok(())
    }

    /// Sends the roster epoch that this device holds to each other device
    /// of the set, as a control record (`DEV-176`). A peer takes an epoch
    /// that follows its own and drops the others.
    pub fn publish_roster<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let Some(roster) = self.roster_bytes()? else {
            return Ok(());
        };
        let body = DeviceSetBody::Control {
            control_type: ControlType::RosterEpoch,
            payload: &roster,
        };
        let mut encoded = vec![0u8; roster.len().saturating_add(16)];
        let used = body.encode(&mut encoded)?;
        encoded.truncate(used);
        let channels: Vec<ConversationId> = self.peer_channels()?.into_values().collect();
        for channel in channels {
            self.queue_sync(channel, &encoded, None, rng)?;
        }
        Ok(())
    }

    /// Starts the resend of each record that a peer did not acknowledge, at
    /// the start of a run (`DEV-072`). [`Client::resend_one`] paces it. A
    /// peer takes a record once (`DEV-025`). The roster goes again too, since
    /// a control record takes no resend of its own.
    pub fn start_sync_resend<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.publish_roster(rng)?;
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(());
        };
        let channels = self.peer_channels()?;
        let peers: Vec<DeviceId> = engine.peers().copied().collect();
        for peer in peers.iter().filter(|peer| channels.contains_key(*peer)) {
            engine.new_queue(peer);
        }
        self.put_engine(&engine, None, rng)
    }

    /// Queues the next record of a resend, one at each call, thus a resend
    /// is no burst (`DEV-073`, `DEV-074`). The result is whether one went.
    pub fn resend_one<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(false);
        };
        if !engine.resending() {
            return Ok(false);
        }
        let channels = self.peer_channels()?;
        let peers: Vec<DeviceId> = engine.peers().copied().collect();
        for peer in peers {
            let Some(channel) = channels.get(&peer).copied() else {
                continue;
            };
            let Some((_, counter)) = engine.next_resend(&peer) else {
                continue;
            };
            let store = &self.open_ref()?.store;
            let row = store.row_id(SYNC_SENT, &counter_key(counter));
            let body = store
                .get(SYNC_SENT, &row)?
                .map(|value| value.get(8..).map(<[u8]>::to_vec))
                .unwrap_or_default();
            self.put_engine(&engine, None, rng)?;
            if let Some(body) = body {
                if let Some(body) = self.restamped(body, now)? {
                    self.queue_sync(channel, &body, None, rng)?;
                }
            }
            return Ok(true);
        }
        self.put_engine(&engine, None, rng)?;
        Ok(false)
    }

    /// Takes the sync bodies of each peer that a commit gave: the records
    /// that go into their conversations, and the acknowledgments that end a
    /// resend. The engine state commits here.
    pub(super) fn take_sync_bodies<R: CryptoRng + ?Sized>(
        &mut self,
        bodies: Vec<(ConversationId, Vec<u8>)>,
        now: u64,
        rng: &mut R,
    ) -> Result<(Vec<Synced>, Vec<RowId>), Error> {
        let Some(mut engine) = self.sync_engine()? else {
            return Ok((Vec::new(), Vec::new()));
        };
        let devices: BTreeMap<ConversationId, DeviceId> = self
            .peer_channels()?
            .into_iter()
            .map(|(device, channel)| (channel, device))
            .collect();
        let mut out = Vec::new();
        // DEV-308: the device that owns the channels relays what one peer
        // publishes to each peer, and a peer drops its own record when the
        // relay brings it back.
        let relays = self.owns_channels()? && engine.peers().count() > 1;
        let mut relay_records: Vec<(Origin, Vec<u8>, u32)> = Vec::new();
        let mut relay_items: Vec<RelayItem> = Vec::new();
        // DEV-075: a record past `SYNC_MAX_AGE` waits for no resend.
        let floor = engine.retained_floor();
        engine.expire(now);
        let mut acked = engine.retained_floor() != floor;
        for (channel, body) in bodies {
            let Some(source) = devices.get(&channel) else {
                continue;
            };
            // DEV-273: a record that does not name its channel changes
            // nothing, and it ends no batch.
            match engine.receive(source, &body, now) {
                Ok(Taken::Record {
                    origin,
                    counter,
                    inner,
                    expires_in,
                }) => {
                    if relays {
                        relay_records.push((origin, inner.clone(), expires_in));
                    } else if self.is_own_echo(&origin, &inner)? {
                        continue;
                    }
                    if let Some(conversation) = self.conversation_of_subject(&origin.subject)? {
                        out.push(Synced {
                            conversation,
                            origin: (*source, counter),
                            app: inner,
                            from_user: origin.author == AUTHOR_USER,
                            is_group: origin.scope == SCOPE_GROUP,
                            expires_in,
                        });
                    } else if origin.scope == SCOPE_GROUP {
                        // DEV-299: the state of the group is on its way on
                        // the chunk path, and its records wait for it.
                        self.hold_group_record(&origin.subject, &inner, expires_in, now, rng)?;
                    } else {
                        // DEV-294: the identity entry of the conversation
                        // comes as an item, and it can come after a record.
                        self.hold_pairwise_record(
                            &origin.subject,
                            &inner,
                            origin.author == AUTHOR_USER,
                            expires_in,
                            now,
                            rng,
                        )?;
                    }
                }
                Ok(Taken::Acknowledged) => acked = true,
                Ok(Taken::Mutable {
                    item,
                    key,
                    value,
                    lamport,
                    writer,
                }) => {
                    if relays {
                        relay_items.push((item, key.clone(), value.clone(), lamport, writer));
                    }
                    // An item that does not apply ends no batch.
                    let _ = self.apply_mutable(item, &key, &value, rng);
                }
                // An epoch that does not verify changes nothing.
                Ok(Taken::Control {
                    control_type: ControlType::RosterEpoch,
                    payload,
                }) if self.apply_roster(&payload, rng).unwrap_or(false) => {
                    self.events.push_back(Event::Conversations);
                }
                // DEV-238: the object of a peer waits for its fetch.
                Ok(Taken::Control {
                    control_type: ControlType::CatchUpDescriptor,
                    payload,
                }) => self.keep_catch_up(channel, &payload, rng)?,
                _ => {}
            }
        }
        // DEV-308: each peer takes each counter of this device, thus the
        // relay goes to each peer, the source too. An item keeps the Lamport
        // counter of its write, thus its echo supersedes no later write of
        // the source. The relays commit with the counters that the source
        // took, thus a fault between the two loses no relay.
        let mut relayed: Vec<(u64, Vec<u8>)> = Vec::new();
        for (origin, inner, expires_in) in relay_records {
            let counter = engine.counter().saturating_add(1);
            if let Ok(published) =
                engine.publish(&inner, origin, counter_ref(counter), expires_in, now)
            {
                relayed.push((published.counter, published.body));
            }
        }
        for (item, key, value, lamport, writer) in relay_items {
            let counter = engine.counter().saturating_add(1);
            if let Ok(published) = engine.relay_mutable(
                item,
                &key,
                &value,
                lamport,
                writer,
                counter_ref(counter),
                now,
            ) {
                relayed.push((published.counter, published.body));
            }
        }
        // DEV-013: the records that the engine took wait in the inbox, in
        // the commit of the engine, until the caller stores them. A crash
        // between the two loses no record: the inbox gives it again.
        let inbox: Vec<Vec<u8>> = out.iter().map(encode_synced).collect();
        let inbox_rows = self.put_engine_all(&engine, &relayed, &inbox, rng)?;
        for (_, body) in &relayed {
            self.queue_to_peers(&engine, body, rng)?;
        }
        if acked {
            let below = engine.retained_floor().saturating_sub(1);
            self.prune_sync_sent(below.max(engine.acked_by_all()))?;
        }
        self.keep_history_holes(&engine, now, rng)?;
        Ok((out, inbox_rows))
    }

    /// Drops the inbox rows of records that the store took.
    pub(super) fn drop_sync_inbox(&mut self, rows: &[RowId]) -> Result<(), Error> {
        if rows.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in rows {
            batch.delete(SYNC_INBOX, *row);
        }
        Ok(batch.commit()?)
    }

    /// The records that an earlier run took from a sync channel and did
    /// not store, with their rows (`DEV-013`).
    pub(super) fn sync_inbox(&self) -> Result<(Vec<Synced>, Vec<RowId>), Error> {
        let mut out = Vec::new();
        let mut rows = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(SYNC_INBOX, None)? {
            let plain = Zeroizing::new(plain);
            rows.push(row);
            if let Some(synced) = decode_synced(&plain) {
                out.push(synced);
            }
        }
        Ok((out, rows))
    }

    /// Queues one body to each peer of the engine.
    fn queue_to_peers<R: CryptoRng + ?Sized>(
        &mut self,
        engine: &SyncEngine,
        body: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let channels = self.peer_channels()?;
        for peer in engine.peers() {
            if let Some(channel) = channels.get(peer) {
                self.queue_sync(*channel, body, None, rng)?;
            }
        }
        Ok(())
    }

    /// Whether a record that the owner of the channels relayed is one that
    /// this device published: its body waits in `SYNC_SENT` until the owner
    /// acknowledges it, and the relay comes before that acknowledgment
    /// (`DEV-308`).
    fn is_own_echo(&self, origin: &Origin, inner: &[u8]) -> Result<bool, Error> {
        for (_, value) in self.open_ref()?.store.list(SYNC_SENT, None)? {
            let value = Zeroizing::new(value);
            let Some(Ok(record)) = value.get(8..).map(SyncedRecord::parse) else {
                continue;
            };
            if record.origin == *origin && record.inner == inner {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A body for a resend at `now`: a timed record carries the period that
    /// remains then (`DEV-243`), and one whose period ended goes nowhere.
    pub(super) fn restamped(
        &mut self,
        mut body: Vec<u8>,
        now: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let (subject, inner) = match SyncedRecord::parse(&body) {
            Ok(record) if record.context.expires_in > 0 => {
                (record.origin.subject, Zeroizing::new(record.inner.to_vec()))
            }
            _ => return Ok(Some(body)),
        };
        let Some(conversation) = self.conversation_of_subject(&subject)? else {
            return Ok(None);
        };
        let expires_in = self.expires_in_of(conversation, &inner, now)?;
        if expires_in == 0 {
            return Ok(None);
        }
        restamp_expires_in(&mut body, expires_in)?;
        Ok(Some(body))
    }

    /// Drops the body of each timed record whose period ended, thus no
    /// resend holds it (`DEV-211`).
    pub(super) fn drop_sync_sent_of(
        &mut self,
        due: &[(ConversationId, MsgRef)],
    ) -> Result<(), Error> {
        let mut gone = Vec::new();
        for (row, value) in self.open_ref()?.store.list(SYNC_SENT, None)? {
            let value = Zeroizing::new(value);
            let Some(Ok(record)) = value.get(8..).map(SyncedRecord::parse) else {
                continue;
            };
            if record.context.expires_in == 0 {
                continue;
            }
            let Some(conversation) = self.conversation_of_subject(&record.origin.subject)? else {
                continue;
            };
            let channel = if record.origin.scope == SCOPE_GROUP {
                umbra_wire::app::Channel::Group
            } else {
                umbra_wire::app::Channel::Pairwise
            };
            let Ok(parsed) = AppMessage::parse(record.inner, channel) else {
                continue;
            };
            let open = self.open_ref()?;
            let reference = super::msg_ref(&open.device_set_key, &parsed.msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let message = MsgRef(open.store.row_id(TableId::MESSAGE, &natural));
            if due.contains(&(conversation, message)) {
                gone.push(row);
            }
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in gone {
            batch.delete(SYNC_SENT, row);
        }
        Ok(batch.commit()?)
    }

    /// Drops the body of each record that each peer acknowledged.
    fn prune_sync_sent(&mut self, acked: u64) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut gone = Vec::new();
        for (row, value) in open.store.list(SYNC_SENT, None)? {
            let counter: [u8; 8] = value
                .get(..8)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            if u64::from_be_bytes(counter) <= acked {
                gone.push(row);
            }
        }
        let mut batch = open.store.begin();
        for row in gone {
            batch.delete(SYNC_SENT, row);
        }
        Ok(batch.commit()?)
    }
}
