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
            group_subject, IdentityEntry, Origin, AUTHOR_PEER, AUTHOR_USER, ITEM_CONTACT_NAME,
            ITEM_DELIVERY, ITEM_GROUP_REKEY, ITEM_GROUP_STATE, ITEM_IDENTITY_ENTRY, SCOPE_GROUP,
            SCOPE_PAIRWISE,
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
    pub app: Vec<u8>,
    pub from_user: bool,
    /// Whether the conversation is a private group (`DEV-296`).
    pub is_group: bool,
}

fn counter_key(counter: u64) -> [u8; 8] {
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
        let others: Vec<DeviceId> = roster
            .devices
            .iter()
            .map(|entry| entry.device_id)
            .filter(|device| *device != identity.device_id)
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
        let mut engine = match store.get(SYNC_STATE, &row)? {
            Some(bytes) => SyncEngine::restore(&Zeroizing::new(bytes))?,
            None => SyncEngine::new(identity.device_id, &[])?,
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
        Ok(Some(engine))
    }

    fn put_engine<R: CryptoRng + ?Sized>(
        &mut self,
        engine: &SyncEngine,
        sent: Option<(u64, &[u8])>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let bytes = Zeroizing::new(engine.export()?);
        let open = self.open_mut()?;
        let row = open.store.row_id(SYNC_STATE, ENGINE_KEY);
        let sent_row = sent.map(|(counter, _)| open.store.row_id(SYNC_SENT, &counter_key(counter)));
        let mut batch = open.store.begin();
        batch.put(SYNC_STATE, row, None, &bytes, rng)?;
        if let (Some((counter, body)), Some(sent_row)) = (sent, sent_row) {
            // The row holds its counter, thus a prune reads it.
            let value = [counter_key(counter).as_slice(), body].concat();
            batch.put(SYNC_SENT, sent_row, None, &value, rng)?;
        }
        Ok(batch.commit()?)
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
    fn conversation_of_subject(
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
        let counter = engine.counter().saturating_add(1);
        let published = engine.publish(app, origin, counter_ref(counter), 0, now)?;
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
            }
            ITEM_CONTACT_NAME => {
                let name = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
                if let Some(conversation) = self.conversation_of_subject(&subject)? {
                    self.apply_contact_name(conversation, name, rng)?;
                    self.events.push_back(Event::Conversations);
                }
            }
            ITEM_GROUP_STATE => self.on_group_state_item(subject, value)?,
            ITEM_GROUP_REKEY => {
                self.on_group_rekey_item(subject, value, unix_now() * 1_000, rng)?
            }
            // An item that this build does not apply changes nothing.
            _ => {}
        }
        Ok(())
    }

    fn queue_sync<R: CryptoRng + ?Sized>(
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
    pub fn resend_one<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<bool, Error> {
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
                self.queue_sync(channel, &body, None, rng)?;
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
    ) -> Result<Vec<Synced>, Error> {
        let Some(mut engine) = self.sync_engine()? else {
            return Ok(Vec::new());
        };
        let devices: BTreeMap<ConversationId, DeviceId> = self
            .peer_channels()?
            .into_iter()
            .map(|(device, channel)| (channel, device))
            .collect();
        let mut out = Vec::new();
        let mut acked = false;
        for (channel, body) in bodies {
            let Some(source) = devices.get(&channel) else {
                continue;
            };
            // DEV-273: a record that does not name its channel changes
            // nothing, and it ends no batch.
            match engine.receive(source, &body, now) {
                Ok(Taken::Record { origin, inner, .. }) => {
                    if let Some(conversation) = self.conversation_of_subject(&origin.subject)? {
                        out.push(Synced {
                            conversation,
                            app: inner,
                            from_user: origin.author == AUTHOR_USER,
                            is_group: origin.scope == SCOPE_GROUP,
                        });
                    } else if origin.scope == SCOPE_GROUP {
                        // DEV-299: the state of the group is on its way on
                        // the chunk path, and its records wait for it.
                        self.hold_group_record(&origin.subject, &inner, rng)?;
                    }
                }
                Ok(Taken::Acknowledged) => acked = true,
                Ok(Taken::Mutable { item, key, value }) => {
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
                _ => {}
            }
        }
        self.put_engine(&engine, None, rng)?;
        if acked {
            self.prune_sync_sent(engine.acked_by_all())?;
        }
        Ok(out)
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
