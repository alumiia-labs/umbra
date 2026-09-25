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
        sync::{Origin, AUTHOR_PEER, AUTHOR_USER, SCOPE_PAIRWISE},
        DeviceId,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{AppKind, AppMessage};
use zeroize::Zeroizing;

use super::{devices::DEVICE_PEERS, Client};
use crate::{ConversationId, Error, MsgRef};

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
    fn sync_engine(&self) -> Result<Option<SyncEngine>, Error> {
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
        if others.is_empty() {
            return Ok(None);
        }
        let store = &self.open_ref()?.store;
        let row = store.row_id(SYNC_STATE, ENGINE_KEY);
        let mut engine = match store.get(SYNC_STATE, &row)? {
            Some(bytes) => SyncEngine::restore(&Zeroizing::new(bytes))?,
            None => SyncEngine::new(identity.device_id, &[])?,
        };
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
        for row in rows {
            let conversation = ConversationId(row);
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
        let parsed = AppMessage::parse(app, umbra_wire::app::Channel::Pairwise)?;
        if !umbra_core::devset::engine::carried_on_sync(parsed.kind) {
            return Ok(());
        }
        let origin = Origin {
            scope: SCOPE_PAIRWISE,
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

    /// Starts the resend of each record that a peer did not acknowledge, at
    /// the start of a run (`DEV-072`). [`Client::resend_one`] paces it. A
    /// peer takes a record once (`DEV-025`).
    pub fn start_sync_resend<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
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
                        });
                    }
                }
                Ok(Taken::Acknowledged) => acked = true,
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
