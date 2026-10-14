//! The deletion for the devices of one user (Part 7 §7.5.7, `DEV-126`). A
//! "delete for me" removes the message on this device and asks each other
//! device of the set to remove it too, with a `Delete` record of scope
//! `0x01` on the sync channel (`WIR-084`). The other party keeps its copy.
//!
//! After a restore the other devices send each deletion again, and one
//! that postdates the backup would remove a message that the restore
//! brought back. Those wait, the view shows their count, and the user
//! confirms them (`DEV-117`, `DEV-118`). Each device counts the deletions
//! of each other device since the last roster epoch, which the removal of
//! that device shows (`DEV-119`, `DEV-120`).

use umbra_core::{
    devset::{roster::Roster, DeviceId},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    edit::{DeleteBody, DeleteScope, DELETE_BATCH_MAX},
    AppKind, AppMessage, Channel,
};
use zeroize::Zeroizing;

use super::{conversation_of, msg_ref, sync::Synced, Client, MESSAGE_PREFIX};
use crate::{ConversationId, Error, Event, MsgRef};

/// Each message that a deletion of another device names after a restore,
/// by its row, with its conversation. It waits for the user (`DEV-118`).
const HELD_DELETIONS: TableId = TableId(0x4D);
/// A restore made this store, thus the deletions of the other devices wait.
pub(super) const HOLDS_DELETIONS: &[u8] = b"restore-holds-deletions";
/// The roster epoch and the count of the deletions of each other device.
const DELETIONS_FROM: &[u8] = b"deletions-from/";

fn count_key(device: &DeviceId) -> Vec<u8> {
    [DELETIONS_FROM, device.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Asks each other device of the set to remove `message`. The caller
    /// removes it on this device after this call, since the record names
    /// the message by its raw `msg_id`.
    pub fn publish_own_deletion<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (conversation, target) = self.own_target(message)?;
        self.publish_own_targets(conversation, vec![target], now_ms, rng)
    }

    /// The conversation of `message` and its raw `msg_id`, which a deletion
    /// names. A row that does not parse, as a placeholder, is `Malformed`.
    fn own_target(&self, message: &MsgRef) -> Result<(ConversationId, [u8; 16]), Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Pairwise)
            .or_else(|_| AppMessage::parse(app, Channel::Group))?
            .msg_id;
        Ok((conversation, target))
    }

    /// One deletion of scope `0x01` for `targets` of one conversation, at
    /// most `DELETE_BATCH_MAX` of them in strict byte order.
    fn publish_own_targets<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        targets: Vec<[u8; 16]>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let body = DeleteBody {
            scope: DeleteScope::OwnDevices,
            targets,
        };
        let mut encoded = vec![0u8; body.len()];
        body.encode(&mut encoded)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::Delete,
            msg_id,
            sent_at: now_ms,
            body: &encoded,
        };
        let mut out = vec![0u8; record.len()];
        record.encode(&mut out)?;
        self.publish_sync(conversation, &out, true, None, now_ms / 1_000, rng)
    }

    /// Deletes each message of `conversation` on this device, and asks each
    /// other device of the set to delete them too (`DEV-333`). No record
    /// goes to the other party. A row that does not parse, as a placeholder,
    /// goes on this device alone.
    pub fn delete_conversation<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let messages = self.messages(conversation)?;
        let mut targets: Vec<[u8; 16]> = messages
            .iter()
            .filter_map(|message| self.own_target(message).ok().map(|(_, target)| target))
            .collect();
        targets.sort_unstable();
        targets.dedup();
        for batch in targets.chunks(DELETE_BATCH_MAX) {
            self.publish_own_targets(conversation, batch.to_vec(), now_ms, rng)?;
        }
        for message in &messages {
            self.delete_for_me(message)?;
        }
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    /// Takes each deletion for the devices of this user out of the records
    /// that another device of the set sent, and removes its targets here.
    /// The other records go on.
    pub(super) fn take_own_deletions<R: CryptoRng + ?Sized>(
        &mut self,
        synced: Vec<Synced>,
        rng: &mut R,
    ) -> Result<Vec<Synced>, Error> {
        let mut kept = Vec::with_capacity(synced.len());
        let mut gone = Vec::new();
        let mut sources = Vec::new();
        for record in synced {
            let targets = AppMessage::parse(&record.app, Channel::Pairwise)
                .ok()
                .filter(|parsed| parsed.kind == AppKind::Delete && record.from_user)
                .and_then(|parsed| DeleteBody::parse(parsed.body).ok())
                .filter(|body| body.scope == DeleteScope::OwnDevices)
                .map(|body| body.targets);
            let Some(targets) = targets else {
                kept.push(record);
                continue;
            };
            sources.push(record.origin.0);
            let open = self.open_ref()?;
            for target in targets {
                let reference = msg_ref(&open.device_set_key, &target);
                let natural = [record.conversation.0.as_slice(), &reference].concat();
                let row = open.store.row_id(TableId::MESSAGE, &natural);
                if open.store.get(TableId::MESSAGE, &row)?.is_some() {
                    gone.push((record.conversation, MsgRef(row)));
                }
            }
        }
        for source in sources {
            self.count_deletion(&source, rng)?;
        }
        // DEV-118: after a restore each one waits for the user.
        if self.setting(HOLDS_DELETIONS)?.is_some() {
            if gone.is_empty() {
                return Ok(kept);
            }
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for (conversation, message) in &gone {
                batch.put(HELD_DELETIONS, message.0, None, &conversation.0, rng)?;
            }
            batch.commit()?;
            self.events.push_back(Event::Conversations);
            return Ok(kept);
        }
        for (conversation, message) in gone {
            self.delete_for_me(&message)?;
            self.events.push_back(Event::Deleted {
                conversation,
                message,
            });
        }
        Ok(kept)
    }

    fn roster_epoch(&self) -> Result<u64, Error> {
        Ok(match self.roster_bytes()? {
            Some(bytes) => Roster::parse(&bytes)?.epoch,
            None => 0,
        })
    }

    /// Counts one deletion of `source` in the current roster epoch.
    fn count_deletion<R: CryptoRng + ?Sized>(
        &mut self,
        source: &DeviceId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let epoch = self.roster_epoch()?;
        let count = self.deletions_from(source)?.saturating_add(1);
        let value = [epoch.to_be_bytes().as_slice(), &count.to_be_bytes()].concat();
        self.put_setting(&count_key(source), &value, rng)
    }

    /// The deletions that `device` made on this device since the last
    /// roster epoch (`DEV-119`).
    pub fn deletions_from(&self, device: &DeviceId) -> Result<u32, Error> {
        let Some(held) = self.setting(&count_key(device))? else {
            return Ok(0);
        };
        let epoch = held
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes);
        if epoch != Some(self.roster_epoch()?) {
            return Ok(0);
        }
        Ok(held
            .get(8..12)
            .and_then(|bytes| bytes.try_into().ok())
            .map_or(0, u32::from_be_bytes))
    }

    /// The messages that the deletions of the other devices name after a
    /// restore, which wait for the user (`DEV-117`).
    pub fn held_deletions(&self) -> Result<usize, Error> {
        Ok(self.open_ref()?.store.list(HELD_DELETIONS, None)?.len())
    }

    /// The user confirmed the deletions that wait (`DEV-118`), and later
    /// deletions apply at once.
    pub fn apply_held_deletions(&mut self) -> Result<(), Error> {
        let held = self.open_ref()?.store.list(HELD_DELETIONS, None)?;
        for (row, conversation) in held {
            let message = MsgRef(row);
            if self.delete_if_held(&message).is_err() {
                continue;
            }
            if let Ok(conversation) = <[u8; 16]>::try_from(conversation.as_slice()) {
                self.events.push_back(Event::Deleted {
                    conversation: ConversationId(conversation),
                    message,
                });
            }
        }
        self.end_held_deletions()
    }

    /// Marks the store as a restore does, for a test.
    #[doc(hidden)]
    pub fn hold_deletions<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        self.put_setting(HOLDS_DELETIONS, &[1], rng)
    }

    /// The user keeps the messages that the restore brought back.
    pub fn keep_restored_messages(&mut self) -> Result<(), Error> {
        self.end_held_deletions()
    }

    fn end_held_deletions(&mut self) -> Result<(), Error> {
        let rows: Vec<_> = self
            .open_ref()?
            .store
            .list(HELD_DELETIONS, None)?
            .into_iter()
            .map(|(row, _)| row)
            .collect();
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in rows {
            batch.delete(HELD_DELETIONS, row);
        }
        batch.commit()?;
        self.remove_setting(HOLDS_DELETIONS)
    }
}
