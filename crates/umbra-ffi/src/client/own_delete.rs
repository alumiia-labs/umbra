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
//!
//! A user also deletes a whole pairwise conversation for everyone
//! (`DEV-334`): the deletion for the devices of the user, and one record
//! of scope `0x03` that asks the contact to delete each message of the
//! conversation, on each of its devices (`DEV-335`, `DEV-336`).

use std::collections::BTreeMap;

use umbra_core::{
    devset::{roster::Roster, DeviceId},
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::{
    edit::{DeleteBody, DeleteScope, DELETE_BATCH_MAX},
    AppKind, AppMessage, Channel,
};
use zeroize::Zeroizing;

use super::{
    conversation_of, info_of, msg_ref, outbox_row, own_pending_key, stored_message, sync::Synced,
    Client, Outgoing, DELETE_RATE_LIMIT, INCOMING, LAST_DELETE_SETTING, MESSAGE_PREFIX, OUTBOX,
    OUTGOING, PENDING, PENDING_ROW_LEN, REF_ORPHAN_MAX, SETTINGS,
};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

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

/// One deletion for the devices of the user that another device of the set
/// sent (`DEV-126`).
pub(super) struct OwnDeletion {
    conversation: ConversationId,
    /// The device that sent it, which `DEV-119` counts.
    source: DeviceId,
    is_group: bool,
    targets: Vec<[u8; 16]>,
}

/// Takes each deletion for the devices of the user out of a batch of
/// synced records. The other records go on in their order.
pub(super) fn split_own_deletions(synced: Vec<Synced>) -> (Vec<Synced>, Vec<OwnDeletion>) {
    let mut kept = Vec::with_capacity(synced.len());
    let mut deletions = Vec::new();
    for record in synced {
        let targets = AppMessage::parse(&record.app, Channel::Pairwise)
            .ok()
            .filter(|parsed| parsed.kind == AppKind::Delete && record.from_user)
            .and_then(|parsed| DeleteBody::parse(parsed.body).ok())
            .filter(|body| body.scope == DeleteScope::OwnDevices)
            .map(|body| body.targets);
        match targets {
            Some(targets) => deletions.push(OwnDeletion {
                conversation: record.conversation,
                source: record.origin.0,
                is_group: record.is_group,
                targets,
            }),
            None => kept.push(record),
        }
    }
    (kept, deletions)
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
        // An edit, a reaction, or a vote of the user that waits for its
        // relay names a message that goes now, and no view shows it. Its
        // record would carry the content after the act. A deletion for the
        // other party and a control record stay: they carry no content.
        let mut gone = messages;
        let mut texts = Vec::new();
        let open = self.open_ref()?;
        for (row, plain) in open.store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            let kind = plain.get(MESSAGE_PREFIX..).and_then(|app| {
                AppMessage::parse(app, Channel::Pairwise)
                    .or_else(|_| AppMessage::parse(app, Channel::Group))
                    .ok()
                    .map(|parsed| parsed.kind)
            });
            let is_content = matches!(
                kind,
                Some(AppKind::Edit | AppKind::Reaction | AppKind::PollVote)
            );
            if is_content && !gone.contains(&MsgRef(row)) {
                gone.push(MsgRef(row));
            }
        }
        // An edit that waits for its target holds a text. A deletion that
        // waits stays, thus a target that comes later stays deleted.
        for (row, entry) in open.store.list(PENDING, Some(&conversation.0))? {
            if entry.len() > PENDING_ROW_LEN {
                texts.push(row);
            }
            drop(Zeroizing::new(entry));
        }
        self.delete_all_held(&gone)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in texts {
            batch.delete(PENDING, row);
        }
        batch.commit()?;
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    /// Deletes each message of a pairwise conversation on each device of
    /// this user, as [`Client::delete_conversation`] does, and asks the
    /// contact to delete each message of the conversation too (`DEV-334`).
    /// The request names the newest message of the contact that this device
    /// holds. Thus a message of the contact that crossed the request stays
    /// on both sides (`DEV-335`). A group takes no such request, and a call
    /// inside `DELETE_RATE_LIMIT` is [`Error::Busy`] and changes nothing.
    pub fn delete_conversation_for_everyone<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.is_group(conversation)? {
            return Err(Error::Malformed);
        }
        let now = now_ms / 1_000;
        let limit = [LAST_DELETE_SETTING, conversation.0.as_slice()].concat();
        let open = self.open_ref()?;
        let limit_row = open.store.row_id(SETTINGS, &limit);
        if let Some(last) = open.store.get(SETTINGS, &limit_row)? {
            let last: [u8; 8] = last.as_slice().try_into().map_err(|_| Error::Integrity)?;
            if now.saturating_sub(u64::from_be_bytes(last)) < DELETE_RATE_LIMIT {
                return Err(Error::Busy);
            }
        }
        let bound = self.newest_of_contact(conversation)?;
        self.delete_conversation(conversation, now_ms, rng)?;

        let body = DeleteBody {
            scope: DeleteScope::Conversation,
            targets: vec![bound],
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
        let mut request = vec![0u8; record.len()];
        record.encode(&mut request)?;
        let open = self.open_mut()?;
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let request_row = open.store.row_id(TableId::MESSAGE, &natural);
        let stored = stored_message(
            OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            &request,
        );
        let mut batch = open.store.begin();
        batch.put(
            TableId::MESSAGE,
            request_row,
            Some(conversation.0),
            &stored,
            rng,
        )?;
        batch.put(OUTBOX, request_row, None, &outbox_row(), rng)?;
        batch.put(SETTINGS, limit_row, None, &now.to_be_bytes(), rng)?;
        batch.commit()?;
        self.outgoing.push_back(Outgoing {
            message: MsgRef(request_row),
            conversation,
            app: request,
        });
        self.auto_lock.touch(now);
        Ok(())
    }

    /// The `msg_id` of the newest message of the contact that this device
    /// holds in `conversation`, or zero for none (`WIR-559`).
    fn newest_of_contact(&self, conversation: ConversationId) -> Result<[u8; 16], Error> {
        for message in self.messages(conversation)?.iter().rev() {
            let Some(plain) = self.open_ref()?.store.get(TableId::MESSAGE, &message.0)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            if info_of(&plain)?.outgoing {
                continue;
            }
            let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
            if let Ok(parsed) = AppMessage::parse(app, Channel::Pairwise) {
                return Ok(parsed.msg_id);
            }
        }
        Ok([0; 16])
    }

    /// Applies the request of the contact to delete the whole conversation
    /// (`DEV-335`). Each message of the contact goes, and each message of
    /// this device up to the one that the request names. A zero bound takes
    /// no message of this device, and a bound that this device holds no
    /// more takes each one. `later` holds the rows that the batch of the
    /// request stored after it, and those stay. The request stays as one
    /// row, the trace of `DEV-336`.
    pub(super) fn take_clear<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        app: &[u8],
        bound: [u8; 16],
        later: &[RowId],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_ref()?;
        let up_to = if bound == [0; 16] {
            None
        } else {
            let reference = msg_ref(&open.device_set_key, &bound);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            match open.store.get(TableId::MESSAGE, &row)? {
                // DEV-085: a bound of the contact names no message of the
                // contact, and such a bound takes no message of this device.
                Some(plain) => {
                    let info = info_of(&Zeroizing::new(plain))?;
                    info.outgoing.then_some(info.stored_at_ms)
                }
                None => Some(u64::MAX),
            }
        };
        let mut gone = Vec::new();
        for message in self.messages(conversation)? {
            if later.contains(&message.0) {
                continue;
            }
            let info = self.info(&message)?;
            if !info.outgoing || up_to.is_some_and(|at| info.stored_at_ms <= at) {
                gone.push(message);
            }
        }
        self.delete_all_held(&gone)?;
        for message in gone {
            self.events.push_back(Event::Deleted {
                conversation,
                message,
            });
        }
        let parsed = AppMessage::parse(app, Channel::Pairwise)?;
        let open = self.open_mut()?;
        let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        if open.store.get(TableId::MESSAGE, &row)?.is_none() {
            let trace = stored_message(
                INCOMING,
                Delivery::Delivered,
                conversation,
                open.stamp.next(now_ms),
                app,
            );
            let mut batch = open.store.begin();
            batch.put(TableId::MESSAGE, row, Some(conversation.0), &trace, rng)?;
            batch.commit()?;
        }
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    /// Removes the targets of each deletion for the devices of this user
    /// that [`split_own_deletions`] took out of a batch of another device of
    /// the set. The caller stores the other records of the batch first. A
    /// pairwise target that did not arrive yet waits in the pending
    /// reference table, and its arrival takes it (`DEV-093`).
    pub(super) fn take_own_deletions<R: CryptoRng + ?Sized>(
        &mut self,
        deletions: Vec<OwnDeletion>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let holds = self.setting(HOLDS_DELETIONS)?.is_some();
        let mut gone = Vec::new();
        let mut waiting: Vec<(ConversationId, Vec<u8>, [u8; 16])> = Vec::new();
        for deletion in &deletions {
            let open = self.open_ref()?;
            for target in &deletion.targets {
                let reference = msg_ref(&open.device_set_key, target);
                let natural = [deletion.conversation.0.as_slice(), &reference].concat();
                let row = open.store.row_id(TableId::MESSAGE, &natural);
                if open.store.get(TableId::MESSAGE, &row)?.is_some() {
                    gone.push((deletion.conversation, MsgRef(row)));
                } else if !holds && !deletion.is_group {
                    // A group target waits under the rules of its group.
                    waiting.push((deletion.conversation, natural, reference));
                }
            }
        }
        for deletion in &deletions {
            self.count_deletion(&deletion.source, rng)?;
        }
        self.pend_own_deletions(&waiting, now_ms, rng)?;
        // DEV-118: after a restore each one waits for the user.
        if holds {
            if gone.is_empty() {
                return Ok(());
            }
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            for (conversation, message) in &gone {
                batch.put(HELD_DELETIONS, message.0, None, &conversation.0, rng)?;
            }
            batch.commit()?;
            self.events.push_back(Event::Conversations);
            return Ok(());
        }
        let messages: Vec<MsgRef> = gone.iter().map(|(_, message)| *message).collect();
        self.delete_all_held(&messages)?;
        for (conversation, message) in gone {
            self.events.push_back(Event::Deleted {
                conversation,
                message,
            });
        }
        Ok(())
    }

    /// Keeps a pending entry for each target of a deletion of the user that
    /// did not arrive, up to `REF_ORPHAN_MAX` for each conversation
    /// (`DEV-093`, `DEV-095`). An edit that waits for the same target stays,
    /// and the arrival of the target takes the two.
    fn pend_own_deletions<R: CryptoRng + ?Sized>(
        &mut self,
        waiting: &[(ConversationId, Vec<u8>, [u8; 16])],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if waiting.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut held: BTreeMap<ConversationId, usize> = BTreeMap::new();
        let mut entries = Vec::new();
        for (conversation, natural, reference) in waiting {
            let count = match held.get(conversation) {
                Some(count) => *count,
                None => open.store.list(PENDING, Some(&conversation.0))?.len(),
            };
            if count >= REF_ORPHAN_MAX {
                continue;
            }
            held.insert(*conversation, count.saturating_add(1));
            let row = open.store.row_id(PENDING, &own_pending_key(natural));
            let entry = Zeroizing::new(
                [
                    conversation.0.as_slice(),
                    reference,
                    &(now_ms / 1_000).to_be_bytes(),
                ]
                .concat(),
            );
            entries.push((row, *conversation, entry));
        }
        let mut batch = open.store.begin();
        for (row, conversation, entry) in &entries {
            batch.put(PENDING, *row, Some(conversation.0), entry, rng)?;
        }
        Ok(batch.commit()?)
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
