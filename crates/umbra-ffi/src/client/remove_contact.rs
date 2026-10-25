//! The removal of a contact (Part 7 §7.5.11).
//!
//! A removal is a local act, as a block is: no record goes to the contact,
//! and no `DEL` goes to its queue (`DEV-339`). Each device of the set
//! erases the conversation, and a guard row keeps the contact from coming
//! back through the sync channel or the node of the current run.

use umbra_core::{
    devset::sync::ITEM_CONTACT_REMOVED,
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{
    alerts, block, dead, devices, drafts, groups, intros, key_changes, key_supply, modes, notify,
    own_delete, pending_copy, pictures, pins, quota, reset, retention, roster_notes, social, sync,
    timers, Client, CONVERSATION, LAST_DELETE_SETTING, PENDING, PUBLISH_PENDING, RECEIPT,
    RECEIPT_SETTING, SETTINGS,
};
use crate::{ConversationId, Error, Event, MsgRef};

/// Each contact that the user removed, under its conversation: the subject
/// of `DEV-226`, then the `RecipientId` of each of its queues. The subject
/// keeps the sync channel from bringing it back (`DEV-341`), and each queue
/// names its push silent (`DEV-340`).
pub(super) const REMOVED_CONTACTS: TableId = TableId(0x58);
const SUBJECT_LEN: usize = 32;

/// The tables whose rows of a conversation carry it in the owner column.
const OWNED: [TableId; 12] = [
    RECEIPT,
    PENDING,
    timers::TIMERS,
    key_changes::KEY_CHANGES,
    reset::RESET_NOTICES,
    key_supply::SEND_INDEX,
    key_supply::KEY_ASKED,
    pictures::PET_AVATARS,
    social::SHARES_HELD,
    groups::GROUP_JOIN,
    intros::INTROS,
    roster_notes::ROSTER_NOTES,
];

/// The tables that hold one row for a conversation, under its identifier
/// or under a key made from it.
const KEYED: [TableId; 10] = [
    CONVERSATION,
    TableId::VERIFICATION,
    dead::DEAD_CHANNEL,
    timers::TIMERS,
    drafts::DRAFTS,
    super::forward::FORWARD_POLICY,
    pictures::PET_AVATARS,
    key_changes::KEY_CHANGES,
    reset::RESET_NOTICES,
    social::SHARES_HELD,
];

/// The settings of a conversation, each before its identifier.
const SETTING_PREFIXES: [&[u8]; 7] = [
    RECEIPT_SETTING,
    LAST_DELETE_SETTING,
    alerts::ALERT_SETTING,
    modes::MODE_SETTING,
    pins::FLAGS,
    dead::UNANSWERED_SETTING,
    key_supply::SERVED_SETTING,
];

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Removes a contact from each device of the set (`DEV-337` to
    /// `DEV-341`). Nothing goes to the contact. A group and a sync channel
    /// are no contact, and they are `Malformed`.
    pub fn remove_contact<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.is_group(conversation)? || self.is_device_peer(conversation)? {
            return Err(Error::Malformed);
        }
        let subject = self.subject_of(conversation)?.ok_or(Error::NotFound)?;

        self.publish_mutable(ITEM_CONTACT_REMOVED, &subject, &[1], rng)?;
        self.erase_contact(conversation, subject, rng)
    }

    /// Takes the removal of a contact from another device of the set. The
    /// guard holds the subject when this device holds no conversation of
    /// it yet, thus a later identity entry makes none.
    pub(super) fn apply_contact_removal<R: CryptoRng + ?Sized>(
        &mut self,
        subject: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        if let Some(conversation) = self.conversation_of_subject(&subject)? {
            return self.erase_contact(conversation, subject, rng);
        }
        if self.is_removed_subject(&subject)? {
            return Ok(());
        }

        // DEV-341: a record of the subject that waits for its identity
        // entry waits for an entry that the guard refuses, thus it goes.
        let held = self.held_records(&subject)?;

        // The row of a guard that names no conversation takes a key from
        // the subject.
        let open = self.open_mut()?;
        let row = open.store.row_id(REMOVED_CONTACTS, &subject);
        let value = [subject.as_slice(), &[0; 32]].concat();
        let mut batch = open.store.begin();
        for (table, held_row) in held {
            batch.delete(table, held_row);
        }
        batch.put(REMOVED_CONTACTS, row, None, &value, rng)?;

        Ok(batch.commit()?)
    }

    /// The synced records of `subject` that wait for the identity entry
    /// of their conversation (`DEV-294`).
    fn held_records(&self, subject: &[u8; 32]) -> Result<Vec<(TableId, RowId)>, Error> {
        Ok(self
            .open_ref()?
            .store
            .list(sync::PAIRWISE_HELD, None)?
            .into_iter()
            .filter_map(|(row, plain)| {
                let plain = Zeroizing::new(plain);
                (plain.get(..SUBJECT_LEN) == Some(subject.as_slice()))
                    .then_some((sync::PAIRWISE_HELD, row))
            })
            .collect())
    }

    /// Whether the user removed the contact that `subject` names.
    pub(super) fn is_removed_subject(&self, subject: &[u8; 32]) -> Result<bool, Error> {
        Ok(self
            .open_ref()?
            .store
            .list(REMOVED_CONTACTS, None)?
            .iter()
            .any(|(_, value)| value.get(..SUBJECT_LEN) == Some(subject.as_slice())))
    }

    /// Each conversation that a removal erased since the last call, from
    /// this device or from another one. The bridge of the run drops each
    /// one, thus no later record of the run goes to it (`DEV-340`).
    pub fn take_erased(&mut self) -> Vec<ConversationId> {
        core::mem::take(&mut self.erased)
    }

    /// The `RecipientId` of each queue of each removed contact. A row of an
    /// earlier build holds the first queue alone.
    pub(super) fn removed_queues(&self) -> Result<Vec<[u8; 32]>, Error> {
        Ok(self
            .open_ref()?
            .store
            .list(REMOVED_CONTACTS, None)?
            .iter()
            .filter_map(|(_, value)| value.get(SUBJECT_LEN..))
            .flat_map(|recipients| recipients.as_chunks::<32>().0.to_vec())
            .filter(|recipient| *recipient != [0; 32])
            .collect())
    }

    /// Erases each message and each row of a contact (`DEV-337`,
    /// `DEV-338`). The channel ends as the channel of a revoked device
    /// does, thus the node of this run changes nothing more (`DEV-340`).
    fn erase_contact<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        subject: [u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        // DEV-340: each queue of the contact, the one of a rotation too.
        let store = &self.open_ref()?.store;
        let recipients: Vec<u8> = store
            .get(TableId::CONTACT, &conversation.0)?
            .map(Zeroizing::new)
            .map(|row| notify::contact_queues(&row).concat())
            .unwrap_or_else(|| vec![0; 32]);

        // A control record is a row of the conversation too, thus the list
        // takes each row and not the messages of a view alone.
        let messages: Vec<MsgRef> = store
            .list(TableId::MESSAGE, Some(&conversation.0))?
            .into_iter()
            .map(|(row, plain)| {
                drop(Zeroizing::new(plain));
                MsgRef(row)
            })
            .collect();
        let mut rows = self.message_rows(&messages)?;
        rows.extend(self.contact_rows(conversation, &subject)?);
        self.delete_all_held(&messages)?;

        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for (table, row) in rows {
            batch.delete(table, row);
        }

        batch.delete(TableId::CONTACT, conversation.0);
        batch.put(devices::ENDED_CHANNELS, conversation.0, None, &[1], rng)?;
        let value = [subject.as_slice(), &recipients].concat();
        batch.put(REMOVED_CONTACTS, conversation.0, None, &value, rng)?;
        batch.commit()?;

        self.subjects.remove(&conversation);
        self.outgoing
            .retain(|waiting| waiting.conversation != conversation);
        self.erased.push(conversation);
        self.events.push_back(Event::Conversations);
        self.events.push_back(Event::WakeTable);

        Ok(())
    }

    /// The rows of each message that the removal of a message leaves: the
    /// source of a synced copy, and the hold of a file.
    fn message_rows(&self, messages: &[MsgRef]) -> Result<Vec<(TableId, RowId)>, Error> {
        let store = &self.open_ref()?.store;
        let mut rows = Vec::new();
        for message in messages {
            if store.get(retention::SYNC_ORIGIN, &message.0)?.is_some() {
                rows.push((retention::SYNC_ORIGIN, message.0));
            }

            let held = store.row_id(SETTINGS, &[quota::HELD_SETTING, &message.0].concat());
            if store.get(SETTINGS, &held)?.is_some() {
                rows.push((SETTINGS, held));
            }
        }

        Ok(rows)
    }

    /// Each row outside the messages that names a contact. The share that
    /// the contact holds of the user stays (`DEV-338`).
    fn contact_rows(
        &self,
        conversation: ConversationId,
        subject: &[u8; 32],
    ) -> Result<Vec<(TableId, RowId)>, Error> {
        let store = &self.open_ref()?.store;
        let id = conversation.0;
        let mut rows = Vec::new();
        for table in OWNED {
            for (row, plain) in store.list(table, Some(&id))? {
                drop(Zeroizing::new(plain));
                rows.push((table, row));
            }
        }

        let mut keyed: Vec<(TableId, RowId)> = KEYED
            .iter()
            .flat_map(|table| [(*table, id), (*table, store.row_id(*table, &id))])
            .collect();
        keyed.extend(SETTING_PREFIXES.iter().map(|prefix| {
            (
                SETTINGS,
                store.row_id(SETTINGS, &[prefix, id.as_slice()].concat()),
            )
        }));
        keyed.push((
            block::BLOCKED,
            store.row_id(block::BLOCKED, &block::contact_key(conversation)),
        ));
        for (table, row) in keyed {
            if store.get(table, &row)?.is_some() {
                rows.push((table, row));
            }
        }

        // A record that waits for the other devices names the contact
        // after its place in the order.
        for (row, plain) in store.list(PUBLISH_PENDING, None)? {
            let plain = Zeroizing::new(plain);
            if pending_copy(&plain).is_some_and(|(_, held, _)| held == conversation) {
                rows.push((PUBLISH_PENDING, row));
            }
        }

        // These rows name the contact in their value: a deletion that
        // waits for its target, and the third party of an introduction.
        let names = |table: TableId, at: core::ops::Range<usize>, value: &[u8]| {
            store.list(table, None).map(|listed| {
                listed
                    .into_iter()
                    .filter(|(_, plain)| plain.get(at.clone()) == Some(value))
                    .map(|(row, plain)| {
                        drop(Zeroizing::new(plain));
                        (table, row)
                    })
                    .collect::<Vec<_>>()
            })
        };
        rows.extend(names(own_delete::HELD_DELETIONS, 0..16, &id)?);
        rows.extend(names(intros::INTROS, 17..33, &id)?);
        rows.extend(self.held_records(subject)?);

        // A group names the contact behind a member, and the admin of an
        // offer that the contact sent.
        for (row, owner, plain) in store.list_owned(groups::GROUP_MEMBER)? {
            let plain = Zeroizing::new(plain);
            let is_member = plain.as_slice() == id.as_slice();
            let is_offer = owner.is_some_and(|group| {
                row == store.row_id(
                    groups::GROUP_MEMBER,
                    &Self::offer_key(ConversationId(group), conversation),
                )
            });
            if is_member || is_offer {
                rows.push((groups::GROUP_MEMBER, row));
            }
        }

        rows.sort_unstable();
        rows.dedup();

        Ok(rows)
    }
}
