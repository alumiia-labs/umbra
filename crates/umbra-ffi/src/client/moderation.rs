//! The moderator actions of Part 11 §11.9.6: hide and remove, in a signed
//! moderation epoch. A hidden record stays on the device and out of the
//! default view, and a removed record leaves as a placeholder that names
//! the acting role (`GRP-082`, `GRP-083`). The epoch itself folds into
//! unsigned local state: the count of each act, with no signature and no
//! target list (`GRP-181`, `GRP-182`).

use umbra_core::store::{
    engine::Backend,
    record::TableId,
    wrap::SecureElement,
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::{
    app::{AppMessage, Channel},
    group::control::{ModAction, Role},
};
use zeroize::Zeroizing;

use super::{
    conversation_of, msg_ref, placeholder_of, Client, CHUNK_CRED, FILE_DATA, FILE_STATE,
    MESSAGE_PREFIX, OUTBOX, REACTION, REVISION,
};
use crate::{ConversationId, Error, Event, MsgRef};

/// The moderation state of each message of a group, under the row of the
/// message: the conversation, the action, and the role of the actor. A
/// target that did not arrive yet takes its state at its arrival.
pub(super) const MODERATED: TableId = TableId(0x39);
/// One row for each moderation epoch that this device applied: the
/// conversation, the time, the role of the actor, and the count of each act
/// (`GRP-089`).
pub(super) const MOD_NOTES: TableId = TableId(0x3A);

/// Takes a message out of the default view of each member.
pub const MOD_HIDE: u8 = 0x01;
/// Deletes a message on the device of each member.
pub const MOD_REMOVE: u8 = 0x02;
/// Puts a hidden message back.
pub const MOD_UNHIDE: u8 = 0x03;

/// One moderation epoch as this device applied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModNote {
    /// The time of the application, in milliseconds.
    pub at_ms: u64,
    /// The role of the acting member.
    pub actor_role: u8,
    /// The messages that the epoch hid.
    pub hidden: u16,
    /// The messages that the epoch removed.
    pub removed: u16,
    /// The messages that the epoch put back.
    pub shown: u16,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The moderation state of a message and the role of the actor, or none.
    pub fn moderation_of(&self, message: &MsgRef) -> Result<Option<(u8, u8)>, Error> {
        let Some(value) = self.open_ref()?.store.get(MODERATED, &message.0)? else {
            return Ok(None);
        };
        match value.get(16..18) {
            Some([action, role]) => Ok(Some((*action, *role))),
            _ => Err(Error::Integrity),
        }
    }

    /// Applies the actions of a verified moderation epoch (`GRP-080`). An
    /// act on a message that an earlier epoch removed changes nothing
    /// (`GRP-084`).
    pub(super) fn apply_moderation<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        actor_role: Role,
        actions: &[ModAction],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut note = ModNote {
            at_ms: now_ms,
            actor_role: actor_role as u8,
            hidden: 0,
            removed: 0,
            shown: 0,
        };
        for action in actions {
            let open = self.open_ref()?;
            let reference = msg_ref(&open.device_set_key, &action.target);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let message = MsgRef(open.store.row_id(TableId::MESSAGE, &natural));
            let held = self.moderation_of(&message)?;
            if held.is_some_and(|(state, _)| state == MOD_REMOVE) {
                continue;
            }
            match action.action {
                MOD_HIDE => {
                    self.put_moderation(conversation, message, MOD_HIDE, actor_role, rng)?;
                    note.hidden = note.hidden.saturating_add(1);
                }
                MOD_UNHIDE if held.is_some() => {
                    let open = self.open_mut()?;
                    let mut batch = open.store.begin();
                    batch.delete(MODERATED, message.0);
                    batch.commit()?;
                    note.shown = note.shown.saturating_add(1);
                }
                MOD_REMOVE => {
                    self.put_moderation(conversation, message, MOD_REMOVE, actor_role, rng)?;
                    self.remove_content(conversation, message, rng)?;
                    note.removed = note.removed.saturating_add(1);
                }
                _ => continue,
            }
            self.events.push_back(Event::Edited {
                conversation,
                message,
            });
        }
        let value = [
            conversation.0.as_slice(),
            &note.at_ms.to_be_bytes(),
            &[note.actor_role],
            &note.hidden.to_be_bytes(),
            &note.removed.to_be_bytes(),
            &note.shown.to_be_bytes(),
        ]
        .concat();
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let open = self.open_mut()?;
        let row = open.store.row_id(MOD_NOTES, &key);
        let mut batch = open.store.begin();
        batch.put(MOD_NOTES, row, Some(conversation.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    fn put_moderation<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        action: u8,
        actor_role: Role,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = [conversation.0.as_slice(), &[action, actor_role as u8]].concat();
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(MODERATED, message.0, Some(conversation.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    /// Overwrites a removed message with a placeholder, and erases each row
    /// of it (`GRP-082`). A message that did not arrive yet takes the same
    /// at its arrival.
    fn remove_content<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(plain) = self.open_ref()?.store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(());
        };
        let plain = Zeroizing::new(plain);
        if conversation_of(&plain)? != conversation {
            return Ok(());
        }
        let placeholder = placeholder_of(&plain)?;
        self.outgoing.retain(|waiting| waiting.message != message);
        self.files.uploads.retain(|job| job.message != message);
        self.files.downloads.retain(|job| job.message != message);
        let reactions = self.reaction_rows(&message, conversation)?;
        let votes = self.vote_rows(&message, conversation)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, message.0, Some(conversation.0), &placeholder, rng)?;
        for row in reactions {
            batch.delete(REACTION, row);
        }
        for row in votes {
            batch.delete(super::polls::VOTES, row);
        }
        for table in [
            OUTBOX,
            REVISION,
            FILE_STATE,
            FILE_DATA,
            CHUNK_CRED,
            super::polls::POLLS,
            super::groups::MENTIONED,
            super::timers::DEADLINES,
        ] {
            batch.delete(table, message.0);
        }
        Ok(batch.commit()?)
    }

    /// Gives a message that arrived after its removal the placeholder at
    /// once, thus the content never shows.
    pub(super) fn enforce_moderation<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.moderation_of(&message)?.is_some_and(|(state, _)| state == MOD_REMOVE) {
            self.remove_content(conversation, message, rng)?;
        }
        Ok(())
    }

    /// Hides, removes, or puts back one message of a group, in a moderation
    /// epoch that this member signs. A member below `moderator` acts on
    /// nothing (`GRP-081`), and a removed message takes no second act
    /// (`GRP-084`).
    pub fn moderate<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        action: u8,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !matches!(action, MOD_HIDE | MOD_REMOVE | MOD_UNHIDE) {
            return Err(Error::Malformed);
        }
        let conversation = self.conversation_of_message(message)?;
        if !self.is_group(conversation)? || !self.owns_channels()? {
            return Err(Error::Malformed);
        }
        let held = self.moderation_of(message)?;
        let is_allowed = match (action, held) {
            (_, Some((MOD_REMOVE, _))) => false,
            (MOD_UNHIDE, held) => held.is_some(),
            (MOD_HIDE, Some(_)) => false,
            _ => true,
        };
        if !is_allowed {
            return Err(Error::Malformed);
        }
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Group)?.msg_id;
        let group = self.group_of(conversation)?;
        let object = group
            .moderate(&[(action, target)], rng)
            .map_err(|_| Error::Malformed)?;
        self.post_group_control(conversation, &object, now_ms, rng)?;
        self.apply_own_roster_object(conversation, &object, now_ms, rng)?;
        Ok(())
    }

    /// The moderation epochs that this device applied in a conversation, in
    /// the order of time (`GRP-089`).
    pub fn moderation_notes(&self, conversation: ConversationId) -> Result<Vec<ModNote>, Error> {
        let mut notes = Vec::new();
        for (_, value) in self.open_ref()?.store.list(MOD_NOTES, Some(&conversation.0))? {
            let field = |range: core::ops::Range<usize>| value.get(range).ok_or(Error::Integrity);
            let at: [u8; 8] = field(16..24)?.try_into().map_err(|_| Error::Integrity)?;
            let count = |at: usize| -> Result<u16, Error> {
                let bytes: [u8; 2] = field(at..at + 2)?.try_into().map_err(|_| Error::Integrity)?;
                Ok(u16::from_be_bytes(bytes))
            };
            notes.push(ModNote {
                at_ms: u64::from_be_bytes(at),
                actor_role: *field(24..25)?.first().ok_or(Error::Integrity)?,
                hidden: count(25)?,
                removed: count(27)?,
                shown: count(29)?,
            });
        }
        notes.sort_by_key(|note| note.at_ms);
        Ok(notes)
    }
}
