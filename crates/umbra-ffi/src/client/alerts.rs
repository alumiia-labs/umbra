//! The notification setting of Part 7 §7.5.9: what the client shows for
//! each conversation after a wake. The setting changes no wake of Part 8
//! §8.3 (`DEV-223`), and the device set converges it as mutable state
//! (`DEV-219`, `DEV-220`).

use umbra_core::store::{engine::Backend, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{info_of, Client, MESSAGE_PREFIX, SETTINGS};
use crate::{ConversationId, Error, Event, MsgRef};

/// A notification for each record of the conversation.
pub const ALERT_ALL: u8 = 0;
/// A notification for a record that names the user (Part 6 §6.6.5).
pub const ALERT_MENTIONS: u8 = 1;
/// No notification, and the conversation stays in the list.
pub const ALERT_NONE: u8 = 2;
/// `GROUP_ALL_NOTIFY_MAX`: the members of a new group at or below which it
/// shows each record (Part 11 §11.10).
pub const GROUP_ALL_NOTIFY_MAX: usize = 50;
/// The row of the mute and the notification setting in the mutable state of
/// §7.5.3, the second row of its table.
pub(super) const ITEM_ALERT: u8 = 2;

const ALERT_SETTING: &[u8] = b"alert/";

fn alert_key(conversation: ConversationId) -> Vec<u8> {
    [ALERT_SETTING, conversation.0.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The notification setting of a conversation. A pairwise conversation
    /// with no setting shows each record (`DEV-258`).
    pub fn alert_setting(&self, conversation: ConversationId) -> Result<u8, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, &alert_key(conversation));
        Ok(match store.get(SETTINGS, &row)?.as_deref() {
            Some([value]) if *value <= ALERT_NONE => *value,
            _ => ALERT_ALL,
        })
    }

    fn put_alert<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        value: u8,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, &alert_key(conversation));
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &[value], rng)?;
        Ok(batch.commit()?)
    }

    /// Sets the notification setting of a conversation, and each other
    /// device of the set takes it (`DEV-220`).
    pub fn set_alert_setting<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        value: u8,
        rng: &mut R,
    ) -> Result<(), Error> {
        if value > ALERT_NONE {
            return Err(Error::Malformed);
        }
        self.put_alert(conversation, value, rng)?;
        if let Some(subject) = self.subject_of(conversation)? {
            self.publish_mutable(ITEM_ALERT, &subject, &[value], rng)?;
        }
        Ok(())
    }

    /// Takes the setting of another device of the set.
    pub(super) fn apply_alert_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let [value] = value else {
            return Err(Error::Malformed);
        };
        if *value > ALERT_NONE {
            return Err(Error::Malformed);
        }
        if let Some(conversation) = self.conversation_of_subject(subject)? {
            self.put_alert(conversation, *value, rng)?;
            self.events.push_back(Event::Conversations);
        }
        Ok(())
    }

    /// The setting of a group that this device holds for the first time:
    /// each record at or below `GROUP_ALL_NOTIFY_MAX` members, and the
    /// mentions above (`DEV-259`, `DEV-221`). A group keeps the setting of
    /// its start as it grows.
    pub(super) fn start_group_alert<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        members: usize,
        rng: &mut R,
    ) -> Result<(), Error> {
        let store = &self.open_ref()?.store;
        if store.get(SETTINGS, &store.row_id(SETTINGS, &alert_key(conversation)))?.is_some() {
            return Ok(());
        }
        let value = if members > GROUP_ALL_NOTIFY_MAX {
            ALERT_MENTIONS
        } else {
            ALERT_ALL
        };
        self.put_alert(conversation, value, rng)
    }

    /// Whether a message that arrived gives a notification under the
    /// setting of its conversation. The client asks after the wake, thus
    /// the setting costs no wake and no cell.
    pub fn should_alert(&self, message: &MsgRef) -> Result<bool, Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(umbra_core::store::record::TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        if plain.get(MESSAGE_PREFIX..).is_none() || info_of(&plain)?.outgoing {
            return Ok(false);
        }
        let conversation = self.conversation_of_message(message)?;
        Ok(match self.alert_setting(conversation)? {
            ALERT_ALL => true,
            ALERT_MENTIONS => self.info(message)?.mentions_me,
            _ => false,
        })
    }
}
