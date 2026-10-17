//! The notification setting of Part 7 §7.5.9: what the client shows for
//! each conversation after a wake. The setting changes no wake of Part 8
//! §8.3 (`DEV-223`), and the device set converges it as mutable state
//! (`DEV-219`, `DEV-220`). A mute until a time stops each notification of
//! the conversation, and it shares the item of the setting (`DEV-331`,
//! `DEV-332`).

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
/// The end of a mute that has no end (`DEV-332`).
pub const MUTE_FOREVER: u64 = u64::MAX;

const ALERT_SETTING: &[u8] = b"alert/";

fn alert_key(conversation: ConversationId) -> Vec<u8> {
    [ALERT_SETTING, conversation.0.as_slice()].concat()
}

/// The setting and the end of the mute in a value of `DEV-332`. A value of
/// one byte has no mute.
fn parse_alert(value: &[u8]) -> Option<(u8, u64)> {
    match value {
        [setting] if *setting <= ALERT_NONE => Some((*setting, 0)),
        [setting, end @ ..] if *setting <= ALERT_NONE => {
            Some((*setting, u64::from_be_bytes(end.try_into().ok()?)))
        }
        _ => None,
    }
}

/// The value of `DEV-332`. A value with no mute is one byte, which a build
/// before the mute also reads.
fn alert_value(setting: u8, muted_until_ms: u64) -> Vec<u8> {
    if muted_until_ms == 0 {
        vec![setting]
    } else {
        [[setting].as_slice(), &muted_until_ms.to_be_bytes()].concat()
    }
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The notification setting of a conversation. A pairwise conversation
    /// with no setting shows each record (`DEV-258`).
    pub fn alert_setting(&self, conversation: ConversationId) -> Result<u8, Error> {
        Ok(self.alert_state(conversation)?.0)
    }

    /// The end of the mute of a conversation in milliseconds of the Unix
    /// time, 0 for no mute, or [`MUTE_FOREVER`].
    pub fn muted_until(&self, conversation: ConversationId) -> Result<u64, Error> {
        Ok(self.alert_state(conversation)?.1)
    }

    fn alert_state(&self, conversation: ConversationId) -> Result<(u8, u64), Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, &alert_key(conversation));
        Ok(store
            .get(SETTINGS, &row)?
            .as_deref()
            .and_then(parse_alert)
            .unwrap_or((ALERT_ALL, 0)))
    }

    fn put_alert<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, &alert_key(conversation));
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, value, rng)?;
        Ok(batch.commit()?)
    }

    /// Writes the setting and the mute, and each other device of the set
    /// takes the two in one item (`DEV-332`).
    fn publish_alert<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        setting: u8,
        muted_until_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = alert_value(setting, muted_until_ms);
        self.put_alert(conversation, &value, rng)?;

        // NTF-135: the wake table names a silent and a muted queue.
        self.wake_changed();
        if let Some(subject) = self.subject_of(conversation)? {
            self.publish_mutable(ITEM_ALERT, &subject, &value, rng)?;
        }

        Ok(())
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

        let muted_until_ms = self.muted_until(conversation)?;
        self.publish_alert(conversation, value, muted_until_ms, rng)
    }

    /// Mutes a conversation until `until_ms` in milliseconds of the Unix
    /// time, with no end at [`MUTE_FOREVER`], or ends the mute at 0. Each
    /// other device of the set takes it (`DEV-331`).
    pub fn set_muted_until<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        until_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let setting = self.alert_setting(conversation)?;
        self.publish_alert(conversation, setting, until_ms, rng)
    }

    /// Takes the setting of another device of the set.
    pub(super) fn apply_alert_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let (setting, muted_until_ms) = parse_alert(value).ok_or(Error::Malformed)?;
        if let Some(conversation) = self.conversation_of_subject(subject)? {
            self.put_alert(conversation, &alert_value(setting, muted_until_ms), rng)?;
            self.events.push_back(Event::Conversations);
            self.wake_changed();
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
        if store
            .get(SETTINGS, &store.row_id(SETTINGS, &alert_key(conversation)))?
            .is_some()
        {
            return Ok(());
        }
        let value = if members > GROUP_ALL_NOTIFY_MAX {
            ALERT_MENTIONS
        } else {
            ALERT_ALL
        };
        self.put_alert(conversation, &[value], rng)
    }

    /// Whether a message that arrived gives a notification at `now_ms`
    /// under the setting and the mute of its conversation. The client asks
    /// after the wake, thus the setting costs no wake and no cell.
    pub fn should_alert(&self, message: &MsgRef, now_ms: u64) -> Result<bool, Error> {
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
        let (setting, muted_until_ms) = self.alert_state(conversation)?;
        if now_ms < muted_until_ms {
            return Ok(false);
        }

        Ok(match setting {
            ALERT_ALL => true,
            ALERT_MENTIONS => self.info(message)?.mentions_me,
            _ => false,
        })
    }
}
