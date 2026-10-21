//! The pin flag of a conversation (Part 7 `DEV-329`, `DEV-330`): a pinned
//! conversation stays above each other one in the list. The device set
//! converges the flag as mutable state of §7.5.3.

use umbra_core::store::{engine::Backend, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;

use super::{Client, SETTINGS};
use crate::{ConversationId, Error, Event};

/// The row of the archive flag, the pin flag, and the folder label in the
/// mutable state of §7.5.3, the tenth row of its table.
pub(super) const ITEM_FLAGS: u8 = 10;
/// Bit 0 of the flags (`DEV-329`).
const FLAG_PIN: u8 = 0x01;

pub(super) const FLAGS: &[u8] = b"flags/";

fn flags_key(conversation: ConversationId) -> Vec<u8> {
    [FLAGS, conversation.0.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Whether the user pinned the conversation.
    pub fn is_pinned(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, &flags_key(conversation));
        let held = store.get(SETTINGS, &row)?;
        Ok(matches!(held.as_deref(), Some([flags, ..]) if flags & FLAG_PIN != 0))
    }

    fn put_pinned<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        is_pinned: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let flags = if is_pinned { FLAG_PIN } else { 0 };
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, &flags_key(conversation));
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &[flags], rng)?;

        Ok(batch.commit()?)
    }

    /// Pins or unpins a conversation, and each other device of the set
    /// takes it (`DEV-329`).
    pub fn set_pinned<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        is_pinned: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.put_pinned(conversation, is_pinned, rng)?;
        if let Some(subject) = self.subject_of(conversation)? {
            let flags = if is_pinned { FLAG_PIN } else { 0 };
            self.publish_mutable(ITEM_FLAGS, &subject, &[flags], rng)?;
        }

        Ok(())
    }

    /// Takes the flags of another device of the set. A later version puts
    /// the archive flag and the folder label in the other bits and bytes,
    /// and this build keeps the pin flag alone.
    pub(super) fn apply_flags_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let [flags, ..] = value else {
            return Err(Error::Malformed);
        };

        if let Some(conversation) = self.conversation_of_subject(subject)? {
            self.put_pinned(conversation, flags & FLAG_PIN != 0, rng)?;
            self.events.push_back(Event::Conversations);
        }

        Ok(())
    }
}
