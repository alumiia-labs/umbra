//! The draft of each conversation (Part 7 §7.5.3). A draft is the one item
//! of mutable state that carries content, since a peer device then holds
//! text that no party sent. The store holds it under the record encryption
//! (`DEV-199`), its table is not one that a backup carries (`DEV-200`), a
//! send or a clear erases it from the set (`DEV-201`), and the user can turn
//! its sync off (`DEV-202`).

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::Client;
use crate::{ConversationId, Error};

/// The draft of each conversation, as UTF-8, by the conversation.
pub(super) const DRAFTS: TableId = TableId(0x49);
/// The row of the draft text in the mutable state of §7.5.3, the twelfth
/// row of its table.
pub(super) const ITEM_DRAFT: u8 = 12;
/// The setting that turns the draft sync off.
const DRAFT_SYNC_OFF: &[u8] = b"draft-sync-off";
/// The longest draft that goes to the other devices, in bytes of UTF-8. A
/// longer one goes cut at a character.
const DRAFT_SYNC_MAX: usize = 4_096;

/// `text` cut to at most `max` bytes at a character boundary.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }

    text.get(..end).unwrap_or_default()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The draft of a conversation, as UTF-16 code units, or none.
    pub fn draft(&self, conversation: ConversationId) -> Result<Zeroizing<Vec<u16>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(DRAFTS, &conversation.0);
        let Some(bytes) = store.get(DRAFTS, &row)? else {
            return Ok(Zeroizing::new(Vec::new()));
        };

        let bytes = Zeroizing::new(bytes);
        let text = core::str::from_utf8(&bytes).map_err(|_| Error::Integrity)?;

        Ok(Zeroizing::new(text.encode_utf16().collect()))
    }

    /// Keeps the draft of a conversation, and an empty one erases it. Each
    /// other device of the set takes it while the draft sync is on.
    pub fn set_draft<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        code_units: &[u16],
        rng: &mut R,
    ) -> Result<(), Error> {
        let text = Zeroizing::new(String::from_utf16(code_units).map_err(|_| Error::Malformed)?);
        if !self.put_draft(conversation, &text, rng)? {
            return Ok(());
        }

        if self.draft_sync()? {
            if let Some(subject) = self.subject_of(conversation)? {
                let value = cut(&text, DRAFT_SYNC_MAX).as_bytes().to_vec();
                let value = Zeroizing::new(value);
                self.publish_mutable(ITEM_DRAFT, &subject, &value, rng)?;
            }
        }

        Ok(())
    }

    /// The user sent the draft: it leaves this device and the set.
    pub(super) fn clear_draft<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.set_draft(conversation, &[], rng)
    }

    /// Puts or erases the row. The result is whether it changed.
    fn put_draft<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        text: &str,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(DRAFTS, &conversation.0);
        let held = open.store.get(DRAFTS, &row)?.map(Zeroizing::new);
        if held.as_deref().map(Vec::as_slice).unwrap_or_default() == text.as_bytes() {
            return Ok(false);
        }

        let mut batch = open.store.begin();
        if text.is_empty() {
            batch.delete(DRAFTS, row);
        } else {
            batch.put(DRAFTS, row, None, text.as_bytes(), rng)?;
        }

        batch.commit()?;

        Ok(true)
    }

    /// Takes the draft of another device of the set.
    pub(super) fn apply_draft_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.draft_sync()? {
            return Ok(());
        }

        let text = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
        if let Some(conversation) = self.conversation_of_subject(subject)? {
            self.put_draft(conversation, text, rng)?;
        }

        Ok(())
    }

    /// Whether the drafts go to the other devices of the set. It is on by
    /// default.
    pub fn draft_sync(&self) -> Result<bool, Error> {
        Ok(self.setting(DRAFT_SYNC_OFF)?.is_none())
    }

    /// Turns the draft sync on or off (`DEV-202`).
    pub fn set_draft_sync<R: CryptoRng + ?Sized>(
        &mut self,
        is_on: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        if is_on {
            self.remove_setting(DRAFT_SYNC_OFF)
        } else {
            self.put_setting(DRAFT_SYNC_OFF, &[1], rng)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cut;

    #[test]
    fn a_cut_ends_at_a_character() {
        assert_eq!(cut("abc", 2), "ab");
        assert_eq!(cut("aé", 2), "a");
        assert_eq!(cut("aé", 3), "aé");
    }
}
