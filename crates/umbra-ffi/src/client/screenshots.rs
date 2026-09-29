//! The screenshot block of Part 14 §14.6.6: a setting of one conversation
//! on this device, off by default (`IMP-058`, `IMP-059`). The window of the
//! conversation applies it, thus no other device of the set takes it.

use umbra_core::store::{engine::Backend, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;

use super::{Client, SETTINGS};
use crate::{ConversationId, Error};

const SCREENSHOT_SETTING: &[u8] = b"screenshot/";

fn screenshot_key(conversation: ConversationId) -> Vec<u8> {
    [SCREENSHOT_SETTING, conversation.0.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Whether this device blocks a screenshot of a conversation. A
    /// conversation with no setting blocks none (`IMP-059`).
    pub fn screenshot_blocked(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, &screenshot_key(conversation));
        Ok(store.get(SETTINGS, &row)?.as_deref() == Some(&[1]))
    }

    /// Turns the screenshot block of one conversation on or off (`IMP-058`).
    pub fn set_screenshot_blocked<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        is_on: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, &screenshot_key(conversation));
        let mut batch = open.store.begin();
        if is_on {
            batch.put(SETTINGS, row, None, &[1], rng)?;
        } else {
            batch.delete(SETTINGS, row);
        }
        Ok(batch.commit()?)
    }
}
