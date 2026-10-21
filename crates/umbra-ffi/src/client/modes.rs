//! The privacy mode of each conversation (Part 3 §3.9): the per-hop delay of
//! the circuits that carry its records and its files (`NET-028`, Part 12
//! `ATT-167`). The user sets it for each conversation, and Balanced is the
//! default.
//!
//! A limit of this client: a group takes Balanced, since the session of the
//! group queues carries each group of the user.

use umbra_core::session::node::DelayClass;
use umbra_core::store::{engine::Backend, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;

use super::Client;
use crate::{ConversationId, Error};

pub(super) const MODE_SETTING: &[u8] = b"mode/";

fn mode_key(conversation: ConversationId) -> Vec<u8> {
    [MODE_SETTING, conversation.0.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The privacy mode of a conversation.
    pub fn privacy_mode(&self, conversation: ConversationId) -> Result<DelayClass, Error> {
        Ok(match self.setting(&mode_key(conversation))?.as_deref() {
            Some([byte]) => DelayClass::from_byte(*byte).unwrap_or_default(),
            _ => DelayClass::default(),
        })
    }

    /// Sets the privacy mode of a conversation.
    pub fn set_privacy_mode<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        mode: DelayClass,
        rng: &mut R,
    ) -> Result<(), Error> {
        if mode == DelayClass::default() {
            return self.remove_setting(&mode_key(conversation));
        }

        self.put_setting(&mode_key(conversation), &[mode as u8], rng)
    }
}
