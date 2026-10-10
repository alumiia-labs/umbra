//! The renewal guard of Part 3 §3.2.6 on the receiving side. A renewal
//! bundle of a contact that does not open the guard of that contact runs no
//! handshake. It waits in the stored contact for the answer of the user
//! (`NET-355`), and the channel carries each record meanwhile.

use umbra_core::{
    session::node::{stored_renewal_ask, stored_with_renewal_answer, ContactId},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{Client, QUEUE_ID_LEN};
use crate::{ConversationId, Error, Event};

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Whether a stored contact holds a bundle that waits for the user.
    pub(super) fn asks_renewal(state: &[u8]) -> bool {
        matches!(stored_renewal_ask(state), Ok(Some(_)))
    }

    /// The arrival time, in milliseconds, of the renewal bundle that waits
    /// for the answer of the user in a conversation, or none (`NET-355`).
    pub fn renewal_ask(&self, conversation: ConversationId) -> Result<Option<u64>, Error> {
        if self.is_device_peer(conversation)? {
            return Ok(None);
        }
        let Some(plain) = self
            .open_ref()?
            .store
            .get(TableId::CONTACT, &conversation.0)?
        else {
            return Ok(None);
        };
        let plain = Zeroizing::new(plain);
        let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
        Ok(stored_renewal_ask(state)
            .ok()
            .flatten()
            .map(|at| at.saturating_mul(1_000)))
    }

    /// The contact of a conversation whose renewal bundle waits, for the
    /// node of a run that is up. That node takes the answer, and the store
    /// follows it.
    pub fn renewal_contact(&self, conversation: ConversationId) -> Result<ContactId, Error> {
        if self.renewal_ask(conversation)?.is_none() {
            return Err(Error::NotFound);
        }
        self.contact_id_of(conversation).map(ContactId)
    }

    /// Writes the answer of the user into the stored contact, for a store
    /// with no run (`NET-355`). The next run starts the handshake of an
    /// accepted bundle. A refused bundle goes, and the channel stays.
    pub fn answer_renewal_stored<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        accept: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.renewal_ask(conversation)?.is_none() {
            return Err(Error::NotFound);
        }
        let open = self.open_mut()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::CONTACT, &conversation.0)?
                .ok_or(Error::NotFound)?,
        );
        let (contact, state) = plain
            .split_at_checked(QUEUE_ID_LEN)
            .ok_or(Error::Integrity)?;
        let answered = stored_with_renewal_answer(state, accept).map_err(|_| Error::Integrity)?;
        let changed = Zeroizing::new([contact, &answered].concat());
        let mut batch = open.store.begin();
        batch.put(TableId::CONTACT, conversation.0, None, &changed, rng)?;
        batch.commit()?;
        self.events.push_back(Event::RenewalAsk { conversation });
        Ok(())
    }
}
