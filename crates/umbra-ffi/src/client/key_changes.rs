//! The key-change notice of Part 4 §4.5.1 on the receiving side. A notice
//! from the receiving chain of a contact waits for the answer of the user,
//! and the conversation is blocked until then (`IDN-025`, `IDN-061`). The
//! new keys apply only after the user accepts them for that one contact
//! (`IDN-062`, `IDN-092`), and the next handshake binds them (`IDN-060`).

use umbra_core::{
    identity::address::safety_number,
    session::node::{stored_contact_keys, stored_with_peer_key, ContactId},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::keys::KeyChangeNotice;
use zeroize::Zeroizing;

use super::{Client, QUEUE_ID_LEN};
use crate::{ConversationId, Error, Event};

/// The notice that waits for the answer of the user in each conversation,
/// under the row of the conversation: the conversation, the new X25519 key,
/// the new ML-KEM key, and the time of its arrival.
pub(super) const KEY_CHANGES: TableId = TableId(0x3D);

/// The new X25519 key and the arrival time sit here in a row.
const X25519_AT: usize = 16;
const MLKEM_LEN: usize = 1_184;

/// A notice that waits for the answer of the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKeyChange {
    /// The safety number of the conversation under the new key, for a
    /// comparison out of band before the answer (`IDN-090`).
    pub new_safety_number: String,
    /// The time of the arrival, in milliseconds.
    pub at_ms: u64,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Keeps a notice that a contact sent on its receiving chain
    /// (`IDN-059`). A notice that does not parse changes nothing, and a
    /// later notice takes the place of one that waits.
    pub(super) fn take_key_change<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        body: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Ok(notice) = KeyChangeNotice::parse(body) else {
            return Ok(());
        };
        let value = Zeroizing::new(
            [
                conversation.0.as_slice(),
                &notice.new_x25519_pk,
                notice.new_mlkem_pk,
                &now_ms.to_be_bytes(),
            ]
            .concat(),
        );
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(
            KEY_CHANGES,
            conversation.0,
            Some(conversation.0),
            &value,
            rng,
        )?;
        batch.commit()?;
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    fn held_key_change(
        &self,
        conversation: ConversationId,
    ) -> Result<Option<([u8; 32], u64)>, Error> {
        let Some(value) = self.open_ref()?.store.get(KEY_CHANGES, &conversation.0)? else {
            return Ok(None);
        };
        let key: [u8; 32] = value
            .get(X25519_AT..X25519_AT + 32)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        let at_from = X25519_AT + 32 + MLKEM_LEN;
        let at: [u8; 8] = value
            .get(at_from..at_from + 8)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        Ok(Some((key, u64::from_be_bytes(at))))
    }

    /// The notice that waits in a conversation, or none. While one waits the
    /// conversation takes no message of this device (`IDN-025`).
    pub fn key_change(
        &self,
        conversation: ConversationId,
    ) -> Result<Option<PendingKeyChange>, Error> {
        let Some((key, at_ms)) = self.held_key_change(conversation)? else {
            return Ok(None);
        };
        let store = &self.open_ref()?.store;
        let plain = Zeroizing::new(
            store
                .get(TableId::CONTACT, &conversation.0)?
                .ok_or(Error::NotFound)?,
        );
        let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
        let (own, _) = stored_contact_keys(state, &self.root_identity()?)?;
        Ok(Some(PendingKeyChange {
            new_safety_number: safety_number(&own, &key),
            at_ms,
        }))
    }

    /// The user accepted the new key of one contact (`IDN-062`, `IDN-092`).
    /// The stored contact takes it, and the result names the contact and
    /// the key for a node that runs. The verification of the earlier key
    /// counts for nothing now (`IDN-175`).
    pub fn accept_key_change<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(ContactId, [u8; 32]), Error> {
        let (key, _) = self.held_key_change(conversation)?.ok_or(Error::NotFound)?;
        let open = self.open_mut()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::CONTACT, &conversation.0)?
                .ok_or(Error::NotFound)?,
        );
        let contact: [u8; 32] = plain
            .get(..QUEUE_ID_LEN)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
        let changed =
            Zeroizing::new([contact.as_slice(), &stored_with_peer_key(state, &key)?].concat());
        let mut batch = open.store.begin();
        batch.put(TableId::CONTACT, conversation.0, None, &changed, rng)?;
        batch.delete(KEY_CHANGES, conversation.0);
        batch.commit()?;
        self.events.push_back(Event::Conversations);
        Ok((ContactId(contact), key))
    }
}
