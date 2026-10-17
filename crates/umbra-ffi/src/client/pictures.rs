//! The pet-avatar of Part 9 §9.8: a picture that the user gives a contact.
//! The contact never learns it and no relay carries it in the clear
//! (`DIS-018`). The device set converges it as mutable state of Part 7
//! §7.5.3 (`DEV-327`), and the last writer wins.

use umbra_core::{
    discovery::profile::{ProfilePlain, PICTURE_MAX},
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::Client;
use crate::{ConversationId, Error, Event};

/// The pet-avatar of each contact, by the conversation: the conversation,
/// then the JPEG.
pub(super) const PET_AVATARS: TableId = TableId(0x57);
/// The row of the pet-avatar in the mutable state of §7.5.3, the fourth
/// row of its table.
pub(super) const ITEM_PET_AVATAR: u8 = 4;
/// `PET_AVATAR_MAX` of Part 9 §9.12, in bytes. One sync record in bucket
/// `B2` carries a picture of this size.
pub const PET_AVATAR_MAX: usize = PICTURE_MAX;

/// Whether bytes are a picture that the store takes: a JPEG inside
/// `PET_AVATAR_MAX` with a frame of `DIS-176`.
fn is_picture(picture: &[u8]) -> bool {
    // The profile blob holds the one JPEG check of the core.
    ProfilePlain {
        name: "",
        welcome: "",
        picture,
    }
    .encode()
    .is_ok()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The pet-avatar of a contact, or an empty value for none.
    pub fn contact_picture(&self, conversation: ConversationId) -> Result<Vec<u8>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(PET_AVATARS, &conversation.0);
        let Some(plain) = store.get(PET_AVATARS, &row)? else {
            return Ok(Vec::new());
        };

        // IMP-121: the plaintext names its owner.
        if plain.get(..16) != Some(conversation.0.as_slice()) {
            return Err(Error::Integrity);
        }

        Ok(plain.get(16..).unwrap_or_default().to_vec())
    }

    /// Puts or erases the row. The result is whether it changed.
    fn put_contact_picture<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        picture: &[u8],
        rng: &mut R,
    ) -> Result<bool, Error> {
        if self.contact_picture(conversation)? == picture {
            return Ok(false);
        }

        let open = self.open_mut()?;
        let row = open.store.row_id(PET_AVATARS, &conversation.0);
        let mut batch = open.store.begin();
        if picture.is_empty() {
            batch.delete(PET_AVATARS, row);
        } else {
            let plain = Zeroizing::new([conversation.0.as_slice(), picture].concat());
            batch.put(PET_AVATARS, row, Some(conversation.0), &plain, rng)?;
        }

        batch.commit()?;

        Ok(true)
    }

    /// Gives a contact a picture on the devices of this user, or takes it
    /// away with an empty value (`DIS-017`). The picture is a JPEG that the
    /// platform encoded anew, of at most `PET_AVATAR_MAX` bytes. A group
    /// and a conversation that is no contact take none.
    pub fn set_contact_picture<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        picture: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if picture.len() > PET_AVATAR_MAX {
            return Err(Error::TooLong);
        }
        if !picture.is_empty() && !is_picture(picture) {
            return Err(Error::Malformed);
        }

        let is_contact = self
            .open_ref()?
            .store
            .get(TableId::CONTACT, &conversation.0)?
            .is_some();
        if !is_contact || self.is_device_peer(conversation)? {
            return Err(Error::NotFound);
        }
        if !self.put_contact_picture(conversation, picture, rng)? {
            return Ok(());
        }

        // DEV-327: the picture is mutable state of the set, and an empty
        // value carries the removal.
        if let Some(subject) = self.subject_of(conversation)? {
            self.publish_mutable(ITEM_PET_AVATAR, &subject, picture, rng)?;
        }

        Ok(())
    }

    /// Takes the pet-avatar that another device of the set gave.
    pub(super) fn apply_picture_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if value.len() > PET_AVATAR_MAX {
            return Err(Error::TooLong);
        }
        if !value.is_empty() && !is_picture(value) {
            return Err(Error::Malformed);
        }
        let Some(conversation) = self.conversation_of_subject(subject)? else {
            return Ok(());
        };
        if self.is_group(conversation)? {
            return Ok(());
        }

        if self.put_contact_picture(conversation, value, rng)? {
            self.events.push_back(Event::Conversations);
        }

        Ok(())
    }
}
