//! The block of a contact and of a member of a group (Part 13 §13.12).
//!
//! A block is a state of the client and no protocol message (`ABU-021`).
//! The queue of a blocked contact stays, the device acknowledges each of
//! its records and discards it, and the receipts keep the behavior that
//! held before the block (`ABU-025` to `ABU-031`). The records of a blocked
//! member of a group are discarded after their tag check, and the view
//! shows how many (`ABU-036` to `ABU-038`).

use umbra_core::{
    devset::sync::group_subject,
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::Client;
use crate::{ConversationId, Error};

/// Each block of this device: a contact under its conversation, a member
/// under the group and the index. The value is one byte of the kind, and
/// the count of the records that a block of a group discarded.
pub(super) const BLOCKED: TableId = TableId(0x2E);
const CONTACT_BLOCK: u8 = 1;
const MEMBER_BLOCK: u8 = 2;
const DISCARDED: u8 = 3;

fn contact_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), &[CONTACT_BLOCK]].concat()
}

fn member_key(conversation: ConversationId, index: u16) -> Vec<u8> {
    [
        conversation.0.as_slice(),
        &[MEMBER_BLOCK],
        &index.to_be_bytes(),
    ]
    .concat()
}

fn discarded_key(conversation: ConversationId) -> Vec<u8> {
    [conversation.0.as_slice(), &[DISCARDED]].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn block_row(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(BLOCKED, key);
        Ok(store.get(BLOCKED, &row)?.map(Zeroizing::new))
    }

    fn put_block_row<R: CryptoRng + ?Sized>(
        &mut self,
        key: &[u8],
        value: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row: RowId = open.store.row_id(BLOCKED, key);
        let mut batch = open.store.begin();
        match value {
            Some(value) => batch.put(BLOCKED, row, None, value, rng)?,
            None => batch.delete(BLOCKED, row),
        }

        Ok(batch.commit()?)
    }

    /// Whether the user blocked the contact of a conversation.
    pub fn is_blocked(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self.block_row(&contact_key(conversation))?.is_some())
    }

    /// Blocks or unblocks a contact, and each other device of the set does
    /// the same (`ABU-021`, `ABU-022`). Nothing goes to the contact, and its
    /// queue stays (`ABU-023` to `ABU-025`).
    pub fn set_blocked<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        blocked: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.apply_blocked(conversation, blocked, rng)?;
        if let Some(subject) = self.subject_of(conversation)? {
            self.publish_mutable(
                umbra_core::devset::sync::ITEM_BLOCK,
                &subject,
                &[u8::from(blocked)],
                rng,
            )?;
        }

        Ok(())
    }

    fn apply_blocked<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        blocked: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = [1u8];
        self.put_block_row(
            &contact_key(conversation),
            blocked.then_some(value.as_slice()),
            rng,
        )?;

        // NET-194: the dead-channel work drops the blob of a blocked
        // contact at its next pass.
        if !blocked {
            return Ok(());
        }

        // ABU-031: a read receipt that waits for its slot says that the
        // user read a record of this contact, and it goes with the block.
        let open = self.open_mut()?;
        let mut waiting = Vec::new();
        for (row, plain) in open.store.list(super::RECEIPT, Some(&conversation.0))? {
            if plain.get(16) == Some(&(umbra_wire::app::AppKind::ReadReceipt as u8)) {
                waiting.push(row);
            }
        }

        if waiting.is_empty() {
            return Ok(());
        }

        let mut batch = open.store.begin();
        for row in waiting {
            batch.delete(super::RECEIPT, row);
        }

        Ok(batch.commit()?)
    }

    /// The members of a group that the user blocked, by index.
    pub fn blocked_members(&self, conversation: ConversationId) -> Result<Vec<u16>, Error> {
        let mut out = Vec::new();
        let group = self.group_of(conversation)?;
        for member in group.roster().active() {
            if self
                .block_row(&member_key(conversation, member.index))?
                .is_some()
            {
                out.push(member.index);
            }
        }

        Ok(out)
    }

    /// Whether the user blocked the member at `index` of a group.
    pub(super) fn is_member_blocked(
        &self,
        conversation: ConversationId,
        index: u16,
    ) -> Result<bool, Error> {
        Ok(self.block_row(&member_key(conversation, index))?.is_some())
    }

    /// Blocks or unblocks a member of a group, on each device of the set.
    /// No record of the group names it (`ABU-037`).
    pub fn set_member_blocked<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        index: u16,
        blocked: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = [1u8];
        self.put_block_row(
            &member_key(conversation, index),
            blocked.then_some(value.as_slice()),
            rng,
        )?;
        let group_id = *self.group_of(conversation)?.group_id();
        let subject = group_subject(&self.open_ref()?.device_set_key, &group_id);
        let key = [subject.as_slice(), &index.to_be_bytes()].concat();
        self.publish_mutable(
            umbra_core::devset::sync::ITEM_BLOCK,
            &key,
            &[u8::from(blocked)],
            rng,
        )
    }

    /// A member that moved to a new index keeps its block (`GRP-345`).
    pub(super) fn move_member_block<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        old: u16,
        new: u16,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.is_member_blocked(conversation, old)? {
            return Ok(());
        }

        let value = [1u8];
        self.put_block_row(&member_key(conversation, new), Some(&value), rng)?;
        self.put_block_row(&member_key(conversation, old), None, rng)
    }

    /// Counts one record of a blocked member that the device discarded
    /// (`ABU-038`).
    pub(super) fn count_discarded<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let count = self.discarded_count(conversation)?.saturating_add(1);
        self.put_block_row(
            &discarded_key(conversation),
            Some(&count.to_be_bytes()),
            rng,
        )
    }

    /// How many records of blocked members of a group this device
    /// discarded, thus the view shows the gap (`ABU-038`).
    pub fn discarded_count(&self, conversation: ConversationId) -> Result<u64, Error> {
        Ok(self
            .block_row(&discarded_key(conversation))?
            .and_then(|bytes| bytes.as_slice().try_into().ok())
            .map_or(0, u64::from_be_bytes))
    }

    /// Takes a block that another device of the set published: a contact
    /// under its subject, or a member under the subject of its group and its
    /// index.
    pub(super) fn apply_block_item<R: CryptoRng + ?Sized>(
        &mut self,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let blocked = value.first() == Some(&1);
        let subject: [u8; 32] = key
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Malformed)?;
        match key.get(32..) {
            Some([]) => {
                if let Some(conversation) = self.conversation_of_subject(&subject)? {
                    self.apply_blocked(conversation, blocked, rng)?;
                }
            }
            Some([high, low]) => {
                let index = u16::from_be_bytes([*high, *low]);
                if let Some(conversation) = self.conversation_of_subject(&subject)? {
                    let value = [1u8];
                    self.put_block_row(
                        &member_key(conversation, index),
                        blocked.then_some(value.as_slice()),
                        rng,
                    )?;
                }
            }
            _ => return Err(Error::Malformed),
        }

        self.events.push_back(super::Event::Conversations);

        Ok(())
    }
}
