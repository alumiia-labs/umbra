//! The block of a contact and of a member of a group (Part 13 §13.12).

use super::{conversation_of, locked, FfiError, Handle};
use crate::runtime::OsRng;

#[uniffi::export]
impl Handle {
    /// Whether the user blocked the contact of a conversation.
    pub fn is_blocked(&self, conversation: Vec<u8>) -> Result<bool, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.is_blocked(conversation)?)
    }

    /// Blocks or unblocks the contact of a conversation on each device of
    /// the set. The contact can still send, its records go unread, and it
    /// learns nothing (`ABU-040`, `ABU-041`).
    pub fn set_blocked(&self, conversation: Vec<u8>, blocked: bool) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        inner
            .client
            .set_blocked(conversation, blocked, &mut OsRng)?;
        inner.flush_outgoing();
        Ok(())
    }

    /// The members of a group that the user blocked, by index.
    pub fn blocked_members(&self, conversation: Vec<u8>) -> Result<Vec<u16>, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.blocked_members(conversation)?)
    }

    /// Blocks or unblocks a member of a group on each device of the set.
    pub fn set_member_blocked(
        &self,
        conversation: Vec<u8>,
        index: u16,
        blocked: bool,
    ) -> Result<(), FfiError> {
        let conversation = conversation_of(&conversation)?;
        let mut inner = locked(&self.inner);
        inner
            .client
            .set_member_blocked(conversation, index, blocked, &mut OsRng)?;
        inner.flush_outgoing();
        Ok(())
    }

    /// How many records of blocked members of a group this device
    /// discarded (`ABU-038`).
    pub fn discarded_count(&self, conversation: Vec<u8>) -> Result<u64, FfiError> {
        let conversation = conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.discarded_count(conversation)?)
    }
}
