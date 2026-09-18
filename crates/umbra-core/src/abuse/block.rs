//! The block of a contact (Part 14 §14.12): a client state that sends
//! nothing, keeps the queue and the ratchet alive, and discards what the
//! blocked party sends after the acknowledgement.

use alloc::collections::{BTreeMap, BTreeSet};

/// What a client does with a record of a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Render it, and raise a notification as usual.
    Render,
    /// Acknowledge it, advance the ratchet, and discard it without a
    /// render or a notification (`ABU-026` to `ABU-029`).
    Discard,
}

/// The kind of an outbound signal, for the rules of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// An `ACK` on the queue.
    Ack,
    /// A delivery receipt of kind `0x06`.
    DeliveryReceipt,
    /// A read receipt of kind `0x07`.
    ReadReceipt,
    /// A `DEL` of the queue.
    QueueDelete,
    /// A record that names the block.
    BlockNotice,
}

/// The block state, which is mutable state of Part 7 §7.5.3 and converges
/// across the device set (`ABU-021`, `ABU-022`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockList {
    contacts: BTreeSet<[u8; 32]>,
    discarded: BTreeMap<([u8; 32], [u8; 32]), u32>,
}

impl BlockList {
    /// Blocks a contact.
    pub fn block(&mut self, contact: [u8; 32]) {
        self.contacts.insert(contact);
    }

    /// Unblocks a contact and restores the ordinary behavior (`ABU-034`).
    /// What was discarded stays discarded (`ABU-035`).
    pub fn unblock(&mut self, contact: &[u8; 32]) {
        self.contacts.remove(contact);
    }

    /// Whether a contact is blocked.
    pub fn is_blocked(&self, contact: &[u8; 32]) -> bool {
        self.contacts.contains(contact)
    }

    /// The disposition of a pairwise record from `contact`.
    pub fn on_record(&self, contact: &[u8; 32]) -> Disposition {
        if self.is_blocked(contact) {
            Disposition::Discard
        } else {
            Disposition::Render
        }
    }

    /// The disposition of a group record from `member` in `group`, after
    /// the tag check, with the discarded count kept for the gap shown to
    /// the user (`ABU-036`, `ABU-038`).
    pub fn on_group_record(&mut self, group: [u8; 32], member: [u8; 32]) -> Disposition {
        if self.is_blocked(&member) {
            let count = self.discarded.entry((group, member)).or_insert(0);
            *count = count.saturating_add(1);
            Disposition::Discard
        } else {
            Disposition::Render
        }
    }

    /// The records of `member` discarded in `group`.
    pub fn discarded(&self, group: &[u8; 32], member: &[u8; 32]) -> u32 {
        self.discarded.get(&(*group, *member)).copied().unwrap_or(0)
    }

    /// Whether a signal may go to `contact` (`ABU-023` to `ABU-026`,
    /// `ABU-030`, `ABU-031`, `ABU-037`).
    pub fn allows(&self, contact: &[u8; 32], signal: Signal) -> bool {
        match signal {
            Signal::BlockNotice => false,
            Signal::Ack | Signal::DeliveryReceipt => true,
            Signal::ReadReceipt | Signal::QueueDelete => !self.is_blocked(contact),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_discards_keeps_the_queue_and_counts_the_group_gap() {
        let mut list = BlockList::default();
        let bob = [1u8; 32];
        assert_eq!(list.on_record(&bob), Disposition::Render);
        assert!(list.allows(&bob, Signal::QueueDelete));
        list.block(bob);
        assert_eq!(list.on_record(&bob), Disposition::Discard);
        assert!(list.allows(&bob, Signal::Ack));
        assert!(list.allows(&bob, Signal::DeliveryReceipt));
        assert!(!list.allows(&bob, Signal::ReadReceipt));
        assert!(!list.allows(&bob, Signal::QueueDelete));
        assert!(!list.allows(&bob, Signal::BlockNotice));
        assert!(!list.allows(&[2; 32], Signal::BlockNotice));
        let group = [7u8; 32];
        assert_eq!(list.on_group_record(group, bob), Disposition::Discard);
        assert_eq!(list.on_group_record(group, bob), Disposition::Discard);
        assert_eq!(list.on_group_record(group, [2; 32]), Disposition::Render);
        assert_eq!(list.discarded(&group, &bob), 2);
        list.unblock(&bob);
        assert_eq!(list.on_record(&bob), Disposition::Render);
        assert_eq!(list.discarded(&group, &bob), 2);
    }
}
