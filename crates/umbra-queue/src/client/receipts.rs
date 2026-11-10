//! The receipt and acknowledgment hold of Part 3 §3.5.4: nothing leaves
//! before `RECEIPT_MIN_DELAY`, nothing waits past `RECEIPT_MAX_HOLD`, and a
//! batch to one peer holds at most `RECEIPT_BATCH_MAX` targets.
//!
//! The runtime asks at each cover slot or at a session it opened for
//! another cause (`NET-046`). No timer of this type opens a session.

use alloc::vec::Vec;

use crate::params::{RECEIPT_BATCH_MAX, RECEIPT_MAX_HOLD, RECEIPT_MIN_DELAY};

/// One held receipt: the target and the arrival it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    /// The `msg_id` of the message.
    pub target: [u8; 16],
    /// The time of the arrival, or of the read, that it reports.
    pub at: u64,
}

/// The receipts that the hold of one peer keeps. A peer sets the count of
/// its messages, and a session that opens late takes no batch meanwhile.
pub const RECEIPT_HELD_MAX: usize = 4_096;

/// The hold of one peer.
#[derive(Default)]
pub struct ReceiptHold {
    held: Vec<Held>,
}

impl ReceiptHold {
    /// Queues a receipt for `target` reporting an event at `at`. A hold at
    /// `RECEIPT_HELD_MAX` first loses each receipt that is stale at `at`,
    /// and then its oldest one.
    pub fn push(&mut self, target: [u8; 16], at: u64) {
        if self.held.iter().any(|h| h.target == target) {
            return;
        }

        if self.held.len() >= RECEIPT_HELD_MAX {
            self.discard_stale(at);
        }

        if self.held.len() >= RECEIPT_HELD_MAX {
            let oldest = self
                .held
                .iter()
                .enumerate()
                .min_by_key(|(_, h)| h.at)
                .map(|(index, _)| index);
            if let Some(index) = oldest {
                self.held.swap_remove(index);
            }
        }

        self.held.push(Held { target, at });
    }

    /// Discards each receipt held past `RECEIPT_MAX_HOLD` (`NET-052`).
    pub fn discard_stale(&mut self, now: u64) -> usize {
        let before = self.held.len();
        self.held
            .retain(|h| now.saturating_sub(h.at) < RECEIPT_MAX_HOLD);
        before.saturating_sub(self.held.len())
    }

    /// Takes the batch that may go in the opportunity at `now`: the targets
    /// past `RECEIPT_MIN_DELAY` (`NET-050`), at most `RECEIPT_BATCH_MAX`
    /// (`NET-045`), in the strictly increasing byte order the wire body
    /// needs. The oldest receipts go first, because each one takes the
    /// first opportunity after its floor (`NET-051`). Thus no receipt
    /// waits to `RECEIPT_MAX_HOLD` behind a newer one. The rest waits for
    /// the next opportunity (`NET-056`).
    pub fn take_batch(&mut self, now: u64) -> Vec<[u8; 16]> {
        self.discard_stale(now);

        let mut oldest: Vec<Held> = self
            .held
            .iter()
            .filter(|h| now.saturating_sub(h.at) >= RECEIPT_MIN_DELAY)
            .copied()
            .collect();

        // The identifier breaks a tie, thus the choice is the same on each
        // run.
        oldest.sort_unstable_by_key(|h| (h.at, h.target));
        oldest.truncate(RECEIPT_BATCH_MAX);

        let mut ready: Vec<[u8; 16]> = oldest.iter().map(|h| h.target).collect();
        ready.sort_unstable();
        self.held.retain(|h| !ready.contains(&h.target));
        ready
    }

    /// The receipts still held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_the_batch_and_the_discard_hold() {
        let mut hold = ReceiptHold::default();
        for i in 0..12u8 {
            hold.push([12 - i; 16], 1_000);
        }
        hold.push([1; 16], 1_000);
        assert_eq!(hold.len(), 12);

        assert!(hold.take_batch(1_000 + RECEIPT_MIN_DELAY - 1).is_empty());
        let batch = hold.take_batch(1_000 + RECEIPT_MIN_DELAY);
        assert_eq!(batch.len(), RECEIPT_BATCH_MAX);
        assert!(batch.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(hold.len(), 3);

        assert_eq!(hold.discard_stale(1_000 + RECEIPT_MAX_HOLD), 3);
        assert!(hold.is_empty());
    }

    #[test]
    fn a_full_hold_loses_its_oldest_receipt() {
        let mut hold = ReceiptHold::default();
        let target = |i: usize| {
            let mut target = [0u8; 16];
            target[..8].copy_from_slice(&(i as u64).to_be_bytes());
            target
        };

        for i in 0..RECEIPT_HELD_MAX {
            hold.push(target(i), 1_000 + i as u64);
        }

        hold.push(target(RECEIPT_HELD_MAX), 1_500);
        assert_eq!(hold.len(), RECEIPT_HELD_MAX);
        assert!(!hold.held.iter().any(|h| h.target == target(0)));
    }

    #[test]
    fn the_oldest_receipts_leave_first_whatever_their_identifiers() {
        let mut hold = ReceiptHold::default();
        // The oldest receipt holds the highest identifier.
        hold.push([0xFF; 16], 1_000);
        for i in 0..12u8 {
            hold.push([i; 16], 1_010 + u64::from(i));
        }

        let batch = hold.take_batch(2_000 + RECEIPT_MIN_DELAY);
        assert_eq!(batch.len(), RECEIPT_BATCH_MAX);
        assert!(batch.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(batch.last(), Some(&[0xFF; 16]));

        // The newest wait, and not the highest.
        assert!(!batch.contains(&[8; 16]));
        let rest = hold.take_batch(2_000 + RECEIPT_MIN_DELAY);
        assert_eq!(rest, [[8; 16], [9; 16], [10; 16], [11; 16]]);
        assert!(hold.is_empty());
    }
}
