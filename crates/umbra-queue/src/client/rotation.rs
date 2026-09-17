//! The rotation schedule of one queue (Part 3 §3.2.4 and §3.2.6): the age
//! and count limits under an independent jitter, the grace on the old
//! queue, and the silence that marks a dead channel.

use crate::params::{
    DEAD_CHANNEL_SILENCE, ROTATE_AFTER_MESSAGES, ROTATE_AFTER_SECONDS, ROTATE_GRACE,
    ROTATE_JITTER_PERCENT,
};

/// The rotation state of one queue that a client owns.
pub struct Rotation {
    made_at: u64,
    age_limit: u64,
    count_limit: u32,
    sent: u32,
    new_address_sent_at: Option<u64>,
    record_on_new_queue: bool,
}

impl Rotation {
    /// A queue made at `made_at`. `jitter` is one random value that the
    /// caller drew for this queue alone (`NET-018`, `NET-019`); it moves
    /// each limit by up to `ROTATE_JITTER_PERCENT` either way.
    pub fn new(made_at: u64, jitter: u64) -> Self {
        // The jitter maps a random value onto [-20 %, +20 %] of each limit.
        let span = ROTATE_JITTER_PERCENT.saturating_mul(2);
        let offset = jitter % span.saturating_add(1);
        let percent = 100u64
            .saturating_sub(ROTATE_JITTER_PERCENT)
            .saturating_add(offset);
        Rotation {
            made_at,
            age_limit: ROTATE_AFTER_SECONDS.saturating_mul(percent) / 100,
            count_limit: u32::try_from(
                u64::from(ROTATE_AFTER_MESSAGES).saturating_mul(percent) / 100,
            )
            .unwrap_or(ROTATE_AFTER_MESSAGES),
            sent: 0,
            new_address_sent_at: None,
            record_on_new_queue: false,
        }
    }

    /// Counts one accepted send on the queue.
    pub fn sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    /// Whether the first of the two limits occurred (`ROTATE_AFTER`), and a
    /// new queue is due before the next send (`WIR-033`).
    pub fn due(&self, now: u64) -> bool {
        now.saturating_sub(self.made_at) >= self.age_limit || self.sent >= self.count_limit
    }

    /// The owner sent the new `QueueAddress` at `now` (`NET-176`).
    pub fn new_address_sent(&mut self, now: u64) {
        self.new_address_sent_at = Some(now);
    }

    /// A record arrived on the new queue.
    pub fn record_on_new_queue(&mut self) {
        self.record_on_new_queue = true;
    }

    /// Whether the `DEL` of the old queue may go (`NET-177`, `NET-178`).
    pub fn may_delete_old(&self, now: u64) -> bool {
        self.record_on_new_queue
            || self
                .new_address_sent_at
                .is_some_and(|at| now.saturating_sub(at) >= ROTATE_GRACE)
    }
}

/// Whether a channel is silent: a record that the client sent holds no
/// delivery receipt `DEAD_CHANNEL_SILENCE` after its send (§3.2.6).
pub const fn silent(sent_at: u64, now: u64) -> bool {
    now.saturating_sub(sent_at) >= DEAD_CHANNEL_SILENCE
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
    fn the_first_limit_applies_under_the_jitter() {
        let low = Rotation::new(0, 0);
        assert!(low.due(ROTATE_AFTER_SECONDS * 80 / 100));
        assert!(!low.due(ROTATE_AFTER_SECONDS * 80 / 100 - 1));
        let high = Rotation::new(0, 40);
        assert!(!high.due(ROTATE_AFTER_SECONDS));
        assert!(high.due(ROTATE_AFTER_SECONDS * 120 / 100));
        let mut counted = Rotation::new(0, 20);
        for _ in 0..ROTATE_AFTER_MESSAGES {
            counted.sent();
        }
        assert!(counted.due(1));
        assert!(!counted.may_delete_old(1));
        counted.new_address_sent(1);
        assert!(!counted.may_delete_old(1 + ROTATE_GRACE - 1));
        assert!(counted.may_delete_old(1 + ROTATE_GRACE));
        let mut fast = Rotation::new(0, 20);
        fast.new_address_sent(1);
        fast.record_on_new_queue();
        assert!(fast.may_delete_old(2));
        assert!(silent(0, DEAD_CHANNEL_SILENCE));
        assert!(!silent(0, DEAD_CHANNEL_SILENCE - 1));
    }
}
