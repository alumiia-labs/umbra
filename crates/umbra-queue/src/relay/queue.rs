//! A pairwise queue at a relay: the quota, the sequence, the cumulative
//! acknowledgment, the two lifetimes, and the notifier credential.

use alloc::{vec, vec::Vec};

use crate::{
    params::{MSG_TTL, QUEUE_IDLE_TTL, QUEUE_QUOTA},
    relay::Stored,
    Reject,
};

/// The two identifiers and the three public keys of one queue.
pub struct QueueKeys {
    /// `RecipientId`, known to the owner.
    pub recipient_id: [u8; 32],
    /// `SenderId`, known to the writers.
    pub sender_id: [u8; 32],
    /// `QR_auth`.
    pub qr_auth_pk: [u8; 32],
    /// `QS_auth`.
    pub qs_auth_pk: [u8; 32],
}

/// A pairwise queue.
pub struct Queue {
    keys: QueueKeys,
    records: Vec<Stored>,
    next_seq: u32,
    last_ack: u32,
    notifier: Option<([u8; 32], [u8; 32])>,
    last_activity: u64,
    subscribed: bool,
}

impl Queue {
    /// Makes a queue at `now`. The relay drew the two identifiers from its
    /// CSPRNG (`NET-004`).
    pub fn new(keys: QueueKeys, now: u64) -> Self {
        Queue {
            keys,
            records: Vec::new(),
            next_seq: 1,
            last_ack: 0,
            notifier: None,
            last_activity: now,
            subscribed: false,
        }
    }

    /// The identifiers and keys.
    pub fn keys(&self) -> &QueueKeys {
        &self.keys
    }

    /// The records the queue holds.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the queue holds no record.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The capacity left under `QUEUE_QUOTA`, which a `QUOTA` reports
    /// (`NET-017`).
    pub fn remaining(&self) -> usize {
        QUEUE_QUOTA.saturating_sub(self.records.len())
    }

    /// Accepts a `SEND` and returns its sequence number (§6.4.3 rule 5).
    /// Rejects at the quota (`NET-016`).
    pub fn send(&mut self, record: &[u8], now: u64) -> Result<u32, Reject> {
        if self.records.len() >= QUEUE_QUOTA {
            return Err(Reject::Limit);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(Reject::Busy)?;
        self.records.push(Stored {
            seq,
            accepted_at: now,
            bytes: record.to_vec(),
        });
        self.last_activity = now;
        Ok(seq)
    }

    /// Records a `SUB` (`NET-195`) or an `UNSUB`.
    pub fn subscribe(&mut self, on: bool, now: u64) {
        self.subscribed = on;
        if on {
            self.last_activity = now;
        }
    }

    /// Whether a session holds a subscription.
    pub fn subscribed(&self) -> bool {
        self.subscribed
    }

    /// The records that no `ACK` covers, in sequence order, which a relay
    /// emits as `MSG` (`WIR-110`).
    pub fn pending(&self) -> impl Iterator<Item = &Stored> {
        self.records.iter().filter(move |r| r.seq > self.last_ack)
    }

    /// Applies a cumulative `ACK` at `seq` (`WIR-048`). An `ACK` below the
    /// last one changes nothing.
    pub fn ack(&mut self, seq: u32) {
        if seq <= self.last_ack {
            return;
        }
        self.last_ack = seq;
        self.records.retain(|r| r.seq > seq);
    }

    /// Erases each record older than `MSG_TTL` (`WIR-111`).
    pub fn expire(&mut self, now: u64) {
        self.records
            .retain(|r| now.saturating_sub(r.accepted_at) < MSG_TTL);
    }

    /// Whether the queue passed `QUEUE_IDLE_TTL` with no activity.
    pub fn idle(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) >= QUEUE_IDLE_TTL
    }

    /// Stores the notifier credential of an `NKEY` and returns the
    /// `notifier_id` the relay drew for it.
    pub fn set_notifier(&mut self, notifier_pk: [u8; 32], notifier_id: [u8; 32]) {
        self.notifier = Some((notifier_pk, notifier_id));
    }

    /// The notifier credential, if one is set.
    pub fn notifier(&self) -> Option<&([u8; 32], [u8; 32])> {
        self.notifier.as_ref()
    }

    /// Erases everything a `DEL` erases (`WIR-039` to `WIR-042`), and
    /// returns the record bytes so the caller can zeroize them.
    pub fn delete(self) -> Vec<Vec<u8>> {
        let mut out = vec![];
        for r in self.records {
            out.push(r.bytes);
        }
        out
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

    fn queue() -> Queue {
        Queue::new(
            QueueKeys {
                recipient_id: [1; 32],
                sender_id: [2; 32],
                qr_auth_pk: [3; 32],
                qs_auth_pk: [4; 32],
            },
            1_000,
        )
    }

    #[test]
    fn the_sequence_starts_at_one_and_the_ack_is_cumulative() {
        let mut q = queue();
        assert_eq!(q.send(b"a", 1_000).unwrap(), 1);
        assert_eq!(q.send(b"b", 1_001).unwrap(), 2);
        assert_eq!(q.send(b"c", 1_002).unwrap(), 3);
        assert_eq!(q.pending().count(), 3);
        q.ack(2);
        let left: Vec<u32> = q.pending().map(|r| r.seq).collect();
        assert_eq!(left, vec![3]);
        q.ack(1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.send(b"d", 1_003).unwrap(), 4);
    }

    #[test]
    fn the_quota_and_the_two_lifetimes_hold() {
        let mut q = queue();
        for i in 0..QUEUE_QUOTA {
            q.send(&[0], 1_000 + i as u64).unwrap();
        }
        assert_eq!(q.remaining(), 0);
        assert_eq!(q.send(&[0], 2_000), Err(Reject::Limit));
        q.expire(1_000 + MSG_TTL + 10);
        assert_eq!(q.len(), QUEUE_QUOTA - 11);
        assert!(!q.idle(1_000 + QUEUE_QUOTA as u64 + QUEUE_IDLE_TTL - 2));
        assert!(q.idle(1_000 + QUEUE_QUOTA as u64 + QUEUE_IDLE_TTL));
        q.subscribe(true, 5_000_000);
        assert!(!q.idle(5_000_000 + QUEUE_IDLE_TTL - 1));
        q.set_notifier([7; 32], [8; 32]);
        assert_eq!(q.notifier().unwrap().1, [8; 32]);
        assert!(!q.delete().is_empty());
    }
}
