//! A group queue at a relay: the retained records, the sequence, the post
//! rate, the two graces of a credential rotation, and the notifier set.

use alloc::{collections::VecDeque, vec::Vec};

use crate::{
    params::{
        GROUP_IDLE_TTL, GROUP_NOTIFIER_MAX, GROUP_POST_RATE, GROUP_POST_WINDOW, GROUP_QUEUE_QUOTA,
        GROUP_READ_GRACE, GROUP_RETENTION, GROUP_WRITE_GRACE,
    },
    relay::Stored,
    Reject,
};

/// A credential with the previous value it replaced, held for a grace.
struct Credential {
    current: [u8; 32],
    previous: Option<([u8; 32], u64)>,
    grace: u64,
}

impl Credential {
    fn new(pk: [u8; 32], grace: u64) -> Self {
        Credential {
            current: pk,
            previous: None,
            grace,
        }
    }

    fn rotate(&mut self, pk: [u8; 32], now: u64) {
        // A second GKEY inside a grace replaces the previous key (WIR-397).
        self.previous = Some((self.current, now));
        self.current = pk;
    }

    fn accepts(&self, pk: &[u8; 32], now: u64) -> bool {
        if *pk == self.current {
            return true;
        }
        matches!(self.previous, Some((prev, at)) if prev == *pk && now.saturating_sub(at) < self.grace)
    }

    fn expire(&mut self, now: u64) {
        if let Some((_, at)) = self.previous {
            if now.saturating_sub(at) >= self.grace {
                self.previous = None;
            }
        }
    }
}

/// A group queue.
pub struct GroupQueue {
    id: [u8; 32],
    read: Credential,
    write: Credential,
    own_pk: [u8; 32],
    records: VecDeque<Stored>,
    bytes: usize,
    next_seq: u32,
    posts: VecDeque<u64>,
    notifiers: Vec<[u8; 32]>,
    last_activity: u64,
}

impl GroupQueue {
    /// Makes a group queue at `now`. The relay drew `id` from its CSPRNG
    /// (`NET-224`).
    pub fn new(
        id: [u8; 32],
        read_pk: [u8; 32],
        write_pk: [u8; 32],
        own_pk: [u8; 32],
        now: u64,
    ) -> Self {
        GroupQueue {
            id,
            read: Credential::new(read_pk, GROUP_READ_GRACE),
            write: Credential::new(write_pk, GROUP_WRITE_GRACE),
            own_pk,
            records: VecDeque::new(),
            bytes: 0,
            next_seq: 1,
            posts: VecDeque::new(),
            notifiers: Vec::new(),
            last_activity: now,
        }
    }

    /// The `GroupQueueId`.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// The owner credential.
    pub fn own_pk(&self) -> [u8; 32] {
        self.own_pk
    }

    /// Whether `pk` authorizes a reader command at `now` (`NET-243`).
    pub fn accepts_read(&self, pk: &[u8; 32], now: u64) -> bool {
        self.read.accepts(pk, now)
    }

    /// Whether `pk` authorizes a `GPOST` at `now` (`NET-243`).
    pub fn accepts_write(&self, pk: &[u8; 32], now: u64) -> bool {
        self.write.accepts(pk, now)
    }

    /// Applies a `GKEY` (`NET-242`).
    pub fn rotate(&mut self, read_pk: [u8; 32], write_pk: [u8; 32], now: u64) {
        self.read.rotate(read_pk, now);
        self.write.rotate(write_pk, now);
    }

    /// The records held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the queue holds no record.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Accepts a `GPOST` and returns its `seq`. A record whose bytes the
    /// relay already holds returns the `seq` it holds (`NET-239`); a post
    /// above `GROUP_POST_RATE` is rejected with `LIMIT` (`NET-241`); the
    /// oldest record leaves at the quota (`NET-247`).
    pub fn post(&mut self, record: &[u8], now: u64) -> Result<u32, Reject> {
        if let Some(held) = self.records.iter().find(|r| r.bytes == record) {
            return Ok(held.seq);
        }
        while self
            .posts
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= GROUP_POST_WINDOW)
        {
            self.posts.pop_front();
        }
        if self.posts.len() >= GROUP_POST_RATE {
            return Err(Reject::Limit);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(Reject::Busy)?;
        self.posts.push_back(now);
        self.records.push_back(Stored {
            seq,
            accepted_at: now,
            bytes: record.to_vec(),
        });
        self.bytes = self.bytes.saturating_add(record.len());
        while self.bytes > GROUP_QUEUE_QUOTA {
            match self.records.pop_front() {
                Some(old) => self.bytes = self.bytes.saturating_sub(old.bytes.len()),
                None => break,
            }
        }
        self.last_activity = now;
        Ok(seq)
    }

    /// The retained records above `from_seq`, in `seq` order, which a
    /// `GSUB` emits (`WIR-387`).
    pub fn since(&self, from_seq: u32) -> impl Iterator<Item = &Stored> {
        self.records.iter().filter(move |r| r.seq > from_seq)
    }

    /// Records a `GSUB` as activity (`NET-250`).
    pub fn touch(&mut self, now: u64) {
        self.last_activity = now;
    }

    /// Erases each record past `GROUP_RETENTION` (`NET-246`) and each
    /// previous credential past its grace (`WIR-395`).
    pub fn expire(&mut self, now: u64) {
        while self
            .records
            .front()
            .is_some_and(|r| now.saturating_sub(r.accepted_at) >= GROUP_RETENTION)
        {
            if let Some(old) = self.records.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.bytes.len());
            }
        }
        self.read.expire(now);
        self.write.expire(now);
    }

    /// Whether the queue passed `GROUP_IDLE_TTL` with no activity
    /// (`NET-249`).
    pub fn idle(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) >= GROUP_IDLE_TTL
    }

    /// Adds a notifier from a `GNREG`, keyed by the `sender_id` of its
    /// notify queue. Rejects above `GROUP_NOTIFIER_MAX` (`NET-252`).
    pub fn register(&mut self, notify_sender_id: [u8; 32]) -> Result<(), Reject> {
        if self.notifiers.contains(&notify_sender_id) {
            return Ok(());
        }
        if self.notifiers.len() >= GROUP_NOTIFIER_MAX {
            return Err(Reject::Limit);
        }
        self.notifiers.push(notify_sender_id);
        Ok(())
    }

    /// Removes a notifier at a `GNUNREG`.
    pub fn unregister(&mut self, notify_sender_id: &[u8; 32]) {
        self.notifiers.retain(|n| n != notify_sender_id);
    }

    /// The count of notifiers.
    pub fn notifier_count(&self) -> usize {
        self.notifiers.len()
    }

    /// Erases everything a `GDEL` erases (`NET-244`).
    pub fn delete(self) -> Vec<Vec<u8>> {
        self.records.into_iter().map(|r| r.bytes).collect()
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
    use alloc::vec;

    fn queue() -> GroupQueue {
        GroupQueue::new([1; 32], [2; 32], [3; 32], [4; 32], 1_000)
    }

    #[test]
    fn a_post_is_idempotent_and_the_rate_holds() {
        let mut q = queue();
        assert_eq!(q.post(b"a", 1_000).unwrap(), 1);
        assert_eq!(q.post(b"a", 1_001).unwrap(), 1);
        assert_eq!(q.post(b"b", 1_001).unwrap(), 2);
        for i in 0..(GROUP_POST_RATE - 2) {
            q.post(&[9, i as u8], 1_002).unwrap();
        }
        assert_eq!(q.post(b"z", 1_003), Err(Reject::Limit));
        assert_eq!(q.post(b"z", 1_000 + GROUP_POST_WINDOW).unwrap(), 61);
        let since: Vec<u32> = q.since(59).map(|r| r.seq).collect();
        assert_eq!(since, vec![60, 61]);
    }

    #[test]
    fn the_graces_of_a_rotation_hold() {
        let mut q = queue();
        q.rotate([5; 32], [6; 32], 2_000);
        assert!(q.accepts_read(&[5; 32], 2_000));
        assert!(q.accepts_read(&[2; 32], 2_000 + GROUP_READ_GRACE - 1));
        assert!(!q.accepts_read(&[2; 32], 2_000 + GROUP_READ_GRACE));
        assert!(q.accepts_write(&[3; 32], 2_000 + GROUP_WRITE_GRACE - 1));
        assert!(!q.accepts_write(&[3; 32], 2_000 + GROUP_WRITE_GRACE));
        q.expire(2_000 + GROUP_WRITE_GRACE);
        assert!(!q.accepts_write(&[3; 32], 2_000));
        assert!(q.accepts_read(&[2; 32], 2_000));
        // A second GKEY inside the grace replaces the previous key.
        q.rotate([7; 32], [8; 32], 3_000);
        assert!(q.accepts_read(&[5; 32], 3_000));
        assert!(!q.accepts_read(&[2; 32], 3_000));
    }

    #[test]
    fn retention_quota_idle_and_notifiers_hold() {
        let mut q = queue();
        q.post(b"old", 1_000).unwrap();
        q.post(b"new", 1_000 + GROUP_RETENTION - 1).unwrap();
        q.expire(1_000 + GROUP_RETENTION);
        assert_eq!(q.len(), 1);
        let big = vec![0u8; GROUP_QUEUE_QUOTA / 2 + 1];
        let mut other = big.clone();
        other[0] = 1;
        q.post(&big, 5_000).unwrap();
        q.post(&other, 5_001).unwrap();
        assert_eq!(q.len(), 1);
        assert!(q.idle(5_001 + GROUP_IDLE_TTL));
        q.touch(9_000_000);
        assert!(!q.idle(9_000_000 + GROUP_IDLE_TTL - 1));
        for i in 0..GROUP_NOTIFIER_MAX {
            let mut id = [0u8; 32];
            id[..2].copy_from_slice(&(i as u16).to_be_bytes());
            q.register(id).unwrap();
        }
        assert_eq!(q.register([0xFF; 32]), Err(Reject::Limit));
        q.unregister(&[0; 32]);
        assert_eq!(q.notifier_count(), GROUP_NOTIFIER_MAX - 1);
        assert_eq!(q.id(), [1; 32]);
        assert_eq!(q.own_pk(), [4; 32]);
    }
}
