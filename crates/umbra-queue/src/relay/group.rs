//! A group queue at a relay: the retained records, the sequence, the post
//! rate, and the two graces of a credential rotation. The notifier set of
//! Part 8 §8.5.2 sits with the digest gate at the service.

use alloc::{collections::VecDeque, vec::Vec};

use umbra_crypto::stored::{Reader, Writer};

use crate::{
    params::{
        store_grace_time, store_time, GROUP_IDLE_TTL, GROUP_POST_RATE, GROUP_POST_WINDOW,
        GROUP_QUEUE_QUOTA, GROUP_READ_GRACE, GROUP_RETENTION, GROUP_WRITE_GRACE,
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
        // A second GKEY with the same key changes nothing (GRP-363), thus
        // the key of the epoch before keeps its grace.
        if pk == self.current {
            return;
        }
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

    fn pair(&self, now: u64) -> ([u8; 32], Option<[u8; 32]>) {
        let previous = self
            .previous
            .filter(|(_, at)| now.saturating_sub(*at) < self.grace)
            .map(|(pk, _)| pk);
        (self.current, previous)
    }

    fn export(&self, writer: &mut Writer) {
        writer.bytes(&self.current);
        writer.option(self.previous.as_ref(), |w, (pk, at)| {
            w.bytes(pk);
            w.u64(store_grace_time(*at));
        });
    }

    fn import(reader: &mut Reader<'_>, grace: u64) -> Result<Self, umbra_crypto::Error> {
        Ok(Credential {
            current: reader.array()?,
            previous: reader.option(|r| Ok((r.array()?, r.u64()?)))?,
            grace,
        })
    }

    fn expire(&mut self, now: u64) {
        if let Some((_, at)) = self.previous {
            if now.saturating_sub(at) >= self.grace {
                self.previous = None;
            }
        }
    }
}

/// The result of an accepted `GPOST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Posted {
    /// The sequence of the record.
    pub seq: u32,
    /// Whether the bytes are new here. A second send of one record is
    /// idempotent (`NET-239`), and it moves no reader.
    pub fresh: bool,
    /// The quota took each record at or below this sequence (`NET-247`).
    pub dropped_through: Option<u32>,
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

    /// The reader credentials that authorize a command at `now`: the
    /// current one, and the previous one while its grace holds.
    pub fn read_pks(&self, now: u64) -> ([u8; 32], Option<[u8; 32]>) {
        self.read.pair(now)
    }

    /// The writer credentials that authorize a `GPOST` at `now`.
    pub fn write_pks(&self, now: u64) -> ([u8; 32], Option<[u8; 32]>) {
        self.write.pair(now)
    }

    /// Applies a `GKEY` (`NET-242`). The owner credential takes no grace:
    /// a new one ends the old one at once (`WIR-522`).
    pub fn rotate(&mut self, read_pk: [u8; 32], write_pk: [u8; 32], own_pk: [u8; 32], now: u64) {
        self.read.rotate(read_pk, now);
        self.write.rotate(write_pk, now);
        self.own_pk = own_pk;
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
    pub fn post(&mut self, record: &[u8], now: u64) -> Result<Posted, Reject> {
        if let Some(held) = self.records.iter().find(|r| r.bytes == record) {
            return Ok(Posted {
                seq: held.seq,
                fresh: false,
                dropped_through: None,
            });
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
        let mut dropped_through = None;
        while self.bytes > GROUP_QUEUE_QUOTA {
            match self.records.pop_front() {
                Some(old) => {
                    self.bytes = self.bytes.saturating_sub(old.bytes.len());
                    dropped_through = Some(old.seq);
                }
                None => break,
            }
        }
        self.last_activity = now;
        Ok(Posted {
            seq,
            fresh: true,
            dropped_through,
        })
    }

    /// Writes the head of the queue: its identifier, its three credentials
    /// with the previous pair of a rotation, its sequence, and the time of
    /// its last activity. The records travel beside it.
    pub fn export_head(&self, writer: &mut Writer) {
        writer.bytes(&self.id);
        self.read.export(writer);
        self.write.export(writer);
        writer.bytes(&self.own_pk);
        writer.u32(self.next_seq);
        writer.u64(store_time(self.last_activity));
    }

    /// A group queue from the head that [`GroupQueue::export_head`] wrote
    /// and from its stored records. A record at or above `next_seq` and a
    /// set above the quota are faults of the store.
    pub fn restore(reader: &mut Reader<'_>, mut records: Vec<Stored>) -> Result<Self, Reject> {
        let mut head = || -> Result<GroupQueue, umbra_crypto::Error> {
            Ok(GroupQueue {
                id: reader.array()?,
                read: Credential::import(reader, GROUP_READ_GRACE)?,
                write: Credential::import(reader, GROUP_WRITE_GRACE)?,
                own_pk: reader.array()?,
                records: VecDeque::new(),
                bytes: 0,
                next_seq: reader.u32()?,
                // The rate of a new run starts empty, and a restart is no
                // way past `GROUP_POST_RATE`: it costs a run of the relay.
                posts: VecDeque::new(),
                last_activity: reader.u64()?,
            })
        };
        let mut queue = head().map_err(|_| Reject::Rejected)?;
        records.sort_by_key(|record| record.seq);
        let bytes: usize = records.iter().map(|record| record.bytes.len()).sum();
        if bytes > GROUP_QUEUE_QUOTA || records.iter().any(|record| record.seq >= queue.next_seq) {
            return Err(Reject::Rejected);
        }
        queue.bytes = bytes;
        queue.records = records.into();
        Ok(queue)
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
    /// previous credential past its grace (`WIR-395`). The result is the
    /// highest sequence that left, for the store.
    pub fn expire(&mut self, now: u64) -> Option<u32> {
        let mut dropped_through = None;
        while self
            .records
            .front()
            .is_some_and(|r| now.saturating_sub(r.accepted_at) >= GROUP_RETENTION)
        {
            if let Some(old) = self.records.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.bytes.len());
                dropped_through = Some(old.seq);
            }
        }
        self.read.expire(now);
        self.write.expire(now);
        dropped_through
    }

    /// Whether the queue passed `GROUP_IDLE_TTL` with no activity
    /// (`NET-249`).
    pub fn idle(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) >= GROUP_IDLE_TTL
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
        assert_eq!(
            q.post(b"a", 1_000).unwrap(),
            Posted {
                seq: 1,
                fresh: true,
                dropped_through: None,
            }
        );
        assert_eq!(
            q.post(b"a", 1_001).unwrap(),
            Posted {
                seq: 1,
                fresh: false,
                dropped_through: None,
            }
        );
        assert_eq!(q.post(b"b", 1_001).unwrap().seq, 2);
        for i in 0..(GROUP_POST_RATE - 2) {
            q.post(&[9, i as u8], 1_002).unwrap();
        }
        assert_eq!(q.post(b"z", 1_003), Err(Reject::Limit));
        assert_eq!(q.post(b"z", 1_000 + GROUP_POST_WINDOW).unwrap().seq, 61);
        let since: Vec<u32> = q.since(59).map(|r| r.seq).collect();
        assert_eq!(since, vec![60, 61]);
    }

    #[test]
    fn the_graces_of_a_rotation_hold() {
        let mut q = queue();
        q.rotate([5; 32], [6; 32], [4; 32], 2_000);
        assert!(q.accepts_read(&[5; 32], 2_000));
        assert!(q.accepts_read(&[2; 32], 2_000 + GROUP_READ_GRACE - 1));
        assert!(!q.accepts_read(&[2; 32], 2_000 + GROUP_READ_GRACE));
        assert!(q.accepts_write(&[3; 32], 2_000 + GROUP_WRITE_GRACE - 1));
        assert!(!q.accepts_write(&[3; 32], 2_000 + GROUP_WRITE_GRACE));
        q.expire(2_000 + GROUP_WRITE_GRACE);
        assert!(!q.accepts_write(&[3; 32], 2_000));
        assert!(q.accepts_read(&[2; 32], 2_000));
        // A second GKEY inside the grace replaces the previous key.
        // WIR-522: a new owner key ends the old one with no grace.
        q.rotate([7; 32], [8; 32], [9; 32], 3_000);
        assert_eq!(q.own_pk(), [9; 32]);
        assert!(q.accepts_read(&[5; 32], 3_000));
        assert!(!q.accepts_read(&[2; 32], 3_000));
        assert_eq!(q.read_pks(3_000), ([7; 32], Some([5; 32])));
        assert_eq!(q.write_pks(3_000 + GROUP_WRITE_GRACE), ([8; 32], None));
    }

    #[test]
    fn a_stored_queue_comes_back_with_its_records_and_its_graces() {
        let mut q = queue();
        q.post(b"one", 1_000).unwrap();
        q.post(b"two", 1_001).unwrap();
        q.rotate([5; 32], [6; 32], [4; 32], 2_000);
        let records: Vec<Stored> = q.since(0).cloned().collect();
        let mut writer = Writer::new();
        q.export_head(&mut writer);
        let head = writer.finish();

        let mut reader = Reader::new(&head);
        let back = GroupQueue::restore(&mut reader, records).unwrap();
        assert_eq!(back.id(), [1; 32]);
        assert_eq!(back.own_pk(), [4; 32]);
        assert_eq!(back.len(), 2);
        // The sequence continues, thus no record takes the number of an
        // earlier one (`NET-232`).
        assert_eq!(back.since(0).map(|r| r.seq).collect::<Vec<_>>(), [1, 2]);
        let mut back = back;
        assert_eq!(back.post(b"three", 2_001).unwrap().seq, 3);
        // The previous credentials of the rotation came back with it.
        assert!(back.accepts_read(&[2; 32], 2_100));
        assert!(back.accepts_write(&[3; 32], 2_100));
        assert!(!back.accepts_write(&[3; 32], 2_000 + GROUP_WRITE_GRACE));

        // A record at or above the next sequence is a fault of the store.
        let mut reader = Reader::new(&head);
        let ahead = alloc::vec![Stored {
            seq: 9,
            accepted_at: 1_000,
            bytes: alloc::vec![0; 4],
        }];
        assert!(GroupQueue::restore(&mut reader, ahead).is_err());
    }

    #[test]
    fn the_retention_the_quota_and_the_idle_life_hold() {
        let mut q = queue();
        q.post(b"old", 1_000).unwrap();
        q.post(b"new", 1_000 + GROUP_RETENTION - 1).unwrap();
        assert_eq!(q.expire(1_000 + GROUP_RETENTION), Some(1));
        assert_eq!(q.len(), 1);
        let big = vec![0u8; GROUP_QUEUE_QUOTA / 2 + 1];
        let mut other = big.clone();
        other[0] = 1;
        q.post(&big, 5_000).unwrap();
        assert_eq!(q.post(&other, 5_001).unwrap().dropped_through, Some(3));
        assert_eq!(q.len(), 1);
        assert!(q.idle(5_001 + GROUP_IDLE_TTL));
        q.touch(9_000_000);
        assert!(!q.idle(9_000_000 + GROUP_IDLE_TTL - 1));
        assert_eq!(q.id(), [1; 32]);
        assert_eq!(q.own_pk(), [4; 32]);
        assert_eq!(q.delete().len(), 1);
    }
}
