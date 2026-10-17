//! The digest path of a group queue (Part 8 §8.5.1, §8.5.2): the
//! `NotifyDigest` record, the registrations a relay holds in memory, and
//! the minimum gap of a group.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_wire::codec::{Reader, Writer};

use super::{GROUP_DIGEST_MIN_GAP, REGISTRATION_MAX, REGISTRATION_TTL};
use crate::Error;

/// The length of a `NotifyDigest`.
pub const DIGEST_LEN: usize = 34;

/// The L6 record of kind `0x04`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyDigest {
    /// The `GroupQueueId` of the group (`NTF-099`).
    pub id: [u8; 32],
    /// The posts since the previous digest, saturated at 255.
    pub post_count: u8,
}

impl NotifyDigest {
    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.id)?;
        w.u8(self.post_count)?;
        Ok(w.position())
    }

    /// Reads a record.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let out = NotifyDigest {
            id: r.array()?,
            post_count: r.u8()?,
        };
        r.finish()?;

        Ok(out)
    }
}

/// The digest policy of a relay class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// A group-queue relay: one digest in each `GROUP_DIGEST_MIN_GAP`, with
    /// one at the end of the gap when a record arrived inside it
    /// (`NTF-096` to `NTF-098`).
    Group,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Registered {
    registered_at: u64,
    last_digest: Option<u64>,
    unsent: u32,
}

/// The registrations of one group queue, keyed by the
/// `sender_id` of the notify queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestGate {
    policy: Policy,
    registrations: BTreeMap<[u8; 32], Registered>,
}

/// A digest to write as a `SEND` into a notify queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Due {
    /// The registration.
    pub queue: [u8; 32],
    /// The posts since the previous digest to it.
    pub post_count: u8,
}

impl DigestGate {
    /// A gate under `policy`.
    pub const fn new(policy: Policy) -> Self {
        DigestGate {
            policy,
            registrations: BTreeMap::new(),
        }
    }

    /// Registers a notify queue (`NTF-100`, `NTF-101`).
    pub fn register(&mut self, queue: [u8; 32], now: u64) -> Result<(), Error> {
        if self.registrations.contains_key(&queue) {
            return Ok(());
        }
        if self.registrations.len() >= REGISTRATION_MAX {
            return Err(Error::NoPath);
        }

        self.registrations.insert(
            queue,
            Registered {
                registered_at: now,
                last_digest: None,
                unsent: 0,
            },
        );
        Ok(())
    }

    /// Drops a registration (`NTF-103`).
    pub fn unregister(&mut self, queue: &[u8; 32]) {
        self.registrations.remove(queue);
    }

    /// Whether the gate holds the registration of `queue`.
    pub fn holds(&self, queue: &[u8; 32]) -> bool {
        self.registrations.contains_key(queue)
    }

    /// The registrations held.
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    fn allowed(policy: Policy, r: &Registered, now: u64) -> bool {
        match policy {
            Policy::Group => r
                .last_digest
                .is_none_or(|at| now.saturating_sub(at) >= GROUP_DIGEST_MIN_GAP),
        }
    }

    fn take(queue: [u8; 32], r: &mut Registered, now: u64) -> Due {
        let count = u8::try_from(r.unsent).unwrap_or(u8::MAX);
        r.unsent = 0;
        r.last_digest = Some(now);
        Due {
            queue,
            post_count: count,
        }
    }

    /// A post at `now`: the digests to write at once. A registration that
    /// the policy holds back keeps the post for the next tick.
    pub fn on_post(&mut self, now: u64) -> Vec<Due> {
        let policy = self.policy;
        let mut due = Vec::new();
        for (queue, r) in &mut self.registrations {
            r.unsent = r.unsent.saturating_add(1);
            if Self::allowed(policy, r, now) {
                due.push(Self::take(*queue, r, now));
            }
        }

        due
    }

    /// The digests due at `now` for posts held back, and the registrations
    /// past their retention dropped (`NTF-102`).
    pub fn tick(&mut self, now: u64) -> Vec<Due> {
        self.registrations
            .retain(|_, r| now.saturating_sub(r.registered_at) < REGISTRATION_TTL);

        let policy = self.policy;
        let mut due = Vec::new();
        for (queue, r) in &mut self.registrations {
            if r.unsent > 0 && Self::allowed(policy, r, now) {
                due.push(Self::take(*queue, r, now));
            }
        }

        due
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_round_trips_and_a_group_gate_keeps_the_gap() {
        let d = NotifyDigest {
            id: [1; 32],
            post_count: 7,
        };
        let mut out = [0u8; DIGEST_LEN];
        assert_eq!(d.encode(&mut out).unwrap(), DIGEST_LEN);
        assert_eq!(NotifyDigest::parse(&out).unwrap(), d);
        assert!(NotifyDigest::parse(&out[..33]).is_err());

        let mut gate = DigestGate::new(Policy::Group);
        gate.register([1; 32], 0).unwrap();
        gate.register([1; 32], 0).unwrap();
        assert_eq!(gate.len(), 1);

        let first = gate.on_post(100);
        assert_eq!(
            first,
            alloc::vec![Due {
                queue: [1; 32],
                post_count: 1
            }]
        );

        assert!(gate.on_post(105).is_empty());
        assert!(gate.on_post(108).is_empty());
        assert!(gate.tick(109).is_empty());
        let end = gate.tick(110);
        assert_eq!(end[0].post_count, 2);
        assert!(gate.tick(111).is_empty());

        gate.unregister(&[1; 32]);
        assert!(gate.is_empty());

        gate.register([2; 32], 0).unwrap();
        assert!(gate.tick(REGISTRATION_TTL).is_empty());
        assert!(gate.is_empty());
    }
}
