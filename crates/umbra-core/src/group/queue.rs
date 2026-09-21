//! The client side of the group queue (Part 11 §11.2): the two replicas
//! under different operators and blocs, the cursor of each, the
//! subscription that alternates, the post that waits for the newest
//! epoch-key record, and the state when no replica answers.

use alloc::vec::Vec;

use umbra_crypto::stored::{Reader, Writer};
use umbra_wire::group::control::ReplicaRef;

use super::{roster::STORED_VERSION, GROUP_REPLICAS};
use crate::Error;

/// A relay a creator may put a group queue on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The relay.
    pub relay_id: [u8; 32],
    /// The operator.
    pub operator_id: [u8; 32],
    /// The jurisdiction bloc.
    pub bloc: u8,
}

/// The pair a creator selected, and whether the bloc invariant was relaxed
/// (`GRP-191`, `GRP-192`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// The two relays.
    pub relays: [[u8; 32]; GROUP_REPLICAS],
    /// Whether the two share a bloc.
    pub relaxed: bool,
}

/// Selects two relays under different operators, and under different
/// blocs when such a pair exists.
pub fn select_pair(candidates: &[Candidate]) -> Result<Pair, Error> {
    for (i, a) in candidates.iter().enumerate() {
        for b in candidates.iter().skip(i.saturating_add(1)) {
            if a.operator_id != b.operator_id && a.bloc != b.bloc {
                return Ok(Pair {
                    relays: [a.relay_id, b.relay_id],
                    relaxed: false,
                });
            }
        }
    }
    for (i, a) in candidates.iter().enumerate() {
        for b in candidates.iter().skip(i.saturating_add(1)) {
            if a.operator_id != b.operator_id {
                return Ok(Pair {
                    relays: [a.relay_id, b.relay_id],
                    relaxed: true,
                });
            }
        }
    }
    Err(Error::NoPath)
}

/// The reader state over the two replicas of one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replicas {
    refs: [ReplicaRef; GROUP_REPLICAS],
    cursors: [u32; GROUP_REPLICAS],
    newest_epoch_key: [Option<u32>; GROUP_REPLICAS],
    last_subscribed: Option<usize>,
    reachable: [bool; GROUP_REPLICAS],
}

impl Replicas {
    /// The replicas of an admit, with the cursor at the `seq` of the add
    /// (`GRP-313`).
    pub fn from_admit(refs: [ReplicaRef; GROUP_REPLICAS]) -> Self {
        Replicas {
            cursors: [refs[0].seq_of_add, refs[1].seq_of_add],
            refs,
            newest_epoch_key: [None, None],
            last_subscribed: None,
            reachable: [true, true],
        }
    }

    /// The replicas of a creator, from `seq` 0.
    pub fn fresh(refs: [ReplicaRef; GROUP_REPLICAS]) -> Self {
        Replicas {
            refs,
            cursors: [0, 0],
            newest_epoch_key: [None, None],
            last_subscribed: None,
            reachable: [true, true],
        }
    }

    /// Writes the replica state to its stored form.
    pub fn export(&self, w: &mut Writer) {
        w.u8(STORED_VERSION);
        for index in 0..GROUP_REPLICAS {
            let Some(reference) = self.refs.get(index) else {
                continue;
            };
            w.bytes(&reference.relay_id);
            w.bytes(&reference.group_queue_id);
            w.u32(reference.seq_of_add);
            w.u32(self.cursors.get(index).copied().unwrap_or(0));
            w.option(
                self.newest_epoch_key.get(index).copied().flatten().as_ref(),
                |w, seq| w.u32(*seq),
            );
            w.flag(self.reachable.get(index).copied().unwrap_or(false));
        }
        w.option(self.last_subscribed.as_ref(), |w, which| {
            w.u8(u8::try_from(*which).unwrap_or(0));
        });
    }

    /// Reads a replica state that [`Replicas::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.u8()? != STORED_VERSION {
            return Err(Error::Stale);
        }
        let mut refs = [ReplicaRef {
            relay_id: [0; 32],
            group_queue_id: [0; 32],
            seq_of_add: 0,
        }; GROUP_REPLICAS];
        let mut cursors = [0u32; GROUP_REPLICAS];
        let mut newest_epoch_key = [None; GROUP_REPLICAS];
        let mut reachable = [false; GROUP_REPLICAS];
        for index in 0..GROUP_REPLICAS {
            let reference = ReplicaRef {
                relay_id: r.array()?,
                group_queue_id: r.array()?,
                seq_of_add: r.u32()?,
            };
            let cursor = r.u32()?;
            let newest = r.option(Reader::u32)?;
            let up = r.flag()?;
            if let Some(slot) = refs.get_mut(index) {
                *slot = reference;
            }
            if let Some(slot) = cursors.get_mut(index) {
                *slot = cursor;
            }
            if let Some(slot) = newest_epoch_key.get_mut(index) {
                *slot = newest;
            }
            if let Some(slot) = reachable.get_mut(index) {
                *slot = up;
            }
        }
        Ok(Replicas {
            refs,
            cursors,
            newest_epoch_key,
            last_subscribed: r.option(|r| Ok(usize::from(r.u8()?)))?,
            reachable,
        })
    }

    /// The replica to subscribe to in this session: the other one than
    /// last time, or a random one at first (`GRP-203`, `GRP-204`).
    pub fn pick(&mut self, random: bool) -> usize {
        let next = match self.last_subscribed {
            Some(last) => 1 - last,
            None => usize::from(random),
        };
        self.last_subscribed = Some(next);
        next
    }

    /// The other replica, for a gap repair (`GRP-205`).
    pub fn other(&self) -> usize {
        self.last_subscribed.map_or(0, |last| 1 - last)
    }

    /// The reference of replica `which`.
    pub fn reference(&self, which: usize) -> Option<&ReplicaRef> {
        self.refs.get(which)
    }

    /// The cursor of replica `which` (`GRP-202`).
    pub fn cursor(&self, which: usize) -> u32 {
        self.cursors.get(which).copied().unwrap_or(0)
    }

    /// A record at `seq` arrived from replica `which`; an epoch-key record
    /// moves the newest-epoch-key mark (`GRP-207`).
    pub fn arrived(&mut self, which: usize, seq: u32, epoch_key: bool) {
        if let Some(cursor) = self.cursors.get_mut(which) {
            if seq > *cursor {
                *cursor = seq;
            }
        }
        if epoch_key {
            if let Some(mark) = self.newest_epoch_key.get_mut(which) {
                *mark = Some(mark.map_or(seq, |m| m.max(seq)));
            }
        }
    }

    /// Whether a `GPOST` may go: the cursor of one replica is at or above
    /// the newest epoch-key record it holds (`GRP-207`).
    pub fn may_post(&self) -> bool {
        (0..GROUP_REPLICAS).any(|i| {
            self.reachable.get(i).copied().unwrap_or(false)
                && self
                    .newest_epoch_key
                    .get(i)
                    .copied()
                    .flatten()
                    .is_none_or(|mark| self.cursor(i) >= mark)
        })
    }

    /// Marks a replica reachable or not.
    pub fn set_reachable(&mut self, which: usize, reachable: bool) {
        if let Some(slot) = self.reachable.get_mut(which) {
            *slot = reachable;
        }
    }

    /// Whether no replica answers, which shows the waiting line and keeps
    /// each outbound record queued (`GRP-199`, `GRP-200`).
    pub fn unreachable(&self) -> bool {
        self.reachable.iter().all(|r| !r)
    }

    /// The relays to send a record to, which is both (`GRP-194`).
    pub fn targets(&self) -> Vec<[u8; 32]> {
        self.refs.iter().map(|r| r.relay_id).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn refs() -> [ReplicaRef; 2] {
        [
            ReplicaRef {
                relay_id: [1; 32],
                group_queue_id: [2; 32],
                seq_of_add: 5,
            },
            ReplicaRef {
                relay_id: [3; 32],
                group_queue_id: [4; 32],
                seq_of_add: 9,
            },
        ]
    }

    #[test]
    fn the_pair_prefers_two_blocs_and_the_reader_alternates() {
        let c = |r: u8, op: u8, bloc: u8| Candidate {
            relay_id: [r; 32],
            operator_id: [op; 32],
            bloc,
        };
        let pair = select_pair(&[c(1, 1, 1), c(2, 1, 2), c(3, 2, 1), c(4, 2, 2)]).unwrap();
        assert_eq!(pair.relays, [[1; 32], [4; 32]]);
        assert!(!pair.relaxed);
        let relaxed = select_pair(&[c(1, 1, 1), c(2, 2, 1)]).unwrap();
        assert!(relaxed.relaxed);
        assert!(select_pair(&[c(1, 1, 1), c(2, 1, 2)]).is_err());

        let mut r = Replicas::from_admit(refs());
        assert_eq!(r.cursor(1), 9);
        let first = r.pick(true);
        assert_eq!(first, 1);
        assert_eq!(r.pick(false), 0);
        assert_eq!(r.other(), 1);
        assert!(r.may_post());
        r.arrived(0, 20, true);
        assert_eq!(r.cursor(0), 20);
        assert!(r.may_post());
        r.arrived(0, 25, true);
        r.cursors[0] = 22;
        r.set_reachable(1, false);
        assert!(!r.may_post());
        r.arrived(0, 25, false);
        assert!(r.may_post());
        r.set_reachable(0, false);
        assert!(r.unreachable());
        assert_eq!(r.targets(), alloc::vec![[1; 32], [3; 32]]);
    }
}
