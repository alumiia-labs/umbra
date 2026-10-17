//! The edit and the deletion of Part 7 §7.5.6 and the conversation timer
//! of §7.5.8, on the receiving side: the window, the revision limit, the
//! high-water mark, the pending reference table, the deletion rate, and
//! the timer deadline.

use alloc::{collections::BTreeMap, vec::Vec};

use super::{DELETE_RATE_INTERVAL, EDIT_MAX, EDIT_WINDOW, REF_ORPHAN_MAX, REF_ORPHAN_TTL};
use crate::Error;

/// What a receiver holds about one message for the edit rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditState {
    received_at: u64,
    revisions: u32,
    high_water: Option<u64>,
    tombstoned: bool,
}

impl EditState {
    /// A message received at `received_at`.
    pub const fn new(received_at: u64) -> Self {
        EditState {
            received_at,
            revisions: 0,
            high_water: None,
            tombstoned: false,
        }
    }

    /// Applies a revision at the author's sender-chain `position`, received
    /// at `now`, by the ratchet owner of the recipient (`DEV-087` to
    /// `DEV-089`, `DEV-033` to `DEV-035`).
    pub fn edit(&mut self, position: u64, now: u64) -> Result<(), Error> {
        if self.tombstoned {
            return Err(Error::Stale);
        }
        if now.saturating_sub(self.received_at) > EDIT_WINDOW {
            return Err(Error::Stale);
        }
        if self.high_water.is_some_and(|mark| position <= mark) {
            return Err(Error::Stale);
        }
        if self.revisions >= EDIT_MAX {
            return Err(Error::Stale);
        }

        self.revisions = self.revisions.saturating_add(1);
        self.high_water = Some(position);
        Ok(())
    }

    /// Applies a revision that the ratchet owner already accepted, at a
    /// device that does not own the ratchet (`DEV-246`).
    pub fn edit_forwarded(&mut self, position: u64) -> Result<(), Error> {
        if self.tombstoned || self.high_water.is_some_and(|mark| position <= mark) {
            return Err(Error::Stale);
        }

        self.revisions = self.revisions.saturating_add(1);
        self.high_water = Some(position);
        Ok(())
    }

    /// A tombstone is terminal: it wins against every later edit.
    pub fn tombstone(&mut self) {
        self.tombstoned = true;
    }

    /// The revisions applied so far.
    pub fn revisions(&self) -> u32 {
        self.revisions
    }
}

/// The key of a pending reference (`DEV-093`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PendingKey {
    /// The conversation or the group.
    pub conversation: [u8; 32],
    /// The direction in a pairwise conversation, or the author index in a
    /// group.
    pub origin: u32,
    /// The `msg_ref` of the target.
    pub target: [u8; 16],
}

/// A pending edit or deletion whose target has not arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Whether it is a deletion; otherwise an edit.
    pub deletion: bool,
    /// The sender-chain position, for the order of an edit.
    pub position: u64,
    /// The arrival time.
    pub arrived_at: u64,
}

/// The pending reference table of one device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingTable {
    entries: BTreeMap<PendingKey, Pending>,
}

impl PendingTable {
    /// Holds a reference. Above `REF_ORPHAN_MAX` for the conversation the
    /// oldest entry of that conversation leaves (`DEV-095`).
    pub fn hold(&mut self, key: PendingKey, pending: Pending) {
        let in_conversation: Vec<PendingKey> = self
            .entries
            .keys()
            .filter(|k| k.conversation == key.conversation)
            .copied()
            .collect();

        if in_conversation.len() >= REF_ORPHAN_MAX {
            if let Some(oldest) = in_conversation
                .iter()
                .min_by_key(|k| self.entries.get(k).map_or(u64::MAX, |p| p.arrived_at))
            {
                self.entries.remove(oldest);
            }
        }

        self.entries.insert(key, pending);
    }

    /// Takes the reference for a target that arrived, if one waits.
    pub fn take(&mut self, key: &PendingKey) -> Option<Pending> {
        self.entries.remove(key)
    }

    /// Drops each entry older than `REF_ORPHAN_TTL` (`DEV-095`).
    pub fn expire(&mut self, now: u64) {
        self.entries
            .retain(|_, p| now.saturating_sub(p.arrived_at) < REF_ORPHAN_TTL);
    }

    /// The entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing waits.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The deletion rate of one sender in one conversation: one record of
/// kind `0x05` in each `DELETE_RATE_INTERVAL`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteRate {
    last: Option<u64>,
}

impl DeleteRate {
    /// Whether a deletion may go at `now`, and records it if so.
    pub fn allow(&mut self, now: u64) -> bool {
        if self
            .last
            .is_some_and(|l| now.saturating_sub(l) < DELETE_RATE_INTERVAL)
        {
            return false;
        }

        self.last = Some(now);
        true
    }
}

/// The deadline of a timed record at one device (§7.5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// The local time at which the record key is discarded and the record
    /// overwritten (`DEV-210`, `DEV-211`).
    pub at: u64,
}

impl Deadline {
    /// A record from the other party, measured from the local receive time
    /// (`DEV-208`).
    pub const fn received(received_at: u64, timer_seconds: u32) -> Self {
        Deadline {
            at: received_at.saturating_add(timer_seconds as u64),
        }
    }

    /// A sync copy, measured from its receive time by `expires_in`
    /// (`DEV-244`).
    pub const fn from_sync(received_at: u64, expires_in: u32) -> Self {
        Deadline {
            at: received_at.saturating_add(expires_in as u64),
        }
    }

    /// `expires_in` for a send or a resend of this record at `now`
    /// (`DEV-243`).
    pub fn expires_in(&self, now: u64) -> u32 {
        u32::try_from(self.at.saturating_sub(now)).unwrap_or(u32::MAX)
    }

    /// Whether the record is due for erasure at `now`.
    pub const fn due(&self, now: u64) -> bool {
        now >= self.at
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
    fn the_window_the_limit_and_the_mark_hold() {
        let mut state = EditState::new(1_000);
        state.edit(5, 1_100).unwrap();
        assert_eq!(state.edit(5, 1_101), Err(Error::Stale));
        assert_eq!(state.edit(4, 1_101), Err(Error::Stale));

        for p in 6..=12u64 {
            state.edit(p, 1_200).unwrap();
        }
        assert_eq!(state.revisions(), EDIT_MAX);
        assert_eq!(state.edit(13, 1_200), Err(Error::Stale));

        let mut late = EditState::new(1_000);
        assert_eq!(late.edit(1, 1_000 + EDIT_WINDOW + 1), Err(Error::Stale));
        late.edit_forwarded(1).unwrap();
        late.tombstone();
        assert_eq!(late.edit_forwarded(2), Err(Error::Stale));
    }

    #[test]
    fn the_pending_table_the_rate_and_the_deadline_hold() {
        let mut table = PendingTable::default();
        let key = PendingKey {
            conversation: [1; 32],
            origin: 0,
            target: [2; 16],
        };

        table.hold(
            key,
            Pending {
                deletion: true,
                position: 3,
                arrived_at: 10,
            },
        );
        assert_eq!(table.len(), 1);
        table.expire(10 + REF_ORPHAN_TTL);
        assert!(table.is_empty());

        for i in 0..REF_ORPHAN_MAX as u32 + 1 {
            table.hold(
                PendingKey { origin: i, ..key },
                Pending {
                    deletion: false,
                    position: 1,
                    arrived_at: u64::from(i),
                },
            );
        }

        assert_eq!(table.len(), REF_ORPHAN_MAX);
        assert!(table.take(&PendingKey { origin: 0, ..key }).is_none());
        assert!(table.take(&PendingKey { origin: 1, ..key }).is_some());

        let mut rate = DeleteRate::default();
        assert!(rate.allow(0));
        assert!(!rate.allow(9));
        assert!(rate.allow(10));

        let d = Deadline::received(100, 3_600);
        assert!(!d.due(3_699));
        assert!(d.due(3_700));
        assert_eq!(d.expires_in(1_000), 2_700);
        assert_eq!(Deadline::from_sync(500, d.expires_in(1_000)).at, 3_200);
    }
}
