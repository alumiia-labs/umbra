//! The presence signal and the eviction it drives (Part 11 §11.8, §11.9.7),
//! and the rates of the roster chain (§11.9.4).

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::stored::{Reader, Writer};
use umbra_wire::group::control::Role;

use super::{
    roster::count, GRANT_RATE_DAY, GROUP_SILENT_EVICT, GROUP_SLOT_RATE, GROUP_SLOT_SKEW, OWNER_MIN,
    PRESENCE_INTERVAL, RATE_DAY_SLOTS, REKEY_RATE_DAY, ROSTER_SLOT_RATE,
};
use crate::Error;

/// What an admin holds about the activity of each member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresenceTracker {
    last_seen: BTreeMap<u16, u64>,
}

/// What an admin must do about a silent member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eviction {
    /// Remove with a plain epoch, then rotate (`GRP-133`, `GRP-264`).
    Remove,
    /// Remove the role with a granting epoch first (`GRP-166`), which does
    /// not count against `GRANT_RATE` (`GRP-167`).
    DemoteFirst,
    /// Hold: the removal would leave fewer than two owners; prompt each
    /// surviving owner to grant `owner` (`GRP-168`, `GRP-184`).
    HoldForOwners,
    /// Hold: a group of two members evicts nobody (`GRP-169`).
    HoldTwoMembers,
}

impl PresenceTracker {
    /// A record or a presence record from `index` at `now` (`GRP-132`).
    pub fn seen(&mut self, index: u16, now: u64) {
        let slot = self.last_seen.entry(index).or_insert(now);
        if now > *slot {
            *slot = now;
        }
    }

    /// A member that joined at `now` starts its silence from the join.
    pub fn joined(&mut self, index: u16, now: u64) {
        self.last_seen.insert(index, now);
    }

    /// Forgets a member.
    pub fn removed(&mut self, index: u16) {
        self.last_seen.remove(&index);
    }

    /// The members silent for `GROUP_SILENT_EVICT` at `now`, in index order
    /// (`GRP-132`, `GRP-134`).
    pub fn silent(&self, now: u64) -> Vec<u16> {
        self.last_seen
            .iter()
            .filter(|(_, at)| now.saturating_sub(**at) >= GROUP_SILENT_EVICT)
            .map(|(i, _)| *i)
            .collect()
    }

    /// What to do about a silent member of `role`, given the active member
    /// count and the owner count of the roster.
    pub const fn eviction(role: Role, active: usize, owners: usize) -> Eviction {
        if active <= 2 {
            return Eviction::HoldTwoMembers;
        }

        match role {
            Role::Owner if owners <= OWNER_MIN => Eviction::HoldForOwners,
            Role::Moderator | Role::Admin | Role::Owner => Eviction::DemoteFirst,
            Role::Member | Role::Observer => Eviction::Remove,
        }
    }
}

/// Whether a member must emit a presence record at `now`: it sent no
/// other record to the group in the last `PRESENCE_INTERVAL` (`GRP-128`).
pub fn presence_due(last_sent: Option<u64>, now: u64) -> bool {
    last_sent.is_none_or(|at| now.saturating_sub(at) >= PRESENCE_INTERVAL)
}

/// One roster object, as the rates of `GRP-076` count it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateKind {
    /// A plain epoch or a moderation epoch.
    Epoch,
    /// A granting epoch that gives a role at `moderator` or above.
    Grant,
    /// A granting epoch that takes such a role away. It counts against no
    /// rate of the grants (`GRP-167`).
    Demotion,
    /// A re-key that moves its maker to `new_index`.
    Rekey {
        /// The index that the re-key adds.
        new_index: u16,
    },
}

/// One window of a rate: the slot that opened it and the objects in it. It
/// also says whether this roster cannot know that each member holds the
/// same window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Window {
    start: u32,
    held: u32,
    /// The window opened while an object that this roster never read could
    /// still count in the window of the group. Such a window refuses
    /// nothing.
    unsure: bool,
}

/// The slots after which a window that ended goes. A receiver takes a
/// record of a slot inside `GROUP_SLOT_WINDOW` and `GROUP_SLOT_SKEW` of its
/// clock alone, thus no record can name a window that went.
const WINDOW_KEPT: u32 = 48;

/// The window after one more object of `slot`. A slot at or above the end
/// of the window opens the next one, and each other slot counts in the
/// window that stands. Thus an older slot gives no second window.
///
/// `unseen` is the highest slot that an object from before the history of
/// this roster can name. It is none for a roster that read the chain from
/// its start. A window can open `span` slots above that slot, and `span`
/// slots above each object that this roster counted for it. Such a window
/// opens at each member alike. No object, read or not, lies in the `span`
/// slots below it, thus the window of each member ended. The windows are
/// equal from there on. A window that opens earlier can stand across two
/// windows of the group, or start inside one, and it is not sure.
fn step(window: Window, slot: u32, span: u32, unseen: Option<u32>) -> Window {
    if window.held != 0 && slot < window.start.saturating_add(span) {
        return Window {
            held: window.held.saturating_add(1),
            ..window
        };
    }

    // An object of the window that ended lies below `start + span`.
    let quiet = window.held == 0
        || slot
            >= window
                .start
                .saturating_add(span.saturating_mul(2).saturating_sub(1));
    let was_sure = if window.held == 0 {
        unseen.is_none()
    } else {
        !window.unsure
    };
    let is_sure =
        was_sure || (quiet && unseen.is_none_or(|unseen| slot >= unseen.saturating_add(span)));

    Window {
        start: slot,
        held: 1,
        unsure: !is_sure,
    }
}

/// The rates of the roster chain (`GRP-076`). Each rate counts on the slot
/// of the record that carried the object, and not on the clock of the
/// receiver. Each member reads that slot alike. Thus a member that reads a
/// backlog gives each object the verdict that each other member gave it.
///
/// A roster from a snapshot, and one from a stored form before the rates,
/// did not read each object of the windows that stand. It counts from its
/// first object on, and it refuses nothing for a window that it cannot
/// know. A count that starts inside a window of the group can pass a limit
/// that the count of the group did not pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RosterRates {
    members: BTreeMap<u16, Window>,
    group: Window,
    grants: Window,
    /// The re-keys of each member, under the index that it holds now.
    rekeys: BTreeMap<u16, Window>,
    /// The highest slot that an object from before the history of this
    /// roster can name. It is none for a roster that read the chain from
    /// its start.
    unseen: Option<u32>,
}

impl RosterRates {
    /// The rates of a roster whose history starts at `slot`. An object that
    /// it never read names a slot at or below `slot` and the skew of a
    /// clock.
    pub fn partial(slot: u32) -> Self {
        RosterRates::default().since(slot)
    }

    /// Marks rates that counted nothing before `slot`.
    #[must_use]
    pub fn since(mut self, slot: u32) -> Self {
        self.unseen = Some(slot.saturating_add(GROUP_SLOT_SKEW));
        self
    }

    /// Whether this roster read each object of each window that it holds,
    /// thus each limit binds here.
    pub const fn is_whole(&self) -> bool {
        self.unseen.is_none()
    }

    /// Whether an object of `kind` from `maker`, in a record of `slot`, is
    /// inside every rate, and counts it if so. One slot takes
    /// `ROSTER_SLOT_RATE` objects of one maker and `GROUP_SLOT_RATE`
    /// objects of the group. `RATE_DAY_SLOTS` slots take `GRANT_RATE_DAY`
    /// grants of the group and `REKEY_RATE_DAY` re-keys of one member. The
    /// last one keeps one member from the use of each index of the group
    /// (`GRP-306`). A window that this roster cannot know counts and
    /// refuses nothing.
    pub fn allow(&mut self, maker: u16, kind: RateKind, slot: u32) -> bool {
        let unseen = self.unseen;
        let over = |window: Window, limit: u32| window.held > limit && !window.unsure;

        let member = step(
            self.members.get(&maker).copied().unwrap_or_default(),
            slot,
            1,
            unseen,
        );
        let group = step(self.group, slot, 1, unseen);
        if over(member, ROSTER_SLOT_RATE) || over(group, GROUP_SLOT_RATE) {
            return false;
        }

        let grants = step(self.grants, slot, RATE_DAY_SLOTS, unseen);
        if kind == RateKind::Grant && over(grants, GRANT_RATE_DAY) {
            return false;
        }

        let rekeys = step(
            self.rekeys.get(&maker).copied().unwrap_or_default(),
            slot,
            RATE_DAY_SLOTS,
            unseen,
        );
        if matches!(kind, RateKind::Rekey { .. }) && over(rekeys, REKEY_RATE_DAY) {
            return false;
        }

        self.members
            .retain(|_, window| slot < window.start.saturating_add(WINDOW_KEPT));
        self.rekeys.retain(|_, window| {
            slot < window
                .start
                .saturating_add(RATE_DAY_SLOTS.saturating_add(WINDOW_KEPT))
        });

        self.members.insert(maker, member);
        self.group = group;
        match kind {
            RateKind::Grant => self.grants = grants,
            // The count of a member moves with it to its new index.
            RateKind::Rekey { new_index } => {
                self.rekeys.remove(&maker);
                self.rekeys.insert(new_index, rekeys);
            }
            RateKind::Epoch | RateKind::Demotion => {}
        }

        true
    }

    /// Writes the rates to their stored form.
    pub fn export(&self, w: &mut Writer) -> Result<(), Error> {
        for map in [&self.members, &self.rekeys] {
            w.u32(count(map.len())?);
            for (index, window) in map {
                w.u16(*index);
                w.u32(window.start);
                w.u32(window.held);
                w.flag(window.unsure);
            }
        }

        for window in [self.group, self.grants] {
            w.u32(window.start);
            w.u32(window.held);
            w.flag(window.unsure);
        }

        w.option(self.unseen.as_ref(), |w, slot| w.u32(*slot));
        Ok(())
    }

    /// Reads the rates that [`RosterRates::export`] wrote. With `marks`
    /// false the form is the one before the mark of each window.
    pub fn import(r: &mut Reader<'_>, marks: bool) -> Result<Self, Error> {
        let window = |r: &mut Reader<'_>| -> Result<Window, Error> {
            Ok(Window {
                start: r.u32()?,
                held: r.u32()?,
                unsure: marks && r.flag()?,
            })
        };

        let mut maps = [BTreeMap::new(), BTreeMap::new()];
        for map in &mut maps {
            for _ in 0..r.u32()? {
                let index = r.u16()?;
                map.insert(index, window(r)?);
            }
        }

        let [members, rekeys] = maps;
        Ok(RosterRates {
            members,
            group: window(r)?,
            grants: window(r)?,
            rekeys,
            unseen: if marks { r.option(Reader::u32)? } else { None },
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn silence_evicts_after_thirty_days_with_the_floors_kept() {
        let mut t = PresenceTracker::default();
        t.joined(1, 0);
        t.joined(2, 0);
        t.seen(2, 100);
        t.seen(2, 50);

        assert!(t.silent(GROUP_SILENT_EVICT - 1).is_empty());
        assert_eq!(t.silent(GROUP_SILENT_EVICT), alloc::vec![1]);
        assert_eq!(t.silent(GROUP_SILENT_EVICT + 100), alloc::vec![1, 2]);

        t.removed(1);
        assert_eq!(t.silent(GROUP_SILENT_EVICT + 100), alloc::vec![2]);

        assert_eq!(
            PresenceTracker::eviction(Role::Member, 5, 2),
            Eviction::Remove
        );
        assert_eq!(
            PresenceTracker::eviction(Role::Moderator, 5, 2),
            Eviction::DemoteFirst
        );
        assert_eq!(
            PresenceTracker::eviction(Role::Owner, 5, 2),
            Eviction::HoldForOwners
        );
        assert_eq!(
            PresenceTracker::eviction(Role::Owner, 5, 3),
            Eviction::DemoteFirst
        );
        assert_eq!(
            PresenceTracker::eviction(Role::Member, 2, 2),
            Eviction::HoldTwoMembers
        );

        assert!(presence_due(None, 0));
        assert!(!presence_due(Some(0), PRESENCE_INTERVAL - 1));
        assert!(presence_due(Some(0), PRESENCE_INTERVAL));
    }

    #[test]
    fn the_roster_rates_bound_each_member_the_group_the_grants_and_the_rekeys() {
        // One maker: `ROSTER_SLOT_RATE` objects in one slot, and an older
        // slot opens no second window.
        let mut r = RosterRates::default();
        for _ in 0..ROSTER_SLOT_RATE {
            assert!(r.allow(1, RateKind::Epoch, 100));
        }
        assert!(!r.allow(1, RateKind::Epoch, 100));
        assert!(!r.allow(1, RateKind::Epoch, 99));
        assert!(r.allow(2, RateKind::Epoch, 100));
        assert!(r.allow(1, RateKind::Epoch, 101));

        // The group: `GROUP_SLOT_RATE` objects in one slot.
        let mut all = RosterRates::default();
        for maker in 0..GROUP_SLOT_RATE {
            assert!(all.allow(u16::try_from(maker).unwrap(), RateKind::Epoch, 7));
        }
        assert!(!all.allow(999, RateKind::Epoch, 7));
        assert!(all.allow(999, RateKind::Epoch, 8));

        // The grants: four in 24 slots, and a demotion counts in none.
        let mut g = RosterRates::default();
        for maker in 0..4u16 {
            assert!(g.allow(maker, RateKind::Grant, 10 + u32::from(maker)));
        }

        // A refusal counts nothing.
        let before = g.clone();
        assert!(!g.allow(5, RateKind::Grant, 20));
        assert_eq!(g, before);
        assert!(g.allow(5, RateKind::Demotion, 20));
        assert!(g.allow(5, RateKind::Grant, 10 + RATE_DAY_SLOTS));

        // The re-keys: the count follows the member to each new index.
        let mut k = RosterRates::default();
        let mut index = 3u16;
        for _ in 0..REKEY_RATE_DAY {
            assert!(k.allow(
                index,
                RateKind::Rekey {
                    new_index: index + 1
                },
                50
            ));
            index += 1;
        }
        assert!(!k.allow(
            index,
            RateKind::Rekey {
                new_index: index + 1
            },
            51
        ));
        assert!(k.allow(
            index,
            RateKind::Rekey {
                new_index: index + 1
            },
            50 + RATE_DAY_SLOTS
        ));

        // The stored form holds each window.
        let mut w = Writer::new();
        k.export(&mut w).unwrap();
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(RosterRates::import(&mut reader, true).unwrap(), k);
        reader.end().unwrap();
    }

    #[test]
    fn a_roster_that_did_not_read_a_window_refuses_nothing_for_it() {
        // GRP-076: the history of this roster starts at slot 100. The group
        // can hold a window that opened before it, thus a count from slot
        // 100 on can stand across two windows of the group.
        let rekey = |index: u16| RateKind::Rekey {
            new_index: index + 1,
        };

        // `count` re-keys of one member from the index `from` in one slot,
        // each of which the rates take. The result is its index after them.
        let run = |rates: &mut RosterRates, from: u16, count: u32, slot: u32| {
            let count = u16::try_from(count).unwrap();
            for index in from..from + count {
                assert!(rates.allow(index, rekey(index), slot));
            }
            from + count
        };
        let mut partial = RosterRates::partial(100);
        assert!(!partial.is_whole());

        run(&mut partial, 3, REKEY_RATE_DAY + 1, 101);

        // A member whose window opens `RATE_DAY_SLOTS` above each object
        // that this roster did not read holds the window of the group.
        let known = 100 + GROUP_SLOT_SKEW + RATE_DAY_SLOTS;
        let index = run(&mut partial, 40, REKEY_RATE_DAY, known);
        assert!(!partial.allow(index, rekey(index), known));

        // The window of a member stays open while its objects follow each
        // other inside two windows. It is sure after a pause of that
        // length.
        let mut dense = RosterRates::partial(100);
        let mut index = 3u16;
        for day in 0..6 {
            let slot = 101 + day * RATE_DAY_SLOTS;
            index = run(&mut dense, index, REKEY_RATE_DAY + 1, slot);
        }
        let slot = 101 + 7 * RATE_DAY_SLOTS;
        let index = run(&mut dense, index, REKEY_RATE_DAY, slot);
        assert!(!dense.allow(index, rekey(index), slot));

        // The rates of one slot are sure from the first slot above the
        // history.
        let mut slots = RosterRates::partial(100);
        for _ in 0..=ROSTER_SLOT_RATE {
            assert!(slots.allow(1, RateKind::Epoch, 100 + GROUP_SLOT_SKEW));
        }
        for _ in 0..ROSTER_SLOT_RATE {
            assert!(slots.allow(1, RateKind::Epoch, 101 + GROUP_SLOT_SKEW));
        }
        assert!(!slots.allow(1, RateKind::Epoch, 101 + GROUP_SLOT_SKEW));

        // The stored form keeps each mark.
        let mut w = Writer::new();
        dense.export(&mut w).unwrap();
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(RosterRates::import(&mut reader, true).unwrap(), dense);
        reader.end().unwrap();
    }
}
