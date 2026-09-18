//! The presence signal and the eviction it drives (Part 11 §11.8, §11.9.7),
//! and the rates of the roster chain (§11.9.4).

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_wire::group::control::Role;

use super::{
    GRANT_RATE_DAY, GRANT_RATE_INTERVAL, GROUP_EPOCH_RATE, GROUP_SILENT_EVICT, OWNER_MIN,
    PRESENCE_INTERVAL, ROSTER_RATE_LIMIT,
};

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

    /// What to do about the silent member `index` of `role`, given the
    /// active member count and the owner count of the roster.
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

/// The rates of the roster chain at a receiver (`GRP-076`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RosterRates {
    per_member: BTreeMap<u16, u64>,
    group_minute: Vec<u64>,
    grants: Vec<u64>,
}

impl RosterRates {
    /// Whether an epoch from `maker` at `now` is inside every rate, and
    /// records it if so. A granting epoch counts against `GRANT_RATE` as
    /// well, unless it is a silence demotion (`GRP-167`).
    pub fn allow(&mut self, maker: u16, granting: bool, silence_demotion: bool, now: u64) -> bool {
        self.group_minute
            .retain(|at| now.saturating_sub(*at) < ROSTER_RATE_LIMIT);
        self.grants.retain(|at| now.saturating_sub(*at) < 86_400);
        if self
            .per_member
            .get(&maker)
            .is_some_and(|at| now.saturating_sub(*at) < ROSTER_RATE_LIMIT)
        {
            return false;
        }
        if self.group_minute.len() >= usize::try_from(GROUP_EPOCH_RATE).unwrap_or(usize::MAX) {
            return false;
        }
        if granting && !silence_demotion {
            let recent = self
                .grants
                .iter()
                .any(|at| now.saturating_sub(*at) < GRANT_RATE_INTERVAL);
            if recent || self.grants.len() >= usize::try_from(GRANT_RATE_DAY).unwrap_or(usize::MAX)
            {
                return false;
            }
            self.grants.push(now);
        }
        self.per_member.insert(maker, now);
        self.group_minute.push(now);
        true
    }
}

#[cfg(test)]
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
    fn the_roster_rates_bound_each_member_the_group_and_the_grants() {
        let mut r = RosterRates::default();
        assert!(r.allow(1, false, false, 0));
        assert!(!r.allow(1, false, false, 59));
        assert!(r.allow(2, false, false, 1));
        for m in 3..=6u16 {
            assert!(r.allow(m, false, false, 2));
        }
        assert!(!r.allow(7, false, false, 3));
        assert!(r.allow(7, false, false, 61));
        // Grants: one in 300 s and four in a day, silence demotions exempt.
        let mut g = RosterRates::default();
        assert!(g.allow(1, true, false, 0));
        assert!(!g.allow(2, true, false, 299));
        assert!(g.allow(2, true, true, 299));
        assert!(g.allow(3, true, false, 300));
        assert!(g.allow(4, true, false, 600));
        assert!(g.allow(5, true, false, 900));
        assert!(!g.allow(6, true, false, 1_200));
        assert!(g.allow(6, true, false, 86_400));
    }
}
