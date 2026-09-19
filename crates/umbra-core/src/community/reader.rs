//! The cross-relay checks of a reader (Part 12 §12.2.1, §12.4.1,
//! §12.4.3): the hold of a pending post that one relay serves, the three
//! display ages of a pending post, and the relay integrity warnings for a
//! gap, a body divergence, and a checkpoint divergence.
//!
//! A relay is an untrusted cache. These checks are the mechanism that
//! makes that statement hold, thus a warning always names its relays
//! (`COM-068`), and no check selects one of two bodies silently
//! (`COM-013`).

use alloc::{collections::BTreeMap, vec::Vec};

use super::{PENDING_DEMOTE, PENDING_EXPIRE, SETTLE_WINDOW};

/// A relay with the operator that runs it, from the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelayName {
    /// The relay.
    pub relay_id: [u8; 32],
    /// The operator of the relay.
    pub operator_id: [u8; 32],
}

/// How the client shows a post with no checkpoint (§12.4.1). No state
/// deletes the post (`COM-057`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDisplay {
    /// One relay serves the post, thus the client holds it (`COM-053`).
    Held,
    /// Shown in a state that attributes no final authorship (`COM-055`).
    ShownAsPending,
    /// Out of the default timeline, under the "unverified" filter.
    Unverified,
    /// Hidden from each default view, and kept locally.
    Hidden,
}

/// One body at one triple with no checkpoint over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPost {
    hash: [u8; 32],
    first_seen: u64,
    servers: Vec<RelayName>,
}

impl PendingPost {
    /// A body with `hash` that `relay` served first at `now`.
    pub fn new(hash: [u8; 32], relay: RelayName, now: u64) -> Self {
        PendingPost {
            hash,
            first_seen: now,
            servers: alloc::vec![relay],
        }
    }

    /// The hash of the body.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// One more relay served the same body at the same triple.
    pub fn served_by(&mut self, relay: RelayName) {
        if !self.servers.contains(&relay) {
            self.servers.push(relay);
        }
    }

    fn has_two_operators(&self) -> bool {
        self.servers
            .iter()
            .any(|a| self.servers.iter().any(|b| a.operator_id != b.operator_id))
    }

    /// The display state at `now` (`COM-054`, and the table of §12.4.1).
    /// A pending post is never moderation evidence (`COM-056`).
    pub fn display(&self, now: u64) -> PendingDisplay {
        let age = now.saturating_sub(self.first_seen);
        if age >= PENDING_EXPIRE {
            PendingDisplay::Hidden
        } else if age >= PENDING_DEMOTE {
            PendingDisplay::Unverified
        } else if self.has_two_operators() {
            PendingDisplay::ShownAsPending
        } else {
            PendingDisplay::Held
        }
    }
}

/// What one relay served for one triple, when the client asked that relay
/// for that index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// One `CommunityPost` with this hash.
    Body([u8; 32]),
    /// One `PostStub` with this hash.
    Stub([u8; 32]),
    /// No record, and the index is at or above the chain floor of the
    /// relay. The caller records this only for a window that it holds in
    /// full, or for an index that it requested by itself (`COM-072`,
    /// `COM-088`).
    Missing,
    /// The index is below the chain floor of the relay (`COM-230`).
    Pruned,
}

/// A relay integrity warning. The interface keeps it apart from a
/// moderator removal and from an author withdrawal (`COM-079`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// A relay serves no record, or a stub that no verified artifact
    /// names (`COM-069`, `COM-089`).
    Gap {
        /// The author.
        pseudonym: [u8; 32],
        /// The index.
        index: u32,
        /// The relay that the warning names.
        relay: RelayName,
    },
    /// Two relays serve two different bodies at one triple (`COM-011`,
    /// `COM-012`).
    BodyDivergence {
        /// The author.
        pseudonym: [u8; 32],
        /// The index.
        index: u32,
        /// The two relays.
        relays: [RelayName; 2],
    },
    /// One relay serves no checkpoint for a window that another relay
    /// serves one for (`COM-058`, `COM-074`).
    CheckpointDivergence {
        /// The author.
        pseudonym: [u8; 32],
        /// The last index of the window.
        end_index: u32,
        /// The relay without the checkpoint.
        relay: RelayName,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Sightings<T> {
    by_relay: BTreeMap<RelayName, T>,
    /// The time the client first saw two relays differ.
    differ_since: Option<u64>,
}

impl<T> Default for Sightings<T> {
    fn default() -> Self {
        Sightings {
            by_relay: BTreeMap::new(),
            differ_since: None,
        }
    }
}

/// The sightings of the posts and the checkpoints of one community across
/// its relays.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Consistency {
    posts: BTreeMap<([u8; 32], u32), Sightings<Seen>>,
    checkpoints: BTreeMap<([u8; 32], u32), Sightings<bool>>,
}

impl Consistency {
    /// Records what `relay` served at a triple.
    pub fn see_post(
        &mut self,
        pseudonym: [u8; 32],
        index: u32,
        relay: RelayName,
        seen: Seen,
        now: u64,
    ) {
        let sightings = self.posts.entry((pseudonym, index)).or_default();
        sightings.by_relay.insert(relay, seen);
        let mut served = sightings
            .by_relay
            .values()
            .filter(|seen| **seen != Seen::Pruned);
        let first = served.next();
        let differs = first.is_some_and(|first| served.any(|other| other != first));
        // A stub and an absence need an artifact, with or without a second
        // relay that serves the body.
        let absent = sightings
            .by_relay
            .values()
            .any(|seen| matches!(seen, Seen::Stub(_) | Seen::Missing));
        sightings.differ_since = match (differs || absent, sightings.differ_since) {
            (true, None) => Some(now),
            (true, since) => since,
            (false, _) => None,
        };
    }

    /// Records whether `relay` served the checkpoint of a window.
    pub fn see_checkpoint(
        &mut self,
        pseudonym: [u8; 32],
        end_index: u32,
        relay: RelayName,
        present: bool,
        now: u64,
    ) {
        let sightings = self.checkpoints.entry((pseudonym, end_index)).or_default();
        sightings.by_relay.insert(relay, present);
        let differs =
            sightings.by_relay.values().any(|p| *p) && sightings.by_relay.values().any(|p| !*p);
        sightings.differ_since = match (differs, sightings.differ_since) {
            (true, None) => Some(now),
            (true, since) => since,
            (false, _) => None,
        };
    }

    /// The warnings that stand at `now`. `authorized` says whether the
    /// client verified an artifact of §12.5.2 that names the pair. A
    /// difference is no warning before the settle window passes
    /// (`COM-073`, `COM-076`, `COM-077`), a body and a stub under a
    /// verified artifact are equal (`COM-070`, `COM-071`), and a pruned
    /// index is never a fault (`COM-231` to `COM-233`).
    ///
    /// An `OperatorRemoval` authorizes the stub of the relay that signed it
    /// only (`COM-361`), thus `authorized` takes the relay.
    pub fn warnings(
        &self,
        now: u64,
        authorized: impl Fn(&[u8; 32], u32, &RelayName) -> bool,
    ) -> Vec<Warning> {
        let settled =
            |since: Option<u64>| since.is_some_and(|at| now.saturating_sub(at) >= SETTLE_WINDOW);
        let mut warnings = Vec::new();
        for ((pseudonym, index), sightings) in &self.posts {
            if !settled(sightings.differ_since) {
                continue;
            }
            let mut bodies: Vec<(&RelayName, &[u8; 32])> = Vec::new();
            for (relay, seen) in &sightings.by_relay {
                match seen {
                    Seen::Body(hash) => bodies.push((relay, hash)),
                    Seen::Stub(_) | Seen::Missing => {
                        let is_stub = matches!(seen, Seen::Stub(_));
                        if !(is_stub && authorized(pseudonym, *index, relay)) {
                            warnings.push(Warning::Gap {
                                pseudonym: *pseudonym,
                                index: *index,
                                relay: *relay,
                            });
                        }
                    }
                    Seen::Pruned => {}
                }
            }
            let differing = bodies
                .iter()
                .enumerate()
                .find_map(|(position, (a, hash_a))| {
                    bodies
                        .iter()
                        .skip(position.saturating_add(1))
                        .find(|(_, hash_b)| hash_a != hash_b)
                        .map(|(b, _)| [**a, **b])
                });
            if let Some(relays) = differing {
                warnings.push(Warning::BodyDivergence {
                    pseudonym: *pseudonym,
                    index: *index,
                    relays,
                });
            }
        }
        for ((pseudonym, end_index), sightings) in &self.checkpoints {
            if !settled(sightings.differ_since) {
                continue;
            }
            for (relay, present) in &sightings.by_relay {
                if !present {
                    warnings.push(Warning::CheckpointDivergence {
                        pseudonym: *pseudonym,
                        end_index: *end_index,
                        relay: *relay,
                    });
                }
            }
        }
        warnings
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn relay(tag: u8, operator: u8) -> RelayName {
        RelayName {
            relay_id: [tag; 32],
            operator_id: [operator; 32],
        }
    }

    #[test]
    fn a_pending_post_waits_for_a_second_operator_and_is_never_deleted() {
        let mut pending = PendingPost::new([1; 32], relay(1, 1), 1_000);
        assert_eq!(pending.display(1_000), PendingDisplay::Held);
        pending.served_by(relay(2, 1));
        assert_eq!(
            pending.display(1_100),
            PendingDisplay::Held,
            "one operator runs both"
        );
        pending.served_by(relay(3, 2));
        assert_eq!(pending.display(1_100), PendingDisplay::ShownAsPending);
        assert_eq!(
            pending.display(1_000 + PENDING_DEMOTE),
            PendingDisplay::Unverified
        );
        assert_eq!(
            pending.display(1_000 + PENDING_EXPIRE),
            PendingDisplay::Hidden
        );

        let lone = PendingPost::new([1; 32], relay(1, 1), 1_000);
        assert_eq!(
            lone.display(1_000 + PENDING_DEMOTE),
            PendingDisplay::Unverified
        );
    }

    #[test]
    fn a_divergence_waits_for_the_settle_window_and_names_its_relays() {
        let author = [7; 32];
        let (a, b, c) = (relay(1, 1), relay(2, 2), relay(3, 3));
        let mut view = Consistency::default();
        view.see_post(author, 4, a, Seen::Body([1; 32]), 100);
        view.see_post(author, 4, b, Seen::Body([2; 32]), 150);
        view.see_post(author, 4, c, Seen::Pruned, 150);
        let none = |_: &[u8; 32], _: u32, _: &RelayName| false;
        assert!(view.warnings(150 + SETTLE_WINDOW - 1, none).is_empty());
        assert_eq!(
            view.warnings(150 + SETTLE_WINDOW, none),
            [Warning::BodyDivergence {
                pseudonym: author,
                index: 4,
                relays: [a, b],
            }]
        );

        // The relays agree later, thus the divergence ends.
        view.see_post(author, 4, b, Seen::Body([1; 32]), 9_000);
        assert!(view.warnings(u64::MAX, none).is_empty());
    }

    #[test]
    fn a_stub_needs_its_artifact_and_a_pruned_index_is_no_gap() {
        let author = [7; 32];
        let (a, b, c) = (relay(1, 1), relay(2, 2), relay(3, 3));
        let mut view = Consistency::default();
        view.see_post(author, 2, a, Seen::Body([1; 32]), 0);
        view.see_post(author, 2, b, Seen::Stub([1; 32]), 0);
        view.see_post(author, 2, c, Seen::Missing, 0);
        view.see_post(author, 3, a, Seen::Body([1; 32]), 0);
        view.see_post(author, 3, b, Seen::Pruned, 0);

        let at = SETTLE_WINDOW;
        let none = |_: &[u8; 32], _: u32, _: &RelayName| false;
        let gaps = view.warnings(at, none);
        assert_eq!(gaps.len(), 2);
        assert!(gaps.contains(&Warning::Gap {
            pseudonym: author,
            index: 2,
            relay: b
        }));
        assert!(gaps.contains(&Warning::Gap {
            pseudonym: author,
            index: 2,
            relay: c
        }));

        // A verified artifact makes the stub an authorized absence. An
        // operator removal does that for its own relay only.
        let at_b = |_: &[u8; 32], _: u32, relay: &RelayName| *relay == b;
        assert_eq!(
            view.warnings(at, at_b),
            [Warning::Gap {
                pseudonym: author,
                index: 2,
                relay: c
            }]
        );
    }

    #[test]
    fn a_missing_checkpoint_is_a_divergence_after_the_window_only() {
        let author = [7; 32];
        let (a, b) = (relay(1, 1), relay(2, 2));
        let mut view = Consistency::default();
        let none = |_: &[u8; 32], _: u32, _: &RelayName| false;
        view.see_checkpoint(author, 9, a, true, 1_000);
        view.see_checkpoint(author, 9, b, false, 1_000);
        assert!(view.warnings(1_000 + SETTLE_WINDOW - 1, none).is_empty());
        assert_eq!(
            view.warnings(1_000 + SETTLE_WINDOW, none),
            [Warning::CheckpointDivergence {
                pseudonym: author,
                end_index: 9,
                relay: b,
            }]
        );
        view.see_checkpoint(author, 9, b, true, 6_000);
        assert!(view.warnings(u64::MAX, none).is_empty());
    }
}
