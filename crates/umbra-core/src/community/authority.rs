//! The control chain of one community (Part 12 §12.5.2 rules 5, 6, 10, 11,
//! and 12): the chain of authority from the genesis key, the selection
//! between two concurrent successors, the fork of one signer, the owner
//! majority, and the moderation state that the selected chain gives. A
//! client and a relay run the same type (`COM-209`).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::hash::sha3_256;

use super::{
    community_id,
    control::{ActionKind, ControlBody, ControlObject, ModerationAction, Role, RosterEntry},
    ADMISSION_OPEN, MOD_CHAIN_FETCH_MAX, NO_INDEX,
};
use crate::Error;

/// The role holders at one point of the chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authority {
    roster: Vec<RosterEntry>,
    moderators: BTreeSet<[u8; 32]>,
}

impl Authority {
    /// The role of `actor`, where a roster role is above a moderator role.
    pub fn role_of(&self, actor: &[u8; 32]) -> Option<Role> {
        self.roster
            .iter()
            .find(|entry| entry.pseudonym == *actor)
            .map(|entry| entry.role)
            .or_else(|| self.moderators.contains(actor).then_some(Role::Moderator))
    }

    /// The entries of the current roster, which are the designated
    /// verifiers of a report (`COM-112`).
    pub fn roster(&self) -> &[RosterEntry] {
        &self.roster
    }

    fn owners(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.roster
            .iter()
            .filter(|entry| entry.role == Role::Owner)
            .map(|entry| &entry.pseudonym)
    }

    fn adopt(&mut self, object: &ControlObject) {
        match &object.body {
            ControlBody::Roster { entries, .. } => self.roster = entries.clone(),
            ControlBody::ModeratorSet { moderators } => {
                self.moderators = moderators.iter().copied().collect();
            }
            ControlBody::Moderation { .. } => {}
        }
    }

    /// Rule 5 and rule 12 for a successor under this authority.
    fn authorize(&self, object: &ControlObject) -> Result<Role, Error> {
        let role = self.role_of(&object.actor).ok_or(Error::Unverified)?;
        match &object.body {
            ControlBody::Roster { entries, .. } => {
                // COM-123.
                if role != Role::Owner {
                    return Err(Error::Unverified);
                }
                check_owner_count(entries)?;
                let dropped = self.owners().any(|owner| {
                    !entries
                        .iter()
                        .any(|e| e.role == Role::Owner && e.pseudonym == *owner)
                });
                let cosigners = object.verified_cosigners()?;
                if !dropped {
                    // COM-367.
                    return if cosigners.is_empty() {
                        Ok(role)
                    } else {
                        Err(Error::Unverified)
                    };
                }
                // COM-364, COM-365: the signer counts as one owner.
                if cosigners
                    .iter()
                    .any(|c| self.role_of(c) != Some(Role::Owner))
                {
                    return Err(Error::Unverified);
                }
                let agreeing = cosigners.len().saturating_add(1);
                if agreeing.saturating_mul(2) <= self.owners().count() {
                    return Err(Error::Unverified);
                }
            }
            ControlBody::ModeratorSet { .. } => {
                // COM-309.
                if role > Role::Admin {
                    return Err(Error::Unverified);
                }
            }
            ControlBody::Moderation {
                actor_role,
                actions,
            } => {
                // COM-121, COM-122.
                if *actor_role != role || actions.iter().any(|a| a.kind.minimum_role() < role) {
                    return Err(Error::Unverified);
                }
            }
        }
        Ok(role)
    }
}

fn check_owner_count(entries: &[RosterEntry]) -> Result<(), Error> {
    // COM-109, COM-130.
    if entries.iter().filter(|e| e.role == Role::Owner).count() < 2 {
        return Err(Error::Unverified);
    }
    Ok(())
}

/// The end of a lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEnd {
    /// The lock ends at this time, which the party measured from its own
    /// acceptance of the epoch (`COM-305`, `COM-353`).
    At(u64),
    /// The lock stands until an unlock.
    UntilUnlock,
}

/// The state that the moderation actions of the chain give (`COM-296`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModerationState {
    removed: BTreeSet<([u8; 32], u32)>,
    restored: BTreeSet<([u8; 32], u32)>,
    ban_removed_to: BTreeMap<[u8; 32], u32>,
    banned: BTreeSet<[u8; 32]>,
    pinned: BTreeSet<([u8; 32], u32)>,
    lock: Option<LockEnd>,
}

impl ModerationState {
    fn apply(&mut self, action: &ModerationAction, accepted_at: u64) {
        let pair = (action.target, action.index);
        match action.kind {
            ActionKind::Remove => {
                self.removed.insert(pair);
                self.restored.remove(&pair);
            }
            ActionKind::Restore => {
                self.removed.remove(&pair);
                self.restored.insert(pair);
            }
            ActionKind::Ban => {
                self.banned.insert(action.target);
                if action.index != NO_INDEX {
                    let bound = self.ban_removed_to.entry(action.target).or_insert(0);
                    *bound = (*bound).max(action.index);
                    let upto = *bound;
                    self.restored
                        .retain(|(target, index)| *target != action.target || *index > upto);
                }
            }
            ActionKind::Unban => {
                self.banned.remove(&action.target);
            }
            ActionKind::Pin => {
                self.pinned.insert(pair);
            }
            ActionKind::Unpin => {
                self.pinned.remove(&pair);
            }
            ActionKind::Lock => {
                self.lock = Some(if action.index == NO_INDEX {
                    LockEnd::UntilUnlock
                } else {
                    LockEnd::At(accepted_at.saturating_add(u64::from(action.index)))
                });
            }
            ActionKind::Unlock => self.lock = None,
        }
    }

    /// Whether a moderation artifact names the post, thus a relay serves a
    /// stub for it and a reader accepts that stub.
    pub fn is_removed(&self, pseudonym: &[u8; 32], index: u32) -> bool {
        let pair = (*pseudonym, index);
        if self.removed.contains(&pair) {
            return true;
        }
        self.ban_removed_to
            .get(pseudonym)
            .is_some_and(|upto| index <= *upto && !self.restored.contains(&pair))
    }

    /// Whether a ban stands on the pseudonym (`COM-298`).
    pub fn is_banned(&self, pseudonym: &[u8; 32]) -> bool {
        self.banned.contains(pseudonym)
    }

    /// The pinned posts (`COM-303`).
    pub fn pinned(&self) -> impl Iterator<Item = &([u8; 32], u32)> {
        self.pinned.iter()
    }

    /// The lock that stands at `now`, if one does (`COM-304`, `COM-306`).
    pub fn lock_at(&self, now: u64) -> Option<LockEnd> {
        match self.lock {
            Some(LockEnd::At(end)) if now >= end => None,
            other => other,
        }
    }
}

/// Two successors of one epoch from one signer (`COM-125`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// The epoch that both name.
    pub previous_epoch: [u8; 32],
    /// The role pseudonym that signed both.
    pub actor: [u8; 32],
    /// The two objects.
    pub hashes: [[u8; 32]; 2],
}

/// What an object did to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The object is on the selected chain now.
    Selected,
    /// The chain holds the object already.
    Duplicate,
    /// A moderation epoch that lost the selection. Its actions apply
    /// (`COM-307`).
    ActionsApplied,
    /// A roster or a moderator set that lost the selection. Its actor
    /// publishes it again against the selected epoch (`COM-139`).
    NotSelected,
    /// The signer made two successors of one epoch. The interface names
    /// that actor, and the chain keeps the first one it held (`COM-126`).
    Forked(Fork),
    /// The chain does not hold `previous_epoch`. The caller requests that
    /// object from the relay that served this one (`COM-135`).
    Missing([u8; 32]),
}

struct Node {
    object: ControlObject,
    hash: [u8; 32],
    accepted_at: u64,
}

/// The control chain of one community.
pub struct ControlChain {
    community_id: [u8; 32],
    selected: Vec<Node>,
    /// The verified moderation epochs that lost a selection and that name
    /// a selected epoch.
    side: Vec<Node>,
    forks: Vec<Fork>,
    authority: Authority,
    moderation: ModerationState,
}

impl ControlChain {
    /// An empty chain, which accepts the roster at `epoch_index` 0 first
    /// (`COM-206`).
    pub fn new(community_id: [u8; 32]) -> Self {
        ControlChain {
            community_id,
            selected: Vec::new(),
            side: Vec::new(),
            forks: Vec::new(),
            authority: Authority::default(),
            moderation: ModerationState::default(),
        }
    }

    /// The community.
    pub fn community_id(&self) -> &[u8; 32] {
        &self.community_id
    }

    /// Whether the chain holds its genesis roster.
    pub fn has_genesis(&self) -> bool {
        !self.selected.is_empty()
    }

    /// The role holders at the head.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The moderation state at the head.
    pub fn moderation(&self) -> &ModerationState {
        &self.moderation
    }

    /// The forks that the chain saw.
    pub fn forks(&self) -> &[Fork] {
        &self.forks
    }

    /// The hash and the index of the head.
    pub fn head(&self) -> Option<([u8; 32], u32)> {
        self.selected
            .last()
            .map(|node| (node.hash, node.object.epoch_index))
    }

    /// Whether the chain holds the object with this hash, selected or not.
    pub fn holds(&self, hash: &[u8; 32]) -> bool {
        self.selected
            .iter()
            .chain(self.side.iter())
            .any(|node| node.hash == *hash)
    }

    /// The selected objects with an `epoch_index` at or above `from`, in
    /// order, then the side epochs. A relay serves these under selector
    /// `0x03`.
    pub fn objects_from(&self, from: u32) -> impl Iterator<Item = &ControlObject> {
        self.selected
            .iter()
            .chain(self.side.iter())
            .map(|node| &node.object)
            .filter(move |object| object.epoch_index >= from)
    }

    fn authority_at(&self, position: usize) -> Authority {
        let mut authority = Authority::default();
        for node in self.selected.iter().take(position.saturating_add(1)) {
            authority.adopt(&node.object);
        }
        authority
    }

    fn rebuild(&mut self) {
        self.authority = self.authority_at(self.selected.len());
        let mut state = ModerationState::default();
        let mut previous = [0u8; 32];
        for node in &self.selected {
            // COM-308: the selected epoch applies last among the
            // successors of one epoch, thus it decides a reversal.
            let mut siblings: Vec<&Node> = self
                .side
                .iter()
                .filter(|s| s.object.previous_epoch == previous)
                .collect();
            siblings.sort_by_key(|s| core::cmp::Reverse(order_key(&previous, &s.object.actor)));
            for sibling in siblings.into_iter().chain(core::iter::once(node)) {
                if let ControlBody::Moderation { actions, .. } = &sibling.object.body {
                    for action in actions {
                        state.apply(action, sibling.accepted_at);
                    }
                }
            }
            previous = node.hash;
        }
        self.moderation = state;
    }

    /// Verifies `object` and applies it (`COM-119`, `COM-127`). Each check
    /// runs before the first change of state. `now` is the clock of this
    /// party, and a lock duration counts from it.
    pub fn apply(&mut self, object: ControlObject, now: u64) -> Result<Outcome, Error> {
        object.verify_signature(&self.community_id)?;
        let hash = object.hash()?;
        if self
            .selected
            .iter()
            .chain(self.side.iter())
            .any(|node| node.hash == hash)
        {
            return Ok(Outcome::Duplicate);
        }

        if object.epoch_index == 0 {
            return self.apply_genesis(object, hash, now);
        }
        let Some(position) = self
            .selected
            .iter()
            .position(|node| node.hash == object.previous_epoch)
        else {
            return Ok(Outcome::Missing(object.previous_epoch));
        };
        let expected_index = self
            .selected
            .get(position)
            .and_then(|node| node.object.epoch_index.checked_add(1));
        if expected_index != Some(object.epoch_index) {
            return Err(Error::Unverified);
        }
        let authority = self.authority_at(position);
        let role = authority.authorize(&object)?;
        let node = Node {
            object,
            hash,
            accepted_at: now,
        };

        let Some(rival) = self.selected.get(position.saturating_add(1)) else {
            self.selected.push(node);
            self.rebuild();
            return Ok(Outcome::Selected);
        };
        let previous = node.object.previous_epoch;
        let twin = core::iter::once(rival)
            .chain(
                self.side
                    .iter()
                    .filter(|s| s.object.previous_epoch == previous),
            )
            .find(|held| held.object.actor == node.object.actor);
        if let Some(twin) = twin {
            let fork = Fork {
                previous_epoch: previous,
                actor: node.object.actor,
                hashes: [twin.hash, hash],
            };
            self.forks.push(fork);
            return Ok(Outcome::Forked(fork));
        }

        // COM-136: the role of the signer, then the hash order.
        let rival_role = authority
            .role_of(&rival.object.actor)
            .unwrap_or(Role::Moderator);
        let wins = (role, order_key(&previous, &node.object.actor))
            < (rival_role, order_key(&previous, &rival.object.actor));
        let is_moderation = matches!(node.object.body, ControlBody::Moderation { .. });
        if !wins {
            if !is_moderation {
                // COM-138.
                return Ok(Outcome::NotSelected);
            }
            self.side.push(node);
            self.rebuild();
            return Ok(Outcome::ActionsApplied);
        }

        let mut displaced = self.selected.split_off(position.saturating_add(1));
        self.selected.push(node);
        // The old successor still names a selected epoch, thus its actions
        // stay. Each object behind it lost its predecessor.
        if !displaced.is_empty() {
            let old = displaced.remove(0);
            if matches!(old.object.body, ControlBody::Moderation { .. }) {
                self.side.push(old);
            }
        }
        let selected_hashes: BTreeSet<[u8; 32]> = self.selected.iter().map(|n| n.hash).collect();
        self.side
            .retain(|s| selected_hashes.contains(&s.object.previous_epoch));
        self.rebuild();
        Ok(Outcome::Selected)
    }

    fn apply_genesis(
        &mut self,
        object: ControlObject,
        hash: [u8; 32],
        now: u64,
    ) -> Result<Outcome, Error> {
        let ControlBody::Roster { entries, cosigns } = &object.body else {
            return Err(Error::Unverified);
        };
        // COM-120: the identity binds the key of the genesis signer.
        if community_id(ADMISSION_OPEN, &object.actor_pk)? != self.community_id
            || object.previous_epoch != [0u8; 32]
            || !cosigns.is_empty()
        {
            return Err(Error::Unverified);
        }
        let signer_is_owner = entries
            .iter()
            .any(|e| e.role == Role::Owner && e.pseudonym == object.actor);
        if !signer_is_owner {
            return Err(Error::Unverified);
        }
        check_owner_count(entries)?;
        if let Some(held) = self.selected.first() {
            // The identity admits one genesis key, thus a second genesis
            // roster is a fork of that owner.
            let fork = Fork {
                previous_epoch: [0u8; 32],
                actor: object.actor,
                hashes: [held.hash, hash],
            };
            self.forks.push(fork);
            return Ok(Outcome::Forked(fork));
        }
        self.selected.push(Node {
            object,
            hash,
            accepted_at: now,
        });
        self.rebuild();
        Ok(Outcome::Selected)
    }
}

/// `SHA3-256(previous_epoch || actor)`, the second key of the successor
/// order. No party knows `previous_epoch` before the race starts, thus no
/// party grinds a pseudonym that wins each race.
pub(crate) fn order_key(previous_epoch: &[u8; 32], actor: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[previous_epoch, actor])
}

/// The bound of one predecessor walk under `COM-135` (`COM-313`,
/// `COM-355`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PredecessorWalk {
    fetched: usize,
}

impl PredecessorWalk {
    /// Counts one fetch. At the bound the client rejects the epoch that
    /// started the walk.
    pub fn step(&mut self) -> Result<(), Error> {
        if self.fetched >= MOD_CHAIN_FETCH_MAX {
            return Err(Error::Unverified);
        }
        self.fetched = self.fetched.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        community::{control::tests::entry, identity::RoleIdentity, test_util::role},
    };

    pub const OWNER_A: u8 = 1;
    pub const OWNER_B: u8 = 2;
    pub const ADMIN: u8 = 3;
    pub const MODERATOR: u8 = 4;

    pub fn genesis_entries() -> Vec<RosterEntry> {
        alloc::vec![
            entry(Role::Owner, OWNER_A),
            entry(Role::Owner, OWNER_B),
            entry(Role::Admin, ADMIN),
        ]
    }

    pub fn sign(
        actor: &RoleIdentity,
        id: [u8; 32],
        at: (u32, [u8; 32]),
        body: ControlBody,
    ) -> ControlObject {
        ControlObject::sign(actor, id, at.0, at.1, body, &mut Rng(u64::from(at.0) + 1)).unwrap()
    }

    /// A chain with two owners, one admin, and one moderator.
    pub fn community() -> ([u8; 32], ControlChain) {
        let owner = role(OWNER_A);
        let id = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
        let mut chain = ControlChain::new(id);
        let roster = sign(
            &owner,
            id,
            (0, [0; 32]),
            ControlBody::Roster {
                entries: genesis_entries(),
                cosigns: Vec::new(),
            },
        );
        assert_eq!(chain.apply(roster, 100).unwrap(), Outcome::Selected);
        let set = sign(
            &role(ADMIN),
            id,
            (1, chain.head().unwrap().0),
            ControlBody::ModeratorSet {
                moderators: alloc::vec![role(MODERATOR).pseudonym()],
            },
        );
        assert_eq!(chain.apply(set, 101).unwrap(), Outcome::Selected);
        (id, chain)
    }

    pub fn moderation(
        actor_role: Role,
        kind: ActionKind,
        target: [u8; 32],
        index: u32,
    ) -> ControlBody {
        ControlBody::Moderation {
            actor_role,
            actions: alloc::vec![ModerationAction {
                kind,
                target,
                index,
            }],
        }
    }

    #[test]
    fn the_genesis_binds_the_identity_and_needs_two_owners() {
        let owner = role(OWNER_A);
        let id = community_id(ADMISSION_OPEN, owner.public_key()).unwrap();
        let body = |entries| ControlBody::Roster {
            entries,
            cosigns: Vec::new(),
        };

        let mut chain = ControlChain::new(id);
        let lone = sign(
            &owner,
            id,
            (0, [0; 32]),
            body(alloc::vec![entry(Role::Owner, OWNER_A)]),
        );
        assert!(chain.apply(lone, 0).is_err());

        let stranger = sign(&role(OWNER_B), id, (0, [0; 32]), body(genesis_entries()));
        assert!(
            chain.apply(stranger, 0).is_err(),
            "the key is not the genesis key"
        );
        assert!(!chain.has_genesis());

        let (_, chain) = community();
        assert_eq!(
            chain.authority().role_of(&role(ADMIN).pseudonym()),
            Some(Role::Admin)
        );
        assert_eq!(
            chain.authority().role_of(&role(MODERATOR).pseudonym()),
            Some(Role::Moderator)
        );
        assert_eq!(chain.authority().role_of(&role(9).pseudonym()), None);
    }

    #[test]
    fn each_role_signs_its_own_objects_and_no_other() {
        let (id, mut chain) = community();
        let head = chain.head().unwrap();
        let next = (head.1 + 1, head.0);

        let roster_by_admin = sign(
            &role(ADMIN),
            id,
            next,
            ControlBody::Roster {
                entries: genesis_entries(),
                cosigns: Vec::new(),
            },
        );
        assert!(chain.apply(roster_by_admin, 0).is_err());

        let set_by_moderator = sign(
            &role(MODERATOR),
            id,
            next,
            ControlBody::ModeratorSet {
                moderators: Vec::new(),
            },
        );
        assert!(chain.apply(set_by_moderator, 0).is_err());

        let lock_by_moderator = sign(
            &role(MODERATOR),
            id,
            next,
            moderation(Role::Moderator, ActionKind::Lock, [0; 32], 60),
        );
        assert!(chain.apply(lock_by_moderator, 0).is_err());

        let wrong_role = sign(
            &role(MODERATOR),
            id,
            next,
            moderation(Role::Admin, ActionKind::Remove, [7; 32], 1),
        );
        assert!(chain.apply(wrong_role, 0).is_err());

        let stranger = sign(
            &role(9),
            id,
            next,
            moderation(Role::Moderator, ActionKind::Remove, [7; 32], 1),
        );
        assert!(chain.apply(stranger, 0).is_err());
        assert_eq!(
            chain.head().unwrap(),
            head,
            "a failed check changes nothing"
        );

        let removal = sign(
            &role(MODERATOR),
            id,
            next,
            moderation(Role::Moderator, ActionKind::Remove, [7; 32], 1),
        );
        assert_eq!(chain.apply(removal.clone(), 0).unwrap(), Outcome::Selected);
        assert_eq!(chain.apply(removal, 0).unwrap(), Outcome::Duplicate);
        assert!(chain.moderation().is_removed(&[7; 32], 1));
        assert!(!chain.moderation().is_removed(&[7; 32], 2));

        let skipped = sign(
            &role(ADMIN),
            id,
            (next.0 + 5, chain.head().unwrap().0),
            moderation(Role::Admin, ActionKind::Pin, [7; 32], 2),
        );
        assert!(
            chain.apply(skipped, 0).is_err(),
            "the index follows its predecessor"
        );

        let orphan = sign(
            &role(ADMIN),
            id,
            (next.0 + 1, [0xEE; 32]),
            moderation(Role::Admin, ActionKind::Pin, [7; 32], 2),
        );
        assert_eq!(
            chain.apply(orphan, 0).unwrap(),
            Outcome::Missing([0xEE; 32])
        );
    }

    #[test]
    fn two_signers_at_one_epoch_resolve_and_one_signer_forks() {
        let (id, mut chain) = community();
        let head = chain.head().unwrap();
        let next = (head.1 + 1, head.0);
        let target = [7; 32];

        // The moderator is first, and the owner then wins by its role.
        let by_moderator = sign(
            &role(MODERATOR),
            id,
            next,
            moderation(Role::Moderator, ActionKind::Remove, target, 1),
        );
        let by_owner = sign(
            &role(OWNER_A),
            id,
            next,
            moderation(Role::Owner, ActionKind::Pin, target, 2),
        );
        assert_eq!(chain.apply(by_moderator, 0).unwrap(), Outcome::Selected);
        assert_eq!(chain.apply(by_owner.clone(), 0).unwrap(), Outcome::Selected);
        assert_eq!(chain.head().unwrap().0, by_owner.hash().unwrap());
        assert!(chain.forks().is_empty());
        // COM-307: the removal that lost the selection stands.
        assert!(chain.moderation().is_removed(&target, 1));
        assert!(chain.moderation().pinned().any(|p| *p == (target, 2)));

        // COM-308: a late sibling that reverses the selected epoch loses.
        let unpin = sign(
            &role(ADMIN),
            id,
            next,
            moderation(Role::Admin, ActionKind::Unpin, target, 2),
        );
        assert_eq!(chain.apply(unpin, 0).unwrap(), Outcome::ActionsApplied);
        assert!(chain.moderation().pinned().any(|p| *p == (target, 2)));

        // A moderator set that loses the selection is not applied.
        let set = sign(
            &role(OWNER_B),
            id,
            next,
            ControlBody::ModeratorSet {
                moderators: Vec::new(),
            },
        );
        let lost = order_key(&next.1, &role(OWNER_B).pseudonym())
            > order_key(&next.1, &role(OWNER_A).pseudonym());
        let outcome = chain.apply(set, 0).unwrap();
        assert_eq!(outcome == Outcome::NotSelected, lost);
        assert_eq!(
            chain
                .authority()
                .role_of(&role(MODERATOR).pseudonym())
                .is_some(),
            lost
        );

        // One signer with two successors is a fork that names the signer.
        let second = sign(
            &role(OWNER_A),
            id,
            next,
            moderation(Role::Owner, ActionKind::Pin, target, 3),
        );
        match chain.apply(second, 0).unwrap() {
            Outcome::Forked(fork) => assert_eq!(fork.actor, role(OWNER_A).pseudonym()),
            other => panic!("{other:?}"),
        }
        assert!(!chain.moderation().pinned().any(|p| *p == (target, 3)));
    }

    #[test]
    fn a_roster_that_drops_an_owner_needs_the_owner_majority() {
        let (id, mut chain) = community();
        let head = chain.head().unwrap();
        let next = (head.1 + 1, head.0);
        let without_b = ControlBody::Roster {
            entries: alloc::vec![entry(Role::Owner, OWNER_A), entry(Role::Owner, ADMIN),],
            cosigns: Vec::new(),
        };

        let alone = sign(&role(OWNER_A), id, next, without_b.clone());
        assert!(
            chain.apply(alone, 0).is_err(),
            "one of two owners is not a majority"
        );

        let mut by_admin = sign(&role(OWNER_A), id, next, without_b.clone());
        by_admin.cosign(&role(ADMIN), &mut Rng(9)).unwrap();
        assert!(
            chain.apply(by_admin, 0).is_err(),
            "an admin is not an owner"
        );

        let mut agreed = sign(&role(OWNER_A), id, next, without_b);
        agreed.cosign(&role(OWNER_B), &mut Rng(9)).unwrap();
        let parsed = ControlObject::parse(&agreed.encode().unwrap()).unwrap();
        assert_eq!(chain.apply(parsed, 0).unwrap(), Outcome::Selected);
        assert_eq!(chain.authority().role_of(&role(OWNER_B).pseudonym()), None);
        assert_eq!(
            chain.authority().role_of(&role(ADMIN).pseudonym()),
            Some(Role::Owner)
        );

        // COM-367: a cosignature on a roster that drops no owner.
        let head = chain.head().unwrap();
        let mut needless = sign(
            &role(OWNER_A),
            id,
            (head.1 + 1, head.0),
            ControlBody::Roster {
                entries: alloc::vec![
                    entry(Role::Owner, OWNER_A),
                    entry(Role::Owner, ADMIN),
                    entry(Role::Admin, 8),
                ],
                cosigns: Vec::new(),
            },
        );
        needless.cosign(&role(ADMIN), &mut Rng(9)).unwrap();
        assert!(chain.apply(needless, 0).is_err());
    }

    #[test]
    fn a_ban_a_restore_and_a_lock_give_the_last_state() {
        let (id, mut chain) = community();
        let target = [7; 32];
        let push = |chain: &mut ControlChain, body: ControlBody, now: u64| {
            let head = chain.head().unwrap();
            let object = sign(&role(ADMIN), id, (head.1 + 1, head.0), body);
            assert_eq!(chain.apply(object, now).unwrap(), Outcome::Selected);
        };

        push(
            &mut chain,
            moderation(Role::Admin, ActionKind::Ban, target, 4),
            0,
        );
        assert!(chain.moderation().is_banned(&target));
        assert!(chain.moderation().is_removed(&target, 0));
        assert!(chain.moderation().is_removed(&target, 4));
        assert!(!chain.moderation().is_removed(&target, 5));

        push(
            &mut chain,
            moderation(Role::Admin, ActionKind::Restore, target, 2),
            0,
        );
        assert!(!chain.moderation().is_removed(&target, 2));
        assert!(chain.moderation().is_removed(&target, 3));

        push(
            &mut chain,
            moderation(Role::Admin, ActionKind::Unban, target, NO_INDEX),
            0,
        );
        assert!(!chain.moderation().is_banned(&target));
        assert!(
            chain.moderation().is_removed(&target, 3),
            "an unban restores no post"
        );

        push(
            &mut chain,
            moderation(Role::Admin, ActionKind::Lock, [0; 32], 600),
            1_000,
        );
        assert_eq!(chain.moderation().lock_at(1_599), Some(LockEnd::At(1_600)));
        assert_eq!(chain.moderation().lock_at(1_600), None);
        push(
            &mut chain,
            moderation(Role::Admin, ActionKind::Lock, [0; 32], NO_INDEX),
            2_000,
        );
        assert_eq!(
            chain.moderation().lock_at(u64::MAX),
            Some(LockEnd::UntilUnlock)
        );
        push(
            &mut chain,
            moderation(Role::Admin, ActionKind::Unlock, [0; 32], NO_INDEX),
            2_001,
        );
        assert_eq!(chain.moderation().lock_at(2_002), None);

        let mut walk = PredecessorWalk::default();
        for _ in 0..MOD_CHAIN_FETCH_MAX {
            walk.step().unwrap();
        }
        assert!(walk.step().is_err());
    }
}
