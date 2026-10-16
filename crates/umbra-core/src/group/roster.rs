//! The roster of a group and its hash chain (Part 11 §11.9): the members
//! with their roles and keys, the plain, granting, moderation, and re-key
//! objects with their authority and their chain checks, the fork rule, the
//! active-member set of each roster epoch, and the rotation trigger that a
//! roster change raises.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{
    hash::sha3_256,
    stored::{Reader, Writer},
};
use umbra_wire::group::control::{
    ControlType, GrantingEpoch, GroupControl, GroupMemberEntry, ModAction, ModerationEpoch,
    PlainEpoch, PlainOp, RekeyRecord, Role, RosterSnapshot,
};

use super::{
    presence::{RateKind, RosterRates},
    slot_of, GROUP_MAX, MOD_ACTION_MAX, OWNER_MIN, ROLE_HOLDER_MAX,
};
use crate::Error;

/// The version of each stored object of a group.
pub(crate) const STORED_VERSION: u8 = 0x01;

/// The version of the stored roster: version `0x01` with the re-key at the
/// head of the chain and the moves of each re-key after it.
const ROSTER_VERSION_MOVES: u8 = 0x02;

/// Version `0x02` with the roster before the head of the chain, and the
/// maker of the head (`GRP-117`).
const ROSTER_VERSION_UNDO: u8 = 0x03;

/// Version `0x03` with the roster epoch of each successor and the rival
/// that took the place of the head re-key (`GRP-369`). It also holds the
/// open index of a roster from a snapshot (`GRP-320`) and the rates
/// (`GRP-076`).
const ROSTER_VERSION_RATES: u8 = 0x04;

/// Version `0x04` with the mark of each window of the rates that the
/// roster cannot know (`GRP-076`).
const ROSTER_VERSION: u8 = 0x05;

/// The entries of an authority path: `BE16(len) || GroupControl` each.
pub fn split_path(path: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let mut entries = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        let len = usize::from(u16::from_be_bytes([
            *rest.first().ok_or(Error::Malformed)?,
            *rest.get(1).ok_or(Error::Malformed)?,
        ]));
        entries.push(rest.get(2..2 + len).ok_or(Error::Malformed)?);
        rest = rest.get(2 + len..).ok_or(Error::Malformed)?;
    }
    Ok(entries)
}

/// A count in a stored object, which a later read bounds by the rules of
/// its own type.
pub(crate) fn count(len: usize) -> Result<u32, Error> {
    u32::try_from(len).map_err(|_| Error::Malformed)
}

/// One member of the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member index.
    pub index: u16,
    /// The role.
    pub role: Role,
    /// `GroupPairKey_g.pk`.
    pub pair_pk: [u8; 32],
    /// `SHA3-256(GroupRosterKey_g.pk)`.
    pub roster_pk_hash: [u8; 32],
    /// `SHA3-256(GroupKemKey_g.pk)`.
    pub kem_pk_hash: [u8; 32],
    /// The full KEM key, once verified against its hash (`GRP-307`).
    pub kem_pk: Option<Vec<u8>>,
    /// The full roster key, where this device holds it: its own, and the
    /// creator's from the offer. A signed roster object carries the key of
    /// its signer, thus no check needs this field (`GRP-316`).
    pub roster_pk: Option<Vec<u8>>,
    /// Whether the member is in the active set.
    pub active: bool,
}

impl Member {
    /// Stores a KEM key after the hash check (`GRP-308`).
    pub fn set_kem_pk(&mut self, kem_pk: &[u8]) -> Result<(), Error> {
        if sha3_256(&[kem_pk]) != self.kem_pk_hash {
            return Err(Error::Unverified);
        }
        self.kem_pk = Some(kem_pk.to_vec());
        Ok(())
    }

    /// Stores a roster key after the hash check (`GRP-308`).
    pub fn set_roster_pk(&mut self, roster_pk: &[u8]) -> Result<(), Error> {
        if sha3_256(&[roster_pk]) != self.roster_pk_hash {
            return Err(Error::Unverified);
        }
        self.roster_pk = Some(roster_pk.to_vec());
        Ok(())
    }
}

/// A rotation trigger that a roster change raised (§11.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trigger {
    /// The index the trigger excludes from the next epoch, if one.
    pub excluded: Option<u16>,
    /// The roster epoch that carries the trigger.
    pub roster_epoch: u32,
}

/// What a roster object did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// A member joined at the index.
    Added(u16),
    /// A member left, by removal or by self-removal; a trigger.
    Removed(Trigger),
    /// A role changed.
    Granted {
        /// The member.
        index: u16,
        /// The new role.
        role: Role,
    },
    /// Moderation actions to apply, after the signature check, and the role
    /// of the actor for the placeholder of each target (`GRP-082`).
    Moderated {
        /// The role of the acting member.
        actor_role: Role,
        /// The actions, in the order of the epoch.
        actions: Vec<ModAction>,
    },
    /// A member moved to new keys under a new index; a trigger.
    Rekeyed {
        /// The old index, which the trigger excludes.
        old: u16,
        /// The new index.
        new: u16,
        /// The trigger.
        trigger: Trigger,
        /// Whether this re-key took the place of a rival re-key of the same
        /// index at the head of the chain (`GRP-369`). The keys at `new`
        /// changed, and the index did not.
        replaced: bool,
    },
}

/// A re-key at the head of the chain. A rival re-key of the same index at
/// the same predecessor can still take its place (`GRP-369`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadRekey {
    /// The epoch hash that both re-keys name as their predecessor.
    pub predecessor: [u8; 32],
    /// The index that the re-key excluded.
    pub old_index: u16,
    /// The index that the re-key added. A rival gets the same one.
    pub new_index: u16,
}

/// The fact that the re-key at the head of the chain had a rival
/// (`GRP-369`). A rival is a second re-key of the same index at the same
/// predecessor that verified here. The fact holds whichever of the two
/// stands and whichever came first. The two re-keys made two sets of keys
/// for the new index, and the roster epoch is one. Thus an epoch-key record
/// of that roster epoch can hold a slot for the keys that lost. No field of
/// the record says which keys its rotator held. The roster counts the
/// epochs that this member installed under that roster epoch. The second
/// one answers the rival at each member, in each order of arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replaced {
    /// The roster epoch of the re-key and of its rival.
    pub roster_epoch: u32,
    /// The index whose keys the rival changed.
    pub new_index: u16,
    /// The epochs of that roster epoch that this member installed, and
    /// two at most.
    rotations: u8,
    /// Whether the one epoch of them came before a rival that took the
    /// place of the head. Its slot for `new_index` then went to the keys
    /// that lost.
    pending: bool,
}

/// A fork the client must show (`GRP-070` to `GRP-074`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// The predecessor both successors name.
    pub predecessor: [u8; 32],
    /// The member that made both, when a signature names it.
    pub named: Option<u16>,
}

/// The head of the roster chain as the order of `GRP-117` can still move
/// it: the roster before the head, and the member that made the head.
#[derive(Clone)]
struct Undo {
    before: Roster,
    maker: u16,
}

/// A head of the chain that a successor of another member took the place
/// of (`GRP-117`). Its maker publishes it again against the new head
/// (`GRP-119`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Displaced {
    /// The member that made the displaced epoch.
    pub maker: u16,
    /// The hash of the displaced epoch.
    pub hash: [u8; 32],
}

/// The roster of one group at one member.
#[derive(Clone)]
pub struct Roster {
    group_id: [u8; 32],
    epoch_index: u32,
    chain_hash: [u8; 32],
    members: BTreeMap<u16, Member>,
    highest_index: Option<u16>,
    history: BTreeMap<u32, (Vec<u16>, u64)>,
    admission_epoch: u32,
    /// The successor of each predecessor from each maker, with the roster
    /// epoch that the successor made.
    successors: BTreeMap<([u8; 32], u16), ([u8; 32], u32)>,
    forks: Vec<Fork>,
    head_rekey: Option<HeadRekey>,
    /// The new index of each re-key, under the index it excluded.
    moves: BTreeMap<u16, u16>,
    undo: Option<alloc::boxed::Box<Undo>>,
    displaced: Option<Displaced>,
    replaced: Option<Replaced>,
    /// The highest index that the next add or re-key may take. It applies
    /// in a roster from a snapshot that does not name the highest index
    /// ever used (`GRP-320`).
    open_index: Option<u16>,
    rates: RosterRates,
    /// Whether the last object set the mark of [`Replaced`]. The group
    /// takes it once and gives the mark the count of its epochs.
    rival_seen: bool,
}

impl Roster {
    /// The roster at the creation: the creator at index 0 as `owner`, at
    /// roster epoch 0 with the zero hash before it.
    pub fn genesis(group_id: [u8; 32], creator: Member, now: u64) -> Self {
        let mut members = BTreeMap::new();
        let index = creator.index;
        members.insert(
            index,
            Member {
                active: true,
                ..creator
            },
        );
        let mut history = BTreeMap::new();
        history.insert(0, (alloc::vec![index], now));
        Roster {
            group_id,
            epoch_index: 0,
            chain_hash: [0; 32],
            members,
            highest_index: Some(index),
            history,
            admission_epoch: 0,
            successors: BTreeMap::new(),
            forks: Vec::new(),
            head_rekey: None,
            moves: BTreeMap::new(),
            undo: None,
            displaced: None,
            replaced: None,
            open_index: None,
            rates: RosterRates::default(),
            rival_seen: false,
        }
    }

    /// The roster of a joiner from a verified snapshot (`GRP-326`): the
    /// `chain_hash` must be the hash of the add record, each KEM key must
    /// match its entry, and the authority path must verify from the
    /// creator's roster key. The path is a sequence of `BE16(len) ||
    /// GroupControl` entries in chain order.
    pub fn from_snapshot(
        snapshot: &RosterSnapshot<'_>,
        expected_chain_hash: &[u8; 32],
        creator_roster_pk: &[u8],
        now: u64,
    ) -> Result<Self, Error> {
        if snapshot.chain_hash != *expected_chain_hash {
            return Err(Error::Unverified);
        }
        if snapshot.entries.len() > GROUP_MAX {
            return Err(Error::Malformed);
        }
        let mut members = BTreeMap::new();
        let mut highest = None;
        for entry in &snapshot.entries {
            let member = Member {
                index: entry.index,
                role: entry.role,
                pair_pk: entry.pair_pk,
                roster_pk_hash: entry.roster_pk_hash,
                kem_pk_hash: entry.kem_pk_hash,
                kem_pk: None,
                roster_pk: None,
                active: true,
            };
            highest = Some(highest.map_or(entry.index, |h: u16| h.max(entry.index)));
            if members.insert(entry.index, member).is_some() {
                return Err(Error::Malformed);
            }
        }
        for key in &snapshot.keys {
            members
                .get_mut(&key.index)
                .ok_or(Error::Malformed)?
                .set_kem_pk(key.kem_pk)?;
        }
        if members.values().any(|m| m.kem_pk.is_none()) {
            return Err(Error::Unverified);
        }
        let active: Vec<u16> = members.keys().copied().collect();
        let mut history = BTreeMap::new();
        history.insert(snapshot.roster_epoch, (active, now));
        let mut roster = Roster {
            group_id: snapshot.group_id,
            epoch_index: snapshot.roster_epoch,
            chain_hash: snapshot.chain_hash,
            members,
            highest_index: highest,
            history,
            admission_epoch: snapshot.roster_epoch,
            successors: BTreeMap::new(),
            forks: Vec::new(),
            head_rekey: None,
            moves: BTreeMap::new(),
            undo: None,
            displaced: None,
            replaced: None,
            open_index: None,
            // GRP-076: the snapshot carries no count, and an object of the
            // windows that stand came before it.
            rates: RosterRates::partial(slot_of(now)),
            rival_seen: false,
        };
        roster.verify_path(snapshot.path, creator_roster_pk)?;
        Ok(roster)
    }

    /// Opens the index of the next add or re-key (`GRP-329`). This applies
    /// to a roster that a member took from a snapshot at a roster epoch
    /// that is not its own add. The snapshot holds the active members
    /// alone, thus the highest index that the group ever used can lie above
    /// each entry. Each index took one roster epoch, thus the next index
    /// lies at or below `roster_epoch + 1`. The first add or re-key that
    /// verifies gives the true value, and the index closes (`GRP-320`).
    pub fn open_next_index(&mut self) {
        let bound = self.epoch_index.saturating_add(1);
        self.open_index = Some(u16::try_from(bound).unwrap_or(u16::MAX));
    }

    /// Whether the index of the next add or re-key is open (`GRP-329`).
    /// This roster came from a snapshot, and no add or re-key gave it the
    /// highest index of the group since.
    pub const fn index_is_open(&self) -> bool {
        self.open_index.is_some()
    }

    /// The index that an add or a re-key of this member takes (`GRP-305`).
    /// A roster whose index is open gives none (`GRP-329`). Each other
    /// member takes one index alone, and an object under a lower one would
    /// stand at this member and nowhere else.
    pub fn build_index(&self) -> Result<u16, Error> {
        if self.index_is_open() {
            return Err(Error::NoPath);
        }
        self.next_index()
    }

    /// Whether this roster read each object of each window of the rates
    /// (`GRP-076`).
    pub const fn rates_are_whole(&self) -> bool {
        self.rates.is_whole()
    }

    /// Verifies the authority path: each granting epoch in chain order,
    /// under a roster key the path or the creator gave (`GRP-062`,
    /// `GRP-326`). The grantee roster keys the path carries are kept.
    /// Verifies the authority path of a snapshot in chain order
    /// (`GRP-326`, `GRP-399`). The creator starts as `owner`. Each grant
    /// needs a granter at `admin` or above at that point of the path, and
    /// the key it carries must match the hash of the granter: from its
    /// entry, or, for a granter that left since, from the grant that gave
    /// it its role. Each role holder of the snapshot must hold the role
    /// that the path gives it last.
    fn verify_path(&mut self, path: &[u8], creator_roster_pk: &[u8]) -> Result<(), Error> {
        let creator_hash = sha3_256(&[creator_roster_pk]);
        let mut creator = None;
        if let Some(member) = self
            .members
            .values_mut()
            .find(|m| m.roster_pk_hash == creator_hash)
        {
            member.set_roster_pk(creator_roster_pk)?;
            creator = Some(member.index);
        }
        let mut grants = Vec::new();
        for bytes in split_path(path)? {
            let control = GroupControl::parse(bytes)?;
            if control.control_type != ControlType::GrantingEpoch {
                return Err(Error::Malformed);
            }
            grants.push(GrantingEpoch::parse(control.payload)?);
        }
        grants.sort_by_key(|grant| grant.chain.epoch_index);
        if grants.windows(2).any(|pair| {
            pair.first().map(|g| g.chain.epoch_index) == pair.get(1).map(|g| g.chain.epoch_index)
        }) {
            return Err(Error::Malformed);
        }
        // The role and the key hash of each index that the path names.
        let mut state: BTreeMap<u16, (Role, [u8; 32])> = self
            .members
            .values()
            .map(|member| (member.index, (Role::Member, member.roster_pk_hash)))
            .collect();
        // The creation gives the creator index 0 (`GRP-306`). A creator
        // that left the group still starts the path at that index, under
        // its own key and not under the key of an entry there.
        let creator_index = creator.unwrap_or(0);
        state.insert(creator_index, (Role::Owner, creator_hash));
        for grant in &grants {
            if grant.chain.group_id != self.group_id {
                return Err(Error::Unverified);
            }
            let (granter_role, granter_hash) =
                *state.get(&grant.granter_index).ok_or(Error::Unverified)?;
            if granter_role < Role::Admin || grant.granter_index == grant.grantee_index {
                return Err(Error::Unverified);
            }
            grant.verify(&granter_hash)?;
            match state.get_mut(&grant.grantee_index) {
                Some((role, hash)) => {
                    if *hash != grant.grantee_roster_pk_hash
                        || !Self::may_change(granter_role, *role, grant.role)
                    {
                        return Err(Error::Unverified);
                    }
                    *role = grant.role;
                }
                None => {
                    if !Self::may_change(granter_role, Role::Member, grant.role) {
                        return Err(Error::Unverified);
                    }
                    state.insert(
                        grant.grantee_index,
                        (grant.role, grant.grantee_roster_pk_hash),
                    );
                }
            }
        }
        // GRP-399: the path backs a role holder by its key and its role. An
        // entry with keys of its own at the index of a creator that left, or
        // of a grantee, has no grant behind it.
        let backed = |member: &Member| {
            member.role < Role::Moderator
                || member.index == creator_index && member.roster_pk_hash == creator_hash
                || state.get(&member.index) == Some(&(member.role, member.roster_pk_hash))
        };
        if !self.members.values().all(backed) {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// Whether a granter that holds `granter` may move a member from
    /// `from` to `to` (`GRP-063`). Only an owner gives `owner` or changes
    /// the role of an owner, thus an admin cannot take a group from its
    /// owners.
    fn may_change(granter: Role, from: Role, to: Role) -> bool {
        granter == Role::Owner || granter >= Role::Admin && from < Role::Owner && to < Role::Owner
    }

    fn check_granting_signature(&self, epoch: &GrantingEpoch<'_>) -> Result<(), Error> {
        // GRP-063: a re-key or a self-removal takes its maker out of the
        // active set and leaves its entry and its role. Such an entry
        // grants nothing.
        let granter = self
            .members
            .get(&epoch.granter_index)
            .filter(|m| m.active)
            .ok_or(Error::Unverified)?;
        if granter.role < Role::Admin {
            return Err(Error::Unverified);
        }
        // GRP-316: the epoch carries the key of its granter, and the roster
        // entry binds it by its hash.
        epoch.verify(&granter.roster_pk_hash)?;
        Ok(())
    }

    /// Whether the epoch names the grantee by the hash of its roster
    /// entry.
    fn check_grantee_key(&self, epoch: &GrantingEpoch<'_>) -> Result<(), Error> {
        let grantee = self
            .members
            .get(&epoch.grantee_index)
            .ok_or(Error::Unverified)?;
        if grantee.roster_pk_hash != epoch.grantee_roster_pk_hash {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// The group.
    pub const fn group_id(&self) -> &[u8; 32] {
        &self.group_id
    }

    /// The current roster epoch.
    pub const fn epoch_index(&self) -> u32 {
        self.epoch_index
    }

    /// The hash of the current roster epoch.
    pub const fn chain_hash(&self) -> &[u8; 32] {
        &self.chain_hash
    }

    /// The roster epoch of this member's own admission.
    pub const fn admission_epoch(&self) -> u32 {
        self.admission_epoch
    }

    /// A member, active or not.
    pub fn member(&self, index: u16) -> Option<&Member> {
        self.members.get(&index)
    }

    /// A member, for a key to store.
    pub fn member_mut(&mut self, index: u16) -> Option<&mut Member> {
        self.members.get_mut(&index)
    }

    /// The active members in index order.
    pub fn active(&self) -> impl Iterator<Item = &Member> {
        self.members.values().filter(|m| m.active)
    }

    /// The active member count.
    pub fn active_count(&self) -> usize {
        self.active().count()
    }

    /// The active owners.
    pub fn owner_count(&self) -> usize {
        self.active().filter(|m| m.role == Role::Owner).count()
    }

    /// The active set at `roster_epoch`, if the client keeps it
    /// (`GRP-263`).
    pub fn active_at(&self, roster_epoch: u32) -> Option<&[u16]> {
        self.history
            .get(&roster_epoch)
            .map(|(set, _)| set.as_slice())
    }

    /// The rank of `index` among the active members of `roster_epoch`, for
    /// a dense tag vector.
    pub fn rank_at(&self, roster_epoch: u32, index: u16) -> Option<usize> {
        self.active_at(roster_epoch)?
            .iter()
            .position(|i| *i == index)
    }

    /// The forks shown so far.
    pub fn forks(&self) -> &[Fork] {
        &self.forks
    }

    /// The head that the last object displaced, once (`GRP-119`).
    pub fn take_displaced(&mut self) -> Option<Displaced> {
        self.displaced.take()
    }

    /// The member that made the head of the chain, while the order of
    /// `GRP-117` can still move the head.
    pub fn head_maker(&self) -> Option<u16> {
        self.undo.as_ref().map(|undo| undo.maker)
    }

    /// This roster with no roster before its head.
    fn detached(&mut self) -> Roster {
        let undo = self.undo.take();
        let copy = self.clone();
        self.undo = undo;
        copy
    }

    /// The chain fields of a roster object, if it is one.
    fn chain_of(control: &GroupControl<'_>) -> Option<umbra_wire::group::control::Chain> {
        match control.control_type {
            ControlType::PlainEpoch => PlainEpoch::parse(control.payload).ok().map(|e| e.chain),
            ControlType::GrantingEpoch => {
                GrantingEpoch::parse(control.payload).ok().map(|e| e.chain)
            }
            ControlType::ModerationEpoch => ModerationEpoch::parse(control.payload)
                .ok()
                .map(|e| e.chain),
            ControlType::Rekey => RekeyRecord::parse(control.payload)
                .ok()
                .filter(|record| !record.chain_is_zero())
                .map(|record| record.chain),
            _ => None,
        }
    }

    /// A successor of the predecessor of the head, from `sender` (§11.9.4).
    /// From another member it is the normal race of two makers, and the
    /// order of `GRP-117` decides with no fork shown (`GRP-118`). From the
    /// maker of the head it is a fork (`GRP-070`). The successor whose
    /// SHA3-256 is lower stands, as `GRP-369` orders two re-keys. Each
    /// member that reads the two then holds the same head, in each order of
    /// arrival. A rival of the re-key at the head goes to the rule of
    /// `GRP-369` itself. The result is none for an object that is no such
    /// successor.
    fn contest(
        &mut self,
        control: &GroupControl<'_>,
        chain: &umbra_wire::group::control::Chain,
        sender: u16,
        slot: u32,
        now: u64,
    ) -> Result<Option<Applied>, Error> {
        let Some(undo) = self.undo.as_ref() else {
            return Ok(None);
        };
        if chain.group_id != self.group_id
            || chain.epoch_index != self.epoch_index
            || chain.previous_epoch_hash != undo.before.chain_hash
        {
            return Ok(None);
        }
        let hash = control.epoch_hash();
        let by_maker = sender == undo.maker;
        // The same object from the same maker is a copy. A plain epoch
        // binds no maker, thus two self-removals at one predecessor carry
        // the same bytes and remove two members.
        if by_maker && hash == self.chain_hash {
            return Err(Error::Stale);
        }
        if by_maker {
            if control.control_type == ControlType::Rekey
                && self.head_rekey.is_some_and(|head| head.old_index == sender)
            {
                return Ok(None);
            }
        } else if undo
            .before
            .a_before_b(&chain.previous_epoch_hash, undo.maker, sender)
        {
            return Err(Error::Stale);
        }
        // The object applies to the roster before the head. GRP-381: each
        // check of it runs here, before it counts as a successor.
        let displaced_maker = undo.maker;
        let mut candidate = undo.before.clone();
        let applied = candidate.apply_inner(control, sender, slot, now)?;
        if by_maker {
            // GRP-072 to GRP-074: a signed object names its maker, and a
            // plain one names nobody.
            let named = matches!(
                control.control_type,
                ControlType::GrantingEpoch | ControlType::ModerationEpoch | ControlType::Rekey
            )
            .then_some(sender);
            self.show_fork(chain.previous_epoch_hash, named);
            // GRP-070: a re-key stands over each other successor of its
            // maker. A signature is random, thus a holder of the old keys
            // could grind another object to a lower hash and undo the
            // re-key. GRP-369 orders two re-keys, before this point.
            let is_rekey = control.control_type == ControlType::Rekey;
            let head_is_rekey = self.head_rekey.is_some_and(|head| head.old_index == sender);
            let stands = match (is_rekey, head_is_rekey) {
                (true, false) => true,
                (false, true) => false,
                _ => hash < self.chain_hash,
            };
            if !stands {
                return Err(Error::Stale);
            }
        }
        // The object comes first: it stands on the roster before the head,
        // and the head goes.
        let old = core::mem::replace(self, candidate);
        let before = old.undo.map(|undo| undo.before).ok_or(Error::Malformed)?;
        self.undo = Some(alloc::boxed::Box::new(Undo {
            before,
            maker: sender,
        }));
        self.forks = old.forks;
        for (key, held) in old.successors {
            self.successors.entry(key).or_insert(held);
        }
        self.displaced = Some(Displaced {
            maker: displaced_maker,
            hash: old.chain_hash,
        });
        Ok(Some(applied))
    }

    /// The re-key at the head of the chain, if the head is one.
    pub const fn head_rekey(&self) -> Option<HeadRekey> {
        self.head_rekey
    }

    /// The index that a member holds now after each re-key since `index`,
    /// or none when no re-key moved it.
    pub fn successor_of(&self, index: u16) -> Option<u16> {
        let mut at = *self.moves.get(&index)?;
        // Each move goes to a higher index, thus the walk ends.
        while let Some(next) = self.moves.get(&at) {
            at = *next;
        }
        Some(at)
    }

    /// The new index of a re-key of `old` that the chain holds already, by
    /// its hash, or none.
    pub fn holds_rekey(&self, control: &GroupControl<'_>, old: u16) -> Option<u16> {
        if control.control_type != ControlType::Rekey {
            return None;
        }
        let record = RekeyRecord::parse(control.payload).ok()?;
        let held = self
            .successors
            .get(&(record.chain.previous_epoch_hash, old))?;
        (record.old_index == old && held.0 == control.epoch_hash())
            .then(|| self.moves.get(&old).copied())
            .flatten()
    }

    /// The rival that took the place of the head re-key, if one did
    /// (`GRP-369`).
    pub const fn rekey_replaced(&self) -> Option<Replaced> {
        self.replaced
    }

    /// Whether the last object set the mark of [`Replaced`], once.
    pub fn take_rival_seen(&mut self) -> bool {
        core::mem::take(&mut self.rival_seen)
    }

    /// The second of the two re-keys of `GRP-369` verified after this
    /// member installed `rotations` epochs of their roster epoch: those
    /// epochs count. With `pending` the one epoch came before a rival that
    /// took the place of the head. Its slot for the new index went to the
    /// keys that lost, thus the rival stands as a trigger until the next
    /// epoch.
    pub fn rival_after_rotation(&mut self, rotations: u8, pending: bool) {
        if let Some(replaced) = self.replaced.as_mut() {
            replaced.rotations = rotations.min(2);
            replaced.pending = pending && rotations == 1;
        }
    }

    /// This member installed a new epoch whose record names `roster_epoch`.
    /// An epoch at or above the roster epoch of a rival answers it here.
    pub fn note_rotation(&mut self, roster_epoch: u32) {
        if let Some(replaced) = self.replaced.as_mut() {
            if roster_epoch == replaced.roster_epoch {
                replaced.rotations = replaced.rotations.saturating_add(1).min(2);
            }
            if roster_epoch >= replaced.roster_epoch {
                replaced.pending = false;
            }
        }
    }

    /// Whether a rival re-key at `roster_epoch` leaves room for one more
    /// epoch of that roster epoch (`GRP-369`). A member that took the rival
    /// before the first such epoch cannot know which keys that epoch
    /// served. Thus it takes a second one and no third.
    pub fn rival_allows_rotation(&self, roster_epoch: u32) -> bool {
        self.replaced
            .is_some_and(|replaced| replaced.roster_epoch == roster_epoch && replaced.rotations < 2)
    }

    /// Whether a member whose epoch names `roster_epoch` gives no key of it
    /// to `index` (`GRP-404`). A rival changed the keys at that index, and
    /// the epoch may have served the keys that lost.
    pub fn rival_bars_supply(&self, index: u16, roster_epoch: u32) -> bool {
        self.replaced
            .is_some_and(|replaced| replaced.new_index == index)
            && self.rival_allows_rotation(roster_epoch)
    }

    /// Shows a fork once for each predecessor and maker (`GRP-070`).
    fn show_fork(&mut self, predecessor: [u8; 32], named: Option<u16>) {
        let fork = Fork { predecessor, named };
        if !self.forks.contains(&fork) {
            self.forks.push(fork);
        }
    }

    /// The rotation triggers the roster chain holds after `roster_epoch`
    /// (§11.4.1, `GRP-357`): one for each index that the active set of an
    /// epoch lost. A removal, a self-removal, an eviction, and a re-key
    /// each lose one, and an add loses none. A rival that took the place of
    /// the re-key at `roster_epoch` after an epoch of it is a trigger too.
    /// It excludes no index (`GRP-369`). The kept history bounds the
    /// answer, thus an epoch older than `GROUP_RETENTION` raises no trigger
    /// and the age rule of `GRP-360` covers it.
    pub fn triggers_since(&self, roster_epoch: u32) -> Vec<Trigger> {
        let mut triggers = Vec::new();
        if self
            .replaced
            .is_some_and(|replaced| replaced.pending && replaced.roster_epoch == roster_epoch)
        {
            triggers.push(Trigger {
                excluded: None,
                roster_epoch,
            });
        }
        let mut before: Option<&Vec<u16>> = None;
        for (epoch, (active, _)) in self.history.range(roster_epoch..) {
            if let Some(previous) = before {
                // Each set is in index order.
                for gone in previous
                    .iter()
                    .filter(|index| active.binary_search(index).is_err())
                {
                    triggers.push(Trigger {
                        excluded: Some(*gone),
                        roster_epoch: *epoch,
                    });
                }
            }
            before = Some(active);
        }
        triggers
    }

    /// Drops the active sets older than `GROUP_RETENTION` (`GRP-263`). The
    /// current set stays, and so does the set before it, which the order of
    /// `GRP-117` can bring back. Each set at or above `keep_from` stays
    /// too. `keep_from` is the roster epoch of the oldest group epoch that
    /// this member holds. The triggers of `GRP-357` count from it, and the
    /// rotator of `GRP-356` was active at it. A successor that an epoch
    /// below each kept set made goes with them: a rival of it is stale by
    /// its index.
    pub fn retain_history(&mut self, now: u64, keep_from: u32) {
        let current = self.epoch_index;
        let floor = keep_from.min(current.saturating_sub(1));
        self.history.retain(|epoch, (_, at)| {
            *epoch >= floor || now.saturating_sub(*at) < umbra_queue::params::GROUP_RETENTION
        });
        let oldest = self.history.keys().next().copied().unwrap_or(current);
        self.successors.retain(|_, (_, epoch)| *epoch >= oldest);
        if let Some(undo) = self.undo.as_mut() {
            undo.before.retain_history(now, keep_from);
        }
    }

    /// The lowest index above every index the roster ever used
    /// (`GRP-305`).
    pub fn next_index(&self) -> Result<u16, Error> {
        match self.highest_index {
            None => Ok(0),
            Some(h) => h.checked_add(1).ok_or(Error::NoPath),
        }
    }

    /// Whether `index` is the index of the next add or re-key (`GRP-320`,
    /// `GRP-366`). A roster whose index is open takes each index from that
    /// value up to its bound, once. A group that used each index takes
    /// none (`GRP-306`).
    fn index_fits(&self, index: u16) -> bool {
        let Ok(next) = self.next_index() else {
            return false;
        };
        index == next
            || self
                .open_index
                .is_some_and(|bound| index > next && index <= bound)
    }

    /// Whether the keys of an add or a re-key serve each member (`GRP-237`,
    /// `GRP-308`). The pair key gives a contributory output, and the KEM
    /// key decodes. A sender derives a pair key with each entry, and a
    /// rotator seals a slot to each one. Thus one entry that fails would
    /// stop each of them.
    pub(crate) fn check_keys(
        keys: &umbra_wire::group::control::MemberKeys<'_>,
    ) -> Result<(), Error> {
        if !umbra_crypto::group::pair::pair_public_is_contributory(&keys.pair_pk)
            || umbra_crypto::kem::PublicKey::from_bytes(keys.kem_pk).is_err()
        {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    /// The kind of a roster object for the rates of `GRP-076`, or none for
    /// an object that is no roster object.
    pub fn rate_kind(control: &GroupControl<'_>) -> Option<RateKind> {
        match control.control_type {
            ControlType::PlainEpoch | ControlType::ModerationEpoch => Some(RateKind::Epoch),
            ControlType::GrantingEpoch => {
                let epoch = GrantingEpoch::parse(control.payload).ok()?;
                Some(if epoch.role >= Role::Moderator {
                    RateKind::Grant
                } else {
                    RateKind::Demotion
                })
            }
            ControlType::Rekey => {
                let record = RekeyRecord::parse(control.payload).ok()?;
                (!record.chain_is_zero()).then_some(RateKind::Rekey {
                    new_index: record.new_index,
                })
            }
            _ => None,
        }
    }

    /// Whether the rates of `GRP-076` take one more object of `kind` from
    /// `maker` in a record of `slot`. A maker asks before it posts, thus it
    /// posts no object that each member then discards.
    pub fn rate_allows(&self, maker: u16, kind: RateKind, slot: u32) -> bool {
        self.rates.clone().allow(maker, kind, slot)
    }

    /// Counts one object against the rates of `GRP-076`.
    fn rate(&mut self, maker: u16, kind: RateKind, slot: u32) -> Result<(), Error> {
        if self.rates.allow(maker, kind, slot) {
            Ok(())
        } else {
            Err(Error::Unverified)
        }
    }

    /// Whether the chain fields of an object fit this roster: the
    /// successor of the current epoch (`GRP-314`, `GRP-315`). An older
    /// epoch is stale, and an unknown predecessor must be held.
    fn check_chain(&self, epoch_index: u32, previous_epoch_hash: &[u8; 32]) -> Result<(), Error> {
        if epoch_index <= self.epoch_index {
            return Err(Error::Stale);
        }
        if epoch_index != self.epoch_index.saturating_add(1)
            || *previous_epoch_hash != self.chain_hash
        {
            return Err(Error::NoPath);
        }
        Ok(())
    }

    /// Records a successor of `predecessor` from `maker`, and notes a fork
    /// when the same maker made a different one before (`GRP-070`).
    fn note_successor(
        &mut self,
        predecessor: [u8; 32],
        maker: u16,
        hash: [u8; 32],
        named: bool,
    ) -> Result<(), Error> {
        match self.successors.get(&(predecessor, maker)) {
            Some((held, _)) if *held != hash => {
                self.forks.push(Fork {
                    predecessor,
                    named: named.then_some(maker),
                });
                Err(Error::Stale)
            }
            _ => {
                let epoch = self.epoch_index.saturating_add(1);
                self.successors.insert((predecessor, maker), (hash, epoch));
                Ok(())
            }
        }
    }

    fn commit(&mut self, hash: [u8; 32], now: u64) {
        self.head_rekey = None;
        self.epoch_index = self.epoch_index.saturating_add(1);
        self.chain_hash = hash;
        let active: Vec<u16> = self.active().map(|m| m.index).collect();
        self.history.insert(self.epoch_index, (active, now));
    }

    fn insert_member(
        &mut self,
        index: u16,
        keys: &umbra_wire::group::control::MemberKeys<'_>,
        role: Role,
    ) -> Result<(), Error> {
        let mut member = Member {
            index,
            role,
            pair_pk: keys.pair_pk,
            roster_pk_hash: keys.roster_pk_hash,
            kem_pk_hash: sha3_256(&[keys.kem_pk]),
            kem_pk: None,
            roster_pk: None,
            active: true,
        };
        member.set_kem_pk(keys.kem_pk)?;
        self.members.insert(index, member);
        self.highest_index = Some(index);
        // GRP-320: the index of this object is the index of the group.
        self.open_index = None;
        Ok(())
    }

    /// Applies a roster object of this member at `now`. The record that
    /// carries it holds the slot of that time (`GRP-246`).
    pub fn apply(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        now: u64,
    ) -> Result<Applied, Error> {
        self.apply_at(control, sender, slot_of(now), now)
    }

    /// Applies a roster object that a verified tag attributes to `sender`
    /// (`GRP-318`), at `now`. `slot` is the slot of the record that carried
    /// it, on which the rates of `GRP-076` count. A re-key on the pairwise
    /// channel has no sender and zero chain fields, and does not come here.
    pub fn apply_at(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        slot: u32,
        now: u64,
    ) -> Result<Applied, Error> {
        let chain = Self::chain_of(control);
        if let Some(chain) = &chain {
            if let Some(applied) = self.contest(control, chain, sender, slot, now)? {
                return Ok(applied);
            }
        }
        let extends = chain.as_ref().is_some_and(|chain| {
            chain.epoch_index == self.epoch_index.saturating_add(1)
                && chain.previous_epoch_hash == self.chain_hash
        });
        let before = extends.then(|| self.detached());
        let epoch = self.epoch_index;
        let applied = self.apply_inner(control, sender, slot, now)?;
        if let Some(before) = before {
            if self.epoch_index != epoch {
                self.undo = Some(alloc::boxed::Box::new(Undo {
                    before,
                    maker: sender,
                }));
            }
        }
        Ok(applied)
    }

    fn apply_inner(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
        slot: u32,
        now: u64,
    ) -> Result<Applied, Error> {
        let hash = control.epoch_hash();
        match control.control_type {
            ControlType::PlainEpoch => {
                let epoch = PlainEpoch::parse(control.payload)?;
                self.check_chain(epoch.chain.epoch_index, &epoch.chain.previous_epoch_hash)?;
                if epoch.chain.group_id != self.group_id {
                    return Err(Error::Unverified);
                }
                let sender_role = self
                    .members
                    .get(&sender)
                    .filter(|m| m.active)
                    .map(|m| m.role)
                    .ok_or(Error::Unverified)?;
                let applied = match epoch.op {
                    PlainOp::Add { index, keys } => {
                        if sender_role < Role::Admin
                            || !self.index_fits(index)
                            || self.active_count() >= GROUP_MAX
                        {
                            return Err(Error::Unverified);
                        }
                        Self::check_keys(&keys)?;
                        self.rate(sender, RateKind::Epoch, slot)?;
                        self.note_successor(epoch.chain.previous_epoch_hash, sender, hash, false)?;
                        self.insert_member(index, &keys, Role::Member)?;
                        Applied::Added(index)
                    }
                    PlainOp::Remove { index } => {
                        if sender_role < Role::Admin {
                            return Err(Error::Unverified);
                        }
                        let target = self
                            .members
                            .get(&index)
                            .filter(|m| m.active)
                            .ok_or(Error::Unverified)?;
                        if target.role > Role::Member {
                            return Err(Error::Unverified);
                        }
                        self.rate(sender, RateKind::Epoch, slot)?;
                        self.note_successor(epoch.chain.previous_epoch_hash, sender, hash, false)?;
                        if let Some(m) = self.members.get_mut(&index) {
                            m.active = false;
                        }
                        Applied::Removed(Trigger {
                            excluded: Some(index),
                            roster_epoch: self.epoch_index.saturating_add(1),
                        })
                    }
                    PlainOp::SelfRemoval => {
                        self.rate(sender, RateKind::Epoch, slot)?;
                        self.note_successor(epoch.chain.previous_epoch_hash, sender, hash, false)?;
                        if let Some(m) = self.members.get_mut(&sender) {
                            m.active = false;
                        }
                        Applied::Removed(Trigger {
                            excluded: Some(sender),
                            roster_epoch: self.epoch_index.saturating_add(1),
                        })
                    }
                };
                self.commit(hash, now);
                Ok(applied)
            }
            ControlType::GrantingEpoch => {
                let epoch = GrantingEpoch::parse(control.payload)?;
                self.check_chain(epoch.chain.epoch_index, &epoch.chain.previous_epoch_hash)?;
                if epoch.chain.group_id != self.group_id || epoch.granter_index != sender {
                    return Err(Error::Unverified);
                }
                self.check_granting_signature(&epoch)?;
                if epoch.granter_index == epoch.grantee_index {
                    return Err(Error::Unverified);
                }
                let granter_role = self
                    .members
                    .get(&sender)
                    .map(|m| m.role)
                    .ok_or(Error::Unverified)?;
                let grantee = self
                    .members
                    .get(&epoch.grantee_index)
                    .filter(|m| m.active)
                    .ok_or(Error::Unverified)?;
                if !Self::may_change(granter_role, grantee.role, epoch.role) {
                    return Err(Error::Unverified);
                }
                let holders = self.active().filter(|m| m.role >= Role::Moderator).count();
                if epoch.role >= Role::Moderator
                    && grantee.role < Role::Moderator
                    && holders >= ROLE_HOLDER_MAX
                {
                    return Err(Error::Unverified);
                }
                if grantee.role == Role::Owner
                    && epoch.role < Role::Owner
                    && self.owner_count() <= OWNER_MIN
                {
                    return Err(Error::Unverified);
                }
                self.check_grantee_key(&epoch)?;
                // GRP-167: an epoch that takes a role away counts against
                // no rate of the grants.
                let kind = if epoch.role >= Role::Moderator {
                    RateKind::Grant
                } else {
                    RateKind::Demotion
                };
                self.rate(sender, kind, slot)?;
                self.note_successor(epoch.chain.previous_epoch_hash, sender, hash, true)?;
                if let Some(m) = self.members.get_mut(&epoch.grantee_index) {
                    m.role = epoch.role;
                }
                self.commit(hash, now);
                Ok(Applied::Granted {
                    index: epoch.grantee_index,
                    role: epoch.role,
                })
            }
            ControlType::ModerationEpoch => {
                let epoch = ModerationEpoch::parse(control.payload)?;
                self.check_chain(epoch.chain.epoch_index, &epoch.chain.previous_epoch_hash)?;
                if epoch.chain.group_id != self.group_id || epoch.actor_index != sender {
                    return Err(Error::Unverified);
                }
                if epoch.actions.is_empty() || epoch.actions.len() > MOD_ACTION_MAX {
                    return Err(Error::Malformed);
                }
                let actor = self
                    .members
                    .get(&sender)
                    .filter(|m| m.active)
                    .ok_or(Error::Unverified)?;
                if actor.role < Role::Moderator || actor.role != epoch.actor_role {
                    return Err(Error::Unverified);
                }
                epoch.verify(&actor.roster_pk_hash)?;
                self.rate(sender, RateKind::Epoch, slot)?;
                self.note_successor(epoch.chain.previous_epoch_hash, sender, hash, true)?;
                self.commit(hash, now);
                Ok(Applied::Moderated {
                    actor_role: epoch.actor_role,
                    actions: epoch.actions,
                })
            }
            ControlType::Rekey => {
                let record = RekeyRecord::parse(control.payload)?;
                if record.chain_is_zero() {
                    return Err(Error::Malformed);
                }
                if record.chain.group_id != self.group_id || record.old_index != sender {
                    return Err(Error::Unverified);
                }
                let predecessor = record.chain.previous_epoch_hash;
                if let Some(head) = self.head_rekey.filter(|head| {
                    head.old_index == record.old_index
                        && head.predecessor == predecessor
                        && record.chain.epoch_index == self.epoch_index
                }) {
                    return self.replace_rekey(&record, head, hash, slot);
                }
                let old = self
                    .members
                    .get(&record.old_index)
                    .ok_or(Error::Unverified)?;
                let (old_key, is_active, role) = (old.roster_pk_hash, old.active, old.role);
                // The chain moved past the re-key that this one rivals, thus
                // the fork shows and nothing changes. The fork names the
                // maker, thus the signature comes first (GRP-072): a record
                // that any holder of the slot key built names nobody.
                if self
                    .successors
                    .get(&(predecessor, sender))
                    .is_some_and(|(held, _)| *held != hash)
                {
                    record.verify(&old_key)?;
                    self.show_fork(predecessor, Some(sender));
                    return Err(Error::Stale);
                }
                self.check_chain(record.chain.epoch_index, &predecessor)?;
                if !is_active {
                    return Err(Error::Unverified);
                }
                record.verify(&old_key)?;
                // GRP-366: one index leaves and one enters, thus a group
                // of `GROUP_MAX` members takes a re-key.
                if !self.index_fits(record.new_index) || self.active_count() > GROUP_MAX {
                    return Err(Error::Unverified);
                }
                Self::check_keys(&record.new_keys)?;
                self.rate(
                    sender,
                    RateKind::Rekey {
                        new_index: record.new_index,
                    },
                    slot,
                )?;
                // Two re-keys for one old index and one predecessor: the
                // lower hash wins, and the fork shows (GRP-369).
                self.note_successor(record.chain.previous_epoch_hash, sender, hash, true)?;
                if let Some(m) = self.members.get_mut(&record.old_index) {
                    m.active = false;
                }
                self.insert_member(record.new_index, &record.new_keys, role)?;
                self.commit(hash, now);
                self.head_rekey = Some(HeadRekey {
                    predecessor,
                    old_index: record.old_index,
                    new_index: record.new_index,
                });
                self.moves.insert(record.old_index, record.new_index);
                let trigger = Trigger {
                    excluded: Some(record.old_index),
                    roster_epoch: self.epoch_index,
                };
                Ok(Applied::Rekeyed {
                    old: record.old_index,
                    new: record.new_index,
                    trigger,
                    replaced: false,
                })
            }
            _ => Err(Error::Malformed),
        }
    }

    /// A rival of the re-key at the head of the chain: the same old index
    /// and the same predecessor (`GRP-369`). The fork shows, because one
    /// member made two successors, and the record whose SHA3-256 is lower
    /// stands. Both re-keys take the same new index, thus the rival changes
    /// the keys at that index and the head hash. Each member that verifies
    /// the two leaves the mark of [`Replaced`], whichever one it read
    /// first: the mark is a fact of the pair.
    fn replace_rekey(
        &mut self,
        record: &RekeyRecord<'_>,
        head: HeadRekey,
        hash: [u8; 32],
        slot: u32,
    ) -> Result<Applied, Error> {
        if hash == self.chain_hash {
            return Err(Error::Stale);
        }
        let old = self
            .members
            .get(&record.old_index)
            .ok_or(Error::Unverified)?;
        record.verify(&old.roster_pk_hash)?;
        if record.new_index != head.new_index {
            return Err(Error::Unverified);
        }
        Self::check_keys(&record.new_keys)?;
        // GRP-076: each of the two counts on the roster before the head,
        // as the one that came first did. A rival above a rate is no
        // re-key at a member that reads it first, thus it is none here.
        let mut rates = self.undo.as_ref().map(|undo| undo.before.rates.clone());
        if let Some(rates) = rates.as_mut() {
            let kind = RateKind::Rekey {
                new_index: record.new_index,
            };
            if !rates.allow(record.old_index, kind, slot) {
                return Err(Error::Unverified);
            }
        }
        self.show_fork(head.predecessor, Some(record.old_index));
        // GRP-369: the head re-key of this roster epoch had a rival. The
        // mark of an earlier copy of the pair keeps its count.
        let is_marked = self.replaced.is_some_and(|replaced| {
            replaced.roster_epoch == self.epoch_index && replaced.new_index == head.new_index
        });
        if !is_marked {
            self.replaced = Some(Replaced {
                roster_epoch: self.epoch_index,
                new_index: head.new_index,
                rotations: 0,
                pending: false,
            });
            self.rival_seen = true;
        }
        if hash > self.chain_hash {
            return Err(Error::Stale);
        }
        // The count of the re-key that stands runs from the slot of its
        // own record, at each member alike.
        if let Some(rates) = rates {
            self.rates = rates;
        }
        let role = self
            .members
            .get(&head.new_index)
            .map(|member| member.role)
            .ok_or(Error::Unverified)?;
        let mut member = Member {
            index: head.new_index,
            role,
            pair_pk: record.new_keys.pair_pk,
            roster_pk_hash: record.new_keys.roster_pk_hash,
            kem_pk_hash: sha3_256(&[record.new_keys.kem_pk]),
            kem_pk: None,
            roster_pk: None,
            active: true,
        };
        member.set_kem_pk(record.new_keys.kem_pk)?;
        self.members.insert(head.new_index, member);
        self.chain_hash = hash;
        self.successors.insert(
            (head.predecessor, record.old_index),
            (hash, self.epoch_index),
        );
        // An epoch-key record of this roster epoch can hold a slot for the
        // keys that lost, thus the rival is a trigger (GRP-368). The group
        // sets the count when its epoch is of this roster epoch.
        Ok(Applied::Rekeyed {
            old: record.old_index,
            new: head.new_index,
            trigger: Trigger {
                excluded: Some(record.old_index),
                roster_epoch: self.epoch_index,
            },
            replaced: true,
        })
    }

    /// The order of two epochs that name one predecessor from two members
    /// (`GRP-117`): the higher role first, then the lower
    /// `SHA3-256(previous_epoch_hash || BE16(index))`. Returns whether `a`
    /// comes first.
    pub fn a_before_b(&self, predecessor: &[u8; 32], a: u16, b: u16) -> bool {
        let role = |i: u16| self.members.get(&i).map(|m| m.role);
        match (role(a), role(b)) {
            (Some(ra), Some(rb)) if ra != rb => ra > rb,
            _ => {
                let key = |i: u16| sha3_256(&[predecessor, &i.to_be_bytes()]);
                key(a) < key(b)
            }
        }
    }

    /// Writes the roster to the stored form of Part 14 §14.6.4.
    pub fn export(&self, w: &mut Writer) -> Result<(), Error> {
        w.u8(ROSTER_VERSION);
        w.bytes(&self.group_id);
        w.u32(self.epoch_index);
        w.bytes(&self.chain_hash);
        w.u32(self.admission_epoch);
        w.option(self.highest_index.as_ref(), |w, index| w.u16(*index));
        w.u32(count(self.members.len())?);
        for member in self.members.values() {
            w.u16(member.index);
            w.u8(member.role as u8);
            w.bytes(&member.pair_pk);
            w.bytes(&member.roster_pk_hash);
            w.bytes(&member.kem_pk_hash);
            w.flag(member.active);
            w.option(member.kem_pk.as_ref(), |w, key| {
                let _ = w.var(key);
            });
            w.option(member.roster_pk.as_ref(), |w, key| {
                let _ = w.var(key);
            });
        }
        w.u32(count(self.history.len())?);
        for (roster_epoch, (active, at)) in &self.history {
            w.u32(*roster_epoch);
            w.u64(*at);
            w.u32(count(active.len())?);
            for index in active {
                w.u16(*index);
            }
        }
        w.u32(count(self.successors.len())?);
        for ((predecessor, maker), (hash, epoch)) in &self.successors {
            w.bytes(predecessor);
            w.u16(*maker);
            w.bytes(hash);
            w.u32(*epoch);
        }
        w.u32(count(self.forks.len())?);
        for fork in &self.forks {
            w.bytes(&fork.predecessor);
            w.option(fork.named.as_ref(), |w, index| w.u16(*index));
        }
        w.option(self.head_rekey.as_ref(), |w, head| {
            w.bytes(&head.predecessor);
            w.u16(head.old_index);
            w.u16(head.new_index);
        });
        w.u32(count(self.moves.len())?);
        for (old, new) in &self.moves {
            w.u16(*old);
            w.u16(*new);
        }
        match &self.undo {
            Some(undo) => {
                w.flag(true);
                w.u16(undo.maker);
                let mut inner = Writer::new();
                undo.before.export(&mut inner)?;
                w.var(&inner.finish())?;
            }
            None => w.flag(false),
        }
        w.option(self.replaced.as_ref(), |w, replaced| {
            w.u32(replaced.roster_epoch);
            w.u16(replaced.new_index);
            w.u8(replaced.rotations);
            w.flag(replaced.pending);
        });
        w.option(self.open_index.as_ref(), |w, index| w.u16(*index));
        self.rates.export(w)?;
        Ok(())
    }

    /// Reads a roster that [`Roster::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        let version = r.u8()?;
        if ![
            STORED_VERSION,
            ROSTER_VERSION_MOVES,
            ROSTER_VERSION_UNDO,
            ROSTER_VERSION,
        ]
        .contains(&version)
        {
            return Err(Error::Stale);
        }
        let group_id = r.array()?;
        let epoch_index = r.u32()?;
        let chain_hash = r.array()?;
        let admission_epoch = r.u32()?;
        let highest_index = r.option(Reader::u16)?;
        let mut members = BTreeMap::new();
        for _ in 0..r.u32()? {
            let member = Member {
                index: r.u16()?,
                role: Role::from_byte(r.u8()?)?,
                pair_pk: r.array()?,
                roster_pk_hash: r.array()?,
                kem_pk_hash: r.array()?,
                active: r.flag()?,
                kem_pk: r.option(|r| r.var().map(<[u8]>::to_vec))?,
                roster_pk: r.option(|r| r.var().map(<[u8]>::to_vec))?,
            };
            members.insert(member.index, member);
        }
        let mut history = BTreeMap::new();
        for _ in 0..r.u32()? {
            let roster_epoch = r.u32()?;
            let at = r.u64()?;
            let mut active = Vec::new();
            for _ in 0..r.u32()? {
                active.push(r.u16()?);
            }
            history.insert(roster_epoch, (active, at));
        }
        let mut successors = BTreeMap::new();
        for _ in 0..r.u32()? {
            let predecessor: [u8; 32] = r.array()?;
            let maker = r.u16()?;
            let hash: [u8; 32] = r.array()?;
            // A form before the epoch of a successor gives it the epoch of
            // the head, thus it stays as long as a new one does.
            let epoch = if version >= ROSTER_VERSION_RATES {
                r.u32()?
            } else {
                epoch_index
            };
            successors.insert((predecessor, maker), (hash, epoch));
        }
        let mut forks = Vec::new();
        for _ in 0..r.u32()? {
            forks.push(Fork {
                predecessor: r.array()?,
                named: r.option(Reader::u16)?,
            });
        }
        let mut head_rekey = None;
        let mut moves = BTreeMap::new();
        let mut undo = None;
        if version >= ROSTER_VERSION_MOVES {
            head_rekey = r.option(|r| {
                Ok(HeadRekey {
                    predecessor: r.array()?,
                    old_index: r.u16()?,
                    new_index: r.u16()?,
                })
            })?;
            for _ in 0..r.u32()? {
                let old = r.u16()?;
                let new = r.u16()?;
                if new <= old {
                    return Err(Error::Malformed);
                }
                moves.insert(old, new);
            }
        }
        if version >= ROSTER_VERSION_UNDO && r.flag()? {
            let maker = r.u16()?;
            let before = Roster::import(&mut Reader::new(r.var()?))?;
            if before.undo.is_some() {
                return Err(Error::Malformed);
            }
            undo = Some(alloc::boxed::Box::new(Undo { before, maker }));
        }
        let mut replaced = None;
        let mut open_index = None;
        let mut rates = RosterRates::default();
        if version >= ROSTER_VERSION_RATES {
            replaced = r.option(|r| {
                Ok(Replaced {
                    roster_epoch: r.u32()?,
                    new_index: r.u16()?,
                    rotations: r.u8()?,
                    pending: r.flag()?,
                })
            })?;
            open_index = r.option(Reader::u16)?;
            rates = RosterRates::import(r, version >= ROSTER_VERSION)?;
        }
        // GRP-076: a form before the marks of the rates counted nothing, or
        // it counted from a snapshot with no mark of it. The roster read no
        // object after the one at its head. Thus each object that it did
        // not count names a slot at or below the time of that head.
        if version < ROSTER_VERSION {
            let head = history
                .get(&epoch_index)
                .map_or(0, |(_, at): &(Vec<u16>, u64)| *at);
            rates = rates.since(slot_of(head));
        }
        Ok(Roster {
            group_id,
            epoch_index,
            chain_hash,
            members,
            highest_index,
            history,
            admission_epoch,
            successors,
            forks,
            head_rekey,
            moves,
            undo,
            displaced: None,
            replaced,
            open_index,
            rates,
            rival_seen: false,
        })
    }

    /// The authority path of the current roles, from the granting epochs
    /// that a member keeps (§11.9.3, §11.9.8): the last grant of each role
    /// holder, and for each granter the last grant before that one that
    /// named it, back to the creator at index 0. The result is the path in
    /// chain order and the position of each grant it holds; each other
    /// grant is on no path and may go (`GRP-068`, `GRP-069`).
    pub fn authority_path(&self, grants: &[&[u8]]) -> Result<(Vec<u8>, Vec<usize>), Error> {
        let mut parsed = Vec::with_capacity(grants.len());
        for bytes in grants {
            let control = GroupControl::parse(bytes)?;
            let grant = GrantingEpoch::parse(control.payload)?;
            parsed.push((
                grant.chain.epoch_index,
                grant.granter_index,
                grant.grantee_index,
            ));
        }
        let mut needed = alloc::collections::BTreeSet::new();
        let mut work: Vec<(u16, u32)> = self
            .active()
            .filter(|member| member.role >= Role::Moderator && member.index != 0)
            .map(|member| (member.index, u32::MAX))
            .collect();
        while let Some((holder, before)) = work.pop() {
            let last = parsed
                .iter()
                .enumerate()
                .filter(|(_, (epoch, _, grantee))| *grantee == holder && *epoch < before)
                .max_by_key(|(_, (epoch, _, _))| *epoch);
            let Some((position, (epoch, granter, _))) = last else {
                continue;
            };
            if needed.insert(position) && *granter != 0 {
                work.push((*granter, *epoch));
            }
        }
        let mut kept: Vec<usize> = needed.into_iter().collect();
        kept.sort_by_key(|position| parsed.get(*position).map(|(epoch, _, _)| *epoch));
        let mut path = Vec::new();
        for position in &kept {
            let bytes = grants.get(*position).ok_or(Error::Malformed)?;
            let len = u16::try_from(bytes.len()).map_err(|_| Error::Malformed)?;
            path.extend_from_slice(&len.to_be_bytes());
            path.extend_from_slice(bytes);
        }
        Ok((path, kept))
    }

    /// The entries of the roster at its current epoch, for a snapshot.
    pub fn entries(&self) -> Vec<GroupMemberEntry> {
        self.active()
            .map(|m| GroupMemberEntry {
                index: m.index,
                role: m.role,
                pair_pk: m.pair_pk,
                roster_pk_hash: m.roster_pk_hash,
                kem_pk_hash: m.kem_pk_hash,
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use crate::{abuse::test_rng::Rng, group::test_util::member};
    use umbra_crypto::group::MemberKeys as Keys;
    use umbra_wire::group::control::{Chain, MemberKeys};

    pub(crate) fn entry_of(keys: &Keys, index: u16, role: Role) -> Member {
        let kem = keys.kem().public().to_bytes();
        Member {
            index,
            role,
            pair_pk: keys.pair_public(),
            roster_pk_hash: sha3_256(&[&keys.roster().verifying_key().to_bytes()]),
            kem_pk_hash: sha3_256(&[&kem]),
            kem_pk: Some(kem.to_vec()),
            roster_pk: Some(keys.roster().verifying_key().to_bytes().to_vec()),
            active: true,
        }
    }

    pub(crate) fn add_control(roster: &Roster, keys: &Keys, index: u16) -> Vec<u8> {
        let kem = keys.kem().public().to_bytes();
        let epoch = PlainEpoch {
            chain: Chain {
                group_id: *roster.group_id(),
                epoch_index: roster.epoch_index() + 1,
                previous_epoch_hash: *roster.chain_hash(),
            },
            op: PlainOp::Add {
                index,
                keys: MemberKeys {
                    pair_pk: keys.pair_public(),
                    roster_pk_hash: sha3_256(&[&keys.roster().verifying_key().to_bytes()]),
                    kem_pk: &kem,
                },
            },
        };
        let mut payload = alloc::vec![0u8; 2_000];
        let n = epoch.encode(&mut payload).unwrap();
        payload.truncate(n);
        let control = GroupControl {
            control_type: ControlType::PlainEpoch,
            payload: &payload,
        };
        let mut out = alloc::vec![0u8; 2_100];
        let n = control.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    pub(crate) fn plain_control(roster: &Roster, op: PlainOp<'_>) -> Vec<u8> {
        let epoch = PlainEpoch {
            chain: Chain {
                group_id: *roster.group_id(),
                epoch_index: roster.epoch_index() + 1,
                previous_epoch_hash: *roster.chain_hash(),
            },
            op,
        };
        let mut payload = alloc::vec![0u8; 2_000];
        let n = epoch.encode(&mut payload).unwrap();
        payload.truncate(n);
        let control = GroupControl {
            control_type: ControlType::PlainEpoch,
            payload: &payload,
        };
        let mut out = alloc::vec![0u8; 2_100];
        let n = control.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn two_makers_at_one_predecessor_take_the_order_of_grp_117() {
        let creator = member(1);
        let bob = member(2);
        let carol = member(3);
        let dave = member(4);
        let erin = member(5);
        let mut base = Roster::genesis([7; 32], entry_of(&creator, 0, Role::Owner), 0);
        for (keys, index) in [(&bob, 1), (&carol, 2)] {
            let add = add_control(&base, keys, index);
            base.apply(&GroupControl::parse(&add).unwrap(), 0, 1)
                .unwrap();
        }
        // Two members leave at one predecessor: one set of bytes, two
        // makers. The owner adds a member at the same predecessor.
        let leave = plain_control(&base, PlainOp::SelfRemoval);
        let leave = GroupControl::parse(&leave).unwrap();
        let add = add_control(&base, &dave, 3);
        let add = GroupControl::parse(&add).unwrap();

        // GRP-117: the role comes first, thus the add of the owner stands in
        // each order of arrival, and no fork shows (GRP-118).
        let mut a = base.clone();
        let mut b = base.clone();
        a.apply(&leave, 1, 2).unwrap();
        assert_eq!(a.head_maker(), Some(1));
        assert_eq!(a.apply(&add, 0, 3).unwrap(), Applied::Added(3));
        assert_eq!(a.take_displaced().unwrap().maker, 1);
        assert_eq!(a.head_maker(), Some(0));
        b.apply(&add, 0, 2).unwrap();
        assert_eq!(b.apply(&leave, 1, 3), Err(Error::Stale));
        assert!(b.take_displaced().is_none());
        assert_eq!(a.chain_hash(), b.chain_hash());
        assert!(a.member(1).unwrap().active && b.member(1).unwrap().active);
        assert!(a.member(3).unwrap().active && b.member(3).unwrap().active);
        assert!(a.forks().is_empty() && b.forks().is_empty());

        // Two plain members: the lower SHA3(predecessor || index) stands.
        let mut c = base.clone();
        let mut d = base.clone();
        c.apply(&leave, 1, 2).unwrap();
        let _ = c.apply(&leave, 2, 3);
        d.apply(&leave, 2, 2).unwrap();
        let _ = d.apply(&leave, 1, 3);
        let first = if base.a_before_b(base.chain_hash(), 1, 2) {
            1
        } else {
            2
        };
        for roster in [&c, &d] {
            assert!(!roster.member(first).unwrap().active);
            assert!(roster.member(3 - first).unwrap().active);
        }

        // The stored form keeps the roster before the head, thus a restart
        // between the two objects still takes the order.
        let mut e = base.clone();
        e.apply(&leave, 1, 2).unwrap();
        let mut w = Writer::new();
        e.export(&mut w).unwrap();
        let bytes = w.finish();
        let mut e = Roster::import(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(e.apply(&add, 0, 3).unwrap(), Applied::Added(3));
        assert_eq!(e.chain_hash(), b.chain_hash());

        // A copy of the head from its maker changes nothing, and a second
        // successor from that maker is a fork that names nobody (GRP-073).
        // The one whose hash is lower stands, in each order of arrival.
        assert_eq!(b.apply(&add, 0, 4), Err(Error::Stale));
        let other = add_control(&base, &erin, 3);
        let other = GroupControl::parse(&other).unwrap();
        let lower = add.epoch_hash().min(other.epoch_hash());
        let mut f = base.clone();
        f.apply(&other, 0, 2).unwrap();
        let _ = f.apply(&add, 0, 3);
        let _ = b.apply(&other, 0, 4);
        for roster in [&b, &f] {
            assert_eq!(*roster.chain_hash(), lower);
            assert_eq!(roster.forks().len(), 1);
            assert_eq!(roster.forks()[0].named, None);
            assert_eq!(roster.active_count(), 4);
        }
        // A copy of the one that lost changes nothing more.
        let _ = b.apply(&add, 0, 4);
        let _ = b.apply(&other, 0, 4);
        assert_eq!(*b.chain_hash(), lower);
        assert_eq!(b.forks().len(), 1);

        // An object on the head takes the head: the head before it cannot
        // move any more.
        let late = plain_control(&b, PlainOp::Remove { index: 2 });
        b.apply(&GroupControl::parse(&late).unwrap(), 0, 5).unwrap();
        assert_eq!(b.apply(&leave, 1, 6), Err(Error::Stale));
    }

    fn grant_control(
        roster: &Roster,
        granter: &Keys,
        granter_index: u16,
        grantee: &Keys,
        grantee_index: u16,
        role: Role,
    ) -> Vec<u8> {
        let grantee_pk = grantee.roster().verifying_key().to_bytes();
        let granter_pk = granter.roster().verifying_key().to_bytes();
        let mut epoch = GrantingEpoch {
            chain: Chain {
                group_id: *roster.group_id(),
                epoch_index: roster.epoch_index() + 1,
                previous_epoch_hash: *roster.chain_hash(),
            },
            granter_index,
            grantee_index,
            grantee_roster_pk_hash: sha3_256(&[&grantee_pk]),
            role,
            granter_roster_pk: &granter_pk,
            sig: &[],
        };
        let preimage = epoch.preimage();
        let sig = granter
            .roster()
            .sign(&preimage, &mut Rng(3))
            .unwrap()
            .to_bytes();
        epoch.sig = &sig;
        let mut payload = alloc::vec![0u8; 6_000];
        let n = epoch.encode(&mut payload).unwrap();
        payload.truncate(n);
        let control = GroupControl {
            control_type: ControlType::GrantingEpoch,
            payload: &payload,
        };
        let mut out = alloc::vec![0u8; 6_100];
        let n = control.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn the_chain_adds_grants_removes_and_orders_a_contest() {
        let creator = member(1);
        let bob = member(2);
        let carol = member(3);
        let mut roster = Roster::genesis([7; 32], entry_of(&creator, 0, Role::Owner), 0);
        assert_eq!(roster.next_index().unwrap(), 1);

        let add = add_control(&roster, &bob, 1);
        let control = GroupControl::parse(&add).unwrap();
        assert_eq!(roster.apply(&control, 0, 10).unwrap(), Applied::Added(1));
        assert_eq!(roster.epoch_index(), 1);
        assert_eq!(roster.active_at(1).unwrap(), &[0, 1]);
        // A replay is stale, and a wrong index or a non-admin sender fails.
        assert_eq!(roster.apply(&control, 0, 11), Err(Error::Stale));
        let bad_index = add_control(&roster, &carol, 5);
        assert_eq!(
            roster.apply(&GroupControl::parse(&bad_index).unwrap(), 0, 12),
            Err(Error::Unverified)
        );
        let by_member = add_control(&roster, &carol, 2);
        assert_eq!(
            roster.apply(&GroupControl::parse(&by_member).unwrap(), 1, 12),
            Err(Error::Unverified)
        );
        roster
            .apply(&GroupControl::parse(&by_member).unwrap(), 0, 12)
            .unwrap();

        // A grant to owner needs an admin signer, and it carries the key of
        // that signer alone (`GRP-316`).
        let grant = grant_control(&roster, &creator, 0, &bob, 1, Role::Owner);
        let applied = roster
            .apply(&GroupControl::parse(&grant).unwrap(), 0, 13)
            .unwrap();
        assert_eq!(
            applied,
            Applied::Granted {
                index: 1,
                role: Role::Owner
            }
        );
        assert!(roster.member(1).unwrap().roster_pk.is_none());
        assert_eq!(roster.owner_count(), 2);
        let demote = grant_control(&roster, &bob, 1, &creator, 0, Role::Member);
        assert_eq!(
            roster.apply(&GroupControl::parse(&demote).unwrap(), 1, 14),
            Err(Error::Unverified)
        );
        let forged = grant_control(&roster, &carol, 2, &carol, 2, Role::Admin);
        assert_eq!(
            roster.apply(&GroupControl::parse(&forged).unwrap(), 2, 14),
            Err(Error::Unverified)
        );
        // The new owner signs under a key that this roster never held, and
        // its epoch verifies against the hash of its entry.
        let by_bob = grant_control(&roster, &bob, 1, &carol, 2, Role::Observer);
        assert_eq!(
            roster
                .apply(&GroupControl::parse(&by_bob).unwrap(), 1, 14)
                .unwrap(),
            Applied::Granted {
                index: 2,
                role: Role::Observer
            }
        );

        // A removal is a trigger, and a self-removal too.
        let remove = PlainEpoch {
            chain: Chain {
                group_id: [7; 32],
                epoch_index: roster.epoch_index() + 1,
                previous_epoch_hash: *roster.chain_hash(),
            },
            op: PlainOp::Remove { index: 2 },
        };
        let mut payload = [0u8; 128];
        let n = remove.encode(&mut payload).unwrap();
        let control = GroupControl {
            control_type: ControlType::PlainEpoch,
            payload: &payload[..n],
        };
        let mut bytes = [0u8; 160];
        let n = control.encode(&mut bytes).unwrap();
        let applied = roster
            .apply(&GroupControl::parse(&bytes[..n]).unwrap(), 1, 15)
            .unwrap();
        assert!(matches!(
            applied,
            Applied::Removed(Trigger {
                excluded: Some(2),
                ..
            })
        ));
        assert!(!roster.member(2).unwrap().active);
        assert_eq!(roster.next_index().unwrap(), 3);
        assert_eq!(roster.rank_at(roster.epoch_index(), 1), Some(1));

        // The contest order: a higher role first, then the hash.
        assert!(roster.a_before_b(&[0; 32], 0, 2));
        let owner_pair = roster.a_before_b(&[0; 32], 0, 1);
        assert_eq!(owner_pair, !roster.a_before_b(&[0; 32], 1, 0));
    }

    #[test]
    fn a_second_successor_from_one_maker_is_a_fork() {
        let creator = member(1);
        let mut roster = Roster::genesis([7; 32], entry_of(&creator, 0, Role::Owner), 0);
        let first = add_control(&roster, &member(2), 1);
        let second = add_control(&roster, &member(3), 1);
        roster
            .apply(&GroupControl::parse(&first).unwrap(), 0, 1)
            .unwrap();
        // The second names the same predecessor: stale by index, and the
        // fork check runs on the chain position.
        let mut back = Roster::genesis([7; 32], entry_of(&creator, 0, Role::Owner), 0);
        back.apply(&GroupControl::parse(&first).unwrap(), 0, 1)
            .unwrap();
        assert!(back.forks().is_empty());
        let mut again = Roster::genesis([7; 32], entry_of(&creator, 0, Role::Owner), 0);
        again
            .note_successor(
                [0; 32],
                0,
                GroupControl::parse(&first).unwrap().epoch_hash(),
                false,
            )
            .unwrap();
        assert_eq!(
            again.note_successor(
                [0; 32],
                0,
                GroupControl::parse(&second).unwrap().epoch_hash(),
                false
            ),
            Err(Error::Stale)
        );
        assert_eq!(again.forks().len(), 1);
        assert_eq!(again.forks()[0].named, None);
    }

    /// The keys of a re-key from `seed`.
    fn fresh(seed: u8) -> crate::group::join::JoinKeys {
        crate::group::join::JoinKeys {
            seed: umbra_crypto::secret::Secret::new([seed; 32]),
            keys: member(seed),
        }
    }

    /// The re-key of the member at `old_index` to the keys of `seed`.
    fn rekey_control(roster: &Roster, old: &Keys, old_index: u16, seed: u8) -> Vec<u8> {
        crate::group::join::rekey_record(old, &fresh(seed), roster, old_index, true, &mut Rng(7))
            .unwrap()
    }

    /// The creator, and the members of seed 2 and 3 at index 1 and 2.
    fn three() -> Roster {
        let mut roster = Roster::genesis([7; 32], entry_of(&member(1), 0, Role::Owner), 0);
        for (seed, index) in [(2, 1), (3, 2)] {
            let add = add_control(&roster, &member(seed), index);
            roster
                .apply(&GroupControl::parse(&add).unwrap(), 0, 1)
                .unwrap();
        }
        roster
    }

    #[test]
    fn an_add_or_a_rekey_with_a_key_that_serves_no_member_is_refused() {
        let bob = member(2);
        let mut roster = Roster::genesis([7; 32], entry_of(&member(1), 0, Role::Owner), 0);
        let kem = bob.kem().public().to_bytes();
        let hash = sha3_256(&[&bob.roster().verifying_key().to_bytes()]);
        // GRP-237: a pair key of low order gives no pair key with any
        // member, and each sender would stop at its entry.
        let low = plain_control(
            &roster,
            PlainOp::Add {
                index: 1,
                keys: MemberKeys {
                    pair_pk: [0; 32],
                    roster_pk_hash: hash,
                    kem_pk: &kem,
                },
            },
        );
        assert_eq!(
            roster.apply(&GroupControl::parse(&low).unwrap(), 0, 1),
            Err(Error::Unverified)
        );
        // GRP-308: a KEM key that does not decode takes no slot, and each
        // rotator would stop at its entry. The X25519 half is of low order.
        let mut undecoded = kem;
        undecoded[..32].fill(0);
        let bad = plain_control(
            &roster,
            PlainOp::Add {
                index: 1,
                keys: MemberKeys {
                    pair_pk: bob.pair_public(),
                    roster_pk_hash: hash,
                    kem_pk: &undecoded,
                },
            },
        );
        assert_eq!(
            roster.apply(&GroupControl::parse(&bad).unwrap(), 0, 1),
            Err(Error::Unverified)
        );
        // GRP-381: an epoch that failed counts as no successor.
        let add = add_control(&roster, &bob, 1);
        roster
            .apply(&GroupControl::parse(&add).unwrap(), 0, 1)
            .unwrap();
        assert!(roster.forks().is_empty());

        // A re-key with such a key fails the same way, under a good
        // signature of the old key.
        let old_pk = bob.roster().verifying_key().to_bytes();
        let new = member(9);
        let new_kem = new.kem().public().to_bytes();
        let mut record = RekeyRecord {
            chain: Chain {
                group_id: [7; 32],
                epoch_index: roster.epoch_index() + 1,
                previous_epoch_hash: *roster.chain_hash(),
            },
            old_index: 1,
            old_roster_pk: &old_pk,
            new_index: 2,
            new_keys: MemberKeys {
                pair_pk: [0; 32],
                roster_pk_hash: sha3_256(&[&new.roster().verifying_key().to_bytes()]),
                kem_pk: &new_kem,
            },
            sig: &[],
        };
        let sig = bob
            .roster()
            .sign(&record.preimage(), &mut Rng(4))
            .unwrap()
            .to_bytes();
        record.sig = &sig;
        let mut payload = alloc::vec![0u8; 8_000];
        let n = record.encode(&mut payload).unwrap();
        let control = GroupControl {
            control_type: ControlType::Rekey,
            payload: &payload[..n],
        };
        assert_eq!(roster.apply(&control, 1, 2), Err(Error::Unverified));
        assert!(roster.member(1).unwrap().active);
        let good = rekey_control(&roster, &bob, 1, 9);
        assert!(matches!(
            roster
                .apply(&GroupControl::parse(&good).unwrap(), 1, 2)
                .unwrap(),
            Applied::Rekeyed { old: 1, new: 2, .. }
        ));
        assert!(roster.forks().is_empty());
    }

    #[test]
    fn a_late_rival_rekey_shows_a_fork_only_under_a_signature_that_verifies() {
        let base = three();
        let mut roster = base.clone();
        let first = rekey_control(&base, &member(2), 1, 9);
        roster
            .apply(&GroupControl::parse(&first).unwrap(), 1, 2)
            .unwrap();
        let add = add_control(&roster, &member(4), 4);
        roster
            .apply(&GroupControl::parse(&add).unwrap(), 0, 3)
            .unwrap();
        // GRP-072: the fork names its maker, thus the signature comes
        // first. Any holder of the slot key builds a record under index 1
        // with a signature that does not verify, and it shows nothing.
        let rival = rekey_control(&base, &member(2), 1, 10);
        let mut forged = rival.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let refused = roster.apply(&GroupControl::parse(&forged).unwrap(), 1, 4);
        assert!(refused.is_err() && refused != Err(Error::Stale));
        assert!(roster.forks().is_empty());
        // GRP-410: the true rival came after the chain moved past the
        // re-key. The fork shows and names index 1, and nothing changes.
        let head = *roster.chain_hash();
        assert_eq!(
            roster.apply(&GroupControl::parse(&rival).unwrap(), 1, 4),
            Err(Error::Stale)
        );
        assert_eq!(roster.forks().len(), 1);
        assert_eq!(roster.forks()[0].named, Some(1));
        assert_eq!(*roster.chain_hash(), head);
    }

    #[test]
    fn a_group_of_group_max_members_takes_a_rekey_and_no_add() {
        let bob = member(2);
        let mut roster = Roster::genesis([7; 32], entry_of(&member(1), 0, Role::Owner), 0);
        // The rates count on the slot of the record, thus the adds go over
        // several slots.
        for index in 1..GROUP_MAX {
            let index = u16::try_from(index).unwrap();
            let add = add_control(&roster, &bob, index);
            roster
                .apply_at(
                    &GroupControl::parse(&add).unwrap(),
                    0,
                    u32::from(index / 50),
                    1,
                )
                .unwrap();
        }
        assert_eq!(roster.active_count(), GROUP_MAX);
        let full = add_control(&roster, &bob, 500);
        assert_eq!(
            roster.apply_at(&GroupControl::parse(&full).unwrap(), 0, 20, 2),
            Err(Error::Unverified)
        );
        // GRP-366: one index leaves and one enters.
        let rekey = rekey_control(&roster, &bob, 7, 9);
        assert!(matches!(
            roster
                .apply_at(&GroupControl::parse(&rekey).unwrap(), 7, 20, 2)
                .unwrap(),
            Applied::Rekeyed {
                old: 7,
                new: 500,
                ..
            }
        ));
        assert_eq!(roster.active_count(), GROUP_MAX);
    }

    #[test]
    fn a_rekey_stands_over_a_self_removal_of_its_maker_in_each_order() {
        // GRP-070: two holders of the keys of one member make two
        // successors of one epoch. Each member that reads the two holds the
        // same head, the re-key, and each one shows the fork.
        let base = three();
        let rekey = rekey_control(&base, &member(2), 1, 9);
        let rekey = GroupControl::parse(&rekey).unwrap();
        let leave = plain_control(&base, PlainOp::SelfRemoval);
        let leave = GroupControl::parse(&leave).unwrap();
        let lower = rekey.epoch_hash();

        let mut a = base.clone();
        a.apply(&rekey, 1, 2).unwrap();
        let _ = a.apply(&leave, 1, 3);
        let mut b = base.clone();
        b.apply(&leave, 1, 2).unwrap();
        let _ = b.apply(&rekey, 1, 3);
        // The stored form between the two keeps the order.
        let mut c = base.clone();
        c.apply(&leave, 1, 2).unwrap();
        let mut w = Writer::new();
        c.export(&mut w).unwrap();
        let bytes = w.finish();
        let mut c = Roster::import(&mut Reader::new(&bytes)).unwrap();
        let _ = c.apply(&rekey, 1, 3);
        for roster in [&a, &b, &c] {
            assert_eq!(*roster.chain_hash(), lower);
            assert_eq!(roster.forks().len(), 1);
            assert_eq!(roster.epoch_index(), base.epoch_index() + 1);
            assert!(!roster.member(1).unwrap().active);
        }
        let set = |roster: &Roster| roster.active().map(|m| m.index).collect::<Vec<_>>();
        assert_eq!(set(&a), set(&b));
        assert_eq!(set(&a), set(&c));
        assert_eq!(a.successor_of(1), b.successor_of(1));
        // An object that fails its checks is no second successor, and it
        // shows no fork (GRP-381).
        let mut d = base.clone();
        d.apply(&leave, 1, 2).unwrap();
        let forged = add_control(&base, &member(8), 3);
        assert_eq!(
            d.apply(&GroupControl::parse(&forged).unwrap(), 1, 3),
            Err(Error::Unverified)
        );
        assert!(d.forks().is_empty());
    }

    #[test]
    fn the_rates_of_the_chain_count_on_the_slot_of_the_record() {
        use crate::group::{RATE_DAY_SLOTS, REKEY_RATE_DAY, ROSTER_SLOT_RATE};
        // GRP-076: one member reads the records as they come, and one reads
        // them a month later. Each gives each object the same verdict,
        // because the slot of the record carries the rate.
        let base = three();
        let mut live = base.clone();
        let mut late = base.clone();
        let later = 40 * 86_400;
        let mut both = |object: &[u8], sender: u16, slot: u32| {
            let control = GroupControl::parse(object).unwrap();
            let first = live.apply_at(&control, sender, slot, 5).map(|_| ());
            let second = late.apply_at(&control, sender, slot, later).map(|_| ());
            assert_eq!(first, second);
            assert_eq!(live.chain_hash(), late.chain_hash());
            first
        };
        // The creator adds a member and removes it again, 60 objects in
        // one slot, and the next one of that slot is above the rate.
        let dave = member(4);
        let mut index = 3u16;
        let mut head = base.clone();
        for made in 0..ROSTER_SLOT_RATE {
            let object = if made % 2 == 0 {
                add_control(&head, &dave, index)
            } else {
                index += 1;
                plain_control(&head, PlainOp::Remove { index: index - 1 })
            };
            both(&object, 0, 900).unwrap();
            head.apply_at(&GroupControl::parse(&object).unwrap(), 0, 900, 5)
                .unwrap();
        }
        let above = add_control(&head, &dave, index);
        assert_eq!(both(&above, 0, 900), Err(Error::Unverified));
        // An older slot opens no second window, another member is inside
        // its own rate, and the next slot takes the object.
        assert_eq!(both(&above, 0, 899), Err(Error::Unverified));
        let leave = plain_control(&head, PlainOp::SelfRemoval);
        let mut other = head.clone();
        other
            .apply_at(&GroupControl::parse(&leave).unwrap(), 2, 900, 5)
            .unwrap();
        both(&above, 0, 901).unwrap();
        head.apply_at(&GroupControl::parse(&above).unwrap(), 0, 901, 5)
            .unwrap();

        // GRP-306: one member re-keys `REKEY_RATE_DAY` times in a day, and
        // the count follows it to each new index.
        let mut keys = member(2);
        let mut at = 1u16;
        for step in 0..REKEY_RATE_DAY {
            let seed = 20 + u8::try_from(step).unwrap();
            let object = rekey_control(&head, &keys, at, seed);
            both(&object, at, 902).unwrap();
            let applied = head
                .apply_at(&GroupControl::parse(&object).unwrap(), at, 902, 5)
                .unwrap();
            let Applied::Rekeyed { new, .. } = applied else {
                panic!("the re-key moved no member");
            };
            at = new;
            keys = member(seed);
        }
        let fifth = rekey_control(&head, &keys, at, 30);
        assert_eq!(both(&fifth, at, 903), Err(Error::Unverified));
        both(&fifth, at, 902 + RATE_DAY_SLOTS).unwrap();
        // A maker asks before it posts.
        assert!(!head.rate_allows(at, RateKind::Rekey { new_index: 99 }, 903));
        assert!(head.rate_allows(at, RateKind::Epoch, 903));
    }

    #[test]
    fn each_lost_index_is_a_trigger_and_the_history_keeps_what_an_epoch_names() {
        let mut roster = three();
        let remove = plain_control(&roster, PlainOp::Remove { index: 2 });
        roster
            .apply(&GroupControl::parse(&remove).unwrap(), 0, 100)
            .unwrap();
        let leave = plain_control(&roster, PlainOp::SelfRemoval);
        roster
            .apply(&GroupControl::parse(&leave).unwrap(), 1, 200)
            .unwrap();
        // GRP-357: the two epochs since epoch 2 lost one index each.
        assert_eq!(
            roster.triggers_since(2),
            alloc::vec![
                Trigger {
                    excluded: Some(2),
                    roster_epoch: 3
                },
                Trigger {
                    excluded: Some(1),
                    roster_epoch: 4
                },
            ]
        );
        assert_eq!(roster.triggers_since(3).len(), 1);
        assert!(roster.triggers_since(4).is_empty());

        // GRP-263: after the retention the sets below the epoch that the
        // group epoch names go, and the trigger count from it stays whole.
        let later = umbra_queue::params::GROUP_RETENTION + 300;
        roster.retain_history(later, 3);
        assert!(roster.active_at(2).is_none());
        assert!(roster.active_at(0).is_none());
        assert_eq!(roster.active_at(3).unwrap(), &[0, 1]);
        assert_eq!(roster.triggers_since(3).len(), 1);
        // The head and the set before it stay under each bound.
        roster.retain_history(later, u32::MAX);
        assert!(roster.active_at(3).is_some() && roster.active_at(4).is_some());
        // A successor of an epoch that went leaves with it, and the newer
        // ones stay.
        assert_eq!(roster.successors.len(), 2);
    }

    /// The stored form of a roster before `ROSTER_VERSION`.
    fn export_before(roster: &Roster, w: &mut Writer) {
        w.u8(ROSTER_VERSION_UNDO);
        w.bytes(&roster.group_id);
        w.u32(roster.epoch_index);
        w.bytes(&roster.chain_hash);
        w.u32(roster.admission_epoch);
        w.option(roster.highest_index.as_ref(), |w, index| w.u16(*index));
        w.u32(count(roster.members.len()).unwrap());
        for member in roster.members.values() {
            w.u16(member.index);
            w.u8(member.role as u8);
            w.bytes(&member.pair_pk);
            w.bytes(&member.roster_pk_hash);
            w.bytes(&member.kem_pk_hash);
            w.flag(member.active);
            w.option(member.kem_pk.as_ref(), |w, key| {
                let _ = w.var(key);
            });
            w.option(member.roster_pk.as_ref(), |w, key| {
                let _ = w.var(key);
            });
        }
        w.u32(count(roster.history.len()).unwrap());
        for (roster_epoch, (active, at)) in &roster.history {
            w.u32(*roster_epoch);
            w.u64(*at);
            w.u32(count(active.len()).unwrap());
            for index in active {
                w.u16(*index);
            }
        }
        w.u32(count(roster.successors.len()).unwrap());
        for ((predecessor, maker), (hash, _)) in &roster.successors {
            w.bytes(predecessor);
            w.u16(*maker);
            w.bytes(hash);
        }
        w.u32(0);
        w.option(roster.head_rekey.as_ref(), |w, head| {
            w.bytes(&head.predecessor);
            w.u16(head.old_index);
            w.u16(head.new_index);
        });
        w.u32(count(roster.moves.len()).unwrap());
        for (old, new) in &roster.moves {
            w.u16(*old);
            w.u16(*new);
        }
        match &roster.undo {
            Some(undo) => {
                w.flag(true);
                w.u16(undo.maker);
                let mut inner = Writer::new();
                export_before(&undo.before, &mut inner);
                w.var(&inner.finish()).unwrap();
            }
            None => w.flag(false),
        }
    }

    #[test]
    fn the_stored_roster_keeps_the_rival_and_the_rates_and_reads_the_form_before() {
        // A re-key at the head, and a rival of it with the lower hash.
        let base = three();
        let first = rekey_control(&base, &member(2), 1, 9);
        let second = rekey_control(&base, &member(2), 1, 10);
        let (first, second) = (
            GroupControl::parse(&first).unwrap(),
            GroupControl::parse(&second).unwrap(),
        );
        let (high, low) = if first.epoch_hash() > second.epoch_hash() {
            (first, second)
        } else {
            (second, first)
        };
        let mut roster = base.clone();
        roster.apply(&high, 1, 2).unwrap();
        assert!(roster.rekey_replaced().is_none());
        assert!(matches!(
            roster.apply(&low, 1, 3).unwrap(),
            Applied::Rekeyed { replaced: true, .. }
        ));
        // GRP-369: the mark of the rival, and one epoch of its roster epoch
        // that came before it.
        let epoch = roster.epoch_index();
        assert_eq!(roster.rekey_replaced().unwrap().roster_epoch, epoch);
        assert_eq!(roster.rekey_replaced().unwrap().new_index, 3);
        assert!(roster.take_rival_seen() && !roster.take_rival_seen());
        roster.rival_after_rotation(1, true);
        assert_eq!(
            roster.triggers_since(epoch),
            alloc::vec![Trigger {
                excluded: None,
                roster_epoch: epoch
            }]
        );
        assert!(roster.rival_bars_supply(3, epoch));
        assert!(!roster.rival_bars_supply(0, epoch));

        let mut w = Writer::new();
        roster.export(&mut w).unwrap();
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        let mut back = Roster::import(&mut reader).unwrap();
        reader.end().unwrap();
        assert_eq!(back.rekey_replaced(), roster.rekey_replaced());
        assert_eq!(back.triggers_since(epoch).len(), 1);
        assert_eq!(back.rates, roster.rates);
        assert_eq!(back.successors, roster.successors);
        // The next epoch of that roster epoch answers the rival, and no
        // third one has room.
        back.note_rotation(epoch);
        assert!(back.triggers_since(epoch).is_empty());
        assert!(!back.rival_allows_rotation(epoch));
        assert!(!back.rival_bars_supply(3, epoch));

        // The form before this one holds no rival and no rate, and a read
        // takes it.
        let mut w = Writer::new();
        export_before(&roster, &mut w);
        let bytes = w.finish();
        let mut reader = Reader::new(&bytes);
        let old = Roster::import(&mut reader).unwrap();
        reader.end().unwrap();
        assert_eq!(old.chain_hash(), roster.chain_hash());
        assert_eq!(old.head_rekey(), roster.head_rekey());
        assert_eq!(old.head_maker(), roster.head_maker());
        assert!(old.rekey_replaced().is_none());
        // GRP-076: it counted nothing, thus it knows no window that stands
        // at the time of its head.
        assert_eq!(old.rates, RosterRates::partial(slot_of(3)));
        assert!(!old.rates_are_whole() && roster.rates_are_whole());
        assert_eq!(old.successors.len(), roster.successors.len());
    }

    #[test]
    fn the_mark_of_a_rival_rekey_is_one_in_each_order_of_the_two() {
        // GRP-369: the two re-keys of one index at one predecessor, read
        // in each order. The head and the mark are one.
        let base = three();
        let first = rekey_control(&base, &member(2), 1, 9);
        let second = rekey_control(&base, &member(2), 1, 10);
        let (first, second) = (
            GroupControl::parse(&first).unwrap(),
            GroupControl::parse(&second).unwrap(),
        );
        let (high, low) = if first.epoch_hash() > second.epoch_hash() {
            (first, second)
        } else {
            (second, first)
        };
        let mut loser_first = base.clone();
        loser_first.apply_at(&high, 1, 50, 2).unwrap();
        loser_first.apply_at(&low, 1, 53, 3).unwrap();
        let mut winner_first = base.clone();
        winner_first.apply_at(&low, 1, 53, 2).unwrap();
        assert!(winner_first.rekey_replaced().is_none());
        assert_eq!(winner_first.apply_at(&high, 1, 50, 3), Err(Error::Stale));
        assert!(winner_first.take_rival_seen());
        assert_eq!(winner_first.rekey_replaced(), loser_first.rekey_replaced());
        assert_eq!(winner_first.chain_hash(), loser_first.chain_hash());
        assert_eq!(winner_first.forks(), loser_first.forks());
        // GRP-076: the count of the re-key runs from the slot of the record
        // that stands, in each order.
        assert_eq!(winner_first.rates, loser_first.rates);
        // A second copy of the record that lost keeps the count of the
        // mark.
        winner_first.rival_after_rotation(1, false);
        assert_eq!(winner_first.apply_at(&high, 1, 50, 4), Err(Error::Stale));
        assert!(!winner_first.take_rival_seen());
        assert!(winner_first.rival_allows_rotation(winner_first.epoch_index()));
        winner_first.note_rotation(winner_first.epoch_index());
        assert!(!winner_first.rival_allows_rotation(winner_first.epoch_index()));
    }

    #[test]
    fn a_roster_from_a_snapshot_builds_no_index_until_an_object_gives_it() {
        // GRP-329: the highest index of the group can lie above each entry
        // of a snapshot. Thus the roster builds no add and no re-key from
        // its own count.
        let mut roster = three();
        assert_eq!(roster.build_index().unwrap(), 3);
        roster.open_next_index();
        assert!(roster.index_is_open());
        assert_eq!(roster.build_index(), Err(Error::NoPath));
        let mut w = Writer::new();
        roster.export(&mut w).unwrap();
        let bytes = w.finish();
        let mut roster = Roster::import(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(roster.build_index(), Err(Error::NoPath));
        // The add of another member gives the index.
        let mut ahead = three();
        let add = add_control(&ahead, &member(4), 3);
        ahead
            .apply(&GroupControl::parse(&add).unwrap(), 0, 5)
            .unwrap();
        roster
            .apply(&GroupControl::parse(&add).unwrap(), 0, 5)
            .unwrap();
        assert!(!roster.index_is_open());
        assert_eq!(roster.build_index().unwrap(), 4);
    }

    /// `three()` with the member at index 1 as `admin`.
    fn three_with_admin() -> Roster {
        let mut roster = three();
        let grant = grant_control(&roster, &member(1), 0, &member(2), 1, Role::Admin);
        roster
            .apply(&GroupControl::parse(&grant).unwrap(), 0, 2)
            .unwrap();
        roster
    }

    #[test]
    fn an_admin_that_a_rekey_took_out_grants_nothing_on_the_head() {
        // GRP-063, GRP-257: the admin at index 1 re-keys. A device that
        // still holds the old keys signs a grant that extends the head. The
        // maker of the head passes the check of the sender, and its old
        // entry keeps the role.
        let mut roster = three_with_admin();
        let rekey = rekey_control(&roster, &member(2), 1, 9);
        roster
            .apply(&GroupControl::parse(&rekey).unwrap(), 1, 3)
            .unwrap();
        assert_eq!(roster.head_maker(), Some(1));
        assert!(!roster.member(1).unwrap().active);
        let grant = grant_control(&roster, &member(2), 1, &member(3), 2, Role::Admin);
        let head = *roster.chain_hash();
        assert_eq!(
            roster.apply(&GroupControl::parse(&grant).unwrap(), 1, 4),
            Err(Error::Unverified)
        );
        assert_eq!(*roster.chain_hash(), head);
        assert_eq!(roster.member(2).unwrap().role, Role::Member);
        // The new keys of the member grant as before.
        let grant = grant_control(&roster, &member(9), 3, &member(3), 2, Role::Moderator);
        roster
            .apply(&GroupControl::parse(&grant).unwrap(), 3, 4)
            .unwrap();
        assert_eq!(roster.member(2).unwrap().role, Role::Moderator);
    }

    #[test]
    fn a_rekey_stands_over_a_grant_of_its_maker_in_each_order() {
        // GRP-070: the holder of the old keys of an admin signs a grant at
        // the predecessor of the re-key of the user. A signature is random,
        // thus the hash of the grant can lie on either side. The re-key
        // stands at each member, in each order of arrival.
        let base = three_with_admin();
        let rekey = rekey_control(&base, &member(2), 1, 9);
        let rekey = GroupControl::parse(&rekey).unwrap();
        for seed in [3u64, 4, 5, 6] {
            let grant = {
                let granter = member(2);
                let grantee_pk = member(3).roster().verifying_key().to_bytes();
                let granter_pk = granter.roster().verifying_key().to_bytes();
                let mut epoch = GrantingEpoch {
                    chain: Chain {
                        group_id: *base.group_id(),
                        epoch_index: base.epoch_index() + 1,
                        previous_epoch_hash: *base.chain_hash(),
                    },
                    granter_index: 1,
                    grantee_index: 2,
                    grantee_roster_pk_hash: sha3_256(&[&grantee_pk]),
                    role: Role::Admin,
                    granter_roster_pk: &granter_pk,
                    sig: &[],
                };
                let sig = granter
                    .roster()
                    .sign(&epoch.preimage(), &mut Rng(seed))
                    .unwrap()
                    .to_bytes();
                epoch.sig = &sig;
                let mut payload = alloc::vec![0u8; 6_000];
                let n = epoch.encode(&mut payload).unwrap();
                let control = GroupControl {
                    control_type: ControlType::GrantingEpoch,
                    payload: &payload[..n],
                };
                let mut out = alloc::vec![0u8; 6_100];
                let n = control.encode(&mut out).unwrap();
                out.truncate(n);
                out
            };
            let grant = GroupControl::parse(&grant).unwrap();
            let mut a = base.clone();
            a.apply(&rekey, 1, 3).unwrap();
            assert_eq!(a.apply(&grant, 1, 4), Err(Error::Stale));
            let mut b = base.clone();
            b.apply(&grant, 1, 3).unwrap();
            assert!(matches!(
                b.apply(&rekey, 1, 4).unwrap(),
                Applied::Rekeyed { old: 1, new: 3, .. }
            ));
            assert_eq!(b.take_displaced().unwrap().maker, 1);
            for roster in [&a, &b] {
                assert_eq!(*roster.chain_hash(), rekey.epoch_hash());
                assert_eq!(roster.forks().len(), 1);
                assert_eq!(roster.forks()[0].named, Some(1));
                assert_eq!(roster.member(2).unwrap().role, Role::Member);
                assert!(roster.member(3).unwrap().active);
            }
        }
    }

    #[test]
    fn only_an_owner_names_an_owner_and_no_granter_grants_itself() {
        let mut roster = three_with_admin();
        let refused = |roster: &mut Roster, control: &[u8], sender: u16| {
            let head = *roster.chain_hash();
            let result = roster.apply_at(&GroupControl::parse(control).unwrap(), sender, 5, 5);
            assert_eq!(result, Err(Error::Unverified));
            assert_eq!(*roster.chain_hash(), head);
        };
        // GRP-063: an admin gives no `owner` and takes no role of an owner.
        let to_owner = grant_control(&roster, &member(2), 1, &member(3), 2, Role::Owner);
        refused(&mut roster, &to_owner, 1);
        let demote = grant_control(&roster, &member(2), 1, &member(1), 0, Role::Member);
        refused(&mut roster, &demote, 1);
        // No granter grants itself, up or down.
        let up = grant_control(&roster, &member(2), 1, &member(2), 1, Role::Owner);
        refused(&mut roster, &up, 1);
        let down = grant_control(&roster, &member(2), 1, &member(2), 1, Role::Member);
        refused(&mut roster, &down, 1);
        // An owner does each of them for another member.
        let by_owner = grant_control(&roster, &member(1), 0, &member(3), 2, Role::Owner);
        roster
            .apply_at(&GroupControl::parse(&by_owner).unwrap(), 0, 6, 6)
            .unwrap();
        assert_eq!(roster.owner_count(), 2);
        // An admin still gives and takes the roles below `owner`.
        let by_admin = grant_control(&roster, &member(2), 1, &member(1), 0, Role::Admin);
        refused(&mut roster, &by_admin, 1);
        let back = grant_control(&roster, &member(3), 2, &member(2), 1, Role::Moderator);
        roster
            .apply_at(&GroupControl::parse(&back).unwrap(), 2, 7, 7)
            .unwrap();
        assert_eq!(roster.member(1).unwrap().role, Role::Moderator);
    }

    /// The path of `GRP-326` from `grants`, each `BE16(len) || GroupControl`.
    fn path_of(grants: &[&[u8]]) -> Vec<u8> {
        let mut path = Vec::new();
        for grant in grants {
            path.extend_from_slice(&u16::try_from(grant.len()).unwrap().to_be_bytes());
            path.extend_from_slice(grant);
        }
        path
    }

    /// The roster of a snapshot of `entries` with the KEM keys of `keys`.
    fn from_entries(
        roster: &Roster,
        entries: Vec<GroupMemberEntry>,
        keys: &[(u16, Vec<u8>)],
        path: &[u8],
    ) -> Result<Roster, Error> {
        let snapshot = RosterSnapshot {
            group_id: *roster.group_id(),
            roster_epoch: roster.epoch_index(),
            chain_hash: *roster.chain_hash(),
            entries,
            keys: keys
                .iter()
                .map(|(index, kem_pk)| umbra_wire::group::control::MemberKemKey {
                    index: *index,
                    kem_pk,
                })
                .collect(),
            path,
        };
        let creator_pk = member(1).roster().verifying_key().to_bytes();
        Roster::from_snapshot(&snapshot, roster.chain_hash(), &creator_pk, 9)
    }

    #[test]
    fn a_snapshot_backs_each_role_by_its_key_and_traces_it_to_the_creator() {
        // The creator names the member at index 1 `owner` and leaves.
        let mut roster = three();
        let grant = grant_control(&roster, &member(1), 0, &member(2), 1, Role::Owner);
        roster
            .apply(&GroupControl::parse(&grant).unwrap(), 0, 2)
            .unwrap();
        let leave = plain_control(&roster, PlainOp::SelfRemoval);
        roster
            .apply(&GroupControl::parse(&leave).unwrap(), 0, 3)
            .unwrap();
        let path = path_of(&[&grant]);
        let kem = |seed: u8| member(seed).kem().public().to_bytes().to_vec();
        let keys = [(1, kem(2)), (2, kem(3))];
        let whole = from_entries(&roster, roster.entries(), &keys, &path).unwrap();
        assert_eq!(whole.member(1).unwrap().role, Role::Owner);

        // GRP-399: an entry at the index of the creator with keys of its
        // own claims `owner`. The creator holds no entry, and its index
        // starts the path under the key of the creator alone.
        let fake = member(9);
        let mut entries = roster.entries();
        entries.insert(
            0,
            GroupMemberEntry {
                index: 0,
                role: Role::Owner,
                pair_pk: fake.pair_public(),
                roster_pk_hash: sha3_256(&[&fake.roster().verifying_key().to_bytes()]),
                kem_pk_hash: sha3_256(&[&fake.kem().public().to_bytes()]),
            },
        );
        let mut with_fake = alloc::vec![(0, kem(9))];
        with_fake.extend(keys.iter().cloned());
        assert_eq!(
            from_entries(&roster, entries.clone(), &with_fake, &path).err(),
            Some(Error::Unverified)
        );
        // The same with no path at all.
        assert_eq!(
            from_entries(&roster, entries, &with_fake, &[]).err(),
            Some(Error::Unverified)
        );
        // A grantee whose entry holds keys other than the grant names.
        let mut entries = roster.entries();
        entries[0].roster_pk_hash = sha3_256(&[&fake.roster().verifying_key().to_bytes()]);
        assert!(from_entries(&roster, entries, &keys, &path).is_err());
    }
}
