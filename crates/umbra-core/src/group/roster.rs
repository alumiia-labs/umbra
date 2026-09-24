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

use super::{GROUP_MAX, MOD_ACTION_MAX, OWNER_MIN, ROLE_HOLDER_MAX};
use crate::Error;

/// The version of each stored object of a group.
pub(crate) const STORED_VERSION: u8 = 0x01;

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
    /// Moderation actions to apply, after the signature check.
    Moderated(Vec<ModAction>),
    /// A member moved to new keys under a new index; a trigger.
    Rekeyed {
        /// The old index, which the trigger excludes.
        old: u16,
        /// The new index.
        new: u16,
        /// The trigger.
        trigger: Trigger,
    },
}

/// A fork the client must show (`GRP-070` to `GRP-074`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// The predecessor both successors name.
    pub predecessor: [u8; 32],
    /// The member that made both, when a signature names it.
    pub named: Option<u16>,
}

/// The roster of one group at one member.
pub struct Roster {
    group_id: [u8; 32],
    epoch_index: u32,
    chain_hash: [u8; 32],
    members: BTreeMap<u16, Member>,
    highest_index: Option<u16>,
    history: BTreeMap<u32, (Vec<u16>, u64)>,
    admission_epoch: u32,
    successors: BTreeMap<([u8; 32], u16), [u8; 32]>,
    forks: Vec<Fork>,
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
        };
        roster.verify_path(snapshot.path, creator_roster_pk)?;
        Ok(roster)
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
        let creator_index = creator.unwrap_or(0);
        state.insert(creator_index, (Role::Owner, creator_hash));
        for grant in &grants {
            if grant.chain.group_id != self.group_id {
                return Err(Error::Unverified);
            }
            let (granter_role, granter_hash) =
                *state.get(&grant.granter_index).ok_or(Error::Unverified)?;
            if granter_role < Role::Admin {
                return Err(Error::Unverified);
            }
            grant.verify(&granter_hash)?;
            match state.get_mut(&grant.grantee_index) {
                Some((role, hash)) => {
                    if *hash != grant.grantee_roster_pk_hash {
                        return Err(Error::Unverified);
                    }
                    *role = grant.role;
                }
                None => {
                    state.insert(
                        grant.grantee_index,
                        (grant.role, grant.grantee_roster_pk_hash),
                    );
                }
            }
        }
        let backed = |member: &Member| {
            member.role < Role::Moderator
                || member.index == creator_index && member.roster_pk_hash == creator_hash
                || state.get(&member.index).map(|(role, _)| *role) == Some(member.role)
        };
        if !self.members.values().all(backed) {
            return Err(Error::Unverified);
        }
        Ok(())
    }

    fn check_granting_signature(&self, epoch: &GrantingEpoch<'_>) -> Result<(), Error> {
        let granter = self
            .members
            .get(&epoch.granter_index)
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

    /// The rotation triggers the roster chain holds after `roster_epoch`
    /// (§11.4.1, `GRP-357`): each epoch whose active set lost an index. A
    /// removal, a self-removal, an eviction, and a re-key each lose one,
    /// and an add loses none. The kept history bounds the answer, thus an
    /// epoch older than `GROUP_RETENTION` raises no trigger and the age
    /// rule of `GRP-360` covers it.
    pub fn triggers_since(&self, roster_epoch: u32) -> Vec<Trigger> {
        let mut triggers = Vec::new();
        let mut before: Option<&Vec<u16>> = None;
        for (epoch, (active, _)) in &self.history {
            if let Some(previous) = before {
                if *epoch > roster_epoch {
                    if let Some(gone) = previous.iter().find(|index| !active.contains(index)) {
                        triggers.push(Trigger {
                            excluded: Some(*gone),
                            roster_epoch: *epoch,
                        });
                    }
                }
            }
            before = Some(active);
        }
        triggers
    }

    /// Drops the active sets older than `GROUP_RETENTION` (`GRP-263`),
    /// and never the current one.
    pub fn retain_history(&mut self, now: u64) {
        let current = self.epoch_index;
        self.history.retain(|epoch, (_, at)| {
            *epoch == current || now.saturating_sub(*at) < umbra_queue::params::GROUP_RETENTION
        });
    }

    /// The lowest index above every index the roster ever used
    /// (`GRP-305`).
    pub fn next_index(&self) -> Result<u16, Error> {
        match self.highest_index {
            None => Ok(0),
            Some(h) => h.checked_add(1).ok_or(Error::NoPath),
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
            Some(held) if *held != hash => {
                self.forks.push(Fork {
                    predecessor,
                    named: named.then_some(maker),
                });
                Err(Error::Stale)
            }
            _ => {
                self.successors.insert((predecessor, maker), hash);
                Ok(())
            }
        }
    }

    fn commit(&mut self, hash: [u8; 32], now: u64) {
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
        if index != self.next_index()? || self.active_count() >= GROUP_MAX {
            return Err(Error::Unverified);
        }
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
        Ok(())
    }

    /// Applies a roster object that a verified tag attributes to `sender`
    /// (`GRP-318`), at `now`. A re-key on the pairwise channel has no
    /// sender and zero chain fields, and does not come here.
    pub fn apply(
        &mut self,
        control: &GroupControl<'_>,
        sender: u16,
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
                            || index != self.next_index()?
                            || self.active_count() >= GROUP_MAX
                            || sha3_256(&[keys.kem_pk]) == [0; 32]
                        {
                            return Err(Error::Unverified);
                        }
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
                let grantee = self
                    .members
                    .get(&epoch.grantee_index)
                    .filter(|m| m.active)
                    .ok_or(Error::Unverified)?;
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
                self.note_successor(epoch.chain.previous_epoch_hash, sender, hash, true)?;
                self.commit(hash, now);
                Ok(Applied::Moderated(epoch.actions))
            }
            ControlType::Rekey => {
                let record = RekeyRecord::parse(control.payload)?;
                if record.chain_is_zero() {
                    return Err(Error::Malformed);
                }
                self.check_chain(record.chain.epoch_index, &record.chain.previous_epoch_hash)?;
                if record.chain.group_id != self.group_id || record.old_index != sender {
                    return Err(Error::Unverified);
                }
                let old = self
                    .members
                    .get(&record.old_index)
                    .filter(|m| m.active)
                    .ok_or(Error::Unverified)?;
                record.verify(&old.roster_pk_hash)?;
                let role = old.role;
                if record.new_index != self.next_index()? || self.active_count() >= GROUP_MAX {
                    return Err(Error::Unverified);
                }
                // Two re-keys for one old index and one predecessor: the
                // lower hash wins, and the fork shows (GRP-369).
                self.note_successor(record.chain.previous_epoch_hash, sender, hash, true)?;
                self.insert_member(record.new_index, &record.new_keys, role)?;
                if let Some(m) = self.members.get_mut(&record.old_index) {
                    m.active = false;
                }
                self.commit(hash, now);
                let trigger = Trigger {
                    excluded: Some(record.old_index),
                    roster_epoch: self.epoch_index,
                };
                Ok(Applied::Rekeyed {
                    old: record.old_index,
                    new: record.new_index,
                    trigger,
                })
            }
            _ => Err(Error::Malformed),
        }
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
        w.u8(STORED_VERSION);
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
        for ((predecessor, maker), hash) in &self.successors {
            w.bytes(predecessor);
            w.u16(*maker);
            w.bytes(hash);
        }
        w.u32(count(self.forks.len())?);
        for fork in &self.forks {
            w.bytes(&fork.predecessor);
            w.option(fork.named.as_ref(), |w, index| w.u16(*index));
        }
        Ok(())
    }

    /// Reads a roster that [`Roster::export`] wrote.
    pub fn import(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.u8()? != STORED_VERSION {
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
            successors.insert((predecessor, maker), r.array()?);
        }
        let mut forks = Vec::new();
        for _ in 0..r.u32()? {
            forks.push(Fork {
                predecessor: r.array()?,
                named: r.option(Reader::u16)?,
            });
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
}
