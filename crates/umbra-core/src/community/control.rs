//! The control objects of a community (Part 12 §12.5.2): the community
//! roster with its owner cosignatures, the moderator set, and the
//! moderation epoch. Each object names its signer, carries the key of that
//! signer, and chains to the object before it.

use alloc::vec::Vec;

use umbra_crypto::{
    hash::sha3_256,
    kem::PUBLIC_KEY_LEN,
    labels,
    rand_core::TryCryptoRng,
    sign::{SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::{
    address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN},
    codec::{Reader, Writer},
};

use super::{
    identity::RoleIdentity, pseudonym_of, record::verify_signature, RecordType, MODERATOR_MAX,
    MOD_ACTION_MAX, NO_INDEX, ROSTER_ENTRY_MAX, VERSION,
};
use crate::Error;

/// The length of a `RosterEntry`.
pub const ROSTER_ENTRY_LEN: usize = 1 + 32 + PUBLIC_KEY_LEN + QUEUE_ADDRESS_LEN;
/// The length of a `RosterCosign`.
pub const ROSTER_COSIGN_LEN: usize = 32 + VERIFYING_KEY_LEN + SIGNATURE_LEN;
/// The length of a `ModerationAction`.
pub const MODERATION_ACTION_LEN: usize = 37;
/// The largest record that one `PAGE` holds: the `B3` L5 payload less the
/// 51 bytes of the page header and the 10 bytes of the entry (`COM-182`).
pub const RECORD_MAX: usize = 32_650 - 61;

/// A role in a community, in the order of precedence (§12.5.2 rule 6).
/// The byte values are those of a `RosterEntry` and of `actor_role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    /// An owner, which signs a roster.
    Owner = 1,
    /// An admin, which signs a moderator set and receives a report.
    Admin = 2,
    /// A moderator, which a moderator set names.
    Moderator = 3,
}

impl Role {
    fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            1 => Role::Owner,
            2 => Role::Admin,
            3 => Role::Moderator,
            _ => return Err(Error::Malformed),
        })
    }
}

/// One owner or one admin in a `CommunityRoster`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    /// `Owner` or `Admin`.
    pub role: Role,
    /// The role pseudonym of the member.
    pub pseudonym: [u8; 32],
    /// The encapsulation key of `RoleReportKey_r`.
    pub report_ek: Vec<u8>,
    /// The encoded `QueueAddress` of the report queue. The roster is
    /// public, thus the address is held as the bytes that the roster shows.
    pub report_queue: [u8; QUEUE_ADDRESS_LEN],
}

impl RosterEntry {
    /// An entry for `member` with the report queue that the member gave
    /// the signer (`COM-275`).
    pub fn new(
        role: Role,
        member: &RoleIdentity,
        report_queue: &QueueAddress,
    ) -> Result<Self, Error> {
        let mut queue = [0u8; QUEUE_ADDRESS_LEN];
        report_queue.encode(&mut queue)?;
        Ok(RosterEntry {
            role,
            pseudonym: member.pseudonym(),
            report_ek: member.report_key().public().to_bytes().to_vec(),
            report_queue: queue,
        })
    }

    /// The report queue.
    pub fn queue(&self) -> Result<QueueAddress, Error> {
        Ok(QueueAddress::parse(&self.report_queue)?)
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        if self.role == Role::Moderator || self.report_ek.len() != PUBLIC_KEY_LEN {
            return Err(Error::Malformed);
        }
        w.u8(self.role as u8)?;
        w.put(&self.pseudonym)?;
        w.put(&self.report_ek)?;
        w.put(&self.report_queue)?;
        Ok(())
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let role = Role::from_byte(r.u8()?)?;
        if role == Role::Moderator {
            return Err(Error::Malformed);
        }
        let entry = RosterEntry {
            role,
            pseudonym: r.array()?,
            report_ek: r.take(PUBLIC_KEY_LEN)?.to_vec(),
            report_queue: r.array()?,
        };
        entry.queue()?;
        Ok(entry)
    }
}

/// The cosignature of one owner over the preimage of a roster (§12.5.2
/// rule 12). It carries the key of that owner, because a `RosterEntry`
/// holds no signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterCosign {
    /// The owner role pseudonym.
    pub actor: [u8; 32],
    /// The ML-DSA-65 public key of that pseudonym.
    pub actor_pk: Vec<u8>,
    /// The signature over the preimage of the roster.
    pub signature: Vec<u8>,
}

/// The kind of a moderation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionKind {
    /// Remove a post.
    Remove = 1,
    /// Ban a pseudonym, with or without a removal of its history.
    Ban = 2,
    /// Pin a post.
    Pin = 3,
    /// Lock the community.
    Lock = 4,
    /// Unban a pseudonym.
    Unban = 5,
    /// Unpin a post.
    Unpin = 6,
    /// Unlock the community.
    Unlock = 7,
    /// Restore a removed post.
    Restore = 8,
}

impl ActionKind {
    /// The lowest role that the kind needs. A lock stops each author of
    /// the community, thus it needs an admin.
    pub fn minimum_role(self) -> Role {
        match self {
            ActionKind::Lock | ActionKind::Unlock => Role::Admin,
            _ => Role::Moderator,
        }
    }
}

/// One `ModerationAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModerationAction {
    /// The kind.
    pub kind: ActionKind,
    /// The authoring pseudonym, or zero bytes for a lock and an unlock.
    pub target: [u8; 32],
    /// The post index, the ban bound, the lock duration, or `NO_INDEX`.
    pub index: u32,
}

impl ModerationAction {
    fn check(&self) -> Result<(), Error> {
        let zero_target = self.target == [0u8; 32];
        let valid = match self.kind {
            // COM-116: a removal names the pair, and the same holds for a
            // pin, an unpin, and a restore.
            ActionKind::Remove | ActionKind::Pin | ActionKind::Unpin | ActionKind::Restore => {
                !zero_target && self.index != NO_INDEX
            }
            ActionKind::Ban => !zero_target,
            ActionKind::Unban => !zero_target && self.index == NO_INDEX,
            ActionKind::Lock => zero_target,
            ActionKind::Unlock => zero_target && self.index == NO_INDEX,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        // COM-295: a kind outside the table rejects the epoch.
        let kind = match r.u8()? {
            1 => ActionKind::Remove,
            2 => ActionKind::Ban,
            3 => ActionKind::Pin,
            4 => ActionKind::Lock,
            5 => ActionKind::Unban,
            6 => ActionKind::Unpin,
            7 => ActionKind::Unlock,
            8 => ActionKind::Restore,
            _ => return Err(Error::Malformed),
        };
        let action = ModerationAction {
            kind,
            target: r.array()?,
            index: r.u32()?,
        };
        action.check()?;
        Ok(action)
    }
}

/// The part of a control object that its type gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlBody {
    /// A `CommunityRoster`.
    Roster {
        /// The owners and the admins.
        entries: Vec<RosterEntry>,
        /// The owner cosignatures of rule 12.
        cosigns: Vec<RosterCosign>,
    },
    /// A `ModeratorSet`, in strictly increasing byte order.
    ModeratorSet {
        /// The role pseudonym of each moderator.
        moderators: Vec<[u8; 32]>,
    },
    /// A `ModerationEpoch`.
    Moderation {
        /// The role that the signer states.
        actor_role: Role,
        /// The actions.
        actions: Vec<ModerationAction>,
    },
}

impl ControlBody {
    /// The record type.
    pub fn record_type(&self) -> RecordType {
        match self {
            ControlBody::Roster { .. } => RecordType::Roster,
            ControlBody::ModeratorSet { .. } => RecordType::ModeratorSet,
            ControlBody::Moderation { .. } => RecordType::ModerationEpoch,
        }
    }

    fn label(&self) -> &'static [u8] {
        match self {
            ControlBody::Roster { .. } => labels::COMMUNITY_ROSTER,
            ControlBody::ModeratorSet { .. } => labels::MODERATOR_SET,
            ControlBody::Moderation { .. } => labels::COMMUNITY_MODERATION,
        }
    }

    fn check(&self) -> Result<(), Error> {
        match self {
            ControlBody::Roster { entries, .. } => {
                // COM-146, and one entry for each pseudonym.
                let mut names: Vec<&[u8; 32]> = entries.iter().map(|e| &e.pseudonym).collect();
                names.sort_unstable();
                names.dedup();
                if entries.len() > ROSTER_ENTRY_MAX || names.len() != entries.len() {
                    return Err(Error::Malformed);
                }
            }
            ControlBody::ModeratorSet { moderators } => {
                let increasing = moderators.windows(2).all(|w| match w {
                    [a, b] => a < b,
                    _ => true,
                });
                // COM-293.
                if moderators.len() > MODERATOR_MAX || !increasing {
                    return Err(Error::Malformed);
                }
            }
            ControlBody::Moderation { actions, .. } => {
                if actions.is_empty() || actions.len() > MOD_ACTION_MAX {
                    return Err(Error::Malformed);
                }
                for action in actions {
                    action.check()?;
                }
            }
        }
        Ok(())
    }
}

/// One object of the control chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlObject {
    /// The community.
    pub community_id: [u8; 32],
    /// The position in the control chain.
    pub epoch_index: u32,
    /// The hash of the object before this one, or zero bytes at index 0.
    pub previous_epoch: [u8; 32],
    /// The role pseudonym of the signer.
    pub actor: [u8; 32],
    /// The ML-DSA-65 public key of that pseudonym.
    pub actor_pk: Vec<u8>,
    /// The typed part.
    pub body: ControlBody,
    /// The signature of the actor.
    pub signature: Vec<u8>,
}

impl ControlObject {
    /// Signs an object under the role identity of the actor.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        actor: &RoleIdentity,
        community_id: [u8; 32],
        epoch_index: u32,
        previous_epoch: [u8; 32],
        body: ControlBody,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut object = ControlObject {
            community_id,
            epoch_index,
            previous_epoch,
            actor: actor.pseudonym(),
            actor_pk: actor.public_key().to_vec(),
            body,
            signature: Vec::new(),
        };
        object.signature = actor.sign(&object.preimage()?, rng)?.to_bytes().to_vec();
        Ok(object)
    }

    /// Adds the cosignature of one more owner to a roster (`COM-366`).
    pub fn cosign<R: TryCryptoRng + ?Sized>(
        &mut self,
        owner: &RoleIdentity,
        rng: &mut R,
    ) -> Result<(), Error> {
        let signature = owner.sign(&self.preimage()?, rng)?.to_bytes().to_vec();
        match &mut self.body {
            ControlBody::Roster { cosigns, .. } => {
                cosigns.push(RosterCosign {
                    actor: owner.pseudonym(),
                    actor_pk: owner.public_key().to_vec(),
                    signature,
                });
                Ok(())
            }
            _ => Err(Error::Malformed),
        }
    }

    /// The bytes that the signature covers, without the label: each field
    /// from `version` to the entries or the actions.
    fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        self.body.check()?;
        if self.actor_pk.len() != VERIFYING_KEY_LEN {
            return Err(Error::Malformed);
        }
        let mut out = alloc::vec![0u8; RECORD_MAX];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(self.body.record_type() as u8)?;
        w.put(&self.community_id)?;
        w.u32(self.epoch_index)?;
        w.put(&self.previous_epoch)?;
        w.put(&self.actor)?;
        w.put(&self.actor_pk)?;
        match &self.body {
            ControlBody::Roster { entries, .. } => {
                w.u8(u8::try_from(entries.len()).map_err(|_| Error::Malformed)?)?;
                for entry in entries {
                    entry.write(&mut w)?;
                }
            }
            ControlBody::ModeratorSet { moderators } => {
                w.u16(u16::try_from(moderators.len()).map_err(|_| Error::Malformed)?)?;
                for moderator in moderators {
                    w.put(moderator)?;
                }
            }
            ControlBody::Moderation {
                actor_role,
                actions,
            } => {
                w.u8(*actor_role as u8)?;
                w.u8(u8::try_from(actions.len()).map_err(|_| Error::Malformed)?)?;
                for action in actions {
                    w.u8(action.kind as u8)?;
                    w.put(&action.target)?;
                    w.u32(action.index)?;
                }
            }
        }
        let used = w.position();
        out.truncate(used);
        Ok(out)
    }

    fn preimage(&self) -> Result<Vec<u8>, Error> {
        Ok([self.body.label(), &self.signed_bytes()?].concat())
    }

    /// The identifier that a successor puts in `previous_epoch`: the hash
    /// of the signed bytes. No signature byte enters it, thus two
    /// signatures over one object give one identifier.
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        Ok(sha3_256(&[&self.signed_bytes()?]))
    }

    /// Encodes the object. A roster with its cosignatures stays inside the
    /// record bound of one `PAGE`.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.signed_bytes()?;
        if let ControlBody::Roster { cosigns, .. } = &self.body {
            out.push(u8::try_from(cosigns.len()).map_err(|_| Error::Malformed)?);
            for cosign in cosigns {
                if cosign.actor_pk.len() != VERIFYING_KEY_LEN
                    || cosign.signature.len() != SIGNATURE_LEN
                {
                    return Err(Error::Malformed);
                }
                out.extend_from_slice(&cosign.actor);
                out.extend_from_slice(&cosign.actor_pk);
                out.extend_from_slice(&cosign.signature);
            }
        }
        if self.signature.len() != SIGNATURE_LEN {
            return Err(Error::Malformed);
        }
        out.extend_from_slice(&self.signature);
        if out.len() > RECORD_MAX {
            return Err(Error::Malformed);
        }
        Ok(out)
    }

    /// Reads an object of one of the three control types.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > RECORD_MAX {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let record_type = RecordType::from_byte(r.u8()?)?;
        let community_id = r.array()?;
        let epoch_index = r.u32()?;
        let previous_epoch = r.array()?;
        let actor = r.array()?;
        let actor_pk = r.take(VERIFYING_KEY_LEN)?.to_vec();
        let body = match record_type {
            RecordType::Roster => {
                let entry_count = usize::from(r.u8()?);
                if entry_count > ROSTER_ENTRY_MAX {
                    return Err(Error::Malformed);
                }
                let mut entries = Vec::with_capacity(entry_count);
                for _ in 0..entry_count {
                    entries.push(RosterEntry::read(&mut r)?);
                }
                let cosign_count = usize::from(r.u8()?);
                let mut cosigns = Vec::with_capacity(cosign_count.min(ROSTER_ENTRY_MAX));
                for _ in 0..cosign_count {
                    cosigns.push(RosterCosign {
                        actor: r.array()?,
                        actor_pk: r.take(VERIFYING_KEY_LEN)?.to_vec(),
                        signature: r.take(SIGNATURE_LEN)?.to_vec(),
                    });
                }
                ControlBody::Roster { entries, cosigns }
            }
            RecordType::ModeratorSet => {
                let count = usize::from(r.u16()?);
                if count > MODERATOR_MAX {
                    return Err(Error::Malformed);
                }
                let mut moderators = Vec::with_capacity(count);
                for _ in 0..count {
                    moderators.push(r.array()?);
                }
                ControlBody::ModeratorSet { moderators }
            }
            RecordType::ModerationEpoch => {
                let actor_role = Role::from_byte(r.u8()?)?;
                let count = usize::from(r.u8()?);
                if count == 0 || count > MOD_ACTION_MAX {
                    return Err(Error::Malformed);
                }
                let mut actions = Vec::with_capacity(count);
                for _ in 0..count {
                    actions.push(ModerationAction::read(&mut r)?);
                }
                ControlBody::Moderation {
                    actor_role,
                    actions,
                }
            }
            _ => return Err(Error::Malformed),
        };
        let signature = r.take(SIGNATURE_LEN)?.to_vec();
        r.finish()?;
        body.check()?;
        Ok(ControlObject {
            community_id,
            epoch_index,
            previous_epoch,
            actor,
            actor_pk,
            body,
            signature,
        })
    }

    /// Rule 1 and the signature: the hash of `actor_pk` is `actor`, and the
    /// signature verifies (`COM-114`, `COM-115`). The chain of authority is
    /// the work of [`super::authority`].
    pub fn verify_signature(&self, community_id: &[u8; 32]) -> Result<(), Error> {
        if self.community_id != *community_id || pseudonym_of(&self.actor_pk) != self.actor {
            return Err(Error::Unverified);
        }
        verify_signature(&self.actor_pk, &self.preimage()?, &self.signature)
    }

    /// The owner pseudonyms whose cosignature verifies, without a repeat
    /// and without the signer (`COM-366`).
    pub fn verified_cosigners(&self) -> Result<Vec<[u8; 32]>, Error> {
        let ControlBody::Roster { cosigns, .. } = &self.body else {
            return Ok(Vec::new());
        };
        let preimage = self.preimage()?;
        let mut verified: Vec<[u8; 32]> = Vec::with_capacity(cosigns.len());
        for cosign in cosigns {
            if cosign.actor == self.actor
                || verified.contains(&cosign.actor)
                || pseudonym_of(&cosign.actor_pk) != cosign.actor
            {
                return Err(Error::Unverified);
            }
            verify_signature(&cosign.actor_pk, &preimage, &cosign.signature)?;
            verified.push(cosign.actor);
        }
        Ok(verified)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use umbra_crypto::secret::Secret;

    use super::*;
    use crate::{abuse::test_rng::Rng, community::test_util::role};

    pub fn queue(tag: u8) -> QueueAddress {
        QueueAddress {
            relay_id: [tag; 32],
            sender_id: [tag ^ 0x55; 32],
            qs_auth_sk: Secret::new([tag ^ 0x0F; 32]),
            qe: Secret::new([tag ^ 0xF0; 32]),
        }
    }

    pub fn entry(role_kind: Role, seed: u8) -> RosterEntry {
        RosterEntry::new(role_kind, &role(seed), &queue(seed)).unwrap()
    }

    #[test]
    fn the_three_objects_round_trip_at_their_stated_sizes() {
        let owner = role(1);
        let entries: Vec<RosterEntry> = (0..19u8).map(|i| entry(Role::Admin, i + 1)).collect();
        assert_eq!(ROSTER_ENTRY_LEN, 1_378);
        let roster = ControlObject::sign(
            &owner,
            [9; 32],
            0,
            [0; 32],
            ControlBody::Roster {
                entries,
                cosigns: Vec::new(),
            },
            &mut Rng(1),
        )
        .unwrap();
        let bytes = roster.encode().unwrap();
        assert_eq!(bytes.len(), 31_547);
        let parsed = ControlObject::parse(&bytes).unwrap();
        assert_eq!(parsed, roster);
        parsed.verify_signature(&[9; 32]).unwrap();
        assert!(parsed.verify_signature(&[8; 32]).is_err());

        let mut moderators: Vec<[u8; 32]> = (0..800u16)
            .map(|i| {
                let mut p = [0u8; 32];
                p[..2].copy_from_slice(&i.to_be_bytes());
                p
            })
            .collect();
        let set = ControlObject::sign(
            &owner,
            [9; 32],
            1,
            roster.hash().unwrap(),
            ControlBody::ModeratorSet {
                moderators: moderators.clone(),
            },
            &mut Rng(2),
        )
        .unwrap();
        let set_bytes = set.encode().unwrap();
        assert_eq!(set_bytes.len(), 30_965);
        let length_of = crate::community::record::record_len;
        assert_eq!(length_of(&set_bytes).unwrap(), set_bytes.len());
        assert_eq!(length_of(&bytes).unwrap(), bytes.len());
        moderators.swap(0, 1);
        assert!(ControlObject::sign(
            &owner,
            [9; 32],
            1,
            [0; 32],
            ControlBody::ModeratorSet { moderators },
            &mut Rng(2),
        )
        .is_err());

        let actions = alloc::vec![
            ModerationAction {
                kind: ActionKind::Remove,
                target: [4; 32],
                index: 7,
            };
            20
        ];
        let epoch = ControlObject::sign(
            &owner,
            [9; 32],
            2,
            set.hash().unwrap(),
            ControlBody::Moderation {
                actor_role: Role::Owner,
                actions,
            },
            &mut Rng(3),
        )
        .unwrap();
        let epoch_bytes = epoch.encode().unwrap();
        assert_eq!(epoch_bytes.len(), 6_105);
        assert_eq!(length_of(&epoch_bytes).unwrap(), epoch_bytes.len());
        assert_eq!(ControlObject::parse(&epoch_bytes).unwrap(), epoch);

        // A kind outside the table rejects the epoch.
        let mut bad = epoch_bytes.clone();
        let first_kind = 2 + 32 + 4 + 32 + 32 + VERIFYING_KEY_LEN + 2;
        bad[first_kind] = 9;
        assert!(ControlObject::parse(&bad).is_err());
    }

    #[test]
    fn a_cosignature_verifies_under_its_own_key_and_not_twice() {
        let owner = role(1);
        let second = role(2);
        let mut roster = ControlObject::sign(
            &owner,
            [9; 32],
            3,
            [7; 32],
            ControlBody::Roster {
                entries: alloc::vec![entry(Role::Owner, 1), entry(Role::Owner, 3)],
                cosigns: Vec::new(),
            },
            &mut Rng(1),
        )
        .unwrap();
        let hash_before = roster.hash().unwrap();
        roster.cosign(&second, &mut Rng(2)).unwrap();
        assert_eq!(roster.hash().unwrap(), hash_before);
        let cosigned = roster.encode().unwrap();
        assert_eq!(
            crate::community::record::record_len(&cosigned).unwrap(),
            cosigned.len()
        );
        let parsed = ControlObject::parse(&cosigned).unwrap();
        assert_eq!(parsed.verified_cosigners().unwrap(), [second.pseudonym()]);

        roster.cosign(&second, &mut Rng(3)).unwrap();
        assert!(roster.verified_cosigners().is_err());
    }

    #[test]
    fn an_action_outside_its_table_row_is_rejected() {
        let bad = [
            ModerationAction {
                kind: ActionKind::Remove,
                target: [1; 32],
                index: NO_INDEX,
            },
            ModerationAction {
                kind: ActionKind::Lock,
                target: [1; 32],
                index: 60,
            },
            ModerationAction {
                kind: ActionKind::Unban,
                target: [1; 32],
                index: 4,
            },
            ModerationAction {
                kind: ActionKind::Unlock,
                target: [0; 32],
                index: 4,
            },
        ];
        for action in bad {
            assert!(action.check().is_err());
        }
        assert!(ActionKind::Lock.minimum_role() == Role::Admin);
        assert!(ActionKind::Ban.minimum_role() == Role::Moderator);
    }
}
