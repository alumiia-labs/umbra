//! The group control record of Part 6 §6.6.3 and its nine objects.
//!
//! Four objects, the plain epoch, the granting epoch, the moderation epoch,
//! and the presence record, have their fields in Part 11 §11.9 and no byte
//! layout in any part. The layouts below follow the signature preimages of
//! Part 11, field for field, and the specification amendment that records
//! them names this module.

use alloc::{boxed::Box, vec::Vec};

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// `GROUP_REPLICAS`.
pub const REPLICAS: usize = 2;
/// `MOD_ACTION_MAX`.
pub const MOD_ACTION_MAX: usize = 20;
/// The length of a `JoinRecord`.
pub const JOIN_LEN: usize = 1_313;
/// The length of a `RekeyRecord`.
pub const REKEY_LEN: usize = 6_614;
/// The length of a `GroupMemberEntry`.
pub const MEMBER_ENTRY_LEN: usize = 99;
/// The length of a `MemberKemKey`.
pub const MEMBER_KEM_KEY_LEN: usize = 1_218;
/// The length of a KEM public key.
pub const KEM_PK_LEN: usize = 1_216;

/// The control type. The value `0x01` is retired and never returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlType {
    /// A `JoinRecord`, on the pairwise channel of the join.
    Join = 0x02,
    /// A plain epoch.
    PlainEpoch = 0x03,
    /// A granting epoch.
    GrantingEpoch = 0x04,
    /// A moderation epoch.
    ModerationEpoch = 0x05,
    /// A `GroupPresence`.
    Presence = 0x06,
    /// A `GroupInvitation`, on the pairwise channel of the join.
    Invitation = 0x07,
    /// A `SnapshotNotice`.
    SnapshotNotice = 0x08,
    /// A `RekeyRecord`.
    Rekey = 0x09,
}

impl ControlType {
    /// The type of a byte, in this namespace only (`WIR-147`).
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x02 => ControlType::Join,
            0x03 => ControlType::PlainEpoch,
            0x04 => ControlType::GrantingEpoch,
            0x05 => ControlType::ModerationEpoch,
            0x06 => ControlType::Presence,
            0x07 => ControlType::Invitation,
            0x08 => ControlType::SnapshotNotice,
            0x09 => ControlType::Rekey,
            _ => return Err(Error::Malformed),
        })
    }

    /// Whether the type travels on the pairwise channel of a join
    /// (`WIR-443`) rather than as a group record (`WIR-445`). A re-key
    /// travels on both, and its chain fields say which.
    pub const fn pairwise_only(self) -> bool {
        matches!(self, ControlType::Join | ControlType::Invitation)
    }
}

/// A group control record: the wrapper and the payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupControl<'a> {
    /// The type.
    pub control_type: ControlType,
    /// The object that `control_type` names.
    pub payload: &'a [u8],
}

impl<'a> GroupControl<'a> {
    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.control_type as u8)?;
        w.put(self.payload)?;
        Ok(w.position())
    }

    /// Reads a record.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        Ok(GroupControl {
            control_type: ControlType::from_byte(r.u8()?)?,
            payload: r.rest(),
        })
    }

    /// The hash of a roster epoch: SHA3-256 of the payload bytes
    /// (`GRP-314`).
    pub fn epoch_hash(&self) -> [u8; 32] {
        sha3_256(&[self.payload])
    }
}

/// The role of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    /// Reads only.
    Observer = 0x01,
    /// A plain member.
    Member = 0x02,
    /// May hide or remove.
    Moderator = 0x03,
    /// May change the roster.
    Admin = 0x04,
    /// An admin that the roster cannot remove by a majority of one.
    Owner = 0x05,
}

impl Role {
    /// The role of a byte (`WIR-448`).
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x01 => Role::Observer,
            0x02 => Role::Member,
            0x03 => Role::Moderator,
            0x04 => Role::Admin,
            0x05 => Role::Owner,
            _ => return Err(Error::Malformed),
        })
    }
}

/// The chain fields that every roster object carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    /// The group.
    pub group_id: [u8; 32],
    /// The roster epoch of this record.
    pub epoch_index: u32,
    /// The hash of the predecessor (`GRP-315`).
    pub previous_epoch_hash: [u8; 32],
}

impl Chain {
    fn put(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.put(&self.group_id)?;
        w.u32(self.epoch_index)?;
        w.put(&self.previous_epoch_hash)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Chain {
            group_id: r.array()?,
            epoch_index: r.u32()?,
            previous_epoch_hash: r.array()?,
        })
    }

    /// The bytes of the three fields, in the order a preimage takes them.
    fn preimage(&self) -> [u8; 68] {
        let mut out = [0u8; 68];
        let mut w = Writer::new(&mut out);
        // The buffer is sized for the three fields, thus the puts cannot fail.
        let _ = self.put(&mut w);
        out
    }
}

/// The keys of a joiner, as the join record and the add carry them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKeys<'a> {
    /// `GroupPairKey_g.pk`.
    pub pair_pk: [u8; 32],
    /// `SHA3-256(GroupRosterKey_g.pk)`.
    pub roster_pk_hash: [u8; 32],
    /// `GroupKemKey_g.pk`.
    pub kem_pk: &'a [u8],
}

impl<'a> MemberKeys<'a> {
    fn put(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        if self.kem_pk.len() != KEM_PK_LEN {
            return Err(Error::Malformed);
        }
        w.put(&self.pair_pk)?;
        w.put(&self.roster_pk_hash)?;
        w.put(self.kem_pk)
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(MemberKeys {
            pair_pk: r.array()?,
            roster_pk_hash: r.array()?,
            kem_pk: r.take(KEM_PK_LEN)?,
        })
    }
}

/// A `JoinRecord`, control type `0x02`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRecord<'a> {
    /// The group.
    pub group_id: [u8; 32],
    /// The keys of the joiner.
    pub keys: MemberKeys<'a>,
}

impl<'a> JoinRecord<'a> {
    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.group_id)?;
        self.keys.put(&mut w)?;
        Ok(w.position())
    }

    /// Reads a record (`WIR-435`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != JOIN_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        Ok(JoinRecord {
            group_id: r.array()?,
            keys: MemberKeys::read(&mut r)?,
        })
    }
}

/// The operation of a plain epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlainOp<'a> {
    /// Adds a member at `index` with its keys (`GRP-319`).
    Add {
        /// The new index, the lowest above every index the roster used.
        index: u16,
        /// The keys from the `JoinRecord`.
        keys: MemberKeys<'a>,
    },
    /// Removes a member of role `member` or `observer`.
    Remove {
        /// The index removed.
        index: u16,
    },
    /// The sender leaves; the tag vector names it.
    SelfRemoval,
}

/// A plain epoch, control type `0x03`. It carries no signature
/// (`GRP-064`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainEpoch<'a> {
    /// The chain fields.
    pub chain: Chain,
    /// The operation.
    pub op: PlainOp<'a>,
}

impl<'a> PlainEpoch<'a> {
    /// Writes the epoch.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        self.chain.put(&mut w)?;
        match &self.op {
            PlainOp::Add { index, keys } => {
                w.u8(0x01)?;
                w.u16(*index)?;
                keys.put(&mut w)?;
            }
            PlainOp::Remove { index } => {
                w.u8(0x02)?;
                w.u16(*index)?;
            }
            PlainOp::SelfRemoval => w.u8(0x03)?,
        }
        Ok(w.position())
    }

    /// Reads an epoch.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let chain = Chain::read(&mut r)?;
        let op = match r.u8()? {
            0x01 => PlainOp::Add {
                index: r.u16()?,
                keys: MemberKeys::read(&mut r)?,
            },
            0x02 => PlainOp::Remove { index: r.u16()? },
            0x03 => PlainOp::SelfRemoval,
            _ => return Err(Error::Malformed),
        };
        r.finish()?;
        Ok(PlainEpoch { chain, op })
    }
}

/// A granting epoch, control type `0x04`. It gives or takes a role at
/// `moderator` or above, under a signature of the granter (`GRP-060`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantingEpoch<'a> {
    /// The chain fields.
    pub chain: Chain,
    /// The member that gives the role.
    pub granter_index: u16,
    /// The member that receives it.
    pub grantee_index: u16,
    /// `SHA3-256(GroupRosterKey_g.pk)` of the grantee.
    pub grantee_roster_pk_hash: [u8; 32],
    /// The role after the epoch.
    pub role: Role,
    /// The full roster key of the granter. The verifier checks it against
    /// the roster entry of the granter, thus no member holds another
    /// member's key before it (`GRP-316`).
    pub granter_roster_pk: &'a [u8],
    /// The signature under the roster key of the granter.
    pub sig: &'a [u8],
}

impl<'a> GrantingEpoch<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.granter_roster_pk.len() != VERIFYING_KEY_LEN || self.sig.len() != SIGNATURE_LEN {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The preimage of `GRP-061`, label first.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(labels::GROUP_GRANT);
        out.extend_from_slice(&self.chain.preimage());
        out.extend_from_slice(&self.granter_index.to_be_bytes());
        out.extend_from_slice(&self.grantee_index.to_be_bytes());
        out.extend_from_slice(&self.grantee_roster_pk_hash);
        out.push(self.role as u8);
        out
    }

    /// Verifies the carried roster key against `granter_roster_pk_hash`
    /// of the roster entry of the granter (`GRP-317`), and `sig` under it
    /// (`GRP-062`).
    pub fn verify(&self, granter_roster_pk_hash: &[u8; 32]) -> Result<(), Error> {
        verify_signer(
            self.granter_roster_pk,
            granter_roster_pk_hash,
            &self.preimage(),
            self.sig,
        )
    }

    /// Writes the epoch.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        self.chain.put(&mut w)?;
        w.u16(self.granter_index)?;
        w.u16(self.grantee_index)?;
        w.put(&self.grantee_roster_pk_hash)?;
        w.u8(self.role as u8)?;
        w.put(self.granter_roster_pk)?;
        w.put(self.sig)?;
        Ok(w.position())
    }

    /// Reads an epoch.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let chain = Chain::read(&mut r)?;
        let granter_index = r.u16()?;
        let grantee_index = r.u16()?;
        let grantee_roster_pk_hash = r.array()?;
        let role = Role::from_byte(r.u8()?)?;
        let granter_roster_pk = r.take(VERIFYING_KEY_LEN)?;
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        let out = GrantingEpoch {
            chain,
            granter_index,
            grantee_index,
            grantee_roster_pk_hash,
            role,
            granter_roster_pk,
            sig,
        };
        out.check()?;
        Ok(out)
    }
}

/// Verifies a signed roster object: the carried roster key against the
/// hash of the roster entry of its signer, and the signature under it.
fn verify_signer(
    roster_pk: &[u8],
    roster_pk_hash: &[u8; 32],
    preimage: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if sha3_256(&[roster_pk]) != *roster_pk_hash {
        return Err(Error::Malformed);
    }
    let key = VerifyingKey::from_bytes(roster_pk)?;
    let sig = Signature::from_bytes(sig)?;
    key.verify(preimage, &sig)?;
    Ok(())
}

/// One moderator action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModAction {
    /// `0x01` hide, `0x02` remove, `0x03` unhide.
    pub action: u8,
    /// The `msg_id` of the target.
    pub target: [u8; 16],
    /// A rendering hint of the author index, or `0xFFFF`. Not in the
    /// preimage (`GRP-179`).
    pub author_hint: u16,
}

/// A moderation epoch, control type `0x05` (`GRP-077`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationEpoch<'a> {
    /// The chain fields.
    pub chain: Chain,
    /// The acting member.
    pub actor_index: u16,
    /// The role of the actor at this epoch.
    pub actor_role: Role,
    /// 1 to `MOD_ACTION_MAX` actions.
    pub actions: Vec<ModAction>,
    /// The full roster key of the actor, which the verifier checks against
    /// the roster entry of the actor (`GRP-316`).
    pub actor_roster_pk: &'a [u8],
    /// The signature under the roster key of the actor.
    pub sig: &'a [u8],
}

impl<'a> ModerationEpoch<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.actions.is_empty()
            || self.actions.len() > MOD_ACTION_MAX
            || self.actions.iter().any(|a| !(1..=3).contains(&a.action))
            || self.actor_roster_pk.len() != VERIFYING_KEY_LEN
            || self.sig.len() != SIGNATURE_LEN
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// The preimage of `GRP-078`, label first; the hints stay out.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.actions.len() * 17);
        out.extend_from_slice(labels::GROUP_MODERATION);
        out.extend_from_slice(&self.chain.preimage());
        out.extend_from_slice(&self.actor_index.to_be_bytes());
        out.push(self.actor_role as u8);
        out.push(u8::try_from(self.actions.len()).unwrap_or(u8::MAX));
        for a in &self.actions {
            out.push(a.action);
            out.extend_from_slice(&a.target);
        }
        out
    }

    /// Verifies the carried roster key against `actor_roster_pk_hash` of
    /// the roster entry of the actor, and `sig` under it (`GRP-079`).
    pub fn verify(&self, actor_roster_pk_hash: &[u8; 32]) -> Result<(), Error> {
        verify_signer(
            self.actor_roster_pk,
            actor_roster_pk_hash,
            &self.preimage(),
            self.sig,
        )
    }

    /// Writes the epoch.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        self.chain.put(&mut w)?;
        w.u16(self.actor_index)?;
        w.u8(self.actor_role as u8)?;
        w.u8(u8::try_from(self.actions.len()).map_err(|_| Error::Malformed)?)?;
        for a in &self.actions {
            w.u8(a.action)?;
            w.put(&a.target)?;
            w.u16(a.author_hint)?;
        }
        w.put(self.actor_roster_pk)?;
        w.put(self.sig)?;
        Ok(w.position())
    }

    /// Reads an epoch.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let chain = Chain::read(&mut r)?;
        let actor_index = r.u16()?;
        let actor_role = Role::from_byte(r.u8()?)?;
        let count = usize::from(r.u8()?);
        if count == 0 || count > MOD_ACTION_MAX {
            return Err(Error::Malformed);
        }
        let mut actions = Vec::with_capacity(count);
        for _ in 0..count {
            actions.push(ModAction {
                action: r.u8()?,
                target: r.array()?,
                author_hint: r.u16()?,
            });
        }
        let actor_roster_pk = r.take(VERIFYING_KEY_LEN)?;
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        let out = ModerationEpoch {
            chain,
            actor_index,
            actor_role,
            actions,
            actor_roster_pk,
            sig,
        };
        out.check()?;
        Ok(out)
    }
}

/// The presence record, control type `0x06`. It carries a version and
/// nothing else; the sparse tag vector names the sender.
pub const PRESENCE: [u8; 1] = [0x01];

/// Reads a presence record.
pub fn parse_presence(bytes: &[u8]) -> Result<(), Error> {
    if bytes == PRESENCE {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

/// One replica of a group queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaRef {
    /// The relay.
    pub relay_id: [u8; 32],
    /// The queue at that relay.
    pub group_queue_id: [u8; 32],
    /// The `seq` of the plain epoch that added the joiner, at that relay.
    pub seq_of_add: u32,
}

/// The two stages of an invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationStage<'a> {
    /// Stage `0x01`.
    Offer {
        /// The display name of the group.
        name: &'a str,
        /// `GroupRosterKey_g.pk` of the inviting admin.
        admin_roster_pk: &'a [u8],
        /// `GroupRosterKey_g.pk` of the creator.
        creator_roster_pk: &'a [u8],
    },
    /// Stage `0x02`. It is boxed, because the three keys make it far
    /// larger than an offer.
    Admit(Box<InvitationAdmit<'a>>),
}

/// The body of an admit, `InvitationAdmit` of §6.6.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationAdmit<'a> {
    /// The member index the admin gave the joiner.
    pub index: u16,
    /// The group epoch at the admit.
    pub epoch: u32,
    /// The slot at which the key of the joiner starts.
    pub t_join: u32,
    /// `K_{e,t_join}`, or the history-window key.
    pub slot_key: [u8; 32],
    /// `read_sk_e`. A joiner holds no `K_e`, thus the admit hands it the
    /// two queue credentials (`WIR-520`).
    pub read_sk: [u8; 32],
    /// `write_sk_e`.
    pub write_sk: [u8; 32],
    /// The roster epoch of the snapshot.
    pub roster_epoch: u32,
    /// The two replicas.
    pub replicas: [ReplicaRef; REPLICAS],
    /// A `FileDescriptor` that names a `RosterSnapshot`.
    pub descriptor: &'a [u8],
}

/// The fixed part of an admit body, before the descriptor (`WIR-521`).
pub const ADMIT_FIXED: usize = 249;

/// A `GroupInvitation`, control type `0x07`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInvitation<'a> {
    /// The group.
    pub group_id: [u8; 32],
    /// The stage.
    pub stage: InvitationStage<'a>,
}

impl<'a> GroupInvitation<'a> {
    /// Writes the invitation.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.group_id)?;
        match &self.stage {
            InvitationStage::Offer {
                name,
                admin_roster_pk,
                creator_roster_pk,
            } => {
                if admin_roster_pk.len() != VERIFYING_KEY_LEN
                    || creator_roster_pk.len() != VERIFYING_KEY_LEN
                {
                    return Err(Error::Malformed);
                }
                let name_len = u8::try_from(name.len()).map_err(|_| Error::Malformed)?;
                w.u8(0x01)?;
                w.u16(u16::try_from(3_905 + name.len()).map_err(|_| Error::Malformed)?)?;
                w.u8(name_len)?;
                w.put(name.as_bytes())?;
                w.put(admin_roster_pk)?;
                w.put(creator_roster_pk)?;
            }
            InvitationStage::Admit(admit) => {
                let InvitationAdmit {
                    index,
                    epoch,
                    t_join,
                    slot_key,
                    read_sk,
                    write_sk,
                    roster_epoch,
                    replicas,
                    descriptor,
                } = admit.as_ref();
                w.u8(0x02)?;
                w.u16(
                    u16::try_from(ADMIT_FIXED + descriptor.len()).map_err(|_| Error::Malformed)?,
                )?;
                w.u16(*index)?;
                w.u32(*epoch)?;
                w.u32(*t_join)?;
                w.put(slot_key)?;
                w.put(read_sk)?;
                w.put(write_sk)?;
                w.u32(*roster_epoch)?;
                w.u8(REPLICAS as u8)?;
                for rep in replicas {
                    w.put(&rep.relay_id)?;
                    w.put(&rep.group_queue_id)?;
                    w.u32(rep.seq_of_add)?;
                }
                w.u16(u16::try_from(descriptor.len()).map_err(|_| Error::Malformed)?)?;
                w.put(descriptor)?;
            }
        }
        Ok(w.position())
    }

    /// Reads an invitation (`WIR-436` to `WIR-440`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let group_id = r.array()?;
        let stage_byte = r.u8()?;
        let body_len = usize::from(r.u16()?);
        let body = r.take(body_len)?;
        r.finish()?;
        let mut b = Reader::new(body);
        let stage = match stage_byte {
            0x01 => {
                let name_len = usize::from(b.u8()?);
                if body_len != 3_905 + name_len {
                    return Err(Error::Malformed);
                }
                let name = core::str::from_utf8(b.take(name_len)?).map_err(|_| Error::Malformed)?;
                InvitationStage::Offer {
                    name,
                    admin_roster_pk: b.take(VERIFYING_KEY_LEN)?,
                    creator_roster_pk: b.take(VERIFYING_KEY_LEN)?,
                }
            }
            0x02 => {
                let index = b.u16()?;
                let epoch = b.u32()?;
                let t_join = b.u32()?;
                let slot_key = b.array()?;
                let read_sk = b.array()?;
                let write_sk = b.array()?;
                let roster_epoch = b.u32()?;
                if usize::from(b.u8()?) != REPLICAS {
                    return Err(Error::Malformed);
                }
                let mut replicas = [ReplicaRef {
                    relay_id: [0; 32],
                    group_queue_id: [0; 32],
                    seq_of_add: 0,
                }; REPLICAS];
                for rep in replicas.iter_mut() {
                    *rep = ReplicaRef {
                        relay_id: b.array()?,
                        group_queue_id: b.array()?,
                        seq_of_add: b.u32()?,
                    };
                }
                let desc_len = usize::from(b.u16()?);
                if body_len != ADMIT_FIXED + desc_len {
                    return Err(Error::Malformed);
                }
                InvitationStage::Admit(Box::new(InvitationAdmit {
                    index,
                    epoch,
                    t_join,
                    slot_key,
                    read_sk,
                    write_sk,
                    roster_epoch,
                    replicas,
                    descriptor: b.take(desc_len)?,
                }))
            }
            _ => return Err(Error::Malformed),
        };
        b.finish()?;
        Ok(GroupInvitation { group_id, stage })
    }
}

/// A `SnapshotNotice`, control type `0x08`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotNotice<'a> {
    /// The group.
    pub group_id: [u8; 32],
    /// The roster epoch the snapshot describes.
    pub roster_epoch: u32,
    /// A `FileDescriptor` that names the snapshot.
    pub descriptor: &'a [u8],
}

impl<'a> SnapshotNotice<'a> {
    /// Writes the notice.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.group_id)?;
        w.u32(self.roster_epoch)?;
        w.u16(u16::try_from(self.descriptor.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.descriptor)?;
        Ok(w.position())
    }

    /// Reads a notice (`WIR-447`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let group_id = r.array()?;
        let roster_epoch = r.u32()?;
        let desc_len = usize::from(r.u16()?);
        let descriptor = r.take(desc_len)?;
        r.finish()?;
        Ok(SnapshotNotice {
            group_id,
            roster_epoch,
            descriptor,
        })
    }
}

/// One entry of a roster snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMemberEntry {
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
}

/// The KEM key of one active member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberKemKey<'a> {
    /// The member index.
    pub index: u16,
    /// `GroupKemKey_g.pk`.
    pub kem_pk: &'a [u8],
}

/// A `RosterSnapshot`, the object on the chunk path that a joiner reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterSnapshot<'a> {
    /// The group.
    pub group_id: [u8; 32],
    /// The roster epoch.
    pub roster_epoch: u32,
    /// The hash of the roster epoch it describes.
    pub chain_hash: [u8; 32],
    /// The entries, index ascending.
    pub entries: Vec<GroupMemberEntry>,
    /// The KEM key of every active member, index ascending.
    pub keys: Vec<MemberKemKey<'a>>,
    /// The authority path, in chain order.
    pub path: &'a [u8],
}

impl<'a> RosterSnapshot<'a> {
    /// The fixed part.
    pub const FIXED: usize = 77;

    /// The encoded length.
    pub fn len(&self) -> usize {
        Self::FIXED
            .saturating_add(self.entries.len().saturating_mul(MEMBER_ENTRY_LEN))
            .saturating_add(self.keys.len().saturating_mul(MEMBER_KEM_KEY_LEN))
            .saturating_add(self.path.len())
    }

    /// Whether the snapshot holds no entry. Clippy asks for this beside
    /// `len`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn check(&self) -> Result<(), Error> {
        fn ordered(indices: impl Iterator<Item = u16>) -> bool {
            let mut last: Option<u16> = None;
            for i in indices {
                if last.is_some_and(|l| l >= i) {
                    return false;
                }
                last = Some(i);
            }
            true
        }
        if !ordered(self.entries.iter().map(|e| e.index))
            || !ordered(self.keys.iter().map(|k| k.index))
        {
            return Err(Error::Malformed);
        }
        for key in &self.keys {
            let entry = self
                .entries
                .iter()
                .find(|e| e.index == key.index)
                .ok_or(Error::Malformed)?;
            if key.kem_pk.len() != KEM_PK_LEN || sha3_256(&[key.kem_pk]) != entry.kem_pk_hash {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }

    /// Writes the snapshot.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.group_id)?;
        w.u32(self.roster_epoch)?;
        w.put(&self.chain_hash)?;
        w.u16(u16::try_from(self.entries.len()).map_err(|_| Error::Malformed)?)?;
        for e in &self.entries {
            w.u16(e.index)?;
            w.u8(e.role as u8)?;
            w.put(&e.pair_pk)?;
            w.put(&e.roster_pk_hash)?;
            w.put(&e.kem_pk_hash)?;
        }
        w.u16(u16::try_from(self.keys.len()).map_err(|_| Error::Malformed)?)?;
        for k in &self.keys {
            w.u16(k.index)?;
            w.put(k.kem_pk)?;
        }
        w.u32(u32::try_from(self.path.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.path)?;
        Ok(w.position())
    }

    /// Reads a snapshot (`WIR-448` to `WIR-453`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let group_id = r.array()?;
        let roster_epoch = r.u32()?;
        let chain_hash = r.array()?;
        let entry_count = usize::from(r.u16()?);
        if entry_count.saturating_mul(MEMBER_ENTRY_LEN) > r.remaining() {
            return Err(Error::Malformed);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(GroupMemberEntry {
                index: r.u16()?,
                role: Role::from_byte(r.u8()?)?,
                pair_pk: r.array()?,
                roster_pk_hash: r.array()?,
                kem_pk_hash: r.array()?,
            });
        }
        let key_count = usize::from(r.u16()?);
        if key_count.saturating_mul(MEMBER_KEM_KEY_LEN) > r.remaining() {
            return Err(Error::Malformed);
        }
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            keys.push(MemberKemKey {
                index: r.u16()?,
                kem_pk: r.take(KEM_PK_LEN)?,
            });
        }
        let path_len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        let path = r.take(path_len)?;
        r.finish()?;
        let out = RosterSnapshot {
            group_id,
            roster_epoch,
            chain_hash,
            entries,
            keys,
            path,
        };
        out.check()?;
        Ok(out)
    }
}

/// A `RekeyRecord`, control type `0x09` (Part 11 §11.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyRecord<'a> {
    /// The chain fields; zero on a pairwise channel.
    pub chain: Chain,
    /// The index the member holds.
    pub old_index: u16,
    /// `GroupRosterKey_g.pk` of that index.
    pub old_roster_pk: &'a [u8],
    /// The lowest index above every index the roster used.
    pub new_index: u16,
    /// The three new public values.
    pub new_keys: MemberKeys<'a>,
    /// The signature under the old roster key.
    pub sig: &'a [u8],
}

impl<'a> RekeyRecord<'a> {
    /// The preimage of Part 6 §6.6.3, label first.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3_400);
        out.extend_from_slice(labels::GROUP_REKEY);
        out.extend_from_slice(&self.chain.preimage());
        out.extend_from_slice(&self.old_index.to_be_bytes());
        out.extend_from_slice(self.old_roster_pk);
        out.extend_from_slice(&self.new_index.to_be_bytes());
        out.extend_from_slice(&self.new_keys.pair_pk);
        out.extend_from_slice(&self.new_keys.roster_pk_hash);
        out.extend_from_slice(self.new_keys.kem_pk);
        out
    }

    /// Verifies `sig` against `old_roster_pk`, and that key against the
    /// `roster_pk_hash` the receiver holds for `old_index` (`WIR-478`).
    pub fn verify(&self, expected_old_hash: &[u8; 32]) -> Result<(), Error> {
        if sha3_256(&[self.old_roster_pk]) != *expected_old_hash {
            return Err(Error::Malformed);
        }
        let key = VerifyingKey::from_bytes(self.old_roster_pk)?;
        let sig = Signature::from_bytes(self.sig)?;
        key.verify(&self.preimage(), &sig)?;
        Ok(())
    }

    /// Whether the chain fields are zero, which names the pairwise carrier
    /// (`WIR-484`).
    pub fn chain_is_zero(&self) -> bool {
        self.chain.epoch_index == 0 && self.chain.previous_epoch_hash == [0; 32]
    }

    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.old_roster_pk.len() != VERIFYING_KEY_LEN || self.sig.len() != SIGNATURE_LEN {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        self.chain.put(&mut w)?;
        w.u16(self.old_index)?;
        w.put(self.old_roster_pk)?;
        w.u16(self.new_index)?;
        self.new_keys.put(&mut w)?;
        w.put(self.sig)?;
        Ok(w.position())
    }

    /// Reads a record (`WIR-482`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != REKEY_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        Ok(RekeyRecord {
            chain: Chain::read(&mut r)?,
            old_index: r.u16()?,
            old_roster_pk: r.take(VERIFYING_KEY_LEN)?,
            new_index: r.u16()?,
            new_keys: MemberKeys::read(&mut r)?,
            sig: r.take(SIGNATURE_LEN)?,
        })
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
    use alloc::vec;
    use umbra_crypto::{secret::Secret, sign::SigningKey};

    fn chain() -> Chain {
        Chain {
            group_id: [7; 32],
            epoch_index: 3,
            previous_epoch_hash: [8; 32],
        }
    }

    fn keys() -> MemberKeys<'static> {
        MemberKeys {
            pair_pk: [1; 32],
            roster_pk_hash: [2; 32],
            kem_pk: &[3; KEM_PK_LEN],
        }
    }

    struct Rng(u8);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    #[test]
    fn the_join_and_the_plain_epoch_round_trip() {
        let mut out = [0u8; 2_000];
        let join = JoinRecord {
            group_id: [7; 32],
            keys: keys(),
        };
        assert_eq!(join.encode(&mut out).unwrap(), JOIN_LEN);
        assert_eq!(JoinRecord::parse(&out[..JOIN_LEN]).unwrap(), join);
        assert!(JoinRecord::parse(&out[..JOIN_LEN - 1]).is_err());
        let add = PlainEpoch {
            chain: chain(),
            op: PlainOp::Add {
                index: 4,
                keys: keys(),
            },
        };
        let n = add.encode(&mut out).unwrap();
        assert_eq!(PlainEpoch::parse(&out[..n]).unwrap(), add);
        let leave = PlainEpoch {
            chain: chain(),
            op: PlainOp::SelfRemoval,
        };
        let n = leave.encode(&mut out).unwrap();
        assert_eq!(n, 70);
        assert_eq!(PlainEpoch::parse(&out[..n]).unwrap(), leave);
        out[69] = 0x04;
        assert!(PlainEpoch::parse(&out[..n]).is_err());
        let wrapped = GroupControl {
            control_type: ControlType::PlainEpoch,
            payload: &out[..n],
        };
        assert_eq!(wrapped.epoch_hash(), sha3_256(&[&out[..n]]));
        assert!(ControlType::from_byte(0x01).is_err());
        assert!(ControlType::from_byte(0x0A).is_err());
    }

    #[test]
    fn the_granting_and_moderation_epochs_verify_their_signatures() {
        let granter = SigningKey::from_seed(Secret::new([5; 32]));
        let grantee = SigningKey::from_seed(Secret::new([6; 32]));
        let granter_pk = granter.verifying_key().to_bytes();
        let grantee_pk = grantee.verifying_key().to_bytes();
        let granter_hash = sha3_256(&[&granter_pk]);
        let mut epoch = GrantingEpoch {
            chain: chain(),
            granter_index: 0,
            grantee_index: 4,
            grantee_roster_pk_hash: sha3_256(&[&grantee_pk]),
            role: Role::Moderator,
            granter_roster_pk: &granter_pk,
            sig: &[0; SIGNATURE_LEN],
        };
        let sig = granter
            .sign(&epoch.preimage(), &mut Rng(1))
            .unwrap()
            .to_bytes();
        epoch.sig = &sig;
        let mut out = vec![0u8; 6_000];
        let n = epoch.encode(&mut out).unwrap();
        let back = GrantingEpoch::parse(&out[..n]).unwrap();
        // GRP-317: the carried key must match the hash of the entry.
        back.verify(&granter_hash).unwrap();
        assert!(back.verify(&sha3_256(&[&grantee_pk])).is_err());
        // A key of another signer under the right hash fails the signature.
        let swapped = GrantingEpoch {
            granter_roster_pk: &grantee_pk,
            ..back.clone()
        };
        assert!(swapped.verify(&sha3_256(&[&grantee_pk])).is_err());
        // A demotion carries the key of the signer as each grant does.
        let demote = GrantingEpoch {
            role: Role::Member,
            ..epoch.clone()
        };
        assert_eq!(demote.encode(&mut out).unwrap(), n);
        let short = GrantingEpoch {
            granter_roster_pk: &granter_pk[..100],
            ..epoch.clone()
        };
        assert!(short.encode(&mut out).is_err());

        let mut moderation = ModerationEpoch {
            chain: chain(),
            actor_index: 0,
            actor_role: Role::Moderator,
            actions: vec![ModAction {
                action: 1,
                target: [9; 16],
                author_hint: 0xFFFF,
            }],
            actor_roster_pk: &granter_pk,
            sig: &[0; SIGNATURE_LEN],
        };
        let sig = granter
            .sign(&moderation.preimage(), &mut Rng(2))
            .unwrap()
            .to_bytes();
        moderation.sig = &sig;
        let n = moderation.encode(&mut out).unwrap();
        let back = ModerationEpoch::parse(&out[..n]).unwrap();
        back.verify(&granter_hash).unwrap();
        // The hint is not in the preimage, thus a changed hint still verifies.
        let mut hinted = back.clone();
        hinted.actions[0].author_hint = 3;
        hinted.verify(&granter_hash).unwrap();
        let too_many = ModerationEpoch {
            actions: vec![moderation.actions[0]; 21],
            ..moderation.clone()
        };
        assert!(too_many.encode(&mut out).is_err());
        assert!(parse_presence(&PRESENCE).is_ok());
        assert!(parse_presence(&[0x02]).is_err());
    }

    #[test]
    fn the_invitation_holds_its_two_stages() {
        let mut out = vec![0u8; 5_000];
        let offer = GroupInvitation {
            group_id: [7; 32],
            stage: InvitationStage::Offer {
                name: "friends",
                admin_roster_pk: &[1; VERIFYING_KEY_LEN],
                creator_roster_pk: &[2; VERIFYING_KEY_LEN],
            },
        };
        let n = offer.encode(&mut out).unwrap();
        assert_eq!(n, 36 + 3_905 + 7);
        assert_eq!(GroupInvitation::parse(&out[..n]).unwrap(), offer);
        let rep = ReplicaRef {
            relay_id: [3; 32],
            group_queue_id: [4; 32],
            seq_of_add: 9,
        };
        let admit = GroupInvitation {
            group_id: [7; 32],
            stage: InvitationStage::Admit(Box::new(InvitationAdmit {
                index: 4,
                epoch: 2,
                t_join: 497_000,
                slot_key: [5; 32],
                read_sk: [8; 32],
                write_sk: [9; 32],
                roster_epoch: 3,
                replicas: [rep, rep],
                descriptor: &[6; 257],
            })),
        };
        let n = admit.encode(&mut out).unwrap();
        assert_eq!(n, 36 + ADMIT_FIXED + 257);
        assert_eq!(GroupInvitation::parse(&out[..n]).unwrap(), admit);
        out[33] = 0x03;
        assert!(GroupInvitation::parse(&out[..n]).is_err());
        out[33] = 0x02;
        // The replica count byte sits after the three keys.
        out[36 + 110] = 3;
        assert!(GroupInvitation::parse(&out[..n]).is_err());
    }

    #[test]
    fn the_snapshot_checks_its_hashes_and_the_rekey_its_signature() {
        let kem_pk = [3u8; KEM_PK_LEN];
        let entry = GroupMemberEntry {
            index: 0,
            role: Role::Owner,
            pair_pk: [1; 32],
            roster_pk_hash: [2; 32],
            kem_pk_hash: sha3_256(&[&kem_pk]),
        };
        let snap = RosterSnapshot {
            group_id: [7; 32],
            roster_epoch: 3,
            chain_hash: [8; 32],
            entries: vec![entry],
            keys: vec![MemberKemKey {
                index: 0,
                kem_pk: &kem_pk,
            }],
            path: b"",
        };
        let mut out = vec![0u8; snap.len()];
        assert_eq!(snap.encode(&mut out).unwrap(), 77 + 99 + 1_218);
        assert_eq!(RosterSnapshot::parse(&out).unwrap(), snap);
        out[77 + 99 + 2] ^= 1;
        assert!(RosterSnapshot::parse(&out).is_err());
        let orphan = RosterSnapshot {
            keys: vec![MemberKemKey {
                index: 1,
                kem_pk: &kem_pk,
            }],
            ..snap.clone()
        };
        assert!(orphan.encode(&mut out).is_err());

        let old = SigningKey::from_seed(Secret::new([5; 32]));
        let old_pk = old.verifying_key().to_bytes();
        let mut rekey = RekeyRecord {
            chain: Chain {
                epoch_index: 0,
                previous_epoch_hash: [0; 32],
                ..chain()
            },
            old_index: 2,
            old_roster_pk: &old_pk,
            new_index: 5,
            new_keys: keys(),
            sig: &[0; SIGNATURE_LEN],
        };
        let sig = old.sign(&rekey.preimage(), &mut Rng(3)).unwrap().to_bytes();
        rekey.sig = &sig;
        let mut out = vec![0u8; REKEY_LEN];
        assert_eq!(rekey.encode(&mut out).unwrap(), REKEY_LEN);
        let back = RekeyRecord::parse(&out).unwrap();
        assert!(back.chain_is_zero());
        back.verify(&sha3_256(&[&old_pk])).unwrap();
        assert!(back.verify(&[0; 32]).is_err());
        // A changed old_index fails the signature (WIR-481).
        out[69] ^= 1;
        assert!(RekeyRecord::parse(&out)
            .unwrap()
            .verify(&sha3_256(&[&old_pk]))
            .is_err());
    }
}
