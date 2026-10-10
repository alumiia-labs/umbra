//! The join flow of Part 11 §11.9.1 at both ends, the history window of
//! §11.3.2, the re-key of §11.12, and the key request rate of §11.4.3.

use alloc::vec::Vec;

use umbra_crypto::{
    group::{
        chain::{ChainState, Credentials},
        MemberKeys,
    },
    hash::sha3_256,
    rand_core::TryCryptoRng,
    secret::Secret,
};
use umbra_wire::group::control::{
    Chain, ControlType, GroupControl, GroupInvitation, InvitationAdmit, InvitationStage,
    JoinRecord, MemberKeys as WireKeys, PlainEpoch, PlainOp, RekeyRecord, ReplicaRef,
    RosterSnapshot, ADMIT_FIXED,
};

use super::{epoch::EpochState, roster::Roster, GROUP_SLOT, HISTORY_WINDOW_MAX, KEY_REQUEST_RATE};
use crate::Error;

/// The seed and the keys a member makes at a join (`GRP-052`).
pub struct JoinKeys {
    /// `GroupRosterSeed_g`, for the local identity table.
    pub seed: Secret<32>,
    /// The three keys.
    pub keys: MemberKeys,
}

impl JoinKeys {
    /// Fresh keys from the device CSPRNG.
    pub fn make<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut seed = Secret::<32>::zeroed();
        rng.try_fill_bytes(seed.expose_mut())
            .map_err(|_| Error::Unverified)?;
        let keys = MemberKeys::from_seed(&seed);
        Ok(JoinKeys { seed, keys })
    }

    /// The wire keys of this member.
    pub fn wire_keys<'a>(&self, kem_pk: &'a [u8; 1_216]) -> WireKeys<'a> {
        WireKeys {
            pair_pk: self.keys.pair_public(),
            roster_pk_hash: sha3_256(&[&self.keys.roster().verifying_key().to_bytes()]),
            kem_pk,
        }
    }

    /// The `JoinRecord` the joiner sends on the pairwise channel
    /// (`GRP-309`).
    pub fn join_record(&self, group_id: [u8; 32]) -> Result<Vec<u8>, Error> {
        let kem_pk = self.keys.kem().public().to_bytes();
        let record = JoinRecord {
            group_id,
            keys: self.wire_keys(&kem_pk),
        };
        let mut payload = alloc::vec![0u8; 1_400];
        let n = record.encode(&mut payload)?;
        wrap(ControlType::Join, payload.get(..n).ok_or(Error::Malformed)?)
    }
}

pub(crate) fn wrap(control_type: ControlType, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let control = GroupControl {
        control_type,
        payload,
    };
    let mut out = alloc::vec![0u8; payload.len().saturating_add(8)];
    let n = control.encode(&mut out)?;
    out.truncate(n);
    Ok(out)
}

/// The plain epoch that adds a joiner, from its `JoinRecord`
/// (`GRP-310`, `GRP-319`). An admin builds none for keys that each member
/// would refuse (`GRP-320`), and none while its roster holds no certain
/// index for it (`GRP-329`).
pub fn add_epoch(roster: &Roster, join: &JoinRecord<'_>) -> Result<Vec<u8>, Error> {
    if join.group_id != *roster.group_id() {
        return Err(Error::Unverified);
    }
    Roster::check_keys(&join.keys)?;
    let epoch = PlainEpoch {
        chain: Chain {
            group_id: *roster.group_id(),
            epoch_index: roster.epoch_index().saturating_add(1),
            previous_epoch_hash: *roster.chain_hash(),
        },
        op: PlainOp::Add {
            index: roster.build_index()?,
            keys: join.keys.clone(),
        },
    };
    let mut payload = alloc::vec![0u8; 1_400];
    let n = epoch.encode(&mut payload)?;
    wrap(
        ControlType::PlainEpoch,
        payload.get(..n).ok_or(Error::Malformed)?,
    )
}

/// The slot whose key the admit hands: `t_join`, or `t_join − W` under a
/// history window, and never before the start of the epoch (`GRP-233`,
/// `GRP-234`).
pub const fn admit_slot(t_join: u32, start_slot: u32, history_window_seconds: u64) -> u32 {
    let window = if history_window_seconds > HISTORY_WINDOW_MAX {
        HISTORY_WINDOW_MAX
    } else {
        history_window_seconds
    };
    let back = (window / GROUP_SLOT) as u32;
    let wanted = t_join.saturating_sub(back);
    if wanted < start_slot {
        start_slot
    } else {
        wanted
    }
}

/// The admit an inviting admin sends after the add took `GSEQ` at each
/// replica (`GRP-312`). `chain` is the epoch chain of the admin, from
/// which the slot key of `slot` comes.
#[allow(clippy::too_many_arguments)]
pub fn admit(
    group_id: [u8; 32],
    index: u16,
    epoch: u32,
    t_e: u32,
    slot: u32,
    chain: &ChainState,
    credentials: &Credentials,
    roster_epoch: u32,
    replicas: [ReplicaRef; 2],
    descriptor: &[u8],
) -> Result<Vec<u8>, Error> {
    let slot_key = chain.slot_key(slot)?;
    let invitation = GroupInvitation {
        group_id,
        stage: InvitationStage::Admit(alloc::boxed::Box::new(InvitationAdmit {
            index,
            epoch,
            t_e,
            t_join: slot,
            slot_key: *slot_key.expose(),
            // GRP-384: the joiner holds no `K_e`, thus the admit hands it
            // the two credentials of the group queue.
            read_sk: *credentials.read_secret().expose(),
            write_sk: *credentials.write_secret().expose(),
            roster_epoch,
            replicas,
            descriptor,
        })),
    };
    // 36 bytes of header, the fixed body, and the descriptor.
    let mut payload = alloc::vec![0u8; descriptor.len().saturating_add(ADMIT_FIXED + 64)];
    let n = invitation.encode(&mut payload)?;
    wrap(
        ControlType::Invitation,
        payload.get(..n).ok_or(Error::Malformed)?,
    )
}

/// What a joiner installs from an admit and the snapshot it fetched
/// (`GRP-313`, `GRP-326`).
pub struct Admitted {
    /// The roster at the add.
    pub roster: Roster,
    /// The epoch state from the slot key.
    pub epoch: EpochState,
    /// The member index.
    pub index: u16,
    /// The replicas with the `seq` of the add at each.
    pub replicas: [ReplicaRef; 2],
}

impl Admitted {
    /// Whether the entry at the index of the admit holds the three keys of
    /// `own`, the joiner (`GRP-326`). Under another entry the joiner would
    /// find no tag for itself and no slot, and it would read nothing with
    /// no failed admission shown (`GRP-328`).
    pub fn holds_keys(&self, own: &MemberKeys) -> bool {
        self.roster.member(self.index).is_some_and(|entry| {
            entry.active
                && entry.pair_pk == own.pair_public()
                && entry.kem_pk_hash == sha3_256(&[&own.kem().public().to_bytes()])
                && entry.roster_pk_hash == sha3_256(&[&own.roster().verifying_key().to_bytes()])
        })
    }

    /// The admission, for a joiner whose keys come from `seed`; an admit
    /// under the entry of another member fails (`GRP-327`).
    pub fn for_seed(self, seed: &Secret<32>) -> Result<Self, Error> {
        if self.holds_keys(&MemberKeys::from_seed(seed)) {
            Ok(self)
        } else {
            Err(Error::Unverified)
        }
    }
}

/// Verifies an admit against the fetched snapshot and the hash of the add
/// record, and installs the epoch from the slot key. The joiner then
/// checks the entry of its index with [`Admitted::for_seed`].
pub fn accept_admit(
    invitation: &GroupInvitation<'_>,
    snapshot: &RosterSnapshot<'_>,
    add_record_hash: &[u8; 32],
    creator_roster_pk: &[u8],
    now: u64,
) -> Result<Admitted, Error> {
    let InvitationStage::Admit(admit) = &invitation.stage else {
        return Err(Error::Malformed);
    };
    let InvitationAdmit {
        index,
        epoch,
        t_e,
        t_join,
        slot_key,
        read_sk,
        write_sk,
        roster_epoch,
        replicas,
        ..
    } = admit.as_ref();
    if snapshot.group_id != invitation.group_id || snapshot.roster_epoch != *roster_epoch {
        return Err(Error::Unverified);
    }
    let roster = Roster::from_snapshot(snapshot, add_record_hash, creator_roster_pk, now)?;
    if !roster.member(*index).is_some_and(|m| m.active) {
        return Err(Error::Unverified);
    }
    // GRP-224: the age of the epoch runs from its start, and the key of the
    // joiner starts at or after it.
    if t_join < t_e {
        return Err(Error::Malformed);
    }
    let chain = ChainState::from_slot_key(*epoch, *t_join, Secret::new(*slot_key));
    let credentials = Credentials::from_secrets(&Secret::new(*read_sk), &Secret::new(*write_sk));
    let epoch_state = EpochState::from_chain(chain, *epoch, *t_e, *roster_epoch, credentials, now);
    Ok(Admitted {
        roster,
        epoch: epoch_state,
        index: *index,
        replicas: *replicas,
    })
}

/// The `RekeyRecord` of a member that moves to new keys, signed under the
/// old roster key (`GRP-365`). With `on_chain` false the chain fields are
/// zero, for the pairwise channel of `GRP-370`. A record for the chain
/// takes an index that each member holds as the next one. Thus a roster
/// whose index is open builds none (`GRP-329`).
pub fn rekey_record<R: TryCryptoRng + ?Sized>(
    old: &MemberKeys,
    new: &JoinKeys,
    roster: &Roster,
    old_index: u16,
    on_chain: bool,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let chain = if on_chain {
        Chain {
            group_id: *roster.group_id(),
            epoch_index: roster.epoch_index().saturating_add(1),
            previous_epoch_hash: *roster.chain_hash(),
        }
    } else {
        Chain {
            group_id: *roster.group_id(),
            epoch_index: 0,
            previous_epoch_hash: [0; 32],
        }
    };
    let old_pk = old.roster().verifying_key().to_bytes();
    let kem_pk = new.keys.kem().public().to_bytes();
    let mut record = RekeyRecord {
        chain,
        old_index,
        old_roster_pk: &old_pk,
        new_index: if on_chain {
            roster.build_index()?
        } else {
            roster.next_index()?
        },
        new_keys: new.wire_keys(&kem_pk),
        sig: &[],
    };
    let preimage = record.preimage();
    let sig = old.roster().sign(&preimage, rng)?.to_bytes();
    record.sig = &sig;
    let mut payload = alloc::vec![0u8; 8_000];
    let n = record.encode(&mut payload)?;
    wrap(
        ControlType::Rekey,
        payload.get(..n).ok_or(Error::Malformed)?,
    )
}

/// The epoch key requests of one group in one day (`GRP-295`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyRequestRate {
    sent: Vec<u64>,
}

impl KeyRequestRate {
    /// Whether a request may go at `now`, and records it if so.
    pub fn allow(&mut self, now: u64) -> bool {
        self.sent.retain(|at| now.saturating_sub(*at) < 86_400);
        if self.sent.len() >= usize::try_from(KEY_REQUEST_RATE).unwrap_or(usize::MAX) {
            return false;
        }
        self.sent.push(now);
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        group::{roster::tests::entry_of, test_util::member},
    };
    use umbra_crypto::group::chain::EpochSecret;
    use umbra_wire::group::control::{GroupMemberEntry, MemberKemKey, Role};

    #[test]
    fn a_join_adds_admits_and_installs_the_slot_key() {
        let group = [7u8; 32];
        let creator = member(1);
        let mut roster = Roster::genesis(group, entry_of(&creator, 0, Role::Owner), 0);
        let mut rng = Rng(1);
        let joiner = JoinKeys::make(&mut rng).unwrap();
        let join_bytes = joiner.join_record(group).unwrap();
        let control = GroupControl::parse(&join_bytes).unwrap();
        assert_eq!(control.control_type, ControlType::Join);
        let join = JoinRecord::parse(control.payload).unwrap();
        let add = add_epoch(&roster, &join).unwrap();
        let add_control = GroupControl::parse(&add).unwrap();
        roster.apply(&add_control, 0, 10).unwrap();
        let add_hash = add_control.epoch_hash();

        // The admin's epoch chain gives the slot key.
        let secret = EpochSecret::generate(&mut rng).unwrap();
        let chain = secret.start(&group, 3, 100);
        let slot = admit_slot(120, 100, 0);
        assert_eq!(slot, 120);
        assert_eq!(admit_slot(120, 100, 5 * GROUP_SLOT), 115);
        assert_eq!(admit_slot(120, 100, 40 * GROUP_SLOT), 100);
        let replicas = [
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
        ];
        let admit_bytes = admit(
            group,
            1,
            3,
            100,
            slot,
            &chain,
            &secret.credentials(),
            roster.epoch_index(),
            replicas,
            b"descriptor",
        )
        .unwrap();
        let admit_control = GroupControl::parse(&admit_bytes).unwrap();
        let invitation = GroupInvitation::parse(admit_control.payload).unwrap();

        // The snapshot at the add, with the creator's key on no path.
        let creator_pk = creator.roster().verifying_key().to_bytes();
        let entries: Vec<GroupMemberEntry> = roster.entries();
        let creator_kem = creator.kem().public().to_bytes();
        let joiner_kem = joiner.keys.kem().public().to_bytes();
        let keys = alloc::vec![
            MemberKemKey {
                index: 0,
                kem_pk: &creator_kem
            },
            MemberKemKey {
                index: 1,
                kem_pk: &joiner_kem
            },
        ];
        let snapshot = RosterSnapshot {
            group_id: group,
            roster_epoch: roster.epoch_index(),
            chain_hash: add_hash,
            entries,
            keys,
            path: &[],
        };
        let admitted = accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, 50)
            .unwrap()
            .for_seed(&joiner.seed)
            .unwrap();
        assert_eq!(admitted.index, 1);
        assert_eq!(admitted.epoch.epoch(), 3);
        // GRP-224: the joiner takes `t_e` of the epoch, and its key starts
        // at the join slot.
        assert_eq!(admitted.epoch.start_slot(), 100);
        assert_eq!(admitted.epoch.chain().slot(), slot);
        assert_eq!(admitted.roster.active_count(), 2);
        // The joiner's chain agrees with the admin's from the join slot on.
        let mut joiner_chain = ChainState::from_slot_key(3, slot, chain.slot_key(slot).unwrap());
        joiner_chain.advance(slot).unwrap();
        assert_eq!(
            joiner_chain.record_key(125).unwrap().expose(),
            chain.record_key(125).unwrap().expose()
        );
        assert!(joiner_chain.record_key(119).is_err());
        let wrong = RosterSnapshot {
            chain_hash: [0; 32],
            ..snapshot
        };
        assert!(accept_admit(&invitation, &wrong, &add_hash, &creator_pk, 50).is_err());
        // GRP-326: the entry at the index of the admit holds the keys of
        // the joiner. An admit with the index of another member fails.
        let other = GroupInvitation {
            group_id: group,
            stage: match &invitation.stage {
                InvitationStage::Admit(admit) => {
                    InvitationStage::Admit(alloc::boxed::Box::new(InvitationAdmit {
                        index: 0,
                        epoch: admit.epoch,
                        t_e: admit.t_e,
                        t_join: admit.t_join,
                        slot_key: admit.slot_key,
                        read_sk: admit.read_sk,
                        write_sk: admit.write_sk,
                        roster_epoch: admit.roster_epoch,
                        replicas: admit.replicas,
                        descriptor: admit.descriptor,
                    }))
                }
                _ => panic!("the invitation is no admit"),
            },
        };
        let whole = RosterSnapshot {
            chain_hash: add_hash,
            ..wrong
        };
        let under_other = accept_admit(&other, &whole, &add_hash, &creator_pk, 50).unwrap();
        assert!(!under_other.holds_keys(&joiner.keys));
        assert_eq!(
            under_other.for_seed(&joiner.seed).err(),
            Some(Error::Unverified)
        );
        assert!(
            accept_admit(&invitation, &whole, &add_hash, &creator_pk, 50)
                .unwrap()
                .for_seed(&joiner.seed)
                .is_ok()
        );
        // GRP-320: an admin builds no add for a pair key of low order.
        let kem = joiner.keys.kem().public().to_bytes();
        let low = JoinRecord {
            group_id: group,
            keys: WireKeys {
                pair_pk: [0; 32],
                ..joiner.wire_keys(&kem)
            },
        };
        assert_eq!(add_epoch(&roster, &low).err(), Some(Error::Unverified));
    }

    #[test]
    fn a_rekey_chains_the_roster_and_moves_the_role() {
        let group = [7u8; 32];
        let creator = member(1);
        let old = member(2);
        let mut roster = Roster::genesis(group, entry_of(&creator, 0, Role::Owner), 0);
        let join = old.kem().public().to_bytes();
        let add = add_epoch(
            &roster,
            &JoinRecord {
                group_id: group,
                keys: WireKeys {
                    pair_pk: old.pair_public(),
                    roster_pk_hash: sha3_256(&[&old.roster().verifying_key().to_bytes()]),
                    kem_pk: &join,
                },
            },
        )
        .unwrap();
        roster
            .apply(&GroupControl::parse(&add).unwrap(), 0, 1)
            .unwrap();
        let mut rng = Rng(4);
        let fresh = JoinKeys::make(&mut rng).unwrap();
        let record = rekey_record(&old, &fresh, &roster, 1, true, &mut rng).unwrap();
        let control = GroupControl::parse(&record).unwrap();
        let applied = roster.apply(&control, 1, 2).unwrap();
        assert!(matches!(
            applied,
            crate::group::roster::Applied::Rekeyed { old: 1, new: 2, .. }
        ));
        assert!(!roster.member(1).unwrap().active);
        assert_eq!(roster.member(2).unwrap().role, Role::Member);
        let pairwise = rekey_record(&old, &fresh, &roster, 1, false, &mut rng).unwrap();
        let control = GroupControl::parse(&pairwise).unwrap();
        assert!(RekeyRecord::parse(control.payload).unwrap().chain_is_zero());
        let mut rate = KeyRequestRate::default();
        for _ in 0..KEY_REQUEST_RATE {
            assert!(rate.allow(0));
        }
        assert!(!rate.allow(1));
        assert!(rate.allow(86_400));
    }
}
