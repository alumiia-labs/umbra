//! The ownership claim record of Part 7 §7.3.1 and the fold that gives the
//! current owner of each subject, with the absence claim and the two
//! rates.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    roster::{ClaimScope, OwnerClaim, Roster, CLAIM_LEN},
    DeviceId, OWNER_ABSENCE, OWNER_ABSENCE_RATE, OWNER_CLAIM_MAX, OWNER_CLAIM_RATE, OWNER_TIMEOUT,
};
use crate::Error;

/// The fixed fields of a claim record, without the claims and signature.
pub const FIXED: usize = 62;

/// An ownership claim record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerClaimRecord<'a> {
    /// The roster epoch this record extends.
    pub roster_epoch: u64,
    /// SHA3-256 of that roster epoch.
    pub roster_hash: [u8; 32],
    /// Strictly increasing for each signer in that epoch.
    pub claim_seq: u32,
    /// 1 to `OWNER_CLAIM_MAX` claims.
    pub claims: Vec<OwnerClaim>,
    /// The signing device.
    pub signer_id: DeviceId,
    /// The signature under `DeviceRosterKey` of the signer.
    pub sig: &'a [u8],
}

impl<'a> OwnerClaimRecord<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.claims.is_empty()
            || self.claims.len() > OWNER_CLAIM_MAX
            || self.sig.len() != SIGNATURE_LEN
        {
            return Err(Error::Malformed);
        }
        // DEV-234: an absence claim travels alone. A subject shows once.
        // The parse of the scope rejects `0x02` (DEV-192).
        let has_absence = self.claims.iter().any(|c| c.scope == ClaimScope::Absence);
        if has_absence && self.claims.iter().any(|c| c.scope != ClaimScope::Absence) {
            return Err(Error::Malformed);
        }
        for (i, a) in self.claims.iter().enumerate() {
            if self
                .claims
                .iter()
                .skip(i + 1)
                .any(|b| b.subject == a.subject)
            {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }

    fn put_signed(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(0x01)?;
        w.put(&self.roster_epoch.to_be_bytes())?;
        w.put(&self.roster_hash)?;
        w.u32(self.claim_seq)?;
        w.u8(u8::try_from(self.claims.len()).map_err(|_| Error::Malformed)?)?;
        for c in &self.claims {
            c.put(w)?;
        }
        w.put(&self.signer_id)?;
        Ok(())
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        FIXED
            .saturating_add(self.claims.len().saturating_mul(CLAIM_LEN))
            .saturating_add(SIGNATURE_LEN)
    }

    /// Whether the record holds no claim.
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// The signature preimage.
    pub fn preimage(&self) -> Result<Vec<u8>, Error> {
        let mut body = alloc::vec![0u8; self.len().saturating_sub(SIGNATURE_LEN)];
        let mut w = Writer::new(&mut body);
        self.put_signed(&mut w)?;
        let n = w.position();
        let mut out = Vec::with_capacity(labels::DEVICE_CLAIM.len() + n);
        out.extend_from_slice(labels::DEVICE_CLAIM);
        out.extend_from_slice(body.get(..n).ok_or(Error::Malformed)?);
        Ok(out)
    }

    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        self.put_signed(&mut w)?;
        w.put(self.sig)?;
        Ok(w.position())
    }

    /// Reads a record.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let roster_epoch = u64::from_be_bytes(r.array()?);
        let roster_hash = r.array()?;
        let claim_seq = r.u32()?;
        let count = usize::from(r.u8()?);
        if count == 0 || count > OWNER_CLAIM_MAX {
            return Err(Error::Malformed);
        }
        let mut claims = Vec::with_capacity(count);
        for _ in 0..count {
            claims.push(OwnerClaim::read(&mut r)?);
        }
        let signer_id = r.array()?;
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        let out = OwnerClaimRecord {
            roster_epoch,
            roster_hash,
            claim_seq,
            claims,
            signer_id,
            sig,
        };
        out.check()?;
        Ok(out)
    }

    /// Verifies the record against the roster epoch it names (`DEV-185`
    /// to `DEV-188`).
    pub fn verify(
        &self,
        roster: &Roster<'_>,
        roster_hash: &[u8; 32],
        highest_applied: u64,
    ) -> Result<(), Error> {
        if roster.epoch != self.roster_epoch || self.roster_hash != *roster_hash {
            return Err(Error::Unverified);
        }
        if self.roster_epoch < highest_applied {
            return Err(Error::Stale);
        }
        let entry = roster.entry(&self.signer_id).ok_or(Error::Unverified)?;
        let key = VerifyingKey::from_bytes(entry.mldsa_pk)?;
        let sig = Signature::from_bytes(self.sig)?;
        key.verify(&self.preimage()?, &sig)?;
        Ok(())
    }

    /// The hash of the record bytes, for a caller that must compare two.
    pub fn hash(bytes: &[u8]) -> [u8; 32] {
        sha3_256(&[bytes])
    }
}

/// The owner of one subject and the pair that named it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owned {
    /// The owner.
    pub owner: DeviceId,
    /// The roster epoch and the claim sequence that named it; a roster
    /// epoch ranks at claim sequence zero.
    pub at: (u64, u32),
    /// The signer of that claim, the tiebreak of `DEV-190`.
    pub signer: DeviceId,
}

/// The ownership table (`DEV-227`), with the absence subjects the caller
/// learned from the roster beside it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ownership {
    table: BTreeMap<[u8; 32], Owned>,
    absent: BTreeMap<[u8; 32], DeviceId>,
}

impl Ownership {
    /// The owner of `subject`, or `None` when no claim named it, in which
    /// case the device that established it owns it (`DEV-159`).
    pub fn owner(&self, subject: &[u8; 32]) -> Option<&Owned> {
        self.table.get(subject)
    }

    fn apply(&mut self, subject: [u8; 32], candidate: Owned) {
        let replace = match self.table.get(&subject) {
            None => true,
            Some(held) => {
                candidate.at > held.at
                    || (candidate.at == held.at && candidate.signer < held.signer)
            }
        };
        if replace {
            self.table.insert(subject, candidate);
        }
    }

    /// Folds the claims of a verified roster epoch (`DEV-158`).
    pub fn fold_roster(&mut self, roster: &Roster<'_>) {
        for c in &roster.claims {
            self.fold_one(c, roster.epoch, 0, roster.signer_id);
        }
    }

    /// Folds a verified claim record (`DEV-189`, `DEV-190`). The record's
    /// bytes are not retained afterwards (`DEV-229`).
    pub fn fold_record(&mut self, record: &OwnerClaimRecord<'_>) {
        for c in &record.claims {
            self.fold_one(c, record.roster_epoch, record.claim_seq, record.signer_id);
        }
    }

    fn fold_one(&mut self, claim: &OwnerClaim, epoch: u64, seq: u32, signer: DeviceId) {
        let candidate = Owned {
            owner: claim.owner,
            at: (epoch, seq),
            signer,
        };
        if claim.scope == ClaimScope::Absence {
            // Every subject the absent device owns at this point moves
            // (DEV-233). The subject names the absent device.
            let absent = self.absent_device(&claim.subject);
            let moved: Vec<[u8; 32]> = self
                .table
                .iter()
                .filter(|(_, o)| Some(o.owner) == absent)
                .map(|(s, _)| *s)
                .collect();
            for s in moved {
                self.apply(s, candidate);
            }
            return;
        }
        self.apply(claim.subject, candidate);
    }

    /// Records the blinded subject of an absence claim against the device
    /// it names, which the caller learned from the roster.
    pub fn register_absence_subject(&mut self, subject: [u8; 32], device: DeviceId) {
        self.absent.insert(subject, device);
    }

    fn absent_device(&self, subject: &[u8; 32]) -> Option<DeviceId> {
        self.absent.get(subject).copied()
    }
}

impl Ownership {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Whether a device may claim a subject whose owner has been silent for
/// `silent_for` seconds (`DEV-049`, `DEV-169`).
pub const fn may_claim_after_timeout(silent_for: u64) -> bool {
    silent_for >= OWNER_TIMEOUT
}

/// Whether a claimant may publish an absence claim for a device silent
/// for `absent_for` seconds (`DEV-231`).
pub const fn may_claim_absence(absent_for: u64) -> bool {
    absent_for >= OWNER_ABSENCE
}

/// The two rates of claim records (`DEV-191`, `DEV-232`, `DEV-260`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimRate {
    ordinary: Vec<u64>,
    absence: Vec<u64>,
}

impl ClaimRate {
    /// Whether a record of `scope` may go at `now`, and records it if so.
    pub fn allow(&mut self, scope: ClaimScope, now: u64) -> bool {
        match scope {
            ClaimScope::Absence => {
                self.absence.retain(|t| now.saturating_sub(*t) < 3_600);
                if self.absence.len() >= OWNER_ABSENCE_RATE as usize {
                    return false;
                }
                self.absence.push(now);
                true
            }
            _ => {
                self.ordinary.retain(|t| now.saturating_sub(*t) < 86_400);
                if self.ordinary.len() >= OWNER_CLAIM_RATE as usize {
                    return false;
                }
                self.ordinary.push(now);
                true
            }
        }
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
    use crate::devset::roster::tests::{entry, key, sign};
    use crate::directory::descriptor::tests::Rng;

    #[test]
    fn a_record_verifies_against_its_epoch_and_the_fold_ranks_by_pair() {
        let k1 = key(1);
        let pk1 = k1.verifying_key().to_bytes();
        let kem = [9u8; 1_184];
        let sig0 = [0u8; SIGNATURE_LEN];
        let mut roster = Roster {
            epoch: 4,
            devices: alloc::vec![entry(1, &pk1, &kem)],
            revoked: Vec::new(),
            claims: alloc::vec![OwnerClaim {
                scope: ClaimScope::Pairwise,
                subject: [7; 32],
                owner: [1; 16],
            }],
            prev_hash: [0; 32],
            signer_id: [1; 16],
            sig: &sig0,
        };
        let mut s = [0u8; SIGNATURE_LEN];
        sign(&mut roster, &k1, &mut s);
        roster.sig = &s;
        let mut bytes = alloc::vec![0u8; roster.len()];
        roster.encode(&mut bytes).unwrap();
        let hash = Roster::hash(&bytes);

        let mut record = OwnerClaimRecord {
            roster_epoch: 4,
            roster_hash: hash,
            claim_seq: 1,
            claims: alloc::vec![OwnerClaim {
                scope: ClaimScope::Pairwise,
                subject: [7; 32],
                owner: [2; 16],
            }],
            signer_id: [1; 16],
            sig: &sig0,
        };
        let rs = k1
            .sign(&record.preimage().unwrap(), &mut Rng(2))
            .unwrap()
            .to_bytes();
        record.sig = &rs;
        let mut rb = alloc::vec![0u8; record.len()];
        record.encode(&mut rb).unwrap();
        assert_eq!(rb.len(), 62 + 49 + 3_309);
        let parsed = OwnerClaimRecord::parse(&rb).unwrap();
        parsed.verify(&roster, &hash, 4).unwrap();
        assert_eq!(parsed.verify(&roster, &hash, 5), Err(Error::Stale));
        assert!(parsed.verify(&roster, &[1; 32], 4).is_err());

        let mut table = Ownership::new();
        table.fold_roster(&roster);
        assert_eq!(table.owner(&[7; 32]).unwrap().owner, [1; 16]);
        table.fold_record(&parsed);
        assert_eq!(table.owner(&[7; 32]).unwrap().owner, [2; 16]);
        // A lower pair does not move it back.
        table.fold_roster(&roster);
        assert_eq!(table.owner(&[7; 32]).unwrap().owner, [2; 16]);

        // An absence claim moves every subject of the absent device.
        table.register_absence_subject([8; 32], [2; 16]);
        let absence = OwnerClaimRecord {
            roster_epoch: 4,
            roster_hash: hash,
            claim_seq: 2,
            claims: alloc::vec![OwnerClaim {
                scope: ClaimScope::Absence,
                subject: [8; 32],
                owner: [1; 16],
            }],
            signer_id: [1; 16],
            sig: &sig0,
        };
        table.fold_record(&absence);
        assert_eq!(table.owner(&[7; 32]).unwrap().owner, [1; 16]);
        assert!(may_claim_after_timeout(OWNER_TIMEOUT));
        assert!(!may_claim_absence(OWNER_ABSENCE - 1));
        let mut rate = ClaimRate::default();
        for _ in 0..OWNER_CLAIM_RATE {
            assert!(rate.allow(ClaimScope::Pairwise, 0));
        }
        assert!(!rate.allow(ClaimScope::GroupSender, 0));
        assert!(rate.allow(ClaimScope::Absence, 0));
        assert!(!rate.allow(ClaimScope::Absence, 100));
        assert!(rate.allow(ClaimScope::Absence, 3_600));
    }
}
