//! The roster of Part 7 §7.3.1: the signed, hash-chained description of a
//! device set, and the five rules of a roster epoch.

use alloc::vec::Vec;

use umbra_crypto::{
    hash::sha3_256,
    labels,
    secret::Secret,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{DeviceId, MAX_DEVICES, OWNER_CLAIM_MAX};
use crate::Error;

/// The width of a `DeviceEntry`.
pub const ENTRY_LEN: usize = 3_225;
/// The width of an `OwnerClaim`.
pub const CLAIM_LEN: usize = 49;
/// The fixed fields of a roster, without the entries, tombstones, claims
/// and signature.
pub const FIXED: usize = 60;

/// The sync scope of a device (§7.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncScope {
    /// All the history in the retention window.
    Full = 0x01,
    /// The last 30 days.
    Recent = 0x02,
    /// Only what arrives after the link.
    Live = 0x03,
}

impl SyncScope {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(SyncScope::Full),
            0x02 => Ok(SyncScope::Recent),
            0x03 => Ok(SyncScope::Live),
            _ => Err(Error::Malformed),
        }
    }
}

/// One device of the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry<'a> {
    /// Random, not derived (`DEV-224`).
    pub device_id: DeviceId,
    /// The X25519 half of `DeviceKey_i`.
    pub x25519_pk: [u8; 32],
    /// The ML-KEM-768 half of `DeviceKey_i`.
    pub mlkem_pk: &'a [u8],
    /// `DeviceRosterKey_i`, made on that device.
    pub mldsa_pk: &'a [u8],
    /// The user-visible label.
    pub label: [u8; 32],
    /// The epoch that added the device.
    pub added_epoch: u64,
    /// The sync scope.
    pub sync_scope: SyncScope,
}

/// The scope of an ownership claim. The value `0x02` is retired and never
/// returns (`DEV-192`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClaimScope {
    /// A pairwise identity.
    Pairwise = 0x01,
    /// Each subject of an absent device.
    Absence = 0x03,
    /// The group sender owner.
    GroupSender = 0x04,
}

impl ClaimScope {
    /// The scope of a byte.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(ClaimScope::Pairwise),
            0x03 => Ok(ClaimScope::Absence),
            0x04 => Ok(ClaimScope::GroupSender),
            _ => Err(Error::Malformed),
        }
    }
}

/// One ownership claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerClaim {
    /// The scope.
    pub scope: ClaimScope,
    /// The blinded subject of `DEV-226`.
    pub subject: [u8; 32],
    /// The device that takes the ownership.
    pub owner: DeviceId,
}

impl OwnerClaim {
    /// `subject = SHA3-256(K_set || scope || value)` (`DEV-226`). The value
    /// of scope `0x04` is 32 zero bytes.
    pub fn subject(set_key: &Secret<32>, scope: ClaimScope, value: &[u8]) -> [u8; 32] {
        sha3_256(&[set_key.expose(), &[scope as u8], value])
    }

    pub(crate) fn put(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(self.scope as u8)?;
        w.put(&self.subject)?;
        w.put(&self.owner)?;
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(OwnerClaim {
            scope: ClaimScope::from_byte(r.u8()?)?,
            subject: r.array()?,
            owner: r.array()?,
        })
    }
}

/// A roster epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster<'a> {
    /// Strictly increasing.
    pub epoch: u64,
    /// The devices.
    pub devices: Vec<DeviceEntry<'a>>,
    /// The tombstones, never removed.
    pub revoked: Vec<DeviceId>,
    /// The ownership changes of this epoch.
    pub claims: Vec<OwnerClaim>,
    /// SHA3-256 of the previous roster.
    pub prev_hash: [u8; 32],
    /// The signing device.
    pub signer_id: DeviceId,
    /// The signature under `DeviceRosterKey` of the signer.
    pub sig: &'a [u8],
}

impl<'a> Roster<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.devices.is_empty()
            || self.devices.len() > MAX_DEVICES
            || self.claims.len() > OWNER_CLAIM_MAX
            || self.sig.len() != SIGNATURE_LEN
            || self
                .devices
                .iter()
                .any(|d| d.mlkem_pk.len() != 1_184 || d.mldsa_pk.len() != VERIFYING_KEY_LEN)
        {
            return Err(Error::Malformed);
        }

        // DEV-224, DEV-157: a `device_id` names one device. An epoch that
        // names one identifier two times gives two devices one sync channel.
        // An epoch that names a revoked identifier as a device puts back a
        // device that a tombstone removed.
        for (i, a) in self.devices.iter().enumerate() {
            if self
                .devices
                .iter()
                .skip(i.saturating_add(1))
                .any(|b| b.device_id == a.device_id)
                || self.revoked.contains(&a.device_id)
            {
                return Err(Error::Malformed);
            }
        }

        // DEV-162: no subject twice in one epoch.
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
        w.put(&self.epoch.to_be_bytes())?;
        w.u8(u8::try_from(self.devices.len()).map_err(|_| Error::Malformed)?)?;
        for d in &self.devices {
            w.put(&d.device_id)?;
            w.put(&d.x25519_pk)?;
            w.put(d.mlkem_pk)?;
            w.put(d.mldsa_pk)?;
            w.put(&d.label)?;
            w.put(&d.added_epoch.to_be_bytes())?;
            w.u8(d.sync_scope as u8)?;
        }
        w.u8(u8::try_from(self.revoked.len()).map_err(|_| Error::Malformed)?)?;
        for t in &self.revoked {
            w.put(t)?;
        }
        w.u8(u8::try_from(self.claims.len()).map_err(|_| Error::Malformed)?)?;
        for c in &self.claims {
            c.put(w)?;
        }
        w.put(&self.prev_hash)?;
        w.put(&self.signer_id)?;
        Ok(())
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        FIXED
            .saturating_add(self.devices.len().saturating_mul(ENTRY_LEN))
            .saturating_add(self.revoked.len().saturating_mul(16))
            .saturating_add(self.claims.len().saturating_mul(CLAIM_LEN))
            .saturating_add(SIGNATURE_LEN)
    }

    /// Whether the roster names no device.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// The signature preimage.
    pub fn preimage(&self) -> Result<Vec<u8>, Error> {
        let mut body = alloc::vec![0u8; self.len().saturating_sub(SIGNATURE_LEN)];
        let mut w = Writer::new(&mut body);
        self.put_signed(&mut w)?;
        let n = w.position();

        let mut out = Vec::with_capacity(labels::DEVICE_ROSTER.len() + n);
        out.extend_from_slice(labels::DEVICE_ROSTER);
        out.extend_from_slice(body.get(..n).ok_or(Error::Malformed)?);
        Ok(out)
    }

    /// Writes the roster.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        self.put_signed(&mut w)?;
        w.put(self.sig)?;
        Ok(w.position())
    }

    /// Reads a roster (`DEV-010`, `DEV-161`, `DEV-162`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let epoch = u64::from_be_bytes(r.array()?);
        let count = usize::from(r.u8()?);
        if count == 0 || count > MAX_DEVICES {
            return Err(Error::Malformed);
        }

        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            devices.push(DeviceEntry {
                device_id: r.array()?,
                x25519_pk: r.array()?,
                mlkem_pk: r.take(1_184)?,
                mldsa_pk: r.take(VERIFYING_KEY_LEN)?,
                label: r.array()?,
                added_epoch: u64::from_be_bytes(r.array()?),
                sync_scope: SyncScope::from_byte(r.u8()?)?,
            });
        }

        let revoked_count = usize::from(r.u8()?);
        let mut revoked = Vec::with_capacity(revoked_count);
        for _ in 0..revoked_count {
            revoked.push(r.array()?);
        }

        let claim_count = usize::from(r.u8()?);
        if claim_count > OWNER_CLAIM_MAX {
            return Err(Error::Malformed);
        }

        let mut claims = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            claims.push(OwnerClaim::read(&mut r)?);
        }

        let prev_hash = r.array()?;
        let signer_id = r.array()?;
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;

        let out = Roster {
            epoch,
            devices,
            revoked,
            claims,
            prev_hash,
            signer_id,
            sig,
        };
        out.check()?;
        Ok(out)
    }

    /// The hash of the roster bytes, which the successor chains to.
    pub fn hash(bytes: &[u8]) -> [u8; 32] {
        sha3_256(&[bytes])
    }

    /// The entry of `device_id`, if the roster holds it.
    pub fn entry(&self, device_id: &DeviceId) -> Option<&DeviceEntry<'a>> {
        self.devices.iter().find(|d| d.device_id == *device_id)
    }

    fn verify_with(&self, key_bytes: &[u8]) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(key_bytes)?;
        let sig = Signature::from_bytes(self.sig)?;
        key.verify(&self.preimage()?, &sig)?;
        Ok(())
    }

    /// Verifies the signature of the epoch under one `DeviceRosterKey`,
    /// for a caller that holds the key of the signer from another epoch.
    /// It checks no chain and no authority (`DEV-150` to `DEV-153`).
    pub fn verify_signature(&self, mldsa_pk: &[u8]) -> Result<(), Error> {
        self.verify_with(mldsa_pk)
    }

    /// Verifies epoch 0, the trust anchor, against its own device list
    /// (`DEV-155`, `DEV-156`).
    pub fn verify_genesis(&self) -> Result<(), Error> {
        if self.epoch != 0 {
            return Err(Error::Malformed);
        }

        let entry = self.entry(&self.signer_id).ok_or(Error::Unverified)?;
        self.verify_with(entry.mldsa_pk)
    }

    /// Verifies a successor against the previous epoch and its hash
    /// (`DEV-150` to `DEV-154`, `DEV-157`, `DEV-176`).
    pub fn verify_successor(
        &self,
        previous: &Roster<'_>,
        previous_hash: &[u8; 32],
    ) -> Result<(), Error> {
        if self.epoch != previous.epoch.saturating_add(1) || self.prev_hash != *previous_hash {
            return Err(Error::Unverified);
        }
        if previous.revoked.contains(&self.signer_id) {
            return Err(Error::Unverified);
        }
        if !previous.revoked.iter().all(|t| self.revoked.contains(t)) {
            return Err(Error::Unverified);
        }

        let entry = previous.entry(&self.signer_id).ok_or(Error::Unverified)?;
        self.verify_with(entry.mldsa_pk)
    }

    /// Verifies an epoch at the index of the head against the parent of the
    /// head, which the device keeps as [`Parent`] alone (`DEV-229`). A rival
    /// of the head verifies as the head did (`DEV-150` to `DEV-157`).
    pub fn verify_rival(&self, parent: &Parent) -> Result<(), Error> {
        if self.epoch != parent.epoch.saturating_add(1) || self.prev_hash != parent.hash {
            return Err(Error::Unverified);
        }
        if parent.revoked.contains(&self.signer_id)
            || !parent.revoked.iter().all(|t| self.revoked.contains(t))
        {
            return Err(Error::Unverified);
        }

        let (_, key) = parent
            .signers
            .iter()
            .find(|(device, _)| *device == self.signer_id)
            .ok_or(Error::Unverified)?;
        self.verify_with(key)
    }

    /// Whether the roster revokes `own`, which a device must not apply and
    /// must show (`DEV-180`, `DEV-181`).
    pub fn revokes(&self, own: &DeviceId) -> bool {
        self.revoked.contains(own)
    }
}

/// The part of the parent of the head that verifies a rival of the head:
/// its index, its hash, its tombstones, and the `DeviceRosterKey` of each
/// device. It carries no claim and no signature, thus it is no roster epoch
/// (`DEV-229`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    /// The index of the parent.
    pub epoch: u64,
    /// The SHA3-256 of the parent.
    pub hash: [u8; 32],
    /// The tombstones of the parent.
    pub revoked: Vec<DeviceId>,
    /// Each device of the parent and its `mldsa_pk`.
    pub signers: Vec<(DeviceId, Vec<u8>)>,
}

impl Parent {
    /// The parent data of the roster `bytes`.
    pub fn of(bytes: &[u8]) -> Result<Self, Error> {
        let roster = Roster::parse(bytes)?;
        Ok(Parent {
            epoch: roster.epoch,
            hash: Roster::hash(bytes),
            revoked: roster.revoked.clone(),
            signers: roster
                .devices
                .iter()
                .map(|d| (d.device_id, d.mldsa_pk.to_vec()))
                .collect(),
        })
    }

    /// The encoding for the store.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let len =
            8 + 32 + 2 + self.revoked.len() * 16 + self.signers.len() * (16 + VERIFYING_KEY_LEN);
        let mut out = alloc::vec![0u8; len];
        let mut w = Writer::new(&mut out);
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.hash)?;

        w.u8(u8::try_from(self.revoked.len()).map_err(|_| Error::Malformed)?)?;
        for t in &self.revoked {
            w.put(t)?;
        }

        w.u8(u8::try_from(self.signers.len()).map_err(|_| Error::Malformed)?)?;
        for (device, key) in &self.signers {
            if key.len() != VERIFYING_KEY_LEN {
                return Err(Error::Malformed);
            }
            w.put(device)?;
            w.put(key)?;
        }

        Ok(out)
    }

    /// Reads [`Parent::encode`].
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let epoch = u64::from_be_bytes(r.array()?);
        let hash = r.array()?;

        let mut revoked = Vec::new();
        for _ in 0..r.u8()? {
            revoked.push(r.array()?);
        }

        let mut signers = Vec::new();
        for _ in 0..r.u8()? {
            let device = r.array()?;
            signers.push((device, r.take(VERIFYING_KEY_LEN)?.to_vec()));
        }

        r.finish()?;
        Ok(Parent {
            epoch,
            hash,
            revoked,
            signers,
        })
    }
}

/// What two verified epochs at one index mean (`DEV-170`, `DEV-177`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Competing {
    /// One signer made two epochs: a fork the device shows and names, and
    /// it selects neither (`DEV-170`, `DEV-171`).
    Fork,
    /// Two signers raced: apply the epoch at `index`, and the other signer
    /// publishes its claims again (`DEV-179`).
    Select {
        /// The epoch that the order selects, 0 or 1.
        index: usize,
        /// The two `revoked` lists differ, thus the device shows the fork
        /// as well (`DEV-178`).
        fork: bool,
    },
}

/// Resolves two verified successors of one predecessor.
pub fn resolve(a: &Roster<'_>, b: &Roster<'_>) -> Result<Competing, Error> {
    if a.epoch != b.epoch || a.prev_hash != b.prev_hash {
        return Err(Error::Malformed);
    }
    if a.signer_id == b.signer_id {
        return Ok(Competing::Fork);
    }

    // DEV-178: the fork shows in each case but two equal lists.
    let fork =
        a.revoked.len() != b.revoked.len() || !a.revoked.iter().all(|t| b.revoked.contains(t));
    let index = if a.revoked.len() == b.revoked.len() {
        usize::from(b.signer_id < a.signer_id)
    } else {
        usize::from(b.revoked.len() > a.revoked.len())
    };

    Ok(Competing::Select { index, fork })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
pub(crate) mod tests {
    use super::*;
    use crate::directory::descriptor::tests::Rng;
    use umbra_crypto::sign::SigningKey;

    pub(crate) fn key(seed: u8) -> SigningKey {
        SigningKey::from_seed(Secret::new([seed; 32]))
    }

    pub(crate) fn entry<'a>(id: u8, pk: &'a [u8], kem: &'a [u8]) -> DeviceEntry<'a> {
        DeviceEntry {
            device_id: [id; 16],
            x25519_pk: [id; 32],
            mlkem_pk: kem,
            mldsa_pk: pk,
            label: [b'L'; 32],
            added_epoch: 0,
            sync_scope: SyncScope::Full,
        }
    }

    pub(crate) fn sign(
        roster: &mut Roster<'_>,
        signer: &SigningKey,
        sig_out: &mut [u8; SIGNATURE_LEN],
    ) {
        *sig_out = signer
            .sign(&roster.preimage().unwrap(), &mut Rng(1))
            .unwrap()
            .to_bytes();
    }

    #[test]
    fn the_retired_claim_scope_fails_to_parse() {
        assert!(ClaimScope::from_byte(0x02).is_err());
        assert_eq!(
            ClaimScope::from_byte(0x04).ok(),
            Some(ClaimScope::GroupSender)
        );
    }

    #[test]
    fn the_chain_verifies_and_a_revoked_signer_cannot_continue_it() {
        let k1 = key(1);
        let k2 = key(2);
        let pk1 = k1.verifying_key().to_bytes();
        let pk2 = k2.verifying_key().to_bytes();
        let kem = [9u8; 1_184];
        let sig0 = [0u8; SIGNATURE_LEN];
        let mut genesis = Roster {
            epoch: 0,
            devices: alloc::vec![entry(1, &pk1, &kem), entry(2, &pk2, &kem)],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: [0; 32],
            signer_id: [1; 16],
            sig: &sig0,
        };
        let mut s0 = [0u8; SIGNATURE_LEN];
        sign(&mut genesis, &k1, &mut s0);
        genesis.sig = &s0;
        let mut bytes0 = alloc::vec![0u8; genesis.len()];
        genesis.encode(&mut bytes0).unwrap();
        let g = Roster::parse(&bytes0).unwrap();
        g.verify_genesis().unwrap();
        assert_eq!(bytes0.len(), 60 + 2 * 3_225 + 3_309);
        let h0 = Roster::hash(&bytes0);

        // Epoch 1 by device 2 revokes device 1.
        let mut e1 = Roster {
            epoch: 1,
            devices: alloc::vec![entry(2, &pk2, &kem)],
            revoked: alloc::vec![[1; 16]],
            claims: alloc::vec![OwnerClaim {
                scope: ClaimScope::Pairwise,
                subject: [7; 32],
                owner: [2; 16],
            }],
            prev_hash: h0,
            signer_id: [2; 16],
            sig: &sig0,
        };
        let mut s1 = [0u8; SIGNATURE_LEN];
        sign(&mut e1, &k2, &mut s1);
        e1.sig = &s1;
        let mut bytes1 = alloc::vec![0u8; e1.len()];
        e1.encode(&mut bytes1).unwrap();
        let r1 = Roster::parse(&bytes1).unwrap();
        r1.verify_successor(&g, &h0).unwrap();

        // DEV-229: the parent data alone verifies a rival of the head.
        let parent = Parent::parse(&Parent::of(&bytes0).unwrap().encode().unwrap()).unwrap();
        assert_eq!(parent.hash, h0);
        r1.verify_rival(&parent).unwrap();
        let mut wrong = parent.clone();
        wrong.signers.retain(|(device, _)| *device != [2; 16]);
        assert!(r1.verify_rival(&wrong).is_err());

        assert!(r1.revokes(&[1; 16]));
        assert!(r1.verify_successor(&g, &[1; 32]).is_err());

        // Device 1, now revoked, cannot sign epoch 2 (DEV-153), and a
        // successor that drops the tombstone fails (DEV-157).
        let mut e2 = Roster {
            epoch: 2,
            devices: alloc::vec![entry(1, &pk1, &kem), entry(2, &pk2, &kem)],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: Roster::hash(&bytes1),
            signer_id: [1; 16],
            sig: &sig0,
        };
        let mut s2 = [0u8; SIGNATURE_LEN];
        sign(&mut e2, &k1, &mut s2);
        e2.sig = &s2;
        assert!(e2.verify_successor(&r1, &Roster::hash(&bytes1)).is_err());

        assert_eq!(
            OwnerClaim::subject(&Secret::new([1; 32]), ClaimScope::GroupSender, &[0; 32]).len(),
            32
        );
    }

    #[test]
    fn an_epoch_names_one_device_id_one_time_and_no_revoked_one() {
        let k1 = key(1);
        let pk1 = k1.verifying_key().to_bytes();
        let kem = [9u8; 1_184];
        let sig = [0u8; SIGNATURE_LEN];
        let base = Roster {
            epoch: 1,
            devices: alloc::vec![entry(1, &pk1, &kem), entry(2, &pk1, &kem)],
            revoked: alloc::vec![[3; 16]],
            claims: Vec::new(),
            prev_hash: [5; 32],
            signer_id: [1; 16],
            sig: &sig,
        };
        let mut out = alloc::vec![0u8; base.len() + ENTRY_LEN];
        base.encode(&mut out).unwrap();

        // DEV-224: two entries with one identifier.
        let twice = Roster {
            devices: alloc::vec![entry(1, &pk1, &kem), entry(1, &pk1, &kem)],
            ..base.clone()
        };
        assert_eq!(twice.encode(&mut out), Err(Error::Malformed));

        // DEV-157: a tombstone is permanent, thus no entry holds its id.
        let back = Roster {
            devices: alloc::vec![entry(1, &pk1, &kem), entry(3, &pk1, &kem)],
            ..base.clone()
        };
        assert_eq!(back.encode(&mut out), Err(Error::Malformed));

        // A parser rejects the same bytes: the second entry takes the
        // identifier of the first one.
        let used = base.encode(&mut out).unwrap();
        out[1 + 8 + 1 + ENTRY_LEN..][..16].copy_from_slice(&[1; 16]);
        assert_eq!(Roster::parse(&out[..used]).err(), Some(Error::Malformed));

        // The signature check alone reads no chain.
        let mut signed = base.clone();
        let mut made = [0u8; SIGNATURE_LEN];
        sign(&mut signed, &k1, &mut made);
        signed.sig = &made;
        signed.verify_signature(&pk1).unwrap();
        assert!(signed
            .verify_signature(&key(2).verifying_key().to_bytes())
            .is_err());
    }

    #[test]
    fn two_signers_at_one_index_resolve_and_one_signer_forks() {
        let kem = [9u8; 1_184];
        let pk = [1u8; VERIFYING_KEY_LEN];
        let sig = [0u8; SIGNATURE_LEN];
        let base = Roster {
            epoch: 3,
            devices: alloc::vec![entry(1, &pk, &kem)],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: [5; 32],
            signer_id: [1; 16],
            sig: &sig,
        };

        let by_two = Roster {
            signer_id: [2; 16],
            ..base.clone()
        };
        assert_eq!(
            resolve(&base, &by_two).unwrap(),
            Competing::Select {
                index: 0,
                fork: false
            }
        );

        let more_revoked = Roster {
            signer_id: [2; 16],
            revoked: alloc::vec![[3; 16]],
            ..base.clone()
        };
        // DEV-178: the order selects the revocation, and the fork shows.
        assert_eq!(
            resolve(&base, &more_revoked).unwrap(),
            Competing::Select {
                index: 1,
                fork: true
            }
        );

        let other_revoked = Roster {
            signer_id: [0; 16],
            revoked: alloc::vec![[4; 16]],
            ..base.clone()
        };
        assert_eq!(
            resolve(&more_revoked, &other_revoked).unwrap(),
            Competing::Select {
                index: 1,
                fork: true
            }
        );

        assert_eq!(resolve(&base, &base).unwrap(), Competing::Fork);
        let other_epoch = Roster {
            epoch: 4,
            ..base.clone()
        };
        assert!(resolve(&base, &other_epoch).is_err());
    }
}
