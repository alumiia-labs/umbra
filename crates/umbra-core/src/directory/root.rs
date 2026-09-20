//! The directory root of Part 10 §10.5.2 under its 5-of-7 multi-signature,
//! the key set and its rotation, and the client's consensus state with the
//! clock correction.

use alloc::vec::Vec;

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    AUTHORITY_COUNT, CLOCK_SKEW, CONSENSUS_VALIDITY, EPOCH_SECONDS, MEASURER_REVOKE_MAX,
    SIGNATURES_NEEDED,
};
use crate::Error;

/// One authority signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySig<'a> {
    /// The index in the key set.
    pub authority_index: u8,
    /// The ML-DSA-65 signature.
    pub sig: &'a [u8],
}

fn read_sigs<'a>(r: &mut Reader<'a>) -> Result<Vec<AuthoritySig<'a>>, Error> {
    let count = usize::from(r.u8()?);
    if !(SIGNATURES_NEEDED..=AUTHORITY_COUNT).contains(&count) {
        return Err(Error::Malformed);
    }
    let mut sigs = Vec::with_capacity(count);
    let mut last: Option<u8> = None;
    for _ in 0..count {
        let authority_index = r.u8()?;
        // REL-028 and REL-030: ascending, no repeat.
        if last.is_some_and(|l| l >= authority_index) {
            return Err(Error::Malformed);
        }
        last = Some(authority_index);
        sigs.push(AuthoritySig {
            authority_index,
            sig: r.take(SIGNATURE_LEN)?,
        });
    }
    Ok(sigs)
}

fn put_sigs(w: &mut Writer<'_>, sigs: &[AuthoritySig<'_>]) -> Result<(), Error> {
    w.u8(u8::try_from(sigs.len()).map_err(|_| Error::Malformed)?)?;
    for s in sigs {
        if s.sig.len() != SIGNATURE_LEN {
            return Err(Error::Malformed);
        }
        w.u8(s.authority_index)?;
        w.put(s.sig)?;
    }
    Ok(())
}

/// The authority key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryKeySet<'a> {
    /// Strictly increasing.
    pub keyset_epoch: u64,
    /// Authorities under different beneficial control.
    pub independent_count: u8,
    /// The seven ML-DSA-65 public keys.
    pub keys: Vec<&'a [u8]>,
}

impl<'a> DirectoryKeySet<'a> {
    /// The canonical encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.keyset_epoch.to_be_bytes())?;
        w.u8(u8::try_from(self.keys.len()).map_err(|_| Error::Malformed)?)?;
        w.u8(self.independent_count)?;
        for k in &self.keys {
            if k.len() != VERIFYING_KEY_LEN {
                return Err(Error::Malformed);
            }
            w.put(k)?;
        }
        Ok(w.position())
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        11usize.saturating_add(self.keys.len().saturating_mul(VERIFYING_KEY_LEN))
    }

    /// Whether the set holds no key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `keyset_hash`, over the canonical encoding alone (`REL-043`).
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        let mut buf = alloc::vec![0u8; self.len()];
        let n = self.encode(&mut buf)?;
        Ok(sha3_256(&[buf.get(..n).ok_or(Error::Malformed)?]))
    }

    /// Reads a key set from the front of `bytes` and returns the bytes it
    /// took.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let keyset_epoch = u64::from_be_bytes(r.array()?);
        let count = usize::from(r.u8()?);
        if count != AUTHORITY_COUNT {
            return Err(Error::Malformed);
        }
        let independent_count = r.u8()?;
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(r.take(VERIFYING_KEY_LEN)?);
        }
        Ok((
            DirectoryKeySet {
                keyset_epoch,
                independent_count,
                keys,
            },
            r.position(),
        ))
    }

    fn key(&self, index: u8) -> Result<VerifyingKey, Error> {
        let bytes = self.keys.get(usize::from(index)).ok_or(Error::Malformed)?;
        Ok(VerifyingKey::from_bytes(bytes)?)
    }

    /// Counts the valid signatures over `preimage` and fails below five
    /// (`REL-031`, `REL-032`).
    fn verify_multi(&self, preimage: &[u8], sigs: &[AuthoritySig<'_>]) -> Result<(), Error> {
        let mut valid = 0usize;
        for s in sigs {
            let key = self.key(s.authority_index)?;
            let sig = Signature::from_bytes(s.sig)?;
            if key.verify(preimage, &sig).is_ok() {
                valid = valid.saturating_add(1);
            }
        }
        if valid >= SIGNATURES_NEEDED {
            Ok(())
        } else {
            Err(Error::Unverified)
        }
    }

    /// Accepts a `SignedKeySet` as the successor of this set (`REL-036`,
    /// `REL-037`), and returns the new set.
    pub fn rotate(&self, signed: &'a [u8]) -> Result<DirectoryKeySet<'a>, Error> {
        let (next, used) = DirectoryKeySet::parse(signed)?;
        if next.keyset_epoch <= self.keyset_epoch {
            return Err(Error::Stale);
        }
        let mut r = Reader::new(signed.get(used..).ok_or(Error::Malformed)?);
        let sigs = read_sigs(&mut r)?;
        r.finish()?;
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(labels::DIRECTORY_KEYSET);
        preimage.push(0x01);
        preimage.extend_from_slice(&next.keyset_epoch.to_be_bytes());
        preimage.extend_from_slice(&next.hash()?);
        self.verify_multi(&preimage, &sigs)?;
        Ok(next)
    }
}

/// A directory root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryRoot<'a> {
    /// The consensus epoch.
    pub epoch: u64,
    /// `epoch × 3 600`.
    pub epoch_start_unix: u64,
    /// The Merkle root over the relay set.
    pub root: [u8; 32],
    /// SHA3-256 over the canonical key set.
    pub keyset_hash: [u8; 32],
    /// SHA3-256 over the canonical bloc list.
    pub bloc_hash: [u8; 32],
    /// The revoked measurer identifiers.
    pub revoked: Vec<[u8; 16]>,
    /// The signatures.
    pub sigs: Vec<AuthoritySig<'a>>,
}

impl<'a> DirectoryRoot<'a> {
    fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(labels::DIRECTORY_ROOT);
        out.push(0x01);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.epoch_start_unix.to_be_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.keyset_hash);
        out.extend_from_slice(&self.bloc_hash);
        out.push(u8::try_from(self.revoked.len()).unwrap_or(u8::MAX));
        for r in &self.revoked {
            out.extend_from_slice(r);
        }
        out
    }

    /// Writes the root.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.revoked.len() > MEASURER_REVOKE_MAX {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.epoch_start_unix.to_be_bytes())?;
        w.put(&self.root)?;
        w.put(&self.keyset_hash)?;
        w.put(&self.bloc_hash)?;
        w.u8(u8::try_from(self.revoked.len()).map_err(|_| Error::Malformed)?)?;
        for r in &self.revoked {
            w.put(r)?;
        }
        put_sigs(&mut w, &self.sigs)?;
        Ok(w.position())
    }

    /// Reads a root and applies the structural rules `REL-027` to
    /// `REL-030`, `REL-118`, and `REL-120`. The signatures are checked by
    /// [`Consensus::accept`].
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let epoch = u64::from_be_bytes(r.array()?);
        let epoch_start_unix = u64::from_be_bytes(r.array()?);
        if epoch_start_unix != epoch.saturating_mul(EPOCH_SECONDS) {
            return Err(Error::Malformed);
        }
        let root = r.array()?;
        let keyset_hash = r.array()?;
        let bloc_hash = r.array()?;
        let revoked_count = usize::from(r.u8()?);
        if revoked_count > MEASURER_REVOKE_MAX {
            return Err(Error::Malformed);
        }
        let mut revoked = Vec::with_capacity(revoked_count);
        for _ in 0..revoked_count {
            revoked.push(r.array()?);
        }
        let sigs = read_sigs(&mut r)?;
        r.finish()?;
        Ok(DirectoryRoot {
            epoch,
            epoch_start_unix,
            root,
            keyset_hash,
            bloc_hash,
            revoked,
            sigs,
        })
    }
}

/// The clock state of `REL-116`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockState {
    /// No correction yet.
    Unsynchronized,
    /// A correction at or below `CLOCK_SKEW`.
    Synchronized,
    /// A correction above `CLOCK_SKEW`, which the client shows.
    Corrected,
}

/// The consensus a client holds: the key set, the highest verified epoch,
/// the accepted root, and the clock correction.
pub struct Consensus<'a> {
    keyset: DirectoryKeySet<'a>,
    keyset_hash: [u8; 32],
    highest_epoch: u64,
    accepted: Option<DirectoryRoot<'a>>,
    correction: Option<i64>,
}

impl<'a> Consensus<'a> {
    /// Starts from the shipped key set and the shipped epoch of `REL-045`.
    pub fn new(keyset: DirectoryKeySet<'a>, shipped_epoch: u64) -> Result<Self, Error> {
        let keyset_hash = keyset.hash()?;
        Ok(Consensus {
            keyset,
            keyset_hash,
            highest_epoch: shipped_epoch,
            accepted: None,
            correction: None,
        })
    }

    /// The key set held.
    pub fn keyset(&self) -> &DirectoryKeySet<'a> {
        &self.keyset
    }

    /// The accepted root, if any.
    pub fn accepted(&self) -> Option<&DirectoryRoot<'a>> {
        self.accepted.as_ref()
    }

    /// The client clock: the device clock plus the correction (§10.5.2).
    pub fn client_clock(&self, device_clock: u64) -> Option<u64> {
        let c = self.correction?;
        Some(if c >= 0 {
            device_clock.saturating_add(c.unsigned_abs())
        } else {
            device_clock.saturating_sub(c.unsigned_abs())
        })
    }

    /// The clock state.
    pub fn clock_state(&self) -> ClockState {
        match self.correction {
            None => ClockState::Unsynchronized,
            Some(c) if c.unsigned_abs() <= CLOCK_SKEW => ClockState::Synchronized,
            Some(_) => ClockState::Corrected,
        }
    }

    /// A clock movement of Part 1 §1.9 discards the correction (`REL-115`).
    pub fn clock_moved(&mut self) {
        self.correction = None;
    }

    /// Rotates the key set from a `SignedKeySet`.
    pub fn rotate_keys(&mut self, signed: &'a [u8]) -> Result<(), Error> {
        let next = self.keyset.rotate(signed)?;
        self.keyset_hash = next.hash()?;
        self.keyset = next;
        Ok(())
    }

    /// Accepts a root under the rules of §10.5.2 at the device clock
    /// `device_clock`, and records or refreshes the correction.
    pub fn accept(&mut self, root: DirectoryRoot<'a>, device_clock: u64) -> Result<(), Error> {
        self.verify(&root, device_clock)?;
        self.commit(root, device_clock);
        Ok(())
    }

    /// Tests a root under the rules of §10.5.2, and changes nothing. A caller
    /// that must verify more under the root does that between this test and
    /// `commit`.
    pub fn verify(&self, root: &DirectoryRoot<'_>, device_clock: u64) -> Result<(), Error> {
        if root.keyset_hash != self.keyset_hash {
            return Err(Error::Unverified);
        }
        if root.epoch < self.highest_epoch
            || (self.accepted.is_some() && root.epoch == self.highest_epoch)
        {
            return Err(Error::Stale);
        }
        self.keyset.verify_multi(&root.preimage(), &root.sigs)?;
        // REL-035: not older than the validity plus the skew.
        let is_stale = self.client_clock(device_clock).is_some_and(|clock| {
            clock.saturating_sub(root.epoch_start_unix)
                > CONSENSUS_VALIDITY.saturating_add(CLOCK_SKEW)
        });
        if is_stale {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Takes a root that `verify` passed, and records or refreshes the
    /// correction.
    pub(crate) fn commit(&mut self, root: DirectoryRoot<'a>, device_clock: u64) {
        // REL-044: a root further ahead than the skew gives a new correction.
        let is_ahead = self
            .client_clock(device_clock)
            .is_none_or(|clock| root.epoch_start_unix.saturating_sub(clock) > CLOCK_SKEW);
        if is_ahead {
            self.correction = Some(correction(root.epoch_start_unix, device_clock));
        }
        self.highest_epoch = root.epoch;
        self.accepted = Some(root);
    }
}

fn correction(root_start: u64, device_clock: u64) -> i64 {
    i64::try_from(root_start).unwrap_or(i64::MAX) - i64::try_from(device_clock).unwrap_or(i64::MAX)
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
    use umbra_crypto::{secret::Secret, sign::SigningKey};

    pub(crate) fn authorities(seed: u8) -> Vec<SigningKey> {
        (0..7u8)
            .map(|i| SigningKey::from_seed(Secret::new([seed + i; 32])))
            .collect()
    }

    pub(crate) fn keyset_of(
        keys: &[SigningKey],
        epoch: u64,
    ) -> (Vec<[u8; VERIFYING_KEY_LEN]>, u64) {
        (
            keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
            epoch,
        )
    }

    fn keyset<'a>(pks: &'a [[u8; VERIFYING_KEY_LEN]], epoch: u64) -> DirectoryKeySet<'a> {
        DirectoryKeySet {
            keyset_epoch: epoch,
            independent_count: 7,
            keys: pks.iter().map(|k| &k[..]).collect(),
        }
    }

    pub(crate) fn signed_root(
        keys: &[SigningKey],
        signers: &[u8],
        epoch: u64,
        keyset_hash: [u8; 32],
        merkle_root: [u8; 32],
    ) -> Vec<u8> {
        let mut root = DirectoryRoot {
            epoch,
            epoch_start_unix: epoch * 3_600,
            root: merkle_root,
            keyset_hash,
            bloc_hash: crate::directory::bloc::BlocList::v1().hash().unwrap(),
            revoked: Vec::new(),
            sigs: Vec::new(),
        };
        let preimage = root.preimage();
        let sigs: Vec<(u8, [u8; SIGNATURE_LEN])> = signers
            .iter()
            .map(|i| {
                (
                    *i,
                    keys[usize::from(*i)]
                        .sign(&preimage, &mut Rng(*i))
                        .unwrap()
                        .to_bytes(),
                )
            })
            .collect();
        root.sigs = sigs
            .iter()
            .map(|(i, s)| AuthoritySig {
                authority_index: *i,
                sig: &s[..],
            })
            .collect();
        let mut out = alloc::vec![0u8; 24_000];
        let n = root.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn a_root_needs_five_valid_signatures_and_a_rising_epoch() {
        let keys = authorities(10);
        let (pks, _) = keyset_of(&keys, 1);
        let set = keyset(&pks, 1);
        let hash = set.hash().unwrap();
        let mut consensus = Consensus::new(set, 100).unwrap();

        let bytes = signed_root(&keys, &[0, 1, 2, 3, 4], 101, hash, [9; 32]);
        assert_eq!(bytes.len(), 16_665);
        let root = DirectoryRoot::parse(&bytes).unwrap();
        consensus.accept(root, 101 * 3_600 + 5).unwrap();
        assert_eq!(consensus.clock_state(), ClockState::Synchronized);

        // Four valid and one forged: rejected (REL-032).
        let mut forged = signed_root(&keys, &[0, 1, 2, 3, 4], 102, hash, [9; 32]);
        forged[200] ^= 1;
        assert!(consensus
            .accept(DirectoryRoot::parse(&forged).unwrap(), 0)
            .is_err());
        // The same epoch again is stale (REL-034), and the shipped floor holds (REL-046).
        let again = signed_root(&keys, &[0, 1, 2, 3, 4], 101, hash, [9; 32]);
        assert_eq!(
            consensus.accept(DirectoryRoot::parse(&again).unwrap(), 0),
            Err(Error::Stale)
        );
        let old = signed_root(&keys, &[0, 1, 2, 3, 4], 99, hash, [9; 32]);
        assert_eq!(
            consensus.accept(DirectoryRoot::parse(&old).unwrap(), 0),
            Err(Error::Stale)
        );
        // A root that is too old for the client clock is stale (REL-035).
        let fresh = signed_root(&keys, &[1, 2, 3, 4, 5, 6], 110, hash, [9; 32]);
        assert_eq!(fresh.len(), 16_665 + 3_310);
        let far_future_clock = 110 * 3_600 + CONSENSUS_VALIDITY + CLOCK_SKEW + 20;
        assert_eq!(
            consensus.accept(DirectoryRoot::parse(&fresh).unwrap(), far_future_clock),
            Err(Error::Stale)
        );
        // A root ahead of the clock by more than the skew corrects the clock (REL-044).
        consensus
            .accept(DirectoryRoot::parse(&fresh).unwrap(), 101 * 3_600 + 5)
            .unwrap();
        assert_eq!(consensus.clock_state(), ClockState::Corrected);
        assert_eq!(
            consensus.client_clock(0),
            Some(110 * 3_600 - 101 * 3_600 - 5)
        );
        consensus.clock_moved();
        assert_eq!(consensus.clock_state(), ClockState::Unsynchronized);
    }

    #[test]
    fn the_structural_rules_and_the_rotation_hold() {
        let keys = authorities(10);
        let (pks, _) = keyset_of(&keys, 1);
        let set = keyset(&pks, 1);
        let hash = set.hash().unwrap();
        let bytes = signed_root(&keys, &[0, 1, 2, 3, 4], 5, hash, [9; 32]);
        // Four signatures, out of order, repeated, and a wrong epoch start.
        let mut four = bytes.clone();
        four[1 + 8 + 8 + 96 + 1] = 4;
        assert!(DirectoryRoot::parse(&four[..four.len() - 3_310]).is_err());
        let mut swapped = bytes.clone();
        swapped[1 + 8 + 8 + 96 + 1 + 1] = 1;
        swapped[1 + 8 + 8 + 96 + 1 + 1 + 3_310] = 0;
        assert!(DirectoryRoot::parse(&swapped).is_err());
        let mut start = bytes.clone();
        start[16] ^= 1;
        assert!(DirectoryRoot::parse(&start).is_err());

        // A rotation under five of the previous keys.
        let next_keys = authorities(50);
        let (next_pks, _) = keyset_of(&next_keys, 2);
        let next = keyset(&next_pks, 2);
        let mut signed = alloc::vec![0u8; 40_000];
        let n = next.encode(&mut signed).unwrap();
        let mut preimage = Vec::new();
        preimage.extend_from_slice(labels::DIRECTORY_KEYSET);
        preimage.push(0x01);
        preimage.extend_from_slice(&2u64.to_be_bytes());
        preimage.extend_from_slice(&next.hash().unwrap());
        let sigs: Vec<[u8; SIGNATURE_LEN]> = (0..5u8)
            .map(|i| {
                keys[usize::from(i)]
                    .sign(&preimage, &mut Rng(i))
                    .unwrap()
                    .to_bytes()
            })
            .collect();
        let mut w = Writer::new(&mut signed[n..]);
        w.u8(5).unwrap();
        for (i, s) in sigs.iter().enumerate() {
            w.u8(i as u8).unwrap();
            w.put(s).unwrap();
        }
        let total = n + w.position();
        let mut consensus = Consensus::new(set, 0).unwrap();
        consensus.rotate_keys(&signed[..total]).unwrap();
        assert_eq!(consensus.keyset().keyset_epoch, 2);
        // The same rotation again is stale (REL-037).
        assert_eq!(consensus.rotate_keys(&signed[..total]), Err(Error::Stale));
    }
}
