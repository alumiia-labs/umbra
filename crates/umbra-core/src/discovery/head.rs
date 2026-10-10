//! The signed tree head of Part 9 §9.5.2, its log key set, and the client
//! rules over both: the 2-of-3 acceptance, the freshness and the skew, the
//! rollback bound, the retention, the key-set rotation, the degraded read,
//! and the gossip of §9.5.3.

use alloc::vec::Vec;

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::{
    app::keys::{DigestBody, DigestSource},
    codec::{Reader, Writer},
};

use super::{
    GOSSIP_INTERVAL, SIGNATURES_NEEDED, SIGNER_COUNT, TREE_HEAD_FRESHNESS, TREE_HEAD_RETAIN,
};
use crate::{directory::CLOCK_SKEW, Error};

/// The fixed part of a `SignedTreeHead`, before `sigs`.
pub const HEAD_FIXED: usize = 1 + 8 + 8 + 32 + 32 + 1;
/// One `SignerSig`.
pub const SIGNER_SIG_LEN: usize = 1 + SIGNATURE_LEN;
/// A `LogKeySet`.
pub const KEYSET_LEN: usize = 1 + 8 + 1 + SIGNER_COUNT * VERIFYING_KEY_LEN;

/// One signer's signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerSig<'a> {
    /// The index in the key set.
    pub signer_index: u8,
    /// The ML-DSA-65 signature.
    pub sig: &'a [u8],
}

fn parse_sigs<'a>(r: &mut Reader<'a>) -> Result<Vec<SignerSig<'a>>, Error> {
    let count = usize::from(r.u8()?);
    if !(SIGNATURES_NEEDED..=SIGNER_COUNT).contains(&count) {
        return Err(Error::Malformed);
    }
    let mut sigs = Vec::with_capacity(count);
    let mut last: Option<u8> = None;
    for _ in 0..count {
        let signer_index = r.u8()?;
        // Ascending order rejects a repeat as well (DIS-055, DIS-057).
        if last.is_some_and(|l| signer_index <= l) || usize::from(signer_index) >= SIGNER_COUNT {
            return Err(Error::Malformed);
        }
        last = Some(signer_index);
        sigs.push(SignerSig {
            signer_index,
            sig: r.take(SIGNATURE_LEN)?,
        });
    }
    Ok(sigs)
}

fn write_sigs(w: &mut Writer<'_>, sigs: &[SignerSig<'_>]) -> Result<(), Error> {
    w.u8(u8::try_from(sigs.len()).map_err(|_| Error::Malformed)?)?;
    for s in sigs {
        if s.sig.len() != SIGNATURE_LEN {
            return Err(Error::Malformed);
        }
        w.u8(s.signer_index)?;
        w.put(s.sig)?;
    }
    Ok(())
}

/// The key set of the three signers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogKeySet<'a> {
    /// Strictly increasing.
    pub keyset_epoch: u64,
    /// The ML-DSA-65 public keys, at signer indexes 0, 1, and 2.
    pub keys: Vec<&'a [u8]>,
}

impl<'a> LogKeySet<'a> {
    /// Writes the canonical set.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.keys.len() != SIGNER_COUNT {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.keyset_epoch.to_be_bytes())?;
        w.u8(u8::try_from(SIGNER_COUNT).map_err(|_| Error::Malformed)?)?;
        for key in &self.keys {
            if key.len() != VERIFYING_KEY_LEN {
                return Err(Error::Malformed);
            }
            w.put(key)?;
        }
        Ok(w.position())
    }

    /// Reads a set and returns the bytes used.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let keyset_epoch = u64::from_be_bytes(r.array()?);
        if usize::from(r.u8()?) != SIGNER_COUNT {
            return Err(Error::Malformed);
        }
        let mut keys = Vec::with_capacity(SIGNER_COUNT);
        for _ in 0..SIGNER_COUNT {
            keys.push(r.take(VERIFYING_KEY_LEN)?);
        }
        Ok((LogKeySet { keyset_epoch, keys }, r.position()))
    }

    /// `SHA3-256` over the canonical set (`DIS-046`).
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        let mut bytes = [0u8; KEYSET_LEN];
        let n = self.encode(&mut bytes)?;
        Ok(sha3_256(&[bytes.get(..n).ok_or(Error::Malformed)?]))
    }

    fn key(&self, index: u8) -> Result<VerifyingKey, Error> {
        let bytes = self.keys.get(usize::from(index)).ok_or(Error::Malformed)?;
        Ok(VerifyingKey::from_bytes(bytes)?)
    }

    /// Counts the valid signatures over `preimage` and fails below two
    /// (`DIS-058`, `DIS-059`).
    fn verify_multi(&self, preimage: &[u8], sigs: &[SignerSig<'_>]) -> Result<(), Error> {
        let mut valid = 0usize;
        for s in sigs {
            let key = self.key(s.signer_index)?;
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

    /// The preimage that the previous set signs for this set
    /// (`DIS-064`).
    pub fn rotation_preimage(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(labels::TREE_HEAD_KEYSET.len() + 1 + 8 + 32);
        out.extend_from_slice(labels::TREE_HEAD_KEYSET);
        out.push(0x01);
        out.extend_from_slice(&self.keyset_epoch.to_be_bytes());
        out.extend_from_slice(&self.hash()?);
        Ok(out)
    }

    /// Accepts a `SignedLogKeySet` as the successor of this set
    /// (`DIS-064`, `DIS-065`).
    pub fn rotate(&self, signed: &'a [u8]) -> Result<LogKeySet<'a>, Error> {
        let (next, used) = LogKeySet::parse(signed)?;
        if next.keyset_epoch <= self.keyset_epoch {
            return Err(Error::Stale);
        }
        let mut r = Reader::new(signed.get(used..).ok_or(Error::Malformed)?);
        let sigs = parse_sigs(&mut r)?;
        r.finish()?;
        self.verify_multi(&next.rotation_preimage()?, &sigs)?;
        Ok(next)
    }
}

/// A signed tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead<'a> {
    /// The epoch of the log, which is its leaf count.
    pub tree_size: u64,
    /// Unix seconds, set by the log operator.
    pub timestamp: u64,
    /// The root hash of the log tree.
    pub root: [u8; 32],
    /// `SHA3-256` over the canonical `LogKeySet`.
    pub keyset_hash: [u8; 32],
    /// The signatures, in ascending signer index.
    pub sigs: Vec<SignerSig<'a>>,
}

impl<'a> SignedTreeHead<'a> {
    /// Writes the head.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.tree_size.to_be_bytes())?;
        w.put(&self.timestamp.to_be_bytes())?;
        w.put(&self.root)?;
        w.put(&self.keyset_hash)?;
        write_sigs(&mut w, &self.sigs)?;
        Ok(w.position())
    }

    /// Reads a head (`DIS-054`, `DIS-055`, `DIS-057`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let tree_size = u64::from_be_bytes(r.array()?);
        let timestamp = u64::from_be_bytes(r.array()?);
        let root = r.array()?;
        let keyset_hash = r.array()?;
        let sigs = parse_sigs(&mut r)?;
        r.finish()?;
        Ok(SignedTreeHead {
            tree_size,
            timestamp,
            root,
            keyset_hash,
            sigs,
        })
    }

    /// The signed preimage: the label and the fields before `sig_count`.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(labels::TREE_HEAD.len() + HEAD_FIXED);
        out.extend_from_slice(labels::TREE_HEAD);
        out.push(0x01);
        out.extend_from_slice(&self.tree_size.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.keyset_hash);
        out
    }
}

/// A head the client accepted, with its acceptance time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedHead {
    /// The tree size.
    pub tree_size: u64,
    /// The root.
    pub root: [u8; 32],
    /// The timestamp of the head.
    pub timestamp: u64,
    /// The local acceptance time.
    pub accepted_at: u64,
}

/// What a client holds about the log.
pub struct HeadState<'a> {
    keyset: LogKeySet<'a>,
    keyset_hash: [u8; 32],
    highest_tree_size: u64,
    retained: Vec<AcceptedHead>,
}

impl<'a> HeadState<'a> {
    /// Starts from the shipped key set (`DIS-066`).
    pub fn new(keyset: LogKeySet<'a>) -> Result<Self, Error> {
        let keyset_hash = keyset.hash()?;
        Ok(HeadState {
            keyset,
            keyset_hash,
            highest_tree_size: 0,
            retained: Vec::new(),
        })
    }

    /// The key set held.
    pub const fn keyset(&self) -> &LogKeySet<'a> {
        &self.keyset
    }

    /// Rotates to a signed successor set.
    pub fn rotate_keys(&mut self, signed: &'a [u8]) -> Result<(), Error> {
        let next = self.keyset.rotate(signed)?;
        self.keyset_hash = next.hash()?;
        self.keyset = next;
        Ok(())
    }

    /// Accepts a head under rules 5 to 12 of §9.5.2, at `device_clock`.
    pub fn accept(&mut self, head: &SignedTreeHead<'_>, device_clock: u64) -> Result<(), Error> {
        if head.keyset_hash != self.keyset_hash {
            return Err(Error::Unverified);
        }
        self.keyset.verify_multi(&head.preimage(), &head.sigs)?;
        if head.tree_size < self.highest_tree_size {
            return Err(Error::Stale);
        }
        // DIS-160: a second root at a retained size is a split view, and
        // the two heads are the evidence of `DIS-051`.
        let held = self
            .retained
            .iter()
            .position(|h| h.tree_size == head.tree_size);
        if held
            .and_then(|at| self.retained.get(at))
            .is_some_and(|h| h.root != head.root)
        {
            return Err(Error::Unverified);
        }
        if head
            .timestamp
            .saturating_add(TREE_HEAD_FRESHNESS + CLOCK_SKEW)
            < device_clock
        {
            return Err(Error::Stale);
        }
        if head.timestamp > device_clock.saturating_add(CLOCK_SKEW) {
            return Err(Error::Stale);
        }
        self.highest_tree_size = head.tree_size;
        let accepted = AcceptedHead {
            tree_size: head.tree_size,
            root: head.root,
            timestamp: head.timestamp,
            accepted_at: device_clock,
        };
        // One row for each size: the same head again takes the place of
        // its row, and `DIS-063` then counts from the later acceptance.
        match held.and_then(|at| self.retained.get_mut(at)) {
            Some(row) => *row = accepted,
            None => self.retained.push(accepted),
        }
        Ok(())
    }

    /// Accepts a head that extends the newest retained head. The
    /// consistency proof shows that the log only grew, and a second root at
    /// one `tree_size` is the evidence of `DIS-051`. A client with no
    /// retained head has nothing to compare, and it accepts under
    /// [`HeadState::accept`] alone.
    pub fn accept_extending(
        &mut self,
        head: &SignedTreeHead<'_>,
        consistency: &[[u8; 32]],
        device_clock: u64,
    ) -> Result<(), Error> {
        if let Some(held) = self.newest() {
            super::logtree::verify_consistency(
                held.tree_size,
                &held.root,
                head.tree_size,
                &head.root,
                consistency,
            )?;
        }
        self.accept(head, device_clock)
    }

    /// Drops each head past `TREE_HEAD_RETAIN` (`DIS-063`).
    pub fn retain(&mut self, now: u64) {
        self.retained
            .retain(|h| now.saturating_sub(h.accepted_at) < TREE_HEAD_RETAIN);
    }

    /// The newest head accepted, if any is retained.
    pub fn newest(&self) -> Option<&AcceptedHead> {
        self.retained.iter().max_by_key(|h| h.tree_size)
    }

    /// Whether the client is in the degraded read: no retained head passes
    /// the freshness rule at `device_clock` (§9.5.2).
    pub fn degraded(&self, device_clock: u64) -> bool {
        !self
            .retained
            .iter()
            .any(|h| h.timestamp.saturating_add(TREE_HEAD_FRESHNESS + CLOCK_SKEW) >= device_clock)
    }

    /// The head retained at `tree_size`.
    pub fn at(&self, tree_size: u64) -> Option<&AcceptedHead> {
        self.retained.iter().find(|h| h.tree_size == tree_size)
    }

    /// The digest to gossip: the newest accepted head (`DIS-072`).
    pub fn digest(&self) -> Option<DigestBody> {
        self.newest().map(|h| DigestBody {
            source: DigestSource::TreeHead,
            epoch: h.tree_size,
            digest: h.root,
        })
    }

    /// Compares a received digest against the head at that epoch
    /// (`DIS-033`, `DIS-034`, `DIS-136`, `DIS-071`).
    pub fn compare(&self, digest: &DigestBody, device_clock: u64) -> Verdict {
        if digest.source != DigestSource::TreeHead {
            return Verdict::NotOurs;
        }
        if self.degraded(device_clock) {
            return Verdict::Degraded;
        }
        match self.at(digest.epoch) {
            Some(h) if h.root == digest.digest => Verdict::Match,
            Some(_) => Verdict::SplitView,
            None => Verdict::FetchHead,
        }
    }
}

/// The outcome of a digest comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The two roots agree.
    Match,
    /// The two roots differ: show the split-view warning.
    SplitView,
    /// No head at that epoch is held: fetch the co-signed head first.
    FetchHead,
    /// The client is in the degraded read and shows no warning.
    Degraded,
    /// The digest names another source.
    NotOurs,
}

/// The gossip limiter: at most one digest for each source in each
/// `GOSSIP_INTERVAL` (`DIS-028`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gossip {
    last: [Option<u64>; 3],
}

impl Gossip {
    fn slot(source: DigestSource) -> usize {
        match source {
            DigestSource::TreeHead => 0,
            DigestSource::ConsensusRoot => 1,
            DigestSource::ReleaseLog => 2,
        }
    }

    /// Whether a digest of `source` may go in the cover slot at `now`, and
    /// records it if so.
    pub fn allow(&mut self, source: DigestSource, now: u64) -> bool {
        let slot = self.last.get_mut(Self::slot(source));
        match slot {
            Some(last) => {
                if last.is_some_and(|l| now.saturating_sub(l) < GOSSIP_INTERVAL) {
                    return false;
                }
                *last = Some(now);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use umbra_crypto::{secret::Secret, sign::SigningKey};

    struct Rng(u64);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            Ok((self.0 >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?) << 32 | u64::from(self.try_next_u32()?))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for b in dest {
                *b = self.try_next_u32()? as u8;
            }
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    fn signers(seed: u8) -> Vec<SigningKey> {
        (0..SIGNER_COUNT as u8)
            .map(|i| SigningKey::from_seed(Secret::new([seed.wrapping_add(i); 32])))
            .collect()
    }

    fn keyset_bytes(keys: &[SigningKey], epoch: u64) -> Vec<u8> {
        let pks: Vec<[u8; VERIFYING_KEY_LEN]> =
            keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let set = LogKeySet {
            keyset_epoch: epoch,
            keys: pks.iter().map(|p| &p[..]).collect(),
        };
        let mut out = alloc::vec![0u8; KEYSET_LEN];
        let n = set.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    fn signed_head(
        keys: &[SigningKey],
        which: &[u8],
        tree_size: u64,
        timestamp: u64,
        keyset_hash: [u8; 32],
    ) -> Vec<u8> {
        let root = [tree_size as u8; 32];
        signed_head_over(keys, which, tree_size, timestamp, keyset_hash, root)
    }

    fn signed_head_over(
        keys: &[SigningKey],
        which: &[u8],
        tree_size: u64,
        timestamp: u64,
        keyset_hash: [u8; 32],
        root: [u8; 32],
    ) -> Vec<u8> {
        let mut rng = Rng(1);
        let head = SignedTreeHead {
            tree_size,
            timestamp,
            root,
            keyset_hash,
            sigs: Vec::new(),
        };
        let preimage = head.preimage();
        let sigs: Vec<[u8; SIGNATURE_LEN]> = which
            .iter()
            .map(|&i| {
                keys[i as usize]
                    .sign(&preimage, &mut rng)
                    .unwrap()
                    .to_bytes()
            })
            .collect();
        let head = SignedTreeHead {
            sigs: which
                .iter()
                .zip(&sigs)
                .map(|(&i, s)| SignerSig {
                    signer_index: i,
                    sig: &s[..],
                })
                .collect(),
            ..head
        };
        let mut out = alloc::vec![0u8; HEAD_FIXED + 3 * SIGNER_SIG_LEN];
        let n = head.encode(&mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn a_second_root_at_one_size_is_refused_and_a_repeat_keeps_one_row() {
        let keys = signers(1);
        let ks_bytes = keyset_bytes(&keys, 1);
        let (keyset, _) = LogKeySet::parse(&ks_bytes).unwrap();
        let hash = keyset.hash().unwrap();
        let mut state = HeadState::new(keyset).unwrap();
        let clock = 1_000_000u64;
        let head = signed_head(&keys, &[0, 1], 10, clock - 100, hash);
        let head = SignedTreeHead::parse(&head).unwrap();
        state.accept(&head, clock).unwrap();
        // The state accepts the same head again, and it adds no row.
        state.accept(&head, clock + 5).unwrap();
        assert_eq!(state.retained.len(), 1);
        assert_eq!(state.at(10).unwrap().accepted_at, clock + 5);
        // DIS-160: two signers sign another root at that size.
        let split = signed_head_over(&keys, &[1, 2], 10, clock - 50, hash, [0xEE; 32]);
        assert_eq!(
            state.accept(&SignedTreeHead::parse(&split).unwrap(), clock + 6),
            Err(Error::Unverified)
        );
        assert_eq!(state.at(10).unwrap().root, [10; 32]);
    }

    #[test]
    fn a_head_needs_two_of_three_and_the_bounds_hold() {
        let keys = signers(1);
        let ks_bytes = keyset_bytes(&keys, 1);
        let (keyset, _) = LogKeySet::parse(&ks_bytes).unwrap();
        let hash = keyset.hash().unwrap();
        let mut state = HeadState::new(keyset).unwrap();
        let clock = 1_000_000u64;

        let two = signed_head(&keys, &[0, 2], 10, clock - 100, hash);
        state
            .accept(&SignedTreeHead::parse(&two).unwrap(), clock)
            .unwrap();
        assert_eq!(state.newest().unwrap().tree_size, 10);
        assert!(!state.degraded(clock));

        // One valid signer with a forged second fails; a wrong key set hash
        // fails; a rollback fails; a stale timestamp and a future one fail.
        let other = signers(9);
        let mixed = {
            let mut bytes = signed_head(&keys, &[0, 1], 11, clock, hash);
            let forged = signed_head(&other, &[0, 1], 11, clock, hash);
            bytes[HEAD_FIXED + SIGNER_SIG_LEN..]
                .copy_from_slice(&forged[HEAD_FIXED + SIGNER_SIG_LEN..]);
            bytes
        };
        assert_eq!(
            state.accept(&SignedTreeHead::parse(&mixed).unwrap(), clock),
            Err(Error::Unverified)
        );
        let wrong_set = signed_head(&keys, &[0, 1], 11, clock, [0; 32]);
        assert_eq!(
            state.accept(&SignedTreeHead::parse(&wrong_set).unwrap(), clock),
            Err(Error::Unverified)
        );
        let rollback = signed_head(&keys, &[0, 1], 9, clock, hash);
        assert_eq!(
            state.accept(&SignedTreeHead::parse(&rollback).unwrap(), clock),
            Err(Error::Stale)
        );
        let old = signed_head(
            &keys,
            &[1, 2],
            12,
            clock - TREE_HEAD_FRESHNESS - CLOCK_SKEW - 1,
            hash,
        );
        assert_eq!(
            state.accept(&SignedTreeHead::parse(&old).unwrap(), clock),
            Err(Error::Stale)
        );
        let future = signed_head(&keys, &[1, 2], 12, clock + CLOCK_SKEW + 1, hash);
        assert_eq!(
            state.accept(&SignedTreeHead::parse(&future).unwrap(), clock),
            Err(Error::Stale)
        );

        // The parser rejects one signature, a repeat, and a descending order.
        let mut one = signed_head(&keys, &[0, 1], 12, clock, hash);
        one[HEAD_FIXED - 1] = 1;
        one.truncate(HEAD_FIXED + SIGNER_SIG_LEN);
        assert!(SignedTreeHead::parse(&one).is_err());
        let mut repeat = signed_head(&keys, &[0, 1], 12, clock, hash);
        repeat[HEAD_FIXED + SIGNER_SIG_LEN] = 0;
        assert!(SignedTreeHead::parse(&repeat).is_err());
        let mut descending = signed_head(&keys, &[0, 1], 12, clock, hash);
        descending[HEAD_FIXED] = 1;
        descending[HEAD_FIXED + SIGNER_SIG_LEN] = 0;
        assert!(SignedTreeHead::parse(&descending).is_err());

        // Gossip, retention, and the degraded read.
        let digest = state.digest().unwrap();
        assert_eq!(digest.epoch, 10);
        assert_eq!(state.compare(&digest, clock), Verdict::Match);
        let split = DigestBody {
            digest: [1; 32],
            ..digest
        };
        assert_eq!(state.compare(&split, clock), Verdict::SplitView);
        let unknown = DigestBody { epoch: 4, ..digest };
        assert_eq!(state.compare(&unknown, clock), Verdict::FetchHead);
        let later = clock + TREE_HEAD_RETAIN;
        assert!(state.degraded(later));
        assert_eq!(state.compare(&digest, later), Verdict::Degraded);
        state.retain(later);
        assert!(state.newest().is_none());

        let mut gossip = Gossip::default();
        assert!(gossip.allow(DigestSource::TreeHead, 0));
        assert!(!gossip.allow(DigestSource::TreeHead, GOSSIP_INTERVAL - 1));
        assert!(gossip.allow(DigestSource::ConsensusRoot, 1));
        assert!(gossip.allow(DigestSource::TreeHead, GOSSIP_INTERVAL));
    }

    #[test]
    fn a_key_set_rotates_under_two_signatures_of_the_previous_set() {
        let keys = signers(1);
        let next_keys = signers(20);
        let ks_bytes = keyset_bytes(&keys, 1);
        let (keyset, _) = LogKeySet::parse(&ks_bytes).unwrap();
        let mut state = HeadState::new(keyset).unwrap();
        let mut rng = Rng(3);
        let make = |epoch: u64, which: &[u8], signers: &[SigningKey]| {
            let next_bytes = keyset_bytes(&next_keys, epoch);
            let (next, _) = LogKeySet::parse(&next_bytes).unwrap();
            let preimage = next.rotation_preimage().unwrap();
            let mut out = next_bytes.clone();
            out.push(which.len() as u8);
            for &i in which {
                out.push(i);
                out.extend_from_slice(
                    &signers[i as usize]
                        .sign(&preimage, &mut Rng(5))
                        .unwrap()
                        .to_bytes(),
                );
            }
            out
        };
        let _ = &mut rng;
        let same_epoch = make(1, &[0, 1], &keys);
        assert_eq!(state.rotate_keys(&same_epoch), Err(Error::Stale));
        let self_signed = make(2, &[0, 1], &next_keys);
        assert_eq!(state.rotate_keys(&self_signed), Err(Error::Unverified));
        let good = make(2, &[1, 2], &keys);
        state.rotate_keys(&good).unwrap();
        assert_eq!(state.keyset().keyset_epoch, 2);
        assert_eq!(
            state.keyset().keys[0],
            &next_keys[0].verifying_key().to_bytes()[..]
        );
    }
}
