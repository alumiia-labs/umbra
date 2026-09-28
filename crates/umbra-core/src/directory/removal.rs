//! The removed link of Part 10 §10.4.2: a link that an isolation query named
//! and no relay of it, which the authorities sign as they sign a root, and
//! which each client leaves out of its chains (`REL-183` to `REL-185`).

use alloc::vec::Vec;

use umbra_crypto::{
    labels,
    rand_core::CryptoRng,
    sign::{SigningKey, SIGNATURE_LEN},
};
use umbra_wire::codec::Reader;

use super::{
    root::{read_sigs, DirectoryKeySet},
    AUTHORITY_COUNT,
};
use crate::Error;

/// `LINK_REMOVAL_EPOCHS`: the life of a removed link, in consensus epochs.
pub const LINK_REMOVAL_EPOCHS: u64 = 168;
/// The fixed part of a `LinkRemoval`, before its signatures.
const FIXED_LEN: usize = 1 + 8 + 32 + 32;

/// One removed link: two relays that no chain holds side by side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkRemoval {
    /// The consensus epoch of the verdict.
    pub epoch: u64,
    /// The lower `relay_id` of the two.
    pub relay_a: [u8; 32],
    /// The higher `relay_id`.
    pub relay_b: [u8; 32],
}

impl LinkRemoval {
    /// The removal of the link between two relays, in either order.
    pub fn of(epoch: u64, one: [u8; 32], other: [u8; 32]) -> Self {
        let (relay_a, relay_b) = if one <= other { (one, other) } else { (other, one) };
        LinkRemoval {
            epoch,
            relay_a,
            relay_b,
        }
    }

    fn body(&self) -> [u8; FIXED_LEN] {
        let mut out = [0u8; FIXED_LEN];
        out[0] = 0x01;
        out[1..9].copy_from_slice(&self.epoch.to_be_bytes());
        out[9..41].copy_from_slice(&self.relay_a);
        out[41..73].copy_from_slice(&self.relay_b);
        out
    }

    fn preimage(&self) -> Vec<u8> {
        [labels::LINK_REMOVAL, &self.body()].concat()
    }

    /// Signs the removal with the key of each authority of `signers`, in
    /// ascending order, and writes it (`REL-183`).
    pub fn sign<R: CryptoRng + ?Sized>(
        &self,
        signers: &[(u8, &SigningKey)],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let unordered = signers
            .windows(2)
            .any(|pair| matches!(pair, [one, other] if one.0 >= other.0));
        if signers.len() > AUTHORITY_COUNT || unordered {
            return Err(Error::Malformed);
        }
        let preimage = self.preimage();
        let mut out = self.body().to_vec();
        out.push(u8::try_from(signers.len()).map_err(|_| Error::Malformed)?);
        for (index, key) in signers {
            out.push(*index);
            out.extend_from_slice(&key.sign(&preimage, rng)?.to_bytes());
        }
        Ok(out)
    }

    /// The width of the removal at the front of `bytes`, from its count of
    /// signatures.
    pub fn len_of(bytes: &[u8]) -> Result<usize, Error> {
        let count = usize::from(*bytes.get(FIXED_LEN).ok_or(Error::Malformed)?);
        Ok(FIXED_LEN + 1 + count * (1 + SIGNATURE_LEN))
    }

    /// Reads a removal and verifies it under `keyset` for a root of
    /// `root_epoch` (`REL-184`).
    pub fn verify(bytes: &[u8], keyset: &DirectoryKeySet<'_>, root_epoch: u64) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let removal = LinkRemoval {
            epoch: u64::from_be_bytes(r.array()?),
            relay_a: r.array()?,
            relay_b: r.array()?,
        };
        let sigs = read_sigs(&mut r)?;
        r.finish()?;
        if removal.relay_a >= removal.relay_b {
            return Err(Error::Malformed);
        }
        if removal.epoch > root_epoch || removal.epoch.saturating_add(LINK_REMOVAL_EPOCHS) < root_epoch {
            return Err(Error::Stale);
        }
        keyset.verify_multi(&removal.preimage(), &sigs)?;
        Ok(removal)
    }

    /// Whether two relays side by side form this link, in either order.
    pub fn names(&self, one: &[u8; 32], other: &[u8; 32]) -> bool {
        (self.relay_a == *one && self.relay_b == *other) || (self.relay_a == *other && self.relay_b == *one)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::directory::{descriptor::tests::Rng, root::tests::authorities};

    #[test]
    fn a_removal_verifies_under_five_authorities_for_its_life() {
        let mut rng = Rng(9);
        let keys = authorities(90);
        let pks: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let keyset = DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|k| &k[..]).collect(),
        };
        let removal = LinkRemoval::of(100, [9; 32], [3; 32]);
        assert_eq!((removal.relay_a, removal.relay_b), ([3; 32], [9; 32]));
        assert!(removal.names(&[9; 32], &[3; 32]) && removal.names(&[3; 32], &[9; 32]));
        let five: Vec<(u8, &SigningKey)> = (0..5u8).map(|i| (i, &keys[usize::from(i)])).collect();
        let signed = removal.sign(&five, &mut rng).unwrap();
        assert_eq!(LinkRemoval::len_of(&signed).unwrap(), signed.len());
        assert_eq!(LinkRemoval::verify(&signed, &keyset, 100).unwrap(), removal);
        assert_eq!(
            LinkRemoval::verify(&signed, &keyset, 100 + LINK_REMOVAL_EPOCHS + 1),
            Err(Error::Stale)
        );
        assert_eq!(LinkRemoval::verify(&signed, &keyset, 99), Err(Error::Stale));
        // Four signatures are not a consensus.
        let four: Vec<(u8, &SigningKey)> = (0..4u8).map(|i| (i, &keys[usize::from(i)])).collect();
        assert!(LinkRemoval::verify(&removal.sign(&four, &mut rng).unwrap(), &keyset, 100).is_err());
    }
}
