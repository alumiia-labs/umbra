//! The group keys of Part 11 and Part 5 §5.8.
//!
//! A group holds one secret for each epoch. The slot chain of [`chain`]
//! turns that secret into one record key for each hour, and each member
//! receives the secret in a [`slot`] sealed to its own `UMBRA-KEM` key.
//! Attribution is the [`pair`] tag: a 12-byte MAC under a key that two
//! members share, thus a record proves authorship to no third party, and
//! an insider cannot forge a tag to another member.
//!
//! The byte layouts of the records live in the wire crate. This module
//! gives the keys, the tags, and the AEAD calls that those layouts carry.

pub mod chain;
pub mod pair;
pub mod slot;

use hkdf::Hkdf;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::{kem::KeyPair, labels, secret::Secret, sign::SigningKey, Error};

use pair::PairKey;

/// `GROUP_SLOT`: the length of one slot, in seconds.
pub const SLOT_SECONDS: u64 = 3_600;
/// `GROUP_SLOT_WINDOW`: the slots a device keeps behind the current one.
pub const SLOT_WINDOW: u32 = 24;
/// `GROUP_SLOT_SKEW`: the slots a receiver accepts ahead of its clock.
pub const SLOT_SKEW: u32 = 2;
/// `GROUP_TAG_LEN`: the length of a pair tag.
pub const TAG_LEN: usize = 12;
/// `GROUP_MAX`: the most members one group holds.
pub const MEMBER_MAX: usize = 500;

/// The slot index of a unix time (`GRP-223`).
pub fn slot_of(unix_seconds: u64) -> u32 {
    u32::try_from(unix_seconds / SLOT_SECONDS).unwrap_or(u32::MAX)
}

/// The three keys of one member in one group, from `GroupRosterSeed_g`
/// (Part 11 §11.3.3).
///
/// Every device of the member holds the same seed, thus the same keys.
pub struct MemberKeys {
    roster: SigningKey,
    pair: StaticSecret,
    kem: KeyPair,
}

impl MemberKeys {
    /// Derives the three keys from the seed.
    pub fn from_seed(seed: &Secret<32>) -> Self {
        let kdf = Hkdf::<Sha3_256>::new(None, seed.expose());

        let mut pair = Secret::<32>::zeroed();
        // The output lengths are below the HKDF bound, thus expand cannot fail.
        let _ = kdf.expand(labels::GROUP_PAIR, pair.expose_mut());

        let mut hybrid = Secret::<96>::zeroed();
        let _ = kdf.expand(labels::GROUP_KEM, hybrid.expose_mut());
        let (x_part, dz_part) = hybrid.expose().split_at(32);
        let mut x = [0u8; 32];
        let mut dz = [0u8; 64];
        x.copy_from_slice(x_part);
        dz.copy_from_slice(dz_part);

        Self {
            roster: SigningKey::from_seed(Secret::new(*seed.expose())),
            pair: StaticSecret::from(*pair.expose()),
            kem: KeyPair::from_seeds(Secret::new(x), Secret::new(dz)),
        }
    }

    /// `GroupRosterKey_g`, the roster signing key.
    pub fn roster(&self) -> &SigningKey {
        &self.roster
    }

    /// `GroupKemKey_g`, the key that an epoch-key slot seals to.
    pub fn kem(&self) -> &KeyPair {
        &self.kem
    }

    /// The public half of `GroupPairKey_g`, as the roster entry carries it.
    pub fn pair_public(&self) -> [u8; 32] {
        *XPublic::from(&self.pair).as_bytes()
    }

    /// `K_ij` with the member whose pair public key is `peer`, in the group
    /// `group_id` (`GRP-235`).
    ///
    /// Fails on a non-contributory Diffie-Hellman output (`GRP-237`).
    pub fn pair_key(&self, peer: &[u8; 32], group_id: &[u8; 32]) -> Result<PairKey, Error> {
        PairKey::derive(&self.pair, &self.pair_public(), peer, group_id)
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

    #[test]
    fn slot_index_follows_the_clock() {
        assert_eq!(slot_of(0), 0);
        assert_eq!(slot_of(3_599), 0);
        assert_eq!(slot_of(3_600), 1);
        assert_eq!(slot_of(u64::MAX), u32::MAX);
    }

    #[test]
    fn keys_come_from_the_seed_alone() {
        let a = MemberKeys::from_seed(&Secret::new([1; 32]));
        let b = MemberKeys::from_seed(&Secret::new([1; 32]));
        let c = MemberKeys::from_seed(&Secret::new([2; 32]));
        assert_eq!(a.pair_public(), b.pair_public());
        assert_ne!(a.pair_public(), c.pair_public());
        assert_eq!(a.kem().public().to_bytes(), b.kem().public().to_bytes());
        assert_ne!(a.kem().public().to_bytes(), c.kem().public().to_bytes());
        assert_eq!(
            a.roster().verifying_key().to_bytes(),
            b.roster().verifying_key().to_bytes()
        );
    }

    #[test]
    fn a_low_order_peer_key_is_refused() {
        let a = MemberKeys::from_seed(&Secret::new([1; 32]));
        assert!(a.pair_key(&[0; 32], &[7; 32]).is_err());
    }
}
