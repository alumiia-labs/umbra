//! The sync channel seed of Part 7 §7.3 and §7.7: derived from the
//! device-set key, and replaced at each epoch that revokes a device.

use umbra_crypto::{hierarchy::RootIdentity, hkdf::Hkdf, labels, secret::Secret, sha3::Sha3_256};
use umbra_wire::codec::{Reader, Writer};

use crate::Error;

/// The length of a `SyncSeedUpdate`.
pub const UPDATE_LEN: usize = 40;

/// `SyncChannelSeed_n`.
pub struct SyncSeed(Secret<32>);

impl SyncSeed {
    /// `SyncChannelSeed_0` from `K_devset` of the root identity (§7.3).
    pub fn genesis(root: &RootIdentity) -> Self {
        let set_key = root.device_set_key();
        let kdf = Hkdf::<Sha3_256>::new(None, set_key.expose());
        let mut seed = Secret::<32>::zeroed();
        let _ = kdf.expand(labels::SYNC_SEED, seed.expose_mut());
        SyncSeed(seed)
    }

    /// Wraps a seed a restore holds.
    pub const fn from_secret(seed: Secret<32>) -> Self {
        SyncSeed(seed)
    }

    /// The seed bytes, for the queue derivations of the sync channels.
    pub fn expose(&self) -> &Secret<32> {
        &self.0
    }

    /// `SyncChannelSeed_n+1` from a `SyncSeedUpdate` (`DEV-252`).
    pub fn next(&self, update: &SyncSeedUpdate) -> SyncSeed {
        let kdf = Hkdf::<Sha3_256>::new(Some(self.0.expose()), &update.seed_input);
        let mut seed = Secret::<32>::zeroed();
        let _ = kdf.expand_multi_info(
            &[labels::SYNC_SEED, &update.epoch.to_be_bytes()],
            seed.expose_mut(),
        );
        SyncSeed(seed)
    }
}

/// The seed input that the signer of a revoking epoch sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSeedUpdate {
    /// The epoch that revokes the device.
    pub epoch: u64,
    /// 32 bytes from the signer's CSPRNG (`DEV-250`).
    pub seed_input: [u8; 32],
}

impl SyncSeedUpdate {
    /// Writes the update.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.seed_input)?;
        Ok(w.position())
    }

    /// Reads an update.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = SyncSeedUpdate {
            epoch: u64::from_be_bytes(r.array()?),
            seed_input: r.array()?,
        };
        r.finish()?;
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_seed_moves_only_at_an_update_and_both_ends_agree() {
        let root = RootIdentity::new(Secret::new([1; 32]));
        let a = SyncSeed::genesis(&root);
        let b = SyncSeed::genesis(&root);
        assert_eq!(a.expose().expose(), b.expose().expose());
        let update = SyncSeedUpdate {
            epoch: 3,
            seed_input: [7; 32],
        };
        let mut bytes = [0u8; UPDATE_LEN];
        assert_eq!(update.encode(&mut bytes).unwrap(), UPDATE_LEN);
        assert_eq!(SyncSeedUpdate::parse(&bytes).unwrap(), update);
        let a1 = a.next(&update);
        let b1 = b.next(&SyncSeedUpdate::parse(&bytes).unwrap());
        assert_eq!(a1.expose().expose(), b1.expose().expose());
        assert_ne!(a1.expose().expose(), a.expose().expose());
        let other = a.next(&SyncSeedUpdate { epoch: 4, ..update });
        assert_ne!(other.expose().expose(), a1.expose().expose());
    }
}
