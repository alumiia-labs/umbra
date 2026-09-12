//! The key hierarchy of Part 5 §5.2.
//!
//! Every key below comes from one 256-bit `RootIdentity` through
//! `Expand(info, L) = HKDF-SHA3-256(salt = "", ikm = RootIdentity, info, L)`
//! and, for a keypair, through `Hybrid(t)`, which splits 96 bytes into the
//! X25519 scalar and the ML-KEM seeds `d` and `z`. One-way derivation gives
//! the unlinkability of the derived keys; an observer that holds two of them
//! cannot relate them without the root.

use hkdf::Hkdf;
use sha3::Sha3_256;

use crate::{kem::KeyPair, labels, secret::Secret};

/// The device-local root seed. It never leaves the device except over the
/// device-link channel of Part 7 §7.4.
pub struct RootIdentity(Secret<32>);

impl RootIdentity {
    /// Wraps a root seed.
    pub const fn new(seed: Secret<32>) -> Self {
        Self(seed)
    }

    /// `Expand(info, L)` into `out`.
    fn expand(&self, info: &[&[u8]], out: &mut [u8]) {
        let hk = Hkdf::<Sha3_256>::new(None, self.0.expose());
        // The output is at most 96 bytes, thus the length bound of HKDF holds.
        let _ = hk.expand_multi_info(info, out);
    }

    fn expand32(&self, label: &[u8]) -> Secret<32> {
        let mut out = Secret::<32>::zeroed();
        self.expand(&[label], out.expose_mut());
        out
    }

    fn hybrid(&self, info: &[&[u8]]) -> KeyPair {
        let mut t = Secret::<96>::zeroed();
        self.expand(info, t.expose_mut());
        let b = t.expose();
        let mut x = [0u8; 32];
        let mut dz = [0u8; 64];
        x.copy_from_slice(&b[..32]);
        dz.copy_from_slice(&b[32..]);
        KeyPair::from_seeds(Secret::new(x), Secret::new(dz))
    }

    /// `K_rng_harden`, the RFC 8937 hardening secret.
    pub fn rng_harden_key(&self) -> Secret<32> {
        self.expand32(labels::RNG_HARDEN)
    }

    /// `K_store`, the at-rest master key.
    pub fn storage_key(&self) -> Secret<32> {
        self.expand32(labels::STORAGE)
    }

    /// `K_devset`, the device-set membership key.
    pub fn device_set_key(&self) -> Secret<32> {
        self.expand32(labels::DEVICE_SET)
    }

    /// `PairwiseIdentity_c` for the contact whose salt is `salt_c`.
    pub fn pairwise_identity(&self, salt_c: &[u8; 16]) -> KeyPair {
        self.hybrid(&[labels::PAIRWISE, salt_c])
    }

    /// `PublicAddressKey_j`.
    pub fn public_address_key(&self, j: u32) -> KeyPair {
        self.hybrid(&[labels::PUBLIC_ADDRESS, &j.to_be_bytes()])
    }

    /// `HandleKey_{j,r}`, the handle key of `PublicAddressKey_j` at rotation `r`.
    pub fn handle_key(&self, j: u32, r: u32) -> KeyPair {
        self.hybrid(&[labels::HANDLE_KEY, &j.to_be_bytes(), &r.to_be_bytes()])
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

    fn root(b: u8) -> RootIdentity {
        RootIdentity::new(Secret::new([b; 32]))
    }

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let a = root(1);
        let b = root(1);
        assert_eq!(a.storage_key().expose(), b.storage_key().expose());
        assert_ne!(a.storage_key().expose(), a.device_set_key().expose());
        assert_ne!(a.storage_key().expose(), root(2).storage_key().expose());
        let pk1 = a.pairwise_identity(&[9u8; 16]).public().to_bytes();
        let pk2 = b.pairwise_identity(&[9u8; 16]).public().to_bytes();
        let pk3 = a.pairwise_identity(&[8u8; 16]).public().to_bytes();
        assert_eq!(pk1, pk2);
        assert_ne!(pk1, pk3);
        assert_ne!(
            a.public_address_key(0).public().to_bytes(),
            a.handle_key(0, 0).public().to_bytes()
        );
        assert_ne!(
            a.handle_key(0, 0).public().to_bytes(),
            a.handle_key(0, 1).public().to_bytes()
        );
    }

    #[test]
    fn a_derived_keypair_decapsulates() {
        let mut rng = crate::test_rng::TestRng::new(b"hier");
        let kp = root(3).pairwise_identity(&[0u8; 16]);
        let (ct, ss) = crate::kem::encapsulate(kp.public(), &mut rng);
        assert_eq!(kp.decapsulate(&ct).expect("decap").expose(), ss.expose());
    }
}
