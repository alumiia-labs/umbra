//! ML-DSA-65 signatures (Part 5 §5.1, primitive 3).
//!
//! UMBRA signs only objects that a third party verifies: directory roots,
//! relay descriptors, roster epochs, and the like. A message carries no
//! signature (§5.7). Each signed preimage starts with its label of §5.11, and
//! the caller builds that preimage; this module signs bytes.
//!
//! Signing is hedged: the 32-byte `rnd` of FIPS 204 comes from the caller's
//! generator, which is the hardened one of [`crate::rng`] on a protocol path
//! (§5.9). Each signature is verified after it is made (§5.12).

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyExport, MlDsa65, Seed};
use rand_core::TryCryptoRng;

use crate::{secret::Secret, Error};

/// Size of an encoded verifying key.
pub const VERIFYING_KEY_LEN: usize = 1952;
/// Size of an encoded signature.
pub const SIGNATURE_LEN: usize = 3309;

/// A signing key, held as its 32-byte seed. It zeroizes on drop.
pub struct SigningKey(ml_dsa::SigningKey<MlDsa65>);

impl SigningKey {
    /// Derives the key from `seed`, as FIPS 204 `KeyGen_internal` does.
    pub fn from_seed(seed: Secret<32>) -> Self {
        Self(ml_dsa::SigningKey::from_seed(&Seed::from(*seed.expose())))
    }

    /// Makes a key from `rng`.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut seed = Secret::<32>::zeroed();
        rng.try_fill_bytes(seed.expose_mut())
            .map_err(|_| Error::Rng)?;
        Ok(Self::from_seed(seed))
    }

    /// The verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.expanded_key().verifying_key())
    }

    /// Signs `message` with fresh `rnd` from `rng`, and verifies the result
    /// before it returns it.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature, Error> {
        let sig = self
            .0
            .expanded_key()
            .sign_randomized(message, b"", rng)
            .map_err(|_| Error::Rng)?;
        let sig = Signature(sig);
        // A fault during signing gives a signature that leaks the key, thus
        // the check runs before any byte leaves this function (§5.12).
        self.verifying_key().verify(message, &sig)?;
        Ok(sig)
    }
}

/// A verifying key.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey(ml_dsa::VerifyingKey<MlDsa65>);

impl VerifyingKey {
    /// Encodes the key as FIPS 204 `pkEncode`.
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.0.to_bytes().into()
    }

    /// Decodes a key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let enc: EncodedVerifyingKey<MlDsa65> = bytes.try_into().map_err(|_| Error::Length)?;
        Ok(Self(ml_dsa::VerifyingKey::decode(&enc)))
    }

    /// Verifies `sig` over `message`. A failure gives one value and names
    /// no cause.
    pub fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), Error> {
        if self.0.verify_with_context(message, b"", &sig.0) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

/// A signature.
#[derive(Clone, Debug, PartialEq)]
pub struct Signature(ml_dsa::Signature<MlDsa65>);

impl Signature {
    /// Encodes the signature as FIPS 204 `sigEncode`.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.encode().into()
    }

    /// Decodes a signature. A signature whose `z` is out of range does not
    /// decode, thus a verifier never runs on it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let enc: EncodedSignature<MlDsa65> = bytes.try_into().map_err(|_| Error::Length)?;
        ml_dsa::Signature::decode(&enc)
            .map(Self)
            .ok_or(Error::Signature)
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
    use crate::test_rng::TestRng;

    #[test]
    fn sign_verify_and_reject_a_change() {
        let mut rng = TestRng::new(b"sign");
        let sk = SigningKey::generate(&mut rng).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"umbra/v1/group-grant hello", &mut rng).unwrap();
        vk.verify(b"umbra/v1/group-grant hello", &sig).unwrap();
        assert_eq!(
            vk.verify(b"umbra/v1/group-grant hellp", &sig),
            Err(Error::Signature)
        );
        let vk2 = VerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
        assert_eq!(vk2, vk);
        let sig2 = Signature::from_bytes(&sig.to_bytes()).unwrap();
        assert_eq!(sig2, sig);
        assert_eq!(Signature::from_bytes(&[0u8; 3]), Err(Error::Length));
    }

    #[test]
    fn the_same_seed_gives_the_same_key() {
        let a = SigningKey::from_seed(Secret::new([9u8; 32]));
        let b = SigningKey::from_seed(Secret::new([9u8; 32]));
        assert_eq!(a.verifying_key(), b.verifying_key());
    }
}
