//! The two identities of a member in one community (Part 12 §12.3.2,
//! §12.6.3): the authoring identity that posts, and the role identity that
//! signs a control object and opens a report. Each one comes from its own
//! seed from the device CSPRNG, and no seed derives from another key
//! (`COM-027` to `COM-031`).

use umbra_crypto::{
    hkdf::Hkdf,
    kem::KeyPair,
    labels,
    rand_core::TryCryptoRng,
    secret::Secret,
    sha3::Sha3_256,
    sign::{Signature, SigningKey, VERIFYING_KEY_LEN},
};

use super::pseudonym_of;
use crate::Error;

/// `Hybrid(HKDF-SHA3-256(ikm = seed, info = label, L = 96))`, in the manner
/// of the member KEM key of Part 11 §11.3.3.
fn hybrid_from(seed: &Secret<32>, label: &[u8]) -> KeyPair {
    let kdf = Hkdf::<Sha3_256>::new(None, seed.expose());
    let mut stream = Secret::<96>::zeroed();
    // 96 bytes is below the HKDF bound, thus expand cannot fail.
    let _ = kdf.expand(label, stream.expose_mut());
    let (x_part, dz_part) = stream.expose().split_at(32);
    let mut x = [0u8; 32];
    let mut dz = [0u8; 64];
    x.copy_from_slice(x_part);
    dz.copy_from_slice(dz_part);
    KeyPair::from_seeds(Secret::new(x), Secret::new(dz))
}

/// The ML-DSA-65 key of a seed, with its public bytes and its pseudonym.
struct Signer {
    key: SigningKey,
    public_key: [u8; VERIFYING_KEY_LEN],
    pseudonym: [u8; 32],
}

impl Signer {
    fn from_seed(seed: &Secret<32>) -> Self {
        let key = SigningKey::from_seed(Secret::new(*seed.expose()));
        let public_key = key.verifying_key().to_bytes();
        Signer {
            key,
            pseudonym: pseudonym_of(&public_key),
            public_key,
        }
    }
}

/// `CommunityIdentityKey_g` with its pseudonym, and the contact key of
/// §12.6.3 from the same seed.
pub struct AuthorIdentity {
    signer: Signer,
    contact: KeyPair,
}

impl AuthorIdentity {
    /// Derives the identity from `CommunityIdentitySeed_g`.
    pub fn from_seed(seed: &Secret<32>) -> Self {
        AuthorIdentity {
            signer: Signer::from_seed(seed),
            contact: hybrid_from(seed, labels::COMMUNITY_CONTACT),
        }
    }

    /// `pseudonym_g`.
    pub fn pseudonym(&self) -> [u8; 32] {
        self.signer.pseudonym
    }

    /// `CommunityIdentityKey_g.pk`, which a checkpoint carries (`COM-036`).
    pub fn public_key(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.signer.public_key
    }

    /// `CommunityContactKey_g`, which opens a hello to this pseudonym.
    pub fn contact_key(&self) -> &KeyPair {
        &self.contact
    }

    /// Signs `message`, which is the preimage of a checkpoint.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature, Error> {
        Ok(self.signer.key.sign(message, rng)?)
    }
}

/// `RoleSigningKey_r` with its role pseudonym, and `RoleReportKey_r`
/// (`COM-142` to `COM-145`).
pub struct RoleIdentity {
    signer: Signer,
    report: KeyPair,
}

impl RoleIdentity {
    /// Derives the identity from `RoleSeed_r`.
    pub fn from_seed(seed: &Secret<32>) -> Self {
        RoleIdentity {
            signer: Signer::from_seed(seed),
            report: hybrid_from(seed, labels::COMMUNITY_REPORT),
        }
    }

    /// The role pseudonym.
    pub fn pseudonym(&self) -> [u8; 32] {
        self.signer.pseudonym
    }

    /// The public key that a control object carries in `actor_pk`
    /// (`COM-037`).
    pub fn public_key(&self) -> &[u8; VERIFYING_KEY_LEN] {
        &self.signer.public_key
    }

    /// `RoleReportKey_r`, which opens a report record.
    pub fn report_key(&self) -> &KeyPair {
        &self.report
    }

    /// Signs `message`, which is the preimage of a control object.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Signature, Error> {
        Ok(self.signer.key.sign(message, rng)?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::{author, role};

    #[test]
    fn two_seeds_give_two_unrelated_identities() {
        let a = author(1);
        let b = author(2);
        assert_ne!(a.pseudonym(), b.pseudonym());
        assert_ne!(
            a.contact_key().public().to_bytes(),
            b.contact_key().public().to_bytes()
        );
        // One seed under the two derivations gives one signing key and two
        // different KEM keys, because the labels differ.
        let r = role(1);
        assert_eq!(a.pseudonym(), r.pseudonym());
        assert_ne!(
            a.contact_key().public().to_bytes(),
            r.report_key().public().to_bytes()
        );
    }
}
