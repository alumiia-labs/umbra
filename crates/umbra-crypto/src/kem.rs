//! `UMBRA-KEM`, the hybrid of X25519 and ML-KEM-768 (Part 5 §5.3).
//!
//! The combiner hashes both shared secrets, both ciphertexts, and both
//! public keys, thus its security does not rest on the FO transform of
//! ML-KEM and it survives a change of the post-quantum half (§5.3.1). The
//! concatenation order on the wire is classical then post-quantum; the order
//! inside the hash is post-quantum then classical. The two orders differ on
//! purpose (`CRY-036`, `CRY-037`).

use kem::{Decapsulate, Encapsulate};
use ml_kem::{
    array::Array, Ciphertext as MlCiphertext, DecapsulationKey, EncapsulationKey, Key, KeyExport,
    MlKem768, Seed, B32,
};
use rand_core::CryptoRng;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, StaticSecret};

use crate::{labels, secret::Secret, Error};

/// Size of an encoded public key: `pk_X || pk_M`.
pub const PUBLIC_KEY_LEN: usize = 32 + 1184;
/// Size of an encoded ciphertext: `pub_X || ct_M`.
pub const CIPHERTEXT_LEN: usize = 32 + 1088;
/// Size of a shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// The shared secret of one encapsulation.
pub type SharedSecret = Secret<SHARED_SECRET_LEN>;

/// A public key `pk = pk_X || pk_M`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    x: x25519_dalek::PublicKey,
    m: EncapsulationKey<MlKem768>,
}

impl PublicKey {
    /// Encodes the key as `pk_X || pk_M` (`CRY-034`, `CRY-035`).
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        let (x, m) = out.split_at_mut(32);
        x.copy_from_slice(self.x.as_bytes());
        m.copy_from_slice(&self.m.to_bytes());
        out
    }

    /// Decodes `pk_X || pk_M`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::Length);
        }
        let (x, m) = bytes.split_at(32);
        let x: [u8; 32] = x.try_into().map_err(|_| Error::Length)?;
        let m: Key<EncapsulationKey<MlKem768>> = Array::try_from(m).map_err(|_| Error::Length)?;
        let m = EncapsulationKey::<MlKem768>::new(&m).map_err(|_| Error::Key)?;
        Ok(Self {
            x: x25519_dalek::PublicKey::from(x),
            m,
        })
    }
}

/// A keypair. The public key sits beside the secret key, because a
/// decapsulation reads it and a rebuild from the secret key is not constant
/// time in every ML-KEM implementation (`CRY-038`, `CRY-039`).
pub struct KeyPair {
    x_sk: StaticSecret,
    m_dk: DecapsulationKey<MlKem768>,
    pk: PublicKey,
}

impl KeyPair {
    /// Makes a keypair from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut x = [0u8; 32];
        rng.fill_bytes(&mut x);
        let mut dz = [0u8; 64];
        rng.fill_bytes(&mut dz);
        let kp = Self::from_seeds(Secret::new(x), Secret::new(dz));
        Self::wipe(x, dz);
        kp
    }

    /// Makes a keypair from the X25519 scalar `x` and the ML-KEM seeds
    /// `d || z`, as the key hierarchy of Part 5 §5.2 does. `x` is clamped
    /// here, before its first use (`CRY-120`).
    pub fn from_seeds(x: Secret<32>, dz: Secret<64>) -> Self {
        let x_sk = StaticSecret::from(clamp(*x.expose()));
        let m_dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*dz.expose()));
        let pk = PublicKey {
            x: x25519_dalek::PublicKey::from(&x_sk),
            m: m_dk.encapsulation_key().clone(),
        };
        Self { x_sk, m_dk, pk }
    }

    /// The public key.
    pub fn public(&self) -> &PublicKey {
        &self.pk
    }

    /// Recovers `ss` from `ct` (`UMBRA-KEM.Decap`).
    ///
    /// The classical half aborts on an all-zero output (`CRY-040`). The
    /// post-quantum half never aborts; a malformed `ct_M` gives a pseudorandom
    /// secret and the mismatch shows later as an AEAD failure (`CRY-041`).
    /// Every failure gives [`Error::Kem`] (`CRY-042`).
    pub fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret, Error> {
        let (pub_x, ct_m) = ct.split();
        let ss_x = self
            .x_sk
            .diffie_hellman(&x25519_dalek::PublicKey::from(pub_x));
        if !ss_x.was_contributory() {
            return Err(Error::Kem);
        }
        let ct_m: MlCiphertext<MlKem768> = Array::try_from(ct_m).map_err(|_| Error::Kem)?;
        let ss_m = self.m_dk.decapsulate(&ct_m);
        Ok(combine(&ss_m, ss_x.as_bytes(), &ct_m, &pub_x, &self.pk))
    }

    fn wipe(mut x: [u8; 32], mut dz: [u8; 64]) {
        use zeroize::Zeroize;
        x.zeroize();
        dz.zeroize();
    }
}

/// A ciphertext `ct = pub_X || ct_M`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext([u8; CIPHERTEXT_LEN]);

impl Ciphertext {
    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_LEN] {
        &self.0
    }

    /// Decodes `pub_X || ct_M`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into().map(Self).map_err(|_| Error::Length)
    }

    fn split(&self) -> ([u8; 32], &[u8]) {
        let (x, m) = self.0.split_at(32);
        let mut pub_x = [0u8; 32];
        pub_x.copy_from_slice(x);
        (pub_x, m)
    }
}

/// Encapsulates to `pk` with fresh coins from `rng` (`UMBRA-KEM.Encap`).
///
/// The X25519 ephemeral is consumed by its one Diffie-Hellman call, thus one
/// ephemeral cannot serve two encapsulations (`CRY-026`).
pub fn encapsulate<R: CryptoRng + ?Sized>(
    pk: &PublicKey,
    rng: &mut R,
) -> (Ciphertext, SharedSecret) {
    let ek_x = EphemeralSecret::random_from_rng(rng);
    let pub_x = x25519_dalek::PublicKey::from(&ek_x);
    let ss_x = ek_x.diffie_hellman(&pk.x);
    let (ct_m, ss_m) = pk.m.encapsulate_with_rng(rng);
    finish(pk, pub_x, ss_x.as_bytes(), ct_m, &ss_m)
}

/// Encapsulates with the X25519 scalar `ek_x` and the ML-KEM message `m`
/// given, for a test vector. A protocol path uses [`encapsulate`].
pub fn encapsulate_deterministic(
    pk: &PublicKey,
    ek_x: Secret<32>,
    m: Secret<32>,
) -> (Ciphertext, SharedSecret) {
    let ek_x = StaticSecret::from(clamp(*ek_x.expose()));
    let pub_x = x25519_dalek::PublicKey::from(&ek_x);
    let ss_x = ek_x.diffie_hellman(&pk.x);
    let (ct_m, ss_m) = pk.m.encapsulate_deterministic(&B32::from(*m.expose()));
    finish(pk, pub_x, ss_x.as_bytes(), ct_m, &ss_m)
}

fn finish(
    pk: &PublicKey,
    pub_x: x25519_dalek::PublicKey,
    ss_x: &[u8; 32],
    ct_m: MlCiphertext<MlKem768>,
    ss_m: &[u8],
) -> (Ciphertext, SharedSecret) {
    let ss = combine(ss_m, ss_x, &ct_m, pub_x.as_bytes(), pk);
    let mut ct = [0u8; CIPHERTEXT_LEN];
    let (x, m) = ct.split_at_mut(32);
    x.copy_from_slice(pub_x.as_bytes());
    m.copy_from_slice(&ct_m);
    (Ciphertext(ct), ss)
}

// The hash order is post-quantum then classical, and it differs from the
// wire order on purpose. Do not reorder these calls.
fn combine(
    ss_m: &[u8],
    ss_x: &[u8; 32],
    ct_m: &[u8],
    pub_x: &[u8; 32],
    pk: &PublicKey,
) -> SharedSecret {
    let mut h = Sha3_256::new();
    h.update(labels::KEM_COMBINE);
    h.update(ss_m);
    h.update(ss_x);
    h.update(ct_m);
    h.update(pub_x);
    h.update(pk.m.to_bytes());
    h.update(pk.x.as_bytes());
    Secret::new(h.finalize().into())
}

/// Clamps an X25519 scalar as RFC 7748 §5 states.
pub(crate) fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    if let Some(first) = k.first_mut() {
        *first &= 248;
    }
    if let Some(last) = k.last_mut() {
        *last &= 127;
        *last |= 64;
    }
    k
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
    fn round_trip() {
        let mut rng = TestRng::new(b"kem");
        let kp = KeyPair::generate(&mut rng);
        let (ct, ss_a) = encapsulate(kp.public(), &mut rng);
        let ss_b = kp.decapsulate(&ct).expect("decapsulate");
        assert_eq!(ss_a.expose(), ss_b.expose());
    }

    #[test]
    fn encoding_round_trips() {
        let mut rng = TestRng::new(b"enc");
        let kp = KeyPair::generate(&mut rng);
        let pk = PublicKey::from_bytes(&kp.public().to_bytes()).expect("pk");
        assert_eq!(pk.to_bytes(), kp.public().to_bytes());
        let (ct, _) = encapsulate(&pk, &mut rng);
        assert_eq!(Ciphertext::from_bytes(ct.as_bytes()).expect("ct"), ct);
        assert_eq!(PublicKey::from_bytes(&[0u8; 5]).err(), Some(Error::Length));
    }

    #[test]
    fn a_changed_ml_kem_ciphertext_gives_a_different_secret_and_no_error() {
        let mut rng = TestRng::new(b"reject");
        let kp = KeyPair::generate(&mut rng);
        let (ct, ss) = encapsulate(kp.public(), &mut rng);
        let mut bad = *ct.as_bytes();
        bad[40] ^= 1;
        let ss_bad = kp
            .decapsulate(&Ciphertext(bad))
            .expect("implicit rejection");
        assert_ne!(ss.expose(), ss_bad.expose());
    }

    #[test]
    fn an_all_zero_x25519_point_is_rejected() {
        let mut rng = TestRng::new(b"zero");
        let kp = KeyPair::generate(&mut rng);
        let (ct, _) = encapsulate(kp.public(), &mut rng);
        let mut bad = *ct.as_bytes();
        bad[..32].fill(0);
        assert_eq!(kp.decapsulate(&Ciphertext(bad)).err(), Some(Error::Kem));
    }

    #[test]
    fn clamp_follows_rfc_7748() {
        let k = clamp([0xffu8; 32]);
        assert_eq!(k[0], 0xf8);
        assert_eq!(k[31], 0x7f);
        let k = clamp([0u8; 32]);
        assert_eq!(k[31], 0x40);
    }

    #[test]
    fn deterministic_encapsulation_is_stable() {
        let kp = KeyPair::from_seeds(Secret::new([1u8; 32]), Secret::new([2u8; 64]));
        let a =
            encapsulate_deterministic(kp.public(), Secret::new([3u8; 32]), Secret::new([4u8; 32]));
        let b =
            encapsulate_deterministic(kp.public(), Secret::new([3u8; 32]), Secret::new([4u8; 32]));
        assert_eq!(a.0, b.0);
        assert_eq!(a.1.expose(), b.1.expose());
        assert_eq!(kp.decapsulate(&a.0).expect("decap").expose(), a.1.expose());
    }
}
