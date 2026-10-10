//! RSABSSA-SHA384-PSS-Deterministic of RFC 9474, which is AUX-1 of Part 5
//! §5.1: the cross-relay token of Part 13 §13.3.1, which a third party
//! verifies with the public key of the issuer alone.
//!
//! The issuer signs, the client blinds and finalizes, and any party
//! verifies. No key is generated here: the issuer holds its key from its
//! own tooling, and a client holds the public key from the log of Part 13
//! §13.5. The modulus width is a type parameter, because the RFC vectors
//! use 4096 bits and UMBRA uses 2048; [`PublicKey2048`] is the UMBRA key.
//! The variant is PSS with a 48-byte salt that the client draws at the
//! blind, and a deterministic message preparation.

use alloc::vec::Vec;

use crypto_bigint::{
    modular::{FixedMontyForm, FixedMontyParams},
    NonZero, Odd, Uint, U2048,
};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha384};
use subtle::{ConstantTimeEq, ConstantTimeLess};
use zeroize::Zeroize;

use crate::Error;

/// The hash length of SHA-384, which is also the salt length.
const HASH_LEN: usize = 48;
/// The salt length of the PSS variant.
pub const SALT_LEN: usize = 48;
/// The public exponent, which is fixed at 65 537.
const EXPONENT: u32 = 65_537;
/// The bit length of the public exponent.
const EXPONENT_BITS: u32 = 17;
/// The draws of a blind before the generator counts as failed. Each draw
/// fails with a probability below one half.
const BLIND_DRAWS: usize = 128;
/// The limbs of the UMBRA modulus.
pub const LIMBS_2048: usize = U2048::LIMBS;
/// The modulus and signature length of the UMBRA key, in bytes.
pub const MODULUS_LEN_2048: usize = 256;

/// The UMBRA public key, a 2048-bit modulus.
pub type PublicKey2048 = PublicKey<LIMBS_2048>;
/// The UMBRA signing key.
pub type SecretKey2048 = SecretKey<LIMBS_2048>;

/// A public key: a modulus of `LIMBS` limbs with the exponent 65 537.
#[derive(Clone)]
pub struct PublicKey<const LIMBS: usize> {
    params: FixedMontyParams<LIMBS>,
    n: NonZero<Uint<LIMBS>>,
    bytes: Vec<u8>,
}

impl<const LIMBS: usize> PublicKey<LIMBS> {
    /// The modulus and signature length, in bytes.
    pub const MODULUS_LEN: usize = Uint::<LIMBS>::BYTES;

    /// A key from the big-endian modulus, which must fill its width.
    pub fn from_modulus(n: &[u8]) -> Result<Self, Error> {
        if n.len() != Self::MODULUS_LEN {
            return Err(Error::Length);
        }
        // The top bit must be set, thus the modulus has its full width.
        if n.first().is_none_or(|b| b & 0x80 == 0) {
            return Err(Error::Key);
        }
        let n_uint = Uint::<LIMBS>::from_be_slice(n);
        let odd = Option::from(Odd::new(n_uint)).ok_or(Error::Key)?;
        let nonzero = Option::from(NonZero::new(n_uint)).ok_or(Error::Key)?;
        Ok(PublicKey {
            params: FixedMontyParams::new(odd),
            n: nonzero,
            bytes: n.to_vec(),
        })
    }

    /// The modulus bytes.
    pub fn modulus(&self) -> &[u8] {
        &self.bytes
    }

    fn form(&self, x: &Uint<LIMBS>) -> FixedMontyForm<LIMBS> {
        FixedMontyForm::new(x, &self.params)
    }

    /// `RSAVP1`: `x^e mod n`.
    fn public_op(&self, x: &Uint<LIMBS>) -> Uint<LIMBS> {
        // The exponent is public and 17 bits long, thus the ladder runs over
        // 17 bits and not over the width of the modulus.
        self.form(x)
            .pow_bounded_exp(&Uint::<LIMBS>::from_u32(EXPONENT), EXPONENT_BITS)
            .retrieve()
    }

    fn below_modulus(&self, x: &Uint<LIMBS>) -> bool {
        bool::from(x.ct_lt(self.n.as_ref()))
    }

    fn os2ip(&self, bytes: &[u8]) -> Result<Uint<LIMBS>, Error> {
        if bytes.len() != Self::MODULUS_LEN {
            return Err(Error::Length);
        }
        let x = Uint::<LIMBS>::from_be_slice(bytes);
        if !self.below_modulus(&x) {
            return Err(Error::Signature);
        }
        Ok(x)
    }
}

fn i2osp<const LIMBS: usize>(x: &Uint<LIMBS>) -> Vec<u8> {
    x.to_be_bytes().as_ref().to_vec()
}

/// A signing key: the modulus and the private exponent.
pub struct SecretKey<const LIMBS: usize> {
    public: PublicKey<LIMBS>,
    d: Uint<LIMBS>,
}

impl<const LIMBS: usize> Drop for SecretKey<LIMBS> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl<const LIMBS: usize> SecretKey<LIMBS> {
    /// A key from the big-endian modulus and private exponent.
    pub fn from_parts(n: &[u8], d: &[u8]) -> Result<Self, Error> {
        let public = PublicKey::from_modulus(n)?;
        if d.len() != PublicKey::<LIMBS>::MODULUS_LEN {
            return Err(Error::Length);
        }
        let d = Uint::<LIMBS>::from_be_slice(d);
        Ok(SecretKey { public, d })
    }

    /// The public key.
    pub const fn public(&self) -> &PublicKey<LIMBS> {
        &self.public
    }

    /// `BlindSign`: signs a blinded message, and checks the result before
    /// it leaves (RFC 9474 §4.3).
    pub fn blind_sign(&self, blinded_msg: &[u8]) -> Result<Vec<u8>, Error> {
        let m = self.public.os2ip(blinded_msg)?;
        let s = self.public.form(&m).pow(&self.d).retrieve();
        if self.public.public_op(&s) != m {
            return Err(Error::Signature);
        }
        Ok(i2osp(&s))
    }
}

#[cfg(feature = "keygen")]
mod keygen {
    use core::convert::Infallible;

    use crypto_bigint::U1024;
    use crypto_primes::{random_prime, Flavor};
    use hmac::{Hmac, KeyInit, Mac};
    use rand_core::{TryCryptoRng, TryRng};
    use sha3::Sha3_256;

    use zeroize::Zeroize;

    use super::{Error, NonZero, SecretKey, Uint, EXPONENT, LIMBS_2048, U2048};
    use crate::{labels, secret::Secret};

    /// `HMAC-SHA3-256(key, BE64(counter))` blocks: the primes of one seed
    /// and one context, the same at each call.
    struct SeedStream {
        mac: Hmac<Sha3_256>,
        counter: u64,
    }

    impl TryRng for SeedStream {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for chunk in dst.chunks_mut(32) {
                let mut mac = self.mac.clone();
                mac.update(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                let block = mac.finalize().into_bytes();
                let n = chunk.len().min(block.len());
                if let (Some(to), Some(from)) = (chunk.get_mut(..n), block.get(..n)) {
                    to.copy_from_slice(from);
                }
            }
            Ok(())
        }
    }

    impl TryCryptoRng for SeedStream {}

    impl SecretKey<LIMBS_2048> {
        /// The 2 048-bit key of one issuer for one `context`, such as an
        /// epoch, from a secret seed: the stream of
        /// `HMAC-SHA3-256(seed, "umbra/v1/issuer-rsa" || context)` gives
        /// the two primes, thus a restart of the issuer finds the same key
        /// (Part 13 §13.6).
        pub fn from_seed(seed: &Secret<32>, context: &[u8]) -> Result<Self, Error> {
            let mut outer = <Hmac<Sha3_256> as KeyInit>::new_from_slice(seed.expose())
                .map_err(|_| Error::Key)?;
            outer.update(labels::ISSUER_RSA);
            outer.update(context);
            let mut key = outer.finalize().into_bytes();
            let mac = <Hmac<Sha3_256> as KeyInit>::new_from_slice(&key);
            key.zeroize();
            let mac = mac.map_err(|_| Error::Key)?;
            let mut stream = SeedStream { mac, counter: 0 };
            let e = U2048::from_u32(EXPONENT);
            loop {
                let mut p: U1024 = random_prime(&mut stream, Flavor::Any, 1_024);
                let mut q: U1024 = random_prime(&mut stream, Flavor::Any, 1_024);
                let n: U2048 = p.concatenating_mul(&q);
                let mut phi: U2048 = p
                    .wrapping_sub(&U1024::ONE)
                    .concatenating_mul(&q.wrapping_sub(&U1024::ONE));
                let distinct = p != q;
                // The primes and the order go at each turn of the loop,
                // the turn that returns among them.
                p.zeroize();
                q.zeroize();
                let order = Option::<NonZero<Uint<LIMBS_2048>>>::from(NonZero::new(phi));
                phi.zeroize();
                if !distinct || n.bits() != 2_048 {
                    continue;
                }
                let Some(mut order) = order else {
                    continue;
                };
                // 65 537 must have an inverse modulo the order.
                let inverse = Option::<U2048>::from(e.invert_mod(&order));
                order.zeroize();
                let Some(mut d) = inverse else {
                    continue;
                };
                let mut d_bytes = d.to_be_bytes();
                d.zeroize();
                let key = Self::from_parts(n.to_be_bytes().as_ref(), d_bytes.as_ref());
                d_bytes.as_mut().zeroize();
                return key;
            }
        }
    }
}

/// The inverse of the blind, which the client keeps until the finalize.
pub struct BlindInverse<const LIMBS: usize>(Uint<LIMBS>);

impl<const LIMBS: usize> Drop for BlindInverse<LIMBS> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `MGF1` with SHA-384.
fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.saturating_add(HASH_LEN));
    let mut counter = 0u32;
    while out.len() < len {
        let mut h = Sha384::new();
        h.update(seed);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter = counter.saturating_add(1);
    }
    out.truncate(len);
    out
}

/// `H(0x00 × 8 || SHA-384(msg) || salt)`, the `M'` hash.
fn m_prime_hash(msg: &[u8], salt: &[u8]) -> [u8; HASH_LEN] {
    let m_hash: [u8; HASH_LEN] = Sha384::digest(msg).into();
    let mut h = Sha384::new();
    h.update([0u8; 8]);
    h.update(m_hash);
    h.update(salt);
    h.finalize().into()
}

/// `EMSA-PSS-ENCODE` at `emBits = 8 × em_len − 1` (RFC 8017 §9.1.1).
fn pss_encode(msg: &[u8], salt: &[u8; SALT_LEN], em_len: usize) -> Vec<u8> {
    let h = m_prime_hash(msg, salt);
    let db_len = em_len.saturating_sub(HASH_LEN + 1);
    let mut db = alloc::vec![0u8; db_len];
    let ps_len = db_len.saturating_sub(SALT_LEN + 1);
    if let Some(marker) = db.get_mut(ps_len) {
        *marker = 0x01;
    }
    if let Some(tail) = db.get_mut(ps_len + 1..) {
        tail.copy_from_slice(salt);
    }
    let mask = mgf1(&h, db_len);
    for (b, m) in db.iter_mut().zip(&mask) {
        *b ^= m;
    }
    if let Some(first) = db.first_mut() {
        *first &= 0x7F;
    }
    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xBC);
    em
}

/// `EMSA-PSS-VERIFY` (RFC 8017 §9.1.2).
fn pss_verify(msg: &[u8], em: &[u8]) -> Result<(), Error> {
    if em.len() < HASH_LEN + SALT_LEN + 2 || em.last() != Some(&0xBC) {
        return Err(Error::Signature);
    }
    let db_len = em.len().saturating_sub(HASH_LEN + 1);
    let masked_db = em.get(..db_len).ok_or(Error::Signature)?;
    let h = em.get(db_len..db_len + HASH_LEN).ok_or(Error::Signature)?;
    if masked_db.first().is_none_or(|b| b & 0x80 != 0) {
        return Err(Error::Signature);
    }
    let mask = mgf1(h, db_len);
    let mut db: Vec<u8> = masked_db.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
    if let Some(first) = db.first_mut() {
        *first &= 0x7F;
    }
    let ps_len = db_len.saturating_sub(SALT_LEN + 1);
    let ps_ok = db
        .get(..ps_len)
        .is_some_and(|ps| ps.iter().all(|&b| b == 0));
    if !ps_ok || db.get(ps_len) != Some(&0x01) {
        return Err(Error::Signature);
    }
    let salt = db.get(ps_len + 1..).ok_or(Error::Signature)?;
    if bool::from(m_prime_hash(msg, salt).ct_eq(h)) {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}

/// `Blind` with a given salt and blind `r`, for the known-answer tests.
pub fn blind_with<const LIMBS: usize>(
    pk: &PublicKey<LIMBS>,
    msg: &[u8],
    salt: &[u8; SALT_LEN],
    r: &Uint<LIMBS>,
) -> Result<(Vec<u8>, BlindInverse<LIMBS>), Error> {
    let em = pss_encode(msg, salt, PublicKey::<LIMBS>::MODULUS_LEN);
    let m = pk.os2ip(&em)?;
    // RFC 9474 §4.2 step 4: the encoded message is coprime to `n`. A value
    // that is not would give a factor of `n`.
    if !bool::from(m.invert_mod(&pk.n).is_some()) {
        return Err(Error::Signature);
    }
    let inverse = Option::from(r.invert_mod(&pk.n)).ok_or(Error::Rng)?;
    let x = pk.public_op(r);
    let z = (pk.form(&m) * pk.form(&x)).retrieve();
    Ok((i2osp(&z), BlindInverse(inverse)))
}

/// `Blind` (RFC 9474 §4.2): the blinded message to send and the inverse
/// to keep.
pub fn blind<const LIMBS: usize, R: TryCryptoRng + ?Sized>(
    pk: &PublicKey<LIMBS>,
    msg: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, BlindInverse<LIMBS>), Error> {
    let mut salt = [0u8; SALT_LEN];
    rng.try_fill_bytes(&mut salt).map_err(|_| Error::Rng)?;
    // `random_integer_uniform(1, n)` by rejection. A reduction modulo `n`
    // would favor the low values, and the issuer could then tell a true
    // blind from a false one. The top bit of `n` is set, thus a draw passes
    // with a probability above one half.
    for _ in 0..BLIND_DRAWS {
        let mut bytes = alloc::vec![0u8; PublicKey::<LIMBS>::MODULUS_LEN];
        rng.try_fill_bytes(&mut bytes).map_err(|_| Error::Rng)?;
        let mut r = Uint::<LIMBS>::from_be_slice(&bytes);
        bytes.zeroize();
        if pk.below_modulus(&r) && bool::from(r.is_nonzero()) {
            if let Ok(out) = blind_with(pk, msg, &salt, &r) {
                r.zeroize();
                return Ok(out);
            }
        }
        r.zeroize();
    }
    Err(Error::Rng)
}

/// `Finalize` (RFC 9474 §4.4): the signature, verified before it leaves.
pub fn finalize<const LIMBS: usize>(
    pk: &PublicKey<LIMBS>,
    msg: &[u8],
    blind_sig: &[u8],
    inverse: &BlindInverse<LIMBS>,
) -> Result<Vec<u8>, Error> {
    let z = pk.os2ip(blind_sig)?;
    let s = (pk.form(&z) * pk.form(&inverse.0)).retrieve();
    let sig = i2osp(&s);
    verify(pk, msg, &sig)?;
    Ok(sig)
}

/// `RSASSA-PSS-VERIFY` with the 48-byte salt of the variant.
pub fn verify<const LIMBS: usize>(
    pk: &PublicKey<LIMBS>,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let s = pk.os2ip(sig)?;
    let em = i2osp(&pk.public_op(&s));
    pss_verify(msg, &em)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crypto_bigint::U4096;

    const LIMBS_4096: usize = U4096::LIMBS;

    #[cfg(feature = "keygen")]
    #[test]
    fn a_seed_gives_one_key_that_signs_a_blind_message() {
        use crate::{secret::Secret, test_rng::TestRng};

        let seed = Secret::new([0x5A; 32]);
        let key = SecretKey2048::from_seed(&seed, &7u32.to_be_bytes()).unwrap();
        let again = SecretKey2048::from_seed(&seed, &7u32.to_be_bytes()).unwrap();
        assert_eq!(key.public().modulus(), again.public().modulus());
        assert_eq!(key.public().modulus().len(), MODULUS_LEN_2048);
        let other = SecretKey2048::from_seed(&seed, &8u32.to_be_bytes()).unwrap();
        assert_ne!(key.public().modulus(), other.public().modulus());

        let mut rng = TestRng::new(b"blind");
        let (blinded, inverse) = blind(key.public(), b"token input", &mut rng).unwrap();
        let signed = key.blind_sign(&blinded).unwrap();
        let sig = finalize(key.public(), b"token input", &signed, &inverse).unwrap();
        verify(key.public(), b"token input", &sig).unwrap();
        assert!(verify(other.public(), b"token input", &sig).is_err());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const VECTOR: &str = include_str!("../../../tests/vectors/rfc9474/deterministic.txt");

    fn field(name: &str) -> Vec<u8> {
        let line = VECTOR
            .lines()
            .find(|l| l.starts_with(&alloc::format!("{name}=")))
            .unwrap();
        hex(line.split_once('=').unwrap().1.trim())
    }

    #[test]
    fn the_rfc_9474_deterministic_vector_holds() {
        let sk = SecretKey::<LIMBS_4096>::from_parts(&field("n"), &field("d")).unwrap();
        let pk = sk.public();
        let msg = field("msg");
        let salt: [u8; SALT_LEN] = field("salt").try_into().unwrap();
        assert_eq!(pss_encode(&msg, &salt, 512), field("encoded_msg"));
        let inv = U4096::from_be_slice(&field("inv"));
        let r = Option::<U4096>::from(inv.invert_mod(&pk.n)).unwrap();
        let (blinded, inverse) = blind_with(pk, &msg, &salt, &r).unwrap();
        assert_eq!(blinded, field("blinded_msg"));
        assert_eq!(i2osp(&inverse.0), field("inv"));
        let blind_sig = sk.blind_sign(&blinded).unwrap();
        assert_eq!(blind_sig, field("blind_sig"));
        let sig = finalize(pk, &msg, &blind_sig, &inverse).unwrap();
        assert_eq!(sig, field("sig"));
        verify(pk, &msg, &sig).unwrap();
        assert!(verify(pk, b"other", &sig).is_err());
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(verify(pk, &msg, &bad).is_err());
        assert!(sk.blind_sign(&blinded[..100]).is_err());
    }

    #[test]
    fn a_random_blind_round_trips_and_a_bad_modulus_is_refused() {
        let sk = SecretKey::<LIMBS_4096>::from_parts(&field("n"), &field("d")).unwrap();
        let mut rng = crate::test_rng::TestRng::new(b"rsabssa");
        let (blinded, inverse) = blind(sk.public(), b"token input", &mut rng).unwrap();
        let blind_sig = sk.blind_sign(&blinded).unwrap();
        let sig = finalize(sk.public(), b"token input", &blind_sig, &inverse).unwrap();
        verify(sk.public(), b"token input", &sig).unwrap();
        assert!(finalize(sk.public(), b"other", &blind_sig, &inverse).is_err());
        let mut even = field("n");
        even[511] &= 0xFE;
        assert!(PublicKey::<LIMBS_4096>::from_modulus(&even).is_err());
        assert!(PublicKey::<LIMBS_4096>::from_modulus(&field("n")[1..]).is_err());
        assert!(PublicKey2048::from_modulus(&field("n")).is_err());
        assert_eq!(PublicKey2048::MODULUS_LEN, MODULUS_LEN_2048);
    }
}
