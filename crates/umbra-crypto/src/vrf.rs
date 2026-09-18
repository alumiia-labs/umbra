//! ECVRF-EDWARDS25519-SHA512-TAI of RFC 9381, which is AUX-3 of Part 5
//! §5.1: the index blinding of the handle transparency log (Part 9 §9.5)
//! and the probe selection of Part 10 §10.4.1. The suite is classically
//! secure only, and Part 9 §9.5.4 states that limit.
//!
//! Part 9 §9.11 gives the checklist: an identity point from the
//! encoding is rejected, a low-order public key is rejected, a
//! non-canonical encoding is rejected, and the expanded key is wiped.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as B,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{secret::Secret, Error};

/// A public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// A proof, which is `Gamma || c || s`.
pub const PROOF_LEN: usize = 80;
/// The output `beta`.
pub const OUTPUT_LEN: usize = 64;

const SUITE: u8 = 0x03;
const CHALLENGE_LEN: usize = 16;

fn point_from_bytes(bytes: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    let compressed = CompressedEdwardsY(*bytes);
    let point = compressed.decompress().ok_or(Error::Key)?;
    // A non-canonical y encoding decodes to a point that compresses
    // differently.
    if point.compress() != compressed {
        return Err(Error::Key);
    }
    Ok(point)
}

/// `ECVRF_encode_to_curve_try_and_increment`.
fn encode_to_curve(salt: &[u8; 32], alpha: &[u8]) -> Result<EdwardsPoint, Error> {
    for ctr in 0u8..=255 {
        let mut h = Sha512::new();
        h.update([SUITE, 0x01]);
        h.update(salt);
        h.update(alpha);
        h.update([ctr, 0x00]);
        let hash: [u8; 64] = h.finalize().into();
        let mut head = [0u8; 32];
        head.copy_from_slice(hash.get(..32).unwrap_or(&[0; 32]));
        if let Some(point) = CompressedEdwardsY(head).decompress() {
            let cleared = point.mul_by_cofactor();
            if !cleared.is_identity() {
                return Ok(cleared);
            }
        }
    }
    Err(Error::Key)
}

/// `ECVRF_challenge_generation`.
fn challenge(points: [&EdwardsPoint; 5]) -> Scalar {
    let mut h = Sha512::new();
    h.update([SUITE, 0x02]);
    for point in points {
        h.update(point.compress().as_bytes());
    }
    h.update([0x00]);
    let hash: [u8; 64] = h.finalize().into();
    let mut c = [0u8; 32];
    if let Some(head) = c.get_mut(..CHALLENGE_LEN) {
        head.copy_from_slice(hash.get(..CHALLENGE_LEN).unwrap_or(&[0; CHALLENGE_LEN]));
    }
    Scalar::from_bytes_mod_order(c)
}

/// `ECVRF_proof_to_hash` on a decoded `Gamma`.
fn gamma_to_hash(gamma: &EdwardsPoint) -> [u8; OUTPUT_LEN] {
    let mut h = Sha512::new();
    h.update([SUITE, 0x03]);
    h.update(gamma.mul_by_cofactor().compress().as_bytes());
    h.update([0x00]);
    h.finalize().into()
}

fn decode_proof(pi: &[u8; PROOF_LEN]) -> Result<(EdwardsPoint, Scalar, Scalar), Error> {
    let gamma_bytes: [u8; 32] = pi
        .get(..32)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Length)?;
    let gamma = point_from_bytes(&gamma_bytes)?;
    let mut c_bytes = [0u8; 32];
    if let Some(head) = c_bytes.get_mut(..CHALLENGE_LEN) {
        head.copy_from_slice(pi.get(32..48).unwrap_or(&[0; CHALLENGE_LEN]));
    }
    let c = Scalar::from_bytes_mod_order(c_bytes);
    let s_bytes: [u8; 32] = pi
        .get(48..)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Length)?;
    let s = Option::from(Scalar::from_canonical_bytes(s_bytes)).ok_or(Error::Signature)?;
    Ok((gamma, c, s))
}

/// A secret key, expanded from its 32-byte seed as RFC 8032 does.
pub struct SecretKey {
    x: Scalar,
    nonce_seed: [u8; 32],
    public: [u8; PUBLIC_KEY_LEN],
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.x.zeroize();
        self.nonce_seed.zeroize();
    }
}

impl SecretKey {
    /// Expands `seed`.
    pub fn from_seed(seed: &Secret<32>) -> Self {
        let mut hashed: [u8; 64] = Sha512::digest(seed.expose()).into();
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(hashed.get(..32).unwrap_or(&[0; 32]));
        x_bytes[0] &= 248;
        x_bytes[31] &= 127;
        x_bytes[31] |= 64;
        let x = Scalar::from_bytes_mod_order(x_bytes);
        let mut nonce_seed = [0u8; 32];
        nonce_seed.copy_from_slice(hashed.get(32..).unwrap_or(&[0; 32]));
        let public = (x * B).compress().to_bytes();
        hashed.zeroize();
        x_bytes.zeroize();
        SecretKey {
            x,
            nonce_seed,
            public,
        }
    }

    /// The public key.
    pub const fn public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// `ECVRF_prove(SK, alpha)`.
    pub fn prove(&self, alpha: &[u8]) -> Result<[u8; PROOF_LEN], Error> {
        let h_point = encode_to_curve(&self.public, alpha)?;
        let h_string = h_point.compress();
        let gamma = self.x * h_point;
        let mut k_hash = Sha512::new();
        k_hash.update(self.nonce_seed);
        k_hash.update(h_string.as_bytes());
        let mut k_bytes: [u8; 64] = k_hash.finalize().into();
        let k = Scalar::from_bytes_mod_order_wide(&k_bytes);
        k_bytes.zeroize();
        let u = k * B;
        let v = k * h_point;
        let y = point_from_bytes(&self.public)?;
        let c = challenge([&y, &h_point, &gamma, &u, &v]);
        let s = k + c * self.x;
        let mut pi = [0u8; PROOF_LEN];
        if let Some(part) = pi.get_mut(..32) {
            part.copy_from_slice(gamma.compress().as_bytes());
        }
        if let Some(part) = pi.get_mut(32..48) {
            part.copy_from_slice(c.to_bytes().get(..CHALLENGE_LEN).unwrap_or(&[0; 16]));
        }
        if let Some(part) = pi.get_mut(48..) {
            part.copy_from_slice(&s.to_bytes());
        }
        Ok(pi)
    }

    /// `ECVRF_proof_to_hash(ECVRF_prove(SK, alpha))`.
    pub fn hash(&self, alpha: &[u8]) -> Result<[u8; OUTPUT_LEN], Error> {
        let pi = self.prove(alpha)?;
        proof_to_hash(&pi)
    }
}

/// A public key that passed `ECVRF_validate_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    point: EdwardsPoint,
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    /// Decodes and validates a key: canonical, and not of low order.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, Error> {
        let point = point_from_bytes(bytes)?;
        if point.is_small_order() {
            return Err(Error::Key);
        }
        Ok(PublicKey {
            point,
            bytes: *bytes,
        })
    }

    /// The bytes.
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.bytes
    }

    /// `ECVRF_verify(Y, pi, alpha)`, which returns `beta` when the proof
    /// holds.
    pub fn verify(&self, alpha: &[u8], pi: &[u8; PROOF_LEN]) -> Result<[u8; OUTPUT_LEN], Error> {
        let (gamma, c, s) = decode_proof(pi)?;
        let h_point = encode_to_curve(&self.bytes, alpha)?;
        let u = s * B - c * self.point;
        let v = s * h_point - c * gamma;
        let expected = challenge([&self.point, &h_point, &gamma, &u, &v]);
        if bool::from(expected.to_bytes().ct_eq(&c.to_bytes())) {
            Ok(gamma_to_hash(&gamma))
        } else {
            Err(Error::Signature)
        }
    }
}

/// `ECVRF_proof_to_hash(pi)`, without a verification.
pub fn proof_to_hash(pi: &[u8; PROOF_LEN]) -> Result<[u8; OUTPUT_LEN], Error> {
    let (gamma, _, _) = decode_proof(pi)?;
    Ok(gamma_to_hash(&gamma))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_rfc_9381_vectors_of_the_tai_suite_hold() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
                "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
                "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
                "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
            ),
        ];
        for (sk, pk, alpha, pi, beta) in cases {
            let key = SecretKey::from_seed(&Secret::new(hex(sk).try_into().unwrap()));
            assert_eq!(key.public()[..], hex(pk)[..]);
            let alpha = hex(alpha);
            let proof = key.prove(&alpha).unwrap();
            assert_eq!(proof[..], hex(pi)[..]);
            assert_eq!(key.hash(&alpha).unwrap()[..], hex(beta)[..]);
            let public = PublicKey::from_bytes(key.public()).unwrap();
            assert_eq!(public.verify(&alpha, &proof).unwrap()[..], hex(beta)[..]);
            assert_eq!(proof_to_hash(&proof).unwrap()[..], hex(beta)[..]);
            let mut wrong_alpha = alpha.clone();
            wrong_alpha.push(1);
            assert!(public.verify(&wrong_alpha, &proof).is_err());
            let mut bad = proof;
            bad[50] ^= 1;
            assert!(public.verify(&alpha, &bad).is_err());
        }
    }

    #[test]
    fn a_low_order_key_a_non_canonical_point_and_a_large_s_are_rejected() {
        // The identity is a low-order point.
        let identity = EdwardsPoint::default().compress().to_bytes();
        assert_eq!(PublicKey::from_bytes(&identity), Err(Error::Key));
        // y = p + 1 is a non-canonical encoding of the point with y = 1.
        let mut non_canonical = [0u8; 32];
        non_canonical[0] = 0xEE;
        for b in non_canonical.iter_mut().skip(1).take(30) {
            *b = 0xFF;
        }
        non_canonical[31] = 0x7F;
        assert_eq!(PublicKey::from_bytes(&non_canonical), Err(Error::Key));
        let key = SecretKey::from_seed(&Secret::new([5; 32]));
        let mut pi = key.prove(b"x").unwrap();
        pi[48..].copy_from_slice(&[0xFF; 32]);
        assert_eq!(proof_to_hash(&pi), Err(Error::Signature));
    }
}
