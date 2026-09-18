//! The VOPRF of RFC 9497 over ristretto255 with SHA-512, which is AUX-2 of
//! Part 5 §5.1: the blind directory lookup of Part 9 §9.4 and the
//! first-party token of Part 14 §14.3.2.
//!
//! The client blinds its input, the server evaluates the blinded element
//! under its key with a DLEQ proof, and the client unblinds and verifies.
//! The server never sees the input, and the client never sees the key.

use alloc::vec::Vec;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{secret::Secret, Error};

/// A serialized group element.
pub const ELEMENT_LEN: usize = 32;
/// A serialized scalar.
pub const SCALAR_LEN: usize = 32;
/// A DLEQ proof, which is `c || s`.
pub const PROOF_LEN: usize = 64;
/// The output of the function.
pub const OUTPUT_LEN: usize = 64;

/// `"OPRFV1-" || I2OSP(mode, 1) || "-" || "ristretto255-SHA512"` at the
/// VOPRF mode.
const CONTEXT: &[u8] = b"OPRFV1-\x01-ristretto255-SHA512";

/// `expand_message_xmd` of RFC 9380 with SHA-512 for one block of 64
/// bytes, which every use here needs.
fn expand_message_xmd(parts: &[&[u8]], dst_parts: &[&[u8]]) -> [u8; 64] {
    let dst_len = dst_parts.iter().map(|p| p.len()).sum::<usize>();
    let dst_len_byte = [u8::try_from(dst_len).unwrap_or(u8::MAX)];
    let mut h = Sha512::new();
    h.update([0u8; 128]);
    for part in parts {
        h.update(part);
    }
    h.update([0u8, 64, 0]);
    for part in dst_parts {
        h.update(part);
    }
    h.update(dst_len_byte);
    let b0: [u8; 64] = h.finalize().into();
    let mut h = Sha512::new();
    h.update(b0);
    h.update([1u8]);
    for part in dst_parts {
        h.update(part);
    }
    h.update(dst_len_byte);
    h.finalize().into()
}

fn hash_to_group(parts: &[&[u8]]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&expand_message_xmd(parts, &[b"HashToGroup-", CONTEXT]))
}

fn hash_to_scalar(parts: &[&[u8]], dst_parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&expand_message_xmd(parts, dst_parts))
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Option::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::Key)
}

fn element_from_bytes(bytes: &[u8; 32]) -> Result<RistrettoPoint, Error> {
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| Error::Key)?
        .decompress()
        .ok_or(Error::Key)
}

fn len_prefix(part: &[u8]) -> [u8; 2] {
    u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes()
}

/// `ComputeComposites` for one element, which is the only batch size
/// this crate uses.
fn composites(pk: &[u8; 32], c: &[u8; 32], d: &[u8; 32]) -> (Scalar, RistrettoPoint) {
    let seed_dst: &[u8] = b"Seed-";
    let mut h = Sha512::new();
    h.update(len_prefix(pk));
    h.update(pk);
    h.update(len_prefix(&[seed_dst, CONTEXT].concat()));
    h.update(seed_dst);
    h.update(CONTEXT);
    let seed: [u8; 64] = h.finalize().into();
    let di = hash_to_scalar(
        &[
            &len_prefix(&seed),
            &seed,
            &[0u8, 0],
            &len_prefix(c),
            c,
            &len_prefix(d),
            d,
            b"Composite",
        ],
        &[b"HashToScalar-", CONTEXT],
    );
    (di, RistrettoPoint::default())
}

fn challenge(
    pk: &[u8; 32],
    m: &RistrettoPoint,
    z: &RistrettoPoint,
    t2: &RistrettoPoint,
    t3: &RistrettoPoint,
) -> Scalar {
    let a0 = m.compress().to_bytes();
    let a1 = z.compress().to_bytes();
    let a2 = t2.compress().to_bytes();
    let a3 = t3.compress().to_bytes();
    hash_to_scalar(
        &[
            &len_prefix(pk),
            pk,
            &len_prefix(&a0),
            &a0,
            &len_prefix(&a1),
            &a1,
            &len_prefix(&a2),
            &a2,
            &len_prefix(&a3),
            &a3,
            b"Challenge",
        ],
        &[b"HashToScalar-", CONTEXT],
    )
}

/// The server key.
pub struct ServerKey {
    secret: Scalar,
    public: [u8; 32],
}

impl Drop for ServerKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ServerKey {
    fn from_scalar(secret: Scalar) -> Self {
        let public = (secret * G).compress().to_bytes();
        ServerKey { secret, public }
    }

    /// `DeriveKeyPair(seed, info)` of RFC 9497 §3.2.1.
    pub fn derive(seed: &Secret<32>, info: &[u8]) -> Result<Self, Error> {
        for counter in 0u8..=255 {
            let secret = hash_to_scalar(
                &[seed.expose(), &len_prefix(info), info, &[counter]],
                &[b"DeriveKeyPair", CONTEXT],
            );
            if secret != Scalar::ZERO {
                return Ok(Self::from_scalar(secret));
            }
        }
        Err(Error::Key)
    }

    /// A key from a fresh random scalar.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut wide = [0u8; 64];
        rng.try_fill_bytes(&mut wide).map_err(|_| Error::Rng)?;
        let secret = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        if secret == Scalar::ZERO {
            return Err(Error::Rng);
        }
        Ok(Self::from_scalar(secret))
    }

    /// The key from its canonical scalar bytes.
    pub fn from_bytes(bytes: &Secret<32>) -> Result<Self, Error> {
        let secret = scalar_from_bytes(bytes.expose())?;
        if secret == Scalar::ZERO {
            return Err(Error::Key);
        }
        Ok(Self::from_scalar(secret))
    }

    /// The canonical scalar bytes.
    pub fn to_bytes(&self) -> Secret<32> {
        Secret::new(self.secret.to_bytes())
    }

    /// The public key `pkS`.
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// `BlindEvaluate`: the evaluated element and the proof, with the
    /// proof scalar from `rng`.
    pub fn evaluate<R: TryCryptoRng + ?Sized>(
        &self,
        blinded: &[u8; ELEMENT_LEN],
        rng: &mut R,
    ) -> Result<Evaluation, Error> {
        let mut wide = [0u8; 64];
        rng.try_fill_bytes(&mut wide).map_err(|_| Error::Rng)?;
        let r = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        self.evaluate_with(blinded, r)
    }

    /// `BlindEvaluate` with a given proof scalar, for the known-answer
    /// tests.
    pub fn evaluate_with(
        &self,
        blinded: &[u8; ELEMENT_LEN],
        r: Scalar,
    ) -> Result<Evaluation, Error> {
        let blinded_point = element_from_bytes(blinded)?;
        let evaluated_point = self.secret * blinded_point;
        let element = evaluated_point.compress().to_bytes();
        let (di, _) = composites(&self.public, blinded, &element);
        let m = di * blinded_point;
        let z = self.secret * m;
        let t2 = r * G;
        let t3 = r * m;
        let c = challenge(&self.public, &m, &z, &t2, &t3);
        let s = r - c * self.secret;
        let mut proof = [0u8; PROOF_LEN];
        if let Some(head) = proof.get_mut(..32) {
            head.copy_from_slice(&c.to_bytes());
        }
        if let Some(tail) = proof.get_mut(32..) {
            tail.copy_from_slice(&s.to_bytes());
        }
        Ok(Evaluation { element, proof })
    }

    /// `Evaluate`: the output for `input` at the server itself, which the
    /// token issuer uses to check a redeemed token.
    pub fn evaluate_direct(&self, input: &[u8]) -> [u8; OUTPUT_LEN] {
        let point = self.secret * hash_to_group(&[input]);
        finalize_hash(input, &point.compress().to_bytes())
    }
}

/// The answer of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    /// The evaluated element.
    pub element: [u8; ELEMENT_LEN],
    /// The DLEQ proof.
    pub proof: [u8; PROOF_LEN],
}

/// The state a client holds between its blind and its finalize.
pub struct BlindState {
    blind: Scalar,
    input: Vec<u8>,
}

impl Drop for BlindState {
    fn drop(&mut self) {
        self.blind.zeroize();
        self.input.zeroize();
    }
}

impl BlindState {
    /// `Blind`: the state and the blinded element for `input`, with the
    /// blind from `rng`.
    pub fn blind<R: TryCryptoRng + ?Sized>(
        input: &[u8],
        rng: &mut R,
    ) -> Result<(Self, [u8; ELEMENT_LEN]), Error> {
        let mut wide = [0u8; 64];
        rng.try_fill_bytes(&mut wide).map_err(|_| Error::Rng)?;
        let blind = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        Self::blind_with(input, blind)
    }

    /// `Blind` with a given blind scalar, for the known-answer tests.
    pub fn blind_with(input: &[u8], blind: Scalar) -> Result<(Self, [u8; ELEMENT_LEN]), Error> {
        if blind == Scalar::ZERO {
            return Err(Error::Rng);
        }
        let element = (blind * hash_to_group(&[input])).compress().to_bytes();
        Ok((
            BlindState {
                blind,
                input: input.to_vec(),
            },
            element,
        ))
    }

    /// The blinded element again, for a retry of the same request.
    pub fn blinded_element(&self) -> [u8; ELEMENT_LEN] {
        (self.blind * hash_to_group(&[&self.input]))
            .compress()
            .to_bytes()
    }

    /// `Finalize`: verifies the proof under `pk` and returns the output.
    pub fn finalize(
        &self,
        evaluation: &Evaluation,
        pk: &[u8; ELEMENT_LEN],
    ) -> Result<[u8; OUTPUT_LEN], Error> {
        let blinded = self.blinded_element();
        verify_proof(pk, &blinded, evaluation)?;
        let evaluated_point = element_from_bytes(&evaluation.element)?;
        let unblinded = (self.blind.invert() * evaluated_point)
            .compress()
            .to_bytes();
        Ok(finalize_hash(&self.input, &unblinded))
    }
}

/// `VerifyProof` for one element.
pub fn verify_proof(
    pk: &[u8; ELEMENT_LEN],
    blinded: &[u8; ELEMENT_LEN],
    evaluation: &Evaluation,
) -> Result<(), Error> {
    let pk_point = element_from_bytes(pk)?;
    let blinded_point = element_from_bytes(blinded)?;
    let evaluated_point = element_from_bytes(&evaluation.element)?;
    let c_bytes: [u8; 32] = evaluation
        .proof
        .get(..32)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Length)?;
    let s_bytes: [u8; 32] = evaluation
        .proof
        .get(32..)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Length)?;
    let c = scalar_from_bytes(&c_bytes)?;
    let s = scalar_from_bytes(&s_bytes)?;
    let (di, _) = composites(pk, blinded, &evaluation.element);
    let m = di * blinded_point;
    let z = di * evaluated_point;
    let t2 = s * G + c * pk_point;
    let t3 = s * m + c * z;
    let expected = challenge(pk, &m, &z, &t2, &t3);
    if bool::from(expected.to_bytes().ct_eq(&c_bytes)) {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}

fn finalize_hash(input: &[u8], unblinded: &[u8; 32]) -> [u8; OUTPUT_LEN] {
    let mut h = Sha512::new();
    h.update(len_prefix(input));
    h.update(input);
    h.update(len_prefix(unblinded));
    h.update(unblinded);
    h.update(b"Finalize");
    h.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn scalar(s: &str) -> Scalar {
        Scalar::from_canonical_bytes(hex(s).try_into().unwrap()).unwrap()
    }

    #[test]
    fn the_rfc_9497_vectors_hold_at_the_voprf_mode() {
        let seed = Secret::new(
            hex("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3")
                .try_into()
                .unwrap(),
        );
        let key = ServerKey::derive(&seed, b"test key").unwrap();
        // The mode byte is in the derivation context, thus the VOPRF-mode
        // key differs from the OPRF-mode key of the same seed.
        assert_eq!(
            key.to_bytes().expose()[..],
            hex("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909")[..]
        );
        assert_eq!(
            key.public()[..],
            hex("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e")[..]
        );
        let blind = scalar("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
        let r = scalar("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e");
        let cases = [
            (
                "00",
                "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
                "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
                "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d",
                "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c",
            ),
            (
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c",
                "60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468",
                "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02",
                "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6",
            ),
        ];
        for (input, blinded, evaluated, proof, output) in cases {
            let input = hex(input);
            let (state, element) = BlindState::blind_with(&input, blind).unwrap();
            assert_eq!(element[..], hex(blinded)[..]);
            let evaluation = key.evaluate_with(&element, r).unwrap();
            assert_eq!(evaluation.element[..], hex(evaluated)[..]);
            assert_eq!(evaluation.proof[..], hex(proof)[..]);
            let out = state.finalize(&evaluation, key.public()).unwrap();
            assert_eq!(out[..], hex(output)[..]);
            assert_eq!(key.evaluate_direct(&input), out);

            // A proof under another key, a changed element, and a changed
            // proof byte each fail.
            let other = ServerKey::derive(&seed, b"other").unwrap();
            assert_eq!(
                state.finalize(&evaluation, other.public()),
                Err(Error::Auth)
            );
            let mut bad = evaluation;
            bad.proof[40] ^= 1;
            assert_eq!(state.finalize(&bad, key.public()), Err(Error::Auth));
            let mut forged = evaluation;
            forged.element = other.evaluate_with(&element, r).unwrap().element;
            assert_eq!(state.finalize(&forged, key.public()), Err(Error::Auth));
        }
    }

    #[test]
    fn a_random_blind_gives_the_same_output_as_the_server() {
        let mut rng = crate::test_rng::TestRng::new(b"voprf");
        let key = ServerKey::generate(&mut rng).unwrap();
        let (state, element) = BlindState::blind(b"@alice#1234", &mut rng).unwrap();
        let evaluation = key.evaluate(&element, &mut rng).unwrap();
        let out = state.finalize(&evaluation, key.public()).unwrap();
        assert_eq!(out, key.evaluate_direct(b"@alice#1234"));
        assert_ne!(out, key.evaluate_direct(b"@alice#1235"));
        let again = ServerKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(again.public(), key.public());
    }
}
