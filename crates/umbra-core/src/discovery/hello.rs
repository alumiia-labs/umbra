//! The hello of Part 9 §9.6: the sealed envelope to the entry key, and the
//! derived proof-of-work values of Part 13 §13.4. The client keeps the
//! inbound limit and the spent nonces of a Profile in its store.

use alloc::vec::Vec;

use umbra_crypto::{
    aead,
    hash::sha3_256,
    hkdf::Hkdf,
    kem::{self, Ciphertext, KeyPair, PublicKey, CIPHERTEXT_LEN},
    labels,
    rand_core::CryptoRng,
    secret::Secret,
    sha3::Sha3_256,
};
use umbra_wire::{
    admission::{Admission, AdmissionKind},
    codec::{Reader, Writer},
};

use super::HELLO_POW_EFFORT;
use crate::{identity::invitation::Bundle, Error};

/// The version byte of a hello envelope.
pub const VERSION: u8 = 0x01;
/// The bytes before the sealed body: the version, the encapsulation, and
/// the nonce.
pub const HEADER_LEN: usize = 1 + CIPHERTEXT_LEN + 24;

/// The plaintext of a hello: the invitation fields, the profile the
/// initiator shows, and the admission at the end (`DIS-086`, `DIS-131`).
pub struct HelloBody<'a> {
    /// The fresh invitation fields of Part 5 §5.4.1.
    pub bundle: Bundle<'a>,
    /// The profile blob plaintext of Part 4 §4.2.5.
    pub profile: &'a [u8],
    /// A cross-relay token or a proof-of-work solution (`DIS-132`).
    pub admission: Admission<'a>,
}

impl<'a> HelloBody<'a> {
    /// The plaintext length.
    pub fn len(&self) -> usize {
        2 + self.bundle.len() + 2 + self.profile.len() + self.admission.len()
    }

    /// Whether the profile is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.profile.is_empty()
    }

    /// Writes the plaintext.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u16(u16::try_from(self.bundle.len()).map_err(|_| Error::Malformed)?)?;
        let n = self.bundle.encode(w.tail())?;
        let mut at = w.position().saturating_add(n);
        let mut w = Writer::new(out.get_mut(at..).ok_or(Error::Malformed)?);
        w.u16(u16::try_from(self.profile.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.profile)?;
        let n = self.admission.encode(w.tail())?;
        at = at.saturating_add(w.position()).saturating_add(n);
        Ok(at)
    }

    /// Reads the plaintext. An admission of kind `0x00` is rejected
    /// (`ABU-085`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let bundle_len = usize::from(r.u16()?);
        let bundle = Bundle::parse(r.take(bundle_len)?)?;
        let profile_len = usize::from(r.u16()?);
        let profile = r.take(profile_len)?;
        let rest = r.rest();
        let (admission, used) = Admission::parse(rest)?;
        if used != rest.len() || admission.kind == AdmissionKind::None {
            return Err(Error::Malformed);
        }
        Ok(HelloBody {
            bundle,
            profile,
            admission,
        })
    }
}

/// The hello key: HKDF-SHA3-256 with the shared secret as the key
/// material and the label then the entry key as the info.
fn hello_key(ss: &Secret<32>, entry_pk: &[u8]) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(None, ss.expose());
    let mut key = Secret::<32>::zeroed();
    let _ = kdf.expand_multi_info(&[labels::HELLO, entry_pk], key.expose_mut());
    key
}

/// Seals a hello to `entry_pk`, which is `HK_pub` or `address_pk`
/// (`DIS-110`). The envelope is the version, the encapsulation, the
/// nonce, and the ciphertext with its tag.
pub fn seal<R: CryptoRng + ?Sized>(
    entry_pk: &[u8],
    body: &HelloBody<'_>,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let pk = PublicKey::from_bytes(entry_pk)?;
    let (ct, ss) = kem::encapsulate(&pk, rng);
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let mut out = alloc::vec![0u8; HEADER_LEN + body.len() + aead::TAG_LEN];
    let mut w = Writer::new(&mut out);
    w.u8(VERSION)?;
    w.put(ct.as_bytes())?;
    w.put(&nonce)?;
    let n = body.encode(w.tail())?;
    let end = HEADER_LEN.saturating_add(n);
    let plain = out.get_mut(HEADER_LEN..end).ok_or(Error::Malformed)?;
    let tag = aead::seal(&hello_key(&ss, entry_pk), &nonce, ct.as_bytes(), plain)?;
    out.get_mut(end..)
        .ok_or(Error::Malformed)?
        .copy_from_slice(&tag);
    Ok(out)
}

/// Opens a hello with the private half of the entry key, and returns the
/// plaintext.
pub fn open(entry_key: &KeyPair, envelope: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(envelope);
    if r.u8()? != VERSION {
        return Err(Error::Malformed);
    }
    let ct_bytes = r.take(CIPHERTEXT_LEN)?;
    let nonce: [u8; 24] = r.array()?;
    let rest = r.rest();
    if rest.len() < aead::TAG_LEN {
        return Err(Error::Malformed);
    }
    let split = rest.len().saturating_sub(aead::TAG_LEN);
    let mut plain = rest.get(..split).ok_or(Error::Malformed)?.to_vec();
    let tag = rest.get(split..).ok_or(Error::Malformed)?;
    let ct = Ciphertext::from_bytes(ct_bytes)?;
    let ss = entry_key.decapsulate(&ct)?;
    let entry_pk = entry_key.public().to_bytes();
    aead::open(
        &hello_key(&ss, &entry_pk),
        &nonce,
        ct_bytes,
        &mut plain,
        tag,
    )?;
    Ok(plain)
}

/// The derived proof-of-work challenge of a hello (Part 13 §13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloPow {
    /// `SHA3-256("umbra/v1/hello-verifier" || entry_pk)`.
    pub verifier_id: [u8; 32],
    /// `SHA3-256("umbra/v1/hello-seed" || entry_pk || BE32(epoch))`.
    pub seed: [u8; 32],
    /// `HELLO_POW_EFFORT`.
    pub effort: u8,
}

impl HelloPow {
    /// The challenge values for `entry_pk` at `epoch` (`ABU-082`).
    pub fn derive(entry_pk: &[u8], epoch: u32) -> Self {
        HelloPow {
            verifier_id: sha3_256(&[labels::HELLO_VERIFIER, entry_pk]),
            seed: sha3_256(&[labels::HELLO_SEED, entry_pk, &epoch.to_be_bytes()]),
            effort: HELLO_POW_EFFORT,
        }
    }

    /// The seeds an addressee accepts at `epoch`: the current epoch and
    /// the one before it (`ABU-083`).
    pub fn accepted_seeds(entry_pk: &[u8], epoch: u32) -> [[u8; 32]; 2] {
        [
            Self::derive(entry_pk, epoch).seed,
            Self::derive(entry_pk, epoch.wrapping_sub(1)).seed,
        ]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::discovery::entry::tests::queue;
    use umbra_crypto::hierarchy::RootIdentity;

    struct Rng(u64);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            Ok((self.0 >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?) << 32 | u64::from(self.try_next_u32()?))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for b in dest {
                *b = self.try_next_u32()? as u8;
            }
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    #[test]
    fn a_hello_opens_at_the_entry_key_only_and_needs_an_admission() {
        let root = RootIdentity::new(Secret::new([1; 32]));
        let hk = root.handle_key(0, 0);
        let other = root.handle_key(0, 1);
        let ek = [3u8; 1_184];
        let body = HelloBody {
            bundle: Bundle {
                responder_static_x25519: [2; 32],
                responder_kem_ek: &ek,
                version_range: [1, 1],
                queue_address: queue(4),
                relay_bundle: b"relays",
            },
            profile: b"Alice",
            admission: Admission {
                kind: AdmissionKind::Pow,
                body: &[9; 69],
            },
        };
        let mut rng = Rng(11);
        let envelope = seal(&hk.public().to_bytes(), &body, &mut rng).unwrap();
        assert_eq!(envelope.len(), HEADER_LEN + body.len() + aead::TAG_LEN);
        let plain = open(&hk, &envelope).unwrap();
        let back = HelloBody::parse(&plain).unwrap();
        assert_eq!(back.profile, b"Alice");
        assert_eq!(back.bundle.relay_bundle, b"relays");
        assert_eq!(back.admission.kind, AdmissionKind::Pow);
        assert!(open(&other, &envelope).is_err());
        let mut corrupt = envelope.clone();
        corrupt[HEADER_LEN + 3] ^= 1;
        assert!(open(&hk, &corrupt).is_err());

        let none = HelloBody {
            admission: Admission::NONE,
            ..body
        };
        let mut plain = alloc::vec![0u8; none.len()];
        let n = none.encode(&mut plain).unwrap();
        assert!(HelloBody::parse(&plain[..n]).is_err());
    }

    #[test]
    fn the_pow_values_hold() {
        let pow = HelloPow::derive(&[1; 1_216], 5);
        assert_eq!(pow.effort, HELLO_POW_EFFORT);
        assert_ne!(pow.seed, HelloPow::derive(&[1; 1_216], 6).seed);
        assert_eq!(HelloPow::accepted_seeds(&[1; 1_216], 6)[1], pow.seed);
    }
}
