//! The lease renewal challenge of Part 9 §9.9.1 and the write
//! authorization of §9.9.3. Both prove that a party holds the private half
//! of the `HK_pub` that the directory holds, with `UMBRA-KEM` and
//! HMAC-SHA3-256 and nothing more.

use alloc::vec::Vec;

use umbra_crypto::{
    ct_eq,
    hash::sha3_256,
    hkdf::Hkdf,
    hmac::{digest::KeyInit, Hmac, Mac},
    kem::{self, Ciphertext, KeyPair, PublicKey, SharedSecret, CIPHERTEXT_LEN},
    labels,
    rand_core::CryptoRng,
    secret::Secret,
    sha3::Sha3_256,
};

use crate::Error;

/// The nonce of a challenge.
pub const NONCE_LEN: usize = 16;
/// The answer, an HMAC-SHA3-256 tag.
pub const ANSWER_LEN: usize = 32;
/// The bytes the directory sends: `ct || nonce`.
pub const CHALLENGE_LEN: usize = CIPHERTEXT_LEN + NONCE_LEN;

/// What a challenge proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A lease renewal at `lease_epoch` (§9.9.1).
    Renew {
        /// The lease epoch the directory issued.
        lease_epoch: u64,
    },
    /// A write of `version_new` (§9.9.3).
    Write {
        /// The version of the entry the writer sends.
        version_new: u32,
    },
    /// A write of the profile blob of the label, which the answer binds
    /// (`DIS-175`).
    Blob,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::Renew { .. } => labels::HANDLE_RENEW,
            Purpose::Write { .. } => labels::HANDLE_WRITE,
            Purpose::Blob => labels::HANDLE_BLOB,
        }
    }

    /// Whether the answer binds the bytes that it authorizes.
    const fn binds(self) -> bool {
        matches!(self, Purpose::Write { .. } | Purpose::Blob)
    }

    fn info_tail(self) -> Vec<u8> {
        match self {
            Purpose::Renew { lease_epoch } => lease_epoch.to_be_bytes().to_vec(),
            Purpose::Write { version_new } => version_new.to_be_bytes().to_vec(),
            Purpose::Blob => Vec::new(),
        }
    }
}

/// `k = HKDF-SHA3-256(salt = label, ikm = ss, info = handle || tail)`.
fn derive_k(purpose: Purpose, ss: &SharedSecret, handle: &[u8]) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(Some(purpose.label()), ss.expose());
    let mut k = Secret::<32>::zeroed();
    let _ = kdf.expand_multi_info(&[handle, &purpose.info_tail()], k.expose_mut());
    k
}

fn answer_of(
    k: &Secret<32>,
    nonce: &[u8; NONCE_LEN],
    entry_new: Option<&[u8]>,
) -> [u8; ANSWER_LEN] {
    // A 32-byte key is inside the HMAC key bound, thus this cannot fail.
    let mut mac = Hmac::<Sha3_256>::new_from_slice(k.expose())
        .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()));
    mac.update(nonce);
    if let Some(entry) = entry_new {
        mac.update(&sha3_256(&[entry]));
    }
    mac.finalize().into_bytes().into()
}

/// A challenge the directory issued and holds until the answer arrives.
pub struct Issued {
    purpose: Purpose,
    expected_k: Secret<32>,
    nonce: [u8; NONCE_LEN],
    bytes: [u8; CHALLENGE_LEN],
}

impl Issued {
    /// Encapsulates to `hk_pub` and draws the nonce from `rng` (`DIS-035`,
    /// `DIS-036`, `DIS-094`). The `handle` is the canonical handle, or the
    /// 20 bytes of an address (`DIS-108`).
    pub fn new<R: CryptoRng + ?Sized>(
        purpose: Purpose,
        hk_pub: &[u8],
        handle: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let pk = PublicKey::from_bytes(hk_pub)?;
        let (ct, ss) = kem::encapsulate(&pk, rng);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let expected_k = derive_k(purpose, &ss, handle);
        let mut bytes = [0u8; CHALLENGE_LEN];
        if let Some(head) = bytes.get_mut(..CIPHERTEXT_LEN) {
            head.copy_from_slice(ct.as_bytes());
        }
        if let Some(tail) = bytes.get_mut(CIPHERTEXT_LEN..) {
            tail.copy_from_slice(&nonce);
        }
        // The shared secret leaves with the encapsulation (DIS-042,
        // DIS-100); the directory holds `k` until the answer.
        Ok(Issued {
            purpose,
            expected_k,
            nonce,
            bytes,
        })
    }

    /// `ct || nonce`, which the directory sends.
    pub const fn bytes(&self) -> &[u8; CHALLENGE_LEN] {
        &self.bytes
    }

    /// The purpose.
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Verifies an answer in constant time (`DIS-039`, `DIS-097`). A
    /// write answer carries the entry it authorizes, and the entry's
    /// `version` must be `version_new` (`DIS-099`).
    pub fn verify(self, answer: &[u8], entry_new: Option<&[u8]>) -> Result<(), Error> {
        if entry_new.is_some() != self.purpose.binds() {
            return Err(Error::Malformed);
        }
        let expected = answer_of(&self.expected_k, &self.nonce, entry_new);
        if ct_eq(&expected, answer) {
            Ok(())
        } else {
            Err(Error::Unverified)
        }
    }
}

/// Answers a challenge with the private half of `HK_pub` (`DIS-037`,
/// `DIS-038`, `DIS-095`, `DIS-096`).
pub fn answer(
    purpose: Purpose,
    hk: &KeyPair,
    handle: &[u8],
    challenge: &[u8],
    entry_new: Option<&[u8]>,
) -> Result<[u8; ANSWER_LEN], Error> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(Error::Malformed);
    }
    if entry_new.is_some() != purpose.binds() {
        return Err(Error::Malformed);
    }
    let ct = Ciphertext::from_bytes(challenge.get(..CIPHERTEXT_LEN).ok_or(Error::Malformed)?)?;
    let nonce: [u8; NONCE_LEN] = challenge
        .get(CIPHERTEXT_LEN..)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Malformed)?;
    let ss = hk.decapsulate(&ct)?;
    let k = derive_k(purpose, &ss, handle);
    Ok(answer_of(&k, &nonce, entry_new))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
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
    fn a_renewal_and_a_write_verify_and_each_wrong_input_fails() {
        let root = RootIdentity::new(Secret::new([1; 32]));
        let hk = root.handle_key(0, 0);
        let other = root.handle_key(0, 1);
        let mut rng = Rng(9);
        let handle = b"@alice#1234";

        let renew = Purpose::Renew { lease_epoch: 7 };
        let issued = Issued::new(renew, &hk.public().to_bytes(), handle, &mut rng).unwrap();
        let ans = answer(renew, &hk, handle, issued.bytes(), None).unwrap();
        let wrong_key = answer(renew, &other, handle, issued.bytes(), None).unwrap();
        let wrong_epoch = answer(
            Purpose::Renew { lease_epoch: 8 },
            &hk,
            handle,
            issued.bytes(),
            None,
        )
        .unwrap();
        let wrong_handle = answer(renew, &hk, b"@alice#1235", issued.bytes(), None).unwrap();
        assert_ne!(ans, wrong_key);
        assert_ne!(ans, wrong_epoch);
        assert_ne!(ans, wrong_handle);
        assert!(answer(renew, &hk, handle, &issued.bytes()[..10], None).is_err());
        assert!(answer(renew, &hk, handle, issued.bytes(), Some(b"x")).is_err());
        let bytes = *issued.bytes();
        issued.verify(&ans, None).unwrap();
        let again = Issued::new(renew, &hk.public().to_bytes(), handle, &mut rng).unwrap();
        assert_ne!(again.bytes(), &bytes);
        assert_eq!(again.verify(&ans, None), Err(Error::Unverified));

        let write = Purpose::Write { version_new: 4 };
        let entry = b"entry bytes";
        let issued = Issued::new(write, &hk.public().to_bytes(), handle, &mut rng).unwrap();
        let ans = answer(write, &hk, handle, issued.bytes(), Some(entry)).unwrap();
        let other_entry = answer(write, &hk, handle, issued.bytes(), Some(b"other")).unwrap();
        assert_ne!(ans, other_entry);
        assert_eq!(issued.verify(&ans, None), Err(Error::Malformed));
        let issued = Issued::new(write, &hk.public().to_bytes(), handle, &mut rng).unwrap();
        let ans = answer(write, &hk, handle, issued.bytes(), Some(entry)).unwrap();
        issued.verify(&ans, Some(entry)).unwrap();
    }
}
