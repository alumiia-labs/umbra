//! The one-shot seal to an X25519 key of Part 10 §10.4.2: a fresh ephemeral
//! key, `HKDF-SHA3-256` over the shared value with `ephemeral || recipient`
//! as the salt and the label as the info, and ChaCha20-Poly1305 under a nonce
//! of zero bytes, because each key seals one plaintext.
//!
//! The seal is X25519 alone and not post-quantum. It serves the link-fault
//! report, which must fit the L6 record of a `B0` cell; the Cause note of
//! Part 10 §10.4.2 gives the reason and the cost.

use alloc::vec::Vec;

use hkdf::SimpleHkdf;
use rand_core::CryptoRng;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    aead::{self, TAG_LEN},
    kem::clamp,
    secret::Secret,
    Error,
};

/// The bytes that a seal adds to its plaintext: the ephemeral key and the tag.
pub const OVERHEAD: usize = 32 + TAG_LEN;

/// The X25519 public key of a secret scalar.
pub fn public_of(secret: &Secret<32>) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(clamp(*secret.expose()))).to_bytes()
}

fn key_of(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32], label: &[u8]) -> Result<Secret<32>, Error> {
    // A non-contributory output names no secret.
    if shared == &[0u8; 32] {
        return Err(Error::Key);
    }
    let salt = [ephemeral.as_slice(), recipient].concat();
    let hkdf = SimpleHkdf::<Sha3_256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hkdf.expand(label, &mut key).map_err(|_| Error::Length)?;
    Ok(Secret::new(key))
}

/// Seals `plain` to `recipient` under `label`: the ephemeral public key, then
/// the ciphertext and its tag.
pub fn seal<R: CryptoRng + ?Sized>(
    recipient: &[u8; 32],
    label: &[u8],
    plain: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let mut scalar = [0u8; 32];
    rng.fill_bytes(&mut scalar);
    let ephemeral = StaticSecret::from(clamp(scalar));
    let ephemeral_pk = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient)).to_bytes();
    let key = key_of(&shared, &ephemeral_pk, recipient, label)?;
    let mut body = plain.to_vec();
    let tag = aead::seal_ietf(&key, &[0u8; aead::NONCE_LEN_IETF], &[], &mut body)?;
    let mut out = Vec::with_capacity(plain.len().saturating_add(OVERHEAD));
    out.extend_from_slice(&ephemeral_pk);
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens a seal of [`seal`] with the secret scalar of the recipient.
pub fn open(secret: &Secret<32>, label: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < OVERHEAD {
        return Err(Error::Length);
    }
    let (ephemeral_pk, rest) = sealed.split_at(32);
    let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
    let ephemeral_pk: [u8; 32] = ephemeral_pk.try_into().map_err(|_| Error::Length)?;
    let own = StaticSecret::from(clamp(*secret.expose()));
    let recipient = PublicKey::from(&own).to_bytes();
    let shared = own.diffie_hellman(&PublicKey::from(ephemeral_pk)).to_bytes();
    let key = key_of(&shared, &ephemeral_pk, &recipient, label)?;
    let mut plain = body.to_vec();
    aead::open_ietf(&key, &[0u8; aead::NONCE_LEN_IETF], &[], &mut plain, tag)?;
    Ok(plain)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;

    #[test]
    fn a_seal_opens_under_its_key_and_label_alone() {
        let mut rng = TestRng::new(b"seal");
        let secret = Secret::new([5; 32]);
        let pk = public_of(&secret);
        let sealed = seal(&pk, b"umbra/v1/link-fault-seal", b"report", &mut rng).unwrap();
        assert_eq!(sealed.len(), 6 + OVERHEAD);
        assert_eq!(open(&secret, b"umbra/v1/link-fault-seal", &sealed).unwrap(), b"report");
        assert!(open(&secret, b"umbra/v1/other", &sealed).is_err());
        assert!(open(&Secret::new([6; 32]), b"umbra/v1/link-fault-seal", &sealed).is_err());
        let mut torn = sealed.clone();
        torn[40] ^= 1;
        assert!(open(&secret, b"umbra/v1/link-fault-seal", &torn).is_err());
        // Two seals of one plaintext differ.
        let again = seal(&pk, b"umbra/v1/link-fault-seal", b"report", &mut rng).unwrap();
        assert_ne!(again, sealed);
    }
}
