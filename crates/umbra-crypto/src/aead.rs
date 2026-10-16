//! XChaCha20-Poly1305 with a 24-byte nonce, for the objects at rest and
//! the sealed blobs of Parts 3, 4, 12, and 14. The two functions with the
//! `_ietf` suffix are ChaCha20-Poly1305 with the 12-byte nonce of RFC 8439,
//! for the HPKE seal of the OHTTP request of Part 8.

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag, XChaCha20Poly1305, XNonce,
};

use crate::{secret::Secret, Error};

/// The tag length.
pub const TAG_LEN: usize = 16;
/// The nonce length.
pub const NONCE_LEN: usize = 24;

/// Seals `buf` in place and returns the tag.
pub fn seal(
    key: &Secret<32>,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let tag = XChaCha20Poly1305::new(key.expose().into())
        .encrypt_inout_detached(&XNonce::from(*nonce), ad, buf.into())
        .map_err(|_| Error::Length)?;
    Ok(tag.into())
}

/// Opens `buf` in place.
pub fn open(
    key: &Secret<32>,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Length)?;
    XChaCha20Poly1305::new(key.expose().into())
        .decrypt_inout_detached(&XNonce::from(*nonce), ad, buf.into(), &Tag::from(tag))
        .map_err(|_| Error::Aead)
}

/// The nonce length of the `_ietf` functions.
pub const NONCE_LEN_IETF: usize = 12;

/// Seals `buf` in place under a 12-byte nonce and returns the tag.
pub fn seal_ietf(
    key: &Secret<32>,
    nonce: &[u8; NONCE_LEN_IETF],
    ad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let tag = ChaCha20Poly1305::new(key.expose().into())
        .encrypt_inout_detached(&Nonce::from(*nonce), ad, buf.into())
        .map_err(|_| Error::Length)?;
    Ok(tag.into())
}

/// Opens `buf` in place under a 12-byte nonce.
pub fn open_ietf(
    key: &Secret<32>,
    nonce: &[u8; NONCE_LEN_IETF],
    ad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Length)?;
    ChaCha20Poly1305::new(key.expose().into())
        .decrypt_inout_detached(&Nonce::from(*nonce), ad, buf.into(), &Tag::from(tag))
        .map_err(|_| Error::Aead)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_round_trips_and_binds_its_associated_data() {
        let key = Secret::new([1; 32]);
        let mut buf = *b"backup root";
        let tag = seal(&key, &[2; 24], b"ad", &mut buf).unwrap();
        let mut wrong = buf;
        assert!(open(&key, &[2; 24], b"xx", &mut wrong, &tag).is_err());
        open(&key, &[2; 24], b"ad", &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"backup root");
    }

    #[test]
    fn the_short_nonce_form_round_trips() {
        let key = Secret::new([1; 32]);
        let mut buf = *b"metadata";
        let tag = seal_ietf(&key, &[3; 12], b"ad", &mut buf).unwrap();
        let mut wrong = buf;
        assert!(open_ietf(&key, &[3; 12], b"xx", &mut wrong, &tag).is_err());
        open_ietf(&key, &[3; 12], b"ad", &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"metadata");
    }
}
