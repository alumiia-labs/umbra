//! XChaCha20-Poly1305 with a 24-byte nonce, for the objects at rest and
//! the sealed blobs of Parts 3, 4, 13, and 15.

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
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
        .map_err(|_| Error::Queue)?;
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
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Queue)?;
    XChaCha20Poly1305::new(key.expose().into())
        .decrypt_inout_detached(&XNonce::from(*nonce), ad, buf.into(), &Tag::from(tag))
        .map_err(|_| Error::Queue)
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
}
