//! The queue end-to-end layer of Part 6 §6.4.2: `K_QE` and its AEAD.
//!
//! The layer sits below the ratchet and above the queue command. A relay
//! reads the version, the nonce, and the bucket, and nothing else.

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use sha3::Sha3_256;

use crate::{labels, secret::Secret, Error};

/// The length of the AEAD tag.
pub const TAG_LEN: usize = 16;

/// `K_QE`, the key of one queue.
pub struct QueueKey(Secret<32>);

impl QueueKey {
    /// `HKDF-SHA3-256("umbra/v1/queue-e2e", QE, SenderId)` (`WIR-017`).
    pub fn derive(queue_secret: &Secret<32>, sender_id: &[u8; 32]) -> Self {
        let kdf = Hkdf::<Sha3_256>::new(None, queue_secret.expose());
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand_multi_info(&[labels::QUEUE_E2E, sender_id], key.expose_mut());
        Self(key)
    }

    /// Writes the key for the at-rest store.
    pub fn export(&self, writer: &mut crate::stored::Writer) {
        writer.bytes(self.0.expose());
    }

    /// Reads the key that [`QueueKey::export`] wrote.
    pub fn restore(reader: &mut crate::stored::Reader<'_>) -> Result<Self, Error> {
        Ok(Self(Secret::new(reader.array()?)))
    }

    /// Seals `buf` in place with `version || SenderId` bound (`WIR-022`).
    pub fn seal(
        &self,
        nonce: &[u8; 12],
        version: u8,
        sender_id: &[u8; 32],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        let ad = associated_data(version, sender_id);
        let tag = ChaCha20Poly1305::new(self.0.expose().into())
            .encrypt_inout_detached(&Nonce::from(*nonce), &ad, buf.into())
            .map_err(|_| Error::Queue)?;
        Ok(tag.into())
    }

    /// Opens `buf` in place. One error covers every cause (`WIR-032`).
    pub fn open(
        &self,
        nonce: &[u8; 12],
        version: u8,
        sender_id: &[u8; 32],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Queue)?;
        let ad = associated_data(version, sender_id);
        ChaCha20Poly1305::new(self.0.expose().into())
            .decrypt_inout_detached(&Nonce::from(*nonce), &ad, buf.into(), &Tag::from(tag))
            .map_err(|_| Error::Queue)
    }
}

fn associated_data(version: u8, sender_id: &[u8; 32]) -> [u8; 33] {
    let mut ad = [0u8; 33];
    let (v, id) = ad.split_at_mut(1);
    v.copy_from_slice(&[version]);
    id.copy_from_slice(sender_id);
    ad
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

    #[test]
    fn a_record_opens_under_its_sender_id_and_version_only() {
        let key = QueueKey::derive(&Secret::new([1u8; 32]), &[2u8; 32]);
        let nonce = [3u8; 12];
        let mut buf = *b"queue record";
        let tag = key.seal(&nonce, 1, &[2u8; 32], &mut buf).unwrap();
        let mut wrong = buf;
        assert!(key.open(&nonce, 2, &[2u8; 32], &mut wrong, &tag).is_err());
        let mut wrong = buf;
        assert!(key.open(&nonce, 1, &[9u8; 32], &mut wrong, &tag).is_err());
        let other = QueueKey::derive(&Secret::new([1u8; 32]), &[9u8; 32]);
        let mut wrong = buf;
        assert!(other.open(&nonce, 1, &[2u8; 32], &mut wrong, &tag).is_err());
        key.open(&nonce, 1, &[2u8; 32], &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"queue record");
    }
}
