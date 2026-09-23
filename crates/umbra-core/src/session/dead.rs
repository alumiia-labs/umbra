//! The dead-channel blob of Part 3 §3.2.6: the `QueueAddress` of the
//! current queue of a writer, sealed under the blob key of one week and
//! padded to one handle-addressed chunk (Part 13 `ATT-147`).

use alloc::vec::Vec;

use umbra_crypto::{
    aead::{self, NONCE_LEN, TAG_LEN},
    secret::Secret,
    zeroize::Zeroizing,
};
use umbra_wire::address::{QueueAddress, LEN as ADDRESS_LEN};

use crate::{
    attach::segment::{pad_handle_object, unpad_handle_object},
    Error,
};

/// The version of a `DeadChannelBlob`.
pub const BLOB_VERSION: u8 = 0x01;

/// The length of a `DeadChannelBlob` before the padding: the version, the
/// nonce, and the sealed address with its tag.
pub const BLOB_LEN: usize = 1 + NONCE_LEN + ADDRESS_LEN + TAG_LEN;

/// The count of consensus epochs of one week (`NET-203`).
pub const EPOCHS_PER_WEEK: u64 = 168;

/// The week of `NET-203` from the `epoch` of the newest `DirectoryRoot`.
pub fn week_of(consensus_epoch: u64) -> u32 {
    u32::try_from(consensus_epoch / EPOCHS_PER_WEEK).unwrap_or(u32::MAX)
}

/// Seals `address`, an encoded `QueueAddress`, into one chunk under
/// `blob_key` (`NET-183`).
pub fn seal_blob(
    blob_key: &Secret<32>,
    address: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    QueueAddress::parse(address)?;
    let mut blob = Zeroizing::new(Vec::with_capacity(BLOB_LEN));
    blob.push(BLOB_VERSION);
    blob.extend_from_slice(&nonce);
    let mut sealed = Zeroizing::new(address.to_vec());
    let tag = aead::seal(blob_key, &nonce, &[], &mut sealed)?;
    blob.extend_from_slice(&sealed);
    blob.extend_from_slice(&tag);
    pad_handle_object(&blob)
}

/// Opens the blob of one chunk, and gives the encoded `QueueAddress`. A
/// blob that does not open is an empty handle (`NET-192`), and the caller
/// reads the error as one.
pub fn open_blob(blob_key: &Secret<32>, chunk: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let blob = unpad_handle_object(chunk)?;
    if blob.len() != BLOB_LEN || blob.first() != Some(&BLOB_VERSION) {
        return Err(Error::Malformed);
    }
    let nonce: [u8; NONCE_LEN] = blob
        .get(1..1 + NONCE_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Malformed)?;
    let body = blob.get(1 + NONCE_LEN..).ok_or(Error::Malformed)?;
    let (sealed, tag) = body.split_at(ADDRESS_LEN);
    let mut address = Zeroizing::new(sealed.to_vec());
    aead::open(blob_key, &nonce, &[], &mut address, tag)?;
    QueueAddress::parse(&address)?;
    Ok(address)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use alloc::{vec, vec::Vec};

    use umbra_crypto::secret::Secret;
    use umbra_wire::address::{QueueAddress, LEN};

    use super::{open_blob, seal_blob, week_of, BLOB_LEN};
    use crate::attach::CHUNK_SIZE;

    fn address() -> Vec<u8> {
        let mut out = vec![0u8; LEN];
        QueueAddress {
            relay_id: [1; 32],
            sender_id: [2; 32],
            qs_auth_sk: Secret::new([3; 32]),
            qe: Secret::new([4; 32]),
        }
        .encode(&mut out)
        .unwrap();
        out
    }

    #[test]
    fn a_blob_fills_one_chunk_and_opens_under_its_key_alone() {
        let key = Secret::new([7; 32]);
        let chunk = seal_blob(&key, &address(), [9; 24]).unwrap();
        assert_eq!(chunk.len(), CHUNK_SIZE);
        assert_eq!(chunk[BLOB_LEN], 0x80);
        assert_eq!(*open_blob(&key, &chunk).unwrap(), address());
        // NET-192: another key, or a changed byte, opens nothing.
        assert!(open_blob(&Secret::new([8; 32]), &chunk).is_err());
        let mut changed = chunk.clone();
        changed[40] ^= 1;
        assert!(open_blob(&key, &changed).is_err());
        assert!(seal_blob(&key, &[0u8; 12], [9; 24]).is_err());
    }

    #[test]
    fn a_week_is_168_epochs() {
        assert_eq!(week_of(0), 0);
        assert_eq!(week_of(167), 0);
        assert_eq!(week_of(168), 1);
    }
}
