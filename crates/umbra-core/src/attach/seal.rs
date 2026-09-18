//! The key-committing seal of Part 13 §13.3.1, the key derivations of
//! §13.3.3 and §13.3.4, the relay hint of §13.3.2, and the two ends of a
//! file: the sender that seals it and the receiver that opens it chunk by
//! chunk.

use alloc::vec::Vec;

use umbra_crypto::{
    aead, ct_eq, hash::sha3_256, hkdf::Hkdf, labels, secret::Secret, sha3::Sha3_256,
    x25519::StaticSecret,
};
use umbra_wire::descriptor::{FileDescriptor, Level};

use super::{segment, CHUNK_SIZE, MAX_FILE_SIZE, SEGMENT_SIZE};
use crate::Error;

/// `commit = SHA3-256("umbra/v1/file-commit" || file_key || file_nonce)`.
pub fn commit(file_key: &Secret<32>, file_nonce: &[u8; 24]) -> [u8; 32] {
    sha3_256(&[labels::FILE_COMMIT, file_key.expose(), file_nonce])
}

/// Checks the commitment of a descriptor in constant time, before any
/// chunk is fetched or opened (`ATT-026` to `ATT-030`).
pub fn verify_commit(descriptor: &FileDescriptor) -> Result<(), Error> {
    let expected = commit(&descriptor.file_key, &descriptor.file_nonce);
    if ct_eq(&expected, &descriptor.commit) {
        Ok(())
    } else {
        Err(Error::Unverified)
    }
}

/// `nonce_i = file_nonce[0..20] || BE32(i)`.
pub fn chunk_nonce(file_nonce: &[u8; 24], index: u32) -> [u8; 24] {
    let mut nonce = *file_nonce;
    if let Some(tail) = nonce.get_mut(20..) {
        tail.copy_from_slice(&index.to_be_bytes());
    }
    nonce
}

/// `ad = BE32(i) || last_i`.
fn associated_data(index: u32, last: bool) -> [u8; 5] {
    let mut ad = [0u8; 5];
    if let Some(head) = ad.get_mut(..4) {
        head.copy_from_slice(&index.to_be_bytes());
    }
    if let Some(flag) = ad.last_mut() {
        *flag = u8::from(last);
    }
    ad
}

/// Seals segment `index` into one chunk (`ATT-149`).
pub fn seal_segment(
    file_key: &Secret<32>,
    file_nonce: &[u8; 24],
    index: u32,
    last: bool,
    segment: &[u8],
) -> Result<Vec<u8>, Error> {
    if segment.len() != SEGMENT_SIZE {
        return Err(Error::Malformed);
    }
    let mut chunk = Vec::with_capacity(CHUNK_SIZE);
    chunk.extend_from_slice(segment);
    let tag = aead::seal(
        file_key,
        &chunk_nonce(file_nonce, index),
        &associated_data(index, last),
        &mut chunk,
    )?;
    chunk.extend_from_slice(&tag);
    Ok(chunk)
}

/// Opens chunk `index`. A tag that fails rejects the chunk, and the flag
/// is in the associated data, thus a wrong flag fails the tag (`ATT-150`,
/// `ATT-151`, `ATT-159`).
pub fn open_chunk(
    file_key: &Secret<32>,
    file_nonce: &[u8; 24],
    index: u32,
    last: bool,
    chunk: &[u8],
) -> Result<Vec<u8>, Error> {
    if chunk.len() != CHUNK_SIZE {
        return Err(Error::Malformed);
    }
    let body = chunk.get(..SEGMENT_SIZE).ok_or(Error::Malformed)?;
    let tag = chunk.get(SEGMENT_SIZE..).ok_or(Error::Malformed)?;
    let mut plain = body.to_vec();
    aead::open(
        file_key,
        &chunk_nonce(file_nonce, index),
        &associated_data(index, last),
        &mut plain,
        tag,
    )?;
    Ok(plain)
}

/// `read_sk` of file chunk `index` (`ATT-037`): HKDF-SHA3-256 with
/// `file_key` as the key material and the label then `BE32(index)` as the
/// info.
pub fn read_secret(file_key: &Secret<32>, index: u32) -> StaticSecret {
    let kdf = Hkdf::<Sha3_256>::new(None, file_key.expose());
    let mut secret = Secret::<32>::zeroed();
    let _ = kdf.expand_multi_info(
        &[labels::CHUNK_READ, &index.to_be_bytes()],
        secret.expose_mut(),
    );
    StaticSecret::from(*secret.expose())
}

/// `K_manifest` (`ATT-075`): HKDF-SHA3-256 with `file_key` as the key
/// material and the label then `file_nonce` as the info.
pub fn manifest_key(file_key: &Secret<32>, file_nonce: &[u8; 24]) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(None, file_key.expose());
    let mut key = Secret::<32>::zeroed();
    let _ = kdf.expand_multi_info(&[labels::FILE_MANIFEST, file_nonce], key.expose_mut());
    key
}

/// The `relay_hint` of a `RelayRef` (§13.3.2).
pub fn relay_hint(relay_id: &[u8; 32]) -> [u8; 12] {
    let full = sha3_256(&[labels::RELAYREF, relay_id]);
    let mut hint = [0u8; 12];
    hint.copy_from_slice(full.get(..12).unwrap_or(&[0; 12]));
    hint
}

/// The proof of possession that a `CPRF` carries (§13.4.1).
pub fn proof(nonce: &[u8; 16], chunk: &[u8]) -> [u8; 32] {
    sha3_256(&[nonce, chunk])
}

/// A sealed file: the chunks in order and the descriptor fields that the
/// seal fixes.
pub struct SealedFile {
    /// The chunks, each of `CHUNK_SIZE` bytes.
    pub chunks: Vec<Vec<u8>>,
    /// SHA3-256 of the plaintext.
    pub digest: [u8; 32],
    /// The key commitment.
    pub commit: [u8; 32],
    /// The chunk count times `CHUNK_SIZE`.
    pub padded_size: u32,
}

/// Pads and seals a whole file under `file_key` (`ATT-022`, `ATT-149`).
pub fn seal_file(
    file_key: &Secret<32>,
    file_nonce: &[u8; 24],
    plain: &[u8],
) -> Result<SealedFile, Error> {
    if u64::try_from(plain.len()).map_or(true, |n| n > MAX_FILE_SIZE) {
        return Err(Error::Malformed);
    }
    let padded = segment::pad_file(plain);
    let count = padded.len() / SEGMENT_SIZE;
    let chunks = padded
        .as_chunks::<SEGMENT_SIZE>()
        .0
        .iter()
        .enumerate()
        .map(|(i, segment)| {
            let index = u32::try_from(i).map_err(|_| Error::Malformed)?;
            seal_segment(
                file_key,
                file_nonce,
                index,
                i.saturating_add(1) == count,
                segment,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let padded_size =
        u32::try_from(count.saturating_mul(CHUNK_SIZE)).map_err(|_| Error::Malformed)?;
    Ok(SealedFile {
        chunks,
        digest: sha3_256(&[plain]),
        commit: commit(file_key, file_nonce),
        padded_size,
    })
}

/// A receiver that opens a file in chunk order. The last flag comes from
/// the chunk count, thus a truncated or an extended file fails at the chunk
/// that shows it.
pub struct Assembler {
    key: Secret<32>,
    nonce: [u8; 24],
    digest: Option<[u8; 32]>,
    chunk_count: u32,
    next: u32,
    plain: Vec<u8>,
}

impl Assembler {
    fn new(key: Secret<32>, nonce: [u8; 24], digest: Option<[u8; 32]>, chunk_count: u32) -> Self {
        Assembler {
            key,
            nonce,
            digest,
            chunk_count,
            next: 0,
            plain: Vec::new(),
        }
    }

    /// The data chunks of a descriptor, under `file_key`. The commitment
    /// is checked first (`ATT-030`), and at level `0x00` the ref count must
    /// equal the chunk count (`ATT-067`).
    pub fn for_data(descriptor: &FileDescriptor) -> Result<Self, Error> {
        verify_commit(descriptor)?;
        let chunk_count = descriptor.padded_size / umbra_wire::descriptor::CHUNK_SIZE;
        if chunk_count == 0 {
            return Err(Error::Malformed);
        }
        if descriptor.level == Level::Data
            && usize::try_from(chunk_count).ok() != Some(descriptor.refs.len())
        {
            return Err(Error::Malformed);
        }
        Ok(Self::new(
            Secret::new(*descriptor.file_key.expose()),
            descriptor.file_nonce,
            Some(descriptor.digest),
            chunk_count,
        ))
    }

    /// The manifest chunks of a level `0x01` descriptor, under `K_manifest`
    /// (§13.3.4). A manifest carries no digest, and each chunk tag
    /// authenticates it.
    pub fn for_manifest(descriptor: &FileDescriptor) -> Result<Self, Error> {
        verify_commit(descriptor)?;
        if descriptor.level != Level::Manifest || descriptor.refs.is_empty() {
            return Err(Error::Malformed);
        }
        let chunk_count = u32::try_from(descriptor.refs.len()).map_err(|_| Error::Malformed)?;
        Ok(Self::new(
            manifest_key(&descriptor.file_key, &descriptor.file_nonce),
            descriptor.file_nonce,
            None,
            chunk_count,
        ))
    }

    /// The chunk count.
    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// The index of the next chunk.
    pub const fn next_index(&self) -> u32 {
        self.next
    }

    /// Whether each chunk is in.
    pub const fn is_complete(&self) -> bool {
        self.next == self.chunk_count
    }

    /// Opens the next chunk and returns its verified segment, which a media
    /// player may render before the digest check (`ATT-152`).
    pub fn accept(&mut self, chunk: &[u8]) -> Result<&[u8], Error> {
        if self.is_complete() {
            return Err(Error::Stale);
        }
        let last = self.next.saturating_add(1) == self.chunk_count;
        let segment = open_chunk(&self.key, &self.nonce, self.next, last, chunk)?;
        let start = self.plain.len();
        self.plain.extend_from_slice(&segment);
        self.next = self.next.saturating_add(1);
        self.plain.get(start..).ok_or(Error::Malformed)
    }

    /// Removes the padding and checks the digest (`ATT-031`, `ATT-032`).
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if !self.is_complete() {
            return Err(Error::Stale);
        }
        segment::unpad_file(&mut self.plain)?;
        if let Some(digest) = self.digest {
            if !ct_eq(&sha3_256(&[&self.plain]), &digest) {
                return Err(Error::Unverified);
            }
        }
        Ok(self.plain)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn descriptor(key: [u8; 32], nonce: [u8; 24], sealed: &SealedFile) -> FileDescriptor {
        FileDescriptor {
            level: Level::Data,
            file_key: Secret::new(key),
            file_nonce: nonce,
            commit: sealed.commit,
            digest: sealed.digest,
            media_seconds: 0,
            padded_size: sealed.padded_size,
            mime_class: 5,
            pixel_w: 0,
            pixel_h: 0,
            refs: alloc::vec![
                umbra_wire::descriptor::ChunkRef {
                    relay_id: [1; 32],
                    chunk_id: [2; 32],
                    cred_pk: [3; 32],
                    replicas: [[4; 12], [5; 12]],
                };
                sealed.chunks.len()
            ],
        }
    }

    #[test]
    fn a_file_round_trips_and_each_bound_holds() {
        let key = Secret::new([9; 32]);
        let nonce = [8; 24];
        let plain: Vec<u8> = (0..SEGMENT_SIZE + 77).map(|i| (i % 253) as u8).collect();
        let sealed = seal_file(&key, &nonce, &plain).unwrap();
        assert_eq!(sealed.chunks.len(), 2);
        assert_eq!(sealed.padded_size, 2 * CHUNK_SIZE as u32);
        let d = descriptor([9; 32], nonce, &sealed);

        let mut a = Assembler::for_data(&d).unwrap();
        let first = a.accept(&sealed.chunks[0]).unwrap();
        assert_eq!(first, &plain[..SEGMENT_SIZE]);
        assert!(!a.is_complete());
        a.accept(&sealed.chunks[1]).unwrap();
        assert!(a.is_complete());
        assert_eq!(a.accept(&sealed.chunks[1]), Err(Error::Stale));
        assert_eq!(a.finish().unwrap(), plain);

        // A swapped order fails the tag, because the index is in the nonce
        // and the flag in the associated data.
        let mut b = Assembler::for_data(&d).unwrap();
        assert_eq!(b.accept(&sealed.chunks[1]), Err(Error::Unverified));

        // A truncated file: the descriptor claims one chunk, and the first
        // chunk carries last = 0.
        let mut short = descriptor([9; 32], nonce, &sealed);
        short.padded_size = CHUNK_SIZE as u32;
        short.refs.truncate(1);
        let mut c = Assembler::for_data(&short).unwrap();
        assert_eq!(c.accept(&sealed.chunks[0]), Err(Error::Unverified));

        // A wrong digest fails at the close.
        let mut wrong = descriptor([9; 32], nonce, &sealed);
        wrong.digest[0] ^= 1;
        let mut e = Assembler::for_data(&wrong).unwrap();
        e.accept(&sealed.chunks[0]).unwrap();
        e.accept(&sealed.chunks[1]).unwrap();
        assert_eq!(e.finish(), Err(Error::Unverified));

        // A corrupt byte fails the chunk.
        let mut bad = sealed.chunks[0].clone();
        bad[100] ^= 1;
        let mut f = Assembler::for_data(&d).unwrap();
        assert_eq!(f.accept(&bad), Err(Error::Unverified));
    }

    #[test]
    fn the_commitment_binds_the_key_and_a_wrong_key_is_rejected_before_a_fetch() {
        let key = Secret::new([1; 32]);
        let nonce = [2; 24];
        let sealed = seal_file(&key, &nonce, b"hello").unwrap();
        let d = descriptor([1; 32], nonce, &sealed);
        verify_commit(&d).unwrap();
        let mut other = descriptor([3; 32], nonce, &sealed);
        assert_eq!(verify_commit(&other), Err(Error::Unverified));
        assert!(Assembler::for_data(&other).is_err());
        // The negative vector of ATT-007: the same ciphertext under a
        // different key fails, even with a commitment made for that key.
        other.commit = commit(&Secret::new([3; 32]), &nonce);
        let mut a = Assembler::for_data(&other).unwrap();
        assert_eq!(a.accept(&sealed.chunks[0]), Err(Error::Unverified));
    }

    #[test]
    fn the_manifest_key_the_read_key_and_the_hint_are_distinct_derivations() {
        let key = Secret::new([1; 32]);
        let nonce = [2; 24];
        assert_ne!(manifest_key(&key, &nonce).expose(), key.expose());
        assert_ne!(
            manifest_key(&key, &nonce).expose(),
            manifest_key(&key, &[3; 24]).expose()
        );
        assert_ne!(
            read_secret(&key, 0).to_bytes(),
            read_secret(&key, 1).to_bytes()
        );
        assert_ne!(relay_hint(&[1; 32]), relay_hint(&[2; 32]));
        assert_eq!(chunk_nonce(&nonce, 7)[20..], [0, 0, 0, 7]);
        assert_eq!(chunk_nonce(&nonce, 7)[..20], nonce[..20]);
        assert_ne!(proof(&[1; 16], b"chunk"), proof(&[2; 16], b"chunk"));
    }

    #[test]
    fn a_manifest_assembler_uses_the_manifest_key() {
        let key = Secret::new([4; 32]);
        let nonce = [5; 24];
        let refs_plain = [6u8; 240];
        let sealed = seal_file(&manifest_key(&key, &nonce), &nonce, &refs_plain).unwrap();
        let mut d = descriptor([4; 32], nonce, &sealed);
        d.level = Level::Manifest;
        d.commit = commit(&key, &nonce);
        d.padded_size = 3 * CHUNK_SIZE as u32;
        let mut a = Assembler::for_manifest(&d).unwrap();
        a.accept(&sealed.chunks[0]).unwrap();
        assert_eq!(a.finish().unwrap(), refs_plain);
        // The same bytes under file_key do not open (ATT-076).
        let under_file_key = seal_file(&key, &nonce, &refs_plain).unwrap();
        let mut b = Assembler::for_manifest(&d).unwrap();
        assert!(b.accept(&under_file_key.chunks[0]).is_err());
        d.level = Level::Data;
        assert!(Assembler::for_manifest(&d).is_err());
    }
}
