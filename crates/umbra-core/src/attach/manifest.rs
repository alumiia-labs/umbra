//! The manifest level of Part 13 §13.3.4: the level rule, the manifest
//! plaintext, and the replicas that a set of refs names for one chunk.

use alloc::vec::Vec;

use umbra_wire::{
    bucket::Bucket,
    codec::{Reader, Writer},
    descriptor::{ChunkRef, Level, CHUNK_REF_LEN},
};

use super::{segment, MANIFEST_REFS_PER_CHUNK, MAX_DESCRIPTOR_REFS, SEGMENT_SIZE};
use crate::Error;

/// The refs a descriptor holds at each bucket (§13.3.2). No descriptor
/// fits `B0` (§13.6).
pub const fn descriptor_refs(bucket: Bucket) -> usize {
    match bucket {
        Bucket::B0 => 0,
        Bucket::B1 => 13,
        Bucket::B2 => 64,
        Bucket::B3 => MAX_DESCRIPTOR_REFS,
    }
}

/// The level for `data_chunks` under a descriptor of `bucket_refs` refs
/// (`ATT-072`, `ATT-073`). Above one level the ceiling holds (`ATT-082`).
pub const fn level_for(data_chunks: usize, bucket_refs: usize) -> Result<Level, Error> {
    if data_chunks == 0 {
        return Err(Error::Malformed);
    }
    if data_chunks <= bucket_refs {
        return Ok(Level::Data);
    }
    if data_chunks <= bucket_refs.saturating_mul(MANIFEST_REFS_PER_CHUNK) {
        return Ok(Level::Manifest);
    }
    Err(Error::Malformed)
}

/// The manifest chunk count for `data_chunks` refs.
pub const fn manifest_chunks(data_chunks: usize) -> usize {
    segment::unit_count(data_chunks.saturating_mul(CHUNK_REF_LEN), SEGMENT_SIZE)
}

/// Writes one `ChunkRef`.
pub fn encode_ref(chunk_ref: &ChunkRef, out: &mut [u8]) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.put(&chunk_ref.relay_id)?;
    w.put(&chunk_ref.chunk_id)?;
    w.put(&chunk_ref.cred_pk)?;
    w.put(&chunk_ref.replicas[0])?;
    w.put(&chunk_ref.replicas[1])?;
    Ok(w.position())
}

/// Reads one `ChunkRef`.
pub fn parse_ref(bytes: &[u8]) -> Result<ChunkRef, Error> {
    let mut r = Reader::new(bytes);
    let out = ChunkRef {
        relay_id: r.array()?,
        chunk_id: r.array()?,
        cred_pk: r.array()?,
        replicas: [r.array()?, r.array()?],
    };
    r.finish()?;
    Ok(out)
}

/// The manifest plaintext: each ref in chunk order (`ATT-077`).
pub fn build(refs: &[ChunkRef]) -> Result<Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; refs.len().saturating_mul(CHUNK_REF_LEN)];
    for (slot, chunk_ref) in out.as_chunks_mut::<CHUNK_REF_LEN>().0.iter_mut().zip(refs) {
        encode_ref(chunk_ref, slot)?;
    }
    Ok(out)
}

/// Reads a manifest plaintext after its padding is removed (`ATT-078`).
pub fn parse(plain: &[u8]) -> Result<Vec<ChunkRef>, Error> {
    if plain.is_empty() || !plain.len().is_multiple_of(CHUNK_REF_LEN) {
        return Err(Error::Malformed);
    }
    plain
        .as_chunks::<CHUNK_REF_LEN>()
        .0
        .iter()
        .map(|slot| parse_ref(slot))
        .collect()
}

/// One chunk and each relay that the refs name for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replicas {
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// The write credential.
    pub cred_pk: [u8; 32],
    /// The relays named in full.
    pub relay_ids: Vec<[u8; 32]>,
    /// The relays named by a hint, with each null hint left out.
    pub hints: Vec<[u8; 12]>,
}

/// Groups the refs by `chunk_id` in first-seen order. A second ref with
/// one `chunk_id` adds replicas of the same chunk (`ATT-176`), and the
/// group count must equal `expected` (`ATT-067`).
pub fn collapse(refs: &[ChunkRef], expected: usize) -> Result<Vec<Replicas>, Error> {
    let mut out: Vec<Replicas> = Vec::new();
    for chunk_ref in refs {
        let entry = match out.iter_mut().find(|r| r.chunk_id == chunk_ref.chunk_id) {
            Some(entry) => entry,
            None => {
                out.push(Replicas {
                    chunk_id: chunk_ref.chunk_id,
                    cred_pk: chunk_ref.cred_pk,
                    relay_ids: Vec::new(),
                    hints: Vec::new(),
                });
                out.last_mut().ok_or(Error::Malformed)?
            }
        };
        if entry.cred_pk != chunk_ref.cred_pk {
            return Err(Error::Malformed);
        }
        if !entry.relay_ids.contains(&chunk_ref.relay_id) {
            entry.relay_ids.push(chunk_ref.relay_id);
        }
        for hint in &chunk_ref.replicas {
            if *hint != [0; 12] && !entry.hints.contains(hint) {
                entry.hints.push(*hint);
            }
        }
    }
    if out.len() != expected {
        return Err(Error::Malformed);
    }
    Ok(out)
}

/// Rejects a null `RelayRef` on a pairwise or group channel
/// (`ATT-142`).
pub fn reject_null_hints(refs: &[ChunkRef]) -> Result<(), Error> {
    if refs.iter().any(|r| r.replicas.contains(&[0; 12])) {
        return Err(Error::Malformed);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::attach::{MAX_DATA_CHUNKS, MAX_DESCRIPTOR_REFS};

    fn chunk_ref(seed: u8) -> ChunkRef {
        ChunkRef {
            relay_id: [seed; 32],
            chunk_id: [seed.wrapping_add(100); 32],
            cred_pk: [seed.wrapping_add(200); 32],
            replicas: [[seed; 12], [seed.wrapping_add(1); 12]],
        }
    }

    #[test]
    fn the_level_follows_the_bucket_and_the_ceiling() {
        assert_eq!(level_for(1, 13), Ok(Level::Data));
        assert_eq!(level_for(13, 13), Ok(Level::Data));
        assert_eq!(level_for(14, 13), Ok(Level::Manifest));
        assert_eq!(
            level_for(MAX_DATA_CHUNKS, MAX_DESCRIPTOR_REFS),
            Ok(Level::Manifest)
        );
        assert!(level_for(MAX_DATA_CHUNKS + 1, MAX_DESCRIPTOR_REFS).is_err());
        assert!(level_for(0, 13).is_err());
        assert_eq!(manifest_chunks(271), 1);
        assert_eq!(manifest_chunks(272), 2);
        assert_eq!(manifest_chunks(MAX_DATA_CHUNKS), MAX_DESCRIPTOR_REFS);
        assert_eq!(descriptor_refs(Bucket::B3), MAX_DESCRIPTOR_REFS);
    }

    #[test]
    fn a_manifest_round_trips_and_a_ragged_one_is_rejected() {
        let refs = [chunk_ref(1), chunk_ref(2), chunk_ref(3)];
        let plain = build(&refs).unwrap();
        assert_eq!(plain.len(), 360);
        assert_eq!(parse(&plain).unwrap(), refs);
        assert!(parse(&plain[..359]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn two_refs_with_one_chunk_id_are_replicas_of_one_chunk() {
        let mut extra = chunk_ref(1);
        extra.relay_id = [9; 32];
        extra.replicas = [[8; 12], [0; 12]];
        let refs = [chunk_ref(1), chunk_ref(2), extra];
        let groups = collapse(&refs, 2).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].relay_ids, alloc::vec![[1; 32], [9; 32]]);
        assert_eq!(groups[0].hints, alloc::vec![[1; 12], [2; 12], [8; 12]]);
        assert!(collapse(&refs, 3).is_err());
        let mut wrong_cred = extra;
        wrong_cred.cred_pk = [0; 32];
        assert!(collapse(&[chunk_ref(1), wrong_cred], 1).is_err());
        assert!(reject_null_hints(&refs).is_err());
        assert!(reject_null_hints(&refs[..2]).is_ok());
    }
}
