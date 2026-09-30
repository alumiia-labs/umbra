//! The attachments of Part 12: the segments and their padding, the
//! key-committing seal of each chunk, the manifest level, the twelve chunk
//! commands, the chunk store of a relay, the placement of a
//! handle-addressed chunk, and the upload of one chunk.
//!
//! The descriptor itself lives in `umbra_wire::descriptor`. Each type here
//! takes the time and the random values it needs as arguments.

pub mod command;
pub mod handle;
pub mod manifest;
pub mod place;
pub mod seal;
pub mod segment;
pub mod store;
pub mod transfer;
pub mod upload;

/// `CHUNK_SIZE`.
pub const CHUNK_SIZE: usize = 32_650;
/// `SEGMENT_SIZE`, which is `CHUNK_SIZE` less the 16-byte tag.
pub const SEGMENT_SIZE: usize = CHUNK_SIZE - umbra_crypto::aead::TAG_LEN;
/// `MAX_FILE_SIZE`, in bytes.
pub const MAX_FILE_SIZE: u64 = 250 * 1_024 * 1_024;
/// `LARGE_FILE_WARN`, in bytes.
pub const LARGE_FILE_WARN: u64 = 25 * 1_024 * 1_024;
/// `IMAGE_REENCODE_BYTES`.
pub const IMAGE_REENCODE_BYTES: u64 = 2 * 1_024 * 1_024;
/// `CHUNK_TTL`, in seconds: two weeks, below `MSG_TTL` by the choice of
/// `ATT-050`.
pub const CHUNK_TTL: u64 = 14 * 86_400;
/// `CHUNK_LIFE_MAX`, in seconds: a renewal keeps a chunk that a party
/// still reads two weeks more at the most.
pub const CHUNK_LIFE_MAX: u64 = 28 * 86_400;
/// `BACKUP_TTL` of Part 4 §4.8, in seconds.
pub const BACKUP_TTL: u64 = 180 * 86_400;
/// `REPLICAS`.
pub const REPLICAS: usize = 3;
/// `BACKUP_REPLICAS` of Part 4 §4.7.2.
pub const BACKUP_REPLICAS: usize = 2;
/// `HOT_REPLICAS`.
pub const HOT_REPLICAS: usize = 6;
/// `MAX_CONCURRENT_CHUNKS`, up.
pub const MAX_CONCURRENT_UP: usize = 8;
/// `MAX_CONCURRENT_CHUNKS`, down.
pub const MAX_CONCURRENT_DOWN: usize = 32;
/// `MAX_DESCRIPTOR_REFS`, one `B3` cell.
pub const MAX_DESCRIPTOR_REFS: usize = 269;
/// `MESSAGE_DESCRIPTOR_REFS`: the refs of a descriptor at level `0x00` in
/// a record of kind `0x02`, which leaves room in one `B3` cell for the
/// largest name and preview of Part 6 rule `WIR-531` (`ATT-072`).
pub const MESSAGE_DESCRIPTOR_REFS: usize = MAX_DESCRIPTOR_REFS
    - umbra_wire::descriptor::TRAILER_MAX.div_ceil(umbra_wire::descriptor::CHUNK_REF_LEN);
/// `MANIFEST_REFS_PER_CHUNK`.
pub const MANIFEST_REFS_PER_CHUNK: usize = 271;
/// `MAX_DATA_CHUNKS`.
pub const MAX_DATA_CHUNKS: usize = MAX_DESCRIPTOR_REFS * MANIFEST_REFS_PER_CHUNK;
/// `VOICE_MAX_SECONDS`.
pub const VOICE_MAX_SECONDS: u16 = 900;
/// `UPLOAD_QUOTA_DAY`, in bytes, before the replicas.
pub const UPLOAD_QUOTA_DAY: u64 = 512 * 1_024 * 1_024;
/// The lifetime of a quota counter (`ATT-094`).
pub const QUOTA_WINDOW: u64 = 86_400;
/// `CHUNK_STORE_MIN`, in bytes.
pub const CHUNK_STORE_MIN: u64 = 100 * 1_024 * 1_024 * 1_024;
/// `CHUNK_STORE_TARGET`, in bytes.
pub const CHUNK_STORE_TARGET: u64 = 200 * 1_024 * 1_024 * 1_024;
/// `CHUNK_EGRESS_BUDGET_DAY`, in bytes.
pub const CHUNK_EGRESS_BUDGET_DAY: u64 = 4 * CHUNK_STORE_TARGET;
/// `CHUNK_FETCH_RATE`, fetches of one chunk in one hour.
pub const CHUNK_FETCH_RATE: u32 = 60;
/// The hold-off before the same `CGET` goes to the same relay (`ATT-174`).
pub const FETCH_RETRY_HOLD: u64 = 3_600;
/// `PLACE_PROBE`.
pub const PLACE_PROBE: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parameters_agree_with_the_table() {
        assert_eq!(SEGMENT_SIZE, 32_634);
        assert_eq!(MAX_DATA_CHUNKS, 72_899);
        assert_eq!(MANIFEST_REFS_PER_CHUNK, SEGMENT_SIZE / 120);
    }
}
