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
/// `CHUNK_TTL`, in seconds; it equals `MSG_TTL`.
pub const CHUNK_TTL: u64 = 45 * 86_400;
/// `CHUNK_LIFE_MAX`, in seconds.
pub const CHUNK_LIFE_MAX: u64 = 90 * 86_400;
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
/// The floor of `REPLICA_VERIFY_SAMPLE`.
pub const VERIFY_SAMPLE_MIN: usize = 4;
/// The ceiling of `REPLICA_VERIFY_SAMPLE`.
pub const VERIFY_SAMPLE_MAX: usize = 64;
/// The divisor of `REPLICA_VERIFY_SAMPLE`.
pub const VERIFY_SAMPLE_DIVISOR: usize = 32;

/// `REPLICA_VERIFY_SAMPLE` for a relay that holds `chunks_held` chunks of
/// one file (§12.4.1).
pub const fn verify_sample(chunks_held: usize) -> usize {
    let share = chunks_held / VERIFY_SAMPLE_DIVISOR;
    let floored = if share < VERIFY_SAMPLE_MIN {
        VERIFY_SAMPLE_MIN
    } else {
        share
    };
    let capped = if floored > VERIFY_SAMPLE_MAX {
        VERIFY_SAMPLE_MAX
    } else {
        floored
    };
    if capped > chunks_held {
        chunks_held
    } else {
        capped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parameters_agree_with_the_table() {
        assert_eq!(SEGMENT_SIZE, 32_634);
        assert_eq!(MAX_DATA_CHUNKS, 72_899);
        assert_eq!(MANIFEST_REFS_PER_CHUNK, SEGMENT_SIZE / 120);
        assert_eq!(verify_sample(2), 2);
        assert_eq!(verify_sample(100), 4);
        assert_eq!(verify_sample(320), 10);
        assert_eq!(verify_sample(10_000), 64);
    }
}
