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
/// `CHUNK_PENDING_TTL`, in seconds: the life of a registration that waits
/// for its bytes (`ATT-181`).
pub const CHUNK_PENDING_TTL: u64 = 30 * 60;
/// `BACKUP_TTL` of Part 4 §4.8, in seconds.
pub const BACKUP_TTL: u64 = 180 * 86_400;
/// `REPLICAS`.
pub const REPLICAS: usize = 3;
/// `BACKUP_REPLICAS` of Part 4 §4.7.2.
pub const BACKUP_REPLICAS: usize = 2;
/// `HOT_REPLICAS`.
pub const HOT_REPLICAS: usize = 6;
/// `MAX_CONCURRENT_CHUNKS`, up.
pub const MAX_CONCURRENT_UP: usize = 128;
/// `MAX_CONCURRENT_CHUNKS`, down.
pub const MAX_CONCURRENT_DOWN: usize = 32;
/// `MAX_DESCRIPTOR_REFS`, one `B3` cell.
pub const MAX_DESCRIPTOR_REFS: usize = 269;
/// `MESSAGE_DESCRIPTOR_REFS`: the refs of a descriptor at level `0x00` in
/// a record of kind `0x02`. With the largest name, preview, and caption of
/// Part 6 rules `WIR-531` and `WIR-535`, the record fits one `B3` cell with
/// the braid frame of the default chunk (`ATT-072`, `ATT-021`).
pub const MESSAGE_DESCRIPTOR_REFS: usize = (umbra_wire::bucket::Bucket::B3.app_default_chunk()
    - umbra_wire::bucket::APP_HEADER
    - umbra_wire::descriptor::FIXED
    - umbra_wire::descriptor::TRAILER_MAX)
    / umbra_wire::descriptor::CHUNK_REF_LEN;
// ATT-073: a receiver takes level 0x01 only above this count, thus the
// count of the receivers of today stays.
const _: () = assert!(MESSAGE_DESCRIPTOR_REFS == 207);
/// `MESSAGE_BODY_MAX`: the largest body of a record of kind `0x02` that a
/// client sends. The record fits `B3` with the braid frame of the default
/// chunk also as the `inner` of a `SyncedRecord` of Part 7 §7.5.3 with
/// `MAX_DEVICES` entries, which each other device of the set takes
/// (`ATT-208`).
pub const MESSAGE_BODY_MAX: usize = umbra_wire::bucket::Bucket::B3.app_default_chunk()
    - umbra_wire::bucket::APP_HEADER
    - crate::devset::sync::synced_overhead(crate::devset::MAX_DEVICES)
    - umbra_wire::bucket::APP_HEADER;
// ATT-208: a record at the ref limit fits it with the largest name and
// caption, once its preview stays out.
const _: () = assert!(
    umbra_wire::descriptor::FIXED
        + MESSAGE_DESCRIPTOR_REFS * umbra_wire::descriptor::CHUNK_REF_LEN
        + umbra_wire::descriptor::TRAILER_MAX
        - umbra_wire::descriptor::PREVIEW_MAX
        <= MESSAGE_BODY_MAX
);
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

/// `CHUNK_PENDING_SHARE` of a store of `capacity` bytes: one eighth, which
/// the registrations that wait for their bytes keep (`ATT-200`).
pub const fn pending_share(capacity: u64) -> u64 {
    capacity / 8
}

/// The trim target of a store of `capacity` bytes: `CHUNK_STORE_TARGET`,
/// or the store less its pending share when that is smaller (`ATT-201`).
pub const fn trim_target(capacity: u64) -> u64 {
    let kept = capacity.saturating_sub(pending_share(capacity));
    if kept < CHUNK_STORE_TARGET {
        kept
    } else {
        CHUNK_STORE_TARGET
    }
}

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
