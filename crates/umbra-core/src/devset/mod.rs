//! Device sets, Part 7: the roster chain, the ownership claims, the sync
//! seed, the convergence machines of the sync channel, the edit and
//! deletion rules, and the revocation steps.

pub mod claim;
pub mod edits;
pub mod engine;
pub mod link;
pub mod revocation;
pub mod roster;
pub mod seed;
pub mod sync;

/// `MAX_DEVICES`.
pub const MAX_DEVICES: usize = 8;
/// `OWNER_TIMEOUT`, in seconds.
pub const OWNER_TIMEOUT: u64 = 90;
/// `LINK_QR_TTL`, in seconds.
pub const LINK_QR_TTL: u64 = 120;
/// `LINK_PROVISION_TTL`, in seconds: the life of a provision and of its
/// snapshot on the chunk path when the sync channel does not open.
pub const LINK_PROVISION_TTL: u64 = 600;
/// `SYNC_MAX_AGE` by default, in seconds.
pub const SYNC_MAX_AGE: u64 = 365 * 86_400;
/// `SYNC_MAX_BYTES` by default.
pub const SYNC_MAX_BYTES: u64 = 2 * 1_024 * 1_024 * 1_024;
/// `SYNC_ACK_BATCH`.
pub const SYNC_ACK_BATCH: u32 = 32;
/// `SYNC_ACK_MAX_DELAY`, in seconds.
pub const SYNC_ACK_MAX_DELAY: u64 = 6 * 3_600;
/// The roster epoch rate limit: one in this many seconds for each device.
pub const ROSTER_EPOCH_INTERVAL: u64 = 10;
/// `OWNER_CLAIM_MAX`.
pub const OWNER_CLAIM_MAX: usize = 8;
/// `OWNER_CLAIM_RATE`, claim records of scope 1, 2, or 4 each day.
pub const OWNER_CLAIM_RATE: u32 = 4;
/// `OWNER_ABSENCE`, in seconds.
pub const OWNER_ABSENCE: u64 = 24 * 3_600;
/// `OWNER_ABSENCE_RATE`, claim records of scope 3 each hour.
pub const OWNER_ABSENCE_RATE: u32 = 1;
/// `SYNC_INTERACTIVE_RATE`, tokens each minute.
pub const SYNC_INTERACTIVE_RATE: u32 = 4;
/// `SYNC_INTERACTIVE_BURST`.
pub const SYNC_INTERACTIVE_BURST: u32 = 12;
/// `SYNC_CATCHUP_LAG`, records.
pub const SYNC_CATCHUP_LAG: u64 = 360;
/// `FORWARD_MAX_DEPTH`.
pub const FORWARD_MAX_DEPTH: u8 = 5;
/// `EDIT_WINDOW`, in seconds.
pub const EDIT_WINDOW: u64 = 24 * 3_600;
/// `EDIT_MAX`, revisions of one message.
pub const EDIT_MAX: u32 = 8;
/// `REF_ORPHAN_TTL`, in seconds.
pub const REF_ORPHAN_TTL: u64 = 45 * 86_400;
/// `REF_ORPHAN_MAX`, entries for each conversation.
pub const REF_ORPHAN_MAX: usize = 4_096;
/// `DELETE_RATE_LIMIT`: one deletion in this many seconds.
pub const DELETE_RATE_INTERVAL: u64 = 10;

/// A device identifier.
pub type DeviceId = [u8; 16];
