//! The relay directory of Part 10, on the client side.

pub mod authority;
pub mod bloc;
pub mod descriptor;
pub mod diff;
pub mod family;
pub mod layer;
pub mod manifest;
pub mod path;
pub mod root;
pub mod tree;

/// The consensus epoch length, in seconds.
pub const EPOCH_SECONDS: u64 = 3_600;
/// `CONSENSUS_VALIDITY`, in seconds.
pub const CONSENSUS_VALIDITY: u64 = 3 * 3_600;
/// `CLOCK_SKEW`, in seconds.
pub const CLOCK_SKEW: u64 = 3_600;
/// The authority count.
pub const AUTHORITY_COUNT: usize = 7;
/// The signatures a consensus needs.
pub const SIGNATURES_NEEDED: usize = 5;
/// `AUTHORITY_FLOOR`.
pub const AUTHORITY_FLOOR: u8 = 5;
/// `MEASURER_REVOKE_MAX`.
pub const MEASURER_REVOKE_MAX: usize = 16;
/// `FAMILY_MAX`.
pub const FAMILY_MAX: usize = 64;
/// The ingress pin lifetime when confirmed, in seconds.
pub const INGRESS_PIN_CONFIRMED: u64 = 60 * 86_400;
/// The ingress pin lifetime when unconfirmed, in seconds.
pub const INGRESS_PIN_UNCONFIRMED: u64 = 120 * 86_400;
