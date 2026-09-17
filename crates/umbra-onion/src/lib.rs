//! The onion layer of the UMBRA protocol, Part 3 §3.4.
//!
//! A circuit is three telescoped hops. Each hop holds one key set for each
//! direction, and each cell passes through one rugged-PRP layer for each
//! hop (§3.4.4). The layer is AES-256 with POLYVAL in the UIV+ shape, thus
//! a change of one bit anywhere in a cell randomizes the innermost left
//! block, and the endpoint rejects the cell. Replay protection is a free
//! result of the chaining value (§3.4.5).
#![forbid(unsafe_code)]
#![no_std]

pub mod build;
pub mod circuit;
pub mod layer;

/// `HOPS`, fixed at three (§3.4.2).
pub const HOPS: usize = 3;
/// `CIRCUIT_MAX_AGE`, in seconds.
pub const CIRCUIT_MAX_AGE: u64 = 4 * 3_600;
/// `CIRCUIT_MAX_CELLS` in one direction.
pub const CIRCUIT_MAX_CELLS: u32 = 8_192;
/// `CIRCUIT_BUILD_TIMEOUT`, in seconds.
pub const CIRCUIT_BUILD_TIMEOUT: u64 = 5;

/// The one error of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A body length is not a multiple of 16, or a buffer is too short.
    Length,
    /// The innermost left block is not zero: the cell was changed, replayed,
    /// or arrived out of order (`NET-114`).
    Rejected,
    /// A build flight did not verify, or the build is in the wrong state.
    Build,
    /// A wire structure did not parse.
    Wire(umbra_wire::Error),
}

impl From<umbra_wire::Error> for Error {
    fn from(inner: umbra_wire::Error) -> Self {
        Error::Wire(inner)
    }
}

impl From<umbra_crypto::Error> for Error {
    fn from(_: umbra_crypto::Error) -> Self {
        Error::Build
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Length => f.write_str("wrong length"),
            Error::Rejected => f.write_str("cell rejected"),
            Error::Build => f.write_str("circuit build failed"),
            Error::Wire(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for Error {}
