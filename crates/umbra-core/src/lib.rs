//! The core of the UMBRA protocol: the objects and the state machines of
//! the parts above the wire, over the five crates below it.
//!
//! [`directory`] holds Part 10: the directory root under its 5-of-7
//! multi-signature, the relay descriptor and entry, the relay-set tree
//! and its proofs, the diff, the bloc list, the layer assignment, and the
//! path invariants of Part 3 §3.4.6. [`attach`] holds Part 13: the
//! segments, the key-committing seal, the manifest level, the chunk
//! commands, the relay chunk store, and the placement of a handle-addressed
//! chunk. Each type takes the time and the random values it needs as
//! arguments.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod attach;
pub mod devset;
pub mod directory;
pub mod identity;

/// The one error of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An object is not the canonical encoding.
    Malformed,
    /// A signature, a hash, or a proof does not verify.
    Unverified,
    /// An object is older than one the client holds, or outside its validity.
    Stale,
    /// No object satisfies the rule, thus the client fails closed.
    NoPath,
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
        Error::Unverified
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Malformed => f.write_str("malformed object"),
            Error::Unverified => f.write_str("does not verify"),
            Error::Stale => f.write_str("stale or out of validity"),
            Error::NoPath => f.write_str("no conformant path"),
            Error::Wire(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for Error {}
