//! Wire format of the UMBRA protocol, Part 6.
//!
//! Every structure is fixed-layout binary with explicit lengths and no
//! self-description (§6.1). Each parser is total: it returns a structure or
//! an error, with no panic, no unbounded allocation, and no recursion
//! (`WIR-006`). A parser reports one error for every rejection, because a
//! receiver must not tell a peer which check failed (`WIR-032`).
//!
//! Each byte namespace of §6.1.1 rule 7 is its own type, and no conversion
//! exists between two of them (`WIR-009`, `WIR-010`).
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod address;
pub mod admission;
pub mod app;
pub mod bucket;
pub mod capsule;
pub mod cell;
pub mod codec;
pub mod command;
pub mod descriptor;
pub mod directory;
pub mod group;
pub mod nack;
pub mod ndr;
pub mod queue;
pub mod ratchet;
pub mod session;

/// The one error of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not the canonical encoding of any structure.
    Malformed,
    /// The content does not fit the bucket or the buffer given.
    Capacity,
    /// A cryptographic check failed. `umbra_crypto::Error` gives the class.
    Crypto(umbra_crypto::Error),
}

impl From<umbra_crypto::Error> for Error {
    fn from(inner: umbra_crypto::Error) -> Self {
        Error::Crypto(inner)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Malformed => f.write_str("malformed encoding"),
            Error::Capacity => f.write_str("does not fit"),
            Error::Crypto(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for Error {}
