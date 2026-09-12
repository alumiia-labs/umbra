//! Cryptographic core of the UMBRA protocol.
//!
//! This crate holds the six primitives of Part 5 §5.1, the `UMBRA-KEM`
//! combiner of §5.3, the key hierarchy of §5.2, and the randomness hardening
//! of §5.9. It has no dependency inside the workspace and no `std`.
//!
//! Each secret is a newtype that zeroizes on drop and has no `Debug`, no
//! `Clone`, and no `Serialize` (Part 15 §15.4). A keypair is one type, never
//! two values.
#![forbid(unsafe_code)]
#![no_std]

// The skipped-key store of the ratchet lives on the heap, as Part 15 §15.4
// prefers for a secret.
extern crate alloc;

pub mod handshake;
pub mod hierarchy;
pub mod kem;
pub mod labels;
pub mod ratchet;
pub mod rng;
pub mod secret;
pub mod sign;

#[cfg(test)]
pub(crate) mod test_rng;

/// The one error of this crate.
///
/// A decapsulation gives `Kem` and no other value, thus a caller cannot learn
/// which half of the hybrid failed (Part 5 rule `CRY-042`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A byte string has the wrong length for the object it encodes.
    Length,
    /// An encoded public key does not decode.
    Key,
    /// A decapsulation failed.
    Kem,
    /// A signature does not verify, or does not decode.
    Signature,
    /// The random generator failed.
    Rng,
    /// A handshake aborted. One value covers every cause (Part 5 §5.4).
    Handshake,
    /// A ratchet record does not open, or a limit of Part 5 §5.5.4 holds.
    Ratchet,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::Length => "wrong length",
            Error::Key => "invalid key",
            Error::Kem => "decapsulation failed",
            Error::Signature => "invalid signature",
            Error::Rng => "random generator failed",
            Error::Handshake => "handshake aborted",
            Error::Ratchet => "ratchet record rejected",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}
