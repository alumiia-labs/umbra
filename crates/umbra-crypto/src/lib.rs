//! Cryptographic core of the UMBRA protocol.
//!
//! This crate holds the six primitives of Part 5 §5.1, the `UMBRA-KEM`
//! combiner of §5.3, the key hierarchy of §5.2, the group keys of §5.8, and
//! the randomness hardening of §5.9. It has no dependency inside the workspace and no `std`.
//!
//! Each secret is a newtype that zeroizes on drop and has no `Debug`, no
//! `Clone`, and no `Serialize` (Part 15 §15.4). A keypair is one type, never
//! two values.
#![forbid(unsafe_code)]
#![no_std]

// The skipped-key store of the ratchet lives on the heap, as Part 15 §15.4
// prefers for a secret.
extern crate alloc;

pub mod auth;
pub mod group;
pub mod handshake;
pub mod hash;
pub mod hierarchy;
pub mod kem;
pub mod labels;
pub mod queue;
pub mod ratchet;
pub mod rng;
pub mod secret;
pub mod sign;

/// The random-generator traits, for a caller that signs or draws a key.
pub use rand_core;
/// The X25519 crate, for a caller that holds a queue or a group
/// credential and links no primitive of its own.
pub use x25519_dalek as x25519;

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
    /// A group record, a tag, or an epoch-key slot does not verify, or the
    /// slot chain would run backward (Part 11 §11.3).
    Group,
    /// A command authenticator or a session authenticator does not verify.
    Auth,
    /// A queue end-to-end record does not open.
    Queue,
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
            Error::Group => "group record rejected",
            Error::Auth => "authenticator rejected",
            Error::Queue => "queue record rejected",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}
