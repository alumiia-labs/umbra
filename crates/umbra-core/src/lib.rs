//! The core of the UMBRA protocol: the objects and the state machines of
//! the parts above the wire, over the five crates below it.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`identity`] | Part 4: addresses, invitation, verification, table MAC, recovery, backup. |
//! | [`devset`] | Part 7: device sets, ownership claims, sync, revocation. |
//! | [`notify`] | Part 8: the notification blob, tokens, push, and wake rules. |
//! | [`discovery`] | Part 9: handles, the transparency log, and the hello. |
//! | [`directory`] | Part 10: the 5-of-7 directory root, descriptors, and the path rules of Part 3 §3.4.6. |
//! | [`group`] | Part 11: private groups. |
//! | [`attach`] | Part 12: attachments, chunk commands, and the chunk store. |
//! | [`abuse`] | Part 13: tokens, proof of work, and admission. |
//! | [`store`] | Part 14: the local store. |
//! | [`session`] | The session driver from a conversation to the cells of a circuit. |
//!
//! Each type takes the time and the random values it needs as arguments.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod abuse;
pub mod attach;
pub mod devset;
pub mod directory;
pub mod discovery;
pub mod group;
pub mod identity;
pub mod notify;
pub mod session;
pub mod store;

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
    /// The platform store failed to read or to write.
    Storage,
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
            Error::Storage => f.write_str("the platform store failed"),
            Error::Wire(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for Error {}
