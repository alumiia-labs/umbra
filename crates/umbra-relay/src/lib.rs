//! The relay of the UMBRA protocol.
//!
//! [`circuits`] holds the circuits of Part 3 §3.4: the answer to a build
//! cell, the move of a cell between two hops, and the endpoint. [`service`]
//! holds what a relay of layer 3 serves at the end of a circuit: the
//! pairwise queues, the group queues, and the chunks. [`placement`] reads the layer
//! of this relay from a signed relay set. [`node`] ties the two to the
//! session links of Part 6 §6.2 and to the pacing clock of Part 3 §3.5.2.
//!
//! The library takes no socket and draws no random value, and each time of
//! the wall clock is an argument of a call. A test thus drives three relays
//! and two clients in one process. [`node`] reads the monotonic clock of
//! the machine for the budgets of a link alone. The binary of this crate
//! binds the node to the native transport stack.
#![forbid(unsafe_code)]

pub mod circuits;
#[cfg(feature = "native")]
pub mod issuer_keys;

/// The oldest epoch whose issuer key a relay keeps when it takes the key
/// of `epoch`: the one before the epoch before, since a token names the
/// current epoch or the one before (`ABU-095`).
pub const fn issuer_floor(epoch: u32) -> u32 {
    epoch.saturating_sub(2)
}
#[cfg(feature = "native")]
pub mod directory_server;
#[cfg(feature = "native")]
pub mod fcm;
#[cfg(feature = "native")]
pub mod ndr_server;
pub mod node;
pub mod placement;
pub mod receipts;
#[cfg(feature = "native")]
pub mod server;
pub mod service;
#[cfg(feature = "native")]
pub mod sqlite_store;
pub mod store;
