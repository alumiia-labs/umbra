//! The relay of the UMBRA protocol.
//!
//! [`circuits`] holds the circuits of Part 3 §3.4: the answer to a build
//! cell, the move of a cell between two hops, and the endpoint. [`service`]
//! holds what a relay of layer 3 serves at the end of a circuit: the
//! pairwise queues and the community caches. [`placement`] reads the layer
//! of this relay from a signed relay set. [`node`] ties the two to the
//! session links of Part 6 §6.2 and to the pacing clock of Part 3 §3.5.2.
//!
//! The library takes no socket, reads no clock, and draws no random value,
//! thus a test drives three relays and two clients in one process. The
//! binary of this crate binds the node to the native transport stack.
#![forbid(unsafe_code)]

pub mod circuits;
pub mod node;
pub mod placement;
#[cfg(feature = "native")]
pub mod server;
pub mod service;
#[cfg(feature = "native")]
pub mod sqlite_store;
pub mod store;
