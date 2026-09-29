//! The discovery of Part 9: the canonical handle, the directory entry and
//! the address entry, the signed tree head with its key set and the
//! client rules over it, the renewal and the write challenges, the label
//! lifecycle at the directory and the takeover check at the client, and
//! the hello with its inbound limits.
//!
//! [`translog`] holds the combined tree of §9.5.1 over [`prefix`] and
//! [`logtree`]: the lookup proof that a client verifies, the log operator,
//! and the check of an auditor. Each type here takes the time and the
//! random values it needs as arguments.

pub mod challenge;
pub mod dirclient;
pub mod entry;
pub mod handle;
pub mod head;
pub mod hello;
pub mod lifecycle;
pub mod logtree;
pub mod prefix;
pub mod profile;
pub mod reader;
pub mod service;
pub mod translog;

/// `GOSSIP_INTERVAL`, in seconds, for each digest source.
pub const GOSSIP_INTERVAL: u64 = 6 * 3_600;
/// `HANDLE_LEASE`, in seconds.
pub const HANDLE_LEASE: u64 = 180 * 86_400;
/// `LEASE_MIN`, in seconds: the shortest lease that a registration names
/// (`DIS-173`).
pub const LEASE_MIN: u64 = 3_600;
/// `TREE_HEAD_FRESHNESS`, in seconds, from the `timestamp` of the head.
pub const TREE_HEAD_FRESHNESS: u64 = 7 * 86_400;
/// `TREE_HEAD_RETAIN`, in seconds, from the acceptance of the head.
pub const TREE_HEAD_RETAIN: u64 = 14 * 86_400;
/// `HANDLE_RESERVE`, in seconds, from the tombstone.
pub const HANDLE_RESERVE: u64 = 180 * 86_400;
/// `HANDLE_HISTORY_MAX`, the version scan bound of §9.9.2.
pub const HANDLE_HISTORY_MAX: u32 = 64;
/// `RENDEZVOUS_ROTATE`, in seconds, from the write of the current
/// rendezvous version.
pub const RENDEZVOUS_ROTATE: u64 = 30 * 86_400;
/// `ROTATE_GRACE` of Part 3 §3.2.6, in seconds.
pub const ROTATE_GRACE: u64 = 7 * 86_400;
/// The signer count of the log.
pub const SIGNER_COUNT: usize = 3;
/// The signatures a head or a key set needs.
pub const SIGNATURES_NEEDED: usize = 2;
/// `HELLO_INBOUND_LIMIT` of Part 13 §13.4, hellos for one entry in one
/// epoch.
pub const HELLO_INBOUND_LIMIT: u32 = 64;
/// `HELLO_POW_EFFORT` of Part 13 §13.13.
pub const HELLO_POW_EFFORT: u8 = 50;
