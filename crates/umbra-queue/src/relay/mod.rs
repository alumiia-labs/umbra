//! What a relay holds: a pairwise queue (Part 3 §3.2.4 and Part 6 §6.4.3),
//! a group queue (Part 3 §3.2.7 and Part 6 §6.4.5), and a transport
//! session with its authenticator state (Part 3 §3.2.3, Part 6 §6.2.3).

pub mod group;
pub mod queue;
pub mod session;

/// One stored record with the sequence number the relay gave it and the
/// time the relay accepted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// The relay-local sequence number.
    pub seq: u32,
    /// The acceptance time, in seconds.
    pub accepted_at: u64,
    /// The record bytes.
    pub bytes: alloc::vec::Vec<u8>,
}
