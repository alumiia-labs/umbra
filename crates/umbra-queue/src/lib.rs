//! The queue layer of the UMBRA protocol, Part 3 §3.2, §3.5, and §3.7.
//!
//! Every type here is a state machine that takes the time as an argument.
//! No type reads a clock, draws a random value, or touches a socket, thus a
//! test drives each rule with stated inputs, and a relay or a client binds
//! the machines to its runtime.
//!
//! [`relay`] holds what a relay keeps for a pairwise queue, a group queue,
//! and a transport session. [`client`] holds the acknowledgment cursor, the
//! ARQ, and the receipt hold of a client.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

pub mod client;
pub mod params;
pub mod relay;

/// The reason a relay rejects a command, one for each `NACK` reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The object is unknown, the authenticator fails, the `corr_id`
    /// repeats, or the payload does not parse (`REJECTED`).
    Rejected,
    /// Admission control refuses the command (`ADMISSION`).
    Admission,
    /// A rate or a size bound rejects it, and a retry can pass (`LIMIT`).
    Limit,
    /// The relay holds no capacity (`BUSY`).
    Busy,
    /// The version is not served (`VERSION`).
    Version,
}

impl Reject {
    /// The `NACK` reason of the rejection.
    pub const fn reason(self) -> umbra_wire::nack::Reason {
        use umbra_wire::nack::Reason;
        match self {
            Reject::Rejected => Reason::Rejected,
            Reject::Admission => Reason::Admission,
            Reject::Limit => Reason::Limit,
            Reject::Busy => Reason::Busy,
            Reject::Version => Reason::Version,
        }
    }
}
