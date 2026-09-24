//! The transport of the UMBRA protocol: the L1 wire of Part 3 §3.8 and
//! Part 6 §6.2.1, and the L2 session of Part 6 §6.2.2 and §6.2.3.
//!
//! The layer has two halves. The platform-neutral half is here in every
//! build: the dial target, the HTTP upgrade, the WebSocket frame, the
//! session link machine on both ends, and the connection race policy. The
//! native half, behind the `native` feature, binds that machine to TLS 1.3
//! through rustls and to QUIC through quinn on tokio. The web client of
//! Part 14 §14.7 binds the same machine to the WebSocket API of its
//! browser in the web crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "native"), no_std)]

extern crate alloc;

pub mod link;
pub mod race;
pub mod upgrade;
pub mod websocket;

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod native;

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod https;

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub mod ndr;

/// Where a client connects: the co-tenant host name of a relay and one of
/// its addresses, from the descriptor of Part 10 §10.5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dial {
    /// The host name that the TLS certificate names and the `Host` header
    /// carries.
    pub host: alloc::string::String,
    /// The IPv4 address, or `None`.
    pub addr_v4: Option<[u8; 4]>,
    /// The IPv6 address, or `None`.
    pub addr_v6: Option<[u8; 16]>,
    /// The port, 443 by default.
    pub port: u16,
}

/// The one error of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A frame, an upgrade, or a control record is not the canonical
    /// encoding.
    Malformed,
    /// A buffer is too short.
    Capacity,
    /// The session is in the wrong state for the call.
    State,
    /// The relay refused the upgrade or the session.
    Refused,
    /// A wire structure did not parse.
    Wire(umbra_wire::Error),
}

impl From<umbra_wire::Error> for Error {
    fn from(inner: umbra_wire::Error) -> Self {
        Error::Wire(inner)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Malformed => f.write_str("malformed frame"),
            Error::Capacity => f.write_str("buffer too short"),
            Error::State => f.write_str("wrong session state"),
            Error::Refused => f.write_str("refused by the relay"),
            Error::Wire(inner) => write!(f, "{inner}"),
        }
    }
}

impl core::error::Error for Error {}
