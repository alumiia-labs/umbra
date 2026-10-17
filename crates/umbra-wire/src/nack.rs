//! The rejection of Part 6 §6.4.4.
//!
//! One wire form for every rejection, in the place of a cover cell, thus a
//! rejection adds no cell that an observer can count.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The payload length.
pub const LEN: usize = 17;

/// The reason of a rejection. The list is closed (`WIR-316`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    /// The relay does not hold the object, `auth` fails, `corr_id`
    /// repeats, or the payload does not parse.
    Rejected = 0x01,
    /// Admission control refused the command, and a credential would admit
    /// it.
    Admission = 0x02,
    /// A rate limit or a size bound rejects it, and a retry can pass.
    Limit = 0x03,
    /// The relay holds no capacity for the command.
    Busy = 0x04,
    /// The `version` is not one the relay serves.
    Version = 0x05,
}

impl Reason {
    /// The reason of a byte, in this namespace only.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x01 => Reason::Rejected,
            0x02 => Reason::Admission,
            0x03 => Reason::Limit,
            0x04 => Reason::Busy,
            0x05 => Reason::Version,
            _ => return Err(Error::Malformed),
        })
    }
}

/// The payload of a `NACK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackPayload {
    /// The `corr_id` of the rejected command.
    pub corr_id: [u8; 16],
    /// The reason.
    pub reason: Reason,
}

impl NackPayload {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.corr_id)?;
        w.u8(self.reason as u8)?;
        Ok(w.position())
    }

    /// Reads the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let corr_id = r.array()?;
        let reason = Reason::from_byte(r.u8()?)?;
        r.finish()?;
        Ok(NackPayload { corr_id, reason })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_round_trips_and_the_reason_list_is_closed() {
        let nack = NackPayload {
            corr_id: [5; 16],
            reason: Reason::Limit,
        };
        let mut out = [0u8; LEN];
        assert_eq!(nack.encode(&mut out).unwrap(), LEN);
        assert_eq!(NackPayload::parse(&out).unwrap(), nack);

        out[16] = 0x06;
        assert!(NackPayload::parse(&out).is_err());
        out[16] = 0x00;
        assert!(NackPayload::parse(&out).is_err());
        assert!(NackPayload::parse(&out[..16]).is_err());
    }
}
