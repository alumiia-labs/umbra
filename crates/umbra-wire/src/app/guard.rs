//! The renewal guard of Part 3 §3.2.6: the commitment that a party gives
//! its contact under the ratchet, and that a renewal bundle must open.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The width of a `RenewalGuard` body.
pub const RENEWAL_GUARD_LEN: usize = 1 + 4 + 32;

/// The guard of one party for one contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalGuard {
    /// The counter of the guard, from 1.
    pub guard_seq: u32,
    /// `SHA3-256("umbra/v1/renewal-guard" || R)`.
    pub commitment: [u8; 32],
}

impl RenewalGuard {
    /// Writes the body.
    pub fn encode(&self) -> Result<[u8; RENEWAL_GUARD_LEN], Error> {
        if self.guard_seq == 0 {
            return Err(Error::Malformed);
        }

        let mut out = [0u8; RENEWAL_GUARD_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(0x01)?;
        w.u32(self.guard_seq)?;
        w.put(&self.commitment)?;
        Ok(out)
    }

    /// Reads a body. A counter of zero names no guard (`WIR-551`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let out = RenewalGuard {
            guard_seq: r.u32()?,
            commitment: r.array()?,
        };
        r.finish()?;

        if out.guard_seq == 0 {
            return Err(Error::Malformed);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_guard_round_trips_and_a_counter_of_zero_goes() {
        let guard = RenewalGuard {
            guard_seq: 7,
            commitment: [3; 32],
        };
        let bytes = guard.encode().unwrap();
        assert_eq!(RenewalGuard::parse(&bytes).unwrap(), guard);
        assert!(RenewalGuard::parse(&bytes[..36]).is_err());

        let mut zero = bytes;
        zero[1..5].copy_from_slice(&[0; 4]);
        assert!(RenewalGuard::parse(&zero).is_err());

        let none = RenewalGuard {
            guard_seq: 0,
            ..guard
        };
        assert!(none.encode().is_err());
    }
}
