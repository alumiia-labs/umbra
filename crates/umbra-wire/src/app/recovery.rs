//! The recovery share of Part 4 §4.7.3: one share of `C_social` for one
//! contact, on the pairwise channel of that contact.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The width of a `RecoveryShare` body.
pub const RECOVERY_SHARE_LEN: usize = 1 + 16 + 1 + 1 + 17;

/// One share of the social half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryShare {
    /// The split that the share belongs to. Shares of two splits do not
    /// join.
    pub set_id: [u8; 16],
    /// The shares that a recovery needs.
    pub threshold: u8,
    /// The shares of the split.
    pub count: u8,
    /// The share: its index, 1 to `count`, and 16 bytes.
    pub share: [u8; 17],
}

impl RecoveryShare {
    fn check(&self) -> Result<(), Error> {
        let index = self.share[0];

        if self.threshold < 2 || self.count < self.threshold || index == 0 || index > self.count {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the body.
    pub fn encode(&self) -> Result<[u8; RECOVERY_SHARE_LEN], Error> {
        self.check()?;

        let mut out = [0u8; RECOVERY_SHARE_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(0x01)?;
        w.put(&self.set_id)?;
        w.u8(self.threshold)?;
        w.u8(self.count)?;
        w.put(&self.share)?;
        Ok(out)
    }

    /// Reads a body of Part 4 §4.7.3.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let out = RecoveryShare {
            set_id: r.array()?,
            threshold: r.u8()?,
            count: r.u8()?,
            share: r.array()?,
        };
        r.finish()?;
        out.check()?;
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_share_round_trips_and_a_bad_index_goes() {
        let share = RecoveryShare {
            set_id: [4; 16],
            threshold: 3,
            count: 5,
            share: [2; 17],
        };
        let bytes = share.encode().unwrap();
        assert_eq!(RecoveryShare::parse(&bytes).unwrap(), share);

        let mut bad = share;
        bad.share[0] = 6;
        assert!(bad.encode().is_err());

        let mut low = share;
        low.threshold = 1;
        assert!(low.encode().is_err());

        assert!(RecoveryShare::parse(&bytes[..35]).is_err());
    }
}
