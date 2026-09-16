//! The queue address of Part 6 §6.6.10: what a sender needs before it
//! writes to one queue.

use umbra_crypto::secret::Secret;

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The encoded length.
pub const LEN: usize = 129;
/// The version.
pub const VERSION: u8 = 0x01;

/// A queue address. It holds two secrets, thus it has no `Debug` and no
/// `Clone`.
pub struct QueueAddress {
    /// The relay that holds the queue.
    pub relay_id: [u8; 32],
    /// The `SenderId` of the queue.
    pub sender_id: [u8; 32],
    /// The `QS_auth` private key.
    pub qs_auth_sk: Secret<32>,
    /// The per-queue secret `QE`.
    pub qe: Secret<32>,
}

impl QueueAddress {
    /// Writes the address.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        w.put(&self.relay_id)?;
        w.put(&self.sender_id)?;
        w.put(self.qs_auth_sk.expose())?;
        w.put(self.qe.expose())?;
        Ok(w.position())
    }

    /// Reads an address (`WIR-327`, `WIR-328`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let out = QueueAddress {
            relay_id: r.array()?,
            sender_id: r.array()?,
            qs_auth_sk: Secret::new(r.array()?),
            qe: Secret::new(r.array()?),
        };
        r.finish()?;
        Ok(out)
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
    fn the_address_round_trips_at_129_bytes() {
        let address = QueueAddress {
            relay_id: [1; 32],
            sender_id: [2; 32],
            qs_auth_sk: Secret::new([3; 32]),
            qe: Secret::new([4; 32]),
        };
        let mut out = [0u8; LEN];
        assert_eq!(address.encode(&mut out).unwrap(), LEN);
        let back = QueueAddress::parse(&out).unwrap();
        assert_eq!(back.sender_id, [2; 32]);
        assert_eq!(back.qe.expose(), &[4; 32]);
        out[0] = 0x02;
        assert!(QueueAddress::parse(&out).is_err());
        out[0] = 0x01;
        assert!(QueueAddress::parse(&out[..128]).is_err());
    }
}
