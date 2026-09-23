//! The binding that gives a queue relay what it seals a blob with (Part 8
//! §8.2.1 to §8.2.3): the root of the key schedule, the handle and the
//! token key of the group, and the device-local fields of the blob, sealed
//! to the notification key of the relay with `UMBRA-KEM` in HPKE.

use alloc::vec::Vec;

use umbra_crypto::{
    hpke,
    kem::{KeyPair, PublicKey},
    labels,
    rand_core::CryptoRng,
    secret::Secret,
};
use umbra_wire::codec::{Reader, Writer};

use super::HANDLE_LEN;
use crate::Error;

/// The plaintext length of a binding.
pub const PLAIN_LEN: usize = 32 + HANDLE_LEN + 32 + 16 + 2;

/// What the relay holds for one queue after the binding.
pub struct Binding {
    /// `k_ntf_root` of the key schedule.
    pub root: Secret<32>,
    /// The handle of the group.
    pub handle: [u8; HANDLE_LEN],
    /// The token key of the group.
    pub k_tok: Secret<32>,
    /// The device-local alias the blob carries.
    pub queue_alias: [u8; 16],
    /// The device-local relay index the blob carries.
    pub relay_idx: u16,
}

impl Binding {
    /// The 98 plain bytes, as the store of a queue relay holds them.
    pub fn encode(&self) -> Result<[u8; PLAIN_LEN], Error> {
        let mut out = [0u8; PLAIN_LEN];
        let mut w = Writer::new(&mut out);
        w.put(self.root.expose())?;
        w.put(&self.handle)?;
        w.put(self.k_tok.expose())?;
        w.put(&self.queue_alias)?;
        w.u16(self.relay_idx)?;
        Ok(out)
    }

    /// Reads the plain bytes that [`Binding::encode`] wrote.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = Binding {
            root: Secret::new(r.array()?),
            handle: r.array()?,
            k_tok: Secret::new(r.array()?),
            queue_alias: r.array()?,
            relay_idx: r.u16()?,
        };
        r.finish()?;
        Ok(out)
    }

    /// Seals the binding to the notification key of the relay, with the
    /// `RecipientId` of the queue as associated data.
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        relay_ntf_pk: &PublicKey,
        recipient_id: &[u8; 32],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let plain = self.encode()?;
        Ok(hpke::seal(
            relay_ntf_pk,
            labels::NTF,
            recipient_id,
            &plain,
            rng,
        )?)
    }

    /// Opens a binding at the relay.
    pub fn open(
        relay_ntf: &KeyPair,
        recipient_id: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Self, Error> {
        let plain = hpke::open(relay_ntf, labels::NTF, recipient_id, sealed)?;
        Self::parse(&plain)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;

    #[test]
    fn a_binding_opens_at_the_relay_and_binds_the_queue() {
        let mut rng = Rng(3);
        let relay = KeyPair::generate(&mut rng);
        let binding = Binding {
            root: Secret::new([1; 32]),
            handle: [2; 16],
            k_tok: Secret::new([3; 32]),
            queue_alias: [4; 16],
            relay_idx: 5,
        };
        let sealed = binding.seal(relay.public(), &[9; 32], &mut rng).unwrap();
        let back = Binding::open(&relay, &[9; 32], &sealed).unwrap();
        assert_eq!(back.root.expose(), &[1; 32]);
        assert_eq!(back.handle, [2; 16]);
        assert_eq!(back.relay_idx, 5);
        assert!(Binding::open(&relay, &[8; 32], &sealed).is_err());
        let other = KeyPair::generate(&mut rng);
        assert!(Binding::open(&other, &[9; 32], &sealed).is_err());
    }
}
