//! The dead-channel secret of Part 3 §3.2.6: one secret from the two
//! pairwise X25519 keys of a contact, and the handle, the read key, and
//! the blob key of each writer and each week under it.

use hkdf::Hkdf;
use sha3::Sha3_256;
use x25519_dalek::PublicKey as XPublic;
use zeroize::Zeroizing;

use crate::{handshake::contributory, kem::KeyPair, labels, secret::Secret, Error};

/// The pseudorandom key of one contact:
/// `HKDF-SHA3-256-Extract(salt = "umbra/v1/dead-channel", ikm = ss_pair)`.
///
/// The key lives in a buffer that wipes itself, because the state of
/// `Hkdf` has no wipe. Each expansion builds its own `Hkdf` from it.
pub struct DeadChannel {
    prk: Zeroizing<[u8; 32]>,
}

impl DeadChannel {
    /// The secret of the pair `own` and `peer_x25519_pk`. The two parties
    /// compute the same one. An all-zero `ss_pair` fails (`CRY-014`).
    pub fn new(own: &KeyPair, peer_x25519_pk: &[u8; 32]) -> Result<Self, Error> {
        let ss = own
            .x25519_secret()
            .diffie_hellman(&XPublic::from(*peer_x25519_pk));
        contributory(&ss)?;

        let (mut out, _) = Hkdf::<Sha3_256>::extract(Some(labels::DEAD_CHANNEL), ss.as_bytes());
        let mut prk = Zeroizing::new([0u8; 32]);
        prk.copy_from_slice(&out);
        zeroize::Zeroize::zeroize(out.as_mut_slice());
        Ok(DeadChannel { prk })
    }

    fn expand(&self, tag: u8, writer_pk: &[u8; 32], week: u32) -> Secret<32> {
        let mut out = Secret::new([0u8; 32]);
        let week = week.to_be_bytes();
        let info: [&[u8]; 3] = [&[tag], &week, writer_pk];

        // A 32-byte key is the hash length, and a 32-byte output is inside
        // the bound of HKDF, thus neither call fails.
        if let Ok(kdf) = Hkdf::<Sha3_256>::from_prk(&*self.prk) {
            let _ = kdf.expand_multi_info(&info, out.expose_mut());
        }
        out
    }

    /// `handle(P, w)`: the `chunk_id` of the blob that the writer with the
    /// pairwise key `writer_pk` writes in week `week`.
    pub fn handle(&self, writer_pk: &[u8; 32], week: u32) -> [u8; 32] {
        *self.expand(0x01, writer_pk, week).expose()
    }

    /// `read_sk(P, w)`.
    pub fn read_secret(&self, writer_pk: &[u8; 32], week: u32) -> Secret<32> {
        self.expand(0x02, writer_pk, week)
    }

    /// `blob_key(P, w)`.
    pub fn blob_key(&self, writer_pk: &[u8; 32], week: u32) -> Secret<32> {
        self.expand(0x03, writer_pk, week)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::DeadChannel;
    use crate::{kem::KeyPair, secret::Secret};

    fn pair(seed: u8) -> KeyPair {
        KeyPair::from_seeds(Secret::new([seed; 32]), Secret::new([seed; 64]))
    }

    #[test]
    fn two_parties_derive_one_secret_and_each_writer_its_own_handle() {
        let (alice, bob) = (pair(1), pair(2));
        let at_alice = DeadChannel::new(&alice, &bob.x25519_public()).unwrap();
        let at_bob = DeadChannel::new(&bob, &alice.x25519_public()).unwrap();
        let a = alice.x25519_public();
        let b = bob.x25519_public();

        assert_eq!(at_alice.handle(&a, 7), at_bob.handle(&a, 7));
        assert_eq!(
            at_alice.blob_key(&b, 7).expose(),
            at_bob.blob_key(&b, 7).expose()
        );
        assert_ne!(at_alice.handle(&a, 7), at_alice.handle(&b, 7));
        assert_ne!(at_alice.handle(&a, 7), at_alice.handle(&a, 8));
        assert_ne!(
            at_alice.read_secret(&a, 7).expose(),
            at_alice.blob_key(&a, 7).expose()
        );

        // A third party with another key derives another secret.
        let eve = DeadChannel::new(&pair(3), &bob.x25519_public()).unwrap();
        assert_ne!(eve.handle(&a, 7), at_bob.handle(&a, 7));
    }

    #[test]
    fn a_low_order_peer_key_fails() {
        assert!(DeadChannel::new(&pair(1), &[0u8; 32]).is_err());
    }
}
