//! One per-hop layer of Part 3 §3.4.4: the key schedule of `NET-106`, the
//! encipher and decipher steps of `NET-108` and `NET-113`, the chaining
//! update of `NET-116`, and the key update of the endpoint layer.
//!
//! The layer is a rugged PRP in the Counter Galois Onion shape. The left
//! block carries the tag of the layer below, thus three layers fit one cell
//! at a constant width.

use aes::{
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher},
    Aes256,
};
use hkdf::Hkdf;
use polyval::{universal_hash::UniversalHash, Polyval};
use sha3::Sha3_256;
use umbra_crypto::{labels, secret::Secret};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

/// The width of the left block, the tag, and the tweak.
pub const BLOCK: usize = 16;

type Ctr = ctr::Ctr128BE<Aes256>;

/// The key set of one hop in one direction.
pub struct HopKeys {
    prp: Secret<32>,
    stream: Secret<32>,
    hash: Secret<16>,
    tweak: [u8; BLOCK],
    chain: [u8; BLOCK],
}

impl Drop for HopKeys {
    fn drop(&mut self) {
        self.tweak.zeroize();
        self.chain.zeroize();
    }
}

/// The two key sets of one hop.
pub struct KeySet {
    /// Client to relay.
    pub forward: HopKeys,
    /// Relay to client.
    pub backward: HopKeys,
}

impl KeySet {
    /// Derives the hop key material from `ss_hop` at `hop_index`, which is
    /// the layer of the relay from 1 to 3 (`NET-106`).
    ///
    /// The tweak `T` of each layer is the last block of the derivation, a
    /// value that both parties of the hop hold. The circuit identifier
    /// cannot serve, because each hop rewrites it and the client never
    /// learns the value on the links after the first.
    pub fn derive(ss_hop: &Secret<32>, hop_index: u32) -> Self {
        let kdf = Hkdf::<Sha3_256>::new(Some(ss_hop.expose()), &[]);
        let mut t = Zeroizing::new([[0u8; BLOCK]; 2 * HOP_BLOCKS + 1]);
        // 208 bytes are inside the HKDF bound, thus expand cannot fail.
        let _ = kdf.expand_multi_info(
            &[labels::ONION_HOP, &hop_index.to_be_bytes()],
            t.as_flattened_mut(),
        );
        let [f0, f1, f2, f3, f4, f5, b0, b1, b2, b3, b4, b5, tweak] = &*t;
        KeySet {
            forward: HopKeys::from_blocks([f0, f1, f2, f3, f4, f5], *tweak),
            backward: HopKeys::from_blocks([b0, b1, b2, b3, b4, b5], *tweak),
        }
    }
}

/// The blocks of the key material of one hop in one direction: `K_prp` and
/// `K_str` of two blocks each, then `K_h`, then the chaining value.
const HOP_BLOCKS: usize = 6;

/// A key of two blocks. The lengths are types, thus a length fault does not
/// compile, and no key falls back to zero bytes.
fn pair(head: &[u8; BLOCK], tail: &[u8; BLOCK]) -> Secret<{ 2 * BLOCK }> {
    let mut out = Secret::<{ 2 * BLOCK }>::zeroed();
    let (first, second) = out.expose_mut().split_at_mut(BLOCK);
    first.copy_from_slice(head);
    second.copy_from_slice(tail);
    out
}

fn xor_into(dst: &mut [u8; BLOCK], src: &[u8; BLOCK]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

impl HopKeys {
    fn from_blocks(material: [&[u8; BLOCK]; HOP_BLOCKS], tweak: [u8; BLOCK]) -> Self {
        let [prp_head, prp_tail, stream_head, stream_tail, hash, chain] = material;
        HopKeys {
            prp: pair(prp_head, prp_tail),
            stream: pair(stream_head, stream_tail),
            hash: Secret::new(*hash),
            tweak,
            chain: *chain,
        }
    }

    /// The current chaining value `C`.
    pub fn chain(&self) -> [u8; BLOCK] {
        self.chain
    }

    /// The tweak `T` of the layer.
    pub fn tweak(&self) -> [u8; BLOCK] {
        self.tweak
    }

    /// A one-way digest of the key set and the chaining value, for the
    /// conformance check of `NET-210` and `NET-112`.
    pub fn fingerprint(&self) -> [u8; 32] {
        umbra_crypto::hash::sha3_256(&[
            self.prp.expose(),
            self.stream.expose(),
            self.hash.expose(),
            &self.tweak,
            &self.chain,
        ])
    }

    fn polyval(&self, data: &[u8]) -> [u8; BLOCK] {
        let mut hasher = Polyval::new(self.hash.expose().into());
        hasher.update_padded(data);
        hasher.finalize().into()
    }

    fn stream(&self, counter: &[u8; BLOCK], data: &mut [u8]) {
        Ctr::new(self.stream.expose().into(), counter.into()).apply_keystream(data);
    }

    fn check_body(body: &[u8]) -> Result<(), Error> {
        if body.is_empty() || !body.len().is_multiple_of(BLOCK) {
            return Err(Error::Length);
        }
        Ok(())
    }

    /// Enciphers one layer in place (`NET-108`) and chains (`NET-116`).
    /// Returns `Y_L`.
    pub fn encipher(&mut self, x_l: &[u8; BLOCK], body: &mut [u8]) -> Result<[u8; BLOCK], Error> {
        Self::check_body(body)?;
        let mut s = *x_l;
        xor_into(&mut s, &self.chain);
        xor_into(&mut s, &self.tweak);
        let mut s_block = s.into();
        Aes256::new(self.prp.expose().into()).encrypt_block(&mut s_block);
        let s: [u8; BLOCK] = s_block.into();
        self.stream(&s, body);
        let mut y_l = s;
        xor_into(&mut y_l, &self.polyval(body));
        self.chain = y_l;
        Ok(y_l)
    }

    /// Deciphers one layer in place (`NET-113`) and chains (`NET-116`).
    /// Returns `X_L`, which the next layer takes as its `Y_L`.
    pub fn decipher(&mut self, y_l: &[u8; BLOCK], body: &mut [u8]) -> Result<[u8; BLOCK], Error> {
        Self::check_body(body)?;
        let mut s = *y_l;
        xor_into(&mut s, &self.polyval(body));
        self.stream(&s, body);
        let mut x_block = s.into();
        Aes256::new(self.prp.expose().into()).decrypt_block(&mut x_block);
        let mut x_l: [u8; BLOCK] = x_block.into();
        xor_into(&mut x_l, &self.chain);
        xor_into(&mut x_l, &self.tweak);
        self.chain = *y_l;
        Ok(x_l)
    }

    /// The key update of the endpoint layer (`NET-204` to `NET-208`): a
    /// fresh key set and chaining value from `K_str` and `Y_L`, and the old
    /// set erased.
    pub fn update(&mut self, y_l: &[u8; BLOCK]) {
        let kdf = Hkdf::<Sha3_256>::new(Some(self.stream.expose()), y_l);
        let mut u = Zeroizing::new([[0u8; BLOCK]; HOP_BLOCKS]);
        // 96 bytes are inside the HKDF bound, thus expand cannot fail.
        let _ = kdf.expand(labels::ONION_HOP_UPDATE, u.as_flattened_mut());
        let [u0, u1, u2, u3, u4, u5] = &*u;
        let fresh = HopKeys::from_blocks([u0, u1, u2, u3, u4, u5], self.tweak);
        self.chain.zeroize();
        *self = fresh;
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

    fn keys() -> KeySet {
        KeySet::derive(&Secret::new([7u8; 32]), 1)
    }

    #[test]
    fn a_layer_round_trips_and_chains() {
        let mut sender = keys();
        let mut receiver = keys();
        let mut body = [0x42u8; 480];
        let y_l = sender.forward.encipher(&[0; 16], &mut body).unwrap();
        assert_ne!(body, [0x42u8; 480]);
        let x_l = receiver.forward.decipher(&y_l, &mut body).unwrap();
        assert_eq!(x_l, [0; 16]);
        assert_eq!(body, [0x42u8; 480]);
        assert_eq!(sender.forward.chain(), receiver.forward.chain());
        // The chain moved, thus a replay of the same cell fails.
        let y_l2 = sender.forward.encipher(&[0; 16], &mut body).unwrap();
        assert_ne!(y_l, y_l2);
        let mut replay = body;
        let x_l = receiver.forward.decipher(&y_l2, &mut replay).unwrap();
        assert_eq!(x_l, [0; 16]);
        let x_l = receiver.forward.decipher(&y_l2, &mut replay).unwrap();
        assert_ne!(x_l, [0; 16]);
    }

    #[test]
    fn each_key_is_its_own_part_of_the_derivation() {
        // NET-106: the forward set, the backward set, then the tweak.
        let kdf = Hkdf::<Sha3_256>::new(Some(&[7u8; 32]), &[]);
        let mut t = [0u8; 208];
        kdf.expand_multi_info(&[labels::ONION_HOP, &1u32.to_be_bytes()], &mut t)
            .unwrap();
        let print = |from: usize| {
            umbra_crypto::hash::sha3_256(&[
                &t[from..from + 32],
                &t[from + 32..from + 64],
                &t[from + 64..from + 80],
                &t[192..208],
                &t[from + 80..from + 96],
            ])
        };
        let set = keys();
        assert_eq!(set.forward.fingerprint(), print(0));
        assert_eq!(set.backward.fingerprint(), print(96));
        assert_eq!(set.forward.tweak(), t[192..208]);

        // NET-204: the update gives the same four parts, and the tweak stays.
        let mut forward = keys().forward;
        let kdf = Hkdf::<Sha3_256>::new(Some(&t[32..64]), &[1; 16]);
        let mut u = [0u8; 96];
        kdf.expand(labels::ONION_HOP_UPDATE, &mut u).unwrap();
        forward.update(&[1; 16]);
        assert_eq!(
            forward.fingerprint(),
            umbra_crypto::hash::sha3_256(&[
                &u[..32],
                &u[32..64],
                &u[64..80],
                &t[192..208],
                &u[80..96]
            ])
        );
    }

    #[test]
    fn one_changed_bit_randomizes_the_left_block() {
        let mut sender = keys();
        let mut body = [0x42u8; 480];
        let y_l = sender.forward.encipher(&[0; 16], &mut body).unwrap();
        let mut receiver = keys();
        let mut bad = body;
        bad[100] ^= 1;
        assert_ne!(receiver.forward.decipher(&y_l, &mut bad).unwrap(), [0; 16]);
        let mut receiver = keys();
        let mut bad_tag = y_l;
        bad_tag[3] ^= 1;
        assert_ne!(
            receiver.forward.decipher(&bad_tag, &mut body).unwrap(),
            [0; 16]
        );
    }

    #[test]
    fn the_directions_and_the_hops_differ_and_the_update_moves_the_keys() {
        let set = keys();
        assert_ne!(set.forward.fingerprint(), set.backward.fingerprint());
        assert_ne!(
            KeySet::derive(&Secret::new([7u8; 32]), 2)
                .forward
                .fingerprint(),
            set.forward.fingerprint()
        );
        let mut a = keys();
        let mut b = keys();
        let before = a.forward.fingerprint();
        a.forward.update(&[1; 16]);
        b.forward.update(&[1; 16]);
        assert_ne!(a.forward.fingerprint(), before);
        assert_eq!(a.forward.fingerprint(), b.forward.fingerprint());
        assert_eq!(a.forward.tweak(), set.forward.tweak());
        assert!(a.forward.encipher(&[0; 16], &mut [0u8; 15]).is_err());
        assert!(a.forward.encipher(&[0; 16], &mut []).is_err());
    }
}
