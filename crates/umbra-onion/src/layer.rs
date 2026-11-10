//! One per-hop layer of Part 3 §3.4.4: the key schedule of `NET-106`, the
//! encipher and decipher steps of `NET-108` and `NET-113`, the chaining
//! update of `NET-116`, and the key update of the endpoint layer.
//!
//! The layer is a rugged PRP in the Counter Galois Onion shape. The left
//! block carries the tag of the layer below, thus three layers fit one cell
//! at a constant width.

use aes::{
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, InnerIvInit, KeyInit, StreamCipher},
    Aes256, Aes256Enc,
};
use hkdf::Hkdf;
use polyval::{universal_hash::UniversalHash, Polyval};
use sha3::Sha3_256;
use umbra_crypto::{labels, secret::Secret};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

/// The width of the left block, the tag, and the tweak.
pub const BLOCK: usize = 16;

type Ctr = ctr::Ctr128BE<Aes256Enc>;

/// The key set of one hop in one direction.
pub struct HopKeys {
    prp: Secret<32>,
    stream: Secret<32>,
    hash: Secret<16>,
    tweak: [u8; BLOCK],
    chain: [u8; BLOCK],
    // The key schedules of `prp` and `stream`, made once for each key set
    // and not for each cell. The `zeroize` feature of `aes` wipes each one
    // when it drops, thus an update also erases them (`NET-208`).
    prp_cipher: Aes256,
    stream_cipher: Aes256Enc,
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
        // `EXPAND_FITS` proves the length, thus expand cannot fail.
        let filled = kdf.expand_multi_info(
            &[labels::ONION_HOP, &hop_index.to_be_bytes()],
            t.as_flattened_mut(),
        );
        debug_assert!(filled.is_ok());

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

/// The largest output of one HKDF-SHA3-256 expand: 255 blocks of the hash.
const HKDF_MAX: usize = 255 * 32;

// A longer derivation would fail at expand and leave a key set of zero
// bytes. This check stops such a change at compile time.
const EXPAND_FITS: () = assert!((2 * HOP_BLOCKS + 1) * BLOCK <= HKDF_MAX);
const _: () = EXPAND_FITS;

/// A key of two blocks. The lengths are types, thus a length fault does not
/// compile, and no key falls back to zero bytes.
fn pair(head: &[u8; BLOCK], tail: &[u8; BLOCK]) -> Secret<{ 2 * BLOCK }> {
    let mut out = Secret::<{ 2 * BLOCK }>::zeroed();
    write_pair(&mut out, head, tail);
    out
}

fn write_pair(key: &mut Secret<{ 2 * BLOCK }>, head: &[u8; BLOCK], tail: &[u8; BLOCK]) {
    let (first, second) = key.expose_mut().split_at_mut(BLOCK);
    first.copy_from_slice(head);
    second.copy_from_slice(tail);
}

/// The last block of the POLYVAL input: the length of the body in bytes, as
/// a big-endian integer in the last 8 bytes (`NET-108`).
fn length_block(body_len: usize) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    let (_, tail) = block.split_at_mut(BLOCK / 2);
    tail.copy_from_slice(&u64::try_from(body_len).unwrap_or(u64::MAX).to_be_bytes());
    block
}

fn xor_into(dst: &mut [u8; BLOCK], src: &[u8; BLOCK]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

impl HopKeys {
    fn from_blocks(material: [&[u8; BLOCK]; HOP_BLOCKS], tweak: [u8; BLOCK]) -> Self {
        let [prp_head, prp_tail, stream_head, stream_tail, hash, chain] = material;
        let prp = pair(prp_head, prp_tail);
        let stream = pair(stream_head, stream_tail);
        let prp_cipher = Aes256::new(prp.expose().into());
        let stream_cipher = Aes256Enc::new(stream.expose().into());
        HopKeys {
            prp,
            stream,
            hash: Secret::new(*hash),
            tweak,
            chain: *chain,
            prp_cipher,
            stream_cipher,
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
        // POLYVAL ignores zero blocks at the start of its input. The length
        // block binds the bucket, thus no hop makes a longer cell of a
        // shorter one with the same tag.
        hasher.update_padded(&length_block(data.len()));
        hasher.finalize().into()
    }

    fn stream(&self, counter: &[u8; BLOCK], data: &mut [u8]) {
        // The copy of the key schedule wipes itself when the counter mode drops.
        let core = ctr::CtrCore::inner_iv_init(self.stream_cipher.clone(), counter.into());
        Ctr::from_core(core).apply_keystream(data);
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
        self.prp_cipher.encrypt_block(&mut s_block);
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
        self.prp_cipher.decrypt_block(&mut x_block);
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
        // `EXPAND_FITS` covers this shorter length also.
        let filled = kdf.expand(labels::ONION_HOP_UPDATE, u.as_flattened_mut());
        debug_assert!(filled.is_ok());
        let [prp_head, prp_tail, stream_head, stream_tail, hash, chain] = &*u;

        // NET-208: each key goes into its own place. A new key set on the
        // stack would leave a copy that no drop erases.
        write_pair(&mut self.prp, prp_head, prp_tail);
        write_pair(&mut self.stream, stream_head, stream_tail);
        self.hash.expose_mut().copy_from_slice(hash);
        self.chain = *chain;

        // Each old key schedule wipes itself when the new one replaces it.
        self.prp_cipher = Aes256::new(self.prp.expose().into());
        self.stream_cipher = Aes256Enc::new(self.stream.expose().into());
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
    fn a_longer_body_with_zero_blocks_in_front_does_not_keep_the_tag() {
        let mut sender = keys();
        let mut body = [0x42u8; 480];
        let y_l = sender.forward.encipher(&[0; 16], &mut body).unwrap();

        // A hostile hop puts zero blocks before the body of a small cell.
        let mut longer = [0u8; 2_016];
        longer[2_016 - 480..].copy_from_slice(&body);
        let mut receiver = keys();
        assert_ne!(
            receiver.forward.decipher(&y_l, &mut longer).unwrap(),
            [0; 16]
        );

        // The same cell at its own length still opens.
        let mut receiver = keys();
        assert_eq!(receiver.forward.decipher(&y_l, &mut body).unwrap(), [0; 16]);
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

    /// The layer as it was before the cached key schedules: a key expansion
    /// for each step. The cache must give the same bytes.
    fn reference_encipher(
        prp: &[u8; 32],
        stream: &[u8; 32],
        hash: &[u8; 16],
        tweak: &[u8; 16],
        chain: &[u8; 16],
        x_l: &[u8; 16],
        body: &mut [u8],
    ) -> [u8; 16] {
        use aes::cipher::KeyIvInit;

        let mut s = *x_l;
        xor_into(&mut s, chain);
        xor_into(&mut s, tweak);
        let mut s_block = s.into();
        Aes256::new(prp.into()).encrypt_block(&mut s_block);
        let s: [u8; 16] = s_block.into();
        ctr::Ctr128BE::<Aes256>::new(stream.into(), (&s).into()).apply_keystream(body);

        let mut hasher = Polyval::new(hash.into());
        hasher.update_padded(body);
        let mut len = [0u8; 16];
        len[8..].copy_from_slice(&(body.len() as u64).to_be_bytes());
        hasher.update_padded(&len);
        let mut y_l = s;
        xor_into(&mut y_l, &hasher.finalize().into());
        y_l
    }

    #[test]
    fn the_cached_key_schedules_give_the_bytes_of_a_fresh_expansion() {
        let mut sender = keys().forward;
        let mut receiver = keys().forward;
        for round in 0u8..6 {
            let x_l = [round; 16];
            let mut plain = [0u8; 480];
            for (i, b) in plain.iter_mut().enumerate() {
                *b = (i as u8) ^ round;
            }

            let mut expected = plain;
            let expected_y = reference_encipher(
                sender.prp.expose(),
                sender.stream.expose(),
                sender.hash.expose(),
                &sender.tweak,
                &sender.chain,
                &x_l,
                &mut expected,
            );

            let mut body = plain;
            let y_l = sender.encipher(&x_l, &mut body).unwrap();
            assert_eq!(y_l, expected_y);
            assert_eq!(body, expected);

            assert_eq!(receiver.decipher(&y_l, &mut body).unwrap(), x_l);
            assert_eq!(body, plain);

            // An update rebuilds the schedules from the new keys.
            if round % 2 == 1 {
                sender.update(&y_l);
                receiver.update(&y_l);
            }
        }
    }
}
