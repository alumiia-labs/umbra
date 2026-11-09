//! SHA3-256 over a list of parts, for the hashes that the wire objects
//! carry: a roster key hash, a chain hash, a message reference. Also the
//! HMAC-SHA3-256 instance under a 32-byte key.

use hmac::{
    digest::{common::KeySizeUser, typenum::Unsigned, Key, KeyInit},
    Hmac,
};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// The key block of HMAC-SHA3-256, which is the block of SHA3-256.
const KEY_BLOCK_LEN: usize = <<Hmac<Sha3_256> as KeySizeUser>::KeySize as Unsigned>::USIZE;

// A block shorter than the key would cut the key, and no call could tell.
const _: () = assert!(KEY_BLOCK_LEN >= 32);

/// `SHA3-256(parts[0] || parts[1] || ...)`.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `HMAC-SHA3-256` under a 32-byte `key`.
///
/// HMAC pads a key shorter than the hash block with zeros. Thus the padded
/// block gives the same MAC as the 32 bytes, and no call can fail. A fallible
/// call would need a fallback key, and a wrong fallback would run silently.
pub fn hmac_sha3_256(key: &[u8; 32]) -> Hmac<Sha3_256> {
    let mut block = Key::<Hmac<Sha3_256>>::default();
    // The assert on `KEY_BLOCK_LEN` makes the block hold each key byte.
    for (slot, byte) in block.iter_mut().zip(key) {
        *slot = *byte;
    }

    let mac = <Hmac<Sha3_256> as KeyInit>::new(&block);
    block.as_mut_slice().zeroize();
    mac
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_parts_concatenate() {
        assert_eq!(sha3_256(&[b"ab", b"c"]), sha3_256(&[b"abc"]));
        assert_ne!(sha3_256(&[b"ab"]), sha3_256(&[b"abc"]));
    }

    #[test]
    fn the_padded_key_gives_the_mac_of_the_slice_key() {
        use hmac::Mac;

        for seed in [0u8, 1, 0x5c, 0xff] {
            let key: [u8; 32] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
            let mut old = <Hmac<Sha3_256> as KeyInit>::new_from_slice(&key).unwrap();
            let mut new = hmac_sha3_256(&key);
            old.update(b"umbra");
            new.update(b"umbra");
            assert_eq!(old.finalize().into_bytes(), new.finalize().into_bytes());
        }
    }

    #[test]
    fn the_mac_matches_a_known_answer() {
        use hmac::Mac;

        // HMAC-SHA3-256 of the empty message under 32 zero bytes, computed
        // with Python hmac and hashlib.sha3_256.
        let expected: [u8; 32] = [
            0xe8, 0x41, 0xc1, 0x64, 0xe5, 0xb4, 0xf1, 0x0c, 0x9f, 0x39, 0x85, 0x58, 0x79, 0x62,
            0xaf, 0x72, 0xfd, 0x60, 0x7a, 0x95, 0x11, 0x96, 0xfc, 0x92, 0xfb, 0x3a, 0x52, 0x51,
            0x94, 0x17, 0x84, 0xea,
        ];
        let tag: [u8; 32] = hmac_sha3_256(&[0u8; 32]).finalize().into_bytes().into();
        assert_eq!(tag, expected);
    }
}
