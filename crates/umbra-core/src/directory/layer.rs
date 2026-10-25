//! The layer assignment of Part 10 §10.5.4: a public function of the
//! consensus that puts each chain relay in layer 2 or layer 3, thus an
//! operator cannot select its position. A directory authority computes it
//! one time, at the admission of a relay, and the entry carries the result.
//! A client reads the entry, and it calls this function only for an audit.

use umbra_crypto::{hash::sha3_256, labels};

/// The layer of a chain relay with the queue role, under the seed of the
/// root that listed the relay as pending (`REL-060`, `REL-156`). That root
/// comes after the operator chose `relay_id`, thus no operator grinds
/// against it.
pub fn layer(seed: &[u8; 32], epoch: u64, relay_id: &[u8; 32]) -> u8 {
    let digest = sha3_256(&[labels::RELAY_LAYER, seed, &epoch.to_be_bytes(), relay_id]);
    2 + (digest.last().copied().unwrap_or(0) & 0x01)
}

/// The seed of the layer function under the encoded `DirectoryRoot`
/// `signed_root`, its signatures included (`REL-060`). Each authority signs
/// with fresh randomness, thus no operator knows the seed when it submits
/// its descriptor. The `root` field covers the entries alone, and the
/// operator of a pending relay can compute it for each descriptor that it
/// could submit.
pub fn layer_seed(signed_root: &[u8]) -> [u8; 32] {
    sha3_256(&[signed_root])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_layer_is_two_or_three_and_moves_with_the_root() {
        let mut twos = 0;
        let mut threes = 0;
        for i in 0..64u8 {
            match layer(&[1; 32], 7, &[i; 32]) {
                2 => twos += 1,
                3 => threes += 1,
                _ => panic!("layer outside 2 and 3"),
            }
        }
        assert!(twos > 10 && threes > 10);
        let a = layer(&[1; 32], 7, &[5; 32]);
        let moved = (0..32u8).any(|e| layer(&[e; 32], 7, &[5; 32]) != a);
        assert!(moved);
    }

    #[test]
    fn the_seed_covers_each_byte_of_the_signed_root() {
        let signed = [0x5Cu8; 96];
        let mut other_signature = signed;
        other_signature[95] ^= 1;
        assert_ne!(layer_seed(&signed), layer_seed(&other_signature));
        assert_eq!(layer_seed(&signed), layer_seed(&[0x5C; 96]));
    }
}
