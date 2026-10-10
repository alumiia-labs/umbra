//! The layer assignment of Part 10 §10.5.4: a public function of the
//! consensus that puts each chain relay in layer 2 or layer 3, thus an
//! operator cannot select its position. A directory authority computes it
//! one time, at the admission of a relay, and the entry carries the result.
//! A client reads the entry, and it calls this function only for an audit.

use umbra_crypto::{hash::sha3_256, labels};

/// The layer of a chain relay with the queue role, under the root that
/// listed the relay as pending (`REL-060`, `REL-156`). That root comes
/// after the operator chose `relay_id`, thus no operator grinds against it.
pub fn layer(root: &[u8; 32], epoch: u64, relay_id: &[u8; 32]) -> u8 {
    let digest = sha3_256(&[labels::RELAY_LAYER, root, &epoch.to_be_bytes(), relay_id]);
    2 + (digest.last().copied().unwrap_or(0) & 0x01)
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
}
