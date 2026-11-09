//! The relay-set Merkle tree of Part 10 §10.5.3: leaves and nodes under
//! two prefixes, an odd node carried up unchanged, and the inclusion proof
//! a client checks before it selects a relay.

use alloc::vec::Vec;

use umbra_crypto::hash::sha3_256;

use crate::Error;

/// `leaf(e) = SHA3-256(0x00 || entry)`.
pub fn leaf(entry: &[u8]) -> [u8; 32] {
    sha3_256(&[&[0x00], entry])
}

/// `node(l, r) = SHA3-256(0x01 || l || r)`.
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[&[0x01], left, right])
}

/// One step of a proof: the sibling and which side it sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// The sibling hash.
    pub sibling: [u8; 32],
    /// Whether the sibling is on the right of the path node.
    pub sibling_right: bool,
}

/// The root over leaf hashes in `relay_id` order (`REL-054`, `REL-056`).
/// An empty set has no root.
pub fn root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.len() <= 1 {
        return leaves.first().copied();
    }

    let mut level = parent_level(leaves);
    while level.len() > 1 {
        level = parent_level(&level);
    }
    level.first().copied()
}

/// The level above `level`: each pair joins in a node, and an odd last
/// hash goes up unchanged.
fn parent_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        match pair {
            [l, r] => next.push(node(l, r)),
            [odd] => next.push(*odd),
            _ => {}
        }
    }
    next
}

/// Each level above `leaves`, from the parents of the leaves to the root.
/// One leaf or none has no level above it.
fn upper_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    loop {
        let below = levels.last().map_or(leaves, Vec::as_slice);
        if below.len() <= 1 {
            return levels;
        }
        let above = parent_level(below);
        levels.push(above);
    }
}

/// The proof of the leaf at `index`, from the levels of [`upper_levels`].
fn path(leaves: &[[u8; 32]], upper: &[Vec<[u8; 32]>], index: usize) -> Vec<Step> {
    // Each level below the root gives one sibling, or none for an odd last
    // node.
    let below_root = core::iter::once(leaves)
        .chain(upper.iter().map(Vec::as_slice))
        .take(upper.len());

    let mut steps = Vec::with_capacity(upper.len());
    let mut at = index;
    for level in below_root {
        let sibling_index = at ^ 1;
        if let Some(sibling) = level.get(sibling_index) {
            steps.push(Step {
                sibling: *sibling,
                sibling_right: sibling_index > at,
            });
        }
        at /= 2;
    }
    steps
}

/// The proof of the leaf at `index`, from the leaf to the root.
pub fn prove(leaves: &[[u8; 32]], index: usize) -> Option<Vec<Step>> {
    if index >= leaves.len() {
        return None;
    }

    let upper = upper_levels(leaves);
    Some(path(leaves, &upper, index))
}

/// The proof of each leaf, in the order of `leaves`. The levels of the tree
/// are built one time for all the proofs.
pub fn prove_all(leaves: &[[u8; 32]]) -> Vec<Vec<Step>> {
    let upper = upper_levels(leaves);
    (0..leaves.len())
        .map(|index| path(leaves, &upper, index))
        .collect()
}

/// Verifies that `entry` sits under `expected_root` (`REL-057`).
pub fn verify(entry: &[u8], proof: &[Step], expected_root: &[u8; 32]) -> Result<(), Error> {
    verify_leaf(leaf(entry), proof, expected_root)
}

/// Verifies that the leaf hash `leaf_hash` sits under `expected_root`
/// (`REL-057`). A caller that keeps the leaf hash hashes the entry one time.
pub fn verify_leaf(
    leaf_hash: [u8; 32],
    proof: &[Step],
    expected_root: &[u8; 32],
) -> Result<(), Error> {
    let mut hash = leaf_hash;
    for step in proof {
        hash = if step.sibling_right {
            node(&hash, &step.sibling)
        } else {
            node(&step.sibling, &hash)
        };
    }

    if hash == *expected_root {
        Ok(())
    } else {
        Err(Error::Unverified)
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
    fn every_leaf_of_an_odd_tree_proves_and_a_changed_entry_fails() {
        let entries: Vec<Vec<u8>> = (0..7u8).map(|i| alloc::vec![i; 40]).collect();
        let leaves: Vec<[u8; 32]> = entries.iter().map(|e| leaf(e)).collect();
        let r = root(&leaves).unwrap();
        for (i, e) in entries.iter().enumerate() {
            let proof = prove(&leaves, i).unwrap();
            verify(e, &proof, &r).unwrap();
            let mut bad = e.clone();
            bad[0] ^= 1;
            assert!(verify(&bad, &proof, &r).is_err());
        }
        assert!(prove(&leaves, 7).is_none());
        assert!(root(&[]).is_none());
        // A leaf and a node over the same bytes differ (REL-053).
        assert_ne!(leaf(&[0u8; 64]), node(&[0u8; 32], &[0u8; 32]));
        // One leaf is its own root.
        assert_eq!(root(&leaves[..1]).unwrap(), leaves[0]);
        assert!(prove(&leaves[..1], 0).unwrap().is_empty());
    }

    /// The proof of one leaf, one level after the other, as the tree of
    /// `REL-057` defines it.
    fn level_by_level(leaves: &[[u8; 32]], index: usize) -> Vec<Step> {
        let mut level = leaves.to_vec();
        let mut at = index;
        let mut steps = Vec::new();
        while level.len() > 1 {
            if let Some(sibling) = level.get(at ^ 1) {
                steps.push(Step {
                    sibling: *sibling,
                    sibling_right: at ^ 1 > at,
                });
            }
            level = parent_level(&level);
            at /= 2;
        }
        steps
    }

    #[test]
    fn the_proofs_of_all_leaves_match_the_proof_of_each_leaf() {
        for count in 0..=9u8 {
            let leaves: Vec<[u8; 32]> = (0..count).map(|i| leaf(&[i; 40])).collect();
            let all = prove_all(&leaves);
            assert_eq!(all.len(), leaves.len());
            for (index, proof) in all.iter().enumerate() {
                assert_eq!(*proof, prove(&leaves, index).unwrap());
                assert_eq!(*proof, level_by_level(&leaves, index));
                verify_leaf(leaves[index], proof, &root(&leaves).unwrap()).unwrap();
            }
        }
    }
}
