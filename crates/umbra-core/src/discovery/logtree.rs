//! The log tree of Part 9 §9.5.1: a left-balanced append-only Merkle tree
//! with one leaf for each epoch. The hashes and the inclusion proof are
//! those of [`crate::directory::tree`], which has the same shape. This
//! file adds the consistency proof between two sizes, in the manner of
//! RFC 9162 §2.1.4.

use alloc::vec::Vec;

use crate::{
    directory::tree::{leaf, node, prove, root, Step},
    Error,
};

/// The data of the log leaf of one epoch: the tree-wide nonce of that
/// epoch, then the root of the prefix tree after the updates of the epoch.
pub fn epoch_leaf(nonce: &[u8; 32], prefix_root: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    let (nonce_part, root_part) = data.split_at_mut(32);
    nonce_part.copy_from_slice(nonce);
    root_part.copy_from_slice(prefix_root);
    leaf(&data)
}

/// The root over the leaf hashes.
pub fn log_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    root(leaves)
}

/// The roots of the full subtrees of a log, from the largest on the left:
/// the root of the next size comes from these and one leaf, thus a close
/// of an epoch hashes a few nodes and not each leaf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFrontier {
    size: u64,
    /// Each full subtree: its height, then its root.
    subtrees: Vec<(u32, [u8; 32])>,
}

impl LogFrontier {
    /// The number of leaves.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Appends one leaf hash. Two full subtrees of one height join.
    pub fn push(&mut self, leaf_hash: [u8; 32]) {
        let mut height = 0u32;
        let mut hash = leaf_hash;
        while let Some((last_height, last_hash)) = self.subtrees.last().copied() {
            if last_height != height {
                break;
            }
            self.subtrees.pop();
            hash = node(&last_hash, &hash);
            height = height.saturating_add(1);
        }
        self.subtrees.push((height, hash));
        self.size = self.size.saturating_add(1);
    }

    /// The root, as [`log_root`] gives it over the same leaves.
    pub fn root(&self) -> Option<[u8; 32]> {
        let mut subtrees = self.subtrees.iter().rev();
        let (_, mut hash) = *subtrees.next()?;
        for (_, left) in subtrees {
            hash = node(left, &hash);
        }
        Some(hash)
    }
}

/// The inclusion proof of the newest leaf.
pub fn prove_newest(leaves: &[[u8; 32]]) -> Option<Vec<Step>> {
    prove(leaves, leaves.len().checked_sub(1)?)
}

/// Verifies that `newest_leaf` is the last leaf under `expected_root`. The
/// last leaf of a left-balanced tree has each sibling on its left, thus a
/// proof with a sibling on the right names another position.
pub fn verify_newest(
    newest_leaf: &[u8; 32],
    proof: &[Step],
    expected_root: &[u8; 32],
) -> Result<(), Error> {
    let mut hash = *newest_leaf;
    for step in proof {
        if step.sibling_right {
            return Err(Error::Unverified);
        }
        hash = node(&step.sibling, &hash);
    }
    if hash == *expected_root {
        Ok(())
    } else {
        Err(Error::Unverified)
    }
}

/// The largest power of two below `n`, for `n` of 2 or more.
fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

fn subproof(first: usize, leaves: &[[u8; 32]], whole: bool, out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if first == n {
        if !whole {
            out.extend(root(leaves));
        }
        return;
    }
    let k = split_point(n);
    let (left, right) = leaves.split_at(k.min(n));
    if first <= k {
        subproof(first, left, whole, out);
        out.extend(root(right));
    } else {
        subproof(first.saturating_sub(k), right, false, out);
        out.extend(root(left));
    }
}

/// The consistency proof from the tree of the first `first` leaves to the
/// tree of all of `leaves`.
pub fn prove_consistency(leaves: &[[u8; 32]], first: usize) -> Option<Vec<[u8; 32]>> {
    if first == 0 || first > leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    subproof(first, leaves, true, &mut out);
    Some(out)
}

/// Verifies that the tree of `second` leaves under `second_root` extends
/// the tree of `first` leaves under `first_root`.
pub fn verify_consistency(
    first: u64,
    first_root: &[u8; 32],
    second: u64,
    second_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> Result<(), Error> {
    if first == 0 || first > second {
        return Err(Error::Unverified);
    }
    if first == second {
        return if proof.is_empty() && first_root == second_root {
            Ok(())
        } else {
            Err(Error::Unverified)
        };
    }
    let mut path = proof.iter();
    let mut from_node = first.saturating_sub(1);
    let mut to_node = second.saturating_sub(1);
    while from_node & 1 == 1 {
        from_node >>= 1;
        to_node >>= 1;
    }
    // A first tree that is one full subtree is its own first proof node.
    let seed = if first.is_power_of_two() {
        *first_root
    } else {
        *path.next().ok_or(Error::Unverified)?
    };
    let mut first_hash = seed;
    let mut second_hash = seed;
    for sibling in path {
        if to_node == 0 {
            return Err(Error::Unverified);
        }
        if from_node & 1 == 1 || from_node == to_node {
            first_hash = node(sibling, &first_hash);
            second_hash = node(sibling, &second_hash);
            while from_node & 1 == 0 && from_node != 0 {
                from_node >>= 1;
                to_node >>= 1;
            }
        } else {
            second_hash = node(&second_hash, sibling);
        }
        from_node >>= 1;
        to_node >>= 1;
    }
    if to_node == 0 && first_hash == *first_root && second_hash == *second_root {
        Ok(())
    } else {
        Err(Error::Unverified)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn leaves(n: u8) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| epoch_leaf(&[i; 32], &[i ^ 0xFF; 32]))
            .collect()
    }

    #[test]
    fn each_pair_of_sizes_proves_consistent_and_a_changed_leaf_does_not() {
        for n in 1..=20u8 {
            let all = leaves(n);
            let second_root = log_root(&all).unwrap();
            for first in 1..=usize::from(n) {
                let first_root = log_root(&all[..first]).unwrap();
                let proof = prove_consistency(&all, first).unwrap();
                verify_consistency(
                    first as u64,
                    &first_root,
                    u64::from(n),
                    &second_root,
                    &proof,
                )
                .unwrap();

                // A log that rewrote an old leaf does not extend the old tree.
                let mut forked = all.clone();
                forked[first - 1] = [0xEE; 32];
                let forked_root = log_root(&forked).unwrap();
                let forked_proof = prove_consistency(&forked, first).unwrap();
                assert!(verify_consistency(
                    first as u64,
                    &first_root,
                    u64::from(n),
                    &forked_root,
                    &forked_proof
                )
                .is_err());
            }
        }
        assert!(prove_consistency(&leaves(3), 0).is_none());
        assert!(prove_consistency(&leaves(3), 4).is_none());
        assert!(verify_consistency(3, &[0; 32], 2, &[0; 32], &[]).is_err());
    }

    #[test]
    fn the_frontier_gives_the_root_of_each_size() {
        let all = leaves(70);
        let mut frontier = LogFrontier::default();
        assert!(frontier.root().is_none());
        for (count, leaf_hash) in all.iter().enumerate() {
            frontier.push(*leaf_hash);
            assert_eq!(frontier.size(), count as u64 + 1);
            assert_eq!(frontier.root(), log_root(&all[..=count]));
        }
    }

    #[test]
    fn the_newest_leaf_proves_at_the_last_position_only() {
        for n in 1..=9u8 {
            let all = leaves(n);
            let tree_root = log_root(&all).unwrap();
            let proof = prove_newest(&all).unwrap();
            verify_newest(all.last().unwrap(), &proof, &tree_root).unwrap();
            if n > 1 {
                let older = prove(&all, 0).unwrap();
                assert!(verify_newest(&all[0], &older, &tree_root).is_err());
            }
        }
        assert!(prove_newest(&[]).is_none());
    }
}
