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
        let _ = self.push_proving(leaf_hash);
    }

    /// As [`LogFrontier::push`], and gives the inclusion proof of the new
    /// leaf under the new root, as [`prove_newest`] gives it over each
    /// leaf. Each subtree that joins is one step, and then each subtree on
    /// the left is one, thus the proof costs no pass over the leaves.
    pub fn push_proving(&mut self, leaf_hash: [u8; 32]) -> Vec<Step> {
        let left = |sibling: [u8; 32]| Step {
            sibling,
            sibling_right: false,
        };
        let mut steps = Vec::new();
        let mut height = 0u32;
        let mut hash = leaf_hash;
        while let Some((last_height, last_hash)) = self.subtrees.last().copied() {
            if last_height != height {
                break;
            }
            self.subtrees.pop();
            steps.push(left(last_hash));
            hash = node(&last_hash, &hash);
            height = height.saturating_add(1);
        }
        steps.extend(self.subtrees.iter().rev().map(|(_, root)| left(*root)));
        self.subtrees.push((height, hash));
        self.size = self.size.saturating_add(1);
        steps
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

/// The root of each full subtree of a log, at each height. Level 0 holds
/// the leaf hashes. Level `h` holds the roots of the subtrees of 2^h
/// leaves, in the order of the log. A consistency proof reads a few of
/// these roots, thus a request for one costs no pass over the leaves. A log
/// of one year holds about 53 000 leaves and twice that many roots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogNodes {
    levels: Vec<Vec<[u8; 32]>>,
}

impl LogNodes {
    /// The number of leaves.
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// Whether the log holds no leaf.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends one leaf hash, and the root of each subtree that it fills.
    pub fn push(&mut self, leaf_hash: [u8; 32]) {
        let mut hash = leaf_hash;
        let mut height = 0usize;
        loop {
            if self.levels.len() <= height {
                self.levels.push(Vec::new());
            }
            let Some(level) = self.levels.get_mut(height) else {
                return;
            };
            level.push(hash);
            // An even count fills the subtree one level up.
            let filled = match level.as_slice() {
                [.., left, right] if level.len().is_multiple_of(2) => node(left, right),
                _ => return,
            };
            hash = filled;
            height = height.saturating_add(1);
        }
    }

    /// The root over the `count` leaves from `start`, as [`root`] gives it
    /// over that slice. Each range that a proof asks for starts at a
    /// multiple of its split points, thus the levels hold its full
    /// subtrees.
    fn range_root(&self, start: usize, count: usize) -> Option<[u8; 32]> {
        if count == 0 {
            return None;
        }
        if count.is_power_of_two() && start.is_multiple_of(count) {
            let height = usize::try_from(count.trailing_zeros()).ok()?;
            return self.levels.get(height)?.get(start / count).copied();
        }
        let k = split_point(count);
        let left = self.range_root(start, k)?;
        let right = self.range_root(start.checked_add(k)?, count.checked_sub(k)?)?;
        Some(node(&left, &right))
    }

    fn subproof(
        &self,
        first: usize,
        start: usize,
        count: usize,
        whole: bool,
        out: &mut Vec<[u8; 32]>,
    ) {
        if first == count {
            if !whole {
                out.extend(self.range_root(start, count));
            }
            return;
        }
        let k = split_point(count).min(count);
        let after = start.saturating_add(k);
        let rest = count.saturating_sub(k);
        if first <= k {
            self.subproof(first, start, k, whole, out);
            out.extend(self.range_root(after, rest));
        } else {
            self.subproof(first.saturating_sub(k), after, rest, false, out);
            out.extend(self.range_root(start, k));
        }
    }

    /// The consistency proof from the tree of the first `first` leaves to
    /// the tree of each leaf, as [`prove_consistency`] gives it.
    pub fn consistency(&self, first: usize) -> Option<Vec<[u8; 32]>> {
        if first == 0 || first > self.len() {
            return None;
        }
        let mut out = Vec::new();
        self.subproof(first, 0, self.len(), true, &mut out);
        Some(out)
    }
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
    fn the_held_subtree_roots_give_each_consistency_proof() {
        let all = leaves(70);
        let mut nodes = LogNodes::default();
        assert!(nodes.is_empty() && nodes.consistency(1).is_none());
        for (count, leaf_hash) in all.iter().enumerate() {
            nodes.push(*leaf_hash);
            let size = count + 1;
            assert_eq!(nodes.len(), size);
            for first in 1..=size {
                assert_eq!(
                    nodes.consistency(first),
                    prove_consistency(&all[..size], first),
                    "{first} of {size}"
                );
            }
            assert!(nodes.consistency(0).is_none());
            assert!(nodes.consistency(size + 1).is_none());
        }
    }

    #[test]
    fn the_frontier_gives_the_proof_of_each_newest_leaf() {
        let all = leaves(70);
        let mut frontier = LogFrontier::default();
        for (count, leaf_hash) in all.iter().enumerate() {
            let proof = frontier.push_proving(*leaf_hash);
            assert_eq!(Some(&proof), prove_newest(&all[..=count]).as_ref());
            verify_newest(leaf_hash, &proof, &frontier.root().unwrap()).unwrap();
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
