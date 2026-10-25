//! The prefix tree of Part 9 §9.5.1: a binary Merkle tree over the
//! VRF-blinded indexes, with a fresh tree-wide nonce in each hash
//! (`DIS-008`). A leaf sits at the first depth where its prefix is alone.
//! A proof shows a leaf, an empty node, or another leaf on the path of the
//! index, and the last two show an absence.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::hash::sha3_256;
use umbra_wire::codec::{Reader, Writer};

use crate::Error;

const TAG_EMPTY: u8 = 0x10;
const TAG_LEAF: u8 = 0x11;
const TAG_INTERIOR: u8 = 0x12;

/// The greatest depth: one level for each bit of an index.
pub const DEPTH_MAX: usize = 256;

fn bit(index: &[u8; 32], depth: usize) -> bool {
    index
        .get(depth / 8)
        .is_some_and(|byte| (byte >> (7 - depth % 8)) & 1 == 1)
}

/// `index` with each bit at position `depth` or later cleared.
fn prefix_of(index: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut prefix = [0u8; 32];
    for (position, (out, byte)) in prefix.iter_mut().zip(index).enumerate() {
        let first_bit = position.saturating_mul(8);
        *out = if first_bit.saturating_add(8) <= depth {
            *byte
        } else if first_bit >= depth {
            0
        } else {
            byte & !(0xFFu8 >> (depth - first_bit))
        };
    }
    prefix
}

fn depth_bytes(depth: usize) -> [u8; 2] {
    u16::try_from(depth).unwrap_or(u16::MAX).to_be_bytes()
}

fn empty_hash(nonce: &[u8; 32], index: &[u8; 32], depth: usize) -> [u8; 32] {
    sha3_256(&[
        &[TAG_EMPTY],
        nonce,
        &prefix_of(index, depth),
        &depth_bytes(depth),
    ])
}

fn leaf_hash(nonce: &[u8; 32], index: &[u8; 32], depth: usize, commitment: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[&[TAG_LEAF], nonce, index, &depth_bytes(depth), commitment])
}

fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[&[TAG_INTERIOR], left, right])
}

/// What sits at the end of the path of an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// The leaf of the index, with its commitment.
    Found([u8; 32]),
    /// An empty node.
    Empty,
    /// The leaf of another index that shares the prefix.
    Other {
        /// The index of that leaf.
        index: [u8; 32],
        /// The commitment of that leaf.
        commitment: [u8; 32],
    },
}

/// The proof for one index: the terminal, and the sibling at each depth
/// from the root down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixProof {
    /// What the path ends at.
    pub terminal: Terminal,
    /// The siblings, the root level first.
    pub siblings: Vec<[u8; 32]>,
}

impl PrefixProof {
    /// The encoded length.
    pub fn len(&self) -> usize {
        let terminal = match self.terminal {
            Terminal::Found(_) => 32,
            Terminal::Empty => 0,
            Terminal::Other { .. } => 64,
        };
        1 + terminal + 2 + self.siblings.len().saturating_mul(32)
    }

    /// Whether the proof holds no sibling, which is the proof of a tree
    /// with one node.
    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Writes the proof.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        match &self.terminal {
            Terminal::Found(commitment) => {
                w.u8(0x00)?;
                w.put(commitment)?;
            }
            Terminal::Empty => w.u8(0x01)?,
            Terminal::Other { index, commitment } => {
                w.u8(0x02)?;
                w.put(index)?;
                w.put(commitment)?;
            }
        }

        w.u16(u16::try_from(self.siblings.len()).map_err(|_| Error::Malformed)?)?;
        for sibling in &self.siblings {
            w.put(sibling)?;
        }
        Ok(())
    }

    /// Reads a proof.
    pub fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let terminal = match r.u8()? {
            0x00 => Terminal::Found(r.array()?),
            0x01 => Terminal::Empty,
            0x02 => Terminal::Other {
                index: r.array()?,
                commitment: r.array()?,
            },
            _ => return Err(Error::Malformed),
        };

        let count = usize::from(r.u16()?);
        if count > DEPTH_MAX {
            return Err(Error::Malformed);
        }

        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            siblings.push(r.array()?);
        }

        Ok(PrefixProof { terminal, siblings })
    }

    /// Verifies the proof for `index` under `expected_root`, and returns
    /// the commitment of the leaf, or `None` for a proven absence.
    pub fn verify(
        &self,
        nonce: &[u8; 32],
        index: &[u8; 32],
        expected_root: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, Error> {
        let depth = self.siblings.len();
        if depth > DEPTH_MAX {
            return Err(Error::Malformed);
        }

        let (mut hash, found) = match &self.terminal {
            Terminal::Found(commitment) => (
                leaf_hash(nonce, index, depth, commitment),
                Some(*commitment),
            ),
            Terminal::Empty => (empty_hash(nonce, index, depth), None),
            Terminal::Other {
                index: other,
                commitment,
            } => {
                // The other leaf is on the path of `index`, and it is not
                // the leaf of `index`.
                if other == index || prefix_of(other, depth) != prefix_of(index, depth) {
                    return Err(Error::Unverified);
                }
                (leaf_hash(nonce, other, depth, commitment), None)
            }
        };

        for (level, sibling) in self.siblings.iter().enumerate().rev() {
            hash = if bit(index, level) {
                interior_hash(sibling, &hash)
            } else {
                interior_hash(&hash, sibling)
            };
        }

        if hash == *expected_root {
            Ok(found)
        } else {
            Err(Error::Unverified)
        }
    }
}

/// The depth down to which a sealed tree keeps the hash of each subtree.
/// Below it a subtree holds few leaves, and a proof hashes them again.
const CACHE_DEPTH: usize = 20;

/// The key of a cached subtree: its depth and its prefix.
type NodeKey = (u16, [u8; 32]);

/// The leaves of the prefix tree: the commitment at each index. The tree
/// only grows, because a new version of a label takes a new index
/// (`DIS-007`). The tree keeps the subtree hashes of the epoch that
/// [`PrefixTree::seal`] closed, thus a proof under that nonce reads its
/// siblings and hashes no other part of the tree.
#[derive(Debug, Clone, Default)]
pub struct PrefixTree {
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
    cache: BTreeMap<NodeKey, [u8; 32]>,
    cache_nonce: Option<[u8; 32]>,
}

/// The cache of a sealed epoch, which an epoch that does not close gives
/// back.
pub(crate) struct SealCache {
    cache: BTreeMap<NodeKey, [u8; 32]>,
    nonce: Option<[u8; 32]>,
}

impl PartialEq for PrefixTree {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves
    }
}

impl Eq for PrefixTree {}

/// `index` with each bit at position `depth` or later set: the last index
/// of the subtree at that depth.
fn prefix_end(index: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut end = prefix_of(index, depth);
    for (position, byte) in end.iter_mut().enumerate() {
        let first_bit = position.saturating_mul(8);
        if first_bit >= depth {
            *byte = 0xFF;
        } else if first_bit.saturating_add(8) > depth {
            *byte |= 0xFFu8 >> (depth - first_bit);
        }
    }
    end
}

impl PrefixTree {
    /// The count of the leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree holds no leaf.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Adds a leaf. An index that the tree holds is rejected, thus no call
    /// changes or removes a leaf.
    pub fn insert(&mut self, index: [u8; 32], commitment: [u8; 32]) -> Result<(), Error> {
        if self.leaves.contains_key(&index) {
            return Err(Error::Stale);
        }

        self.leaves.insert(index, commitment);
        self.cache.clear();
        self.cache_nonce = None;
        Ok(())
    }

    /// Takes the cache of the sealed epoch out, for [`PrefixTree::undo`].
    pub(crate) fn take_cache(&mut self) -> SealCache {
        SealCache {
            cache: core::mem::take(&mut self.cache),
            nonce: self.cache_nonce.take(),
        }
    }

    /// Takes back the leaves of an epoch that did not close, and puts back
    /// the cache of the epoch before it. The log operator calls this alone,
    /// before any proof names one of those leaves.
    pub(crate) fn undo(&mut self, indexes: &[[u8; 32]], kept: SealCache) {
        for index in indexes {
            self.leaves.remove(index);
        }

        self.cache = kept.cache;
        self.cache_nonce = kept.nonce;
    }

    /// Whether the tree holds a leaf at `index`.
    pub fn contains(&self, index: &[u8; 32]) -> bool {
        self.leaves.contains_key(index)
    }

    /// Whether the last seal ran under `nonce`, with no leaf after it.
    pub(crate) fn is_sealed(&self, nonce: &[u8; 32]) -> bool {
        self.cache_nonce.as_ref() == Some(nonce)
    }

    /// The same leaves with no cache of a seal.
    pub(crate) fn leaves_only(&self) -> Self {
        PrefixTree {
            leaves: self.leaves.clone(),
            ..PrefixTree::default()
        }
    }

    fn sorted(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.leaves.iter().map(|(i, c)| (*i, *c)).collect()
    }

    /// The root under the nonce of one epoch.
    pub fn root(&self, nonce: &[u8; 32]) -> [u8; 32] {
        subtree(&self.sorted(), 0, &[0u8; 32], nonce, &mut None)
    }

    /// The root under the nonce of the epoch that closes, with the hash of
    /// each subtree down to `CACHE_DEPTH` kept for the proofs of that epoch.
    pub fn seal(&mut self, nonce: &[u8; 32]) -> [u8; 32] {
        // A level below about log2(n) - 4 holds subtrees of a few leaves,
        // which a proof hashes again at no cost; the cache keeps no such
        // level, thus it holds about n / 8 nodes.
        let bits = usize::try_from(self.leaves.len().max(1).ilog2()).unwrap_or(0);
        let keep = bits.saturating_sub(4).min(CACHE_DEPTH);

        let mut cache = BTreeMap::new();
        let root = subtree(
            &self.sorted(),
            0,
            &[0u8; 32],
            nonce,
            &mut Some((&mut cache, keep)),
        );

        self.cache = cache;
        self.cache_nonce = Some(*nonce);
        root
    }

    /// The hash of the subtree at `depth` over the prefix of `path`: from
    /// the cache of the sealed epoch, or from the leaves under that prefix.
    fn subtree_at(&self, nonce: &[u8; 32], path: &[u8; 32], depth: usize) -> [u8; 32] {
        let prefix = prefix_of(path, depth);
        if self.cache_nonce.as_ref() == Some(nonce) && depth <= CACHE_DEPTH {
            let key = (u16::try_from(depth).unwrap_or(u16::MAX), prefix);
            if let Some(hash) = self.cache.get(&key) {
                return *hash;
            }
        }

        let leaves: Vec<([u8; 32], [u8; 32])> = self
            .leaves
            .range(prefix..=prefix_end(path, depth))
            .map(|(index, commitment)| (*index, *commitment))
            .collect();

        subtree(&leaves, depth, path, nonce, &mut None)
    }

    /// The proof for `index` under the nonce of one epoch. Each step reads
    /// the leaves under the prefix of the path alone, thus a lookup costs
    /// the depth of the path and not the size of the tree.
    pub fn prove(&self, nonce: &[u8; 32], index: &[u8; 32]) -> PrefixProof {
        let mut siblings = Vec::new();
        let mut depth = 0usize;
        loop {
            let mut under = self
                .leaves
                .range(prefix_of(index, depth)..=prefix_end(index, depth));
            let first = under.next();
            if under.next().is_none() || depth >= DEPTH_MAX {
                let terminal = match first {
                    None => Terminal::Empty,
                    Some((leaf, commitment)) if leaf == index => Terminal::Found(*commitment),
                    Some((leaf, commitment)) => Terminal::Other {
                        index: *leaf,
                        commitment: *commitment,
                    },
                };
                return PrefixProof { terminal, siblings };
            }

            // The sibling subtree sits under the path prefix with the bit
            // of this depth inverted.
            let mut sibling_path = *index;
            if let Some(byte) = sibling_path.get_mut(depth / 8) {
                *byte ^= 0x80 >> (depth % 8);
            }

            let next = depth.saturating_add(1);
            siblings.push(self.subtree_at(nonce, &sibling_path, next));
            depth = next;
        }
    }
}

/// The hash of the subtree that holds `leaves` at `depth`. `path` gives
/// the prefix of the subtree in its first `depth` bits. A cache takes the
/// hash of each subtree down to `CACHE_DEPTH`.
fn subtree(
    leaves: &[([u8; 32], [u8; 32])],
    depth: usize,
    path: &[u8; 32],
    nonce: &[u8; 32],
    cache: &mut Option<(&mut BTreeMap<NodeKey, [u8; 32]>, usize)>,
) -> [u8; 32] {
    let hash = subtree_hash(leaves, depth, path, nonce, cache);

    if let Some((cache, keep)) = cache.as_mut() {
        if depth <= *keep {
            let key = (
                u16::try_from(depth).unwrap_or(u16::MAX),
                prefix_of(path, depth),
            );
            cache.insert(key, hash);
        }
    }
    hash
}

fn subtree_hash(
    leaves: &[([u8; 32], [u8; 32])],
    depth: usize,
    path: &[u8; 32],
    nonce: &[u8; 32],
    cache: &mut Option<(&mut BTreeMap<NodeKey, [u8; 32]>, usize)>,
) -> [u8; 32] {
    match leaves {
        [] => empty_hash(nonce, path, depth),
        [(index, commitment)] => leaf_hash(nonce, index, depth, commitment),
        _ if depth >= DEPTH_MAX => empty_hash(nonce, path, depth),
        _ => {
            let split = leaves.partition_point(|(leaf, _)| !bit(leaf, depth));
            let (left, right) = leaves.split_at(split);

            let mut right_path = *path;
            if let Some(byte) = right_path.get_mut(depth / 8) {
                *byte |= 0x80 >> (depth % 8);
            }

            let mut left_path = *path;
            if let Some(byte) = left_path.get_mut(depth / 8) {
                *byte &= !(0x80 >> (depth % 8));
            }

            let next = depth.saturating_add(1);
            interior_hash(
                &subtree(left, next, &left_path, nonce, cache),
                &subtree(right, next, &right_path, nonce, cache),
            )
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn index(n: u16) -> [u8; 32] {
        sha3_256(&[&n.to_be_bytes()])
    }

    fn tree(count: u16) -> PrefixTree {
        let mut tree = PrefixTree::default();
        for n in 0..count {
            tree.insert(index(n), [n as u8; 32]).unwrap();
        }
        tree
    }

    #[test]
    fn a_sealed_tree_proves_as_an_unsealed_one() {
        let nonce = [7; 32];
        let plain = tree(300);
        let mut sealed = plain.clone();
        assert_eq!(sealed.seal(&nonce), plain.root(&nonce));

        for n in (0..300u16).chain(2_000..2_050) {
            assert_eq!(
                sealed.prove(&nonce, &index(n)),
                plain.prove(&nonce, &index(n))
            );
        }

        // Another nonce reads no cached hash.
        let root = sealed.root(&[9; 32]);
        let proof = sealed.prove(&[9; 32], &index(4));
        assert_eq!(
            proof.verify(&[9; 32], &index(4), &root).unwrap(),
            Some([4; 32])
        );
    }

    #[test]
    fn each_leaf_proves_and_each_other_index_proves_absent() {
        let nonce = [7; 32];
        for count in [0u16, 1, 2, 3, 50] {
            let tree = tree(count);
            let root = tree.root(&nonce);
            for n in 0..count {
                let proof = tree.prove(&nonce, &index(n));
                assert_eq!(
                    proof.verify(&nonce, &index(n), &root).unwrap(),
                    Some([n as u8; 32])
                );
                assert!(proof.verify(&nonce, &index(n + 5_000), &root).is_err());
            }
            for n in 1_000..1_040u16 {
                let proof = tree.prove(&nonce, &index(n));
                assert_eq!(proof.verify(&nonce, &index(n), &root).unwrap(), None);
            }
        }
    }

    #[test]
    fn a_proof_binds_the_nonce_the_commitment_and_the_other_leaf() {
        let tree = tree(50);
        let nonce = [7; 32];
        let root = tree.root(&nonce);
        assert_ne!(
            root,
            tree.root(&[8; 32]),
            "each epoch hashes the whole tree again"
        );

        let mut proof = tree.prove(&nonce, &index(3));
        assert!(proof.verify(&[8; 32], &index(3), &root).is_err());
        proof.terminal = Terminal::Found([0xEE; 32]);
        assert!(proof.verify(&nonce, &index(3), &root).is_err());

        // A present leaf cannot be shown as absent through itself.
        let mut lie = tree.prove(&nonce, &index(3));
        lie.terminal = Terminal::Other {
            index: index(3),
            commitment: [3; 32],
        };
        assert!(lie.verify(&nonce, &index(3), &root).is_err());
        lie.terminal = Terminal::Empty;
        assert!(lie.verify(&nonce, &index(3), &root).is_err());

        let mut grown = tree.clone();
        assert!(grown.insert(index(3), [9; 32]).is_err(), "no leaf changes");
        grown.insert(index(900), [9; 32]).unwrap();
        assert_ne!(grown.root(&nonce), root);
    }

    #[test]
    fn a_proof_round_trips_on_the_wire() {
        let tree = tree(50);
        let nonce = [7; 32];
        for target in [index(3), index(2_000)] {
            let proof = tree.prove(&nonce, &target);
            let mut buffer = alloc::vec![0u8; proof.len()];
            let mut w = Writer::new(&mut buffer);
            proof.write(&mut w).unwrap();
            assert_eq!(w.position(), proof.len());

            let mut r = Reader::new(&buffer);
            assert_eq!(PrefixProof::read(&mut r).unwrap(), proof);
            r.finish().unwrap();
        }

        assert_eq!(prefix_of(&[0xFF; 32], 0), [0; 32]);
        assert_eq!(prefix_of(&[0xFF; 32], 11)[..3], [0xFF, 0xE0, 0x00]);
        assert_eq!(prefix_of(&[0xFF; 32], 256), [0xFF; 32]);
    }
}
