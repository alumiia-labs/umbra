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

/// The leaves of the prefix tree: the commitment at each index. The tree
/// only grows, because a new version of a label takes a new index
/// (`DIS-007`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixTree {
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
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
        Ok(())
    }

    /// Whether the tree holds a leaf at `index`.
    pub fn contains(&self, index: &[u8; 32]) -> bool {
        self.leaves.contains_key(index)
    }

    fn sorted(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.leaves.iter().map(|(i, c)| (*i, *c)).collect()
    }

    /// The root under the nonce of one epoch.
    pub fn root(&self, nonce: &[u8; 32]) -> [u8; 32] {
        subtree(&self.sorted(), 0, &[0u8; 32], nonce)
    }

    /// The proof for `index` under the nonce of one epoch.
    pub fn prove(&self, nonce: &[u8; 32], index: &[u8; 32]) -> PrefixProof {
        let sorted = self.sorted();
        let mut range: &[([u8; 32], [u8; 32])] = &sorted;
        let mut siblings = Vec::new();
        let mut depth = 0usize;
        while range.len() > 1 && depth < DEPTH_MAX {
            let split = range.partition_point(|(leaf, _)| !bit(leaf, depth));
            let (left, right) = range.split_at(split);
            let (own, other) = if bit(index, depth) {
                (right, left)
            } else {
                (left, right)
            };
            // The sibling subtree sits under the path prefix with the bit
            // of this depth inverted.
            let mut sibling_path = *index;
            if let Some(byte) = sibling_path.get_mut(depth / 8) {
                *byte ^= 0x80 >> (depth % 8);
            }
            siblings.push(subtree(
                other,
                depth.saturating_add(1),
                &sibling_path,
                nonce,
            ));
            range = own;
            depth = depth.saturating_add(1);
        }
        let terminal = match range.first() {
            None => Terminal::Empty,
            Some((leaf, commitment)) if leaf == index => Terminal::Found(*commitment),
            Some((leaf, commitment)) => Terminal::Other {
                index: *leaf,
                commitment: *commitment,
            },
        };
        PrefixProof { terminal, siblings }
    }
}

/// The hash of the subtree that holds `leaves` at `depth`. `path` gives
/// the prefix of the subtree in its first `depth` bits.
fn subtree(
    leaves: &[([u8; 32], [u8; 32])],
    depth: usize,
    path: &[u8; 32],
    nonce: &[u8; 32],
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
                &subtree(left, next, &left_path, nonce),
                &subtree(right, next, &right_path, nonce),
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
