//! The relay manifest of Part 10 §10.5.5: a signed root, and relay entries
//! with their inclusion proofs. A bootstrap carrier of Part 3 §3.10 moves it,
//! and no carrier needs trust, because each byte of it is under the root.

use alloc::vec::Vec;

use umbra_wire::codec::{Reader, Writer};

use super::{
    bloc::BlocList,
    descriptor::{roles, RelayEntry, ENTRY_LEN},
    path::Candidate,
    root::{Consensus, DirectoryRoot},
    tree::{self, Step},
};
use crate::Error;

/// The largest count of steps in one proof: a tree of 65 536 leaves.
pub const PROOF_STEPS_MAX: usize = 16;
/// The encoded width of one proof step.
const STEP_LEN: usize = 33;

/// One entry of a manifest with its proof under the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenEntry<'a> {
    /// The bytes of a `RelayEntry`.
    pub entry: &'a [u8],
    /// The sibling of each level, from the leaf to the root.
    pub proof: Vec<Step>,
}

/// A relay manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayManifest<'a> {
    /// The bytes of a `DirectoryRoot`.
    pub root: &'a [u8],
    /// The entries, in ascending order of `relay_id`.
    pub entries: Vec<ProvenEntry<'a>>,
}

impl<'a> RelayManifest<'a> {
    /// The encoded width.
    pub fn len(&self) -> usize {
        let entries: usize = self
            .entries
            .iter()
            .map(|entry| ENTRY_LEN + 1 + entry.proof.len() * STEP_LEN)
            .sum();
        1 + 2 + self.root.len() + 2 + entries
    }

    /// Whether the manifest holds no entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writes the manifest.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; self.len()];
        let mut w = Writer::new(&mut out);
        w.u8(0x01)?;
        w.u16(u16::try_from(self.root.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.root)?;
        w.u16(u16::try_from(self.entries.len()).map_err(|_| Error::Malformed)?)?;
        for proven in &self.entries {
            if proven.entry.len() != ENTRY_LEN || proven.proof.len() > PROOF_STEPS_MAX {
                return Err(Error::Malformed);
            }
            w.put(proven.entry)?;
            w.u8(u8::try_from(proven.proof.len()).map_err(|_| Error::Malformed)?)?;
            for step in &proven.proof {
                w.u8(u8::from(step.sibling_right))?;
                w.put(&step.sibling)?;
            }
        }
        Ok(out)
    }

    /// Reads a manifest. It verifies nothing: `RelaySet::accept` does.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let root_len = usize::from(r.u16()?);
        let root = r.take(root_len)?;
        let entry_count = usize::from(r.u16()?);
        // A count that the bytes cannot hold must not size an allocation.
        if entry_count > r.remaining() / (ENTRY_LEN + 1) {
            return Err(Error::Malformed);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let entry = r.take(ENTRY_LEN)?;
            let step_count = usize::from(r.u8()?);
            if step_count > PROOF_STEPS_MAX {
                return Err(Error::Malformed);
            }
            let mut proof = Vec::with_capacity(step_count);
            for _ in 0..step_count {
                let sibling_right = match r.u8()? {
                    0x00 => false,
                    0x01 => true,
                    _ => return Err(Error::Malformed),
                };
                proof.push(Step {
                    sibling: r.array()?,
                    sibling_right,
                });
            }
            entries.push(ProvenEntry { entry, proof });
        }
        r.finish()?;
        Ok(RelayManifest { root, entries })
    }
}

/// One relay of a verified manifest: what a client needs to dial it, to open
/// a hop to it, and to test a chain that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedRelay {
    /// The facts that the path selection tests.
    pub candidate: Candidate,
    /// The X25519 static of the hop handshake.
    pub ntor_pk: [u8; 32],
    /// The IPv4 address, or zero.
    pub addr_v4: [u8; 4],
    /// The IPv6 address, or zero.
    pub addr_v6: [u8; 16],
    /// The port.
    pub port: u16,
    /// The co-tenant host name.
    pub host: alloc::string::String,
    /// ISO 3166-1 alpha-2.
    pub jurisdiction: [u8; 2],
    /// Whether the descriptor offers the attachment role.
    pub has_attachment_role: bool,
    /// The ML-DSA-65 identity key, which signs the proof-of-work
    /// challenge of the relay (Part 13 `ABU-068`).
    pub identity_pk: Vec<u8>,
    /// The verified class, 0 to 3.
    pub class: u8,
}

/// The relays of one accepted manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySet {
    /// The epoch of the root.
    pub epoch: u64,
    /// The Merkle root over the relay set.
    pub root: [u8; 32],
    /// The relays, in ascending order of `relay_id`.
    pub relays: Vec<ListedRelay>,
}

impl RelaySet {
    /// Accepts the root of a manifest under `consensus`, and then verifies
    /// each entry under that root. One entry that fails rejects the whole
    /// manifest, because a carrier that changed one byte gets no part of its
    /// choice through.
    pub fn accept<'a>(
        consensus: &mut Consensus<'a>,
        manifest: &RelayManifest<'a>,
        blocs: &BlocList,
        device_clock: u64,
    ) -> Result<Self, Error> {
        let root = DirectoryRoot::parse(manifest.root)?;
        // The blocs decide invariant 2, thus the list must be the signed one.
        if root.bloc_hash != blocs.hash()? {
            return Err(Error::Unverified);
        }
        // The root comes first: a carrier must not make a client verify the
        // signature of each entry under a root that no authority signed.
        consensus.verify(&root, device_clock)?;
        let (epoch, merkle_root) = (root.epoch, root.root);
        // The consensus takes the root after the last entry, because a
        // manifest with a bad entry must leave the consensus as it was.
        let mut relays: Vec<ListedRelay> = Vec::with_capacity(manifest.entries.len());
        for proven in &manifest.entries {
            tree::verify(proven.entry, &proven.proof, &merkle_root)?;
            let entry = RelayEntry::parse(proven.entry)?;
            let descriptor = &entry.descriptor;
            if descriptor.valid_after > epoch {
                return Err(Error::Unverified);
            }
            let is_after_last = relays
                .last()
                .is_none_or(|last| last.candidate.relay_id < descriptor.relay_id);
            if !is_after_last {
                return Err(Error::Malformed);
            }
            relays.push(ListedRelay {
                candidate: Candidate::from_entry(&entry, blocs),
                ntor_pk: descriptor.ntor_pk,
                addr_v4: descriptor.addr_v4,
                addr_v6: descriptor.addr_v6,
                port: descriptor.port,
                host: descriptor.host_str().into(),
                jurisdiction: descriptor.jurisdiction,
                has_attachment_role: descriptor.roles & roles::ATTACHMENT != 0,
                identity_pk: descriptor.identity_pk.to_vec(),
                class: entry.class,
            });
        }
        consensus.commit(root, device_clock);
        Ok(RelaySet {
            epoch,
            root: merkle_root,
            relays,
        })
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
    use crate::directory::{
        descriptor::tests::entry_bytes,
        root::{
            tests::{authorities, keyset_of, signed_root},
            DirectoryKeySet,
        },
    };

    /// Entries in the order of the tree, and their leaves.
    fn sorted_entries(seeds: &[u8]) -> Vec<Vec<u8>> {
        let mut entries: Vec<Vec<u8>> = seeds
            .iter()
            // The flags go 1, 2, 0 in turn: an ingress, a last relay, and a
            // relay of layer 2.
            .map(|seed| {
                entry_bytes(
                    *seed,
                    [b'A' + *seed, b'A'],
                    64_500 + u32::from(*seed),
                    *seed % 3,
                )
            })
            .collect();
        entries.sort_by_key(|entry| entry[1..33].to_vec());
        entries
    }

    fn manifest_of<'a>(
        root: &'a [u8],
        entries: &'a [Vec<u8>],
        listed: &[usize],
    ) -> RelayManifest<'a> {
        let leaves: Vec<[u8; 32]> = entries.iter().map(|entry| tree::leaf(entry)).collect();
        RelayManifest {
            root,
            entries: listed
                .iter()
                .map(|index| ProvenEntry {
                    entry: &entries[*index],
                    proof: tree::prove(&leaves, *index).unwrap(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_manifest_gives_its_relays_and_a_changed_one_gives_none() {
        let keys = authorities(40);
        let (pks, _) = keyset_of(&keys, 1);
        let keyset = || DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|key| &key[..]).collect(),
        };
        let keyset_hash = keyset().hash().unwrap();
        let entries = sorted_entries(&[1, 2, 3, 4, 5, 6]);
        let leaves: Vec<[u8; 32]> = entries.iter().map(|entry| tree::leaf(entry)).collect();
        let merkle_root = tree::root(&leaves).unwrap();
        let root = signed_root(&keys, &[0, 2, 3, 5, 6], 200, keyset_hash, merkle_root);
        let blocs = BlocList::v1();

        // The whole set, and then a part of it: each entry has its proof.
        for listed in [&[0usize, 1, 2, 3, 4, 5][..], &[1, 3][..]] {
            let manifest = manifest_of(&root, &entries, listed);
            let bytes = manifest.encode().unwrap();
            assert_eq!(bytes.len(), manifest.len());
            let read = RelayManifest::parse(&bytes).unwrap();
            assert_eq!(read, manifest);
            let mut consensus = Consensus::new(keyset(), 100).unwrap();
            let set = RelaySet::accept(&mut consensus, &read, &blocs, 200 * 3_600).unwrap();
            assert_eq!(set.relays.len(), listed.len());
            assert_eq!(set.epoch, 200);
            assert!(set.relays.iter().all(|relay| relay.host == "relay.example"));
            for layer in 1..=3u8 {
                let of_layer = set
                    .relays
                    .iter()
                    .filter(|relay| relay.candidate.layer == layer);
                if listed.len() == entries.len() {
                    assert_eq!(of_layer.count(), 2, "layer {layer}");
                }
            }
            assert!(set
                .relays
                .iter()
                .all(|relay| relay.candidate.is_exit() == (relay.candidate.layer == 3)));
            assert!(consensus.accepted().is_some());
        }

        let refused = |manifest: &RelayManifest<'_>| {
            let mut consensus = Consensus::new(keyset(), 100).unwrap();
            let result = RelaySet::accept(&mut consensus, manifest, &blocs, 200 * 3_600);
            // A refused manifest must not move the consensus.
            assert!(consensus.accepted().is_none());
            result.is_err()
        };
        // An entry of another tree, an order that is not ascending, the same
        // entry two times, and a proof that lost a step.
        let others = sorted_entries(&[7, 8]);
        let mut foreign = manifest_of(&root, &entries, &[0, 1]);
        foreign.entries[1].entry = &others[0];
        assert!(refused(&foreign));
        assert!(refused(&manifest_of(&root, &entries, &[2, 1])));
        assert!(refused(&manifest_of(&root, &entries, &[1, 1])));
        let mut short = manifest_of(&root, &entries, &[0]);
        short.entries[0].proof.pop();
        assert!(refused(&short));
        // A root under four signatures.
        let weak = signed_root(&keys, &[0, 1, 2, 3], 200, keyset_hash, merkle_root);
        assert!(refused(&manifest_of(&weak, &entries, &[0])));
        // A descriptor that starts after the epoch of the root.
        let early = signed_root(&keys, &[0, 1, 2, 3, 4], 0, keyset_hash, merkle_root);
        let mut consensus = Consensus::new(keyset(), 0).unwrap();
        let manifest = manifest_of(&early, &entries, &[0]);
        assert!(RelaySet::accept(&mut consensus, &manifest, &blocs, 0).is_err());

        // Bytes that stop early, a version that is not known, a side that is
        // no side, and a count that the bytes cannot hold.
        let bytes = manifest_of(&root, &entries, &[0, 1]).encode().unwrap();
        assert!(RelayManifest::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut wrong = bytes.clone();
        wrong[0] = 0x02;
        assert!(RelayManifest::parse(&wrong).is_err());
        let mut wrong = bytes.clone();
        wrong[1 + 2 + root.len() + 2 + ENTRY_LEN + 1] = 0x02;
        assert!(RelayManifest::parse(&wrong).is_err());
        let mut wrong = bytes;
        wrong[1 + 2 + root.len()] = 0xFF;
        assert!(RelayManifest::parse(&wrong).is_err());
    }
}
