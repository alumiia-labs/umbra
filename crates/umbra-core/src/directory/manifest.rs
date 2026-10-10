//! The relay manifest of Part 10 §10.5.5: a signed root, and relay entries
//! with their inclusion proofs. A bootstrap carrier of Part 3 §3.10 moves
//! it. Each entry is under the root, and a client computes the root again
//! over the entries that it took. Thus a carrier adds no relay, changes
//! none, and hides none of a manifest that passes for the whole set.
//!
//! The report queues and the removed links are outside the root. Each one
//! carries its own signatures, thus a carrier makes none. A carrier can
//! leave one out, and `RelaySet::accept` bounds what a repeat or an older
//! one does.

use alloc::vec::Vec;

use umbra_wire::codec::{Reader, Writer};

use super::{
    bloc::BlocList,
    descriptor::{roles, RelayEntry, ENTRY_LEN},
    path::Candidate,
    removal::{LinkRemoval, LINK_REMOVALS_MAX},
    report::{ReportQueue, REPORT_QUEUES_MAX, REPORT_QUEUE_LEN},
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
    /// The signed report queue of each authority that published one
    /// (`REL-167`). A manifest of an earlier build holds none.
    pub queues: Vec<&'a [u8]>,
    /// The signed removal of each removed link (`REL-183`).
    pub removals: Vec<&'a [u8]>,
}

impl<'a> RelayManifest<'a> {
    /// The encoded width.
    pub fn len(&self) -> usize {
        let entries: usize = self
            .entries
            .iter()
            .map(|entry| ENTRY_LEN + 1 + entry.proof.len() * STEP_LEN)
            .sum();
        let queues = if self.queues.is_empty() && self.removals.is_empty() {
            0
        } else {
            1 + self.queues.len() * REPORT_QUEUE_LEN
        };
        let removals = if self.removals.is_empty() {
            0
        } else {
            2 + self
                .removals
                .iter()
                .map(|removal| removal.len())
                .sum::<usize>()
        };
        1 + 2 + self.root.len() + 2 + entries + queues + removals
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
        // The count is absent with no queue and no removal, thus a manifest
        // with none keeps the bytes of an earlier build.
        if !self.queues.is_empty() || !self.removals.is_empty() {
            if self.queues.len() > REPORT_QUEUES_MAX {
                return Err(Error::Malformed);
            }
            w.u8(u8::try_from(self.queues.len()).map_err(|_| Error::Malformed)?)?;
            for queue in &self.queues {
                if queue.len() != REPORT_QUEUE_LEN {
                    return Err(Error::Malformed);
                }
                w.put(queue)?;
            }
        }
        if !self.removals.is_empty() {
            if self.removals.len() > LINK_REMOVALS_MAX {
                return Err(Error::Malformed);
            }
            w.u16(u16::try_from(self.removals.len()).map_err(|_| Error::Malformed)?)?;
            for removal in &self.removals {
                if LinkRemoval::len_of(removal)? != removal.len() {
                    return Err(Error::Malformed);
                }
                w.put(removal)?;
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
        let mut queues = Vec::new();
        if r.remaining() > 0 {
            let count = usize::from(r.u8()?);
            if count > REPORT_QUEUES_MAX {
                return Err(Error::Malformed);
            }
            for _ in 0..count {
                queues.push(r.take(REPORT_QUEUE_LEN)?);
            }
        }
        let mut removals = Vec::new();
        if r.remaining() > 0 {
            let count = usize::from(r.u16()?);
            // Each removal costs a client five to seven verifications, thus
            // a carrier must not add them without a bound.
            if count > LINK_REMOVALS_MAX {
                return Err(Error::Malformed);
            }
            let mut rest = r.rest();
            for _ in 0..count {
                let (removal, after) = rest
                    .split_at_checked(LinkRemoval::len_of(rest)?)
                    .ok_or(Error::Malformed)?;
                removals.push(removal);
                rest = after;
            }
            if !rest.is_empty() {
                return Err(Error::Malformed);
            }
        }
        r.finish()?;
        Ok(RelayManifest {
            root,
            entries,
            queues,
            removals,
        })
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
    /// The consensus digest of the root (`REL-160`).
    pub digest: [u8; 32],
    /// The relays, in ascending order of `relay_id`.
    pub relays: Vec<ListedRelay>,
    /// Whether the entries of the manifest are each leaf of the tree: the
    /// root over them is the signed root (`REL-147`). A part of the set
    /// passes each proof too. Thus a client that takes its relay set or its
    /// pins from a manifest tests this first.
    pub is_whole: bool,
    /// The report queues that verified under the key set, the newest one of
    /// each authority (`REL-168`).
    pub report_queues: Vec<ReportQueue>,
    /// The removed links that verified under the key set, each link one
    /// time (`REL-184`).
    pub removed_links: Vec<LinkRemoval>,
}

impl RelaySet {
    /// Accepts the root of a manifest under `consensus`, and then verifies
    /// each entry under that root. One entry that fails rejects the whole
    /// manifest, because a carrier that changed one byte gets no part of
    /// its choice through. A manifest that holds a part of the set passes
    /// with `is_whole` false, and the caller decides what a part may do.
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
        let (epoch, merkle_root, digest) = (root.epoch, root.root, root.digest());
        // The consensus takes the root after the last entry, because a
        // manifest with a bad entry must leave the consensus as it was.
        let mut relays: Vec<ListedRelay> = Vec::with_capacity(manifest.entries.len());
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(manifest.entries.len());
        let mut last_id: Option<[u8; 32]> = None;
        for proven in &manifest.entries {
            tree::verify(proven.entry, &proven.proof, &merkle_root)?;
            leaves.push(tree::leaf(proven.entry));
            let entry = RelayEntry::parse(proven.entry)?;
            let descriptor = &entry.descriptor;
            if last_id.is_some_and(|last| last >= descriptor.relay_id) {
                return Err(Error::Malformed);
            }
            last_id = Some(descriptor.relay_id);
            // REL-148: an entry that starts after the epoch of the root
            // goes, and the manifest stays.
            if descriptor.valid_after > epoch {
                continue;
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
        // The proofs say that each entry is a leaf. The root over the
        // entries in their order says that no leaf is absent. A leaf and a
        // node hash under two prefixes (`REL-053`), thus no other list of
        // leaves gives the signed root.
        let is_whole = tree::root(&leaves) == Some(merkle_root);
        // REL-168: a queue that fails goes, and the manifest stays. No root
        // covers a queue, thus a carrier can repeat one or show an older
        // one of the same authority. Each authority counts one time, with
        // the queue of its highest epoch.
        let mut report_queues: Vec<ReportQueue> = Vec::new();
        for bytes in &manifest.queues {
            let Ok(queue) = ReportQueue::verify(bytes, consensus.keyset(), epoch) else {
                continue;
            };
            let held = report_queues
                .iter_mut()
                .find(|held| held.authority_index == queue.authority_index);
            match held {
                Some(held) if held.epoch < queue.epoch => *held = queue,
                Some(_) => {}
                None => report_queues.push(queue),
            }
        }
        // REL-184: a removal that fails or ended goes, and the manifest
        // stays. A link that the list holds already costs no second
        // verification.
        let mut removed_links: Vec<LinkRemoval> = Vec::new();
        for bytes in &manifest.removals {
            let is_held = LinkRemoval::link_of(bytes).is_some_and(|(relay_a, relay_b)| {
                removed_links
                    .iter()
                    .any(|held| held.relay_a == relay_a && held.relay_b == relay_b)
            });
            if is_held {
                continue;
            }
            if let Ok(removal) = LinkRemoval::verify(bytes, consensus.keyset(), epoch) {
                removed_links.push(removal);
            }
        }
        consensus.commit(root, device_clock);
        Ok(RelaySet {
            epoch,
            root: merkle_root,
            digest,
            relays,
            is_whole,
            report_queues,
            removed_links,
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
        descriptor::tests::{entry_bytes, Rng},
        report::QUEUE_ADDRESS_LEN,
        root::{
            tests::{authorities, keyset_of, signed_root},
            DirectoryKeySet,
        },
    };
    use umbra_crypto::sign::SigningKey;

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
            queues: Vec::new(),
            removals: Vec::new(),
        }
    }

    #[test]
    fn a_manifest_carries_report_queues_after_its_entries() {
        let entries = [alloc::vec![3u8; ENTRY_LEN]];
        let root = [9u8; 40];
        let plain = manifest_of(&root, &entries, &[0]);
        let old = plain.encode().unwrap();
        // With no queue the bytes are those of an earlier build.
        assert_eq!(old.len(), 1 + 2 + 40 + 2 + ENTRY_LEN + 1);
        assert_eq!(RelayManifest::parse(&old).unwrap(), plain);
        let queue = alloc::vec![5u8; REPORT_QUEUE_LEN];
        let with = RelayManifest {
            queues: alloc::vec![queue.as_slice()],
            ..plain.clone()
        };
        let bytes = with.encode().unwrap();
        assert_eq!(bytes.len(), old.len() + 1 + REPORT_QUEUE_LEN);
        assert_eq!(RelayManifest::parse(&bytes).unwrap(), with);
        let torn = &bytes[..bytes.len() - 1];
        assert!(RelayManifest::parse(torn).is_err());
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
            // REL-147: a part of the set verifies, and `is_whole` shows
            // that it is a part.
            assert_eq!(set.is_whole, listed.len() == entries.len());
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
        // REL-148: a descriptor that starts after the epoch of the root is
        // no relay of the set, and the manifest stays whole with it.
        let early = signed_root(&keys, &[0, 1, 2, 3, 4], 0, keyset_hash, merkle_root);
        let mut consensus = Consensus::new(keyset(), 0).unwrap();
        let manifest = manifest_of(&early, &entries, &[0, 1, 2, 3, 4, 5]);
        let set = RelaySet::accept(&mut consensus, &manifest, &blocs, 0).unwrap();
        assert!(set.relays.is_empty() && set.is_whole);

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

    #[test]
    fn a_set_with_an_entry_left_out_is_not_whole() {
        let keys = authorities(40);
        let (pks, _) = keyset_of(&keys, 1);
        let keyset = || DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|key| &key[..]).collect(),
        };
        let entries = sorted_entries(&[1, 2, 3, 4, 5]);
        let leaves: Vec<[u8; 32]> = entries.iter().map(|entry| tree::leaf(entry)).collect();
        let merkle_root = tree::root(&leaves).unwrap();
        let root = signed_root(
            &keys,
            &[0, 1, 2, 3, 4],
            200,
            keyset().hash().unwrap(),
            merkle_root,
        );
        let blocs = BlocList::v1();
        let whole = |listed: &[usize]| {
            let manifest = manifest_of(&root, &entries, listed);
            let mut consensus = Consensus::new(keyset(), 100).unwrap();
            RelaySet::accept(&mut consensus, &manifest, &blocs, 200 * 3_600)
                .unwrap()
                .is_whole
        };
        assert!(whole(&[0, 1, 2, 3, 4]));
        // The first, the last, one of the middle, and the odd leaf alone.
        for part in [&[1usize, 2, 3, 4][..], &[0, 1, 2, 3], &[0, 1, 3, 4], &[4]] {
            assert!(!whole(part), "{part:?}");
        }
        assert!(!whole(&[]));
    }

    #[test]
    fn each_authority_counts_one_queue_and_each_link_one_removal() {
        let mut rng = Rng(11);
        let keys = authorities(40);
        let (pks, _) = keyset_of(&keys, 1);
        let keyset = || DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|key| &key[..]).collect(),
        };
        let entries = sorted_entries(&[1, 2, 3]);
        let leaves: Vec<[u8; 32]> = entries.iter().map(|entry| tree::leaf(entry)).collect();
        let root = signed_root(
            &keys,
            &[0, 1, 2, 3, 4],
            200,
            keyset().hash().unwrap(),
            tree::root(&leaves).unwrap(),
        );
        let mut queue = |index: u8, epoch: u64, mark: u8| {
            ReportQueue {
                authority_index: index,
                epoch,
                address: [mark; QUEUE_ADDRESS_LEN],
                report_pk: [mark; 32],
            }
            .sign(&keys[usize::from(index)], &mut rng)
            .unwrap()
        };
        // Authority 2 with three queues, the newest in the middle, and
        // authority 5 with one.
        let queues = [
            queue(2, 150, 1),
            queue(2, 190, 2),
            queue(2, 170, 3),
            queue(5, 100, 4),
        ];
        let five: Vec<(u8, &SigningKey)> = (0..5u8).map(|i| (i, &keys[usize::from(i)])).collect();
        let mut rng = Rng(12);
        let removals = [
            LinkRemoval::of(190, [1; 32], [2; 32])
                .sign(&five, &mut rng)
                .unwrap(),
            LinkRemoval::of(195, [2; 32], [1; 32])
                .sign(&five, &mut rng)
                .unwrap(),
            LinkRemoval::of(195, [2; 32], [3; 32])
                .sign(&five, &mut rng)
                .unwrap(),
        ];
        let manifest = RelayManifest {
            queues: queues.iter().map(Vec::as_slice).collect(),
            removals: removals.iter().map(Vec::as_slice).collect(),
            ..manifest_of(&root, &entries, &[0, 1, 2])
        };
        let mut consensus = Consensus::new(keyset(), 100).unwrap();
        let set =
            RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), 200 * 3_600).unwrap();
        let held: Vec<(u8, u64, u8)> = set
            .report_queues
            .iter()
            .map(|queue| (queue.authority_index, queue.epoch, queue.report_pk[0]))
            .collect();
        assert_eq!(held, [(2, 190, 2), (5, 100, 4)]);
        assert_eq!(
            set.removed_links,
            [
                LinkRemoval::of(190, [1; 32], [2; 32]),
                LinkRemoval::of(195, [2; 32], [3; 32])
            ]
        );

        // A count of removals above the bound does not parse, and it does
        // not encode.
        let many: Vec<&[u8]> = (0..=LINK_REMOVALS_MAX)
            .map(|_| removals[0].as_slice())
            .collect();
        let over = RelayManifest {
            removals: many,
            ..manifest_of(&root, &entries, &[0])
        };
        assert!(over.encode().is_err());
        let at_bound = RelayManifest {
            removals: over.removals[1..].to_vec(),
            ..over.clone()
        };
        let mut bytes = at_bound.encode().unwrap();
        assert!(RelayManifest::parse(&bytes).is_ok());
        let count_at = 1 + 2 + root.len() + 2 + ENTRY_LEN + 1 + entries_proof_len(&at_bound) + 1;
        let over_count = u16::try_from(LINK_REMOVALS_MAX + 1).unwrap().to_be_bytes();
        bytes[count_at..count_at + 2].copy_from_slice(&over_count);
        assert!(RelayManifest::parse(&bytes).is_err());
    }

    /// The width of the proof steps of the first entry of `manifest`.
    fn entries_proof_len(manifest: &RelayManifest<'_>) -> usize {
        manifest.entries[0].proof.len() * STEP_LEN
    }
}
