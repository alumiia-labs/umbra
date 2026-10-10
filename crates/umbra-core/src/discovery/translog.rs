//! The combined tree of Part 9 §9.5.1: the commitment of a leaf, the VRF
//! index of `(label, version)`, the binary ladder that shows the newest
//! version of a label, the lookup proof and its verification at a client,
//! the log operator that serves it, and the check of an auditor.
//!
//! The label of the VRF is the search key that the VOPRF of §9.4 gives.
//! The directory reads that key and never the handle of a query.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::{
    hmac::{digest::KeyInit, Hmac, Mac},
    labels,
    sha3::Sha3_256,
    vrf,
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    entry::DirectoryEntry,
    head::AcceptedHead,
    logtree::{epoch_leaf, verify_newest, LogFrontier, LogNodes},
    prefix::{PrefixProof, PrefixTree},
};
use crate::{directory::tree::Step, Error};

/// The version byte of a `LookupProof`.
pub const VERSION: u8 = 0x01;
/// The longest inclusion path of a log leaf: one step for each bit of
/// `tree_size`.
pub const LOG_PATH_MAX: usize = 64;
/// The most steps of a binary ladder over a 32-bit version.
pub const LADDER_MAX: usize = 65;
/// The longest entry that a leaf commits to.
pub const ENTRY_MAX: usize = 8_192;

/// `commitment = HMAC-SHA3-256(opening, "umbra/v1/log-commit" || entry)`.
/// The entry holds the handle string, thus the leaf commits to it
/// (`DIS-009`).
pub fn commitment(opening: &[u8; 32], entry: &[u8]) -> [u8; 32] {
    // A 32-byte key is inside the HMAC key bound, thus this cannot fail.
    let mut mac = Hmac::<Sha3_256>::new_from_slice(opening)
        .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()));
    mac.update(labels::LOG_COMMIT);
    mac.update(entry);
    mac.finalize().into_bytes().into()
}

/// The VRF input of one version of a label (`DIS-007`).
fn vrf_input(search_key: &[u8], version: u32) -> Vec<u8> {
    [search_key, &version.to_be_bytes()].concat()
}

fn index_of(output: &[u8; vrf::OUTPUT_LEN]) -> [u8; 32] {
    let mut index = [0u8; 32];
    index.copy_from_slice(output.get(..32).unwrap_or(&[0; 32]));
    index
}

/// The binary ladder for a label whose newest version is `newest`: the
/// versions to look up in order, and whether each one is present. The
/// versions `2^k - 1` run until the first absent one, and a binary search
/// then closes the range. A label with no version has one absent step.
pub fn ladder(newest: Option<u32>) -> Vec<(u32, bool)> {
    let is_present = |version: u64| newest.is_some_and(|n| version <= u64::from(n));
    let mut steps = Vec::new();
    let mut present_below: Option<u64> = None;
    let mut absent_at = u64::from(u32::MAX) + 1;
    for power in 0..=32u32 {
        let version = (1u64 << power) - 1;
        if version > u64::from(u32::MAX) {
            break;
        }
        steps.push((version, is_present(version)));
        if is_present(version) {
            present_below = Some(version);
        } else {
            absent_at = version;
            break;
        }
    }
    while let Some(low) = present_below {
        if absent_at - low <= 1 {
            break;
        }
        let middle = low + (absent_at - low) / 2;
        steps.push((middle, is_present(middle)));
        if is_present(middle) {
            present_below = Some(middle);
        } else {
            absent_at = middle;
        }
    }
    steps
        .into_iter()
        .filter_map(|(version, present)| u32::try_from(version).ok().map(|v| (v, present)))
        .collect()
}

/// One step of a ladder: the VRF proof of the version, and the prefix
/// proof at the index that the VRF gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderStep {
    /// The ECVRF proof over `search_key || version`.
    pub vrf_proof: [u8; vrf::PROOF_LEN],
    /// The inclusion or the absence at that index.
    pub prefix: PrefixProof,
}

/// The answer of the directory to one lookup (§9.4 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupProof {
    /// The `tree_size` of the head that the proof is under (`DIS-052`).
    pub tree_size: u64,
    /// The tree-wide nonce of the newest epoch.
    pub nonce: [u8; 32],
    /// The root of the prefix tree at the newest epoch.
    pub prefix_root: [u8; 32],
    /// The inclusion of the newest log leaf under the root of the head.
    pub log_path: Vec<Step>,
    /// The newest version of the label, or `None` for an absent label.
    pub newest: Option<u32>,
    /// The steps of `ladder(newest)`, in order.
    pub steps: Vec<LadderStep>,
    /// The opening and the entry of the newest version.
    pub opened: Option<([u8; 32], Vec<u8>)>,
}

impl LookupProof {
    /// Encodes the proof.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let steps_len: usize = self
            .steps
            .iter()
            .map(|step| vrf::PROOF_LEN + step.prefix.len())
            .sum();
        let opened_len = self
            .opened
            .as_ref()
            .map_or(0, |(_, entry)| 34 + entry.len());
        let len = 1 + 8 + 64 + 1 + self.log_path.len() * 33 + 5 + 1 + steps_len + opened_len;
        let mut out = alloc::vec![0u8; len];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.put(&self.tree_size.to_be_bytes())?;
        w.put(&self.nonce)?;
        w.put(&self.prefix_root)?;
        w.u8(u8::try_from(self.log_path.len()).map_err(|_| Error::Malformed)?)?;
        for step in &self.log_path {
            w.u8(u8::from(step.sibling_right))?;
            w.put(&step.sibling)?;
        }
        w.u8(u8::from(self.newest.is_some()))?;
        w.u32(self.newest.unwrap_or(0))?;
        w.u8(u8::try_from(self.steps.len()).map_err(|_| Error::Malformed)?)?;
        for step in &self.steps {
            w.put(&step.vrf_proof)?;
            step.prefix.write(&mut w)?;
        }
        if let Some((opening, entry)) = &self.opened {
            w.put(opening)?;
            w.u16(u16::try_from(entry.len()).map_err(|_| Error::Malformed)?)?;
            w.put(entry)?;
        }
        Ok(out)
    }

    /// Reads a proof.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let tree_size = u64::from_be_bytes(r.array()?);
        let nonce = r.array()?;
        let prefix_root = r.array()?;
        let path_len = usize::from(r.u8()?);
        if path_len > LOG_PATH_MAX {
            return Err(Error::Malformed);
        }
        let mut log_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let sibling_right = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Malformed),
            };
            log_path.push(Step {
                sibling: r.array()?,
                sibling_right,
            });
        }
        let found = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Malformed),
        };
        let version = r.u32()?;
        if !found && version != 0 {
            return Err(Error::Malformed);
        }
        let step_count = usize::from(r.u8()?);
        if step_count > LADDER_MAX {
            return Err(Error::Malformed);
        }
        let mut steps = Vec::with_capacity(step_count);
        for _ in 0..step_count {
            steps.push(LadderStep {
                vrf_proof: r.array()?,
                prefix: PrefixProof::read(&mut r)?,
            });
        }
        let opened = if found {
            let opening = r.array()?;
            let entry_len = usize::from(r.u16()?);
            if entry_len > ENTRY_MAX {
                return Err(Error::Malformed);
            }
            Some((opening, r.take(entry_len)?.to_vec()))
        } else {
            None
        };
        r.finish()?;
        Ok(LookupProof {
            tree_size,
            nonce,
            prefix_root,
            log_path,
            newest: found.then_some(version),
            steps,
            opened,
        })
    }

    /// Verifies the proof for `search_key` against a head that the client
    /// accepted (`DIS-053`), and returns the entry of the newest version,
    /// or `None` for a proven absence.
    ///
    /// The ladder shows that no version above `newest` exists, thus the
    /// directory cannot answer with an old key of the label.
    pub fn verify(
        &self,
        search_key: &[u8],
        vrf_key: &vrf::PublicKey,
        head: &AcceptedHead,
    ) -> Result<Option<&[u8]>, Error> {
        if self.tree_size != head.tree_size || self.tree_size == 0 {
            return Err(Error::Unverified);
        }
        let leaf = epoch_leaf(&self.nonce, &self.prefix_root);
        verify_newest(&leaf, &self.log_path, &head.root)?;

        let expected = ladder(self.newest);
        if expected.len() != self.steps.len() {
            return Err(Error::Unverified);
        }
        let mut newest_commitment = None;
        for ((version, present), step) in expected.into_iter().zip(&self.steps) {
            let output = vrf_key.verify(&vrf_input(search_key, version), &step.vrf_proof)?;
            let found = step
                .prefix
                .verify(&self.nonce, &index_of(&output), &self.prefix_root)?;
            if found.is_some() != present {
                return Err(Error::Unverified);
            }
            if Some(version) == self.newest {
                newest_commitment = found;
            }
        }
        match (&self.opened, newest_commitment) {
            (Some((opening, entry)), Some(held)) if commitment(opening, entry) == held => {
                Ok(Some(entry))
            }
            (None, None) if self.newest.is_none() => Ok(None),
            _ => Err(Error::Unverified),
        }
    }

    /// Verifies a handle lookup. The entry names the handle of the query,
    /// and its `version` is the version of the log (`DIS-009`).
    pub fn verify_handle(
        &self,
        canonical_handle: &[u8],
        search_key: &[u8],
        vrf_key: &vrf::PublicKey,
        head: &AcceptedHead,
    ) -> Result<Option<DirectoryEntry>, Error> {
        let Some(bytes) = self.verify(search_key, vrf_key, head)? else {
            return Ok(None);
        };
        let entry = DirectoryEntry::parse(bytes)?;
        if entry.handle != canonical_handle || Some(entry.version) != self.newest {
            return Err(Error::Unverified);
        }
        Ok(Some(entry))
    }
}

/// The proof of one version of a label under a head (§9.9.2): the VRF
/// proof of that version, the inclusion of its commitment in the prefix
/// tree, and its opening. A client reads each version between a held key
/// and a resolved one with it (`DIS-079`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionProof {
    /// The `tree_size` of the head that the proof is under.
    pub tree_size: u64,
    /// The tree-wide nonce of the newest epoch.
    pub nonce: [u8; 32],
    /// The root of the prefix tree at the newest epoch.
    pub prefix_root: [u8; 32],
    /// The inclusion of the newest log leaf under the root of the head.
    pub log_path: Vec<Step>,
    /// The version that the proof shows.
    pub version: u32,
    /// The VRF proof of the version and its inclusion.
    pub step: LadderStep,
    /// The opening of the commitment.
    pub opening: [u8; 32],
    /// The entry of the version.
    pub entry: Vec<u8>,
}

impl VersionProof {
    /// Encodes the proof.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let len = 1
            + 8
            + 64
            + 1
            + self.log_path.len() * 33
            + 4
            + vrf::PROOF_LEN
            + self.step.prefix.len()
            + 32
            + 2
            + self.entry.len();
        let mut out = alloc::vec![0u8; len];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.put(&self.tree_size.to_be_bytes())?;
        w.put(&self.nonce)?;
        w.put(&self.prefix_root)?;
        w.u8(u8::try_from(self.log_path.len()).map_err(|_| Error::Malformed)?)?;
        for step in &self.log_path {
            w.u8(u8::from(step.sibling_right))?;
            w.put(&step.sibling)?;
        }
        w.u32(self.version)?;
        w.put(&self.step.vrf_proof)?;
        self.step.prefix.write(&mut w)?;
        w.put(&self.opening)?;
        w.u16(u16::try_from(self.entry.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.entry)?;
        Ok(out)
    }

    /// Reads a proof.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let tree_size = u64::from_be_bytes(r.array()?);
        let nonce = r.array()?;
        let prefix_root = r.array()?;
        let path_len = usize::from(r.u8()?);
        if path_len > LOG_PATH_MAX {
            return Err(Error::Malformed);
        }
        let mut log_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let sibling_right = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Malformed),
            };
            log_path.push(Step {
                sibling: r.array()?,
                sibling_right,
            });
        }
        let version = r.u32()?;
        let step = LadderStep {
            vrf_proof: r.array()?,
            prefix: PrefixProof::read(&mut r)?,
        };
        let opening = r.array()?;
        let entry_len = usize::from(r.u16()?);
        if entry_len > ENTRY_MAX {
            return Err(Error::Malformed);
        }
        let entry = r.take(entry_len)?.to_vec();
        r.finish()?;
        Ok(VersionProof {
            tree_size,
            nonce,
            prefix_root,
            log_path,
            version,
            step,
            opening,
            entry,
        })
    }

    /// Verifies the proof of `version` for `search_key` against a head that
    /// the client accepted, and returns the entry of that version.
    pub fn verify(
        &self,
        search_key: &[u8],
        version: u32,
        vrf_key: &vrf::PublicKey,
        head: &AcceptedHead,
    ) -> Result<&[u8], Error> {
        if self.version != version || self.tree_size != head.tree_size || self.tree_size == 0 {
            return Err(Error::Unverified);
        }
        let leaf = epoch_leaf(&self.nonce, &self.prefix_root);
        verify_newest(&leaf, &self.log_path, &head.root)?;
        let output = vrf_key.verify(&vrf_input(search_key, version), &self.step.vrf_proof)?;
        let held = self
            .step
            .prefix
            .verify(&self.nonce, &index_of(&output), &self.prefix_root)?;
        if held != Some(commitment(&self.opening, &self.entry)) {
            return Err(Error::Unverified);
        }
        Ok(&self.entry)
    }
}

/// What one epoch added to the log, for the auditors (`DIS-049`,
/// `DIS-050`). An auditor sees blinded indexes and commitments, and no
/// label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochUpdate {
    /// The `tree_size` after the epoch.
    pub tree_size: u64,
    /// The fresh nonce of the epoch (`DIS-008`).
    pub nonce: [u8; 32],
    /// The new leaves of the prefix tree.
    pub added: Vec<([u8; 32], [u8; 32])>,
    /// The root of the log tree, which the head of the epoch carries.
    pub log_root: [u8; 32],
}

struct Stored {
    opening: [u8; 32],
    entry: Vec<u8>,
}

/// The log at its operator: the prefix tree, the versions of each label,
/// the entries, and the log tree.
pub struct LogOperator {
    vrf: vrf::SecretKey,
    tree: PrefixTree,
    newest: BTreeMap<Vec<u8>, u32>,
    stored: BTreeMap<(Vec<u8>, u32), Stored>,
    staged: BTreeMap<Vec<u8>, Stored>,
    epochs: Vec<([u8; 32], [u8; 32])>,
    /// The leaves of the log tree and the root of each full subtree, for
    /// the consistency proof of a `Head` request.
    log_nodes: LogNodes,
    log_frontier: LogFrontier,
    /// The inclusion proof of the newest log leaf, made one time at the
    /// close of its epoch. A lookup needs no admission, thus it must not
    /// cost a pass over each leaf of the log.
    newest_path: Vec<Step>,
    used_nonces: BTreeSet<[u8; 32]>,
}

impl LogOperator {
    /// An empty log under the VRF key of the directory.
    pub fn new(vrf: vrf::SecretKey) -> Self {
        LogOperator {
            vrf,
            tree: PrefixTree::default(),
            newest: BTreeMap::new(),
            stored: BTreeMap::new(),
            staged: BTreeMap::new(),
            epochs: Vec::new(),
            log_nodes: LogNodes::default(),
            log_frontier: LogFrontier::default(),
            newest_path: Vec::new(),
            used_nonces: BTreeSet::new(),
        }
    }

    /// The VRF public key, which a client build ships beside the key set.
    pub fn vrf_public(&self) -> &[u8; vrf::PUBLIC_KEY_LEN] {
        self.vrf.public()
    }

    /// The `tree_size` and the root of the log, for the next head.
    pub fn head(&self) -> Option<(u64, [u8; 32])> {
        Some((self.log_frontier.size(), self.log_frontier.root()?))
    }

    /// Whether a version of the label waits for the close of the open
    /// epoch.
    pub fn is_staged(&self, search_key: &[u8]) -> bool {
        self.staged.contains_key(search_key)
    }

    /// The version that [`LogOperator::stage`] gives the next entry of a
    /// label, or none when a version waits or the counter ends.
    pub fn next_version(&self, search_key: &[u8]) -> Option<u32> {
        if self.staged.contains_key(search_key) {
            return None;
        }
        match self.newest.get(search_key) {
            Some(held) => held.checked_add(1),
            None => Some(0),
        }
    }

    /// Stages the next version of a label for the open epoch, and returns
    /// its version. A label with a staged update is rejected (`DIS-010`).
    /// `opening` comes from the CSPRNG of the operator.
    pub fn stage(
        &mut self,
        search_key: &[u8],
        entry: Vec<u8>,
        opening: [u8; 32],
    ) -> Result<u32, Error> {
        if entry.len() > ENTRY_MAX || self.staged.contains_key(search_key) {
            return Err(Error::Stale);
        }
        let version = match self.newest.get(search_key) {
            Some(held) => held.checked_add(1).ok_or(Error::NoPath)?,
            None => 0,
        };
        self.staged
            .insert(search_key.to_vec(), Stored { opening, entry });
        Ok(version)
    }

    /// Closes the epoch under a fresh nonce: each staged version enters
    /// the prefix tree, and one leaf enters the log tree (`DIS-047`).
    pub fn close_epoch(&mut self, nonce: [u8; 32]) -> Result<EpochUpdate, Error> {
        if !self.used_nonces.insert(nonce) {
            return Err(Error::Stale);
        }
        let mut added = Vec::with_capacity(self.staged.len());
        for (search_key, stored) in core::mem::take(&mut self.staged) {
            let version = self
                .newest
                .get(&search_key)
                .map_or(0, |v| v.saturating_add(1));
            let output = self.vrf.hash(&vrf_input(&search_key, version))?;
            let index = index_of(&output);
            let leaf_commitment = commitment(&stored.opening, &stored.entry);
            self.tree.insert(index, leaf_commitment)?;
            added.push((index, leaf_commitment));
            self.newest.insert(search_key.clone(), version);
            self.stored.insert((search_key, version), stored);
        }
        let prefix_root = self.tree.seal(&nonce);
        self.epochs.push((nonce, prefix_root));
        let leaf_hash = epoch_leaf(&nonce, &prefix_root);
        self.log_nodes.push(leaf_hash);
        self.newest_path = self.log_frontier.push_proving(leaf_hash);
        let log_root = self.log_frontier.root().ok_or(Error::NoPath)?;
        Ok(EpochUpdate {
            tree_size: self.log_nodes.len() as u64,
            nonce,
            added,
            log_root,
        })
    }

    /// The proof for one lookup under the newest head.
    pub fn lookup(&self, search_key: &[u8]) -> Result<LookupProof, Error> {
        let (nonce, prefix_root) = *self.epochs.last().ok_or(Error::NoPath)?;
        let newest = self.newest.get(search_key).copied();
        let mut steps = Vec::new();
        for (version, _) in ladder(newest) {
            let input = vrf_input(search_key, version);
            let vrf_proof = self.vrf.prove(&input)?;
            let index = index_of(&vrf::proof_to_hash(&vrf_proof)?);
            steps.push(LadderStep {
                vrf_proof,
                prefix: self.tree.prove(&nonce, &index),
            });
        }
        let opened = newest
            .and_then(|version| self.stored.get(&(search_key.to_vec(), version)))
            .map(|stored| (stored.opening, stored.entry.clone()));
        Ok(LookupProof {
            tree_size: self.log_nodes.len() as u64,
            nonce,
            prefix_root,
            log_path: self.newest_path.clone(),
            newest,
            steps,
            opened,
        })
    }

    /// The proof of one version of a label under the newest head, or an
    /// error for a version that the log does not hold.
    pub fn version(&self, search_key: &[u8], version: u32) -> Result<VersionProof, Error> {
        let (nonce, prefix_root) = *self.epochs.last().ok_or(Error::NoPath)?;
        let stored = self
            .stored
            .get(&(search_key.to_vec(), version))
            .ok_or(Error::NoPath)?;
        let vrf_proof = self.vrf.prove(&vrf_input(search_key, version))?;
        let index = index_of(&vrf::proof_to_hash(&vrf_proof)?);
        Ok(VersionProof {
            tree_size: self.log_nodes.len() as u64,
            nonce,
            prefix_root,
            log_path: self.newest_path.clone(),
            version,
            step: LadderStep {
                vrf_proof,
                prefix: self.tree.prove(&nonce, &index),
            },
            opening: stored.opening,
            entry: stored.entry.clone(),
        })
    }

    /// The consistency proof from the log of `first` epochs to the newest
    /// log, for a client or an auditor that holds the older head.
    pub fn consistency(&self, first: u64) -> Option<Vec<[u8; 32]>> {
        self.log_nodes.consistency(usize::try_from(first).ok()?)
    }
}

/// The state of one auditor: the leaves of the prefix tree, and the full
/// subtrees of the log tree, that it verified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Auditor {
    tree: PrefixTree,
    log: LogFrontier,
    used_nonces: BTreeSet<[u8; 32]>,
}

impl Auditor {
    /// Verifies one epoch, and returns the log root that the auditor signs
    /// in the head of that epoch. The nonce is fresh (`DIS-008`), each new
    /// index is new, thus no leaf changed and no leaf left, and the log
    /// grew by one leaf over the log that the auditor holds (`DIS-049`). A
    /// failed check changes no state.
    pub fn audit(&mut self, update: &EpochUpdate) -> Result<[u8; 32], Error> {
        let expected_size = self.log.size().saturating_add(1);
        if update.tree_size != expected_size || self.used_nonces.contains(&update.nonce) {
            return Err(Error::Unverified);
        }
        let mut tree = self.tree.clone();
        for (index, leaf_commitment) in &update.added {
            tree.insert(*index, *leaf_commitment)
                .map_err(|_| Error::Unverified)?;
        }
        let mut log = self.log.clone();
        log.push(epoch_leaf(&update.nonce, &tree.root(&update.nonce)));
        if log.root() != Some(update.log_root) {
            return Err(Error::Unverified);
        }
        self.tree = tree;
        self.log = log;
        self.used_nonces.insert(update.nonce);
        Ok(update.log_root)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use umbra_crypto::secret::Secret;

    use super::*;
    use crate::discovery::logtree::verify_consistency;

    fn operator() -> LogOperator {
        LogOperator::new(vrf::SecretKey::from_seed(&Secret::new([3; 32])))
    }

    fn head_of(operator: &LogOperator) -> AcceptedHead {
        let (tree_size, root) = operator.head().unwrap();
        AcceptedHead {
            tree_size,
            root,
            timestamp: 0,
            accepted_at: 0,
        }
    }

    fn vrf_key(operator: &LogOperator) -> vrf::PublicKey {
        vrf::PublicKey::from_bytes(operator.vrf_public()).unwrap()
    }

    #[test]
    fn the_ladder_closes_on_the_newest_version() {
        assert_eq!(ladder(None), [(0, false)]);
        assert_eq!(ladder(Some(0)), [(0, true), (1, false)]);
        assert_eq!(
            ladder(Some(1)),
            [(0, true), (1, true), (3, false), (2, false)]
        );
        assert_eq!(
            ladder(Some(5)),
            [
                (0, true),
                (1, true),
                (3, true),
                (7, false),
                (5, true),
                (6, false)
            ]
        );
        for newest in [0u32, 1, 2, 6, 7, 8, 63, 1_000, u32::MAX - 1, u32::MAX] {
            let steps = ladder(Some(newest));
            assert!(steps.len() <= LADDER_MAX);
            assert!(steps.contains(&(newest, true)));
            if let Some(above) = newest.checked_add(1) {
                assert!(steps.contains(&(above, false)));
            }
            assert!(steps.iter().all(|(v, present)| (*v <= newest) == *present));
        }
    }

    #[test]
    fn a_lookup_gives_the_newest_version_and_proves_an_absence() {
        let mut log = operator();
        for n in 0..20u8 {
            log.stage(&[n; 64], alloc::vec![n; 40], [n; 32]).unwrap();
        }
        assert!(
            log.stage(&[1; 64], alloc::vec![9; 40], [9; 32]).is_err(),
            "one update in an epoch"
        );
        log.close_epoch([0xA0; 32]).unwrap();
        for round in 1..=3u8 {
            assert_eq!(
                log.stage(&[1; 64], alloc::vec![round; 44], [round; 32])
                    .unwrap(),
                u32::from(round)
            );
            log.close_epoch([0xA0 + round; 32]).unwrap();
        }
        assert!(
            log.close_epoch([0xA0; 32]).is_err(),
            "the nonce of an epoch is fresh"
        );

        let head = head_of(&log);
        let key = vrf_key(&log);
        let proof = LookupProof::parse(&log.lookup(&[1; 64]).unwrap().encode().unwrap()).unwrap();
        assert_eq!(proof.newest, Some(3));
        assert_eq!(
            proof.verify(&[1; 64], &key, &head).unwrap(),
            Some([3u8; 44].as_slice())
        );
        assert!(proof.verify(&[2; 64], &key, &head).is_err());

        let absent =
            LookupProof::parse(&log.lookup(&[0xEE; 64]).unwrap().encode().unwrap()).unwrap();
        assert_eq!(absent.verify(&[0xEE; 64], &key, &head).unwrap(), None);

        // A head of another epoch does not take the proof.
        let mut older = head;
        older.tree_size -= 1;
        assert!(proof.verify(&[1; 64], &key, &older).is_err());
    }

    #[test]
    fn a_version_proof_shows_one_version_and_no_other() {
        let mut log = operator();
        for round in 0..3u8 {
            log.stage(&[1; 64], alloc::vec![round; 30], [round; 32])
                .unwrap();
            log.stage(&[2; 64], alloc::vec![0x40 + round; 30], [round; 32])
                .unwrap();
            log.close_epoch([0xB0 + round; 32]).unwrap();
        }
        let head = head_of(&log);
        let key = vrf_key(&log);
        for version in 0..3u32 {
            let bytes = log.version(&[1; 64], version).unwrap().encode().unwrap();
            let proof = VersionProof::parse(&bytes).unwrap();
            assert_eq!(
                proof.verify(&[1; 64], version, &key, &head).unwrap(),
                [u8::try_from(version).unwrap(); 30].as_slice()
            );
            // The proof names its version and its label.
            assert!(proof.verify(&[1; 64], version + 1, &key, &head).is_err());
            assert!(proof.verify(&[2; 64], version, &key, &head).is_err());
        }
        assert!(log.version(&[1; 64], 3).is_err());

        // Another entry under the opening of this version fails.
        let mut forged = log.version(&[1; 64], 1).unwrap();
        forged.entry = alloc::vec![0x41; 30];
        assert!(forged.verify(&[1; 64], 1, &key, &head).is_err());
        // The proof of the version of another label fails at its index.
        let mut moved = log.version(&[2; 64], 1).unwrap();
        moved.opening = [1; 32];
        moved.entry = alloc::vec![1; 30];
        assert!(moved.verify(&[1; 64], 1, &key, &head).is_err());
        // A head of another epoch does not take the proof.
        let proof = log.version(&[1; 64], 0).unwrap();
        let mut older = head;
        older.tree_size -= 1;
        assert!(proof.verify(&[1; 64], 0, &key, &older).is_err());
    }

    #[test]
    fn the_directory_cannot_serve_an_old_version_or_another_entry() {
        let mut log = operator();
        log.stage(&[1; 64], b"version zero".to_vec(), [1; 32])
            .unwrap();
        log.close_epoch([0xA0; 32]).unwrap();
        let old = log.lookup(&[1; 64]).unwrap();
        log.stage(&[1; 64], b"version one".to_vec(), [2; 32])
            .unwrap();
        log.close_epoch([0xA1; 32]).unwrap();
        let head = head_of(&log);
        let key = vrf_key(&log);

        // The old proof names the old epoch.
        assert!(old.verify(&[1; 64], &key, &head).is_err());

        // A proof that claims version 0 under the new head has to show
        // version 1 absent, and the tree holds it.
        let current = log.lookup(&[1; 64]).unwrap();
        let mut rolled_back = current.clone();
        rolled_back.newest = Some(0);
        rolled_back.opened = old.opened.clone();
        assert!(rolled_back.verify(&[1; 64], &key, &head).is_err());

        let mut swapped = current.clone();
        swapped.opened = Some(([2; 32], b"version 1 forged".to_vec()));
        assert!(swapped.verify(&[1; 64], &key, &head).is_err());

        let mut hidden = current;
        hidden.newest = None;
        hidden.opened = None;
        hidden.steps.truncate(1);
        assert!(hidden.verify(&[1; 64], &key, &head).is_err());
    }

    #[test]
    fn an_auditor_follows_an_honest_log_and_stops_at_a_rewrite() {
        let mut log = operator();
        let mut auditor = Auditor::default();
        let mut heads = Vec::new();
        for epoch in 0..6u8 {
            log.stage(&[epoch; 64], alloc::vec![epoch; 30], [epoch; 32])
                .unwrap();
            let update = log.close_epoch([0xB0 + epoch; 32]).unwrap();
            assert_eq!(auditor.audit(&update).unwrap(), log.head().unwrap().1);
            heads.push(log.head().unwrap());
        }
        let (first_size, first_root) = heads[1];
        let (last_size, last_root) = heads[5];
        let proof = log.consistency(first_size).unwrap();
        verify_consistency(first_size, &first_root, last_size, &last_root, &proof).unwrap();

        log.stage(&[9; 64], alloc::vec![9; 30], [9; 32]).unwrap();
        let honest = log.close_epoch([0xC0; 32]).unwrap();
        let before = auditor.clone();

        let mut reused_nonce = honest.clone();
        reused_nonce.nonce = [0xB0; 32];
        assert!(auditor.audit(&reused_nonce).is_err());

        let mut changed_leaf = honest.clone();
        changed_leaf.added.push((honest.added[0].0, [0xEE; 32]));
        assert!(auditor.audit(&changed_leaf).is_err());

        let mut hidden_leaf = honest.clone();
        hidden_leaf.added.clear();
        assert!(auditor.audit(&hidden_leaf).is_err());
        assert_eq!(auditor, before, "a failed check changes no state");
        auditor.audit(&honest).unwrap();
    }
}
