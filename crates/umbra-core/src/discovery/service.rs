//! The directory and the issuer of Part 9 §9.10 and Part 13 §13.9 as one
//! state machine: each request in, one response out, and an epoch of the
//! log at each `DIRECTORY_EPOCH`. It does no I/O. The server gives it the
//! bytes of each request, the time, and the random values, and it keeps the
//! events that [`Directory::take_events`] gives, in order, for a replay at
//! the next start.
//!
//! The two auditors of §9.5.2 run in this process in a test network alone:
//! a deployment runs each one at its own operator, with its own key.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::String,
    vec,
    vec::Vec,
};

use umbra_crypto::{
    hash::sha3_256,
    labels, pow,
    rand_core::{CryptoRng, TryCryptoRng},
    rsabssa::SecretKey2048,
    secret::Secret,
    sign::SigningKey,
    voprf::ServerKey,
    vrf,
};
use umbra_wire::{
    admission::{Admission, AdmissionKind},
    codec::Reader,
    directory::{self, put_var16, take_var16, Kind, Status, ISSUE_REQUEST_MAX},
};

use super::{
    challenge::{Issued, Purpose, ANSWER_LEN},
    entry::{AddressEntry, DirectoryEntry},
    handle::{Handle, BLOB_VERSION},
    head::{LogKeySet, SignedTreeHead, SignerSig},
    lifecycle::{Label, Needs},
    profile::PROFILE_BLOB_MAX,
    translog::{Auditor, LogOperator},
    HANDLE_LEASE, LEASE_MIN,
};
use crate::{
    abuse::{
        epoch_number,
        issuer::{issuer_label_input, IssuerKeyEntry},
        pow::PowSolution,
        spend::SpendSet,
        token::{
            FirstPartyIssuer, Token, TokenChallenge, FIRST_PARTY_LEN, TYPE_CROSS_RELAY,
            TYPE_FIRST_PARTY,
        },
        POW_EFFORT_MAX, POW_LOOKUP_FLOOR,
    },
    identity, Error,
};

/// `DIRECTORY_EPOCH` of Part 9 §9.11, in seconds.
pub const DIRECTORY_EPOCH: u64 = 600;
/// `CHALLENGE_TTL` of Part 9 §9.11, in seconds.
pub const CHALLENGE_TTL: u64 = 300;

/// The keys of a directory.
pub struct DirectoryKeys {
    /// The seed of the VOPRF key of the directory (§9.4).
    pub voprf_seed: Secret<32>,
    /// The seed of the ECVRF key of the log (§9.5.1).
    pub vrf_seed: Secret<32>,
    /// The seed of the issuer keys, one for each epoch (Part 13 §13.9). A
    /// deployment holds it apart from the other keys.
    pub issuer_seed: Secret<32>,
    /// The three signers of §9.5.2: the operator at index 0. Each key is
    /// large, thus they sit on the heap.
    pub signers: Vec<SigningKey>,
    /// The encoded `LogKeySet` of the three signers.
    pub keyset: Vec<u8>,
    /// The RSA key of the cross-relay tokens of each epoch (Part 13
    /// §13.3.1), or none for a directory that issues first-party tokens
    /// alone. The key generation lives outside this crate.
    pub cross_relay: Option<CrossRelayKeys>,
}

/// The source of the RSA key of the cross-relay tokens of one epoch.
pub type CrossRelayKeys = alloc::boxed::Box<dyn Fn(u32) -> Option<SecretKey2048> + Send>;

/// What the store keeps, in order, for a replay (the log itself and the
/// lease of each label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirEvent {
    /// A version staged for the next epoch.
    Staged {
        /// The search key of its label.
        search_key: Vec<u8>,
        /// The encoded entry.
        entry: Vec<u8>,
        /// The opening of its commitment.
        opening: [u8; 32],
    },
    /// An epoch closed at `at`, under `nonce`.
    Closed {
        /// The nonce of the epoch.
        nonce: [u8; 32],
        /// The time of the close, which the head carries.
        at: u64,
        /// The root of the prefix tree of the epoch, or none in a store of
        /// an earlier build. A replay takes it and hashes no tree for the
        /// epoch.
        root: Option<[u8; 32]>,
    },
    /// The state of one label after a change.
    Label {
        /// The search key.
        search_key: Vec<u8>,
        /// The stored form of [`LabelRecord`].
        state: Vec<u8>,
    },
    /// A token nonce of `epoch` spent. A restart holds it until the end of
    /// the next epoch, as the set does (`ABU-095`); the store drops it
    /// then, and it replays the rest in the order of their epochs.
    Spent {
        /// The epoch of the token.
        epoch: u32,
        /// Its nonce.
        nonce: [u8; 32],
    },
}

/// A label that a holder publishes: a handle or an address.
#[derive(Clone)]
struct LabelRecord {
    /// The label input of §9.10.
    input: Vec<u8>,
    /// The lease and the key.
    label: Label,
    /// The sealed profile blob of §9.3.1, which no log commits.
    blob: Option<Vec<u8>>,
}

impl LabelRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(self.input.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.input);
        out.extend_from_slice(&self.label.version.to_be_bytes());
        out.extend_from_slice(&self.label.hk_pub);
        out.extend_from_slice(&self.label.lease_until.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.label.tombstoned_at.unwrap_or(u64::MAX).to_be_bytes());
        out.extend_from_slice(&self.label.lease_epoch.to_be_bytes());
        out.extend_from_slice(&self.label.ends_at.unwrap_or(0).to_be_bytes());

        let blob = self.blob.as_deref().unwrap_or(&[]);
        out.extend_from_slice(&u16::try_from(blob.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(blob);
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let input = take_var16(&mut r)?.to_vec();
        let version = r.u32()?;
        let hk_pub: [u8; 1_216] = r.array()?;
        let lease_until = u64::from_be_bytes(r.array()?);
        let tombstoned_at = u64::from_be_bytes(r.array()?);
        let lease_epoch = u64::from_be_bytes(r.array()?);

        // A record of an earlier build ends here.
        let ends_at = if r.remaining() == 0 {
            0
        } else {
            u64::from_be_bytes(r.array()?)
        };
        let blob = if r.remaining() == 0 {
            Vec::new()
        } else {
            take_var16(&mut r)?.to_vec()
        };

        r.finish()?;
        Ok(LabelRecord {
            input,
            label: Label {
                version,
                hk_pub,
                lease_until: (tombstoned_at == u64::MAX).then_some(lease_until),
                tombstoned_at: (tombstoned_at != u64::MAX).then_some(tombstoned_at),
                lease_epoch,
                ends_at: (ends_at != 0).then_some(ends_at),
            },
            blob: (!blob.is_empty()).then_some(blob),
        })
    }

    /// The bytes that a challenge names: the canonical handle, or the 20
    /// bytes of an address (`DIS-108`).
    fn challenge_name(&self) -> &[u8] {
        self.input
            .strip_prefix(labels::ADDRESS_INDEX)
            .unwrap_or(&self.input)
    }
}

/// An issued challenge that waits for its answer.
struct Pending {
    issued: Issued,
    at: u64,
    /// The answer to the request, which a repeat gets again.
    out: Vec<u8>,
    /// The version of the label at the issue. A write moves the key, and a
    /// challenge sealed to the key before ends with it.
    version: u32,
    /// Whether a token paid for the registration challenge (`DIS-203`).
    paid: bool,
}

/// The purpose byte of a `Challenge` request, which keys its pending
/// challenge beside the search key.
const RENEW: u8 = 0x01;
const WRITE: u8 = 0x02;
const BLOB: u8 = 0x03;
/// A registration challenge, which proves the key of the new entry
/// (`DIS-197`). Its slot holds the hash of that key beside the search key,
/// thus two parties that register one label end no challenge of the other.
const REGISTER: u8 = super::dirclient::REGISTER_PURPOSE;

/// The registration challenges with no token that wait at once. A request
/// for one costs an encapsulation and no token, thus the count has a
/// bound. Only a client of an earlier build asks for one (`DIS-203`).
const REGISTER_PENDING_MAX: usize = 4_096;

/// The registration challenges that a token paid and that wait at once
/// (`DIS-203`). The bound holds the memory. At it the oldest paid
/// challenge goes, and no count refuses a paid challenge.
const REGISTER_PAID_MAX: usize = 16_384;

/// The seeds of the lookup proofs of work that the directory holds
/// (`DIS-200`). Each one cost a proof of work at `POW_LOOKUP_FLOOR`. At the
/// bound a random one goes (`DIS-202`).
const LOOKUP_SEEDS_MAX: usize = 1 << 18;

/// The seeds of the lookup proofs of work that the directory took
/// (`DIS-200`). A seed of an epoch before the one before the clock serves
/// no request, and it goes. At the bound a random seed goes, and no count
/// refuses a lookup (`DIS-202`).
struct LookupSeeds {
    held: BTreeSet<(u32, [u8; 32])>,
    /// The seeds of `held` in no order, thus a random one goes in one step.
    list: Vec<(u32, [u8; 32])>,
    /// The epoch of the clock at the last seed.
    epoch: u32,
    max: usize,
}

impl LookupSeeds {
    fn new(max: usize) -> Self {
        LookupSeeds {
            held: BTreeSet::new(),
            list: Vec::new(),
            epoch: 0,
            max,
        }
    }

    fn is_held(&self, epoch: u32, seed: &[u8; 32]) -> bool {
        self.held.contains(&(epoch, *seed))
    }

    /// Holds the seed of `epoch` at the epoch `now` of the clock.
    fn hold<R: CryptoRng + ?Sized>(&mut self, now: u32, epoch: u32, seed: [u8; 32], rng: &mut R) {
        if now != self.epoch {
            let oldest = now.saturating_sub(1);
            self.held.retain(|(epoch, _)| *epoch >= oldest);
            self.list.retain(|(epoch, _)| *epoch >= oldest);
            self.epoch = now;
        }

        if self.held.contains(&(epoch, seed)) {
            return;
        }

        // A drop in a fixed order lets a party with one solution more than
        // the bound send its solutions again in that order, and each one
        // passes. A random drop hides which of its seeds is free.
        while !self.list.is_empty() && self.list.len() >= self.max {
            let len = u64::try_from(self.list.len()).unwrap_or(u64::MAX);
            let index = usize::try_from(rng.next_u64() % len).unwrap_or(0);
            let dropped = self.list.swap_remove(index);
            self.held.remove(&dropped);
        }

        self.held.insert((epoch, seed));
        self.list.push((epoch, seed));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.list.len()
    }
}

/// The rotations of the log key set that one answer to a `KeySet` request
/// holds. Each one is near 16 KB, and the largest answer is 96 KiB.
const KEYSET_CHAIN_ANSWER: usize = 4;

/// The blind signatures of the cross-relay issuer that the directory holds
/// for a second request. Each one is 256 bytes, thus the set stays near
/// one mebibyte.
const SIGNED_HELD_MAX: usize = 4_096;

/// The directory and the issuer.
pub struct Directory {
    voprf: ServerKey,
    lookup_verifier: [u8; 32],
    operator: LogOperator,
    auditors: [Auditor; 2],
    signers: Vec<SigningKey>,
    keyset_hash: [u8; 32],
    head: Option<Vec<u8>>,
    last_close: Option<u64>,
    epoch_seconds: u64,
    labels: BTreeMap<Vec<u8>, LabelRecord>,
    challenges: BTreeMap<(Vec<u8>, u8), Pending>,
    /// The registration challenges that wait at once: with no token, and
    /// paid (`DIS-203`).
    register_max: (usize, usize),
    spent: SpendSet,
    /// The seed of each lookup proof of work that an evaluation took, for
    /// this epoch and the one before it (`DIS-200`).
    lookup_seeds: LookupSeeds,
    /// Each `SignedLogKeySet` from the first set after the genesis set to
    /// the set of the signers, in order (`DIS-198`).
    keyset_chain: Vec<Vec<u8>>,
    issuer_seed: Secret<32>,
    issuers: BTreeMap<u32, FirstPartyIssuer>,
    cross_relay: Option<CrossRelayKeys>,
    cross_relay_keys: BTreeMap<u32, SecretKey2048>,
    /// The blind signature of each blinded message that the cross-relay
    /// issuer signed. The key is the epoch and the hash of the message, and
    /// `signed_order` holds the order in which they came. A second request
    /// for a message takes its signature from here, in whatever batch it
    /// comes, and costs no signature more.
    signed: BTreeMap<(u32, [u8; 32]), Vec<u8>>,
    signed_order: VecDeque<(u32, [u8; 32])>,
    /// The epoch below which the directory holds no such signature.
    signed_from: u32,
    /// Each issuer key in the log: its token type and its epoch.
    published_issuers: BTreeSet<(u16, u32)>,
    profile: fn(&str) -> Option<String>,
    events: Vec<DirEvent>,
}

fn tag(status: Status, body: &[u8]) -> Vec<u8> {
    directory::encode_response(status, body)
        .or_else(|_| directory::encode_response(Status::Busy, &[]))
        .unwrap_or_default()
}

/// The seed of the proof of work of a lookup (`DIS-165`).
pub fn lookup_seed(epoch: u32, blinded: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::LOOKUP_POW, &epoch.to_be_bytes(), blinded])
}

/// The verifier of the proof of work of a lookup (`DIS-165`).
pub fn lookup_verifier(directory_pk: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::LOOKUP_POW_VERIFIER, directory_pk])
}

/// The seed of the proof of work of an issuance (`ABU-109`).
pub fn issue_seed(epoch: u32, blinded: &[u8]) -> [u8; 32] {
    sha3_256(&[labels::ISSUE_POW, &epoch.to_be_bytes(), blinded])
}

/// The verifier of the proof of work of an issuance (`ABU-109`).
pub fn issue_verifier(issuer_pk: &[u8]) -> [u8; 32] {
    sha3_256(&[labels::ISSUE_POW_VERIFIER, issuer_pk])
}

impl Directory {
    /// A directory with no epoch yet. `profile` is the PRECIS profile of
    /// `DIS-088`, which a registration of a handle runs (`DIS-091`).
    pub fn new(
        keys: DirectoryKeys,
        epoch_seconds: u64,
        profile: fn(&str) -> Option<String>,
    ) -> Result<Self, Error> {
        let voprf = ServerKey::derive(&keys.voprf_seed, &[]).map_err(|_| Error::Malformed)?;
        let (keyset, _) = LogKeySet::parse(&keys.keyset)?;
        if keys.signers.len() != keyset.keys.len() {
            return Err(Error::Malformed);
        }

        let keyset_hash = keyset.hash()?;
        Ok(Directory {
            lookup_verifier: lookup_verifier(voprf.public()),
            voprf,
            operator: LogOperator::new(vrf::SecretKey::from_seed(&keys.vrf_seed)),
            auditors: [Auditor::default(), Auditor::default()],
            signers: keys.signers,
            keyset_hash,
            head: None,
            last_close: None,
            epoch_seconds,
            labels: BTreeMap::new(),
            challenges: BTreeMap::new(),
            register_max: (REGISTER_PENDING_MAX, REGISTER_PAID_MAX),
            spent: SpendSet::default(),
            lookup_seeds: LookupSeeds::new(LOOKUP_SEEDS_MAX),
            keyset_chain: Vec::new(),
            issuer_seed: keys.issuer_seed,
            cross_relay: keys.cross_relay,
            cross_relay_keys: BTreeMap::new(),
            signed: BTreeMap::new(),
            signed_order: VecDeque::new(),
            signed_from: 0,
            issuers: BTreeMap::new(),
            published_issuers: BTreeSet::new(),
            profile,
            events: Vec::new(),
        })
    }

    /// The VOPRF key of the directory, which a client build ships.
    pub fn voprf_public(&self) -> &[u8; 32] {
        self.voprf.public()
    }

    /// The ECVRF key of the log, which a client build ships (`DIS-158`).
    pub fn vrf_public(&self) -> &[u8; 32] {
        self.operator.vrf_public()
    }

    /// Takes the signed rotations of the log key set, from the first set
    /// after the genesis set to the set of the signers, in order
    /// (`DIS-045`, `DIS-198`). Each set holds a higher epoch than the one
    /// before it, and the last one is the set that the heads name.
    pub fn set_keyset_chain(&mut self, chain: Vec<Vec<u8>>) -> Result<(), Error> {
        let mut epoch = 0u64;
        let mut last = None;

        for signed in &chain {
            let (set, _) = LogKeySet::parse(signed)?;
            if set.keyset_epoch <= epoch {
                return Err(Error::Malformed);
            }

            epoch = set.keyset_epoch;
            last = Some(set.hash()?);
        }

        if last.is_some_and(|hash| hash != self.keyset_hash) {
            return Err(Error::Malformed);
        }

        self.keyset_chain = chain;
        Ok(())
    }

    /// The events since the last call, which the store keeps in order.
    pub fn take_events(&mut self) -> Vec<DirEvent> {
        core::mem::take(&mut self.events)
    }

    /// Takes the stored events of an earlier run, in order.
    ///
    /// A closed epoch takes the root that its close kept, and the prefix
    /// tree seals one time, at the newest epoch. Thus a restart costs each
    /// version one time, and not each leaf at each epoch since the first
    /// one. The auditors checked each epoch at its close, and they take the
    /// log as it stands.
    pub fn replay<R: CryptoRng + ?Sized>(
        &mut self,
        events: &[DirEvent],
        rng: &mut R,
    ) -> Result<(), Error> {
        for event in events {
            match event {
                DirEvent::Staged {
                    search_key,
                    entry,
                    opening,
                } => {
                    self.operator.stage(search_key, entry.clone(), *opening)?;
                    if let Ok(issuer) = IssuerKeyEntry::parse(entry) {
                        self.published_issuers
                            .insert((issuer.token_type, issuer.epoch));
                    }
                }
                DirEvent::Closed { nonce, at, root } => {
                    match root {
                        Some(root) => self.operator.replay_epoch(*nonce, *root)?,
                        // An epoch of an earlier build seals as at its close.
                        None => {
                            self.operator.close_epoch(*nonce)?;
                        }
                    }
                    self.last_close = Some(*at);
                }
                DirEvent::Label { search_key, state } => {
                    self.labels
                        .insert(search_key.clone(), LabelRecord::parse(state)?);
                }
                // A repeat in the store spends nothing more.
                DirEvent::Spent { epoch, nonce } => self.spent.restore(*epoch, *nonce),
            }
        }

        // A root that the seal does not give again is a fault of the store.
        self.operator.seal_newest()?;
        self.auditors = [
            Auditor::following(&self.operator),
            Auditor::following(&self.operator),
        ];

        self.events.clear();

        // The newest head alone: a client asks for no older one.
        match self.last_close {
            Some(at) => self.sign_head(at, rng),
            None => Ok(()),
        }
    }

    fn issuer(&mut self, epoch: u32) -> Result<&FirstPartyIssuer, Error> {
        if !self.issuers.contains_key(&epoch) {
            let key = ServerKey::derive(&self.issuer_seed, &epoch.to_be_bytes())
                .map_err(|_| Error::Malformed)?;
            self.issuers.insert(epoch, FirstPartyIssuer::new(key));
        }
        self.issuers.get(&epoch).ok_or(Error::NoPath)
    }

    /// The RSA key of the cross-relay tokens of an epoch, when this
    /// directory issues them.
    fn cross_relay_key(&mut self, epoch: u32) -> Option<&SecretKey2048> {
        if !self.cross_relay_keys.contains_key(&epoch) {
            let key = (self.cross_relay.as_ref()?)(epoch)?;
            self.cross_relay_keys.insert(epoch, key);
        }
        self.cross_relay_keys.get(&epoch)
    }

    /// The modulus of the cross-relay key of an epoch, for a test.
    pub fn cross_relay_public(&mut self, epoch: u32) -> Option<Vec<u8>> {
        self.cross_relay_key(epoch)
            .map(|key| key.public().modulus().to_vec())
    }

    /// The issuer key of an epoch, for a test and for a build that pins it.
    pub fn issuer_public(&mut self, epoch: u32) -> Result<[u8; 32], Error> {
        Ok(*self.issuer(epoch)?.public())
    }

    fn stage(
        &mut self,
        search_key: &[u8],
        entry: Vec<u8>,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Result<u32, Error> {
        let mut opening = [0u8; 32];
        rng.fill_bytes(&mut opening);

        let version = self.operator.stage(search_key, entry.clone(), opening)?;
        self.events.push(DirEvent::Staged {
            search_key: search_key.to_vec(),
            entry,
            opening,
        });

        Ok(version)
    }

    fn keep_label(&mut self, search_key: &[u8], mut record: LabelRecord) {
        // DIS-178: a tombstone takes the blob with it.
        if record.label.is_tombstoned() {
            record.blob = None;
        }

        self.events.push(DirEvent::Label {
            search_key: search_key.to_vec(),
            state: record.encode(),
        });
        self.labels.insert(search_key.to_vec(), record);
    }

    /// Closes the epoch, and the two auditors check it. The log moves only
    /// when both auditors pass, and the two move with it. A failed check
    /// thus keeps each staged version for the next epoch.
    fn advance(&mut self, nonce: [u8; 32], at: u64) -> Result<(), Error> {
        let auditors = &self.auditors;
        let mut steps = Vec::with_capacity(auditors.len());

        self.operator.close_epoch_checked(nonce, |update| {
            // DIS-049, DIS-050: each auditor checks the epoch before it
            // signs.
            let mut root = None;
            for auditor in auditors {
                let (step, checked) = auditor.check(update)?;
                if root.is_some_and(|held| held != checked) {
                    return Err(Error::Unverified);
                }
                root = Some(checked);
                steps.push(step);
            }
            root.map(|_| ()).ok_or(Error::NoPath)
        })?;

        for (auditor, step) in self.auditors.iter_mut().zip(steps) {
            auditor.commit(step);
        }

        self.last_close = Some(at);
        Ok(())
    }

    /// Signs the head of the newest epoch, closed at `at`. The signatures
    /// of ML-DSA-65 are hedged, thus a replay signs again with fresh
    /// randomness, and the head verifies as before.
    fn sign_head<R: CryptoRng + ?Sized>(&mut self, at: u64, rng: &mut R) -> Result<(), Error> {
        let (tree_size, root) = self.operator.head().ok_or(Error::NoPath)?;
        let unsigned = SignedTreeHead {
            tree_size,
            timestamp: at,
            root,
            keyset_hash: self.keyset_hash,
            sigs: Vec::new(),
        };

        let preimage = unsigned.preimage();
        let mut sigs = Vec::new();
        for signer in &self.signers {
            sigs.push(
                signer
                    .sign(&preimage, rng)
                    .map_err(|_| Error::Unverified)?
                    .to_bytes(),
            );
        }

        let head = SignedTreeHead {
            sigs: sigs
                .iter()
                .enumerate()
                .map(|(index, sig)| SignerSig {
                    signer_index: u8::try_from(index).unwrap_or(0),
                    sig,
                })
                .collect(),
            ..unsigned
        };

        let mut out = vec![0u8; super::head::HEAD_FIXED + 3 * super::head::SIGNER_SIG_LEN];
        let used = head.encode(&mut out)?;
        out.truncate(used);

        self.head = Some(out);
        Ok(())
    }

    /// The work of the clock: each lease that lapsed takes its tombstone
    /// (`DIS-073`), each issuer key of this epoch and the next goes into
    /// the log (`ABU-098`), and an epoch closes at each `epoch_seconds`
    /// (`DIS-167`).
    pub fn tick<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self
            .last_close
            .is_some_and(|last| now < last.saturating_add(self.epoch_seconds))
        {
            return Ok(());
        }

        let lapsed: Vec<Vec<u8>> = self
            .labels
            .iter()
            // A label with a staged version takes its tombstone at the
            // next epoch (DIS-010).
            .filter(|(key, record)| {
                !self.operator.is_staged(key)
                    && !record.label.is_tombstoned()
                    && record.label.lease_until.is_some_and(|until| now >= until)
            })
            .map(|(key, _)| key.clone())
            .collect();

        for search_key in lapsed {
            let Some(mut record) = self.labels.get(&search_key).cloned() else {
                continue;
            };

            let Some(version) = record.label.tombstone_if_lapsed(now) else {
                continue;
            };

            // A label whose tombstone does not build or does not stage
            // keeps its state, and the next epoch tries it again. The
            // epoch closes without it: one label with a fault must not
            // hold each other label and each head of the log.
            let Ok(entry) = tombstone_entry(&record.input, version) else {
                continue;
            };

            if self.stage(&search_key, entry, rng).is_err() {
                continue;
            }

            self.keep_label(&search_key, record);
        }

        // ABU-098: each key of this epoch and of the next one goes into the
        // log before its epoch starts.
        let epoch = epoch_number(now);
        for epoch in [epoch, epoch.saturating_add(1)] {
            for token_type in [TYPE_FIRST_PARTY, TYPE_CROSS_RELAY] {
                if self.published_issuers.contains(&(token_type, epoch)) {
                    continue;
                }

                let public_key = if token_type == TYPE_FIRST_PARTY {
                    self.issuer_public(epoch)?.to_vec()
                } else {
                    let Some(modulus) = self.cross_relay_public(epoch) else {
                        continue;
                    };
                    modulus
                };

                let entry = IssuerKeyEntry {
                    token_type,
                    epoch,
                    public_key,
                }
                .encode()?;

                let search_key = self
                    .voprf
                    .evaluate_direct(&issuer_label_input(token_type, epoch));

                self.stage(&search_key, entry, rng)?;
                self.published_issuers.insert((token_type, epoch));
            }
        }

        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        self.advance(nonce, now)?;
        self.sign_head(now, rng)?;
        self.events.push(DirEvent::Closed {
            nonce,
            at: now,
            root: self.operator.newest_root(),
        });

        self.challenges
            .retain(|_, pending| now.saturating_sub(pending.at) < CHALLENGE_TTL);
        Ok(())
    }

    /// Answers one request.
    pub fn handle<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        request: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Vec<u8> {
        let Ok((kind, body)) = directory::parse_request(request) else {
            return tag(Status::Malformed, &[]);
        };

        let result = match kind {
            Kind::Evaluate => self.evaluate(body, now, rng),
            Kind::Lookup => self.lookup(body),
            Kind::Head => self.head_request(body),
            Kind::Register => self.register(body, now, rng),
            Kind::Challenge => self.challenge(body, now, rng),
            Kind::Write => self.write(body, now, rng),
            Kind::Renew => self.renew(body, now),
            Kind::Blob => self.put_blob(body, now),
            Kind::Version => self.version(body),
            Kind::KeySet => self.keysets(body),
            Kind::Issue => self.issue(body, now, rng),
        };

        match result {
            Ok(body) => tag(Status::Done, &body),
            Err(status) => tag(status, &[]),
        }
    }

    fn newest_head(&self) -> Result<&[u8], Status> {
        self.head.as_deref().ok_or(Status::NotFound)
    }

    fn evaluate<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let (admission, used) = Admission::parse(body).map_err(|_| Status::Malformed)?;
        let mut r = Reader::new(body.get(used..).ok_or(Status::Malformed)?);
        let blinded: [u8; 32] = r.array().map_err(|_| Status::Malformed)?;
        r.finish().map_err(|_| Status::Malformed)?;

        match admission.kind {
            // DIS-164: a first-party token or a proof of work.
            AdmissionKind::Token => self.spend_token(admission.body, now)?,
            AdmissionKind::Pow => {
                let solution = PowSolution::parse(admission.body).map_err(|_| Status::Malformed)?;
                let epoch = epoch_number(now);
                let seed_epoch = [epoch, epoch.saturating_sub(1)]
                    .into_iter()
                    .find(|e| lookup_seed(*e, &blinded) == solution.seed);
                let Some(seed_epoch) = seed_epoch else {
                    return Err(Status::Refused);
                };

                // DIS-200: a seed serves one evaluation, thus a request that
                // comes again costs no proof check and no evaluation.
                if solution.effort < POW_LOOKUP_FLOOR
                    || self.lookup_seeds.is_held(seed_epoch, &solution.seed)
                {
                    return Err(Status::Refused);
                }

                pow::verify(
                    &self.lookup_verifier,
                    &solution.seed,
                    &solution.nonce,
                    solution.effort,
                    &solution.solution,
                )
                .map_err(|_| Status::Refused)?;

                // DIS-202: a full set drops a random seed. A refusal here
                // would stop each lookup until the epoch ends (§9.4.1).
                self.lookup_seeds
                    .hold(epoch, seed_epoch, solution.seed, rng);
            }
            AdmissionKind::None => return Err(Status::Refused),
        }

        let evaluation = self
            .voprf
            .evaluate(&blinded, rng)
            .map_err(|_| Status::Malformed)?;
        Ok([&evaluation.element[..], &evaluation.proof].concat())
    }

    /// Verifies and spends one first-party token of this epoch or the one
    /// before it (`ABU-094`, `ABU-095`).
    fn spend_token(&mut self, bytes: &[u8], now: u64) -> Result<(), Status> {
        let (token_epoch, nonce) = self.check_token(bytes, now)?;
        self.commit_spend(token_epoch, nonce, now)
    }

    /// Spends the nonce of a token that [`Directory::check_token`] passed.
    fn commit_spend(&mut self, token_epoch: u32, nonce: [u8; 32], now: u64) -> Result<(), Status> {
        self.spent
            .spend(epoch_number(now), token_epoch, nonce)
            .map_err(|_| Status::Refused)?;

        // A restart takes the spent nonce again from the store.
        self.events.push(DirEvent::Spent {
            epoch: token_epoch,
            nonce,
        });
        Ok(())
    }

    /// Verifies one first-party token of this epoch or the one before it,
    /// and spends nothing: its epoch and its nonce.
    fn check_token(&mut self, bytes: &[u8], now: u64) -> Result<(u32, [u8; 32]), Status> {
        let token = Token::parse(bytes).map_err(|_| Status::Malformed)?;
        if token.token_type != TYPE_FIRST_PARTY {
            return Err(Status::Refused);
        }

        let epoch = epoch_number(now);
        for token_epoch in [epoch, epoch.saturating_sub(1)] {
            let digest = TokenChallenge {
                token_type: TYPE_FIRST_PARTY,
                epoch: token_epoch,
                redemption_context: [0; 32],
            }
            .digest();
            if digest != token.challenge_digest {
                continue;
            }

            if self.spent.is_spent(token_epoch, &token.nonce) {
                return Err(Status::Refused);
            }

            let issuer = self.issuer(token_epoch).map_err(|_| Status::Refused)?;
            issuer.verify(&token).map_err(|_| Status::Refused)?;
            return Ok((token_epoch, token.nonce));
        }
        Err(Status::Refused)
    }

    fn lookup(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        if body.len() != 64 {
            return Err(Status::Malformed);
        }

        let head = self.newest_head()?;
        let proof = self
            .operator
            .lookup(body)
            .and_then(|proof| proof.encode())
            .map_err(|_| Status::NotFound)?;

        // DIS-175: the sealed profile blob of a live label comes with it.
        let blob = self
            .labels
            .get(body)
            .filter(|record| !record.label.is_tombstoned())
            .and_then(|record| record.blob.as_deref())
            .unwrap_or(&[]);

        let mut out = Vec::new();
        put_var16(&mut out, head).map_err(|_| Status::Busy)?;
        put_var16(&mut out, blob).map_err(|_| Status::Busy)?;
        out.extend_from_slice(&proof);
        Ok(out)
    }

    /// The proof of one version of a label under the newest head
    /// (`DIS-079`). The request shows the search key, as a lookup does.
    fn version(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let search_key = r.take(64).map_err(|_| Status::Malformed)?;
        let version = r.u32().map_err(|_| Status::Malformed)?;
        r.finish().map_err(|_| Status::Malformed)?;

        let head = self.newest_head()?;
        let proof = self
            .operator
            .version(search_key, version)
            .and_then(|proof| proof.encode())
            .map_err(|_| Status::NotFound)?;

        let mut out = Vec::new();
        put_var16(&mut out, head).map_err(|_| Status::Busy)?;
        out.extend_from_slice(&proof);
        Ok(out)
    }

    /// The signed rotations of the log key set after the epoch that the
    /// reader holds, in order, up to `KEYSET_CHAIN_ANSWER` of them
    /// (`DIS-198`). A reader at the newest set gets none.
    fn keysets(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let held: [u8; 8] = body.try_into().map_err(|_| Status::Malformed)?;
        let held = u64::from_be_bytes(held);
        let after: Vec<&Vec<u8>> = self
            .keyset_chain
            .iter()
            .filter(|signed| LogKeySet::parse(signed).is_ok_and(|(set, _)| set.keyset_epoch > held))
            .take(KEYSET_CHAIN_ANSWER)
            .collect();

        let mut out = vec![u8::try_from(after.len()).map_err(|_| Status::Busy)?];
        for signed in after {
            put_var16(&mut out, signed).map_err(|_| Status::Busy)?;
        }
        Ok(out)
    }

    /// Keeps or drops the profile blob of a live label, under the answer
    /// of a blob challenge that binds the blob (`DIS-175`). An empty blob
    /// drops it. The log commits no blob, thus the write needs no epoch.
    fn put_blob(&mut self, body: &[u8], now: u64) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let input = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        let answer: [u8; ANSWER_LEN] = r.array().map_err(|_| Status::Malformed)?;
        let blob = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        r.finish().map_err(|_| Status::Malformed)?;

        if blob.len() > PROFILE_BLOB_MAX || blob.first().is_some_and(|v| *v != BLOB_VERSION) {
            return Err(Status::Malformed);
        }

        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let mut record = self
            .labels
            .get(&search_key)
            .cloned()
            .ok_or(Status::NotFound)?;

        if record.label.is_tombstoned() {
            return Err(Status::Stale);
        }

        let version = record.label.version;
        self.answer_pending(&search_key, BLOB, version, &answer, Some(&blob), now)?;

        record.blob = (!blob.is_empty()).then_some(blob);
        self.keep_label(&search_key, record);
        Ok(Vec::new())
    }

    fn head_request(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let from: [u8; 8] = body.try_into().map_err(|_| Status::Malformed)?;
        let from = u64::from_be_bytes(from);
        let head = self.newest_head()?;
        let mut out = Vec::new();
        put_var16(&mut out, head).map_err(|_| Status::Busy)?;

        let (size, _) = self.operator.head().ok_or(Status::NotFound)?;
        let proof = if from > 0 && from < size {
            self.operator.consistency(from).ok_or(Status::Stale)?
        } else {
            Vec::new()
        };

        out.push(u8::try_from(proof.len()).map_err(|_| Status::Busy)?);
        for hash in proof {
            out.extend_from_slice(&hash);
        }
        Ok(out)
    }

    /// The key of the entry that a label input names, after the entry
    /// checks against it (`DIS-169`, `DIS-170`). `is_held` says that the
    /// label holds a version already and its holder writes the next one, as
    /// `Handle::parse_held` reads it. A registration takes no such name.
    fn check_entry(
        &self,
        input: &[u8],
        entry: &[u8],
        version: u32,
        is_held: bool,
    ) -> Result<[u8; 1_216], Status> {
        if let Some(address) = input.strip_prefix(labels::ADDRESS_INDEX) {
            let parsed = AddressEntry::parse(entry).map_err(|_| Status::Malformed)?;
            if parsed.address.as_slice() != address || parsed.version != version {
                return Err(Status::Refused);
            }

            parsed.check().map_err(|_| Status::Refused)?;
            return Ok(parsed.address_pk);
        }

        let text = core::str::from_utf8(input).map_err(|_| Status::Malformed)?;
        // DIS-091: the name holds under the profile.
        let handle = if is_held {
            Handle::parse_held(text, &self.profile)
        } else {
            Handle::parse(text, &self.profile)
        }
        .map_err(|_| Status::Refused)?;
        if handle.label_input() != input {
            return Err(Status::Refused);
        }

        let parsed = DirectoryEntry::parse(entry).map_err(|_| Status::Malformed)?;
        if parsed.handle != input || parsed.version != version {
            return Err(Status::Refused);
        }
        Ok(parsed.hk_pub)
    }

    /// The version that a registration of a label gives, or why the label
    /// takes none: a label that no version holds registers at 0 (`DIS-101`),
    /// and one after its reservation as the next version (`DIS-077`).
    fn register_version(&self, search_key: &[u8], now: u64) -> Result<u32, Status> {
        match self.labels.get(search_key) {
            None => Ok(0),
            Some(record) if record.label.needs(now) == Needs::Token => {
                Ok(record.label.version.saturating_add(1))
            }
            Some(_) => Err(Status::Stale),
        }
    }

    /// The slot of the registration challenge of one key for a label.
    fn register_slot(search_key: &[u8], key: &[u8]) -> Vec<u8> {
        [search_key, &sha3_256(&[key])].concat()
    }

    fn register<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let token = body.get(..FIRST_PARTY_LEN).ok_or(Status::Malformed)?;
        let mut r = Reader::new(body.get(FIRST_PARTY_LEN..).ok_or(Status::Malformed)?);
        let input = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        let entry = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        let answer: [u8; ANSWER_LEN] = r.array().map_err(|_| Status::Malformed)?;

        // DIS-172: a registration can end before a full lease.
        let lease = if r.remaining() == 0 {
            None
        } else {
            let seconds = u64::from(r.u32().map_err(|_| Status::Malformed)?);
            if !(LEASE_MIN..=HANDLE_LEASE).contains(&seconds) {
                return Err(Status::Malformed);
            }
            Some(seconds)
        };
        r.finish().map_err(|_| Status::Malformed)?;

        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let version = self.register_version(&search_key, now)?;

        // DIS-010: one version of a label in each epoch.
        if self.operator.is_staged(&search_key) {
            return Err(Status::Busy);
        }

        let key = self.check_entry(&input, &entry, version, false)?;
        if key == [0; 1_216] {
            return Err(Status::Refused);
        }

        // DIS-076: the label takes the change before the log does, thus a
        // change that the label refuses stages no entry.
        let mut label = match self.labels.get(&search_key).cloned() {
            None => Label::register(key, now),
            Some(mut record) => {
                record
                    .label
                    .publish(version, key, now)
                    .map_err(|_| Status::Stale)?;
                record.label
            }
        };

        if let Some(seconds) = lease {
            label.end_at(now.saturating_add(seconds));
        }

        if self.operator.next_version(&search_key) != Some(version) {
            return Err(Status::Stale);
        }

        // DIS-203: a challenge that a token paid needs no second token. A
        // challenge that the bound dropped gets no token check.
        let slot = Self::register_slot(&search_key, &key);
        let is_paid = self
            .challenges
            .get(&(slot.clone(), REGISTER))
            .ok_or(Status::Stale)?
            .paid;
        let spend = if is_paid {
            None
        } else {
            Some(self.check_token(token, now)?)
        };

        // DIS-197: the registrant holds the private half of the key of the
        // entry, and the answer binds the entry.
        self.answer_pending(&slot, REGISTER, version, &answer, Some(&entry), now)?;

        // The token spends after each check that can refuse, thus a refused
        // registration keeps it.
        if let Some((token_epoch, nonce)) = spend {
            self.commit_spend(token_epoch, nonce, now)?;
        }

        if self
            .stage(&search_key, entry, rng)
            .map_err(|_| Status::Stale)?
            != version
        {
            return Err(Status::Stale);
        }

        self.keep_label(
            &search_key,
            LabelRecord {
                input,
                label,
                blob: None,
            },
        );
        Ok(Vec::new())
    }

    /// Issues the registration challenge of `DIS-197`: an encapsulation to
    /// the key of the entry that registers, as the write challenge of
    /// §9.9.3 for the version that the registration gives. The answer
    /// carries that version after the challenge. A request with a token
    /// pays for its challenge with that token (`DIS-203`).
    fn register_challenge<R: CryptoRng + ?Sized>(
        &mut self,
        r: &mut Reader<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let input = take_var16(r).map_err(|_| Status::Malformed)?.to_vec();
        let key: [u8; 1_216] = r.array().map_err(|_| Status::Malformed)?;

        // A client of an earlier build sends no token.
        let token = if r.remaining() == 0 {
            None
        } else {
            Some(r.take(FIRST_PARTY_LEN).map_err(|_| Status::Malformed)?)
        };
        r.finish().map_err(|_| Status::Malformed)?;

        if key == [0; 1_216] {
            return Err(Status::Refused);
        }

        let name = match input.strip_prefix(labels::ADDRESS_INDEX) {
            // DIS-169: an address names the hash of its key.
            Some(address) => {
                let address: [u8; 20] = address.try_into().map_err(|_| Status::Malformed)?;
                identity::address::check(&address, &key).map_err(|_| Status::Refused)?;
                address.to_vec()
            }
            // DIS-091: a name that no registration takes gets no challenge.
            None => {
                let text = core::str::from_utf8(&input).map_err(|_| Status::Malformed)?;
                let handle = Handle::parse(text, &self.profile).map_err(|_| Status::Refused)?;
                if handle.label_input() != input {
                    return Err(Status::Refused);
                }
                input.clone()
            }
        };

        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let version = self.register_version(&search_key, now)?;
        let slot = (Self::register_slot(&search_key, &key), REGISTER);

        // DIS-194: a live challenge goes again, and it spends no token.
        if let Some(pending) = self.challenges.get(&slot) {
            if pending.version == version && now.saturating_sub(pending.at) < CHALLENGE_TTL {
                return Ok(pending.out.clone());
            }
        }

        let paid = match token {
            Some(token) => Some(self.check_token(token, now)?),
            None => None,
        };

        // DIS-203: a challenge with no token takes no place of a paid one.
        let (unpaid_max, paid_max) = self.register_max;
        let bound = if paid.is_some() { paid_max } else { unpaid_max };
        let is_peer = |((_, purpose), pending): &(&(Vec<u8>, u8), &Pending)| {
            *purpose == REGISTER
                && pending.paid == paid.is_some()
                && now.saturating_sub(pending.at) < CHALLENGE_TTL
        };
        let is_full = self.challenges.iter().filter(is_peer).count() >= bound;
        if is_full && paid.is_none() {
            return Err(Status::Busy);
        }

        let issued = Issued::new(
            Purpose::Write {
                version_new: version,
            },
            &key,
            &name,
            rng,
        )
        .map_err(|_| Status::Busy)?;

        let mut out = issued.bytes().to_vec();
        out.extend_from_slice(&version.to_be_bytes());

        // The token spends after each check of the challenge that can
        // refuse, thus a refused challenge keeps it.
        if let Some((token_epoch, nonce)) = paid {
            self.commit_spend(token_epoch, nonce, now)?;
        }

        // DIS-203: a full bound of paid challenges drops the oldest one. A
        // refusal would stop each registration while a party pays the bound
        // in tokens in each `CHALLENGE_TTL`. A drop makes it pay the bound in
        // the seconds between a challenge and its registration.
        if is_full {
            let oldest = self
                .challenges
                .iter()
                .filter(is_peer)
                .min_by_key(|(_, pending)| pending.at)
                .map(|(slot, _)| slot.clone());
            if let Some(oldest) = oldest {
                self.challenges.remove(&oldest);
            }
        }

        self.challenges.insert(
            slot,
            Pending {
                issued,
                at: now,
                out: out.clone(),
                version,
                paid: paid.is_some(),
            },
        );
        Ok(out)
    }

    fn challenge<R: CryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let purpose = r.u8().map_err(|_| Status::Malformed)?;
        if purpose == REGISTER {
            return self.register_challenge(&mut r, now, rng);
        }

        let input = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        r.finish().map_err(|_| Status::Malformed)?;

        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let mut record = self
            .labels
            .get(&search_key)
            .cloned()
            .ok_or(Status::NotFound)?;

        let allowed = match purpose {
            RENEW | BLOB => !record.label.is_tombstoned(),
            // DIS-075: during the reservation the last key writes too.
            WRITE => record.label.needs(now) != Needs::Token,
            _ => false,
        };

        if !allowed {
            return Err(Status::Stale);
        }

        // DIS-194: a live challenge of this purpose goes again, thus a
        // party that asks for the label of another ends no challenge of it.
        let slot = (search_key.clone(), purpose);
        if let Some(pending) = self.challenges.get(&slot) {
            let current = pending.version == record.label.version
                && match pending.issued.purpose() {
                    Purpose::Renew { lease_epoch } => lease_epoch == record.label.lease_epoch,
                    Purpose::Write { .. } | Purpose::Blob => true,
                };
            if current && now.saturating_sub(pending.at) < CHALLENGE_TTL {
                return Ok(pending.out.clone());
            }
        }

        let (purpose, lease_epoch) = match purpose {
            RENEW => {
                let lease_epoch = record.label.issue_lease_epoch();
                (Purpose::Renew { lease_epoch }, Some(lease_epoch))
            }
            WRITE => (
                Purpose::Write {
                    version_new: record.label.version.saturating_add(1),
                },
                None,
            ),
            _ => (Purpose::Blob, None),
        };

        let issued = Issued::new(purpose, &record.label.hk_pub, record.challenge_name(), rng)
            .map_err(|_| Status::Busy)?;
        let mut out = issued.bytes().to_vec();
        if let Some(lease_epoch) = lease_epoch {
            out.extend_from_slice(&lease_epoch.to_be_bytes());
        }

        let version = record.label.version;
        if lease_epoch.is_some() {
            self.keep_label(&search_key, record);
        }

        self.challenges.insert(
            slot,
            Pending {
                issued,
                at: now,
                out: out.clone(),
                version,
                paid: false,
            },
        );
        Ok(out)
    }

    /// Verifies an answer to the live challenge of `purpose` for a label,
    /// and ends that challenge when the answer holds (`DIS-168`). A wrong
    /// answer ends nothing (`DIS-194`). `search_key` names the slot: the
    /// search key, or the slot of a registration challenge.
    #[allow(clippy::too_many_arguments)]
    fn answer_pending(
        &mut self,
        search_key: &[u8],
        purpose: u8,
        version: u32,
        answer: &[u8; 32],
        bound: Option<&[u8]>,
        now: u64,
    ) -> Result<Purpose, Status> {
        let slot = (search_key.to_vec(), purpose);
        let pending = self.challenges.get(&slot).ok_or(Status::Stale)?;

        // A challenge sealed to a key that a write replaced ends with it.
        if now.saturating_sub(pending.at) >= CHALLENGE_TTL || pending.version != version {
            self.challenges.remove(&slot);
            return Err(Status::Stale);
        }

        pending
            .issued
            .verify(answer, bound)
            .map_err(|_| Status::Refused)?;

        let purpose = pending.issued.purpose();
        self.challenges.remove(&slot);
        Ok(purpose)
    }

    fn write<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let input = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        let answer: [u8; 32] = r.array().map_err(|_| Status::Malformed)?;
        let entry = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        r.finish().map_err(|_| Status::Malformed)?;

        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let mut record = self
            .labels
            .get(&search_key)
            .cloned()
            .ok_or(Status::NotFound)?;

        if self.operator.is_staged(&search_key) {
            return Err(Status::Busy);
        }

        // DIS-097, DIS-098: the answer binds the entry.
        let version = record.label.version;
        let Purpose::Write { version_new } =
            self.answer_pending(&search_key, WRITE, version, &answer, Some(&entry), now)?
        else {
            return Err(Status::Stale);
        };

        let key = self.check_entry(&input, &entry, version_new, true)?;

        // DIS-076: the label takes the change before the log does, thus a
        // change that the label refuses stages no entry, and the label and
        // the log never part.
        if key == [0; 1_216] {
            // DIS-171: the holder retires the entry.
            record
                .label
                .retire(version_new, now)
                .map_err(|_| Status::Stale)?;
        } else {
            record
                .label
                .publish(version_new, key, now)
                .map_err(|_| Status::Stale)?;
        }

        if self.operator.next_version(&search_key) != Some(version_new) {
            return Err(Status::Stale);
        }

        if self
            .stage(&search_key, entry, rng)
            .map_err(|_| Status::Stale)?
            != version_new
        {
            return Err(Status::Stale);
        }

        self.keep_label(&search_key, record);
        Ok(Vec::new())
    }

    /// Signs a batch of blinded cross-relay tokens (Part 13 §13.3.1). Each
    /// item is a blinded message of the modulus width and one proof of work
    /// at `POW_EFFORT_MAX` (`ABU-076`, `ABU-109`). The answer is the count
    /// and the blind signatures. The signature of one message is one value,
    /// thus a second request for it gives the same token. The directory
    /// keeps that value for the life of its epoch. A request that comes
    /// again costs the proofs of work alone and no signature. This applies
    /// in the same batch, in another order, and to a part of the batch.
    fn issue_cross_relay(
        &mut self,
        r: &mut Reader<'_>,
        epoch: u32,
        current: u32,
        count: usize,
    ) -> Result<Vec<u8>, Status> {
        let modulus = self.cross_relay_public(epoch).ok_or(Status::NotFound)?;
        let verifier = issue_verifier(&modulus);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let message = r.take(modulus.len()).map_err(|_| Status::Malformed)?;
            let solution = PowSolution::parse(
                r.take(crate::abuse::pow::SOLUTION_LEN)
                    .map_err(|_| Status::Malformed)?,
            )
            .map_err(|_| Status::Malformed)?;

            if solution.seed != issue_seed(epoch, message) || solution.effort < POW_EFFORT_MAX {
                return Err(Status::Refused);
            }

            pow::verify(
                &verifier,
                &solution.seed,
                &solution.nonce,
                solution.effort,
                &solution.solution,
            )
            .map_err(|_| Status::Refused)?;

            blinded.push(message.to_vec());
        }
        r.finish().map_err(|_| Status::Malformed)?;

        // ABU-110: no request names an epoch before this one, thus the
        // signatures of an epoch that ended go.
        if self.signed_from < current {
            self.signed.retain(|(held, _), _| *held >= current);
            self.signed_order.retain(|(held, _)| *held >= current);
            self.signed_from = current;
        }

        let names: Vec<(u32, [u8; 32])> = blinded
            .iter()
            .map(|message| (epoch, sha3_256(&[message])))
            .collect();

        // Each message that no earlier request held, one time.
        let mut fresh: Vec<Vec<u8>> = Vec::new();
        let mut fresh_names = Vec::new();
        for (name, message) in names.iter().zip(&blinded) {
            if !self.signed.contains_key(name) && !fresh_names.contains(name) {
                fresh_names.push(*name);
                fresh.push(message.clone());
            }
        }

        if !fresh.is_empty() {
            let key = self.cross_relay_key(epoch).ok_or(Status::NotFound)?;
            let signatures = crate::abuse::token::issue_cross_relay(key, &fresh)
                .map_err(|_| Status::Malformed)?;
            for (name, signature) in fresh_names.into_iter().zip(signatures) {
                self.signed.insert(name, signature);
                self.signed_order.push_back(name);
            }
        }

        let mut out = vec![u8::try_from(count).map_err(|_| Status::Malformed)?];
        for name in &names {
            out.extend_from_slice(self.signed.get(name).ok_or(Status::Busy)?);
        }

        // The oldest signatures go at the bound, after this answer took
        // its own.
        while self.signed_order.len() > SIGNED_HELD_MAX {
            if let Some(oldest) = self.signed_order.pop_front() {
                self.signed.remove(&oldest);
            }
        }
        Ok(out)
    }

    fn renew(&mut self, body: &[u8], now: u64) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let input = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        let answer: [u8; 32] = r.array().map_err(|_| Status::Malformed)?;
        r.finish().map_err(|_| Status::Malformed)?;

        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let mut record = self
            .labels
            .get(&search_key)
            .cloned()
            .ok_or(Status::NotFound)?;

        let version = record.label.version;
        let Purpose::Renew { lease_epoch } =
            self.answer_pending(&search_key, RENEW, version, &answer, None, now)?
        else {
            return Err(Status::Stale);
        };

        record
            .label
            .renew(lease_epoch, now)
            .map_err(|_| Status::Stale)?;

        self.keep_label(&search_key, record);
        Ok(Vec::new())
    }

    fn issue<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let token_type = r.u16().map_err(|_| Status::Malformed)?;
        let epoch = r.u32().map_err(|_| Status::Malformed)?;
        let count = usize::from(r.u8().map_err(|_| Status::Malformed)?);
        if ![TYPE_FIRST_PARTY, TYPE_CROSS_RELAY].contains(&token_type)
            || count == 0
            || count > ISSUE_REQUEST_MAX
        {
            return Err(Status::Malformed);
        }

        // ABU-110: this epoch, and the next once its key is in the log.
        let current = epoch_number(now);
        let allowed = epoch == current
            || (epoch == current.saturating_add(1)
                && self.published_issuers.contains(&(token_type, epoch)));
        if !allowed {
            return Err(Status::Stale);
        }

        if token_type == TYPE_CROSS_RELAY {
            return self.issue_cross_relay(&mut r, epoch, current, count);
        }

        let issuer_pk = *self.issuer(epoch).map_err(|_| Status::Busy)?.public();
        let verifier = issue_verifier(&issuer_pk);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let element: [u8; 32] = r.array().map_err(|_| Status::Malformed)?;
            let solution = PowSolution::parse(
                r.take(crate::abuse::pow::SOLUTION_LEN)
                    .map_err(|_| Status::Malformed)?,
            )
            .map_err(|_| Status::Malformed)?;

            // ABU-076, ABU-077, ABU-109.
            if solution.seed != issue_seed(epoch, &element) || solution.effort < POW_EFFORT_MAX {
                return Err(Status::Refused);
            }

            pow::verify(
                &verifier,
                &solution.seed,
                &solution.nonce,
                solution.effort,
                &solution.solution,
            )
            .map_err(|_| Status::Refused)?;

            blinded.push(element);
        }
        r.finish().map_err(|_| Status::Malformed)?;

        let batch = self
            .issuer(epoch)
            .map_err(|_| Status::Busy)?
            .issue(&blinded, rng)
            .map_err(|_| Status::Malformed)?;

        let mut out = vec![u8::try_from(count).map_err(|_| Status::Malformed)?];
        for element in &batch.elements {
            out.extend_from_slice(element);
        }
        out.extend_from_slice(&batch.proof);
        Ok(out)
    }
}

/// The tombstone entry of a label at `version` (`DIS-073`).
fn tombstone_entry(input: &[u8], version: u32) -> Result<Vec<u8>, Error> {
    if let Some(address) = input.strip_prefix(labels::ADDRESS_INDEX) {
        let entry = AddressEntry {
            address: address.try_into().map_err(|_| Error::Malformed)?,
            address_pk: [0; 1_216],
            rendezvous: None,
            version,
        };

        let mut out = vec![0u8; super::entry::ADDRESS_ENTRY_LEN];
        let used = entry.encode(&mut out)?;
        out.truncate(used);
        return Ok(out);
    }

    let entry = DirectoryEntry::tombstone(input.to_vec(), version);
    let mut out = vec![0u8; entry.len()];
    let used = entry.encode(&mut out)?;
    out.truncate(used);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use umbra_crypto::{hierarchy::RootIdentity, kem::KeyPair};

    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        discovery::{
            challenge::answer,
            dirclient::{self, DirError},
            entry::{tests::queue, ADDRESS_ENTRY_LEN, DIRECTORY_ENTRY_MAX},
            handle::{address_label_input, ascii_profile},
            head::{AcceptedHead, HeadState, KEYSET_LEN},
            HANDLE_LEASE,
        },
        identity::address::address_of,
    };

    const T0: u64 = 1_800_000_000;

    fn keys() -> (DirectoryKeys, Vec<u8>) {
        let signers: Vec<_> = [0u8, 1, 2]
            .into_iter()
            .map(|i| SigningKey::from_seed(Secret::new([40 + i; 32])))
            .collect();
        let public: Vec<_> = signers
            .iter()
            .map(|s| s.verifying_key().to_bytes())
            .collect();
        let set = LogKeySet {
            keyset_epoch: 1,
            keys: public.iter().map(|k| &k[..]).collect(),
        };

        let mut keyset = vec![0u8; KEYSET_LEN];
        let used = set.encode(&mut keyset).unwrap();
        keyset.truncate(used);

        (
            DirectoryKeys {
                voprf_seed: Secret::new([1; 32]),
                vrf_seed: Secret::new([2; 32]),
                issuer_seed: Secret::new([3; 32]),
                signers,
                keyset: keyset.clone(),
                cross_relay: None,
            },
            keyset,
        )
    }

    fn directory() -> (Directory, Vec<u8>) {
        let (keys, keyset) = keys();
        (
            Directory::new(keys, DIRECTORY_EPOCH, ascii_profile).unwrap(),
            keyset,
        )
    }

    #[test]
    fn each_epoch_puts_its_cross_relay_key_into_the_log() {
        use crate::abuse::{
            issuer::{issuer_label_input, IssuerKeyEntry},
            token::{TYPE_CROSS_RELAY, TYPE_FIRST_PARTY},
        };
        use umbra_crypto::rsabssa::{SecretKey2048, MODULUS_LEN_2048};

        let mut rng = Rng(14);
        let (mut keys, keyset) = keys();
        let seed = Secret::new([0x4A; 32]);
        keys.cross_relay = Some(alloc::boxed::Box::new(move |epoch: u32| {
            SecretKey2048::from_seed(&seed, &epoch.to_be_bytes()).ok()
        }));
        let mut dir = Directory::new(keys, DIRECTORY_EPOCH, ascii_profile).unwrap();
        dir.tick(T0, &mut rng).unwrap();
        let now = T0 + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();

        // ABU-098: the key of this epoch and of the next one, beside the
        // first-party keys, each under its own label.
        let epoch = epoch_number(now);
        for epoch in [epoch, epoch + 1] {
            let input = issuer_label_input(TYPE_CROSS_RELAY, epoch);
            let entry =
                IssuerKeyEntry::parse(&read(&mut dir, &keyset, &input, now, &mut rng).unwrap())
                    .unwrap();
            assert_eq!((entry.token_type, entry.epoch), (TYPE_CROSS_RELAY, epoch));
            assert_eq!(entry.public_key.len(), MODULUS_LEN_2048);
            assert_eq!(Some(entry.public_key), dir.cross_relay_public(epoch));
            let input = issuer_label_input(TYPE_FIRST_PARTY, epoch);
            assert!(read(&mut dir, &keyset, &input, now, &mut rng).is_some());
        }

        // Two epochs take two keys.
        assert_ne!(
            dir.cross_relay_public(epoch),
            dir.cross_relay_public(epoch + 1)
        );
    }

    #[test]
    fn a_client_takes_cross_relay_tokens_under_the_key_of_the_log() {
        use crate::abuse::{
            issuer::{issuer_label_input, IssuerKeyEntry},
            token::{verify_cross_relay, TYPE_CROSS_RELAY},
        };
        use umbra_crypto::rsabssa::{PublicKey2048, SecretKey2048};

        let mut rng = Rng(15);
        let (mut keys, keyset) = keys();
        let seed = Secret::new([0x4B; 32]);
        keys.cross_relay = Some(alloc::boxed::Box::new(move |epoch: u32| {
            SecretKey2048::from_seed(&seed, &epoch.to_be_bytes()).ok()
        }));
        let mut dir = Directory::new(keys, DIRECTORY_EPOCH, ascii_profile).unwrap();
        dir.tick(T0, &mut rng).unwrap();
        let now = T0 + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        let epoch = epoch_number(now);

        // ABU-002: the key comes from the log.
        let input = issuer_label_input(TYPE_CROSS_RELAY, epoch);
        let entry = IssuerKeyEntry::parse(&read(&mut dir, &keyset, &input, now, &mut rng).unwrap())
            .unwrap();
        let issuer_pk = PublicKey2048::from_modulus(&entry.public_key).unwrap();

        let (state, body) =
            dirclient::cross_relay_issue_request(epoch, &issuer_pk, 2, &mut rng).unwrap();
        let answer = call(&mut dir, Kind::Issue, &body, now, &mut rng).unwrap();
        let tokens = dirclient::cross_relay_issue_finish(&state, &answer, &issuer_pk).unwrap();
        assert_eq!(tokens.len(), 2);
        for token in &tokens {
            // ABU-078: a third party verifies with the public key alone.
            verify_cross_relay(&issuer_pk, token).unwrap();
        }

        // The signature of one blinded message is one value.
        let again = call(&mut dir, Kind::Issue, &body, now, &mut rng).unwrap();
        assert_eq!(again, answer);

        // The directory holds each signature. Thus the same messages in
        // another order, and one of them alone, take what it holds. It
        // signs nothing more.
        assert_eq!(dir.signed.len(), 2);
        let (head, items) = body.split_at(7);
        let (first, second) = items.split_at(items.len() / 2);
        let (first_sig, second_sig) = answer[1..].split_at(256);
        let turned = [head, second, first].concat();
        assert_eq!(
            call(&mut dir, Kind::Issue, &turned, now, &mut rng).unwrap(),
            [&[2u8][..], second_sig, first_sig].concat()
        );
        let mut one = [head, second].concat();
        one[6] = 1;
        assert_eq!(
            call(&mut dir, Kind::Issue, &one, now, &mut rng).unwrap(),
            [&[1u8][..], second_sig].concat()
        );

        // One message two times in one batch is one signature.
        let twice = [head, first, first].concat();
        assert_eq!(
            call(&mut dir, Kind::Issue, &twice, now, &mut rng).unwrap(),
            [&[2u8][..], first_sig, first_sig].concat()
        );
        assert_eq!(dir.signed.len(), 2);
        assert_eq!(dir.signed_order.len(), 2);

        // A message whose proof of work does not verify takes no signature
        // that the directory holds.
        let mut bare = one.clone();
        let last = bare.len() - 1;
        bare[last] ^= 1;
        assert!(call(&mut dir, Kind::Issue, &bare, now, &mut rng).is_err());

        // The signatures of an epoch go when it ends.
        let next = now + crate::abuse::EPOCH_SECONDS;
        assert_eq!(epoch_number(next), epoch + 1);
        let next_pk =
            PublicKey2048::from_modulus(&dir.cross_relay_public(epoch + 1).unwrap()).unwrap();
        let (_, next_body) =
            dirclient::cross_relay_issue_request(epoch + 1, &next_pk, 1, &mut rng).unwrap();
        call(&mut dir, Kind::Issue, &next_body, next, &mut rng).unwrap();
        assert_eq!(dir.signed.len(), 1);
        assert!(dir.signed.keys().all(|(held, _)| *held == epoch + 1));

        // ABU-110: an epoch two ahead holds no key yet.
        let far = epoch + 2;
        let (_, far_body) =
            dirclient::cross_relay_issue_request(far, &issuer_pk, 1, &mut rng).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Issue, &far_body, now, &mut rng),
            Err(DirError::Status(Status::Stale))
        );
    }

    fn call(
        dir: &mut Directory,
        kind: Kind,
        body: &[u8],
        now: u64,
        rng: &mut Rng,
    ) -> Result<Vec<u8>, DirError> {
        let response = dir.handle(&dirclient::request(kind, body).unwrap(), now, rng);
        dirclient::done(&response)
    }

    fn challenge(
        dir: &mut Directory,
        renew: bool,
        input: &[u8],
        now: u64,
        rng: &mut Rng,
    ) -> Result<(Vec<u8>, Purpose), DirError> {
        let body = dirclient::challenge_body(renew, input).unwrap();
        let answer = call(dir, Kind::Challenge, &body, now, rng)?;
        let version = dir
            .labels
            .get(dir.voprf.evaluate_direct(input).as_slice())
            .unwrap()
            .label
            .version;
        Ok(dirclient::parse_challenge(&answer, version).unwrap())
    }

    /// A registration under the challenge of `DIS-197`: the challenge to the
    /// key of the entry, the answer of `key` over the entry, and the token.
    #[allow(clippy::too_many_arguments)]
    fn register(
        dir: &mut Directory,
        token: &[u8],
        input: &[u8],
        entry: &[u8],
        key: &KeyPair,
        lease: Option<u32>,
        now: u64,
        rng: &mut Rng,
    ) -> Result<Vec<u8>, DirError> {
        register_as(dir, token, input, entry, key, key, lease, now, rng)
    }

    /// A registration whose challenge goes to `claimed`, answered by
    /// `holder`. The challenge carries no token, as the request of an
    /// earlier build.
    #[allow(clippy::too_many_arguments)]
    fn register_as(
        dir: &mut Directory,
        token: &[u8],
        input: &[u8],
        entry: &[u8],
        claimed: &KeyPair,
        holder: &KeyPair,
        lease: Option<u32>,
        now: u64,
        rng: &mut Rng,
    ) -> Result<Vec<u8>, DirError> {
        let body =
            dirclient::register_challenge_body(input, &claimed.public().to_bytes(), None).unwrap();
        let bytes = call(dir, Kind::Challenge, &body, now, rng)?;
        let (challenge, purpose) = dirclient::parse_register_challenge(&bytes).unwrap();
        let name = input.strip_prefix(labels::ADDRESS_INDEX).unwrap_or(input);
        let ans = answer(purpose, holder, name, &challenge, Some(entry)).unwrap();
        let body = dirclient::register_body(token, input, entry, &ans, lease).unwrap();
        call(dir, Kind::Register, &body, now, rng)
    }

    fn tokens(
        dir: &mut Directory,
        epoch: u32,
        count: usize,
        now: u64,
        rng: &mut Rng,
    ) -> Vec<Vec<u8>> {
        let pk = dir.issuer_public(epoch).unwrap();
        let (state, body) = dirclient::issue_request(epoch, &pk, count, rng).unwrap();
        let answer = call(dir, Kind::Issue, &body, now, rng).unwrap();
        dirclient::issue_finish(&state, &answer, &pk)
            .unwrap()
            .iter()
            .map(|t| dirclient::token_bytes(t).unwrap())
            .collect()
    }

    fn handle_entry(handle: &[u8], hk: &KeyPair, version: u32) -> Vec<u8> {
        let entry = DirectoryEntry {
            handle: handle.to_vec(),
            hk_pub: hk.public().to_bytes(),
            rendezvous: Some(queue(1)),
            version,
        };
        let mut out = vec![0u8; DIRECTORY_ENTRY_MAX];
        let used = entry.encode(&mut out).unwrap();
        out.truncate(used);
        out
    }

    /// The entry of `input` as a client reads it: the search key under a
    /// proof of work, the lookup, the head, and the proof.
    fn read(
        dir: &mut Directory,
        keyset: &[u8],
        input: &[u8],
        now: u64,
        rng: &mut Rng,
    ) -> Option<Vec<u8>> {
        let pk = *dir.voprf_public();
        let (state, body) =
            dirclient::evaluate_request(input, &pk, epoch_number(now), None, rng).unwrap();
        let evaluated = call(dir, Kind::Evaluate, &body, now, rng).unwrap();
        let search_key = dirclient::evaluate_finish(&state, &evaluated, &pk).unwrap();
        let looked = call(dir, Kind::Lookup, &search_key, now, rng).unwrap();
        let (head, _, proof) = dirclient::parse_lookup(&looked).unwrap();
        let head = SignedTreeHead::parse(&head).unwrap();
        let (set, _) = LogKeySet::parse(keyset).unwrap();
        let mut heads = HeadState::new(set).unwrap();
        heads.accept(&head, now).unwrap();
        let accepted = AcceptedHead {
            tree_size: head.tree_size,
            root: head.root,
            timestamp: head.timestamp,
            accepted_at: now,
        };
        let vrf_key = vrf::PublicKey::from_bytes(dir.vrf_public()).unwrap();
        proof
            .verify(&search_key, &vrf_key, &accepted)
            .unwrap()
            .map(<[u8]>::to_vec)
    }

    #[test]
    fn a_handle_registers_under_a_token_and_renews_and_writes_under_its_key() {
        let mut rng = Rng(5);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([9; 32]));
        let hk = root.handle_key(0, 0);
        let input = b"@alice#1234";

        let spent = tokens(&mut dir, epoch_number(T0), 2, T0, &mut rng);
        let entry0 = handle_entry(input, &hk, 0);

        // DIS-197: a party that holds no private half of the key of the
        // entry does not register it, and its token stays unspent.
        let thief = root.handle_key(5, 0);
        assert_eq!(
            register_as(
                &mut dir,
                &spent[0],
                input,
                &entry0,
                &hk,
                &thief,
                None,
                T0 + 1,
                &mut rng
            ),
            Err(DirError::Status(Status::Refused))
        );
        register(
            &mut dir,
            &spent[0],
            input,
            &entry0,
            &hk,
            None,
            T0 + 1,
            &mut rng,
        )
        .unwrap();

        // DIS-170: a held label does not register again, and a token
        // spends once.
        assert_eq!(
            register(
                &mut dir,
                &spent[0],
                input,
                &entry0,
                &hk,
                None,
                T0 + 2,
                &mut rng
            ),
            Err(DirError::Status(Status::Stale))
        );
        let other = b"@bob#99";
        let other_entry = handle_entry(other, &hk, 0);
        assert_eq!(
            register(
                &mut dir,
                &spent[0],
                other,
                &other_entry,
                &hk,
                None,
                T0 + 2,
                &mut rng
            ),
            Err(DirError::Status(Status::Refused))
        );

        // DIS-169: the entry names its label.
        assert_eq!(
            register(
                &mut dir,
                &spent[1],
                other,
                &entry0,
                &hk,
                None,
                T0 + 2,
                &mut rng
            ),
            Err(DirError::Status(Status::Refused))
        );

        // DIS-166: the version shows at the next head.
        assert!(read(&mut dir, &keyset, input, T0 + 3, &mut rng).is_none());
        dir.tick(T0 + DIRECTORY_EPOCH, &mut rng).unwrap();
        let now = T0 + DIRECTORY_EPOCH + 1;
        let held = read(&mut dir, &keyset, input, now, &mut rng).unwrap();
        assert_eq!(held, handle_entry(input, &hk, 0));

        // A renewal, which a replay of its answer does not repeat.
        let (bytes, purpose) = challenge(&mut dir, true, input, now, &mut rng).unwrap();
        let ans = answer(purpose, &hk, input, &bytes, None).unwrap();
        let renew = dirclient::renew_body(input, &ans).unwrap();
        call(&mut dir, Kind::Renew, &renew, now + 1, &mut rng).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Renew, &renew, now + 2, &mut rng),
            Err(DirError::Status(Status::Stale))
        );

        // A write to a new key under the old one; a wrong answer fails.
        let next = root.handle_key(0, 1);
        let entry = handle_entry(input, &next, 1);
        challenge(&mut dir, false, input, now, &mut rng).unwrap();
        let bad = dirclient::write_body(input, &[0; 32], &entry).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Write, &bad, now + 1, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
        let (bytes, purpose) = challenge(&mut dir, false, input, now, &mut rng).unwrap();
        let ans = answer(purpose, &hk, input, &bytes, Some(&entry)).unwrap();
        let write = dirclient::write_body(input, &ans, &entry).unwrap();
        call(&mut dir, Kind::Write, &write, now + 1, &mut rng).unwrap();

        // DIS-168: a challenge lapses.
        let (bytes, purpose) = challenge(&mut dir, true, input, now, &mut rng).unwrap();
        let ans = answer(purpose, &next, input, &bytes, None).unwrap();
        let renew = dirclient::renew_body(input, &ans).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Renew, &renew, now + CHALLENGE_TTL, &mut rng),
            Err(DirError::Status(Status::Stale))
        );

        let now = T0 + 2 * DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert_eq!(
            read(&mut dir, &keyset, input, now, &mut rng).unwrap(),
            entry
        );

        // A replay of the events gives the same log and the same labels.
        let events = dir.take_events();
        let (keys, _) = keys();
        let mut again = Directory::new(keys, DIRECTORY_EPOCH, ascii_profile).unwrap();
        again.replay(&events, &mut rng).unwrap();
        assert_eq!(
            read(&mut again, &keyset, input, now, &mut rng).unwrap(),
            entry
        );
        let search_key = again.voprf.evaluate_direct(input).to_vec();
        assert_eq!(again.labels.get(&search_key).unwrap().label.version, 1);
        assert!(again.take_events().is_empty());

        // ABU-114: a restart keeps each spent nonce.
        assert!(!dir.spent.is_empty());
        assert_eq!(again.spent.len(), dir.spent.len());

        // DIS-079: each version stays readable, the first one too.
        let key: [u8; 64] = search_key.as_slice().try_into().unwrap();
        let answer = call(
            &mut again,
            Kind::Version,
            &dirclient::version_body(&key, 0),
            now,
            &mut rng,
        )
        .unwrap();
        let (head, proof) = dirclient::parse_version(&answer).unwrap();
        let head = SignedTreeHead::parse(&head).unwrap();
        let accepted = AcceptedHead {
            tree_size: head.tree_size,
            root: head.root,
            timestamp: head.timestamp,
            accepted_at: now,
        };
        let vrf_key = vrf::PublicKey::from_bytes(again.vrf_public()).unwrap();
        assert_eq!(
            proof.verify(&key, 0, &vrf_key, &accepted).unwrap(),
            handle_entry(input, &hk, 0).as_slice()
        );
        assert_eq!(
            call(
                &mut again,
                Kind::Version,
                &dirclient::version_body(&key, 2),
                now,
                &mut rng
            ),
            Err(DirError::Status(Status::NotFound))
        );
    }

    #[test]
    fn a_held_handle_with_a_mark_still_writes_and_retires_and_none_registers() {
        // The profile of RFC 8265 passes the four marks of `DIS-089`.
        fn passing(name: &str) -> Option<String> {
            Some(name.to_ascii_lowercase())
        }
        let mut rng = Rng(21);
        let (keys, keyset) = keys();
        let mut dir = Directory::new(keys, DIRECTORY_EPOCH, passing).unwrap();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([7; 32]));
        let hk = root.handle_key(0, 0);
        for input in [&b"@a%23b#12"[..], b"@a#b#12", b"@a@b#12", b"@a/b#12"] {
            let at = dir.last_close.unwrap();

            // A registration takes no such name.
            let spent = tokens(&mut dir, epoch_number(at), 1, at, &mut rng);
            let entry = handle_entry(input, &hk, 0);
            assert_eq!(
                register(&mut dir, &spent[0], input, &entry, &hk, None, at, &mut rng),
                Err(DirError::Status(Status::Refused))
            );

            // A directory of an earlier build holds the label.
            let search_key = dir.voprf.evaluate_direct(input).to_vec();
            dir.stage(&search_key, handle_entry(input, &hk, 0), &mut rng)
                .unwrap();
            dir.keep_label(
                &search_key,
                LabelRecord {
                    input: input.to_vec(),
                    label: Label::register(hk.public().to_bytes(), at),
                    blob: None,
                },
            );
            let now = at + DIRECTORY_EPOCH;
            dir.tick(now, &mut rng).unwrap();
            assert_eq!(
                read(&mut dir, &keyset, input, now, &mut rng).unwrap(),
                handle_entry(input, &hk, 0)
            );

            // The holder renews it, and moves it to its next key.
            let (bytes, purpose) = challenge(&mut dir, true, input, now, &mut rng).unwrap();
            let ans = answer(purpose, &hk, input, &bytes, None).unwrap();
            let renew = dirclient::renew_body(input, &ans).unwrap();
            call(&mut dir, Kind::Renew, &renew, now, &mut rng).unwrap();
            let next = root.handle_key(0, 1);
            let entry = handle_entry(input, &next, 1);
            let (bytes, purpose) = challenge(&mut dir, false, input, now, &mut rng).unwrap();
            let ans = answer(purpose, &hk, input, &bytes, Some(&entry)).unwrap();
            let write = dirclient::write_body(input, &ans, &entry).unwrap();
            call(&mut dir, Kind::Write, &write, now, &mut rng).unwrap();
            let now = now + DIRECTORY_EPOCH;
            dir.tick(now, &mut rng).unwrap();

            // DIS-171: the holder retires it.
            let tomb = DirectoryEntry::tombstone(input.to_vec(), 2);
            let mut bytes_of = vec![0u8; tomb.len()];
            let used = tomb.encode(&mut bytes_of).unwrap();
            bytes_of.truncate(used);
            let (bytes, purpose) = challenge(&mut dir, false, input, now, &mut rng).unwrap();
            let ans = answer(purpose, &next, input, &bytes, Some(&bytes_of)).unwrap();
            let write = dirclient::write_body(input, &ans, &bytes_of).unwrap();
            call(&mut dir, Kind::Write, &write, now, &mut rng).unwrap();
            let now = now + DIRECTORY_EPOCH;
            dir.tick(now, &mut rng).unwrap();
            let shown =
                DirectoryEntry::parse(&read(&mut dir, &keyset, input, now, &mut rng).unwrap())
                    .unwrap();
            assert!(shown.is_tombstone());
        }
    }

    #[test]
    fn an_address_retires_early_and_a_lapsed_lease_tombstones() {
        let mut rng = Rng(6);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([8; 32]));
        let key = root.public_address_key(3);
        let pk = key.public().to_bytes();
        let address = address_of(&pk);
        let input = address_label_input(&address);
        let encode = |entry: &AddressEntry| {
            let mut out = vec![0u8; ADDRESS_ENTRY_LEN];
            entry.encode(&mut out).unwrap();
            out
        };
        let live = encode(&AddressEntry {
            address,
            address_pk: pk,
            rendezvous: Some(queue(4)),
            version: 0,
        });
        let spent = tokens(&mut dir, epoch_number(T0), 2, T0, &mut rng);

        // DIS-169: the challenge names the key whose hash is the address.
        let other = root.public_address_key(4);
        assert_eq!(
            register(&mut dir, &spent[0], &input, &live, &other, None, T0, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
        register(&mut dir, &spent[0], &input, &live, &key, None, T0, &mut rng).unwrap();

        // DIS-171: the holder writes the tombstone.
        let tomb = encode(&AddressEntry {
            address,
            address_pk: [0; 1_216],
            rendezvous: None,
            version: 1,
        });
        let (bytes, purpose) = challenge(&mut dir, false, &input, T0, &mut rng).unwrap();
        let ans = answer(purpose, &key, &address, &bytes, Some(&tomb)).unwrap();
        let write = dirclient::write_body(&input, &ans, &tomb).unwrap();

        // DIS-010: one version in each epoch, thus the write waits.
        assert_eq!(
            call(&mut dir, Kind::Write, &write, T0, &mut rng),
            Err(DirError::Status(Status::Busy))
        );
        let at = T0 + DIRECTORY_EPOCH;
        dir.tick(at, &mut rng).unwrap();
        let (bytes, purpose) = challenge(&mut dir, false, &input, at, &mut rng).unwrap();
        let ans = answer(purpose, &key, &address, &bytes, Some(&tomb)).unwrap();
        let write = dirclient::write_body(&input, &ans, &tomb).unwrap();
        call(&mut dir, Kind::Write, &write, at, &mut rng).unwrap();
        let now = T0 + 2 * DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert_eq!(
            read(&mut dir, &keyset, &input, now, &mut rng).unwrap(),
            tomb
        );

        // A tombstone renews nothing.
        assert_eq!(
            challenge(&mut dir, true, &input, now, &mut rng).map(|_| ()),
            Err(DirError::Status(Status::Stale))
        );

        // DIS-073: a handle whose lease lapses takes its tombstone.
        let hk = root.handle_key(0, 0);
        let handle = b"@carol#42";
        let entry0 = handle_entry(handle, &hk, 0);
        register(
            &mut dir, &spent[1], handle, &entry0, &hk, None, now, &mut rng,
        )
        .unwrap();
        let lapse = now + HANDLE_LEASE + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();

        // The tombstone stages at the tick, and shows at the next one.
        let lapse = lapse + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();
        let entry =
            DirectoryEntry::parse(&read(&mut dir, &keyset, handle, lapse, &mut rng).unwrap())
                .unwrap();
        assert!(entry.is_tombstone());
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn a_label_whose_tombstone_does_not_build_holds_no_epoch_and_no_other_label() {
        let mut rng = Rng(8);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([8; 32]));
        let hk = root.handle_key(0, 0);
        let handle = b"@carol#42";
        let spent = tokens(&mut dir, epoch_number(T0), 1, T0, &mut rng);
        let entry0 = handle_entry(handle, &hk, 0);
        register(
            &mut dir, &spent[0], handle, &entry0, &hk, None, T0, &mut rng,
        )
        .unwrap();

        // A stored label with a fault: an address input of a wrong length,
        // whose tombstone entry does not build.
        let held = dir
            .labels
            .get(dir.voprf.evaluate_direct(handle).as_slice())
            .unwrap()
            .clone();
        let faulty = alloc::vec![0xEEu8; 32];
        dir.labels.insert(
            faulty.clone(),
            LabelRecord {
                input: [labels::ADDRESS_INDEX, b"short"].concat(),
                ..held
            },
        );

        // DIS-073: the leases lapse. The epoch closes, the handle takes
        // its tombstone, and the label with the fault keeps its state.
        let lapse = T0 + HANDLE_LEASE + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();
        let lapse = lapse + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();
        assert_eq!(dir.last_close, Some(lapse));
        let entry =
            DirectoryEntry::parse(&read(&mut dir, &keyset, handle, lapse, &mut rng).unwrap())
                .unwrap();
        assert!(entry.is_tombstone());
        assert!(!dir.labels[&faulty].label.is_tombstoned());
    }

    /// The sealed profile blob that a lookup of `input` carries.
    fn read_blob(dir: &mut Directory, input: &[u8], now: u64, rng: &mut Rng) -> Option<Vec<u8>> {
        let pk = *dir.voprf_public();
        let (state, body) =
            dirclient::evaluate_request(input, &pk, epoch_number(now), None, rng).unwrap();
        let evaluated = call(dir, Kind::Evaluate, &body, now, rng).unwrap();
        let search_key = dirclient::evaluate_finish(&state, &evaluated, &pk).unwrap();
        let looked = call(dir, Kind::Lookup, &search_key, now, rng).unwrap();
        dirclient::parse_lookup(&looked).unwrap().1
    }

    #[test]
    fn a_handle_keeps_its_profile_blob_and_a_tombstone_drops_it() {
        use crate::discovery::profile::ProfilePlain;

        let mut rng = Rng(12);
        let (mut dir, _) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([12; 32]));
        let hk = root.handle_key(0, 0);
        let input = b"@erin#77";
        let spent = tokens(&mut dir, epoch_number(T0), 1, T0, &mut rng);
        let entry0 = handle_entry(input, &hk, 0);
        register(&mut dir, &spent[0], input, &entry0, &hk, None, T0, &mut rng).unwrap();
        let now = T0 + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert!(read_blob(&mut dir, input, now, &mut rng).is_none());

        let handle = Handle::parse("@erin#77", &ascii_profile).unwrap();
        let plain = ProfilePlain {
            name: "Erin",
            welcome: "Say where we met.",
            picture: &[],
        }
        .encode()
        .unwrap();
        let fragment = [5; 16];
        let blob = handle.seal_blob(&fragment, [6; 24], &plain).unwrap();
        let blob_challenge = |dir: &mut Directory, rng: &mut Rng| {
            let body = dirclient::blob_challenge_body(input).unwrap();
            call(dir, Kind::Challenge, &body, now, rng).unwrap()
        };

        // DIS-175: the answer binds the blob, thus another blob under it is
        // refused.
        let bytes = blob_challenge(&mut dir, &mut rng);
        let ans = answer(Purpose::Blob, &hk, input, &bytes, Some(&blob)).unwrap();
        let other = handle.seal_blob(&fragment, [7; 24], &plain).unwrap();
        let wrong = dirclient::blob_body(input, &ans, &other).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Blob, &wrong, now, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
        let bytes = blob_challenge(&mut dir, &mut rng);
        let ans = answer(Purpose::Blob, &hk, input, &bytes, Some(&blob)).unwrap();
        let write = dirclient::blob_body(input, &ans, &blob).unwrap();
        call(&mut dir, Kind::Blob, &write, now, &mut rng).unwrap();

        // The blob needs no epoch of the log, and the fragment opens it.
        let held = read_blob(&mut dir, input, now, &mut rng).unwrap();
        assert_eq!(held, blob);
        let opened = handle.open_blob(&fragment, &held).unwrap();
        assert_eq!(ProfilePlain::parse(&opened).unwrap().name, "Erin");
        assert!(handle.open_blob(&[9; 16], &held).is_err());

        // DIS-178: a tombstone takes the blob with it.
        let tomb = DirectoryEntry::tombstone(input.to_vec(), 1);
        let mut tomb_bytes = vec![0u8; tomb.len()];
        let used = tomb.encode(&mut tomb_bytes).unwrap();
        tomb_bytes.truncate(used);
        let (bytes, purpose) = challenge(&mut dir, false, input, now, &mut rng).unwrap();
        let ans = answer(purpose, &hk, input, &bytes, Some(&tomb_bytes)).unwrap();
        let write = dirclient::write_body(input, &ans, &tomb_bytes).unwrap();
        call(&mut dir, Kind::Write, &write, now, &mut rng).unwrap();
        let later = now + DIRECTORY_EPOCH;
        dir.tick(later, &mut rng).unwrap();
        assert!(read_blob(&mut dir, input, later, &mut rng).is_none());
    }

    #[test]
    fn a_timed_address_ends_at_the_directory_with_no_holder_online() {
        let mut rng = Rng(9);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([9; 32]));
        let key = root.public_address_key(5);
        let pk = key.public().to_bytes();
        let address = address_of(&pk);
        let input = address_label_input(&address);
        let mut live = vec![0u8; ADDRESS_ENTRY_LEN];
        AddressEntry {
            address,
            address_pk: pk,
            rendezvous: Some(queue(6)),
            version: 0,
        }
        .encode(&mut live)
        .unwrap();
        let spent = tokens(&mut dir, epoch_number(T0), 2, T0, &mut rng);

        // DIS-173: a lease below LEASE_MIN or above HANDLE_LEASE is no
        // lease, and the token stays unspent.
        assert_eq!(
            register(
                &mut dir,
                &spent[0],
                &input,
                &live,
                &key,
                Some(60),
                T0,
                &mut rng
            ),
            Err(DirError::Status(Status::Malformed))
        );
        register(
            &mut dir,
            &spent[0],
            &input,
            &live,
            &key,
            Some(3_600),
            T0,
            &mut rng,
        )
        .unwrap();
        let now = T0 + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert_eq!(
            read(&mut dir, &keyset, &input, now, &mut rng).unwrap(),
            live
        );

        // DIS-172: a renewal keeps the end of the registration.
        let (bytes, purpose) = challenge(&mut dir, true, &input, now, &mut rng).unwrap();
        let ans = answer(purpose, &key, &address, &bytes, None).unwrap();
        let renew = dirclient::renew_body(&input, &ans).unwrap();
        call(&mut dir, Kind::Renew, &renew, now + 1, &mut rng).unwrap();

        // The lease lapses at its end, and the directory writes the
        // tombstone with no request of the holder.
        let lapse = T0 + 3_600 + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();
        let lapse = lapse + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();
        let shown = read(&mut dir, &keyset, &input, lapse, &mut rng).unwrap();
        let entry = AddressEntry::parse(&shown).unwrap();
        assert!(entry.rendezvous.is_none());
        assert_eq!(entry.address_pk, [0; 1_216]);
    }

    #[test]
    fn an_issuance_refuses_a_far_epoch_and_a_low_effort() {
        let mut rng = Rng(7);
        let (mut dir, _) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let epoch = epoch_number(T0);
        let pk = dir.issuer_public(epoch + 2).unwrap();
        let (_, body) = dirclient::issue_request(epoch + 2, &pk, 1, &mut rng).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Issue, &body, T0, &mut rng),
            Err(DirError::Status(Status::Stale))
        );

        // ABU-110: the next epoch is in the log after the first tick.
        assert_eq!(tokens(&mut dir, epoch + 1, 1, T0, &mut rng).len(), 1);

        let pk = dir.issuer_public(epoch).unwrap();
        let (_, mut body) = dirclient::issue_request(epoch, &pk, 1, &mut rng).unwrap();

        // The effort of the one solution: after the type, the epoch, the
        // count, the element, the version byte, the seed, and the nonce.
        let at = 7 + 32 + 1 + 32 + 16;
        body[at..at + 4].copy_from_slice(&20u32.to_be_bytes());
        assert_eq!(
            call(&mut dir, Kind::Issue, &body, T0, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
    }

    #[test]
    fn a_lapsed_label_registers_again_only_under_the_key_that_it_names() {
        use crate::discovery::HANDLE_RESERVE;

        let mut rng = Rng(31);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([31; 32]));
        let hk = root.handle_key(0, 0);
        let input = b"@frank#5150";
        let spent = tokens(&mut dir, epoch_number(T0), 1, T0, &mut rng);
        let entry0 = handle_entry(input, &hk, 0);
        register(&mut dir, &spent[0], input, &entry0, &hk, None, T0, &mut rng).unwrap();
        dir.tick(T0 + DIRECTORY_EPOCH, &mut rng).unwrap();

        // DIS-073: the lease lapses, and the tombstone shows at version 1.
        let lapse = T0 + HANDLE_LEASE + DIRECTORY_EPOCH;
        dir.tick(lapse, &mut rng).unwrap();
        dir.tick(lapse + DIRECTORY_EPOCH, &mut rng).unwrap();

        // DIS-077: after the reservation the label registers as version 2.
        let later = lapse + HANDLE_RESERVE;
        dir.tick(later, &mut rng).unwrap();
        let at = later + 1;
        let fresh = tokens(&mut dir, epoch_number(at), 2, at, &mut rng);

        // A second party reuses the published key of the holder with a
        // queue of its own. It holds no private half, thus no answer of it
        // holds (DIS-197).
        let thief = root.handle_key(9, 0);
        let stolen = {
            let entry = DirectoryEntry {
                handle: input.to_vec(),
                hk_pub: hk.public().to_bytes(),
                rendezvous: Some(queue(9)),
                version: 2,
            };
            let mut out = vec![0u8; DIRECTORY_ENTRY_MAX];
            let used = entry.encode(&mut out).unwrap();
            out.truncate(used);
            out
        };
        assert_eq!(
            register_as(&mut dir, &fresh[0], input, &stolen, &hk, &thief, None, at, &mut rng),
            Err(DirError::Status(Status::Refused))
        );

        // The challenge names the version that the entry carries.
        assert_eq!(
            register(
                &mut dir,
                &fresh[0],
                input,
                &handle_entry(input, &hk, 0),
                &hk,
                None,
                at,
                &mut rng
            ),
            Err(DirError::Status(Status::Refused))
        );

        // The holder registers it again under its own key.
        let entry2 = handle_entry(input, &hk, 2);
        register(&mut dir, &fresh[0], input, &entry2, &hk, None, at, &mut rng).unwrap();
        let now = at + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert_eq!(
            read(&mut dir, &keyset, input, now, &mut rng).unwrap(),
            entry2
        );
    }

    #[test]
    fn a_lookup_proof_of_work_serves_one_evaluation() {
        let mut rng = Rng(32);
        let (mut dir, _) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let pk = *dir.voprf_public();
        let (_, body) =
            dirclient::evaluate_request(b"@gina#1", &pk, epoch_number(T0), None, &mut rng).unwrap();
        call(&mut dir, Kind::Evaluate, &body, T0, &mut rng).unwrap();

        // DIS-200: the same element and solution again cost no evaluation.
        assert_eq!(
            call(&mut dir, Kind::Evaluate, &body, T0 + 1, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
        assert_eq!(dir.lookup_seeds.len(), 1);
    }

    #[test]
    fn a_full_seed_set_drops_a_random_seed_and_still_evaluates() {
        let mut rng = Rng(36);
        let (mut dir, _) = directory();
        dir.tick(T0, &mut rng).unwrap();
        dir.lookup_seeds = LookupSeeds::new(2);
        let pk = *dir.voprf_public();
        let epoch = epoch_number(T0);
        let bodies: Vec<Vec<u8>> = (0..3)
            .map(|_| {
                dirclient::evaluate_request(b"@ivy#1", &pk, epoch, None, &mut rng)
                    .unwrap()
                    .1
            })
            .collect();
        let is_held = |dir: &Directory, body: &[u8]| {
            let blinded: [u8; 32] = body[body.len() - 32..].try_into().unwrap();
            dir.lookup_seeds
                .is_held(epoch, &lookup_seed(epoch, &blinded))
        };

        // DIS-202: a full set refuses no lookup.
        for body in &bodies {
            call(&mut dir, Kind::Evaluate, body, T0, &mut rng).unwrap();
        }
        assert_eq!(dir.lookup_seeds.len(), 2);
        assert!(is_held(&dir, &bodies[2]));

        // DIS-200: each seed that the set holds serves no second evaluation.
        let held: Vec<&Vec<u8>> = bodies.iter().filter(|body| is_held(&dir, body)).collect();
        assert_eq!(held.len(), 2);
        for body in held {
            assert_eq!(
                call(&mut dir, Kind::Evaluate, body, T0 + 1, &mut rng),
                Err(DirError::Status(Status::Refused))
            );
        }

        // A party with one solution more than the bound sends them again in
        // a fixed order. A drop of the oldest seed lets each one pass, and a
        // random drop does not.
        let mut passed = 0;
        for body in bodies.iter().cycle().take(30) {
            if call(&mut dir, Kind::Evaluate, body, T0 + 2, &mut rng).is_ok() {
                passed += 1;
            }
            assert_eq!(dir.lookup_seeds.len(), 2);
        }
        assert!(passed < 30, "{passed} replays passed");

        // A seed of an epoch before the one before the clock goes.
        let later = T0 + 2 * crate::abuse::EPOCH_SECONDS;
        let (_, body) =
            dirclient::evaluate_request(b"@ivy#1", &pk, epoch_number(later), None, &mut rng)
                .unwrap();
        call(&mut dir, Kind::Evaluate, &body, later, &mut rng).unwrap();
        assert_eq!(dir.lookup_seeds.len(), 1);
    }

    #[test]
    fn a_token_pays_for_a_registration_challenge_and_a_flood_with_none_stops_no_paid_one() {
        let mut rng = Rng(37);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        dir.register_max = (1, 1);
        let epoch = epoch_number(T0);
        let root = RootIdentity::new(Secret::new([37; 32]));
        let hk = root.handle_key(0, 0);
        let pk = hk.public().to_bytes();
        let paid = tokens(&mut dir, epoch, 2, T0, &mut rng);
        let nonce = |token: &[u8]| Token::parse(token).unwrap().nonce;

        // DIS-091: a name that no registration takes gets no challenge.
        let body = dirclient::register_challenge_body(&[7; 8], &pk, None).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Challenge, &body, T0, &mut rng),
            Err(DirError::Status(Status::Refused))
        );

        // Challenges with no token fill their own bound.
        let flood = root.handle_key(1, 0).public().to_bytes();
        for (input, status) in [(b"@flood#1001", None), (b"@flood#1002", Some(Status::Busy))] {
            let body = dirclient::register_challenge_body(input, &flood, None).unwrap();
            let result = call(&mut dir, Kind::Challenge, &body, T0, &mut rng);
            assert_eq!(result.err(), status.map(DirError::Status));
        }

        // DIS-203: a challenge with a token takes a place of its own, and
        // the token spends with it.
        let input = b"@ivan#1001";
        let entry = handle_entry(input, &hk, 0);
        let body = dirclient::register_challenge_body(input, &pk, Some(&paid[0])).unwrap();
        let bytes = call(&mut dir, Kind::Challenge, &body, T0, &mut rng).unwrap();
        assert!(dir.spent.is_spent(epoch, &nonce(&paid[0])));

        // A spent token pays for no other challenge, and a repeat of the
        // live one gets it again (DIS-194).
        let other = dirclient::register_challenge_body(b"@ivan#1002", &pk, Some(&paid[0])).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Challenge, &other, T0 + 1, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
        let again = dirclient::register_challenge_body(input, &pk, Some(&paid[1])).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Challenge, &again, T0 + 1, &mut rng).unwrap(),
            bytes
        );
        assert!(!dir.spent.is_spent(epoch, &nonce(&paid[1])));

        // The registration under the paid challenge spends no second token.
        let (challenge, purpose) = dirclient::parse_register_challenge(&bytes).unwrap();
        let ans = answer(purpose, &hk, input, &challenge, Some(&entry)).unwrap();
        let register = dirclient::register_body(&paid[1], input, &entry, &ans, None).unwrap();
        call(&mut dir, Kind::Register, &register, T0 + 1, &mut rng).unwrap();
        assert!(!dir.spent.is_spent(epoch, &nonce(&paid[1])));

        let now = T0 + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert_eq!(
            read(&mut dir, &keyset, input, now, &mut rng).unwrap(),
            entry
        );
    }

    #[test]
    fn a_full_bound_of_paid_challenges_drops_the_oldest_one() {
        let mut rng = Rng(39);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        dir.register_max = (1, 1);
        let paid = tokens(&mut dir, epoch_number(T0), 2, T0, &mut rng);
        let root = RootIdentity::new(Secret::new([39; 32]));
        let mut claims = Vec::new();
        for (i, input) in [b"@jade#1001", b"@jade#1002"].into_iter().enumerate() {
            let hk = root.handle_key(0, u32::try_from(i).unwrap());
            let body =
                dirclient::register_challenge_body(input, &hk.public().to_bytes(), Some(&paid[i]))
                    .unwrap();
            let now = T0 + u64::try_from(i).unwrap();
            let bytes = call(&mut dir, Kind::Challenge, &body, now, &mut rng).unwrap();
            claims.push((input, hk, bytes));
        }

        // DIS-203: the second paid challenge took the place of the first one,
        // and the registration under the first one ends.
        for (i, (input, hk, bytes)) in claims.iter().enumerate() {
            let entry = handle_entry(*input, hk, 0);
            let (challenge, purpose) = dirclient::parse_register_challenge(bytes).unwrap();
            let ans = answer(purpose, hk, *input, &challenge, Some(&entry)).unwrap();
            let body = dirclient::register_body(&paid[i], *input, &entry, &ans, None).unwrap();
            let result = call(&mut dir, Kind::Register, &body, T0 + 2, &mut rng);
            let expected = if i == 0 {
                Err(DirError::Status(Status::Stale))
            } else {
                Ok(Vec::new())
            };
            assert_eq!(result, expected);
        }

        let now = T0 + DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        assert!(read(&mut dir, &keyset, b"@jade#1001", now, &mut rng).is_none());
        assert!(read(&mut dir, &keyset, b"@jade#1002", now, &mut rng).is_some());
    }

    #[test]
    fn a_replay_takes_the_root_of_each_epoch_and_checks_the_newest_one() {
        let mut rng = Rng(38);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([38; 32]));
        let hk = root.handle_key(0, 0);
        let spent = tokens(&mut dir, epoch_number(T0), 2, T0, &mut rng);
        let first = b"@jade#1001";
        let entry1 = handle_entry(first, &hk, 0);
        register(&mut dir, &spent[0], first, &entry1, &hk, None, T0, &mut rng).unwrap();
        dir.tick(T0 + DIRECTORY_EPOCH, &mut rng).unwrap();
        let second = b"@jade#1002";
        let entry2 = handle_entry(second, &hk, 0);
        let at = T0 + DIRECTORY_EPOCH + 1;
        register(
            &mut dir, &spent[1], second, &entry2, &hk, None, at, &mut rng,
        )
        .unwrap();
        dir.tick(T0 + 2 * DIRECTORY_EPOCH, &mut rng).unwrap();
        let now = T0 + 3 * DIRECTORY_EPOCH;
        dir.tick(now, &mut rng).unwrap();
        let events = dir.take_events();

        // Each close keeps its root.
        let kept = events
            .iter()
            .filter(|event| matches!(event, DirEvent::Closed { root: Some(_), .. }))
            .count();
        assert_eq!(kept, 4);

        let replay = |events: &[DirEvent], rng: &mut Rng| {
            let (keys, _) = keys();
            let mut again = Directory::new(keys, DIRECTORY_EPOCH, ascii_profile).unwrap();
            again.replay(events, rng).map(|()| again)
        };

        // A store of an earlier build kept no root for its first epochs.
        let mut mixed = events.clone();
        for event in mixed
            .iter_mut()
            .filter(|event| matches!(event, DirEvent::Closed { .. }))
            .take(2)
        {
            if let DirEvent::Closed { root, .. } = event {
                assert!(root.is_some());
                *root = None;
            }
        }

        for events in [&events, &mixed] {
            let mut again = replay(events, &mut rng).unwrap();
            assert_eq!(again.operator.head(), dir.operator.head());
            assert_eq!(again.auditors, dir.auditors);
            assert_eq!(
                read(&mut again, &keyset, first, now, &mut rng).unwrap(),
                entry1
            );
            assert_eq!(
                read(&mut again, &keyset, second, now, &mut rng).unwrap(),
                entry2
            );

            // The auditors of the replay check the next epoch.
            again.tick(now + DIRECTORY_EPOCH, &mut rng).unwrap();
        }

        // A newest root that the seal does not give again starts nothing.
        let mut broken = events.clone();
        if let Some(DirEvent::Closed { root, .. }) = broken
            .iter_mut()
            .rev()
            .find(|event| matches!(event, DirEvent::Closed { .. }))
        {
            *root = Some([9; 32]);
        }
        assert!(replay(&broken, &mut rng).is_err());
    }

    #[test]
    fn an_epoch_that_an_auditor_refuses_keeps_its_versions_for_the_next_one() {
        let mut rng = Rng(33);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let root = RootIdentity::new(Secret::new([33; 32]));
        let hk = root.handle_key(0, 0);
        let input = b"@hana#33";
        let spent = tokens(&mut dir, epoch_number(T0), 1, T0, &mut rng);
        let entry0 = handle_entry(input, &hk, 0);
        register(&mut dir, &spent[0], input, &entry0, &hk, None, T0, &mut rng).unwrap();

        // An auditor that holds another log refuses the epoch: the log, the
        // other auditor, and the staged version stay as they were.
        let held = dir.auditors.clone();
        let size = dir.operator.head().unwrap().0;
        dir.auditors[1] = Auditor::default();
        let now = T0 + DIRECTORY_EPOCH;
        assert!(dir.tick(now, &mut rng).is_err());
        assert_eq!(dir.operator.head().unwrap().0, size);
        assert_eq!(dir.auditors[0], held[0]);
        let search_key = dir.voprf.evaluate_direct(input).to_vec();
        assert!(dir.operator.is_staged(&search_key));

        // With the auditor back, the next tick closes the epoch.
        dir.auditors[1] = held[1].clone();
        dir.tick(now + 1, &mut rng).unwrap();
        assert_eq!(dir.operator.head().unwrap().0, size + 1);
        assert_eq!(
            read(&mut dir, &keyset, input, now + 1, &mut rng).unwrap(),
            entry0
        );
    }

    /// A reader over a directory in this process, as a client holds it.
    struct Local {
        dir: core::cell::RefCell<Directory>,
        rng: core::cell::RefCell<Rng>,
        pins: dirclient::DirectoryPins,
        held: core::cell::Cell<Option<crate::discovery::reader::HeldHead>>,
        keyset: core::cell::RefCell<Vec<u8>>,
        now: core::cell::Cell<u64>,
    }

    impl crate::discovery::reader::LogChannel for Local {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>, crate::discovery::reader::ReadError> {
            let now = self.now.get();
            Ok(self
                .dir
                .borrow_mut()
                .handle(request, now, &mut *self.rng.borrow_mut()))
        }

        fn pins(&self) -> &dirclient::DirectoryPins {
            &self.pins
        }

        fn held(&self) -> Option<crate::discovery::reader::HeldHead> {
            self.held.get()
        }

        fn set_held(&self, head: crate::discovery::reader::HeldHead) {
            self.held.set(Some(head));
        }

        fn now(&self) -> u64 {
            self.now.get()
        }

        fn keyset(&self) -> Vec<u8> {
            self.keyset.borrow().clone()
        }

        fn set_keyset(&self, keyset: Vec<u8>) {
            *self.keyset.borrow_mut() = keyset;
        }
    }

    #[test]
    fn a_held_search_key_reads_the_entry_with_no_evaluation() {
        use crate::discovery::reader;

        let mut rng = Rng(39);
        let (mut dir, keyset) = directory();
        dir.tick(T0, &mut rng).unwrap();
        let pins = dirclient::DirectoryPins {
            key_config: Vec::new(),
            keyset: keyset.clone(),
            vrf_public: *dir.vrf_public(),
            voprf_public: *dir.voprf_public(),
        };
        let local = Local {
            dir: core::cell::RefCell::new(dir),
            rng: core::cell::RefCell::new(Rng(40)),
            pins,
            held: core::cell::Cell::new(None),
            keyset: core::cell::RefCell::new(keyset),
            now: core::cell::Cell::new(T0 + 1),
        };

        // DIS-204: one input gives one search key under one key, thus a read
        // under the held key costs no evaluation and no proof of work.
        let input = issuer_label_input(TYPE_FIRST_PARTY, epoch_number(T0));
        let (found, key) = reader::find_keyed(&local, &input, &mut rng).unwrap();
        assert!(found.entry.is_some());
        assert_eq!(local.dir.borrow().lookup_seeds.len(), 1);

        let again = reader::find_under(&local, &key).unwrap();
        assert_eq!((again.entry, again.version), (found.entry, found.version));
        assert_eq!(local.dir.borrow().lookup_seeds.len(), 1);

        let (_, evaluated) = reader::find_keyed(&local, &input, &mut rng).unwrap();
        assert_eq!(evaluated, key);
    }

    #[test]
    fn a_reader_follows_a_signed_key_set_rotation_and_reads_a_stale_head_as_degraded() {
        use crate::directory::CLOCK_SKEW;
        use crate::discovery::{reader, TREE_HEAD_FRESHNESS};

        let mut rng = Rng(34);
        let (old, genesis) = keys();

        // DIS-064: the next set, signed by two signers of the genesis set.
        let next: Vec<_> = [0u8, 1, 2]
            .into_iter()
            .map(|i| SigningKey::from_seed(Secret::new([90 + i; 32])))
            .collect();
        let public: Vec<_> = next.iter().map(|s| s.verifying_key().to_bytes()).collect();
        let set = LogKeySet {
            keyset_epoch: 2,
            keys: public.iter().map(|k| &k[..]).collect(),
        };
        let mut next_set = vec![0u8; KEYSET_LEN];
        let used = set.encode(&mut next_set).unwrap();
        next_set.truncate(used);
        let preimage = set.rotation_preimage().unwrap();
        let mut signed = next_set.clone();
        signed.push(2);
        for (index, signer) in old.signers.iter().enumerate().take(2) {
            signed.push(index as u8);
            signed.extend_from_slice(&signer.sign(&preimage, &mut rng).unwrap().to_bytes());
        }
        let keys = DirectoryKeys {
            signers: next,
            keyset: next_set.clone(),
            ..old
        };
        let mut dir = Directory::new(keys, DIRECTORY_EPOCH, ascii_profile).unwrap();

        // DIS-198: the chain ends at the set of the signers.
        assert!(dir.set_keyset_chain(vec![genesis.clone()]).is_err());
        dir.set_keyset_chain(vec![signed]).unwrap();
        dir.tick(T0, &mut rng).unwrap();
        let pins = dirclient::DirectoryPins {
            key_config: Vec::new(),
            keyset: genesis.clone(),
            vrf_public: *dir.vrf_public(),
            voprf_public: *dir.voprf_public(),
        };
        let local = Local {
            dir: core::cell::RefCell::new(dir),
            rng: core::cell::RefCell::new(Rng(35)),
            pins,
            held: core::cell::Cell::new(None),
            keyset: core::cell::RefCell::new(genesis.clone()),
            now: core::cell::Cell::new(T0 + 1),
        };

        // DIS-199: a head under the next set takes the rotation, and the
        // reader keeps that set.
        let input = issuer_label_input(TYPE_FIRST_PARTY, epoch_number(T0));
        let (found, _) = reader::find_keyed(&local, &input, &mut rng).unwrap();
        assert!(found.entry.is_some());
        assert!(!found.degraded);
        assert_eq!(*local.keyset.borrow(), next_set);
        assert!(local.held.get().is_some());

        // DIS-067, DIS-068: a head past its freshness completes the lookup
        // as unverified, and the reader holds no such head.
        let held = local.held.get();
        local.now.set(T0 + TREE_HEAD_FRESHNESS + CLOCK_SKEW + 2);
        let (found, key) = reader::find_keyed(&local, &input, &mut rng).unwrap();
        assert!(found.entry.is_some());
        assert!(found.degraded);
        assert_eq!(local.held.get(), held);

        // A strict read and an issuer key take no such head.
        assert_eq!(
            reader::lookup(&local, &key).map(|_| ()),
            Err(reader::ReadError::Stale)
        );
        assert_eq!(
            reader::cross_relay_key(&local, epoch_number(T0), &mut rng).map(|_| ()),
            Err(reader::ReadError::Stale)
        );

        // DIS-060: a reader whose held set no rotation reaches refuses.
        let other = Local {
            keyset: core::cell::RefCell::new(next_set.clone()),
            now: core::cell::Cell::new(T0 + 1),
            held: core::cell::Cell::new(None),
            ..local
        };
        let mut wrong = next_set.clone();
        wrong[1] = 0xFF;
        *other.keyset.borrow_mut() = wrong;
        assert_eq!(
            reader::find_keyed(&other, &input, &mut rng).map(|_| ()),
            Err(reader::ReadError::Unverified)
        );
    }
}
