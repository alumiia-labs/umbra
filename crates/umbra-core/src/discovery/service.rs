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
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec,
    vec::Vec,
};

use umbra_crypto::{
    hash::sha3_256,
    labels, pow,
    rand_core::{CryptoRng, TryCryptoRng},
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
    challenge::{Issued, Purpose},
    entry::{AddressEntry, DirectoryEntry},
    handle::Handle,
    head::{LogKeySet, SignedTreeHead, SignerSig},
    lifecycle::{Label, Needs},
    translog::{Auditor, LogOperator},
    HANDLE_LEASE, LEASE_MIN,
};
use crate::{
    abuse::{
        epoch_number,
        issuer::{issuer_label_input, IssuerKeyEntry},
        pow::PowSolution,
        spend::SpendSet,
        token::{FirstPartyIssuer, Token, TokenChallenge, FIRST_PARTY_LEN, TYPE_FIRST_PARTY},
        POW_EFFORT_MAX, POW_LOOKUP_FLOOR,
    },
    Error,
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
}

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
    },
    /// The state of one label after a change.
    Label {
        /// The search key.
        search_key: Vec<u8>,
        /// The stored form of [`LabelRecord`].
        state: Vec<u8>,
    },
}

/// A label that a holder publishes: a handle or an address.
#[derive(Clone)]
struct LabelRecord {
    /// The label input of §9.10.
    input: Vec<u8>,
    /// The lease and the key.
    label: Label,
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
}

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
    challenges: BTreeMap<Vec<u8>, Pending>,
    spent: SpendSet,
    issuer_seed: Secret<32>,
    issuers: BTreeMap<u32, FirstPartyIssuer>,
    published_issuers: BTreeSet<u32>,
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
    sha3_256(&[labels::LOOKUP_POW, directory_pk])
}

/// The seed of the proof of work of an issuance (`ABU-109`).
pub fn issue_seed(epoch: u32, blinded: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::ISSUE_POW, &epoch.to_be_bytes(), blinded])
}

/// The verifier of the proof of work of an issuance (`ABU-109`).
pub fn issue_verifier(issuer_pk: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::ISSUE_POW, issuer_pk])
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
            spent: SpendSet::default(),
            issuer_seed: keys.issuer_seed,
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

    /// The events since the last call, which the store keeps in order.
    pub fn take_events(&mut self) -> Vec<DirEvent> {
        core::mem::take(&mut self.events)
    }

    /// Takes the stored events of an earlier run, in order.
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
                        self.published_issuers.insert(issuer.epoch);
                    }
                }
                DirEvent::Closed { nonce, at } => self.advance(*nonce, *at)?,
                DirEvent::Label { search_key, state } => {
                    self.labels
                        .insert(search_key.clone(), LabelRecord::parse(state)?);
                }
            }
        }
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

    fn keep_label(&mut self, search_key: &[u8], record: LabelRecord) {
        self.events.push(DirEvent::Label {
            search_key: search_key.to_vec(),
            state: record.encode(),
        });
        self.labels.insert(search_key.to_vec(), record);
    }

    /// Closes the epoch, and the two auditors check it.
    fn advance(&mut self, nonce: [u8; 32], at: u64) -> Result<(), Error> {
        let update = self.operator.close_epoch(nonce)?;
        // DIS-049, DIS-050: each auditor checks the epoch before it signs.
        let mut root = None;
        for auditor in &mut self.auditors {
            let checked = auditor.audit(&update)?;
            if root.is_some_and(|held| held != checked) {
                return Err(Error::Unverified);
            }
            root = Some(checked);
        }
        root.ok_or(Error::NoPath)?;
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
            let entry = tombstone_entry(&record.input, version)?;
            self.stage(&search_key, entry, rng)?;
            self.keep_label(&search_key, record);
        }
        let epoch = epoch_number(now);
        for epoch in [epoch, epoch.saturating_add(1)] {
            if self.published_issuers.contains(&epoch) {
                continue;
            }
            let public_key = self.issuer_public(epoch)?.to_vec();
            let entry = IssuerKeyEntry {
                token_type: TYPE_FIRST_PARTY,
                epoch,
                public_key,
            }
            .encode()?;
            let search_key = self
                .voprf
                .evaluate_direct(&issuer_label_input(TYPE_FIRST_PARTY, epoch));
            self.stage(&search_key, entry, rng)?;
            self.published_issuers.insert(epoch);
        }
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        self.advance(nonce, now)?;
        self.sign_head(now, rng)?;
        self.events.push(DirEvent::Closed { nonce, at: now });
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
                let live = [epoch, epoch.saturating_sub(1)]
                    .iter()
                    .any(|e| lookup_seed(*e, &blinded) == solution.seed);
                if !live || solution.effort < POW_LOOKUP_FLOOR {
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
            let issuer = self.issuer(token_epoch).map_err(|_| Status::Refused)?;
            issuer.verify(&token).map_err(|_| Status::Refused)?;
            return self
                .spent
                .spend(epoch, token_epoch, token.nonce)
                .map_err(|_| Status::Refused);
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
        let mut out = Vec::new();
        put_var16(&mut out, head).map_err(|_| Status::Busy)?;
        out.extend_from_slice(&proof);
        Ok(out)
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
    /// checks against it (`DIS-169`, `DIS-170`).
    fn check_entry(&self, input: &[u8], entry: &[u8], version: u32) -> Result<[u8; 1_216], Status> {
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
        let handle = Handle::parse(text, &self.profile).map_err(|_| Status::Refused)?;
        if handle.label_input() != input {
            return Err(Status::Refused);
        }
        let parsed = DirectoryEntry::parse(entry).map_err(|_| Status::Malformed)?;
        if parsed.handle != input || parsed.version != version {
            return Err(Status::Refused);
        }
        Ok(parsed.hk_pub)
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
        let held = self.labels.get(&search_key).cloned();
        // A label that no version holds registers under a token (DIS-101),
        // and one after its reservation as the next version (DIS-077).
        let version = match &held {
            None => 0,
            Some(record) if record.label.needs(now) == Needs::Token => {
                record.label.version.saturating_add(1)
            }
            Some(_) => return Err(Status::Stale),
        };
        // DIS-010: one version of a label in each epoch.
        if self.operator.is_staged(&search_key) {
            return Err(Status::Busy);
        }
        let key = self.check_entry(&input, &entry, version)?;
        if key == [0; 1_216] {
            return Err(Status::Refused);
        }
        self.spend_token(token, now)?;
        if self
            .stage(&search_key, entry, rng)
            .map_err(|_| Status::Stale)?
            != version
        {
            return Err(Status::Stale);
        }
        let mut label = match held {
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
        self.keep_label(&search_key, LabelRecord { input, label });
        Ok(Vec::new())
    }

    fn challenge<R: CryptoRng + ?Sized>(
        &mut self,
        body: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Status> {
        let mut r = Reader::new(body);
        let purpose = r.u8().map_err(|_| Status::Malformed)?;
        let input = take_var16(&mut r).map_err(|_| Status::Malformed)?.to_vec();
        r.finish().map_err(|_| Status::Malformed)?;
        let search_key = self.voprf.evaluate_direct(&input).to_vec();
        let mut record = self
            .labels
            .get(&search_key)
            .cloned()
            .ok_or(Status::NotFound)?;
        let (purpose, lease_epoch) = match purpose {
            0x01 if !record.label.is_tombstoned() => {
                let lease_epoch = record.label.issue_lease_epoch();
                (Purpose::Renew { lease_epoch }, Some(lease_epoch))
            }
            // DIS-075: during the reservation the last key writes too.
            0x02 if record.label.needs(now) != Needs::Token => (
                Purpose::Write {
                    version_new: record.label.version.saturating_add(1),
                },
                None,
            ),
            _ => return Err(Status::Stale),
        };
        let issued = Issued::new(purpose, &record.label.hk_pub, record.challenge_name(), rng)
            .map_err(|_| Status::Busy)?;
        let mut out = issued.bytes().to_vec();
        if let Some(lease_epoch) = lease_epoch {
            out.extend_from_slice(&lease_epoch.to_be_bytes());
            self.keep_label(&search_key, record);
        }
        // DIS-168: a second challenge ends the first.
        self.challenges
            .insert(search_key, Pending { issued, at: now });
        Ok(out)
    }

    fn take_pending(&mut self, search_key: &[u8], now: u64) -> Result<Issued, Status> {
        let pending = self.challenges.remove(search_key).ok_or(Status::Stale)?;
        if now.saturating_sub(pending.at) >= CHALLENGE_TTL {
            return Err(Status::Stale);
        }
        Ok(pending.issued)
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
        let issued = self.take_pending(&search_key, now)?;
        let Purpose::Write { version_new } = issued.purpose() else {
            return Err(Status::Stale);
        };
        // DIS-097, DIS-098: the answer binds the entry.
        issued
            .verify(&answer, Some(&entry))
            .map_err(|_| Status::Refused)?;
        let key = self.check_entry(&input, &entry, version_new)?;
        if self
            .stage(&search_key, entry, rng)
            .map_err(|_| Status::Stale)?
            != version_new
        {
            return Err(Status::Stale);
        }
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
        self.keep_label(&search_key, record);
        Ok(Vec::new())
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
        let issued = self.take_pending(&search_key, now)?;
        let Purpose::Renew { lease_epoch } = issued.purpose() else {
            return Err(Status::Stale);
        };
        issued.verify(&answer, None).map_err(|_| Status::Refused)?;
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
        if token_type != TYPE_FIRST_PARTY || count == 0 || count > ISSUE_REQUEST_MAX {
            return Err(Status::Malformed);
        }
        // ABU-110: this epoch, and the next once its key is in the log.
        let current = epoch_number(now);
        let allowed = epoch == current
            || (epoch == current.saturating_add(1) && self.published_issuers.contains(&epoch));
        if !allowed {
            return Err(Status::Stale);
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
        let (head, proof) = dirclient::parse_lookup(&looked).unwrap();
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
        let register =
            dirclient::register_body(&spent[0], input, &handle_entry(input, &hk, 0), None).unwrap();
        call(&mut dir, Kind::Register, &register, T0 + 1, &mut rng).unwrap();
        // DIS-170: a held label does not register again, and a token
        // spends once.
        assert_eq!(
            call(&mut dir, Kind::Register, &register, T0 + 2, &mut rng),
            Err(DirError::Status(Status::Stale))
        );
        let other = b"@bob#99";
        let again =
            dirclient::register_body(&spent[0], other, &handle_entry(other, &hk, 0), None).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Register, &again, T0 + 2, &mut rng),
            Err(DirError::Status(Status::Refused))
        );
        // DIS-169: the entry names its label.
        let wrong =
            dirclient::register_body(&spent[1], other, &handle_entry(input, &hk, 0), None).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Register, &wrong, T0 + 2, &mut rng),
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
        let register = dirclient::register_body(&spent[0], &input, &live, None).unwrap();
        call(&mut dir, Kind::Register, &register, T0, &mut rng).unwrap();

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
        let register =
            dirclient::register_body(&spent[1], handle, &handle_entry(handle, &hk, 0), None)
                .unwrap();
        call(&mut dir, Kind::Register, &register, now, &mut rng).unwrap();
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
        let short = dirclient::register_body(&spent[0], &input, &live, Some(60)).unwrap();
        assert_eq!(
            call(&mut dir, Kind::Register, &short, T0, &mut rng),
            Err(DirError::Status(Status::Malformed))
        );
        let register = dirclient::register_body(&spent[0], &input, &live, Some(3_600)).unwrap();
        call(&mut dir, Kind::Register, &register, T0, &mut rng).unwrap();
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
}
