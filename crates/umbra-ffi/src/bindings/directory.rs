//! The calls of the client to the directory and the issuer of Part 9 §9.10
//! and Part 13 §13.9, each in OHTTP through the pinned ingress relay.
//!
//! Each call blocks on a small runtime of its own, thus the platform calls
//! it from a worker thread, and the lock of the client is not held while it
//! runs. A proof of work of an issuance takes some seconds.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use umbra_core::discovery::{RENDEZVOUS_ROTATE, ROTATE_GRACE};
use umbra_core::{
    abuse::{
        epoch_number,
        issuer::{issuer_label_input, IssuerKeys},
        token::TYPE_FIRST_PARTY,
    },
    discovery::{
        challenge::{answer, Purpose},
        dirclient::{self, DirError, DirectoryPins},
        entry::{AddressEntry, DirectoryEntry, ADDRESS_ENTRY_LEN, ENTRY_PK_LEN},
        handle::{
            address_label_input, parse_profile_link, username_case_mapped, Handle as DirHandle,
            PROFILE_LINK_PREFIX,
        },
        head::{AcceptedHead, LogKeySet},
        lifecycle::{assess, Takeover, Version},
        profile::ProfilePlain,
        reader::{self, HeldHead, LogChannel, ReadError},
        service::DIRECTORY_EPOCH,
        translog::LookupProof,
        HANDLE_HISTORY_MAX, HANDLE_LEASE, LEASE_MIN,
    },
    identity::address,
};
use umbra_crypto::{kem::KeyPair, rand_core::TryRng, rsabssa::PublicKey2048, vrf};
use umbra_transport::{
    directory::{call, DirectoryRoute},
    https::Url,
    native,
};
use umbra_wire::{
    address::{QueueAddress, LEN as QUEUE_ADDRESS_LEN},
    directory::{Kind, Status},
};

use super::{locked, unix_now, FfiError, Handle};
use crate::{
    client::{EntryKind, PendingWrite, Published},
    runtime::OsRng,
};

/// The search keys that one link holds. A device publishes a few labels,
/// and the issuer label changes once in each epoch.
const SEARCH_KEYS_HELD: usize = 64;

/// The pinned route to the directory, with the keys of `DIS-163`.
#[derive(Clone)]
pub struct DirectoryLink {
    route: DirectoryRoute,
    pins: Arc<DirectoryPins>,
    tls: Arc<native::ClientConfig>,
    /// The newest head that this device accepted: its size, its root, and
    /// its timestamp (`DIS-061`).
    held: Arc<std::sync::Mutex<Option<HeldHead>>>,
    /// The key set of the log that a signed rotation gave, or none for the
    /// pinned set (`DIS-199`).
    keyset: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    /// The search key of each label of this device and of each issuer
    /// label that a call evaluated under the pinned VOPRF key (`DIS-204`).
    /// Each link of one route shares it.
    search_keys: Arc<std::sync::Mutex<BTreeMap<Vec<u8>, [u8; 64]>>>,
}

impl From<DirError> for FfiError {
    fn from(error: DirError) -> Self {
        match error {
            DirError::Malformed | DirError::Status(Status::Malformed) => FfiError::Malformed,
            DirError::Status(Status::Refused) => FfiError::Unverified,
            DirError::Status(Status::NotFound) => FfiError::NotFound,
            DirError::Status(Status::Stale) => FfiError::Stale,
            DirError::Status(Status::Busy | Status::Done) => FfiError::Busy,
        }
    }
}

pub use umbra_core::discovery::reader::Found;

impl From<ReadError> for FfiError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::Offline => FfiError::Offline,
            ReadError::Busy => FfiError::Busy,
            ReadError::Stale => FfiError::Stale,
            ReadError::Unverified => FfiError::Unverified,
            ReadError::NotFound => FfiError::NotFound,
            ReadError::Malformed => FfiError::Malformed,
            ReadError::TooLong => FfiError::TooLong,
        }
    }
}

/// The client reads the log over the pinned route, and each device keeps
/// the newest head that it accepted.
impl LogChannel for DirectoryLink {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, ReadError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ReadError::Offline)?;
        runtime
            .block_on(call(&self.route, request, self.tls.clone(), &mut OsRng))
            .map_err(|_| ReadError::Offline)
    }

    fn pins(&self) -> &DirectoryPins {
        &self.pins
    }

    fn held(&self) -> Option<HeldHead> {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_held(&self, head: HeldHead) {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(head);
    }

    fn now(&self) -> u64 {
        unix_now()
    }

    fn keyset(&self) -> Vec<u8> {
        self.keyset
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| self.pins.keyset.clone())
    }

    fn set_keyset(&self, keyset: Vec<u8>) {
        *self
            .keyset
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(keyset);
    }
}

impl DirectoryLink {
    /// The route of a network that pins one, or none.
    pub fn new(
        relay_url: &str,
        relay_ipv4: Option<&[u8]>,
        pins: &[u8],
        tls: Arc<native::ClientConfig>,
    ) -> Option<Self> {
        let mut relay = Url::parse(relay_url)?;
        if let Some(ipv4) = relay_ipv4 {
            let octets: [u8; 4] = ipv4.try_into().ok()?;
            relay.address = Some(std::net::IpAddr::from(octets));
        }

        let pins = DirectoryPins::parse(pins).ok()?;
        let (key_id, gateway) = umbra_crypto::ohttp::parse_key_config(&pins.key_config).ok()?;
        LogKeySet::parse(&pins.keyset).ok()?;

        Some(DirectoryLink {
            route: DirectoryRoute {
                relay,
                key_id,
                gateway,
            },
            pins: Arc::new(pins),
            tls,
            held: Arc::default(),
            keyset: Arc::default(),
            search_keys: Arc::default(),
        })
    }

    /// The link for one call, from the head and the key set that the store
    /// holds.
    fn with_held(&self, held: Option<HeldHead>, keyset: Vec<u8>) -> Self {
        DirectoryLink {
            held: Arc::new(std::sync::Mutex::new(held)),
            keyset: Arc::new(std::sync::Mutex::new(Some(keyset))),
            ..self.clone()
        }
    }

    /// The key set that this link holds now.
    fn held_keyset(&self) -> Vec<u8> {
        LogChannel::keyset(self)
    }

    /// Sends one request and returns the body of a done answer.
    fn send(&self, kind: Kind, body: &[u8]) -> Result<Vec<u8>, FfiError> {
        Ok(reader::send(self, kind, body)?)
    }

    /// The search key of a label input, under a proof of work at the floor
    /// (`DIS-164`).
    fn search_key(&self, input: &[u8]) -> Result<[u8; 64], FfiError> {
        Ok(reader::search_key(self, input, &mut OsRng)?)
    }

    /// The search key of a label of this device or of an issuer: the held
    /// one, or one evaluation that the link then holds (`DIS-204`). A held
    /// key costs the directory no evaluation and this device no proof of
    /// work. The output of the VOPRF for one input under the pinned key does
    /// not change.
    fn held_search_key(&self, input: &[u8]) -> Result<[u8; 64], FfiError> {
        let held = self
            .search_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(input)
            .copied();
        if let Some(key) = held {
            return Ok(key);
        }

        let key = self.search_key(input)?;
        let mut keys = self
            .search_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if keys.len() >= SEARCH_KEYS_HELD {
            keys.clear();
        }
        keys.insert(input.to_vec(), key);
        Ok(key)
    }

    /// The newest entry of a label of this device under a fresh head, read
    /// under its held search key (`DIS-137`, `DIS-204`).
    fn find_own(&self, input: &[u8]) -> Result<Found, FfiError> {
        let search_key = self.held_search_key(input)?;
        let found = reader::find_under(self, &search_key)?;
        if found.degraded {
            return Err(FfiError::Stale);
        }

        Ok(found)
    }

    /// The lookup proof of a search key under the newest head, after the
    /// head verified under the pinned key set (`DIS-066`).
    fn lookup(
        &self,
        search_key: &[u8; 64],
    ) -> Result<(LookupProof, AcceptedHead, Option<Vec<u8>>), FfiError> {
        Ok(reader::lookup(self, search_key)?)
    }

    /// Verifies the head of an answer and holds it when it extends the held
    /// head, or gives none for a head whose proof names another epoch.
    fn accept_head(&self, bytes: &[u8]) -> Result<Option<AcceptedHead>, FfiError> {
        Ok(reader::accept_head(self, bytes)?)
    }

    /// The entry of one version of a label, verified under the log
    /// (`DIS-183`, `DIS-184`).
    fn version_entry(&self, search_key: &[u8; 64], version: u32) -> Result<Vec<u8>, FfiError> {
        Ok(reader::version_entry(self, search_key, version)?)
    }

    /// Whether the tree head of a contact at `tree_size` lies in the log
    /// that this device reads (`DIS-136`): the proof of consistency from that
    /// size to the newest head. None while the log is not that long here, or
    /// when an epoch closed between two answers.
    ///
    /// `held_size` is the size of the newest head that this device holds:
    /// a directory that refuses the proof for a size at or below it, or
    /// that serves a log below it, shows another view (`DIS-034`).
    fn holds_head(
        &self,
        tree_size: u64,
        root: &[u8; 32],
        held_size: u64,
    ) -> Result<Option<bool>, FfiError> {
        let reaches = held_size >= tree_size;
        let answer = match self.send(Kind::Head, &tree_size.to_be_bytes()) {
            Ok(answer) => answer,
            // A directory with no head yet answers NotFound, as one that
            // restarted does, and it shows no other view.
            Err(FfiError::NotFound) => return Ok(None),
            Err(FfiError::Stale | FfiError::Malformed) => {
                return Ok(reaches.then_some(false));
            }
            Err(other) => return Err(other),
        };

        let (bytes, proof) = dirclient::parse_head(&answer).map_err(|_| FfiError::Malformed)?;
        let Some(newest) = self.accept_head(&bytes)? else {
            return Ok(None);
        };
        if newest.tree_size < tree_size {
            return Ok(reaches.then_some(false));
        }
        if newest.tree_size == tree_size {
            return Ok(Some(newest.root == *root));
        }

        Ok(Some(
            umbra_core::discovery::logtree::verify_consistency(
                tree_size,
                root,
                newest.tree_size,
                &newest.root,
                &proof,
            )
            .is_ok(),
        ))
    }

    /// The takeover check of a hello to a handle (§9.9.2): a held key that
    /// differs from the resolved one is replaced in silence after a
    /// rotation, and a registration of another party warns (`DIS-078` to
    /// `DIS-085`).
    fn assess_handle(
        &self,
        input: &[u8],
        search_key: &[u8; 64],
        held: &Version,
        resolved: &Version,
    ) -> Result<Takeover, FfiError> {
        if held.hk_pub == resolved.hk_pub {
            return Ok(Takeover::Silent);
        }

        // DIS-061: the log does not give an older version than it gave.
        if resolved.version <= held.version {
            return Err(FfiError::Stale);
        }

        // DIS-080: a long history warns with no fetch.
        if resolved.version.saturating_sub(held.version) > HANDLE_HISTORY_MAX {
            return Ok(Takeover::Warn);
        }

        let mut between = Vec::new();
        for version in held.version.saturating_add(1)..resolved.version {
            let bytes = self.version_entry(search_key, version)?;
            let entry = DirectoryEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
            if entry.handle != input || entry.version != version {
                return Err(FfiError::Unverified);
            }

            between.push(Version {
                version,
                hk_pub: entry.hk_pub,
            });
        }
        between.push(*resolved);
        assess(held, &between).map_err(|_| FfiError::Unverified)
    }

    fn vrf_key(&self) -> Result<vrf::PublicKey, FfiError> {
        Ok(reader::vrf_key(self)?)
    }

    /// The newest entry of a label input and its search key. A head past its
    /// freshness gives the degraded read of `DIS-067`, which `Found` marks.
    fn find_read(&self, input: &[u8]) -> Result<(Found, [u8; 64]), FfiError> {
        Ok(reader::find_keyed(self, input, &mut OsRng)?)
    }

    /// One first-party token of this epoch, under a proof of work
    /// (`ABU-076`). The issuer key comes from the log (`ABU-002`).
    pub fn token(&self) -> Result<Vec<u8>, FfiError> {
        let epoch = epoch_number(unix_now());
        let input = issuer_label_input(TYPE_FIRST_PARTY, epoch);
        let search_key = self.held_search_key(&input)?;
        let (proof, head, _) = self.lookup(&search_key)?;

        let mut keys = IssuerKeys::default();
        keys.accept_from_log(
            TYPE_FIRST_PARTY,
            epoch,
            &proof,
            &search_key,
            &self.vrf_key()?,
            &head,
        )
        .map_err(|_| FfiError::Unverified)?;

        let issuer_pk: [u8; 32] = keys
            .key(TYPE_FIRST_PARTY, epoch)
            .and_then(|key| key.try_into().ok())
            .ok_or(FfiError::Unverified)?;

        let (state, body) = dirclient::issue_request(epoch, &issuer_pk, 1, &mut OsRng)
            .map_err(|_| FfiError::Malformed)?;
        let issued = self.send(Kind::Issue, &body)?;
        let tokens = dirclient::issue_finish(&state, &issued, &issuer_pk)
            .map_err(|_| FfiError::Unverified)?;

        let token = tokens.first().ok_or(FfiError::Unverified)?;
        dirclient::token_bytes(token).map_err(|_| FfiError::Malformed)
    }

    /// Registers a label under `token` (`DIS-101`), with the lease of a
    /// timed link (`DIS-172`). The registration challenge proves `key`
    /// (`DIS-197`), and it names the version of the entry that `entry_of`
    /// writes. `keep` runs before the registration leaves, and a fault of
    /// it sends nothing (`DIS-205`). The result is that version, or the
    /// fault with what it left at the directory.
    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        token: &[u8],
        input: &[u8],
        name: &[u8],
        key: &KeyPair,
        entry_of: impl FnOnce(u32) -> Result<Vec<u8>, FfiError>,
        lease: Option<u32>,
        keep: impl FnOnce(u32) -> Result<(), FfiError>,
    ) -> Result<u32, (WriteFault, FfiError)> {
        // A fault before the registration request leaves registers nothing.
        let (body, version_new) = (|| {
            let challenge = self.register_challenge(input, key, token)?;
            let (challenge, purpose) =
                dirclient::parse_register_challenge(&challenge).map_err(|_| FfiError::Malformed)?;
            let Purpose::Write { version_new } = purpose else {
                return Err(FfiError::Malformed);
            };

            let entry = entry_of(version_new)?;
            let ans = answer(purpose, key, name, &challenge, Some(&entry))
                .map_err(|_| FfiError::Unverified)?;
            let body = dirclient::register_body(token, input, &entry, &ans, lease)
                .map_err(|_| FfiError::Malformed)?;

            keep(version_new)?;
            Ok((body, version_new))
        })()
        .map_err(|error| (WriteFault::Refused, error))?;

        match self.send(Kind::Register, &body) {
            Ok(_) => Ok(version_new),
            // The directory answered, and its answer names a refusal.
            Err(
                error @ (FfiError::Busy
                | FfiError::Stale
                | FfiError::NotFound
                | FfiError::Unverified),
            ) => Err((WriteFault::Refused, error)),
            // A link that ended, or an answer that does not parse.
            Err(error) => Err((WriteFault::Unknown, error)),
        }
    }

    /// The registration challenge of `key` for a label, paid with `token`
    /// (`DIS-203`). A directory of an earlier build reads no token in it, and
    /// the registration spends the token there.
    fn register_challenge(
        &self,
        input: &[u8],
        key: &KeyPair,
        token: &[u8],
    ) -> Result<Vec<u8>, FfiError> {
        let key = key.public().to_bytes();
        let paid = dirclient::register_challenge_body(input, &key, Some(token))
            .map_err(|_| FfiError::Malformed)?;
        match self.send(Kind::Challenge, &paid) {
            Err(FfiError::Malformed) => {
                let body = dirclient::register_challenge_body(input, &key, None)
                    .map_err(|_| FfiError::Malformed)?;
                self.send(Kind::Challenge, &body)
            }
            answered => answered,
        }
    }

    /// Writes the next version of a label under the key of the version
    /// that `version` names (`DIS-093`), with what a fault left at the
    /// directory. A tombstone entry retires the label (`DIS-171`).
    fn write_staged(
        &self,
        input: &[u8],
        name: &[u8],
        key: &KeyPair,
        version: u32,
        entry: &[u8],
    ) -> Result<(), (WriteFault, FfiError)> {
        // A fault before the write request left sends no version.
        let body = (|| {
            let body = dirclient::challenge_body(false, input).map_err(|_| FfiError::Malformed)?;
            let challenge = self.send(Kind::Challenge, &body)?;
            let (challenge, purpose) =
                dirclient::parse_challenge(&challenge, version).map_err(|_| FfiError::Malformed)?;
            let ans = answer(purpose, key, name, &challenge, Some(entry))
                .map_err(|_| FfiError::Unverified)?;
            dirclient::write_body(input, &ans, entry).map_err(|_| FfiError::Malformed)
        })()
        .map_err(|error| (WriteFault::Refused, error))?;

        match self.send(Kind::Write, &body) {
            Ok(_) => Ok(()),
            // The directory answered, and its answer names a refusal.
            Err(
                error @ (FfiError::Busy
                | FfiError::Stale
                | FfiError::NotFound
                | FfiError::Unverified),
            ) => Err((WriteFault::Refused, error)),
            // A link that ended, or an answer that does not parse.
            Err(error) => Err((WriteFault::Unknown, error)),
        }
    }

    /// The key of the cross-relay issuer of `epoch` from the log: version
    /// 0 of its label, of that type and that epoch (`ABU-099` to `ABU-101`).
    pub fn cross_relay_key(&self, epoch: u32) -> Result<PublicKey2048, FfiError> {
        Ok(reader::cross_relay_key(self, epoch, &mut OsRng)?)
    }

    /// `count` cross-relay tokens of `epoch`, each paid with a proof of work
    /// and each verified under `key` (`ABU-111`, `ABU-112`).
    pub fn cross_relay_tokens(
        &self,
        epoch: u32,
        key: &PublicKey2048,
        count: usize,
    ) -> Result<Vec<Vec<u8>>, FfiError> {
        let (state, body) = dirclient::cross_relay_issue_request(epoch, key, count, &mut OsRng)
            .map_err(|_| FfiError::Malformed)?;
        let answer = self.send(Kind::Issue, &body)?;
        let tokens = dirclient::cross_relay_issue_finish(&state, &answer, key)
            .map_err(|_| FfiError::Unverified)?;

        tokens
            .iter()
            .map(|token| dirclient::token_bytes(token).map_err(|_| FfiError::Malformed))
            .collect()
    }

    /// Writes the sealed profile blob of a label under the blob challenge,
    /// whose answer binds the blob (`DIS-175`).
    pub fn put_blob(
        &self,
        input: &[u8],
        name: &[u8],
        key: &KeyPair,
        blob: &[u8],
    ) -> Result<(), FfiError> {
        let body = dirclient::blob_challenge_body(input).map_err(|_| FfiError::Malformed)?;
        let challenge = self.send(Kind::Challenge, &body)?;
        let ans = answer(Purpose::Blob, key, name, &challenge, Some(blob))
            .map_err(|_| FfiError::Unverified)?;
        let body = dirclient::blob_body(input, &ans, blob).map_err(|_| FfiError::Malformed)?;
        self.send(Kind::Blob, &body).map(|_| ())
    }

    /// Renews the lease of a label under its key (`DIS-040`).
    pub fn renew(&self, input: &[u8], name: &[u8], key: &KeyPair) -> Result<(), FfiError> {
        let body = dirclient::challenge_body(true, input).map_err(|_| FfiError::Malformed)?;
        let challenge = self.send(Kind::Challenge, &body)?;
        let (challenge, purpose) =
            dirclient::parse_challenge(&challenge, 0).map_err(|_| FfiError::Malformed)?;
        if !matches!(purpose, Purpose::Renew { .. }) {
            return Err(FfiError::Malformed);
        }

        let ans = answer(purpose, key, name, &challenge, None).map_err(|_| FfiError::Unverified)?;
        let body = dirclient::renew_body(input, &ans).map_err(|_| FfiError::Malformed)?;
        self.send(Kind::Renew, &body).map(|_| ())
    }
}

/// What a profile link shows before a request (§9.3.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ContactPreview {
    /// The canonical handle.
    pub handle: String,
    /// The name from the profile blob, or empty.
    pub name: String,
    /// The welcome text from the profile blob, or empty.
    pub welcome: String,
    /// The JPEG picture from the profile blob, or empty.
    pub picture: Vec<u8>,
    /// Whether the read is the degraded read of Part 9 §9.5.2: no head that
    /// the log gave passes its freshness, thus the view shows the preview
    /// as unverified (`DIS-068`).
    pub unverified: bool,
}

/// A reusable link of this device (Part 4 §4.3.2), as a view shows it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PublicLink {
    /// The identifier of the entry.
    pub id: Vec<u8>,
    /// The link, `umbra://p/` and the address.
    pub link: String,
    /// The time of the registration, in Unix seconds.
    pub created_at: u64,
    /// The end of a timed link, or 0 for none.
    pub expires_at: u64,
}

/// A contact request that waits for the user (Part 9 §9.6).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ContactRequestInfo {
    /// The identifier of the request.
    pub id: Vec<u8>,
    /// The name that the sender shows, or an empty one. No party checks it.
    pub name: String,
    /// The link or the handle that the request came through.
    pub via: String,
    /// The time of the arrival, in Unix seconds.
    pub received_at: u64,
    /// The note that the sender wrote with the request, or an empty one.
    pub note: String,
    /// The JPEG picture of the sender, or an empty one.
    pub picture: Vec<u8>,
}

/// What a write that failed left at the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteFault {
    /// The directory holds no new version for certain.
    Refused,
    /// The write left, and no answer says whether the directory took it.
    Unknown,
}

/// How the newest version that the log shows stands to the entry that this
/// device holds (`DIS-137`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// The log shows the version of this device, with its key and its queue.
    Own,
    /// The log shows a version below the one of this device. The write of
    /// this device waits for the next epoch (`DIS-166`), or it did not
    /// reach the directory.
    Staged,
    /// The log shows a version that this device did not write (`DIS-138`).
    Foreign,
}

/// The standing of an entry at version `held` when the log shows `shown`.
/// The store takes a new version before the directory does. Thus a version
/// of the log above the held one is never a write of this device.
fn standing(held: u32, shown: u32, is_same_key: bool, is_same_queue: bool) -> Standing {
    match shown.cmp(&held) {
        core::cmp::Ordering::Less => Standing::Staged,
        core::cmp::Ordering::Greater => Standing::Foreign,
        core::cmp::Ordering::Equal if is_same_key && is_same_queue => Standing::Own,
        core::cmp::Ordering::Equal => Standing::Foreign,
    }
}

/// Which key of this device signs the write of the held version again, when
/// the log shows the version before it under `shown`. After a move of the
/// queue, the key of the held rotation signs. After a rotation of the
/// handle key, the key before it signs. No key of the two means a version
/// that this device does not write over (`DIS-139`).
fn signer_of<'a>(
    shown: &[u8; ENTRY_PK_LEN],
    held: &'a KeyPair,
    before: Option<&'a KeyPair>,
) -> Option<&'a KeyPair> {
    if held.public().to_bytes() == *shown {
        return Some(held);
    }
    before.filter(|key| key.public().to_bytes() == *shown)
}

/// The time after which a version that the log does not show did not reach
/// the directory. A staged write shows at the first head after it
/// (`DIS-166`), and an epoch closes at each `DIRECTORY_EPOCH`.
const WRITE_SETTLE: u64 = 2 * DIRECTORY_EPOCH;

/// What the upkeep does with an entry after a write of it that waits for
/// its answer settled (`DIS-205`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// The upkeep of the entry ends for this run.
    Done,
    /// The log still shows the held version: the tombstone goes again.
    Retire,
    /// The upkeep of the entry goes on.
    Upkeep,
}

/// The version of the log that the upkeep read for an entry.
struct Shown {
    version: u32,
    key: [u8; ENTRY_PK_LEN],
}

/// The bytes of the version of an entry that the store holds, under `key`.
fn entry_bytes(entry: &Published, key: &KeyPair) -> Result<Vec<u8>, FfiError> {
    let rendezvous = QueueAddress::parse(&entry.rendezvous).map_err(|_| FfiError::Integrity)?;
    Ok(match entry.kind {
        EntryKind::Address => {
            let mut out = vec![0u8; ADDRESS_ENTRY_LEN];
            AddressEntry {
                address: entry
                    .name
                    .as_slice()
                    .try_into()
                    .map_err(|_| FfiError::Integrity)?,
                address_pk: key.public().to_bytes(),
                rendezvous: Some(rendezvous),
                version: entry.version,
            }
            .encode(&mut out)
            .map_err(|_| FfiError::Malformed)?;
            out
        }
        EntryKind::Handle => {
            let next = DirectoryEntry {
                handle: entry.name.clone(),
                hk_pub: key.public().to_bytes(),
                rendezvous: Some(rendezvous),
                version: entry.version,
            };
            let mut out = vec![0u8; next.len()];
            let used = next.encode(&mut out).map_err(|_| FfiError::Malformed)?;
            out.truncate(used);
            out
        }
    })
}

/// The tokens below which the upkeep asks the issuer for a batch.
const TOKEN_LOW: usize = 2;
/// The tokens of one batch. Each one costs a proof of work at
/// `POW_EFFORT_MAX` on this device.
const TOKEN_BATCH: usize = 4;

/// The wait for the relay to make a rendezvous queue.
const QUEUE_WAIT: Duration = Duration::from_secs(60);
/// The interval of the lease renewals of Part 9 §9.9.1. The lease is
/// `HANDLE_LEASE`, thus a renewal in each interval keeps it far from its end.
const RENEW_EVERY: u64 = 30 * 86_400;
/// The tries of a new discriminator when a handle is taken.
const CLAIM_TRIES: usize = 4;

fn id16(bytes: &[u8]) -> Result<[u8; 16], FfiError> {
    bytes.try_into().map_err(|_| FfiError::Malformed)
}

fn via_text(entry: &Published) -> String {
    match entry.kind {
        EntryKind::Address => entry
            .name
            .as_slice()
            .try_into()
            .map(|address: [u8; 20]| address::link_string(&address))
            .unwrap_or_default(),
        EntryKind::Handle => String::from_utf8_lossy(&entry.name).into_owned(),
    }
}

/// The link of one call, which keeps the newest head that the call
/// accepted in the store when it ends (`DIS-063`).
struct HeldLink<'a> {
    handle: &'a Handle,
    link: DirectoryLink,
    before: Option<HeldHead>,
    keyset: Vec<u8>,
}

impl core::ops::Deref for HeldLink<'_> {
    type Target = DirectoryLink;

    fn deref(&self) -> &DirectoryLink {
        &self.link
    }
}

impl Drop for HeldLink<'_> {
    fn drop(&mut self) {
        // DIS-199: a key set that a signed rotation gave stays for the next
        // call.
        let keyset = self.link.held_keyset();
        if keyset != self.keyset {
            let _ = locked(&self.handle.inner)
                .client
                .keep_log_keyset(&keyset, &mut OsRng);
        }

        let Some((size, root, timestamp)) = self.link.held() else {
            return;
        };
        if self.before.is_some_and(|(held, _, _)| held >= size) {
            return;
        }

        let _ = locked(&self.handle.inner).client.keep_head(
            size,
            &root,
            timestamp,
            unix_now(),
            &mut OsRng,
        );
    }
}

impl Handle {
    /// The route to the directory, for a device that owns its channels.
    fn directory_link(&self) -> Result<HeldLink<'_>, FfiError> {
        let inner = locked(&self.inner);

        // DEV-287: a linked device makes no contact of its own.
        if !inner.owns_channels {
            return Err(FfiError::NotFound);
        }

        let before = inner.client.newest_head()?;
        let directory = inner.directory.as_ref().ok_or(FfiError::Offline)?;
        let keyset = inner.client.log_keyset(&directory.pins.keyset)?;
        let link = directory.with_held(before, keyset.clone());

        Ok(HeldLink {
            handle: self,
            link,
            before,
            keyset,
        })
    }

    /// Makes a rendezvous queue and waits for its address.
    fn new_rendezvous(&self) -> Result<([u8; 32], Vec<u8>), FfiError> {
        let tag = {
            let mut inner = locked(&self.inner);
            let tag = inner.next_rendezvous_tag;
            inner.next_rendezvous_tag = tag.wrapping_add(1);
            inner
                .bridge
                .as_ref()
                .ok_or(FfiError::Offline)?
                .make_rendezvous_queue(tag)?;
            tag
        };

        let start = Instant::now();
        loop {
            let mut inner = locked(&self.inner);

            // A lock ends the wait at once. The caller can hold keys of the
            // store, and the runtime stops at a lock.
            if !inner.client.is_unlocked() {
                return Err(FfiError::Locked);
            }

            if let Some(made) = inner.rendezvous_ready.remove(&tag) {
                return Ok(made);
            }
            if inner.rendezvous_refused.remove(&tag) {
                return Err(FfiError::Busy);
            }

            drop(inner);
            if start.elapsed() > QUEUE_WAIT {
                return Err(FfiError::Offline);
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn end_rendezvous(&self, queue: [u8; 32]) {
        if let Some(bridge) = locked(&self.inner).bridge.as_ref() {
            let _ = bridge.end_rendezvous_queue(queue);
        }
    }

    /// Registers an entry on a new rendezvous queue, and keeps it. The
    /// store takes the entry with its mark before the registration leaves,
    /// thus a label that the directory takes always has its row, and a lock
    /// before that point sends nothing (`DIS-205`).
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        link: &DirectoryLink,
        kind: EntryKind,
        index: u32,
        label: Vec<u8>,
        name: Vec<u8>,
        entry_of: impl FnOnce(&KeyPair, QueueAddress, u32) -> Result<Vec<u8>, FfiError>,
        expires_at: u64,
    ) -> Result<Published, FfiError> {
        // DIS-172: the directory ends a timed link at its end, also while
        // this device is off.
        let lease = (expires_at != 0).then(|| {
            let seconds = expires_at
                .saturating_sub(unix_now())
                .clamp(LEASE_MIN, HANDLE_LEASE);
            u32::try_from(seconds).unwrap_or(u32::MAX)
        });

        let mut id = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| FfiError::Storage)?;

        let (queue, rendezvous) = self.new_rendezvous()?;
        let now = unix_now();
        let row = |version: u32, pending: Option<PendingWrite>| Published {
            id,
            kind,
            index,
            rotation: 0,
            label: label.clone(),
            name: name.clone(),
            queue,
            rendezvous: rendezvous.clone(),
            version,
            created_at: now,
            expires_at,
            renewed_at: now,
            queue_since: now,
            previous: None,
            foreign: false,
            pending,
        };

        let registered = (|| {
            // The proof of work of the token takes seconds. The entry key
            // leaves the store after it, thus a lock in that time finds no
            // key in memory, and the challenge lives through no proof.
            let token = link.token().map_err(|error| (WriteFault::Refused, error))?;
            let key = locked(&self.inner)
                .client
                .entry_key(kind, index, 0)
                .map_err(|error| (WriteFault::Refused, FfiError::from(error)))?;
            let address = QueueAddress::parse(&rendezvous)
                .map_err(|_| (WriteFault::Refused, FfiError::Malformed))?;
            let keep = |version: u32| -> Result<(), FfiError> {
                let entry = row(version, Some(PendingWrite::Register));
                Ok(locked(&self.inner)
                    .client
                    .put_published(&entry, &mut OsRng)?)
            };
            link.register(
                &token,
                &label,
                &name,
                &key,
                |version| entry_of(&key, address, version),
                lease,
                keep,
            )
        })();

        match registered {
            Ok(version) => {
                // A lock here leaves the mark, and the upkeep reads the log.
                let entry = row(version, None);
                let mut inner = locked(&self.inner);
                if kind == EntryKind::Handle {
                    inner.client.set_profile_blob_due(true, &mut OsRng)?;
                }
                inner.client.put_published(&entry, &mut OsRng)?;
                Ok(entry)
            }
            // The directory holds no version of this device: the row, when
            // the store took it, goes with the queue.
            Err((WriteFault::Refused, error)) => {
                let _ = locked(&self.inner).client.drop_published(&id, &mut OsRng);
                self.end_rendezvous(queue);
                Err(error)
            }
            // The registration left with no answer: the row keeps its mark
            // and its queue for the upkeep.
            Err((WriteFault::Unknown, error)) => Err(error),
        }
    }

    /// Proves each tree head that a contact gossiped and that no held head
    /// names against the log, and a failed proof is a split view
    /// (`DIS-034`, `DIS-136`).
    fn check_gossiped_heads(&self, link: &DirectoryLink) -> Result<(), FfiError> {
        let checks = locked(&self.inner).client.head_checks()?;
        for check in checks {
            let held_size = locked(&self.inner)
                .client
                .held_heads()?
                .iter()
                .map(|(size, _, _)| *size)
                .max()
                .unwrap_or(0);
            if let Some(holds) = link.holds_head(check.tree_size, &check.root, held_size)? {
                locked(&self.inner)
                    .client
                    .head_check_done(&check, !holds, &mut OsRng)?;
            }
        }
        Ok(())
    }

    /// Keeps the key of the cross-relay issuer of this epoch and of the
    /// next one, thus a token in a hello verifies here, and keeps
    /// `TOKEN_LOW` tokens of this epoch for the hellos of this device.
    fn keep_cross_relay_tokens(&self, link: &DirectoryLink, now: u64) -> Result<(), FfiError> {
        self.keep_cross_relay_keys(link, now)?;

        let epoch = epoch_number(now);
        if locked(&self.inner).client.token_count(epoch)? >= TOKEN_LOW {
            return Ok(());
        }

        self.fetch_tokens(link, epoch, TOKEN_BATCH)
    }

    fn fetch_tokens(&self, link: &DirectoryLink, epoch: u32, count: usize) -> Result<(), FfiError> {
        let key = locked(&self.inner)
            .client
            .cross_relay_key(epoch)?
            .ok_or(FfiError::NotFound)?;
        let tokens = link.cross_relay_tokens(epoch, &key, count)?;
        Ok(locked(&self.inner)
            .client
            .put_tokens(epoch, &tokens, &mut OsRng)?)
    }

    fn keep_cross_relay_keys(&self, link: &DirectoryLink, now: u64) -> Result<(), FfiError> {
        let epoch = epoch_number(now);
        for held in [epoch, epoch.saturating_add(1)] {
            if locked(&self.inner).client.cross_relay_key(held)?.is_none() {
                // The next key enters the log before its epoch (ABU-098).
                if let Ok(key) = link.cross_relay_key(held) {
                    locked(&self.inner).client.put_cross_relay_key(
                        held,
                        key.modulus(),
                        &mut OsRng,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Writes the profile blob of the handle when it waits: the name and
    /// the welcome text, sealed under the key of the fragment of its link
    /// (`DIS-141`, `DIS-176`). A device with no handle writes nothing.
    fn publish_profile_blob(&self, link: &DirectoryLink) -> Result<(), FfiError> {
        let (entry, key, blob) = {
            let mut inner = locked(&self.inner);
            if !inner.client.profile_blob_due()? {
                return Ok(());
            }
            let Some(entry) = inner
                .client
                .published()?
                .into_iter()
                .find(|entry| entry.kind == EntryKind::Handle)
            else {
                return Ok(());
            };

            let handle = DirHandle::parse(
                core::str::from_utf8(&entry.name).map_err(|_| FfiError::Integrity)?,
                &username_case_mapped,
            )
            .map_err(|_| FfiError::Integrity)?;

            let name = inner.client.profile_name()?;
            let welcome = inner.client.welcome()?;
            let picture = inner.client.profile_picture()?;
            let plain = ProfilePlain {
                name: &name,
                welcome: &welcome,
                picture: &picture,
            }
            .encode()
            .map_err(|_| FfiError::Malformed)?;

            let fragment = inner.client.handle_fragment(&mut OsRng)?;
            let mut nonce = [0u8; 24];
            OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| FfiError::Storage)?;
            let blob = handle
                .seal_blob(&fragment, nonce, &plain)
                .map_err(|_| FfiError::Malformed)?;

            let key = inner
                .client
                .entry_key(EntryKind::Handle, entry.index, entry.rotation)?;
            (entry, key, blob)
        };

        link.put_blob(&entry.label, &entry.name, &key, &blob)?;
        Ok(locked(&self.inner)
            .client
            .set_profile_blob_due(false, &mut OsRng)?)
    }

    /// Writes the tombstone of an entry (`DIS-171`) and ends its queue. The
    /// store takes the mark of the tombstone before the write leaves. Thus
    /// a tombstone whose answer did not come shows at the upkeep as a
    /// version of this device, and not as a takeover (`DIS-205`).
    fn retire(&self, link: &DirectoryLink, entry: &Published) -> Result<(), FfiError> {
        let key = locked(&self.inner)
            .client
            .entry_key(entry.kind, entry.index, entry.rotation)?;
        let version = entry.version.checked_add(1).ok_or(FfiError::TooLong)?;

        let tombstone = match entry.kind {
            EntryKind::Address => {
                let address: [u8; 20] = entry
                    .name
                    .as_slice()
                    .try_into()
                    .map_err(|_| FfiError::Integrity)?;
                let mut out = vec![0u8; ADDRESS_ENTRY_LEN];
                AddressEntry {
                    address,
                    address_pk: [0; ENTRY_PK_LEN],
                    rendezvous: None,
                    version,
                }
                .encode(&mut out)
                .map_err(|_| FfiError::Malformed)?;
                out
            }
            EntryKind::Handle => {
                let tomb = DirectoryEntry::tombstone(entry.name.clone(), version);
                let mut out = vec![0u8; tomb.len()];
                let used = tomb.encode(&mut out).map_err(|_| FfiError::Malformed)?;
                out.truncate(used);
                out
            }
        };

        let marked = Published {
            pending: Some(PendingWrite::Retire),
            ..entry.clone()
        };
        if entry.pending != marked.pending {
            locked(&self.inner)
                .client
                .put_published(&marked, &mut OsRng)?;
        }

        match link.write_staged(&entry.label, &entry.name, &key, entry.version, &tombstone) {
            // A label that the directory tombstoned already, or holds no
            // more, is retired.
            Ok(()) | Err((_, FfiError::NotFound | FfiError::Stale)) => self.retired(entry),
            // The log holds the version before for certain, thus the store
            // goes back to the entry as it stood.
            Err((WriteFault::Refused, error)) => {
                let _ = locked(&self.inner).client.put_published(entry, &mut OsRng);
                Err(error)
            }
            // The directory may hold the tombstone: the mark stays, and the
            // upkeep reads the log.
            Err((WriteFault::Unknown, error)) => Err(error),
        }
    }

    /// Ends an entry that the directory retired, and drops it. The
    /// tombstone of a handle took its blob (`DIS-178`), and a later handle
    /// takes a new link.
    fn retired(&self, entry: &Published) -> Result<(), FfiError> {
        self.end_entry(entry)?;
        if entry.kind == EntryKind::Handle {
            let mut inner = locked(&self.inner);
            inner.client.drop_handle_fragment()?;
            inner.client.set_profile_blob_due(false, &mut OsRng)?;
        }
        Ok(())
    }

    /// Settles a write of an entry that left with no answer against the
    /// log (`DIS-205`). A registration that the log shows as this device
    /// wrote it holds. One that the log does not show after `WRITE_SETTLE`
    /// did not reach the directory, and its entry goes. A tombstone at the
    /// version after the held one is the retirement of this device. A log
    /// that still shows the held version takes the tombstone again.
    fn settle_pending(
        &self,
        entry: &Published,
        standing: Standing,
        shown: Option<&Shown>,
        now: u64,
    ) -> Settled {
        match entry.pending {
            Some(PendingWrite::Register) => {
                if standing == Standing::Own {
                    let held = Published {
                        pending: None,
                        ..entry.clone()
                    };
                    let mut inner = locked(&self.inner);

                    // §9.3.1: the profile of a new handle goes beside it,
                    // also when the answer to its registration did not come.
                    let is_due = entry.kind != EntryKind::Handle
                        || inner.client.set_profile_blob_due(true, &mut OsRng).is_ok();
                    if is_due {
                        let _ = inner.client.put_published(&held, &mut OsRng);
                    }
                } else if now.saturating_sub(entry.created_at) >= WRITE_SETTLE {
                    let _ = self.end_entry(entry);
                }
                Settled::Done
            }
            Some(PendingWrite::Retire) => {
                let is_own_tombstone = shown.is_some_and(|shown| {
                    entry.version.checked_add(1) == Some(shown.version)
                        && shown.key == [0; ENTRY_PK_LEN]
                });
                if is_own_tombstone {
                    let _ = self.retired(entry);
                    Settled::Done
                } else if standing == Standing::Own {
                    Settled::Retire
                } else {
                    // Another version is no write of this device (DIS-138).
                    Settled::Upkeep
                }
            }
            None => Settled::Upkeep,
        }
    }

    /// Ends the queues of an entry that the directory holds no more, and
    /// drops it.
    fn end_entry(&self, entry: &Published) -> Result<(), FfiError> {
        self.end_rendezvous(entry.queue);
        if let Some((previous, _)) = entry.previous {
            self.end_rendezvous(previous);
        }

        let mut inner = locked(&self.inner);

        // NTF-043: the handle of the queue goes with it.
        let _ = inner.client.unbind_queue(&entry.queue, &mut OsRng);
        if let Some((previous, _)) = entry.previous {
            let _ = inner.client.unbind_queue(&previous, &mut OsRng);
        }
        inner.client.drop_published(&entry.id, &mut OsRng)?;
        Ok(())
    }

    /// Moves an entry to a new rendezvous queue (`DIS-133`): the new entry
    /// version goes to the directory under the key of the entry, and the
    /// queue before it stays for `ROTATE_GRACE` (`DIS-134`).
    fn rotate_queue(
        &self,
        link: &DirectoryLink,
        entry: &Published,
        now: u64,
    ) -> Result<(), FfiError> {
        let version = entry.version.checked_add(1).ok_or(FfiError::TooLong)?;
        let key = locked(&self.inner)
            .client
            .entry_key(entry.kind, entry.index, entry.rotation)?;

        let (queue, rendezvous) = self.new_rendezvous()?;
        let rotated = Published {
            version,
            queue,
            rendezvous,
            queue_since: now,
            previous: Some((entry.queue, now.saturating_add(ROTATE_GRACE))),
            pending: None,
            ..entry.clone()
        };

        self.write_version(link, entry, &rotated, &key, &key, entry.version)
    }

    /// Moves an entry from `before` to `after`, its next version on a new
    /// queue. The store takes `after` first, and the write under `signer`
    /// over the version `over` of the log follows. A lock or the end of the
    /// process between the two leaves the store one version above the log.
    /// The upkeep reads that as a write that waits, and it sends again
    /// (`Handle::write_again`). The other order would leave the log above
    /// the store. The device would then call its own version a takeover
    /// (`DIS-138`). The next start would end the new queue, since no entry
    /// of the store names it.
    ///
    /// Neither write of the store touches an earlier identity root
    /// (`DEV-306`). The key of `before` signs this write, and it signs the
    /// write again after a fault. Thus its root stays until the log shows
    /// `after` (`Client::confirm_published`). A refusal thus puts back the
    /// exact state before the call.
    fn write_version(
        &self,
        link: &DirectoryLink,
        before: &Published,
        after: &Published,
        signer: &KeyPair,
        key: &KeyPair,
        over: u32,
    ) -> Result<(), FfiError> {
        let kept = entry_bytes(after, key).and_then(|bytes| {
            locked(&self.inner)
                .client
                .put_published(after, &mut OsRng)?;
            Ok(bytes)
        });
        let bytes = match kept {
            Ok(bytes) => bytes,
            Err(error) => {
                self.end_rendezvous(after.queue);
                return Err(error);
            }
        };

        match link.write_staged(&before.label, &before.name, signer, over, &bytes) {
            Ok(()) => Ok(()),
            // The log holds the version before for certain, thus the store
            // goes back to it. A store that does not go back, at a lock,
            // holds a write that waits, and the upkeep sends it again.
            Err((WriteFault::Refused, error)) => {
                let is_back = locked(&self.inner)
                    .client
                    .put_published(before, &mut OsRng)
                    .is_ok();
                if is_back {
                    self.end_rendezvous(after.queue);
                }
                Err(error)
            }
            // The directory may hold the version: the store keeps it, and
            // the upkeep reads the log.
            Err((WriteFault::Unknown, error)) => Err(error),
        }
    }

    /// Sends the write of the held version of an entry again, when the log
    /// still shows the version before it after `WRITE_SETTLE`. The write
    /// did not reach the directory. A lock, a fault of the link, or the end
    /// of the process came first. The key of the shown version signs, and a
    /// version under no key of this device takes no write (`DIS-139`).
    fn write_again(
        &self,
        link: &DirectoryLink,
        entry: &mut Published,
        shown: &Shown,
        now: u64,
    ) -> Result<(), FfiError> {
        if shown.version.checked_add(1) != Some(entry.version) {
            return Ok(());
        }

        let (key, before) = {
            let inner = locked(&self.inner);
            let key = inner
                .client
                .entry_key(entry.kind, entry.index, entry.rotation)?;
            let before = match (entry.kind, entry.rotation.checked_sub(1)) {
                (EntryKind::Handle, Some(rotation)) => {
                    Some(inner.client.entry_key(entry.kind, entry.index, rotation)?)
                }
                _ => None,
            };
            (key, before)
        };
        let Some(signer) = signer_of(&shown.key, &key, before.as_ref()) else {
            return Ok(());
        };

        let bytes = entry_bytes(entry, &key)?;
        match link.write_staged(&entry.label, &entry.name, signer, shown.version, &bytes) {
            // The next look waits for the epoch of this write.
            Ok(()) | Err((WriteFault::Unknown, _)) => {
                entry.queue_since = now;
                locked(&self.inner)
                    .client
                    .put_published(entry, &mut OsRng)?;
                Ok(())
            }
            // A write of this epoch waits already, or the log moved: the
            // next upkeep reads it.
            Err((WriteFault::Refused, error)) => Err(error),
        }
    }

    /// Finds the key of a handle that a restore holds at a stale rotation
    /// (Part 4 `IDN-109`, `IDN-110`): each `r` from the held one to it plus
    /// `HANDLE_KEY_LOOKAHEAD` against the newest `HK_pub` of the entry
    /// (`IDN-118`). The first match sets `r` (`IDN-111`), and a new version
    /// under that key names a rendezvous queue that this device holds,
    /// since the queue of the newest version came after the backup. A
    /// tombstone and no match give false, and the entry shows as held by
    /// another party (`IDN-112`).
    fn resync_handle(
        &self,
        link: &DirectoryLink,
        entry: &mut Published,
        now: u64,
    ) -> Result<bool, FfiError> {
        // DIS-138: only a handle of a restore looks for its key; on any
        // other device a newer version is another writer.
        if !locked(&self.inner).client.awaits_resync(&entry.id)? {
            return Ok(false);
        }

        let found = link.find_own(&entry.label)?;

        // A look that ends for certain ends the look of the restore; one
        // that a fault of the network ended goes again at the next upkeep.
        let done = |this: &Self| {
            let _ = locked(&this.inner)
                .client
                .resync_done(&entry.id, &mut OsRng);
        };
        let (Some(bytes), Some(version)) = (found.entry, found.version) else {
            done(self);
            return Ok(false);
        };
        let Ok(shown) = DirectoryEntry::parse(&bytes) else {
            done(self);
            return Ok(false);
        };

        let last = entry
            .rotation
            .saturating_add(umbra_core::identity::HANDLE_KEY_LOOKAHEAD);
        let mut matched = None;
        for rotation in entry.rotation..=last {
            let key =
                locked(&self.inner)
                    .client
                    .entry_key(EntryKind::Handle, entry.index, rotation)?;
            if key.public().to_bytes() == shown.hk_pub {
                matched = Some((rotation, key));
                break;
            }
        }
        let Some((rotation, key)) = matched else {
            done(self);
            return Ok(false);
        };

        let next_version = version.checked_add(1).ok_or(FfiError::TooLong)?;
        let (queue, rendezvous) = self.new_rendezvous()?;
        let found = Published {
            rotation,
            version: next_version,
            queue,
            rendezvous,
            queue_since: now,
            previous: None,
            pending: None,
            ..entry.clone()
        };

        self.write_version(link, entry, &found, &key, &key, version)?;
        entry.rotation = found.rotation;
        entry.version = found.version;
        entry.queue = found.queue;
        entry.rendezvous = found.rendezvous;
        entry.queue_since = found.queue_since;
        entry.previous = None;
        done(self);
        Ok(true)
    }

    /// The rotation of the handle key of this device and whether the
    /// directory shows the handle as held by another party, for a test.
    #[doc(hidden)]
    pub fn handle_rotation(&self) -> Result<Option<(u32, bool)>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .find(|entry| entry.kind == EntryKind::Handle)
            .map(|entry| (entry.rotation, entry.foreign)))
    }

    /// Sets the handle back to its first key and version, as a restore from
    /// a backup before a rotation holds it, for a test.
    #[doc(hidden)]
    pub fn rewind_handle(&self) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        let mut entry = inner
            .client
            .published()?
            .into_iter()
            .find(|entry| entry.kind == EntryKind::Handle)
            .ok_or(FfiError::NotFound)?;
        entry.rotation = 0;
        entry.version = 0;
        inner.client.put_published(&entry, &mut OsRng)?;

        // The handle stands as a restore left it, and it looks for its key.
        Ok(inner.client.mark_resync(&mut OsRng)?)
    }

    /// How the directory shows the entry (`DIS-137`). It shows the entry as
    /// this device wrote it when the newest version is its version, with
    /// its key and its queue. It shows a write of this device that the log
    /// does not show yet, with the version that the log shows. Else it
    /// shows a version of another writer.
    fn entry_standing(
        &self,
        link: &DirectoryLink,
        entry: &Published,
    ) -> Result<(Standing, Option<Shown>), FfiError> {
        let found = link.find_own(&entry.label)?;
        let (Some(bytes), Some(version)) = (found.entry, found.version) else {
            return Ok((Standing::Foreign, None));
        };

        let shown = match entry.kind {
            EntryKind::Address => AddressEntry::parse(&bytes)
                .map(|shown| (shown.address_pk, shown.rendezvous))
                .map_err(|_| FfiError::Unverified),
            EntryKind::Handle => DirectoryEntry::parse(&bytes)
                .map(|shown| (shown.hk_pub, shown.rendezvous))
                .map_err(|_| FfiError::Unverified),
        };

        if version != entry.version {
            let shown = shown.ok().map(|(key, _)| Shown { version, key });
            return Ok((standing(entry.version, version, false, false), shown));
        }

        let (shown_key, shown_queue) = shown?;
        let key = locked(&self.inner)
            .client
            .entry_key(entry.kind, entry.index, entry.rotation)?
            .public()
            .to_bytes();
        let rendezvous = QueueAddress::parse(&entry.rendezvous).map_err(|_| FfiError::Integrity)?;
        let same_queue = shown_queue.is_some_and(|queue| {
            queue.relay_id == rendezvous.relay_id && queue.sender_id == rendezvous.sender_id
        });

        Ok((
            standing(entry.version, version, shown_key == key, same_queue),
            None,
        ))
    }

    /// The upkeep of the entries at `now`; [`Handle::maintain_directory`]
    /// gives it the clock of the device. A test gives it a later time.
    #[doc(hidden)]
    pub fn maintain_directory_at(&self, now: u64) -> Result<(), FfiError> {
        let link = self.directory_link()?;

        // §9.3.1: a profile blob that no write took yet goes now.
        let _ = self.publish_profile_blob(&link);

        // Part 13 §13.3.1: the keys that a hello of a stranger names, and
        // the tokens of the hellos of this device.
        let _ = self.keep_cross_relay_tokens(&link, now);

        // DIS-136: the tree heads of contacts that no held head names.
        let _ = self.check_gossiped_heads(&link);

        let entries = locked(&self.inner).client.published()?;
        let owed = locked(&self.inner).client.rendezvous_owed(&mut OsRng)?;
        for mut entry in entries {
            if entry.expires_at != 0 && now >= entry.expires_at {
                // DIS-172: the directory ended the lease and wrote the
                // tombstone at a later version, thus a write of the holder
                // finds no version to follow. DIS-174: the queue ends now.
                let _ = self.end_entry(&entry);
                continue;
            }

            // DIS-137, DIS-138: the holder reads its own entry. IDN-109:
            // a restored handle finds its current key before it shows as
            // held by another party.
            let mut is_staged = false;
            let read = self.entry_standing(&link, &entry);

            // DIS-205: a write that left with no answer settles first, and it
            // waits for a read of the log.
            if entry.pending.is_some() {
                let settled = match &read {
                    Ok((standing, shown)) => {
                        self.settle_pending(&entry, *standing, shown.as_ref(), now)
                    }
                    Err(_) => Settled::Done,
                };
                match settled {
                    Settled::Done => continue,
                    Settled::Retire => {
                        let _ = self.retire(&link, &entry);
                        continue;
                    }
                    Settled::Upkeep => {}
                }
            }

            if let Ok((standing, shown)) = read {
                is_staged = standing == Standing::Staged;

                // DEV-306: the log shows the held version under its key,
                // thus the directory holds the key of the held rotation. An
                // earlier identity root that served the rotation before it
                // has no more use. Only this proof erases one: a write that
                // the store took, and one that the directory refused, erase
                // none.
                if standing == Standing::Own {
                    let _ = locked(&self.inner)
                        .client
                        .confirm_published(&entry.id, &mut OsRng);
                }
                let own = if standing != Standing::Foreign {
                    // The entry belongs to this device, thus a look of a
                    // restore for it has no more to find.
                    let _ = locked(&self.inner)
                        .client
                        .resync_done(&entry.id, &mut OsRng);

                    // A write that the log does not show after its epoch
                    // did not reach the directory, and it goes again. A
                    // fault here leaves it for the next upkeep.
                    if let Some(shown) = shown.filter(|_| {
                        is_staged && now.saturating_sub(entry.queue_since) >= WRITE_SETTLE
                    }) {
                        let _ = self.write_again(&link, &mut entry, &shown, now);
                    }
                    Some(true)
                } else if entry.kind == EntryKind::Handle {
                    // A fault of the network changes no state of the entry.
                    self.resync_handle(&link, &mut entry, now).ok()
                } else {
                    Some(false)
                };
                let Some(own) = own else {
                    continue;
                };

                if own == entry.foreign {
                    entry.foreign = !own;
                    locked(&self.inner)
                        .client
                        .put_published(&entry, &mut OsRng)?;
                }
            }

            // DIS-139: over a version of another writer, only the user acts.
            if entry.foreign {
                continue;
            }

            // DIS-134: the grace of the queue before the last rotation ends.
            // The log names that queue while the write of the rotation
            // waits, thus it ends no queue then.
            if let Some((previous, until)) = entry.previous.filter(|_| !is_staged) {
                if now >= until {
                    self.end_rendezvous(previous);
                    let mut inner = locked(&self.inner);
                    let _ = inner.client.unbind_queue(&previous, &mut OsRng);
                    entry.previous = None;
                    inner.client.put_published(&entry, &mut OsRng)?;
                }
            }

            // DEV-347: a queue that a removed device knew takes its successor
            // now. That device knew a queue in its grace too, and it ends
            // first: one queue waits at a time.
            if owed.contains(&entry.queue) && !is_staged {
                if let Some((previous, _)) = entry.previous.take() {
                    self.end_rendezvous(previous);
                    let mut inner = locked(&self.inner);
                    let _ = inner.client.unbind_queue(&previous, &mut OsRng);
                    inner.client.put_published(&entry, &mut OsRng)?;
                }
                let _ = self.rotate_queue(&link, &entry, now);
                continue;
            }

            // DIS-133: a queue of `RENDEZVOUS_ROTATE` takes its successor. A
            // queue in its grace waits for the end of that grace.
            if entry.previous.is_none()
                && !is_staged
                && now.saturating_sub(entry.queue_since) >= RENDEZVOUS_ROTATE
            {
                let _ = self.rotate_queue(&link, &entry, now);
                continue;
            }

            // A timed link ends inside its lease, and no renewal moves that
            // end (DIS-172).
            if entry.expires_at != 0 || now.saturating_sub(entry.renewed_at) < RENEW_EVERY {
                continue;
            }

            let key =
                locked(&self.inner)
                    .client
                    .entry_key(entry.kind, entry.index, entry.rotation)?;
            if link.renew(&entry.label, &entry.name, &key).is_ok() {
                let renewed = Published {
                    renewed_at: now,
                    ..entry
                };
                locked(&self.inner)
                    .client
                    .put_published(&renewed, &mut OsRng)?;
            }
        }
        Ok(())
    }

    /// Takes the keys of the cross-relay issuer from the log, and `count`
    /// tokens of this epoch, for a test that needs no full batch.
    #[doc(hidden)]
    pub fn stock_tokens(&self, count: u32) -> Result<(), FfiError> {
        let link = self.directory_link()?;
        let now = unix_now();
        self.keep_cross_relay_keys(&link, now)?;
        if count == 0 {
            return Ok(());
        }

        self.fetch_tokens(&link, epoch_number(now), count as usize)
    }

    /// The tokens of this epoch that this device holds, for a test.
    #[doc(hidden)]
    pub fn tokens_held(&self) -> Result<u32, FfiError> {
        let count = locked(&self.inner)
            .client
            .token_count(epoch_number(unix_now()))?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// The rendezvous queue of an entry and the one before it, for a test.
    #[doc(hidden)]
    pub fn entry_queues(&self, id: &[u8]) -> Result<([u8; 32], Option<[u8; 32]>), FfiError> {
        let entry = self.find_published(id)?;
        Ok((entry.queue, entry.previous.map(|(queue, _)| queue)))
    }

    fn find_published(&self, id: &[u8]) -> Result<Published, FfiError> {
        let id = id16(id)?;
        locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .find(|entry| entry.id == id)
            .ok_or(FfiError::NotFound)
    }
}

#[uniffi::export]
impl Handle {
    /// Whether the build pins a directory, thus whether this device can
    /// publish a link or a handle and send a request to one.
    pub fn has_directory(&self) -> bool {
        let inner = locked(&self.inner);
        inner.owns_channels && inner.directory.is_some()
    }

    /// The link or the handle of each entry that took the limit of hellos of
    /// this week (`ABU-086`). The view offers a new queue (`ABU-087`).
    pub fn entries_at_limit(&self) -> Result<Vec<String>, FfiError> {
        let inner = locked(&self.inner);
        let now = unix_now();
        let mut out = Vec::new();
        for entry in inner.client.published()? {
            if inner.client.is_at_hello_limit(&entry.id, now)? {
                out.push(via_text(&entry));
            }
        }
        Ok(out)
    }

    /// Moves a link or the handle to a new rendezvous queue at once, at a
    /// tap of the user (§9.9, `ABU-087`). `label` is the link or the handle
    /// as the views show it. A queue in its grace ends first.
    pub fn rotate_entry(&self, label: String) -> Result<(), FfiError> {
        let link = self.directory_link()?;
        let mut entry = locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .find(|entry| via_text(entry) == label)
            .ok_or(FfiError::NotFound)?;

        if let Some((previous, _)) = entry.previous.take() {
            self.end_rendezvous(previous);
            let _ = locked(&self.inner)
                .client
                .unbind_queue(&previous, &mut OsRng);
        }

        self.rotate_queue(&link, &entry, unix_now())
    }

    /// The link or the handle of each entry whose newest version in the
    /// directory this device did not write (`DIS-138`). The view warns of a
    /// takeover.
    pub fn directory_warnings(&self) -> Result<Vec<String>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .filter(|entry| entry.foreign)
            .map(|entry| via_text(&entry))
            .collect())
    }

    /// Each reusable link of this device, oldest first.
    pub fn public_links(&self) -> Result<Vec<PublicLink>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .filter(|entry| entry.kind == EntryKind::Address)
            .map(|entry| PublicLink {
                id: entry.id.to_vec(),
                link: via_text(&entry),
                created_at: entry.created_at,
                expires_at: entry.expires_at,
            })
            .collect())
    }

    /// Publishes a new reusable link at the next Public Address index
    /// (Part 4 §4.3.2, `DIS-103`). A link with `valid_seconds` above 0 ends
    /// after that time, and 0 gives a link with no end. The call blocks for
    /// some seconds: the relay makes a queue, and the proof of work of a
    /// token runs (Part 13 §13.9).
    pub fn create_public_link(&self, valid_seconds: u64) -> Result<PublicLink, FfiError> {
        let link = self.directory_link()?;
        let index = locked(&self.inner).client.take_address_index(&mut OsRng)?;
        let key = locked(&self.inner)
            .client
            .entry_key(EntryKind::Address, index, 0)?;
        let address_pk = key.public().to_bytes();
        let address = address::address_of(&address_pk);

        let expires_at = match valid_seconds {
            0 => 0,
            seconds => unix_now().saturating_add(seconds),
        };

        let entry = self.publish(
            &link,
            EntryKind::Address,
            index,
            address_label_input(&address),
            address.to_vec(),
            |_, rendezvous, version| {
                let mut out = vec![0u8; ADDRESS_ENTRY_LEN];
                AddressEntry {
                    address,
                    address_pk,
                    rendezvous: Some(rendezvous),
                    version,
                }
                .encode(&mut out)
                .map_err(|_| FfiError::Malformed)?;
                Ok(out)
            },
            expires_at,
        )?;

        Ok(PublicLink {
            id: entry.id.to_vec(),
            link: address::link_string(&address),
            created_at: entry.created_at,
            expires_at,
        })
    }

    /// Retires a reusable link: the directory shows its tombstone, and its
    /// queue ends (`DIS-171`). A second write in one epoch of the log waits
    /// for the next one, and the call then gives `Busy`.
    pub fn retire_public_link(&self, id: Vec<u8>) -> Result<(), FfiError> {
        let entry = self.find_published(&id)?;

        // A timed link past its end holds no label to write (DIS-172).
        if entry.expires_at != 0 && unix_now() >= entry.expires_at {
            return self.end_entry(&entry);
        }

        let link = self.directory_link()?;
        self.retire(&link, &entry)
    }

    /// The handle of this device, or none.
    pub fn my_handle(&self) -> Result<Option<String>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .find(|entry| entry.kind == EntryKind::Handle)
            .map(|entry| via_text(&entry)))
    }

    /// Claims a handle `@name#dddd` with a random discriminator (Part 9
    /// §9.9). The name takes the profile of `DIS-088`. A taken handle takes
    /// another discriminator. The call blocks as
    /// [`Handle::create_public_link`] does.
    pub fn claim_handle(&self, name: String) -> Result<String, FfiError> {
        let link = self.directory_link()?;
        if self.my_handle()?.is_some() {
            return Err(FfiError::Stale);
        }

        let name = name.trim().trim_start_matches("@");
        for _ in 0..CLAIM_TRIES {
            let mut draw = [0u8; 4];
            OsRng
                .try_fill_bytes(&mut draw)
                .map_err(|_| FfiError::Storage)?;
            let digits = 1_000 + u32::from_be_bytes(draw) % 9_000;
            let handle = DirHandle::parse(&format!("@{name}#{digits}"), &username_case_mapped)
                .map_err(|_| FfiError::Malformed)?;

            let canonical = handle.label_input();
            let entry_name = canonical.clone();
            let published = self.publish(
                &link,
                EntryKind::Handle,
                0,
                canonical.clone(),
                canonical,
                |key, rendezvous, version| {
                    let entry = DirectoryEntry {
                        handle: entry_name,
                        hk_pub: key.public().to_bytes(),
                        rendezvous: Some(rendezvous),
                        version,
                    };
                    let mut out = vec![0u8; entry.len()];
                    let used = entry.encode(&mut out).map_err(|_| FfiError::Malformed)?;
                    out.truncate(used);
                    Ok(out)
                },
                0,
            );

            match published {
                Ok(entry) => {
                    // §9.3.1: the profile of the new handle goes beside it.
                    let _ = self.publish_profile_blob(&link);
                    return Ok(via_text(&entry));
                }
                // A held label: another discriminator.
                Err(FfiError::Stale) => continue,
                Err(error) => return Err(error),
            }
        }

        Err(FfiError::Stale)
    }

    /// Moves the handle to the next key `HandleKey_{0,r+1}` and to a new
    /// rendezvous queue at one tap (Part 9 §9.3, §9.9): the old key answers
    /// the write challenge of the new version (`DIS-093`). The old queue
    /// takes hellos in its grace, and a hello sealed to the old key opens no
    /// more.
    pub fn rotate_handle_key(&self) -> Result<(), FfiError> {
        let link = self.directory_link()?;
        let entry = locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .find(|entry| entry.kind == EntryKind::Handle)
            .ok_or(FfiError::NotFound)?;

        let rotation = entry.rotation.checked_add(1).ok_or(FfiError::TooLong)?;
        let (old, new) = {
            let inner = locked(&self.inner);
            (
                inner
                    .client
                    .entry_key(EntryKind::Handle, entry.index, entry.rotation)?,
                inner
                    .client
                    .entry_key(EntryKind::Handle, entry.index, rotation)?,
            )
        };

        let version = entry.version.checked_add(1).ok_or(FfiError::TooLong)?;
        let (queue, rendezvous) = self.new_rendezvous()?;
        let now = unix_now();
        let rotated = Published {
            version,
            rotation,
            queue,
            rendezvous,
            queue_since: now,
            previous: Some((entry.queue, now.saturating_add(ROTATE_GRACE))),
            pending: None,
            ..entry.clone()
        };
        self.write_version(&link, &entry, &rotated, &old, &new, entry.version)?;

        // A queue still in its grace ends now: one queue waits at a time.
        if let Some((previous, _)) = entry.previous {
            self.end_rendezvous(previous);
            let _ = locked(&self.inner)
                .client
                .unbind_queue(&previous, &mut OsRng);
        }
        Ok(())
    }

    /// Releases the handle of this device: the directory shows its
    /// tombstone (Part 9 §9.9.2).
    pub fn release_handle(&self) -> Result<(), FfiError> {
        let link = self.directory_link()?;
        let entry = locked(&self.inner)
            .client
            .published()?
            .into_iter()
            .find(|entry| entry.kind == EntryKind::Handle)
            .ok_or(FfiError::NotFound)?;

        // DIS-178: the tombstone takes the blob, and a later handle takes a
        // new link.
        self.retire(&link, &entry)
    }

    /// Sends a contact request to a reusable link, an `umbra:pub:` string,
    /// or a handle (Part 4 §4.3.3). The call looks the entry up under the
    /// log, and the hello leaves when the runtime has made its queue. A
    /// [`FfiEvent::Contact`] follows when the addressee accepts. A handle
    /// that a different party now holds gives [`FfiError::Takeover`], and
    /// the hello goes only with `confirmed` (`DIS-085`). In the degraded
    /// read of Part 9 §9.5.2 the entry is unverified: the call gives
    /// [`FfiError::Unverified`], and the hello goes only with `confirmed`
    /// (`DIS-068`, `DIS-069`).
    pub fn send_contact_request(
        &self,
        target: String,
        note: String,
        confirmed: bool,
    ) -> Result<(), FfiError> {
        let note = note.trim().to_owned();
        if note.len() > umbra_core::discovery::profile::WELCOME_MAX {
            return Err(FfiError::TooLong);
        }

        let link = self.directory_link()?;
        let target = target.trim();

        // DIS-078: the key of a handle that this hello goes to.
        let mut to_hold = None;
        let (entry_pk, rendezvous) = if target.starts_with("@")
            || target.starts_with(PROFILE_LINK_PREFIX)
        {
            let handle = if target.starts_with("@") {
                DirHandle::parse(target, &username_case_mapped).map_err(|_| FfiError::Malformed)?
            } else {
                parse_profile_link(target, &username_case_mapped)
                    .map_err(|_| FfiError::Malformed)?
                    .0
            };

            let input = handle.label_input();
            let (found, search_key) = link.find_read(&input)?;
            if found.degraded && !confirmed {
                return Err(FfiError::Unverified);
            }

            let degraded = found.degraded;
            let bytes = found.entry.ok_or(FfiError::NotFound)?;
            let entry = DirectoryEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
            if entry.handle != input || Some(entry.version) != found.version {
                return Err(FfiError::Unverified);
            }

            let rendezvous = entry.rendezvous.ok_or(FfiError::NotFound)?;
            let resolved = Version {
                version: entry.version,
                hk_pub: entry.hk_pub,
            };

            let held = locked(&self.inner).client.held_handle_key(&input)?;
            if degraded {
                // DIS-070: an unverified read replaces no held key, and the
                // device holds no key from it.
                if held.is_some_and(|held| held.hk_pub != resolved.hk_pub) {
                    return Err(FfiError::Unverified);
                }
            } else {
                if let Some(held) = held {
                    let verdict = link.assess_handle(&input, &search_key, &held, &resolved)?;
                    if verdict == Takeover::Warn && !confirmed {
                        return Err(FfiError::Takeover);
                    }
                }
                to_hold = Some((input, resolved));
            }
            (entry.hk_pub, rendezvous)
        } else {
            let address = address::parse(target).map_err(|_| FfiError::Malformed)?;
            let (found, _) = link.find_read(&address_label_input(&address))?;
            if found.degraded && !confirmed {
                return Err(FfiError::Unverified);
            }

            let bytes = found.entry.ok_or(FfiError::NotFound)?;
            let entry = AddressEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;

            // IDN-131, DIS-128: the key hashes to the address.
            if entry.address != address || entry.check().is_err() {
                return Err(FfiError::Unverified);
            }

            let rendezvous = entry.rendezvous.ok_or(FfiError::NotFound)?;
            (entry.address_pk, rendezvous)
        };

        let mut encoded = vec![0u8; QUEUE_ADDRESS_LEN];
        rendezvous
            .encode(&mut encoded)
            .map_err(|_| FfiError::Malformed)?;

        let inner = locked(&self.inner);

        // DIS-180: the hello carries the profile of the sender, with the
        // note in the place of the welcome text.
        let name = inner.client.profile_name()?;
        let picture = inner.client.profile_picture()?;
        let profile = ProfilePlain {
            name: &name,
            welcome: &note,
            picture: &picture,
        }
        .encode()
        .map_err(|_| FfiError::Malformed)?;
        drop(inner);

        // DIS-132: a cross-relay token of this epoch, when the device holds
        // one, and else a proof of work.
        let mut inner = locked(&self.inner);

        // ABU-076: a token leaves the store only for a hello that a run
        // takes, thus a client with no run spends none.
        if inner.bridge.is_none() {
            return Err(FfiError::Offline);
        }

        let token = inner.client.take_token(epoch_number(unix_now()))?;
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        bridge.hello(entry_pk.to_vec(), encoded, profile, token)?;

        if let Some((input, resolved)) = to_hold {
            inner
                .client
                .hold_handle_key(&input, &resolved, &mut OsRng)?;
        }
        Ok(())
    }

    /// The name that a contact request of this device shows.
    pub fn profile_name(&self) -> Result<String, FfiError> {
        Ok(locked(&self.inner).client.profile_name()?)
    }

    /// Sets that name, at most 32 bytes. The profile blob of the handle
    /// takes it now, or at the next upkeep.
    pub fn set_profile_name(&self, name: String) -> Result<(), FfiError> {
        locked(&self.inner)
            .client
            .set_profile_name(&name, &mut OsRng)?;
        if let Ok(link) = self.directory_link() {
            let _ = self.publish_profile_blob(&link);
        }
        Ok(())
    }

    /// The picture of the profile, or empty for the generated one.
    pub fn profile_picture(&self) -> Result<Vec<u8>, FfiError> {
        Ok(locked(&self.inner).client.profile_picture()?)
    }

    /// Sets the picture of the profile, a JPEG of at most 6 144 bytes that
    /// the platform encoded anew, or empty for the generated one. The
    /// profile blob takes it now, or at the next upkeep.
    pub fn set_profile_picture(&self, picture: Vec<u8>) -> Result<(), FfiError> {
        locked(&self.inner)
            .client
            .set_profile_picture(&picture, &mut OsRng)?;
        if let Ok(link) = self.directory_link() {
            let _ = self.publish_profile_blob(&link);
        }
        Ok(())
    }

    /// The welcome text that the profile link shows (§9.3.1).
    pub fn welcome(&self) -> Result<String, FfiError> {
        Ok(locked(&self.inner).client.welcome()?)
    }

    /// Sets the welcome text, at most 280 bytes.
    pub fn set_welcome(&self, text: String) -> Result<(), FfiError> {
        locked(&self.inner).client.set_welcome(&text, &mut OsRng)?;
        if let Ok(link) = self.directory_link() {
            let _ = self.publish_profile_blob(&link);
        }
        Ok(())
    }

    /// The link of the handle of this device with the fragment that opens
    /// its profile (`DIS-179`), or none with no handle.
    pub fn my_handle_link(&self) -> Result<Option<String>, FfiError> {
        let Some(handle) = self.my_handle()? else {
            return Ok(None);
        };

        let handle =
            DirHandle::parse(&handle, &username_case_mapped).map_err(|_| FfiError::Integrity)?;
        let fragment = locked(&self.inner).client.handle_fragment(&mut OsRng)?;
        Ok(Some(handle.profile_link(&fragment)))
    }

    /// The profile that a profile link shows before a request: the name and
    /// the welcome text from the blob that the directory keeps (§9.3.1). A
    /// handle with no blob, or a blob that the fragment does not open,
    /// shows none.
    pub fn preview_contact(&self, target: String) -> Result<ContactPreview, FfiError> {
        let link = self.directory_link()?;
        let (handle, fragment) =
            parse_profile_link(&target, &username_case_mapped).map_err(|_| FfiError::Malformed)?;
        let input = handle.label_input();

        // DIS-067: a stale head still completes the lookup.
        let (found, _) = link.find_read(&input)?;
        let bytes = found.entry.ok_or(FfiError::NotFound)?;

        // DIS-157: the entry names this handle at the newest version, and a
        // tombstone previews no contact.
        let entry = DirectoryEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
        if entry.handle != input || Some(entry.version) != found.version {
            return Err(FfiError::Unverified);
        }

        entry.rendezvous.ok_or(FfiError::NotFound)?;
        let mut preview = ContactPreview {
            handle: handle.canonical(),
            name: String::new(),
            welcome: String::new(),
            picture: Vec::new(),
            unverified: found.degraded,
        };

        if let Some(plain) = found
            .blob
            .and_then(|blob| handle.open_blob(&fragment, &blob).ok())
        {
            if let Ok(profile) = ProfilePlain::parse(&plain) {
                preview.name = profile.name.to_owned();
                preview.welcome = profile.welcome.to_owned();
                preview.picture = profile.picture.to_vec();
            }
        }
        Ok(preview)
    }

    /// Each contact request that waits, oldest first.
    pub fn contact_requests(&self) -> Result<Vec<ContactRequestInfo>, FfiError> {
        let inner = locked(&self.inner);
        let published = inner.client.published()?;
        Ok(inner
            .client
            .contact_requests()?
            .into_iter()
            .map(|request| ContactRequestInfo {
                id: request.id.to_vec(),
                name: request.name,
                via: published
                    .iter()
                    .find(|entry| entry.id == request.via)
                    .map(via_text)
                    .unwrap_or_default(),
                received_at: request.received_at,
                note: request.note,
                picture: request.picture,
            })
            .collect())
    }

    /// Accepts a contact request: flight 1 goes to the queue that its hello
    /// named (`DIS-087`), and a [`FfiEvent::Contact`] follows.
    pub fn accept_contact_request(&self, id: Vec<u8>) -> Result<(), FfiError> {
        let id = id16(&id)?;
        let mut inner = locked(&self.inner);
        if inner.bridge.is_none() {
            return Err(FfiError::Offline);
        }

        let bundle = inner.client.take_request(&id)?;
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(bridge.accept(bundle.to_vec())?)
    }

    /// Drops a contact request. The sender learns nothing.
    pub fn decline_contact_request(&self, id: Vec<u8>) -> Result<(), FfiError> {
        let id = id16(&id)?;
        Ok(locked(&self.inner).client.decline_request(&id)?)
    }

    /// The upkeep of the entries of this device: a timed link at its end
    /// retires (`DIS-171`), and a lease renews in each `RENEW_EVERY`
    /// (Part 9 §9.9.1). The call blocks for each write, thus the platform
    /// calls it from a worker thread after the client is online.
    pub fn maintain_directory(&self) -> Result<(), FfiError> {
        self.maintain_directory_at(unix_now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_of_the_log_stands_as_own_staged_or_foreign() {
        // DIS-137: the version of this device, with its key and its queue.
        assert_eq!(standing(3, 3, true, true), Standing::Own);

        // DIS-138: the same version under another key or on another queue.
        assert_eq!(standing(3, 3, false, true), Standing::Foreign);
        assert_eq!(standing(3, 3, true, false), Standing::Foreign);

        // DIS-166: the store took a version that the log does not show yet,
        // whatever the version of the log holds. A rotation that a lock or
        // the end of the process cut after the store is such a case, and it
        // is no takeover.
        assert_eq!(standing(3, 2, false, false), Standing::Staged);
        assert_eq!(standing(3, 0, true, true), Standing::Staged);

        // The store takes a version before the directory does, thus a
        // version above the held one is of another writer.
        assert_eq!(standing(3, 4, true, true), Standing::Foreign);
    }

    #[test]
    fn the_write_of_a_cut_rotation_goes_again_under_the_key_of_the_log() {
        let held = KeyPair::generate(&mut OsRng);
        let before = KeyPair::generate(&mut OsRng);
        let other = KeyPair::generate(&mut OsRng);
        let same = |found: Option<&KeyPair>, key: &KeyPair| {
            found.map(|found| found.public().to_bytes()) == Some(key.public().to_bytes())
        };

        // A move of the queue: the log shows the held key, and it signs.
        let shown = held.public().to_bytes();
        assert!(same(signer_of(&shown, &held, Some(&before)), &held));
        assert!(same(signer_of(&shown, &held, None), &held));

        // A rotation of the handle key: the log shows the key before, which
        // answers the challenge of the new version (`DIS-093`).
        let shown = before.public().to_bytes();
        assert!(same(signer_of(&shown, &held, Some(&before)), &before));
        assert!(signer_of(&shown, &held, None).is_none());

        // DIS-139: a version under no key of this device takes no write.
        let shown = other.public().to_bytes();
        assert!(signer_of(&shown, &held, Some(&before)).is_none());
    }

    /// An entry at version 2 whose write `pending` waits for its answer.
    fn waiting(id: u8, kind: EntryKind, pending: PendingWrite, at: u64) -> Published {
        Published {
            id: [id; 16],
            kind,
            index: 1,
            rotation: 0,
            label: vec![id],
            name: vec![id],
            queue: [id; 32],
            rendezvous: vec![0; 8],
            version: 2,
            created_at: at,
            expires_at: 0,
            renewed_at: at,
            queue_since: at,
            previous: None,
            foreign: false,
            pending: Some(pending),
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_write_with_no_answer_settles_against_the_log() {
        let (handle, directory) = super::super::tests::open("settle");
        let now = 1_800_000_000;
        let put = |entry: &Published| {
            locked(&handle.inner)
                .client
                .put_published(entry, &mut OsRng)
                .unwrap();
        };
        let held = |id: u8| {
            locked(&handle.inner)
                .client
                .published()
                .unwrap()
                .into_iter()
                .find(|entry| entry.id == [id; 16])
        };

        // DIS-205: a registration that the log shows holds, and its mark
        // goes.
        let shown = waiting(1, EntryKind::Address, PendingWrite::Register, now);
        put(&shown);
        let settled = handle.settle_pending(&shown, Standing::Own, None, now);
        assert_eq!(settled, Settled::Done);
        assert_eq!(held(1).unwrap().pending, None);

        // §9.3.1: a handle that the log shows takes its profile blob.
        let blob_due = || locked(&handle.inner).client.profile_blob_due().unwrap();
        let claimed = waiting(5, EntryKind::Handle, PendingWrite::Register, now);
        put(&claimed);
        assert!(!blob_due());
        handle.settle_pending(&claimed, Standing::Own, None, now);
        assert_eq!(held(5).unwrap().pending, None);
        assert!(blob_due());

        // One that the log does not show waits for `WRITE_SETTLE`, and then
        // its entry goes.
        let lost = waiting(2, EntryKind::Address, PendingWrite::Register, now);
        put(&lost);
        handle.settle_pending(&lost, Standing::Foreign, None, now + 1);
        assert!(held(2).is_some());
        handle.settle_pending(&lost, Standing::Foreign, None, now + WRITE_SETTLE);
        assert!(held(2).is_none());

        // DIS-138: the tombstone of this device at the next version is no
        // takeover, and the entry ends.
        let retiring = waiting(3, EntryKind::Handle, PendingWrite::Retire, now);
        put(&retiring);
        let tombstone = Shown {
            version: 3,
            key: [0; ENTRY_PK_LEN],
        };
        let settled = handle.settle_pending(&retiring, Standing::Foreign, Some(&tombstone), now);
        assert_eq!(settled, Settled::Done);
        assert!(held(3).is_none());
        assert!(handle.directory_warnings().unwrap().is_empty());

        // A log that still shows the held version takes the tombstone
        // again, and each other version is a version of another party.
        let link = waiting(4, EntryKind::Address, PendingWrite::Retire, now);
        put(&link);
        let settled = handle.settle_pending(&link, Standing::Own, None, now);
        assert_eq!(settled, Settled::Retire);
        let other = Shown {
            version: 3,
            key: [5; ENTRY_PK_LEN],
        };
        let settled = handle.settle_pending(&link, Standing::Foreign, Some(&other), now);
        assert_eq!(settled, Settled::Upkeep);
        assert!(held(4).is_some());

        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
