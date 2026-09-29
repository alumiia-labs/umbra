//! The calls of the client to the directory and the issuer of Part 9 §9.10
//! and Part 13 §13.9, each in OHTTP through the pinned ingress relay.
//!
//! Each call blocks on a small runtime of its own, thus the platform calls
//! it from a worker thread, and the lock of the client is not held while it
//! runs. A proof of work of an issuance takes some seconds.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use umbra_core::discovery::{RENDEZVOUS_ROTATE, ROTATE_GRACE};
use umbra_core::{
    abuse::{
        epoch_number,
        issuer::{issuer_label_input, IssuerKeyEntry, IssuerKeys},
        token::{TYPE_CROSS_RELAY, TYPE_FIRST_PARTY},
    },
    discovery::{
        challenge::{answer, Purpose},
        dirclient::{self, DirError, DirectoryPins},
        entry::{AddressEntry, DirectoryEntry, ADDRESS_ENTRY_LEN, ENTRY_PK_LEN},
        handle::{
            address_label_input, parse_profile_link, username_case_mapped, Handle as DirHandle,
            PROFILE_LINK_PREFIX,
        },
        head::{AcceptedHead, HeadState, LogKeySet, SignedTreeHead},
        lifecycle::{assess, Takeover, Version},
        profile::ProfilePlain,
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
    client::{EntryKind, Published},
    runtime::OsRng,
};

/// The pinned route to the directory, with the keys of `DIS-163`.
#[derive(Clone)]
pub struct DirectoryLink {
    route: DirectoryRoute,
    pins: Arc<DirectoryPins>,
    tls: Arc<native::ClientConfig>,
    /// The newest head that this device accepted: its size, its root, and
    /// its timestamp (`DIS-061`).
    held: Arc<std::sync::Mutex<Option<HeldHead>>>,
}

/// A head that this device accepted: its size, its root, and its timestamp.
type HeldHead = (u64, [u8; 32], u64);

/// The tries of a lookup whose head and consistency proof name two epochs,
/// since an epoch closed between the two requests.
const HEAD_TRIES: usize = 3;

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

/// An entry as the log shows it under a head that verified.
pub struct Found {
    /// The entry bytes, or none for a label with no version.
    pub entry: Option<Vec<u8>>,
    /// The newest version of the label.
    pub version: Option<u32>,
    /// The sealed profile blob that the directory keeps beside the label.
    pub blob: Option<Vec<u8>>,
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
        })
    }

    /// The link for one call, from the head that the store holds.
    fn with_held(&self, held: Option<HeldHead>) -> Self {
        DirectoryLink {
            held: Arc::new(std::sync::Mutex::new(held)),
            ..self.clone()
        }
    }

    fn held(&self) -> Option<HeldHead> {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Verifies a head under the pinned key set and the clock (`DIS-054` to
    /// `DIS-062`).
    fn verify_head<'a>(&self, bytes: &'a [u8], now: u64) -> Result<SignedTreeHead<'a>, FfiError> {
        let head = SignedTreeHead::parse(bytes).map_err(|_| FfiError::Malformed)?;
        let (keyset, _) = LogKeySet::parse(&self.pins.keyset).map_err(|_| FfiError::Malformed)?;
        let mut heads = HeadState::new(keyset).map_err(|_| FfiError::Malformed)?;
        heads.accept(&head, now).map_err(|error| match error {
            umbra_core::Error::Stale => FfiError::Stale,
            _ => FfiError::Unverified,
        })?;
        Ok(head)
    }

    /// Sends one request and returns the body of a done answer.
    fn send(&self, kind: Kind, body: &[u8]) -> Result<Vec<u8>, FfiError> {
        let request = dirclient::request(kind, body).map_err(|_| FfiError::TooLong)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| FfiError::Offline)?;
        let response = runtime
            .block_on(call(&self.route, &request, self.tls.clone(), &mut OsRng))
            .map_err(|_| FfiError::Offline)?;
        Ok(dirclient::done(&response)?)
    }

    /// The search key of a label input, under a proof of work at the floor
    /// (`DIS-164`).
    fn search_key(&self, input: &[u8]) -> Result<[u8; 64], FfiError> {
        let pk = &self.pins.voprf_public;
        let (state, body) =
            dirclient::evaluate_request(input, pk, epoch_number(unix_now()), None, &mut OsRng)
                .map_err(|_| FfiError::Malformed)?;
        let evaluated = self.send(Kind::Evaluate, &body)?;
        dirclient::evaluate_finish(&state, &evaluated, pk).map_err(|_| FfiError::Unverified)
    }

    /// The lookup proof of a search key under the newest head, after the
    /// head verified under the pinned key set (`DIS-066`).
    fn lookup(
        &self,
        search_key: &[u8; 64],
    ) -> Result<(LookupProof, AcceptedHead, Option<Vec<u8>>), FfiError> {
        for _ in 0..HEAD_TRIES {
            let looked = self.send(Kind::Lookup, search_key)?;
            let (bytes, blob, proof) =
                dirclient::parse_lookup(&looked).map_err(|_| FfiError::Malformed)?;
            // None: an epoch closed between the lookup and the proof.
            if let Some(head) = self.accept_head(&bytes)? {
                return Ok((proof, head, blob));
            }
        }
        Err(FfiError::Busy)
    }

    /// Verifies the head of an answer and holds it when it extends the held
    /// head, or gives none for a head whose proof names another epoch.
    fn accept_head(&self, bytes: &[u8]) -> Result<Option<AcceptedHead>, FfiError> {
        let now = unix_now();
        let head = self.verify_head(bytes, now)?;
        if !self.extends_held(&head, now)? {
            return Ok(None);
        }
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((head.tree_size, head.root, head.timestamp));
        Ok(Some(AcceptedHead {
            tree_size: head.tree_size,
            root: head.root,
            timestamp: head.timestamp,
            accepted_at: now,
        }))
    }

    /// The entry of one version of a label, verified under the log
    /// (`DIS-183`, `DIS-184`).
    fn version_entry(&self, search_key: &[u8; 64], version: u32) -> Result<Vec<u8>, FfiError> {
        let body = dirclient::version_body(search_key, version);
        for _ in 0..HEAD_TRIES {
            let answer = self.send(Kind::Version, &body)?;
            let (bytes, proof) =
                dirclient::parse_version(&answer).map_err(|_| FfiError::Malformed)?;
            if let Some(head) = self.accept_head(&bytes)? {
                return proof
                    .verify(search_key, version, &self.vrf_key()?, &head)
                    .map(<[u8]>::to_vec)
                    .map_err(|_| FfiError::Unverified);
            }
        }
        Err(FfiError::Busy)
    }

    /// Whether the tree head of a contact at `tree_size` lies in the log
    /// that this device reads (`DIS-136`): the proof of consistency from that
    /// size to the newest head. None while the log is not that long here, or
    /// when an epoch closed between two answers.
    fn holds_head(&self, tree_size: u64, root: &[u8; 32]) -> Result<Option<bool>, FfiError> {
        let answer = match self.send(Kind::Head, &tree_size.to_be_bytes()) {
            Ok(answer) => answer,
            Err(FfiError::NotFound | FfiError::Stale | FfiError::Malformed) => return Ok(None),
            Err(other) => return Err(other),
        };
        let (bytes, proof) = dirclient::parse_head(&answer).map_err(|_| FfiError::Malformed)?;
        let Some(newest) = self.accept_head(&bytes)? else {
            return Ok(None);
        };
        if newest.tree_size < tree_size {
            return Ok(None);
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

    /// Whether a head extends the newest held head: a smaller log is a
    /// rollback (`DIS-061`), a second root at one size is a split view, and
    /// a larger log proves that it holds the held one. `false` is a proof
    /// that names another head, which a new lookup settles.
    fn extends_held(&self, head: &SignedTreeHead<'_>, now: u64) -> Result<bool, FfiError> {
        let Some((size, root, _)) = self.held() else {
            return Ok(true);
        };
        if head.tree_size < size {
            return Err(FfiError::Stale);
        }
        if head.tree_size == size {
            return if head.root == root {
                Ok(true)
            } else {
                Err(FfiError::Unverified)
            };
        }
        let answer = self.send(Kind::Head, &size.to_be_bytes())?;
        let (newest, consistency) =
            dirclient::parse_head(&answer).map_err(|_| FfiError::Malformed)?;
        let newest = self.verify_head(&newest, now)?;
        if newest.tree_size != head.tree_size || newest.root != head.root {
            return Ok(false);
        }
        umbra_core::discovery::logtree::verify_consistency(
            size,
            &root,
            head.tree_size,
            &head.root,
            &consistency,
        )
        .map_err(|_| FfiError::Unverified)?;
        Ok(true)
    }

    fn vrf_key(&self) -> Result<vrf::PublicKey, FfiError> {
        vrf::PublicKey::from_bytes(&self.pins.vrf_public).map_err(|_| FfiError::Malformed)
    }

    /// The newest entry of a label input, verified under the log.
    pub fn find(&self, input: &[u8]) -> Result<Found, FfiError> {
        Ok(self.find_keyed(input)?.0)
    }

    /// The newest entry of a label input and its search key.
    fn find_keyed(&self, input: &[u8]) -> Result<(Found, [u8; 64]), FfiError> {
        let search_key = self.search_key(input)?;
        let (proof, head, blob) = self.lookup(&search_key)?;
        let entry = proof
            .verify(&search_key, &self.vrf_key()?, &head)
            .map_err(|_| FfiError::Unverified)?
            .map(<[u8]>::to_vec);
        let found = Found {
            entry,
            version: proof.newest,
            blob,
        };
        Ok((found, search_key))
    }

    /// One first-party token of this epoch, under a proof of work
    /// (`ABU-076`). The issuer key comes from the log (`ABU-002`).
    pub fn token(&self) -> Result<Vec<u8>, FfiError> {
        let epoch = epoch_number(unix_now());
        let input = issuer_label_input(TYPE_FIRST_PARTY, epoch);
        let search_key = self.search_key(&input)?;
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

    /// Registers the first version of a label under a token (`DIS-101`),
    /// with the lease of a timed link (`DIS-172`).
    pub fn register(&self, input: &[u8], entry: &[u8], lease: Option<u32>) -> Result<(), FfiError> {
        let token = self.token()?;
        let body = dirclient::register_body(&token, input, entry, lease)
            .map_err(|_| FfiError::Malformed)?;
        self.send(Kind::Register, &body).map(|_| ())
    }

    /// Writes the next version of a label under the key of the version
    /// that `version` names (`DIS-093`). A tombstone entry retires the
    /// label (`DIS-171`).
    pub fn write(
        &self,
        input: &[u8],
        name: &[u8],
        key: &KeyPair,
        version: u32,
        entry: &[u8],
    ) -> Result<(), FfiError> {
        let body = dirclient::challenge_body(false, input).map_err(|_| FfiError::Malformed)?;
        let challenge = self.send(Kind::Challenge, &body)?;
        let (challenge, purpose) =
            dirclient::parse_challenge(&challenge, version).map_err(|_| FfiError::Malformed)?;
        let ans = answer(purpose, key, name, &challenge, Some(entry))
            .map_err(|_| FfiError::Unverified)?;
        let body = dirclient::write_body(input, &ans, entry).map_err(|_| FfiError::Malformed)?;
        self.send(Kind::Write, &body).map(|_| ())
    }

    /// The key of the cross-relay issuer of `epoch` from the log: version
    /// 0 of its label, of that type and that epoch (`ABU-099` to `ABU-101`).
    pub fn cross_relay_key(&self, epoch: u32) -> Result<PublicKey2048, FfiError> {
        let found = self.find(&issuer_label_input(TYPE_CROSS_RELAY, epoch))?;
        let bytes = found.entry.ok_or(FfiError::NotFound)?;
        let entry = IssuerKeyEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
        if found.version != Some(0) || entry.token_type != TYPE_CROSS_RELAY || entry.epoch != epoch
        {
            return Err(FfiError::Unverified);
        }
        PublicKey2048::from_modulus(&entry.public_key).map_err(|_| FfiError::Unverified)
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
}

impl core::ops::Deref for HeldLink<'_> {
    type Target = DirectoryLink;

    fn deref(&self) -> &DirectoryLink {
        &self.link
    }
}

impl Drop for HeldLink<'_> {
    fn drop(&mut self) {
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
        let link = inner
            .directory
            .as_ref()
            .ok_or(FfiError::Offline)?
            .with_held(before);
        Ok(HeldLink {
            handle: self,
            link,
            before,
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

    /// Registers an entry on a new rendezvous queue, and keeps it.
    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        link: &DirectoryLink,
        kind: EntryKind,
        index: u32,
        label: Vec<u8>,
        name: Vec<u8>,
        entry_of: impl FnOnce(&KeyPair, QueueAddress) -> Result<Vec<u8>, FfiError>,
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
        let (queue, rendezvous) = self.new_rendezvous()?;
        let registered = (|| {
            let key = locked(&self.inner).client.entry_key(kind, index, 0)?;
            let address = QueueAddress::parse(&rendezvous).map_err(|_| FfiError::Malformed)?;
            let entry = entry_of(&key, address)?;
            link.register(&label, &entry, lease)
        })();
        if let Err(error) = registered {
            self.end_rendezvous(queue);
            return Err(error);
        }
        let now = unix_now();
        let mut id = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| FfiError::Storage)?;
        let entry = Published {
            id,
            kind,
            index,
            rotation: 0,
            label,
            name,
            queue,
            rendezvous,
            version: 0,
            created_at: now,
            expires_at,
            renewed_at: now,
            queue_since: now,
            previous: None,
            foreign: false,
        };
        locked(&self.inner)
            .client
            .put_published(&entry, &mut OsRng)?;
        Ok(entry)
    }

    /// Writes the tombstone of an entry (`DIS-171`) and ends its queue.
    /// Proves each tree head that a contact gossiped and that no held head
    /// names against the log, and a failed proof is a split view
    /// (`DIS-034`, `DIS-136`).
    fn check_gossiped_heads(&self, link: &DirectoryLink) -> Result<(), FfiError> {
        let checks = locked(&self.inner).client.head_checks()?;
        for check in checks {
            if let Some(holds) = link.holds_head(check.tree_size, &check.root)? {
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
        match link.write(&entry.label, &entry.name, &key, entry.version, &tombstone) {
            // A label that the directory tombstoned already, or holds no
            // more, is retired.
            Ok(()) | Err(FfiError::NotFound | FfiError::Stale) => {}
            Err(error) => return Err(error),
        }
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
        inner.client.drop_published(&entry.id)?;
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
        let (queue, rendezvous) = self.new_rendezvous()?;
        let written = (|| {
            let key =
                locked(&self.inner)
                    .client
                    .entry_key(entry.kind, entry.index, entry.rotation)?;
            let address = QueueAddress::parse(&rendezvous).map_err(|_| FfiError::Malformed)?;
            let version = entry.version.checked_add(1).ok_or(FfiError::TooLong)?;
            let bytes = match entry.kind {
                EntryKind::Address => {
                    let mut out = vec![0u8; ADDRESS_ENTRY_LEN];
                    AddressEntry {
                        address: entry
                            .name
                            .as_slice()
                            .try_into()
                            .map_err(|_| FfiError::Integrity)?,
                        address_pk: key.public().to_bytes(),
                        rendezvous: Some(address),
                        version,
                    }
                    .encode(&mut out)
                    .map_err(|_| FfiError::Malformed)?;
                    out
                }
                EntryKind::Handle => {
                    let next = DirectoryEntry {
                        handle: entry.name.clone(),
                        hk_pub: key.public().to_bytes(),
                        rendezvous: Some(address),
                        version,
                    };
                    let mut out = vec![0u8; next.len()];
                    let used = next.encode(&mut out).map_err(|_| FfiError::Malformed)?;
                    out.truncate(used);
                    out
                }
            };
            link.write(&entry.label, &entry.name, &key, entry.version, &bytes)
        })();
        if let Err(error) = written {
            self.end_rendezvous(queue);
            return Err(error);
        }
        let rotated = Published {
            version: entry.version.saturating_add(1),
            queue,
            rendezvous,
            queue_since: now,
            previous: Some((entry.queue, now.saturating_add(ROTATE_GRACE))),
            ..entry.clone()
        };
        locked(&self.inner)
            .client
            .put_published(&rotated, &mut OsRng)?;
        Ok(())
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
        let found = link.find(&entry.label)?;
        let (Some(bytes), Some(version)) = (found.entry, found.version) else {
            return Ok(false);
        };
        let Ok(shown) = DirectoryEntry::parse(&bytes) else {
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
            return Ok(false);
        };
        let next_version = version.checked_add(1).ok_or(FfiError::TooLong)?;
        let (queue, rendezvous) = self.new_rendezvous()?;
        let written = (|| {
            let next = DirectoryEntry {
                handle: entry.name.clone(),
                hk_pub: key.public().to_bytes(),
                rendezvous: Some(
                    QueueAddress::parse(&rendezvous).map_err(|_| FfiError::Integrity)?,
                ),
                version: next_version,
            };
            let mut out = vec![0u8; next.len()];
            let used = next.encode(&mut out).map_err(|_| FfiError::Malformed)?;
            out.truncate(used);
            link.write(&entry.label, &entry.name, &key, version, &out)
        })();
        if let Err(error) = written {
            self.end_rendezvous(queue);
            return Err(error);
        }
        entry.rotation = rotation;
        entry.version = next_version;
        entry.queue = queue;
        entry.rendezvous = rendezvous;
        entry.queue_since = now;
        entry.previous = None;
        locked(&self.inner)
            .client
            .put_published(entry, &mut OsRng)?;
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
        Ok(inner.client.put_published(&entry, &mut OsRng)?)
    }

    /// Whether the directory shows the entry as this device wrote it
    /// (`DIS-137`): the newest version is its version, with its key and its
    /// queue. A version below it is a write of this device that waits for
    /// the next epoch.
    fn is_own_entry(&self, link: &DirectoryLink, entry: &Published) -> Result<bool, FfiError> {
        let found = link.find(&entry.label)?;
        let (Some(bytes), Some(version)) = (found.entry, found.version) else {
            return Ok(false);
        };
        if version < entry.version {
            return Ok(true);
        }
        if version > entry.version {
            return Ok(false);
        }
        let key = locked(&self.inner)
            .client
            .entry_key(entry.kind, entry.index, entry.rotation)?
            .public()
            .to_bytes();
        let rendezvous = QueueAddress::parse(&entry.rendezvous).map_err(|_| FfiError::Integrity)?;
        let (shown_key, shown_queue) = match entry.kind {
            EntryKind::Address => {
                let shown = AddressEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
                (shown.address_pk, shown.rendezvous)
            }
            EntryKind::Handle => {
                let shown = DirectoryEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
                (shown.hk_pub, shown.rendezvous)
            }
        };
        let same_queue = shown_queue.is_some_and(|queue| {
            queue.relay_id == rendezvous.relay_id && queue.sender_id == rendezvous.sender_id
        });
        Ok(shown_key == key && same_queue)
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
        for mut entry in entries {
            if entry.expires_at != 0 && now >= entry.expires_at {
                // A write in the same epoch waits for the next call.
                let _ = self.retire(&link, &entry);
                continue;
            }
            // DIS-137, DIS-138: the holder reads its own entry. IDN-109:
            // a restored handle finds its current key before it shows as
            // held by another party.
            if let Ok(own) = self.is_own_entry(&link, &entry) {
                let own = own
                    || (entry.kind == EntryKind::Handle
                        && self.resync_handle(&link, &mut entry, now).unwrap_or(false));
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
            if let Some((previous, until)) = entry.previous {
                if now >= until {
                    self.end_rendezvous(previous);
                    let mut inner = locked(&self.inner);
                    let _ = inner.client.unbind_queue(&previous, &mut OsRng);
                    entry.previous = None;
                    inner.client.put_published(&entry, &mut OsRng)?;
                }
            }
            // DIS-133: a queue of `RENDEZVOUS_ROTATE` takes its successor. A
            // queue in its grace waits for the end of that grace.
            if entry.previous.is_none()
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
            |_, rendezvous| {
                let mut out = vec![0u8; ADDRESS_ENTRY_LEN];
                AddressEntry {
                    address,
                    address_pk,
                    rendezvous: Some(rendezvous),
                    version: 0,
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
        let link = self.directory_link()?;
        let entry = self.find_published(&id)?;
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
                |key, rendezvous| {
                    let entry = DirectoryEntry {
                        handle: entry_name,
                        hk_pub: key.public().to_bytes(),
                        rendezvous: Some(rendezvous),
                        version: 0,
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
                    let _ = locked(&self.inner)
                        .client
                        .set_profile_blob_due(true, &mut OsRng);
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
        let written = (|| {
            let next = DirectoryEntry {
                handle: entry.name.clone(),
                hk_pub: new.public().to_bytes(),
                rendezvous: Some(
                    QueueAddress::parse(&rendezvous).map_err(|_| FfiError::Integrity)?,
                ),
                version,
            };
            let mut bytes = vec![0u8; next.len()];
            let used = next.encode(&mut bytes).map_err(|_| FfiError::Malformed)?;
            bytes.truncate(used);
            link.write(&entry.label, &entry.name, &old, entry.version, &bytes)
        })();
        if let Err(error) = written {
            self.end_rendezvous(queue);
            return Err(error);
        }
        // A queue still in its grace ends now: one queue waits at a time.
        if let Some((previous, _)) = entry.previous {
            self.end_rendezvous(previous);
            let _ = locked(&self.inner)
                .client
                .unbind_queue(&previous, &mut OsRng);
        }
        let now = unix_now();
        let rotated = Published {
            version,
            rotation,
            queue,
            rendezvous,
            queue_since: now,
            previous: Some((entry.queue, now.saturating_add(ROTATE_GRACE))),
            ..entry
        };
        locked(&self.inner)
            .client
            .put_published(&rotated, &mut OsRng)?;
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
        self.retire(&link, &entry)?;
        // DIS-178: the tombstone took the blob, and a later handle takes a
        // new link.
        let mut inner = locked(&self.inner);
        inner.client.drop_handle_fragment()?;
        Ok(inner.client.set_profile_blob_due(false, &mut OsRng)?)
    }

    /// Sends a contact request to a reusable link, an `umbra:pub:` string,
    /// or a handle (Part 4 §4.3.3). The call looks the entry up under the
    /// log, and the hello leaves when the runtime has made its queue. A
    /// [`FfiEvent::Contact`] follows when the addressee accepts. A handle
    /// that a different party now holds gives [`FfiError::Takeover`], and
    /// the hello goes only with `confirmed` (`DIS-085`).
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
            let (found, search_key) = link.find_keyed(&input)?;
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
            if let Some(held) = held {
                let verdict = link.assess_handle(&input, &search_key, &held, &resolved)?;
                if verdict == Takeover::Warn && !confirmed {
                    return Err(FfiError::Takeover);
                }
            }
            to_hold = Some((input, resolved));
            (entry.hk_pub, rendezvous)
        } else {
            let address = address::parse(target).map_err(|_| FfiError::Malformed)?;
            let found = link.find(&address_label_input(&address))?;
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
        let token = locked(&self.inner)
            .client
            .take_token(epoch_number(unix_now()))?;
        let mut inner = locked(&self.inner);
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
        let found = link.find(&handle.label_input())?;
        found.entry.ok_or(FfiError::NotFound)?;
        let mut preview = ContactPreview {
            handle: handle.canonical(),
            name: String::new(),
            welcome: String::new(),
            picture: Vec::new(),
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
