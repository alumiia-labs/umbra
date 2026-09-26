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
        handle::{address_label_input, username_case_mapped, Handle as DirHandle},
        head::{AcceptedHead, HeadState, LogKeySet, SignedTreeHead},
        translog::LookupProof,
    },
    identity::address,
};
use umbra_crypto::{kem::KeyPair, rand_core::TryRng, vrf};
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

/// An entry as the log shows it under a head that verified.
pub struct Found {
    /// The entry bytes, or none for a label with no version.
    pub entry: Option<Vec<u8>>,
    /// The newest version of the label.
    pub version: Option<u32>,
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
        })
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
    fn lookup(&self, search_key: &[u8; 64]) -> Result<(LookupProof, AcceptedHead), FfiError> {
        let looked = self.send(Kind::Lookup, search_key)?;
        let (head, proof) = dirclient::parse_lookup(&looked).map_err(|_| FfiError::Malformed)?;
        let head = SignedTreeHead::parse(&head).map_err(|_| FfiError::Malformed)?;
        let (keyset, _) = LogKeySet::parse(&self.pins.keyset).map_err(|_| FfiError::Malformed)?;
        let now = unix_now();
        let mut heads = HeadState::new(keyset).map_err(|_| FfiError::Malformed)?;
        heads.accept(&head, now).map_err(|error| match error {
            umbra_core::Error::Stale => FfiError::Stale,
            _ => FfiError::Unverified,
        })?;
        Ok((
            proof,
            AcceptedHead {
                tree_size: head.tree_size,
                root: head.root,
                timestamp: head.timestamp,
                accepted_at: now,
            },
        ))
    }

    fn vrf_key(&self) -> Result<vrf::PublicKey, FfiError> {
        vrf::PublicKey::from_bytes(&self.pins.vrf_public).map_err(|_| FfiError::Malformed)
    }

    /// The newest entry of a label input, verified under the log.
    pub fn find(&self, input: &[u8]) -> Result<Found, FfiError> {
        let search_key = self.search_key(input)?;
        let (proof, head) = self.lookup(&search_key)?;
        let entry = proof
            .verify(&search_key, &self.vrf_key()?, &head)
            .map_err(|_| FfiError::Unverified)?
            .map(<[u8]>::to_vec);
        Ok(Found {
            entry,
            version: proof.newest,
        })
    }

    /// One first-party token of this epoch, under a proof of work
    /// (`ABU-076`). The issuer key comes from the log (`ABU-002`).
    pub fn token(&self) -> Result<Vec<u8>, FfiError> {
        let epoch = epoch_number(unix_now());
        let input = issuer_label_input(TYPE_FIRST_PARTY, epoch);
        let search_key = self.search_key(&input)?;
        let (proof, head) = self.lookup(&search_key)?;
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

    /// Registers the first version of a label under a token (`DIS-101`).
    pub fn register(&self, input: &[u8], entry: &[u8]) -> Result<(), FfiError> {
        let token = self.token()?;
        let body =
            dirclient::register_body(&token, input, entry).map_err(|_| FfiError::Malformed)?;
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
}

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

impl Handle {
    /// The route to the directory, for a device that owns its channels.
    fn directory_link(&self) -> Result<DirectoryLink, FfiError> {
        let inner = locked(&self.inner);
        // DEV-287: a linked device makes no contact of its own.
        if !inner.owns_channels {
            return Err(FfiError::NotFound);
        }
        inner.directory.clone().ok_or(FfiError::Offline)
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
            if let Some(made) = locked(&self.inner).rendezvous_ready.remove(&tag) {
                return Ok(made);
            }
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
        let (queue, rendezvous) = self.new_rendezvous()?;
        let registered = (|| {
            let key = locked(&self.inner).client.entry_key(kind, index, 0)?;
            let address = QueueAddress::parse(&rendezvous).map_err(|_| FfiError::Malformed)?;
            let entry = entry_of(&key, address)?;
            link.register(&label, &entry)
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
        };
        locked(&self.inner)
            .client
            .put_published(&entry, &mut OsRng)?;
        Ok(entry)
    }

    /// Writes the tombstone of an entry (`DIS-171`) and ends its queue.
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
        let mut inner = locked(&self.inner);
        // NTF-043: the handle of the queue goes with it.
        let _ = inner.client.unbind_queue(&entry.queue, &mut OsRng);
        inner.client.drop_published(&entry.id)?;
        Ok(())
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
                Ok(entry) => return Ok(via_text(&entry)),
                // A held label: another discriminator.
                Err(FfiError::Stale) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(FfiError::Stale)
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
        self.retire(&link, &entry)
    }

    /// Sends a contact request to a reusable link, an `umbra:pub:` string,
    /// or a handle (Part 4 §4.3.3). The call looks the entry up under the
    /// log, and the hello leaves when the runtime has made its queue. A
    /// [`FfiEvent::Contact`] follows when the addressee accepts.
    pub fn send_contact_request(&self, target: String) -> Result<(), FfiError> {
        let link = self.directory_link()?;
        let target = target.trim();
        let (entry_pk, rendezvous) = if target.starts_with("@") {
            let handle =
                DirHandle::parse(target, &username_case_mapped).map_err(|_| FfiError::Malformed)?;
            let input = handle.label_input();
            let found = link.find(&input)?;
            let bytes = found.entry.ok_or(FfiError::NotFound)?;
            let entry = DirectoryEntry::parse(&bytes).map_err(|_| FfiError::Unverified)?;
            if entry.handle != input || Some(entry.version) != found.version {
                return Err(FfiError::Unverified);
            }
            let rendezvous = entry.rendezvous.ok_or(FfiError::NotFound)?;
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
        let profile = inner.client.profile_name()?.into_bytes();
        let bridge = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(bridge.hello(entry_pk.to_vec(), encoded, profile)?)
    }

    /// The name that a contact request of this device shows.
    pub fn profile_name(&self) -> Result<String, FfiError> {
        Ok(locked(&self.inner).client.profile_name()?)
    }

    /// Sets that name, at most 32 bytes.
    pub fn set_profile_name(&self, name: String) -> Result<(), FfiError> {
        Ok(locked(&self.inner)
            .client
            .set_profile_name(&name, &mut OsRng)?)
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
        let link = self.directory_link()?;
        let now = unix_now();
        let entries = locked(&self.inner).client.published()?;
        for entry in entries {
            if entry.expires_at != 0 && now >= entry.expires_at {
                // A write in the same epoch waits for the next call.
                let _ = self.retire(&link, &entry);
                continue;
            }
            if now.saturating_sub(entry.renewed_at) < RENEW_EVERY {
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
}
