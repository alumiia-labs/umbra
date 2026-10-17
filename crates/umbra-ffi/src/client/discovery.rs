//! The entries that this device publishes in the directory of Part 9, the
//! rendezvous queue of each one, and the contact requests that arrive on
//! those queues (§9.6).
//!
//! A reusable link is a Public Address of Part 4 §4.3.2 at its own index
//! `j`, and a timed link is one whose device retires its entry at the end
//! of its period (`DIS-171`). A handle is the `DirectoryEntry` of §9.3 under
//! `HandleKey_{0,r}`. Each entry has its own rendezvous queue (`DIS-106`).

use umbra_core::{
    abuse::{epoch_number, pow::PowSolution},
    discovery::{
        head::LogKeySet,
        hello::{self, HelloBody},
        profile::{is_plain_name, is_plain_note, ProfilePlain},
        HELLO_INBOUND_LIMIT,
    },
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{kem::KeyPair, rand_core::CryptoRng};
use umbra_wire::admission::AdmissionKind;
use zeroize::Zeroizing;

use super::Client;
use crate::Error;

/// The stored form of each rendezvous queue, under its `RecipientId`.
pub(crate) const RENDEZVOUS_STATE: TableId = TableId(0x27);
/// Each entry that this device publishes, under its identifier.
pub(super) const PUBLISHED: TableId = TableId(0x28);
/// Each contact request that waits for the user, under its identifier.
pub(super) const REQUESTS: TableId = TableId(0x29);
/// Each head of the log that this device accepted, under its `tree_size`
/// (`DIS-063`): the size, the root, the timestamp, and the time of the
/// acceptance.
const DIRECTORY_HEADS: TableId = TableId(0x2D);
const HEAD_ROW_LEN: usize = 8 + 32 + 8 + 8;

/// The next Public Address index. Profile 0 has no entry (Part 4 §4.2.5),
/// thus the first link takes index 1.
const NEXT_ADDRESS_SETTING: &[u8] = b"next-address-index";
/// The hellos shown for one entry in one epoch of Part 13 §13.6, before
/// the identifier of the entry.
const HELLO_COUNT_SETTING: &[u8] = b"hello-count/";
/// The name that a hello of this device shows.
const PROFILE_NAME_SETTING: &[u8] = b"profile-name";
/// The welcome text of the profile blob (§9.3.1).
const WELCOME_SETTING: &[u8] = b"profile-welcome";
/// The fragment of the profile link of the handle.
const FRAGMENT_SETTING: &[u8] = b"handle-fragment";
/// Whether the profile blob waits for a write.
const BLOB_DUE_SETTING: &[u8] = b"profile-blob-due";
/// The selected picture of the profile blob: a JPEG after the re-encode of
/// `DIS-001`.
const PICTURE_SETTING: &[u8] = b"profile-picture";
/// The newest `LogKeySet` that a signed rotation gave this device
/// (`DIS-199`).
const LOG_KEYSET_SETTING: &[u8] = b"log-keyset";

/// The longest name of a Profile (Part 4 §4.2.5).
pub const PROFILE_NAME_MAX: usize = 32;

/// The identity roots from before a reset that still give the key of a
/// published entry, in the local identity table (`DEV-306`). Each root
/// holds its seed, a count, and the name of each entry that it serves. The
/// directory holds the key of the earlier root for such an entry. Thus the
/// device needs that root to answer a hello, to renew, to rotate, and to
/// retire the entry. A name leaves the row with its entry, or when the log
/// shows a later rotation of its entry. A root leaves the row with its last
/// name. No write of the store alone takes a name out.
pub(super) const EARLIER_ROOTS_KEY: &[u8] = b"discovery-roots";
/// The name of an entry in that row: the kind, the index, the rotation.
const ENTRY_NAME_LEN: usize = 1 + 4 + 4;

type EntryName = [u8; ENTRY_NAME_LEN];
type EarlierRoot = (Zeroizing<[u8; 32]>, Vec<EntryName>);

fn entry_name(kind: EntryKind, index: u32, rotation: u32) -> EntryName {
    let mut name = [0u8; ENTRY_NAME_LEN];
    name[0] = match kind {
        EntryKind::Address => 1,
        EntryKind::Handle => 2,
    };
    name[1..5].copy_from_slice(&index.to_be_bytes());
    name[5..].copy_from_slice(&rotation.to_be_bytes());
    name
}

fn parse_earlier_roots(bytes: &[u8]) -> Result<Vec<EarlierRoot>, Error> {
    let mut r = Cursor(bytes);
    let mut roots = Vec::new();
    while !r.0.is_empty() {
        let seed = Zeroizing::new(r.array::<32>()?);
        let count = usize::from(u16::from_be_bytes(r.array()?));
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            names.push(r.array::<ENTRY_NAME_LEN>()?);
        }

        roots.push((seed, names));
    }

    Ok(roots)
}

fn encode_earlier_roots(roots: &[EarlierRoot]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(Vec::new());
    for (seed, names) in roots {
        out.extend_from_slice(seed.as_slice());
        let count = u16::try_from(names.len()).map_err(|_| Error::TooLong)?;
        out.extend_from_slice(&count.to_be_bytes());
        for name in names {
            out.extend_from_slice(name);
        }
    }

    Ok(out)
}

/// The form of an entry with no rotation of its queue yet.
const PUBLISHED_V1: u8 = 0x01;
/// The form with the time of the queue and the queue before it.
const PUBLISHED_VERSION: u8 = 0x02;
const REQUEST_VERSION: u8 = 0x01;

/// The kind of a published entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// An `AddressEntry` of Part 9 §9.3.3: a reusable link.
    Address,
    /// A `DirectoryEntry` of Part 9 §9.3: a handle.
    Handle,
}

/// One entry that this device publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The identifier of the row.
    pub id: [u8; 16],
    /// The kind.
    pub kind: EntryKind,
    /// The index `j`.
    pub index: u32,
    /// The rotation `r` of a handle key, 0 for an address.
    pub rotation: u32,
    /// The label input of Part 9 §9.10.
    pub label: Vec<u8>,
    /// The name that a challenge binds: the 20 bytes of an address, or the
    /// canonical handle (`DIS-108`).
    pub name: Vec<u8>,
    /// The `RecipientId` of the rendezvous queue.
    pub queue: [u8; 32],
    /// The encoded rendezvous `QueueAddress`.
    pub rendezvous: Vec<u8>,
    /// The newest version of the entry.
    pub version: u32,
    /// The time of the registration, in Unix seconds.
    pub created_at: u64,
    /// The end of a timed link, or 0 for none.
    pub expires_at: u64,
    /// The time of the last renewal of the lease.
    pub renewed_at: u64,
    /// The time of the write of the current queue, from which its next
    /// rotation counts (`DIS-133`).
    pub queue_since: u64,
    /// The queue that the last rotation replaced, and the end of its grace
    /// (`DIS-134`).
    pub previous: Option<([u8; 32], u64)>,
    /// Whether the directory shows a version of the label that this device
    /// did not write (`DIS-138`).
    pub foreign: bool,
}

impl Published {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut out = Zeroizing::new(vec![PUBLISHED_VERSION]);
        out.extend_from_slice(&self.id);
        out.push(match self.kind {
            EntryKind::Address => 1,
            EntryKind::Handle => 2,
        });
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.rotation.to_be_bytes());
        put_var(&mut out, &self.label)?;
        put_var(&mut out, &self.name)?;
        out.extend_from_slice(&self.queue);
        put_var(&mut out, &self.rendezvous)?;
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.renewed_at.to_be_bytes());
        out.extend_from_slice(&self.queue_since.to_be_bytes());
        match &self.previous {
            Some((queue, until)) => {
                out.push(1);
                out.extend_from_slice(queue);
                out.extend_from_slice(&until.to_be_bytes());
            }
            None => out.push(0),
        }

        out.push(u8::from(self.foreign));

        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Cursor(bytes);
        let version = r.u8()?;
        if version != PUBLISHED_VERSION && version != PUBLISHED_V1 {
            return Err(Error::Integrity);
        }

        let mut out = Published {
            id: r.array()?,
            kind: match r.u8()? {
                1 => EntryKind::Address,
                2 => EntryKind::Handle,
                _ => return Err(Error::Integrity),
            },
            index: u32::from_be_bytes(r.array()?),
            rotation: u32::from_be_bytes(r.array()?),
            label: r.var()?,
            name: r.var()?,
            queue: r.array()?,
            rendezvous: r.var()?,
            version: u32::from_be_bytes(r.array()?),
            created_at: u64::from_be_bytes(r.array()?),
            expires_at: u64::from_be_bytes(r.array()?),
            renewed_at: u64::from_be_bytes(r.array()?),
            queue_since: 0,
            previous: None,
            foreign: false,
        };
        if version == PUBLISHED_V1 {
            out.queue_since = out.created_at;
        } else {
            out.queue_since = u64::from_be_bytes(r.array()?);
            if r.u8()? == 1 {
                out.previous = Some((r.array()?, u64::from_be_bytes(r.array()?)));
            }

            out.foreign = r.u8()? == 1;
        }

        r.end()?;

        Ok(out)
    }
}

/// One contact request, as a view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRequest {
    /// The identifier of the row.
    pub id: [u8; 16],
    /// The entry that the hello reached.
    pub via: [u8; 16],
    /// The time of the arrival, in Unix seconds.
    pub received_at: u64,
    /// The name that the sender shows. No party checks it (Part 9 §9.8).
    pub name: String,
    /// The note that the sender wrote with the request, or empty.
    pub note: String,
    /// The JPEG picture of the sender, or empty.
    pub picture: Vec<u8>,
}

fn put_var(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        if self.0.len() < n {
            return Err(Error::Integrity);
        }

        let (head, rest) = self.0.split_at(n);
        self.0 = rest;

        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Integrity)
    }

    fn var(&mut self) -> Result<Vec<u8>, Error> {
        let len = usize::from(u16::from_be_bytes(self.array()?));
        Ok(self.take(len)?.to_vec())
    }

    fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Integrity)
        }
    }
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn put_row<R: CryptoRng + ?Sized>(
        &mut self,
        table: TableId,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(table, key);
        let mut batch = open.store.begin();
        batch.put(table, row, None, value, rng)?;
        Ok(batch.commit()?)
    }

    fn delete_row(&mut self, table: TableId, key: &[u8]) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row: RowId = open.store.row_id(table, key);
        let mut batch = open.store.begin();
        batch.delete(table, row);
        Ok(batch.commit()?)
    }

    fn get_row(&self, table: TableId, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(table, key);
        Ok(store.get(table, &row)?.map(Zeroizing::new))
    }

    /// The newest head of the log that this device accepted: its size, its
    /// root, and its timestamp.
    pub fn newest_head(&self) -> Result<Option<(u64, [u8; 32], u64)>, Error> {
        Ok(self
            .held_heads()?
            .into_iter()
            .max_by_key(|(size, _, _)| *size))
    }

    /// Each head of the log that this device keeps (`DIS-063`): its size,
    /// its root, and its timestamp.
    pub fn held_heads(&self) -> Result<Vec<(u64, [u8; 32], u64)>, Error> {
        let store = &self.open_ref()?.store;
        let mut heads = Vec::new();
        for (_, plain) in store.list(DIRECTORY_HEADS, None)? {
            let plain = Zeroizing::new(plain);
            if plain.len() != HEAD_ROW_LEN {
                return Err(Error::Integrity);
            }

            let mut r = Cursor(&plain);
            let size = u64::from_be_bytes(r.array()?);
            let root = r.array()?;
            let timestamp = u64::from_be_bytes(r.array()?);
            heads.push((size, root, timestamp));
        }

        Ok(heads)
    }

    /// Keeps a head that this device accepted, and drops each other head
    /// after `TREE_HEAD_RETAIN` (`DIS-063`).
    pub fn keep_head<R: CryptoRng + ?Sized>(
        &mut self,
        size: u64,
        root: &[u8; 32],
        timestamp: u64,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(DIRECTORY_HEADS, &size.to_be_bytes());
        let mut stale = Vec::new();
        for (held_row, plain) in open.store.list(DIRECTORY_HEADS, None)? {
            let accepted_at = plain
                .get(48..56)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(Error::Integrity)?;
            let retained = accepted_at.saturating_add(umbra_core::discovery::TREE_HEAD_RETAIN);
            if held_row != row && now >= retained {
                stale.push(held_row);
            }
        }

        let value = [
            size.to_be_bytes().as_slice(),
            root,
            &timestamp.to_be_bytes(),
            &now.to_be_bytes(),
        ]
        .concat();
        let mut batch = open.store.begin();
        batch.put(DIRECTORY_HEADS, row, None, &value, rng)?;
        for held in stale {
            batch.delete(DIRECTORY_HEADS, held);
        }

        Ok(batch.commit()?)
    }

    /// The key set of the log that this device holds: the stored set of a
    /// signed rotation when its epoch is above the one of `pinned`, the
    /// genesis set of the build, and else `pinned` (`DIS-066`, `DIS-199`).
    pub fn log_keyset(&self, pinned: &[u8]) -> Result<Vec<u8>, Error> {
        let epoch = |bytes: &[u8]| {
            LogKeySet::parse(bytes)
                .ok()
                .map(|(set, _)| set.keyset_epoch)
        };

        Ok(match self.get_row(super::SETTINGS, LOG_KEYSET_SETTING)? {
            Some(held) if epoch(&held) > epoch(pinned) => held.to_vec(),
            _ => pinned.to_vec(),
        })
    }

    /// Keeps a key set of the log that a signed rotation gave.
    pub fn keep_log_keyset<R: CryptoRng + ?Sized>(
        &mut self,
        keyset: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        LogKeySet::parse(keyset).map_err(|_| Error::Malformed)?;
        self.put_row(super::SETTINGS, LOG_KEYSET_SETTING, keyset, rng)
    }

    /// Each entry that this device publishes, oldest first.
    pub fn published(&self) -> Result<Vec<Published>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (_, plain) in store.list(PUBLISHED, None)? {
            out.push(Published::parse(&Zeroizing::new(plain))?);
        }

        out.sort_by_key(|entry| entry.created_at);

        Ok(out)
    }

    /// Keeps an entry. The row of the earlier roots stays as it is
    /// (`DEV-306`). The store takes a version before the directory does,
    /// thus a write here is no proof that the directory holds its key. A
    /// write that the directory refused puts the version before it back.
    pub fn put_published<R: CryptoRng + ?Sized>(
        &mut self,
        entry: &Published,
        rng: &mut R,
    ) -> Result<(), Error> {
        let plain = entry.encode()?;
        self.put_row(PUBLISHED, &entry.id, &plain, rng)
    }

    /// Takes each name of an earlier root that the entry `id` holds no more
    /// (`DEV-306`). The caller runs it after the log showed the held
    /// version of that entry under its key. The directory holds the key of
    /// the held rotation from then, thus no write and no renewal needs the
    /// key before it. An earlier root leaves the store with its last name.
    pub fn confirm_published<R: CryptoRng + ?Sized>(
        &mut self,
        id: &[u8; 16],
        rng: &mut R,
    ) -> Result<(), Error> {
        let published = self.published()?;
        let Some(kept) = self.used_earlier_roots(&published, Some(id))? else {
            return Ok(());
        };

        if kept.is_empty() {
            self.delete_row(TableId::LOCAL_IDENTITY, EARLIER_ROOTS_KEY)
        } else {
            let value = encode_earlier_roots(&kept)?;
            self.put_row(TableId::LOCAL_IDENTITY, EARLIER_ROOTS_KEY, &value, rng)
        }
    }

    /// Drops an entry and each request that it brought. DEV-306: the names
    /// of the entry leave the earlier roots in the same commit, and a root
    /// with no name goes. Thus a later entry at the same index takes the
    /// key of the current root.
    pub fn drop_published<R: CryptoRng + ?Sized>(
        &mut self,
        id: &[u8; 16],
        rng: &mut R,
    ) -> Result<(), Error> {
        let requests: Vec<[u8; 16]> = self
            .contact_requests()?
            .into_iter()
            .filter(|request| request.via == *id)
            .map(|request| request.id)
            .collect();
        let mut published = self.published()?;
        published.retain(|entry| entry.id != *id);
        let roots = match self.used_earlier_roots(&published, None)? {
            Some(kept) if kept.is_empty() => Some(None),
            Some(kept) => Some(Some(encode_earlier_roots(&kept)?)),
            None => None,
        };
        let open = self.open_mut()?;
        let roots_row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, EARLIER_ROOTS_KEY);
        let entry_row = open.store.row_id(PUBLISHED, id);
        let request_rows: Vec<RowId> = requests
            .iter()
            .map(|request| open.store.row_id(REQUESTS, request))
            .collect();
        let mut batch = open.store.begin();
        for row in request_rows {
            batch.delete(REQUESTS, row);
        }

        batch.delete(PUBLISHED, entry_row);
        match &roots {
            Some(Some(value)) => {
                batch.put(TableId::LOCAL_IDENTITY, roots_row, None, value, rng)?;
            }
            Some(None) => batch.delete(TableId::LOCAL_IDENTITY, roots_row),
            None => {}
        }

        Ok(batch.commit()?)
    }

    /// The identity roots from before a reset that still serve an entry.
    fn earlier_roots(&self) -> Result<Vec<EarlierRoot>, Error> {
        match self.get_row(TableId::LOCAL_IDENTITY, EARLIER_ROOTS_KEY)? {
            Some(bytes) => parse_earlier_roots(&bytes),
            None => Ok(Vec::new()),
        }
    }

    /// The stored row of the earlier roots, for a test.
    #[cfg(test)]
    pub(super) fn earlier_roots_row(&self) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        self.get_row(TableId::LOCAL_IDENTITY, EARLIER_ROOTS_KEY)
    }

    /// The row of the earlier roots after a reset at this moment. It holds
    /// each root that the row holds now, and the current root for each
    /// published entry that no earlier root serves. None when this device
    /// publishes no entry. The reset writes it in the commit of the new
    /// root.
    pub(super) fn roots_for_published(&self) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let mut roots = self.earlier_roots()?;
        let served: Vec<EntryName> = roots
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        let names: Vec<EntryName> = self
            .published()?
            .iter()
            .map(|entry| entry_name(entry.kind, entry.index, entry.rotation))
            .filter(|name| !served.contains(name))
            .collect();
        if !names.is_empty() {
            roots.push((self.root_seed()?, names));
        }
        if roots.is_empty() {
            return Ok(None);
        }

        encode_earlier_roots(&roots).map(Some)
    }

    /// The earlier roots with each name that an entry of `published` can
    /// still need, and no root with no name. None when the row holds
    /// exactly that already. An entry needs each name of its kind and its
    /// index. The name of its rotation gives its key. The name of the
    /// rotation before it signs the write of a rotation that the directory
    /// did not take yet. The entry `confirmed`, whose held version the log
    /// showed under its key, needs the name of its rotation alone.
    fn used_earlier_roots(
        &self,
        published: &[Published],
        confirmed: Option<&[u8; 16]>,
    ) -> Result<Option<Vec<EarlierRoot>>, Error> {
        let roots = self.earlier_roots()?;
        if roots.is_empty() {
            return Ok(None);
        }

        let is_needed = |name: &EntryName| {
            published.iter().any(|entry| {
                let own = entry_name(entry.kind, entry.index, entry.rotation);
                own[..5] == name[..5] && (own == *name || confirmed != Some(&entry.id))
            })
        };
        let kept: Vec<EarlierRoot> = roots
            .iter()
            .map(|(seed, names)| {
                let names: Vec<EntryName> = names
                    .iter()
                    .filter(|name| is_needed(name))
                    .copied()
                    .collect();
                (seed.clone(), names)
            })
            .filter(|(_, names)| !names.is_empty())
            .collect();
        let is_same = kept.len() == roots.len()
            && kept.iter().zip(&roots).all(|(a, b)| a.1.len() == b.1.len());

        Ok((!is_same).then_some(kept))
    }

    /// Takes the next Public Address index (`IDN-006`).
    pub fn take_address_index<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<u32, Error> {
        let index = match self.get_row(super::SETTINGS, NEXT_ADDRESS_SETTING)? {
            Some(bytes) => {
                u32::from_be_bytes(bytes.as_slice().try_into().map_err(|_| Error::Integrity)?)
            }
            None => 1,
        };
        let next = index.checked_add(1).ok_or(Error::TooLong)?;
        self.put_row(
            super::SETTINGS,
            NEXT_ADDRESS_SETTING,
            &next.to_be_bytes(),
            rng,
        )?;

        Ok(index)
    }

    /// The key of an entry: `PublicAddressKey_j` or `HandleKey_{j,r}`. An
    /// entry that this device published before a reset of the identity
    /// keeps the key of the root of that time (`DEV-306`). The directory
    /// holds that key until the device retires the entry or rotates its
    /// key.
    pub fn entry_key(&self, kind: EntryKind, index: u32, rotation: u32) -> Result<KeyPair, Error> {
        let name = entry_name(kind, index, rotation);
        let earlier = self
            .earlier_roots()?
            .into_iter()
            .find(|(_, names)| names.contains(&name));
        let root = match earlier {
            Some((seed, _)) => {
                umbra_crypto::hierarchy::RootIdentity::new(umbra_crypto::secret::Secret::new(*seed))
            }
            None => self.root_identity()?,
        };

        Ok(match kind {
            EntryKind::Address => root.public_address_key(index),
            EntryKind::Handle => root.handle_key(index, rotation),
        })
    }

    /// The name that a hello of this device shows, or an empty one.
    pub fn profile_name(&self) -> Result<String, Error> {
        Ok(self
            .get_row(super::SETTINGS, PROFILE_NAME_SETTING)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default())
    }

    /// Sets that name, at most `PROFILE_NAME_MAX` bytes. The profile blob
    /// of the handle takes it at the next write (§9.3.1).
    pub fn set_profile_name<R: CryptoRng + ?Sized>(
        &mut self,
        name: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        let name = name.trim();
        if name.len() > PROFILE_NAME_MAX {
            return Err(Error::TooLong);
        }

        // DIS-201: no control character, line break, or bidirectional
        // format character.
        if !is_plain_name(name) {
            return Err(Error::Malformed);
        }

        self.put_row(super::SETTINGS, PROFILE_NAME_SETTING, name.as_bytes(), rng)?;
        self.put_row(super::SETTINGS, BLOB_DUE_SETTING, &[1], rng)
    }

    /// The welcome text of the profile blob, or an empty one.
    pub fn welcome(&self) -> Result<String, Error> {
        Ok(self
            .get_row(super::SETTINGS, WELCOME_SETTING)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default())
    }

    /// Sets the welcome text, at most `WELCOME_MAX` bytes.
    pub fn set_welcome<R: CryptoRng + ?Sized>(
        &mut self,
        text: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        let text = text.trim();
        if text.len() > umbra_core::discovery::profile::WELCOME_MAX {
            return Err(Error::TooLong);
        }
        if !is_plain_note(text) {
            return Err(Error::Malformed);
        }

        self.put_row(super::SETTINGS, WELCOME_SETTING, text.as_bytes(), rng)?;
        self.put_row(super::SETTINGS, BLOB_DUE_SETTING, &[1], rng)
    }

    /// The selected picture of the profile, or an empty one for the
    /// generated picture of Part 4 §4.2.5.
    pub fn profile_picture(&self) -> Result<Vec<u8>, Error> {
        Ok(self
            .get_row(super::SETTINGS, PICTURE_SETTING)?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default())
    }

    /// Sets the picture, a JPEG of at most `PICTURE_MAX` bytes that the
    /// platform encoded anew (`DIS-001` to `DIS-003`), or none.
    pub fn set_profile_picture<R: CryptoRng + ?Sized>(
        &mut self,
        picture: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if picture.is_empty() {
            self.delete_row(super::SETTINGS, PICTURE_SETTING)?;
        } else {
            umbra_core::discovery::profile::ProfilePlain {
                name: "",
                welcome: "",
                picture,
            }
            .encode()
            .map_err(|_| Error::Malformed)?;
            self.put_row(super::SETTINGS, PICTURE_SETTING, picture, rng)?;
        }

        self.put_row(super::SETTINGS, BLOB_DUE_SETTING, &[1], rng)
    }

    /// The fragment of the profile link of the handle: drawn once, and kept
    /// until the handle goes (`DIS-179`).
    pub fn handle_fragment<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<[u8; umbra_core::discovery::handle::FRAGMENT_LEN], Error> {
        if let Some(held) = self.get_row(super::SETTINGS, FRAGMENT_SETTING)? {
            return held.as_slice().try_into().map_err(|_| Error::Integrity);
        }

        let mut fragment = [0u8; umbra_core::discovery::handle::FRAGMENT_LEN];
        rng.fill_bytes(&mut fragment);
        self.put_row(super::SETTINGS, FRAGMENT_SETTING, &fragment, rng)?;

        Ok(fragment)
    }

    /// Drops the fragment with the handle, thus a later handle takes a new
    /// link.
    pub fn drop_handle_fragment(&mut self) -> Result<(), Error> {
        self.delete_row(super::SETTINGS, FRAGMENT_SETTING)
    }

    /// Whether the profile blob waits for a write.
    pub fn profile_blob_due(&self) -> Result<bool, Error> {
        Ok(self.get_row(super::SETTINGS, BLOB_DUE_SETTING)?.is_some())
    }

    /// Marks the profile blob as written, or as due again.
    pub fn set_profile_blob_due<R: CryptoRng + ?Sized>(
        &mut self,
        due: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        if due {
            self.put_row(super::SETTINGS, BLOB_DUE_SETTING, &[1], rng)
        } else {
            self.delete_row(super::SETTINGS, BLOB_DUE_SETTING)
        }
    }

    /// Takes a hello from a rendezvous queue. The request waits for the user
    /// when the envelope opens under the key of its entry and its proof of
    /// work holds (`ABU-012`), and `HELLO_INBOUND_LIMIT` of the epoch is not
    /// reached. The result names the new request.
    pub fn on_hello<R: CryptoRng + ?Sized>(
        &mut self,
        queue: &[u8; 32],
        envelope: &[u8],
        now: u64,
        rng: &mut R,
    ) -> Result<Option<[u8; 16]>, Error> {
        // DIS-135: the queue that a rotation replaced takes hellos in its
        // grace too.
        let Some(entry) = self.published()?.into_iter().find(|entry| {
            entry.queue == *queue || entry.previous.is_some_and(|(held, _)| held == *queue)
        }) else {
            return Ok(None);
        };

        // DIS-174: a timed link takes no hello after its end, although its
        // queue waits for the upkeep of this device.
        if entry.expires_at != 0 && now >= entry.expires_at {
            return Ok(None);
        }

        let key = self.entry_key(entry.kind, entry.index, entry.rotation)?;
        let Ok(plain) = hello::open(&key, envelope) else {
            return Ok(None);
        };

        let plain = Zeroizing::new(plain);
        let Ok(body) = HelloBody::parse(&plain) else {
            return Ok(None);
        };

        // DIS-132: a cross-relay token that the log vouches for, or a proof
        // of work. ABU-079: a first-party token needs the secret of its
        // issuer, thus it admits no hello.
        let epoch = epoch_number(now);
        match body.admission.kind {
            AdmissionKind::Token => {
                if !self.admit_token(body.admission.body, epoch, rng)? {
                    return Ok(None);
                }
            }
            AdmissionKind::Pow => {
                let Ok(solution) = PowSolution::parse(body.admission.body) else {
                    return Ok(None);
                };

                let entry_pk = key.public().to_bytes();
                if umbra_core::abuse::pow::verify_hello(&entry_pk, epoch, &solution).is_err() {
                    return Ok(None);
                }
                if !self.admit_hello_work(&solution, epoch, rng)? {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        }

        // ABU-086: HELLO_INBOUND_LIMIT hellos for one entry in one epoch.
        let count_key = [HELLO_COUNT_SETTING, entry.id.as_slice()].concat();
        let count = match self.get_row(super::SETTINGS, &count_key)? {
            Some(bytes) => {
                let mut r = Cursor(&bytes);
                let held_epoch = u32::from_be_bytes(r.array()?);
                let held = u32::from_be_bytes(r.array()?);
                if held_epoch == epoch {
                    held
                } else {
                    0
                }
            }
            None => 0,
        };
        if count >= HELLO_INBOUND_LIMIT {
            // ABU-087: the view offers the rotation of the queue.
            self.events.push_back(super::Event::Conversations);
            return Ok(None);
        }

        let mut bundle = Zeroizing::new(vec![0u8; body.bundle.len()]);
        let used = body.bundle.encode(&mut bundle)?;
        bundle.truncate(used);

        // A second copy of one hello is no second request.
        let requests = self.stored_requests()?;
        if requests
            .iter()
            .any(|(_, held)| held.bundle.as_slice() == bundle.as_slice())
        {
            return Ok(None);
        }

        // DIS-180: the profile of the sender, or the bare name of a build
        // before it.
        let (name, note, picture) = match ProfilePlain::parse(body.profile) {
            Ok(profile) => (
                profile.name.to_owned(),
                profile.welcome.to_owned(),
                profile.picture.to_vec(),
            ),
            Err(_) => (
                core::str::from_utf8(body.profile)
                    .ok()
                    .filter(|name| name.len() <= PROFILE_NAME_MAX && is_plain_name(name))
                    .unwrap_or_default()
                    .to_owned(),
                String::new(),
                Vec::new(),
            ),
        };
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let mut value = Zeroizing::new(vec![REQUEST_VERSION]);
        value.extend_from_slice(&id);
        value.extend_from_slice(&entry.id);
        value.extend_from_slice(&now.to_be_bytes());
        put_var(&mut value, &bundle)?;
        put_var(&mut value, name.as_bytes())?;
        put_var(&mut value, note.as_bytes())?;
        put_var(&mut value, &picture)?;
        self.put_row(REQUESTS, &id, &value, rng)?;
        let mut counted = epoch.to_be_bytes().to_vec();
        counted.extend_from_slice(&(count + 1).to_be_bytes());
        self.put_row(super::SETTINGS, &count_key, &counted, rng)?;

        Ok(Some(id))
    }

    fn stored_requests(&self) -> Result<Vec<(ContactRequest, StoredRequest)>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for (_, plain) in store.list(REQUESTS, None)? {
            let plain = Zeroizing::new(plain);
            let mut r = Cursor(&plain);
            if r.u8()? != REQUEST_VERSION {
                return Err(Error::Integrity);
            }

            let id = r.array()?;
            let via = r.array()?;
            let received_at = u64::from_be_bytes(r.array()?);
            let bundle = Zeroizing::new(r.var()?);
            let name = String::from_utf8_lossy(&r.var()?).into_owned();

            // A row of an earlier build ends after the name.
            let (note, picture) = if r.0.is_empty() {
                (String::new(), Vec::new())
            } else {
                (
                    String::from_utf8_lossy(&r.var()?).into_owned(),
                    r.var()?.to_vec(),
                )
            };
            r.end()?;
            out.push((
                ContactRequest {
                    id,
                    via,
                    received_at,
                    name,
                    note,
                    picture,
                },
                StoredRequest { bundle },
            ));
        }

        out.sort_by_key(|(request, _)| request.received_at);

        Ok(out)
    }

    /// Whether an entry took `HELLO_INBOUND_LIMIT` hellos in the epoch of
    /// `now` (`ABU-086`), thus the view offers its rotation (`ABU-087`).
    pub fn is_at_hello_limit(&self, id: &[u8; 16], now: u64) -> Result<bool, Error> {
        let key = [HELLO_COUNT_SETTING, id.as_slice()].concat();
        let Some(bytes) = self.get_row(super::SETTINGS, &key)? else {
            return Ok(false);
        };

        let mut r = Cursor(&bytes);
        let epoch = u32::from_be_bytes(r.array()?);
        let count = u32::from_be_bytes(r.array()?);

        Ok(epoch == epoch_number(now) && count >= HELLO_INBOUND_LIMIT)
    }

    /// Each contact request that waits, oldest first.
    pub fn contact_requests(&self) -> Result<Vec<ContactRequest>, Error> {
        Ok(self
            .stored_requests()?
            .into_iter()
            .map(|(request, _)| request)
            .collect())
    }

    /// Takes a request from the store, and gives its bundle: the invitation
    /// that the device accepts (`DIS-087`).
    pub fn take_request(&mut self, id: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (_, held) = self
            .stored_requests()?
            .into_iter()
            .find(|(request, _)| request.id == *id)
            .ok_or(Error::NotFound)?;
        self.delete_row(REQUESTS, id)?;

        Ok(held.bundle)
    }

    /// Drops a request.
    pub fn decline_request(&mut self, id: &[u8; 16]) -> Result<(), Error> {
        self.delete_row(REQUESTS, id)
    }
}

struct StoredRequest {
    bundle: Zeroizing<Vec<u8>>,
}
