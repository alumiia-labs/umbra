//! The recovery code of Part 4 §4.7.1 and the encrypted backup of §4.7.2.
//!
//! The code is two independent CSPRNG outputs (`IDN-070`), and the store
//! keeps it beside the root seed. It leaves the core only as the digits of
//! §4.7.7, through a sink of the platform (`IMP-037`), and never as hex
//! (`IDN-041`).

use std::collections::{BTreeMap, BTreeSet};

use umbra_core::{
    attach::{
        segment::pad_handle_object,
        transfer::{ChunkCredential, Uploaded},
    },
    identity::{
        backup::{BackupObject, BackupRow, KIND_DELTA, KIND_FULL},
        recovery::{
            to_digits, BackupEntry, BackupRoot, BackupRootKey, DigitsType, EpochCredentials,
            RecoveryCode,
        },
        BACKUP_EARLY_INTERVAL, BACKUP_EARLY_WINDOW, BACKUP_FULL_INTERVAL, BACKUP_HISTORY_DAYS,
        BACKUP_INTERVAL, BACKUP_ROOT_ENTRIES,
    },
    session::dead::week_of,
    store::{
        engine::Backend,
        record::{RowId, RowKey, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{
    hash::sha3_256,
    hierarchy::RootIdentity,
    rand_core::CryptoRng,
    secret::Secret,
    stored::{Reader, Writer},
    x25519::{PublicKey as XPublic, StaticSecret},
    zeroize::Zeroizing,
};

use super::{devices::RowWrite, Client};
use crate::{Error, Sink};

/// The row of the recovery code in the local identity table.
const RECOVERY_CODE_KEY: &[u8] = b"recovery-code";

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The recovery code of this device. A store that holds none makes one
    /// now: a store of a build before the code, or a new one (`IDN-070`).
    pub fn recovery_code<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<RecoveryCode, Error> {
        let open = self.open_mut()?;
        let row = open
            .store
            .row_id(TableId::LOCAL_IDENTITY, RECOVERY_CODE_KEY);
        if let Some(bytes) = open.store.get(TableId::LOCAL_IDENTITY, &row)? {
            let bytes = Zeroizing::new(bytes);
            return Ok(RecoveryCode::from_bytes(&bytes)?);
        }

        // IDN-070: two independent outputs of the CSPRNG.
        let mut user = Secret::new([0u8; 16]);
        rng.fill_bytes(user.expose_mut());
        let mut social = Secret::new([0u8; 16]);
        rng.fill_bytes(social.expose_mut());
        let code = RecoveryCode::new(user, social);
        let mut batch = open.store.begin();
        batch.put(
            TableId::LOCAL_IDENTITY,
            row,
            None,
            code.bytes().expose(),
            rng,
        )?;
        batch.commit()?;

        Ok(code)
    }

    /// Writes the recovery code into `sink` as `RecoveryDigits` of type
    /// `0x0001`, 87 digits in groups of five (`IDN-149`).
    pub fn render_recovery_code<R: CryptoRng + ?Sized>(
        &mut self,
        sink: &mut dyn Sink,
        rng: &mut R,
    ) -> Result<(), Error> {
        let code = self.recovery_code(rng)?;
        let digits = to_digits(DigitsType::Code, code.bytes().expose())?;
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(digits.encode_utf16().collect());
        sink.put(&units);
        Ok(())
    }

    /// The writes that give this device a new recovery code and no state
    /// of a backup (`DEV-316`). The absent device held the code before.
    /// The next backup is a full object under a root that the absent
    /// device cannot derive.
    pub(super) fn new_recovery_code_writes<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<RowWrite>, Error> {
        let store = &self.open_ref()?.store;

        // IDN-070: two independent outputs of the CSPRNG.
        let mut code = Zeroizing::new(vec![0u8; 32]);
        let (user, social) = code.split_at_mut(16);
        rng.fill_bytes(user);
        rng.fill_bytes(social);
        let mut writes = vec![
            RowWrite::Put(
                TableId::LOCAL_IDENTITY,
                store.row_id(TableId::LOCAL_IDENTITY, RECOVERY_CODE_KEY),
                code,
            ),
            RowWrite::Delete(BACKUP_STATE, store.row_id(BACKUP_STATE, STATE_KEY)),
            RowWrite::Delete(BACKUP_STATE, store.row_id(BACKUP_STATE, ROOT_KEY_KEY)),
        ];
        for (row, _) in store.list(BACKUP_INDEX, None)? {
            writes.push(RowWrite::Delete(BACKUP_INDEX, row));
        }

        Ok(writes)
    }
}

/// The hash of each row that the last backup object carried, by the table
/// and the surrogate identifier of the row: a delta holds the rows whose
/// hash moved and the rows that left (`IDN-179`).
const BACKUP_INDEX: TableId = TableId(0x1F);
/// The state of the backup of this device: the schedule and the entries of
/// the root with the credentials of their chunks. A backup carries neither.
const BACKUP_STATE: TableId = TableId(0x20);
const STATE_KEY: &[u8] = b"backup-state";
/// `BackupRootKey`, which the KDF of `IDN-177` gives once for the device.
const ROOT_KEY_KEY: &[u8] = b"backup-root-key";
const INDEX_VALUE_LEN: usize = 1 + 16 + 32;

/// The tables that a backup carries (`IDN-179`). Invitations, push
/// registrations, the dead-channel state, the files, and the state of the
/// backup itself stay on the device (`IDN-180`). The state of each file goes
/// as one that waits for a tap (`IDN-186`). A timed record stays, and the
/// timer of its conversation goes (`DEV-215`). The published entries go
/// with their rendezvous queues, thus a restored handle keeps its current
/// `r` (`IDN-108`); blocks and held handle keys go as the user set them.
/// The forward policy and the pet-avatar of each contact go too, thus a
/// restore and a link keep them (`DEV-324`, `DEV-328`).
const BACKED_UP: [TableId; 39] = [
    super::files::FILE_STATE,
    TableId::MESSAGE,
    TableId::TOMBSTONE,
    TableId::CONTACT,
    TableId::QUEUE,
    TableId::VERIFICATION,
    TableId::LOCAL_IDENTITY,
    super::OUTBOX,
    super::CONVERSATION,
    super::SETTINGS,
    super::RECEIPT,
    super::PENDING,
    super::REVISION,
    super::REACTION,
    super::groups::GROUP,
    super::groups::GROUP_QUEUE,
    super::groups::GROUP_JOIN,
    super::groups::GROUP_MEMBER,
    super::groups::GROUP_PRESENCE,
    super::groups::GROUP_OWNERS,
    super::groups::GROUP_GRANTS,
    super::timers::TIMERS,
    super::polls::POLLS,
    super::polls::VOTES,
    super::groups::MENTIONED,
    super::moderation::MODERATED,
    super::moderation::MOD_NOTES,
    super::group_changes::GROUP_SENDER,
    super::roster_notes::ROSTER_NOTES,
    super::key_changes::KEY_CHANGES,
    super::reset::RESET_NOTICES,
    super::social::SHARES_HELD,
    super::social::SHARES_GIVEN,
    super::discovery::PUBLISHED,
    super::discovery::RENDEZVOUS_STATE,
    super::block::BLOCKED,
    super::held_handles::HELD_HANDLES,
    super::forward::FORWARD_POLICY,
    super::pictures::PET_AVATARS,
];

/// A backup object that is due: its bytes, which go up as a file of the
/// backup class, and what its upload commits.
pub struct BackupUpload {
    /// The encoded `BackupObject`.
    pub plain: Zeroizing<Vec<u8>>,
    /// What the upload commits.
    pub pending: PendingBackup,
}

/// A backup object that goes up, with the index that its upload commits.
pub struct PendingBackup {
    kind: u8,
    written_at: u64,
    index: Vec<(RowId, Option<Vec<u8>>)>,
}

impl PendingBackup {
    /// Whether the object is a full one.
    pub fn is_full(&self) -> bool {
        self.kind == KIND_FULL
    }
}

/// The write of the backup root of the week (`IDN-093`, `IDN-098`), and
/// the chunks that go after it (`IDN-099`).
pub struct RootWrite {
    /// `backup_handle_epoch`, the `chunk_id` of the root.
    pub handle: [u8; 32],
    /// `backup_write_cred`.
    pub cred: Secret<32>,
    /// The public half of `backup_read_cred`.
    pub read_pk: [u8; 32],
    /// The sealed and padded root.
    pub chunk: Vec<u8>,
    /// The chunks of each object that the new root names no more. They go
    /// after the root is written.
    pub erase: Vec<ChunkCredential>,
}

struct StoredEntry {
    kind: u8,
    descriptor: Vec<u8>,
    credentials: Vec<ChunkCredential>,
}

#[derive(Default)]
struct BackupState {
    next_full_at: u64,
    next_delta_at: u64,
    last_written_at: u64,
    entries: Vec<StoredEntry>,
    /// The time of the first backup write of this install, or zero for a
    /// state that an earlier version wrote.
    first_written_at: u64,
}

impl BackupState {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut writer = Writer::new();
        writer.u64(self.next_full_at);
        writer.u64(self.next_delta_at);
        writer.u64(self.last_written_at);
        writer.u8(u8::try_from(self.entries.len()).map_err(|_| Error::Integrity)?);
        for entry in &self.entries {
            writer.u8(entry.kind);
            writer.var(&entry.descriptor)?;
            writer.u32(u32::try_from(entry.credentials.len()).map_err(|_| Error::Integrity)?);
            for credential in &entry.credentials {
                writer.bytes(&credential.chunk_id);
                writer.bytes(credential.cred.expose());
                writer.u8(u8::try_from(credential.relays.len()).map_err(|_| Error::Integrity)?);
                for relay in &credential.relays {
                    writer.bytes(relay);
                }
            }
        }

        writer.u64(self.first_written_at);

        Ok(writer.finish())
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        let next_full_at = reader.u64()?;
        let next_delta_at = reader.u64()?;
        let last_written_at = reader.u64()?;
        let count = reader.u8()?;
        let mut entries = Vec::new();
        for _ in 0..count {
            let kind = reader.u8()?;
            let descriptor = reader.var()?.to_vec();
            let mut credentials = Vec::new();
            for _ in 0..reader.u32()? {
                let chunk_id = reader.array()?;
                let cred = Secret::new(reader.array()?);
                let mut relays = Vec::new();
                for _ in 0..reader.u8()? {
                    relays.push(reader.array()?);
                }

                credentials.push(ChunkCredential {
                    chunk_id,
                    cred,
                    relays,
                });
            }

            entries.push(StoredEntry {
                kind,
                descriptor,
                credentials,
            });
        }

        // A state of an earlier version ends after the entries.
        let first_written_at = if reader.end().is_ok() {
            0
        } else {
            reader.u64()?
        };
        reader.end()?;

        Ok(BackupState {
            next_full_at,
            next_delta_at,
            last_written_at,
            entries,
            first_written_at,
        })
    }
}

/// The time of the next write of an interval: a uniform draw over one
/// interval, centered on it, thus the time follows no act of the user
/// (`IDN-048`, `IDN-081`).
fn next_write<R: CryptoRng + ?Sized>(now: u64, interval: u64, rng: &mut R) -> u64 {
    let mut draw = [0u8; 8];
    rng.fill_bytes(&mut draw);
    now.saturating_add(interval / 2)
        .saturating_add(u64::from_be_bytes(draw) % interval.max(1))
}

fn index_key(table: TableId, row: &RowId) -> Vec<u8> {
    [&[table.0][..], row].concat()
}

fn row_hash(table: TableId, row: &RowId, owner: Option<&RowId>, plain: &[u8]) -> [u8; 32] {
    let owner_part: &[u8] = owner.map_or(&[0u8][..], |owner| owner.as_slice());
    let flag = [u8::from(owner.is_some())];
    sha3_256(&[
        b"umbra/backup-index",
        &[table.0],
        row,
        &flag,
        owner_part,
        plain,
    ])
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn backup_state(&self) -> Result<Option<BackupState>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(BACKUP_STATE, STATE_KEY);
        match store.get(BACKUP_STATE, &row)? {
            Some(bytes) => Ok(Some(BackupState::parse(&Zeroizing::new(bytes))?)),
            None => Ok(None),
        }
    }

    /// The time of the last backup object that went up, or none.
    pub fn last_backup_at(&self) -> Result<Option<u64>, Error> {
        Ok(self
            .backup_state()?
            .map(|state| state.last_written_at)
            .filter(|at| *at != 0))
    }

    /// The four values of the weekly epoch `week` (§4.7.2). The KDF of
    /// `IDN-177` runs once, and the state of the backup keeps its result.
    pub fn backup_credentials<R: CryptoRng + ?Sized>(
        &mut self,
        week: u32,
        rng: &mut R,
    ) -> Result<EpochCredentials, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(BACKUP_STATE, ROOT_KEY_KEY);
        if let Some(bytes) = store.get(BACKUP_STATE, &row)? {
            let bytes = Zeroizing::new(bytes);
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Integrity)?;
            return Ok(BackupRootKey::from_secret(Secret::new(key)).epoch(week));
        }

        let key = self.recovery_code(rng)?.backup_root_key()?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(
            BACKUP_STATE,
            row,
            None,
            key.expose_for_store().expose(),
            rng,
        )?;
        batch.commit()?;

        Ok(key.epoch(week))
    }

    /// Whether a row of a carried table stays on the device: a setting of
    /// this device alone (`IDN-180`), or a message older than
    /// `BACKUP_HISTORY_DAYS` (`IDN-082`).
    fn stays(
        &self,
        table: TableId,
        row: &RowId,
        owner: Option<&RowId>,
        plain: &[u8],
        now: u64,
        device_peers: &BTreeSet<RowId>,
    ) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;

        // DEV-286: a sync channel belongs to this device alone.
        if device_peers.contains(row) || owner.is_some_and(|owner| device_peers.contains(owner)) {
            return Ok(true);
        }

        if table == super::SETTINGS {
            let local = [
                super::notify::PUSH_TOKEN_SETTING,
                super::notify::CONTACT_SET_SETTING,
                super::INGRESS_PINS_SETTING,
                super::AUTO_DOWNLOAD_SETTING,
                super::UNMETERED_ONLY_SETTING,
                super::devices::PENDING_PEER_SETTING,
                super::devices::SYNC_BUNDLE_SETTING,
                super::devices::LINK_FLOOR_SETTING,
                super::devices::DEVICE_INVITES_SETTING,
                RESTORE_STALE_SETTING,
            ];
            return Ok(local
                .iter()
                .any(|key| store.row_id(super::SETTINGS, key) == *row));
        }

        // DEV-215: a timed record enters no store but the local database,
        // and each row of it stays with it.
        let message = if table == super::REACTION {
            match (owner, plain.get(16..32)) {
                (Some(conversation), Some(reference)) => {
                    let natural = [conversation.as_slice(), reference].concat();
                    Some(store.row_id(TableId::MESSAGE, &natural))
                }
                _ => None,
            }
        } else if table == super::polls::VOTES {
            plain.get(16..32).and_then(|poll| poll.try_into().ok())
        } else if [
            TableId::MESSAGE,
            super::OUTBOX,
            super::REVISION,
            super::files::FILE_STATE,
            super::polls::POLLS,
            super::groups::MENTIONED,
            super::moderation::MODERATED,
            super::group_changes::GROUP_SENDER,
        ]
        .contains(&table)
        {
            Some(*row)
        } else {
            None
        };
        if let Some(message) = message {
            if store.get(super::timers::DEADLINES, &message)?.is_some() {
                return Ok(true);
            }
        }
        if table == TableId::MESSAGE {
            if let Ok(info) = super::info_of(plain) {
                let age_ms = now.saturating_mul(1_000).saturating_sub(info.stored_at_ms);
                return Ok(age_ms > BACKUP_HISTORY_DAYS * 86_400 * 1_000);
            }
        }

        Ok(false)
    }

    /// Whether a backup and the snapshot of a link carry the list of the
    /// sync invitations at `now`, and whether they carry another setting.
    #[cfg(test)]
    pub(crate) fn backup_rows_for_test(&self, now: u64) -> (bool, bool) {
        let Ok(open) = self.open_ref() else {
            return (false, false);
        };

        let list = open
            .store
            .row_id(super::SETTINGS, super::devices::DEVICE_INVITES_SETTING);
        let rows = self
            .carried_rows(now, &[super::SETTINGS])
            .unwrap_or_default();
        let is_list = |row: &BackupRow| matches!(row, BackupRow::Put { row, .. } if *row == list);
        (
            rows.iter().any(is_list),
            rows.iter().any(|row| !is_list(row)),
        )
    }

    /// Each row of `tables` that a backup carries at `now`.
    fn carried_rows(&self, now: u64, tables: &[TableId]) -> Result<Vec<BackupRow>, Error> {
        let device_peers: BTreeSet<RowId> = self
            .device_peers()?
            .into_iter()
            .map(|conversation| conversation.0)
            .collect();
        let mut current: Vec<BackupRow> = Vec::new();
        for &table in tables {
            let rows = self.open_ref()?.store.list_owned(table)?;
            for (row, owner, plain) in rows {
                let mut plain = Zeroizing::new(plain);
                if table == super::files::FILE_STATE {
                    super::files::carried_state(&mut plain);
                }
                if !self.stays(table, &row, owner.as_ref(), &plain, now, &device_peers)? {
                    current.push(BackupRow::Put {
                        table,
                        row,
                        owner,
                        plain,
                    });
                }
            }
        }

        Ok(current)
    }

    /// The snapshot of a link (Part 7 `DEV-004`): one full backup object,
    /// which touches neither the index nor the schedule of the backup, with
    /// the rows of the link. A record that waits to go stays here, since its
    /// sender is this device (`DEV-287`).
    pub fn link_snapshot(
        &self,
        now: u64,
        roster: &[u8],
        sync_bundle: &[u8],
        sync_floor: u64,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let tables: Vec<TableId> = BACKED_UP
            .into_iter()
            .filter(|table| *table != super::OUTBOX)
            .collect();
        let mut rows = self.carried_rows(now, &tables)?;

        // The recovery code opens each later backup, thus a device that the
        // user removes later must not hold it (§7.7). The device that owns
        // the channels writes the backups and keeps the code.
        let code = self
            .open_ref()?
            .store
            .row_id(TableId::LOCAL_IDENTITY, RECOVERY_CODE_KEY);
        rows.retain(|row| {
            !matches!(
                row,
                BackupRow::Put { table, row, .. }
                    if *table == TableId::LOCAL_IDENTITY && *row == code
            )
        });
        rows.extend(self.link_rows(roster, sync_bundle, sync_floor)?);
        let object = BackupObject {
            kind: KIND_FULL,
            written_at: now,
            base_at: 0,
            rows,
        };

        Ok(object.encode()?)
    }

    /// The backup object that is due at `now`, in the foreground only
    /// (`IDN-080`): a full object at `BACKUP_FULL_INTERVAL`, and a delta at
    /// `BACKUP_INTERVAL` between two full ones (`IDN-078`, `IDN-079`). A
    /// delta with no row goes too, thus the cadence shows no activity.
    pub fn backup_due(
        &mut self,
        now: u64,
        is_foreground: bool,
    ) -> Result<Option<BackupUpload>, Error> {
        if !is_foreground {
            return Ok(None);
        }

        let state = self.backup_state()?;
        let kind = match &state {
            None => KIND_FULL,
            Some(state) if now >= state.next_full_at => KIND_FULL,
            Some(state) if state.entries.len() >= BACKUP_ROOT_ENTRIES => KIND_FULL,
            Some(state) if now >= state.next_delta_at && !state.entries.is_empty() => KIND_DELTA,
            Some(_) => return Ok(None),
        };
        let current = self.carried_rows(now, &BACKED_UP)?;
        let store = &self.open_ref()?.store;
        let mut indexed: BTreeMap<RowId, Vec<u8>> = BTreeMap::new();
        for (key, value) in store.list(BACKUP_INDEX, None)? {
            indexed.insert(key, value);
        }

        let mut rows = Vec::new();
        let mut index = Vec::new();
        let mut kept: BTreeSet<RowId> = BTreeSet::new();
        for put in current {
            let BackupRow::Put {
                table,
                row,
                owner,
                plain,
            } = &put
            else {
                continue;
            };
            let (table, row) = (*table, *row);
            let hash = row_hash(table, &row, owner.as_ref(), plain);
            let key = store.row_id(BACKUP_INDEX, &index_key(table, &row));
            kept.insert(key);
            let value = [&[table.0][..], &row, &hash].concat();
            let is_same = indexed.get(&key).is_some_and(|held| *held == value);
            if kind == KIND_DELTA && is_same {
                continue;
            }

            if !is_same {
                index.push((key, Some(value)));
            }

            rows.push(put);
        }

        for (key, value) in &indexed {
            if kept.contains(key) {
                continue;
            }

            index.push((*key, None));
            if kind == KIND_DELTA && value.len() == INDEX_VALUE_LEN {
                let table = TableId(value.first().copied().ok_or(Error::Integrity)?);
                let row: RowId = value
                    .get(1..17)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?;
                rows.push(BackupRow::Delete { table, row });
            }
        }

        let base_at = match (&state, kind) {
            (Some(state), KIND_DELTA) => state.last_written_at,
            _ => 0,
        };
        let object = BackupObject {
            kind,
            written_at: now,
            base_at,
            rows,
        };

        Ok(Some(BackupUpload {
            plain: object.encode()?,
            pending: PendingBackup {
                kind,
                written_at: now,
                index,
            },
        }))
    }

    /// The object of `pending` is at the relays: its index commits, the
    /// schedule moves, and the root of the week names it with the objects
    /// before it. A full object replaces each entry, and their chunks go
    /// after the new root (`IDN-097` to `IDN-099`).
    pub fn backup_uploaded<R: CryptoRng + ?Sized>(
        &mut self,
        pending: PendingBackup,
        uploaded: &Uploaded,
        consensus_epoch: u64,
        rng: &mut R,
    ) -> Result<RootWrite, Error> {
        let held = self.backup_state()?;
        let is_first = held.is_none();
        let mut state = held.unwrap_or_default();
        let mut descriptor = alloc_vec(uploaded.descriptor.len());
        uploaded.descriptor.encode(&mut descriptor)?;
        let entry = StoredEntry {
            kind: pending.kind,
            descriptor,
            credentials: uploaded
                .credentials
                .iter()
                .map(|credential| ChunkCredential {
                    chunk_id: credential.chunk_id,
                    cred: Secret::new(*credential.cred.expose()),
                    relays: credential.relays.clone(),
                })
                .collect(),
        };
        let mut erase = Vec::new();
        let now = pending.written_at;
        if pending.kind == KIND_FULL {
            for old in core::mem::take(&mut state.entries) {
                erase.extend(old.credentials);
            }

            state.next_full_at = next_write(now, BACKUP_FULL_INTERVAL, rng);
        }

        state.entries.push(entry);
        if is_first {
            state.first_written_at = now;
        }

        // IDN-185: a new install writes more often, on a clock that follows
        // the age of the install and no act of the user.
        let is_early = state.first_written_at != 0
            && now < state.first_written_at.saturating_add(BACKUP_EARLY_WINDOW);
        let interval = if is_early {
            BACKUP_EARLY_INTERVAL
        } else {
            BACKUP_INTERVAL
        };
        state.next_delta_at = next_write(now, interval, rng);
        state.last_written_at = now;

        let credentials = self.backup_credentials(week_of(consensus_epoch), rng)?;
        let root = BackupRoot {
            entries: state
                .entries
                .iter()
                .map(|entry| BackupEntry {
                    kind: entry.kind,
                    descriptor: &entry.descriptor,
                })
                .collect(),
        };
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let sealed = root.seal(&credentials, nonce)?;
        let chunk = pad_handle_object(&sealed)?;
        let read_pk = *XPublic::from(&StaticSecret::from(*credentials.read.expose())).as_bytes();

        let encoded = state.encode()?;
        let open = self.open_mut()?;
        let state_row = open.store.row_id(BACKUP_STATE, STATE_KEY);
        let mut batch = open.store.begin();
        batch.put(BACKUP_STATE, state_row, None, &encoded, rng)?;
        for (key, value) in pending.index {
            match value {
                Some(value) => batch.put(BACKUP_INDEX, key, None, &value, rng)?,
                None => batch.delete(BACKUP_INDEX, key),
            }
        }

        batch.commit()?;

        Ok(RootWrite {
            handle: credentials.handle,
            cred: Secret::new(*credentials.write.expose()),
            read_pk,
            chunk,
            erase,
        })
    }
}

fn alloc_vec(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

/// The setting that lists each contact of a restore whose channel waits
/// for its renewal. Each run marks them stale again, until the renewal of
/// each one ends (`IDN-183`).
pub(super) const RESTORE_STALE_SETTING: &[u8] = b"restore-stale";
/// The handle entries of a restore that did not look for their current key
/// yet (`IDN-109`), 16 bytes each.
const RESTORE_RESYNC_SETTING: &[u8] = b"restore-resync";

/// The rows of a restore: the full object and each delta after it, in the
/// order of the root (`IDN-182`), with the root seed that they hold.
pub struct RestoredBackup {
    seed: Secret<32>,
    rows: Vec<BackupRow>,
    contacts: Vec<[u8; 32]>,
}

impl RestoredBackup {
    /// Applies `objects` in order, and finds the root seed among the rows
    /// of the local identity table: the one row whose seed names that row
    /// under its own `K_store`. A backup with no such row recovered no
    /// identity (`IDN-155`), and the result is `NotFound`.
    pub fn assemble(objects: &[Zeroizing<Vec<u8>>]) -> Result<Self, Error> {
        let mut rows: BTreeMap<(u8, RowId), BackupRow> = BTreeMap::new();
        for (at, bytes) in objects.iter().enumerate() {
            let object = BackupObject::parse(bytes)?;

            // IDN-102: the full object first, and then each delta.
            if (at == 0) != (object.kind == KIND_FULL) {
                return Err(Error::Malformed);
            }

            for row in object.rows {
                match row {
                    BackupRow::Put { table, row: id, .. } => {
                        let key = (table.0, id);
                        rows.insert(key, row);
                    }
                    BackupRow::Delete { table, row: id } => {
                        rows.remove(&(table.0, id));
                    }
                }
            }
        }

        let names_root = |seed: [u8; 32], row: &RowId| {
            let store_key = RootIdentity::new(Secret::new(seed)).storage_key();
            RowKey::derive(&store_key).row_id(TableId::LOCAL_IDENTITY, super::ROOT_KEY) == *row
        };
        let seed = rows
            .values()
            .find_map(|row| match row {
                BackupRow::Put {
                    table, row, plain, ..
                } if *table == TableId::LOCAL_IDENTITY => {
                    let seed: [u8; 32] = plain.as_slice().try_into().ok()?;
                    names_root(seed, row).then_some(seed)
                }
                _ => None,
            })
            .ok_or(Error::NotFound)?;
        let contacts = rows
            .values()
            .filter_map(|row| match row {
                BackupRow::Put { table, plain, .. } if *table == TableId::CONTACT => {
                    plain.get(..32).and_then(|id| id.try_into().ok())
                }
                _ => None,
            })
            .collect();

        Ok(RestoredBackup {
            seed: Secret::new(seed),
            rows: rows.into_values().collect(),
            contacts,
        })
    }

    /// The root seed, for the store of the restored device.
    pub fn seed(&self) -> Secret<32> {
        Secret::new(*self.seed.expose())
    }

    /// The count of the contacts that the backup holds.
    pub fn contact_count(&self) -> usize {
        self.contacts.len()
    }
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Writes each row of a restore into the store that
    /// [`Client::create_with_seed`] made under its seed, and lists each
    /// contact for the stale mark of its next run (`IDN-183`).
    pub fn apply_restore<R: CryptoRng + ?Sized>(
        &mut self,
        restored: &RestoredBackup,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let listed = open.store.row_id(super::SETTINGS, RESTORE_STALE_SETTING);
        let holds = open
            .store
            .row_id(super::SETTINGS, super::own_delete::HOLDS_DELETIONS);
        let mut batch = open.store.begin();
        for row in &restored.rows {
            if let BackupRow::Put {
                table,
                row,
                owner,
                plain,
            } = row
            {
                batch.put(*table, *row, *owner, plain, rng)?;
            }
        }

        batch.put(
            super::SETTINGS,
            listed,
            None,
            &restored.contacts.concat(),
            rng,
        )?;

        // DEV-117: the deletions of the other devices wait for the user.
        batch.put(super::SETTINGS, holds, None, &[1], rng)?;
        batch.commit()?;

        // IDN-109: each handle of the restore looks for its current key
        // once; a device that no restore made takes no newer version of
        // its handle in silence (DIS-138).
        self.mark_resync(rng)
    }

    /// Each handle entry that this device holds looks for its current key
    /// once, as after a restore (`IDN-109`).
    pub fn mark_resync<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let ids: Vec<u8> = self
            .published()?
            .iter()
            .filter(|entry| entry.kind == super::discovery::EntryKind::Handle)
            .flat_map(|entry| entry.id)
            .collect();
        let open = self.open_mut()?;
        let row = open.store.row_id(super::SETTINGS, RESTORE_RESYNC_SETTING);
        let mut batch = open.store.begin();
        batch.put(super::SETTINGS, row, None, &ids, rng)?;

        Ok(batch.commit()?)
    }

    /// Whether the handle entry `id` came from a restore and did not look
    /// for its current key yet (`IDN-109`).
    pub fn awaits_resync(&self, id: &[u8; 16]) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(super::SETTINGS, RESTORE_RESYNC_SETTING);
        Ok(store
            .get(super::SETTINGS, &row)?
            .is_some_and(|bytes| bytes.as_chunks::<16>().0.contains(id)))
    }

    /// The handle entry `id` looked for its current key.
    pub fn resync_done<R: CryptoRng + ?Sized>(
        &mut self,
        id: &[u8; 16],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(super::SETTINGS, RESTORE_RESYNC_SETTING);
        let Some(bytes) = open.store.get(super::SETTINGS, &row)? else {
            return Ok(());
        };

        let kept: Vec<u8> = bytes
            .as_chunks::<16>()
            .0
            .iter()
            .filter(|held| *held != id)
            .flatten()
            .copied()
            .collect();
        let mut batch = open.store.begin();
        if kept.is_empty() {
            batch.delete(super::SETTINGS, row);
        } else {
            batch.put(super::SETTINGS, row, None, &kept, rng)?;
        }

        Ok(batch.commit()?)
    }

    /// Each contact of a restore whose renewal did not end yet.
    pub fn restored_stale(&self) -> Result<Vec<[u8; 32]>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(super::SETTINGS, RESTORE_STALE_SETTING);
        let Some(bytes) = store.get(super::SETTINGS, &row)? else {
            return Ok(Vec::new());
        };

        Ok(bytes.as_chunks::<32>().0.to_vec())
    }

    /// The renewal of a contact of a restore ended: its run marks it stale
    /// no more.
    pub fn restored_renewed<R: CryptoRng + ?Sized>(
        &mut self,
        contact: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut listed = self.restored_stale()?;
        if !listed.contains(contact) {
            return Ok(());
        }

        listed.retain(|held| held != contact);
        let open = self.open_mut()?;
        let row = open.store.row_id(super::SETTINGS, RESTORE_STALE_SETTING);
        let mut batch = open.store.begin();
        if listed.is_empty() {
            batch.delete(super::SETTINGS, row);
        } else {
            batch.put(super::SETTINGS, row, None, &listed.concat(), rng)?;
        }

        Ok(batch.commit()?)
    }
}
