//! The store over a platform backend (Part 4 §4.6, Part 14 §14.6.4): the
//! commit batch that keeps each table MAC in step with its rows, the
//! check of each MAC at the unlock, the scan that compares a table with
//! its accumulator, and the deletion batch.
//!
//! The backend is SQLite on Android and IndexedDB in the web client. It
//! reads and writes opaque bytes under surrogate identifiers, and it holds
//! no key.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::{rand_core::CryptoRng, secret::Secret, zeroize::Zeroizing};

use super::record::{RowId, RowKey, SealedRecord, TableId, RECORD_VERSION};
use crate::{
    identity::table::{TableKey, TableState},
    Error,
};

/// One row as a backend holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRow {
    /// The surrogate identifier, which is unique in its table (`IDN-030`).
    pub row_id: RowId,
    /// The surrogate of the owner of the row, such as a conversation. A
    /// backend indexes on it, thus a client reads one conversation without
    /// a scan of the table.
    pub owner: Option<RowId>,
    /// The sealed record.
    pub sealed: Vec<u8>,
}

/// One opened row with its owner column: the surrogate identifier, the
/// owner, and the plaintext.
pub type OwnedRow = (RowId, Option<RowId>, Vec<u8>);

/// The MAC state of one table as a backend holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredTable {
    /// The accumulator.
    pub accum: [u8; 32],
    /// The count of the live rows.
    pub row_count: u64,
    /// The commit counter.
    pub commit_counter: u64,
    /// The table MAC.
    pub mac: [u8; 32],
}

/// One write of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// Insert the row, or replace the row with that identifier.
    Put(TableId, StoredRow),
    /// Remove the row.
    Delete(TableId, RowId),
    /// Replace the MAC state of a table.
    Table(TableId, StoredTable),
}

/// A commit batch. A backend applies each write of it, or none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch {
    /// The writes, in order.
    pub writes: Vec<Write>,
    /// The batch is a deletion batch. The SQLite backend runs under
    /// `secure_delete` and then truncates the write-ahead log (`IMP-042`,
    /// `IMP-043`). The IndexedDB backend overwrites each deleted record
    /// with zero bytes before it deletes it (`IMP-108`).
    pub deletion: bool,
}

/// The storage of the platform.
pub trait Backend {
    /// The row with `row_id`, if the table holds it.
    fn read(&self, table: TableId, row_id: &RowId) -> Result<Option<StoredRow>, Error>;
    /// Each row of the table, or each row of one owner.
    fn rows(&self, table: TableId, owner: Option<&RowId>) -> Result<Vec<StoredRow>, Error>;
    /// The identifiers of at most `limit` rows of the table in ascending
    /// order: the first ones, or the ones after the row `after`. A caller
    /// walks a table with it and reads one row at a time, thus it holds
    /// no table in RAM (`IMP-130`).
    fn row_ids(
        &self,
        table: TableId,
        after: Option<&RowId>,
        limit: usize,
    ) -> Result<Vec<RowId>, Error>;
    /// The MAC state of each table that holds one.
    fn tables(&self) -> Result<Vec<(TableId, StoredTable)>, Error>;
    /// Applies the batch in one transaction.
    fn apply(&mut self, batch: &Batch) -> Result<(), Error>;
}

/// The unlocked store. It holds `K_store` in RAM, and a lock drops it.
pub struct Store<B: Backend> {
    backend: B,
    store_key: Secret<32>,
    table_key: TableKey,
    row_key: RowKey,
    tables: BTreeMap<TableId, TableState>,
    /// The MAC state of the set of tables (`IDN-193`).
    set: TableState,
    /// Whether the store held the set MAC at the unlock. A store of an
    /// earlier build holds none, and the next commit writes it.
    indexed: bool,
    /// The record version of the store (`IMP-130`).
    form: Form,
    /// The fault that ended [`Store::migrate`] in this run. A write then
    /// fails with it and runs no second pass: the next unlock does.
    migration_fault: Option<Error>,
}

/// The record version that a store holds. The form of each MAC says it,
/// thus no row and no column carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// Version `0x01`, of an earlier build: the associated data and the
    /// row tag read no owner, and the set MAC reads no table MAC. A read
    /// takes a record of each version, and [`Store::migrate`] ends this
    /// form.
    Earlier,
    /// [`RECORD_VERSION`], and no record of another version.
    Current,
}

/// The `table_id` input of a MAC: the table, and for [`Form::Current`] the
/// record version after it.
struct Domain {
    bytes: [u8; 2],
    len: usize,
}

impl Domain {
    fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

impl Form {
    fn domain(self, table: TableId) -> Domain {
        Domain {
            bytes: [table.0, RECORD_VERSION],
            len: match self {
                Form::Earlier => 1,
                Form::Current => 2,
            },
        }
    }

    /// `row_tag` of one stored row. [`Form::Current`] reads the owner
    /// column too.
    fn row_tag(
        self,
        table_key: &TableKey,
        table: TableId,
        row_id: &RowId,
        owner: Option<&RowId>,
        sealed: &[u8],
    ) -> Result<[u8; 32], Error> {
        let tag = SealedRecord::mac_input_of(sealed)?;
        let domain = self.domain(table);
        Ok(match self {
            Form::Earlier => table_key.row_tag(domain.bytes(), row_id, &tag),
            Form::Current => table_key.row_tag_owned(
                domain.bytes(),
                row_id,
                owner.map(|owner| owner.as_slice()),
                &tag,
            ),
        })
    }

    /// The tag of one table in the set MAC: a table is a row of the set.
    /// [`Form::Current`] takes the first 16 bytes of the MAC of the table
    /// as the record tag. Thus the set MAC changes at each commit, and one
    /// table from an earlier state of the file fails the unlock.
    fn set_tag(self, table_key: &TableKey, table: TableId, mac: &[u8; 32]) -> [u8; 32] {
        let domain = self.domain(TableId::SET);
        match self {
            Form::Earlier => table_key.row_tag(domain.bytes(), &[table.0], &[0; 16]),
            Form::Current => {
                let bound = umbra_crypto::bytes::part::<0, 16, 32>(mac);
                table_key.row_tag_owned(domain.bytes(), &[table.0], None, &bound)
            }
        }
    }
}

/// The sealed bytes that one batch of [`Store::migrate`] holds at most
/// before it commits. A record above that size is a batch of its own.
const MIGRATION_BATCH: usize = 4 << 20;
/// The records that one batch of [`Store::migrate`] holds at most.
const MIGRATION_ROWS: usize = 256;
/// The row identifiers that [`Store::migrate`] reads at once.
const MIGRATION_PAGE: usize = 1_024;

fn stored_table(state: &TableState, mac: [u8; 32]) -> StoredTable {
    let (accum, row_count, commit_counter) = state.fields();
    StoredTable {
        accum,
        row_count,
        commit_counter,
        mac,
    }
}

impl<B: Backend> Store<B> {
    /// Unlocks the store, and verifies each table MAC without a scan
    /// (`IDN-037`, `IDN-038`). A mismatch is `Unverified`, and the client
    /// tells the user (`IDN-039`, `IDN-040`).
    pub fn unlock(backend: B, store_key: Secret<32>) -> Result<Self, Error> {
        let table_key = TableKey::derive(&store_key);
        let row_key = RowKey::derive(&store_key);
        let stored_tables = backend.tables()?;
        // IMP-130: the form of the set MAC is the mark of the record
        // version. A new store holds no table and starts at the current
        // version. A store with tables and no set MAC is of a build before
        // `IDN-193`. Each table MAC verifies under the form of its store
        // alone. Thus a set MAC of the earlier form that a party puts back
        // fails at the first table.
        let form = match stored_tables
            .iter()
            .find(|(table, _)| *table == TableId::SET)
        {
            None if stored_tables.is_empty() => Form::Current,
            None => Form::Earlier,
            Some((_, stored)) => {
                let state =
                    TableState::restore(stored.accum, stored.row_count, stored.commit_counter);
                let current = Form::Current.domain(TableId::SET);
                if state
                    .verify(&table_key, current.bytes(), &stored.mac)
                    .is_ok()
                {
                    Form::Current
                } else {
                    Form::Earlier
                }
            }
        };
        let mut tables = BTreeMap::new();
        let mut held_set = None;
        let mut scanned = TableState::new();
        for (table, stored) in stored_tables {
            let state = TableState::restore(stored.accum, stored.row_count, stored.commit_counter);
            state.verify(&table_key, form.domain(table).bytes(), &stored.mac)?;
            if table == TableId::SET {
                held_set = Some(state);
                continue;
            }
            scanned.insert(&form.set_tag(&table_key, table, &stored.mac));
            tables.insert(table, state);
        }
        // IDN-193: a table whose MAC row left the file shows here, since
        // the set MAC counts each table that the store ever held. In the
        // current form it reads the MAC of each table too, thus a table
        // from an earlier state of the file shows here.
        let indexed = held_set.is_some();
        let set = match held_set {
            Some(held) => {
                let (held_accum, held_count, _) = held.fields();
                let (accum, count, _) = scanned.fields();
                if !umbra_crypto::ct_eq(&held_accum, &accum) || held_count != count {
                    return Err(Error::Unverified);
                }
                held
            }
            None => scanned,
        };
        Ok(Store {
            backend,
            store_key,
            table_key,
            row_key,
            tables,
            set,
            indexed,
            form,
            migration_fault: None,
        })
    }

    /// Whether the store holds the record version of an earlier build, and
    /// [`Store::migrate`] has work.
    pub fn migration_due(&self) -> bool {
        self.form == Form::Earlier
    }

    /// Moves the store of an earlier build to [`RECORD_VERSION`]
    /// (`IMP-130`). The pass seals each record of version `0x01` again
    /// under its row and its owner column, table by table. One last batch
    /// writes each table MAC and the set MAC in the current form. That
    /// batch is the mark: before it the store reads the two versions, and
    /// after it a record of version `0x01` does not open. A pass that ends
    /// early leaves a store of the earlier form with some records of the
    /// current version. The next pass takes the rest.
    ///
    /// The first [`Transaction::put`] of a store calls this. A client calls
    /// it before, at the unlock, to report its result in the manner of
    /// `IDN-039`.
    ///
    /// The pass reads one row at a time and holds no table: the largest row
    /// of a store is a whole file. It holds one record in the clear for the
    /// time of its seal, and one batch of sealed records.
    ///
    /// The result says whether each table matched its accumulator before
    /// the pass. A table that does not match holds a row that a party with
    /// the file removed, put back, or changed. Such a party can also put
    /// the store back into the earlier form to pass a record of version
    /// `0x01` through this pass. The mismatch is the sign of it that the
    /// pass sees. The pass still moves each record, thus each one stays
    /// readable, and the client tells the user (`IDN-039`).
    ///
    /// A fault ends the pass for this run. A later write fails with the
    /// same fault and runs no second pass, and the next unlock runs it.
    pub fn migrate<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<bool, Error> {
        if self.form == Form::Current {
            return Ok(true);
        }
        if let Some(fault) = self.migration_fault {
            return Err(fault);
        }
        let moved = self.migrate_tables(rng);
        if let Err(fault) = moved {
            self.migration_fault = Some(fault);
        }
        moved
    }

    /// The pass of [`Store::migrate`].
    fn migrate_tables<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<bool, Error> {
        let ids: Vec<TableId> = self.tables.keys().copied().collect();
        let mut moved: BTreeMap<TableId, TableState> = BTreeMap::new();
        let mut is_sound = true;
        for table in ids {
            let held = self.tables.get(&table).cloned().unwrap_or_default();
            let mut earlier = held.clone();
            let mut scanned = TableState::new();
            let mut current = TableState::new();
            let mut writes = Vec::new();
            let mut size = 0usize;
            let mut after: Option<RowId> = None;
            loop {
                let page = self
                    .backend
                    .row_ids(table, after.as_ref(), MIGRATION_PAGE)?;
                let Some(last) = page.last().copied() else {
                    break;
                };
                after = Some(last);
                for row_id in page {
                    let Some(row) = self.backend.read(table, &row_id)? else {
                        continue;
                    };
                    let owner = row.owner;
                    let old_tag = Form::Earlier.row_tag(
                        &self.table_key,
                        table,
                        &row_id,
                        None,
                        &row.sealed,
                    )?;
                    scanned.insert(&old_tag);
                    let sealed = SealedRecord::from_bytes(row.sealed)?;
                    // A record with a discarded key has no plaintext, and a
                    // record that opens under neither version is a fault
                    // that each later read reports. The two stay as they
                    // are. The plaintext of a record that is current
                    // already leaves RAM at once.
                    let plain = if sealed.is_discarded()
                        || sealed
                            .open(&self.store_key, table, &row_id, owner.as_ref())
                            .map(Zeroizing::new)
                            .is_ok()
                    {
                        None
                    } else {
                        sealed
                            .open_earlier(&self.store_key, table, &row_id)
                            .ok()
                            .map(Zeroizing::new)
                    };
                    let Some(plain) = plain else {
                        current.insert(&Form::Current.row_tag(
                            &self.table_key,
                            table,
                            &row_id,
                            owner.as_ref(),
                            sealed.as_bytes(),
                        )?);
                        continue;
                    };
                    // The earlier bytes go before the seal, and the
                    // plaintext goes right after it.
                    drop(sealed);
                    let again = SealedRecord::seal(
                        &self.store_key,
                        table,
                        &row_id,
                        owner.as_ref(),
                        &plain,
                        rng,
                    )?;
                    drop(plain);
                    let len = again.as_bytes().len();
                    // A record that does not fit beside the ones that wait
                    // lets them commit first. Thus a record above the bound
                    // is a batch of its own.
                    if !writes.is_empty() && size.saturating_add(len) > MIGRATION_BATCH {
                        self.apply_earlier(table, &mut earlier, &mut writes)?;
                        size = 0;
                    }
                    let new_tag = Form::Earlier.row_tag(
                        &self.table_key,
                        table,
                        &row_id,
                        None,
                        again.as_bytes(),
                    )?;
                    current.insert(&Form::Current.row_tag(
                        &self.table_key,
                        table,
                        &row_id,
                        owner.as_ref(),
                        again.as_bytes(),
                    )?);
                    earlier.update(&old_tag, &new_tag);
                    size = size.saturating_add(len);
                    writes.push(Write::Put(
                        table,
                        StoredRow {
                            row_id,
                            owner,
                            sealed: again.into_bytes(),
                        },
                    ));
                    if size >= MIGRATION_BATCH || writes.len() >= MIGRATION_ROWS {
                        self.apply_earlier(table, &mut earlier, &mut writes)?;
                        size = 0;
                    }
                }
            }
            if !writes.is_empty() {
                self.apply_earlier(table, &mut earlier, &mut writes)?;
            }
            // A table that did not match its accumulator before the pass
            // does not match it after. The difference moves with the rows,
            // thus the scan of `IDN-162` still reports it. The commit
            // counter goes on from the batches of this pass (`IDN-068`).
            let (mut accum, _, _) = current.fields();
            let (held_accum, held_rows, _) = held.fields();
            let (_, _, commit_counter) = earlier.fields();
            let (scanned_accum, scanned_rows, _) = scanned.fields();
            if !umbra_crypto::ct_eq(&held_accum, &scanned_accum) || held_rows != scanned_rows {
                is_sound = false;
            }
            for ((byte, held), scanned) in accum.iter_mut().zip(held_accum).zip(scanned_accum) {
                *byte ^= held ^ scanned;
            }
            moved.insert(table, TableState::restore(accum, held_rows, commit_counter));
        }
        // The mark: each MAC in the current form, in one transaction.
        let mut writes = Vec::with_capacity(moved.len().saturating_add(1));
        let mut set = TableState::new();
        for (table, state) in &mut moved {
            let mac = state.commit(&self.table_key, Form::Current.domain(*table).bytes());
            set.insert(&Form::Current.set_tag(&self.table_key, *table, &mac));
            writes.push(Write::Table(*table, stored_table(state, mac)));
        }
        let (accum, row_count, _) = set.fields();
        let (_, _, commit_counter) = self.set.fields();
        let mut set = TableState::restore(accum, row_count, commit_counter);
        let mac = set.commit(&self.table_key, Form::Current.domain(TableId::SET).bytes());
        writes.push(Write::Table(TableId::SET, stored_table(&set, mac)));
        self.backend.apply(&Batch {
            writes,
            deletion: false,
        })?;
        self.tables = moved;
        self.set = set;
        self.indexed = true;
        self.form = Form::Current;
        Ok(is_sound)
    }

    /// Commits one batch of [`Store::migrate`] under the MAC of the
    /// earlier form, thus the store verifies at an unlock between two
    /// batches.
    fn apply_earlier(
        &mut self,
        table: TableId,
        state: &mut TableState,
        writes: &mut Vec<Write>,
    ) -> Result<(), Error> {
        let mac = state.commit(&self.table_key, Form::Earlier.domain(table).bytes());
        let mut writes = core::mem::take(writes);
        writes.push(Write::Table(table, stored_table(state, mac)));
        self.backend.apply(&Batch {
            writes,
            deletion: false,
        })?;
        self.tables.insert(table, state.clone());
        Ok(())
    }

    /// Opens one record under the owner that its column names. A store of
    /// the earlier form reads a record of version `0x01` too, until
    /// [`Store::migrate`] ends that form.
    fn open_row(
        &self,
        table: TableId,
        row_id: &RowId,
        owner: Option<&RowId>,
        sealed: &SealedRecord,
    ) -> Result<Vec<u8>, Error> {
        match sealed.open(&self.store_key, table, row_id, owner) {
            Err(Error::Unverified) if self.form == Form::Earlier => {
                sealed.open_earlier(&self.store_key, table, row_id)
            }
            other => other,
        }
    }

    /// Whether the store held the MAC of its set of tables at the unlock.
    /// A client that wrote that MAC before and finds none holds a store
    /// that a party with the file changed (`IDN-193`).
    pub fn indexed(&self) -> bool {
        self.indexed
    }

    /// Each table that the store holds, for the scan of `IDN-162`.
    pub fn table_ids(&self) -> Vec<TableId> {
        self.tables.keys().copied().collect()
    }

    /// Locks the store: the keys leave RAM, and the backend stays.
    pub fn lock(self) -> B {
        self.backend
    }

    /// The surrogate identifier of a natural key in a table.
    pub fn row_id(&self, table: TableId, natural_key: &[u8]) -> RowId {
        self.row_key.row_id(table, natural_key)
    }

    /// Reads and opens one row.
    pub fn get(&self, table: TableId, row_id: &RowId) -> Result<Option<Vec<u8>>, Error> {
        let Some(row) = self.backend.read(table, row_id)? else {
            return Ok(None);
        };
        let sealed = SealedRecord::from_bytes(row.sealed)?;
        Ok(Some(self.open_row(
            table,
            row_id,
            row.owner.as_ref(),
            &sealed,
        )?))
    }

    /// Reads and opens each row of one owner, or each row of the table. The
    /// result leaves out a row with a discarded key. Each record opens
    /// under the owner that the caller asked for (`IMP-121`). Thus a row
    /// that a party with the file moved to that owner fails the call. No
    /// caller reads the row of another owner.
    pub fn list(
        &self,
        table: TableId,
        owner: Option<&RowId>,
    ) -> Result<Vec<(RowId, Vec<u8>)>, Error> {
        let mut out = Vec::new();
        for row in self.backend.rows(table, owner)? {
            let sealed = SealedRecord::from_bytes(row.sealed)?;
            if sealed.is_discarded() {
                continue;
            }
            let bound = owner.or(row.owner.as_ref());
            out.push((
                row.row_id,
                self.open_row(table, &row.row_id, bound, &sealed)?,
            ));
        }
        Ok(out)
    }

    /// Reads and opens each row of the table with its owner column, as a
    /// backup of Part 4 §4.7.2 carries it. A row with a discarded key is
    /// left out.
    pub fn list_owned(&self, table: TableId) -> Result<Vec<OwnedRow>, Error> {
        let mut out = Vec::new();
        for row in self.backend.rows(table, None)? {
            let sealed = SealedRecord::from_bytes(row.sealed)?;
            if sealed.is_discarded() {
                continue;
            }
            let plain = self.open_row(table, &row.row_id, row.owner.as_ref(), &sealed)?;
            out.push((row.row_id, row.owner, plain));
        }
        Ok(out)
    }

    /// Compares a table with its accumulator by a scan. The unlock does
    /// not run this (`IDN-037`); the client runs it in the background. It
    /// finds a removed row, a row from an earlier state, and two rows with
    /// one identifier (`IDN-031`, `IDN-032`). In a store of the current
    /// record version it finds a row whose owner column changed too.
    pub fn audit(&self, table: TableId) -> Result<(), Error> {
        let mut scanned = TableState::new();
        let mut seen: BTreeSet<RowId> = BTreeSet::new();
        for row in self.backend.rows(table, None)? {
            if !seen.insert(row.row_id) {
                return Err(Error::Unverified);
            }
            scanned.insert(&self.form.row_tag(
                &self.table_key,
                table,
                &row.row_id,
                row.owner.as_ref(),
                &row.sealed,
            )?);
        }
        let held = self.tables.get(&table).cloned().unwrap_or_default();
        let (scanned_accum, scanned_rows, _) = scanned.fields();
        let (held_accum, held_rows, _) = held.fields();
        if scanned_accum == held_accum && scanned_rows == held_rows {
            Ok(())
        } else {
            Err(Error::Unverified)
        }
    }

    /// Opens a commit batch.
    pub fn begin(&mut self) -> Transaction<'_, B> {
        Transaction {
            store: self,
            pending: BTreeMap::new(),
            deletion: false,
        }
    }
}

enum Pending {
    Put(StoredRow),
    Delete,
}

/// One commit batch. Nothing reaches the backend before
/// [`Transaction::commit`], and a dropped transaction changes nothing.
pub struct Transaction<'s, B: Backend> {
    store: &'s mut Store<B>,
    pending: BTreeMap<(TableId, RowId), Pending>,
    deletion: bool,
}

impl<B: Backend> Transaction<'_, B> {
    /// Writes a row under a fresh record key. The first write of a store of
    /// an earlier build moves that store to the current record version
    /// before it (`IMP-130`). This call holds the CSPRNG that the move
    /// needs, and the unlock holds none.
    pub fn put<R: CryptoRng + ?Sized>(
        &mut self,
        table: TableId,
        row_id: RowId,
        owner: Option<RowId>,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.store.form == Form::Earlier {
            self.store.migrate(rng)?;
        }
        let sealed = SealedRecord::seal(
            &self.store.store_key,
            table,
            &row_id,
            owner.as_ref(),
            plaintext,
            rng,
        )?;
        self.pending.insert(
            (table, row_id),
            Pending::Put(StoredRow {
                row_id,
                owner,
                sealed: sealed.as_bytes().to_vec(),
            }),
        );
        Ok(())
    }

    /// Deletes a row, which makes the batch a deletion batch.
    pub fn delete(&mut self, table: TableId, row_id: RowId) {
        self.pending.insert((table, row_id), Pending::Delete);
        self.deletion = true;
    }

    /// Makes the batch a deletion batch with no delete: a put that replaces
    /// the text of a row leaves the earlier ciphertext in no log (Part 14
    /// `IMP-154`).
    pub fn erase_earlier(&mut self) {
        self.deletion = true;
    }

    /// Discards the record key of a row and keeps the row (`IMP-041`), as
    /// a tombstone and a timer expiry of Part 7 ask. The batch is a
    /// deletion batch.
    pub fn discard_key(&mut self, table: TableId, row_id: RowId) -> Result<(), Error> {
        let row = self
            .store
            .backend
            .read(table, &row_id)?
            .ok_or(Error::NoPath)?;
        let mut sealed = SealedRecord::from_bytes(row.sealed)?;
        sealed.discard_key();
        self.pending.insert(
            (table, row_id),
            Pending::Put(StoredRow {
                sealed: sealed.as_bytes().to_vec(),
                ..row
            }),
        );
        self.deletion = true;
        Ok(())
    }

    /// Ends the batch: each table MAC takes the changed rows in and out
    /// (`IDN-036`, `IDN-068`), and the backend applies the rows and the
    /// MACs in one transaction. The state in RAM changes after the backend
    /// succeeds.
    pub fn commit(self) -> Result<(), Error> {
        let store = self.store;
        let form = store.form;
        let mut states: BTreeMap<TableId, TableState> = BTreeMap::new();
        let mut writes = Vec::with_capacity(self.pending.len());
        for ((table, row_id), change) in self.pending {
            let state = states
                .entry(table)
                .or_insert_with(|| store.tables.get(&table).cloned().unwrap_or_default());
            let old_tag = match store.backend.read(table, &row_id)? {
                Some(old) => Some(form.row_tag(
                    &store.table_key,
                    table,
                    &row_id,
                    old.owner.as_ref(),
                    &old.sealed,
                )?),
                None => None,
            };
            match change {
                Pending::Put(row) => {
                    let new_tag = form.row_tag(
                        &store.table_key,
                        table,
                        &row_id,
                        row.owner.as_ref(),
                        &row.sealed,
                    )?;
                    match old_tag {
                        Some(old) => state.update(&old, &new_tag),
                        None => state.insert(&new_tag),
                    }
                    writes.push(Write::Put(table, row));
                }
                Pending::Delete => {
                    if let Some(old) = old_tag {
                        state.remove(&old);
                        writes.push(Write::Delete(table, row_id));
                    }
                }
            }
        }
        // IDN-193: a table that enters the store enters the set MAC, and a
        // store of an earlier build writes that MAC at its first commit.
        // In the current form the set MAC reads the MAC of each table,
        // thus each commit that changes a table writes the set MAC too.
        let mut set = store.set.clone();
        let mut set_changed = !store.indexed;
        for (table, state) in &mut states {
            let mac = state.commit(&store.table_key, form.domain(*table).bytes());
            let new_tag = form.set_tag(&store.table_key, *table, &mac);
            match store.tables.get(table) {
                Some(old) if form == Form::Current => {
                    let old_mac = old.mac(&store.table_key, form.domain(*table).bytes());
                    set.update(&form.set_tag(&store.table_key, *table, &old_mac), &new_tag);
                    set_changed = true;
                }
                Some(_) => {}
                None => {
                    set.insert(&new_tag);
                    set_changed = true;
                }
            }
            writes.push(Write::Table(*table, stored_table(state, mac)));
        }
        if set_changed {
            let mac = set.commit(&store.table_key, form.domain(TableId::SET).bytes());
            writes.push(Write::Table(TableId::SET, stored_table(&set, mac)));
        }
        store.backend.apply(&Batch {
            writes,
            deletion: self.deletion,
        })?;
        store.tables.extend(states);
        if set_changed {
            store.set = set;
            store.indexed = true;
        }
        Ok(())
    }
}

/// A backend in memory, for a test and for a platform that holds no disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryBackend {
    rows: BTreeMap<(TableId, RowId), StoredRow>,
    tables: BTreeMap<TableId, StoredTable>,
    /// The count of the deletion batches, which a test reads.
    pub deletion_batches: u32,
}

impl MemoryBackend {
    /// The rows, for a test that plays the party with the file.
    pub fn rows_mut(&mut self) -> &mut BTreeMap<(TableId, RowId), StoredRow> {
        &mut self.rows
    }
}

impl Backend for MemoryBackend {
    fn read(&self, table: TableId, row_id: &RowId) -> Result<Option<StoredRow>, Error> {
        Ok(self.rows.get(&(table, *row_id)).cloned())
    }

    fn rows(&self, table: TableId, owner: Option<&RowId>) -> Result<Vec<StoredRow>, Error> {
        Ok(self
            .rows
            .iter()
            .filter(|((t, _), row)| {
                *t == table && owner.is_none_or(|o| row.owner.as_ref() == Some(o))
            })
            .map(|(_, row)| row.clone())
            .collect())
    }

    fn row_ids(
        &self,
        table: TableId,
        after: Option<&RowId>,
        limit: usize,
    ) -> Result<Vec<RowId>, Error> {
        Ok(self
            .rows
            .keys()
            .filter(|(held, row_id)| *held == table && after.is_none_or(|after| row_id > after))
            .map(|(_, row_id)| *row_id)
            .take(limit)
            .collect())
    }

    fn tables(&self) -> Result<Vec<(TableId, StoredTable)>, Error> {
        Ok(self.tables.iter().map(|(t, s)| (*t, *s)).collect())
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), Error> {
        for write in &batch.writes {
            match write {
                Write::Put(table, row) => {
                    self.rows.insert((*table, row.row_id), row.clone());
                }
                Write::Delete(table, row_id) => {
                    self.rows.remove(&(*table, *row_id));
                }
                Write::Table(table, stored) => {
                    self.tables.insert(*table, *stored);
                }
            }
        }
        if batch.deletion {
            self.deletion_batches = self.deletion_batches.saturating_add(1);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;

    const KEY: [u8; 32] = [1; 32];

    fn filled() -> (Store<MemoryBackend>, RowId, RowId, RowId) {
        let mut store = Store::unlock(MemoryBackend::default(), Secret::new(KEY)).unwrap();
        let conversation = store.row_id(TableId::CONTACT, b"alice");
        let first = store.row_id(TableId::MESSAGE, b"alice/1");
        let second = store.row_id(TableId::MESSAGE, b"alice/2");
        let mut rng = Rng(1);
        let mut batch = store.begin();
        batch
            .put(
                TableId::MESSAGE,
                first,
                Some(conversation),
                b"one",
                &mut rng,
            )
            .unwrap();
        batch
            .put(
                TableId::MESSAGE,
                second,
                Some(conversation),
                b"two",
                &mut rng,
            )
            .unwrap();
        batch
            .put(TableId::CONTACT, conversation, None, b"alice", &mut rng)
            .unwrap();
        batch.commit().unwrap();
        (store, conversation, first, second)
    }

    #[test]
    fn a_batch_writes_rows_and_macs_together_and_the_store_opens_again() {
        let (store, conversation, first, _) = filled();
        assert_eq!(
            store.get(TableId::MESSAGE, &first).unwrap().unwrap(),
            b"one"
        );
        assert_eq!(
            store
                .list(TableId::MESSAGE, Some(&conversation))
                .unwrap()
                .len(),
            2
        );
        assert!(store
            .list(TableId::MESSAGE, Some(&first))
            .unwrap()
            .is_empty());
        store.audit(TableId::MESSAGE).unwrap();
        store.audit(TableId::CONTACT).unwrap();

        let backend = store.lock();
        assert_eq!(backend.deletion_batches, 0);
        let again = Store::unlock(backend.clone(), Secret::new(KEY)).unwrap();
        assert_eq!(
            again.get(TableId::MESSAGE, &first).unwrap().unwrap(),
            b"one"
        );
        // Another master key fails at the first table MAC.
        assert!(Store::unlock(backend, Secret::new([2; 32])).is_err());
    }

    #[test]
    fn a_dropped_batch_changes_nothing() {
        let (store, _, first, _) = filled();
        let before = store.lock();
        let mut store = Store::unlock(before.clone(), Secret::new(KEY)).unwrap();
        let mut batch = store.begin();
        batch
            .put(TableId::MESSAGE, first, None, b"changed", &mut Rng(2))
            .unwrap();
        drop(batch);
        assert_eq!(store.lock(), before);
    }

    #[test]
    fn a_party_with_the_file_cannot_roll_back_remove_or_move_a_row() {
        let (store, conversation, first, second) = filled();
        let old_first = store.lock();
        let mut store = Store::unlock(old_first.clone(), Secret::new(KEY)).unwrap();
        let mut batch = store.begin();
        batch
            .put(
                TableId::MESSAGE,
                first,
                Some(conversation),
                b"one, edited",
                &mut Rng(3),
            )
            .unwrap();
        batch.commit().unwrap();
        let current = store.lock();

        // A rollback of one row to its earlier ciphertext.
        let mut rolled = current.clone();
        let earlier = old_first.read(TableId::MESSAGE, &first).unwrap().unwrap();
        rolled.rows_mut().insert((TableId::MESSAGE, first), earlier);
        let store = Store::unlock(rolled, Secret::new(KEY)).unwrap();
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));

        // A removed row.
        let mut removed = current.clone();
        removed.rows_mut().remove(&(TableId::MESSAGE, second));
        let store = Store::unlock(removed, Secret::new(KEY)).unwrap();
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));

        // A record moved into another row does not open.
        let mut moved = current.clone();
        let mut row = moved.read(TableId::MESSAGE, &first).unwrap().unwrap();
        row.row_id = second;
        moved.rows_mut().insert((TableId::MESSAGE, second), row);
        let store = Store::unlock(moved, Secret::new(KEY)).unwrap();
        assert!(store.get(TableId::MESSAGE, &second).is_err());

        // A changed MAC state fails at the unlock.
        let mut forged = current.clone();
        forged.tables.get_mut(&TableId::MESSAGE).unwrap().row_count = 1;
        assert!(Store::unlock(forged, Secret::new(KEY)).is_err());

        // IDN-193: a table whose MAC row and rows left the file fails at
        // the unlock.
        let mut dropped = current.clone();
        dropped.tables.remove(&TableId::CONTACT);
        dropped
            .rows_mut()
            .retain(|(table, _), _| *table != TableId::CONTACT);
        assert_eq!(
            Store::unlock(dropped, Secret::new(KEY)).err(),
            Some(Error::Unverified)
        );
        // The set MAC that left the file alone fails too. Each table MAC is
        // of the current form, and a store with no set MAC is not.
        let mut bare = current.clone();
        bare.tables.remove(&TableId::SET);
        assert_eq!(
            Store::unlock(bare, Secret::new(KEY)).err(),
            Some(Error::Unverified)
        );
        // A store of an earlier build with no set MAC opens and writes one
        // at its next commit.
        let earlier = earlier_backend(false);
        let mut store = Store::unlock(earlier, Secret::new(KEY)).unwrap();
        assert!(!store.indexed());
        let mut batch = store.begin();
        batch
            .put(TableId::CONTACT, conversation, None, b"alice", &mut Rng(4))
            .unwrap();
        batch.commit().unwrap();
        assert!(store.indexed());
        assert!(Store::unlock(store.lock(), Secret::new(KEY))
            .unwrap()
            .indexed());
    }

    /// The store of an earlier build: two messages of one conversation and
    /// the contact. They are records of version `0x01` under MACs of the
    /// earlier form, with the set MAC or with none.
    fn earlier_backend(indexed: bool) -> MemoryBackend {
        let rows = RowKey::derive(&Secret::new(KEY));
        let conversation = rows.row_id(TableId::CONTACT, b"alice");
        earlier_backend_of(
            &[
                (TableId::MESSAGE, b"alice/1", Some(conversation), b"one"),
                (TableId::MESSAGE, b"alice/2", Some(conversation), b"two"),
                (TableId::CONTACT, b"alice", None, b"alice"),
            ],
            indexed,
        )
    }

    /// The table, the natural key, the owner, and the plaintext of a row.
    type Content<'a> = (TableId, &'a [u8], Option<RowId>, &'a [u8]);

    /// The store of an earlier build with the rows of `content`.
    fn earlier_backend_of(content: &[Content<'_>], indexed: bool) -> MemoryBackend {
        let key = Secret::new(KEY);
        let table_key = TableKey::derive(&key);
        let rows = RowKey::derive(&key);
        let mut rng = Rng(7);
        let mut backend = MemoryBackend::default();
        let mut set = TableState::new();
        let tables: BTreeSet<TableId> = content.iter().map(|row| row.0).collect();
        for table in tables {
            let mut state = TableState::new();
            for (_, natural, owner, plain) in content.iter().filter(|row| row.0 == table) {
                let row_id = rows.row_id(table, natural);
                let sealed =
                    SealedRecord::seal_earlier(&key, table, &row_id, plain, &mut rng).unwrap();
                state.insert(&table_key.row_tag(&[table.0], &row_id, &sealed.mac_input().unwrap()));
                backend.rows.insert(
                    (table, row_id),
                    StoredRow {
                        row_id,
                        owner: *owner,
                        sealed: sealed.as_bytes().to_vec(),
                    },
                );
            }
            let mac = state.commit(&table_key, &[table.0]);
            backend.tables.insert(table, stored_table(&state, mac));
            set.insert(&table_key.row_tag(&[TableId::SET.0], &[table.0], &[0; 16]));
        }
        if indexed {
            let mac = set.commit(&table_key, &[TableId::SET.0]);
            backend.tables.insert(TableId::SET, stored_table(&set, mac));
        }
        backend
    }

    /// A backend that fails each batch after the first `left` ones, as a
    /// run that the platform ends.
    struct Ending {
        inner: MemoryBackend,
        left: u32,
        /// The sealed length of each row of each batch that landed.
        batches: Vec<Vec<usize>>,
    }

    impl Backend for Ending {
        fn read(&self, table: TableId, row_id: &RowId) -> Result<Option<StoredRow>, Error> {
            self.inner.read(table, row_id)
        }
        fn rows(&self, table: TableId, owner: Option<&RowId>) -> Result<Vec<StoredRow>, Error> {
            self.inner.rows(table, owner)
        }
        fn row_ids(
            &self,
            table: TableId,
            after: Option<&RowId>,
            limit: usize,
        ) -> Result<Vec<RowId>, Error> {
            self.inner.row_ids(table, after, limit)
        }
        fn tables(&self) -> Result<Vec<(TableId, StoredTable)>, Error> {
            self.inner.tables()
        }
        fn apply(&mut self, batch: &Batch) -> Result<(), Error> {
            if self.left == 0 {
                return Err(Error::Storage);
            }
            self.left = self.left.saturating_sub(1);
            self.batches.push(
                batch
                    .writes
                    .iter()
                    .filter_map(|write| match write {
                        Write::Put(_, row) => Some(row.sealed.len()),
                        _ => None,
                    })
                    .collect(),
            );
            self.inner.apply(batch)
        }
    }

    #[test]
    fn a_row_that_a_party_moves_to_another_owner_does_not_open() {
        let (mut store, conversation, first, second) = filled();
        let other = store.row_id(TableId::CONTACT, b"bob");
        let third = store.row_id(TableId::MESSAGE, b"bob/1");
        let mut batch = store.begin();
        batch
            .put(TableId::MESSAGE, third, Some(other), b"three", &mut Rng(5))
            .unwrap();
        batch.commit().unwrap();
        let current = store.lock();

        // IMP-121: the owner column of one row names another conversation.
        let mut moved = current.clone();
        moved
            .rows_mut()
            .get_mut(&(TableId::MESSAGE, first))
            .unwrap()
            .owner = Some(other);
        let store = Store::unlock(moved, Secret::new(KEY)).unwrap();
        assert_eq!(
            store.list(TableId::MESSAGE, Some(&other)),
            Err(Error::Unverified)
        );
        assert_eq!(store.get(TableId::MESSAGE, &first), Err(Error::Unverified));
        assert_eq!(store.list(TableId::MESSAGE, None), Err(Error::Unverified));
        assert_eq!(store.list_owned(TableId::MESSAGE), Err(Error::Unverified));
        // The rows that stayed with their owner still open.
        assert_eq!(
            store.list(TableId::MESSAGE, Some(&conversation)).unwrap(),
            [(second, b"two".to_vec())]
        );
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));

        // A row that a party hides from each owner fails the scan.
        let mut hidden = current;
        hidden
            .rows_mut()
            .get_mut(&(TableId::MESSAGE, first))
            .unwrap()
            .owner = None;
        let store = Store::unlock(hidden, Secret::new(KEY)).unwrap();
        assert_eq!(
            store
                .list(TableId::MESSAGE, Some(&conversation))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
        assert_eq!(store.get(TableId::MESSAGE, &first), Err(Error::Unverified));
    }

    #[test]
    fn one_table_from_an_earlier_state_of_the_file_fails_the_unlock() {
        let (mut store, conversation, first, _) = filled();
        let before = store.lock();
        store = Store::unlock(before.clone(), Secret::new(KEY)).unwrap();
        let mut batch = store.begin();
        batch.delete(TableId::MESSAGE, first);
        batch
            .put(
                TableId::CONTACT,
                conversation,
                None,
                b"alice b",
                &mut Rng(6),
            )
            .unwrap();
        batch.commit().unwrap();
        let current = store.lock();
        Store::unlock(current.clone(), Secret::new(KEY)).unwrap();

        // IDN-193: the rows and the MAC of one table go back, and each
        // other table stays.
        let mut rolled = current.clone();
        rolled
            .rows_mut()
            .retain(|(table, _), _| *table != TableId::MESSAGE);
        for (key, row) in &before.rows {
            if key.0 == TableId::MESSAGE {
                rolled.rows_mut().insert(*key, row.clone());
            }
        }
        let held = *before.tables.get(&TableId::MESSAGE).unwrap();
        rolled.tables.insert(TableId::MESSAGE, held);
        assert_eq!(
            Store::unlock(rolled, Secret::new(KEY)).err(),
            Some(Error::Unverified)
        );
        // The set MAC of the earlier state with the tables of this one.
        let mut rolled = current;
        let held = *before.tables.get(&TableId::SET).unwrap();
        rolled.tables.insert(TableId::SET, held);
        assert_eq!(
            Store::unlock(rolled, Secret::new(KEY)).err(),
            Some(Error::Unverified)
        );
    }

    #[test]
    fn a_store_of_an_earlier_build_moves_to_the_current_version_and_then_refuses_the_earlier_one() {
        for indexed in [true, false] {
            let earlier = earlier_backend(indexed);
            let mut store = Store::unlock(earlier.clone(), Secret::new(KEY)).unwrap();
            assert!(store.migration_due());
            let conversation = store.row_id(TableId::CONTACT, b"alice");
            let first = store.row_id(TableId::MESSAGE, b"alice/1");
            // Before the move the store reads each record and passes the
            // scan of the earlier form.
            assert_eq!(
                store
                    .list(TableId::MESSAGE, Some(&conversation))
                    .unwrap()
                    .len(),
                2
            );
            store.audit(TableId::MESSAGE).unwrap();

            // The first write moves the store.
            let fourth = store.row_id(TableId::MESSAGE, b"alice/4");
            let mut batch = store.begin();
            batch
                .put(
                    TableId::MESSAGE,
                    fourth,
                    Some(conversation),
                    b"four",
                    &mut Rng(8),
                )
                .unwrap();
            batch.commit().unwrap();
            assert!(!store.migration_due());
            assert!(store.indexed());
            store.audit(TableId::MESSAGE).unwrap();
            store.audit(TableId::CONTACT).unwrap();
            let moved = store.lock();
            let store = Store::unlock(moved.clone(), Secret::new(KEY)).unwrap();
            assert!(!store.migration_due());
            assert_eq!(
                store.get(TableId::MESSAGE, &first).unwrap().unwrap(),
                b"one"
            );
            assert_eq!(
                store
                    .list(TableId::MESSAGE, Some(&conversation))
                    .unwrap()
                    .len(),
                3
            );
            assert_eq!(
                store.get(TableId::CONTACT, &conversation).unwrap().unwrap(),
                b"alice"
            );
            // No record kept its bytes of version 0x01.
            for (key, row) in &earlier.rows {
                assert_ne!(moved.rows.get(key).unwrap().sealed, row.sealed);
            }

            // IMP-130: a record of version 0x01 that a party puts back
            // does not open, and the scan reports it.
            let mut downgraded = moved.clone();
            let old = earlier.rows.get(&(TableId::MESSAGE, first)).unwrap();
            downgraded
                .rows_mut()
                .insert((TableId::MESSAGE, first), old.clone());
            let store = Store::unlock(downgraded, Secret::new(KEY)).unwrap();
            assert_eq!(store.get(TableId::MESSAGE, &first), Err(Error::Unverified));
            assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));

            // A party puts back the MACs of the earlier build, with or
            // without its rows of that build. They fail the unlock or the
            // scan: no path leads back to version 0x01 with the rows of
            // this build.
            let mut downgraded = moved.clone();
            downgraded.tables.remove(&TableId::SET);
            if let Some(set) = earlier.tables.get(&TableId::SET) {
                downgraded.tables.insert(TableId::SET, *set);
            }
            assert_eq!(
                Store::unlock(downgraded, Secret::new(KEY)).err(),
                Some(Error::Unverified)
            );
            let mut downgraded = moved;
            downgraded.tables = earlier.tables.clone();
            let store = Store::unlock(downgraded, Secret::new(KEY)).unwrap();
            assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
            assert_eq!(store.audit(TableId::CONTACT), Err(Error::Unverified));
        }
    }

    #[test]
    fn a_move_that_a_run_ends_early_continues_at_the_next_unlock() {
        // The first batch, of the message table, lands. The batch of the
        // contact table and the mark do not.
        let ending = Ending {
            inner: earlier_backend(true),
            left: 1,
            batches: Vec::new(),
        };
        let mut store = Store::unlock(ending, Secret::new(KEY)).unwrap();
        let conversation = store.row_id(TableId::CONTACT, b"alice");
        let first = store.row_id(TableId::MESSAGE, b"alice/1");
        assert_eq!(store.migrate(&mut Rng(9)), Err(Error::Storage));
        assert!(store.migration_due());
        // A write of that run fails with the move, and changes nothing. It
        // runs no second pass, although the backend would take one now:
        // the next unlock does.
        store.backend.left = u32::MAX;
        let mut batch = store.begin();
        assert_eq!(
            batch.put(TableId::CONTACT, conversation, None, b"x", &mut Rng(10)),
            Err(Error::Storage)
        );
        drop(batch);
        assert_eq!(store.migrate(&mut Rng(10)), Err(Error::Storage));
        assert!(store.migration_due());
        assert_eq!(store.backend.batches.len(), 1);
        let half = store.lock().inner;

        // The store of the two versions opens, reads each row, and passes
        // the scan.
        let mut store = Store::unlock(half.clone(), Secret::new(KEY)).unwrap();
        assert!(store.migration_due());
        assert_eq!(
            store.get(TableId::MESSAGE, &first).unwrap().unwrap(),
            b"one"
        );
        assert_eq!(
            store.get(TableId::CONTACT, &conversation).unwrap().unwrap(),
            b"alice"
        );
        store.audit(TableId::MESSAGE).unwrap();
        store.audit(TableId::CONTACT).unwrap();
        // IDN-068: the commit counter of a table goes up only, through the
        // batches of the two passes and the mark.
        let before = half.tables.get(&TableId::MESSAGE).unwrap().commit_counter;
        assert!(store.migrate(&mut Rng(11)).unwrap());
        assert!(!store.migration_due());
        let (_, _, after) = store.tables.get(&TableId::MESSAGE).unwrap().fields();
        assert_eq!(after, before + 1);
        let (_, _, contact) = store.tables.get(&TableId::CONTACT).unwrap().fields();
        let first_contact = half.tables.get(&TableId::CONTACT).unwrap().commit_counter;
        assert_eq!(contact, first_contact + 2);
        store.audit(TableId::MESSAGE).unwrap();
        store.audit(TableId::CONTACT).unwrap();
        let done = store.lock();
        // The second pass sealed no record of the current version again.
        assert_eq!(
            done.rows.get(&(TableId::MESSAGE, first)),
            half.rows.get(&(TableId::MESSAGE, first))
        );
        assert_ne!(
            done.rows.get(&(TableId::CONTACT, conversation)),
            half.rows.get(&(TableId::CONTACT, conversation))
        );
        let store = Store::unlock(done, Secret::new(KEY)).unwrap();
        assert!(!store.migration_due());
        assert_eq!(
            store
                .list(TableId::MESSAGE, Some(&conversation))
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_move_keeps_a_discarded_record_and_the_fault_of_a_table() {
        // A record with a discarded key stays, and the store still moves.
        let mut earlier = earlier_backend(true);
        let mut store = Store::unlock(earlier.clone(), Secret::new(KEY)).unwrap();
        let conversation = store.row_id(TableId::CONTACT, b"alice");
        let first = store.row_id(TableId::MESSAGE, b"alice/1");
        let second = store.row_id(TableId::MESSAGE, b"alice/2");
        let mut batch = store.begin();
        batch.discard_key(TableId::MESSAGE, first).unwrap();
        batch.commit().unwrap();
        assert!(store.migration_due());
        store.migrate(&mut Rng(12)).unwrap();
        assert_eq!(store.get(TableId::MESSAGE, &first), Err(Error::Stale));
        assert_eq!(
            store.list(TableId::MESSAGE, Some(&conversation)).unwrap(),
            [(second, b"two".to_vec())]
        );
        store.audit(TableId::MESSAGE).unwrap();
        Store::unlock(store.lock(), Secret::new(KEY)).unwrap();

        // IDN-163: a table that lost a row before the move fails the scan
        // after it too.
        earlier.rows_mut().remove(&(TableId::MESSAGE, second));
        let mut store = Store::unlock(earlier, Secret::new(KEY)).unwrap();
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
        // The pass says that a table did not match, and it moves the rest.
        assert!(!store.migrate(&mut Rng(13)).unwrap());
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
        store.audit(TableId::CONTACT).unwrap();
        let store = Store::unlock(store.lock(), Secret::new(KEY)).unwrap();
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
    }

    #[test]
    fn a_move_reads_one_row_at_a_time_and_bounds_each_batch() {
        // A file of a message is one row. One row above the bound of a
        // batch stands between many small ones.
        let rows = RowKey::derive(&Secret::new(KEY));
        let conversation = rows.row_id(TableId::CONTACT, b"alice");
        let large = alloc::vec![0x5A; MIGRATION_BATCH + 1_000];
        let naturals: Vec<Vec<u8>> = (0..2 * MIGRATION_ROWS + 40)
            .map(|index| alloc::format!("alice/{index}").into_bytes())
            .collect();
        let middle = naturals.len() / 2;
        let content: Vec<Content<'_>> = naturals
            .iter()
            .enumerate()
            .map(|(index, natural)| {
                let plain: &[u8] = if index == middle { &large } else { b"small" };
                (
                    TableId::MESSAGE,
                    natural.as_slice(),
                    Some(conversation),
                    plain,
                )
            })
            .collect();
        let ending = Ending {
            inner: earlier_backend_of(&content, true),
            left: u32::MAX,
            batches: Vec::new(),
        };
        let mut store = Store::unlock(ending, Secret::new(KEY)).unwrap();
        assert!(store.migrate(&mut Rng(14)).unwrap());
        store.audit(TableId::MESSAGE).unwrap();
        let file = store.row_id(TableId::MESSAGE, &naturals[middle]);
        assert_eq!(store.get(TableId::MESSAGE, &file).unwrap().unwrap(), large);
        assert_eq!(
            store
                .list(TableId::MESSAGE, Some(&conversation))
                .unwrap()
                .len(),
            naturals.len()
        );
        // The last batch is the mark and holds no row.
        let batches = &store.backend.batches;
        assert!(batches.last().unwrap().is_empty());
        let moved = &batches[..batches.len() - 1];
        assert_eq!(moved.iter().map(Vec::len).sum::<usize>(), naturals.len());
        assert!(moved.len() >= 4);
        for batch in moved {
            // Each batch holds both bounds, and the row above the bound of
            // the bytes is a batch of its own.
            assert!(batch.len() <= MIGRATION_ROWS);
            let bytes: usize = batch.iter().sum();
            assert!(bytes <= MIGRATION_BATCH || batch.len() == 1, "{bytes}");
        }
        assert!(moved
            .iter()
            .any(|batch| batch.len() == 1 && batch[0] > MIGRATION_BATCH));
        Store::unlock(store.lock().inner, Secret::new(KEY)).unwrap();
    }

    #[test]
    fn a_store_that_a_party_puts_back_into_the_earlier_form_shows_at_the_move() {
        // The store moves, and takes one more message.
        let earlier = earlier_backend(true);
        let mut store = Store::unlock(earlier.clone(), Secret::new(KEY)).unwrap();
        let conversation = store.row_id(TableId::CONTACT, b"alice");
        let first = store.row_id(TableId::MESSAGE, b"alice/1");
        let third = store.row_id(TableId::MESSAGE, b"alice/3");
        let mut batch = store.begin();
        batch
            .put(
                TableId::MESSAGE,
                third,
                Some(conversation),
                b"three",
                &mut Rng(15),
            )
            .unwrap();
        batch.commit().unwrap();
        let moved = store.lock();

        // A party with the file puts back each MAC of the earlier form,
        // and one record of version 0x01 under another owner. The MACs of
        // that form verify at the unlock, and the pass would bind the
        // record to the owner that the file names.
        let other = RowKey::derive(&Secret::new(KEY)).row_id(TableId::CONTACT, b"bob");
        let mut back = moved.clone();
        back.tables = earlier.tables.clone();
        let mut old = earlier
            .rows
            .get(&(TableId::MESSAGE, first))
            .unwrap()
            .clone();
        old.owner = Some(other);
        back.rows_mut().insert((TableId::MESSAGE, first), old);
        let mut store = Store::unlock(back, Secret::new(KEY)).unwrap();
        assert!(store.migration_due());
        // IDN-039: the pass finds a table that does not match the MAC that
        // came back, and it says so before a view reads the row.
        assert!(!store.migrate(&mut Rng(16)).unwrap());
        assert!(!store.migration_due());
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
        // A store that no party changed moves with no such word.
        let mut store = Store::unlock(earlier, Secret::new(KEY)).unwrap();
        assert!(store.migrate(&mut Rng(17)).unwrap());
    }

    #[test]
    fn a_store_in_the_bytes_of_version_1_unlocks_and_moves() {
        use umbra_crypto::{
            aead,
            hkdf::Hkdf,
            hmac::{digest::KeyInit, Hmac, Mac},
            sha3::Sha3_256,
        };
        // Each byte below comes from the layout of version 0x01 in Part 4
        // §4.6 and Part 14 §14.6.4 and from the primitives. No byte comes
        // from a function of the store. A store that an earlier build wrote
        // holds these bytes, thus a change that reads them no more fails
        // here.
        let expand = |salt: Option<&[u8]>, info: &[u8]| {
            let mut out = Secret::<32>::zeroed();
            Hkdf::<Sha3_256>::new(salt, &KEY)
                .expand(info, out.expose_mut())
                .unwrap();
            out
        };
        let hmac = |key: &Secret<32>, parts: &[&[u8]]| -> [u8; 32] {
            let mut mac = Hmac::<Sha3_256>::new_from_slice(key.expose()).unwrap();
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().into()
        };
        let row_key = expand(None, b"umbra/v1/row-id");
        let table_key = expand(None, b"umbra/v1/table-mac");
        // `row_id`: the first 16 bytes of the MAC over the table and the
        // natural key.
        let row_id = |table: u8, natural: &[u8]| -> RowId {
            hmac(&row_key, &[&[table], natural])[..16]
                .try_into()
                .unwrap()
        };
        let conversation = row_id(0x03, b"alice");
        // The table, the row, the owner column, the salt, and the plaintext.
        type Row<'a> = (u8, RowId, Option<RowId>, u8, &'a [u8]);
        let content: [Row<'_>; 3] = [
            (
                0x01,
                row_id(0x01, b"alice/1"),
                Some(conversation),
                0xA1,
                b"one",
            ),
            (
                0x01,
                row_id(0x01, b"alice/2"),
                Some(conversation),
                0xA2,
                b"two",
            ),
            (0x03, conversation, None, 0xA3, b"alice"),
        ];
        let mut backend = MemoryBackend::default();
        let mut set_accum = [0u8; 32];
        for table in [0x01u8, 0x03] {
            let mut accum = [0u8; 32];
            let mut count = 0u64;
            for (_, row, owner, salt, plain) in content.iter().filter(|row| row.0 == table) {
                // The record: `record_salt || nonce || ct || tag`, under
                // the key of its salt, its table and its row. The
                // associated data is `table_id || row_id`: no version and
                // no owner.
                let salt = [*salt; 16];
                let nonce = [0xB0; aead::NONCE_LEN];
                let ad = [&[table][..], row].concat();
                let key = expand(Some(&salt), &[&b"umbra/v1/record-key"[..], &ad].concat());
                let mut body = plain.to_vec();
                let tag = aead::seal(&key, &nonce, &ad, &mut body).unwrap();
                let sealed = [&salt[..], &nonce, &body, &tag].concat();
                // `row_tag`: 0x01, the table, the row, and the record tag.
                let row_tag = hmac(&table_key, &[&[0x01], &[table], row, &tag]);
                for (byte, tag) in accum.iter_mut().zip(row_tag) {
                    *byte ^= tag;
                }
                count += 1;
                backend.rows.insert(
                    (TableId(table), *row),
                    StoredRow {
                        row_id: *row,
                        owner: *owner,
                        sealed,
                    },
                );
            }
            // `table_mac`: 0x02, the table, the count of the rows, the
            // commit counter, and the accumulator.
            let counter = 7u64;
            let mac = hmac(
                &table_key,
                &[
                    &[0x02],
                    &[table],
                    &count.to_be_bytes(),
                    &counter.to_be_bytes(),
                    &accum,
                ],
            );
            backend.tables.insert(
                TableId(table),
                StoredTable {
                    accum,
                    row_count: count,
                    commit_counter: counter,
                    mac,
                },
            );
            // The set of tables is table 0x00: a table is a row of it
            // under its identifier, with a record tag of 16 zero bytes.
            let set_tag = hmac(&table_key, &[&[0x01], &[0x00], &[table], &[0; 16]]);
            for (byte, tag) in set_accum.iter_mut().zip(set_tag) {
                *byte ^= tag;
            }
        }
        let set_mac = hmac(
            &table_key,
            &[
                &[0x02],
                &[0x00],
                &2u64.to_be_bytes(),
                &1u64.to_be_bytes(),
                &set_accum,
            ],
        );
        backend.tables.insert(
            TableId::SET,
            StoredTable {
                accum: set_accum,
                row_count: 2,
                commit_counter: 1,
                mac: set_mac,
            },
        );

        // The unlock takes the store as one of the earlier form, reads
        // each record, and passes the scan of that form.
        let first = content[0].1;
        let mut store = Store::unlock(backend.clone(), Secret::new(KEY)).unwrap();
        assert!(store.migration_due());
        assert!(store.indexed());
        assert_eq!(store.row_id(TableId::MESSAGE, b"alice/1"), first);
        assert_eq!(store.row_id(TableId::CONTACT, b"alice"), conversation);
        assert_eq!(
            store.get(TableId::MESSAGE, &first).unwrap().unwrap(),
            b"one"
        );
        store.audit(TableId::MESSAGE).unwrap();
        store.audit(TableId::CONTACT).unwrap();
        // The move: each record under its owner, and each MAC of the
        // current form.
        assert!(store.migrate(&mut Rng(18)).unwrap());
        assert!(!store.migration_due());
        store.audit(TableId::MESSAGE).unwrap();
        store.audit(TableId::CONTACT).unwrap();
        let moved = store.lock();
        for (key, row) in &backend.rows {
            let held = moved.rows.get(key).unwrap();
            assert_eq!(held.owner, row.owner);
            assert_ne!(held.sealed, row.sealed);
        }
        let store = Store::unlock(moved.clone(), Secret::new(KEY)).unwrap();
        assert!(!store.migration_due());
        assert_eq!(
            store.list(TableId::MESSAGE, Some(&conversation)).unwrap(),
            {
                let mut rows = alloc::vec![
                    (content[0].1, b"one".to_vec()),
                    (content[1].1, b"two".to_vec()),
                ];
                rows.sort();
                rows
            }
        );
        assert_eq!(
            store.get(TableId::CONTACT, &conversation).unwrap().unwrap(),
            b"alice"
        );
        // IMP-121: the owner column is in the record now.
        let mut other = moved;
        other
            .rows_mut()
            .get_mut(&(TableId::MESSAGE, first))
            .unwrap()
            .owner = None;
        let store = Store::unlock(other, Secret::new(KEY)).unwrap();
        assert_eq!(store.get(TableId::MESSAGE, &first), Err(Error::Unverified));
    }

    #[test]
    fn a_salt_that_a_party_sets_to_zero_fails_the_scan() {
        let (store, _, first, _) = filled();
        let mut backend = store.lock();
        // IDN-031, IDN-163: a row hidden by a zero salt shows in the scan.
        let row = backend.rows.get_mut(&(TableId::MESSAGE, first)).unwrap();
        for byte in row.sealed.iter_mut().take(16) {
            *byte = 0;
        }
        let store = Store::unlock(backend, Secret::new(KEY)).unwrap();
        assert_eq!(store.audit(TableId::MESSAGE), Err(Error::Unverified));
    }

    #[test]
    fn a_deletion_batch_removes_a_row_and_discards_a_key() {
        let (mut store, conversation, first, second) = filled();
        let mut batch = store.begin();
        batch.delete(TableId::MESSAGE, first);
        batch.discard_key(TableId::MESSAGE, second).unwrap();
        batch.delete(TableId::MESSAGE, [9; 16]);
        batch.commit().unwrap();

        assert_eq!(store.get(TableId::MESSAGE, &first).unwrap(), None);
        assert_eq!(store.get(TableId::MESSAGE, &second), Err(Error::Stale));
        assert!(store
            .list(TableId::MESSAGE, Some(&conversation))
            .unwrap()
            .is_empty());
        store.audit(TableId::MESSAGE).unwrap();
        let backend = store.lock();
        assert_eq!(backend.deletion_batches, 1);
        Store::unlock(backend, Secret::new(KEY)).unwrap();
    }
}
