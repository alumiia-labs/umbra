//! The store over a platform backend (Part 4 §4.6, Part 14 §14.6.4): the
//! commit batch that keeps each table MAC in step with its rows, the
//! check of each MAC at the unlock, the scan that compares a table with
//! its accumulator, and the deletion batch.
//!
//! The backend is SQLite on Android and IndexedDB in the web client. It
//! reads and writes opaque bytes under surrogate identifiers, and it holds
//! no key.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{rand_core::CryptoRng, secret::Secret};

use super::record::{RowId, RowKey, SealedRecord, TableId};
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
}

/// The tag of one table in the set MAC: a table is a row of the set.
fn set_tag(table_key: &TableKey, table: TableId) -> [u8; 32] {
    table_key.row_tag(&[TableId::SET.0], &[table.0], &[0; 16])
}

impl<B: Backend> Store<B> {
    /// Unlocks the store, and verifies each table MAC without a scan
    /// (`IDN-037`, `IDN-038`). A mismatch is `Unverified`, and the client
    /// tells the user (`IDN-039`, `IDN-040`).
    pub fn unlock(backend: B, store_key: Secret<32>) -> Result<Self, Error> {
        let table_key = TableKey::derive(&store_key);
        let row_key = RowKey::derive(&store_key);
        let mut tables = BTreeMap::new();
        let mut held_set = None;
        let mut scanned = TableState::new();
        for (table, stored) in backend.tables()? {
            let state = TableState::restore(stored.accum, stored.row_count, stored.commit_counter);
            state.verify(&table_key, &[table.0], &stored.mac)?;
            if table == TableId::SET {
                held_set = Some(state);
                continue;
            }
            scanned.insert(&set_tag(&table_key, table));
            tables.insert(table, state);
        }
        // IDN-193: a table whose MAC row left the file shows here, since
        // the set MAC counts each table that the store ever held.
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
        })
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
        Ok(Some(sealed.open(&self.store_key, table, row_id)?))
    }

    /// Reads and opens each row of one owner, or each row of the table.
    /// A row with a discarded key is left out.
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
            out.push((
                row.row_id,
                sealed.open(&self.store_key, table, &row.row_id)?,
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
            out.push((
                row.row_id,
                row.owner,
                sealed.open(&self.store_key, table, &row.row_id)?,
            ));
        }
        Ok(out)
    }

    /// Compares a table with its accumulator by a scan. The unlock does
    /// not run this (`IDN-037`); the client runs it in the background. It
    /// finds a removed row, a row from an earlier state, and two rows with
    /// one identifier (`IDN-031`, `IDN-032`).
    pub fn audit(&self, table: TableId) -> Result<(), Error> {
        let mut scanned = TableState::new();
        let mut seen: Vec<RowId> = Vec::new();
        for row in self.backend.rows(table, None)? {
            if seen.contains(&row.row_id) {
                return Err(Error::Unverified);
            }
            seen.push(row.row_id);
            let tag = SealedRecord::from_bytes(row.sealed)?.tag();
            scanned.insert(&self.table_key.row_tag(&[table.0], &row.row_id, &tag));
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
    /// Writes a row under a fresh record key.
    pub fn put<R: CryptoRng + ?Sized>(
        &mut self,
        table: TableId,
        row_id: RowId,
        owner: Option<RowId>,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let sealed = SealedRecord::seal(&self.store.store_key, table, &row_id, plaintext, rng)?;
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
        let mut states: BTreeMap<TableId, TableState> = BTreeMap::new();
        let mut writes = Vec::with_capacity(self.pending.len());
        for ((table, row_id), change) in self.pending {
            let state = states
                .entry(table)
                .or_insert_with(|| store.tables.get(&table).cloned().unwrap_or_default());
            let table_id = [table.0];
            let old_tag = match store.backend.read(table, &row_id)? {
                Some(old) => {
                    let tag = SealedRecord::from_bytes(old.sealed)?.tag();
                    Some(store.table_key.row_tag(&table_id, &row_id, &tag))
                }
                None => None,
            };
            match change {
                Pending::Put(row) => {
                    let tag = SealedRecord::from_bytes(row.sealed.clone())?.tag();
                    let new_tag = store.table_key.row_tag(&table_id, &row_id, &tag);
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
        let mut set = store.set.clone();
        let mut set_changed = !store.indexed;
        for table in states.keys() {
            if !store.tables.contains_key(table) {
                set.insert(&set_tag(&store.table_key, *table));
                set_changed = true;
            }
        }
        if set_changed {
            let mac = set.commit(&store.table_key, &[TableId::SET.0]);
            let (accum, row_count, commit_counter) = set.fields();
            writes.push(Write::Table(
                TableId::SET,
                StoredTable {
                    accum,
                    row_count,
                    commit_counter,
                    mac,
                },
            ));
        }
        for (table, state) in &mut states {
            let mac = state.commit(&store.table_key, &[table.0]);
            let (accum, row_count, commit_counter) = state.fields();
            writes.push(Write::Table(
                *table,
                StoredTable {
                    accum,
                    row_count,
                    commit_counter,
                    mac,
                },
            ));
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
        // A store with no set MAC opens and writes one at its next commit.
        let mut earlier = current;
        earlier.tables.remove(&TableId::SET);
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
