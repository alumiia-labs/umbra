//! The SQLite backend of Part 14 §14.6.4: plain SQLite from the bundled
//! library, with each record sealed by the application. The database
//! indexes on the keyed surrogates only, runs under `secure_delete`, and
//! truncates its write-ahead log after a deletion batch.

use std::{
    collections::BTreeMap,
    sync::{Condvar, Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{params, Connection, OptionalExtension};
use umbra_core::{
    store::{
        engine::{Backend, Batch, StoredRow, StoredTable, Write},
        record::{RowId, TableId},
        wrap::{WrapHeader, HEADER_LEN},
    },
    Error,
};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS rows (
        table_id INTEGER NOT NULL,
        row_id   BLOB NOT NULL,
        owner    BLOB,
        sealed   BLOB NOT NULL,
        PRIMARY KEY (table_id, row_id)
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS rows_by_owner ON rows (table_id, owner);
    CREATE TABLE IF NOT EXISTS tables (
        table_id       INTEGER PRIMARY KEY,
        accum          BLOB NOT NULL,
        row_count      INTEGER NOT NULL,
        commit_counter INTEGER NOT NULL,
        mac            BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS wrap (
        id     INTEGER PRIMARY KEY CHECK (id = 1),
        header BLOB NOT NULL
    );
";

/// The three columns of one row: the identifier, the owner, and the
/// sealed record.
type Columns = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);

fn storage<T>(result: rusqlite::Result<T>) -> Result<T, Error> {
    result.map_err(|_| Error::Storage)
}

fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Storage)
}

/// The count of the connections of this process that hold each database
/// file, by the path that opened it.
static OPEN: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());
/// Signals each connection that closed to [`SqliteBackend::await_closed`].
static CLOSED: Condvar = Condvar::new();

fn open_files() -> MutexGuard<'static, BTreeMap<String, usize>> {
    OPEN.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One connection in the count of its file, until its drop.
struct Counted(String);

impl Counted {
    fn new(path: &str) -> Self {
        let mut open = open_files();
        let count = open.entry(path.to_owned()).or_insert(0);
        *count = count.saturating_add(1);
        Counted(path.to_owned())
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        let mut open = open_files();
        if let Some(count) = open.get_mut(&self.0) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.0);
            }
        }

        drop(open);
        CLOSED.notify_all();
    }
}

/// A store in one SQLite file.
pub struct SqliteBackend {
    connection: Connection,
    /// The place of this connection in the count of its file. The fields
    /// drop in their order, thus the count falls after the connection
    /// closed.
    _counted: Option<Counted>,
    /// A checkpoint of a deletion that did not truncate the log, which the
    /// next batch runs again (`IMP-043`).
    checkpoint_due: bool,
    /// The checkpoints that ran, which a test reads.
    #[cfg(test)]
    checkpoints: u32,
}

impl SqliteBackend {
    /// Opens the database at `path`, and makes the schema at the first
    /// launch (`IMP-042`).
    pub fn open(path: &str) -> Result<Self, Error> {
        let counted = Counted::new(path);
        Self::prepare(storage(Connection::open(path))?, Some(counted))
    }

    /// A database in memory, for a test.
    pub fn in_memory() -> Result<Self, Error> {
        Self::prepare(storage(Connection::open_in_memory())?, None)
    }

    /// Waits until no connection of this process holds the database that
    /// `path` opened, for `wait` at most. The result is false when one
    /// still holds it. The path is the text that [`SqliteBackend::open`]
    /// took: another spelling of one file names another count.
    pub fn await_closed(path: &str, wait: Duration) -> bool {
        let (open, _) = CLOSED
            .wait_timeout_while(open_files(), wait, |open| open.contains_key(path))
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !open.contains_key(path)
    }

    fn prepare(connection: Connection, counted: Option<Counted>) -> Result<Self, Error> {
        // The backend holds the two from here, thus a fault below closes
        // the connection before the count falls too.
        let mut backend = SqliteBackend {
            connection,
            _counted: counted,
            checkpoint_due: true,
            #[cfg(test)]
            checkpoints: 0,
        };

        let connection = &backend.connection;
        storage(connection.pragma_update(None, "secure_delete", "ON"))?;
        storage(connection.pragma_update(None, "journal_mode", "WAL"))?;
        storage(connection.execute_batch(SCHEMA))?;

        // IMP-043: a checkpoint that an earlier run left undone runs now,
        // and at the next batch when a reader keeps it from its end.
        backend.checkpoint();
        Ok(backend)
    }

    /// Whether the file at `path` holds the header of its wrap, read with a
    /// connection that writes nothing: no schema, no checkpoint.
    pub fn holds_header(path: &str) -> Result<bool, Error> {
        let connection = storage(Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ))?;
        let tables: i64 = storage(connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'wrap'",
            [],
            |row| row.get(0),
        ))?;
        if tables == 0 {
            return Ok(false);
        }

        let headers: i64 = storage(connection.query_row(
            "SELECT count(*) FROM wrap WHERE id = 1 AND header IS NOT NULL",
            [],
            |row| row.get(0),
        ))?;
        Ok(headers > 0)
    }

    /// Moves each frame of the log into the file and empties the log
    /// (`IMP-043`). A checkpoint that a reader keeps from its end stays due.
    fn checkpoint(&mut self) {
        let busy = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                row.get::<_, i64>(0)
            });
        self.checkpoint_due = !matches!(busy, Ok(0));
        #[cfg(test)]
        {
            self.checkpoints = self.checkpoints.saturating_add(1);
        }
    }

    /// The header of the wrap, which holds no secret and sits beside the
    /// records.
    pub fn header(&self) -> Result<Option<WrapHeader>, Error> {
        let bytes: Option<Vec<u8>> = storage(
            self.connection
                .query_row("SELECT header FROM wrap WHERE id = 1", [], |row| row.get(0))
                .optional(),
        )?;
        bytes.map(|b| WrapHeader::parse(&b)).transpose()
    }

    /// Stores the header at the creation and at a passphrase change.
    pub fn set_header(&self, header: &WrapHeader) -> Result<(), Error> {
        let bytes: [u8; HEADER_LEN] = header.encode()?;
        storage(self.connection.execute(
            "INSERT INTO wrap (id, header) VALUES (1, ?1)
             ON CONFLICT (id) DO UPDATE SET header = excluded.header",
            params![bytes.as_slice()],
        ))?;
        Ok(())
    }

    fn row_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<Columns> {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }

    fn stored((row_id, owner, sealed): Columns) -> Result<StoredRow, Error> {
        Ok(StoredRow {
            row_id: array(row_id)?,
            owner: owner.map(array).transpose()?,
            sealed,
        })
    }
}

impl Backend for SqliteBackend {
    fn read(&self, table: TableId, row_id: &RowId) -> Result<Option<StoredRow>, Error> {
        let found = storage(
            self.connection
                .query_row(
                    "SELECT row_id, owner, sealed FROM rows WHERE table_id = ?1 AND row_id = ?2",
                    params![table.0, row_id.as_slice()],
                    Self::row_of,
                )
                .optional(),
        )?;
        found.map(Self::stored).transpose()
    }

    fn rows(&self, table: TableId, owner: Option<&RowId>) -> Result<Vec<StoredRow>, Error> {
        let (sql, owner_bytes) = match owner {
            Some(owner) => (
                "SELECT row_id, owner, sealed FROM rows WHERE table_id = ?1 AND owner = ?2",
                Some(owner.as_slice()),
            ),
            None => (
                "SELECT row_id, owner, sealed FROM rows WHERE table_id = ?1 AND ?2 IS NULL",
                None,
            ),
        };

        let mut statement = storage(self.connection.prepare(sql))?;
        let found = storage(statement.query_map(params![table.0, owner_bytes], Self::row_of))?;
        let mut out = Vec::new();
        for row in found {
            out.push(Self::stored(storage(row)?)?);
        }
        Ok(out)
    }

    fn row_ids(
        &self,
        table: TableId,
        after: Option<&RowId>,
        limit: usize,
    ) -> Result<Vec<RowId>, Error> {
        // The primary key orders the rows of a table by `row_id`, thus the
        // read starts in the index at `after` and loads no record. No row
        // identifier is below the empty one.
        let mut statement = storage(self.connection.prepare(
            "SELECT row_id FROM rows
             WHERE table_id = ?1 AND row_id > ?2
             ORDER BY row_id LIMIT ?3",
        ))?;

        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let after = after.map_or(&[][..], |after| after.as_slice());
        let found = storage(statement.query_map(params![table.0, after, limit], |row| {
            row.get::<_, Vec<u8>>(0)
        }))?;

        let mut out = Vec::new();
        for row_id in found {
            out.push(array(storage(row_id)?)?);
        }
        Ok(out)
    }

    fn tables(&self) -> Result<Vec<(TableId, StoredTable)>, Error> {
        let mut statement = storage(
            self.connection
                .prepare("SELECT table_id, accum, row_count, commit_counter, mac FROM tables"),
        )?;
        let found = storage(statement.query_map([], |row| {
            Ok((
                row.get::<_, u8>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        }))?;

        let mut out = Vec::new();
        for row in found {
            let (table, accum, row_count, commit_counter, mac) = storage(row)?;
            out.push((
                TableId(table),
                StoredTable {
                    accum: array(accum)?,
                    row_count: u64::try_from(row_count).map_err(|_| Error::Storage)?,
                    commit_counter: u64::try_from(commit_counter).map_err(|_| Error::Storage)?,
                    mac: array(mac)?,
                },
            ));
        }
        Ok(out)
    }

    fn apply(&mut self, batch: &Batch) -> Result<(), Error> {
        // IMP-123: the rows and the table MACs of a batch commit together.
        let transaction = storage(self.connection.transaction())?;

        // IMP-133: a batch that replaces the row of a channel is no
        // deletion batch. The state before it holds chain keys that the
        // forward secrecy erased. Without a checkpoint the file keeps that
        // state while the log holds the new one. The first row of a channel
        // replaces none, thus it asks for no checkpoint, and one lookup in
        // the primary key answers for the batch.
        let mut replaces_channel = false;
        for write in &batch.writes {
            match write {
                Write::Put(table, row) if *table == TableId::CONTACT && !replaces_channel => {
                    let held: Option<i64> = storage(
                        transaction
                            .query_row(
                                "SELECT 1 FROM rows WHERE table_id = ?1 AND row_id = ?2",
                                params![table.0, row.row_id.as_slice()],
                                |row| row.get(0),
                            )
                            .optional(),
                    )?;
                    replaces_channel = held.is_some();
                }
                _ => {}
            }
        }

        for write in &batch.writes {
            match write {
                Write::Put(table, row) => storage(transaction.execute(
                    "INSERT INTO rows (table_id, row_id, owner, sealed) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (table_id, row_id)
                     DO UPDATE SET owner = excluded.owner, sealed = excluded.sealed",
                    params![
                        table.0,
                        row.row_id.as_slice(),
                        row.owner.as_ref().map(|o| o.as_slice()),
                        row.sealed.as_slice()
                    ],
                ))?,
                Write::Delete(table, row_id) => storage(transaction.execute(
                    "DELETE FROM rows WHERE table_id = ?1 AND row_id = ?2",
                    params![table.0, row_id.as_slice()],
                ))?,
                Write::Table(table, stored) => storage(transaction.execute(
                    "INSERT INTO tables (table_id, accum, row_count, commit_counter, mac)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (table_id) DO UPDATE SET accum = excluded.accum,
                         row_count = excluded.row_count,
                         commit_counter = excluded.commit_counter, mac = excluded.mac",
                    params![
                        table.0,
                        stored.accum.as_slice(),
                        i64::try_from(stored.row_count).map_err(|_| Error::Storage)?,
                        i64::try_from(stored.commit_counter).map_err(|_| Error::Storage)?,
                        stored.mac.as_slice()
                    ],
                ))?,
            };
        }

        storage(transaction.commit())?;
        if batch.deletion || replaces_channel || self.checkpoint_due {
            // IMP-043: no frame of the deleted record stays in the log. The
            // batch holds with its commit; a checkpoint that a reader kept
            // from its end goes again at the next batch, thus the state of
            // the tables never parts from the file (IMP-123). One
            // checkpoint serves the whole batch.
            self.checkpoint();
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use umbra_core::store::engine::Store;
    use umbra_crypto::secret::Secret;

    use super::*;

    #[test]
    fn a_file_counts_as_closed_after_its_last_connection_closed() {
        let directory = std::env::temp_dir().join(format!("umbra-ffi-c-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("count.db");
        let _ = std::fs::remove_file(&path);
        let path_text = path.to_str().unwrap().to_owned();

        assert!(SqliteBackend::await_closed(&path_text, Duration::ZERO));
        let first = SqliteBackend::open(&path_text).unwrap();
        let second = SqliteBackend::open(&path_text).unwrap();
        assert!(!SqliteBackend::await_closed(&path_text, Duration::ZERO));
        drop(first);
        assert!(!SqliteBackend::await_closed(
            &path_text,
            Duration::from_millis(50)
        ));

        // The wait ends at the close on another thread, before its bound.
        let closes = std::thread::spawn(move || drop(second));
        assert!(SqliteBackend::await_closed(
            &path_text,
            Duration::from_secs(60)
        ));
        closes.join().unwrap();

        // A file that is closed takes its removal on each platform.
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_file_with_no_header_is_no_store() {
        let directory = std::env::temp_dir().join(format!("umbra-ffi-h-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("header.db");
        let _ = std::fs::remove_file(&path);
        let path_text = path.to_str().unwrap().to_owned();

        // A first launch that ended before its header.
        let backend = SqliteBackend::open(&path_text).unwrap();
        assert!(!SqliteBackend::holds_header(&path_text).unwrap());
        let header = umbra_core::store::wrap::WrapHeader {
            cost: umbra_core::store::wrap::Cost {
                m_kib: umbra_core::store::wrap::M_KIB_FLOOR,
                t: umbra_core::store::wrap::T_FLOOR,
            },
            salt: [1; 16],
            nonce: [2; 24],
            wrapped: [3; 32],
            tag: [4; 16],
        };

        backend.set_header(&header).unwrap();
        assert!(SqliteBackend::holds_header(&path_text).unwrap());
        drop(backend);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_store_runs_over_sqlite_and_a_deleted_record_leaves_the_file() {
        let directory = std::env::temp_dir().join(format!("umbra-ffi-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("store.db");
        let _ = std::fs::remove_file(&path);
        let path_text = path.to_str().unwrap().to_owned();

        struct Counter(u8);
        impl umbra_crypto::rand_core::TryRng for Counter {
            type Error = core::convert::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for byte in dst {
                    self.0 = self.0.wrapping_add(1);
                    *byte = self.0;
                }
                Ok(())
            }
        }
        impl umbra_crypto::rand_core::TryCryptoRng for Counter {}

        let mut rng = Counter(0);
        let mut store = Store::unlock(
            SqliteBackend::open(&path_text).unwrap(),
            Secret::new([1; 32]),
        )
        .unwrap();

        let owner = store.row_id(TableId::CONTACT, b"alice");
        let row = store.row_id(TableId::MESSAGE, b"alice/1");
        let mut batch = store.begin();
        batch
            .put(TableId::MESSAGE, row, Some(owner), b"a message", &mut rng)
            .unwrap();
        batch.commit().unwrap();
        let sealed = store
            .lock()
            .read(TableId::MESSAGE, &row)
            .unwrap()
            .unwrap()
            .sealed;

        // The record is in the file now, thus the check below proves a
        // removal and not an absence.
        let holds = |needle: &[u8]| {
            std::fs::read_dir(&directory).unwrap().any(|entry| {
                let bytes = std::fs::read(entry.unwrap().path()).unwrap();
                bytes.windows(needle.len()).any(|window| window == needle)
            })
        };
        assert!(holds(&sealed[..24]));

        // The file opens again, and the MAC of each table verifies.
        let mut store = Store::unlock(
            SqliteBackend::open(&path_text).unwrap(),
            Secret::new([1; 32]),
        )
        .unwrap();
        assert_eq!(
            store.get(TableId::MESSAGE, &row).unwrap().unwrap(),
            b"a message"
        );
        assert_eq!(store.list(TableId::MESSAGE, Some(&owner)).unwrap().len(), 1);
        assert!(store.list(TableId::MESSAGE, Some(&row)).unwrap().is_empty());
        store.audit(TableId::MESSAGE).unwrap();

        // The walk of a table by its row identifiers, one page at a time.
        let more: Vec<RowId> = (0..5u8)
            .map(|index| store.row_id(TableId::MESSAGE, &[index]))
            .collect();
        let mut batch = store.begin();
        for next in &more {
            batch
                .put(TableId::MESSAGE, *next, Some(owner), b"another", &mut rng)
                .unwrap();
        }
        batch.commit().unwrap();

        let mut written = more;
        written.push(row);
        written.sort_unstable();
        let backend = store.lock();
        let mut walked = Vec::new();
        let mut after = None;
        loop {
            let page = backend
                .row_ids(TableId::MESSAGE, after.as_ref(), 2)
                .unwrap();
            assert!(page.len() <= 2);
            let Some(last) = page.last().copied() else {
                break;
            };

            after = Some(last);
            walked.extend(page);
        }
        assert_eq!(walked, written);
        assert!(backend
            .row_ids(TableId::CONTACT, None, 8)
            .unwrap()
            .is_empty());
        let mut store = Store::unlock(backend, Secret::new([1; 32])).unwrap();
        assert!(Store::unlock(
            SqliteBackend::open(&path_text).unwrap(),
            Secret::new([2; 32])
        )
        .is_err());

        let mut batch = store.begin();
        batch.delete(TableId::MESSAGE, row);
        batch.commit().unwrap();
        drop(store);

        // WIR-356: the ciphertext of the deleted record is in no file.
        assert!(!holds(&sealed[..24]));

        let backend = SqliteBackend::open(&path_text).unwrap();
        assert!(backend.header().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_channel_row_that_a_commit_replaces_leaves_the_file() {
        let directory = std::env::temp_dir().join(format!("umbra-ffi-c-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("channel.db");
        let _ = std::fs::remove_file(&path);
        let path_text = path.to_str().unwrap().to_owned();

        struct Counter(u8);
        impl umbra_crypto::rand_core::TryRng for Counter {
            type Error = core::convert::Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for byte in dst {
                    self.0 = self.0.wrapping_add(1);
                    *byte = self.0;
                }
                Ok(())
            }
        }
        impl umbra_crypto::rand_core::TryCryptoRng for Counter {}

        let mut rng = Counter(0);
        let mut store = Store::unlock(
            SqliteBackend::open(&path_text).unwrap(),
            Secret::new([1; 32]),
        )
        .unwrap();

        let row = store.row_id(TableId::CONTACT, b"alice");
        let other = store.row_id(TableId::CONTACT, b"bob");
        let mut batch = store.begin();
        batch
            .put(TableId::CONTACT, row, None, b"the first state", &mut rng)
            .unwrap();
        batch
            .put(TableId::CONTACT, other, None, b"the first of bob", &mut rng)
            .unwrap();
        batch.commit().unwrap();

        let backend = store.lock();

        // The first row of a channel replaces no state: the open ran one
        // checkpoint, and this batch ran none.
        assert_eq!(backend.checkpoints, 1);
        let sealed = backend
            .read(TableId::CONTACT, &row)
            .unwrap()
            .unwrap()
            .sealed;
        let holds = |needle: &[u8]| {
            std::fs::read_dir(&directory).unwrap().any(|entry| {
                let bytes = std::fs::read(entry.unwrap().path()).unwrap();
                bytes.windows(needle.len()).any(|window| window == needle)
            })
        };
        assert!(holds(&sealed[..24]));

        // IMP-133: the commit of the next state is a put and no delete. The
        // earlier state is in no file after it: not in the database, and
        // not in its log.
        let mut store = Store::unlock(backend, Secret::new([1; 32])).unwrap();
        let mut batch = store.begin();
        batch
            .put(TableId::CONTACT, row, None, b"the next state!", &mut rng)
            .unwrap();
        batch
            .put(TableId::CONTACT, other, None, b"the next of bob!", &mut rng)
            .unwrap();
        batch.commit().unwrap();
        assert!(!holds(&sealed[..24]));

        // One checkpoint serves the two rows of the batch.
        let backend = store.lock();
        assert_eq!(backend.checkpoints, 2);
        let store = Store::unlock(backend, Secret::new([1; 32])).unwrap();
        assert_eq!(
            store.get(TableId::CONTACT, &row).unwrap().unwrap(),
            b"the next state!"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
