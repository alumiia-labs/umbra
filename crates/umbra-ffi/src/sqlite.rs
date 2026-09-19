//! The SQLite backend of Part 15 §15.6.4: plain SQLite from the bundled
//! library, with each record sealed by the application. The database
//! indexes on the keyed surrogates only, runs under `secure_delete`, and
//! truncates its write-ahead log after a deletion batch.

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

/// A store in one SQLite file.
pub struct SqliteBackend {
    connection: Connection,
}

impl SqliteBackend {
    /// Opens the database at `path`, and makes the schema at the first
    /// launch (`IMP-042`).
    pub fn open(path: &str) -> Result<Self, Error> {
        Self::prepare(storage(Connection::open(path))?)
    }

    /// A database in memory, for a test.
    pub fn in_memory() -> Result<Self, Error> {
        Self::prepare(storage(Connection::open_in_memory())?)
    }

    fn prepare(connection: Connection) -> Result<Self, Error> {
        storage(connection.pragma_update(None, "secure_delete", "ON"))?;
        storage(connection.pragma_update(None, "journal_mode", "WAL"))?;
        storage(connection.execute_batch(SCHEMA))?;
        Ok(SqliteBackend { connection })
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
        if batch.deletion {
            // IMP-043: no frame of the deleted record stays in the log.
            storage(
                self.connection
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())),
            )?;
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
}
