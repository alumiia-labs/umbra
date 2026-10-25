//! The store of a relay over SQLite. One commit of [`RelayStore::commit`]
//! is one transaction, thus a crash leaves the changes of a call in the file
//! as a whole or not at all.
//!
//! The file runs under `secure_delete`, and each commit that deletes rows
//! truncates the write-ahead log. A record that an `ACK` covered and a queue
//! that a `DEL` ended leave no bytes in the file (`WIR-039` to `WIR-042`).

use rusqlite::{params, types::Value, Connection, OptionalExtension};
use umbra_core::attach::store::{Class, Credentials, HeldChunk};
use umbra_queue::relay::Stored;

use crate::receipts::{KeptReceipt, ReceiptShelf};
use crate::store::{Loaded, RelayStore, StoreChange, StoreFault, StoredInvitation, StoredQueue};

/// The schema version in `user_version`. Version 2 added the group
/// queues of Part 11, version 3 the chunks of Part 12, and version 4 the
/// spent token nonces of `ABU-114`.
const SCHEMA_VERSION: i64 = 4;

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS queues (
        recipient_id BLOB PRIMARY KEY,
        head         BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS records (
        recipient_id BLOB NOT NULL,
        seq          INTEGER NOT NULL,
        accepted_at  INTEGER NOT NULL,
        bytes        BLOB NOT NULL,
        PRIMARY KEY (recipient_id, seq)
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS records_by_time ON records (accepted_at);
    CREATE TABLE IF NOT EXISTS invitations (
        link_id      BLOB PRIMARY KEY,
        recipient_id BLOB NOT NULL,
        at           INTEGER NOT NULL,
        blob         BLOB
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS group_queues (
        group_queue_id BLOB PRIMARY KEY,
        head           BLOB NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS group_records (
        group_queue_id BLOB NOT NULL,
        seq            INTEGER NOT NULL,
        accepted_at    INTEGER NOT NULL,
        bytes          BLOB NOT NULL,
        PRIMARY KEY (group_queue_id, seq)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS chunks (
        chunk_id      BLOB PRIMARY KEY,
        class         INTEGER NOT NULL,
        cred_pk       BLOB NOT NULL,
        read_pk       BLOB NOT NULL,
        registered_at INTEGER NOT NULL,
        renewed_at    INTEGER NOT NULL,
        erase_at      INTEGER NOT NULL,
        bytes         BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS spent (
        epoch INTEGER NOT NULL,
        nonce BLOB NOT NULL,
        PRIMARY KEY (epoch, nonce)
    ) WITHOUT ROWID;
";

/// The class of a chunk in its column.
const fn class_code(class: Class) -> i64 {
    match class {
        Class::Attachment => 1,
        Class::Backup => 2,
    }
}

/// The store of one relay in one SQLite file.
pub struct SqliteStore {
    connection: Connection,
}

fn fault<T>(result: rusqlite::Result<T>) -> Result<T, StoreFault> {
    result.map_err(|_| StoreFault)
}

/// SQLite holds a signed 64-bit integer. A time and a sequence number of
/// this protocol sit below that bound.
fn signed(value: u64) -> Result<i64, StoreFault> {
    i64::try_from(value).map_err(|_| StoreFault)
}

fn unsigned(value: i64) -> Result<u64, StoreFault> {
    u64::try_from(value).map_err(|_| StoreFault)
}

/// The bytes of a field of a `BLOB` column, or none for another type.
fn blob_of(value: Value) -> Option<Vec<u8>> {
    match value {
        Value::Blob(bytes) => Some(bytes),
        _ => None,
    }
}

/// An identifier of `N` bytes from a field of a `BLOB` column.
fn id_of<const N: usize>(value: Value) -> Option<[u8; N]> {
    blob_of(value)?.try_into().ok()
}

/// A field of an `INTEGER` column, or none for another type.
fn int_of(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(number) => Some(*number),
        _ => None,
    }
}

/// A time of an `INTEGER` column, which is never below zero.
fn time_of(value: &Value) -> Option<u64> {
    u64::try_from(int_of(value)?).ok()
}

/// Adds one stored record to its queue. A record that does not read makes
/// the head of its queue empty, thus the queue does not parse and leaves
/// the file (`NET-303`).
fn push_record(queue: &mut StoredQueue, seq: &Value, accepted_at: &Value, bytes: Value) {
    let seq = int_of(seq).and_then(|seq| u32::try_from(seq).ok());
    match (seq, time_of(accepted_at), blob_of(bytes)) {
        (Some(seq), Some(accepted_at), Some(bytes)) => queue.records.push(Stored {
            seq,
            accepted_at,
            bytes,
        }),
        _ => queue.head.clear(),
    }
}

impl SqliteStore {
    /// Opens the file at `path`, and makes it when it does not exist. A
    /// file of another schema version is a fault, and no data of it changes.
    pub fn open(path: &str) -> Result<Self, StoreFault> {
        let connection = fault(Connection::open(path))?;
        fault(connection.pragma_update(None, "secure_delete", "ON"))?;
        fault(connection.pragma_update(None, "journal_mode", "WAL"))?;
        // A `QUOTA` leaves after its commit, thus the commit reaches the
        // disk before it returns (`NET-298`).
        fault(connection.pragma_update(None, "synchronous", "FULL"))?;

        let version: i64 =
            fault(connection.query_row("PRAGMA user_version", [], |row| row.get(0)))?;
        let is_new = fault(
            connection
                .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |_| Ok(()))
                .optional(),
        )?
        .is_none();

        // Version 1 holds the pairwise queues alone, and version 2 adds the
        // group queues. The schema below adds tables and takes nothing
        // away, thus those files open here and keep what they hold.
        if !is_new && !(1..=SCHEMA_VERSION).contains(&version) {
            return Err(StoreFault);
        }

        fault(connection.execute_batch(SCHEMA))?;
        fault(connection.pragma_update(None, "user_version", SCHEMA_VERSION))?;

        Ok(SqliteStore { connection })
    }
}

impl RelayStore for SqliteStore {
    fn load(&mut self) -> Result<Loaded, StoreFault> {
        // NET-302: a record of no queue serves no one, and it leaves.
        fault(self.connection.execute_batch(
            "DELETE FROM records WHERE recipient_id NOT IN (SELECT recipient_id FROM queues);
             DELETE FROM group_records
                WHERE group_queue_id NOT IN (SELECT group_queue_id FROM group_queues);",
        ))?;

        let mut loaded = Loaded::default();
        // NET-303: a row whose fields do not read leaves the file, and each
        // other row stays. Before this, one such row stopped the load, and
        // the relay did not start.
        let mut dropped: Vec<(&str, Value)> = Vec::new();

        let mut queues = fault(
            self.connection
                .prepare("SELECT recipient_id, head FROM queues"),
        )?;
        let rows = fault(queues.query_map([], |row| {
            Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?))
        }))?;

        for row in rows {
            let (key, head) = fault(row)?;
            match (id_of::<32>(key.clone()), blob_of(head)) {
                (Some(recipient_id), Some(head)) => {
                    let queue = StoredQueue {
                        head,
                        records: Vec::new(),
                    };
                    loaded.queues.insert(recipient_id, queue);
                }
                // NET-302: the records of a queue that leaves go with it.
                _ => {
                    dropped.push(("DELETE FROM records WHERE recipient_id IS ?1", key.clone()));
                    dropped.push(("DELETE FROM queues WHERE recipient_id IS ?1", key));
                }
            }
        }

        let mut records = fault(self.connection.prepare(
            "SELECT recipient_id, seq, accepted_at, bytes FROM records ORDER BY recipient_id, seq",
        ))?;
        let rows = fault(records.query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
            ))
        }))?;

        for row in rows {
            let (recipient_id, seq, accepted_at, bytes) = fault(row)?;
            // NET-303: a record that does not read makes its queue one that
            // does not parse, and the other queues stay. A record of no
            // queue serves no one.
            let Some(queue) = id_of::<32>(recipient_id).and_then(|id| loaded.queues.get_mut(&id))
            else {
                continue;
            };

            push_record(queue, &seq, &accepted_at, bytes);
        }

        let mut group_queues = fault(
            self.connection
                .prepare("SELECT group_queue_id, head FROM group_queues"),
        )?;
        let rows = fault(group_queues.query_map([], |row| {
            Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?))
        }))?;

        for row in rows {
            let (key, head) = fault(row)?;
            match (id_of::<32>(key.clone()), blob_of(head)) {
                (Some(group_queue_id), Some(head)) => {
                    let queue = StoredQueue {
                        head,
                        records: Vec::new(),
                    };
                    loaded.group_queues.insert(group_queue_id, queue);
                }
                _ => {
                    let records = "DELETE FROM group_records WHERE group_queue_id IS ?1";
                    dropped.push((records, key.clone()));
                    dropped.push(("DELETE FROM group_queues WHERE group_queue_id IS ?1", key));
                }
            }
        }

        let mut group_records = fault(self.connection.prepare(
            "SELECT group_queue_id, seq, accepted_at, bytes FROM group_records
             ORDER BY group_queue_id, seq",
        ))?;
        let rows = fault(group_records.query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
            ))
        }))?;

        for row in rows {
            let (group_queue_id, seq, accepted_at, bytes) = fault(row)?;
            let Some(queue) =
                id_of::<32>(group_queue_id).and_then(|id| loaded.group_queues.get_mut(&id))
            else {
                continue;
            };

            push_record(queue, &seq, &accepted_at, bytes);
        }

        let mut invitations = fault(
            self.connection
                .prepare("SELECT link_id, recipient_id, at, blob FROM invitations"),
        )?;
        let rows = fault(invitations.query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
            ))
        }))?;

        for row in rows {
            let (key, recipient_id, at, blob) = fault(row)?;
            let blob = match blob {
                Value::Null => Some(None),
                Value::Blob(bytes) => Some(Some(bytes)),
                _ => None,
            };

            let held = (|| {
                Some(StoredInvitation {
                    recipient_id: id_of(recipient_id)?,
                    blob: blob?,
                    at: time_of(&at)?,
                })
            })();

            match (id_of(key.clone()), held) {
                (Some(link_id), Some(held)) => {
                    loaded.invitations.insert(link_id, held);
                }
                _ => dropped.push(("DELETE FROM invitations WHERE link_id IS ?1", key)),
            }
        }

        let mut spent = fault(
            self.connection
                .prepare("SELECT epoch, nonce FROM spent ORDER BY epoch"),
        )?;
        let rows = fault(spent.query_map([], |row| {
            Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?))
        }))?;

        for row in rows {
            let (epoch, nonce) = fault(row)?;
            // A row that does not read spends nothing.
            let epoch = int_of(&epoch).and_then(|epoch| u32::try_from(epoch).ok());
            if let (Some(epoch), Some(nonce)) = (epoch, id_of::<32>(nonce)) {
                loaded.spent.insert((epoch, nonce));
            }
        }

        let mut chunks = fault(self.connection.prepare(
            "SELECT chunk_id, class, cred_pk, read_pk, registered_at, renewed_at, erase_at, bytes
             FROM chunks",
        ))?;
        let rows = fault(chunks.query_map([], |row| {
            Ok((
                row.get::<_, Value>(0)?,
                row.get::<_, Value>(1)?,
                row.get::<_, Value>(2)?,
                row.get::<_, Value>(3)?,
                row.get::<_, Value>(4)?,
                row.get::<_, Value>(5)?,
                row.get::<_, Value>(6)?,
                row.get::<_, Value>(7)?,
            ))
        }))?;

        for row in rows {
            let (key, class, cred_pk, read_pk, registered_at, renewed_at, erase_at, bytes) =
                fault(row)?;

            let held = (|| {
                let class = match int_of(&class)? {
                    1 => Class::Attachment,
                    2 => Class::Backup,
                    _ => return None,
                };

                Some(HeldChunk {
                    class,
                    credentials: Credentials {
                        cred_pk: id_of(cred_pk)?,
                        read_pk: id_of(read_pk)?,
                    },
                    bytes: blob_of(bytes)?,
                    registered_at: time_of(&registered_at)?,
                    renewed_at: time_of(&renewed_at)?,
                    erase_at: time_of(&erase_at)?,
                })
            })();

            match (id_of(key.clone()), held) {
                (Some(chunk_id), Some(held)) => {
                    loaded.chunks.insert(chunk_id, held);
                }
                _ => dropped.push(("DELETE FROM chunks WHERE chunk_id IS ?1", key)),
            }
        }

        // Each statement above read its last row, thus no delete runs
        // under an open read.
        for (delete, key) in dropped {
            fault(self.connection.execute(delete, [key]))?;
        }

        Ok(loaded)
    }

    fn commit(&mut self, changes: &[StoreChange]) -> Result<(), StoreFault> {
        if changes.is_empty() {
            return Ok(());
        }

        let transaction = fault(self.connection.transaction())?;
        let mut deleted = false;

        for change in changes {
            match change {
                StoreChange::Queue { recipient_id, head } => fault(transaction.execute(
                    "INSERT INTO queues (recipient_id, head) VALUES (?1, ?2)
                     ON CONFLICT (recipient_id) DO UPDATE SET head = excluded.head",
                    params![recipient_id.as_slice(), head],
                ))?,
                StoreChange::Record {
                    recipient_id,
                    record,
                } => fault(transaction.execute(
                    "INSERT INTO records (recipient_id, seq, accepted_at, bytes)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        recipient_id.as_slice(),
                        i64::from(record.seq),
                        signed(record.accepted_at)?,
                        record.bytes
                    ],
                ))?,
                StoreChange::Acked { recipient_id, seq } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM records WHERE recipient_id = ?1 AND seq <= ?2",
                        params![recipient_id.as_slice(), i64::from(*seq)],
                    ))?
                }
                StoreChange::Expired { accepted_before } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM records WHERE accepted_at < ?1",
                        params![signed(*accepted_before)?],
                    ))?
                }
                StoreChange::QueueDeleted { recipient_id } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM records WHERE recipient_id = ?1",
                        params![recipient_id.as_slice()],
                    ))?;
                    fault(transaction.execute(
                        "DELETE FROM queues WHERE recipient_id = ?1",
                        params![recipient_id.as_slice()],
                    ))?
                }
                StoreChange::Invitation { link_id, held } => fault(transaction.execute(
                    "INSERT INTO invitations (link_id, recipient_id, at, blob)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (link_id) DO UPDATE
                     SET recipient_id = excluded.recipient_id, at = excluded.at,
                         blob = excluded.blob",
                    params![
                        link_id.as_slice(),
                        held.recipient_id.as_slice(),
                        signed(held.at)?,
                        held.blob
                    ],
                ))?,
                StoreChange::InvitationDeleted { link_id } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM invitations WHERE link_id = ?1",
                        params![link_id.as_slice()],
                    ))?
                }
                StoreChange::GroupQueue {
                    group_queue_id,
                    head,
                } => fault(transaction.execute(
                    "INSERT INTO group_queues (group_queue_id, head) VALUES (?1, ?2)
                     ON CONFLICT (group_queue_id) DO UPDATE SET head = excluded.head",
                    params![group_queue_id.as_slice(), head],
                ))?,
                StoreChange::GroupRecord {
                    group_queue_id,
                    record,
                } => fault(transaction.execute(
                    "INSERT INTO group_records (group_queue_id, seq, accepted_at, bytes)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        group_queue_id.as_slice(),
                        i64::from(record.seq),
                        signed(record.accepted_at)?,
                        record.bytes
                    ],
                ))?,
                StoreChange::GroupTrimmed {
                    group_queue_id,
                    through_seq,
                } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM group_records WHERE group_queue_id = ?1 AND seq <= ?2",
                        params![group_queue_id.as_slice(), i64::from(*through_seq)],
                    ))?
                }
                StoreChange::GroupQueueDeleted { group_queue_id } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM group_records WHERE group_queue_id = ?1",
                        params![group_queue_id.as_slice()],
                    ))?;
                    fault(transaction.execute(
                        "DELETE FROM group_queues WHERE group_queue_id = ?1",
                        params![group_queue_id.as_slice()],
                    ))?
                }
                StoreChange::Chunk { chunk_id, held } => fault(transaction.execute(
                    "INSERT OR REPLACE INTO chunks
                     (chunk_id, class, cred_pk, read_pk, registered_at, renewed_at, erase_at, bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        chunk_id.as_slice(),
                        class_code(held.class),
                        held.credentials.cred_pk.as_slice(),
                        held.credentials.read_pk.as_slice(),
                        signed(held.registered_at)?,
                        signed(held.renewed_at)?,
                        signed(held.erase_at)?,
                        held.bytes
                    ],
                ))?,
                StoreChange::ChunkRenewed {
                    chunk_id,
                    renewed_at,
                    erase_at,
                } => fault(transaction.execute(
                    "UPDATE chunks SET renewed_at = ?2, erase_at = ?3 WHERE chunk_id = ?1",
                    params![
                        chunk_id.as_slice(),
                        signed(*renewed_at)?,
                        signed(*erase_at)?
                    ],
                ))?,
                StoreChange::ChunkDeleted { chunk_id } => {
                    deleted = true;
                    fault(transaction.execute(
                        "DELETE FROM chunks WHERE chunk_id = ?1",
                        params![chunk_id.as_slice()],
                    ))?
                }
                StoreChange::Spent { epoch, nonce } => {
                    fault(transaction.execute(
                        "INSERT OR IGNORE INTO spent (epoch, nonce) VALUES (?1, ?2)",
                        params![i64::from(*epoch), nonce.as_slice()],
                    ))?;
                    // ABU-114: a nonce two epochs back names no token that
                    // passes.
                    fault(transaction.execute(
                        "DELETE FROM spent WHERE epoch < ?1",
                        [i64::from(epoch.saturating_sub(1))],
                    ))?
                }
            };
        }

        fault(transaction.commit())?;

        if deleted {
            // The log holds the old pages of a deleted row until a
            // checkpoint truncates it.
            fault(
                self.connection
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())),
            )?;
        }

        Ok(())
    }
}

/// The schema of a receipt file. Each leaf of a receipt has a row in
/// `receipt_leaves` under its epoch and its first 8 bytes, thus a query
/// reads the receipts that may cover its cell and no other.
const RECEIPT_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS receipts (
        id     INTEGER PRIMARY KEY,
        issued INTEGER NOT NULL,
        epoch  INTEGER NOT NULL,
        at     INTEGER NOT NULL,
        signed BLOB NOT NULL,
        leaves BLOB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS receipts_by_time ON receipts (at);
    CREATE TABLE IF NOT EXISTS receipt_leaves (
        epoch   INTEGER NOT NULL,
        leaf    INTEGER NOT NULL,
        receipt INTEGER NOT NULL,
        PRIMARY KEY (epoch, leaf, receipt)
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS receipt_leaves_by_receipt ON receipt_leaves (receipt);
";

/// The receipts of a relay in one SQLite file, apart from its queues. A
/// busy relay closes more windows in `RECEIPT_RETENTION` than RAM holds,
/// and a restart keeps each receipt that a query may ask for (`REL-073`).
pub struct SqliteShelf {
    connection: Connection,
    /// The bytes of receipts that the file holds at most.
    max_bytes: u64,
    /// The receipts that the shelf kept since it last read its size.
    since_check: u32,
}

/// The bytes of receipts that a receipt file holds at most. The peers of a
/// relay set the rate of its receipts. The file shares a disk with the
/// queues, whose failed commit stops the relay. Above the bound the oldest
/// receipts leave first, before `RECEIPT_RETENTION`.
pub const RECEIPT_FILE_MAX: u64 = 8 << 30;
/// The receipts between two reads of the size of the file.
const SIZE_CHECK_EVERY: u32 = 64;
/// The receipts that leave in one transaction when the file is above its
/// bound, and the transactions of one check. The shelf runs on the task of
/// the node, thus one check erases a bounded count of rows. That count is
/// more than the receipts between two checks, thus the file comes back
/// under its bound over some checks. No cell waits for one long erase.
const TRIM_BATCH: i64 = 8;
const TRIM_STEPS: u32 = 16;

/// The index column of a leaf: its first 8 bytes.
fn leaf_key(leaf: &[u8; 32]) -> i64 {
    i64::from_be_bytes(umbra_crypto::bytes::part::<0, 8, 32>(leaf))
}

impl SqliteShelf {
    /// Opens the receipt file at `path`, and makes it when it does not exist.
    pub fn open(path: &str) -> Result<Self, StoreFault> {
        let connection = fault(Connection::open(path))?;
        // REL-074: an erased receipt leaves no bytes in the file.
        fault(connection.pragma_update(None, "secure_delete", "ON"))?;
        fault(connection.pragma_update(None, "journal_mode", "WAL"))?;
        // A crash loses at most the last receipts, which no client needs.
        fault(connection.pragma_update(None, "synchronous", "NORMAL"))?;
        fault(connection.execute_batch(RECEIPT_SCHEMA))?;

        Ok(SqliteShelf {
            connection,
            max_bytes: RECEIPT_FILE_MAX,
            since_check: 0,
        })
    }

    /// Sets the bytes that the file holds at most.
    pub fn set_max_bytes(&mut self, max_bytes: u64) {
        self.max_bytes = max_bytes;
    }

    /// The bytes of the pages that hold a row.
    fn used_bytes(&self) -> Result<u64, StoreFault> {
        let read = |pragma: &str| -> Result<u64, StoreFault> {
            unsigned(fault(
                self.connection
                    .query_row(pragma, [], |row| row.get::<_, i64>(0)),
            )?)
        };

        let pages = read("PRAGMA page_count")?.saturating_sub(read("PRAGMA freelist_count")?);

        Ok(pages.saturating_mul(read("PRAGMA page_size")?))
    }

    /// Erases the oldest receipts while the file is above its bound, in at
    /// most `TRIM_STEPS` transactions of `TRIM_BATCH` receipts.
    fn trim(&mut self) -> Result<(), StoreFault> {
        let mut trimmed = false;

        for _ in 0..TRIM_STEPS {
            if self.used_bytes()? <= self.max_bytes {
                break;
            }

            // The last receipt of the batch, or each one when the file
            // holds less than a batch.
            let last: i64 = fault(
                self.connection
                    .query_row(
                        "SELECT id FROM receipts ORDER BY id LIMIT 1 OFFSET ?1",
                        [TRIM_BATCH - 1],
                        |row| row.get(0),
                    )
                    .optional(),
            )?
            .unwrap_or(i64::MAX);

            let transaction = fault(self.connection.transaction())?;
            fault(transaction.execute("DELETE FROM receipt_leaves WHERE receipt <= ?1", [last]))?;
            let gone = fault(transaction.execute("DELETE FROM receipts WHERE id <= ?1", [last]))?;
            fault(transaction.commit())?;
            trimmed = true;

            // A file that is above its bound with no receipt has nothing
            // more to give.
            if gone == 0 {
                break;
            }
        }
        if trimmed {
            fault(
                self.connection
                    .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())),
            )?;
        }
        Ok(())
    }

    fn put(&mut self, kept: &KeptReceipt) -> Result<(), StoreFault> {
        let transaction = fault(self.connection.transaction())?;
        let leaves: Vec<u8> = kept.leaves.iter().flatten().copied().collect();
        let epoch = signed(kept.epoch)?;

        fault(transaction.execute(
            "INSERT INTO receipts (issued, epoch, at, signed, leaves) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                i64::from(kept.issued),
                epoch,
                signed(kept.at)?,
                kept.signed,
                leaves
            ],
        ))?;

        let id = transaction.last_insert_rowid();

        {
            let mut insert = fault(transaction.prepare(
                "INSERT OR IGNORE INTO receipt_leaves (epoch, leaf, receipt) VALUES (?1, ?2, ?3)",
            ))?;
            for leaf in &kept.leaves {
                fault(insert.execute(params![epoch, leaf_key(leaf), id]))?;
            }
        }

        fault(transaction.commit())
    }

    fn erase(&mut self, floor: u64) -> Result<(), StoreFault> {
        let floor = signed(floor)?;
        let old: Option<i64> = fault(
            self.connection
                .query_row(
                    "SELECT 1 FROM receipts WHERE at < ?1 LIMIT 1",
                    [floor],
                    |row| row.get(0),
                )
                .optional(),
        )?;

        if old.is_none() {
            return Ok(());
        }

        let transaction = fault(self.connection.transaction())?;
        fault(transaction.execute(
            "DELETE FROM receipt_leaves WHERE receipt IN (SELECT id FROM receipts WHERE at < ?1)",
            [floor],
        ))?;
        fault(transaction.execute("DELETE FROM receipts WHERE at < ?1", [floor]))?;
        fault(transaction.commit())?;

        fault(
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())),
        )?;
        Ok(())
    }

    fn read(&self, epoch: u64, leaf: &[u8; 32]) -> Result<Vec<KeptReceipt>, StoreFault> {
        let mut query = fault(self.connection.prepare(
            "SELECT r.issued, r.epoch, r.at, r.signed, r.leaves
             FROM receipt_leaves l JOIN receipts r ON r.id = l.receipt
             WHERE l.epoch = ?1 AND l.leaf = ?2
             ORDER BY r.issued DESC, r.id",
        ))?;

        let rows = fault(
            query.query_map(params![signed(epoch)?, leaf_key(leaf)], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            }),
        )?;

        let mut found = Vec::new();
        for row in rows {
            let (issued, epoch, at, signed, leaves) = fault(row)?;
            let (whole, rest) = leaves.as_chunks::<32>();
            if !rest.is_empty() {
                return Err(StoreFault);
            }

            let leaves = whole.to_vec();
            found.push(KeptReceipt {
                issued: issued != 0,
                epoch: unsigned(epoch)?,
                signed,
                leaves,
                at: unsigned(at)?,
            });
        }

        Ok(found)
    }

    fn count(&self, issued: bool) -> Result<usize, StoreFault> {
        let count: i64 = fault(self.connection.query_row(
            "SELECT COUNT(*) FROM receipts WHERE issued = ?1",
            [i64::from(issued)],
            |row| row.get(0),
        ))?;

        usize::try_from(count).map_err(|_| StoreFault)
    }
}

impl ReceiptShelf for SqliteShelf {
    fn keep(&mut self, kept: KeptReceipt) -> Result<(), StoreFault> {
        self.put(&kept)?;
        self.since_check = self.since_check.saturating_add(1);

        if self.since_check >= SIZE_CHECK_EVERY {
            self.since_check = 0;
            // A fault leaves the rows, and the next check trims them.
            let _ = self.trim();
        }
        Ok(())
    }

    fn find(&self, epoch: u64, leaf: &[u8; 32]) -> Vec<KeptReceipt> {
        self.read(epoch, leaf).unwrap_or_default()
    }

    fn erase_before(&mut self, floor: u64) {
        // A fault leaves the rows, and the next tick erases them.
        let _ = self.erase(floor);
    }

    fn held(&self) -> (usize, usize) {
        (
            self.count(true).unwrap_or(0),
            self.count(false).unwrap_or(0),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    #[test]
    fn a_receipt_file_above_its_bound_loses_its_oldest_receipts() {
        let path = file("receipts-bound.db");
        let mut shelf = SqliteShelf::open(&path).unwrap();
        shelf.set_max_bytes(1 << 20);

        let kept = |index: u32| KeptReceipt {
            issued: true,
            epoch: 7,
            signed: vec![1; 3_400],
            leaves: (0..1_024u32)
                .map(|leaf| {
                    let mut bytes = [0u8; 32];
                    bytes[..4].copy_from_slice(&index.to_be_bytes());
                    bytes[4..8].copy_from_slice(&leaf.to_be_bytes());
                    bytes
                })
                .collect(),
            at: u64::from(index),
        };

        // Each full window takes about 60 kB with its index, thus 256 of
        // them pass the bound many times.
        for index in 0..256 {
            shelf.keep(kept(index)).unwrap();
        }

        let (issued, _) = shelf.held();
        assert!(issued < 256, "{issued}");
        assert!(shelf.used_bytes().unwrap() <= 1 << 20);

        // The newest receipt stays, and the oldest one left.
        let leaf = |index: u32| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            bytes
        };

        assert!(shelf.find(7, &leaf(0)).is_empty());
        assert_eq!(shelf.find(7, &leaf(255)).len(), 1);
    }

    #[test]
    fn a_receipt_file_finds_a_leaf_and_erases_after_retention() {
        let path = file("receipts.db");
        let kept = |issued: bool, epoch: u64, fill: u8, at: u64| KeptReceipt {
            issued,
            epoch,
            signed: vec![fill; 40],
            leaves: (0..4u8).map(|i| [fill.wrapping_add(i); 32]).collect(),
            at,
        };

        {
            let mut shelf = SqliteShelf::open(&path).unwrap();
            shelf.keep(kept(false, 7, 10, 100)).unwrap();
            shelf.keep(kept(true, 7, 12, 200)).unwrap();
            shelf.keep(kept(true, 8, 10, 300)).unwrap();
            assert_eq!(shelf.held(), (2, 1));
        }

        // A restart keeps each receipt.
        let mut shelf = SqliteShelf::open(&path).unwrap();
        let found = shelf.find(7, &[13; 32]);
        assert_eq!(found.len(), 2);
        assert!(found[0].issued);
        assert_eq!(found[0].signed, vec![12; 40]);
        assert!(!found[1].issued);
        assert_eq!(found[1].leaves.len(), 4);
        assert!(shelf.find(9, &[13; 32]).is_empty());

        shelf.erase_before(250);
        assert_eq!(shelf.held(), (1, 0));
        assert!(shelf.find(7, &[13; 32]).is_empty());
        assert_eq!(shelf.find(8, &[11; 32]).len(), 1);

        let rows: i64 = shelf
            .connection
            .query_row("SELECT COUNT(*) FROM receipt_leaves", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 4);
    }

    fn chunk(class: Class, fill: u8) -> Box<HeldChunk> {
        Box::new(HeldChunk {
            class,
            credentials: Credentials {
                cred_pk: [fill; 32],
                read_pk: [fill.wrapping_add(1); 32],
            },
            bytes: vec![fill; 4_096],
            registered_at: 100,
            renewed_at: 110,
            erase_at: 900,
        })
    }

    fn changes() -> Vec<StoreChange> {
        let record = |seq: u32, at: u64| Stored {
            seq,
            accepted_at: at,
            bytes: vec![seq as u8; 390],
        };
        let invitation = |blob: Option<Vec<u8>>| StoredInvitation {
            recipient_id: [1; 32],
            blob,
            at: 50,
        };

        vec![
            StoreChange::Queue {
                recipient_id: [1; 32],
                head: vec![1, 1],
            },
            StoreChange::Queue {
                recipient_id: [2; 32],
                head: vec![2],
            },
            StoreChange::Queue {
                recipient_id: [3; 32],
                head: vec![3],
            },
            StoreChange::Record {
                recipient_id: [1; 32],
                record: record(1, 10),
            },
            StoreChange::Record {
                recipient_id: [1; 32],
                record: record(2, 20),
            },
            StoreChange::Record {
                recipient_id: [1; 32],
                record: record(3, 30),
            },
            StoreChange::Record {
                recipient_id: [2; 32],
                record: record(1, 5),
            },
            StoreChange::Record {
                recipient_id: [2; 32],
                record: record(2, 40),
            },
            StoreChange::Record {
                recipient_id: [3; 32],
                record: record(1, 40),
            },
            StoreChange::Queue {
                recipient_id: [1; 32],
                head: vec![1, 2],
            },
            StoreChange::Acked {
                recipient_id: [1; 32],
                seq: 2,
            },
            StoreChange::Expired { accepted_before: 6 },
            StoreChange::QueueDeleted {
                recipient_id: [3; 32],
            },
            StoreChange::Invitation {
                link_id: [7; 24],
                held: invitation(None),
            },
            StoreChange::Invitation {
                link_id: [7; 24],
                held: invitation(Some(vec![9; 1_400])),
            },
            StoreChange::Invitation {
                link_id: [8; 24],
                held: invitation(None),
            },
            StoreChange::InvitationDeleted { link_id: [8; 24] },
            StoreChange::GroupQueue {
                group_queue_id: [4; 32],
                head: vec![4],
            },
            StoreChange::GroupQueue {
                group_queue_id: [5; 32],
                head: vec![5],
            },
            StoreChange::GroupRecord {
                group_queue_id: [4; 32],
                record: record(1, 10),
            },
            StoreChange::GroupRecord {
                group_queue_id: [4; 32],
                record: record(2, 20),
            },
            StoreChange::GroupRecord {
                group_queue_id: [5; 32],
                record: record(1, 10),
            },
            StoreChange::GroupTrimmed {
                group_queue_id: [4; 32],
                through_seq: 1,
            },
            StoreChange::GroupQueueDeleted {
                group_queue_id: [5; 32],
            },
            StoreChange::Chunk {
                chunk_id: [6; 32],
                held: chunk(Class::Attachment, 6),
            },
            StoreChange::Chunk {
                chunk_id: [7; 32],
                held: chunk(Class::Backup, 7),
            },
            StoreChange::Chunk {
                chunk_id: [8; 32],
                held: chunk(Class::Attachment, 8),
            },
            StoreChange::ChunkRenewed {
                chunk_id: [6; 32],
                renewed_at: 500,
                erase_at: 1_500,
            },
            StoreChange::ChunkDeleted { chunk_id: [8; 32] },
            StoreChange::Spent {
                epoch: 5,
                nonce: [1; 32],
            },
            StoreChange::Spent {
                epoch: 7,
                nonce: [2; 32],
            },
            StoreChange::Spent {
                epoch: 6,
                nonce: [3; 32],
            },
        ]
    }

    fn file(name: &str) -> String {
        let directory = std::env::temp_dir().join(format!("umbra-relay-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();

        let path = directory.join(name);
        let _ = std::fs::remove_file(&path);
        path.to_str().unwrap().to_owned()
    }

    #[test]
    fn the_file_holds_what_the_memory_model_holds() {
        let path = file("model.db");
        let mut model = MemoryStore::default();
        let mut store = SqliteStore::open(&path).unwrap();

        // The changes go in several commits, as the calls of a node give
        // them.
        for batch in changes().chunks(4) {
            model.commit(batch).unwrap();
            store.commit(batch).unwrap();
        }
        assert_eq!(store.load().unwrap(), model.load().unwrap());

        // A second process reads the same state.
        drop(store);
        let mut again = SqliteStore::open(&path).unwrap();
        let loaded = again.load().unwrap();
        assert_eq!(loaded, model.load().unwrap());

        assert_eq!(loaded.queues[&[1; 32]].head, [1, 2]);
        assert_eq!(loaded.queues[&[1; 32]].records.len(), 1);
        assert_eq!(loaded.queues[&[2; 32]].records.len(), 1);
        assert_eq!(loaded.invitations.len(), 1);

        // A group queue and its records come back, and a `GDEL` leaves
        // neither (`NET-245`).
        assert_eq!(loaded.group_queues.len(), 1);
        assert_eq!(loaded.group_queues[&[4; 32]].head, [4]);
        assert_eq!(loaded.group_queues[&[4; 32]].records.len(), 1);
        assert_eq!(loaded.group_queues[&[4; 32]].records[0].seq, 2);

        // The chunks come back with their class and their renewal, and a
        // `CDEL` leaves none (`ATT-191`).
        assert_eq!(loaded.chunks.len(), 2);
        assert_eq!(loaded.chunks[&[6; 32]].erase_at, 1_500);
        assert_eq!(loaded.chunks[&[7; 32]].class, Class::Backup);

        // ABU-114: the spent nonces of the two newest epochs stay.
        assert_eq!(
            loaded.spent.iter().copied().collect::<Vec<_>>(),
            [(6, [3; 32]), (7, [2; 32])]
        );
    }

    #[test]
    fn a_record_that_does_not_read_drops_its_queue_alone() {
        let path = file("bad-row.db");
        let mut store = SqliteStore::open(&path).unwrap();
        store.commit(&changes()).unwrap();

        store
            .connection
            .execute(
                "UPDATE records SET seq = -1 WHERE recipient_id = ?1",
                [[1u8; 32].as_slice()],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO records (recipient_id, seq, accepted_at, bytes) VALUES (?1, 1, 0, x'00')",
                [[9u8; 32].as_slice()],
            )
            .unwrap();

        // NET-303: the queue of that record parses no more, the other one
        // stays, and a record of no queue leaves the file.
        let loaded = store.load().unwrap();
        assert!(loaded.queues[&[1; 32]].head.is_empty());
        assert_eq!(loaded.queues[&[2; 32]].records.len(), 1);

        let orphans: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM records WHERE recipient_id = ?1",
                [[9u8; 32].as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0);
    }

    #[test]
    fn a_row_that_does_not_read_leaves_the_file_and_the_others_load() {
        let path = file("bad-rows.db");
        let mut store = SqliteStore::open(&path).unwrap();
        store.commit(&changes()).unwrap();

        let connection = &store.connection;
        let insert = |sql: &str, params: &[&dyn rusqlite::ToSql]| {
            connection.execute(sql, params).unwrap();
        };

        insert(
            "INSERT INTO queues (recipient_id, head) VALUES (?1, x'01')",
            &[&[5u8; 31].as_slice()],
        );
        insert(
            "INSERT INTO queues (recipient_id, head) VALUES (?1, 'text')",
            &[&[6u8; 32].as_slice()],
        );
        insert(
            "INSERT INTO records (recipient_id, seq, accepted_at, bytes) VALUES (?1, 1, 0, x'00')",
            &[&[6u8; 32].as_slice()],
        );
        insert(
            "INSERT INTO group_queues (group_queue_id, head) VALUES (x'07', x'07')",
            &[],
        );
        insert(
            "INSERT INTO invitations (link_id, recipient_id, at, blob) VALUES (?1, ?2, -1, NULL)",
            &[&[9u8; 24].as_slice(), &[2u8; 32].as_slice()],
        );
        insert(
            "INSERT INTO chunks
             (chunk_id, class, cred_pk, read_pk, registered_at, renewed_at, erase_at, bytes)
             VALUES (?1, 9, ?2, ?2, 0, 0, 0, x'00')",
            &[&[9u8; 32].as_slice(), &[1u8; 32].as_slice()],
        );
        insert(
            "UPDATE records SET bytes = 'text' WHERE recipient_id = ?1",
            &[&[2u8; 32].as_slice()],
        );

        // NET-303: the load holds each row that reads. A record that does
        // not read makes its queue one that does not parse. Before this,
        // one row that did not read stopped the load.
        let loaded = store.load().unwrap();
        assert_eq!(loaded.queues.len(), 2);
        assert_eq!(loaded.queues[&[1; 32]].records.len(), 1);
        assert!(loaded.queues[&[2; 32]].head.is_empty());
        assert_eq!(loaded.group_queues.len(), 1);
        assert_eq!(loaded.invitations.len(), 1);
        assert_eq!(loaded.chunks.len(), 2);

        // Each row that did not read left the file.
        let count = |table: &str| -> i64 {
            store
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        };

        assert_eq!(count("queues"), 2);
        assert_eq!(count("records"), 2);
        assert_eq!(count("group_queues"), 1);
        assert_eq!(count("invitations"), 1);
        assert_eq!(count("chunks"), 2);
    }

    #[test]
    fn a_deleted_chunk_leaves_no_bytes_in_the_file() {
        let path = file("chunk-erase.db");
        let mut store = SqliteStore::open(&path).unwrap();
        let held = chunk(Class::Attachment, 0xC9);
        let marker = held.bytes.clone();

        store
            .commit(&[StoreChange::Chunk {
                chunk_id: [1; 32],
                held,
            }])
            .unwrap();

        let holds = |path: &str| {
            let mut bytes = std::fs::read(path).unwrap();
            bytes.extend(std::fs::read(format!("{path}-wal")).unwrap_or_default());
            bytes.windows(64).any(|window| window == &marker[..64])
        };

        assert!(holds(&path));

        store
            .commit(&[StoreChange::ChunkDeleted { chunk_id: [1; 32] }])
            .unwrap();
        assert!(!holds(&path));
    }

    #[test]
    fn a_file_of_the_earlier_schema_keeps_its_queues() {
        let path = file("upgrade.db");
        // A file of version 1: the three tables of the pairwise queues,
        // and one queue in them.
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE queues (recipient_id BLOB PRIMARY KEY, head BLOB NOT NULL);
                     CREATE TABLE records (recipient_id BLOB NOT NULL, seq INTEGER NOT NULL,
                        accepted_at INTEGER NOT NULL, bytes BLOB NOT NULL,
                        PRIMARY KEY (recipient_id, seq));
                     CREATE TABLE invitations (link_id BLOB PRIMARY KEY,
                        recipient_id BLOB NOT NULL, at INTEGER NOT NULL, blob BLOB);
                     PRAGMA user_version = 1;",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO queues (recipient_id, head) VALUES (?1, ?2)",
                    rusqlite::params![[1u8; 32].as_slice(), vec![1u8, 2]],
                )
                .unwrap();
        }

        let mut store = SqliteStore::open(&path).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.queues.len(), 1);
        assert!(loaded.group_queues.is_empty());

        // The file now takes a group queue.
        store
            .commit(&[StoreChange::GroupQueue {
                group_queue_id: [4; 32],
                head: vec![4],
            }])
            .unwrap();
        assert_eq!(store.load().unwrap().group_queues.len(), 1);
    }

    #[test]
    fn a_file_of_a_later_schema_does_not_open() {
        let path = file("future.db");
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch("CREATE TABLE queues (x INTEGER); PRAGMA user_version = 99;")
                .unwrap();
        }
        assert!(SqliteStore::open(&path).is_err());
    }

    #[test]
    fn a_deleted_record_leaves_no_bytes_in_the_file() {
        let path = file("erase.db");
        let mut store = SqliteStore::open(&path).unwrap();
        let marker = vec![0xC7u8; 390];
        let record = Stored {
            seq: 1,
            accepted_at: 10,
            bytes: marker.clone(),
        };

        store
            .commit(&[
                StoreChange::Queue {
                    recipient_id: [1; 32],
                    head: vec![1],
                },
                StoreChange::Record {
                    recipient_id: [1; 32],
                    record,
                },
            ])
            .unwrap();

        let holds = |path: &str| {
            let mut bytes = std::fs::read(path).unwrap();
            bytes.extend(std::fs::read(format!("{path}-wal")).unwrap_or_default());
            bytes.windows(64).any(|window| window == &marker[..64])
        };

        assert!(holds(&path));

        store
            .commit(&[StoreChange::Acked {
                recipient_id: [1; 32],
                seq: 1,
            }])
            .unwrap();
        assert!(!holds(&path));
    }

    #[test]
    fn a_failed_commit_leaves_no_part_of_it() {
        let path = file("atomic.db");
        let mut store = SqliteStore::open(&path).unwrap();

        let record = Stored {
            seq: 1,
            accepted_at: 10,
            bytes: vec![1; 8],
        };
        let twice = [
            StoreChange::Queue {
                recipient_id: [1; 32],
                head: vec![1],
            },
            StoreChange::Record {
                recipient_id: [1; 32],
                record: record.clone(),
            },
            // The same sequence number a second time breaks the key.
            StoreChange::Record {
                recipient_id: [1; 32],
                record,
            },
        ];

        assert_eq!(store.commit(&twice), Err(StoreFault));
        assert_eq!(store.load().unwrap(), Loaded::default());
    }
}
