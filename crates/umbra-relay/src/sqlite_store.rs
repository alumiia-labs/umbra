//! The store of a relay over SQLite. One commit of [`RelayStore::commit`]
//! is one transaction, thus a crash leaves the changes of a call in the file
//! as a whole or not at all.
//!
//! The file runs under `secure_delete`, and each commit that deletes rows
//! truncates the write-ahead log. A record that an `ACK` covered and a queue
//! that a `DEL` ended leave no bytes in the file (`WIR-039` to `WIR-042`).

use rusqlite::{params, Connection, OptionalExtension};
use umbra_core::attach::store::{Class, Credentials, HeldChunk};
use umbra_queue::relay::Stored;

use crate::store::{Loaded, RelayStore, StoreChange, StoreFault, StoredInvitation, StoredQueue};

/// The schema version in `user_version`. Version 2 added the group
/// queues of Part 11, and version 3 the chunks of Part 12.
const SCHEMA_VERSION: i64 = 3;

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

fn id<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], StoreFault> {
    bytes.try_into().map_err(|_| StoreFault)
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
        let mut loaded = Loaded::default();
        let mut queues = fault(
            self.connection
                .prepare("SELECT recipient_id, head FROM queues"),
        )?;
        let rows = fault(queues.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        }))?;
        for row in rows {
            let (recipient_id, head) = fault(row)?;
            let queue = StoredQueue {
                head,
                records: Vec::new(),
            };
            loaded.queues.insert(id(recipient_id)?, queue);
        }

        let mut records = fault(self.connection.prepare(
            "SELECT recipient_id, seq, accepted_at, bytes FROM records ORDER BY recipient_id, seq",
        ))?;
        let rows = fault(records.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        }))?;
        for row in rows {
            let (recipient_id, seq, accepted_at, bytes) = fault(row)?;
            // A record of no queue is a fault of an earlier crash model, and
            // one transaction for each commit excludes it.
            let queue = loaded
                .queues
                .get_mut(&id::<32>(recipient_id)?)
                .ok_or(StoreFault)?;
            queue.records.push(Stored {
                seq: u32::try_from(seq).map_err(|_| StoreFault)?,
                accepted_at: unsigned(accepted_at)?,
                bytes,
            });
        }

        let mut group_queues = fault(
            self.connection
                .prepare("SELECT group_queue_id, head FROM group_queues"),
        )?;
        let rows = fault(group_queues.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        }))?;
        for row in rows {
            let (group_queue_id, head) = fault(row)?;
            loaded.group_queues.insert(
                id(group_queue_id)?,
                StoredQueue {
                    head,
                    records: Vec::new(),
                },
            );
        }

        let mut group_records = fault(self.connection.prepare(
            "SELECT group_queue_id, seq, accepted_at, bytes FROM group_records
             ORDER BY group_queue_id, seq",
        ))?;
        let rows = fault(group_records.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        }))?;
        for row in rows {
            let (group_queue_id, seq, accepted_at, bytes) = fault(row)?;
            let queue = loaded
                .group_queues
                .get_mut(&id::<32>(group_queue_id)?)
                .ok_or(StoreFault)?;
            queue.records.push(Stored {
                seq: u32::try_from(seq).map_err(|_| StoreFault)?,
                accepted_at: unsigned(accepted_at)?,
                bytes,
            });
        }

        let mut invitations = fault(
            self.connection
                .prepare("SELECT link_id, recipient_id, at, blob FROM invitations"),
        )?;
        let rows = fault(invitations.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        }))?;
        for row in rows {
            let (link_id, recipient_id, at, blob) = fault(row)?;
            let held = StoredInvitation {
                recipient_id: id(recipient_id)?,
                blob,
                at: unsigned(at)?,
            };
            loaded.invitations.insert(id(link_id)?, held);
        }

        let mut chunks = fault(self.connection.prepare(
            "SELECT chunk_id, class, cred_pk, read_pk, registered_at, renewed_at, erase_at, bytes
             FROM chunks",
        ))?;
        let rows = fault(chunks.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        }))?;
        for row in rows {
            let (chunk_id, class, cred_pk, read_pk, registered_at, renewed_at, erase_at, bytes) =
                fault(row)?;
            let class = match class {
                1 => Class::Attachment,
                2 => Class::Backup,
                _ => return Err(StoreFault),
            };
            let held = HeldChunk {
                class,
                credentials: Credentials {
                    cred_pk: id(cred_pk)?,
                    read_pk: id(read_pk)?,
                },
                bytes,
                registered_at: unsigned(registered_at)?,
                renewed_at: unsigned(renewed_at)?,
                erase_at: unsigned(erase_at)?,
            };
            loaded.chunks.insert(id(chunk_id)?, held);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

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
