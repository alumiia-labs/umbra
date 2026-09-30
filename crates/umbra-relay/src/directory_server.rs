//! The directory and the issuer of Part 9 §9.10 and Part 13 §13.9 as a
//! server: the OHTTP gateway, the store of the log and of the labels, and
//! the clock that closes each epoch.
//!
//! The store keeps the staged versions and the closed epochs in order, and
//! the newest state of each label. A restart replays them. The server writes
//! no log line that names a handle, an address, or a token.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use umbra_core::discovery::service::{DirEvent, Directory};
use umbra_crypto::ohttp;
use umbra_transport::https;

use crate::{ndr_server::Gateway, server::OsRng, store::StoreFault};

/// The path of the gateway.
pub const GATEWAY_PATH: &str = "/gateway";
/// The longest encapsulated request: the padded `DirRequest` of Part 9
/// §9.10, the header, the encapsulation, and the tag.
const REQUEST_MAX: usize = 16_384;
/// The interval of the clock. An epoch closes at the first tick after its
/// end.
const TICK: Duration = Duration::from_secs(5);

/// The store of the directory.
pub trait DirectoryStore: Send {
    /// Reads each event at the start of a run, in order.
    fn load(&mut self) -> Result<Vec<DirEvent>, StoreFault>;
    /// Commits the events of one step, all or none.
    fn commit(&mut self, events: &[DirEvent]) -> Result<(), StoreFault>;
}

/// A store in RAM, for a test.
#[derive(Default)]
pub struct MemoryDirectoryStore(pub Vec<DirEvent>);

impl DirectoryStore for MemoryDirectoryStore {
    fn load(&mut self) -> Result<Vec<DirEvent>, StoreFault> {
        Ok(self.0.clone())
    }

    fn commit(&mut self, events: &[DirEvent]) -> Result<(), StoreFault> {
        self.0.extend_from_slice(events);
        Ok(())
    }
}

/// The store in one SQLite file: the log in order, and the newest state of
/// each label.
pub struct SqliteDirectoryStore {
    connection: Connection,
}

fn fault<T>(result: rusqlite::Result<T>) -> Result<T, StoreFault> {
    result.map_err(|_| StoreFault)
}

const STAGED: i64 = 1;
const CLOSED: i64 = 2;

impl SqliteDirectoryStore {
    /// Opens the file at `path`, and makes it when it does not exist.
    pub fn open(path: &str) -> Result<Self, StoreFault> {
        let connection = fault(Connection::open(path))?;
        fault(connection.pragma_update(None, "secure_delete", "ON"))?;
        fault(connection.pragma_update(None, "journal_mode", "WAL"))?;
        fault(connection.pragma_update(None, "synchronous", "FULL"))?;
        fault(connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS log (
                seq   INTEGER PRIMARY KEY,
                kind  INTEGER NOT NULL,
                a     BLOB NOT NULL,
                b     BLOB NOT NULL,
                c     BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS labels (
                search_key BLOB PRIMARY KEY,
                state      BLOB NOT NULL
            ) WITHOUT ROWID;",
        ))?;
        Ok(SqliteDirectoryStore { connection })
    }
}

impl DirectoryStore for SqliteDirectoryStore {
    fn load(&mut self) -> Result<Vec<DirEvent>, StoreFault> {
        let mut out = Vec::new();
        let mut statement = fault(
            self.connection
                .prepare("SELECT kind, a, b, c FROM log ORDER BY seq"),
        )?;
        let rows = fault(statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        }))?;
        for row in rows {
            let (kind, a, b, c) = fault(row)?;
            out.push(match kind {
                STAGED => DirEvent::Staged {
                    search_key: a,
                    entry: b,
                    opening: c.try_into().map_err(|_| StoreFault)?,
                },
                CLOSED => DirEvent::Closed {
                    nonce: a.try_into().map_err(|_| StoreFault)?,
                    at: u64::from_be_bytes(b.try_into().map_err(|_| StoreFault)?),
                },
                _ => return Err(StoreFault),
            });
        }
        let mut statement = fault(
            self.connection
                .prepare("SELECT search_key, state FROM labels"),
        )?;
        let rows = fault(statement.query_map([], |row| {
            Ok(DirEvent::Label {
                search_key: row.get(0)?,
                state: row.get(1)?,
            })
        }))?;
        for row in rows {
            out.push(fault(row)?);
        }
        Ok(out)
    }

    fn commit(&mut self, events: &[DirEvent]) -> Result<(), StoreFault> {
        if events.is_empty() {
            return Ok(());
        }
        let transaction = fault(self.connection.transaction())?;
        for event in events {
            match event {
                DirEvent::Staged {
                    search_key,
                    entry,
                    opening,
                } => fault(transaction.execute(
                    "INSERT INTO log (kind, a, b, c) VALUES (?1, ?2, ?3, ?4)",
                    params![STAGED, search_key, entry, opening.as_slice()],
                ))?,
                DirEvent::Closed { nonce, at } => fault(transaction.execute(
                    "INSERT INTO log (kind, a, b, c) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        CLOSED,
                        nonce.as_slice(),
                        at.to_be_bytes().as_slice(),
                        [0u8; 0].as_slice()
                    ],
                ))?,
                DirEvent::Label { search_key, state } => fault(transaction.execute(
                    "INSERT OR REPLACE INTO labels (search_key, state) VALUES (?1, ?2)",
                    params![search_key, state],
                ))?,
            };
        }
        fault(transaction.commit())
    }
}

struct State {
    directory: Directory,
    store: Box<dyn DirectoryStore>,
    /// A commit failed: the state in memory ran ahead of the store, and
    /// the directory serves nothing more until a restart replays the
    /// store. Serving it would sign a head that a restart does not sign
    /// again, which is a split view (`DIS-034`).
    broken: bool,
}

impl State {
    /// Runs one step and commits its events. A store that takes no commit
    /// refuses the request, and each later one.
    fn step<T>(&mut self, run: impl FnOnce(&mut Directory) -> T) -> Option<T> {
        if self.broken {
            return None;
        }
        let out = run(&mut self.directory);
        if self.store.commit(&self.directory.take_events()).is_err() {
            eprintln!("the store took no commit, and the directory serves nothing more");
            self.broken = true;
            return None;
        }
        Some(out)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    gateway: Arc<Gateway>,
    state: Arc<Mutex<State>>,
) {
    let mut inbound = Vec::new();
    let Ok(request) = https::read_request(&mut stream, &mut inbound, REQUEST_MAX).await else {
        return;
    };
    if request.method != "POST" || request.path != GATEWAY_PATH {
        let _ = https::respond(&mut stream, 404, "text/plain", &[]).await;
        return;
    }
    let Ok((plain, key)) = ohttp::decapsulate_request(gateway.key_id, &gateway.pair, &request.body)
    else {
        let _ = https::respond(&mut stream, 400, "text/plain", &[]).await;
        return;
    };
    // The proofs of work of an issuance take some milliseconds, thus the
    // step leaves the runtime threads free.
    let answer = tokio::task::spawn_blocking(move || match state.lock() {
        Ok(mut state) => state.step(|directory| directory.handle(&plain, now(), &mut OsRng)),
        Err(_) => None,
    })
    .await
    .ok()
    .flatten();
    let Some(answer) = answer else {
        let _ = https::respond(&mut stream, 502, "text/plain", &[]).await;
        return;
    };
    let Ok(sealed) = ohttp::encapsulate_response(&key, &answer, &mut OsRng) else {
        return;
    };
    let _ = https::respond(&mut stream, 200, "message/ohttp-res", &sealed).await;
}

/// Runs the directory until the listener fails.
pub async fn run_directory(
    listener: TcpListener,
    tls: TlsAcceptor,
    gateway: Gateway,
    mut directory: Directory,
    mut store: Box<dyn DirectoryStore>,
) -> Result<(), StoreFault> {
    let events = store.load()?;
    directory
        .replay(&events, &mut OsRng)
        .map_err(|_| StoreFault)?;
    let state = Arc::new(Mutex::new(State {
        directory,
        store,
        broken: false,
    }));
    let clock = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        loop {
            interval.tick().await;
            let clock = clock.clone();
            // DIS-167: an epoch closes at each interval, with or without an
            // update. Three signatures take some milliseconds.
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(mut state) = clock.lock() {
                    let _ = state.step(|directory| directory.tick(now(), &mut OsRng));
                }
            })
            .await;
        }
    });
    let gateway = Arc::new(gateway);
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            return Ok(());
        };
        let tls = tls.clone();
        let gateway = gateway.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Ok(stream) = tls.accept(tcp).await {
                serve(stream, gateway, state).await;
            }
        });
    }
}
