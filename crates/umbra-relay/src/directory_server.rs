//! The directory and the issuer of Part 9 §9.10 and Part 13 §13.9 as a
//! server: the OHTTP gateway, the store of the log and of the labels, and
//! the clock that closes each epoch.
//!
//! The store keeps the staged versions and the closed epochs in order, the
//! newest state of each label, and the token nonces spent in this epoch and
//! the one before it (`ABU-114`). A restart replays them. The server writes
//! no log line that names a handle, an address, or a token.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use umbra_core::{
    abuse::epoch_number,
    discovery::service::{DirEvent, Directory},
};
use umbra_crypto::{hash::sha3_256, ohttp};
use umbra_transport::https;
use umbra_wire::directory::{self, Kind, Status};

use crate::{ndr_server::Gateway, server::OsRng, store::StoreFault};

/// The path of the gateway.
pub const GATEWAY_PATH: &str = "/gateway";
/// The longest encapsulated request: the padded `DirRequest` of Part 9
/// §9.10, the header, the encapsulation, and the tag.
const REQUEST_MAX: usize = 16_384;
/// The interval of the clock. An epoch closes at the first tick after its
/// end.
const TICK: Duration = Duration::from_secs(5);
/// The time that one connection has from its accept to its answer. A peer
/// that stalls holds no task past it (`NET-335`).
const CONNECTION_TIME: Duration = Duration::from_secs(30);
/// The time that the TLS handshake of one connection has.
const HANDSHAKE_TIME: Duration = Duration::from_secs(10);
/// The wait after an accept that failed.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);
/// The connections that the server holds at once. One more waits for none:
/// it closes at its accept.
const CONNECTION_MAX: usize = 4_096;

/// The requests that run or wait for the state at once. One more gets the
/// answer `busy` at once. The work of a request runs on a blocking thread,
/// and the time of its connection does not end that thread. Thus this
/// bound, and not `CONNECTION_MAX`, holds the queue for the state.
const WORK_MAX: usize = 64;
/// The answers of the issuer that the server holds, for the epoch of the
/// clock.
const ISSUED_HELD: usize = 1_024;
/// The wait of a request for the clock, between two looks.
const CLOCK_WAIT: Duration = Duration::from_millis(1);

/// The answer of each recent issuance, by the hash of its request. The
/// issuer holds no replay set (`ABU-110`). A party that sends one paid
/// request again and again would thus take the work of its signatures.
/// A request that repeats one gets the answer of the first one, and the
/// directory signs nothing.
#[derive(Default)]
struct Issued {
    epoch: u32,
    held: BTreeMap<[u8; 32], Vec<u8>>,
    order: VecDeque<[u8; 32]>,
}

impl Issued {
    /// The key of `request` when it is an issuance: the hash of its body.
    fn key_of(request: &[u8]) -> Option<[u8; 32]> {
        match directory::parse_request(request) {
            Ok((Kind::Issue, body)) => Some(sha3_256(&[body])),
            _ => None,
        }
    }

    /// An answer of an epoch that ended serves no request (`ABU-110`).
    fn at(&mut self, now: u64) {
        let epoch = epoch_number(now);
        if epoch != self.epoch {
            self.epoch = epoch;
            self.held.clear();
            self.order.clear();
        }
    }

    /// The answer that the request of `key` took before.
    fn get(&mut self, key: &[u8; 32], now: u64) -> Option<Vec<u8>> {
        self.at(now);
        self.held.get(key).cloned()
    }

    /// Holds `answer` for the request of `key`, when the issuer signed.
    fn keep(&mut self, key: [u8; 32], answer: &[u8], now: u64) {
        if !matches!(directory::parse_response(answer), Ok((Status::Done, _))) {
            return;
        }

        self.at(now);
        if self.held.insert(key, answer.to_vec()).is_none() {
            self.order.push_back(key);
        }

        if self.order.len() > ISSUED_HELD {
            if let Some(oldest) = self.order.pop_front() {
                self.held.remove(&oldest);
            }
        }
    }
}

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
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS spent (
                epoch INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                PRIMARY KEY (epoch, nonce)
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
                    // A row of an earlier build keeps no root.
                    root: match c.len() {
                        0 => None,
                        _ => Some(c.try_into().map_err(|_| StoreFault)?),
                    },
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

        let mut statement = fault(
            self.connection
                .prepare("SELECT epoch, nonce FROM spent ORDER BY epoch"),
        )?;
        let rows = fault(statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        }))?;
        for row in rows {
            let (epoch, nonce) = fault(row)?;
            out.push(DirEvent::Spent {
                epoch: u32::try_from(epoch).map_err(|_| StoreFault)?,
                nonce: nonce.try_into().map_err(|_| StoreFault)?,
            });
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
                DirEvent::Closed { nonce, at, root } => fault(transaction.execute(
                    "INSERT INTO log (kind, a, b, c) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        CLOSED,
                        nonce.as_slice(),
                        at.to_be_bytes().as_slice(),
                        root.as_ref().map_or(&[][..], |root| root.as_slice())
                    ],
                ))?,
                DirEvent::Label { search_key, state } => fault(transaction.execute(
                    "INSERT OR REPLACE INTO labels (search_key, state) VALUES (?1, ?2)",
                    params![search_key, state],
                ))?,
                DirEvent::Spent { epoch, nonce } => fault(transaction.execute(
                    "INSERT OR IGNORE INTO spent (epoch, nonce) VALUES (?1, ?2)",
                    params![i64::from(*epoch), nonce.as_slice()],
                ))?,
            };
        }

        // ABU-095: a nonce two epochs back names no token that passes.
        let newest = events
            .iter()
            .filter_map(|event| match event {
                DirEvent::Spent { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .max();
        if let Some(newest) = newest {
            fault(transaction.execute(
                "DELETE FROM spent WHERE epoch < ?1",
                [i64::from(newest.saturating_sub(1))],
            ))?;
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

/// What each connection and the clock share.
struct Shared {
    state: Mutex<State>,
    /// The clock waits for the state or holds it. A request takes the
    /// state after the clock, thus no count of requests holds an epoch
    /// open (`DIS-167`).
    clock_waits: AtomicBool,
    /// The places of the requests that run or wait for the state.
    work: Arc<tokio::sync::Semaphore>,
    issued: Mutex<Issued>,
}

impl Shared {
    fn new(state: State) -> Self {
        Shared {
            state: Mutex::new(state),
            clock_waits: AtomicBool::new(false),
            work: Arc::new(tokio::sync::Semaphore::new(WORK_MAX)),
            issued: Mutex::new(Issued::default()),
        }
    }

    /// One request, on a blocking thread. It lets the clock go first.
    fn handle(&self, request: &[u8]) -> Option<Vec<u8>> {
        while self.clock_waits.load(Ordering::Acquire) {
            std::thread::sleep(CLOCK_WAIT);
        }

        match self.state.lock() {
            Ok(mut state) => state.step(|directory| directory.handle(request, now(), &mut OsRng)),
            Err(_) => None,
        }
    }

    /// One tick of the clock, on a blocking thread. The result is whether
    /// the tick ran with no fault.
    fn tick(&self) -> bool {
        self.clock_waits.store(true, Ordering::Release);
        let ticked = match self.state.lock() {
            Ok(mut state) => state.step(|directory| directory.tick(now(), &mut OsRng)),
            Err(_) => None,
        };
        self.clock_waits.store(false, Ordering::Release);
        matches!(ticked, Some(Ok(())))
    }

    /// The answer to one request that the gateway opened. It is the answer
    /// that an issuance took before, the answer `busy` when the work has no
    /// free place, or the answer of the directory.
    async fn answer(self: &Arc<Self>, plain: Vec<u8>) -> Option<Vec<u8>> {
        let issue = Issued::key_of(&plain);
        if let Some(key) = &issue {
            let held = match self.issued.lock() {
                Ok(mut issued) => issued.get(key, now()),
                Err(_) => None,
            };
            if held.is_some() {
                return held;
            }
        }

        let Ok(place) = self.work.clone().try_acquire_owned() else {
            return directory::encode_response(Status::Busy, &[]).ok();
        };

        // The proofs of work of an issuance take some milliseconds, thus the
        // step leaves the runtime threads free. The step keeps its place
        // until it ends, whatever the connection does meanwhile. The server
        // also holds the answer of an issuance for a connection that left.
        let shared = self.clone();
        tokio::task::spawn_blocking(move || {
            let _place = place;
            let answer = shared.handle(&plain)?;
            if let Some(key) = issue {
                if let Ok(mut issued) = shared.issued.lock() {
                    issued.keep(key, &answer, now());
                }
            }
            Some(answer)
        })
        .await
        .ok()
        .flatten()
    }
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    gateway: Arc<Gateway>,
    shared: Arc<Shared>,
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

    let Some(answer) = shared.answer(plain).await else {
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

    let shared = Arc::new(Shared::new(State {
        directory,
        store,
        broken: false,
    }));

    let clock = shared.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        let mut failed = false;
        loop {
            interval.tick().await;
            let clock = clock.clone();
            // DIS-167: an epoch closes at each interval, with or without an
            // update. Three signatures take some milliseconds.
            let ticked = tokio::task::spawn_blocking(move || clock.tick())
                .await
                .unwrap_or(false);

            // One line for each run of ticks that fail. It names no label.
            if !ticked && !failed {
                eprintln!("a tick of the directory failed, and the epoch does not close");
            }
            failed = !ticked;
        }
    });

    let gateway = Arc::new(gateway);
    let held = Arc::new(tokio::sync::Semaphore::new(CONNECTION_MAX));

    loop {
        // An accept that fails ends no directory: the process is out of
        // descriptors, or a peer reset its connection in the queue, and
        // both pass. It writes no line, because the cause can come from a
        // peer at will.
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(ACCEPT_RETRY).await;
            continue;
        };

        let Ok(permit) = held.clone().try_acquire_owned() else {
            continue;
        };

        let tls = tls.clone();
        let gateway = gateway.clone();
        let shared = shared.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(CONNECTION_TIME, async move {
                // A peer that sends no handshake holds its place for
                // `HANDSHAKE_TIME` and not for the whole of the connection.
                let accepted = tokio::time::timeout(HANDSHAKE_TIME, tls.accept(tcp)).await;
                if let Ok(Ok(stream)) = accepted {
                    serve(stream, gateway, shared).await;
                }
            })
            .await;
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn the_store_keeps_the_root_of_an_epoch_and_reads_a_row_with_none() {
        let mut store = SqliteDirectoryStore::open(":memory:").unwrap();
        let events = [
            DirEvent::Closed {
                nonce: [1; 32],
                at: NOW,
                root: Some([2; 32]),
            },
            DirEvent::Closed {
                nonce: [3; 32],
                at: NOW + 600,
                root: None,
            },
        ];
        store.commit(&events).unwrap();
        assert_eq!(store.load().unwrap(), events);

        // A root of another length is a fault of the store.
        store
            .connection
            .execute(
                "INSERT INTO log (kind, a, b, c) VALUES (?1, ?2, ?3, ?4)",
                params![
                    CLOSED,
                    [4u8; 32].as_slice(),
                    NOW.to_be_bytes().as_slice(),
                    [5u8; 7].as_slice()
                ],
            )
            .unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn an_issuance_that_repeats_takes_the_answer_of_the_first_one() {
        let request = directory::encode_request(Kind::Issue, &[7; 40]).unwrap();
        let key = Issued::key_of(&request).unwrap();
        // A request of another kind has no key: its answer follows the
        // state of the directory.
        let lookup = directory::encode_request(Kind::Lookup, &[7; 64]).unwrap();
        assert!(Issued::key_of(&lookup).is_none());
        assert!(Issued::key_of(&[0xFF; 9]).is_none());

        let mut issued = Issued::default();
        assert!(issued.get(&key, NOW).is_none());

        // The server holds no refusal: the request can pass at a later time.
        let refused = directory::encode_response(Status::Refused, &[]).unwrap();
        issued.keep(key, &refused, NOW);
        assert!(issued.get(&key, NOW).is_none());

        let done = directory::encode_response(Status::Done, &[1, 2, 3]).unwrap();
        issued.keep(key, &done, NOW);
        assert_eq!(issued.get(&key, NOW + 1), Some(done.clone()));

        // A bound holds the count of the answers, and the oldest one leaves.
        for index in 0..ISSUED_HELD {
            let mut other = [0u8; 32];
            other[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
            other[31] = 1;
            issued.keep(other, &done, NOW);
        }
        assert_eq!(issued.held.len(), ISSUED_HELD);

        assert!(issued.get(&key, NOW).is_none());

        // ABU-110: an answer serves the epoch of the clock and no later one.
        issued.keep(key, &done, NOW);
        let next_epoch = NOW + 8 * 86_400;
        assert_ne!(epoch_number(NOW), epoch_number(next_epoch));
        assert!(issued.get(&key, next_epoch).is_none());
    }
}
