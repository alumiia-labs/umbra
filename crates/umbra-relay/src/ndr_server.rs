//! The Notification Delivery Relay of Part 8 §8.2 as a server: the OHTTP
//! gateway, the store of the registrations, and the post to the provider.
//!
//! The NDR holds `(handle, ct_token)` and a removal hash for each
//! registration. A push brings `k_tok`; the token opens for that one post
//! and leaves memory with it. The server writes no log line that names a
//! handle, a token, or an address (§8.2.1).

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{params, Connection};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use umbra_core::notify::ndr::{Delivery, Held, Ndr, NdrChange};
use umbra_crypto::{kem::KeyPair, ohttp};
use umbra_transport::https::{self, Url};
use umbra_wire::ndr::{NdrResponse, TokenCarrier, HANDLE_LEN};

use crate::{fcm::Fcm, server::OsRng, store::StoreFault};

/// The path of the gateway.
pub const GATEWAY_PATH: &str = "/gateway";
/// The longest encapsulated request.
const REQUEST_MAX: usize = 4_096;
/// The wait for the provider.
const PROVIDER_WAIT: Duration = Duration::from_secs(10);

/// The store of the registrations.
pub trait NdrStore: Send {
    /// Reads each registration at the start of a run.
    fn load(&mut self) -> Result<Vec<([u8; HANDLE_LEN], Held)>, StoreFault>;
    /// Commits the changes of one request, all or none.
    fn commit(&mut self, changes: &[NdrChange]) -> Result<(), StoreFault>;
}

/// A store in RAM, for a test.
#[derive(Default)]
pub struct MemoryNdrStore(pub BTreeMap<[u8; HANDLE_LEN], Held>);

impl NdrStore for MemoryNdrStore {
    fn load(&mut self) -> Result<Vec<([u8; HANDLE_LEN], Held)>, StoreFault> {
        Ok(self.0.iter().map(|(h, held)| (*h, held.clone())).collect())
    }

    fn commit(&mut self, changes: &[NdrChange]) -> Result<(), StoreFault> {
        for change in changes {
            match change {
                NdrChange::Registered { handle, held } => {
                    self.0.insert(*handle, held.clone());
                }
                NdrChange::Unregistered { handle } => {
                    self.0.remove(handle);
                }
            }
        }
        Ok(())
    }
}

/// The store of the registrations in one SQLite file, under
/// `secure_delete`: a dropped registration leaves no bytes.
pub struct SqliteNdrStore {
    connection: Connection,
}

fn fault<T>(result: rusqlite::Result<T>) -> Result<T, StoreFault> {
    result.map_err(|_| StoreFault)
}

impl SqliteNdrStore {
    /// Opens the file at `path`, and makes it when it does not exist.
    pub fn open(path: &str) -> Result<Self, StoreFault> {
        let connection = fault(Connection::open(path))?;
        fault(connection.pragma_update(None, "secure_delete", "ON"))?;
        fault(connection.pragma_update(None, "journal_mode", "WAL"))?;
        fault(connection.pragma_update(None, "synchronous", "FULL"))?;
        fault(connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS registrations (
                handle       BLOB PRIMARY KEY,
                nonce        BLOB NOT NULL,
                ct_token     BLOB NOT NULL,
                removal_hash BLOB NOT NULL
            ) WITHOUT ROWID;",
        ))?;
        Ok(SqliteNdrStore { connection })
    }
}

impl NdrStore for SqliteNdrStore {
    fn load(&mut self) -> Result<Vec<([u8; HANDLE_LEN], Held)>, StoreFault> {
        let mut statement = fault(
            self.connection
                .prepare("SELECT handle, nonce, ct_token, removal_hash FROM registrations"),
        )?;
        let rows = fault(statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        }))?;
        let mut out = Vec::new();
        for row in rows {
            let (handle, nonce, ct_token, removal_hash) = fault(row)?;
            out.push((
                handle.try_into().map_err(|_| StoreFault)?,
                Held {
                    nonce: nonce.try_into().map_err(|_| StoreFault)?,
                    ct_token,
                    removal_hash: removal_hash.try_into().map_err(|_| StoreFault)?,
                },
            ));
        }
        Ok(out)
    }

    fn commit(&mut self, changes: &[NdrChange]) -> Result<(), StoreFault> {
        if changes.is_empty() {
            return Ok(());
        }
        let transaction = fault(self.connection.transaction())?;
        for change in changes {
            match change {
                NdrChange::Registered { handle, held } => fault(transaction.execute(
                    "INSERT OR REPLACE INTO registrations (handle, nonce, ct_token, removal_hash)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        handle.as_slice(),
                        held.nonce.as_slice(),
                        held.ct_token,
                        held.removal_hash.as_slice()
                    ],
                ))?,
                NdrChange::Unregistered { handle } => fault(transaction.execute(
                    "DELETE FROM registrations WHERE handle = ?1",
                    params![handle.as_slice()],
                ))?,
            };
        }
        fault(transaction.commit())?;
        fault(
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())),
        )
    }
}

/// The key of the gateway, which the build of a client and the settings of
/// a queue relay pin (`NTF-127`).
pub struct Gateway {
    /// The key id of the key configuration.
    pub key_id: u8,
    /// The key pair.
    pub pair: KeyPair,
}

struct State {
    ndr: Ndr,
    store: Box<dyn NdrStore>,
    /// A commit failed: the registrations in memory ran ahead of the store,
    /// and the NDR serves nothing more until a restart reads the store.
    broken: bool,
}

impl State {
    /// Runs one step of the NDR and commits what it changed. A store that
    /// takes no commit refuses the request, and each later one.
    fn step<T>(&mut self, run: impl FnOnce(&mut Ndr) -> T) -> Option<T> {
        if self.broken {
            return None;
        }
        let out = run(&mut self.ndr);
        if self.store.commit(&self.ndr.take_changes()).is_err() {
            eprintln!("the store took no commit, and the NDR serves nothing more");
            self.broken = true;
            return None;
        }
        Some(out)
    }
}

/// Posts the blob to the provider. FCM takes a data message of high
/// priority, and a UnifiedPush endpoint takes the 69 bytes as the body; each
/// carries the expiry (`NTF-065`). An NDR with no FCM account posts nothing
/// for an FCM token.
async fn deliver(
    delivery: &Delivery,
    tls: Arc<rustls::ClientConfig>,
    fcm: Option<&Fcm>,
) -> Option<u16> {
    if delivery.carrier == TokenCarrier::Fcm {
        let token = core::str::from_utf8(&delivery.target).ok()?;
        return fcm?.send(token, &delivery.blob, delivery.ttl).await;
    }
    let url = Url::parse(core::str::from_utf8(&delivery.target).ok()?)?;
    let ttl = delivery.ttl.to_string();
    https::post(
        &url,
        "application/octet-stream",
        &[("TTL", &ttl), ("Urgency", "high")],
        &delivery.blob,
        tls,
        4_096,
        PROVIDER_WAIT,
    )
    .await
    .ok()
    .map(|(status, _)| status)
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    gateway: Arc<Gateway>,
    state: Arc<Mutex<State>>,
    provider_tls: Arc<rustls::ClientConfig>,
    fcm: Option<Arc<Fcm>>,
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
    let stepped = match state.lock() {
        Ok(mut state) => state.step(|ndr| ndr.handle(&plain)),
        Err(_) => None,
    };
    let Some((mut answer, delivery)) = stepped else {
        let _ = https::respond(&mut stream, 502, "text/plain", &[]).await;
        return;
    };
    if let Some(delivery) = delivery {
        match deliver(&delivery, provider_tls, fcm.as_deref()).await {
            // NTF-125: the provider named the target gone.
            Some(404 | 410) => {
                if let Ok(mut state) = state.lock() {
                    let _ = state.step(|ndr| ndr.gone(delivery.handle));
                }
                answer = NdrResponse::Gone;
            }
            // A provider that took the push answers 2xx; each other status
            // is a push that did not go, and the relay may try again.
            Some(200..=299) => {}
            Some(_) | None => answer = NdrResponse::Refused,
        }
    }
    let Ok(sealed) = ohttp::encapsulate_response(&key, &answer.encode(), &mut OsRng) else {
        return;
    };
    let _ = https::respond(&mut stream, 200, "message/ohttp-res", &sealed).await;
}

/// Runs the NDR until the listener fails. `provider_tls` is the
/// configuration that the posts to the providers trust, and `fcm` the
/// sender of the FCM account of the deployment, if it has one.
/// `unified_push` makes it post to UnifiedPush endpoints too (`NTF-134`).
pub async fn run_ndr(
    listener: TcpListener,
    tls: TlsAcceptor,
    gateway: Gateway,
    mut store: Box<dyn NdrStore>,
    provider_tls: Arc<rustls::ClientConfig>,
    fcm: Option<Fcm>,
    unified_push: bool,
) -> Result<(), StoreFault> {
    let fcm = fcm.map(Arc::new);
    let held = store.load()?;
    let state = Arc::new(Mutex::new(State {
        ndr: Ndr::restore(held).serving_unified_push(unified_push),
        store,
        broken: false,
    }));
    let gateway = Arc::new(gateway);
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            return Ok(());
        };
        let tls = tls.clone();
        let gateway = gateway.clone();
        let state = state.clone();
        let provider_tls = provider_tls.clone();
        let fcm = fcm.clone();
        tokio::spawn(async move {
            if let Ok(stream) = tls.accept(tcp).await {
                serve(stream, gateway, state, provider_tls, fcm).await;
            }
        });
    }
}
