//! The Notification Delivery Relay of Part 8 §8.2 as a server: the OHTTP
//! gateway, the store of the registrations, and the post to the provider.
//!
//! The NDR holds `(handle, ct_token)` and a removal hash for each
//! registration. A push brings `k_tok`; the token opens for that one post
//! and leaves memory with it. The server writes no log line that names a
//! handle, a token, or an address (§8.2.1).

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{params, Connection};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use umbra_core::notify::{
    ndr::{Delivery, Held, Ndr, NdrChange},
    MAX_QUEUES_PER_HANDLE, WAKE_COALESCE_WINDOW,
};
use umbra_crypto::{hash::sha3_256, kem::KeyPair, ohttp, zeroize::Zeroizing};
use umbra_transport::https::{self, Url};
use umbra_wire::ndr::{NdrRequest, NdrResponse, TokenCarrier, HANDLE_LEN};

use crate::{
    fcm::{Fcm, Sent},
    server::OsRng,
    store::StoreFault,
};

/// The path of the gateway.
pub const GATEWAY_PATH: &str = "/gateway";
/// The longest encapsulated request.
const REQUEST_MAX: usize = 4_096;
/// The wait for the provider.
const PROVIDER_WAIT: Duration = Duration::from_secs(10);
/// The time that one connection has from its accept to its answer, the
/// wait for the provider included.
const CONNECTION_TIME: Duration = Duration::from_secs(30);
/// The connections that the server holds at once. One more closes at its
/// accept.
const CONNECTION_MAX: usize = 4_096;

/// The time that the TLS handshake of one connection has. A peer that
/// sends no handshake holds its place for this time and not for the whole
/// of `CONNECTION_TIME`.
const HANDSHAKE_TIME: Duration = Duration::from_secs(10);
/// The wait after an accept that failed. The causes pass: the process is
/// out of descriptors, or a peer reset its connection in the queue.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// The registrations that the NDR holds at most. A first `NREG` carries no
/// admission and the OHTTP relay hides its sender, thus no bound for each
/// device exists. This bound keeps the memory and the file of the NDR
/// inside what a server holds. The NDR takes an `NREG` that moves a held
/// handle at the bound. An `NREG` for one more handle takes the place of
/// the oldest registration that took no push since the start of this run.
/// The NDR refuses it when each registration took one. Before this, the
/// NDR refused each new handle at the bound. A flood of first `NREG`
/// requests then left each new device with no push for `NDR_REG_TTL`.
pub const REGISTRATIONS_MAX: usize = 1 << 20;
/// The new handles that the NDR registers in one minute, over all OHTTP
/// relays. At this rate a flood needs more than 14 hours to reach
/// `REGISTRATIONS_MAX`, which is time for an operator to see the count
/// rise. The NDR refuses an `NREG` above it, and the device sends it again.
pub const NEW_HANDLES_PER_MINUTE: u32 = 1_200;
/// The new handles that the NDR registers in one minute from one OHTTP
/// relay, by the address of its connection. One relay that a flood passes
/// through then leaves the devices behind each other relay their part.
pub const NEW_HANDLES_PER_RELAY: u32 = 300;
/// The pushes that one handle takes inside one `WAKE_COALESCE_WINDOW`. A
/// handle holds `MAX_QUEUES_PER_HANDLE` queues at the most (`NTF-033`),
/// each at a relay of its own at the most. One relay hands one push for a
/// handle in a window (`NTF-048`). The window of a relay and the window of
/// the NDR start at different times. A relay that keeps the rule thus
/// lands two pushes in one window of the NDR at the most. The NDR refuses
/// a push above the bound, and that push goes to no provider.
const PUSHES_PER_WINDOW: usize = 2 * MAX_QUEUES_PER_HANDLE;
/// The requests whose hash the NDR holds. A request that repeats one does
/// nothing. An OHTTP relay that kept the bytes of an `NPUSH` thus wakes no
/// device with them a second time (RFC 9458 §6.5).
///
/// The NDR holds the hash of a request that proved its right alone. Such a
/// request is a push whose token opened and that went to the provider, or
/// a request that changed a registration. The hash covers the handle and
/// the encapsulated bytes. Before this, the hash of each request that the
/// gateway opened took a place. Any party then flushed the 65 536 places
/// with requests that parsed as nothing, and each kept `NPUSH` passed
/// again. The places now turn over at the rate of the requests that prove
/// a right. A party that holds no `k_tok` adds a place for each new handle
/// that `NEW_HANDLES_PER_MINUTE` admits. That is more than three hours for
/// all of them.
///
/// The places are in memory alone, thus a restart of the NDR empties them,
/// and so does a flush at the rate above. A kept `NPUSH` that passes again
/// is then one push of its handle under `PUSHES_PER_WINDOW`. That bound
/// holds with no memory of a request. The rotation of the handle ends its
/// `k_tok`, and the kept `NPUSH` then passes no more.
const REPLAYS_HELD: usize = 1 << 18;
/// The time that the NDR holds the count at an `NREG` of a handle, in
/// seconds. It is above `CONNECTION_TIME`, thus it covers each push that
/// was at the provider when the `NREG` came.
const MOVED_HELD: u64 = 60;

/// What the NDR holds beside the registrations to bound the work that a
/// request makes. It holds hashes, counts, and times, and it is in memory
/// alone.
#[derive(Default)]
struct Guard {
    /// The hash of each recent request that proved its right, and their
    /// order.
    seen: BTreeSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    /// The minute of the clock, the new handles inside it, and those of
    /// each OHTTP relay.
    minute: u64,
    new_handles: u32,
    new_by_relay: BTreeMap<[u8; 16], u32>,
    /// The time of the registration of each handle, and whether it took a
    /// push since the start of this run.
    born: BTreeMap<[u8; HANDLE_LEN], (u64, bool)>,
    /// The handles that took no push, the oldest registration first.
    unpushed: BTreeSet<(u64, [u8; HANDLE_LEN])>,
    /// The window of the clock, and the pushes of each handle inside it.
    window: u64,
    pushed: BTreeMap<[u8; HANDLE_LEN], usize>,
    /// The count of the `NREG` requests that the NDR took.
    moves: u64,
    /// The count and the time at the last `NREG` of each handle, for
    /// `MOVED_HELD`.
    moved: BTreeMap<[u8; HANDLE_LEN], (u64, u64)>,
    moved_pruned_at: u64,
}

impl Guard {
    /// Whether the NDR holds `key`: a request that proved its right came
    /// with it before.
    fn repeats(&self, key: &[u8; 32]) -> bool {
        self.seen.contains(key)
    }

    /// Holds `key` from now on, for a request that proved its right.
    fn remember(&mut self, key: [u8; 32]) {
        if !self.seen.insert(key) {
            return;
        }
        self.seen_order.push_back(key);
        if self.seen_order.len() > REPLAYS_HELD {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    /// Whether the NDR registers one more new handle from the OHTTP relay
    /// at `relay` in the minute of `now`. The bounds `(all, one)` hold for
    /// all relays and for one. It counts the one that it admits.
    fn admits_handle(&mut self, relay: [u8; 16], (all, one): (u32, u32), now: u64) -> bool {
        let minute = now / 60;
        if minute != self.minute {
            self.minute = minute;
            self.new_handles = 0;
            self.new_by_relay.clear();
        }
        let of_relay = self.new_by_relay.entry(relay).or_insert(0);
        if self.new_handles >= all || *of_relay >= one {
            return false;
        }
        *of_relay = of_relay.saturating_add(1);
        self.new_handles = self.new_handles.saturating_add(1);
        true
    }

    /// The oldest registration that took no push, other than `handle`.
    fn oldest_unpushed(&self, handle: &[u8; HANDLE_LEN]) -> Option<[u8; HANDLE_LEN]> {
        self.unpushed
            .iter()
            .map(|(_, held)| *held)
            .find(|held| held != handle)
    }

    /// The handle took a push.
    fn pushed(&mut self, handle: &[u8; HANDLE_LEN]) {
        if let Some((at, pushed)) = self.born.get_mut(handle) {
            *pushed = true;
            self.unpushed.remove(&(*at, *handle));
        }
    }

    /// Takes the time of a registration, new or moved.
    fn registered(&mut self, handle: [u8; HANDLE_LEN], at: u64) {
        let pushed = match self.born.insert(handle, (at, false)) {
            Some((before, pushed)) => {
                self.unpushed.remove(&(before, handle));
                pushed
            }
            None => false,
        };
        if pushed {
            self.born.insert(handle, (at, true));
        } else {
            self.unpushed.insert((at, handle));
        }
    }

    /// A registration left.
    fn unregistered(&mut self, handle: &[u8; HANDLE_LEN]) {
        if let Some((at, _)) = self.born.remove(handle) {
            self.unpushed.remove(&(at, *handle));
        }
    }

    /// Whether one more push of `handle` goes to the provider at `now`.
    fn admits_push(&mut self, handle: [u8; HANDLE_LEN], now: u64) -> bool {
        let window = now / WAKE_COALESCE_WINDOW;
        if window != self.window {
            self.window = window;
            self.pushed.clear();
        }
        let count = self.pushed.entry(handle).or_insert(0);
        if *count >= PUSHES_PER_WINDOW {
            return false;
        }
        *count = count.saturating_add(1);
        true
    }

    /// Counts each `NREG` among `changes`, and takes its count and time.
    fn note(&mut self, changes: &[NdrChange], now: u64) {
        if self.moved_pruned_at != now {
            self.moved_pruned_at = now;
            self.moved
                .retain(|_, (_, at)| now.saturating_sub(*at) < MOVED_HELD);
        }
        for change in changes {
            match change {
                NdrChange::Registered { handle, held } => {
                    self.moves = self.moves.saturating_add(1);
                    self.moved.insert(*handle, (self.moves, now));
                    self.registered(*handle, held.registered_at);
                }
                NdrChange::Unregistered { handle } => self.unregistered(handle),
            }
        }
    }

    /// Whether an `NREG` of `handle` came after the count was `mark`.
    fn moved_since(&self, handle: &[u8; HANDLE_LEN], mark: u64) -> bool {
        self.moved.get(handle).is_some_and(|(at, _)| *at > mark)
    }
}

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
                handle        BLOB PRIMARY KEY,
                nonce         BLOB NOT NULL,
                ct_token      BLOB NOT NULL,
                removal_hash  BLOB NOT NULL,
                registered_at INTEGER NOT NULL DEFAULT 0
            ) WITHOUT ROWID;",
        ))?;
        // A file of an earlier build holds no time of registration.
        let has_time = fault(connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('registrations') WHERE name = 'registered_at'",
            [],
            |row| row.get::<_, i64>(0),
        ))? > 0;
        if !has_time {
            fault(connection.execute_batch(
                "ALTER TABLE registrations ADD COLUMN registered_at INTEGER NOT NULL DEFAULT 0;",
            ))?;
        }
        Ok(SqliteNdrStore { connection })
    }
}

impl NdrStore for SqliteNdrStore {
    fn load(&mut self) -> Result<Vec<([u8; HANDLE_LEN], Held)>, StoreFault> {
        let mut statement = fault(self.connection.prepare(
            "SELECT handle, nonce, ct_token, removal_hash, registered_at FROM registrations",
        ))?;
        let rows = fault(statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        }))?;
        // A row of an earlier build lives its full time from this start.
        let now = unix_now();
        let mut out = Vec::new();
        for row in rows {
            let (handle, nonce, ct_token, removal_hash, at) = fault(row)?;
            out.push((
                handle.try_into().map_err(|_| StoreFault)?,
                Held {
                    nonce: nonce.try_into().map_err(|_| StoreFault)?,
                    ct_token,
                    removal_hash: removal_hash.try_into().map_err(|_| StoreFault)?,
                    registered_at: u64::try_from(at).ok().filter(|at| *at > 0).unwrap_or(now),
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
                    "INSERT OR REPLACE INTO registrations
                     (handle, nonce, ct_token, removal_hash, registered_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        handle.as_slice(),
                        held.nonce.as_slice(),
                        held.ct_token,
                        held.removal_hash.as_slice(),
                        i64::try_from(held.registered_at).unwrap_or(i64::MAX)
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

/// How often the NDR drops the registrations past their time (`NTF-138`).
const SWEEP_EVERY: Duration = Duration::from_secs(3_600);

/// The time now, in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

struct State {
    ndr: Ndr,
    store: Box<dyn NdrStore>,
    guard: Guard,
    /// The registrations that the NDR holds at most.
    registrations_max: usize,
    /// The new handles of one minute, over all OHTTP relays and from one.
    new_handles_max: (u32, u32),
    /// A commit failed: the registrations in memory ran ahead of the store,
    /// and the NDR serves nothing more until a restart reads the store.
    broken: bool,
}

impl State {
    fn new(ndr: Ndr, store: Box<dyn NdrStore>) -> Self {
        State {
            ndr,
            store,
            guard: Guard::default(),
            registrations_max: REGISTRATIONS_MAX,
            new_handles_max: (NEW_HANDLES_PER_MINUTE, NEW_HANDLES_PER_RELAY),
            broken: false,
        }
    }

    /// The state of a run that continues the registrations `held` of an
    /// earlier one. None of them took a push in this run yet.
    fn restored(held: Vec<([u8; HANDLE_LEN], Held)>, store: Box<dyn NdrStore>) -> Self {
        let mut guard = Guard::default();
        for (handle, registration) in &held {
            guard.registered(*handle, registration.registered_at);
        }
        State {
            guard,
            ..State::new(Ndr::restore(held), store)
        }
    }

    /// Commits `changes`. A store that takes no commit refuses the request,
    /// and each later one.
    fn commit(&mut self, changes: &[NdrChange], now: u64) -> Option<()> {
        self.guard.note(changes, now);
        if self.store.commit(changes).is_err() {
            eprintln!("the store took no commit, and the NDR serves nothing more");
            self.broken = true;
            return None;
        }
        Some(())
    }

    /// Runs one step of the NDR and commits what it changed. A store that
    /// takes no commit refuses the request, and each later one.
    fn step<T>(&mut self, run: impl FnOnce(&mut Ndr) -> T) -> Option<T> {
        if self.broken {
            return None;
        }
        let out = run(&mut self.ndr);
        let changes = self.ndr.take_changes();
        self.commit(&changes, unix_now())?;
        Some(out)
    }

    /// Serves one request that the gateway opened. `digest` is the hash of
    /// its encapsulated bytes, and `relay` the address of the OHTTP relay
    /// that carried it. The NDR refuses a request that does not parse, and
    /// a request that repeats one that proved its right. It refuses a new
    /// handle above the rate of its minute, or above `REGISTRATIONS_MAX`
    /// with no place to take. It refuses a push above `PUSHES_PER_WINDOW`.
    /// None of them changes a registration or reaches a provider.
    fn request(
        &mut self,
        digest: [u8; 32],
        plain: &[u8],
        relay: [u8; 16],
        now: u64,
    ) -> Option<(NdrResponse, Option<Delivery>)> {
        if self.broken {
            return None;
        }
        let (handle, registers) = match NdrRequest::parse(plain) {
            Ok(NdrRequest::Register { handle, .. }) => (handle, true),
            Ok(NdrRequest::Unregister { handle, .. } | NdrRequest::Push { handle, .. }) => {
                (handle, false)
            }
            Err(_) => return Some((NdrResponse::Refused, None)),
        };
        // The key of a request binds its bytes to the handle that it names.
        let key = sha3_256(&[&handle[..], &digest[..]]);
        if self.guard.repeats(&key) {
            return Some((NdrResponse::Refused, None));
        }
        let before = self.ndr.len();
        let (answer, delivery) = self.ndr.handle(plain, now);
        if registers && self.ndr.len() > before {
            // The handle is new. It stays when its minute admits it and the
            // NDR holds room, or a place that no push ever used.
            let mut stays = self.guard.admits_handle(relay, self.new_handles_max, now);
            if stays && self.ndr.len() > self.registrations_max {
                match self.guard.oldest_unpushed(&handle) {
                    Some(oldest) => self.ndr.gone(oldest),
                    None => stays = false,
                }
            }
            if !stays {
                // It leaves again, and the store sees neither change.
                self.ndr.gone(handle);
                drop(self.ndr.take_changes());
                return Some((NdrResponse::Refused, None));
            }
        }
        let changes = self.ndr.take_changes();
        self.commit(&changes, now)?;
        // The count takes a push whose token opened and no other one. A
        // party that holds no `k_tok` thus uses up no push of a handle.
        if let Some(delivery) = &delivery {
            if !self.guard.admits_push(delivery.handle, now) {
                return Some((NdrResponse::Refused, None));
            }
            self.guard.pushed(&delivery.handle);
        }
        // A push that goes to the provider and a request that changed a
        // registration proved a right, and their bytes pass no second time.
        if delivery.is_some() || (answer == NdrResponse::Taken && !changes.is_empty()) {
            self.guard.remember(key);
        }
        Some((answer, delivery))
    }

    /// The provider named the target of a push gone (`NTF-125`). The count
    /// of the `NREG` requests was `mark` when the push started. A handle
    /// that an `NREG` moved since then holds another token now, thus its
    /// registration stays; the result is whether the registration left.
    fn provider_gone(&mut self, handle: [u8; HANDLE_LEN], mark: u64) -> Option<bool> {
        if self.guard.moved_since(&handle, mark) {
            return Some(false);
        }
        self.step(|ndr| ndr.gone(handle)).map(|()| true)
    }
}

/// Posts the blob to the provider. FCM takes a data message of high
/// priority, and a UnifiedPush endpoint takes the 69 bytes as the body; each
/// carries the expiry (`NTF-065`). An NDR with no FCM account posts nothing
/// for an FCM token.
async fn deliver(delivery: &Delivery, tls: Arc<rustls::ClientConfig>, fcm: Option<&Fcm>) -> Sent {
    let Ok(target) = core::str::from_utf8(&delivery.target) else {
        return Sent::Refused;
    };
    if delivery.carrier == TokenCarrier::Fcm {
        return match fcm {
            Some(fcm) => fcm.send(target, &delivery.blob, delivery.ttl).await,
            None => Sent::Refused,
        };
    }
    let Some(url) = Url::parse(target) else {
        return Sent::Refused;
    };
    let ttl = delivery.ttl.to_string();
    let posted = https::post(
        &url,
        "application/octet-stream",
        &[("TTL", &ttl), ("Urgency", "high")],
        &delivery.blob,
        tls,
        4_096,
        PROVIDER_WAIT,
    )
    .await;
    match posted {
        // An endpoint that is gone answers 404 or 410.
        Ok((404 | 410, _)) => Sent::Gone,
        Ok((200..=299, _)) => Sent::Taken,
        Ok(_) | Err(_) => Sent::Refused,
    }
}

async fn serve(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    relay: [u8; 16],
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
    // The request of a push holds `k_tok`. It serves the one step below, and
    // `Zeroizing` wipes it before the wait for the provider (§8.2.1).
    let plain = Zeroizing::new(plain);
    let digest = sha3_256(&[&request.body[..]]);
    let stepped = match state.lock() {
        Ok(mut state) => state
            .request(digest, &plain, relay, unix_now())
            .map(|served| (served, state.guard.moves)),
        Err(_) => None,
    };
    drop(plain);
    let Some(((mut answer, delivery), mark)) = stepped else {
        let _ = https::respond(&mut stream, 502, "text/plain", &[]).await;
        return;
    };
    if let Some(delivery) = delivery {
        match deliver(&delivery, provider_tls, fcm.as_deref()).await {
            // NTF-125: the provider named the target gone. A handle that
            // moved to another token since the push started keeps its
            // registration, and the relay may try again.
            Sent::Gone => {
                let left = match state.lock() {
                    Ok(mut state) => state.provider_gone(delivery.handle, mark),
                    Err(_) => None,
                };
                answer = if left == Some(true) {
                    NdrResponse::Gone
                } else {
                    NdrResponse::Refused
                };
            }
            Sent::Taken => {}
            // A push that did not go, and the relay may try again.
            Sent::Refused => answer = NdrResponse::Refused,
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
    let mut state = State::restored(held, store);
    state.ndr = core::mem::take(&mut state.ndr).serving_unified_push(unified_push);
    let state = Arc::new(Mutex::new(state));
    // NTF-138: a registration that no `NREG` renewed leaves, at the start
    // and each hour after it.
    let sweeping = state.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(mut state) = sweeping.lock() {
                let _ = state.step(|ndr| ndr.expire(unix_now()));
            }
            tokio::time::sleep(SWEEP_EVERY).await;
        }
    });
    let gateway = Arc::new(gateway);
    let held = Arc::new(tokio::sync::Semaphore::new(CONNECTION_MAX));
    loop {
        // An accept that fails ends no NDR: a restart would empty the
        // memory of the requests. It writes no line, because the cause can
        // come from a peer at will.
        let Ok((tcp, address)) = listener.accept().await else {
            tokio::time::sleep(ACCEPT_RETRY).await;
            continue;
        };
        // A peer that stalls holds no task past its time, and the server
        // holds a bounded count of them (`NET-335`).
        let Ok(permit) = held.clone().try_acquire_owned() else {
            continue;
        };
        // The address of the OHTTP relay, for the count of its new handles.
        // The NDR holds it for one minute and writes it nowhere.
        let relay = match address.ip().to_canonical() {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        };
        let tls = tls.clone();
        let gateway = gateway.clone();
        let state = state.clone();
        let provider_tls = provider_tls.clone();
        let fcm = fcm.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(CONNECTION_TIME, async move {
                let accepted = tokio::time::timeout(HANDSHAKE_TIME, tls.accept(tcp)).await;
                if let Ok(Ok(stream)) = accepted {
                    serve(stream, relay, gateway, state, provider_tls, fcm).await;
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

    #[test]
    fn a_file_of_an_earlier_build_opens_and_each_row_takes_a_time() {
        let directory = std::env::temp_dir().join(format!("umbra-ndr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("ndr.db");
        let path = path.to_str().unwrap();
        {
            let old = Connection::open(path).unwrap();
            old.execute_batch(
                "CREATE TABLE registrations (
                    handle       BLOB PRIMARY KEY,
                    nonce        BLOB NOT NULL,
                    ct_token     BLOB NOT NULL,
                    removal_hash BLOB NOT NULL
                ) WITHOUT ROWID;",
            )
            .unwrap();
            old.execute(
                "INSERT INTO registrations VALUES (?1, ?2, ?3, ?4)",
                params![
                    [7u8; HANDLE_LEN].as_slice(),
                    [1u8; 24].as_slice(),
                    vec![2u8; 40],
                    [3u8; 32].as_slice()
                ],
            )
            .unwrap();
        }
        // NTF-138: the row of the earlier build lives its full time from
        // this start, and a new row keeps the time of its NREG.
        let mut store = SqliteNdrStore::open(path).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].1.registered_at + 60 >= unix_now());
        let held = Held {
            nonce: [4; 24],
            ct_token: vec![5; 40],
            removal_hash: [6; 32],
            registered_at: 1_700_000_000,
        };
        store
            .commit(&[NdrChange::Registered {
                handle: [8; HANDLE_LEN],
                held: held.clone(),
            }])
            .unwrap();
        drop(store);
        let mut again = SqliteNdrStore::open(path).unwrap();
        let loaded = again.load().unwrap();
        assert!(loaded.contains(&([8; HANDLE_LEN], held)));
        drop(again);
        let _ = std::fs::remove_dir_all(&directory);
    }

    use umbra_core::notify::token::HandleSet;
    use umbra_crypto::secret::Secret;
    use umbra_wire::ndr::{encode_token, BLOB_LEN, NDR_REQUEST_LEN, PUSH_TOKEN_MAX};

    const NOW: u64 = 1_700_000_000;

    fn encode(request: &NdrRequest<'_>) -> [u8; NDR_REQUEST_LEN] {
        let mut out = [0u8; NDR_REQUEST_LEN];
        request.encode(&mut out).unwrap();
        out
    }

    /// The handle of a device, the `NREG` of its FCM token, the `NPUSH`
    /// that opens it, and an `NPUSH` under another key.
    type Device = (
        [u8; HANDLE_LEN],
        [u8; NDR_REQUEST_LEN],
        [u8; NDR_REQUEST_LEN],
        [u8; NDR_REQUEST_LEN],
    );

    fn device(seed: u8) -> Device {
        let mut rng = OsRng;
        let set = HandleSet::assign(&[[seed; 32]], &[], &[], 0, &mut rng).unwrap();
        let group = &set.groups()[0];
        let mut plain = [0u8; PUSH_TOKEN_MAX];
        let n = encode_token(TokenCarrier::Fcm, b"fcm-token", &mut plain).unwrap();
        let registration = group.registration(&plain[..n], [4; 24]).unwrap();
        let register = encode(&NdrRequest::Register {
            handle: group.handle,
            nonce: registration.nonce,
            ct_token: &registration.ct_token,
            removal_hash: sha3_256(&[&[9u8; 32]]),
            prior: Secret::new([9; 32]),
        });
        let push = encode(&NdrRequest::Push {
            handle: group.handle,
            k_tok: Secret::new(*group.k_tok.expose()),
            ttl: 60,
            blob: [6; BLOB_LEN],
        });
        let other_key = encode(&NdrRequest::Push {
            handle: group.handle,
            k_tok: Secret::new([0; 32]),
            ttl: 60,
            blob: [6; BLOB_LEN],
        });
        (group.handle, register, push, other_key)
    }

    /// The address of one OHTTP relay.
    const RELAY: [u8; 16] = [0x52; 16];

    fn state() -> State {
        State::new(Ndr::default(), Box::new(MemoryNdrStore::default()))
    }

    impl State {
        /// One request that the OHTTP relay at `RELAY` carried.
        fn request_from(
            &mut self,
            digest: [u8; 32],
            plain: &[u8],
            now: u64,
        ) -> Option<(NdrResponse, Option<Delivery>)> {
            self.request(digest, plain, RELAY, now)
        }
    }

    #[test]
    fn a_request_that_repeats_its_bytes_does_nothing() {
        let mut state = state();
        let (_, register, push, _) = device(1);
        let taken = state.request_from([1; 32], &register, NOW).unwrap();
        assert_eq!(taken.0, NdrResponse::Taken);
        // The encapsulated bytes of the push come two times: the first
        // one opens the token, and the second one reaches no provider.
        let (answer, delivery) = state.request_from([2; 32], &push, NOW).unwrap();
        assert_eq!(answer, NdrResponse::Taken);
        assert!(delivery.is_some());
        let (answer, delivery) = state.request_from([2; 32], &push, NOW + 1).unwrap();
        assert_eq!(answer, NdrResponse::Refused);
        assert!(delivery.is_none());
        // The same push under a new encapsulation is a new request.
        let (answer, delivery) = state.request_from([3; 32], &push, NOW + 1).unwrap();
        assert_eq!(answer, NdrResponse::Taken);
        assert!(delivery.is_some());
    }

    #[test]
    fn a_handle_takes_a_bounded_count_of_pushes_in_one_window() {
        let mut state = state();
        let (_, register, push, _) = device(1);
        let (_, other_register, other_push, other_key) = device(2);
        state.request_from([0xA0; 32], &register, NOW).unwrap();
        state
            .request_from([0xA1; 32], &other_register, NOW)
            .unwrap();
        let start = NOW - NOW % WAKE_COALESCE_WINDOW;
        let mut digest = [0u8; 32];
        for sent in 0..PUSHES_PER_WINDOW {
            digest[0] = u8::try_from(sent).unwrap();
            let (answer, delivery) = state.request(digest, &push, RELAY, start).unwrap();
            assert_eq!(answer, NdrResponse::Taken);
            assert!(delivery.is_some());
        }
        // One more inside the window goes to no provider.
        let (answer, delivery) = state.request_from([0xB0; 32], &push, start + 1).unwrap();
        assert_eq!(answer, NdrResponse::Refused);
        assert!(delivery.is_none());
        // A push that opens no token counts for no handle, thus a party
        // with no `k_tok` uses up no push of the other handle.
        for sent in 0..=PUSHES_PER_WINDOW {
            digest[1] = u8::try_from(sent).unwrap() + 1;
            let (answer, _) = state.request(digest, &other_key, RELAY, start + 1).unwrap();
            assert_eq!(answer, NdrResponse::Refused);
        }
        // Another handle has a count of its own, and so has the next window.
        let (answer, _) = state
            .request_from([0xB1; 32], &other_push, start + 1)
            .unwrap();
        assert_eq!(answer, NdrResponse::Taken);
        let next = start + WAKE_COALESCE_WINDOW;
        let (answer, delivery) = state.request_from([0xB2; 32], &push, next).unwrap();
        assert_eq!(answer, NdrResponse::Taken);
        assert!(delivery.is_some());
    }

    #[test]
    fn a_handle_above_the_bound_takes_the_oldest_place_that_no_push_used() {
        let mut state = state();
        state.registrations_max = 2;
        let (_, first, first_push, _) = device(1);
        let (_, second, second_push, _) = device(2);
        let (_, third, third_push, _) = device(3);
        let (_, fourth, fourth_push, _) = device(4);
        let taken = |state: &mut State, digest: u8, plain: &[u8], now: u64| {
            state.request_from([digest; 32], plain, now).unwrap().0
        };
        assert_eq!(taken(&mut state, 1, &first, NOW), NdrResponse::Taken);
        assert_eq!(taken(&mut state, 2, &second, NOW + 1), NdrResponse::Taken);
        assert_eq!(
            taken(&mut state, 3, &first_push, NOW + 1),
            NdrResponse::Taken
        );
        // One more handle at the bound takes the place of the oldest
        // registration that took no push. The first one took a push, thus
        // the second one leaves, in the NDR and in its store.
        assert_eq!(taken(&mut state, 4, &third, NOW + 2), NdrResponse::Taken);
        assert_eq!(state.ndr.len(), 2);
        assert_eq!(state.store.load().unwrap().len(), 2);
        assert_eq!(
            taken(&mut state, 5, &second_push, NOW + 2),
            NdrResponse::Gone
        );
        assert_eq!(
            taken(&mut state, 6, &third_push, NOW + 2),
            NdrResponse::Taken
        );
        // Each registration took a push now: the NDR refuses one more
        // handle, and neither the NDR nor its store holds it.
        assert_eq!(taken(&mut state, 7, &fourth, NOW + 3), NdrResponse::Refused);
        assert_eq!(state.ndr.len(), 2);
        assert_eq!(state.store.load().unwrap().len(), 2);
        assert_eq!(
            taken(&mut state, 8, &fourth_push, NOW + 3),
            NdrResponse::Gone
        );
        // NTF-124: a held handle moves at the bound too.
        assert_eq!(taken(&mut state, 9, &first, NOW + 4), NdrResponse::Taken);
        assert_eq!(state.ndr.len(), 2);

        // A run that restarts holds each registration as one that took no
        // push, the oldest first.
        let held = state.store.load().unwrap();
        let mut again = State::restored(held, Box::new(MemoryNdrStore::default()));
        again.registrations_max = 2;
        assert_eq!(taken(&mut again, 10, &fourth, NOW + 5), NdrResponse::Taken);
        assert_eq!(
            taken(&mut again, 11, &third_push, NOW + 5),
            NdrResponse::Gone
        );
        assert_eq!(
            taken(&mut again, 12, &first_push, NOW + 5),
            NdrResponse::Taken
        );
    }

    #[test]
    fn the_new_handles_of_one_minute_are_bounded_for_one_relay_and_for_all() {
        let mut state = state();
        state.new_handles_max = (3, 2);
        let other_relay = [0x53; 16];
        let minute = NOW - NOW % 60;
        let registers: Vec<_> = (1..=6).map(|seed| device(seed).1).collect();
        let mut digest = 0u8;
        let mut taken = |state: &mut State, plain: &[u8], relay: [u8; 16], now: u64| {
            digest += 1;
            state.request([digest; 32], plain, relay, now).unwrap().0
        };
        // One OHTTP relay brings its count of new handles, and no more.
        assert_eq!(
            taken(&mut state, &registers[0], RELAY, minute),
            NdrResponse::Taken
        );
        assert_eq!(
            taken(&mut state, &registers[1], RELAY, minute),
            NdrResponse::Taken
        );
        assert_eq!(
            taken(&mut state, &registers[2], RELAY, minute),
            NdrResponse::Refused
        );
        // Another relay has a count of its own, inside the count of all.
        assert_eq!(
            taken(&mut state, &registers[2], other_relay, minute + 1),
            NdrResponse::Taken
        );
        assert_eq!(
            taken(&mut state, &registers[3], other_relay, minute + 2),
            NdrResponse::Refused
        );
        assert_eq!(state.ndr.len(), 3);
        assert_eq!(state.store.load().unwrap().len(), 3);
        // NTF-124: a held handle moves above the count: it is no new one.
        assert_eq!(
            taken(&mut state, &registers[0], RELAY, minute + 3),
            NdrResponse::Taken
        );
        // The next minute gives each count back.
        assert_eq!(
            taken(&mut state, &registers[3], RELAY, minute + 60),
            NdrResponse::Taken
        );
    }

    #[test]
    fn a_request_that_proves_no_right_takes_no_place_among_the_repeats() {
        let mut state = state();
        let (_, register, push, other_key) = device(1);
        state.request_from([1; 32], &register, NOW).unwrap();
        assert!(state.request_from([2; 32], &push, NOW).unwrap().1.is_some());
        let held = state.guard.seen.len();
        assert_eq!(held, 2);
        // Bytes that parse as no request and a push under another key take
        // no place. A push for a handle that the NDR does not hold takes
        // none too. Before this, such requests flushed the places, and a
        // kept push then passed a second time.
        let (_, _, absent_push, _) = device(2);
        for sent in 0..40u8 {
            let digest = [0x80 + sent; 32];
            let junk = [sent; NDR_REQUEST_LEN];
            assert_eq!(
                state.request_from(digest, &junk, NOW).unwrap().0,
                NdrResponse::Refused
            );
            assert!(state
                .request_from(digest, &other_key, NOW)
                .unwrap()
                .1
                .is_none());
            assert!(state
                .request_from(digest, &absent_push, NOW)
                .unwrap()
                .1
                .is_none());
        }
        assert_eq!(state.guard.seen.len(), held);
        // The kept push still repeats.
        let (answer, delivery) = state.request_from([2; 32], &push, NOW + 1).unwrap();
        assert_eq!(answer, NdrResponse::Refused);
        assert!(delivery.is_none());
    }

    #[test]
    fn a_gone_answer_for_the_token_before_a_move_drops_no_registration() {
        let mut state = state();
        let (handle, register, push, _) = device(1);
        state.request_from([1; 32], &register, NOW).unwrap();
        // A push starts, and the device moves its handle to another token
        // while the push is at the provider.
        assert!(state.request_from([2; 32], &push, NOW).unwrap().1.is_some());
        let mark = state.guard.moves;
        assert_eq!(
            state.request_from([3; 32], &register, NOW).unwrap().0,
            NdrResponse::Taken
        );
        // NTF-125: the provider names the token before the move gone, and
        // the registration of the token after it stays.
        assert_eq!(state.provider_gone(handle, mark), Some(false));
        assert_eq!(state.ndr.len(), 1);
        // A push that starts after the move drops it.
        assert_eq!(state.provider_gone(handle, state.guard.moves), Some(true));
        assert!(state.ndr.is_empty());
    }
}
