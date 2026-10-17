//! The watch of a locked client in Direct mode (Part 8 §8.4.3).
//!
//! A locked client holds no key of its store (Part 14 `IMP-127`), thus it
//! reads no queue. The watch holds the notifier credential of each queue
//! (§8.2.4), which sees an arrival and can read and acknowledge no record.
//! One task with a node and a link of its own sends the `NSUB` of each
//! queue, and it gives each blob of an `NWAKE` to the platform. The
//! platform opens the blob with the wake table, as it opens a push
//! (`NTF-136`).
//!
//! The open client writes the watch table, and the platform seals it under
//! its keystore beside the wake table (`NTF-145`). The node of the watch
//! makes no contact, thus its root identity is a fresh value that names
//! nothing.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::mpsc;
use umbra_core::session::node::{ClientEvent, ClientNode};
use umbra_crypto::{
    hierarchy::RootIdentity,
    rand_core::TryRng,
    secret::Secret,
    stored::{Reader, Writer},
    x25519::StaticSecret,
};
use umbra_transport::{
    native,
    race::{Plan, Wire},
    Dial,
};
use zeroize::Zeroizing;

use crate::{
    bindings::{relay_info, FfiError, HopRoles, RelayEndpoint},
    runtime::OsRng,
};

/// The tick of the task.
const TICK: Duration = Duration::from_secs(1);

/// The ticks between two tries of the watches that wait for a circuit.
const RETRY_TICKS: u32 = 30;

/// The first wait before a new link. Each session that ends before its
/// first circuit is ready doubles it, up to [`RELINK_MAX`].
const RELINK_FIRST: Duration = Duration::from_secs(2);

/// The longest wait before a new link, as `NTF-118` bounds a run.
const RELINK_MAX: Duration = Duration::from_secs(30);

/// The form of the table.
const VERSION: u8 = 1;

/// One watch: the relay of the queue, its `notifier_id`, and its notifier
/// secret.
struct Entry {
    relay: [u8; 32],
    notifier_id: [u8; 32],
    secret: Secret<32>,
}

/// What the watch needs while the client is locked (`NTF-145`): the
/// ingress relay of the last run, the relay set of that run, and each
/// watch. It holds no key of the store.
pub struct WatchTable {
    guard: RelayEndpoint,
    relays: Vec<RelayEndpoint>,
    root_ca_path: Option<String>,
    bootstrap: bool,
    entries: Vec<Entry>,
}

fn put_text(w: &mut Writer, text: &str) -> Result<(), FfiError> {
    w.var(text.as_bytes()).map_err(|_| FfiError::TooLong)
}

fn put_relay(w: &mut Writer, relay: &RelayEndpoint) -> Result<(), FfiError> {
    put_text(w, &relay.host)?;
    w.var(&relay.ipv4).map_err(|_| FfiError::TooLong)?;
    w.u16(relay.port);
    w.var(&relay.static_key).map_err(|_| FfiError::TooLong)?;
    w.var(&relay.relay_id).map_err(|_| FfiError::TooLong)?;
    w.u8(relay.layer);
    put_text(w, &relay.operator)?;
    w.flag(relay.family.is_some());
    if let Some(family) = &relay.family {
        put_text(w, family)?;
    }
    put_text(w, &relay.country)?;
    w.u32(relay.asn);
    w.flag(relay.prefix.is_some());
    if let Some(prefix) = &relay.prefix {
        w.var(prefix).map_err(|_| FfiError::TooLong)?;
    }
    w.flag(relay.holds_files);
    w.var(&relay.identity_pk).map_err(|_| FfiError::TooLong)?;
    w.option(relay.roles.as_ref(), |w, roles| {
        w.flag(roles.ingress);
        w.flag(roles.chain);
        w.flag(roles.queue);
    });
    w.flag(relay.prefix_v6.is_some());
    if let Some(prefix) = &relay.prefix_v6 {
        w.var(prefix).map_err(|_| FfiError::TooLong)?;
    }
    w.option(relay.class.as_ref(), |w, class| w.u8(*class));
    Ok(())
}

fn text(r: &mut Reader<'_>) -> Result<String, FfiError> {
    let bytes = r.var().map_err(|_| FfiError::Malformed)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| FfiError::Malformed)
}

fn var(r: &mut Reader<'_>) -> Result<Vec<u8>, FfiError> {
    r.var().map(<[u8]>::to_vec).map_err(|_| FfiError::Malformed)
}

fn relay(r: &mut Reader<'_>) -> Result<RelayEndpoint, FfiError> {
    let bad = |_| FfiError::Malformed;
    let host = text(r)?;
    let ipv4 = var(r)?;
    let port = r.u16().map_err(bad)?;
    let static_key = var(r)?;
    let relay_id = var(r)?;
    let layer = r.u8().map_err(bad)?;
    let operator = text(r)?;
    let family = if r.flag().map_err(bad)? {
        Some(text(r)?)
    } else {
        None
    };
    let country = text(r)?;
    let asn = r.u32().map_err(bad)?;
    let prefix = if r.flag().map_err(bad)? {
        Some(var(r)?)
    } else {
        None
    };
    let holds_files = r.flag().map_err(bad)?;
    let identity_pk = var(r)?;
    let roles = r
        .option(|r| {
            Ok(HopRoles {
                ingress: r.flag()?,
                chain: r.flag()?,
                queue: r.flag()?,
            })
        })
        .map_err(bad)?;
    let prefix_v6 = if r.flag().map_err(bad)? {
        Some(var(r)?)
    } else {
        None
    };
    let class = r.option(|r| r.u8()).map_err(bad)?;

    Ok(RelayEndpoint {
        host,
        ipv4,
        port,
        static_key,
        relay_id,
        layer,
        operator,
        family,
        country,
        asn,
        prefix,
        holds_files,
        identity_pk,
        roles,
        prefix_v6,
        class,
    })
}

/// The most bytes that [`put_relay`] writes for `relay`: each field, and a
/// length or a flag in front of each one.
fn relay_size(relay: &RelayEndpoint) -> usize {
    let fixed = 64;
    [
        relay.host.len(),
        relay.ipv4.len(),
        relay.static_key.len(),
        relay.relay_id.len(),
        relay.operator.len(),
        relay.family.as_ref().map_or(0, String::len),
        relay.country.len(),
        relay.prefix.as_ref().map_or(0, Vec::len),
        relay.identity_pk.len(),
        relay.prefix_v6.as_ref().map_or(0, Vec::len),
    ]
    .into_iter()
    .fold(fixed, usize::saturating_add)
}

impl WatchTable {
    /// The table of the open client.
    pub fn new(
        guard: RelayEndpoint,
        relays: Vec<RelayEndpoint>,
        root_ca_path: Option<String>,
        bootstrap: bool,
        entries: Vec<crate::client::WatchEntry>,
    ) -> Self {
        WatchTable {
            guard,
            relays,
            root_ca_path,
            bootstrap,
            entries: entries
                .into_iter()
                .map(|(relay, notifier_id, secret)| Entry {
                    relay,
                    notifier_id,
                    secret,
                })
                .collect(),
        }
    }

    /// The most bytes that [`WatchTable::encode`] writes.
    fn size(&self) -> usize {
        let relays = self
            .relays
            .iter()
            .map(relay_size)
            .fold(relay_size(&self.guard), usize::saturating_add);
        let path = self.root_ca_path.as_ref().map_or(0, String::len);
        let entries = self.entries.len().saturating_mul(96);
        [relays, path, entries]
            .into_iter()
            .fold(32, usize::saturating_add)
    }

    /// The bytes that the platform seals. The writer holds the notifier
    /// secrets, thus it takes its full size first: a growth would free a
    /// copy of them that no one wipes (`IMP-124`).
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, FfiError> {
        let mut w = Writer::with_capacity(self.size());
        w.u8(VERSION);
        put_relay(&mut w, &self.guard)?;
        w.u32(u32::try_from(self.relays.len()).map_err(|_| FfiError::TooLong)?);
        for relay in &self.relays {
            put_relay(&mut w, relay)?;
        }

        w.flag(self.root_ca_path.is_some());
        if let Some(path) = &self.root_ca_path {
            put_text(&mut w, path)?;
        }

        w.flag(self.bootstrap);
        w.u32(u32::try_from(self.entries.len()).map_err(|_| FfiError::TooLong)?);
        for entry in &self.entries {
            w.bytes(&entry.relay);
            w.bytes(&entry.notifier_id);
            w.bytes(entry.secret.expose());
        }

        Ok(w.finish())
    }

    /// Reads the bytes that [`WatchTable::encode`] wrote.
    pub fn parse(bytes: &[u8]) -> Result<Self, FfiError> {
        let bad = |_| FfiError::Malformed;
        let mut r = Reader::new(bytes);
        if r.u8().map_err(bad)? != VERSION {
            return Err(FfiError::Malformed);
        }

        let guard = relay(&mut r)?;
        let count = r.u32().map_err(bad)?;
        let mut relays = Vec::new();
        for _ in 0..count {
            relays.push(relay(&mut r)?);
        }

        let root_ca_path = if r.flag().map_err(bad)? {
            Some(text(&mut r)?)
        } else {
            None
        };

        let bootstrap = r.flag().map_err(bad)?;
        let count = r.u32().map_err(bad)?;
        let mut entries = Vec::new();
        for _ in 0..count {
            entries.push(Entry {
                relay: r.array().map_err(bad)?,
                notifier_id: r.array().map_err(bad)?,
                secret: Secret::new(r.array().map_err(bad)?),
            });
        }

        r.end().map_err(bad)?;
        Ok(WatchTable {
            guard,
            relays,
            root_ca_path,
            bootstrap,
            entries,
        })
    }

    /// The count of the watches.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no watch.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The platform side of a watch.
#[uniffi::export(with_foreign)]
pub trait WatchListener: Send + Sync {
    /// Takes the blob of one arrival (Part 8 §8.2.2). The platform opens
    /// it with the wake table under `NTF-136`. An exception of the platform
    /// is an error, and the watch continues.
    fn wake(&self, blob: Vec<u8>) -> Result<(), FfiError>;

    /// The watch ended, and it starts no new session: its table holds no
    /// relay that it can reach. No message arrives until the unlock, and
    /// the platform tells the user so (`NTF-120`).
    fn down(&self) -> Result<(), FfiError>;
}

/// A watch that runs. It ends at [`Watch::stop`] or when the platform
/// drops it.
#[derive(uniffi::Object)]
pub struct Watch {
    stop: Mutex<Option<mpsc::UnboundedSender<()>>>,
}

#[uniffi::export]
impl Watch {
    /// Ends the watch. Its link closes, and each relay ends the watches of
    /// its circuits with them.
    pub fn stop(&self) {
        if let Ok(mut held) = self.stop.lock() {
            held.take();
        }
    }
}

/// Starts the watch of a locked client from its table (`NTF-142`). The
/// caller holds the result for as long as the watch runs. A table whose
/// ingress relay has no address, whose relay entry does not parse, or
/// whose root certificate file does not read is an error here: no session
/// of it could start, and the platform would show a watch that never runs
/// (`NTF-120`).
#[uniffi::export]
pub fn start_watch(
    table: Vec<u8>,
    listener: Arc<dyn WatchListener>,
) -> Result<Arc<Watch>, FfiError> {
    let table = Zeroizing::new(table);
    let parsed = WatchTable::parse(&table)?;
    if parsed.is_empty() {
        return Err(FfiError::NotFound);
    }

    node_of(&parsed, &mut OsRng)?;

    let (stop, stopped) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("umbra-watch".to_owned())
        .stack_size(16 << 20)
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(run_watch(parsed, listener, stopped));
        })
        .map_err(|_| FfiError::Offline)?;

    Ok(Arc::new(Watch {
        stop: Mutex::new(Some(stop)),
    }))
}

/// How a session ended.
enum End {
    Lost,
    Closed,
    /// The table gives no node any more, thus no later session starts.
    Down,
}

/// The wait before the next session (`NTF-118`): it doubles from
/// [`RELINK_FIRST`] up to [`RELINK_MAX`], and a session that reached the
/// ready state sets it back.
fn next_wait(backoff: &mut Duration, was_ready: bool) -> Duration {
    if was_ready {
        *backoff = RELINK_FIRST;
    }
    let wait = *backoff;
    *backoff = backoff.saturating_mul(2).min(RELINK_MAX);
    wait
}

/// Runs the watch until the platform stops it. A session that ends starts
/// again after a backoff.
async fn run_watch(
    table: WatchTable,
    listener: Arc<dyn WatchListener>,
    mut stopped: mpsc::UnboundedReceiver<()>,
) {
    crate::devlog::line(format!("watch: start, {} queues", table.len()));
    let mut backoff = RELINK_FIRST;
    loop {
        let (end, was_ready) = session(&table, listener.as_ref(), &mut stopped).await;
        match end {
            End::Lost => {}
            End::Closed => break,
            End::Down => {
                crate::devlog::line("watch: down".to_owned());
                let _ = listener.down();
                break;
            }
        }

        let wait = next_wait(&mut backoff, was_ready);
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stopped.recv() => break,
        }
    }

    crate::devlog::line("watch: end".to_owned());
}

/// One session: one link, the circuits to the relays of the watches, and
/// each blob until the link, a circuit, or the platform ends it. It gives
/// whether a circuit was ready, for the backoff.
async fn session(
    table: &WatchTable,
    listener: &dyn WatchListener,
    stopped: &mut mpsc::UnboundedReceiver<()>,
) -> (End, bool) {
    let mut rng = OsRng;
    let Ok((mut node, dial, tls)) = node_of(table, &mut rng) else {
        return (End::Down, false);
    };

    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let connected = native::connect(&dial, tls, plan, key, mask, Duration::from_secs(10)).await;
    let Ok(mut link) = connected else {
        return (End::Lost, false);
    };
    if node.connected(&mut rng).is_err() {
        return (End::Lost, false);
    }

    for entry in &table.entries {
        let secret = StaticSecret::from(*entry.secret.expose());
        let _ = node.watch(entry.relay, entry.notifier_id, secret, &mut rng);
    }

    let mut is_ready = false;
    let mut ticks = 0u32;
    let mut tick = tokio::time::interval(TICK);
    let end = 'run: loop {
        for capsule in node.take_capsules() {
            if link.send(&capsule).await.is_err() {
                break 'run End::Lost;
            }
        }
        let events = tokio::select! {
            received = link.recv() => match received {
                Ok(bytes) => match node.on_capsule(&bytes, crate::runtime::unix_now(), &mut rng) {
                    Ok(events) => events,
                    Err(_) => break 'run End::Lost,
                },
                Err(_) => break 'run End::Lost,
            },
            _ = stopped.recv() => break 'run End::Closed,
            _ = tick.tick() => {
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(RETRY_TICKS) && node.watches_wait() {
                    let _ = node.retry_watches(&mut rng);
                }
                node.on_tick(crate::runtime::unix_now())
            }
        };

        // The node of a watch holds no contact, thus it commits nothing.
        let _ = node.take_changes();
        for event in events {
            match event {
                ClientEvent::CircuitReady => {
                    if !is_ready {
                        crate::devlog::line("watch: ready".to_owned());
                    }
                    is_ready = true;
                }
                ClientEvent::CircuitLost | ClientEvent::CircuitAged => break 'run End::Lost,
                // A fault of the platform with one blob ends no watch.
                ClientEvent::Wake { blob, .. } => {
                    let _ = listener.wake(blob);
                }
                _ => {}
            }
        }
    };

    // WIR-246: the session ends at the relay now.
    if let Some(capsule) = node.close() {
        let _ = tokio::time::timeout(Duration::from_secs(1), link.send(&capsule)).await;
    }

    (end, is_ready)
}

/// The node, the dial of the ingress relay, and the TLS setup of one
/// session.
fn node_of(
    table: &WatchTable,
    rng: &mut OsRng,
) -> Result<(ClientNode, Dial, Arc<native::ClientConfig>), FfiError> {
    let address = table.guard.ipv4.as_slice().try_into();
    let dial = Dial {
        host: table.guard.host.clone(),
        addr_v4: Some(address.map_err(|_| FfiError::Malformed)?),
        addr_v6: None,
        port: table.guard.port,
    };

    let ingress = relay_info(&table.guard)?;
    let mut candidates = Vec::new();
    for relay in table.relays.iter().filter(|relay| relay.layer != 1) {
        candidates.push(relay_info(relay)?);
    }

    let tls = match &table.root_ca_path {
        Some(path) => native::tls_config_with_root_file(path),
        None => native::tls_config(),
    }
    .map_err(|_| FfiError::Storage)?;

    let mut seed = [0u8; 32];
    let _ = rng.try_fill_bytes(&mut seed);
    let root = RootIdentity::new(Secret::new(seed));
    let mut node = ClientNode::with_relays(ingress, candidates, root);
    node.set_bootstrap(table.bootstrap);
    Ok((node, dial, tls))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn endpoint(id: u8, layer: u8) -> RelayEndpoint {
        RelayEndpoint {
            host: format!("r{id}.example"),
            ipv4: vec![10, 0, 0, id],
            port: 443,
            static_key: vec![id; 32],
            relay_id: vec![id; 32],
            layer,
            operator: format!("op{id}"),
            family: (id == 2).then(|| "fam".to_owned()),
            country: "US".to_owned(),
            asn: 64_500,
            prefix: None,
            holds_files: id == 3,
            identity_pk: vec![id; 4],
            roles: (id == 1).then_some(HopRoles {
                ingress: true,
                chain: false,
                queue: false,
            }),
            prefix_v6: (id == 3).then(|| vec![1; 6]),
            class: Some(2),
        }
    }

    #[test]
    fn a_table_reads_back_as_it_was_written() {
        let table = WatchTable::new(
            endpoint(1, 1),
            vec![endpoint(1, 1), endpoint(2, 2), endpoint(3, 3)],
            Some("/data/ca.pem".to_owned()),
            true,
            vec![([3; 32], [4; 32], Secret::new([5; 32]))],
        );
        let bytes = table.encode().unwrap();

        // IMP-124: the writer took its full size first, thus it grew in no
        // reallocation.
        assert!(bytes.len() <= table.size());
        assert_eq!(bytes.capacity(), table.size());

        let back = WatchTable::parse(&bytes).unwrap();
        assert_eq!(back.guard.host, "r1.example");
        assert_eq!(back.relays.len(), 3);
        assert_eq!(back.relays[1].family.as_deref(), Some("fam"));
        assert_eq!(back.relays[2].prefix_v6, Some(vec![1; 6]));
        assert!(back.relays[0].roles.unwrap().ingress);
        assert_eq!(back.root_ca_path.as_deref(), Some("/data/ca.pem"));
        assert!(back.bootstrap);
        assert_eq!(back.len(), 1);
        assert_eq!(back.entries[0].notifier_id, [4; 32]);
        assert_eq!(back.entries[0].secret.expose(), &[5; 32]);
        assert_eq!(back.encode().unwrap(), bytes);

        // A table with bytes after its end does not parse.
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(WatchTable::parse(&long).is_err());
    }

    #[test]
    fn the_wait_before_a_new_session_doubles_from_two_seconds() {
        // NTF-118: 2, 4, 8, 16, and then the ceiling of 30 s.
        let mut backoff = RELINK_FIRST;
        let waits: Vec<u64> = (0..6)
            .map(|_| next_wait(&mut backoff, false).as_secs())
            .collect();
        assert_eq!(waits, [2, 4, 8, 16, 30, 30]);

        // A session that reached the ready state sets it back to 2 s.
        assert_eq!(next_wait(&mut backoff, true).as_secs(), 2);
        assert_eq!(next_wait(&mut backoff, false).as_secs(), 4);
    }

    struct Nobody;

    impl WatchListener for Nobody {
        fn wake(&self, _blob: Vec<u8>) -> Result<(), FfiError> {
            Ok(())
        }

        fn down(&self) -> Result<(), FfiError> {
            Ok(())
        }
    }

    #[test]
    fn a_table_that_reaches_no_relay_starts_no_watch() {
        let entries = || vec![([3; 32], [4; 32], Secret::new([5; 32]))];
        let start = |table: WatchTable| {
            start_watch(table.encode().unwrap().to_vec(), Arc::new(Nobody)).err()
        };

        // NTF-120: a guard with no IPv4 address.
        let mut guard = endpoint(1, 1);
        guard.ipv4 = vec![10, 0, 0];
        let table = WatchTable::new(guard, vec![endpoint(2, 2)], None, false, entries());
        assert_eq!(start(table), Some(FfiError::Malformed));

        // A root certificate file that an update of the app removed.
        let table = WatchTable::new(
            endpoint(1, 1),
            vec![endpoint(2, 2)],
            Some("/no/such/root-ca.pem".to_owned()),
            false,
            entries(),
        );
        assert_eq!(start(table), Some(FfiError::Storage));
    }
}
