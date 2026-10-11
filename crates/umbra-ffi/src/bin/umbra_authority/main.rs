//! The report queue of one directory authority (Part 10 §10.4.2): the
//! authority holds a queue at a queue relay, as a client holds one, and
//! each link-fault report of a client arrives there sealed to its key.
//!
//! ```text
//! umbra-authority <settings file>
//! ```
//!
//! The settings file holds one `key=value` pair on each line. A deployment
//! names two directories, and the file holds no secret:
//!
//! ```text
//! keys=/etc/umbra-signer/keys             # the key directory of the signer
//! secrets=/var/lib/umbra-authority/secrets
//! index=0                                 # this authority in the key set
//! verdicts=/var/lib/umbra-authority/verdicts
//! manifest=/var/www/umbra/.well-known/umbra/manifest
//! keyset=/var/www/umbra/.well-known/umbra/keyset.bin
//! state=/var/lib/umbra-authority/report-queue.state
//! queue=/var/lib/umbra-authority/report-queue.bin
//! aggregators=0,1                         # the aggregators of §10.8 that it plays
//! ```
//!
//! `keys` is the directory that `umbra-signer keygen` made. The key of the
//! authority `index` is the file `authority-<index>.seed` there, and the
//! key of an aggregator is the file of its index. `secrets` holds the two
//! secrets of the report queue: `queue-client.seed`, the identity of the
//! queue client, and `report.seed`, the X25519 key of the reports. The
//! program makes each one at its first start, readable by its owner alone.
//! On a Unix system it refuses a key file or a secret file that a group or
//! each other user can read.
//!
//! A test network gives the seeds in the settings file in the place of the
//! two directories, and it names the root that its relays chain to:
//!
//! ```text
//! seed=<64 hex characters>                # the seed of the test authorities
//! root_seed=<64 hex characters>           # the identity of the queue client
//! report_seed=<64 hex characters>         # the X25519 key of the reports
//! ca=tests/fixtures/tls/ca.pem            # the root that the relays chain to
//! ```
//!
//! A settings file with those seeds protects nothing. A file that holds a
//! `keys` line and a `seed` line does not parse.
//!
//! The program writes `queue` once the relay made the queue, and the
//! signer signs that file into the next manifest (`REL-167`). Each report
//! that opens is one line on the standard output.
//!
//! After the end of each epoch the authority reads the noised chain count
//! of each relay that `FAULT_MIN_REPORTS` reports of that epoch name, from
//! the two aggregators of §10.8. A relay whose fault rate reaches
//! `RELAY_FAULT_RATE` gets an isolation query on the chain of the last of
//! its reports (`REL-080`, `REL-112`, `REL-195`). A query on the evidence of
//! the authority (`REL-108`) runs as
//!
//! ```text
//! umbra-authority <settings file> probe <relay>,<relay>,<relay>
//! ```
//!
//! with the three `relay_id` values of a chain in hex, the ingress first. A
//! verdict is one line of the file `verdicts`. The noised chain count of one
//! relay in one ended epoch prints as
//!
//! ```text
//! umbra-authority <settings file> count <relay> <epoch>
//! ```

#![forbid(unsafe_code)]

mod isolation;
mod stats;

use std::{collections::BTreeMap, path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use umbra_core::{
    directory::{
        bloc::BlocList,
        manifest::{ListedRelay, RelayManifest, RelaySet},
        report::LinkFaultReport,
        root::{Consensus, DirectoryKeySet},
        EPOCH_SECONDS,
    },
    session::node::{ClientNode, ContactId, RelayInfo, StateChange},
};
use umbra_crypto::{
    handshake::nk::RelayStatic, hash::sha3_256, hierarchy::RootIdentity, seal, secret::Secret,
    sign::SigningKey,
};
use umbra_ffi::runtime::{run_client, Command, Persist, Update};
use umbra_transport::{native, Dial};

/// The wait before a run that ended starts again.
const RETRY: Duration = Duration::from_secs(5);
/// `FAULT_MIN_REPORTS`: the reports of one epoch below which no query runs
/// (`REL-112`).
const FAULT_MIN_REPORTS: u16 = 3;
/// `RELAY_FAULT_RATE`: the reports of one epoch over the chains of one
/// relay at which a query runs (`REL-080`).
const RELAY_FAULT_RATE: f64 = 0.02;
/// The wait after the end of an epoch before its shares are read: each
/// relay makes them at its first tick of the next epoch (`REL-190`).
const SHARE_SETTLE: u64 = 120;
/// The period of the check for an ended epoch.
const EVALUATE_EVERY: Duration = Duration::from_secs(60);

/// Where the keys of the authorities come from.
enum KeySource {
    /// The seed of the test authorities, in the settings file.
    TestSeed([u8; 32]),
    /// The key directory of the signer: one seed file for each authority,
    /// readable by its owner alone.
    Directory(PathBuf),
}

struct Settings {
    keys: KeySource,
    index: u8,
    verdicts: PathBuf,
    manifest: PathBuf,
    keyset: PathBuf,
    /// The root that the relays chain to, or none for the public roots.
    ca: Option<String>,
    root_seed: [u8; 32],
    report_seed: [u8; 32],
    state: PathBuf,
    queue: PathBuf,
    /// The aggregators of §10.8 that this program plays, by index.
    aggregators: Vec<u8>,
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Reads a secret of 32 bytes from its file in hex. On a Unix system a
/// file that a group or each other user can read gives none.
fn read_secret(path: &std::path::Path) -> Option<[u8; 32]> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).ok()?.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!("{} is open to more than its owner", path.display());
            return None;
        }
    }
    let text = zeroize::Zeroizing::new(std::fs::read_to_string(path).ok()?);
    hex32(text.trim())
}

/// Reads the secret at `path`, or makes it from the generator of the
/// operating system, readable by its owner alone.
fn secret_at(path: &std::path::Path) -> Option<[u8; 32]> {
    if path.exists() {
        return read_secret(path);
    }
    let mut secret = [0u8; 32];
    umbra_crypto::rand_core::TryRng::try_fill_bytes(&mut umbra_ffi::runtime::OsRng, &mut secret)
        .ok()?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let text = zeroize::Zeroizing::new(to_hex(&secret));
    let mut file = options.open(path).ok()?;
    std::io::Write::write_all(&mut file, text.as_bytes()).ok()?;
    file.sync_all().ok()?;
    Some(secret)
}

fn read_settings(path: &str) -> Option<Settings> {
    let text = std::fs::read_to_string(path).ok()?;
    let values: BTreeMap<&str, &str> = text
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    // A deployment names the key directory and the secret directory. A
    // test network gives each seed in the file.
    let (keys, root_seed, report_seed) = match (values.get("keys"), values.get("seed")) {
        (Some(dir), None) => {
            if values.contains_key("root_seed") || values.contains_key("report_seed") {
                eprintln!("a settings file with a keys line holds no seed");
                return None;
            }
            let secrets = PathBuf::from(values.get("secrets")?);
            std::fs::create_dir_all(&secrets).ok()?;
            (
                KeySource::Directory(PathBuf::from(dir)),
                secret_at(&secrets.join("queue-client.seed"))?,
                secret_at(&secrets.join("report.seed"))?,
            )
        }
        (None, Some(seed)) => (
            KeySource::TestSeed(hex32(seed)?),
            hex32(values.get("root_seed")?)?,
            hex32(values.get("report_seed")?)?,
        ),
        _ => return None,
    };
    Some(Settings {
        keys,
        index: values.get("index")?.parse().ok()?,
        verdicts: values.get("verdicts")?.into(),
        manifest: values.get("manifest")?.into(),
        keyset: values.get("keyset")?.into(),
        ca: values.get("ca").map(|ca| (*ca).to_owned()),
        root_seed,
        report_seed,
        state: values.get("state")?.into(),
        queue: values.get("queue")?.into(),
        aggregators: values
            .get("aggregators")
            .map(|list| {
                list.split(',')
                    .filter_map(|index| index.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// The store of the authority: the stored form of its report queue, which
/// the node gives as the state of a rendezvous queue.
struct QueueStore {
    state: PathBuf,
}

impl Persist for QueueStore {
    fn commit(&mut self, changes: Vec<StateChange>, _received: &[(ContactId, Vec<u8>)]) -> bool {
        for change in changes {
            if let StateChange::RendezvousQueue { state, .. } = change {
                if std::fs::write(&self.state, state).is_err() {
                    return false;
                }
            }
        }
        true
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The key of the authority `index`: from the seed of the test authorities
/// as `umbra-test-authority` derives it, or from its seed file in the key
/// directory of the signer.
fn authority_key(settings: &Settings, index: u8) -> Option<SigningKey> {
    let seed = match &settings.keys {
        KeySource::TestSeed(seed) => sha3_256(&[b"umbra/test/authority", seed, &[index]]),
        KeySource::Directory(dir) => read_secret(&dir.join(format!("authority-{index}.seed")))?,
    };
    Some(SigningKey::from_seed(Secret::new(seed)))
}

/// The TLS configuration of each dial: the root of a test network, or the
/// public roots.
fn tls_of(settings: &Settings) -> Result<Arc<native::ClientConfig>, &'static str> {
    match &settings.ca {
        Some(ca) => native::tls_config_with_root_file(ca),
        None => native::tls_config(),
    }
    .map_err(|_| "the root does not read")
}

fn info(relay: &ListedRelay) -> RelayInfo {
    RelayInfo {
        candidate: relay.candidate,
        key: RelayStatic {
            s: relay.ntor_pk,
            relay_id: relay.candidate.relay_id,
        },
    }
}

fn dial_of(relay: &ListedRelay) -> Dial {
    Dial {
        host: relay.host.clone(),
        addr_v4: Some(relay.addr_v4),
        addr_v6: None,
        port: relay.port,
    }
}

/// The relays of the manifest that the key set verifies: the first ingress
/// relay to dial, and each relay of a chain.
fn relays_of(settings: &Settings) -> Result<(RelayInfo, Dial, Vec<RelayInfo>), &'static str> {
    let set = relay_set(settings)?;
    let guard = set
        .relays
        .iter()
        .find(|relay| relay.candidate.ingress && relay.addr_v4 != [0; 4])
        .ok_or("the manifest holds no ingress relay")?;
    let chain = set
        .relays
        .iter()
        .filter(|relay| !relay.candidate.ingress)
        .map(info)
        .collect();
    Ok((info(guard), dial_of(guard), chain))
}

/// The relay set of the manifest, verified under the key set. A manifest
/// with a part of the signed set gives none (`REL-147`). A probe of a chain
/// would find a listed relay absent, and the guard would come from a part.
fn relay_set(settings: &Settings) -> Result<RelaySet, &'static str> {
    let manifest = std::fs::read(&settings.manifest).map_err(|_| "the manifest does not read")?;
    let keyset = std::fs::read(&settings.keyset).map_err(|_| "the key set does not read")?;
    let (keyset, _) = DirectoryKeySet::parse(&keyset).map_err(|_| "the key set does not parse")?;
    let mut consensus = Consensus::new(keyset, 0).map_err(|_| "the key set does not parse")?;
    let manifest = RelayManifest::parse(&manifest).map_err(|_| "the manifest does not parse")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the clock is before 1970")?
        .as_secs();
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now)
        .map_err(|_| "the manifest does not verify")?;
    if !set.is_whole {
        return Err("the manifest holds a part of the relay set");
    }
    Ok(set)
}

/// Whether the key set makes the directory provisional (`REL-126`). The
/// tool then builds its chains under the relaxation of Part 3 `NET-340`,
/// as each client does: with one operator no other chain exists.
fn is_provisional(settings: &Settings) -> Result<bool, &'static str> {
    let keyset = std::fs::read(&settings.keyset).map_err(|_| "the key set does not read")?;
    let (keyset, _) = DirectoryKeySet::parse(&keyset).map_err(|_| "the key set does not parse")?;
    Ok(keyset.independent_count < umbra_core::directory::AUTHORITY_FLOOR)
}

/// The reports of one relay in one epoch.
struct Tally {
    /// The reports that name the relay.
    reports: u16,
    /// The chain of the last of them.
    chain: [[u8; 32]; 3],
    /// Whether the fault rate of the epoch ran.
    is_done: bool,
}

/// The reports of each relay in each epoch.
type Counts = BTreeMap<(u64, [u8; 32]), Tally>;

/// Counts one report under each relay that it names.
fn count_report(counts: &mut Counts, report: &LinkFaultReport) {
    let floor = (unix_now() / EPOCH_SECONDS).saturating_sub(2);
    counts.retain(|(epoch, _), _| *epoch >= floor);
    for relay in report.hops {
        let held = counts.entry((report.epoch, relay)).or_insert(Tally {
            reports: 0,
            chain: report.hops,
            is_done: false,
        });
        held.reports = held.reports.saturating_add(1);
        held.chain = report.hops;
    }
}

/// Runs the fault rate of each ended epoch once its shares exist
/// (`REL-195`): a relay that `FAULT_MIN_REPORTS` reports name, whose
/// reports over its noised chain count reach `RELAY_FAULT_RATE`, gets an
/// isolation query (`REL-080`, `REL-112`).
fn evaluate(settings: &Arc<Settings>, key: &Arc<SigningKey>, counts: &mut Counts) {
    let now = unix_now();
    for ((epoch, relay), tally) in counts.iter_mut() {
        let ended = epoch
            .saturating_add(1)
            .saturating_mul(EPOCH_SECONDS)
            .saturating_add(SHARE_SETTLE);
        if tally.is_done || now < ended {
            continue;
        }
        tally.is_done = true;
        if tally.reports < FAULT_MIN_REPORTS {
            continue;
        }
        let (settings, key, chain) = (Arc::clone(settings), Arc::clone(key), tally.chain);
        let (epoch, relay, reports) = (*epoch, *relay, tally.reports);
        tokio::spawn(async move {
            let Ok(set) = relay_set(&settings) else {
                return;
            };
            let Some(listed) = set
                .relays
                .iter()
                .find(|listed| listed.candidate.relay_id == relay)
            else {
                return;
            };
            let Some(chains) = stats::chain_count(&settings, listed, epoch).await else {
                println!("no chain count for {} in epoch {epoch}", to_hex(&relay));
                return;
            };
            // A noised count of 0 gives the largest rate, and REL-112 is the
            // floor that holds then.
            let rate = f64::from(reports) / chains.max(1) as f64;
            println!(
                "fault rate {} epoch={epoch} reports={reports} chains={chains} rate={rate:.3}",
                to_hex(&relay)
            );
            if rate < RELAY_FAULT_RATE {
                return;
            }
            println!("isolation query on {}", to_hex(&relay));
            match isolation::isolate(&settings, &key, chain).await {
                Ok((verdict, epoch)) => isolation::record(&settings, &chain, &verdict, epoch),
                Err(cause) => eprintln!("the isolation query failed: {cause}"),
            }
        });
    }
}

/// One run: the queue, and each report until the run ends.
async fn run_once(
    settings: &Arc<Settings>,
    key: &Arc<SigningKey>,
    counts: &mut Counts,
    report_sk: &Secret<32>,
) -> Result<(), &'static str> {
    let (guard, dial, chain) = relays_of(settings)?;
    let tls = tls_of(settings)?;
    let mut node = ClientNode::with_relays(
        guard,
        chain,
        RootIdentity::new(Secret::new(settings.root_seed)),
    );
    node.set_bootstrap(is_provisional(settings)?);
    let (commands, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, mut updates) = mpsc::unbounded_channel();
    // A queue of an earlier run continues, and its address stays in the
    // manifest.
    let restored = std::fs::read(&settings.state)
        .ok()
        .and_then(|state| node.restore_report_queue(&state).ok())
        .is_some();
    if !restored {
        let _ = commands.send(Command::MakeReportQueue);
    }
    let store = Box::new(QueueStore {
        state: settings.state.clone(),
    });
    let run = tokio::spawn(run_client(
        node,
        dial,
        tls,
        runtime_commands,
        runtime_updates,
        store,
        None,
    ));
    let report_pk = seal::public_of(report_sk);
    let mut clock = tokio::time::interval(EVALUATE_EVERY);
    loop {
        let update = tokio::select! {
            update = updates.recv() => update,
            _ = clock.tick() => {
                evaluate(settings, key, counts);
                continue;
            }
        };
        let Some(update) = update else {
            break;
        };
        match update {
            Update::Online => println!("authority online, queue restored={restored}"),
            Update::ReportQueue { address } => {
                let held = [address.as_slice(), &report_pk].concat();
                std::fs::write(&settings.queue, held)
                    .map_err(|_| "the queue file does not write")?;
                println!("report queue made, written to {}", settings.queue.display());
            }
            Update::LinkFault(sealed) => match LinkFaultReport::open(report_sk, &sealed) {
                Ok(report) => {
                    println!(
                        "report epoch={} hops={},{},{} loops_sent={} loops_lost={}",
                        report.epoch,
                        to_hex(&report.hops[0]),
                        to_hex(&report.hops[1]),
                        to_hex(&report.hops[2]),
                        report.loops_sent,
                        report.loops_lost,
                    );
                    // REL-170: a report of the current epoch or the one
                    // before it counts, and each other goes.
                    let epoch = unix_now() / EPOCH_SECONDS;
                    if report.epoch == epoch || report.epoch.saturating_add(1) == epoch {
                        count_report(counts, &report);
                    }
                }
                // REL-170: a report that does not open goes.
                Err(_) => println!("a report did not open"),
            },
            Update::Offline(ended) => {
                println!("authority offline: {ended:?}");
                break;
            }
            _ => {}
        }
    }
    drop(commands);
    let _ = run.await;
    Ok(())
}

/// The three relays of a chain in hex, the ingress first.
fn read_chain(text: &str) -> Option<[[u8; 32]; 3]> {
    let relays: Vec<[u8; 32]> = text.split(',').map(hex32).collect::<Option<_>>()?;
    relays.try_into().ok()
}

/// Prints the noised chain count of one relay in one epoch (§10.8).
fn print_count(path: &str, relay: &str, epoch: &str) -> ExitCode {
    let (Some(settings), Some(relay), Ok(epoch)) =
        (read_settings(path), hex32(relay), epoch.parse::<u64>())
    else {
        eprintln!("usage: umbra-authority <settings file> count <relay> <epoch>");
        return ExitCode::from(2);
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(1);
    };
    runtime.block_on(async {
        let Ok(set) = relay_set(&settings) else {
            eprintln!("the manifest does not verify");
            return ExitCode::from(1);
        };
        let Some(listed) = set
            .relays
            .iter()
            .find(|listed| listed.candidate.relay_id == relay)
        else {
            eprintln!("the manifest names no such relay");
            return ExitCode::from(1);
        };
        match stats::chain_count(&settings, listed, epoch).await {
            Some(count) => {
                println!("chains {} epoch={epoch} noised={count}", to_hex(&relay));
                ExitCode::SUCCESS
            }
            None => {
                eprintln!(
                    "no count: an aggregator is not this program, or the relay holds no share"
                );
                ExitCode::from(1)
            }
        }
    })
}

/// The stack of the thread that reads a key. An ML-DSA-65 key needs more
/// than the 1 MiB that the main thread of Windows has.
const STACK_BYTES: usize = 16 << 20;

fn main() -> ExitCode {
    let done = std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(run_main)
        .ok()
        .and_then(|thread| thread.join().ok());
    done.unwrap_or_else(|| {
        eprintln!("the main thread stopped");
        ExitCode::from(1)
    })
}

fn run_main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (path, probe) = match arguments.as_slice() {
        [path] => (path, None),
        [path, word, relay, epoch] if word == "count" => {
            return print_count(path, relay, epoch);
        }
        [path, word, chain] if word == "probe" => match read_chain(chain) {
            Some(chain) => (path, Some(chain)),
            None => {
                eprintln!("a chain is three relay_id values in hex, with commas");
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!("usage: umbra-authority <settings file> [probe <relay>,<relay>,<relay>]");
            return ExitCode::from(2);
        }
    };
    let Some(settings) = read_settings(path) else {
        eprintln!("the settings file does not parse");
        return ExitCode::from(2);
    };
    let settings = Arc::new(settings);
    let Some(key) = authority_key(&settings, settings.index) else {
        eprintln!("the key of the authority does not read");
        return ExitCode::from(1);
    };
    let key = Arc::new(key);
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(16 << 20)
        .enable_all()
        .build()
    else {
        eprintln!("the runtime does not start");
        return ExitCode::from(1);
    };
    // REL-108: one query on the evidence of this authority.
    if let Some(chain) = probe {
        return runtime.block_on(async {
            match isolation::isolate(&settings, &key, chain).await {
                Ok((verdict, epoch)) => {
                    isolation::record(&settings, &chain, &verdict, epoch);
                    ExitCode::SUCCESS
                }
                Err(cause) => {
                    eprintln!("the isolation query failed: {cause}");
                    ExitCode::from(1)
                }
            }
        });
    }
    let report_sk = Secret::new(settings.report_seed);
    let mut counts = Counts::new();
    runtime.block_on(async {
        loop {
            if let Err(cause) = run_once(&settings, &key, &mut counts, &report_sk).await {
                eprintln!("{cause}");
            }
            tokio::time::sleep(RETRY).await;
        }
    })
}
