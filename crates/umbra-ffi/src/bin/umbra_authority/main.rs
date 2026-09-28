//! The report queue of one directory authority of a test network (Part 10
//! §10.4.2): the authority holds a queue at a queue relay, as a client
//! holds one, and each link-fault report of a client arrives there sealed
//! to its key.
//!
//! ```text
//! umbra-authority <settings file>
//! ```
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! seed=<64 hex characters>                # the seed of the test authorities
//! index=0                                 # this authority in the key set
//! verdicts=target/devnet/verdicts.txt     # the verdicts, for the signer
//! manifest=target/devnet/manifest.bin     # the relays, which the key set verifies
//! keyset=tests/fixtures/devnet/keyset.bin
//! ca=tests/fixtures/tls/ca.pem            # the root that the relays chain to
//! root_seed=<64 hex characters>           # the identity of the queue client
//! report_seed=<64 hex characters>         # the X25519 key of the reports
//! state=target/devnet/report-queue.state  # the queue, across a restart
//! queue=target/devnet/report-queue.bin    # the address and the key, for the signer
//! ```
//!
//! The seeds are in the settings file, thus this program protects nothing.
//! It writes `queue` once the relay made the queue, and `umbra-test-authority`
//! signs that file into the next manifest (`REL-167`). Each report that
//! opens is one line on the standard output.
//!
//! A relay that `FAULT_MIN_REPORTS` reports of one epoch name gets an
//! isolation query on the chain of the last of them (`REL-080`, `REL-112`).
//! The rate of `REL-080` needs the chain count of each relay, the statistic
//! of §10.8, which this network does not make, thus the count of reports
//! alone starts a query here. A query on the evidence of the authority
//! (`REL-108`) runs as
//!
//! ```text
//! umbra-authority <settings file> probe <relay>,<relay>,<relay>
//! ```
//!
//! with the three `relay_id` values of a chain in hex, the ingress first. A
//! verdict is one line of the file `verdicts`.

#![forbid(unsafe_code)]

mod isolation;

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

struct Settings {
    seed: [u8; 32],
    index: u8,
    verdicts: PathBuf,
    manifest: PathBuf,
    keyset: PathBuf,
    ca: String,
    root_seed: [u8; 32],
    report_seed: [u8; 32],
    state: PathBuf,
    queue: PathBuf,
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

fn read_settings(path: &str) -> Option<Settings> {
    let text = std::fs::read_to_string(path).ok()?;
    let values: BTreeMap<&str, &str> = text
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    Some(Settings {
        seed: hex32(values.get("seed")?)?,
        index: values.get("index")?.parse().ok()?,
        verdicts: values.get("verdicts")?.into(),
        manifest: values.get("manifest")?.into(),
        keyset: values.get("keyset")?.into(),
        ca: (*values.get("ca")?).to_owned(),
        root_seed: hex32(values.get("root_seed")?)?,
        report_seed: hex32(values.get("report_seed")?)?,
        state: values.get("state")?.into(),
        queue: values.get("queue")?.into(),
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

/// The key of this authority, from the seed of the test authorities as
/// `umbra-test-authority` derives it.
fn authority_key(settings: &Settings) -> SigningKey {
    SigningKey::from_seed(Secret::new(sha3_256(&[
        b"umbra/test/authority",
        &settings.seed,
        &[settings.index],
    ])))
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

/// The relay set of the manifest, verified under the key set.
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
    RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now)
        .map_err(|_| "the manifest does not verify")
}

/// The reports of each relay in each epoch, and the chain of the last one.
type Counts = BTreeMap<(u64, [u8; 32]), (u16, [[u8; 32]; 3])>;

/// Counts one report under each relay that it names, and starts a query on
/// a relay that reaches `FAULT_MIN_REPORTS` in the epoch (`REL-080`,
/// `REL-112`).
fn count_report(settings: &Arc<Settings>, key: &Arc<SigningKey>, counts: &mut Counts, report: &LinkFaultReport) {
    let floor = (unix_now() / EPOCH_SECONDS).saturating_sub(1);
    counts.retain(|(epoch, _), _| *epoch >= floor);
    for relay in report.hops {
        let held = counts.entry((report.epoch, relay)).or_insert((0, report.hops));
        held.0 = held.0.saturating_add(1);
        held.1 = report.hops;
        if held.0 == FAULT_MIN_REPORTS {
            let (settings, key, chain) = (Arc::clone(settings), Arc::clone(key), report.hops);
            println!("isolation query on {}", to_hex(&relay));
            tokio::spawn(async move {
                match isolation::isolate(&settings, &key, chain).await {
                    Ok((verdict, epoch)) => isolation::record(&settings, &chain, &verdict, epoch),
                    Err(cause) => eprintln!("the isolation query failed: {cause}"),
                }
            });
        }
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
    let tls = native::tls_config_with_root_file(&settings.ca).map_err(|_| "the root does not read")?;
    let mut node = ClientNode::with_relays(guard, chain, RootIdentity::new(Secret::new(settings.root_seed)));
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
    ));
    let report_pk = seal::public_of(report_sk);
    while let Some(update) = updates.recv().await {
        match update {
            Update::Online => println!("authority online, queue restored={restored}"),
            Update::ReportQueue { address } => {
                let held = [address.as_slice(), &report_pk].concat();
                std::fs::write(&settings.queue, held).map_err(|_| "the queue file does not write")?;
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
                    // REL-170: a report of an older epoch goes.
                    let epoch = unix_now() / EPOCH_SECONDS;
                    if report.epoch.saturating_add(1) >= epoch {
                        count_report(settings, key, counts, &report);
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

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (path, probe) = match arguments.as_slice() {
        [path] => (path, None),
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
    let key = Arc::new(authority_key(&settings));
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
