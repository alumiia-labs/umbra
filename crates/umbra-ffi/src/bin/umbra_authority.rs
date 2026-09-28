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

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, path::PathBuf, process::ExitCode, time::Duration};

use tokio::sync::mpsc;
use umbra_core::{
    directory::{
        bloc::BlocList,
        manifest::{RelayManifest, RelaySet},
        report::LinkFaultReport,
        root::{Consensus, DirectoryKeySet},
    },
    session::node::{ClientNode, ContactId, RelayInfo, StateChange},
};
use umbra_crypto::{handshake::nk::RelayStatic, hierarchy::RootIdentity, seal, secret::Secret};
use umbra_ffi::runtime::{run_client, Command, Persist, Update};
use umbra_transport::{native, Dial};

/// The wait before a run that ended starts again.
const RETRY: Duration = Duration::from_secs(5);

struct Settings {
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

/// The relays of the manifest that the key set verifies: the first ingress
/// relay to dial, and each relay of a chain.
fn relays_of(settings: &Settings) -> Result<(RelayInfo, Dial, Vec<RelayInfo>), &'static str> {
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
    let info = |relay: &umbra_core::directory::manifest::ListedRelay| RelayInfo {
        candidate: relay.candidate,
        key: RelayStatic {
            s: relay.ntor_pk,
            relay_id: relay.candidate.relay_id,
        },
    };
    let guard = set
        .relays
        .iter()
        .find(|relay| relay.candidate.ingress && relay.addr_v4 != [0; 4])
        .ok_or("the manifest holds no ingress relay")?;
    let dial = Dial {
        host: guard.host.clone(),
        addr_v4: Some(guard.addr_v4),
        addr_v6: None,
        port: guard.port,
    };
    let chain = set
        .relays
        .iter()
        .filter(|relay| !relay.candidate.ingress)
        .map(info)
        .collect();
    Ok((info(guard), dial, chain))
}

/// One run: the queue, and each report until the run ends.
async fn run_once(settings: &Settings, report_sk: &Secret<32>) -> Result<(), &'static str> {
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
                Ok(report) => println!(
                    "report epoch={} hops={},{},{} loops_sent={} loops_lost={}",
                    report.epoch,
                    to_hex(&report.hops[0]),
                    to_hex(&report.hops[1]),
                    to_hex(&report.hops[2]),
                    report.loops_sent,
                    report.loops_lost,
                ),
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

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [path] = arguments.as_slice() else {
        eprintln!("usage: umbra-authority <settings file>");
        return ExitCode::from(2);
    };
    let Some(settings) = read_settings(path) else {
        eprintln!("the settings file does not parse");
        return ExitCode::from(2);
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(16 << 20)
        .enable_all()
        .build()
    else {
        eprintln!("the runtime does not start");
        return ExitCode::from(1);
    };
    let report_sk = Secret::new(settings.report_seed);
    runtime.block_on(async {
        loop {
            if let Err(cause) = run_once(&settings, &report_sk).await {
                eprintln!("{cause}");
            }
            tokio::time::sleep(RETRY).await;
        }
    })
}
