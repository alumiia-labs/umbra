//! The measurer of Part 10 §10.3: it runs the class test of each relay of
//! a relay set, and it writes one result line for each test. The signer
//! reads those lines and lists each relay at the class that they verify
//! (§10.2).
//!
//! ```text
//! umbra-measurer keygen <key directory>
//! umbra-measurer run <settings file>
//! umbra-measurer test <settings file> <relay_id in hex> <class 0 to 3>
//! ```
//!
//! `keygen` writes `measurer.seed`, readable by its owner alone, and
//! `measurer.pub`, the ML-DSA-65 public key in hex. `umbra-signer
//! measurer-cert` issues the `MeasurerCert` of that key (`REL-070`).
//!
//! `run` tests each relay one time. A timer runs it one time in each
//! `MEASURE_INTERVAL` (`REL-097`). `test` tests one relay at one class.
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! key=/var/lib/umbra-measurer/measurer.seed
//! cert=/var/lib/umbra-measurer/measurer.cert
//! manifest=/var/www/umbra/.well-known/umbra/manifest
//! keyset=/var/www/umbra/.well-known/umbra/keyset.bin
//! unlisted=<descriptor file>,<ingress|middle|exit>
//! results=/var/lib/umbra-measurer/results
//! capacity=500          # the rate that this measurer sends, in Mbit/s
//! slot=30               # the length of a slot, in seconds
//! sockets=4             # the connections of one test
//! ```
//!
//! The relays are those of the manifest, which must verify under the key
//! set. An `unlisted` line names a relay that the manifest does not list,
//! as a relay that failed the test of C0: the measurer tests it too, thus
//! a later pass lists it again. The line repeats.
//!
//! `capacity` bounds the tests. A test of a class needs 2.25 times the
//! rate of the class. The measurer tests each relay at the highest class
//! that its capacity holds, or at the class that the relay declares when
//! that one is lower. It puts as many relays in one slot as its capacity
//! holds at that class.
//!
//! The relays of one cluster go in one slot (`REL-099`): one ASN, one IPv4
//! /24, one IPv6 /48, or one family. A cluster above `CLUSTER_FULL` relays
//! goes in samples of `CLUSTER_SAMPLE`, in an order from the generator of
//! the operating system (`REL-100`). A measurer whose capacity holds fewer
//! relays than the slot needs says so on the standard error, and its
//! slots hold what the capacity permits.
//!
//! Each test appends one line to the results file and prints it:
//!
//! ```text
//! <relay_id in hex> <class> <pass|fail> <epoch>
//! ```
//!
//! A relay that opened no measurement session gets no line, and the
//! command ends with status 1. A relay gives a rejected `MEAS_OPEN` no
//! sign (`REL-069`), thus the measurer cannot tell a relay that refused it
//! from a certificate that is void. A void certificate must demote no
//! relay.
//!
//! Three more lines serve a test network on one machine. `trust` names
//! the root that the relays chain to. `host_alias=10.0.2.2` makes the
//! measurer dial `127.0.0.1` in the place of that address. `scale=1000`
//! divides each rate by 1 000. No deployment sets one of the three.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use umbra_core::directory::{
    bloc::BlocList,
    descriptor::RelayEntry,
    manifest::{RelayManifest, RelaySet},
    measure::{ClassResult, SLOT_SECONDS},
    root::{Consensus, DirectoryKeySet},
    EPOCH_SECONDS,
};
use umbra_crypto::{rand_core::TryRng, secret::Secret, sign::SigningKey, zeroize::Zeroizing};
use umbra_relay::{
    measurer::{highest_class, measure, slot_width, slots, MeasureError, Plan, Target, SOCKETS},
    server::OsRng,
};
use umbra_transport::native;

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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |at| at.as_secs())
}

fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<(), &'static str> {
    let mut options = std::fs::OpenOptions::new();
    // A key directory that holds a key keeps it.
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;

    let mut file = options
        .open(path)
        .map_err(|_| "a key file exists already, or its directory does not open")?;

    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "a key file does not take its bytes")
}

fn keygen(dir: &Path) -> Result<(), &'static str> {
    std::fs::create_dir_all(dir).map_err(|_| "the key directory does not open")?;

    let mut seed = Secret::<32>::zeroed();
    OsRng
        .try_fill_bytes(seed.expose_mut())
        .map_err(|_| "no random value")?;

    // `Zeroizing` wipes the hex form of the seed after its file took it.
    let text = Zeroizing::new(to_hex(seed.expose()));
    write_new(&dir.join("measurer.seed"), text.as_bytes(), true)?;

    let public = SigningKey::from_seed(seed).verifying_key().to_bytes();
    write_new(&dir.join("measurer.pub"), to_hex(&public).as_bytes(), false)?;

    println!("measurer.pub={} bytes", public.len());
    Ok(())
}

/// The settings of a run.
struct Settings {
    key: Arc<SigningKey>,
    cert: Vec<u8>,
    targets: Vec<Target>,
    results: PathBuf,
    capacity_bits: u64,
    slot: Duration,
    sockets: usize,
    scale: u64,
    tls: Arc<rustls::ClientConfig>,
}

fn layer_of_place(place: &str) -> Option<u8> {
    match place {
        "ingress" => Some(1),
        "middle" => Some(2),
        "exit" => Some(3),
        _ => None,
    }
}

/// The relays of the manifest at `manifest`, which must verify under the
/// key set at `keyset` and hold the whole relay set.
fn listed(manifest: &Path, keyset: &Path) -> Result<Vec<Target>, &'static str> {
    let manifest = std::fs::read(manifest).map_err(|_| "the manifest does not read")?;
    let keyset = std::fs::read(keyset).map_err(|_| "the key set does not read")?;
    let (keyset, _) = DirectoryKeySet::parse(&keyset).map_err(|_| "the key set does not parse")?;
    let mut consensus = Consensus::new(keyset, 0).map_err(|_| "the key set gives no consensus")?;

    let parsed = RelayManifest::parse(&manifest).map_err(|_| "the manifest does not parse")?;
    let set = RelaySet::accept(&mut consensus, &parsed, &BlocList::v1(), unix_now())
        .map_err(|_| "the manifest does not verify under the key set")?;

    if !set.is_whole {
        return Err("the manifest holds a part of the relay set");
    }

    let mut targets = Vec::with_capacity(parsed.entries.len());
    for proven in &parsed.entries {
        let entry = RelayEntry::parse(proven.entry).map_err(|_| "an entry does not parse")?;
        let layer = if entry.ingress() { 1 } else { entry.layer() };
        targets.push(Target::of_descriptor(&entry.descriptor, layer));
    }
    Ok(targets)
}

fn read_settings(path: &str) -> Result<Settings, &'static str> {
    let text = std::fs::read_to_string(path).map_err(|_| "the settings file does not read")?;
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    let mut unlisted = Vec::new();

    for line in text.lines() {
        // A comment follows a value on its line, as in the form above.
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        match line.split_once('=') {
            Some(("unlisted", value)) => {
                let (file, place) = value
                    .split_once(',')
                    .ok_or("an unlisted line does not parse")?;
                let layer = layer_of_place(place).ok_or("an unlisted line does not parse")?;
                let descriptor =
                    std::fs::read(file).map_err(|_| "a descriptor file does not read")?;
                unlisted.push(
                    Target::of(&descriptor, layer).ok_or("a descriptor file does not parse")?,
                );
            }
            Some((
                name @ ("key" | "cert" | "manifest" | "keyset" | "results" | "capacity" | "slot"
                | "sockets" | "trust" | "host_alias" | "scale"),
                value,
            )) => {
                values.insert(name, value.trim());
            }
            _ => return Err("the settings file does not parse"),
        }
    }

    let need = |name: &'static str, cause: &'static str| values.get(name).copied().ok_or(cause);

    let seed = Zeroizing::new(
        std::fs::read_to_string(need(
            "key",
            "the settings file needs a line: key=<seed file>",
        )?)
        .map_err(|_| "the seed file does not read")?,
    );
    let seed = Zeroizing::new(hex32(seed.trim()).ok_or("the seed file does not parse")?);
    let key = Arc::new(SigningKey::from_seed(Secret::new(*seed)));

    let cert = std::fs::read(need(
        "cert",
        "the settings file needs a line: cert=<certificate file>",
    )?)
    .map_err(|_| "the certificate file does not read")?;

    let mut targets = match (values.get("manifest"), values.get("keyset")) {
        (Some(manifest), Some(keyset)) => listed(Path::new(manifest), Path::new(keyset))?,
        (None, None) => Vec::new(),
        _ => return Err("the manifest line and the keyset line go together"),
    };

    for target in unlisted {
        if !targets.iter().any(|held| held.relay_id == target.relay_id) {
            targets.push(target);
        }
    }

    if let Some(alias) = values.get("host_alias") {
        let alias = alias
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "the host_alias line does not parse")?
            .octets();
        for target in &mut targets {
            if target.dial.addr_v4 == Some(alias) {
                target.dial.addr_v4 = Some([127, 0, 0, 1]);
            }
        }
    }

    let number = |name: &str, default: u64| match values.get(name) {
        Some(value) => value.parse::<u64>().map_err(|_| "a number does not parse"),
        None => Ok(default),
    };

    let capacity = number("capacity", 0)?;
    if capacity == 0 {
        return Err("the settings file needs a line: capacity=<Mbit/s>");
    }

    let tls = match values.get("trust") {
        Some(root) => native::tls_config_with_root_file(root),
        None => native::tls_config(),
    }
    .map_err(|_| "the TLS configuration does not build")?;

    Ok(Settings {
        key,
        cert,
        targets,
        results: PathBuf::from(need(
            "results",
            "the settings file needs a line: results=<results file>",
        )?),
        capacity_bits: capacity.saturating_mul(1_000_000),
        slot: Duration::from_secs(number("slot", SLOT_SECONDS)?.max(1)),
        sockets: usize::try_from(number("sockets", SOCKETS as u64)?).unwrap_or(SOCKETS),
        scale: number("scale", 1)?.max(1),
        tls,
    })
}

/// Appends one result to the results file in one write, and prints it.
fn record(results: &Path, result: &ClassResult, echoed_bits: u64) -> Result<(), &'static str> {
    let line = result.line();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(results)
        .map_err(|_| "the results file does not open")?;

    file.write_all(format!("{line}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "the results file does not take a line")?;

    println!("{line}");

    eprintln!(
        "relay {} echoed {} kbit/s",
        to_hex(&result.relay_id),
        echoed_bits / 1_000
    );
    Ok(())
}

/// Runs one slot: the test of each relay of `slot` at once, each at its
/// class. Returns whether each relay gave a result.
async fn run_slot(settings: &Settings, slot: &[(Target, u8)]) -> Result<bool, &'static str> {
    let epoch = unix_now() / EPOCH_SECONDS;
    let mut tests = tokio::task::JoinSet::new();

    for (target, class) in slot {
        let plan = Plan::of(*class, settings.slot, settings.sockets, settings.scale)
            .ok_or("no such class")?;
        let (target, class) = (target.clone(), *class);
        let cert = settings.cert.clone();
        let tls = settings.tls.clone();
        let key = settings.key.clone();

        tests.spawn(async move {
            let outcome = measure(&target, &cert, &key, plan, tls).await;
            (target.relay_id, class, outcome)
        });
    }

    let mut is_whole = true;
    while let Some(done) = tests.join_next().await {
        let (relay_id, class, outcome) = done.map_err(|_| "a test stopped")?;
        match outcome {
            Ok(outcome) => record(
                &settings.results,
                &ClassResult {
                    relay_id,
                    class,
                    passed: outcome.passed,
                    epoch,
                },
                outcome.echoed_bits,
            )?,
            Err(cause) => {
                is_whole = false;
                let cause = match cause {
                    MeasureError::Connect => "no connection",
                    MeasureError::Build => "no answer to the build cell",
                    MeasureError::NoSession => "no measurement session",
                    MeasureError::Local => "a local fault",
                };
                eprintln!("relay {} gave no result: {cause}", to_hex(&relay_id));
            }
        }
    }
    Ok(is_whole)
}

async fn run(settings: Settings, only: Option<([u8; 32], u8)>) -> Result<bool, &'static str> {
    // The scale of a test network divides each rate, thus the capacity
    // holds that many times the tests.
    let capacity = settings.capacity_bits.saturating_mul(settings.scale);

    if let Some((relay_id, class)) = only {
        let target = settings
            .targets
            .iter()
            .find(|target| target.relay_id == relay_id)
            .ok_or("the manifest and the unlisted lines name no such relay")?
            .clone();

        if slot_width(capacity, class) == 0 {
            return Err("the capacity is below the test of that class");
        }

        return run_slot(&settings, &[(target, class)]).await;
    }

    let highest = highest_class(capacity).ok_or("the capacity is below the test of C0")?;
    let width = slot_width(capacity, highest);
    let (slots, is_narrow) = slots(&settings.targets, width, &mut OsRng);

    if is_narrow {
        eprintln!(
            "the capacity holds {width} relays in one slot at C{highest}, and a cluster needs \
             more: its relays go in more slots than REL-099 and REL-101 give"
        );
    }

    let mut is_whole = true;
    for slot in slots {
        let slot: Vec<(Target, u8)> = slot
            .into_iter()
            .filter_map(|index| settings.targets.get(index).cloned())
            .map(|target| {
                let class = target.capacity_class.min(highest);
                (target, class)
            })
            .collect();

        is_whole &= run_slot(&settings, &slot).await?;

        // The relays of the next slot share hardware with those of this
        // one, and their links drain first.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(is_whole)
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
    let only = match arguments.as_slice() {
        [command, dir] if command == "keygen" => {
            return match keygen(Path::new(dir)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(cause) => {
                    eprintln!("{cause}");
                    ExitCode::from(1)
                }
            };
        }
        [command, _] if command == "run" => None,
        [command, _, relay, class] if command == "test" => {
            let (Some(relay), Ok(class @ 0..=3)) = (hex32(relay), class.parse::<u8>()) else {
                eprintln!("the relay is 64 hex characters, and the class is 0 to 3");
                return ExitCode::from(2);
            };
            Some((relay, class))
        }
        _ => {
            eprintln!(
                "usage: umbra-measurer keygen <key directory>\n       \
                 umbra-measurer run <settings file>\n       \
                 umbra-measurer test <settings file> <relay_id in hex> <class 0 to 3>"
            );
            return ExitCode::from(2);
        }
    };

    let Some(path) = arguments.get(1) else {
        return ExitCode::from(2);
    };

    let settings = match read_settings(path) {
        Ok(settings) => settings,
        Err(cause) => {
            eprintln!("{cause}");
            return ExitCode::from(1);
        }
    };

    // An ML-DSA-65 signature needs more stack than a worker thread has by
    // default.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(16 << 20)
        .build();

    let Ok(runtime) = runtime else {
        eprintln!("the runtime does not start");
        return ExitCode::from(1);
    };

    match runtime.block_on(run(settings, only)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(cause) => {
            eprintln!("{cause}");
            ExitCode::from(1)
        }
    }
}
