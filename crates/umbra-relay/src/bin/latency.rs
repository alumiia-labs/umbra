//! The propagation of a real relay population (Part 3 `NET-137`), and the
//! first bench numbers of the call proposal (`docs/design/real-time-calls.md`
//! §11, Stage 0).
//!
//! ```text
//! umbra-latency [--manifest <file>] [--keyset <file>] [--rounds <count>]
//! ```
//!
//! The manifest and the key set default to the files of `umbra-cli` in
//! `target/umbra-cli`, and to the shipped key set of the release app. The
//! manifest must verify under the key set.
//!
//! The probe builds circuits as a client does, one hop at a time, and it
//! times each `EXTEND` until its `EXTENDED`. A build cell to hop `n` passes
//! hops 1 to `n − 1`, thus the difference of two steps is the round trip of
//! one leg between two relays. The probe needs no measurer certificate, and
//! it sends no cell after the build.
//!
//! The output gives, for each relay, the round trip of a TCP connect and of
//! a one-hop build. Then it gives the leg from each ingress relay to each
//! layer 2 relay, and from each layer 2 relay to each layer 3 relay. The
//! last table sums one way of a call for two designs: a splice at layer 2
//! (four links) and a splice at layer 3 (six links). Both parties of that
//! sum sit at the place of this machine, thus the sum is a floor for two
//! parties far apart.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use umbra_core::directory::{
    bloc::BlocList,
    descriptor::RelayEntry,
    manifest::{RelayManifest, RelaySet},
    root::{Consensus, DirectoryKeySet},
};
use umbra_crypto::{handshake::nk::RelayStatic, rand_core::TryRng, secret::Secret};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, DelayClass, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::CircuitBuild,
    CIRCUIT_BUILD_TIMEOUT,
};
use umbra_relay::{measurer::Target, server::OsRng};
use umbra_transport::{link::ClientLink, native};
use umbra_wire::{
    capsule::{self, CapsuleType},
    cell::{Cell, CellCommand},
};

/// The rounds of each measurement, when the arguments name no count.
const ROUNDS: usize = 10;
/// The wait between two builds, which keeps the load on a relay low.
const PAUSE: Duration = Duration::from_millis(200);

type Failure = &'static str;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |at| at.as_secs())
}

/// The relays of a manifest that verifies under the key set, as the
/// measurer reads them.
fn listed(manifest: &Path, keyset: &Path) -> Result<Vec<Target>, Failure> {
    let manifest = std::fs::read(manifest).map_err(|_| "the manifest does not read")?;
    let keyset = std::fs::read(keyset).map_err(|_| "the key set does not read")?;
    let (keyset, _) = DirectoryKeySet::parse(&keyset).map_err(|_| "the key set does not parse")?;
    let mut consensus = Consensus::new(keyset, 0).map_err(|_| "the key set gives no consensus")?;

    let parsed = RelayManifest::parse(&manifest).map_err(|_| "the manifest does not parse")?;
    RelaySet::accept(&mut consensus, &parsed, &BlocList::v1(), unix_now())
        .map_err(|_| "the manifest does not verify under the key set")?;

    let mut targets = Vec::with_capacity(parsed.entries.len());
    for proven in &parsed.entries {
        let entry = RelayEntry::parse(proven.entry).map_err(|_| "an entry does not parse")?;
        let layer = if entry.ingress() { 1 } else { entry.layer() };
        targets.push(Target::of_descriptor(&entry.descriptor, layer));
    }
    Ok(targets)
}

struct Arguments {
    manifest: PathBuf,
    keyset: PathBuf,
    rounds: usize,
}

fn arguments() -> Result<Arguments, Failure> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let held = repository.join("target/umbra-cli/keyset-held.bin");
    let mut parsed = Arguments {
        manifest: repository.join("target/umbra-cli/manifest.bin"),
        keyset: if held.exists() {
            held
        } else {
            repository.join("android/app/src/release/assets/umbra-keyset.bin")
        },
        rounds: ROUNDS,
    };

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("each flag needs a value")?;
        match flag.as_str() {
            "--manifest" => parsed.manifest = PathBuf::from(value),
            "--keyset" => parsed.keyset = PathBuf::from(value),
            "--rounds" => {
                parsed.rounds = value
                    .parse()
                    .ok()
                    .filter(|rounds| *rounds > 0)
                    .ok_or("the rounds are a count above 0")?;
            }
            _ => return Err("the flags are --manifest, --keyset, and --rounds"),
        }
    }

    Ok(parsed)
}

/// The round trip of one TCP connect, which holds no relay work.
async fn tcp_round_trip(target: &Target) -> Option<Duration> {
    let address = std::net::SocketAddr::from((target.addr_v4, target.dial.port));
    let start = Instant::now();
    let wait = Duration::from_secs(CIRCUIT_BUILD_TIMEOUT);
    let stream = tokio::time::timeout(wait, tokio::net::TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;
    let elapsed = start.elapsed();
    drop(stream);
    Some(elapsed)
}

/// Builds a circuit through `chain`, one hop at a time. The result is the
/// time of each step, from the send of its `EXTEND` to its `EXTENDED`.
async fn build(
    chain: &[&Target],
    tls: Arc<rustls::ClientConfig>,
) -> Result<Vec<Duration>, Failure> {
    let first = chain.first().ok_or("an empty chain")?;
    let mut rng = OsRng;
    let mut draw = [0u8; 16 + 4 + 8 + 32 + 16];
    rng.try_fill_bytes(&mut draw)
        .map_err(|_| "the random source failed")?;
    let take = |from: usize, len: usize| draw.get(from..from + len).unwrap_or(&[]);
    let ws_key: [u8; 16] = take(0, 16).try_into().map_err(|_| "a local fault")?;
    let mask: [u8; 4] = take(16, 4).try_into().map_err(|_| "a local fault")?;
    let session_id: [u8; 8] = take(20, 8).try_into().map_err(|_| "a local fault")?;
    let secret: [u8; 32] = take(28, 32).try_into().map_err(|_| "a local fault")?;
    let circ_id: [u8; 16] = take(60, 16).try_into().map_err(|_| "a local fault")?;

    let wait = Duration::from_secs(CIRCUIT_BUILD_TIMEOUT);
    let mut tcp = tokio::time::timeout(
        wait,
        native::TcpLink::connect(&first.dial, tls, ws_key, mask),
    )
    .await
    .map_err(|_| "the connect timed out")?
    .map_err(|_| "the connect failed")?;

    let mut buffer = vec![0u8; 40_000];
    let (mut link, used) = ClientLink::open(session_id, Secret::new(secret), &mut buffer)
        .map_err(|_| "a local fault")?;
    tcp.send(buffer.get(..used).unwrap_or(&[]))
        .await
        .map_err(|_| "the link failed")?;

    let mut circuit = CircuitBuild::new(circ_id);
    let mut steps = Vec::with_capacity(chain.len());
    for (index, target) in chain.iter().enumerate() {
        let relay = RelayStatic {
            s: target.ntor_pk,
            relay_id: target.relay_id,
        };
        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(&relay, DelayClass::Fast, &mut rng, &mut hello)
            .map_err(|_| "a local fault")?;
        let mut body = vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).map_err(|_| "a local fault")?;
        let tag = circuit.seal(&mut body).map_err(|_| "a local fault")?;
        let cell = [circ_id.as_slice(), &tag, &body].concat();
        let used = link.send(&cell, &mut buffer).map_err(|_| "a local fault")?;

        let start = Instant::now();
        tcp.send(buffer.get(..used).unwrap_or(&[]))
            .await
            .map_err(|_| "the link failed")?;
        let reply = tokio::time::timeout(wait, async {
            loop {
                let bytes = tcp.recv().await.map_err(|_| "the link closed")?;
                let Ok((CapsuleType::Cell, value, _)) = capsule::parse(&bytes) else {
                    continue;
                };
                let Ok(Some(cell)) = link.receive(value) else {
                    continue;
                };
                let (parsed, _) = Cell::parse(cell).map_err(|_| "a cell does not parse")?;
                if *parsed.circ_id != circ_id {
                    continue;
                }

                let mut body = parsed.body.to_vec();
                circuit
                    .open(parsed.tag, &mut body)
                    .map_err(|_| "a reply does not open")?;
                let (command, reply) =
                    read_cell_body(&body).map_err(|_| "a reply does not parse")?;
                if command != CellCommand::Extended {
                    return Err("the relay refused the extend");
                }
                return Ok::<Vec<u8>, Failure>(reply.to_vec());
            }
        })
        .await
        .map_err(|_| "the extend timed out")??;
        steps.push(start.elapsed());

        let ss_hop = if index == 2 {
            pending
                .finish_at_queue_relay(&reply)
                .map(|(ss_hop, _)| ss_hop)
        } else {
            pending.finish(&reply)
        }
        .map_err(|_| "a reply does not verify")?;
        circuit.push(&ss_hop).map_err(|_| "a local fault")?;
    }

    Ok(steps)
}

/// The median, the 90th percentile, and the minimum of the samples, in
/// milliseconds.
fn summary(samples: &[f64]) -> Option<(f64, f64, f64)> {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let at = |share: f64| {
        let index = ((sorted.len() as f64 - 1.0) * share).round() as usize;
        sorted.get(index).copied()
    };
    Some((at(0.5)?, at(0.9)?, *sorted.first()?))
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn show(label: &str, samples: &[f64], total: usize) {
    match summary(samples) {
        Some((median, p90, min)) => println!(
            "{label:<44} p50 {median:>7.1} ms   p90 {p90:>7.1} ms   min {min:>7.1} ms   ({}/{total})",
            samples.len()
        ),
        None => println!("{label:<44} no sample of {total}"),
    }
}

fn name(target: &Target) -> String {
    format!("{} (L{})", target.dial.host, target.layer)
}

async fn run(arguments: Arguments) -> Result<(), Failure> {
    let targets = listed(&arguments.manifest, &arguments.keyset)?;
    let tls = native::tls_config().map_err(|_| "the TLS settings failed")?;
    let rounds = arguments.rounds;
    let of_layer = |layer: u8| targets.iter().filter(move |target| target.layer == layer);

    println!("Relays of the manifest:");
    for target in &targets {
        let [a, b, c, d] = target.addr_v4;
        println!("  {:<40} {a}.{b}.{c}.{d}  AS{}", name(target), target.asn);
    }

    println!("\nThis machine to each relay:");
    let mut first_leg: BTreeMap<[u8; 32], f64> = BTreeMap::new();
    for target in &targets {
        let mut tcp = Vec::new();
        let mut hop = Vec::new();
        for _ in 0..rounds {
            if let Some(rtt) = tcp_round_trip(target).await {
                tcp.push(ms(rtt));
            }
            if let Ok(steps) = build(&[target], tls.clone()).await {
                hop.extend(steps.first().map(|step| ms(*step)));
            }
            tokio::time::sleep(PAUSE).await;
        }
        show(&format!("{} TCP connect", target.dial.host), &tcp, rounds);
        show(&format!("{} one-hop build", target.dial.host), &hop, rounds);
        if let Some((median, _, _)) = summary(&hop) {
            first_leg.insert(target.relay_id, median);
        }
    }

    println!("\nLegs between relays (step n less step n - 1 of one circuit):");
    let mut half_l2: Vec<(String, f64)> = Vec::new();
    let mut half_l3: Vec<(String, f64)> = Vec::new();
    let mut failures: BTreeMap<Failure, usize> = BTreeMap::new();
    for ingress in of_layer(1) {
        for middle in of_layer(2) {
            let mut leg = Vec::new();
            let mut whole = Vec::new();
            for _ in 0..rounds {
                match build(&[ingress, middle], tls.clone()).await {
                    Ok(steps) => {
                        if let [one, two] = steps.as_slice() {
                            leg.push(ms(*two) - ms(*one));
                            whole.push(ms(*two));
                        }
                    }
                    Err(cause) => *failures.entry(cause).or_default() += 1,
                }
                tokio::time::sleep(PAUSE).await;
            }
            show(
                &format!("{} -> {}", ingress.dial.host, middle.dial.host),
                &leg,
                rounds,
            );
            if let Some((median, _, _)) = summary(&whole) {
                half_l2.push((
                    format!("{} > {}", ingress.dial.host, middle.dial.host),
                    median,
                ));
            }

            for last in of_layer(3) {
                let mut leg = Vec::new();
                let mut whole = Vec::new();
                for _ in 0..rounds {
                    match build(&[ingress, middle, last], tls.clone()).await {
                        Ok(steps) => {
                            if let [_, two, three] = steps.as_slice() {
                                leg.push(ms(*three) - ms(*two));
                                whole.push(ms(*three));
                            }
                        }
                        Err(cause) => *failures.entry(cause).or_default() += 1,
                    }
                    tokio::time::sleep(PAUSE).await;
                }
                show(
                    &format!(
                        "  {} -> {} -> {}",
                        ingress.dial.host, middle.dial.host, last.dial.host
                    ),
                    &leg,
                    rounds,
                );
                if let Some((median, _, _)) = summary(&whole) {
                    half_l3.push((
                        format!(
                            "{} > {} > {}",
                            ingress.dial.host, middle.dial.host, last.dial.host
                        ),
                        median,
                    ));
                }
            }
        }
    }

    for (cause, count) in &failures {
        println!("  failed builds: {count} x {cause}");
    }

    // One way of a call is two halves, each half one way of its chain,
    // thus one round trip of a half. Both parties sit here.
    println!("\nOne way of a call, both parties at this machine, median of the build:");
    for (chain, median) in &half_l2 {
        println!("  splice at layer 2, {chain:<52} {median:>7.1} ms");
    }
    for (chain, median) in &half_l3 {
        println!("  splice at layer 3, {chain:<52} {median:>7.1} ms");
    }
    if first_leg.is_empty() {
        println!("  no relay took a one-hop build");
    }

    Ok(())
}

fn main() -> ExitCode {
    let parsed = match arguments() {
        Ok(parsed) => parsed,
        Err(cause) => {
            eprintln!("umbra-latency: {cause}");
            return ExitCode::from(2);
        }
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(16 << 20)
        .build();
    let Ok(runtime) = runtime else {
        eprintln!("umbra-latency: the runtime does not start");
        return ExitCode::from(1);
    };

    match runtime.block_on(run(parsed)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(cause) => {
            eprintln!("umbra-latency: {cause}");
            ExitCode::from(1)
        }
    }
}
