//! The seven directory authorities of a test network, in one process. It
//! reads the signed descriptors of the relays, and it writes a manifest and
//! the key set that a client and a relay verify it under (Part 10 §10.5).
//!
//! The seed of the seven keys is in the settings file, thus the signatures
//! of this program protect nothing. A real authority is one of seven legal
//! persons, and it holds one key.
//!
//! ```text
//! umbra-test-authority <settings file> <output directory>
//! ```
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! seed=<64 hex characters>
//! relay=<descriptor file>,<operator name>,<class 0 to 3>,<ingress|chain>
//! report_queue=<authority index>,<queue file>
//! verdicts=<file of verdicts>
//! ```
//!
//! The `relay` line repeats. Each relay is of the first root of its network,
//! thus the layer function of `REL-060` takes the genesis root.
//!
//! A `report_queue` line names the file that `umbra-authority` writes: the
//! `QueueAddress` and the X25519 key of the report queue of that authority.
//! The manifest then carries a `ReportQueue` that the key of that authority
//! signs (Part 10 `REL-166`, `REL-167`). A file that does not exist yet
//! gives no queue.
//!
//! A `verdicts` line names the file of the isolation queries of
//! `umbra-authority`. A relay of an `expel <relay_id>` line leaves the
//! manifest (`REL-083`), and a link of a `link <relay_id> <relay_id>
//! <epoch>` line takes a `LinkRemoval` that the seven keys sign, for
//! `LINK_REMOVAL_EPOCHS` after that epoch (`REL-183`). The dense-subgraph
//! search peels the removed links of their life, and each relay that it
//! peels leaves the manifest too (`REL-188`).

#![forbid(unsafe_code)]

use std::{path::Path, process::ExitCode};

use umbra_core::directory::{
    authority::{entry_of, keyset_bytes, sign_manifest, Admission, Listing, GENESIS_ROOT},
    bloc::BlocList,
    descriptor::RelayEntry,
    manifest::RelayManifest,
    removal::{peel, LinkRemoval, LINK_REMOVAL_EPOCHS},
    report::{ReportQueue, QUEUE_ADDRESS_LEN},
    AUTHORITY_COUNT, EPOCH_SECONDS,
};
use umbra_crypto::{hash::sha3_256, secret::Secret, sign::SigningKey};
use umbra_relay::server::OsRng;

/// The epoch of the key set of a test network.
const KEYSET_EPOCH: u64 = 1;

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

/// One `relay` line.
struct Admitted {
    descriptor: Vec<u8>,
    operator_id: [u8; 32],
    class: u8,
    is_ingress: bool,
}

fn read_relay(value: &str) -> Option<Admitted> {
    let [file, operator, class, role]: [&str; 4] =
        value.split(',').collect::<Vec<_>>().try_into().ok()?;
    Some(Admitted {
        descriptor: std::fs::read(file).ok()?,
        // An opaque value for each beneficial control (`REL-128`).
        operator_id: sha3_256(&[b"umbra/test/operator", operator.as_bytes()]),
        class: class.parse().ok()?,
        is_ingress: match role {
            "ingress" => true,
            "chain" => false,
            _ => return None,
        },
    })
}

fn run(settings: &str, out: &Path) -> Result<(), &'static str> {
    let text = std::fs::read_to_string(settings).map_err(|_| "the settings file does not read")?;
    let mut seed = None;
    let mut relays = Vec::new();
    let mut report_queues = Vec::new();
    let mut expelled: Vec<[u8; 32]> = Vec::new();
    let mut removed: Vec<LinkRemoval> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match line.split_once('=') {
            Some(("seed", value)) => seed = hex32(value),
            Some(("relay", value)) => {
                relays.push(read_relay(value).ok_or("a relay line does not parse")?);
            }
            Some(("verdicts", value)) => {
                // A file that does not exist yet holds no verdict.
                let held = std::fs::read_to_string(value).unwrap_or_default();
                expelled.extend(
                    held.lines()
                        .filter_map(|line| line.strip_prefix("expel "))
                        .filter_map(|relay| hex32(relay.trim())),
                );
                removed.extend(held.lines().filter_map(|line| {
                    let mut words = line.strip_prefix("link ")?.split_whitespace();
                    let (one, other) = (hex32(words.next()?)?, hex32(words.next()?)?);
                    let epoch = words.next()?.parse().ok()?;
                    Some(LinkRemoval::of(epoch, one, other))
                }));
            }
            Some(("report_queue", value)) => {
                let (index, file) = value
                    .split_once(',')
                    .ok_or("a report_queue line does not parse")?;
                let index: u8 = index
                    .parse()
                    .map_err(|_| "a report_queue line does not parse")?;
                report_queues.push((index, file.to_owned()));
            }
            _ => return Err("the settings file does not parse"),
        }
    }
    let seed = seed.ok_or("the settings file needs a line: seed=<64 hex characters>")?;
    let keys: Vec<SigningKey> = (0..AUTHORITY_COUNT)
        .map(|index| {
            let index = u8::try_from(index).unwrap_or(u8::MAX);
            SigningKey::from_seed(Secret::new(sha3_256(&[
                b"umbra/test/authority",
                &seed,
                &[index],
            ])))
        })
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the clock is before 1970")?
        .as_secs();
    let epoch = now / EPOCH_SECONDS;
    // REL-188: the dense-subgraph search over the removed links of their
    // life expels each relay that it peels.
    let live: Vec<LinkRemoval> = removed
        .iter()
        .filter(|removal| removal.epoch <= epoch && removal.epoch + LINK_REMOVAL_EPOCHS >= epoch)
        .copied()
        .collect();
    for relay in peel(&live) {
        println!("relay {} expelled by the link-fault search", to_hex(&relay));
        expelled.push(relay);
    }

    let mut entries = Vec::with_capacity(relays.len());
    for relay in &relays {
        let listing = Listing {
            descriptor: &relay.descriptor,
            operator_id: relay.operator_id,
            class: relay.class,
            is_ingress: relay.is_ingress,
        };
        let entry = entry_of(
            &listing,
            Admission::Placed {
                root: GENESIS_ROOT,
                epoch: 0,
            },
        )
        .map_err(|_| "a descriptor does not verify, or its class is above the declared one")?;
        let read = RelayEntry::parse(&entry).map_err(|_| "an entry does not verify")?;
        if expelled.contains(&read.descriptor.relay_id) {
            println!("relay {} expelled", to_hex(&read.descriptor.relay_id));
            continue;
        }
        println!(
            "relay {} layer={} host={}",
            to_hex(&read.descriptor.relay_id),
            read.layer(),
            read.descriptor.host_str(),
        );
        entries.push(entry);
    }
    let manifest = sign_manifest(
        &keys,
        &[0, 1, 2, 3, 4, 5, 6],
        KEYSET_EPOCH,
        epoch,
        entries,
        &BlocList::v1(),
        &mut OsRng,
    )
    .map_err(|_| "the manifest does not build")?;
    // REL-167: the report queue of each authority that wrote one.
    let mut signed_queues = Vec::new();
    for (index, file) in &report_queues {
        let Ok(held) = std::fs::read(file) else {
            continue;
        };
        let (address, report_pk) = held
            .split_at_checked(QUEUE_ADDRESS_LEN)
            .ok_or("a report queue file does not parse")?;
        let queue = ReportQueue {
            authority_index: *index,
            epoch,
            address: address
                .try_into()
                .map_err(|_| "a report queue file does not parse")?,
            report_pk: report_pk
                .try_into()
                .map_err(|_| "a report queue file does not parse")?,
        };
        let key = keys
            .get(usize::from(*index))
            .ok_or("no authority of that index")?;
        signed_queues.push(
            queue
                .sign(key, &mut OsRng)
                .map_err(|_| "a report queue does not sign")?,
        );
    }
    // REL-183: each removed link of its life, under each key. One link
    // keeps its newest removal, thus a renewed removal stays in force.
    removed.sort_by(|one, other| {
        (one.relay_a, one.relay_b, other.epoch).cmp(&(other.relay_a, other.relay_b, one.epoch))
    });
    removed.dedup_by(|one, other| one.relay_a == other.relay_a && one.relay_b == other.relay_b);
    let signers: Vec<(u8, &SigningKey)> = (0u8..).zip(keys.iter()).collect();
    let mut signed_removals = Vec::new();
    for removal in removed
        .iter()
        .filter(|removal| removal.epoch <= epoch && removal.epoch + LINK_REMOVAL_EPOCHS >= epoch)
    {
        signed_removals.push(
            removal
                .sign(&signers, &mut OsRng)
                .map_err(|_| "a link removal does not sign")?,
        );
    }
    let manifest = if signed_queues.is_empty() && signed_removals.is_empty() {
        manifest
    } else {
        let mut parsed =
            RelayManifest::parse(&manifest).map_err(|_| "the manifest does not parse")?;
        parsed.queues = signed_queues.iter().map(Vec::as_slice).collect();
        parsed.removals = signed_removals.iter().map(Vec::as_slice).collect();
        parsed.encode().map_err(|_| "the manifest does not build")?
    };
    let keyset = keyset_bytes(&keys, KEYSET_EPOCH).map_err(|_| "the key set does not build")?;
    std::fs::write(out.join("manifest.bin"), &manifest)
        .and_then(|()| std::fs::write(out.join("keyset.bin"), &keyset))
        .map_err(|_| "the output directory does not take a file")?;
    println!(
        "epoch={epoch} manifest={} bytes keyset={} bytes report_queues={} removed_links={}",
        manifest.len(),
        keyset.len(),
        signed_queues.len(),
        signed_removals.len()
    );
    Ok(())
}

/// The stack of the thread that signs. An ML-DSA-65 signature needs more
/// than the 1 MiB that the main thread of Windows has.
const STACK_BYTES: usize = 16 << 20;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [settings, out] = arguments.as_slice() else {
        eprintln!("usage: umbra-test-authority <settings file> <output directory>");
        return ExitCode::from(2);
    };
    let (settings, out) = (settings.clone(), out.clone());
    let work = move || run(&settings, Path::new(&out));
    let done = std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(work)
        .ok()
        .and_then(|thread| thread.join().ok());
    match done {
        Some(Ok(())) => ExitCode::SUCCESS,
        Some(Err(cause)) => {
            eprintln!("{cause}");
            ExitCode::from(1)
        }
        None => {
            eprintln!("the signing thread stopped");
            ExitCode::from(1)
        }
    }
}
