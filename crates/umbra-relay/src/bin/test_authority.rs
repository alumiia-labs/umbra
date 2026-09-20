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
//! ```
//!
//! The `relay` line repeats. Each relay is of the first root of its network,
//! thus the layer function of `REL-060` takes the genesis root.

#![forbid(unsafe_code)]

use std::{path::Path, process::ExitCode};

use umbra_core::directory::{
    authority::{entry_of, keyset_bytes, sign_manifest, Listing, GENESIS_ROOT},
    bloc::BlocList,
    descriptor::RelayEntry,
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
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match line.split_once('=') {
            Some(("seed", value)) => seed = hex32(value),
            Some(("relay", value)) => {
                relays.push(read_relay(value).ok_or("a relay line does not parse")?);
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

    let mut entries = Vec::with_capacity(relays.len());
    for relay in &relays {
        let listing = Listing {
            descriptor: &relay.descriptor,
            operator_id: relay.operator_id,
            class: relay.class,
            is_ingress: relay.is_ingress,
        };
        let entry =
            entry_of(&listing, &GENESIS_ROOT, 0).map_err(|_| "a descriptor does not verify")?;
        let read = RelayEntry::parse(&entry).map_err(|_| "an entry does not verify")?;
        println!(
            "relay {} layer={} host={}",
            to_hex(&read.descriptor.relay_id),
            read.layer(),
            read.descriptor.host_str(),
        );
        entries.push(entry);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "the clock is before 1970")?
        .as_secs();
    let epoch = now / EPOCH_SECONDS;
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
    let keyset = keyset_bytes(&keys, KEYSET_EPOCH).map_err(|_| "the key set does not build")?;
    std::fs::write(out.join("manifest.bin"), &manifest)
        .and_then(|()| std::fs::write(out.join("keyset.bin"), &keyset))
        .map_err(|_| "the output directory does not take a file")?;
    println!(
        "epoch={epoch} manifest={} bytes keyset={} bytes",
        manifest.len(),
        keyset.len()
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
