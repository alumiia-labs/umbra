//! The signer of a directory with one operator: the seven keys of the
//! directory authorities on one machine, which signs the relay manifest of
//! each hour (Part 10 §10.5). The key set that it makes says
//! `independent_count` 1, thus each client shows the `provisional
//! directory` state (`REL-126`), and the relaxations of Part 3 `NET-340` and
//! `NET-350` hold. The keys stay off the relays.
//!
//! ```text
//! umbra-signer keygen <key directory>
//! umbra-signer sign <settings file>
//! ```
//!
//! `keygen` writes seven fresh seeds, `authority-0.seed` to
//! `authority-6.seed`, readable by their owner alone, and `keyset.bin`, the
//! key set that the app and each relay pin. It refuses a directory that
//! holds a seed already.
//!
//! `sign` reads one `key=value` pair on each line:
//!
//! ```text
//! keys=/etc/umbra-signer/keys
//! out=/var/www/umbra/.well-known/umbra
//! relay=<descriptor file>,<operator name>,<class 0 to 3>,<ingress|middle|exit>
//! report_queue=<authority index>,<queue file>
//! verdicts=<file of verdicts>
//! ```
//!
//! The `relay` line repeats. Its last field is the place of the relay: the
//! ingress role, layer 2, or layer 3. Under a provisional directory each
//! relay is of the one operator, thus the signer sets the layers
//! (`REL-198`), and a network of four chain relays gets one at layer 2 and
//! three at layer 3 in place of the draw of a hash. The signer refuses to
//! place a relay under a key set of `AUTHORITY_FLOOR` independent keys or
//! more.
//!
//! The output directory takes `manifest`, served at
//! `/.well-known/umbra/manifest`, and `keyset.bin`. Each file is written
//! under another name and renamed, thus a reader never sees half of one.
//! A timer runs `sign` each hour; a root is valid for three hours
//! (`CONSENSUS_VALIDITY`).

#![forbid(unsafe_code)]

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use umbra_core::directory::{
    authority::{entry_of, keyset_bytes_with, sign_manifest_under, Admission, Listing},
    bloc::BlocList,
    descriptor::RelayEntry,
    manifest::{RelayManifest, RelaySet},
    removal::{peel, LinkRemoval, LINK_REMOVAL_EPOCHS},
    report::{ReportQueue, QUEUE_ADDRESS_LEN},
    root::{Consensus, DirectoryKeySet},
    AUTHORITY_COUNT, AUTHORITY_FLOOR, EPOCH_SECONDS,
};
use umbra_crypto::{hash::sha3_256, rand_core::TryRng, secret::Secret, sign::SigningKey};
use umbra_relay::server::OsRng;

/// The epoch of the first key set.
const KEYSET_EPOCH: u64 = 1;
/// The one operator of a provisional directory.
const INDEPENDENT_COUNT: u8 = 1;

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

fn seed_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("authority-{index}.seed"))
}

/// Writes `bytes` to `path` under a temporary name, then renames it.
fn write_whole(path: &Path, bytes: &[u8], secret: bool) -> Result<(), &'static str> {
    let temporary = path.with_extension("part");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options
        .open(&temporary)
        .map_err(|_| "a file does not open for writing")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "a file does not take its bytes")?;
    std::fs::rename(&temporary, path).map_err(|_| "a file does not take its name")
}

fn keygen(dir: &Path) -> Result<(), &'static str> {
    // The keys go into a directory beside the one named and take its name
    // at the end, thus a keygen that stops half-way leaves no key there.
    let holds_any = std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some());
    if holds_any {
        return Err("the key directory holds a file already");
    }
    let staging = dir.with_extension("new");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|_| "the key directory does not open")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "the key directory takes no mode")?;
    }
    let mut keys = Vec::with_capacity(AUTHORITY_COUNT);
    for index in 0..AUTHORITY_COUNT {
        let mut seed = Secret::<32>::zeroed();
        OsRng
            .try_fill_bytes(seed.expose_mut())
            .map_err(|_| "the system gives no randomness")?;
        write_whole(
            &seed_path(&staging, index),
            &to_hex(seed.expose()).into_bytes(),
            true,
        )?;
        keys.push(SigningKey::from_seed(seed));
    }
    let keyset = keyset_bytes_with(&keys, KEYSET_EPOCH, INDEPENDENT_COUNT)
        .map_err(|_| "the key set does not build")?;
    write_whole(&staging.join("keyset.bin"), &keyset, false)?;
    // An empty directory of that name gives way to the keys.
    let _ = std::fs::remove_dir(dir);
    std::fs::rename(&staging, dir).map_err(|_| "the key directory does not take its name")?;
    println!(
        "keyset={} bytes sha3-256={}",
        keyset.len(),
        to_hex(&sha3_256(&[&keyset]))
    );
    Ok(())
}

fn read_keys(dir: &Path) -> Result<(Vec<SigningKey>, Vec<u8>), &'static str> {
    let mut keys = Vec::with_capacity(AUTHORITY_COUNT);
    for index in 0..AUTHORITY_COUNT {
        let text = std::fs::read_to_string(seed_path(dir, index))
            .map_err(|_| "a seed file does not read")?;
        let seed = hex32(text.trim()).ok_or("a seed file does not parse")?;
        keys.push(SigningKey::from_seed(Secret::new(seed)));
    }
    let keyset = std::fs::read(dir.join("keyset.bin")).map_err(|_| "keyset.bin does not read")?;
    // The key set on the disk names these keys, or a client rejects each
    // root that the signer makes.
    let (parsed, _) = DirectoryKeySet::parse(&keyset).map_err(|_| "keyset.bin does not parse")?;
    let named = keys
        .iter()
        .zip(parsed.keys.iter())
        .all(|(key, public)| key.verifying_key().to_bytes().as_slice() == *public);
    if !named || parsed.keys.len() != AUTHORITY_COUNT {
        return Err("keyset.bin names other keys than the seeds");
    }
    Ok((keys, keyset))
}

/// The place of one relay.
#[derive(Clone, Copy)]
enum Place {
    Ingress,
    Middle,
    Exit,
}

struct Admitted {
    descriptor: Vec<u8>,
    operator_id: [u8; 32],
    class: u8,
    place: Place,
}

fn read_relay(value: &str) -> Option<Admitted> {
    let [file, operator, class, place]: [&str; 4] =
        value.split(',').collect::<Vec<_>>().try_into().ok()?;
    Some(Admitted {
        descriptor: std::fs::read(file).ok()?,
        // An opaque value for each beneficial control (`REL-128`).
        operator_id: sha3_256(&[b"umbra/operator", operator.as_bytes()]),
        class: class.parse().ok()?,
        place: match place {
            "ingress" => Place::Ingress,
            "middle" => Place::Middle,
            "exit" => Place::Exit,
            _ => return None,
        },
    })
}

fn sign(settings: &str) -> Result<(), &'static str> {
    let text = std::fs::read_to_string(settings).map_err(|_| "the settings file does not read")?;
    let mut key_dir = None;
    let mut out = None;
    let mut relays = Vec::new();
    let mut report_queues = Vec::new();
    let mut expelled: Vec<[u8; 32]> = Vec::new();
    let mut removed: Vec<LinkRemoval> = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        match line.split_once('=') {
            Some(("keys", value)) => key_dir = Some(PathBuf::from(value)),
            Some(("out", value)) => out = Some(PathBuf::from(value)),
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
    let key_dir = key_dir.ok_or("the settings file needs a line: keys=<key directory>")?;
    let out = out.ok_or("the settings file needs a line: out=<output directory>")?;
    let (keys, keyset) = read_keys(&key_dir)?;
    let (parsed, _) = DirectoryKeySet::parse(&keyset).map_err(|_| "keyset.bin does not parse")?;
    // REL-198: the signer places the relays of one operator alone.
    if parsed.independent_count >= AUTHORITY_FLOOR {
        return Err("the key set is no provisional directory, thus the signer places no relay");
    }

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
            is_ingress: matches!(relay.place, Place::Ingress),
        };
        let admission = match relay.place {
            Place::Exit => Admission::Fixed { layer: 3 },
            Place::Ingress | Place::Middle => Admission::Fixed { layer: 2 },
        };
        let entry = entry_of(&listing, admission)
            .map_err(|_| "a descriptor does not verify, or its class is above the declared one")?;
        let read = RelayEntry::parse(&entry).map_err(|_| "an entry does not verify")?;
        if expelled.contains(&read.descriptor.relay_id) {
            println!("relay {} expelled", to_hex(&read.descriptor.relay_id));
            continue;
        }
        if matches!(relay.place, Place::Ingress) && !read.ingress() {
            return Err("an ingress relay is below class 1 or offers no ingress role");
        }
        if matches!(relay.place, Place::Exit) && read.layer() != 3 {
            return Err("an exit relay offers no queue role and no chain role");
        }
        println!(
            "relay {} ingress={} layer={} class={} host={}",
            to_hex(&read.descriptor.relay_id),
            read.ingress(),
            read.layer(),
            read.class,
            read.descriptor.host_str(),
        );
        entries.push(entry);
    }
    let signers: Vec<u8> = (0u8..).take(AUTHORITY_COUNT).collect();
    let manifest = sign_manifest_under(
        &keys,
        &keyset,
        &signers,
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
    // REL-183: each removed link of its life, under each key.
    removed.sort_by(|one, other| {
        (one.relay_a, one.relay_b, other.epoch).cmp(&(other.relay_a, other.relay_b, one.epoch))
    });
    removed.dedup_by(|one, other| one.relay_a == other.relay_a && one.relay_b == other.relay_b);
    let removal_signers: Vec<(u8, &SigningKey)> = (0u8..).zip(keys.iter()).collect();
    let mut signed_removals = Vec::new();
    for removal in removed
        .iter()
        .filter(|removal| removal.epoch <= epoch && removal.epoch + LINK_REMOVAL_EPOCHS >= epoch)
    {
        signed_removals.push(
            removal
                .sign(&removal_signers, &mut OsRng)
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
    // The signer verifies its own manifest as each relay and each client
    // does, thus a fault of one entry stops here and not at the network.
    let (keyset_parsed, _) =
        DirectoryKeySet::parse(&keyset).map_err(|_| "keyset.bin does not parse")?;
    let mut consensus =
        Consensus::new(keyset_parsed, 0).map_err(|_| "the key set gives no consensus")?;
    let parsed = RelayManifest::parse(&manifest).map_err(|_| "the manifest does not parse")?;
    RelaySet::accept(&mut consensus, &parsed, &BlocList::v1(), now)
        .map_err(|_| "the manifest does not verify; check the clock of each relay")?;
    std::fs::create_dir_all(&out).map_err(|_| "the output directory does not open")?;
    write_whole(&out.join("manifest"), &manifest, false)?;
    write_whole(&out.join("keyset.bin"), &keyset, false)?;
    println!(
        "epoch={epoch} relays={} manifest={} bytes report_queues={} removed_links={}",
        relays.len(),
        manifest.len(),
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
    let work: Box<dyn FnOnce() -> Result<(), &'static str> + Send> = match arguments.as_slice() {
        [command, dir] if command == "keygen" => {
            let dir = PathBuf::from(dir);
            Box::new(move || keygen(&dir))
        }
        [command, settings] if command == "sign" => {
            let settings = settings.clone();
            Box::new(move || sign(&settings))
        }
        _ => {
            eprintln!("usage: umbra-signer keygen <key directory>\n       umbra-signer sign <settings file>");
            return ExitCode::from(2);
        }
    };
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
