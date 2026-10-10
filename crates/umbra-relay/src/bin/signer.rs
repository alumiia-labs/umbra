//! The signer of a directory with one operator: the seven keys of the
//! directory authorities on one machine, which signs the relay manifest of
//! each hour (Part 10 §10.5). The key set that it makes says
//! `independent_count` 1, thus each client shows the `provisional
//! directory` state (`REL-126`), and the relaxations of Part 3 `NET-340` and
//! `NET-350` hold. The keys stay off the relays.
//!
//! ```text
//! umbra-signer keygen <key directory> [<keyset epoch>]
//! umbra-signer rotate <old key directory> <new key directory> <key chain file> [<manifest file>]
//! umbra-signer sign [--force] <settings file>
//! ```
//!
//! `keygen` writes seven fresh seeds, `authority-0.seed` to
//! `authority-6.seed`, readable by their owner alone, and `keyset.bin`, the
//! key set that the app and each relay pin. It refuses a directory that
//! holds a seed already.
//!
//! `rotate` signs the key set of the new directory with each old key
//! (`REL-036`). `keygen` made that key set under the epoch after the old
//! one (`REL-037`). `rotate` adds that link to the key chain file
//! (`REL-199`). The `keys` line of the settings then names the new
//! directory, and each relay and each app walks the chain to it
//! (`REL-200`). Keep the old directory offline until each build that ships
//! its key set is gone.
//!
//! A new key set whose `independent_count` is `AUTHORITY_FLOOR` or more
//! ends the provisional directory. `rotate` then needs the manifest of the
//! current epoch as its last argument. It refuses the key set while an
//! ingress relay of that set has no chain under invariants 1 to 3 (Part 3
//! §3.4.6, `REL-142`).
//!
//! `sign` reads one `key=value` pair on each line:
//!
//! ```text
//! keys=/etc/umbra-signer/keys
//! out=/var/www/umbra/.well-known/umbra
//! keychain=/var/lib/umbra-signer/keychain
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
//!
//! An epoch takes one root (`REL-160`). A client that holds a root rejects
//! a second one of the same epoch, and two digests for one epoch read as an
//! equivocation (`REL-161`). Thus `sign` leaves the published files as they
//! are when the output directory holds a manifest of the current epoch
//! already. It then prints a line with `kept=same` when that manifest holds
//! the same relay set. It prints a line with `kept=other` when the settings
//! changed since, and the next epoch signs the new set. `sign --force`
//! signs a second root for the epoch. Use it to take a relay out now, and
//! accept that warning.
//!
//! A relay with the attachment role declares `CHUNK_STORE_MIN` or more
//! (Part 12 `ATT-088`). The bootstrap period of Part 3 `NET-340` relaxes
//! that floor: under a provisional directory a relay may declare less. This
//! signer signs a provisional directory alone, thus it applies no floor.

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
    path::{select, Candidate},
    removal::{peel, LinkRemoval, LINK_REMOVALS_MAX, LINK_REMOVAL_EPOCHS},
    report::{ReportQueue, QUEUE_ADDRESS_LEN},
    root::{Consensus, DirectoryKeySet, DirectoryRoot},
    AUTHORITY_COUNT, AUTHORITY_FLOOR, EPOCH_SECONDS,
};
use umbra_crypto::{
    hash::sha3_256, rand_core::TryRng, secret::Secret, sign::SigningKey, zeroize::Zeroizing,
};
use umbra_relay::server::OsRng;

/// The epoch of the first key set.
const FIRST_KEYSET_EPOCH: u64 = 1;
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

fn keygen(dir: &Path, keyset_epoch: u64) -> Result<(), &'static str> {
    let holds_any = std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some());
    if holds_any || dir.is_file() {
        return Err("the key directory holds a file already");
    }
    // The keys go into a new directory beside the one named and take its
    // name at the end. Thus a keygen that stops half-way leaves no key
    // there. This run makes the random name of that directory, thus the
    // tool deletes no directory that it did not make.
    let mut tag = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut tag)
        .map_err(|_| "the system gives no randomness")?;
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("the key directory has no name")?;
    let staging = dir.with_file_name(format!(".{name}.keygen-{}", to_hex(&tag)));
    if let Some(parent) = staging.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|_| "the key directory does not open")?;
    }
    std::fs::create_dir(&staging).map_err(|_| "the key directory does not open")?;
    let made = fill_keys(&staging, keyset_epoch).and_then(|keyset| {
        // An empty directory of that name gives way to the keys.
        let _ = std::fs::remove_dir(dir);
        std::fs::rename(&staging, dir).map_err(|_| "the key directory does not take its name")?;
        Ok(keyset)
    });
    let keyset = match made {
        Ok(keyset) => keyset,
        Err(cause) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(cause);
        }
    };
    println!(
        "keyset={} bytes sha3-256={}",
        keyset.len(),
        to_hex(&sha3_256(&[&keyset]))
    );
    Ok(())
}

/// Writes seven fresh seeds and their key set into `staging`, a directory
/// that this run made, and returns the key set.
fn fill_keys(staging: &Path, keyset_epoch: u64) -> Result<Vec<u8>, &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "the key directory takes no mode")?;
    }
    let mut keys = Vec::with_capacity(AUTHORITY_COUNT);
    for index in 0..AUTHORITY_COUNT {
        let mut seed = Secret::<32>::zeroed();
        OsRng
            .try_fill_bytes(seed.expose_mut())
            .map_err(|_| "the system gives no randomness")?;
        // `Zeroizing` wipes the hex form of the seed after its file took it.
        let text = Zeroizing::new(to_hex(seed.expose()));
        write_whole(&seed_path(staging, index), text.as_bytes(), true)?;
        keys.push(SigningKey::from_seed(seed));
    }
    let keyset = keyset_bytes_with(&keys, keyset_epoch, INDEPENDENT_COUNT)
        .map_err(|_| "the key set does not build")?;
    write_whole(&staging.join("keyset.bin"), &keyset, false)?;
    Ok(keyset)
}

fn read_keys(dir: &Path) -> Result<(Vec<SigningKey>, Vec<u8>), &'static str> {
    let mut keys = Vec::with_capacity(AUTHORITY_COUNT);
    for index in 0..AUTHORITY_COUNT {
        // The tool wipes the text and the seed when the key holds the seed.
        let text = Zeroizing::new(
            std::fs::read_to_string(seed_path(dir, index))
                .map_err(|_| "a seed file does not read")?,
        );
        let seed = Zeroizing::new(hex32(text.trim()).ok_or("a seed file does not parse")?);
        keys.push(SigningKey::from_seed(Secret::new(*seed)));
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

/// Whether `new` is the epoch that follows `old` (`REL-037`). A client
/// rejects a key set at or below the epoch that it holds. It also rejects
/// one more than one above it.
fn is_next_epoch(old: u64, new: u64) -> bool {
    old.checked_add(1) == Some(new)
}

/// The first ingress relay of `candidates` from which no chain satisfies
/// invariants 1 to 3 of Part 3 §3.4.6 (`REL-142`). The search tries each
/// chain with the relaxation of `NET-200` and without it. The test is the
/// selection of a client outside a provisional directory, thus a set that
/// passes gives each client a chain.
fn ingress_with_no_chain(candidates: &[Candidate]) -> Option<[u8; 32]> {
    candidates
        .iter()
        .filter(|candidate| candidate.ingress)
        .find(|ingress| select(ingress, candidates).is_err())
        .map(|ingress| ingress.relay_id)
}

/// Whether the authorities may state `independent_count` over the relay set
/// `candidates` (`REL-142`). A count below `AUTHORITY_FLOOR` keeps the
/// directory provisional, and each relay set stands under it. A count at
/// the floor or above ends the bootstrap relaxation of each client. It thus
/// needs a chain from each ingress relay. A set with no ingress relay gives
/// no client a chain.
fn count_stands(independent_count: u8, candidates: &[Candidate]) -> bool {
    independent_count < AUTHORITY_FLOOR
        || (candidates.iter().any(|candidate| candidate.ingress)
            && ingress_with_no_chain(candidates).is_none())
}

/// The relays of the manifest at `path`, which must verify under `keyset`
/// at `now` and hold the whole relay set.
fn candidates_of(path: &Path, keyset: &[u8], now: u64) -> Result<Vec<Candidate>, &'static str> {
    let bytes = std::fs::read(path).map_err(|_| "the manifest file does not read")?;
    let (keyset, _) = DirectoryKeySet::parse(keyset).map_err(|_| "keyset.bin does not parse")?;
    let mut consensus = Consensus::new(keyset, 0).map_err(|_| "the key set gives no consensus")?;
    let manifest = RelayManifest::parse(&bytes).map_err(|_| "the manifest does not parse")?;
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now).map_err(|_| {
        "the manifest does not verify under the old key set; give the one of this epoch"
    })?;
    if !set.is_whole {
        return Err("the manifest holds a part of the relay set");
    }
    Ok(set.relays.iter().map(|relay| relay.candidate).collect())
}

/// Signs the key set of `new` under each key of `old` (`REL-036`), and adds
/// the link to the key chain at `chain` (`REL-199`). `manifest` is the file
/// of the current manifest, which a new key set at `AUTHORITY_FLOOR` needs
/// (`REL-142`).
fn rotate(
    old: &Path,
    new: &Path,
    chain: &Path,
    manifest: Option<&Path>,
) -> Result<(), &'static str> {
    let (old_keys, old_keyset) = read_keys(old)?;
    let (_, new_keyset) = read_keys(new)?;
    let (old_parsed, _) =
        DirectoryKeySet::parse(&old_keyset).map_err(|_| "the old keyset.bin does not parse")?;
    let (new_parsed, _) =
        DirectoryKeySet::parse(&new_keyset).map_err(|_| "the new keyset.bin does not parse")?;
    // REL-037: a client takes the next epoch alone, thus a set of another
    // epoch would leave each client at the old set.
    if !is_next_epoch(old_parsed.keyset_epoch, new_parsed.keyset_epoch) {
        return Err(
            "the new key set needs the epoch of the old one plus 1, or each client \
             rejects it (REL-037): keygen <dir> <epoch>",
        );
    }
    // REL-142: the count rises to the floor only over a relay set that
    // carries a chain from each ingress relay.
    if new_parsed.independent_count >= AUTHORITY_FLOOR {
        let manifest = manifest.ok_or(
            "a key set of AUTHORITY_FLOOR independent keys or more needs the manifest of \
             this epoch (REL-142): rotate <old> <new> <key chain file> <manifest file>",
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "the clock is before 1970")?
            .as_secs();
        let candidates = candidates_of(manifest, &old_keyset, now)?;
        if !count_stands(new_parsed.independent_count, &candidates) {
            return Err(
                "the relay set holds an ingress relay with no chain of three operators, \
                 two blocs and three networks, thus independent_count stays below \
                 AUTHORITY_FLOOR (REL-142)",
            );
        }
    }
    let link = umbra_core::directory::keychain::sign_keyset(&old_keys, &new_keyset, &mut OsRng)
        .map_err(|_| "the new key set does not sign")?;
    let held = std::fs::read(chain).ok();
    let mut links: Vec<&[u8]> = match &held {
        Some(bytes) => umbra_core::directory::keychain::links(bytes)
            .map_err(|_| "the key chain file does not parse")?,
        None => Vec::new(),
    };
    // A rotation runs one time: a chain that reaches this epoch takes no
    // second link of it.
    let reached = links.iter().any(|held| {
        DirectoryKeySet::parse(held)
            .is_ok_and(|(set, _)| set.keyset_epoch >= new_parsed.keyset_epoch)
    });
    if reached {
        return Err("the key chain reaches that epoch already");
    }
    links.push(&link);
    let encoded =
        umbra_core::directory::keychain::encode(&links).map_err(|_| "the key chain is full")?;
    // The chain walks from the old set to the new one, as each client will.
    umbra_core::directory::keychain::advance(&old_keyset, &encoded)
        .ok()
        .filter(|reached| *reached == new_keyset)
        .ok_or("the key chain does not reach the new key set")?;
    write_whole(chain, &encoded, false)?;
    println!(
        "keychain links={} newest epoch={}",
        links.len(),
        new_parsed.keyset_epoch
    );
    Ok(())
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

/// Whether the verdict `removal` is inside its life at `epoch`
/// (`REL-183`). A verdict of a later epoch is not, and an epoch near the end
/// of its range wraps nothing.
fn in_life(removal: &LinkRemoval, epoch: u64) -> bool {
    removal.epoch <= epoch && removal.epoch.saturating_add(LINK_REMOVAL_EPOCHS) >= epoch
}

/// The removed links of `removed` that a manifest of `epoch` carries
/// (`REL-183`), and the count of those that found no room. The manifest
/// carries each link one time, with the newest of its verdicts inside their
/// life. It carries no link of a relay in `expelled`, which the manifest
/// lists no more. A manifest takes `LINK_REMOVALS_MAX` at the most, and
/// each client rejects one above it, thus the newest stay.
///
/// The verdicts outside their life leave first. Before this, the newest
/// verdict of a link took the place of each other one first. A verdict of
/// a later epoch beside a live one of the same link then left the manifest
/// with no removal of that link.
fn live_removals(
    removed: &[LinkRemoval],
    expelled: &[[u8; 32]],
    epoch: u64,
) -> (Vec<LinkRemoval>, usize) {
    let mut live: Vec<LinkRemoval> = removed
        .iter()
        .filter(|removal| in_life(removal, epoch))
        .filter(|removal| {
            !expelled.contains(&removal.relay_a) && !expelled.contains(&removal.relay_b)
        })
        .copied()
        .collect();
    let by_link = |one: &LinkRemoval, other: &LinkRemoval| {
        (one.relay_a, one.relay_b, other.epoch).cmp(&(other.relay_a, other.relay_b, one.epoch))
    };
    live.sort_by(by_link);
    live.dedup_by(|one, other| one.relay_a == other.relay_a && one.relay_b == other.relay_b);
    let over = live.len().saturating_sub(LINK_REMOVALS_MAX);
    if over > 0 {
        live.sort_by(|one, other| other.epoch.cmp(&one.epoch).then(by_link(one, other)));
        live.truncate(LINK_REMOVALS_MAX);
        live.sort_by(by_link);
    }
    (live, over)
}

/// What the output directory holds for the epoch of a fresh manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Published {
    /// No manifest of that epoch.
    Nothing,
    /// A manifest of that epoch whose root signs the same fields.
    Same,
    /// A manifest of that epoch with another relay set, key set, or count
    /// of report queues or removed links.
    Other,
}

/// Compares the manifest `held` of the output directory with `fresh`
/// (`REL-160`). A file that does not parse counts as no manifest, thus a
/// damaged one gives way to the fresh one.
fn published(held: Option<&[u8]>, fresh: &[u8]) -> Published {
    let read = |bytes| {
        let manifest = RelayManifest::parse(bytes).ok()?;
        let root = DirectoryRoot::parse(manifest.root).ok()?;
        Some((
            root.epoch,
            root.digest(),
            manifest.queues.len(),
            manifest.removals.len(),
        ))
    };
    let (Some(held), Some(fresh)) = (held.and_then(read), read(fresh)) else {
        return Published::Nothing;
    };
    if held.0 != fresh.0 {
        Published::Nothing
    } else if held == fresh {
        // The signatures differ at each run and the digest does not. The
        // queues and the removals sit outside the root, thus their counts
        // stand in for them.
        Published::Same
    } else {
        Published::Other
    }
}

fn sign(settings: &str, force: bool) -> Result<(), &'static str> {
    let text = std::fs::read_to_string(settings).map_err(|_| "the settings file does not read")?;
    let mut key_dir = None;
    let mut out = None;
    let mut keychain: Option<PathBuf> = None;
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
            Some(("keychain", value)) => keychain = Some(PathBuf::from(value)),
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
    // REL-200: each relay and each app reaches the key set of the manifest
    // through the chain alone, thus the signer signs under the set that
    // the chain ends at, and under the first set before any rotation. A
    // key directory of no rotation would leave each client with no network.
    let chain = keychain.as_ref().and_then(|path| std::fs::read(path).ok());
    let newest = match &chain {
        Some(bytes) => umbra_core::directory::keychain::links(bytes)
            .map_err(|_| "the key chain file does not parse")?
            .last()
            .and_then(|link| DirectoryKeySet::parse(link).ok())
            .map(|(set, used)| (set.keyset_epoch, used)),
        None => None,
    };
    match (&chain, newest) {
        (Some(bytes), Some((_, used))) => {
            let links = umbra_core::directory::keychain::links(bytes)
                .map_err(|_| "the key chain file does not parse")?;
            let last = links.last().and_then(|link| link.get(..used));
            if last != Some(keyset.as_slice()) {
                return Err("the keys are not the newest set of the key chain; run rotate first");
            }
        }
        _ if parsed.keyset_epoch > FIRST_KEYSET_EPOCH => {
            return Err("a key set after the first one needs its key chain: the keychain= line");
        }
        _ => {}
    }
    // REL-198: the signer places the relays of one operator alone.
    let parsed_count = parsed.independent_count;
    let provisional = parsed_count < AUTHORITY_FLOOR;
    if !provisional {
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
        .filter(|removal| in_life(removal, epoch))
        .copied()
        .collect();
    for relay in peel(&live) {
        println!("relay {} expelled by the link-fault search", to_hex(&relay));
        expelled.push(relay);
    }
    // REL-183: the manifest carries the removed links after the search,
    // thus the links of a relay that it expelled take no place. Before
    // this, the bound stopped the run before the search took out a relay
    // with many removed links. The signer then signed no manifest until an
    // operator edited the verdicts.
    let (carried, left_out) = live_removals(&removed, &expelled, epoch);
    if left_out > 0 {
        eprintln!(
            "the verdicts hold {left_out} removed links above LINK_REMOVALS_MAX, \
             and the manifest carries the newest of them alone"
        );
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
        // ATT-088: the floor of the chunk store applies from the first
        // directory that is not provisional (Part 3 `NET-340` to `NET-345`).
        // This signer signs a provisional directory alone (`REL-198`).
        // It thus holds no check of the floor: the one that stood here ran
        // after the refusal of each other key set and refused nothing. An
        // authority that signs under `AUTHORITY_FLOOR` keys or more applies
        // the floor.
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
    let removal_signers: Vec<(u8, &SigningKey)> = (0u8..).zip(keys.iter()).collect();
    let mut signed_removals = Vec::new();
    for removal in &carried {
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
    let set = RelaySet::accept(&mut consensus, &parsed, &BlocList::v1(), now)
        .map_err(|_| "the manifest does not verify; check the clock of each relay")?;
    // REL-147: each client and each relay takes a whole set alone.
    if !set.is_whole {
        return Err("the manifest holds a part of the relay set");
    }
    // REL-142: no manifest goes out under a count at the floor over a relay
    // set with an ingress relay that has no chain.
    let candidates: Vec<Candidate> = set.relays.iter().map(|relay| relay.candidate).collect();
    if !count_stands(parsed_count, &candidates) {
        return Err(
            "the relay set holds an ingress relay with no chain of three operators, \
             two blocs and three networks, thus independent_count stays below \
             AUTHORITY_FLOOR (REL-142)",
        );
    }
    // REL-160: an epoch takes one root. A second run inside the epoch leaves
    // the first root in its place, with or without a changed relay set.
    let held = std::fs::read(out.join("manifest")).ok();
    match published(held.as_deref(), &manifest) {
        Published::Same if !force => {
            println!("epoch={epoch} kept=same the root of this epoch is published already");
            return Ok(());
        }
        Published::Other if !force => {
            println!(
                "epoch={epoch} kept=other this epoch has a root of other settings already; \
                 the next epoch signs these, and sign --force signs them now"
            );
            return Ok(());
        }
        _ => {}
    }
    std::fs::create_dir_all(&out).map_err(|_| "the output directory does not open")?;
    write_whole(&out.join("manifest"), &manifest, false)?;
    write_whole(&out.join("keyset.bin"), &keyset, false)?;
    // REL-199: the chain of each rotation, beside the manifest.
    if let Some(chain) = keychain.as_ref().and_then(|path| std::fs::read(path).ok()) {
        write_whole(&out.join("keychain"), &chain, false)?;
    }
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
            Box::new(move || keygen(&dir, FIRST_KEYSET_EPOCH))
        }
        [command, dir, epoch] if command == "keygen" => {
            let dir = PathBuf::from(dir);
            let Ok(epoch) = epoch.parse::<u64>() else {
                eprintln!("the keyset epoch is a number");
                return ExitCode::from(2);
            };
            Box::new(move || keygen(&dir, epoch))
        }
        [command, old, new, chain] if command == "rotate" => {
            let (old, new, chain) = (PathBuf::from(old), PathBuf::from(new), PathBuf::from(chain));
            Box::new(move || rotate(&old, &new, &chain, None))
        }
        [command, old, new, chain, manifest] if command == "rotate" => {
            let (old, new, chain) = (PathBuf::from(old), PathBuf::from(new), PathBuf::from(chain));
            let manifest = PathBuf::from(manifest);
            Box::new(move || rotate(&old, &new, &chain, Some(&manifest)))
        }
        [command, settings] if command == "sign" => {
            let settings = settings.clone();
            Box::new(move || sign(&settings, false))
        }
        [command, force, settings] if command == "sign" && force == "--force" => {
            let settings = settings.clone();
            Box::new(move || sign(&settings, true))
        }
        _ => {
            eprintln!(
                "usage: umbra-signer keygen <key directory> [<keyset epoch>]\n       \
                 umbra-signer rotate <old key directory> <new key directory> <key chain file> \
                 [<manifest file>]\n       \
                 umbra-signer sign [--force] <settings file>"
            );
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use umbra_core::directory::descriptor::{roles, RelayDescriptor};

    fn keys(tag: u8) -> Vec<SigningKey> {
        (0u8..)
            .take(AUTHORITY_COUNT)
            .map(|index| SigningKey::from_seed(Secret::new([tag.wrapping_add(index); 32])))
            .collect()
    }

    /// The signed descriptor of the relay `seed`.
    fn descriptor(seed: u8, relay_roles: u8, chunk_store_gib: u32) -> Vec<u8> {
        let mut host = [0u8; umbra_core::directory::descriptor::HOST_LEN];
        host[..9].copy_from_slice(b"localhost");
        RelayDescriptor {
            relay_id: [0; 32],
            identity_pk: &[],
            ntor_pk: [seed; 32],
            addr_v4: [127, seed, 0, 1],
            addr_v6: [0; 16],
            port: 443,
            host,
            asn: u32::from(seed),
            jurisdiction: *b"US",
            family_id: [seed; 32],
            capacity_class: 1,
            roles: relay_roles,
            chunk_store_gib,
            valid_after: 0,
            sig: &[],
        }
        .sign(&SigningKey::from_seed(Secret::new([seed; 32])), &mut OsRng)
        .unwrap()
    }

    /// The entry of the exit relay `seed`, under a fresh descriptor.
    fn entry(seed: u8) -> Vec<u8> {
        let descriptor = descriptor(seed, roles::QUEUE | roles::CHAIN, 0);
        let listing = Listing {
            descriptor: &descriptor,
            operator_id: [1; 32],
            class: 1,
            is_ingress: false,
        };
        entry_of(&listing, Admission::Fixed { layer: 3 }).unwrap()
    }

    /// A manifest of `epoch` under `keys` over `entries`.
    fn manifest(keys: &[SigningKey], epoch: u64, entries: &[Vec<u8>]) -> Vec<u8> {
        let keyset = keyset_bytes_with(keys, FIRST_KEYSET_EPOCH, INDEPENDENT_COUNT).unwrap();
        let signers: Vec<u8> = (0u8..).take(AUTHORITY_COUNT).collect();
        sign_manifest_under(
            keys,
            &keyset,
            &signers,
            epoch,
            entries.to_vec(),
            &BlocList::v1(),
            &mut OsRng,
        )
        .unwrap()
    }

    fn on_a_signing_stack(work: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(STACK_BYTES)
            .spawn(work)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn keygen_deletes_no_directory_that_it_did_not_make() {
        on_a_signing_stack(|| {
            let mut tag = [0u8; 8];
            OsRng.try_fill_bytes(&mut tag).unwrap();
            let root = std::env::temp_dir().join(format!("umbra-signer-test-{}", to_hex(&tag)));
            std::fs::create_dir_all(&root).unwrap();
            // A live key directory with the name that an earlier keygen
            // took for its work, and one with a dot in its name.
            let other = root.join("keys.new");
            std::fs::create_dir(&other).unwrap();
            std::fs::write(other.join("authority-0.seed"), b"live").unwrap();
            let dotted = root.join("keys.2026");
            std::fs::create_dir(&dotted).unwrap();
            std::fs::write(dotted.join("authority-0.seed"), b"live").unwrap();

            keygen(&root.join("keys"), FIRST_KEYSET_EPOCH).unwrap();
            assert!(read_keys(&root.join("keys")).is_ok());
            assert_eq!(
                std::fs::read(other.join("authority-0.seed")).unwrap(),
                b"live"
            );
            // A directory that holds a file takes no keys and keeps its file.
            assert!(keygen(&dotted, FIRST_KEYSET_EPOCH).is_err());
            assert!(keygen(&root.join("keys"), FIRST_KEYSET_EPOCH).is_err());
            assert_eq!(
                std::fs::read(dotted.join("authority-0.seed")).unwrap(),
                b"live"
            );
            // No work directory stays behind.
            let left: Vec<_> = std::fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .filter(|name| name.contains("keygen"))
                .collect();
            assert!(left.is_empty(), "{left:?}");
            std::fs::remove_dir_all(&root).unwrap();
        });
    }

    #[test]
    fn an_epoch_with_a_published_root_takes_no_second_one() {
        on_a_signing_stack(|| {
            let first_keys = keys(0x40);
            let two = [entry(1), entry(2)];
            let first = manifest(&first_keys, 700, &two);
            // REL-160: the first run of a directory, and a damaged file.
            assert_eq!(published(None, &first), Published::Nothing);
            assert_eq!(published(Some(&[0x01, 0x02]), &first), Published::Nothing);
            // The same settings sign other bytes under the same digest.
            let again = manifest(&first_keys, 700, &two);
            assert_ne!(first, again);
            assert_eq!(published(Some(&first), &again), Published::Same);
            // A relay more in the same epoch is another root for it.
            let three = [two[0].clone(), two[1].clone(), entry(3)];
            let more = manifest(&first_keys, 700, &three);
            assert_eq!(published(Some(&first), &more), Published::Other);
            // A descriptor that a relay signed again is another root too.
            let signed_again = manifest(&first_keys, 700, &[two[0].clone(), entry(2)]);
            assert_eq!(published(Some(&first), &signed_again), Published::Other);
            // Another key set in the same epoch is another root too.
            let rotated = manifest(&keys(0x80), 700, &two);
            assert_eq!(published(Some(&first), &rotated), Published::Other);
            // The next epoch signs the new set.
            let next = manifest(&first_keys, 701, &three);
            assert_eq!(published(Some(&first), &next), Published::Nothing);
        });
    }

    #[test]
    fn rotate_takes_the_next_keyset_epoch_alone() {
        on_a_signing_stack(|| {
            // REL-037: the step of one is the only bound of the epoch.
            assert!(is_next_epoch(1, 2));
            assert!(!is_next_epoch(1, 1));
            assert!(!is_next_epoch(2, 1));
            assert!(!is_next_epoch(1, 3));
            assert!(!is_next_epoch(u64::MAX, 0));

            let mut tag = [0u8; 8];
            OsRng.try_fill_bytes(&mut tag).unwrap();
            let root = std::env::temp_dir().join(format!("umbra-signer-test-{}", to_hex(&tag)));
            std::fs::create_dir_all(&root).unwrap();
            let chain = root.join("keychain");
            keygen(&root.join("first"), FIRST_KEYSET_EPOCH).unwrap();
            keygen(&root.join("same"), FIRST_KEYSET_EPOCH).unwrap();
            keygen(&root.join("far"), FIRST_KEYSET_EPOCH + 2).unwrap();
            keygen(&root.join("next"), FIRST_KEYSET_EPOCH + 1).unwrap();
            // A set of the same epoch and a set two above sign no link.
            assert!(rotate(&root.join("first"), &root.join("same"), &chain, None).is_err());
            assert!(rotate(&root.join("first"), &root.join("far"), &chain, None).is_err());
            assert!(!chain.exists());
            rotate(&root.join("first"), &root.join("next"), &chain, None).unwrap();
            assert!(chain.exists());
            std::fs::remove_dir_all(&root).unwrap();
        });
    }

    #[test]
    fn a_manifest_takes_512_removed_links_and_no_more() {
        let link = |index: u16, epoch: u64| {
            let mut other = [0xFF; 32];
            other[..2].copy_from_slice(&index.to_be_bytes());
            LinkRemoval::of(epoch, [0; 32], other)
        };
        let max = u16::try_from(LINK_REMOVALS_MAX).unwrap();
        let full: Vec<LinkRemoval> = (0..max).map(|index| link(index, 700)).collect();
        assert_eq!(live_removals(&full, &[], 700), (full.clone(), 0));
        // A second verdict of one link and a link past its life count for
        // nothing.
        let mut same = full.clone();
        same.push(link(0, 699));
        same.push(link(max, 700 - LINK_REMOVAL_EPOCHS - 1));
        same.push(link(max + 1, 701));
        assert_eq!(live_removals(&same, &[], 700), (full.clone(), 0));
        // One live link more leaves the oldest one out, and the run goes
        // on: the manifest carries the newest 512.
        let mut over: Vec<LinkRemoval> = (0..max)
            .map(|index| link(index, if index == 7 { 698 } else { 700 }))
            .collect();
        over.push(link(max, 700));
        let (carried, left_out) = live_removals(&over, &[], 700);
        assert_eq!((carried.len(), left_out), (512, 1));
        assert!(!carried.contains(&link(7, 698)));
        assert!(carried.contains(&link(max, 700)));
        // The links of a relay that the search expelled take no place.
        let mut far = [0xFF; 32];
        far[..2].copy_from_slice(&3u16.to_be_bytes());
        let (carried, left_out) = live_removals(&over, &[far], 700);
        assert_eq!((carried.len(), left_out), (512, 0));
        assert!(!carried.contains(&link(3, 700)));
        assert!(live_removals(&over, &[[0; 32]], 700).0.is_empty());
    }

    #[test]
    fn a_verdict_of_a_later_epoch_hides_no_live_verdict_of_its_link() {
        let live = LinkRemoval::of(690, [1; 32], [2; 32]);
        let later = LinkRemoval::of(900, [1; 32], [2; 32]);
        // The verdict of the later epoch is outside its life, and the live
        // one of the same link stays. Before this, the later one took its
        // place first, and the manifest carried no removal of the link.
        assert_eq!(live_removals(&[later, live], &[], 700), (vec![live], 0));
        // An epoch at the end of its range wraps nothing.
        let last = LinkRemoval::of(u64::MAX, [1; 32], [2; 32]);
        assert!(in_life(&last, u64::MAX));
        assert!(!in_life(&last, 700));
        assert_eq!(live_removals(&[last], &[], 700), (Vec::new(), 0));
    }

    #[test]
    fn the_count_reaches_the_floor_when_each_ingress_relay_has_a_chain_alone() {
        on_a_signing_stack(|| {
            let blocs = BlocList::v1();
            // The relay `seed` of the operator `operator` in `code`: the
            // ingress relay of layer 1, or a chain relay of `layer`.
            let relay = |seed: u8, operator: u8, code: &[u8; 2], layer: u8| {
                let is_ingress = layer == 1;
                let relay_roles = if is_ingress {
                    roles::INGRESS_OFFERED | roles::CHAIN
                } else {
                    roles::QUEUE | roles::CHAIN
                };
                let descriptor = descriptor(seed, relay_roles, 0);
                let listing = Listing {
                    descriptor: &descriptor,
                    operator_id: [operator; 32],
                    class: 1,
                    is_ingress,
                };
                let entry = entry_of(
                    &listing,
                    Admission::Fixed {
                        layer: layer.max(2),
                    },
                )
                .unwrap();
                Candidate {
                    bloc: blocs.bloc_of(code),
                    ..Candidate::from_entry(&RelayEntry::parse(&entry).unwrap(), &blocs)
                }
            };
            // Three operators, and hop 1 and hop 3 in two blocs.
            let apart = [
                relay(1, 1, b"US", 1),
                relay(2, 2, b"US", 2),
                relay(3, 3, b"SE", 3),
            ];
            assert_eq!(ingress_with_no_chain(&apart), None);
            assert!(count_stands(AUTHORITY_FLOOR, &apart));

            // REL-142: the relay set of one operator carries no chain, thus
            // the count stays below the floor over it.
            let one_operator = [
                relay(1, 1, b"US", 1),
                relay(2, 1, b"US", 2),
                relay(3, 1, b"SE", 3),
            ];
            assert_eq!(
                ingress_with_no_chain(&one_operator),
                Some(one_operator[0].relay_id)
            );
            assert!(!count_stands(AUTHORITY_FLOOR, &one_operator));
            assert!(count_stands(AUTHORITY_FLOOR - 1, &one_operator));

            // One ingress relay with no chain holds the count down, beside
            // one that has a chain: hop 1 and hop 3 in one bloc.
            let lone = relay(4, 4, b"FI", 1);
            let mut mixed = apart.to_vec();
            mixed.push(lone);
            assert_eq!(ingress_with_no_chain(&mixed), Some(lone.relay_id));
            assert!(!count_stands(AUTHORITY_FLOOR, &mixed));

            // A set with no ingress relay gives no client a chain.
            assert!(!count_stands(AUTHORITY_FLOOR, &apart[1..]));
            assert!(count_stands(INDEPENDENT_COUNT, &apart[1..]));
        });
    }
}
