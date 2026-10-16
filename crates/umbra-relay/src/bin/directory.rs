//! The directory of Part 9 and the first-party issuer of Part 13 §13.9 in
//! one process, behind one OHTTP gateway (`DIS-162`).
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! listen=0.0.0.0:443
//! cert=/etc/umbra/directory-cert.pem
//! key=/etc/umbra/directory-key.pem
//! kem_seed=<64 hex characters>
//! key_id=1
//! store=/var/lib/umbra/directory.db
//! voprf_seed=<64 hex characters>
//! vrf_seed=<64 hex characters>
//! issuer_seed=<64 hex characters>
//! cross_relay_seed=<64 hex characters, optional>
//! signer_seeds=<64 hex>,<64 hex>,<64 hex>
//! keyset_epoch=1
//! keyset_chain=<hex>,<hex>, optional
//! epoch_seconds=600
//! ```
//!
//! Each seed gives the same key at each start. `umbra-directory pins
//! <settings>` prints in hex what a client build pins (`DIS-163`): the key
//! configuration of the gateway, the key set of the signers, the VRF key of
//! the log, and the VOPRF key of the directory.
//!
//! A rotation of the signers (`DIS-064`) takes new seeds and a higher
//! `keyset_epoch`. `umbra-directory sign-keyset <old settings> <new
//! settings>` prints in hex the `SignedLogKeySet` of the new set under the
//! signers of the old one. `keyset_chain` lists each such set from the
//! first rotation on, in order, and a client takes them to reach the set of
//! the heads (`DIS-198`, `DIS-199`).
//!
//! In a deployment the second and the third signer are the two auditors of
//! §9.5.2, each at its own operator. This process holds all three seeds for
//! a test network alone.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, process::ExitCode};

use tokio::net::TcpListener;
use umbra_core::{
    discovery::{
        dirclient::DirectoryPins,
        handle::username_case_mapped,
        head::{LogKeySet, KEYSET_LEN},
        service::{CrossRelayKeys, Directory, DirectoryKeys, DIRECTORY_EPOCH},
    },
    notify::seeded_pair,
};
use umbra_crypto::{
    kem::KeyPair, ohttp, rsabssa::SecretKey2048, secret::Secret, sign::SigningKey,
    zeroize::Zeroizing,
};
use umbra_relay::{
    directory_server::{run_directory, DirectoryStore, SqliteDirectoryStore},
    ndr_server::Gateway,
    server::tls_acceptor,
};

/// The stack of each thread of this program. An ML-DSA-65 key and its
/// signature need more than the 1 MiB that the main thread of Windows has.
const STACK_BYTES: usize = 16 << 20;

/// Reads a seed of 64 hex characters. It leaves no copy in memory.
fn hex32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (at, slot) in out.iter_mut().enumerate() {
        let start = at.checked_mul(2)?;
        *slot = u8::from_str_radix(text.get(start..start.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn settings(text: &str) -> BTreeMap<&str, &str> {
    text.lines()
        .filter_map(|line| line.trim().split_once('='))
        .collect()
}

/// The `SignedLogKeySet` of the set of `new` under each signer of `old`
/// (`DIS-045`, `DIS-064`).
fn sign_keyset(old: &BTreeMap<&str, &str>, new: &BTreeMap<&str, &str>) -> Option<Vec<u8>> {
    let (old_keys, _) = keys(old)?;
    let (_, next) = keys(new)?;
    let (set, _) = LogKeySet::parse(&next).ok()?;
    let preimage = set.rotation_preimage().ok()?;
    let mut out = next.clone();
    out.push(u8::try_from(old_keys.signers.len()).ok()?);
    for (index, signer) in old_keys.signers.iter().enumerate() {
        out.push(u8::try_from(index).ok()?);
        let sig = signer
            .sign(&preimage, &mut umbra_relay::server::OsRng)
            .ok()?;
        out.extend_from_slice(&sig.to_bytes());
    }
    Some(out)
}

/// The gateway key of a seed.
fn gateway_pair(seed: &[u8; 32]) -> KeyPair {
    seeded_pair(umbra_crypto::labels::DIRECTORY, seed)
}

fn main() -> ExitCode {
    let work = || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(STACK_BYTES)
            .build();
        match runtime {
            Ok(runtime) => runtime.block_on(run()),
            Err(_) => {
                eprintln!("the runtime does not start");
                ExitCode::from(1)
            }
        }
    };
    std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(work)
        .ok()
        .and_then(|thread| thread.join().ok())
        .unwrap_or(ExitCode::from(1))
}

/// The keys of the settings, and the encoded key set.
fn keys(values: &BTreeMap<&str, &str>) -> Option<(DirectoryKeys, Vec<u8>)> {
    let seed = |name: &str| {
        values
            .get(name)
            .and_then(|text| hex32(text))
            .map(|seed| Secret::new(*seed))
    };
    let signers: Vec<SigningKey> = values
        .get("signer_seeds")?
        .split(',')
        .map(|text| hex32(text.trim()).map(|seed| SigningKey::from_seed(Secret::new(*seed))))
        .collect::<Option<_>>()?;
    let public: Vec<_> = signers
        .iter()
        .map(|signer| signer.verifying_key().to_bytes())
        .collect();
    let set = LogKeySet {
        keyset_epoch: values
            .get("keyset_epoch")
            .map_or(Some(1), |text| text.parse().ok())?,
        keys: public.iter().map(|key| &key[..]).collect(),
    };
    let mut keyset = vec![0u8; KEYSET_LEN];
    let used = set.encode(&mut keyset).ok()?;
    keyset.truncate(used);
    Some((
        DirectoryKeys {
            voprf_seed: seed("voprf_seed")?,
            vrf_seed: seed("vrf_seed")?,
            issuer_seed: seed("issuer_seed")?,
            signers,
            keyset: keyset.clone(),
            // Part 13 §13.3.1: the seed of the RSA key of each epoch, for a
            // directory that issues cross-relay tokens.
            cross_relay: seed("cross_relay_seed").map(|seed| -> CrossRelayKeys {
                Box::new(move |epoch: u32| {
                    SecretKey2048::from_seed(&seed, &epoch.to_be_bytes()).ok()
                })
            }),
        },
        keyset,
    ))
}

async fn run() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let [flag, old, new] = arguments.as_slice() {
        if flag == "sign-keyset" {
            let (Ok(old), Ok(new)) = (std::fs::read_to_string(old), std::fs::read_to_string(new))
            else {
                eprintln!("a settings file does not read");
                return ExitCode::from(2);
            };
            let Some(signed) = sign_keyset(&settings(&old), &settings(&new)) else {
                eprintln!("the two settings files give no signed key set");
                return ExitCode::from(2);
            };
            println!("{}", hex_text(&signed));
            return ExitCode::SUCCESS;
        }
    }
    let (path, prints_pins) = match arguments.as_slice() {
        [flag, path] if flag == "pins" => (path, true),
        [path] => (path, false),
        _ => {
            eprintln!(
                "usage: umbra-directory <settings file> | pins <settings file> | sign-keyset <old settings> <new settings>"
            );
            return ExitCode::from(2);
        }
    };
    // The text holds each seed of the directory, thus `Zeroizing` wipes it.
    let Ok(text) = std::fs::read_to_string(path).map(Zeroizing::new) else {
        eprintln!("the settings file does not read");
        return ExitCode::from(2);
    };
    let values = settings(&text);
    let (Some(seed), Some(key_id), Some((keys, keyset))) = (
        values.get("kem_seed").and_then(|seed| hex32(seed)),
        values.get("key_id").and_then(|id| id.parse::<u8>().ok()),
        keys(&values),
    ) else {
        eprintln!("the settings file needs kem_seed, key_id, the four seeds, and a valid key set");
        return ExitCode::from(2);
    };
    let epoch_seconds = match values.get("epoch_seconds") {
        Some(text) => match text.parse::<u64>() {
            Ok(seconds) if seconds > 0 => seconds,
            _ => {
                eprintln!("epoch_seconds does not parse");
                return ExitCode::from(2);
            }
        },
        None => DIRECTORY_EPOCH,
    };
    let pair = gateway_pair(&seed);
    let mut directory = match Directory::new(keys, epoch_seconds, username_case_mapped) {
        Ok(directory) => directory,
        Err(_) => {
            eprintln!("the keys do not load");
            return ExitCode::from(2);
        }
    };
    if let Some(chain) = values.get("keyset_chain") {
        let chain: Option<Vec<Vec<u8>>> = chain
            .split(',')
            .map(|text| hex_bytes(text.trim()))
            .collect();
        if chain
            .and_then(|chain| directory.set_keyset_chain(chain).ok())
            .is_none()
        {
            eprintln!("keyset_chain does not end at the key set of the signers");
            return ExitCode::from(2);
        }
    }
    if prints_pins {
        let pins = DirectoryPins {
            key_config: ohttp::encode_key_config(key_id, pair.public()).to_vec(),
            keyset,
            vrf_public: *directory.vrf_public(),
            voprf_public: *directory.voprf_public(),
        };
        let Ok(bytes) = pins.encode() else {
            return ExitCode::from(1);
        };
        println!("{}", hex_text(&bytes));
        return ExitCode::SUCCESS;
    }
    let (Some(listen), Some(cert), Some(key), Some(store)) = (
        values.get("listen"),
        values.get("cert"),
        values.get("key"),
        values.get("store"),
    ) else {
        eprintln!("the settings file needs listen, cert, key, and store");
        return ExitCode::from(2);
    };
    let Some(tls) = tls_acceptor(cert, key) else {
        eprintln!("the certificate or the key does not load");
        return ExitCode::from(2);
    };
    let store: Box<dyn DirectoryStore> = match SqliteDirectoryStore::open(store) {
        Ok(store) => Box::new(store),
        Err(_) => {
            eprintln!("the store file does not open");
            return ExitCode::from(1);
        }
    };
    let Ok(listener) = TcpListener::bind(listen).await else {
        eprintln!("the listen address does not bind");
        return ExitCode::from(1);
    };
    println!("directory listen={listen} key_id={key_id} epoch_seconds={epoch_seconds}");
    match run_directory(listener, tls, Gateway { key_id, pair }, directory, store).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("the store does not load");
            ExitCode::from(1)
        }
    }
}
