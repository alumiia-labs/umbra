//! The Notification Delivery Relay of Part 8 §8.2: the OHTTP gateway that
//! holds the push registrations and posts each push to its provider.
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! listen=0.0.0.0:443
//! cert=/etc/umbra/ndr-cert.pem
//! key=/etc/umbra/ndr-key.pem
//! kem_seed=<64 hex characters>
//! key_id=1
//! store=/var/lib/umbra/ndr.db
//! trust=/etc/umbra/test-authority.pem
//! fcm_credentials=/etc/umbra/fcm-service-account.json
//! ```
//!
//! The seed gives the gateway key, thus a restart keeps the key that each
//! client and each queue relay pins (`NTF-127`). `umbra-ndr key-config
//! <settings>` prints the key configuration for them in hex. The `trust`
//! line is for a test network: the posts to the providers then trust that
//! one authority and not the web roots.
//!
//! The `fcm_credentials` line names the service account file of the
//! Firebase project of the deployment, and the NDR then sends to each FCM
//! token. An `fcm_api` line names another API than FCM, for a test.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, process::ExitCode};

use tokio::net::TcpListener;
use umbra_core::notify::seeded_pair;
use umbra_crypto::{kem::KeyPair, ohttp};
use umbra_relay::{
    fcm::{Fcm, ServiceAccount, FCM_API},
    ndr_server::{run_ndr, Gateway, NdrStore, SqliteNdrStore},
    server::tls_acceptor,
};
use umbra_transport::native;

fn hex32(text: &str) -> Option<[u8; 32]> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}

/// The gateway key of a seed.
fn gateway_pair(seed: &[u8; 32]) -> KeyPair {
    seeded_pair(umbra_crypto::labels::NDR, seed)
}

fn main() -> ExitCode {
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::from(1);
    };
    runtime.block_on(run())
}

async fn run() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (path, prints_config) = match arguments.as_slice() {
        [flag, path] if flag == "key-config" => (path, true),
        [path] => (path, false),
        _ => {
            eprintln!("usage: umbra-ndr <settings file> | key-config <settings file>");
            return ExitCode::from(2);
        }
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("the settings file does not read");
        return ExitCode::from(2);
    };
    let values: BTreeMap<&str, &str> = text
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .collect();
    let (Some(seed), Some(key_id)) = (
        values.get("kem_seed").and_then(|seed| hex32(seed)),
        values.get("key_id").and_then(|id| id.parse::<u8>().ok()),
    ) else {
        eprintln!("the settings file needs kem_seed and key_id");
        return ExitCode::from(2);
    };
    let pair = gateway_pair(&seed);
    if prints_config {
        let config = ohttp::encode_key_config(key_id, pair.public());
        println!(
            "{}",
            config
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
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
    let provider_tls = match values.get("trust") {
        Some(path) => native::tls_config_with_root_file(path),
        None => native::tls_config(),
    };
    let Ok(provider_tls) = provider_tls else {
        eprintln!("the TLS client configuration does not build");
        return ExitCode::from(1);
    };
    let store: Box<dyn NdrStore> = match SqliteNdrStore::open(store) {
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
    // No line of this program names a handle, a token, or an address.
    println!("ndr listen={listen} key_id={key_id}");
    let fcm = match values.get("fcm_credentials") {
        Some(path) => {
            let account = std::fs::read_to_string(path)
                .ok()
                .and_then(|json| ServiceAccount::parse(&json));
            let api = values.get("fcm_api").copied().unwrap_or(FCM_API);
            match account.and_then(|account| Fcm::new(account, api, provider_tls.clone())) {
                Some(fcm) => Some(fcm),
                None => {
                    eprintln!("the FCM service account does not read");
                    return ExitCode::from(2);
                }
            }
        }
        None => None,
    };
    match run_ndr(
        listener,
        tls,
        Gateway { key_id, pair },
        store,
        provider_tls,
        fcm,
        // NTF-134: the reference NDR posts to FCM alone.
        false,
    )
    .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("the store does not load");
            ExitCode::from(1)
        }
    }
}
