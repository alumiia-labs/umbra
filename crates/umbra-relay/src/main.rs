//! The relay server: it reads one settings file, listens on TLS 1.3 with
//! the WebSocket upgrade of Part 6 §6.2.1, and dials the relays of the
//! next layer when a circuit needs one.
//!
//! The settings file holds one `key=value` pair on each line:
//!
//! ```text
//! listen=0.0.0.0:443
//! layer=2
//! relay_id=<64 hex characters>
//! static_secret=<64 hex characters>
//! cert=/etc/umbra/cert.pem
//! key=/etc/umbra/key.pem
//! issuer_modulus=<512 hex characters>
//! community_capacity=1073741824
//! next=<relay_id hex>,<host name>,<IPv4 address>,<port>
//! trust=/etc/umbra/test-authority.pem
//! ```
//!
//! The `next` line repeats, one for each relay of the next layer. The
//! `trust` line is for a test network: the dialer then trusts that one
//! authority and not the web roots. A deployment leaves it out.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, process::ExitCode};

use tokio::net::TcpListener;
use umbra_crypto::{
    handshake::nk::RelayStatic,
    rsabssa::PublicKey2048,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_relay::{
    node::{Config, RelayNode},
    server::{run_relay, tls_acceptor, PACING_MEAN_MS},
};
use umbra_transport::{native, Dial};

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    hex(text)?.try_into().ok()
}

struct Settings {
    listen: String,
    cert: String,
    key: String,
    trust: Option<String>,
    config: Config,
    next: BTreeMap<[u8; 32], Dial>,
}

fn read_settings(path: &str) -> Option<Settings> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    let mut next = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (key, value) = line.split_once('=')?;
        if key != "next" {
            values.insert(key, value);
            continue;
        }
        let mut parts = value.split(',');
        let relay_id = hex32(parts.next()?)?;
        let host = parts.next()?.to_owned();
        let address: std::net::Ipv4Addr = parts.next()?.parse().ok()?;
        let port = parts.next()?.parse().ok()?;
        next.insert(
            relay_id,
            Dial {
                host,
                addr_v4: Some(address.octets()),
                addr_v6: None,
                port,
            },
        );
    }
    let static_secret = StaticSecret::from(hex32(values.get("static_secret")?)?);
    let relay = RelayStatic {
        s: *XPublic::from(&static_secret).as_bytes(),
        relay_id: hex32(values.get("relay_id")?)?,
    };
    Some(Settings {
        listen: (*values.get("listen")?).to_owned(),
        cert: (*values.get("cert")?).to_owned(),
        key: (*values.get("key")?).to_owned(),
        trust: values.get("trust").map(|path| (*path).to_owned()),
        config: Config {
            relay,
            static_secret,
            layer: values
                .get("layer")?
                .parse()
                .ok()
                .filter(|l| (1..=3).contains(l))?,
            issuer_key: PublicKey2048::from_modulus(&hex(values.get("issuer_modulus")?)?).ok()?,
            community_capacity: values.get("community_capacity")?.parse().ok()?,
        },
        next,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: umbra-relay <settings file>");
        return ExitCode::from(2);
    };
    let Some(settings) = read_settings(&path) else {
        eprintln!("the settings file does not parse");
        return ExitCode::from(2);
    };
    let Some(tls) = tls_acceptor(&settings.cert, &settings.key) else {
        eprintln!("the certificate or the key does not load");
        return ExitCode::from(2);
    };
    let Ok(listener) = TcpListener::bind(&settings.listen).await else {
        eprintln!("the listen address does not bind");
        return ExitCode::from(1);
    };

    let client_tls = match &settings.trust {
        Some(path) => native::tls_config_with_root_file(path),
        None => native::tls_config(),
    };
    let Ok(client_tls) = client_tls else {
        eprintln!("the TLS client configuration does not build");
        return ExitCode::from(1);
    };
    // The public half of the identity, for the network record of a client.
    println!(
        "relay_id={} static_key={} layer={} listen={}",
        to_hex(&settings.config.relay.relay_id),
        to_hex(&settings.config.relay.s),
        settings.config.layer,
        settings.listen,
    );
    run_relay(
        RelayNode::new(settings.config),
        listener,
        tls,
        settings.next,
        client_tls,
        PACING_MEAN_MS,
    )
    .await;
    ExitCode::SUCCESS
}
