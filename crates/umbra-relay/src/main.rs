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
//! ```
//!
//! The `next` line repeats, one for each relay of the next layer.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, process::ExitCode, sync::Arc, time::Duration};

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;
use umbra_crypto::{
    handshake::nk::RelayStatic,
    rand_core::TryRng,
    rsabssa::PublicKey2048,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_relay::{
    circuits::LinkId,
    node::{Config, RelayNode},
    server::{run_node, serve_connection, Input, OsRng, Request},
};
use umbra_transport::{
    native,
    race::{Plan, Wire},
    Dial,
};

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    hex(text)?.try_into().ok()
}

struct Settings {
    listen: String,
    cert: String,
    key: String,
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

fn acceptor(cert: &str, key: &str) -> Option<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .ok()?
        .collect::<Result<_, _>>()
        .ok()?;
    let key = PrivateKeyDer::from_pem_file(key).ok()?;
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .ok()?;
    Some(TlsAcceptor::from(Arc::new(config)))
}

/// Dials one relay of the next layer, and moves its capsules until the
/// link closes.
async fn dial(relay_id: [u8; 32], target: Dial, link: LinkId, node: mpsc::Sender<Input>) {
    let mut rng = OsRng;
    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let Ok(tls) = native::tls_config() else {
        return;
    };
    let plan = Plan::Only(Wire::Tcp);
    let Ok(mut connection) =
        native::connect(&target, tls, plan, key, mask, Duration::from_secs(10)).await
    else {
        return;
    };
    let (writer, mut outbound) = mpsc::unbounded_channel::<Vec<u8>>();
    let opened = Input::Dialed {
        link,
        relay_id,
        writer,
    };
    if node.send(opened).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            received = connection.recv() => match received {
                Ok(bytes) => {
                    if node.send(Input::Capsule { link, bytes }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            next = outbound.recv() => match next {
                Some(bytes) if connection.send(&bytes).await.is_ok() => {}
                _ => break,
            },
        }
    }
    let _ = node.send(Input::Closed { link }).await;
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
    let Some(tls) = acceptor(&settings.cert, &settings.key) else {
        eprintln!("the certificate or the key does not load");
        return ExitCode::from(2);
    };
    let Ok(listener) = TcpListener::bind(&settings.listen).await else {
        eprintln!("the listen address does not bind");
        return ExitCode::from(1);
    };

    let (inputs, node_inputs) = mpsc::channel::<Input>(1_024);
    let (requests, mut node_requests) = mpsc::unbounded_channel::<Request>();
    tokio::spawn(run_node(
        RelayNode::new(settings.config),
        node_inputs,
        requests,
    ));

    // Accepted links take the even identifiers, and dialed links the odd.
    let next_hops = settings.next;
    let dial_inputs = inputs.clone();
    tokio::spawn(async move {
        let mut link: LinkId = 1;
        // Each relay of the next layer gets a link at the start, thus the
        // first circuit of a client does not wait for a dial.
        for (relay_id, target) in &next_hops {
            tokio::spawn(dial(*relay_id, target.clone(), link, dial_inputs.clone()));
            link = link.saturating_add(2);
        }
        while let Some(request) = node_requests.recv().await {
            match request {
                Request::Dial(relay_id) => {
                    if let Some(target) = next_hops.get(&relay_id) {
                        tokio::spawn(dial(relay_id, target.clone(), link, dial_inputs.clone()));
                        link = link.saturating_add(2);
                    }
                }
                // The write of a digest needs a circuit of this relay to the
                // queue relay of the subscriber. That sender is not built
                // yet, thus the digest stops here.
                Request::Digest(_) => {}
            }
        }
    });

    let mut link: LinkId = 2;
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let tls = tls.clone();
        let inputs = inputs.clone();
        let this_link = link;
        link = link.saturating_add(2);
        tokio::spawn(async move {
            if let Ok(stream) = tls.accept(tcp).await {
                serve_connection(stream, this_link, inputs).await;
            }
        });
    }
}
