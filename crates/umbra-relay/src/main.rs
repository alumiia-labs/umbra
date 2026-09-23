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
//! chunk_capacity=107374182400
//! next=<relay_id hex>,<host name>,<IPv4 address>,<port>
//! trust=/etc/umbra/test-authority.pem
//! store=/var/lib/umbra/relay.db
//! public=relay1.example.org,203.0.113.7,443
//! ```
//!
//! A relay of a signed directory (Part 10) has these lines in the place of
//! `layer`, `relay_id` and `next`:
//!
//! ```text
//! identity_seed=<64 hex characters>
//! manifest=/var/lib/umbra/manifest.bin
//! keyset=/etc/umbra/keyset.bin
//! ```
//!
//! The identity seed gives the ML-DSA-65 key that signs the descriptor, and
//! `relay_id` is the hash of its public half. The manifest gives the layer
//! of this relay and each relay of the next layer.
//!
//! More forms of the command line help an operator:
//!
//! ```text
//! umbra-relay keygen                            # a new identity
//! umbra-relay descriptor <settings>             # the line of this relay for a client
//! umbra-relay sign-descriptor <settings> <file> # the descriptor for the authorities
//! ```
//!
//! The `sign-descriptor` form reads `public`, `country` and `asn`, and also
//! `family=<64 hex characters>`, `class=<0 to 3>` and
//! `roles=<queue,chain,ingress,attachment>`.
//!
//! The `public` line gives the host name of the certificate, the address,
//! and the port that a client dials. The `descriptor` form reads it.
//!
//! The `store` line names the SQLite file of the queues. A relay with no
//! such line keeps its queues in RAM, and a restart of it ends each contact
//! that it served. It says so at its start.
//!
//! An `ohttp_gateway=https://ndr.example/gateway` line gives the relay the
//! OHTTP relay role of Part 8 §8.2: it forwards each `POST /ohttp` to that
//! gateway of the Notification Delivery Relay.
//!
//! The `next` line repeats, one for each relay of the next layer. The
//! `trust` line is for a test network: the dialer then trusts that one
//! authority and not the web roots. A deployment leaves it out.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, process::ExitCode};

use tokio::net::TcpListener;
use umbra_core::directory::{
    descriptor::{roles, RelayDescriptor, HOST_LEN},
    EPOCH_SECONDS,
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hash::sha3_256,
    rsabssa::PublicKey2048,
    secret::Secret,
    sign::SigningKey,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_relay::{
    node::{Config, RelayNode},
    placement::placement,
    server::{run_relay, tls_acceptor, Carried, OhttpForward, OsRng, PACING_MEAN_MS},
    sqlite_store::SqliteStore,
    store::{MemoryStore, RelayStore},
};
use umbra_transport::{https, native, Dial};

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
    store: Option<String>,
    public: Option<String>,
    config: Config,
    next: BTreeMap<[u8; 32], Dial>,
    /// Each other relay with the attachment role, from the manifest.
    replicas: BTreeMap<[u8; 32], Dial>,
    /// The key that signs the descriptor of this relay.
    identity: Option<SigningKey>,
    /// The manifest that gave this relay its place. The relay serves it to
    /// a client that asks over HTTPS (Part 3 §3.10).
    manifest: Option<Vec<u8>>,
    /// The gateway of the NDR, for a relay with the OHTTP relay role.
    ohttp_gateway: Option<https::Url>,
    /// What this relay declares of itself for a network descriptor: the
    /// operator, the country, the autonomous system, and the IPv4 /16.
    facts: BTreeMap<String, String>,
}

/// Reads the settings file. With `takes_place` the relay reads its layer
/// from the manifest, when the file names one.
fn read_settings(path: &str, takes_place: bool) -> Option<Settings> {
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
    let identity = match values.get("identity_seed") {
        Some(seed) => Some(SigningKey::from_seed(Secret::new(hex32(seed)?))),
        None => None,
    };
    // The identity key gives the identifier (`REL-049`). A settings file
    // with the two lines must not name another one.
    let derived = identity
        .as_ref()
        .map(|key| sha3_256(&[&key.verifying_key().to_bytes()]));
    let written = match values.get("relay_id") {
        Some(text) => Some(hex32(text)?),
        None => None,
    };
    if derived.is_some() && written.is_some() && derived != written {
        return None;
    }
    let relay = RelayStatic {
        s: *XPublic::from(&static_secret).as_bytes(),
        relay_id: derived.or(written)?,
    };
    // The manifest gives the layer and the next hops, and the settings file
    // then gives neither.
    let placed = match (values.get("manifest"), values.get("keyset")) {
        (Some(_), Some(_)) if values.contains_key("layer") || !next.is_empty() => return None,
        // The descriptor of a relay comes before the first manifest that
        // lists it, thus that form of the command line reads no manifest.
        (Some(_), Some(_)) if !takes_place => None,
        (Some(manifest), Some(keyset)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            let manifest = std::fs::read(manifest).ok()?;
            let keyset = std::fs::read(keyset).ok()?;
            match placement(&manifest, &keyset, &relay.relay_id, &relay.s, now) {
                Ok(placed) => Some((placed, manifest)),
                Err(cause) => {
                    eprintln!("the manifest gives this relay no place: {cause:?}");
                    return None;
                }
            }
        }
        (None, None) => None,
        _ => return None,
    };
    let (placed, manifest) = placed.unzip();
    let layer = match &placed {
        Some(placed) => placed.layer,
        None if !takes_place => 0,
        None => values
            .get("layer")?
            .parse()
            .ok()
            .filter(|l| (1..=3).contains(l))?,
    };
    let (next, replicas) = match placed {
        Some(placed) => (placed.next, placed.replicas),
        None => (next, BTreeMap::new()),
    };
    Some(Settings {
        listen: (*values.get("listen")?).to_owned(),
        cert: (*values.get("cert")?).to_owned(),
        key: (*values.get("key")?).to_owned(),
        trust: values.get("trust").map(|path| (*path).to_owned()),
        store: values.get("store").map(|path| (*path).to_owned()),
        public: values.get("public").map(|value| (*value).to_owned()),
        config: Config {
            relay,
            static_secret,
            layer,
            issuer_key: PublicKey2048::from_modulus(&hex(values.get("issuer_modulus")?)?).ok()?,
            community_capacity: values.get("community_capacity")?.parse().ok()?,
            // A relay with no such line has no attachment role.
            chunk_capacity: match values.get("chunk_capacity") {
                Some(bytes) => bytes.parse().ok()?,
                None => 0,
            },
        },
        next,
        replicas,
        identity,
        manifest,
        ohttp_gateway: match values.get("ohttp_gateway") {
            Some(url) => Some(https::Url::parse(url)?),
            None => None,
        },
        facts: [
            "operator", "country", "asn", "prefix", "family", "class", "roles",
        ]
        .iter()
        .filter_map(|name| Some(((*name).to_owned(), (*values.get(name)?).to_owned())))
        .collect(),
    })
}

/// Prints a new identity for a settings file. The secrets show on the
/// terminal of the operator one time, and no file of this program holds
/// them.
fn keygen() -> ExitCode {
    let mut identity_seed = [0u8; 32];
    let mut static_secret = [0u8; 32];
    if getrandom::fill(&mut identity_seed).is_err() || getrandom::fill(&mut static_secret).is_err()
    {
        eprintln!("the operating system gave no random bytes");
        return ExitCode::from(1);
    }
    let identity = SigningKey::from_seed(Secret::new(identity_seed));
    println!("identity_seed={}", to_hex(&identity_seed));
    println!("static_secret={}", to_hex(&static_secret));
    println!(
        "# relay_id {}",
        to_hex(&sha3_256(&[&identity.verifying_key().to_bytes()]))
    );
    ExitCode::SUCCESS
}

/// Writes the signed descriptor of this relay (`REL-047`, `REL-048`) to
/// `out`. The operator gives that file to the directory authorities.
fn sign_descriptor(settings: &Settings, out: &str) -> ExitCode {
    let Some(bytes) = signed_descriptor(settings) else {
        eprintln!(
            "the settings file needs: identity_seed=, public=<host>,<IPv4 address>,<port>, \
             country=, asn=, family=<64 hex characters>, class=<0 to 3>, \
             roles=<queue,chain,ingress,attachment>"
        );
        return ExitCode::from(2);
    };
    if std::fs::write(out, bytes).is_err() {
        eprintln!("the descriptor file does not write");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn signed_descriptor(settings: &Settings) -> Option<Vec<u8>> {
    let identity = settings.identity.as_ref()?;
    let [name, address, port]: [&str; 3] = settings
        .public
        .as_deref()?
        .split(',')
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    let mut host = [0u8; HOST_LEN];
    host.get_mut(..name.len())?.copy_from_slice(name.as_bytes());
    let fact = |name: &str| settings.facts.get(name).map(String::as_str);
    let mut role_bits = 0u8;
    for role in fact("roles")?.split(',') {
        role_bits |= match role {
            "queue" => roles::QUEUE,
            "chain" => roles::CHAIN,
            "ingress" => roles::INGRESS_OFFERED,
            "attachment" => roles::ATTACHMENT,
            _ => return None,
        };
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    RelayDescriptor {
        relay_id: [0; 32],
        identity_pk: &[],
        ntor_pk: settings.config.relay.s,
        addr_v4: address.parse::<std::net::Ipv4Addr>().ok()?.octets(),
        addr_v6: [0; 16],
        port: port.parse().ok()?,
        host,
        asn: fact("asn")?.parse().ok()?,
        jurisdiction: fact("country")?.as_bytes().try_into().ok()?,
        family_id: hex32(fact("family")?)?,
        capacity_class: fact("class")?.parse().ok()?,
        roles: role_bits,
        chunk_store_gib: 0,
        valid_after: now / EPOCH_SECONDS,
        sig: &[],
    }
    .sign(identity, &mut OsRng)
    .ok()
}

/// Prints the line of this relay in a network descriptor, which holds the
/// public half of its identity and the place that a client dials.
fn descriptor(settings: &Settings) -> ExitCode {
    let parts: Option<[&str; 3]> = settings
        .public
        .as_deref()
        .and_then(|public| public.split(',').collect::<Vec<_>>().try_into().ok());
    let Some([host, address, port]) = parts else {
        eprintln!("the settings file needs a line: public=<host>,<IPv4 address>,<port>");
        return ExitCode::from(2);
    };
    // The facts that a client tests before it puts two relays into one
    // chain (Part 3 §3.4.6). The operator of a relay declares them.
    let facts = ["operator", "country", "asn", "prefix"]
        .iter()
        .filter_map(|name| Some(format!(" {name}={}", settings.facts.get(*name)?)))
        .collect::<String>();
    if ["operator", "country", "asn"]
        .iter()
        .any(|name| !settings.facts.contains_key(*name))
    {
        eprintln!("the settings file needs the lines: operator=, country=, asn=");
        return ExitCode::from(2);
    }
    println!(
        "relay {host} {address} {port} {} {} layer={}{facts}",
        to_hex(&settings.config.relay.s),
        to_hex(&settings.config.relay.relay_id),
        settings.config.layer,
    );
    ExitCode::SUCCESS
}

/// The stack of each thread of this program. An ML-DSA-65 signature needs
/// more than the 1 MiB that the main thread of Windows has.
const STACK_BYTES: usize = 16 << 20;

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

async fn run() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let path = match arguments.as_slice() {
        ["keygen"] => return keygen(),
        ["descriptor", path] | ["sign-descriptor", path, _] | [path] => *path,
        _ => {
            eprintln!(
                "usage: umbra-relay <settings file> | keygen | descriptor <settings file> \
                 | sign-descriptor <settings file> <descriptor file>"
            );
            return ExitCode::from(2);
        }
    };
    let takes_place = !matches!(arguments.as_slice(), ["sign-descriptor", ..]);
    let Some(settings) = read_settings(path, takes_place) else {
        eprintln!("the settings file does not parse");
        return ExitCode::from(2);
    };
    match arguments.as_slice() {
        ["descriptor", _] => return descriptor(&settings),
        ["sign-descriptor", _, out] => return sign_descriptor(&settings, out),
        _ => {}
    }
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
    let mut store: Box<dyn RelayStore> = match &settings.store {
        Some(path) => match SqliteStore::open(path) {
            Ok(store) => Box::new(store),
            Err(_) => {
                eprintln!("the store file does not open, or it has another schema");
                return ExitCode::from(1);
            }
        },
        None => {
            eprintln!("no store line: the queues sit in RAM and end with this process");
            Box::new(MemoryStore::default())
        }
    };
    let Ok(loaded) = store.load() else {
        eprintln!("the store does not load");
        return ExitCode::from(1);
    };
    println!(
        "queues={} invitations={}",
        loaded.queues.len(),
        loaded.invitations.len()
    );
    run_relay(
        RelayNode::restored(settings.config, loaded),
        listener,
        tls,
        settings.next,
        settings.replicas,
        client_tls.clone(),
        PACING_MEAN_MS,
        store,
        Carried {
            manifest: settings.manifest,
            // NTF-127: the OHTTP relay role posts to the gateway of the NDR.
            ohttp: settings.ohttp_gateway.map(|gateway| OhttpForward {
                gateway,
                tls: client_tls.clone(),
            }),
        },
    )
    .await;
    ExitCode::SUCCESS
}
