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
//! keyset=/var/lib/umbra/keyset.bin
//! manifest_from=<host name>,<IPv4 address>,<port>
//! ```
//!
//! The `manifest_from` line names the HTTPS carrier of the signer: the
//! relay fetches `/.well-known/umbra/manifest` there each five minutes, and
//! a manifest that verifies and still places the relay takes the place of
//! the file. A rotation of the key set (Part 10 `REL-200`) writes the
//! `keyset` file, thus it sits where the relay may write. The relay also
//! carries the key chain of the signer at `/.well-known/umbra/keychain`.
//!
//! The lines `max_connections=` and `max_conns_per_ip=` change the limits of
//! Part 3 `NET-333` and `NET-334`. A relay of a signed directory applies the
//! second one in each layer and counts no relay of its set. A relay with a
//! `layer` line applies it as an ingress relay alone. A value of 0 turns it
//! off.
//!
//! A test network on one machine can list a relay at an address that names
//! this machine from an emulator, as `10.0.2.2` does. The line
//! `host_alias=10.0.2.2` makes this relay dial `127.0.0.1` in its place,
//! for a relay of the next layer and for a relay that takes a push.
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
//! `roles=<queue,chain,ingress,attachment>`. The descriptor declares the
//! store of the `chunk_capacity` line for a relay with the attachment role.
//! It declares a store of 0 for each other relay (`REL-127`).
//!
//! The `public` line gives the host name of the certificate, the address,
//! and the port that a client dials. The `descriptor` form reads it.
//!
//! The `store` line names the SQLite file of the queues. A relay with no
//! such line keeps its queues in RAM, and a restart of it ends each contact
//! that it served. It says so at its start. The link receipts of the relay
//! go in a second file beside it, with `.receipts` after its name; a relay
//! with no `store` line keeps its newest receipts in RAM.
//!
//! An `ohttp_gateway=https://ndr.example/gateway` line gives the relay the
//! OHTTP relay role of Part 8 §8.2: it forwards each `POST /ohttp` to that
//! gateway of the Notification Delivery Relay. A
//! `directory_gateway=https://directory.example/gateway` line does the same
//! for each `POST /directory`, to the gateway of the directory and the
//! issuer of Part 9 §9.12.
//!
//! A queue relay pushes to the NDR through the OHTTP relay of an
//! `ndr_route=https://relay1.example/ohttp` line, under the gateway key of
//! an `ndr_key_config=<hex>` line, which `umbra-ndr key-config` prints.
//! A relay with neither line sends no push.
//!
//! A relay takes the key of the cross-relay issuer of each epoch from the
//! log of Part 9 §9.5 through the directory route of a
//! `directory_route=https://relay1.example/directory` line, under the pins
//! of a `directory_pins=<hex>` line, which `umbra-directory pins` prints. A
//! relay with neither line admits no cross-relay token (Part 13 §13.5).
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
    ohttp,
    secret::Secret,
    sign::SigningKey,
    x25519::{PublicKey as XPublic, StaticSecret},
    zeroize::Zeroizing,
};
use umbra_relay::{
    node::{Config, RelayNode},
    placement::placement,
    server::{
        run_relay, tls_acceptor, Carried, ConnectionLimits, ManifestSource, OhttpForward, OsRng,
        PACING_MEAN_MS,
    },
    sqlite_store::{SqliteShelf, SqliteStore},
    store::{MemoryStore, RelayStore},
};
use umbra_transport::{https, native, ndr::NdrRoute, Dial};

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

/// A secret of 32 bytes from its hex form. The bytes go into one buffer and
/// into no list on the way. `Zeroizing` wipes that buffer when it leaves
/// memory.
fn secret32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
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
    /// The static key of each queue relay, for the deposit of a digest.
    queue_keys: BTreeMap<[u8; 32], [u8; 32]>,
    /// The carriers of the manifest, which take the challenge of this
    /// relay (Part 13 `ABU-102`).
    carriers: Vec<[u8; 32]>,
    /// The identity key of each relay, for a challenge that this relay
    /// carries (`ABU-103`).
    identities: BTreeMap<[u8; 32], Vec<u8>>,
    /// The key that signs the descriptor of this relay.
    identity: Option<SigningKey>,
    /// The manifest that gave this relay its place. The relay serves it to
    /// a client that asks over HTTPS (Part 3 §3.10).
    manifest: Option<Vec<u8>>,
    /// The file of the manifest, which the relay reads again for a newer
    /// one to serve.
    manifest_source: Option<ManifestSource>,
    /// The gateway of the NDR, for a relay with the OHTTP relay role.
    ohttp_gateway: Option<https::Url>,
    /// The gateway of the directory and the issuer.
    directory_gateway: Option<https::Url>,
    /// The pinned route to the NDR, for the pushes of a queue relay.
    ndr_route: Option<NdrRoute>,
    /// The route to the log and its pins, for the keys of the issuer.
    directory_read: Option<(https::Url, umbra_core::discovery::dirclient::DirectoryPins)>,
    /// What this relay declares of itself for a network descriptor: the
    /// operator, the country, the autonomous system, and the IPv4 /16.
    facts: BTreeMap<String, String>,
    /// The limits of the connections (Part 3 `NET-333` to `NET-335`).
    limits: ConnectionLimits,
    /// The relays of the layer before, from the manifest (`REL-174`).
    previous: Option<std::collections::BTreeSet<[u8; 32]>>,
    /// The address of each relay of the set, which the cap of one address
    /// does not count (`NET-334`).
    addresses: std::collections::BTreeSet<std::net::IpAddr>,
    /// The address that names this machine in a test network.
    host_alias: Option<[u8; 4]>,
}

/// The lines that a settings file can hold.
const KNOWN_LINES: [&str; 31] = [
    "listen",
    "layer",
    "relay_id",
    "static_secret",
    "cert",
    "key",
    "chunk_capacity",
    "next",
    "trust",
    "store",
    "public",
    "identity_seed",
    "manifest",
    "keyset",
    "manifest_from",
    "max_connections",
    "max_conns_per_ip",
    "host_alias",
    "ohttp_gateway",
    "directory_gateway",
    "ndr_route",
    "ndr_key_config",
    "directory_route",
    "directory_pins",
    "operator",
    "country",
    "asn",
    "prefix",
    "family",
    "class",
    "roles",
];

/// Says when each user of the machine can read the settings file, which
/// holds the two secrets of the relay.
#[cfg(unix)]
fn warn_of_open_file(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let is_open = std::fs::metadata(path).is_ok_and(|file| file.permissions().mode() & 0o004 != 0);
    if is_open {
        eprintln!("each user of this machine can read the settings file, which holds secrets");
    }
}

#[cfg(not(unix))]
fn warn_of_open_file(_path: &str) {}

/// A carrier line: `<host name>,<IPv4 address>,<port>`.
fn dial_of(value: &str) -> Option<Dial> {
    let mut parts = value.split(',');
    let host = parts.next()?.to_owned();
    let address: std::net::Ipv4Addr = parts.next()?.parse().ok()?;
    let port = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(Dial {
        host,
        addr_v4: Some(address.octets()),
        addr_v6: None,
        port,
    })
}

/// Reads the settings file. With `takes_place` the relay reads its layer
/// from the manifest, when the file names one.
fn read_settings(path: &str, takes_place: bool) -> Option<Settings> {
    // The text holds the two secrets of the relay, thus `Zeroizing` wipes
    // it when this call ends.
    let text = Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    let mut next = BTreeMap::new();
    // A line that starts with `#` is a comment, thus the output of `keygen`
    // pastes as it is.
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (key, value) = line.split_once('=')?;
        // Before this, the relay said nothing of a line that it does not
        // know. A wrong letter in `store=` then left the queues in RAM.
        if !KNOWN_LINES.contains(&key) {
            eprintln!("the settings file holds a line that this relay does not know: {key}");
        }
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
    let static_secret = StaticSecret::from(*secret32(values.get("static_secret")?)?);
    let identity = match values.get("identity_seed") {
        Some(seed) => Some(SigningKey::from_seed(Secret::new(*secret32(seed)?))),
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
            let path = std::path::Path::new(manifest);
            let manifest = std::fs::read(path).ok()?;
            let keyset = std::fs::read(keyset).ok()?;
            let place =
                |manifest: &[u8]| placement(manifest, &keyset, &relay.relay_id, &relay.s, now);
            let placed = match place(&manifest) {
                Ok(placed) => (placed, manifest),
                Err(cause) => {
                    // REL-200: a stop between the write of a new key set
                    // and the rename of its manifest leaves that manifest
                    // beside the file. It takes its place here, when it
                    // places this relay under the key set of the file.
                    let part = path.with_extension("part");
                    let waiting = std::fs::read(&part).ok();
                    let mended = waiting
                        .and_then(|waiting| Some((place(&waiting).ok()?, waiting)))
                        .filter(|_| std::fs::rename(&part, path).is_ok());
                    let Some(mended) = mended else {
                        eprintln!("the manifest gives this relay no place: {cause:?}");
                        return None;
                    };
                    mended
                }
            };
            // REL-035: a root past its validity still gives the place of
            // this relay, because the relay fetches the next one only when
            // it runs. A client takes no such root, thus the operator
            // learns of it here.
            if now > placed.0.valid_until {
                eprintln!("the manifest is past its validity, and no client takes it");
            }
            Some(placed)
        }
        (None, None) => None,
        _ => return None,
    };
    let (placed, manifest) = placed.unzip();
    let manifest_source = match (values.get("manifest"), values.get("keyset"), &manifest) {
        (Some(path), Some(keyset), Some(_)) => Some(ManifestSource {
            path: std::path::PathBuf::from(path),
            keyset: std::sync::Mutex::new(std::fs::read(keyset).ok()?),
            keyset_path: std::path::PathBuf::from(keyset),
            relay_id: relay.relay_id,
            s: relay.s,
            fetch: match values.get("manifest_from") {
                Some(carrier) => Some(dial_of(carrier)?),
                None => None,
            },
        }),
        _ => None,
    };
    let layer = match &placed {
        Some(placed) => placed.layer,
        None if !takes_place => 0,
        None => values
            .get("layer")?
            .parse()
            .ok()
            .filter(|l| (1..=3).contains(l))?,
    };
    let is_placed = placed.is_some();
    // NET-332: a relay of layer 1 or 2 with no identity key sends no hello.
    // The next layer takes no circuit of a relay that it cannot name.
    if is_placed && identity.is_none() && layer < 3 {
        eprintln!("no identity_seed line: the next layer takes no circuit of this relay");
    }
    let (previous, addresses) = match &placed {
        Some(placed) => (Some(placed.previous.clone()), placed.addresses.clone()),
        None => (None, std::collections::BTreeSet::new()),
    };
    let (mut next, mut replicas, queue_relays, carriers, identities) = match placed {
        Some(placed) => (
            placed.next,
            placed.replicas,
            placed.queue_relays,
            placed.carriers,
            placed.identities,
        ),
        None => (
            next,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        ),
    };
    // ABU-102: a challenge goes on the same one-shot connection as a copy.
    for (relay_id, dial) in &carriers {
        replicas.entry(*relay_id).or_insert_with(|| dial.clone());
    }
    let carriers = carriers.into_keys().collect();
    // WIR-526: a deposit goes on the same one-shot connection as a copy.
    for (relay_id, (dial, _)) in &queue_relays {
        replicas.entry(*relay_id).or_insert_with(|| dial.clone());
    }
    // A relay that the manifest lists at the alias of this machine is on
    // this machine.
    let host_alias = match values.get("host_alias") {
        Some(alias) => Some(alias.parse::<std::net::Ipv4Addr>().ok()?.octets()),
        None => None,
    };
    umbra_relay::server::dial_at_alias(&mut replicas, host_alias);
    umbra_relay::server::dial_at_alias(&mut next, host_alias);
    let queue_keys = queue_relays
        .into_iter()
        .map(|(relay_id, (_, key))| (relay_id, key))
        .collect();
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
            // A relay with no such line has no attachment role.
            chunk_capacity: match values.get("chunk_capacity") {
                Some(bytes) => bytes.parse().ok()?,
                None => 0,
            },
        },
        next,
        replicas,
        queue_keys,
        carriers,
        identities,
        identity,
        manifest,
        manifest_source,
        previous,
        addresses,
        host_alias,
        // NET-334: the cap of one address counts no relay of the set, thus
        // a relay of a signed directory applies it in each layer. A relay
        // with a `layer` line knows no set, thus it applies the cap as an
        // ingress relay alone. A relay of another layer takes a connection
        // for each push of another relay.
        limits: ConnectionLimits {
            max_connections: match values.get("max_connections") {
                Some(count) => count.parse().ok()?,
                None => ConnectionLimits::CONN_MAX,
            },
            per_ip_max: match (layer == 1 || is_placed, values.get("max_conns_per_ip")) {
                (true, Some(count)) => count.parse().ok()?,
                (true, None) => ConnectionLimits::CONN_PER_IP,
                _ => 0,
            },
            ..ConnectionLimits::default()
        },
        ohttp_gateway: match values.get("ohttp_gateway") {
            Some(url) => Some(https::Url::parse(url)?),
            None => None,
        },
        directory_gateway: match values.get("directory_gateway") {
            Some(url) => Some(https::Url::parse(url)?),
            None => None,
        },
        ndr_route: match (values.get("ndr_route"), values.get("ndr_key_config")) {
            (Some(url), Some(config)) => {
                let (key_id, gateway) = ohttp::parse_key_config(&hex(config)?).ok()?;
                Some(NdrRoute {
                    relay: https::Url::parse(url)?,
                    key_id,
                    gateway,
                })
            }
            (None, None) => None,
            _ => return None,
        },
        directory_read: match (values.get("directory_route"), values.get("directory_pins")) {
            (Some(url), Some(pins)) => Some((
                https::Url::parse(url)?,
                umbra_core::discovery::dirclient::DirectoryPins::parse(&hex(pins)?).ok()?,
            )),
            (None, None) => None,
            _ => return None,
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
    let mut identity_seed = Zeroizing::new([0u8; 32]);
    let mut static_secret = Zeroizing::new([0u8; 32]);
    if getrandom::fill(identity_seed.as_mut_slice()).is_err()
        || getrandom::fill(static_secret.as_mut_slice()).is_err()
    {
        eprintln!("the operating system gave no random bytes");
        return ExitCode::from(1);
    }
    let identity = SigningKey::from_seed(Secret::new(*identity_seed));
    // `Zeroizing` wipes the hex form of each secret after its line.
    println!(
        "identity_seed={}",
        Zeroizing::new(to_hex(identity_seed.as_slice())).as_str()
    );
    println!(
        "static_secret={}",
        Zeroizing::new(to_hex(static_secret.as_slice())).as_str()
    );
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

/// The `chunk_store_gib` of a descriptor with the roles `role_bits`
/// (`REL-127`, `ATT-087`): the store that the relay holds for chunks, in
/// whole GiB. It is 0 for a relay without the attachment role, whatever its
/// settings file says.
fn declared_store_gib(role_bits: u8, chunk_capacity: u64) -> u32 {
    if role_bits & roles::ATTACHMENT == 0 {
        return 0;
    }
    u32::try_from(chunk_capacity >> 30).unwrap_or(u32::MAX)
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
        chunk_store_gib: declared_store_gib(role_bits, settings.config.chunk_capacity),
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
    warn_of_open_file(path);
    // The `descriptor` form prints the layer of a relay that the manifest
    // places. The line of a relay comes before the first manifest that lists
    // it. The form thus also reads a settings file whose manifest gives no
    // place, and it then prints layer 0.
    let is_line = matches!(arguments.as_slice(), ["descriptor", _]);
    let settings = read_settings(path, takes_place)
        .or_else(|| is_line.then(|| read_settings(path, false)).flatten());
    let Some(settings) = settings else {
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
    // REL-073: the receipts of RECEIPT_RETENTION outgrow RAM on a busy relay.
    let shelf = match &settings.store {
        Some(path) => match SqliteShelf::open(&format!("{path}.receipts")) {
            Ok(shelf) => Some(shelf),
            Err(_) => {
                eprintln!("the receipt file does not open");
                return ExitCode::from(1);
            }
        },
        None => None,
    };
    println!(
        "queues={} invitations={}",
        loaded.queues.len(),
        loaded.invitations.len()
    );
    run_relay(
        {
            let mut node = RelayNode::restored(settings.config, loaded);
            node.set_queue_relays(settings.queue_keys);
            if let Some(shelf) = shelf {
                node.set_receipt_shelf(Box::new(shelf));
            }
            // ABU-057, ABU-102: the identity key signs the challenge of each
            // period, and the carriers of the manifest serve it.
            if let Some(identity) = settings.identity {
                node.set_challenge_signer(identity, settings.carriers);
            }
            node.set_relay_identities(settings.identities);
            // REL-174: a relay outside the layer before names no peer.
            if let Some(previous) = settings.previous {
                node.set_previous_layer(previous);
            }
            node
        },
        listener,
        tls,
        settings.next,
        settings.replicas,
        client_tls.clone(),
        PACING_MEAN_MS,
        store,
        Carried {
            manifest: std::sync::Mutex::new(settings.manifest),
            manifest_source: settings.manifest_source,
            // NTF-127: the OHTTP relay role posts to the gateway of the NDR.
            ohttp: settings.ohttp_gateway.map(|gateway| OhttpForward {
                gateway,
                tls: client_tls.clone(),
            }),
            // DIS-162: the directory and the issuer take the same role.
            directory: settings.directory_gateway.map(|gateway| OhttpForward {
                gateway,
                tls: client_tls.clone(),
            }),
            // NTF-127: the route of the pushes of this queue relay.
            ndr: settings.ndr_route.map(|route| (route, client_tls.clone())),
            issuer_reader: std::sync::Mutex::new(settings.directory_read.and_then(
                |(relay, pins)| {
                    let (key_id, gateway) = ohttp::parse_key_config(&pins.key_config).ok()?;
                    let route = NdrRoute {
                        relay,
                        key_id,
                        gateway,
                    };
                    Some(umbra_relay::issuer_keys::IssuerReader::new(
                        route,
                        pins,
                        client_tls.clone(),
                    ))
                },
            )),
            limits: settings.limits,
            relay_addresses: std::sync::Mutex::new(settings.addresses),
            host_alias: settings.host_alias,
            ..Carried::default()
        },
    )
    .await;
    // A relay serves until a signal ends it, thus a return is a fault: the
    // listener failed, or the store took no commit. A supervisor restarts
    // it on this status.
    eprintln!("the relay stopped");
    ExitCode::from(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_reads_from_64_hex_characters_alone() {
        assert_eq!(*secret32(&"a5".repeat(32)).unwrap(), [0xA5; 32]);
        assert_eq!(secret32(&"A5".repeat(32)).as_deref(), Some(&[0xA5; 32]));
        assert!(secret32(&"a5".repeat(31)).is_none());
        assert!(secret32(&"a5".repeat(33)).is_none());
        assert!(secret32(&"zz".repeat(32)).is_none());
    }

    /// The descriptor that `sign-descriptor` makes for a settings file with
    /// the roles `relay_roles` and a `chunk_capacity` line of 8 GiB.
    fn descriptor_of(relay_roles: &str) -> Vec<u8> {
        let path = std::env::temp_dir().join(format!(
            "umbra-relay-test-{}-{}.conf",
            std::process::id(),
            relay_roles.replace(',', "-"),
        ));
        let text = format!(
            "listen=127.0.0.1:0\ncert=cert.pem\nkey=key.pem\n\
             identity_seed={seed}\nstatic_secret={secret}\n\
             chunk_capacity={capacity}\npublic=relay.example.org,203.0.113.7,443\n\
             country=US\nasn=64500\nfamily={family}\nclass=1\nroles={relay_roles}\n",
            seed = "11".repeat(32),
            secret = "22".repeat(32),
            family = "33".repeat(32),
            capacity = 8u64 << 30,
        );
        std::fs::write(&path, text).unwrap();
        let settings = read_settings(path.to_str().unwrap(), false);
        let _ = std::fs::remove_file(&path);
        signed_descriptor(&settings.unwrap()).unwrap()
    }

    #[test]
    fn a_relay_without_the_attachment_role_declares_no_chunk_store() {
        std::thread::Builder::new()
            .stack_size(STACK_BYTES)
            .spawn(|| {
                // REL-127: the capacity line of a chain relay declares nothing.
                let chain = descriptor_of("chain");
                let chain = RelayDescriptor::parse(&chain).unwrap();
                assert_eq!(chain.roles & roles::ATTACHMENT, 0);
                assert_eq!(chain.chunk_store_gib, 0);
                // ATT-087: a relay with the role declares its store.
                let exit = descriptor_of("queue,chain,attachment");
                let exit = RelayDescriptor::parse(&exit).unwrap();
                assert_ne!(exit.roles & roles::ATTACHMENT, 0);
                assert_eq!(exit.chunk_store_gib, 8);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn the_declared_store_is_whole_gib_and_never_wraps() {
        assert_eq!(declared_store_gib(roles::ATTACHMENT, (1 << 30) - 1), 0);
        assert_eq!(declared_store_gib(roles::ATTACHMENT, 1 << 30), 1);
        assert_eq!(declared_store_gib(roles::ATTACHMENT, u64::MAX), u32::MAX);
        assert_eq!(declared_store_gib(roles::QUEUE | roles::CHAIN, u64::MAX), 0);
    }
}
