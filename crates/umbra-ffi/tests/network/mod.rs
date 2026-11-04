//! The network of a test over real sockets: signed relays on localhost, and
//! the set of relays that a transfer task of a client reads. The targets
//! `app` and `throughput` share this module.

use std::{future::Future, sync::Arc, time::Duration};

use tokio::{net::TcpListener, sync::mpsc};
use umbra_core::{
    abuse::pow::ChallengeBook,
    attach::place::AttachmentRelay,
    directory::{
        authority::{
            entry_of, keyset_bytes_with, sign_manifest_under, Admission, Listing, GENESIS_ROOT,
        },
        bloc::BlocList,
        descriptor::{roles, RelayDescriptor, RelayEntry, HOST_LEN},
        manifest::{ListedRelay, RelayManifest, RelaySet},
        root::{Consensus, DirectoryKeySet},
    },
    session::node::{ClientNode, RelayInfo},
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    secret::Secret,
    sign::SigningKey,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_ffi::transfers::{run_transfers, TransferCommand, TransferUpdate};
use umbra_relay::{
    busy::BusyGauge,
    node::{Config as RelayConfig, RelayNode},
    placement::placement,
    server::{run_relay, tls_acceptor, Carried, OhttpForward, OsRng},
    store::{MemoryStore, RelayStore},
};
use umbra_transport::{
    https::Url,
    native::{self, ClientConfig},
    ndr::NdrRoute,
    Dial,
};

pub const PACING_MEAN_MS: u64 = 20;

pub const CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/ca.pem"
);
pub const LEAF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/leaf.pem"
);
pub const LEAF_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/leaf.key"
);

/// The values of a signed network that a measurement sets.
pub struct Tuning {
    /// `PACING_MEAN`. A test passes less than a deployment.
    pub pacing_mean_ms: u64,
    /// The chunk store of each relay.
    pub chunk_capacity: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            pacing_mean_ms: PACING_MEAN_MS,
            chunk_capacity: 1 << 26,
        }
    }
}

pub fn relay_static(number: u8) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([number; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [0x10 + number; 32],
    };
    (relay, secret)
}

/// The NDR of a test: its port, and its key id and gateway key.
pub struct TestNdr {
    pub port: u16,
    pub key_id: u8,
    pub gateway: umbra_crypto::kem::PublicKey,
}

/// What one relay of a test carries: the OHTTP relay role at layer 1 and
/// the route of the pushes at layer 3, when an NDR runs.
pub fn carried_of(
    layer: u8,
    ports: &[u16],
    ndr: Option<&TestNdr>,
    tls: &Arc<native::ClientConfig>,
) -> Carried {
    let Some(ndr) = ndr else {
        return Carried::default();
    };
    match layer {
        1 => Carried {
            ohttp: Some(OhttpForward {
                gateway: Url::parse(&format!("https://localhost:{}/gateway", ndr.port)).unwrap(),
                tls: tls.clone(),
            }),
            ..Carried::default()
        },
        3 => Carried {
            ndr: Some((
                NdrRoute {
                    relay: Url::parse(&format!("https://localhost:{}/ohttp", ports[0])).unwrap(),
                    key_id: ndr.key_id,
                    gateway: ndr.gateway.clone(),
                },
                tls.clone(),
            )),
            ..Carried::default()
        },
        _ => Carried::default(),
    }
}

/// The identity seed of each relay of a signed test network. The first and
/// the sixth relay are the two ingress relays. Under the genesis root the
/// layer function puts the other ones in the layers 2, 3, 2, 3 and 3, thus
/// three relays hold the three copies of a chunk.
pub const IDENTITY_SEEDS: [u8; 7] = [0x65, 0x66, 0x61, 0x68, 0x63, 0x70, 0x62];
pub const SIGNED_LAYERS: [u8; 7] = [1, 2, 3, 2, 3, 1, 3];

/// A network of relays under a signed manifest, on sockets of this machine.
pub struct SignedNetwork {
    pub manifest: Vec<u8>,
    pub keyset: Vec<u8>,
    pub ports: Vec<u16>,
    pub entries: Vec<Vec<u8>>,
    pub authorities: Vec<SigningKey>,
    pub epoch: u64,
    /// The time that the node task of each relay ran, in the order of
    /// [`IDENTITY_SEEDS`].
    pub node_busy: Vec<Arc<BusyGauge>>,
}

pub fn start_signed_network(relays: &tokio::runtime::Runtime) -> SignedNetwork {
    start_signed_network_at(relays, None)
}

/// The same network on given ports, for a test that ends each relay
/// process and starts it again. The keys come from fixed seeds, thus a
/// client of the first network knows each relay of the second.
pub fn start_signed_network_at(
    relays: &tokio::runtime::Runtime,
    at: Option<&[u16]>,
) -> SignedNetwork {
    start_signed_network_with(relays, at, None, None, false)
}

/// The signed network with an NDR: the ingress relays carry its OHTTP
/// requests, and each queue relay pushes through the first of them. A
/// `provisional` network has one operator and one family for each relay,
/// under a key set of one independent authority (Part 3 `NET-340`).
pub fn start_signed_network_with(
    relays: &tokio::runtime::Runtime,
    at: Option<&[u16]>,
    ndr: Option<&TestNdr>,
    directory: Option<u16>,
    provisional: bool,
) -> SignedNetwork {
    let tuning = Tuning::default();
    start_signed_network_tuned(relays, at, ndr, directory, provisional, &tuning)
}

/// The signed network of [`start_signed_network_with`] under `tuning`.
pub fn start_signed_network_tuned(
    relays: &tokio::runtime::Runtime,
    at: Option<&[u16]>,
    ndr: Option<&TestNdr>,
    directory: Option<u16>,
    provisional: bool,
    tuning: &Tuning,
) -> SignedNetwork {
    let owner = |number: u8| if provisional { [1; 32] } else { [number; 32] };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let epoch = now / 3_600;

    // Each relay has a loopback address in a /16 of its own, because a
    // manifest gives no prefix but the one of the address.
    let mut listeners = Vec::new();
    let mut entries = Vec::new();
    let mut identities = Vec::new();
    for (index, seed) in IDENTITY_SEEDS.iter().enumerate() {
        let number = index as u8 + 1;
        let address = [127, number, 0, 1];
        let port = at.and_then(|ports| ports.get(index).copied()).unwrap_or(0);
        let listener = relays
            .block_on(TcpListener::bind((std::net::Ipv4Addr::from(address), port)))
            .unwrap();
        let (relay, static_secret) = relay_static(number);
        let mut host = [0u8; HOST_LEN];
        host[..9].copy_from_slice(b"localhost");
        let is_ingress = SIGNED_LAYERS[index] == 1;
        let descriptor = RelayDescriptor {
            relay_id: [0; 32],
            identity_pk: &[],
            ntor_pk: relay.s,
            addr_v4: address,
            addr_v6: [0; 16],
            port: listener.local_addr().unwrap().port(),
            host,
            asn: 64_500 + u32::from(number),
            jurisdiction: [b'Z', b'A' + number],
            family_id: owner(number),
            capacity_class: 2,
            roles: if is_ingress {
                roles::INGRESS_OFFERED | roles::CHAIN
            } else {
                roles::QUEUE | roles::CHAIN | roles::ATTACHMENT
            },
            chunk_store_gib: 0,
            // One epoch back, thus a manifest of that epoch can list it.
            valid_after: epoch - 1,
            sig: &[],
        }
        .sign(&SigningKey::from_seed(Secret::new([*seed; 32])), &mut OsRng)
        .unwrap();

        let listing = Listing {
            descriptor: &descriptor,
            operator_id: owner(number),
            class: 2,
            is_ingress,
        };
        let entry = entry_of(
            &listing,
            Admission::Placed {
                root: GENESIS_ROOT,
                epoch: 0,
            },
        )
        .unwrap();

        let relay_id = RelayEntry::parse(&entry).unwrap().descriptor.relay_id;
        identities.push((relay_id, relay.s, static_secret, *seed));
        entries.push(entry);
        listeners.push(listener);
    }

    let authorities: Vec<SigningKey> = (0..7u8)
        .map(|index| SigningKey::from_seed(Secret::new([0xD0 + index; 32])))
        .collect();

    let keyset = keyset_bytes_with(&authorities, 1, if provisional { 1 } else { 7 }).unwrap();
    let manifest = sign_manifest_under(
        &authorities,
        &keyset,
        &[0, 1, 2, 4, 6],
        epoch,
        entries.clone(),
        &BlocList::v1(),
        &mut OsRng,
    )
    .unwrap();

    // Each relay reads its layer and its next hops from the manifest.
    let client_tls = native::tls_config_with_root_file(CA).unwrap();
    let mut layers = Vec::new();
    let mut node_busy = Vec::new();
    let ports: Vec<u16> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    for (listener, (relay_id, static_key, static_secret, seed)) in
        listeners.into_iter().zip(identities)
    {
        let placed = placement(&manifest, &keyset, &relay_id, &static_key, now).unwrap();
        layers.push(placed.layer);
        let config = RelayConfig {
            relay: RelayStatic {
                s: static_key,
                relay_id,
            },
            static_secret,
            layer: placed.layer,
            chunk_capacity: tuning.chunk_capacity,
        };
        let mut store: Box<dyn RelayStore> = Box::new(MemoryStore::default());
        let mut node = RelayNode::restored(config, store.load().unwrap());

        // WIR-526: a deposit reaches each other queue relay.
        node.set_queue_relays(
            placed
                .queue_relays
                .iter()
                .map(|(id, (_, key))| (*id, *key))
                .collect(),
        );

        // ABU-057, ABU-102: each relay signs its challenge, and the ingress
        // relays carry it beside the manifest.
        node.set_challenge_signer(
            SigningKey::from_seed(Secret::new([seed; 32])),
            placed.carriers.keys().copied().collect(),
        );
        node.set_relay_identities(placed.identities.clone());
        let mut replicas = placed.replicas;
        for (id, (dial, _)) in &placed.queue_relays {
            replicas.entry(*id).or_insert_with(|| dial.clone());
        }
        for (id, dial) in &placed.carriers {
            replicas.entry(*id).or_insert_with(|| dial.clone());
        }
        let mut carried = carried_of(placed.layer, &ports, ndr, &client_tls);
        let busy = Arc::new(BusyGauge::default());
        if let Some(route) = carried.ndr.as_mut() {
            // The first ingress relay has an address of its own here.
            route.0.relay.address = Some(std::net::IpAddr::from([127, 1, 0, 1]));
        }

        // The ingress relay is the carrier of the manifest, and of the
        // requests to the directory (`DIS-162`).
        carried.manifest = std::sync::Mutex::new((placed.layer == 1).then(|| manifest.clone()));
        if placed.layer == 1 {
            carried.directory = directory.map(|port| OhttpForward {
                gateway: Url::parse(&format!("https://localhost:{port}/gateway")).unwrap(),
                tls: client_tls.clone(),
            });
        }
        carried.node_busy = busy.clone();
        node_busy.push(busy);
        relays.spawn(run_relay(
            node,
            listener,
            tls_acceptor(LEAF, LEAF_KEY).unwrap(),
            placed.next,
            replicas,
            client_tls.clone(),
            tuning.pacing_mean_ms,
            store,
            carried,
        ));
    }
    assert_eq!(layers, SIGNED_LAYERS);
    SignedNetwork {
        manifest,
        keyset,
        ports,
        entries,
        authorities,
        epoch,
        node_busy,
    }
}

/// The relay set of a signed network, as a client reads it from the manifest,
/// with the challenges of a fetch.
pub struct TransferSet {
    ingress: ListedRelay,
    others: Vec<ListedRelay>,
    guard: Dial,
    /// The relays that hold chunks.
    pub holders: Vec<AttachmentRelay>,
    book: ChallengeBook,
    now: u64,
    tls: Arc<ClientConfig>,
}

fn info_of(relay: &ListedRelay) -> RelayInfo {
    RelayInfo {
        candidate: relay.candidate,
        key: RelayStatic {
            s: relay.ntor_pk,
            relay_id: relay.candidate.relay_id,
        },
    }
}

impl TransferSet {
    /// Reads the manifest of `network`, and fetches the signed challenges of
    /// its relays on `clients`.
    pub fn read(network: &SignedNetwork, clients: &tokio::runtime::Runtime) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (keyset, _) = DirectoryKeySet::parse(&network.keyset).unwrap();
        let mut consensus = Consensus::new(keyset, 0).unwrap();
        let manifest = RelayManifest::parse(&network.manifest).unwrap();
        let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now).unwrap();

        let ingress = set
            .relays
            .iter()
            .find(|relay| relay.candidate.ingress)
            .unwrap()
            .clone();
        let guard = Dial {
            host: ingress.host.clone(),
            addr_v4: Some(ingress.addr_v4),
            addr_v6: None,
            port: ingress.port,
        };
        let others = set
            .relays
            .iter()
            .filter(|relay| !relay.candidate.ingress)
            .cloned()
            .collect();
        let holders: Vec<AttachmentRelay> = set
            .relays
            .iter()
            .filter(|relay| relay.has_attachment_role && relay.candidate.is_exit())
            .map(|relay| AttachmentRelay {
                relay_id: relay.candidate.relay_id,
                operator_id: relay.candidate.operator_id,
                family_id: relay.candidate.family_id,
            })
            .collect();

        // ABU-106: a registration carries a solution, thus each task takes
        // the signed challenges of the relays first, as a connect fetches
        // them.
        std::thread::sleep(Duration::from_secs(3));
        let tls = native::tls_config_with_root_file(CA).unwrap();
        let bundle = clients
            .block_on(native::fetch_challenges(&guard, tls.clone()))
            .unwrap();

        let mut book = ChallengeBook::default();
        for challenge in ChallengeBook::parse_bundle(&bundle).unwrap() {
            let listed = set
                .relays
                .iter()
                .find(|relay| relay.candidate.relay_id == challenge.verifier_id)
                .unwrap();
            let identity =
                umbra_crypto::sign::VerifyingKey::from_bytes(&listed.identity_pk).unwrap();
            book.take(challenge, &identity, now).unwrap();
        }

        TransferSet {
            ingress,
            others,
            guard,
            holders,
            book,
            now,
            tls,
        }
    }

    /// The transfer task of one device, with a connection of its own, and
    /// its two channels. The task holds the challenges of the fetch.
    pub fn task(
        &self,
        seed: u8,
    ) -> (
        impl Future<Output = ()> + Send + 'static,
        mpsc::UnboundedSender<TransferCommand>,
        mpsc::UnboundedReceiver<TransferUpdate>,
    ) {
        self.task_via(seed, self.guard.clone())
    }

    /// The ingress relay as a client dials it.
    pub fn guard(&self) -> Dial {
        self.guard.clone()
    }

    /// As [`TransferSet::task`], over `guard`: a test puts a shaped link
    /// between the client and the ingress relay there.
    pub fn task_via(
        &self,
        seed: u8,
        guard: Dial,
    ) -> (
        impl Future<Output = ()> + Send + 'static,
        mpsc::UnboundedSender<TransferCommand>,
        mpsc::UnboundedReceiver<TransferUpdate>,
    ) {
        let node = ClientNode::for_transfers(
            info_of(&self.ingress),
            self.others.iter().map(info_of).collect(),
            umbra_crypto::hierarchy::RootIdentity::new(Secret::new([seed; 32])),
        );
        let (commands, task_commands) = mpsc::unbounded_channel();
        let (task_updates, updates) = mpsc::unbounded_channel();
        let task = run_transfers(
            node,
            guard,
            self.tls.clone(),
            self.holders.clone(),
            Arc::default(),
            Arc::default(),
            task_commands,
            task_updates,
        );
        commands
            .send(TransferCommand::Challenges {
                book: self.book.clone(),
                now: self.now,
            })
            .ok()
            .unwrap();

        (task, commands, updates)
    }
}
