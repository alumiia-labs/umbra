//! The calls of the Android app, driven from Rust: two handles over SQLite
//! files connect to three relay servers on localhost, one invites, the
//! other accepts, and a draft of each becomes a rendered message of the
//! other.

#![cfg(all(feature = "bindings", feature = "sockets-test"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::net::TcpListener;
use umbra_core::{
    attach::{place::AttachmentRelay, transfer::Shape},
    directory::{
        authority::{entry_of, keyset_bytes, sign_manifest, Admission, Listing, GENESIS_ROOT},
        bloc::BlocList,
        descriptor::{roles, RelayDescriptor, RelayEntry, HOST_LEN},
        manifest::{ListedRelay, RelayManifest, RelaySet},
        root::{Consensus, DirectoryKeySet},
    },
    group::{
        join::{accept_admit, JoinKeys},
        queue::{select_pair, Candidate as GroupRelay},
        receive::Outcome,
        roster::Applied,
        state::{EpochCarrier, Group},
    },
    session::node::{ClientNode, RelayInfo},
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hmac::{digest::KeyInit, Hmac, Mac},
    rsabssa::PublicKey2048,
    secret::Secret,
    sha2::Sha256,
    sign::SigningKey,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_ffi::bindings::{
    fetch_manifest, init, init_linked, init_restored, parse_network, recovery_digits_kind, Config,
    FfiError, FfiEvent, Handle, LinkStatus, MsgHandle, Network, Receipts, RelayEndpoint,
    RestoreStatus, SecureElementCallback, TextSink,
};
use umbra_ffi::groups::{run_groups, GroupCommand, GroupUpdate};
use umbra_ffi::transfers::{run_transfers, TransferCommand, TransferUpdate};
use umbra_relay::{
    ndr_server::{run_ndr, Gateway, MemoryNdrStore},
    node::{Config as RelayConfig, RelayNode},
    placement::placement,
    server::{run_relay, tls_acceptor, Carried, OhttpForward, OsRng},
    sqlite_store::SqliteStore,
    store::{MemoryStore, RelayStore},
};
use umbra_transport::{
    https::{self, Url},
    native,
    ndr::NdrRoute,
    Dial,
};

const PACING_MEAN_MS: u64 = 20;
const HOST: &str = "invite.umbra.test";
const STEP: Duration = Duration::from_secs(20);

/// The turn of a test of several devices of one set.
static DEVICE_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

const CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/ca.pem"
);
const LEAF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/leaf.pem"
);
const LEAF_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/leaf.key"
);

struct Keystore([u8; 32]);

impl SecureElementCallback for Keystore {
    fn keyed(&self, input: Vec<u8>) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).unwrap();
        mac.update(&input);
        mac.finalize().into_bytes().to_vec()
    }
}

#[derive(Default)]
struct View(Mutex<Vec<u16>>);

impl TextSink for View {
    fn put(&self, code_units: Vec<u16>) {
        *self.0.lock().unwrap() = code_units;
    }
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// The layer of each relay of the test network, by its index: one ingress,
/// two relays of layer 2, and two queue relays. Thus the chains of the two
/// apps can differ, and a record can need a circuit to a second queue relay.
const LAYERS: [u8; 5] = [1, 2, 2, 3, 3];

fn relay_static(number: u8) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([number; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [0x10 + number; 32],
    };
    (relay, secret)
}

fn localhost(port: u16) -> Dial {
    Dial {
        host: "localhost".into(),
        addr_v4: Some([127, 0, 0, 1]),
        addr_v6: None,
        port,
    }
}

/// Waits for the first event that `pick` takes, and drops each other one.
#[track_caller]
fn wait_for<T>(handle: &Handle, mut pick: impl FnMut(FfiEvent) -> Option<T>) -> T {
    let start = Instant::now();
    while start.elapsed() < STEP {
        let Some(event) = handle.wait_event(500) else {
            continue;
        };
        // A stop by the application is no fault of the network.
        if let FfiEvent::Offline { cause } = event {
            assert_eq!(cause, 0, "the client went offline");
            continue;
        }
        if let Some(found) = pick(event) {
            return found;
        }
    }
    panic!("no such event in time");
}

#[track_caller]
fn wait_for_contact(handle: &Handle) -> Vec<u8> {
    wait_for(handle, |event| match event {
        FfiEvent::Contact { conversation } => Some(conversation),
        _ => None,
    })
}

#[track_caller]
fn wait_for_message(handle: &Handle) -> (Vec<u8>, Arc<MsgHandle>) {
    wait_for(handle, |event| match event {
        FfiEvent::Message {
            conversation,
            message,
        } => Some((conversation, message)),
        _ => None,
    })
}

fn rendered(handle: &Handle, message: Arc<MsgHandle>) -> String {
    let view = Arc::new(View::default());
    handle.msg_render(message, view.clone()).unwrap();
    let text = String::from_utf16(&view.0.lock().unwrap()).unwrap();
    text
}

/// Starts three relay servers on localhost, and returns their runtime with
/// their ports. With a directory each relay keeps its queues in an SQLite
/// file there. With ports each relay takes the port of an earlier run. A
/// drop of the runtime ends the three servers and closes each socket.
fn start_relays(
    directory: Option<&std::path::Path>,
    ports: Option<&[u16]>,
) -> (tokio::runtime::Runtime, Vec<u16>) {
    start_relays_with(directory, ports, None)
}

/// The NDR of a test: its port, and its key id and gateway key.
struct TestNdr {
    port: u16,
    key_id: u8,
    gateway: umbra_crypto::kem::PublicKey,
}

/// Starts the relays as [`start_relays`] does. With an NDR the relay of
/// layer 1 carries its OHTTP requests, and each queue relay pushes through
/// that relay.
fn start_relays_with(
    directory: Option<&std::path::Path>,
    ports: Option<&[u16]>,
    ndr: Option<&TestNdr>,
) -> (tokio::runtime::Runtime, Vec<u16>) {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let client_tls = native::tls_config_with_root_file(CA).unwrap();
    let mut listeners = Vec::new();
    for index in 0..LAYERS.len() {
        let port = ports.map_or(0, |ports| ports[index]);
        let listener = relays
            .block_on(TcpListener::bind(("127.0.0.1", port)))
            .unwrap();
        listeners.push(listener);
    }
    let ports: Vec<u16> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    for (index, listener) in listeners.into_iter().enumerate() {
        let number = index as u8 + 1;
        let layer = LAYERS[index];
        let (relay, static_secret) = relay_static(number);
        let config = RelayConfig {
            relay,
            static_secret,
            layer,
            issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
            chunk_capacity: 1 << 26,
        };
        let mut store: Box<dyn RelayStore> = match directory {
            Some(directory) => {
                let path = directory.join(format!("relay{number}.db"));
                Box::new(SqliteStore::open(path.to_str().unwrap()).unwrap())
            }
            None => Box::new(MemoryStore::default()),
        };
        let node = RelayNode::restored(config, store.load().unwrap());
        // A relay dials each relay of the next layer.
        let next_hops: BTreeMap<_, _> = (0..LAYERS.len())
            .filter(|next| LAYERS[*next] == layer + 1)
            .map(|next| {
                (
                    relay_static(next as u8 + 1).0.relay_id,
                    localhost(ports[next]),
                )
            })
            .collect();
        relays.spawn(run_relay(
            node,
            listener,
            tls_acceptor(LEAF, LEAF_KEY).unwrap(),
            next_hops,
            BTreeMap::new(),
            client_tls.clone(),
            PACING_MEAN_MS,
            store,
            carried_of(layer, &ports, ndr, &client_tls),
        ));
    }
    (relays, ports)
}

/// What one relay of a test carries: the OHTTP relay role at layer 1 and
/// the route of the pushes at layer 3, when an NDR runs.
fn carried_of(
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

fn network_of(ports: &[u16]) -> Network {
    Network {
        relays: (0..LAYERS.len())
            .map(|index| {
                let number = index as u8 + 1;
                let relay = relay_static(number).0;
                RelayEndpoint {
                    host: "localhost".into(),
                    ipv4: vec![127, 0, 0, 1],
                    port: ports[index],
                    static_key: relay.s.to_vec(),
                    relay_id: relay.relay_id.to_vec(),
                    layer: LAYERS[index],
                    // Five operators in five places. Each relay of this test
                    // has the address of one machine, thus each names a
                    // network of its own.
                    operator: format!("operator-{number}"),
                    family: None,
                    country: format!("Z{}", char::from(b'A' + number)),
                    asn: 64_500 + u32::from(number),
                    prefix: Some(vec![10, number]),
                    holds_files: false,
                    identity_pk: Vec::new(),
                }
            })
            .collect(),
        root_ca_path: Some(CA.into()),
        invitation_host: HOST.into(),
        ndr_relay_url: None,
        ndr_key_config: None,
        ndr_relay_ipv4: None,
        directory_relay_url: None,
        directory_pins: None,
        directory_relay_ipv4: None,
        report_queues: Vec::new(),
        removed_links: Vec::new(),
    }
}

fn launch(directory: &std::path::Path, name: &str, key: u8) -> Arc<Handle> {
    let config = Config {
        database_path: directory.join(name).to_str().unwrap().to_owned(),
        // A slow device keeps the floor cost, which keeps this test short.
        argon2_floor_ms: 60_000,
    };
    let keystore = Arc::new(Keystore([key; 32])) as Arc<dyn SecureElementCallback>;
    init(config, keystore, units("correct horse")).unwrap()
}

/// As [`wait_for`], for a test that ends the relays: a run that ends with a
/// fault is what that test expects.
fn wait_past_faults<T>(handle: &Handle, mut pick: impl FnMut(FfiEvent) -> Option<T>) -> T {
    let start = Instant::now();
    while start.elapsed() < STEP {
        let found = handle.wait_event(500).and_then(&mut pick);
        if let Some(found) = found {
            return found;
        }
    }
    panic!("no such event in time");
}

#[test]
fn the_relay_processes_end_and_the_contact_continues() {
    let directory = std::env::temp_dir().join(format!("umbra-relays-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let (relays, ports) = start_relays(Some(&directory), None);
    let network = network_of(&ports);
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    alice.clone().connect(network.clone()).unwrap();
    bob.clone().connect(network.clone()).unwrap();

    alice.invite().unwrap();
    let link = wait_past_faults(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let contact = |event| match event {
        FfiEvent::Contact { conversation } => Some(conversation),
        _ => None,
    };
    let alice_conversation = wait_past_faults(&alice, contact);
    let bob_conversation = wait_past_faults(&bob, contact);

    // Bob leaves. The queue relay accepts a record for him and holds it in
    // its file.
    bob.disconnect();
    let draft = alice.new_draft(alice_conversation.clone()).unwrap();
    draft.set_text(units("held in the file")).unwrap();
    alice.send_draft(draft).unwrap();
    wait_past_faults(&alice, |event| match event {
        FfiEvent::Delivery { state: 1, .. } => Some(()),
        _ => None,
    });

    // Each relay process ends, and three new ones take the same ports and
    // the same files.
    drop(relays);
    let (_relays, again) = start_relays(Some(&directory), Some(&ports));
    assert_eq!(again, ports);
    alice.clone().connect(network.clone()).unwrap();
    bob.clone().connect(network.clone()).unwrap();

    let message = |event| match event {
        FfiEvent::Message { message, .. } => Some(message),
        _ => None,
    };
    let held = wait_past_faults(&bob, message);
    assert_eq!(rendered(&bob, held), "held in the file");
    let draft = bob.new_draft(bob_conversation).unwrap();
    draft.set_text(units("the queues are there")).unwrap();
    bob.send_draft(draft).unwrap();
    let answer = wait_past_faults(&alice, message);
    assert_eq!(rendered(&alice, answer), "the queues are there");

    alice.disconnect();
    bob.disconnect();
}

#[test]
fn two_apps_meet_and_talk_through_the_exported_surface() {
    // The relays run on a runtime of the test. Each handle makes its own.
    let (_relays, ports) = start_relays(None, None);
    let network = network_of(&ports);

    let directory = std::env::temp_dir().join(format!("umbra-app-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let launch = |name: &str, key: u8, is_first: bool| {
        let path = directory.join(name);
        if is_first {
            let _ = std::fs::remove_file(&path);
        }
        let config = Config {
            database_path: path.to_str().unwrap().to_owned(),
            // A slow device keeps the floor cost, which keeps this test short.
            argon2_floor_ms: 60_000,
        };
        let keystore = Arc::new(Keystore([key; 32])) as Arc<dyn SecureElementCallback>;
        init(config, keystore, units("correct horse")).unwrap()
    };
    let alice = launch("alice.db", 1, true);
    let bob = launch("bob.db", 2, true);

    // No network runs yet.
    assert_eq!(alice.invite(), Err(FfiError::Offline));
    alice.clone().connect(network.clone()).unwrap();
    bob.clone().connect(network.clone()).unwrap();

    // A link of another host and a link that does not parse are errors of
    // the call, and the network stays up.
    let foreign = "https://evil.example/i#AAAA".to_owned();
    assert_eq!(bob.accept(foreign), Err(FfiError::Malformed));
    assert_eq!(
        bob.accept(format!("https://{HOST}/i#short")),
        Err(FfiError::Malformed)
    );

    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    // IDN-159: the fragment is 91 characters of base64url.
    assert_eq!(link.len(), format!("https://{HOST}/i#").len() + 91);
    bob.accept(link.clone()).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);

    // The link worked one time. A second use finds no blob, and the user
    // learns it (`IDN-023`).
    bob.accept(link).unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::InvitationGone => Some(()),
        _ => None,
    });

    // A draft of Bob becomes a message of Alice.
    let draft = bob.new_draft(bob_conversation.clone()).unwrap();
    draft.set_text(units("hello alice")).unwrap();
    bob.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&alice);
    assert_eq!(conversation, alice_conversation);
    assert_eq!(rendered(&alice, message), "hello alice");
    let accepted = wait_for(&bob, |event| match event {
        FfiEvent::Delivery { state, .. } => Some(state),
        _ => None,
    });
    assert_eq!(accepted, 1);

    // And back.
    let draft = alice.new_draft(alice_conversation.clone()).unwrap();
    draft.set_text(units("hello bob")).unwrap();
    alice.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&bob);
    assert_eq!(conversation, bob_conversation);
    assert_eq!(rendered(&bob, message), "hello bob");
    // The list of Bob shows one conversation with one message that he did
    // not see, under the name that he gave. The name and the marker live
    // in his store alone.
    bob.set_contact_name(bob_conversation.clone(), "  Alice  ".into())
        .unwrap();
    let listed = bob.summaries().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Alice");
    assert_eq!(listed[0].unread, 1);
    assert_eq!(
        rendered(&bob, listed[0].last_message.clone().unwrap()),
        "hello bob"
    );
    bob.mark_read(bob_conversation.clone()).unwrap();
    assert_eq!(bob.summaries().unwrap()[0].unread, 0);
    assert!(bob
        .set_contact_name(bob_conversation.clone(), "x".repeat(121))
        .is_err());
    assert_eq!(alice.summaries().unwrap()[0].name, "");

    // The two devices hold one safety number, and no contact is verified.
    let number = alice.safety_number(alice_conversation.clone()).unwrap();
    assert_eq!(number.len(), 71);
    assert_eq!(bob.safety_number(bob_conversation.clone()).unwrap(), number);
    assert!(!bob.summaries().unwrap()[0].verified);

    // Alice starts a ceremony, and the two devices show one code. The code
    // alone verifies nothing (`IDN-148`). Bob confirms, and his store holds
    // the state. Alice did not confirm, and her store holds none.
    alice
        .start_verification(alice_conversation.clone())
        .unwrap();
    let code = |event| match event {
        FfiEvent::VerificationCode { code, .. } => Some(code),
        _ => None,
    };
    let alice_code = wait_for(&alice, code);
    let bob_code = wait_for(&bob, code);
    assert_eq!(alice_code, bob_code);
    assert_eq!(alice_code.len(), 6);
    assert!(!bob.summaries().unwrap()[0].verified);
    bob.confirm_verification(bob_conversation.clone()).unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::Verified { .. } => Some(()),
        _ => None,
    });
    assert!(bob.summaries().unwrap()[0].verified);
    assert!(!alice.summaries().unwrap()[0].verified);
    // A confirmation with no ceremony is refused.
    bob.confirm_verification(bob_conversation.clone()).unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::VerificationRefused { .. } => Some(()),
        _ => None,
    });
    // A scanned number that matches verifies, and a wrong one does not.
    assert!(!alice
        .verify_by_number(alice_conversation.clone(), "12345 67890".into())
        .unwrap());
    assert!(alice
        .verify_by_number(alice_conversation.clone(), number.replace(' ', ""))
        .unwrap());
    assert!(alice.summaries().unwrap()[0].verified);

    // The view of Bob holds the two messages in the order of their store.
    let shown = bob.messages(bob_conversation.clone()).unwrap();
    assert_eq!(shown.len(), 2);
    let first = bob.msg_info(shown[0].clone()).unwrap();
    let second = bob.msg_info(shown[1].clone()).unwrap();
    assert!(first.outgoing && first.delivery == 1);
    assert!(!second.outgoing && second.delivery == 2);
    assert!(first.stored_at_ms <= second.stored_at_ms);

    // A draft for no contact fails, and the network stays up.
    let draft = alice.new_draft(vec![0xEE; 16]).unwrap();
    draft.set_text(units("nobody")).unwrap();
    alice.send_draft(draft).unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::Delivery { state: 4, .. } => Some(()),
        _ => None,
    });

    let say = |from: &Handle, conversation: &[u8], words: &str| {
        let draft = from.new_draft(conversation.to_vec()).unwrap();
        draft.set_text(units(words)).unwrap();
        from.send_draft(draft).unwrap();
    };

    // Bob leaves the network. Alice writes, and the relay holds the record.
    // The next run of Bob continues the contact from the store.
    bob.disconnect();
    assert_eq!(bob.invite(), Err(FfiError::Offline));
    say(&alice, &alice_conversation, "while you were away");
    assert_eq!(
        bob.conversations().unwrap(),
        std::slice::from_ref(&bob_conversation)
    );
    bob.clone().connect(network.clone()).unwrap();
    let (conversation, message) = wait_for_message(&bob);
    assert_eq!(conversation, bob_conversation);
    assert_eq!(rendered(&bob, message), "while you were away");

    // A lock ends the network, because a locked client holds no key in
    // RAM. An unlock and a new run continue the contact.
    alice.lock();
    assert_eq!(alice.invite(), Err(FfiError::Offline));
    alice.unlock(units("correct horse")).unwrap();
    alice.clone().connect(network.clone()).unwrap();
    say(&alice, &alice_conversation, "after the lock");
    let (_, message) = wait_for_message(&bob);
    assert_eq!(rendered(&bob, message), "after the lock");

    // A record that Bob writes with no network waits in the store, and the
    // next run sends it.
    bob.disconnect();
    say(&bob, &bob_conversation, "written offline");
    bob.clone().connect(network.clone()).unwrap();
    let (_, message) = wait_for_message(&alice);
    assert_eq!(rendered(&alice, message), "written offline");

    // The process of Alice ends. A new process opens the same file, and
    // the contact, the history, and the ratchet are there.
    alice.disconnect();
    drop(alice);
    let alice = launch("alice.db", 1, false);
    alice.unlock(units("correct horse")).unwrap();
    assert_eq!(
        alice.conversations().unwrap(),
        std::slice::from_ref(&alice_conversation)
    );
    assert_eq!(alice.messages(alice_conversation.clone()).unwrap().len(), 5);
    alice.clone().connect(network.clone()).unwrap();
    say(&alice, &alice_conversation, "a new process");
    let (_, message) = wait_for_message(&bob);
    assert_eq!(rendered(&bob, message), "a new process");
    say(&bob, &bob_conversation, "and an answer");
    let (_, message) = wait_for_message(&alice);
    assert_eq!(rendered(&alice, message), "and an answer");

    alice.disconnect();
    bob.disconnect();
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_message_to_an_app_that_went_away_reaches_its_push_endpoint() {
    use umbra_crypto::{kem::KeyPair, ohttp};
    // A UnifiedPush endpoint that hands each post to the test.
    let services = tokio::runtime::Runtime::new().unwrap();
    let endpoint = services
        .block_on(TcpListener::bind(("127.0.0.1", 0)))
        .unwrap();
    let endpoint_port = endpoint.local_addr().unwrap().port();
    let (pushed, mut posts) = tokio::sync::mpsc::unbounded_channel();
    let acceptor = tls_acceptor(LEAF, LEAF_KEY).unwrap();
    services.spawn(async move {
        loop {
            let (tcp, _) = endpoint.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut inbound = Vec::new();
            if let Ok(request) = https::read_request(&mut stream, &mut inbound, 4_096).await {
                let _ = pushed.send(request.body);
            }
            let _ = https::respond(&mut stream, 201, "text/plain", &[]).await;
        }
    });

    // The NDR, and the relays that carry its requests.
    let pair = KeyPair::generate(&mut OsRng);
    let config = ohttp::encode_key_config(1, pair.public());
    let ndr_listener = services
        .block_on(TcpListener::bind(("127.0.0.1", 0)))
        .unwrap();
    let ndr = TestNdr {
        port: ndr_listener.local_addr().unwrap().port(),
        key_id: 1,
        gateway: pair.public().clone(),
    };
    services.spawn(run_ndr(
        ndr_listener,
        tls_acceptor(LEAF, LEAF_KEY).unwrap(),
        Gateway { key_id: 1, pair },
        Box::new(MemoryNdrStore::default()),
        native::tls_config_with_root_file(CA).unwrap(),
        None,
    ));
    let (_relays, ports) = start_relays_with(None, None, Some(&ndr));
    let mut network = network_of(&ports);
    network.ndr_relay_url = Some(format!("https://localhost:{}/ohttp", ports[0]));
    network.ndr_key_config = Some(config.to_vec());

    let directory = std::env::temp_dir().join(format!("umbra-push-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    alice
        .set_push_endpoint(Some(format!("https://localhost:{endpoint_port}/up/alice")))
        .unwrap();
    alice.clone().connect(network.clone()).unwrap();
    bob.clone().connect(network.clone()).unwrap();
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);

    // NTF-112, NTF-113, NTF-122: the queue of Alice binds at its relay, and
    // her handle group registers with the NDR through the OHTTP relay.
    let started = std::time::Instant::now();
    while alice.push_state().unwrap() != (1, 1) {
        assert!(started.elapsed() < STEP, "{:?}", alice.push_state());
        std::thread::sleep(Duration::from_millis(50));
    }

    // NET-322, NTF-128: Alice leaves, her circuit ends at each hop, and the
    // next record for her goes to her endpoint as one blob.
    alice.disconnect();
    std::thread::sleep(Duration::from_millis(500));
    let draft = bob.new_draft(bob_conversation).unwrap();
    draft.set_text(units("while you are away")).unwrap();
    bob.send_draft(draft).unwrap();
    let blob = services
        .block_on(async { tokio::time::timeout(STEP, posts.recv()).await })
        .unwrap()
        .unwrap();
    assert_eq!(blob.len(), umbra_wire::ndr::BLOB_LEN);
    bob.disconnect();
}

#[test]
fn a_group_record_wakes_a_member_that_went_away_through_its_notify_queue() {
    use umbra_crypto::{kem::KeyPair, ohttp};
    let services = tokio::runtime::Runtime::new().unwrap();
    let endpoint = services
        .block_on(TcpListener::bind(("127.0.0.1", 0)))
        .unwrap();
    let endpoint_port = endpoint.local_addr().unwrap().port();
    let (pushed, mut posts) = tokio::sync::mpsc::unbounded_channel();
    let acceptor = tls_acceptor(LEAF, LEAF_KEY).unwrap();
    services.spawn(async move {
        loop {
            let (tcp, _) = endpoint.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut inbound = Vec::new();
            if let Ok(request) = https::read_request(&mut stream, &mut inbound, 4_096).await {
                let _ = pushed.send(request.body);
            }
            let _ = https::respond(&mut stream, 201, "text/plain", &[]).await;
        }
    });
    let pair = KeyPair::generate(&mut OsRng);
    let config = ohttp::encode_key_config(1, pair.public());
    let ndr_listener = services
        .block_on(TcpListener::bind(("127.0.0.1", 0)))
        .unwrap();
    let ndr = TestNdr {
        port: ndr_listener.local_addr().unwrap().port(),
        key_id: 1,
        gateway: pair.public().clone(),
    };
    services.spawn(run_ndr(
        ndr_listener,
        tls_acceptor(LEAF, LEAF_KEY).unwrap(),
        Gateway { key_id: 1, pair },
        Box::new(MemoryNdrStore::default()),
        native::tls_config_with_root_file(CA).unwrap(),
        None,
    ));
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network_with(&relays, None, Some(&ndr), None);

    let directory = std::env::temp_dir().join(format!("umbra-gpush-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    bob.set_push_endpoint(Some(format!("https://localhost:{endpoint_port}/up/bob")))
        .unwrap();
    let mut networks = Vec::new();
    for handle in [&alice, &bob] {
        let mut verified = handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network;
        verified.ndr_relay_url = Some(format!("https://localhost:{}/ohttp", network.ports[0]));
        verified.ndr_key_config = Some(config.to_vec());
        verified.ndr_relay_ipv4 = Some(vec![127, 1, 0, 1]);
        networks.push(verified.clone());
        handle.clone().connect(verified).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    wait_for_contact(&bob);

    let group = alice.create_group("Summit".into()).unwrap();
    let start = Instant::now();
    while !alice.group_info(group.clone()).unwrap().is_ready {
        assert!(start.elapsed() < STEP, "the group took no queues");
        std::thread::sleep(Duration::from_millis(50));
    }
    alice
        .offer_group(group.clone(), alice_conversation.clone())
        .unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::GroupOffer => Some(()),
        _ => None,
    });
    let offers = bob.group_offers().unwrap();
    bob.accept_group_offer(offers[0].from.clone(), offers[0].group_id.clone())
        .unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::GroupJoiner => Some(()),
        _ => None,
    });
    let joiners = alice.group_joiners().unwrap();
    alice
        .admit_joiner(joiners[0].from.clone(), joiners[0].group_id.clone())
        .unwrap();
    let start = Instant::now();
    while !bob
        .summaries()
        .unwrap()
        .iter()
        .any(|summary| bob.is_group(summary.conversation.clone()).unwrap_or(false))
    {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "Bob did not come in"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // NTF-090, NTF-091: Bob holds a notify queue for the group under a
    // handle of its own, beside the handle of his pairwise queue, and both
    // register with the NDR.
    let start = Instant::now();
    while bob.push_state().unwrap() != (2, 2) {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "{:?}",
            bob.push_state()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // NTF-093: the GNREG of each replica leaves with the next pump.
    std::thread::sleep(Duration::from_secs(2));

    // NTF-096, WIR-526: Bob leaves, a record of Alice reaches the group
    // queue, its relay deposits a digest into the notify queue of Bob, and
    // the queue relay of that queue pushes.
    bob.disconnect();
    std::thread::sleep(Duration::from_millis(500));
    let draft = alice.new_draft(group).unwrap();
    draft.set_text(units("we leave at six")).unwrap();
    alice.send_draft(draft).unwrap();
    let blob = services
        .block_on(async { tokio::time::timeout(Duration::from_secs(30), posts.recv()).await })
        .expect("no push reached the endpoint of Bob")
        .unwrap();
    assert_eq!(blob.len(), umbra_wire::ndr::BLOB_LEN);

    // NTF-132, NTF-133: Bob comes back and leaves the group. His notify queue leaves
    // both replicas and ends, and his pairwise queue stays bound.
    bob.clone().connect(networks[1].clone()).unwrap();
    let bob_group = bob
        .summaries()
        .unwrap()
        .into_iter()
        .map(|summary| summary.conversation)
        .find(|conversation| bob.is_group(conversation.clone()).unwrap_or(false))
        .unwrap();
    let start = Instant::now();
    while bob.leave_group(bob_group.clone()).is_err() {
        assert!(start.elapsed() < STEP, "Bob could not leave");
        std::thread::sleep(Duration::from_millis(100));
    }
    let start = Instant::now();
    while bob.push_state().unwrap().0 != 1 {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{:?}",
            bob.push_state()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    bob.disconnect();
    alice.disconnect();
}

#[test]
fn a_descriptor_names_the_facts_of_each_relay_and_the_first_version_reads() {
    let key = "ab".repeat(32);
    let line =
        |port: u16, facts: &str| format!("relay localhost 127.0.0.1 {port} {key} {key} {facts}");
    let facts = |layer: u8, place: &str| {
        format!("layer={layer} operator=op-{place} country={place} asn=6450{layer}")
    };
    let text = [
        "umbra-network 2".to_owned(),
        line(7441, &facts(1, "SE")),
        line(7442, &format!("{} prefix=10.2", facts(2, "CH"))),
        line(7443, &facts(3, "IS")),
        line(7445, &facts(3, "NO")),
        "invite invite.umbra.test".to_owned(),
    ]
    .join("\n");
    let network = parse_network(text.clone(), None).unwrap();
    assert_eq!(network.relays.len(), 4);
    assert_eq!(network.relays[1].prefix, Some(vec![10, 2]));
    assert_eq!(network.relays[3].country, "NO");
    assert_eq!(network.relays[0].layer, 1);

    // A set with no relay of one layer holds no chain, and a line with a
    // fact two times, with no operator, or with a word that is no fact does
    // not parse.
    for wrong in [
        text.replace("layer=2", "layer=3"),
        text.replace("asn=64501", "asn=64501 asn=64501"),
        text.replace("operator=op-SE ", ""),
        text.replace("country=SE", "country=se"),
        text.replace("layer=1", "layer=4"),
        text.replace("prefix=10.2", "prefix=10.2.3"),
        text.replace("asn=64503", "weight=9"),
    ] {
        assert!(matches!(
            parse_network(wrong, None),
            Err(FfiError::Malformed)
        ));
    }

    // Version 1 is one path of three lines with no facts.
    let first = [
        "umbra-network 1".to_owned(),
        line(7441, ""),
        line(7442, ""),
        line(7443, ""),
        "invite invite.umbra.test".to_owned(),
    ]
    .join("\n");
    let network = parse_network(first.clone(), None).unwrap();
    assert_eq!(
        network
            .relays
            .iter()
            .map(|relay| relay.layer)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(parse_network(first.replace("umbra-network 1", "umbra-network 3"), None).is_err());
}

/// The identity seed of each relay of a signed test network. The first and
/// the sixth relay are the two ingress relays. Under the genesis root the
/// layer function puts the other ones in the layers 2, 3, 2, 3 and 3, thus
/// three relays hold the three copies of a chunk.
const IDENTITY_SEEDS: [u8; 7] = [0x65, 0x66, 0x61, 0x68, 0x63, 0x70, 0x62];
const SIGNED_LAYERS: [u8; 7] = [1, 2, 3, 2, 3, 1, 3];

/// A network of relays under a signed manifest, on sockets of this machine.
struct SignedNetwork {
    manifest: Vec<u8>,
    keyset: Vec<u8>,
    ports: Vec<u16>,
    entries: Vec<Vec<u8>>,
    authorities: Vec<SigningKey>,
    epoch: u64,
}

fn start_signed_network(relays: &tokio::runtime::Runtime) -> SignedNetwork {
    start_signed_network_at(relays, None)
}

/// The same network on given ports, for a test that ends each relay
/// process and starts it again. The keys come from fixed seeds, thus a
/// client of the first network knows each relay of the second.
fn start_signed_network_at(relays: &tokio::runtime::Runtime, at: Option<&[u16]>) -> SignedNetwork {
    start_signed_network_with(relays, at, None, None)
}

/// A directory of Part 9 with its issuer, on loopback, with an epoch of one
/// second: its gateway port and the pins of `DIS-163`.
fn start_test_directory(relays: &tokio::runtime::Runtime) -> (u16, Vec<u8>) {
    use umbra_core::discovery::{
        dirclient::DirectoryPins,
        handle::username_case_mapped,
        head::{LogKeySet, KEYSET_LEN},
        service::{Directory, DirectoryKeys},
    };
    let signers: Vec<SigningKey> = (0..3u8)
        .map(|i| SigningKey::from_seed(Secret::new([0x70 + i; 32])))
        .collect();
    let public: Vec<_> = signers
        .iter()
        .map(|signer| signer.verifying_key().to_bytes())
        .collect();
    let mut keyset = vec![0u8; KEYSET_LEN];
    let used = LogKeySet {
        keyset_epoch: 1,
        keys: public.iter().map(|key| &key[..]).collect(),
    }
    .encode(&mut keyset)
    .unwrap();
    keyset.truncate(used);
    let directory = Directory::new(
        DirectoryKeys {
            voprf_seed: Secret::new([0x61; 32]),
            vrf_seed: Secret::new([0x62; 32]),
            issuer_seed: Secret::new([0x63; 32]),
            signers,
            keyset: keyset.clone(),
            // Part 13 §13.3.1: the RSA key of each epoch from one seed.
            cross_relay: Some(Box::new(|epoch: u32| {
                umbra_crypto::rsabssa::SecretKey2048::from_seed(
                    &Secret::new([0x64; 32]),
                    &epoch.to_be_bytes(),
                )
                .ok()
            })),
        },
        1,
        username_case_mapped,
    )
    .unwrap();
    let pair = umbra_crypto::kem::KeyPair::generate(&mut OsRng);
    let pins = DirectoryPins {
        key_config: umbra_crypto::ohttp::encode_key_config(1, pair.public()).to_vec(),
        keyset,
        vrf_public: *directory.vrf_public(),
        voprf_public: *directory.voprf_public(),
    }
    .encode()
    .unwrap();
    let listener = relays.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    relays.spawn(umbra_relay::directory_server::run_directory(
        listener,
        tls_acceptor(LEAF, LEAF_KEY).unwrap(),
        Gateway { key_id: 1, pair },
        directory,
        Box::new(umbra_relay::directory_server::MemoryDirectoryStore::default()),
    ));
    (port, pins)
}

/// The signed network with an NDR: the ingress relays carry its OHTTP
/// requests, and each queue relay pushes through the first of them.
fn start_signed_network_with(
    relays: &tokio::runtime::Runtime,
    at: Option<&[u16]>,
    ndr: Option<&TestNdr>,
    directory: Option<u16>,
) -> SignedNetwork {
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
            family_id: [number; 32],
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
            operator_id: [number; 32],
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
    let manifest = sign_manifest(
        &authorities,
        &[0, 1, 2, 4, 6],
        1,
        epoch,
        entries.clone(),
        &BlocList::v1(),
        &mut OsRng,
    )
    .unwrap();
    let keyset = keyset_bytes(&authorities, 1).unwrap();

    // Each relay reads its layer and its next hops from the manifest.
    let client_tls = native::tls_config_with_root_file(CA).unwrap();
    let mut layers = Vec::new();
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
            issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
            chunk_capacity: 1 << 26,
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
        relays.spawn(run_relay(
            node,
            listener,
            tls_acceptor(LEAF, LEAF_KEY).unwrap(),
            placed.next,
            replicas,
            client_tls.clone(),
            PACING_MEAN_MS,
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
    }
}

#[test]
fn two_apps_take_their_network_from_a_signed_manifest() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let SignedNetwork {
        manifest,
        keyset,
        ports,
        entries,
        authorities,
        epoch,
    } = start_signed_network(&relays);

    // A client reads the manifest over HTTPS from the ingress relay. A relay
    // that holds none gives none.
    let fetched = fetch_manifest(
        "localhost".into(),
        vec![127, 1, 0, 1],
        ports[0],
        Some(CA.into()),
    );
    assert_eq!(fetched.as_ref(), Ok(&manifest));
    let absent = fetch_manifest(
        "localhost".into(),
        vec![127, 2, 0, 1],
        ports[1],
        Some(CA.into()),
    );
    assert_eq!(absent, Err(FfiError::Offline));

    let directory = std::env::temp_dir().join(format!("umbra-manifest-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for name in ["alice.db", "bob.db", "carol.db", "dave.db"] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    let network_of = |handle: &Handle, manifest: &[u8], shipped_epoch: u64| {
        handle.network_of_manifest(
            manifest.to_vec(),
            keyset.clone(),
            shipped_epoch,
            HOST.into(),
            Some(CA.into()),
        )
    };

    // A build that is newer than the manifest refuses it, a changed byte
    // fails under the root, and another key set signs nothing here.
    assert_eq!(
        network_of(&alice, &manifest, epoch + 1).err(),
        Some(FfiError::Stale)
    );
    let mut changed = manifest.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        network_of(&alice, &changed, 0).err(),
        Some(FfiError::Unverified)
    );
    let others: Vec<SigningKey> = (0..7u8)
        .map(|index| SigningKey::from_seed(Secret::new([0xE0 + index; 32])))
        .collect();
    let other_keyset = keyset_bytes(&others, 1).unwrap();
    let refused = alice.network_of_manifest(
        manifest.clone(),
        other_keyset,
        0,
        HOST.into(),
        Some(CA.into()),
    );
    assert_eq!(refused.err(), Some(FfiError::Unverified));

    let verified = network_of(&alice, &manifest, 0).unwrap();
    assert_eq!(verified.epoch, epoch);
    assert!(!verified.is_clock_corrected);
    assert_eq!(verified.network.relays.len(), 7);
    // The two ingress relays are the two pins, and they come first. The
    // store holds them, thus the next call gives them in the same order.
    let pins_of = |network: &Network| -> Vec<Vec<u8>> {
        assert!(network.relays[..2].iter().all(|relay| relay.layer == 1));
        assert!(network.relays[2..].iter().all(|relay| relay.layer != 1));
        network.relays[..2]
            .iter()
            .map(|relay| relay.relay_id.clone())
            .collect()
    };
    let pins = pins_of(&verified.network);
    assert_ne!(pins[0], pins[1]);
    for _ in 0..4 {
        assert_eq!(
            pins_of(&network_of(&alice, &manifest, 0).unwrap().network),
            pins
        );
    }

    // The first pin of Dave refuses the dial. The next run takes the second
    // pin, and the client comes online (Part 10 §10.6.1).
    let dave = launch(&directory, "dave.db", 4);
    let mut lame = network_of(&dave, &manifest, 0).unwrap().network;
    let closed = relays
        .block_on(TcpListener::bind(("127.0.0.1", 0)))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    lame.relays[0].port = closed;
    dave.clone().connect(lame.clone()).unwrap();
    wait_past_faults(&dave, |event| match event {
        FfiEvent::Offline { .. } => Some(()),
        _ => None,
    });
    dave.clone().connect(lame).unwrap();
    wait_past_faults(&dave, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    dave.disconnect();

    alice.clone().connect(verified.network).unwrap();
    bob.clone()
        .connect(network_of(&bob, &manifest, 0).unwrap().network)
        .unwrap();

    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);
    for (from, to, conversation, text) in [
        (&bob, &alice, &bob_conversation, "over a signed set"),
        (&alice, &bob, &alice_conversation, "and back"),
    ] {
        let draft = from.new_draft(conversation.clone()).unwrap();
        draft.set_text(units(text)).unwrap();
        from.send_draft(draft).unwrap();
        let (_, message) = wait_for_message(to);
        assert_eq!(rendered(to, message), text);
    }

    // The view of the connection: each circuit is one relay of each layer,
    // and the two pins are the ingress relay of the run and its standby.
    let connection = alice.connection().unwrap();
    assert!(connection.is_running);
    assert!(!connection.circuits.is_empty());
    for circuit in &connection.circuits {
        let layers: Vec<u8> = circuit.iter().map(|hop| hop.layer).collect();
        assert_eq!(layers, [1, 2, 3]);
    }
    assert!(connection.relays_in_use >= 3);
    assert_eq!(connection.relays_known, 7);
    assert_eq!(connection.directory_epoch, epoch);
    let (ingress, standby) = (connection.ingress.unwrap(), connection.standby.unwrap());
    assert_eq!((ingress.layer, standby.layer), (1, 1));
    assert_ne!(ingress.country, standby.country);
    assert_eq!(connection.circuits[0][0], ingress);

    // The store holds the epoch, thus a later run refuses an older root.
    let older = sign_manifest(
        &authorities,
        &[0, 1, 2, 3, 4],
        1,
        epoch - 1,
        entries,
        &BlocList::v1(),
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(network_of(&alice, &older, 0).err(), Some(FfiError::Stale));
    // A device with no verified root takes it.
    let carol = launch(&directory, "carol.db", 3);
    assert_eq!(network_of(&carol, &older, 0).unwrap().epoch, epoch - 1);
    alice.disconnect();
    bob.disconnect();
    let _ = std::fs::remove_dir_all(&directory);
}

/// Waits for the end of one transfer, and drops each progress update.
fn transfer_end(
    updates: &mut tokio::sync::mpsc::UnboundedReceiver<TransferUpdate>,
) -> TransferUpdate {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        match updates.try_recv() {
            Ok(TransferUpdate::Progress { .. }) => {}
            Ok(end) => return end,
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    panic!("the transfer did not end in time");
}

#[test]
fn a_file_goes_through_the_relays_of_a_signed_network() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // The relay set, as a client reads it from the manifest.
    let (keyset, _) = DirectoryKeySet::parse(&network.keyset).unwrap();
    let mut consensus = Consensus::new(keyset, 0).unwrap();
    let manifest = RelayManifest::parse(&network.manifest).unwrap();
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now).unwrap();
    let info_of = |relay: &ListedRelay| RelayInfo {
        candidate: relay.candidate,
        key: RelayStatic {
            s: relay.ntor_pk,
            relay_id: relay.candidate.relay_id,
        },
    };
    let ingress = set
        .relays
        .iter()
        .find(|relay| relay.candidate.ingress)
        .unwrap();
    let guard = Dial {
        host: ingress.host.clone(),
        addr_v4: Some(ingress.addr_v4),
        addr_v6: None,
        port: ingress.port,
    };
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
    assert_eq!(holders.len(), 3);

    // Two devices, each with a transfer task on a connection of its own.
    let clients = tokio::runtime::Runtime::new().unwrap();
    let tls = native::tls_config_with_root_file(CA).unwrap();
    // ABU-106: a registration carries a solution, thus each task takes the
    // signed challenges of the relays first, as a connect fetches them.
    std::thread::sleep(Duration::from_secs(3));
    let bundle = clients
        .block_on(native::fetch_challenges(&guard, tls.clone()))
        .unwrap();
    let mut book = umbra_core::abuse::pow::ChallengeBook::default();
    for challenge in umbra_core::abuse::pow::ChallengeBook::parse_bundle(&bundle).unwrap() {
        let listed = set
            .relays
            .iter()
            .find(|relay| relay.candidate.relay_id == challenge.verifier_id)
            .unwrap();
        let identity = umbra_crypto::sign::VerifyingKey::from_bytes(&listed.identity_pk).unwrap();
        book.take(challenge, &identity, now).unwrap();
    }
    let start = |seed: u8| {
        let node = ClientNode::for_transfers(
            info_of(ingress),
            set.relays
                .iter()
                .filter(|relay| !relay.candidate.ingress)
                .map(info_of)
                .collect(),
            umbra_crypto::hierarchy::RootIdentity::new(Secret::new([seed; 32])),
        );
        let (commands, task_commands) = tokio::sync::mpsc::unbounded_channel();
        let (task_updates, updates) = tokio::sync::mpsc::unbounded_channel();
        clients.spawn(run_transfers(
            node,
            guard.clone(),
            tls.clone(),
            holders.clone(),
            task_commands,
            task_updates,
        ));
        commands
            .send(TransferCommand::Challenges {
                book: book.clone(),
                now,
            })
            .ok()
            .unwrap();
        (commands, updates)
    };
    let (sender, mut sender_updates) = start(0x81);
    let (receiver, mut receiver_updates) = start(0x82);

    // Ten chunks: more than the eight that go up side by side.
    let plain: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    sender
        .send(TransferCommand::Upload {
            tag: 7,
            plain: zeroize::Zeroizing::new(plain.clone()),
            shape: Shape {
                mime_class: 1,
                pixel_w: 1_024,
                pixel_h: 768,
                ..Shape::default()
            },
        })
        .ok()
        .unwrap();
    let TransferUpdate::Uploaded { tag: 7, uploaded } = transfer_end(&mut sender_updates) else {
        panic!("the upload failed");
    };
    assert_eq!(uploaded.descriptor.refs.len(), 10);
    assert_eq!(uploaded.credentials.len(), 10);

    // The descriptor goes to the other device inside a record.
    let mut encoded = vec![0u8; uploaded.descriptor.len()];
    uploaded.descriptor.encode(&mut encoded).unwrap();
    let descriptor = umbra_wire::descriptor::FileDescriptor::parse(&encoded).unwrap();
    receiver
        .send(TransferCommand::Download {
            tag: 9,
            descriptor: Box::new(descriptor),
        })
        .ok()
        .unwrap();
    let TransferUpdate::Downloaded {
        tag: 9,
        plain: fetched,
    } = transfer_end(&mut receiver_updates)
    else {
        panic!("the download failed");
    };
    assert_eq!(*fetched, plain);

    // A descriptor whose chunks no relay holds ends with no file, and the
    // end says that each replica lacks a chunk (Part 12 `ATT-052`).
    let mut unknown = umbra_wire::descriptor::FileDescriptor::parse(&encoded).unwrap();
    for chunk_ref in &mut unknown.refs {
        chunk_ref.chunk_id[0] ^= 1;
    }
    receiver
        .send(TransferCommand::Download {
            tag: 10,
            descriptor: Box::new(unknown),
        })
        .ok()
        .unwrap();
    assert!(matches!(
        transfer_end(&mut receiver_updates),
        TransferUpdate::Gone { tag: 10 }
    ));
}

/// Waits until the file of a message has the state `state`.
fn wait_for_file(handle: &Handle, message: &Arc<MsgHandle>, state: u8) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        let file = handle.msg_info(message.clone()).unwrap().file.unwrap();
        if file.state == state {
            return;
        }
        assert_ne!(file.state, 4, "the transfer failed");
        let _ = handle.wait_event(200);
    }
    panic!("the file did not reach the state {state} in time");
}

#[test]
fn one_app_sends_a_file_and_the_other_app_gets_it() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-files-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for name in ["alice.db", "bob.db", "photo.bin"] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    for handle in [&alice, &bob] {
        let verified = handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap();
        // The three relays of layer 3 hold the chunks of a file.
        let holders = verified
            .network
            .relays
            .iter()
            .filter(|relay| relay.holds_files);
        assert_eq!(holders.count(), 3);
        handle.clone().connect(verified.network).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);

    // A file of five chunks, which the platform gives by its path.
    let plain: Vec<u8> = (0..140_000u32).map(|i| (i % 249) as u8).collect();
    let path = directory.join("photo.bin");
    std::fs::write(&path, &plain).unwrap();
    let draft = alice.new_draft(alice_conversation.clone()).unwrap();
    draft
        .attach_file(
            path.to_str().unwrap().to_owned(),
            1,
            800,
            600,
            0,
            None,
            None,
        )
        .unwrap();
    // The record of a file holds no text.
    // WIR-535: the text of a draft with a file is its caption, of
    // CAPTION_MAX at most.
    let long = alice.new_draft(alice_conversation.clone()).unwrap();
    long.set_text(units(&"a".repeat(umbra_wire::descriptor::CAPTION_MAX + 1)))
        .unwrap();
    long.attach_file(
        path.to_str().unwrap().to_owned(),
        1,
        800,
        600,
        0,
        None,
        None,
    )
    .unwrap();
    assert_eq!(alice.send_draft(long).err(), Some(FfiError::TooLong));
    draft.set_text(units("the summit at six")).unwrap();

    let sent = alice.send_draft(draft).unwrap();
    // The sender shows the caption while the upload runs.
    assert_eq!(rendered(&alice, sent.clone()), "the summit at six");
    let info = alice.msg_info(sent.clone()).unwrap();
    let file = info.file.unwrap();
    assert_eq!((file.pixel_w, file.pixel_h, file.mime_class), (800, 600, 1));
    assert!(file.state == 1 || file.state == 3);
    // The sender holds its own file from the start.
    assert_eq!(*alice.file_bytes(&sent).unwrap(), plain);

    // The relays take the chunks, and then the record with the descriptor
    // goes to Bob. His device fetches the file.
    let (conversation, received) = wait_for_message(&bob);
    assert_eq!(conversation, bob_conversation);
    wait_for_file(&alice, &sent, 3);
    wait_for_file(&bob, &received, 3);
    let info = bob.msg_info(received.clone()).unwrap();
    let file = info.file.unwrap();
    assert_eq!((file.pixel_w, file.pixel_h, file.mime_class), (800, 600, 1));
    assert_eq!(*bob.file_bytes(&received).unwrap(), plain);
    // The caption travels in the body, and the sender keeps it after the
    // upload.
    assert_eq!(rendered(&bob, received.clone()), "the summit at six");
    assert_eq!(rendered(&alice, sent.clone()), "the summit at six");

    // ATT-161: Alice deletes the message for each party. Her device erases
    // the chunks, and the two stores hold the file no more.
    alice.delete_for_everyone(sent.clone()).unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::Deleted { .. } => Some(()),
        _ => None,
    });
    assert!(bob.msg_info(received.clone()).unwrap().file.is_none());
    assert_eq!(bob.file_bytes(&received).err(), Some(FfiError::NotFound));
    assert_eq!(alice.file_bytes(&sent).err(), Some(FfiError::NotFound));

    alice.disconnect();
    bob.disconnect();
    let _ = std::fs::remove_dir_all(&directory);
}

/// The next update of a group run, or a panic.
fn group_update(updates: &mut tokio::sync::mpsc::UnboundedReceiver<GroupUpdate>) -> GroupUpdate {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        match updates.try_recv() {
            Ok(update) => return update,
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    panic!("the group run gave no update in time");
}

#[test]
fn a_push_wake_session_ends_after_six_seconds_unless_the_app_comes_to_the_screen() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-wake-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let _ = std::fs::remove_file(directory.join("alice.db"));
    let alice = launch(&directory, "alice.db", 1);
    let verified = alice
        .network_of_manifest(
            network.manifest.clone(),
            network.keyset.clone(),
            0,
            HOST.into(),
            Some(CA.into()),
        )
        .unwrap();
    let offline_cause = |within: Duration| {
        let start = Instant::now();
        while start.elapsed() < within {
            if let Some(FfiEvent::Offline { cause }) = alice.wait_event(200) {
                return Some((cause, start.elapsed()));
            }
        }
        None
    };

    // NET-100: a wake ends by itself, and the cause is no fault.
    alice.set_foreground(false);
    alice
        .clone()
        .connect_wake(verified.network.clone())
        .unwrap();
    let (cause, after) = offline_cause(Duration::from_secs(20)).expect("the wake did not end");
    assert_eq!(cause, 7);
    assert!(after >= Duration::from_secs(5), "ended after {after:?}");

    // A wake that the screen takes is a full run.
    alice
        .clone()
        .connect_wake(verified.network.clone())
        .unwrap();
    alice.set_foreground(true);
    assert_eq!(offline_cause(Duration::from_secs(9)), None);
    alice.disconnect();
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_contact_that_reset_its_identity_joins_a_group_and_reads_it() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-reset-join-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for name in ["alice.db", "bob.db"] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    let mut networks = Vec::new();
    for handle in [&alice, &bob] {
        let verified = handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap();
        networks.push(verified.network.clone());
        handle.clone().connect(verified.network).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    wait_for_contact(&bob);

    // DEV-263: Bob resets, and his run starts again under the new root.
    bob.clone().reset_identity().unwrap();
    bob.disconnect();
    bob.clone().connect(networks[1].clone()).unwrap();

    let group = alice.create_group("Summit".into()).unwrap();
    let start = Instant::now();
    while start.elapsed() < STEP && !alice.group_info(group.clone()).unwrap().is_ready {
        std::thread::sleep(Duration::from_millis(50));
    }
    alice
        .offer_group(group.clone(), alice_conversation.clone())
        .unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::GroupOffer => Some(()),
        _ => None,
    });
    let offers = bob.group_offers().unwrap();
    bob.accept_group_offer(offers[0].from.clone(), offers[0].group_id.clone())
        .unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::GroupJoiner => Some(()),
        _ => None,
    });
    let joiners = alice.group_joiners().unwrap();
    alice
        .admit_joiner(joiners[0].from.clone(), joiners[0].group_id.clone())
        .unwrap();
    let start = Instant::now();
    let mut joined = None;
    while start.elapsed() < Duration::from_secs(60) {
        if let Some(summary) = bob
            .summaries()
            .unwrap()
            .into_iter()
            .find(|summary| bob.is_group(summary.conversation.clone()).unwrap_or(false))
        {
            joined = Some(summary.conversation);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let joined = joined.expect("Bob did not come into the group");
    let draft = alice.new_draft(group.clone()).unwrap();
    draft.set_text(units("we leave at six")).unwrap();
    alice.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&bob);
    assert_eq!(conversation, joined);
    assert_eq!(rendered(&bob, message), "we leave at six");

    // DEV-263: a reset of a member re-keys the group that it holds, and the
    // group carries on in both directions.
    let counts = bob.clone().reset_identity().unwrap();
    assert_eq!(counts.groups, 1);
    bob.disconnect();
    bob.clone().connect(networks[1].clone()).unwrap();
    let draft = bob.new_draft(joined.clone()).unwrap();
    draft.set_text(units("after my reset")).unwrap();
    bob.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&alice);
    assert_eq!(conversation, group);
    assert_eq!(rendered(&alice, message), "after my reset");
    let draft = alice.new_draft(group.clone()).unwrap();
    draft.set_text(units("seen it")).unwrap();
    alice.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&bob);
    assert_eq!(conversation, joined);
    assert_eq!(rendered(&bob, message), "seen it");

    alice.disconnect();
    bob.disconnect();
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn one_app_offers_a_group_and_the_other_app_joins_it() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-join-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for name in ["alice.db", "bob.db"] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    let mut networks = Vec::new();
    for handle in [&alice, &bob] {
        let verified = handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap();
        networks.push(verified.network.clone());
        handle.clone().connect(verified.network).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);

    // Alice makes the group, and its two queues answer.
    let group = alice.create_group("Summit".into()).unwrap();
    let start = Instant::now();
    while start.elapsed() < STEP {
        if alice.group_info(group.clone()).unwrap().is_ready {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let info = alice.group_info(group.clone()).unwrap();
    assert!(info.is_ready, "the group took no queues");

    // Step 1: the offer reaches Bob on the pairwise channel.
    alice
        .offer_group(group.clone(), alice_conversation.clone())
        .unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::GroupOffer => Some(()),
        _ => None,
    });
    let offers = bob.group_offers().unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].name, "Summit");
    assert_eq!(offers[0].from, bob_conversation);

    // Step 2: Bob asks to come in, and Alice sees the request.
    bob.accept_group_offer(offers[0].from.clone(), offers[0].group_id.clone())
        .unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::GroupJoiner => Some(()),
        _ => None,
    });
    let joiners = alice.group_joiners().unwrap();
    assert_eq!(joiners.len(), 1);
    assert_eq!(joiners[0].group_id, info.group_id);

    // Steps 3 to 5: the add, the snapshot on the chunk path, and the admit.
    alice
        .admit_joiner(joiners[0].from.clone(), joiners[0].group_id.clone())
        .unwrap();
    // The add applied at once, thus the roster of Alice holds two members.
    assert_eq!(alice.group_info(group.clone()).unwrap().members, 2);
    let start = Instant::now();
    let mut joined = None;
    while start.elapsed() < Duration::from_secs(60) {
        if let Some(summary) = bob
            .summaries()
            .unwrap()
            .into_iter()
            .find(|summary| bob.is_group(summary.conversation.clone()).unwrap_or(false))
        {
            joined = Some(summary.conversation);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let joined = joined.expect("Bob did not come into the group");
    let at_bob = bob.group_info(joined.clone()).unwrap();
    assert_eq!(at_bob.group_id, info.group_id);
    assert_eq!((at_bob.own_index, at_bob.members), (1, 2));
    assert!(at_bob.is_ready);
    // The admin that offered the group shows under the name of its contact.
    let members = bob.group_members(joined.clone()).unwrap();
    let admin = members.iter().find(|member| member.index == 0).unwrap();
    assert_eq!(admin.contact.as_deref(), Some(bob_conversation.as_slice()));
    assert_eq!(alice.group_info(group.clone()).unwrap().members, 2);
    assert!(alice.group_joiners().unwrap().is_empty());

    // A message of Alice reaches the member that came in.
    let draft = alice.new_draft(group.clone()).unwrap();
    draft.set_text(units("we leave at six")).unwrap();
    alice.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&bob);
    assert_eq!(conversation, joined);
    assert_eq!(rendered(&bob, message), "we leave at six");

    // A file of Alice goes to the group queue and reaches Bob with its name
    // (Part 11 §11.2, IMP-163, WIR-531).
    let plain: Vec<u8> = (0..70_000u32).map(|i| (i % 241) as u8).collect();
    let path = directory.join("route.gpx");
    std::fs::write(&path, &plain).unwrap();
    let draft = alice.new_draft(group.clone()).unwrap();
    draft
        .attach_file(
            path.to_str().unwrap().to_owned(),
            umbra_wire::descriptor::class::OTHER,
            0,
            0,
            0,
            Some("route.gpx".into()),
            None,
        )
        .unwrap();
    let sent = alice.send_draft(draft).unwrap();
    let (conversation, received) = wait_for_message(&bob);
    assert_eq!(conversation, joined);
    wait_for_file(&alice, &sent, 3);
    wait_for_file(&bob, &received, 3);
    let file = bob.msg_info(received.clone()).unwrap().file.unwrap();
    assert_eq!(file.name.as_deref(), Some("route.gpx"));
    assert_eq!(file.size, 70_000);
    assert_eq!(*bob.file_bytes(&received).unwrap(), plain);

    // The run of Alice ends and starts again, as at a change of the network
    // of the device. The group comes back with it, and no record of a
    // contact is needed to wake it.
    alice.disconnect();
    alice.clone().connect(networks[0].clone()).unwrap();
    let draft = bob.new_draft(joined.clone()).unwrap();
    draft.set_text(units("still in the group")).unwrap();
    bob.send_draft(draft).unwrap();
    let (conversation, message) = wait_for_message(&alice);
    assert_eq!(conversation, group);
    assert_eq!(rendered(&alice, message), "still in the group");

    alice.disconnect();
    bob.disconnect();
}

#[test]
fn two_members_talk_in_a_group_over_the_relays_of_a_signed_network() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let (keyset, _) = DirectoryKeySet::parse(&network.keyset).unwrap();
    let mut consensus = Consensus::new(keyset, 0).unwrap();
    let manifest = RelayManifest::parse(&network.manifest).unwrap();
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now).unwrap();
    let info_of = |relay: &ListedRelay| RelayInfo {
        candidate: relay.candidate,
        key: RelayStatic {
            s: relay.ntor_pk,
            relay_id: relay.candidate.relay_id,
        },
    };
    let ingress = set
        .relays
        .iter()
        .find(|relay| relay.candidate.ingress)
        .unwrap();
    let guard = Dial {
        host: ingress.host.clone(),
        addr_v4: Some(ingress.addr_v4),
        addr_v6: None,
        port: ingress.port,
    };

    // GRP-191: the two replicas take two operators and two blocs. Each test
    // relay has a jurisdiction of its own, thus a pair exists.
    let candidates: Vec<GroupRelay> = set
        .relays
        .iter()
        .filter(|relay| relay.candidate.is_exit())
        .map(|relay| GroupRelay {
            relay_id: relay.candidate.relay_id,
            operator_id: relay.candidate.operator_id,
            bloc: BlocList::v1().bloc_of(&relay.jurisdiction),
        })
        .collect();
    let pair = select_pair(&candidates).unwrap();
    assert!(!pair.relaxed);
    let replicas = pair.relays;

    let clients = tokio::runtime::Runtime::new().unwrap();
    let tls = native::tls_config_with_root_file(CA).unwrap();
    let start = |seed: u8| {
        let node = ClientNode::for_groups(
            info_of(ingress),
            set.relays
                .iter()
                .filter(|relay| !relay.candidate.ingress)
                .map(info_of)
                .collect(),
            umbra_crypto::hierarchy::RootIdentity::new(Secret::new([seed; 32])),
        );
        let (commands, task_commands) = tokio::sync::mpsc::unbounded_channel();
        let (task_updates, updates) = tokio::sync::mpsc::unbounded_channel();
        clients.spawn(run_groups(
            node,
            guard.clone(),
            tls.clone(),
            task_commands,
            task_updates,
        ));
        (commands, updates)
    };
    let (creator_tx, mut creator_rx) = start(0x91);
    let (member_tx, mut member_rx) = start(0x92);

    // The creator makes the group and one queue at each replica.
    let mut rng = OsRng;
    let creator_seed = Secret::new([0x41; 32]);
    let creator_pk = umbra_crypto::group::MemberKeys::from_seed(&creator_seed)
        .roster()
        .verifying_key()
        .to_bytes();
    let mut creator = Group::create([0x77; 32], &creator_seed, now, &mut rng).unwrap();
    let credentials = creator.credentials().unwrap();
    let (read_pk, write_pk) = (credentials.read_public(), credentials.write_public());
    let write_sk = credentials.write_secret();
    for (index, relay) in replicas.iter().enumerate() {
        creator_tx
            .send(GroupCommand::Create {
                tag: index as u64,
                relay: *relay,
                read_pk,
                write_pk,
                own: Secret::new(*creator.owner(index).unwrap().expose()),
            })
            .ok()
            .unwrap();
    }
    let mut queue_ids = [[0u8; 32]; 2];
    for _ in 0..2 {
        let GroupUpdate::Created {
            tag,
            relay,
            group_queue_id,
        } = group_update(&mut creator_rx)
        else {
            panic!("a replica made no group queue");
        };
        assert_eq!(relay, replicas[tag as usize]);
        queue_ids[tag as usize] = group_queue_id;
    }
    assert_ne!(queue_ids[0], queue_ids[1]);
    creator.set_replicas([
        umbra_wire::group::control::ReplicaRef {
            relay_id: replicas[0],
            group_queue_id: queue_ids[0],
            seq_of_add: 0,
        },
        umbra_wire::group::control::ReplicaRef {
            relay_id: replicas[1],
            group_queue_id: queue_ids[1],
            seq_of_add: 0,
        },
    ]);

    // The add and the admit travel on the pairwise channel, which this test
    // stands in for. §11.9.1 gives the four steps.
    let joiner = JoinKeys::make(&mut rng).unwrap();
    let kem_pk = joiner.keys.kem().public().to_bytes();
    let join_record = umbra_wire::group::control::JoinRecord {
        group_id: *creator.group_id(),
        keys: joiner.wire_keys(&kem_pk),
    };
    let add = creator.add_object(&join_record).unwrap();
    let add_control = umbra_wire::group::control::GroupControl::parse(&add).unwrap();
    let add_hash = add_control.epoch_hash();
    assert_eq!(
        creator.apply_control(&add_control, 0, now).unwrap(),
        Applied::Added(1)
    );
    let admit = creator.admit_for(1, 0, b"", now).unwrap();
    let admit_control = umbra_wire::group::control::GroupControl::parse(&admit).unwrap();
    let invitation =
        umbra_wire::group::control::GroupInvitation::parse(admit_control.payload).unwrap();
    let snapshot_bytes = creator.snapshot(&[]).unwrap();
    let snapshot = umbra_wire::group::control::RosterSnapshot::parse(&snapshot_bytes).unwrap();
    let admitted = accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now).unwrap();
    let mut member = Group::joined(admitted, &joiner.seed).unwrap();

    // One message of the creator goes to each replica (`GRP-194`).
    let text_of = |body: &[u8]| {
        let message = umbra_wire::app::AppMessage {
            kind: umbra_wire::app::AppKind::Text,
            msg_id: [0x5A; 16],
            sent_at: now * 1_000,
            body,
        };
        let mut out = vec![0u8; message.len()];
        let n = message.encode(&mut out).unwrap();
        out.truncate(n);
        out
    };
    let mut post = |group: &mut Group, body: &[u8], tag: u64| {
        let record = group.post(&text_of(body), now, &mut rng).unwrap();
        for (index, relay) in replicas.iter().enumerate() {
            creator_tx
                .send(GroupCommand::Post {
                    tag: tag + index as u64,
                    relay: *relay,
                    group_queue_id: queue_ids[index],
                    write: Secret::new(*write_sk.expose()),
                    fallback: None,
                    record: record.clone(),
                })
                .ok()
                .unwrap();
        }
        record
    };
    let first = post(&mut creator, b"a group of two", 10);
    for _ in 0..2 {
        let GroupUpdate::Posted { tag, seq, .. } = group_update(&mut creator_rx) else {
            panic!("a replica refused the record");
        };
        assert!(tag == 10 || tag == 11);
        assert_eq!(seq, 1);
    }

    // The member subscribes from the `seq` of its add, which is 0 here
    // because no roster record went to the queue. The record that waits
    // comes with the subscription (`WIR-387`).
    member_tx
        .send(GroupCommand::Subscribe {
            relay: replicas[0],
            group_queue_id: queue_ids[0],
            read: member.credentials().unwrap().read_secret(),
            fallback: None,
            from_seq: 0,
        })
        .ok()
        .unwrap();
    let mut read_one = |expected: &[u8], body: &[u8]| {
        let GroupUpdate::Record {
            group_queue_id,
            record: carried,
            ..
        } = group_update(&mut member_rx)
        else {
            panic!("the member got no record");
        };
        assert_eq!(group_queue_id, queue_ids[0]);
        assert_eq!(carried, expected);
        let Outcome::Content {
            sender, app: read, ..
        } = member.receive(&carried, now).unwrap()
        else {
            panic!("the record did not open");
        };
        assert_eq!(sender, 0);
        assert_eq!(
            umbra_wire::app::AppMessage::parse(&read, umbra_wire::app::Channel::Group)
                .unwrap()
                .body,
            body
        );
    };
    read_one(&first, b"a group of two");

    // A record that the relay takes while the session lives reaches the
    // reader without a second `GSUB` (`WIR-388`).
    let second = post(&mut creator, b"and a second line", 20);
    read_one(&second, b"and a second line");

    // A record under a credential that the queue does not hold is refused.
    creator_tx
        .send(GroupCommand::Post {
            tag: 12,
            relay: replicas[0],
            group_queue_id: queue_ids[0],
            write: Secret::new([0x13; 32]),
            fallback: None,
            record: second,
        })
        .ok()
        .unwrap();
    // The refusal and the two answers of the record before it arrive in
    // no fixed order, thus this loop waits for each of the three.
    let mut refused = false;
    let mut accepted = 0;
    while !refused || accepted < 2 {
        match group_update(&mut creator_rx) {
            GroupUpdate::Failed { tag: 12, .. } => refused = true,
            GroupUpdate::Posted { tag, .. } => {
                assert!(tag == 20 || tag == 21);
                accepted += 1;
            }
            other => panic!("{}", update_name(&other)),
        }
    }

    // §11.4: the creator removes the member and rotates in the same
    // action. The roster object goes out under the epoch that stands.
    let removal = creator.remove_object(1).unwrap();
    let removal_control = umbra_wire::group::control::GroupControl::parse(&removal).unwrap();
    let control_message = umbra_wire::app::AppMessage {
        kind: umbra_wire::app::AppKind::GroupControl,
        msg_id: [0x5B; 16],
        sent_at: now * 1_000,
        body: &removal,
    };
    let mut control_app = vec![0u8; control_message.len()];
    let control_len = control_message.encode(&mut control_app).unwrap();
    control_app.truncate(control_len);
    // GRP-389: the record names the roster epoch that stands, thus the
    // member it removes still reads the object that removes it.
    let control_record = creator.post(&control_app, now, &mut rng).unwrap();
    assert!(matches!(
        creator.apply_control(&removal_control, 0, now).unwrap(),
        Applied::Removed(_)
    ));
    for (index, relay) in replicas.iter().enumerate() {
        creator_tx
            .send(GroupCommand::Post {
                tag: 30 + index as u64,
                relay: *relay,
                group_queue_id: queue_ids[index],
                write: Secret::new(*write_sk.expose()),
                fallback: None,
                record: control_record.clone(),
            })
            .ok()
            .unwrap();
    }
    for _ in 0..2 {
        let GroupUpdate::Posted { tag, .. } = group_update(&mut creator_rx) else {
            panic!("a replica refused the roster object");
        };
        assert!(tag == 30 || tag == 31);
    }
    let GroupUpdate::Record {
        record: carried, ..
    } = group_update(&mut member_rx)
    else {
        panic!("the member got no roster object");
    };
    let Outcome::Content { app: read, .. } = member.receive(&carried, now).unwrap() else {
        panic!("the roster object did not open");
    };
    let parsed =
        umbra_wire::app::AppMessage::parse(&read, umbra_wire::app::Channel::Group).unwrap();
    let control = umbra_wire::group::control::GroupControl::parse(parsed.body).unwrap();
    assert!(matches!(
        member.apply_control(&control, 0, now).unwrap(),
        Applied::Removed(_)
    ));

    // The epoch-key record goes to each replica under the write
    // credential of the epoch before it (`GRP-362`).
    let rotation = creator.rotate(now, &mut rng).unwrap();
    assert_eq!(rotation.epoch, 2);
    let EpochCarrier::Inline(record) = &rotation.carrier else {
        panic!("a small group went on the chunk path");
    };
    for (index, relay) in replicas.iter().enumerate() {
        creator_tx
            .send(GroupCommand::Post {
                tag: 32 + index as u64,
                relay: *relay,
                group_queue_id: queue_ids[index],
                write: Secret::new(*rotation.write.expose()),
                fallback: None,
                record: record.clone(),
            })
            .ok()
            .unwrap();
    }
    for _ in 0..2 {
        let GroupUpdate::Posted { tag, .. } = group_update(&mut creator_rx) else {
            panic!("a replica refused the epoch-key record");
        };
        assert!(tag == 32 || tag == 33);
    }

    // The removed member still reads inside `GROUP_READ_GRACE`, and the
    // record holds no slot for it (`GRP-276`).
    let GroupUpdate::Record { record: key, .. } = group_update(&mut member_rx) else {
        panic!("the member got no epoch-key record");
    };
    let Outcome::EpochKey {
        epoch,
        start_slot,
        body,
    } = member.receive(&key, now).unwrap()
    else {
        panic!("the record is no epoch-key record");
    };
    assert_eq!(epoch, 2);
    assert!(member
        .install_epoch_key(epoch, start_slot, &body, now)
        .is_err());

    // The relay holds the credentials of the old epoch until a `GKEY`,
    // thus a record of the new epoch is refused before it and accepted
    // after it (`GRP-361`).
    let next = creator
        .post(&text_of(b"after the rotation"), now, &mut rng)
        .unwrap();
    let new_write = creator.credentials().unwrap().write_secret();
    let new_read = creator.credentials().unwrap().read_public();
    let new_write_pk = creator.credentials().unwrap().write_public();
    creator_tx
        .send(GroupCommand::Post {
            tag: 40,
            relay: replicas[0],
            group_queue_id: queue_ids[0],
            write: Secret::new(*new_write.expose()),
            fallback: None,
            record: next.clone(),
        })
        .ok()
        .unwrap();
    let GroupUpdate::Failed { tag: 40, .. } = group_update(&mut creator_rx) else {
        panic!("the relay took a credential it does not hold");
    };
    // GRP-398: the same record under the new pair, with the pair of the
    // epoch before it as the fallback, goes in before any `GKEY`.
    creator_tx
        .send(GroupCommand::Post {
            tag: 42,
            relay: replicas[1],
            group_queue_id: queue_ids[1],
            write: Secret::new(*new_write.expose()),
            fallback: Some(Secret::new(*rotation.write.expose())),
            record: next.clone(),
        })
        .ok()
        .unwrap();
    let GroupUpdate::Posted { tag: 42, .. } = group_update(&mut creator_rx) else {
        panic!("the fallback did not take the record");
    };
    creator_tx
        .send(GroupCommand::Rotate {
            relay: replicas[0],
            group_queue_id: queue_ids[0],
            own: Secret::new(*creator.owner(0).unwrap().expose()),
            next_own_pk: None,
            read_pk: new_read,
            write_pk: new_write_pk,
        })
        .ok()
        .unwrap();
    creator_tx
        .send(GroupCommand::Post {
            tag: 41,
            relay: replicas[0],
            group_queue_id: queue_ids[0],
            write: Secret::new(*new_write.expose()),
            fallback: None,
            record: next,
        })
        .ok()
        .unwrap();
    let GroupUpdate::Posted { tag: 41, .. } = group_update(&mut creator_rx) else {
        panic!("the replica refused the record after the `GKEY`");
    };
}

/// The name of an update, for a test that met one it did not expect.
fn update_name(update: &GroupUpdate) -> &'static str {
    match update {
        GroupUpdate::Created { .. } => "created",
        GroupUpdate::Posted { .. } => "posted",
        GroupUpdate::Record { .. } => "record",
        GroupUpdate::Failed { .. } => "failed",
        GroupUpdate::Unsent { .. } => "unsent",
        GroupUpdate::SubscriptionLost { .. } => "subscription lost",
        GroupUpdate::Reset => "reset",
        GroupUpdate::Ended => "ended",
    }
}

#[test]
fn the_group_run_outlives_its_relays_and_carries_its_commands_on() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (keyset, _) = DirectoryKeySet::parse(&network.keyset).unwrap();
    let mut consensus = Consensus::new(keyset, 0).unwrap();
    let manifest = RelayManifest::parse(&network.manifest).unwrap();
    let set = RelaySet::accept(&mut consensus, &manifest, &BlocList::v1(), now).unwrap();
    let info_of = |relay: &ListedRelay| RelayInfo {
        candidate: relay.candidate,
        key: RelayStatic {
            s: relay.ntor_pk,
            relay_id: relay.candidate.relay_id,
        },
    };
    let ingress = set
        .relays
        .iter()
        .find(|relay| relay.candidate.ingress)
        .unwrap();
    let guard = Dial {
        host: ingress.host.clone(),
        addr_v4: Some(ingress.addr_v4),
        addr_v6: None,
        port: ingress.port,
    };
    let exit = set
        .relays
        .iter()
        .find(|relay| relay.candidate.is_exit())
        .unwrap()
        .candidate
        .relay_id;
    let node = ClientNode::for_groups(
        info_of(ingress),
        set.relays
            .iter()
            .filter(|relay| !relay.candidate.ingress)
            .map(info_of)
            .collect(),
        umbra_crypto::hierarchy::RootIdentity::new(Secret::new([0x93; 32])),
    );
    let clients = tokio::runtime::Runtime::new().unwrap();
    let (commands, task_commands) = tokio::sync::mpsc::unbounded_channel();
    let (task_updates, mut updates) = tokio::sync::mpsc::unbounded_channel();
    clients.spawn(run_groups(
        node,
        guard,
        native::tls_config_with_root_file(CA).unwrap(),
        task_commands,
        task_updates,
    ));
    let create = |tag: u64| GroupCommand::Create {
        tag,
        relay: exit,
        read_pk: [0x11; 32],
        write_pk: [0x12; 32],
        own: Secret::new([0x13; 32]),
    };
    commands.send(create(1)).ok().unwrap();
    let GroupUpdate::Created {
        tag: 1,
        group_queue_id,
        ..
    } = group_update(&mut updates)
    else {
        panic!("the relay made no group queue");
    };

    // Each relay process ends. The run does not end with its link: it
    // tells the caller, and it opens a new link after a backoff.
    drop(relays);
    let update = group_update(&mut updates);
    assert!(
        matches!(update, GroupUpdate::Reset),
        "{}",
        update_name(&update)
    );
    // A record that the caller gives while no relay runs waits in the
    // run, and it fails nowhere.
    commands
        .send(GroupCommand::Post {
            tag: 2,
            relay: exit,
            group_queue_id,
            write: Secret::new([0x14; 32]),
            fallback: None,
            record: vec![0; umbra_wire::bucket::Bucket::B0.group_record()],
        })
        .ok()
        .unwrap();

    // The same relays come back on the same ports, with empty stores. The
    // record goes in the new session, and the relay answers it: the queue
    // it names is gone with the old process.
    let relays = tokio::runtime::Runtime::new().unwrap();
    let _again = start_signed_network_at(&relays, Some(&network.ports));
    let mut answered = false;
    let start = Instant::now();
    while !answered && start.elapsed() < Duration::from_secs(90) {
        match group_update(&mut updates) {
            GroupUpdate::Failed {
                tag: 2,
                reason: Some(_),
            } => answered = true,
            GroupUpdate::Reset => {}
            other => panic!("{}", update_name(&other)),
        }
    }
    assert!(answered, "the record did not go in the new session");
    // The new session takes a new command as the first one did.
    commands.send(create(3)).ok().unwrap();
    let GroupUpdate::Created { tag: 3, .. } = group_update(&mut updates) else {
        panic!("the new session made no group queue");
    };

    // The run ends when the caller drops the commands, and not before.
    drop(commands);
    loop {
        match group_update(&mut updates) {
            GroupUpdate::Ended => break,
            GroupUpdate::Reset => {}
            other => panic!("{}", update_name(&other)),
        }
    }
}

#[test]
fn an_app_in_the_foreground_writes_its_backup_to_the_relays() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-backup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let alice = launch(&directory, "alice.db", 1);
    let verified = alice
        .network_of_manifest(
            network.manifest.clone(),
            network.keyset.clone(),
            0,
            HOST.into(),
            Some(CA.into()),
        )
        .unwrap()
        .network;
    assert_eq!(alice.last_backup_at(), None);
    // IDN-080: a device in the background writes none.
    alice.clone().connect(verified).unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(alice.last_backup_at(), None);

    // In the foreground the first full object goes up at the next check,
    // which runs each minute of a ready run.
    alice.set_foreground(true);
    let start = Instant::now();
    while alice.last_backup_at().is_none() {
        assert!(start.elapsed() < Duration::from_secs(150), "no backup");
        std::thread::sleep(Duration::from_millis(250));
    }
    alice.disconnect();
}

#[test]
fn a_lost_phone_comes_back_from_its_backup_and_its_contact_talks_again() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-restore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let network_for = |handle: &Handle| {
        handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network
    };
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    for handle in [&alice, &bob] {
        handle.clone().connect(network_for(handle)).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);
    let draft = bob.new_draft(bob_conversation.clone()).unwrap();
    draft.set_text(units("see you soon")).unwrap();
    bob.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&alice);
    assert_eq!(rendered(&alice, message), "see you soon");

    // The backup of Alice goes up, and she writes her recovery code down.
    alice.set_foreground(true);
    let start = Instant::now();
    while alice.last_backup_at().is_none() {
        assert!(start.elapsed() < Duration::from_secs(150), "no backup");
        std::thread::sleep(Duration::from_millis(250));
    }
    // The root follows the object.
    std::thread::sleep(Duration::from_secs(5));
    let code = Arc::new(View::default());
    alice.recovery_code(code.clone()).unwrap();
    let digits = code.0.lock().unwrap().clone();
    assert_eq!(recovery_digits_kind(digits.clone()), 1);
    assert_eq!(recovery_digits_kind(units("12345")), 0);

    // The phone is lost.
    alice.disconnect();
    drop(alice);

    // A new phone: a first launch, the network, and the restore.
    let fresh = launch(&directory, "new.db", 3);
    fresh.clone().connect(network_for(&fresh)).unwrap();
    wait_for(&fresh, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    fresh.restore_backup(digits).unwrap();
    let start = Instant::now();
    loop {
        match fresh.restore_status() {
            RestoreStatus::Ready { contacts } => {
                assert_eq!(contacts, 1);
                break;
            }
            RestoreStatus::Searching { .. } | RestoreStatus::Fetching { .. } => {}
            other => panic!("{other:?}"),
        }
        assert!(start.elapsed() < Duration::from_secs(60), "no restore");
        std::thread::sleep(Duration::from_millis(100));
    }
    let restored = fresh.take_restored().unwrap();
    fresh.disconnect();
    drop(fresh);
    let config = Config {
        database_path: directory.join("new.db").to_str().unwrap().to_owned(),
        argon2_floor_ms: 60_000,
    };
    let keystore = Arc::new(Keystore([3; 32])) as Arc<dyn SecureElementCallback>;
    let back = init_restored(config, keystore, units("a new phrase"), restored).unwrap();

    // The conversation and its history are here, under the new passphrase.
    assert!(back
        .summaries()
        .unwrap()
        .iter()
        .any(|summary| summary.conversation == alice_conversation));
    back.clone().connect(network_for(&back)).unwrap();

    // NET-325 to NET-329: the stale channel renews, and the two talk again.
    let draft = back.new_draft(alice_conversation.clone()).unwrap();
    draft.set_text(units("I am back")).unwrap();
    back.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&bob);
    assert_eq!(rendered(&bob, message), "I am back");
    let draft = bob.new_draft(bob_conversation).unwrap();
    draft.set_text(units("welcome back")).unwrap();
    bob.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&back);
    assert_eq!(rendered(&back, message), "welcome back");
    back.disconnect();
    bob.disconnect();
}

/// Ticks each handle until `done` holds, and panics after a minute.
#[track_caller]
fn tick_until(handles: &[&Arc<Handle>], mut done: impl FnMut() -> bool, what: &str) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < Duration::from_secs(60), "{what}");
        for handle in handles {
            (*handle).clone().tick();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_new_device_links_from_the_code_of_the_existing_one() {
    // The tests of several devices take turns, thus the suite keeps its
    // waits on a loaded machine.
    let _turn = DEVICE_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let network_for = |handle: &Handle| {
        handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network
    };
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    for handle in [&alice, &bob] {
        handle.clone().connect(network_for(handle)).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);
    let draft = bob.new_draft(bob_conversation.clone()).unwrap();
    draft.set_text(units("before the tablet")).unwrap();
    bob.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&alice);
    assert_eq!(rendered(&alice, message), "before the tablet");
    assert!(alice.devices().unwrap().is_empty());

    // DEV-280: the offer goes up before the ticket shows.
    alice.start_link("Phone".into()).unwrap();
    let mut ticket = String::new();
    tick_until(
        &[&alice],
        || match alice.link_status() {
            LinkStatus::Ticket { text } => {
                ticket = text;
                true
            }
            LinkStatus::Preparing => false,
            other => panic!("{other:?}"),
        },
        "no ticket",
    );
    assert!(ticket.starts_with("UMBRA-LINK:"));
    // DEV-285: the set begins with the existing device alone.
    let devices = alice.devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert!(devices[0].is_self);

    // The new device joins on a handle of its own.
    let tablet = launch(&directory, "tablet.db", 3);
    tablet.clone().connect(network_for(&tablet)).unwrap();
    wait_for(&tablet, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    assert_eq!(
        tablet
            .join_link("UMBRA-LINK:AAAA".into(), "Tablet".into())
            .err(),
        Some(FfiError::Malformed)
    );
    tablet.join_link(ticket, "Tablet".into()).unwrap();

    // DEV-283: the two screens show one code.
    let code_of = |handle: &Handle| match handle.link_status() {
        LinkStatus::Code { code } => Some(code),
        _ => None,
    };
    tick_until(
        &[&alice, &tablet],
        || code_of(&alice).is_some() && code_of(&tablet).is_some(),
        "no code",
    );
    assert_eq!(code_of(&alice), code_of(&tablet));
    assert_eq!(code_of(&alice).unwrap().len(), 6);
    // No provision before the confirmation.
    std::thread::sleep(Duration::from_secs(3));
    assert!(code_of(&tablet).is_some());

    alice.confirm_link().unwrap();
    tick_until(
        &[&alice, &tablet],
        || match tablet.link_status() {
            LinkStatus::Ready => true,
            LinkStatus::Code { .. } | LinkStatus::Fetching => false,
            other => panic!("{other:?}"),
        },
        "no snapshot",
    );
    let linked = tablet.take_linked().unwrap();
    tablet.disconnect();
    drop(tablet);
    let config = Config {
        database_path: directory.join("tablet.db").to_str().unwrap().to_owned(),
        argon2_floor_ms: 60_000,
    };
    let keystore = Arc::new(Keystore([3; 32])) as Arc<dyn SecureElementCallback>;
    let tablet = init_linked(config, keystore, units("tablet phrase"), linked).unwrap();

    // DEV-284: the history is here, and the tablet is in the set.
    let summaries = tablet.summaries().unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].conversation, alice_conversation);
    let devices = tablet.devices().unwrap();
    assert_eq!(devices.len(), 2);
    let own = devices.iter().find(|device| device.is_self).unwrap();
    assert_eq!(own.label, "Tablet");
    assert_eq!(own.added_epoch, 1);

    // DEV-286: the first run opens the sync channel, and neither device
    // shows it as a conversation.
    // The app connects at the open and again when its carrier starts.
    tablet.clone().connect(network_for(&tablet)).unwrap();
    tablet.clone().connect(network_for(&tablet)).unwrap();
    wait_for(&tablet, |event| match event {
        FfiEvent::DeviceLinked => Some(()),
        _ => None,
    });
    wait_for(&alice, |event| match event {
        FfiEvent::DeviceLinked => Some(()),
        _ => None,
    });
    assert_eq!(alice.link_status(), LinkStatus::Linked);
    assert_eq!(alice.devices().unwrap().len(), 2);
    assert_eq!(alice.summaries().unwrap().len(), 1);
    assert_eq!(tablet.summaries().unwrap().len(), 1);

    // DEV-287: the existing device still owns the channel of Bob, and
    // DEV-268: the record of Bob reaches the tablet on the sync channel.
    let draft = bob.new_draft(bob_conversation.clone()).unwrap();
    draft.set_text(units("after the tablet")).unwrap();
    bob.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&alice);
    assert_eq!(rendered(&alice, message), "after the tablet");
    let (conversation, message) = wait_for_message(&tablet);
    assert_eq!(conversation, alice_conversation);
    assert_eq!(rendered(&tablet, message), "after the tablet");

    // A record that the phone sends reaches the tablet as one of the user.
    let draft = alice.new_draft(alice_conversation.clone()).unwrap();
    draft.set_text(units("from the phone")).unwrap();
    alice.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&bob);
    assert_eq!(rendered(&bob, message), "from the phone");
    let texts_of = |handle: &Handle| -> Vec<(String, bool)> {
        handle
            .messages(alice_conversation.clone())
            .unwrap()
            .into_iter()
            .map(|message| {
                let outgoing = handle.msg_info(message.clone()).unwrap().outgoing;
                (rendered(handle, message), outgoing)
            })
            .collect()
    };
    let start = Instant::now();
    while !texts_of(&tablet).contains(&("from the phone".into(), true)) {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no copy of the send"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // DEV-047: a record that the tablet composes goes to Bob through the
    // phone, under the msg_id of the tablet. Bob sends delivery receipts.
    bob.set_receipt_settings(
        bob_conversation.clone(),
        Receipts {
            delivery: true,
            read: false,
        },
    )
    .unwrap();
    let draft = tablet.new_draft(alice_conversation.clone()).unwrap();
    draft.set_text(units("from the tablet")).unwrap();
    tablet.send_draft(draft).unwrap();
    let (_, message) = wait_for_message(&bob);
    assert_eq!(rendered(&bob, message), "from the tablet");
    let start = Instant::now();
    while !texts_of(&alice).contains(&("from the tablet".into(), true)) {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no copy at the phone"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // DEV-304: the receipt of Bob reaches the phone, and the state of the
    // message reaches the tablet that composed it.
    let on_tablet = tablet
        .messages(alice_conversation.clone())
        .unwrap()
        .into_iter()
        .find(|message| rendered(&tablet, message.clone()) == "from the tablet")
        .unwrap();
    let on_phone = alice
        .messages(alice_conversation.clone())
        .unwrap()
        .into_iter()
        .find(|message| rendered(&alice, message.clone()) == "from the tablet")
        .unwrap();
    // A receipt waits `RECEIPT_MIN_DELAY` and then a slot of the cover
    // clock (Part 3 §3.5.4).
    let start = Instant::now();
    while tablet.msg_info(on_tablet.clone()).unwrap().delivery != 2 {
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "the tablet did not learn the delivery: phone {} tablet {}",
            alice.msg_info(on_phone.clone()).unwrap().delivery,
            tablet.msg_info(on_tablet.clone()).unwrap().delivery,
        );
        for handle in [&alice, &tablet, &bob] {
            handle.clone().tick();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    // DEV-294: a contact that the phone makes after the link, and its
    // name, reach the tablet, and so does the first record of that contact.
    let carol = launch(&directory, "carol.db", 4);
    carol.clone().connect(network_for(&carol)).unwrap();
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    carol.accept(link).unwrap();
    let alice_carol = wait_for_contact(&alice);
    let carol_conversation = wait_for_contact(&carol);
    alice
        .set_contact_name(alice_carol.clone(), "Carol".into())
        .unwrap();
    let start = Instant::now();
    loop {
        let named = tablet
            .summaries()
            .unwrap()
            .into_iter()
            .any(|summary| summary.conversation == alice_carol && summary.name == "Carol");
        if named {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no new contact on the tablet"
        );
        tablet.clone().tick();
        std::thread::sleep(Duration::from_millis(200));
    }
    let draft = carol.new_draft(carol_conversation).unwrap();
    draft.set_text(units("hello from carol")).unwrap();
    carol.send_draft(draft).unwrap();
    let (conversation, message) = wait_for(&tablet, |event| match event {
        FfiEvent::Message {
            conversation,
            message,
        } if conversation == alice_carol => Some((conversation, message)),
        _ => None,
    });
    assert_eq!(conversation, alice_carol);
    assert_eq!(rendered(&tablet, message), "hello from carol");
    carol.disconnect();

    // One copy on each device, and the tablet holds its own one time.
    assert_eq!(
        texts_of(&alice)
            .iter()
            .filter(|(text, _)| text == "from the tablet")
            .count(),
        1
    );
    assert_eq!(
        texts_of(&tablet)
            .iter()
            .filter(|(text, _)| text == "from the tablet")
            .count(),
        1
    );
    // §7.7: the snapshot held no recovery code of the phone, thus a device
    // that the user removes reads no later backup.
    let code_of = |handle: &Handle| {
        let view = Arc::new(View::default());
        handle.recovery_code(view.clone()).unwrap();
        let digits = view.0.lock().unwrap().clone();
        digits
    };
    assert_ne!(code_of(&alice), code_of(&tablet));

    // The phone removes the tablet: the set holds the phone alone, a record
    // of Bob reaches the phone and not the tablet, and a record that the
    // tablet hands over reaches nobody.
    let tablet_id = tablet
        .devices()
        .unwrap()
        .into_iter()
        .find(|device| device.is_self)
        .unwrap()
        .device_id;
    assert_eq!(
        tablet.remove_device(tablet_id.clone()).err(),
        Some(FfiError::NotFound)
    );
    alice.remove_device(tablet_id).unwrap();
    assert_eq!(alice.devices().unwrap().len(), 1);
    let draft = bob.new_draft(bob_conversation.clone()).unwrap();
    draft.set_text(units("after the removal")).unwrap();
    bob.send_draft(draft).unwrap();
    // The phone holds an earlier record of Carol in its events too.
    wait_for(&alice, |event| match event {
        FfiEvent::Message { message, .. } => {
            (rendered(&alice, message) == "after the removal").then_some(())
        }
        _ => None,
    });
    let draft = tablet.new_draft(alice_conversation.clone()).unwrap();
    draft.set_text(units("from a removed tablet")).unwrap();
    tablet.send_draft(draft).unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Some(FfiEvent::Message { message, .. }) = tablet.wait_event(200) {
            assert_ne!(rendered(&tablet, message), "after the removal");
        }
        if let Some(FfiEvent::Message { message, .. }) = bob.wait_event(200) {
            assert_ne!(rendered(&bob, message), "from a removed tablet");
        }
    }
    // The channel of the removed tablet shows as no conversation, in this
    // run and in the next one.
    assert_eq!(alice.summaries().unwrap().len(), 2);
    alice.clone().connect(network_for(&alice)).unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    assert_eq!(alice.summaries().unwrap().len(), 2);
    for handle in [&alice, &bob, &tablet] {
        handle.disconnect();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// Links a new device to `owner` (Part 7 §7.4) and gives its handle, on
/// its own first run.
#[track_caller]
fn link_new_device(
    owner: &Arc<Handle>,
    directory: &std::path::Path,
    name: &str,
    key: u8,
    network_for: &dyn Fn(&Handle) -> Network,
) -> Arc<Handle> {
    owner.start_link("Phone".into()).unwrap();
    let mut ticket = String::new();
    tick_until(
        &[owner],
        || match owner.link_status() {
            LinkStatus::Ticket { text } => {
                ticket = text;
                true
            }
            _ => false,
        },
        "no ticket",
    );
    let fresh = launch(directory, name, key);
    fresh.clone().connect(network_for(&fresh)).unwrap();
    wait_for(&fresh, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    fresh.join_link(ticket, "Tablet".into()).unwrap();
    tick_until(
        &[owner, &fresh],
        || matches!(owner.link_status(), LinkStatus::Code { .. }),
        "no code",
    );
    owner.confirm_link().unwrap();
    tick_until(
        &[owner, &fresh],
        || fresh.link_status() == LinkStatus::Ready,
        "no snapshot",
    );
    let linked = fresh.take_linked().unwrap();
    fresh.disconnect();
    drop(fresh);
    let config = Config {
        database_path: directory.join(name).to_str().unwrap().to_owned(),
        argon2_floor_ms: 60_000,
    };
    let keystore = Arc::new(Keystore([key; 32])) as Arc<dyn SecureElementCallback>;
    let device = init_linked(config, keystore, units("device phrase"), linked).unwrap();
    device.clone().connect(network_for(&device)).unwrap();
    wait_for(&device, |event| match event {
        FfiEvent::DeviceLinked => Some(()),
        _ => None,
    });
    // The owner reads flight 3 after the new device, thus its side of the
    // link ends a moment later, and a second link waits for it.
    tick_until(
        &[owner, &device],
        || owner.link_status() == LinkStatus::Linked,
        "the owner did not end the link",
    );
    device
}

/// A message of `handle` whose text is `text`, in `conversation`.
#[track_caller]
fn wait_for_text(handle: &Handle, conversation: &[u8], text: &str) {
    wait_for(handle, |event| match event {
        FfiEvent::Message {
            conversation: held,
            message,
        } if held == conversation => (rendered(handle, message) == text).then_some(()),
        _ => None,
    });
}

/// Whether the store of `handle` holds a message with `text`.
fn holds_text(handle: &Handle, conversation: &[u8], text: &str) -> bool {
    handle
        .messages(conversation.to_vec())
        .unwrap()
        .into_iter()
        .any(|message| rendered(handle, message) == text)
}

/// Whether the store of `handle` holds a message of the user with `text`.
fn holds_own_text(handle: &Handle, conversation: &[u8], text: &str) -> bool {
    handle
        .messages(conversation.to_vec())
        .unwrap()
        .into_iter()
        .any(|message| {
            handle.msg_info(message.clone()).unwrap().outgoing && rendered(handle, message) == text
        })
}

#[test]
fn a_linked_device_reads_and_writes_a_group() {
    // The tests of several devices take turns, thus the suite keeps its
    // waits on a loaded machine.
    let _turn = DEVICE_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-link-group-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let network_for = |handle: &Handle| {
        handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network
    };
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    for handle in [&alice, &bob] {
        handle.clone().connect(network_for(handle)).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    wait_for_contact(&bob);

    // Alice makes a group, and Bob joins it.
    let group = alice.create_group("Summit".into()).unwrap();
    let start = Instant::now();
    while !alice.group_info(group.clone()).unwrap().is_ready {
        assert!(start.elapsed() < STEP, "the group took no queues");
        std::thread::sleep(Duration::from_millis(50));
    }
    alice
        .offer_group(group.clone(), alice_conversation)
        .unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::GroupOffer => Some(()),
        _ => None,
    });
    let offer = bob.group_offers().unwrap().remove(0);
    bob.accept_group_offer(offer.from, offer.group_id).unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::GroupJoiner => Some(()),
        _ => None,
    });
    let joiner = alice.group_joiners().unwrap().remove(0);
    alice.admit_joiner(joiner.from, joiner.group_id).unwrap();
    let start = Instant::now();
    let joined = loop {
        let found = bob
            .summaries()
            .unwrap()
            .into_iter()
            .find(|summary| bob.is_group(summary.conversation.clone()).unwrap_or(false));
        if let Some(summary) = found {
            break summary.conversation;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "Bob did not come in"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // The tablet joins the set of Alice, and it holds the group.
    let tablet = link_new_device(&alice, &directory, "tablet.db", 3, &network_for);
    assert!(tablet.is_group(group.clone()).unwrap());

    // GRP-343: a record of Bob reaches the tablet on its own subscription.
    let draft = bob.new_draft(joined.clone()).unwrap();
    draft.set_text(units("from bob")).unwrap();
    bob.send_draft(draft).unwrap();
    wait_for_text(&alice, &group, "from bob");
    wait_for_text(&tablet, &group, "from bob");

    // DEV-296: a record of Alice reaches the tablet on the sync channel.
    let draft = alice.new_draft(group.clone()).unwrap();
    draft.set_text(units("from the phone")).unwrap();
    alice.send_draft(draft).unwrap();
    wait_for_text(&bob, &joined, "from the phone");
    let start = Instant::now();
    while !holds_own_text(&tablet, &group, "from the phone") {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no copy on the tablet"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // GRP-340: a record that the tablet composes goes to the group through
    // the phone, and the phone holds it as its own.
    let draft = tablet.new_draft(group.clone()).unwrap();
    draft.set_text(units("from the tablet")).unwrap();
    tablet.send_draft(draft).unwrap();
    wait_for_text(&bob, &joined, "from the tablet");
    let start = Instant::now();
    while !holds_own_text(&alice, &group, "from the tablet") {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no copy on the phone"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // GRP-338: the tablet makes no group of its own.
    assert!(tablet.create_group("Other".into()).is_err());

    // DEV-126: a delete for me removes the message on each device of the
    // set, and Bob keeps his copy.
    let from_bob = alice
        .messages(group.clone())
        .unwrap()
        .into_iter()
        .find(|message| rendered(&alice, message.clone()) == "from bob")
        .unwrap();
    assert!(holds_text(&tablet, &group, "from bob"));
    alice.delete_for_me(from_bob).unwrap();
    assert!(!holds_text(&alice, &group, "from bob"));
    let start = Instant::now();
    while holds_text(&tablet, &group, "from bob") {
        assert!(start.elapsed() < STEP, "the tablet kept the message");
        std::thread::sleep(Duration::from_millis(200));
    }

    // GRP-345: the phone removes the tablet, and it moves to new keys in the
    // group under a new index. Bob and the phone still talk.
    let own_before = alice.group_info(group.clone()).unwrap().own_index;
    let tablet_id = tablet
        .devices()
        .unwrap()
        .into_iter()
        .find(|device| device.is_self)
        .unwrap()
        .device_id;
    alice.remove_device(tablet_id).unwrap();
    let own_after = alice.group_info(group.clone()).unwrap().own_index;
    assert_ne!(own_after, own_before);
    let draft = alice.new_draft(group.clone()).unwrap();
    draft.set_text(units("after the rekey")).unwrap();
    alice.send_draft(draft).unwrap();
    wait_for_text(&bob, &joined, "after the rekey");
    let draft = bob.new_draft(joined.clone()).unwrap();
    draft.set_text(units("bob after the rekey")).unwrap();
    bob.send_draft(draft).unwrap();
    wait_for_text(&alice, &group, "bob after the rekey");
    for handle in [&alice, &bob, &tablet] {
        handle.disconnect();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// DEV-298 to DEV-301: a group that the phone makes after two links reaches
/// each linked device, and the device that stays follows the re-key of a
/// removal and reads the group on.
#[test]
fn a_group_made_after_the_link_reaches_each_linked_device() {
    // The tests of several devices take turns, thus the suite keeps its
    // waits on a loaded machine.
    let _turn = DEVICE_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-late-group-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let network_for = |handle: &Handle| {
        handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network
    };
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    for handle in [&alice, &bob] {
        handle.clone().connect(network_for(handle)).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    wait_for_contact(&bob);

    // The two devices link before the group exists.
    let tablet = link_new_device(&alice, &directory, "tablet.db", 3, &network_for);
    let laptop = link_new_device(&alice, &directory, "laptop.db", 4, &network_for);

    let group = alice.create_group("Later".into()).unwrap();
    let start = Instant::now();
    while !alice.group_info(group.clone()).unwrap().is_ready {
        assert!(start.elapsed() < STEP, "the group took no queues");
        std::thread::sleep(Duration::from_millis(50));
    }
    alice
        .offer_group(group.clone(), alice_conversation)
        .unwrap();
    wait_for(&bob, |event| match event {
        FfiEvent::GroupOffer => Some(()),
        _ => None,
    });
    let offer = bob.group_offers().unwrap().remove(0);
    bob.accept_group_offer(offer.from, offer.group_id).unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::GroupJoiner => Some(()),
        _ => None,
    });
    let joiner = alice.group_joiners().unwrap().remove(0);
    alice.admit_joiner(joiner.from, joiner.group_id).unwrap();
    let start = Instant::now();
    let joined = loop {
        let found = bob
            .summaries()
            .unwrap()
            .into_iter()
            .find(|summary| bob.is_group(summary.conversation.clone()).unwrap_or(false));
        if let Some(summary) = found {
            break summary.conversation;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "Bob did not come in"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // DEV-298, DEV-299: each linked device holds the group.
    tick_until(
        &[&alice, &tablet, &laptop],
        || tablet.is_group(group.clone()).unwrap() && laptop.is_group(group.clone()).unwrap(),
        "the group did not reach the linked devices",
    );
    let draft = bob.new_draft(joined.clone()).unwrap();
    draft.set_text(units("from bob")).unwrap();
    bob.send_draft(draft).unwrap();
    wait_for_text(&alice, &group, "from bob");
    // A linked device builds its own circuits to the replicas first.
    let start = Instant::now();
    loop {
        let (t, l) = (
            holds_text(&tablet, &group, "from bob"),
            holds_text(&laptop, &group, "from bob"),
        );
        if t && l {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the linked devices did not read the group: tablet {t} laptop {l}, reading tablet {:?} laptop {:?}",
            tablet.group_info(group.clone()).map(|info| info.is_ready),
            laptop.group_info(group.clone()).map(|info| info.is_ready),
        );
        for handle in [&tablet, &laptop] {
            handle.clone().tick();
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // DEV-300, DEV-301: the phone removes the tablet and re-keys, and the
    // laptop moves to the same index and reads the group on.
    let tablet_id = tablet
        .devices()
        .unwrap()
        .into_iter()
        .find(|device| device.is_self)
        .unwrap()
        .device_id;
    alice.remove_device(tablet_id).unwrap();
    let own_after = alice.group_info(group.clone()).unwrap().own_index;
    tick_until(
        &[&alice, &laptop],
        || laptop.group_info(group.clone()).unwrap().own_index == own_after,
        "the laptop did not follow the re-key",
    );
    let draft = bob.new_draft(joined.clone()).unwrap();
    draft.set_text(units("bob after the rekey")).unwrap();
    bob.send_draft(draft).unwrap();
    wait_for_text(&alice, &group, "bob after the rekey");
    tick_until(
        &[&laptop],
        || holds_text(&laptop, &group, "bob after the rekey"),
        "the laptop did not read the group after the re-key",
    );
    for handle in [&alice, &bob, &tablet, &laptop] {
        handle.disconnect();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// Waits until `handle` holds `count` contact requests. A hello crosses
/// two circuits, and a loaded machine slows each build.
#[track_caller]
fn wait_for_requests(handle: &Arc<Handle>, count: usize) {
    let start = Instant::now();
    while handle.contact_requests().unwrap().len() < count {
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "no contact request"
        );
        handle.clone().tick();
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Sends a contact request to `target` until the log shows its entry: a
/// registration or a write shows at the next epoch (`DIS-166`).
fn request_until_listed(handle: &Handle, target: &str) {
    request_with_note(handle, target, "");
}

/// A request with a note, once the log lists its target.
#[track_caller]
fn request_with_note(handle: &Handle, target: &str, note: &str) {
    let start = Instant::now();
    loop {
        match handle.send_contact_request(target.into(), note.into(), false) {
            Ok(()) => return,
            Err(FfiError::NotFound | FfiError::Busy) => {
                assert!(
                    start.elapsed() < Duration::from_secs(40),
                    "{target} never listed"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(other) => panic!("{other:?}"),
        }
    }
}

/// The preview of a profile link, once the log lists its handle.
#[track_caller]
fn preview_until_listed(handle: &Handle, target: &str) -> (String, String, String, Vec<u8>) {
    let start = Instant::now();
    loop {
        match handle.preview_contact(target.into()) {
            Ok(preview) => {
                return (
                    preview.handle,
                    preview.name,
                    preview.welcome,
                    preview.picture,
                )
            }
            Err(FfiError::NotFound | FfiError::Busy) => {
                assert!(
                    start.elapsed() < Duration::from_secs(40),
                    "{target} never listed"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(other) => panic!("{other:?}"),
        }
    }
}

/// Part 9 end to end through the app: a reusable link and a handle take
/// requests, the link moves to a new queue at its rotation (`DIS-133`), and
/// a retired link takes none.
#[test]
fn a_link_and_a_handle_take_requests_and_the_link_moves_to_a_new_queue() {
    let _turn = DEVICE_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let relays = tokio::runtime::Runtime::new().unwrap();
    let (directory_port, pins) = start_test_directory(&relays);
    let network = start_signed_network_with(&relays, None, None, Some(directory_port));
    let directory = std::env::temp_dir().join(format!("umbra-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let ingress = network.ports[0];
    let network_for = |handle: &Handle| Network {
        directory_relay_url: Some(format!("https://localhost:{ingress}/directory")),
        directory_pins: Some(pins.clone()),
        directory_relay_ipv4: Some(vec![127, 1, 0, 1]),
        ..handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network
    };
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    let carol = launch(&directory, "carol.db", 3);
    for handle in [&alice, &bob, &carol] {
        handle.clone().connect(network_for(handle)).unwrap();
        wait_for(handle, |event| match event {
            FfiEvent::Online => Some(()),
            _ => None,
        });
    }
    assert!(alice.has_directory());

    // A reusable link, and the request of Bob to it.
    let link = alice.create_public_link(0).unwrap();
    assert!(link.link.starts_with("umbra://p/"));
    bob.set_profile_name("Bob".into()).unwrap();
    // DIS-132: a cross-relay token admits the hello in place of the proof
    // of work. The addressee holds the key from the log.
    alice.stock_tokens(0).unwrap();
    bob.stock_tokens(1).unwrap();
    assert_eq!(bob.tokens_held().unwrap(), 1);
    // DIS-180: the hello carries the profile of the sender and its note.
    request_with_note(&bob, &link.link, "We met at the summit.");
    assert_eq!(bob.tokens_held().unwrap(), 0);
    wait_for_requests(&alice, 1);
    let request = alice.contact_requests().unwrap().remove(0);
    assert_eq!(
        (request.name.as_str(), request.via.as_str()),
        ("Bob", link.link.as_str())
    );
    assert_eq!(request.note, "We met at the summit.");
    assert!(request.picture.is_empty());
    alice.accept_contact_request(request.id).unwrap();
    wait_for_contact(&alice);
    wait_for_contact(&bob);

    // DIS-133: the link moves to a new queue, and the request of Carol
    // reaches it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let later = now + umbra_core::discovery::RENDEZVOUS_ROTATE + 60;
    let (first, _) = alice.entry_queues(&link.id).unwrap();
    alice.maintain_directory_at(later).unwrap();
    let (second, previous) = alice.entry_queues(&link.id).unwrap();
    assert_ne!(second, first);
    assert_eq!(previous, Some(first));
    std::thread::sleep(Duration::from_secs(6));
    request_until_listed(&carol, &link.link);
    wait_for_requests(&alice, 1);
    let request = alice.contact_requests().unwrap().remove(0);
    alice.decline_contact_request(request.id).unwrap();
    assert!(alice.contact_requests().unwrap().is_empty());
    // DIS-134: the grace of the old queue ends.
    alice
        .maintain_directory_at(later + umbra_core::discovery::ROTATE_GRACE + 60)
        .unwrap();
    assert_eq!(alice.entry_queues(&link.id).unwrap(), (second, None));
    // DIS-137: the device reads its own entries, and each one is its own.
    assert!(alice.directory_warnings().unwrap().is_empty());

    // A handle, and the request of Carol to it.
    let handle = alice.claim_handle("Alice".into()).unwrap();
    assert!(handle.starts_with("@alice#"), "{handle}");
    assert_eq!(alice.my_handle().unwrap(), Some(handle.clone()));
    // §9.3.1: the profile link opens the blob beside the handle, and the
    // directory holds no key of it.
    alice.set_profile_name("Alice".into()).unwrap();
    alice.set_welcome("Say where we met.".into()).unwrap();
    // DIS-176: the picture is a JPEG, and other bytes are refused.
    let picture = vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 0xFF, 0xD9];
    assert_eq!(
        alice.set_profile_picture(b"GIF89a".to_vec()).err(),
        Some(FfiError::Malformed)
    );
    alice.set_profile_picture(picture.clone()).unwrap();
    let profile_link = alice.my_handle_link().unwrap().unwrap();
    assert!(
        profile_link.starts_with("umbra://h/alice%23"),
        "{profile_link}"
    );
    let (shown, name, welcome, shown_picture) = preview_until_listed(&carol, &profile_link);
    assert_eq!(shown, handle);
    assert_eq!(shown_picture, picture);
    assert_eq!(
        (name.as_str(), welcome.as_str()),
        ("Alice", "Say where we met.")
    );
    let carol_picture = vec![0xFF, 0xD8, 0xFF, 0xE0, 9, 9, 0xFF, 0xD9];
    carol.set_profile_picture(carol_picture.clone()).unwrap();
    request_until_listed(&carol, &handle);
    wait_for_requests(&alice, 1);
    let requests = alice.contact_requests().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].picture, carol_picture);
    assert!(alice.entries_at_limit().unwrap().is_empty());
    // §9.9: one tap moves the handle to a new queue.
    let start = Instant::now();
    loop {
        match alice.rotate_entry(handle.clone()) {
            Ok(()) => break,
            Err(FfiError::Busy) => {
                assert!(start.elapsed() < Duration::from_secs(40), "no rotation");
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(other) => panic!("{other:?}"),
        }
    }

    // §9.3: one tap moves the handle to its next key, and a request reaches
    // the new key.
    let start = Instant::now();
    loop {
        match alice.rotate_handle_key() {
            Ok(()) => break,
            Err(FfiError::Busy) => {
                assert!(start.elapsed() < Duration::from_secs(40), "no key rotation");
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(other) => panic!("{other:?}"),
        }
    }
    std::thread::sleep(Duration::from_secs(6));
    // The blob stays beside the label through the rotation of its key, and
    // a request through the profile link reaches the new key.
    assert_eq!(preview_until_listed(&bob, &profile_link).1, "Alice");
    request_until_listed(&bob, &profile_link);
    wait_for_requests(&alice, 2);
    assert_eq!(alice.contact_requests().unwrap().len(), 2);
    assert!(alice.directory_warnings().unwrap().is_empty());
    // DIS-079: Carol holds the key of her first hello. The versions between
    // it and the new key show a rotation and no tombstone, thus her second
    // hello goes with no warning.
    request_with_note(&carol, &handle, "Again.");
    wait_for_requests(&alice, 3);

    // IDN-109, IDN-118: a restore from a backup before the rotation holds
    // the first key. The upkeep finds the current one and holds the handle
    // as its own, with no warning of another party (IDN-111).
    alice.rewind_handle().unwrap();
    let start = Instant::now();
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = alice.maintain_directory_at(now);
        if alice.handle_rotation().unwrap() == Some((1, false)) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(40),
            "the handle key did not come back"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // DIS-171: a retired link takes no request.
    let start = Instant::now();
    loop {
        match alice.retire_public_link(link.id.clone()) {
            Ok(()) => break,
            Err(FfiError::Busy) => {
                assert!(start.elapsed() < Duration::from_secs(40), "no retirement");
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(other) => panic!("{other:?}"),
        }
    }
    assert!(alice.public_links().unwrap().is_empty());
    let start = Instant::now();
    loop {
        match bob.send_contact_request(link.link.clone(), String::new(), false) {
            Err(FfiError::NotFound) => break,
            Ok(()) | Err(FfiError::Busy) => {
                assert!(
                    start.elapsed() < Duration::from_secs(40),
                    "the link still takes requests"
                );
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(other) => panic!("{other:?}"),
        }
    }

    // DIS-172: a timed link registers with its lease, which the directory
    // keeps, and it takes requests before its end.
    let timed = alice.create_public_link(3_600).unwrap();
    assert!(timed.expires_at > 0);
    std::thread::sleep(Duration::from_secs(6));
    request_until_listed(&carol, &timed.link);
    wait_for_requests(&alice, 4);
    for handle in [&alice, &bob, &carol] {
        handle.disconnect();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// Part 13 §13.12: a block discards each record of the contact after its
/// acknowledgment, and tells the contact nothing. An unblock gives the next
/// record, and a discarded one stays gone (`ABU-035`).
#[test]
fn a_blocked_contact_sends_and_nothing_shows() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-block-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let network_for = |handle: &Handle| {
        handle
            .network_of_manifest(
                network.manifest.clone(),
                network.keyset.clone(),
                0,
                HOST.into(),
                Some(CA.into()),
            )
            .unwrap()
            .network
    };
    let alice = launch(&directory, "alice.db", 1);
    let bob = launch(&directory, "bob.db", 2);
    for handle in [&alice, &bob] {
        handle.clone().connect(network_for(handle)).unwrap();
    }
    alice.invite().unwrap();
    let link = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { link } => Some(link),
        _ => None,
    });
    bob.accept(link).unwrap();
    let alice_bob = wait_for_contact(&alice);
    let bob_alice = wait_for_contact(&bob);
    let send = |text: &str| {
        let draft = bob.new_draft(bob_alice.clone()).unwrap();
        draft.set_text(units(text)).unwrap();
        bob.send_draft(draft).unwrap();
    };
    send("before");
    wait_for_text(&alice, &alice_bob, "before");

    alice.set_blocked(alice_bob.clone(), true).unwrap();
    assert!(alice.is_blocked(alice_bob.clone()).unwrap());
    send("while blocked");
    // The relay takes the record, and the device of Alice acknowledges it.
    let sent = bob
        .messages(bob_alice.clone())
        .unwrap()
        .into_iter()
        .find(|message| rendered(&bob, message.clone()) == "while blocked")
        .unwrap();
    tick_until(
        &[&bob, &alice],
        || bob.msg_info(sent.clone()).unwrap().delivery == 1,
        "the relay did not take the record",
    );
    std::thread::sleep(Duration::from_secs(5));
    assert!(!holds_text(&alice, &alice_bob, "while blocked"));

    alice.set_blocked(alice_bob.clone(), false).unwrap();
    send("after");
    wait_for_text(&alice, &alice_bob, "after");
    assert!(!holds_text(&alice, &alice_bob, "while blocked"));
    for handle in [&alice, &bob] {
        handle.disconnect();
    }
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_connect_that_replaces_a_run_keeps_the_new_run() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    let directory = std::env::temp_dir().join(format!("umbra-reconnect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let alice = launch(&directory, "alice.db", 1);
    let verified = alice
        .network_of_manifest(
            network.manifest.clone(),
            network.keyset.clone(),
            0,
            HOST.into(),
            Some(CA.into()),
        )
        .unwrap()
        .network;
    // The app connects at the open and again when its carrier starts. The
    // end of each replaced run must not end the run that replaced it.
    for _ in 0..6 {
        alice.clone().connect(verified.clone()).unwrap();
        std::thread::sleep(Duration::from_millis(700));
    }
    wait_for(&alice, |event| match event {
        FfiEvent::Online => Some(()),
        _ => None,
    });
    std::thread::sleep(Duration::from_secs(2));
    alice.invite().unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::Invitation { .. } => Some(()),
        _ => None,
    });
    alice.disconnect();
}

#[test]
fn a_client_takes_the_signed_challenge_of_each_relay_from_the_carrier() {
    let relays = tokio::runtime::Runtime::new().unwrap();
    let network = start_signed_network(&relays);
    // ABU-057, ABU-102: each relay signs its challenge at its start and
    // hands it to the carriers of the manifest.
    std::thread::sleep(Duration::from_secs(3));
    let directory = std::env::temp_dir().join(format!("umbra-challenges-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let alice = launch(&directory, "alice.db", 1);
    let verified = alice
        .network_of_manifest(
            network.manifest.clone(),
            network.keyset.clone(),
            0,
            HOST.into(),
            Some(CA.into()),
        )
        .unwrap()
        .network;
    let relay_count = verified.relays.len() as u32;
    assert!(verified
        .relays
        .iter()
        .all(|relay| !relay.identity_pk.is_empty()));
    assert_eq!(alice.challenges_held(), 0);
    // ABU-065, ABU-105: the connect fetches them from the ingress, and each
    // one verifies under the identity key of its relay.
    alice.clone().connect(verified).unwrap();
    let start = Instant::now();
    while alice.challenges_held() < relay_count {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "{} of {relay_count}",
            alice.challenges_held()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    alice.disconnect();
}
