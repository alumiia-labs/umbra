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
        state::Group,
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
    fetch_manifest, init, parse_network, Config, FfiError, FfiEvent, Handle, MsgHandle, Network,
    RelayEndpoint, SecureElementCallback, TextSink,
};
use umbra_ffi::groups::{run_groups, GroupCommand, GroupUpdate};
use umbra_ffi::transfers::{run_transfers, TransferCommand, TransferUpdate};
use umbra_relay::{
    node::{Config as RelayConfig, RelayNode},
    placement::placement,
    server::{run_relay, tls_acceptor, OsRng},
    sqlite_store::SqliteStore,
    store::{MemoryStore, RelayStore},
};
use umbra_transport::{native, Dial};

const PACING_MEAN_MS: u64 = 20;
const HOST: &str = "invite.umbra.test";
const STEP: Duration = Duration::from_secs(20);

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

fn wait_for_contact(handle: &Handle) -> Vec<u8> {
    wait_for(handle, |event| match event {
        FfiEvent::Contact { conversation } => Some(conversation),
        _ => None,
    })
}

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
            community_capacity: 1 << 20,
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
            None,
        ));
    }
    (relays, ports)
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
                }
            })
            .collect(),
        root_ca_path: Some(CA.into()),
        invitation_host: HOST.into(),
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
        let listener = relays
            .block_on(TcpListener::bind((std::net::Ipv4Addr::from(address), 0)))
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
        identities.push((relay_id, relay.s, static_secret));
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
    for (listener, (relay_id, static_key, static_secret)) in listeners.into_iter().zip(identities) {
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
            community_capacity: 1 << 20,
            chunk_capacity: 1 << 26,
        };
        let mut store: Box<dyn RelayStore> = Box::new(MemoryStore::default());
        relays.spawn(run_relay(
            RelayNode::restored(config, store.load().unwrap()),
            listener,
            tls_acceptor(LEAF, LEAF_KEY).unwrap(),
            placed.next,
            placed.replicas,
            client_tls.clone(),
            PACING_MEAN_MS,
            store,
            // The ingress relay is the carrier of the manifest.
            (placed.layer == 1).then(|| manifest.clone()),
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

    // A descriptor whose chunks no relay holds ends with no file.
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
        TransferUpdate::Failed { tag: 10 }
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
        .attach_file(path.to_str().unwrap().to_owned(), 1, 800, 600, 0)
        .unwrap();
    // The record of a file holds no text.
    let both = alice.new_draft(alice_conversation.clone()).unwrap();
    both.set_text(units("a caption")).unwrap();
    both.attach_file(path.to_str().unwrap().to_owned(), 1, 800, 600, 0)
        .unwrap();
    assert_eq!(alice.send_draft(both).err(), Some(FfiError::Malformed));

    let sent = alice.send_draft(draft).unwrap();
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
    // A file has no text to render.
    assert_eq!(rendered(&bob, received.clone()), "");

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
            record: second,
        })
        .ok()
        .unwrap();
    loop {
        match group_update(&mut creator_rx) {
            GroupUpdate::Failed { tag: 12, .. } => break,
            GroupUpdate::Posted { tag, .. } => assert!(tag == 20 || tag == 21),
            other => panic!("{}", update_name(&other)),
        }
    }
}

/// The name of an update, for a test that met one it did not expect.
fn update_name(update: &GroupUpdate) -> &'static str {
    match update {
        GroupUpdate::Created { .. } => "created",
        GroupUpdate::Posted { .. } => "posted",
        GroupUpdate::Record { .. } => "record",
        GroupUpdate::Failed { .. } => "failed",
        GroupUpdate::Ended => "ended",
    }
}
