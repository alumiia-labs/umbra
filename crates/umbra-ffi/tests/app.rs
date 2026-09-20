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
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hmac::{digest::KeyInit, Hmac, Mac},
    rsabssa::PublicKey2048,
    sha2::Sha256,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_ffi::bindings::{
    init, Config, FfiError, FfiEvent, Handle, MsgHandle, Network, RelayEndpoint,
    SecureElementCallback, TextSink,
};
use umbra_relay::{
    node::{Config as RelayConfig, RelayNode},
    server::{run_relay, tls_acceptor},
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

fn relay_static(layer: u8) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([layer; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [0x10 + layer; 32],
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
    for index in 0..3 {
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
        let layer = index as u8 + 1;
        let (relay, static_secret) = relay_static(layer);
        let config = RelayConfig {
            relay,
            static_secret,
            layer,
            issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
            community_capacity: 1 << 20,
        };
        let mut store: Box<dyn RelayStore> = match directory {
            Some(directory) => {
                let path = directory.join(format!("relay{layer}.db"));
                Box::new(SqliteStore::open(path.to_str().unwrap()).unwrap())
            }
            None => Box::new(MemoryStore::default()),
        };
        let node = RelayNode::restored(config, store.load().unwrap());
        let mut next_hops = BTreeMap::new();
        if layer < 3 {
            next_hops.insert(
                relay_static(layer + 1).0.relay_id,
                localhost(ports[index + 1]),
            );
        }
        relays.spawn(run_relay(
            node,
            listener,
            tls_acceptor(LEAF, LEAF_KEY).unwrap(),
            next_hops,
            client_tls.clone(),
            PACING_MEAN_MS,
            store,
        ));
    }
    (relays, ports)
}

fn network_of(ports: &[u16]) -> Network {
    Network {
        relays: (1..=3u8)
            .map(|layer| {
                let relay = relay_static(layer).0;
                RelayEndpoint {
                    host: "localhost".into(),
                    ipv4: vec![127, 0, 0, 1],
                    port: ports[usize::from(layer) - 1],
                    static_key: relay.s.to_vec(),
                    relay_id: relay.relay_id.to_vec(),
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
