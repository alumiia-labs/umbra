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
};
use umbra_transport::{native, Dial};

const PACING_MEAN_MS: u64 = 20;
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
        assert!(
            !matches!(event, FfiEvent::Offline),
            "the client went offline"
        );
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

#[test]
fn two_apps_meet_and_talk_through_the_exported_surface() {
    // The relays run on a runtime of the test. Each handle makes its own.
    let relays = tokio::runtime::Runtime::new().unwrap();
    let client_tls = native::tls_config_with_root_file(CA).unwrap();
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..3 {
        let listener = relays
            .block_on(TcpListener::bind(("127.0.0.1", 0)))
            .unwrap();
        ports.push(listener.local_addr().unwrap().port());
        listeners.push(listener);
    }
    for (index, listener) in listeners.into_iter().enumerate() {
        let layer = index as u8 + 1;
        let (relay, static_secret) = relay_static(layer);
        let node = RelayNode::new(RelayConfig {
            relay,
            static_secret,
            layer,
            issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
            community_capacity: 1 << 20,
        });
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
        ));
    }
    let network = Network {
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
    };

    let directory = std::env::temp_dir().join(format!("umbra-app-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let launch = |name: &str, key: u8| {
        let path = directory.join(name);
        let _ = std::fs::remove_file(&path);
        let config = Config {
            database_path: path.to_str().unwrap().to_owned(),
            // A slow device keeps the floor cost, which keeps this test short.
            argon2_floor_ms: 60_000,
        };
        let keystore = Arc::new(Keystore([key; 32])) as Arc<dyn SecureElementCallback>;
        init(config, keystore, units("correct horse")).unwrap()
    };
    let alice = launch("alice.db", 1);
    let bob = launch("bob.db", 2);

    // No network runs yet.
    assert_eq!(alice.invite(), Err(FfiError::Offline));
    alice.clone().connect(network.clone()).unwrap();
    bob.clone().connect(network.clone()).unwrap();

    alice.invite().unwrap();
    let bundle = wait_for(&alice, |event| match event {
        FfiEvent::Invitation { bundle } => Some(bundle),
        _ => None,
    });
    bob.accept(bundle).unwrap();
    let alice_conversation = wait_for_contact(&alice);
    let bob_conversation = wait_for_contact(&bob);

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
    assert_eq!(bob.messages(bob_conversation).unwrap().len(), 2);

    // A draft for no contact fails, and the network stays up.
    let draft = alice.new_draft(vec![0xEE; 16]).unwrap();
    draft.set_text(units("nobody")).unwrap();
    alice.send_draft(draft).unwrap();
    wait_for(&alice, |event| match event {
        FfiEvent::Delivery { state: 4, .. } => Some(()),
        _ => None,
    });

    // A lock ends the network, because the ratchet keys sit in RAM.
    alice.lock();
    assert_eq!(alice.invite(), Err(FfiError::Offline));
    bob.disconnect();
    assert_eq!(bob.invite(), Err(FfiError::Offline));
    std::fs::remove_dir_all(&directory).ok();
}
