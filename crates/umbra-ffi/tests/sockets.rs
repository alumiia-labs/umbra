//! Three relay servers and two client runtimes on localhost, over TCP, TLS
//! 1.3, and the WebSocket framing: one client invites, the other accepts,
//! and text travels both ways.

#![cfg(feature = "sockets-test")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{collections::BTreeMap, time::Duration};

use tokio::{
    net::TcpListener,
    sync::mpsc::{self, UnboundedReceiver},
    time::timeout,
};
use umbra_core::session::node::{ClientNode, ContactId};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hierarchy::RootIdentity,
    rsabssa::PublicKey2048,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_ffi::runtime::{run_client, Command, NoStore, Update};
use umbra_relay::{
    node::{Config, RelayNode},
    server::{run_relay, tls_acceptor},
    store::MemoryStore,
};
use umbra_transport::{native, Dial};
use umbra_wire::app::{AppKind, AppMessage, Channel};

/// The mean of the pacing clock in this test. The value of a deployment is
/// one second, which would make each flight of the test wait that long.
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

fn text(tag: u8, words: &str) -> Vec<u8> {
    let message = AppMessage {
        kind: AppKind::Text,
        msg_id: [tag; 16],
        sent_at: 0,
        body: words.as_bytes(),
    };
    let mut out = vec![0u8; message.len()];
    message.encode(&mut out).unwrap();
    out
}

/// Waits for the first update that `pick` takes, and drops each other one.
async fn wait_for<T>(
    updates: &mut UnboundedReceiver<Update>,
    mut pick: impl FnMut(Update) -> Option<T>,
) -> T {
    timeout(STEP, async {
        loop {
            let update = updates.recv().await.expect("the runtime stopped");
            assert!(
                !matches!(update, Update::Offline(_)),
                "the client went offline"
            );
            if let Some(found) = pick(update) {
                return found;
            }
        }
    })
    .await
    .expect("no such update in time")
}

async fn wait_for_contact(updates: &mut UnboundedReceiver<Update>) -> ContactId {
    wait_for(updates, |update| match update {
        Update::Contact { contact, .. } => Some(contact),
        _ => None,
    })
    .await
}

async fn wait_for_message(updates: &mut UnboundedReceiver<Update>) -> (ContactId, Vec<u8>) {
    wait_for(updates, |update| match update {
        Update::Message { contact, app } => Some((contact, app)),
        _ => None,
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_meet_and_talk_over_real_sockets() {
    let client_tls = native::tls_config_with_root_file(CA).unwrap();

    // Each listener binds before a relay starts, thus the dial of a lower
    // layer at its start finds a port that accepts.
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        ports.push(listener.local_addr().unwrap().port());
        listeners.push(listener);
    }
    for (index, listener) in listeners.into_iter().enumerate() {
        let layer = index as u8 + 1;
        let (relay, static_secret) = relay_static(layer);
        let node = RelayNode::new(Config {
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
        tokio::spawn(run_relay(
            node,
            listener,
            tls_acceptor(LEAF, LEAF_KEY).unwrap(),
            next_hops,
            client_tls.clone(),
            PACING_MEAN_MS,
            Box::new(MemoryStore::default()),
        ));
    }

    let mut clients = Vec::new();
    for index in 0..2u8 {
        let path = [relay_static(1).0, relay_static(2).0, relay_static(3).0];
        let node = ClientNode::new(path, RootIdentity::new(Secret::new([0x40 + index; 32])));
        let (commands, runtime_commands) = mpsc::unbounded_channel();
        let (runtime_updates, updates) = mpsc::unbounded_channel();
        tokio::spawn(run_client(
            node,
            localhost(ports[0]),
            client_tls.clone(),
            runtime_commands,
            runtime_updates,
            Box::new(NoStore),
        ));
        clients.push((commands, updates));
    }
    let (bob, mut bob_updates) = clients.pop().unwrap();
    let (alice, mut alice_updates) = clients.pop().unwrap();

    // The commands go before the circuits are ready, and the runtime holds
    // them.
    alice.send(Command::Invite).unwrap();
    let bundle = wait_for(&mut alice_updates, |update| match update {
        Update::Invitation(bundle) => Some(bundle),
        _ => None,
    })
    .await;
    bob.send(Command::Accept(bundle)).unwrap();
    let alice_contact = wait_for_contact(&mut alice_updates).await;
    let bob_contact = wait_for_contact(&mut bob_updates).await;

    // Bob writes, the relay acknowledges, and Alice reads.
    let send = Command::Send {
        contact: bob_contact,
        app: text(1, "hello alice"),
        tag: 71,
    };
    bob.send(send).unwrap();
    let (from, app) = wait_for_message(&mut alice_updates).await;
    assert_eq!(from, alice_contact);
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"hello alice");
    wait_for(&mut bob_updates, |update| {
        (update == Update::Sent(71)).then_some(())
    })
    .await;

    // And back.
    let send = Command::Send {
        contact: alice_contact,
        app: text(2, "hello bob"),
        tag: 72,
    };
    alice.send(send).unwrap();
    let (from, app) = wait_for_message(&mut bob_updates).await;
    assert_eq!(from, bob_contact);
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"hello bob");

    // A record for no contact fails, and the runtime stays up.
    let send = Command::Send {
        contact: ContactId([0xEE; 32]),
        app: text(3, "nobody"),
        tag: 73,
    };
    alice.send(send).unwrap();
    wait_for(&mut alice_updates, |update| {
        (update == Update::Failed(73)).then_some(())
    })
    .await;
}
