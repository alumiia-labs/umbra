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
use umbra_core::session::node::{ClientNode, ContactId, StateChange};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hierarchy::RootIdentity,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_ffi::runtime::{run_client, Command, Persist, Update};
use umbra_relay::{
    node::{Config, RelayNode},
    server::{run_relay, tls_acceptor, Carried},
    store::MemoryStore,
};
use umbra_transport::{native, Dial};
use umbra_wire::app::{AppKind, AppMessage, Channel};
use zeroize::Zeroizing;

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

fn text(tag: u8, words: &str) -> Zeroizing<Vec<u8>> {
    let message = AppMessage {
        kind: AppKind::Text,
        msg_id: [tag; 16],
        sent_at: 0,
        body: words.as_bytes(),
    };
    let mut out = Zeroizing::new(vec![0u8; message.len()]);
    message.encode(&mut out).unwrap();
    out
}

/// The store of a test: it takes each batch, and it gives each record of a
/// batch to the test. The update of a record carries no plaintext, thus the
/// store is the one place that holds it.
struct Kept(mpsc::UnboundedSender<(ContactId, Vec<u8>)>);

impl Persist for Kept {
    fn commit(&mut self, _: Vec<StateChange>, received: &[(ContactId, Vec<u8>)]) -> bool {
        for record in received {
            let _ = self.0.send(record.clone());
        }
        true
    }
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

/// Waits for the update of one record, and takes the record from the store:
/// the commit of a record comes before its update (`IMP-132`).
async fn wait_for_message(
    updates: &mut UnboundedReceiver<Update>,
    kept: &mut UnboundedReceiver<(ContactId, Vec<u8>)>,
) -> (ContactId, Vec<u8>) {
    let from = wait_for(updates, |update| match update {
        Update::Message { contact } => Some(contact),
        _ => None,
    })
    .await;
    let (contact, app) = kept.try_recv().expect("the store took no record");
    assert_eq!(contact, from);
    (contact, app)
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
            chunk_capacity: 1 << 26,
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
            BTreeMap::new(),
            client_tls.clone(),
            PACING_MEAN_MS,
            Box::new(MemoryStore::default()),
            Carried::default(),
        ));
    }

    let mut clients = Vec::new();
    for index in 0..2u8 {
        let path = [relay_static(1).0, relay_static(2).0, relay_static(3).0];
        let node = ClientNode::new(path, RootIdentity::new(Secret::new([0x40 + index; 32])));
        let (commands, runtime_commands) = mpsc::unbounded_channel();
        let (runtime_updates, updates) = mpsc::unbounded_channel();
        let (keeps, kept) = mpsc::unbounded_channel();
        tokio::spawn(run_client(
            node,
            localhost(ports[0]),
            client_tls.clone(),
            runtime_commands,
            runtime_updates,
            Box::new(Kept(keeps)),
        ));
        clients.push((commands, updates, kept));
    }
    let (bob, mut bob_updates, mut bob_kept) = clients.pop().unwrap();
    let (alice, mut alice_updates, mut alice_kept) = clients.pop().unwrap();

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
    let (from, app) = wait_for_message(&mut alice_updates, &mut alice_kept).await;
    assert_eq!(from, alice_contact);
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"hello alice");
    wait_for(&mut bob_updates, |update| {
        (update == Update::Sent(71)).then_some(())
    })
    .await;

    // A record whose plaintext is no `AppMessage`, as a kind of a later
    // build, ends no run of its reader (`WIR-023`, `IMP-132`). The relay
    // takes it, the store decides what shows, and the next record arrives.
    let mut unknown = text(4, "of a later build");
    unknown[1] = 0xEE;
    assert!(AppMessage::parse(&unknown, Channel::Pairwise).is_err());
    let send = Command::Send {
        contact: bob_contact,
        app: unknown,
        tag: 74,
    };
    bob.send(send).unwrap();
    wait_for(&mut bob_updates, |update| {
        (update == Update::Sent(74)).then_some(())
    })
    .await;
    let send = Command::Send {
        contact: bob_contact,
        app: text(5, "after it"),
        tag: 75,
    };
    bob.send(send).unwrap();
    let app = loop {
        let (from, app) = wait_for_message(&mut alice_updates, &mut alice_kept).await;
        assert_eq!(from, alice_contact);
        if AppMessage::parse(&app, Channel::Pairwise).is_ok() {
            break app;
        }
    };
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"after it");

    // And back.
    let send = Command::Send {
        contact: alice_contact,
        app: text(2, "hello bob"),
        tag: 72,
    };
    alice.send(send).unwrap();
    let (from, app) = wait_for_message(&mut bob_updates, &mut bob_kept).await;
    assert_eq!(from, bob_contact);
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"hello bob");

    // A record for no contact goes to no relay, and the runtime stays up.
    let send = Command::Send {
        contact: ContactId([0xEE; 32]),
        app: text(3, "nobody"),
        tag: 73,
    };
    alice.send(send).unwrap();
    wait_for(&mut alice_updates, |update| {
        (update == Update::Unsent(73)).then_some(())
    })
    .await;
}
