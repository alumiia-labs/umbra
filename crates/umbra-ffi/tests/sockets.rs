//! Three relay servers and two client runtimes on localhost, over TCP, TLS
//! 1.3, and the WebSocket framing: one client invites, the other accepts,
//! and text travels both ways. A second run of one client resumes the
//! session of its first run.

#![cfg(feature = "sockets-test")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

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
use umbra_ffi::runtime::{run_client, Command, Ended, Persist, Prior, ResumeSlot, Update};
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
            None,
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
        prior: Prior::default(),
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
        prior: Prior::default(),
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
        prior: Prior::default(),
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
        prior: Prior::default(),
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
        prior: Prior::default(),
    };
    alice.send(send).unwrap();
    wait_for(&mut alice_updates, |update| {
        (update == Update::Unsent(73)).then_some(())
    })
    .await;
}

/// The mean of the pacing clock in the resume test: the value of a
/// deployment. A cell of the queue relay that is on its way when the
/// session parks ends its circuit (`WIR-543`), and a clock of 20 ms would
/// put one there in many runs.
const DEPLOYED_PACING_MS: u64 = 1_000;

/// The store of a client that lives through two runs: it keeps the state
/// of each contact, and it gives each record to the test.
#[derive(Clone)]
struct Lasting {
    contacts: Arc<Mutex<BTreeMap<ContactId, Vec<u8>>>>,
    records: mpsc::UnboundedSender<(ContactId, Vec<u8>)>,
}

impl Persist for Lasting {
    fn commit(&mut self, changes: Vec<StateChange>, received: &[(ContactId, Vec<u8>)]) -> bool {
        let mut contacts = self.contacts.lock().unwrap();
        for change in changes {
            if let StateChange::Contact { contact, state } = change {
                contacts.insert(contact, state.to_vec());
            }
        }
        for record in received {
            let _ = self.records.send(record.clone());
        }
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_run_resumes_the_session_and_reads_with_no_circuit_build() {
    let client_tls = native::tls_config_with_root_file(CA).unwrap();
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..3 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        ports.push(listener.local_addr().unwrap().port());
        listeners.push(listener);
    }
    // The chains that each relay opened, which its node counts at each
    // second.
    let builds: Vec<Arc<AtomicU64>> = (0..3).map(|_| Arc::default()).collect();
    for (index, listener) in listeners.into_iter().enumerate() {
        let layer = index as u8 + 1;
        let (relay, static_secret) = relay_static(layer);
        let mut node = RelayNode::new(Config {
            relay,
            static_secret,
            layer,
            chunk_capacity: 1 << 26,
        });
        node.count_builds_into(builds[index].clone());
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
            DEPLOYED_PACING_MS,
            Box::new(MemoryStore::default()),
            Carried::default(),
        ));
    }
    let built = || -> Vec<u64> {
        builds
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect()
    };
    let path = || [relay_static(1).0, relay_static(2).0, relay_static(3).0];

    // Bob runs for the whole test with a store that keeps nothing. Alice
    // has a store that lasts, and the place of her parked session.
    let (bob, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, mut bob_updates) = mpsc::unbounded_channel();
    let (keeps, _bob_kept) = mpsc::unbounded_channel();
    tokio::spawn(run_client(
        ClientNode::new(path(), RootIdentity::new(Secret::new([0x41; 32]))),
        localhost(ports[0]),
        client_tls.clone(),
        runtime_commands,
        runtime_updates,
        Box::new(Kept(keeps)),
        None,
    ));
    let (records, mut alice_kept) = mpsc::unbounded_channel();
    let store = Lasting {
        contacts: Arc::default(),
        records,
    };
    let slot = ResumeSlot::default();
    let (alice, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, mut alice_updates) = mpsc::unbounded_channel();
    tokio::spawn(run_client(
        ClientNode::new(path(), RootIdentity::new(Secret::new([0x40; 32]))),
        localhost(ports[0]),
        client_tls.clone(),
        runtime_commands,
        runtime_updates,
        Box::new(store.clone()),
        Some(slot.clone()),
    ));

    alice.send(Command::Invite).unwrap();
    let bundle = wait_for(&mut alice_updates, |update| match update {
        Update::Invitation(bundle) => Some(bundle),
        _ => None,
    })
    .await;
    bob.send(Command::Accept(bundle)).unwrap();
    let alice_contact = wait_for_contact(&mut alice_updates).await;
    let bob_contact = wait_for_contact(&mut bob_updates).await;

    // Alice receives a record in her first run.
    let send = Command::Send {
        contact: bob_contact,
        app: text(1, "the first run"),
        tag: 81,
        prior: Prior::default(),
    };
    bob.send(send).unwrap();
    let (from, app) = wait_for_message(&mut alice_updates, &mut alice_kept).await;
    assert_eq!(from, alice_contact);
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"the first run");
    wait_for(&mut bob_updates, |update| {
        (update == Update::Sent(81)).then_some(())
    })
    .await;

    // NET-100, WIR-360: the run of Alice ends as a push wake does. It
    // pauses its session, and it leaves the session for the next run.
    alice.send(Command::Wake).unwrap();
    let ended = timeout(STEP, async {
        loop {
            match alice_updates.recv().await.expect("the runtime stopped") {
                Update::Offline(ended) => return ended,
                _ => continue,
            }
        }
    })
    .await
    .expect("the wake did not end");
    assert_eq!(ended, Ended::WakeDone);
    assert!(slot.holds());
    drop(alice);
    // Each relay counted each build of the two first runs by now.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let before = built();
    assert!(before.iter().all(|count| *count >= 2), "{before:?}");

    // A record arrives between the two runs, and the relay takes it.
    let send = Command::Send {
        contact: bob_contact,
        app: text(2, "between the runs"),
        tag: 82,
        prior: Prior::default(),
    };
    bob.send(send).unwrap();
    wait_for(&mut bob_updates, |update| {
        (update == Update::Sent(82)).then_some(())
    })
    .await;

    // WIR-361: the second run of Alice starts from her store, and it
    // resumes the session on a new connection.
    let mut node = ClientNode::new(path(), RootIdentity::new(Secret::new([0x40; 32])));
    for state in store.contacts.lock().unwrap().values() {
        node.restore_contact(state).unwrap();
    }
    let (_alice, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, mut alice_updates) = mpsc::unbounded_channel();
    tokio::spawn(run_client(
        node,
        localhost(ports[0]),
        client_tls.clone(),
        runtime_commands,
        runtime_updates,
        Box::new(store.clone()),
        Some(slot.clone()),
    ));
    assert!(
        !slot.holds() || {
            // The run takes the session at its start.
            tokio::time::sleep(Duration::from_millis(200)).await;
            !slot.holds()
        }
    );
    let (from, app) = wait_for_message(&mut alice_updates, &mut alice_kept).await;
    assert_eq!(from, alice_contact);
    let parsed = AppMessage::parse(&app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"between the runs");

    // The record reached Alice, and no relay opened a chain for it: each
    // circuit of the second run is a circuit of the first one.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(built(), before);
}

/// Three relay servers on localhost, one of each layer, and their ports.
async fn start_relays(client_tls: &Arc<native::ClientConfig>, pacing_ms: u64) -> Vec<u16> {
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
            pacing_ms,
            Box::new(MemoryStore::default()),
            Carried::default(),
        ));
    }
    ports
}

/// The store of an existing device through two runs: the stored form of
/// each invitation, and the list of the sync invitations (`DEV-290`).
#[derive(Clone, Default)]
struct Linking {
    invitations: Arc<Mutex<BTreeMap<[u8; 32], Vec<u8>>>>,
    listed: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl Persist for Linking {
    fn commit(&mut self, changes: Vec<StateChange>, _: &[(ContactId, Vec<u8>)]) -> bool {
        let mut invitations = self.invitations.lock().unwrap();
        for change in changes {
            match change {
                StateChange::Invitation { queue, state } => {
                    // The hook comes before the batch of the invitation.
                    assert!(self.listed.lock().unwrap().contains(&queue));
                    invitations.insert(queue, state.to_vec());
                }
                StateChange::InvitationEnded { queue } => {
                    invitations.remove(&queue);
                    self.listed.lock().unwrap().retain(|held| *held != queue);
                }
                _ => {}
            }
        }
        true
    }

    fn device_invitation(&mut self, queue: &[u8; 32]) -> bool {
        self.listed.lock().unwrap().push(*queue);
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sync_invitation_of_a_link_that_ended_with_its_run_retires_in_the_next_run() {
    let client_tls = native::tls_config_with_root_file(CA).unwrap();
    let ports = start_relays(&client_tls, PACING_MEAN_MS).await;
    let path = || [relay_static(1).0, relay_static(2).0, relay_static(3).0];
    let root = || RootIdentity::new(Secret::new([0x44; 32]));
    let store = Linking::default();

    // The first run makes the sync invitation of a link, and the store
    // lists its queue.
    let (commands, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, mut updates) = mpsc::unbounded_channel();
    tokio::spawn(run_client(
        ClientNode::new(path(), root()),
        localhost(ports[0]),
        client_tls.clone(),
        runtime_commands,
        runtime_updates,
        Box::new(store.clone()),
        None,
    ));
    commands.send(Command::InviteDevice).unwrap();
    wait_for(&mut updates, |update| match update {
        Update::DeviceInvitation(bundle) => Some(bundle),
        _ => None,
    })
    .await;
    let listed = store.listed.lock().unwrap().clone();
    assert_eq!(listed.len(), 1);
    let queue = listed[0];
    let waits = |store: &Linking| {
        let mut node = ClientNode::new(path(), root());
        match store.invitations.lock().unwrap().get(&queue) {
            Some(state) => {
                node.restore_invitation(state).unwrap();
                node.holds_handshake()
            }
            None => false,
        }
    };
    assert!(waits(&store));

    // The run ends with the link: no command retired the invitation.
    drop(commands);
    timeout(STEP, async {
        while !matches!(updates.recv().await, Some(Update::Offline(_)) | None) {}
    })
    .await
    .expect("the run did not end");
    assert!(waits(&store));

    // DEV-290: the next run starts from the store, and it retires each
    // invitation on the list. The prekey and the handshake state go, and
    // the queue owes its `DEL`.
    let mut node = ClientNode::new(path(), root());
    for state in store.invitations.lock().unwrap().values() {
        node.restore_invitation(state).unwrap();
    }
    assert!(node.holds_handshake());
    let (commands, runtime_commands) = mpsc::unbounded_channel();
    let (runtime_updates, _updates) = mpsc::unbounded_channel();
    tokio::spawn(run_client(
        node,
        localhost(ports[0]),
        client_tls.clone(),
        runtime_commands,
        runtime_updates,
        Box::new(store.clone()),
        None,
    ));
    commands.send(Command::EndDeviceInvitation(listed)).unwrap();
    timeout(STEP, async {
        while waits(&store) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the invitation did not retire");
    let mut node = ClientNode::new(path(), root());
    if let Some(state) = store.invitations.lock().unwrap().get(&queue) {
        node.restore_invitation(state).unwrap();
        assert!(node.ending_queues().iter().any(|(held, _)| *held == queue));
    }
    assert!(!node.holds_handshake());
}
