//! Two client nodes over a set of five relays: one ingress, two relays of
//! layer 2, and two of layer 3. Each circuit takes a chain of its own, a
//! queue lives at the end of the chain that made it, and a record for a
//! queue goes on a circuit that ends at the relay of that queue
//! (Part 3 §3.4.6, `NET-023`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    // An index of this file names a relay, its layer, its link, and its node.
    clippy::needless_range_loop,
    missing_docs
)]

use std::collections::{BTreeMap, VecDeque};

use umbra_core::{
    directory::{bloc::BlocId, path::Candidate},
    session::node::{ClientEvent, ClientNode, ContactId, RelayInfo, StateChange},
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hierarchy::RootIdentity,
    rand_core::{TryCryptoRng, TryRng},
    rsabssa::PublicKey2048,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_relay::{
    circuits::LinkId,
    node::{Config, Output, RelayNode},
};
use umbra_wire::app::{AppKind, AppMessage, Channel};

struct Rng(u64);

impl TryRng for Rng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        Ok(self.0 >> 11 ^ self.0 << 7)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Rng {}

/// The layer of each relay of the set, by its index.
const LAYERS: [u8; 5] = [1, 2, 2, 3, 3];

fn relay_static(index: usize) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([0x20 + index as u8; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [0x30 + index as u8; 32],
    };
    (relay, secret)
}

/// Five operators in five blocs and five networks, thus each chain of one
/// relay for each layer obeys each invariant.
fn relay_info(index: usize) -> RelayInfo {
    let key = relay_static(index).0;
    RelayInfo {
        candidate: Candidate {
            relay_id: key.relay_id,
            operator_id: key.relay_id,
            family_id: key.relay_id,
            bloc: BlocId::Own([b'A', index as u8]),
            asn: index as u32 + 1,
            v4_prefix: Some([10, index as u8]),
            v6_prefix: None,
            ingress: LAYERS[index] == 1,
            chain: LAYERS[index] != 1,
            queue: LAYERS[index] == 3,
            layer: LAYERS[index],
        },
        key,
    }
}

fn client(seed: u8) -> ClientNode {
    ClientNode::with_relays(
        relay_info(0),
        (1..5).map(relay_info).collect(),
        RootIdentity::new(Secret::new([seed; 32])),
    )
}

#[derive(Clone, Copy)]
enum Peer {
    Client(usize),
    Relay(usize, LinkId),
}

struct Mesh {
    relays: Vec<RelayNode>,
    peers: Vec<Vec<(LinkId, Peer)>>,
    clients: Vec<ClientNode>,
    /// The link of each client at the ingress. A new run takes a new one.
    links: Vec<LinkId>,
    /// The stored contacts of each client, as the at-rest store holds them.
    stored: Vec<BTreeMap<ContactId, Vec<u8>>>,
    inboxes: Vec<VecDeque<Vec<u8>>>,
    events: Vec<Vec<ClientEvent>>,
    rng: Rng,
    now: u64,
    /// The seed of the root identity of each client.
    seeds: Vec<u8>,
}

impl Mesh {
    /// The relays, with a link from each relay to each relay of the next
    /// layer, and `seeds.len()` clients at the ingress.
    fn new(seeds: &[u8]) -> Self {
        let relays = (0..5)
            .map(|index| {
                let (relay, static_secret) = relay_static(index);
                RelayNode::new(Config {
                    relay,
                    static_secret,
                    layer: LAYERS[index],
                    issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
                    community_capacity: 1 << 20,
                })
            })
            .collect();
        let mut mesh = Mesh {
            relays,
            peers: vec![Vec::new(); 5],
            clients: Vec::new(),
            links: Vec::new(),
            stored: Vec::new(),
            inboxes: Vec::new(),
            events: Vec::new(),
            rng: Rng(7),
            now: 1_000,
            seeds: seeds.to_vec(),
        };
        for from in 0..5usize {
            for to in (0..5usize).filter(|to| LAYERS[*to] == LAYERS[from] + 1) {
                let (out_link, in_link) = (900 + to as LinkId, 800 + from as LinkId);
                mesh.peers[from].push((out_link, Peer::Relay(to, in_link)));
                mesh.peers[to].push((in_link, Peer::Relay(from, out_link)));
                let outputs = mesh.relays[from].dialed(
                    out_link,
                    relay_static(to).0.relay_id,
                    [from as u8 * 8 + to as u8; 8],
                    Secret::new([9; 32]),
                );
                mesh.route(from, outputs);
            }
        }
        for (index, seed) in seeds.iter().enumerate() {
            let mut node = client(*seed);
            node.connected(&mut Rng(100 + u64::from(*seed))).unwrap();
            mesh.clients.push(node);
            mesh.links.push(index as LinkId + 1);
            mesh.stored.push(BTreeMap::new());
            mesh.inboxes.push(VecDeque::new());
            mesh.events.push(Vec::new());
            mesh.peers[0].push((index as LinkId + 1, Peer::Client(index)));
        }
        mesh
    }

    fn route(&mut self, relay: usize, outputs: Vec<Output>) {
        let mut work: VecDeque<(usize, Output)> = outputs.into_iter().map(|o| (relay, o)).collect();
        while let Some((at, output)) = work.pop_front() {
            let (link, capsule) = match output {
                Output::Send { link, capsule } => (link, capsule),
                // The link of a client that stopped.
                Output::Close { .. } => continue,
                other => panic!("an unexpected output: {other:?}"),
            };
            let Some(peer) = self.peers[at].iter().find(|(l, _)| *l == link) else {
                continue;
            };
            let peer = peer.1;
            match peer {
                Peer::Client(client) => self.inboxes[client].push_back(capsule),
                Peer::Relay(next, next_link) => {
                    let outputs =
                        self.relays[next].on_capsule(next_link, &capsule, self.now, &mut self.rng);
                    work.extend(outputs.into_iter().map(|o| (next, o)));
                }
            }
        }
    }

    fn settle(&mut self) {
        for _ in 0..16 {
            self.step();
        }
    }

    /// One turn of each party.
    fn step(&mut self) {
        {
            for client in 0..self.clients.len() {
                // The store takes each change before a capsule leaves.
                for change in self.clients[client].take_changes().unwrap() {
                    if let StateChange::Contact { contact, state } = change {
                        self.stored[client].insert(contact, state.to_vec());
                    }
                }
                for capsule in self.clients[client].take_capsules() {
                    let outputs = self.relays[0].on_capsule(
                        self.links[client],
                        &capsule,
                        self.now,
                        &mut self.rng,
                    );
                    self.route(0, outputs);
                }
            }
            for relay in (0..5).filter(|relay| LAYERS[*relay] == 3) {
                let circuits: Vec<_> = self.relays[relay].paced_circuits().copied().collect();
                for circuit in circuits {
                    let outputs = self.relays[relay].pacing_tick(&circuit, self.now, &mut self.rng);
                    self.route(relay, outputs);
                }
            }
            for client in 0..self.clients.len() {
                while let Some(capsule) = self.inboxes[client].pop_front() {
                    let events = self.clients[client]
                        .on_capsule(&capsule, self.now, &mut self.rng)
                        .unwrap();
                    self.events[client].extend(events);
                }
            }
            self.now += 1;
        }
    }

    /// Ends the run of a client and starts a new one from its store.
    fn restart(&mut self, client: usize, seed: u8) {
        let old_link = self.links[client];
        let closed = self.relays[0].link_closed(old_link, self.now);
        self.route(0, closed);
        self.peers[0].retain(|(link, _)| *link != old_link);
        self.inboxes[client].clear();
        let mut node = self::client(seed);
        for state in self.stored[client].values() {
            node.restore_contact(state).unwrap();
        }
        node.connected(&mut Rng(300 + u64::from(seed))).unwrap();
        self.clients[client] = node;
        self.links[client] = old_link + 100;
        self.peers[0].push((self.links[client], Peer::Client(client)));
    }

    fn take_events(&mut self, client: usize) -> Vec<ClientEvent> {
        core::mem::take(&mut self.events[client])
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

fn contact_of(events: &[ClientEvent]) -> ContactId {
    events
        .iter()
        .find_map(|event| match event {
            ClientEvent::ContactReady { contact, .. } => Some(*contact),
            _ => None,
        })
        .expect("a ready contact")
}

fn texts_of(events: Vec<ClientEvent>) -> Vec<Vec<u8>> {
    events
        .into_iter()
        .filter_map(|event| match event {
            ClientEvent::Message { app, .. } => Some(
                AppMessage::parse(&app, Channel::Pairwise)
                    .unwrap()
                    .body
                    .to_vec(),
            ),
            _ => None,
        })
        .collect()
}

/// The end of the first chain of a client.
fn exit_of(node: &ClientNode) -> [u8; 32] {
    node.chains()[0][2]
}

#[test]
fn two_clients_at_two_queue_relays_meet_and_talk() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    // The draw of a chain is random. Two seeds whose first chains end at
    // two relays give the case that this test is for.
    let mut found = None;
    for seed in 0x40..0x60u8 {
        let mut mesh = Mesh::new(&[seed, seed + 0x20]);
        mesh.settle();
        if exit_of(&mesh.clients[ALICE]) != exit_of(&mesh.clients[BOB]) {
            found = Some(mesh);
            break;
        }
    }
    let mut mesh = found.expect("two first chains that end at two relays");
    assert_eq!(mesh.take_events(ALICE), [ClientEvent::CircuitReady]);
    assert_eq!(mesh.take_events(BOB), [ClientEvent::CircuitReady]);
    let (alice_exit, bob_exit) = (exit_of(&mesh.clients[ALICE]), exit_of(&mesh.clients[BOB]));

    // Each chain is the ingress, a relay of layer 2, and a relay of layer 3.
    for node in &mesh.clients {
        let [chain] = node.chains()[..] else {
            panic!("one chain at the start");
        };
        assert_eq!(chain[0], relay_static(0).0.relay_id);
        assert!([1, 2]
            .map(|i| relay_static(i).0.relay_id)
            .contains(&chain[1]));
        assert!([3, 4]
            .map(|i| relay_static(i).0.relay_id)
            .contains(&chain[2]));
    }

    // Alice invites: her queue lives at the end of her chain. Bob holds no
    // circuit to that relay, thus his flight 1 waits for one, and the queue
    // of Bob lives at the end of his own chain.
    mesh.clients[ALICE].invite(&mut Rng(1)).unwrap();
    mesh.settle();
    let events = mesh.take_events(ALICE);
    let [ClientEvent::Invitation { bundle, .. }] = &events[..] else {
        panic!("{events:?}");
    };
    mesh.clients[BOB]
        .accept(bundle.clone(), &mut Rng(2))
        .unwrap();
    mesh.settle();
    mesh.settle();
    let alice_contact = contact_of(&mesh.take_events(ALICE));
    let bob_contact = contact_of(&mesh.take_events(BOB));

    // Each client now holds a second circuit, to the relay of the other one.
    let ends = |node: &ClientNode| -> Vec<[u8; 32]> {
        let mut ends: Vec<_> = node.chains().iter().map(|chain| chain[2]).collect();
        ends.sort_unstable();
        ends
    };
    let mut both = vec![alice_exit, bob_exit];
    both.sort_unstable();
    assert_eq!(ends(&mesh.clients[ALICE]), both);
    assert_eq!(ends(&mesh.clients[BOB]), both);
    // NET-023: the two chains of one client share no relay but the ingress.
    for node in &mesh.clients {
        let chains = node.chains();
        assert_ne!(chains[0][1], chains[1][1]);
        assert_ne!(chains[0][2], chains[1][2]);
    }

    // Text travels both ways, each record to the relay of its queue.
    let now = mesh.now;
    mesh.clients[BOB]
        .send(&bob_contact, &text(1, "hello alice"), now, &mut Rng(3))
        .unwrap();
    mesh.clients[ALICE]
        .send(&alice_contact, &text(2, "hello bob"), now, &mut Rng(4))
        .unwrap();
    mesh.settle();
    assert_eq!(texts_of(mesh.take_events(ALICE)), [b"hello alice"]);
    assert_eq!(texts_of(mesh.take_events(BOB)), [b"hello bob"]);

    // A new run of Alice holds one circuit, to the relay of her own queue.
    // A record for Bob waits for a circuit to his relay, and it goes when
    // that circuit holds its three hops (`NET-309`).
    // The record of Bob has no ACK yet, thus the relay of Alice sends it
    // again at her `SUB`. It arrives while her record for Bob still waits,
    // and an arrival must not end a run for the lack of a circuit.
    let alice_seed = mesh_seed_of(&mesh, ALICE);
    mesh.restart(ALICE, alice_seed);
    // Alice writes at the moment her first circuit holds its three hops:
    // the `SUB` left, the record of Bob is on its way to her, and the
    // circuit to the relay of Bob does not exist yet.
    while mesh.clients[ALICE].chains().is_empty() {
        mesh.step();
    }
    let now = mesh.now;
    let sent = mesh.clients[ALICE]
        .send(
            &alice_contact,
            &text(3, "after a new run"),
            now,
            &mut Rng(5),
        )
        .unwrap();
    assert_eq!(mesh.clients[ALICE].chains().len(), 1);
    mesh.settle();
    assert!(mesh.clients[ALICE].chains().contains(
        &mesh.clients[ALICE]
            .chains()
            .into_iter()
            .find(|chain| chain[2] == alice_exit)
            .expect("a circuit to the relay of the queue of Alice")
    ));
    assert_eq!(texts_of(mesh.take_events(BOB)), [b"after a new run"]);
    assert!(mesh
        .take_events(ALICE)
        .contains(&ClientEvent::Accepted { handle: sent }));
    assert_eq!(mesh.clients[ALICE].chains().len(), 2);
}

#[test]
fn a_queue_at_a_relay_that_left_the_set_does_not_end_the_run() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut mesh = Mesh::new(&[0x41, 0x42]);
    mesh.settle();
    mesh.clients[ALICE].invite(&mut Rng(1)).unwrap();
    mesh.settle();
    let bundle = mesh
        .take_events(ALICE)
        .into_iter()
        .find_map(|event| match event {
            ClientEvent::Invitation { bundle, .. } => Some(bundle),
            _ => None,
        })
        .expect("an invitation");
    mesh.clients[BOB].accept(bundle, &mut Rng(2)).unwrap();
    mesh.settle();
    mesh.settle();
    let alice_contact = contact_of(&mesh.take_events(ALICE));
    mesh.take_events(BOB);

    // The store of Alice names a relay for her inbound queue that the relay
    // set does not hold: the version byte, the salt, the key of the peer,
    // and then that relay.
    for state in mesh.stored[ALICE].values_mut() {
        state[1 + 16 + 32..1 + 16 + 32 + 32].fill(0xEE);
    }
    let alice_seed = mesh_seed_of(&mesh, ALICE);
    mesh.restart(ALICE, alice_seed);
    mesh.settle();
    // No circuit ends at that relay. One circuit is there for a new queue.
    let chains = mesh.clients[ALICE].chains();
    assert_eq!(chains.len(), 1);
    assert_ne!(chains[0][2], [0xEE; 32]);

    // The queue of Bob is in reach, thus a record for him arrives.
    let now = mesh.now;
    mesh.clients[ALICE]
        .send(&alice_contact, &text(1, "still there"), now, &mut Rng(3))
        .unwrap();
    mesh.settle();
    assert_eq!(texts_of(mesh.take_events(BOB)), [b"still there"]);
}

/// The seed of the root identity of a client of the mesh of this test.
fn mesh_seed_of(mesh: &Mesh, client: usize) -> u8 {
    mesh.seeds[client]
}

#[test]
fn a_relay_set_with_no_conformant_chain_builds_none() {
    // NET-033: the two relays of layer 3 share their operator with the
    // ingress, thus no chain obeys invariant 1, and the build fails closed.
    let mut relays: Vec<RelayInfo> = (1..5).map(relay_info).collect();
    let ingress = relay_info(0);
    for relay in relays.iter_mut().filter(|relay| relay.candidate.layer == 3) {
        relay.candidate.operator_id = ingress.candidate.operator_id;
    }
    let mut node =
        ClientNode::with_relays(ingress, relays, RootIdentity::new(Secret::new([1; 32])));
    assert!(node.connected(&mut Rng(5)).is_err());
    assert!(node.chains().is_empty());
}
