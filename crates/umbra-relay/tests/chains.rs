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
    attach::{
        command::ReplicaTarget,
        place::AttachmentRelay,
        transfer::{Download, Progress, Shape, Upload, Uploaded},
        CHUNK_SIZE, SEGMENT_SIZE,
    },
    directory::{bloc::BlocId, path::Candidate},
    session::node::{
        ChunkJob, ChunkOutcome, ClientEvent, ClientNode, ContactId, GroupJob, GroupOutcome,
        RelayInfo, StateChange,
    },
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
use umbra_wire::{
    app::{AppKind, AppMessage, Channel},
    bucket::Bucket,
};

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

/// The layer of each relay of the set, by its index. Three relays of layer 3
/// hold the three copies of a chunk (Part 13 §13.4), and two more let an
/// upload leave a relay that fails.
const LAYERS: [u8; 8] = [1, 2, 2, 3, 3, 3, 3, 3];
/// The relay of layer 3 whose chunk store has no room: it refuses each
/// registration.
const FULL_RELAY: usize = 7;

fn relay_static(index: usize) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([0x20 + index as u8; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [0x30 + index as u8; 32],
    };
    (relay, secret)
}

/// An operator, a bloc and a network for each relay, thus each chain of one
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
        (1..LAYERS.len()).map(relay_info).collect(),
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
    /// The count of the copies that went between two relays.
    pushes: LinkId,
    /// A relay that gets no copy: each push to it is lost on its way.
    loses_pushes_to: Option<[u8; 32]>,
}

impl Mesh {
    /// The relays, with a link from each relay to each relay of the next
    /// layer, and `seeds.len()` clients at the ingress.
    fn new(seeds: &[u8]) -> Self {
        let relays = (0..LAYERS.len())
            .map(|index| {
                let (relay, static_secret) = relay_static(index);
                RelayNode::new(Config {
                    relay,
                    static_secret,
                    layer: LAYERS[index],
                    issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
                    community_capacity: 1 << 20,
                    chunk_capacity: if index == FULL_RELAY { 0 } else { 1 << 26 },
                })
            })
            .collect();
        let mut mesh = Mesh {
            relays,
            peers: vec![Vec::new(); LAYERS.len()],
            clients: Vec::new(),
            links: Vec::new(),
            stored: Vec::new(),
            inboxes: Vec::new(),
            events: Vec::new(),
            rng: Rng(7),
            now: 1_000,
            seeds: seeds.to_vec(),
            pushes: 0,
            loses_pushes_to: None,
        };
        for from in 0..LAYERS.len() {
            for to in (0..LAYERS.len()).filter(|to| LAYERS[*to] == LAYERS[from] + 1) {
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
                // The copy of a chunk goes on a connection of its own.
                Output::Push { relay_id, capsule } => {
                    let target = (0..LAYERS.len())
                        .find(|index| relay_static(*index).0.relay_id == relay_id)
                        .unwrap();
                    if self.loses_pushes_to == Some(relay_id) {
                        continue;
                    }
                    self.pushes += 1;
                    let link = 5_000 + self.pushes;
                    let outputs =
                        self.relays[target].on_capsule(link, &capsule, self.now, &mut self.rng);
                    work.extend(outputs.into_iter().map(|o| (target, o)));
                    continue;
                }
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
            for relay in (0..LAYERS.len()).filter(|relay| LAYERS[*relay] == 3) {
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
        assert!([3, 4, 5, 6, 7]
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

/// Waits for the answer to one chunk command.
fn outcome_of(mesh: &mut Mesh, client: usize, handle: u64) -> ChunkOutcome {
    mesh.settle();
    let mut outcomes = mesh
        .take_events(client)
        .into_iter()
        .filter_map(|event| match event {
            ClientEvent::Chunk {
                handle: of,
                outcome,
            } if of == handle => Some(outcome),
            _ => None,
        });
    let outcome = outcomes.next().expect("an answer to the chunk command");
    assert!(outcomes.next().is_none());
    outcome
}

#[test]
fn a_chunk_goes_to_one_relay_and_that_relay_makes_the_two_copies() {
    const CLIENT: usize = 0;
    let mut mesh = Mesh::new(&[0x61]);
    // Part 13 §13.8: the transfer has a connection and a node of its own.
    let mut node = ClientNode::for_transfers(
        relay_info(0),
        (1..LAYERS.len()).map(relay_info).collect(),
        RootIdentity::new(Secret::new([0x61; 32])),
    );
    node.connected(&mut Rng(61)).unwrap();
    mesh.clients[CLIENT] = node;
    mesh.settle();
    mesh.take_events(CLIENT);

    let exits: Vec<[u8; 32]> = (3..6).map(|index| relay_static(index).0.relay_id).collect();
    let [first, second, third] = exits[..] else {
        panic!("three exits");
    };
    let cred = || StaticSecret::from([0x71; 32]);
    let read = || StaticSecret::from([0x72; 32]);
    let chunk_id = [0xC4; 32];
    let chunk = vec![0xAB; CHUNK_SIZE];
    let mut rng = Rng(9);

    // ATT-096: a registration at each of the three relays, before the bytes.
    let mut tokens = Vec::new();
    for relay in [first, second, third] {
        let job = ChunkJob::Register {
            cred: cred(),
            read_pk: *XPublic::from(&read()).as_bytes(),
            is_backup: false,
        };
        let handle = mesh.clients[CLIENT]
            .chunk(relay, chunk_id, job, &mut rng)
            .unwrap();
        let ChunkOutcome::Registered(token) = outcome_of(&mut mesh, CLIENT, handle) else {
            panic!("no token");
        };
        tokens.push(token);
    }
    // A circuit ends at each relay that holds a copy.
    assert_eq!(mesh.clients[CLIENT].chains().len(), 3);

    // ATT-097: the bytes go to one relay. ATT-042: its own token binds them.
    let wrong_token = ChunkJob::Put {
        cred: cred(),
        storage_token: tokens[1],
        chunk: chunk.clone(),
    };
    let handle = mesh.clients[CLIENT]
        .chunk(first, chunk_id, wrong_token, &mut rng)
        .unwrap();
    assert!(matches!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::Refused(_)
    ));
    let put = ChunkJob::Put {
        cred: cred(),
        storage_token: tokens[0],
        chunk: chunk.clone(),
    };
    let handle = mesh.clients[CLIENT]
        .chunk(first, chunk_id, put, &mut rng)
        .unwrap();
    assert_eq!(outcome_of(&mut mesh, CLIENT, handle), ChunkOutcome::Stored);

    // No replica holds the chunk before the `CREP`.
    let early = ChunkJob::Fetch { read: read() };
    let handle = mesh.clients[CLIENT]
        .chunk(third, chunk_id, early, &mut rng)
        .unwrap();
    assert!(matches!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::Refused(_)
    ));

    // ATT-098, ATT-102: the first relay sends one copy to each target.
    let replicate = ChunkJob::Replicate {
        cred: cred(),
        targets: vec![
            ReplicaTarget {
                relay_id: second,
                storage_token: tokens[1],
            },
            ReplicaTarget {
                relay_id: third,
                storage_token: tokens[2],
            },
        ],
        chunk: chunk.clone(),
    };
    let handle = mesh.clients[CLIENT]
        .chunk(first, chunk_id, replicate, &mut rng)
        .unwrap();
    assert_eq!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::Replicated
    );
    assert_eq!(mesh.pushes, 2);

    // ATT-113: each replica proves its copy, and a proof over other bytes
    // does not pass.
    for relay in [second, third] {
        let verify = ChunkJob::Verify {
            cred: cred(),
            chunk: chunk.clone(),
        };
        let handle = mesh.clients[CLIENT]
            .chunk(relay, chunk_id, verify, &mut rng)
            .unwrap();
        assert_eq!(
            outcome_of(&mut mesh, CLIENT, handle),
            ChunkOutcome::Verified
        );
    }
    let other_bytes = ChunkJob::Verify {
        cred: cred(),
        chunk: vec![0xAC; CHUNK_SIZE],
    };
    let handle = mesh.clients[CLIENT]
        .chunk(second, chunk_id, other_bytes, &mut rng)
        .unwrap();
    assert_eq!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::WrongProof
    );

    // A reader fetches from a replica under the read credential alone.
    let by_cred = ChunkJob::Fetch { read: cred() };
    let handle = mesh.clients[CLIENT]
        .chunk(third, chunk_id, by_cred, &mut rng)
        .unwrap();
    assert!(matches!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::Refused(_)
    ));
    let fetch = ChunkJob::Fetch { read: read() };
    let handle = mesh.clients[CLIENT]
        .chunk(third, chunk_id, fetch, &mut rng)
        .unwrap();
    assert_eq!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::Fetched(chunk.clone())
    );

    // ATT-161: the erase at one relay, and that relay holds the chunk no more.
    let erase = ChunkJob::Erase { cred: cred() };
    let handle = mesh.clients[CLIENT]
        .chunk(first, chunk_id, erase, &mut rng)
        .unwrap();
    assert_eq!(outcome_of(&mut mesh, CLIENT, handle), ChunkOutcome::Erased);
    let gone = ChunkJob::Fetch { read: read() };
    let handle = mesh.clients[CLIENT]
        .chunk(first, chunk_id, gone, &mut rng)
        .unwrap();
    assert!(matches!(
        outcome_of(&mut mesh, CLIENT, handle),
        ChunkOutcome::Refused(_)
    ));

    // A node of queues sends no chunk command (`WIR-309`).
    let mut queues = client(0x62);
    let refused = queues.chunk(first, chunk_id, ChunkJob::Erase { cred: cred() }, &mut rng);
    assert!(refused.is_err());
}

/// A node for transfers in the place of the node of queues of one client.
fn use_transfer_node(mesh: &mut Mesh, client: usize, seed: u8) {
    let mut node = ClientNode::for_transfers(
        relay_info(0),
        (1..LAYERS.len()).map(relay_info).collect(),
        RootIdentity::new(Secret::new([seed; 32])),
    );
    node.connected(&mut Rng(u64::from(seed))).unwrap();
    mesh.clients[client] = node;
}

/// Each answer to a chunk command that one client got in one turn.
fn chunk_answers(mesh: &mut Mesh, client: usize) -> Vec<(u64, ChunkOutcome)> {
    mesh.step();
    mesh.take_events(client)
        .into_iter()
        .filter_map(|event| match event {
            ClientEvent::Chunk { handle, outcome } => Some((handle, outcome)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_file_goes_up_from_one_client_and_comes_down_at_another() {
    const SENDER: usize = 0;
    const RECEIVER: usize = 1;
    let mut mesh = Mesh::new(&[0x63, 0x64]);
    use_transfer_node(&mut mesh, SENDER, 0x63);
    use_transfer_node(&mut mesh, RECEIVER, 0x64);
    mesh.settle();
    let relays: Vec<AttachmentRelay> = (3..6)
        .map(|index| {
            let info = relay_info(index).candidate;
            AttachmentRelay {
                relay_id: info.relay_id,
                operator_id: info.operator_id,
                family_id: info.family_id,
            }
        })
        .collect();

    // Three segments and a part of a fourth one.
    let plain: Vec<u8> = (0..SEGMENT_SIZE * 3 + 999)
        .map(|i| (i % 251) as u8)
        .collect();
    let shape = Shape {
        mime_class: 1,
        pixel_w: 640,
        pixel_h: 480,
        ..Shape::default()
    };
    let mut rng = Rng(11);
    // The redundancy is mandatory, thus a set of two relays holds no file.
    assert!(Upload::new(&plain, shape, &relays[..2], &mut rng).is_err());
    let mut upload = Upload::new(&plain, shape, &relays, &mut rng).unwrap();
    upload.tick(&mut mesh.clients[SENDER], &mut rng).unwrap();
    let mut uploaded: Option<Uploaded> = None;
    for _ in 0..400 {
        for (handle, outcome) in chunk_answers(&mut mesh, SENDER) {
            let node = &mut mesh.clients[SENDER];
            if let Progress::Done(done) =
                upload.on_outcome(node, handle, outcome, &mut rng).unwrap()
            {
                uploaded = Some(done);
            }
        }
        if uploaded.is_some() {
            break;
        }
    }
    let uploaded = uploaded.expect("the upload ends");
    let descriptor = &uploaded.descriptor;
    assert_eq!(descriptor.refs.len(), 4);
    assert_eq!(descriptor.padded_size as usize, 4 * CHUNK_SIZE);
    assert_eq!((descriptor.pixel_w, descriptor.pixel_h), (640, 480));
    // Each chunk has a credential and an identifier of its own (`ATT-036`,
    // `ATT-055`), and one relay made two copies of each.
    assert_eq!(uploaded.credentials.len(), 4);
    assert_eq!(mesh.pushes, 8);
    for (index, credential) in uploaded.credentials.iter().enumerate() {
        assert!(uploaded.credentials[..index]
            .iter()
            .all(|other| other.chunk_id != credential.chunk_id
                && other.cred.expose() != credential.cred.expose()));
    }

    // ATT-161: the sender erases the first chunk at the relay of its ref.
    // The receiver gets that chunk from a copy (`ATT-019`).
    let first = &uploaded.credentials[0];
    let erase = ChunkJob::Erase {
        cred: StaticSecret::from(*first.cred.expose()),
    };
    let lost_at = descriptor.refs[0].relay_id;
    let handle = mesh.clients[SENDER]
        .chunk(lost_at, first.chunk_id, erase, &mut rng)
        .unwrap();
    assert_eq!(outcome_of(&mut mesh, SENDER, handle), ChunkOutcome::Erased);

    // The descriptor travels in a record, thus the receiver reads its bytes.
    let mut encoded = vec![0u8; descriptor.len()];
    descriptor.encode(&mut encoded).unwrap();
    let received = umbra_wire::descriptor::FileDescriptor::parse(&encoded).unwrap();
    let mut rng = Rng(12);
    let mut download = Download::new(&received, &relays, &mut rng).unwrap();
    download
        .tick(&mut mesh.clients[RECEIVER], &mut rng)
        .unwrap();
    let mut fetched = None;
    for _ in 0..400 {
        for (handle, outcome) in chunk_answers(&mut mesh, RECEIVER) {
            let node = &mut mesh.clients[RECEIVER];
            if let Progress::Done(bytes) = download
                .on_outcome(node, handle, outcome, &mut rng)
                .unwrap()
            {
                fetched = Some(bytes);
            }
        }
        if fetched.is_some() {
            break;
        }
    }
    assert_eq!(fetched.expect("the download ends"), plain);
}

fn holder(index: usize) -> AttachmentRelay {
    let info = relay_info(index).candidate;
    AttachmentRelay {
        relay_id: info.relay_id,
        operator_id: info.operator_id,
        family_id: info.family_id,
    }
}

#[test]
fn an_upload_leaves_a_relay_that_refuses_and_a_relay_that_holds_no_copy() {
    const SENDER: usize = 0;
    const RECEIVER: usize = 1;
    let mut mesh = Mesh::new(&[0x65, 0x66]);
    use_transfer_node(&mut mesh, SENDER, 0x65);
    use_transfer_node(&mut mesh, RECEIVER, 0x66);
    mesh.settle();
    // Five relays hold files. One has no room, and one gets no copy.
    let relays: Vec<AttachmentRelay> = (3..8).map(holder).collect();
    let full = holder(FULL_RELAY).relay_id;
    let deaf = holder(4).relay_id;
    mesh.loses_pushes_to = Some(deaf);

    let plain: Vec<u8> = (0..SEGMENT_SIZE * 7 + 5).map(|i| (i % 247) as u8).collect();
    let mut rng = Rng(31);
    let mut upload = Upload::new(&plain, Shape::default(), &relays, &mut rng).unwrap();
    upload.tick(&mut mesh.clients[SENDER], &mut rng).unwrap();
    let mut uploaded: Option<Uploaded> = None;
    for _ in 0..3_000 {
        for (handle, outcome) in chunk_answers(&mut mesh, SENDER) {
            let node = &mut mesh.clients[SENDER];
            if let Progress::Done(done) =
                upload.on_outcome(node, handle, outcome, &mut rng).unwrap()
            {
                uploaded = Some(done);
            }
        }
        if uploaded.is_some() {
            break;
        }
        // The clock of the caller: a proof that a replica did not hold goes
        // again at a tick.
        upload.tick(&mut mesh.clients[SENDER], &mut rng).unwrap();
    }
    let uploaded = uploaded.expect("the upload ends");
    let repairs = upload.repairs();
    assert_eq!(uploaded.credentials.len(), 8);
    let mut met_deaf = false;
    for credential in &uploaded.credentials {
        assert_eq!(credential.relays.len(), 3);
        // ATT-017: three operators. The relay with no room holds no chunk,
        // and the relay that gets no copy holds a chunk only where it took
        // the bytes from this device.
        for (place, relay) in credential.relays.iter().enumerate() {
            assert_ne!(*relay, full);
            assert!(*relay != deaf || place == 0);
            assert!(credential.relays[..place]
                .iter()
                .all(|other| other != relay));
        }
        met_deaf |= credential.relays.first() == Some(&deaf);
    }
    // The draw of this seed met the two relays, thus the test tested them.
    assert!(met_deaf);
    assert!(repairs >= 2, "{repairs} repairs");

    // Each chunk is at three relays that hold it: the file comes down.
    let mut rng = Rng(32);
    let mut download = Download::new(&uploaded.descriptor, &relays, &mut rng).unwrap();
    download
        .tick(&mut mesh.clients[RECEIVER], &mut rng)
        .unwrap();
    let mut fetched = None;
    for _ in 0..600 {
        for (handle, outcome) in chunk_answers(&mut mesh, RECEIVER) {
            let node = &mut mesh.clients[RECEIVER];
            if let Progress::Done(bytes) = download
                .on_outcome(node, handle, outcome, &mut rng)
                .unwrap()
            {
                fetched = Some(bytes);
            }
        }
        if fetched.is_some() {
            break;
        }
    }
    assert_eq!(fetched.expect("the download ends"), plain);

    // With three relays and one of them with no room, no draw holds a file.
    let few = [holder(3), holder(5), holder(FULL_RELAY)];
    let mut upload = Upload::new(&plain[..100], Shape::default(), &few, &mut rng).unwrap();
    upload.tick(&mut mesh.clients[SENDER], &mut rng).unwrap();
    let mut failed = false;
    'upload: for _ in 0..600 {
        for (handle, outcome) in chunk_answers(&mut mesh, SENDER) {
            let node = &mut mesh.clients[SENDER];
            match upload.on_outcome(node, handle, outcome, &mut rng) {
                Ok(Progress::Done(_)) => panic!("an upload to two relays"),
                Ok(Progress::Running(..)) => {}
                Err(_) => {
                    failed = true;
                    break 'upload;
                }
            }
        }
    }
    assert!(failed);
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

/// A node for group queues in the place of the node of queues of one client.
fn use_group_node(mesh: &mut Mesh, client: usize, seed: u8) {
    let mut node = ClientNode::for_groups(
        relay_info(0),
        (1..LAYERS.len()).map(relay_info).collect(),
        RootIdentity::new(Secret::new([seed; 32])),
    );
    node.connected(&mut Rng(u64::from(seed))).unwrap();
    mesh.clients[client] = node;
}

/// Each answer to a group command that one client got in one turn.
fn group_answers(mesh: &mut Mesh, client: usize) -> Vec<(u64, GroupOutcome)> {
    mesh.step();
    mesh.take_events(client)
        .into_iter()
        .filter_map(|event| match event {
            ClientEvent::Group { handle, outcome } => Some((handle, outcome)),
            _ => None,
        })
        .collect()
}

/// Turns of the mesh until one answer arrives, or a panic.
fn one_answer(mesh: &mut Mesh, client: usize) -> GroupOutcome {
    for _ in 0..40 {
        if let Some((_, outcome)) = group_answers(mesh, client).into_iter().next() {
            return outcome;
        }
    }
    panic!("no answer to the group command");
}

/// Each group record that one client holds after some turns.
fn group_records(mesh: &mut Mesh, client: usize, turns: usize) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    for _ in 0..turns {
        mesh.step();
        for event in mesh.take_events(client) {
            if let ClientEvent::GroupRecord { seq, record, .. } = event {
                out.push((seq, record));
            }
        }
    }
    out
}

#[test]
fn a_group_queue_takes_a_record_at_one_client_and_gives_it_at_another() {
    const CREATOR: usize = 0;
    const READER: usize = 1;
    let mut mesh = Mesh::new(&[0x71, 0x72]);
    use_group_node(&mut mesh, CREATOR, 0x71);
    use_group_node(&mut mesh, READER, 0x72);
    mesh.settle();
    let relay = relay_info(3).candidate.relay_id;
    let (read, write, own) = (
        StaticSecret::from([0x31u8; 32]),
        StaticSecret::from([0x32u8; 32]),
        StaticSecret::from([0x33u8; 32]),
    );
    let public = |sk: &StaticSecret| *XPublic::from(sk).as_bytes();

    // The creator makes the queue, and the relay names it.
    mesh.clients[CREATOR]
        .group(
            relay,
            [0; 32],
            GroupJob::Create {
                read_pk: public(&read),
                write_pk: public(&write),
                own: StaticSecret::from(own.to_bytes()),
            },
            &mut Rng(21),
        )
        .unwrap();
    let GroupOutcome::Created(group_queue_id) = one_answer(&mut mesh, CREATOR) else {
        panic!("the relay made no group queue");
    };

    // A reader of the epoch subscribes from its cursor at 0.
    mesh.clients[READER]
        .group(
            relay,
            group_queue_id,
            GroupJob::Subscribe {
                read: StaticSecret::from(read.to_bytes()),
                from_seq: 0,
            },
            &mut Rng(22),
        )
        .unwrap();
    mesh.settle();

    // The creator posts one record, and the reader takes it.
    let record: Vec<u8> = (0..Bucket::B1.group_record())
        .map(|i| (i % 253) as u8)
        .collect();
    mesh.clients[CREATOR]
        .group(
            relay,
            group_queue_id,
            GroupJob::Post {
                write: StaticSecret::from(write.to_bytes()),
                record: record.clone(),
            },
            &mut Rng(23),
        )
        .unwrap();
    assert_eq!(one_answer(&mut mesh, CREATOR), GroupOutcome::Posted(1));
    let held = group_records(&mut mesh, READER, 8);
    assert_eq!(held, vec![(1, record.clone())]);

    // The same bytes again take the sequence that the relay holds, and the
    // reader gets no second copy (`WIR-385`, `WIR-519`).
    mesh.clients[CREATOR]
        .group(
            relay,
            group_queue_id,
            GroupJob::Post {
                write: StaticSecret::from(write.to_bytes()),
                record: record.clone(),
            },
            &mut Rng(24),
        )
        .unwrap();
    assert_eq!(one_answer(&mut mesh, CREATOR), GroupOutcome::Posted(1));
    assert!(group_records(&mut mesh, READER, 8).is_empty());

    // A record under a credential that the queue does not hold is refused.
    mesh.clients[CREATOR]
        .group(
            relay,
            group_queue_id,
            GroupJob::Post {
                write: StaticSecret::from([0x44u8; 32]),
                record: vec![9u8; Bucket::B1.group_record()],
            },
            &mut Rng(25),
        )
        .unwrap();
    assert!(matches!(
        one_answer(&mut mesh, CREATOR),
        GroupOutcome::Refused(_)
    ));

    // GRP-187: a second group at one relay takes a circuit of its own.
    let before = mesh.clients[CREATOR].chains().len();
    mesh.clients[CREATOR]
        .group(
            relay,
            [0; 32],
            GroupJob::Create {
                read_pk: public(&read),
                write_pk: public(&write),
                own: StaticSecret::from(own.to_bytes()),
            },
            &mut Rng(26),
        )
        .unwrap();
    let GroupOutcome::Created(second) = one_answer(&mut mesh, CREATOR) else {
        panic!("the relay made no second group queue");
    };
    assert_ne!(second, group_queue_id);
    assert!(mesh.clients[CREATOR].chains().len() > before);
}
