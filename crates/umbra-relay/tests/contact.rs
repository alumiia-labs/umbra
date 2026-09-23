//! Two client nodes and three relay nodes in one process: each client
//! builds its circuit, one invites and the other accepts, the three flights
//! of the handshake cross the two queues, and text travels both ways.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::collections::{BTreeMap, VecDeque};

use umbra_core::session::node::{ClientEvent, ClientNode, ContactId, CoverSlot, StateChange};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hierarchy::RootIdentity,
    rand_core::{TryCryptoRng, TryRng},
    rsabssa::PublicKey2048,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_queue::params::RECEIPT_MIN_DELAY;
use umbra_relay::{
    circuits::LinkId,
    node::{Config, Output, RelayNode},
    service::queue::NdrPush,
    store::{MemoryStore, RelayStore},
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

#[derive(Clone, Copy)]
enum Peer {
    Client(usize),
    Relay(usize, LinkId),
}

/// What one client holds between two runs, as the at-rest store does.
#[derive(Default)]
struct Stored {
    contacts: BTreeMap<ContactId, Vec<u8>>,
    invitations: BTreeMap<[u8; 32], Vec<u8>>,
}

struct Network {
    relays: Vec<RelayNode>,
    /// The store of each relay, which outlives its node.
    relay_stores: Vec<MemoryStore>,
    peers: Vec<Vec<(LinkId, Peer)>>,
    clients: Vec<ClientNode>,
    /// The link of each client at the guard. A restart takes a new one.
    links: Vec<LinkId>,
    stored: Vec<Stored>,
    inboxes: Vec<VecDeque<Vec<u8>>>,
    events: Vec<Vec<ClientEvent>>,
    /// The pushes that the queue relays handed to their runtime.
    pushes: Vec<NdrPush>,
    rng: Rng,
    now: u64,
}

fn relay_static(layer: u8) -> (RelayStatic, StaticSecret) {
    let secret = StaticSecret::from([layer; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&secret).as_bytes(),
        relay_id: [0x10 + layer; 32],
    };
    (relay, secret)
}

impl Network {
    fn relay_config(layer: u8) -> Config {
        let (relay, static_secret) = relay_static(layer);
        Config {
            relay,
            static_secret,
            layer,
            issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
            community_capacity: 1 << 20,
            chunk_capacity: 1 << 26,
        }
    }

    /// The links between the relays of two layers.
    fn wire_relays(&mut self) {
        self.peers = vec![Vec::new(), Vec::new(), Vec::new()];
        for from in 0..2usize {
            self.peers[from].push((900, Peer::Relay(from + 1, 800)));
            self.peers[from + 1].push((800, Peer::Relay(from, 900)));
            let next_id = relay_static(from as u8 + 2).0.relay_id;
            let outputs = self.relays[from].dialed(
                900,
                next_id,
                [from as u8; 8],
                Secret::new([9; 32]),
                self.now,
                &mut self.rng,
            );
            self.route(from, outputs);
        }
    }

    /// The store takes each change of each relay.
    fn commit_relays(&mut self) {
        for (relay, store) in self.relays.iter_mut().zip(&mut self.relay_stores) {
            store.commit(&relay.take_changes()).unwrap();
        }
    }

    /// Each relay process ends, and a new one starts from its store. Each
    /// circuit, session, and subscription is gone, thus each client starts
    /// a new run too.
    fn restart_network(&mut self, seeds: &[u8]) {
        self.commit_relays();
        self.relays = (1..=3u8)
            .zip(&mut self.relay_stores)
            .map(|(layer, store)| {
                RelayNode::restored(Self::relay_config(layer), store.load().unwrap())
            })
            .collect();
        self.wire_relays();
        for (client, seed) in seeds.iter().enumerate() {
            self.restart(client, *seed);
        }
    }

    fn new() -> Self {
        let relays = (1..=3u8)
            .map(|layer| RelayNode::new(Self::relay_config(layer)))
            .collect();
        let clients = (0..2u8)
            .map(|index| {
                let path = [relay_static(1).0, relay_static(2).0, relay_static(3).0];
                ClientNode::new(path, RootIdentity::new(Secret::new([0x40 + index; 32])))
            })
            .collect();
        let mut network = Network {
            relays,
            relay_stores: vec![MemoryStore::default(); 3],
            peers: Vec::new(),
            clients,
            links: vec![1, 2],
            stored: vec![Stored::default(), Stored::default()],
            inboxes: vec![VecDeque::new(), VecDeque::new()],
            events: vec![Vec::new(), Vec::new()],
            pushes: Vec::new(),
            rng: Rng(7),
            now: 1_000,
        };
        network.wire_relays();
        for client in 0..2usize {
            network.peers[0].push((network.links[client], Peer::Client(client)));
            network.clients[client]
                .connected(&mut Rng(100 + client as u64))
                .unwrap();
        }
        network
    }

    fn route(&mut self, relay: usize, outputs: Vec<Output>) {
        let mut work: VecDeque<(usize, Output)> = outputs.into_iter().map(|o| (relay, o)).collect();
        while let Some((at, output)) = work.pop_front() {
            let (link, capsule) = match output {
                Output::Send { link, capsule } => (link, capsule),
                // The link of a client that stopped.
                Output::Close { .. } => continue,
                Output::NdrPush(push) => {
                    self.pushes.push(push);
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

    /// Runs the network until each party had its turn several times: the
    /// clients send, each pacing clock ticks, and the clients receive.
    fn settle(&mut self) {
        for _ in 0..12 {
            self.step();
        }
    }

    /// One turn of each party.
    fn step(&mut self) {
        self.commit_relays();
        {
            for client in 0..self.clients.len() {
                // The store takes each change before a capsule leaves.
                self.commit(client);
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
            let circuits: Vec<_> = self.relays[2].paced_circuits().copied().collect();
            for circuit in circuits {
                let outputs = self.relays[2].pacing_tick(&circuit, self.now, &mut self.rng);
                self.route(2, outputs);
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

    fn commit(&mut self, client: usize) {
        for change in self.clients[client].take_changes().unwrap() {
            let stored = &mut self.stored[client];
            match change {
                StateChange::Contact { contact, state } => {
                    stored.contacts.insert(contact, state.to_vec());
                }
                StateChange::Invitation { queue, state } => {
                    stored.invitations.insert(queue, state.to_vec());
                }
                StateChange::InvitationEnded { queue } => {
                    stored.invitations.remove(&queue);
                }
            }
        }
    }

    /// Ends the run of a client and starts a new one from its store: the
    /// link closes, the node drops, and a new node takes the stored state.
    fn restart(&mut self, client: usize, seed: u8) {
        self.commit(client);
        let closed = self.relays[0].link_closed(self.links[client], self.now);
        self.route(0, closed);
        let old_link = self.links[client];
        self.peers[0].retain(|(link, _)| *link != old_link);
        self.inboxes[client].clear();

        let mut node = ClientNode::new(
            [relay_static(1).0, relay_static(2).0, relay_static(3).0],
            RootIdentity::new(Secret::new([seed; 32])),
        );
        for state in self.stored[client].contacts.values() {
            node.restore_contact(state).unwrap();
        }
        for state in self.stored[client].invitations.values() {
            node.restore_invitation(state).unwrap();
        }
        node.connected(&mut Rng(300 + u64::from(seed))).unwrap();
        self.clients[client] = node;
        self.links[client] = old_link + 100;
        self.peers[0].push((self.links[client], Peer::Client(client)));
    }

    /// Connects one more client to the guard, and returns its index.
    fn add_client(&mut self, seed: u8) -> usize {
        let index = self.clients.len();
        let mut client = ClientNode::new(
            [relay_static(1).0, relay_static(2).0, relay_static(3).0],
            RootIdentity::new(Secret::new([seed; 32])),
        );
        client.connected(&mut Rng(200 + u64::from(seed))).unwrap();
        self.clients.push(client);
        self.links.push(index as LinkId + 1);
        self.stored.push(Stored::default());
        self.inboxes.push(VecDeque::new());
        self.events.push(Vec::new());
        self.peers[0].push((index as LinkId + 1, Peer::Client(index)));
        self.settle();
        assert_eq!(self.take_events(index), [ClientEvent::CircuitReady]);
        index
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

fn contact_of(events: &[ClientEvent]) -> (ContactId, [u8; 32]) {
    events
        .iter()
        .find_map(|event| match event {
            ClientEvent::ContactReady {
                contact,
                peer_static,
            } => Some((*contact, *peer_static)),
            _ => None,
        })
        .expect("a ready contact")
}

#[test]
fn two_clients_become_contacts_and_exchange_text() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    assert_eq!(network.take_events(ALICE), [ClientEvent::CircuitReady]);
    assert_eq!(network.take_events(BOB), [ClientEvent::CircuitReady]);

    // Alice invites. The bundle travels out of band.
    let invite = network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let events = network.take_events(ALICE);
    let [ClientEvent::Invitation { handle, bundle }] = &events[..] else {
        panic!("{events:?}");
    };
    assert_eq!(*handle, invite);

    // Bob accepts, and the three flights cross the two queues.
    network.clients[BOB]
        .accept(bundle.clone(), &mut Rng(2))
        .unwrap();
    network.settle();
    let (alice_contact, bob_static) = contact_of(&network.take_events(ALICE));
    let (bob_contact, alice_static) = contact_of(&network.take_events(BOB));
    assert_ne!(bob_static, [0; 32]);
    assert_ne!(alice_static, bob_static);
    assert_eq!(network.clients[ALICE].contacts().count(), 1);

    // Text travels from Bob to Alice, and the relay acknowledges it.
    let now = network.now;
    let sent = network.clients[BOB]
        .send(&bob_contact, &text(1, "hello alice"), now, &mut Rng(3))
        .unwrap();
    network.settle();
    assert!(network
        .take_events(BOB)
        .contains(&ClientEvent::Accepted { handle: sent }));
    let events = network.take_events(ALICE);
    let [ClientEvent::Message { contact, app }] = &events[..] else {
        panic!("{events:?}");
    };
    assert_eq!(*contact, alice_contact);
    let parsed = AppMessage::parse(app, Channel::Pairwise).unwrap();
    assert_eq!(parsed.body, b"hello alice");
    // NET-050: the ACK waits for its floor. A slot of the cover clock before
    // that time makes a cover cell in the foreground and nothing in the
    // background, and a relay gives a cover cell no answer.
    let now = network.now;
    let slot = network.clients[ALICE]
        .on_cover_slot(false, None, now, &mut Rng(4))
        .unwrap();
    assert_eq!(slot, CoverSlot::Nothing);
    let mut kinds = Vec::new();
    for seed in 0..24 {
        kinds.push(
            network.clients[ALICE]
                .on_cover_slot(true, None, now, &mut Rng(40 + seed))
                .unwrap(),
        );
    }
    assert!(kinds.contains(&CoverSlot::Loop));
    assert!(kinds.contains(&CoverSlot::Cover));
    assert!(!kinds.contains(&CoverSlot::Acknowledgment));
    network.settle();
    assert!(network.take_events(ALICE).is_empty());
    // NET-064: the ACK that is due takes the slot, in the background also.
    network.now += RECEIPT_MIN_DELAY;
    let now = network.now;
    let slot = network.clients[ALICE]
        .on_cover_slot(false, None, now, &mut Rng(90))
        .unwrap();
    assert_eq!(slot, CoverSlot::Acknowledgment);
    let slot = network.clients[ALICE]
        .on_cover_slot(false, None, now, &mut Rng(91))
        .unwrap();
    assert_eq!(slot, CoverSlot::Nothing);
    network.settle();

    // And back, several records in a row.
    for n in 0..3u8 {
        let now = network.now;
        network.clients[ALICE]
            .send(
                &alice_contact,
                &text(10 + n, "hello bob"),
                now,
                &mut Rng(5 + u64::from(n)),
            )
            .unwrap();
    }
    network.settle();
    let received: Vec<_> = network
        .take_events(BOB)
        .into_iter()
        .filter(|event| matches!(event, ClientEvent::Message { .. }))
        .collect();
    assert_eq!(received.len(), 3);

    // NET-065: the records of the handshake are older than the floor, and
    // their ACK goes before a receipt. The receipt takes the next slot, in
    // the background also.
    let receipt = control(
        AppKind::DeliveryReceipt,
        &[[0x01u8, 0x01].as_slice(), &[10; 16]].concat(),
    );
    let now = network.now;
    for (seed, carried) in [(92, CoverSlot::Acknowledgment), (94, CoverSlot::Receipt)] {
        let slot = network.clients[BOB]
            .on_cover_slot(false, Some((&bob_contact, &receipt)), now, &mut Rng(seed))
            .unwrap();
        assert_eq!(slot, carried);
    }
    network.settle();
    let receipt_body = AppMessage::parse(&receipt, Channel::Pairwise)
        .unwrap()
        .body
        .to_vec();
    assert_eq!(messages_of(network.take_events(ALICE)), [receipt_body]);
    // The three records of Alice are now older than the floor.
    network.now += RECEIPT_MIN_DELAY;
    let now = network.now;
    let slot = network.clients[BOB]
        .on_cover_slot(false, Some((&bob_contact, &receipt)), now, &mut Rng(93))
        .unwrap();
    assert_eq!(slot, CoverSlot::Acknowledgment);
    network.settle();

    // A second use of the bundle gets no contact, because its prekey served.
    let carol = network.add_client(0x50);
    network.clients[carol]
        .accept(bundle.clone(), &mut Rng(6))
        .unwrap();
    network.settle();
    assert!(!network
        .take_events(carol)
        .iter()
        .any(|event| matches!(event, ClientEvent::ContactReady { .. })));
    assert_eq!(network.clients[ALICE].contacts().count(), 1);
}

fn became_contact(events: &[ClientEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, ClientEvent::ContactReady { .. }))
}

#[test]
fn a_second_holder_of_the_bundle_ends_no_handshake_in_progress() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.take_events(ALICE);
    network.take_events(BOB);
    let carol = network.add_client(0x50);

    network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let events = network.take_events(ALICE);
    let [ClientEvent::Invitation { bundle, .. }] = &events[..] else {
        panic!("{events:?}");
    };

    // The two accept in one turn, thus the second flight 1 reaches Alice
    // while she waits for the flight 3 of the first (`WIR-503`).
    network.clients[BOB]
        .accept(bundle.clone(), &mut Rng(2))
        .unwrap();
    network.clients[carol]
        .accept(bundle.clone(), &mut Rng(3))
        .unwrap();
    network.settle();

    assert!(became_contact(&network.take_events(ALICE)));
    let bob_won = became_contact(&network.take_events(BOB));
    let carol_won = became_contact(&network.take_events(carol));
    assert!(
        bob_won != carol_won,
        "one holder and no more gets the contact"
    );
    assert_eq!(network.clients[ALICE].contacts().count(), 1);
}

fn messages_of(events: Vec<ClientEvent>) -> Vec<Vec<u8>> {
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

#[test]
fn a_client_continues_each_contact_after_a_restart() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let events = network.take_events(ALICE);
    let Some(ClientEvent::Invitation { bundle, .. }) = events.last() else {
        panic!("{events:?}");
    };
    network.clients[BOB]
        .accept(bundle.clone(), &mut Rng(2))
        .unwrap();
    network.settle();
    let (alice_contact, _) = contact_of(&network.take_events(ALICE));
    let (bob_contact, _) = contact_of(&network.take_events(BOB));
    // The handshake ended the stored invitation, and the contact took its
    // place.
    assert!(network.stored[ALICE].invitations.is_empty());
    assert_eq!(network.stored[ALICE].contacts.len(), 1);

    let now = network.now;
    network.clients[BOB]
        .send(&bob_contact, &text(1, "before"), now, &mut Rng(3))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(ALICE)), [b"before"]);
    network.now += RECEIPT_MIN_DELAY;
    assert!(network.clients[ALICE]
        .acknowledge(&alice_contact, network.now, &mut Rng(4))
        .unwrap());
    network.settle();

    // Alice stops. Bob writes two records, and the relay holds them.
    network.restart(ALICE, 0x40);
    let now = network.now;
    for (n, words) in ["while away", "and again"].into_iter().enumerate() {
        network.clients[BOB]
            .send(
                &bob_contact,
                &text(10 + n as u8, words),
                now,
                &mut Rng(5 + n as u64),
            )
            .unwrap();
    }
    network.settle();
    let events = network.take_events(ALICE);
    assert!(events.contains(&ClientEvent::CircuitReady));
    assert_eq!(network.clients[ALICE].contacts().count(), 1);
    assert_eq!(
        messages_of(events),
        [b"while away".to_vec(), b"and again".to_vec()]
    );

    // The store holds the two records, but no ACK left. After a second
    // restart the relay delivers them again, and the cursor drops them.
    network.restart(ALICE, 0x40);
    network.settle();
    assert_eq!(
        messages_of(network.take_events(ALICE)),
        Vec::<Vec<u8>>::new()
    );

    // And Alice writes under the ratchet of the stored state.
    let now = network.now;
    network.clients[ALICE]
        .send(&alice_contact, &text(20, "back again"), now, &mut Rng(9))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(BOB)), [b"back again"]);
}

#[test]
fn an_invitation_waits_across_a_restart() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let events = network.take_events(ALICE);
    let Some(ClientEvent::Invitation { bundle, .. }) = events.last() else {
        panic!("{events:?}");
    };
    assert_eq!(network.stored[ALICE].invitations.len(), 1);

    network.restart(ALICE, 0x40);
    network.settle();
    network.take_events(ALICE);
    network.clients[BOB]
        .accept(bundle.clone(), &mut Rng(2))
        .unwrap();
    network.settle();
    contact_of(&network.take_events(ALICE));
    contact_of(&network.take_events(BOB));
    assert!(network.stored[ALICE].invitations.is_empty());
}

#[test]
fn a_circuit_near_its_age_ends_the_run_before_a_relay_drops_it() {
    use umbra_core::session::node::CIRCUIT_AGE_MARGIN;
    use umbra_onion::CIRCUIT_MAX_AGE;
    let mut network = Network::new();
    network.settle();
    network.take_events(0);
    let start = network.now;
    // The first tick starts the age, and the relays count theirs from the
    // `EXTEND` cells before it.
    assert!(network.clients[0].on_tick(start).is_empty());
    let aged = start + CIRCUIT_MAX_AGE - CIRCUIT_AGE_MARGIN;
    assert!(network.clients[0].on_tick(aged - 1).is_empty());
    // NET-320: the client acts first, and the runtime starts a new run.
    assert_eq!(network.clients[0].on_tick(aged), [ClientEvent::CircuitAged]);
}

#[test]
fn a_circuit_near_its_cells_ends_the_run_and_the_relay_ends_it_after() {
    use umbra_onion::CIRCUIT_MAX_CELLS;
    let mut network = Network::new();
    network.settle();
    network.take_events(0);
    // The first cell of a circuit at the exit starts its pacing clock.
    let now = network.now;
    network.clients[0]
        .on_cover_slot(true, None, now, &mut Rng(5))
        .unwrap();
    // The exit paces one cell toward the client at each step, thus the
    // count toward the client reaches the limit first.
    let mut steps = 0u32;
    loop {
        network.step();
        steps += 1;
        let events = network.clients[0].on_tick(network.now);
        if events.contains(&ClientEvent::CircuitAged) {
            break;
        }
        assert!(
            steps < CIRCUIT_MAX_CELLS,
            "the client never left the circuit"
        );
    }
    // NET-321: the client leaves before the relay counts the limit.
    assert!(steps < CIRCUIT_MAX_CELLS);
    let paced = network.relays[2].paced_circuits().count();
    for _ in 0..200 {
        network.step();
    }
    // The exit counts past the limit, and its sweep ends those circuits.
    let now = network.now;
    network.relays[2].sweep(now);
    assert!(network.relays[2].paced_circuits().count() < paced);
}

/// Two clients that became contacts, with their two conversations.
fn contacts(network: &mut Network) -> (ContactId, ContactId) {
    network.settle();
    network.take_events(0);
    network.take_events(1);
    network.clients[0].invite(&mut Rng(1)).unwrap();
    network.settle();
    let events = network.take_events(0);
    let Some(ClientEvent::Invitation { bundle, .. }) = events.last() else {
        panic!("{events:?}");
    };
    network.clients[1]
        .accept(bundle.clone(), &mut Rng(2))
        .unwrap();
    network.settle();
    let (alice, _) = contact_of(&network.take_events(0));
    let (bob, _) = contact_of(&network.take_events(1));
    (alice, bob)
}

#[test]
fn a_queue_takes_its_binding_and_a_live_arrival_wakes_nobody() {
    use umbra_core::notify::binding::Binding;
    use umbra_crypto::kem::PublicKey;
    let mut network = Network::new();
    let (_, bob_contact) = contacts(&mut network);

    // NTF-112: the relay of each inbound queue of Alice answers her `NKEY`
    // with its notification key.
    let queues = network.clients[0].inbound_queues();
    assert_eq!(queues.len(), 1);
    let (queue, relay) = queues[0];
    assert_eq!(relay, relay_static(3).0.relay_id);
    network.clients[0]
        .notify_queue(&queue, &mut Rng(5))
        .unwrap();
    network.settle();
    let events = network.take_events(0);
    let [ClientEvent::NotifyKey {
        recipient_id,
        relay_ntf_pk,
    }] = &events[..]
    else {
        panic!("{events:?}");
    };
    assert_eq!(*recipient_id, queue);
    let relay_ntf = PublicKey::from_bytes(relay_ntf_pk).unwrap();

    // NTF-113: she seals her binding to it.
    let binding = Binding {
        root: Secret::new([0x31; 32]),
        handle: [0x32; 16],
        k_tok: Secret::new([0x33; 32]),
        queue_alias: [0x34; 16],
        relay_idx: 0,
    };
    let sealed = binding.seal(&relay_ntf, &queue, &mut Rng(6)).unwrap();
    network.clients[0]
        .bind_queue(&queue, &sealed, &mut Rng(7))
        .unwrap();
    network.settle();

    // NTF-128: her subscription takes the record, and no push follows.
    let now = network.now;
    network.clients[1]
        .send(&bob_contact, &text(1, "while she reads"), now, &mut Rng(8))
        .unwrap();
    network.settle();
    assert!(network
        .take_events(0)
        .iter()
        .any(|event| matches!(event, ClientEvent::Message { .. })));
    assert!(network.pushes.is_empty());
}

fn invitations_of(events: Vec<ClientEvent>) -> Vec<Vec<u8>> {
    events
        .into_iter()
        .filter_map(|event| match event {
            ClientEvent::Invitation { bundle, .. } => Some(bundle),
            _ => None,
        })
        .collect()
}

#[test]
fn more_queues_than_one_session_serves_go_to_more_circuits() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.take_events(ALICE);

    // A relay serves 8 queues in one session (`NET-022`). The ninth queue
    // and each later one wait for a second circuit.
    for n in 0..11u64 {
        network.clients[ALICE].invite(&mut Rng(40 + n)).unwrap();
    }
    network.settle();
    network.settle();
    let events = network.take_events(ALICE);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, ClientEvent::Rejected { .. })),
        "{events:?}"
    );
    let bundles = invitations_of(events);
    assert_eq!(bundles.len(), 11);
    assert_eq!(network.stored[ALICE].invitations.len(), 11);

    // A new run divides the 11 stored queues over two circuits, and the
    // last invitation, which is on the second one, gives a contact.
    network.restart(ALICE, 0x40);
    network.settle();
    let events = network.take_events(ALICE);
    assert!(!events
        .iter()
        .any(|event| matches!(event, ClientEvent::Rejected { .. })));
    network.clients[BOB]
        .accept(bundles[10].clone(), &mut Rng(60))
        .unwrap();
    network.settle();
    let (alice_contact, _) = contact_of(&network.take_events(ALICE));
    let (bob_contact, _) = contact_of(&network.take_events(BOB));

    // Text travels both ways with the queues on different circuits.
    let now = network.now;
    network.clients[BOB]
        .send(
            &bob_contact,
            &text(1, "to the second circuit"),
            now,
            &mut Rng(61),
        )
        .unwrap();
    network.clients[ALICE]
        .send(&alice_contact, &text(2, "and back"), now, &mut Rng(62))
        .unwrap();
    network.settle();
    assert_eq!(
        messages_of(network.take_events(ALICE)),
        [b"to the second circuit"]
    );
    assert_eq!(messages_of(network.take_events(BOB)), [b"and back"]);
}

#[test]
fn the_inviter_writes_first_and_the_record_waits_for_the_chain() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let bundle = invitations_of(network.take_events(ALICE)).remove(0);
    network.clients[BOB].accept(bundle, &mut Rng(2)).unwrap();

    // Alice writes in the turn that gives her the contact. Her ratchet has
    // no sending chain before the first record of Bob arrives (`NET-292`),
    // thus the record waits in the node, and it does not fail.
    let mut alice_contact = None;
    for _ in 0..24 {
        network.step();
        let events = network.take_events(ALICE);
        if let Some(ClientEvent::ContactReady { contact, .. }) = events
            .iter()
            .find(|event| matches!(event, ClientEvent::ContactReady { .. }))
        {
            alice_contact = Some(*contact);
            break;
        }
    }
    let alice_contact = alice_contact.expect("a contact");
    let now = network.now;
    let sent = network.clients[ALICE]
        .send(
            &alice_contact,
            &text(7, "the inviter writes first"),
            now,
            &mut Rng(3),
        )
        .unwrap();
    network.settle();
    assert!(network
        .take_events(ALICE)
        .contains(&ClientEvent::Accepted { handle: sent }));
    // The queue address record of Bob is no message of the conversation.
    assert_eq!(
        messages_of(network.take_events(BOB)),
        [b"the inviter writes first"]
    );
}

fn link_of(events: Vec<ClientEvent>) -> Vec<u8> {
    events
        .into_iter()
        .find_map(|event| match event {
            ClientEvent::InvitationLink { fragment, .. } => Some(fragment),
            _ => None,
        })
        .expect("a link")
}

#[test]
fn a_link_gives_one_contact_and_a_second_fetch_finds_nothing() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    let carol = network.add_client(0x50);

    // The relay draws the link identifier, Alice seals the bundle under
    // it, and the relay holds a blob that it cannot read.
    network.clients[ALICE].invite_link(&mut Rng(1)).unwrap();
    network.settle();
    let fragment = link_of(network.take_events(ALICE));
    assert_eq!(fragment.len(), 68);
    assert_eq!(network.stored[ALICE].invitations.len(), 1);

    // The link waits across a restart of Alice, and the store gives the
    // fragment again.
    network.restart(ALICE, 0x40);
    network.settle();
    network.take_events(ALICE);

    // Bob makes the first fetch, which locks the queue of Alice to his key.
    network.clients[BOB]
        .accept_link(&fragment, &mut Rng(2))
        .unwrap();
    network.settle();
    let (alice_contact, _) = contact_of(&network.take_events(ALICE));
    let (bob_contact, _) = contact_of(&network.take_events(BOB));

    // IDN-023: a second party that holds the link gets no blob, and it
    // learns that.
    let late = network.clients[carol]
        .accept_link(&fragment, &mut Rng(3))
        .unwrap();
    network.settle();
    assert_eq!(
        network.take_events(carol),
        [ClientEvent::InvitationGone { handle: late }]
    );

    let now = network.now;
    network.clients[ALICE]
        .send(&alice_contact, &text(1, "over a link"), now, &mut Rng(4))
        .unwrap();
    network.clients[BOB]
        .send(&bob_contact, &text(2, "and back"), now, &mut Rng(5))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(BOB)), [b"over a link"]);
    assert_eq!(messages_of(network.take_events(ALICE)), [b"and back"]);
}

#[test]
fn a_party_that_fetches_first_is_seen_by_the_true_invitee() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    let mallory = network.add_client(0x66);
    network.clients[ALICE].invite_link(&mut Rng(1)).unwrap();
    network.settle();
    let fragment = link_of(network.take_events(ALICE));

    // Mallory reads the link on its way and fetches first.
    network.clients[mallory]
        .accept_link(&fragment, &mut Rng(2))
        .unwrap();
    network.settle();
    network.take_events(mallory);

    // The fetch of Bob fails, thus Bob and Alice learn of the attack when
    // they compare: Bob holds no contact, and Alice holds one.
    let tried = network.clients[BOB]
        .accept_link(&fragment, &mut Rng(3))
        .unwrap();
    network.settle();
    assert!(network
        .take_events(BOB)
        .contains(&ClientEvent::InvitationGone { handle: tried }));
    assert_eq!(network.clients[BOB].contacts().count(), 0);
}

#[test]
fn a_link_with_a_wrong_key_opens_no_blob() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite_link(&mut Rng(1)).unwrap();
    network.settle();
    let mut fragment = link_of(network.take_events(ALICE));

    // The first 32 bytes are the key material. The relay knows the link
    // identifier alone, thus it gives the blob, and the blob does not open.
    fragment[0] ^= 1;
    let tried = network.clients[BOB]
        .accept_link(&fragment, &mut Rng(2))
        .unwrap();
    network.settle();
    assert!(network
        .take_events(BOB)
        .contains(&ClientEvent::InvitationGone { handle: tried }));
    assert!(network.clients[BOB]
        .accept_link(&fragment[..60], &mut Rng(3))
        .is_err());
}

#[test]
fn the_relays_restart_and_each_contact_continues() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite_link(&mut Rng(1)).unwrap();
    network.settle();
    let first_link = link_of(network.take_events(ALICE));
    network.clients[BOB]
        .accept_link(&first_link, &mut Rng(2))
        .unwrap();
    network.settle();
    let (alice_contact, _) = contact_of(&network.take_events(ALICE));
    let (bob_contact, _) = contact_of(&network.take_events(BOB));

    // A second link waits at the relay, and Bob writes a record that Alice
    // does not take before the restart: her client is gone first.
    network.clients[ALICE].invite_link(&mut Rng(3)).unwrap();
    network.settle();
    let waiting_link = link_of(network.take_events(ALICE));
    network.restart(ALICE, 0x40);
    let now = network.now;
    network.clients[BOB]
        .send(
            &bob_contact,
            &text(1, "held across the restart"),
            now,
            &mut Rng(4),
        )
        .unwrap();
    network.settle();
    network.commit_relays();
    let holds_a_record =
        |store: &MemoryStore| store.0.queues.values().any(|q| !q.records.is_empty());
    assert!(holds_a_record(&network.relay_stores[2]));

    // Each relay process ends. The store of the queue relay holds the two
    // queues of the pair, the queue of the second link, the record, and
    // the blob.
    network.restart_network(&[0x40, 0x41]);
    let held = &network.relay_stores[2].0;
    assert_eq!(held.queues.len(), 3);
    assert_eq!(held.invitations.len(), 1);
    assert!(network.relay_stores[0].0.queues.is_empty());
    network.settle();

    // Alice takes the record one time, and the pair talks under the
    // stored ratchets.
    assert_eq!(
        messages_of(network.take_events(ALICE)),
        [b"held across the restart"]
    );
    let now = network.now;
    network.clients[ALICE]
        .send(
            &alice_contact,
            &text(2, "after the relays"),
            now,
            &mut Rng(5),
        )
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(BOB)), [b"after the relays"]);

    // The link that waited serves a third party, and the lock of the first
    // link holds: a record under the old `QS_auth` would be refused, and
    // the records of Bob above went under his lock key.
    let carol = network.add_client(0x50);
    network.clients[carol]
        .accept_link(&waiting_link, &mut Rng(6))
        .unwrap();
    network.settle();
    contact_of(&network.take_events(carol));
    assert_eq!(network.clients[ALICE].contacts().count(), 2);
}

fn code_of(events: &[ClientEvent]) -> Option<u32> {
    events.iter().find_map(|event| match event {
        ClientEvent::VerificationCode { code, .. } => Some(*code),
        _ => None,
    })
}

fn control(kind: AppKind, body: &[u8]) -> Vec<u8> {
    let message = AppMessage {
        kind,
        msg_id: [0x77; 16],
        sent_at: 0,
        body,
    };
    let mut out = vec![0u8; message.len()];
    message.encode(&mut out).unwrap();
    out
}

#[test]
fn a_ceremony_gives_one_code_and_only_the_user_verifies() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let bundle = invitations_of(network.take_events(ALICE)).remove(0);
    network.clients[BOB].accept(bundle, &mut Rng(2)).unwrap();
    network.settle();
    let (alice_contact, bob_static) = contact_of(&network.take_events(ALICE));
    let (bob_contact, alice_static) = contact_of(&network.take_events(BOB));

    // No ceremony ran, and a confirmation sets nothing (IDN-148).
    assert!(network.clients[ALICE]
        .confirm_verification(&alice_contact)
        .is_err());

    // Alice starts. The two devices get one code, and no record of the
    // ceremony shows as a message.
    let now = network.now;
    network.clients[ALICE]
        .start_verification(&alice_contact, now, &mut Rng(3))
        .unwrap();
    // The commit went, and the reveal of Bob is not here yet.
    assert!(network.clients[ALICE]
        .confirm_verification(&alice_contact)
        .is_err());
    network.settle();
    let alice_events = network.take_events(ALICE);
    let bob_events = network.take_events(BOB);
    let code = code_of(&alice_events).expect("a code at Alice");
    assert_eq!(code_of(&bob_events), Some(code));
    assert!(code < 1_000_000);
    assert!(messages_of(alice_events).is_empty());
    assert!(messages_of(bob_events).is_empty());

    // The confirmation gives the key that the handshake gave, one time.
    assert_eq!(
        network.clients[ALICE]
            .confirm_verification(&alice_contact)
            .unwrap(),
        bob_static
    );
    assert!(network.clients[ALICE]
        .confirm_verification(&alice_contact)
        .is_err());
    assert_eq!(
        network.clients[BOB]
            .confirm_verification(&bob_contact)
            .unwrap(),
        alice_static
    );

    // A second ceremony uses new nonces, and its code is its own.
    let now = network.now;
    network.clients[BOB]
        .start_verification(&bob_contact, now, &mut Rng(4))
        .unwrap();
    network.settle();
    let second = code_of(&network.take_events(BOB)).expect("a code at Bob");
    assert_eq!(code_of(&network.take_events(ALICE)), Some(second));
    assert_ne!(second, code);

    // The user starts two times in a row. The answer to the first start
    // pairs with nothing, and the two devices end with one code.
    for seed in [5, 6] {
        let now = network.now;
        network.clients[ALICE]
            .start_verification(&alice_contact, now, &mut Rng(seed))
            .unwrap();
    }
    network.settle();
    let third = code_of(&network.take_events(ALICE)).expect("a code at Alice");
    assert_eq!(code_of(&network.take_events(BOB)), Some(third));

    // The two users start at one time, and one start becomes the answer.
    let now = network.now;
    network.clients[ALICE]
        .start_verification(&alice_contact, now, &mut Rng(7))
        .unwrap();
    network.clients[BOB]
        .start_verification(&bob_contact, now, &mut Rng(8))
        .unwrap();
    network.settle();
    let alice_events = network.take_events(ALICE);
    let fourth = code_of(&alice_events).expect("a code at Alice");
    assert_eq!(code_of(&network.take_events(BOB)), Some(fourth));
    let codes = alice_events
        .iter()
        .filter(|event| matches!(event, ClientEvent::VerificationCode { .. }))
        .count();
    assert_eq!(codes, 1);

    // IDN-144: a reveal that does not match its commit gives no code.
    let forged_start = [[0x11; 32], [0; 32]].concat();
    for (seed, kind, body) in [
        (9, AppKind::VerifyCommit, forged_start.as_slice()),
        (10, AppKind::VerifyReveal, [0x22; 32].as_slice()),
    ] {
        let now = network.now;
        network.clients[BOB]
            .send(&bob_contact, &control(kind, body), now, &mut Rng(seed))
            .unwrap();
        network.settle();
    }
    assert_eq!(code_of(&network.take_events(ALICE)), None);
    assert!(network.clients[ALICE]
        .confirm_verification(&alice_contact)
        .is_err());
}

#[test]
fn a_stored_contact_of_the_first_version_continues() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    let bundle = invitations_of(network.take_events(ALICE)).remove(0);
    network.clients[BOB].accept(bundle, &mut Rng(2)).unwrap();
    network.settle();
    let (bob_contact, _) = contact_of(&network.take_events(BOB));
    network.take_events(ALICE);

    // Version 0x01 named no relay of the inbound queue: the version byte,
    // the salt, the key of the peer, and then the channel. The two queues
    // of such a contact live at one relay, and the channel names it.
    for state in network.stored[ALICE].contacts.values_mut() {
        assert_eq!(state[0], 0x02);
        state[0] = 0x01;
        state.drain(1 + 16 + 32..1 + 16 + 32 + 32);
    }
    network.restart(ALICE, 0x41);
    let now = network.now;
    network.clients[BOB]
        .send(&bob_contact, &text(1, "still here"), now, &mut Rng(3))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(ALICE)), [b"still here"]);
    // The next store of the contact is of the present version, and it names
    // the relay of the inbound queue.
    let queue_relay = relay_static(3).0.relay_id;
    assert!(network.stored[ALICE]
        .contacts
        .values()
        .all(|state| state[0] == 0x02 && state[49..81] == queue_relay));
}
