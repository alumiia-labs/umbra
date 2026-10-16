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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use umbra_core::session::node::{
    ClientEvent, ClientNode, ContactId, CoverSlot, ParkedSession, StateChange,
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    hierarchy::RootIdentity,
    rand_core::{TryCryptoRng, TryRng},
    secret::Secret,
    sign::SigningKey,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_queue::params::RECEIPT_MIN_DELAY;
use umbra_relay::{
    circuits::{CircuitKey, LinkId},
    node::{Config, Output, QueryAnswer, RelayNode},
    service::queue::NdrPush,
    store::{MemoryStore, RelayStore},
};
use umbra_wire::{
    address::QueueAddress,
    app::{AppKind, AppMessage, Channel},
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
    rendezvous: BTreeMap<[u8; 32], Vec<u8>>,
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
            chunk_capacity: 1 << 26,
        }
    }

    /// The identity key of each relay, which signs its hello and its
    /// receipts (Part 10 §10.4.2), and the identities of the set.
    fn sign_relays(&mut self) {
        let keys: Vec<SigningKey> = (1..=3u8)
            .map(|layer| SigningKey::from_seed(Secret::new([0x30 + layer; 32])))
            .collect();
        let identities: BTreeMap<[u8; 32], Vec<u8>> = (1..=3u8)
            .zip(&keys)
            .map(|(layer, key)| {
                (
                    relay_static(layer).0.relay_id,
                    key.verifying_key().to_bytes().to_vec(),
                )
            })
            .collect();
        for (relay, key) in self.relays.iter_mut().zip(keys) {
            relay.set_challenge_signer(key, Vec::new());
            relay.set_relay_identities(identities.clone());
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
        self.sign_relays();
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
        network.sign_relays();
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
                // WIR-241: the connection that resumed serves the
                // identifier of the session from now on.
                Output::Adopt { link, as_link } => {
                    self.peers[at].retain(|(held, _)| *held != as_link);
                    for (held, _) in &mut self.peers[at] {
                        if *held == link {
                            *held = as_link;
                        }
                    }
                    for held in &mut self.links {
                        if *held == link {
                            *held = as_link;
                        }
                    }
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

    /// Runs each forward cell that waits for its per-hop delay (Part 3
    /// §3.9) at once, until no relay holds one: the mesh has no clock of
    /// milliseconds.
    fn flush_delayed(&mut self) {
        for _ in 0..64 {
            let mut any = false;
            for relay in 0..self.relays.len() {
                if !self.relays[relay].has_delayed() {
                    continue;
                }
                any = true;
                let outputs = self.relays[relay].release_delayed(u64::MAX, self.now, &mut self.rng);
                self.route(relay, outputs);
            }
            if !any {
                return;
            }
        }
    }

    /// One turn of each party.
    fn step(&mut self) {
        self.commit_relays();
        {
            for client in 0..self.clients.len() {
                self.clients[client]
                    .start_rendezvous_due(self.now, &mut self.rng)
                    .unwrap();
                self.clients[client]
                    .rebuild_lost(self.now, &mut self.rng)
                    .unwrap();
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
            self.flush_delayed();
            let circuits: Vec<_> = self.relays[2].paced_circuits().copied().collect();
            for circuit in circuits {
                let outputs = self.relays[2].pacing_tick(&circuit, self.now, &mut self.rng);
                self.route(2, outputs);
            }
            let outputs = self.relays[2].drain_tick(self.now, &mut self.rng);
            self.route(2, outputs);
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
                StateChange::RendezvousQueue { queue, state } => {
                    stored.rendezvous.insert(queue, state.to_vec());
                }
                StateChange::RendezvousQueueEnded { queue } => {
                    stored.rendezvous.remove(&queue);
                }
                // No test of this harness makes a notify queue.
                StateChange::NotifyQueue { .. } | StateChange::NotifyQueueEnded { .. } => {}
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
        for state in self.stored[client].rendezvous.values() {
            node.restore_rendezvous_queue(state).unwrap();
        }
        // A session identifier comes from the CSPRNG (`WIR-136`), thus each
        // run takes a new one. The ingress relay parked the session of the
        // run before, and it refuses a second open of that identifier
        // (`WIR-233`).
        let run = old_link / 100;
        node.connected(&mut Rng(300 + u64::from(seed) + run * 1_000))
            .unwrap();
        self.clients[client] = node;
        self.links[client] = old_link + 100;
        self.peers[0].push((self.links[client], Peer::Client(client)));
    }

    /// Ends the run of a client with a pause of its session (`WIR-539`):
    /// the guard answers, the connection closes, and the result is the
    /// parked session.
    fn pause(&mut self, client: usize) -> ParkedSession {
        self.commit(client);
        self.clients[client].pause().unwrap();
        let link = self.links[client];
        for capsule in self.clients[client].take_capsules() {
            let outputs = self.relays[0].on_capsule(link, &capsule, self.now, &mut self.rng);
            self.route(0, outputs);
        }
        self.flush_delayed();
        while let Some(capsule) = self.inboxes[client].pop_front() {
            let events = self.clients[client]
                .on_capsule(&capsule, self.now, &mut self.rng)
                .unwrap();
            self.events[client].extend(events);
        }
        self.commit(client);
        assert!(self.clients[client].is_paused());
        let parked = self.clients[client].park(self.now).unwrap();
        let closed = self.relays[0].link_closed(link, self.now);
        assert!(closed.is_empty());
        self.peers[0].retain(|(held, _)| *held != link);
        parked
    }

    /// Starts a new run of a client from its store on a new connection,
    /// with the session that the run before parked. The result says
    /// whether the node resumed that session.
    fn resume(&mut self, client: usize, seed: u8, parked: ParkedSession) -> bool {
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
        for state in self.stored[client].rendezvous.values() {
            node.restore_rendezvous_queue(state).unwrap();
        }
        let resumed = node
            .resumed(parked, self.now, &mut Rng(500 + self.now))
            .unwrap();
        self.inboxes[client].clear();
        self.clients[client] = node;
        self.links[client] += 100;
        self.peers[0].push((self.links[client], Peer::Client(client)));
        resumed
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
                ..
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
        .on_cover_slot(false, None, None, now, &mut Rng(4))
        .unwrap();
    assert_eq!(slot, CoverSlot::Nothing);
    let mut kinds = Vec::new();
    for seed in 0..24 {
        kinds.push(
            network.clients[ALICE]
                .on_cover_slot(true, None, None, now, &mut Rng(40 + seed))
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
        .on_cover_slot(false, None, None, now, &mut Rng(90))
        .unwrap();
    assert_eq!(slot, CoverSlot::Acknowledgment);
    let slot = network.clients[ALICE]
        .on_cover_slot(false, None, None, now, &mut Rng(91))
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
            .on_cover_slot(
                false,
                Some((&bob_contact, &receipt)),
                None,
                now,
                &mut Rng(seed),
            )
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
        .on_cover_slot(
            false,
            Some((&bob_contact, &receipt)),
            None,
            now,
            &mut Rng(93),
        )
        .unwrap();
    assert_eq!(slot, CoverSlot::Acknowledgment);
    network.settle();

    // REL-169: a link-fault report takes a slot after the receipts. It goes
    // to a report queue whose relay a ready circuit reaches, thus it builds
    // no circuit, and with no such queue it waits.
    let queue_at = |relay: [u8; 32]| {
        let mut address = [0u8; 129];
        QueueAddress {
            relay_id: relay,
            sender_id: [0x77; 32],
            qs_auth_sk: Secret::new([0x78; 32]),
            qe: Secret::new([0x79; 32]),
        }
        .encode(&mut address)
        .unwrap();
        (address, [0x7A; 32])
    };
    let chain = [[0x11; 32], [0x12; 32], [0x13; 32]];
    let now = network.now;
    let faults = network.clients[BOB].faults_mut();
    faults.forced_replacement(&chain, now);
    faults.forced_replacement(&chain, now);
    network.clients[BOB].set_report_queues(vec![queue_at([0xEE; 32])]);
    let slot = network.clients[BOB]
        .on_cover_slot(false, None, None, now, &mut Rng(95))
        .unwrap();
    assert_eq!(slot, CoverSlot::Nothing);
    // REL-182: after REPORT_WAIT a report builds a circuit, and to a relay
    // of the set alone: this queue names none, thus the report waits.
    let later = now + umbra_core::session::faults::REPORT_WAIT;
    let slot = network.clients[BOB]
        .on_cover_slot(true, None, None, later, &mut Rng(98))
        .unwrap();
    assert_ne!(slot, CoverSlot::Report);
    assert!(network.clients[BOB].faults_mut().due().is_some());
    network.clients[BOB].set_report_queues(
        (1..=5)
            .map(|layer| queue_at(relay_static(layer).0.relay_id))
            .collect(),
    );
    let slot = network.clients[BOB]
        .on_cover_slot(false, None, None, now, &mut Rng(96))
        .unwrap();
    assert_eq!(slot, CoverSlot::Report);
    // REL-107: one report in a run that makes no cover cell.
    let faults = network.clients[BOB].faults_mut();
    faults.forced_replacement(&[[0x11; 32], [0x14; 32], [0x15; 32]], now);
    let slot = network.clients[BOB]
        .on_cover_slot(false, None, None, now, &mut Rng(97))
        .unwrap();
    assert_eq!(slot, CoverSlot::Nothing);
    network.settle();
    network.take_events(BOB);

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

/// Part 9 §9.6: a stranger sends a hello with a fresh invitation to the
/// rendezvous queue of an entry, and the addressee accepts it as a bundle.
/// The queue and the invitation of the hello wait across a restart.
#[test]
fn a_hello_on_a_rendezvous_queue_becomes_a_contact() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.take_events(ALICE);
    network.take_events(BOB);
    let general = network.clients[ALICE].chains().len();
    network.clients[ALICE]
        .make_rendezvous_queue(&mut Rng(1))
        .unwrap();
    network.settle();
    // DIS-014: the rendezvous queue has a circuit of its own.
    assert_eq!(network.clients[ALICE].chains().len(), general + 1);
    let events = network.take_events(ALICE);
    let Some(ClientEvent::RendezvousQueue { address, .. }) = events.last() else {
        panic!("{events:?}");
    };
    let address = address.clone();
    assert_eq!(network.stored[ALICE].rendezvous.len(), 1);
    network.restart(ALICE, 0x40);
    // DIS-015: the rendezvous circuit of a run starts after 20 to 120 s.
    for _ in 0..11 {
        network.settle();
    }
    network.take_events(ALICE);
    assert_eq!(network.clients[ALICE].chains().len(), 2);

    // Bob holds the key of the entry and the queue from a lookup.
    let key = RootIdentity::new(Secret::new([0x40; 32])).public_address_key(1);
    let entry_pk = key.public().to_bytes();
    let epoch = umbra_core::abuse::epoch_number(network.now);
    network.clients[BOB]
        .hello(&entry_pk, &address, b"Bob", epoch, None, &mut Rng(2))
        .unwrap();
    network.settle();
    let sent = network.take_events(BOB);
    assert!(sent
        .iter()
        .any(|event| matches!(event, ClientEvent::HelloSent { .. })));
    // No view shows the invitation of a hello after a restart.
    assert_eq!(network.stored[BOB].invitations.len(), 1);
    network.restart(BOB, 0x41);
    network.settle();
    network.take_events(BOB);

    let events = network.take_events(ALICE);
    let Some(envelope) = events.iter().find_map(|event| match event {
        ClientEvent::Hello { envelope, .. } => Some(envelope.clone()),
        _ => None,
    }) else {
        panic!("{events:?}");
    };
    let plain = umbra_core::discovery::hello::open(&key, &envelope).unwrap();
    let body = umbra_core::discovery::hello::HelloBody::parse(&plain).unwrap();
    assert_eq!(body.profile, b"Bob");
    let solution = umbra_core::abuse::pow::PowSolution::parse(body.admission.body).unwrap();
    umbra_core::abuse::pow::verify_hello(&entry_pk, epoch, &solution).unwrap();
    let mut bundle = vec![0u8; body.bundle.len()];
    body.bundle.encode(&mut bundle).unwrap();

    // DIS-087: flight 1 goes to the queue of the invitation of the hello.
    network.clients[ALICE].accept(bundle, &mut Rng(3)).unwrap();
    network.settle();
    contact_of(&network.take_events(ALICE));
    contact_of(&network.take_events(BOB));
    assert!(network.stored[BOB].invitations.is_empty());
}

/// A run that ends between two flights of a handshake strands nothing: the
/// invitee waits for flight 2 in its stored form and sends flight 1 again,
/// and the inviter waits for flight 3 in its stored form.
#[test]
fn a_handshake_continues_after_a_restart_in_each_window() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    for restarted in [BOB, ALICE] {
        let mut network = Network::new();
        network.settle();
        network.clients[ALICE].invite(&mut Rng(1)).unwrap();
        network.settle();
        let events = network.take_events(ALICE);
        let Some(ClientEvent::Invitation { bundle, .. }) = events.last() else {
            panic!("{events:?}");
        };
        network.take_events(BOB);
        network.clients[BOB]
            .accept(bundle.clone(), &mut Rng(2))
            .unwrap();
        // The invitee holds its half after the relay made its queue; the
        // inviter holds the responder state after flight 1.
        let waiting = |network: &Network| {
            let form = if restarted == BOB { 0x06 } else { 0x07 };
            network.stored[restarted]
                .invitations
                .values()
                .any(|state| state.first() == Some(&form))
        };
        let mut steps = 0;
        while !waiting(&network) {
            network.step();
            steps += 1;
            assert!(steps < 60, "no stored half");
        }
        network.restart(restarted, 0x40 + restarted as u8);
        for _ in 0..3 {
            network.settle();
        }
        contact_of(&network.take_events(ALICE));
        contact_of(&network.take_events(BOB));
        assert!(network.stored[ALICE].invitations.is_empty());
        assert!(network.stored[BOB].invitations.is_empty());
    }
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
        .on_cover_slot(true, None, None, now, &mut Rng(5))
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
    network.relays[2].sweep(now, &mut Rng(3));
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
        .notify_queue(&queue, &[6; 32], &mut Rng(5))
        .unwrap();
    network.settle();
    let events = network.take_events(0);
    // NTF-112: the `NPK` comes first, and the `NID` names the notifier.
    let [ClientEvent::NotifyKey {
        recipient_id,
        relay_ntf_pk,
    }, ClientEvent::NotifierId { .. }] = &events[..]
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

#[test]
fn a_lost_client_link_parks_its_circuits_and_the_next_arrival_is_pushed() {
    use umbra_core::notify::{binding::Binding, blob::Receiver};
    use umbra_crypto::kem::PublicKey;
    use umbra_wire::ndr::NdrRequest;
    let mut network = Network::new();
    let (_, bob_contact) = contacts(&mut network);
    let (queue, _) = network.clients[0].inbound_queues()[0];
    network.clients[0]
        .notify_queue(&queue, &[6; 32], &mut Rng(5))
        .unwrap();
    network.settle();
    let events = network.take_events(0);
    let [ClientEvent::NotifyKey { relay_ntf_pk, .. }, ClientEvent::NotifierId { .. }] = &events[..]
    else {
        panic!("{events:?}");
    };
    let binding = Binding {
        root: Secret::new([0x41; 32]),
        handle: [0x42; 16],
        k_tok: Secret::new([0x43; 32]),
        queue_alias: [0x44; 16],
        relay_idx: 2,
    };
    let sealed = binding
        .seal(
            &PublicKey::from_bytes(relay_ntf_pk).unwrap(),
            &queue,
            &mut Rng(6),
        )
        .unwrap();
    network.clients[0]
        .bind_queue(&queue, &sealed, &mut Rng(7))
        .unwrap();
    network.settle();

    // WIR-542, WIR-546: the link of Alice at the guard closes with no
    // `SessionClose`, thus the guard parks her session and each relay of
    // her chain takes a `CircuitPause`. The exit ends her subscription, and
    // the pacing clock of her circuit stops.
    let exits = network.relays[2].paced_circuits().count();
    let now = network.now;
    let closed = network.relays[0].link_closed(network.links[0], now);
    network.route(0, closed);
    let link = network.links[0];
    network.peers[0].retain(|(held, _)| *held != link);
    assert_eq!(network.relays[2].paced_circuits().count(), exits - 1);

    // NTF-128: no subscription takes the record, thus the exit pushes.
    network.clients[1]
        .send(
            &bob_contact,
            &text(1, "while she is away"),
            now,
            &mut Rng(8),
        )
        .unwrap();
    network.settle();
    assert_eq!(network.pushes.len(), 1);
    let NdrRequest::Push { handle, blob, .. } =
        NdrRequest::parse(&network.pushes[0].request[..]).unwrap()
    else {
        panic!("not a push");
    };
    assert_eq!(handle, [0x42; 16]);
    let plain = Receiver::new(Secret::new([0x41; 32]))
        .open(&blob, network.now)
        .unwrap();
    assert_eq!(plain.queue_alias, [0x44; 16]);

    // A link between two relays closes: Bob learns that his circuit ended,
    // and his runtime builds again.
    let (at_exit, at_middle) = network.peers[2]
        .iter()
        .find_map(|(link, peer)| match peer {
            Peer::Relay(1, other) => Some((*link, *other)),
            _ => None,
        })
        .unwrap();
    let now = network.now;
    let closed = network.relays[2].link_closed(at_exit, now);
    network.route(2, closed);
    let closed = network.relays[1].link_closed(at_middle, now);
    network.route(1, closed);
    network.step();
    assert!(network.take_events(1).contains(&ClientEvent::CircuitLost));
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

fn ended_of(events: &[ClientEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, ClientEvent::VerificationEnded { .. }))
        .count()
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

    // Alice starts. IDN-170: the client of Bob answers nothing and
    // reveals nothing before Bob acts, thus no device holds a code.
    let now = network.now;
    network.clients[ALICE]
        .start_verification(&alice_contact, now, &mut Rng(3))
        .unwrap();
    // The commit went, and the reveal of Bob is not here yet.
    assert!(network.clients[ALICE]
        .confirm_verification(&alice_contact)
        .is_err());
    network.settle();
    assert_eq!(code_of(&network.take_events(ALICE)), None);
    assert_eq!(code_of(&network.take_events(BOB)), None);
    assert!(network.clients[BOB]
        .confirm_verification(&bob_contact)
        .is_err());
    // Bob accepts. The two devices get one code, and no record of the
    // ceremony shows as a message.
    let now = network.now;
    network.clients[BOB]
        .start_verification(&bob_contact, now, &mut Rng(30))
        .unwrap();
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
    let now = network.now;
    network.clients[ALICE]
        .start_verification(&alice_contact, now, &mut Rng(40))
        .unwrap();
    network.settle();
    let second = code_of(&network.take_events(BOB)).expect("a code at Bob");
    assert_eq!(code_of(&network.take_events(ALICE)), Some(second));
    assert_ne!(second, code);

    // The user starts two times in a row. Bob accepts the second start,
    // and the two devices end with one code. The ceremony of Bob held the
    // commit of Alice from the ceremony before, thus her new start ends
    // it, and Bob learns that (IDN-170).
    for seed in [5, 6] {
        let now = network.now;
        network.clients[ALICE]
            .start_verification(&alice_contact, now, &mut Rng(seed))
            .unwrap();
    }
    network.settle();
    let bob_events = network.take_events(BOB);
    assert_eq!(code_of(&bob_events), None);
    assert_eq!(ended_of(&bob_events), 1);
    assert!(network.clients[BOB]
        .confirm_verification(&bob_contact)
        .is_err());
    let now = network.now;
    network.clients[BOB]
        .start_verification(&bob_contact, now, &mut Rng(50))
        .unwrap();
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

    // IDN-170: the ceremony of Alice holds the commit of Bob, thus a new
    // start of Bob ends it one time. Each later start waits for Alice
    // with no answer. IDN-144: a reveal that does not match its commit
    // gives no code.
    let forged_start = [[0x11; 32], [0; 32]].concat();
    let later_start = [[0x12; 32], [0; 32]].concat();
    for (seed, kind, body) in [
        (9, AppKind::VerifyCommit, forged_start.as_slice()),
        (10, AppKind::VerifyReveal, [0x22; 32].as_slice()),
        (11, AppKind::VerifyCommit, later_start.as_slice()),
    ] {
        let now = network.now;
        network.clients[BOB]
            .send(&bob_contact, &control(kind, body), now, &mut Rng(seed))
            .unwrap();
        network.settle();
    }
    let alice_events = network.take_events(ALICE);
    assert_eq!(code_of(&alice_events), None);
    assert_eq!(ended_of(&alice_events), 1);
    assert!(network.clients[ALICE]
        .confirm_verification(&alice_contact)
        .is_err());
    // No answer and no reveal of Alice reached Bob: his ceremony still
    // holds the code of the ceremony before, and no new one.
    assert_eq!(code_of(&network.take_events(BOB)), None);
}

#[test]
fn a_stored_contact_of_the_first_version_continues() {
    // The renewal guard of version 0x06: the guard of this device, the
    // guard of the peer, and the flag of a bundle that waits.
    const GUARD: usize = (4 + 32 + 8 + 1) + (4 + 32 + 1) + 1;
    // The tail of version 0x06: the contact, the time of the queue, the
    // state of a rotation, the own address, the stale flag, the time of a
    // swept rotation, and the renewal guard.
    const TAIL: usize = 32 + 8 + 32 + 8 + 1 + 129 + 1 + 8 + GUARD;
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
    // of such a contact live at one relay, and the channel names it. Nor
    // did it hold the tail of version 0x03: the contact, the time of the
    // queue, the state of a rotation, and the address of the own queue,
    // which the bundle of the inviter gave.
    for state in network.stored[ALICE].contacts.values_mut() {
        assert_eq!(state[0], 0x06);
        assert_eq!(state[state.len() - GUARD - 139], 1);
        state[0] = 0x01;
        state.truncate(state.len() - TAIL);
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
        .all(|state| state[0] == 0x06 && state[49..81] == queue_relay));

    // Version 0x02 named the relay and held no tail. A contact of the first
    // version holds no address of its own queue, thus its tail ends with
    // the flag of none, the stale flag, and no swept time.
    for state in network.stored[ALICE].contacts.values_mut() {
        let end = state.len() - GUARD;
        assert_eq!(state[end - 10..end], [0; 10]);
        state[0] = 0x02;
        state.truncate(state.len() - (TAIL - 129));
    }
    network.restart(ALICE, 0x41);
    let now = network.now;
    network.clients[BOB]
        .send(&bob_contact, &text(2, "and still"), now, &mut Rng(4))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(ALICE)), [b"and still"]);
    assert!(network.clients[ALICE].contacts().count() == 1);

    // Version 0x04 held the stale flag and no swept time.
    for state in network.stored[ALICE].contacts.values_mut() {
        assert_eq!(state[0], 0x06);
        state[0] = 0x04;
        state.truncate(state.len() - 8 - GUARD);
    }
    network.restart(ALICE, 0x41);
    let now = network.now;
    network.clients[BOB]
        .send(&bob_contact, &text(5, "once more"), now, &mut Rng(5))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(ALICE)), [b"once more"]);

    // Version 0x05 held the swept time and no renewal guard.
    for state in network.stored[ALICE].contacts.values_mut() {
        assert_eq!(state[0], 0x06);
        state[0] = 0x05;
        state.truncate(state.len() - GUARD);
    }
    network.restart(ALICE, 0x41);
    let now = network.now;
    network.clients[BOB]
        .send(&bob_contact, &text(6, "and again"), now, &mut Rng(6))
        .unwrap();
    network.settle();
    assert_eq!(messages_of(network.take_events(ALICE)), [b"and again"]);
    assert!(network.stored[ALICE]
        .contacts
        .values()
        .all(|state| state[0] == 0x06));
}

/// Part 10 §10.4.2: each relay link carries receipts both ways. The dialing
/// relay names itself in its hello, the end of an epoch closes each window,
/// and each side keeps the receipt of the other over the cells it sent.
#[test]
fn each_relay_link_returns_receipts_for_its_cells() {
    let mut network = Network::new();
    network.settle();
    for relay in 0..3 {
        assert_eq!(network.relays[relay].receipts_held(), (0, 0));
    }
    network.now += 3_600;
    for relay in 0..3 {
        let outputs = network.relays[relay].push_tick(network.now, &mut Rng(200 + relay as u64));
        network.route(relay, outputs);
    }
    network.settle();
    // The middle relay has two relay links, the other two have one.
    let held: Vec<(usize, usize)> = (0..3)
        .map(|relay| network.relays[relay].receipts_held())
        .collect();
    assert_eq!(held, [(1, 1), (2, 2), (1, 1)], "{held:?}");
}

/// Part 10 §10.4.2: an authority makes a report queue, a client seals a
/// report to it in a cover slot, and the authority opens the report
/// (`REL-166`, `REL-169`, `WIR-536`).
#[test]
fn a_link_fault_report_reaches_the_report_queue_of_an_authority() {
    use umbra_core::directory::report::LinkFaultReport;
    use umbra_crypto::seal;

    const AUTHORITY: usize = 0;
    const CLIENT: usize = 1;
    let mut network = Network::new();
    network.settle();
    network.clients[AUTHORITY]
        .make_report_queue(&mut Rng(1))
        .unwrap();
    network.settle();
    let events = network.take_events(AUTHORITY);
    let Some(ClientEvent::ReportQueue { address, .. }) = events
        .iter()
        .find(|event| matches!(event, ClientEvent::ReportQueue { .. }))
    else {
        panic!("{events:?}");
    };
    let address: [u8; 129] = address.as_slice().try_into().unwrap();
    let report_sk = Secret::new([0x5A; 32]);
    let report_pk = seal::public_of(&report_sk);

    let chain = [[0x11; 32], [0x12; 32], [0x13; 32]];
    let now = network.now;
    let faults = network.clients[CLIENT].faults_mut();
    faults.forced_replacement(&chain, now);
    faults.forced_replacement(&chain, now);
    network.clients[CLIENT].set_report_queues(vec![(address, report_pk)]);
    let slot = network.clients[CLIENT]
        .on_cover_slot(true, None, None, now, &mut Rng(2))
        .unwrap();
    assert_eq!(slot, CoverSlot::Report);
    network.settle();
    let sealed: Vec<Vec<u8>> = network
        .take_events(AUTHORITY)
        .into_iter()
        .filter_map(|event| match event {
            ClientEvent::LinkFault { sealed, .. } => Some(sealed),
            _ => None,
        })
        .collect();
    assert_eq!(sealed.len(), 1);
    let report = LinkFaultReport::open(&report_sk, &sealed[0]).unwrap();
    assert_eq!(report.hops, chain);
    assert_eq!((report.loops_sent, report.loops_lost), (2, 2));
}

/// Part 10 §10.4.2: the probe of an isolation query names its cell at each
/// hop by the tag that the client computed, and after the epoch each relay
/// answers with the receipt that covers it, thus each link of the chain
/// holds (`REL-109` to `REL-111`, `REL-179`).
#[test]
fn a_probe_cell_is_covered_by_the_receipts_of_each_link() {
    use umbra_core::directory::receipt::{judge_link, LinkVerdict, ReceiptQuery};

    const AUTHORITY: usize = 0;
    let mut network = Network::new();
    network.settle();
    let (chain, tags) = network.clients[AUTHORITY].probe().unwrap();
    let relays: Vec<[u8; 32]> = (1..=3u8)
        .map(|layer| relay_static(layer).0.relay_id)
        .collect();
    assert_eq!(chain.to_vec(), relays);
    network.settle();
    let epoch = network.now / 3_600;
    network.now += 3_600;
    for relay in 0..3 {
        let outputs = network.relays[relay].push_tick(network.now, &mut Rng(300 + relay as u64));
        network.route(relay, outputs);
    }
    network.settle();
    let identity = |layer: u8| {
        SigningKey::from_seed(Secret::new([0x30 + layer; 32]))
            .verifying_key()
            .to_bytes()
    };
    // The link from hop k to hop k + 1 carries the tag of hop k + 1.
    for hop in 1..3usize {
        // REL-179: each relay takes a query that names it.
        let query = ReceiptQuery {
            authority_index: 0,
            relay_id: chain[hop],
            epoch,
            tag: tags[hop],
        };
        let before = ReceiptQuery {
            relay_id: chain[hop - 1],
            ..query
        };
        let at = epoch * umbra_core::directory::EPOCH_SECONDS;
        assert_eq!(
            network.relays[hop - 1].receipt_answer(&query, at),
            QueryAnswer::Elsewhere
        );
        let taken = network.relays[hop - 1]
            .receipt_answer(&before, at)
            .given()
            .unwrap();
        let issued = network.relays[hop]
            .receipt_answer(&query, at)
            .given()
            .unwrap();
        let verdict = judge_link(
            chain[hop - 1],
            chain[hop],
            &query,
            Some(&taken),
            Some(&issued),
            &identity(hop as u8 + 1),
        );
        assert_eq!(verdict, LinkVerdict::Held, "link {hop}");
    }
    // REL-186, REL-187: the middle relay answered this authority twice, and
    // it answers RECEIPT_QUERY_MAX in one epoch and no more.
    let query = ReceiptQuery {
        authority_index: 0,
        relay_id: chain[1],
        epoch,
        tag: tags[1],
    };
    let at = epoch * umbra_core::directory::EPOCH_SECONDS;
    let max = umbra_core::directory::stat::RECEIPT_QUERY_MAX;
    // REL-180: a query for another relay counts toward no bound, and the
    // relay tells it from a query above the bound.
    let elsewhere = ReceiptQuery {
        relay_id: chain[2],
        ..query
    };
    for _ in 0..max {
        assert_eq!(
            network.relays[1].receipt_answer(&elsewhere, at),
            QueryAnswer::Elsewhere
        );
    }
    for _ in 2..max {
        assert!(network.relays[1]
            .receipt_answer(&query, at)
            .given()
            .is_some());
    }
    assert_eq!(
        network.relays[1].receipt_answer(&query, at),
        QueryAnswer::Above
    );
    assert_eq!(
        network.relays[1].receipt_answer(&elsewhere, at),
        QueryAnswer::Elsewhere
    );
    // Another authority, and the next epoch, have their own bound.
    let other = ReceiptQuery {
        authority_index: 1,
        ..query
    };
    assert!(network.relays[1]
        .receipt_answer(&other, at)
        .given()
        .is_some());
    assert!(network.relays[1]
        .receipt_answer(&query, at + umbra_core::directory::EPOCH_SECONDS)
        .given()
        .is_some());
}

#[test]
fn a_relay_under_load_makes_a_queue_for_a_cross_relay_token_once() {
    use umbra_core::abuse::{
        epoch_number,
        pow::Verifier,
        token::{issue_cross_relay, CrossRelayRequest, TokenChallenge, TYPE_CROSS_RELAY},
    };
    use umbra_crypto::rsabssa::SecretKey2048;
    use umbra_queue::Reject;

    const ALICE: usize = 0;
    let mut network = Network::new();
    network.settle();
    assert_eq!(network.take_events(ALICE), [ClientEvent::CircuitReady]);

    // ABU-048: each relay raises its effort, and holds the key of the
    // cross-relay issuer of this epoch from the log.
    let now = network.now;
    let epoch = epoch_number(now);
    let key = SecretKey2048::from_seed(&Secret::new([0x71; 32]), &epoch.to_be_bytes()).unwrap();
    for relay in &mut network.relays {
        relay.set_issuer_key(epoch, key.public().clone());
        let gate = relay.gate_mut();
        gate.pow = Verifier::new(gate.relay_id, 4);
        gate.pow.issue(0, now, &mut Rng(9)).unwrap();
    }
    let challenge = TokenChallenge {
        token_type: TYPE_CROSS_RELAY,
        epoch,
        redemption_context: [0; 32],
    };
    let (state, blinded) =
        CrossRelayRequest::new(1, &challenge, key.public(), &mut Rng(3)).unwrap();
    let signed = issue_cross_relay(&key, &blinded).unwrap();
    let token = state.finalize(&signed, key.public()).unwrap().remove(0);
    let token = umbra_core::discovery::dirclient::token_bytes(&token).unwrap();

    // The NEW with no credential asks for one, and the NEW with the token
    // makes the queue.
    let invite = network.clients[ALICE].invite(&mut Rng(1)).unwrap();
    network.settle();
    assert_eq!(
        network.take_events(ALICE),
        [ClientEvent::AdmissionAsked { handle: invite }]
    );
    let events = network.clients[ALICE]
        .admit_queue(invite, Some(&token), &mut Rng(2))
        .unwrap();
    assert!(events.is_empty());
    network.settle();
    let events = network.take_events(ALICE);
    let [ClientEvent::Invitation { handle, .. }] = &events[..] else {
        panic!("{events:?}");
    };
    assert_eq!(*handle, invite);

    // ABU-006: the relay spends the token once, and a paid NEW asks no
    // more.
    let again = network.clients[ALICE].invite(&mut Rng(4)).unwrap();
    network.settle();
    assert_eq!(
        network.take_events(ALICE),
        [ClientEvent::AdmissionAsked { handle: again }]
    );
    network.clients[ALICE]
        .admit_queue(again, Some(&token), &mut Rng(5))
        .unwrap();
    network.settle();
    assert_eq!(
        network.take_events(ALICE),
        [ClientEvent::Rejected {
            handle: again,
            reason: Reject::Admission,
        }]
    );

    // A device with no token and no challenge ends the call.
    let third = network.clients[ALICE].invite(&mut Rng(6)).unwrap();
    network.settle();
    assert_eq!(
        network.take_events(ALICE),
        [ClientEvent::AdmissionAsked { handle: third }]
    );
    assert_eq!(
        network.clients[ALICE]
            .admit_queue(third, None, &mut Rng(7))
            .unwrap(),
        [ClientEvent::Rejected {
            handle: third,
            reason: Reject::Admission,
        }]
    );
}

/// The paced circuits of the queue relay.
fn paced(network: &Network) -> BTreeSet<CircuitKey> {
    network.relays[2].paced_circuits().copied().collect()
}

/// The circuits that each relay holds.
fn held(network: &Network) -> [usize; 3] {
    [0, 1, 2].map(|relay| network.relays[relay].circuits_held())
}

/// Binds the first inbound queue of a client, thus a record that no
/// subscription takes gives a push.
fn bind_first_queue(network: &mut Network, client: usize) {
    use umbra_core::notify::binding::Binding;
    use umbra_crypto::kem::PublicKey;
    let (queue, _) = network.clients[client].inbound_queues()[0];
    network.clients[client]
        .notify_queue(&queue, &[6; 32], &mut Rng(5))
        .unwrap();
    network.settle();
    let events = network.take_events(client);
    let [ClientEvent::NotifyKey { relay_ntf_pk, .. }, ClientEvent::NotifierId { .. }] = &events[..]
    else {
        panic!("{events:?}");
    };
    let binding = Binding {
        root: Secret::new([0x41; 32]),
        handle: [0x42; 16],
        k_tok: Secret::new([0x43; 32]),
        queue_alias: [0x44; 16],
        relay_idx: 2,
    };
    let sealed = binding
        .seal(
            &PublicKey::from_bytes(relay_ntf_pk).unwrap(),
            &queue,
            &mut Rng(6),
        )
        .unwrap();
    network.clients[client]
        .bind_queue(&queue, &sealed, &mut Rng(7))
        .unwrap();
    network.settle();
}

fn bodies(events: &[ClientEvent]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|event| match event {
            ClientEvent::Message { app, .. } => Some(
                AppMessage::parse(app, Channel::Pairwise)
                    .unwrap()
                    .body
                    .to_vec(),
            ),
            _ => None,
        })
        .collect()
}

#[test]
fn a_paused_session_resumes_on_a_new_link_and_its_circuits_carry_on() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    let (alice_contact, bob_contact) = contacts(&mut network);
    bind_first_queue(&mut network, ALICE);
    let circuits = held(&network);
    let clocks = paced(&network);
    let first_link = network.links[ALICE];

    // WIR-539, WIR-541: Alice pauses her session, and the guard parks it.
    // Each relay keeps each circuit.
    let parked = network.pause(ALICE);
    assert!(parked.is_clean());
    assert_eq!(network.relays[0].sessions_parked(), 1);
    assert_eq!(held(&network), circuits);
    // WIR-546: the pacing clock of each circuit of Alice stops.
    let stopped: Vec<CircuitKey> = clocks.difference(&paced(&network)).copied().collect();
    assert_eq!(stopped.len(), parked.circuits());
    for circuit in &stopped {
        let now = network.now;
        let outputs = network.relays[2].pacing_tick(circuit, now, &mut Rng(9));
        assert!(outputs.is_empty());
    }

    // WIR-546, NET-322: the subscription of Alice ended with the pause.
    // Thus a record that arrives for her paused circuit takes its push.
    let now = network.now;
    network.clients[BOB]
        .send(
            &bob_contact,
            &text(1, "while she is away"),
            now,
            &mut Rng(8),
        )
        .unwrap();
    network.settle();
    assert_eq!(network.pushes.len(), 1);
    assert_eq!(held(&network), circuits);
    assert_eq!(paced(&network).len(), clocks.len() - stopped.len());

    // WIR-361, WIR-241: the next run resumes on a new connection, which
    // takes the place of the first one. No relay builds a circuit, and the
    // record comes on the circuit that Alice held before.
    assert!(network.resume(ALICE, 0x40, parked));
    assert!(!network.clients[ALICE].is_ready());
    network.settle();
    assert_eq!(network.links[ALICE], first_link);
    assert_eq!(network.relays[0].sessions_parked(), 0);
    assert_eq!(held(&network), circuits);
    assert_eq!(paced(&network), clocks);
    let events = network.take_events(ALICE);
    assert_eq!(events.first(), Some(&ClientEvent::CircuitReady));
    assert!(!events.contains(&ClientEvent::CircuitLost));
    assert_eq!(bodies(&events), [b"while she is away".to_vec()]);

    // A cell flows on the old circuit in each direction after the resume.
    let now = network.now;
    network.clients[ALICE]
        .send(&alice_contact, &text(2, "back again"), now, &mut Rng(10))
        .unwrap();
    network.clients[BOB]
        .send(&bob_contact, &text(3, "welcome"), now, &mut Rng(11))
        .unwrap();
    network.settle();
    assert_eq!(bodies(&network.take_events(BOB)), [b"back again".to_vec()]);
    assert_eq!(bodies(&network.take_events(ALICE)), [b"welcome".to_vec()]);
    assert_eq!(held(&network), circuits);
    // Her subscription takes the record, thus no second push goes.
    assert_eq!(network.pushes.len(), 1);

    // WIR-234, WIR-235: a second pause and a second resume of the session.
    let parked = network.pause(ALICE);
    assert!(network.resume(ALICE, 0x40, parked));
    network.settle();
    assert_eq!(held(&network), circuits);
    assert!(network
        .take_events(ALICE)
        .contains(&ClientEvent::CircuitReady));
}

#[test]
fn a_resume_with_a_lost_frame_closes_and_the_relay_discards_the_session() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    let (alice_contact, bob_contact) = contacts(&mut network);
    let circuits = held(&network);

    // A frame of Alice is lost with her connection: the client counts it,
    // and the relay did not take it.
    let now = network.now;
    network.clients[ALICE]
        .send(&alice_contact, &text(1, "lost"), now, &mut Rng(8))
        .unwrap();
    network.commit(ALICE);
    assert!(!network.clients[ALICE].take_capsules().is_empty());
    let parked = network.clients[ALICE].park(now).unwrap();
    assert!(!parked.is_clean());
    // WIR-542: the link closes with no `SessionClose`, and the guard parks
    // the session with its circuits.
    let link = network.links[ALICE];
    let closed = network.relays[0].link_closed(link, now);
    network.route(0, closed);
    network.peers[0].retain(|(held, _)| *held != link);
    assert_eq!(network.relays[0].sessions_parked(), 1);
    assert_eq!(held(&network), circuits);

    // WIR-544: the two counts of the resume differ from the counts of the
    // relay. The new connection closes with no cause, and the relay ends
    // each circuit of the session at each hop.
    assert!(network.resume(ALICE, 0x40, parked));
    let new_link = network.links[ALICE];
    let capsules = network.clients[ALICE].take_capsules();
    let outputs = network.relays[0].on_capsule(new_link, &capsules[0], now, &mut Rng(9));
    assert!(outputs.contains(&Output::Close { link: new_link }));
    assert!(!outputs
        .iter()
        .any(|output| matches!(output, Output::Adopt { .. })));
    network.route(0, outputs);
    assert_eq!(network.relays[0].sessions_parked(), 0);
    let left = held(&network);
    assert!(left.iter().zip(circuits).all(|(now, before)| *now < before));
    assert_eq!(left[0], left[2]);

    // WIR-547: the client drops the session, and it opens a new one with
    // new circuits. The session of the same identifier opens no more.
    assert!(network.clients[ALICE].is_resuming());
    network.clients[ALICE].resume_failed();
    network.clients[ALICE].connected(&mut Rng(77)).unwrap();
    network.settle();
    assert!(network
        .take_events(ALICE)
        .contains(&ClientEvent::CircuitReady));
    assert_eq!(held(&network), circuits);
    let now = network.now;
    network.clients[BOB]
        .send(&bob_contact, &text(2, "still here"), now, &mut Rng(10))
        .unwrap();
    network.settle();
    assert_eq!(
        bodies(&network.take_events(ALICE)),
        [b"still here".to_vec()]
    );
}

#[test]
fn a_resume_that_does_not_verify_leaves_the_parked_session() {
    const ALICE: usize = 0;
    let mut network = Network::new();
    contacts(&mut network);
    let circuits = held(&network);
    let parked = network.pause(ALICE);

    // WIR-237, WIR-239: a party that knows the session identifier and not
    // the secret closes its own connection alone.
    // The random source of the first run of Alice gives her session
    // identifier again.
    let mut probe = ClientNode::new(
        [relay_static(1).0, relay_static(2).0, relay_static(3).0],
        RootIdentity::new(Secret::new([0x66; 32])),
    );
    probe.connected(&mut Rng(100)).unwrap();
    let open = probe.take_capsules().remove(0);
    let session_id: [u8; 8] = open[7..15].try_into().unwrap();
    let forged =
        umbra_wire::session::SessionControl::resume(&Secret::new([0x99; 32]), session_id, 1, 0, 0);
    let mut record = [0u8; 37];
    forged.encode(&mut record).unwrap();
    let mut capsule = vec![0u8; 43];
    umbra_wire::capsule::encode(
        umbra_wire::capsule::CapsuleType::Session,
        &record,
        &mut capsule,
    )
    .unwrap();
    let now = network.now;
    let outputs = network.relays[0].on_capsule(7_000, &capsule, now, &mut Rng(9));
    assert_eq!(outputs, [Output::Close { link: 7_000 }]);
    assert_eq!(network.relays[0].sessions_parked(), 1);
    assert_eq!(held(&network), circuits);

    // The session still takes the resume of its client.
    assert!(network.resume(ALICE, 0x40, parked));
    network.settle();
    assert_eq!(network.relays[0].sessions_parked(), 0);
    assert!(network
        .take_events(ALICE)
        .contains(&ClientEvent::CircuitReady));
}

#[test]
fn a_parked_session_ends_at_its_window() {
    use umbra_transport::link::RESUME_WINDOW;
    const ALICE: usize = 0;
    let mut network = Network::new();
    contacts(&mut network);
    let circuits = held(&network);
    let parked = network.pause(ALICE);
    let paused_at = network.now;

    // NET-335: a parked link holds no connection, and it is not idle.
    let now = paused_at + 3_600;
    let swept = network.relays[0].sweep(now, &mut Rng(9));
    network.route(0, swept);
    assert_eq!(network.relays[0].sessions_parked(), 1);
    assert_eq!(held(&network), circuits);

    // WIR-244: the window ends, and the relay closes the session as it
    // closes a link: each circuit of it ends at each hop.
    network.now = paused_at + RESUME_WINDOW;
    let now = network.now;
    let swept = network.relays[0].sweep(now, &mut Rng(9));
    network.route(0, swept);
    assert_eq!(network.relays[0].sessions_parked(), 0);
    assert!(held(&network)
        .iter()
        .zip(circuits)
        .all(|(now, before)| *now < before));

    // WIR-245: the client opens a new session after its own window.
    assert!(!network.resume(ALICE, 0x40, parked));
    assert!(!network.clients[ALICE].is_resuming());
}

#[test]
fn a_backward_cell_for_a_parked_link_ends_its_circuit_alone() {
    const ALICE: usize = 0;
    let mut network = Network::new();
    contacts(&mut network);
    // More queues than one circuit serves give Alice a second circuit.
    for n in 0..10u64 {
        network.clients[ALICE].invite(&mut Rng(40 + n)).unwrap();
    }
    network.settle();
    network.settle();
    network.take_events(ALICE);
    let circuits = held(&network);

    // A pause and a resume show which circuits of the queue relay are the
    // circuits of Alice.
    let clocks = paced(&network);
    let parked = network.pause(ALICE);
    let of_alice: Vec<CircuitKey> = clocks.difference(&paced(&network)).copied().collect();
    assert_eq!(of_alice.len(), 2);
    assert!(network.resume(ALICE, 0x40, parked));
    network.settle();
    network.take_events(ALICE);
    assert_eq!(paced(&network), clocks);

    // A cell of one of the two circuits is on its way when the session
    // parks. WIR-543: the guard cannot send it, thus that circuit ends at
    // each hop, and the other circuit stays.
    let now = network.now;
    let late = network.relays[2].pacing_tick(&of_alice[0], now, &mut Rng(9));
    assert!(!late.is_empty());
    let parked = network.pause(ALICE);
    network.route(2, late);
    assert_eq!(network.relays[0].sessions_parked(), 1);
    assert_eq!(held(&network), circuits.map(|count| count - 1));

    // The client learns of the lost circuit after the resume, with a
    // `CircuitDestroy`. The other circuit serves, and the lost one builds
    // again inside the run.
    assert!(network.resume(ALICE, 0x40, parked));
    let new_link = network.links[ALICE];
    let now = network.now;
    let capsules = network.clients[ALICE].take_capsules();
    let outputs = network.relays[0].on_capsule(new_link, &capsules[0], now, &mut Rng(9));
    let destroys = outputs
        .iter()
        .filter(|output| matches!(output, Output::Send { .. }))
        .count();
    assert!(matches!(outputs.first(), Some(Output::Adopt { .. })));
    assert_eq!(destroys, 1);
    network.route(0, outputs);
    let link = network.links[ALICE];
    for capsule in &capsules[1..] {
        let outputs = network.relays[0].on_capsule(link, capsule, now, &mut Rng(9));
        network.route(0, outputs);
    }
    network.step();
    assert_eq!(held(&network), circuits.map(|count| count - 1));
    network.settle();
    let events = network.take_events(ALICE);
    assert!(events.contains(&ClientEvent::CircuitReady));
    assert!(!events.contains(&ClientEvent::CircuitLost));
    assert_eq!(held(&network), circuits);
    assert_eq!(paced(&network).len(), clocks.len());
}

#[test]
fn a_circuit_pause_waits_behind_the_forward_cells_of_its_circuit() {
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    let (alice_contact, _) = contacts(&mut network);
    let clocks = paced(&network);

    // A record of Alice leaves, and her pause follows it at once. Part 3
    // §3.9: each hop holds a forward cell for the delay of its circuit,
    // thus the record waits at the guard.
    let now = network.now;
    network.clients[ALICE]
        .send(&alice_contact, &text(1, "then away"), now, &mut Rng(8))
        .unwrap();
    network.commit(ALICE);
    network.clients[ALICE].pause().unwrap();
    let link = network.links[ALICE];
    for capsule in network.clients[ALICE].take_capsules() {
        let outputs = network.relays[0].on_capsule(link, &capsule, now, &mut Rng(9));
        network.route(0, outputs);
    }
    assert!(network.relays[0].has_delayed());
    // WIR-545: the `CircuitPause` goes behind the record at each hop. The
    // record thus starts no pacing clock after the pause.
    assert_eq!(paced(&network), clocks);
    network.flush_delayed();
    let left = paced(&network).len();
    assert!(left < clocks.len());
    network.settle();
    assert_eq!(bodies(&network.take_events(BOB)), [b"then away".to_vec()]);
    assert_eq!(paced(&network).len(), left);
    assert_eq!(network.relays[0].sessions_parked(), 1);
}

#[test]
fn a_resume_names_a_circuit_whose_end_waits_behind_a_forward_cell() {
    const ALICE: usize = 0;
    let mut network = Network::new();
    let (alice_contact, _) = contacts(&mut network);
    let circuits = held(&network);

    // A pause and a resume show which circuit of the queue relay is the
    // circuit of Alice.
    let clocks = paced(&network);
    let parked = network.pause(ALICE);
    let of_alice: Vec<CircuitKey> = clocks.difference(&paced(&network)).copied().collect();
    assert_eq!(of_alice.len(), 1);
    assert!(network.resume(ALICE, 0x40, parked));
    network.settle();
    network.take_events(ALICE);

    // A cell of the queue relay is on its way. A record of Alice leaves,
    // and her pause follows it at once: the record waits at the guard for
    // its per-hop delay (Part 3 §3.9).
    let now = network.now;
    let late = network.relays[2].pacing_tick(&of_alice[0], now, &mut Rng(9));
    assert!(!late.is_empty());
    network.clients[ALICE]
        .send(&alice_contact, &text(1, "then away"), now, &mut Rng(8))
        .unwrap();
    network.commit(ALICE);
    network.clients[ALICE].pause().unwrap();
    let link = network.links[ALICE];
    for capsule in network.clients[ALICE].take_capsules() {
        let outputs = network.relays[0].on_capsule(link, &capsule, now, &mut Rng(9));
        network.route(0, outputs);
    }
    assert!(network.relays[0].has_delayed());
    // WIR-543: the guard cannot send the cell on the parked link, thus the
    // circuit ends. NET-339: its end waits behind the record.
    network.route(2, late);
    assert_eq!(held(&network), circuits);
    while let Some(capsule) = network.inboxes[ALICE].pop_front() {
        network.clients[ALICE]
            .on_capsule(&capsule, now, &mut Rng(9))
            .unwrap();
    }
    assert!(network.clients[ALICE].is_paused());
    let parked = network.clients[ALICE].park(now).unwrap();
    assert!(network.relays[0].link_closed(link, now).is_empty());
    network.peers[0].retain(|(held, _)| *held != link);

    // The resume comes before that end. The guard names the circuit all
    // the same, before each cell.
    assert!(network.resume(ALICE, 0x40, parked));
    let new_link = network.links[ALICE];
    let capsules = network.clients[ALICE].take_capsules();
    let outputs = network.relays[0].on_capsule(new_link, &capsules[0], now, &mut Rng(9));
    assert!(matches!(outputs.first(), Some(Output::Adopt { .. })));
    let destroys = outputs
        .iter()
        .filter(|output| matches!(output, Output::Send { .. }))
        .count();
    assert_eq!(destroys, 1);
    network.route(0, outputs);
    let link = network.links[ALICE];
    for capsule in &capsules[1..] {
        let outputs = network.relays[0].on_capsule(link, capsule, now, &mut Rng(9));
        network.route(0, outputs);
    }
    // The queue relay did not read the pause of the circuit yet, and one
    // more cell of its clock reaches the client behind the hole. The
    // client holds that circuit no more, thus the cell ends no run.
    let stale = network.relays[2].pacing_tick(&of_alice[0], now, &mut Rng(9));
    network.route(2, stale);
    network.settle();
    let events = network.take_events(ALICE);
    assert!(events.contains(&ClientEvent::CircuitReady));
    assert!(!events.contains(&ClientEvent::CircuitLost), "{events:?}");
    assert_eq!(held(&network), circuits);
}

/// Part 3 `NET-065`: a later retransmission of a record of the user comes
/// after an acknowledgment and before a link-fault report. The runtime
/// holds the record, and it asks the node for the slot of an
/// acknowledgment alone.
#[test]
fn the_slot_of_a_later_retransmission_gives_way_to_an_acknowledgment_alone() {
    use umbra_crypto::seal;
    use umbra_queue::params::RECEIPT_MIN_DELAY;

    const SENDER: usize = 0;
    const CLIENT: usize = 1;
    let mut network = Network::new();
    let (peer_of_sender, _) = contacts(&mut network);
    let authority = network.add_client(0x52);
    network.settle();
    network.clients[authority]
        .make_report_queue(&mut Rng(1))
        .unwrap();
    network.settle();
    let events = network.take_events(authority);
    let Some(ClientEvent::ReportQueue { address, .. }) = events
        .iter()
        .find(|event| matches!(event, ClientEvent::ReportQueue { .. }))
    else {
        panic!("{events:?}");
    };
    let address: [u8; 129] = address.as_slice().try_into().unwrap();
    let report_pk = seal::public_of(&Secret::new([0x5A; 32]));

    // A link-fault report is due at the client, and no acknowledgment.
    let chain = [[0x11; 32], [0x12; 32], [0x13; 32]];
    let now = network.now;
    let faults = network.clients[CLIENT].faults_mut();
    faults.forced_replacement(&chain, now);
    faults.forced_replacement(&chain, now);
    network.clients[CLIENT].set_report_queues(vec![(address, report_pk)]);
    // The acknowledgments of the handshake go first.
    while network.clients[CLIENT]
        .on_ack_slot(now, &mut Rng(2))
        .unwrap()
    {}
    network.settle();
    // The slot is free for the retransmission: the report waits behind it,
    // and the call sends no cell.
    let now = network.now;
    let taken = network.clients[CLIENT].on_ack_slot(now, &mut Rng(2));
    assert!(!taken.unwrap());
    assert!(network.clients[CLIENT].take_capsules().is_empty());

    // A record arrives, and its acknowledgment is due after the floor of
    // `NET-050`. That acknowledgment takes the slot before the record.
    network.clients[SENDER]
        .send(&peer_of_sender, &text(1, "a record"), now, &mut Rng(3))
        .unwrap();
    network.settle();
    let got = network.take_events(CLIENT);
    assert!(got
        .iter()
        .any(|event| matches!(event, ClientEvent::Message { .. })));
    let now = network.now;
    let taken = network.clients[CLIENT].on_ack_slot(now, &mut Rng(4));
    assert!(!taken.unwrap());
    let due = now + RECEIPT_MIN_DELAY;
    let taken = network.clients[CLIENT].on_ack_slot(due, &mut Rng(5));
    assert!(taken.unwrap());
    let taken = network.clients[CLIENT].on_ack_slot(due, &mut Rng(6));
    assert!(!taken.unwrap());
    // The report is still due, and a slot with no retransmission has it.
    let slot = network.clients[CLIENT]
        .on_cover_slot(true, None, None, due, &mut Rng(7))
        .unwrap();
    assert_eq!(slot, CoverSlot::Report);
}

/// One turn of the network with the tick of one client, as its runtime
/// gives it: the build timeouts, and the spare of each circuit near a
/// margin. The result is each event of the tick.
fn step_with_tick(network: &mut Network, client: usize) -> Vec<ClientEvent> {
    let now = network.now;
    let events = network.clients[client].on_tick(now);
    network.clients[client]
        .replace_aging(now, &mut Rng(now))
        .unwrap();
    network.step();
    events
}

/// Part 3 §3.4.3, `NET-320`: a spare takes the place of a circuit before
/// its age margin. The run goes on, each queue moves to the new circuit
/// with no time with no subscription, and no record is lost or doubled.
#[test]
fn a_spare_takes_the_place_of_a_circuit_near_its_age_and_the_run_goes_on() {
    use umbra_core::session::node::{CIRCUIT_AGE_MARGIN, CIRCUIT_RETIRE_WAIT, CIRCUIT_SPARE_LEAD};
    use umbra_onion::CIRCUIT_MAX_AGE;
    const ALICE: usize = 0;
    const BOB: usize = 1;
    let mut network = Network::new();
    let (_, alice_at_bob) = contacts(&mut network);
    // A record that no subscription takes gives a push, thus a queue with
    // no subscription shows.
    bind_first_queue(&mut network, ALICE);
    let start = network.now;
    assert!(network.clients[ALICE].on_tick(start).is_empty());

    // Alice holds one record with no `ACK` yet: no slot of the cover
    // clock came. The relay holds it for the next subscription.
    network.clients[BOB]
        .send(&alice_at_bob, &text(1, "before"), start, &mut Rng(8))
        .unwrap();
    network.settle();
    assert_eq!(bodies(&network.take_events(ALICE)), [b"before".to_vec()]);
    let served = held(&network);
    let exits = paced(&network);

    // One second before the lead no spare builds.
    let margin = start + CIRCUIT_MAX_AGE - CIRCUIT_AGE_MARGIN;
    network.now = margin - CIRCUIT_SPARE_LEAD - 1;
    assert!(step_with_tick(&mut network, ALICE).is_empty());
    assert_eq!(held(&network), served);

    // At the lead the spare of each circuit of Alice builds, and it takes
    // the place of its circuit. No event ends the run.
    let mut events = Vec::new();
    for _ in 0..24 {
        events.extend(step_with_tick(&mut network, ALICE));
    }
    assert!(events.is_empty(), "{events:?}");
    assert!(held(&network)[2] > served[2]);
    assert_ne!(paced(&network), exits);
    // WIR-110: the relay sent the record with no `ACK` again on the new
    // circuit. Its `seq` is the one that Alice holds, and no second record
    // comes of it.
    assert!(bodies(&network.take_events(ALICE)).is_empty());

    // The old circuit still stands, and the queue reads on the new one: a
    // record arrives one time, and no push leaves.
    let now = network.now;
    network.clients[BOB]
        .send(&alice_at_bob, &text(2, "between"), now, &mut Rng(9))
        .unwrap();
    for _ in 0..12 {
        events.extend(step_with_tick(&mut network, ALICE));
    }
    assert_eq!(bodies(&network.take_events(ALICE)), [b"between".to_vec()]);
    assert!(network.pushes.is_empty());

    // The old circuit ends with its `DESTROY` after the wait, and the
    // exit holds the count of before. The end of it ends no subscription.
    network.now += CIRCUIT_RETIRE_WAIT;
    for _ in 0..12 {
        events.extend(step_with_tick(&mut network, ALICE));
    }
    assert_eq!(held(&network)[2], served[2]);
    let now = network.now;
    network.clients[BOB]
        .send(&alice_at_bob, &text(3, "after"), now, &mut Rng(10))
        .unwrap();
    for _ in 0..12 {
        events.extend(step_with_tick(&mut network, ALICE));
    }
    assert_eq!(bodies(&network.take_events(ALICE)), [b"after".to_vec()]);
    assert!(network.pushes.is_empty());

    // NET-320: the margin of the first circuits passes, and no circuit of
    // Alice is that old. The run did not end.
    network.now = margin + 1;
    events.extend(step_with_tick(&mut network, ALICE));
    assert!(events.is_empty(), "{events:?}");
    // The acknowledgment of the three records leaves on the new circuit.
    let due = network.now + RECEIPT_MIN_DELAY;
    assert!(network.clients[ALICE]
        .on_ack_slot(due, &mut Rng(11))
        .unwrap());
}

/// Part 3 `NET-099`: a push-wake session builds no spare circuit. Its
/// circuit ends the run at the margin, as `NET-320` requires.
#[test]
fn a_push_wake_session_builds_no_spare_circuit() {
    use umbra_core::session::node::{CIRCUIT_AGE_MARGIN, CIRCUIT_SPARE_LEAD};
    use umbra_onion::CIRCUIT_MAX_AGE;
    let mut network = Network::new();
    network.settle();
    network.take_events(0);
    let start = network.now;
    assert!(network.clients[0].on_tick(start).is_empty());
    let served = held(&network);
    network.clients[0].set_wake(true);
    let margin = start + CIRCUIT_MAX_AGE - CIRCUIT_AGE_MARGIN;
    network.now = margin - CIRCUIT_SPARE_LEAD;
    for _ in 0..12 {
        assert!(step_with_tick(&mut network, 0).is_empty());
    }
    assert_eq!(held(&network), served);
    network.now = margin;
    assert_eq!(step_with_tick(&mut network, 0), [ClientEvent::CircuitAged]);
}

/// Part 3 `NET-321`: a spare takes the place of a circuit before its cell
/// margin. The pacing of the exit counts one cell each step toward the
/// client, and no circuit of the client reaches the margin.
#[test]
fn a_spare_takes_the_place_of_a_circuit_near_its_cells() {
    use umbra_onion::CIRCUIT_MAX_CELLS;
    let mut network = Network::new();
    let (_, alice_at_bob) = contacts(&mut network);
    let now = network.now;
    network.clients[0]
        .on_cover_slot(true, None, None, now, &mut Rng(5))
        .unwrap();
    // The two clients tick, thus the circuits of each one take a spare.
    let tick = |network: &mut Network| {
        let now = network.now;
        let events = network.clients[1].on_tick(now);
        assert!(events.is_empty(), "{events:?}");
        network.clients[1]
            .replace_aging(now, &mut Rng(now + 1))
            .unwrap();
        let events = step_with_tick(network, 0);
        assert!(events.is_empty(), "{events:?}");
    };
    for _ in 0..CIRCUIT_MAX_CELLS + 700 {
        tick(&mut network);
    }
    for client in [0, 1] {
        let events = network.take_events(client);
        assert!(!events.contains(&ClientEvent::CircuitLost), "{events:?}");
    }
    let now = network.now;
    network.clients[1]
        .send(&alice_at_bob, &text(4, "still here"), now, &mut Rng(6))
        .unwrap();
    for _ in 0..12 {
        tick(&mut network);
    }
    assert_eq!(bodies(&network.take_events(0)), [b"still here".to_vec()]);
}
