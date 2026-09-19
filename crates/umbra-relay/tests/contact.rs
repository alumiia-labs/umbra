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

use umbra_core::session::node::{ClientEvent, ClientNode, ContactId, StateChange};
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
    peers: Vec<Vec<(LinkId, Peer)>>,
    clients: Vec<ClientNode>,
    /// The link of each client at the guard. A restart takes a new one.
    links: Vec<LinkId>,
    stored: Vec<Stored>,
    inboxes: Vec<VecDeque<Vec<u8>>>,
    events: Vec<Vec<ClientEvent>>,
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
    fn new() -> Self {
        let mut relays = Vec::new();
        for layer in 1..=3u8 {
            let (relay, static_secret) = relay_static(layer);
            relays.push(RelayNode::new(Config {
                relay,
                static_secret,
                layer,
                issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
                community_capacity: 1 << 20,
            }));
        }
        let clients = (0..2u8)
            .map(|index| {
                let path = [relay_static(1).0, relay_static(2).0, relay_static(3).0];
                ClientNode::new(path, RootIdentity::new(Secret::new([0x40 + index; 32])))
            })
            .collect();
        let mut network = Network {
            relays,
            peers: vec![Vec::new(), Vec::new(), Vec::new()],
            clients,
            links: vec![1, 2],
            stored: vec![Stored::default(), Stored::default()],
            inboxes: vec![VecDeque::new(), VecDeque::new()],
            events: vec![Vec::new(), Vec::new()],
            rng: Rng(7),
            now: 1_000,
        };
        for from in 0..2usize {
            network.peers[from].push((900, Peer::Relay(from + 1, 800)));
            network.peers[from + 1].push((800, Peer::Relay(from, 900)));
            let next_id = relay_static(from as u8 + 2).0.relay_id;
            let outputs =
                network.relays[from].dialed(900, next_id, [from as u8; 8], Secret::new([9; 32]));
            network.route(from, outputs);
        }
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
    let now = network.now;
    network.clients[ALICE]
        .acknowledge(&alice_contact, now, &mut Rng(4))
        .unwrap();

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
    network.clients[ALICE]
        .acknowledge(&alice_contact, network.now, &mut Rng(4))
        .unwrap();
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
