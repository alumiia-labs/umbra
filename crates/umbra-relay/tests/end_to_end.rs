//! Two clients and three relays in one process. Each client builds a
//! circuit hop by hop through the real link framing, makes a queue, and
//! one record travels from one client to the other.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use umbra_core::session::{
    batch::Range,
    channel::{Inbound, Outbound, PairwiseChannel, Received},
    circuit::{CircuitSession, Event},
};
use umbra_crypto::{
    auth::CommandAuthKey,
    handshake::{
        nk::RelayStatic,
        xk::{InitialDh, SessionKeys},
    },
    rand_core::{TryCryptoRng, TryRng},
    ratchet::{braid::Ratchet, codeword::Width, dr::Role},
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_onion::CIRCUIT_BUILD_TIMEOUT;
use umbra_onion::{
    build::{build_cell_body, read_cell_body, DelayClass, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::{Circuit, CircuitBuild},
};
use umbra_queue::params::{DRAIN_THRESHOLD, QUEUE_QUOTA};
use umbra_relay::{
    circuits::{CircuitKey, LinkId, LINK_BUILD_BURST},
    node::{Backlog, Config, Output, RelayNode, LINK_IDLE_TIMEOUT, LINK_OPEN_TIMEOUT},
    service::DRAINS_PER_MINUTE,
};
use umbra_transport::link::ClientLink;
use umbra_wire::{
    address::QueueAddress,
    admission::{Admission, AdmissionKind},
    bucket::Bucket,
    capsule,
    cell::{pad_body, Cell, CellCommand},
    command::{Cmd, Command, IdsPayload, NewPayload},
    queue::L6Kind,
    session::SessionControl,
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

/// Who sits at the far end of a link of one relay.
#[derive(Clone, Copy)]
enum Peer {
    Client(usize),
    Relay(usize, LinkId),
}

struct Network {
    relays: Vec<RelayNode>,
    statics: Vec<RelayStatic>,
    /// The peer of each link, by relay and link.
    peers: Vec<Vec<(LinkId, Peer)>>,
    /// The capsules that wait at each client.
    inboxes: Vec<VecDeque<Vec<u8>>>,
    rng: Rng,
}

impl Network {
    fn new() -> Self {
        let mut network = Network::unlinked();
        // Relay 1 dials relay 2, and relay 2 dials relay 3.
        for from in 0..2usize {
            network.dial(from);
        }
        network
    }

    /// The three relays with no link between them. Each one dials the next
    /// one at the first `EXTEND` that needs it, as a relay does after its
    /// start.
    fn unlinked() -> Self {
        let mut relays = Vec::new();
        let mut statics = Vec::new();
        for layer in 1..=3u8 {
            let static_secret = StaticSecret::from([layer; 32]);
            let relay = RelayStatic {
                s: *XPublic::from(&static_secret).as_bytes(),
                relay_id: [0x10 + layer; 32],
            };
            statics.push(RelayStatic { ..relay });
            relays.push(RelayNode::new(Config {
                relay,
                static_secret,
                layer,
                chunk_capacity: 1 << 26,
            }));
        }
        Network {
            relays,
            statics,
            peers: vec![Vec::new(), Vec::new(), Vec::new()],
            inboxes: vec![VecDeque::new(), VecDeque::new()],
            rng: Rng(7),
        }
    }

    /// Relay `from` dials the relay of the next layer.
    fn dial(&mut self, from: usize) {
        let link: LinkId = 900;
        self.peers[from].push((link, Peer::Relay(from + 1, 800)));
        self.peers[from + 1].push((800, Peer::Relay(from, link)));
        let next_id = self.statics[from + 1].relay_id;
        let outputs = self.relays[from].dialed(
            link,
            next_id,
            [from as u8; 8],
            Secret::new([9; 32]),
            100,
            &mut self.rng,
        );
        self.route(from, outputs);
    }

    fn route(&mut self, relay: usize, outputs: Vec<Output>) {
        let mut work: VecDeque<(usize, Output)> = outputs.into_iter().map(|o| (relay, o)).collect();
        while let Some((at, output)) = work.pop_front() {
            let (link, capsule) = match output {
                Output::Send { link, capsule } => (link, capsule),
                // The dial ends after the relay took the cell that asked
                // for it, as a socket does.
                Output::Dial { relay_id } => {
                    assert_eq!(relay_id, self.statics[at + 1].relay_id);
                    self.dial(at);
                    continue;
                }
                other => panic!("an unexpected output: {other:?}"),
            };
            let peer = self.peers[at].iter().find(|(l, _)| *l == link).unwrap().1;
            match peer {
                Peer::Client(client) => self.inboxes[client].push_back(capsule),
                Peer::Relay(next, next_link) => {
                    let outputs =
                        self.relays[next].on_capsule(next_link, &capsule, 100, &mut self.rng);
                    work.extend(outputs.into_iter().map(|o| (next, o)));
                }
            }
        }
    }

    fn client_sends(&mut self, client: usize, capsule: &[u8]) {
        let link = client as LinkId + 1;
        let outputs = self.relays[0].on_capsule(link, capsule, 100, &mut self.rng);
        self.route(0, outputs);
    }

    /// One pacing tick of each circuit that ends at relay 3.
    fn tick(&mut self) {
        let circuits: Vec<_> = self.relays[2].paced_circuits().copied().collect();
        for circuit in circuits {
            let outputs = self.relays[2].pacing_tick(&circuit, 100, &mut self.rng);
            self.route(2, outputs);
        }
        let outputs = self.relays[2].drain_tick(100, &mut self.rng);
        self.route(2, outputs);
    }
}

struct Client {
    index: usize,
    link: ClientLink,
    session: CircuitSession,
}

impl Client {
    /// Opens the link, and builds the three hops.
    fn connect(network: &mut Network, index: usize) -> Self {
        let (link, circuit, relay_session_pk) = Client::build(network, index);
        Client {
            index,
            link,
            session: CircuitSession::new(circuit, relay_session_pk, Range::Queue),
        }
    }

    /// Opens the link, and builds the three hops: the link, the circuit,
    /// and the session key of the queue relay.
    fn build(network: &mut Network, index: usize) -> (ClientLink, Circuit, [u8; 32]) {
        network.peers[0].push((index as LinkId + 1, Peer::Client(index)));
        let mut buffer = vec![0u8; 40_000];
        let (mut link, used) = ClientLink::open(
            [0xC0 + index as u8; 8],
            Secret::new([index as u8; 32]),
            &mut buffer,
        )
        .unwrap();
        network.client_sends(index, &buffer[..used]);

        let mut rng = Rng(100 + index as u64);
        let mut build = CircuitBuild::new([0xA0 + index as u8; 16]);
        let mut relay_session_pk = [0u8; 32];
        for hop in 0..3usize {
            let relay = network.statics[hop].clone_static();
            let mut hello = [0u8; HELLO_LEN];
            let pending = Pending::hello(&relay, DelayClass::Fast, &mut rng, &mut hello).unwrap();
            let mut body = vec![0u8; BUILD_BUCKET.body_len()];
            build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();
            let tag = build.seal(&mut body).unwrap();
            let cell = [build.circ_id().as_slice(), &tag, &body].concat();
            let used = link.send(&cell, &mut buffer).unwrap();
            network.client_sends(index, &buffer[..used]);

            let capsule_bytes = network.inboxes[index]
                .pop_front()
                .expect("an EXTENDED cell");
            let (_, value, _) = capsule::parse(&capsule_bytes).unwrap();
            let cell = link.receive(value).unwrap().unwrap().to_vec();
            let (parsed, _) = Cell::parse(&cell).unwrap();
            let mut body = parsed.body.to_vec();
            build.open(parsed.tag, &mut body).unwrap();
            let (command, reply) = read_cell_body(&body).unwrap();
            assert_eq!(command, CellCommand::Extended);
            let ss_hop = if hop == 2 {
                let (ss_hop, er) = pending.finish_at_queue_relay(reply).unwrap();
                relay_session_pk = er;
                ss_hop
            } else {
                pending.finish(reply).unwrap()
            };
            build.push(&ss_hop).unwrap();
        }
        (link, build.finish().unwrap(), relay_session_pk)
    }

    fn flush(&mut self, network: &mut Network) {
        let mut buffer = vec![0u8; 40_000];
        while let Some(cell) = self.session.next_cell().unwrap() {
            let used = self.link.send(&cell, &mut buffer).unwrap();
            network.client_sends(self.index, &buffer[..used]);
        }
    }

    /// Takes each cell that waits, and returns the events without the
    /// cover cells.
    fn drain(&mut self, network: &mut Network) -> Vec<Event> {
        let mut events = Vec::new();
        while let Some(capsule_bytes) = network.inboxes[self.index].pop_front() {
            let (_, value, _) = capsule::parse(&capsule_bytes).unwrap();
            let cell = self.link.receive(value).unwrap().unwrap().to_vec();
            events.extend(self.session.receive_cell(&cell).unwrap());
        }
        events
    }

    /// Makes a queue at relay 3, and returns its reader side with the
    /// address that a peer writes to.
    fn new_queue(&mut self, network: &mut Network, tag: u8) -> (Inbound, QueueAddress) {
        let qr = StaticSecret::from([tag; 32]);
        let qs_bytes = [tag + 1; 32];
        let queue_secret = Secret::new([tag + 2; 32]);
        let new = NewPayload {
            qr_auth_pk: *XPublic::from(&qr).as_bytes(),
            qs_auth_pk: *XPublic::from(&StaticSecret::from(qs_bytes)).as_bytes(),
            admission: Admission {
                kind: AdmissionKind::None,
                body: &[],
            },
        };
        let mut payload = [0u8; 67];
        new.encode(&mut payload).unwrap();
        let mut command = Command {
            cmd: Cmd::New,
            corr_id: [tag; 16],
            queue_id: [0; 32],
            auth: [0; 32],
            payload: &payload,
        };
        let key = CommandAuthKey::derive(&qr, self.session.relay_session_pk()).unwrap();
        command.sign(&key, b"").unwrap();
        let mut encoded = vec![0u8; command.len()];
        command.encode(&mut encoded).unwrap();
        self.session.queue(encoded, 1).unwrap();
        self.flush(network);
        network.tick();
        let events = self.drain(network);
        let [Event::Answered {
            handle: 1,
            cmd: Cmd::Ids,
            payload,
        }] = &events[..]
        else {
            panic!("{events:?}");
        };
        let ids = IdsPayload::parse(payload).unwrap();
        // NET-288: the IDS names the session key of this circuit.
        assert_eq!(&ids.relay_session_pk, self.session.relay_session_pk());
        let address = QueueAddress {
            relay_id: [0x13; 32],
            sender_id: ids.sender_id,
            qs_auth_sk: Secret::new(qs_bytes),
            qe: Secret::new(*queue_secret.expose()),
        };
        let inbound = Inbound::new(ids.recipient_id, ids.sender_id, qr, &queue_secret, 0);
        (inbound, address)
    }
}

trait CloneStatic {
    fn clone_static(&self) -> RelayStatic;
}

impl CloneStatic for RelayStatic {
    fn clone_static(&self) -> RelayStatic {
        RelayStatic {
            s: self.s,
            relay_id: self.relay_id,
        }
    }
}

fn ratchets() -> (Ratchet, Ratchet) {
    let mut rng = Rng(11);
    let er_sk = StaticSecret::from([21; 32]);
    let er = *XPublic::from(&er_sk).as_bytes();
    let keys = |dh| SessionKeys {
        rk: Secret::new([1; 32]),
        hk_i2r: Secret::new([2; 32]),
        hk_r2i: Secret::new([3; 32]),
        transcript: [0; 32],
        dh_initial: dh,
    };
    (
        Ratchet::new(
            keys(InitialDh::Peer(er)),
            Role::Initiator,
            Width::W64,
            0,
            &mut rng,
        )
        .unwrap(),
        Ratchet::new(
            keys(InitialDh::Own(er_sk)),
            Role::Responder,
            Width::W64,
            0,
            &mut rng,
        )
        .unwrap(),
    )
}

#[test]
fn a_record_travels_between_two_clients_over_three_relays() {
    let mut network = Network::new();
    let mut alice = Client::connect(&mut network, 0);
    let mut bob = Client::connect(&mut network, 1);

    let (alice_in, to_alice) = alice.new_queue(&mut network, 40);
    let (bob_in, to_bob) = bob.new_queue(&mut network, 60);
    let (alice_ratchet, bob_ratchet) = ratchets();
    let mut alice_channel = PairwiseChannel::new(alice_ratchet, Outbound::new(&to_bob), alice_in);
    let mut bob_channel = PairwiseChannel::new(bob_ratchet, Outbound::new(&to_alice), bob_in);
    let mut rng = Rng(5);

    // Bob subscribes. A tick with nothing to deliver gives a cover cell.
    let sub = bob_channel
        .subscribe(bob.session.relay_session_pk(), [1; 16])
        .unwrap();
    bob.session.queue(sub, 2).unwrap();
    bob.flush(&mut network);
    network.tick();
    assert_eq!(network.inboxes[1].len(), 1, "a cover cell on the tick");
    assert!(bob.drain(&mut network).is_empty());
    // The clock of each circuit runs, thus Alice took cover cells too.
    assert!(!network.inboxes[0].is_empty());
    assert!(alice.drain(&mut network).is_empty());

    // Alice sends, and the relay acknowledges with a QUOTA on her tick.
    let app = b"hello over three hops";
    let (_, send) = alice_channel
        .send(
            app,
            alice.session.relay_session_pk(),
            [2; 16],
            [3; 12],
            100,
            &mut rng,
        )
        .unwrap();
    alice.session.queue(send, 3).unwrap();
    alice.flush(&mut network);
    assert!(
        network.inboxes[0].is_empty() && network.inboxes[1].is_empty(),
        "nothing moves before a tick"
    );
    network.tick();
    let events = alice.drain(&mut network);
    assert!(
        matches!(
            events[..],
            [Event::Answered {
                handle: 3,
                cmd: Cmd::Quota,
                ..
            }]
        ),
        "{events:?}"
    );

    // The same tick pushed the MSG to Bob.
    let events = bob.drain(&mut network);
    let [Event::Message {
        queue_id,
        bucket,
        payload,
    }] = &events[..]
    else {
        panic!("{events:?}");
    };
    assert_eq!(queue_id, bob_channel.inbound().recipient_id());
    assert_eq!(*bucket, Bucket::B0);
    let received = bob_channel
        .receive(payload, *bucket, 110, &mut rng)
        .unwrap();
    assert_eq!(
        received,
        Received::App {
            seq: 1,
            bytes: app.to_vec()
        }
    );

    // Bob acknowledges, and a second subscription finds nothing to push.
    let (point, ack) = bob_channel
        .acknowledge(
            bob.session.relay_session_pk(),
            [4; 16],
            111 + umbra_queue::params::RECEIPT_MIN_DELAY,
        )
        .unwrap()
        .unwrap();
    bob.session.queue(ack, 4).unwrap();
    bob_channel.acknowledged(point);
    let again = bob_channel
        .subscribe(bob.session.relay_session_pk(), [5; 16])
        .unwrap();
    bob.session.queue(again, 5).unwrap();
    bob.flush(&mut network);
    network.tick();
    assert!(bob.drain(&mut network).is_empty());

    // A command under a wrong key gets a NACK with one reason.
    let forged = PairwiseChannel::new(
        ratchets().0,
        Outbound::new(&QueueAddress {
            relay_id: [0x13; 32],
            sender_id: to_bob.sender_id,
            qs_auth_sk: Secret::new([0xEE; 32]),
            qe: Secret::new([0; 32]),
        }),
        Inbound::new(
            [0; 32],
            [0; 32],
            StaticSecret::from([1; 32]),
            &Secret::new([0; 32]),
            0,
        ),
    );
    let mut forged = forged;
    let (_, send) = forged
        .send(
            b"forged",
            alice.session.relay_session_pk(),
            [6; 16],
            [3; 12],
            120,
            &mut rng,
        )
        .unwrap();
    alice.session.queue(send, 6).unwrap();
    alice.flush(&mut network);
    network.tick();
    let events = alice.drain(&mut network);
    assert!(
        matches!(
            events[..],
            [Event::Rejected {
                handle: 6,
                reason: umbra_queue::Reject::Rejected
            }]
        ),
        "{events:?}"
    );
}

#[test]
fn a_circuit_of_three_hops_opens_no_measurement_session() {
    let mut network = Network::new();
    let (mut link, mut circuit, relay_session_pk) = Client::build(&mut network, 0);
    // Part 10 §10.3.1: a measurement circuit has one hop. A `MEAS_OPEN`
    // and a `MEAS_ECHO` that pass three hops end at relay 3, which drops
    // each one (`REL-068`). A close of a link would stop the route of this
    // network.
    let mut buffer = vec![0u8; 40_000];
    for (command, bucket) in [
        (CellCommand::MeasOpen, Bucket::B3),
        (CellCommand::MeasEcho, Bucket::B0),
    ] {
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, command, &[0x5A; 64], &mut body).unwrap();
        let tag = circuit.seal(&mut body).unwrap();
        let cell = [circuit.circ_id().as_slice(), &tag, &body].concat();
        let used = link.send(&cell, &mut buffer).unwrap();
        network.client_sends(0, &buffer[..used]);
        assert!(network.inboxes[0].is_empty());
    }
    // The relay opened no measurement session: the pacing clock gives
    // cover alone, and the circuit serves its client as before.
    let mut client = Client {
        index: 0,
        link,
        session: CircuitSession::new(circuit, relay_session_pk, Range::Queue),
    };
    network.tick();
    assert!(client.drain(&mut network).is_empty());
    client.new_queue(&mut network, 40);
}

#[test]
fn a_relay_holds_an_extend_while_it_dials_the_next_relay() {
    // NET-319: before this rule the relay dropped the body, and the client
    // waited for an `EXTENDED` that never came.
    let mut network = Network::unlinked();
    let mut client = Client::connect(&mut network, 0);
    // The circuit holds three hops and carries a command.
    let (_, _) = client.new_queue(&mut network, 0x40);
}

#[test]
fn a_relay_drops_an_extend_to_a_relay_outside_the_next_layer() {
    // NET-167: relay 1 knows another next layer, thus the EXTEND to relay 2
    // draws no dial, and no EXTENDED comes back.
    let mut network = Network::unlinked();
    network.relays[0].set_next_layer([[0x77; 32]].into_iter().collect());
    network.peers[0].push((1, Peer::Client(0)));
    let mut buffer = vec![0u8; 40_000];
    let (mut link, used) = ClientLink::open([0xC0; 8], Secret::new([0; 32]), &mut buffer).unwrap();
    network.client_sends(0, &buffer[..used]);
    let mut rng = Rng(100);
    let mut build = CircuitBuild::new([0xA0; 16]);
    for hop in 0..2usize {
        let relay = network.statics[hop].clone_static();
        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(&relay, DelayClass::Fast, &mut rng, &mut hello).unwrap();
        let mut body = vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();
        let tag = build.seal(&mut body).unwrap();
        let cell = [build.circ_id().as_slice(), &tag, &body].concat();
        let used = link.send(&cell, &mut buffer).unwrap();
        network.client_sends(0, &buffer[..used]);
        let Some(capsule_bytes) = network.inboxes[0].pop_front() else {
            assert_eq!(hop, 1);
            return;
        };
        let (_, value, _) = capsule::parse(&capsule_bytes).unwrap();
        let cell = link.receive(value).unwrap().unwrap().to_vec();
        let (parsed, _) = Cell::parse(&cell).unwrap();
        let mut body = parsed.body.to_vec();
        build.open(parsed.tag, &mut body).unwrap();
        let (command, reply) = read_cell_body(&body).unwrap();
        assert_eq!(command, CellCommand::Extended);
        build.push(&pending.finish(reply).unwrap()).unwrap();
    }
    panic!("relay 1 took the EXTEND to relay 2");
}

/// One relay of `layer` with the static key of the seed `layer`, as the
/// relays of [`Network`] have.
fn lone_relay(layer: u8) -> (RelayNode, RelayStatic) {
    let static_secret = StaticSecret::from([layer; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&static_secret).as_bytes(),
        relay_id: [0x10 + layer; 32],
    };
    let held = relay.clone_static();
    let node = RelayNode::new(Config {
        relay,
        static_secret,
        layer,
        chunk_capacity: 0,
    });
    (node, held)
}

/// A client link to one relay with no network around it.
struct Direct {
    at: LinkId,
    link: ClientLink,
    rng: Rng,
}

impl Direct {
    /// Opens a session on the link `at` of `node`.
    fn open(node: &mut RelayNode, at: LinkId, now: u64) -> Self {
        let mut buffer = vec![0u8; 64];
        let (link, used) =
            ClientLink::open([at as u8; 8], Secret::new([at as u8; 32]), &mut buffer).unwrap();
        assert!(node
            .on_capsule(at, &buffer[..used], now, &mut Rng(at))
            .is_empty());
        Direct {
            at,
            link,
            rng: Rng(200 + at),
        }
    }

    /// Sends the `EXTEND` of the next hop of `build` for `relay`.
    fn extend(
        &mut self,
        node: &mut RelayNode,
        build: &mut CircuitBuild,
        relay: &RelayStatic,
        now: u64,
    ) -> (Vec<Output>, Pending) {
        let mut hello = [0u8; HELLO_LEN];
        let pending = Pending::hello(relay, DelayClass::Fast, &mut self.rng, &mut hello).unwrap();
        let mut body = vec![0u8; BUILD_BUCKET.body_len()];
        build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();
        let tag = build.seal(&mut body).unwrap();
        let cell = [build.circ_id().as_slice(), &tag, &body].concat();
        let mut buffer = vec![0u8; 40_000];
        let used = self.link.send(&cell, &mut buffer).unwrap();
        let outputs = node.on_capsule(self.at, &buffer[..used], now, &mut self.rng);
        (outputs, pending)
    }

    /// Builds the first hop of a new circuit at `node`, and tells whether
    /// the relay answered.
    fn first_hop(
        &mut self,
        node: &mut RelayNode,
        relay: &RelayStatic,
        circ: u8,
        now: u64,
    ) -> Option<CircuitBuild> {
        let mut build = CircuitBuild::new([circ; 16]);
        let (outputs, pending) = self.extend(node, &mut build, relay, now);
        // The answer is the cell among the capsules for this link: a relay
        // at its count of circuits tells of an ended circuit first.
        let value = outputs.iter().find_map(|output| match output {
            Output::Send { link, capsule } if *link == self.at => {
                match capsule::parse(capsule).unwrap() {
                    (capsule::CapsuleType::Cell, value, _) => Some(value),
                    _ => None,
                }
            }
            _ => None,
        })?;
        let cell = self.link.receive(value).unwrap().unwrap().to_vec();
        let (parsed, _) = Cell::parse(&cell).unwrap();
        let mut body = parsed.body.to_vec();
        build.open(parsed.tag, &mut body).unwrap();
        let (command, reply) = read_cell_body(&body).unwrap();
        assert_eq!(command, CellCommand::Extended);
        build.push(&pending.finish(reply).unwrap()).unwrap();
        Some(build)
    }
}

fn dials(outputs: &[Output]) -> usize {
    outputs
        .iter()
        .filter(|output| matches!(output, Output::Dial { .. }))
        .count()
}

fn closes(outputs: &[Output], at: LinkId) -> bool {
    outputs
        .iter()
        .any(|output| matches!(output, Output::Close { link } if *link == at))
}

fn identity(seed: u8) -> umbra_crypto::sign::SigningKey {
    umbra_crypto::sign::SigningKey::from_seed(Secret::new([seed; 32]))
}

#[test]
fn a_relay_of_layer_2_takes_a_build_from_a_relay_of_the_layer_before_alone() {
    // NET-332: relay 2 holds a relay set, and relay 1 names itself with its
    // hello at the dial. The circuit of a client of relay 1 builds.
    let mut network = Network::unlinked();
    let key = identity(0x51);
    let relay_1 = network.statics[0].relay_id;
    let set: BTreeMap<[u8; 32], Vec<u8>> =
        [(relay_1, key.verifying_key().to_bytes().to_vec())].into();
    network.relays[0].set_challenge_signer(key, Vec::new());
    network.relays[1].set_relay_identities(set.clone());
    network.relays[1].set_previous_layer([relay_1].into());
    let _client = Client::connect(&mut network, 0);
    assert_eq!(network.relays[1].circuits_held(), 1);

    // A host that is no relay dials relay 2 itself: the address and the
    // static key are public. Its session opens, and its build cell gets no
    // answer and costs no key agreement.
    let relay_2 = network.statics[1].clone_static();
    let mut host = Direct::open(&mut network.relays[1], 77, 100);
    assert!(host
        .first_hop(&mut network.relays[1], &relay_2, 0xB0, 100)
        .is_none());
    assert_eq!(network.relays[1].circuits_held(), 1);
    // NET-335: a link that named no relay of the layer before gives its
    // place back, and the link of relay 1 stays.
    let outputs = network.relays[1].push_tick(100 + LINK_OPEN_TIMEOUT, &mut Rng(3));
    assert!(closes(&outputs, 77) && !closes(&outputs, 800));

    // REL-174: a hello of a relay outside the layer before names no peer,
    // thus the dial of relay 1 gives no relay link here.
    let (mut other, other_static) = lone_relay(2);
    other.set_relay_identities(set);
    other.set_previous_layer([[0x99; 32]].into());
    let (mut first, _) = lone_relay(1);
    first.set_challenge_signer(identity(0x51), Vec::new());
    for output in first.dialed(
        900,
        other_static.relay_id,
        [7; 8],
        Secret::new([9; 32]),
        100,
        &mut Rng(5),
    ) {
        let Output::Send { capsule, .. } = output else {
            panic!("an unexpected output");
        };
        other.on_capsule(800, &capsule, 100, &mut Rng(6));
    }
    let outputs = other.push_tick(100 + LINK_OPEN_TIMEOUT, &mut Rng(3));
    assert!(closes(&outputs, 800));
}

#[test]
fn a_flood_of_builds_on_one_link_gets_the_budget_of_that_link_and_no_more() {
    // NET-332: one client link builds its burst at an ingress relay.
    let (mut ingress, relay) = lone_relay(1);
    let mut client = Direct::open(&mut ingress, 1, 100);
    let burst = LINK_BUILD_BURST as u8;
    for circ in 0..burst + 6 {
        let built = client.first_hop(&mut ingress, &relay, circ, 100).is_some();
        assert_eq!(built, circ < burst, "{circ}");
    }
    assert_eq!(ingress.circuits_held(), usize::from(burst));
    // Another link has a budget of its own.
    let mut second = Direct::open(&mut ingress, 2, 100);
    assert!(second.first_hop(&mut ingress, &relay, 1, 100).is_some());

    // NET-331: a relay at its count of circuits ends the oldest circuit
    // that carried nothing for each new build. The builds of one link thus
    // never grow what the relay holds. This relay knows no relay set, as
    // in a test network.
    let (mut middle, relay) = lone_relay(2);
    middle.set_circuits_max(4);
    let mut link = Direct::open(&mut middle, 800, 100);
    for circ in 0..12 {
        assert!(link.first_hop(&mut middle, &relay, circ, 100).is_some());
        assert!(middle.circuits_held() <= 4);
    }
    assert_eq!(middle.circuits_held(), 4);
}

#[test]
fn a_relay_dials_again_after_a_dial_that_failed_while_builds_arrive() {
    // NET-319: before this, one dial that failed left each later `EXTEND`
    // behind the body of the one before it. No new dial started while a
    // build arrived inside each `CIRCUIT_BUILD_TIMEOUT`.
    let (mut node, relay) = lone_relay(1);
    let next = lone_relay(2).1;
    let mut client = Direct::open(&mut node, 1, 100);
    let mut extend = |node: &mut RelayNode, circ: u8, now: u64| {
        let mut build = client.first_hop(node, &relay, circ, now).unwrap();
        client.extend(node, &mut build, &next, now).0
    };
    assert_eq!(dials(&extend(&mut node, 1, 100)), 1);
    // The dial runs: a second body draws no second dial.
    assert_eq!(dials(&extend(&mut node, 2, 101)), 0);
    node.dial_failed(next.relay_id, 101);
    // The hold-off, and then the next body dials again.
    assert_eq!(dials(&extend(&mut node, 3, 101)), 0);
    assert_eq!(dials(&extend(&mut node, 4, 102)), 1);
    // A dial that failed starts again at the clock too, while a body waits.
    node.dial_failed(next.relay_id, 102);
    assert_eq!(dials(&node.push_tick(103, &mut Rng(8))), 1);
    // A dial that reports nothing gives way after its time.
    assert_eq!(dials(&extend(&mut node, 5, 104)), 0);
    assert_eq!(dials(&extend(&mut node, 6, 103 + 15)), 1);
}

#[test]
fn a_circuit_whose_next_hop_gives_no_extended_ends_at_the_build_timeout() {
    // NET-169: the client ends a build with no `EXTENDED`, and its
    // `DESTROY` is a cell of the middle here that this relay cannot read.
    let (mut node, relay) = lone_relay(1);
    let next = lone_relay(2).1;
    node.dialed(
        900,
        next.relay_id,
        [3; 8],
        Secret::new([9; 32]),
        100,
        &mut Rng(5),
    );
    let mut client = Direct::open(&mut node, 1, 100);
    let mut build = client.first_hop(&mut node, &relay, 1, 100).unwrap();
    let (outputs, _) = client.extend(&mut node, &mut build, &next, 100);
    assert!(matches!(outputs[..], [Output::Send { link: 900, .. }]));
    // A circuit with its three hops stays.
    let _held = client.first_hop(&mut node, &relay, 2, 100).unwrap();
    assert_eq!(node.circuits_held(), 2);
    node.sweep(100 + CIRCUIT_BUILD_TIMEOUT - 1, &mut Rng(6));
    assert_eq!(node.circuits_held(), 2);
    // The next hop never answered: the circuit ends, and each neighbor
    // learns it (`NET-322`).
    let outputs = node.sweep(100 + CIRCUIT_BUILD_TIMEOUT, &mut Rng(6));
    assert_eq!(node.circuits_held(), 1);
    let told: Vec<LinkId> = outputs
        .iter()
        .filter_map(|output| match output {
            Output::Send { link, .. } => Some(*link),
            _ => None,
        })
        .collect();
    assert!(told.contains(&900) && told.contains(&1), "{told:?}");
}

/// A runtime whose link `0` is at its bound.
struct Full(LinkId);

impl Backlog for Full {
    fn of(&self, link: LinkId) -> Option<(usize, usize)> {
        Some(if link == self.0 {
            (1 << 20, 1 << 20)
        } else {
            (0, 1 << 20)
        })
    }
}

#[test]
fn a_full_backlog_ends_the_circuit_of_its_cell_and_keeps_the_link() {
    // NET-349: before this, a link at its bound closed, and each circuit
    // that shared it ended.
    let (mut node, relay) = lone_relay(1);
    let mut client = Direct::open(&mut node, 1, 100);
    let _held = client.first_hop(&mut node, &relay, 1, 100).unwrap();
    node.set_backlog(Box::new(Full(1)));
    let mut build = CircuitBuild::new([2; 16]);
    let (outputs, _) = client.extend(&mut node, &mut build, &relay, 100);
    // The `EXTENDED` found no room: its circuit ends with a `Destroy` to
    // the neighbor, and nothing closes the link.
    let [Output::Send { link: 1, capsule }] = &outputs[..] else {
        panic!("{outputs:?}");
    };
    let (kind, _, _) = capsule::parse(capsule).unwrap();
    assert_eq!(kind, capsule::CapsuleType::Session);
    assert_eq!(node.circuits_held(), 1);
    // A link with room takes its cell.
    let mut other = Direct::open(&mut node, 2, 100);
    assert!(other.first_hop(&mut node, &relay, 3, 100).is_some());
}

#[test]
fn a_link_with_no_session_and_an_idle_client_link_give_their_place_back() {
    let (mut node, relay) = lone_relay(1);
    // NET-335: a connection that upgraded and sent no `Open`.
    node.opened(4, 100);
    let mut client = Direct::open(&mut node, 6, 100);
    let outputs = node.push_tick(100 + LINK_OPEN_TIMEOUT, &mut Rng(3));
    assert!(closes(&outputs, 4) && !closes(&outputs, 6));
    // A client link that holds a circuit stays, and one that holds none
    // for LINK_IDLE_TIMEOUT closes.
    let _idle = Direct::open(&mut node, 8, 100);
    let _held = client.first_hop(&mut node, &relay, 1, 100).unwrap();
    assert!(node.sweep(160, &mut Rng(3)).is_empty());
    let outputs = node.sweep(160 + LINK_IDLE_TIMEOUT, &mut Rng(3));
    assert!(closes(&outputs, 8) && !closes(&outputs, 6));
}

/// The circuits whose end `outputs` tell a neighbor of, by link.
fn ended(outputs: &[Output]) -> Vec<(LinkId, [u8; 16])> {
    outputs
        .iter()
        .filter_map(|output| {
            let Output::Send { link, capsule } = output else {
                return None;
            };
            let (capsule::CapsuleType::Session, value, _) = capsule::parse(capsule).unwrap() else {
                return None;
            };
            match SessionControl::parse(value).unwrap() {
                SessionControl::Destroy { circ_id } => Some((*link, circ_id)),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn a_build_above_the_share_of_its_address_ends_a_circuit_of_that_address() {
    let (mut ingress, relay) = lone_relay(1);
    ingress.set_circuits_max(8);
    // NET-331: the links 1 and 2 come from one address, and the link 3
    // from another one.
    ingress.set_source(1, [0xA1; 16]);
    ingress.set_source(2, [0xA1; 16]);
    ingress.set_source(3, [0xB1; 16]);
    let mut first = Direct::open(&mut ingress, 1, 100);
    let mut second = Direct::open(&mut ingress, 2, 100);
    let mut other = Direct::open(&mut ingress, 3, 100);
    let mut carried = first.first_hop(&mut ingress, &relay, 1, 100).unwrap();
    for circ in 2..=3 {
        assert!(first.first_hop(&mut ingress, &relay, circ, 100).is_some());
    }
    for circ in 4..=6 {
        assert!(second.first_hop(&mut ingress, &relay, circ, 100).is_some());
    }
    assert_eq!(ingress.circuits_held(), 6);
    // The circuit 1 carries a forward cell, thus it is the last of its
    // address that a build ends. Before this, one cell took a circuit out
    // of the reach of each build, and a few addresses held the table.
    let next = lone_relay(2).1;
    first.extend(&mut ingress, &mut carried, &next, 100);

    let build = |node: &mut RelayNode, from: &mut Direct, circ: u8| {
        let mut build = CircuitBuild::new([circ; 16]);
        let (outputs, _) = from.extend(node, &mut build, &relay, 100);
        ended(&outputs)
    };
    // The other address builds into the room that the table has.
    assert!(build(&mut ingress, &mut other, 10).is_empty());
    assert!(build(&mut ingress, &mut other, 11).is_empty());
    // The table is at its count: each build ends the stalest circuit of
    // the address that holds the most.
    assert_eq!(build(&mut ingress, &mut other, 12), [(1, [2; 16])]);
    assert_eq!(build(&mut ingress, &mut other, 13), [(1, [3; 16])]);
    // Each address holds its share now: a build ends a circuit of its own
    // address, and the circuits of the other one stay.
    assert_eq!(build(&mut ingress, &mut other, 14), [(3, [10; 16])]);
    assert_eq!(build(&mut ingress, &mut other, 15), [(3, [11; 16])]);
    assert_eq!(build(&mut ingress, &mut second, 7), [(2, [4; 16])]);
    assert_eq!(build(&mut ingress, &mut first, 8), [(2, [5; 16])]);
    assert_eq!(ingress.circuits_held(), 8);
}

#[test]
fn a_relay_that_left_the_layer_before_loses_its_link() {
    let mut network = Network::unlinked();
    let key = identity(0x51);
    let relay_1 = network.statics[0].relay_id;
    let set: BTreeMap<[u8; 32], Vec<u8>> =
        [(relay_1, key.verifying_key().to_bytes().to_vec())].into();
    network.relays[0].set_challenge_signer(key, Vec::new());
    network.relays[1].set_relay_identities(set);
    network.relays[1].set_previous_layer([relay_1].into());
    let _client = Client::connect(&mut network, 0);
    assert_eq!(network.relays[1].circuits_held(), 1);
    // A set that still names relay 1 in the layer before closes nothing.
    assert!(network.relays[1].close_strangers(100).is_empty());
    // REL-174: a newer set names another relay there. Before this, relay 1
    // kept the link of its hello and built circuits on it.
    network.relays[1].set_previous_layer([[0x99; 32]].into());
    let outputs = network.relays[1].close_strangers(100);
    assert!(closes(&outputs, 800));
    assert_eq!(network.relays[1].circuits_held(), 0);
}

/// A runtime that counts the bytes of one link as a test sets them.
struct Counted {
    link: LinkId,
    waiting: Arc<AtomicUsize>,
    limit: usize,
}

impl Backlog for Counted {
    fn of(&self, link: LinkId) -> Option<(usize, usize)> {
        (link == self.link).then(|| (self.waiting.load(Ordering::Relaxed), self.limit))
    }
}

#[test]
fn a_link_near_its_bound_ends_the_circuit_that_holds_the_most_of_it() {
    let mut network = Network::new();
    let mut alice = Client::connect(&mut network, 0);
    let mut bob = Client::connect(&mut network, 1);
    // Each circuit ends at relay 3 from its first command on.
    alice.new_queue(&mut network, 40);
    bob.new_queue(&mut network, 60);
    let circuits: Vec<CircuitKey> = network.relays[2].paced_circuits().copied().collect();
    let [heavy, light] = circuits[..] else {
        panic!("{circuits:?}");
    };
    assert_eq!((heavy.link, light.link), (800, 800));
    // The link to relay 2 holds one MiB, and nothing reads it.
    let waiting = Arc::new(AtomicUsize::new(0));
    let limit = 1 << 20;
    network.relays[2].set_backlog(Box::new(Counted {
        link: 800,
        waiting: waiting.clone(),
        limit,
    }));
    // One cell of `circuit` to the link: its bytes, and the circuits that
    // the relay ended for it.
    let tick = |network: &mut Network, circuit: &CircuitKey| {
        let outputs = network.relays[2].pacing_tick(circuit, 100, &mut Rng(1));
        network.relays[2].flushed();
        let bytes: usize = outputs
            .iter()
            .map(|output| match output {
                Output::Send { capsule, .. } => capsule.len(),
                _ => 0,
            })
            .sum();
        waiting.fetch_add(bytes, Ordering::Relaxed);
        let lost: Vec<[u8; 16]> = ended(&outputs).into_iter().map(|(_, id)| id).collect();
        (bytes, lost)
    };
    // One circuit fills the link up to the part that stays free.
    let (cell, _) = tick(&mut network, &heavy);
    let mark = limit - limit / 8;
    while waiting.load(Ordering::Relaxed) + 2 * cell + 128 <= mark {
        let (bytes, lost) = tick(&mut network, &heavy);
        assert!(bytes > 0 && lost.is_empty());
    }
    // NET-349: the cell of the other circuit reaches into that part. The
    // relay ends the circuit that filled the link, and the cell goes.
    // Before this, a full link ended the circuit of each cell that
    // arrived. The circuit that filled it thus ended those of each other
    // client on the link.
    let mut lost = Vec::new();
    for _ in 0..3 {
        let (bytes, ended) = tick(&mut network, &light);
        assert!(bytes >= cell);
        lost.extend(ended);
        if !lost.is_empty() {
            break;
        }
    }
    assert_eq!(lost, [heavy.circ_id]);
    let left: Vec<CircuitKey> = network.relays[2].paced_circuits().copied().collect();
    assert_eq!(left, [light]);
    assert_eq!(network.relays[2].circuits_held(), 1);
}

/// One `SEND` of a record of `bucket` to `address`, for the session of
/// `sender`.
fn record_for(sender: &Client, address: &QueueAddress, bucket: Bucket, corr: u16) -> Vec<u8> {
    let mut corr_id = [0x5E; 16];
    corr_id[..2].copy_from_slice(&corr.to_be_bytes());
    Outbound::new(address)
        .seal_record_from(L6Kind::Ratchet, &[7; 40], [3; 12], bucket)
        .unwrap()
        .sign(sender.session.relay_session_pk(), corr_id)
        .unwrap()
}

/// The sequence of each `MSG` among `events`.
fn messages(events: &[Event]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Message { payload, .. } => {
                Some(u32::from_be_bytes(payload[..4].try_into().unwrap()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn a_long_backlog_leaves_in_steps_and_a_refused_sub_leaves_no_subscription() {
    let mut network = Network::new();
    let mut alice = Client::connect(&mut network, 0);
    let mut bob = Client::connect(&mut network, 1);
    let (bob_in, to_bob) = bob.new_queue(&mut network, 60);
    let count = u16::try_from(DRAIN_THRESHOLD).unwrap() + 5;
    let mut sent = 0u16;
    let mut send = |network: &mut Network, alice: &mut Client| {
        sent += 1;
        let record = record_for(alice, &to_bob, Bucket::B0, sent);
        alice.session.queue(record, 100 + u64::from(sent)).unwrap();
        alice.flush(network);
        network.tick();
        alice.drain(network);
    };
    for _ in 0..count {
        send(&mut network, &mut alice);
    }
    assert!(messages(&bob.drain(&mut network)).is_empty());

    // NET-037: the backlog is above the threshold, thus it leaves at the
    // tick of the clock of the relay and not on the pacing clock.
    let mut asked = 0u8;
    let mut subscribe = |network: &mut Network, bob: &mut Client| {
        asked += 1;
        let sub = bob_in
            .subscribe(bob.session.relay_session_pk(), [asked; 16])
            .unwrap();
        bob.session.queue(sub, 1_000 + u64::from(asked)).unwrap();
        bob.flush(network);
        network.tick();
        bob.drain(network)
    };
    let whole: Vec<u32> = (1..=u32::from(count)).collect();
    assert_eq!(messages(&subscribe(&mut network, &mut bob)), whole);
    // Each further `SUB` of the minute takes the place of the drain before
    // it, and the records leave again: no `ACK` covered one.
    for _ in 1..DRAINS_PER_MINUTE {
        assert_eq!(messages(&subscribe(&mut network, &mut bob)), whole);
    }
    // NET-349: one more gets a `NACK` with the reason `LIMIT` and no
    // record.
    let events = subscribe(&mut network, &mut bob);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::Rejected {
                reason: umbra_queue::Reject::Limit,
                ..
            }
        )),
        "{events:?}"
    );
    assert!(messages(&events).is_empty());
    // The refused `SUB` left no subscription: the next record gives the
    // circuit no `MSG` above the backlog that did not leave.
    send(&mut network, &mut alice);
    network.tick();
    assert!(messages(&bob.drain(&mut network)).is_empty());
}

#[test]
fn the_drains_of_one_link_take_its_room_in_turns() {
    let mut network = Network::new();
    let mut alice = Client::connect(&mut network, 0);
    let mut bob = Client::connect(&mut network, 1);
    let (alice_in, to_alice) = alice.new_queue(&mut network, 40);
    let (bob_in, to_bob) = bob.new_queue(&mut network, 60);
    // The step of one drain at one tick (`NET-349`).
    let step = 256 << 10;
    // Each queue holds its quota of records, which is more than two steps.
    assert!(QUEUE_QUOTA * Bucket::B2.l6_record() > 2 * step);
    for sent in 0..u16::try_from(QUEUE_QUOTA).unwrap() {
        let record = record_for(&alice, &to_bob, Bucket::B2, sent);
        alice.session.queue(record, 100 + u64::from(sent)).unwrap();
        alice.flush(&mut network);
        let record = record_for(&bob, &to_alice, Bucket::B2, sent);
        bob.session.queue(record, 100 + u64::from(sent)).unwrap();
        bob.flush(&mut network);
        network.tick();
        alice.drain(&mut network);
        bob.drain(&mut network);
    }
    // The link to relay 2 is empty at each tick. One quarter of its bound
    // holds the step of one drain and not of two.
    network.relays[2].set_backlog(Box::new(Counted {
        link: 800,
        waiting: Arc::new(AtomicUsize::new(0)),
        limit: 4 * step + (16 << 10),
    }));
    let sub = alice_in
        .subscribe(alice.session.relay_session_pk(), [0xA5; 16])
        .unwrap();
    alice.session.queue(sub, 2_000).unwrap();
    alice.flush(&mut network);
    let sub = bob_in
        .subscribe(bob.session.relay_session_pk(), [0xB5; 16])
        .unwrap();
    bob.session.queue(sub, 2_000).unwrap();
    bob.flush(&mut network);
    let mut taken = [0usize; 2];
    let mut tick = |network: &mut Network, alice: &mut Client, bob: &mut Client| {
        network.relays[2].flushed();
        let outputs = network.relays[2].drain_tick(100, &mut Rng(9));
        network.route(2, outputs);
        taken[0] += messages(&alice.drain(network)).len();
        taken[1] += messages(&bob.drain(network)).len();
        taken
    };
    // The first tick has room for the step of one circuit.
    let first = tick(&mut network, &mut alice, &mut bob);
    assert!((first[0] == 0) != (first[1] == 0), "{first:?}");
    // The next tick gives its room to the other circuit. Before this, the
    // circuit of the lowest identifier took each tick until its drain
    // ended, and the other one waited for it.
    let second = tick(&mut network, &mut alice, &mut bob);
    assert_eq!(second[0], second[1], "{second:?}");
    assert!(second[0] > 0 && second[0] < QUEUE_QUOTA);
    // The drains end in turns, and each one gives each record one time.
    for _ in 0..80 {
        tick(&mut network, &mut alice, &mut bob);
    }
    assert_eq!(taken, [QUEUE_QUOTA; 2]);
}

// The measurement session of Part 10 §10.3.1.

use umbra_core::directory::{
    authority::keyset_bytes,
    measure::{
        issue_cert, open_content, MeasurerTrust, MEAS_ATTEMPT_BURST, MEAS_ATTEMPT_PERIOD,
        MEAS_CIRCUITS_MAX, MEAS_SESSIONS_MAX, MEAS_SESSION_MAX,
    },
};
use umbra_crypto::sign::SigningKey;
use umbra_onion::{circuit::MeasureCircuit, CIRCUIT_MAX_CELLS};

/// The time of each measurement test, in consensus epoch 0.
const T: u64 = 100;

/// The seven authorities, a measurer key, and a certificate of two
/// authorities for it.
struct Fleet {
    authorities: Vec<SigningKey>,
    key: SigningKey,
    cert: Vec<u8>,
}

impl Fleet {
    fn new() -> Self {
        let authorities: Vec<SigningKey> = (0..7u8).map(|index| identity(0x60 + index)).collect();
        let key = identity(0x70);
        let cert = Fleet::cert_for(&authorities, &key, [0x4D; 16], &[1, 4]);
        Fleet {
            authorities,
            key,
            cert,
        }
    }

    fn cert_for(
        authorities: &[SigningKey],
        key: &SigningKey,
        measurer_id: [u8; 16],
        signers: &[u8],
    ) -> Vec<u8> {
        let signers: Vec<(u8, &SigningKey)> = signers
            .iter()
            .map(|index| (*index, &authorities[usize::from(*index)]))
            .collect();
        issue_cert(
            measurer_id,
            &key.verifying_key().to_bytes(),
            0,
            10,
            &signers,
            &mut Rng(31),
        )
        .unwrap()
    }

    fn trust(&self, revoked: &[[u8; 16]]) -> MeasurerTrust {
        MeasurerTrust {
            keyset: keyset_bytes(&self.authorities, 1).unwrap(),
            revoked: revoked.to_vec(),
        }
    }

    /// A relay of `layer` that holds the key set of the fleet. A relay of
    /// layer 2 or 3 holds a relay set, thus it tells a relay link from
    /// each other link.
    fn relay(&self, layer: u8) -> (RelayNode, RelayStatic) {
        let (mut node, held) = lone_relay(layer);
        node.set_measurer_trust(self.trust(&[]));
        if layer > 1 {
            node.set_relay_identities([([0x99; 32], vec![0u8; 4])].into());
            node.set_previous_layer([[0x99; 32]].into());
        }
        (node, held)
    }
}

impl Direct {
    /// Builds a circuit of one hop at `node`, a relay of `layer`.
    fn one_hop(
        &mut self,
        node: &mut RelayNode,
        relay: &RelayStatic,
        layer: u8,
        circ: u8,
        now: u64,
    ) -> Option<MeasureCircuit> {
        let mut build = CircuitBuild::new([circ; 16]);
        let (outputs, pending) = self.extend(node, &mut build, relay, now);
        let cell = self.cells(&outputs).into_iter().next()?;
        let (parsed, _) = Cell::parse(&cell).unwrap();
        let (command, reply) = read_cell_body(parsed.body).unwrap();
        assert_eq!(command, CellCommand::Extended);
        let ss_hop = pending.finish(reply).unwrap();
        Some(MeasureCircuit::new(&ss_hop, u32::from(layer), [circ; 16]))
    }

    /// The cells for this link among `outputs`.
    fn cells(&mut self, outputs: &[Output]) -> Vec<Vec<u8>> {
        let mut cells = Vec::new();
        for output in outputs {
            let Output::Send { link, capsule } = output else {
                continue;
            };
            if *link != self.at {
                continue;
            }
            if let (capsule::CapsuleType::Cell, value, _) = capsule::parse(capsule).unwrap() {
                cells.push(self.link.receive(value).unwrap().unwrap().to_vec());
            }
        }
        cells
    }

    /// Sends one cell on `circuit`, and returns what the relay does.
    fn cell(
        &mut self,
        node: &mut RelayNode,
        circuit: &mut MeasureCircuit,
        command: CellCommand,
        bucket: Bucket,
        content: &[u8],
        now: u64,
    ) -> Vec<Output> {
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, command, content, &mut body).unwrap();
        let tag = circuit.seal(&mut body).unwrap();
        let cell = [circuit.circ_id().as_slice(), &tag, &body].concat();
        let mut buffer = vec![0u8; 40_000];
        let used = self.link.send(&cell, &mut buffer).unwrap();
        node.on_capsule(self.at, &buffer[..used], now, &mut self.rng)
    }

    /// Sends the `MEAS_OPEN` of `fleet` for `relay` on `circuit`.
    fn meas_open(
        &mut self,
        node: &mut RelayNode,
        circuit: &mut MeasureCircuit,
        fleet: &Fleet,
        relay: &RelayStatic,
        now: u64,
    ) -> Vec<Output> {
        let content = open_content(
            &fleet.cert,
            &fleet.key,
            &relay.relay_id,
            &circuit.circ_id(),
            &mut Rng(41),
        )
        .unwrap();
        self.cell(
            node,
            circuit,
            CellCommand::MeasOpen,
            Bucket::B3,
            &content,
            now,
        )
    }

    /// Sends one `MEAS_ECHO` with `content`, and returns the content of
    /// each echo that comes back.
    fn echo(
        &mut self,
        node: &mut RelayNode,
        circuit: &mut MeasureCircuit,
        content: &[u8],
        now: u64,
    ) -> Vec<Vec<u8>> {
        let outputs = self.cell(
            node,
            circuit,
            CellCommand::MeasEcho,
            Bucket::B0,
            content,
            now,
        );
        self.cells(&outputs)
            .iter()
            .map(|cell| {
                let (parsed, bucket) = Cell::parse(cell).unwrap();
                assert_eq!(bucket, Bucket::B0);
                assert_eq!(parsed.circ_id, &circuit.circ_id());
                let mut body = parsed.body.to_vec();
                circuit.open(parsed.tag, &mut body).unwrap();
                let (command, content) = umbra_wire::cell::unpad_body(&body).unwrap();
                assert_eq!(command, CellCommand::MeasEcho);
                content.to_vec()
            })
            .collect()
    }
}

#[test]
fn a_session_opens_with_a_certificate_and_each_echo_comes_back() {
    let fleet = Fleet::new();
    for layer in 1..=3u8 {
        let (mut node, relay) = fleet.relay(layer);
        let mut measurer = Direct::open(&mut node, 5, T);
        let mut circuit = measurer.one_hop(&mut node, &relay, layer, 0xA1, T).unwrap();
        // REL-064: the relay gives the `MEAS_OPEN` no answer.
        assert!(measurer
            .meas_open(&mut node, &mut circuit, &fleet, &relay, T)
            .is_empty());
        assert_eq!(node.measure_sessions(), 1);
        // REL-002, REL-003: each echo comes back at once, with its content.
        for count in 0..3u32 {
            let content = [&count.to_be_bytes()[..], &[0x5A; 40]].concat();
            assert_eq!(
                measurer.echo(&mut node, &mut circuit, &content, T + 1),
                vec![content]
            );
        }
        // NET-335: the link of a measurer holds its place for the session.
        let outputs = node.push_tick(T + LINK_OPEN_TIMEOUT, &mut Rng(3));
        assert!(!closes(&outputs, 5));
        // REL-189: a measurement circuit of a relay of layer 2 or 3 is no
        // chain. The session ends with its circuit.
        measurer.cell(
            &mut node,
            &mut circuit,
            CellCommand::Destroy,
            Bucket::B0,
            &[],
            T + 2,
        );
        assert_eq!(node.circuits_held(), 0);
        assert_eq!(node.measure_sessions(), 0);
    }
}

#[test]
fn a_session_passes_the_cells_of_a_circuit_and_ends_at_its_time() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(1);
    let mut measurer = Direct::open(&mut node, 5, T);
    let mut circuit = measurer.one_hop(&mut node, &relay, 1, 0xA1, T).unwrap();
    measurer.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
    // REL-201: `CIRCUIT_MAX_CELLS` does not end the circuit of a session.
    let mut back = 0u32;
    for count in 0..CIRCUIT_MAX_CELLS + 64 {
        back += measurer
            .echo(&mut node, &mut circuit, &count.to_be_bytes(), T + 1)
            .len() as u32;
    }
    assert_eq!(back, CIRCUIT_MAX_CELLS + 64);
    node.sweep(T + 2, &mut Rng(3));
    assert_eq!(node.circuits_held(), 1);
    // The session ends `MEAS_SESSION_MAX` after its open: the echo at
    // that time gets no answer, and the circuit is gone.
    let last = T + MEAS_SESSION_MAX - 1;
    assert_eq!(measurer.echo(&mut node, &mut circuit, b"in", last).len(), 1);
    let late = measurer.cell(
        &mut node,
        &mut circuit,
        CellCommand::MeasEcho,
        Bucket::B0,
        b"late",
        T + MEAS_SESSION_MAX,
    );
    assert!(measurer.cells(&late).is_empty());
    assert_eq!(node.circuits_held(), 0);
    assert_eq!(node.measure_sessions(), 0);
}

#[test]
fn an_echo_outside_a_session_gets_no_answer() {
    let fleet = Fleet::new();
    // REL-068: at an ingress relay the circuit is one of a client, and the
    // echo drops.
    let (mut node, relay) = fleet.relay(1);
    let mut stranger = Direct::open(&mut node, 5, T);
    let mut circuit = stranger.one_hop(&mut node, &relay, 1, 0xA1, T).unwrap();
    for _ in 0..3 {
        assert!(stranger
            .cell(
                &mut node,
                &mut circuit,
                CellCommand::MeasEcho,
                Bucket::B0,
                b"echo",
                T
            )
            .is_empty());
    }
    assert_eq!(node.measure_sessions(), 0);
    // NET-353: at a relay of layer 2 or 3 the circuit is a candidate. It
    // ends at the echo, and the relay sends nothing.
    for layer in 2..=3u8 {
        let (mut node, relay) = fleet.relay(layer);
        let mut stranger = Direct::open(&mut node, 5, T);
        let mut circuit = stranger.one_hop(&mut node, &relay, layer, 0xA1, T).unwrap();
        assert_eq!(node.circuits_held(), 1);
        assert!(stranger
            .cell(
                &mut node,
                &mut circuit,
                CellCommand::MeasEcho,
                Bucket::B0,
                b"echo",
                T
            )
            .is_empty());
        assert_eq!(node.circuits_held(), 0);
    }
}

#[test]
fn an_echo_of_another_bucket_gets_no_answer() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(3);
    let mut measurer = Direct::open(&mut node, 5, T);
    let mut circuit = measurer.one_hop(&mut node, &relay, 3, 0xA1, T).unwrap();
    measurer.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
    // REL-041: a larger bucket would make the echo an amplifier.
    for bucket in [Bucket::B1, Bucket::B2, Bucket::B3] {
        assert!(measurer
            .cell(
                &mut node,
                &mut circuit,
                CellCommand::MeasEcho,
                bucket,
                b"large",
                T
            )
            .is_empty());
    }
    // The session stays, and it serves no other command.
    assert!(measurer
        .cell(
            &mut node,
            &mut circuit,
            CellCommand::Loop,
            Bucket::B0,
            &[],
            T
        )
        .is_empty());
    assert_eq!(measurer.echo(&mut node, &mut circuit, b"b0", T).len(), 1);
}

#[test]
fn a_certificate_that_does_not_verify_opens_no_session() {
    let fleet = Fleet::new();
    let (_, relay) = fleet.relay(3);
    // The open of `cert` under `key` for the relay `named` at `now`, at a
    // relay that holds `trust`.
    let opens = |cert: &[u8], key: &SigningKey, named: [u8; 32], now: u64, trust: MeasurerTrust| {
        let (mut node, _) = fleet.relay(3);
        node.set_measurer_trust(trust);
        let mut measurer = Direct::open(&mut node, 5, now);
        let mut circuit = measurer.one_hop(&mut node, &relay, 3, 0xA1, now).unwrap();
        let content = open_content(cert, key, &named, &[0xA1; 16], &mut Rng(41)).unwrap();
        let outputs = measurer.cell(
            &mut node,
            &mut circuit,
            CellCommand::MeasOpen,
            Bucket::B3,
            &content,
            now,
        );
        // A relay gives a rejected attempt no sign (`REL-069`).
        assert!(outputs.is_empty());
        let opened = node.measure_sessions() == 1;
        assert_eq!(node.circuits_held(), usize::from(opened));
        opened
    };
    let own = relay.relay_id;
    assert!(opens(&fleet.cert, &fleet.key, own, T, fleet.trust(&[])));
    // REL-104: the root revoked the measurer.
    assert!(!opens(
        &fleet.cert,
        &fleet.key,
        own,
        T,
        fleet.trust(&[[0x4D; 16]])
    ));
    // REL-067: the certificate is void after epoch 10.
    assert!(!opens(
        &fleet.cert,
        &fleet.key,
        own,
        11 * 3_600,
        fleet.trust(&[])
    ));
    // REL-066: the signatures of keys outside the key set.
    let others: Vec<SigningKey> = (0..7u8).map(|index| identity(0x20 + index)).collect();
    let forged = Fleet::cert_for(&others, &fleet.key, [0x4D; 16], &[1, 4]);
    assert!(!opens(&forged, &fleet.key, own, T, fleet.trust(&[])));
    // REL-065: the signature names another relay, or comes from another
    // key than the one of the certificate.
    assert!(!opens(
        &fleet.cert,
        &fleet.key,
        [0x12; 32],
        T,
        fleet.trust(&[])
    ));
    assert!(!opens(
        &fleet.cert,
        &identity(0x71),
        own,
        T,
        fleet.trust(&[])
    ));
}

#[test]
fn a_relay_with_no_root_opens_no_session() {
    let fleet = Fleet::new();
    let (mut node, relay) = lone_relay(1);
    let mut measurer = Direct::open(&mut node, 5, T);
    let mut circuit = measurer.one_hop(&mut node, &relay, 1, 0xA1, T).unwrap();
    measurer.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
    assert_eq!(node.measure_sessions(), 0);
    assert!(measurer
        .echo(&mut node, &mut circuit, b"echo", T)
        .is_empty());
}

#[test]
fn the_rate_of_rejected_attempts_holds_at_an_ingress_relay() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(1);
    node.set_source(5, [9; 16]);
    node.set_source(6, [9; 16]);
    node.set_source(7, [8; 16]);
    let mut attacker = Direct::open(&mut node, 5, T);
    // REL-069: each `MEAS_OPEN` that does not verify spends one attempt of
    // its address.
    for circ in 0..MEAS_ATTEMPT_BURST as u8 {
        let mut circuit = attacker.one_hop(&mut node, &relay, 1, circ, T).unwrap();
        let outputs = attacker.cell(
            &mut node,
            &mut circuit,
            CellCommand::MeasOpen,
            Bucket::B3,
            &[0x5A; 9_000],
            T,
        );
        assert!(outputs.is_empty());
    }
    assert_eq!(node.circuits_held(), 0);
    // Above the rate the relay verifies nothing: a certificate that
    // verifies opens no session from that address, on each of its links.
    let mut same = Direct::open(&mut node, 6, T);
    let mut circuit = same.one_hop(&mut node, &relay, 1, 0xA1, T).unwrap();
    assert!(same
        .meas_open(&mut node, &mut circuit, &fleet, &relay, T + 1)
        .is_empty());
    assert_eq!(node.measure_sessions(), 0);
    assert!(same
        .echo(&mut node, &mut circuit, b"echo", T + 1)
        .is_empty());
    // Another address holds its own attempts.
    let mut other = Direct::open(&mut node, 7, T);
    let mut circuit = other.one_hop(&mut node, &relay, 1, 0xA2, T).unwrap();
    other.meas_open(&mut node, &mut circuit, &fleet, &relay, T + 1);
    assert_eq!(node.measure_sessions(), 1);
    // One attempt comes back after `MEAS_ATTEMPT_PERIOD`.
    let later = T + MEAS_ATTEMPT_PERIOD;
    let mut circuit = same.one_hop(&mut node, &relay, 1, 0xA3, later).unwrap();
    same.meas_open(&mut node, &mut circuit, &fleet, &relay, later);
    assert_eq!(same.echo(&mut node, &mut circuit, b"echo", later).len(), 1);
}

#[test]
fn the_rate_of_rejected_attempts_holds_at_a_relay_of_layer_3() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(3);
    node.set_source(5, [9; 16]);
    node.set_source(6, [9; 16]);
    let mut attacker = Direct::open(&mut node, 5, T);
    // NET-353: a candidate spends one attempt at its build, and one with
    // no `MEAS_OPEN` gives none back.
    for circ in 0..MEAS_ATTEMPT_BURST as u8 {
        assert!(attacker.one_hop(&mut node, &relay, 3, circ, T).is_some());
    }
    // REL-069: above the rate a build cell gets no answer and costs no
    // key agreement, on each link of that address.
    assert!(attacker.one_hop(&mut node, &relay, 3, 0xF0, T).is_none());
    let mut same = Direct::open(&mut node, 6, T);
    assert!(same.one_hop(&mut node, &relay, 3, 0xF1, T).is_none());
    assert_eq!(node.circuits_held(), MEAS_ATTEMPT_BURST as usize);
    // A candidate with no `MEAS_OPEN` ends at `CIRCUIT_BUILD_TIMEOUT`.
    node.sweep(T + CIRCUIT_BUILD_TIMEOUT, &mut Rng(3));
    assert_eq!(node.circuits_held(), 0);
    assert!(same
        .one_hop(&mut node, &relay, 3, 0xF2, T + CIRCUIT_BUILD_TIMEOUT)
        .is_none());
    // One attempt comes back after `MEAS_ATTEMPT_PERIOD`, and an open
    // that verifies gives its attempt back at once.
    let later = T + MEAS_ATTEMPT_PERIOD;
    for circ in 0xA0..0xA4u8 {
        let mut circuit = same.one_hop(&mut node, &relay, 3, circ, later).unwrap();
        same.meas_open(&mut node, &mut circuit, &fleet, &relay, later);
        assert_eq!(same.echo(&mut node, &mut circuit, b"echo", later).len(), 1);
    }
    assert_eq!(node.measure_sessions(), 1);
}

#[test]
fn a_candidate_serves_no_other_cell() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(2);
    node.set_next_layer([[0x13; 32]].into());
    let mut stranger = Direct::open(&mut node, 5, T);
    // NET-353: an `EXTEND` on a candidate ends it, and the relay dials no
    // relay for it. A client thus enters no chain at layer 2.
    let mut circuit = stranger.one_hop(&mut node, &relay, 2, 0xA1, T).unwrap();
    let (_, next) = lone_relay(3);
    let mut hello = [0u8; HELLO_LEN];
    Pending::hello(&next, DelayClass::Fast, &mut Rng(8), &mut hello).unwrap();
    let outputs = stranger.cell(
        &mut node,
        &mut circuit,
        CellCommand::Extend,
        BUILD_BUCKET,
        &hello,
        T,
    );
    assert!(outputs.is_empty());
    assert_eq!(node.circuits_held(), 0);
    // A `MEAS_OPEN` after `CIRCUIT_BUILD_TIMEOUT` opens no session.
    let mut circuit = stranger.one_hop(&mut node, &relay, 2, 0xA2, T).unwrap();
    let late = T + CIRCUIT_BUILD_TIMEOUT;
    assert!(stranger
        .meas_open(&mut node, &mut circuit, &fleet, &relay, late)
        .is_empty());
    assert_eq!(node.measure_sessions(), 0);
    assert_eq!(node.circuits_held(), 0);
    // An open session extends no circuit.
    let mut circuit = stranger.one_hop(&mut node, &relay, 2, 0xA3, T).unwrap();
    stranger.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
    let outputs = stranger.cell(
        &mut node,
        &mut circuit,
        CellCommand::Extend,
        BUILD_BUCKET,
        &hello,
        T,
    );
    assert_eq!(dials(&outputs), 0);
    assert_eq!(node.measure_sessions(), 1);
}

#[test]
fn one_measurer_holds_one_session_and_a_relay_holds_a_small_count() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(1);
    let mut measurer = Direct::open(&mut node, 5, T);
    // REL-202: each circuit of one measurer is of one session, up to
    // `MEAS_CIRCUITS_MAX`.
    for circ in 0..MEAS_CIRCUITS_MAX as u8 {
        let mut circuit = measurer.one_hop(&mut node, &relay, 1, circ, T).unwrap();
        measurer.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
        assert_eq!(node.measure_sessions(), 1);
    }
    assert_eq!(node.circuits_held(), MEAS_CIRCUITS_MAX);
    let mut circuit = measurer.one_hop(&mut node, &relay, 1, 0xEE, T).unwrap();
    measurer.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
    assert_eq!(node.circuits_held(), MEAS_CIRCUITS_MAX);
    assert!(measurer
        .echo(&mut node, &mut circuit, b"echo", T)
        .is_empty());
    // A relay holds `MEAS_SESSIONS_MAX` sessions, each of one measurer.
    for index in 1..=MEAS_SESSIONS_MAX as u8 {
        let other = Fleet {
            authorities: (0..7u8).map(|index| identity(0x60 + index)).collect(),
            key: identity(0x70),
            cert: Fleet::cert_for(&fleet.authorities, &fleet.key, [index; 16], &[0, 6]),
        };
        let mut link = Direct::open(&mut node, 10 + LinkId::from(index), T);
        let mut circuit = link.one_hop(&mut node, &relay, 1, 0xB0, T).unwrap();
        link.meas_open(&mut node, &mut circuit, &other, &relay, T);
        let opened = link.echo(&mut node, &mut circuit, b"echo", T).len() == 1;
        assert_eq!(opened, usize::from(index) < MEAS_SESSIONS_MAX);
    }
    assert_eq!(node.measure_sessions(), MEAS_SESSIONS_MAX);
}

#[test]
fn an_echo_with_no_room_on_its_link_drops_and_the_circuit_stays() {
    let fleet = Fleet::new();
    let (mut node, relay) = fleet.relay(1);
    let waiting = Arc::new(AtomicUsize::new(0));
    node.set_backlog(Box::new(Counted {
        link: 5,
        waiting: waiting.clone(),
        limit: 1 << 20,
    }));
    let mut measurer = Direct::open(&mut node, 5, T);
    let mut circuit = measurer.one_hop(&mut node, &relay, 1, 0xA1, T).unwrap();
    measurer.meas_open(&mut node, &mut circuit, &fleet, &relay, T);
    assert_eq!(measurer.echo(&mut node, &mut circuit, b"one", T).len(), 1);
    // REL-204: the echoes fill half of the bound of their link at most.
    // An echo above it drops, and it ends no circuit (`NET-349`).
    waiting.store(1 << 19, Ordering::Relaxed);
    for _ in 0..4 {
        assert!(measurer
            .echo(&mut node, &mut circuit, b"lost", T)
            .is_empty());
    }
    assert_eq!(node.circuits_held(), 1);
    // The echo after the room came back opens at the measurer: a dropped
    // echo moved no chaining value.
    waiting.store(0, Ordering::Relaxed);
    node.flushed();
    assert_eq!(
        measurer.echo(&mut node, &mut circuit, b"two", T),
        vec![b"two".to_vec()]
    );
}
