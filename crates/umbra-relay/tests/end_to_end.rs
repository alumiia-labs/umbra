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

use std::collections::VecDeque;

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
    rsabssa::PublicKey2048,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::CircuitBuild,
};
use umbra_relay::{
    circuits::LinkId,
    node::{Config, Output, RelayNode},
};
use umbra_transport::link::ClientLink;
use umbra_wire::{
    address::QueueAddress,
    admission::{Admission, AdmissionKind},
    bucket::Bucket,
    capsule,
    cell::{Cell, CellCommand},
    command::{Cmd, Command, IdsPayload, NewPayload},
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
                issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
                community_capacity: 1 << 20,
            }));
        }
        let mut network = Network {
            relays,
            statics,
            peers: vec![Vec::new(), Vec::new(), Vec::new()],
            inboxes: vec![VecDeque::new(), VecDeque::new()],
            rng: Rng(7),
        };
        // Relay 1 dials relay 2, and relay 2 dials relay 3.
        for from in 0..2usize {
            let link: LinkId = 900;
            network.peers[from].push((link, Peer::Relay(from + 1, 800)));
            network.peers[from + 1].push((800, Peer::Relay(from, link)));
            let next_id = network.statics[from + 1].relay_id;
            let outputs =
                network.relays[from].dialed(link, next_id, [from as u8; 8], Secret::new([9; 32]));
            network.route(from, outputs);
        }
        network
    }

    fn route(&mut self, relay: usize, outputs: Vec<Output>) {
        let mut work: VecDeque<(usize, Output)> = outputs.into_iter().map(|o| (relay, o)).collect();
        while let Some((at, output)) = work.pop_front() {
            let Output::Send { link, capsule } = output else {
                panic!("an unexpected output");
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
            let pending = Pending::hello(&relay, &mut rng, &mut hello).unwrap();
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
        Client {
            index,
            link,
            session: CircuitSession::new(build.finish().unwrap(), relay_session_pk, Range::Queue),
        }
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
