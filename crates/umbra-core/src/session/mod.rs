//! The session driver of a client: the path of one application record
//! from a conversation to the cells of a circuit, and back.
//!
//! [`channel`] holds one pairwise channel: the ratchet of Part 5 §5.5, the
//! L6 record of Part 6 §6.4.2, and the signed commands of the two queues.
//! [`batch`] packs the ready commands into cells under Part 6 §6.4.1.
//! [`circuit`] puts a cell under the onion layers of Part 3 §3.4, and it
//! matches each answer of the relay to its command.
//!
//! No type here reads a clock, draws a random value, or opens a socket.
//! The platform crate moves the cells through the link of the transport
//! crate, and it calls these types on the cover clock.

pub mod batch;
pub mod channel;
pub mod circuit;
pub mod contact;
pub mod node;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use alloc::vec::Vec;

    use umbra_crypto::{
        handshake::xk::{InitialDh, SessionKeys},
        ratchet::{braid::Ratchet, codeword::Width, dr::Role},
        secret::Secret,
        x25519::{PublicKey as XPublic, StaticSecret},
    };
    use umbra_onion::circuit::{Circuit, Position, RelayHop};
    use umbra_queue::{
        params::RECEIPT_MIN_DELAY,
        relay::{
            queue::{Queue, QueueKeys},
            session::Session,
        },
        Reject,
    };
    use umbra_wire::{
        address::QueueAddress,
        bucket::Bucket,
        cell::{pad_body, unpad_body, Cell, CellCommand},
        command::{Cmd, Command},
        nack::{NackPayload, Reason},
        queue::msg_from_send,
        session::SessionControl,
    };

    use super::{
        batch::{unpack, Range},
        channel::{Inbound, Outbound, PairwiseChannel, Received},
        circuit::{CircuitSession, Event},
    };
    use crate::abuse::test_rng::Rng;

    /// The three hops of one circuit, and the session of its last hop.
    struct RelaySide {
        hops: Vec<RelayHop>,
        session: Session,
        circ_id: [u8; 16],
    }

    fn circuit(tag: u8) -> (CircuitSession, RelaySide) {
        let secrets = [
            Secret::new([tag; 32]),
            Secret::new([tag + 1; 32]),
            Secret::new([tag + 2; 32]),
        ];
        let circ_id = [tag; 16];
        let hops = alloc::vec![
            RelayHop::new(&secrets[0], 1, Position::Middle),
            RelayHop::new(&secrets[1], 2, Position::Middle),
            RelayHop::new(&secrets[2], 3, Position::Endpoint),
        ];
        let session_sk = StaticSecret::from([tag + 3; 32]);
        let session_pk = *XPublic::from(&session_sk).as_bytes();
        let open = SessionControl::Open {
            session_id: [tag; 8],
            session_secret: Secret::new([tag; 32]),
        };
        let client = CircuitSession::new(Circuit::new(&secrets, circ_id), session_pk, Range::Queue);
        let relay = RelaySide {
            hops,
            session: Session::open(open, session_sk).unwrap(),
            circ_id,
        };
        (client, relay)
    }

    impl RelaySide {
        /// Removes the three forward layers, and returns the content.
        fn forward(&mut self, cell: &[u8]) -> (Bucket, Vec<u8>) {
            let (parsed, bucket) = Cell::parse(cell).unwrap();
            let mut body = parsed.body.to_vec();
            let mut tag = *parsed.tag;
            for hop in &mut self.hops {
                tag = hop.forward(&tag, &mut body).unwrap();
            }
            let (command, content) = unpad_body(&body).unwrap();
            assert_eq!(command, CellCommand::Data);
            (bucket, content.to_vec())
        }

        /// Removes the three forward layers of a cell of any command.
        fn forward_any(&mut self, cell: &[u8]) -> CellCommand {
            let (parsed, _) = Cell::parse(cell).unwrap();
            let mut body = parsed.body.to_vec();
            let mut tag = *parsed.tag;
            for hop in &mut self.hops {
                tag = hop.forward(&tag, &mut body).unwrap();
            }
            unpad_body(&body).unwrap().0
        }

        /// Adds the three backward layers over one command.
        fn backward(&mut self, bucket: Bucket, command: &Command<'_>) -> Vec<u8> {
            let mut encoded = alloc::vec![0u8; command.len()];
            command.encode(&mut encoded).unwrap();
            let mut body = alloc::vec![0u8; bucket.body_len()];
            pad_body(bucket, CellCommand::Data, &encoded, &mut body).unwrap();
            let mut tag = [0u8; 16];
            for hop in self.hops.iter_mut().rev() {
                tag = hop.backward(&tag, &mut body).unwrap();
            }
            [self.circ_id.as_slice(), &tag, &body].concat()
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
        let alice = Ratchet::new(
            keys(InitialDh::Peer(er)),
            Role::Initiator,
            Width::W64,
            0,
            &mut rng,
        )
        .unwrap();
        let bob = Ratchet::new(
            keys(InitialDh::Own(er_sk)),
            Role::Responder,
            Width::W64,
            0,
            &mut rng,
        )
        .unwrap();
        (alice, bob)
    }

    /// One queue at the relay, with the writer side and the reader side.
    fn queue(tag: u8) -> (Queue, Outbound, Inbound) {
        let qr = StaticSecret::from([tag; 32]);
        let qs = StaticSecret::from([tag + 1; 32]);
        let keys = QueueKeys {
            recipient_id: [tag + 2; 32],
            sender_id: [tag + 3; 32],
            qr_auth_pk: *XPublic::from(&qr).as_bytes(),
            qs_auth_pk: *XPublic::from(&qs).as_bytes(),
        };
        let address = QueueAddress {
            relay_id: [9; 32],
            sender_id: keys.sender_id,
            qs_auth_sk: Secret::new([tag + 1; 32]),
            qe: Secret::new([tag + 4; 32]),
        };
        let inbound = Inbound::new(keys.recipient_id, keys.sender_id, qr, &address.qe, 0);
        (Queue::new(keys, 0), Outbound::new(&address), inbound)
    }

    #[test]
    fn a_record_travels_from_one_device_to_the_other_through_a_relay() {
        let (alice_ratchet, bob_ratchet) = ratchets();
        let (mut queue_to_bob, alice_out, bob_in) = queue(40);
        let (_queue_to_alice, bob_out, alice_in) = queue(60);
        let mut alice = PairwiseChannel::new(alice_ratchet, alice_out, alice_in);
        let mut bob = PairwiseChannel::new(bob_ratchet, bob_out, bob_in);
        let (mut alice_circuit, mut relay_a) = circuit(100);
        let (mut bob_circuit, mut relay_b) = circuit(120);
        let mut rng = Rng(5);

        // Bob subscribes.
        let sub = bob
            .subscribe(bob_circuit.relay_session_pk(), [1; 16])
            .unwrap();
        bob_circuit.queue(sub, 1).unwrap();
        let cell = bob_circuit.next_cell().unwrap().unwrap();
        assert_eq!(cell.len(), Bucket::B0.cell_len());
        let (bucket, content) = relay_b.forward(&cell);
        let commands = unpack(&content, bucket).unwrap();
        assert_eq!(commands[0].cmd, Cmd::Sub);
        relay_b
            .session
            .accept(&commands[0], &queue_to_bob.keys().qr_auth_pk)
            .unwrap();
        queue_to_bob.subscribe(true, 0);

        // Alice sends.
        let app = b"an application record";
        let (bucket, send) = alice
            .send(
                app,
                alice_circuit.relay_session_pk(),
                [2; 16],
                [3; 12],
                10,
                &mut rng,
            )
            .unwrap();
        assert_eq!(bucket, Bucket::B0);
        alice_circuit.queue(send.clone(), 77).unwrap();
        assert!(
            alice_circuit.queue(send, 78).is_err(),
            "one corr_id for each command"
        );
        let cell = alice_circuit.next_cell().unwrap().unwrap();
        assert!(alice_circuit.next_cell().unwrap().is_none());
        let (bucket, content) = relay_a.forward(&cell);
        let commands = unpack(&content, bucket).unwrap();
        let send = &commands[0];
        assert_eq!(
            (send.cmd, send.queue_id),
            (Cmd::Send, queue_to_bob.keys().sender_id)
        );
        relay_a
            .session
            .accept(send, &queue_to_bob.keys().qs_auth_pk)
            .unwrap();
        // The recipient key does not authorize a write.
        assert_eq!(
            relay_a
                .session
                .accept(send, &queue_to_bob.keys().qr_auth_pk),
            Err(Reject::Rejected)
        );
        let seq = queue_to_bob.send(send.payload, 10).unwrap();

        // The relay acknowledges with a QUOTA under the corr_id of the SEND.
        let remaining = u32::try_from(queue_to_bob.remaining())
            .unwrap()
            .to_be_bytes();
        let quota = Command {
            cmd: Cmd::Quota,
            corr_id: send.corr_id,
            queue_id: send.queue_id,
            auth: [0; 32],
            payload: &remaining,
        };
        let answer = relay_a.backward(Bucket::B0, &quota);
        let events = alice_circuit.receive_cell(&answer).unwrap();
        assert!(matches!(
            events[..],
            [Event::Answered {
                handle: 77,
                cmd: Cmd::Quota,
                ..
            }]
        ));
        assert_eq!(alice_circuit.pending(), 0);

        // The relay pushes the MSG to Bob.
        let stored = queue_to_bob.pending().next().unwrap().bytes.clone();
        let mut msg_payload = alloc::vec![0u8; 4 + stored.len()];
        msg_from_send(seq, &stored, Bucket::B0, &mut msg_payload).unwrap();
        let msg = Command {
            cmd: Cmd::Msg,
            corr_id: [8; 16],
            queue_id: *bob.inbound().recipient_id(),
            auth: [0; 32],
            payload: &msg_payload,
        };
        let cell = relay_b.backward(Bucket::B0, &msg);
        let events = bob_circuit.receive_cell(&cell).unwrap();
        let Event::Message {
            queue_id,
            bucket,
            payload,
        } = &events[0]
        else {
            panic!("{events:?}");
        };
        assert_eq!(queue_id, bob.inbound().recipient_id());
        let received = bob.receive(payload, *bucket, 20, &mut rng).unwrap();
        assert_eq!(
            received,
            Received::App {
                seq: 1,
                bytes: app.to_vec()
            }
        );
        assert_eq!(
            bob.receive(payload, *bucket, 21, &mut rng).unwrap(),
            Received::Duplicate
        );

        // Bob acknowledges after the commit, and the relay erases the record.
        let (point, ack) = bob
            .acknowledge(
                bob_circuit.relay_session_pk(),
                [4; 16],
                21 + RECEIPT_MIN_DELAY,
            )
            .unwrap()
            .unwrap();
        assert_eq!(point.seq, 1);
        bob_circuit.queue(ack, 2).unwrap();
        let cell = bob_circuit.next_cell().unwrap().unwrap();
        let (bucket, content) = relay_b.forward(&cell);
        let commands = unpack(&content, bucket).unwrap();
        relay_b
            .session
            .accept(&commands[0], &queue_to_bob.keys().qr_auth_pk)
            .unwrap();
        queue_to_bob.ack(u32::from_be_bytes(commands[0].payload.try_into().unwrap()));
        assert_eq!(queue_to_bob.pending().count(), 0);
        bob.acknowledged(point);
        assert!(bob
            .acknowledge(bob_circuit.relay_session_pk(), [5; 16], 23)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_nack_reaches_its_command_and_a_changed_cell_ends_the_circuit() {
        let (alice_ratchet, _) = ratchets();
        let (_, alice_out, _) = queue(40);
        let (_, _, alice_in) = queue(60);
        let mut alice = PairwiseChannel::new(alice_ratchet, alice_out, alice_in);
        let (mut session, mut relay) = circuit(100);
        let mut rng = Rng(5);

        let (_, send) = alice
            .send(
                &[7; 1_000],
                session.relay_session_pk(),
                [2; 16],
                [3; 12],
                10,
                &mut rng,
            )
            .unwrap();
        session.queue(send, 5).unwrap();
        let cell = session.next_cell().unwrap().unwrap();
        assert_eq!(
            cell.len(),
            Bucket::B1.cell_len(),
            "the record picks its bucket"
        );
        relay.forward(&cell);

        let mut payload = [0u8; 17];
        let nack = |corr_id| NackPayload {
            corr_id,
            reason: Reason::Limit,
        };
        nack([9; 16]).encode(&mut payload).unwrap();
        let stray = Command {
            cmd: Cmd::Nack,
            corr_id: [0; 16],
            queue_id: [0; 32],
            auth: [0; 32],
            payload: &payload,
        };
        let cell = relay.backward(Bucket::B0, &stray);
        assert!(
            session.receive_cell(&cell).unwrap().is_empty(),
            "no command has that corr_id"
        );

        let mut payload = [0u8; 17];
        nack([2; 16]).encode(&mut payload).unwrap();
        let named = Command {
            payload: &payload,
            ..stray
        };
        let cell = relay.backward(Bucket::B0, &named);
        assert_eq!(
            session.receive_cell(&cell).unwrap(),
            [Event::Rejected {
                handle: 5,
                reason: Reject::Limit
            }]
        );

        let cover = session.cover_cell(Bucket::B0).unwrap();
        assert_eq!(cover.len(), Bucket::B0.cell_len());
        relay.forward_any(&cover);

        let mut changed = relay.backward(Bucket::B0, &stray);
        changed[40] ^= 1;
        assert!(session.receive_cell(&changed).is_err());
    }
}
