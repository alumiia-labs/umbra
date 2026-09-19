//! The pairwise queues of one relay (Part 3 §3.2, Part 6 §6.4): `NEW`,
//! `SEND`, `SUB`, `UNSUB`, `ACK`, `NKEY`, and `DEL`, with the answer of
//! each one and the push of a `MSG` to the circuit that subscribed.

use std::collections::BTreeMap;

use umbra_core::abuse::admission::{Accepts, RelayGate};
use umbra_crypto::rand_core::CryptoRng;
use umbra_queue::{
    params::{INVITE_RESERVE_TTL, INVITE_TTL},
    relay::{
        queue::{Queue, QueueKeys},
        session::Session,
    },
    Reject,
};
use umbra_wire::{
    bucket::Bucket,
    command::{
        blob_bucket, iblob_payload, iput_parse, Cmd, Command, IdsPayload, NewPayload, IGET_LEN,
        LINK_ID_LEN,
    },
    queue::msg_from_send,
};

use super::{answer, Outbound, Reply};
use crate::circuits::CircuitKey;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// One invitation of Part 4 §4.3.1. The relay holds a ciphertext that it
/// cannot read, and the link identifier is no key of it.
struct Invitation {
    recipient_id: [u8; 32],
    /// `None` between the `IRES` and the `IPUT`.
    blob: Option<Vec<u8>>,
    /// The time of the `IRES`, and then the time of the `IPUT` (`IDN-126`).
    at: u64,
}

/// The queues of the relay, by `RecipientId`.
#[derive(Default)]
pub struct QueueService {
    /// The invitations, by link identifier. A queue holds one at most.
    invitations: BTreeMap<[u8; LINK_ID_LEN], Invitation>,
    queues: BTreeMap<[u8; 32], Queue>,
    /// `RecipientId` by `SenderId`.
    by_sender: BTreeMap<[u8; 32], [u8; 32]>,
    /// The circuit that holds the subscription of a queue.
    subscribers: BTreeMap<[u8; 32], CircuitKey>,
}

fn random_id<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut id = [0u8; 32];
    rng.fill_bytes(&mut id);
    id
}

/// The `MSG` of one stored record, in the bucket that its length gives.
fn msg_of<R: CryptoRng + ?Sized>(
    recipient_id: [u8; 32],
    seq: u32,
    record: &[u8],
    rng: &mut R,
) -> Option<Outbound> {
    let bucket = BUCKETS
        .into_iter()
        .find(|bucket| bucket.l6_record() == record.len())?;
    let mut payload = vec![0u8; record.len().saturating_add(4)];
    msg_from_send(seq, record, bucket, &mut payload).ok()?;
    let mut corr_id = [0u8; 16];
    // WIR-495: a command that the relay starts draws its own corr_id.
    rng.fill_bytes(&mut corr_id);
    let command = Command {
        cmd: Cmd::Msg,
        corr_id,
        queue_id: recipient_id,
        auth: [0; 32],
        payload: &payload,
    };
    let mut encoded = vec![0u8; command.len()];
    command.encode(&mut encoded).ok()?;
    Some(Outbound { bucket, encoded })
}

impl QueueService {
    /// The count of the queues.
    pub fn len(&self) -> usize {
        self.queues.len()
    }

    /// Whether the relay holds no queue.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Handles one command of the queue range on `circuit`.
    #[allow(clippy::too_many_arguments)]
    pub fn handle<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        gate: &mut RelayGate,
        accepts: &Accepts<'_>,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<Reply>, Reject> {
        match command.cmd {
            Cmd::New => {
                let new = NewPayload::parse(command.payload).map_err(|_| Reject::Rejected)?;
                session.accept(command, &new.qr_auth_pk)?;
                gate.admit(&new.admission, accepts, now)?;
                let keys = QueueKeys {
                    recipient_id: random_id(rng),
                    sender_id: random_id(rng),
                    qr_auth_pk: new.qr_auth_pk,
                    qs_auth_pk: new.qs_auth_pk,
                };
                let ids = IdsPayload {
                    recipient_id: keys.recipient_id,
                    sender_id: keys.sender_id,
                    relay_session_pk: session.relay_session_pk(),
                };
                session.bind_queue(keys.recipient_id)?;
                self.by_sender.insert(keys.sender_id, keys.recipient_id);
                self.queues.insert(keys.recipient_id, Queue::new(keys, now));
                let mut payload = [0u8; 96];
                ids.encode(&mut payload).map_err(|_| Reject::Busy)?;
                Ok(vec![answer(circuit, command, Cmd::Ids, &payload)])
            }
            Cmd::Send => {
                // WIR-317: an unknown queue and a failed auth give one reason.
                let recipient_id = *self
                    .by_sender
                    .get(&command.queue_id)
                    .ok_or(Reject::Rejected)?;
                let queue = self.queues.get_mut(&recipient_id).ok_or(Reject::Rejected)?;
                session.accept(command, &queue.keys().qs_auth_pk)?;
                let seq = queue.send(command.payload, now)?;
                let remaining = u32::try_from(queue.remaining()).unwrap_or(u32::MAX);
                // WIR-496: the QUOTA is the relay acknowledgment.
                let mut replies = vec![answer(
                    circuit,
                    command,
                    Cmd::Quota,
                    &remaining.to_be_bytes(),
                )];
                if let Some(subscriber) = self.subscribers.get(&recipient_id) {
                    if let Some(outbound) = msg_of(recipient_id, seq, command.payload, rng) {
                        replies.push(Reply {
                            circuit: *subscriber,
                            outbound,
                        });
                    }
                }
                Ok(replies)
            }
            Cmd::Iget => {
                // The party holds no key of the queue yet. It signs under
                // the lock key, thus the lock names a key that it holds.
                let payload: &[u8; IGET_LEN] =
                    command.payload.try_into().map_err(|_| Reject::Rejected)?;
                let (link_id, lock_pk) = payload.split_at(LINK_ID_LEN);
                let link_id: [u8; LINK_ID_LEN] =
                    link_id.try_into().map_err(|_| Reject::Rejected)?;
                let lock_pk: [u8; 32] = lock_pk.try_into().map_err(|_| Reject::Rejected)?;
                // WIR-317: an unknown link, a link with no blob, and a
                // failed auth give one reason.
                let held = self.invitations.get(&link_id).ok_or(Reject::Rejected)?;
                let blob = held.blob.as_ref().ok_or(Reject::Rejected)?;
                session.accept(command, &lock_pk)?;
                let bucket = blob_bucket(blob.len()).ok_or(Reject::Rejected)?;
                let payload = iblob_payload(blob, bucket).map_err(|_| Reject::Busy)?;
                // IDN-023: the first fetch takes the blob and locks the
                // queue. A second fetch finds no link.
                let recipient_id = held.recipient_id;
                self.invitations.remove(&link_id);
                if let Some(queue) = self.queues.get_mut(&recipient_id) {
                    queue.lock_sender(lock_pk);
                }
                Ok(vec![answer(circuit, command, Cmd::Iblob, &payload)])
            }
            Cmd::Sub | Cmd::Unsub | Cmd::Ack | Cmd::Del | Cmd::Nkey | Cmd::Ires | Cmd::Iput => {
                self.recipient_command(circuit, session, command, now, rng)
            }
            _ => Err(Reject::Rejected),
        }
    }

    fn recipient_command<R: CryptoRng + ?Sized>(
        &mut self,
        circuit: CircuitKey,
        session: &mut Session,
        command: &Command<'_>,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<Reply>, Reject> {
        let recipient_id = command.queue_id;
        let queue = self.queues.get_mut(&recipient_id).ok_or(Reject::Rejected)?;
        session.accept(command, &queue.keys().qr_auth_pk)?;
        match command.cmd {
            Cmd::Sub => {
                session.bind_queue(recipient_id)?;
                queue.subscribe(true, now);
                self.subscribers.insert(recipient_id, circuit);
                // WIR-110: each record that no ACK covers goes out.
                Ok(queue
                    .pending()
                    .filter_map(|stored| msg_of(recipient_id, stored.seq, &stored.bytes, rng))
                    .map(|outbound| Reply { circuit, outbound })
                    .collect())
            }
            Cmd::Unsub => {
                queue.subscribe(false, now);
                self.subscribers.remove(&recipient_id);
                Ok(Vec::new())
            }
            Cmd::Ack => {
                let seq: [u8; 4] = command.payload.try_into().map_err(|_| Reject::Rejected)?;
                queue.ack(u32::from_be_bytes(seq));
                Ok(Vec::new())
            }
            Cmd::Nkey => {
                let notifier_pk: [u8; 32] =
                    command.payload.try_into().map_err(|_| Reject::Rejected)?;
                let notifier_id = random_id(rng);
                queue.set_notifier(notifier_pk, notifier_id);
                Ok(vec![answer(circuit, command, Cmd::Nid, &notifier_id)])
            }
            Cmd::Ires => {
                // One queue holds one invitation. A second `IRES` takes the
                // place of the first, and the first link ends.
                self.invitations
                    .retain(|_, held| held.recipient_id != recipient_id);
                let mut link_id = [0u8; LINK_ID_LEN];
                rng.fill_bytes(&mut link_id);
                let reserved = Invitation {
                    recipient_id,
                    blob: None,
                    at: now,
                };
                self.invitations.insert(link_id, reserved);
                Ok(vec![answer(circuit, command, Cmd::Ilink, &link_id)])
            }
            Cmd::Iput => {
                let (link_id, blob) = iput_parse(command.payload).map_err(|_| Reject::Rejected)?;
                let held = self
                    .invitations
                    .get_mut(&link_id)
                    .filter(|held| held.recipient_id == recipient_id && held.blob.is_none())
                    .ok_or(Reject::Rejected)?;
                held.blob = Some(blob.to_vec());
                // IDN-126: the lifetime runs from the store of the blob.
                held.at = now;
                Ok(vec![answer(circuit, command, Cmd::Ilink, &link_id)])
            }
            Cmd::Del => {
                self.invitations
                    .retain(|_, held| held.recipient_id != recipient_id);
                // WIR-039 to WIR-042: no identifier of the queue stays.
                if let Some(queue) = self.queues.remove(&recipient_id) {
                    self.by_sender.remove(&queue.keys().sender_id);
                    drop(queue.delete());
                }
                self.subscribers.remove(&recipient_id);
                Ok(Vec::new())
            }
            _ => Err(Reject::Rejected),
        }
    }

    /// A circuit ended, thus its subscriptions end.
    pub fn circuit_closed(&mut self, circuit: &CircuitKey, now: u64) {
        let ended: Vec<[u8; 32]> = self
            .subscribers
            .iter()
            .filter(|(_, held)| *held == circuit)
            .map(|(recipient_id, _)| *recipient_id)
            .collect();
        for recipient_id in ended {
            self.subscribers.remove(&recipient_id);
            if let Some(queue) = self.queues.get_mut(&recipient_id) {
                queue.subscribe(false, now);
            }
        }
    }

    /// Expires each record past `MSG_TTL`, and erases each idle queue.
    pub fn sweep(&mut self, now: u64) {
        self.invitations.retain(|_, held| {
            let limit = match held.blob {
                Some(_) => INVITE_TTL,
                None => INVITE_RESERVE_TTL,
            };
            now.saturating_sub(held.at) < limit
        });
        for queue in self.queues.values_mut() {
            queue.expire(now);
        }
        let idle: Vec<[u8; 32]> = self
            .queues
            .iter()
            .filter(|(_, queue)| queue.idle(now))
            .map(|(recipient_id, _)| *recipient_id)
            .collect();
        for recipient_id in idle {
            if let Some(queue) = self.queues.remove(&recipient_id) {
                self.by_sender.remove(&queue.keys().sender_id);
            }
            self.subscribers.remove(&recipient_id);
        }
    }
}
