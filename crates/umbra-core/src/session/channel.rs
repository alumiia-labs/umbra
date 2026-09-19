//! One pairwise channel between two devices (Part 3 §3.2, Part 5 §5.5,
//! Part 6 §6.4.2, §6.5): the ratchet, the queue that this device writes to,
//! and the queue that it reads. The send path turns an application record
//! into the payload of a `SEND`, and the receive path turns the payload of
//! a `MSG` back.

use alloc::vec::Vec;

use umbra_crypto::{
    auth::CommandAuthKey, queue::QueueKey, rand_core::CryptoRng, ratchet::braid::Ratchet,
    secret::Secret, x25519::StaticSecret,
};
use umbra_queue::client::ack::{AckCursor, AckPoint};
use umbra_wire::{
    address::QueueAddress,
    bucket::Bucket,
    command::{Cmd, Command},
    queue::{self, L6Kind},
};

use crate::Error;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// The queue of the peer, which this device writes to.
pub struct Outbound {
    sender_id: [u8; 32],
    auth_secret: StaticSecret,
    queue_key: QueueKey,
    relay_id: [u8; 32],
}

impl Outbound {
    /// The writer side of a `QueueAddress` that the peer gave.
    pub fn new(address: &QueueAddress) -> Self {
        Outbound {
            sender_id: address.sender_id,
            auth_secret: StaticSecret::from(*address.qs_auth_sk.expose()),
            queue_key: QueueKey::derive(&address.qe, &address.sender_id),
            relay_id: address.relay_id,
        }
    }

    /// The relay that holds the queue.
    pub fn relay_id(&self) -> &[u8; 32] {
        &self.relay_id
    }
}

/// The queue of this device, which the peer writes to.
pub struct Inbound {
    recipient_id: [u8; 32],
    sender_id: [u8; 32],
    auth_secret: StaticSecret,
    queue_key: QueueKey,
    cursor: AckCursor,
}

impl Inbound {
    /// The reader side of a queue: the two identifiers of the `IDS`, the
    /// private half of `QR_auth`, the queue secret `QE`, and the last
    /// sequence number that the device acknowledged.
    pub fn new(
        recipient_id: [u8; 32],
        sender_id: [u8; 32],
        qr_auth_sk: StaticSecret,
        queue_secret: &Secret<32>,
        acked: u32,
    ) -> Self {
        Inbound {
            recipient_id,
            sender_id,
            auth_secret: qr_auth_sk,
            queue_key: QueueKey::derive(queue_secret, &sender_id),
            cursor: AckCursor::new(acked),
        }
    }

    /// `RecipientId`, which names the queue in a `MSG`.
    pub fn recipient_id(&self) -> &[u8; 32] {
        &self.recipient_id
    }

    /// The cursor, for the gap state of the conversation.
    pub fn cursor(&self) -> &AckCursor {
        &self.cursor
    }
}

/// A record that the channel took from a `MSG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// An application record, in the encoding of Part 6 §6.6.
    App {
        /// The sequence number of the `MSG`.
        seq: u32,
        /// The `AppMessage` bytes.
        bytes: Vec<u8>,
    },
    /// A record that the queue already delivered.
    Duplicate,
    /// A record that does not open. It counts as received (`WIR-114`), and
    /// the failed check stays inside this device (`WIR-032`).
    Undecryptable {
        /// The sequence number of the `MSG`.
        seq: u32,
    },
}

fn signed(
    cmd: Cmd,
    queue_id: [u8; 32],
    corr_id: [u8; 16],
    payload: &[u8],
    auth_secret: &StaticSecret,
    relay_session_pk: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let key = CommandAuthKey::derive(auth_secret, relay_session_pk)?;
    let mut command = Command {
        cmd,
        corr_id,
        queue_id,
        auth: [0; 32],
        payload,
    };
    // NET-119: the bind of a queue command is empty.
    command.sign(&key, b"")?;
    let mut out = alloc::vec![0u8; command.len()];
    command.encode(&mut out)?;
    Ok(out)
}

/// The ratchet and the two queues of one channel.
pub struct PairwiseChannel {
    ratchet: Ratchet,
    outbound: Outbound,
    inbound: Inbound,
}

impl PairwiseChannel {
    /// A channel over a ratchet that the handshake of Part 5 §5.4 made.
    pub fn new(ratchet: Ratchet, outbound: Outbound, inbound: Inbound) -> Self {
        PairwiseChannel {
            ratchet,
            outbound,
            inbound,
        }
    }

    /// The queue that this device writes to.
    pub fn outbound(&self) -> &Outbound {
        &self.outbound
    }

    /// The queue that this device reads.
    pub fn inbound(&self) -> &Inbound {
        &self.inbound
    }

    /// The smallest bucket that holds an application record of `app_len`
    /// bytes with a default braid frame, or `None` when the record needs
    /// an attachment.
    pub fn bucket_for(&self, app_len: usize) -> Option<Bucket> {
        let overhead = self.ratchet.overhead_with_frame();
        BUCKETS
            .into_iter()
            .find(|bucket| app_len.saturating_add(overhead) <= bucket.l7_record())
    }

    /// Seals one application record into an encoded `SEND` for the queue
    /// of the peer. `relay_session_pk` is the session key of the circuit
    /// that carries the command, and `corr_id` and `nonce` come from the
    /// CSPRNG.
    pub fn send<R: CryptoRng + ?Sized>(
        &mut self,
        app: &[u8],
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
        nonce: [u8; 12],
        now: u64,
        rng: &mut R,
    ) -> Result<(Bucket, Vec<u8>), Error> {
        let bucket = self.bucket_for(app.len()).ok_or(Error::NoPath)?;
        let mut record = alloc::vec![0u8; bucket.l7_record()];
        let record_len = self.ratchet.send(app, true, now, rng, &mut record)?;
        let inner = record.get(..record_len).ok_or(Error::Malformed)?;
        let mut payload = alloc::vec![0u8; bucket.l6_record()];
        queue::seal(
            &self.outbound.queue_key,
            nonce,
            &self.outbound.sender_id,
            L6Kind::Ratchet,
            inner,
            bucket,
            &mut payload,
        )?;
        let encoded = signed(
            Cmd::Send,
            self.outbound.sender_id,
            corr_id,
            &payload,
            &self.outbound.auth_secret,
            relay_session_pk,
        )?;
        Ok((bucket, encoded))
    }

    /// Opens the payload of a `MSG` of the inbound queue. The caller
    /// commits the result to the store before it acknowledges
    /// (`WIR-115`).
    pub fn receive<R: CryptoRng + ?Sized>(
        &mut self,
        msg_payload: &[u8],
        bucket: Bucket,
        now: u64,
        rng: &mut R,
    ) -> Result<Received, Error> {
        let (seq, record) = queue::split_msg(msg_payload, bucket)?;
        if !self.inbound.cursor.receive(seq, now) {
            return Ok(Received::Duplicate);
        }
        let mut inner = alloc::vec![0u8; bucket.l6_record()];
        let opened = queue::open(
            &self.inbound.queue_key,
            &self.inbound.sender_id,
            record,
            bucket,
            &mut inner,
        );
        let Ok((L6Kind::Ratchet, inner_len)) = opened else {
            return Ok(Received::Undecryptable { seq });
        };
        let mut app = alloc::vec![0u8; bucket.l7_record()];
        let ratchet_record = inner.get(..inner_len).ok_or(Error::Malformed)?;
        match self.ratchet.receive(ratchet_record, now, rng, &mut app) {
            Ok(opened) => {
                app.truncate(opened.len);
                Ok(Received::App { seq, bytes: app })
            }
            Err(_) => Ok(Received::Undecryptable { seq }),
        }
    }

    /// The `SUB` of the inbound queue.
    pub fn subscribe(
        &self,
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
    ) -> Result<Vec<u8>, Error> {
        signed(
            Cmd::Sub,
            self.inbound.recipient_id,
            corr_id,
            &[],
            &self.inbound.auth_secret,
            relay_session_pk,
        )
    }

    /// The `ACK` that the cursor offers at `now`, with its point. The
    /// point never sits above a hole before `ACK_HOLE_TIMEOUT` (`WIR-112`,
    /// `WIR-113`). The caller gives the point back to
    /// [`PairwiseChannel::acknowledged`] after the command left.
    pub fn acknowledge(
        &self,
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
        now: u64,
    ) -> Result<Option<(AckPoint, Vec<u8>)>, Error> {
        let Some(point) = self.inbound.cursor.ack_point(now) else {
            return Ok(None);
        };
        let encoded = signed(
            Cmd::Ack,
            self.inbound.recipient_id,
            corr_id,
            &point.seq.to_be_bytes(),
            &self.inbound.auth_secret,
            relay_session_pk,
        )?;
        Ok(Some((point, encoded)))
    }

    /// Commits an `ACK` that the device sent.
    pub fn acknowledged(&mut self, point: AckPoint) {
        self.inbound.cursor.acknowledged(point);
    }
}
