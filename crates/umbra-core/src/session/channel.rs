//! One pairwise channel between two devices (Part 3 §3.2, Part 5 §5.5,
//! Part 6 §6.4.2, §6.5): the ratchet, the queue that this device writes to,
//! and the queue that it reads. The send path turns an application record
//! into the payload of a `SEND`, and the receive path turns the payload of
//! a `MSG` back.
//!
//! The two queue ends stand alone too, because the handshake of Part 5
//! §5.4 uses them before a ratchet exists.

use alloc::vec::Vec;

use umbra_crypto::{
    auth::CommandAuthKey,
    queue::QueueKey,
    rand_core::CryptoRng,
    ratchet::braid::Ratchet,
    secret::Secret,
    stored::{Reader, Writer},
    x25519::{PublicKey as XPublic, StaticSecret},
    zeroize::Zeroizing,
};
use umbra_queue::client::ack::{AckCursor, AckPoint};
use umbra_wire::{
    address::QueueAddress,
    admission::{Admission, AdmissionKind},
    bucket::Bucket,
    command::{Cmd, Command, NewPayload},
    queue::{self, L6Kind},
};

use crate::Error;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

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

/// The `NEW` of a queue under the two auth keys of its owner, with no
/// credential. A relay under load asks for one with a `NACK` (`WIR-325`).
pub fn new_queue_command(
    qr_auth_secret: &StaticSecret,
    qs_auth_secret: &StaticSecret,
    relay_session_pk: &[u8; 32],
    corr_id: [u8; 16],
) -> Result<Vec<u8>, Error> {
    let new = NewPayload {
        qr_auth_pk: *XPublic::from(qr_auth_secret).as_bytes(),
        qs_auth_pk: *XPublic::from(qs_auth_secret).as_bytes(),
        admission: Admission {
            kind: AdmissionKind::None,
            body: &[],
        },
    };
    let mut payload = [0u8; 67];
    let used = new.encode(&mut payload)?;
    signed(
        Cmd::New,
        [0; 32],
        corr_id,
        payload.get(..used).ok_or(Error::Malformed)?,
        qr_auth_secret,
        relay_session_pk,
    )
}

/// The queue of the peer, which this device writes to.
pub struct Outbound {
    sender_id: [u8; 32],
    auth_secret: StaticSecret,
    queue_key: QueueKey,
    relay_id: [u8; 32],
}

impl Outbound {
    fn export(&self, writer: &mut Writer) {
        writer.bytes(&self.sender_id);
        writer.bytes(self.auth_secret.as_bytes());
        self.queue_key.export(writer);
        writer.bytes(&self.relay_id);
    }

    fn restore(reader: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Outbound {
            sender_id: reader.array()?,
            auth_secret: StaticSecret::from(reader.array::<32>()?),
            queue_key: QueueKey::restore(reader)?,
            relay_id: reader.array()?,
        })
    }

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

    /// Seals one inner record of `kind` into an encoded `SEND`, in the
    /// smallest bucket that holds it. `corr_id` and `nonce` come from the
    /// CSPRNG.
    pub fn send_record(
        &self,
        kind: L6Kind,
        inner: &[u8],
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
        nonce: [u8; 12],
    ) -> Result<(Bucket, Vec<u8>), Error> {
        let bucket = BUCKETS
            .into_iter()
            .find(|bucket| inner.len() <= bucket.l7_record())
            .ok_or(Error::NoPath)?;
        let mut payload = alloc::vec![0u8; bucket.l6_record()];
        queue::seal(
            &self.queue_key,
            nonce,
            &self.sender_id,
            kind,
            inner,
            bucket,
            &mut payload,
        )?;
        let encoded = signed(
            Cmd::Send,
            self.sender_id,
            corr_id,
            &payload,
            &self.auth_secret,
            relay_session_pk,
        )?;
        Ok((bucket, encoded))
    }
}

/// What the reader end took from a `MSG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// One inner record.
    Record {
        /// The sequence number of the `MSG`.
        seq: u32,
        /// The L6 kind.
        kind: L6Kind,
        /// The inner record.
        inner: Vec<u8>,
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

/// The queue of this device, which the peer writes to.
pub struct Inbound {
    recipient_id: [u8; 32],
    sender_id: [u8; 32],
    auth_secret: StaticSecret,
    queue_key: QueueKey,
    cursor: AckCursor,
}

impl Inbound {
    /// Writes the queue end for the at-rest store.
    pub fn export(&self, writer: &mut Writer) -> Result<(), Error> {
        writer.bytes(&self.recipient_id);
        writer.bytes(&self.sender_id);
        writer.bytes(self.auth_secret.as_bytes());
        self.queue_key.export(writer);
        Ok(self.cursor.export(writer)?)
    }

    /// Reads the queue end that [`Inbound::export`] wrote.
    pub fn restore(reader: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Inbound {
            recipient_id: reader.array()?,
            sender_id: reader.array()?,
            auth_secret: StaticSecret::from(reader.array::<32>()?),
            queue_key: QueueKey::restore(reader)?,
            cursor: AckCursor::restore(reader)?,
        })
    }

    /// The `ACK` at the point that the device acknowledged last, or `None`
    /// before the first one. A device sends it after a restart, because the
    /// `ACK` of the last run can be lost with its link, and the relay
    /// would deliver those records at each later `SUB`.
    pub fn acknowledge_again(
        &self,
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
    ) -> Result<Option<Vec<u8>>, Error> {
        let acked = self.cursor.acked();
        if acked == 0 {
            return Ok(None);
        }
        signed(
            Cmd::Ack,
            self.recipient_id,
            corr_id,
            &acked.to_be_bytes(),
            &self.auth_secret,
            relay_session_pk,
        )
        .map(Some)
    }

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

    /// Opens the payload of a `MSG` down to its inner record.
    pub fn open(&mut self, msg_payload: &[u8], bucket: Bucket, now: u64) -> Result<Opened, Error> {
        let (seq, record) = queue::split_msg(msg_payload, bucket)?;
        if !self.cursor.receive(seq, now) {
            return Ok(Opened::Duplicate);
        }
        let mut inner = alloc::vec![0u8; bucket.l6_record()];
        match queue::open(&self.queue_key, &self.sender_id, record, bucket, &mut inner) {
            Ok((kind, len)) => {
                inner.truncate(len);
                Ok(Opened::Record { seq, kind, inner })
            }
            Err(_) => Ok(Opened::Undecryptable { seq }),
        }
    }

    /// The `SUB` of the queue.
    pub fn subscribe(
        &self,
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
    ) -> Result<Vec<u8>, Error> {
        signed(
            Cmd::Sub,
            self.recipient_id,
            corr_id,
            &[],
            &self.auth_secret,
            relay_session_pk,
        )
    }

    /// The `ACK` that the cursor offers at `now`, with its point. The
    /// point never sits above a hole before `ACK_HOLE_TIMEOUT` (`WIR-112`,
    /// `WIR-113`). The caller gives the point back to
    /// [`Inbound::acknowledged`] after the command left.
    pub fn acknowledge(
        &self,
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
        now: u64,
    ) -> Result<Option<(AckPoint, Vec<u8>)>, Error> {
        let Some(point) = self.cursor.ack_point(now) else {
            return Ok(None);
        };
        let encoded = signed(
            Cmd::Ack,
            self.recipient_id,
            corr_id,
            &point.seq.to_be_bytes(),
            &self.auth_secret,
            relay_session_pk,
        )?;
        Ok(Some((point, encoded)))
    }

    /// Commits an `ACK` that the device sent.
    pub fn acknowledged(&mut self, point: AckPoint) {
        self.cursor.acknowledged(point);
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
    /// A record that does not open, or a record of another kind than a
    /// ratchet record.
    Undecryptable {
        /// The sequence number of the `MSG`.
        seq: u32,
    },
}

/// The ratchet and the two queues of one channel.
pub struct PairwiseChannel {
    ratchet: Ratchet,
    outbound: Outbound,
    inbound: Inbound,
}

/// The version byte of a stored channel.
const STORED_VERSION: u8 = 0x01;

impl PairwiseChannel {
    /// Writes the channel for the at-rest store: the two queue ends and the
    /// ratchet. A client stores it before a record of
    /// [`PairwiseChannel::send`] leaves the device, and in the batch that
    /// commits a record of [`PairwiseChannel::receive`].
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut writer = Writer::new();
        writer.u8(STORED_VERSION);
        self.outbound.export(&mut writer);
        self.inbound.export(&mut writer)?;
        writer.var(&self.ratchet.export()?)?;
        Ok(writer.finish())
    }

    /// Reads the channel that [`PairwiseChannel::export`] wrote.
    pub fn restore(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        if reader.u8()? != STORED_VERSION {
            return Err(Error::Malformed);
        }
        let outbound = Outbound::restore(&mut reader)?;
        let inbound = Inbound::restore(&mut reader)?;
        let ratchet = Ratchet::restore(reader.var()?)?;
        reader.end()?;
        Ok(PairwiseChannel {
            ratchet,
            outbound,
            inbound,
        })
    }

    /// A channel over a ratchet that the handshake of Part 5 §5.4 made.
    pub fn new(ratchet: Ratchet, outbound: Outbound, inbound: Inbound) -> Self {
        PairwiseChannel {
            ratchet,
            outbound,
            inbound,
        }
    }

    /// Whether the ratchet holds a sending chain. The inviter holds none
    /// before the first record of the invitee arrives (`NET-292`).
    pub fn can_send(&self) -> bool {
        self.ratchet.can_send()
    }

    /// Takes the newest `QueueAddress` of the peer as the queue that this
    /// device writes to (`NET-179`).
    pub fn accept_address(&mut self, address: &QueueAddress) {
        self.outbound = Outbound::new(address);
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
        self.outbound
            .send_record(L6Kind::Ratchet, inner, relay_session_pk, corr_id, nonce)
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
        let (seq, inner) = match self.inbound.open(msg_payload, bucket, now)? {
            Opened::Duplicate => return Ok(Received::Duplicate),
            Opened::Undecryptable { seq } => return Ok(Received::Undecryptable { seq }),
            Opened::Record {
                seq,
                kind: L6Kind::Ratchet,
                inner,
            } => (seq, inner),
            Opened::Record { seq, .. } => return Ok(Received::Undecryptable { seq }),
        };
        let mut app = alloc::vec![0u8; bucket.l7_record()];
        match self.ratchet.receive(&inner, now, rng, &mut app) {
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
        self.inbound.subscribe(relay_session_pk, corr_id)
    }

    /// The `ACK` that the cursor offers at `now`, with its point.
    pub fn acknowledge(
        &self,
        relay_session_pk: &[u8; 32],
        corr_id: [u8; 16],
        now: u64,
    ) -> Result<Option<(AckPoint, Vec<u8>)>, Error> {
        self.inbound.acknowledge(relay_session_pk, corr_id, now)
    }

    /// Commits an `ACK` that the device sent.
    pub fn acknowledged(&mut self, point: AckPoint) {
        self.inbound.acknowledged(point);
    }
}
