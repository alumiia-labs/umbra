//! The session of one circuit to one relay (Part 3 §3.4, Part 6 §6.3,
//! §6.4): the ready commands go into `DATA` cells under the three onion
//! layers, and each inbound cell comes back as the answers and the records
//! that it carries.
//!
//! The session reads no clock and opens no socket. The caller moves the
//! cells through the link of the transport crate, and it takes a cover
//! cell from here when the cover clock ticks with nothing ready.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_onion::circuit::Circuit;
use umbra_queue::Reject;
use umbra_wire::{
    bucket::Bucket,
    cell::{pad_body, unpad_body, Cell, CellCommand},
    command::{Cmd, Command},
    group::GroupCmd,
    nack::{NackPayload, Reason},
};

use super::batch::{smallest_bucket, unpack, Batcher, Range};
use crate::Error;

/// What an inbound cell carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A `MSG` of a queue that this session subscribed to.
    Message {
        /// `RecipientId`.
        queue_id: [u8; 32],
        /// The bucket of the cell, which gives the record length.
        bucket: Bucket,
        /// The payload of the `MSG`.
        payload: Vec<u8>,
    },
    /// The relay answered a command of this session. For a `SEND` the
    /// answer is a `QUOTA`, which is the relay acknowledgment of the ARQ.
    Answered {
        /// The handle that the caller gave the command.
        handle: u64,
        /// The command of the answer.
        cmd: Cmd,
        /// The payload of the answer.
        payload: Vec<u8>,
    },
    /// The relay rejected a command of this session. The reason goes to
    /// the ARQ and to the user, and to no other party (`WIR-326`).
    Rejected {
        /// The handle that the caller gave the command.
        handle: u64,
        /// The reason of the `NACK`.
        reason: Reject,
    },
    /// A command that the relay started, other than a `MSG`.
    Relay {
        /// The command.
        cmd: Cmd,
        /// The identifier that the command names.
        queue_id: [u8; 32],
        /// The payload.
        payload: Vec<u8>,
    },
}

fn reject_of(reason: Reason) -> Reject {
    match reason {
        Reason::Rejected => Reject::Rejected,
        Reason::Admission => Reject::Admission,
        Reason::Limit => Reject::Limit,
        Reason::Busy => Reject::Busy,
        Reason::Version => Reject::Version,
    }
}

/// One circuit with the commands that wait on it.
pub struct CircuitSession {
    circuit: Circuit,
    relay_session_pk: [u8; 32],
    batcher: Batcher,
    /// The handle of each command that holds no answer yet, by `corr_id`.
    pending: BTreeMap<[u8; 16], u64>,
}

impl CircuitSession {
    /// A session over a built circuit. `relay_session_pk` is the `er` of
    /// the reply of the last hop. The session carries the commands of one
    /// range.
    pub fn new(circuit: Circuit, relay_session_pk: [u8; 32], range: Range) -> Self {
        CircuitSession {
            circuit,
            relay_session_pk,
            batcher: Batcher::new(range),
            pending: BTreeMap::new(),
        }
    }

    /// The cells sent and received, against `CIRCUIT_MAX_CELLS`.
    pub fn cells(&self) -> (u32, u32) {
        self.circuit.cells()
    }

    /// The identifier of the circuit, which leads each cell of it.
    pub fn circ_id(&self) -> [u8; 16] {
        self.circuit.circ_id()
    }

    /// `RelaySession_pk`, which keys the authenticator of each command on
    /// this circuit.
    pub fn relay_session_pk(&self) -> &[u8; 32] {
        &self.relay_session_pk
    }

    /// The count of the commands that hold no answer.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether a command waits for a cell.
    pub fn has_ready(&self) -> bool {
        !self.batcher.is_empty()
    }

    /// Queues an encoded command under a handle of the caller. A `corr_id`
    /// that this session used is rejected, because the relay rejects it
    /// (`NET-122`). The result says whether an answer will name the handle.
    pub fn queue(&mut self, encoded: Vec<u8>, handle: u64) -> Result<bool, Error> {
        let (cmd, corr_id) = {
            // A `SEND` fills the command area of its bucket, thus the
            // smallest bucket that holds the command is its bucket.
            let bucket = smallest_bucket(encoded.len()).ok_or(Error::Malformed)?;
            let (command, used) = Command::parse(&encoded, bucket)?;
            if used != encoded.len() {
                return Err(Error::Malformed);
            }
            (command.cmd, command.corr_id)
        };
        if self.pending.contains_key(&corr_id) {
            return Err(Error::Stale);
        }
        self.batcher.push(cmd, encoded)?;
        // A relay gives these no answer but a `NACK`, thus nothing waits
        // for one. A `NACK` of one of them names no command here, and
        // `WIR-323` drops it: the records of a lost `ACK` come again.
        // A `CRNW` of Part 13 has no answer at all (`ATT-126`), and neither
        // has an `NBIND` (`NTF-129`). Of the group range only a `GNEW` and
        // a `GPOST` are answered (§6.4.5).
        const CRNW: u8 = 0x7A;
        let awaits = !matches!(
            cmd,
            Cmd::Ack
                | Cmd::Sub
                | Cmd::Unsub
                | Cmd::Del
                | Cmd::Nbind
                | Cmd::Attachment(CRNW)
                | Cmd::Group(
                    GroupCmd::Gsub
                        | GroupCmd::Gunsub
                        | GroupCmd::Gkey
                        | GroupCmd::Gdel
                        | GroupCmd::Gnreg
                        | GroupCmd::Gnunreg
                )
        );
        if awaits {
            self.pending.insert(corr_id, handle);
        }
        Ok(awaits)
    }

    /// Puts a `COVER` of the shape of a `B0` `SEND` with the ready commands
    /// (`WIR-015`). A relay gives no answer, thus nothing waits for one.
    pub fn queue_cover(&mut self, corr_id: [u8; 16]) -> Result<(), Error> {
        let payload = alloc::vec![0u8; Bucket::B0.l5_payload()];
        let cover = Command {
            cmd: Cmd::Cover,
            corr_id,
            queue_id: [0; 32],
            auth: [0; 32],
            payload: &payload,
        };
        let mut encoded = alloc::vec![0u8; cover.len()];
        cover.encode(&mut encoded)?;
        self.batcher.push(Cmd::Cover, encoded)
    }

    fn seal_cell(
        &mut self,
        bucket: Bucket,
        command: CellCommand,
        content: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut cell = alloc::vec![0u8; bucket.cell_len()];
        let (head, body) = cell.split_at_mut(32);
        pad_body(bucket, command, content, body)?;
        let tag = self.circuit.seal(body).map_err(|_| Error::Unverified)?;
        let (circ_id, tag_out) = head.split_at_mut(16);
        circ_id.copy_from_slice(&self.circuit.circ_id());
        tag_out.copy_from_slice(&tag);
        Ok(cell)
    }

    /// The next cell with the ready commands, or `None` when none waits.
    pub fn next_cell(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let Some((bucket, content)) = self.batcher.next_cell() else {
            return Ok(None);
        };
        self.seal_cell(bucket, CellCommand::Data, &content)
            .map(Some)
    }

    /// A loop cover cell for a tick of the cover clock with nothing ready
    /// (Part 3 §3.6). Each hop sees a cell of the common shape.
    pub fn cover_cell(&mut self, bucket: Bucket) -> Result<Vec<u8>, Error> {
        self.seal_cell(bucket, CellCommand::Loop, &[])
    }

    /// Removes the three layers of an inbound cell and reads its commands.
    /// A cell that fails the check of the onion layer gives an error, and
    /// the caller tears the circuit down (`NET-130`).
    pub fn receive_cell(&mut self, cell: &[u8]) -> Result<Vec<Event>, Error> {
        let (parsed, bucket) = Cell::parse(cell)?;
        if *parsed.circ_id != self.circuit.circ_id() {
            return Err(Error::Unverified);
        }
        let mut body = parsed.body.to_vec();
        self.circuit
            .open(parsed.tag, &mut body)
            .map_err(|_| Error::Unverified)?;
        let (command, content) = unpad_body(&body)?;
        if command != CellCommand::Data {
            // A reflected cover cell and a padding cell carry no command.
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for command in unpack(content, bucket)? {
            if let Some(event) = self.event_of(&command, bucket)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    fn event_of(&mut self, command: &Command<'_>, bucket: Bucket) -> Result<Option<Event>, Error> {
        let payload = command.payload.to_vec();
        Ok(match command.cmd {
            Cmd::Cover => None,
            Cmd::Msg => Some(Event::Message {
                queue_id: command.queue_id,
                bucket,
                payload,
            }),
            Cmd::Nack => {
                let nack = NackPayload::parse(command.payload)?;
                // WIR-323: a NACK that names no command of this session.
                self.pending
                    .remove(&nack.corr_id)
                    .map(|handle| Event::Rejected {
                        handle,
                        reason: reject_of(nack.reason),
                    })
            }
            cmd => Some(match self.pending.remove(&command.corr_id) {
                Some(handle) => Event::Answered {
                    handle,
                    cmd,
                    payload,
                },
                None => Event::Relay {
                    cmd,
                    queue_id: command.queue_id,
                    payload,
                },
            }),
        })
    }
}
