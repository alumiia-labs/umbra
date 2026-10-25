//! The services of a relay at the end of a circuit: the pairwise queues,
//! the group queues, and the chunk store. Each service takes one command
//! and gives the commands that go back. A record for the circuit of a
//! subscriber is an arrival, which holds no copy of the record.

use umbra_queue::Reject;
use umbra_wire::{
    address::LEN as QUEUE_ADDRESS_LEN,
    bucket::Bucket,
    command::{Cmd, Command},
    nack::{NackPayload, Reason},
};

use crate::circuits::CircuitKey;

pub mod chunk;
pub mod group;
pub mod queue;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// A digest for the runtime to write as a `SEND` into a notify queue. The
/// relay is a sender there, over a circuit of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestDue {
    /// The `GroupQueueId` of the group (`NTF-099`).
    pub id: [u8; 32],
    /// The encoded `QueueAddress` of the notify queue.
    pub queue: [u8; QUEUE_ADDRESS_LEN],
    /// The posts since the previous digest.
    pub post_count: u8,
}

/// One encoded command of the relay, with the bucket of its cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// The bucket.
    pub bucket: Bucket,
    /// The encoded command.
    pub encoded: Vec<u8>,
}

/// The bytes of the records that the drains of one circuit name at most
/// (`NET-349`). A `SUB` or a `GSUB` of a full queue fits.
pub const DRAIN_MAX: usize = 40 << 20;

/// The drains that one circuit may ask for in a minute, the refused ones
/// too. A session holds `MAX_QUEUES_PER_SESSION` queues, thus a client that
/// subscribes each of them and asks one time more for each stays inside it.
/// The check of a drain reads the length of each record of its backlog.
/// This bound keeps a circuit that repeats a refused drain from that work.
pub const DRAINS_PER_MINUTE: u32 = 16;

/// One drain of a circuit (`NET-037`): the records of one queue above
/// `after` and below `end`, which leave in the steps of the clock
/// (`NET-349`). A drain holds a place in the queue and no record: each step
/// reads its records from the queue. Before this, a drain was a copy of
/// each record of its backlog, and the relay made it before it read the
/// bound. A circuit that asked again for a full queue thus cost the relay
/// that copy each time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drain {
    /// The queue: a `RecipientId` or a `GroupQueueId`.
    pub queue_id: [u8; 32],
    /// The sequence of the last record that left.
    pub after: u32,
    /// The sequence of the first record after the drain. A record at or
    /// above it arrived after the subscription, and it goes as a live one.
    pub end: u32,
    /// The bytes of the records that the drain still names.
    pub left: usize,
}

/// One record that arrived at a queue with a live subscription, for the
/// circuit of that subscription. The node holds it as a place in its queue
/// and reads the record at its tick (`NET-365`). Before this, a service gave
/// a copy of the record. One `GPOST` then held a copy for each circuit that
/// subscribed, and the bound of the answers of a circuit dropped live
/// records with no command that went again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    /// The circuit of the subscription.
    pub circuit: CircuitKey,
    /// The queue: a `RecipientId` or a `GroupQueueId`.
    pub queue_id: [u8; 32],
    /// The sequence of the record.
    pub seq: u32,
}

impl Arrival {
    /// The place of the record in its queue, as a drain of that one record.
    pub fn place(&self) -> Drain {
        Drain {
            queue_id: self.queue_id,
            after: self.seq.saturating_sub(1),
            end: self.seq.saturating_add(1),
            left: 0,
        }
    }
}

/// The drains of one circuit, and the count of those it asked for in the
/// minute that runs.
#[derive(Debug, Default)]
pub struct Drains {
    held: Vec<Drain>,
    /// The backlogs at or below `DRAIN_THRESHOLD`, which leave on the
    /// pacing clock one record at each tick (`NET-365`). Each one holds a
    /// place in its queue and no record, as a drain does. Before this, a
    /// `SUB` copied each record of such a backlog at once, and each `SUB`
    /// again copied it again: one cell of `SUB` commands made the relay
    /// build and hold many copies of one backlog.
    paced: Vec<Drain>,
    /// The queues of the paced backlogs since the last
    /// [`Drains::take_fresh`], in their order.
    fresh: Vec<[u8; 32]>,
    asked: (u64, u32),
}

impl Drains {
    /// Admits a drain of `queue_id` whose records have the lengths
    /// `lengths`, and gives the bytes that it names. It reads no record. A
    /// circuit above `DRAINS_PER_MINUTE` gets `LIMIT` (`NET-349`). A drain
    /// that finds no room under `DRAIN_MAX` beside the drains of the other
    /// queues of the circuit gets `LIMIT` too.
    pub fn admit(
        &mut self,
        queue_id: &[u8; 32],
        lengths: impl Iterator<Item = usize>,
        now: u64,
    ) -> Result<usize, Reject> {
        let minute = now / 60;
        if self.asked.0 != minute {
            self.asked = (minute, 0);
        }

        if self.asked.1 >= DRAINS_PER_MINUTE {
            return Err(Reject::Limit);
        }

        self.asked.1 = self.asked.1.saturating_add(1);

        let named = self
            .held
            .iter()
            .filter(|drain| drain.queue_id != *queue_id)
            .fold(0usize, |sum, drain| sum.saturating_add(drain.left));
        let room = DRAIN_MAX.saturating_sub(named);

        let mut bytes = 0usize;
        for len in lengths {
            bytes = bytes.saturating_add(len);
            if bytes > room {
                return Err(Reject::Limit);
            }
        }

        Ok(bytes)
    }

    /// Holds `drain`. It takes the place of an earlier drain of its queue:
    /// the client named a new cursor, and the records below it serve no
    /// one.
    pub fn hold(&mut self, drain: Drain) {
        self.end(&drain.queue_id);
        self.held.push(drain);
    }

    /// Holds the backlog of a `SUB` or a `GSUB` at or below
    /// `DRAIN_THRESHOLD`, which leaves on the pacing clock. It takes the
    /// place of an earlier drain or backlog of its queue, as
    /// [`Drains::hold`] does.
    pub fn pace(&mut self, backlog: Drain) {
        self.end(&backlog.queue_id);
        if !self.fresh.contains(&backlog.queue_id) {
            self.fresh.push(backlog.queue_id);
        }
        self.paced.push(backlog);
    }

    /// The queues of the backlogs that [`Drains::pace`] took since the
    /// last call. The node gives each one its place among the answers.
    pub fn take_fresh(&mut self) -> Vec<[u8; 32]> {
        core::mem::take(&mut self.fresh)
    }

    /// The paced backlog of `queue_id`, if the circuit holds one.
    pub fn paced_mut(&mut self, queue_id: &[u8; 32]) -> Option<&mut Drain> {
        self.paced
            .iter_mut()
            .find(|backlog| backlog.queue_id == *queue_id)
    }

    /// Ends the paced backlog of `queue_id`: its last record left.
    pub fn end_paced(&mut self, queue_id: &[u8; 32]) {
        self.paced.retain(|backlog| backlog.queue_id != *queue_id);
    }

    /// Ends the drain and the paced backlog of `queue_id`, if the circuit
    /// holds one.
    pub fn end(&mut self, queue_id: &[u8; 32]) {
        self.held.retain(|drain| drain.queue_id != *queue_id);
        self.end_paced(queue_id);
    }

    /// Ends each drain and each paced backlog: the client of the circuit
    /// paused its session, and its subscriptions ended with it.
    pub fn end_all(&mut self) {
        self.held.clear();
        self.paced.clear();
        self.fresh.clear();
    }

    /// Ends the drain that took the last step.
    pub fn end_first(&mut self) {
        if !self.held.is_empty() {
            self.held.remove(0);
        }
    }

    /// Whether the circuit holds no drain. A paced backlog does not count:
    /// the pacing clock sends it, and the clock of the drains does not.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The drain that takes the next step: the oldest one.
    pub fn first_mut(&mut self) -> Option<&mut Drain> {
        self.held.first_mut()
    }

    /// The drain of `queue_id`, for a test.
    #[doc(hidden)]
    pub fn of(&self, queue_id: &[u8; 32]) -> Option<&Drain> {
        self.held.iter().find(|drain| drain.queue_id == *queue_id)
    }
}

/// A command of the relay for one circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The circuit that takes the command.
    pub circuit: CircuitKey,
    /// The command.
    pub outbound: Outbound,
}

fn encode(cmd: Cmd, corr_id: [u8; 16], queue_id: [u8; 32], payload: &[u8]) -> Outbound {
    let command = Command {
        cmd,
        corr_id,
        queue_id,
        auth: [0; 32],
        payload,
    };

    let mut encoded = vec![0u8; command.len()];
    // The buffer has the length of the command, thus the write cannot fail.
    let _ = command.encode(&mut encoded);

    let bucket = BUCKETS
        .into_iter()
        .find(|bucket| encoded.len() <= bucket.command_area())
        .unwrap_or(Bucket::B3);

    Outbound { bucket, encoded }
}

/// The answer to `command`, under its `corr_id` (`WIR-494`).
pub fn answer(circuit: CircuitKey, command: &Command<'_>, cmd: Cmd, payload: &[u8]) -> Reply {
    Reply {
        circuit,
        outbound: encode(cmd, command.corr_id, command.queue_id, payload),
    }
}

/// The `NACK` of a rejected command, in bucket `B0` (`WIR-313`, `WIR-314`,
/// `WIR-319`).
pub fn nack(circuit: CircuitKey, command: &Command<'_>, reject: Reject) -> Reply {
    let reason = match reject {
        Reject::Rejected => Reason::Rejected,
        Reject::Admission => Reason::Admission,
        Reject::Limit => Reason::Limit,
        Reject::Busy => Reason::Busy,
        Reject::Version => Reason::Version,
    };

    let mut payload = [0u8; 17];
    let _ = NackPayload {
        corr_id: command.corr_id,
        reason,
    }
    .encode(&mut payload);

    answer(circuit, command, Cmd::Nack, &payload)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MIB: usize = 1 << 20;

    fn drain(queue: u8, left: usize) -> Drain {
        Drain {
            queue_id: [queue; 32],
            after: 0,
            end: 100,
            left,
        }
    }

    #[test]
    fn a_drain_finds_its_room_from_the_lengths_alone_and_before_any_copy() {
        let mut drains = Drains::default();
        // NET-349: a full group queue fits, and the drains hold it.
        let bytes = drains
            .admit(&[1; 32], core::iter::repeat_n(MIB, 32), 60)
            .unwrap();
        assert_eq!(bytes, 32 * MIB);
        drains.hold(drain(1, bytes));

        // A drain of another queue finds what the first one left of
        // `DRAIN_MAX`, and one above it gets `LIMIT`. The check stops at
        // the record that passes the room: it reads no length after it.
        let mut read = 0usize;
        let lengths = core::iter::repeat_n(MIB, 1_000).inspect(|_| read += 1);
        assert_eq!(drains.admit(&[2; 32], lengths, 60), Err(Reject::Limit));
        assert_eq!(read, 9);

        let bytes = drains
            .admit(&[2; 32], core::iter::repeat_n(MIB, 8), 60)
            .unwrap();
        drains.hold(drain(2, bytes));

        // A new drain of a queue takes the place of the one before it,
        // thus its own bytes count for nothing against it.
        assert!(drains
            .admit(&[1; 32], core::iter::repeat_n(MIB, 32), 60)
            .is_ok());
        assert_eq!(
            drains.admit(&[1; 32], core::iter::repeat_n(MIB, 33), 60),
            Err(Reject::Limit)
        );

        drains.hold(drain(1, 5 * MIB));
        assert_eq!(drains.of(&[1; 32]).unwrap().left, 5 * MIB);
        assert_eq!(drains.of(&[2; 32]).unwrap().left, 8 * MIB);

        // The drains take their steps in the order of their arrival.
        assert_eq!(drains.first_mut().unwrap().queue_id, [2; 32]);
        drains.end_first();
        drains.end(&[1; 32]);
        assert!(drains.is_empty());
    }

    #[test]
    fn a_circuit_asks_for_a_bounded_count_of_drains_in_a_minute() {
        let mut drains = Drains::default();
        let minute = 6_000;

        // The refused ones count too: the fifth and each later one is above
        // the room, and each costs one of the count.
        for asked in 0..DRAINS_PER_MINUTE {
            let lengths = core::iter::repeat_n(DRAIN_MAX, if asked < 4 { 1 } else { 2 });
            assert_eq!(drains.admit(&[1; 32], lengths, minute).is_ok(), asked < 4);
        }

        // One more reads no length at all.
        let mut read = 0usize;
        let lengths = core::iter::repeat_n(1, 4).inspect(|_| read += 1);
        assert_eq!(
            drains.admit(&[1; 32], lengths, minute + 59),
            Err(Reject::Limit)
        );
        assert_eq!(read, 0);

        // The next minute gives the count back.
        assert!(drains
            .admit(&[1; 32], core::iter::repeat_n(1, 4), minute + 60)
            .is_ok());
    }
}
