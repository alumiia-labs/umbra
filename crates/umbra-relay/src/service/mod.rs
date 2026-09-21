//! The services of a relay at the end of a circuit: the pairwise queues,
//! the community caches, the group queues, and the chunk store. Each
//! service takes one command and gives the commands that go back, to the
//! circuit of the command or to the circuit of a subscriber.

use umbra_queue::Reject;
use umbra_wire::{
    address::LEN as QUEUE_ADDRESS_LEN,
    bucket::Bucket,
    command::{Cmd, Command},
    nack::{NackPayload, Reason},
};

use crate::circuits::CircuitKey;

pub mod chunk;
pub mod community;
pub mod group;
pub mod queue;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// A digest for the runtime to write as a `SEND` into a notify queue. The
/// relay is a sender there, over a circuit of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestDue {
    /// The `community_id`, or the `GroupQueueId` of a group (`NTF-099`).
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
