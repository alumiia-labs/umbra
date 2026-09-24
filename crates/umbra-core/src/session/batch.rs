//! The batching of commands into cells (Part 6 §6.4.1): each ready command
//! that fits goes into one cell, and a cell holds the commands of one range
//! only.

use alloc::{collections::VecDeque, vec::Vec};

use umbra_wire::{
    bucket::Bucket,
    command::{Cmd, Command},
};

use crate::Error;

/// The range of a command. A transport session carries one range, and a
/// cell holds one range (`WIR-108`, `WIR-363`, `WIR-364`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// The queue commands `0x01` to `0x60`.
    Queue,
    /// The attachment commands.
    Attachment,
    /// The group-queue commands.
    Group,
}

impl Range {
    /// The range of `cmd`.
    pub fn of(cmd: Cmd) -> Self {
        match cmd {
            Cmd::Attachment(_) => Range::Attachment,
            Cmd::Group(_) => Range::Group,
            _ => Range::Queue,
        }
    }
}

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];

/// The smallest bucket whose command area holds `len` bytes.
pub(crate) fn smallest_bucket(len: usize) -> Option<Bucket> {
    BUCKETS
        .into_iter()
        .find(|bucket| len <= bucket.command_area())
}

/// The ready commands of one circuit, in the order they became ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batcher {
    range: Range,
    ready: VecDeque<Vec<u8>>,
}

impl Batcher {
    /// A batcher for a session of one range.
    pub fn new(range: Range) -> Self {
        Batcher {
            range,
            ready: VecDeque::new(),
        }
    }

    /// The count of the ready commands.
    pub fn len(&self) -> usize {
        self.ready.len()
    }

    /// Whether no command is ready.
    pub fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }

    /// Adds an encoded command. A command of another range is rejected.
    pub fn push(&mut self, cmd: Cmd, encoded: Vec<u8>) -> Result<(), Error> {
        let largest = Bucket::B3.command_area();
        if Range::of(cmd) != self.range || encoded.len() > largest {
            return Err(Error::Malformed);
        }
        self.ready.push_back(encoded);
        Ok(())
    }

    /// The content of the next cell with its bucket: the oldest command in
    /// the smallest bucket that holds it, and then each next command that
    /// fits the rest of the command area (`WIR-016`, `WIR-109`). The order
    /// of the commands stays.
    pub fn next_cell(&mut self) -> Option<(Bucket, Vec<u8>)> {
        let first = self.ready.pop_front()?;
        let bucket = smallest_bucket(first.len())?;
        let mut content = first;
        while let Some(next) = self.ready.front() {
            if content.len().saturating_add(next.len()) > bucket.command_area() {
                break;
            }
            content.extend(self.ready.pop_front().unwrap_or_default());
        }
        Some((bucket, content))
    }
}

/// Splits the content of a `DATA` cell into its commands.
pub fn unpack(content: &[u8], bucket: Bucket) -> Result<Vec<Command<'_>>, Error> {
    let mut commands = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (command, used) = Command::parse(rest, bucket)?;
        commands.push(command);
        rest = rest.get(used..).ok_or(Error::Malformed)?;
    }
    let mut ranges = commands.iter().map(|c| Range::of(c.cmd));
    let first = ranges.next();
    if ranges.any(|range| Some(range) != first) {
        return Err(Error::Malformed);
    }
    Ok(commands)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn encoded(cmd: Cmd, payload_len: usize) -> Vec<u8> {
        let payload = alloc::vec![7u8; payload_len];
        let command = Command {
            cmd,
            corr_id: [1; 16],
            queue_id: [2; 32],
            auth: [3; 32],
            payload: &payload,
        };
        let mut out = alloc::vec![0u8; command.len()];
        command.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn small_commands_share_a_cell_and_a_full_one_travels_alone() {
        let mut batcher = Batcher::new(Range::Queue);
        batcher.push(Cmd::Ack, encoded(Cmd::Ack, 4)).unwrap();
        batcher.push(Cmd::Sub, encoded(Cmd::Sub, 0)).unwrap();
        batcher.push(Cmd::Ack, encoded(Cmd::Ack, 4)).unwrap();
        let send = encoded(Cmd::Send, Bucket::B0.l6_record());
        batcher.push(Cmd::Send, send.clone()).unwrap();
        batcher.push(Cmd::Ack, encoded(Cmd::Ack, 4)).unwrap();

        let (bucket, content) = batcher.next_cell().unwrap();
        assert_eq!(bucket, Bucket::B0);
        let commands = unpack(&content, bucket).unwrap();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[1].cmd, Cmd::Sub);

        let (bucket, content) = batcher.next_cell().unwrap();
        assert_eq!((bucket, content.len()), (Bucket::B0, send.len()));
        assert_eq!(unpack(&content, bucket).unwrap()[0].cmd, Cmd::Send);
        assert_eq!(batcher.len(), 1);
        batcher.next_cell().unwrap();
        assert!(batcher.next_cell().is_none());
    }

    #[test]
    fn a_cell_holds_one_range() {
        let mut batcher = Batcher::new(Range::Queue);
        let chunk = encoded(Cmd::Attachment(0x70), 75);
        assert!(batcher.push(Cmd::Attachment(0x70), chunk.clone()).is_err());
        let mut attachment = Batcher::new(Range::Attachment);
        attachment
            .push(Cmd::Attachment(0x70), chunk.clone())
            .unwrap();

        let mixed = [encoded(Cmd::Sub, 0), chunk].concat();
        assert!(unpack(&mixed, Bucket::B0).is_err());
    }
}
