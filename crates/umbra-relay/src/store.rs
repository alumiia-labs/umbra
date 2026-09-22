//! What a relay keeps between two runs: the pairwise queues with their
//! records, the group queues of Part 11 with theirs, and the invitations
//! that wait for their first fetch.
//!
//! A group lives at two relays for weeks. A relay that loses its group
//! queues at a restart ends each group that it served, and no member
//! action brings one back: the identifiers of the two queues sit inside
//! the admit of every member.
//!
//! A client names a contact by the identifiers of two queues. A relay that
//! loses its queues at a restart ends each contact that it served, and no
//! client action brings one back. Thus the queue service records each
//! change, and the process around the node commits the changes of one call
//! before it sends an output of that call. A `QUOTA` that left the relay
//! for a record that the store does not hold would be a false
//! acknowledgment (`NET-298`).
//!
//! The store holds what Part 3 §3.11 gives a queue relay already: queue
//! identifiers, public keys, and ciphertext. It holds no circuit, no
//! session, and no subscription, because each one ends with its run.

use std::collections::BTreeMap;

use umbra_queue::relay::Stored;
use umbra_wire::command::LINK_ID_LEN;

/// One change of the stored state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreChange {
    /// A queue is new, or its head moved: its keys, its two sequence
    /// points, its notifier, or the time of its last activity.
    Queue {
        /// `RecipientId`.
        recipient_id: [u8; 32],
        /// The head of `umbra_queue::relay::queue::Queue::export_head`.
        head: Vec<u8>,
    },
    /// The relay accepted a `SEND`.
    Record {
        /// `RecipientId`.
        recipient_id: [u8; 32],
        /// The record.
        record: Stored,
    },
    /// An `ACK` covers each record of the queue at or below `seq`.
    Acked {
        /// `RecipientId`.
        recipient_id: [u8; 32],
        /// The cumulative point.
        seq: u32,
    },
    /// Each record that the relay accepted before this time passed
    /// `MSG_TTL` (`WIR-111`).
    Expired {
        /// The time, in seconds.
        accepted_before: u64,
    },
    /// A `DEL` or the idle lifetime ended the queue. No identifier of it
    /// stays (`WIR-039` to `WIR-042`).
    QueueDeleted {
        /// `RecipientId`.
        recipient_id: [u8; 32],
    },
    /// An invitation is new, or it took its blob.
    Invitation {
        /// The link identifier.
        link_id: [u8; LINK_ID_LEN],
        /// The invitation.
        held: StoredInvitation,
    },
    /// The first fetch, a second `IRES`, or a lifetime ended the
    /// invitation.
    InvitationDeleted {
        /// The link identifier.
        link_id: [u8; LINK_ID_LEN],
    },
    /// A group queue is new, or its head moved: a credential, its
    /// sequence, or the time of its last activity.
    GroupQueue {
        /// `GroupQueueId`.
        group_queue_id: [u8; 32],
        /// The head of `umbra_queue::relay::group::GroupQueue::export_head`.
        head: Vec<u8>,
    },
    /// The relay accepted a `GPOST`.
    GroupRecord {
        /// `GroupQueueId`.
        group_queue_id: [u8; 32],
        /// The record.
        record: Stored,
    },
    /// The retention or the quota took each record of the group queue at
    /// or below this sequence (`NET-246`, `NET-247`).
    GroupTrimmed {
        /// `GroupQueueId`.
        group_queue_id: [u8; 32],
        /// The highest sequence that left.
        through_seq: u32,
    },
    /// A `GDEL` or the idle lifetime ended the group queue. No identifier
    /// of it stays (`NET-245`).
    GroupQueueDeleted {
        /// `GroupQueueId`.
        group_queue_id: [u8; 32],
    },
}

/// One invitation of Part 4 §4.3.1, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredInvitation {
    /// The queue of the invitation.
    pub recipient_id: [u8; 32],
    /// The blob, or `None` between the `IRES` and the `IPUT`.
    pub blob: Option<Vec<u8>>,
    /// The time of the `IRES`, and then the time of the `IPUT`.
    pub at: u64,
}

/// A queue, as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoredQueue {
    /// The head.
    pub head: Vec<u8>,
    /// The records that no `ACK` covers.
    pub records: Vec<Stored>,
}

/// The whole stored state, which a relay reads at its start.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Loaded {
    /// The queues, by `RecipientId`.
    pub queues: BTreeMap<[u8; 32], StoredQueue>,
    /// The invitations, by link identifier.
    pub invitations: BTreeMap<[u8; LINK_ID_LEN], StoredInvitation>,
    /// The group queues, by `GroupQueueId`.
    pub group_queues: BTreeMap<[u8; 32], StoredQueue>,
}

impl Loaded {
    /// Applies one change. The memory store is this function, and a test
    /// of a second backend compares against it.
    pub fn apply(&mut self, change: &StoreChange) {
        match change {
            StoreChange::Queue { recipient_id, head } => {
                self.queues.entry(*recipient_id).or_default().head = head.clone();
            }
            StoreChange::Record {
                recipient_id,
                record,
            } => {
                let queue = self.queues.entry(*recipient_id).or_default();
                queue.records.push(record.clone());
            }
            StoreChange::Acked { recipient_id, seq } => {
                if let Some(queue) = self.queues.get_mut(recipient_id) {
                    queue.records.retain(|record| record.seq > *seq);
                }
            }
            StoreChange::Expired { accepted_before } => {
                for queue in self.queues.values_mut() {
                    queue
                        .records
                        .retain(|record| record.accepted_at >= *accepted_before);
                }
            }
            StoreChange::QueueDeleted { recipient_id } => {
                self.queues.remove(recipient_id);
            }
            StoreChange::Invitation { link_id, held } => {
                self.invitations.insert(*link_id, held.clone());
            }
            StoreChange::InvitationDeleted { link_id } => {
                self.invitations.remove(link_id);
            }
            StoreChange::GroupQueue {
                group_queue_id,
                head,
            } => {
                self.group_queues.entry(*group_queue_id).or_default().head = head.clone();
            }
            StoreChange::GroupRecord {
                group_queue_id,
                record,
            } => {
                let queue = self.group_queues.entry(*group_queue_id).or_default();
                queue.records.push(record.clone());
            }
            StoreChange::GroupTrimmed {
                group_queue_id,
                through_seq,
            } => {
                if let Some(queue) = self.group_queues.get_mut(group_queue_id) {
                    queue.records.retain(|record| record.seq > *through_seq);
                }
            }
            StoreChange::GroupQueueDeleted { group_queue_id } => {
                self.group_queues.remove(group_queue_id);
            }
        }
    }
}

/// The store failed. A relay that cannot write stops, because it can
/// acknowledge nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFault;

/// The store of one relay.
pub trait RelayStore: Send {
    /// Reads the whole state at the start of a run.
    fn load(&mut self) -> Result<Loaded, StoreFault>;

    /// Commits the changes of one call of the node, all or none.
    fn commit(&mut self, changes: &[StoreChange]) -> Result<(), StoreFault>;
}

/// A store in RAM: the state ends with the process. A test network uses
/// it, and a test reads it to start a second node.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore(pub Loaded);

impl RelayStore for MemoryStore {
    fn load(&mut self) -> Result<Loaded, StoreFault> {
        Ok(self.0.clone())
    }

    fn commit(&mut self, changes: &[StoreChange]) -> Result<(), StoreFault> {
        for change in changes {
            self.0.apply(change);
        }
        Ok(())
    }
}
