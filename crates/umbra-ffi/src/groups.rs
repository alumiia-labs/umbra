//! The runtime of the group queues (Part 11 §11.2): one task with a node
//! and a connection of its own, beside the run of the queues and the run of
//! the transfers.
//!
//! A group-queue session carries no other command range (`GRP-186`), thus
//! the group flow needs a connection of its own. The task stays while the
//! client is unlocked, because a subscription lives with its session: a
//! record arrives while the `GSUB` holds and not after it.
//!
//! The task carries bytes. The state of a group, its epoch keys, and its
//! roster sit at the store, which seals a record before it hands it over
//! and opens one that arrives.

use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;
use umbra_core::session::node::{ClientEvent, ClientNode, GroupJob, GroupOutcome};
use umbra_crypto::{rand_core::TryRng, secret::Secret, x25519::StaticSecret};
use umbra_queue::Reject;
use umbra_transport::{
    native::{self, ClientConfig},
    race::{Plan, Wire},
    Dial,
};

use crate::runtime::OsRng;

/// The tick that keeps the run from a stall with no traffic.
const TICK: Duration = Duration::from_secs(1);

/// What the caller asks of the task. Each command names one replica: the
/// caller sends the same record to each of the two (`GRP-194`).
pub enum GroupCommand {
    /// `GNEW`. Two of these, at two relays of different operators and
    /// blocs, make one group (`GRP-191`).
    Create {
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The relay.
        relay: [u8; 32],
        /// `read_pk` of epoch 1.
        read_pk: [u8; 32],
        /// `write_pk` of epoch 1.
        write_pk: [u8; 32],
        /// The owner credential of this replica (`GRP-190`).
        own: Secret<32>,
    },
    /// `GPOST` at one replica.
    Post {
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// `write_sk` of the epoch.
        write: Secret<32>,
        /// One sealed `GroupQueueRecord`.
        record: Vec<u8>,
    },
    /// `GSUB` at one replica, from the cursor of this device (`GRP-202`).
    Subscribe {
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// `read_sk` of the epoch.
        read: Secret<32>,
        /// The cursor.
        from_seq: u32,
    },
    /// `GKEY` at one replica, which an admin sends at a rotation.
    Rotate {
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// The owner credential of this replica.
        own: Secret<32>,
        /// `read_pk` of the new epoch.
        read_pk: [u8; 32],
        /// `write_pk` of the new epoch.
        write_pk: [u8; 32],
    },
    /// `GDEL` at one replica, which closes the group there.
    Delete {
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// The owner credential of this replica.
        own: Secret<32>,
    },
}

/// What the task tells the caller.
pub enum GroupUpdate {
    /// The relay made the group queue.
    Created {
        /// The tag of the command.
        tag: u64,
        /// The relay that holds it.
        relay: [u8; 32],
        /// The `GroupQueueId` that the relay drew.
        group_queue_id: [u8; 32],
    },
    /// The replica holds the record. The caller marks the record accepted
    /// at the first of the two (`GRP-195`).
    Posted {
        /// The tag of the command.
        tag: u64,
        /// The relay that answered.
        relay: [u8; 32],
        /// The sequence at that replica. It is no order across replicas
        /// (`GRP-201`).
        seq: u32,
    },
    /// One record of a group queue that this device subscribed to.
    Record {
        /// The group queue that carried it.
        group_queue_id: [u8; 32],
        /// The sequence at that replica.
        seq: u32,
        /// The `GroupQueueRecord` bytes.
        record: Vec<u8>,
    },
    /// The relay refused the command, or the run ended before it left.
    Failed {
        /// The tag of the command.
        tag: u64,
        /// The reason, where the relay gave one.
        reason: Option<Reject>,
    },
    /// The run ended. Each subscription ended with it, and the caller opens
    /// a new run to continue.
    Ended,
}

/// The command that one handle of the node belongs to.
struct Pending {
    tag: u64,
    relay: [u8; 32],
}

/// Runs the group queues until the link ends or the caller drops the
/// commands. Each command that never left fails.
pub async fn run_groups(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    mut commands: mpsc::UnboundedReceiver<GroupCommand>,
    updates: mpsc::UnboundedSender<GroupUpdate>,
) {
    let mut rng = OsRng;
    let mut pending: std::collections::BTreeMap<u64, Pending> = std::collections::BTreeMap::new();
    let mut early: Vec<GroupCommand> = Vec::new();

    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let connected = native::connect(&guard, tls, plan, key, mask, Duration::from_secs(10)).await;
    let Ok(mut link) = connected else {
        let _ = updates.send(GroupUpdate::Ended);
        return;
    };
    if node.connected(&mut rng).is_err() {
        let _ = updates.send(GroupUpdate::Ended);
        return;
    }

    let mut is_ready = false;
    let mut tick = tokio::time::interval(TICK);
    'run: loop {
        for capsule in node.take_capsules() {
            if link.send(&capsule).await.is_err() {
                break 'run;
            }
        }
        let events = tokio::select! {
            received = link.recv() => match received {
                Ok(bytes) => match node.on_capsule(&bytes, crate::runtime::unix_now(), &mut rng) {
                    Ok(events) => events,
                    Err(_) => break 'run,
                },
                Err(_) => break 'run,
            },
            command = commands.recv() => match command {
                Some(command) => {
                    early.push(command);
                    Vec::new()
                }
                None => break 'run,
            },
            _ = tick.tick() => Vec::new(),
        };
        // A group node holds no contact, thus it commits nothing.
        let _ = node.take_changes();
        for event in events {
            match event {
                ClientEvent::CircuitReady => is_ready = true,
                ClientEvent::CircuitLost => break 'run,
                ClientEvent::Group { handle, outcome } => {
                    let Some(held) = pending.remove(&handle) else {
                        continue;
                    };
                    let update = match outcome {
                        GroupOutcome::Created(group_queue_id) => GroupUpdate::Created {
                            tag: held.tag,
                            relay: held.relay,
                            group_queue_id,
                        },
                        GroupOutcome::Posted(seq) => GroupUpdate::Posted {
                            tag: held.tag,
                            relay: held.relay,
                            seq,
                        },
                        GroupOutcome::Refused(reason) => GroupUpdate::Failed {
                            tag: held.tag,
                            reason: Some(reason),
                        },
                    };
                    let _ = updates.send(update);
                }
                ClientEvent::GroupRecord {
                    group_queue_id,
                    seq,
                    record,
                } => {
                    let _ = updates.send(GroupUpdate::Record {
                        group_queue_id,
                        seq,
                        record,
                    });
                }
                _ => {}
            }
        }
        if !is_ready {
            continue;
        }
        for command in early.drain(..) {
            let (tag, relay, group_queue_id, job) = match command {
                GroupCommand::Create {
                    tag,
                    relay,
                    read_pk,
                    write_pk,
                    own,
                } => (
                    Some(tag),
                    relay,
                    [0; 32],
                    GroupJob::Create {
                        read_pk,
                        write_pk,
                        own: StaticSecret::from(*own.expose()),
                    },
                ),
                GroupCommand::Post {
                    tag,
                    relay,
                    group_queue_id,
                    write,
                    record,
                } => (
                    Some(tag),
                    relay,
                    group_queue_id,
                    GroupJob::Post {
                        write: StaticSecret::from(*write.expose()),
                        record,
                    },
                ),
                GroupCommand::Subscribe {
                    relay,
                    group_queue_id,
                    read,
                    from_seq,
                } => (
                    None,
                    relay,
                    group_queue_id,
                    GroupJob::Subscribe {
                        read: StaticSecret::from(*read.expose()),
                        from_seq,
                    },
                ),
                GroupCommand::Rotate {
                    relay,
                    group_queue_id,
                    own,
                    read_pk,
                    write_pk,
                } => (
                    None,
                    relay,
                    group_queue_id,
                    GroupJob::Rotate {
                        own: StaticSecret::from(*own.expose()),
                        read_pk,
                        write_pk,
                    },
                ),
                GroupCommand::Delete {
                    relay,
                    group_queue_id,
                    own,
                } => (
                    None,
                    relay,
                    group_queue_id,
                    GroupJob::Delete {
                        own: StaticSecret::from(*own.expose()),
                    },
                ),
            };
            match node.group(relay, group_queue_id, job, &mut rng) {
                Ok(handle) => {
                    if let Some(tag) = tag {
                        pending.insert(handle, Pending { tag, relay });
                    }
                }
                Err(_) => {
                    if let Some(tag) = tag {
                        let _ = updates.send(GroupUpdate::Failed { tag, reason: None });
                    }
                }
            }
        }
    }
    for held in pending.values() {
        let _ = updates.send(GroupUpdate::Failed {
            tag: held.tag,
            reason: None,
        });
    }
    for command in &early {
        let tag = match command {
            GroupCommand::Create { tag, .. } | GroupCommand::Post { tag, .. } => Some(*tag),
            _ => None,
        };
        if let Some(tag) = tag {
            let _ = updates.send(GroupUpdate::Failed { tag, reason: None });
        }
    }
    let _ = updates.send(GroupUpdate::Ended);
}
