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
//!
//! A link or a circuit that ends does not end the task. The task opens a
//! new link after a backoff and tells the caller with
//! [`GroupUpdate::Reset`], because each subscription ended with the old
//! session. The task ends when the caller drops the commands.

use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;
use umbra_core::session::node::{ClientEvent, ClientNode, GroupJob, GroupOutcome, Payment};
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

/// `GROUP_RELINK_FIRST`: the first wait before a new link. Each session
/// that ends before its circuit is ready doubles it, up to
/// [`GROUP_RELINK_MAX`] (`GRP-394`).
const GROUP_RELINK_FIRST: Duration = Duration::from_secs(1);

/// `GROUP_RELINK_MAX`: the longest wait before a new link.
const GROUP_RELINK_MAX: Duration = Duration::from_secs(60);

/// How long a session must stay ready before a `GKEY` or a `GDEL` that it
/// carried counts as delivered. Neither command has an answer.
const SETTLED: Duration = Duration::from_secs(30);

/// The first wait before a `GSUB` goes again after a `LIMIT`. Each `LIMIT`
/// of the same group queue doubles it, up to [`GSUB_AGAIN_MAX`].
const GSUB_AGAIN_FIRST: Duration = Duration::from_secs(2);

/// The longest wait before a `GSUB` goes again after a `LIMIT`.
const GSUB_AGAIN_MAX: Duration = Duration::from_secs(30);

/// What the caller asks of the task. Each command names one replica: the
/// caller sends the same record to each of the two (`GRP-194`).
pub enum GroupCommand {
    /// The challenges of the relays of the last fetch, for a `GNEW` that
    /// pays with a proof of work (`ABU-014`). It has no answer.
    Challenges {
        /// The challenges.
        book: umbra_core::abuse::pow::ChallengeBook,
        /// The time of the fetch.
        now: u64,
    },
    /// `GNREG` or `GNUNREG`: the notify queue of this device at one
    /// replica (Part 8 `NTF-093`, `NTF-103`). It has no answer.
    Notify {
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// `read_sk` of the epoch.
        read: Secret<32>,
        /// The encoded `QueueAddress` of the notify queue.
        queue: Vec<u8>,
        /// A `GNREG`, or a `GNUNREG`.
        on: bool,
    },
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
        /// The credential: none, and a token or a proof of work after a
        /// relay under load refused the `GNEW` with none (`ABU-048`).
        payment: Payment,
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
        /// `write_sk` of the previous epoch inside its grace. A refusal
        /// under `write` sends the same bytes under it at once (`GRP-398`).
        fallback: Option<Secret<32>>,
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
        /// `read_sk` of the previous epoch inside its grace, as for a
        /// `GPOST` (`GRP-398`).
        fallback: Option<Secret<32>>,
        /// The cursor.
        from_seq: u32,
    },
    /// A second `GSUB` of one group in one session, at the other replica
    /// than the one that it reads, for a gap (`GRP-205`, `GRP-255`). It is
    /// a `GSUB` in each respect but one: a loss of it ends no subscription,
    /// thus the caller hears of none.
    Repair {
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// `read_sk` of the epoch.
        read: Secret<32>,
        /// `read_sk` of the previous epoch inside its grace (`GRP-398`).
        fallback: Option<Secret<32>>,
        /// The cursor at that replica.
        from_seq: u32,
    },
    /// `GKEY` at one replica, which an admin sends at a rotation.
    Rotate {
        /// The relay.
        relay: [u8; 32],
        /// The group queue at that relay.
        group_queue_id: [u8; 32],
        /// The owner credential of this replica, which authorizes it.
        own: Secret<32>,
        /// The owner credential after the command, or none to keep `own`
        /// (`WIR-522`).
        next_own_pk: Option<[u8; 32]>,
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
    /// The chains of the circuits of the pairwise run of this client. A
    /// chain of the group node puts their relays last (Part 3 `NET-310`).
    /// It has no answer.
    Chains(Vec<[[u8; 32]; 3]>),
}

impl GroupCommand {
    /// The tag of a command that takes an answer.
    pub fn tag(&self) -> Option<u64> {
        match self {
            GroupCommand::Create { tag, .. } | GroupCommand::Post { tag, .. } => Some(*tag),
            _ => None,
        }
    }

    /// The same command, for a later session.
    pub fn copy(&self) -> GroupCommand {
        match self {
            GroupCommand::Notify {
                relay,
                group_queue_id,
                read,
                queue,
                on,
            } => GroupCommand::Notify {
                relay: *relay,
                group_queue_id: *group_queue_id,
                read: Secret::new(*read.expose()),
                queue: queue.clone(),
                on: *on,
            },
            GroupCommand::Create {
                tag,
                relay,
                read_pk,
                write_pk,
                own,
                payment,
            } => GroupCommand::Create {
                tag: *tag,
                relay: *relay,
                read_pk: *read_pk,
                write_pk: *write_pk,
                own: Secret::new(*own.expose()),
                payment: payment.clone(),
            },
            GroupCommand::Challenges { book, now } => GroupCommand::Challenges {
                book: book.clone(),
                now: *now,
            },
            GroupCommand::Post {
                tag,
                relay,
                group_queue_id,
                write,
                fallback,
                record,
            } => GroupCommand::Post {
                tag: *tag,
                relay: *relay,
                group_queue_id: *group_queue_id,
                write: Secret::new(*write.expose()),
                fallback: fallback.as_ref().map(|held| Secret::new(*held.expose())),
                record: record.clone(),
            },
            GroupCommand::Subscribe {
                relay,
                group_queue_id,
                read,
                fallback,
                from_seq,
            } => GroupCommand::Subscribe {
                relay: *relay,
                group_queue_id: *group_queue_id,
                read: Secret::new(*read.expose()),
                fallback: fallback.as_ref().map(|held| Secret::new(*held.expose())),
                from_seq: *from_seq,
            },
            GroupCommand::Repair {
                relay,
                group_queue_id,
                read,
                fallback,
                from_seq,
            } => GroupCommand::Repair {
                relay: *relay,
                group_queue_id: *group_queue_id,
                read: Secret::new(*read.expose()),
                fallback: fallback.as_ref().map(|held| Secret::new(*held.expose())),
                from_seq: *from_seq,
            },
            GroupCommand::Rotate {
                relay,
                group_queue_id,
                own,
                next_own_pk,
                read_pk,
                write_pk,
            } => GroupCommand::Rotate {
                relay: *relay,
                group_queue_id: *group_queue_id,
                own: Secret::new(*own.expose()),
                next_own_pk: *next_own_pk,
                read_pk: *read_pk,
                write_pk: *write_pk,
            },
            GroupCommand::Delete {
                relay,
                group_queue_id,
                own,
            } => GroupCommand::Delete {
                relay: *relay,
                group_queue_id: *group_queue_id,
                own: Secret::new(*own.expose()),
            },
            GroupCommand::Chains(chains) => GroupCommand::Chains(chains.clone()),
        }
    }
}

/// The tag of a command that takes an answer, the relay, the group queue,
/// and the job of the node.
type CommandJob = (Option<u64>, [u8; 32], [u8; 32], GroupJob);

impl GroupCommand {
    /// The same command under the credential of the previous epoch, when
    /// it carries one (`GRP-398`).
    fn under_fallback(&self) -> Option<GroupCommand> {
        match self.copy() {
            GroupCommand::Post {
                tag,
                relay,
                group_queue_id,
                fallback: Some(write),
                record,
                ..
            } => Some(GroupCommand::Post {
                tag,
                relay,
                group_queue_id,
                write,
                fallback: None,
                record,
            }),
            GroupCommand::Subscribe {
                relay,
                group_queue_id,
                fallback: Some(read),
                from_seq,
                ..
            } => Some(GroupCommand::Subscribe {
                relay,
                group_queue_id,
                read,
                fallback: None,
                from_seq,
            }),
            GroupCommand::Repair {
                relay,
                group_queue_id,
                fallback: Some(read),
                from_seq,
                ..
            } => Some(GroupCommand::Repair {
                relay,
                group_queue_id,
                read,
                fallback: None,
                from_seq,
            }),
            _ => None,
        }
    }

    /// The tag, the relay, the group queue, and the job of the node for a
    /// command that goes on a circuit. The challenges go on none.
    fn job(&self) -> Option<CommandJob> {
        match self {
            GroupCommand::Create {
                tag,
                relay,
                read_pk,
                write_pk,
                own,
                payment,
            } => Some((
                Some(*tag),
                *relay,
                [0; 32],
                GroupJob::Create {
                    read_pk: *read_pk,
                    write_pk: *write_pk,
                    own: StaticSecret::from(*own.expose()),
                    payment: payment.clone(),
                },
            )),
            // The receive arms take the challenges and the chains.
            GroupCommand::Challenges { .. } | GroupCommand::Chains(_) => None,
            GroupCommand::Post {
                tag,
                relay,
                group_queue_id,
                write,
                record,
                ..
            } => Some((
                Some(*tag),
                *relay,
                *group_queue_id,
                GroupJob::Post {
                    write: StaticSecret::from(*write.expose()),
                    record: record.clone(),
                },
            )),
            GroupCommand::Subscribe {
                relay,
                group_queue_id,
                read,
                from_seq,
                ..
            }
            | GroupCommand::Repair {
                relay,
                group_queue_id,
                read,
                from_seq,
                ..
            } => Some((
                None,
                *relay,
                *group_queue_id,
                GroupJob::Subscribe {
                    read: StaticSecret::from(*read.expose()),
                    from_seq: *from_seq,
                },
            )),
            GroupCommand::Rotate {
                relay,
                group_queue_id,
                own,
                next_own_pk,
                read_pk,
                write_pk,
            } => Some((
                None,
                *relay,
                *group_queue_id,
                GroupJob::Rotate {
                    own: StaticSecret::from(*own.expose()),
                    next_own_pk: *next_own_pk,
                    read_pk: *read_pk,
                    write_pk: *write_pk,
                },
            )),
            GroupCommand::Delete {
                relay,
                group_queue_id,
                own,
            } => Some((
                None,
                *relay,
                *group_queue_id,
                GroupJob::Delete {
                    own: StaticSecret::from(*own.expose()),
                },
            )),
            GroupCommand::Notify {
                relay,
                group_queue_id,
                read,
                queue,
                on,
            } => Some((
                None,
                *relay,
                *group_queue_id,
                GroupJob::Notify {
                    read: StaticSecret::from(*read.expose()),
                    queue: queue.clone(),
                    on: *on,
                },
            )),
        }
    }
}

/// What the task tells the caller.
pub enum GroupUpdate {
    /// A replica that never accepted a record made a link-fault report,
    /// which the next run of the queues sends (`GRP-197`).
    Faults(Box<umbra_core::session::faults::LinkFaults>),
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
    /// No circuit reached the relay of a command, which leaves no answer
    /// (`GRP-197`). The view shows the line of `GRP-199` when no replica
    /// answers.
    Unreachable {
        /// The tag of the command.
        tag: u64,
    },
    /// The relay refused the command, or the node could not send it.
    Failed {
        /// The tag of the command.
        tag: u64,
        /// The reason, where the relay gave one.
        reason: Option<Reject>,
    },
    /// The session that carried the command ended before an answer. The
    /// caller sends the same bytes in a later session, and a relay that
    /// holds them gives the answer it holds (`GRP-392`, `NET-239`).
    Unsent {
        /// The tag of the command.
        tag: u64,
    },
    /// No circuit reached the relay of a `GSUB`. The caller subscribes at
    /// the other replica (`GRP-391`).
    SubscriptionLost {
        /// The group queue of the `GSUB`.
        group_queue_id: [u8; 32],
    },
    /// The session ended, and a new one starts after a backoff. Each
    /// subscription ended with the old session.
    Reset,
    /// The chains of the circuits of this task, at each change. The other
    /// nodes of the client put their relays last (`NET-310`).
    Chains(Vec<[[u8; 32]; 3]>),
    /// The task ended, because the caller dropped the commands.
    Ended,
}

/// The command that one handle of the node belongs to.
struct Pending {
    tag: u64,
    relay: [u8; 32],
}

/// Why a session ended.
enum End {
    /// The link or the circuit failed, and a new session starts.
    Lost,
    /// The caller dropped the commands.
    Closed,
}

/// What one session leaves to the next.
struct Carried {
    /// The commands that did not leave yet.
    early: Vec<GroupCommand>,
    /// Each `GKEY` and `GDEL` of this session, until it settles.
    quiet: Vec<GroupCommand>,
}

/// Runs the group queues until the caller drops the commands. A session
/// that ends starts again after a backoff.
pub async fn run_groups(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    mut commands: mpsc::UnboundedReceiver<GroupCommand>,
    updates: mpsc::UnboundedSender<GroupUpdate>,
) {
    let mut carried = Carried {
        early: Vec::new(),
        quiet: Vec::new(),
    };
    let mut backoff = GROUP_RELINK_FIRST;
    loop {
        let (end, was_ready) = session(
            &mut node,
            &guard,
            tls.clone(),
            &mut commands,
            &updates,
            &mut carried,
        )
        .await;
        if matches!(end, End::Closed) {
            break;
        }

        // A `GKEY` or a `GDEL` that may not have arrived goes in the next
        // session. A `GSUB` of the caller comes again after `Reset`.
        carried.early.append(&mut carried.quiet);
        carried.early.retain(|command| {
            !matches!(
                command,
                GroupCommand::Subscribe { .. } | GroupCommand::Repair { .. }
            )
        });
        let _ = updates.send(GroupUpdate::Reset);

        backoff = if was_ready {
            GROUP_RELINK_FIRST
        } else {
            backoff.saturating_mul(2).min(GROUP_RELINK_MAX)
        };
        let wait = tokio::time::sleep(backoff);
        tokio::pin!(wait);
        let is_closed = loop {
            tokio::select! {
                () = &mut wait => break false,
                command = commands.recv() => match command {
                    Some(GroupCommand::Challenges { book, now }) => node.set_challenges(book, now),
                    Some(GroupCommand::Chains(chains)) => node.set_other_chains(chains),
                    Some(command) => carried.early.push(command),
                    None => break true,
                },
            }
        };
        if is_closed {
            break;
        }
    }

    for command in carried.early.iter() {
        if let GroupCommand::Create { tag, .. } | GroupCommand::Post { tag, .. } = command {
            let _ = updates.send(GroupUpdate::Failed {
                tag: *tag,
                reason: None,
            });
        }
    }

    let _ = updates.send(GroupUpdate::Ended);
}

/// One session: one link, the circuits of the node on it, and the commands
/// until the link, a circuit, or the caller ends it. It gives whether its
/// circuit was ready, for the backoff.
async fn session(
    node: &mut ClientNode,
    guard: &Dial,
    tls: Arc<ClientConfig>,
    commands: &mut mpsc::UnboundedReceiver<GroupCommand>,
    updates: &mpsc::UnboundedSender<GroupUpdate>,
    carried: &mut Carried,
) -> (End, bool) {
    let mut rng = OsRng;
    let mut pending: std::collections::BTreeMap<u64, Pending> = std::collections::BTreeMap::new();

    // Each `GSUB` as it left, by the handle of the node.
    let mut subscribed: std::collections::BTreeMap<u64, GroupCommand> =
        std::collections::BTreeMap::new();

    // Each `GSUB` that a relay answered with `LIMIT`, with the instant at
    // which it goes again, and the wait of each group queue (`NET-349`).
    let mut again: Vec<(tokio::time::Instant, GroupCommand)> = Vec::new();
    let mut waits: std::collections::BTreeMap<[u8; 32], Duration> =
        std::collections::BTreeMap::new();

    // The second form of each command that carries a credential of the
    // previous epoch, by the handle of its first form (`GRP-398`).
    let mut second: std::collections::BTreeMap<u64, GroupCommand> =
        std::collections::BTreeMap::new();

    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let connected = native::connect(guard, tls, plan, key, mask, Duration::from_secs(10)).await;
    let Ok(mut link) = connected else {
        return (End::Lost, false);
    };

    // NET-024: the node builds each chain again on a new link.
    if node.connected(&mut rng).is_err() {
        return (End::Lost, false);
    }

    let mut ready_since: Option<tokio::time::Instant> = None;
    let mut tick = tokio::time::interval(TICK);
    let mut circuit_clock = crate::runtime::CircuitClock::default();
    let mut shown_chains: Vec<[[u8; 32]; 3]> = Vec::new();
    let end = 'run: loop {
        // NET-310: the other nodes of the client learn the chains of this
        // one.
        let chains = node.chains();
        if chains != shown_chains {
            shown_chains.clone_from(&chains);
            let _ = updates.send(GroupUpdate::Chains(chains));
        }

        for capsule in node.take_capsules() {
            if link.send(&capsule).await.is_err() {
                break 'run End::Lost;
            }
        }

        let events = tokio::select! {
            received = link.recv() => match received {
                Ok(bytes) => match node.on_capsule(&bytes, crate::runtime::unix_now(), &mut rng) {
                    Ok(events) => events,
                    Err(_) => break 'run End::Lost,
                },
                Err(_) => break 'run End::Lost,
            },
            command = commands.recv() => match command {
                Some(GroupCommand::Challenges { book, now }) => {
                    node.set_challenges(book, now);
                    Vec::new()
                }
                Some(GroupCommand::Chains(chains)) => {
                    node.set_other_chains(chains);
                    Vec::new()
                }
                Some(command) => {
                    carried.early.push(command);
                    Vec::new()
                }
                None => break 'run End::Closed,
            },
            _ = tick.tick() => {
                if ready_since.is_some_and(|since| since.elapsed() >= SETTLED) {
                    carried.quiet.clear();
                }

                // A `GSUB` whose wait after a `LIMIT` ran out goes again.
                let now = tokio::time::Instant::now();
                let (due, later): (Vec<_>, Vec<_>) =
                    again.drain(..).partition(|(at, _)| *at <= now);
                again = later;
                carried.early.extend(due.into_iter().map(|(_, command)| command));

                // CIRCUIT_BUILD_TIMEOUT: a build that no relay answers ends.
                // NET-370: a circuit keeps the age that its relays count.
                let now = crate::runtime::unix_now();
                if let Some(step) = circuit_clock.step(now) {
                    node.circuit_clock_moved(step);
                }
                node.set_challenge_clock(now);
                node.on_tick(now)
            }
        };

        // A group node holds no contact, thus it commits nothing.
        let _ = node.take_changes();
        for event in events {
            match event {
                ClientEvent::CircuitReady => {
                    ready_since.get_or_insert_with(tokio::time::Instant::now);
                }
                // A new run takes new circuits, and `Reset` subscribes
                // each group again.
                ClientEvent::CircuitLost | ClientEvent::CircuitAged => break 'run End::Lost,
                ClientEvent::Group { handle, outcome } => {
                    // GRP-398: the relay holds the credentials of a new
                    // epoch only after a `GKEY`, thus a refusal under them
                    // goes again under the previous pair, and the caller
                    // hears only of the second answer. A `LIMIT` and each
                    // other reason refuse no credential.
                    let retry = second.remove(&handle);
                    if let (GroupOutcome::Refused(Reject::Rejected), Some(retry)) =
                        (&outcome, retry)
                    {
                        subscribed.remove(&handle);
                        pending.remove(&handle);
                        carried.early.insert(0, retry);
                        continue;
                    }

                    if let Some(command) = subscribed.remove(&handle) {
                        let (GroupCommand::Subscribe { group_queue_id, .. }
                        | GroupCommand::Repair { group_queue_id, .. }) = &command
                        else {
                            continue;
                        };

                        let group_queue_id = *group_queue_id;

                        // NET-349: the relay held no room for the drain of
                        // this `GSUB`, and it gave none of its records. The
                        // same `GSUB` goes again after a wait, from the
                        // cursor that it named. A record that the relay
                        // accepted since arrived already, and it moved no
                        // record of the backlog here.
                        if outcome == GroupOutcome::Refused(Reject::Limit) {
                            let wait = waits.entry(group_queue_id).or_insert(GSUB_AGAIN_FIRST);
                            again.push((tokio::time::Instant::now() + *wait, command));
                            *wait = wait.saturating_mul(2).min(GSUB_AGAIN_MAX);
                            continue;
                        }

                        // GRP-205: the loss of a second `GSUB` for a gap
                        // ends no subscription.
                        if matches!(command, GroupCommand::Subscribe { .. }) {
                            let _ = updates.send(GroupUpdate::SubscriptionLost { group_queue_id });
                        }
                        continue;
                    }

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
                        // GRP-390: the other replica takes the same record.
                        // GRP-197, NET-259: the replica that never accepted
                        // it is a link fault, whether or not the other one
                        // accepted it.
                        GroupOutcome::Unreachable => {
                            node.report_relay(&held.relay);
                            let faults = Box::new(node.take_faults());
                            let _ = updates.send(GroupUpdate::Faults(faults));
                            GroupUpdate::Unreachable { tag: held.tag }
                        }
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
        if ready_since.is_none() {
            continue;
        }

        for command in carried.early.drain(..) {
            // The receive arms take the challenges.
            let Some((tag, relay, group_queue_id, job)) = command.job() else {
                continue;
            };

            match node.group(relay, group_queue_id, job, &mut rng) {
                Ok(handle) => {
                    if let Some(tag) = tag {
                        pending.insert(handle, Pending { tag, relay });
                    }
                    if let Some(retry) = command.under_fallback() {
                        second.insert(handle, retry);
                    }
                    if matches!(
                        command,
                        GroupCommand::Subscribe { .. } | GroupCommand::Repair { .. }
                    ) {
                        subscribed.insert(handle, command.copy());
                    }
                    if matches!(
                        command,
                        GroupCommand::Rotate { .. } | GroupCommand::Delete { .. }
                    ) {
                        carried.quiet.push(command);
                    }
                }
                Err(_) => {
                    if let Some(tag) = tag {
                        let _ = updates.send(GroupUpdate::Failed { tag, reason: None });
                    }
                }
            }
        }
    };

    // WIR-246: no run continues this session, thus it ends at the relay
    // now, and the relay holds no circuit for it.
    if let Some(capsule) = node.close() {
        let _ = tokio::time::timeout(Duration::from_secs(1), link.send(&capsule)).await;
    }

    // Each command that left and took no answer goes again in a later
    // session, under the tag the caller gave it.
    for held in pending.values() {
        let _ = updates.send(GroupUpdate::Unsent { tag: held.tag });
    }

    // The circuits of the session end with it.
    if !shown_chains.is_empty() {
        let _ = updates.send(GroupUpdate::Chains(Vec::new()));
    }

    (end, ready_since.is_some())
}
