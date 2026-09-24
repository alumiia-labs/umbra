//! The runtime of the public communities (Part 12 §12.3.3): one task with a
//! node and a connection of its own, beside the run of the queues, the run
//! of the group queues, and the run of the transfers.
//!
//! A community command rides no session that carries another range
//! (`WIR-309`), and one circuit of the node serves one community
//! (`COM-173`). Thus the communities have a task of their own.
//!
//! The task carries bytes. The cursors, the records, and the identities of
//! a community sit at the store. The content of a community is public
//! (§12.1), and the task keeps nothing of it after an answer.
//!
//! A link or a circuit that ends does not end the task. The task opens a
//! new link after a backoff and tells the caller with
//! [`CommunityUpdate::Reset`]. The task ends when the caller drops the
//! commands.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use umbra_core::session::node::{ClientEvent, ClientNode, CommunityJob, GroupOutcome};
use umbra_crypto::rand_core::TryRng;
use umbra_queue::Reject;
use umbra_transport::{
    native::{self, ClientConfig},
    race::{Plan, Wire},
    Dial,
};

use crate::runtime::OsRng;

/// The tick that keeps the run from a stall with no traffic.
const TICK: Duration = Duration::from_secs(1);

/// The first wait before a new link. Each session that ends before its
/// circuit is ready doubles it, up to [`RELINK_MAX`], as for the group
/// queues (`GRP-394`).
const RELINK_FIRST: Duration = Duration::from_secs(1);

/// The longest wait before a new link.
const RELINK_MAX: Duration = Duration::from_secs(60);

/// What the caller asks of the task. Each command names one relay of the
/// community.
pub enum CommunityCommand {
    /// `PULL` with an encoded `PullRequest`.
    Pull {
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The relay.
        relay: [u8; 32],
        /// The community.
        community_id: [u8; 32],
        /// The request.
        request: Vec<u8>,
    },
    /// `PUB` of one record with its `Admission` trailer. The caller sends
    /// the same record to each relay of the community (`COM-200`).
    Publish {
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The relay.
        relay: [u8; 32],
        /// The community.
        community_id: [u8; 32],
        /// The record, then the `Admission`.
        payload: Vec<u8>,
    },
    /// `NREG` or `NUNREG` of the notify queue of this device (§12.6.4). It
    /// has no answer.
    Notify {
        /// The relay.
        relay: [u8; 32],
        /// The community.
        community_id: [u8; 32],
        /// The encoded `NotifyRegistration`.
        registration: Vec<u8>,
        /// An `NREG`, or an `NUNREG`.
        on: bool,
    },
}

impl CommunityCommand {
    /// The tag of a command that takes an answer.
    pub fn tag(&self) -> Option<u64> {
        match self {
            CommunityCommand::Pull { tag, .. } | CommunityCommand::Publish { tag, .. } => {
                Some(*tag)
            }
            CommunityCommand::Notify { .. } => None,
        }
    }

    /// The same command, for a later session.
    pub fn copy(&self) -> CommunityCommand {
        match self {
            CommunityCommand::Pull {
                tag,
                relay,
                community_id,
                request,
            } => CommunityCommand::Pull {
                tag: *tag,
                relay: *relay,
                community_id: *community_id,
                request: request.clone(),
            },
            CommunityCommand::Publish {
                tag,
                relay,
                community_id,
                payload,
            } => CommunityCommand::Publish {
                tag: *tag,
                relay: *relay,
                community_id: *community_id,
                payload: payload.clone(),
            },
            CommunityCommand::Notify {
                relay,
                community_id,
                registration,
                on,
            } => CommunityCommand::Notify {
                relay: *relay,
                community_id: *community_id,
                registration: registration.clone(),
                on: *on,
            },
        }
    }
}

/// What the task tells the caller.
pub enum CommunityUpdate {
    /// The relay answered a `PULL`.
    Page {
        /// The tag of the command.
        tag: u64,
        /// The relay that answered.
        relay: [u8; 32],
        /// The encoded `PullResponse`.
        page: Vec<u8>,
    },
    /// The relay holds the record (`COM-202`).
    Published {
        /// The tag of the command.
        tag: u64,
        /// The relay that answered.
        relay: [u8; 32],
        /// The `seq` of the record at that relay.
        seq: u64,
    },
    /// The relay refused the command, or the node could not send it.
    Failed {
        /// The tag of the command.
        tag: u64,
        /// The reason, where the relay gave one.
        reason: Option<Reject>,
    },
    /// The session that carried the command ended before an answer. A
    /// `PUB` goes again in a later session (`COM-201`), and a relay that
    /// holds its record answers with the `seq` it holds (`COM-203`).
    Unsent {
        /// The tag of the command.
        tag: u64,
    },
    /// The session ended, and a new one starts after a backoff.
    Reset,
    /// The task ended, because the caller dropped the commands.
    Ended,
}

/// Why a session ended.
enum End {
    /// The link or the circuit failed, and a new session starts.
    Lost,
    /// The caller dropped the commands.
    Closed,
}

/// Runs the communities until the caller drops the commands. A session that
/// ends starts again after a backoff.
pub async fn run_communities(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    mut commands: mpsc::UnboundedReceiver<CommunityCommand>,
    updates: mpsc::UnboundedSender<CommunityUpdate>,
) {
    let mut early: Vec<CommunityCommand> = Vec::new();
    let mut backoff = RELINK_FIRST;
    loop {
        let (end, was_ready) = session(
            &mut node,
            &guard,
            tls.clone(),
            &mut commands,
            &updates,
            &mut early,
        )
        .await;
        if matches!(end, End::Closed) {
            break;
        }
        let _ = updates.send(CommunityUpdate::Reset);
        backoff = if was_ready {
            RELINK_FIRST
        } else {
            backoff.saturating_mul(2).min(RELINK_MAX)
        };
        let wait = tokio::time::sleep(backoff);
        tokio::pin!(wait);
        let is_closed = loop {
            tokio::select! {
                () = &mut wait => break false,
                command = commands.recv() => match command {
                    Some(command) => early.push(command),
                    None => break true,
                },
            }
        };
        if is_closed {
            break;
        }
    }
    for command in early.iter() {
        if let Some(tag) = command.tag() {
            let _ = updates.send(CommunityUpdate::Failed { tag, reason: None });
        }
    }
    let _ = updates.send(CommunityUpdate::Ended);
}

/// One session: one link, the circuits of the node on it, and the commands
/// until the link, a circuit, or the caller ends it. It gives whether its
/// circuit was ready, for the backoff.
async fn session(
    node: &mut ClientNode,
    guard: &Dial,
    tls: Arc<ClientConfig>,
    commands: &mut mpsc::UnboundedReceiver<CommunityCommand>,
    updates: &mpsc::UnboundedSender<CommunityUpdate>,
    early: &mut Vec<CommunityCommand>,
) -> (End, bool) {
    let mut rng = OsRng;
    // The tag and the relay of each command that takes an answer, by the
    // handle of the node.
    let mut pending: BTreeMap<u64, (u64, [u8; 32])> = BTreeMap::new();
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

    let mut is_ready = false;
    let mut tick = tokio::time::interval(TICK);
    let end = 'run: loop {
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
                Some(command) => {
                    early.push(command);
                    Vec::new()
                }
                None => break 'run End::Closed,
            },
            // CIRCUIT_BUILD_TIMEOUT: a build that no relay answers ends.
            _ = tick.tick() => node.on_tick(crate::runtime::unix_now()),
        };
        // A community node holds no contact, thus it commits nothing.
        let _ = node.take_changes();
        for event in events {
            match event {
                ClientEvent::CircuitReady => is_ready = true,
                ClientEvent::CircuitLost | ClientEvent::CircuitAged => break 'run End::Lost,
                ClientEvent::Group { handle, outcome } => {
                    let Some((tag, relay)) = pending.remove(&handle) else {
                        continue;
                    };
                    let update = match outcome {
                        GroupOutcome::Page(page) => CommunityUpdate::Page { tag, relay, page },
                        GroupOutcome::Published(seq) => {
                            CommunityUpdate::Published { tag, relay, seq }
                        }
                        GroupOutcome::Refused(reason) => CommunityUpdate::Failed {
                            tag,
                            reason: Some(reason),
                        },
                        // The other relays of the community take the same
                        // command.
                        GroupOutcome::Unreachable => CommunityUpdate::Failed { tag, reason: None },
                        // A community node sends no group-queue command.
                        GroupOutcome::Created(_) | GroupOutcome::Posted(_) => continue,
                    };
                    let _ = updates.send(update);
                }
                _ => {}
            }
        }
        if !is_ready {
            continue;
        }
        for command in early.drain(..) {
            let tag = command.tag();
            let (relay, community_id, job) = match command {
                CommunityCommand::Pull {
                    relay,
                    community_id,
                    request,
                    ..
                } => (relay, community_id, CommunityJob::Pull { request }),
                CommunityCommand::Publish {
                    relay,
                    community_id,
                    payload,
                    ..
                } => (relay, community_id, CommunityJob::Publish { payload }),
                CommunityCommand::Notify {
                    relay,
                    community_id,
                    registration,
                    on,
                } => (
                    relay,
                    community_id,
                    CommunityJob::Notify { registration, on },
                ),
            };
            match node.community(relay, community_id, job, &mut rng) {
                Ok(handle) => {
                    if let Some(tag) = tag {
                        pending.insert(handle, (tag, relay));
                    }
                }
                Err(_) => {
                    if let Some(tag) = tag {
                        let _ = updates.send(CommunityUpdate::Failed { tag, reason: None });
                    }
                }
            }
        }
    };
    // Each command that left and took no answer goes again in a later
    // session, under the tag the caller gave it.
    for (tag, _) in pending.values() {
        let _ = updates.send(CommunityUpdate::Unsent { tag: *tag });
    }
    (end, is_ready)
}
