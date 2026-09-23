//! The client runtime over tokio: one task owns the client node and the
//! connection to its guard, and it moves capsules between the two. The
//! node stays a plain state machine, thus this file holds the clock, the
//! random source, and the socket, and no protocol rule.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::mpsc;
use umbra_core::{
    identity::invitation::FRAGMENT_LEN,
    session::node::{ClientEvent, ClientNode, ContactId, CoverSlot, StateChange},
};
use umbra_crypto::rand_core::{TryCryptoRng, TryRng};
use umbra_transport::{
    native::{self, ClientConfig},
    race::{Plan, Wire},
    Dial,
};

/// The entropy of the operating system. A client that cannot draw a random
/// value stops, because each key and each identifier needs one.
pub struct OsRng;

impl TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if getrandom::fill(dst).is_err() {
            std::process::abort();
        }
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

/// What the application asks of the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Make one invitation with a link. An [`Update::Invitation`] follows
    /// with the 68 bytes of the fragment of Part 4 §4.3.1.
    Invite,
    /// Accept an invitation: the 68 bytes of a fragment, or a bundle that
    /// came by another path.
    Accept(Vec<u8>),
    /// Send one application record. An [`Update::Sent`] with the same tag
    /// follows the acknowledgment of the relay.
    Send {
        /// The contact.
        contact: ContactId,
        /// The encoded `AppMessage`.
        app: Vec<u8>,
        /// A value of the caller, which comes back in the update.
        tag: u64,
    },
    /// The app entered or left the screen. A client in the background
    /// makes no cover cell (Part 3 §3.6.2, tier C).
    Foreground(bool),
    /// Start a verification ceremony with a contact (Part 4 §4.5.2). An
    /// [`Update::VerificationCode`] follows at the two devices.
    Verify(ContactId),
    /// The user says that the two codes match. An [`Update::Verified`]
    /// follows, or an [`Update::VerificationRefused`] with no complete
    /// ceremony.
    ConfirmVerified(ContactId),
    /// Make a notify queue of Part 8 §8.5.2. An [`Update::NotifyQueue`]
    /// with the same tag follows.
    MakeNotifyQueue(u64),
    /// End a notify queue with a `DEL` (`NTF-103`, `NTF-105`).
    EndNotifyQueue([u8; 32]),
    /// Send the `NKEY` of an inbound queue. An [`Update::NotifyKey`]
    /// follows with the notification key of its relay (Part 8 §8.2.3).
    NotifyQueue([u8; 32]),
    /// Send the `NBIND` of an inbound queue: its binding, sealed.
    BindQueue {
        /// The queue.
        recipient_id: [u8; 32],
        /// The sealed binding of 1 234 bytes.
        sealed: Vec<u8>,
    },
}

/// The store of the client, as the runtime sees it.
pub trait Persist: Send {
    /// Commits the changes of the node state and the records that one call
    /// of the node gave, in one batch. The result is false when the store
    /// did not take the batch, and the run then ends with no capsule of
    /// that call on the link.
    fn commit(&mut self, changes: Vec<StateChange>, received: &[(ContactId, Vec<u8>)]) -> bool;

    /// A batch of receipts that may leave at `now`, in seconds, and the
    /// contact that gets it (Part 3 §3.5.4). The store holds the batch
    /// until [`Persist::receipt_sent`].
    fn due_receipt(&mut self, _now: u64) -> Option<(ContactId, Vec<u8>)> {
        None
    }

    /// The batch of the last [`Persist::due_receipt`] left in a slot, and
    /// the store erases it (`NET-054`).
    fn receipt_sent(&mut self) {}
}

/// A store that keeps nothing, for a run whose state ends with it.
pub struct NoStore;

impl Persist for NoStore {
    fn commit(&mut self, _: Vec<StateChange>, _: &[(ContactId, Vec<u8>)]) -> bool {
        true
    }
}

/// What the runtime tells the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// The circuit is ready.
    Online,
    /// The circuits that hold their three hops, each as its three relays.
    /// It comes at each change of that set.
    Circuits(Vec<[[u8; 32]; 3]>),
    /// Each inbound queue that a ready circuit serves, with its relay. It
    /// comes at each change of that set, for the bindings of Part 8.
    Queues(Vec<([u8; 32], [u8; 32])>),
    /// A notify queue exists at its relay (`NTF-090`).
    NotifyQueue {
        /// The tag of the command.
        tag: u64,
        /// The `RecipientId` of the queue.
        recipient_id: [u8; 32],
        /// The encoded `QueueAddress` that a group relay writes to.
        address: Vec<u8>,
    },
    /// A digest arrived on a notify queue (`NTF-107`).
    Digest {
        /// The `GroupQueueId` that holds records.
        group_queue_id: [u8; 32],
    },
    /// An inbound queue of a contact ended at the end of its rotation.
    QueueEnded([u8; 32]),
    /// The relay of an inbound queue answered its `NKEY`.
    NotifyKey {
        /// The queue.
        recipient_id: [u8; 32],
        /// The notification key of the relay.
        relay_ntf_pk: Vec<u8>,
    },
    /// The fragment of an invitation link, which the user gives out of
    /// band.
    Invitation(Vec<u8>),
    /// The relay holds no blob for a link that the user accepted: a second
    /// party fetched it first, or it passed its lifetime (`IDN-023`).
    InvitationGone,
    /// A contact is ready.
    Contact {
        /// The contact.
        contact: ContactId,
        /// The static key of the peer.
        peer_static: [u8; 32],
    },
    /// An application record arrived.
    Message {
        /// The contact.
        contact: ContactId,
        /// The encoded `AppMessage`.
        app: Vec<u8>,
    },
    /// The six-digit code of a ceremony, which the two users compare.
    VerificationCode {
        /// The contact.
        contact: ContactId,
        /// The code.
        code: u32,
    },
    /// A ceremony did not start, or the node holds no complete ceremony to
    /// confirm.
    VerificationRefused(ContactId),
    /// The user confirmed a complete ceremony (`IDN-147`).
    Verified {
        /// The contact.
        contact: ContactId,
        /// The pairwise identity key of the peer, which the state names.
        peer_static: [u8; 32],
    },
    /// A relay acknowledged the record with this tag.
    Sent(u64),
    /// A relay rejected the record with this tag.
    Failed(u64),
    /// The node refused an invitation command. A bundle that does not parse
    /// gives this update, and the runtime stays up.
    Refused,
    /// The run ended.
    Offline(Ended),
}

/// Why a run of the network ended. The interface shows it, and a later
/// reconnect policy reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ended {
    /// The application stopped the run.
    Stopped = 0,
    /// The dial of the guard failed.
    DialFailed = 1,
    /// The link to the guard closed.
    LinkClosed = 2,
    /// A relay destroyed the circuit.
    CircuitLost = 3,
    /// A capsule or a command gave a fault in the client node.
    NodeFault = 4,
    /// The store did not take a batch, such as the store of a locked
    /// client.
    StoreFault = 5,
    /// A circuit came near `CIRCUIT_MAX_AGE` (`NET-320`). The next run
    /// starts at once, and the view shows no fault.
    Aged = 6,
}

/// Commits what the last call of the node gave. The caller writes the
/// capsules of the node after this function only (`IMP-131`). The `ACK` of a
/// record follows its commit (`WIR-115`), in a slot of the cover clock.
fn settle(
    node: &mut ClientNode,
    persist: &mut dyn Persist,
    events: &[ClientEvent],
) -> Result<(), Ended> {
    let received: Vec<(ContactId, Vec<u8>)> = events
        .iter()
        .filter_map(|event| match event {
            ClientEvent::Message { contact, app } => Some((*contact, app.clone())),
            _ => None,
        })
        .collect();
    let changes = node.take_changes().map_err(|_| Ended::NodeFault)?;
    if changes.is_empty() && received.is_empty() {
        return Ok(());
    }
    if !persist.commit(changes, &received) {
        return Err(Ended::StoreFault);
    }
    Ok(())
}

/// The mean time between two slots of the cover clock: λ = 0.05 cells for
/// each second (Part 3 §3.6.2, tier A).
const COVER_MEAN: Duration = Duration::from_secs(20);

/// The time to the next slot of a Poisson clock.
fn cover_delay(rng: &mut OsRng) -> Duration {
    let mut bytes = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut bytes);
    // A value in (0, 1], thus the logarithm is finite.
    let unit = (f64::from(u32::from_be_bytes(bytes)) + 1.0) / (f64::from(u32::MAX) + 1.0);
    COVER_MEAN.mul_f64(-unit.ln())
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs one client until the connection ends or each sender of `commands`
/// closes. A command that arrives before the circuit is ready waits. The
/// channel has no bound, because the caller is a thread of the platform
/// that cannot wait, and the store holds each record of it already.
///
/// `node` holds the contacts and the invitations of the earlier runs, and
/// `persist` takes each change of them.
pub async fn run_client(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    updates: mpsc::UnboundedSender<Update>,
    mut persist: Box<dyn Persist>,
) {
    let mut rng = OsRng;
    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    let Ok(mut link) = native::connect(&guard, tls, plan, key, mask, Duration::from_secs(10)).await
    else {
        let _ = updates.send(Update::Offline(Ended::DialFailed));
        return;
    };
    if node.connected(&mut rng).is_err() {
        let _ = updates.send(Update::Offline(Ended::NodeFault));
        return;
    }

    let mut early: VecDeque<Command> = VecDeque::new();
    let mut shown_chains: Vec<[[u8; 32]; 3]> = Vec::new();
    let mut shown_queues: Vec<([u8; 32], [u8; 32])> = Vec::new();
    let mut notify_tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut is_foreground = true;
    let mut next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
    // The tick of `CIRCUIT_BUILD_TIMEOUT`. It sends nothing unless a build
    // ran out, and the cover clock stays memoryless.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // The check of the queue rotations of Part 3 §3.2.6. A rotation
    // counts in days, thus a check each minute is on time.
    let mut next_rotation_check = unix_now();
    let ended = 'run: loop {
        for capsule in node.take_capsules() {
            if link.send(&capsule).await.is_err() {
                break 'run Ended::LinkClosed;
            }
        }
        let events = tokio::select! {
            received = link.recv() => match received {
                Ok(bytes) => match node.on_capsule(&bytes, unix_now(), &mut rng) {
                    Ok(events) => events,
                    Err(_) => break 'run Ended::NodeFault,
                },
                Err(_) => break 'run Ended::LinkClosed,
            },
            command = commands.recv() => match command {
                None => break 'run Ended::Stopped,
                Some(Command::Foreground(now_foreground)) => {
                    is_foreground = now_foreground;
                    Vec::new()
                }
                Some(command) => {
                    early.push_back(command);
                    Vec::new()
                }
            },
            // The clock is memoryless, and it fires whether or not a cell
            // waits (`NET-049`). A fault of one slot ends no run.
            () = tokio::time::sleep_until(next_slot) => {
                next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
                let now = unix_now();
                let receipt = persist.due_receipt(now);
                let given = receipt.as_ref().map(|(contact, app)| (contact, app.as_slice()));
                if node.on_cover_slot(is_foreground, given, now, &mut rng) == Ok(CoverSlot::Receipt) {
                    persist.receipt_sent();
                }
                Vec::new()
            }
            // NET-169: a build that no relay answers ends, and the run
            // ends with its last circuit.
            _ = tick.tick() => {
                let now = unix_now();
                let mut events = node.on_tick(now);
                // NET-176: a fault of one rotation ends no run, and the
                // next check tries again.
                if node.is_ready() && now >= next_rotation_check {
                    next_rotation_check = now.saturating_add(60);
                    events.extend(node.rotate_due(now, &mut rng).unwrap_or_default());
                }
                events
            }
        };
        if let Err(ended) = settle(&mut node, persist.as_mut(), &events) {
            break 'run ended;
        }
        for event in events {
            let update = match event {
                ClientEvent::CircuitReady => Update::Online,
                ClientEvent::Invitation { bundle, .. } => Update::Invitation(bundle),
                ClientEvent::InvitationLink { fragment, .. } => Update::Invitation(fragment),
                ClientEvent::InvitationGone { .. } => Update::InvitationGone,
                ClientEvent::ContactReady {
                    contact,
                    peer_static,
                } => Update::Contact {
                    contact,
                    peer_static,
                },
                ClientEvent::Message { contact, app } => Update::Message { contact, app },
                ClientEvent::VerificationCode { contact, code } => {
                    Update::VerificationCode { contact, code }
                }
                ClientEvent::Accepted { handle } => match tags.remove(&handle) {
                    Some(tag) => Update::Sent(tag),
                    None => continue,
                },
                ClientEvent::Rejected { handle, .. } => match tags.remove(&handle) {
                    Some(tag) => Update::Failed(tag),
                    None => continue,
                },
                // The node of the queues sends no chunk command and no
                // group-queue command, thus it gets no such answer. The
                // transfer of Part 13 has a node and a connection of its
                // own (§13.8), and a group queue takes a session that
                // carries no other range (`GRP-186`).
                ClientEvent::Chunk { .. }
                | ClientEvent::Group { .. }
                | ClientEvent::GroupRecord { .. } => continue,
                ClientEvent::NotifyQueue {
                    handle,
                    recipient_id,
                    address,
                } => match notify_tags.remove(&handle) {
                    Some(tag) => Update::NotifyQueue {
                        tag,
                        recipient_id,
                        address,
                    },
                    None => continue,
                },
                ClientEvent::Digest { id, .. } => Update::Digest { group_queue_id: id },
                ClientEvent::NotifyKey {
                    recipient_id,
                    relay_ntf_pk,
                } => Update::NotifyKey {
                    recipient_id,
                    relay_ntf_pk,
                },
                ClientEvent::QueueEnded { queue } => Update::QueueEnded(queue),
                ClientEvent::CircuitLost => break 'run Ended::CircuitLost,
                ClientEvent::CircuitAged => break 'run Ended::Aged,
            };
            let _ = updates.send(update);
        }
        let chains = node.chains();
        if chains != shown_chains {
            shown_chains.clone_from(&chains);
            let _ = updates.send(Update::Circuits(chains));
        }
        let queues = node.inbound_queues();
        if queues != shown_queues {
            shown_queues.clone_from(&queues);
            let _ = updates.send(Update::Queues(queues));
        }
        while node.is_ready() {
            let Some(command) = early.pop_front() else {
                break;
            };
            let now = unix_now();
            // A value of the user ends no runtime: a bad bundle and a send
            // to no contact fail that one command.
            match command {
                // The loop above takes this command.
                Command::Foreground(_) => {}
                Command::Invite => {
                    if node.invite_link(&mut rng).is_err() {
                        let _ = updates.send(Update::Refused);
                    }
                }
                Command::Accept(given) => {
                    let accepted = if given.len() == FRAGMENT_LEN {
                        node.accept_link(&given, &mut rng)
                    } else {
                        node.accept(given, &mut rng)
                    };
                    if accepted.is_err() {
                        let _ = updates.send(Update::Refused);
                    }
                }
                Command::Verify(contact) => {
                    if node.start_verification(&contact, now, &mut rng).is_err() {
                        let _ = updates.send(Update::VerificationRefused(contact));
                    }
                }
                Command::ConfirmVerified(contact) => {
                    let update = match node.confirm_verification(&contact) {
                        Ok(peer_static) => Update::Verified {
                            contact,
                            peer_static,
                        },
                        Err(_) => Update::VerificationRefused(contact),
                    };
                    let _ = updates.send(update);
                }
                Command::Send { contact, app, tag } => {
                    match node.send(&contact, &app, now, &mut rng) {
                        Ok(handle) => {
                            tags.insert(handle, tag);
                        }
                        Err(_) => {
                            let _ = updates.send(Update::Failed(tag));
                        }
                    }
                }
                // A queue that no circuit serves any more takes its binding
                // in a later run, thus a failure here ends nothing.
                Command::MakeNotifyQueue(tag) => {
                    if let Ok(handle) = node.make_notify_queue(&mut rng) {
                        notify_tags.insert(handle, tag);
                    }
                }
                Command::EndNotifyQueue(recipient_id) => {
                    let _ = node.end_notify_queue(&recipient_id, &mut rng);
                }
                Command::NotifyQueue(recipient_id) => {
                    let _ = node.notify_queue(&recipient_id, &mut rng);
                }
                Command::BindQueue {
                    recipient_id,
                    sealed,
                } => {
                    let _ = node.bind_queue(&recipient_id, &sealed, &mut rng);
                }
            }
            if let Err(ended) = settle(&mut node, persist.as_mut(), &[]) {
                break 'run ended;
            }
        }
    };
    let _ = updates.send(Update::Offline(ended));
}
