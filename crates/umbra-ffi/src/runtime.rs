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
    let mut tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut is_foreground = true;
    let mut next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
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
                // The node of the queues sends no chunk command, thus it
                // gets no such answer. The transfer of Part 13 has a node
                // and a connection of its own (§13.8).
                ClientEvent::Chunk { .. } => continue,
                ClientEvent::CircuitLost => break 'run Ended::CircuitLost,
            };
            let _ = updates.send(update);
        }
        let chains = node.chains();
        if chains != shown_chains {
            shown_chains.clone_from(&chains);
            let _ = updates.send(Update::Circuits(chains));
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
            }
            if let Err(ended) = settle(&mut node, persist.as_mut(), &[]) {
                break 'run ended;
            }
        }
    };
    let _ = updates.send(Update::Offline(ended));
}
