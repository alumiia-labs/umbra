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
use umbra_core::session::node::{ClientEvent, ClientNode, ContactId};
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
    /// Make one invitation. An [`Update::Invitation`] follows.
    Invite,
    /// Accept the bundle of an inviter.
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
    /// The application committed each record of a contact that it took,
    /// thus the runtime acknowledges them to the relay (`WIR-115`).
    Committed(ContactId),
}

/// What the runtime tells the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    /// The circuit is ready.
    Online,
    /// The bundle of an invitation, which the user gives out of band.
    Invitation(Vec<u8>),
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
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs one client until the connection ends or each sender of `commands`
/// closes. A command that arrives before the circuit is ready waits. The
/// channel has no bound, because the caller is a thread of the platform
/// that cannot wait, and the store holds each record of it already.
pub async fn run_client(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    updates: mpsc::UnboundedSender<Update>,
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
    let mut tags: BTreeMap<u64, u64> = BTreeMap::new();
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
                Some(command) => {
                    early.push_back(command);
                    Vec::new()
                }
            },
        };
        for event in events {
            let update = match event {
                ClientEvent::CircuitReady => Update::Online,
                ClientEvent::Invitation { bundle, .. } => Update::Invitation(bundle),
                ClientEvent::ContactReady {
                    contact,
                    peer_static,
                } => Update::Contact {
                    contact,
                    peer_static,
                },
                ClientEvent::Message { contact, app } => Update::Message { contact, app },
                ClientEvent::Accepted { handle } => match tags.remove(&handle) {
                    Some(tag) => Update::Sent(tag),
                    None => continue,
                },
                ClientEvent::Rejected { handle, .. } => match tags.remove(&handle) {
                    Some(tag) => Update::Failed(tag),
                    None => continue,
                },
                ClientEvent::CircuitLost => break 'run Ended::CircuitLost,
            };
            let _ = updates.send(update);
        }
        while node.is_ready() {
            let Some(command) = early.pop_front() else {
                break;
            };
            let now = unix_now();
            // A value of the user ends no runtime: a bad bundle and a send
            // to no contact fail that one command.
            let done = match command {
                Command::Invite => {
                    if node.invite(&mut rng).is_err() {
                        let _ = updates.send(Update::Refused);
                    }
                    Ok(())
                }
                Command::Accept(bundle) => {
                    if node.accept(bundle, &mut rng).is_err() {
                        let _ = updates.send(Update::Refused);
                    }
                    Ok(())
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
                    Ok(())
                }
                Command::Committed(contact) => node.acknowledge(&contact, now, &mut rng),
            };
            if done.is_err() {
                break 'run Ended::NodeFault;
            }
        }
    };
    let _ = updates.send(Update::Offline(ended));
}
