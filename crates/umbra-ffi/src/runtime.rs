//! The client runtime over tokio: one task owns the client node and the
//! connection to its guard, and it moves capsules between the two. The
//! node stays a plain state machine, thus this file holds the clock, the
//! random source, and the socket, and no protocol rule.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::mpsc;
use umbra_core::{
    identity::invitation::FRAGMENT_LEN,
    session::{
        faults::LinkFaults,
        node::{ClientEvent, ClientNode, ContactId, CoverSlot, StateChange},
    },
};
use umbra_crypto::{
    rand_core::{TryCryptoRng, TryRng},
    rng::HardenedRng,
    secret::Secret,
};
use umbra_transport::{
    native::{self, ClientConfig},
    race::{Plan, Wire},
    Dial,
};
use zeroize::Zeroizing;

/// The entropy of the operating system, hardened under `K_rng_harden` once a
/// store is open (Part 5 §5.9, Part 14 `IMP-093`). A client that cannot draw
/// a random value stops, because each key and each identifier needs one.
pub struct OsRng;

/// `K_rng_harden` of the store that this process opened. It stays until the
/// process ends, thus a platform generator that fails after the first
/// unlock shows no raw output on the wire.
static HARDEN: std::sync::Mutex<Option<Secret<32>>> = std::sync::Mutex::new(None);

/// The context of each value of this process under the hardening.
const HARDEN_CONTEXT: &[u8] = b"umbra/v1/client-rng";

/// Hardens each later value of [`OsRng`] under `key`.
pub fn harden_with(key: Secret<32>) {
    *HARDEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
}

/// The platform source alone.
struct PlatformRng;

impl TryRng for PlatformRng {
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

impl TryCryptoRng for PlatformRng {}

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
        let held = HARDEN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match held.as_ref() {
            Some(key) => {
                HardenedRng::new(&mut PlatformRng, key, HARDEN_CONTEXT).try_fill_bytes(dst)
            }
            None => PlatformRng.try_fill_bytes(dst),
        }
    }
}

impl TryCryptoRng for OsRng {}

/// What the application asks of the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// The challenges of the relays of the last fetch, for a `NEW` that
    /// pays with a proof of work (`ABU-014`).
    Challenges {
        /// The challenges.
        book: umbra_core::abuse::pow::ChallengeBook,
        /// The time of the fetch.
        now: u64,
    },
    /// Sets the privacy mode of the conversation of a contact (Part 3
    /// §3.9, `NET-028`).
    SetClass {
        /// The contact.
        contact: ContactId,
        /// The mode.
        class: umbra_core::session::node::DelayClass,
    },
    /// Make one invitation with a link. An [`Update::Invitation`] follows
    /// with the 68 bytes of the fragment of Part 4 §4.3.1.
    Invite,
    /// Accept an invitation: the 68 bytes of a fragment, or a bundle that
    /// came by another path.
    Accept(Vec<u8>),
    /// Make the invitation of the sync channel of a device (Part 7
    /// `DEV-286`). An [`Update::DeviceInvitation`] follows with its bundle.
    InviteDevice,
    /// Accept the bundle of the sync channel that a device gave in its
    /// provision.
    AcceptDevice(Vec<u8>),
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
    /// makes no cover cell (Part 3 §3.6.2, tier C). A run that enters the
    /// screen is a push-wake session no more.
    Foreground(bool),
    /// The run is a push-wake session: it ends after `WAKE_SESSION_MAX`
    /// unless the app enters the screen first (Part 3 `NET-100`).
    Wake,
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
    /// End a notify queue with a `DEL` (`NTF-133`).
    EndNotifyQueue([u8; 32]),
    /// Make a new queue for a dead channel (`NET-182`).
    RotateNow(ContactId),
    /// Makes a new queue for a contact after its own delay, for an
    /// operation that moves the queues of many contacts (`NET-180`).
    RotateSwept(ContactId),
    /// The dead-channel blob of the peer gave its address (`NET-190`).
    PeerMoved {
        /// The contact.
        contact: ContactId,
        /// The encoded `QueueAddress`.
        address: Zeroizing<Vec<u8>>,
    },
    /// The user accepted a new pairwise key of the peer (Part 4 §4.5.1).
    PeerKey {
        /// The contact.
        contact: ContactId,
        /// The new X25519 key of the peer.
        key: [u8; 32],
    },
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
    /// Make a rendezvous queue of Part 9 §9.6. An
    /// [`Update::RendezvousQueue`] with the same tag follows.
    MakeRendezvousQueue(u64),
    /// Make the report queue of an authority (Part 10 `REL-166`). An
    /// [`Update::ReportQueue`] follows.
    MakeReportQueue,
    /// Build a circuit to a relay for the probe of an isolation query
    /// (Part 10 `REL-109`).
    OpenCircuit([u8; 32]),
    /// Send the loop of a probe on a ready circuit. An [`Update::Probe`]
    /// follows, or [`Update::ProbeFailed`].
    Probe,
    /// End a rendezvous queue with a `DEL`.
    EndRendezvousQueue([u8; 32]),
    /// Send a hello of Part 9 §9.6 to the rendezvous queue of an entry.
    Hello {
        /// The key of the entry.
        entry_pk: Vec<u8>,
        /// The encoded rendezvous `QueueAddress`.
        rendezvous: Vec<u8>,
        /// The profile that the hello shows.
        profile: Vec<u8>,
        /// A cross-relay token in place of the proof of work.
        token: Option<Vec<u8>>,
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

    /// One cross-relay token for a `NEW` that a relay under load refused
    /// (`ABU-048`), or none, and the store holds it no more.
    fn admission_token(&mut self, _now: u64) -> Option<Vec<u8>> {
        None
    }

    /// A transparency digest that may leave at `now`, and the contact that
    /// gets it (Part 9 §9.5.3, Part 10 `REL-008`).
    fn due_digest(&mut self, _now: u64) -> Option<(ContactId, Vec<u8>)> {
        None
    }

    /// The digest of the last [`Persist::due_digest`] left in a slot.
    fn digest_sent(&mut self) {}
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
    /// A rendezvous queue exists at its relay.
    RendezvousQueue {
        /// The tag of the command.
        tag: u64,
        /// The `RecipientId` of the queue.
        recipient_id: [u8; 32],
        /// The encoded `QueueAddress` that a stranger writes to.
        address: Vec<u8>,
    },
    /// No relay made the rendezvous queue of this tag.
    RendezvousRefused(u64),
    /// The report queue of an authority exists at its relay.
    ReportQueue {
        /// The encoded `QueueAddress` that a client writes to.
        address: Vec<u8>,
    },
    /// A `SealedReport` arrived on the report queue (`WIR-536`).
    LinkFault(Vec<u8>),
    /// The loop of a probe left: its chain and the tag that each hop read.
    Probe {
        /// The relays of the chain, the ingress first.
        chain: [[u8; 32]; 3],
        /// The tag of the cell at each hop.
        tags: [[u8; 16]; 3],
    },
    /// No ready circuit took the probe.
    ProbeFailed,
    /// The loop count and the forced replacements of the run, for the next
    /// run. It comes before [`Update::Offline`].
    Faults(Box<LinkFaults>),
    /// A hello arrived on a rendezvous queue.
    Hello {
        /// The rendezvous queue.
        queue: [u8; 32],
        /// The sealed envelope of `DIS-143`.
        envelope: Vec<u8>,
    },
    /// A digest arrived on a notify queue (`NTF-107`).
    Digest {
        /// The `GroupQueueId` that holds records.
        group_queue_id: [u8; 32],
    },
    /// An inbound queue of a contact ended at the end of its rotation.
    QueueEnded([u8; 32]),
    /// A relay refused a record to a contact with `REJECTED` (`NET-182`).
    ChannelDead(ContactId),
    /// This device acknowledged the queue of a contact above a hole, and
    /// the records in that hole are lost (Part 6 `WIR-116`).
    DeliveryGap(ContactId),
    /// The node sealed the record of a tag under this `send_index`.
    SendIndex {
        /// The tag of the send.
        tag: u64,
        /// The `send_index` of the record.
        index: u16,
    },
    /// A record of a contact did not open, and its context names this
    /// `send_index` (`WIR-254`).
    Lost {
        /// The contact.
        contact: ContactId,
        /// The `send_index` of the record.
        index: u16,
    },
    /// The relay took the record of a tag and named the room of the queue.
    Room {
        /// The tag of the send.
        tag: u64,
        /// The records that the queue can still take.
        remaining: u32,
    },
    /// The queue of the contact is full, and the record of the tag waits
    /// for room (`NET-016`, `IMP-082`).
    Held(u64),
    /// A contact reads a new queue, at this address.
    QueueRotated {
        /// The contact.
        contact: ContactId,
        /// The encoded `QueueAddress`.
        address: Zeroizing<Vec<u8>>,
    },
    /// The peer gave a new address on the channel.
    PeerMoved(ContactId),
    /// A renewal replaced the channel of a contact (Part 3 §3.2.6).
    ChannelRenewed(ContactId),
    /// A minute of a ready run passed. The work of weeks and hours, as the
    /// dead-channel blob of Part 3 §3.2.6, runs at it.
    Tick,
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
    /// The bundle of the sync channel of a device, for its provision.
    DeviceInvitation(Vec<u8>),
    /// The relay holds no blob for a link that the user accepted: a second
    /// party fetched it first, or it passed its lifetime (`IDN-023`).
    InvitationGone,
    /// A contact is ready.
    Contact {
        /// The contact.
        contact: ContactId,
        /// The static key of the peer.
        peer_static: [u8; 32],
        /// Whether the channel is the sync channel of a device.
        is_device: bool,
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
    /// A push-wake session reached `WAKE_SESSION_MAX` (`NET-100`). No fault.
    WakeDone = 7,
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
        let _ = updates.send(Update::Faults(Box::new(node.take_faults())));
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
    let mut rendezvous_tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut device_invites: BTreeSet<u64> = BTreeSet::new();
    let mut is_foreground = true;
    let mut next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
    // The tick of `CIRCUIT_BUILD_TIMEOUT`. It sends nothing unless a build
    // ran out, and the cover clock stays memoryless.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // The check of the queue rotations of Part 3 §3.2.6. A rotation
    // counts in days, thus a check each minute is on time.
    let mut next_rotation_check = unix_now();
    let mut last_faults = LinkFaults::default();
    // NET-100: the end of a push-wake session, or none for a run of the
    // screen or of the carrier.
    let mut wake_end: Option<tokio::time::Instant> = None;
    // SCP-018: the monotonic source beside the device clock, from which a
    // tick sees a clock movement.
    let mut clock_base = (tokio::time::Instant::now(), unix_now());
    let ended = 'run: loop {
        // WIR-254, WIR-339: the indices of the records of the user, and the
        // holes of the records of the contacts.
        for (handle, index) in node.take_send_indices() {
            if let Some(tag) = tags.get(&handle) {
                let _ = updates.send(Update::SendIndex { tag: *tag, index });
            }
        }
        for (contact, index) in node.take_lost() {
            let _ = updates.send(Update::Lost { contact, index });
        }
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
                    if now_foreground {
                        wake_end = None;
                    }
                    Vec::new()
                }
                Some(Command::Challenges { book, now }) => {
                    node.set_challenges(book, now);
                    Vec::new()
                }
                Some(Command::Wake) => {
                    wake_end = Some(
                        tokio::time::Instant::now()
                            + Duration::from_secs(umbra_core::notify::WAKE_SESSION_MAX),
                    );
                    Vec::new()
                }
                Some(command) => {
                    early.push_back(command);
                    Vec::new()
                }
            },
            () = async {
                match wake_end {
                    Some(end) => tokio::time::sleep_until(end).await,
                    None => core::future::pending().await,
                }
            } => break 'run Ended::WakeDone,
            // The clock is memoryless, and it fires whether or not a cell
            // waits (`NET-049`). A fault of one slot ends no run.
            () = tokio::time::sleep_until(next_slot) => {
                next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
                let now = unix_now();
                let receipt = persist.due_receipt(now);
                // NET-065: a digest only where no receipt waits.
                let digest = if receipt.is_none() { persist.due_digest(now) } else { None };
                let given = receipt.as_ref().map(|(contact, app)| (contact, app.as_slice()));
                let offered = digest.as_ref().map(|(contact, app)| (contact, app.as_slice()));
                match node.on_cover_slot(is_foreground, given, offered, now, &mut rng) {
                    Ok(CoverSlot::Receipt) => persist.receipt_sent(),
                    Ok(CoverSlot::Digest) => persist.digest_sent(),
                    _ => {}
                }
                for contact in node.take_gaps() {
                    let _ = updates.send(Update::DeliveryGap(contact));
                }
                Vec::new()
            }
            // NET-169: a build that no relay answers ends, and the run
            // ends with its last circuit.
            _ = tick.tick() => {
                let now = unix_now();
                // SCP-019: a step of the device clock of more than
                // CLOCK_SKEW against the monotonic source interrupts each
                // duration that runs.
                let mono = i128::from(clock_base.0.elapsed().as_secs());
                let wall = i128::from(now) - i128::from(clock_base.1);
                if (wall - mono).abs() > i128::from(umbra_core::directory::CLOCK_SKEW) {
                    node.clock_moved(now);
                }
                clock_base = (tokio::time::Instant::now(), now);
                node.set_challenge_clock(now);
                let mut events = node.on_tick(now);
                // DIS-015: the rendezvous circuits start on their own delay.
                let _ = node.start_rendezvous_due(now, &mut rng);
                // NET-176: a fault of one rotation ends no run, and the
                // next check tries again.
                if node.is_ready() && now >= next_rotation_check {
                    next_rotation_check = now.saturating_add(60);
                    events.extend(node.rotate_due(now, &mut rng).unwrap_or_default());
                    let _ = updates.send(Update::Tick);
                }
                // The view of the connection reads the counts while the run
                // holds them.
                if node.faults() != &last_faults {
                    last_faults = node.faults().clone();
                    let _ = updates.send(Update::Faults(Box::new(last_faults.clone())));
                }
                events
            }
        };
        // ABU-048: each `NEW` that a relay under load refused goes once
        // more with a token of this device, or with a proof of work.
        let mut events = events;
        let asked: Vec<u64> = events
            .iter()
            .filter_map(|event| match event {
                ClientEvent::AdmissionAsked { handle } => Some(*handle),
                _ => None,
            })
            .collect();
        for handle in asked {
            let token = persist.admission_token(unix_now());
            match node.admit_queue(handle, token.as_deref(), &mut rng) {
                Ok(more) => events.extend(more),
                Err(_) => break 'run Ended::NodeFault,
            }
        }
        if let Err(ended) = settle(&mut node, persist.as_mut(), &events) {
            break 'run ended;
        }
        for event in events {
            let update = match event {
                ClientEvent::CircuitReady => Update::Online,
                ClientEvent::Invitation { handle, bundle } => {
                    if device_invites.remove(&handle) {
                        Update::DeviceInvitation(bundle)
                    } else {
                        Update::Invitation(bundle)
                    }
                }
                ClientEvent::InvitationLink { fragment, .. } => Update::Invitation(fragment),
                ClientEvent::InvitationGone { .. } => Update::InvitationGone,
                ClientEvent::ContactReady {
                    contact,
                    peer_static,
                    is_device,
                } => Update::Contact {
                    contact,
                    peer_static,
                    is_device,
                },
                ClientEvent::Message { contact, app } => Update::Message { contact, app },
                ClientEvent::VerificationCode { contact, code } => {
                    Update::VerificationCode { contact, code }
                }
                ClientEvent::Accepted { handle } => match tags.remove(&handle) {
                    Some(tag) => Update::Sent(tag),
                    None => continue,
                },
                ClientEvent::Room { handle, remaining } => match tags.get(&handle) {
                    Some(tag) => Update::Room {
                        tag: *tag,
                        remaining,
                    },
                    None => continue,
                },
                // NET-218: a `LIMIT` of a full queue ends no send.
                ClientEvent::Rejected {
                    handle,
                    reason: umbra_queue::Reject::Limit,
                } if tags.contains_key(&handle) => match tags.remove(&handle) {
                    Some(tag) => Update::Held(tag),
                    None => continue,
                },
                ClientEvent::Rejected { handle, .. } => match tags.remove(&handle) {
                    Some(tag) => Update::Failed(tag),
                    // A relay refused the `NEW` of a rendezvous queue.
                    None => match rendezvous_tags.remove(&handle) {
                        Some(tag) => Update::RendezvousRefused(tag),
                        None => continue,
                    },
                },
                // The node of the queues sends no chunk command and no
                // group-queue command, thus it gets no such answer. The
                // transfer of Part 12 has a node and a connection of its
                // own (§12.8), and a group queue takes a session that
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
                ClientEvent::RendezvousQueue {
                    handle,
                    recipient_id,
                    address,
                } => match rendezvous_tags.remove(&handle) {
                    Some(tag) => Update::RendezvousQueue {
                        tag,
                        recipient_id,
                        address,
                    },
                    None => continue,
                },
                ClientEvent::Hello { queue, envelope } => Update::Hello { queue, envelope },
                ClientEvent::ReportQueue { address, .. } => Update::ReportQueue { address },
                ClientEvent::LinkFault { sealed, .. } => Update::LinkFault(sealed),
                // The contact follows flight 1 of the addressee.
                ClientEvent::HelloSent { .. } | ClientEvent::AdmissionAsked { .. } => continue,
                ClientEvent::NotifyKey {
                    recipient_id,
                    relay_ntf_pk,
                } => Update::NotifyKey {
                    recipient_id,
                    relay_ntf_pk,
                },
                ClientEvent::QueueEnded { queue } => Update::QueueEnded(queue),
                ClientEvent::ChannelDead { contact } => Update::ChannelDead(contact),
                ClientEvent::QueueRotated { contact, address } => Update::QueueRotated {
                    contact,
                    address: Zeroizing::new(address),
                },
                ClientEvent::PeerMoved { contact } => Update::PeerMoved(contact),
                ClientEvent::ChannelRenewed { contact } => Update::ChannelRenewed(contact),
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
                // The loop above takes these commands.
                Command::Foreground(_) | Command::Wake | Command::Challenges { .. } => {}
                Command::SetClass { contact, class } => node.set_contact_class(&contact, class),
                Command::Invite => {
                    if node.invite_link(&mut rng).is_err() {
                        let _ = updates.send(Update::Refused);
                    }
                }
                Command::InviteDevice => match node.invite_device(&mut rng) {
                    Ok(handle) => {
                        device_invites.insert(handle);
                    }
                    Err(_) => {
                        let _ = updates.send(Update::Refused);
                    }
                },
                Command::AcceptDevice(bundle) => {
                    if node.accept_device(bundle, &mut rng).is_err() {
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
                Command::RotateNow(contact) => {
                    let _ = node.rotate_now(&contact);
                }
                Command::RotateSwept(contact) => {
                    let _ = node.rotate_swept(&contact, now, &mut rng);
                }
                Command::PeerMoved { contact, address } => {
                    let _ = node.peer_moved(&contact, &address, now, &mut rng);
                }
                Command::PeerKey { contact, key } => {
                    let _ = node.set_peer_key(&contact, key);
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
                Command::MakeRendezvousQueue(tag) => match node.make_rendezvous_queue(&mut rng) {
                    Ok(handle) => {
                        rendezvous_tags.insert(handle, tag);
                    }
                    Err(_) => {
                        let _ = updates.send(Update::RendezvousRefused(tag));
                    }
                },
                Command::MakeReportQueue => {
                    let _ = node.make_report_queue(&mut rng);
                }
                Command::OpenCircuit(relay) => {
                    let _ = node.open_circuit(relay, &mut rng);
                }
                Command::Probe => {
                    let _ = updates.send(match node.probe() {
                        Ok((chain, tags)) => Update::Probe { chain, tags },
                        Err(_) => Update::ProbeFailed,
                    });
                }
                Command::EndRendezvousQueue(recipient_id) => {
                    let _ = node.end_rendezvous_queue(&recipient_id, &mut rng);
                }
                Command::Hello {
                    entry_pk,
                    rendezvous,
                    profile,
                    token,
                } => {
                    let epoch = umbra_core::abuse::epoch_number(now);
                    let _ = node.hello(
                        &entry_pk,
                        &rendezvous,
                        &profile,
                        epoch,
                        token.as_deref(),
                        &mut rng,
                    );
                }
            }
            if let Err(ended) = settle(&mut node, persist.as_mut(), &[]) {
                break 'run ended;
            }
        }
    };
    // REL-172: the counts go to the next run.
    let _ = updates.send(Update::Faults(Box::new(node.take_faults())));
    let _ = updates.send(Update::Offline(ended));
}
