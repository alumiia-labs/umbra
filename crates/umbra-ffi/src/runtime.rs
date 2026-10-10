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
        node::{ClientEvent, ClientNode, ContactId, CoverSlot, ParkedSession, StateChange},
    },
};
use umbra_crypto::{
    rand_core::{TryCryptoRng, TryRng},
    rng::HardenedRng,
    secret::Secret,
};
use umbra_transport::{
    link::PAUSE_WAIT,
    native::{self, ClientConfig},
    race::{Plan, Wire},
    Dial,
};
use zeroize::{Zeroize, Zeroizing};

/// The entropy of the operating system, hardened under `K_rng_harden` once a
/// store is open (Part 5 §5.9, Part 14 `IMP-093`). A client that cannot draw
/// a random value stops, because each key and each identifier needs one.
pub struct OsRng;

/// `K_rng_harden` of the store that this process opened. It stays while the
/// store is open, thus a platform generator that fails after the first
/// unlock shows no raw output on the wire. A lock takes it away with each
/// other key (`IMP-127`). A locked client runs no network, and its values
/// come from the platform source alone until the next unlock.
static HARDEN: std::sync::Mutex<Option<Secret<32>>> = std::sync::Mutex::new(None);

/// The context of each value of this process under the hardening.
const HARDEN_CONTEXT: &[u8] = umbra_crypto::labels::CLIENT_RNG;

/// The draws of this process under the hardening.
static HARDEN_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The value that separates one hardened draw from each other (RFC 8937 §4):
/// the call number of the process and the wall time in nanoseconds. The
/// number separates two draws of one process, and the time separates two
/// processes that start from one image of the memory.
fn harden_call() -> [u8; umbra_crypto::rng::CALL_LEN] {
    let call = HARDEN_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let mut out = [0u8; umbra_crypto::rng::CALL_LEN];
    let (head, tail) = out.split_at_mut(8);
    head.copy_from_slice(&call.to_be_bytes());
    tail.copy_from_slice(&nanos.to_be_bytes());
    out
}

/// Hardens each later value of [`OsRng`] under `key`.
pub fn harden_with(key: Secret<32>) {
    *HARDEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(key);
}

/// Takes `K_rng_harden` out of the memory at a lock (`IMP-127`). The key
/// overwrites itself at its drop.
pub fn harden_clear() {
    *HARDEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// Whether [`OsRng`] hardens its values now.
pub fn is_hardened() -> bool {
    HARDEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
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
            Some(key) => HardenedRng::new(&mut PlatformRng, key, HARDEN_CONTEXT, harden_call())
                .try_fill_bytes(dst),
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
    /// The link of a device ended with no sync channel (Part 7 `DEV-290`):
    /// each invitation on the list of the store ends, and each one that
    /// [`Command::InviteDevice`] asked for in this run. Its prekey and its
    /// handshake state go, and its queue takes a `DEL`. An invitation
    /// whose queue no relay made yet ends when the relay made it, and no
    /// update names it.
    EndDeviceInvitation(Vec<[u8; 32]>),
    /// Send one application record. An [`Update::Sent`] with the same tag
    /// follows the acknowledgment of the relay.
    Send {
        /// The contact.
        contact: ContactId,
        /// The encoded `AppMessage`. It is plaintext, thus it overwrites
        /// itself at its drop, also while the command waits for a circuit
        /// (`IMP-126`).
        app: Zeroizing<Vec<u8>>,
        /// A value of the caller, which comes back in the update.
        tag: u64,
        /// The sends of the record before this command.
        prior: Prior,
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
    /// The dead-channel blob of the peer gave a candidate address
    /// (`NET-190`).
    PeerMoved {
        /// The contact.
        contact: ContactId,
        /// The encoded `QueueAddress`.
        address: Zeroizing<Vec<u8>>,
        /// Whether the channel is dead, and not silent alone.
        dead: bool,
        /// Whether an earlier run sent to this candidate already
        /// (`NET-191`): this run then sends nothing more to it.
        sent: bool,
    },
    /// The user accepted a new pairwise key of the peer (Part 4 §4.5.1).
    PeerKey {
        /// The contact.
        contact: ContactId,
        /// The new X25519 key of the peer.
        key: [u8; 32],
    },
    /// The answer of the user to a renewal bundle that came with no proof
    /// of the guard (Part 3 `NET-355`).
    AnswerRenewal {
        /// The contact.
        contact: ContactId,
        /// Whether the user accepted the bundle.
        accept: bool,
    },
    /// End each delay of `NET-180` that runs. For a test over real sockets
    /// alone.
    #[cfg(feature = "sockets-test")]
    EndSweeps,
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

/// The sends of one record before a [`Command::Send`], as the store counts
/// them (Part 3 `NET-219`, `NET-220`). The default is a record that never
/// left.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Prior {
    /// The count of the sends, for each reason.
    pub sends: u32,
    /// The time of the first send, in seconds, or 0 with no send.
    pub first: u64,
    /// Whether the send waits for a slot of the cover clock (`NET-071`):
    /// the wait of the record after a `LIMIT` ended inside the run.
    pub in_slot: bool,
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

    /// A relay answered the record of the batch of the last
    /// [`Persist::due_receipt`], and the store erases it (`NET-054`). The
    /// runtime asks for no second batch before.
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

    /// A relay answered the record of the digest of the last
    /// [`Persist::due_digest`].
    fn digest_sent(&mut self) {}

    /// Takes a hello that arrived on a rendezvous queue, before the batch
    /// that moves the cursor of that queue (`WIR-115`). The runtime calls
    /// it in the step that commits the call of the node, and it writes no
    /// capsule of that call before. Thus no `ACK` of the hello leaves while
    /// the store does not hold its request. A run that ends between the two
    /// commits gets the hello again, and a store drops the second copy. The
    /// result is none for a store that takes no hello here: the runtime
    /// then gives it as an [`Update::Hello`]. False ends the run with no
    /// commit, as a batch that the store did not take does.
    fn commit_hello(&mut self, _queue: &[u8; 32], _envelope: &[u8]) -> Option<bool> {
        None
    }

    /// Takes the queue of a sync invitation of a device that a relay made
    /// (`DEV-290`), before the batch that stores the invitation. Thus a
    /// later run retires an invitation whose link ended with this run.
    /// False ends the run with no commit.
    fn device_invitation(&mut self, _queue: &[u8; 32]) -> bool {
        true
    }
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
    /// The device clock moved against the monotonic source (Part 1
    /// `SCP-018`), thus the directory correction goes (Part 10 `REL-115`).
    ClockMoved,
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
    /// The address of this device left for the candidate address of a
    /// contact (`NET-191`). Or a relay answered the bundle of a renewal
    /// that went there (`NET-330`). The store keeps that.
    CandidateSent(ContactId),
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
    /// An application record arrived. The store took its plaintext in the
    /// batch of its ratchet state, thus the update carries none.
    Message {
        /// The contact.
        contact: ContactId,
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
    /// No path took the record with this tag: the node could not seal it
    /// or holds no channel for it (`IMP-074`).
    Unsent(u64),
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
    /// A circuit reached a margin of `NET-320` or `NET-321` with no spare
    /// in its place: a push-wake session builds none, and a spare build
    /// can fail. The next run starts at once, and the view shows no fault.
    Aged = 6,
    /// A push-wake session reached `WAKE_SESSION_MAX` (`NET-100`). No fault.
    WakeDone = 7,
}

/// The queue of each invitation of `asked` that the changes of one call
/// store: the stored form of an invitation holds its bundle. The node
/// names an invitation by the handle of its call alone, and it ends one by
/// its queue.
fn invitation_queues(changes: &[StateChange], asked: &[(u64, &[u8])]) -> Vec<(u64, [u8; 32])> {
    let holds = |state: &[u8], bundle: &[u8]| {
        !bundle.is_empty() && state.windows(bundle.len()).any(|part| part == bundle)
    };
    asked
        .iter()
        .filter_map(|(handle, bundle)| {
            changes.iter().find_map(|change| match change {
                StateChange::Invitation { queue, state } if holds(state, bundle) => {
                    Some((*handle, *queue))
                }
                _ => None,
            })
        })
        .collect()
}

/// Commits what the last call of the node gave. The caller writes the
/// capsules of the node after this function only (`IMP-131`). The `ACK` of a
/// record follows its commit (`WIR-115`), in a slot of the cover clock.
///
/// `device_invites` holds the handle of each invitation of a device link
/// that waits for its queue. The result names the queue of each one that
/// this call made (`DEV-290`).
///
/// A hello of this call goes to the store first (`WIR-115`), and the
/// result says whether the store took the hellos.
fn settle(
    node: &mut ClientNode,
    persist: &mut dyn Persist,
    events: &[ClientEvent],
    device_invites: &BTreeSet<u64>,
) -> Result<Settled, Ended> {
    let changes = node.take_changes().map_err(|_| Ended::NodeFault)?;
    let mut stores_hellos = false;
    for event in events {
        if let ClientEvent::Hello { queue, envelope } = event {
            match persist.commit_hello(queue, envelope) {
                Some(true) => stores_hellos = true,
                Some(false) => return Err(Ended::StoreFault),
                None => {}
            }
        }
    }
    let asked: Vec<(u64, &[u8])> = events
        .iter()
        .filter_map(|event| match event {
            ClientEvent::Invitation { handle, bundle } if device_invites.contains(handle) => {
                Some((*handle, bundle.as_slice()))
            }
            _ => None,
        })
        .collect();
    let made = invitation_queues(&changes, &asked);
    for (_, queue) in &made {
        if !persist.device_invitation(queue) {
            return Err(Ended::StoreFault);
        }
    }
    let mut received: Vec<(ContactId, Vec<u8>)> = events
        .iter()
        .filter_map(|event| match event {
            ClientEvent::Message { contact, app } => Some((*contact, app.clone())),
            _ => None,
        })
        .collect();
    let settled = Settled {
        made,
        stores_hellos,
    };
    if changes.is_empty() && received.is_empty() {
        return Ok(settled);
    }
    let committed = persist.commit(changes, &received);
    // IMP-126: the store holds each record now, and this copy of the
    // plaintext leaves the memory.
    for (_, app) in &mut received {
        app.zeroize();
    }
    if !committed {
        return Err(Ended::StoreFault);
    }
    Ok(settled)
}

/// What one commit of [`settle`] found.
struct Settled {
    /// The queue of each device invitation that the call made, by the
    /// handle of its call.
    made: Vec<(u64, [u8; 32])>,
    /// Whether the store took the hellos of the call, thus no update
    /// carries one.
    stores_hellos: bool,
}

/// The ARQ of the records of the user inside one run (Part 3 §3.7). A
/// relay that answers a `SEND` with `BUSY` or `ADMISSION` refuses the
/// moment and not the record, thus the record goes again (`NET-218`). A
/// record whose send took no answer in [`answer_wait`] goes again too. Each
/// one goes in a slot of the cover clock and at no timeout (`NET-071`). A
/// record goes `SEND_MAX_ATTEMPTS` times at most (`NET-219`), and for
/// `SEND_GIVE_UP` from its first send at most (`NET-220`). The two bounds
/// start from the count of the store, thus they hold across the runs. A
/// record whose ARQ stops fails (`NET-221`). The run holds the plaintext
/// of each record that waits for its relay acknowledgment, and each copy
/// overwrites itself at its drop (`IMP-126`). The store holds the record
/// too, thus the next run sends one that this run lost.
#[derive(Default)]
struct Resends {
    held: BTreeMap<u64, HeldSend>,
    /// The tags that wait for a slot, the oldest refusal first.
    due: VecDeque<u64>,
}

struct HeldSend {
    contact: ContactId,
    app: Zeroizing<Vec<u8>>,
    arq: umbra_queue::client::arq::Arq,
    /// The time from which the record goes again with no answer, or none
    /// while no send of it waits for one.
    again_at: Option<u64>,
}

/// The first wait for the answer of a relay to a `SEND`, in seconds. The
/// wait is the one of a group post (Part 11 `GRP-198`).
const ANSWER_WAIT: u64 = 30;

/// The longest wait for the answer of a relay to a `SEND`, in seconds.
const ANSWER_WAIT_MAX: u64 = 12 * 3_600;

/// The time that a record waits for the answer of a relay after its send
/// of the number `sends`: [`ANSWER_WAIT`], and twice the time before at
/// each later send, up to [`ANSWER_WAIT_MAX`]. No timer fires at its end
/// (`NET-071`): the slot of the cover clock after it carries the record.
fn answer_wait(sends: u32) -> u64 {
    ANSWER_WAIT
        .saturating_mul(1u64 << sends.saturating_sub(1).min(16))
        .min(ANSWER_WAIT_MAX)
}

impl Resends {
    /// Holds the record of `tag` for its ARQ, with the sends that the
    /// store counts. The result says whether a send may happen at `now`.
    /// False is the end of its ARQ, and the run holds nothing for it.
    fn hold(
        &mut self,
        tag: u64,
        contact: ContactId,
        app: Zeroizing<Vec<u8>>,
        prior: Prior,
        now: u64,
    ) -> bool {
        let first = (prior.sends > 0 && prior.first != 0).then_some(prior.first);
        let mut arq = umbra_queue::client::arq::Arq::resumed(prior.sends, first);
        if !arq.may_send(now) {
            return false;
        }
        let held = HeldSend {
            contact,
            app,
            arq,
            again_at: None,
        };
        self.held.insert(tag, held);
        true
    }

    /// A send of the record of `tag` left at `now`: the node sealed it
    /// and put it on a circuit. The send counts, and the wait for its
    /// answer starts.
    fn left(&mut self, tag: u64, now: u64) {
        if let Some(held) = self.held.get_mut(&tag) {
            held.arq.sent(now);
            held.again_at = Some(now.saturating_add(answer_wait(held.arq.attempts())));
        }
    }

    /// The record of `tag` waits for a slot.
    fn wait(&mut self, tag: u64) {
        if self.held.contains_key(&tag) && !self.due.contains(&tag) {
            self.due.push_back(tag);
        }
    }

    /// The ARQ of `tag` ended: a relay took the record, or the record
    /// failed.
    fn ended(&mut self, tag: u64) {
        self.held.remove(&tag);
        self.due.retain(|held| *held != tag);
    }

    /// A relay refused the record of `tag` with `reason` at `now`. The
    /// result says whether the record goes again in a slot. False is the
    /// end of its ARQ.
    fn refused(&mut self, tag: u64, reason: umbra_queue::Reject, now: u64) -> bool {
        let Some(held) = self.held.get_mut(&tag) else {
            return false;
        };
        held.arq.rejected(reason);
        held.again_at = None;
        if held.arq.may_send(now) {
            self.wait(tag);
            return true;
        }
        self.ended(tag);
        false
    }

    /// Each record whose send took no answer of a relay until `now`, neither
    /// a `QUOTA` nor a `NACK`, waits for a slot, the oldest send first.
    fn unanswered(&mut self, now: u64) {
        let mut late: Vec<(u64, u64)> = self
            .held
            .iter()
            .filter_map(|(tag, held)| Some((held.again_at.filter(|at| now >= *at)?, *tag)))
            .collect();
        late.sort_unstable();
        for (_, tag) in late {
            if let Some(held) = self.held.get_mut(&tag) {
                held.again_at = None;
            }
            self.wait(tag);
        }
    }

    /// The record that takes the next slot at `now`: its tag, and whether
    /// the send is its first retransmission (`NET-065`). Each record whose
    /// ARQ stopped while it waited goes to `stopped`.
    fn next(&mut self, now: u64, stopped: &mut Vec<u64>) -> Option<(u64, bool)> {
        while let Some(tag) = self.due.front().copied() {
            let Some(held) = self.held.get_mut(&tag) else {
                self.due.pop_front();
                continue;
            };
            if held.arq.may_send(now) {
                return Some((tag, held.arq.attempts() == 1));
            }
            self.ended(tag);
            stopped.push(tag);
        }
        None
    }

    /// The record of `tag` takes this slot: its contact and its bytes.
    /// The send counts when it leaves ([`Resends::left`]).
    fn take(&mut self, tag: u64) -> Option<(ContactId, Zeroizing<Vec<u8>>)> {
        self.due.retain(|held| *held != tag);
        let held = self.held.get(&tag)?;
        Some((held.contact, held.app.clone()))
    }
}

/// The mean time between two slots of the cover clock: λ = 0.05 cells for
/// each second (Part 3 §3.6.2, tier A).
const COVER_MEAN: Duration = Duration::from_secs(20);

/// The longest time that the run waits for the answer of a relay
/// (`IMP-146`). The answer is to the record of a batch of receipts or of a
/// digest. The store keeps the batch past it, and a later slot carries it
/// again.
const CARRIED_WAIT: Duration = Duration::from_secs(600);

/// A monotonic source that runs while the device sleeps. `Instant` stops
/// in a suspend on Linux and Android, and a night of sleep then reads as a
/// clock movement; `/proc/uptime` counts the suspend, as `CLOCK_BOOTTIME`
/// does. A platform with no such file falls back to `Instant`.
#[derive(Clone, Copy)]
struct AwakeClock {
    instant: tokio::time::Instant,
    uptime: Option<u64>,
}

impl AwakeClock {
    fn uptime() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/uptime").ok()?;
        let whole = text.split(['.', ' ']).next()?;
        whole.parse().ok()
    }

    fn now() -> Self {
        AwakeClock {
            instant: tokio::time::Instant::now(),
            uptime: Self::uptime(),
        }
    }

    /// The seconds since `self`, and whether the source of that count runs
    /// while the device sleeps. A file that did not read at one of the two
    /// times gives the count of `Instant`, which no sleep moves.
    fn elapsed(&self) -> (u64, bool) {
        match (self.uptime, Self::uptime()) {
            (Some(then), Some(now)) => (now.saturating_sub(then), true),
            _ => (self.instant.elapsed().as_secs(), false),
        }
    }
}

/// The idle time of the auto-lock (`IMP-119`, Part 1 `SCP-018`). It is the
/// time since the last action of the user, on a monotonic source that runs
/// while the device sleeps. The device clock has no part in it, thus a step
/// of that clock neither locks a client nor keeps one open. With no source
/// that counts the sleep the count is the one of `Instant`: the client then
/// locks late by each sleep, and never early.
pub struct IdleClock {
    last: AwakeClock,
}

impl Default for IdleClock {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleClock {
    /// An idle time that starts now.
    pub fn new() -> Self {
        IdleClock {
            last: AwakeClock::now(),
        }
    }

    /// The user acted, and the idle time starts again.
    pub fn touch(&mut self) {
        self.last = AwakeClock::now();
    }

    /// The seconds since the last action of the user.
    pub fn idle(&self) -> u64 {
        self.last.elapsed().0
    }
}

/// The two clocks at the first reading of this process: the monotonic
/// source, and the device clock in seconds.
static CLOCK_ANCHOR: std::sync::OnceLock<(AwakeClock, u64)> = std::sync::OnceLock::new();

/// The reading of [`clock_offset`] that a run of this process saw last. A
/// run that starts compares its first reading against it. Thus it sees a
/// movement of the device clock while no run lived: under a lock, or with
/// no network.
static CLOCK_SEEN: std::sync::Mutex<Option<(i64, bool)>> = std::sync::Mutex::new(None);

/// How far the device clock at `now` ran ahead of the monotonic source
/// since the first reading of this process, in seconds. The result also
/// says whether that source runs while the device sleeps.
fn clock_offset(now: u64) -> (i64, bool) {
    let (anchor, then) = CLOCK_ANCHOR.get_or_init(|| (AwakeClock::now(), now));
    let (mono, counts_sleep) = anchor.elapsed();
    let ahead = i128::from(now) - i128::from(*then) - i128::from(mono);
    let bound = if ahead < 0 { i64::MIN } else { i64::MAX };
    (i64::try_from(ahead).unwrap_or(bound), counts_sleep)
}

/// Whether the device clock moved between two readings of
/// [`clock_offset`] by more than `CLOCK_SKEW` (Part 1 `SCP-019`). The two
/// compare against one source. On a source that runs while the device
/// sleeps, a movement in each direction counts. A source that stops in a
/// sleep falls behind the device clock by each sleep. Thus a device clock
/// that ran ahead of it shows a sleep or a movement, and it counts as none.
/// A night of sleep must not start each rotation, each invitation, and each
/// `DEL` again. A device clock that fell behind such a source moved back.
/// Two readings of two sources compare no more.
fn clock_stepped(before: (i64, bool), after: (i64, bool)) -> bool {
    let skew = i64::try_from(umbra_core::directory::CLOCK_SKEW).unwrap_or(i64::MAX);
    let moved = after.0.saturating_sub(before.0);
    match (before.1, after.1) {
        (true, true) => moved.saturating_abs() > skew,
        (false, false) => moved < skew.saturating_neg(),
        _ => false,
    }
}

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

/// The session that one run parked, for the next run of this process
/// (Part 6 §6.2.3). It lives in the memory of the process alone
/// (`WIR-549`): no store takes it, and a lock erases it with each other
/// key. Each run takes a turn at its start. A run that is not the newest
/// one any more leaves nothing here, thus the session of a run that a lock
/// or a later run ended comes back in no later one.
#[derive(Clone, Default)]
pub struct ResumeSlot(Arc<std::sync::Mutex<(u64, Option<ParkedSession>)>>);

impl ResumeSlot {
    fn held(&self) -> std::sync::MutexGuard<'_, (u64, Option<ParkedSession>)> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The turn of a run that starts, and the session that the run before
    /// parked.
    fn take(&self) -> (u64, Option<ParkedSession>) {
        let mut held = self.held();
        held.0 = held.0.wrapping_add(1);
        (held.0, held.1.take())
    }

    /// Keeps the session that the run of `turn` parked.
    fn put(&self, turn: u64, parked: Option<ParkedSession>) {
        let mut held = self.held();
        if held.0 == turn {
            held.1 = parked;
        }
    }

    /// Erases the parked session, and takes the turn of each run that
    /// lives: at a lock, and at a change of the identity.
    pub fn clear(&self) {
        let mut held = self.held();
        held.0 = held.0.wrapping_add(1);
        held.1 = None;
    }

    /// Whether a parked session waits for the next run.
    pub fn holds(&self) -> bool {
        self.held().1.is_some()
    }
}

/// The time that a run waits for the first capsule of the relay after a
/// `SessionResume`. A relay that binds the resume sends a cell on each kept
/// circuit that took a `SUB`, about one hop delay later.
const RESUME_CONFIRM_WAIT: Duration = Duration::from_secs(10);

/// The time that the `SessionClose` of a run that ends has to leave.
const CLOSE_WAIT: Duration = Duration::from_secs(1);

/// Opens a connection to the guard.
async fn dial(guard: &Dial, tls: &Arc<ClientConfig>, rng: &mut OsRng) -> Option<native::Link> {
    let mut key = [0u8; 16];
    let mut mask = [0u8; 4];
    let _ = rng.try_fill_bytes(&mut key);
    let _ = rng.try_fill_bytes(&mut mask);
    let plan = Plan::Only(Wire::Tcp);
    native::connect(guard, tls.clone(), plan, key, mask, Duration::from_secs(10))
        .await
        .ok()
}

/// The resume of a session failed (`WIR-547`): the node drops it, and it
/// opens a new session with new circuits on a new connection.
async fn open_again(
    node: &mut ClientNode,
    guard: &Dial,
    tls: &Arc<ClientConfig>,
    rng: &mut OsRng,
) -> Result<native::Link, Ended> {
    node.resume_failed();
    let link = dial(guard, tls, rng).await.ok_or(Ended::DialFailed)?;
    node.connected(rng).map_err(|_| Ended::NodeFault)?;
    Ok(link)
}

/// Runs one client until the connection ends or each sender of `commands`
/// closes. A command that arrives before the circuit is ready waits. The
/// channel has no bound, because the caller is a thread of the platform
/// that cannot wait, and the store holds each record of it already.
///
/// `node` holds the contacts and the invitations of the earlier runs, and
/// `persist` takes each change of them.
///
/// `resume` holds the session that an earlier run of this process parked.
/// The run continues it on its connection (`WIR-361`). A run that ends at
/// the word of the client, or with its link, parks its session there for
/// the next run (`WIR-360`). A run with no such place keeps no session: it
/// ends each one with a `SessionClose` (`WIR-246`).
pub async fn run_client(
    mut node: ClientNode,
    guard: Dial,
    tls: Arc<ClientConfig>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    updates: mpsc::UnboundedSender<Update>,
    mut persist: Box<dyn Persist>,
    resume: Option<ResumeSlot>,
) {
    let mut rng = OsRng;
    let (turn, parked) = resume.as_ref().map_or((0, None), ResumeSlot::take);
    let Some(mut link) = dial(&guard, &tls, &mut rng).await else {
        // The session is as good as before, and the next run tries it.
        if let Some(slot) = &resume {
            slot.put(turn, parked);
        }
        let _ = updates.send(Update::Faults(Box::new(node.take_faults())));
        let _ = updates.send(Update::Offline(Ended::DialFailed));
        return;
    };
    let started = match parked {
        Some(parked) => node.resumed(parked, unix_now(), &mut rng).map(|_| ()),
        None => node.connected(&mut rng),
    };
    if started.is_err() {
        // REL-172: the counts go to the next run.
        let _ = updates.send(Update::Faults(Box::new(node.take_faults())));
        let _ = updates.send(Update::Offline(Ended::NodeFault));
        return;
    }
    // WIR-547: the time at which a resume with no capsule of the relay
    // counts as failed.
    let resume_end = tokio::time::Instant::now() + RESUME_CONFIRM_WAIT;
    // WIR-539, WIR-540: the cause of the end of a run that pauses its
    // session, and the time at which it waits for the relay no more.
    let mut pausing: Option<(Ended, tokio::time::Instant)> = None;

    let mut early: VecDeque<Command> = VecDeque::new();
    let mut shown_chains: Vec<[[u8; 32]; 3]> = Vec::new();
    let mut shown_queues: Vec<([u8; 32], [u8; 32])> = Vec::new();
    let mut notify_tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut rendezvous_tags: BTreeMap<u64, u64> = BTreeMap::new();
    let mut tags: BTreeMap<u64, u64> = BTreeMap::new();
    // NET-218: the records of the user that wait for a relay
    // acknowledgment, for the ARQ of this run.
    let mut resends = Resends::default();
    let mut device_invites: BTreeSet<u64> = BTreeSet::new();
    // DEV-290: the handle of each device invitation whose link ended
    // before a relay made its queue. The store holds the queue of each
    // other one.
    let mut ended_invites: BTreeSet<u64> = BTreeSet::new();
    let mut is_foreground = true;
    let mut next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
    // The tick of `CIRCUIT_BUILD_TIMEOUT`. It sends nothing unless a build
    // ran out, and the cover clock stays memoryless.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // The check of the queue rotations of Part 3 §3.2.6. A rotation
    // counts in days, thus a check each minute is on time. The minute
    // counts on the monotonic source (`SCP-018`): a device clock that moves
    // back stops no check, and no work of [`Update::Tick`] with it.
    let mut next_rotation_check = tokio::time::Instant::now();
    // IMP-146: the batch of receipts or the digest that a slot carried,
    // until a relay answered its record. With it goes the time at which the
    // run waits for that answer no more. The store erases the batch at the
    // answer, thus a run that ends before it leaves the batch there. While
    // one waits, no slot asks the store for a second one: the store names
    // the batch of its last answer alone.
    let mut carried: Option<(CoverSlot, tokio::time::Instant)> = None;
    let mut last_faults = LinkFaults::default();
    // NET-100: the end of a push-wake session, or none for a run of the
    // screen or of the carrier.
    let mut wake_end: Option<tokio::time::Instant> = None;
    // SCP-018, SCP-019: the reading of the two clocks that this run saw
    // last, from which a tick sees a clock movement. It starts from the
    // reading of the last run of this process.
    let mut clock_seen = *CLOCK_SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ended = 'run: loop {
        // WIR-254, WIR-339: the indices of the records of the user, and the
        // holes of the records of the contacts.
        for (handle, index) in node.take_send_indices() {
            if let Some(tag) = tags.get(&handle) {
                // NET-219: a seal is one send of the record, and the wait
                // for its answer starts.
                resends.left(*tag, unix_now());
                let _ = updates.send(Update::SendIndex { tag: *tag, index });
            }
        }
        for (contact, index) in node.take_lost() {
            let _ = updates.send(Update::Lost { contact, index });
        }
        // WIR-540: the relay answered the pause, thus each of its frames
        // arrived, and the connection closes.
        if let Some((cause, _)) = pausing.filter(|_| node.is_paused()) {
            break 'run cause;
        }
        let mut is_closed = false;
        for capsule in node.take_capsules() {
            if link.send(&capsule).await.is_err() {
                is_closed = true;
                break;
            }
        }
        if is_closed {
            if let Some((cause, _)) = pausing {
                break 'run cause;
            }
            if !node.is_resuming() {
                break 'run Ended::LinkClosed;
            }
            match open_again(&mut node, &guard, &tls, &mut rng).await {
                Ok(opened) => link = opened,
                Err(ended) => break 'run ended,
            }
            continue 'run;
        }
        let events = tokio::select! {
            received = link.recv() => match received {
                Ok(bytes) => match node.on_capsule(&bytes, unix_now(), &mut rng) {
                    Ok(events) => events,
                    // The link and the circuit took the cell. A step after
                    // them that sends finds no way while the session
                    // pauses, and the next run does it.
                    Err(_) if pausing.is_some() => Vec::new(),
                    Err(_) => break 'run Ended::NodeFault,
                },
                Err(_) => match pausing {
                    Some((cause, _)) => break 'run cause,
                    None if node.is_resuming() => {
                        match open_again(&mut node, &guard, &tls, &mut rng).await {
                            Ok(opened) => link = opened,
                            Err(ended) => break 'run ended,
                        }
                        Vec::new()
                    }
                    None => break 'run Ended::LinkClosed,
                },
            },
            // WIR-540: a relay that gives no `SessionPaused` in time holds
            // no run open.
            () = async {
                match pausing {
                    Some((_, end)) => tokio::time::sleep_until(end).await,
                    None => core::future::pending().await,
                }
            } => match pausing {
                Some((cause, _)) => break 'run cause,
                None => Vec::new(),
            },
            // WIR-547: a relay that bound the resume sends a cell soon.
            () = tokio::time::sleep_until(resume_end), if node.is_resuming() => {
                match open_again(&mut node, &guard, &tls, &mut rng).await {
                    Ok(opened) => link = opened,
                    Err(ended) => break 'run ended,
                }
                Vec::new()
            }
            command = commands.recv(), if pausing.is_none() => match command {
                // WIR-539: the run ends at the word of the client, and the
                // session pauses for the next run.
                None => {
                    if resume.is_none() || node.pause().is_err() {
                        break 'run Ended::Stopped;
                    }
                    let end = tokio::time::Instant::now() + Duration::from_secs(PAUSE_WAIT);
                    pausing = Some((Ended::Stopped, end));
                    Vec::new()
                }
                Some(Command::Foreground(now_foreground)) => {
                    is_foreground = now_foreground;
                    if now_foreground {
                        wake_end = None;
                        node.set_wake(false);
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
                    // NET-099: a push-wake session builds no spare circuit.
                    node.set_wake(true);
                    Vec::new()
                }
                Some(command) => {
                    early.push_back(command);
                    Vec::new()
                }
            },
            // WIR-360: a push wake ends with a pause of its session.
            () = async {
                match wake_end {
                    Some(end) => tokio::time::sleep_until(end).await,
                    None => core::future::pending().await,
                }
            }, if pausing.is_none() => {
                if node.pause().is_err() {
                    break 'run Ended::WakeDone;
                }
                let end = tokio::time::Instant::now() + Duration::from_secs(PAUSE_WAIT);
                pausing = Some((Ended::WakeDone, end));
                Vec::new()
            }
            // The clock is memoryless, and it fires whether or not a cell
            // waits (`NET-049`). A fault of one slot ends no run.
            () = tokio::time::sleep_until(next_slot), if pausing.is_none() => {
                next_slot = tokio::time::Instant::now() + cover_delay(&mut rng);
                let now = unix_now();
                // NET-071, NET-065: a record of the user goes again in a
                // slot: one that a relay refused with `BUSY` or
                // `ADMISSION`, one whose send took no answer, and one whose
                // wait after a `LIMIT` ended. Its first retransmission comes
                // before each other item. A later one comes after an
                // acknowledgment alone, thus before a receipt, a link-fault
                // report, and a digest.
                resends.unanswered(now);
                let mut stopped = Vec::new();
                let resend = resends.next(now, &mut stopped);
                for tag in stopped {
                    tags.retain(|_, held| *held != tag);
                    let _ = updates.send(Update::Failed(tag));
                }
                if let Some((tag, is_first)) = resend {
                    let is_free =
                        is_first || matches!(node.on_ack_slot(now, &mut rng), Ok(false));
                    if is_free {
                        if let Some((contact, app)) = resends.take(tag) {
                            match node.send(&contact, &app, now, &mut rng) {
                                Ok(handle) => {
                                    tags.insert(handle, tag);
                                }
                                Err(_) => {
                                    resends.ended(tag);
                                    tags.retain(|_, held| *held != tag);
                                    let _ = updates.send(Update::Unsent(tag));
                                }
                            }
                        }
                    }
                    for contact in node.take_gaps() {
                        let _ = updates.send(Update::DeliveryGap(contact));
                    }
                    Vec::new()
                } else {
                // IMP-146: a batch whose record took no answer in
                // `CARRIED_WAIT` waits for none, and a slot carries the
                // batch of the store again.
                if carried.is_some_and(|(_, until)| tokio::time::Instant::now() >= until) {
                    carried = None;
                }
                let receipt = if carried.is_none() { persist.due_receipt(now) } else { None };
                // NET-065: a digest only where no receipt waits.
                let asks_digest = carried.is_none() && receipt.is_none();
                let digest = if asks_digest { persist.due_digest(now) } else { None };
                let given = receipt.as_ref().map(|(contact, app)| (contact, app.as_slice()));
                let offered = digest.as_ref().map(|(contact, app)| (contact, app.as_slice()));
                if let Ok(slot @ (CoverSlot::Receipt | CoverSlot::Digest)) =
                    node.on_cover_slot(is_foreground, given, offered, now, &mut rng)
                {
                    carried = Some((slot, tokio::time::Instant::now() + CARRIED_WAIT));
                }
                for contact in node.take_gaps() {
                    let _ = updates.send(Update::DeliveryGap(contact));
                }
                Vec::new()
                }
            }
            // NET-169: a build that no relay answers ends, and the run
            // ends with its last circuit.
            _ = tick.tick(), if pausing.is_none() => {
                let now = unix_now();
                // SCP-019: a step of the device clock of more than
                // CLOCK_SKEW against the monotonic source interrupts each
                // duration that runs.
                let offset = clock_offset(now);
                if clock_seen.is_some_and(|seen| clock_stepped(seen, offset)) {
                    node.clock_moved(now);
                    let _ = updates.send(Update::ClockMoved);
                }
                clock_seen = Some(offset);
                *CLOCK_SEEN
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(offset);
                node.set_challenge_clock(now);
                let mut events = node.on_tick(now);
                // DIS-015: the rendezvous circuits start on their own delay.
                let _ = node.start_rendezvous_due(now, &mut rng);
                // NET-347: a record that waits takes a new build after one
                // that ran out of time.
                let _ = node.rebuild_lost(now, &mut rng);
                // NET-320, NET-321: a circuit near a margin takes a spare,
                // and the run goes on.
                let _ = node.replace_aging(now, &mut rng);
                // A `SUB` that a relay refused with `LIMIT` or `BUSY` goes
                // again at the end of its wait.
                let _ = node.subscribe_due(now, &mut rng);
                // NET-176: a fault of one rotation ends no run, and the
                // next check tries again.
                if node.is_ready() && tokio::time::Instant::now() >= next_rotation_check {
                    next_rotation_check =
                        tokio::time::Instant::now() + Duration::from_secs(60);
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
            if pausing.is_some() {
                break;
            }
            let token = persist.admission_token(unix_now());
            match node.admit_queue(handle, token.as_deref(), &mut rng) {
                Ok(more) => events.extend(more),
                Err(_) => break 'run Ended::NodeFault,
            }
        }
        let asked: BTreeSet<u64> = device_invites.union(&ended_invites).copied().collect();
        let Settled {
            made,
            stores_hellos,
        } = match settle(&mut node, persist.as_mut(), &events, &asked) {
            Ok(settled) => settled,
            // The store of a run that the client ended takes no batch. The
            // relay holds each record with no `ACK`, and the next run reads
            // it again.
            Err(_) if pausing.is_some() => continue 'run,
            Err(ended) => break 'run ended,
        };
        for event in events {
            let update = match event {
                ClientEvent::CircuitReady => Update::Online,
                ClientEvent::Invitation { handle, bundle } => {
                    let queue = made
                        .iter()
                        .find(|(held, _)| *held == handle)
                        .map(|(_, queue)| *queue);
                    if ended_invites.remove(&handle) {
                        // DEV-290: the link of this invitation ended before
                        // a relay made its queue. It ends here, and no
                        // party gets its bundle. The next call commits the
                        // change, and the `DEL` leaves at a later check.
                        if let Some(queue) = queue {
                            let _ = node.end_invitation(&queue, &mut rng);
                        }
                        continue;
                    }
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
                ClientEvent::Message { contact, mut app } => {
                    // IMP-126: the store took the record in `settle`.
                    app.zeroize();
                    Update::Message { contact }
                }
                ClientEvent::VerificationCode { contact, code } => {
                    Update::VerificationCode { contact, code }
                }
                // IDN-170: the code that the view shows verifies no more.
                ClientEvent::VerificationEnded { contact } => Update::VerificationRefused(contact),
                ClientEvent::Accepted { handle } => match tags.remove(&handle) {
                    Some(tag) => {
                        resends.ended(tag);
                        // An answer to an earlier send of this record
                        // names no record of the run any more.
                        tags.retain(|_, held| *held != tag);
                        Update::Sent(tag)
                    }
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
                    // The client holds the record for the room of the
                    // queue, and it gives it to a later send (`IMP-082`).
                    Some(tag) => {
                        resends.ended(tag);
                        tags.retain(|_, held| *held != tag);
                        Update::Held(tag)
                    }
                    None => continue,
                },
                // NET-218: a `BUSY` or an `ADMISSION` ends no send. The
                // record stays queued, and a slot carries it again.
                ClientEvent::Rejected {
                    handle,
                    reason: reason @ (umbra_queue::Reject::Busy | umbra_queue::Reject::Admission),
                } if tags.contains_key(&handle) => match tags.remove(&handle) {
                    Some(tag) if resends.refused(tag, reason, unix_now()) => continue,
                    // NET-219 to NET-221: the ARQ stopped, and the record
                    // fails.
                    Some(tag) => {
                        tags.retain(|_, held| *held != tag);
                        Update::Failed(tag)
                    }
                    None => continue,
                },
                ClientEvent::Rejected { handle, .. } => match tags.remove(&handle) {
                    Some(tag) => {
                        resends.ended(tag);
                        tags.retain(|_, held| *held != tag);
                        Update::Failed(tag)
                    }
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
                // WIR-115: the store took the hello with its queue cursor.
                ClientEvent::Hello { .. } if stores_hellos => continue,
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
                ClientEvent::CandidateSent { contact } => Update::CandidateSent(contact),
                // IMP-146, NET-054: a relay answered the record of the
                // batch, and the store erases it. An answer that names no
                // batch of this run, as one that came past `CARRIED_WAIT`,
                // erases nothing.
                ClientEvent::Carried { slot } => {
                    if carried.is_some_and(|(held, _)| held == slot) {
                        carried = None;
                        match slot {
                            CoverSlot::Receipt => persist.receipt_sent(),
                            CoverSlot::Digest => persist.digest_sent(),
                            _ => {}
                        }
                    }
                    continue;
                }
                ClientEvent::ChannelRenewed { contact } => Update::ChannelRenewed(contact),
                // NET-355: the store holds the bundle that waits, in the
                // batch of this call, and the client reads the question
                // from there.
                ClientEvent::RenewalAsked { .. } | ClientEvent::RenewalAskEnded { .. } => continue,
                // A run that pauses reads on to the `SessionPaused`.
                ClientEvent::CircuitLost | ClientEvent::CircuitAged if pausing.is_some() => {
                    continue
                }
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
        while node.is_ready() && pausing.is_none() {
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
                // DEV-290: a link that ended retires its sync invitation.
                // A queue whose handshake finished holds no half, and the
                // call changes nothing for it.
                Command::EndDeviceInvitation(queues) => {
                    ended_invites.append(&mut device_invites);
                    for queue in queues {
                        let _ = node.end_invitation(&queue, &mut rng);
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
                Command::Send {
                    contact,
                    app,
                    tag,
                    prior,
                } => {
                    if !resends.hold(tag, contact, app.clone(), prior, now) {
                        // NET-219 to NET-221: the ARQ of the record stopped
                        // in an earlier run, and the record fails.
                        let _ = updates.send(Update::Failed(tag));
                    } else if prior.in_slot {
                        // NET-071: the retry after a `LIMIT` takes a slot.
                        resends.wait(tag);
                    } else {
                        match node.send(&contact, &app, now, &mut rng) {
                            Ok(handle) => {
                                tags.insert(handle, tag);
                            }
                            Err(_) => {
                                resends.ended(tag);
                                let _ = updates.send(Update::Unsent(tag));
                            }
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
                Command::PeerMoved {
                    contact,
                    address,
                    dead,
                    sent,
                } => {
                    let told = node.peer_candidate(&contact, &address, dead, sent, now, &mut rng);
                    // NET-191: the store learns of the one send.
                    for event in told.unwrap_or_default() {
                        if let ClientEvent::CandidateSent { contact } = event {
                            let _ = updates.send(Update::CandidateSent(contact));
                        }
                    }
                }
                Command::PeerKey { contact, key } => {
                    let _ = node.set_peer_key(&contact, key);
                }
                Command::AnswerRenewal { contact, accept } => {
                    let _ = node.answer_renewal(&contact, accept, &mut rng);
                }
                #[cfg(feature = "sockets-test")]
                Command::EndSweeps => {
                    node.end_sweeps(now);
                    next_rotation_check = tokio::time::Instant::now();
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
            if let Err(ended) = settle(&mut node, persist.as_mut(), &[], &BTreeSet::new()) {
                break 'run ended;
            }
        }
    };
    // WIR-360, WIR-542: the session of a run that ended at the word of the
    // client or with its link stays for the next run. A link that closed
    // with no pause resumes only when no frame was in flight.
    let parked = match ended {
        Ended::WakeDone | Ended::Stopped | Ended::LinkClosed if resume.is_some() => {
            node.park(unix_now())
        }
        _ => None,
    };
    // WIR-246: a session that no run continues ends at the relay now, and
    // the relay holds no circuit for it.
    if parked.is_none() {
        if let Some(capsule) = node.close() {
            let _ = tokio::time::timeout(CLOSE_WAIT, link.send(&capsule)).await;
        }
    }
    if let Some(slot) = &resume {
        slot.put(turn, parked);
    }
    // REL-172: the counts go to the next run.
    let _ = updates.send(Update::Faults(Box::new(node.take_faults())));
    let _ = updates.send(Update::Offline(ended));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_that_a_relay_refuses_with_busy_goes_again_inside_its_bounds() {
        use umbra_queue::{
            params::{SEND_GIVE_UP, SEND_MAX_ATTEMPTS},
            Reject,
        };
        let contact = ContactId([3; 32]);
        let app = || Zeroizing::new(vec![1, 2, 3]);
        let new = Prior::default();
        let mut resends = Resends::default();
        let mut stopped = Vec::new();
        assert!(resends.hold(7, contact, app(), new, 100));
        resends.left(7, 100);
        assert_eq!(resends.next(100, &mut stopped), None);
        // NET-218: a `BUSY` and an `ADMISSION` continue the ARQ, and the
        // record waits for a slot. NET-065: the flag names the first
        // retransmission alone.
        assert!(resends.refused(7, Reject::Busy, 101));
        assert_eq!(resends.next(101, &mut stopped), Some((7, true)));
        assert_eq!(resends.take(7).map(|(to, _)| to), Some(contact));
        resends.left(7, 102);
        assert_eq!(resends.next(102, &mut stopped), None);
        assert!(resends.refused(7, Reject::Admission, 103));
        assert_eq!(resends.next(103, &mut stopped), Some((7, false)));
        // NET-219: the send of `SEND_MAX_ATTEMPTS` is the last one.
        for _ in 2..SEND_MAX_ATTEMPTS {
            assert!(resends.take(7).is_some());
            resends.left(7, 104);
            let goes = resends.refused(7, Reject::Busy, 104);
            assert_eq!(goes, resends.held.contains_key(&7));
        }
        assert!(!resends.held.contains_key(&7));
        assert_eq!(resends.next(105, &mut stopped), None);

        // NET-220: a record that waits for a slot past `SEND_GIVE_UP` of
        // its first send stops, and the caller fails it.
        assert!(resends.hold(8, contact, app(), new, 1_000));
        resends.left(8, 1_000);
        assert!(resends.refused(8, Reject::Busy, 1_001));
        assert_eq!(resends.next(1_000 + SEND_GIVE_UP, &mut stopped), None);
        assert_eq!(stopped, [8]);
        // A relay that took the record ends its ARQ, and a refusal of a
        // record that this run does not hold continues none.
        assert!(resends.hold(9, contact, app(), new, 2_000));
        resends.left(9, 2_000);
        resends.ended(9);
        assert!(!resends.refused(9, Reject::Busy, 2_001));
    }

    #[test]
    fn the_bounds_of_a_record_count_from_the_sends_of_the_earlier_runs() {
        use umbra_queue::{
            params::{SEND_GIVE_UP, SEND_MAX_ATTEMPTS},
            Reject,
        };
        let contact = ContactId([3; 32]);
        let app = || Zeroizing::new(vec![1, 2, 3]);
        let mut resends = Resends::default();
        // NET-219: the store counts 14 sends of the record, for each
        // reason. This run has two sends left, and not sixteen.
        let prior = Prior {
            sends: SEND_MAX_ATTEMPTS - 2,
            first: 1_000,
            in_slot: false,
        };
        assert!(resends.hold(5, contact, app(), prior, 2_000));
        resends.left(5, 2_000);
        assert!(resends.refused(5, Reject::Busy, 2_001));
        assert!(resends.take(5).is_some());
        resends.left(5, 2_002);
        assert!(!resends.refused(5, Reject::Admission, 2_003));
        assert!(!resends.held.contains_key(&5));
        // A record at the count of an earlier run takes no send at all.
        let spent = Prior {
            sends: SEND_MAX_ATTEMPTS,
            first: 1_000,
            in_slot: false,
        };
        assert!(!resends.hold(6, contact, app(), spent, 2_000));
        // NET-220: `SEND_GIVE_UP` runs from the first send of the record,
        // which an earlier run made.
        let old = Prior {
            sends: 1,
            first: 1_000,
            in_slot: false,
        };
        assert!(resends.hold(7, contact, app(), old, 1_000 + SEND_GIVE_UP - 1));
        assert!(!resends.hold(8, contact, app(), old, 1_000 + SEND_GIVE_UP));
    }

    #[test]
    fn a_record_with_no_answer_goes_again_in_a_slot_after_its_wait() {
        let contact = ContactId([3; 32]);
        let app = || Zeroizing::new(vec![1, 2, 3]);
        let mut resends = Resends::default();
        let mut stopped = Vec::new();
        assert!(resends.hold(1, contact, app(), Prior::default(), 100));
        // A record that the node holds for a circuit left no send, and it
        // waits for no answer.
        resends.unanswered(100 + ANSWER_WAIT_MAX);
        assert_eq!(resends.next(100 + ANSWER_WAIT_MAX, &mut stopped), None);
        // NET-071: the wait ends with no send. The slot after it carries
        // the record, as its first retransmission (`NET-065`).
        resends.left(1, 100);
        resends.unanswered(100 + ANSWER_WAIT - 1);
        assert_eq!(resends.next(100 + ANSWER_WAIT - 1, &mut stopped), None);
        resends.unanswered(100 + ANSWER_WAIT);
        assert_eq!(
            resends.next(100 + ANSWER_WAIT, &mut stopped),
            Some((1, true))
        );
        assert!(resends.take(1).is_some());
        resends.left(1, 200);
        // The second wait is twice the first one, and the send after it is
        // a later retransmission.
        resends.unanswered(200 + 2 * ANSWER_WAIT - 1);
        assert_eq!(resends.next(200 + 2 * ANSWER_WAIT - 1, &mut stopped), None);
        resends.unanswered(200 + 2 * ANSWER_WAIT);
        assert_eq!(
            resends.next(200 + 2 * ANSWER_WAIT, &mut stopped),
            Some((1, false))
        );
        // The oldest send goes first.
        assert!(resends.hold(2, contact, app(), Prior::default(), 300));
        assert!(resends.hold(3, contact, app(), Prior::default(), 300));
        resends.left(3, 300);
        resends.left(2, 301);
        resends.ended(1);
        resends.unanswered(1_000);
        assert_eq!(resends.next(1_000, &mut stopped), Some((3, true)));
        assert!(resends.take(3).is_some());
        assert_eq!(resends.next(1_000, &mut stopped), Some((2, true)));
        // A relay that answered ends the wait.
        resends.ended(2);
        resends.unanswered(u64::MAX);
        assert_eq!(resends.next(1_000, &mut stopped), None);
        assert!(stopped.is_empty());
        assert_eq!(answer_wait(1), 30);
        assert_eq!(answer_wait(2), 60);
        assert_eq!(
            answer_wait(umbra_queue::params::SEND_MAX_ATTEMPTS),
            ANSWER_WAIT_MAX
        );
    }

    #[test]
    fn the_retry_after_a_limit_waits_for_a_slot_and_goes_as_a_later_retransmission() {
        let contact = ContactId([3; 32]);
        let mut resends = Resends::default();
        let mut stopped = Vec::new();
        // NET-071: the wait after a `LIMIT` ended inside the run. The
        // record leaves at no minute check: it waits for a slot.
        let held = Prior {
            sends: 1,
            first: 1_000,
            in_slot: true,
        };
        assert!(resends.hold(4, contact, Zeroizing::new(vec![9]), held, 2_000));
        resends.wait(4);
        // NET-065: one send left before, thus this one is the first
        // retransmission. After a second send it is a later one.
        assert_eq!(resends.next(2_000, &mut stopped), Some((4, true)));
        assert!(resends.take(4).is_some());
        resends.left(4, 2_001);
        assert!(resends.refused(4, umbra_queue::Reject::Busy, 2_002));
        assert_eq!(resends.next(2_002, &mut stopped), Some((4, false)));
    }

    /// A store that counts what it takes, in the order of the calls.
    struct Ordered {
        calls: Vec<&'static str>,
        takes_hello: Option<bool>,
    }

    impl Persist for Ordered {
        fn commit(&mut self, _: Vec<StateChange>, _: &[(ContactId, Vec<u8>)]) -> bool {
            self.calls.push("batch");
            true
        }

        fn commit_hello(&mut self, _: &[u8; 32], _: &[u8]) -> Option<bool> {
            self.calls.push("hello");
            self.takes_hello
        }
    }

    #[test]
    fn a_hello_goes_to_the_store_before_the_batch_of_its_queue_cursor() {
        let root = umbra_crypto::hierarchy::RootIdentity::new(Secret::new([7; 32]));
        let relay = |number: u8| umbra_crypto::handshake::nk::RelayStatic {
            s: [number; 32],
            relay_id: [number; 32],
        };
        let mut node = ClientNode::new([relay(1), relay(2), relay(3)], root);
        let hello = [ClientEvent::Hello {
            queue: [4; 32],
            envelope: vec![5; 8],
        }];
        // WIR-115: the store takes the hello in the step that commits the
        // call, and the run gives no update for it.
        let mut store = Ordered {
            calls: Vec::new(),
            takes_hello: Some(true),
        };
        let settled = settle(&mut node, &mut store, &hello, &BTreeSet::new());
        assert!(settled.is_ok_and(|settled| settled.stores_hellos));
        assert_eq!(store.calls.first(), Some(&"hello"));
        // A store that did not take it ends the run before the batch, thus
        // no cursor moves and no `ACK` leaves.
        let mut store = Ordered {
            calls: Vec::new(),
            takes_hello: Some(false),
        };
        let settled = settle(&mut node, &mut store, &hello, &BTreeSet::new());
        assert!(matches!(settled, Err(Ended::StoreFault)));
        assert_eq!(store.calls, ["hello"]);
        // A store with no part in it leaves the hello to the update.
        let mut store = Ordered {
            calls: Vec::new(),
            takes_hello: None,
        };
        let settled = settle(&mut node, &mut store, &hello, &BTreeSet::new());
        assert!(settled.is_ok_and(|settled| !settled.stores_hellos));
    }

    #[test]
    fn the_queue_of_a_device_invitation_is_the_one_whose_stored_form_holds_its_bundle() {
        let bundle = vec![0x5A; 64];
        let other = vec![0x3C; 64];
        let stored = |queue: u8, bundle: &[u8]| StateChange::Invitation {
            queue: [queue; 32],
            state: Zeroizing::new([&[0x04u8; 49][..], bundle, &[9; 20]].concat()),
        };
        let changes = [
            stored(1, &other),
            StateChange::InvitationEnded { queue: [3; 32] },
            stored(2, &bundle),
        ];
        // DEV-290: the invitation of handle 7 reads queue 2, and a handle
        // whose bundle no change stores names no queue.
        let asked = [(7u64, bundle.as_slice()), (8, &[0x11; 64][..])];
        assert_eq!(invitation_queues(&changes, &asked), [(7, [2; 32])]);
        assert!(invitation_queues(&changes, &[(9, &[][..])]).is_empty());
    }

    #[test]
    fn the_idle_time_counts_on_the_monotonic_source_and_no_device_clock_enters_it() {
        // IMP-119: the idle time takes no reading of the device clock,
        // thus no step of that clock moves it. It starts at the action of
        // the user, and it starts again there.
        let mut idle = IdleClock::new();
        assert!(idle.idle() <= 1);
        idle.touch();
        assert!(idle.idle() <= 1);
    }

    #[test]
    fn a_sleep_is_no_clock_movement_on_a_source_that_stops_in_it() {
        let skew = i64::try_from(umbra_core::directory::CLOCK_SKEW).unwrap_or(i64::MAX);
        // SCP-019: on a source that counts the sleep, a step of the device
        // clock in each direction is a movement. A step inside CLOCK_SKEW
        // is none.
        assert!(!clock_stepped((0, true), (skew, true)));
        assert!(clock_stepped((0, true), (skew + 1, true)));
        assert!(clock_stepped((40, true), (39 - skew, true)));
        assert!(!clock_stepped((40, true), (40 - skew, true)));
        // A source that stops in a sleep falls behind by each sleep. A
        // night of sleep is thus no movement, and each duration of a
        // rotation, of an invitation, and of a `DEL` runs on.
        assert!(!clock_stepped((0, false), (8 * 3_600, false)));
        // A device clock that fell behind such a source moved back.
        assert!(clock_stepped((0, false), (-skew - 1, false)));
        assert!(!clock_stepped((0, false), (-skew, false)));
        // Two readings of two sources compare no more.
        assert!(!clock_stepped((0, true), (90_000, false)));
        assert!(!clock_stepped((0, false), (-90_000, true)));
        // The reading of this process starts at its anchor.
        let now = unix_now();
        let (offset, _) = clock_offset(now);
        assert!(offset.abs() <= skew);
    }

    #[test]
    fn a_lock_takes_the_hardening_key_and_the_source_still_gives_values() {
        harden_with(Secret::new([7; 32]));
        assert!(is_hardened());
        let mut hardened = [0u8; 32];
        let _ = OsRng.try_fill_bytes(&mut hardened);
        // IMP-127: a locked client holds no key, and its values come from
        // the platform source alone.
        harden_clear();
        assert!(!is_hardened());
        let mut plain = [0u8; 32];
        let _ = OsRng.try_fill_bytes(&mut plain);
        assert_ne!(hardened, [0u8; 32]);
        assert_ne!(plain, [0u8; 32]);
        assert_ne!(hardened, plain);
    }
}
