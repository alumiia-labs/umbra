//! The link of a device (Part 7 §7.4) over the transfer task.
//!
//! The existing device offers: it writes the offer, reads the hello, shows
//! the code, and after the confirmation of the user it uploads the snapshot
//! and writes the provision. The new device joins on a handle whose store
//! holds no data of the user, as a restore does, and [`init_linked`] makes
//! its store from the snapshot.

use std::sync::{Arc, Mutex};

use umbra_core::{
    attach::{
        segment::{pad_handle_object, unpad_handle_object},
        transfer::Uploaded,
    },
    devset::{
        link::{
            commit, hello_slot, offer_slot, DeviceIdentity, LinkHello, LinkOffer, LinkSecret,
            LinkTicket, Provision, Slot,
        },
        DeviceId, LINK_PROVISION_TTL, LINK_QR_TTL,
    },
};
use umbra_crypto::{kem::KeyPair, rand_core::TryRng, secret::Secret};
use umbra_wire::descriptor::FileDescriptor;
use zeroize::Zeroizing;

use super::{
    init_store_from, locked, unix_now, Config, FfiError, Handle, Inner, SecureElementCallback,
    TransferWork,
};
use crate::{
    client::RestoredBackup,
    runtime::OsRng,
    transfers::{TransferCommand, TransferUpdate},
};

/// The time between two reads of a slot that holds nothing yet, in seconds.
const POLL: u64 = 2;

/// Where a link stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LinkStatus {
    /// No link runs.
    Idle,
    /// The offer goes up, or the new device reads it.
    Preparing,
    /// The existing device shows the ticket as a QR code (`DEV-005`).
    Ticket {
        /// The text of the QR code.
        text: String,
    },
    /// The two devices show the code of `DEV-283`. The existing device
    /// waits for [`Handle::confirm_link`], and the new device for the
    /// provision.
    Code {
        /// Six digits.
        code: String,
    },
    /// The existing device uploads the snapshot and writes the provision.
    Sending,
    /// The provision is there, and the existing device waits for the sync
    /// channel.
    Waiting,
    /// The new device fetches the snapshot.
    Fetching,
    /// The snapshot is here, and [`Handle::take_linked`] gives it.
    Ready,
    /// The sync channel opened. The link is complete.
    Linked,
    /// The ticket or the provision ran out (`DEV-003`, `DEV-005`).
    Expired,
    /// A step failed, or an object did not verify. The user can start
    /// again.
    Failed,
}

/// One device of the set.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Device {
    /// The random `device_id`.
    pub device_id: Vec<u8>,
    /// The label that the user gave it.
    pub label: String,
    /// Whether it is this device.
    pub is_self: bool,
    /// The roster epoch that added it.
    pub added_epoch: u64,
}

/// A hole in the history that the other devices sync (Part 7 §7.5.5).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHistoryHole {
    /// The label of the source device.
    pub label: String,
    /// How many records of that device the hole holds.
    pub count: u64,
    /// The device can still send them (`DEV-076`); else a gap (`DEV-077`).
    pub is_arriving: bool,
}

/// A fork of the roster that waits for the user (Part 7 §7.7).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRosterFork {
    /// The row, for the dismissal.
    pub id: Vec<u8>,
    /// The index of the two epochs.
    pub epoch: u64,
    /// The label of the device that signed the other epoch.
    pub label: String,
    /// 1: one device signed two epochs (`DEV-170`). 2: two devices removed
    /// different devices (`DEV-178`). 3: another device holds another
    /// epoch (`DEV-182`).
    pub kind: u8,
}

/// What the absent device owns, for the view before a take-over (Part 7
/// `DEV-235`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTakeOverCount {
    /// The contacts of the set.
    pub contacts: u32,
    /// The groups of the set.
    pub groups: u32,
    /// The contacts whose channel did not reach this device before the
    /// loss (`DEV-319`). A take-over renews none of them.
    pub unreachable: u32,
}

/// What one transfer of a link does.
pub(super) enum LinkStep {
    WriteOffer,
    ReadHello,
    Snapshot,
    WriteProvision,
    ReadOffer,
    WriteHello,
    ReadProvision,
    ReadSnapshot,
}

/// A link while it runs.
pub(super) struct LinkState {
    serial: u64,
    job: LinkJob,
    status: LinkStatus,
    /// Whether a read of a slot runs.
    reading: bool,
    next_poll: u64,
}

enum LinkJob {
    Offer(Box<Offer>),
    Join(Box<Join>),
}

/// The side of the existing device.
struct Offer {
    nonce: [u8; 16],
    link_key: KeyPair,
    offer: Vec<u8>,
    ticket: String,
    offered_at: u64,
    offer_relays: Vec<[u8; 32]>,
    hello: Option<(LinkHello, LinkSecret)>,
    roster: Option<Vec<u8>>,
    /// The causal counter of this device at the confirmation: each record
    /// after it waits for the new device (`DEV-297`, `DEV-311`).
    sync_floor: u64,
    snapshot: Option<Box<Uploaded>>,
    /// Whether the write of the provision left. The new device reads the
    /// bundle of its sync channel through the provision. Thus no sync
    /// channel that opened before this write is the one of this link.
    provision_sent: bool,
    provision_relays: Vec<[u8; 32]>,
    provisioned_at: u64,
}

/// The side of the new device.
struct Join {
    ticket: LinkTicket,
    identity: Option<DeviceIdentity>,
    started_at: u64,
    hello_at: u64,
    has_offer: bool,
    secret: Option<LinkSecret>,
    hello_relays: Vec<[u8; 32]>,
    restored: Option<RestoredBackup>,
}

/// The snapshot and the identity of a new device, for [`init_linked`].
/// The platform holds this object and never reads it.
#[derive(uniffi::Object)]
pub struct Linked(Mutex<Option<(RestoredBackup, DeviceIdentity)>>);

/// What a pump of the link does next.
enum Next {
    Nothing,
    End(LinkStatus),
    Read(LinkStep, Slot),
}

/// The sync invitations that the store lists and that no link waits for
/// (`DEV-290`): their link ended with its run, or under a lock. A link
/// that waits for its sync channel holds its own. A locked store gives
/// none, and the next run after the unlock reads the list.
pub(super) fn stale_invitations<B, E>(
    client: &crate::client::Client<B, E>,
    link: Option<&LinkState>,
) -> Vec<[u8; 32]>
where
    B: umbra_core::store::engine::Backend,
    E: umbra_core::store::wrap::SecureElement,
{
    let waits = link.is_some_and(|link| {
        matches!(link.job, LinkJob::Offer(_))
            && matches!(link.status, LinkStatus::Sending | LinkStatus::Waiting)
    });
    if waits {
        return Vec::new();
    }
    client.device_invitations().unwrap_or_default()
}

fn is_over(status: &LinkStatus) -> bool {
    matches!(
        status,
        LinkStatus::Idle
            | LinkStatus::Ready
            | LinkStatus::Linked
            | LinkStatus::Expired
            | LinkStatus::Failed
    )
}

fn six_digits(code: u32) -> String {
    format!("{code:06}")
}

impl Inner {
    fn start(&mut self, job: LinkJob) {
        self.cancel_link();
        self.link_serial = self.link_serial.wrapping_add(1);
        self.link = Some(LinkState {
            serial: self.link_serial,
            job,
            status: LinkStatus::Preparing,
            reading: false,
            next_poll: 0,
        });
    }

    fn link_tag(&mut self, step: LinkStep) -> Option<u64> {
        self.link_tag_erasing(step, None)
    }

    fn link_tag_erasing(
        &mut self,
        step: LinkStep,
        erase: Option<([u8; 32], Secret<32>)>,
    ) -> Option<u64> {
        let serial = self.link.as_ref()?.serial;
        Some(self.next_tag(TransferWork::Link {
            serial,
            step,
            erase,
        }))
    }

    fn write_slot(&mut self, step: LinkStep, slot: Slot, object: &[u8]) {
        let Ok(chunk) = pad_handle_object(object) else {
            self.end_link(LinkStatus::Failed);
            return;
        };
        let erase = Some((slot.handle, Secret::new(*slot.cred.expose())));
        let Some(tag) = self.link_tag_erasing(step, erase) else {
            return;
        };
        self.send_transfer(TransferCommand::WriteHandle {
            tag,
            handle: slot.handle,
            read_pk: slot.read_pk(),
            cred: slot.cred,
            chunk,
            replaces: false,
        });
    }

    fn read_slot(&mut self, step: LinkStep, slot: Slot) {
        let Some(tag) = self.link_tag(step) else {
            return;
        };
        if let Some(link) = self.link.as_mut() {
            link.reading = true;
        }
        self.send_transfer(TransferCommand::ReadHandle {
            tag,
            handle: slot.handle,
            read: slot.read,
        });
    }

    fn erase_slot(&mut self, slot: Slot, relays: Vec<[u8; 32]>) {
        if !relays.is_empty() {
            self.send_transfer(TransferCommand::Erase {
                chunk_id: slot.handle,
                cred: slot.cred,
                relays,
            });
        }
    }

    /// Erases each object of the link that is still on the chunk path
    /// (`DEV-003`). Each one goes once.
    fn erase_link_objects(&mut self) {
        for erasure in self.take_link_erasures() {
            self.send_transfer(erasure);
        }
    }

    /// Takes the erasure of each object of the link that is still on the
    /// chunk path. Each one comes once.
    fn take_link_erasures(&mut self) -> Vec<TransferCommand> {
        let mut slots = Vec::new();
        let mut chunks = Vec::new();
        match self.link.as_mut().map(|link| &mut link.job) {
            Some(LinkJob::Offer(offer)) => {
                slots.push((
                    offer_slot(&offer.nonce),
                    core::mem::take(&mut offer.offer_relays),
                ));
                if let Some((_, secret)) = &offer.hello {
                    slots.push((
                        secret.provision_slot(),
                        core::mem::take(&mut offer.provision_relays),
                    ));
                }
                if let Some(snapshot) = offer.snapshot.take() {
                    chunks = snapshot.credentials;
                }
            }
            Some(LinkJob::Join(join)) => {
                slots.push((
                    hello_slot(&join.ticket.nonce),
                    core::mem::take(&mut join.hello_relays),
                ));
            }
            None => {}
        }
        let mut erasures = Vec::new();
        for (slot, relays) in slots {
            if !relays.is_empty() {
                erasures.push(TransferCommand::Erase {
                    chunk_id: slot.handle,
                    cred: slot.cred,
                    relays,
                });
            }
        }
        for credential in chunks {
            erasures.push(TransferCommand::Erase {
                chunk_id: credential.chunk_id,
                cred: credential.cred,
                relays: credential.relays,
            });
        }
        erasures
    }

    /// Ends the link of a locked client (`IMP-127`): the link key, the link
    /// secret, the roster and the snapshot leave RAM with it. The transfer
    /// task ends with the lock, and a command that it took would go with
    /// it. Thus each erasure waits for the next run (`DEV-003`), and the
    /// pending device leaves the store at the next unlock (`DEV-290`).
    pub(super) fn drop_link_at_lock(&mut self) {
        if self.client.is_unlocked() || self.link.is_none() {
            return;
        }
        for erasure in self.take_link_erasures() {
            self.hold_erasure(erasure);
        }
        self.peer_drop_due = true;
        // The store keeps each erasure too, for a process that ends before
        // the next run.
        self.link_erasures_due = true;
        self.link = None;
    }

    /// Takes the pending device of a link that ended out of the store. A
    /// locked client removes no row, thus the removal waits for the unlock.
    fn drop_link_peer(&mut self) {
        // DEV-286: the pending device of a new device is the one that
        // linked it. The snapshot named it, and it stays until the sync
        // channel of the provision opens: no link of this process made it.
        if matches!(self.client.pending_sync_bundle(), Ok(Some(_))) {
            self.peer_drop_due = false;
            return;
        }
        self.peer_drop_due = self.client.drop_pending_peer().is_err();
    }

    /// Retires the sync invitation of a link that ended with no sync
    /// channel (`DEV-290`). The store lists each one, thus with no run up
    /// the next run retires it ([`stale_invitations`]).
    fn end_link_invitation(&self) {
        if let Some(running) = &self.bridge {
            let listed = self.client.device_invitations().unwrap_or_default();
            let _ = running.end_device_invitation(listed);
        }
    }

    /// Sends the erasure of each link object that the store keeps
    /// (`DEV-003`): a link that ended at a lock, or with its process, left
    /// them. A link that runs keeps its objects.
    fn pump_link_erasures(&mut self) {
        if !self.link_erasures_due
            || self.link.is_some()
            || self.bridge.is_none()
            || !self.client.is_unlocked()
        {
            return;
        }
        let Ok(jobs) = self.client.kept_erasures() else {
            return;
        };
        self.link_erasures_due = false;
        for job in jobs {
            self.send_transfer(TransferCommand::Erase {
                chunk_id: job.chunk_id,
                cred: job.cred,
                relays: job.relays,
            });
        }
    }

    fn end_link(&mut self, status: LinkStatus) {
        if !self.client.is_unlocked() {
            self.drop_link_at_lock();
            return;
        }
        self.erase_link_objects();
        // A link that ends with no sync channel leaves no device that the
        // records wait for.
        if matches!(status, LinkStatus::Expired | LinkStatus::Failed)
            && matches!(
                self.link.as_ref().map(|link| &link.job),
                Some(LinkJob::Offer(_))
            )
        {
            self.drop_link_peer();
            self.end_link_invitation();
        }
        if let Some(link) = self.link.as_mut() {
            link.status = status;
            link.reading = false;
        }
    }

    /// Ends the link that runs, and erases what it put on the chunk path.
    pub(super) fn cancel_link(&mut self) {
        if !self.client.is_unlocked() {
            self.drop_link_at_lock();
            return;
        }
        self.erase_link_objects();
        let was_offer = matches!(
            self.link.as_ref().map(|link| (&link.job, &link.status)),
            Some((LinkJob::Offer(_), status)) if !matches!(status, LinkStatus::Linked)
        );
        if was_offer {
            self.drop_link_peer();
            self.end_link_invitation();
        }
        self.link = None;
    }

    /// Asks the run for each queue rotation that a revocation still owes
    /// (Part 7 §7.7 step 2c). NET-180: each contact moves after its own
    /// delay, and the node keeps that time. The client paces the requests,
    /// and it lets a contact go when its queue rotated.
    pub(super) fn pump_revocation(&mut self, now: u64) {
        let Inner { client, bridge, .. } = self;
        let Some(running) = bridge.as_mut() else {
            return;
        };
        if !client.is_unlocked() {
            return;
        }
        for (contact, guard) in client.rotation_owed(now).unwrap_or_default() {
            let _ = running.rotate_swept(umbra_core::session::node::ContactId(contact), guard);
        }
    }

    /// Ends the run of a device that owned the channels and that owns none
    /// any more (`DEV-317`): an epoch of another device took them. The
    /// parked session goes too, since its circuits carry the queues of the
    /// contacts (`WIR-549`). The platform starts the next run, which reads
    /// the sync channels alone. The result is whether a run ended.
    pub(super) fn end_run_of_lost_ownership(&mut self) -> bool {
        if !self.owns_channels || self.client.owns_channels().unwrap_or(true) {
            return false;
        }
        self.owns_channels = false;
        self.end_run_for_ownership();
        // The cause that asks the platform for a new run with no fault.
        self.net_events
            .push_back(super::NetEvent::Offline(super::Ended::Aged));
        true
    }

    /// Ends the run that is up, as a disconnect does, and erases the
    /// parked session. No node of the old ownership commits after this.
    pub(super) fn end_run_for_ownership(&mut self) {
        self.resume.clear();
        self.run = self.run.wrapping_add(1);
        self.bridge = None;
        self.transfers = None;
        self.groups = None;
        self.group_reading.clear();
        self.spawner = None;
        self.circuits.clear();
        self.circuits_changed = true;
        self.online_since = None;
    }

    /// Whether the user can take the set over at `now` (`DEV-231`,
    /// `DEV-315`): the absence reached `OWNER_ABSENCE`, and the run that is
    /// up read the sync channel for `DRAIN_QUIET`. The owning device writes
    /// its roster to that channel at the start of each of its runs. Thus a
    /// device that was off itself takes no set from an owner that lives.
    fn may_take_over(&mut self, now: u64) -> Result<bool, FfiError> {
        if !self.client.may_take_over(now, &mut OsRng)? {
            return Ok(false);
        }
        let quiet = std::time::Duration::from_secs(umbra_core::session::node::DRAIN_QUIET);
        Ok(self.bridge.is_some()
            && self
                .online_since
                .is_some_and(|(run, since)| run == self.run && since.elapsed() >= quiet))
    }

    /// The expiry of each step, and the read of a slot that holds nothing
    /// yet at each `POLL`.
    pub(super) fn pump_link(&mut self, now: u64) {
        // IMP-127: a locked client runs no link.
        self.drop_link_at_lock();
        // DEV-290: the pending device of a link that ended under a lock, or
        // with its process, leaves the store. A link that the user
        // confirmed since holds its own.
        if self.peer_drop_due && self.client.is_unlocked() {
            self.drop_link_peer();
            // The sync invitation of that link retires in the run that is
            // up, and the start of the next run retires it otherwise.
            if !stale_invitations(&self.client, self.link.as_ref()).is_empty() {
                self.end_link_invitation();
            }
        }
        self.pump_link_erasures();
        // Part 7 §7.7 step 2c: a removal of a device with no run up left
        // its rotations in the store. The run that is up takes them.
        self.pump_revocation(now);
        let next = match self.link.as_mut() {
            None => Next::Nothing,
            Some(link) if is_over(&link.status) => Next::Nothing,
            Some(link) => {
                let may_read = !link.reading && now >= link.next_poll;
                match (&link.job, &link.status) {
                    (LinkJob::Offer(offer), LinkStatus::Preparing | LinkStatus::Ticket { .. })
                        if now >= offer.offered_at.saturating_add(LINK_QR_TTL) =>
                    {
                        Next::End(LinkStatus::Expired)
                    }
                    (LinkJob::Offer(offer), LinkStatus::Waiting)
                        if now >= offer.provisioned_at.saturating_add(LINK_PROVISION_TTL) =>
                    {
                        Next::End(LinkStatus::Expired)
                    }
                    (LinkJob::Offer(offer), _)
                        if now >= offer.offered_at.saturating_add(2 * LINK_PROVISION_TTL) =>
                    {
                        Next::End(LinkStatus::Expired)
                    }
                    (LinkJob::Offer(offer), LinkStatus::Ticket { .. }) if may_read => {
                        link.next_poll = now.saturating_add(POLL);
                        Next::Read(LinkStep::ReadHello, hello_slot(&offer.nonce))
                    }
                    (LinkJob::Join(join), LinkStatus::Preparing)
                        if now >= join.started_at.saturating_add(LINK_QR_TTL) =>
                    {
                        Next::End(LinkStatus::Expired)
                    }
                    (LinkJob::Join(join), LinkStatus::Code { .. })
                        if now >= join.hello_at.saturating_add(LINK_PROVISION_TTL) =>
                    {
                        Next::End(LinkStatus::Expired)
                    }
                    (LinkJob::Join(join), LinkStatus::Preparing) if may_read && !join.has_offer => {
                        link.next_poll = now.saturating_add(POLL);
                        Next::Read(LinkStep::ReadOffer, offer_slot(&join.ticket.nonce))
                    }
                    (LinkJob::Join(join), LinkStatus::Code { .. }) if may_read => {
                        match &join.secret {
                            Some(secret) => {
                                link.next_poll = now.saturating_add(POLL);
                                Next::Read(LinkStep::ReadProvision, secret.provision_slot())
                            }
                            None => Next::End(LinkStatus::Failed),
                        }
                    }
                    _ => Next::Nothing,
                }
            }
        };
        match next {
            Next::Nothing => {}
            Next::End(status) => self.end_link(status),
            Next::Read(step, slot) => self.read_slot(step, slot),
        }
    }

    /// Takes the end of a transfer of the link. The result is the update
    /// when the transfer belongs to other work.
    pub(super) fn link_update(&mut self, update: TransferUpdate) -> Option<TransferUpdate> {
        let tag = match &update {
            TransferUpdate::Progress { tag, .. }
            | TransferUpdate::Uploaded { tag, .. }
            | TransferUpdate::Downloaded { tag, .. }
            | TransferUpdate::HandleWritten { tag, .. }
            | TransferUpdate::HandleRead { tag, .. }
            | TransferUpdate::Failed { tag }
            | TransferUpdate::Interrupted { tag }
            | TransferUpdate::Gone { tag } => *tag,
            TransferUpdate::Faults(_) | TransferUpdate::Erased { .. } => return Some(update),
        };
        if !matches!(
            self.transfer_tags.get(&tag),
            Some(TransferWork::Link { .. })
        ) {
            return Some(update);
        }
        if matches!(update, TransferUpdate::Progress { .. }) {
            return None;
        }
        let Some(TransferWork::Link {
            serial,
            step,
            erase,
        }) = self.transfer_tags.remove(&tag)
        else {
            return None;
        };
        // DEV-003: the store keeps the erasure of each object that the link
        // put on the chunk path, from here on. A lock and the end of the
        // process then lose none. A locked client takes no row, and the
        // memory holds the erasure alone.
        match (&update, &erase) {
            (TransferUpdate::HandleWritten { relays, .. }, Some((chunk_id, cred)))
                if !relays.is_empty() =>
            {
                let _ = self.client.keep_erasure(chunk_id, cred, relays, &mut OsRng);
            }
            (TransferUpdate::Uploaded { uploaded, .. }, _) => {
                for credential in &uploaded.credentials {
                    let _ = self.client.keep_erasure(
                        &credential.chunk_id,
                        &credential.cred,
                        &credential.relays,
                        &mut OsRng,
                    );
                }
            }
            _ => {}
        }
        // A transfer of a link that ended goes nowhere, and what it wrote
        // leaves the chunk path (`DEV-003`).
        let is_live = self
            .link
            .as_ref()
            .is_some_and(|link| link.serial == serial && !is_over(&link.status));
        if !is_live {
            match update {
                TransferUpdate::HandleWritten { relays, .. } => {
                    if let Some((chunk_id, cred)) = erase {
                        if !relays.is_empty() {
                            self.send_transfer(TransferCommand::Erase {
                                chunk_id,
                                cred,
                                relays,
                            });
                        }
                    }
                }
                TransferUpdate::Uploaded { uploaded, .. } => {
                    for credential in uploaded.credentials {
                        self.send_transfer(TransferCommand::Erase {
                            chunk_id: credential.chunk_id,
                            cred: credential.cred,
                            relays: credential.relays,
                        });
                    }
                }
                _ => {}
            }
            return None;
        }
        let now = unix_now();
        match (step, update) {
            (LinkStep::WriteOffer, TransferUpdate::HandleWritten { relays, .. }) => {
                if let Some(LinkState {
                    job: LinkJob::Offer(offer),
                    status,
                    ..
                }) = self.link.as_mut()
                {
                    offer.offer_relays = relays;
                    *status = LinkStatus::Ticket {
                        text: offer.ticket.clone(),
                    };
                }
            }
            (
                step @ (LinkStep::ReadHello | LinkStep::ReadOffer | LinkStep::ReadProvision),
                TransferUpdate::HandleRead { chunks, .. },
            ) => {
                if let Some(link) = self.link.as_mut() {
                    link.reading = false;
                }
                // Each chunk that a relay gave is tried in order, and the
                // link fails only when none of them opens.
                let count = chunks.len();
                for (index, chunk) in chunks.iter().enumerate() {
                    let last = index.saturating_add(1) == count;
                    let opened = match step {
                        LinkStep::ReadHello => self.on_hello(chunk, last),
                        LinkStep::ReadOffer => self.on_offer(chunk, last),
                        _ => self.on_provision(chunk, last),
                    };
                    if opened {
                        break;
                    }
                }
            }
            (LinkStep::Snapshot, TransferUpdate::Uploaded { uploaded, .. }) => {
                if let Some(LinkState {
                    job: LinkJob::Offer(offer),
                    ..
                }) = self.link.as_mut()
                {
                    offer.snapshot = Some(uploaded);
                }
                self.write_provision();
            }
            (LinkStep::WriteProvision, TransferUpdate::HandleWritten { relays, .. }) => {
                if let Some(LinkState {
                    job: LinkJob::Offer(offer),
                    status,
                    ..
                }) = self.link.as_mut()
                {
                    offer.provision_relays = relays;
                    offer.provisioned_at = now;
                    // The sync channel may have opened before this write
                    // came back.
                    if *status == LinkStatus::Sending {
                        *status = LinkStatus::Waiting;
                    }
                }
            }
            (LinkStep::WriteHello, TransferUpdate::HandleWritten { relays, .. }) => {
                if let Some(LinkState {
                    job: LinkJob::Join(join),
                    status,
                    ..
                }) = self.link.as_mut()
                {
                    join.hello_relays = relays;
                    join.hello_at = now;
                    if let Some(secret) = &join.secret {
                        *status = LinkStatus::Code {
                            code: six_digits(secret.code()),
                        };
                    }
                }
            }
            (LinkStep::ReadSnapshot, TransferUpdate::Downloaded { plain, .. }) => {
                self.on_snapshot(&plain);
            }
            // A read that failed goes again at the next poll.
            (
                LinkStep::ReadHello | LinkStep::ReadOffer | LinkStep::ReadProvision,
                TransferUpdate::Failed { .. },
            ) => {
                if let Some(link) = self.link.as_mut() {
                    link.reading = false;
                }
            }
            _ => self.end_link(LinkStatus::Failed),
        }
        None
    }

    /// The hello is there: it opens under the key of the offer, and the
    /// offer goes, since the ticket works once (`DEV-006`).
    /// The result is whether the chunk opened; a chunk that does not open
    /// ends the link when it is the `last` one.
    fn on_hello(&mut self, chunk: &[u8], last: bool) -> bool {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status,
            ..
        }) = self.link.as_mut()
        else {
            return true;
        };
        if offer.hello.is_some() {
            return true;
        }
        let opened = unpad_handle_object(chunk).ok().and_then(|bytes| {
            LinkSecret::decapsulate(&offer.link_key, &offer.nonce, &offer.offer, bytes).ok()
        });
        let Some((hello, secret)) = opened else {
            if last {
                self.end_link(LinkStatus::Failed);
            }
            return false;
        };
        *status = LinkStatus::Code {
            code: six_digits(secret.code()),
        };
        offer.hello = Some((hello, secret));
        let relays = core::mem::take(&mut offer.offer_relays);
        let slot = offer_slot(&offer.nonce);
        self.erase_slot(slot, relays);
        true
    }

    /// The user confirmed that the two codes match (`DEV-283`): the roster
    /// of epoch n+1 is signed, and the sync invitation is asked for. The
    /// snapshot goes up when its bundle is here.
    pub(super) fn confirm_link(&mut self) -> Result<(), FfiError> {
        let Inner {
            link,
            client,
            bridge,
            peer_drop_due,
            ..
        } = self;
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status: status @ LinkStatus::Code { .. },
            ..
        }) = link.as_mut()
        else {
            return Err(FfiError::NotFound);
        };
        let (hello, _) = offer.hello.as_ref().ok_or(FfiError::NotFound)?;
        let running = bridge.as_ref().ok_or(FfiError::Offline)?;
        offer.roster = Some(client.sign_linked_device(hello, &mut OsRng)?);
        offer.sync_floor = client.sync_counter()?;
        client.set_pending_peer(hello.device_id, &hello.label, &mut OsRng)?;
        // The pending device is the one of this link from here on.
        *peer_drop_due = false;
        running.invite_device()?;
        *status = LinkStatus::Sending;
        Ok(())
    }

    /// The bundle of the sync channel is here: the snapshot with the rows
    /// of the link goes up.
    pub(super) fn link_bundle(&mut self, bundle: &[u8]) {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status: LinkStatus::Sending,
            ..
        }) = self.link.as_ref()
        else {
            return;
        };
        let Some(roster) = &offer.roster else {
            return;
        };
        let plain = match self
            .client
            .link_snapshot(unix_now(), roster, bundle, offer.sync_floor)
        {
            Ok(plain) => plain,
            Err(_) => {
                self.end_link(LinkStatus::Failed);
                return;
            }
        };
        if let Some(tag) = self.link_tag(LinkStep::Snapshot) {
            self.send_transfer(TransferCommand::UploadBackup { tag, plain });
        }
    }

    fn write_provision(&mut self) {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            ..
        }) = self.link.as_ref()
        else {
            return;
        };
        let (Some((_, secret)), Some(snapshot)) = (&offer.hello, &offer.snapshot) else {
            return;
        };
        let from_device: Option<DeviceId> = self
            .client
            .device_identity()
            .ok()
            .flatten()
            .map(|identity| identity.device_id);
        let mut descriptor = vec![0u8; snapshot.descriptor.len()];
        let sealed = match (from_device, snapshot.descriptor.encode(&mut descriptor)) {
            (Some(from_device), Ok(_)) => secret.seal(
                &Provision {
                    from_device,
                    snapshot: descriptor,
                },
                &mut OsRng,
            ),
            _ => {
                self.end_link(LinkStatus::Failed);
                return;
            }
        };
        let slot = secret.provision_slot();
        match sealed {
            Ok(sealed) => {
                if let Some(LinkState {
                    job: LinkJob::Offer(offer),
                    ..
                }) = self.link.as_mut()
                {
                    offer.provision_sent = true;
                }
                self.write_slot(LinkStep::WriteProvision, slot, &sealed);
            }
            Err(_) => self.end_link(LinkStatus::Failed),
        }
    }

    /// The sync channel of a device opened: the roster of the link holds
    /// from here, and the provision and the snapshot go (`DEV-003`).
    pub(super) fn link_opened(&mut self) {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status: LinkStatus::Sending | LinkStatus::Waiting,
            ..
        }) = self.link.as_ref()
        else {
            return;
        };
        // DEV-290: a sync channel that opened before the provision left is
        // the one of an earlier link. The device of that link read its own
        // provision before that link ended. Such a channel commits no
        // roster of this link.
        if !offer.provision_sent {
            return;
        }
        let committed = offer
            .roster
            .as_ref()
            .is_some_and(|roster| self.client.commit_roster(roster, &mut OsRng).is_ok());
        // DEV-176: each other device of the set takes the new epoch, and the
        // new device takes each record since the confirmation (DEV-072).
        if committed
            && self.client.publish_roster(&mut OsRng).is_ok()
            && self.client.start_sync_resend(&mut OsRng).is_ok()
        {
            let Inner { client, bridge, .. } = &mut *self;
            if let Some(running) = bridge.as_mut() {
                let _ = running.flush(client, &mut OsRng);
            }
        }
        self.end_link(if committed {
            LinkStatus::Linked
        } else {
            LinkStatus::Failed
        });
    }

    /// The offer is there: it checks against the ticket (`DEV-281`), and
    /// the hello goes up.
    /// The result is whether the chunk opened; a chunk that does not open
    /// ends the link when it is the `last` one.
    fn on_offer(&mut self, chunk: &[u8], last: bool) -> bool {
        let Some(LinkState {
            job: LinkJob::Join(join),
            ..
        }) = self.link.as_mut()
        else {
            return true;
        };
        let Some(identity) = join.identity.as_ref() else {
            return true;
        };
        let Some((offer_bytes, offer)) = unpad_handle_object(chunk)
            .ok()
            .and_then(|bytes| Some((bytes, LinkOffer::parse(bytes, &join.ticket).ok()?)))
        else {
            if last {
                self.end_link(LinkStatus::Failed);
            }
            return false;
        };
        let nonce = join.ticket.nonce;
        let (ct, ss) = LinkSecret::encapsulate(&offer, &mut OsRng);
        let hello = LinkHello {
            device_id: identity.device_id,
            device_pk: identity.device_key().public().clone(),
            roster_pk: identity.roster_key().verifying_key().to_bytes().to_vec(),
            label: identity.label,
            ct,
        };
        let Ok(hello_bytes) = hello.seal(&ss, &nonce, &mut OsRng) else {
            self.end_link(LinkStatus::Failed);
            return true;
        };
        join.secret = Some(LinkSecret::new(ss, &nonce, offer_bytes, &hello_bytes));
        join.has_offer = true;
        self.write_slot(LinkStep::WriteHello, hello_slot(&nonce), &hello_bytes);
        true
    }

    /// The provision is there: the snapshot that it names comes down, and
    /// the hello goes.
    /// The result is whether the chunk opened; a chunk that does not open
    /// ends the link when it is the `last` one.
    fn on_provision(&mut self, chunk: &[u8], last: bool) -> bool {
        let Some(LinkState {
            job: LinkJob::Join(join),
            status,
            ..
        }) = self.link.as_mut()
        else {
            return true;
        };
        let descriptor = join.secret.as_ref().and_then(|secret| {
            let sealed = unpad_handle_object(chunk).ok()?;
            let provision = secret.open(sealed).ok()?;
            FileDescriptor::parse(&provision.snapshot).ok()
        });
        let Some(descriptor) = descriptor else {
            if last {
                self.end_link(LinkStatus::Failed);
            }
            return false;
        };
        *status = LinkStatus::Fetching;
        let relays = core::mem::take(&mut join.hello_relays);
        let slot = hello_slot(&join.ticket.nonce);
        self.erase_slot(slot, relays);
        if let Some(tag) = self.link_tag(LinkStep::ReadSnapshot) {
            self.send_transfer(TransferCommand::DownloadBackup {
                tag,
                descriptor: Box::new(descriptor),
            });
        }
        true
    }

    fn on_snapshot(&mut self, plain: &Zeroizing<Vec<u8>>) {
        let restored = RestoredBackup::assemble(core::slice::from_ref(plain));
        let Some(LinkState {
            job: LinkJob::Join(join),
            status,
            ..
        }) = self.link.as_mut()
        else {
            return;
        };
        match restored {
            Ok(restored) => {
                join.restored = Some(restored);
                *status = LinkStatus::Ready;
            }
            Err(_) => self.end_link(LinkStatus::Failed),
        }
    }
}

#[uniffi::export]
impl Handle {
    /// Starts a link as the existing device (Part 7 §7.4): the device set
    /// begins with this device when it has none (`DEV-285`), and the offer
    /// goes up. `link_status` gives the ticket when the offer is there
    /// (`DEV-280`). A link that runs ends first, except one whose snapshot
    /// went and whose sync channel did not open yet: its new device is
    /// taking the handshake, and the call gives `Busy`.
    pub fn start_link(&self, label: String) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        if inner.bridge.is_none() {
            return Err(FfiError::Offline);
        }
        let is_opening = matches!(
            inner.link.as_ref(),
            Some(LinkState {
                job: LinkJob::Offer(_),
                status: LinkStatus::Sending | LinkStatus::Waiting,
                ..
            })
        );
        if is_opening {
            return Err(FfiError::Busy);
        }
        if !inner.client.owns_channels()? {
            return Err(FfiError::NotFound);
        }
        inner.client.ensure_device_set(&label, &mut OsRng)?;
        let link_key = KeyPair::generate(&mut OsRng);
        let offer = LinkOffer {
            link_pk: link_key.public().clone(),
        }
        .encode();
        let mut nonce = [0u8; 16];
        let Ok(()) = OsRng.try_fill_bytes(&mut nonce);
        let ticket = LinkTicket {
            nonce,
            commit: commit(&offer),
        };
        let slot = offer_slot(&nonce);
        inner.start(LinkJob::Offer(Box::new(Offer {
            nonce,
            link_key,
            offer: offer.clone(),
            ticket: ticket.to_text(),
            offered_at: unix_now(),
            offer_relays: Vec::new(),
            hello: None,
            roster: None,
            sync_floor: 0,
            snapshot: None,
            provision_sent: false,
            provision_relays: Vec::new(),
            provisioned_at: 0,
        })));
        inner.write_slot(LinkStep::WriteOffer, slot, &offer);
        Ok(())
    }

    /// Starts a link as the new device, from the text of the scanned QR
    /// code. The handle holds no data of the user: the snapshot makes the
    /// store at [`init_linked`].
    pub fn join_link(&self, ticket: String, label: String) -> Result<(), FfiError> {
        let ticket = LinkTicket::from_text(&ticket).map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        if inner.bridge.is_none() {
            return Err(FfiError::Offline);
        }
        let identity = DeviceIdentity::generate(&label, &mut OsRng);
        inner.start(LinkJob::Join(Box::new(Join {
            ticket,
            identity: Some(identity),
            started_at: unix_now(),
            hello_at: 0,
            has_offer: false,
            secret: None,
            hello_relays: Vec::new(),
            restored: None,
        })));
        inner.pump_link(unix_now());
        Ok(())
    }

    /// Where the link stands.
    pub fn link_status(&self) -> LinkStatus {
        locked(&self.inner)
            .link
            .as_ref()
            .map_or(LinkStatus::Idle, |link| link.status.clone())
    }

    /// The user saw the same code on the two devices (`DEV-283`).
    pub fn confirm_link(&self) -> Result<(), FfiError> {
        locked(&self.inner).confirm_link()
    }

    /// Ends the link that runs.
    pub fn cancel_link(&self) {
        locked(&self.inner).cancel_link();
    }

    /// The snapshot and the identity of a link that is ready, for
    /// [`init_linked`]. The link of this handle ends.
    pub fn take_linked(&self) -> Result<Arc<Linked>, FfiError> {
        let mut inner = locked(&self.inner);
        let Some(LinkState {
            job: LinkJob::Join(join),
            status: LinkStatus::Ready,
            ..
        }) = inner.link.as_mut()
        else {
            return Err(FfiError::NotFound);
        };
        let taken = join.restored.take().zip(join.identity.take());
        inner.link = None;
        let taken = taken.ok_or(FfiError::NotFound)?;
        Ok(Arc::new(Linked(Mutex::new(Some(taken)))))
    }

    /// Removes a device from the set (Part 7 §7.7). The call makes the
    /// epoch that revokes it, the notice to that device, and the end of its
    /// sync channel. Each contact gets a new queue, since the removed
    /// device knew each queue (step 2c). Each other device gets the epoch.
    /// The store holds the rotations and the notice until each one is done,
    /// thus the call needs no run. The removed device keeps what it synced
    /// (`DEV-137`).
    pub fn remove_device(&self, device_id: Vec<u8>) -> Result<(), FfiError> {
        let device: umbra_core::devset::DeviceId = device_id
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        if !inner.client.owns_channels()? {
            return Err(FfiError::NotFound);
        }
        inner.client.revoke_device(device, &mut OsRng)?;
        inner.client.publish_roster(&mut OsRng)?;
        // Step 2e, GRP-345: the removed device holds the keys of each group
        // of the member, thus the member moves to new ones.
        inner
            .client
            .rekey_groups(super::unix_now_ms(), &mut OsRng)?;
        // Step 2c: the store holds the rotation that the revocation owes
        // each contact, and a run that is up takes each one now. With no
        // run, the first step of the next run takes them.
        inner.pump_revocation(super::unix_now());
        let Inner { client, bridge, .. } = &mut *inner;
        if let Some(running) = bridge.as_mut() {
            running.flush(client, &mut OsRng)?;
        }
        inner.pump_groups();
        Ok(())
    }

    /// Whether the user can take the set over now (Part 7 §7.7): this
    /// device owns no channel, the device that owns them is absent for
    /// `OWNER_ABSENCE`, and the run read the sync channel for `DRAIN_QUIET`
    /// (`DEV-231`, `DEV-315`).
    pub fn can_take_over(&self) -> Result<bool, FfiError> {
        locked(&self.inner).may_take_over(unix_now())
    }

    /// What the absent device owns, for the view before a take-over
    /// (`DEV-235`).
    pub fn take_over_count(&self) -> Result<FfiTakeOverCount, FfiError> {
        let count = locked(&self.inner).client.take_over_count()?;
        Ok(FfiTakeOverCount {
            contacts: count.contacts,
            groups: count.groups,
            unreachable: count.unreachable,
        })
    }

    /// Takes the set over (`DEV-314` to `DEV-316`): this device revokes
    /// each other device, owns each channel, and renews each contact. The
    /// new recovery code goes into `sink` as [`Handle::recovery_code`]
    /// gives it (`IMP-037`). The run ends here, and the platform starts
    /// the network again. A call before `can_take_over` gives `Busy`, and a
    /// call on the device that owns the channels gives `NotFound`.
    pub fn take_over(&self, sink: Arc<dyn super::TextSink>) -> Result<(), FfiError> {
        let mut held = super::HeldText::default();
        {
            let mut inner = locked(&self.inner);
            let now = unix_now();
            if inner.client.owns_channels()? {
                return Err(FfiError::NotFound);
            }
            if !inner.may_take_over(now)? {
                return Err(FfiError::Busy);
            }
            inner.client.take_over(now, &mut OsRng)?;
            // The node of this run holds no contact, and the next run
            // restores each one. A circuit of this run carries no queue of
            // a contact either.
            inner.end_run_for_ownership();
            inner.owns_channels = true;
            inner.client.render_recovery_code(&mut held, &mut OsRng)?;
        }
        if let Some(runtime) = locked(&self.runtime).take() {
            runtime.shutdown_background();
        }
        locked(&self.run_done).take();
        let given = held.give(sink.as_ref());
        self.changed.notify_all();
        given
    }

    /// Whether another device of the set removed this one (`DEV-181`).
    pub fn removed_from_set(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.removed_from_set()?)
    }

    /// Whether this device owns the channels of the set, thus whether it
    /// can offer a link (`DEV-287`).
    pub fn owns_channels(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.owns_channels()?)
    }

    /// Each hole in the synced history, which the view shows and does not
    /// hide (`DEV-076` to `DEV-079`).
    pub fn history_holes(&self) -> Result<Vec<FfiHistoryHole>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .history_holes(super::unix_now())?
            .into_iter()
            .map(|hole| FfiHistoryHole {
                label: hole.label,
                count: hole.count,
                is_arriving: hole.is_arriving,
            })
            .collect())
    }

    /// The deletions that `device_id` made on this device since the last
    /// roster epoch, which the removal of that device shows (`DEV-119`).
    pub fn deletions_from(&self, device_id: Vec<u8>) -> Result<u32, FfiError> {
        let device: umbra_core::devset::DeviceId = device_id
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Malformed)?;
        Ok(locked(&self.inner).client.deletions_from(&device)?)
    }

    /// The messages that deletions of the other devices name after a
    /// restore, which wait for the user (`DEV-117`).
    pub fn held_deletions(&self) -> Result<u32, FfiError> {
        let count = locked(&self.inner).client.held_deletions()?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// The user confirmed those deletions (`DEV-118`).
    pub fn apply_held_deletions(&self) -> Result<(), FfiError> {
        Ok(locked(&self.inner).client.apply_held_deletions()?)
    }

    /// The user keeps the messages that the restore brought back.
    pub fn keep_restored_messages(&self) -> Result<(), FfiError> {
        Ok(locked(&self.inner).client.keep_restored_messages()?)
    }

    /// Each fork of the roster that the user did not dismiss.
    pub fn roster_forks(&self) -> Result<Vec<FfiRosterFork>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .roster_forks()?
            .into_iter()
            .map(|fork| FfiRosterFork {
                id: fork.id.to_vec(),
                epoch: fork.epoch,
                label: fork.label,
                kind: fork.kind,
            })
            .collect())
    }

    /// The user saw a fork of the roster.
    pub fn dismiss_roster_fork(&self, id: Vec<u8>) -> Result<(), FfiError> {
        let id: [u8; 16] = id.try_into().map_err(|_| FfiError::Malformed)?;
        Ok(locked(&self.inner)
            .client
            .dismiss_roster_fork(&id, &mut OsRng)?)
    }

    /// The devices of the set, or none when this device has no set.
    pub fn devices(&self) -> Result<Vec<Device>, FfiError> {
        Ok(locked(&self.inner)
            .client
            .devices()?
            .into_iter()
            .map(|device| Device {
                device_id: device.device_id.to_vec(),
                label: device.label,
                is_self: device.is_self,
                added_epoch: device.added_epoch,
            })
            .collect())
    }
}

#[cfg(feature = "sockets-test")]
impl Handle {
    /// Moves the two clocks of a take-over past their periods, as a wait
    /// of `OWNER_ABSENCE` in a run that is up does. For a test over real
    /// sockets alone.
    pub fn age_owner_absence(&self) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.age_owner_absence(unix_now(), &mut OsRng)?;
        let quiet = std::time::Duration::from_secs(umbra_core::session::node::DRAIN_QUIET);
        if let Some((_, since)) = inner.online_since.as_mut() {
            *since = since.checked_sub(quiet).unwrap_or(*since);
        }
        Ok(())
    }

    /// Asks the run for each rotation that a revocation owes, and ends
    /// each delay of Part 3 `NET-180` that runs, as a wait of that time
    /// does. For a test over real sockets alone.
    pub fn end_sweeps(&self) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.pump_revocation(unix_now());
        let running = inner.bridge.as_ref().ok_or(FfiError::Offline)?;
        Ok(running.end_sweeps()?)
    }

    /// Whether a revocation still owes the queue of a conversation its
    /// rotation (Part 7 §7.7 step 2c). For a test over real sockets alone.
    pub fn owes_rotation(&self, conversation: Vec<u8>) -> Result<bool, FfiError> {
        let conversation = super::conversation_of(&conversation)?;
        Ok(locked(&self.inner).client.owes_rotation(conversation)?)
    }
}

/// Makes the store of a new device from the snapshot of a link: as
/// [`super::init_restored`], and the identity of this device joins the set
/// that the snapshot names (`DEV-284`). The device owns no channel
/// (`DEV-287`), and its first run opens the sync channel (`DEV-286`).
#[uniffi::export]
pub fn init_linked(
    config: Config,
    element: Arc<dyn SecureElementCallback>,
    passphrase: Vec<u16>,
    linked: Arc<Linked>,
) -> Result<Arc<Handle>, FfiError> {
    let (restored, identity) = locked(&linked.0).take().ok_or(FfiError::NotFound)?;
    init_store_from(config, element, passphrase, &restored, |client| {
        client.apply_restore(&restored, &mut OsRng)?;
        Ok(client.apply_link(&identity, &mut OsRng)?)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::tests::{open, passphrase};
    use super::*;

    /// The side of the existing device, with its offer on one relay.
    fn offer() -> LinkJob {
        LinkJob::Offer(Box::new(Offer {
            nonce: [5; 16],
            link_key: KeyPair::generate(&mut OsRng),
            offer: Vec::new(),
            ticket: String::new(),
            offered_at: unix_now(),
            offer_relays: vec![[9; 32]],
            hello: None,
            roster: None,
            sync_floor: 0,
            snapshot: None,
            provision_sent: false,
            provision_relays: Vec::new(),
            provisioned_at: 0,
        }))
    }

    #[test]
    fn a_lock_ends_the_link_and_keeps_its_erasure_for_the_next_run() {
        let (handle, directory) = open("link-lock");
        let mut inner = locked(&handle.inner);
        // The pending device of a link of an earlier process goes first.
        assert!(inner.peer_drop_due);
        inner.pump_link(unix_now());
        assert!(!inner.peer_drop_due);

        inner.start(offer());
        inner.client.lock();
        inner.pump_link(unix_now());
        // IMP-127: the link key leaves RAM with the link. DEV-003: the
        // erasure of the offer waits, and DEV-290: so does the removal of
        // the pending device, which a locked store does not take.
        assert!(inner.link.is_none());
        assert_eq!(inner.held_erasures.len(), 1);
        assert!(inner.peer_drop_due);

        // A cancel of the view after the lock finds no link, and no second
        // erasure.
        inner.cancel_link();
        assert_eq!(inner.held_erasures.len(), 1);

        inner.client.unlock(&passphrase(), unix_now()).unwrap();
        inner.pump_link(unix_now());
        assert!(!inner.peer_drop_due);
        assert_eq!(inner.held_erasures.len(), 1);
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_sync_invitation_of_a_link_that_ended_under_a_lock_is_stale_at_the_unlock() {
        let (handle, directory) = open("link-stale");
        let mut inner = locked(&handle.inner);
        inner.start(offer());
        if let Some(link) = inner.link.as_mut() {
            link.status = LinkStatus::Waiting;
        }
        inner
            .client
            .note_device_invitation(&[0x71; 32], &mut OsRng)
            .unwrap();
        // The link waits for its sync channel, thus its invitation is not
        // stale, and the start of a run retires nothing.
        assert!(stale_invitations(&inner.client, inner.link.as_ref()).is_empty());

        // DEV-290: a lock ends the link, and its run with it. A locked
        // store gives no list.
        inner.client.lock();
        inner.pump_link(unix_now());
        assert!(inner.link.is_none());
        assert!(stale_invitations(&inner.client, inner.link.as_ref()).is_empty());

        // The store kept the list. The run after the unlock retires the
        // invitation, and it does not wait for `INVITE_TTL`.
        inner.client.unlock(&passphrase(), unix_now()).unwrap();
        assert_eq!(
            stale_invitations(&inner.client, inner.link.as_ref()),
            [[0x71; 32]]
        );
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_cancel_under_a_lock_ends_the_link_as_the_lock_does() {
        let (handle, directory) = open("link-cancel");
        let mut inner = locked(&handle.inner);
        inner.start(offer());
        inner.client.lock();
        inner.cancel_link();
        assert!(inner.link.is_none());
        assert_eq!(inner.held_erasures.len(), 1);
        assert!(inner.peer_drop_due);
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_sync_channel_before_the_provision_commits_no_roster() {
        let (handle, directory) = open("link-early");
        let mut inner = locked(&handle.inner);
        inner.start(offer());
        let status = |inner: &Inner| inner.link.as_ref().map(|link| link.status.clone());
        if let Some(link) = inner.link.as_mut() {
            link.status = LinkStatus::Sending;
        }
        // DEV-290: the channel of a device of an earlier link opens while
        // the snapshot of this link goes up. The link stays where it is.
        inner.link_opened();
        assert_eq!(status(&inner), Some(LinkStatus::Sending));
        // After the provision left, the opening is the one of this link:
        // it ends the link, here with no roster to commit.
        if let Some(LinkState {
            job: LinkJob::Offer(offer),
            ..
        }) = inner.link.as_mut()
        {
            offer.provision_sent = true;
        }
        inner.link_opened();
        assert_eq!(status(&inner), Some(LinkStatus::Failed));
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
