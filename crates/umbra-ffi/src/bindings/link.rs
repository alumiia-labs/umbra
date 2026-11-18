//! The link of a device (Part 7 §7.4) over the transfer task.
//!
//! The existing device offers: it writes the offer, reads the hello, writes
//! the reply, shows the code, and after the confirmation of the user it
//! uploads the snapshot and writes the provision. The new device joins on a
//! handle whose store holds no data of the user, as a restore does. It shows
//! the code after it read the reply, and [`init_linked`] makes its store
//! from the snapshot.

use std::sync::{Arc, Mutex};

use umbra_core::{
    attach::{
        segment::{pad_handle_object, unpad_handle_object},
        transfer::Uploaded,
    },
    devset::{
        link::{
            commit, hello_slot, offer_slot, DeviceIdentity, LinkHello, LinkOffer, LinkPending,
            LinkSecret, LinkTicket, Provision, Slot,
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
    /// The offer goes up, or the new device reads it. The new device stays
    /// here after its hello too, until the reply of the existing device is
    /// there (`DEV-361`).
    Preparing,
    /// The existing device shows the ticket as a QR code (`DEV-005`).
    Ticket {
        /// The text of the QR code.
        text: String,
    },
    /// The device shows the code of `DEV-283`. The existing device shows
    /// it when it took a hello, and the new device when it read the reply
    /// to its own hello. The existing device waits for
    /// [`Handle::confirm_link`], and the new device for the provision.
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
    WriteReply,
    Snapshot,
    WriteProvision,
    ReadOffer,
    WriteHello,
    ReadReply,
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
    /// The slot of the reply to that hello, for its erasure.
    reply_slot: Option<Slot>,
    reply_relays: Vec<[u8; 32]>,
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
    /// What the hello fixed. The reply turns it into `secret`.
    pending: Option<LinkPending>,
    secret: Option<LinkSecret>,
    hello_relays: Vec<[u8; 32]>,
    restored: Option<RestoredBackup>,
}

/// The snapshot and the identity of a new device, for [`init_linked`].
/// The platform holds this object and never reads it.
#[derive(uniffi::Object)]
pub struct Linked(pub(super) Mutex<LinkedHold>);

/// What a [`Linked`] holds: the snapshot and the keys of the device.
pub(super) type LinkedHold = super::Held<(RestoredBackup, DeviceIdentity)>;

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

        let erase = Some((slot.handle, slot.cred.duplicate()));
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
                if let Some(slot) = offer.reply_slot.take() {
                    slots.push((slot, core::mem::take(&mut offer.reply_relays)));
                }
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
    /// them. A link that runs keeps its objects, and a link that ended sent
    /// the erasures of its own.
    fn pump_link_erasures(&mut self) {
        let runs = self
            .link
            .as_ref()
            .is_some_and(|link| !is_over(&link.status));
        if !self.link_erasures_due || runs || self.bridge.is_none() || !self.client.is_unlocked() {
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
                    // DEV-361: the hello is up, and the reply fixes the code.
                    (LinkJob::Join(join), LinkStatus::Preparing)
                        if may_read && join.hello_at != 0 =>
                    {
                        match &join.pending {
                            Some(pending) => {
                                link.next_poll = now.saturating_add(POLL);
                                Next::Read(LinkStep::ReadReply, pending.reply_slot())
                            }
                            None => Next::Nothing,
                        }
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
            TransferUpdate::Faults(_)
            | TransferUpdate::Erased { .. }
            | TransferUpdate::Chains(_) => return Some(update),
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
            (LinkStep::ReadHello, TransferUpdate::HandleRead { chunks, .. }) => {
                if let Some(link) = self.link.as_mut() {
                    link.reading = false;
                }
                self.on_hellos(&chunks);
            }
            (
                step @ (LinkStep::ReadOffer | LinkStep::ReadReply | LinkStep::ReadProvision),
                TransferUpdate::HandleRead { chunks, .. },
            ) => {
                if let Some(link) = self.link.as_mut() {
                    link.reading = false;
                }

                // Each chunk that a relay gave is tried in order. One
                // that does not open is an empty slot: a replica can give
                // other bytes before the peer wrote, and the link has its
                // own end time. The next poll reads the slot again.
                for chunk in &chunks {
                    let opened = match step {
                        LinkStep::ReadOffer => self.on_offer(chunk),
                        LinkStep::ReadReply => self.on_reply(chunk),
                        _ => self.on_provision(chunk),
                    };
                    if opened {
                        break;
                    }
                }
            }
            (LinkStep::WriteReply, TransferUpdate::HandleWritten { relays, .. }) => {
                if let Some(LinkState {
                    job: LinkJob::Offer(offer),
                    ..
                }) = self.link.as_mut()
                {
                    offer.reply_relays = relays;
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
                // DEV-361: no code yet. The next poll reads the reply.
                if let Some(LinkState {
                    job: LinkJob::Join(join),
                    next_poll,
                    ..
                }) = self.link.as_mut()
                {
                    join.hello_relays = relays;
                    join.hello_at = now.max(1);
                    *next_poll = 0;
                }
            }
            (LinkStep::ReadSnapshot, TransferUpdate::Downloaded { plain, .. }) => {
                self.on_snapshot(&plain);
            }
            // A read that failed goes again at the next poll.
            (
                LinkStep::ReadHello
                | LinkStep::ReadOffer
                | LinkStep::ReadReply
                | LinkStep::ReadProvision,
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

    /// The hello slot gave its chunks. One hello opens under the key of the
    /// offer: the reply goes up, the code shows, and the offer goes, since
    /// the ticket works once (`DEV-006`). Two different hellos show that a
    /// second party holds the ticket, and the link ends (`DEV-362`). A
    /// chunk that does not open is an empty slot, and the next poll reads
    /// the slot again.
    fn on_hellos(&mut self, chunks: &[Vec<u8>]) {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status: LinkStatus::Ticket { .. },
            ..
        }) = self.link.as_ref()
        else {
            return;
        };
        if offer.hello.is_some() {
            return;
        }

        // The replicas of one write give the same bytes, and those count
        // one time.
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut opened = Vec::new();
        for chunk in chunks {
            let Ok(bytes) = unpad_handle_object(chunk) else {
                continue;
            };
            if seen.contains(&bytes) {
                continue;
            }
            seen.push(bytes);

            if let Ok(found) =
                LinkPending::decapsulate(&offer.link_key, &offer.nonce, &offer.offer, bytes)
            {
                opened.push(found);
            }
        }

        if opened.len() > 1 {
            self.end_link(LinkStatus::Failed);
            return;
        }
        let Some((hello, pending)) = opened.pop() else {
            return;
        };

        // DEV-361: the value of the reply is drawn here, after the hello is
        // fixed.
        let slot = pending.reply_slot();
        let kept_slot = pending.reply_slot();
        let Ok((reply, secret)) = pending.answer(&mut OsRng) else {
            self.end_link(LinkStatus::Failed);
            return;
        };

        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status,
            ..
        }) = self.link.as_mut()
        else {
            return;
        };
        *status = LinkStatus::Code {
            code: six_digits(secret.code()),
        };
        offer.hello = Some((hello, secret));
        offer.reply_slot = Some(kept_slot);
        let relays = core::mem::take(&mut offer.offer_relays);
        let offer_slot = offer_slot(&offer.nonce);
        self.erase_slot(offer_slot, relays);
        self.write_slot(LinkStep::WriteReply, slot, &reply);
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

        // A run that ended takes no invitation. The roster and the pending
        // device of this try then go, and the user confirms again.
        if let Err(fault) = running.invite_device() {
            offer.roster = None;
            *peer_drop_due = true;
            return Err(fault.into());
        }
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
        // The descriptor holds the file key of the snapshot.
        let mut descriptor = Zeroizing::new(vec![0u8; snapshot.descriptor.len()]);
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

    /// The sync channel of a device opened in `conversation`: the roster of
    /// the link holds from here, and the provision and the snapshot go
    /// (`DEV-003`). A roster that does not commit names no new device, thus
    /// its channel ends (`DEV-290`).
    ///
    /// The result is whether the channel stays. A channel whose roster did
    /// not commit ends here, and the view gets no event of it.
    pub(super) fn link_opened(&mut self, conversation: crate::ConversationId) -> bool {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status: LinkStatus::Sending | LinkStatus::Waiting,
            ..
        }) = self.link.as_ref()
        else {
            return true;
        };

        // DEV-290: a sync channel that opened before the provision left is
        // the one of an earlier link. The device of that link read its own
        // provision before that link ended. Such a channel commits no
        // roster of this link.
        if !offer.provision_sent {
            return true;
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
                super::flush_logged(running, client);
            }
        }

        if !committed {
            let Inner { client, bridge, .. } = &mut *self;
            let _ = client.refuse_device_channel(conversation, &mut OsRng);
            if let Some(running) = bridge.as_mut() {
                running.forget(&conversation);
            }
        }

        self.end_link(if committed {
            LinkStatus::Linked
        } else {
            LinkStatus::Failed
        });
        committed
    }

    /// The offer is there: it checks against the ticket (`DEV-281`), and
    /// the hello goes up.
    /// The result is whether the chunk opened. A chunk that does not open
    /// is an empty slot, and the next poll reads the slot again.
    fn on_offer(&mut self, chunk: &[u8]) -> bool {
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
            return false;
        };

        let nonce = join.ticket.nonce;
        let (ct, ss) = LinkPending::encapsulate(&offer, &mut OsRng);
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

        join.pending = Some(LinkPending::new(ss, &nonce, offer_bytes, &hello_bytes));
        join.has_offer = true;
        self.write_slot(LinkStep::WriteHello, hello_slot(&nonce), &hello_bytes);
        true
    }

    /// The reply is there (`DEV-361`): it opens under the key of the hello
    /// of this device, thus the existing device took that hello, and the
    /// code shows. The result is whether the chunk opened.
    fn on_reply(&mut self, chunk: &[u8]) -> bool {
        let Some(LinkState {
            job: LinkJob::Join(join),
            status: status @ LinkStatus::Preparing,
            ..
        }) = self.link.as_mut()
        else {
            return true;
        };

        let secret = join.pending.as_ref().and_then(|pending| {
            let sealed = unpad_handle_object(chunk).ok()?;
            pending.open_reply(sealed).ok()
        });
        let Some(secret) = secret else {
            return false;
        };

        *status = LinkStatus::Code {
            code: six_digits(secret.code()),
        };
        join.secret = Some(secret);
        join.pending = None;
        true
    }

    /// The provision is there: the snapshot that it names comes down, and
    /// the hello goes.
    /// The result is whether the chunk opened. A chunk that does not open
    /// is an empty slot, and the next poll reads the slot again.
    fn on_provision(&mut self, chunk: &[u8]) -> bool {
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
            reply_slot: None,
            reply_relays: Vec::new(),
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
    /// store at [`init_linked`]. A handle that holds a device set or a
    /// conversation gives `Refused`, since [`init_linked`] removes its store
    /// (`DEV-007`, `DEV-008`).
    pub fn join_link(&self, ticket: String, label: String) -> Result<(), FfiError> {
        let ticket = LinkTicket::from_text(&ticket).map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        if inner.bridge.is_none() {
            return Err(FfiError::Offline);
        }
        if inner.client.device_identity()?.is_some() || !inner.client.conversations()?.is_empty() {
            return Err(FfiError::Refused);
        }

        let identity = DeviceIdentity::generate(&label, &mut OsRng);
        inner.start(LinkJob::Join(Box::new(Join {
            ticket,
            identity: Some(identity),
            started_at: unix_now(),
            hello_at: 0,
            has_offer: false,
            pending: None,
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
        let linked = Arc::new(Linked(Mutex::new(LinkedHold::new(taken))));
        inner.linked = Arc::downgrade(&linked);
        Ok(linked)
    }

    /// Removes a device from the set (Part 7 §7.7). The call makes the
    /// epoch that revokes it, the notice to that device, and the end of its
    /// sync channel. Each contact gets a new queue, since the removed
    /// device knew each queue (step 2c). Each other device gets the epoch.
    /// The store holds the rotations and the notice until each one is done,
    /// thus the call needs no run. The removed device keeps what it synced
    /// (`DEV-137`). A link whose snapshot goes holds a roster on the head
    /// that this call would move, thus the call gives `Busy` until that
    /// link ends.
    pub fn remove_device(&self, device_id: Vec<u8>) -> Result<(), FfiError> {
        let device: umbra_core::devset::DeviceId = device_id
            .as_slice()
            .try_into()
            .map_err(|_| FfiError::Malformed)?;
        let mut inner = locked(&self.inner);
        if !inner.client.owns_channels()? {
            return Err(FfiError::NotFound);
        }

        let is_linking = matches!(
            inner.link.as_ref(),
            Some(LinkState {
                job: LinkJob::Offer(_),
                status: LinkStatus::Sending | LinkStatus::Waiting,
                ..
            })
        );
        if is_linking {
            return Err(FfiError::Busy);
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
            super::flush_logged(running, client);
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

        // The lock order of `connect`: the runtime, then the state. A start
        // on another thread then runs before this call or after it, and the
        // stop below ends no runtime of a later run.
        let mut runtime = locked(&self.runtime);
        let rendered = {
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

            // The take-over is done here. A code that does not render must
            // not keep the run of the old ownership up, thus its fault
            // returns after the stop below.
            inner.client.render_recovery_code(&mut held, &mut OsRng)
        };

        if let Some(stopped) = runtime.take() {
            stopped.shutdown_background();
        }
        locked(&self.run_done).take();
        drop(runtime);
        self.changed.notify_all();
        rendered?;
        held.give(sink.as_ref())
    }

    /// Whether another device of the set removed this one (`DEV-181`).
    pub fn removed_from_set(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.removed_from_set()?)
    }

    /// Whether this device owns the channels of the set, thus whether it
    /// can offer a link (`DEV-287`). A row that does not read keeps no
    /// store closed (`IMP-188`).
    pub fn owns_channels(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.owns_channels_shown()?)
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

    /// Sends each key-change notice of a reset now, as a wait of its delay
    /// does (`IDN-063`). For a test over real sockets alone.
    pub fn end_notice_delays(&self) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        inner.client.send_due_notices(u64::MAX, &mut OsRng)?;
        let super::Inner { client, bridge, .. } = &mut *inner;
        if let Some(running) = bridge {
            super::flush_logged(running, client);
        }
        Ok(())
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
    // The holder stays free during the long steps, thus a lock of the old
    // handle never waits for them (`IMP-127`).
    let (restored, identity) = locked(&linked.0).lend().ok_or(FfiError::NotFound)?;
    let made = init_store_from(config, element, passphrase, &restored, |client| {
        client.apply_restore(&restored, &mut OsRng)?;
        Ok(client.apply_link(&identity, &mut OsRng)?)
    });

    // A call that fails keeps the snapshot and the identity for the next
    // try. A lock in the long steps found the holder empty, and no later
    // lock reaches it, thus the two drop here after such a lock.
    if made.is_err() {
        locked(&linked.0).give_back((restored, identity));
    }
    made
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
            reply_slot: None,
            reply_relays: Vec::new(),
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
        inner.link_opened(crate::ConversationId([3; 16]));
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
        inner.link_opened(crate::ConversationId([3; 16]));
        assert_eq!(status(&inner), Some(LinkStatus::Failed));
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A transfer task that the test holds. Each command of the link comes
    /// here, and no command fails for a task that does not run.
    fn task(inner: &mut Inner) -> tokio::sync::mpsc::UnboundedReceiver<TransferCommand> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        inner.transfers = Some(sender);
        receiver
    }

    fn sent(
        task: &mut tokio::sync::mpsc::UnboundedReceiver<TransferCommand>,
    ) -> Vec<TransferCommand> {
        let mut commands = Vec::new();
        while let Ok(command) = task.try_recv() {
            commands.push(command);
        }
        commands
    }

    fn erases(commands: &[TransferCommand], handle: [u8; 32]) -> bool {
        commands.iter().any(
            |command| matches!(command, TransferCommand::Erase { chunk_id, .. } if *chunk_id == handle),
        )
    }

    fn status(inner: &Inner) -> LinkStatus {
        inner
            .link
            .as_ref()
            .map_or(LinkStatus::Idle, |link| link.status.clone())
    }

    fn set_status(inner: &mut Inner, status: LinkStatus) {
        if let Some(link) = inner.link.as_mut() {
            link.status = status;
        }
    }

    const NONCE: [u8; 16] = [5; 16];

    /// The side of the existing device with a true offer, which shows its
    /// ticket. The result is the encoded offer.
    fn shown_offer(inner: &mut Inner) -> Vec<u8> {
        let link_key = KeyPair::generate(&mut OsRng);
        let offer_bytes = LinkOffer {
            link_pk: link_key.public().clone(),
        }
        .encode();
        let LinkJob::Offer(mut job) = offer() else {
            unreachable!()
        };
        job.nonce = NONCE;
        job.link_key = link_key;
        job.offer = offer_bytes.clone();
        inner.start(LinkJob::Offer(job));
        set_status(
            inner,
            LinkStatus::Ticket {
                text: String::new(),
            },
        );
        offer_bytes
    }

    /// The hello of a new device for `offer_bytes`: its identity, its
    /// padded chunk, and its side of the link.
    fn hello_for(offer_bytes: &[u8]) -> (DeviceIdentity, Vec<u8>, LinkPending) {
        let ticket = LinkTicket {
            nonce: NONCE,
            commit: commit(offer_bytes),
        };
        let offer = LinkOffer::parse(offer_bytes, &ticket).unwrap();
        let identity = DeviceIdentity::generate("Tablet", &mut OsRng);
        let (ct, ss) = LinkPending::encapsulate(&offer, &mut OsRng);
        let hello = LinkHello {
            device_id: identity.device_id,
            device_pk: identity.device_key().public().clone(),
            roster_pk: identity.roster_key().verifying_key().to_bytes().to_vec(),
            label: identity.label,
            ct,
        };
        let bytes = hello.seal(&ss, &NONCE, &mut OsRng).unwrap();
        let pending = LinkPending::new(ss, &NONCE, offer_bytes, &bytes);
        (identity, pad_handle_object(&bytes).unwrap(), pending)
    }

    /// A hello as the existing device reads it.
    fn read_hello() -> LinkHello {
        let link_key = KeyPair::generate(&mut OsRng);
        let offer_bytes = LinkOffer {
            link_pk: link_key.public().clone(),
        }
        .encode();
        let (_, chunk, _) = hello_for(&offer_bytes);
        let bytes = unpad_handle_object(&chunk).unwrap();
        let (hello, _) = LinkPending::decapsulate(&link_key, &NONCE, &offer_bytes, bytes).unwrap();
        hello
    }

    /// The side of the new device, which waits for its offer.
    fn join() -> LinkJob {
        LinkJob::Join(Box::new(Join {
            ticket: LinkTicket {
                nonce: NONCE,
                commit: [0; 32],
            },
            identity: Some(DeviceIdentity::generate("Tablet", &mut OsRng)),
            started_at: unix_now(),
            hello_at: 0,
            has_offer: false,
            pending: None,
            secret: None,
            hello_relays: Vec::new(),
            restored: None,
        }))
    }

    #[test]
    fn one_hello_gets_its_reply_and_two_hellos_end_the_link() {
        let (handle, directory) = open("link-hellos");
        let mut inner = locked(&handle.inner);
        inner.pump_link(unix_now());
        let mut task = task(&mut inner);

        // Two replicas give the hello of one write, and a third one gives
        // other bytes. That is one hello.
        let offer_bytes = shown_offer(&mut inner);
        let (_, chunk, pending) = hello_for(&offer_bytes);
        let junk = pad_handle_object(&[7u8; 64]).unwrap();
        inner.on_hellos(&[junk, chunk.clone(), chunk]);
        let shown = status(&inner);
        assert!(matches!(shown, LinkStatus::Code { .. }), "{shown:?}");
        let LinkStatus::Code { code } = shown else {
            return;
        };

        // DEV-361: the reply goes under the slot of that hello, and the new
        // device reads the code of the existing device from it. DEV-003:
        // the offer goes.
        let commands = sent(&mut task);
        let reply = commands
            .iter()
            .find_map(|command| match command {
                TransferCommand::WriteHandle { handle, chunk, .. }
                    if *handle == pending.reply_slot().handle =>
                {
                    Some(chunk.clone())
                }
                _ => None,
            })
            .unwrap();
        let secret = pending
            .open_reply(unpad_handle_object(&reply).unwrap())
            .unwrap();
        assert_eq!(six_digits(secret.code()), code);
        assert!(erases(&commands, offer_slot(&NONCE).handle));

        // DEV-006: the ticket works once. A later hello changes nothing.
        let (_, late, _) = hello_for(&offer_bytes);
        inner.on_hellos(&[late]);
        assert_eq!(status(&inner), LinkStatus::Code { code });
        assert!(sent(&mut task).is_empty());

        // DEV-362: two hellos in one read show a second holder of the
        // ticket. No code shows, and no reply goes.
        let offer_bytes = shown_offer(&mut inner);
        sent(&mut task);
        let (_, first, _) = hello_for(&offer_bytes);
        let (_, second, _) = hello_for(&offer_bytes);
        inner.on_hellos(&[first, second]);
        assert_eq!(status(&inner), LinkStatus::Failed);
        assert!(!sent(&mut task)
            .iter()
            .any(|command| matches!(command, TransferCommand::WriteHandle { .. })));
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_new_device_shows_its_code_at_the_reply_to_its_own_hello() {
        let (handle, directory) = open("link-reply");
        let mut inner = locked(&handle.inner);
        inner.pump_link(unix_now());
        let mut task = task(&mut inner);

        // The new device wrote its hello, and it waits for the reply.
        let link_key = KeyPair::generate(&mut OsRng);
        let offer_bytes = LinkOffer {
            link_pk: link_key.public().clone(),
        }
        .encode();
        let (_, chunk, pending) = hello_for(&offer_bytes);
        let reply_handle = pending.reply_slot().handle;
        inner.start(join());
        if let Some(LinkState {
            job: LinkJob::Join(join),
            ..
        }) = inner.link.as_mut()
        {
            join.has_offer = true;
            join.hello_at = unix_now();
            join.pending = Some(pending);
        }

        // It reads the reply slot, and it shows no code before the reply.
        inner.pump_link(unix_now());
        assert!(sent(&mut task).iter().any(|command| matches!(
            command,
            TransferCommand::ReadHandle { handle, .. } if *handle == reply_handle
        )));
        assert_eq!(status(&inner), LinkStatus::Preparing);

        // The reply to the hello of another party opens nothing.
        let (_, other_chunk, _) = hello_for(&offer_bytes);
        let other = unpad_handle_object(&other_chunk).unwrap();
        let (_, taken) = LinkPending::decapsulate(&link_key, &NONCE, &offer_bytes, other).unwrap();
        let (other_reply, _) = taken.answer(&mut OsRng).unwrap();
        assert!(!inner.on_reply(&pad_handle_object(&other_reply).unwrap()));
        assert_eq!(status(&inner), LinkStatus::Preparing);

        // Its own reply gives the code of the existing device.
        let own = unpad_handle_object(&chunk).unwrap();
        let (_, taken) = LinkPending::decapsulate(&link_key, &NONCE, &offer_bytes, own).unwrap();
        let (reply, secret) = taken.answer(&mut OsRng).unwrap();
        assert!(inner.on_reply(&pad_handle_object(&reply).unwrap()));
        assert_eq!(
            status(&inner),
            LinkStatus::Code {
                code: six_digits(secret.code())
            }
        );
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn each_step_of_a_link_ends_at_its_time_and_erases_its_objects() {
        let (handle, directory) = open("link-expiry");
        let mut inner = locked(&handle.inner);
        let now = unix_now();
        inner.pump_link(now);
        let mut task = task(&mut inner);
        let after = |time: u64| now.saturating_add(time).saturating_add(2);

        // DEV-005: the ticket ends at `LINK_QR_TTL`, and the offer goes.
        shown_offer(&mut inner);
        inner.pump_link(now);
        assert!(matches!(status(&inner), LinkStatus::Ticket { .. }));
        inner.pump_link(after(LINK_QR_TTL));
        assert_eq!(status(&inner), LinkStatus::Expired);
        assert!(erases(&sent(&mut task), offer_slot(&NONCE).handle));

        // A code that the user never confirms ends at two times
        // `LINK_PROVISION_TTL`, and the reply goes.
        let offer_bytes = shown_offer(&mut inner);
        let (_, chunk, pending) = hello_for(&offer_bytes);
        inner.on_hellos(&[chunk]);
        if let Some(LinkState {
            job: LinkJob::Offer(offer),
            ..
        }) = inner.link.as_mut()
        {
            offer.reply_relays = vec![[8; 32]];
        }
        sent(&mut task);
        inner.pump_link(after(LINK_QR_TTL));
        assert!(matches!(status(&inner), LinkStatus::Code { .. }));
        inner.pump_link(after(2 * LINK_PROVISION_TTL));
        assert_eq!(status(&inner), LinkStatus::Expired);
        assert!(erases(&sent(&mut task), pending.reply_slot().handle));

        // DEV-003: a provision that no device took ends at
        // `LINK_PROVISION_TTL`. DEV-290: the pending device leaves.
        shown_offer(&mut inner);
        set_status(&mut inner, LinkStatus::Waiting);
        if let Some(LinkState {
            job: LinkJob::Offer(offer),
            ..
        }) = inner.link.as_mut()
        {
            offer.provisioned_at = now;
        }
        inner
            .client
            .set_pending_peer([4; 16], &[0; 32], &mut OsRng)
            .unwrap();
        inner.peer_drop_due = false;
        inner.pump_link(now);
        assert_eq!(status(&inner), LinkStatus::Waiting);
        assert!(inner.client.holds_pending_peer().unwrap());
        inner.pump_link(after(LINK_PROVISION_TTL));
        assert_eq!(status(&inner), LinkStatus::Expired);
        assert!(!inner.client.holds_pending_peer().unwrap());

        // The new device: no offer and no reply inside `LINK_QR_TTL`.
        inner.start(join());
        inner.pump_link(now);
        assert_eq!(status(&inner), LinkStatus::Preparing);
        inner.pump_link(after(LINK_QR_TTL));
        assert_eq!(status(&inner), LinkStatus::Expired);

        // The new device: no provision inside `LINK_PROVISION_TTL` after
        // its hello, and the hello goes.
        let link_key = KeyPair::generate(&mut OsRng);
        let offer_bytes = LinkOffer {
            link_pk: link_key.public().clone(),
        }
        .encode();
        let (_, _, pending) = hello_for(&offer_bytes);
        let (_, secret) = pending.answer(&mut OsRng).unwrap();
        inner.start(join());
        if let Some(LinkState {
            job: LinkJob::Join(join),
            status,
            ..
        }) = inner.link.as_mut()
        {
            join.has_offer = true;
            join.hello_at = now;
            join.hello_relays = vec![[8; 32]];
            join.secret = Some(secret);
            *status = LinkStatus::Code {
                code: "000000".into(),
            };
        }
        sent(&mut task);
        inner.pump_link(now);
        assert!(matches!(status(&inner), LinkStatus::Code { .. }));
        inner.pump_link(after(LINK_PROVISION_TTL));
        assert_eq!(status(&inner), LinkStatus::Expired);
        assert!(erases(&sent(&mut task), hello_slot(&NONCE).handle));
        drop(inner);
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_roster_that_does_not_commit_ends_the_channel_of_its_link() {
        let (handle, directory) = open("link-commit");
        let mut inner = locked(&handle.inner);
        inner.pump_link(unix_now());
        inner.client.ensure_device_set("Phone", &mut OsRng).unwrap();

        // The user confirmed a link, and the sync channel of its device
        // opened. Another epoch took the head in between.
        let first = inner
            .client
            .sign_linked_device(&read_hello(), &mut OsRng)
            .unwrap();
        let other = inner
            .client
            .sign_linked_device(&read_hello(), &mut OsRng)
            .unwrap();
        inner.start(offer());
        set_status(&mut inner, LinkStatus::Waiting);
        if let Some(LinkState {
            job: LinkJob::Offer(offer),
            ..
        }) = inner.link.as_mut()
        {
            offer.roster = Some(first);
            offer.provision_sent = true;
        }
        let conversation = crate::ConversationId([3; 16]);
        inner
            .client
            .set_pending_peer([4; 16], &[0; 32], &mut OsRng)
            .unwrap();
        inner
            .client
            .mark_device_peer(conversation, &mut OsRng)
            .unwrap();
        assert!(inner.client.is_device_peer(conversation).unwrap());
        inner.client.commit_roster(&other, &mut OsRng).unwrap();

        // The link fails, and the channel of a device that no roster names
        // ends with it (`DEV-290`). The view gets no event of a linked
        // device.
        inner
            .net_events
            .push_back(crate::bridge::NetEvent::DeviceLinked(conversation));
        inner.take_link_events();
        assert!(inner.net_events.is_empty());
        assert_eq!(status(&inner), LinkStatus::Failed);
        assert!(!inner.client.is_device_peer(conversation).unwrap());

        // A removal moves the head, thus it waits while the snapshot of a
        // link goes.
        for waits in [LinkStatus::Sending, LinkStatus::Waiting] {
            inner.start(offer());
            set_status(&mut inner, waits);
            drop(inner);
            assert_eq!(
                handle.remove_device(vec![4; 16]).err(),
                Some(FfiError::Busy)
            );
            inner = locked(&handle.inner);
        }

        // With no such link the call reaches the roster, which names no
        // such device.
        inner.cancel_link();
        drop(inner);
        assert_eq!(
            handle.remove_device(vec![4; 16]).err(),
            Some(FfiError::NotFound)
        );
        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_confirmation_needs_a_code_and_a_run() {
        let (handle, directory) = open("link-confirm");
        let mut inner = locked(&handle.inner);
        inner.pump_link(unix_now());
        let mut task = task(&mut inner);

        // No link, and a link with no hello: no code to confirm.
        assert_eq!(inner.confirm_link().err(), Some(FfiError::NotFound));
        let offer_bytes = shown_offer(&mut inner);
        assert_eq!(inner.confirm_link().err(), Some(FfiError::NotFound));

        // A code with no run: the call changes nothing, and the user can
        // confirm again when the network is up.
        let (_, chunk, _) = hello_for(&offer_bytes);
        inner.on_hellos(&[chunk]);
        let shown = status(&inner);
        assert!(matches!(shown, LinkStatus::Code { .. }));
        assert_eq!(inner.confirm_link().err(), Some(FfiError::Offline));
        assert_eq!(status(&inner), shown);
        assert!(!inner.client.holds_pending_peer().unwrap());
        sent(&mut task);
        drop(inner);

        drop(handle);
        let _ = std::fs::remove_dir_all(&directory);
    }

    struct Keystore;

    impl SecureElementCallback for Keystore {
        fn keyed(&self, _input: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            Ok(vec![7; 32])
        }
    }

    #[test]
    fn a_link_store_that_fails_keeps_its_snapshot_for_the_next_try() {
        let (handle, directory) = open("link-init");
        let mut inner = locked(&handle.inner);
        inner.client.ensure_device_set("Phone", &mut OsRng).unwrap();

        // The snapshot of a link whose roster names the new device.
        let link_key = KeyPair::generate(&mut OsRng);
        let offer_bytes = LinkOffer {
            link_pk: link_key.public().clone(),
        }
        .encode();
        let (identity, chunk, _) = hello_for(&offer_bytes);
        let bytes = unpad_handle_object(&chunk).unwrap();
        let (hello, _) = LinkPending::decapsulate(&link_key, &NONCE, &offer_bytes, bytes).unwrap();
        let roster = inner.client.sign_linked_device(&hello, &mut OsRng).unwrap();
        let plain = inner
            .client
            .link_snapshot(unix_now(), &roster, &[7; 64], 0)
            .unwrap();
        drop(inner);
        drop(handle);

        let held = || {
            let restored = RestoredBackup::assemble(core::slice::from_ref(&plain)).unwrap();
            let identity = DeviceIdentity::parse(&identity.encode()).unwrap();
            Arc::new(Linked(Mutex::new(LinkedHold::new((restored, identity)))))
        };
        let config = |file: &str| Config {
            database_path: directory.join(file).to_str().unwrap().to_owned(),
            argon2_floor_ms: 60_000,
        };

        // A folder that is not there fails the open of the store, and the
        // holder keeps the snapshot.
        let linked = held();
        let failed = init_linked(
            config("absent/tablet.db"),
            Arc::new(Keystore),
            passphrase(),
            Arc::clone(&linked),
        );
        assert_eq!(failed.err(), Some(FfiError::Storage));
        assert!(locked(&linked.0).value.is_some());

        // The next try makes the store of a device of the set, and the
        // holder is empty for each later call.
        let made = init_linked(
            config("tablet.db"),
            Arc::new(Keystore),
            passphrase(),
            Arc::clone(&linked),
        )
        .unwrap();
        assert_eq!(made.devices().unwrap().len(), 2);
        assert!(!made.owns_channels().unwrap());
        assert!(locked(&linked.0).value.is_none());
        drop(made);
        let again = init_linked(config("again.db"), Arc::new(Keystore), passphrase(), linked);
        assert_eq!(again.err(), Some(FfiError::NotFound));

        // IMP-127: a lock in the long steps finds the holder empty. A call
        // that fails after it puts nothing back, since no later lock
        // reaches the holder.
        let linked = held();
        let lent = locked(&linked.0).lend().unwrap();
        assert!(locked(&linked.0).take().is_none());
        locked(&linked.0).give_back(lent);
        assert!(locked(&linked.0).value.is_none());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
