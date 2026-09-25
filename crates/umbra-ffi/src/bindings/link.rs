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
use umbra_crypto::{kem::KeyPair, rand_core::TryRng};
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
    snapshot: Option<Box<Uploaded>>,
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
        let serial = self.link.as_ref()?.serial;
        Some(self.next_tag(TransferWork::Link { serial, step }))
    }

    fn write_slot(&mut self, step: LinkStep, slot: Slot, object: &[u8]) {
        let Ok(chunk) = pad_handle_object(object) else {
            self.end_link(LinkStatus::Failed);
            return;
        };
        let Some(tag) = self.link_tag(step) else {
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
        for (slot, relays) in slots {
            self.erase_slot(slot, relays);
        }
        for credential in chunks {
            self.send_transfer(TransferCommand::Erase {
                chunk_id: credential.chunk_id,
                cred: credential.cred,
                relays: credential.relays,
            });
        }
    }

    fn end_link(&mut self, status: LinkStatus) {
        self.erase_link_objects();
        if let Some(link) = self.link.as_mut() {
            link.status = status;
            link.reading = false;
        }
    }

    /// Ends the link that runs, and erases what it put on the chunk path.
    pub(super) fn cancel_link(&mut self) {
        self.erase_link_objects();
        self.link = None;
    }

    /// The expiry of each step, and the read of a slot that holds nothing
    /// yet at each `POLL`.
    pub(super) fn pump_link(&mut self, now: u64) {
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
            | TransferUpdate::Failed { tag } => *tag,
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
        let Some(TransferWork::Link { serial, step }) = self.transfer_tags.remove(&tag) else {
            return None;
        };
        // A transfer of a link that ended goes nowhere.
        if self.link.as_ref().map(|link| link.serial) != Some(serial) {
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
                TransferUpdate::HandleRead { chunk, .. },
            ) => {
                if let Some(link) = self.link.as_mut() {
                    link.reading = false;
                }
                if let Some(chunk) = chunk {
                    match step {
                        LinkStep::ReadHello => self.on_hello(&chunk),
                        LinkStep::ReadOffer => self.on_offer(&chunk),
                        _ => self.on_provision(&chunk),
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
    fn on_hello(&mut self, chunk: &[u8]) {
        let Some(LinkState {
            job: LinkJob::Offer(offer),
            status,
            ..
        }) = self.link.as_mut()
        else {
            return;
        };
        if offer.hello.is_some() {
            return;
        }
        let opened = unpad_handle_object(chunk).ok().and_then(|bytes| {
            LinkSecret::decapsulate(&offer.link_key, &offer.nonce, &offer.offer, bytes).ok()
        });
        let Some((hello, secret)) = opened else {
            self.end_link(LinkStatus::Failed);
            return;
        };
        *status = LinkStatus::Code {
            code: six_digits(secret.code()),
        };
        offer.hello = Some((hello, secret));
        let relays = core::mem::take(&mut offer.offer_relays);
        let slot = offer_slot(&offer.nonce);
        self.erase_slot(slot, relays);
    }

    /// The user confirmed that the two codes match (`DEV-283`): the roster
    /// of epoch n+1 is signed, and the sync invitation is asked for. The
    /// snapshot goes up when its bundle is here.
    pub(super) fn confirm_link(&mut self) -> Result<(), FfiError> {
        let Inner {
            link,
            client,
            bridge,
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
        client.set_pending_peer(hello.device_id, &hello.label, &mut OsRng)?;
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
        let plain = match self.client.link_snapshot(unix_now(), roster, bundle) {
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
            Ok(sealed) => self.write_slot(LinkStep::WriteProvision, slot, &sealed),
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
        let committed = offer
            .roster
            .as_ref()
            .is_some_and(|roster| self.client.commit_roster(roster, &mut OsRng).is_ok());
        // DEV-176: each other device of the set takes the new epoch.
        if committed && self.client.publish_roster(&mut OsRng).is_ok() {
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
    fn on_offer(&mut self, chunk: &[u8]) {
        let Some(LinkState {
            job: LinkJob::Join(join),
            ..
        }) = self.link.as_mut()
        else {
            return;
        };
        let Some(identity) = join.identity.as_ref() else {
            return;
        };
        let Some((offer_bytes, offer)) = unpad_handle_object(chunk)
            .ok()
            .and_then(|bytes| Some((bytes, LinkOffer::parse(bytes, &join.ticket).ok()?)))
        else {
            self.end_link(LinkStatus::Failed);
            return;
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
            return;
        };
        join.secret = Some(LinkSecret::new(ss, &nonce, offer_bytes, &hello_bytes));
        join.has_offer = true;
        self.write_slot(LinkStep::WriteHello, hello_slot(&nonce), &hello_bytes);
    }

    /// The provision is there: the snapshot that it names comes down, and
    /// the hello goes.
    fn on_provision(&mut self, chunk: &[u8]) {
        let Some(LinkState {
            job: LinkJob::Join(join),
            status,
            ..
        }) = self.link.as_mut()
        else {
            return;
        };
        let descriptor = join.secret.as_ref().and_then(|secret| {
            let sealed = unpad_handle_object(chunk).ok()?;
            let provision = secret.open(sealed).ok()?;
            FileDescriptor::parse(&provision.snapshot).ok()
        });
        let Some(descriptor) = descriptor else {
            self.end_link(LinkStatus::Failed);
            return;
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
    /// (`DEV-280`). A link that runs ends first.
    pub fn start_link(&self, label: String) -> Result<(), FfiError> {
        let mut inner = locked(&self.inner);
        if inner.bridge.is_none() {
            return Err(FfiError::Offline);
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
            snapshot: None,
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

    /// Removes a device from the set (Part 7 §7.7): the epoch that revokes
    /// it, the end of its sync channel, a new queue for each contact, since
    /// the removed device knew each queue (step 2c), and the epoch to each
    /// other device. The removed device keeps what it synced (`DEV-137`).
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
        let Inner { client, bridge, .. } = &mut *inner;
        if let Some(running) = bridge.as_mut() {
            let peers = client.device_peers()?;
            for (conversation, contact) in running.contacts() {
                if !peers.contains(&conversation) {
                    running.rotate_now(contact)?;
                }
            }
            running.flush(client, &mut OsRng)?;
        }
        Ok(())
    }

    /// Whether this device owns the channels of the set, thus whether it
    /// can offer a link (`DEV-287`).
    pub fn owns_channels(&self) -> Result<bool, FfiError> {
        Ok(locked(&self.inner).client.owns_channels()?)
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
