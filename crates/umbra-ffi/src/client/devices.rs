//! The device set of Part 7 in the store of one device: its own device
//! identity, the current roster, and the sync channels to the other devices
//! of the set (`DEV-286`).
//!
//! A linked device owns no pairwise ratchet and no group sender at the link
//! (`DEV-287`), thus its runtime reaches no queue of a contact: each queue
//! has one reader, and that reader is the device that owns the channel.
//! The take-over of `takeover.rs` moves that ownership to a linked device.

use umbra_core::{
    devset::{
        link::{sign_roster, DeviceIdentity, EntryKeys, LinkHello, LABEL_LEN},
        roster::{Parent, Roster, SyncScope},
        DeviceId,
    },
    identity::backup::BackupRow,
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::app::devset::{ControlType, DeviceSetBody};
use zeroize::Zeroizing;

use super::{
    roster_fork::{FORK_PEER, PARENT_KEY, ROSTER_HASHES, ROSTER_PARENT},
    Client, SETTINGS,
};
use crate::{ConversationId, Delivery, Error, MsgRef};

/// The identity of this device, with the flag of its channels.
pub(super) const DEVICE_SELF: TableId = TableId(0x21);
/// The current roster epoch of the set.
pub(super) const DEVICE_ROSTER: TableId = TableId(0x22);
/// The sync channel of each other device, by its conversation.
pub(super) const DEVICE_PEERS: TableId = TableId(0x23);
/// Each sync channel that a revocation ended, by its conversation. The node
/// of the run that ended it still holds it, and the store takes no state of
/// it again.
pub(super) const ENDED_CHANNELS: TableId = TableId(0x26);
/// The key of the mark that a verified epoch revoked this device
/// (`DEV-181`), under the settings.
const REMOVED_FROM_SET: &[u8] = b"removed-from-set";

/// The contacts whose queue rotation a revocation owes (Part 7 §7.7 step
/// 2c), under the settings: the conversation of each one in turn. A
/// conversation leaves the row when its queue rotated.
pub(super) const ROTATION_OWED: &[u8] = b"rotation-owed";
/// The rendezvous queues that a revocation owes a successor (`DEV-347`),
/// under the settings: the `RecipientId` of each one, 32 bytes each. A queue
/// leaves the row when no published entry names it as its current queue.
pub(super) const RENDEZVOUS_OWED: &[u8] = b"rendezvous-owed";
/// The sync channel of each revoked device that still waits for the notice
/// of its revocation (`DEV-313`), under the settings. The value holds the
/// conversation of the channel and then the device, in turn.
const LEAVING_CHANNELS: &[u8] = b"leaving-channels";
const LEAVING_ENTRY: usize = 16 + 16;
/// The notice of one revoked device, before its `device_id`: the time of
/// the revocation, in seconds, then the epoch that revokes the device.
const REVOCATION_NOTICE: &[u8] = b"revocation-notice/";
/// The time that the channel of a revoked device waits for a relay to take
/// the notice of `DEV-313`. A device that did not run for that time ends
/// the channel with no notice.
pub const REVOCATION_NOTICE_TTL: u64 = umbra_queue::params::MSG_TTL;
/// The least time between two requests for the owed rotations of one run,
/// in seconds. The node keeps the time of each rotation that it took.
const ROTATION_ASK_EVERY: u64 = 60;

pub(super) const SELF_KEY: &[u8] = b"self";
const ROSTER_KEY: &[u8] = b"roster";

/// One write that commits with a roster epoch.
pub(super) enum RowWrite {
    Put(TableId, RowId, Zeroizing<Vec<u8>>),
    Delete(TableId, RowId),
}
/// The epochs below the head that a device keeps for a peer that missed
/// one (`DEV-229`), each in the roster table under its index.
const ROSTER_CHAIN_KEPT: u64 = 8;
const KEPT_EPOCH: &[u8] = b"epoch/";

fn kept_epoch_key(epoch: u64) -> Vec<u8> {
    [KEPT_EPOCH, epoch.to_be_bytes().as_slice()].concat()
}
/// The device whose sync channel waits for its handshake, and the bundle of
/// that channel at a linked device.
pub(super) const PENDING_PEER_SETTING: &[u8] = b"device-pending-peer";
pub(super) const SYNC_BUNDLE_SETTING: &[u8] = b"device-sync-bundle";
/// The existing device of a link and its causal counter at the snapshot
/// (`DEV-311`).
pub(super) const LINK_FLOOR_SETTING: &[u8] = b"device-link-floor";
/// The queue of each sync invitation of this device that waits for its
/// flight 1 (`DEV-290`), 32 bytes each. The setting stays on the device.
pub(super) const DEVICE_INVITES_SETTING: &[u8] = b"device-invites";

/// One device of the set, as a view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The random `device_id`.
    pub device_id: DeviceId,
    /// The label that the user gave it.
    pub label: String,
    /// Whether it is this device.
    pub is_self: bool,
    /// The roster epoch that added it.
    pub added_epoch: u64,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The identity of this device, when it has a device set.
    pub fn device_identity(&self) -> Result<Option<DeviceIdentity>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(DEVICE_SELF, SELF_KEY);
        match store.get(DEVICE_SELF, &row)? {
            Some(plain) => {
                let plain = Zeroizing::new(plain);
                let identity = plain.get(1..).ok_or(Error::Integrity)?;
                Ok(Some(DeviceIdentity::parse(identity)?))
            }
            None => Ok(None),
        }
    }

    /// Whether this device owns the pairwise channels and the group senders
    /// of the set. A device with no set owns them; a linked device owns none
    /// (`DEV-287`).
    pub fn owns_channels(&self) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(DEVICE_SELF, SELF_KEY);
        Ok(store
            .get(DEVICE_SELF, &row)?
            .is_none_or(|plain| plain.first() == Some(&1)))
    }

    /// [`Client::owns_channels`] for a view. A row that does not read gives
    /// the value of no row, and the unlock told the user of the fault
    /// (`IMP-188`). Each act of the set reads the strict value.
    pub fn owns_channels_shown(&self) -> Result<bool, Error> {
        Ok(super::row_fault(self.owns_channels())?.unwrap_or(true))
    }

    pub(super) fn put_device_identity<R: CryptoRng + ?Sized>(
        &mut self,
        identity: &DeviceIdentity,
        owns: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut plain = Zeroizing::new(vec![u8::from(owns)]);
        plain.extend_from_slice(&identity.encode());
        let open = self.open_mut()?;
        let row = open.store.row_id(DEVICE_SELF, SELF_KEY);
        let mut batch = open.store.begin();
        batch.put(DEVICE_SELF, row, None, &plain, rng)?;

        Ok(batch.commit()?)
    }

    /// The current roster epoch, encoded and signed.
    pub fn roster_bytes(&self) -> Result<Option<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(DEVICE_ROSTER, ROSTER_KEY);
        Ok(store.get(DEVICE_ROSTER, &row)?)
    }

    /// Keeps a roster epoch as the head, with its hash (`DEV-228`). The
    /// head before it becomes the parent when the new epoch follows it; an
    /// epoch at the index of the head keeps the parent.
    pub(super) fn put_roster<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        self.put_roster_with(bytes, Vec::new(), rng)
    }

    /// [`Client::put_roster`], with each write of `writes` in the commit of
    /// the epoch. Thus a fault leaves the epoch and what follows from it
    /// together, or neither.
    pub(super) fn put_roster_with<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        writes: Vec<RowWrite>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let epoch = Roster::parse(bytes)?.epoch;
        let superseded = match self.roster_bytes()? {
            Some(current) if Roster::parse(&current)?.epoch.saturating_add(1) == epoch => {
                Some((Parent::of(&current)?.encode()?, current))
            }
            _ => None,
        };
        let open = self.open_mut()?;
        let row = open.store.row_id(DEVICE_ROSTER, ROSTER_KEY);
        let hash_row = open.store.row_id(ROSTER_HASHES, &epoch.to_be_bytes());
        let parent_row = open.store.row_id(ROSTER_PARENT, PARENT_KEY);
        let below = epoch.saturating_sub(1);
        let kept_row = open.store.row_id(DEVICE_ROSTER, &kept_epoch_key(below));
        let old_row = below
            .checked_sub(ROSTER_CHAIN_KEPT)
            .map(|old| open.store.row_id(DEVICE_ROSTER, &kept_epoch_key(old)));
        let mut batch = open.store.begin();
        batch.put(DEVICE_ROSTER, row, None, bytes, rng)?;
        batch.put(ROSTER_HASHES, hash_row, None, &Roster::hash(bytes), rng)?;
        if let Some((parent, current)) = superseded {
            batch.put(ROSTER_PARENT, parent_row, None, &parent, rng)?;

            // DEV-229: the epoch that the new head follows stays for a peer
            // that missed it, and the one past the bound leaves.
            batch.put(DEVICE_ROSTER, kept_row, None, &current, rng)?;
            if let Some(old_row) = old_row {
                batch.delete(DEVICE_ROSTER, old_row);
            }
        }

        for write in &writes {
            match write {
                RowWrite::Put(table, row, plain) => batch.put(*table, *row, None, plain, rng)?,
                RowWrite::Delete(table, row) => batch.delete(*table, *row),
            }
        }

        Ok(batch.commit()?)
    }

    /// The epoch below the head that this device kept at `epoch`.
    fn kept_epoch(&self, epoch: u64) -> Result<Option<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(DEVICE_ROSTER, &kept_epoch_key(epoch));
        Ok(store.get(DEVICE_ROSTER, &row)?)
    }

    /// The epochs that follow `bytes` up to the head, in order (`DEV-150`,
    /// `DEV-229`). `bytes` must be an epoch below the head on the chain of
    /// this device, and the device must hold each epoch between the two. A
    /// peer that sends such an epoch missed the ones after it, and it
    /// verifies the head only through them. The result is empty in each
    /// other case.
    pub(super) fn roster_chain_after(&self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let Some(head) = self.roster_bytes()? else {
            return Ok(Vec::new());
        };

        let from = Roster::parse(bytes)?.epoch;
        let top = Roster::parse(&head)?.epoch;
        if from >= top || top.saturating_sub(from) > ROSTER_CHAIN_KEPT.saturating_add(1) {
            return Ok(Vec::new());
        }

        let mut chain = Vec::new();
        let mut previous = Roster::hash(bytes);
        for epoch in from.saturating_add(1)..top {
            let Some(kept) = self.kept_epoch(epoch)? else {
                return Ok(Vec::new());
            };
            if Roster::parse(&kept)?.prev_hash != previous {
                return Ok(Vec::new());
            }

            previous = Roster::hash(&kept);
            chain.push(kept);
        }

        if Roster::parse(&head)?.prev_hash != previous {
            return Ok(Vec::new());
        }

        chain.push(head);

        Ok(chain)
    }

    /// Makes the identity of this device and roster epoch 0 with it alone,
    /// when the device has no set yet (`DEV-285`).
    pub fn ensure_device_set<R: CryptoRng + ?Sized>(
        &mut self,
        label: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.device_identity()?.is_some() {
            return Ok(());
        }

        let identity = DeviceIdentity::generate(label, rng);
        let keys = EntryKeys::of(&identity);
        let genesis = Roster {
            epoch: 0,
            devices: vec![keys.entry(identity.device_id, identity.label, 0, SyncScope::Full)?],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: [0; 32],
            signer_id: identity.device_id,
            sig: &[0; umbra_crypto::sign::SIGNATURE_LEN],
        };
        let bytes = sign_roster(&genesis, &identity.roster_key(), rng)?;
        self.put_device_identity(&identity, true, rng)?;
        self.put_roster(&bytes, rng)
    }

    /// A new identity of this device and a new roster epoch 0 with it alone,
    /// at a full identity reset (Part 7 `DEV-172`, `DEV-173`). The old
    /// roster chain has no authority over the new one.
    pub(super) fn new_device_set<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<(DeviceIdentity, Vec<u8>), Error> {
        let label = match self.device_identity()? {
            Some(held) => {
                let end = held
                    .label
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(held.label.len());
                String::from_utf8_lossy(held.label.get(..end).unwrap_or_default()).into_owned()
            }
            None => String::new(),
        };
        let identity = DeviceIdentity::generate(&label, rng);
        let keys = EntryKeys::of(&identity);
        let genesis = Roster {
            epoch: 0,
            devices: vec![keys.entry(identity.device_id, identity.label, 0, SyncScope::Full)?],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: [0; 32],
            signer_id: identity.device_id,
            sig: &[0; umbra_crypto::sign::SIGNATURE_LEN],
        };
        let bytes = sign_roster(&genesis, &identity.roster_key(), rng)?;

        Ok((identity, bytes))
    }

    /// The writes that keep a device set that [`Client::new_device_set`]
    /// made: this device as the owner of the channels, and the roster epoch
    /// with its hash (`DEV-228`). A reset puts them in the commit of the new
    /// root, thus a fault leaves no new root with the set of the old one.
    /// An epoch 0 follows no head, thus it takes no parent and keeps no
    /// epoch below it.
    pub(super) fn device_set_writes(
        &self,
        identity: &DeviceIdentity,
        roster: &[u8],
    ) -> Result<Vec<RowWrite>, Error> {
        let epoch = Roster::parse(roster)?.epoch;
        let mut owner = Zeroizing::new(vec![1u8]);
        owner.extend_from_slice(&identity.encode());

        let store = &self.open_ref()?.store;
        Ok(vec![
            RowWrite::Put(DEVICE_SELF, store.row_id(DEVICE_SELF, SELF_KEY), owner),
            RowWrite::Put(
                DEVICE_ROSTER,
                store.row_id(DEVICE_ROSTER, ROSTER_KEY),
                Zeroizing::new(roster.to_vec()),
            ),
            RowWrite::Put(
                ROSTER_HASHES,
                store.row_id(ROSTER_HASHES, &epoch.to_be_bytes()),
                Zeroizing::new(Roster::hash(roster).to_vec()),
            ),
        ])
    }

    /// Signs the roster epoch that adds the device of `hello`, and gives
    /// its encoding (`DEV-166`, `DEV-176`). The store keeps it at
    /// [`Client::commit_roster`], when the sync channel of the device opens.
    pub fn sign_linked_device<R: CryptoRng + ?Sized>(
        &self,
        hello: &LinkHello,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        let current = self.roster_bytes()?.ok_or(Error::NotFound)?;
        let previous = Roster::parse(&current)?;
        if previous.devices.len() >= umbra_core::devset::MAX_DEVICES {
            return Err(Error::TooLong);
        }

        // DEV-224: an identifier that the roster holds or revoked names
        // another device, and two entries with one identifier would share
        // one sync channel.
        if previous.entry(&hello.device_id).is_some() || previous.revoked.contains(&hello.device_id)
        {
            return Err(Error::Malformed);
        }

        let added = EntryKeys::of_hello(hello);
        let epoch = previous.epoch.saturating_add(1);
        let mut devices = previous.devices.clone();
        devices.push(added.entry(hello.device_id, hello.label, epoch, SyncScope::Full)?);
        let next = Roster {
            epoch,
            devices,
            revoked: previous.revoked.clone(),
            claims: Vec::new(),
            prev_hash: Roster::hash(&current),
            signer_id: identity.device_id,
            sig: previous.sig,
        };

        Ok(sign_roster(&next, &identity.roster_key(), rng)?)
    }

    /// Keeps a roster epoch that this device signed, when it follows the
    /// current one.
    pub fn commit_roster<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let next = Roster::parse(bytes)?;
        if let Some(current) = self.roster_bytes()? {
            if next.prev_hash != Roster::hash(&current) {
                return Err(Error::Integrity);
            }
        }

        self.put_roster(bytes, rng)
    }

    /// Signs the roster epoch that revokes `device` and keeps it (Part 7
    /// §7.7 step 1), and ends the sync channel of that device (step 2a).
    /// The result is the epoch, for the other devices of the set.
    pub fn revoke_device<R: CryptoRng + ?Sized>(
        &mut self,
        device: DeviceId,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        if device == identity.device_id {
            return Err(Error::Malformed);
        }

        let current = self.roster_bytes()?.ok_or(Error::NotFound)?;
        let previous = Roster::parse(&current)?;
        if previous.entry(&device).is_none() {
            return Err(Error::NotFound);
        }

        let mut revoked = previous.revoked.clone();
        revoked.push(device);
        let next = Roster {
            epoch: previous.epoch.saturating_add(1),
            devices: previous
                .devices
                .iter()
                .filter(|entry| entry.device_id != device)
                .cloned()
                .collect(),
            revoked,
            claims: Vec::new(),
            prev_hash: Roster::hash(&current),
            signer_id: identity.device_id,
            sig: previous.sig,
        };
        let bytes = sign_roster(&next, &identity.roster_key(), rng)?;

        // Step 2c and DEV-313: the store holds what the revocation owes
        // before it holds the epoch. Thus a run that is not up now, or a
        // crash after the epoch, loses no rotation and no notice.
        let channel = self.peer_channels()?.get(&device).copied();
        self.owe_revocation(device, channel, &bytes, true, rng)?;
        self.put_roster(&bytes, rng)?;

        // DEV-313: the revoked device learns of it once, on the channel
        // that ends when a relay took the notice, thus it can show it
        // (`DEV-181`). The channel takes no record from here on. A device
        // that missed an epoch verifies the notice through the epochs
        // before it (`DEV-150`), thus the kept ones go first.
        if let Some(channel) = channel {
            self.queue_revocation_notice(channel, &bytes, rng)?;
        }

        Ok(bytes)
    }

    /// The kept epochs that lead to the epoch `notice`, in order. Each one
    /// is the parent of the next, and the last one is the parent of the
    /// notice. The head can be above the notice by now, and the device that
    /// the notice revokes takes no epoch above it. Thus the chain ends
    /// below the notice and not at the head.
    fn roster_chain_below(&self, notice: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let notice = Roster::parse(notice)?;
        let mut chain = Vec::new();
        let mut parent = notice.prev_hash;
        let mut epoch = notice.epoch;
        while let Some(below) = epoch.checked_sub(1) {
            if notice.epoch.saturating_sub(below) > ROSTER_CHAIN_KEPT {
                break;
            }

            // The head is the parent of a notice that a crash kept out of
            // the store, and each other parent is a kept epoch.
            let held = match self.kept_epoch(below)? {
                Some(kept) => Some(kept),
                None => self.roster_bytes()?,
            };
            let Some(held) = held.filter(|held| Roster::hash(held) == parent) else {
                break;
            };

            parent = Roster::parse(&held)?.prev_hash;
            chain.push(held);
            epoch = below;
        }

        chain.reverse();

        Ok(chain)
    }

    /// Keeps what the revocation of `device` owes, in one commit. Each
    /// contact gets a new queue (Part 7 §7.7 step 2c). The revoked device
    /// gets the notice on its sync channel (`DEV-313`). A take-over renews
    /// each channel (`DEV-316`), and a renewal makes each queue new, thus
    /// it owes no rotation of a contact. Each rendezvous queue that the
    /// device knew takes a successor in both cases (`DEV-347`).
    pub(super) fn owe_revocation<R: CryptoRng + ?Sized>(
        &mut self,
        device: DeviceId,
        channel: Option<ConversationId>,
        epoch: &[u8],
        rotates: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let owed = if rotates {
            self.rotations_to_owe()?
        } else {
            Vec::new()
        };
        let rendezvous = self.rendezvous_to_owe()?;
        let mut leaving = self.setting(LEAVING_CHANNELS)?.unwrap_or_default();
        let notice_key = [REVOCATION_NOTICE, device.as_slice()].concat();
        let notice = [super::unix_now_seconds().to_be_bytes().as_slice(), epoch].concat();
        let open = self.open_mut()?;
        let owed_row = open.store.row_id(SETTINGS, ROTATION_OWED);
        let rendezvous_row = open.store.row_id(SETTINGS, RENDEZVOUS_OWED);
        let leaving_row = open.store.row_id(SETTINGS, LEAVING_CHANNELS);
        let notice_row = open.store.row_id(SETTINGS, &notice_key);
        let mut batch = open.store.begin();
        if !owed.is_empty() {
            batch.put(SETTINGS, owed_row, None, &owed, rng)?;
        }
        if !rendezvous.is_empty() {
            batch.put(SETTINGS, rendezvous_row, None, &rendezvous, rng)?;
        }
        if let Some(channel) = channel {
            leaving.extend_from_slice(&channel.0);
            leaving.extend_from_slice(&device);
            batch.put(SETTINGS, leaving_row, None, &leaving, rng)?;
            batch.put(SETTINGS, notice_row, None, &notice, rng)?;
        }

        batch.commit()?;

        // The run that is up takes the rotations at its next step, each
        // with a new guard (`NET-357`).
        self.rotation_asked = 0;
        self.rotation_guarded.clear();

        Ok(())
    }

    /// The row of the owed rotations with each contact of this device in
    /// it: the revoked device knew the queue of each one.
    fn rotations_to_owe(&self) -> Result<Vec<u8>, Error> {
        let mut owed = self.setting(ROTATION_OWED)?.unwrap_or_default();
        let peers = self.device_peers()?;
        let store = &self.open_ref()?.store;
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            drop(Zeroizing::new(plain));
            let is_held = owed.as_chunks::<16>().0.contains(&row);
            if !is_held && !peers.contains(&ConversationId(row)) {
                owed.extend_from_slice(&row);
            }
        }

        Ok(owed)
    }

    /// The row of the owed rendezvous rotations with the current queue of
    /// each published entry in it: the snapshot of a link carries each one
    /// (`DEV-287`).
    fn rendezvous_to_owe(&self) -> Result<Vec<u8>, Error> {
        let mut owed = self.setting(RENDEZVOUS_OWED)?.unwrap_or_default();
        for entry in self.published()? {
            if !owed.as_chunks::<32>().0.contains(&entry.queue) {
                owed.extend_from_slice(&entry.queue);
            }
        }

        Ok(owed)
    }

    /// The rendezvous queues that a revocation still owes a successor, for
    /// the upkeep of the directory (`DEV-347`). A queue that no published
    /// entry names as its current queue owes nothing, and it leaves the
    /// row: a rotation of any cause, or the end of the entry, took it.
    pub fn rendezvous_owed<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<[u8; 32]>, Error> {
        let Some(held) = self.setting(RENDEZVOUS_OWED)? else {
            return Ok(Vec::new());
        };

        let current: Vec<[u8; 32]> = self.published()?.iter().map(|entry| entry.queue).collect();
        let owed: Vec<[u8; 32]> = held
            .as_chunks::<32>()
            .0
            .iter()
            .filter(|queue| current.contains(queue))
            .copied()
            .collect();
        let kept = owed.concat();
        if kept.is_empty() {
            self.remove_setting(RENDEZVOUS_OWED)?;
        } else if kept != held {
            self.put_setting(RENDEZVOUS_OWED, &kept, rng)?;
        }

        Ok(owed)
    }

    /// The contacts whose queue a revocation still owes a rotation, for a
    /// run that is up (Part 7 §7.7 step 2c). The identifier of the first
    /// queue names each one. The run asks the node for each one, and the
    /// node keeps the time of the rotation across runs (`NET-180`). The
    /// result is empty inside `ROTATION_ASK_EVERY` of the last one. The
    /// flag of each contact asks for a new guard too (`NET-357`): the first
    /// request of a run after a revocation has it, and a later one has it
    /// not. Thus a request again sets no second guard.
    ///
    /// Step 2b is not here. The ratchet of this build makes a DH step at a
    /// record of the peer alone. Until then the new queue cuts the revoked
    /// device off.
    pub fn rotation_owed(&mut self, now: u64) -> Result<Vec<([u8; 32], bool)>, Error> {
        if self.rotation_asked != 0 && now.saturating_sub(self.rotation_asked) < ROTATION_ASK_EVERY
        {
            return Ok(Vec::new());
        }
        let Some(owed) = self.setting(ROTATION_OWED)? else {
            return Ok(Vec::new());
        };

        // A link snapshot carries the settings of the device that owns the
        // channels. A linked device owns no queue of a contact (`DEV-287`),
        // thus it owes none.
        if !self.owns_channels()? {
            return Ok(Vec::new());
        }

        let mut contacts = Vec::new();
        for conversation in owed.as_chunks::<16>().0 {
            // A contact that left the store owes nothing.
            let conversation = ConversationId(*conversation);
            if let Ok(contact) = self.contact_id_of(conversation) {
                contacts.push((contact, self.rotation_guarded.insert(conversation)));
            }
        }

        if !contacts.is_empty() {
            self.rotation_asked = now.max(1);
        }

        Ok(contacts)
    }

    /// The queue of a contact rotated: a revocation owes it no rotation.
    /// A rotation before the request of this run for the new guard
    /// (`NET-357`) ends nothing: the guard is still owed, and the next
    /// request sets it.
    pub(super) fn rotation_done<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(owed) = self.setting(ROTATION_OWED)? else {
            return Ok(());
        };

        let (entries, _) = owed.as_chunks::<16>();
        if !entries.contains(&conversation.0) || !self.rotation_guarded.remove(&conversation) {
            return Ok(());
        }

        // A contact that left the store owes nothing either.
        let store = &self.open_ref()?.store;
        let mut left = Vec::new();
        for entry in entries {
            if *entry != conversation.0 && store.get(TableId::CONTACT, entry)?.is_some() {
                left.extend_from_slice(entry);
            }
        }

        if left.is_empty() {
            self.remove_setting(ROTATION_OWED)
        } else {
            self.put_setting(ROTATION_OWED, &left, rng)
        }
    }

    /// Whether a revocation still owes a rotation to the queue of a
    /// conversation.
    pub fn owes_rotation(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self
            .setting(ROTATION_OWED)?
            .is_some_and(|owed| owed.as_chunks::<16>().0.contains(&conversation.0)))
    }

    /// The sync channel of each revoked device that waits for its notice,
    /// with the device.
    fn leaving_channels(&self) -> Result<Vec<(ConversationId, DeviceId)>, Error> {
        let Some(held) = self.setting(LEAVING_CHANNELS)? else {
            return Ok(Vec::new());
        };

        Ok(held
            .as_chunks::<LEAVING_ENTRY>()
            .0
            .iter()
            .filter_map(|entry| {
                let (channel, device) = entry.split_at(16);
                Some((
                    ConversationId(channel.try_into().ok()?),
                    device.try_into().ok()?,
                ))
            })
            .collect())
    }

    /// Whether a conversation is the sync channel of a revoked device that
    /// waits for the notice of `DEV-313`. Such a channel sends that notice,
    /// and it takes no record (`DEV-257`).
    pub fn is_leaving_channel(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self
            .leaving_channels()?
            .iter()
            .any(|(channel, _)| *channel == conversation))
    }

    /// Queues the notice of a revocation on the channel of the revoked
    /// device. The record carries the channel as its message, thus the send
    /// path reports whether a relay took it. One notice waits at a time.
    ///
    /// DEV-313: the kept epochs that lead to the notice go before it at
    /// each queue of it. The queue of a channel is RAM, and a lock or a new
    /// start empties it. A notice that goes again with no chain would not
    /// verify at a device that missed an epoch. That device would never
    /// learn of its removal.
    pub(super) fn queue_revocation_notice<R: CryptoRng + ?Sized>(
        &mut self,
        channel: ConversationId,
        epoch: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let message = MsgRef(channel.0);
        if self
            .sync_out
            .iter()
            .any(|send| send.message == Some(message))
        {
            return Ok(());
        }
        for kept in self.roster_chain_below(epoch)? {
            self.queue_roster(channel, &kept, rng)?;
        }

        let body = DeviceSetBody::Control {
            control_type: ControlType::RosterEpoch,
            payload: epoch,
        };
        let mut encoded = vec![0u8; epoch.len().saturating_add(16)];
        let used = body.encode(&mut encoded)?;
        encoded.truncate(used);
        self.queue_sync(channel, &encoded, Some(message), rng)
    }

    /// The send path reports the state of a record. The result is whether
    /// the record is the notice of a revocation. When a relay took it, the
    /// channel of the revoked device ends (Part 7 §7.7 step 2a). When no
    /// relay took it, the next run sends it again.
    pub(super) fn notice_delivery<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        delivery: Delivery,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let channel = ConversationId(message.0);
        let Some((_, device)) = self
            .leaving_channels()?
            .into_iter()
            .find(|(held, _)| *held == channel)
        else {
            return Ok(false);
        };
        if matches!(
            delivery,
            Delivery::Accepted | Delivery::Delivered | Delivery::Read
        ) {
            self.end_leaving_channel(device, channel, rng)?;
        }

        Ok(true)
    }

    /// Ends the sync channel of a revoked device whose notice left, or
    /// whose time passed, with the rows of that notice, in one commit.
    fn end_leaving_channel<R: CryptoRng + ?Sized>(
        &mut self,
        device: DeviceId,
        channel: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut left = Vec::new();
        for (held, other) in self.leaving_channels()? {
            if held != channel {
                left.extend_from_slice(&held.0);
                left.extend_from_slice(&other);
            }
        }

        let notice_key = [REVOCATION_NOTICE, device.as_slice()].concat();
        let open = self.open_mut()?;
        let leaving_row = open.store.row_id(SETTINGS, LEAVING_CHANNELS);
        let notice_row = open.store.row_id(SETTINGS, &notice_key);
        let mut batch = open.store.begin();
        batch.delete(DEVICE_PEERS, channel.0);
        batch.delete(TableId::CONTACT, channel.0);
        batch.put(ENDED_CHANNELS, channel.0, None, &[1], rng)?;
        if left.is_empty() {
            batch.delete(SETTINGS, leaving_row);
        } else {
            batch.put(SETTINGS, leaving_row, None, &left, rng)?;
        }

        batch.delete(SETTINGS, notice_row);

        Ok(batch.commit()?)
    }

    /// Takes a roster epoch that another device of the set signed, when it
    /// follows the epoch held and verifies (`DEV-150` to `DEV-157`). The
    /// sync channel of each device that it revokes ends (`DEV-257`). An
    /// epoch that revokes this device changes nothing here (`DEV-180`). The
    /// result is whether the store took it.
    pub fn apply_roster<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<bool, Error> {
        self.apply_roster_from(None, bytes, rng)
    }

    /// [`Client::apply_roster`] for an epoch that came on the sync channel
    /// of `source`.
    pub(super) fn apply_roster_from<R: CryptoRng + ?Sized>(
        &mut self,
        source: Option<DeviceId>,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<bool, Error> {
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        let current = self.roster_bytes()?.ok_or(Error::NotFound)?;
        let previous = Roster::parse(&current)?;
        let next = Roster::parse(bytes)?;
        let hash = Roster::hash(bytes);
        let signer = |rosters: &[&Roster<'_>]| {
            rosters
                .iter()
                .find_map(|roster| roster.entry(&next.signer_id).map(|entry| entry.label))
                .unwrap_or([0; 32])
        };

        // DEV-182: a peer applied another epoch at an index that this
        // device applied.
        if next.epoch < previous.epoch {
            if self
                .roster_hash_at(next.epoch)?
                .is_some_and(|held| held != hash)
            {
                // DEV-182: the view names the signer of an epoch whose
                // signature verifies. An epoch that does not verify names
                // the device that sent it, thus a peer cannot put a fork on
                // another device.
                if self.earlier_epoch_verifies(&next, &previous)? {
                    let label = signer(&[&next, &previous]);
                    self.put_roster_fork(next.epoch, next.signer_id, label, FORK_PEER, rng)?;
                } else if let Some(source) = source {
                    let label = previous.entry(&source).map_or([0; 32], |entry| entry.label);
                    self.put_roster_fork(next.epoch, source, label, FORK_PEER, rng)?;
                }
            }
            return Ok(false);
        }

        if next.epoch == previous.epoch {
            if hash == Roster::hash(&current) {
                return Ok(false);
            }
            return self.on_rival_roster(identity.device_id, &current, bytes, rng);
        }

        if next.epoch == previous.epoch.saturating_add(1)
            && next.prev_hash != Roster::hash(&current)
        {
            // The peer chains to another epoch at the index of the head. A
            // signer of the head with a valid signature makes it a fork.
            if next.verify_successor(&previous, &next.prev_hash).is_ok() {
                let label = signer(&[&next, &previous]);
                self.put_roster_fork(previous.epoch, next.signer_id, label, FORK_PEER, rng)?;
            }
            return Ok(false);
        }
        next.verify_successor(&previous, &Roster::hash(&current))?;
        let before: Vec<DeviceId> = previous.devices.iter().map(|d| d.device_id).collect();
        if next.revokes(&identity.device_id) {
            self.mark_removed_from_set(rng)?;

            // DEV-317: the epoch stays out of the store, and its claim
            // still ends the ownership of this device.
            self.fold_claims(&before, &next, rng)?;
            return Ok(false);
        }

        let gone: Vec<DeviceId> = next
            .revoked
            .iter()
            .filter(|device| !previous.revoked.contains(device))
            .copied()
            .collect();
        // Step 2c: the device that owns the channels owes each contact and
        // each published entry a new queue, whichever device signed the
        // epoch (DEV-347).
        if !gone.is_empty() && self.owns_channels()? {
            let owed = self.rotations_to_owe()?;
            if !owed.is_empty() {
                self.put_setting(ROTATION_OWED, &owed, rng)?;
            }
            let rendezvous = self.rendezvous_to_owe()?;
            if !rendezvous.is_empty() {
                self.put_setting(RENDEZVOUS_OWED, &rendezvous, rng)?;
            }

            self.rotation_asked = 0;
            self.rotation_guarded.clear();
        }

        self.put_roster(bytes, rng)?;
        self.fold_claims(&before, &next, rng)?;
        for device in gone {
            self.end_sync_channel(device, rng)?;
        }

        Ok(true)
    }

    /// DEV-181: the user learns that a verified epoch of another device
    /// removed this one.
    pub(super) fn mark_removed_from_set<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, REMOVED_FROM_SET);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &[1], rng)?;
        batch.commit()?;
        self.events.push_back(crate::Event::Conversations);

        Ok(())
    }

    /// Whether the signature of an epoch below the head verifies under the
    /// key of its signer. The key is the one in the kept epoch before it
    /// (`DEV-152`), or the one that the head gives that device. A
    /// `DeviceRosterKey` never changes.
    fn earlier_epoch_verifies(&self, epoch: &Roster<'_>, head: &Roster<'_>) -> Result<bool, Error> {
        let kept = match epoch.epoch.checked_sub(1) {
            Some(below) => self.kept_epoch(below)?,
            None => None,
        };
        if let Some(kept) = kept {
            if let Some(entry) = Roster::parse(&kept)?.entry(&epoch.signer_id) {
                return Ok(epoch.verify_signature(entry.mldsa_pk).is_ok());
            }
        }

        Ok(head
            .entry(&epoch.signer_id)
            .is_some_and(|entry| epoch.verify_signature(entry.mldsa_pk).is_ok()))
    }

    /// Whether a verified epoch of the set revoked this device (`DEV-181`).
    pub fn removed_from_set(&self) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, REMOVED_FROM_SET);
        Ok(store.get(SETTINGS, &row)?.is_some())
    }

    /// Ends the sync channel of a device: its row and its contact go, thus
    /// no view shows it, no later run reads its queue, and a record on it
    /// changes nothing (`DEV-255` to `DEV-257`). No `DEL` goes to its queue
    /// (§7.7).
    pub(super) fn end_sync_channel<R: CryptoRng + ?Sized>(
        &mut self,
        device: DeviceId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let channels = self.peer_channels()?;
        let Some(channel) = channels.get(&device).copied() else {
            return Ok(());
        };

        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(DEVICE_PEERS, channel.0);
        batch.delete(TableId::CONTACT, channel.0);
        batch.put(ENDED_CHANNELS, channel.0, None, &[1], rng)?;

        Ok(batch.commit()?)
    }

    /// Whether a revocation ended the channel of a conversation.
    pub fn is_ended_channel(&self, conversation: ConversationId) -> Result<bool, Error> {
        Ok(self
            .open_ref()?
            .store
            .get(ENDED_CHANNELS, &conversation.0)?
            .is_some())
    }

    /// Ends the sync channel of each device that the roster revoked and
    /// that still holds one, at the start of a run: a revocation and the
    /// end of its channel are two commits, and a crash between them leaves
    /// the channel (`DEV-255` to `DEV-257`). The channel of a device whose
    /// notice no relay took yet stays for `REVOCATION_NOTICE_TTL`, and the
    /// notice goes again in this run (`DEV-313`).
    pub fn end_revoked_channels<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(bytes) = self.roster_bytes()? else {
            return Ok(());
        };

        let roster = Roster::parse(&bytes)?;
        let channels = self.peer_channels()?;
        let leaving = self.leaving_channels()?;
        let now = super::unix_now_seconds();
        for device in roster
            .revoked
            .iter()
            .filter(|device| channels.contains_key(*device))
        {
            let Some((channel, _)) = leaving.iter().find(|(_, held)| held == device) else {
                self.end_sync_channel(*device, rng)?;
                continue;
            };

            let notice = self.setting(&[REVOCATION_NOTICE, device.as_slice()].concat())?;
            let at = notice
                .as_deref()
                .and_then(|held| held.get(..8))
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes);
            match (at, notice.as_deref().and_then(|held| held.get(8..))) {
                (Some(at), Some(epoch)) if now.saturating_sub(at) < REVOCATION_NOTICE_TTL => {
                    self.queue_revocation_notice(*channel, epoch, rng)?;
                }
                _ => self.end_leaving_channel(*device, *channel, rng)?,
            }
        }

        // A notice whose epoch a crash kept out of the store names a device
        // that the roster still holds. Its channel is a sync channel as
        // before, and the user removes the device again.
        for (channel, device) in leaving {
            if !roster.revoked.contains(&device) {
                self.forget_notice(device, channel, rng)?;
            }
        }

        Ok(())
    }

    /// Drops the rows of a notice whose revocation did not happen. The
    /// channel stays.
    fn forget_notice<R: CryptoRng + ?Sized>(
        &mut self,
        device: DeviceId,
        channel: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut left = Vec::new();
        for (held, other) in self.leaving_channels()? {
            if held != channel {
                left.extend_from_slice(&held.0);
                left.extend_from_slice(&other);
            }
        }

        self.remove_setting(&[REVOCATION_NOTICE, device.as_slice()].concat())?;
        if left.is_empty() {
            self.remove_setting(LEAVING_CHANNELS)
        } else {
            self.put_setting(LEAVING_CHANNELS, &left, rng)
        }
    }

    /// The devices of the current roster.
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, Error> {
        let own = self.device_identity()?.map(|identity| identity.device_id);
        let Some(bytes) = self.roster_bytes()? else {
            return Ok(Vec::new());
        };

        let roster = Roster::parse(&bytes)?;
        Ok(roster
            .devices
            .iter()
            .map(|entry| DeviceInfo {
                device_id: entry.device_id,
                label: umbra_core::devset::link::label_text(&entry.label),
                is_self: Some(entry.device_id) == own,
                added_epoch: entry.added_epoch,
            })
            .collect())
    }

    /// The queue of each sync invitation that waits for its flight 1
    /// (`DEV-290`). The store holds the list, thus a link that ended with
    /// its run, or under a lock, leaves its invitation to the next run.
    pub fn device_invitations(&self) -> Result<Vec<[u8; 32]>, Error> {
        let held = self.setting(DEVICE_INVITES_SETTING)?.unwrap_or_default();
        Ok(held.as_chunks::<32>().0.to_vec())
    }

    /// A relay made the queue of a sync invitation. The runtime calls this
    /// before the batch that stores the invitation, thus no stored
    /// invitation of a device is outside the list.
    pub fn note_device_invitation<R: CryptoRng + ?Sized>(
        &mut self,
        queue: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut held = self.device_invitations()?;
        if held.contains(queue) {
            return Ok(());
        }

        held.push(*queue);
        self.put_setting(DEVICE_INVITES_SETTING, &held.concat(), rng)
    }

    /// The invitations on `ended` are gone from the node: their handshake
    /// finished, or the node retired them. The list names them no more.
    pub(super) fn forget_device_invitations<R: CryptoRng + ?Sized>(
        &mut self,
        ended: &[[u8; 32]],
        rng: &mut R,
    ) -> Result<(), Error> {
        let held = self.device_invitations()?;
        let kept: Vec<[u8; 32]> = held
            .iter()
            .filter(|queue| !ended.contains(queue))
            .copied()
            .collect();
        if kept.len() == held.len() {
            return Ok(());
        }
        if kept.is_empty() {
            return self.remove_setting(DEVICE_INVITES_SETTING);
        }

        self.put_setting(DEVICE_INVITES_SETTING, &kept.concat(), rng)
    }

    /// The device whose sync channel opens next: the next handshake that
    /// names a device belongs to it.
    pub fn set_pending_peer<R: CryptoRng + ?Sized>(
        &mut self,
        device: DeviceId,
        label: &[u8; LABEL_LEN],
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = [device.as_slice(), label].concat();
        self.put_setting(PENDING_PEER_SETTING, &value, rng)
    }

    /// The device whose sync channel waits for its handshake, when this
    /// device owns the channels: a record from here on waits for it
    /// (`DEV-013`).
    pub(super) fn pending_peer(&self) -> Result<Option<DeviceId>, Error> {
        if !self.owns_channels()? {
            return Ok(None);
        }

        Ok(self
            .setting(PENDING_PEER_SETTING)?
            .and_then(|value| value.get(..16).and_then(|id| id.try_into().ok())))
    }

    /// The link of the pending device ended with no sync channel.
    pub fn drop_pending_peer(&mut self) -> Result<(), Error> {
        self.remove_setting(PENDING_PEER_SETTING)
    }

    /// Whether the store names the device whose sync channel opens next.
    pub fn holds_pending_peer(&self) -> Result<bool, Error> {
        Ok(self
            .setting(PENDING_PEER_SETTING)?
            .is_some_and(|pending| pending.len() == 16 + LABEL_LEN))
    }

    /// Ends a sync channel that opened while no device waited for one
    /// (`DEV-290`): the link that asked for it ended first. The channel
    /// ends as the channel of a revoked device does, and it names no
    /// device of the set.
    pub fn refuse_device_channel<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(DEVICE_PEERS, conversation.0);
        batch.delete(TableId::CONTACT, conversation.0);
        batch.put(ENDED_CHANNELS, conversation.0, None, &[1], rng)?;

        Ok(batch.commit()?)
    }

    /// Marks the conversation of a sync channel that just opened as the
    /// channel of the pending device. No view shows it as a contact.
    pub fn mark_device_peer<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let pending = self.setting(PENDING_PEER_SETTING)?.unwrap_or_default();
        let value = if pending.len() == 16 + LABEL_LEN {
            pending
        } else {
            vec![0; 16 + LABEL_LEN]
        };
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(DEVICE_PEERS, conversation.0, None, &value, rng)?;
        batch.commit()?;
        self.remove_setting(PENDING_PEER_SETTING)?;
        self.remove_setting(SYNC_BUNDLE_SETTING)
    }

    /// Whether a conversation is the sync channel of another device.
    pub fn is_device_peer(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        Ok(store.get(DEVICE_PEERS, &conversation.0)?.is_some())
    }

    /// The conversation of each sync channel.
    pub fn device_peers(&self) -> Result<Vec<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .list(DEVICE_PEERS, None)?
            .into_iter()
            .map(|(row, _): (RowId, _)| ConversationId(row))
            .collect())
    }

    /// The rows that a link snapshot carries beside the backup rows: the
    /// roster that adds the new device, the bundle of the sync channel, and
    /// this device as the peer of that channel (`DEV-286`). The two stores
    /// share `K_store`, thus a row has one identifier in both.
    pub(super) fn link_rows(
        &self,
        roster: &[u8],
        sync_bundle: &[u8],
        sync_floor: u64,
    ) -> Result<Vec<BackupRow>, Error> {
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;

        // The head of this device is the parent of the epoch that adds the
        // new one, thus the new device verifies a rival of it.
        let parent = self
            .roster_bytes()?
            .map(|current| Parent::of(&current)?.encode())
            .transpose()?;
        let epoch = Roster::parse(roster)?.epoch;
        let store = &self.open_ref()?.store;
        let put = |table: TableId, key: &[u8], plain: Vec<u8>| BackupRow::Put {
            table,
            row: store.row_id(table, key),
            owner: None,
            plain: Zeroizing::new(plain),
        };
        let peer = [identity.device_id.as_slice(), &identity.label].concat();

        // DEV-311: the counter at the confirmation; each record after it
        // waits for the new device under DEV-297, and the snapshot holds
        // the state of each one at or below it.
        let floor = [identity.device_id.as_slice(), &sync_floor.to_be_bytes()].concat();
        let mut rows = vec![
            put(SETTINGS, LINK_FLOOR_SETTING, floor),
            put(DEVICE_ROSTER, ROSTER_KEY, roster.to_vec()),
            put(
                ROSTER_HASHES,
                &epoch.to_be_bytes(),
                Roster::hash(roster).to_vec(),
            ),
            put(SETTINGS, SYNC_BUNDLE_SETTING, sync_bundle.to_vec()),
            put(SETTINGS, PENDING_PEER_SETTING, peer),
        ];
        if let Some(parent) = parent {
            rows.push(put(ROSTER_PARENT, PARENT_KEY, parent));
        }

        Ok(rows)
    }

    /// Takes the identity of this device into a store that a link snapshot
    /// just made (`DEV-284`, `DEV-287`). The roster of the snapshot must
    /// name it.
    pub fn apply_link<R: CryptoRng + ?Sized>(
        &mut self,
        identity: &DeviceIdentity,
        rng: &mut R,
    ) -> Result<(), Error> {
        let roster = self.roster_bytes()?.ok_or(Error::Integrity)?;
        let entry_matches = Roster::parse(&roster)?
            .entry(&identity.device_id)
            .is_some_and(|entry| entry.mldsa_pk == EntryKeys::of(identity).roster_pk.as_slice());
        if !entry_matches || self.pending_sync_bundle()?.is_none() {
            return Err(Error::Integrity);
        }

        self.put_device_identity(identity, false, rng)?;

        // DEV-230: with no record of the existing device yet, its absence
        // counts from the link.
        self.note_owner_heard(super::unix_now_seconds(), rng)?;

        // IDN-183 is for a restore: a linked device renews no contact, and
        // DEV-117 holds no deletion of the other devices.
        self.remove_setting(super::own_delete::HOLDS_DELETIONS)?;
        self.remove_setting(super::backup::RESTORE_STALE_SETTING)
    }

    /// The bundle of the sync channel that a linked device accepts at its
    /// first run, until the channel opens.
    pub fn pending_sync_bundle(&self) -> Result<Option<Vec<u8>>, Error> {
        self.setting(SYNC_BUNDLE_SETTING)
    }

    pub(super) fn setting(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, key);
        Ok(store.get(SETTINGS, &row)?)
    }

    pub(super) fn put_setting<R: CryptoRng + ?Sized>(
        &mut self,
        key: &[u8],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, key);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, value, rng)?;
        Ok(batch.commit()?)
    }

    pub(super) fn remove_setting(&mut self, key: &[u8]) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, key);
        let mut batch = open.store.begin();
        batch.delete(SETTINGS, row);
        Ok(batch.commit()?)
    }
}
