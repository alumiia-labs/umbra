//! The device set of Part 7 in the store of one device: its own device
//! identity, the current roster, and the sync channels to the other devices
//! of the set (`DEV-286`).
//!
//! A linked device owns no pairwise ratchet and no group sender at the link
//! (`DEV-287`), thus its runtime reaches no queue of a contact: each queue
//! has one reader, and that reader is the device that owns the channel.

use umbra_core::{
    devset::{
        link::{sign_roster, DeviceIdentity, EntryKeys, LinkHello, LABEL_LEN},
        roster::{Roster, SyncScope},
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
use zeroize::Zeroizing;

use super::{Client, SETTINGS};
use crate::{ConversationId, Error};

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

const SELF_KEY: &[u8] = b"self";
const ROSTER_KEY: &[u8] = b"roster";
/// The device whose sync channel waits for its handshake, and the bundle of
/// that channel at a linked device.
pub(super) const PENDING_PEER_SETTING: &[u8] = b"device-pending-peer";
pub(super) const SYNC_BUNDLE_SETTING: &[u8] = b"device-sync-bundle";

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

    fn put_device_identity<R: CryptoRng + ?Sized>(
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

    fn put_roster<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(DEVICE_ROSTER, ROSTER_KEY);
        let mut batch = open.store.begin();
        batch.put(DEVICE_ROSTER, row, None, bytes, rng)?;
        Ok(batch.commit()?)
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
                let end = held.label.iter().position(|b| *b == 0).unwrap_or(held.label.len());
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

    /// Keeps a device set that [`Client::new_device_set`] made.
    pub(super) fn keep_device_set<R: CryptoRng + ?Sized>(
        &mut self,
        identity: &DeviceIdentity,
        roster: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        self.put_device_identity(identity, true, rng)?;
        self.put_roster(roster, rng)
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
        self.put_roster(&bytes, rng)?;
        self.end_sync_channel(device, rng)?;
        Ok(bytes)
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
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        let current = self.roster_bytes()?.ok_or(Error::NotFound)?;
        let previous = Roster::parse(&current)?;
        let next = Roster::parse(bytes)?;
        if next.epoch <= previous.epoch {
            return Ok(false);
        }
        next.verify_successor(&previous, &Roster::hash(&current))?;
        if next.revokes(&identity.device_id) {
            return Ok(false);
        }
        let gone: Vec<DeviceId> = next
            .revoked
            .iter()
            .filter(|device| !previous.revoked.contains(device))
            .copied()
            .collect();
        self.put_roster(bytes, rng)?;
        for device in gone {
            self.end_sync_channel(device, rng)?;
        }
        Ok(true)
    }

    /// Ends the sync channel of a device: its row and its contact go, thus
    /// no view shows it, no later run reads its queue, and a record on it
    /// changes nothing (`DEV-255` to `DEV-257`). No `DEL` goes to its queue
    /// (§7.7).
    fn end_sync_channel<R: CryptoRng + ?Sized>(
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
    ) -> Result<Vec<BackupRow>, Error> {
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        let store = &self.open_ref()?.store;
        let put = |table: TableId, key: &[u8], plain: Vec<u8>| BackupRow::Put {
            table,
            row: store.row_id(table, key),
            owner: None,
            plain: Zeroizing::new(plain),
        };
        let peer = [identity.device_id.as_slice(), &identity.label].concat();
        Ok(vec![
            put(DEVICE_ROSTER, ROSTER_KEY, roster.to_vec()),
            put(SETTINGS, SYNC_BUNDLE_SETTING, sync_bundle.to_vec()),
            put(SETTINGS, PENDING_PEER_SETTING, peer),
        ])
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
        // IDN-183 is for a restore: a linked device renews no contact.
        self.remove_setting(super::backup::RESTORE_STALE_SETTING)
    }

    /// The bundle of the sync channel that a linked device accepts at its
    /// first run, until the channel opens.
    pub fn pending_sync_bundle(&self) -> Result<Option<Vec<u8>>, Error> {
        self.setting(SYNC_BUNDLE_SETTING)
    }

    fn setting(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, key);
        Ok(store.get(SETTINGS, &row)?)
    }

    fn put_setting<R: CryptoRng + ?Sized>(
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

    fn remove_setting(&mut self, key: &[u8]) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, key);
        let mut batch = open.store.begin();
        batch.delete(SETTINGS, row);
        Ok(batch.commit()?)
    }
}
