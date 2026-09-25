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
