//! Two roster epochs at one index (Part 7 §7.3.1, §7.7). The store keeps
//! the hash of each epoch that it applied (`DEV-228`) and the part of the
//! parent of the head that verifies a rival of the head (`DEV-229`). A rival
//! from the signer of the head is a fork that the view shows and names, and
//! the device selects neither (`DEV-170`, `DEV-171`). A rival from another
//! signer takes the order of `DEV-177`, and a fork shows when the two
//! `revoked` lists differ (`DEV-178`). A peer that applied another epoch at
//! an index that this device applied is a fork too (`DEV-182`).
//!
//! A limit of this client: a channel that the losing epoch ended stays
//! ended, since the sync state of that device left the store with it.

use umbra_core::{
    devset::{
        link::{label_text, sign_roster},
        roster::{resolve, Competing, Parent, Roster},
        DeviceId,
    },
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;

use super::{Client, Event};
use crate::Error;

/// The SHA3-256 of each roster epoch that this device applied, by its
/// index (`DEV-228`).
pub(super) const ROSTER_HASHES: TableId = TableId(0x45);
/// The [`Parent`] of the head, in one row.
pub(super) const ROSTER_PARENT: TableId = TableId(0x46);
/// Each fork that the view shows, by its index, its signer and its kind.
const ROSTER_FORKS: TableId = TableId(0x47);

pub(super) const PARENT_KEY: &[u8] = b"parent";

/// One signer made two epochs at one index (`DEV-170`).
pub const FORK_ONE_SIGNER: u8 = 1;
/// Two signers made two epochs whose `revoked` lists differ (`DEV-178`).
pub const FORK_REVOKED: u8 = 2;
/// A peer applied another epoch at an index that this device applied
/// (`DEV-182`).
pub const FORK_PEER: u8 = 3;

const FORK_LEN: usize = 8 + 16 + 1 + 1 + 32;

/// A fork of the roster, as the view shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterFork {
    /// The row, for the dismissal.
    pub id: [u8; 16],
    /// The index of the two epochs.
    pub epoch: u64,
    /// The device that signed the other epoch.
    pub device: DeviceId,
    /// The label of that device, or empty when no epoch names it.
    pub label: String,
    /// [`FORK_ONE_SIGNER`], [`FORK_REVOKED`] or [`FORK_PEER`].
    pub kind: u8,
}

/// The label of `device` from the first of `rosters` that names it.
fn label_of(device: &DeviceId, rosters: &[&Roster<'_>]) -> [u8; 32] {
    rosters
        .iter()
        .find_map(|roster| roster.entry(device).map(|entry| entry.label))
        .unwrap_or([0; 32])
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The hash of the epoch that this device applied at `epoch`.
    pub(super) fn roster_hash_at(&self, epoch: u64) -> Result<Option<[u8; 32]>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(ROSTER_HASHES, &epoch.to_be_bytes());
        Ok(store
            .get(ROSTER_HASHES, &row)?
            .and_then(|hash| hash.as_slice().try_into().ok()))
    }

    fn roster_parent(&self) -> Result<Option<Parent>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(ROSTER_PARENT, PARENT_KEY);
        store
            .get(ROSTER_PARENT, &row)?
            .map(|bytes| Ok(Parent::parse(&bytes)?))
            .transpose()
    }

    /// Keeps a fork for the view, once for each index, signer and kind.
    pub(super) fn put_roster_fork<R: CryptoRng + ?Sized>(
        &mut self,
        epoch: u64,
        device: DeviceId,
        label: [u8; 32],
        kind: u8,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let key = [epoch.to_be_bytes().as_slice(), &device, &[kind]].concat();
        let row = open.store.row_id(ROSTER_FORKS, &key);
        if open.store.get(ROSTER_FORKS, &row)?.is_some() {
            return Ok(());
        }
        let value = [epoch.to_be_bytes().as_slice(), &device, &[kind, 0], &label].concat();
        let mut batch = open.store.begin();
        batch.put(ROSTER_FORKS, row, None, &value, rng)?;
        batch.commit()?;
        self.events.push_back(Event::Conversations);
        Ok(())
    }

    /// Each fork that the user did not dismiss.
    pub fn roster_forks(&self) -> Result<Vec<RosterFork>, Error> {
        let mut out = Vec::new();
        for (id, value) in self.open_ref()?.store.list(ROSTER_FORKS, None)? {
            if value.len() != FORK_LEN || value.get(25) != Some(&0) {
                continue;
            }
            let epoch = value
                .get(..8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(Error::Integrity)?;
            let device: DeviceId = value
                .get(8..24)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            let label: [u8; 32] = value
                .get(26..)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Integrity)?;
            out.push(RosterFork {
                id,
                epoch,
                device,
                label: label_text(&label),
                kind: value.get(24).copied().unwrap_or(0),
            });
        }
        out.sort_by_key(|fork| fork.epoch);
        Ok(out)
    }

    /// The user saw a fork. The row stays, thus the same fork does not
    /// show again at the next publish of a peer.
    pub fn dismiss_roster_fork<R: CryptoRng + ?Sized>(
        &mut self,
        id: &[u8; 16],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut value = open.store.get(ROSTER_FORKS, id)?.ok_or(Error::NotFound)?;
        if let Some(flag) = value.get_mut(25) {
            *flag = 1;
        }
        let mut batch = open.store.begin();
        batch.put(ROSTER_FORKS, *id, None, &value, rng)?;
        Ok(batch.commit()?)
    }

    /// An epoch at the index of the head that is not the head. The result
    /// is whether the store took it in the place of the head.
    pub(super) fn on_rival_roster<R: CryptoRng + ?Sized>(
        &mut self,
        own: DeviceId,
        current: &[u8],
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<bool, Error> {
        let head = Roster::parse(current)?;
        let rival = Roster::parse(bytes)?;
        // A device with no parent, as a new one, verifies no rival.
        let Some(parent) = self.roster_parent()? else {
            return Ok(false);
        };
        if rival.verify_rival(&parent).is_err() {
            return Ok(false);
        }
        // DEV-180, DEV-181: this device does not apply a verified rival
        // that revokes it, and the user learns of it as on the successor
        // path.
        if rival.revokes(&own) {
            self.mark_removed_from_set(rng)?;
            // DEV-317: a rival that takes the set over ends the ownership
            // of this device as a successor does.
            let before: Vec<DeviceId> = parent.signers.iter().map(|(id, _)| *id).collect();
            self.fold_claims(&before, &rival, rng)?;
            return Ok(false);
        }
        let label = label_of(&rival.signer_id, &[&rival, &head]);
        let (index, fork) = match resolve(&head, &rival)? {
            Competing::Fork => {
                self.put_roster_fork(rival.epoch, rival.signer_id, label, FORK_ONE_SIGNER, rng)?;
                return Ok(false);
            }
            Competing::Select { index, fork } => (index, fork),
        };
        if fork {
            self.put_roster_fork(rival.epoch, rival.signer_id, label, FORK_REVOKED, rng)?;
        }
        if index == 0 {
            return Ok(false);
        }
        let gone: Vec<DeviceId> = rival
            .revoked
            .iter()
            .filter(|device| !head.revoked.contains(device))
            .copied()
            .collect();
        self.put_roster(bytes, rng)?;
        for device in gone {
            self.end_sync_channel(device, rng)?;
        }
        // DEV-179: the changes of the epoch that lost go again against
        // the epoch that won.
        if head.signer_id == own {
            self.sign_again(&head, &parent, rng)?;
        }
        Ok(true)
    }

    /// Signs the next epoch over the head with the devices that `lost`
    /// added and the ones that it revoked, when the head holds neither.
    fn sign_again<R: CryptoRng + ?Sized>(
        &mut self,
        lost: &Roster<'_>,
        parent: &Parent,
        rng: &mut R,
    ) -> Result<(), Error> {
        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        let current = self.roster_bytes()?.ok_or(Error::NotFound)?;
        let base = Roster::parse(&current)?;
        let in_parent = |device: &DeviceId| parent.signers.iter().any(|(id, _)| id == device);
        let epoch = base.epoch.saturating_add(1);
        let added: Vec<_> = lost
            .devices
            .iter()
            .filter(|entry| {
                !in_parent(&entry.device_id)
                    && base.entry(&entry.device_id).is_none()
                    && !base.revoked.contains(&entry.device_id)
            })
            .cloned()
            .map(|mut entry| {
                entry.added_epoch = epoch;
                entry
            })
            .collect();
        let removed: Vec<DeviceId> = lost
            .revoked
            .iter()
            .filter(|device| !parent.revoked.contains(device) && !base.revoked.contains(device))
            .copied()
            .collect();
        if added.is_empty() && removed.is_empty() {
            return Ok(());
        }
        let mut devices: Vec<_> = base
            .devices
            .iter()
            .filter(|entry| !removed.contains(&entry.device_id))
            .cloned()
            .collect();
        devices.extend(added);
        if devices.len() > umbra_core::devset::MAX_DEVICES {
            return Err(Error::TooLong);
        }
        let mut revoked = base.revoked.clone();
        revoked.extend(removed.iter().copied());
        let next = Roster {
            epoch,
            devices,
            revoked,
            claims: Vec::new(),
            prev_hash: Roster::hash(&current),
            signer_id: identity.device_id,
            sig: base.sig,
        };
        let bytes = sign_roster(&next, &identity.roster_key(), rng)?;
        self.put_roster(&bytes, rng)?;
        for device in removed {
            self.end_sync_channel(device, rng)?;
        }
        self.publish_roster(rng)
    }
}
