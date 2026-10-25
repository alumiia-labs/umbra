//! The take-over of a device set whose owning device is absent (Part 7
//! §7.7, `DEV-314` to `DEV-318`).
//!
//! A linked device signs the roster epoch that revokes each other device,
//! with one claim of scope `0x03` that names the absent device. From that
//! epoch on, it owns each channel of the set. It renews each contact as a
//! restore does (Part 3 `NET-325`), thus the absent device holds no ratchet
//! and no queue of the new channels.

use umbra_core::{
    devset::{
        claim::{may_claim_absence, Ownership},
        link::sign_roster,
        roster::{ClaimScope, OwnerClaim, Roster},
        DeviceId,
    },
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::{CryptoRng, TryCryptoRng};
use zeroize::Zeroizing;

use super::{
    backup::RESTORE_STALE_SETTING,
    devices::{
        RowWrite, DEVICE_SELF, LINK_FLOOR_SETTING, PENDING_PEER_SETTING, SELF_KEY,
        SYNC_BUNDLE_SETTING,
    },
    sync::SYNC_SENT,
    Client, Event, QUEUE_ID_LEN, SETTINGS,
};
use crate::{ConversationId, Error};

/// The receive time of the last record of the owning device on the sync
/// channel, in seconds (`DEV-230`). The setting stays on this device.
const OWNER_HEARD_SETTING: &[u8] = b"owner-heard";
/// The least time between two writes of that setting, in seconds.
const OWNER_HEARD_STEP: u64 = 60;

/// What the absent device owns (`DEV-235`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TakeOverCount {
    /// The contacts of the set.
    pub contacts: u32,
    /// The groups of the set.
    pub groups: u32,
    /// The contacts whose conversation this device holds with no item of
    /// the channel (`DEV-319`): the device that owned the channels was lost
    /// before that item came, or it ran a version before the item. A
    /// take-over renews none of them.
    pub unreachable: u32,
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The device that owns the channels, as a device that owns none sees
    /// it, with the sync channel to it when that channel opened.
    fn owning_device(&self) -> Result<Option<(DeviceId, Option<ConversationId>)>, Error> {
        let channels = self.peer_channels()?;
        if let Some((device, channel)) = channels.iter().next() {
            return Ok(Some((*device, Some(*channel))));
        }

        Ok(self
            .setting(PENDING_PEER_SETTING)?
            .and_then(|value| value.get(..16).and_then(|id| id.try_into().ok()))
            .map(|device| (device, None)))
    }

    /// A record of the owning device came on the sync channel at `now`
    /// (`DEV-230`).
    pub(super) fn note_owner_heard<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let is_recent = self
            .owner_heard()?
            .is_some_and(|held| now.saturating_sub(held) < OWNER_HEARD_STEP && held <= now);
        if is_recent {
            return Ok(());
        }

        self.put_setting(OWNER_HEARD_SETTING, &now.to_be_bytes(), rng)
    }

    fn owner_heard(&self) -> Result<Option<u64>, Error> {
        Ok(self
            .setting(OWNER_HEARD_SETTING)?
            .and_then(|held| held.as_slice().try_into().ok())
            .map(u64::from_be_bytes))
    }

    /// Whether this device can take the set over at all: it is in a set,
    /// it owns no channel, and no epoch removed it.
    fn is_claimant(&self) -> Result<bool, Error> {
        Ok(self.device_identity()?.is_some()
            && !self.owns_channels()?
            && !self.removed_from_set()?
            && self.owning_device()?.is_some())
    }

    /// The time that the owning device is absent at `now`, in seconds, or
    /// none on a device that takes no set over. A store with no receive
    /// time starts the count here.
    pub fn owner_absent_for<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Option<u64>, Error> {
        if !self.is_claimant()? {
            return Ok(None);
        }
        let Some(heard) = self.owner_heard()? else {
            self.note_owner_heard(now, rng)?;
            return Ok(Some(0));
        };

        Ok(Some(now.saturating_sub(heard)))
    }

    /// Whether the absence of the owning device reached `OWNER_ABSENCE` at
    /// `now` (`DEV-231`).
    pub fn may_take_over<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        Ok(self
            .owner_absent_for(now, rng)?
            .is_some_and(may_claim_absence))
    }

    /// Moves the stored receive time back by `OWNER_ABSENCE`, as a clock
    /// that passed it does. For a test over real sockets alone.
    #[cfg(any(test, feature = "sockets-test"))]
    pub fn age_owner_absence<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let heard = self.owner_heard()?.unwrap_or(now).min(now);
        let aged = heard.saturating_sub(umbra_core::devset::OWNER_ABSENCE);
        self.put_setting(OWNER_HEARD_SETTING, &aged.to_be_bytes(), rng)
    }

    /// Whether this device holds the conversation of a contact and no key
    /// of its channel: the entry of `DEV-294` came, and the item of
    /// `DEV-319` did not. No node restores such a contact.
    pub fn holds_no_channel(&self, conversation: ConversationId) -> Result<bool, Error> {
        self.is_shadow_contact(conversation)
    }

    /// What the absent device owns, for the view before a take-over
    /// (`DEV-235`).
    pub fn take_over_count(&self) -> Result<TakeOverCount, Error> {
        let groups = self.group_conversations()?;
        let mut contacts = 0u32;
        let mut unreachable = 0u32;
        for conversation in self.conversations()? {
            if groups.contains(&conversation) {
                continue;
            }

            contacts = contacts.saturating_add(1);
            if self.is_shadow_contact(conversation)? {
                unreachable = unreachable.saturating_add(1);
            }
        }

        Ok(TakeOverCount {
            contacts,
            groups: u32::try_from(groups.len()).unwrap_or(u32::MAX),
            unreachable,
        })
    }

    /// The subject that stands for each subject of the set. The store of a
    /// device holds one owner for the whole set, thus one row of the
    /// ownership table carries the fold.
    fn set_subject(&self) -> Result<[u8; 32], Error> {
        let key = &self.open_ref()?.device_set_key;
        Ok(OwnerClaim::subject(key, ClaimScope::GroupSender, &[0; 32]))
    }

    /// The owner of the set after the absence claims of `epoch`, when
    /// `owner` held it before and `devices` are the devices of the epoch
    /// before (`DEV-158`, `DEV-233`). v1 folds no claim of another scope.
    fn owner_after(
        &self,
        owner: DeviceId,
        devices: &[DeviceId],
        epoch: &Roster<'_>,
    ) -> Result<DeviceId, Error> {
        let key = &self.open_ref()?.device_set_key;
        let subject = self.set_subject()?;
        let mut table = Ownership::new();
        table.establish(subject, owner);
        for device in devices {
            table.register_absence_subject(
                OwnerClaim::subject(key, ClaimScope::Absence, device),
                *device,
            );
        }

        let mut absence = epoch.clone();
        absence
            .claims
            .retain(|claim| claim.scope == ClaimScope::Absence);
        table.fold_roster(&absence);

        Ok(table.owner(&subject).map_or(owner, |held| held.owner))
    }

    /// Folds the claims of a verified epoch into the ownership of this
    /// device (`DEV-227`, `DEV-317`). A device that owned the channels and
    /// that a claim names absent owns none from here on. It reads no queue
    /// of a contact and sends nothing.
    pub(super) fn fold_claims<R: CryptoRng + ?Sized>(
        &mut self,
        devices: &[DeviceId],
        epoch: &Roster<'_>,
        rng: &mut R,
    ) -> Result<(), Error> {
        if epoch.claims.is_empty() || !self.owns_channels()? {
            return Ok(());
        }
        let Some(identity) = self.device_identity()? else {
            return Ok(());
        };

        let own = identity.device_id;
        if epoch.signer_id == own || self.owner_after(own, devices, epoch)? == own {
            return Ok(());
        }

        self.put_device_identity(&identity, false, rng)?;

        // The records that wait go on no channel of this device.
        self.outgoing.clear();
        self.events.push_back(Event::Conversations);

        Ok(())
    }

    /// Takes the set over at `now` (`DEV-314` to `DEV-316`). The result is
    /// the roster epoch that this device signed. The store holds each step
    /// in the commit of that epoch, and the next run of the network starts
    /// the renewal of each contact.
    pub fn take_over<R: CryptoRng + TryCryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        // DEV-231: no claim before `OWNER_ABSENCE`.
        match self.owner_absent_for(now, rng)? {
            None => return Err(Error::NotFound),
            Some(absent_for) if !may_claim_absence(absent_for) => return Err(Error::Busy),
            Some(_) => {}
        }

        let identity = self.device_identity()?.ok_or(Error::NotFound)?;
        let own = identity.device_id;
        let (absent, channel) = self.owning_device()?.ok_or(Error::NotFound)?;
        let current = self.roster_bytes()?.ok_or(Error::NotFound)?;
        let previous = Roster::parse(&current)?;
        let entry = previous.entry(&own).ok_or(Error::Integrity)?.clone();

        // DEV-314: this device reaches no other linked device (`DEV-308`),
        // and a set has one owner. Thus each other device leaves.
        let before: Vec<DeviceId> = previous.devices.iter().map(|d| d.device_id).collect();
        let mut revoked = previous.revoked.clone();
        revoked.extend(before.iter().filter(|device| **device != own));
        let claim = OwnerClaim {
            scope: ClaimScope::Absence,
            subject: OwnerClaim::subject(
                &self.open_ref()?.device_set_key,
                ClaimScope::Absence,
                &absent,
            ),
            owner: own,
        };
        let next = Roster {
            epoch: previous.epoch.saturating_add(1),
            devices: vec![entry],
            revoked,
            claims: vec![claim],
            prev_hash: Roster::hash(&current),
            signer_id: own,
            sig: previous.sig,
        };
        let bytes = sign_roster(&next, &identity.roster_key(), rng)?;
        let signed = Roster::parse(&bytes)?;
        if self.owner_after(absent, &before, &signed)? != own {
            return Err(Error::Integrity);
        }

        // DEV-316: each contact whose channel this device holds renews it.
        let device_peers = self.device_peers()?;
        let mut stale = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(TableId::CONTACT, None)? {
            let plain = Zeroizing::new(plain);
            let conversation = ConversationId(row);
            if device_peers.contains(&conversation) || self.is_shadow_contact(conversation)? {
                continue;
            }

            stale.extend_from_slice(plain.get(..QUEUE_ID_LEN).ok_or(Error::Integrity)?);
        }

        let mut writes = self.new_recovery_code_writes(rng)?;
        let store = &self.open_ref()?.store;
        let mut owner_row = Zeroizing::new(vec![1u8]);
        owner_row.extend_from_slice(&identity.encode());
        writes.push(RowWrite::Put(
            DEVICE_SELF,
            store.row_id(DEVICE_SELF, SELF_KEY),
            owner_row,
        ));
        let stale_row = store.row_id(SETTINGS, RESTORE_STALE_SETTING);
        writes.push(if stale.is_empty() {
            RowWrite::Delete(SETTINGS, stale_row)
        } else {
            RowWrite::Put(SETTINGS, stale_row, Zeroizing::new(stale))
        });

        // The state that named the absent device as the owner goes: the
        // link that did not end, the count of its absence, the rotations
        // that its snapshot carried, and each record that waited for it.
        for key in [
            PENDING_PEER_SETTING,
            SYNC_BUNDLE_SETTING,
            LINK_FLOOR_SETTING,
            OWNER_HEARD_SETTING,
            super::devices::ROTATION_OWED,
        ] {
            writes.push(RowWrite::Delete(SETTINGS, store.row_id(SETTINGS, key)));
        }
        for (row, plain) in store.list(SYNC_SENT, None)? {
            drop(Zeroizing::new(plain));
            writes.push(RowWrite::Delete(SYNC_SENT, row));
        }

        // DEV-313: the store holds the notice before it holds the epoch.
        self.owe_revocation(absent, channel, &bytes, false, rng)?;
        self.put_roster_with(&bytes, writes, rng)?;
        for send in core::mem::take(&mut self.sync_out) {
            drop(Zeroizing::new(send.app));
        }

        self.synced_out.clear();
        if let Some(channel) = channel {
            self.queue_revocation_notice(channel, &bytes, rng)?;
        }

        // IDN-109: each handle of the set looks for its current key once.
        self.mark_resync(rng)?;

        // Part 7 §7.7 step 2e: the absent device holds the keys of each
        // group. A group that waits takes its re-key at a later try, and
        // it does not undo the take-over.
        let _ = self.rekey_groups(now.saturating_mul(1_000), rng);
        self.events.push_back(Event::Conversations);

        Ok(bytes)
    }
}
