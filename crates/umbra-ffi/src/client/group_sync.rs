//! The groups of the user on the other devices of the set (Part 7
//! `DEV-298` to `DEV-301`).
//!
//! A link snapshot carries each group that exists at the link. A group that
//! the device that owns the channels makes or joins later reaches each other
//! device as one backup object on the chunk path, whose descriptor goes as
//! an item of mutable state. A re-key after a removal reaches each other
//! device as the new seed and the re-key object, and each device applies it
//! to its own row, thus its own cursors of the group queue stay
//! (`DEV-261`).

use umbra_core::{
    devset::sync::{group_subject, ITEM_GROUP_REKEY, ITEM_GROUP_STATE},
    identity::backup::{BackupObject, BackupRow, KIND_FULL},
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{rand_core::CryptoRng, secret::Secret};
use umbra_wire::descriptor::FileDescriptor;
use zeroize::Zeroizing;

use super::{
    groups::{
        lost_seed_key, previous_seed_key, GROUP, GROUP_GRANTS, GROUP_MEMBER, GROUP_OWNERS,
        GROUP_PRESENCE,
    },
    Client, CONVERSATION,
};
use crate::{ConversationId, Error};

/// The epoch-key records that a device that does not own the channels read
/// before the roster object that calls for them (`DEV-303`), under the
/// group and the epoch. The owner column names the group.
pub(super) const EPOCH_HELD: TableId = TableId(0x2A);
/// The synced records of a group that this device does not hold yet, by
/// their order of arrival: the subject of the group, then the record
/// (`DEV-299`).
const GROUP_RECORDS_HELD: TableId = TableId(0x2B);
/// The groups whose state waits to go to the other devices of the set, by
/// their conversation. A row stays until the descriptor went out, thus an
/// app that ends before the upload sends it at its next run.
const GROUP_STATE_DUE: TableId = TableId(0x2C);

/// The tables whose rows of one group go with its state. The owner column
/// of each row names the group. The queue jobs of a group that a creator
/// asked for stay with the creator, since a linked device writes no group
/// queue (`GRP-340`).
const OWNED_BY_GROUP: [TableId; 4] = [GROUP_MEMBER, GROUP_PRESENCE, GROUP_OWNERS, GROUP_GRANTS];

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Marks a group whose state goes to the other devices of the set, when
    /// this device owns the channels and has peers (`DEV-298`).
    pub(super) fn group_state_due<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? || self.sync_engine()?.is_none() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_STATE_DUE, &conversation.0);
        let mut batch = open.store.begin();
        batch.put(GROUP_STATE_DUE, row, None, &conversation.0, rng)?;
        Ok(batch.commit()?)
    }

    /// The next group whose state goes up, with the backup object of it. A
    /// group whose upload runs is not taken again.
    pub fn take_group_state(&mut self, now: u64) -> Option<(ConversationId, Zeroizing<Vec<u8>>)> {
        let due: Vec<ConversationId> = self
            .open_ref()
            .ok()?
            .store
            .list(GROUP_STATE_DUE, None)
            .ok()?
            .into_iter()
            .filter_map(|(_, plain)| Some(ConversationId(plain.as_slice().try_into().ok()?)))
            .collect();
        for conversation in due {
            if self.groups.state_out.contains(&conversation) {
                continue;
            }
            match self.group_state_object(conversation, now) {
                Ok(object) => {
                    self.groups.state_out.insert(conversation);
                    return Some((conversation, object));
                }
                // A group that left this device since sends nothing.
                Err(_) => {
                    let _ = self.end_group_state_due(conversation);
                }
            }
        }
        None
    }

    fn end_group_state_due(&mut self, conversation: ConversationId) -> Result<(), Error> {
        self.groups.state_out.remove(&conversation);
        let open = self.open_mut()?;
        let row = open.store.row_id(GROUP_STATE_DUE, &conversation.0);
        let mut batch = open.store.begin();
        batch.delete(GROUP_STATE_DUE, row);
        Ok(batch.commit()?)
    }

    /// The state of one group as a backup object: its row, its seeds, its
    /// name, and each row that it owns in [`OWNED_BY_GROUP`].
    fn group_state_object(
        &self,
        conversation: ConversationId,
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        let group_row = Zeroizing::new(store.get(GROUP, &conversation.0)?.ok_or(Error::NotFound)?);
        let group_id: [u8; 32] = group_row
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let mut rows = vec![BackupRow::Put {
            table: GROUP,
            row: conversation.0,
            owner: None,
            plain: group_row,
        }];
        for key in [
            group_id.to_vec(),
            previous_seed_key(&group_id),
            lost_seed_key(&group_id),
        ] {
            let row = store.row_id(TableId::LOCAL_IDENTITY, &key);
            if let Some(plain) = store.get(TableId::LOCAL_IDENTITY, &row)? {
                rows.push(BackupRow::Put {
                    table: TableId::LOCAL_IDENTITY,
                    row,
                    owner: None,
                    plain: Zeroizing::new(plain),
                });
            }
        }
        let meta = store.row_id(CONVERSATION, &conversation.0);
        if let Some(plain) = store.get(CONVERSATION, &meta)? {
            rows.push(BackupRow::Put {
                table: CONVERSATION,
                row: meta,
                owner: None,
                plain: Zeroizing::new(plain),
            });
        }
        for table in OWNED_BY_GROUP {
            for (row, plain) in store.list(table, Some(&conversation.0))? {
                rows.push(BackupRow::Put {
                    table,
                    row,
                    owner: Some(conversation.0),
                    plain: Zeroizing::new(plain),
                });
            }
        }
        let object = BackupObject {
            kind: KIND_FULL,
            written_at: now,
            base_at: 0,
            rows,
        };
        Ok(object.encode()?)
    }

    /// The object of a group is on the chunk path: its descriptor goes to
    /// the other devices under the subject of the group.
    pub fn group_state_uploaded<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        descriptor: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let group_id = *self.group_of(conversation)?.group_id();
        let subject = group_subject(&self.open_ref()?.device_set_key, &group_id);
        self.publish_mutable(ITEM_GROUP_STATE, &subject, descriptor, rng)?;
        self.end_group_state_due(conversation)
    }

    /// A group whose upload failed goes again at the next pump: its row
    /// stays.
    pub fn group_state_failed(&mut self, conversation: ConversationId) {
        self.groups.state_out.remove(&conversation);
    }

    /// Takes the descriptor of the state of a group that the owner of the
    /// channels published. A device that holds the group takes nothing.
    pub(super) fn on_group_state_item(
        &mut self,
        subject: [u8; 32],
        value: &[u8],
    ) -> Result<(), Error> {
        if self.owns_channels()? {
            return Ok(());
        }
        let descriptor = FileDescriptor::parse(value)?;
        self.groups
            .state_in
            .push_back((subject, Box::new(descriptor)));
        Ok(())
    }

    /// The next group state to fetch.
    pub fn take_group_fetch(&mut self) -> Option<([u8; 32], Box<FileDescriptor>)> {
        self.groups.state_in.pop_front()
    }

    /// Writes the state of a group that arrived (`DEV-299`). Each row must
    /// belong to the group that the subject names, and a group that this
    /// device holds keeps its own row.
    pub fn apply_group_state<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        plain: &[u8],
        rng: &mut R,
    ) -> Result<ConversationId, Error> {
        let object = BackupObject::parse(plain)?;
        let group_id: [u8; 32] = object
            .rows
            .iter()
            .find_map(|row| match row {
                BackupRow::Put {
                    table,
                    plain,
                    owner: None,
                    ..
                } if *table == GROUP => plain.get(..32)?.try_into().ok(),
                _ => None,
            })
            .ok_or(Error::Malformed)?;
        let open = self.open_ref()?;
        if group_subject(&open.device_set_key, &group_id) != *subject {
            return Err(Error::Integrity);
        }
        let conversation = self.conversation_of_group(&group_id)?;
        if self.is_group(conversation)? {
            return Ok(conversation);
        }
        let store = &self.open_ref()?.store;
        let allowed = |table: TableId, row: &RowId, owner: Option<&RowId>| -> bool {
            if table == GROUP {
                return *row == conversation.0 && owner.is_none();
            }
            if table == TableId::LOCAL_IDENTITY {
                let seed = store.row_id(TableId::LOCAL_IDENTITY, &group_id);
                let previous = store.row_id(TableId::LOCAL_IDENTITY, &previous_seed_key(&group_id));
                let lost = store.row_id(TableId::LOCAL_IDENTITY, &lost_seed_key(&group_id));
                return (*row == seed || *row == previous || *row == lost) && owner.is_none();
            }
            if table == CONVERSATION {
                return *row == store.row_id(CONVERSATION, &conversation.0) && owner.is_none();
            }
            OWNED_BY_GROUP.contains(&table) && owner == Some(&conversation.0)
        };
        for row in &object.rows {
            match row {
                BackupRow::Put {
                    table, row, owner, ..
                } if allowed(*table, row, owner.as_ref()) => {}
                _ => return Err(Error::Integrity),
            }
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in &object.rows {
            if let BackupRow::Put {
                table,
                row,
                owner,
                plain,
            } = row
            {
                batch.put(*table, *row, *owner, plain, rng)?;
            }
        }
        batch.commit()?;
        self.events.push_back(super::Event::Conversations);
        self.replay_group_records(subject, conversation, rng)?;
        Ok(conversation)
    }

    /// Keeps a synced record of a group that this device does not hold.
    pub(super) fn hold_group_record<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        app: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.owns_channels()? {
            return Ok(());
        }
        let order = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
            });
        let open = self.open_mut()?;
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let row = open.store.row_id(GROUP_RECORDS_HELD, &nonce);
        let value = Zeroizing::new([subject.as_slice(), &order.to_be_bytes(), app].concat());
        let mut batch = open.store.begin();
        batch.put(GROUP_RECORDS_HELD, row, None, &value, rng)?;
        Ok(batch.commit()?)
    }

    /// Applies each held record of a group whose state arrived, in order.
    fn replay_group_records<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut held: Vec<(u64, RowId, Zeroizing<Vec<u8>>)> = Vec::new();
        for (row, plain) in self.open_ref()?.store.list(GROUP_RECORDS_HELD, None)? {
            let plain = Zeroizing::new(plain);
            if plain.get(..32) != Some(subject.as_slice()) {
                continue;
            }
            let order = u64::from_be_bytes(
                plain
                    .get(32..40)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Integrity)?,
            );
            let app = Zeroizing::new(plain.get(40..).ok_or(Error::Integrity)?.to_vec());
            held.push((order, row, app));
        }
        held.sort_by_key(|(order, _, _)| *order);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        for (_, row, app) in held {
            // A record that does not apply ends no replay.
            let _ = self.apply_synced_group(conversation, &app, now_ms, rng);
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            batch.delete(GROUP_RECORDS_HELD, row);
            batch.commit()?;
        }
        Ok(())
    }

    /// Publishes the new seed of a group and its re-key object to the other
    /// devices of the set (`DEV-300`).
    pub(super) fn publish_group_rekey<R: CryptoRng + ?Sized>(
        &mut self,
        group_id: &[u8; 32],
        seed: &Secret<32>,
        object: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let subject = group_subject(&self.open_ref()?.device_set_key, group_id);
        let value = Zeroizing::new([seed.expose().as_slice(), object].concat());
        self.publish_mutable(ITEM_GROUP_REKEY, &subject, &value, rng)
    }

    /// Applies the re-key of the member that the owner of the channels made
    /// (`DEV-301`): the device moves its own row to the new index and the
    /// new seed.
    pub(super) fn on_group_rekey_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: [u8; 32],
        value: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.owns_channels()? {
            return Ok(());
        }
        let Some(conversation) = self.conversation_of_group_subject(&subject)? else {
            return Ok(());
        };
        let seed: [u8; 32] = value
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Malformed)?;
        let object = value.get(32..).ok_or(Error::Malformed)?;
        let mut group = self.group_of(conversation)?;
        let seed = Secret::new(seed);
        // A re-key that this row holds already changes nothing.
        if group.adopt_rekey(object, &seed, now_ms / 1_000).is_err() {
            return Ok(());
        }
        self.store_rekeyed(conversation, &group, &seed, rng)?;
        self.events.push_back(super::Event::Conversations);
        Ok(())
    }

    /// The group whose subject is `subject`, on this device.
    fn conversation_of_group_subject(
        &self,
        subject: &[u8; 32],
    ) -> Result<Option<ConversationId>, Error> {
        for conversation in self.group_conversations()? {
            let group = self.group_of(conversation)?;
            let set_key = &self.open_ref()?.device_set_key;
            if group_subject(set_key, group.group_id()) == *subject {
                return Ok(Some(conversation));
            }
        }
        Ok(None)
    }
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Keeps an epoch-key record of the next epoch that did not install.
    pub(super) fn hold_epoch_key<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        epoch: u32,
        start_slot: u32,
        body: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let key = [conversation.0.as_slice(), &epoch.to_be_bytes()].concat();
        let row = open.store.row_id(EPOCH_HELD, &key);
        let value = Zeroizing::new(
            [
                epoch.to_be_bytes().as_slice(),
                &start_slot.to_be_bytes(),
                body,
            ]
            .concat(),
        );
        let mut batch = open.store.begin();
        batch.put(EPOCH_HELD, row, Some(conversation.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    /// Installs each held epoch-key record of a group that installs now,
    /// and drops each one below the current epoch.
    pub(super) fn retry_epoch_keys<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut held: Vec<(RowId, u32, u32, Zeroizing<Vec<u8>>)> = Vec::new();
        for (row, plain) in self
            .open_ref()?
            .store
            .list(EPOCH_HELD, Some(&conversation.0))?
        {
            let plain = Zeroizing::new(plain);
            let epoch = u32::from_be_bytes(
                plain
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Integrity)?,
            );
            let start_slot = u32::from_be_bytes(
                plain
                    .get(4..8)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Integrity)?,
            );
            let body = Zeroizing::new(plain.get(8..).ok_or(Error::Integrity)?.to_vec());
            held.push((row, epoch, start_slot, body));
        }
        if held.is_empty() {
            return Ok(());
        }
        held.sort_by_key(|(_, epoch, _, _)| *epoch);
        let now = now_ms / 1_000;
        let mut group = self.group_of(conversation)?;
        let before = super::groups::Before::of(&group);
        let mut done = Vec::new();
        let mut outcomes = std::collections::VecDeque::new();
        let mut installed = false;
        for (row, epoch, start_slot, body) in held {
            if epoch <= group.epoch() {
                done.push(row);
                continue;
            }
            if group
                .install_epoch_key(epoch, start_slot, &body, now)
                .is_ok()
            {
                installed = true;
                done.push(row);
                outcomes.extend(group.retry_held(now));
            }
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in done {
            batch.delete(EPOCH_HELD, row);
        }
        batch.commit()?;
        if !installed {
            return Ok(());
        }
        self.take_outcomes(conversation, group, outcomes, before, true, now_ms, rng)?;
        Ok(())
    }
}
