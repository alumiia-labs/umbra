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
    group::state::Group,
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
/// The epoch-key records that one group holds while each waits.
const EPOCH_HELD_MAX: usize = 8;
/// The re-key items of `DEV-301` that did not apply yet, under the subject
/// of the group: the time of arrival in seconds, the subject, then the
/// item. The group
/// can come later on the chunk path, and the roster epoch before the
/// re-key on the sync channel.
const REKEY_HELD: TableId = TableId(0x4E);
/// A held re-key item that applies in no week applies never.
const REKEY_HOLD_MAX: u64 = 7 * 86_400;
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
    pub(super) fn group_state_object(
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
    /// belong to the group that the subject names. A group that this device
    /// holds keeps its own row, with its own cursors (`DEV-261`). The state
    /// of a new admission replaces a row whose membership ended, or that
    /// names an earlier index of the member (`GRP-414`, `GRP-421`). The
    /// device that owns the channels joined the group again, and the row
    /// here opens nothing that the group sends now.
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
        let replaces = self.is_group(conversation)?;
        if replaces && !self.state_replaces(conversation, &group_id, &object)? {
            return Ok(conversation);
        }

        // The rows of the membership before leave with it. The read mark
        // and the name of the conversation are of this device, and they
        // stay.
        let stale = if replaces {
            self.forget_group_work(conversation);
            let store = &self.open_ref()?.store;
            let mut rows = self.membership_rows(conversation)?;
            for key in [previous_seed_key(&group_id), lost_seed_key(&group_id)] {
                rows.push((
                    TableId::LOCAL_IDENTITY,
                    store.row_id(TableId::LOCAL_IDENTITY, &key),
                ));
            }

            rows
        } else {
            Vec::new()
        };
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
        for (table, row) in stale {
            batch.delete(table, row);
        }
        for row in &object.rows {
            if let BackupRow::Put {
                table,
                row,
                owner,
                plain,
            } = row
            {
                if replaces && *table == CONVERSATION {
                    continue;
                }

                batch.put(*table, *row, *owner, plain, rng)?;
            }
        }

        batch.commit()?;
        self.events.push_back(super::Event::Conversations);
        self.replay_group_records(subject, conversation, rng)?;

        // DEV-301: a re-key item that came before the group applies now.
        self.retry_rekey_items(super::unix_now_seconds().saturating_mul(1_000), rng)?;

        Ok(conversation)
    }

    /// Whether the state of a group that arrived takes the place of the row
    /// that this device holds. The state must hold a member of an open
    /// group. It replaces a row whose own index left the roster, and a row
    /// that names a lower index. An admin gives each admission and each
    /// re-key a higher index (`GRP-305`, `GRP-306`). Thus the state of an
    /// earlier admission that arrives late replaces nothing.
    fn state_replaces(
        &self,
        conversation: ConversationId,
        group_id: &[u8; 32],
        object: &BackupObject,
    ) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let find = |table: TableId, at: RowId| {
            object.rows.iter().find_map(|row| match row {
                BackupRow::Put {
                    table: held,
                    row,
                    plain,
                    ..
                } if *held == table && *row == at => Some(plain),
                _ => None,
            })
        };
        let seed_of = |key: &[u8]| -> Option<Secret<32>> {
            let plain = find(
                TableId::LOCAL_IDENTITY,
                store.row_id(TableId::LOCAL_IDENTITY, key),
            )?;
            Some(Secret::new(plain.as_slice().try_into().ok()?))
        };
        let (Some(row), Some(seed)) = (find(GROUP, conversation.0), seed_of(group_id)) else {
            return Ok(false);
        };

        // The byte after the identifier is the state of the group at the
        // device that wrote the row, and 0 is an open group.
        let Some((&[0], stored)) = row.get(32..).and_then(|rest| rest.split_at_checked(1)) else {
            return Ok(false);
        };

        let previous = seed_of(&previous_seed_key(group_id));
        let Ok(incoming) = Group::restore_with_previous(stored, &seed, previous.as_ref()) else {
            return Ok(false);
        };
        if incoming.own_role().is_none() {
            return Ok(false);
        }

        let held = self.group_of(conversation)?;

        Ok(held.own_role().is_none() || incoming.own_index() > held.own_index())
    }

    /// Keeps a synced record of a group that this device does not hold.
    pub(super) fn hold_group_record<R: CryptoRng + ?Sized>(
        &mut self,
        subject: &[u8; 32],
        app: &[u8],
        expires_in: u32,
        now: u64,
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

        // DEV-244: a timed record waits with its deadline, thus the wait
        // does not lengthen its period.
        let at = if expires_in > 0 {
            umbra_core::devset::edits::Deadline::from_sync(now, expires_in).at
        } else {
            0
        };
        let value = Zeroizing::new(
            [
                subject.as_slice(),
                &order.to_be_bytes(),
                &at.to_be_bytes(),
                app,
            ]
            .concat(),
        );
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
        let mut held: Vec<(u64, RowId, u64, Zeroizing<Vec<u8>>)> = Vec::new();
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
            let at = u64::from_be_bytes(
                plain
                    .get(40..48)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Integrity)?,
            );
            let app = Zeroizing::new(plain.get(48..).ok_or(Error::Integrity)?.to_vec());
            held.push((order, row, at, app));
        }

        held.sort_by_key(|(order, _, _, _)| *order);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        for (_, row, at, app) in held {
            // A record that does not apply ends no replay, and a timed one
            // whose period ended goes (DEV-210).
            let expires_in = u32::try_from(at.saturating_sub(now_ms / 1_000)).unwrap_or(u32::MAX);
            if at == 0 || expires_in > 0 {
                let _ = self.apply_synced_group(conversation, &app, expires_in, now_ms, rng);
            }

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
        self.take_rekey_item(subject, value, now_ms, now_ms / 1_000, rng)
            .map(|_| ())
    }

    /// Applies a re-key item that arrived at `since` seconds, or holds it
    /// under that time. The answer says whether the item waits.
    fn take_rekey_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: [u8; 32],
        value: &[u8],
        now_ms: u64,
        since: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        if self.owns_channels()? {
            return Ok(false);
        }

        // DEV-301: a group that this device does not hold yet takes the
        // item when it comes.
        let Some(conversation) = self.conversation_of_group_subject(&subject)? else {
            self.hold_rekey_item(subject, value, since, rng)?;
            return Ok(true);
        };

        let seed: [u8; 32] = value
            .get(..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Malformed)?;
        let object = value.get(32..).ok_or(Error::Malformed)?;
        let mut group = self.group_of(conversation)?;
        let seed = Secret::new(seed);
        match group.adopt_rekey(object, &seed, now_ms / 1_000) {
            Ok(_) => {}
            // A re-key that this row holds already changes nothing.
            Err(umbra_core::Error::Stale) => return Ok(false),
            // A roster that does not reach the epoch before the re-key
            // takes the item after the next roster object.
            Err(_) => {
                self.hold_rekey_item(subject, value, since, rng)?;
                return Ok(true);
            }
        }

        self.store_rekeyed(conversation, &group, object, &seed, rng)?;

        // DEV-303: an epoch key of the new index that came on the group
        // queue before the seed waits, and it installs now.
        self.retry_epoch_keys(conversation, now_ms, rng)?;
        self.events.push_back(super::Event::Conversations);

        Ok(false)
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
    /// Holds a re-key item under the time of its first arrival, thus a
    /// retry that holds it again moves no clock of `REKEY_HOLD_MAX`.
    fn hold_rekey_item<R: CryptoRng + ?Sized>(
        &mut self,
        subject: [u8; 32],
        value: &[u8],
        since: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(REKEY_HELD, &subject);
        let held = Zeroizing::new([since.to_be_bytes().as_slice(), &subject, value].concat());
        let mut batch = open.store.begin();
        batch.put(REKEY_HELD, row, None, &held, rng)?;

        Ok(batch.commit()?)
    }

    /// Applies each held re-key item again (`DEV-301`), after a roster
    /// object or a group state. An item that still does not apply waits
    /// again, and one older than `REKEY_HOLD_MAX` goes.
    pub(super) fn retry_rekey_items<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let held = self.open_ref()?.store.list(REKEY_HELD, None)?;
        if held.is_empty() {
            return Ok(());
        }

        let now = now_ms / 1_000;
        let mut done = Vec::new();
        for (row, plain) in held {
            let plain = Zeroizing::new(plain);
            let at = plain
                .get(..8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes);
            let subject = plain
                .get(8..40)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
            let (Some(at), Some(subject), Some(item)) = (at, subject, plain.get(40..)) else {
                done.push(row);
                continue;
            };
            if now.saturating_sub(at) > REKEY_HOLD_MAX {
                done.push(row);
                continue;
            }

            // An item that applied goes; one that waits again kept its row
            // and its time; a fault keeps the row for the next try, and it
            // stops no other item.
            if let Ok(false) = self.take_rekey_item(subject, item, now_ms, at, rng) {
                done.push(row);
            }
        }

        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in done {
            batch.delete(REKEY_HELD, row);
        }

        Ok(batch.commit()?)
    }

    /// Keeps an epoch-key record of the next epoch that did not install.
    /// Each record keeps a row of its own, thus a record of a rival rotator
    /// or a key supply for another member takes no place of the one that
    /// holds this device's slot (`DEV-303`, `GRP-273`). A group holds at
    /// most `EPOCH_HELD_MAX` of them.
    pub(super) fn hold_epoch_key<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        epoch: u32,
        start_slot: u32,
        body: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        if open.store.list(EPOCH_HELD, Some(&conversation.0))?.len() >= EPOCH_HELD_MAX {
            return Ok(());
        }

        let digest = umbra_crypto::hash::sha3_256(&[body]);
        let key = [conversation.0.as_slice(), &epoch.to_be_bytes(), &digest].concat();
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
            // A record of the epoch that installed may be the rival of a
            // lower rotator, which takes the place of the one that
            // installed (GRP-273); an older one goes.
            if epoch < group.epoch() {
                done.push(row);
                continue;
            }

            if epoch == group.epoch() {
                if group
                    .install_epoch_key(epoch, start_slot, &body, now)
                    .is_ok()
                {
                    installed = true;
                }
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
