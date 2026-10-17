//! The roster snapshot of a member that a restore left behind the roster
//! (Part 11 §11.9.3). A group that no subscription read for more than
//! `GROUP_RETENTION` shows a gap, and the records of that period, with each
//! roster object in them, are gone. The member then asks an admin with a
//! `KeyRequest` of scope `0x03`, on the group queue and to each contact of
//! the member in the group (`GRP-329`). An admin answers with a
//! `SnapshotNotice` that names a fresh snapshot at its roster epoch
//! (`GRP-330`), and the member takes the members it lacked from it.

use std::collections::VecDeque;

use umbra_core::{
    group::state::Group,
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::{
    app::{
        keys::{KeyRequest, KeyScope},
        AppKind, AppMessage,
    },
    group::control::{ControlType, GroupControl, Role, SnapshotNotice},
};

use super::{groups::Before, Client};

/// A snapshot that an admin owes a member behind the roster (`GRP-330`).
pub struct SnapshotJob {
    /// The group.
    pub conversation: ConversationId,
    /// The roster epoch of the snapshot.
    pub roster_epoch: u32,
    /// The roster epoch of the member that asked, under which the notice
    /// goes.
    pub behind: u32,
    /// The snapshot.
    pub snapshot: Vec<u8>,
}
use crate::{ConversationId, Error};

/// The state of the recovery of each group: [`WANTED`] and the time of the
/// request, or [`NOTICED`], the roster epoch and the descriptor.
const RECOVERY: TableId = TableId(0x4A);
const WANTED: u8 = 1;
const NOTICED: u8 = 2;
/// A member asks again after this period with no answer, in seconds.
const ASK_AGAIN: u64 = 86_400;

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn recovery_row(&self, conversation: ConversationId) -> Result<Option<Vec<u8>>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(RECOVERY, &conversation.0);
        Ok(store.get(RECOVERY, &row)?)
    }

    fn put_recovery<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        value: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(RECOVERY, &conversation.0);
        let mut batch = open.store.begin();
        match value {
            Some(value) => batch.put(RECOVERY, row, Some(conversation.0), value, rng)?,
            None => batch.delete(RECOVERY, row),
        }

        Ok(batch.commit()?)
    }

    /// Asks for the roster snapshot of a group whose records of a period
    /// are gone (`GRP-329`): on the group queue, and to each contact of
    /// this member in the group, since an admin may read neither alone.
    pub(super) fn request_roster_snapshot<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? || !self.is_group(conversation)? {
            return Ok(());
        }

        let now = now_ms / 1_000;
        if let Some(held) = self.recovery_row(conversation)? {
            let asked = held
                .get(1..9)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes);
            if held.first() == Some(&NOTICED)
                || asked.is_some_and(|at| now.saturating_sub(at) < ASK_AGAIN)
            {
                return Ok(());
            }
        }

        let group = self.group_of(conversation)?;

        // WIR-523: scope 0x03 names no member, and the notice goes on the
        // group queue.
        let request = KeyRequest {
            scope: KeyScope::RosterSnapshot,
            id: *group.group_id(),
            epoch: group.roster().epoch_index(),
            index: 0,
        };
        let mut body = [0u8; 64];
        let n = request.encode(&mut body)?;
        let body = body.get(..n).ok_or(Error::Malformed)?.to_vec();
        drop(group);

        // A member that lacks the epoch too posts nothing, and its
        // contacts carry the request.
        let _ = self.post_group_app(conversation, AppKind::KeyRequest, &body, now_ms, rng);
        for contact in self.contacts_in(conversation)? {
            self.send_pairwise_app(contact, AppKind::KeyRequest, &body, now_ms, rng)?;
        }

        let value = [[WANTED].as_slice(), &now.to_be_bytes()].concat();
        self.put_recovery(conversation, Some(&value), rng)
    }

    /// A `KeyRequest` of scope `0x03` for a group of this device. An admin
    /// whose roster is ahead of the one that the request names writes a
    /// snapshot for it (`GRP-330`), inside the rate of the group.
    pub(super) fn on_snapshot_request(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        request: &KeyRequest,
        now: u64,
    ) {
        if request.scope != KeyScope::RosterSnapshot || request.id != *group.group_id() {
            return;
        }

        let is_admin = group
            .roster()
            .member(group.own_index())
            .is_some_and(|member| member.role >= Role::Admin);
        if !is_admin || request.epoch >= group.roster().epoch_index() {
            return;
        }

        let job = (conversation, request.epoch);
        if self.groups.snapshot_jobs.contains(&job) {
            return;
        }

        let rate = self
            .groups
            .key_answers_rate
            .entry((conversation, None))
            .or_default();
        if rate.allow(now) {
            self.groups.snapshot_jobs.push_back(job);
        }
    }

    /// The next snapshot that this admin puts on the chunk path for a
    /// member behind the roster.
    pub fn take_snapshot_job(&mut self) -> Option<SnapshotJob> {
        while let Some((conversation, behind)) = self.groups.snapshot_jobs.pop_front() {
            let Ok(group) = self.group_of(conversation) else {
                continue;
            };
            let Ok(path) = self.authority_path(conversation, &group) else {
                continue;
            };
            if let Ok(snapshot) = group.snapshot(&path) {
                return Some(SnapshotJob {
                    conversation,
                    roster_epoch: group.roster().epoch_index(),
                    behind,
                    snapshot,
                });
            }
        }

        None
    }

    /// The chunk path holds the snapshot, and the notice goes on the group
    /// queue under the roster epoch of the member that asked, which that
    /// member can check (`GRP-330`).
    pub fn post_snapshot_notice<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        roster_epoch: u32,
        behind: u32,
        descriptor: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let group = self.group_of(conversation)?;
        let notice = SnapshotNotice {
            group_id: *group.group_id(),
            roster_epoch,
            descriptor,
        };
        let mut payload = vec![0u8; descriptor.len().saturating_add(64)];
        let n = notice.encode(&mut payload)?;
        payload.truncate(n);
        let control = GroupControl {
            control_type: ControlType::SnapshotNotice,
            payload: &payload,
        };
        let mut body = vec![0u8; payload.len().saturating_add(8)];
        let n = control.encode(&mut body)?;
        body.truncate(n);
        let at = group.roster().active_at(behind).map(|_| behind);
        drop(group);
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::GroupControl,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        self.queue_group_post_at(conversation, None, &app, at, now_ms, rng)
    }

    /// A `SnapshotNotice` of an admin. A member that asked, and whose
    /// roster is behind the notice, fetches the snapshot.
    pub(super) fn on_snapshot_notice<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        group: &Group,
        sender: u16,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let is_admin = group
            .roster()
            .member(sender)
            .is_some_and(|member| member.role >= Role::Admin);
        let Ok(notice) = SnapshotNotice::parse(payload) else {
            return Ok(());
        };

        let wanted = self
            .recovery_row(conversation)?
            .is_some_and(|held| held.first() == Some(&WANTED));
        if !is_admin
            || !wanted
            || notice.group_id != *group.group_id()
            || notice.roster_epoch <= group.roster().epoch_index()
        {
            return Ok(());
        }
        let value = [
            [NOTICED].as_slice(),
            &notice.roster_epoch.to_be_bytes(),
            notice.descriptor,
        ]
        .concat();
        self.put_recovery(conversation, Some(&value), rng)
    }

    /// Each snapshot that this member fetches: the group and the
    /// descriptor.
    pub fn recovery_fetches(&self) -> Result<Vec<(ConversationId, Vec<u8>)>, Error> {
        let mut fetches = Vec::new();
        for conversation in self.group_conversations()? {
            if let Some(value) = self.recovery_row(conversation)? {
                if value.first() == Some(&NOTICED) {
                    if let Some(descriptor) = value.get(5..) {
                        fetches.push((conversation, descriptor.to_vec()));
                    }
                }
            }
        }

        Ok(fetches)
    }

    /// The fetched snapshot: the member takes the roster, each record that
    /// waited for it opens, and the recovery ends. A snapshot that does not
    /// verify ends it too, and the gap asks again later.
    pub fn recovery_fetched<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        snapshot: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.put_recovery(conversation, None, rng)?;
        let mut group = self.group_of(conversation)?;
        let before = Before::of(&group);
        group.recover_roster(snapshot, now_ms / 1_000)?;
        let outcomes: VecDeque<_> = group.retry_held(now_ms / 1_000).into_iter().collect();
        self.take_outcomes(conversation, group, outcomes, before, false, now_ms, rng)?;
        self.events.push_back(crate::Event::Conversations);

        Ok(())
    }

    /// The fetch of a snapshot failed: the gap asks again later.
    pub fn recovery_failed<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.put_recovery(conversation, None, rng)
    }
}
