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
    group::control::{ControlType, GroupControl, Role, RosterSnapshot, SnapshotNotice},
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

/// The state of the recovery of each group: [`WANTED`], the time of the
/// last request and the time of the first, or [`NOTICED_SINCE`], the time
/// of the first request, the roster epoch and the descriptor. A row of an
/// earlier build can be [`NOTICED`], with no time.
const RECOVERY: TableId = TableId(0x4A);
const WANTED: u8 = 1;
const NOTICED: u8 = 2;
const NOTICED_SINCE: u8 = 3;
/// A member asks again after this period with no answer, in seconds
/// (`GRP-433`).
const ASK_AGAIN: u64 = 86_400;
/// A recovery that no snapshot ended in this period from its first request
/// ends, in seconds. A later gap starts a new one (`GRP-433`).
const ASK_FOR: u64 = umbra_queue::params::GROUP_RETENTION;

/// The row of a recovery that waits for a notice.
fn wanted_row(asked: u64, first: u64) -> Vec<u8> {
    [
        [WANTED].as_slice(),
        &asked.to_be_bytes(),
        &first.to_be_bytes(),
    ]
    .concat()
}

/// The time of the last request and the time of the first request of a
/// row that waits for a notice. A row of an earlier build holds one time,
/// which is both.
fn wanted_times(row: &[u8]) -> Option<(u64, u64)> {
    if row.first() != Some(&WANTED) {
        return None;
    }

    let at = |from: usize| -> Option<u64> {
        let bytes = row.get(from..from.checked_add(8)?)?;
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    };
    let asked = at(1)?;

    Some((asked, at(9).unwrap_or(asked)))
}

/// The time of the first request of a recovery, or none for a row of an
/// earlier build that holds a notice.
fn first_asked(row: &[u8]) -> Option<u64> {
    match row.first() {
        Some(&WANTED) => wanted_times(row).map(|(_, first)| first),
        Some(&NOTICED_SINCE) => Some(u64::from_be_bytes(row.get(1..9)?.try_into().ok()?)),
        _ => None,
    }
}

/// The descriptor of a row that holds a notice.
fn noticed_descriptor(row: &[u8]) -> Option<&[u8]> {
    match row.first() {
        Some(&NOTICED) => row.get(5..),
        Some(&NOTICED_SINCE) => row.get(13..),
        _ => None,
    }
}

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
            let asked = wanted_times(&held).map(|(asked, _)| asked);
            if noticed_descriptor(&held).is_some()
                || asked.is_some_and(|at| now.saturating_sub(at) < ASK_AGAIN)
            {
                return Ok(());
            }
        }

        self.send_snapshot_request(conversation, now, now_ms, rng)
    }

    /// Asks again for the snapshot of a group whose last request took no
    /// snapshot in `ASK_AGAIN`, and ends a recovery that took none in
    /// `ASK_FOR` (`GRP-433`). A fetch that failed asks again in the same
    /// way.
    pub(super) fn ask_roster_again<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !self.owns_channels()? {
            return Ok(());
        }

        let Some((asked, first)) = self
            .recovery_row(conversation)?
            .as_deref()
            .and_then(wanted_times)
        else {
            return Ok(());
        };

        let now = now_ms / 1_000;
        if now.saturating_sub(first) >= ASK_FOR {
            return self.put_recovery(conversation, None, rng);
        }
        if now.saturating_sub(asked) < ASK_AGAIN {
            return Ok(());
        }

        self.send_snapshot_request(conversation, first, now_ms, rng)
    }

    /// Sends the request of a recovery whose first request went at
    /// `first`.
    fn send_snapshot_request<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        first: u64,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
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

        // The time goes first, thus a send that fails waits as one that
        // went, and the sweep sends no request at each pass.
        let value = wanted_row(now_ms / 1_000, first);
        self.put_recovery(conversation, Some(&value), rng)?;

        // A member that lacks the epoch too posts nothing, and its
        // contacts carry the request. WIR-337: the requests to one peer
        // share one rate over each scope.
        let _ = self.post_group_app(conversation, AppKind::KeyRequest, &body, now_ms, rng);
        for contact in self.contacts_in(conversation)? {
            if self.asks_peer(contact, now_ms / 1_000, rng)? {
                self.send_pairwise_app(contact, AppKind::KeyRequest, &body, now_ms, rng)?;
            }
        }

        Ok(())
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

        let first = self
            .recovery_row(conversation)?
            .as_deref()
            .and_then(wanted_times)
            .map(|(_, first)| first);
        let Some(first) = first else {
            return Ok(());
        };
        if !is_admin
            || notice.group_id != *group.group_id()
            || notice.roster_epoch <= group.roster().epoch_index()
        {
            return Ok(());
        }

        // GRP-433: the bound counts from the first request, thus a notice
        // whose fetch fails does not start the recovery again.
        let value = [
            [NOTICED_SINCE].as_slice(),
            &first.to_be_bytes(),
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
                if let Some(descriptor) = noticed_descriptor(&value) {
                    fetches.push((conversation, descriptor.to_vec()));
                }
            }
        }

        Ok(fetches)
    }

    /// The fetched snapshot: the member takes the roster, each record that
    /// waited for it opens, and the recovery ends. A snapshot that does not
    /// verify fails as a fetch fails.
    pub fn recovery_fetched<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        snapshot: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let mut group = self.group_of(conversation)?;
        let before = Before::of(&group);

        // GRP-428: the path starts at the creator key, which a roster stored
        // before it kept that key takes from the path of this device.
        let _ = self.creator_roster_pk(conversation, &mut group);
        if let Err(fault) = group.recover_roster(snapshot, now_ms / 1_000) {
            self.recovery_failed(conversation, now_ms, rng)?;
            return Err(fault.into());
        }

        // GRP-430: the path holds each grant and re-key that this member
        // missed, and a snapshot of its own needs them. They go before the
        // roster, thus a crash leaves no roster without its path.
        let parsed = RosterSnapshot::parse(snapshot)?;
        for entry in umbra_core::group::roster::split_path(parsed.path)? {
            self.note_grant(conversation, entry, rng)?;
        }

        self.put_recovery(conversation, None, rng)?;
        let outcomes: VecDeque<_> = group.retry_held(now_ms / 1_000).into_iter().collect();
        self.take_outcomes(conversation, group, outcomes, before, false, now_ms, rng)?;
        self.events.push_back(crate::Event::Conversations);

        Ok(())
    }

    /// The fetch of a snapshot failed. The recovery waits as after a
    /// request, and it asks again after `ASK_AGAIN` (`GRP-433`). It keeps
    /// the time of its first request, thus its bound does not move. A
    /// recovery that ended while the fetch ran stays ended.
    pub fn recovery_failed<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(held) = self.recovery_row(conversation)? else {
            return Ok(());
        };

        let now = now_ms / 1_000;
        let first = first_asked(&held).unwrap_or(now);
        self.put_recovery(conversation, Some(&wanted_row(now, first)), rng)
    }
}
