//! The conversation timer of Part 7 §7.5.8: the setting of each
//! conversation, the deadline of each timed record, and the erasure at the
//! deadline. The timer is a shared setting and not a property of one
//! message: a record that arrives after the timer record takes it, and a
//! record before it keeps no deadline (`DEV-203`, `DEV-204`).

use umbra_core::{
    devset::edits::Deadline,
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::rand_core::CryptoRng;
use umbra_wire::{
    app::{AppKind, AppMessage, Channel},
    group::control::Role,
};
use zeroize::Zeroizing;

use super::{stored_message, Client, Outgoing, OUTBOX, OUTGOING};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The setting of each conversation: the seconds, the time of the change,
/// and whether the user made it.
pub(super) const TIMERS: TableId = TableId(0x34);
/// The deadline of each timed record, under the row of its message: the
/// conversation and the time of the erasure in seconds.
pub(super) const DEADLINES: TableId = TableId(0x35);

/// `TIMER_VALUES` of Part 7 §7.8: the only periods a timer takes, thus a
/// period names no conversation (`WIR-201`, `WIR-202`).
pub const TIMER_VALUES: [u32; 9] = [
    0, 30, 300, 3_600, 28_800, 86_400, 604_800, 2_419_200, 7_776_000,
];

/// The timer of one conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerSetting {
    /// The period in seconds, or 0 for no timer.
    pub seconds: u32,
    /// The time of the change on this device, in milliseconds.
    pub set_at_ms: u64,
    /// Whether the user set it, on this device or another of the set
    /// (`DEV-206`).
    pub by_user: bool,
}

impl TimerSetting {
    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(13));
        out.extend_from_slice(&self.seconds.to_be_bytes());
        out.extend_from_slice(&self.set_at_ms.to_be_bytes());
        out.push(u8::from(self.by_user));
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let seconds = bytes
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        let at = bytes
            .get(4..12)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Integrity)?;
        Ok(TimerSetting {
            seconds: u32::from_be_bytes(seconds),
            set_at_ms: u64::from_be_bytes(at),
            by_user: bytes.get(12) == Some(&1),
        })
    }
}

/// The period of a `ConversationTimer` body, when the body holds a value of
/// the set (Part 6 §6.6.8).
pub fn timer_body(body: &[u8]) -> Option<u32> {
    let [0x01, a, b, c, d] = body else {
        return None;
    };
    let seconds = u32::from_be_bytes([*a, *b, *c, *d]);
    TIMER_VALUES.contains(&seconds).then_some(seconds)
}

/// Whether a record of `kind` is a message that a timer erases. A reaction,
/// an edit, and a deletion go with their target, and a timer record stays
/// as the mark of the change (`DEV-207`).
pub(super) fn is_timed_kind(kind: AppKind) -> bool {
    matches!(
        kind,
        AppKind::Text | AppKind::Attachment | AppKind::Rich | AppKind::Poll | AppKind::ContactShare
    )
}

/// The stored deadline of a message of `conversation` at `at` seconds.
pub(super) fn deadline_row(conversation: ConversationId, at: u64) -> Zeroizing<Vec<u8>> {
    Zeroizing::new([conversation.0.as_slice(), &at.to_be_bytes()].concat())
}

fn deadline_at(value: &[u8]) -> Result<u64, Error> {
    let at = value
        .get(16..24)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Integrity)?;
    Ok(u64::from_be_bytes(at))
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The timer of a conversation, or none when no party ever set one.
    pub fn conversation_timer(
        &self,
        conversation: ConversationId,
    ) -> Result<Option<TimerSetting>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(TIMERS, &conversation.0);
        store
            .get(TIMERS, &row)?
            .map(|value| TimerSetting::parse(&Zeroizing::new(value)))
            .transpose()
    }

    /// The period of the timer of a conversation, or 0.
    pub(super) fn timer_seconds(&self, conversation: ConversationId) -> Result<u32, Error> {
        Ok(self
            .conversation_timer(conversation)?
            .map_or(0, |setting| setting.seconds))
    }

    /// The row of the timer of a conversation.
    pub(super) fn timer_row(&self, conversation: ConversationId) -> Result<RowId, Error> {
        Ok(self.open_ref()?.store.row_id(TIMERS, &conversation.0))
    }

    /// Gives a message its deadline, when its conversation has a timer: the
    /// period from the local receive time of a record of a contact
    /// (`DEV-208`), or from the send of a record of this device (`DEV-245`).
    pub(super) fn stamp_deadline<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        kind: AppKind,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let seconds = self.timer_seconds(conversation)?;
        if seconds == 0 || !is_timed_kind(kind) {
            return Ok(());
        }
        self.put_deadline(conversation, message, Deadline::received(now, seconds), rng)
    }

    /// Keeps the deadline of a message.
    pub(super) fn put_deadline<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        message: MsgRef,
        deadline: Deadline,
        rng: &mut R,
    ) -> Result<(), Error> {
        let value = deadline_row(conversation, deadline.at);
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(DEADLINES, message.0, Some(conversation.0), &value, rng)?;
        Ok(batch.commit()?)
    }

    /// The time at which a timed message is erased, in seconds.
    pub fn deadline_of(&self, message: &MsgRef) -> Result<Option<Deadline>, Error> {
        let store = &self.open_ref()?.store;
        store
            .get(DEADLINES, &message.0)?
            .map(|value| {
                Ok(Deadline {
                    at: deadline_at(&Zeroizing::new(value))?,
                })
            })
            .transpose()
    }

    /// Whether a message is timed, and thus stays out of each durable store
    /// but the local database (`DEV-214` to `DEV-216`).
    pub fn is_timed(&self, message: &MsgRef) -> Result<bool, Error> {
        Ok(self.deadline_of(message)?.is_some())
    }

    /// Erases each timed message whose deadline passed at `now`: its row, its
    /// key, and each row of it (`DEV-210`, `DEV-211`). Each device of the set
    /// erases for itself (`DEV-212`, `DEV-213`).
    pub fn sweep_timed(&mut self, now: u64) -> Result<usize, Error> {
        let mut due = Vec::new();
        for (row, value) in self.open_ref()?.store.list(DEADLINES, None)? {
            let value = Zeroizing::new(value);
            // A row that does not parse stops no other deadline.
            let Ok(at) = deadline_at(&value) else {
                continue;
            };
            if (Deadline { at }).due(now) {
                let conversation: [u8; 16] = value
                    .get(..16)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Integrity)?;
                due.push((ConversationId(conversation), MsgRef(row)));
            }
        }
        for (conversation, message) in &due {
            // A row that a deletion took first leaves its deadline alone.
            // A fault of one message keeps its deadline for the next sweep,
            // and it stops no other expiry.
            if self.delete_if_held(message).is_err() {
                continue;
            }
            let open = self.open_mut()?;
            let mut batch = open.store.begin();
            batch.delete(DEADLINES, message.0);
            batch.commit()?;
            self.events.push_back(Event::Deleted {
                conversation: *conversation,
                message: *message,
            });
        }
        // DEV-211: a body that waits for a resend on a sync channel holds
        // the record too.
        if !due.is_empty() {
            self.drop_sync_sent_of(&due)?;
        }
        Ok(due.len())
    }

    /// Sets the timer of a conversation and sends the timer record to the
    /// other party, or to the group (`DEV-205`, `DEV-207`). In a group a
    /// member below `admin` sets no timer (`DEV-248`). The record is a row
    /// of the conversation, thus each party sees the change.
    pub fn set_conversation_timer<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        seconds: u32,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        if !TIMER_VALUES.contains(&seconds) {
            return Err(Error::Malformed);
        }
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let body = [&[0x01][..], &seconds.to_be_bytes()].concat();
        let record = AppMessage {
            kind: AppKind::ConversationTimer,
            msg_id,
            sent_at: now_ms,
            body: &body,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        let message = if self.is_group(conversation)? {
            if self
                .group_of(conversation)?
                .own_role()
                .is_none_or(|role| role < Role::Admin)
            {
                return Err(Error::Malformed);
            }
            self.post_to_group(conversation, msg_id, &app, now_ms, rng)?
        } else {
            let open = self.open_mut()?;
            let reference = super::msg_ref(&open.device_set_key, &msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            let plain = stored_message(
                OUTGOING,
                Delivery::Queued,
                conversation,
                open.stamp.next(now_ms),
                &app,
            );
            let mut batch = open.store.begin();
            batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
            batch.put(OUTBOX, row, None, &super::outbox_row(), rng)?;
            batch.commit()?;
            let message = MsgRef(row);
            self.outgoing.push_back(Outgoing {
                message,
                conversation,
                app,
            });
            message
        };
        self.put_timer(conversation, seconds, now_ms, true, rng)?;
        Ok(message)
    }

    /// Keeps the timer of a conversation.
    pub(super) fn put_timer<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        seconds: u32,
        now_ms: u64,
        by_user: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let setting = TimerSetting {
            seconds,
            set_at_ms: now_ms,
            by_user,
        };
        let row = self.timer_row(conversation)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(TIMERS, row, Some(conversation.0), &setting.encode(), rng)?;
        Ok(batch.commit()?)
    }

    /// The `expires_in` of a record of `conversation` for a sync copy at
    /// `now`: the rest of the period of its message (`DEV-242`, `DEV-243`).
    pub(super) fn expires_in_of(
        &self,
        conversation: ConversationId,
        app: &[u8],
        now: u64,
    ) -> Result<u32, Error> {
        let channel = if self.is_group(conversation)? {
            Channel::Group
        } else {
            Channel::Pairwise
        };
        let parsed = AppMessage::parse(app, channel)?;
        let open = self.open_ref()?;
        let reference = super::msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        Ok(match self.deadline_of(&MsgRef(row))? {
            // A copy at its deadline goes with one second, and the peer
            // erases it at once.
            Some(deadline) => deadline.expires_in(now).max(1),
            None => 0,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_timer_body_takes_a_value_of_the_set_alone() {
        assert_eq!(timer_body(&[1, 0, 0, 0x0E, 0x10]), Some(3_600));
        assert_eq!(timer_body(&[1, 0, 0, 0, 0]), Some(0));
        // WIR-202: a period out of the set names a conversation.
        assert_eq!(timer_body(&[1, 0, 0, 0x10, 0xF1]), None);
        assert_eq!(timer_body(&[2, 0, 0, 0x0E, 0x10]), None);
        assert_eq!(timer_body(&[1, 0, 0, 0x0E]), None);
    }
}
