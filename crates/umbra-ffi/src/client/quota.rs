//! The `recipient queue full` state of Part 14 §14.9.2. A relay that holds
//! `QUEUE_QUOTA` records of a queue answers each `SEND` to it with a `NACK`
//! of `LIMIT`, and each `QUOTA` names the room that stays (Part 3
//! `NET-016`, `NET-017`). The record stays `queued` in that state
//! (`IMP-082`), and it goes again after `HOLD_RETRY`, as the ARQ continues
//! after a `LIMIT` (`NET-218`). The state is memory of this run, because the
//! next `QUOTA` of the relay states it again.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{conversation_of, info_of, Client, Outgoing, MESSAGE_PREFIX, OUTBOX};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The time after which a record that a full queue refused goes again, in
/// seconds.
pub const HOLD_RETRY: u64 = 15 * 60;

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Whether the queue of the contact of a conversation is full.
    pub fn queue_full(&self, conversation: ConversationId) -> bool {
        self.full_queues.contains(&conversation)
    }

    fn set_full(&mut self, conversation: ConversationId, is_full: bool) {
        let changed = if is_full {
            self.full_queues.insert(conversation)
        } else {
            self.full_queues.remove(&conversation)
        };
        if changed {
            self.events.push_back(Event::Conversations);
        }
    }

    /// A relay took a record of `message` and named the room of the queue.
    /// No room is the full state, and room ends it.
    pub fn queue_room(&mut self, message: &MsgRef, remaining: u32) -> Result<(), Error> {
        let conversation = self.conversation_of_message(message)?;
        self.set_full(conversation, remaining == 0);
        if remaining > 0 {
            // The records that waited for room go at once.
            let waiting: Vec<MsgRef> = self
                .held_sends
                .iter()
                .filter(|(_, (held, _))| *held == conversation)
                .map(|(message, _)| *message)
                .collect();
            for message in waiting {
                self.requeue_held(&message)?;
            }
        }
        Ok(())
    }

    /// A relay refused a record of `message` with `LIMIT`: the queue of the
    /// contact is full, and the record stays `queued` (`IMP-082`).
    pub fn hold_for_room<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let conversation = self.conversation_of_message(message)?;
        // DEV-113, DEV-114: an edit and a deletion take no retry that the
        // quota paces, and the user sees the failure.
        if self.is_change(message)? {
            self.set_full(conversation, true);
            return self.set_delivery(message, Delivery::Failed, rng);
        }
        self.set_full(conversation, true);
        self.held_sends.insert(*message, (conversation, now));
        Ok(())
    }

    /// Whether a stored record is an edit or a deletion request of this
    /// device.
    fn is_change(&self, message: &MsgRef) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let Some(plain) = store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(false);
        };
        let plain = Zeroizing::new(plain);
        Ok(super::change_kind(&plain)?.is_some())
    }

    /// Hands each held record past `HOLD_RETRY` to the send path again. The
    /// result says whether one went.
    pub fn resend_held(&mut self, now: u64) -> Result<bool, Error> {
        let due: Vec<MsgRef> = self
            .held_sends
            .iter()
            .filter(|(_, (_, at))| now.saturating_sub(*at) >= HOLD_RETRY)
            .map(|(message, _)| *message)
            .collect();
        let mut sent = false;
        for message in due {
            sent |= self.requeue_held(&message)?;
        }
        Ok(sent)
    }

    /// Puts a held record back on the send path while it still waits.
    fn requeue_held(&mut self, message: &MsgRef) -> Result<bool, Error> {
        self.held_sends.remove(message);
        let store = &self.open_ref()?.store;
        if store.get(OUTBOX, &message.0)?.is_none() {
            return Ok(false);
        }
        let Some(plain) = store.get(TableId::MESSAGE, &message.0)? else {
            return Ok(false);
        };
        let plain = Zeroizing::new(plain);
        if info_of(&plain)?.delivery != Delivery::Queued {
            return Ok(false);
        }
        let conversation = conversation_of(&plain)?;
        let app = plain
            .get(MESSAGE_PREFIX..)
            .ok_or(Error::Integrity)?
            .to_vec();
        self.outgoing.push_back(Outgoing {
            message: *message,
            conversation,
            app,
        });
        Ok(true)
    }
}
