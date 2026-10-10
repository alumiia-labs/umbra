//! The `recipient queue full` state of Part 14 §14.9.2. A relay that holds
//! `QUEUE_QUOTA` records of a queue answers each `SEND` to it with a `NACK`
//! of `LIMIT`, and each `QUOTA` names the room that stays (Part 3
//! `NET-016`, `NET-017`). The record stays `queued` in that state
//! (`IMP-082`), and it goes again after `HOLD_RETRY`, as the ARQ continues
//! after a `LIMIT` (`NET-218`). The full state of a conversation is memory
//! of this run, because the next `QUOTA` of the relay states it again. The
//! wait of a held record is not. The store holds the time of its next send,
//! the time of its first `LIMIT`, and the count of its `LIMIT` answers.
//! Thus a new run, an unlock, and a new process do not send a held record
//! before its time. The bounds of `NET-219` and `NET-220` count across
//! them.

use umbra_core::store::{engine::Backend, record::TableId, wrap::SecureElement};
use umbra_crypto::rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{conversation_of, info_of, Client, Outgoing, MESSAGE_PREFIX, OUTBOX, SETTINGS};
use crate::{ConversationId, Delivery, Error, Event, MsgRef};

/// The time after which a record that a full queue refused goes again, in
/// seconds.
pub const HOLD_RETRY: u64 = 15 * 60;

/// The time before send `sends + 1` of a record that a full queue refused
/// `sends` times. It is `HOLD_RETRY`, and twice the time before at each
/// later send. A queue stays full while its reader is away. Thus
/// `HOLD_RETRY` alone would spend `SEND_MAX_ATTEMPTS` in four hours
/// (`NET-219`), and the record would fail while `IMP-082` keeps it queued.
/// With the growth the sends reach to `SEND_GIVE_UP` (`NET-220`).
fn hold_wait(sends: u32) -> u64 {
    HOLD_RETRY.saturating_mul(1u64 << sends.saturating_sub(1).min(16))
}

/// The name of the setting that holds the wait of one held record, before
/// the identifier of its message. The setting holds the time from which
/// `HOLD_RETRY` counts to its next send and the time of its first `LIMIT`,
/// both in seconds. It also holds the count of its `LIMIT` answers. A
/// record that no full queue holds has none.
const HELD_SETTING: &[u8] = b"held/";

/// The length of the value of [`HELD_SETTING`].
const HELD_LEN: usize = 8 + 8 + 4;

/// The wait of one held record in the store.
struct HeldRow {
    /// The time from which `HOLD_RETRY` counts to the next send.
    at: u64,
    /// The time of the first `LIMIT`.
    first: u64,
    /// The `LIMIT` answers.
    sends: u32,
}

impl HeldRow {
    fn encode(&self) -> [u8; HELD_LEN] {
        let mut out = [0u8; HELD_LEN];
        let (at, rest) = out.split_at_mut(8);
        let (first, sends) = rest.split_at_mut(8);
        at.copy_from_slice(&self.at.to_be_bytes());
        first.copy_from_slice(&self.first.to_be_bytes());
        sends.copy_from_slice(&self.sends.to_be_bytes());
        out
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; HELD_LEN] = bytes.try_into().ok()?;
        let (at, rest) = bytes.split_at(8);
        let (first, sends) = rest.split_at(8);
        Some(HeldRow {
            at: u64::from_be_bytes(at.try_into().ok()?),
            first: u64::from_be_bytes(first.try_into().ok()?),
            sends: u32::from_be_bytes(sends.try_into().ok()?),
        })
    }
}

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

    /// The wait of a held record that the store holds, or none.
    fn held_row(&self, message: &MsgRef) -> Result<Option<HeldRow>, Error> {
        let store = &self.open_ref()?.store;
        let name = [HELD_SETTING, message.0.as_slice()].concat();
        let row = store.row_id(SETTINGS, &name);
        Ok(store
            .get(SETTINGS, &row)?
            .and_then(|bytes| HeldRow::parse(&bytes)))
    }

    /// Ends the wait of a record in the store: a relay took the record, or
    /// it failed.
    fn end_held_row(&mut self, message: &MsgRef) -> Result<(), Error> {
        if self.held_row(message)?.is_none() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let name = [HELD_SETTING, message.0.as_slice()].concat();
        let row = open.store.row_id(SETTINGS, &name);
        let mut batch = open.store.begin();
        batch.delete(SETTINGS, row);
        Ok(batch.commit()?)
    }

    /// Whether the record of `message` waits for the room of a full queue
    /// at `now`, in seconds. The send path asks it before each send. A
    /// record that waits goes at the end of its wait
    /// ([`Client::resend_held`]) or at a `QUOTA` that names room. It does
    /// not go at each connection, where the full queue would refuse it
    /// again and each such `LIMIT` would count (`NET-219`). After a lock or
    /// a new process the memory holds no wait, and the store gives it back.
    pub fn waits_for_room(&mut self, message: &MsgRef, now: u64) -> Result<bool, Error> {
        if self.held_sends.contains_key(message) {
            return Ok(true);
        }
        // A record that this run released for a send holds its counts in
        // the memory, and it goes.
        if self.limit_sends.contains_key(message) {
            return Ok(false);
        }
        let Some(held) = self.held_row(message)? else {
            return Ok(false);
        };
        self.limit_sends.insert(*message, (held.sends, held.first));
        if now.saturating_sub(held.at) >= HOLD_RETRY {
            return Ok(false);
        }
        let conversation = self.conversation_of_message(message)?;
        self.held_sends.insert(*message, (conversation, held.at));
        self.set_full(conversation, true);
        Ok(true)
    }

    /// A relay took a record of `message` and named the room of the queue.
    /// No room is the full state, and room ends it.
    pub fn queue_room(&mut self, message: &MsgRef, remaining: u32) -> Result<(), Error> {
        // DEV-313: the notice of a revocation is no message of a
        // conversation, and the room of its queue changes no view.
        if self.is_leaving_channel(ConversationId(message.0))? {
            return Ok(());
        }
        // The relay holds this record, thus its wait ended.
        self.end_held_row(message)?;
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
        // DEV-313: the notice of a revocation waits for the next run.
        if self.is_leaving_channel(ConversationId(message.0))? {
            return Ok(());
        }
        let conversation = self.conversation_of_message(message)?;
        // DEV-113, DEV-114: an edit and a deletion take no retry that the
        // quota paces, and the user sees the failure.
        if self.is_change(message)? {
            self.set_full(conversation, true);
            return self.fail(message, crate::FailureCause::Full, rng);
        }
        self.set_full(conversation, true);
        // NET-219 to NET-221: the ARQ of a record ends at
        // `SEND_MAX_ATTEMPTS` sends and at `SEND_GIVE_UP`, and the record
        // then fails. The memory holds the counts of a record that this
        // unlocked client held before, and the store holds them for each
        // other one. `SEND_GIVE_UP` counts from the first `LIMIT`, which
        // came with the first send that reached the relay.
        let stored = match self.limit_sends.get(message).copied() {
            Some(held) => Some(held),
            None => self.held_row(message)?.map(|held| (held.sends, held.first)),
        };
        let (sends, first) = stored.unwrap_or((0, now));
        let sends = sends.saturating_add(1);
        if sends >= umbra_queue::params::SEND_MAX_ATTEMPTS
            || now.saturating_sub(first) >= umbra_queue::params::SEND_GIVE_UP
        {
            self.limit_sends.remove(message);
            self.held_sends.remove(message);
            self.end_held_row(message)?;
            return self.fail(message, crate::FailureCause::Full, rng);
        }
        self.limit_sends.insert(*message, (sends, first));
        // The time of the next send: the wait counts from this refusal.
        let wait = hold_wait(sends).saturating_sub(HOLD_RETRY);
        let at = now.saturating_add(wait);
        self.held_sends.insert(*message, (conversation, at));
        // The store takes the wait, thus a later run keeps it.
        let held = HeldRow { at, first, sends };
        let open = self.open_mut()?;
        let name = [HELD_SETTING, message.0.as_slice()].concat();
        let row = open.store.row_id(SETTINGS, &name);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &held.encode(), rng)?;
        Ok(batch.commit()?)
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

#[cfg(all(test, feature = "runtime"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use umbra_core::{
        session::node::{ContactId, StateChange},
        store::{
            engine::MemoryBackend,
            wrap::{Cost, SecureElement},
        },
    };
    use zeroize::Zeroizing;

    use super::HOLD_RETRY;
    use crate::{
        bridge::Bridge,
        client::Client,
        runtime::{unix_now, Command, OsRng},
        ConversationId, Delivery,
    };

    struct Element;

    impl SecureElement for Element {
        fn keyed(&self, input: &[u8]) -> Result<[u8; 32], umbra_core::Error> {
            Ok(umbra_crypto::hash::sha3_256(&[input]))
        }
    }

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// One connection: the store gives each record that waits to the send
    /// path, and a new bridge takes them. The result is the count of the
    /// records that went to the runtime.
    fn connect(
        client: &mut Client<MemoryBackend, Element>,
        contacts: &BTreeMap<ConversationId, ContactId>,
    ) -> usize {
        client.requeue_waiting().unwrap();
        let (commands, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Command>();
        let mut bridge = Bridge::new(commands, contacts.clone());
        bridge.flush(client, &mut OsRng).unwrap();
        let mut sends = 0;
        while let Ok(command) = receiver.try_recv() {
            sends += usize::from(matches!(command, Command::Send { .. }));
        }
        sends
    }

    #[test]
    fn a_held_record_goes_at_the_end_of_its_wait_and_not_at_each_connection() {
        let mut rng = OsRng;
        let passphrase = units("correct horse");
        let cost = Cost { m_kib: 64, t: 1 };
        let mut client = Client::create(
            MemoryBackend::default(),
            Element,
            &passphrase,
            cost,
            1_000,
            &mut rng,
        )
        .unwrap();
        let peer = ContactId([0x57; 32]);
        let state = [&[0x01][..], &[5; 16], &[7; 32], &[0; 8]].concat();
        let contact = StateChange::Contact {
            contact: peer,
            state: Zeroizing::new(state),
        };
        client
            .commit_network(&[contact], &[], 1_000_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&peer.0).unwrap();
        let contacts: BTreeMap<_, _> = [(conversation, peer)].into();
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("waits for room")).unwrap();
        let message = client.send_draft(draft, 1_001_000, &mut rng).unwrap();
        // The first send, and the `LIMIT` of the full queue.
        assert_eq!(connect(&mut client, &contacts), 1);
        let now = unix_now();
        client.hold_for_room(&message, now, &mut rng).unwrap();
        assert!(client.queue_full(conversation));

        // IMP-082, NET-219: twenty connections inside the wait send the
        // record at no one of them. Thus no `LIMIT` counts for them and the
        // record stays queued.
        for _ in 0..20 {
            assert_eq!(connect(&mut client, &contacts), 0);
        }
        assert_eq!(client.info(&message).unwrap().delivery, Delivery::Queued);

        // A lock takes the memory of the wait, and the store gives it
        // back: the first connection after the unlock sends nothing.
        client.lock();
        client.unlock(&passphrase, now).unwrap();
        assert_eq!(connect(&mut client, &contacts), 0);
        assert!(client.queue_full(conversation));
        // The record goes at the end of its wait, one time.
        assert!(!client.resend_held(now + HOLD_RETRY - 1).unwrap());
        assert!(client.resend_held(now + HOLD_RETRY).unwrap());
        let (commands, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Command>();
        let mut bridge = Bridge::new(commands, contacts.clone());
        bridge.flush(&mut client, &mut rng).unwrap();
        assert!(matches!(receiver.try_recv(), Ok(Command::Send { .. })));
        assert!(receiver.try_recv().is_err());

        // NET-220: `SEND_GIVE_UP` counts from the first `LIMIT`, across a
        // lock. A `LIMIT` inside it holds the record again, and one that
        // comes 7 days after the first one fails it.
        let later = now + HOLD_RETRY;
        client.hold_for_room(&message, later, &mut rng).unwrap();
        assert_eq!(client.info(&message).unwrap().delivery, Delivery::Queued);
        client.lock();
        client.unlock(&passphrase, later).unwrap();
        let last = now + umbra_queue::params::SEND_GIVE_UP;
        client.hold_for_room(&message, last, &mut rng).unwrap();
        assert_eq!(client.info(&message).unwrap().delivery, Delivery::Failed);
        // The wait ended with the record: a later connection holds nothing
        // back for it.
        assert!(!client.waits_for_room(&message, last).unwrap());
    }
}
