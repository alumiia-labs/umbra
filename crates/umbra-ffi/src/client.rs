//! The client behind the surface of Part 15 §15.6.1: the locked and the
//! unlocked state over the store of §15.6.4, the send of a draft, the
//! render of a message into a sink, and the one event stream.
//!
//! Each network, ratchet, queue, and onion function stays on the Rust
//! side. The runtime takes each outgoing record from
//! [`Client::take_outgoing`] and gives each received record to
//! [`Client::receive`], and the platform sees handles and events only.

use std::collections::VecDeque;

use umbra_core::{
    session::node::{ContactId, StateChange},
    store::{
        engine::{Backend, Store},
        record::{RowId, TableId},
        wrap::{AutoLock, Cost, SecureElement, WrapHeader},
    },
};
use umbra_crypto::{hierarchy::RootIdentity, rand_core::CryptoRng, secret::Secret};
use umbra_wire::app::{msg_ref, AppKind, AppMessage, Channel};
use zeroize::Zeroizing;

use crate::{draft::Draft, ConversationId, Delivery, Error, Event, MessageInfo, MsgRef, Sink};

const ROOT_KEY: &[u8] = b"root";
const OUTGOING: u8 = 1;
const INCOMING: u8 = 2;
/// The bytes of a stored message before its `AppMessage`: the direction,
/// the delivery state, the conversation, and the time of this device at the
/// store of the message, in milliseconds. The conversation sits in the
/// plaintext, because the owner column of a row is outside the associated
/// data (`IMP-121`). The store time orders a conversation view, because the
/// send time is a value of the peer.
const MESSAGE_PREFIX: usize = 2 + 16 + 8;
const STORED_AT: core::ops::Range<usize> = 18..26;
/// The table of the records that wait for the send path. A row holds the
/// file references of its draft, under the row identifier of its message.
/// A lock clears the queue in RAM, and an unlock fills it again from here.
const OUTBOX: TableId = TableId(0x07);
/// The table of the invitations that wait for their flight 1. A row holds
/// the `RecipientId` of the queue and then the stored form of the node,
/// with the one-time prekey in it (Part 5 rule `CRY-089`).
const INVITATION: TableId = TableId(0x08);
/// The bytes of a contact row and of an invitation row before the stored
/// form: the `RecipientId` of the queue.
const QUEUE_ID_LEN: usize = 32;

/// The state of the client node that the store holds between two runs.
pub struct StoredNetwork {
    /// Each contact, with its conversation and its stored form.
    pub contacts: Vec<(ConversationId, Zeroizing<Vec<u8>>)>,
    /// The stored form of each invitation that waits.
    pub invitations: Vec<Zeroizing<Vec<u8>>>,
}

/// A record that waits for the send path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The message.
    pub message: MsgRef,
    /// The conversation.
    pub conversation: ConversationId,
    /// The encoded `AppMessage`.
    pub app: Vec<u8>,
    /// The file references of the draft, for the attachment path.
    pub attachments: Vec<String>,
}

struct Open<B: Backend> {
    store: Store<B>,
    device_set_key: Secret<32>,
}

enum State<B: Backend> {
    Locked(B),
    Unlocked(Box<Open<B>>),
    /// A transition failed part way, and the backend is gone.
    Closed,
}

/// The client of one device.
pub struct Client<B: Backend, E: SecureElement> {
    element: E,
    header: WrapHeader,
    state: State<B>,
    events: VecDeque<Event>,
    outgoing: VecDeque<Outgoing>,
    auto_lock: AutoLock,
}

fn passphrase_bytes(code_units: &[u16]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(code_units.len().saturating_mul(3)));
    for decoded in char::decode_utf16(code_units.iter().copied()) {
        let character = decoded.map_err(|_| Error::Malformed)?;
        let mut utf8 = [0u8; 4];
        bytes.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
    }
    Ok(bytes)
}

fn outbox_row(attachments: &[String]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.extend_from_slice(
        &u16::try_from(attachments.len())
            .map_err(|_| Error::TooLong)?
            .to_be_bytes(),
    );
    for file_ref in attachments {
        out.extend_from_slice(
            &u16::try_from(file_ref.len())
                .map_err(|_| Error::TooLong)?
                .to_be_bytes(),
        );
        out.extend_from_slice(file_ref.as_bytes());
    }
    Ok(out)
}

fn attachments_of(row: &[u8]) -> Result<Vec<String>, Error> {
    let take = |at: usize, len: usize| row.get(at..at.saturating_add(len)).ok_or(Error::Integrity);
    let u16_at = |at: usize| -> Result<usize, Error> {
        let bytes: [u8; 2] = take(at, 2)?.try_into().map_err(|_| Error::Integrity)?;
        Ok(usize::from(u16::from_be_bytes(bytes)))
    };
    let mut at = 2usize;
    let mut out = Vec::new();
    for _ in 0..u16_at(0)? {
        let len = u16_at(at)?;
        let text =
            core::str::from_utf8(take(at.saturating_add(2), len)?).map_err(|_| Error::Integrity)?;
        out.push(text.to_owned());
        at = at.saturating_add(2).saturating_add(len);
    }
    Ok(out)
}

fn stored_message(
    direction: u8,
    delivery: Delivery,
    conversation: ConversationId,
    stored_at_ms: u64,
    app: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut plain = Zeroizing::new(Vec::with_capacity(MESSAGE_PREFIX.saturating_add(app.len())));
    plain.push(direction);
    plain.push(delivery as u8);
    plain.extend_from_slice(&conversation.0);
    plain.extend_from_slice(&stored_at_ms.to_be_bytes());
    plain.extend_from_slice(app);
    plain
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// Makes the store of a new device: a root seed from `rng`, `K_store`
    /// from it, and the wrap under the passphrase. The platform keeps
    /// [`Client::header`] beside the database. The client starts unlocked.
    pub fn create<R: CryptoRng + ?Sized>(
        backend: B,
        element: E,
        passphrase: &[u16],
        cost: Cost,
        now: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut seed = Secret::<32>::zeroed();
        rng.fill_bytes(seed.expose_mut());
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let root = RootIdentity::new(Secret::new(*seed.expose()));
        let store_key = root.storage_key();
        let header = WrapHeader::wrap(
            &store_key,
            &passphrase_bytes(passphrase)?,
            cost,
            salt,
            nonce,
            &element,
        )?;
        let mut store = Store::unlock(backend, store_key)?;
        let row = store.row_id(TableId::LOCAL_IDENTITY, ROOT_KEY);
        let mut batch = store.begin();
        batch.put(TableId::LOCAL_IDENTITY, row, None, seed.expose(), rng)?;
        batch.commit()?;
        Ok(Client {
            element,
            header,
            state: State::Unlocked(Box::new(Open {
                store,
                device_set_key: root.device_set_key(),
            })),
            events: VecDeque::new(),
            outgoing: VecDeque::new(),
            auto_lock: AutoLock::new(now),
        })
    }

    /// Opens the store of a device that exists, in the locked state.
    pub fn open(backend: B, element: E, header: WrapHeader, now: u64) -> Self {
        Client {
            element,
            header,
            state: State::Locked(backend),
            events: VecDeque::new(),
            outgoing: VecDeque::new(),
            auto_lock: AutoLock::new(now),
        }
    }

    /// The header that opens the store again.
    pub fn header(&self) -> &WrapHeader {
        &self.header
    }

    /// Whether the client holds `K_store`.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, State::Unlocked(_))
    }

    /// Unlocks with the passphrase of a `CharArray`, which the caller
    /// overwrites after this call. A wrong passphrase leaves the client
    /// locked. A table whose MAC does not match gives an
    /// [`Event::IntegrityFault`], and the client does not continue
    /// silently (`IDN-039`, `IDN-040`).
    pub fn unlock(&mut self, passphrase: &[u16], now: u64) -> Result<(), Error> {
        let State::Locked(_) = self.state else {
            return Ok(());
        };
        let store_key = self
            .header
            .unwrap(&passphrase_bytes(passphrase)?, &self.element)
            .map_err(|_| Error::WrongPassphrase)?;
        let State::Locked(backend) = core::mem::replace(&mut self.state, State::Closed) else {
            return Err(Error::Closed);
        };
        let store = match Store::unlock(backend, store_key) {
            Ok(store) => store,
            Err(_) => {
                self.events.push_back(Event::IntegrityFault);
                return Err(Error::Integrity);
            }
        };
        let row = store.row_id(TableId::LOCAL_IDENTITY, ROOT_KEY);
        let seed = store
            .get(TableId::LOCAL_IDENTITY, &row)?
            .ok_or(Error::Integrity)?;
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
        let root = RootIdentity::new(Secret::new(seed));
        self.state = State::Unlocked(Box::new(Open {
            store,
            device_set_key: root.device_set_key(),
        }));
        // Each record that waited for the send path at the lock waits again.
        self.requeue_waiting()?;
        self.auto_lock.touch(now);
        Ok(())
    }

    /// Locks the client: `K_store` leaves RAM, and each record that waits
    /// for the send path stays in the store.
    pub fn lock(&mut self) {
        if let State::Unlocked(open) = core::mem::replace(&mut self.state, State::Closed) {
            self.state = State::Locked(open.store.lock());
            self.outgoing.clear();
            self.events.push_back(Event::Locked);
        }
    }

    /// The clock of the platform. An idle client locks itself.
    pub fn tick(&mut self, now: u64) {
        if self.is_unlocked() && self.auto_lock.due(now) {
            self.lock();
        }
    }

    /// The user acted at `now`.
    pub fn touch(&mut self, now: u64) {
        self.auto_lock.touch(now);
    }

    fn open_mut(&mut self) -> Result<&mut Open<B>, Error> {
        match &mut self.state {
            State::Unlocked(open) => Ok(open),
            State::Locked(_) => Err(Error::Locked),
            State::Closed => Err(Error::Closed),
        }
    }

    fn open_ref(&self) -> Result<&Open<B>, Error> {
        match &self.state {
            State::Unlocked(open) => Ok(open),
            State::Locked(_) => Err(Error::Locked),
            State::Closed => Err(Error::Closed),
        }
    }

    /// Commits what one call of the client node gave, in one batch
    /// (`IMP-130`): each change of the node state, and each record that the
    /// node opened. The runtime acknowledges the records to the relay after
    /// this call (`WIR-115`), and it writes no capsule of the call before
    /// it. A record that the store holds gives no second event.
    pub fn commit_network<R: CryptoRng + ?Sized>(
        &mut self,
        changes: &[StateChange],
        received: &[(ContactId, Vec<u8>)],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        // The batch borrows the store, thus each row identifier and each
        // duplicate check comes first.
        enum Planned {
            Put(TableId, RowId, Option<RowId>, Zeroizing<Vec<u8>>),
            Delete(TableId, RowId),
        }
        let mut planned = Vec::new();
        for change in changes {
            planned.push(match change {
                StateChange::Contact { contact, state } => Planned::Put(
                    TableId::CONTACT,
                    open.store.row_id(TableId::CONTACT, &contact.0),
                    None,
                    Zeroizing::new([contact.0.as_slice(), state].concat()),
                ),
                StateChange::Invitation { queue, state } => Planned::Put(
                    INVITATION,
                    open.store.row_id(INVITATION, queue),
                    None,
                    Zeroizing::new([queue.as_slice(), state].concat()),
                ),
                StateChange::InvitationEnded { queue } => {
                    Planned::Delete(INVITATION, open.store.row_id(INVITATION, queue))
                }
            });
        }
        let mut events = Vec::new();
        for (contact, app) in received {
            let parsed = AppMessage::parse(app, Channel::Pairwise)?;
            let conversation = ConversationId(open.store.row_id(TableId::CONTACT, &contact.0));
            let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            let message = MsgRef(row);
            let in_batch = events
                .iter()
                .any(|event| matches!(event, Event::Message { message: m, .. } if *m == message));
            if in_batch || open.store.get(TableId::MESSAGE, &row)?.is_some() {
                continue;
            }
            planned.push(Planned::Put(
                TableId::MESSAGE,
                row,
                Some(conversation.0),
                stored_message(INCOMING, Delivery::Delivered, conversation, now_ms, app),
            ));
            events.push(Event::Message {
                conversation,
                message,
            });
        }
        let mut batch = open.store.begin();
        for write in &planned {
            match write {
                Planned::Put(table, row, owner, plain) => {
                    batch.put(*table, *row, *owner, plain, rng)?;
                }
                Planned::Delete(table, row) => batch.delete(*table, *row),
            }
        }
        batch.commit()?;
        self.events.extend(events);
        Ok(())
    }

    /// The state of the client node from the earlier runs.
    pub fn stored_network(&self) -> Result<StoredNetwork, Error> {
        let store = &self.open_ref()?.store;
        let state_of = |plain: Vec<u8>| -> Result<Zeroizing<Vec<u8>>, Error> {
            let plain = Zeroizing::new(plain);
            let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
            Ok(Zeroizing::new(state.to_vec()))
        };
        let mut contacts = Vec::new();
        for (row, plain) in store.list(TableId::CONTACT, None)? {
            contacts.push((ConversationId(row), state_of(plain)?));
        }
        let mut invitations = Vec::new();
        for (_, plain) in store.list(INVITATION, None)? {
            invitations.push(state_of(plain)?);
        }
        Ok(StoredNetwork {
            contacts,
            invitations,
        })
    }

    /// The conversations of the device, one for each contact. The list
    /// needs no network.
    pub fn conversations(&self) -> Result<Vec<ConversationId>, Error> {
        let store = &self.open_ref()?.store;
        let rows = store.list(TableId::CONTACT, None)?;
        Ok(rows
            .into_iter()
            .map(|(row, plain)| {
                drop(Zeroizing::new(plain));
                ConversationId(row)
            })
            .collect())
    }

    /// Puts each record that waits in the store back into the send queue.
    /// A run of the network that ended took records that no relay
    /// accepted, and the next run sends them again under their `msg_id`.
    pub fn requeue_waiting(&mut self) -> Result<(), Error> {
        self.outgoing.clear();
        let store = &self.open_ref()?.store;
        let mut waiting_records = Vec::new();
        for (row, waiting) in store.list(OUTBOX, None)? {
            let Some(plain) = store.get(TableId::MESSAGE, &row)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            let info = info_of(&plain)?;
            waiting_records.push((
                info.stored_at_ms,
                Outgoing {
                    message: MsgRef(row),
                    conversation: conversation_of(&plain)?,
                    app: plain
                        .get(MESSAGE_PREFIX..)
                        .ok_or(Error::Integrity)?
                        .to_vec(),
                    attachments: attachments_of(&waiting)?,
                },
            ));
        }
        // The order of the store is the order of a keyed hash.
        waiting_records.sort_by_key(|(stored_at, _)| *stored_at);
        self.outgoing
            .extend(waiting_records.into_iter().map(|(_, record)| record));
        Ok(())
    }

    /// The root identity of the device, for the network runtime.
    pub fn root_identity(&self) -> Result<RootIdentity, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(TableId::LOCAL_IDENTITY, ROOT_KEY);
        let seed = Zeroizing::new(
            store
                .get(TableId::LOCAL_IDENTITY, &row)?
                .ok_or(Error::Integrity)?,
        );
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
        Ok(RootIdentity::new(Secret::new(seed)))
    }

    /// The conversation of a contact: the surrogate of the contact under
    /// the store key, thus the owner column of a message names no queue to
    /// a party without `K_store`.
    pub fn conversation_for(&self, contact: &[u8; 32]) -> Result<ConversationId, Error> {
        let store = &self.open_ref()?.store;
        Ok(ConversationId(store.row_id(TableId::CONTACT, contact)))
    }

    /// An empty draft for one conversation.
    pub fn new_draft(&self, conversation: ConversationId) -> Draft {
        Draft::new(conversation)
    }

    /// Sends a draft: the client draws `msg_id`, stores the message in the
    /// queued state, and hands the record to the send path. The draft
    /// drops here, and its buffer is zero bytes after that, whether this
    /// call succeeds or fails (`IMP-039`).
    pub fn send_draft<R: CryptoRng + ?Sized>(
        &mut self,
        draft: Draft,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        if draft.is_empty() {
            return Err(Error::Malformed);
        }
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let message = AppMessage {
            kind: AppKind::Text,
            msg_id,
            sent_at: now_ms,
            body: draft.text(),
        };
        let mut app = Zeroizing::new(vec![0u8; message.len()]);
        message.encode(&mut app)?;
        let conversation = draft.conversation();
        let attachments = draft.attachments().to_vec();

        let open = self.open_mut()?;
        // IMP-024, IMP-025: the store holds the keyed form of `msg_id`.
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let plain = stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, &app);
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.put(OUTBOX, row, None, &outbox_row(&attachments)?, rng)?;
        batch.commit()?;

        let message = MsgRef(row);
        self.outgoing.push_back(Outgoing {
            message,
            conversation,
            app: app.to_vec(),
            attachments,
        });
        self.auto_lock.touch(now_ms / 1_000);
        Ok(message)
    }

    /// Cancels a send that the send path did not take yet. The message
    /// leaves the store in a deletion batch.
    pub fn cancel_send(&mut self, message: &MsgRef) -> Result<bool, Error> {
        let Some(position) = self.outgoing.iter().position(|o| o.message == *message) else {
            return Ok(false);
        };
        self.outgoing.remove(position);
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.delete(TableId::MESSAGE, message.0);
        batch.delete(OUTBOX, message.0);
        batch.commit()?;
        Ok(true)
    }

    /// The next record for the send path of the runtime.
    pub fn take_outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.pop_front()
    }

    /// The send path reports a delivery state of a message.
    pub fn set_delivery<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        delivery: Delivery,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        *plain.get_mut(1).ok_or(Error::Integrity)? = delivery as u8;
        let mut batch = open.store.begin();
        batch.put(
            TableId::MESSAGE,
            message.0,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        if delivery != Delivery::Queued {
            // A relay took the record, or the ARQ stopped. It waits no more.
            batch.delete(OUTBOX, message.0);
        }
        batch.commit()?;
        self.events.push_back(Event::Delivery {
            message: *message,
            delivery,
        });
        Ok(())
    }

    /// The receive path gives one application record of a conversation.
    /// The client commits it before the runtime acknowledges it to the
    /// relay (`WIR-115`), and a record that the store holds gives no
    /// second event.
    pub fn receive<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        app: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let parsed = AppMessage::parse(app, Channel::Pairwise)?;
        let open = self.open_mut()?;
        let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let message = MsgRef(row);
        if open.store.get(TableId::MESSAGE, &row)?.is_some() {
            return Ok(message);
        }
        let plain = stored_message(INCOMING, Delivery::Delivered, conversation, now_ms, app);
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.commit()?;
        self.events.push_back(Event::Message {
            conversation,
            message,
        });
        Ok(message)
    }

    /// Whether the stream holds an event.
    pub fn has_event(&self) -> bool {
        !self.events.is_empty()
    }

    /// The next event of the one stream from Rust to the platform.
    pub fn next_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Renders the text of a message into a sink of the platform, as
    /// UTF-16 code units. The plaintext leaves no copy on the Rust side
    /// after the call.
    pub fn render(&self, message: &MsgRef, sink: &mut dyn Sink) -> Result<(), Error> {
        let open = self.open_ref()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let parsed = AppMessage::parse(app, Channel::Pairwise)?;
        if parsed.kind != AppKind::Text {
            return Err(Error::Malformed);
        }
        let text = core::str::from_utf8(parsed.body).map_err(|_| Error::Integrity)?;
        let mut units = Zeroizing::new(Vec::with_capacity(text.len()));
        units.extend(text.encode_utf16());
        sink.put(&units);
        Ok(())
    }

    /// The direction, the delivery state, and the send time of a message.
    pub fn info(&self, message: &MsgRef) -> Result<MessageInfo, Error> {
        let open = self.open_ref()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        info_of(&plain)
    }

    /// The messages of one conversation, as handles, in the order in which
    /// this device stored them. The row identifier is a keyed hash, thus
    /// the order of the store says nothing.
    pub fn messages(&self, conversation: ConversationId) -> Result<Vec<MsgRef>, Error> {
        let open = self.open_ref()?;
        let mut found = Vec::new();
        for (row, plain) in open.store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            // IMP-121: the plaintext names its owner.
            if conversation_of(&plain)? != conversation {
                return Err(Error::Integrity);
            }
            let info = info_of(&plain)?;
            found.push((info.stored_at_ms, info.sent_at_ms, row));
        }
        found.sort_unstable();
        Ok(found.into_iter().map(|(_, _, row)| MsgRef(row)).collect())
    }

    /// Compares each table with its accumulator by a scan, outside the
    /// unlock path (`IDN-162`). A difference gives an
    /// [`Event::IntegrityFault`].
    pub fn audit(&mut self) -> Result<(), Error> {
        let open = self.open_ref()?;
        let tables = [
            TableId::MESSAGE,
            TableId::LOCAL_IDENTITY,
            TableId::CONTACT,
            OUTBOX,
            INVITATION,
        ];
        if tables.iter().any(|table| open.store.audit(*table).is_err()) {
            self.events.push_back(Event::IntegrityFault);
            return Err(Error::Integrity);
        }
        Ok(())
    }
}

fn info_of(plain: &[u8]) -> Result<MessageInfo, Error> {
    let direction = *plain.first().ok_or(Error::Integrity)?;
    let delivery = plain.get(1).copied().and_then(Delivery::from_byte);
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    let stored_at: [u8; 8] = plain
        .get(STORED_AT)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Integrity)?;
    Ok(MessageInfo {
        outgoing: direction == OUTGOING,
        stored_at_ms: u64::from_be_bytes(stored_at),
        delivery: delivery.ok_or(Error::Integrity)?,
        sent_at_ms: AppMessage::parse(app, Channel::Pairwise)?.sent_at,
    })
}

fn conversation_of(plain: &[u8]) -> Result<ConversationId, Error> {
    let bytes: [u8; 16] = plain
        .get(2..18)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Integrity)?;
    Ok(ConversationId(bytes))
}

/// The row identifier type of the store, for a platform crate that names a
/// conversation.
pub type ConversationRow = RowId;
