//! The client behind the surface of Part 14 §14.6.1: the locked and the
//! unlocked state over the store of §14.6.4, the send of a draft, the
//! render of a message into a sink, and the one event stream.
//!
//! Each network, ratchet, queue, and onion function stays on the Rust
//! side. The runtime takes each outgoing record from
//! [`Client::take_outgoing`] and gives each received record to
//! [`Client::receive`], and the platform sees handles and events only.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod backup;
mod dead;
mod devices;
mod files;
mod groups;
mod notify;
mod sync;

pub use backup::{BackupUpload, PendingBackup, RestoredBackup, RootWrite};
pub use dead::DeadWork;
pub use devices::DeviceInfo;
pub use files::{DownloadJob, ErasureJob, FileExtras, FileInfo, FileState, UploadJob};
use files::{FileQueues, CHUNK_CRED, FILE_DATA, FILE_STATE};
pub use groups::{
    EpochUpload, GroupAdmitWaiting, GroupInfo, GroupJoiner, GroupOffer, GroupPost, GroupQueueJob,
    GroupSubscription, Silence, GROUP_NAME_MAX,
};
pub use notify::NdrCall;
pub use sync::SyncSend;
use umbra_core::{
    directory::path::IngressPins,
    identity::address::safety_number,
    session::node::{stored_contact_keys, ContactId, StateChange},
    store::{
        engine::{Backend, Store},
        record::{RowId, TableId},
        wrap::{AutoLock, Cost, SecureElement, WrapHeader, AUTO_LOCK_DEFAULT, AUTO_LOCK_MAX},
    },
};
use umbra_crypto::{hierarchy::RootIdentity, rand_core::CryptoRng, secret::Secret};
use umbra_queue::client::receipts::ReceiptHold;
use umbra_wire::app::{
    edit::{DeleteBody, DeleteScope, EditBody},
    msg_ref,
    rich::RichRecord,
    signal::{ReactionAction, ReactionBody, ReceiptBody},
    AppKind, AppMessage, Channel,
};
use zeroize::Zeroizing;

use crate::{
    draft::Draft, ConversationId, ConversationSummary, Delivery, DueReceipt, Error, Event,
    MessageInfo, MsgRef, Reaction, ReceiptSettings, ReplyTarget, Sink, CONTACT_NAME_MAX,
};

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
/// The table of what this device alone knows of a conversation: the time
/// up to which the user saw its messages, and the name that the user gave
/// the contact. A row holds the conversation, the time, and the name.
const CONVERSATION: TableId = TableId(0x09);
const READ_UP_TO: core::ops::Range<usize> = 16..24;
const CONVERSATION_PREFIX: usize = 16 + 8;

/// The table of the receipts that wait for a slot of the cover clock
/// (`NET-053`). A row holds the conversation, the kind of the receipt, the
/// `msg_id` of its target, and the time that it reports.
const RECEIPT: TableId = TableId(0x0B);
const RECEIPT_ROW_LEN: usize = 16 + 1 + 16 + 8;
/// The name of the receipt setting of a conversation, before its identifier.
const RECEIPT_SETTING: &[u8] = b"receipts/";
const SENDS_DELIVERY: u8 = 0x01;
const SENDS_READ: u8 = 0x02;

/// The pending reference table of Part 7 §7.5.6: a deletion of the contact
/// whose target did not arrive yet. A row holds the conversation, the
/// `msg_ref` of the target, and the time of the deletion, in seconds.
const PENDING: TableId = TableId(0x0C);
const PENDING_ROW_LEN: usize = 16 + 16 + 8;
/// The table of the reactions. A row holds the conversation, the `msg_ref`
/// of the target (`WIR-280`), the direction, and the emoji. One party holds
/// one row for one emoji on one message.
const REACTION: TableId = TableId(0x0E);
const REACTION_PREFIX: usize = 16 + 16 + 1;
/// The most emoji that one party holds on one message. A contact cannot
/// grow the table past this count for each message that the device holds.
pub const REACTIONS_MAX: usize = 16;

/// Whether each code point of `emoji` is one that an emoji sequence uses. The
/// wire checks UTF-8 alone, thus 64 bytes of a reaction could carry a text.
/// This check keeps a reaction a reaction: no letter of a script passes, and
/// no digit, because a keycap sequence starts with one.
pub fn is_emoji(emoji: &str) -> bool {
    !emoji.is_empty()
        && emoji.chars().all(|c| {
            matches!(
                u32::from(c),
                0x00A9 | 0x00AE | 0x200D | 0x203C | 0x2049 | 0x2122 | 0x2139 | 0x24C2
                    | 0x3030 | 0x303D | 0x3297 | 0x3299 | 0xFE0F
                    | 0x2190..=0x21FF
                    | 0x2300..=0x23FF
                    | 0x25A0..=0x25FF
                    | 0x2600..=0x27BF
                    | 0x2934..=0x2935
                    | 0x2B00..=0x2BFF
                    | 0x1F000..=0x1FAFF
                    | 0xE0020..=0xE007F
            )
        })
}

fn reaction_row(
    conversation: ConversationId,
    reference: &[u8; 16],
    direction: u8,
    emoji: &str,
) -> Vec<u8> {
    [
        conversation.0.as_slice(),
        reference,
        &[direction],
        emoji.as_bytes(),
    ]
    .concat()
}

/// The table of the edits of a message: the row of the message, and how
/// many times its sender changed the text. A message with no row here shows
/// no edited mark.
const REVISION: TableId = TableId(0x0D);
/// `EDIT_WINDOW`, in milliseconds. A receiver measures it from its own store
/// time of the target (`DEV-087`).
pub const EDIT_WINDOW_MS: u64 = 24 * 3_600 * 1_000;
/// `EDIT_MAX`: the revisions of one message.
pub const EDIT_MAX: u8 = 8;
/// `REF_ORPHAN_TTL`.
const REF_ORPHAN_TTL: u64 = 45 * 24 * 3_600;
/// `REF_ORPHAN_MAX`, for each conversation.
const REF_ORPHAN_MAX: usize = 4_096;
/// `DELETE_RATE_LIMIT`: one record of kind `0x05` in this time, in seconds,
/// for each conversation.
const DELETE_RATE_LIMIT: u64 = 10;
/// The name of the time of the last deletion request of a conversation,
/// before its identifier.
const LAST_DELETE_SETTING: &[u8] = b"last-delete/";

/// The table of the settings of this device. A row holds one value under
/// the name of its setting.
const SETTINGS: TableId = TableId(0x0A);
/// The stored form of each notify queue of Part 8 §8.5.2, under its
/// `RecipientId`.
pub(crate) const NOTIFY_STATE: TableId = TableId(0x1D);
const AUTO_LOCK_SETTING: &[u8] = b"auto-lock";
/// The automatic download limit of this device, in bytes (`IMP-167`).
pub(crate) const AUTO_DOWNLOAD_SETTING: &[u8] = b"auto-download";
/// Whether the automatic download waits for a network with no cost by the
/// byte (`IMP-168`).
pub(crate) const UNMETERED_ONLY_SETTING: &[u8] = b"auto-download-unmetered";
/// `AUTO_DOWNLOAD_DEFAULT` of Part 12 §12.7, which equals
/// `LARGE_FILE_WARN`.
pub const AUTO_DOWNLOAD_DEFAULT: u64 = umbra_core::attach::LARGE_FILE_WARN;
/// The highest epoch of a directory root that this device verified
/// (Part 10 rule `REL-034`).
const DIRECTORY_EPOCH_SETTING: &[u8] = b"directory-epoch";
/// The pinned ingress relays of this device (Part 10 §10.6.1).
const INGRESS_PINS_SETTING: &[u8] = b"ingress-pins";
/// The idle limit under the setting "when the app leaves the screen". The
/// platform locks at that moment, and this limit covers a device that stays
/// on the screen with no action.
const AUTO_LOCK_ON_LEAVE_IDLE: u64 = 5 * 60;

/// The bytes of a contact row and of an invitation row before the stored
/// form: the `RecipientId` of the queue.
const QUEUE_ID_LEN: usize = 32;

/// The state of the client node that the store holds between two runs.
pub struct StoredNetwork {
    /// Each contact, with its conversation and its stored form.
    pub contacts: Vec<(ConversationId, Zeroizing<Vec<u8>>)>,
    /// The stored form of each invitation that waits.
    pub invitations: Vec<Zeroizing<Vec<u8>>>,
    /// The stored form of each notify queue of Part 8 §8.5.2.
    pub notify_queues: Vec<Zeroizing<Vec<u8>>>,
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
    files: FileQueues,
    groups: groups::GroupQueues,
    auto_lock: AutoLock,
    /// The records for the sync channels (Part 7 §7.5).
    sync_out: VecDeque<sync::SyncSend>,
    /// The records that a peer handed to this device, which the peer
    /// publishes, thus their send publishes nothing.
    synced_out: BTreeSet<MsgRef>,
    /// The blinded subject of each contact conversation (`DEV-292`).
    subjects: BTreeMap<ConversationId, [u8; 32]>,
}

/// One record for the commit path: of a contact, or of the sync channel.
struct Record {
    conversation: ConversationId,
    app: Vec<u8>,
    /// Whether the user wrote the record, on another device of the set.
    from_user: bool,
    /// Whether the record came on a sync channel (`DEV-268`).
    synced: bool,
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

/// The row of a record that waits for the send path. It holds no value:
/// the row of the message holds the record.
fn outbox_row() -> Vec<u8> {
    vec![0, 0]
}

/// What a stored record of kind `0x05` is. A placeholder names its own
/// `msg_id`: it stands in the row of the message that a deletion took. A
/// request names another message: it is the record of this device that
/// waits for its relay, and no view shows it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tombstone {
    Placeholder,
    Request,
}

fn tombstone_of(parsed: &AppMessage<'_>) -> Result<Option<Tombstone>, Error> {
    if parsed.kind != AppKind::Delete {
        return Ok(None);
    }
    let body = DeleteBody::parse(parsed.body)?;
    Ok(Some(if body.targets == [parsed.msg_id] {
        Tombstone::Placeholder
    } else {
        Tombstone::Request
    }))
}

/// An encoded deletion record.
fn deletion_record(msg_id: [u8; 16], sent_at: u64, target: [u8; 16]) -> Result<Vec<u8>, Error> {
    let body = DeleteBody {
        scope: DeleteScope::OtherParty,
        targets: vec![target],
    };
    let mut encoded = vec![0u8; body.len()];
    body.encode(&mut encoded)?;
    let record = AppMessage {
        kind: AppKind::Delete,
        msg_id,
        sent_at,
        body: &encoded,
    };
    let mut app = vec![0u8; record.len()];
    record.encode(&mut app)?;
    Ok(app)
}

/// The record with a new innermost text (`WIR-261`). A reply keeps its
/// target and each other field (`WIR-262`), and a record of another kind
/// takes no edit (`WIR-260`, `WIR-081`).
fn with_text(app: &[u8], text: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    let body = match parsed.kind {
        AppKind::Text => Zeroizing::new(text.to_vec()),
        AppKind::Rich => {
            let rich = RichRecord::parse(parsed.body, Channel::Pairwise)?;
            if rich.inner_kind != AppKind::Text {
                return Err(Error::Malformed);
            }
            let changed = RichRecord {
                inner_body: text,
                ..rich
            };
            let mut encoded = Zeroizing::new(vec![0u8; changed.len()]);
            changed.encode(Channel::Pairwise, &mut encoded)?;
            encoded
        }
        _ => return Err(Error::Malformed),
    };
    let record = AppMessage {
        kind: parsed.kind,
        msg_id: parsed.msg_id,
        sent_at: parsed.sent_at,
        body: &body,
    };
    let mut changed = Zeroizing::new(vec![0u8; record.len()]);
    record.encode(&mut changed)?;
    Ok(changed)
}

/// A stored message with a new text, under the same header.
fn row_with_text(plain: &[u8], text: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let prefix = plain.get(..MESSAGE_PREFIX).ok_or(Error::Integrity)?;
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    Ok(Zeroizing::new(
        [prefix, with_text(app, text)?.as_slice()].concat(),
    ))
}

/// The placeholder of a stored message: the same row with the same header,
/// and a record in the place of its content that names itself. DEV-100: the
/// content is overwritten, and the row is not hidden alone.
fn placeholder_of(plain: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let prefix = plain.get(..MESSAGE_PREFIX).ok_or(Error::Integrity)?;
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    let record = deletion_record(parsed.msg_id, parsed.sent_at, parsed.msg_id)?;
    Ok(Zeroizing::new([prefix, &record].concat()))
}

/// The text of a record: the body of a text, or the inner body of a rich
/// record around a text. Each other kind has no text.
fn text_of<'a>(parsed: &AppMessage<'a>) -> Result<&'a [u8], Error> {
    match parsed.kind {
        AppKind::Text => Ok(parsed.body),
        AppKind::Rich => {
            let rich = RichRecord::parse(parsed.body, Channel::Pairwise)?;
            if rich.inner_kind != AppKind::Text {
                return Err(Error::Malformed);
            }
            Ok(rich.inner_body)
        }
        _ => Err(Error::Malformed),
    }
}

/// The place of `reply_target` in an encoded record with a rich body, or
/// `None` for a record that answers no message. The field follows the
/// version byte of the rich record.
fn reply_field(app: &[u8]) -> Result<Option<core::ops::Range<usize>>, Error> {
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    if parsed.kind != AppKind::Rich {
        return Ok(None);
    }
    let rich = RichRecord::parse(parsed.body, Channel::Pairwise)?;
    if rich.reply_target == [0; 16] {
        return Ok(None);
    }
    let body_at = app.len().saturating_sub(parsed.body.len());
    let at = body_at.saturating_add(1);
    Ok(Some(at..at.saturating_add(16)))
}

/// WIR-170: a stored record holds `reply_target` as the keyed reference, and
/// not as the raw `msg_id` of the wire.
fn keep_reply_as_reference(app: &mut [u8], key: &Secret<32>) -> Result<(), Error> {
    let Some(field) = reply_field(app)? else {
        return Ok(());
    };
    let raw: [u8; 16] = app
        .get(field.clone())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Integrity)?;
    let reference = msg_ref(key, &raw);
    app.get_mut(field)
        .ok_or(Error::Integrity)?
        .copy_from_slice(&reference);
    Ok(())
}

/// The held receipts of one peer and one kind: the conversation, the hold,
/// and the row of each target.
type PeerHold = (ConversationId, ReceiptHold, Vec<(RowId, [u8; 16])>);

fn held_receipt(
    conversation: ConversationId,
    kind: AppKind,
    target: &[u8; 16],
    at: u64,
) -> Vec<u8> {
    [
        conversation.0.as_slice(),
        &[kind as u8],
        target,
        &at.to_be_bytes(),
    ]
    .concat()
}

/// The natural key of a held receipt. One target holds one receipt of each
/// kind.
fn held_receipt_key(conversation: ConversationId, kind: AppKind, target: &[u8; 16]) -> Vec<u8> {
    [conversation.0.as_slice(), &[kind as u8], target].concat()
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
        Self::create_with_seed(backend, element, passphrase, cost, now, seed, rng)
    }

    /// Makes the store of a device under a root seed that a restore of
    /// Part 4 §4.7.2 gave: `K_store` comes from it, thus each row of the
    /// backup takes its place again.
    pub fn create_with_seed<R: CryptoRng + ?Sized>(
        backend: B,
        element: E,
        passphrase: &[u16],
        cost: Cost,
        now: u64,
        seed: Secret<32>,
        rng: &mut R,
    ) -> Result<Self, Error> {
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
        let mut client = Client {
            element,
            header,
            state: State::Unlocked(Box::new(Open {
                store,
                device_set_key: root.device_set_key(),
            })),
            events: VecDeque::new(),
            outgoing: VecDeque::new(),
            sync_out: VecDeque::new(),
            synced_out: BTreeSet::new(),
            subjects: BTreeMap::new(),
            files: FileQueues::default(),
            groups: groups::GroupQueues::default(),
            auto_lock: AutoLock::new(now),
        };
        // IDN-070: the recovery code comes at the first launch.
        client.recovery_code(rng)?;
        Ok(client)
    }

    /// Opens the store of a device that exists, in the locked state.
    pub fn open(backend: B, element: E, header: WrapHeader, now: u64) -> Self {
        Client {
            element,
            header,
            state: State::Locked(backend),
            events: VecDeque::new(),
            outgoing: VecDeque::new(),
            sync_out: VecDeque::new(),
            synced_out: BTreeSet::new(),
            subjects: BTreeMap::new(),
            files: FileQueues::default(),
            groups: groups::GroupQueues::default(),
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
        self.requeue_transfers()?;
        let seconds = self.auto_lock_seconds()?;
        self.apply_auto_lock(seconds);
        self.auto_lock.touch(now);
        Ok(())
    }

    /// Locks the client: `K_store` leaves RAM, and each record that waits
    /// for the send path stays in the store.
    pub fn lock(&mut self) {
        if let State::Unlocked(open) = core::mem::replace(&mut self.state, State::Closed) {
            self.state = State::Locked(open.store.lock());
            self.outgoing.clear();
            // A file job holds the file in the clear, and a group job an
            // owner credential, thus both leave the memory with the key.
            // The store brings them back at the unlock.
            self.files = FileQueues::default();
            self.groups = groups::GroupQueues::default();
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
    /// (`IMP-132`): each change of the node state, and each record that the
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
        let mut records = Vec::with_capacity(received.len());
        for (contact, app) in received {
            records.push(Record {
                conversation: self.conversation_for(&contact.0)?,
                app: app.clone(),
                from_user: false,
                synced: false,
            });
        }
        self.commit_records(changes, &records, now_ms, rng)
    }

    /// The commit of [`Client::commit_network`], for the records of a
    /// contact and for the records that a sync channel gave (Part 7 §7.5).
    /// A synced record of the user takes the direction of this device, and
    /// the owner of the channels sends one that a peer handed to it
    /// (`DEV-047`, `DEV-048`).
    fn commit_records<R: CryptoRng + ?Sized>(
        &mut self,
        changes: &[StateChange],
        records: &[Record],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let owns = self.owns_channels()?;
        let device_peers = self.device_peers()?;
        let mut sends_delivery = Vec::new();
        for record in records.iter().filter(|record| !record.synced) {
            if self.receipt_settings(record.conversation)?.delivery {
                sends_delivery.push(record.conversation);
            }
        }
        let mut sync_bodies: Vec<(ConversationId, Vec<u8>)> = Vec::new();
        let mut to_publish: Vec<(ConversationId, Vec<u8>)> = Vec::new();
        let mut handoffs: Vec<Outgoing> = Vec::new();
        // IMP-167, IMP-168: a file above this size waits for a tap.
        let limit = self.download_limit_now()?;
        let open = self.open_mut()?;
        // The batch borrows the store, thus each row identifier and each
        // duplicate check comes first.
        enum Planned {
            Put(TableId, RowId, Option<RowId>, Zeroizing<Vec<u8>>),
            Delete(TableId, RowId),
        }
        let mut planned = Vec::new();
        let mut wanted: Vec<DownloadJob> = Vec::new();
        let mut control: Vec<(ConversationId, Vec<u8>)> = Vec::new();
        // The requests of Part 11 §11.4.3 of a member that lacks an epoch.
        let mut key_requests: Vec<(ConversationId, Vec<u8>)> = Vec::new();
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
                StateChange::NotifyQueue { queue, state } => Planned::Put(
                    NOTIFY_STATE,
                    open.store.row_id(NOTIFY_STATE, queue),
                    None,
                    Zeroizing::new([queue.as_slice(), state].concat()),
                ),
                StateChange::NotifyQueueEnded { queue } => {
                    Planned::Delete(NOTIFY_STATE, open.store.row_id(NOTIFY_STATE, queue))
                }
            });
        }
        let mut events = Vec::new();
        for record in records {
            let app = &record.app;
            let conversation = record.conversation;
            let from_user = record.from_user;
            let parsed = AppMessage::parse(app, Channel::Pairwise)?;
            // DEV-052: a sync channel carries kind 0x20 alone, and no view
            // shows its records.
            if device_peers.contains(&conversation) {
                if parsed.kind == AppKind::DeviceSet {
                    sync_bodies.push((conversation, parsed.body.to_vec()));
                }
                continue;
            }
            // DEV-050: kind 0x20 on a pairwise channel changes nothing.
            if parsed.kind == AppKind::DeviceSet {
                continue;
            }
            if !record.synced && owns {
                to_publish.push((conversation, app.clone()));
            }
            // The owner of the channels sends each record that a peer
            // handed to it. The record of an edit, a deletion, or a reaction
            // waits in a request row, as one of this device does.
            let handoff = record.synced && from_user && owns;
            if handoff
                && matches!(
                    parsed.kind,
                    AppKind::Reaction | AppKind::Edit | AppKind::Delete
                )
            {
                let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
                let natural = [conversation.0.as_slice(), &reference].concat();
                let row = open.store.row_id(TableId::MESSAGE, &natural);
                let queued = handoffs.iter().any(|held| held.message.0 == row);
                if queued || open.store.get(TableId::MESSAGE, &row)?.is_some() {
                    continue;
                }
                planned.push(Planned::Put(
                    TableId::MESSAGE,
                    row,
                    Some(conversation.0),
                    stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, app),
                ));
                planned.push(Planned::Put(
                    OUTBOX,
                    row,
                    None,
                    Zeroizing::new(outbox_row()),
                ));
                handoffs.push(Outgoing {
                    message: MsgRef(row),
                    conversation,
                    app: app.clone(),
                });
            }
            let direction = if from_user { OUTGOING } else { INCOMING };
            if let Some(reported) = Delivery::of_receipt(parsed.kind) {
                // A receipt is no message. A body that does not parse
                // changes nothing, and it ends no batch.
                let targets =
                    ReceiptBody::parse(parsed.body).map_or(Vec::new(), |body| body.targets);
                let mut named = Vec::new();
                for target in targets {
                    let reference = msg_ref(&open.device_set_key, &target);
                    let natural = [conversation.0.as_slice(), &reference].concat();
                    let row = open.store.row_id(TableId::MESSAGE, &natural);
                    let Some(plain) = open.store.get(TableId::MESSAGE, &row)? else {
                        continue;
                    };
                    // WIR-293: a receipt names a message of this device to
                    // this peer.
                    if info_of(&plain)?.outgoing {
                        named.push((row, Zeroizing::new(plain)));
                    }
                }
                if reported == Delivery::Read {
                    // WIR-514: the peer saw each message up to the newest
                    // one that the receipt names. A message that no relay
                    // took is not one of them.
                    let mut up_to = 0;
                    for (_, plain) in &named {
                        up_to = up_to.max(info_of(plain)?.stored_at_ms);
                    }
                    for (row, plain) in open.store.list(TableId::MESSAGE, Some(&conversation.0))? {
                        let info = info_of(&plain)?;
                        let is_sent =
                            matches!(info.delivery, Delivery::Accepted | Delivery::Delivered);
                        let is_named = named.iter().any(|(held, _)| *held == row);
                        if info.outgoing && is_sent && info.stored_at_ms <= up_to && !is_named {
                            named.push((row, Zeroizing::new(plain)));
                        }
                    }
                }
                for (row, mut plain) in named {
                    // A state goes up only.
                    if !info_of(&plain)?.delivery.is_below(reported) {
                        continue;
                    }
                    *plain.get_mut(1).ok_or(Error::Integrity)? = reported as u8;
                    planned.push(Planned::Put(
                        TableId::MESSAGE,
                        row,
                        Some(conversation.0),
                        plain,
                    ));
                    planned.push(Planned::Delete(OUTBOX, row));
                    events.push(Event::Delivery {
                        message: MsgRef(row),
                        delivery: reported,
                    });
                }
                continue;
            }
            if parsed.kind == AppKind::GroupControl {
                // The join flow of Part 11 §11.9.1 runs after this loop,
                // because it reads and writes groups of its own. The device
                // that owns the channels runs it.
                if !record.synced {
                    control.push((conversation, parsed.body.to_vec()));
                }
                continue;
            }
            if parsed.kind == AppKind::KeyRequest {
                if !record.synced {
                    key_requests.push((conversation, parsed.body.to_vec()));
                }
                continue;
            }
            if parsed.kind == AppKind::Reaction {
                // A reaction is no message. One that does not parse, one
                // with a text in the place of an emoji, and one to a message
                // that this device does not hold change nothing (`WIR-282`).
                let Ok(reaction) = ReactionBody::parse(parsed.body) else {
                    continue;
                };
                if !is_emoji(reaction.emoji) {
                    continue;
                }
                let reference = msg_ref(&open.device_set_key, &reaction.target);
                let natural = [conversation.0.as_slice(), &reference].concat();
                let target = open.store.row_id(TableId::MESSAGE, &natural);
                let Some(held) = open.store.get(TableId::MESSAGE, &target)? else {
                    continue;
                };
                if info_of(&held)?.deleted || is_request(&held)? {
                    continue;
                }
                let plain = reaction_row(conversation, &reference, direction, reaction.emoji);
                let row = open.store.row_id(REACTION, &plain);
                let exists = open.store.get(REACTION, &row)?.is_some();
                match reaction.action {
                    ReactionAction::Add if !exists => {
                        let mut of_contact = 0usize;
                        for (_, other) in open.store.list(REACTION, Some(&conversation.0))? {
                            let same = other.get(16..REACTION_PREFIX)
                                == Some([reference.as_slice(), &[direction]].concat().as_slice());
                            of_contact = of_contact.saturating_add(usize::from(same));
                        }
                        if of_contact >= REACTIONS_MAX {
                            continue;
                        }
                        planned.push(Planned::Put(
                            REACTION,
                            row,
                            Some(conversation.0),
                            Zeroizing::new(plain),
                        ));
                    }
                    // WIR-281: the same sender, emoji, and target.
                    ReactionAction::Remove if exists => {
                        planned.push(Planned::Delete(REACTION, row))
                    }
                    _ => continue,
                }
                events.push(Event::Reacted {
                    conversation,
                    message: MsgRef(target),
                });
                continue;
            }
            if parsed.kind == AppKind::Edit {
                // An edit is no message. A body that does not parse
                // changes nothing.
                let Ok(edit) = EditBody::parse(parsed.body) else {
                    continue;
                };
                let reference = msg_ref(&open.device_set_key, &edit.target);
                let natural = [conversation.0.as_slice(), &reference].concat();
                let row = open.store.row_id(TableId::MESSAGE, &natural);
                match open.store.get(TableId::MESSAGE, &row)? {
                    Some(plain) => {
                        let plain = Zeroizing::new(plain);
                        let info = info_of(&plain)?;
                        let count = match open.store.get(REVISION, &row)? {
                            None => 0,
                            Some(count) => *count.first().ok_or(Error::Integrity)?,
                        };
                        // WIR-082: the sender of the target alone. DEV-087:
                        // inside the window from the store time of this
                        // device. DEV-088: below the limit.
                        let in_window = now_ms.saturating_sub(info.stored_at_ms) < EDIT_WINDOW_MS;
                        if info.outgoing != from_user
                            || info.deleted
                            || !in_window
                            || count >= EDIT_MAX
                        {
                            continue;
                        }
                        // WIR-260: a target with no text takes no edit.
                        let Ok(changed) = row_with_text(&plain, edit.new_body.as_bytes()) else {
                            continue;
                        };
                        // The earlier text goes: the row gets a new key.
                        planned.push(Planned::Put(
                            TableId::MESSAGE,
                            row,
                            Some(conversation.0),
                            changed,
                        ));
                        planned.push(Planned::Put(
                            REVISION,
                            row,
                            None,
                            Zeroizing::new(vec![count.saturating_add(1)]),
                        ));
                        events.push(Event::Edited {
                            conversation,
                            message: MsgRef(row),
                        });
                    }
                    // DEV-093: the target did not arrive yet. A deletion
                    // that waits for the same target stays.
                    None => {
                        let pending = open.store.row_id(PENDING, &natural);
                        let is_deleted = open
                            .store
                            .get(PENDING, &pending)?
                            .is_some_and(|entry| entry.len() == PENDING_ROW_LEN);
                        let held = open.store.list(PENDING, Some(&conversation.0))?.len();
                        if is_deleted || held >= REF_ORPHAN_MAX {
                            continue;
                        }
                        let entry = [
                            conversation.0.as_slice(),
                            &reference,
                            &(now_ms / 1_000).to_be_bytes(),
                            edit.new_body.as_bytes(),
                        ]
                        .concat();
                        planned.push(Planned::Put(
                            PENDING,
                            pending,
                            Some(conversation.0),
                            Zeroizing::new(entry),
                        ));
                    }
                }
                continue;
            }
            if parsed.kind == AppKind::Delete {
                // A deletion is no message. WIR-084: a contact deletes for
                // the other party, and a record of another scope, or one
                // that does not parse, changes nothing.
                let targets = match DeleteBody::parse(parsed.body) {
                    Ok(body) if body.scope == DeleteScope::OtherParty => body.targets,
                    _ => Vec::new(),
                };
                for target in targets {
                    let reference = msg_ref(&open.device_set_key, &target);
                    let natural = [conversation.0.as_slice(), &reference].concat();
                    let row = open.store.row_id(TableId::MESSAGE, &natural);
                    match open.store.get(TableId::MESSAGE, &row)? {
                        Some(plain) => {
                            let plain = Zeroizing::new(plain);
                            // DEV-081, DEV-085: the contact names a message
                            // that the contact sent, and no other one.
                            if info_of(&plain)?.outgoing != from_user || info_of(&plain)?.deleted {
                                continue;
                            }
                            planned.push(Planned::Put(
                                TableId::MESSAGE,
                                row,
                                Some(conversation.0),
                                placeholder_of(&plain)?,
                            ));
                            // A placeholder holds no reaction.
                            for (held, other) in open.store.list(REACTION, Some(&conversation.0))? {
                                if other.get(16..32) == Some(reference.as_slice()) {
                                    planned.push(Planned::Delete(REACTION, held));
                                }
                            }
                            planned.push(Planned::Delete(REVISION, row));
                            // The contact uploaded the file, thus this device
                            // holds no credential that erases a chunk.
                            planned.push(Planned::Delete(FILE_STATE, row));
                            planned.push(Planned::Delete(FILE_DATA, row));
                            events.push(Event::Deleted {
                                conversation,
                                message: MsgRef(row),
                            });
                        }
                        // DEV-093: the target did not arrive yet.
                        None => {
                            let held = open.store.list(PENDING, Some(&conversation.0))?.len();
                            if held >= REF_ORPHAN_MAX {
                                continue;
                            }
                            let pending = open.store.row_id(PENDING, &natural);
                            let entry = [
                                conversation.0.as_slice(),
                                &reference,
                                &(now_ms / 1_000).to_be_bytes(),
                            ]
                            .concat();
                            planned.push(Planned::Put(
                                PENDING,
                                pending,
                                Some(conversation.0),
                                Zeroizing::new(entry),
                            ));
                        }
                    }
                }
                continue;
            }
            let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            let message = MsgRef(row);
            // A deletion that came first takes the message at its arrival:
            // the view shows nothing at that position (Part 7 §7.5.6).
            let pending = open.store.row_id(PENDING, &natural);
            let mut edited_text = None;
            if let Some(entry) = open.store.get(PENDING, &pending)? {
                let entry = Zeroizing::new(entry);
                let at: [u8; 8] = entry
                    .get(32..PENDING_ROW_LEN)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?;
                planned.push(Planned::Delete(PENDING, pending));
                // DEV-095: an entry above its time counts for nothing.
                if (now_ms / 1_000).saturating_sub(u64::from_be_bytes(at)) < REF_ORPHAN_TTL {
                    let text = entry.get(PENDING_ROW_LEN..).ok_or(Error::Integrity)?;
                    // An entry with no text is a deletion.
                    if text.is_empty() {
                        continue;
                    }
                    edited_text = Some(Zeroizing::new(text.to_vec()));
                }
            }
            let in_batch = events.iter().any(|event| {
                matches!(event, Event::Message { message: m, .. } | Event::Delivery { message: m, .. } if *m == message)
            });
            if in_batch || open.store.get(TableId::MESSAGE, &row)?.is_some() {
                continue;
            }
            if handoff {
                // The record goes as the peer wrote it: its reply target
                // becomes a reference at the send (`WIR-071`).
                planned.push(Planned::Put(
                    TableId::MESSAGE,
                    row,
                    Some(conversation.0),
                    stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, app),
                ));
                planned.push(Planned::Put(
                    OUTBOX,
                    row,
                    None,
                    Zeroizing::new(outbox_row()),
                ));
                if parsed.kind == AppKind::Attachment {
                    let (state, _) = files::incoming_state_row(parsed.body, 0);
                    planned.push(Planned::Put(
                        FILE_STATE,
                        row,
                        Some(conversation.0),
                        Zeroizing::new(state),
                    ));
                }
                handoffs.push(Outgoing {
                    message,
                    conversation,
                    app: app.clone(),
                });
                events.push(Event::Delivery {
                    message,
                    delivery: Delivery::Queued,
                });
                continue;
            }
            let mut kept = Zeroizing::new(app.clone());
            // An edit that came first gives the message its text and the
            // edited mark. A target with no text keeps what it has.
            if let Some(text) = edited_text {
                if let Ok(changed) = with_text(&kept, &text) {
                    kept = changed;
                    planned.push(Planned::Put(REVISION, row, None, Zeroizing::new(vec![1])));
                }
            }
            keep_reply_as_reference(&mut kept, &open.device_set_key)?;
            // A record of the user from another device left the owner of
            // the channels, or waits there.
            let delivery = if from_user {
                Delivery::Accepted
            } else {
                Delivery::Delivered
            };
            planned.push(Planned::Put(
                TableId::MESSAGE,
                row,
                Some(conversation.0),
                stored_message(direction, delivery, conversation, now_ms, &kept),
            ));
            if parsed.kind == AppKind::Attachment {
                let (state, descriptor) = files::incoming_state_row(parsed.body, limit);
                planned.push(Planned::Put(
                    FILE_STATE,
                    row,
                    Some(conversation.0),
                    Zeroizing::new(state),
                ));
                if let Some(descriptor) = descriptor {
                    wanted.push(DownloadJob {
                        message,
                        descriptor: Box::new(descriptor),
                    });
                }
            }
            // A record of the user raises no alert.
            events.push(if from_user {
                Event::Delivery { message, delivery }
            } else {
                Event::Message {
                    conversation,
                    message,
                }
            });
            // NET-041: this device holds the message now.
            if !record.synced && sends_delivery.contains(&conversation) {
                let key = held_receipt_key(conversation, AppKind::DeliveryReceipt, &parsed.msg_id);
                planned.push(Planned::Put(
                    RECEIPT,
                    open.store.row_id(RECEIPT, &key),
                    Some(conversation.0),
                    Zeroizing::new(held_receipt(
                        conversation,
                        AppKind::DeliveryReceipt,
                        &parsed.msg_id,
                        now_ms / 1_000,
                    )),
                ));
            }
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
        self.files.downloads.extend(wanted);
        for outgoing in handoffs {
            self.synced_out.insert(outgoing.message);
            self.outgoing.push_back(outgoing);
        }
        for (conversation, body) in control {
            self.on_pairwise_control(conversation, &body, rng)?;
        }
        for (_, body) in key_requests {
            self.on_pairwise_key_request(&body, now_ms, rng)?;
        }
        // DEV-268: each record of a contact goes to each device of the set.
        for (conversation, app) in to_publish {
            self.publish_sync(conversation, &app, false, None, now_ms / 1_000, rng)?;
        }
        if !sync_bodies.is_empty() {
            let synced = self.take_sync_bodies(sync_bodies, now_ms / 1_000, rng)?;
            let records: Vec<Record> = synced
                .into_iter()
                .map(|synced| Record {
                    conversation: synced.conversation,
                    app: synced.app,
                    from_user: synced.from_user,
                    synced: true,
                })
                .collect();
            if !records.is_empty() {
                self.commit_records(&[], &records, now_ms, rng)?;
            }
        }
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
        let mut notify_queues = Vec::new();
        for (_, plain) in store.list(NOTIFY_STATE, None)? {
            notify_queues.push(state_of(plain)?);
        }
        Ok(StoredNetwork {
            contacts,
            invitations,
            notify_queues,
        })
    }

    /// The conversations of the device: one for each contact, and one for
    /// each group of Part 11. The list needs no network. A sync channel of
    /// Part 7 `DEV-286` is no conversation.
    pub fn conversations(&self) -> Result<Vec<ConversationId>, Error> {
        let device_peers = self.device_peers()?;
        let store = &self.open_ref()?.store;
        let rows = store.list(TableId::CONTACT, None)?;
        let mut out: Vec<ConversationId> = rows
            .into_iter()
            .map(|(row, plain)| {
                drop(Zeroizing::new(plain));
                ConversationId(row)
            })
            .filter(|conversation| !device_peers.contains(conversation))
            .collect();
        out.extend(self.group_conversations()?);
        Ok(out)
    }

    /// The idle time of the auto-lock, in seconds. Zero means that the
    /// platform locks when the app leaves the screen. With no stored value
    /// the default of `IMP-119` holds.
    pub fn auto_lock_seconds(&self) -> Result<u64, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, AUTO_LOCK_SETTING);
        let Some(plain) = store.get(SETTINGS, &row)? else {
            return Ok(AUTO_LOCK_DEFAULT);
        };
        let seconds: [u8; 8] = plain.as_slice().try_into().map_err(|_| Error::Integrity)?;
        Ok(u64::from_be_bytes(seconds))
    }

    /// The largest padded size of a received file whose download starts at
    /// once (`IMP-167`). Zero turns the automatic download off, and
    /// `u64::MAX` downloads each file.
    pub fn auto_download_limit(&self) -> Result<u64, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, AUTO_DOWNLOAD_SETTING);
        let Some(plain) = store.get(SETTINGS, &row)? else {
            return Ok(AUTO_DOWNLOAD_DEFAULT);
        };
        let bytes: [u8; 8] = plain.as_slice().try_into().map_err(|_| Error::Integrity)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Whether the automatic download waits for a network with no cost by
    /// the byte (`IMP-168`). Off with no stored value.
    pub fn unmetered_only(&self) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, UNMETERED_ONLY_SETTING);
        Ok(store
            .get(SETTINGS, &row)?
            .is_some_and(|plain| plain.first() == Some(&1)))
    }

    /// Limits the automatic download to a network with no cost by the
    /// byte, or takes that limit away.
    pub fn set_unmetered_only<R: CryptoRng + ?Sized>(
        &mut self,
        is_on: bool,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, UNMETERED_ONLY_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &[u8::from(is_on)], rng)?;
        Ok(batch.commit()?)
    }

    /// Sets the automatic download limit of this device. It acts on each
    /// file that arrives after it, and on none that arrived before.
    pub fn set_auto_download_limit<R: CryptoRng + ?Sized>(
        &mut self,
        bytes: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, AUTO_DOWNLOAD_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &bytes.to_be_bytes(), rng)?;
        Ok(batch.commit()?)
    }

    /// The highest epoch of a directory root that this device verified, or
    /// zero before the first one.
    pub fn directory_epoch(&self) -> Result<u64, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, DIRECTORY_EPOCH_SETTING);
        let Some(plain) = store.get(SETTINGS, &row)? else {
            return Ok(0);
        };
        let epoch: [u8; 8] = plain.as_slice().try_into().map_err(|_| Error::Integrity)?;
        Ok(u64::from_be_bytes(epoch))
    }

    /// Keeps the epoch of a root that the device verified. The value only
    /// goes up, thus a root that a later run gets cannot be an older one.
    pub fn set_directory_epoch<R: CryptoRng + ?Sized>(
        &mut self,
        epoch: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if epoch <= self.directory_epoch()? {
            return Ok(());
        }
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, DIRECTORY_EPOCH_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &epoch.to_be_bytes(), rng)?;
        batch.commit()?;
        Ok(())
    }

    /// The pinned ingress relays of this device, or none before the first
    /// relay set.
    pub fn ingress_pins(&self) -> Result<IngressPins, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, INGRESS_PINS_SETTING);
        match store.get(SETTINGS, &row)? {
            Some(plain) => IngressPins::parse(&plain).map_err(|_| Error::Integrity),
            None => Ok(IngressPins::empty()),
        }
    }

    /// Keeps the pinned ingress relays.
    pub fn set_ingress_pins<R: CryptoRng + ?Sized>(
        &mut self,
        pins: &IngressPins,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, INGRESS_PINS_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &pins.encode(), rng)?;
        batch.commit()?;
        Ok(())
    }

    /// Sets the idle time of the auto-lock. `IMP-119` bounds it at 30
    /// minutes, and a value above that bound is an error and no change.
    pub fn set_auto_lock<R: CryptoRng + ?Sized>(
        &mut self,
        seconds: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if seconds > AUTO_LOCK_MAX {
            return Err(Error::TooLong);
        }
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, AUTO_LOCK_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &seconds.to_be_bytes(), rng)?;
        batch.commit()?;
        self.apply_auto_lock(seconds);
        Ok(())
    }

    fn apply_auto_lock(&mut self, seconds: u64) {
        self.auto_lock.set_limit(if seconds == 0 {
            AUTO_LOCK_ON_LEAVE_IDLE
        } else {
            seconds
        });
    }

    /// A new header for the same `K_store` under `new` (`IMP-118`). The
    /// current passphrase proves that the user of the device asks. The
    /// platform writes the header beside the database, and then it gives it
    /// to [`Client::set_header`]. Each record key comes from `K_store`,
    /// thus no record changes.
    pub fn rewrap<R: CryptoRng + ?Sized>(
        &self,
        current: &[u16],
        new: &[u16],
        rng: &mut R,
    ) -> Result<WrapHeader, Error> {
        self.open_ref()?;
        if new.is_empty() {
            return Err(Error::Malformed);
        }
        let store_key = self
            .header
            .unwrap(&passphrase_bytes(current)?, &self.element)
            .map_err(|_| Error::WrongPassphrase)?;
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        Ok(WrapHeader::wrap(
            &store_key,
            &passphrase_bytes(new)?,
            self.header.cost,
            salt,
            nonce,
            &self.element,
        )?)
    }

    /// Takes the header that the platform wrote beside the database.
    pub fn set_header(&mut self, header: WrapHeader) {
        self.header = header;
    }

    /// The two pairwise identity keys of a conversation: the key of this
    /// device, and the key of the contact.
    fn identity_keys(&self, conversation: ConversationId) -> Result<([u8; 32], [u8; 32]), Error> {
        let store = &self.open_ref()?.store;
        let plain = store
            .get(TableId::CONTACT, &conversation.0)?
            .ok_or(Error::NotFound)?;
        let plain = Zeroizing::new(plain);
        let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
        Ok(stored_contact_keys(state, &self.root_identity()?)?)
    }

    /// The 60-digit safety number of a conversation, in groups of five
    /// (Part 4 §4.5). It needs no network.
    pub fn safety_number(&self, conversation: ConversationId) -> Result<String, Error> {
        let (own, peer) = self.identity_keys(conversation)?;
        Ok(safety_number(&own, &peer))
    }

    /// Records that the user verified `peer_static` for a conversation
    /// (`IDN-147`). The caller is the ceremony of the node after a user
    /// confirmation, or [`Client::verify_by_number`].
    pub fn set_verified<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        peer_static: &[u8; 32],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(TableId::VERIFICATION, &conversation.0);
        let plain = [
            conversation.0.as_slice(),
            peer_static,
            &now_ms.to_be_bytes(),
        ]
        .concat();
        let mut batch = open.store.begin();
        batch.put(TableId::VERIFICATION, row, None, &plain, rng)?;
        Ok(batch.commit()?)
    }

    /// Whether the user verified the key that the contact holds now. A
    /// state for an earlier key of the contact counts for nothing
    /// (`IDN-026`).
    pub fn is_verified(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(TableId::VERIFICATION, &conversation.0);
        let Some(plain) = store.get(TableId::VERIFICATION, &row)? else {
            return Ok(false);
        };
        if plain.get(..16) != Some(conversation.0.as_slice()) {
            return Err(Error::Integrity);
        }
        let (_, peer) = self.identity_keys(conversation)?;
        Ok(plain.get(16..48) == Some(peer.as_slice()))
    }

    /// Compares a safety number that the user scanned or typed with the
    /// number of this device, by its digits alone. A match is a
    /// verification by the user, and the store takes the state.
    pub fn verify_by_number<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        given: &str,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let digits = |text: &str| -> Vec<u8> { text.bytes().filter(u8::is_ascii_digit).collect() };
        let (own, peer) = self.identity_keys(conversation)?;
        if digits(given) != digits(&safety_number(&own, &peer)) {
            return Ok(false);
        }
        self.set_verified(conversation, &peer, now_ms, rng)?;
        Ok(true)
    }

    /// The read marker and the local name of a conversation. A
    /// conversation with no row has the marker zero and no name.
    fn conversation_meta(&self, conversation: ConversationId) -> Result<(u64, String), Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(CONVERSATION, &conversation.0);
        let Some(plain) = store.get(CONVERSATION, &row)? else {
            return Ok((0, String::new()));
        };
        // IMP-121: the plaintext names its owner.
        if plain.get(..16) != Some(conversation.0.as_slice()) {
            return Err(Error::Integrity);
        }
        let marker: [u8; 8] = plain
            .get(READ_UP_TO)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let name = plain.get(CONVERSATION_PREFIX..).ok_or(Error::Integrity)?;
        let name = core::str::from_utf8(name).map_err(|_| Error::Integrity)?;
        Ok((u64::from_be_bytes(marker), name.to_owned()))
    }

    fn put_conversation_meta<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        read_up_to: u64,
        name: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(CONVERSATION, &conversation.0);
        let mut plain = Vec::with_capacity(CONVERSATION_PREFIX.saturating_add(name.len()));
        plain.extend_from_slice(&conversation.0);
        plain.extend_from_slice(&read_up_to.to_be_bytes());
        plain.extend_from_slice(name.as_bytes());
        let mut batch = open.store.begin();
        batch.put(CONVERSATION, row, None, &plain, rng)?;
        Ok(batch.commit()?)
    }

    /// Gives a contact a name on this device. No peer and no relay learns
    /// it. An empty name takes the name away.
    pub fn set_contact_name<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        name: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
        let name = name.trim();
        if name.len() > CONTACT_NAME_MAX {
            return Err(Error::TooLong);
        }
        let (read_up_to, _) = self.conversation_meta(conversation)?;
        self.put_conversation_meta(conversation, read_up_to, name, rng)
    }

    /// The user saw each message of the conversation that the store holds
    /// at `now_ms`.
    pub fn mark_read<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (read_up_to, name) = self.conversation_meta(conversation)?;
        if now_ms <= read_up_to {
            return Ok(());
        }
        // NET-042: the user opened the conversation, and no other act gives
        // a read receipt.
        if self.receipt_settings(conversation)?.read {
            self.hold_read_receipts(conversation, read_up_to, now_ms / 1_000, rng)?;
        }
        self.put_conversation_meta(conversation, now_ms, &name, rng)?;
        self.auto_lock.touch(now_ms / 1_000);
        Ok(())
    }

    fn hold_read_receipts<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        read_up_to: u64,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        // WIR-514: a read receipt names the newest message that the user
        // saw, and it covers each earlier one.
        // The order of a conversation view: two messages of one batch hold
        // one store time.
        let mut newest: Option<((u64, u64, RowId), [u8; 16])> = None;
        for (row, plain) in open.store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            let info = info_of(&plain)?;
            if info.outgoing || info.stored_at_ms <= read_up_to {
                continue;
            }
            let order = (info.stored_at_ms, info.sent_at_ms, row);
            if newest.is_none_or(|(held, _)| order > held) {
                let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                let target = AppMessage::parse(app, Channel::Pairwise)?.msg_id;
                newest = Some((order, target));
            }
        }
        let Some((_, target)) = newest else {
            return Ok(());
        };
        // NET-307: the one that waited names an older message, and it goes.
        let mut earlier = Vec::new();
        for (row, plain) in open.store.list(RECEIPT, Some(&conversation.0))? {
            if plain.get(16) == Some(&(AppKind::ReadReceipt as u8)) {
                earlier.push(row);
            }
        }
        let key = held_receipt_key(conversation, AppKind::ReadReceipt, &target);
        let row = open.store.row_id(RECEIPT, &key);
        let plain = held_receipt(conversation, AppKind::ReadReceipt, &target, now);
        let mut batch = open.store.begin();
        for held in earlier {
            batch.delete(RECEIPT, held);
        }
        batch.put(RECEIPT, row, Some(conversation.0), &plain, rng)?;
        Ok(batch.commit()?)
    }

    /// Removes a message, or the placeholder of a deleted one, from this
    /// device (`DEV-105`). No record leaves the device, and the store erases
    /// the row and its key.
    pub fn delete_for_me(&mut self, message: &MsgRef) -> Result<(), Error> {
        self.outgoing.retain(|waiting| waiting.message != *message);
        self.files.uploads.retain(|job| job.message != *message);
        self.files.downloads.retain(|job| job.message != *message);
        let conversation = self.conversation_of_message(message)?;
        let reactions = self.reaction_rows(message, conversation)?;
        let erasures = self.file_erasures(message)?;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in reactions {
            batch.delete(REACTION, row);
        }
        batch.delete(TableId::MESSAGE, message.0);
        batch.delete(OUTBOX, message.0);
        batch.delete(REVISION, message.0);
        for table in [FILE_STATE, FILE_DATA, CHUNK_CRED] {
            batch.delete(table, message.0);
        }
        batch.commit()?;
        // ATT-161: a deletion of a record with a file that this device
        // uploaded erases each chunk at its relays.
        self.files.erasures.extend(erasures);
        Ok(())
    }

    /// The reactions to a message: those of this device first, and each
    /// party in the order of its emoji.
    pub fn reactions(&self, message: &MsgRef) -> Result<Vec<Reaction>, Error> {
        let open = self.open_ref()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        let mut found = Vec::new();
        for (_, row) in open.store.list(REACTION, Some(&conversation.0))? {
            let reference = row.get(16..32).ok_or(Error::Integrity)?;
            let natural = [conversation.0.as_slice(), reference].concat();
            if open.store.row_id(TableId::MESSAGE, &natural) != message.0 {
                continue;
            }
            let emoji = row.get(REACTION_PREFIX..).ok_or(Error::Integrity)?;
            found.push(Reaction {
                emoji: core::str::from_utf8(emoji)
                    .map_err(|_| Error::Integrity)?
                    .to_owned(),
                mine: row.get(32) == Some(&OUTGOING),
            });
        }
        found.sort_by(|a, b| (!a.mine, &a.emoji).cmp(&(!b.mine, &b.emoji)));
        Ok(found)
    }

    /// Adds the reaction of this device to a message, or removes it when the
    /// device holds it already. The table changes at once, and one record of
    /// kind `0x03` waits for the send path.
    pub fn react<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        emoji: &str,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if !is_emoji(emoji) {
            return Err(Error::Malformed);
        }
        let open = self.open_mut()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        if info_of(&plain)?.deleted || is_request(&plain)? {
            return Err(Error::Malformed);
        }
        let conversation = conversation_of(&plain)?;
        // A group carries a reaction on its own queue, and Part 11 gives
        // that path no rule yet. The view offers none, and this call
        // refuses one.
        if self.is_group(conversation)? {
            return Err(Error::Malformed);
        }
        let open = self.open_mut()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Pairwise)?.msg_id;
        let reference = msg_ref(&open.device_set_key, &target);
        let held = reaction_row(conversation, &reference, OUTGOING, emoji);
        let held_row = open.store.row_id(REACTION, &held);
        let exists = open.store.get(REACTION, &held_row)?.is_some();
        if !exists {
            let mut mine = 0usize;
            for (_, other) in open.store.list(REACTION, Some(&conversation.0))? {
                let same = other.get(16..REACTION_PREFIX)
                    == Some([reference.as_slice(), &[OUTGOING]].concat().as_slice());
                mine = mine.saturating_add(usize::from(same));
            }
            if mine >= REACTIONS_MAX {
                return Err(Error::TooLong);
            }
        }

        let body = ReactionBody {
            target,
            action: if exists {
                ReactionAction::Remove
            } else {
                ReactionAction::Add
            },
            emoji,
        };
        let mut encoded = vec![0u8; 19usize.saturating_add(emoji.len())];
        body.encode(&mut encoded)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::Reaction,
            msg_id,
            sent_at: now_ms,
            body: &encoded,
        };
        let mut request = vec![0u8; record.len()];
        record.encode(&mut request)?;
        let request_ref = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &request_ref].concat();
        let request_row = open.store.row_id(TableId::MESSAGE, &natural);
        let stored = stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, &request);

        let mut batch = open.store.begin();
        if exists {
            batch.delete(REACTION, held_row);
        } else {
            batch.put(REACTION, held_row, Some(conversation.0), &held, rng)?;
        }
        batch.put(
            TableId::MESSAGE,
            request_row,
            Some(conversation.0),
            &stored,
            rng,
        )?;
        batch.put(OUTBOX, request_row, None, &outbox_row(), rng)?;
        batch.commit()?;

        self.outgoing.push_back(Outgoing {
            message: MsgRef(request_row),
            conversation,
            app: request,
        });
        self.auto_lock.touch(now_ms / 1_000);
        Ok(())
    }

    /// Puts one record of this device into the pairwise send path.
    pub(super) fn push_outgoing(
        &mut self,
        message: MsgRef,
        conversation: ConversationId,
        app: Vec<u8>,
    ) {
        self.outgoing.push_back(Outgoing {
            message,
            conversation,
            app,
        });
    }

    /// Erases each reaction to a message, in a batch of the caller.
    fn reaction_rows(
        &self,
        message: &MsgRef,
        conversation: ConversationId,
    ) -> Result<Vec<RowId>, Error> {
        let open = self.open_ref()?;
        let mut rows = Vec::new();
        for (row, plain) in open.store.list(REACTION, Some(&conversation.0))? {
            let reference = plain.get(16..32).ok_or(Error::Integrity)?;
            let natural = [conversation.0.as_slice(), reference].concat();
            if open.store.row_id(TableId::MESSAGE, &natural) == message.0 {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Changes the text of a message that this device sent, to the text of
    /// `draft` (Part 7 §7.5.6). The row takes the new text at once, under a
    /// new key, and the earlier text goes. One record of kind `0x04` waits
    /// for the send path. The contact applies it inside `EDIT_WINDOW` of its
    /// own receive time, thus this device refuses an edit after that time
    /// of its own send, and after `EDIT_MAX` revisions.
    pub fn edit<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        draft: Draft,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if draft.is_empty() || draft.conversation() != self.conversation_of_message(message)? {
            return Err(Error::Malformed);
        }
        // An edit and a deletion of a group travel on its queue, and Part
        // 11 gives that path no rule yet.
        if self.is_group(draft.conversation())? {
            return Err(Error::Malformed);
        }
        let open = self.open_mut()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let info = info_of(&plain)?;
        if !info.outgoing || info.deleted || !info.has_text || is_request(&plain)? {
            return Err(Error::Malformed);
        }
        let count = match open.store.get(REVISION, &message.0)? {
            None => 0,
            Some(count) => *count.first().ok_or(Error::Integrity)?,
        };
        if count >= EDIT_MAX || now_ms.saturating_sub(info.stored_at_ms) >= EDIT_WINDOW_MS {
            return Err(Error::TooLong);
        }
        let conversation = conversation_of(&plain)?;
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Pairwise)?.msg_id;
        let text = core::str::from_utf8(draft.text()).map_err(|_| Error::Malformed)?;

        let body = EditBody {
            target,
            new_body: text,
        };
        let mut encoded = Zeroizing::new(vec![0u8; body.len()]);
        body.encode(&mut encoded)?;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let record = AppMessage {
            kind: AppKind::Edit,
            msg_id,
            sent_at: now_ms,
            body: &encoded,
        };
        let mut request = Zeroizing::new(vec![0u8; record.len()]);
        record.encode(&mut request)?;
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let request_row = open.store.row_id(TableId::MESSAGE, &natural);
        let stored = stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, &request);
        let changed = row_with_text(&plain, draft.text())?;
        let changed_app = changed
            .get(MESSAGE_PREFIX..)
            .ok_or(Error::Integrity)?
            .to_vec();

        let mut batch = open.store.begin();
        batch.put(
            TableId::MESSAGE,
            message.0,
            Some(conversation.0),
            &changed,
            rng,
        )?;
        batch.put(REVISION, message.0, None, &[count.saturating_add(1)], rng)?;
        batch.put(
            TableId::MESSAGE,
            request_row,
            Some(conversation.0),
            &stored,
            rng,
        )?;
        batch.put(OUTBOX, request_row, None, &outbox_row(), rng)?;
        batch.commit()?;

        // A message that the send path did not take yet goes with its new
        // text, and the edit follows it.
        for waiting in self.outgoing.iter_mut().filter(|w| w.message == *message) {
            waiting.app.clone_from(&changed_app);
        }
        self.outgoing.push_back(Outgoing {
            message: MsgRef(request_row),
            conversation,
            app: request.to_vec(),
        });
        self.auto_lock.touch(now_ms / 1_000);
        Ok(())
    }

    /// The conversation of a message.
    pub fn conversation_of_message(&self, message: &MsgRef) -> Result<ConversationId, Error> {
        let plain = Zeroizing::new(
            self.open_ref()?
                .store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        conversation_of(&plain)
    }

    /// Asks the contact to delete a message that this device sent. The
    /// content leaves this device at once (`DEV-106`), and a placeholder
    /// stands in its row. The request is one record of kind `0x05` for the
    /// send path. `DELETE_RATE_LIMIT` permits one such record in 10 seconds
    /// for one conversation, and a call before that time is
    /// [`Error::Busy`] and changes nothing.
    pub fn delete_for_everyone<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.is_group(self.conversation_of_message(message)?)? {
            return Err(Error::Malformed);
        }
        let open = self.open_mut()?;
        let plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let info = info_of(&plain)?;
        // A contact takes a deletion for a message of this device alone.
        if !info.outgoing || info.deleted || is_request(&plain)? {
            return Err(Error::Malformed);
        }
        let conversation = conversation_of(&plain)?;
        let reactions = self.reaction_rows(message, conversation)?;
        let erasures = self.file_erasures(message)?;
        let open = self.open_mut()?;
        let limit = [LAST_DELETE_SETTING, conversation.0.as_slice()].concat();
        let limit_row = open.store.row_id(SETTINGS, &limit);
        let now = now_ms / 1_000;
        if let Some(last) = open.store.get(SETTINGS, &limit_row)? {
            let last: [u8; 8] = last.as_slice().try_into().map_err(|_| Error::Integrity)?;
            if now.saturating_sub(u64::from_be_bytes(last)) < DELETE_RATE_LIMIT {
                return Err(Error::Busy);
            }
        }
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Pairwise)?.msg_id;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let request = deletion_record(msg_id, now_ms, target)?;
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let request_row = open.store.row_id(TableId::MESSAGE, &natural);
        let stored = stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, &request);

        let mut batch = open.store.begin();
        batch.put(
            TableId::MESSAGE,
            message.0,
            Some(conversation.0),
            &placeholder_of(&plain)?,
            rng,
        )?;
        // The message itself waits for no relay now, and a placeholder has
        // no edited mark, no reaction, and no file.
        batch.delete(OUTBOX, message.0);
        batch.delete(REVISION, message.0);
        for table in [FILE_STATE, FILE_DATA, CHUNK_CRED] {
            batch.delete(table, message.0);
        }
        for row in reactions {
            batch.delete(REACTION, row);
        }
        batch.put(
            TableId::MESSAGE,
            request_row,
            Some(conversation.0),
            &stored,
            rng,
        )?;
        batch.put(OUTBOX, request_row, None, &outbox_row(), rng)?;
        batch.put(SETTINGS, limit_row, None, &now.to_be_bytes(), rng)?;
        batch.commit()?;

        // ATT-161: the chunks of a file that this device uploaded go too.
        self.files.erasures.extend(erasures);
        self.files.uploads.retain(|job| job.message != *message);
        self.outgoing.retain(|waiting| waiting.message != *message);
        self.outgoing.push_back(Outgoing {
            message: MsgRef(request_row),
            conversation,
            app: request,
        });
        self.auto_lock.touch(now);
        Ok(())
    }

    /// Which receipts this device sends to the contact of a conversation.
    pub fn receipt_settings(&self, conversation: ConversationId) -> Result<ReceiptSettings, Error> {
        let store = &self.open_ref()?.store;
        let name = [RECEIPT_SETTING, conversation.0.as_slice()].concat();
        let flags = match store.get(SETTINGS, &store.row_id(SETTINGS, &name))? {
            None => 0,
            Some(plain) => *plain.first().ok_or(Error::Integrity)?,
        };
        Ok(ReceiptSettings {
            delivery: flags & SENDS_DELIVERY != 0,
            read: flags & SENDS_READ != 0,
        })
    }

    /// Sets the receipts of one contact. A kind that goes off erases each
    /// receipt of that kind that waits (`NET-054`).
    pub fn set_receipt_settings<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        settings: ReceiptSettings,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let name = [RECEIPT_SETTING, conversation.0.as_slice()].concat();
        let row = open.store.row_id(SETTINGS, &name);
        let flags =
            (u8::from(settings.delivery) * SENDS_DELIVERY) | (u8::from(settings.read) * SENDS_READ);
        let mut ended = Vec::new();
        for (held, plain) in open.store.list(RECEIPT, Some(&conversation.0))? {
            let kind = plain.get(16).copied();
            let is_on = match kind {
                Some(kind) if kind == AppKind::DeliveryReceipt as u8 => settings.delivery,
                Some(kind) if kind == AppKind::ReadReceipt as u8 => settings.read,
                _ => false,
            };
            if !is_on {
                ended.push(held);
            }
        }
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &[flags], rng)?;
        for held in ended {
            batch.delete(RECEIPT, held);
        }
        Ok(batch.commit()?)
    }

    /// The batch of receipts that may leave at `now`, or `None`. A receipt
    /// that waited for longer than `RECEIPT_MAX_HOLD` leaves the store here
    /// and goes to no peer (`NET-052`).
    pub fn due_receipt<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<Option<DueReceipt>, Error> {
        let open = self.open_mut()?;
        let mut stale = Vec::new();
        let mut due = None;
        for kind in [AppKind::DeliveryReceipt, AppKind::ReadReceipt] {
            // One hold for each peer and each kind: the rows of one batch.
            let mut holds: Vec<PeerHold> = Vec::new();
            for (row, plain) in open.store.list(RECEIPT, None)? {
                if plain.len() != RECEIPT_ROW_LEN {
                    return Err(Error::Integrity);
                }
                if plain.get(16) != Some(&(kind as u8)) {
                    continue;
                }
                let field = |at: usize, len: usize| plain.get(at..at.saturating_add(len));
                let conversation: [u8; 16] = field(0, 16)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?;
                let target: [u8; 16] = field(17, 16)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?;
                let at: [u8; 8] = field(33, 8)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Integrity)?;
                let at = u64::from_be_bytes(at);
                if now.saturating_sub(at) >= umbra_queue::params::RECEIPT_MAX_HOLD {
                    stale.push(row);
                    continue;
                }
                let conversation = ConversationId(conversation);
                let at_peer = holds.iter().position(|(held, _, _)| *held == conversation);
                let index = at_peer.unwrap_or_else(|| {
                    holds.push((conversation, ReceiptHold::default(), Vec::new()));
                    holds.len().saturating_sub(1)
                });
                if let Some((_, hold, rows)) = holds.get_mut(index) {
                    hold.push(target, at);
                    rows.push((row, target));
                }
            }
            for (conversation, mut hold, rows) in holds {
                let targets = hold.take_batch(now);
                if due.is_some() || targets.is_empty() {
                    continue;
                }
                let body = ReceiptBody { targets };
                let mut encoded =
                    vec![0u8; 2usize.saturating_add(body.targets.len().saturating_mul(16))];
                body.encode(&mut encoded)?;
                let mut msg_id = [0u8; 16];
                rng.fill_bytes(&mut msg_id);
                let record = AppMessage {
                    kind,
                    msg_id,
                    sent_at: now.saturating_mul(1_000),
                    body: &encoded,
                };
                let mut app = vec![0u8; record.len()];
                record.encode(&mut app)?;
                due = Some(DueReceipt {
                    conversation,
                    app,
                    rows: rows
                        .iter()
                        .filter(|(_, target)| body.targets.contains(target))
                        .map(|(row, _)| *row)
                        .collect(),
                });
            }
        }
        if !stale.is_empty() {
            let mut batch = open.store.begin();
            for row in stale {
                batch.delete(RECEIPT, row);
            }
            batch.commit()?;
        }
        Ok(due)
    }

    /// The batch left in a slot, and the store erases its rows (`NET-054`).
    pub fn receipt_sent(&mut self, receipt: &DueReceipt) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in &receipt.rows {
            batch.delete(RECEIPT, *row);
        }
        Ok(batch.commit()?)
    }

    /// One summary for each contact and for each group, the newest
    /// conversation first. The list needs no network.
    pub fn summaries(&self) -> Result<Vec<ConversationSummary>, Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        for conversation in self.conversations()? {
            let (read_up_to, name) = self.conversation_meta(conversation)?;
            let mut last: Option<(u64, u64, RowId)> = None;
            let mut unread = 0u32;
            for (row, plain) in store.list(TableId::MESSAGE, Some(&conversation.0))? {
                let plain = Zeroizing::new(plain);
                if is_request(&plain)? {
                    continue;
                }
                let info = info_of(&plain)?;
                if !info.outgoing && info.stored_at_ms > read_up_to {
                    unread = unread.saturating_add(1);
                }
                let key = (info.stored_at_ms, info.sent_at_ms, row);
                if last.is_none_or(|newest| key > newest) {
                    last = Some(key);
                }
            }
            out.push(ConversationSummary {
                conversation,
                name,
                last: last.map(|(_, _, row)| MsgRef(row)),
                last_at_ms: last.map_or(0, |(stored_at, _, _)| stored_at),
                unread,
                verified: self.is_verified(conversation)?,
            });
        }
        out.sort_by_key(|summary| core::cmp::Reverse(summary.last_at_ms));
        Ok(out)
    }

    /// Puts each record that waits in the store back into the send queue.
    /// A run of the network that ended took records that no relay
    /// accepted, and the next run sends them again under their `msg_id`.
    pub fn requeue_waiting(&mut self) -> Result<(), Error> {
        self.outgoing.clear();
        let store = &self.open_ref()?.store;
        let mut waiting_records = Vec::new();
        for (row, _) in store.list(OUTBOX, None)? {
            let Some(plain) = store.get(TableId::MESSAGE, &row)? else {
                continue;
            };
            let plain = Zeroizing::new(plain);
            let conversation = conversation_of(&plain)?;
            // A record of a group takes the run of the group queues.
            if self.is_group(conversation)? {
                continue;
            }
            let info = info_of(&plain)?;
            waiting_records.push((
                info.stored_at_ms,
                Outgoing {
                    message: MsgRef(row),
                    conversation,
                    app: plain
                        .get(MESSAGE_PREFIX..)
                        .ok_or(Error::Integrity)?
                        .to_vec(),
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
        mut draft: Draft,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        if draft.is_empty() {
            return Err(Error::Malformed);
        }
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let conversation = draft.conversation();
        if let Some(file) = draft.take_file() {
            // The record of a file holds the descriptor alone.
            if !draft.text().is_empty() || draft.reply_to().is_some() {
                return Err(Error::Malformed);
            }
            return self.send_file(conversation, msg_id, file, now_ms, rng);
        }
        // A reply is a rich record around the text. The wire carries the raw
        // `msg_id` of the target, which the row of the target holds.
        let rich = match draft.reply_to() {
            None => None,
            Some(target) => {
                let plain = Zeroizing::new(
                    self.open_ref()?
                        .store
                        .get(TableId::MESSAGE, &target.0)?
                        .ok_or(Error::NotFound)?,
                );
                // WIR-171: an answer stays inside its conversation.
                if conversation_of(&plain)? != conversation {
                    return Err(Error::Malformed);
                }
                let held = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                let record = RichRecord {
                    reply_target: AppMessage::parse(held, Channel::Pairwise)?.msg_id,
                    thread_root: [0; 16],
                    forward_depth: 0,
                    mentions: Vec::new(),
                    inner_kind: AppKind::Text,
                    inner_body: draft.text(),
                };
                let mut body = Zeroizing::new(vec![0u8; record.len()]);
                record.encode(Channel::Pairwise, &mut body)?;
                Some(body)
            }
        };
        let message = AppMessage {
            kind: if rich.is_some() {
                AppKind::Rich
            } else {
                AppKind::Text
            },
            msg_id,
            sent_at: now_ms,
            body: rich.as_ref().map_or(draft.text(), |body| body.as_slice()),
        };
        let mut app = Zeroizing::new(vec![0u8; message.len()]);
        message.encode(&mut app)?;
        drop(rich);

        // A group record goes to the two replicas of its group queue and
        // on no pairwise channel (Part 11 §11.2).
        if self.is_group(conversation)? {
            let message = self.post_to_group(conversation, msg_id, &app, now_ms, rng)?;
            self.auto_lock.touch(now_ms / 1_000);
            return Ok(message);
        }

        let open = self.open_mut()?;
        // IMP-024, IMP-025: the store holds the keyed form of `msg_id`.
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let plain = stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, &app);
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.put(OUTBOX, row, None, &outbox_row(), rng)?;
        batch.commit()?;

        let message = MsgRef(row);
        self.outgoing.push_back(Outgoing {
            message,
            conversation,
            app: app.to_vec(),
        });
        self.auto_lock.touch(now_ms / 1_000);
        Ok(message)
    }

    /// Stores a message with a file, and gives the file to the transfer
    /// task. The record has no descriptor before the relays hold each
    /// chunk, thus it waits outside the send path until
    /// [`Client::upload_done`].
    fn send_file<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        msg_id: [u8; 16],
        file: crate::draft::DraftFile,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let record = AppMessage {
            kind: AppKind::Attachment,
            msg_id,
            sent_at: now_ms,
            body: &[],
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        let open = self.open_mut()?;
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let plain = stored_message(OUTGOING, Delivery::Queued, conversation, now_ms, &app);
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.put(
            FILE_STATE,
            row,
            Some(conversation.0),
            &files::outgoing_state_row(
                &file.shape,
                u64::try_from(file.plain.len()).unwrap_or(u64::MAX),
                &FileExtras {
                    name: file.name.clone(),
                    preview: file.preview.clone(),
                },
            ),
            rng,
        )?;
        batch.put(FILE_DATA, row, Some(conversation.0), &file.plain, rng)?;
        batch.commit()?;
        let message = MsgRef(row);
        self.files.uploads.push_back(UploadJob {
            message,
            plain: file.plain,
            shape: file.shape,
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
        if is_request(&plain)? && !matches!(delivery, Delivery::Queued | Delivery::Failed) {
            // WIR-071: the request held a raw `msg_id` for its send, and a
            // relay has it now. No view showed the row.
            let mut batch = open.store.begin();
            batch.delete(TableId::MESSAGE, message.0);
            batch.delete(OUTBOX, message.0);
            return Ok(batch.commit()?);
        }
        if info_of(&plain)?.delivery == Delivery::Queued && delivery != Delivery::Queued {
            // WIR-071: the raw target served the send, and its time ends.
            let app = plain.get_mut(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
            keep_reply_as_reference(app, &open.device_set_key)?;
        }
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
        // The record of a file holds no text (Part 6 §6.6), and a view of it
        // shows the file.
        let bytes = match parsed.kind {
            AppKind::Attachment => &[][..],
            _ => text_of(&parsed)?,
        };
        let text = core::str::from_utf8(bytes).map_err(|_| Error::Integrity)?;
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
        let mut info = info_of(&plain)?;
        info.file = self.file_info(message)?;
        info.revisions = match open.store.get(REVISION, &message.0)? {
            None => 0,
            Some(count) => *count.first().ok_or(Error::Integrity)?,
        };
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        if let Some(field) = reply_field(app)? {
            let held: [u8; 16] = app
                .get(field)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            // A record that waits for its relay holds the raw target still.
            let reference = if info.outgoing && info.delivery == Delivery::Queued {
                msg_ref(&open.device_set_key, &held)
            } else {
                held
            };
            // WIR-171, WIR-172: the target is a message of this conversation.
            let natural = [conversation_of(&plain)?.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            info.reply = match open.store.get(TableId::MESSAGE, &row)? {
                Some(_) => ReplyTarget::Message(MsgRef(row)),
                None => ReplyTarget::Absent,
            };
        }
        Ok(info)
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
            if is_request(&plain)? {
                continue;
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
            FILE_STATE,
            FILE_DATA,
            CHUNK_CRED,
            TableId::MESSAGE,
            TableId::LOCAL_IDENTITY,
            TableId::CONTACT,
            TableId::VERIFICATION,
            RECEIPT,
            PENDING,
            REVISION,
            REACTION,
            OUTBOX,
            INVITATION,
            CONVERSATION,
            SETTINGS,
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
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    let stored_at: [u8; 8] = plain
        .get(STORED_AT)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Integrity)?;
    Ok(MessageInfo {
        outgoing: direction == OUTGOING,
        stored_at_ms: u64::from_be_bytes(stored_at),
        delivery: delivery.ok_or(Error::Integrity)?,
        sent_at_ms: parsed.sent_at,
        // The store resolves the target: see `Client::info`.
        reply: ReplyTarget::None,
        deleted: tombstone_of(&parsed)? == Some(Tombstone::Placeholder),
        has_text: text_of(&parsed).is_ok(),
        // The store holds the count: see `Client::info`.
        revisions: 0,
        // The store holds the state of a file: see `Client::info`.
        file: None,
    })
}

/// Whether a stored row is a request of this device to its contact: a
/// deletion or an edit that waits for its relay. No view shows such a row.
/// An edit of the contact changes its target and is never a row.
fn is_request(plain: &[u8]) -> Result<bool, Error> {
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    // A reaction of the contact changes the reaction table and is never a row.
    // A group control object of Part 11 travels on a pairwise channel and
    // is no message of that conversation (`GRP-309`, `GRP-312`).
    Ok(matches!(
        parsed.kind,
        AppKind::Edit | AppKind::Reaction | AppKind::GroupControl | AppKind::KeyRequest
    ) || tombstone_of(&parsed)? == Some(Tombstone::Request))
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
