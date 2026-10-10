//! The client behind the surface of Part 14 §14.6.1: the locked and the
//! unlocked state over the store of §14.6.4, the send of a draft, the
//! render of a message into a sink, and the one event stream.
//!
//! Each network, ratchet, queue, and onion function stays on the Rust
//! side. The runtime takes each outgoing record from
//! [`Client::take_outgoing`] and gives each received record to
//! [`Client::receive`], and the platform sees handles and events only.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod alerts;
mod backup;
mod block;
mod catch_up;
mod dead;
mod devices;
mod discovery;
mod drafts;
mod files;
mod forward;
mod gossip;
mod group_changes;
mod group_sync;
mod groups;
mod held_handles;
mod history;
mod intros;
mod key_changes;
mod key_supply;
mod moderation;
mod modes;
mod notify;
mod own_delete;
mod polls;
mod quota;
mod reset;
mod retention;
mod roster_fork;
mod roster_notes;
mod screenshots;
mod snapshot_recovery;
pub use retention::{HISTORY_AGE_ALL, HISTORY_AGE_MIN};
pub use snapshot_recovery::SnapshotJob;
mod social;
mod sync;
mod timers;
mod tokens;
mod typing;

pub use alerts::{ALERT_ALL, ALERT_MENTIONS, ALERT_NONE};
pub use backup::{BackupUpload, PendingBackup, RestoredBackup, RootWrite};
pub use catch_up::CatchUp;
pub use dead::DeadWork;
pub use devices::{DeviceInfo, REVOCATION_NOTICE_TTL};
pub use discovery::{ContactRequest, EntryKind, Published, PROFILE_NAME_MAX};
pub use files::{DownloadJob, ErasureJob, FileExtras, FileInfo, FileState, UploadJob};
use files::{FileQueues, CHUNK_CRED, ERASE_DUE, FILE_DATA, FILE_STATE};
pub use gossip::{GossipWarning, HeadCheck};
#[cfg(feature = "bindings")]
pub(crate) use groups::EPOCH_CHUNKS_MAX;
pub use groups::{
    EpochUpload, GroupAdmitWaiting, GroupInfo, GroupJoiner, GroupOffer, GroupPost, GroupQueueJob,
    GroupSubscription, Silence, GROUP_NAME_MAX,
};
pub use history::HistoryHole;
pub use intros::Introduction;
pub use key_changes::PendingKeyChange;
pub use key_supply::NOTE_LOST;
pub use moderation::{ModNote, MOD_HIDE, MOD_REMOVE, MOD_UNHIDE};
pub use notify::{NdrCall, WAKE_SILENT};
pub use polls::PollView;
pub use quota::HOLD_RETRY;
pub use reset::ResetSummary;
pub use roster_fork::{RosterFork, FORK_ONE_SIGNER, FORK_PEER, FORK_REVOKED};
pub use roster_notes::{
    RosterNote, NOTE_EVICTED, NOTE_FORK, NOTE_GAP, NOTE_JOINED, NOTE_LEFT, NOTE_NOBODY, NOTE_ROLE,
};
pub use social::{GivenShare, HeldShare};
pub use sync::SyncSend;
pub use timers::{timer_body, TimerSetting, TIMER_VALUES};
pub use typing::{EPHEMERAL, TYPING_INTERVAL_MS, TYPING_TTL_MS};
use umbra_core::{
    devset::edits::Deadline,
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
    keys::{DigestBody, KeyRequest, KeyScope},
    msg_ref,
    poll::Poll,
    rich::RichRecord,
    signal::{ReactionAction, ReactionBody, ReceiptBody, TypingState},
    AppKind, AppMessage, Channel,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    draft::Draft, ConversationId, ConversationSummary, Delivery, DueReceipt, Error, Event,
    MessageInfo, MsgRef, Reaction, ReceiptSettings, ReplyTarget, Sink, CONTACT_NAME_MAX,
};

/// The row of the read marker in the mutable state of Part 7 §7.5.3, the
/// first row of its table.
pub(crate) const ITEM_READ_MARKER: u8 = 1;
/// The row of the verification state, the fifth row of that table.
pub(crate) const ITEM_VERIFICATION: u8 = 5;
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

/// The place of a synced record in the order of its source (`DEV-015`). The
/// place is the device that sent it on the sync channel, and its causal
/// counter.
type SyncPlace = (umbra_core::devset::DeviceId, u64);

/// The count of a revision row, and the high-water mark of `DEV-034`: the
/// place of the newest revision that a sync channel gave. A row of one
/// byte, which an earlier build wrote, holds no mark. Neither does a
/// message whose revisions all came on its own ratchet.
fn revision_of(row: Option<&[u8]>) -> Result<(u8, Option<SyncPlace>), Error> {
    let Some(row) = row else {
        return Ok((0, None));
    };
    let count = *row.first().ok_or(Error::Integrity)?;
    let mark = match (row.get(1..17), row.get(17..25)) {
        (Some(source), Some(counter)) => source
            .try_into()
            .ok()
            .zip(counter.try_into().ok().map(u64::from_be_bytes)),
        _ => None,
    };
    Ok((count, mark))
}

fn revision_row((count, mark): (u8, Option<SyncPlace>)) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(match mark {
        Some((source, counter)) => [&[count][..], &source, &counter.to_be_bytes()].concat(),
        None => vec![count],
    })
}

/// The natural key of a pending reference (`DEV-093`): the conversation, the
/// target, and the direction of the record that waits. The row keeps the
/// layout of an earlier build, whose key named no direction.
fn pending_key(natural: &[u8], from_user: bool) -> Vec<u8> {
    let direction = if from_user { OUTGOING } else { INCOMING };
    [natural, &[direction]].concat()
}

/// The stored form of a record copy that waits for the other devices of the
/// set. The form is its place in the order of the commits, the
/// conversation, then the record. A row of an earlier build holds no place.
const PUBLISH_ORDER_LEN: usize = 8 + 4;

/// Reads a waiting copy: its place, its conversation, and its record. A row
/// of an earlier build, which starts with the conversation, takes the first
/// place.
fn pending_copy(plain: &[u8]) -> Option<(Vec<u8>, ConversationId, &[u8])> {
    let conversation_at = |at: usize| -> Option<ConversationId> {
        let bytes = plain.get(at..at.checked_add(16)?)?;
        Some(ConversationId(bytes.try_into().ok()?))
    };
    let is_record = |app: &[u8]| {
        AppMessage::parse(app, Channel::Pairwise).is_ok()
            || AppMessage::parse(app, Channel::Group).is_ok()
    };
    if let (Some(conversation), Some(app)) = (
        conversation_at(PUBLISH_ORDER_LEN),
        plain.get(PUBLISH_ORDER_LEN.saturating_add(16)..),
    ) {
        if is_record(app) {
            let order = plain.get(..PUBLISH_ORDER_LEN)?.to_vec();
            return Some((order, conversation, app));
        }
    }
    let app = plain.get(16..)?;
    is_record(app).then_some(())?;
    Some((Vec::new(), conversation_at(0)?, app))
}

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
/// The cause of each failed message of this device, under the row of the
/// message: one byte of `FailureCause` (`IMP-074`).
const FAILURE: TableId = TableId(0x4F);
/// Each record of a contact that goes to the other devices of the set, in
/// the commit that stores it (`DEV-293`): the conversation of 16 bytes, then
/// the record.
/// The publish reads it after the commit, thus a crash between the two
/// loses no copy.
const PUBLISH_PENDING: TableId = TableId(0x50);
/// The clock correction of the relay directory in seconds, signed
/// (Part 10 `REL-114`).
const DIRECTORY_CORRECTION_SETTING: &[u8] = b"directory-correction";
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
    /// The stored form of each rendezvous queue of Part 9 §9.6.
    pub rendezvous_queues: Vec<Zeroizing<Vec<u8>>>,
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
    /// The insertion stamp of each message that this device stores.
    stamp: Stamp,
    /// Whether the store holds the mark that it wrote the MAC of its set
    /// of tables (`IDN-193`).
    set_marked: bool,
}

/// The period of one pass of the scan of `IDN-162`: 24 hours, less one
/// hour for the steps of the pass.
const AUDIT_PERIOD: u64 = 23 * 3_600;

/// The place of the scan of `IDN-162`: the index of the next table, and the
/// start of the pass. The first pass starts at the first step of the run.
#[derive(Debug, Default, Clone, Copy)]
struct Audit {
    next: usize,
    started: u64,
}

/// The local insertion sequence of Part 7 §7.5.3 and Part 11 §11.7: a
/// monotone stamp for each message that this device stores. It follows the
/// clock in milliseconds and never goes back, thus a clock that moves back
/// changes no order of a view (`DEV-031`, `GRP-042`), and the edit window
/// and the read mark still read it as a time. The store keeps its floor
/// across runs.
#[derive(Debug, Default, Clone, Copy)]
struct Stamp {
    last: u64,
    kept: u64,
}

impl Stamp {
    /// The stamp of the next message at `now_ms`.
    fn next(&mut self, now_ms: u64) -> u64 {
        self.last = self.last.saturating_add(1).max(now_ms);
        self.last
    }
}

/// The setting that holds the floor of [`Stamp`].
const STAMP_FLOOR: &[u8] = b"insertion-stamp";
/// The row of the local identity that marks a store whose set of tables
/// carries a MAC (`IDN-193`). The row sits beside the root seed, thus a
/// party that drops it drops the identity too.
const SET_MARK: &[u8] = b"table-set";

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
    /// The scan of `IDN-162`, one table at each step.
    audit: Audit,
    /// The last clock of the platform tick, in seconds, or 0 before one.
    clock: u64,
    /// The records for the sync channels (Part 7 §7.5).
    sync_out: VecDeque<sync::SyncSend>,
    /// The records that a peer handed to this device, which the peer
    /// publishes, thus their send publishes nothing.
    synced_out: BTreeSet<MsgRef>,
    /// The blinded subject of each contact conversation (`DEV-292`).
    subjects: BTreeMap<ConversationId, [u8; 32]>,
    /// The time of the last typing record to each peer (`WIR-285`).
    typing_sent: BTreeMap<ConversationId, u64>,
    /// The conversations whose queue a relay named full (Part 14 §14.9.2).
    full_queues: BTreeSet<ConversationId>,
    /// Each record that a full queue refused, with its conversation and the
    /// time of the refusal, in seconds.
    held_sends: BTreeMap<MsgRef, (ConversationId, u64)>,
    /// The sends of each record that a full queue refused, and the time of
    /// the first refusal, in seconds. The two are the bounds of its ARQ
    /// (`NET-219`, `NET-220`).
    limit_sends: BTreeMap<MsgRef, (u32, u64)>,
    /// The queues whose bind is on its way, each with whether a
    /// registration of its handle overtook it (`NTF-125`).
    binding: BTreeMap<[u8; 32], bool>,
    /// The time of the last request for the rotations that a revocation
    /// owes, in seconds, or 0 before one (Part 7 §7.7 step 2c).
    rotation_asked: u64,
    /// The head epoch up to which this run sent the kept roster epochs on
    /// each sync channel (`DEV-229`). A channel takes them once for one
    /// head, thus a copy of an epoch that comes again starts no echo.
    roster_chain_sent: BTreeMap<ConversationId, u64>,
}

/// One record for the commit path: of a contact, or of the sync channel.
struct Record {
    conversation: ConversationId,
    app: Vec<u8>,
    /// Whether the user wrote the record, on another device of the set.
    from_user: bool,
    /// Whether the record came on a sync channel (`DEV-268`).
    synced: bool,
    /// The `expires_in` of a sync copy, or zero (`DEV-244`).
    expires_in: u32,
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
            let rich = RichRecord::parse(parsed.body, Channel::Group)?;
            if rich.inner_kind != AppKind::Text {
                return Err(Error::Malformed);
            }
            let changed = RichRecord {
                inner_body: text,
                ..rich
            };
            let mut encoded = Zeroizing::new(vec![0u8; changed.len()]);
            changed.encode(Channel::Group, &mut encoded)?;
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
        // A stored record passed the check of its channel at its arrival,
        // and the layout of a group is the wider one.
        AppKind::Rich => {
            let rich = RichRecord::parse(parsed.body, Channel::Group)?;
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
    let rich = RichRecord::parse(parsed.body, Channel::Group)?;
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
    // WIR-272: the thread root of a group takes the stored form too.
    for field in [reply_field(app)?, thread_field(app)?]
        .into_iter()
        .flatten()
    {
        let raw: [u8; 16] = app
            .get(field.clone())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::Integrity)?;
        let reference = msg_ref(key, &raw);
        app.get_mut(field)
            .ok_or(Error::Integrity)?
            .copy_from_slice(&reference);
    }
    Ok(())
}

/// The place of `thread_root` in an encoded record with a rich body, or
/// `None` for a record in no thread. The field follows `reply_target`.
fn thread_field(app: &[u8]) -> Result<Option<core::ops::Range<usize>>, Error> {
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    if parsed.kind != AppKind::Rich {
        return Ok(None);
    }
    let rich = RichRecord::parse(parsed.body, Channel::Group)?;
    if rich.thread_root == [0; 16] {
        return Ok(None);
    }
    let body_at = app.len().saturating_sub(parsed.body.len());
    let at = body_at.saturating_add(17);
    Ok(Some(at..at.saturating_add(16)))
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

/// The clock in seconds, for a rule of the store that runs on no call of
/// the caller.
fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
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
        let mark = store.row_id(TableId::LOCAL_IDENTITY, SET_MARK);
        let mut batch = store.begin();
        batch.put(TableId::LOCAL_IDENTITY, row, None, seed.expose(), rng)?;
        batch.put(TableId::LOCAL_IDENTITY, mark, None, &[1], rng)?;
        batch.commit()?;
        let mut client = Client {
            element,
            header,
            state: State::Unlocked(Box::new(Open {
                stamp: Stamp::default(),
                store,
                device_set_key: root.device_set_key(),
                set_marked: true,
            })),
            events: VecDeque::new(),
            outgoing: VecDeque::new(),
            sync_out: VecDeque::new(),
            synced_out: BTreeSet::new(),
            subjects: BTreeMap::new(),
            typing_sent: BTreeMap::new(),
            full_queues: BTreeSet::new(),
            held_sends: BTreeMap::new(),
            limit_sends: BTreeMap::new(),
            binding: BTreeMap::new(),
            rotation_asked: 0,
            roster_chain_sent: BTreeMap::new(),
            files: FileQueues::default(),
            groups: groups::GroupQueues::default(),
            auto_lock: AutoLock::new(now),
            audit: Audit::default(),
            clock: 0,
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
            typing_sent: BTreeMap::new(),
            full_queues: BTreeSet::new(),
            held_sends: BTreeMap::new(),
            limit_sends: BTreeMap::new(),
            binding: BTreeMap::new(),
            rotation_asked: 0,
            roster_chain_sent: BTreeMap::new(),
            files: FileQueues::default(),
            groups: groups::GroupQueues::default(),
            auto_lock: AutoLock::new(now),
            audit: Audit::default(),
            clock: 0,
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
        // IDN-039, IDN-040: a row of the identity that does not read after
        // the store opened is a fault of the file, and the user learns it.
        let read = (|| -> Result<(bool, Zeroizing<[u8; 32]>, u64), Error> {
            // IDN-193: a store that wrote the MAC of its set of tables and
            // holds none lost a table to a party with the file.
            let mark = store.row_id(TableId::LOCAL_IDENTITY, SET_MARK);
            let set_marked = store.get(TableId::LOCAL_IDENTITY, &mark)?.is_some();
            if set_marked && !store.indexed() {
                return Err(Error::Integrity);
            }
            let row = store.row_id(TableId::LOCAL_IDENTITY, ROOT_KEY);
            let seed = Zeroizing::new(
                store
                    .get(TableId::LOCAL_IDENTITY, &row)?
                    .ok_or(Error::Integrity)?,
            );
            let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
            let floor_row = store.row_id(SETTINGS, STAMP_FLOOR);
            let floor = store
                .get(SETTINGS, &floor_row)?
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .map_or(0, u64::from_be_bytes);
            Ok((set_marked, Zeroizing::new(seed), floor))
        })();
        let (set_marked, seed, floor) = match read {
            Ok(read) => read,
            Err(_) => {
                self.events.push_back(Event::IntegrityFault);
                return Err(Error::Integrity);
            }
        };
        let root = RootIdentity::new(Secret::new(*seed));
        self.state = State::Unlocked(Box::new(Open {
            store,
            device_set_key: root.device_set_key(),
            stamp: Stamp {
                last: floor,
                kept: floor,
            },
            set_marked,
        }));
        // Each record that waited for the send path at the lock waits again.
        self.requeue_waiting()?;
        self.requeue_transfers()?;
        let seconds = self.auto_lock_seconds()?;
        self.apply_auto_lock(seconds);
        self.auto_lock.touch(now);
        Ok(())
    }

    /// Moves a store of an earlier build to the current form of its records
    /// (`IMP-130`). The move runs at the unlock and before the first write
    /// of the run. A store of the current form changes nothing.
    ///
    /// A pass that finds a table that does not match its MAC, or a row that
    /// does not read, met a fault of the file. It gives an
    /// [`Event::IntegrityFault`] (`IDN-039`) before a view reads a row. A
    /// party that puts the MACs of the earlier form back shows here. A pass
    /// that the storage ends, as a full disk does, is no such fault and
    /// gives no such event. The call gives [`Error::Storage`], and each
    /// write of this run fails with it and runs no second pass. The next
    /// unlock runs the pass again.
    pub fn migrate_store<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        match self.open_mut()?.store.migrate(rng) {
            Ok(true) => Ok(()),
            Err(umbra_core::Error::Storage) => Err(Error::Storage),
            Ok(false) | Err(_) => {
                self.events.push_back(Event::IntegrityFault);
                Err(Error::Integrity)
            }
        }
    }

    /// Writes the floor of the insertion stamp when it moved, thus a later
    /// run starts above each stamp of this one.
    pub fn keep_stamp<R: CryptoRng + ?Sized>(&mut self, rng: &mut R) -> Result<(), Error> {
        let open = self.open_mut()?;
        if open.stamp.last == open.stamp.kept && open.set_marked {
            return Ok(());
        }
        let row = open.store.row_id(SETTINGS, STAMP_FLOOR);
        let mark = open.store.row_id(TableId::LOCAL_IDENTITY, SET_MARK);
        let last = open.stamp.last;
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &last.to_be_bytes(), rng)?;
        // IDN-193: the commit writes the MAC of the set of tables, and the
        // mark says so from now on.
        if !open.set_marked {
            batch.put(TableId::LOCAL_IDENTITY, mark, None, &[1], rng)?;
        }
        batch.commit()?;
        open.stamp.kept = last;
        open.set_marked = true;
        Ok(())
    }

    /// Locks the client: `K_store` leaves RAM, and each record that waits
    /// for the send path stays in the store.
    pub fn lock(&mut self) {
        // The floor of the insertion stamp survives the lock. A build with
        // no runtime has no entropy source here, and the tick of its
        // caller keeps the floor.
        #[cfg(feature = "runtime")]
        let _ = self.keep_stamp(&mut crate::runtime::OsRng);
        if let State::Unlocked(open) = core::mem::replace(&mut self.state, State::Closed) {
            self.state = State::Locked(open.store.lock());
            // IMP-126, IMP-127: each queue in RAM leaves with the key, and
            // its plaintext is wiped. The store holds each record again at
            // the unlock: the send queue in its rows, and a sync record in
            // its retained body, which the next run sends again. A sync
            // acknowledgment or a catch-up descriptor that waited goes at
            // the next record of its peer. The marks of the records that a
            // peer handed hold no text, and they stay.
            for outgoing in &mut self.outgoing {
                outgoing.app.zeroize();
            }
            for send in &mut self.sync_out {
                send.app.zeroize();
            }
            self.outgoing.clear();
            self.sync_out.clear();
            self.subjects.clear();
            self.typing_sent.clear();
            self.held_sends.clear();
            self.limit_sends.clear();
            self.roster_chain_sent.clear();
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
        self.clock = now;
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
            // A channel that a revocation ended takes nothing (Part 7 §7.7).
            if self.is_ended_channel(self.conversation_for(&contact.0)?)? {
                continue;
            }
            // DEV-257: a channel that waits for the notice of its revocation
            // sends that notice, and it takes no record.
            if self.is_leaving_channel(self.conversation_for(&contact.0)?)? {
                continue;
            }
            records.push(Record {
                conversation: self.conversation_for(&contact.0)?,
                app: app.clone(),
                from_user: false,
                synced: false,
                expires_in: 0,
            });
        }
        let mut kept: Vec<&StateChange> = Vec::with_capacity(changes.len());
        for change in changes {
            if let StateChange::Contact { contact, .. } = change {
                if self.is_ended_channel(self.conversation_for(&contact.0)?)? {
                    continue;
                }
            }
            kept.push(change);
        }
        self.commit_records(&kept, &records, now_ms, rng)?;
        // Part 3 §3.2.6: each record here opened under the ratchet of its
        // contact. Thus it is a sign of the peer, and the silence of its
        // channel ends.
        let mut heard: Vec<ConversationId> = Vec::new();
        for record in &records {
            if !heard.contains(&record.conversation) {
                heard.push(record.conversation);
                self.peer_heard(record.conversation)?;
            }
        }
        Ok(())
    }

    /// Publishes each record copy that waits for the other devices of the
    /// set, and drops its row (`DEV-293`). A copy that a crash left goes
    /// with the next commit.
    fn publish_pending<R: CryptoRng + ?Sized>(
        &mut self,
        now: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let pending = self.open_ref()?.store.list(PUBLISH_PENDING, None)?;
        if pending.is_empty() {
            return Ok(());
        }
        let mut done = Vec::new();
        // DEV-031 to DEV-035: the copies go in the order in which this
        // device took their records. The order of the store is the order of
        // a keyed hash, thus each row holds its place.
        let mut ordered = Vec::with_capacity(pending.len());
        for (row, plain) in pending {
            let plain = Zeroizing::new(plain);
            match pending_copy(&plain) {
                Some((order, conversation, app)) => {
                    ordered.push((order, row, conversation, Zeroizing::new(app.to_vec())));
                }
                // A row that holds no record goes.
                None => done.push(row),
            }
        }
        ordered.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        for (_, row, conversation, app) in ordered {
            match self.publish_sync(conversation, &app, false, None, now, rng) {
                // A copy that no later try can publish goes.
                Ok(()) | Err(Error::Malformed | Error::TooLong | Error::NotFound) => done.push(row),
                // A copy that does not go stays for the next commit, and
                // each copy after it too, thus no later record overtakes it.
                Err(_) => break,
            }
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in done {
            batch.delete(PUBLISH_PENDING, row);
        }
        Ok(batch.commit()?)
    }

    /// The commit of [`Client::commit_network`], for the records of a
    /// contact and for the records that a sync channel gave (Part 7 §7.5).
    /// A synced record of the user takes the direction of this device, and
    /// the owner of the channels sends one that a peer handed to it
    /// (`DEV-047`, `DEV-048`).
    fn commit_records<R: CryptoRng + ?Sized>(
        &mut self,
        changes: &[&StateChange],
        records: &[Record],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.commit_records_at(changes, records, &[], now_ms, rng)
    }

    /// [`Client::commit_records`], with the place of each record that a
    /// sync channel gave, in the order of `records`. A record with no place
    /// came on its own ratchet, or from a table that keeps none.
    fn commit_records_at<R: CryptoRng + ?Sized>(
        &mut self,
        changes: &[&StateChange],
        records: &[Record],
        places: &[Option<SyncPlace>],
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
        let mut blocked = Vec::new();
        // The timer of each conversation, which a timer record of this
        // batch moves for each record after it (`DEV-203`).
        let mut timers: BTreeMap<ConversationId, u32> = BTreeMap::new();
        for record in records {
            if !blocked.contains(&record.conversation) && self.is_blocked(record.conversation)? {
                blocked.push(record.conversation);
            }
            if let std::collections::btree_map::Entry::Vacant(slot) =
                timers.entry(record.conversation)
            {
                slot.insert(self.timer_seconds(record.conversation)?);
            }
        }
        let mut sync_bodies: Vec<(ConversationId, Vec<u8>)> = Vec::new();
        let mut digests: Vec<DigestBody> = Vec::new();
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
        let mut votes: Vec<(ConversationId, Vec<u8>, u16)> = Vec::new();
        let mut key_changes: Vec<(ConversationId, Vec<u8>)> = Vec::new();
        let mut shares: Vec<(ConversationId, Zeroizing<Vec<u8>>)> = Vec::new();
        let mut intros: Vec<(ConversationId, Zeroizing<Vec<u8>>)> = Vec::new();
        let mut supplies: Vec<(ConversationId, Vec<u8>)> = Vec::new();
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
                StateChange::RendezvousQueue { queue, state } => Planned::Put(
                    discovery::RENDEZVOUS_STATE,
                    open.store.row_id(discovery::RENDEZVOUS_STATE, queue),
                    None,
                    Zeroizing::new([queue.as_slice(), state].concat()),
                ),
                StateChange::RendezvousQueueEnded { queue } => Planned::Delete(
                    discovery::RENDEZVOUS_STATE,
                    open.store.row_id(discovery::RENDEZVOUS_STATE, queue),
                ),
            });
        }
        let mut events = Vec::new();
        let mut owner_fault = false;
        let mut delivered: Vec<(RowId, Delivery)> = Vec::new();
        // What this batch plans and the store does not hold yet. The plan
        // holds the count and the mark of each revised message, each
        // pending reference, and the reactions that each party adds to each
        // message.
        let mut revised: BTreeMap<RowId, (u8, Option<SyncPlace>)> = BTreeMap::new();
        let mut pended: BTreeMap<RowId, (ConversationId, Zeroizing<Vec<u8>>)> = BTreeMap::new();
        let mut reacted: BTreeMap<(RowId, u8), usize> = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            let app = &record.app;
            let conversation = record.conversation;
            let from_user = record.from_user;
            let place = places.get(index).copied().flatten();
            // A record whose app does not parse is one silent drop, as
            // GRP-251 has it for a group. A fault here would end the commit
            // of the batch, and no ACK would leave. The relay would give
            // the record again at each connection, and one record of a
            // contact would stop the client for good.
            let Ok(parsed) = AppMessage::parse(app, Channel::Pairwise) else {
                continue;
            };
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
            // DIS-033, REL-008: the digest of a contact is no message, and
            // it compares after the batch. A body that does not parse goes.
            if parsed.kind == AppKind::TransparencyDigest {
                if !from_user && !blocked.contains(&conversation) {
                    if let Ok(body) = DigestBody::parse(parsed.body) {
                        digests.push(body);
                    }
                }
                continue;
            }
            // WIR-176: a pairwise record names no member, and a poll that
            // does not parse is no poll (WIR-180 to WIR-182).
            // DEV-174: a rich record of a pairwise channel goes around a
            // text. Thus one around another kind, or around bytes that are
            // no UTF-8, is no message.
            let is_invalid = match parsed.kind {
                AppKind::Rich => {
                    RichRecord::parse(parsed.body, Channel::Pairwise).map_or(true, |rich| {
                        rich.inner_kind != AppKind::Text
                            || core::str::from_utf8(rich.inner_body).is_err()
                    })
                }
                AppKind::Poll => Poll::parse(parsed.body).is_err(),
                _ => false,
            };
            if is_invalid {
                continue;
            }
            // ABU-027 to ABU-030: the record of a blocked contact goes,
            // after its acknowledgment, with no view and no alert. A
            // delivery receipt keeps the rate that held before the block.
            // It names a record that the store would have kept as a
            // message, and no other one. Thus a typing record or an edit of
            // a blocked contact gets no receipt that it did not get before.
            if !from_user && blocked.contains(&conversation) {
                // WIR-339: a blocked contact that asks for a record of this
                // device gets the answer that it got before the block.
                if parsed.kind == AppKind::KeyRequest && !record.synced {
                    key_requests.push((conversation, parsed.body.to_vec()));
                    continue;
                }
                let is_kept = match parsed.kind {
                    AppKind::Text | AppKind::Rich | AppKind::Attachment | AppKind::Poll => true,
                    AppKind::ConversationTimer => timers::timer_body(parsed.body).is_some(),
                    _ => false,
                };
                if !record.synced && sends_delivery.contains(&conversation) && is_kept {
                    let key =
                        held_receipt_key(conversation, AppKind::DeliveryReceipt, &parsed.msg_id);
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
                continue;
            }
            // DEV-247: the owner of the channels forwards no revision that it
            // rejected, thus the copy of an edit waits for its checks below.
            let publishes = !record.synced && owns;
            if publishes && parsed.kind != AppKind::Edit {
                to_publish.push((conversation, app.clone()));
            }
            // The owner of the channels sends each record that a peer
            // handed to it. The record of an edit, a deletion, or a reaction
            // waits in a request row, as one of this device does.
            let handoff = record.synced && from_user && owns;
            // A row of the store reads back with its body, thus a handed
            // record whose body does not parse is one drop and no row.
            let is_unreadable = match parsed.kind {
                AppKind::Delete => DeleteBody::parse(parsed.body).is_err(),
                AppKind::Edit => EditBody::parse(parsed.body).is_err(),
                _ => false,
            };
            if handoff && is_unreadable {
                continue;
            }
            if handoff
                && matches!(
                    parsed.kind,
                    AppKind::Reaction | AppKind::Edit | AppKind::Delete | AppKind::PollVote
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
                    stored_message(
                        OUTGOING,
                        Delivery::Queued,
                        conversation,
                        open.stamp.next(now_ms),
                        app,
                    ),
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
                        let plain = Zeroizing::new(plain);
                        // IMP-121: the plaintext names its owner. A receipt
                        // of this contact moves no record of another
                        // conversation. Such a row is a fault of the file
                        // that the user learns of one time (`IDN-039`). It
                        // ends no batch. A batch that failed for it would
                        // acknowledge no record, and each receipt of this
                        // contact would come again at each run.
                        if conversation_of(&plain).ok() != Some(conversation) {
                            if !owner_fault {
                                owner_fault = true;
                                events.push(Event::IntegrityFault);
                            }
                            continue;
                        }
                        let info = info_of(&plain)?;
                        let is_sent =
                            matches!(info.delivery, Delivery::Accepted | Delivery::Delivered);
                        let is_named = named.iter().any(|(held, _)| *held == row);
                        if info.outgoing && is_sent && info.stored_at_ms <= up_to && !is_named {
                            named.push((row, plain));
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
                    delivered.push((row, reported));
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
            // WIR-459: the supply of a request of scope 0x01 comes on the
            // channel of the request, and it is no message.
            if parsed.kind == AppKind::KeySupply {
                if !from_user && !record.synced {
                    supplies.push((conversation, parsed.body.to_vec()));
                }
                continue;
            }
            // WIR-287: a typing record of the contact moves a state of the
            // view, and no store holds it. A group takes none (GRP-300).
            if parsed.kind == AppKind::Typing {
                if !from_user && !record.synced {
                    if let Ok(state) = TypingState::parse(parsed.body) {
                        events.push(Event::Typing {
                            conversation,
                            is_typing: state == TypingState::Started,
                        });
                    }
                }
                continue;
            }
            // IDN-059: a key-change notice of the contact comes on its
            // receiving chain, and it waits for the user. It is no message.
            if parsed.kind == AppKind::KeyChange {
                if !from_user {
                    key_changes.push((conversation, parsed.body.to_vec()));
                }
                continue;
            }
            // WIR-196, WIR-358: a contact share is no message, and a request
            // or an offer waits for the user.
            if parsed.kind == AppKind::ContactShare {
                if !from_user && !record.synced {
                    intros.push((conversation, Zeroizing::new(parsed.body.to_vec())));
                }
                continue;
            }
            // IDN-189: a share of a contact is no message, and this device
            // holds it for the day that contact needs it.
            if parsed.kind == AppKind::RecoveryShare {
                if !from_user {
                    shares.push((conversation, Zeroizing::new(parsed.body.to_vec())));
                }
                continue;
            }
            if parsed.kind == AppKind::PollVote {
                // A vote is no message: it moves the count of its poll
                // after the batch.
                let voter = if from_user {
                    polls::VOTER_SELF
                } else {
                    polls::VOTER_PEER
                };
                votes.push((conversation, parsed.body.to_vec(), voter));
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
                        // The reactions that this batch adds count too.
                        let added = reacted.entry((target, direction)).or_insert(0usize);
                        if of_contact.saturating_add(*added) >= REACTIONS_MAX {
                            continue;
                        }
                        *added = added.saturating_add(1);
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
                        // An earlier edit of this batch moved the count and
                        // the mark, and the store does not hold them yet.
                        let held = match revised.get(&row) {
                            Some(held) => *held,
                            None => revision_of(open.store.get(REVISION, &row)?.as_deref())?,
                        };
                        let (count, mark) = held;
                        // WIR-082: the sender of the target alone. DEV-087:
                        // inside the window from the store time of this
                        // device. DEV-088: below the limit. DEV-246: a copy
                        // from a sync channel passed the checks of the
                        // device that took the revision. This device
                        // measures no window and no limit for it.
                        let in_window = now_ms.saturating_sub(info.stored_at_ms) < EDIT_WINDOW_MS;
                        if info.outgoing != from_user
                            || info.deleted
                            || (!record.synced && (!in_window || count >= EDIT_MAX))
                        {
                            continue;
                        }
                        // DEV-034, DEV-035: a copy at or below the newest
                        // revision that its source gave is an older text.
                        // It never takes the place of a newer one. The
                        // counters of two sources do not compare.
                        let is_older = matches!(
                            (place, mark),
                            (Some((source, counter)), Some((held, newest)))
                                if source == held && counter <= newest
                        );
                        if is_older {
                            continue;
                        }
                        // WIR-260: a target with no text takes no edit. An
                        // earlier edit of this batch gave the row its text.
                        let base = planned.iter().rev().find_map(|write| match write {
                            Planned::Put(table, at, _, value)
                                if *table == TableId::MESSAGE && *at == row =>
                            {
                                Some(value.clone())
                            }
                            _ => None,
                        });
                        let base = base.unwrap_or_else(|| plain.clone());
                        let Ok(changed) = row_with_text(&base, edit.new_body.as_bytes()) else {
                            continue;
                        };
                        if publishes {
                            to_publish.push((conversation, app.clone()));
                        }
                        // The earlier text goes: the row gets a new key.
                        planned.push(Planned::Put(
                            TableId::MESSAGE,
                            row,
                            Some(conversation.0),
                            changed,
                        ));
                        let next = (count.saturating_add(1), place.or(mark));
                        revised.insert(row, next);
                        planned.push(Planned::Put(REVISION, row, None, revision_row(next)));
                        events.push(Event::Edited {
                            conversation,
                            message: MsgRef(row),
                        });
                    }
                    // DEV-093: the target did not arrive yet. A deletion
                    // that waits for the same target stays.
                    None => {
                        let pending = open
                            .store
                            .row_id(PENDING, &pending_key(&natural, from_user));
                        let is_deleted = match pended.get(&pending) {
                            Some((_, entry)) => entry.len() == PENDING_ROW_LEN,
                            None => open
                                .store
                                .get(PENDING, &pending)?
                                .is_some_and(|entry| entry.len() == PENDING_ROW_LEN),
                        };
                        // DEV-095: the entries of this batch count too.
                        let held = open
                            .store
                            .list(PENDING, Some(&conversation.0))?
                            .len()
                            .saturating_add(
                                pended
                                    .values()
                                    .filter(|(held, _)| *held == conversation)
                                    .count(),
                            );
                        if is_deleted || held >= REF_ORPHAN_MAX {
                            continue;
                        }
                        if publishes {
                            to_publish.push((conversation, app.clone()));
                        }
                        let entry = Zeroizing::new(
                            [
                                conversation.0.as_slice(),
                                &reference,
                                &(now_ms / 1_000).to_be_bytes(),
                                edit.new_body.as_bytes(),
                            ]
                            .concat(),
                        );
                        pended.insert(pending, (conversation, entry.clone()));
                        planned.push(Planned::Put(PENDING, pending, Some(conversation.0), entry));
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
                            let held = open
                                .store
                                .list(PENDING, Some(&conversation.0))?
                                .len()
                                .saturating_add(
                                    pended
                                        .values()
                                        .filter(|(held, _)| *held == conversation)
                                        .count(),
                                );
                            if held >= REF_ORPHAN_MAX {
                                continue;
                            }
                            let pending = open
                                .store
                                .row_id(PENDING, &pending_key(&natural, from_user));
                            let entry = Zeroizing::new(
                                [
                                    conversation.0.as_slice(),
                                    &reference,
                                    &(now_ms / 1_000).to_be_bytes(),
                                ]
                                .concat(),
                            );
                            pended.insert(pending, (conversation, entry.clone()));
                            planned.push(Planned::Put(
                                PENDING,
                                pending,
                                Some(conversation.0),
                                entry,
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
            // DEV-093: the entry of the party that sent the message alone.
            // Thus an edit or a deletion of the contact takes no record of
            // the user. An entry of an earlier build names no direction,
            // and it came from the contact.
            let mut pending = open
                .store
                .row_id(PENDING, &pending_key(&natural, from_user));
            let mut waiting = match pended.remove(&pending) {
                Some((_, entry)) => Some(entry),
                None => open.store.get(PENDING, &pending)?.map(Zeroizing::new),
            };
            if waiting.is_none() && !from_user {
                pending = open.store.row_id(PENDING, &natural);
                waiting = open.store.get(PENDING, &pending)?.map(Zeroizing::new);
            }
            let mut edited_text = None;
            if let Some(entry) = waiting {
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
            // DEV-205: either party sets the timer, and the record stays in
            // the conversation as the mark of the change (`DEV-207`).
            if parsed.kind == AppKind::ConversationTimer {
                let Some(seconds) = timers::timer_body(parsed.body) else {
                    continue;
                };
                timers.insert(conversation, seconds);
                let setting = TimerSetting {
                    seconds,
                    set_at_ms: now_ms,
                    by_user: from_user,
                };
                planned.push(Planned::Put(
                    timers::TIMERS,
                    open.store.row_id(timers::TIMERS, &conversation.0),
                    Some(conversation.0),
                    setting.encode(),
                ));
            }
            // DEV-208, DEV-244: the period runs from the receive time here,
            // and a sync copy brings the rest of its own.
            let now = now_ms / 1_000;
            let deadline = if !timers::is_timed_kind(parsed.kind) {
                None
            } else if record.synced {
                (record.expires_in > 0).then(|| Deadline::from_sync(now, record.expires_in))
            } else {
                timers
                    .get(&conversation)
                    .filter(|seconds| **seconds > 0)
                    .map(|seconds| Deadline::received(now, *seconds))
            };
            if let Some(deadline) = deadline {
                planned.push(Planned::Put(
                    timers::DEADLINES,
                    row,
                    Some(conversation.0),
                    timers::deadline_row(conversation, deadline.at),
                ));
            }
            if handoff {
                // The record goes as the peer wrote it: its reply target
                // becomes a reference at the send (`WIR-071`).
                planned.push(Planned::Put(
                    TableId::MESSAGE,
                    row,
                    Some(conversation.0),
                    stored_message(
                        OUTGOING,
                        Delivery::Queued,
                        conversation,
                        open.stamp.next(now_ms),
                        app,
                    ),
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
                stored_message(
                    direction,
                    delivery,
                    conversation,
                    open.stamp.next(now_ms),
                    &kept,
                ),
            ));
            // WIR-187: the period of a poll runs from its receive time.
            if parsed.kind == AppKind::Poll {
                let open_seconds = Poll::parse(parsed.body).map_or(0, |poll| poll.open_seconds);
                planned.push(Planned::Put(
                    polls::POLLS,
                    row,
                    Some(conversation.0),
                    polls::poll_row(conversation, open_seconds, now),
                ));
            }
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
        // DEV-268, DEV-293: each record of a contact goes to each device of
        // the set, and its copy waits in the same commit as the record. Each
        // copy holds its place: the time of this commit, above each copy
        // that an earlier commit left, and its index in the batch.
        let mut order_ms = now_ms;
        if !to_publish.is_empty() {
            for (_, held) in open.store.list(PUBLISH_PENDING, None)? {
                let held = Zeroizing::new(held);
                let at = pending_copy(&held)
                    .and_then(|(order, _, _)| <[u8; 8]>::try_from(order.get(..8)?).ok())
                    .map_or(0, u64::from_be_bytes);
                order_ms = order_ms.max(at.saturating_add(1));
            }
        }
        let pending_copies: Vec<(RowId, Zeroizing<Vec<u8>>)> = to_publish
            .iter()
            .enumerate()
            .map(|(index, (conversation, app))| {
                let index = u32::try_from(index).unwrap_or(u32::MAX);
                let order = [order_ms.to_be_bytes().as_slice(), &index.to_be_bytes()].concat();
                (
                    open.store.row_id(PUBLISH_PENDING, &order),
                    Zeroizing::new([order.as_slice(), &conversation.0, app].concat()),
                )
            })
            .collect();
        let mut batch = open.store.begin();
        for write in &planned {
            match write {
                Planned::Put(table, row, owner, plain) => {
                    batch.put(*table, *row, *owner, plain, rng)?;
                }
                Planned::Delete(table, row) => batch.delete(*table, *row),
            }
        }
        // IMP-154: an edit keeps no earlier text in the log of the store.
        if events
            .iter()
            .any(|event| matches!(event, Event::Edited { .. }))
        {
            batch.erase_earlier();
        }
        for (row, value) in &pending_copies {
            batch.put(PUBLISH_PENDING, *row, None, value, rng)?;
        }
        batch.commit()?;
        self.events.extend(events);
        // IMP-132: the batch is in the store, and the relay gives no record
        // of it again. Thus each step below runs to its end. A record that
        // one step does not take is one drop, and a fault of the store in
        // one step stops no other step. The first such fault is the result.
        let mut fault: Option<Error> = None;
        let mut settle = |result: Result<(), Error>| match result {
            Ok(()) | Err(Error::Malformed | Error::TooLong | Error::NotFound | Error::Busy) => {}
            Err(error) => {
                fault.get_or_insert(error);
            }
        };
        settle(self.publish_pending(now_ms / 1_000, rng));
        // DEV-304: each other device of the set holds a copy of the message.
        for (row, delivery) in delivered {
            let _ = self.publish_delivery(&row, delivery, rng);
        }
        self.files.downloads.extend(wanted);
        for outgoing in handoffs {
            self.synced_out.insert(outgoing.message);
            self.outgoing.push_back(outgoing);
        }
        for (conversation, body) in control {
            settle(self.on_pairwise_control(conversation, &body, now_ms, rng));
        }
        for (conversation, body) in key_requests {
            // WIR-455: a request of scope 0x01 names a record of this
            // device on this channel, and the others name a group.
            let is_session =
                KeyRequest::parse(&body).is_ok_and(|request| request.scope == KeyScope::Session);
            settle(if is_session {
                self.on_session_key_request(conversation, &body, now_ms, rng)
            } else {
                self.on_pairwise_key_request(&body, now_ms, rng)
            });
        }
        for (conversation, body) in supplies {
            settle(self.on_key_supply(conversation, &body, now_ms, rng));
        }
        for (conversation, body) in shares {
            settle(self.take_share(conversation, &body, now_ms, rng));
        }
        for (conversation, body) in intros {
            settle(self.take_intro(conversation, &body, now_ms, rng));
        }
        for (conversation, body) in key_changes {
            settle(self.take_key_change(conversation, &body, now_ms, rng));
        }
        for (conversation, body, voter) in votes {
            settle(
                self.take_vote(conversation, &body, voter, now_ms, now_ms / 1_000, rng)
                    .map(|_| ()),
            );
        }
        if !digests.is_empty() {
            settle(self.take_digests(&digests, now_ms / 1_000, rng));
        }
        if !sync_bodies.is_empty() {
            match self.take_sync_bodies(sync_bodies, now_ms / 1_000, rng) {
                Ok((synced, inbox)) => match self.store_synced(synced, now_ms, rng) {
                    // DEV-013: the store holds each record, thus the inbox
                    // lets go. A record that did not store stays in it.
                    Ok(()) => settle(self.drop_sync_inbox(&inbox)),
                    Err(error) => settle(Err(error)),
                },
                Err(error) => settle(Err(error)),
            }
        }
        fault.map_or(Ok(()), Err)
    }

    /// Stores the records that a sync channel gave, in the conversations
    /// they name (Part 7 §7.5).
    fn store_synced<R: CryptoRng + ?Sized>(
        &mut self,
        synced: Vec<sync::Synced>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        // DEV-126: a deletion of the user on another device of the set.
        let synced = self.take_own_deletions(synced, rng)?;
        // DEV-015: each synced message keeps its source and counter.
        let origins: Vec<(ConversationId, Vec<u8>, umbra_core::devset::DeviceId, u64)> = synced
            .iter()
            .map(|record| {
                (
                    record.conversation,
                    record.app.clone(),
                    record.origin.0,
                    record.origin.1,
                )
            })
            .collect();
        let (groups, synced): (Vec<_>, Vec<_>) =
            synced.into_iter().partition(|synced| synced.is_group);
        for record in groups {
            // A record that does not apply ends no batch.
            let _ = self.apply_synced_group(
                record.conversation,
                &record.app,
                record.expires_in,
                now_ms,
                rng,
            );
        }
        let places: Vec<Option<SyncPlace>> =
            synced.iter().map(|synced| Some(synced.origin)).collect();
        let records: Vec<Record> = synced
            .into_iter()
            .map(|synced| Record {
                conversation: synced.conversation,
                app: synced.app,
                from_user: synced.from_user,
                synced: true,
                expires_in: synced.expires_in,
            })
            .collect();
        if !records.is_empty() {
            self.commit_records_at(&[], &records, &places, now_ms, rng)?;
        }
        for (conversation, app, source, counter) in origins {
            let Ok(parsed) = AppMessage::parse(&app, Channel::Pairwise) else {
                continue;
            };
            let open = self.open_ref()?;
            let reference = msg_ref(&open.device_set_key, &parsed.msg_id);
            let natural = [conversation.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            self.keep_sync_origin(row, &source, counter, rng)?;
        }
        Ok(())
    }

    /// Stores each record that an earlier run took from a sync channel and
    /// did not store, at the start of a run (`DEV-013`). A record that does
    /// not store now goes, as it would have gone in its own run.
    pub fn replay_sync_inbox<R: CryptoRng + ?Sized>(
        &mut self,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let (synced, rows) = self.sync_inbox()?;
        if rows.is_empty() {
            return Ok(());
        }
        let _ = self.store_synced(synced, now_ms, rng);
        self.drop_sync_inbox(&rows)
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
        let mut rendezvous_queues = Vec::new();
        for (_, plain) in store.list(discovery::RENDEZVOUS_STATE, None)? {
            rendezvous_queues.push(state_of(plain)?);
        }
        Ok(StoredNetwork {
            contacts,
            invitations,
            notify_queues,
            rendezvous_queues,
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

    /// The clock correction of the relay directory, if the device holds
    /// one (`REL-113`, `REL-114`).
    pub fn directory_correction(&self) -> Result<Option<i64>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(SETTINGS, DIRECTORY_CORRECTION_SETTING);
        let Some(plain) = store.get(SETTINGS, &row)? else {
            return Ok(None);
        };
        let value: [u8; 8] = plain.as_slice().try_into().map_err(|_| Error::Integrity)?;
        Ok(Some(i64::from_be_bytes(value)))
    }

    /// Keeps the clock correction that an accepted root gave (`REL-114`,
    /// `REL-044`).
    pub fn set_directory_correction<R: CryptoRng + ?Sized>(
        &mut self,
        correction: i64,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.directory_correction()? == Some(correction) {
            return Ok(());
        }
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, DIRECTORY_CORRECTION_SETTING);
        let mut batch = open.store.begin();
        batch.put(SETTINGS, row, None, &correction.to_be_bytes(), rng)?;
        batch.commit()?;
        Ok(())
    }

    /// Discards the clock correction after a clock movement (`REL-115`).
    pub fn clear_directory_correction(&mut self) -> Result<(), Error> {
        if self.directory_correction()?.is_none() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let row = open.store.row_id(SETTINGS, DIRECTORY_CORRECTION_SETTING);
        let mut batch = open.store.begin();
        batch.delete(SETTINGS, row);
        batch.commit()?;
        Ok(())
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
        self.put_verified(conversation, peer_static, now_ms, rng)?;
        // DEV-197: each other device of the set takes the state.
        if self.has_sync_peers()? {
            let Some(subject) = self.subject_of(conversation)? else {
                return Ok(());
            };
            let value = [peer_static.as_slice(), &now_ms.to_be_bytes()].concat();
            self.publish_mutable(ITEM_VERIFICATION, &subject, &value, rng)?;
        }
        Ok(())
    }

    /// Keeps the verification state of a conversation.
    fn put_verified<R: CryptoRng + ?Sized>(
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
        // DEV-294: a contact whose channel another device owns holds the
        // salt alone here. This device cannot compare the key, thus it shows
        // no verified mark, and the device that owns the channel shows it.
        if self.is_shadow_contact(conversation)? {
            return Ok(false);
        }
        let (_, peer) = self.identity_keys(conversation)?;
        Ok(plain.get(16..48) == Some(peer.as_slice()))
    }

    /// Whether the stored contact of a conversation is the shadow form of
    /// `DEV-294`. That form is the salt of a contact whose channel another
    /// device of the set owns. It holds no key of the peer and no ratchet.
    pub(super) fn is_shadow_contact(&self, conversation: ConversationId) -> Result<bool, Error> {
        let store = &self.open_ref()?.store;
        let Some(plain) = store.get(TableId::CONTACT, &conversation.0)? else {
            return Ok(false);
        };
        let plain = Zeroizing::new(plain);
        let state = plain.get(QUEUE_ID_LEN..).ok_or(Error::Integrity)?;
        let root = self.root_identity()?;
        Ok(stored_contact_keys(state, &root).is_err()
            && umbra_core::session::node::stored_contact_salt(state).is_ok())
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
        self.put_conversation_meta(conversation, read_up_to, name, rng)?;
        // DEV-197: the name is mutable state of the set.
        self.publish_contact_name(conversation, name, rng)
    }

    /// The name of a contact that another device of the set gave.
    pub(super) fn apply_contact_name<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        name: &str,
        rng: &mut R,
    ) -> Result<(), Error> {
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
        // DEV-031: a message stores the insertion stamp, which a clock that
        // moved back leaves above the clock; the marker covers each one.
        let now_ms = now_ms.max(self.open_ref()?.stamp.last);
        let (read_up_to, name) = self.conversation_meta(conversation)?;
        if now_ms <= read_up_to {
            return Ok(());
        }
        // NET-042: the user opened the conversation, and no other act gives
        // a read receipt. ABU-031: a blocked contact gets none.
        if self.receipt_settings(conversation)?.read && !self.is_blocked(conversation)? {
            self.hold_read_receipts(conversation, read_up_to, now_ms / 1_000, rng)?;
        }
        self.put_conversation_meta(conversation, now_ms, &name, rng)?;
        self.auto_lock.touch(now_ms / 1_000);
        // DEV-197: the read marker converges across the set.
        if self.has_sync_peers()? {
            let Some(subject) = self.subject_of(conversation)? else {
                return Ok(());
            };
            self.publish_mutable(ITEM_READ_MARKER, &subject, &now_ms.to_be_bytes(), rng)?;
        }
        Ok(())
    }

    /// Whether the set holds another device, thus a mutable item goes on.
    fn has_sync_peers(&self) -> Result<bool, Error> {
        Ok(self.sync_engine()?.is_some())
    }

    /// Takes the read marker or the verification state of another device
    /// of the set. A read marker moves forward alone, and it sends no read
    /// receipt, since the device that read sent it.
    pub(super) fn apply_converged_item<R: CryptoRng + ?Sized>(
        &mut self,
        item: u8,
        subject: &[u8; 32],
        value: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        let Some(conversation) = self.conversation_of_subject(subject)? else {
            return Ok(());
        };
        match item {
            ITEM_READ_MARKER => {
                let at: [u8; 8] = value.try_into().map_err(|_| Error::Malformed)?;
                let at = u64::from_be_bytes(at);
                let (read_up_to, name) = self.conversation_meta(conversation)?;
                if at > read_up_to {
                    self.put_conversation_meta(conversation, at, &name, rng)?;
                    self.events.push_back(Event::Conversations);
                }
            }
            ITEM_VERIFICATION => {
                let peer_static: [u8; 32] = value
                    .get(..32)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Malformed)?;
                let at: [u8; 8] = value
                    .get(32..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(Error::Malformed)?;
                self.put_verified(conversation, &peer_static, u64::from_be_bytes(at), rng)?;
                self.events.push_back(Event::Conversations);
            }
            _ => {}
        }
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
        let mut newest: Option<((u64, RowId), [u8; 16])> = None;
        let mut owner_fault = false;
        for (row, plain) in open.store.list(TableId::MESSAGE, Some(&conversation.0))? {
            let plain = Zeroizing::new(plain);
            // IMP-121: the plaintext names its owner. A receipt to this
            // contact names no record of another conversation. This call
            // skips such a row, and the user learns of the fault one time
            // (`IDN-039`). The read receipts of the contact still go.
            if conversation_of(&plain).ok() != Some(conversation) {
                owner_fault = true;
                continue;
            }
            let info = info_of(&plain)?;
            if info.outgoing || info.stored_at_ms <= read_up_to {
                continue;
            }
            // DEV-032: the stamp orders, and the row breaks a tie.
            let order = (info.stored_at_ms, row);
            if newest.is_none_or(|(held, _)| order > held) {
                let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
                let target = AppMessage::parse(app, Channel::Pairwise)?.msg_id;
                newest = Some((order, target));
            }
        }
        let Some((_, target)) = newest else {
            if owner_fault {
                self.events.push_back(Event::IntegrityFault);
            }
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
        batch.commit()?;
        if owner_fault {
            self.events.push_back(Event::IntegrityFault);
        }
        Ok(())
    }

    /// Removes a message, or the placeholder of a deleted one, from this
    /// device (`DEV-105`). No record leaves the device, and the store erases
    /// the row and its key.
    pub fn delete_for_me(&mut self, message: &MsgRef) -> Result<(), Error> {
        self.remove_message(message, true)
    }

    /// Removes a message whose period of the history ended on this device
    /// (Part 7 §7.5.2). `ATT-161` erases the chunks of a file at a
    /// tombstone or at a timer expiry, and the end of that period is
    /// neither. The contact can still hold the descriptor and no file. Thus
    /// the chunks stay at their relays until their own life ends. The
    /// credential row and its copy for the erase go with the message, since
    /// no later deletion can name them. A row that a deletion erased first
    /// counts as done.
    pub(crate) fn remove_aged(&mut self, message: &MsgRef) -> Result<(), Error> {
        match self.remove_message(message, false) {
            Err(Error::NotFound) => Ok(()),
            other => other,
        }
    }

    /// The removal of [`Client::delete_for_me`]. `erases` says whether the
    /// chunks of a file that this device uploaded go at their relays too.
    fn remove_message(&mut self, message: &MsgRef, erases: bool) -> Result<(), Error> {
        self.outgoing.retain(|waiting| waiting.message != *message);
        self.files.uploads.retain(|job| job.message != *message);
        self.files.downloads.retain(|job| job.message != *message);
        let conversation = self.conversation_of_message(message)?;
        let reactions = self.reaction_rows(message, conversation)?;
        let votes = self.vote_rows(message, conversation)?;
        let erasure = if erases {
            Some(self.file_erasures(message)?)
        } else {
            None
        };
        // ATT-161: a deletion takes the hold, thus the copy of the
        // credentials is due. The end of the history period erases no
        // chunk, and it takes the copy too.
        let erase_rows = match &erasure {
            Some(erasure) => erasure.rows(message),
            None => self.erase_rows(message)?.to_vec(),
        };
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in reactions {
            batch.delete(REACTION, row);
        }
        for row in erase_rows {
            batch.delete(ERASE_DUE, row);
        }
        batch.delete(TableId::MESSAGE, message.0);
        batch.delete(OUTBOX, message.0);
        batch.delete(REVISION, message.0);
        batch.delete(FAILURE, message.0);
        batch.delete(timers::DEADLINES, message.0);
        batch.delete(polls::POLLS, message.0);
        batch.delete(groups::MENTIONED, message.0);
        batch.delete(moderation::MODERATED, message.0);
        batch.delete(group_changes::GROUP_SENDER, message.0);
        for row in votes {
            batch.delete(polls::VOTES, row);
        }
        for table in [FILE_STATE, FILE_DATA, CHUNK_CRED] {
            batch.delete(table, message.0);
        }
        batch.commit()?;
        // ATT-161: a deletion of a record with a file that this device
        // uploaded erases each chunk at its relays.
        if let Some(erasure) = erasure {
            self.start_erasures(message, erasure);
        }
        Ok(())
    }

    /// Removes a message as [`Client::delete_for_me`] does, and takes a row
    /// that a deletion erased first as done. Any other fault stays, thus a
    /// sweep keeps the row that points at the message.
    pub(crate) fn delete_if_held(&mut self, message: &MsgRef) -> Result<(), Error> {
        match self.delete_for_me(message) {
            Err(Error::NotFound) => Ok(()),
            other => other,
        }
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
        let stored = stored_message(
            OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            &request,
        );

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
        // An edit in a group is one group record (Part 7 §7.5.6).
        let is_group = self.is_group(draft.conversation())?;
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
        let (count, mark) = revision_of(open.store.get(REVISION, &message.0)?.as_deref())?;
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
        let stored = stored_message(
            OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            &request,
        );
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
        batch.put(
            REVISION,
            message.0,
            None,
            &revision_row((count.saturating_add(1), mark)),
            rng,
        )?;
        // IMP-154: the earlier text leaves the log of the store.
        batch.erase_earlier();
        if !is_group {
            batch.put(
                TableId::MESSAGE,
                request_row,
                Some(conversation.0),
                &stored,
                rng,
            )?;
            batch.put(OUTBOX, request_row, None, &outbox_row(), rng)?;
        }
        batch.commit()?;
        if is_group {
            self.post_to_group(conversation, msg_id, &request, now_ms, rng)?;
            self.auto_lock.touch(now_ms / 1_000);
            return Ok(());
        }

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

    /// Sends a message of this device again after a failure. A failed
    /// record goes again only by an action of the user (`IMP-075`). A file
    /// takes its own path, thus this call refuses one.
    pub fn send_again<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_ref()?;
        let mut plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let info = info_of(&plain)?;
        if !info.outgoing
            || info.delivery != Delivery::Failed
            || info.deleted
            || is_request(&plain)?
        {
            return Err(Error::Malformed);
        }
        if open.store.get(FILE_STATE, &message.0)?.is_some() {
            return Err(Error::Malformed);
        }
        let conversation = conversation_of(&plain)?;
        let app = plain
            .get(MESSAGE_PREFIX..)
            .ok_or(Error::Integrity)?
            .to_vec();
        *plain.get_mut(1).ok_or(Error::Integrity)? = Delivery::Queued as u8;
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        batch.put(
            TableId::MESSAGE,
            message.0,
            Some(conversation.0),
            &plain,
            rng,
        )?;
        batch.put(OUTBOX, message.0, None, &outbox_row(), rng)?;
        batch.commit()?;
        self.events.push_back(Event::Delivery {
            message: *message,
            delivery: Delivery::Queued,
        });
        if self.is_group(conversation)? {
            self.queue_group_post(conversation, Some(*message), &app, now_ms, rng)?;
        } else {
            self.outgoing.push_back(Outgoing {
                message: *message,
                conversation,
                app,
            });
        }
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
        // A deletion in a group is one group record (Part 7 §7.5.6).
        let is_group = self.is_group(self.conversation_of_message(message)?)?;
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
        // The rate comes first, and the hold of the erase leaves in the
        // batch below: a call that changes nothing makes no chunk due.
        let erasure = self.file_erasures(message)?;
        let open = self.open_mut()?;
        let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let target = AppMessage::parse(app, Channel::Pairwise)?.msg_id;
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let request = deletion_record(msg_id, now_ms, target)?;
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let request_row = open.store.row_id(TableId::MESSAGE, &natural);
        let stored = stored_message(
            OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            &request,
        );

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
        for row in erasure.rows(message) {
            batch.delete(ERASE_DUE, row);
        }
        for row in reactions {
            batch.delete(REACTION, row);
        }
        if !is_group {
            batch.put(
                TableId::MESSAGE,
                request_row,
                Some(conversation.0),
                &stored,
                rng,
            )?;
            batch.put(OUTBOX, request_row, None, &outbox_row(), rng)?;
        }
        batch.put(SETTINGS, limit_row, None, &now.to_be_bytes(), rng)?;
        batch.commit()?;
        if is_group {
            self.start_erasures(message, erasure);
            self.files.uploads.retain(|job| job.message != *message);
            self.outgoing.retain(|waiting| waiting.message != *message);
            self.post_to_group(conversation, msg_id, &request, now_ms, rng)?;
            self.auto_lock.touch(now);
            return Ok(());
        }

        // ATT-161: the chunks of a file that this device uploaded go too.
        self.start_erasures(message, erasure);
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
    ///
    /// The call skips a row that does not read, or that names another
    /// owner. The list of the conversations is the way to each other
    /// conversation, thus it never fails as a whole for one row. Such a row
    /// is a fault of the file, and the call gives one
    /// [`Event::IntegrityFault`] for it (`IDN-039`, `IDN-040`). A shorter
    /// history and a lower count with no word would hide the fault.
    pub fn summaries(&mut self) -> Result<Vec<ConversationSummary>, Error> {
        let (out, is_sound) = self.read_summaries()?;
        if !is_sound {
            self.events.push_back(Event::IntegrityFault);
        }
        Ok(out)
    }

    /// The summaries, and whether each row of them read.
    fn read_summaries(&self) -> Result<(Vec<ConversationSummary>, bool), Error> {
        let store = &self.open_ref()?.store;
        let mut out = Vec::new();
        let mut is_sound = true;
        for conversation in self.conversations()? {
            // The line of the developer names the fault in a debug build.
            let (read_up_to, name) = self.conversation_meta(conversation).unwrap_or_else(|_| {
                crate::devlog::line("summaries: a conversation row does not read");
                is_sound = false;
                (0, String::new())
            });
            let mut last: Option<(u64, RowId)> = None;
            let mut unread = 0u32;
            for (row, plain) in store.list(TableId::MESSAGE, Some(&conversation.0))? {
                let plain = Zeroizing::new(plain);
                // IMP-121: the plaintext names its owner, and a row of
                // another conversation counts for none here.
                if conversation_of(&plain).ok() != Some(conversation) {
                    crate::devlog::line("summaries: a message row names another owner");
                    is_sound = false;
                    continue;
                }
                let (Ok(is_hidden), Ok(info)) = (is_request(&plain), info_of(&plain)) else {
                    crate::devlog::line("summaries: a message row does not read");
                    is_sound = false;
                    continue;
                };
                if is_hidden {
                    continue;
                }
                if !info.outgoing && info.stored_at_ms > read_up_to {
                    unread = unread.saturating_add(1);
                }
                let key = (info.stored_at_ms, row);
                if last.is_none_or(|newest| key > newest) {
                    last = Some(key);
                }
            }
            out.push(ConversationSummary {
                conversation,
                name,
                last: last.map(|(_, row)| MsgRef(row)),
                last_at_ms: last.map_or(0, |(stored_at, _)| stored_at),
                unread,
                verified: self.is_verified(conversation).unwrap_or_else(|_| {
                    crate::devlog::line("summaries: a verification row does not read");
                    is_sound = false;
                    false
                }),
            });
        }
        out.sort_by_key(|summary| core::cmp::Reverse(summary.last_at_ms));
        Ok((out, is_sound))
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

    /// `K_rng_harden` of this store (Part 5 §5.2, Part 14 `IMP-093`). It
    /// comes from the storage seed, thus a reset of the identity keeps it.
    pub fn rng_harden_key(&self) -> Result<Secret<32>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(TableId::LOCAL_IDENTITY, ROOT_KEY);
        let seed = Zeroizing::new(
            store
                .get(TableId::LOCAL_IDENTITY, &row)?
                .ok_or(Error::Integrity)?,
        );
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| Error::Integrity)?;
        Ok(RootIdentity::new(Secret::new(seed)).rng_harden_key())
    }

    /// The seed of the root identity: the identity root of a reset, or the
    /// seed of the store.
    fn root_seed(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        if let Some(seed) = self.identity_seed()? {
            return Ok(Zeroizing::new(seed));
        }
        let store = &self.open_ref()?.store;
        let row = store.row_id(TableId::LOCAL_IDENTITY, ROOT_KEY);
        let seed = Zeroizing::new(
            store
                .get(TableId::LOCAL_IDENTITY, &row)?
                .ok_or(Error::Integrity)?,
        );
        Ok(Zeroizing::new(
            seed.as_slice().try_into().map_err(|_| Error::Integrity)?,
        ))
    }

    /// Gives the root seed to `sink` as `RecoveryDigits` of type `0x0004`
    /// (Part 4 `IDN-003`, `IDN-149`). It rebuilds the root identity and no
    /// contact.
    pub fn render_root_seed(&self, sink: &mut dyn Sink) -> Result<(), Error> {
        let seed = self.root_seed()?;
        let digits = umbra_core::identity::recovery::to_digits(
            umbra_core::identity::recovery::DigitsType::Root,
            seed.as_slice(),
        )?;
        let units: Zeroizing<Vec<u16>> = Zeroizing::new(digits.encode_utf16().collect());
        sink.put(&units);
        Ok(())
    }

    /// The root identity of the device, for the network runtime.
    pub fn root_identity(&self) -> Result<RootIdentity, Error> {
        // Part 7 §7.7.1: a reset gives an identity root of its own.
        if let Some(seed) = self.identity_seed()? {
            return Ok(RootIdentity::new(Secret::new(seed)));
        }
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
        let conversation = draft.conversation();
        let message = self.send_checked(draft, now_ms, rng)?;
        // DEV-201: a send erases the draft from the set. A send that this
        // call refused sent nothing, thus the stored draft of each device
        // stays for the next try.
        self.clear_draft(conversation, rng)?;
        Ok(message)
    }

    /// The send of [`Client::send_draft`], with each of its checks.
    fn send_checked<R: CryptoRng + ?Sized>(
        &mut self,
        mut draft: Draft,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        let mut msg_id = [0u8; 16];
        rng.fill_bytes(&mut msg_id);
        let conversation = draft.conversation();
        if let Some(file) = draft.take_file() {
            // The record of a file answers nothing, and its text is a
            // caption of CAPTION_MAX at most (WIR-535).
            if draft.reply_to().is_some() {
                return Err(Error::Malformed);
            }
            if draft.text().len() > umbra_wire::descriptor::CAPTION_MAX {
                return Err(Error::TooLong);
            }
            return self.send_file(conversation, msg_id, file, draft.text(), now_ms, rng);
        }
        // A mention names a member of a group by its pair key (`GRP-334`).
        let is_group = self.is_group(conversation)?;
        let mentions = if is_group && !draft.mentions().is_empty() {
            self.mention_ids(conversation, draft.mentions())?
        } else if draft.mentions().is_empty() {
            Vec::new()
        } else {
            // WIR-175: a pairwise record names no member.
            return Err(Error::Malformed);
        };
        let channel = if is_group {
            Channel::Group
        } else {
            Channel::Pairwise
        };
        // A reply is a rich record around the text. The wire carries the raw
        // `msg_id` of the target, which the row of the target holds.
        let rich = match draft.reply_to() {
            None if mentions.is_empty() => None,
            None => {
                let record = RichRecord {
                    reply_target: [0; 16],
                    thread_root: [0; 16],
                    forward_depth: 0,
                    mentions,
                    inner_kind: AppKind::Text,
                    inner_body: draft.text(),
                };
                let mut body = Zeroizing::new(vec![0u8; record.len()]);
                record.encode(channel, &mut body)?;
                Some(body)
            }
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
                // WIR-269: a pairwise record is in no thread.
                let thread_root = if is_group {
                    self.thread_root_for(&plain, &info_of(&plain)?)?
                } else {
                    [0; 16]
                };
                // The row of a message of this device holds the raw
                // `msg_id` of its answer while no relay took it, and the
                // raw `msg_id` of the message itself at each time.
                let record = RichRecord {
                    reply_target: AppMessage::parse(held, Channel::Group)?.msg_id,
                    thread_root,
                    forward_depth: 0,
                    mentions,
                    inner_kind: AppKind::Text,
                    inner_body: draft.text(),
                };
                let mut body = Zeroizing::new(vec![0u8; record.len()]);
                record.encode(channel, &mut body)?;
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
        self.send_app(conversation, msg_id, &app, is_group, now_ms, rng)
    }

    /// Stores one encoded record of this device in its conversation and
    /// hands it to the send path: the group queue of a group, or the
    /// pairwise channel of a contact.
    pub(super) fn send_app<R: CryptoRng + ?Sized>(
        &mut self,
        conversation: ConversationId,
        msg_id: [u8; 16],
        app: &[u8],
        is_group: bool,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        // IDN-025: a conversation with a key change that waits takes no
        // message before the answer of the user.
        if !is_group && self.key_change(conversation)?.is_some() {
            return Err(Error::Busy);
        }
        // A group record goes to the two replicas of its group queue and
        // on no pairwise channel (Part 11 §11.2).
        if is_group {
            let message = self.post_to_group(conversation, msg_id, app, now_ms, rng)?;
            self.auto_lock.touch(now_ms / 1_000);
            return Ok(message);
        }

        // DEV-215, DEV-245: the deadline of a timed message is in the
        // commit of the message. Thus no crash leaves a message of a timed
        // conversation that never expires.
        let seconds = self.timer_seconds(conversation)?;
        let open = self.open_mut()?;
        // IMP-024, IMP-025: the store holds the keyed form of `msg_id`.
        let reference = msg_ref(&open.device_set_key, &msg_id);
        let natural = [conversation.0.as_slice(), &reference].concat();
        let row = open.store.row_id(TableId::MESSAGE, &natural);
        let plain = stored_message(
            OUTGOING,
            Delivery::Queued,
            conversation,
            open.stamp.next(now_ms),
            app,
        );
        let mut batch = open.store.begin();
        batch.put(TableId::MESSAGE, row, Some(conversation.0), &plain, rng)?;
        batch.put(OUTBOX, row, None, &outbox_row(), rng)?;
        if seconds > 0 {
            let deadline = Deadline::received(now_ms / 1_000, seconds);
            batch.put(
                timers::DEADLINES,
                row,
                Some(conversation.0),
                &timers::deadline_row(conversation, deadline.at),
                rng,
            )?;
        }
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
        caption: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<MsgRef, Error> {
        // The stored record holds the caption alone until the upload ends,
        // and the body with the descriptor takes its place then.
        let record = AppMessage {
            kind: AppKind::Attachment,
            msg_id,
            sent_at: now_ms,
            body: caption,
        };
        let mut app = vec![0u8; record.len()];
        record.encode(&mut app)?;
        // DEV-215: the deadline is in the commit of the message.
        let seconds = self.timer_seconds(conversation)?;
        let open = self.open_mut()?;
        let reference = msg_ref(&open.device_set_key, &msg_id);
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
        if seconds > 0 {
            let deadline = Deadline::received(now_ms / 1_000, seconds);
            batch.put(
                timers::DEADLINES,
                row,
                Some(conversation.0),
                &timers::deadline_row(conversation, deadline.at),
                rng,
            )?;
        }
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

    /// A stored record of this device in the form that goes again on the
    /// wire (`WIR-071`). After the first send the row holds the target of a
    /// reply, and the root of a thread, as a keyed reference. The row of
    /// that target holds its raw `msg_id`. A target that left the store
    /// keeps its reference, and the contact shows it as absent.
    pub(super) fn with_raw_targets(
        &self,
        conversation: ConversationId,
        app: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = app.to_vec();
        let store = &self.open_ref()?.store;
        let fields = [reply_field(app), thread_field(app)];
        for field in fields.into_iter().filter_map(Result::ok).flatten() {
            let Some(reference) = app.get(field.clone()) else {
                continue;
            };
            let natural = [conversation.0.as_slice(), reference].concat();
            let row = store.row_id(TableId::MESSAGE, &natural);
            let Some(target) = store.get(TableId::MESSAGE, &row)? else {
                continue;
            };
            let target = Zeroizing::new(target);
            let raw = target
                .get(MESSAGE_PREFIX..)
                .and_then(|held| AppMessage::parse(held, Channel::Group).ok())
                .map(|parsed| parsed.msg_id);
            if let (Some(raw), Some(place)) = (raw, out.get_mut(field)) {
                place.copy_from_slice(&raw);
            }
        }
        Ok(out)
    }

    /// The next record for the send path of the runtime.
    pub fn take_outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.pop_front()
    }

    /// Fails a message of this device and keeps its cause (`IMP-074`).
    pub fn fail<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        cause: crate::FailureCause,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.set_delivery_with(message, Delivery::Failed, Some(cause), rng)
    }

    /// The send path reports a delivery state of a message.
    pub fn set_delivery<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        delivery: Delivery,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.set_delivery_with(message, delivery, None, rng)
    }

    /// A delivery state and, for a failure, its cause, in one commit.
    fn set_delivery_with<R: CryptoRng + ?Sized>(
        &mut self,
        message: &MsgRef,
        delivery: Delivery,
        cause: Option<crate::FailureCause>,
        rng: &mut R,
    ) -> Result<(), Error> {
        // DEV-313: the notice of a revocation is no message, and its state
        // ends the channel of the revoked device.
        if self.notice_delivery(message, delivery, rng)? {
            return Ok(());
        }
        // Part 3 §3.2.6: the acknowledgment of a relay starts the silence
        // of the channel, which a record of the peer ends.
        if delivery == Delivery::Accepted {
            self.relay_accepted(message, rng)?;
        }
        let open = self.open_mut()?;
        let mut plain = Zeroizing::new(
            open.store
                .get(TableId::MESSAGE, &message.0)?
                .ok_or(Error::NotFound)?,
        );
        let conversation = conversation_of(&plain)?;
        let is_notice = plain
            .get(MESSAGE_PREFIX..)
            .and_then(|app| AppMessage::parse(app, Channel::Pairwise).ok())
            .is_some_and(|parsed| parsed.kind == AppKind::KeyChange);
        if is_request(&plain)? && !matches!(delivery, Delivery::Queued | Delivery::Failed) {
            // WIR-071: the request held a raw `msg_id` for its send, and a
            // relay has it now. No view showed the row.
            let mut batch = open.store.begin();
            batch.delete(TableId::MESSAGE, message.0);
            batch.delete(OUTBOX, message.0);
            // IDN-063: a relay took the key-change notice of this contact,
            // and it waits for no second send.
            if is_notice {
                batch.delete(reset::RESET_NOTICES, conversation.0);
            }
            return Ok(batch.commit()?);
        }
        // DEV-304: a state goes up only. A copy that went again reports
        // `accepted`, or fails, after a receipt named the first copy, and
        // the receipt stays.
        if matches!(
            info_of(&plain)?.delivery,
            Delivery::Delivered | Delivery::Read
        ) && !info_of(&plain)?.delivery.is_below(delivery)
        {
            let mut batch = open.store.begin();
            batch.delete(OUTBOX, message.0);
            return Ok(batch.commit()?);
        }
        // A failed record keeps its raw target, because the user can send it
        // again (`IMP-075`).
        if info_of(&plain)?.delivery == Delivery::Queued
            && !matches!(delivery, Delivery::Queued | Delivery::Failed)
        {
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
        match (delivery, cause) {
            (Delivery::Failed, Some(cause)) => {
                batch.put(FAILURE, message.0, None, &[cause as u8], rng)?;
            }
            (Delivery::Failed, None) => {}
            // A record that goes again, or that a relay took, fails no more.
            _ => batch.delete(FAILURE, message.0),
        }
        // IDN-063: a key-change notice that reached no relay goes again
        // after a new delay of its own, in the commit of the failure. No
        // view shows its row, thus no user could send it again.
        if delivery == Delivery::Failed && is_notice {
            let mut draw = [0u8; 8];
            rng.fill_bytes(&mut draw);
            let due = unix_now_seconds().saturating_add(
                umbra_core::identity::keychange::sweep_delay(u64::from_be_bytes(draw)).max(1),
            );
            let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
            let value =
                Zeroizing::new([conversation.0.as_slice(), &due.to_be_bytes(), app].concat());
            batch.put(
                reset::RESET_NOTICES,
                conversation.0,
                Some(conversation.0),
                &value,
                rng,
            )?;
        }
        batch.commit()?;
        if delivery != Delivery::Queued {
            self.limit_sends.remove(message);
        }
        self.events.push_back(Event::Delivery {
            message: *message,
            delivery,
        });
        // The view of the identity shows a notice that waits again.
        if delivery == Delivery::Failed && is_notice {
            self.events.push_back(Event::Conversations);
        }
        // DEV-114: the user sees an edit or a deletion that reached no relay.
        if delivery == Delivery::Failed {
            if let Some(is_delete) = change_kind(&plain)? {
                self.events.push_back(Event::ChangeFailed {
                    conversation,
                    is_delete,
                });
            }
        }
        // DEV-304: a message that no relay took ends on each device.
        if delivery == Delivery::Failed {
            self.publish_delivery(&message.0, delivery, rng)?;
        }
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
        let plain = stored_message(
            INCOMING,
            Delivery::Delivered,
            conversation,
            open.stamp.next(now_ms),
            app,
        );
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
        !self.events.is_empty() || !self.groups.noted.is_empty()
    }

    /// The next event of the one stream from Rust to the platform.
    pub fn next_event(&mut self) -> Option<Event> {
        // A note of a roster comes after each event of the change that made
        // it, thus it takes no place before them.
        self.events
            .pop_front()
            .or_else(|| self.groups.noted.pop_first().map(|_| Event::Conversations))
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
        // The text of a file is its caption (WIR-535). A file of this
        // device holds the caption alone until its upload ends.
        let bytes = match parsed.kind {
            AppKind::Attachment => match umbra_wire::descriptor::AttachmentBody::parse(parsed.body)
            {
                Ok(body) => body.caption.map_or(&[][..], str::as_bytes),
                // A body that is no descriptor and no text shows no
                // caption, and the rest of the conversation shows.
                Err(_)
                    if info_of(&plain)?.outgoing && core::str::from_utf8(parsed.body).is_ok() =>
                {
                    parsed.body
                }
                Err(_) => &[][..],
            },
            // The mark of a timer change holds no text.
            AppKind::ConversationTimer => &[][..],
            // A poll shows its question.
            AppKind::Poll => umbra_wire::app::poll::Poll::parse(parsed.body)
                .map_or(&[][..], |poll| poll.question.as_bytes()),
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
        info.expires_at = self.deadline_of(message)?.map(|deadline| deadline.at);
        info.mentions_me = open.store.get(groups::MENTIONED, &message.0)?.is_some();
        info.sender = self.group_sender(message)?;
        info.recovered = self.is_recovered(message)?;
        // IMP-074: a failed message names its cause.
        if info.delivery == Delivery::Failed {
            info.failure = open
                .store
                .get(FAILURE, &message.0)?
                .and_then(|value| value.first().copied())
                .and_then(crate::FailureCause::from_byte);
        }
        if let Some((state, role)) = self.moderation_of(message)? {
            info.moderation = state;
            info.moderator_role = role;
        }
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
            // A record that waits for its relay, or that failed, holds the
            // raw target still.
            let reference =
                if info.outgoing && matches!(info.delivery, Delivery::Queued | Delivery::Failed) {
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
        // WIR-271, WIR-273: the root of the thread of a group record, in
        // its conversation alone.
        if let Some(field) = thread_field(app)? {
            let held: [u8; 16] = app
                .get(field)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            let reference =
                if info.outgoing && matches!(info.delivery, Delivery::Queued | Delivery::Failed) {
                    msg_ref(&open.device_set_key, &held)
                } else {
                    held
                };
            let natural = [conversation_of(&plain)?.0.as_slice(), &reference].concat();
            let row = open.store.row_id(TableId::MESSAGE, &natural);
            info.thread = open.store.get(TableId::MESSAGE, &row)?.map(|_| MsgRef(row));
        }
        Ok(info)
    }

    /// The raw `msg_id` of the root of the thread that a reply to `target`
    /// joins (`WIR-266` to `WIR-268`): the root of the target, or the
    /// target itself when it answers nothing, or none when the target is a
    /// reply outside each thread.
    fn thread_root_for(&self, target: &[u8], target_info: &MessageInfo) -> Result<[u8; 16], Error> {
        let app = target.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
        let parsed = AppMessage::parse(app, Channel::Group)?;
        if let Some(field) = thread_field(app)? {
            let held: [u8; 16] = app
                .get(field)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::Integrity)?;
            // A record that waits for its relay holds the raw root.
            if target_info.outgoing
                && matches!(target_info.delivery, Delivery::Queued | Delivery::Failed)
            {
                return Ok(held);
            }
            let natural = [conversation_of(target)?.0.as_slice(), &held].concat();
            let store = &self.open_ref()?.store;
            let row = store.row_id(TableId::MESSAGE, &natural);
            let Some(root) = store.get(TableId::MESSAGE, &row)? else {
                return Ok([0; 16]);
            };
            let root = Zeroizing::new(root);
            let root_app = root.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
            return Ok(AppMessage::parse(root_app, Channel::Group)?.msg_id);
        }
        if reply_field(app)?.is_none() {
            return Ok(parsed.msg_id);
        }
        Ok([0; 16])
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
            // DEV-031, DEV-032: the insertion stamp orders, and the row
            // breaks a tie.
            found.push((info.stored_at_ms, row));
        }
        found.sort_unstable();
        Ok(found.into_iter().map(|(_, row)| MsgRef(row)).collect())
    }

    /// Compares each table with its accumulator by a scan, outside the
    /// unlock path (`IDN-162`). A difference gives an
    /// [`Event::IntegrityFault`].
    pub fn audit(&mut self) -> Result<(), Error> {
        let open = self.open_ref()?;
        let tables = open.store.table_ids();
        if tables.iter().any(|table| open.store.audit(*table).is_err()) {
            self.events.push_back(Event::IntegrityFault);
            return Err(Error::Integrity);
        }
        Ok(())
    }

    /// Discards each pending reference older than `REF_ORPHAN_TTL` at
    /// `now` (`DEV-095`).
    fn sweep_pending_refs(&mut self, now: u64) -> Result<(), Error> {
        let mut gone = Vec::new();
        for (row, entry) in self.open_ref()?.store.list(PENDING, None)? {
            let entry = Zeroizing::new(entry);
            let at = entry
                .get(32..40)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes);
            if at.is_none_or(|at| now.saturating_sub(at) >= REF_ORPHAN_TTL) {
                gone.push(row);
            }
        }
        if gone.is_empty() {
            return Ok(());
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in gone {
            batch.delete(PENDING, row);
        }
        Ok(batch.commit()?)
    }

    /// One step of the scan of `IDN-162` at `now`: one table, and a pass
    /// over each table of the store in each `AUDIT_PERIOD`. The platform
    /// tick calls it, thus no step holds the store for long.
    pub fn audit_step(&mut self, now: u64) -> Result<(), Error> {
        let tables = self.open_ref()?.store.table_ids();
        if self.audit.next == 0 && now.saturating_sub(self.audit.started) < AUDIT_PERIOD {
            return Ok(());
        }
        if self.audit.next == 0 {
            self.audit.started = now;
            // DEV-095: a pending reference above REF_ORPHAN_TTL goes, thus
            // an expired one takes no place under REF_ORPHAN_MAX.
            self.sweep_pending_refs(now)?;
        }
        let Some(table) = tables.get(self.audit.next).copied() else {
            self.audit.next = 0;
            return Ok(());
        };
        self.audit.next = self.audit.next.saturating_add(1);
        if self.open_ref()?.store.audit(table).is_err() {
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
        timer: if parsed.kind == AppKind::ConversationTimer {
            timers::timer_body(parsed.body)
        } else {
            None
        },
        // The store holds the deadline: see `Client::info`.
        expires_at: None,
        poll: parsed.kind == AppKind::Poll,
        // The store holds the mark: see `Client::info`.
        mentions_me: false,
        recovered: false,
        // The store resolves the root: see `Client::info`.
        thread: None,
        // WIR-177: the depth of a forward, and zero for an original.
        forward_depth: plain.get(MESSAGE_PREFIX..).map_or(0, forward::depth_of),
        // The store holds the cause: see `Client::info`.
        failure: None,
        // The store holds the state: see `Client::info`.
        moderation: 0,
        moderator_role: 0,
        // The store holds the sender: see `Client::info`.
        sender: None,
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
        AppKind::Edit
            | AppKind::Reaction
            | AppKind::PollVote
            | AppKind::KeyChange
            | AppKind::RecoveryShare
            | AppKind::GroupControl
            | AppKind::KeyRequest
    ) || tombstone_of(&parsed)? == Some(Tombstone::Request))
}

/// Whether a stored record is an edit (`false`) or a deletion request
/// (`true`) of this device, or none for another record.
fn change_kind(plain: &[u8]) -> Result<Option<bool>, Error> {
    let app = plain.get(MESSAGE_PREFIX..).ok_or(Error::Integrity)?;
    let parsed = AppMessage::parse(app, Channel::Pairwise)?;
    if parsed.kind == AppKind::Edit {
        return Ok(Some(false));
    }
    Ok((tombstone_of(&parsed)? == Some(Tombstone::Request)).then_some(true))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use umbra_core::{
        session::node::{shadow_contact_state, ContactId, StateChange},
        store::{
            engine::MemoryBackend,
            wrap::{Cost, SecureElement},
        },
        Error as CoreError,
    };
    use umbra_crypto::{
        hmac::{digest::KeyInit, Hmac, Mac},
        rand_core::{TryCryptoRng, TryRng},
        sha2::Sha256,
    };
    use umbra_wire::app::{
        edit::{DeleteBody, DeleteScope, EditBody},
        keys::{KeyChangeNotice, KeyRequest, KeyScope, KeySupply, SupplyStatus},
        rich::RichRecord,
        signal::{ReceiptBody, TypingState},
        AppKind, AppMessage, Channel,
    };
    use zeroize::Zeroizing;

    use super::{Client, Record, EDIT_WINDOW_MS, NOTE_LOST};
    use crate::{ConversationId, Delivery, Error, MsgRef, ReceiptSettings, Sink};

    struct Rng(u64);

    impl TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            Ok(self.0 >> 11 ^ self.0 << 7)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for Rng {}

    #[derive(Clone)]
    struct Element([u8; 32]);

    impl SecureElement for Element {
        fn keyed(&self, input: &[u8]) -> Result<[u8; 32], CoreError> {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| CoreError::Malformed)?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().into())
        }
    }

    #[derive(Default)]
    struct View(Vec<u16>);

    impl Sink for View {
        fn put(&mut self, code_units: &[u16]) {
            self.0 = code_units.to_vec();
        }
    }

    type TestClient = Client<MemoryBackend, Element>;

    const T0: u64 = 1_700_000_000_000;

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A stored contact with a salt and a key of the peer, as a node of an
    /// early build wrote it.
    fn contact_state(seed: u8) -> Zeroizing<Vec<u8>> {
        Zeroizing::new([&[0x01][..], &[seed; 16], &[seed; 32]].concat())
    }

    /// A client with one contact, and the conversation of that contact.
    fn client_with_contact(seed: u64) -> (TestClient, Rng, ContactId, ConversationId) {
        let mut rng = Rng(seed);
        let mut client = Client::create(
            MemoryBackend::default(),
            Element([1; 32]),
            &units("correct horse"),
            Cost { m_kib: 64, t: 1 },
            1_000,
            &mut rng,
        )
        .unwrap();
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: contact_state(5),
        };
        client
            .commit_network(&[change], &[], T0 - 1_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&contact.0).unwrap();
        (client, rng, contact, conversation)
    }

    fn record(kind: AppKind, msg_id: [u8; 16], body: &[u8]) -> Vec<u8> {
        let message = AppMessage {
            kind,
            msg_id,
            sent_at: 0,
            body,
        };
        let mut out = vec![0u8; message.len()];
        message.encode(&mut out).unwrap();
        out
    }

    fn edit_record(target: [u8; 16], text: &str, msg_id: u8) -> Vec<u8> {
        let body = EditBody {
            target,
            new_body: text,
        };
        let mut encoded = vec![0u8; body.len()];
        body.encode(&mut encoded).unwrap();
        record(AppKind::Edit, [msg_id; 16], &encoded)
    }

    fn text_of(client: &TestClient, message: &MsgRef) -> String {
        let mut view = View::default();
        client.render(message, &mut view).unwrap();
        String::from_utf16(&view.0).unwrap()
    }

    fn send(
        client: &mut TestClient,
        conversation: ConversationId,
        text: &str,
        now_ms: u64,
    ) -> MsgRef {
        let mut rng = Rng(now_ms);
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units(text)).unwrap();
        let message = client.send_draft(draft, now_ms, &mut rng).unwrap();
        while client.take_outgoing().is_some() {}
        message
    }

    /// Gives the client a device set with one other device, and the sync
    /// channel of that device.
    fn link_device(
        client: &mut TestClient,
        rng: &mut Rng,
    ) -> (umbra_core::devset::DeviceId, ConversationId) {
        use umbra_core::devset::link::{DeviceIdentity, LinkHello};
        client.ensure_device_set("Phone", rng).unwrap();
        let tablet = DeviceIdentity::generate("Tablet", rng);
        let hello = LinkHello {
            device_id: tablet.device_id,
            device_pk: tablet.device_key().public().clone(),
            roster_pk: tablet.roster_key().verifying_key().to_bytes().to_vec(),
            label: tablet.label,
            ct: umbra_crypto::kem::Ciphertext::from_bytes(&[0; umbra_crypto::kem::CIPHERTEXT_LEN])
                .unwrap(),
        };
        let epoch = client.sign_linked_device(&hello, rng).unwrap();
        client.commit_roster(&epoch, rng).unwrap();
        let channel = client.conversation_for(&[0x7C; 32]).unwrap();
        client
            .set_pending_peer(tablet.device_id, &tablet.label, rng)
            .unwrap();
        client.mark_device_peer(channel, rng).unwrap();
        while client.take_sync_send().is_some() {}
        (tablet.device_id, channel)
    }

    /// Whether a sync record carries `inner`.
    fn carries(app: &[u8], inner: &[u8]) -> bool {
        app.windows(inner.len()).any(|window| window == inner)
    }

    #[test]
    fn a_rich_record_around_no_text_is_no_message() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(301);
        let rich = |inner_kind, inner_body: &[u8]| {
            let rich = RichRecord {
                reply_target: [0; 16],
                thread_root: [0; 16],
                forward_depth: 0,
                mentions: Vec::new(),
                inner_kind,
                inner_body,
            };
            let mut body = vec![0u8; rich.len()];
            // The wire check of a rich record refuses some of these, and
            // the client then takes the bytes as a peer could send them.
            if rich.encode(Channel::Pairwise, &mut body).is_err() {
                body = vec![0x01];
                body.extend_from_slice(&[0; 33]);
                body.push(0);
                body.push(inner_kind as u8);
                body.extend_from_slice(inner_body);
            }
            body
        };
        let delete = DeleteBody {
            scope: DeleteScope::OtherParty,
            targets: vec![[4; 16]],
        };
        let mut encoded = vec![0u8; delete.len()];
        delete.encode(&mut encoded).unwrap();
        let received = [
            (
                contact,
                record(AppKind::Rich, [1; 16], &rich(AppKind::Delete, &encoded)),
            ),
            (
                contact,
                record(AppKind::Rich, [2; 16], &rich(AppKind::Text, &[0xFF, 0xFE])),
            ),
            (
                contact,
                record(AppKind::Rich, [3; 16], &rich(AppKind::Text, b"kept")),
            ),
        ];
        client.commit_network(&[], &received, T0, &mut rng).unwrap();
        let messages = client.messages(conversation).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(text_of(&client, &messages[0]), "kept");
        assert_eq!(client.summaries().unwrap().len(), 1);
    }

    #[test]
    fn a_blocked_contact_gets_a_delivery_receipt_for_a_message_and_for_no_other_record() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(302);
        client
            .set_receipt_settings(
                conversation,
                ReceiptSettings {
                    delivery: true,
                    read: true,
                },
                &mut rng,
            )
            .unwrap();
        // ABU-031: a read receipt that waits goes with the block.
        client
            .commit_network(
                &[],
                &[(contact, record(AppKind::Text, [1; 16], b"before"))],
                T0,
                &mut rng,
            )
            .unwrap();
        client.mark_read(conversation, T0 + 10, &mut rng).unwrap();
        while let Some(due) = client.due_receipt(T0 / 1_000 + 1, &mut rng).unwrap() {
            let parsed = AppMessage::parse(&due.app, Channel::Pairwise).unwrap();
            if parsed.kind == AppKind::ReadReceipt {
                break;
            }
            client.receipt_sent(&due).unwrap();
        }
        client.set_blocked(conversation, true, &mut rng).unwrap();
        while let Some(due) = client.due_receipt(T0 / 1_000 + 2, &mut rng).unwrap() {
            let parsed = AppMessage::parse(&due.app, Channel::Pairwise).unwrap();
            assert_eq!(parsed.kind, AppKind::DeliveryReceipt);
            client.receipt_sent(&due).unwrap();
        }

        // ABU-030: a typing record and an edit got no receipt before the
        // block, and they get none after it. A message gets one.
        let mut typing = [0u8; 2];
        TypingState::Started.encode(&mut typing).unwrap();
        let received = [
            (contact, record(AppKind::Typing, [2; 16], &typing)),
            (contact, edit_record([1; 16], "edited", 3)),
            (contact, record(AppKind::Text, [4; 16], b"after")),
        ];
        client
            .commit_network(&[], &received, T0 + 60_000, &mut rng)
            .unwrap();
        let mut named = Vec::new();
        while let Some(due) = client.due_receipt(T0 / 1_000 + 3_600, &mut rng).unwrap() {
            let parsed = AppMessage::parse(&due.app, Channel::Pairwise).unwrap();
            assert_eq!(parsed.kind, AppKind::DeliveryReceipt);
            named.extend(ReceiptBody::parse(parsed.body).unwrap().targets);
            client.receipt_sent(&due).unwrap();
        }
        assert_eq!(named, [[4; 16]]);
        // ABU-027, ABU-028: no record of the blocked contact is in a view.
        assert_eq!(client.messages(conversation).unwrap().len(), 1);
    }

    #[test]
    fn the_owner_forwards_no_edit_that_it_rejected_and_the_copies_keep_their_order() {
        let (mut client, mut rng, contact, _) = client_with_contact(303);
        link_device(&mut client, &mut rng);
        let first = record(AppKind::Text, [1; 16], b"one");
        let second = record(AppKind::Text, [2; 16], b"two");
        let edit = edit_record([1; 16], "one, edited", 3);
        let again = edit_record([1; 16], "one, edited twice", 4);
        let received = [
            (contact, first.clone()),
            (contact, second.clone()),
            (contact, edit.clone()),
            (contact, again.clone()),
        ];
        client.commit_network(&[], &received, T0, &mut rng).unwrap();
        // DEV-031 to DEV-035: one copy of each record, in the order of the
        // records.
        let sends: Vec<_> = core::iter::from_fn(|| client.take_sync_send()).collect();
        let place = |inner: &[u8]| sends.iter().position(|send| carries(&send.app, inner));
        let places = [place(&first), place(&second), place(&edit), place(&again)];
        assert!(places.iter().all(Option::is_some));
        assert!(places.windows(2).all(|pair| pair[0] < pair[1]));

        // DEV-247: an edit outside the window changes nothing here, and no
        // copy of it goes to the set.
        let late = edit_record([1; 16], "too late", 5);
        client
            .commit_network(
                &[],
                &[(contact, late.clone())],
                T0 + EDIT_WINDOW_MS,
                &mut rng,
            )
            .unwrap();
        let sends: Vec<_> = core::iter::from_fn(|| client.take_sync_send()).collect();
        assert!(!sends.iter().any(|send| carries(&send.app, &late)));
    }

    #[test]
    fn a_synced_revision_takes_the_verdict_of_its_source_and_an_older_one_never_wins() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(304);
        client
            .commit_network(
                &[],
                &[(contact, record(AppKind::Text, [1; 16], b"first text"))],
                T0,
                &mut rng,
            )
            .unwrap();
        let message = client.messages(conversation).unwrap()[0];
        let synced = |app: Vec<u8>| Record {
            conversation,
            app,
            from_user: false,
            synced: true,
            expires_in: 0,
        };
        let source = [7u8; 16];
        // DEV-246: the device that owns the ratchet measured the window,
        // and this device measures none for the copy.
        let late = T0 + 2 * EDIT_WINDOW_MS;
        client
            .commit_records_at(
                &[],
                &[synced(edit_record([1; 16], "second text", 2))],
                &[Some((source, 9))],
                late,
                &mut rng,
            )
            .unwrap();
        assert_eq!(text_of(&client, &message), "second text");
        // DEV-035: the copy of an earlier revision that comes after it.
        client
            .commit_records_at(
                &[],
                &[synced(edit_record([1; 16], "older text", 3))],
                &[Some((source, 8))],
                late,
                &mut rng,
            )
            .unwrap();
        assert_eq!(text_of(&client, &message), "second text");
        assert_eq!(client.info(&message).unwrap().revisions, 1);
        client
            .commit_records_at(
                &[],
                &[synced(edit_record([1; 16], "third text", 4))],
                &[Some((source, 10))],
                late,
                &mut rng,
            )
            .unwrap();
        assert_eq!(text_of(&client, &message), "third text");
        // A revision that the contact sends on its ratchet is still inside
        // the window of this device.
        client
            .commit_network(
                &[],
                &[(contact, edit_record([1; 16], "outside", 5))],
                late,
                &mut rng,
            )
            .unwrap();
        assert_eq!(text_of(&client, &message), "third text");
    }

    #[test]
    fn a_pending_reference_of_the_contact_takes_no_record_of_the_user() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(305);
        // DEV-093: the contact deletes a target that this device does not
        // hold, and the entry waits.
        let delete = DeleteBody {
            scope: DeleteScope::OtherParty,
            targets: vec![[1; 16]],
        };
        let mut encoded = vec![0u8; delete.len()];
        delete.encode(&mut encoded).unwrap();
        client
            .commit_network(
                &[],
                &[(contact, record(AppKind::Delete, [2; 16], &encoded))],
                T0,
                &mut rng,
            )
            .unwrap();
        // A record of the user under that `msg_id` comes from another
        // device of the set: the entry of the contact does not name it.
        let own = Record {
            conversation,
            app: record(AppKind::Text, [1; 16], b"mine"),
            from_user: true,
            synced: true,
            expires_in: 0,
        };
        client
            .commit_records(&[], &[own], T0 + 1, &mut rng)
            .unwrap();
        let messages = client.messages(conversation).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(text_of(&client, &messages[0]), "mine");

        // The entry still takes the record of the contact that it names.
        client
            .commit_network(
                &[],
                &[(contact, record(AppKind::Text, [1; 16], b"theirs"))],
                T0 + 2,
                &mut rng,
            )
            .unwrap();
        assert_eq!(client.messages(conversation).unwrap().len(), 1);

        // An edit and its target in one batch: the target takes the text.
        let received = [
            (contact, edit_record([8; 16], "edited", 9)),
            (contact, record(AppKind::Text, [8; 16], b"plain")),
        ];
        client
            .commit_network(&[], &received, T0 + 3, &mut rng)
            .unwrap();
        let messages = client.messages(conversation).unwrap();
        assert_eq!(text_of(&client, messages.last().unwrap()), "edited");
    }

    #[test]
    fn a_shadow_contact_fails_no_list_and_blocks_no_conversation() {
        let (mut client, mut rng, _, conversation) = client_with_contact(306);
        let shadow = ContactId([0x44; 32]);
        let change = StateChange::Contact {
            contact: shadow,
            state: Zeroizing::new(shadow_contact_state(&[3; 16])),
        };
        client.commit_network(&[change], &[], T0, &mut rng).unwrap();
        let held = client.conversation_for(&shadow.0).unwrap();
        // DEV-197: the verification state of the owner of the channel
        // arrives, and this device holds no key to compare.
        client.put_verified(held, &[6; 32], T0, &mut rng).unwrap();
        assert!(!client.is_verified(held).unwrap());
        let summaries = client.summaries().unwrap();
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|summary| !summary.verified));

        // IDN-061: a notice for a shadow contact waits at the owner of the
        // channel, and the conversation takes a draft here.
        let notice = KeyChangeNotice {
            new_x25519_pk: [8; 32],
            new_mlkem_pk: &[0; 1_184],
        };
        let mut body = vec![0u8; umbra_wire::app::keys::KEY_CHANGE_LEN];
        notice.encode(&mut body).unwrap();
        client.take_key_change(held, &body, T0, &mut rng).unwrap();
        assert!(client.key_change(held).unwrap().is_none());
        // A contact with a key of its own takes the notice as before.
        client
            .take_key_change(conversation, &body, T0, &mut rng)
            .unwrap();
        assert!(client.key_change(conversation).unwrap().is_some());
    }

    #[test]
    fn a_send_that_the_client_refuses_keeps_the_stored_draft() {
        let (mut client, mut rng, _, conversation) = client_with_contact(307);
        client
            .set_draft(conversation, &units("not yet"), &mut rng)
            .unwrap();
        let notice = KeyChangeNotice {
            new_x25519_pk: [8; 32],
            new_mlkem_pk: &[0; 1_184],
        };
        let mut body = vec![0u8; umbra_wire::app::keys::KEY_CHANGE_LEN];
        notice.encode(&mut body).unwrap();
        client
            .take_key_change(conversation, &body, T0, &mut rng)
            .unwrap();
        // IDN-025: the conversation takes no message, and DEV-201 erases
        // the draft of a send alone.
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("not yet")).unwrap();
        assert_eq!(client.send_draft(draft, T0, &mut rng), Err(Error::Busy));
        assert_eq!(*client.draft(conversation).unwrap(), units("not yet"));
        client.accept_key_change(conversation, &mut rng).unwrap();
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("not yet")).unwrap();
        client.send_draft(draft, T0, &mut rng).unwrap();
        assert!(client.draft(conversation).unwrap().is_empty());
    }

    #[test]
    fn a_state_goes_up_only_and_a_resend_stays_inside_its_bounds() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(308);
        let day = 86_400_000;
        let old = send(&mut client, conversation, "old", T0);
        let before = send(
            &mut client,
            conversation,
            "before the receipt",
            T0 + 49 * day,
        );
        let receipted = send(&mut client, conversation, "receipted", T0 + 50 * day);
        let after = send(
            &mut client,
            conversation,
            "after the receipt",
            T0 + 51 * day,
        );
        for message in [old, receipted, before, after] {
            client
                .set_delivery(&message, Delivery::Accepted, &mut rng)
                .unwrap();
        }
        // The receipt names the raw `msg_id` of the message.
        let sent = {
            let open = client.open_ref().unwrap();
            let plain = open
                .store
                .get(super::TableId::MESSAGE, &receipted.0)
                .unwrap()
                .unwrap();
            AppMessage::parse(&plain[super::MESSAGE_PREFIX..], Channel::Pairwise)
                .unwrap()
                .msg_id
        };
        let body = ReceiptBody {
            targets: vec![sent],
        };
        let mut encoded = vec![0u8; 2 + 16];
        body.encode(&mut encoded).unwrap();
        client
            .commit_network(
                &[],
                &[(
                    contact,
                    record(AppKind::DeliveryReceipt, [0x77; 16], &encoded),
                )],
                T0 + 52 * day,
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            client.info(&receipted).unwrap().delivery,
            Delivery::Delivered
        );
        // DEV-304: the report of a second copy does not take the receipt.
        client
            .set_delivery(&receipted, Delivery::Accepted, &mut rng)
            .unwrap();
        assert_eq!(
            client.info(&receipted).unwrap().delivery,
            Delivery::Delivered
        );

        // NET-193: the record after the newest receipted one goes again.
        // The one that this device stored before it arrived too, and the
        // one above `MSG_TTL` left each queue.
        client.resend_unreceipted(conversation).unwrap();
        let again: Vec<MsgRef> = core::iter::from_fn(|| client.take_outgoing())
            .map(|outgoing| outgoing.message)
            .collect();
        assert_eq!(again, [after]);
    }

    #[test]
    fn a_reply_that_goes_again_carries_the_raw_target() {
        let (mut client, mut rng, _, conversation) = client_with_contact(309);
        let target = send(&mut client, conversation, "question", T0);
        client
            .set_delivery(&target, Delivery::Accepted, &mut rng)
            .unwrap();
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("answer")).unwrap();
        draft.set_reply_to(Some(target));
        let reply = client.send_draft(draft, T0 + 1, &mut rng).unwrap();
        let first = core::iter::from_fn(|| client.take_outgoing())
            .find(|outgoing| outgoing.message == reply)
            .unwrap();
        client
            .set_delivery(&reply, Delivery::Accepted, &mut rng)
            .unwrap();
        client.resend_unreceipted(conversation).unwrap();
        let again = core::iter::from_fn(|| client.take_outgoing())
            .find(|outgoing| outgoing.message == reply)
            .unwrap();
        // WIR-071: the same bytes as the first send, and no reference.
        assert_eq!(again.app, first.app);
    }

    #[test]
    fn a_receiver_answers_key_requests_up_to_the_rate_and_one_supply_is_one_note() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(310);
        let rate = umbra_core::group::KEY_REQUEST_RATE as usize;
        let request = |index: u32| KeyRequest {
            scope: KeyScope::Session,
            id: [0; 32],
            epoch: 0,
            index,
        };
        let received: Vec<_> = (0..rate as u32 + 5)
            .map(|index| {
                let mut body = vec![0u8; umbra_wire::app::keys::REQUEST_LEN];
                request(index).encode(&mut body).unwrap();
                (
                    contact,
                    record(AppKind::KeyRequest, [index as u8 + 1; 16], &body),
                )
            })
            .collect();
        client.commit_network(&[], &received, T0, &mut rng).unwrap();
        // WIR-338: one supply for each request inside the rate.
        let supplies = core::iter::from_fn(|| client.take_outgoing())
            .filter(|outgoing| {
                AppMessage::parse(&outgoing.app, Channel::Pairwise)
                    .is_ok_and(|parsed| parsed.kind == AppKind::KeySupply)
            })
            .count();
        assert_eq!(supplies, rate);

        // WIR-347: a second copy of one supply changes nothing.
        assert!(client.lost_record(conversation, 40, T0, &mut rng).unwrap());
        let supply = KeySupply {
            request: request(40),
            status: SupplyStatus::NotHeld,
            body: &[],
        };
        let mut body = vec![0u8; umbra_wire::app::keys::SUPPLY_LEN];
        let used = supply.encode(&mut body).unwrap();
        body.truncate(used);
        for copy in 0..3u8 {
            client
                .commit_network(
                    &[],
                    &[(
                        contact,
                        record(AppKind::KeySupply, [0x90 + copy; 16], &body),
                    )],
                    T0 + 1_000,
                    &mut rng,
                )
                .unwrap();
        }
        let lost = client
            .roster_notes(conversation)
            .unwrap()
            .iter()
            .filter(|note| note.kind == NOTE_LOST)
            .count();
        assert_eq!(lost, 1);
        // A hole at that index a day later is another record.
        assert!(!client
            .lost_record(conversation, 40, T0 + 2_000, &mut rng)
            .unwrap());
        assert!(client
            .lost_record(conversation, 40, T0 + 86_400_000, &mut rng)
            .unwrap());
    }

    #[test]
    fn a_key_change_notice_that_reached_no_relay_goes_again() {
        let (mut client, mut rng, _, conversation) = client_with_contact(311);
        let notice = KeyChangeNotice {
            new_x25519_pk: [8; 32],
            new_mlkem_pk: &[0; 1_184],
        };
        let mut body = vec![0u8; umbra_wire::app::keys::KEY_CHANGE_LEN];
        notice.encode(&mut body).unwrap();
        let app = record(AppKind::KeyChange, [0x21; 16], &body);
        {
            let value = [conversation.0.as_slice(), &10u64.to_be_bytes(), &app].concat();
            let open = client.open_mut().unwrap();
            let mut batch = open.store.begin();
            batch
                .put(
                    super::reset::RESET_NOTICES,
                    conversation.0,
                    Some(conversation.0),
                    &value,
                    &mut rng,
                )
                .unwrap();
            batch.commit().unwrap();
        }
        assert_eq!(client.send_due_notices(11, &mut rng).unwrap(), 1);
        let sent = client.take_outgoing().unwrap();
        // The notice is on the send path, and it goes no second time.
        assert_eq!(client.send_due_notices(12, &mut rng).unwrap(), 0);
        assert_eq!(client.notices_waiting().unwrap(), 1);

        // IDN-063: no relay took it, thus it waits again for a delay.
        client
            .fail(&sent.message, crate::FailureCause::NoPath, &mut rng)
            .unwrap();
        assert_eq!(client.notices_waiting().unwrap(), 1);
        assert_eq!(client.send_due_notices(u64::MAX - 1, &mut rng).unwrap(), 1);
        let again = client.take_outgoing().unwrap();
        assert_eq!(again.app, sent.app);
        // A relay took it, and the row goes.
        client
            .set_delivery(&again.message, Delivery::Accepted, &mut rng)
            .unwrap();
        assert_eq!(client.notices_waiting().unwrap(), 0);
        assert_eq!(client.send_due_notices(u64::MAX - 1, &mut rng).unwrap(), 0);
    }

    #[test]
    fn a_removal_of_a_device_owes_each_rotation_and_its_notice_until_they_are_done() {
        let (mut client, mut rng, contact, conversation) = client_with_contact(312);
        let (tablet, channel) = link_device(&mut client, &mut rng);
        // The channel of the tablet as the node stored it.
        let change = StateChange::Contact {
            contact: ContactId([0x7C; 32]),
            state: contact_state(6),
        };
        client.commit_network(&[change], &[], T0, &mut rng).unwrap();

        // No run is up: the removal succeeds, and the store holds what it
        // owes (Part 7 §7.7 step 2c, DEV-313).
        client.revoke_device(tablet, &mut rng).unwrap();
        assert!(client.owes_rotation(conversation).unwrap());
        assert!(!client.owes_rotation(channel).unwrap());
        assert!(client.is_leaving_channel(channel).unwrap());
        assert!(!client.is_ended_channel(channel).unwrap());
        // A lock, or the end of the process, takes the queue in RAM.
        while client.take_sync_send().is_some() {}

        // The next run: the channel is still a channel of the node, and the
        // notice goes again. The run asks for the rotation once in its
        // pace.
        client.end_revoked_channels(&mut rng).unwrap();
        assert!(client
            .stored_network()
            .unwrap()
            .contacts
            .iter()
            .any(|(held, _)| *held == channel));
        // DEV-313: the kept epochs that lead to the notice go before it
        // again, since the queue of the first send is gone.
        let mut sends: Vec<_> = core::iter::from_fn(|| client.take_sync_send()).collect();
        assert!(sends.len() > 1);
        assert!(sends.iter().all(|send| send.peer == channel));
        let notice = sends.pop().unwrap();
        assert!(sends.iter().all(|send| send.message.is_none()));
        assert_eq!(client.rotation_owed(5_000).unwrap(), [contact.0]);
        assert!(client.rotation_owed(5_001).unwrap().is_empty());
        assert_eq!(client.rotation_owed(5_100).unwrap(), [contact.0]);
        // DEV-257: the channel takes no record while it waits.
        let from_tablet = record(AppKind::Text, [0x31; 16], b"still here");
        client
            .commit_network(&[], &[(ContactId([0x7C; 32]), from_tablet)], T0, &mut rng)
            .unwrap();
        // A later epoch goes to no revoked device.
        client.publish_roster(&mut rng).unwrap();
        assert!(client.take_sync_send().is_none());

        // A relay took the notice: the channel ends (step 2a).
        client
            .set_delivery(&notice.message.unwrap(), Delivery::Accepted, &mut rng)
            .unwrap();
        assert!(client.is_ended_channel(channel).unwrap());
        assert!(!client.is_leaving_channel(channel).unwrap());
        assert!(client.device_peers().unwrap().is_empty());
        client.end_revoked_channels(&mut rng).unwrap();
        assert!(client.take_sync_send().is_none());

        // The queue of the contact rotated: the revocation owes nothing.
        client
            .dead_queue_rotated(conversation, &[0; 4], &mut rng)
            .unwrap();
        assert!(!client.owes_rotation(conversation).unwrap());
        assert!(client.rotation_owed(9_000).unwrap().is_empty());
        client.audit().unwrap();
    }

    /// A handle at rotation 2 and version 1, as a claim and one rotation
    /// left it.
    fn held_handle() -> super::Published {
        super::Published {
            id: [3; 16],
            kind: super::EntryKind::Handle,
            index: 0,
            rotation: 2,
            label: vec![1],
            name: b"name".to_vec(),
            queue: [4; 32],
            rendezvous: vec![5; 8],
            version: 1,
            created_at: 100,
            expires_at: 0,
            renewed_at: 100,
            queue_since: 100,
            previous: None,
            foreign: false,
        }
    }

    fn entry_public(
        client: &TestClient,
        kind: super::EntryKind,
        index: u32,
        rotation: u32,
    ) -> Vec<u8> {
        client
            .entry_key(kind, index, rotation)
            .unwrap()
            .public()
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn a_reset_keeps_the_key_of_each_published_entry_until_the_log_shows_its_next_key() {
        use super::{EntryKind, Published};
        let (mut client, mut rng, _, _) = client_with_contact(313);
        let entry = held_handle();
        client.put_published(&entry, &mut rng).unwrap();
        let before = entry_public(&client, EntryKind::Handle, 0, 2);
        let unused = entry_public(&client, EntryKind::Address, 7, 0);
        client.reset_identity(T0, &mut rng).unwrap();
        // DEV-306, DIS-093: the directory holds the key of the entry, and
        // this device still answers under it.
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        // The rotation of the key, and each new entry, take the new root.
        assert_ne!(entry_public(&client, EntryKind::Address, 7, 0), unused);
        // The log shows the entry as this device holds it: the root stays.
        client.confirm_published(&entry.id, &mut rng).unwrap();
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        // The store takes the rotation first. The key before it signs the
        // write, thus it stays while the directory did not take the write.
        let rotated = Published {
            rotation: 3,
            version: 2,
            ..entry.clone()
        };
        client.put_published(&rotated, &mut rng).unwrap();
        client.put_published(&rotated, &mut rng).unwrap();
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        // The log shows the rotation under its key: the earlier root has no
        // more use, and it leaves the store.
        client.confirm_published(&entry.id, &mut rng).unwrap();
        assert!(client.earlier_roots_row().unwrap().is_none());
        assert_ne!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        client.drop_published(&entry.id, &mut rng).unwrap();
        client.audit().unwrap();
    }

    #[test]
    fn a_refused_rotation_after_a_reset_leaves_the_key_that_renews_the_handle() {
        use super::{EntryKind, Published};
        let (mut client, mut rng, _, _) = client_with_contact(315);
        let entry = held_handle();
        let link = Published {
            id: [6; 16],
            kind: EntryKind::Address,
            index: 1,
            rotation: 0,
            ..entry.clone()
        };
        client.put_published(&entry, &mut rng).unwrap();
        client.put_published(&link, &mut rng).unwrap();
        let before = entry_public(&client, EntryKind::Handle, 0, 2);
        client.reset_identity(T0, &mut rng).unwrap();
        let roots = client.earlier_roots_row().unwrap().unwrap();
        // The steps of a rotation that the directory refuses: the store
        // takes the next version, and then the version before it again.
        let rotated = Published {
            rotation: 3,
            version: 2,
            queue: [9; 32],
            ..entry.clone()
        };
        client.put_published(&rotated, &mut rng).unwrap();
        // The upkeep of another entry runs between the two writes.
        client.confirm_published(&link.id, &mut rng).unwrap();
        client.put_published(&entry, &mut rng).unwrap();
        // DEV-306: the state is the one before the call, with its roots.
        assert_eq!(client.earlier_roots_row().unwrap().unwrap(), roots);
        assert_eq!(client.published().unwrap().len(), 2);
        // The directory holds the key of the earlier root, and the renewal
        // and the next rotation answer under it.
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        client.confirm_published(&entry.id, &mut rng).unwrap();
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        client.audit().unwrap();
    }

    #[test]
    fn a_rotation_with_no_answer_after_a_reset_keeps_its_signer_until_the_log_shows_it() {
        use super::{EntryKind, Published};
        let (mut client, mut rng, _, _) = client_with_contact(316);
        let entry = held_handle();
        let link = Published {
            id: [6; 16],
            kind: EntryKind::Address,
            index: 1,
            rotation: 0,
            ..entry.clone()
        };
        client.put_published(&entry, &mut rng).unwrap();
        client.put_published(&link, &mut rng).unwrap();
        let before = entry_public(&client, EntryKind::Handle, 0, 2);
        client.reset_identity(T0, &mut rng).unwrap();
        // The write left, and no answer came: the store keeps the rotation.
        let rotated = Published {
            rotation: 3,
            version: 2,
            ..entry.clone()
        };
        client.put_published(&rotated, &mut rng).unwrap();
        // The upkeep writes each other entry and reads the log for it.
        client.put_published(&link, &mut rng).unwrap();
        client.confirm_published(&link.id, &mut rng).unwrap();
        // The log still shows the version before under the key of the
        // earlier root, which signs the write again (DIS-093).
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        let next = entry_public(&client, EntryKind::Handle, 0, 3);
        assert_ne!(next, before);
        // The write goes again, and the store marks its time.
        let again = Published {
            queue_since: 900,
            ..rotated.clone()
        };
        client.put_published(&again, &mut rng).unwrap();
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        // The log shows the rotation: the earlier root of the handle goes,
        // and the one of the link stays.
        client.confirm_published(&entry.id, &mut rng).unwrap();
        assert_ne!(entry_public(&client, EntryKind::Handle, 0, 2), before);
        assert_eq!(entry_public(&client, EntryKind::Handle, 0, 3), next);
        assert!(client.earlier_roots_row().unwrap().is_some());
        // The link goes: no entry holds a name of an earlier root.
        client.drop_published(&link.id, &mut rng).unwrap();
        assert!(client.earlier_roots_row().unwrap().is_none());
        client.audit().unwrap();
    }

    #[test]
    fn a_linked_device_takes_the_lamport_counter_of_the_device_that_owns_the_channels() {
        use umbra_core::devset::engine::SyncEngine;
        let (mut client, mut rng, _, _) = client_with_contact(319);
        let (peer, _) = link_device(&mut client, &mut rng);
        let own = client.device_identity().unwrap().unwrap().device_id;
        // The sync channel as the node stored it.
        let channel = ContactId([0x7C; 32]);
        let change = StateChange::Contact {
            contact: channel,
            state: contact_state(6),
        };
        client.commit_network(&[change], &[], T0, &mut rng).unwrap();
        // A record of the peer whose Lamport counter is far above the bound
        // of DEV-275. The peer took values of other devices that this
        // device did not see.
        let mut engine = SyncEngine::new(peer, &[own]).unwrap();
        let mut far = |msg_id: u8| {
            let item = engine
                .relay_mutable(0x7F, b"key", b"value", 1 << 40, peer, [msg_id; 16], 10)
                .unwrap();
            record(AppKind::DeviceSet, [msg_id; 16], &item.body)
        };
        let took = |client: &TestClient| {
            let mut engine = client.sync_engine().unwrap().unwrap();
            !engine.acknowledgments(u64::MAX).unwrap().is_empty()
        };
        // This device owns the channels: the bound holds, and it takes
        // neither the counter nor the value.
        client
            .commit_network(&[], &[(channel, far(0x41))], T0, &mut rng)
            .unwrap();
        assert!(!took(&client));

        // The same store as the one of a linked device. Its one peer owns
        // the channels, and the device takes a record of that peer at any
        // value.
        let open = client.open_mut().unwrap();
        let row = open.store.row_id(super::devices::DEVICE_SELF, b"self");
        let mut identity = open
            .store
            .get(super::devices::DEVICE_SELF, &row)
            .unwrap()
            .unwrap();
        identity[0] = 0;
        let mut batch = open.store.begin();
        batch
            .put(super::devices::DEVICE_SELF, row, None, &identity, &mut rng)
            .unwrap();
        batch.commit().unwrap();
        assert!(!client.owns_channels().unwrap());
        client
            .commit_network(&[], &[(channel, far(0x42))], T0, &mut rng)
            .unwrap();
        assert!(took(&client));
    }

    #[test]
    fn a_row_that_names_another_owner_ends_no_batch_and_the_user_learns_of_it_once() {
        use super::{Event, TableId};
        let (mut client, mut rng, contact, conversation) = client_with_contact(318);
        // A message of this device that a relay took, and a message of the
        // contact.
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("to the contact")).unwrap();
        let sent = client.send_draft(draft, T0, &mut rng).unwrap();
        while client.take_outgoing().is_some() {}
        client
            .set_delivery(&sent, Delivery::Accepted, &mut rng)
            .unwrap();
        let from_contact = record(AppKind::Text, [0x21; 16], b"from the contact");
        client
            .commit_network(&[], &[(contact, from_contact)], T0 + 1, &mut rng)
            .unwrap();
        // IMP-121: a row in the owner column of this conversation whose
        // plaintext names another one. A store of record version 0x01 that
        // a party changed leaves such a row after the move.
        let other = ConversationId([0x44; 16]);
        let foreign = super::stored_message(
            super::OUTGOING,
            Delivery::Accepted,
            other,
            T0 + 2,
            &record(AppKind::Text, [0x22; 16], b"of another conversation"),
        );
        let open = client.open_mut().unwrap();
        let row = open
            .store
            .row_id(TableId::MESSAGE, b"a row of another owner");
        let mut batch = open.store.begin();
        batch
            .put(
                TableId::MESSAGE,
                row,
                Some(conversation.0),
                &foreign,
                &mut rng,
            )
            .unwrap();
        batch.commit().unwrap();
        while client.next_event().is_some() {}
        let faults = |client: &mut TestClient| {
            let mut faults = 0;
            while let Some(event) = client.next_event() {
                faults += usize::from(event == Event::IntegrityFault);
            }
            faults
        };

        // The list of the conversations still shows the conversation with
        // each row that reads, and one fault for the call (IDN-039).
        let summaries = client.summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].unread, 1);
        assert_eq!(faults(&mut client), 1);

        // A read receipt of the contact: the batch commits, the message of
        // this device moves, the foreign row stays, and the fault shows one
        // time. A batch that failed would acknowledge no record, and the
        // receipt would come again at each run.
        let sent_id = {
            let open = client.open_ref().unwrap();
            let plain = open.store.get(TableId::MESSAGE, &sent.0).unwrap().unwrap();
            AppMessage::parse(&plain[super::MESSAGE_PREFIX..], Channel::Pairwise)
                .unwrap()
                .msg_id
        };
        let body = ReceiptBody {
            targets: vec![sent_id],
        };
        let mut encoded = vec![0u8; 2 + 16];
        body.encode(&mut encoded).unwrap();
        let receipt = record(AppKind::ReadReceipt, [0x23; 16], &encoded);
        client
            .commit_network(&[], &[(contact, receipt)], T0 + 3, &mut rng)
            .unwrap();
        assert_eq!(client.info(&sent).unwrap().delivery, Delivery::Read);
        assert_eq!(faults(&mut client), 1);
        let held = client.open_ref().unwrap().store.get(TableId::MESSAGE, &row);
        assert_eq!(held.unwrap().unwrap(), foreign.to_vec());

        // The read receipt of this device to the contact still waits for
        // its send after the user opened the conversation.
        let settings = super::ReceiptSettings {
            delivery: true,
            read: true,
        };
        client
            .set_receipt_settings(conversation, settings, &mut rng)
            .unwrap();
        client.mark_read(conversation, T0 + 4, &mut rng).unwrap();
        assert_eq!(faults(&mut client), 1);
        let open = client.open_ref().unwrap();
        let waiting = open
            .store
            .list(super::RECEIPT, Some(&conversation.0))
            .unwrap();
        assert!(waiting
            .iter()
            .any(|(_, held)| held.get(16) == Some(&(AppKind::ReadReceipt as u8))));
    }

    #[test]
    fn a_download_that_fails_after_the_life_of_its_chunks_is_gone() {
        use super::{Event, FileState};
        use umbra_core::attach::CHUNK_LIFE_MAX;
        let (mut client, mut rng, contact, _) = client_with_contact(317);
        let file = record(AppKind::Attachment, [0x71; 16], &[1, 2, 3]);
        client
            .commit_network(&[], &[(contact, file)], T0, &mut rng)
            .unwrap();
        let message = loop {
            match client.next_event() {
                Some(Event::Message { message, .. }) => break message,
                Some(_) => {}
                None => panic!("no message"),
            }
        };
        let state = |client: &TestClient| client.file_info(&message).unwrap().unwrap().state;
        // ATT-010: a replica that no consensus names answers nothing, and
        // the fetch fails. Inside the life of the chunks a tap tries again.
        client.clock = T0 / 1_000 + CHUNK_LIFE_MAX - 1;
        client.download_failed(&message, &mut rng).unwrap();
        assert_eq!(state(&client), FileState::Failed);
        // ATT-160: no relay holds a chunk after `CHUNK_LIFE_MAX`, thus the
        // file is gone, and no tap fetches it again (ATT-052).
        client.clock = T0 / 1_000 + CHUNK_LIFE_MAX;
        client.download_failed(&message, &mut rng).unwrap();
        assert_eq!(state(&client), FileState::Gone);
        assert!(matches!(
            client.fetch_file(&message, &mut rng),
            Err(Error::Malformed)
        ));
        client.audit().unwrap();
    }

    #[test]
    fn the_end_of_the_history_period_erases_no_chunk_and_a_deletion_erases_each_one() {
        use umbra_core::attach::transfer::{ChunkCredential, Shape, Uploaded};
        use umbra_crypto::secret::Secret;
        use umbra_wire::descriptor::{ChunkRef, FileDescriptor, Level};
        let uploaded = |seed: u8| {
            let file_key = Secret::new([seed; 32]);
            let file_nonce = [seed; 24];
            Uploaded {
                descriptor: FileDescriptor {
                    level: Level::Data,
                    commit: umbra_core::attach::seal::commit(&file_key, &file_nonce),
                    file_key,
                    file_nonce,
                    digest: [seed; 32],
                    media_seconds: 0,
                    padded_size: 32_650,
                    mime_class: 1,
                    pixel_w: 640,
                    pixel_h: 480,
                    refs: vec![ChunkRef {
                        relay_id: [0x31; 32],
                        chunk_id: [seed; 32],
                        cred_pk: [0x33; 32],
                        replicas: [[0x34; 12], [0x35; 12]],
                    }],
                },
                credentials: vec![ChunkCredential {
                    chunk_id: [seed; 32],
                    cred: Secret::new([0x36; 32]),
                    relays: vec![[0x31; 32], [0x37; 32], [0x38; 32]],
                }],
            }
        };
        let (mut client, mut rng, _, conversation) = client_with_contact(314);
        let file = |client: &mut TestClient, seed: u8, now_ms: u64| {
            let mut rng = Rng(u64::from(seed));
            let mut draft = client.new_draft(conversation);
            draft
                .attach(Zeroizing::new(vec![seed; 64]), Shape::default())
                .unwrap();
            let message = client.send_draft(draft, now_ms, &mut rng).unwrap();
            client.take_upload().unwrap();
            client
                .upload_done(&message, &uploaded(seed), &mut rng)
                .unwrap();
            while client.take_outgoing().is_some() {}
            client
                .set_delivery(&message, Delivery::Accepted, &mut rng)
                .unwrap();
            message
        };
        let aged = file(&mut client, 1, T0);
        let deleted = file(&mut client, 2, T0 + 1);
        client
            .set_history_age(super::HISTORY_AGE_MIN, &mut rng)
            .unwrap();
        // ATT-161: the end of the period is no deletion.
        let now = T0 / 1_000 + 2 * super::HISTORY_AGE_MIN;
        assert_eq!(client.sweep_history(now, &mut rng).unwrap(), 2);
        assert!(client.take_erasure().is_none());
        assert!(client.info(&aged).is_err());
        assert!(client.info(&deleted).is_err());
        // No copy of a credential outlives its message there.
        let erase_rows = |client: &TestClient| {
            let store = &client.open_ref().unwrap().store;
            store.list(super::ERASE_DUE, None).unwrap().len()
        };
        assert_eq!(erase_rows(&client), 0);

        let kept = file(&mut client, 3, now * 1_000);
        client.delete_for_me(&kept).unwrap();
        assert_eq!(client.take_erasure().unwrap().chunk_id, [3; 32]);
        assert_eq!(erase_rows(&client), 1);

        // A deletion for everyone inside `DELETE_RATE_LIMIT` changes
        // nothing: the hold of its file stays, and no chunk of it is due
        // at a new start.
        let first = file(&mut client, 4, now * 1_000 + 1);
        let second = file(&mut client, 5, now * 1_000 + 2);
        client
            .delete_for_everyone(&first, now * 1_000 + 3, &mut rng)
            .unwrap();
        assert_eq!(client.take_erasure().unwrap().chunk_id, [4; 32]);
        assert!(matches!(
            client.delete_for_everyone(&second, now * 1_000 + 4, &mut rng),
            Err(Error::Busy)
        ));
        assert!(client.take_erasure().is_none());
        assert_eq!(erase_rows(&client), 4);
        let due = |client: &mut TestClient| {
            client.requeue_transfers().unwrap();
            let mut due = Vec::new();
            while let Some(job) = client.take_erasure() {
                due.push(job.chunk_id[0]);
            }
            due.sort_unstable();
            due
        };
        assert_eq!(due(&mut client), [3, 4]);
        let later = (now + super::DELETE_RATE_LIMIT) * 1_000 + 5;
        client
            .delete_for_everyone(&second, later, &mut rng)
            .unwrap();
        assert_eq!(client.take_erasure().unwrap().chunk_id, [5; 32]);

        // A message that left with its row of `CHUNK_CRED` and no erase, as
        // a removal by a moderator leaves it. The copy and its hold go at
        // the next start, and no `CDEL` leaves for them.
        let removed = file(&mut client, 6, later + 1);
        assert_eq!(erase_rows(&client), 5);
        let open = client.open_mut().unwrap();
        let mut batch = open.store.begin();
        batch.delete(super::CHUNK_CRED, removed.0);
        batch.commit().unwrap();
        assert_eq!(due(&mut client), [3, 4, 5]);
        assert_eq!(erase_rows(&client), 3);
        client.audit().unwrap();
    }
}
