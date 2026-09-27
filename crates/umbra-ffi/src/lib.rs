//! The client surface of the UMBRA protocol for Android (Part 14 §14.6.1).
//!
//! The surface is narrow by design. The platform holds opaque handles: a
//! [`draft::Draft`] that it writes text into, and a [`MsgRef`] that it
//! renders into a [`Sink`]. No message plaintext, no key, and no passphrase
//! crosses as a `ByteArray` or a `String` (`IMP-037`). One event stream
//! runs from Rust to the platform, and nothing crosses for each packet.
//!
//! [`client`] holds the client itself, which builds and tests with no
//! binding generator. The `sqlite` feature adds the SQLite backend of
//! §14.6.4, and the `bindings` feature adds the UniFFI scaffolding over
//! both.
#![forbid(unsafe_code)]

#[cfg(feature = "runtime")]
pub mod bridge;
pub mod client;
pub mod draft;
#[cfg(feature = "runtime")]
pub mod groups;
#[cfg(feature = "runtime")]
pub mod runtime;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(feature = "runtime")]
pub mod transfers;

#[cfg(feature = "bindings")]
pub mod bindings;

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();

/// A conversation, as the surrogate identifier of its row. It shows no
/// contact to a party without `K_store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConversationId(pub [u8; 16]);

/// A message, as the surrogate identifier of its row. The platform holds
/// it as an opaque handle (`IMP-038`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MsgRef(pub(crate) [u8; 16]);

impl MsgRef {
    /// The bytes of the handle, for a binding layer that maps it.
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// A handle from the bytes that [`MsgRef::to_bytes`] gave.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        MsgRef(bytes)
    }
}

/// The delivery state of Part 14 §14.9.1. The list is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Delivery {
    /// No relay acknowledged the send.
    Queued = 0,
    /// A relay acknowledged it.
    Accepted = 1,
    /// A delivery receipt arrived, or the record is an inbound one.
    Delivered = 2,
    /// A read receipt arrived.
    Read = 3,
    /// The ARQ stopped.
    Failed = 4,
}

impl Delivery {
    /// The state that a receipt of `kind` reports, or `None` for a record
    /// of another kind.
    pub fn of_receipt(kind: umbra_wire::app::AppKind) -> Option<Self> {
        match kind {
            umbra_wire::app::AppKind::DeliveryReceipt => Some(Delivery::Delivered),
            umbra_wire::app::AppKind::ReadReceipt => Some(Delivery::Read),
            _ => None,
        }
    }

    /// Whether a receipt that reports `reported` moves this state up. A
    /// state goes up only: a delivery receipt after a read receipt changes
    /// nothing.
    pub fn is_below(self, reported: Delivery) -> bool {
        let rank = |state| match state {
            Delivery::Queued | Delivery::Failed => 0,
            Delivery::Accepted => 1,
            Delivery::Delivered => 2,
            Delivery::Read => 3,
        };
        rank(self) < rank(reported)
    }

    /// The state of a stored byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        [
            Delivery::Queued,
            Delivery::Accepted,
            Delivery::Delivered,
            Delivery::Read,
            Delivery::Failed,
        ]
        .into_iter()
        .find(|state| *state as u8 == byte)
    }
}

/// One reaction to a message (Part 6 §6.6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    /// The emoji. It holds emoji code points and no other text, thus it is
    /// no message text under `IMP-037`.
    pub emoji: String,
    /// Whether this device sent it.
    pub mine: bool,
}

/// The message that a message answers (Part 6 §6.6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyTarget {
    /// The message answers no message.
    None,
    /// The message answers this message of its conversation.
    Message(MsgRef),
    /// The message answers a message that this device does not hold. The
    /// view shows it as an answer all the same (`WIR-173`).
    Absent,
}

/// What a conversation view shows beside the text of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// Whether this device sent the message.
    pub outgoing: bool,
    /// The delivery state.
    pub delivery: Delivery,
    /// The send time that the sender wrote, in milliseconds.
    pub sent_at_ms: u64,
    /// The time of this device at the store of the message, in
    /// milliseconds. A conversation view orders by it.
    pub stored_at_ms: u64,
    /// The message that this message answers.
    pub reply: ReplyTarget,
    /// Whether a deletion took the content, and the row is its placeholder
    /// (Part 7 §7.5.6).
    pub deleted: bool,
    /// Whether the record holds a text: a text, or a rich record around one.
    pub has_text: bool,
    /// How many times its sender changed the text. A value above zero is
    /// the edited mark of `DEV-090`.
    pub revisions: u8,
    /// The file of the message, or none for a message with no file.
    pub file: Option<client::FileInfo>,
}

/// The longest local name of a contact, in bytes of UTF-8.
pub const CONTACT_NAME_MAX: usize = 120;

/// Which receipts this device sends to one contact. The two are off for a
/// new contact (`NET-059`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiptSettings {
    /// A delivery receipt follows each message that this device holds.
    pub delivery: bool,
    /// A read receipt follows each message that the user saw in its
    /// conversation.
    pub read: bool,
}

/// A batch of receipts that may leave in a slot of the cover clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueReceipt {
    /// The conversation of the peer.
    pub conversation: ConversationId,
    /// The application record, a `ReceiptBody` of one kind.
    pub app: Vec<u8>,
    /// The rows of the store that the batch came from.
    pub(crate) rows: Vec<[u8; 16]>,
}

/// What a conversation list shows for one conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    /// The conversation.
    pub conversation: ConversationId,
    /// The name that the user of this device gave the contact, or an empty
    /// string. No peer and no relay learns it.
    pub name: String,
    /// The newest message, or none.
    pub last: Option<MsgRef>,
    /// The store time of the newest message, in milliseconds, or zero.
    pub last_at_ms: u64,
    /// The received messages that the user did not see yet.
    pub unread: u32,
    /// Whether the user verified the pairwise identity key that the
    /// contact holds now (Part 4 §4.5).
    pub verified: bool,
}

/// One event of the stream from Rust to the platform. An event carries a
/// handle and no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A message arrived.
    Message {
        /// The conversation.
        conversation: ConversationId,
        /// The message.
        message: MsgRef,
    },
    /// The delivery state of a sent message changed.
    Delivery {
        /// The message.
        message: MsgRef,
        /// The new state.
        delivery: Delivery,
    },
    /// The contact added or removed a reaction to a message.
    Reacted {
        /// The conversation.
        conversation: ConversationId,
        /// The message.
        message: MsgRef,
    },
    /// The contact changed the text of a message.
    Edited {
        /// The conversation.
        conversation: ConversationId,
        /// The message.
        message: MsgRef,
    },
    /// The state of the file of a message changed: the relays hold it, the
    /// store holds it, or its transfer failed.
    File {
        /// The message.
        message: MsgRef,
    },
    /// The contact deleted a message, and its row is a placeholder now.
    Deleted {
        /// The conversation.
        conversation: ConversationId,
        /// The message.
        message: MsgRef,
    },
    /// Another device of the set added a conversation or named one.
    Conversations,
    /// A contact offered a group of Part 11. The user sees the offers of
    /// [`client::Client::group_offers`] and answers one of them
    /// (`GRP-170`).
    GroupOffer {
        /// The pairwise conversation that carried it.
        from: ConversationId,
    },
    /// A contact asked to come into a group of an admin of this device.
    GroupJoiner {
        /// The pairwise conversation that carried it.
        from: ConversationId,
    },
    /// An admin admitted this device to a group. The client fetches the
    /// snapshot that the admit names and then calls
    /// [`client::Client::accept_group_admit`] (`GRP-313`).
    GroupAdmit {
        /// The pairwise conversation that carried it.
        from: ConversationId,
    },
    /// The client locked itself, or the platform locked it.
    Locked,
    /// A table MAC or a scan does not match. The interface tells the user
    /// (`IDN-039`).
    IntegrityFault,
}

/// The view of the platform that takes the text of one message for one
/// frame. The renderer owns it, and it copies the text into no `String`.
pub trait Sink {
    /// Takes the UTF-16 code units of the text.
    fn put(&mut self, code_units: &[u16]);
}

/// The one error of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The client is locked.
    Locked,
    /// The passphrase does not open the store on this device.
    WrongPassphrase,
    /// A table MAC, a scan, or a stored record does not verify.
    Integrity,
    /// A value does not parse, or a draft holds nothing.
    Malformed,
    /// A text or a list is above its bound.
    TooLong,
    /// The handle names no message.
    NotFound,
    /// The platform store failed.
    Storage,
    /// An earlier fault closed the client.
    Closed,
    /// The network runtime does not run.
    Offline,
    /// A limit on the rate of an act holds it back for a short time.
    Busy,
}

impl From<umbra_core::Error> for Error {
    fn from(inner: umbra_core::Error) -> Self {
        match inner {
            umbra_core::Error::Storage => Error::Storage,
            umbra_core::Error::Malformed | umbra_core::Error::Wire(_) => Error::Malformed,
            _ => Error::Integrity,
        }
    }
}

impl From<umbra_wire::Error> for Error {
    fn from(_: umbra_wire::Error) -> Self {
        Error::Malformed
    }
}

/// A stored form of this crate that its reader does not take is a fault
/// of the store.
impl From<umbra_crypto::Error> for Error {
    fn from(_: umbra_crypto::Error) -> Self {
        Error::Integrity
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Locked => "the client is locked",
            Error::WrongPassphrase => "the passphrase does not open the store",
            Error::Integrity => "the local store does not verify",
            Error::Malformed => "a value does not parse",
            Error::TooLong => "a value is above its bound",
            Error::NotFound => "no such message",
            Error::Storage => "the platform store failed",
            Error::Closed => "the client is closed",
            Error::Offline => "the network does not run",
            Error::Busy => "a rate limit holds the act back",
        })
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use umbra_core::{
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

    use super::{
        client::{Client, Silence},
        *,
    };
    use umbra_core::session::node::ContactId;

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

    const CHEAP: Cost = Cost { m_kib: 64, t: 1 };

    fn units(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn new_client(rng: &mut Rng) -> Client<MemoryBackend, Element> {
        Client::create(
            MemoryBackend::default(),
            Element([1; 32]),
            &units("correct horse"),
            CHEAP,
            1_000,
            rng,
        )
        .unwrap()
    }

    #[test]
    fn a_group_takes_its_two_queues_and_lives_through_a_lock() {
        let mut rng = Rng(21);
        let mut client = new_client(&mut rng);
        let contacts = client.conversations().unwrap().len();
        let relays = [[0xA1; 32], [0xB2; 32]];
        let conversation = client
            .create_group("Hiking", relays, 1_700_000_000, &mut rng)
            .unwrap();
        assert!(client.is_group(conversation).unwrap());
        assert_eq!(client.conversations().unwrap().len(), contacts + 1);
        let name_of = |client: &Client<MemoryBackend, Element>| {
            client
                .summaries()
                .unwrap()
                .into_iter()
                .find(|summary| summary.conversation == conversation)
                .map(|summary| summary.name)
        };
        assert_eq!(name_of(&client).as_deref(), Some("Hiking"));

        // The creator is the owner at index 0, and the group is not ready
        // before the two relays named their queues (`GRP-191`).
        let info = client.group_info(conversation).unwrap();
        assert_eq!((info.own_index, info.members, info.epoch), (0, 1, 1));
        assert!(!info.is_ready);
        assert_eq!(
            client.conversation_of_group(&info.group_id).unwrap(),
            conversation
        );

        // Two relays of one operator make no pair.
        assert!(client
            .create_group("Nope", [[0xA1; 32], [0xA1; 32]], 1_700_000_000, &mut rng)
            .is_err());

        // A lock drops the owner credentials from the memory, and the
        // unlock brings each `GNEW` that waits back.
        let mut jobs = Vec::new();
        while let Some(job) = client.take_group_creation() {
            jobs.push((job.replica, job.relay));
        }
        jobs.sort();
        assert_eq!(jobs, vec![(0, relays[0]), (1, relays[1])]);
        assert!(client.take_group_creation().is_none());
        client.lock();
        client
            .unlock(&units("correct horse"), 1_700_000_100)
            .unwrap();
        // The run of the group queues asks for the work at its start.
        assert!(client.take_group_creation().is_none());
        client.resume_group_work(&mut rng).unwrap();
        let first = client.take_group_creation().unwrap();
        let second = client.take_group_creation().unwrap();
        assert!(client.take_group_creation().is_none());
        assert_ne!(first.replica, second.replica);
        assert_eq!(first.read_pk, second.read_pk);

        // The first answer leaves the group unready, and the second one
        // makes it ready.
        let ready = client
            .group_queue_made(
                &info.group_id,
                first.replica,
                first.relay,
                [0xC3; 32],
                &mut rng,
            )
            .unwrap();
        assert!(!ready);
        assert!(!client.group_info(conversation).unwrap().is_ready);
        let ready = client
            .group_queue_made(
                &info.group_id,
                second.replica,
                second.relay,
                [0xD4; 32],
                &mut rng,
            )
            .unwrap();
        assert!(ready);
        assert!(client.group_info(conversation).unwrap().is_ready);

        // GRP-210: a group whose two replicas refused it takes no record,
        // and its state lives through a lock.
        assert!(!client.group_info(conversation).unwrap().is_closed);
        client.close_group(conversation, &mut rng).unwrap();
        assert!(client.group_info(conversation).unwrap().is_closed);
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("into a closed group")).unwrap();
        client
            .send_draft(draft, 1_700_000_150_000, &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_none());
        client.lock();
        client
            .unlock(&units("correct horse"), 1_700_000_160)
            .unwrap();
        client.resume_group_work(&mut rng).unwrap();
        assert!(client.group_info(conversation).unwrap().is_closed);
        assert!(client.take_group_post().is_none());

        // The group came back from the store with its replicas, and the
        // work list is empty at the next unlock.
        client.lock();
        client
            .unlock(&units("correct horse"), 1_700_000_200)
            .unwrap();
        client.resume_group_work(&mut rng).unwrap();
        assert!(client.take_group_creation().is_none());
        let info = client.group_info(conversation).unwrap();
        assert!(info.is_ready);
        assert_eq!(info.epoch, 1);
        assert_eq!(name_of(&client).as_deref(), Some("Hiking"));
    }

    /// A group control object as the `AppMessage` of a group post.
    fn control_app(object: &[u8]) -> Vec<u8> {
        let app = umbra_wire::app::AppMessage {
            kind: umbra_wire::app::AppKind::GroupControl,
            msg_id: [0x5A; 16],
            sent_at: 1_700_000_020_000,
            body: object,
        };
        let mut bytes = vec![0u8; app.len()];
        let n = app.encode(&mut bytes).unwrap();
        bytes.truncate(n);
        bytes
    }

    #[test]
    fn a_cross_relay_token_admits_one_hello_under_the_key_of_the_log() {
        use umbra_core::abuse::token::{
            issue_cross_relay, CrossRelayRequest, TokenChallenge, TYPE_CROSS_RELAY,
        };
        use umbra_crypto::rsabssa::SecretKey2048;

        let mut rng = Rng(81);
        let mut client = new_client(&mut rng);
        use umbra_crypto::secret::Secret;
        let epoch: u32 = 2_900;
        let key = SecretKey2048::from_seed(&Secret::new([0x71; 32]), &epoch.to_be_bytes()).unwrap();
        let other =
            SecretKey2048::from_seed(&Secret::new([0x72; 32]), &epoch.to_be_bytes()).unwrap();
        let mint = |key: &SecretKey2048, epoch: u32, rng: &mut Rng| {
            let challenge = TokenChallenge {
                token_type: TYPE_CROSS_RELAY,
                epoch,
                redemption_context: [0; 32],
            };
            let (state, blinded) =
                CrossRelayRequest::new(1, &challenge, key.public(), rng).unwrap();
            let signed = issue_cross_relay(key, &blinded).unwrap();
            let token = state.finalize(&signed, key.public()).unwrap().remove(0);
            umbra_core::discovery::dirclient::token_bytes(&token).unwrap()
        };
        let token = mint(&key, epoch, &mut rng);
        // No key from the log yet: no admission.
        assert!(!client.admit_token(&token, epoch, &mut rng).unwrap());
        client
            .put_cross_relay_key(epoch, key.public().modulus(), &mut rng)
            .unwrap();
        assert!(client.admit_token(&token, epoch, &mut rng).unwrap());
        // ABU-006: this device spends a nonce once.
        assert!(!client.admit_token(&token, epoch, &mut rng).unwrap());
        // A key that the log does not hold admits nothing.
        let forged = mint(&other, epoch, &mut rng);
        assert!(!client.admit_token(&forged, epoch, &mut rng).unwrap());
        // A token of the epoch before still admits, one of two before does not.
        let fresh = mint(&key, epoch, &mut rng);
        assert!(client.admit_token(&fresh, epoch + 1, &mut rng).unwrap());
        let late = mint(&key, epoch, &mut rng);
        assert!(!client.admit_token(&late, epoch + 2, &mut rng).unwrap());

        // The tokens of this device: one goes to each hello, and an older
        // epoch goes.
        client
            .put_tokens(epoch, &[token.clone(), fresh.clone()], &mut rng)
            .unwrap();
        assert_eq!(client.token_count(epoch).unwrap(), 2);
        assert!(client.take_token(epoch).unwrap().is_some());
        assert_eq!(client.token_count(epoch).unwrap(), 1);
        assert!(client.take_token(epoch + 1).unwrap().is_none());
        assert_eq!(client.token_count(epoch).unwrap(), 0);
    }

    #[test]
    fn a_rival_rekey_takes_the_index_and_the_seed_before_comes_back() {
        use umbra_core::group::join::JoinKeys;
        use umbra_wire::group::control::{GroupControl, RekeyRecord};

        let mut rng = Rng(51);
        let mut client = new_client(&mut rng);
        let relays = [[0xA1; 32], [0xB2; 32]];
        let conversation = client
            .create_group("Race", relays, 1_700_000_000, &mut rng)
            .unwrap();
        let group_id = client.group_info(conversation).unwrap().group_id;
        client
            .group_queue_made(&group_id, 0, relays[0], [0xC3; 32], &mut rng)
            .unwrap();
        client
            .group_queue_made(&group_id, 1, relays[1], [0xD4; 32], &mut rng)
            .unwrap();
        while client.take_group_post().is_some() {}

        // A removed device holds the group as it stood, and a reader of the
        // same keys sees the re-key that this device makes.
        let mut rival = client.group_of(conversation).unwrap();
        let mut reader = client.group_of(conversation).unwrap();
        client.rekey_groups(1_700_000_010_000, &mut rng).unwrap();
        let post = client.take_group_post().unwrap();
        assert_eq!(client.group_info(conversation).unwrap().own_index, 1);
        let umbra_core::group::receive::Outcome::Content { app, .. } =
            reader.receive(&post.record, 1_700_000_011).unwrap()
        else {
            panic!("the reader got no re-key");
        };
        let body = umbra_wire::app::AppMessage::parse(&app, umbra_wire::app::Channel::Group)
            .unwrap()
            .body
            .to_vec();
        let hash = GroupControl::parse(&body).unwrap().epoch_hash();

        // GRP-369: the rival with the lower hash takes the index.
        let rival_object = loop {
            let keys = JoinKeys::make(&mut rng).unwrap();
            let made = rival.rekey_object(&keys, &mut rng).unwrap();
            if GroupControl::parse(&made).unwrap().epoch_hash() < hash {
                break made;
            }
        };
        let record = rival
            .post(&control_app(&rival_object), 1_700_000_012, &mut rng)
            .unwrap();
        client
            .on_group_record(&[0xC3; 32], 2, &record, 1_700_000_013_000, &mut rng)
            .unwrap();
        let info = client.group_info(conversation).unwrap();
        assert_eq!(info.own_index, 0);

        // The seed before the re-key is the seed of the group again, thus a
        // new unlock makes the same keys, and the pairwise record of
        // GRP-370 signs under them.
        client.lock();
        client
            .unlock(&units("correct horse"), 1_700_000_020)
            .unwrap();
        let group = client.group_of(conversation).unwrap();
        assert!(group.lost_rekey());
        let fresh = JoinKeys::make(&mut rng).unwrap();
        let pairwise = group.pairwise_rekey_object(&fresh, &mut rng).unwrap();
        let control = GroupControl::parse(&pairwise).unwrap();
        let parsed = RekeyRecord::parse(control.payload).unwrap();
        let held = group.roster().member(0).unwrap().roster_pk_hash;
        parsed.verify(&held).unwrap();
    }

    #[test]
    fn a_group_message_waits_for_the_two_queues_and_a_record_becomes_a_message() {
        let mut rng = Rng(31);
        let mut client = new_client(&mut rng);
        let relays = [[0xA1; 32], [0xB2; 32]];
        let conversation = client
            .create_group("Trail", relays, 1_700_000_000, &mut rng)
            .unwrap();
        let group_id = client.group_info(conversation).unwrap().group_id;

        // A group with one queue sends nothing (`GRP-191`).
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("first light")).unwrap();
        let sent = client
            .send_draft(draft, 1_700_000_001_000, &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_none());
        // The record takes no pairwise channel.
        assert!(client.take_outgoing().is_none());
        client
            .group_queue_made(&group_id, 0, relays[0], [0xC3; 32], &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_none());

        // The second queue makes the group ready, and the record that
        // waited goes to each replica (`GRP-194`).
        client
            .group_queue_made(&group_id, 1, relays[1], [0xD4; 32], &mut rng)
            .unwrap();
        let post = client.take_group_post().unwrap();
        assert!(client.take_group_post().is_none());
        assert_eq!(post.message, Some(sent));
        assert_eq!(post.conversation, conversation);
        assert_eq!(post.replicas[0].group_queue_id, [0xC3; 32]);
        assert_eq!(post.replicas[1].group_queue_id, [0xD4; 32]);
        assert_eq!(post.replicas[1].relay, relays[1]);

        // A second member joins with the add and the admit of §11.9.1. It
        // reads no record from before its admission (`GRP-252`), thus the
        // first one gives it nothing.
        let mut other = new_client(&mut rng);
        let member = join_group(&mut client, &mut other, conversation, &mut rng);
        assert!(other
            .on_group_record(&[0xC3; 32], 1, &post.record, 1_700_000_002_000, &mut rng)
            .unwrap()
            .is_none());

        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("second light")).unwrap();
        client
            .send_draft(draft, 1_700_000_003_000, &mut rng)
            .unwrap();
        let post = client.take_group_post().unwrap();
        let message = other
            .on_group_record(&[0xC3; 32], 1, &post.record, 1_700_000_003_000, &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(
            other.next_event(),
            Some(Event::Message {
                conversation: member,
                message
            })
        );
        let mut view = View::default();
        other.render(&message, &mut view).unwrap();
        assert_eq!(String::from_utf16(&view.0).unwrap(), "second light");

        // WIR-065: the copy from the other replica gives no second message.
        assert!(other
            .on_group_record(&[0xD4; 32], 1, &post.record, 1_700_000_003_000, &mut rng)
            .unwrap()
            .is_none());
        assert_eq!(other.next_event(), None);

        // A record of a queue that this device does not hold is ignored.
        assert!(other
            .on_group_record(&[0xEE; 32], 1, &post.record, 1_700_000_004_000, &mut rng)
            .unwrap()
            .is_none());
    }

    /// A group of `client` with both queues, and `other` in it at index 1.
    fn ready_pair(
        client: &mut Client<MemoryBackend, Element>,
        other: &mut Client<MemoryBackend, Element>,
        rng: &mut Rng,
    ) -> (ConversationId, ConversationId) {
        let relays = [[0xA1; 32], [0xB2; 32]];
        let conversation = client
            .create_group("Trail", relays, 1_700_000_000, rng)
            .unwrap();
        let group_id = client.group_info(conversation).unwrap().group_id;
        client
            .group_queue_made(&group_id, 0, relays[0], [0xC3; 32], rng)
            .unwrap();
        client
            .group_queue_made(&group_id, 1, relays[1], [0xD4; 32], rng)
            .unwrap();
        let member = join_group(client, other, conversation, rng);
        (conversation, member)
    }

    #[test]
    fn a_quiet_member_sends_presence_and_a_silent_one_is_removed() {
        const DAY: u64 = 86_400;
        let mut rng = Rng(61);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let (conversation, member) = ready_pair(&mut client, &mut other, &mut rng);
        // GRP-169: a group of two evicts nobody, thus a third member joins.
        let mut third = new_client(&mut rng);
        join_group(&mut client, &mut third, conversation, &mut rng);
        let t0 = 1_700_000_010;
        let ms = |seconds: u64| seconds * 1_000;
        // Each clock starts at its first look, and nothing is due then.
        assert!(client
            .members_to_evict(ms(t0), &mut rng)
            .unwrap()
            .is_empty());
        assert!(other
            .groups_owing_presence(ms(t0), &mut rng)
            .unwrap()
            .is_empty());
        // A plain member watches no silence (`GRP-132`).
        assert!(other
            .members_to_evict(ms(t0 + 60 * DAY), &mut rng)
            .unwrap()
            .is_empty());

        // GRP-128: a week with no record gives one presence record, and
        // the owner reads it as a sign of life.
        let week = t0 + 7 * DAY;
        assert!(other
            .groups_owing_presence(ms(week - 1), &mut rng)
            .unwrap()
            .is_empty());
        assert_eq!(
            other.groups_owing_presence(ms(week), &mut rng).unwrap(),
            vec![member]
        );
        other.post_presence(member, ms(week), &mut rng).unwrap();
        let presence = other.take_group_post().unwrap();
        assert!(presence.message.is_none());
        assert!(client
            .on_group_record(&[0xC3; 32], 1, &presence.record, ms(week), &mut rng)
            .unwrap()
            .is_none());
        assert!(other
            .groups_owing_presence(ms(week + DAY), &mut rng)
            .unwrap()
            .is_empty());

        // GRP-134: silence shorter than `GROUP_SILENT_EVICT` removes
        // nobody, and at the bound the owner draws its backoff first. The
        // third member sent nothing at all, thus it is silent first.
        let quiet = t0 + 30 * DAY;
        assert!(client
            .members_to_evict(ms(quiet), &mut rng)
            .unwrap()
            .is_empty());
        assert_eq!(
            client
                .members_to_evict(ms(quiet + 3_600), &mut rng)
                .unwrap(),
            vec![(conversation, 2, Silence::Remove)]
        );
        let silent = week + 30 * DAY;
        // The member of the presence record is not silent yet. Member 2
        // comes back once its wait after the last answer ran out, and at
        // the bound member 1 draws its backoff.
        assert_eq!(
            client.members_to_evict(ms(silent - 1), &mut rng).unwrap(),
            vec![(conversation, 2, Silence::Remove)]
        );
        assert!(client
            .members_to_evict(ms(silent), &mut rng)
            .unwrap()
            .is_empty());
        let due = client
            .members_to_evict(ms(silent + 3_600), &mut rng)
            .unwrap();
        assert_eq!(
            due,
            vec![
                (conversation, 1, Silence::Remove),
                (conversation, 2, Silence::Remove)
            ]
        );

        // GRP-133 and GRP-264: the removal rotates the epoch.
        client
            .remove_from_group(conversation, 2, ms(silent + 3_600), &mut rng)
            .unwrap();
        let info = client.group_info(conversation).unwrap();
        assert_eq!((info.members, info.epoch), (2, 2));
        // A group of two keeps its last member (`GRP-169`).
        assert!(client
            .members_to_evict(ms(silent + 7_200), &mut rng)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn an_admin_sets_a_role_and_a_silent_moderator_loses_it_before_it_goes() {
        use umbra_wire::group::control::Role;
        const DAY: u64 = 86_400;
        let mut rng = Rng(71);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let (conversation, _) = ready_pair(&mut client, &mut other, &mut rng);
        let mut third = new_client(&mut rng);
        join_group(&mut client, &mut third, conversation, &mut rng);
        let t0 = 1_700_000_010;
        let ms = |seconds: u64| seconds * 1_000;

        // The owner makes member 1 a moderator, and the grant goes out
        // before it applies here (`GRP-389`).
        client
            .set_group_role(conversation, 1, Role::Moderator, ms(t0), &mut rng)
            .unwrap();
        let grant = client.take_group_post().unwrap();
        assert!(grant.message.is_none());
        let roles = |client: &Client<MemoryBackend, Element>| -> Vec<Role> {
            client
                .group_members(conversation)
                .unwrap()
                .iter()
                .map(|member| member.role)
                .collect()
        };
        assert_eq!(
            roles(&client),
            vec![Role::Owner, Role::Moderator, Role::Member]
        );

        // GRP-166: a silent moderator loses its role first, and the removal
        // comes after the rate of one epoch (`GRP-076`).
        assert!(client
            .members_to_evict(ms(t0), &mut rng)
            .unwrap()
            .is_empty());
        let silent = t0 + 30 * DAY;
        client.members_to_evict(ms(silent), &mut rng).unwrap();
        let first = client
            .members_to_evict(ms(silent + 3_600), &mut rng)
            .unwrap();
        assert!(first.contains(&(conversation, 1, Silence::Demote)));
        client
            .set_group_role(conversation, 1, Role::Member, ms(silent + 3_600), &mut rng)
            .unwrap();
        let later = client
            .members_to_evict(ms(silent + 3_630), &mut rng)
            .unwrap();
        assert!(!later.iter().any(|(_, index, _)| *index == 1));
        let last = client
            .members_to_evict(ms(silent + 7_200), &mut rng)
            .unwrap();
        assert!(last.contains(&(conversation, 1, Silence::Remove)));
    }

    #[test]
    fn owner_credentials_follow_the_admin_roles() {
        use umbra_wire::group::control::Role;
        let mut rng = Rng(73);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let (conversation, member) = ready_pair(&mut client, &mut other, &mut rng);
        let now = 1_700_000_100_000;
        let mut seq = 0;
        let mut carry = |from: &mut Client<MemoryBackend, Element>,
                         to: &mut Client<MemoryBackend, Element>,
                         at: u64| {
            while let Some(post) = from.take_group_post() {
                seq += 1;
                to.on_group_record(&[0xC3; 32], seq, &post.record, at, &mut Rng(u64::from(seq)))
                    .unwrap();
            }
        };

        // GRP-298, GRP-400: the grant, then the owner credentials.
        client
            .set_group_role(conversation, 1, Role::Admin, now, &mut rng)
            .unwrap();
        carry(&mut client, &mut other, now);
        let owners_at = |client: &Client<MemoryBackend, Element>, conversation| {
            client
                .group_of(conversation)
                .unwrap()
                .owner(0)
                .map(|held| *held.expose())
        };
        assert!(owners_at(&other, member).is_some());
        assert_eq!(owners_at(&other, member), owners_at(&client, conversation));

        // GRP-401: a demotion draws new owner credentials. Each replica
        // moves to them under the ones they replace, and the admin that
        // left holds the old ones alone.
        let old = owners_at(&client, conversation);
        client
            .set_group_role(conversation, 1, Role::Member, now + 1_000, &mut rng)
            .unwrap();
        let mut rekeys = Vec::new();
        while let Some(job) = client.take_group_rekey() {
            rekeys.push(job);
        }
        assert_eq!(rekeys.len(), 2);
        assert!(rekeys.iter().all(|job| job.next_own_pk.is_some()));
        assert_eq!(Some(*rekeys[0].own.expose()), old);
        assert_ne!(owners_at(&client, conversation), old);
        carry(&mut client, &mut other, now + 1_000);
        assert_eq!(owners_at(&other, member), old);

        // GRP-402: an admin that leaves makes another admin draw new
        // owner credentials after its backoff.
        client
            .set_group_role(conversation, 1, Role::Admin, now + 2_000, &mut rng)
            .unwrap();
        carry(&mut client, &mut other, now + 2_000);
        assert_eq!(owners_at(&other, member), owners_at(&client, conversation));
        other.leave_group(member, now + 3_000, &mut rng).unwrap();
        let post = other.take_group_post().unwrap();
        client
            .on_group_record(&[0xC3; 32], 99, &post.record, now + 3_000, &mut rng)
            .unwrap();
        assert!(client
            .groups_owing_owners(now + 3_000, &mut rng)
            .unwrap()
            .is_empty());
        assert_eq!(
            client
                .groups_owing_owners(now + 3_000_000, &mut rng)
                .unwrap(),
            vec![conversation]
        );
        let held = owners_at(&client, conversation);
        client
            .rotate_owners(conversation, now + 3_000_000, &mut rng)
            .unwrap();
        assert_ne!(owners_at(&client, conversation), held);
        assert!(client
            .groups_owing_owners(now + 3_100_000, &mut rng)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_member_that_missed_an_epoch_key_asks_for_it_and_gets_it() {
        const DAY: u64 = 86_400;
        let mut rng = Rng(79);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let (conversation, member) = ready_pair(&mut client, &mut other, &mut rng);
        let later = 1_700_000_000 + 31 * DAY;
        let ms = |seconds: u64| seconds * 1_000;
        // GRP-360: the owner rotates an aged epoch, and its epoch-key
        // record never reaches the member.
        client
            .rotate_group(conversation, ms(later), &mut rng)
            .unwrap();
        let _lost = client.take_group_post().unwrap();
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("under the new key")).unwrap();
        client.send_draft(draft, ms(later), &mut rng).unwrap();
        let text = client.take_group_post().unwrap();
        other
            .on_group_record(&[0xC3; 32], 2, &text.record, ms(later), &mut rng)
            .unwrap();
        assert_eq!(other.next_event(), None);

        // GRP-289: the member asks, once in the slot.
        let lacking = other.groups_lacking_epoch(ms(later)).unwrap();
        assert_eq!(lacking, vec![(member, 2)]);
        assert!(other
            .groups_lacking_epoch(ms(later + 60))
            .unwrap()
            .is_empty());
        other.request_epoch(member, 2, ms(later), &mut rng).unwrap();
        let request = other.take_group_post().unwrap();
        client
            .on_group_record(&[0xC3; 32], 3, &request.record, ms(later), &mut rng)
            .unwrap();
        assert_eq!(client.next_event(), None);

        // GRP-375: after its backoff the owner posts the one-slot record
        // and the notice of its supply. The backoff is an exponential draw,
        // which can end inside the first second.
        let mut due = client.key_answers_due(ms(later));
        if due.is_empty() {
            due = client.key_answers_due(ms(later + 3_600));
        }
        assert_eq!(due, vec![(conversation, 1)]);
        assert!(client.key_answers_due(ms(later + 3_600)).is_empty());
        client
            .answer_key_request(conversation, 1, ms(later + 3_600), &mut rng)
            .unwrap();
        let supply = client.take_group_post().unwrap();
        let notice = client.take_group_post().unwrap();

        // The epoch installs, and the record that waited becomes a message.
        let message = other
            .on_group_record(&[0xC3; 32], 4, &supply.record, ms(later + 3_600), &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(
            other.next_event(),
            Some(Event::Message {
                conversation: member,
                message
            })
        );
        assert!(other
            .on_group_record(&[0xC3; 32], 5, &notice.record, ms(later + 3_600), &mut rng)
            .unwrap()
            .is_none());
        assert_eq!(other.group_info(member).unwrap().epoch, 2);
        assert!(other
            .groups_lacking_epoch(ms(later + 7_200))
            .unwrap()
            .is_empty());

        // GRP-297: a group whose relays refuse a member that lacks its epoch
        // lapsed; it is not gone.
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("one more")).unwrap();
        client
            .send_draft(draft, ms(later + 90 * DAY), &mut rng)
            .unwrap();
        client
            .rotate_group(conversation, ms(later + 90 * DAY), &mut rng)
            .unwrap();
        while client.take_group_post().is_some() {}
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("in the third epoch")).unwrap();
        client
            .send_draft(draft, ms(later + 90 * DAY), &mut rng)
            .unwrap();
        let third = client.take_group_post().unwrap();
        other
            .on_group_record(
                &[0xC3; 32],
                9,
                &third.record,
                ms(later + 90 * DAY),
                &mut rng,
            )
            .unwrap();
        other.close_group(member, &mut rng).unwrap();
        let info = other.group_info(member).unwrap();
        assert!(info.is_lapsed && info.is_closed);
        assert!(!client.group_info(conversation).unwrap().is_lapsed);

        // GRP-290: the lapsed member asks a contact that is a member on
        // their pairwise channel, and names itself by index (`WIR-523`).
        let peer_at_client = ContactId([0x61; 32]);
        let peer_at_other = ContactId([0x62; 32]);
        let pair_at_client = client.conversation_for(&peer_at_client.0).unwrap();
        let pair_at_other = other.conversation_for(&peer_at_other.0).unwrap();
        other
            .note_contact_in(member, b"via", pair_at_other, &mut rng)
            .unwrap();
        let at = ms(later + 91 * DAY);
        assert_eq!(other.groups_to_ask_pairwise(at).unwrap(), vec![(member, 3)]);
        assert_eq!(
            other
                .request_epoch_pairwise(member, 3, at, &mut rng)
                .unwrap(),
            1
        );
        let asked = other.take_outgoing().unwrap();
        assert_eq!(asked.conversation, pair_at_other);
        // GRP-376: the owner holds the epoch and supplies it at once, and
        // the request is no message of the pairwise conversation.
        deliver(&mut client, &peer_at_client, &asked.app, at, &mut rng);
        assert!(client
            .summaries()
            .unwrap()
            .iter()
            .filter(|summary| summary.conversation == pair_at_client)
            .all(|summary| summary.last.is_none()));
        let supply = client.take_group_post().unwrap();
        let _notice = client.take_group_post().unwrap();
        let reopened = other
            .on_group_record(&[0xC3; 32], 10, &supply.record, at, &mut rng)
            .unwrap();
        assert!(reopened.is_some());
        // GRP-405: the epoch it lacked came, thus the group is open again.
        let info = other.group_info(member).unwrap();
        assert!(!info.is_lapsed && !info.is_closed);
        assert_eq!(info.epoch, 3);
    }

    #[test]
    fn a_record_that_came_before_its_epoch_key_opens_when_the_key_does() {
        const DAY: u64 = 86_400;
        let mut rng = Rng(67);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let (conversation, member) = ready_pair(&mut client, &mut other, &mut rng);
        // GRP-360: the age of the epoch calls for a rotation.
        let later = 1_700_000_000 + 31 * DAY;
        let ms = |seconds: u64| seconds * 1_000;
        client
            .rotate_group(conversation, ms(later), &mut rng)
            .unwrap();
        let key = client.take_group_post().unwrap();
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("under the new key")).unwrap();
        client.send_draft(draft, ms(later), &mut rng).unwrap();
        let text = client.take_group_post().unwrap();

        // The content arrives first, and it waits for the key.
        assert!(other
            .on_group_record(&[0xC3; 32], 2, &text.record, ms(later), &mut rng)
            .unwrap()
            .is_none());
        assert_eq!(other.next_event(), None);
        // The key installs, and the record that waited becomes a message.
        let message = other
            .on_group_record(&[0xD4; 32], 1, &key.record, ms(later), &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(
            other.next_event(),
            Some(Event::Message {
                conversation: member,
                message
            })
        );
        assert_eq!(other.group_info(member).unwrap().epoch, 2);
    }

    #[test]
    fn a_group_above_the_inline_carrier_rotates_on_the_chunk_path() {
        use umbra_core::group::join::JoinKeys;
        use umbra_wire::group::control::{GroupControl, JoinRecord};
        const DAY: u64 = 86_400;
        let mut rng = Rng(83);
        let mut client = new_client(&mut rng);
        let mut other = new_client(&mut rng);
        let relays = [[0xA1; 32], [0xB2; 32]];
        let conversation = client
            .create_group("Trail", relays, 1_700_000_000, &mut rng)
            .unwrap();
        let group_id = client.group_info(conversation).unwrap().group_id;
        client
            .group_queue_made(&group_id, 0, relays[0], [0xC3; 32], &mut rng)
            .unwrap();
        client
            .group_queue_made(&group_id, 1, relays[1], [0xD4; 32], &mut rng)
            .unwrap();
        // 28 members join before `other`, thus the group holds 30, above
        // the 27 slots of the inline carrier.
        let mut group = client.group_of(conversation).unwrap();
        for _ in 0..28 {
            let joiner = JoinKeys::make(&mut rng).unwrap();
            let kem_pk = joiner.keys.kem().public().to_bytes();
            let add = group
                .add_object(&JoinRecord {
                    group_id,
                    keys: joiner.wire_keys(&kem_pk),
                })
                .unwrap();
            group
                .apply_control(&GroupControl::parse(&add).unwrap(), 0, 1_700_000_001)
                .unwrap();
        }
        client.save_group(conversation, &group, &mut rng).unwrap();
        let member = join_group(&mut client, &mut other, conversation, &mut rng);

        // GRP-283: the slots go up first, and no record goes before them.
        let later = 1_700_000_000 + 31 * DAY;
        let ms = |seconds: u64| seconds * 1_000;
        client
            .rotate_group(conversation, ms(later), &mut rng)
            .unwrap();
        assert!(client.take_group_post().is_none());
        let upload = client.take_epoch_upload().unwrap();
        assert_eq!(upload.chunked.slot_count, 30);
        // A failed upload goes again, up to its limit.
        client.epoch_upload_failed(upload);
        let upload = client.take_epoch_upload().unwrap();
        assert_eq!(upload.tries, 1);
        client
            .post_chunked_epoch(&upload, b"a descriptor", ms(later), &mut rng)
            .unwrap();
        let key = client.take_group_post().unwrap();
        assert!(key.is_rotation);
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("under the new key")).unwrap();
        client.send_draft(draft, ms(later), &mut rng).unwrap();
        let text = client.take_group_post().unwrap();

        // GRP-284: the member fetches the one chunk that holds its slot,
        // once for the two replicas.
        assert!(other
            .on_group_record(&[0xC3; 32], 2, &text.record, ms(later), &mut rng)
            .unwrap()
            .is_none());
        for (queue, seq) in [([0xC3; 32], 3), ([0xD4; 32], 1)] {
            assert!(other
                .on_group_record(&queue, seq, &key.record, ms(later), &mut rng)
                .unwrap()
                .is_none());
        }
        let (at, wanted) = other.take_epoch_chunk().unwrap();
        assert_eq!(at, member);
        assert!(other.take_epoch_chunk().is_none());
        assert_eq!(wanted.descriptor, b"a descriptor");
        assert_eq!(wanted.chunk, 1);
        let size = umbra_core::attach::SEGMENT_SIZE;
        let block = &upload.chunked.object[size..2 * size];

        // The epoch installs, and the record that waited becomes a message.
        let message = other
            .install_epoch_chunk(member, &wanted, block, ms(later), &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(
            other.next_event(),
            Some(Event::Message {
                conversation: member,
                message
            })
        );
        assert_eq!(other.group_info(member).unwrap().epoch, 2);
        // An upload past its limit is given up, and the members that lack
        // the epoch ask for it.
        let mut upload = upload;
        upload.tries = 2;
        client.epoch_upload_failed(upload);
        assert!(client.take_epoch_upload().is_none());
    }

    #[test]
    fn queues_bind_in_groups_and_each_group_registers_under_its_endpoint() {
        use umbra_core::notify::ndr::Ndr;
        use umbra_crypto::secret::Secret;
        use umbra_wire::ndr::{NdrRequest, NdrResponse, TokenCarrier, BLOB_LEN, NDR_REQUEST_LEN};
        let mut rng = Rng(91);
        let mut client = new_client(&mut rng);
        let queues: Vec<([u8; 32], [u8; 32])> = (0..10u8)
            .map(|i| ([i; 32], [0xA1; 32]))
            .chain([([0x50; 32], [0xB2; 32])])
            .collect();
        // No endpoint, no binding.
        assert!(client
            .queues_to_bind(&queues, 0, &mut rng)
            .unwrap()
            .is_empty());
        let up = TokenCarrier::UnifiedPush;
        assert!(client
            .set_push_token(Some((up, "http://plain.example/up")), &mut rng)
            .is_err());
        let first = "https://push.example/up/one";
        client.set_push_token(Some((up, first)), &mut rng).unwrap();
        assert_eq!(
            client.push_token().unwrap().unwrap()[1..],
            *first.as_bytes()
        );

        // NTF-031: eight queues of one relay share a handle at most.
        let unbound = client.queues_to_bind(&queues, 0, &mut rng).unwrap();
        assert_eq!(unbound.len(), 11);
        let a = client.binding_of(&[0; 32]).unwrap().unwrap();
        let b = client.binding_of(&[7; 32]).unwrap().unwrap();
        let c = client.binding_of(&[8; 32]).unwrap().unwrap();
        let d = client.binding_of(&[0x50; 32]).unwrap().unwrap();
        assert_eq!(a.handle, b.handle);
        assert_ne!(a.handle, c.handle);
        // NTF-007: each group holds a root of its own, which rotates with it.
        assert_eq!(a.root.expose(), b.root.expose());
        assert_ne!(a.root.expose(), c.root.expose());
        assert_ne!(a.queue_alias, b.queue_alias);
        assert_ne!(a.relay_idx, d.relay_idx);
        client.queue_bound(&[0; 32], &mut rng).unwrap();
        let again = client.queues_to_bind(&queues, 0, &mut rng).unwrap();
        assert_eq!(again.len(), 10);
        assert!(!again.contains(&[0; 32]));

        // Each group registers once, and the NDR opens its token.
        let mut ndr = Ndr::default();
        let calls = client.ndr_calls_due(&mut rng).unwrap();
        assert_eq!(calls.len(), 3);
        for call in &calls {
            assert_eq!(ndr.handle(&call.request[..]).0, NdrResponse::Taken);
            client.ndr_call_taken(call, &mut rng).unwrap();
        }
        assert!(client.ndr_calls_due(&mut rng).unwrap().is_empty());
        let mut push = [0u8; NDR_REQUEST_LEN];
        NdrRequest::Push {
            handle: a.handle,
            k_tok: Secret::new(*a.k_tok.expose()),
            ttl: 60,
            blob: [0; BLOB_LEN],
        }
        .encode(&mut push)
        .unwrap();
        let delivery = ndr.handle(&push).1.unwrap();
        assert_eq!(&delivery.target[..], first.as_bytes());

        // NTF-124: a new endpoint moves each held handle on its removal
        // secret, and none takes each group back.
        // An FCM token takes the place of the endpoint.
        let second = "fcm-token-2";
        client
            .set_push_token(Some((TokenCarrier::Fcm, second)), &mut rng)
            .unwrap();
        let calls = client.ndr_calls_due(&mut rng).unwrap();
        assert_eq!(calls.len(), 3);
        for call in &calls {
            assert_eq!(ndr.handle(&call.request[..]).0, NdrResponse::Taken);
            client.ndr_call_taken(call, &mut rng).unwrap();
        }
        assert_eq!(&ndr.handle(&push).1.unwrap().target[..], second.as_bytes());
        client.set_push_token(None, &mut rng).unwrap();
        let calls = client.ndr_calls_due(&mut rng).unwrap();
        assert!(calls.iter().all(|call| call.is_removal));
        for call in &calls {
            assert_eq!(ndr.handle(&call.request[..]).0, NdrResponse::Taken);
            client.ndr_call_taken(call, &mut rng).unwrap();
        }
        assert!(ndr.is_empty());
        assert!(client.ndr_calls_due(&mut rng).unwrap().is_empty());
    }

    #[test]
    fn a_group_notify_queue_rotates_and_each_old_queue_leaves_both_replicas() {
        use umbra_core::notify::ROTATE_INTERVAL;
        use umbra_wire::ndr::TokenCarrier;
        let mut rng = Rng(117);
        let mut client = new_client(&mut rng);
        let relays = [[0xA1; 32], [0xB2; 32]];
        let t0 = 1_800_000_000;
        let conversation = client.create_group("Summit", relays, t0, &mut rng).unwrap();
        let group_id = client.group_info(conversation).unwrap().group_id;
        while let Some(job) = client.take_group_creation() {
            let queue = [0xC0 | job.replica; 32];
            client
                .group_queue_made(&group_id, job.replica, job.relay, queue, &mut rng)
                .unwrap();
        }
        assert!(client.group_info(conversation).unwrap().is_ready);

        // NTF-090: a device with no push token makes no notify queue.
        assert!(client.groups_without_notify(t0).unwrap().is_empty());
        client
            .set_push_token(Some((TokenCarrier::Fcm, "fcm-token")), &mut rng)
            .unwrap();
        assert_eq!(
            client.groups_without_notify(t0).unwrap(),
            vec![conversation]
        );
        let first = vec![0x11; umbra_wire::address::LEN];
        let second = vec![0x22; umbra_wire::address::LEN];
        client
            .set_group_notify(conversation, [0x11; 32], &first, t0, &mut rng)
            .unwrap();
        assert!(client.groups_without_notify(t0).unwrap().is_empty());

        // NTF-093: one GNREG for each replica.
        let register =
            |client: &mut Client<MemoryBackend, Element>, rng: &mut Rng, now: u64, queue: &[u8]| {
                let due = client.notify_registrations_due(now).unwrap();
                assert_eq!(due.len(), 2);
                for registration in due {
                    assert!(registration.on);
                    assert_eq!(registration.queue, queue);
                    client
                        .notify_registered(conversation, registration.which, now, rng)
                        .unwrap();
                }
                assert!(client.notify_registrations_due(now).unwrap().is_empty());
            };
        register(&mut client, &mut rng, t0, &first);
        assert!(client.notify_endings_due().unwrap().is_empty());

        // NTF-104: after seven days the group takes a new queue, and the
        // old one stays until both replicas took the new GNREG (NTF-105).
        let t1 = t0 + ROTATE_INTERVAL;
        assert!(client.groups_without_notify(t1 - 1).unwrap().is_empty());
        assert_eq!(
            client.groups_without_notify(t1).unwrap(),
            vec![conversation]
        );
        client
            .set_group_notify(conversation, [0x22; 32], &second, t1, &mut rng)
            .unwrap();
        // A second rotation waits for the first one to end.
        assert!(client
            .groups_without_notify(t1 + ROTATE_INTERVAL)
            .unwrap()
            .is_empty());
        assert!(client.notify_endings_due().unwrap().is_empty());
        register(&mut client, &mut rng, t1, &second);
        let endings = client.notify_endings_due().unwrap();
        assert_eq!(endings.len(), 1);
        assert_eq!(endings[0].queues, vec![[0x11; 32]]);
        assert_eq!(endings[0].unregistrations.len(), 2);
        for registration in &endings[0].unregistrations {
            assert!(!registration.on);
            assert_eq!(registration.queue, first);
        }
        client.notify_ended(conversation, &mut rng).unwrap();
        assert!(client.notify_endings_due().unwrap().is_empty());
        // The new queue stays registered and lives through a lock.
        client.lock();
        client.unlock(&units("correct horse"), t1).unwrap();
        assert!(client.notify_registrations_due(t1).unwrap().is_empty());
        assert!(client.notify_endings_due().unwrap().is_empty());

        // NTF-132, NTF-133: a closed group sends GNUNREG for its queue, ends it, and
        // takes no new one.
        client.close_group(conversation, &mut rng).unwrap();
        let endings = client.notify_endings_due().unwrap();
        assert_eq!(endings.len(), 1);
        assert_eq!(endings[0].queues, vec![[0x22; 32]]);
        assert_eq!(endings[0].unregistrations.len(), 2);
        assert!(endings[0]
            .unregistrations
            .iter()
            .all(|registration| !registration.on && registration.queue == second));
        client.notify_ended(conversation, &mut rng).unwrap();
        assert!(client.notify_endings_due().unwrap().is_empty());
        assert!(client
            .groups_without_notify(t1 + 2 * ROTATE_INTERVAL)
            .unwrap()
            .is_empty());
        assert!(client
            .notify_registrations_due(t1 + 2 * ROTATE_INTERVAL)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_dead_channel_writes_its_blob_each_week_and_fetches_the_one_of_the_peer() {
        use crate::client::DeadWork;
        use umbra_core::session::node::{ContactId, StateChange};
        use umbra_crypto::{dead::DeadChannel, kem::KeyPair, secret::Secret};

        let mut rng = Rng(131);
        let mut client = new_client(&mut rng);
        // A stored contact: the version, the pairwise salt, and the key of
        // the peer lead its form.
        let salt = [5u8; 16];
        let peer = KeyPair::from_seeds(Secret::new([6; 32]), Secret::new([6; 64]));
        let state = [&[0x02u8][..], &salt, &peer.x25519_public(), &[0; 8]].concat();
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(state),
        };
        client
            .commit_network(&[change], &[], 1_000_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&contact.0).unwrap();
        assert_eq!(client.contact_id_of(conversation).unwrap(), contact.0);
        let own = client.root_identity().unwrap().pairwise_identity(&salt);
        let secret = DeadChannel::new(&own, &peer.x25519_public()).unwrap();
        let (own_pk, peer_pk) = (own.x25519_public(), peer.x25519_public());
        let epoch = 168 * 3_000;
        let now = 1_800_000_000;

        // NET-203: no root gives no week, and a live channel gives no work.
        assert!(client
            .dead_channel_work(now, 0, &[], &mut rng)
            .unwrap()
            .is_empty());
        assert!(client
            .dead_channel_work(now, epoch, &[], &mut rng)
            .unwrap()
            .is_empty());

        // NET-182: a dead channel with no new queue asks for one, and its
        // fetch takes a time in the next 24 hours.
        client.channel_dead(conversation, now, &mut rng).unwrap();
        let work = client.dead_channel_work(now, epoch, &[], &mut rng).unwrap();
        assert!(matches!(work[..], [DeadWork::Rotate { contact: id }] if id == contact.0));

        // NET-183: the new queue goes into the blob of the week.
        let mut real = vec![0u8; umbra_wire::address::LEN];
        umbra_wire::address::QueueAddress {
            relay_id: [1; 32],
            sender_id: [2; 32],
            qs_auth_sk: Secret::new([3; 32]),
            qe: Secret::new([4; 32]),
        }
        .encode(&mut real)
        .unwrap();
        client
            .dead_queue_rotated(conversation, &real, &mut rng)
            .unwrap();
        let work = client.dead_channel_work(now, epoch, &[], &mut rng).unwrap();
        let [DeadWork::Write {
            week,
            handle,
            chunk,
            ..
        }] = &work[..]
        else {
            panic!("one write");
        };
        assert_eq!((*week, *handle), (3_000, secret.handle(&own_pk, 3_000)));
        let opened =
            umbra_core::session::dead::open_blob(&secret.blob_key(&own_pk, 3_000), chunk).unwrap();
        assert_eq!(*opened, real);

        // NET-187, NET-188: a day later the fetch of the two weeks is due,
        // once in the week.
        let work = client
            .dead_channel_work(now + 86_400, epoch, &[], &mut rng)
            .unwrap();
        let reads: Vec<[u8; 32]> = work
            .iter()
            .filter_map(|step| match step {
                DeadWork::Read { handle, .. } => Some(*handle),
                _ => None,
            })
            .collect();
        assert_eq!(
            reads,
            [
                secret.handle(&peer_pk, 3_000),
                secret.handle(&peer_pk, 2_999)
            ]
        );
        let again = client
            .dead_channel_work(now + 2 * 86_400, epoch, &[], &mut rng)
            .unwrap();
        assert!(!again
            .iter()
            .any(|step| matches!(step, DeadWork::Read { .. })));

        // NET-184, NET-185: the blob of the week is there, the next week
        // writes a new one, and the one before it goes.
        let erase = client
            .dead_blob_written(
                conversation,
                3_000,
                Secret::new([8; 32]),
                vec![[1; 32], [2; 32]],
                &mut rng,
            )
            .unwrap();
        assert!(erase.is_none());
        let work = client
            .dead_channel_work(now + 3 * 86_400, epoch, &[], &mut rng)
            .unwrap();
        assert!(!work
            .iter()
            .any(|step| matches!(step, DeadWork::Write { .. })));
        let work = client
            .dead_channel_work(now + 7 * 86_400, epoch + 168, &[], &mut rng)
            .unwrap();
        assert!(work
            .iter()
            .any(|step| matches!(step, DeadWork::Write { week: 3_001, .. })));
        let erase = client
            .dead_blob_written(
                conversation,
                3_001,
                Secret::new([9; 32]),
                vec![[3; 32], [4; 32]],
                &mut rng,
            )
            .unwrap();
        assert!(matches!(
            erase,
            Some(DeadWork::Erase { handle, ref relays, .. })
                if handle == secret.handle(&own_pk, 3_000) && *relays == [[1; 32], [2; 32]]
        ));

        // NET-190: the peer moved, the channel lives, and the last blob goes.
        let erase = client.dead_channel_ended(conversation, &mut rng).unwrap();
        assert!(
            matches!(erase, Some(DeadWork::Erase { handle, .. }) if handle == secret.handle(&own_pk, 3_001))
        );
        assert!(client
            .dead_channel_work(now + 8 * 86_400, epoch + 168, &[], &mut rng)
            .unwrap()
            .is_empty());

        // NET-186, NET-193: a record with no receipt for seven days makes the
        // channel silent, and it goes to the send path again.
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("are you there")).unwrap();
        let message = client
            .send_draft(draft, (now + 8 * 86_400) * 1_000, &mut rng)
            .unwrap();
        while client.take_outgoing().is_some() {}
        client
            .set_delivery(&message, Delivery::Accepted, &mut rng)
            .unwrap();
        let later_ms = (now + 16 * 86_400) * 1_000;
        assert!(client
            .silent_conversations(later_ms - 2 * 86_400 * 1_000)
            .unwrap()
            .is_empty());
        assert_eq!(
            client.silent_conversations(later_ms).unwrap(),
            [conversation]
        );
        client.resend_unreceipted(conversation).unwrap();
        let again = client.take_outgoing().unwrap();
        assert_eq!(again.message, message);
        assert!(client.take_outgoing().is_none());
    }

    #[test]
    fn a_new_store_holds_a_recovery_code_that_leaves_as_digits_alone() {
        use umbra_core::identity::recovery::{from_digits, DigitsType};
        let mut rng = Rng(141);
        let mut client = new_client(&mut rng);
        let mut view = View::default();
        client.render_recovery_code(&mut view, &mut rng).unwrap();
        let text = String::from_utf16(&view.0).unwrap();
        // IDN-149: 87 digits in groups of five, and no hexadecimal form.
        assert_eq!(text.chars().filter(char::is_ascii_digit).count(), 87);
        assert_eq!(text.split(' ').count(), 18);
        let code = from_digits(&text, DigitsType::Code).unwrap();
        // The code lives through a lock, and it is the same code.
        client.lock();
        client.unlock(&units("correct horse"), 1_100).unwrap();
        let mut again = View::default();
        client.render_recovery_code(&mut again, &mut rng).unwrap();
        assert_eq!(again.0, view.0);
        assert_eq!(
            *client.recovery_code(&mut rng).unwrap().bytes().expose(),
            code.as_slice()
        );
        // A second store draws a code of its own.
        let mut other = View::default();
        new_client(&mut Rng(142))
            .render_recovery_code(&mut other, &mut rng)
            .unwrap();
        assert_ne!(other.0, view.0);
    }

    #[test]
    fn a_backup_writes_a_full_object_and_then_deltas_of_what_changed() {
        use crate::client::BackupUpload;
        use umbra_core::{
            attach::{
                segment::unpad_handle_object,
                transfer::{ChunkCredential, Uploaded},
                CHUNK_SIZE,
            },
            identity::{
                backup::{BackupObject, BackupRow},
                recovery::BackupRoot,
            },
            session::node::{ContactId, StateChange},
            store::record::TableId,
        };
        use umbra_crypto::secret::Secret;
        use umbra_wire::{
            descriptor::{ChunkRef, FileDescriptor, Level},
            ndr::TokenCarrier,
        };

        let uploaded = |tag: u8| Uploaded {
            descriptor: FileDescriptor {
                level: Level::Data,
                file_key: Secret::new([tag; 32]),
                file_nonce: [2; 24],
                commit: [3; 32],
                digest: [4; 32],
                media_seconds: 0,
                padded_size: CHUNK_SIZE as u32,
                mime_class: 0,
                pixel_w: 0,
                pixel_h: 0,
                refs: vec![ChunkRef {
                    relay_id: [5; 32],
                    chunk_id: [tag; 32],
                    cred_pk: [7; 32],
                    replicas: [[0; 12]; 2],
                }],
            },
            credentials: vec![ChunkCredential {
                chunk_id: [tag; 32],
                cred: Secret::new([8; 32]),
                relays: vec![[5; 32], [9; 32]],
            }],
        };
        let tables = |object: &BackupObject, table: TableId| {
            object
                .rows
                .iter()
                .filter(|row| {
                    matches!(row, BackupRow::Put { table: held, .. } | BackupRow::Delete { table: held, .. } if *held == table)
                })
                .count()
        };

        let mut rng = Rng(151);
        let mut client = new_client(&mut rng);
        client
            .set_push_token(Some((TokenCarrier::Fcm, "a-token")), &mut rng)
            .unwrap();
        let now = 1_800_000_000;
        let epoch = 168 * 3_000;

        // IDN-080: a write runs in the foreground only.
        assert!(client.backup_due(now, false).unwrap().is_none());
        let BackupUpload { plain, pending } = client.backup_due(now, true).unwrap().unwrap();
        assert!(pending.is_full());
        let full = BackupObject::parse(&plain).unwrap();
        // The root seed and the recovery code go, and the push token of this
        // device stays (IDN-180).
        assert_eq!(tables(&full, TableId::LOCAL_IDENTITY), 2);
        assert_eq!(tables(&full, TableId(0x0A)), 0);
        let root = client
            .backup_uploaded(pending, &uploaded(1), epoch, &mut rng)
            .unwrap();
        assert!(root.erase.is_empty());

        // IDN-093, IDN-094: the root is the chunk of the week, and it opens
        // under the key of that week alone.
        let credentials = client.backup_credentials(3_000, &mut rng).unwrap();
        assert_eq!(root.handle, credentials.handle);
        let mut buf = Vec::new();
        let sealed = unpad_handle_object(&root.chunk).unwrap();
        let opened = BackupRoot::open(&credentials, sealed, &mut buf).unwrap();
        assert_eq!(opened.entries.len(), 1);
        assert_eq!(opened.entries[0].kind, 0x01);
        let other = client.backup_credentials(3_001, &mut rng).unwrap();
        assert_ne!(other.handle, credentials.handle);
        assert!(BackupRoot::open(&other, sealed, &mut Vec::new()).is_err());

        // IDN-081: no write is due right after one.
        assert!(client.backup_due(now + 60, true).unwrap().is_none());
        // IDN-185: a new install writes its next delta inside 1.5 times
        // BACKUP_EARLY_INTERVAL, not a day later.
        let early = client.backup_due(now + 45 * 60 + 1, true).unwrap().unwrap();
        assert!(!early.pending.is_full());

        // A new contact and a message: the delta holds them and nothing
        // that did not change (IDN-179).
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(vec![1, 2, 3]),
        };
        client
            .commit_network(&[change], &[], (now + 100) * 1_000, &mut rng)
            .unwrap();
        let later = now + 2 * 86_400;
        let BackupUpload { plain, pending } = client.backup_due(later, true).unwrap().unwrap();
        assert!(!pending.is_full());
        let delta = BackupObject::parse(&plain).unwrap();
        assert_eq!(delta.base_at, now);
        assert_eq!(tables(&delta, TableId::CONTACT), 1);
        assert_eq!(tables(&delta, TableId::LOCAL_IDENTITY), 0);
        let root = client
            .backup_uploaded(pending, &uploaded(2), epoch, &mut rng)
            .unwrap();
        let sealed = unpad_handle_object(&root.chunk).unwrap();
        let opened = BackupRoot::open(&credentials, sealed, &mut buf).unwrap();
        assert_eq!(
            opened
                .entries
                .iter()
                .map(|entry| entry.kind)
                .collect::<Vec<_>>(),
            [0x01, 0x02]
        );
        // After BACKUP_EARLY_WINDOW the delta clock is BACKUP_INTERVAL again.
        assert!(client
            .backup_due(later + 11 * 3_600, true)
            .unwrap()
            .is_none());

        // IDN-078, IDN-099: after BACKUP_FULL_INTERVAL a full object replaces
        // each entry, and the chunks of the two old objects go after the
        // new root.
        let month = now + 46 * 86_400;
        let BackupUpload { pending, .. } = client.backup_due(month, true).unwrap().unwrap();
        assert!(pending.is_full());
        let root = client
            .backup_uploaded(pending, &uploaded(3), epoch + 168 * 7, &mut rng)
            .unwrap();
        let erased: Vec<[u8; 32]> = root
            .erase
            .iter()
            .map(|credential| credential.chunk_id)
            .collect();
        assert_eq!(erased, [[1; 32], [2; 32]]);
        assert_eq!(
            root.handle,
            client.backup_credentials(3_007, &mut rng).unwrap().handle
        );
    }

    #[test]
    fn a_new_store_under_the_restored_seed_holds_each_row_of_the_backup() {
        use crate::client::{BackupUpload, RestoredBackup};
        use umbra_core::{
            attach::{
                transfer::{ChunkCredential, Uploaded},
                CHUNK_SIZE,
            },
            session::node::{ContactId, StateChange},
        };
        use umbra_crypto::{secret::Secret, zeroize::Zeroizing};
        use umbra_wire::descriptor::{ChunkRef, FileDescriptor, Level};

        let uploaded = || Uploaded {
            descriptor: FileDescriptor {
                level: Level::Data,
                file_key: Secret::new([1; 32]),
                file_nonce: [2; 24],
                commit: [3; 32],
                digest: [4; 32],
                media_seconds: 0,
                padded_size: CHUNK_SIZE as u32,
                mime_class: 0,
                pixel_w: 0,
                pixel_h: 0,
                refs: vec![ChunkRef {
                    relay_id: [5; 32],
                    chunk_id: [6; 32],
                    cred_pk: [7; 32],
                    replicas: [[0; 12]; 2],
                }],
            },
            credentials: vec![ChunkCredential {
                chunk_id: [6; 32],
                cred: Secret::new([8; 32]),
                relays: vec![[5; 32], [9; 32]],
            }],
        };
        let messages_of = |client: &Client<MemoryBackend, Element>, conversation| {
            client
                .messages(conversation)
                .unwrap()
                .iter()
                .map(|message| {
                    let mut view = View::default();
                    client.render(message, &mut view).unwrap();
                    String::from_utf16(&view.0).unwrap()
                })
                .collect::<Vec<_>>()
        };

        let mut rng = Rng(161);
        let mut alice = new_client(&mut rng);
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(vec![0x04, 2, 3]),
        };
        let now = 1_800_000_000;
        alice
            .commit_network(&[change], &[], now * 1_000, &mut rng)
            .unwrap();
        let conversation = alice.conversation_for(&contact.0).unwrap();
        let send =
            |client: &mut Client<MemoryBackend, Element>, words: &str, at: u64, rng: &mut Rng| {
                let mut draft = client.new_draft(conversation);
                draft.set_text(&units(words)).unwrap();
                client.send_draft(draft, at * 1_000, rng).unwrap();
                while client.take_outgoing().is_some() {}
            };
        send(&mut alice, "before the full object", now, &mut rng);
        let BackupUpload {
            plain: full,
            pending,
        } = alice.backup_due(now + 10, true).unwrap().unwrap();
        alice
            .backup_uploaded(pending, &uploaded(), 168 * 3_000, &mut rng)
            .unwrap();
        send(&mut alice, "in the delta", now + 100, &mut rng);
        let BackupUpload {
            plain: delta,
            pending,
        } = alice.backup_due(now + 2 * 86_400, true).unwrap().unwrap();
        assert!(!pending.is_full());

        // IDN-102: a delta alone is no backup.
        assert!(RestoredBackup::assemble(std::slice::from_ref(&delta)).is_err());
        let restored = RestoredBackup::assemble(&[full, delta]).unwrap();
        assert_eq!(restored.contact_count(), 1);

        // The store of the new device comes from the restored seed.
        let mut bob = Client::create_with_seed(
            MemoryBackend::default(),
            Element([2; 32]),
            &units("a new phrase"),
            CHEAP,
            now + 3 * 86_400,
            restored.seed(),
            &mut Rng(162),
        )
        .unwrap();
        bob.apply_restore(&restored, &mut rng).unwrap();
        assert_eq!(bob.conversation_for(&contact.0).unwrap(), conversation);
        assert_eq!(
            messages_of(&bob, conversation),
            messages_of(&alice, conversation)
        );
        assert_eq!(
            messages_of(&bob, conversation),
            ["before the full object", "in the delta"]
        );
        let (mut code_a, mut code_b) = (View::default(), View::default());
        alice.render_recovery_code(&mut code_a, &mut rng).unwrap();
        bob.render_recovery_code(&mut code_b, &mut rng).unwrap();
        assert_eq!(code_a.0, code_b.0);

        // IDN-183: the contact waits for its renewal, across each run.
        assert_eq!(bob.restored_stale().unwrap(), [contact.0]);
        bob.restored_renewed(&contact.0, &mut rng).unwrap();
        assert!(bob.restored_stale().unwrap().is_empty());

        // IDN-155: a backup with no root seed recovered no identity.
        let empty = umbra_core::identity::backup::BackupObject {
            kind: umbra_core::identity::backup::KIND_FULL,
            written_at: now,
            base_at: 0,
            rows: Vec::new(),
        }
        .encode()
        .unwrap();
        assert!(matches!(
            RestoredBackup::assemble(&[Zeroizing::new(empty.to_vec())]),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn a_handle_group_rotates_after_seven_days_and_its_old_handle_leaves() {
        use umbra_core::notify::{ndr::Ndr, ROTATE_INTERVAL};
        use umbra_crypto::secret::Secret;
        use umbra_wire::ndr::{NdrRequest, NdrResponse, TokenCarrier, BLOB_LEN, NDR_REQUEST_LEN};
        let mut rng = Rng(93);
        let mut client = new_client(&mut rng);
        let queues: Vec<([u8; 32], [u8; 32])> = (0..3u8).map(|i| ([i; 32], [0xA1; 32])).collect();
        client
            .set_push_token(Some((TokenCarrier::Fcm, "fcm-token")), &mut rng)
            .unwrap();
        let t0 = 1_800_000_000;
        client.queues_to_bind(&queues, t0, &mut rng).unwrap();
        for queue in &queues {
            client.queue_bound(&queue.0, &mut rng).unwrap();
        }
        let mut ndr = Ndr::default();
        for call in client.ndr_calls_due(&mut rng).unwrap() {
            assert_eq!(ndr.handle(&call.request[..]).0, NdrResponse::Taken);
            client.ndr_call_taken(&call, &mut rng).unwrap();
        }
        let before = client.binding_of(&[0; 32]).unwrap().unwrap();

        // NTF-007: nothing is due inside 7 days.
        assert!(!client.rotate_one_group(t0 + 60, &mut rng).unwrap());
        assert!(!client
            .rotate_one_group(t0 + ROTATE_INTERVAL - 1, &mut rng)
            .unwrap());
        assert!(client
            .rotate_one_group(t0 + ROTATE_INTERVAL, &mut rng)
            .unwrap());
        // The queues bind again under the new triple and root.
        let unbound = client
            .queues_to_bind(&queues, t0 + ROTATE_INTERVAL, &mut rng)
            .unwrap();
        assert_eq!(unbound.len(), 3);
        let after = client.binding_of(&[0; 32]).unwrap().unwrap();
        assert_ne!(after.handle, before.handle);
        assert_ne!(after.k_tok.expose(), before.k_tok.expose());
        assert_ne!(after.root.expose(), before.root.expose());
        assert_eq!(after.queue_alias, before.queue_alias);

        // The new handle registers and the old one leaves the NDR.
        let calls = client.ndr_calls_due(&mut rng).unwrap();
        assert_eq!(calls.len(), 2);
        for call in &calls {
            assert_eq!(ndr.handle(&call.request[..]).0, NdrResponse::Taken);
            client.ndr_call_taken(call, &mut rng).unwrap();
        }
        assert!(client.ndr_calls_due(&mut rng).unwrap().is_empty());
        let push = |binding: &umbra_core::notify::binding::Binding| {
            let mut out = [0u8; NDR_REQUEST_LEN];
            NdrRequest::Push {
                handle: binding.handle,
                k_tok: Secret::new(*binding.k_tok.expose()),
                ttl: 60,
                blob: [0; BLOB_LEN],
            }
            .encode(&mut out)
            .unwrap();
            out
        };
        assert_eq!(ndr.handle(&push(&before)).0, NdrResponse::Refused);
        assert_eq!(ndr.handle(&push(&after)).0, NdrResponse::Taken);
        assert_eq!(ndr.len(), 1);
    }

    /// Puts `other` into the group of `client` with the add, the admit and
    /// the snapshot of §11.9.1, and gives its conversation there.
    fn join_group(
        client: &mut Client<MemoryBackend, Element>,
        other: &mut Client<MemoryBackend, Element>,
        conversation: ConversationId,
        rng: &mut Rng,
    ) -> ConversationId {
        use umbra_core::group::join::{accept_admit, JoinKeys};
        use umbra_wire::group::control::{
            GroupControl, GroupInvitation, JoinRecord, RosterSnapshot,
        };
        let now = 1_700_000_002;
        let mut group = client.group_of(conversation).unwrap();
        // The offer of stage 0x01 carries this key to the joiner.
        let creator_pk = group
            .roster()
            .member(0)
            .and_then(|creator| creator.roster_pk.clone())
            .unwrap();
        let joiner = JoinKeys::make(rng).unwrap();
        let kem_pk = joiner.keys.kem().public().to_bytes();
        let add = group
            .add_object(&JoinRecord {
                group_id: *group.group_id(),
                keys: joiner.wire_keys(&kem_pk),
            })
            .unwrap();
        let control = GroupControl::parse(&add).unwrap();
        let add_hash = control.epoch_hash();
        let umbra_core::group::roster::Applied::Added(index) =
            group.apply_control(&control, 0, now).unwrap()
        else {
            panic!("the add added nobody");
        };
        let admit = group.admit_for(index, 0, b"", now).unwrap();
        let admit_control = GroupControl::parse(&admit).unwrap();
        let invitation = GroupInvitation::parse(admit_control.payload).unwrap();
        let path = client.authority_path(conversation, &group).unwrap();
        let snapshot_bytes = group.snapshot(&path).unwrap();
        let snapshot = RosterSnapshot::parse(&snapshot_bytes).unwrap();
        let admitted = accept_admit(&invitation, &snapshot, &add_hash, &creator_pk, now).unwrap();
        client.save_group(conversation, &group, rng).unwrap();
        other
            .adopt_group(admitted, &joiner.seed, "Trail", false, rng)
            .unwrap()
    }

    /// Brings `joiner` into a new group of `admin` through the pairwise
    /// channel of §11.9.1, and returns the group at the admin, the group at
    /// the joiner, and the two pairwise conversations.
    fn group_of_two(
        admin: &mut Client<MemoryBackend, Element>,
        joiner: &mut Client<MemoryBackend, Element>,
        rng: &mut Rng,
    ) -> (
        ConversationId,
        ConversationId,
        ConversationId,
        ConversationId,
    ) {
        let peer_at_admin = ContactId([0x51; 32]);
        let peer_at_joiner = ContactId([0x52; 32]);
        let pair_at_admin = admin.conversation_for(&peer_at_admin.0).unwrap();
        let pair_at_joiner = joiner.conversation_for(&peer_at_joiner.0).unwrap();
        let relays = [[0xA1; 32], [0xB2; 32]];
        let group = admin
            .create_group("Summit", relays, 1_700_000_000, rng)
            .unwrap();
        let group_id = admin.group_info(group).unwrap().group_id;
        admin
            .group_queue_made(&group_id, 0, relays[0], [0xC3; 32], rng)
            .unwrap();
        admin
            .group_queue_made(&group_id, 1, relays[1], [0xD4; 32], rng)
            .unwrap();
        admin
            .offer_group(group, pair_at_admin, 1_700_000_001_000, rng)
            .unwrap();
        let offer = admin.take_outgoing().unwrap();
        deliver(joiner, &peer_at_joiner, &offer.app, 1_700_000_001_500, rng);
        let held = joiner.group_offers().unwrap();
        joiner
            .accept_group_offer(&held[0], 1_700_000_002_000, rng)
            .unwrap();
        let asked = joiner.take_outgoing().unwrap();
        deliver(admin, &peer_at_admin, &asked.app, 1_700_000_002_500, rng);
        let joiners = admin.group_joiners().unwrap();
        let admission = admin
            .add_joiner(&joiners[0], 1_700_000_003_000, rng)
            .unwrap();
        while admin.take_group_post().is_some() {}
        admin
            .admit_joiner(
                &joiners[0],
                admission.index,
                b"a descriptor",
                1_700_000_004_000,
                rng,
            )
            .unwrap();
        let admit = admin.take_outgoing().unwrap();
        deliver(joiner, &peer_at_joiner, &admit.app, 1_700_000_004_500, rng);
        let member = joiner
            .accept_group_admit(
                pair_at_joiner,
                &group_id,
                &admission.snapshot,
                1_700_000_005,
                rng,
            )
            .unwrap();
        while admin.next_event().is_some() {}
        while joiner.next_event().is_some() {}
        (group, member, pair_at_admin, pair_at_joiner)
    }

    #[test]
    fn a_member_whose_index_a_rival_took_comes_back_through_an_admin() {
        use umbra_core::group::join::JoinKeys;
        use umbra_wire::group::control::GroupControl;

        let mut rng = Rng(61);
        let mut admin = new_client(&mut rng);
        let mut joiner = new_client(&mut rng);
        let (group, member, pair_at_admin, pair_at_joiner) =
            group_of_two(&mut admin, &mut joiner, &mut rng);
        let peer_at_admin = ContactId([0x51; 32]);
        let peer_at_joiner = ContactId([0x52; 32]);
        let group_id = admin.group_info(group).unwrap().group_id;
        assert_eq!(joiner.group_info(member).unwrap().own_index, 1);
        assert_eq!(joiner.return_state(member).unwrap(), (false, false));

        // The member re-keys, and a removed device of it posts a rival with
        // a lower hash.
        let mut rival = joiner.group_of(member).unwrap();
        let mut reader = joiner.group_of(member).unwrap();
        joiner.rekey_groups(1_700_000_010_000, &mut rng).unwrap();
        let first = joiner.take_group_post().unwrap();
        let umbra_core::group::receive::Outcome::Content { app, .. } =
            reader.receive(&first.record, 1_700_000_011).unwrap()
        else {
            panic!("the reader got no re-key");
        };
        let body = umbra_wire::app::AppMessage::parse(&app, umbra_wire::app::Channel::Group)
            .unwrap()
            .body
            .to_vec();
        let hash = GroupControl::parse(&body).unwrap().epoch_hash();
        let rival_object = loop {
            let keys = JoinKeys::make(&mut rng).unwrap();
            let made = rival.rekey_object(&keys, &mut rng).unwrap();
            if GroupControl::parse(&made).unwrap().epoch_hash() < hash {
                break made;
            }
        };
        let second = rival
            .post(&control_app(&rival_object), 1_700_000_012, &mut rng)
            .unwrap();
        for record in [&first.record, &second] {
            admin
                .on_group_record(&[0xC3; 32], 1, record, 1_700_000_013_000, &mut rng)
                .unwrap();
        }
        let rival_index = admin
            .group_of(group)
            .unwrap()
            .roster()
            .successor_of(1)
            .unwrap();
        assert_eq!(rival_index, 2);

        // GRP-370: the member reads the rival, goes back, and asks the admin
        // that brought it in on the pairwise channel.
        joiner
            .on_group_record(&[0xC3; 32], 2, &second, 1_700_000_014_000, &mut rng)
            .unwrap();
        assert_eq!(joiner.group_info(member).unwrap().own_index, 1);
        assert_eq!(joiner.return_state(member).unwrap(), (true, false));
        let ask = joiner.take_outgoing().unwrap();
        assert_eq!(ask.conversation, pair_at_joiner);
        // A second record asks nothing again.
        joiner
            .on_group_record(&[0xC3; 32], 3, &second, 1_700_000_014_500, &mut rng)
            .unwrap();
        assert!(joiner.take_outgoing().is_none());

        // GRP-371: the admin removes the index of the rival with a rotation,
        // and lists the member as a joiner with its new keys.
        deliver(
            &mut admin,
            &peer_at_admin,
            &ask.app,
            1_700_000_015_000,
            &mut rng,
        );
        assert_eq!(
            admin.next_event(),
            Some(Event::GroupJoiner {
                from: pair_at_admin
            })
        );
        let roster = admin.group_of(group).unwrap();
        assert!(!roster.roster().member(rival_index).unwrap().active);
        assert_eq!(admin.group_info(group).unwrap().members, 1);
        let mut moved = Vec::new();
        while let Some(post) = admin.take_group_post() {
            moved.push(post.record);
        }
        assert!(moved.len() >= 2, "a removal and a rotation");
        let joiners = admin.group_joiners().unwrap();
        assert_eq!(joiners.len(), 1);
        let admission = admin
            .add_joiner(&joiners[0], 1_700_000_016_000, &mut rng)
            .unwrap();
        assert_eq!(admission.index, 3);
        while admin.take_group_post().is_some() {}
        admin
            .admit_joiner(
                &joiners[0],
                admission.index,
                b"a descriptor",
                1_700_000_017_000,
                &mut rng,
            )
            .unwrap();
        let admit = admin.take_outgoing().unwrap();
        deliver(
            &mut joiner,
            &peer_at_joiner,
            &admit.app,
            1_700_000_017_500,
            &mut rng,
        );
        assert_eq!(
            joiner.next_event(),
            Some(Event::GroupAdmit {
                from: pair_at_joiner
            })
        );

        // The admit brings the member back into the conversation it held,
        // under the new index and the keys it sent.
        let back = joiner
            .accept_group_admit(
                pair_at_joiner,
                &group_id,
                &admission.snapshot,
                1_700_000_018,
                &mut rng,
            )
            .unwrap();
        assert_eq!(back, member);
        let info = joiner.group_info(member).unwrap();
        assert_eq!((info.own_index, info.members), (3, 2));
        assert_eq!(joiner.return_state(member).unwrap(), (false, false));
        joiner.lock();
        joiner
            .unlock(&units("correct horse"), 1_700_000_019)
            .unwrap();
        assert_eq!(joiner.group_info(member).unwrap().own_index, 3);

        // A message of the admin reaches the member again.
        let mut draft = admin.new_draft(group);
        draft.set_text(&units("welcome back")).unwrap();
        admin
            .send_draft(draft, 1_700_000_020_000, &mut rng)
            .unwrap();
        let post = admin.take_group_post().unwrap();
        assert!(joiner
            .on_group_record(&[0xC3; 32], 9, &post.record, 1_700_000_020_500, &mut rng)
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_displaced_rekey_goes_again_against_the_new_head() {
        use umbra_wire::group::control::Role;

        let mut rng = Rng(71);
        let mut admin = new_client(&mut rng);
        let mut joiner = new_client(&mut rng);
        let (group, member, _, _) = group_of_two(&mut admin, &mut joiner, &mut rng);

        // The member re-keys, and the owner grants it a role at the same
        // predecessor before it read the re-key.
        joiner.rekey_groups(1_700_000_010_000, &mut rng).unwrap();
        let rekey = joiner.take_group_post().unwrap();
        admin
            .set_group_role(group, 1, Role::Moderator, 1_700_000_010_500, &mut rng)
            .unwrap();
        let grant = admin.take_group_post().unwrap();
        while admin.take_group_post().is_some() {}

        // GRP-117: the owner comes first, and the admin keeps its grant.
        admin
            .on_group_record(&[0xC3; 32], 1, &rekey.record, 1_700_000_011_000, &mut rng)
            .unwrap();
        assert_eq!(admin.group_info(group).unwrap().members, 2);
        assert!(
            admin
                .group_of(group)
                .unwrap()
                .roster()
                .member(1)
                .unwrap()
                .active
        );

        // GRP-119: the member goes back, and it re-keys again against the
        // grant.
        joiner
            .on_group_record(&[0xC3; 32], 2, &grant.record, 1_700_000_012_000, &mut rng)
            .unwrap();
        let again = joiner.take_group_post().unwrap();
        assert_ne!(again.record, rekey.record);
        assert_eq!(joiner.group_info(member).unwrap().own_index, 2);
        admin
            .on_group_record(&[0xC3; 32], 3, &again.record, 1_700_000_013_000, &mut rng)
            .unwrap();
        let held = admin.group_of(group).unwrap();
        assert_eq!(held.roster().successor_of(1), Some(2));
        // The re-key keeps the role that the grant gave the old index.
        assert_eq!(held.roster().member(2).unwrap().role, Role::Moderator);
        assert_eq!(
            held.roster().chain_hash(),
            joiner.group_of(member).unwrap().roster().chain_hash()
        );
    }

    #[test]
    fn a_joiner_whose_admitted_add_lost_the_fork_joins_again() {
        use umbra_wire::group::control::Role;

        let mut rng = Rng(73);
        let mut owner = new_client(&mut rng);
        let mut admin = new_client(&mut rng);
        let mut joiner = new_client(&mut rng);
        let (group, at_admin, _, _) = group_of_two(&mut owner, &mut admin, &mut rng);
        let group_id = owner.group_info(group).unwrap().group_id;
        owner
            .set_group_role(group, 1, Role::Admin, 1_700_000_010_000, &mut rng)
            .unwrap();
        let grant = owner.take_group_post().unwrap();
        while owner.take_group_post().is_some() {}
        admin
            .on_group_record(&[0xC3; 32], 1, &grant.record, 1_700_000_010_500, &mut rng)
            .unwrap();
        while admin.take_group_post().is_some() {}

        // The admin brings the joiner in on a pairwise channel of its own.
        let joiner_at_admin = ContactId([0x61; 32]);
        let admin_at_joiner = ContactId([0x62; 32]);
        let pair_at_admin = admin.conversation_for(&joiner_at_admin.0).unwrap();
        let pair_at_joiner = joiner.conversation_for(&admin_at_joiner.0).unwrap();
        admin
            .offer_group(at_admin, pair_at_admin, 1_700_000_011_000, &mut rng)
            .unwrap();
        let offer = admin.take_outgoing().unwrap();
        deliver(&mut joiner, &admin_at_joiner, &offer.app, 1_700_000_011_500, &mut rng);
        let offers = joiner.group_offers().unwrap();
        joiner
            .accept_group_offer(&offers[0], 1_700_000_012_000, &mut rng)
            .unwrap();
        let asked = joiner.take_outgoing().unwrap();
        deliver(&mut admin, &joiner_at_admin, &asked.app, 1_700_000_012_500, &mut rng);
        let joiners = admin.group_joiners().unwrap();
        let first = admin
            .add_joiner(&joiners[0], 1_700_000_013_000, &mut rng)
            .unwrap();
        let add = admin.take_group_post().unwrap();
        while admin.take_group_post().is_some() {}
        admin
            .admit_joiner(&joiners[0], first.index, b"one", 1_700_000_013_500, &mut rng)
            .unwrap();
        let admit = admin.take_outgoing().unwrap();
        deliver(&mut joiner, &admin_at_joiner, &admit.app, 1_700_000_014_000, &mut rng);
        let joined = joiner
            .accept_group_admit(pair_at_joiner, &group_id, &first.snapshot, 1_700_000_014, &mut rng)
            .unwrap();

        // The owner grants a role at the predecessor of the add, and its
        // epoch comes first (GRP-117).
        owner
            .set_group_role(group, 1, Role::Owner, 1_700_000_013_200, &mut rng)
            .unwrap();
        let rival = owner.take_group_post().unwrap();
        while owner.take_group_post().is_some() {}
        owner
            .on_group_record(&[0xC3; 32], 2, &add.record, 1_700_000_014_500, &mut rng)
            .unwrap();
        admin
            .on_group_record(&[0xC3; 32], 3, &rival.record, 1_700_000_015_000, &mut rng)
            .unwrap();

        // GRP-420: the admit went out, and the joiner waits in the list of
        // joiners again. The admin adds it under the new head and admits it
        // again.
        let joiners = admin.group_joiners().unwrap();
        assert_eq!(joiners.len(), 1);
        assert!(!joiners[0].is_added);
        let second = admin
            .add_joiner(&joiners[0], 1_700_000_016_000, &mut rng)
            .unwrap();
        assert_ne!(second.snapshot, first.snapshot);
        let again = admin.take_group_post().unwrap();
        while admin.take_group_post().is_some() {}
        owner
            .on_group_record(&[0xC3; 32], 4, &again.record, 1_700_000_016_500, &mut rng)
            .unwrap();
        admin
            .admit_joiner(&joiners[0], second.index, b"two", 1_700_000_017_000, &mut rng)
            .unwrap();
        let admit = admin.take_outgoing().unwrap();
        deliver(&mut joiner, &admin_at_joiner, &admit.app, 1_700_000_017_500, &mut rng);
        assert_eq!(joiner.group_admits().unwrap().len(), 1);
        let rejoined = joiner
            .accept_group_admit(pair_at_joiner, &group_id, &second.snapshot, 1_700_000_018, &mut rng)
            .unwrap();
        assert_eq!(rejoined, joined);
        assert_eq!(joiner.group_info(joined).unwrap().own_index, second.index);
        let chain = *owner.group_of(group).unwrap().roster().chain_hash();
        assert_eq!(*admin.group_of(at_admin).unwrap().roster().chain_hash(), chain);
        assert_eq!(*joiner.group_of(joined).unwrap().roster().chain_hash(), chain);
    }

    #[test]
    fn an_offer_a_join_record_an_add_and_an_admit_bring_a_member_in() {
        let mut rng = Rng(41);
        let mut admin = new_client(&mut rng);
        let mut joiner = new_client(&mut rng);
        // The two hold a pairwise conversation of each other already.
        let peer_at_admin = ContactId([0x51; 32]);
        let peer_at_joiner = ContactId([0x52; 32]);
        let pair_at_admin = admin.conversation_for(&peer_at_admin.0).unwrap();
        let pair_at_joiner = joiner.conversation_for(&peer_at_joiner.0).unwrap();
        let relays = [[0xA1; 32], [0xB2; 32]];
        let group = admin
            .create_group("Summit", relays, 1_700_000_000, &mut rng)
            .unwrap();
        let group_id = admin.group_info(group).unwrap().group_id;
        admin
            .group_queue_made(&group_id, 0, relays[0], [0xC3; 32], &mut rng)
            .unwrap();
        admin
            .group_queue_made(&group_id, 1, relays[1], [0xD4; 32], &mut rng)
            .unwrap();

        // Step 1: the offer goes out on the pairwise channel, and it is no
        // message of that conversation.
        admin
            .offer_group(group, pair_at_admin, 1_700_000_001_000, &mut rng)
            .unwrap();
        let offer = admin.take_outgoing().unwrap();
        assert_eq!(offer.conversation, pair_at_admin);
        assert!(admin.summaries().unwrap().iter().all(|s| s.last.is_none()));
        deliver(
            &mut joiner,
            &peer_at_joiner,
            &offer.app,
            1_700_000_001_500,
            &mut rng,
        );
        assert_eq!(
            joiner.next_event(),
            Some(Event::GroupOffer {
                from: pair_at_joiner
            })
        );
        let held = joiner.group_offers().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].name, "Summit");
        assert_eq!(held[0].group_id, group_id);

        // Step 2: the user accepted, thus the join record goes back.
        joiner
            .accept_group_offer(&held[0], 1_700_000_002_000, &mut rng)
            .unwrap();
        assert!(joiner.group_offers().unwrap().is_empty());
        let asked = joiner.take_outgoing().unwrap();
        deliver(
            &mut admin,
            &peer_at_admin,
            &asked.app,
            1_700_000_002_500,
            &mut rng,
        );
        assert_eq!(
            admin.next_event(),
            Some(Event::GroupJoiner {
                from: pair_at_admin
            })
        );
        let joiners = admin.group_joiners().unwrap();
        assert_eq!(joiners.len(), 1);

        // Step 3: the add goes to each replica as a record with no message.
        let admission = admin
            .add_joiner(&joiners[0], 1_700_000_003_000, &mut rng)
            .unwrap();
        assert_eq!(admission.index, 1);
        assert_eq!(admin.group_info(group).unwrap().members, 2);
        let add = admin.take_group_post().unwrap();
        assert_eq!(add.message, None);
        assert!(admin.take_group_post().is_none());

        // GRP-323: the roster moves after the add, and a second press gives
        // the snapshot of the add, which the joiner verifies against it.
        admin
            .set_group_role(
                group,
                1,
                umbra_wire::group::control::Role::Moderator,
                1_700_000_003_100,
                &mut rng,
            )
            .unwrap();
        // The joiner reads these from the queue after its add.
        let mut moved = Vec::new();
        while let Some(post) = admin.take_group_post() {
            moved.push(post.record);
        }
        let again = admin
            .add_joiner(&joiners[0], 1_700_000_003_200, &mut rng)
            .unwrap();
        assert_eq!(again.index, admission.index);
        assert_eq!(again.snapshot, admission.snapshot);
        assert_eq!(admin.group_info(group).unwrap().members, 2);
        admin
            .set_group_role(
                group,
                1,
                umbra_wire::group::control::Role::Member,
                1_700_000_003_300,
                &mut rng,
            )
            .unwrap();
        while let Some(post) = admin.take_group_post() {
            moved.push(post.record);
        }

        // Step 4: the admit names the snapshot that the chunk path holds.
        admin
            .admit_joiner(
                &joiners[0],
                admission.index,
                b"a descriptor",
                1_700_000_004_000,
                &mut rng,
            )
            .unwrap();
        assert!(admin.group_joiners().unwrap().is_empty());
        let admit = admin.take_outgoing().unwrap();
        deliver(
            &mut joiner,
            &peer_at_joiner,
            &admit.app,
            1_700_000_004_500,
            &mut rng,
        );
        assert_eq!(
            joiner.next_event(),
            Some(Event::GroupAdmit {
                from: pair_at_joiner
            })
        );

        // Step 5: the joiner fetched the snapshot, thus it holds the group.
        let member = joiner
            .accept_group_admit(
                pair_at_joiner,
                &group_id,
                &admission.snapshot,
                1_700_000_005,
                &mut rng,
            )
            .unwrap();
        let info = joiner.group_info(member).unwrap();
        assert_eq!((info.own_index, info.members, info.epoch), (1, 2, 1));
        assert!(info.is_ready);
        assert_eq!(info.group_id, group_id);

        // The two roster objects after the add reach the new member.
        for (seq, record) in moved.iter().enumerate() {
            joiner
                .on_group_record(
                    &[0xC3; 32],
                    u32::try_from(seq).unwrap() + 1,
                    record,
                    1_700_000_005_500,
                    &mut rng,
                )
                .unwrap();
        }
        assert_eq!(joiner.group_info(member).unwrap().members, 2);

        // A message of the admin reaches the new member.
        let mut draft = admin.new_draft(group);
        draft.set_text(&units("we leave at six")).unwrap();
        admin
            .send_draft(draft, 1_700_000_006_000, &mut rng)
            .unwrap();
        let post = admin.take_group_post().unwrap();
        let message = joiner
            .on_group_record(&[0xC3; 32], 9, &post.record, 1_700_000_006_500, &mut rng)
            .unwrap()
            .unwrap();
        let mut view = View::default();
        joiner.render(&message, &mut view).unwrap();
        assert_eq!(String::from_utf16(&view.0).unwrap(), "we leave at six");

        // A second admit of the same group is refused (`GRP-153`).
        assert!(joiner
            .accept_group_admit(
                pair_at_joiner,
                &group_id,
                &admission.snapshot,
                1_700_000_007,
                &mut rng,
            )
            .is_err());
    }

    /// Puts one record of a contact into a client, as the network would.
    fn deliver(
        client: &mut Client<MemoryBackend, Element>,
        from: &ContactId,
        app: &[u8],
        now_ms: u64,
        rng: &mut Rng,
    ) {
        client
            .commit_network(&[], &[(*from, app.to_vec())], now_ms, rng)
            .unwrap();
    }

    #[test]
    fn a_draft_becomes_a_stored_message_and_renders_into_a_sink() {
        let mut rng = Rng(1);
        let mut client = new_client(&mut rng);
        let conversation = ConversationId([7; 16]);

        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("hello 👋")).unwrap();
        let sent = client.send_draft(draft, 1_010_000, &mut rng).unwrap();
        assert!(client
            .send_draft(client.new_draft(conversation), 1_011_000, &mut rng)
            .is_err());

        let outgoing = client.take_outgoing().unwrap();
        assert_eq!(
            (outgoing.message, outgoing.conversation),
            (sent, conversation)
        );
        let mut view = View::default();
        client.render(&sent, &mut view).unwrap();
        assert_eq!(String::from_utf16(&view.0).unwrap(), "hello 👋");

        client
            .set_delivery(&sent, Delivery::Accepted, &mut rng)
            .unwrap();
        assert_eq!(
            client.next_event(),
            Some(Event::Delivery {
                message: sent,
                delivery: Delivery::Accepted
            })
        );

        // The peer runtime hands the same record over. It gives one event.
        let mut peer = new_client(&mut Rng(2));
        let received = peer
            .receive(conversation, &outgoing.app, 1_012_000, &mut rng)
            .unwrap();
        assert_eq!(
            peer.receive(conversation, &outgoing.app, 1_012_000, &mut rng)
                .unwrap(),
            received
        );
        assert_eq!(
            peer.next_event(),
            Some(Event::Message {
                conversation,
                message: received
            })
        );
        assert_eq!(peer.next_event(), None);
        peer.render(&received, &mut view).unwrap();
        assert_eq!(String::from_utf16(&view.0).unwrap(), "hello 👋");
        assert_eq!(peer.messages(conversation).unwrap(), [received]);
        peer.audit().unwrap();
    }

    fn record(kind: umbra_wire::app::AppKind, msg_id: [u8; 16], body: &[u8]) -> Vec<u8> {
        let message = umbra_wire::app::AppMessage {
            kind,
            msg_id,
            sent_at: 0,
            body,
        };
        let mut out = vec![0u8; message.len()];
        message.encode(&mut out).unwrap();
        out
    }

    fn targets_of(due: &DueReceipt, kind: umbra_wire::app::AppKind) -> Vec<[u8; 16]> {
        use umbra_wire::app::{signal::ReceiptBody, AppMessage, Channel};
        let parsed = AppMessage::parse(&due.app, Channel::Pairwise).unwrap();
        assert_eq!(parsed.kind, kind);
        ReceiptBody::parse(parsed.body).unwrap().targets
    }

    #[test]
    fn receipts_wait_in_the_store_and_a_receipt_moves_a_sent_message_up() {
        use umbra_core::session::node::{ContactId, StateChange};
        use umbra_queue::params::{RECEIPT_BATCH_MAX, RECEIPT_MAX_HOLD, RECEIPT_MIN_DELAY};
        use umbra_wire::app::{signal::ReceiptBody, AppKind};

        let mut rng = Rng(5);
        let mut client = new_client(&mut rng);
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(vec![1, 2, 3]),
        };
        client
            .commit_network(&[change], &[], 1_000_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&contact.0).unwrap();
        let text = |id: u8| (contact, record(AppKind::Text, [id; 16], b"hi"));

        // NET-059: a new contact gets no receipt.
        assert_eq!(
            client.receipt_settings(conversation).unwrap(),
            ReceiptSettings::default()
        );
        client
            .commit_network(&[], &[text(1)], 2_000_000, &mut rng)
            .unwrap();
        assert_eq!(client.due_receipt(2_100, &mut rng).unwrap(), None);

        let both = ReceiptSettings {
            delivery: true,
            read: true,
        };
        client
            .set_receipt_settings(conversation, both, &mut rng)
            .unwrap();
        assert_eq!(client.receipt_settings(conversation).unwrap(), both);
        for id in 2..=12 {
            client
                .commit_network(&[], &[text(id)], 3_000_000 + u64::from(id), &mut rng)
                .unwrap();
        }

        // NET-050 and NET-045: the floor, and nine targets in one batch. A
        // batch that did not leave comes again.
        let floor = 3_000 + RECEIPT_MIN_DELAY;
        assert_eq!(client.due_receipt(floor - 1, &mut rng).unwrap(), None);
        let first = client.due_receipt(floor, &mut rng).unwrap().unwrap();
        assert_eq!(first.conversation, conversation);
        let first_targets = targets_of(&first, AppKind::DeliveryReceipt);
        assert_eq!(first_targets.len(), RECEIPT_BATCH_MAX);
        let again = client.due_receipt(floor, &mut rng).unwrap().unwrap();
        assert_eq!(targets_of(&again, AppKind::DeliveryReceipt), first_targets);
        client.receipt_sent(&first).unwrap();
        let second = client.due_receipt(floor, &mut rng).unwrap().unwrap();
        assert_eq!(targets_of(&second, AppKind::DeliveryReceipt).len(), 2);
        client.receipt_sent(&second).unwrap();
        assert_eq!(client.due_receipt(floor, &mut rng).unwrap(), None);

        // NET-042: the user opens the conversation. A kind that goes off
        // erases what waits.
        client.mark_read(conversation, 4_000_000, &mut rng).unwrap();
        let read = client
            .due_receipt(4_000 + RECEIPT_MIN_DELAY, &mut rng)
            .unwrap()
            .unwrap();
        // WIR-514: one target, the newest message that the user saw.
        assert_eq!(targets_of(&read, AppKind::ReadReceipt), [[12; 16]]);
        let delivery_only = ReceiptSettings {
            delivery: true,
            read: false,
        };
        client
            .set_receipt_settings(conversation, delivery_only, &mut rng)
            .unwrap();
        assert_eq!(
            client
                .due_receipt(4_000 + RECEIPT_MIN_DELAY, &mut rng)
                .unwrap(),
            None
        );

        // NET-052: a receipt that waited too long goes to no peer.
        client
            .commit_network(&[], &[text(13)], 5_000_000, &mut rng)
            .unwrap();
        assert_eq!(
            client
                .due_receipt(5_000 + RECEIPT_MAX_HOLD, &mut rng)
                .unwrap(),
            None
        );
        assert_eq!(
            client
                .due_receipt(5_000 + RECEIPT_MIN_DELAY, &mut rng)
                .unwrap(),
            None
        );

        // A read receipt covers each earlier message that a relay took, and
        // no message that waits.
        let mut early = Vec::new();
        for (words, at) in [("first", 5_800_000), ("still waits", 5_900_000)] {
            let mut draft = client.new_draft(conversation);
            draft.set_text(&units(words)).unwrap();
            early.push(client.send_draft(draft, at, &mut rng).unwrap());
            client.take_outgoing().unwrap();
        }
        client
            .set_delivery(&early[0], Delivery::Accepted, &mut rng)
            .unwrap();

        // A receipt of the peer moves a sent message up, and never down.
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("are you there")).unwrap();
        let sent = client.send_draft(draft, 6_000_000, &mut rng).unwrap();
        let outgoing = client.take_outgoing().unwrap();
        let sent_id =
            umbra_wire::app::AppMessage::parse(&outgoing.app, umbra_wire::app::Channel::Pairwise)
                .unwrap()
                .msg_id;
        client
            .set_delivery(&sent, Delivery::Accepted, &mut rng)
            .unwrap();
        while client.next_event().is_some() {}
        let receipt = |kind, id: u8| {
            let body = ReceiptBody {
                targets: vec![sent_id],
            };
            let mut encoded = vec![0u8; 18];
            body.encode(&mut encoded).unwrap();
            (contact, record(kind, [id; 16], &encoded))
        };
        let before = client.messages(conversation).unwrap().len();
        client
            .commit_network(
                &[],
                &[receipt(AppKind::ReadReceipt, 0xA1)],
                6_100_000,
                &mut rng,
            )
            .unwrap();
        let mut moved = Vec::new();
        while let Some(Event::Delivery { message, delivery }) = client.next_event() {
            assert_eq!(delivery, Delivery::Read);
            moved.push(message);
        }
        moved.sort();
        let mut expected = vec![sent, early[0]];
        expected.sort();
        assert_eq!(moved, expected);
        assert_eq!(client.info(&early[1]).unwrap().delivery, Delivery::Queued);
        client
            .commit_network(
                &[],
                &[receipt(AppKind::DeliveryReceipt, 0xA2)],
                6_200_000,
                &mut rng,
            )
            .unwrap();
        assert_eq!(client.next_event(), None);
        assert_eq!(client.info(&sent).unwrap().delivery, Delivery::Read);
        // A receipt is no message of the conversation.
        assert_eq!(client.messages(conversation).unwrap().len(), before);
        client.audit().unwrap();
    }

    #[test]
    fn a_reply_names_its_target_and_the_store_keeps_the_reference() {
        use umbra_core::session::node::{ContactId, StateChange};
        use umbra_wire::app::{rich::RichRecord, AppKind, AppMessage, Channel};

        let mut rng = Rng(7);
        let mut client = new_client(&mut rng);
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(vec![1, 2, 3]),
        };
        client
            .commit_network(&[change], &[], 1_000_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&contact.0).unwrap();

        // The peer wrote a text, and this device answers it.
        let question = record(AppKind::Text, [0x51; 16], b"coffee at four?");
        client
            .commit_network(&[], &[(contact, question)], 2_000_000, &mut rng)
            .unwrap();
        let asked = client.messages(conversation).unwrap()[0];
        assert_eq!(client.info(&asked).unwrap().reply, ReplyTarget::None);

        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("yes, at four")).unwrap();
        draft.set_reply_to(Some(asked));
        let answer = client.send_draft(draft, 2_100_000, &mut rng).unwrap();
        let outgoing = client.take_outgoing().unwrap();

        // The wire carries the raw `msg_id` of the target in a rich record.
        let sent = AppMessage::parse(&outgoing.app, Channel::Pairwise).unwrap();
        assert_eq!(sent.kind, AppKind::Rich);
        let rich = RichRecord::parse(sent.body, Channel::Pairwise).unwrap();
        assert_eq!(rich.reply_target, [0x51; 16]);
        assert_eq!(rich.thread_root, [0; 16]);
        assert_eq!(rich.inner_body, b"yes, at four");

        // The view gets the text and the target, before and after a relay
        // took the record. WIR-071: the raw target then leaves the store.
        let mut view = View::default();
        for delivery in [Delivery::Queued, Delivery::Accepted] {
            if delivery == Delivery::Accepted {
                client.set_delivery(&answer, delivery, &mut rng).unwrap();
            }
            client.render(&answer, &mut view).unwrap();
            assert_eq!(String::from_utf16(&view.0).unwrap(), "yes, at four");
            assert_eq!(
                client.info(&answer).unwrap().reply,
                ReplyTarget::Message(asked)
            );
        }

        // The peer gets the record, and its store resolves the same target
        // under its own key. A target that it does not hold is absent, and
        // the record stays (WIR-173).
        let mut peer = new_client(&mut Rng(8));
        let peer_change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(vec![1, 2, 3]),
        };
        peer.commit_network(&[peer_change], &[], 1_000_000, &mut rng)
            .unwrap();
        let peer_conversation = peer.conversation_for(&contact.0).unwrap();
        peer.commit_network(&[], &[(contact, outgoing.app.clone())], 2_200_000, &mut rng)
            .unwrap();
        let arrived = peer.messages(peer_conversation).unwrap()[0];
        assert_eq!(peer.info(&arrived).unwrap().reply, ReplyTarget::Absent);
        peer.render(&arrived, &mut view).unwrap();
        assert_eq!(String::from_utf16(&view.0).unwrap(), "yes, at four");

        // WIR-171: an answer stays inside the conversation of its target.
        let mut stray = client.new_draft(ConversationId([3; 16]));
        stray.set_text(&units("wrong place")).unwrap();
        stray.set_reply_to(Some(asked));
        assert_eq!(
            client.send_draft(stray, 2_300_000, &mut rng),
            Err(Error::Malformed)
        );
        client.audit().unwrap();
        peer.audit().unwrap();
    }

    /// A client with one contact, and the conversation of that contact.
    fn client_with_contact(
        seed: u64,
    ) -> (
        Client<MemoryBackend, Element>,
        umbra_core::session::node::ContactId,
        ConversationId,
    ) {
        use umbra_core::session::node::{ContactId, StateChange};
        let mut rng = Rng(seed);
        let mut client = new_client(&mut rng);
        let contact = ContactId([9; 32]);
        let change = StateChange::Contact {
            contact,
            state: zeroize::Zeroizing::new(vec![1, 2, 3]),
        };
        client
            .commit_network(&[change], &[], 1_000_000, &mut rng)
            .unwrap();
        let conversation = client.conversation_for(&contact.0).unwrap();
        (client, contact, conversation)
    }

    /// A descriptor of one chunk, as an upload gives it.
    fn uploaded_file(seed: u8) -> umbra_core::attach::transfer::Uploaded {
        use umbra_core::attach::transfer::{ChunkCredential, Uploaded};
        use umbra_crypto::secret::Secret;
        use umbra_wire::descriptor::{ChunkRef, FileDescriptor, Level};
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
    }

    #[test]
    fn a_document_carries_its_name_and_its_size_and_a_photo_carries_no_name() {
        use umbra_core::attach::transfer::Shape;
        use umbra_wire::{
            app::{AppMessage, Channel},
            descriptor::{class, AttachmentBody},
        };

        let mut rng = Rng(31);
        let (mut alice, _, conversation) = client_with_contact(32);
        let (mut bob, bob_contact, _) = client_with_contact(33);
        let document = zeroize::Zeroizing::new(vec![0x25; 70_000]);
        let doc_shape = Shape {
            mime_class: class::DOC,
            ..Shape::default()
        };

        // ATT-192: the name of a camera file holds its time, thus a photo
        // takes none. WIR-532: a name holds no path.
        let mut photo = alice.new_draft(conversation);
        photo
            .attach(
                document.clone(),
                Shape {
                    mime_class: class::IMAGE,
                    ..Shape::default()
                },
            )
            .unwrap();
        assert_eq!(photo.set_file_name("IMG_0001.jpg"), Err(Error::Malformed));
        let mut draft = alice.new_draft(conversation);
        draft.attach(document.clone(), doc_shape).unwrap();
        assert_eq!(draft.set_file_name("../etc/passwd"), Err(Error::Malformed));
        draft.set_file_name("Minutes 2026-09.pdf").unwrap();
        let sent = alice.send_draft(draft, 1_000_000, &mut rng).unwrap();
        assert_eq!(alice.info(&sent).unwrap().file.unwrap().size, 70_000);
        assert_eq!(
            alice.file_name(&sent).unwrap().as_deref(),
            Some("Minutes 2026-09.pdf")
        );

        // WIR-531: the name travels after the descriptor.
        alice
            .upload_done(&sent, &uploaded_file(0x42), &mut rng)
            .unwrap();
        let outgoing = alice.take_outgoing().unwrap();
        let record = AppMessage::parse(&outgoing.app, Channel::Pairwise).unwrap();
        let body = AttachmentBody::parse(record.body).unwrap();
        assert_eq!(body.name, Some("Minutes 2026-09.pdf"));

        // Bob sees the name and the padded size, and the exact size once
        // the file is there.
        bob.commit_network(
            &[],
            &[(bob_contact, outgoing.app.clone())],
            2_000_000,
            &mut rng,
        )
        .unwrap();
        let Some(Event::Message { message: got, .. }) = bob.next_event() else {
            panic!("no message");
        };
        assert_eq!(
            bob.file_name(&got).unwrap().as_deref(),
            Some("Minutes 2026-09.pdf")
        );
        let padded = u64::from(body.descriptor.padded_size);
        assert_eq!(bob.info(&got).unwrap().file.unwrap().size, padded);
        bob.download_done(&got, &document, &mut rng).unwrap();
        assert_eq!(bob.info(&got).unwrap().file.unwrap().size, 70_000);
        assert_eq!(
            bob.file_name(&got).unwrap().as_deref(),
            Some("Minutes 2026-09.pdf")
        );
    }

    #[test]
    fn a_file_waits_on_a_metered_network_and_starts_on_one_with_no_cost() {
        use client::FileState;
        use umbra_core::attach::transfer::Shape;
        use umbra_wire::descriptor::class;

        let mut rng = Rng(51);
        let (mut alice, _, conversation) = client_with_contact(52);
        let (mut bob, bob_contact, _) = client_with_contact(53);
        let mut draft = alice.new_draft(conversation);
        draft
            .attach(
                zeroize::Zeroizing::new(vec![0x21; 40_000]),
                Shape {
                    mime_class: class::IMAGE,
                    pixel_w: 300,
                    pixel_h: 200,
                    media_seconds: 0,
                },
            )
            .unwrap();
        let sent = alice.send_draft(draft, 1_000_000, &mut rng).unwrap();
        alice
            .upload_done(&sent, &uploaded_file(0x44), &mut rng)
            .unwrap();
        let outgoing = alice.take_outgoing().unwrap();

        // IMP-168: on a metered network a photo below the limit waits.
        bob.set_unmetered_only(true, &mut rng).unwrap();
        assert_eq!(bob.set_metered(true, &mut rng).unwrap(), 0);
        bob.commit_network(
            &[],
            &[(bob_contact, outgoing.app.clone())],
            2_000_000,
            &mut rng,
        )
        .unwrap();
        let Some(Event::Message { message: got, .. }) = bob.next_event() else {
            panic!("no message");
        };
        assert_eq!(bob.info(&got).unwrap().file.unwrap().state, FileState::Held);
        assert!(bob.take_download().is_none());

        // A network with no cost by the byte brings it with no tap.
        assert_eq!(bob.set_metered(false, &mut rng).unwrap(), 1);
        assert_eq!(bob.take_download().unwrap().message, got);
        assert_eq!(
            bob.info(&got).unwrap().file.unwrap().state,
            FileState::Wanted
        );
        // A second report of the same network starts nothing again.
        assert_eq!(bob.set_metered(false, &mut rng).unwrap(), 0);
    }

    #[test]
    fn a_file_above_the_limit_waits_for_a_tap_with_its_preview() {
        use client::FileState;
        use umbra_core::attach::transfer::Shape;
        use umbra_wire::descriptor::class;

        let mut rng = Rng(41);
        let (mut alice, _, conversation) = client_with_contact(42);
        let (mut bob, bob_contact, _) = client_with_contact(43);
        let photo = zeroize::Zeroizing::new(vec![0x3C; 90_000]);
        let hash = &[0xFF, 0xD8, 0xFF, 0xE0, 0x10, 0x20, 0xFF, 0xD9];

        // WIR-533: an image takes a small JPEG, and nothing else is one.
        let mut draft = alice.new_draft(conversation);
        draft
            .attach(
                photo.clone(),
                Shape {
                    mime_class: class::IMAGE,
                    pixel_w: 400,
                    pixel_h: 300,
                    media_seconds: 0,
                },
            )
            .unwrap();
        assert_eq!(draft.set_file_preview(b"not a hash"), Err(Error::Malformed));
        draft.set_file_preview(hash).unwrap();
        let sent = alice.send_draft(draft, 1_000_000, &mut rng).unwrap();
        alice
            .upload_done(&sent, &uploaded_file(0x43), &mut rng)
            .unwrap();
        let outgoing = alice.take_outgoing().unwrap();

        // IMP-167: the default limit holds a photo, thus it comes at once.
        assert_eq!(
            bob.auto_download_limit().unwrap(),
            client::AUTO_DOWNLOAD_DEFAULT
        );
        bob.commit_network(
            &[],
            &[(bob_contact, outgoing.app.clone())],
            2_000_000,
            &mut rng,
        )
        .unwrap();
        while bob.next_event().is_some() {}
        assert!(bob.take_download().is_some());

        // With the automatic download off the same record waits, and its
        // preview and its size are there before any chunk.
        bob.set_auto_download_limit(0, &mut rng).unwrap();
        // A second record of its own, under a new msg_id.
        let body =
            umbra_wire::app::AppMessage::parse(&outgoing.app, umbra_wire::app::Channel::Pairwise)
                .unwrap()
                .body
                .to_vec();
        let again = record(umbra_wire::app::AppKind::Attachment, [0x55; 16], &body);
        bob.commit_network(&[], &[(bob_contact, again)], 2_100_000, &mut rng)
            .unwrap();
        let Some(Event::Message { message: held, .. }) = bob.next_event() else {
            panic!("no message");
        };
        let info = bob.info(&held).unwrap().file.unwrap();
        assert_eq!(info.state, FileState::Held);
        // The padded size of the descriptor, before any chunk.
        assert!(info.size > 0);
        assert!(bob.take_download().is_none());
        assert_eq!(
            bob.file_extras(&held).unwrap().preview.as_deref(),
            Some(&hash[..])
        );

        // A tap asks for it.
        bob.fetch_file(&held, &mut rng).unwrap();
        assert_eq!(bob.take_download().unwrap().message, held);
        assert_eq!(
            bob.info(&held).unwrap().file.unwrap().state,
            FileState::Wanted
        );
    }

    #[test]
    fn a_file_waits_in_the_store_goes_out_after_its_upload_and_leaves_with_its_message() {
        use client::FileState;
        use umbra_core::attach::transfer::Shape;
        use umbra_wire::app::{AppKind, AppMessage, Channel};

        let mut rng = Rng(21);
        let (mut alice, _, conversation) = client_with_contact(22);
        let (mut bob, bob_contact, _) = client_with_contact(23);
        let shape = Shape {
            mime_class: 1,
            pixel_w: 640,
            pixel_h: 480,
            media_seconds: 0,
        };
        let photo = zeroize::Zeroizing::new(vec![0x5A; 50_000]);

        // The record of a file answers no message, and its text is a
        // caption (WIR-535).
        let mut both = alice.new_draft(conversation);
        both.set_reply_to(Some(MsgRef([1; 16])));
        both.attach(photo.clone(), shape).unwrap();
        assert_eq!(
            alice.send_draft(both, 1_000_000, &mut rng),
            Err(Error::Malformed)
        );

        let mut draft = alice.new_draft(conversation);
        draft.attach(photo.clone(), shape).unwrap();
        let sent = alice.send_draft(draft, 1_000_000, &mut rng).unwrap();
        // The record waits for its descriptor, thus the send path has none.
        assert!(alice.take_outgoing().is_none());
        let info = alice.info(&sent).unwrap();
        assert_eq!(info.file.unwrap().state, FileState::Uploading);
        assert_eq!(info.file.unwrap().shape, shape);
        assert!(!info.has_text);
        assert_eq!(*alice.file_bytes(&sent).unwrap(), *photo);

        // A lock takes the job out of the memory, and the unlock brings the
        // file back from the store.
        alice.lock();
        assert!(alice.take_upload().is_none());
        alice.unlock(&units("correct horse"), 5_000).unwrap();
        while alice.next_event().is_some() {}
        let job = alice.take_upload().unwrap();
        assert_eq!(
            (job.message, job.plain.as_slice()),
            (sent, photo.as_slice())
        );
        assert!(alice.take_upload().is_none());

        // The relays hold each chunk: the record goes out with its descriptor.
        let uploaded = uploaded_file(0x41);
        alice.upload_done(&sent, &uploaded, &mut rng).unwrap();
        assert_eq!(alice.next_event(), Some(Event::File { message: sent }));
        assert_eq!(
            alice.info(&sent).unwrap().file.unwrap().state,
            FileState::Ready
        );
        let outgoing = alice.take_outgoing().unwrap();
        assert_eq!(outgoing.message, sent);
        let sent_record = AppMessage::parse(&outgoing.app, Channel::Pairwise).unwrap();
        assert_eq!(sent_record.kind, AppKind::Attachment);
        let descriptor = umbra_wire::descriptor::FileDescriptor::parse(sent_record.body).unwrap();
        assert_eq!(descriptor.refs[0].chunk_id, [0x41; 32]);

        // Bob gets the record, and his device wants the file.
        bob.commit_network(
            &[],
            &[(bob_contact, outgoing.app.clone())],
            2_000_000,
            &mut rng,
        )
        .unwrap();
        let Some(Event::Message { message: got, .. }) = bob.next_event() else {
            panic!("no message");
        };
        assert_eq!(
            bob.info(&got).unwrap().file.unwrap().state,
            FileState::Wanted
        );
        assert_eq!(bob.info(&got).unwrap().file.unwrap().shape, shape);
        let job = bob.take_download().unwrap();
        assert_eq!(job.message, got);
        assert_eq!(job.descriptor.refs[0].chunk_id, [0x41; 32]);
        assert_eq!(bob.file_bytes(&got), Err(Error::NotFound));

        // A download that failed can start again, and one that did not fail
        // cannot.
        assert_eq!(bob.fetch_file(&got, &mut rng), Err(Error::Malformed));
        bob.download_failed(&got, &mut rng).unwrap();
        assert_eq!(bob.next_event(), Some(Event::File { message: got }));
        assert_eq!(
            bob.info(&got).unwrap().file.unwrap().state,
            FileState::Failed
        );
        bob.fetch_file(&got, &mut rng).unwrap();
        assert_eq!(bob.take_download().unwrap().message, got);
        bob.download_done(&got, &photo, &mut rng).unwrap();
        assert_eq!(bob.next_event(), Some(Event::File { message: got }));
        assert_eq!(
            bob.info(&got).unwrap().file.unwrap().state,
            FileState::Ready
        );
        assert_eq!(*bob.file_bytes(&got).unwrap(), *photo);

        // A descriptor that this device cannot read is a message with a file
        // that did not arrive, and no download starts.
        let unread = record(AppKind::Attachment, [0x77; 16], &[1, 2, 3]);
        bob.commit_network(&[], &[(bob_contact, unread)], 2_100_000, &mut rng)
            .unwrap();
        let Some(Event::Message { message: bad, .. }) = bob.next_event() else {
            panic!("no message");
        };
        assert_eq!(
            bob.info(&bad).unwrap().file.unwrap().state,
            FileState::Failed
        );
        assert!(bob.take_download().is_none());

        // An upload that failed makes the message fail. A second attempt
        // takes the file from the store, and the message waits again.
        let mut again = alice.new_draft(conversation);
        again.attach(photo.clone(), shape).unwrap();
        let retried = alice.send_draft(again, 1_200_000, &mut rng).unwrap();
        assert_eq!(alice.take_upload().unwrap().message, retried);
        alice.upload_failed(&retried, &mut rng).unwrap();
        let info = alice.info(&retried).unwrap();
        assert_eq!(info.file.unwrap().state, FileState::Failed);
        assert_eq!(info.delivery, Delivery::Failed);
        alice.fetch_file(&retried, &mut rng).unwrap();
        let info = alice.info(&retried).unwrap();
        assert_eq!(info.file.unwrap().state, FileState::Uploading);
        assert_eq!(info.delivery, Delivery::Queued);
        let job = alice.take_upload().unwrap();
        assert_eq!(
            (job.message, job.plain.as_slice()),
            (retried, photo.as_slice())
        );
        while alice.next_event().is_some() {}

        // ATT-161: the deletion of the message erases each chunk of its file
        // at each relay, and the store holds no row of the file.
        alice.delete_for_me(&sent).unwrap();
        let erase = alice.take_erasure().unwrap();
        assert_eq!(erase.chunk_id, [0x41; 32]);
        assert_eq!(erase.cred.expose(), &[0x36; 32]);
        assert_eq!(erase.relays.len(), 3);
        assert!(alice.take_erasure().is_none());
        assert_eq!(alice.file_bytes(&sent), Err(Error::NotFound));
        // Bob uploaded nothing, thus his deletion erases no chunk.
        bob.delete_for_me(&got).unwrap();
        assert!(bob.take_erasure().is_none());
        assert_eq!(bob.file_bytes(&got), Err(Error::NotFound));
        alice.audit().unwrap();
        bob.audit().unwrap();
    }

    #[test]
    fn a_deletion_leaves_a_placeholder_and_reaches_the_messages_of_its_sender_alone() {
        use umbra_wire::app::{
            edit::{DeleteBody, DeleteScope},
            AppKind, AppMessage, Channel,
        };

        let mut rng = Rng(11);
        let (mut alice, contact, conversation) = client_with_contact(12);
        let (mut bob, _, bob_conversation) = client_with_contact(13);

        // Alice sends two texts, and Bob holds them.
        let mut sent = Vec::new();
        for (words, at) in [("first", 2_000_000), ("second", 2_001_000)] {
            let mut draft = alice.new_draft(conversation);
            draft.set_text(&units(words)).unwrap();
            let message = alice.send_draft(draft, at, &mut rng).unwrap();
            let outgoing = alice.take_outgoing().unwrap();
            alice
                .set_delivery(&message, Delivery::Accepted, &mut rng)
                .unwrap();
            bob.commit_network(&[], &[(contact, outgoing.app)], at + 500, &mut rng)
                .unwrap();
            sent.push(message);
        }
        while alice.next_event().is_some() {}
        while bob.next_event().is_some() {}
        let at_bob = bob.messages(bob_conversation).unwrap();

        // For everyone: the content leaves Alice at once, a placeholder
        // stands in its row, and one request waits for the send path.
        alice
            .delete_for_everyone(&sent[0], 3_000_000, &mut rng)
            .unwrap();
        let mut view = View::default();
        assert!(alice.info(&sent[0]).unwrap().deleted);
        assert!(alice.render(&sent[0], &mut view).is_err());
        assert_eq!(alice.messages(conversation).unwrap(), sent);
        let request = alice.take_outgoing().unwrap();
        let parsed = AppMessage::parse(&request.app, Channel::Pairwise).unwrap();
        assert_eq!(parsed.kind, AppKind::Delete);
        assert_eq!(
            DeleteBody::parse(parsed.body).unwrap().scope,
            DeleteScope::OtherParty
        );

        // DELETE_RATE_LIMIT: a second request inside 10 seconds changes
        // nothing, and a request after that time goes.
        assert_eq!(
            alice.delete_for_everyone(&sent[1], 3_009_000, &mut rng),
            Err(Error::Busy)
        );
        assert!(!alice.info(&sent[1]).unwrap().deleted);

        // The request leaves the store when a relay took it, and no view
        // showed it.
        alice
            .set_delivery(&request.message, Delivery::Accepted, &mut rng)
            .unwrap();
        assert_eq!(alice.info(&request.message), Err(Error::NotFound));
        assert_eq!(alice.messages(conversation).unwrap(), sent);

        // Bob gets the request: a placeholder, an event, and no new message.
        bob.commit_network(&[], &[(contact, request.app.clone())], 3_100_000, &mut rng)
            .unwrap();
        assert_eq!(
            bob.next_event(),
            Some(Event::Deleted {
                conversation: bob_conversation,
                message: at_bob[0]
            })
        );
        assert_eq!(bob.messages(bob_conversation).unwrap(), at_bob);
        assert!(bob.info(&at_bob[0]).unwrap().deleted);
        assert!(bob.render(&at_bob[0], &mut view).is_err());
        bob.render(&at_bob[1], &mut view).unwrap();
        assert_eq!(String::from_utf16(&view.0).unwrap(), "second");

        // DEV-085: a contact deletes no message of this device. Bob wrote a
        // text, and a request of Alice that names it changes nothing.
        let mut draft = bob.new_draft(bob_conversation);
        draft.set_text(&units("mine")).unwrap();
        let mine = bob.send_draft(draft, 3_200_000, &mut rng).unwrap();
        let mine_id = AppMessage::parse(&bob.take_outgoing().unwrap().app, Channel::Pairwise)
            .unwrap()
            .msg_id;
        let body = DeleteBody {
            scope: DeleteScope::OtherParty,
            targets: vec![mine_id],
        };
        let mut encoded = vec![0u8; body.len()];
        body.encode(&mut encoded).unwrap();
        let forged = record(AppKind::Delete, [0xD1; 16], &encoded);
        bob.commit_network(&[], &[(contact, forged)], 3_300_000, &mut rng)
            .unwrap();
        assert!(!bob.info(&mine).unwrap().deleted);
        assert_eq!(bob.next_event(), None);

        // DEV-093: a deletion that comes before its target takes the target
        // at its arrival, and the view shows nothing at that position.
        let body = DeleteBody {
            scope: DeleteScope::OtherParty,
            targets: vec![[0x77; 16]],
        };
        let mut encoded = vec![0u8; body.len()];
        body.encode(&mut encoded).unwrap();
        let early = record(AppKind::Delete, [0xD2; 16], &encoded);
        let late = record(AppKind::Text, [0x77; 16], b"too late");
        let before = bob.messages(bob_conversation).unwrap().len();
        bob.commit_network(&[], &[(contact, early)], 3_400_000, &mut rng)
            .unwrap();
        bob.commit_network(&[], &[(contact, late)], 3_500_000, &mut rng)
            .unwrap();
        assert_eq!(bob.messages(bob_conversation).unwrap().len(), before);
        assert_eq!(bob.next_event(), None);

        // A message of the contact is no target of a request of this device.
        assert_eq!(
            bob.delete_for_everyone(&at_bob[1], 3_600_000, &mut rng),
            Err(Error::Malformed)
        );

        // DEV-105: the user clears a placeholder, and a message of the
        // contact leaves this device alone.
        bob.delete_for_me(&at_bob[0]).unwrap();
        bob.delete_for_me(&at_bob[1]).unwrap();
        assert_eq!(bob.messages(bob_conversation).unwrap(), [mine]);
        assert_eq!(bob.delete_for_me(&at_bob[1]), Err(Error::NotFound));
        alice.audit().unwrap();
        bob.audit().unwrap();
    }

    fn edit_record(target: [u8; 16], text: &str, msg_id: u8) -> Vec<u8> {
        let body = umbra_wire::app::edit::EditBody {
            target,
            new_body: text,
        };
        let mut encoded = vec![0u8; body.len()];
        body.encode(&mut encoded).unwrap();
        record(umbra_wire::app::AppKind::Edit, [msg_id; 16], &encoded)
    }

    #[test]
    fn an_edit_changes_the_text_of_its_sender_alone_inside_the_window() {
        use crate::client::{EDIT_MAX, EDIT_WINDOW_MS};
        use umbra_wire::app::{edit::EditBody, AppKind, AppMessage, Channel};

        let mut rng = Rng(21);
        let (mut alice, contact, conversation) = client_with_contact(22);
        let (mut bob, _, bob_conversation) = client_with_contact(23);
        let text_of = |client: &Client<MemoryBackend, Element>, message: &MsgRef| {
            let mut view = View::default();
            client.render(message, &mut view).unwrap();
            String::from_utf16(&view.0).unwrap()
        };

        // Bob asks, Alice answers with a reply, and Bob holds the answer.
        let question = record(AppKind::Text, [0x61; 16], b"when?");
        alice
            .commit_network(&[], &[(contact, question)], 2_000_000, &mut rng)
            .unwrap();
        let asked = alice.messages(conversation).unwrap()[0];
        let mut draft = alice.new_draft(conversation);
        draft.set_text(&units("at fuor")).unwrap();
        draft.set_reply_to(Some(asked));
        let answer = alice.send_draft(draft, 2_100_000, &mut rng).unwrap();
        let outgoing = alice.take_outgoing().unwrap();
        let answer_id = AppMessage::parse(&outgoing.app, Channel::Pairwise)
            .unwrap()
            .msg_id;
        alice
            .set_delivery(&answer, Delivery::Accepted, &mut rng)
            .unwrap();
        bob.commit_network(&[], &[(contact, outgoing.app)], 2_200_000, &mut rng)
            .unwrap();
        let at_bob = bob.messages(bob_conversation).unwrap()[0];
        while alice.next_event().is_some() {}
        while bob.next_event().is_some() {}

        // Alice corrects the text. Her row changes at once, the reply keeps
        // its target (WIR-262), and one record of kind 0x04 waits.
        let mut fixed = alice.new_draft(conversation);
        fixed.set_text(&units("at four")).unwrap();
        alice.edit(&answer, fixed, 2_300_000, &mut rng).unwrap();
        assert_eq!(text_of(&alice, &answer), "at four");
        let info = alice.info(&answer).unwrap();
        assert_eq!(info.revisions, 1);
        assert_eq!(info.reply, ReplyTarget::Message(asked));
        let request = alice.take_outgoing().unwrap();
        let parsed = AppMessage::parse(&request.app, Channel::Pairwise).unwrap();
        assert_eq!(parsed.kind, AppKind::Edit);
        let sent_edit = EditBody::parse(parsed.body).unwrap();
        assert_eq!(
            (sent_edit.target, sent_edit.new_body),
            (answer_id, "at four")
        );
        // No view shows the request, and it goes when a relay took it.
        assert_eq!(alice.messages(conversation).unwrap(), [asked, answer]);
        alice
            .set_delivery(&request.message, Delivery::Accepted, &mut rng)
            .unwrap();
        assert_eq!(alice.info(&request.message), Err(Error::NotFound));

        // Bob applies it, with the mark and an event, and no new message.
        bob.commit_network(&[], &[(contact, request.app.clone())], 2_400_000, &mut rng)
            .unwrap();
        assert_eq!(
            bob.next_event(),
            Some(Event::Edited {
                conversation: bob_conversation,
                message: at_bob
            })
        );
        assert_eq!(text_of(&bob, &at_bob), "at four");
        assert_eq!(bob.info(&at_bob).unwrap().revisions, 1);
        assert_eq!(bob.messages(bob_conversation).unwrap(), [at_bob]);

        // WIR-082: a contact edits no message of this device. An edit on the
        // receiving chain of Alice that names her own answer changes nothing.
        alice
            .commit_network(
                &[],
                &[(contact, edit_record(answer_id, "forged", 0xE1))],
                2_500_000,
                &mut rng,
            )
            .unwrap();
        assert_eq!(text_of(&alice, &answer), "at four");
        assert_eq!(alice.next_event(), None);

        // DEV-087: Bob measures the window from his own store time, and an
        // edit after it changes nothing.
        bob.commit_network(
            &[],
            &[(contact, edit_record(answer_id, "too late", 0xE2))],
            2_200_000 + EDIT_WINDOW_MS,
            &mut rng,
        )
        .unwrap();
        assert_eq!(text_of(&bob, &at_bob), "at four");
        assert_eq!(bob.next_event(), None);

        // Alice refuses her own edit after the window, and after EDIT_MAX.
        let mut draft = alice.new_draft(conversation);
        draft.set_text(&units("no")).unwrap();
        assert_eq!(
            alice.edit(&answer, draft, 2_100_000 + EDIT_WINDOW_MS, &mut rng),
            Err(Error::TooLong)
        );
        for n in 1..EDIT_MAX {
            let mut draft = alice.new_draft(conversation);
            draft.set_text(&units("again")).unwrap();
            alice
                .edit(&answer, draft, 2_600_000 + u64::from(n), &mut rng)
                .unwrap();
            alice.take_outgoing().unwrap();
        }
        assert_eq!(alice.info(&answer).unwrap().revisions, EDIT_MAX);
        let mut draft = alice.new_draft(conversation);
        draft.set_text(&units("one more")).unwrap();
        assert_eq!(
            alice.edit(&answer, draft, 2_700_000, &mut rng),
            Err(Error::TooLong)
        );
        // A message of the contact takes no edit of this device.
        let mut draft = alice.new_draft(conversation);
        draft.set_text(&units("not mine")).unwrap();
        assert_eq!(
            alice.edit(&asked, draft, 2_800_000, &mut rng),
            Err(Error::Malformed)
        );

        // DEV-093: an edit that comes before its target gives the target
        // its text and its mark at the arrival.
        bob.commit_network(
            &[],
            &[(
                contact,
                edit_record([0x71; 16], "fixed before it came", 0xE3),
            )],
            3_000_000,
            &mut rng,
        )
        .unwrap();
        bob.commit_network(
            &[],
            &[(contact, record(AppKind::Text, [0x71; 16], b"first form"))],
            3_100_000,
            &mut rng,
        )
        .unwrap();
        let arrived = *bob.messages(bob_conversation).unwrap().last().unwrap();
        assert_eq!(text_of(&bob, &arrived), "fixed before it came");
        assert_eq!(bob.info(&arrived).unwrap().revisions, 1);

        // A deletion takes the mark with the content.
        alice
            .delete_for_everyone(&answer, 4_000_000, &mut rng)
            .unwrap();
        assert_eq!(alice.info(&answer).unwrap().revisions, 0);
        alice.audit().unwrap();
        bob.audit().unwrap();
    }

    #[test]
    fn a_reaction_is_an_emoji_on_a_held_message_and_a_second_one_takes_it_away() {
        use crate::client::{is_emoji, REACTIONS_MAX};
        use umbra_wire::app::{
            signal::{ReactionAction, ReactionBody},
            AppKind, AppMessage, Channel,
        };

        // An emoji sequence passes, and a text in any script does not.
        for emoji in [
            "\u{2764}\u{FE0F}",
            "\u{1F44D}",
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",
        ] {
            assert!(is_emoji(emoji), "{emoji}");
        }
        for text in [
            "",
            "ok",
            "1\u{FE0F}\u{20E3}",
            "\u{43F}\u{440}\u{438}",
            "\u{1F44D} yes",
        ] {
            assert!(!is_emoji(text), "{text}");
        }

        let mut rng = Rng(31);
        let (mut alice, contact, conversation) = client_with_contact(32);
        let (mut bob, _, bob_conversation) = client_with_contact(33);

        let mut draft = alice.new_draft(conversation);
        draft.set_text(&units("dinner at seven?")).unwrap();
        let sent = alice.send_draft(draft, 2_000_000, &mut rng).unwrap();
        let outgoing = alice.take_outgoing().unwrap();
        let sent_id = AppMessage::parse(&outgoing.app, Channel::Pairwise)
            .unwrap()
            .msg_id;
        alice
            .set_delivery(&sent, Delivery::Accepted, &mut rng)
            .unwrap();
        bob.commit_network(&[], &[(contact, outgoing.app)], 2_100_000, &mut rng)
            .unwrap();
        let at_bob = bob.messages(bob_conversation).unwrap()[0];
        while alice.next_event().is_some() {}
        while bob.next_event().is_some() {}

        // Bob reacts. His table holds it at once, one record waits, and no
        // view shows that record.
        let thumb = "\u{1F44D}";
        bob.react(&at_bob, thumb, 2_200_000, &mut rng).unwrap();
        assert_eq!(
            bob.reactions(&at_bob).unwrap(),
            [Reaction {
                emoji: thumb.to_owned(),
                mine: true
            }]
        );
        let request = bob.take_outgoing().unwrap();
        let parsed = AppMessage::parse(&request.app, Channel::Pairwise).unwrap();
        assert_eq!(parsed.kind, AppKind::Reaction);
        let body = ReactionBody::parse(parsed.body).unwrap();
        assert_eq!(
            (body.target, body.action, body.emoji),
            (sent_id, ReactionAction::Add, thumb)
        );
        assert_eq!(bob.messages(bob_conversation).unwrap(), [at_bob]);

        // Alice gets it: an event, the reaction of the contact, no message.
        alice
            .commit_network(&[], &[(contact, request.app.clone())], 2_300_000, &mut rng)
            .unwrap();
        assert_eq!(
            alice.next_event(),
            Some(Event::Reacted {
                conversation,
                message: sent
            })
        );
        assert_eq!(
            alice.reactions(&sent).unwrap(),
            [Reaction {
                emoji: thumb.to_owned(),
                mine: false
            }]
        );
        assert_eq!(alice.messages(conversation).unwrap(), [sent]);
        // The same record a second time changes nothing.
        alice
            .commit_network(&[], &[(contact, request.app)], 2_310_000, &mut rng)
            .unwrap();
        assert_eq!(alice.next_event(), None);

        // Alice adds the same emoji: two parties, two rows, hers first.
        alice.react(&sent, thumb, 2_400_000, &mut rng).unwrap();
        alice.take_outgoing().unwrap();
        let both = alice.reactions(&sent).unwrap();
        assert_eq!(both.len(), 2);
        assert!(both[0].mine && !both[1].mine);

        // A second reaction of Bob with the same emoji takes it away, and
        // the record says Remove (WIR-281).
        bob.react(&at_bob, thumb, 2_500_000, &mut rng).unwrap();
        assert!(bob.reactions(&at_bob).unwrap().is_empty());
        let removal = bob.take_outgoing().unwrap();
        let parsed = AppMessage::parse(&removal.app, Channel::Pairwise).unwrap();
        assert_eq!(
            ReactionBody::parse(parsed.body).unwrap().action,
            ReactionAction::Remove
        );
        alice
            .commit_network(&[], &[(contact, removal.app)], 2_600_000, &mut rng)
            .unwrap();
        assert_eq!(alice.reactions(&sent).unwrap().len(), 1);
        assert!(alice.reactions(&sent).unwrap()[0].mine);
        assert!(matches!(alice.next_event(), Some(Event::Reacted { .. })));

        // A text in the place of an emoji changes nothing, from the contact
        // and from the surface. A reaction to an unknown message is dropped.
        let reaction = |target: [u8; 16], emoji: &str, id: u8| {
            let body = ReactionBody {
                target,
                action: ReactionAction::Add,
                emoji,
            };
            let mut encoded = vec![0u8; 19 + emoji.len()];
            body.encode(&mut encoded).unwrap();
            (contact, record(AppKind::Reaction, [id; 16], &encoded))
        };
        alice
            .commit_network(
                &[],
                &[reaction(sent_id, "call me", 0xA1)],
                2_700_000,
                &mut rng,
            )
            .unwrap();
        alice
            .commit_network(
                &[],
                &[reaction([0x44; 16], thumb, 0xA2)],
                2_710_000,
                &mut rng,
            )
            .unwrap();
        assert_eq!(alice.next_event(), None);
        assert_eq!(alice.reactions(&sent).unwrap().len(), 1);
        assert_eq!(
            alice.react(&sent, "nice", 2_720_000, &mut rng),
            Err(Error::Malformed)
        );

        // A contact holds at most REACTIONS_MAX emoji on one message.
        for n in 0..=REACTIONS_MAX {
            let emoji = char::from_u32(0x1F600 + u32::try_from(n).unwrap())
                .unwrap()
                .to_string();
            let id = 0xB0 + u8::try_from(n).unwrap();
            alice
                .commit_network(&[], &[reaction(sent_id, &emoji, id)], 2_800_000, &mut rng)
                .unwrap();
        }
        let of_contact = alice
            .reactions(&sent)
            .unwrap()
            .iter()
            .filter(|reaction| !reaction.mine)
            .count();
        assert_eq!(of_contact, REACTIONS_MAX);

        // A deleted message holds no reaction.
        alice.delete_for_me(&sent).unwrap();
        assert_eq!(alice.reactions(&sent), Err(Error::NotFound));
        alice.audit().unwrap();
        bob.audit().unwrap();
    }

    #[test]
    fn a_lock_drops_the_key_and_an_unlock_brings_the_waiting_records_back() {
        let mut rng = Rng(1);
        let mut client = new_client(&mut rng);
        let conversation = ConversationId([7; 16]);
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("still waiting")).unwrap();
        let waiting = client.send_draft(draft, 1_010_000, &mut rng).unwrap();
        let mut gone = client.new_draft(conversation);
        gone.set_text(&units("never mind")).unwrap();
        let cancelled = client.send_draft(gone, 1_011_000, &mut rng).unwrap();
        assert!(client.cancel_send(&cancelled).unwrap());
        assert!(!client.cancel_send(&cancelled).unwrap());

        // The idle timer locks the client.
        client.tick(1_011 + 15 * 60 - 1);
        assert!(client.is_unlocked());
        client.tick(1_011 + 15 * 60);
        assert!(!client.is_unlocked());
        assert_eq!(client.next_event(), Some(Event::Locked));
        assert!(client.take_outgoing().is_none());
        let mut view = View::default();
        assert_eq!(client.render(&waiting, &mut view), Err(Error::Locked));

        assert_eq!(
            client.unlock(&units("wrong horse"), 5_000),
            Err(Error::WrongPassphrase)
        );
        assert!(!client.is_unlocked());
        client.unlock(&units("correct horse"), 5_000).unwrap();
        let outgoing = client.take_outgoing().unwrap();
        assert_eq!(outgoing.message, waiting);
        assert!(client.take_outgoing().is_none());
        assert_eq!(client.render(&cancelled, &mut view), Err(Error::NotFound));
    }

    #[test]
    fn a_store_from_another_device_does_not_open() {
        let mut rng = Rng(1);
        let client = new_client(&mut rng);
        let header = *client.header();
        let mut elsewhere = Client::open(MemoryBackend::default(), Element([2; 32]), header, 0);
        assert_eq!(
            elsewhere.unlock(&units("correct horse"), 1),
            Err(Error::WrongPassphrase)
        );
    }
}
