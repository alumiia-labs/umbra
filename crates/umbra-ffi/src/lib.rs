//! The client surface of the UMBRA protocol for Android (Part 15 §15.6.1).
//!
//! The surface is narrow by design. The platform holds opaque handles: a
//! [`draft::Draft`] that it writes text into, and a [`MsgRef`] that it
//! renders into a [`Sink`]. No message plaintext, no key, and no passphrase
//! crosses as a `ByteArray` or a `String` (`IMP-037`). One event stream
//! runs from Rust to the platform, and nothing crosses for each packet.
//!
//! [`client`] holds the client itself, which builds and tests with no
//! binding generator. The `sqlite` feature adds the SQLite backend of
//! §15.6.4, and the `bindings` feature adds the UniFFI scaffolding over
//! both.
#![forbid(unsafe_code)]

pub mod client;
pub mod draft;
#[cfg(feature = "sqlite")]
pub mod sqlite;

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

/// The delivery state of Part 15 §15.9.1. The list is closed.
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

    use super::{client::Client, *};

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
    fn a_draft_becomes_a_stored_message_and_renders_into_a_sink() {
        let mut rng = Rng(1);
        let mut client = new_client(&mut rng);
        let conversation = ConversationId([7; 16]);

        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("hello 👋")).unwrap();
        let sent = client.send_draft(draft, 1_010, &mut rng).unwrap();
        assert!(client
            .send_draft(client.new_draft(conversation), 1_011, &mut rng)
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
        let received = peer.receive(conversation, &outgoing.app, &mut rng).unwrap();
        assert_eq!(
            peer.receive(conversation, &outgoing.app, &mut rng).unwrap(),
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

    #[test]
    fn a_lock_drops_the_key_and_an_unlock_brings_the_waiting_records_back() {
        let mut rng = Rng(1);
        let mut client = new_client(&mut rng);
        let conversation = ConversationId([7; 16]);
        let mut draft = client.new_draft(conversation);
        draft.set_text(&units("still waiting")).unwrap();
        draft.attach("content://media/9".into());
        let waiting = client.send_draft(draft, 1_010, &mut rng).unwrap();
        let mut gone = client.new_draft(conversation);
        gone.set_text(&units("never mind")).unwrap();
        let cancelled = client.send_draft(gone, 1_011, &mut rng).unwrap();
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
        assert_eq!(outgoing.attachments, ["content://media/9"]);
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
