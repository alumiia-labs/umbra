//! The application message of Part 6 §6.6 (L8) and its bodies.
//!
//! `msg_id` sits above every encryption layer and never changes on the
//! path. A client stores `msg_ref`, the keyed hash of §6.6, and never the
//! raw value (`WIR-067` to `WIR-069`).

pub mod devset;
pub mod edit;
pub mod keys;
pub mod poll;
pub mod rich;
pub mod share;
pub mod signal;

use umbra_crypto::{hash::sha3_256, secret::Secret};

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The message version.
pub const VERSION: u8 = 0x02;
/// The header length.
pub const HEADER_LEN: usize = 30;

/// The class of Part 7 §7.5.3 that a kind declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A new record in the conversation.
    Insertion,
    /// A change to an earlier record.
    Revision,
    /// A deletion of an earlier record.
    Tombstone,
    /// A signal to the peer, not stored as a record.
    PeerSignal,
    /// Not stored at all.
    Ephemeral,
    /// Protocol state.
    Control,
    /// The class of the inner kind of a rich record.
    Inner,
    /// Mutable state or control, by the sub-kind of a device-set record.
    BySubKind,
}

/// The application kind. The value `0x12` is retired and never returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AppKind {
    /// UTF-8 text.
    Text = 0x01,
    /// A `FileDescriptor` of Part 13.
    Attachment = 0x02,
    /// A `ReactionBody`.
    Reaction = 0x03,
    /// An `EditBody`.
    Edit = 0x04,
    /// A `DeleteBody`.
    Delete = 0x05,
    /// A `ReceiptBody`.
    DeliveryReceipt = 0x06,
    /// A `ReceiptBody`.
    ReadReceipt = 0x07,
    /// A `TypingBody`.
    Typing = 0x08,
    /// A `RichRecord`.
    Rich = 0x09,
    /// A `Poll`.
    Poll = 0x0A,
    /// A `PollVote`.
    PollVote = 0x0B,
    /// A `ContactShare`.
    ContactShare = 0x0C,
    /// A `GroupControl`.
    GroupControl = 0x10,
    /// A device-set sync record.
    DeviceSet = 0x20,
    /// A `KeyChangeNotice`.
    KeyChange = 0x30,
    /// A `DigestBody`.
    TransparencyDigest = 0x31,
    /// A `ConversationTimer`.
    ConversationTimer = 0x32,
    /// A `QueueAddress`.
    QueueAddress = 0x33,
    /// A `KeyRequest`.
    KeyRequest = 0x34,
    /// A `KeySupply`.
    KeySupply = 0x35,
    /// A `VerifyCommit`, 64 bytes: the commit, and the commit that it answers.
    VerifyCommit = 0x36,
    /// A `VerifyReveal`, 32 bytes.
    VerifyReveal = 0x37,
}

impl AppKind {
    /// The kind of a byte, in this namespace only.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x01 => AppKind::Text,
            0x02 => AppKind::Attachment,
            0x03 => AppKind::Reaction,
            0x04 => AppKind::Edit,
            0x05 => AppKind::Delete,
            0x06 => AppKind::DeliveryReceipt,
            0x07 => AppKind::ReadReceipt,
            0x08 => AppKind::Typing,
            0x09 => AppKind::Rich,
            0x0A => AppKind::Poll,
            0x0B => AppKind::PollVote,
            0x0C => AppKind::ContactShare,
            0x10 => AppKind::GroupControl,
            0x20 => AppKind::DeviceSet,
            0x30 => AppKind::KeyChange,
            0x31 => AppKind::TransparencyDigest,
            0x32 => AppKind::ConversationTimer,
            0x33 => AppKind::QueueAddress,
            0x34 => AppKind::KeyRequest,
            0x35 => AppKind::KeySupply,
            0x36 => AppKind::VerifyCommit,
            0x37 => AppKind::VerifyReveal,
            _ => return Err(Error::Malformed),
        })
    }

    /// The class of the kind (`WIR-074`).
    pub const fn class(self) -> Class {
        match self {
            AppKind::Text
            | AppKind::Attachment
            | AppKind::Reaction
            | AppKind::Poll
            | AppKind::PollVote
            | AppKind::ContactShare => Class::Insertion,
            AppKind::Edit => Class::Revision,
            AppKind::Delete => Class::Tombstone,
            AppKind::DeliveryReceipt | AppKind::ReadReceipt => Class::PeerSignal,
            AppKind::Typing | AppKind::VerifyCommit | AppKind::VerifyReveal => Class::Ephemeral,
            AppKind::Rich => Class::Inner,
            AppKind::DeviceSet => Class::BySubKind,
            AppKind::GroupControl
            | AppKind::KeyChange
            | AppKind::TransparencyDigest
            | AppKind::ConversationTimer
            | AppKind::QueueAddress
            | AppKind::KeyRequest
            | AppKind::KeySupply => Class::Control,
        }
    }
}

/// The channel that carried a record, for the rules that differ by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// A pairwise ratchet session.
    Pairwise,
    /// A group queue.
    Group,
}

/// An application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppMessage<'a> {
    /// The kind.
    pub kind: AppKind,
    /// The message identifier, from the device CSPRNG.
    pub msg_id: [u8; 16],
    /// Milliseconds on the sender clock. Advisory only (`WIR-076`).
    pub sent_at: u64,
    /// The body.
    pub body: &'a [u8],
}

impl<'a> AppMessage<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        HEADER_LEN.saturating_add(self.body.len())
    }

    /// Whether the body is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Writes the message.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let body_len = u32::try_from(self.body.len()).map_err(|_| Error::Capacity)?;
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        w.u8(self.kind as u8)?;
        w.put(&self.msg_id)?;
        w.put(&self.sent_at.to_be_bytes())?;
        w.u32(body_len)?;
        w.put(self.body)?;
        Ok(w.position())
    }

    /// Reads a message. Rejects trailing bytes, an unknown kind, a kind the
    /// channel does not carry, and a body whose fixed length is wrong.
    pub fn parse(bytes: &'a [u8], channel: Channel) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let kind = AppKind::from_byte(r.u8()?)?;
        let msg_id = r.array()?;
        let sent_at = u64::from_be_bytes(r.array()?);
        let body_len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        let body = r.take(body_len)?;
        r.finish()?;
        match kind {
            AppKind::Text => {
                core::str::from_utf8(body).map_err(|_| Error::Malformed)?;
            }
            AppKind::VerifyCommit if body.len() != 64 => {
                return Err(Error::Malformed);
            }
            AppKind::VerifyReveal if body.len() != 32 => {
                return Err(Error::Malformed);
            }
            AppKind::QueueAddress
                if body.len() != crate::address::LEN || channel != Channel::Pairwise =>
            {
                return Err(Error::Malformed);
            }
            _ => {}
        }
        Ok(AppMessage {
            kind,
            msg_id,
            sent_at,
            body,
        })
    }
}

/// `msg_ref = SHA3-256(K_set || msg_id)[0..16]`, the stored reference of a
/// message (`WIR-067`).
pub fn msg_ref(device_set_key: &Secret<32>, msg_id: &[u8; 16]) -> [u8; 16] {
    let full = sha3_256(&[device_set_key.expose(), msg_id]);
    let mut out = [0u8; 16];
    if let Some(head) = full.get(..16) {
        out.copy_from_slice(head);
    }
    out
}

/// Checks that a list of 16-byte values is in strictly increasing byte
/// order with no repeat, as the canonical form of a target list requires.
pub(crate) fn strictly_increasing(items: &[[u8; 16]]) -> bool {
    items.windows(2).all(|w| match w {
        [a, b] => a < b,
        _ => true,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn a_message_round_trips_and_checks_its_body() {
        let msg = AppMessage {
            kind: AppKind::Text,
            msg_id: [1; 16],
            sent_at: 1_700_000_000_000,
            body: "héllo".as_bytes(),
        };
        let mut out = vec![0u8; msg.len()];
        assert_eq!(msg.encode(&mut out).unwrap(), 36);
        assert_eq!(AppMessage::parse(&out, Channel::Pairwise).unwrap(), msg);
        out[31] = 0xFF;
        assert!(AppMessage::parse(&out, Channel::Pairwise).is_err());
        out[31] = b'h';
        out[1] = 0x12;
        assert!(AppMessage::parse(&out, Channel::Pairwise).is_err());
        // The kinds of the withdrawn Part 12 are retired.
        for retired in [0x0D, 0x0E, 0x11, 0x38] {
            out[1] = retired;
            assert!(AppMessage::parse(&out, Channel::Group).is_err());
        }
        out[1] = 0x36;
        assert!(AppMessage::parse(&out, Channel::Pairwise).is_err());
        out[0] = 0x01;
        assert!(AppMessage::parse(&out, Channel::Pairwise).is_err());
    }

    #[test]
    fn each_kind_has_a_class_and_the_reference_is_keyed() {
        for b in 0..=0xFFu8 {
            if let Ok(k) = AppKind::from_byte(b) {
                assert_eq!(k as u8, b);
                let _ = k.class();
            }
        }
        assert!(AppKind::from_byte(0x12).is_err());
        assert!(AppKind::from_byte(0x0F).is_err());
        let a = msg_ref(&Secret::new([1; 32]), &[2; 16]);
        let b = msg_ref(&Secret::new([3; 32]), &[2; 16]);
        assert_ne!(a, b);
        assert!(strictly_increasing(&[[1; 16], [2; 16]]));
        assert!(!strictly_increasing(&[[2; 16], [2; 16]]));
    }
}
