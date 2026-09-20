//! The draft of Part 15 §15.6.1: the one place where the text of a message
//! sits before the send. The platform writes UTF-16 code units into it,
//! and the buffer is zero bytes after the drop, whether the send succeeded
//! or failed (`IMP-039`).

use zeroize::Zeroizing;

use crate::{ConversationId, Error, MsgRef};

/// The longest text of one draft, in bytes of UTF-8.
pub const DRAFT_TEXT_MAX: usize = 32_000;

/// A message under composition.
pub struct Draft {
    conversation: ConversationId,
    text: Zeroizing<Vec<u8>>,
    attachments: Vec<String>,
    reply_to: Option<MsgRef>,
}

impl Draft {
    /// An empty draft for one conversation.
    pub fn new(conversation: ConversationId) -> Self {
        Draft {
            conversation,
            text: Zeroizing::new(Vec::new()),
            attachments: Vec::new(),
            reply_to: None,
        }
    }

    /// Makes the draft an answer to a message of its conversation
    /// (Part 6 §6.6.5), or takes that away.
    pub fn set_reply_to(&mut self, message: Option<MsgRef>) {
        self.reply_to = message;
    }

    /// The message that the draft answers.
    pub fn reply_to(&self) -> Option<MsgRef> {
        self.reply_to
    }

    /// The conversation.
    pub fn conversation(&self) -> ConversationId {
        self.conversation
    }

    /// Replaces the text with the UTF-16 code units of a `CharArray`. The
    /// caller overwrites its array after this call returns. A lone
    /// surrogate is no text, thus it is rejected.
    pub fn set_text(&mut self, code_units: &[u16]) -> Result<(), Error> {
        let mut text = Zeroizing::new(Vec::with_capacity(code_units.len().saturating_mul(3)));
        for decoded in char::decode_utf16(code_units.iter().copied()) {
            let character = decoded.map_err(|_| Error::Malformed)?;
            let mut utf8 = [0u8; 4];
            text.extend_from_slice(character.encode_utf8(&mut utf8).as_bytes());
        }
        if text.len() > DRAFT_TEXT_MAX {
            return Err(Error::TooLong);
        }
        self.text = text;
        Ok(())
    }

    /// Adds a file by its reference on the platform. The send path reads
    /// the file, seals it, and uploads it (Part 13).
    pub fn attach(&mut self, file_ref: String) {
        self.attachments.push(file_ref);
    }

    /// The text as UTF-8.
    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }

    /// The file references.
    pub(crate) fn attachments(&self) -> &[String] {
        &self.attachments
    }

    /// Whether the draft holds no text and no file.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty() && self.attachments.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_takes_utf16_and_rejects_a_lone_surrogate() {
        let mut draft = Draft::new(ConversationId([1; 16]));
        assert!(draft.is_empty());
        let units: Vec<u16> = "héllo 👍".encode_utf16().collect();
        draft.set_text(&units).unwrap();
        assert_eq!(draft.text(), "héllo 👍".as_bytes());
        assert!(draft.set_text(&[0xD800]).is_err());
        assert_eq!(
            draft.text(),
            "héllo 👍".as_bytes(),
            "a failed write changes nothing"
        );

        let long = vec![u16::from(b'a'); DRAFT_TEXT_MAX + 1];
        assert_eq!(draft.set_text(&long), Err(Error::TooLong));
        draft.attach("content://media/1".into());
        assert_eq!(draft.attachments().len(), 1);
    }
}
