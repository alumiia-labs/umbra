//! The draft of Part 14 §14.6.1: the one place where the text of a message
//! sits before the send. The platform writes UTF-16 code units into it,
//! and the buffer is zero bytes after the drop, whether the send succeeded
//! or failed (`IMP-039`).

use umbra_core::attach::{transfer::Shape, MAX_FILE_SIZE, VOICE_MAX_SECONDS};
use umbra_wire::descriptor::class;
use zeroize::{Zeroize, Zeroizing};

use crate::{ConversationId, Error, MsgRef};

/// The largest file of a draft: `MAX_FILE_SIZE` (`ATT-022`). A file above
/// one descriptor travels through its manifest (Part 12 §12.3.4).
#[allow(clippy::cast_possible_truncation)]
pub const DRAFT_FILE_MAX: usize = MAX_FILE_SIZE as usize;

/// The file of a draft: its bytes, and what the descriptor says of it.
pub struct DraftFile {
    /// The file, after the re-encode of `ATT-155`.
    pub plain: Zeroizing<Vec<u8>>,
    /// The class and the size of the media.
    pub shape: Shape,
    /// The name of the file, with no path (`WIR-531`).
    pub name: Option<String>,
    /// A JPEG thumbnail of an image or of the first frame of a video
    /// (`WIR-533`).
    pub preview: Option<Vec<u8>>,
}

/// The longest text of one draft, in bytes of UTF-8.
pub const DRAFT_TEXT_MAX: usize = 32_000;

/// A message under composition.
pub struct Draft {
    conversation: ConversationId,
    text: Zeroizing<Vec<u8>>,
    file: Option<DraftFile>,
    reply_to: Option<MsgRef>,
    mentions: Vec<u16>,
}

impl Draft {
    /// An empty draft for one conversation.
    pub fn new(conversation: ConversationId) -> Self {
        Draft {
            conversation,
            text: Zeroizing::new(Vec::new()),
            file: None,
            reply_to: None,
            mentions: Vec::new(),
        }
    }

    /// Names members of a group in the draft, by their roster index
    /// (Part 11 §11.11). A pairwise draft takes none.
    pub fn set_mentions(&mut self, members: Vec<u16>) {
        self.mentions = members;
    }

    /// The members that the draft names.
    pub fn mentions(&self) -> &[u16] {
        &self.mentions
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

    /// Gives the draft its file. The record of an attachment holds the
    /// descriptor and no text (Part 6 §6.6), thus a draft holds a text or a
    /// file, and one file.
    pub fn attach(&mut self, plain: Zeroizing<Vec<u8>>, shape: Shape) -> Result<(), Error> {
        if plain.is_empty() {
            return Err(Error::Malformed);
        }
        if plain.len() > DRAFT_FILE_MAX {
            return Err(Error::TooLong);
        }
        // ATT-069, ATT-070: a duration belongs to an audio, a voice, or a
        // video object alone. ATT-071: a voice object has an upper bound.
        let is_timed = matches!(shape.mime_class, class::AUDIO | class::VOICE | class::VIDEO);
        if !is_timed && shape.media_seconds != 0 {
            return Err(Error::Malformed);
        }
        if shape.mime_class == class::VOICE && shape.media_seconds > VOICE_MAX_SECONDS {
            return Err(Error::TooLong);
        }
        self.file = Some(DraftFile {
            plain,
            shape,
            name: None,
            preview: None,
        });
        Ok(())
    }

    /// Gives the image or the video of the draft its preview: a JPEG
    /// thumbnail of at most `PREVIEW_MAX` bytes (`WIR-533`).
    pub fn set_file_preview(&mut self, preview: &[u8]) -> Result<(), Error> {
        let file = self.file.as_mut().ok_or(Error::NotFound)?;
        if !matches!(file.shape.mime_class, class::IMAGE | class::VIDEO)
            || !umbra_wire::descriptor::is_preview(preview)
        {
            return Err(Error::Malformed);
        }
        // IMP-039: a preview is a picture of the file, thus the one that
        // this call replaces leaves the memory as the text does.
        if let Some(mut earlier) = file.preview.replace(preview.to_vec()) {
            earlier.zeroize();
        }
        Ok(())
    }

    /// Names the file of the draft. An image, a video, and a voice
    /// recording carry no name, because the name of a camera file holds its
    /// time (`ATT-192`).
    ///
    /// The name of a picked file can hold a bidirectional format character,
    /// which no name of the wire holds (`WIR-532`). The draft takes the name
    /// with no such character, thus the file still goes.
    pub fn set_file_name(&mut self, name: &str) -> Result<(), Error> {
        let file = self.file.as_mut().ok_or(Error::NotFound)?;
        let mut name = Zeroizing::new(without_bidi_marks(name));
        if !umbra_wire::descriptor::is_file_name(&name) {
            return Err(Error::Malformed);
        }
        if matches!(
            file.shape.mime_class,
            class::IMAGE | class::VIDEO | class::VOICE
        ) {
            return Err(Error::Malformed);
        }
        if let Some(mut earlier) = file.name.replace(core::mem::take(&mut *name)) {
            earlier.zeroize();
        }
        Ok(())
    }

    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }

    /// The file of the draft, which leaves the draft with this call.
    pub(crate) fn take_file(&mut self) -> Option<DraftFile> {
        self.file.take()
    }

    /// Whether the draft holds a file.
    pub fn has_file(&self) -> bool {
        self.file.is_some()
    }

    /// Whether the draft holds no text and no file.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty() && self.file.is_none()
    }

    /// Overwrites the preview and the name of a file that did not leave
    /// the draft with a send (`IMP-039`). The file and the text overwrite
    /// themselves.
    fn wipe_file(&mut self) {
        if let Some(file) = &mut self.file {
            if let Some(preview) = &mut file.preview {
                preview.zeroize();
            }
            if let Some(name) = &mut file.name {
                name.zeroize();
            }
        }
    }
}

impl Drop for Draft {
    fn drop(&mut self) {
        self.wipe_file();
    }
}

/// A file name with no bidirectional format character: the marks, the
/// embeddings, the overrides, and the isolates that `WIR-532` forbids. With
/// one, a name shows another extension than its bytes hold. A file system
/// permits them, thus the name of a picked file, and a name that the store
/// took before the rule, can hold one.
pub(crate) fn without_bidi_marks(name: &str) -> String {
    name.chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{061C}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
        })
        .collect()
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

        // A draft takes one file, and not an empty one or one above the bound.
        let mut with_file = Draft::new(ConversationId([1; 16]));
        assert_eq!(
            with_file.attach(Zeroizing::new(Vec::new()), Shape::default()),
            Err(Error::Malformed)
        );
        let large = Zeroizing::new(vec![0u8; DRAFT_FILE_MAX + 1]);
        assert_eq!(
            with_file.attach(large, Shape::default()),
            Err(Error::TooLong)
        );
        assert!(with_file.is_empty());
        with_file
            .attach(Zeroizing::new(vec![7; 10]), Shape::default())
            .unwrap();
        assert!(with_file.has_file() && !with_file.is_empty());
    }

    #[test]
    fn a_duration_belongs_to_timed_media_and_a_voice_object_has_a_bound() {
        let mut draft = Draft::new(ConversationId([2; 16]));
        let shape = |mime_class, media_seconds| Shape {
            mime_class,
            media_seconds,
            ..Shape::default()
        };
        let bytes = || Zeroizing::new(vec![7u8; 10]);
        assert_eq!(
            draft.attach(bytes(), shape(class::DOC, 3)),
            Err(Error::Malformed)
        );
        assert_eq!(
            draft.attach(bytes(), shape(class::IMAGE, 1)),
            Err(Error::Malformed)
        );
        assert_eq!(
            draft.attach(bytes(), shape(class::VOICE, VOICE_MAX_SECONDS + 1)),
            Err(Error::TooLong)
        );
        assert!(!draft.has_file());
        draft
            .attach(bytes(), shape(class::VOICE, VOICE_MAX_SECONDS))
            .unwrap();
        // An audio file that the user selected has no such bound.
        draft
            .attach(bytes(), shape(class::AUDIO, VOICE_MAX_SECONDS + 1))
            .unwrap();
        draft.attach(bytes(), shape(class::DOC, 0)).unwrap();
    }

    #[test]
    fn a_draft_that_drops_overwrites_the_preview_and_the_name_of_its_file() {
        // The test puts the two values in place with no check of them.
        let mut draft = Draft::new(ConversationId([3; 16]));
        draft
            .attach(Zeroizing::new(vec![7; 10]), Shape::default())
            .unwrap();
        let file = draft.file.as_mut().unwrap();
        file.preview = Some(vec![0xFF, 0xD8, 0xFF, 0xD9]);
        file.name = Some("minutes.pdf".to_owned());
        // IMP-039: the drop runs this, and a wiped buffer holds no byte.
        draft.wipe_file();
        let file = draft.file.as_ref().unwrap();
        assert_eq!(file.preview.as_deref(), Some(&[][..]));
        assert_eq!(file.name.as_deref(), Some(""));
        // A file that left with the send is no part of the draft.
        assert!(draft.take_file().is_some());
        draft.wipe_file();
        assert!(draft.is_empty());
    }

    #[test]
    fn a_picked_name_with_a_bidirectional_mark_goes_with_no_mark() {
        let mut draft = Draft::new(ConversationId([4; 16]));
        let shape = Shape {
            mime_class: class::DOC,
            ..Shape::default()
        };
        draft.attach(Zeroizing::new(vec![7; 10]), shape).unwrap();
        // WIR-532: the wire takes no such character, and the attach works.
        draft
            .set_file_name("\u{200F}report\u{202E}fdp.exe\u{2069}")
            .unwrap();
        let name = draft.file.as_ref().unwrap().name.clone().unwrap();
        assert_eq!(name, "reportfdp.exe");
        assert!(umbra_wire::descriptor::is_file_name(&name));
        // A name of marks alone is no name, and each other check holds.
        assert_eq!(draft.set_file_name("\u{061C}"), Err(Error::Malformed));
        assert_eq!(draft.set_file_name("a/b"), Err(Error::Malformed));
    }
}
