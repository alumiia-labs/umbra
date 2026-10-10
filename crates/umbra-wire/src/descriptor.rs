//! The file descriptor of Part 12 §12.3: what a receiver needs to fetch
//! and open one object on the chunk path.

use alloc::{borrow::Cow, vec::Vec};

use umbra_crypto::secret::Secret;

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The fixed part.
pub const FIXED: usize = 137;
/// One `ChunkRef`.
pub const CHUNK_REF_LEN: usize = 120;
/// `CHUNK_SIZE`, which `padded_size` must divide by (`ATT-068`).
pub const CHUNK_SIZE: u32 = 32_650;
/// `FILE_NAME_MAX`, in bytes of UTF-8 (Part 6 §6.6, `WIR-531`).
pub const FILE_NAME_MAX: usize = 255;
/// `PREVIEW_MAX`, in bytes: a JPEG thumbnail of low quality (`WIR-533`).
pub const PREVIEW_MAX: usize = 6_144;
/// `CAPTION_MAX`, in bytes of UTF-8: the text that a file carries
/// (`WIR-535`).
pub const CAPTION_MAX: usize = 1_024;
/// The largest trailer of an `AttachmentBody`: three length fields, the
/// longest name, the largest preview, and the longest caption.
pub const TRAILER_MAX: usize = 1 + FILE_NAME_MAX + 2 + PREVIEW_MAX + 2 + CAPTION_MAX;
/// The offset of `ref_count` in the fixed part.
const REF_COUNT_AT: usize = 124;

/// The `mime_class` values of Part 12 §12.3. A receiver shows a value that
/// it does not know as a file of class other (`ATT-193`).
pub mod class {
    /// An image.
    pub const IMAGE: u8 = 0x01;
    /// A video.
    pub const VIDEO: u8 = 0x02;
    /// An audio file that the user selected.
    pub const AUDIO: u8 = 0x03;
    /// A recording that the client made in the conversation.
    pub const VOICE: u8 = 0x04;
    /// A document.
    pub const DOC: u8 = 0x05;
    /// Each other file.
    pub const OTHER: u8 = 0x06;
}

/// The level of the refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Level {
    /// The refs address data chunks.
    Data = 0x00,
    /// The refs address manifest chunks (§12.3.4).
    Manifest = 0x01,
}

/// One chunk and its two replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    /// The relay that holds the chunk.
    pub relay_id: [u8; 32],
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// The read credential.
    pub cred_pk: [u8; 32],
    /// The two replica hints of §12.3.2.
    pub replicas: [[u8; 12]; 2],
}

/// A file descriptor. It holds the file key, thus it has no `Debug`.
pub struct FileDescriptor {
    /// The level.
    pub level: Level,
    /// The XChaCha20-Poly1305 key.
    pub file_key: Secret<32>,
    /// The nonce.
    pub file_nonce: [u8; 24],
    /// The key commitment of §12.3.1.
    pub commit: [u8; 32],
    /// SHA3-256 of the plaintext.
    pub digest: [u8; 32],
    /// The duration of an audio or a video object, else 0.
    pub media_seconds: u16,
    /// The data chunk count times `CHUNK_SIZE`.
    pub padded_size: u32,
    /// The media class.
    pub mime_class: u8,
    /// The width of an image or a video, else 0.
    pub pixel_w: u16,
    /// The height of an image or a video, else 0.
    pub pixel_h: u16,
    /// The refs.
    pub refs: Vec<ChunkRef>,
}

impl FileDescriptor {
    /// The encoded length.
    pub fn len(&self) -> usize {
        FIXED.saturating_add(self.refs.len().saturating_mul(CHUNK_REF_LEN))
    }

    /// Whether the descriptor names no chunk. Clippy asks for this beside
    /// `len`.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Writes the descriptor.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.padded_size.is_multiple_of(CHUNK_SIZE) {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.level as u8)?;
        w.put(self.file_key.expose())?;
        w.put(&self.file_nonce)?;
        w.put(&self.commit)?;
        w.put(&self.digest)?;
        w.u16(self.media_seconds)?;
        w.u32(u32::try_from(self.refs.len()).map_err(|_| Error::Malformed)?)?;
        w.u32(self.padded_size)?;
        w.u8(self.mime_class)?;
        w.u16(self.pixel_w)?;
        w.u16(self.pixel_h)?;
        for r in &self.refs {
            w.put(&r.relay_id)?;
            w.put(&r.chunk_id)?;
            w.put(&r.cred_pk)?;
            w.put(&r.replicas[0])?;
            w.put(&r.replicas[1])?;
        }
        Ok(w.position())
    }

    /// Reads a descriptor.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let level = match r.u8()? {
            0x00 => Level::Data,
            0x01 => Level::Manifest,
            _ => return Err(Error::Malformed),
        };
        let file_key = Secret::new(r.array()?);
        let file_nonce = r.array()?;
        let commit = r.array()?;
        let digest = r.array()?;
        let media_seconds = r.u16()?;
        let ref_count = r.u32()?;
        let padded_size = r.u32()?;
        if !padded_size.is_multiple_of(CHUNK_SIZE) {
            return Err(Error::Malformed);
        }
        let mime_class = r.u8()?;
        let pixel_w = r.u16()?;
        let pixel_h = r.u16()?;
        // The remaining length bounds the count before any allocation.
        let ref_count = usize::try_from(ref_count).map_err(|_| Error::Malformed)?;
        if ref_count.checked_mul(CHUNK_REF_LEN) != Some(r.remaining()) {
            return Err(Error::Malformed);
        }
        let mut refs = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            refs.push(ChunkRef {
                relay_id: r.array()?,
                chunk_id: r.array()?,
                cred_pk: r.array()?,
                replicas: [r.array()?, r.array()?],
            });
        }
        r.finish()?;
        Ok(FileDescriptor {
            level,
            file_key,
            file_nonce,
            commit,
            digest,
            media_seconds,
            padded_size,
            mime_class,
            pixel_w,
            pixel_h,
            refs,
        })
    }
}

/// The body of an `AppMessage` of kind `0x02` (Part 6 §6.6): the
/// descriptor, then an optional name, an optional preview, and an optional
/// caption (`WIR-531`, `WIR-533`, `WIR-535`).
pub struct AttachmentBody<'a> {
    /// The descriptor.
    pub descriptor: FileDescriptor,
    /// The name of the file, with no path. A name that a parser read holds
    /// no bidirectional format character (`WIR-532`).
    pub name: Option<Cow<'a, str>>,
    /// A JPEG thumbnail of an image or of the first frame of a video.
    pub preview: Option<&'a [u8]>,
    /// The text that the sender wrote with the file.
    pub caption: Option<&'a str>,
}

/// Whether text is a caption that `WIR-535` takes: UTF-8 of 1 to
/// `CAPTION_MAX` bytes.
pub fn is_caption(text: &str) -> bool {
    !text.is_empty() && text.len() <= CAPTION_MAX
}

impl<'a> AttachmentBody<'a> {
    /// Reads a body. A body ends after the descriptor, after one
    /// `name_len`, its name, one `preview_len`, and its preview, or after
    /// those and one `caption_len` and its caption. Each other form is
    /// malformed (`WIR-532`), and so is a trailer with no name, no preview,
    /// and no caption.
    ///
    /// A name with a bidirectional format character is not malformed. A
    /// stored record, and a record of a sender before that rule, can hold
    /// one, and its file must stay in reach. The name comes back with no
    /// such character, thus no view and no save shows another extension
    /// than the bytes hold. A name of such characters alone is no name.
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        let count = body
            .get(REF_COUNT_AT..REF_COUNT_AT + 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes)
            .ok_or(Error::Malformed)?;
        let refs = usize::try_from(count).map_err(|_| Error::Malformed)?;
        let end = refs
            .checked_mul(CHUNK_REF_LEN)
            .and_then(|len| len.checked_add(FIXED))
            .ok_or(Error::Malformed)?;
        let (head, rest) = body.split_at_checked(end).ok_or(Error::Malformed)?;
        let descriptor = FileDescriptor::parse(head)?;
        if rest.is_empty() {
            return Ok(AttachmentBody {
                descriptor,
                name: None,
                preview: None,
                caption: None,
            });
        }
        let mut r = Reader::new(rest);
        let name_len = usize::from(r.u8()?);
        let name = r.take(name_len)?;
        let preview_len = usize::from(r.u16()?);
        let preview = r.take(preview_len)?;
        let caption = if r.remaining() == 0 {
            None
        } else {
            let caption_len = usize::from(r.u16()?);
            let caption =
                core::str::from_utf8(r.take(caption_len)?).map_err(|_| Error::Malformed)?;
            if !is_caption(caption) {
                return Err(Error::Malformed);
            }
            Some(caption)
        };
        r.finish()?;
        // WIR-532: a trailer that carries nothing is a second encoding of a
        // body that ends after the descriptor.
        if name.is_empty() && preview.is_empty() && caption.is_none() {
            return Err(Error::Malformed);
        }
        let name = if name.is_empty() {
            None
        } else {
            let name = core::str::from_utf8(name).map_err(|_| Error::Malformed)?;
            if !is_plain_name(name) {
                return Err(Error::Malformed);
            }
            let name = without_bidi_format(name);
            // What stays after the marks can be empty, `.`, or `..`.
            is_file_name(&name).then_some(name)
        };
        let preview = if preview.is_empty() {
            None
        } else {
            // WIR-533: a preview is a small JPEG, and only of a picture.
            let is_picture = matches!(descriptor.mime_class, class::IMAGE | class::VIDEO);
            if !is_picture || !is_preview(preview) {
                return Err(Error::Malformed);
            }
            Some(preview)
        };
        Ok(AttachmentBody {
            descriptor,
            name,
            preview,
            caption,
        })
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        let trailer = match (self.name.as_deref(), self.preview, self.caption) {
            (None, None, None) => 0,
            (name, preview, caption) => {
                3 + name.map_or(0, str::len)
                    + preview.map_or(0, <[u8]>::len)
                    + caption.map_or(0, |caption| 2 + caption.len())
            }
        };
        self.descriptor.len().saturating_add(trailer)
    }

    /// Whether the body names no chunk. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.descriptor.is_empty()
    }

    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let at = self.descriptor.encode(out)?;
        if self.name.is_none() && self.preview.is_none() && self.caption.is_none() {
            return Ok(at);
        }
        if self.caption.is_some_and(|caption| !is_caption(caption)) {
            return Err(Error::Malformed);
        }
        // WIR-532: a sender writes no name with a bidirectional format
        // character, although a parser reads one.
        if self.name.as_deref().is_some_and(|name| !is_file_name(name)) {
            return Err(Error::Malformed);
        }
        let is_picture = matches!(self.descriptor.mime_class, class::IMAGE | class::VIDEO);
        if self
            .preview
            .is_some_and(|preview| !is_picture || !is_preview(preview))
        {
            return Err(Error::Malformed);
        }
        let name = self.name.as_deref().map_or(&[][..], str::as_bytes);
        let preview = self.preview.unwrap_or(&[]);
        let tail = out.get_mut(at..).ok_or(Error::Malformed)?;
        let mut w = Writer::new(tail);
        w.u8(u8::try_from(name.len()).map_err(|_| Error::Malformed)?)?;
        w.put(name)?;
        w.u16(u16::try_from(preview.len()).map_err(|_| Error::Malformed)?)?;
        w.put(preview)?;
        if let Some(caption) = self.caption {
            w.u16(u16::try_from(caption.len()).map_err(|_| Error::Malformed)?)?;
            w.put(caption.as_bytes())?;
        }
        Ok(at + w.position())
    }
}

/// Whether bytes are a preview that `WIR-533` takes: a JPEG of at most
/// `PREVIEW_MAX` bytes, with its start and its end marker. The decoder of
/// the platform reads the rest, as it reads each photo.
pub fn is_preview(bytes: &[u8]) -> bool {
    bytes.len() <= PREVIEW_MAX
        && bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        && bytes.ends_with(&[0xFF, 0xD9])
}

/// Whether a text is a file name that a sender writes (`WIR-532`). Such a
/// name has 1 to `FILE_NAME_MAX` bytes, no control character, no
/// bidirectional format character, and no path separator. It is not `.`
/// or `..`.
pub fn is_file_name(name: &str) -> bool {
    is_plain_name(name) && !name.chars().any(is_bidi_format)
}

/// The part of `WIR-532` that a parser rejects a name for: its length, a
/// control character, a path separator, and `.` or `..`.
fn is_plain_name(name: &str) -> bool {
    (1..=FILE_NAME_MAX).contains(&name.len())
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
}

/// A name with no bidirectional format character. A name that holds none
/// comes back as it is.
pub fn without_bidi_format(name: &str) -> Cow<'_, str> {
    if name.chars().any(is_bidi_format) {
        Cow::Owned(name.chars().filter(|c| !is_bidi_format(*c)).collect())
    } else {
        Cow::Borrowed(name)
    }
}

/// Whether a character changes the direction of the text around it: the
/// marks, the embeddings, the overrides, and the isolates. With one, a
/// sender shows a name that ends in a different extension than the bytes
/// of the name do.
const fn is_bidi_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
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
    fn a_descriptor_round_trips_at_its_fixed_lengths() {
        let one = ChunkRef {
            relay_id: [1; 32],
            chunk_id: [2; 32],
            cred_pk: [3; 32],
            replicas: [[4; 12], [5; 12]],
        };
        let desc = FileDescriptor {
            level: Level::Data,
            file_key: Secret::new([6; 32]),
            file_nonce: [7; 24],
            commit: [8; 32],
            digest: [9; 32],
            media_seconds: 0,
            padded_size: CHUNK_SIZE,
            mime_class: 1,
            pixel_w: 640,
            pixel_h: 480,
            refs: vec![one],
        };
        let mut out = vec![0u8; desc.len()];
        assert_eq!(desc.encode(&mut out).unwrap(), 257);
        let back = FileDescriptor::parse(&out).unwrap();
        assert_eq!(back.refs, vec![one]);
        assert_eq!(back.pixel_h, 480);
        assert!(FileDescriptor::parse(&out[..256]).is_err());
        out[131] = 1;
        assert!(FileDescriptor::parse(&out).is_err());
    }

    fn one_ref_descriptor() -> FileDescriptor {
        FileDescriptor {
            level: Level::Data,
            file_key: Secret::new([6; 32]),
            file_nonce: [7; 24],
            commit: [8; 32],
            digest: [9; 32],
            media_seconds: 0,
            padded_size: CHUNK_SIZE,
            mime_class: class::DOC,
            pixel_w: 0,
            pixel_h: 0,
            refs: vec![ChunkRef {
                relay_id: [1; 32],
                chunk_id: [2; 32],
                cred_pk: [3; 32],
                replicas: [[4; 12], [5; 12]],
            }],
        }
    }

    #[test]
    fn a_body_carries_a_name_and_a_preview_after_the_descriptor_or_none() {
        let named = AttachmentBody {
            descriptor: one_ref_descriptor(),
            name: Some("Report 2026.pdf".into()),
            preview: None,
            caption: None,
        };
        let mut out = vec![0u8; named.len()];
        assert_eq!(named.encode(&mut out).unwrap(), 257 + 3 + 15);
        let back = AttachmentBody::parse(&out).unwrap();
        assert_eq!(back.name.as_deref(), Some("Report 2026.pdf"));
        assert_eq!(back.preview, None);
        assert_eq!(back.descriptor.mime_class, class::DOC);

        // A body that holds the descriptor alone carries neither.
        let bare = &out[..257];
        assert_eq!(AttachmentBody::parse(bare).unwrap().name, None);

        // WIR-532: a length that the rest does not fill, and a stray byte.
        assert!(AttachmentBody::parse(&out[..out.len() - 1]).is_err());
        let mut stray = out.clone();
        stray.push(0);
        assert!(AttachmentBody::parse(&stray).is_err());

        // WIR-533: a photo takes a thumbnail and no name, and a document
        // takes no preview.
        let mut photo = one_ref_descriptor();
        photo.mime_class = class::IMAGE;
        let hash = &[0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 0xFF, 0xD9];
        let shown = AttachmentBody {
            descriptor: photo,
            name: None,
            preview: Some(hash),
            caption: None,
        };
        let mut out = vec![0u8; shown.len()];
        shown.encode(&mut out).unwrap();
        assert_eq!(
            AttachmentBody::parse(&out).unwrap().preview,
            Some(&hash[..])
        );
        let wrong = AttachmentBody {
            descriptor: one_ref_descriptor(),
            name: None,
            preview: Some(hash),
            caption: None,
        };
        let mut out = vec![0u8; wrong.len()];
        assert!(wrong.encode(&mut out).is_err());
    }

    #[test]
    fn a_body_carries_a_caption_after_the_preview() {
        let captioned = AttachmentBody {
            descriptor: one_ref_descriptor(),
            name: None,
            preview: None,
            caption: Some("The summit at six"),
        };
        let mut out = vec![0u8; captioned.len()];
        assert_eq!(captioned.encode(&mut out).unwrap(), 257 + 3 + 2 + 17);
        let back = AttachmentBody::parse(&out).unwrap();
        assert_eq!(back.caption, Some("The summit at six"));
        assert_eq!((back.name, back.preview), (None, None));

        // WIR-535: an empty caption, a caption above CAPTION_MAX, and one
        // that is not UTF-8 are malformed.
        let mut empty = out[..257 + 3].to_vec();
        empty.extend_from_slice(&[0, 0]);
        assert!(AttachmentBody::parse(&empty).is_err());
        let long = "a".repeat(CAPTION_MAX + 1);
        let over = AttachmentBody {
            descriptor: one_ref_descriptor(),
            name: None,
            preview: None,
            caption: Some(&long),
        };
        let mut out = vec![0u8; over.len()];
        assert!(over.encode(&mut out).is_err());
        let mut bad = captioned_bytes();
        let end = bad.len();
        bad[end - 1] = 0xFF;
        assert!(AttachmentBody::parse(&bad).is_err());
        const { assert!(TRAILER_MAX > 1 + FILE_NAME_MAX + 2 + PREVIEW_MAX + CAPTION_MAX) };
    }

    fn captioned_bytes() -> Vec<u8> {
        let body = AttachmentBody {
            descriptor: one_ref_descriptor(),
            name: None,
            preview: None,
            caption: Some("abc"),
        };
        let mut out = vec![0u8; body.len()];
        body.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn a_preview_is_a_small_jpeg() {
        assert!(is_preview(&[0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9]));
        // No end marker, no start marker, and a thumbnail that is too large.
        assert!(!is_preview(&[0xFF, 0xD8, 0xFF, 0xE0]));
        assert!(!is_preview(b"GIF89a"));
        let mut large = vec![0u8; PREVIEW_MAX + 1];
        large[..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
        let end = large.len();
        large[end - 2..].copy_from_slice(&[0xFF, 0xD9]);
        assert!(!is_preview(&large));
    }

    #[test]
    fn a_name_with_a_path_or_a_control_character_is_rejected() {
        for bad in ["", ".", "..", "a/b", "a\\b", "a\nb", "a\u{7f}"] {
            assert!(!is_file_name(bad), "{bad:?}");
            let body = AttachmentBody {
                descriptor: one_ref_descriptor(),
                name: Some(bad.into()),
                preview: None,
                caption: None,
            };
            let mut out = vec![0u8; body.len()];
            assert!(body.encode(&mut out).is_err(), "{bad:?}");
        }
        // A parser rejects each one too.
        for bad in ["a/b", "a\\b", "a\nb", "a\u{7f}", ".", ".."] {
            assert!(AttachmentBody::parse(&named_bytes(bad)).is_err(), "{bad:?}");
        }
        assert!(is_file_name("été – notes.txt"));
        let long = "a".repeat(FILE_NAME_MAX + 1);
        assert!(!is_file_name(&long));
        assert!(is_file_name(&long[1..]));
    }

    /// A body with one name, as a sender before the rule of the
    /// bidirectional format characters wrote it: no check of the name.
    fn named_bytes(name: &str) -> Vec<u8> {
        let descriptor = one_ref_descriptor();
        let mut out = vec![0u8; descriptor.len()];
        descriptor.encode(&mut out).unwrap();
        out.push(u8::try_from(name.len()).unwrap());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn a_sender_writes_no_name_with_a_bidirectional_format_character() {
        for mark in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            let bad = alloc::format!("report{mark}fdp.exe");
            assert!(!is_file_name(&bad), "{bad:?}");
            let body = AttachmentBody {
                descriptor: one_ref_descriptor(),
                name: Some(bad.as_str().into()),
                preview: None,
                caption: None,
            };
            let mut out = vec![0u8; body.len()];
            assert!(body.encode(&mut out).is_err(), "{bad:?}");
        }
        // A name in a script that runs from right to left holds none.
        assert!(is_file_name("تقرير.pdf"));
        assert!(is_file_name("דוח 2026.pdf"));
    }

    #[test]
    fn a_parser_reads_a_name_with_a_bidirectional_format_character_with_none() {
        for mark in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            // A stored record, or one of an earlier sender: the file stays
            // in reach, and the name shows the extension of its bytes.
            let stored = named_bytes(&alloc::format!("report{mark}fdp.exe"));
            let back = AttachmentBody::parse(&stored).unwrap();
            assert_eq!(back.name.as_deref(), Some("reportfdp.exe"), "{mark:?}");
            assert_eq!(back.descriptor.refs.len(), 1);
            // The name that came back is one that a sender writes.
            let mut out = vec![0u8; back.len()];
            assert_eq!(back.encode(&mut out).unwrap(), 257 + 3 + 13);
        }
        // What stays after the marks is no name: the body has none.
        for left in ["\u{200E}", ".\u{202E}", ".\u{200F}.\u{2069}"] {
            let stored = named_bytes(left);
            let back = AttachmentBody::parse(&stored).unwrap();
            assert_eq!(back.name, None, "{left:?}");
        }
        // A name with no such character comes back as the bytes hold it.
        let back_bytes = named_bytes("דוח 2026.pdf");
        let back = AttachmentBody::parse(&back_bytes).unwrap();
        assert!(matches!(back.name, Some(Cow::Borrowed("דוח 2026.pdf"))));
    }

    #[test]
    fn a_trailer_that_carries_nothing_is_rejected() {
        let bare = AttachmentBody {
            descriptor: one_ref_descriptor(),
            name: None,
            preview: None,
            caption: None,
        };
        let mut out = vec![0u8; bare.len()];
        assert_eq!(bare.encode(&mut out).unwrap(), 257);
        assert!(AttachmentBody::parse(&out).is_ok());
        // A name_len of zero and a preview_len of zero, with no caption.
        out.extend_from_slice(&[0, 0, 0]);
        assert!(AttachmentBody::parse(&out).is_err());
        // The same empty part before a caption is a complete trailer.
        assert!(AttachmentBody::parse(&captioned_bytes()).is_ok());
    }
}
