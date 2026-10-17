//! The plaintext of the profile blob of Part 9 §9.3.1: the name, the
//! welcome text, and the picture of a Profile (Part 4 §4.2.5). The holder
//! seals it under the key of its link fragment, and the directory keeps the
//! sealed blob beside the label (`DIS-175` to `DIS-178`).

use alloc::vec::Vec;

use umbra_crypto::stored::{Reader, Writer};

use crate::Error;

/// The version byte of the plaintext.
pub const PROFILE_VERSION: u8 = 0x01;
/// The longest name, in bytes of UTF-8 (Part 4 §4.2.5).
pub const PROFILE_NAME_MAX: usize = 32;
/// `WELCOME_MAX`, in bytes of UTF-8.
pub const WELCOME_MAX: usize = 280;
/// `PICTURE_MAX`, in bytes: a JPEG after the re-encode of `DIS-001`.
pub const PICTURE_MAX: usize = 6_144;
/// The longest side of a picture, in pixels (`DIS-176`).
pub const PICTURE_SIDE_MAX: u16 = 1_024;
/// The longest plaintext.
pub const PROFILE_PLAIN_MAX: usize = 1 + 1 + PROFILE_NAME_MAX + 2 + WELCOME_MAX + 2 + PICTURE_MAX;
/// `PROFILE_BLOB_MAX`, in bytes: the longest sealed blob, which is the
/// version, the nonce, the longest plaintext, and the tag (`DIS-141`).
pub const PROFILE_BLOB_MAX: usize = 1 + 24 + PROFILE_PLAIN_MAX + 16;

/// The plaintext of a profile blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePlain<'a> {
    /// The name, or empty.
    pub name: &'a str,
    /// The welcome text, or empty.
    pub welcome: &'a str,
    /// A JPEG picture, or empty.
    pub picture: &'a [u8],
}

/// The height and the width that the frame header of a JPEG names, from a
/// walk over its segments up to the first scan. The walk decodes no byte
/// of the picture. A baseline, an extended, or a progressive frame gives a
/// size; a picture with another frame, or with no frame before its scan,
/// gives none.
fn frame_size(bytes: &[u8]) -> Option<(u16, u16)> {
    // The start marker takes two bytes. Each turn then takes one byte at
    // least, thus the length of the picture bounds the walk.
    let mut rest = bytes.get(2..)?;

    loop {
        let [0xFF, marker, after @ ..] = rest else {
            return None;
        };

        match *marker {
            // A fill byte before a marker.
            0xFF => rest = rest.get(1..)?,
            // A marker with no segment.
            0x01 | 0xD0..=0xD7 => rest = after,
            // No marker, a second start, the end, or a scan: the frame
            // header did not come first.
            0x00 | 0xD8 | 0xD9 | 0xDA => return None,
            // A lossless, a differential, or an arithmetic frame.
            0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => return None,
            _ => {
                let [high, low, ..] = after else {
                    return None;
                };

                // The length counts its own two bytes.
                let len = usize::from(u16::from_be_bytes([*high, *low]));
                let segment = after.get(2..len)?;
                if matches!(*marker, 0xC0..=0xC2) {
                    // The sample precision, the height, and the width.
                    let [_, h0, h1, w0, w1, ..] = segment else {
                        return None;
                    };
                    return Some((
                        u16::from_be_bytes([*h0, *h1]),
                        u16::from_be_bytes([*w0, *w1]),
                    ));
                }

                rest = after.get(len..)?;
            }
        }
    }
}

/// Whether bytes are a picture that `DIS-176` takes: a JPEG of at most
/// `PICTURE_MAX` bytes whose frame header names a side of 1 to
/// `PICTURE_SIDE_MAX` pixels each way. `PICTURE_MAX` bounds the bytes and
/// not the canvas, thus this check reads the size here, before any decoder.
fn is_picture(bytes: &[u8]) -> bool {
    let side = |side: u16| (1..=PICTURE_SIDE_MAX).contains(&side);

    bytes.len() <= PICTURE_MAX
        && bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        && bytes.ends_with(&[0xFF, 0xD9])
        && frame_size(bytes).is_some_and(|(height, width)| side(height) && side(width))
}

/// Whether a character is one that no profile text holds (`DIS-201`): a
/// control character, a line break other than the line feed of a welcome
/// text, or a format character of the bidirectional algorithm. Such a
/// character moves or hides the text around it, thus a name of a stranger
/// could show as another name.
fn is_barred(c: char, allows_line_feed: bool) -> bool {
    match c {
        '\n' => !allows_line_feed,
        '\u{2028}' | '\u{2029}' => true,
        '\u{061C}'
        | '\u{200E}'
        | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}' => true,
        c => c.is_control(),
    }
}

/// Whether a name holds no character that `DIS-201` bars.
pub fn is_plain_name(text: &str) -> bool {
    !text.chars().any(|c| is_barred(c, false))
}

/// Whether a welcome text or a note holds no character that `DIS-201`
/// bars. A line feed is a line break of the text, and it stays.
pub fn is_plain_note(text: &str) -> bool {
    !text.chars().any(|c| is_barred(c, true))
}

impl<'a> ProfilePlain<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.name.len() > PROFILE_NAME_MAX
            || self.welcome.len() > WELCOME_MAX
            || !is_plain_name(self.name)
            || !is_plain_note(self.welcome)
            || (!self.picture.is_empty() && !is_picture(self.picture))
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the plaintext: `0x01 || name_len u8 || name || welcome_len
    /// u16 || welcome || picture_len u16 || picture` (`DIS-176`).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;

        let mut w = Writer::new();
        w.u8(PROFILE_VERSION);
        w.u8(u8::try_from(self.name.len()).map_err(|_| Error::Malformed)?);
        w.bytes(self.name.as_bytes());
        w.u16(u16::try_from(self.welcome.len()).map_err(|_| Error::Malformed)?);
        w.bytes(self.welcome.as_bytes());
        w.u16(u16::try_from(self.picture.len()).map_err(|_| Error::Malformed)?);
        w.bytes(self.picture);
        Ok(w.finish().to_vec())
    }

    /// Reads a plaintext, and rejects each other form (`DIS-177`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != PROFILE_VERSION {
            return Err(Error::Malformed);
        }

        let name_len = usize::from(r.u8()?);
        let name = core::str::from_utf8(r.take(name_len)?).map_err(|_| Error::Malformed)?;
        let welcome_len = usize::from(r.u16()?);
        let welcome = core::str::from_utf8(r.take(welcome_len)?).map_err(|_| Error::Malformed)?;
        let picture_len = usize::from(r.u16()?);
        let picture = r.take(picture_len)?;
        r.end()?;

        let plain = ProfilePlain {
            name,
            welcome,
            picture,
        };

        plain.check()?;
        Ok(plain)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A JPEG of one application segment, a frame header of `marker` with
    /// the two sides, and no scan.
    fn jpeg(marker: u8, height: u16, width: u16) -> Vec<u8> {
        let mut bytes = alloc::vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x4A, 0x46];
        bytes.extend([0xFF, marker, 0x00, 0x0B, 0x08]);
        bytes.extend(height.to_be_bytes());
        bytes.extend(width.to_be_bytes());
        bytes.extend([0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9]);
        bytes
    }

    #[test]
    fn a_picture_names_its_size_in_a_frame_header_and_no_side_is_above_the_bound() {
        // DIS-176: a baseline and a progressive frame at the bound.
        assert_eq!(frame_size(&jpeg(0xC0, 480, 640)), Some((480, 640)));
        assert!(is_picture(&jpeg(0xC0, PICTURE_SIDE_MAX, PICTURE_SIDE_MAX)));
        assert!(is_picture(&jpeg(0xC2, 1, 1)));

        // A side above the bound, and a side of zero.
        assert!(!is_picture(&jpeg(0xC0, PICTURE_SIDE_MAX + 1, 16)));
        assert!(!is_picture(&jpeg(0xC2, 16, PICTURE_SIDE_MAX + 1)));
        assert!(!is_picture(&jpeg(0xC0, 0xFFFF, 0xFFFF)));
        assert!(!is_picture(&jpeg(0xC0, 0, 16)));
        assert!(!is_picture(&jpeg(0xC0, 16, 0)));

        // A lossless frame, and no frame header at all.
        assert!(!is_picture(&jpeg(0xC3, 16, 16)));
        assert!(!is_picture(&[0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9]));
        assert!(!is_picture(&[0xFF, 0xD8, 0xFF, 0xD9]));

        // A frame header after the scan started is none.
        let mut late = alloc::vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02];
        late.extend(&jpeg(0xC0, 16, 16)[8..]);
        assert!(!is_picture(&late));

        // A segment that names more bytes than the picture holds, a length
        // below its own two bytes, and a frame header cut short.
        assert!(!is_picture(&[
            0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF, 0xFF, 0xD9
        ]));
        assert!(!is_picture(&[
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01, 0xFF, 0xD9
        ]));
        assert!(!is_picture(&[
            0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x04, 0x08, 0x00, 0xFF, 0xD9
        ]));

        // Fill bytes before a marker change nothing.
        let mut filled = alloc::vec![0xFF, 0xD8, 0xFF, 0xFF, 0xFF];
        filled.extend(&jpeg(0xC0, 16, 16)[8..]);
        assert_eq!(frame_size(&filled), Some((16, 16)));
    }

    #[test]
    fn a_profile_reads_back_and_its_limits_hold() {
        let plain = ProfilePlain {
            name: "Dana",
            welcome: "Say where we met.",
            picture: &[],
        };
        let bytes = plain.encode().unwrap();
        assert_eq!(ProfilePlain::parse(&bytes).unwrap(), plain);

        // A stray byte, another version, and a picture that is no JPEG.
        let mut stray = bytes.clone();
        stray.push(0);
        assert!(ProfilePlain::parse(&stray).is_err());

        let mut other = bytes.clone();
        other[0] = 2;
        assert!(ProfilePlain::parse(&other).is_err());

        let long = "a".repeat(PROFILE_NAME_MAX + 1);
        assert!(ProfilePlain {
            name: &long,
            welcome: "",
            picture: &[],
        }
        .encode()
        .is_err());

        assert!(ProfilePlain {
            name: "",
            welcome: "",
            picture: b"GIF89a",
        }
        .encode()
        .is_err());

        let jpeg = jpeg(0xC0, 96, 96);
        let with_picture = ProfilePlain {
            name: "",
            welcome: "",
            picture: &jpeg,
        };
        let bytes = with_picture.encode().unwrap();
        assert_eq!(ProfilePlain::parse(&bytes).unwrap().picture, jpeg);

        // DIS-201: no control character, line break, or bidirectional
        // format character in the name, and a line feed alone in the note.
        let note = ProfilePlain {
            name: "Dana",
            welcome: "Two lines,\nas typed.",
            picture: &[],
        };
        assert_eq!(ProfilePlain::parse(&note.encode().unwrap()).unwrap(), note);

        for name in [
            "Da\nna",
            "Dana\u{202E}",
            "\u{2066}Dana",
            "Da\u{0007}na",
            "Dana\u{2028}",
        ] {
            assert!(!is_plain_name(name));
            let barred = ProfilePlain {
                name,
                welcome: "",
                picture: &[],
            };
            assert!(barred.encode().is_err());

            // A blob that a stranger wrote with such a name does not parse.
            let mut bytes = alloc::vec![PROFILE_VERSION, name.len() as u8];
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 0]);
            assert!(ProfilePlain::parse(&bytes).is_err());
        }

        for welcome in ["a\rb", "a\u{200F}b", "a\u{0000}b", "a\tb"] {
            assert!(!is_plain_note(welcome));
        }

        const { assert!(PROFILE_BLOB_MAX < umbra_wire::directory::DIR_REQUEST_LEN - 128) };
    }
}
