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

/// Whether bytes are a picture that `DIS-176` takes: a JPEG of at most
/// `PICTURE_MAX` bytes.
fn is_picture(bytes: &[u8]) -> bool {
    bytes.len() <= PICTURE_MAX
        && bytes.starts_with(&[0xFF, 0xD8, 0xFF])
        && bytes.ends_with(&[0xFF, 0xD9])
}

impl<'a> ProfilePlain<'a> {
    fn check(&self) -> Result<(), Error> {
        if self.name.len() > PROFILE_NAME_MAX
            || self.welcome.len() > WELCOME_MAX
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
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9];
        let with_picture = ProfilePlain {
            name: "",
            welcome: "",
            picture: &jpeg,
        };
        let bytes = with_picture.encode().unwrap();
        assert_eq!(ProfilePlain::parse(&bytes).unwrap().picture, jpeg);
        const { assert!(PROFILE_BLOB_MAX < umbra_wire::directory::DIR_REQUEST_LEN - 128) };
    }
}
