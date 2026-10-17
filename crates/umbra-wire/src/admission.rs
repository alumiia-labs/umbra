//! The admission trailer of Part 13 §13.2: a token, a proof of work, or
//! nothing.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The trailer with no credential, 3 bytes.
pub const NONE_LEN: usize = 3;

/// The kind of credential. The value `0x02` is retired and never returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdmissionKind {
    /// No credential; the body is empty.
    None = 0x00,
    /// A token of Part 13 §13.3, 354 or 162 bytes by the token type.
    Token = 0x01,
    /// A `PowSolution` of Part 13 §13.8, 69 bytes.
    Pow = 0x03,
}

impl AdmissionKind {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x00 => Ok(AdmissionKind::None),
            0x01 => Ok(AdmissionKind::Token),
            0x03 => Ok(AdmissionKind::Pow),
            _ => Err(Error::Malformed),
        }
    }

    const fn body_len_ok(self, len: usize) -> bool {
        match self {
            AdmissionKind::None => len == 0,
            AdmissionKind::Token => len == 354 || len == 162,
            AdmissionKind::Pow => len == 69,
        }
    }
}

/// An admission trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission<'a> {
    /// The kind.
    pub kind: AdmissionKind,
    /// The body, of the length the kind fixes.
    pub body: &'a [u8],
}

impl<'a> Admission<'a> {
    /// The trailer with no credential.
    pub const NONE: Admission<'static> = Admission {
        kind: AdmissionKind::None,
        body: &[],
    };

    /// The encoded length.
    pub const fn len(&self) -> usize {
        NONE_LEN + self.body.len()
    }

    /// Whether the body is empty. Clippy asks for this beside `len`.
    pub const fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Writes the trailer.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.kind.body_len_ok(self.body.len()) {
            return Err(Error::Malformed);
        }

        let len = u16::try_from(self.body.len()).map_err(|_| Error::Malformed)?;

        let mut w = Writer::new(out);
        w.u8(self.kind as u8)?;
        w.u16(len)?;
        w.put(self.body)?;
        Ok(w.position())
    }

    /// Reads a trailer from the front of `bytes`, and returns the count of
    /// bytes it took.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let mut r = Reader::new(bytes);
        let kind = AdmissionKind::from_byte(r.u8()?)?;
        let len = usize::from(r.u16()?);
        if !kind.body_len_ok(len) {
            return Err(Error::Malformed);
        }

        let body = r.take(len)?;
        Ok((Admission { kind, body }, r.position()))
    }
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

    #[test]
    fn each_kind_holds_its_length() {
        let mut out = [0u8; 400];
        assert_eq!(Admission::NONE.encode(&mut out).unwrap(), 3);
        assert_eq!(Admission::parse(&out[..3]).unwrap(), (Admission::NONE, 3));

        let pow = Admission {
            kind: AdmissionKind::Pow,
            body: &[1; 69],
        };
        assert_eq!(pow.encode(&mut out).unwrap(), 72);
        assert_eq!(Admission::parse(&out[..80]).unwrap().1, 72);

        let bad = Admission {
            kind: AdmissionKind::Pow,
            body: &[1; 68],
        };
        assert!(bad.encode(&mut out).is_err());

        out[0] = 0x02;
        assert!(Admission::parse(&out).is_err());
        out[0] = 0x01;
        out[1] = 0x00;
        out[2] = 0x45;
        assert!(Admission::parse(&out).is_err());
    }
}
