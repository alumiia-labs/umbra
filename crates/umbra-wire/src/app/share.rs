//! The contact share of Part 6 §6.6.7: a three-record flow that asks the
//! shared contact first.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The type of a contact share. The value `0x04` is retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShareType {
    /// Alice asks Bob; the body is empty.
    Request = 0x01,
    /// Bob answers Alice with a fresh invitation.
    Grant = 0x02,
    /// Alice tells Carol with that invitation.
    Offer = 0x03,
}

/// A contact share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactShare<'a> {
    /// The type.
    pub share_type: ShareType,
    /// The petname the sender uses.
    pub name: &'a str,
    /// Empty for a request; a one-time invitation otherwise.
    pub body: &'a [u8],
}

impl<'a> ContactShare<'a> {
    fn check(&self) -> Result<(), Error> {
        let empty = self.body.is_empty();
        match self.share_type {
            ShareType::Request if !empty => Err(Error::Malformed),
            ShareType::Grant | ShareType::Offer if empty => Err(Error::Malformed),
            _ => Ok(()),
        }
    }

    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;

        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.share_type as u8)?;
        w.u8(u8::try_from(self.name.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.name.as_bytes())?;
        w.u16(u16::try_from(self.body.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.body)?;
        Ok(w.position())
    }

    /// Reads a record (`WIR-197`, `WIR-198`, `WIR-454`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let share_type = match r.u8()? {
            0x01 => ShareType::Request,
            0x02 => ShareType::Grant,
            0x03 => ShareType::Offer,
            _ => return Err(Error::Malformed),
        };

        let name_len = usize::from(r.u8()?);
        let name = core::str::from_utf8(r.take(name_len)?).map_err(|_| Error::Malformed)?;
        let body_len = usize::from(r.u16()?);
        let body = r.take(body_len)?;
        r.finish()?;

        let out = ContactShare {
            share_type,
            name,
            body,
        };
        out.check()?;
        Ok(out)
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
    fn each_type_holds_its_body_rule() {
        let mut out = [0u8; 100];
        let request = ContactShare {
            share_type: ShareType::Request,
            name: "Carol",
            body: b"",
        };
        let n = request.encode(&mut out).unwrap();
        assert_eq!(ContactShare::parse(&out[..n]).unwrap(), request);

        let grant = ContactShare {
            share_type: ShareType::Grant,
            name: "Carol",
            body: b"invite",
        };
        let n = grant.encode(&mut out).unwrap();
        assert_eq!(ContactShare::parse(&out[..n]).unwrap(), grant);

        let bad = ContactShare {
            share_type: ShareType::Request,
            name: "Carol",
            body: b"x",
        };
        assert!(bad.encode(&mut out).is_err());

        let bad = ContactShare {
            share_type: ShareType::Offer,
            name: "Carol",
            body: b"",
        };
        assert!(bad.encode(&mut out).is_err());

        out[1] = 0x04;
        assert!(ContactShare::parse(&out[..n]).is_err());
    }
}
