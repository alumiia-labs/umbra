//! The edit body and the delete body of Part 6 §6.6.1.

use alloc::vec::Vec;

use crate::{
    app::strictly_increasing,
    codec::{Reader, Writer},
    Error,
};

/// `DELETE_BATCH_MAX`, a security parameter and not a bandwidth choice.
pub const DELETE_BATCH_MAX: usize = 9;
/// The most `new_body` bytes an edit holds at bucket `B0`.
pub const EDIT_B0_MAX: usize = 138;

/// An edit of an earlier text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditBody<'a> {
    /// The `msg_id` of the message this record edits.
    pub target: [u8; 16],
    /// The new text.
    pub new_body: &'a str,
}

impl<'a> EditBody<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        17usize.saturating_add(self.new_body.len())
    }

    /// Whether the new text is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.new_body.is_empty()
    }

    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.new_body.is_empty() {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.target)?;
        w.put(self.new_body.as_bytes())?;
        Ok(w.position())
    }

    /// Reads a body (`WIR-078`, `WIR-079`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 18 {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let target = r.array()?;
        let new_body = core::str::from_utf8(r.rest()).map_err(|_| Error::Malformed)?;
        Ok(EditBody { target, new_body })
    }
}

/// The scope of a deletion. The client holds the check of the scope
/// against the channel (`WIR-084`). This crate does not tell the sync
/// channel of a device set from the channel of a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeleteScope {
    /// The devices of one user.
    OwnDevices = 0x01,
    /// The other party.
    OtherParty = 0x02,
    /// The whole pairwise conversation, at the other party (`WIR-558`).
    /// The one target bounds the messages of the receiver that go.
    Conversation = 0x03,
}

/// A tombstone over one or more targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteBody {
    /// The scope.
    pub scope: DeleteScope,
    /// The targets, in strictly increasing byte order.
    pub targets: Vec<[u8; 16]>,
}

impl DeleteBody {
    /// The encoded length.
    pub fn len(&self) -> usize {
        2usize.saturating_add(self.targets.len().saturating_mul(16))
    }

    /// Whether the target list is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.targets.is_empty()
            || self.targets.len() > DELETE_BATCH_MAX
            || (self.scope == DeleteScope::Conversation && self.targets.len() != 1)
            || !strictly_increasing(&self.targets)
        {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.scope as u8)?;
        for t in &self.targets {
            w.put(t)?;
        }
        Ok(w.position())
    }

    /// Reads a body (`WIR-085` to `WIR-089`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let scope = match r.u8()? {
            0x01 => DeleteScope::OwnDevices,
            0x02 => DeleteScope::OtherParty,
            0x03 => DeleteScope::Conversation,
            _ => return Err(Error::Malformed),
        };
        let rest = r.remaining();
        if !rest.is_multiple_of(16) {
            return Err(Error::Malformed);
        }
        let k = rest / 16;
        if k == 0 || k > DELETE_BATCH_MAX {
            return Err(Error::Malformed);
        }
        // WIR-559: the deletion of a conversation names one bound.
        if scope == DeleteScope::Conversation && k != 1 {
            return Err(Error::Malformed);
        }
        let mut targets = Vec::with_capacity(k);
        for _ in 0..k {
            targets.push(r.array()?);
        }
        if !strictly_increasing(&targets) {
            return Err(Error::Malformed);
        }
        Ok(DeleteBody { scope, targets })
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
    use alloc::vec;

    #[test]
    fn the_edit_holds_its_bounds() {
        let edit = EditBody {
            target: [1; 16],
            new_body: "x",
        };
        let mut out = [0u8; 200];
        assert_eq!(edit.encode(&mut out).unwrap(), 18);
        assert_eq!(EditBody::parse(&out[..18]).unwrap(), edit);
        assert!(EditBody::parse(&out[..17]).is_err());
        out[17] = 0xFF;
        assert!(EditBody::parse(&out[..18]).is_err());
        assert_eq!(
            crate::bucket::Bucket::B0.text_default_chunk() - 17,
            EDIT_B0_MAX
        );
    }

    #[test]
    fn the_delete_holds_its_canonical_form() {
        let del = DeleteBody {
            scope: DeleteScope::OtherParty,
            targets: vec![[1; 16], [2; 16]],
        };
        let mut out = [0u8; 200];
        assert_eq!(del.encode(&mut out).unwrap(), 34);
        assert_eq!(DeleteBody::parse(&out[..34]).unwrap(), del);
        assert!(DeleteBody::parse(&out[..33]).is_err());
        assert!(DeleteBody::parse(&out[..2]).is_err());
        let mut swapped = out;
        swapped[2..18].copy_from_slice(&[2; 16]);
        swapped[18..34].copy_from_slice(&[1; 16]);
        assert!(DeleteBody::parse(&swapped[..34]).is_err());
        swapped[18..34].copy_from_slice(&[2; 16]);
        assert!(DeleteBody::parse(&swapped[..34]).is_err());
        out[1] = 0x03;
        assert!(DeleteBody::parse(&out[..34]).is_err());
        let big = DeleteBody {
            scope: DeleteScope::OwnDevices,
            targets: (0..10u8).map(|i| [i; 16]).collect(),
        };
        assert!(big.encode(&mut out).is_err());
    }

    #[test]
    fn the_deletion_of_a_conversation_names_one_bound() {
        let whole = DeleteBody {
            scope: DeleteScope::Conversation,
            targets: vec![[0; 16]],
        };
        let mut out = [0u8; 200];
        assert_eq!(whole.encode(&mut out).unwrap(), 18);
        assert_eq!(&out[..2], &[0x01, 0x03]);
        assert_eq!(DeleteBody::parse(&out[..18]).unwrap(), whole);
        // WIR-559: a second target is no bound.
        let two = DeleteBody {
            scope: DeleteScope::Conversation,
            targets: vec![[1; 16], [2; 16]],
        };
        assert!(two.encode(&mut out).is_err());
        out[18..34].copy_from_slice(&[2; 16]);
        assert!(DeleteBody::parse(&out[..34]).is_err());
    }
}
