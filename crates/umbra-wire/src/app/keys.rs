//! The key request and the key supply of Part 6 §6.6.11, the key-change
//! notice of Part 4 §4.5.1, and the transparency digest of §6.6.4.

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The length of a `KeyRequest`.
pub const REQUEST_LEN: usize = 42;
/// The length of a `KeySupply` with no body.
pub const SUPPLY_LEN: usize = 45;
/// The length of a `KeyChangeNotice`.
pub const KEY_CHANGE_LEN: usize = 1_217;
/// The length of a `DigestBody`.
pub const DIGEST_LEN: usize = 42;

/// The scope of a key request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyScope {
    /// A pairwise session; the answer is a re-send.
    Session = 0x01,
    /// A group epoch; the answer is a one-slot epoch-key record.
    GroupEpoch = 0x02,
    /// A roster snapshot; the answer is a `SnapshotNotice`.
    RosterSnapshot = 0x03,
}

impl KeyScope {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(KeyScope::Session),
            0x02 => Ok(KeyScope::GroupEpoch),
            0x03 => Ok(KeyScope::RosterSnapshot),
            _ => Err(Error::Malformed),
        }
    }
}

/// The status of a key supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SupplyStatus {
    /// The answering member posted the record on the group queue.
    Posted = 0x01,
    /// The sender does not hold the message.
    NotHeld = 0x02,
    /// The sender sent the message again.
    Resent = 0x03,
}

impl SupplyStatus {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(SupplyStatus::Posted),
            0x02 => Ok(SupplyStatus::NotHeld),
            0x03 => Ok(SupplyStatus::Resent),
            _ => Err(Error::Malformed),
        }
    }
}

/// The four fields that a request and its supply share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRequest {
    /// The scope.
    pub scope: KeyScope,
    /// The session identifier or the `group_id`.
    pub id: [u8; 32],
    /// The ratchet epoch, the group epoch lacked, or the roster epoch held.
    pub epoch: u32,
    /// The `send_index` of the record. For scope `0x02`: 0 for the member
    /// that sent it, or 1 plus the member index of the member that lacks
    /// the epoch, when another carries it (`WIR-523`). For scope `0x03`: 0.
    pub index: u32,
}

impl KeyRequest {
    fn check(&self) -> Result<(), Error> {
        let bound = match self.scope {
            KeyScope::Session => u32::MAX,
            KeyScope::GroupEpoch => u32::from(u16::MAX) + 1,
            KeyScope::RosterSnapshot => 0,
        };
        if self.index > bound {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn put(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(0x01)?;
        w.u8(self.scope as u8)?;
        w.put(&self.id)?;
        w.u32(self.epoch)?;
        w.u32(self.index)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let out = KeyRequest {
            scope: KeyScope::from_byte(r.u8()?)?,
            id: r.array()?,
            epoch: r.u32()?,
            index: r.u32()?,
        };
        out.check()?;
        Ok(out)
    }

    /// Writes the request.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        self.put(&mut w)?;
        Ok(w.position())
    }

    /// Reads a request (`WIR-332`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = Self::read(&mut r)?;
        r.finish()?;
        Ok(out)
    }
}

/// The answer to a key request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySupply<'a> {
    /// The request it answers.
    pub request: KeyRequest,
    /// The status.
    pub status: SupplyStatus,
    /// Empty in each scope of this draft.
    pub body: &'a [u8],
}

impl<'a> KeySupply<'a> {
    /// Writes the supply.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.request.check()?;
        let mut w = Writer::new(out);
        self.request.put(&mut w)?;
        w.u8(self.status as u8)?;
        w.u16(u16::try_from(self.body.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.body)?;
        Ok(w.position())
    }

    /// Reads a supply (`WIR-332`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let request = KeyRequest::read(&mut r)?;
        let status = SupplyStatus::from_byte(r.u8()?)?;
        let body_len = usize::from(r.u16()?);
        let body = r.take(body_len)?;
        r.finish()?;
        Ok(KeySupply {
            request,
            status,
            body,
        })
    }
}

/// The key-change notice of Part 4 §4.5.1. It carries no signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChangeNotice<'a> {
    /// The new X25519 public key.
    pub new_x25519_pk: [u8; 32],
    /// The new ML-KEM-768 encapsulation key.
    pub new_mlkem_pk: &'a [u8],
}

impl<'a> KeyChangeNotice<'a> {
    /// Writes the notice.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.new_mlkem_pk.len() != 1_184 {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.new_x25519_pk)?;
        w.put(self.new_mlkem_pk)?;
        Ok(w.position())
    }

    /// Reads a notice.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != KEY_CHANGE_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        Ok(KeyChangeNotice {
            new_x25519_pk: r.array()?,
            new_mlkem_pk: r.take(1_184)?,
        })
    }
}

/// The source of a transparency digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DigestSource {
    /// The Part 9 tree head.
    TreeHead = 0x01,
    /// The Part 10 consensus root.
    ConsensusRoot = 0x02,
    /// The Part 16 §16.5 release log head.
    ReleaseLog = 0x03,
}

/// A transparency digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestBody {
    /// The source.
    pub source: DigestSource,
    /// The epoch or the tree size the digest names.
    pub epoch: u64,
    /// The digest.
    pub digest: [u8; 32],
}

impl DigestBody {
    /// Writes the body.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.source as u8)?;
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.digest)?;
        Ok(w.position())
    }

    /// Reads a body (`WIR-151`, `WIR-152`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DIGEST_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let source = match r.u8()? {
            0x01 => DigestSource::TreeHead,
            0x02 => DigestSource::ConsensusRoot,
            0x03 => DigestSource::ReleaseLog,
            _ => return Err(Error::Malformed),
        };
        Ok(DigestBody {
            source,
            epoch: u64::from_be_bytes(r.array()?),
            digest: r.array()?,
        })
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
    fn the_request_and_the_supply_hold_each_scope_and_status() {
        let mut out = [0u8; 100];
        for (scope, index) in [
            (KeyScope::Session, 7),
            (KeyScope::GroupEpoch, 0),
            (KeyScope::RosterSnapshot, 0),
        ] {
            let req = KeyRequest {
                scope,
                id: [1; 32],
                epoch: 3,
                index,
            };
            assert_eq!(req.encode(&mut out).unwrap(), REQUEST_LEN);
            assert_eq!(KeyRequest::parse(&out[..42]).unwrap(), req);
            for status in [
                SupplyStatus::Posted,
                SupplyStatus::NotHeld,
                SupplyStatus::Resent,
            ] {
                let sup = KeySupply {
                    request: req,
                    status,
                    body: b"",
                };
                assert_eq!(sup.encode(&mut out).unwrap(), SUPPLY_LEN);
                assert_eq!(KeySupply::parse(&out[..45]).unwrap(), sup);
            }
        }
        // WIR-523: scope 0x02 names a member as 1 plus its index, and no
        // index above the member range; scope 0x03 names none.
        let carried = KeyRequest {
            scope: KeyScope::GroupEpoch,
            id: [1; 32],
            epoch: 3,
            index: 1,
        };
        assert!(carried.encode(&mut out).is_ok());
        let beyond = KeyRequest {
            index: u32::from(u16::MAX) + 2,
            ..carried
        };
        assert!(beyond.encode(&mut out).is_err());
        let bad = KeyRequest {
            scope: KeyScope::RosterSnapshot,
            index: 1,
            ..carried
        };
        assert!(bad.encode(&mut out).is_err());
        out[1] = 0x04;
        assert!(KeySupply::parse(&out[..45]).is_err());
        out[1] = 0x01;
        out[42] = 0x04;
        assert!(KeySupply::parse(&out[..45]).is_err());
    }

    #[test]
    fn the_notice_and_the_digest_hold_their_lengths() {
        let mut out = [0u8; 1_300];
        let notice = KeyChangeNotice {
            new_x25519_pk: [1; 32],
            new_mlkem_pk: &[2; 1_184],
        };
        assert_eq!(notice.encode(&mut out).unwrap(), KEY_CHANGE_LEN);
        assert_eq!(KeyChangeNotice::parse(&out[..1_217]).unwrap(), notice);
        assert!(KeyChangeNotice::parse(&out[..1_216]).is_err());
        let digest = DigestBody {
            source: DigestSource::ReleaseLog,
            epoch: 9,
            digest: [3; 32],
        };
        assert_eq!(digest.encode(&mut out).unwrap(), DIGEST_LEN);
        assert_eq!(DigestBody::parse(&out[..42]).unwrap(), digest);
        assert!(DigestBody::parse(&out[..43]).is_err());
        out[1] = 0x04;
        assert!(DigestBody::parse(&out[..42]).is_err());
    }
}
