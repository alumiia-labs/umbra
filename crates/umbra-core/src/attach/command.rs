//! The twelve chunk commands of Part 13 §13.3.3 and their payloads. The
//! command header is the one of Part 6 §6.4, with the `chunk_id` in the
//! `queue_id` field.

use alloc::vec::Vec;

use umbra_wire::{
    admission::Admission,
    codec::{Reader, Writer},
};

use super::{CHUNK_SIZE, HOT_REPLICAS};
use crate::Error;

/// The length of a `storage_token`.
pub const TOKEN_LEN: usize = 32;
/// The length of a `CVFY` nonce.
pub const NONCE_LEN: usize = 16;
/// The length of a `CPRF` proof.
pub const PROOF_LEN: usize = 32;
/// One `ReplicaTarget`.
pub const TARGET_LEN: usize = 64;
/// The length of a `CRPUT` payload.
pub const CRPUT_LEN: usize = TOKEN_LEN + CHUNK_SIZE;

/// A chunk command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkCmd {
    /// Registers an attachment chunk.
    Cnew = 0x70,
    /// Answers a registration with the storage token.
    Cid = 0x71,
    /// Uploads the chunk.
    Cput = 0x72,
    /// Fetches the chunk.
    Cget = 0x73,
    /// Answers a fetch with the chunk.
    Cdat = 0x74,
    /// Erases the chunk.
    Cdel = 0x75,
    /// Names the replica targets.
    Crep = 0x76,
    /// Pushes a copy to a target, relay to relay.
    Crput = 0x77,
    /// Asks for a proof of possession.
    Cvfy = 0x78,
    /// Answers with the proof.
    Cprf = 0x79,
    /// Renews the erase time.
    Crnw = 0x7A,
    /// Registers a backup-class chunk.
    Bnew = 0x7B,
}

/// The party whose credential authorizes a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorizer {
    /// `cred_pk` of the chunk (`ATT-040`).
    Cred,
    /// `read_pk` of the chunk (`ATT-041`).
    Read,
    /// The `storage_token` of the registration (`ATT-107`).
    Token,
    /// The relay sends it, under the session.
    Relay,
}

impl ChunkCmd {
    /// The command of a byte.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x70 => ChunkCmd::Cnew,
            0x71 => ChunkCmd::Cid,
            0x72 => ChunkCmd::Cput,
            0x73 => ChunkCmd::Cget,
            0x74 => ChunkCmd::Cdat,
            0x75 => ChunkCmd::Cdel,
            0x76 => ChunkCmd::Crep,
            0x77 => ChunkCmd::Crput,
            0x78 => ChunkCmd::Cvfy,
            0x79 => ChunkCmd::Cprf,
            0x7A => ChunkCmd::Crnw,
            0x7B => ChunkCmd::Bnew,
            _ => return Err(Error::Malformed),
        })
    }

    /// The byte.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Whose credential authorizes the command.
    pub const fn authorizer(self) -> Authorizer {
        match self {
            ChunkCmd::Cnew
            | ChunkCmd::Bnew
            | ChunkCmd::Cput
            | ChunkCmd::Cdel
            | ChunkCmd::Crep
            | ChunkCmd::Cvfy => Authorizer::Cred,
            ChunkCmd::Cget | ChunkCmd::Crnw => Authorizer::Read,
            ChunkCmd::Crput => Authorizer::Token,
            ChunkCmd::Cid | ChunkCmd::Cdat | ChunkCmd::Cprf => Authorizer::Relay,
        }
    }

    /// Whether a relay sends it.
    pub const fn relay_sent(self) -> bool {
        matches!(self.authorizer(), Authorizer::Relay | Authorizer::Token)
    }

    /// Whether the payload is one chunk of `CHUNK_SIZE` bytes (`ATT-043`).
    pub const fn carries_chunk(self) -> bool {
        matches!(self, ChunkCmd::Cput | ChunkCmd::Cdat)
    }
}

/// The payload of `CNEW` and of `BNEW`.
pub struct RegisterPayload<'a> {
    /// The write credential.
    pub cred_pk: [u8; 32],
    /// The read credential.
    pub read_pk: [u8; 32],
    /// The admission trailer of Part 14 §14.2.
    pub admission: Admission<'a>,
}

impl<'a> RegisterPayload<'a> {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.cred_pk)?;
        w.put(&self.read_pk)?;
        let n = self.admission.encode(w.tail())?;
        Ok(w.position().saturating_add(n))
    }

    /// Reads the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let cred_pk = r.array()?;
        let read_pk = r.array()?;
        let (admission, used) = Admission::parse(r.rest())?;
        if used != bytes.len().saturating_sub(64) {
            return Err(Error::Malformed);
        }
        Ok(RegisterPayload {
            cred_pk,
            read_pk,
            admission,
        })
    }
}

/// Reads a payload that is one 32-byte value: a `CID` token or a `CPRF`
/// proof.
pub fn fixed_payload<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Malformed)
}

/// Reads a `CPUT` or a `CDAT` payload (`ATT-043`, `ATT-044`).
pub fn chunk_payload(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.len() != CHUNK_SIZE {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}

/// One target of a `CREP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaTarget {
    /// The relay that takes the copy.
    pub relay_id: [u8; 32],
    /// The token that the `CID` of that relay gave.
    pub storage_token: [u8; TOKEN_LEN],
}

/// The payload of `CREP` (§13.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrepPayload {
    /// The targets, one per replica after the one that took the `CPUT`.
    pub targets: Vec<ReplicaTarget>,
}

impl CrepPayload {
    /// The encoded length.
    pub fn len(&self) -> usize {
        2usize.saturating_add(self.targets.len().saturating_mul(TARGET_LEN))
    }

    /// Whether no target is named. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    fn check(&self) -> Result<(), Error> {
        if self.targets.is_empty() || self.targets.len() >= HOT_REPLICAS {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(u8::try_from(self.targets.len()).map_err(|_| Error::Malformed)?)?;
        for t in &self.targets {
            w.put(&t.relay_id)?;
            w.put(&t.storage_token)?;
        }
        Ok(w.position())
    }

    /// Reads the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let count = usize::from(r.u8()?);
        let mut targets = Vec::with_capacity(count);
        for _ in 0..count {
            targets.push(ReplicaTarget {
                relay_id: r.array()?,
                storage_token: r.array()?,
            });
        }
        r.finish()?;
        let out = CrepPayload { targets };
        out.check()?;
        Ok(out)
    }
}

/// The payload of `CRPUT`.
pub struct CrputPayload<'a> {
    /// The token that the target issued.
    pub storage_token: [u8; TOKEN_LEN],
    /// The chunk, without a change from the `CPUT` (`ATT-104`).
    pub chunk: &'a [u8],
}

impl<'a> CrputPayload<'a> {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        chunk_payload(self.chunk)?;
        let mut w = Writer::new(out);
        w.put(&self.storage_token)?;
        w.put(self.chunk)?;
        Ok(w.position())
    }

    /// Reads the payload (`ATT-111`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != CRPUT_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        let storage_token = r.array()?;
        let chunk = chunk_payload(r.rest())?;
        Ok(CrputPayload {
            storage_token,
            chunk,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_twelve_commands_map_and_name_their_authorizer() {
        for b in 0x70u8..=0x7B {
            assert_eq!(ChunkCmd::from_byte(b).unwrap().to_byte(), b);
        }
        assert!(ChunkCmd::from_byte(0x7C).is_err());
        assert_eq!(ChunkCmd::Cput.authorizer(), Authorizer::Cred);
        assert_eq!(ChunkCmd::Cget.authorizer(), Authorizer::Read);
        assert_eq!(ChunkCmd::Crput.authorizer(), Authorizer::Token);
        assert!(ChunkCmd::Cid.relay_sent());
        assert!(!ChunkCmd::Bnew.relay_sent());
        assert!(ChunkCmd::Cdat.carries_chunk());
    }

    #[test]
    fn each_payload_round_trips_at_its_width() {
        let reg = RegisterPayload {
            cred_pk: [1; 32],
            read_pk: [2; 32],
            admission: Admission::NONE,
        };
        let mut out = [0u8; 128];
        let n = reg.encode(&mut out).unwrap();
        assert_eq!(n, 67);
        let back = RegisterPayload::parse(&out[..n]).unwrap();
        assert_eq!(back.read_pk, [2; 32]);
        assert!(RegisterPayload::parse(&out[..n + 1]).is_err());

        let crep = CrepPayload {
            targets: alloc::vec![
                ReplicaTarget {
                    relay_id: [3; 32],
                    storage_token: [4; 32],
                },
                ReplicaTarget {
                    relay_id: [5; 32],
                    storage_token: [6; 32],
                },
            ],
        };
        let mut out = [0u8; 400];
        let n = crep.encode(&mut out).unwrap();
        assert_eq!(n, 130);
        assert_eq!(CrepPayload::parse(&out[..n]).unwrap(), crep);
        assert!(CrepPayload::parse(&out[..n - 1]).is_err());
        let empty = CrepPayload {
            targets: Vec::new(),
        };
        assert!(empty.encode(&mut out).is_err());
        let too_many = CrepPayload {
            targets: alloc::vec![crep.targets[0]; HOT_REPLICAS],
        };
        assert!(too_many.encode(&mut out).is_err());

        let chunk = alloc::vec![7u8; CHUNK_SIZE];
        let crput = CrputPayload {
            storage_token: [8; 32],
            chunk: &chunk,
        };
        let mut out = alloc::vec![0u8; CRPUT_LEN + 1];
        assert_eq!(crput.encode(&mut out).unwrap(), 32_682);
        let back = CrputPayload::parse(&out[..CRPUT_LEN]).unwrap();
        assert_eq!(back.storage_token, [8; 32]);
        assert!(CrputPayload::parse(&out).is_err());
        assert!(chunk_payload(&chunk[..CHUNK_SIZE - 1]).is_err());
        assert_eq!(fixed_payload::<32>(&[9; 32]).unwrap(), [9; 32]);
        assert!(fixed_payload::<32>(&[9; 31]).is_err());
    }
}
