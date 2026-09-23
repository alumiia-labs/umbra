//! The session frame (L2) and the session control records of Part 6 §6.2.2
//! and §6.2.3.
//!
//! The frame is not a reliability layer. It carries the resend marker that
//! lets a relay drop a duplicate without a decryption of the cell.

use umbra_crypto::{auth, secret::Secret};

use crate::{
    bucket::Bucket,
    codec::{Reader, Writer},
    Error,
};

/// The frame overhead: `session_id`, `seq`, and `flags`.
pub const SESSION_FRAME_OVERHEAD: usize = 12;
/// The lengths of the four control records, by op.
pub const CONTROL_LENS: [usize; 4] = [41, 29, 9, 17];
/// The highest `seq` a frame carries.
pub const SEQ_MAX: u32 = 0x00FF_FFFF;

/// A session frame around one cell.
pub struct SessionFrame<'a> {
    /// The session identifier, from the device CSPRNG at the open.
    pub session_id: [u8; 8],
    /// The frame index in this session.
    pub seq: u32,
    /// Bit 0 of `flags`: this frame is a resend.
    pub resend: bool,
    /// The cell, of one bucket.
    pub cell: &'a [u8],
}

impl<'a> SessionFrame<'a> {
    /// Writes the frame and returns its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        Bucket::from_cell_len(self.cell.len()).ok_or(Error::Malformed)?;
        let mut w = Writer::new(out);
        w.put(&self.session_id)?;
        w.u24(self.seq)?;
        w.u8(u8::from(self.resend))?;
        w.put(self.cell)?;
        Ok(w.position())
    }

    /// Reads a frame. Rejects a set reserved bit (`WIR-142`) and a cell of
    /// no bucket.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, Bucket), Error> {
        let mut r = Reader::new(bytes);
        let session_id = r.array()?;
        let seq = r.u24()?;
        let flags = r.u8()?;
        if flags & !0x01 != 0 {
            return Err(Error::Malformed);
        }
        let cell = r.rest();
        let bucket = Bucket::from_cell_len(cell.len()).ok_or(Error::Malformed)?;
        Ok((
            SessionFrame {
                session_id,
                seq,
                resend: flags & 0x01 != 0,
                cell,
            },
            bucket,
        ))
    }
}

/// A session control record in an `UMBRA_SESSION` capsule.
pub enum SessionControl {
    /// Op `0x01`, 41 bytes.
    Open {
        /// The new session identifier.
        session_id: [u8; 8],
        /// The secret that authenticates each later resume.
        session_secret: Secret<32>,
    },
    /// Op `0x02`, 29 bytes.
    Resume {
        /// The session to bind to this connection.
        session_id: [u8; 8],
        /// 1 at the first resume, then increasing.
        resume_count: u32,
        /// The authenticator of §6.2.3.
        auth: [u8; auth::RESUME_AUTH_LEN],
    },
    /// Op `0x03`, 9 bytes.
    Close {
        /// The session that ends.
        session_id: [u8; 8],
    },
    /// Op `0x04`, 17 bytes: the circuit of this `circ_id` on this link
    /// ended at the sender (`NET-322`).
    Destroy {
        /// The circuit on this link.
        circ_id: [u8; 16],
    },
}

impl SessionControl {
    /// A resume with its `auth` computed from the session secret.
    pub fn resume(session_secret: &Secret<32>, session_id: [u8; 8], resume_count: u32) -> Self {
        SessionControl::Resume {
            session_id,
            resume_count,
            auth: auth::session_resume_auth(session_secret, &session_id, resume_count),
        }
    }

    /// Writes the record and returns its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        match self {
            SessionControl::Open {
                session_id,
                session_secret,
            } => {
                w.u8(0x01)?;
                w.put(session_id)?;
                w.put(session_secret.expose())?;
            }
            SessionControl::Resume {
                session_id,
                resume_count,
                auth,
            } => {
                w.u8(0x02)?;
                w.put(session_id)?;
                w.u32(*resume_count)?;
                w.put(auth)?;
            }
            SessionControl::Close { session_id } => {
                w.u8(0x03)?;
                w.put(session_id)?;
            }
            SessionControl::Destroy { circ_id } => {
                w.u8(0x04)?;
                w.put(circ_id)?;
            }
        }
        Ok(w.position())
    }

    /// Reads a record. The length must match the op (`WIR-221`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = match r.u8()? {
            0x01 => SessionControl::Open {
                session_id: r.array()?,
                session_secret: Secret::new(r.array()?),
            },
            0x02 => SessionControl::Resume {
                session_id: r.array()?,
                resume_count: r.u32()?,
                auth: r.array()?,
            },
            0x03 => SessionControl::Close {
                session_id: r.array()?,
            },
            0x04 => SessionControl::Destroy {
                circ_id: r.array()?,
            },
            _ => return Err(Error::Malformed),
        };
        r.finish()?;
        Ok(out)
    }

    /// Verifies a resume against the secret and the last accepted count
    /// (`WIR-237`, `WIR-238`).
    pub fn verify_resume(
        &self,
        session_secret: &Secret<32>,
        expected_id: &[u8; 8],
        last_accepted: u32,
    ) -> Result<u32, Error> {
        match self {
            SessionControl::Resume {
                session_id,
                resume_count,
                auth: given,
            } if session_id == expected_id && *resume_count > last_accepted => {
                auth::verify_session_resume(session_secret, session_id, *resume_count, given)?;
                Ok(*resume_count)
            }
            _ => Err(Error::Malformed),
        }
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
    fn the_frame_round_trips_and_rejects_a_reserved_bit() {
        let cell = vec![1u8; 512];
        let frame = SessionFrame {
            session_id: [2; 8],
            seq: 0x0A_0B_0C,
            resend: true,
            cell: &cell,
        };
        let mut out = vec![0u8; 524];
        assert_eq!(frame.encode(&mut out).unwrap(), 524);
        let (back, bucket) = SessionFrame::parse(&out).unwrap();
        assert_eq!(bucket, Bucket::B0);
        assert_eq!(back.seq, 0x0A_0B_0C);
        assert!(back.resend);
        out[11] = 0x02;
        assert!(SessionFrame::parse(&out).is_err());
        out[11] = 0x00;
        assert!(SessionFrame::parse(&out[..523]).is_err());
    }

    #[test]
    fn the_control_records_hold_their_lengths_and_the_resume_verifies() {
        let secret = Secret::new([9u8; 32]);
        let id = [4u8; 8];
        let mut buf = [0u8; 41];
        let open = SessionControl::Open {
            session_id: id,
            session_secret: Secret::new([9u8; 32]),
        };
        assert_eq!(open.encode(&mut buf).unwrap(), 41);
        assert!(SessionControl::parse(&buf).is_ok());
        assert!(SessionControl::parse(&buf[..40]).is_err());

        let resume = SessionControl::resume(&secret, id, 1);
        let n = resume.encode(&mut buf).unwrap();
        assert_eq!(n, 29);
        let parsed = SessionControl::parse(&buf[..29]).unwrap();
        assert_eq!(parsed.verify_resume(&secret, &id, 0).unwrap(), 1);
        // A repeated count and a changed auth bit both fail (WIR-297).
        assert!(parsed.verify_resume(&secret, &id, 1).is_err());
        buf[28] ^= 1;
        let bad = SessionControl::parse(&buf[..29]).unwrap();
        assert!(bad.verify_resume(&secret, &id, 0).is_err());

        let close = SessionControl::Close { session_id: id };
        assert_eq!(close.encode(&mut buf).unwrap(), 9);
        assert!(SessionControl::parse(&buf[..9]).is_ok());
        assert!(SessionControl::parse(&buf[..10]).is_err());
        buf[0] = 0x04;
        assert!(SessionControl::parse(&buf[..9]).is_err());
    }
}
