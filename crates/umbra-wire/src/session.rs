//! The session frame (L2) and the session control records of Part 6 §6.2.2
//! and §6.2.3.
//!
//! The frame is not a reliability layer. It gives each direction of a
//! session one count, and the two ends of a resume compare those counts:
//! a resume holds only when no frame is lost.

use umbra_crypto::{auth, secret::Secret};

use crate::{
    bucket::Bucket,
    codec::{Reader, Writer},
    Error,
};

/// The frame overhead: `session_id`, `seq`, and `flags`.
pub const SESSION_FRAME_OVERHEAD: usize = 12;
/// The lengths of the control records, by op from `0x01` to `0x07`.
pub const CONTROL_LENS: [usize; 7] = [41, 37, 9, 17, 9, 9, 17];
/// The highest `seq` a frame carries.
pub const SEQ_MAX: u32 = 0x00FF_FFFF;

/// A session frame around one cell.
pub struct SessionFrame<'a> {
    /// The session identifier, from the device CSPRNG at the open.
    pub session_id: [u8; 8],
    /// The frame index in this session.
    pub seq: u32,
    /// Bit 0 of `flags`, which v1 reserves and sends as zero (`WIR-140`).
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
    /// Op `0x02`, 37 bytes.
    Resume {
        /// The session to bind to this connection.
        session_id: [u8; 8],
        /// 1 at the first resume, then increasing.
        resume_count: u32,
        /// The next frame sequence of the client.
        sent: u32,
        /// The count of the relay frames that the client accepted.
        received: u32,
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
    /// Op `0x05`, 9 bytes: the client sends no further frame on this
    /// connection, and the relay parks the session.
    Pause {
        /// The session that pauses.
        session_id: [u8; 8],
    },
    /// Op `0x06`, 9 bytes: the relay parked the session, and it sends no
    /// further frame on this connection.
    Paused {
        /// The session that the relay parked.
        session_id: [u8; 8],
    },
    /// Op `0x07`, 17 bytes: the client of the circuit of this `circ_id` on
    /// this link reads no cell until it resumes its session.
    CircuitPause {
        /// The circuit on this link.
        circ_id: [u8; 16],
    },
}

impl SessionControl {
    /// A resume with its `auth` computed from the session secret.
    pub fn resume(
        session_secret: &Secret<32>,
        session_id: [u8; 8],
        resume_count: u32,
        sent: u32,
        received: u32,
    ) -> Self {
        SessionControl::Resume {
            session_id,
            resume_count,
            sent,
            received,
            auth: auth::session_resume_auth(
                session_secret,
                &session_id,
                resume_count,
                sent,
                received,
            ),
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
                sent,
                received,
                auth,
            } => {
                w.u8(0x02)?;
                w.put(session_id)?;
                w.u32(*resume_count)?;
                w.u32(*sent)?;
                w.u32(*received)?;
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
            SessionControl::Pause { session_id } => {
                w.u8(0x05)?;
                w.put(session_id)?;
            }
            SessionControl::Paused { session_id } => {
                w.u8(0x06)?;
                w.put(session_id)?;
            }
            SessionControl::CircuitPause { circ_id } => {
                w.u8(0x07)?;
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
                sent: r.u32()?,
                received: r.u32()?,
                auth: r.array()?,
            },
            0x03 => SessionControl::Close {
                session_id: r.array()?,
            },
            0x04 => SessionControl::Destroy {
                circ_id: r.array()?,
            },
            0x05 => SessionControl::Pause {
                session_id: r.array()?,
            },
            0x06 => SessionControl::Paused {
                session_id: r.array()?,
            },
            0x07 => SessionControl::CircuitPause {
                circ_id: r.array()?,
            },
            _ => return Err(Error::Malformed),
        };
        r.finish()?;
        Ok(out)
    }

    /// Verifies a resume against the secret and the last accepted count
    /// (`WIR-237`, `WIR-238`). The result is the count and the two frame
    /// counts of the record, which the caller compares with its own.
    pub fn verify_resume(
        &self,
        session_secret: &Secret<32>,
        expected_id: &[u8; 8],
        last_accepted: u32,
    ) -> Result<(u32, u32, u32), Error> {
        match self {
            SessionControl::Resume {
                session_id,
                resume_count,
                sent,
                received,
                auth: given,
            } if session_id == expected_id && *resume_count > last_accepted => {
                auth::verify_session_resume(
                    session_secret,
                    session_id,
                    *resume_count,
                    *sent,
                    *received,
                    given,
                )?;
                Ok((*resume_count, *sent, *received))
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

        let resume = SessionControl::resume(&secret, id, 1, 5, 6);
        let n = resume.encode(&mut buf).unwrap();
        assert_eq!(n, 37);
        let parsed = SessionControl::parse(&buf[..37]).unwrap();
        assert_eq!(parsed.verify_resume(&secret, &id, 0).unwrap(), (1, 5, 6));
        // A repeated count and a changed auth bit both fail (WIR-297).
        assert!(parsed.verify_resume(&secret, &id, 1).is_err());
        buf[36] ^= 1;
        let bad = SessionControl::parse(&buf[..37]).unwrap();
        assert!(bad.verify_resume(&secret, &id, 0).is_err());
        // The `auth` covers the two frame counts.
        buf[36] ^= 1;
        buf[16] ^= 1;
        let moved = SessionControl::parse(&buf[..37]).unwrap();
        assert!(moved.verify_resume(&secret, &id, 0).is_err());
        assert!(SessionControl::parse(&buf[..29]).is_err());

        let close = SessionControl::Close { session_id: id };
        assert_eq!(close.encode(&mut buf).unwrap(), 9);
        assert!(SessionControl::parse(&buf[..9]).is_ok());
        assert!(SessionControl::parse(&buf[..10]).is_err());
        buf[0] = 0x04;
        assert!(SessionControl::parse(&buf[..9]).is_err());
    }

    #[test]
    fn the_pause_records_hold_their_ops_and_their_lengths() {
        let mut buf = [0u8; 17];
        let pause = SessionControl::Pause { session_id: [4; 8] };
        assert_eq!(pause.encode(&mut buf).unwrap(), 9);
        assert_eq!(buf[0], 0x05);
        assert!(matches!(
            SessionControl::parse(&buf[..9]),
            Ok(SessionControl::Pause { session_id }) if session_id == [4; 8]
        ));
        assert!(SessionControl::parse(&buf[..17]).is_err());

        let paused = SessionControl::Paused { session_id: [5; 8] };
        assert_eq!(paused.encode(&mut buf).unwrap(), 9);
        assert_eq!(buf[0], 0x06);
        assert!(matches!(
            SessionControl::parse(&buf[..9]),
            Ok(SessionControl::Paused { session_id }) if session_id == [5; 8]
        ));
        assert!(SessionControl::parse(&buf[..8]).is_err());

        let circuit = SessionControl::CircuitPause { circ_id: [6; 16] };
        assert_eq!(circuit.encode(&mut buf).unwrap(), 17);
        assert_eq!(buf[0], 0x07);
        assert!(matches!(
            SessionControl::parse(&buf),
            Ok(SessionControl::CircuitPause { circ_id }) if circ_id == [6; 16]
        ));
        assert!(SessionControl::parse(&buf[..9]).is_err());
        buf[0] = 0x08;
        assert!(SessionControl::parse(&buf).is_err());
    }
}
