//! The RFC 9297 capsule of Part 6 §6.2.1, the L1 framing.
//!
//! The two varints hold one form each: `type` in the 2-byte form and
//! `length` in the 4-byte form (`WIR-216`, `WIR-217`). Thus the header is 6
//! bytes at each bucket, and a receiver takes the cell length from it.

use crate::{
    bucket::Bucket,
    codec::{Reader, Writer},
    session::SESSION_FRAME_OVERHEAD,
    Error,
};

/// The capsule header length.
pub const HEADER_LEN: usize = 6;

/// The capsule type. The list is closed (`WIR-218`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CapsuleType {
    /// A `SessionFrame` of §6.2.2.
    Cell = 0x0B52,
    /// A session control record of §6.2.3.
    Session = 0x0B53,
    /// One `CRPUT` between two relays, outside each session (`WIR-211`).
    Replica = 0x0B54,
    /// One `SEND` of a relay into a queue at another relay, outside each
    /// session: the digest of a group or a community (`WIR-526`).
    Deposit = 0x0B55,
}

/// The value of an `UMBRA_REPLICA` capsule: the command header, and the
/// 32 682 bytes of a `CRPUT` payload (`WIR-213`).
pub const REPLICA_LEN: usize = crate::bucket::COMMAND_HEADER + 32 + 32_650;

/// The value of an `UMBRA_DEPOSIT` capsule: one `SEND` of bucket `B0`, with
/// its header (`WIR-526`).
pub const DEPOSIT_LEN: usize =
    crate::bucket::COMMAND_HEADER + crate::bucket::Bucket::B0.l6_record();

impl CapsuleType {
    const fn from_value(v: u64) -> Result<Self, Error> {
        match v {
            0x0B52 => Ok(CapsuleType::Cell),
            0x0B53 => Ok(CapsuleType::Session),
            0x0B54 => Ok(CapsuleType::Replica),
            0x0B55 => Ok(CapsuleType::Deposit),
            _ => Err(Error::Malformed),
        }
    }
}

/// Writes one capsule and returns its length.
pub fn encode(kind: CapsuleType, value: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    check_value_len(kind, value.len())?;
    let len = u32::try_from(value.len()).map_err(|_| Error::Capacity)?;
    let mut w = Writer::new(out);
    // The 2-byte form carries prefix 01, and the 4-byte form prefix 10.
    w.u16(0x4000 | kind as u16)?;
    w.u32(0x8000_0000 | len)?;
    w.put(value)?;
    Ok(w.position())
}

/// Reads one capsule from the front of `bytes`. Returns its type, its
/// value, and the count of bytes it took, thus a stream parses in a loop.
pub fn parse(bytes: &[u8]) -> Result<(CapsuleType, &[u8], usize), Error> {
    let mut r = Reader::new(bytes);
    let kind_raw = r.u16()?;
    if kind_raw >> 14 != 0b01 {
        return Err(Error::Malformed);
    }
    let kind = CapsuleType::from_value(u64::from(kind_raw & 0x3FFF))?;
    let len_raw = r.u32()?;
    if len_raw >> 30 != 0b10 {
        return Err(Error::Malformed);
    }
    let len = usize::try_from(len_raw & 0x3FFF_FFFF).map_err(|_| Error::Malformed)?;
    check_value_len(kind, len)?;
    let value = r.take(len)?;
    Ok((kind, value, r.position()))
}

fn check_value_len(kind: CapsuleType, len: usize) -> Result<(), Error> {
    match kind {
        CapsuleType::Cell => {
            // WIR-220: the value is a SessionFrame of one bucket.
            let cell = len
                .checked_sub(SESSION_FRAME_OVERHEAD)
                .ok_or(Error::Malformed)?;
            Bucket::from_cell_len(cell)
                .map(|_| ())
                .ok_or(Error::Malformed)
        }
        // WIR-221: the session parser checks the length against its op.
        CapsuleType::Session => {
            if crate::session::CONTROL_LENS.contains(&len) {
                Ok(())
            } else {
                Err(Error::Malformed)
            }
        }
        // WIR-213: one length.
        CapsuleType::Replica => {
            if len == REPLICA_LEN {
                Ok(())
            } else {
                Err(Error::Malformed)
            }
        }
        // WIR-526: one length.
        CapsuleType::Deposit => {
            if len == DEPOSIT_LEN {
                Ok(())
            } else {
                Err(Error::Malformed)
            }
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
    fn a_cell_capsule_round_trips_at_each_bucket() {
        for bucket in Bucket::ALL {
            let frame = vec![5u8; bucket.cell_len() + SESSION_FRAME_OVERHEAD];
            let mut out = vec![0u8; frame.len() + HEADER_LEN];
            let n = encode(CapsuleType::Cell, &frame, &mut out).unwrap();
            assert_eq!(n, out.len());
            assert_eq!(&out[..2], &[0x4B, 0x52]);
            let (kind, value, used) = parse(&out).unwrap();
            assert_eq!(kind, CapsuleType::Cell);
            assert_eq!(value, &frame[..]);
            assert_eq!(used, n);
        }
    }

    #[test]
    fn the_rejections_of_wir_295_hold() {
        let frame = vec![5u8; 524];
        let mut out = vec![0u8; 530];
        encode(CapsuleType::Cell, &frame, &mut out).unwrap();
        // A type of 0x0B54.
        let mut bad = out.clone();
        bad[1] = 0x54;
        assert!(parse(&bad).is_err());
        // A type in the 4-byte form.
        let mut bad = vec![0x80, 0x00, 0x0B, 0x52];
        bad.extend_from_slice(&out[2..]);
        assert!(parse(&bad).is_err());
        // A length in the 2-byte form.
        let mut bad = out[..2].to_vec();
        bad.extend_from_slice(&[0x42, 0x0C]);
        bad.extend_from_slice(&frame);
        assert!(parse(&bad).is_err());
        // A cell capsule of length 525.
        let mut bad = vec![0u8; 531];
        assert!(encode(CapsuleType::Cell, &vec![5u8; 525], &mut bad).is_err());
        bad[..6].copy_from_slice(&[0x4B, 0x52, 0x80, 0x00, 0x02, 0x0D]);
        assert!(parse(&bad).is_err());
        // A SessionResume of length 41.
        let mut bad = vec![0u8; 47];
        bad[..6].copy_from_slice(&[0x4B, 0x53, 0x80, 0x00, 0x00, 0x29]);
        bad[6] = 0x02;
        assert!(crate::session::SessionControl::parse(parse(&bad).unwrap().1).is_err());
        // A truncated value.
        assert!(parse(&out[..529]).is_err());
    }
}
