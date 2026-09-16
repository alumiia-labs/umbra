//! The ratchet record of Part 6 §6.5 (L7), as a structural parser.
//!
//! The crypto crate makes and opens these bytes. This parser gives a
//! receiver the fields it reads without a key: the context, the braid
//! frame, and the split of the record, with each rejection of `WIR-255` to
//! `WIR-258` and `WIR-349`.

use umbra_crypto::ratchet::{
    codeword::{Kind, Width},
    dr::{Ctx, HDR_CT_LEN, VERSION},
};

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The four `pq_frame_len` values.
pub const FRAME_LENS: [usize; 4] = [0, 39, 71, 135];
/// The body tag length.
pub const BODY_TAG_LEN: usize = 16;

/// A braid frame, read without a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqFrame<'a> {
    /// The braid epoch of Part 5 §5.5.2.
    pub epoch: u32,
    /// The chunk kind.
    pub kind: Kind,
    /// The chunk index.
    pub index: u16,
    /// The chunk.
    pub chunk: &'a [u8],
}

/// A ratchet record split into its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetRecord<'a> {
    /// The context field.
    pub ctx: Ctx,
    /// The header nonce.
    pub hdr_nonce: [u8; 12],
    /// The encrypted header and its tag.
    pub hdr_ct: &'a [u8],
    /// The braid frame, if any.
    pub pq_frame: Option<PqFrame<'a>>,
    /// The body nonce.
    pub body_nonce: [u8; 12],
    /// The encrypted body and its tag.
    pub body_ct: &'a [u8],
}

impl<'a> RatchetRecord<'a> {
    /// Reads a record. The crypto crate opens the two ciphertexts.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let ctx = Ctx {
            session_tag: r.array()?,
            send_index: r.u16()?,
        };
        let hdr_nonce = r.array()?;
        let hdr_ct = r.take(HDR_CT_LEN)?;
        let frame_len = usize::from(r.u8()?);
        if !FRAME_LENS.contains(&frame_len) {
            return Err(Error::Malformed);
        }
        let pq_frame = if frame_len == 0 {
            None
        } else {
            let epoch = r.u32()?;
            let kind = Kind::from_byte(r.u8()?)?;
            let index = r.u16()?;
            let width =
                Width::from_frame_len(u8::try_from(frame_len).map_err(|_| Error::Malformed)?)?;
            // WIR-258 and CRY-082: the index is inside the codeword, and the
            // kind is the one that position holds.
            if width.kind_at(usize::from(index))? != kind {
                return Err(Error::Malformed);
            }
            Some(PqFrame {
                epoch,
                kind,
                index,
                chunk: r.take(width.bytes())?,
            })
        };
        let body_nonce = r.array()?;
        let body_ct = r.rest();
        if body_ct.len() < BODY_TAG_LEN {
            return Err(Error::Malformed);
        }
        Ok(RatchetRecord {
            ctx,
            hdr_nonce,
            hdr_ct,
            pq_frame,
            body_nonce,
            body_ct,
        })
    }

    /// Writes the record from its fields, for a test vector. A protocol
    /// path takes the bytes from the crypto crate.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        w.put(&self.ctx.session_tag)?;
        w.u16(self.ctx.send_index)?;
        w.put(&self.hdr_nonce)?;
        if self.hdr_ct.len() != HDR_CT_LEN {
            return Err(Error::Malformed);
        }
        w.put(self.hdr_ct)?;
        match self.pq_frame {
            None => w.u8(0)?,
            Some(f) => {
                let width = Width::from_frame_len(
                    u8::try_from(7usize.saturating_add(f.chunk.len()))
                        .map_err(|_| Error::Malformed)?,
                )?;
                if width.kind_at(usize::from(f.index))? != f.kind {
                    return Err(Error::Malformed);
                }
                w.u8(width.frame_len())?;
                w.u32(f.epoch)?;
                w.u8(f.kind as u8)?;
                w.u16(f.index)?;
                w.put(f.chunk)?;
            }
        }
        w.put(&self.body_nonce)?;
        w.put(self.body_ct)?;
        Ok(w.position())
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

    fn record(frame: Option<PqFrame<'static>>) -> RatchetRecord<'static> {
        RatchetRecord {
            ctx: Ctx {
                session_tag: [1, 2],
                send_index: 65_535,
            },
            hdr_nonce: [3; 12],
            hdr_ct: &[4; HDR_CT_LEN],
            pq_frame: frame,
            body_nonce: [5; 12],
            body_ct: &[6; 20],
        }
    }

    #[test]
    fn a_record_at_each_frame_length_round_trips() {
        let mut out = vec![0u8; 300];
        let n = record(None).encode(&mut out).unwrap();
        assert_eq!(n, 86 + 20);
        assert_eq!(RatchetRecord::parse(&out[..n]).unwrap(), record(None));
        for (width, chunk) in [
            (Width::W32, &[7u8; 128][..32]),
            (Width::W64, &[7u8; 128][..64]),
            (Width::W128, &[7u8; 128][..128]),
        ] {
            let frame = PqFrame {
                epoch: 256,
                kind: Kind::Header,
                index: 0,
                chunk,
            };
            let rec = record(Some(frame));
            let n = rec.encode(&mut out).unwrap();
            assert_eq!(n, 106 + usize::from(width.frame_len()));
            assert_eq!(RatchetRecord::parse(&out[..n]).unwrap(), rec);
        }
        // A parity chunk at index 36 of the 64-byte width (WIR-298).
        let parity = PqFrame {
            epoch: 255,
            kind: Kind::Parity,
            index: 36,
            chunk: &[7; 64],
        };
        let n = record(Some(parity)).encode(&mut out).unwrap();
        assert!(RatchetRecord::parse(&out[..n]).is_ok());
    }

    #[test]
    fn the_rejections_of_wir_299_hold() {
        let mut out = vec![0u8; 300];
        let frame = PqFrame {
            epoch: 1,
            kind: Kind::Header,
            index: 0,
            chunk: &[7; 64],
        };
        let n = record(Some(frame)).encode(&mut out).unwrap();
        let mut bad = out.clone();
        bad[73] = 68;
        assert!(RatchetRecord::parse(&bad[..n]).is_err());
        let mut bad = out.clone();
        bad[79] = 0;
        bad[80] = 41;
        assert!(RatchetRecord::parse(&bad[..n]).is_err());
        let mut bad = out.clone();
        bad[0] = 0x01;
        assert!(RatchetRecord::parse(&bad[..n]).is_err());
        let mut bad = out.clone();
        bad[78] = 0x05;
        assert!(RatchetRecord::parse(&bad[..n]).is_err());
        bad[78] = 0x00;
        assert!(RatchetRecord::parse(&bad[..n]).is_err());
        bad[78] = 0x07;
        assert!(RatchetRecord::parse(&bad[..n]).is_err());
        assert!(RatchetRecord::parse(&out[..n - 5]).is_err());
    }
}
