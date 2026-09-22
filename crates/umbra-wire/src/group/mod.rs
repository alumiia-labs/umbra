//! The group-queue commands of Part 6 §6.4.5 and the group queue record of
//! §6.4.6.

pub mod control;
pub mod record;

use crate::{
    address::{self, QueueAddress},
    admission::Admission,
    bucket::Bucket,
    codec::{Reader, Writer},
    Error,
};

/// The eleven group-queue commands. The bytes `0x9B` to `0x9F` are rejected
/// (`WIR-368`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupCmd {
    /// Sent by the creator under the `own_sk` of its own payload
    /// (`WIR-517`).
    Gnew = 0x90,
    /// Sent by the relay.
    Gids = 0x91,
    /// Sent by a member under `write_sk`.
    Gpost = 0x92,
    /// Sent by the relay.
    Gseq = 0x93,
    /// Sent by a member under `read_sk`.
    Gsub = 0x94,
    /// Sent by the relay.
    Gmsg = 0x95,
    /// Sent by a member under `read_sk`.
    Gunsub = 0x96,
    /// Sent by an admin under `own_sk`.
    Gkey = 0x97,
    /// Sent by an admin under `own_sk`.
    Gdel = 0x98,
    /// Sent by a member under `read_sk`.
    Gnreg = 0x99,
    /// Sent by a member under `read_sk`.
    Gnunreg = 0x9A,
}

impl GroupCmd {
    /// The command of a byte, in this namespace only.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x90 => GroupCmd::Gnew,
            0x91 => GroupCmd::Gids,
            0x92 => GroupCmd::Gpost,
            0x93 => GroupCmd::Gseq,
            0x94 => GroupCmd::Gsub,
            0x95 => GroupCmd::Gmsg,
            0x96 => GroupCmd::Gunsub,
            0x97 => GroupCmd::Gkey,
            0x98 => GroupCmd::Gdel,
            0x99 => GroupCmd::Gnreg,
            0x9A => GroupCmd::Gnunreg,
            _ => return Err(Error::Malformed),
        })
    }

    /// The `payload_len` that §6.4.5 fixes for this command at `bucket`
    /// (`WIR-369` to `WIR-371`). A `GNEW` carries a variable admission body.
    pub const fn fixed_payload_len(self, bucket: Bucket) -> Option<usize> {
        match self {
            GroupCmd::Gnew => None,
            GroupCmd::Gids => Some(32),
            GroupCmd::Gpost => Some(bucket.group_record()),
            GroupCmd::Gseq => Some(GSEQ_LEN),
            GroupCmd::Gsub => Some(4),
            GroupCmd::Gmsg => Some(bucket.l5_payload()),
            GroupCmd::Gunsub | GroupCmd::Gdel => Some(0),
            GroupCmd::Gkey => Some(GKEY_LEN),
            GroupCmd::Gnreg | GroupCmd::Gnunreg => Some(NOTIFY_REGISTRATION_LEN),
        }
    }
}

/// The length of a `GNEW` payload at an empty admission.
pub const GNEW_NONE_LEN: usize = 99;
/// The length of a `GSEQ` payload.
pub const GSEQ_LEN: usize = 20;
/// The length of a `GKEY` payload.
pub const GKEY_LEN: usize = 96;
/// The length of a `GNREG` or `GNUNREG` payload.
pub const NOTIFY_REGISTRATION_LEN: usize = 1 + address::LEN;

/// The payload of `GNEW`.
pub struct GnewPayload<'a> {
    /// The reader credential of epoch 1.
    pub read_pk: [u8; 32],
    /// The writer credential of epoch 1.
    pub write_pk: [u8; 32],
    /// The owner credential.
    pub own_pk: [u8; 32],
    /// The admission trailer.
    pub admission: Admission<'a>,
}

impl<'a> GnewPayload<'a> {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.read_pk)?;
        w.put(&self.write_pk)?;
        w.put(&self.own_pk)?;
        let n = self.admission.encode(w.tail())?;
        Ok(w.position().saturating_add(n))
    }

    /// Reads the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let read_pk = r.array()?;
        let write_pk = r.array()?;
        let own_pk = r.array()?;
        let (admission, used) = Admission::parse(r.rest())?;
        if used != bytes.len().saturating_sub(96) {
            return Err(Error::Malformed);
        }
        Ok(GnewPayload {
            read_pk,
            write_pk,
            own_pk,
            admission,
        })
    }
}

/// The payload of `GSEQ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GseqPayload {
    /// The `corr_id` of the `GPOST` it acknowledges.
    pub corr_id: [u8; 16],
    /// The sequence number the relay gave the record.
    pub seq: u32,
}

impl GseqPayload {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.corr_id)?;
        w.u32(self.seq)?;
        Ok(w.position())
    }

    /// Reads the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = GseqPayload {
            corr_id: r.array()?,
            seq: r.u32()?,
        };
        r.finish()?;
        Ok(out)
    }
}

/// The payload of `GSUB`: the relay emits each record above this `seq`.
pub fn encode_gsub(from_seq: u32, out: &mut [u8]) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.u32(from_seq)?;
    Ok(w.position())
}

/// Reads a `GSUB` payload.
pub fn parse_gsub(bytes: &[u8]) -> Result<u32, Error> {
    let mut r = Reader::new(bytes);
    let from_seq = r.u32()?;
    r.finish()?;
    Ok(from_seq)
}

/// The payload of `GMSG`: the sequence the relay gave the record, then the
/// record itself (`WIR-371`, `WIR-372`).
pub fn encode_gmsg(
    seq: u32,
    record: &[u8],
    bucket: Bucket,
    out: &mut [u8],
) -> Result<usize, Error> {
    if record.len() != bucket.group_record() {
        return Err(Error::Malformed);
    }
    let mut w = Writer::new(out);
    w.u32(seq)?;
    w.put(record)?;
    Ok(w.position())
}

/// Splits a `GMSG` payload into its sequence number and its record.
pub fn split_gmsg(payload: &[u8], bucket: Bucket) -> Result<(u32, &[u8]), Error> {
    if payload.len() != bucket.l5_payload() {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(payload);
    let seq = r.u32()?;
    Ok((seq, r.rest()))
}

/// The payload of `GKEY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GkeyPayload {
    /// The reader credential of the new epoch.
    pub read_pk: [u8; 32],
    /// The writer credential of the new epoch.
    pub write_pk: [u8; 32],
    /// The owner credential after the command: the present one keeps the
    /// owners, and a new one ends each `own_sk` that an admin who left the
    /// role still holds (`WIR-522`).
    pub own_pk: [u8; 32],
}

impl GkeyPayload {
    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.put(&self.read_pk)?;
        w.put(&self.write_pk)?;
        w.put(&self.own_pk)?;
        Ok(w.position())
    }

    /// Reads the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let out = GkeyPayload {
            read_pk: r.array()?,
            write_pk: r.array()?,
            own_pk: r.array()?,
        };
        r.finish()?;
        Ok(out)
    }
}

/// The payload of `GNREG` and `GNUNREG`.
pub struct GroupNotifyRegistration {
    /// A notify queue that the reader made for this group.
    pub queue: QueueAddress,
}

impl GroupNotifyRegistration {
    /// Writes the registration.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        let n = self.queue.encode(w.tail())?;
        Ok(w.position().saturating_add(n))
    }

    /// Reads a registration (`WIR-401`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        Ok(GroupNotifyRegistration {
            queue: QueueAddress::parse(r.rest())?,
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
    use alloc::vec;
    use umbra_crypto::secret::Secret;

    #[test]
    fn each_payload_holds_the_length_of_the_table() {
        let mut out = [0u8; 200];
        let gnew = GnewPayload {
            read_pk: [1; 32],
            write_pk: [2; 32],
            own_pk: [3; 32],
            admission: Admission::NONE,
        };
        assert_eq!(gnew.encode(&mut out).unwrap(), GNEW_NONE_LEN);
        assert_eq!(GnewPayload::parse(&out[..99]).unwrap().own_pk, [3; 32]);
        assert!(GnewPayload::parse(&out[..100]).is_err());

        let gseq = GseqPayload {
            corr_id: [4; 16],
            seq: 9,
        };
        assert_eq!(gseq.encode(&mut out).unwrap(), GSEQ_LEN);
        assert_eq!(GseqPayload::parse(&out[..20]).unwrap(), gseq);

        assert_eq!(encode_gsub(77, &mut out).unwrap(), 4);
        assert_eq!(parse_gsub(&out[..4]).unwrap(), 77);
        assert!(parse_gsub(&out[..5]).is_err());

        let gkey = GkeyPayload {
            read_pk: [5; 32],
            write_pk: [6; 32],
            own_pk: [7; 32],
        };
        assert_eq!(gkey.encode(&mut out).unwrap(), GKEY_LEN);
        assert_eq!(GkeyPayload::parse(&out[..96]).unwrap(), gkey);
        assert!(GkeyPayload::parse(&out[..64]).is_err());

        let reg = GroupNotifyRegistration {
            queue: QueueAddress {
                relay_id: [7; 32],
                sender_id: [8; 32],
                qs_auth_sk: Secret::new([9; 32]),
                qe: Secret::new([10; 32]),
            },
        };
        assert_eq!(reg.encode(&mut out).unwrap(), NOTIFY_REGISTRATION_LEN);
        assert_eq!(
            GroupNotifyRegistration::parse(&out[..130])
                .unwrap()
                .queue
                .sender_id,
            [8; 32]
        );
        out[0] = 0x02;
        assert!(GroupNotifyRegistration::parse(&out[..130]).is_err());
    }

    #[test]
    fn the_range_is_closed() {
        for b in 0x9Bu8..=0x9F {
            assert!(GroupCmd::from_byte(b).is_err());
        }
        assert_eq!(GroupCmd::Gpost.fixed_payload_len(Bucket::B1), Some(1_926));
        assert_eq!(GroupCmd::Gmsg.fixed_payload_len(Bucket::B1), Some(1_930));

        let record = vec![7u8; Bucket::B1.group_record()];
        let mut msg = vec![0u8; Bucket::B1.l5_payload()];
        assert_eq!(
            encode_gmsg(42, &record, Bucket::B1, &mut msg).unwrap(),
            Bucket::B1.l5_payload()
        );
        assert_eq!(split_gmsg(&msg, Bucket::B1).unwrap(), (42, &record[..]));
        assert!(encode_gmsg(42, &record, Bucket::B2, &mut msg).is_err());
        assert!(split_gmsg(&msg, Bucket::B2).is_err());
    }
}
