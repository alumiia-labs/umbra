//! The queue end-to-end record of Part 6 §6.4.2 (L6), and the `SEND` and
//! `MSG` payloads around it.
//!
//! The record is filled to a fixed length for the bucket, thus a relay
//! reads the version, the nonce, and the bucket, and not the true length.

use umbra_crypto::queue::{QueueKey, TAG_LEN};

use crate::{
    bucket::Bucket,
    codec::{Reader, Writer},
    Error,
};

/// The record version.
pub const VERSION: u8 = 0x01;
/// The prefix of the plaintext: the true length and the kind.
pub const PLAIN_PREFIX: usize = 3;

/// The L6 record kind. The value `0x02` is retired and never returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L6Kind {
    /// A ratchet record of §6.5.
    Ratchet = 0x01,
    /// A report record of Part 12 §12.5.3.
    Report = 0x03,
    /// A `NotifyDigest` of Part 12 §12.6.4.
    NotifyDigest = 0x04,
}

impl L6Kind {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(L6Kind::Ratchet),
            0x03 => Ok(L6Kind::Report),
            0x04 => Ok(L6Kind::NotifyDigest),
            _ => Err(Error::Malformed),
        }
    }
}

/// The largest inner record a bucket holds, which is the L7 row of §6.9.
pub const fn inner_capacity(bucket: Bucket) -> usize {
    bucket.l7_record()
}

/// Seals `inner` of `kind` into a `SEND` payload at `bucket`: the L6 record
/// at the "L6 record on a `MSG`" row (`WIR-024`, `WIR-025`).
pub fn seal(
    key: &QueueKey,
    nonce: [u8; 12],
    sender_id: &[u8; 32],
    kind: L6Kind,
    inner: &[u8],
    bucket: Bucket,
    out: &mut [u8],
) -> Result<usize, Error> {
    let record_len = bucket.l6_record();
    if inner.len() > inner_capacity(bucket) {
        return Err(Error::Capacity);
    }
    let out = out.get_mut(..record_len).ok_or(Error::Capacity)?;
    let mut w = Writer::new(out);
    w.u8(VERSION)?;
    w.put(&nonce)?;
    let start = w.position();
    w.u16(u16::try_from(inner.len()).map_err(|_| Error::Capacity)?)?;
    w.u8(kind as u8)?;
    w.put(inner)?;
    w.zeros(w.remaining().saturating_sub(TAG_LEN))?;
    let end = w.position();
    let (plain, tag_out) = out
        .get_mut(start..)
        .ok_or(Error::Capacity)?
        .split_at_mut(end - start);
    let tag = key.seal(&nonce, VERSION, sender_id, plain)?;
    tag_out.copy_from_slice(&tag);
    Ok(record_len)
}

/// Opens a `SEND` payload or the record part of a `MSG` payload. Writes
/// the inner record into `out` and returns its kind and its length. One
/// error covers every cause (`WIR-032`).
pub fn open(
    key: &QueueKey,
    sender_id: &[u8; 32],
    record: &[u8],
    bucket: Bucket,
    out: &mut [u8],
) -> Result<(L6Kind, usize), Error> {
    if record.len() != bucket.l6_record() {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(record);
    if r.u8()? != VERSION {
        return Err(Error::Malformed);
    }
    let nonce: [u8; 12] = r.array()?;
    let ct = r.rest();
    let plain_len = ct.len().checked_sub(TAG_LEN).ok_or(Error::Malformed)?;
    let (body, tag) = ct.split_at(plain_len);
    let plain = out.get_mut(..plain_len).ok_or(Error::Capacity)?;
    plain.copy_from_slice(body);
    key.open(&nonce, VERSION, sender_id, plain, tag)?;
    let mut p = Reader::new(plain);
    let true_len = usize::from(p.u16()?);
    let kind = L6Kind::from_byte(p.u8()?)?;
    p.take(true_len)?;
    p.finish_zero()?;
    // Move the inner record to the front of `out` for the caller.
    plain.copy_within(PLAIN_PREFIX..PLAIN_PREFIX.saturating_add(true_len), 0);
    Ok((kind, true_len))
}

/// Makes the `MSG` payload that a relay emits from a `SEND` payload
/// (`WIR-026`, `WIR-029`).
pub fn msg_from_send(
    seq: u32,
    send_payload: &[u8],
    bucket: Bucket,
    out: &mut [u8],
) -> Result<usize, Error> {
    if send_payload.len() != bucket.l6_record() {
        return Err(Error::Malformed);
    }
    let mut w = Writer::new(out);
    w.u32(seq)?;
    w.put(send_payload)?;
    Ok(w.position())
}

/// Splits a `MSG` payload into its sequence number and its record.
pub fn split_msg(payload: &[u8], bucket: Bucket) -> Result<(u32, &[u8]), Error> {
    if payload.len() != bucket.l5_payload() {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(payload);
    let seq = r.u32()?;
    Ok((seq, r.rest()))
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
    fn a_send_becomes_a_msg_and_opens_at_each_bucket() {
        let key = QueueKey::derive(&Secret::new([1; 32]), &[2; 32]);
        for bucket in Bucket::ALL {
            let inner = vec![0x42u8; inner_capacity(bucket)];
            let mut send = vec![0u8; bucket.l6_record()];
            assert_eq!(
                seal(
                    &key,
                    [3; 12],
                    &[2; 32],
                    L6Kind::Ratchet,
                    &inner,
                    bucket,
                    &mut send
                )
                .unwrap(),
                bucket.l6_record()
            );
            let mut msg = vec![0u8; bucket.l5_payload()];
            msg_from_send(7, &send, bucket, &mut msg).unwrap();
            let (seq, record) = split_msg(&msg, bucket).unwrap();
            assert_eq!(seq, 7);
            let mut out = vec![0u8; bucket.l6_record()];
            let (kind, len) = open(&key, &[2; 32], record, bucket, &mut out).unwrap();
            assert_eq!(kind, L6Kind::Ratchet);
            assert_eq!(&out[..len], &inner[..]);
            let too_big = vec![0u8; inner_capacity(bucket) + 1];
            assert!(seal(
                &key,
                [3; 12],
                &[2; 32],
                L6Kind::Ratchet,
                &too_big,
                bucket,
                &mut send
            )
            .is_err());
        }
    }

    #[test]
    fn a_short_record_keeps_its_true_length_and_rejects_a_bad_kind() {
        let key = QueueKey::derive(&Secret::new([1; 32]), &[2; 32]);
        let mut send = vec![0u8; Bucket::B0.l6_record()];
        seal(
            &key,
            [3; 12],
            &[2; 32],
            L6Kind::Report,
            b"short",
            Bucket::B0,
            &mut send,
        )
        .unwrap();
        let mut out = vec![0u8; 400];
        let (kind, len) = open(&key, &[2; 32], &send, Bucket::B0, &mut out).unwrap();
        assert_eq!((kind, &out[..len]), (L6Kind::Report, &b"short"[..]));
        let mut bad = send.clone();
        bad[0] = 0x02;
        assert!(open(&key, &[2; 32], &bad, Bucket::B0, &mut out).is_err());
        let mut bad = send.clone();
        bad[20] ^= 1;
        assert!(open(&key, &[2; 32], &bad, Bucket::B0, &mut out).is_err());
        assert!(open(&key, &[9; 32], &send, Bucket::B0, &mut out).is_err());
        assert!(open(&key, &[2; 32], &send[..389], Bucket::B0, &mut out).is_err());
    }
}
