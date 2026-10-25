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

/// The L6 record kind. The values `0x02` and `0x03` are retired and never
/// return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L6Kind {
    /// A ratchet record of §6.5.
    Ratchet = 0x01,
    /// A `NotifyDigest` of Part 8 §8.5.1.
    NotifyDigest = 0x04,
    /// One flight of the pairwise handshake of Part 5 §5.4: the flight
    /// number from 1 to 3, and then the flight.
    Handshake = 0x05,
    /// The bundle of a channel renewal of Part 3 §3.2.6: a party whose
    /// ratchet is stale offers a new handshake to its contact.
    Renewal = 0x06,
    /// A hello of Part 9 §9.6 on a rendezvous queue: the sealed envelope of
    /// `DIS-143`.
    Hello = 0x07,
    /// A link-fault report of Part 10 §10.4.2 on the report queue of an
    /// authority: a `SealedReport` (`WIR-536`).
    LinkFault = 0x08,
}

impl L6Kind {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(L6Kind::Ratchet),
            0x04 => Ok(L6Kind::NotifyDigest),
            0x05 => Ok(L6Kind::Handshake),
            0x06 => Ok(L6Kind::Renewal),
            0x07 => Ok(L6Kind::Hello),
            0x08 => Ok(L6Kind::LinkFault),
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

    // WIR-032: a tag that does not verify is the same error as a record
    // that does not parse.
    key.open(&nonce, VERSION, sender_id, plain, tag)
        .map_err(|_| Error::Malformed)?;

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

/// The prefix of a renewal record: the counter of the guard and its secret.
pub const RENEWAL_PROOF_LEN: usize = 4 + 32;

/// The content of an L6 record of kind `0x06`: the proof of the renewal
/// guard of Part 3 §3.2.6, and the bundle of Part 5 §5.4.1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RenewalRecord<'a> {
    /// The counter of the newest guard of the sender and the secret that
    /// opens it, or none for a sender that holds no guard.
    pub proof: Option<(u32, &'a [u8; 32])>,
    /// The bundle.
    pub bundle: &'a [u8],
}

impl<'a> RenewalRecord<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        RENEWAL_PROOF_LEN.saturating_add(self.bundle.len())
    }

    /// Whether the record holds no bundle. Clippy asks for this beside
    /// `len`.
    pub fn is_empty(&self) -> bool {
        self.bundle.is_empty()
    }

    /// Writes the record. A proof with a counter of zero is no proof.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        match self.proof {
            Some((guard_seq, secret)) if guard_seq != 0 => {
                w.u32(guard_seq)?;
                w.put(secret)?;
            }
            Some(_) => return Err(Error::Malformed),
            None => w.zeros(RENEWAL_PROOF_LEN)?,
        }
        w.put(self.bundle)?;
        Ok(w.position())
    }

    /// Reads a record. The form with no proof is 36 zero bytes, and no
    /// other form has a counter of zero (`WIR-552`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let guard_seq = r.u32()?;
        let secret: &[u8; 32] = r.take(32)?.try_into().map_err(|_| Error::Malformed)?;

        let proof = if guard_seq == 0 {
            if secret != &[0u8; 32] {
                return Err(Error::Malformed);
            }
            None
        } else {
            Some((guard_seq, secret))
        };

        Ok(RenewalRecord {
            proof,
            bundle: r.rest(),
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
    use alloc::{vec, vec::Vec};
    use umbra_crypto::secret::Secret;

    #[test]
    fn a_renewal_record_has_one_form_with_a_proof_and_one_with_none() {
        let secret = [7u8; 32];
        let with = RenewalRecord {
            proof: Some((3, &secret)),
            bundle: b"bundle",
        };
        let mut out = vec![0u8; with.len()];
        assert_eq!(with.encode(&mut out).unwrap(), 42);
        assert!(RenewalRecord::parse(&out).unwrap() == with);

        let none = RenewalRecord {
            proof: None,
            bundle: b"bundle",
        };
        none.encode(&mut out).unwrap();
        assert_eq!(&out[..RENEWAL_PROOF_LEN], &[0u8; RENEWAL_PROOF_LEN]);
        assert!(RenewalRecord::parse(&out).unwrap() == none);

        // WIR-552: a counter of zero with a secret is no form.
        out[10] = 1;
        assert!(RenewalRecord::parse(&out).is_err());
        assert!(RenewalRecord::parse(&out[..35]).is_err());

        let zero = RenewalRecord {
            proof: Some((0, &secret)),
            bundle: b"bundle",
        };
        assert!(zero.encode(&mut out).is_err());
    }

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

    /// A `B0` record that a sender with no rule writes: a raw kind byte,
    /// and `edit` changes the plaintext before the seal.
    fn raw_record(key: &QueueKey, kind: u8, inner: &[u8], edit: impl Fn(&mut [u8])) -> Vec<u8> {
        let nonce = [3u8; 12];
        let mut record = vec![0u8; Bucket::B0.l6_record()];
        record[0] = VERSION;
        record[1..13].copy_from_slice(&nonce);

        let tag_at = record.len() - TAG_LEN;
        let plain = &mut record[13..tag_at];
        plain[..2].copy_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
        plain[2] = kind;
        plain[PLAIN_PREFIX..PLAIN_PREFIX + inner.len()].copy_from_slice(inner);
        edit(plain);

        let tag = key.seal(&nonce, VERSION, &[2; 32], plain).unwrap();
        record[tag_at..].copy_from_slice(&tag);
        record
    }

    #[test]
    fn a_reserved_or_unknown_kind_and_a_fill_byte_are_rejected() {
        let key = QueueKey::derive(&Secret::new([1; 32]), &[2; 32]);
        let mut out = vec![0u8; 400];
        let good = raw_record(&key, L6Kind::Ratchet as u8, b"short", |_| {});
        assert_eq!(
            open(&key, &[2; 32], &good, Bucket::B0, &mut out),
            Ok((L6Kind::Ratchet, 5))
        );

        // WIR-023: the retired kinds 0x02 and 0x03, and the unknown ones.
        for kind in [0x00, 0x02, 0x03, 0x09, 0xFF] {
            let record = raw_record(&key, kind, b"short", |_| {});
            assert_eq!(
                open(&key, &[2; 32], &record, Bucket::B0, &mut out),
                Err(Error::Malformed),
                "kind {kind:#04x}"
            );
        }

        // WIR-028: a fill byte that is not zero, at the first and at the
        // last position of the fill.
        let first_fill = PLAIN_PREFIX + 5;
        for at in [first_fill, Bucket::B0.l6_record() - 13 - TAG_LEN - 1] {
            let record = raw_record(&key, L6Kind::Ratchet as u8, b"short", |plain| {
                plain[at] = 1;
            });
            assert_eq!(
                open(&key, &[2; 32], &record, Bucket::B0, &mut out),
                Err(Error::Malformed)
            );
        }

        // A true length above the plaintext.
        let record = raw_record(&key, L6Kind::Ratchet as u8, b"short", |plain| {
            plain[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        });
        assert_eq!(
            open(&key, &[2; 32], &record, Bucket::B0, &mut out),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn a_short_record_keeps_its_true_length_and_rejects_a_changed_record() {
        let key = QueueKey::derive(&Secret::new([1; 32]), &[2; 32]);
        let mut send = vec![0u8; Bucket::B0.l6_record()];
        seal(
            &key,
            [3; 12],
            &[2; 32],
            L6Kind::NotifyDigest,
            b"short",
            Bucket::B0,
            &mut send,
        )
        .unwrap();

        let mut out = vec![0u8; 400];
        let (kind, len) = open(&key, &[2; 32], &send, Bucket::B0, &mut out).unwrap();
        assert_eq!((kind, &out[..len]), (L6Kind::NotifyDigest, &b"short"[..]));

        let mut bad = send.clone();
        bad[0] = 0x02;
        assert!(open(&key, &[2; 32], &bad, Bucket::B0, &mut out).is_err());
        let mut bad = send.clone();
        bad[20] ^= 1;
        assert!(open(&key, &[2; 32], &bad, Bucket::B0, &mut out).is_err());
        assert!(open(&key, &[9; 32], &send, Bucket::B0, &mut out).is_err());
        assert!(open(&key, &[2; 32], &send[..389], Bucket::B0, &mut out).is_err());
    }

    #[test]
    fn each_rejection_of_a_record_is_the_one_error() {
        let key = QueueKey::derive(&Secret::new([1; 32]), &[2; 32]);
        let mut send = vec![0u8; Bucket::B0.l6_record()];
        seal(
            &key,
            [3; 12],
            &[2; 32],
            L6Kind::Ratchet,
            b"short",
            Bucket::B0,
            &mut send,
        )
        .unwrap();

        let mut out = vec![0u8; 400];
        // WIR-032: a wrong version, a changed byte under the tag, and a
        // wrong sender.
        let mut version = send.clone();
        version[0] = 0x02;
        let mut changed = send.clone();
        changed[20] ^= 1;

        for (record, sender) in [(&version, [2u8; 32]), (&changed, [2; 32]), (&send, [9; 32])] {
            assert_eq!(
                open(&key, &sender, record, Bucket::B0, &mut out),
                Err(Error::Malformed)
            );
        }
    }
}
