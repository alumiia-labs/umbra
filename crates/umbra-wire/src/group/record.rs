//! The group queue record of Part 6 §6.4.6: the content record with its
//! tag vector, and the epoch-key record with its KEM slots.
//!
//! The record is the L6 layer of a group queue, and there is no L7 under
//! it. The relay reads `version`, `kind`, `epoch`, `slot`, and the bucket
//! (`WIR-408`).

use alloc::vec::Vec;

use umbra_crypto::group::{chain, slot, TAG_LEN};

use crate::{
    bucket::{Bucket, GROUP_RECORD_FIXED},
    codec::{Reader, Writer},
    Error,
};

/// The record version.
pub const VERSION: u8 = 0x01;
/// `GROUP_REPLICAS`, the `own_count` of an admin slot.
pub const REPLICAS: u8 = 2;
/// The fixed part of a `SlotPayload` at `own_count` 0.
pub const SLOT_PAYLOAD_FIXED: usize = 47;
/// The fixed part of an `EpochKeyBody`.
pub const EPOCH_KEY_FIXED: usize = 7;

/// The record kind. This namespace holds two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// A content record, under the slot key.
    Content = 0x01,
    /// An epoch-key record, with one KEM slot for each member.
    EpochKey = 0x02,
}

impl RecordKind {
    const fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(RecordKind::Content),
            0x02 => Ok(RecordKind::EpochKey),
            _ => Err(Error::Malformed),
        }
    }
}

/// The fixed part of a record, with its body.
pub struct GroupQueueRecord<'a> {
    /// The kind.
    pub kind: RecordKind,
    /// The group epoch.
    pub epoch: u32,
    /// The slot index of a content record, or the start slot of an epoch.
    pub slot: u32,
    /// Fresh from the CSPRNG on a content record; zero on an epoch-key record.
    pub nonce: [u8; 12],
    /// The body, at the `body` row of the bucket.
    pub body: &'a [u8],
}

impl<'a> GroupQueueRecord<'a> {
    /// Writes the record at the "record on a `GMSG`" row of `bucket`
    /// (`WIR-406`). The body must already hold its fill.
    pub fn encode(&self, bucket: Bucket, out: &mut [u8]) -> Result<usize, Error> {
        if self.body.len() != bucket.group_body() {
            return Err(Error::Capacity);
        }
        if self.kind == RecordKind::EpochKey && self.nonce != [0; 12] {
            return Err(Error::Malformed);
        }
        let body_len = u16::try_from(self.body.len()).map_err(|_| Error::Capacity)?;
        let mut w = Writer::new(out);
        w.u8(VERSION)?;
        w.u8(self.kind as u8)?;
        w.u32(self.epoch)?;
        w.u32(self.slot)?;
        w.put(&self.nonce)?;
        w.u16(body_len)?;
        w.put(self.body)?;
        Ok(w.position())
    }

    /// Reads a record of `bucket` (`WIR-410`, `WIR-411`, `WIR-422`).
    pub fn parse(bytes: &'a [u8], bucket: Bucket) -> Result<Self, Error> {
        if bytes.len() != bucket.group_record() {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let kind = RecordKind::from_byte(r.u8()?)?;
        let epoch = r.u32()?;
        let slot = r.u32()?;
        let nonce = r.array()?;
        if kind == RecordKind::EpochKey && nonce != [0; 12] {
            return Err(Error::Malformed);
        }
        let body_len = usize::from(r.u16()?);
        if body_len != bucket.group_record().saturating_sub(GROUP_RECORD_FIXED) {
            return Err(Error::Malformed);
        }
        let body = r.take(body_len)?;
        r.finish()?;
        Ok(GroupQueueRecord {
            kind,
            epoch,
            slot,
            nonce,
            body,
        })
    }
}

/// The tag vector of a content record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tags<'a> {
    /// One tag for each active member in index order; the sender's position
    /// holds zero bytes.
    Dense(&'a [u8]),
    /// One entry for each named member, in strictly increasing index order.
    Sparse(Vec<(u16, [u8; TAG_LEN])>),
}

impl Tags<'_> {
    /// The encoded length of the vector.
    pub fn len(&self) -> usize {
        match self {
            Tags::Dense(bytes) => bytes.len(),
            Tags::Sparse(entries) => entries.len().saturating_mul(2 + TAG_LEN),
        }
    }

    /// Whether the vector holds no tag.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The tag at the receiver's position: its rank among the active members
    /// in dense mode, its index in sparse mode (`WIR-420`).
    pub fn tag_for(&self, rank: usize, index: u16) -> Option<[u8; TAG_LEN]> {
        match self {
            Tags::Dense(bytes) => {
                let start = rank.checked_mul(TAG_LEN)?;
                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(bytes.get(start..start.checked_add(TAG_LEN)?)?);
                Some(tag)
            }
            Tags::Sparse(entries) => entries.iter().find(|(i, _)| *i == index).map(|(_, t)| *t),
        }
    }
}

/// The plaintext of a content record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentPlain<'a> {
    /// The member index of the sender.
    pub sender_index: u16,
    /// Strictly increasing for each (member, epoch), from 1.
    pub counter: u32,
    /// The roster epoch whose active-member order gives the tag order.
    pub roster_epoch: u32,
    /// The tag vector.
    pub tags: Tags<'a>,
    /// One `AppMessage` of §6.6.
    pub app: &'a [u8],
}

impl<'a> ContentPlain<'a> {
    /// Writes the plaintext with its fill to the `ContentPlain` row of
    /// `bucket` (`WIR-404`). The output is what the caller seals.
    pub fn encode(&self, bucket: Bucket, out: &mut [u8]) -> Result<usize, Error> {
        let total = bucket.content_plain();
        let out = out.get_mut(..total).ok_or(Error::Capacity)?;
        let mut w = Writer::new(out);
        w.u16(self.sender_index)?;
        w.u32(self.counter)?;
        w.u32(self.roster_epoch)?;
        match &self.tags {
            Tags::Dense(bytes) => {
                if bytes.len() % TAG_LEN != 0 {
                    return Err(Error::Malformed);
                }
                w.u8(0x01)?;
                w.u16(u16::try_from(bytes.len() / TAG_LEN).map_err(|_| Error::Malformed)?)?;
                w.put(bytes)?;
            }
            Tags::Sparse(entries) => {
                w.u8(0x02)?;
                w.u16(u16::try_from(entries.len()).map_err(|_| Error::Malformed)?)?;
                let mut last: Option<u16> = None;
                for (index, tag) in entries {
                    if last.is_some_and(|l| l >= *index) {
                        return Err(Error::Malformed);
                    }
                    last = Some(*index);
                    w.u16(*index)?;
                    w.put(tag)?;
                }
            }
        }
        w.u16(u16::try_from(self.app.len()).map_err(|_| Error::Capacity)?)?;
        w.put(self.app)?;
        w.zeros(w.remaining())?;
        Ok(total)
    }

    /// Reads a plaintext. `active_members` is the active member count of
    /// the receiver's roster at `roster_epoch`, which a dense vector must
    /// match (`WIR-414`). The caller resolves `roster_epoch` first.
    pub fn parse(
        bytes: &'a [u8],
        active_members: impl Fn(u32) -> Option<u16>,
    ) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let sender_index = r.u16()?;
        let counter = r.u32()?;
        let roster_epoch = r.u32()?;
        let mode = r.u8()?;
        let tag_count = r.u16()?;
        let tags = match mode {
            0x01 => {
                if active_members(roster_epoch) != Some(tag_count) {
                    return Err(Error::Malformed);
                }
                Tags::Dense(r.take(usize::from(tag_count).saturating_mul(TAG_LEN))?)
            }
            0x02 => {
                // The remaining length bounds the count before any allocation
                // (`WIR-006`).
                let count = usize::from(tag_count);
                if count.saturating_mul(2 + TAG_LEN) > r.remaining() {
                    return Err(Error::Malformed);
                }
                let mut entries = Vec::with_capacity(count);
                let mut last: Option<u16> = None;
                for _ in 0..tag_count {
                    let index = r.u16()?;
                    if last.is_some_and(|l| l >= index) {
                        return Err(Error::Malformed);
                    }
                    last = Some(index);
                    entries.push((index, r.array()?));
                }
                Tags::Sparse(entries)
            }
            _ => return Err(Error::Malformed),
        };
        let app_len = usize::from(r.u16()?);
        let app = r.take(app_len)?;
        r.finish_zero()?;
        Ok(ContentPlain {
            sender_index,
            counter,
            roster_epoch,
            tags,
            app,
        })
    }
}

/// Seals a content record: builds the plaintext, encrypts it under the
/// record key, and writes the full record at `bucket`.
#[allow(clippy::too_many_arguments)]
pub fn seal_content(
    plain: &ContentPlain<'_>,
    record_key: &umbra_crypto::secret::Secret<32>,
    nonce: [u8; 12],
    group_id: &[u8; 32],
    epoch: u32,
    slot: u32,
    bucket: Bucket,
    out: &mut [u8],
) -> Result<usize, Error> {
    let record_len = bucket.group_record();
    let out = out.get_mut(..record_len).ok_or(Error::Capacity)?;
    let (_, body) = out.split_at_mut(GROUP_RECORD_FIXED);
    let (plaintext, tag_out) = body.split_at_mut(bucket.content_plain());
    plain.encode(bucket, plaintext)?;
    let tag = chain::seal_record(record_key, &nonce, group_id, epoch, slot, plaintext)?;
    tag_out.copy_from_slice(&tag);
    let mut w = Writer::new(out);
    w.u8(VERSION)?;
    w.u8(RecordKind::Content as u8)?;
    w.u32(epoch)?;
    w.u32(slot)?;
    w.put(&nonce)?;
    w.u16(u16::try_from(bucket.group_body()).map_err(|_| Error::Capacity)?)?;
    Ok(record_len)
}

/// Opens the body of a content record into `out`, which then holds the
/// `ContentPlain` bytes. One error covers every cause (`GRP-251`).
pub fn open_content(
    record: &GroupQueueRecord<'_>,
    record_key: &umbra_crypto::secret::Secret<32>,
    group_id: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, Error> {
    if record.kind != RecordKind::Content {
        return Err(Error::Malformed);
    }
    let plain_len = record
        .body
        .len()
        .checked_sub(chain::RECORD_TAG_LEN)
        .ok_or(Error::Malformed)?;
    let (ct, tag) = record.body.split_at(plain_len);
    let out = out.get_mut(..plain_len).ok_or(Error::Capacity)?;
    out.copy_from_slice(ct);
    chain::open_record(
        record_key,
        &record.nonce,
        group_id,
        record.epoch,
        record.slot,
        out,
        tag,
    )?;
    Ok(plain_len)
}

/// One KEM slot of an epoch-key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemSlot<'a> {
    /// The member index the slot serves.
    pub index: u16,
    /// `kem_ct || ct`, as `umbra_crypto::group::slot` seals it.
    pub sealed: &'a [u8],
}

/// The length of a slot with `own_count` owner secrets.
pub const fn slot_len(own_count: u8) -> usize {
    2 + slot::sealed_len(SLOT_PAYLOAD_FIXED + 32 * own_count as usize)
}

/// The carrier of the slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Carrier<'a> {
    /// The slots inline, in member-index order.
    Inline(Vec<KemSlot<'a>>),
    /// A `FileDescriptor` that names the slot object on the chunk path.
    Chunked {
        /// The slots in each segment.
        slots_per_chunk: u16,
        /// The descriptor of Part 12 §12.3.
        descriptor: &'a [u8],
    },
}

/// The body of an epoch-key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKeyBody<'a> {
    /// The roster epoch whose active members hold slots.
    pub roster_epoch: u32,
    /// The count of slots, inline or in the object.
    pub slot_count: u16,
    /// Where the slots are.
    pub carrier: Carrier<'a>,
}

impl<'a> EpochKeyBody<'a> {
    /// Writes the body with its fill to the `body` row of `bucket`
    /// (`WIR-405`).
    pub fn encode(&self, bucket: Bucket, out: &mut [u8]) -> Result<usize, Error> {
        let total = bucket.group_body();
        let out = out.get_mut(..total).ok_or(Error::Capacity)?;
        let mut w = Writer::new(out);
        w.u32(self.roster_epoch)?;
        match &self.carrier {
            Carrier::Inline(slots) => {
                if slots.len() != usize::from(self.slot_count) {
                    return Err(Error::Malformed);
                }
                w.u8(0x01)?;
                w.u16(self.slot_count)?;
                let mut last: Option<u16> = None;
                for s in slots {
                    if last.is_some_and(|l| l >= s.index) {
                        return Err(Error::Malformed);
                    }
                    last = Some(s.index);
                    w.u16(s.index)?;
                    w.put(s.sealed)?;
                }
            }
            Carrier::Chunked {
                slots_per_chunk,
                descriptor,
            } => {
                if *slots_per_chunk == 0 {
                    return Err(Error::Malformed);
                }
                w.u8(0x02)?;
                w.u16(self.slot_count)?;
                w.u16(*slots_per_chunk)?;
                w.u16(u16::try_from(descriptor.len()).map_err(|_| Error::Capacity)?)?;
                w.put(descriptor)?;
            }
        }
        w.zeros(w.remaining())?;
        Ok(total)
    }

    /// Reads a body. `own_count` gives the owner count of each index from
    /// the roles of the receiver's roster (`WIR-428`), and `None` for an
    /// index the roster does not hold.
    pub fn parse(bytes: &'a [u8], own_count: impl Fn(u16) -> Option<u8>) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let roster_epoch = r.u32()?;
        let carrier_byte = r.u8()?;
        let slot_count = r.u16()?;
        let carrier = match carrier_byte {
            0x01 => {
                // The remaining length bounds the count before any allocation
                // (`WIR-006`): no slot is shorter than the slot of a member.
                let count = usize::from(slot_count);
                if count.saturating_mul(slot_len(0)) > r.remaining() {
                    return Err(Error::Malformed);
                }
                let mut slots = Vec::with_capacity(count);
                let mut last: Option<u16> = None;
                for _ in 0..slot_count {
                    let index = r.u16()?;
                    if last.is_some_and(|l| l >= index) {
                        return Err(Error::Malformed);
                    }
                    last = Some(index);
                    let own = own_count(index).ok_or(Error::Malformed)?;
                    if own != 0 && own != REPLICAS {
                        return Err(Error::Malformed);
                    }
                    let sealed = r.take(slot_len(own).saturating_sub(2))?;
                    slots.push(KemSlot { index, sealed });
                }
                Carrier::Inline(slots)
            }
            0x02 => {
                let slots_per_chunk = r.u16()?;
                if slots_per_chunk == 0 {
                    return Err(Error::Malformed);
                }
                let desc_len = usize::from(r.u16()?);
                Carrier::Chunked {
                    slots_per_chunk,
                    descriptor: r.take(desc_len)?,
                }
            }
            _ => return Err(Error::Malformed),
        };
        r.finish_zero()?;
        Ok(EpochKeyBody {
            roster_epoch,
            slot_count,
            carrier,
        })
    }

    /// The largest `slots_per_chunk` at which every segment of the given
    /// slot sizes fits `segment_size` (`WIR-425`).
    pub fn slots_per_chunk(slot_lens: &[usize], segment_size: usize) -> Option<u16> {
        let mut best = 0usize;
        for n in 1..=slot_lens.len() {
            let fits = slot_lens
                .chunks(n)
                .all(|seg| seg.iter().sum::<usize>() <= segment_size);
            if fits {
                best = n;
            } else {
                break;
            }
        }
        u16::try_from(best).ok().filter(|n| *n > 0)
    }
}

/// The payload inside a KEM slot.
pub struct SlotPayload {
    /// The member index of the rotator.
    pub rotator: u16,
    /// The epoch secret.
    pub epoch_secret: umbra_crypto::secret::Secret<32>,
    /// The rotator's tag to the member the slot serves.
    pub tag: [u8; TAG_LEN],
    /// The owner secrets, in the replica order of the roster snapshot;
    /// empty below `admin`.
    pub own_sks: Vec<umbra_crypto::secret::Secret<32>>,
}

impl SlotPayload {
    /// The encoded length.
    pub fn len(&self) -> usize {
        SLOT_PAYLOAD_FIXED.saturating_add(self.own_sks.len().saturating_mul(32))
    }

    /// Whether the payload carries no owner secret.
    pub fn is_empty(&self) -> bool {
        self.own_sks.is_empty()
    }

    /// Writes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let own_count = u8::try_from(self.own_sks.len()).map_err(|_| Error::Malformed)?;
        if own_count != 0 && own_count != REPLICAS {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u16(self.rotator)?;
        w.put(self.epoch_secret.expose())?;
        w.put(&self.tag)?;
        w.u8(own_count)?;
        for sk in &self.own_sks {
            w.put(sk.expose())?;
        }
        Ok(w.position())
    }

    /// Reads a payload (`WIR-431`).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let rotator = r.u16()?;
        let epoch_secret = umbra_crypto::secret::Secret::new(r.array()?);
        let tag = r.array()?;
        let own_count = r.u8()?;
        if own_count != 0 && own_count != REPLICAS {
            return Err(Error::Malformed);
        }
        let mut own_sks = Vec::with_capacity(usize::from(own_count));
        for _ in 0..own_count {
            own_sks.push(umbra_crypto::secret::Secret::new(r.array()?));
        }
        r.finish()?;
        Ok(SlotPayload {
            rotator,
            epoch_secret,
            tag,
            own_sks,
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

    const GROUP: [u8; 32] = [0x67; 32];

    #[test]
    fn a_content_record_seals_and_opens_at_the_bucket_row() {
        let key = Secret::new([1; 32]);
        let tags = [0u8; 36];
        let plain = ContentPlain {
            sender_index: 0,
            counter: 1,
            roster_epoch: 1,
            tags: Tags::Dense(&tags),
            app: b"hello",
        };
        let mut out = vec![0u8; Bucket::B0.group_record()];
        let n = seal_content(&plain, &key, [7; 12], &GROUP, 1, 100, Bucket::B0, &mut out).unwrap();
        assert_eq!(n, 390);
        let record = GroupQueueRecord::parse(&out, Bucket::B0).unwrap();
        assert_eq!(record.kind, RecordKind::Content);
        assert_eq!(record.slot, 100);
        let mut buf = vec![0u8; Bucket::B0.content_plain()];
        let len = open_content(&record, &key, &GROUP, &mut buf).unwrap();
        let back = ContentPlain::parse(&buf[..len], |_| Some(3)).unwrap();
        assert_eq!(back, plain);
        assert!(ContentPlain::parse(&buf[..len], |_| Some(4)).is_err());
        assert_eq!(back.tags.tag_for(1, 1), Some([0; 12]));
        assert!(GroupQueueRecord::parse(&out, Bucket::B1).is_err());
        assert!(GroupQueueRecord::parse(&out[..389], Bucket::B0).is_err());
    }

    #[test]
    fn the_sparse_vector_holds_its_order() {
        let plain = ContentPlain {
            sender_index: 3,
            counter: 2,
            roster_epoch: 5,
            tags: Tags::Sparse(vec![(1, [1; 12]), (4, [4; 12])]),
            app: b"presence",
        };
        let mut buf = vec![0u8; Bucket::B0.content_plain()];
        plain.encode(Bucket::B0, &mut buf).unwrap();
        let back = ContentPlain::parse(&buf, |_| None).unwrap();
        assert_eq!(back.tags.tag_for(0, 4), Some([4; 12]));
        assert_eq!(back.tags.tag_for(0, 2), None);
        let bad = ContentPlain {
            tags: Tags::Sparse(vec![(4, [4; 12]), (1, [1; 12])]),
            ..plain.clone()
        };
        assert!(bad.encode(Bucket::B0, &mut buf).is_err());
        // A non-zero fill byte is rejected (WIR-407).
        plain.encode(Bucket::B0, &mut buf).unwrap();
        *buf.last_mut().unwrap() = 1;
        assert!(ContentPlain::parse(&buf, |_| None).is_err());
        buf[10] = 0x03;
        assert!(ContentPlain::parse(&buf, |_| None).is_err());
    }

    #[test]
    fn a_count_above_the_bytes_that_remain_is_rejected_before_an_allocation() {
        // A sparse vector that names 65 535 entries in a B0 plaintext.
        let mut buf = vec![0u8; Bucket::B0.content_plain()];
        buf[10] = 0x02;
        buf[11] = 0xFF;
        buf[12] = 0xFF;
        assert!(ContentPlain::parse(&buf, |_| None).is_err());
        // An inline carrier that names 65 535 slots in a B0 body.
        let mut buf = vec![0u8; Bucket::B0.group_body()];
        buf[4] = 0x01;
        buf[5] = 0xFF;
        buf[6] = 0xFF;
        assert!(EpochKeyBody::parse(&buf, |_| Some(0)).is_err());
    }

    #[test]
    fn the_epoch_key_body_holds_the_slot_sizes() {
        assert_eq!(slot_len(0), 1_185);
        assert_eq!(slot_len(2), 1_249);
        let plain_slot = vec![9u8; slot_len(0) - 2];
        let admin_slot = vec![8u8; slot_len(2) - 2];
        let body = EpochKeyBody {
            roster_epoch: 1,
            slot_count: 3,
            carrier: Carrier::Inline(vec![
                KemSlot {
                    index: 0,
                    sealed: &admin_slot,
                },
                KemSlot {
                    index: 1,
                    sealed: &admin_slot,
                },
                KemSlot {
                    index: 2,
                    sealed: &plain_slot,
                },
            ]),
        };
        let mut buf = vec![0u8; Bucket::B2.group_body()];
        body.encode(Bucket::B2, &mut buf).unwrap();
        assert_eq!(7 + 2 * 1_249 + 1_185, 3_690);
        let roles = |i: u16| {
            if i < 2 {
                Some(2)
            } else if i == 2 {
                Some(0)
            } else {
                None
            }
        };
        assert_eq!(EpochKeyBody::parse(&buf, roles).unwrap(), body);
        // The wrong own_count for an index breaks the slot boundaries.
        assert!(EpochKeyBody::parse(&buf, |_| Some(0)).is_err());
        // 27 plain slots fit B3 inline, and 28 do not (WIR-423).
        assert!(7 + 27 * slot_len(0) <= Bucket::B3.group_body());
        assert!(7 + 28 * slot_len(0) > Bucket::B3.group_body());
        let sizes = vec![slot_len(0) - 2 + 2; 500];
        assert_eq!(EpochKeyBody::slots_per_chunk(&sizes, 32_634), Some(27));
        let chunked = EpochKeyBody {
            roster_epoch: 1,
            slot_count: 500,
            carrier: Carrier::Chunked {
                slots_per_chunk: 27,
                descriptor: &[5; 40],
            },
        };
        let mut buf = vec![0u8; Bucket::B0.group_body()];
        chunked.encode(Bucket::B0, &mut buf).unwrap();
        assert_eq!(EpochKeyBody::parse(&buf, |_| None).unwrap(), chunked);
        buf[7] = 0;
        buf[8] = 0;
        assert!(EpochKeyBody::parse(&buf, |_| None).is_err());
    }

    #[test]
    fn the_slot_payload_holds_its_two_lengths() {
        let plain = SlotPayload {
            rotator: 0,
            epoch_secret: Secret::new([1; 32]),
            tag: [2; 12],
            own_sks: Vec::new(),
        };
        let mut buf = [0u8; 111];
        assert_eq!(plain.encode(&mut buf).unwrap(), 47);
        assert!(SlotPayload::parse(&buf[..47]).is_ok());
        let admin = SlotPayload {
            own_sks: vec![Secret::new([3; 32]), Secret::new([4; 32])],
            ..plain
        };
        assert_eq!(admin.encode(&mut buf).unwrap(), 111);
        assert_eq!(SlotPayload::parse(&buf).unwrap().own_sks.len(), 2);
        buf[46] = 1;
        assert!(SlotPayload::parse(&buf[..79]).is_err());
    }
}
