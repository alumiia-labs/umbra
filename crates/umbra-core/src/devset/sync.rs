//! The sync channel machines of Part 7 §7.5.1, §7.5.2, §7.5.3, and §7.5.5:
//! the causal context, the source watermark, the retained-record log with
//! its acknowledgment point, the acknowledgment batch, the interactive
//! token bucket, and the catch-up trigger.
//!
//! The specification names the causal context as a compact version vector
//! with a Lamport counter and gives it no byte layout. The layout here is
//! the one the sync envelope carries, and the next amendment records it.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::stored;
use umbra_wire::codec::{Reader, Writer};

use super::{
    DeviceId, SYNC_ACK_BATCH, SYNC_ACK_MAX_DELAY, SYNC_CATCHUP_LAG, SYNC_INTERACTIVE_BURST,
    SYNC_INTERACTIVE_RATE, SYNC_MAX_AGE,
};
use crate::Error;

/// The causal context of a sync record (§7.5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalContext {
    /// The Lamport counter of the sender at the send.
    pub lamport: u64,
    /// The causal counter of each device the sender has seen, itself
    /// included, in ascending device order.
    pub vector: Vec<(DeviceId, u64)>,
    /// The remaining period of a timed record in seconds, or zero
    /// (`DEV-242`).
    pub expires_in: u32,
}

impl CausalContext {
    /// Writes the context.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self
            .vector
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.0 >= b.0))
        {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.lamport.to_be_bytes())?;
        w.u8(u8::try_from(self.vector.len()).map_err(|_| Error::Malformed)?)?;
        for (id, counter) in &self.vector {
            w.put(id)?;
            w.put(&counter.to_be_bytes())?;
        }
        w.u32(self.expires_in)?;
        Ok(w.position())
    }

    /// Reads a context.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let lamport = u64::from_be_bytes(r.array()?);
        let count = usize::from(r.u8()?);
        if count > super::MAX_DEVICES {
            return Err(Error::Malformed);
        }
        let mut vector = Vec::with_capacity(count);
        let mut last: Option<DeviceId> = None;
        for _ in 0..count {
            let id: DeviceId = r.array()?;
            if last.is_some_and(|l| l >= id) {
                return Err(Error::Malformed);
            }
            last = Some(id);
            vector.push((id, u64::from_be_bytes(r.array()?)));
        }
        let expires_in = r.u32()?;
        r.finish()?;
        Ok(CausalContext {
            lamport,
            vector,
            expires_in,
        })
    }

    /// The causal counter of `device` in the vector.
    pub fn counter_of(&self, device: &DeviceId) -> Option<u64> {
        self.vector
            .iter()
            .find(|(d, _)| d == device)
            .map(|(_, c)| *c)
    }
}

/// The scope of a synced record of a pairwise conversation (`DEV-292`).
pub const SCOPE_PAIRWISE: u8 = 0x01;
/// The scope of a synced record of a private group (`DEV-296`).
pub const SCOPE_GROUP: u8 = 0x02;

/// The subject of a group in a synced record (`DEV-296`):
/// `SHA3-256(K_set || 0x02 || group_id)`. A party outside the set cannot
/// test a group against it.
pub fn group_subject(set_key: &umbra_crypto::secret::Secret<32>, group_id: &[u8; 32]) -> [u8; 32] {
    umbra_crypto::hash::sha3_256(&[set_key.expose(), &[SCOPE_GROUP], group_id])
}
/// The author of a synced record: the user, on a device of the set.
pub const AUTHOR_USER: u8 = 0x00;
/// The author of a synced record: the other party of the conversation.
pub const AUTHOR_PEER: u8 = 0x01;

/// The item of the contact name in the mutable-state table (§7.5.3).
pub const ITEM_CONTACT_NAME: u8 = 3;
/// The item of the delivery state and the read state of one message
/// (§7.5.3, `DEV-304`), under the row of the message in the stores of the
/// set.
pub const ITEM_DELIVERY: u8 = 6;
/// The item of an entry of the local identity table (`DEV-011`, `DEV-294`).
pub const ITEM_IDENTITY_ENTRY: u8 = 13;
/// The item of the state of a group that the owner of the channels made or
/// joined: the descriptor of one backup object on the chunk path
/// (`DEV-298`).
pub const ITEM_GROUP_STATE: u8 = 14;
/// The item of the re-key of the member in a group: the new seed and the
/// re-key object (`DEV-300`).
pub const ITEM_GROUP_REKEY: u8 = 15;

/// An entry of the local identity table for a pairwise identity, the value
/// of [`ITEM_IDENTITY_ENTRY`] under the subject of that identity
/// (`DEV-294`): the salt of §4.2.2 and the key of the conversation in the
/// stores of the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityEntry {
    /// The pairwise salt.
    pub salt: [u8; 16],
    /// The key of the conversation.
    pub conversation: [u8; 32],
}

impl IdentityEntry {
    /// The 49 bytes: kind `0x01`, the salt, and the key.
    pub fn encode(&self) -> [u8; 49] {
        let mut out = [0u8; 49];
        out[0] = 0x01;
        out[1..17].copy_from_slice(&self.salt);
        out[17..].copy_from_slice(&self.conversation);
        out
    }

    /// Reads an entry.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let entry = IdentityEntry {
            salt: r.array()?,
            conversation: r.array()?,
        };
        r.finish()?;
        Ok(entry)
    }
}

/// Where a synced record belongs (`DEV-292`): the scope, the subject that
/// names the conversation, and the author of the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {
    /// [`SCOPE_PAIRWISE`].
    pub scope: u8,
    /// For a pairwise conversation, the SHA3-256 of the public key of its
    /// pairwise identity: the subject of a claim of scope `0x01`.
    pub subject: [u8; 32],
    /// [`AUTHOR_USER`] or [`AUTHOR_PEER`].
    pub author: u8,
}

/// A synced conversation record: the causal context, the origin, and the
/// inner `AppMessage` bytes, the payload of kind `0x20` sub-kind `0x03`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedRecord<'a> {
    /// The causal context.
    pub context: CausalContext,
    /// The conversation and the author.
    pub origin: Origin,
    /// The `AppMessage` of Part 6 §6.6 that the peer synced.
    pub inner: &'a [u8],
}

impl<'a> SyncedRecord<'a> {
    /// Writes the record.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x03)?;
        let n = self.context.encode(w.tail())?;
        let at = w.position().saturating_add(n);
        let mut w = Writer::new(out.get_mut(at..).ok_or(Error::Malformed)?);
        w.u8(self.origin.scope)?;
        w.put(&self.origin.subject)?;
        w.u8(self.origin.author)?;
        w.u32(u32::try_from(self.inner.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.inner)?;
        Ok(at.saturating_add(w.position()))
    }

    /// Reads a record.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x03 {
            return Err(Error::Malformed);
        }
        let context_len = context_len_at(r.rest())?;
        let mut r = Reader::new(bytes.get(1..).ok_or(Error::Malformed)?);
        let context = CausalContext::parse(r.take(context_len)?)?;
        let origin = Origin {
            scope: r.u8()?,
            subject: r.array()?,
            author: r.u8()?,
        };
        // DEV-292, DEV-296: two scopes and two authors.
        if !matches!(origin.scope, SCOPE_PAIRWISE | SCOPE_GROUP) || origin.author > AUTHOR_PEER {
            return Err(Error::Malformed);
        }
        let inner_len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        let inner = r.take(inner_len)?;
        r.finish()?;
        Ok(SyncedRecord {
            context,
            origin,
            inner,
        })
    }
}

/// The length of the context at the front of `bytes`, from its count.
fn context_len_at(bytes: &[u8]) -> Result<usize, Error> {
    let count = usize::from(*bytes.get(9).ok_or(Error::Malformed)?);
    Ok(1 + 8 + 1 + count * 24 + 4)
}

/// One item of mutable state, the payload of kind `0x20` sub-kind `0x01`:
/// the causal context, the item of the table of §7.5.3, its key, and its
/// value. Last writer wins by the context, then by the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutableItem<'a> {
    /// The causal context.
    pub context: CausalContext,
    /// The item, a row of the mutable-state table in its order from 1.
    pub item: u8,
    /// The scope key: a conversation, a contact, an identity, or a message.
    pub key: &'a [u8],
    /// The value.
    pub value: &'a [u8],
}

impl<'a> MutableItem<'a> {
    /// Writes the item.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        let n = self.context.encode(w.tail())?;
        let at = w.position().saturating_add(n);
        let mut w = Writer::new(out.get_mut(at..).ok_or(Error::Malformed)?);
        w.u8(self.item)?;
        w.u16(u16::try_from(self.key.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.key)?;
        w.u16(u16::try_from(self.value.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.value)?;
        Ok(at.saturating_add(w.position()))
    }

    /// Reads an item.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let context_len = context_len_at(r.rest())?;
        let mut r = Reader::new(bytes.get(1..).ok_or(Error::Malformed)?);
        let context = CausalContext::parse(r.take(context_len)?)?;
        let item = r.u8()?;
        let key_len = usize::from(r.u16()?);
        let key = r.take(key_len)?;
        let value_len = usize::from(r.u16()?);
        let value = r.take(value_len)?;
        r.finish()?;
        Ok(MutableItem {
            context,
            item,
            key,
            value,
        })
    }

    /// Whether this write wins against `held` (§7.5.3): the higher Lamport
    /// counter, then the lower device.
    pub fn wins_over(
        &self,
        held: &MutableItem<'_>,
        own_device: &DeviceId,
        held_device: &DeviceId,
    ) -> bool {
        self.context.lamport > held.context.lamport
            || (self.context.lamport == held.context.lamport && own_device < held_device)
    }
}

/// The source watermarks of one device (§7.5.2): the counter at or below
/// which each source's records are gone, and an insertion below it is
/// rejected (`DEV-037`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watermarks {
    marks: BTreeMap<DeviceId, u64>,
}

impl Watermarks {
    /// The watermark of `source`, or zero.
    pub fn get(&self, source: &DeviceId) -> u64 {
        self.marks.get(source).copied().unwrap_or(0)
    }

    /// Records that every record of `source` at or below `counter` is gone
    /// (`DEV-015`). A watermark never moves down (`DEV-016` is the caller's
    /// rule about held records).
    pub fn advance(&mut self, source: DeviceId, counter: u64) {
        let entry = self.marks.entry(source).or_insert(0);
        if counter > *entry {
            *entry = counter;
        }
    }

    /// A `live` device sets each watermark to the current counter of the
    /// source at the link (`DEV-017`, `DEV-018`).
    pub fn set_live(&mut self, sources: &[(DeviceId, u64)]) {
        for (source, counter) in sources {
            self.marks.insert(*source, *counter);
        }
    }

    /// Whether an insertion from `source` at `counter` is accepted.
    pub fn accepts(&self, source: &DeviceId, counter: u64) -> bool {
        counter > self.get(source)
    }

    pub(super) fn export(&self, w: &mut stored::Writer) {
        w.u32(u32::try_from(self.marks.len()).unwrap_or(0));
        for (source, counter) in &self.marks {
            w.bytes(source);
            w.u64(*counter);
        }
    }

    pub(super) fn restore(r: &mut stored::Reader<'_>) -> Result<Self, Error> {
        let mut marks = BTreeMap::new();
        for _ in 0..bounded(r.u32()?)? {
            let source: DeviceId = r.array()?;
            marks.insert(source, r.u64()?);
        }
        Ok(Watermarks { marks })
    }
}

/// A count of a stored form, bounded so that a damaged row allocates
/// nothing large.
pub(super) fn bounded(count: u32) -> Result<usize, Error> {
    let count = usize::try_from(count).map_err(|_| Error::Malformed)?;
    if count > 1 << 20 {
        return Err(Error::Malformed);
    }
    Ok(count)
}

/// One retained record, keyed by `msg_ref` and the causal counter
/// (`DEV-066`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retained {
    /// The stored reference.
    pub msg_ref: [u8; 16],
    /// The causal counter of the sender at the send.
    pub counter: u64,
    /// The send time.
    pub sent_at: u64,
}

/// The durable log of what one device sent to one peer (§7.5.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetainedLog {
    records: Vec<Retained>,
    acked: u64,
}

impl RetainedLog {
    /// Retains a sent record (`DEV-065`).
    pub fn sent(&mut self, msg_ref: [u8; 16], counter: u64, now: u64) {
        self.records.push(Retained {
            msg_ref,
            counter,
            sent_at: now,
        });
    }

    /// The peer's acknowledgment point (`DEV-055`).
    pub fn acked(&self) -> u64 {
        self.acked
    }

    /// A sync acknowledgment arrived; everything at or below leaves the log.
    pub fn acknowledged(&mut self, counter: u64) {
        if counter > self.acked {
            self.acked = counter;
        }
        self.records.retain(|r| r.counter > self.acked);
    }

    /// Drops what passed `SYNC_MAX_AGE` (`DEV-075`).
    pub fn expire(&mut self, now: u64) {
        self.records
            .retain(|r| now.saturating_sub(r.sent_at) < SYNC_MAX_AGE);
    }

    /// The records to resend, in counter order, at an acknowledgment or a
    /// new queue (`DEV-069` to `DEV-072`). The caller paces them
    /// (`DEV-073`).
    pub fn to_resend(&self) -> impl Iterator<Item = &Retained> {
        self.records.iter().filter(move |r| r.counter > self.acked)
    }

    /// Whether the peer lags enough for a catch-up object (`DEV-236`).
    pub fn needs_catch_up(&self, own_counter: u64) -> bool {
        own_counter.saturating_sub(self.acked) > SYNC_CATCHUP_LAG
    }

    pub(super) fn export(&self, w: &mut stored::Writer) {
        w.u64(self.acked);
        w.u32(u32::try_from(self.records.len()).unwrap_or(0));
        for record in &self.records {
            w.bytes(&record.msg_ref);
            w.u64(record.counter);
            w.u64(record.sent_at);
        }
    }

    pub(super) fn restore(r: &mut stored::Reader<'_>) -> Result<Self, Error> {
        let acked = r.u64()?;
        let mut records = Vec::new();
        for _ in 0..bounded(r.u32()?)? {
            records.push(Retained {
                msg_ref: r.array()?,
                counter: r.u64()?,
                sent_at: r.u64()?,
            });
        }
        Ok(RetainedLog { records, acked })
    }
}

/// The acknowledgment batch state for one peer (§7.5.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckBatch {
    pending: u32,
    period_start: Option<u64>,
    highest: u64,
}

impl AckBatch {
    /// A record of the peer at `counter` was taken, pruned, or declined by
    /// a watermark, thus it needs no resend.
    pub fn took(&mut self, counter: u64, now: u64) {
        if counter > self.highest {
            self.highest = counter;
        }
        self.pending = self.pending.saturating_add(1);
        if self.period_start.is_none() {
            self.period_start = Some(now);
        }
    }

    /// The `SyncAck` counter to send at `now`, if the batch or the period is
    /// due (`DEV-056`, `DEV-057`, `DEV-060`, `DEV-061`).
    pub fn due(&self, now: u64) -> Option<u64> {
        if self.pending == 0 {
            return None;
        }
        let batch = self.pending >= SYNC_ACK_BATCH;
        let period = self
            .period_start
            .is_some_and(|start| now.saturating_sub(start) >= SYNC_ACK_MAX_DELAY);
        (batch || period).then_some(self.highest)
    }

    /// The acknowledgment was sent (`DEV-058`, `DEV-059`).
    pub fn sent(&mut self) {
        self.pending = 0;
        self.period_start = None;
    }

    pub(super) fn export(&self, w: &mut stored::Writer) {
        w.u32(self.pending);
        w.u64(self.period_start.unwrap_or(u64::MAX));
        w.u64(self.highest);
    }

    pub(super) fn restore(r: &mut stored::Reader<'_>) -> Result<Self, Error> {
        let pending = r.u32()?;
        let start = r.u64()?;
        Ok(AckBatch {
            pending,
            period_start: (start != u64::MAX).then_some(start),
            highest: r.u64()?,
        })
    }
}

/// The token bucket of interactive sync records (`DEV-195`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveBucket {
    tokens: u32,
    last: u64,
}

impl Default for InteractiveBucket {
    fn default() -> Self {
        InteractiveBucket {
            tokens: SYNC_INTERACTIVE_BURST,
            last: 0,
        }
    }
}

impl InteractiveBucket {
    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last);
        let refill = u32::try_from(elapsed / 60)
            .unwrap_or(u32::MAX)
            .saturating_mul(SYNC_INTERACTIVE_RATE);
        if refill > 0 {
            self.tokens = self
                .tokens
                .saturating_add(refill)
                .min(SYNC_INTERACTIVE_BURST);
            self.last = now.saturating_sub(elapsed % 60);
        }
    }

    /// Takes one token for an interactive record at `now`, or reports that
    /// the record waits for the pacing clock (`DEV-241`).
    pub fn take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
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
    fn the_context_round_trips_in_device_order() {
        let ctx = CausalContext {
            lamport: 9,
            vector: vec![([1; 16], 4), ([2; 16], 7)],
            expires_in: 3_600,
        };
        let mut out = [0u8; 100];
        let n = ctx.encode(&mut out).unwrap();
        assert_eq!(CausalContext::parse(&out[..n]).unwrap(), ctx);
        assert_eq!(ctx.counter_of(&[2; 16]), Some(7));
        let bad = CausalContext {
            vector: vec![([2; 16], 7), ([1; 16], 4)],
            ..ctx
        };
        assert!(bad.encode(&mut out).is_err());
    }

    #[test]
    fn the_envelope_and_the_item_round_trip() {
        let ctx = CausalContext {
            lamport: 3,
            vector: vec![([1; 16], 3)],
            expires_in: 0,
        };
        let rec = SyncedRecord {
            context: ctx.clone(),
            origin: Origin {
                scope: SCOPE_PAIRWISE,
                subject: [4; 32],
                author: AUTHOR_PEER,
            },
            inner: b"app message bytes",
        };
        let mut out = [0u8; 200];
        let n = rec.encode(&mut out).unwrap();
        assert_eq!(SyncedRecord::parse(&out[..n]).unwrap(), rec);
        let entry = IdentityEntry {
            salt: [5; 16],
            conversation: [6; 32],
        };
        assert_eq!(IdentityEntry::parse(&entry.encode()).unwrap(), entry);
        assert!(IdentityEntry::parse(&entry.encode()[..48]).is_err());
        // DEV-292: a scope or an author that the layout does not name.
        let other_scope = SyncedRecord {
            origin: Origin {
                scope: 0x03,
                ..rec.origin
            },
            ..rec.clone()
        };
        let n = other_scope.encode(&mut out).unwrap();
        assert!(SyncedRecord::parse(&out[..n]).is_err());
        let item = MutableItem {
            context: ctx.clone(),
            item: 1,
            key: &[9; 32],
            value: &[1],
        };
        let n = item.encode(&mut out).unwrap();
        let back = MutableItem::parse(&out[..n]).unwrap();
        assert_eq!(back, item);
        let newer = MutableItem {
            context: CausalContext { lamport: 4, ..ctx },
            ..item.clone()
        };
        assert!(newer.wins_over(&item, &[2; 16], &[1; 16]));
        assert!(!item.wins_over(&newer, &[1; 16], &[2; 16]));
        assert!(item.wins_over(&item, &[0; 16], &[1; 16]));
    }

    #[test]
    fn the_watermark_the_log_and_the_batch_hold_their_rules() {
        let mut marks = Watermarks::default();
        marks.advance([1; 16], 10);
        marks.advance([1; 16], 5);
        assert!(!marks.accepts(&[1; 16], 10));
        assert!(marks.accepts(&[1; 16], 11));
        marks.set_live(&[([2; 16], 40)]);
        assert_eq!(marks.get(&[2; 16]), 40);

        let mut log = RetainedLog::default();
        for c in 1..=5u64 {
            log.sent([c as u8; 16], c, 100);
        }
        log.acknowledged(3);
        assert_eq!(log.to_resend().count(), 2);
        log.acknowledged(2);
        assert_eq!(log.acked(), 3);
        assert!(!log.needs_catch_up(3 + SYNC_CATCHUP_LAG));
        assert!(log.needs_catch_up(4 + SYNC_CATCHUP_LAG));
        log.expire(100 + SYNC_MAX_AGE);
        assert_eq!(log.to_resend().count(), 0);

        let mut batch = AckBatch::default();
        assert_eq!(batch.due(0), None);
        for c in 1..SYNC_ACK_BATCH as u64 {
            batch.took(c, 10);
        }
        assert_eq!(batch.due(10), None);
        assert_eq!(batch.due(10 + SYNC_ACK_MAX_DELAY), Some(31));
        batch.took(32, 11);
        assert_eq!(batch.due(11), Some(32));
        batch.sent();
        assert_eq!(batch.due(11 + SYNC_ACK_MAX_DELAY), None);

        let mut bucket = InteractiveBucket::default();
        for _ in 0..SYNC_INTERACTIVE_BURST {
            assert!(bucket.take(0));
        }
        assert!(!bucket.take(0));
        assert!(!bucket.take(59));
        assert!(bucket.take(60));
    }
}
