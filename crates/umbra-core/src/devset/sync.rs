//! The sync channel machines of Part 7 §7.5.1, §7.5.2, §7.5.3, and §7.5.5:
//! the causal context, the source watermark, the retained-record log with
//! its acknowledgment point, the acknowledgment batch, the interactive
//! token bucket, and the catch-up trigger.
//!
//! The specification names the causal context as a compact version vector
//! with a Lamport counter and gives it no byte layout. The layout here is
//! the one the sync envelope carries, and the next amendment records it.

use alloc::{collections::BTreeMap, vec::Vec};

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
