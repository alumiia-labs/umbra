//! The acknowledgment cursor of one queue at a recipient (Part 6 §6.4.3
//! rule 7): a cumulative `ACK` never crosses a hole, except after
//! `ACK_HOLE_TIMEOUT`, and then the conversation shows a gap.

use alloc::collections::BTreeMap;

use umbra_crypto::stored::{Reader, Writer};

use crate::params::{ACK_HOLE_TIMEOUT, DRAIN_THRESHOLD, IN_FLIGHT_WINDOW, RECEIPT_MIN_DELAY};

/// The cursor of one queue.
pub struct AckCursor {
    acked: u32,
    received: BTreeMap<u32, u64>,
    hole_since: Option<u64>,
    gap_shown: bool,
}

/// What the cursor offers to acknowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPoint {
    /// The `s` of the `ACK`.
    pub seq: u32,
    /// Whether the `ACK` crosses a hole, which the conversation must show
    /// as a delivery gap (`WIR-117`).
    pub crosses_hole: bool,
}

impl Default for AckCursor {
    fn default() -> Self {
        Self::new(0)
    }
}

impl AckCursor {
    /// Writes the cursor for the at-rest store. A client stores it in the
    /// batch that commits the records it covers (`WIR-115`), thus a record
    /// that arrives a second time after a restart is a duplicate.
    pub fn export(&self, writer: &mut Writer) -> Result<(), umbra_crypto::Error> {
        writer.u32(self.acked);
        let count = u32::try_from(self.received.len());
        writer.u32(count.map_err(|_| umbra_crypto::Error::Length)?);
        for (seq, at) in &self.received {
            writer.u32(*seq);
            writer.u64(*at);
        }
        writer.option(self.hole_since.as_ref(), |w, since| w.u64(*since));
        writer.flag(self.gap_shown);
        Ok(())
    }

    /// Reads the cursor that [`AckCursor::export`] wrote.
    pub fn restore(reader: &mut Reader<'_>) -> Result<Self, umbra_crypto::Error> {
        let acked = reader.u32()?;
        let count = reader.u32()?;
        if count > IN_FLIGHT_WINDOW {
            return Err(umbra_crypto::Error::Length);
        }
        let mut received = BTreeMap::new();
        for _ in 0..count {
            let seq = reader.u32()?;
            received.insert(seq, reader.u64()?);
        }
        Ok(AckCursor {
            acked,
            received,
            hole_since: reader.option(|r| r.u64())?,
            gap_shown: reader.flag()?,
        })
    }

    /// A cursor whose last acknowledged sequence is `acked`.
    pub fn new(acked: u32) -> Self {
        AckCursor {
            acked,
            received: BTreeMap::new(),
            hole_since: None,
            gap_shown: false,
        }
    }

    /// The last acknowledged sequence number, the cursor of the peek.
    pub fn acked(&self) -> u32 {
        self.acked
    }

    /// Records a `MSG` at `seq`, committed to the store. A record that
    /// cannot be decrypted counts as received (`WIR-114`). Returns false
    /// for a sequence the cursor already covers.
    pub fn receive(&mut self, seq: u32, now: u64) -> bool {
        if seq <= self.acked || self.received.contains_key(&seq) {
            return false;
        }
        if seq > self.acked.saturating_add(IN_FLIGHT_WINDOW) {
            return false;
        }
        self.received.insert(seq, now);
        if self
            .received
            .keys()
            .next()
            .is_some_and(|first| *first > self.acked.saturating_add(1))
            && self.hole_since.is_none()
        {
            self.hole_since = Some(now);
        }
        true
    }

    /// The lowest sequence the recipient did not receive above the cursor,
    /// if one exists below a received record.
    pub fn hole(&self) -> Option<u32> {
        let mut expect = self.acked.saturating_add(1);
        for seq in self.received.keys() {
            if *seq != expect {
                return Some(expect);
            }
            expect = expect.saturating_add(1);
        }
        None
    }

    /// The `ACK` the cursor can send now, or `None` when nothing new is
    /// contiguous. After `ACK_HOLE_TIMEOUT` the point may cross the hole
    /// (`WIR-116`), and the point then says so. The point stops below a
    /// record that arrived less than `RECEIPT_MIN_DELAY` ago (`NET-050`).
    pub fn ack_point(&self, now: u64) -> Option<AckPoint> {
        let mut point = self.acked;
        let mut expect = self.acked.saturating_add(1);
        let mut crosses = false;
        for (seq, arrived) in &self.received {
            if now.saturating_sub(*arrived) < RECEIPT_MIN_DELAY {
                break;
            }
            if *seq != expect {
                let stale = self
                    .hole_since
                    .is_some_and(|since| now.saturating_sub(since) >= ACK_HOLE_TIMEOUT);
                if !stale {
                    break;
                }
                crosses = true;
            }
            point = *seq;
            expect = seq.saturating_add(1);
        }
        (point > self.acked).then_some(AckPoint {
            seq: point,
            crosses_hole: crosses,
        })
    }

    /// Commits an `ACK` at `point`, which the caller sent.
    pub fn acknowledged(&mut self, point: AckPoint) {
        self.acked = point.seq;
        self.received.retain(|seq, _| *seq > point.seq);
        if point.crosses_hole {
            self.gap_shown = true;
        }
        self.hole_since = match self.hole() {
            Some(_) => self.hole_since,
            None => None,
        };
    }

    /// Whether the conversation shows a delivery gap (`WIR-118`).
    pub fn gap_shown(&self) -> bool {
        self.gap_shown
    }

    /// Whether a peek of `backlog` records is above `DRAIN_THRESHOLD`, thus
    /// the relay answers it in one unpaced response (`NET-037`).
    pub const fn drains(backlog: usize) -> bool {
        backlog > DRAIN_THRESHOLD
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

    #[test]
    fn the_ack_stops_below_a_hole_until_the_timeout() {
        let mut c = AckCursor::new(0);
        assert!(c.receive(1, 100));
        assert!(c.receive(2, 101));
        assert!(c.receive(4, 102));
        assert!(!c.receive(2, 103));
        assert_eq!(c.hole(), Some(3));
        let p = c.ack_point(200).unwrap();
        assert_eq!(
            p,
            AckPoint {
                seq: 2,
                crosses_hole: false
            }
        );
        c.acknowledged(p);
        assert_eq!(c.acked(), 2);
        assert_eq!(c.ack_point(200), None);
        // The hole closes when 3 arrives.
        assert!(c.receive(3, 300));
        // NET-050: the record at 3 is too new, and the point waits for it.
        assert_eq!(c.ack_point(300 + RECEIPT_MIN_DELAY - 1), None);
        let p = c.ack_point(300 + RECEIPT_MIN_DELAY).unwrap();
        assert_eq!(p.seq, 4);
        assert!(!p.crosses_hole);
        c.acknowledged(p);
        assert!(!c.gap_shown());
    }

    #[test]
    fn a_stale_hole_may_be_crossed_and_shows_a_gap() {
        let mut c = AckCursor::new(10);
        c.receive(12, 1_000);
        assert_eq!(c.ack_point(1_000 + ACK_HOLE_TIMEOUT - 1), None);
        let p = c.ack_point(1_000 + ACK_HOLE_TIMEOUT).unwrap();
        assert_eq!(
            p,
            AckPoint {
                seq: 12,
                crosses_hole: true
            }
        );
        c.acknowledged(p);
        assert!(c.gap_shown());
        assert!(!c.receive(11, 2_000));
        assert!(!c.receive(10 + IN_FLIGHT_WINDOW + 5, 2_000));
        assert!(AckCursor::drains(61));
        assert!(!AckCursor::drains(60));
    }
}
