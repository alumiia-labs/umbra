//! The loop count and the forced replacements of Part 10 §10.4.2: what each
//! chain of this client did in each consensus epoch, and the link-fault
//! reports that follow from it (`REL-076`, `REL-163` to `REL-165`,
//! `REL-171`, `REL-172`). The type holds counts and no circuit, thus a test
//! drives it with a clock alone.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use crate::directory::{report::LinkFaultReport, EPOCH_SECONDS};

/// The three relays of a chain, the ingress first.
pub type Chain = [[u8; 32]; 3];

/// `LOOP_RETURN_WAIT`: a loop that has not come back after it is lost.
pub const LOOP_RETURN_WAIT: u64 = 120;
/// `LOOP_FAULT_MIN`: the loops of one chain below which no rate counts.
pub const LOOP_FAULT_MIN: u16 = 10;
/// `LOOP_FAULT_RATE`, in percent of the loops of one chain.
pub const LOOP_FAULT_RATE: u16 = 20;
/// `FORCED_REPEAT`: the forced replacements of one epoch that send a report.
pub const FORCED_REPEAT: u16 = 2;
/// `REPORT_WAIT`: the wait of a report before it builds a circuit
/// (`REL-181`, `REL-182`).
pub const REPORT_WAIT: u64 = 15 * 60;
/// The reports that wait for a slot at one time. An older one goes first.
const DUE_MAX: usize = 4;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Count {
    loops_sent: u16,
    loops_back: u16,
    loops_lost: u16,
    /// The send time of each loop that has not come back, the oldest first.
    waiting: VecDeque<u64>,
    builds: u16,
    failed_builds: u16,
}

/// The counts of the chains of this client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkFaults {
    counts: BTreeMap<(u64, Chain), Count>,
    /// The forced replacements of each epoch.
    forced: BTreeMap<u64, u16>,
    /// The chains of each epoch that a report named already.
    reported: BTreeSet<(u64, Chain)>,
    /// Each report that waits, with the time it became due.
    due: VecDeque<(LinkFaultReport, u64)>,
}

fn epoch_of(now: u64) -> u64 {
    now / EPOCH_SECONDS
}

impl LinkFaults {
    fn count(&mut self, chain: &Chain, now: u64) -> &mut Count {
        self.counts.entry((epoch_of(now), *chain)).or_default()
    }

    /// A loop left on a circuit of `chain`.
    pub fn loop_sent(&mut self, chain: &Chain, now: u64) {
        let count = self.count(chain, now);
        count.loops_sent = count.loops_sent.saturating_add(1);
        count.waiting.push_back(now);
    }

    /// A loop came back on a circuit of `chain`. It closes the oldest loop
    /// that waits, of this epoch or of the one before it.
    pub fn loop_back(&mut self, chain: &Chain, now: u64) {
        let epoch = epoch_of(now);
        for held in [epoch.saturating_sub(1), epoch] {
            if let Some(count) = self.counts.get_mut(&(held, *chain)) {
                if count.waiting.pop_front().is_some() {
                    count.loops_back = count.loops_back.saturating_add(1);
                    return;
                }
            }
        }
    }

    /// A build of `chain` started.
    pub fn build_started(&mut self, chain: &Chain, now: u64) {
        let count = self.count(chain, now);
        count.builds = count.builds.saturating_add(1);
    }

    /// A build of `chain` failed, or a circuit of it ended with no teardown
    /// by this client: a forced replacement (`REL-171`). The count that
    /// reaches `FORCED_REPEAT` sends a report of this chain (`REL-172`).
    pub fn forced_replacement(&mut self, chain: &Chain, now: u64) {
        let epoch = epoch_of(now);
        let count = self.count(chain, now);
        count.failed_builds = count.failed_builds.saturating_add(1);
        let (sent, lost) = (
            count.builds.saturating_add(count.loops_sent),
            count.failed_builds.saturating_add(count.loops_lost),
        );
        let forced = self.forced.entry(epoch).or_default();
        *forced = forced.saturating_add(1);
        if *forced == FORCED_REPEAT {
            self.report(epoch, chain, sent.max(lost), lost, now);
        }
    }

    fn report(&mut self, epoch: u64, chain: &Chain, loops_sent: u16, loops_lost: u16, now: u64) {
        if !self.reported.insert((epoch, *chain)) {
            return;
        }
        if self.due.len() >= DUE_MAX {
            self.due.pop_front();
        }
        let report = LinkFaultReport {
            epoch,
            hops: *chain,
            loops_sent,
            loops_lost,
        };
        self.due.push_back((report, now));
    }

    /// Counts the loops lost at `now`, and closes each epoch before the
    /// current one whose loops all resolved: a chain at `LOOP_FAULT_RATE`
    /// with at least `LOOP_FAULT_MIN` loops gives a report (`REL-076`).
    pub fn tick(&mut self, now: u64) {
        let epoch = epoch_of(now);
        let mut closed = Vec::new();
        for ((held, chain), count) in &mut self.counts {
            while count
                .waiting
                .front()
                .is_some_and(|sent| now.saturating_sub(*sent) >= LOOP_RETURN_WAIT)
            {
                count.waiting.pop_front();
                count.loops_lost = count.loops_lost.saturating_add(1);
            }
            if *held < epoch && count.waiting.is_empty() {
                closed.push((*held, *chain));
            }
        }
        for key in closed {
            let Some(count) = self.counts.remove(&key) else {
                continue;
            };
            let at_rate = u32::from(count.loops_lost) * 100
                >= u32::from(count.loops_sent) * u32::from(LOOP_FAULT_RATE);
            if count.loops_sent >= LOOP_FAULT_MIN && at_rate {
                self.report(key.0, &key.1, count.loops_sent, count.loops_lost, now);
            }
        }
        // The reports and the counts of forced replacements older than the
        // epoch before this one name no epoch that an authority takes
        // (`REL-170`).
        let floor = epoch.saturating_sub(1);
        self.forced.retain(|held, _| *held >= floor);
        self.reported.retain(|(held, _)| *held >= floor);
        self.due.retain(|(report, _)| report.epoch >= floor);
    }

    /// The oldest report that waits for a slot.
    pub fn due(&self) -> Option<&LinkFaultReport> {
        self.due.front().map(|(report, _)| report)
    }

    /// The time at which the oldest report that waits became due.
    pub fn due_since(&self) -> Option<u64> {
        self.due.front().map(|(_, since)| *since)
    }

    /// The oldest report left in a slot.
    pub fn sent(&mut self) {
        self.due.pop_front();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const A: Chain = [[1; 32], [2; 32], [3; 32]];
    const B: Chain = [[1; 32], [4; 32], [5; 32]];
    const T0: u64 = 1_700_000_000 - 1_700_000_000 % EPOCH_SECONDS;

    #[test]
    fn a_chain_that_loses_a_fifth_of_its_loops_is_reported_after_its_epoch() {
        let mut faults = LinkFaults::default();
        for i in 0..10 {
            faults.loop_sent(&A, T0 + i * 60);
            faults.loop_sent(&B, T0 + i * 60);
            // Chain A gets 8 of 10 back, chain B 9.
            if i < 8 {
                faults.loop_back(&A, T0 + i * 60 + 5);
            }
            if i < 9 {
                faults.loop_back(&B, T0 + i * 60 + 5);
            }
        }
        faults.tick(T0 + 1_000);
        assert!(faults.due().is_none(), "the epoch runs");
        faults.tick(T0 + EPOCH_SECONDS + 10);
        let report = *faults.due().unwrap();
        assert_eq!(report.hops, A);
        assert_eq!((report.loops_sent, report.loops_lost), (10, 2));
        assert_eq!(report.epoch, T0 / EPOCH_SECONDS);
        faults.sent();
        assert!(faults.due().is_none(), "B lost one in ten");
    }

    #[test]
    fn a_chain_with_few_loops_gives_no_report() {
        let mut faults = LinkFaults::default();
        for i in 0..3 {
            faults.loop_sent(&A, T0 + i);
        }
        faults.tick(T0 + EPOCH_SECONDS + LOOP_RETURN_WAIT);
        assert!(faults.due().is_none());
    }

    #[test]
    fn a_loop_near_the_end_of_an_epoch_counts_after_its_wait() {
        let mut faults = LinkFaults::default();
        for i in 0..10 {
            faults.loop_sent(&A, T0 + EPOCH_SECONDS - 50 + i);
        }
        // The next epoch starts, and the loops still wait.
        faults.tick(T0 + EPOCH_SECONDS + 1);
        assert!(faults.due().is_none());
        for i in 0..10 {
            faults.loop_back(&A, T0 + EPOCH_SECONDS + 5 + i);
        }
        faults.tick(T0 + EPOCH_SECONDS + 200);
        assert!(faults.due().is_none(), "each loop came back");
    }

    #[test]
    fn the_second_forced_replacement_of_an_epoch_reports_its_chain_once() {
        let mut faults = LinkFaults::default();
        faults.build_started(&A, T0);
        faults.forced_replacement(&A, T0 + 1);
        assert!(faults.due().is_none());
        faults.build_started(&B, T0 + 2);
        faults.forced_replacement(&B, T0 + 3);
        let report = *faults.due().unwrap();
        assert_eq!(report.hops, B);
        assert_eq!((report.loops_sent, report.loops_lost), (1, 1));
        faults.sent();
        faults.forced_replacement(&B, T0 + 4);
        assert!(faults.due().is_none(), "one report of a chain in an epoch");
        // An old report goes when its epoch passes the one before this.
        faults.forced_replacement(&A, T0 + EPOCH_SECONDS);
        faults.forced_replacement(&A, T0 + EPOCH_SECONDS + 1);
        assert!(faults.due().is_some());
        faults.tick(T0 + 3 * EPOCH_SECONDS);
        assert!(faults.due().is_none());
    }
}
