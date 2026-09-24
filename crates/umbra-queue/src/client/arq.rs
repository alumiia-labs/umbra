//! The ARQ of one outbound record (Part 3 §3.7) and the delivery state of
//! Part 14 §14.9.1 that it drives.
//!
//! A retransmission never fires at a timeout: the cover clock or the next
//! session opened for another cause carries it (`NET-071`, `NET-072`). This
//! machine says whether a send may happen; the runtime picks the moment.

use crate::{
    params::{GROUP_REPLICAS, SEND_GIVE_UP, SEND_MAX_ATTEMPTS},
    Reject,
};

/// Why an ARQ stopped without an acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailCause {
    /// A `NACK` with `REJECTED` or `VERSION` (`NET-217`).
    Permanent(Reject),
    /// `SEND_MAX_ATTEMPTS` sends (`NET-219`).
    Attempts,
    /// `SEND_GIVE_UP` after the first send (`NET-220`).
    GiveUp,
}

/// The delivery state of Part 14 §14.9.1. The list is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// No relay acknowledged the send.
    Queued,
    /// A relay acknowledged it.
    Accepted,
    /// A delivery receipt arrived.
    Delivered,
    /// A read receipt arrived.
    Read,
    /// The ARQ stopped.
    Failed(FailCause),
}

/// The ARQ of one record to one relay.
pub struct Arq {
    first_send: Option<u64>,
    attempts: u32,
    state: Delivery,
}

impl Default for Arq {
    fn default() -> Self {
        Self::new()
    }
}

impl Arq {
    /// A record that no relay has seen.
    pub const fn new() -> Self {
        Arq {
            first_send: None,
            attempts: 0,
            state: Delivery::Queued,
        }
    }

    /// The state.
    pub fn state(&self) -> Delivery {
        self.state
    }

    /// The sends so far.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Whether a send may happen at `now`. A `Failed` record needs a user
    /// action (`NET-222`), and `SEND_GIVE_UP` stops the ARQ first.
    pub fn may_send(&mut self, now: u64) -> bool {
        self.check_give_up(now);
        matches!(self.state, Delivery::Queued) && self.attempts < SEND_MAX_ATTEMPTS
    }

    /// Records one send at `now`. Fails the record at `SEND_MAX_ATTEMPTS`
    /// when this send was the last one allowed.
    pub fn sent(&mut self, now: u64) {
        if self.first_send.is_none() {
            self.first_send = Some(now);
        }
        self.attempts = self.attempts.saturating_add(1);
    }

    /// The relay acknowledged the record.
    pub fn accepted(&mut self) {
        if matches!(self.state, Delivery::Queued) {
            self.state = Delivery::Accepted;
        }
    }

    /// A `NACK` arrived. A permanent reason stops the ARQ; the others
    /// continue it (`NET-217`, `NET-218`).
    pub fn rejected(&mut self, reason: Reject) {
        if !matches!(self.state, Delivery::Queued) {
            return;
        }
        if matches!(reason, Reject::Rejected | Reject::Version) {
            self.state = Delivery::Failed(FailCause::Permanent(reason));
        }
    }

    /// A delivery receipt arrived.
    pub fn delivered(&mut self) {
        if matches!(self.state, Delivery::Accepted) {
            self.state = Delivery::Delivered;
        }
    }

    /// A read receipt arrived.
    pub fn read(&mut self) {
        if matches!(self.state, Delivery::Accepted | Delivery::Delivered) {
            self.state = Delivery::Read;
        }
    }

    /// The user asked for a resend of a failed record (`IMP-074`).
    pub fn resend_by_user(&mut self) {
        if matches!(self.state, Delivery::Failed(_)) {
            *self = Arq::new();
        }
    }

    fn check_give_up(&mut self, now: u64) {
        if !matches!(self.state, Delivery::Queued) {
            return;
        }
        if self
            .first_send
            .is_some_and(|first| now.saturating_sub(first) >= SEND_GIVE_UP)
        {
            self.state = Delivery::Failed(FailCause::GiveUp);
        } else if self.attempts >= SEND_MAX_ATTEMPTS {
            self.state = Delivery::Failed(FailCause::Attempts);
        }
    }

    /// Applies the two stop rules at `now` without a send, for a runtime
    /// that wakes.
    pub fn tick(&mut self, now: u64) -> Delivery {
        self.check_give_up(now);
        self.state
    }
}

/// The ARQ of one `GPOST` to its two replicas (`NET-270` to `NET-272`).
pub struct GroupArq {
    replicas: [Arq; GROUP_REPLICAS],
}

impl Default for GroupArq {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupArq {
    /// A post that no replica has seen.
    pub const fn new() -> Self {
        GroupArq {
            replicas: [Arq::new(), Arq::new()],
        }
    }

    /// The ARQ of one replica.
    pub fn replica(&mut self, index: usize) -> Option<&mut Arq> {
        self.replicas.get_mut(index)
    }

    /// The state of the post: `accepted` when any replica returned a
    /// `GSEQ` (`NET-257`), `failed` only when every replica failed
    /// (`NET-272`), and `queued` otherwise.
    pub fn state(&mut self, now: u64) -> Delivery {
        let states = [self.replicas[0].tick(now), self.replicas[1].tick(now)];
        if states.iter().any(|s| matches!(s, Delivery::Accepted)) {
            return Delivery::Accepted;
        }
        if states.iter().all(|s| matches!(s, Delivery::Failed(_))) {
            return Delivery::Failed(FailCause::GiveUp);
        }
        Delivery::Queued
    }

    /// The replicas that failed after the other accepted, which the client
    /// reports as a link fault (`NET-259`).
    pub fn faulted_replicas(&mut self, now: u64) -> [bool; GROUP_REPLICAS] {
        let accepted = matches!(self.state(now), Delivery::Accepted);
        let mut out = [false; GROUP_REPLICAS];
        for (flag, arq) in out.iter_mut().zip(self.replicas.iter_mut()) {
            *flag = accepted && matches!(arq.tick(now), Delivery::Failed(_));
        }
        out
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
    fn the_arq_stops_at_the_three_ends() {
        let mut a = Arq::new();
        for i in 0..SEND_MAX_ATTEMPTS {
            assert!(a.may_send(u64::from(i)));
            a.sent(u64::from(i));
        }
        assert!(!a.may_send(100));
        assert_eq!(a.state(), Delivery::Failed(FailCause::Attempts));
        a.resend_by_user();
        assert!(a.may_send(200));
        a.sent(200);
        assert!(!a.may_send(200 + SEND_GIVE_UP));
        assert_eq!(a.state(), Delivery::Failed(FailCause::GiveUp));

        let mut b = Arq::new();
        b.sent(0);
        b.rejected(Reject::Limit);
        assert!(b.may_send(1));
        b.rejected(Reject::Rejected);
        assert_eq!(
            b.state(),
            Delivery::Failed(FailCause::Permanent(Reject::Rejected))
        );

        let mut c = Arq::new();
        c.sent(0);
        c.accepted();
        c.rejected(Reject::Rejected);
        assert_eq!(c.state(), Delivery::Accepted);
        c.read();
        assert_eq!(c.state(), Delivery::Read);
        assert!(!c.may_send(1));
    }

    #[test]
    fn a_group_post_is_accepted_at_the_first_replica() {
        let mut g = GroupArq::new();
        g.replica(0).unwrap().sent(0);
        g.replica(1).unwrap().sent(0);
        assert_eq!(g.state(1), Delivery::Queued);
        g.replica(1).unwrap().accepted();
        assert_eq!(g.state(1), Delivery::Accepted);
        g.replica(0).unwrap().rejected(Reject::Rejected);
        assert_eq!(g.faulted_replicas(1), [true, false]);
        let mut h = GroupArq::new();
        h.replica(0).unwrap().rejected(Reject::Version);
        h.replica(1).unwrap().sent(0);
        assert_eq!(h.state(SEND_GIVE_UP), Delivery::Failed(FailCause::GiveUp));
        assert!(h.replica(2).is_none());
    }
}
