//! The push scheduler of a queue relay (Part 8 §8.4.2, §8.5): the
//! coalescing window for each handle, the expiry of a push, and the
//! re-push when no drain follows.

use alloc::{collections::BTreeMap, vec::Vec};

use super::{HANDLE_LEN, PUSH_TTL_MESSAGE, REPUSH_INTERVAL, REPUSH_MAX, WAKE_COALESCE_WINDOW};

/// A push to hand to the NDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Push {
    /// The handle.
    pub handle: [u8; HANDLE_LEN],
    /// The expiry the provider applies, in seconds (`NTF-065`, `NTF-086`).
    pub ttl: u64,
    /// Whether the push carries a digest.
    pub digest: bool,
    /// Whether the push is a re-push.
    pub repush: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HandleState {
    last_handoff: Option<u64>,
    pending: Option<bool>,
    undrained_since: Option<u64>,
    repushes: u32,
}

/// The scheduler over every handle of a relay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushScheduler {
    handles: BTreeMap<[u8; HANDLE_LEN], HandleState>,
}

impl PushScheduler {
    fn push(handle: [u8; HANDLE_LEN], digest: bool, repush: bool) -> Push {
        Push {
            handle,
            // NTF-086: one expiry for each push, thus the provider reads
            // no push kind from it. The blob alone names a digest.
            ttl: PUSH_TTL_MESSAGE,
            digest,
            repush,
        }
    }

    /// An arrival for `handle` at `now`: a push at once when the window is
    /// open, else one push at the end of the window (`NTF-048`, `NTF-049`).
    pub fn on_arrival(&mut self, handle: [u8; HANDLE_LEN], digest: bool, now: u64) -> Option<Push> {
        let state = self.handles.entry(handle).or_insert(HandleState {
            last_handoff: None,
            pending: None,
            undrained_since: None,
            repushes: 0,
        });
        let inside = state
            .last_handoff
            .is_some_and(|at| now.saturating_sub(at) < WAKE_COALESCE_WINDOW);
        if inside {
            // A message inside the window outranks a digest.
            state.pending = Some(state.pending.unwrap_or(true) && digest);
            return None;
        }
        // This push carries the wake of each arrival before it, thus the
        // end of the last window has nothing more to hand.
        state.pending = None;
        state.last_handoff = Some(now);
        state.undrained_since.get_or_insert(now);
        state.repushes = 0;
        Some(Self::push(handle, digest, false))
    }

    /// A drain of `handle`, which ends the re-push of `NTF-066` and the
    /// push that waits for the end of the window. The device holds each
    /// record of the window, thus one more push would wake it for nothing
    /// (`NTF-014`).
    pub fn on_drain(&mut self, handle: &[u8; HANDLE_LEN]) {
        if let Some(state) = self.handles.get_mut(handle) {
            state.pending = None;
            state.undrained_since = None;
            state.repushes = 0;
        }
    }

    /// The pushes due at `now`: the end of a window with an arrival inside
    /// it, and a re-push for a handle that no drain followed inside
    /// `REPUSH_INTERVAL`, at most `REPUSH_MAX` times (`NTF-066`, `NTF-067`).
    pub fn tick(&mut self, now: u64) -> Vec<Push> {
        let mut due = Vec::new();
        for (handle, state) in &mut self.handles {
            let window_closed = state
                .last_handoff
                .is_none_or(|at| now.saturating_sub(at) >= WAKE_COALESCE_WINDOW);
            if let (Some(digest), true) = (state.pending, window_closed) {
                state.pending = None;
                state.last_handoff = Some(now);
                // The arrival inside the window had no drain, thus this
                // push starts the re-push clock (`NTF-066`).
                state.undrained_since.get_or_insert(now);
                state.repushes = 0;
                due.push(Self::push(*handle, digest, false));
                continue;
            }
            let repush_due = state.undrained_since.is_some()
                && state.repushes < REPUSH_MAX
                && state
                    .last_handoff
                    .is_some_and(|at| now.saturating_sub(at) >= REPUSH_INTERVAL);
            if repush_due {
                state.repushes = state.repushes.saturating_add(1);
                state.last_handoff = Some(now);
                due.push(Self::push(*handle, false, true));
            }
        }
        // A handle with no push to come holds no state: an arrival makes it
        // again, thus the scheduler holds the handles of live work alone.
        self.handles.retain(|_, state| {
            state.pending.is_some()
                || (state.undrained_since.is_some() && state.repushes < REPUSH_MAX)
                || state
                    .last_handoff
                    .is_some_and(|at| now.saturating_sub(at) < WAKE_COALESCE_WINDOW)
        });
        due
    }

    /// Drops each push to come for `handle`: no queue names it any more,
    /// thus a later push would go under the binding of another handle.
    pub fn forget(&mut self, handle: &[u8; HANDLE_LEN]) {
        self.handles.remove(handle);
    }

    /// Whether the scheduler holds state of `handle`.
    pub fn holds(&self, handle: &[u8; HANDLE_LEN]) -> bool {
        self.handles.contains_key(handle)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_window_coalesces_and_a_message_outranks_a_digest() {
        let mut s = PushScheduler::default();
        let h = [1u8; 16];
        let first = s.on_arrival(h, true, 100).unwrap();
        assert_eq!(first.ttl, PUSH_TTL_MESSAGE);
        assert!(first.digest);
        assert!(s.on_arrival(h, true, 105).is_none());
        assert!(s.on_arrival(h, false, 106).is_none());
        assert!(s.tick(109).is_empty());
        let end = s.tick(110);
        assert_eq!(end.len(), 1);
        assert!(!end[0].digest);
        assert_eq!(end[0].ttl, PUSH_TTL_MESSAGE);
        assert!(s.tick(111).is_empty());
        // Another handle has its own window.
        assert!(s.on_arrival([2; 16], false, 111).is_some());
    }

    #[test]
    fn a_handle_with_no_drain_gets_at_most_three_re_pushes() {
        let mut s = PushScheduler::default();
        let h = [1u8; 16];
        s.on_arrival(h, false, 0).unwrap();
        assert!(s.tick(REPUSH_INTERVAL - 1).is_empty());
        let mut count = 0;
        let mut t = REPUSH_INTERVAL;
        while count < 5 {
            let due = s.tick(t);
            if due.is_empty() {
                break;
            }
            assert!(due[0].repush);
            count += 1;
            t += REPUSH_INTERVAL;
        }
        assert_eq!(count, REPUSH_MAX);
        // A drain ends the re-push; a new arrival starts it again.
        s.on_arrival(h, false, t + 1).unwrap();
        s.on_drain(&h);
        assert!(s.tick(t + 1 + REPUSH_INTERVAL).is_empty());
        s.on_arrival(h, false, t + 2 + REPUSH_INTERVAL).unwrap();
        assert_eq!(s.tick(t + 2 + 2 * REPUSH_INTERVAL).len(), 1);
    }

    #[test]
    fn a_drain_inside_the_window_ends_the_push_of_its_end() {
        let mut s = PushScheduler::default();
        let h = [1u8; 16];
        s.on_arrival(h, false, 0).unwrap();
        assert!(s.on_arrival(h, false, 1).is_none());
        // The device drains both records before the window ends.
        s.on_drain(&h);
        assert!(s.tick(WAKE_COALESCE_WINDOW).is_empty());
        assert!(s.tick(REPUSH_INTERVAL).is_empty());
        assert!(!s.holds(&h));
    }

    #[test]
    fn an_arrival_after_the_window_takes_the_push_of_its_end() {
        let mut s = PushScheduler::default();
        let h = [1u8; 16];
        s.on_arrival(h, false, 0).unwrap();
        assert!(s.on_arrival(h, false, 5).is_none());
        // No tick ran at the end of the window. The next arrival gives one
        // push at once, and the tick that follows hands no second one.
        s.on_arrival(h, false, WAKE_COALESCE_WINDOW + 2).unwrap();
        assert!(s.tick(WAKE_COALESCE_WINDOW + 3).is_empty());
        assert!(s.tick(2 * WAKE_COALESCE_WINDOW + 2).is_empty());
    }

    #[test]
    fn the_push_at_the_end_of_a_window_starts_the_re_push_clock() {
        let mut s = PushScheduler::default();
        let h = [1u8; 16];
        s.on_arrival(h, false, 0).unwrap();
        s.on_drain(&h);
        // An arrival after the drain and inside the window waits for its
        // end, and no drain follows the push of the end.
        assert!(s.on_arrival(h, false, 5).is_none());
        let end = s.tick(WAKE_COALESCE_WINDOW);
        assert_eq!(end.len(), 1);
        assert!(!end[0].repush);
        assert!(s.tick(2 * WAKE_COALESCE_WINDOW).is_empty());
        assert!(s.holds(&h));
        assert!(s
            .tick(WAKE_COALESCE_WINDOW + REPUSH_INTERVAL - 1)
            .is_empty());
        let again = s.tick(WAKE_COALESCE_WINDOW + REPUSH_INTERVAL);
        assert_eq!(again.len(), 1);
        assert!(again[0].repush);
    }
}
