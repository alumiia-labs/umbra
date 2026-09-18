//! The wake rules at the client (Part 8 §8.3, §8.4.1, §8.4.3, §8.2.6): the
//! three modes and their carriers, the fixed clock of Private mode with
//! its random phase, the bound of a push-wake session, and the drain of a
//! rendezvous queue in each mode.

use super::{RENDEZVOUS_DRAIN_PRIVATE, WAKE_SESSION_MAX};

/// The cadence of Private mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// 20 minutes.
    Twenty,
    /// 30 minutes.
    Thirty,
}

impl Cadence {
    /// The interval, in seconds.
    pub const fn seconds(self) -> u64 {
        match self {
            Cadence::Twenty => 20 * 60,
            Cadence::Thirty => 30 * 60,
        }
    }
}

/// The notification mode of one Profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// One push for each event.
    Instant,
    /// Constant-rate wakes.
    Private(Cadence),
    /// A drain when the user opens the application.
    Off,
}

/// The carrier a build holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// Firebase Cloud Messaging.
    Fcm,
    /// UnifiedPush.
    UnifiedPush,
    /// A persistent socket of the client.
    Socket,
    /// No carrier.
    None,
}

impl Carrier {
    /// Whether the carrier may carry a fixed-cadence wake (`NTF-038`,
    /// `NTF-039`).
    pub const fn carries_private(self) -> bool {
        matches!(self, Carrier::UnifiedPush | Carrier::Socket)
    }

    /// Whether Private mode is available on this build (`NTF-040`,
    /// `NTF-041`).
    pub const fn private_available(self) -> bool {
        self.carries_private()
    }
}

impl Mode {
    /// The shipped default (`NTF-083`).
    pub const DEFAULT: Mode = Mode::Instant;

    /// Whether the mode registers a push token and the digest queues of
    /// §8.5 (`NTF-045`, `NTF-069`, `NTF-074`, `NTF-090`, `NTF-106`).
    pub const fn registers_push(self) -> bool {
        matches!(self, Mode::Instant)
    }

    /// Whether the mode is available under `carrier`.
    pub const fn available(self, carrier: Carrier) -> bool {
        match self {
            Mode::Instant => !matches!(carrier, Carrier::None),
            Mode::Private(_) => carrier.private_available(),
            Mode::Off => true,
        }
    }
}

/// The fixed clock of Private mode: an interval and a phase from the
/// CSPRNG, drawn again at each network change and at each change of the
/// ingress pair (`NTF-052`, `NTF-053`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    interval: u64,
    phase: u64,
}

impl FixedClock {
    /// A clock at `cadence` with a phase from `random`.
    pub fn new(cadence: Cadence, random: u64) -> Self {
        let interval = cadence.seconds();
        FixedClock {
            interval,
            phase: random % interval,
        }
    }

    /// Draws the phase again.
    pub fn rephase(&mut self, random: u64) {
        self.phase = random % self.interval;
    }

    /// The next wake at or after `now`. An arrival never moves it.
    pub fn next_wake(&self, now: u64) -> u64 {
        let base = now.saturating_sub(self.phase);
        let slots = base / self.interval;
        let candidate = slots
            .saturating_mul(self.interval)
            .saturating_add(self.phase);
        if candidate >= now {
            candidate
        } else {
            candidate.saturating_add(self.interval)
        }
    }

    /// The interval.
    pub const fn interval(&self) -> u64 {
        self.interval
    }
}

/// A push-wake session, bounded by `WAKE_SESSION_MAX` and with no spare
/// circuit (`NTF-012`, `NTF-013`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeSession {
    opened_at: u64,
}

impl WakeSession {
    /// A session opened at `now`.
    pub const fn open(now: u64) -> Self {
        WakeSession { opened_at: now }
    }

    /// Whether the session must stop at `now`.
    pub fn must_stop(&self, now: u64) -> bool {
        now.saturating_sub(self.opened_at) >= WAKE_SESSION_MAX
    }

    /// The circuits a wake session builds: one, and no spare.
    pub const CIRCUITS: usize = 1;
}

/// Whether a rendezvous queue is due for a drain (`NTF-045` to
/// `NTF-047`). In Instant mode the push carries the wake, thus no scheduled
/// drain is due.
pub fn rendezvous_drain_due(
    mode: Mode,
    last_drain: Option<u64>,
    now: u64,
    foreground: bool,
) -> bool {
    match mode {
        Mode::Instant => false,
        Mode::Private(_) => {
            last_drain.is_none_or(|at| now.saturating_sub(at) >= RENDEZVOUS_DRAIN_PRIVATE)
        }
        Mode::Off => foreground,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_modes_follow_the_carrier_and_the_fixed_clock_ignores_arrivals() {
        assert!(Mode::Instant.available(Carrier::Fcm));
        assert!(!Mode::Private(Cadence::Twenty).available(Carrier::Fcm));
        assert!(Mode::Private(Cadence::Thirty).available(Carrier::UnifiedPush));
        assert!(Mode::Off.available(Carrier::None));
        assert!(!Mode::Instant.available(Carrier::None));
        assert!(Mode::DEFAULT.registers_push());
        assert!(!Mode::Private(Cadence::Twenty).registers_push());

        let clock = FixedClock::new(Cadence::Twenty, 1_000_007);
        let interval = clock.interval();
        let first = clock.next_wake(50_000);
        assert!(first >= 50_000 && first < 50_000 + interval);
        assert_eq!(clock.next_wake(first), first);
        assert_eq!(clock.next_wake(first + 1), first + interval);
        let mut moved = clock;
        moved.rephase(3);
        assert_eq!(moved.next_wake(0), 3);

        let session = WakeSession::open(10);
        assert!(!session.must_stop(15));
        assert!(session.must_stop(16));
        assert_eq!(WakeSession::CIRCUITS, 1);

        assert!(!rendezvous_drain_due(Mode::Instant, None, 0, false));
        assert!(rendezvous_drain_due(
            Mode::Private(Cadence::Twenty),
            None,
            0,
            false
        ));
        assert!(!rendezvous_drain_due(
            Mode::Private(Cadence::Twenty),
            Some(0),
            86_399,
            false
        ));
        assert!(rendezvous_drain_due(
            Mode::Private(Cadence::Twenty),
            Some(0),
            86_400,
            false
        ));
        assert!(rendezvous_drain_due(Mode::Off, Some(0), 1, true));
        assert!(!rendezvous_drain_due(Mode::Off, Some(0), 1, false));
    }
}
