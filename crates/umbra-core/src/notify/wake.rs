//! The wake rules at the client (Part 8 §8.3, §8.4.1, §8.4.2, §8.2.6): the
//! three modes and their carriers, and the bound of a push-wake session.

use super::WAKE_SESSION_MAX;

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
    /// §8.5 (`NTF-045`, `NTF-090`, `NTF-106`).
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

        let session = WakeSession::open(10);
        assert!(!session.must_stop(15));
        assert!(session.must_stop(16));
        assert_eq!(WakeSession::CIRCUITS, 1);
    }
}
