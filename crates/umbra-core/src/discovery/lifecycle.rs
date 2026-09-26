//! The lifecycle of a label at the directory (Part 9 §9.9, §9.9.2,
//! §9.9.3), the takeover check at the client (§9.9.2), and the scheduled
//! rendezvous rotation (§9.9).

use alloc::vec::Vec;

use super::{HANDLE_HISTORY_MAX, HANDLE_LEASE, HANDLE_RESERVE, RENDEZVOUS_ROTATE, ROTATE_GRACE};
use crate::Error;

/// One published version of a label, as the client reads it from the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// The version number.
    pub version: u32,
    /// `HK_pub`, or zero bytes in a tombstone.
    pub hk_pub: [u8; 1_216],
}

impl Version {
    /// Whether the version is a tombstone.
    pub fn is_tombstone(&self) -> bool {
        self.hk_pub == [0; 1_216]
    }
}

/// The state of one label at the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// The current version number.
    pub version: u32,
    /// The `HK_pub` of the current version, or of the last live version
    /// during the reservation.
    pub hk_pub: [u8; 1_216],
    /// The lease end, or `None` when tombstoned.
    pub lease_until: Option<u64>,
    /// The time of the tombstone, when tombstoned.
    pub tombstoned_at: Option<u64>,
    /// The lease epoch the directory issued last.
    pub lease_epoch: u64,
}

/// What a publication needs from the writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    /// A first-party token and no challenge (`DIS-101`).
    Token,
    /// The challenge against the current `HK_pub` (`DIS-093`).
    WriteChallenge,
    /// The renewal challenge against the last `HK_pub` of a tombstoned
    /// label inside `HANDLE_RESERVE` (`DIS-075`).
    ReserveChallenge,
}

impl Label {
    /// Registers a label that no version holds (`DIS-101`). The caller
    /// verified the token.
    pub fn register(hk_pub: [u8; 1_216], now: u64) -> Self {
        Label {
            version: 0,
            hk_pub,
            lease_until: Some(now.saturating_add(HANDLE_LEASE)),
            tombstoned_at: None,
            lease_epoch: 0,
        }
    }

    /// Whether the label is tombstoned.
    pub const fn is_tombstoned(&self) -> bool {
        self.tombstoned_at.is_some()
    }

    /// Whether the reservation of a tombstoned label holds at `now`
    /// (`DIS-074`).
    pub fn reserved(&self, now: u64) -> bool {
        self.tombstoned_at
            .is_some_and(|t| now.saturating_sub(t) < HANDLE_RESERVE)
    }

    /// What a new version needs at `now`.
    pub fn needs(&self, now: u64) -> Needs {
        if !self.is_tombstoned() {
            Needs::WriteChallenge
        } else if self.reserved(now) {
            Needs::ReserveChallenge
        } else {
            Needs::Token
        }
    }

    /// Publishes a new version after the write challenge or the reserve
    /// challenge verified (`DIS-076`, `DIS-098`, `DIS-099`). During the
    /// reservation the key stays the same; after it, any key registers
    /// under a token as the next version (`DIS-077`).
    pub fn publish(
        &mut self,
        version_new: u32,
        hk_pub: [u8; 1_216],
        now: u64,
    ) -> Result<(), Error> {
        if version_new != self.version.saturating_add(1) || hk_pub == [0; 1_216] {
            return Err(Error::Stale);
        }
        if self.needs(now) == Needs::ReserveChallenge && hk_pub != self.hk_pub {
            return Err(Error::Unverified);
        }
        self.version = version_new;
        self.hk_pub = hk_pub;
        self.lease_until = Some(now.saturating_add(HANDLE_LEASE));
        self.tombstoned_at = None;
        // A lease epoch issued before this version was encapsulated to the
        // key of an earlier version, thus it renews nothing now.
        self.lease_epoch = 0;
        Ok(())
    }

    /// Issues a lease epoch for a renewal challenge (`DIS-041`).
    pub fn issue_lease_epoch(&mut self) -> u64 {
        self.lease_epoch = self.lease_epoch.saturating_add(1);
        self.lease_epoch
    }

    /// Renews the lease after the challenge for `lease_epoch` verified
    /// (`DIS-040`, `DIS-041`).
    pub fn renew(&mut self, lease_epoch: u64, now: u64) -> Result<(), Error> {
        if self.is_tombstoned() || lease_epoch != self.lease_epoch {
            return Err(Error::Stale);
        }
        self.lease_until = Some(now.saturating_add(HANDLE_LEASE));
        Ok(())
    }

    /// Tombstones a live label at the request of its holder, after the
    /// write challenge verified (`DIS-171`). The reservation of `DIS-074`
    /// holds as for a lapsed lease.
    pub fn retire(&mut self, version_new: u32, now: u64) -> Result<(), Error> {
        if self.is_tombstoned() || version_new != self.version.saturating_add(1) {
            return Err(Error::Stale);
        }
        self.version = version_new;
        self.lease_until = None;
        self.tombstoned_at = Some(now);
        self.lease_epoch = 0;
        Ok(())
    }

    /// Tombstones a lapsed lease, and returns the tombstone version to
    /// publish (`DIS-073`, `DIS-102`).
    pub fn tombstone_if_lapsed(&mut self, now: u64) -> Option<u32> {
        if self.is_tombstoned() || self.lease_until.is_some_and(|until| now < until) {
            return None;
        }
        self.version = self.version.saturating_add(1);
        self.lease_until = None;
        self.tombstoned_at = Some(now);
        Some(self.version)
    }
}

/// What a client concludes before it replaces a held `HK_pub`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Takeover {
    /// A rotation: replace in silence (`DIS-020`).
    Silent,
    /// A different party now holds the handle: warn, and send no hello
    /// without a confirmation (`DIS-080`, `DIS-082`, `DIS-085`).
    Warn,
}

/// Assesses the versions between a held version and a resolved one
/// (`DIS-078` to `DIS-082`). `between` holds each version after `held`
/// up to and including `resolved`, in order.
pub fn assess(held: &Version, between: &[Version]) -> Result<Takeover, Error> {
    let resolved = between.last().ok_or(Error::Malformed)?;
    if resolved.version <= held.version {
        return Err(Error::Stale);
    }
    let expected: Vec<u32> = (held.version.saturating_add(1)..=resolved.version).collect();
    if between
        .iter()
        .map(|v| v.version)
        .ne(expected.iter().copied())
    {
        return Err(Error::Malformed);
    }
    if resolved.version.saturating_sub(held.version) > HANDLE_HISTORY_MAX {
        return Ok(Takeover::Warn);
    }
    let chain: Vec<&Version> = core::iter::once(held).chain(between.iter()).collect();
    for (i, v) in chain.iter().enumerate() {
        if v.is_tombstone() {
            let before = chain.get(i.wrapping_sub(1)).map(|b| b.hk_pub);
            let after = chain.get(i.saturating_add(1)).map(|a| a.hk_pub);
            if let (Some(b), Some(a)) = (before, after) {
                if b != a {
                    return Ok(Takeover::Warn);
                }
            }
        }
    }
    Ok(Takeover::Silent)
}

/// The scheduled rendezvous rotation of one published entry (`DIS-133`
/// to `DIS-135`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousSchedule {
    /// The write time of the current rendezvous version.
    pub written_at: u64,
    /// The write time of the previous version, while its grace runs.
    pub previous_written_at: Option<u64>,
}

impl RendezvousSchedule {
    /// A schedule from the first write.
    pub const fn new(written_at: u64) -> Self {
        RendezvousSchedule {
            written_at,
            previous_written_at: None,
        }
    }

    /// Whether a new rendezvous queue is due at `now`.
    pub fn due(&self, now: u64) -> bool {
        now.saturating_sub(self.written_at) >= RENDEZVOUS_ROTATE
    }

    /// Records the write of a new queue at `now`.
    pub fn rotated(&mut self, now: u64) {
        self.previous_written_at = Some(self.written_at);
        self.written_at = now;
    }

    /// Whether the previous queue is still drained at `now`.
    pub fn drain_previous(&self, now: u64) -> bool {
        self.previous_written_at.is_some() && now.saturating_sub(self.written_at) < ROTATE_GRACE
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> [u8; 1_216] {
        [seed; 1_216]
    }

    #[test]
    fn a_label_leases_tombstones_reserves_and_takes_over() {
        let mut label = Label::register(pk(1), 0);
        assert_eq!(label.needs(1), Needs::WriteChallenge);
        assert_eq!(label.publish(2, pk(2), 1), Err(Error::Stale));
        label.publish(1, pk(2), 1).unwrap();
        let epoch = label.issue_lease_epoch();
        assert_eq!(label.renew(epoch + 1, 2), Err(Error::Stale));
        label.renew(epoch, 2).unwrap();
        assert!(label.tombstone_if_lapsed(2 + HANDLE_LEASE - 1).is_none());
        assert_eq!(label.tombstone_if_lapsed(2 + HANDLE_LEASE), Some(2));
        let t = 2 + HANDLE_LEASE;
        assert!(label.tombstone_if_lapsed(t).is_none());
        assert_eq!(label.needs(t + 1), Needs::ReserveChallenge);
        assert_eq!(label.publish(3, pk(9), t + 1), Err(Error::Unverified));
        assert_eq!(label.publish(3, pk(0), t + 1), Err(Error::Stale));
        let mut restored = label.clone();
        restored.publish(3, pk(2), t + 1).unwrap();
        assert!(!restored.is_tombstoned());
        assert_eq!(label.needs(t + HANDLE_RESERVE), Needs::Token);
        label.publish(3, pk(9), t + HANDLE_RESERVE).unwrap();
        assert_eq!(label.version, 3);
        assert_eq!(label.renew(epoch, t + HANDLE_RESERVE), Err(Error::Stale));
    }

    #[test]
    fn the_takeover_check_reads_the_versions_between() {
        let held = Version {
            version: 1,
            hk_pub: pk(1),
        };
        let rotation = [Version {
            version: 2,
            hk_pub: pk(2),
        }];
        assert_eq!(assess(&held, &rotation).unwrap(), Takeover::Silent);
        let restore = [
            Version {
                version: 2,
                hk_pub: pk(0),
            },
            Version {
                version: 3,
                hk_pub: pk(1),
            },
        ];
        assert_eq!(assess(&held, &restore).unwrap(), Takeover::Silent);
        let takeover = [
            Version {
                version: 2,
                hk_pub: pk(0),
            },
            Version {
                version: 3,
                hk_pub: pk(7),
            },
        ];
        assert_eq!(assess(&held, &takeover).unwrap(), Takeover::Warn);
        let many: Vec<Version> = (2..=2 + HANDLE_HISTORY_MAX)
            .map(|v| Version {
                version: v,
                hk_pub: pk(1),
            })
            .collect();
        assert_eq!(assess(&held, &many).unwrap(), Takeover::Warn);
        assert_eq!(
            assess(&held, &many[..many.len() - 1]).unwrap(),
            Takeover::Silent
        );
        assert!(assess(&held, &[]).is_err());
        assert!(assess(&held, &restore[1..]).is_err());
        assert_eq!(assess(&restore[1], &rotation), Err(Error::Stale));
    }

    #[test]
    fn the_rendezvous_rotates_on_schedule_and_drains_the_previous_queue() {
        let mut s = RendezvousSchedule::new(0);
        assert!(!s.due(RENDEZVOUS_ROTATE - 1));
        assert!(s.due(RENDEZVOUS_ROTATE));
        assert!(!s.drain_previous(1));
        s.rotated(RENDEZVOUS_ROTATE);
        assert!(s.drain_previous(RENDEZVOUS_ROTATE + ROTATE_GRACE - 1));
        assert!(!s.drain_previous(RENDEZVOUS_ROTATE + ROTATE_GRACE));
    }
}
