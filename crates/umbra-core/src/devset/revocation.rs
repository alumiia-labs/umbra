//! The revocation of Part 7 §7.7 and the full identity reset of §7.7.1,
//! as the steps a device takes when it applies a roster epoch.

use alloc::vec::Vec;

use super::{roster::Roster, DeviceId};

/// One step of §7.7 that the runtime performs after it applies an epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Delete the sync channels to the revoked device (2a).
    DeleteSyncChannels(DeviceId),
    /// An immediate DH ratchet step on every pairwise channel this device
    /// owns (2b).
    RatchetEveryOwnedChannel,
    /// Rotate every queue the revoked device knew, with no `DEL` (2c).
    RotateQueuesKnownBy(DeviceId),
    /// Derive the next sync channel seed from the seed update of the
    /// signer (2d).
    ApplySeedUpdate,
    /// Start the group re-key of Part 11 §11.12 for each group (2e,
    /// `DEV-262`).
    RekeyEveryGroup,
    /// Show the count of deletions from the revoked device since the
    /// previous epoch, and the restore hint (`DEV-119`, `DEV-120`).
    ShowDeletionsFrom(DeviceId),
    /// Claim each subject the revoked device owned (3).
    ClaimSubjectsOf(DeviceId),
}

/// The steps for an applied epoch, given the epoch before it. An epoch
/// with no new tombstone gives no step (`DEV-254`).
pub fn steps(previous: &Roster<'_>, applied: &Roster<'_>) -> Vec<Step> {
    let new: Vec<DeviceId> = applied
        .revoked
        .iter()
        .filter(|t| !previous.revoked.contains(t))
        .copied()
        .collect();
    if new.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for device in &new {
        out.push(Step::DeleteSyncChannels(*device));
    }
    out.push(Step::RatchetEveryOwnedChannel);
    for device in &new {
        out.push(Step::RotateQueuesKnownBy(*device));
    }
    out.push(Step::ApplySeedUpdate);
    out.push(Step::RekeyEveryGroup);
    for device in &new {
        out.push(Step::ShowDeletionsFrom(*device));
        out.push(Step::ClaimSubjectsOf(*device));
    }
    out
}

/// What a full identity reset does beyond a new root (§7.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetStep {
    /// A new `DeviceRosterKey` on each remaining device (`DEV-172`).
    NewRosterKeyOnEachDevice,
    /// A new roster epoch 0 for the new set (`DEV-173`).
    PublishGenesis,
    /// A key-change notice to each contact, spread by the sweep delay.
    NoticeEachContact,
    /// The group re-key in each group (`DEV-263`).
    RekeyEveryGroup,
}

/// The steps of a full identity reset, in order.
pub const RESET_STEPS: [ResetStep; 4] = [
    ResetStep::NewRosterKeyOnEachDevice,
    ResetStep::PublishGenesis,
    ResetStep::NoticeEachContact,
    ResetStep::RekeyEveryGroup,
];

/// The two sentences the interface states about a revocation (`DEV-137`,
/// `DEV-138`).
pub const REVOCATION_LIMIT_TEXT: &str =
    "Revocation acts on the future only. A revoked device keeps the data that it synced.";
/// The recommendation for a device in hostile hands.
pub const HOSTILE_DEVICE_TEXT: &str =
    "For a device in hostile hands, reset the identity in the settings.";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::devset::roster::tests::entry;
    use alloc::vec;

    #[test]
    fn a_new_tombstone_gives_the_seven_steps_and_none_otherwise() {
        let kem = [0u8; 1_184];
        let pk = [0u8; 1_952];
        let sig = [0u8; 3_309];
        let before = Roster {
            epoch: 1,
            devices: vec![entry(1, &pk, &kem), entry(2, &pk, &kem)],
            revoked: Vec::new(),
            claims: Vec::new(),
            prev_hash: [0; 32],
            signer_id: [1; 16],
            sig: &sig,
        };
        let after = Roster {
            epoch: 2,
            devices: vec![entry(1, &pk, &kem)],
            revoked: vec![[2; 16]],
            ..before.clone()
        };
        let steps = steps(&before, &after);
        assert_eq!(steps.len(), 7);
        assert_eq!(steps[0], Step::DeleteSyncChannels([2; 16]));
        assert_eq!(steps[6], Step::ClaimSubjectsOf([2; 16]));
        assert!(super::steps(&after, &after).is_empty());
        assert_eq!(RESET_STEPS[1], ResetStep::PublishGenesis);
    }
}
