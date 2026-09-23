//! Identity, Part 4: the address strings, the invitation, the verification
//! ceremony, the local table MAC, the recovery code with its backup root,
//! and the key-change sweep. The root identity and the pairwise, public,
//! and handle keys themselves live in the crypto crate's hierarchy.

pub mod address;
pub mod backup;
pub mod invitation;
pub mod keychange;
pub mod recovery;
pub mod table;
pub mod verify;

/// `INVITE_TTL`, in seconds.
pub const INVITE_TTL: u64 = 14 * 86_400;
/// `PALETTE_SIZE`.
pub const PALETTE_SIZE: u8 = 12;
/// `HANDLE_KEY_LOOKAHEAD`.
pub const HANDLE_KEY_LOOKAHEAD: u32 = 64;
/// `BACKUP_INTERVAL`, in seconds.
pub const BACKUP_INTERVAL: u64 = 86_400;
/// `BACKUP_FULL_INTERVAL`, in seconds.
pub const BACKUP_FULL_INTERVAL: u64 = 30 * 86_400;
/// `BACKUP_REPLICAS`.
pub const BACKUP_REPLICAS: usize = 2;
/// `BACKUP_HISTORY_DAYS`.
pub const BACKUP_HISTORY_DAYS: u64 = 45;
/// `BACKUP_TTL`, in seconds.
pub const BACKUP_TTL: u64 = 180 * 86_400;
/// `BACKUP_LOOKBACK`, in weekly epochs.
pub const BACKUP_LOOKBACK: u32 = 26;
/// `BACKUP_ROOT_ENTRIES`.
pub const BACKUP_ROOT_ENTRIES: usize = 31;
/// `BACKUP_DESC_REFS`.
pub const BACKUP_DESC_REFS: usize = 7;
/// `SWEEP_SPREAD` of Part 7 §7.5.6, the mean in seconds.
pub const SWEEP_SPREAD: u64 = 30 * 60;
/// The consensus epochs in one weekly epoch.
pub const WEEK_EPOCHS: u64 = 168;

/// The weekly epoch of a consensus epoch (Part 4 §4.7.2, Part 3 §3.2.6).
pub const fn weekly_epoch(consensus_epoch: u64) -> u32 {
    let w = consensus_epoch / WEEK_EPOCHS;
    if w > u32::MAX as u64 {
        u32::MAX
    } else {
        w as u32
    }
}
