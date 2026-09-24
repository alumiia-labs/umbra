//! The private groups of Part 11: the roster and its chain, the epoch
//! state with its slot window and its rotation, the sender and the
//! receiver of a group record, the presence and the eviction, the join and
//! the re-key flows, and the client side of the group queue.
//!
//! The codecs live in `umbra_wire::group`, and the keys, the slot chain,
//! the tags, and the KEM slots in `umbra_crypto::group`. Each type here
//! takes the time and the random values it needs as arguments.

pub mod backoff;
pub mod epoch;
pub mod join;
pub mod presence;
pub mod queue;
pub mod receive;
pub mod roster;
pub mod send;
pub mod state;

/// `GROUP_MAX`.
pub const GROUP_MAX: usize = 500;
/// `GROUP_REPLICAS`.
pub const GROUP_REPLICAS: usize = 2;
/// `GROUP_SLOT`, in seconds.
pub const GROUP_SLOT: u64 = 3_600;
/// `GROUP_SLOT_WINDOW`, in slots.
pub const GROUP_SLOT_WINDOW: u32 = 24;
/// `GROUP_SLOT_SKEW`, in slots.
pub const GROUP_SLOT_SKEW: u32 = 2;
/// `GROUP_EPOCH_MAX_AGE`, in seconds from `t_e`.
pub const GROUP_EPOCH_MAX_AGE: u64 = 30 * 86_400;
/// `GROUP_EPOCH_GRACE`, in seconds; it equals `GROUP_WRITE_GRACE`.
pub const GROUP_EPOCH_GRACE: u64 = umbra_queue::params::GROUP_WRITE_GRACE;
/// `GROUP_ROSTER_WAIT`, in seconds.
pub const GROUP_ROSTER_WAIT: u64 = 24 * 3_600;
/// `GROUP_GAP_TIMEOUT`, in seconds.
pub const GROUP_GAP_TIMEOUT: u64 = 60;
/// `ROTATE_BACKOFF_ROLE`, the mean in seconds.
pub const ROTATE_BACKOFF_ROLE: u64 = 10;
/// `ROTATE_BACKOFF_MEMBER`, the mean in seconds.
pub const ROTATE_BACKOFF_MEMBER: u64 = 60;
/// `GROUP_INDEX_MAX`.
pub const GROUP_INDEX_MAX: u16 = u16::MAX;
/// `ROLE_HOLDER_MAX`, members at `moderator` or above.
pub const ROLE_HOLDER_MAX: usize = 16;
/// `GROUP_ALL_NOTIFY_MAX`.
pub const GROUP_ALL_NOTIFY_MAX: usize = 50;
/// `GROUP_SILENT_EVICT`, in seconds; it equals `GROUP_RETENTION`.
pub const GROUP_SILENT_EVICT: u64 = umbra_queue::params::GROUP_RETENTION;
/// `PRESENCE_INTERVAL`, in seconds.
pub const PRESENCE_INTERVAL: u64 = 7 * 86_400;
/// The most `HISTORY_WINDOW` an admin may turn on, in seconds.
pub const HISTORY_WINDOW_MAX: u64 = 7 * 86_400;
/// `ROSTER_RATE_LIMIT`: one epoch for each member in this many seconds.
pub const ROSTER_RATE_LIMIT: u64 = 60;
/// `GROUP_EPOCH_RATE`: this many epochs for each group in 60 seconds.
pub const GROUP_EPOCH_RATE: u32 = 6;
/// `GRANT_RATE`, the short bound: one granting epoch in this many seconds.
pub const GRANT_RATE_INTERVAL: u64 = 300;
/// `GRANT_RATE`, the long bound: this many granting epochs in one day.
pub const GRANT_RATE_DAY: u32 = 4;
/// `KEY_REQUEST_RATE`, epoch requests for one group in one day.
pub const KEY_REQUEST_RATE: u32 = 8;
/// `POLL_GROUP_MAX`.
pub const POLL_GROUP_MAX: usize = 100;
/// `MENTION_MAX`.
pub const MENTION_MAX: usize = 16;
/// `POLL_OPTION_MAX`.
pub const POLL_OPTION_MAX: usize = 12;
/// `MOD_ACTION_MAX` of §11.9.6.
pub const MOD_ACTION_MAX: usize = 20;
/// The owner floor (`GRP-051`).
pub const OWNER_MIN: usize = 2;
/// The inline carrier holds this many slots when at most nine are admin
/// slots (`GRP-280`).
pub const INLINE_SLOTS_MAX: usize = 27;

/// The slot of a unix time (`GRP-223`).
pub fn slot_of(now: u64) -> u32 {
    umbra_crypto::group::slot_of(now)
}

#[cfg(test)]
pub(crate) mod test_util {
    use umbra_crypto::{group::MemberKeys, secret::Secret};

    /// The keys of member `seed` in the tests.
    pub(crate) fn member(seed: u8) -> MemberKeys {
        MemberKeys::from_seed(&Secret::new([seed; 32]))
    }
}
