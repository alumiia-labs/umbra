//! The constants of Part 3 §3.2.4, §3.2.6, §3.2.7, §3.5, §3.7, and §3.9,
//! each under the name the specification gives it. Times are in seconds.

/// `QUEUE_QUOTA`, records a pairwise queue holds.
pub const QUEUE_QUOTA: usize = 256;
/// `INVITE_TTL`: a relay deletes an invitation blob that no party fetched
/// (Part 4 §4.8, `IDN-126`).
pub const INVITE_TTL: u64 = 14 * 86_400;
/// `INVITE_RESERVE_TTL`: a relay deletes a link identifier that got no blob.
pub const INVITE_RESERVE_TTL: u64 = 600;
/// `MSG_TTL`.
pub const MSG_TTL: u64 = 45 * 86_400;
/// `QUEUE_IDLE_TTL`.
pub const QUEUE_IDLE_TTL: u64 = 60 * 86_400;
/// `ROTATE_AFTER`, the age limit.
pub const ROTATE_AFTER_SECONDS: u64 = 90 * 86_400;
/// `ROTATE_AFTER`, the count limit.
pub const ROTATE_AFTER_MESSAGES: u32 = 10_000;
/// `ROTATE_JITTER`, in percent.
pub const ROTATE_JITTER_PERCENT: u64 = 20;
/// `ACK_HOLE_TIMEOUT`.
pub const ACK_HOLE_TIMEOUT: u64 = 24 * 3_600;
/// `MAX_QUEUES_PER_SESSION`.
pub const MAX_QUEUES_PER_SESSION: usize = 8;
/// `ROTATE_GRACE`.
pub const ROTATE_GRACE: u64 = 7 * 86_400;
/// `DEAD_CHANNEL_SILENCE`.
pub const DEAD_CHANNEL_SILENCE: u64 = 7 * 86_400;
/// `DRAIN_THRESHOLD`, records above which a peek answers unpaced.
pub const DRAIN_THRESHOLD: usize = 60;
/// `PACING_MEAN`, in milliseconds.
pub const PACING_MEAN_MS: u64 = 1_000;
/// `RECEIPT_MIN_DELAY`.
pub const RECEIPT_MIN_DELAY: u64 = 30;
/// `RECEIPT_MAX_HOLD`.
pub const RECEIPT_MAX_HOLD: u64 = 3_600;
/// `RECEIPT_BATCH_MAX`.
pub const RECEIPT_BATCH_MAX: usize = 9;
/// `SEND_MAX_ATTEMPTS`, the first send included.
pub const SEND_MAX_ATTEMPTS: u32 = 16;
/// `SEND_GIVE_UP`.
pub const SEND_GIVE_UP: u64 = 7 * 86_400;
/// `IN_FLIGHT_WINDOW` of §3.7 item 4.
pub const IN_FLIGHT_WINDOW: u32 = 1_000;
/// `GROUP_RETENTION`.
pub const GROUP_RETENTION: u64 = 30 * 86_400;
/// `GROUP_QUEUE_QUOTA`, in bytes.
pub const GROUP_QUEUE_QUOTA: usize = 32 * 1_024 * 1_024;
/// `GROUP_POST_RATE`, records in each window.
pub const GROUP_POST_RATE: usize = 60;
/// The window of `GROUP_POST_RATE`.
pub const GROUP_POST_WINDOW: u64 = 60;
/// `GROUP_READ_GRACE`.
pub const GROUP_READ_GRACE: u64 = 30 * 86_400;
/// `GROUP_WRITE_GRACE`.
pub const GROUP_WRITE_GRACE: u64 = 24 * 3_600;
/// `GROUP_IDLE_TTL`.
pub const GROUP_IDLE_TTL: u64 = 60 * 86_400;
/// `GROUP_NOTIFIER_MAX`.
pub const GROUP_NOTIFIER_MAX: usize = 4_096;
/// `GROUP_REPLICAS`.
pub const GROUP_REPLICAS: usize = 2;
