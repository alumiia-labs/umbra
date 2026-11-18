//! The clock of the system, as Unix time.

use std::time::{SystemTime, UNIX_EPOCH};

/// The Unix time in milliseconds. A clock before 1970 gives 0.
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The Unix time in seconds. A clock before 1970 gives 0.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
