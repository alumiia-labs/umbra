//! The notifications of Part 8: the fixed blob and its key schedule, the
//! token blinding and the handle groups, the binding that gives a queue
//! relay what it seals with, the push scheduler of a queue relay, the
//! digest gate of a group-queue relay, the Notification Delivery
//! Relay (`ndr`), and the wake rules of the three modes at the client.
//!
//! Each type takes the time and the random values it needs as arguments.

pub mod binding;
pub mod blob;
pub mod digest;
pub mod ndr;
pub mod push;
pub mod token;
pub mod wake;

/// The epoch length of the key schedule of §8.2.3, in seconds.
pub const EPOCH_SECONDS: u64 = 86_400;
/// `MAX_QUEUES_PER_HANDLE`, which equals `MAX_QUEUES_PER_SESSION`.
pub const MAX_QUEUES_PER_HANDLE: usize = umbra_queue::params::MAX_QUEUES_PER_SESSION;
/// A notification handle.
pub const HANDLE_LEN: usize = 16;
/// The rotation period of the triple and the root (`NTF-007`), in seconds.
pub const ROTATE_INTERVAL: u64 = 7 * 86_400;
/// `NTF_FAIL_MAX`.
pub const NTF_FAIL_MAX: u32 = 3;
/// `WAKE_COALESCE_WINDOW`, in seconds.
pub const WAKE_COALESCE_WINDOW: u64 = 10;
/// `PUSH_TTL_MESSAGE`, in seconds.
pub const PUSH_TTL_MESSAGE: u64 = 86_400;
/// `PUSH_TTL_DIGEST`, in seconds.
pub const PUSH_TTL_DIGEST: u64 = 3_600;
/// `REPUSH_INTERVAL`, in seconds.
pub const REPUSH_INTERVAL: u64 = 3_600;
/// `REPUSH_MAX`.
pub const REPUSH_MAX: u32 = 3;
/// `GROUP_DIGEST_MIN_GAP`, in seconds.
pub const GROUP_DIGEST_MIN_GAP: u64 = 10;
/// The retention of a notify registration (`NTF-102`), in
/// seconds.
pub const REGISTRATION_TTL: u64 = 7 * 86_400 + crate::directory::CLOCK_SKEW;
/// The most registrations one group queue holds.
pub const REGISTRATION_MAX: usize = umbra_queue::params::GROUP_NOTIFIER_MAX;
/// The longest push-wake session (`NTF-012`), in seconds.
pub const WAKE_SESSION_MAX: u64 = 6;
/// The daily drain of a rendezvous queue in Private mode (`NTF-046`), in
/// seconds.
pub const RENDEZVOUS_DRAIN_PRIVATE: u64 = 86_400;

/// The epoch of the key schedule at `now`.
pub const fn epoch_of(now: u64) -> u32 {
    let epoch = now / EPOCH_SECONDS;
    if epoch > u32::MAX as u64 {
        u32::MAX
    } else {
        epoch as u32
    }
}

/// An `UMBRA-KEM` key pair from a 32-byte seed under `label`: the gateway
/// key of the NDR, and the notification key of a queue relay (`NTF-112`).
/// A restart then keeps the key that each party pinned or sealed to.
pub fn seeded_pair(label: &[u8], seed: &[u8; 32]) -> umbra_crypto::kem::KeyPair {
    use umbra_crypto::zeroize::Zeroizing;
    use umbra_crypto::{hash::sha3_256, secret::Secret};
    // The seeds of the key leave no copy on the stack.
    let x = Zeroizing::new(sha3_256(&[label, b"/x", seed]));
    let d = Zeroizing::new(sha3_256(&[label, b"/d", seed]));
    let z = Zeroizing::new(sha3_256(&[label, b"/z", seed]));
    let mut dz = Zeroizing::new([0u8; 64]);
    for (slot, byte) in dz.iter_mut().zip(d.iter().chain(z.iter())) {
        *slot = *byte;
    }
    umbra_crypto::kem::KeyPair::from_seeds(Secret::new(*x), Secret::new(*dz))
}
