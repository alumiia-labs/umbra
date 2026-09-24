//! Public communities (Part 12): the community identity, the pseudonyms,
//! the records and their chains, the control chain with its authority
//! rules, the pull protocol, the relay cache, the cross-relay checks of a
//! reader, the metadata and the link, the report path, and the social
//! records.
//!
//! The content of a community is public (§12.1). The code here protects
//! which party publishes and which party subscribes, thus no type holds a
//! subscriber list and no request holds a client identifier.

use umbra_crypto::{hash::sha3_256, hkdf::Hkdf, labels, secret::Secret, sha3::Sha3_256};

use crate::Error;

pub mod authority;
pub mod chain;
pub mod control;
pub mod exchange;
pub mod identity;
pub mod link;
pub mod meta;
pub mod pull;
pub mod reader;
pub mod record;
pub mod relay;
pub mod report;
pub mod social;
pub mod view;

/// The version byte of each community object.
pub const VERSION: u8 = 0x01;
/// The admission byte of an open community (§12.2.2).
pub const ADMISSION_OPEN: u8 = 0x01;
/// The sentinel of an index field that names no index.
pub const NO_INDEX: u32 = 0xFFFF_FFFF;

/// `COMMUNITY_MIN_RELAYS`.
pub const COMMUNITY_MIN_RELAYS: usize = 3;
/// `COMMUNITY_RELAY_MAX`.
pub const COMMUNITY_RELAY_MAX: usize = 8;
/// The lower bound of `PULL_INTERVAL`, in seconds.
pub const PULL_INTERVAL_MIN: u64 = 30;
/// The upper bound of `PULL_INTERVAL`, in seconds.
pub const PULL_INTERVAL_MAX: u64 = 180;
/// `PULL_BATCH`.
pub const PULL_BATCH: u8 = 30;
/// `POST_RATE_LIMIT`, for each pseudonym in one `POST_RATE_WINDOW`.
pub const POST_RATE_LIMIT: u32 = 20;
/// `REACT_RATE_LIMIT`.
pub const REACT_RATE_LIMIT: u32 = 120;
/// `REPOST_RATE_LIMIT`.
pub const REPOST_RATE_LIMIT: u32 = 20;
/// `POST_RATE_WINDOW`, in seconds.
pub const POST_RATE_WINDOW: u64 = 3_600;
/// `ROSTER_ENTRY_MAX`.
pub const ROSTER_ENTRY_MAX: usize = 19;
/// `MODERATOR_MAX`.
pub const MODERATOR_MAX: usize = 800;
/// `MOD_ACTION_MAX`.
pub const MOD_ACTION_MAX: usize = 20;
/// The window of `MOD_EPOCH_RATE`, `MOD_EPOCH_COMMUNITY_RATE`, and
/// `ROSTER_RATE`, in seconds.
pub const CONTROL_RATE_WINDOW: u64 = 60;
/// `MOD_EPOCH_COMMUNITY_RATE`.
pub const MOD_EPOCH_COMMUNITY_RATE: usize = 12;
/// `MOD_CHAIN_FETCH_MAX`.
pub const MOD_CHAIN_FETCH_MAX: usize = 64;
/// `MUTE_LIST_MAX`.
pub const MUTE_LIST_MAX: usize = 1_000;
/// `REPORT_NOTE_MAX`.
pub const REPORT_NOTE_MAX: usize = 200;
/// `REPORT_POLL_MAX`, in seconds.
pub const REPORT_POLL_MAX: u64 = 86_400;
/// `REPORT_HOLD`, in seconds.
pub const REPORT_HOLD: u64 = 86_400;
/// `MAX_POST_SIZE`.
pub const MAX_POST_SIZE: usize = 7_967;
/// `SIG_INTERVAL`.
pub const SIG_INTERVAL: u32 = 5;
/// `SIG_MAX_AGE`, in seconds.
pub const SIG_MAX_AGE: u64 = 3_600;
/// `SIG_MIN_INTERVAL`, in seconds.
pub const SIG_MIN_INTERVAL: u64 = 60;
/// `PENDING_DEMOTE`, in seconds.
pub const PENDING_DEMOTE: u64 = 5_400;
/// `PENDING_EXPIRE`, in seconds.
pub const PENDING_EXPIRE: u64 = 86_400;
/// `WITHDRAW_MAX`.
pub const WITHDRAW_MAX: usize = 8;
/// `COMMUNITY_RETENTION`, in seconds.
pub const COMMUNITY_RETENTION: u64 = 90 * 86_400;
/// `META_NAME_MAX`.
pub const META_NAME_MAX: usize = 64;
/// `META_TEXT_MAX`.
pub const META_TEXT_MAX: usize = 512;
/// `META_RULES_MAX`.
pub const META_RULES_MAX: usize = 1_536;
/// The time a checkpoint or a body can be absent from one relay before a
/// reader reports a divergence (§12.4.3.1 rule 4).
pub const SETTLE_WINDOW: u64 = SIG_MAX_AGE + PULL_INTERVAL_MAX;

// COM-051 and COM-052 bind the parameter set, thus a change that breaks
// either one does not compile.
const _: () = assert!(SIG_MAX_AGE >= SIG_INTERVAL as u64 * 3_600 / POST_RATE_LIMIT as u64);
const _: () = assert!(PENDING_DEMOTE > SIG_MAX_AGE + PULL_INTERVAL_MAX);

/// The type byte of a community record (§12.4.4). The namespace has its
/// own type, and no conversion to another namespace exists (`COM-080`,
/// `COM-081`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecordType {
    /// A `CommunityPost`.
    Post = 0x01,
    /// A `PostStub`.
    Stub = 0x02,
    /// A `ModerationEpoch`.
    ModerationEpoch = 0x03,
    /// A `CommunityRoster`.
    Roster = 0x04,
    /// A `Checkpoint`.
    Checkpoint = 0x05,
    /// A `CommunityMeta`.
    Meta = 0x06,
    /// A `CommunityReport`.
    Report = 0x07,
    /// A `ModeratorSet`.
    ModeratorSet = 0x08,
    /// An `OperatorRemoval`.
    OperatorRemoval = 0x09,
}

impl RecordType {
    /// Reads the type byte.
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => RecordType::Post,
            0x02 => RecordType::Stub,
            0x03 => RecordType::ModerationEpoch,
            0x04 => RecordType::Roster,
            0x05 => RecordType::Checkpoint,
            0x06 => RecordType::Meta,
            0x07 => RecordType::Report,
            0x08 => RecordType::ModeratorSet,
            0x09 => RecordType::OperatorRemoval,
            _ => return Err(Error::Malformed),
        })
    }

    /// The type of an encoded record, from its first two bytes.
    pub fn of(record: &[u8]) -> Result<Self, Error> {
        match record {
            [VERSION, type_byte, ..] => Self::from_byte(*type_byte),
            _ => Err(Error::Malformed),
        }
    }
}

/// `community_id` of §12.2, from the admission byte and the ML-DSA-65
/// public key of the genesis owner. An admission byte that this
/// specification does not define is rejected (`COM-169`, `COM-170`).
pub fn community_id(admission: u8, genesis_public_key: &[u8]) -> Result<[u8; 32], Error> {
    if admission != ADMISSION_OPEN {
        return Err(Error::Malformed);
    }
    Ok(sha3_256(&[
        labels::COMMUNITY_ID,
        &[admission],
        genesis_public_key,
    ]))
}

/// `pseudonym = SHA3-256(pk)`, for an authoring key and for a role key
/// (§12.3.2).
pub fn pseudonym_of(public_key: &[u8]) -> [u8; 32] {
    sha3_256(&[public_key])
}

/// `pull_sk` of §12.3.3, which keys the authenticator of each community
/// command in the place of a queue secret (`COM-175`).
pub fn pull_secret(community_id: &[u8; 32]) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(Some(labels::COMMUNITY_PULL), community_id);
    let mut out = Secret::<32>::zeroed();
    // 32 bytes is below the HKDF bound, thus expand cannot fail.
    let _ = kdf.expand(&[], out.expose_mut());
    out
}

/// A `PULL_INTERVAL` from one uniform 32-bit value. A client draws one for
/// each community and each relay (`COM-174`).
pub fn pull_interval(random: u32) -> u64 {
    let span = PULL_INTERVAL_MAX - PULL_INTERVAL_MIN + 1;
    PULL_INTERVAL_MIN + u64::from(random) % span
}

#[cfg(test)]
pub(crate) mod test_util {
    use umbra_crypto::secret::Secret;

    use super::identity::{AuthorIdentity, RoleIdentity};

    /// An authoring identity from a one-byte seed.
    pub fn author(seed: u8) -> AuthorIdentity {
        AuthorIdentity::from_seed(&Secret::new([seed; 32]))
    }

    /// A role identity from a one-byte seed.
    pub fn role(seed: u8) -> RoleIdentity {
        RoleIdentity::from_seed(&Secret::new([seed; 32]))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_binds_the_admission_byte_and_rejects_the_reserved_one() {
        let a = community_id(ADMISSION_OPEN, &[7; 1952]).unwrap();
        let b = community_id(ADMISSION_OPEN, &[8; 1952]).unwrap();
        assert_ne!(a, b);
        assert!(community_id(0x02, &[7; 1952]).is_err());
        assert!(community_id(0x00, &[7; 1952]).is_err());

        assert!(RecordType::of(&[VERSION, 0x05, 0]).unwrap() == RecordType::Checkpoint);
        assert!(RecordType::of(&[VERSION, 0x0A]).is_err());
        assert!(RecordType::of(&[0x02, 0x01]).is_err());

        for random in [0u32, 1, 150, 151, u32::MAX] {
            let interval = pull_interval(random);
            assert!((PULL_INTERVAL_MIN..=PULL_INTERVAL_MAX).contains(&interval));
        }
        assert_ne!(
            pull_secret(&a).expose(),
            pull_secret(&b).expose(),
            "one pull key for each community"
        );
    }
}
