//! The anti-abuse system of Part 13: the two token types with their
//! issuance and verification, the proof of work with its challenge and
//! its verifier, the admission gate of a relay, the issuer keys a client
//! accepts, the relay-local spend set, and the block of a contact.
//!
//! Each type takes the time and the random values it needs as arguments.
//! The proof-of-work solve and check need the `pow` feature of
//! `umbra-crypto`, which is on by default.

pub mod admission;
pub mod block;
pub mod issuer;
pub mod pow;
pub mod spend;
pub mod token;

/// The epoch length of §13.6, in seconds.
pub const EPOCH_SECONDS: u64 = 604_800;
/// `POW_CHALLENGE_PERIOD`, in seconds.
pub const POW_CHALLENGE_PERIOD: u64 = 600;
/// `POW_EFFORT_MAX`.
pub const POW_EFFORT_MAX: u32 = 150;
/// `POW_LOOKUP_FLOOR`.
pub const POW_LOOKUP_FLOOR: u32 = 20;
/// `POW_CHUNK_FLOOR`: the lowest effort of a solution that admits a
/// `CNEW` or a `BNEW` with no token (`ABU-106`).
pub const POW_CHUNK_FLOOR: u32 = 8;
/// `POW_CHUNK_ALLOWANCE`: the `CNEW` and `BNEW` commands that one solution
/// admits at one relay (`ABU-107`), which is about 2 MiB of chunks.
pub const POW_CHUNK_ALLOWANCE: u16 = 64;
/// `HELLO_POW_EFFORT`.
pub const HELLO_POW_EFFORT: u32 = 50;
/// The admissions pending in one `POW_CHALLENGE_PERIOD` that raise the
/// effort by one (`ABU-092`).
pub const POW_BACKLOG_UNIT: u32 = 64;
/// The most tokens in one batch (§13.6).
pub const BATCH_MAX: usize = 256;

/// The epoch number of `now` (§13.6).
pub const fn epoch_number(now: u64) -> u32 {
    let epoch = now / EPOCH_SECONDS;
    if epoch > u32::MAX as u64 {
        u32::MAX
    } else {
        epoch as u32
    }
}

#[cfg(test)]
pub(crate) mod test_rng {
    /// A deterministic generator for the tests of this module.
    pub(crate) struct Rng(pub u64);

    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            Ok((self.0 >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?) << 32 | u64::from(self.try_next_u32()?))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for b in dest {
                *b = self.try_next_u32()? as u8;
            }
            Ok(())
        }
    }

    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_the_week_number() {
        assert_eq!(epoch_number(0), 0);
        assert_eq!(epoch_number(EPOCH_SECONDS - 1), 0);
        assert_eq!(epoch_number(EPOCH_SECONDS), 1);
        assert_eq!(epoch_number(u64::MAX), u32::MAX);
    }
}
