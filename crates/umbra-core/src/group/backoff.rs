//! The rotation backoff of Part 11 §11.4.1: an exponential delay whose
//! mean follows the role, so that one member answers a trigger and the
//! others stand down.

use umbra_wire::group::control::Role;

use super::{ROTATE_BACKOFF_MEMBER, ROTATE_BACKOFF_ROLE};

/// The mean of the backoff for `role` (`GRP-358`).
pub const fn mean_for(role: Role) -> u64 {
    match role {
        Role::Moderator | Role::Admin | Role::Owner => ROTATE_BACKOFF_ROLE,
        Role::Observer | Role::Member => ROTATE_BACKOFF_MEMBER,
    }
}

/// `ln(2^32 / (random + 1))` in 1/1024 units, from the bit length and a
/// sixteen-entry table of the fraction, which is close enough for a
/// backoff.
fn ln_inverse_1024(random: u32) -> u64 {
    // ln(2) × 1024, and log2(1 + k/16) × 1024 for k in 0..16.
    const LN2: u64 = 710;
    const FRACTION: [u64; 16] = [
        0, 90, 174, 254, 330, 402, 470, 536, 599, 659, 717, 773, 827, 879, 929, 977,
    ];

    let value = u64::from(random).saturating_add(1);
    let bits = 64 - value.leading_zeros();
    let top = bits.saturating_sub(1);
    let mantissa = if top >= 4 {
        (value >> (top - 4)) & 0x0F
    } else {
        (value << (4 - top)) & 0x0F
    };

    let log2_value = u64::from(top).saturating_mul(1024)
        + FRACTION
            .get(usize::try_from(mantissa).unwrap_or(0))
            .copied()
            .unwrap_or(0);
    let log2_max = 32u64 * 1024;
    log2_max.saturating_sub(log2_value).saturating_mul(LN2) / 1024
}

/// A delay from an exponential distribution with mean `mean`, from one
/// uniform draw.
pub fn exponential(mean: u64, random: u32) -> u64 {
    mean.saturating_mul(ln_inverse_1024(random)) / 1024
}

/// The backoff of a member at `role` that reads a trigger it did not cause.
pub fn rotation_delay(role: Role, random: u32) -> u64 {
    exponential(mean_for(role), random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_delay_is_exponential_in_shape_and_follows_the_role() {
        assert_eq!(exponential(60, u32::MAX), 0);
        assert!(exponential(60, 0) > 60 * 20);

        // The median of an exponential is mean × ln 2.
        let median = exponential(60, u32::MAX / 2);
        assert!((40..=44).contains(&median), "median {median}");
        let quarter = exponential(60, u32::MAX / 4 * 3);
        assert!((16..=19).contains(&quarter), "quarter {quarter}");

        assert!(
            rotation_delay(Role::Admin, u32::MAX / 2) < rotation_delay(Role::Member, u32::MAX / 2)
        );
        assert_eq!(mean_for(Role::Moderator), ROTATE_BACKOFF_ROLE);
        assert_eq!(mean_for(Role::Observer), ROTATE_BACKOFF_MEMBER);
    }
}
