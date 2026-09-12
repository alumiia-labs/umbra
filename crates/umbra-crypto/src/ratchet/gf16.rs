//! Arithmetic in GF(2¹⁶) for the erasure code of Part 5 §5.5.2.
//!
//! The field is GF(2)[x] modulo `x¹⁶ + x¹² + x³ + x + 1` (`0x1100B`, rule
//! `CRY-067`), and the generator element is `0x0002` (`CRY-068`). A symbol
//! is two bytes in big-endian order (`CRY-069`). Multiplication is a
//! carry-less product reduced bit by bit, with no table, thus the code
//! carries no lookup that a cache attack reads. The code protects no
//! secret, and the choice is for size and for portability.

/// The reduction polynomial without its leading term.
const POLY: u32 = 0x1100B;

/// The generator element.
pub const GENERATOR: u16 = 0x0002;

/// `a + b`, which is `a ^ b` in characteristic 2.
#[inline]
pub const fn add(a: u16, b: u16) -> u16 {
    a ^ b
}

/// `a · b`.
pub const fn mul(a: u16, b: u16) -> u16 {
    let mut acc: u32 = 0;
    let mut a = a as u32;
    let mut b = b;
    let mut i = 0;
    while i < 16 {
        // Add a when the low bit of b is set, then shift a up and reduce.
        let take = 0u32.wrapping_sub((b & 1) as u32);
        acc ^= a & take;
        b >>= 1;
        a <<= 1;
        let overflow = 0u32.wrapping_sub((a >> 16) & 1);
        a ^= POLY & overflow;
        i += 1;
    }
    acc as u16
}

/// `a^e`.
pub const fn pow(a: u16, mut e: u32) -> u16 {
    let mut base = a;
    let mut out: u16 = 1;
    while e > 0 {
        if e & 1 == 1 {
            out = mul(out, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    out
}

/// `a⁻¹`, which is `a^(2¹⁶ − 2)`. Zero has no inverse and gives zero.
pub const fn inv(a: u16) -> u16 {
    pow(a, 65534)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn field_laws_hold() {
        let xs = [1u16, 2, 3, 0x1234, 0xffff, 0x8000, 0x0101];
        for &a in &xs {
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(a, inv(a)), 1, "inverse of {a:#x}");
            for &b in &xs {
                assert_eq!(mul(a, b), mul(b, a));
                for &c in &xs {
                    assert_eq!(mul(a, mul(b, c)), mul(mul(a, b), c));
                    assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
                }
            }
        }
    }

    #[test]
    fn the_generator_has_full_order() {
        // 2^(2^16 - 1) = 1 and no smaller divisor exponent gives 1; the
        // divisors of 65535 are 3, 5, 17, and 257.
        assert_eq!(pow(GENERATOR, 65535), 1);
        for d in [65535 / 3, 65535 / 5, 65535 / 17, 65535 / 257] {
            assert_ne!(pow(GENERATOR, d), 1);
        }
    }

    #[test]
    fn known_products() {
        // x^15 * x = x^16 = x^12 + x^3 + x + 1
        assert_eq!(mul(0x8000, 0x0002), 0x100B);
        assert_eq!(mul(0x8000, 0x8000), pow(2, 30));
    }
}
