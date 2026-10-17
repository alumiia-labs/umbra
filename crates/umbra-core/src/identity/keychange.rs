//! The key-change notice on the receiving side of Part 4 §4.5.1, and the
//! sweep delay that spreads one notice over each contact (`IDN-063`).

use super::SWEEP_SPREAD;

/// A notice that waits for the user's answer to the blocking prompt
/// (`IDN-061`, `IDN-062`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingNotice {
    /// The new X25519 public key.
    pub new_x25519_pk: [u8; 32],
    /// The new ML-KEM-768 encapsulation key.
    pub new_mlkem_pk: alloc::vec::Vec<u8>,
    /// Whether the user verified the contact out of band before this
    /// answer, which the prompt offers (`IDN-090`).
    pub verified_out_of_band: bool,
}

/// The user's answer to one prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Apply the new keys and end the post-compromise healing.
    Accept,
    /// Keep the old keys and the blocked conversation.
    Refuse,
}

impl PendingNotice {
    /// Applies the user's answer and returns the keys to bind into the next
    /// handshake (`IDN-060`), or `None` on a refusal. One call answers one
    /// contact (`IDN-092`).
    pub fn answer(self, answer: Answer) -> Option<([u8; 32], alloc::vec::Vec<u8>)> {
        match answer {
            Answer::Accept => Some((self.new_x25519_pk, self.new_mlkem_pk)),
            Answer::Refuse => None,
        }
    }
}

/// One sample of an exponential distribution with mean `SWEEP_SPREAD`,
/// from 64 random bits, in seconds. The client draws one for each contact
/// (`IDN-064`).
pub fn sweep_delay(random: u64) -> u64 {
    exponential(random, SWEEP_SPREAD)
}

/// One sample of an exponential distribution with mean `mean`, from 64
/// random bits, in the unit of `mean`. A fixed-point inverse transform,
/// thus two implementations draw the same delay from the same bits.
pub fn exponential(random: u64, mean: u64) -> u64 {
    // u in (0, 1] as a 53-bit fraction; −ln(u) by a table-free series on
    // the mantissa and the exponent.
    let bits = (random >> 11).max(1);
    let u = bits as f64 / (1u64 << 53) as f64;
    let x = -ln(u);
    (x * mean as f64) as u64
}

fn ln(mut x: f64) -> f64 {
    // ln(x) = k·ln2 + ln(m) with m in [1, 2), by the atanh series.
    let mut k = 0i32;
    while x >= 2.0 {
        x /= 2.0;
        k += 1;
    }
    while x < 1.0 {
        x *= 2.0;
        k -= 1;
    }

    let y = (x - 1.0) / (x + 1.0);
    let y2 = y * y;
    let mut term = y;
    let mut sum = 0.0;
    for i in 0..30u32 {
        sum += term / f64::from(2 * i + 1);
        term *= y2;
    }

    f64::from(k) * core::f64::consts::LN_2 + 2.0 * sum
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn the_delay_is_exponential_with_the_stated_mean() {
        let mut total = 0u64;
        let n = 4_000u64;
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            total += sweep_delay(x);
        }
        let mean = total / n;
        assert!(mean > SWEEP_SPREAD * 85 / 100 && mean < SWEEP_SPREAD * 115 / 100);

        assert_eq!(exponential(u64::MAX, 100), 0);
        assert!(exponential(0, 100) > 3_000);
        assert!((ln(core::f64::consts::E) - 1.0).abs() < 1e-9);

        let notice = PendingNotice {
            new_x25519_pk: [1; 32],
            new_mlkem_pk: alloc::vec![2; 1_184],
            verified_out_of_band: false,
        };
        assert!(notice.clone().answer(Answer::Refuse).is_none());
        assert_eq!(notice.answer(Answer::Accept).unwrap().0, [1; 32]);
    }
}
