//! Randomness hardening of Part 5 §5.9 (RFC 8937).
//!
//! Each random value comes from `HMAC-SHA3-256(K_rng_harden, CSPRNG(32) ||
//! context || call || counter)`. A platform generator that fails after the
//! first launch then shows no raw output on the wire. The key sits in the
//! encrypted store, and the failure mixes with it. `call` is the value
//! that differs between two draws (RFC 8937 §4, `tag2`). Thus a platform
//! generator that repeats its output does not repeat a hardened value.

use core::convert::Infallible;

use hmac::{Hmac, KeyInit, Mac};
use rand_core::{TryCryptoRng, TryRng};
use sha3::Sha3_256;

use zeroize::Zeroize;

use crate::secret::Secret;

/// A generator that hardens an inner CSPRNG under `K_rng_harden`.
///
/// The `context` names the use, such as a KEM coin or an ephemeral key. The
/// `call` separates one draw from each other draw of the process. One draw
/// is the life of one generator, and it can fill more than one buffer.
pub struct HardenedRng<'a, R> {
    inner: &'a mut R,
    mac: Hmac<Sha3_256>,
    context: &'static [u8],
    call: [u8; CALL_LEN],
    /// `block` of `CRY-025`: the 32-byte blocks of the draw from zero. It
    /// runs across each fill and restarts at no fill, thus two fills under
    /// one `call` never take the same input.
    counter: u32,
}

/// The length of the per-call value: a call number and a time, 8 bytes each.
pub const CALL_LEN: usize = 16;

impl<'a, R: TryCryptoRng> HardenedRng<'a, R> {
    /// Wraps `inner` under `key` for one `context` and one draw. The caller
    /// gives a `call` that no other draw under `key` carries: a call number
    /// that only rises, beside a time.
    pub fn new(
        inner: &'a mut R,
        key: &Secret<32>,
        context: &'static [u8],
        call: [u8; CALL_LEN],
    ) -> Self {
        // HMAC accepts a key of any length, thus the Result never carries Err.
        let mac = match Hmac::<Sha3_256>::new_from_slice(key.expose()) {
            Ok(mac) => mac,
            Err(_) => Hmac::<Sha3_256>::new(&Default::default()),
        };
        Self {
            inner,
            mac,
            context,
            call,
            counter: 0,
        }
    }

    fn block(&mut self, out: &mut [u8]) -> Result<(), <R as TryRng>::Error> {
        let mut fresh = Secret::<32>::zeroed();
        self.inner.try_fill_bytes(fresh.expose_mut())?;

        let mut mac = self.mac.clone();
        mac.update(fresh.expose());
        mac.update(self.context);
        mac.update(&self.call);
        mac.update(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);

        let mut tag = mac.finalize().into_bytes();
        let n = out.len().min(tag.len());
        if let (Some(dst), Some(src)) = (out.get_mut(..n), tag.get(..n)) {
            dst.copy_from_slice(src);
        }

        // The tag is the random value itself, which becomes a key or a
        // nonce of the caller.
        tag.zeroize();
        Ok(())
    }
}

impl<R: TryCryptoRng> TryRng for HardenedRng<'_, R> {
    type Error = <R as TryRng>::Error;

    fn try_next_u32(&mut self) -> Result<u32, <R as TryRng>::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, <R as TryRng>::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), <R as TryRng>::Error> {
        for chunk in dst.chunks_mut(32) {
            self.block(chunk)?;
        }
        Ok(())
    }
}

impl<R: TryCryptoRng> TryCryptoRng for HardenedRng<'_, R> {}

// A hardened generator over an infallible source is itself infallible, thus
// the blanket impls of `rand_core` give it `Rng` and `CryptoRng`.
const _: fn() = || {
    fn assert_crypto<T: rand_core::CryptoRng>() {}
    fn check<R: TryCryptoRng<Error = Infallible>>() {
        assert_crypto::<HardenedRng<'_, R>>();
    }
    let _ = check::<crate::rng::Never>;
};

/// A generator that is never used; it exists for the type check above.
struct Never;

impl TryRng for Never {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Infallible> {
        Ok(())
    }
}

impl TryCryptoRng for Never {}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;
    use rand_core::Rng;

    #[test]
    fn same_inputs_give_same_output_and_context_separates() {
        let key = Secret::<32>::new([7u8; 32]);
        let mut a = TestRng::new(b"seed");
        let mut b = TestRng::new(b"seed");
        let mut c = TestRng::new(b"seed");
        let mut x = [0u8; 70];
        let mut y = [0u8; 70];
        let mut z = [0u8; 70];

        HardenedRng::new(&mut a, &key, b"ctx", [0; CALL_LEN]).fill_bytes(&mut x);
        HardenedRng::new(&mut b, &key, b"ctx", [0; CALL_LEN]).fill_bytes(&mut y);
        HardenedRng::new(&mut c, &key, b"other", [0; CALL_LEN]).fill_bytes(&mut z);

        assert_eq!(x, y);
        assert_ne!(x, z);
        assert_ne!(&x[..32], &x[32..64]);
    }

    #[test]
    fn a_platform_generator_that_repeats_does_not_repeat_a_hardened_value() {
        let key = Secret::<32>::new([7u8; 32]);
        let mut a = TestRng::new(b"seed");
        let mut b = TestRng::new(b"seed");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let mut second = [0u8; CALL_LEN];
        second[7] = 1;
        HardenedRng::new(&mut a, &key, b"ctx", [0; CALL_LEN]).fill_bytes(&mut x);
        HardenedRng::new(&mut b, &key, b"ctx", second).fill_bytes(&mut y);
        assert_ne!(x, y);
    }
}
