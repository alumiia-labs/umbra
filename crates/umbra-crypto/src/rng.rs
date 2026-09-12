//! Randomness hardening of Part 5 §5.9 (RFC 8937).
//!
//! Each random value comes from `HMAC-SHA3-256(K_rng_harden, CSPRNG(32) ||
//! context || counter)`. A platform generator that fails after the first
//! launch then shows no raw output on the wire, because the key sits in the
//! encrypted store and the failure mixes with it.

use core::convert::Infallible;

use hmac::{Hmac, KeyInit, Mac};
use rand_core::{TryCryptoRng, TryRng};
use sha3::Sha3_256;

use crate::secret::Secret;

/// A generator that hardens an inner CSPRNG under `K_rng_harden`.
///
/// The `context` names the use, such as a KEM coin or an ephemeral key, and
/// a counter separates the blocks of one call.
pub struct HardenedRng<'a, R> {
    inner: &'a mut R,
    mac: Hmac<Sha3_256>,
    context: &'static [u8],
    counter: u32,
}

impl<'a, R: TryCryptoRng> HardenedRng<'a, R> {
    /// Wraps `inner` under `key` for one `context`.
    pub fn new(inner: &'a mut R, key: &Secret<32>, context: &'static [u8]) -> Self {
        // HMAC accepts a key of any length, thus the Result never carries Err.
        let mac = match Hmac::<Sha3_256>::new_from_slice(key.expose()) {
            Ok(mac) => mac,
            Err(_) => Hmac::<Sha3_256>::new(&Default::default()),
        };
        Self {
            inner,
            mac,
            context,
            counter: 0,
        }
    }

    fn block(&mut self, out: &mut [u8]) -> Result<(), <R as TryRng>::Error> {
        let mut fresh = Secret::<32>::zeroed();
        self.inner.try_fill_bytes(fresh.expose_mut())?;
        let mut mac = self.mac.clone();
        mac.update(fresh.expose());
        mac.update(self.context);
        mac.update(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        let tag = mac.finalize().into_bytes();
        let n = out.len().min(tag.len());
        if let (Some(dst), Some(src)) = (out.get_mut(..n), tag.get(..n)) {
            dst.copy_from_slice(src);
        }
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
#[doc(hidden)]
pub struct Never;

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
        HardenedRng::new(&mut a, &key, b"ctx").fill_bytes(&mut x);
        HardenedRng::new(&mut b, &key, b"ctx").fill_bytes(&mut y);
        HardenedRng::new(&mut c, &key, b"other").fill_bytes(&mut z);
        assert_eq!(x, y);
        assert_ne!(x, z);
        assert_ne!(&x[..32], &x[32..64]);
    }
}
