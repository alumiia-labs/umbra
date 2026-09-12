//! A deterministic generator for tests. It is not a CSPRNG.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};

pub(crate) struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

impl TestRng {
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut s = [0u8; 32];
        let mut h = Shake256::default();
        h.update(seed);
        h.finalize_xof_into(&mut s);
        Self {
            seed: s,
            counter: 0,
        }
    }
}

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let mut h = Shake256::default();
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        h.finalize_xof_into(dst);
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}
