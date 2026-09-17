//! Secret byte strings.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret of `N` bytes that zeroizes on drop.
///
/// The type has no `Debug`, no `Clone`, and no `Serialize`, and a caller
/// reads the bytes through [`Secret::expose`] only (Part 15 §15.4).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Wraps `bytes`. The caller gives up its copy.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// A secret of zero bytes, for a buffer that a KDF fills.
    pub const fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// The bytes.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// The bytes, for a KDF that writes into them.
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for Secret<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> subtle::ConstantTimeEq for Secret<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}
