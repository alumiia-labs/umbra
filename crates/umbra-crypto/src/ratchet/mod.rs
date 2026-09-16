//! The ratchet of Part 5 §5.5: the header-encrypted Double Ratchet and the
//! chunked ML-KEM braid.
//!
//! [`braid::Ratchet`] joins the Double Ratchet of §5.5.1 to the braid of
//! §5.5.2 and §5.5.3; [`dr::Session`] is the Double Ratchet alone.

pub mod braid;
pub mod codeword;
pub mod dr;
pub mod gf16;
pub mod rs;
