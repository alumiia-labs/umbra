//! The ratchet of Part 5 §5.5: the header-encrypted Double Ratchet and the
//! chunked ML-KEM braid.
//!
//! This module lands in three parts. The first is the erasure code and the
//! codeword of §5.5.2, which are here. The Double Ratchet of §5.5.1 and the
//! braid schedule of §5.5.3 follow.

pub mod codeword;
pub mod gf16;
pub mod rs;
