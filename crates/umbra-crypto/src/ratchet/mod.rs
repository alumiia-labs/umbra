//! The ratchet of Part 5 §5.5: the header-encrypted Double Ratchet and the
//! chunked ML-KEM braid.
//!
//! The erasure code and the codeword of §5.5.2 and the Double Ratchet of
//! §5.5.1 are here. The braid schedule of §5.5.3 follows.

pub mod codeword;
pub mod dr;
pub mod gf16;
pub mod rs;
