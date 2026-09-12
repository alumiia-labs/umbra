//! Cryptographic core of the UMBRA protocol.
//!
//! This crate holds the six primitives of Part 5 §5.1, the `UMBRA-KEM`
//! combiner of §5.3, and the key hierarchy of §5.2. It has no dependency
//! inside the workspace.
#![forbid(unsafe_code)]
#![no_std]
