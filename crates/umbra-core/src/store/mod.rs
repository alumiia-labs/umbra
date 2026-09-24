//! The local store of Part 14 §14.6.4 and §14.7.4, over the table MAC of
//! Part 4 §4.6. [`wrap`] turns the passphrase and one keyed operation of
//! the secure element into the key that wraps `K_store`. [`record`] seals
//! each record under a key of its own. [`engine`] keeps the rows and the
//! table MACs in step over the storage of the platform.
//!
//! The core holds no file and no database. A platform crate gives the
//! [`engine::Backend`] and the [`wrap::SecureElement`].

pub mod engine;
pub mod record;
pub mod wrap;
