//! The handle keys that this device holds (Part 9 §9.9.2): for each handle
//! that a hello of this device went to, the version of the entry and its
//! `HK_pub` (`DIS-078`). A later hello to that handle compares the key that
//! the log gives with the held one, and a takeover shows.

use umbra_core::{
    discovery::lifecycle::Version,
    store::{engine::Backend, record::TableId, wrap::SecureElement},
};
use umbra_crypto::rand_core::CryptoRng;

use super::Client;
use crate::Error;

/// Each held key, under the canonical label input of its handle: the
/// version, then `HK_pub`.
pub(super) const HELD_HANDLES: TableId = TableId(0x32);

impl<B: Backend, E: SecureElement> Client<B, E> {
    /// The version and the key that this device holds for a handle.
    pub fn held_handle_key(&self, label: &[u8]) -> Result<Option<Version>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(HELD_HANDLES, label);
        let Some(value) = store.get(HELD_HANDLES, &row)? else {
            return Ok(None);
        };
        let (version, hk_pub) = value.split_at_checked(4).ok_or(Error::Integrity)?;
        Ok(Some(Version {
            version: u32::from_be_bytes(version.try_into().map_err(|_| Error::Integrity)?),
            hk_pub: hk_pub.try_into().map_err(|_| Error::Integrity)?,
        }))
    }

    /// Holds the version and the key of a handle that a hello goes to.
    pub fn hold_handle_key<R: CryptoRng + ?Sized>(
        &mut self,
        label: &[u8],
        held: &Version,
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let row = open.store.row_id(HELD_HANDLES, label);
        let value = [&held.version.to_be_bytes()[..], &held.hk_pub[..]].concat();
        let mut batch = open.store.begin();
        batch.put(HELD_HANDLES, row, None, &value, rng)?;
        Ok(batch.commit()?)
    }
}
