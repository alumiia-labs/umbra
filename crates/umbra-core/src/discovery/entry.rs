//! The directory entry of Part 9 §9.3 and the address entry of §9.3.3,
//! with the tombstone form of §9.9.2.

use alloc::vec::Vec;

use umbra_crypto::kem::PUBLIC_KEY_LEN;
use umbra_wire::{
    address::{self, QueueAddress},
    codec::{Reader, Writer},
};

use super::handle::NAME_MAX;
use crate::{identity, Error};

/// The width of `HK_pub` and of `address_pk`.
pub const ENTRY_PK_LEN: usize = PUBLIC_KEY_LEN;
/// The length of an `AddressEntry`.
pub const ADDRESS_ENTRY_LEN: usize = 20 + ENTRY_PK_LEN + address::LEN + 4;
/// The most bytes of a `DirectoryEntry`: the length byte, the canonical
/// handle at `NAME_MAX` plus `@`, `#`, and nine digits, then the fixed
/// fields.
pub const DIRECTORY_ENTRY_MAX: usize = 1 + NAME_MAX + 11 + ENTRY_PK_LEN + address::LEN + 4;

/// The published state of a handle.
pub struct DirectoryEntry {
    /// The canonical handle.
    pub handle: Vec<u8>,
    /// `HK_pub`, or zero bytes in a tombstone.
    pub hk_pub: [u8; ENTRY_PK_LEN],
    /// The rendezvous queue, or `None` in a tombstone.
    pub rendezvous: Option<QueueAddress>,
    /// The version.
    pub version: u32,
}

impl DirectoryEntry {
    /// Whether the entry is a tombstone (`DIS-073`).
    pub fn is_tombstone(&self) -> bool {
        self.hk_pub == [0; ENTRY_PK_LEN] && self.rendezvous.is_none()
    }

    /// The tombstone of `handle` at `version`.
    pub fn tombstone(handle: Vec<u8>, version: u32) -> Self {
        DirectoryEntry {
            handle,
            hk_pub: [0; ENTRY_PK_LEN],
            rendezvous: None,
            version,
        }
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        1 + self.handle.len() + ENTRY_PK_LEN + address::LEN + 4
    }

    /// Whether the handle is empty, which no entry allows. Clippy asks for
    /// this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.handle.is_empty()
    }

    /// Writes the entry: the handle with a length byte, `HK_pub`, the
    /// rendezvous address, and the version.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.handle.is_empty() || self.handle.len() > NAME_MAX + 11 {
            return Err(Error::Malformed);
        }
        if (self.hk_pub == [0; ENTRY_PK_LEN]) != self.rendezvous.is_none() {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(u8::try_from(self.handle.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.handle)?;
        w.put(&self.hk_pub)?;
        let at = match &self.rendezvous {
            Some(q) => {
                q.encode(w.tail())?;
                w.position().saturating_add(address::LEN)
            }
            None => {
                w.zeros(address::LEN)?;
                w.position()
            }
        };
        let mut w = Writer::new(out.get_mut(at..).ok_or(Error::Malformed)?);
        w.u32(self.version)?;
        Ok(at.saturating_add(w.position()))
    }

    /// Reads an entry.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let len = usize::from(r.u8()?);
        if len == 0 || len > NAME_MAX + 11 {
            return Err(Error::Malformed);
        }
        let handle = r.take(len)?.to_vec();
        let hk_pub: [u8; ENTRY_PK_LEN] = r.array()?;
        let queue = r.take(address::LEN)?;
        let rendezvous = if queue.iter().all(|&b| b == 0) {
            None
        } else {
            Some(QueueAddress::parse(queue)?)
        };
        let version = r.u32()?;
        r.finish()?;
        if (hk_pub == [0; ENTRY_PK_LEN]) != rendezvous.is_none() {
            return Err(Error::Malformed);
        }
        Ok(DirectoryEntry {
            handle,
            hk_pub,
            rendezvous,
            version,
        })
    }
}

/// The published state of a Public Address.
pub struct AddressEntry {
    /// `SHA3-256(PublicAddressKey_j.pk)[0..20]`.
    pub address: [u8; 20],
    /// The public half of `PublicAddressKey_j`, or zero bytes in a
    /// tombstone.
    pub address_pk: [u8; ENTRY_PK_LEN],
    /// The rendezvous queue, or `None` in a tombstone.
    pub rendezvous: Option<QueueAddress>,
    /// The version.
    pub version: u32,
}

impl AddressEntry {
    /// Whether the entry is a tombstone.
    pub fn is_tombstone(&self) -> bool {
        self.address_pk == [0; ENTRY_PK_LEN] && self.rendezvous.is_none()
    }

    /// Checks `address` against `address_pk` (`DIS-105`, `DIS-128`). A
    /// tombstone carries no key and passes.
    pub fn check(&self) -> Result<(), Error> {
        if self.is_tombstone() {
            return Ok(());
        }
        identity::address::check(&self.address, &self.address_pk)
    }

    /// Writes the entry.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if (self.address_pk == [0; ENTRY_PK_LEN]) != self.rendezvous.is_none() {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.put(&self.address)?;
        w.put(&self.address_pk)?;
        let at = match &self.rendezvous {
            Some(q) => {
                q.encode(w.tail())?;
                w.position().saturating_add(address::LEN)
            }
            None => {
                w.zeros(address::LEN)?;
                w.position()
            }
        };
        let mut w = Writer::new(out.get_mut(at..).ok_or(Error::Malformed)?);
        w.u32(self.version)?;
        Ok(at.saturating_add(w.position()))
    }

    /// Reads an entry.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ADDRESS_ENTRY_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        let address = r.array()?;
        let address_pk: [u8; ENTRY_PK_LEN] = r.array()?;
        let queue = r.take(address::LEN)?;
        let rendezvous = if queue.iter().all(|&b| b == 0) {
            None
        } else {
            Some(QueueAddress::parse(queue)?)
        };
        let version = r.u32()?;
        r.finish()?;
        if (address_pk == [0; ENTRY_PK_LEN]) != rendezvous.is_none() {
            return Err(Error::Malformed);
        }
        Ok(AddressEntry {
            address,
            address_pk,
            rendezvous,
            version,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use umbra_crypto::secret::Secret;

    pub(crate) fn queue(seed: u8) -> QueueAddress {
        QueueAddress {
            relay_id: [seed; 32],
            sender_id: [seed.wrapping_add(1); 32],
            qs_auth_sk: Secret::new([seed.wrapping_add(2); 32]),
            qe: Secret::new([seed.wrapping_add(3); 32]),
        }
    }

    #[test]
    fn a_directory_entry_and_its_tombstone_round_trip() {
        let entry = DirectoryEntry {
            handle: b"@alice#1234".to_vec(),
            hk_pub: [7; ENTRY_PK_LEN],
            rendezvous: Some(queue(1)),
            version: 3,
        };
        let mut out = [0u8; DIRECTORY_ENTRY_MAX];
        let n = entry.encode(&mut out).unwrap();
        assert_eq!(n, 1 + 11 + ENTRY_PK_LEN + address::LEN + 4);
        let back = DirectoryEntry::parse(&out[..n]).unwrap();
        assert_eq!(back.handle, entry.handle);
        assert_eq!(back.version, 3);
        assert!(!back.is_tombstone());
        assert!(DirectoryEntry::parse(&out[..n - 1]).is_err());
        let tomb = DirectoryEntry::tombstone(b"@alice#1234".to_vec(), 4);
        let n = tomb.encode(&mut out).unwrap();
        let back = DirectoryEntry::parse(&out[..n]).unwrap();
        assert!(back.is_tombstone());
        // A zero key with a live queue is neither form.
        let mixed = DirectoryEntry {
            handle: b"@a#12".to_vec(),
            hk_pub: [0; ENTRY_PK_LEN],
            rendezvous: Some(queue(2)),
            version: 1,
        };
        assert!(mixed.encode(&mut out).is_err());
    }

    #[test]
    fn an_address_entry_is_fixed_width_and_checks_its_hash() {
        let pk = [9u8; ENTRY_PK_LEN];
        let entry = AddressEntry {
            address: identity::address::address_of(&pk),
            address_pk: pk,
            rendezvous: Some(queue(5)),
            version: 0,
        };
        let mut out = [0u8; ADDRESS_ENTRY_LEN + 1];
        assert_eq!(entry.encode(&mut out).unwrap(), ADDRESS_ENTRY_LEN);
        assert_eq!(ADDRESS_ENTRY_LEN, 1_369);
        let back = AddressEntry::parse(&out[..ADDRESS_ENTRY_LEN]).unwrap();
        back.check().unwrap();
        assert!(AddressEntry::parse(&out).is_err());
        let wrong = AddressEntry {
            address: [1; 20],
            ..back
        };
        assert_eq!(wrong.check(), Err(Error::Unverified));
    }
}
