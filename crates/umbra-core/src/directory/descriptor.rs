//! The relay descriptor and the relay entry of Part 10 §10.5.3.
//!
//! The relay signs the descriptor. The directory authority wraps it in an
//! entry with the three fields it verified, and the signed root covers the
//! entry.

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use crate::Error;

/// The descriptor width.
pub const DESCRIPTOR_LEN: usize = 5_464;
/// The entry width.
pub const ENTRY_LEN: usize = 5_498;
/// The bytes of the descriptor before `sig`, which the signature covers.
pub const SIGNED_LEN: usize = DESCRIPTOR_LEN - SIGNATURE_LEN;
/// The host field width.
pub const HOST_LEN: usize = 64;

/// The roles bits.
pub mod roles {
    /// Serves queues, pairwise and group.
    pub const QUEUE: u8 = 0x01;
    /// Serves as a chain relay.
    pub const CHAIN: u8 = 0x02;
    /// Offers the ingress role.
    pub const INGRESS_OFFERED: u8 = 0x04;
    /// Serves attachments.
    pub const ATTACHMENT: u8 = 0x08;
}

/// A relay descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDescriptor<'a> {
    /// `SHA3-256(identity_pk)`.
    pub relay_id: [u8; 32],
    /// The ML-DSA-65 key that signs the descriptor.
    pub identity_pk: &'a [u8],
    /// The X25519 static of the hop handshake.
    pub ntor_pk: [u8; 32],
    /// The IPv4 address, or zero.
    pub addr_v4: [u8; 4],
    /// The IPv6 address, or zero.
    pub addr_v6: [u8; 16],
    /// The port.
    pub port: u16,
    /// The co-tenant host name, ASCII, zero-padded.
    pub host: [u8; HOST_LEN],
    /// The autonomous system.
    pub asn: u32,
    /// ISO 3166-1 alpha-2.
    pub jurisdiction: [u8; 2],
    /// SHA3-256 of the family certificate.
    pub family_id: [u8; 32],
    /// The declared class, 0 to 3.
    pub capacity_class: u8,
    /// The role bits.
    pub roles: u8,
    /// The declared chunk store, in GiB.
    pub chunk_store_gib: u32,
    /// The first consensus epoch of this descriptor.
    pub valid_after: u64,
    /// The signature.
    pub sig: &'a [u8],
}

fn host_ok(host: &[u8; HOST_LEN]) -> bool {
    let name_len = host.iter().position(|b| *b == 0).unwrap_or(HOST_LEN);
    if name_len == 0 {
        return false;
    }

    let (name, pad) = host.split_at(name_len);
    pad.iter().all(|b| *b == 0)
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
}

impl<'a> RelayDescriptor<'a> {
    /// The host name as text.
    pub fn host_str(&self) -> &str {
        let len = self.host.iter().position(|b| *b == 0).unwrap_or(HOST_LEN);
        core::str::from_utf8(self.host.get(..len).unwrap_or(&[])).unwrap_or("")
    }

    /// Writes the descriptor.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.identity_pk.len() != VERIFYING_KEY_LEN || self.sig.len() != SIGNATURE_LEN {
            return Err(Error::Malformed);
        }

        let mut w = Writer::new(out);
        self.put_signed(&mut w)?;
        w.put(self.sig)?;
        Ok(w.position())
    }

    fn put_signed(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(0x01)?;
        w.put(&self.relay_id)?;
        w.put(self.identity_pk)?;
        w.put(&self.ntor_pk)?;
        w.put(&self.addr_v4)?;
        w.put(&self.addr_v6)?;
        w.u16(self.port)?;
        w.put(&self.host)?;
        w.u32(self.asn)?;
        w.put(&self.jurisdiction)?;
        w.put(&self.family_id)?;
        w.u8(self.capacity_class)?;
        w.u8(self.roles)?;
        w.u32(self.chunk_store_gib)?;
        w.put(&self.valid_after.to_be_bytes())?;
        Ok(())
    }

    /// Reads a descriptor, checks `relay_id` against `identity_pk`
    /// (`REL-050`), the host (`REL-144`), and the signature (`REL-051`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != DESCRIPTOR_LEN {
            return Err(Error::Malformed);
        }

        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let out = RelayDescriptor {
            relay_id: r.array()?,
            identity_pk: r.take(VERIFYING_KEY_LEN)?,
            ntor_pk: r.array()?,
            addr_v4: r.array()?,
            addr_v6: r.array()?,
            port: r.u16()?,
            host: r.array()?,
            asn: r.u32()?,
            jurisdiction: r.array()?,
            family_id: r.array()?,
            capacity_class: r.u8()?,
            roles: r.u8()?,
            chunk_store_gib: r.u32()?,
            valid_after: u64::from_be_bytes(r.array()?),
            sig: r.take(SIGNATURE_LEN)?,
        };
        r.finish()?;

        if out.relay_id != sha3_256(&[out.identity_pk])
            || !host_ok(&out.host)
            || out.capacity_class > 3
        {
            return Err(Error::Malformed);
        }
        // REL-092: the code is two capital letters. The bloc of a code is a
        // match of its bytes, thus `us` beside `US` would be a second bloc
        // of one country. Two such relays would pass invariant 2.
        if !out.jurisdiction.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Malformed);
        }

        let key = VerifyingKey::from_bytes(out.identity_pk)?;
        let sig = Signature::from_bytes(out.sig)?;
        let mut preimage =
            alloc::vec::Vec::with_capacity(labels::RELAY_DESCRIPTOR.len() + SIGNED_LEN);
        preimage.extend_from_slice(labels::RELAY_DESCRIPTOR);
        preimage.extend_from_slice(bytes.get(..SIGNED_LEN).ok_or(Error::Malformed)?);
        key.verify(&preimage, &sig)?;
        Ok(out)
    }

    /// Signs the descriptor under the identity key of the relay, and gives
    /// its bytes. It sets `identity_pk` and `relay_id` from `key`, and it
    /// reads neither those two fields nor `sig` of `self`.
    pub fn sign<R: umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &self,
        key: &umbra_crypto::sign::SigningKey,
        rng: &mut R,
    ) -> Result<alloc::vec::Vec<u8>, Error> {
        let identity_pk = key.verifying_key().to_bytes();
        let unsigned = RelayDescriptor {
            relay_id: sha3_256(&[&identity_pk]),
            identity_pk: &identity_pk,
            sig: &[0; SIGNATURE_LEN],
            ..self.clone()
        };
        let sig = key.sign(&unsigned.preimage()?, rng)?.to_bytes();
        let signed = RelayDescriptor {
            sig: &sig,
            ..unsigned
        };

        let mut out = alloc::vec![0u8; DESCRIPTOR_LEN];
        signed.encode(&mut out)?;
        // A descriptor that this relay could not read back helps no party.
        RelayDescriptor::parse(&out)?;
        Ok(out)
    }

    /// The preimage a relay signs (`REL-048`).
    pub fn preimage(&self) -> Result<alloc::vec::Vec<u8>, Error> {
        let mut body = [0u8; SIGNED_LEN];
        let mut w = Writer::new(&mut body);
        self.put_signed(&mut w)?;

        let mut out = alloc::vec::Vec::with_capacity(labels::RELAY_DESCRIPTOR.len() + SIGNED_LEN);
        out.extend_from_slice(labels::RELAY_DESCRIPTOR);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// A relay entry: the descriptor and the three fields the authority set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEntry<'a> {
    /// The descriptor.
    pub descriptor: RelayDescriptor<'a>,
    /// One opaque value for each beneficial control.
    pub operator_id: [u8; 32],
    /// The verified class, 0 to 3.
    pub class: u8,
    /// Bit 0: ingress eligible. Bit 1: layer 3.
    pub flags: u8,
}

/// The flag bits of an entry.
pub mod flags {
    /// The relay may serve at hop 1.
    pub const INGRESS: u8 = 0x01;
    /// The admission put the relay in layer 3 (`REL-060`).
    pub const LAYER_3: u8 = 0x02;
    /// The root lists the relay and places it in no layer yet (`REL-156`).
    /// The next root carries its layer, computed under this one.
    pub const PENDING: u8 = 0x04;
}

impl<'a> RelayEntry<'a> {
    /// Whether the entry may serve at hop 1 (`REL-133`).
    pub fn ingress(&self) -> bool {
        self.flags & flags::INGRESS != 0
    }

    /// Whether the root that carries the entry places the relay in no
    /// layer yet. A client selects such a relay for no hop (`REL-158`).
    pub fn pending(&self) -> bool {
        self.flags & flags::PENDING != 0
    }

    /// The layer of the relay, from 1 to 3 (`REL-061`).
    pub fn layer(&self) -> u8 {
        if self.ingress() {
            1
        } else if self.flags & flags::LAYER_3 != 0 {
            3
        } else {
            2
        }
    }

    /// Writes the entry.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.descriptor.encode(out)?;
        let mut w = Writer::new(out.get_mut(n..).ok_or(Error::Malformed)?);
        w.put(&self.operator_id)?;
        w.u8(self.class)?;
        w.u8(self.flags)?;
        Ok(n.saturating_add(w.position()))
    }

    /// Reads and verifies an entry.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != ENTRY_LEN {
            return Err(Error::Malformed);
        }

        let (desc, rest) = bytes.split_at(DESCRIPTOR_LEN);
        let descriptor = RelayDescriptor::parse(desc)?;
        let mut r = Reader::new(rest);
        let out = RelayEntry {
            descriptor,
            operator_id: r.array()?,
            class: r.u8()?,
            flags: r.u8()?,
        };
        r.finish()?;

        if out.class > 3 || out.class > out.descriptor.capacity_class {
            return Err(Error::Malformed);
        }

        // REL-151: layer 3 needs the queue role and the chain role, it is no
        // ingress, and no other bit exists. REL-157: a pending entry names
        // no layer.
        let exit_roles = roles::QUEUE | roles::CHAIN;
        let is_layer_3 = out.flags & flags::LAYER_3 != 0;
        let is_pending = out.flags & flags::PENDING != 0;
        if out.flags & !(flags::INGRESS | flags::LAYER_3 | flags::PENDING) != 0
            || (is_layer_3 && out.ingress())
            || (is_layer_3 && out.descriptor.roles & exit_roles != exit_roles)
            || (is_pending && is_layer_3)
        {
            return Err(Error::Malformed);
        }

        Ok(out)
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;
    use umbra_crypto::{secret::Secret, sign::SigningKey};

    pub(crate) struct Rng(pub u8);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    /// A signed entry for the relay whose identity seed is `seed`.
    pub(crate) fn entry_bytes(
        seed: u8,
        jurisdiction: [u8; 2],
        asn: u32,
        flags: u8,
    ) -> alloc::vec::Vec<u8> {
        let key = SigningKey::from_seed(Secret::new([seed; 32]));
        let pk = key.verifying_key().to_bytes();
        let mut host = [0u8; HOST_LEN];
        host[..13].copy_from_slice(b"relay.example");
        let mut desc = RelayDescriptor {
            relay_id: sha3_256(&[&pk]),
            identity_pk: &pk,
            ntor_pk: [seed; 32],
            addr_v4: [10, 0, seed, 1],
            addr_v6: [0; 16],
            port: 443,
            host,
            asn,
            jurisdiction,
            family_id: [seed; 32],
            capacity_class: 3,
            roles: roles::QUEUE | roles::CHAIN | roles::INGRESS_OFFERED,
            chunk_store_gib: 0,
            valid_after: 1,
            sig: &[0; SIGNATURE_LEN],
        };
        let sig = key
            .sign(&desc.preimage().unwrap(), &mut Rng(seed))
            .unwrap()
            .to_bytes();
        desc.sig = &sig;
        let entry = RelayEntry {
            descriptor: desc,
            operator_id: [seed; 32],
            class: 2,
            flags,
        };
        let mut out = vec![0u8; ENTRY_LEN];
        entry.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn a_signed_entry_round_trips_and_a_changed_byte_fails() {
        let bytes = entry_bytes(1, *b"DE", 3_320, 1);
        let entry = RelayEntry::parse(&bytes).unwrap();
        assert_eq!(entry.descriptor.host_str(), "relay.example");
        assert!(entry.ingress());
        assert_eq!(entry.descriptor.port, 443);
        let mut bad = bytes.clone();
        bad[2_100] ^= 1;
        assert!(RelayEntry::parse(&bad).is_err());
        let mut bad_host = bytes.clone();
        bad_host[1 + 32 + 1952 + 32 + 4 + 16 + 2] = b' ';
        assert!(RelayEntry::parse(&bad_host).is_err());
        assert!(RelayEntry::parse(&bytes[..ENTRY_LEN - 1]).is_err());
    }

    #[test]
    fn a_jurisdiction_that_is_not_two_capital_letters_is_no_entry() {
        // REL-092: each of these verifies under the key of its relay.
        for code in [*b"de", *b"De", *b"dE", *b"D1", [b'D', 0]] {
            assert!(RelayEntry::parse(&entry_bytes(1, code, 3_320, 1)).is_err());
        }
        assert!(RelayEntry::parse(&entry_bytes(1, *b"DE", 3_320, 1)).is_ok());
    }

    #[test]
    fn the_flags_of_an_entry_give_one_layer() {
        for (flags, layer) in [(0u8, 2u8), (1, 1), (2, 3)] {
            let bytes = entry_bytes(2, *b"SE", 64_501, flags);
            assert_eq!(RelayEntry::parse(&bytes).unwrap().layer(), layer);
        }
        // A pending entry names no layer of its own (`REL-157`).
        let bytes = entry_bytes(2, *b"SE", 64_501, 4);
        let pending = RelayEntry::parse(&bytes).unwrap();
        assert!(pending.pending());
        assert_eq!(pending.layer(), 2);
        // An ingress relay of layer 3, a pending entry of layer 3, and a bit
        // that does not exist.
        for flags in [3u8, 6, 0x80] {
            assert!(RelayEntry::parse(&entry_bytes(2, *b"SE", 64_501, flags)).is_err());
        }
    }
}
