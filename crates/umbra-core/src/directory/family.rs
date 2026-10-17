//! The family certificate of Part 10 §10.6.3, which a directory authority
//! verifies before it lists a member. A client never fetches it.

use alloc::vec::Vec;

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, VerifyingKey, SIGNATURE_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::FAMILY_MAX;
use crate::Error;

/// A family certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyCert<'a> {
    /// A label the operator selects.
    pub family_name: [u8; 32],
    /// The relay identifiers of the members.
    pub members: Vec<[u8; 32]>,
    /// The first consensus epoch.
    pub valid_after: u64,
    /// One signature for each member, in member order.
    pub sigs: Vec<&'a [u8]>,
}

impl<'a> FamilyCert<'a> {
    /// The preimage each member signs.
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + self.members.len() * 32);
        out.extend_from_slice(labels::RELAY_FAMILY);
        out.push(0x01);
        out.extend_from_slice(&self.family_name);
        out.extend_from_slice(
            &u16::try_from(self.members.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for m in &self.members {
            out.extend_from_slice(m);
        }
        out.extend_from_slice(&self.valid_after.to_be_bytes());
        out
    }

    /// Writes the certificate.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.members.is_empty()
            || self.members.len() > FAMILY_MAX
            || self.sigs.len() != self.members.len()
            || self.sigs.iter().any(|s| s.len() != SIGNATURE_LEN)
        {
            return Err(Error::Malformed);
        }

        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.family_name)?;
        w.u16(u16::try_from(self.members.len()).map_err(|_| Error::Malformed)?)?;
        for m in &self.members {
            w.put(m)?;
        }
        w.put(&self.valid_after.to_be_bytes())?;
        w.u8(u8::try_from(self.sigs.len()).map_err(|_| Error::Malformed)?)?;
        for s in &self.sigs {
            w.put(s)?;
        }

        Ok(w.position())
    }

    /// Reads a certificate (`REL-088`).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let family_name = r.array()?;
        let count = usize::from(r.u16()?);
        if count == 0 || count > FAMILY_MAX {
            return Err(Error::Malformed);
        }

        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            members.push(r.array()?);
        }
        let valid_after = u64::from_be_bytes(r.array()?);

        let sig_count = usize::from(r.u8()?);
        if sig_count != count {
            return Err(Error::Malformed);
        }

        let mut sigs = Vec::with_capacity(count);
        for _ in 0..count {
            sigs.push(r.take(SIGNATURE_LEN)?);
        }
        r.finish()?;

        Ok(FamilyCert {
            family_name,
            members,
            valid_after,
            sigs,
        })
    }

    /// `family_id`: the SHA3-256 of the certificate bytes (`REL-086`).
    pub fn family_id(bytes: &[u8]) -> [u8; 32] {
        sha3_256(&[bytes])
    }

    /// Verifies every member signature against the identity keys the
    /// authority holds, given in member order (`REL-087`), and that
    /// `relay_id` is a member (`REL-089`).
    pub fn verify(&self, identity_keys: &[&[u8]], relay_id: &[u8; 32]) -> Result<(), Error> {
        if identity_keys.len() != self.members.len() || !self.members.contains(relay_id) {
            return Err(Error::Unverified);
        }

        let preimage = self.preimage();
        for ((member, key), sig) in self.members.iter().zip(identity_keys).zip(&self.sigs) {
            if sha3_256(&[key]) != *member {
                return Err(Error::Unverified);
            }
            VerifyingKey::from_bytes(key)?.verify(&preimage, &Signature::from_bytes(sig)?)?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::directory::descriptor::tests::Rng;
    use umbra_crypto::{secret::Secret, sign::SigningKey};

    #[test]
    fn every_member_signs_and_a_stranger_is_not_a_member() {
        let keys: Vec<SigningKey> = (1..=2u8)
            .map(|i| SigningKey::from_seed(Secret::new([i; 32])))
            .collect();
        let pks: Vec<[u8; 1952]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let members: Vec<[u8; 32]> = pks.iter().map(|p| sha3_256(&[p])).collect();
        let mut cert = FamilyCert {
            family_name: [7; 32],
            members: members.clone(),
            valid_after: 3,
            sigs: Vec::new(),
        };
        let preimage = cert.preimage();
        let sigs: Vec<[u8; SIGNATURE_LEN]> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| k.sign(&preimage, &mut Rng(i as u8)).unwrap().to_bytes())
            .collect();
        cert.sigs = sigs.iter().map(|s| &s[..]).collect();
        let mut out = alloc::vec![0u8; 8_000];
        let n = cert.encode(&mut out).unwrap();
        let parsed = FamilyCert::parse(&out[..n]).unwrap();
        let key_refs: Vec<&[u8]> = pks.iter().map(|p| &p[..]).collect();
        parsed.verify(&key_refs, &members[0]).unwrap();
        assert!(parsed.verify(&key_refs, &[9; 32]).is_err());
        let swapped: Vec<&[u8]> = key_refs.iter().rev().copied().collect();
        assert!(parsed.verify(&swapped, &members[0]).is_err());
        let _ = FamilyCert::family_id(&out[..n]);
    }
}
