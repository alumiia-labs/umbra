//! The link-fault report of Part 10 §10.4.2: the report itself, the report
//! queue that an authority publishes in the manifest, and the seal of a report
//! to that queue.

use alloc::vec::Vec;

use umbra_crypto::{
    labels,
    rand_core::CryptoRng,
    seal,
    secret::Secret,
    sign::{SigningKey, SIGNATURE_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::root::DirectoryKeySet;
use crate::Error;

/// The encoded width of a `LinkFaultReport`.
pub const REPORT_LEN: usize = 1 + 8 + 3 * 32 + 2 + 2;
/// The encoded width of a `SealedReport`.
pub const SEALED_REPORT_LEN: usize = REPORT_LEN + seal::OVERHEAD;
/// The width of a `QueueAddress` of Part 6 §6.6.10.
pub const QUEUE_ADDRESS_LEN: usize = 129;
/// The encoded width of a `ReportQueue`.
pub const REPORT_QUEUE_LEN: usize = 1 + 1 + 8 + QUEUE_ADDRESS_LEN + 32 + SIGNATURE_LEN;
/// The most report queues of one manifest: one for each authority.
pub const REPORT_QUEUES_MAX: usize = 7;

/// A loop-fault report of one chain in one epoch (`REL-076`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFaultReport {
    /// The consensus epoch.
    pub epoch: u64,
    /// The `relay_id` of each hop, the ingress first.
    pub hops: [[u8; 32]; 3],
    /// The loops, and the builds for a forced replacement, that the client
    /// tried on the chain.
    pub loops_sent: u16,
    /// Those that failed.
    pub loops_lost: u16,
}

impl LinkFaultReport {
    /// Writes the report.
    pub fn encode(&self) -> Result<[u8; REPORT_LEN], Error> {
        let mut out = [0u8; REPORT_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(0x01)?;
        w.put(&self.epoch.to_be_bytes())?;
        for hop in &self.hops {
            w.put(hop)?;
        }
        w.u16(self.loops_sent)?;
        w.u16(self.loops_lost)?;
        Ok(out)
    }

    /// Reads a report.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let epoch = u64::from_be_bytes(r.array()?);
        let hops = [r.array()?, r.array()?, r.array()?];
        let loops_sent = r.u16()?;
        let loops_lost = r.u16()?;
        r.finish()?;
        if loops_lost > loops_sent {
            return Err(Error::Malformed);
        }
        Ok(LinkFaultReport {
            epoch,
            hops,
            loops_sent,
            loops_lost,
        })
    }

    /// Seals the report to the `report_pk` of a report queue (`REL-169`).
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        report_pk: &[u8; 32],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        Ok(seal::seal(
            report_pk,
            labels::LINK_FAULT_SEAL,
            &self.encode()?,
            rng,
        )?)
    }

    /// Opens a `SealedReport` with the secret of the queue (`REL-170`).
    pub fn open(report_sk: &Secret<32>, sealed: &[u8]) -> Result<Self, Error> {
        if sealed.len() != SEALED_REPORT_LEN {
            return Err(Error::Malformed);
        }
        let plain = seal::open(report_sk, labels::LINK_FAULT_SEAL, sealed)
            .map_err(|_| Error::Unverified)?;
        Self::parse(&plain)
    }
}

/// The report queue of one authority (`REL-166`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportQueue {
    /// The index of the authority in the key set.
    pub authority_index: u8,
    /// The first consensus epoch that the queue serves.
    pub epoch: u64,
    /// The `QueueAddress` of the queue.
    pub address: [u8; QUEUE_ADDRESS_LEN],
    /// The X25519 key that a report seals to.
    pub report_pk: [u8; 32],
}

impl ReportQueue {
    fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REPORT_QUEUE_LEN);
        out.extend_from_slice(labels::REPORT_QUEUE);
        out.push(0x01);
        out.push(self.authority_index);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.address);
        out.extend_from_slice(&self.report_pk);
        out
    }

    /// Signs the queue with the key of its authority, and writes it.
    pub fn sign<R: CryptoRng + ?Sized>(
        &self,
        key: &SigningKey,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let sig = key.sign(&self.preimage(), rng)?;
        let mut out = alloc::vec![0u8; REPORT_QUEUE_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(0x01)?;
        w.u8(self.authority_index)?;
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.address)?;
        w.put(&self.report_pk)?;
        w.put(&sig.to_bytes())?;
        Ok(out)
    }

    /// Reads a signed queue and verifies it under `keyset` for a root of
    /// `root_epoch` (`REL-168`).
    pub fn verify(
        bytes: &[u8],
        keyset: &DirectoryKeySet<'_>,
        root_epoch: u64,
    ) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let queue = ReportQueue {
            authority_index: r.u8()?,
            epoch: u64::from_be_bytes(r.array()?),
            address: r.array()?,
            report_pk: r.array()?,
        };
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        if queue.epoch > root_epoch {
            return Err(Error::Stale);
        }
        keyset.verify_by(queue.authority_index, &queue.preimage(), sig)?;
        Ok(queue)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::directory::descriptor::tests::Rng;
    use crate::directory::root::tests::authorities;

    #[test]
    fn a_report_seals_to_its_queue_and_opens_there_alone() {
        let mut rng = Rng(3);
        let report = LinkFaultReport {
            epoch: 490_000,
            hops: [[1; 32], [2; 32], [3; 32]],
            loops_sent: 12,
            loops_lost: 4,
        };
        assert_eq!(
            LinkFaultReport::parse(&report.encode().unwrap()).unwrap(),
            report
        );
        let secret = Secret::new([9; 32]);
        let pk = seal::public_of(&secret);
        let sealed = report.seal(&pk, &mut rng).unwrap();
        assert_eq!(sealed.len(), SEALED_REPORT_LEN);
        assert_eq!(LinkFaultReport::open(&secret, &sealed).unwrap(), report);
        assert!(LinkFaultReport::open(&Secret::new([8; 32]), &sealed).is_err());
        let mut more = report.encode().unwrap();
        more[REPORT_LEN - 1] = 13;
        assert!(
            LinkFaultReport::parse(&more).is_err(),
            "more lost than sent"
        );
    }

    #[test]
    fn a_report_queue_verifies_under_its_authority_alone() {
        let mut rng = Rng(4);
        let keys = authorities(40);
        let pks: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let keyset = DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|k| &k[..]).collect(),
        };
        let queue = ReportQueue {
            authority_index: 2,
            epoch: 100,
            address: [7; QUEUE_ADDRESS_LEN],
            report_pk: [5; 32],
        };
        let signed = queue.sign(&keys[2], &mut rng).unwrap();
        assert_eq!(signed.len(), REPORT_QUEUE_LEN);
        assert_eq!(ReportQueue::verify(&signed, &keyset, 100).unwrap(), queue);
        assert_eq!(ReportQueue::verify(&signed, &keyset, 99), Err(Error::Stale));
        // The key of another authority does not sign for index 2.
        let forged = queue.sign(&keys[3], &mut rng).unwrap();
        assert!(ReportQueue::verify(&forged, &keyset, 100).is_err());
        let mut moved = signed.clone();
        moved[20] ^= 1;
        assert!(ReportQueue::verify(&moved, &keyset, 100).is_err());
    }
}
