//! The upload of one chunk (Part 13 §13.4.1): a registration at each
//! replica, one `CPUT`, one `CREP`, and the verification sample. The
//! client holds the write credential until the chunk is erased.

use alloc::vec::Vec;

use umbra_crypto::x25519::{PublicKey, StaticSecret};
use umbra_wire::descriptor::ChunkRef;

use super::{
    command::{CrepPayload, ReplicaTarget},
    place::AttachmentRelay,
    seal, HOT_REPLICAS,
};
use crate::Error;

/// Whether each relay holds a distinct `operator_id` (`ATT-017`).
pub fn distinct_operators(relays: &[AttachmentRelay]) -> bool {
    relays.iter().enumerate().all(|(i, a)| {
        relays
            .iter()
            .skip(i.saturating_add(1))
            .all(|b| a.operator_id != b.operator_id)
    })
}

/// The chunks a client samples for `CVFY` at one relay: `sample` distinct
/// positions below `count`, drawn at random (`ATT-120`, `ATT-121`).
/// `random` gives a value below its argument.
pub fn sample_positions(count: u32, sample: usize, random: &mut dyn FnMut(u32) -> u32) -> Vec<u32> {
    let mut positions: Vec<u32> = (0..count).collect();
    let wanted = sample.min(positions.len());
    let mut picked = Vec::with_capacity(wanted);
    for _ in 0..wanted {
        let bound = u32::try_from(positions.len()).unwrap_or(u32::MAX);
        let at = usize::try_from(random(bound)).unwrap_or(0) % positions.len().max(1);
        picked.push(positions.swap_remove(at));
    }
    picked
}

/// The state of one chunk at the uploader.
pub struct ChunkUpload {
    chunk_id: [u8; 32],
    cred: StaticSecret,
    registrations: Vec<ReplicaTarget>,
    put_done: bool,
    rep_done: bool,
}

impl ChunkUpload {
    /// A chunk under a random `chunk_id` and a random `cred_sk`, both from
    /// the device CSPRNG (`ATT-034`, `ATT-055`).
    pub fn new(chunk_id: [u8; 32], cred: StaticSecret) -> Self {
        ChunkUpload {
            chunk_id,
            cred,
            registrations: Vec::new(),
            put_done: false,
            rep_done: false,
        }
    }

    /// The chunk.
    pub const fn chunk_id(&self) -> &[u8; 32] {
        &self.chunk_id
    }

    /// `cred_pk`.
    pub fn cred_pk(&self) -> [u8; 32] {
        PublicKey::from(&self.cred).to_bytes()
    }

    /// `cred_sk`, retained until the chunk is erased (`ATT-160`).
    pub const fn cred_secret(&self) -> &StaticSecret {
        &self.cred
    }

    /// Records the `CID` of one relay. The first relay takes the `CPUT`
    /// (`ATT-096`, `ATT-100`).
    pub fn register(&mut self, relay_id: [u8; 32], storage_token: [u8; 32]) -> Result<(), Error> {
        if self.put_done
            || self.registrations.len() >= HOT_REPLICAS
            || self.registrations.iter().any(|r| r.relay_id == relay_id)
        {
            return Err(Error::Stale);
        }
        self.registrations.push(ReplicaTarget {
            relay_id,
            storage_token,
        });
        Ok(())
    }

    /// The relays registered, in order.
    pub fn relays(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.registrations.iter().map(|r| &r.relay_id)
    }

    /// The relay that takes the `CPUT` and the token the `CPUT` binds
    /// (`ATT-042`, `ATT-097`), once `replicas` relays are registered.
    pub fn put_target(&self, replicas: usize) -> Result<&ReplicaTarget, Error> {
        if self.registrations.len() < replicas {
            return Err(Error::Stale);
        }
        self.registrations.first().ok_or(Error::Stale)
    }

    /// Records that the `CPUT` succeeded.
    pub fn put_done(&mut self, replicas: usize) -> Result<(), Error> {
        self.put_target(replicas)?;
        self.put_done = true;
        Ok(())
    }

    /// The `CREP` for the relay that took the `CPUT`, with the token of
    /// each other relay (`ATT-098` to `ATT-101`).
    pub fn crep(&mut self) -> Result<CrepPayload, Error> {
        if !self.put_done || self.rep_done {
            return Err(Error::Stale);
        }
        let targets: Vec<ReplicaTarget> = self.registrations.iter().skip(1).copied().collect();
        if targets.is_empty() {
            return Err(Error::Stale);
        }
        self.rep_done = true;
        Ok(CrepPayload { targets })
    }

    /// Whether the chunk is put and replicated.
    pub const fn is_placed(&self) -> bool {
        self.put_done && self.rep_done
    }

    /// The `ChunkRef` of the chunk: the first relay in full and the next
    /// two as hints, with a null hint for an absent one (`ATT-141`). A
    /// fourth relay and beyond go in a further ref of the same chunk
    /// (`ATT-175`).
    pub fn chunk_refs(&self) -> Result<Vec<ChunkRef>, Error> {
        if !self.is_placed() {
            return Err(Error::Stale);
        }
        let mut refs = Vec::new();
        for group in self.registrations.chunks(3) {
            let first = group.first().ok_or(Error::Stale)?;
            let hint = |i: usize| {
                group
                    .get(i)
                    .map_or([0; 12], |r| seal::relay_hint(&r.relay_id))
            };
            refs.push(ChunkRef {
                relay_id: first.relay_id,
                chunk_id: self.chunk_id,
                cred_pk: self.cred_pk(),
                replicas: [hint(1), hint(2)],
            });
        }
        Ok(refs)
    }

    /// Replaces a replica that failed its proof with a fresh relay
    /// (`ATT-118`): the old relay leaves the list, and the new one goes
    /// through its own `CNEW` and `CPUT` under this credential.
    pub fn replace_replica(
        &mut self,
        failed: &[u8; 32],
        relay_id: [u8; 32],
        storage_token: [u8; 32],
    ) {
        self.registrations.retain(|r| r.relay_id != *failed);
        self.registrations.push(ReplicaTarget {
            relay_id,
            storage_token,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::attach::REPLICAS;

    #[test]
    fn an_upload_registers_puts_once_replicates_and_names_its_refs() {
        let mut up = ChunkUpload::new([1; 32], StaticSecret::from([2; 32]));
        assert!(up.put_target(REPLICAS).is_err());
        up.register([10; 32], [11; 32]).unwrap();
        assert!(up.register([10; 32], [12; 32]).is_err());
        up.register([20; 32], [21; 32]).unwrap();
        assert!(up.crep().is_err());
        up.register([30; 32], [31; 32]).unwrap();
        assert_eq!(up.put_target(REPLICAS).unwrap().storage_token, [11; 32]);
        up.put_done(REPLICAS).unwrap();
        assert!(up.register([40; 32], [41; 32]).is_err());
        let crep = up.crep().unwrap();
        assert_eq!(crep.targets.len(), 2);
        assert_eq!(crep.targets[0].relay_id, [20; 32]);
        assert_eq!(crep.targets[1].storage_token, [31; 32]);
        assert!(up.crep().is_err());
        let refs = up.chunk_refs().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].relay_id, [10; 32]);
        assert_eq!(refs[0].cred_pk, up.cred_pk());
        assert_eq!(refs[0].replicas[0], seal::relay_hint(&[20; 32]));
        assert_eq!(refs[0].replicas[1], seal::relay_hint(&[30; 32]));
        up.replace_replica(&[30; 32], [40; 32], [41; 32]);
        assert_eq!(up.relays().count(), 3);
        assert_eq!(
            up.chunk_refs().unwrap()[0].replicas[1],
            seal::relay_hint(&[40; 32])
        );
    }

    #[test]
    fn a_backup_chunk_has_one_null_hint_and_a_hot_chunk_a_second_ref() {
        let mut up = ChunkUpload::new([1; 32], StaticSecret::from([2; 32]));
        up.register([10; 32], [11; 32]).unwrap();
        up.register([20; 32], [21; 32]).unwrap();
        up.put_done(2).unwrap();
        up.crep().unwrap();
        let refs = up.chunk_refs().unwrap();
        assert_eq!(refs[0].replicas[1], [0; 12]);

        let mut hot = ChunkUpload::new([1; 32], StaticSecret::from([2; 32]));
        for i in 1..=HOT_REPLICAS as u8 {
            hot.register([i; 32], [i; 32]).unwrap();
        }
        assert!(hot.register([9; 32], [9; 32]).is_err());
        hot.put_done(HOT_REPLICAS).unwrap();
        assert_eq!(hot.crep().unwrap().targets.len(), HOT_REPLICAS - 1);
        let refs = hot.chunk_refs().unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[1].relay_id, [4; 32]);
        assert_eq!(refs[1].chunk_id, refs[0].chunk_id);
    }

    #[test]
    fn the_operators_are_distinct_and_the_sample_is_random_and_whole() {
        let relay = |op: u8| AttachmentRelay {
            relay_id: [op; 32],
            operator_id: [op; 32],
            family_id: [op; 32],
        };
        assert!(distinct_operators(&[relay(1), relay(2), relay(3)]));
        assert!(!distinct_operators(&[relay(1), relay(2), relay(1)]));
        let mut counter = 0u32;
        let mut random = |bound: u32| {
            counter = counter.wrapping_add(7);
            counter % bound
        };
        let picks = sample_positions(100, 4, &mut random);
        assert_eq!(picks.len(), 4);
        let mut sorted = picks.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
        assert_eq!(sample_positions(3, 64, &mut random).len(), 3);
        assert!(sample_positions(0, 4, &mut random).is_empty());
    }
}
