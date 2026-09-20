//! The chunk store of a relay: the registrations, the held chunks, the
//! erase times of the two classes, the upload quota of §13.10, and the
//! egress budget of §13.11. The relay authenticates a command before it
//! calls the store, with the credentials that the store hands it.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_queue::Reject;

use super::{
    seal, BACKUP_TTL, CHUNK_EGRESS_BUDGET_DAY, CHUNK_FETCH_RATE, CHUNK_LIFE_MAX, CHUNK_SIZE,
    CHUNK_STORE_TARGET, CHUNK_TTL, QUOTA_WINDOW, UPLOAD_QUOTA_DAY,
};

/// The class of a chunk, which fixes its erase time and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Registered under `CNEW`: `CHUNK_TTL`, renewable to `CHUNK_LIFE_MAX`.
    Attachment,
    /// Registered under `BNEW`: `BACKUP_TTL`, not renewable.
    Backup,
}

/// The two credentials of a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credentials {
    /// Authorizes `CPUT`, `CDEL`, `CREP`, and `CVFY`.
    pub cred_pk: [u8; 32],
    /// Authorizes `CGET` and `CRNW`.
    pub read_pk: [u8; 32],
}

/// A registration that waits for its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The class.
    pub class: Class,
    /// The credentials.
    pub credentials: Credentials,
    /// The token that the `CID` gave, which the `CPUT` binds and a `CRPUT`
    /// presents.
    pub storage_token: [u8; 32],
    /// The registration time.
    pub registered_at: u64,
}

struct Held {
    class: Class,
    credentials: Credentials,
    bytes: Vec<u8>,
    registered_at: u64,
    renewed_at: u64,
    erase_at: u64,
    fetch_hour: u64,
    fetches: u32,
}

/// The chunk store of one relay.
pub struct ChunkStore {
    capacity: u64,
    target: u64,
    pending: BTreeMap<[u8; 32], Registration>,
    held: BTreeMap<[u8; 32], Held>,
    quota: BTreeMap<[u8; 32], (u64, u64)>,
    egress_day: u64,
    egress_bytes: u64,
}

const CHUNK_BYTES: u64 = CHUNK_SIZE as u64;

impl ChunkStore {
    /// A store of `capacity` bytes at `CHUNK_STORE_TARGET`.
    pub const fn new(capacity: u64) -> Self {
        Self::with_target(capacity, CHUNK_STORE_TARGET)
    }

    /// A store of `capacity` bytes whose trim starts at `target`.
    pub const fn with_target(capacity: u64, target: u64) -> Self {
        ChunkStore {
            capacity,
            target,
            pending: BTreeMap::new(),
            held: BTreeMap::new(),
            quota: BTreeMap::new(),
            egress_day: 0,
            egress_bytes: 0,
        }
    }

    /// The bytes held or reserved by a registration.
    pub fn used(&self) -> u64 {
        let count = self.held.len().saturating_add(self.pending.len());
        u64::try_from(count).map_or(u64::MAX, |n| n.saturating_mul(CHUNK_BYTES))
    }

    /// The free bytes.
    pub fn free(&self) -> u64 {
        self.capacity.saturating_sub(self.used())
    }

    /// Whether the store is above `CHUNK_STORE_TARGET`, which the relay
    /// signals as a capacity fault (`ATT-091`).
    pub fn over_target(&self) -> bool {
        self.used() > self.target
    }

    /// The chunks held.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// The registration of `chunk_id`, for the authentication of a `CPUT`.
    pub fn registration(&self, chunk_id: &[u8; 32]) -> Option<&Registration> {
        self.pending.get(chunk_id)
    }

    /// The credentials of a held chunk, for the authentication of a
    /// `CGET`, a `CDEL`, a `CREP`, a `CVFY`, or a `CRNW`.
    pub fn credentials(&self, chunk_id: &[u8; 32]) -> Option<Credentials> {
        self.held.get(chunk_id).map(|h| h.credentials)
    }

    /// Registers a chunk under `CNEW` or `BNEW`. The `holder` is the
    /// credential of the admission token, which the quota binds to
    /// (`ATT-092`). The `storage_token` comes from the relay CSPRNG
    /// (`ATT-038`).
    pub fn register(
        &mut self,
        chunk_id: [u8; 32],
        class: Class,
        credentials: Credentials,
        holder: [u8; 32],
        storage_token: [u8; 32],
        now: u64,
    ) -> Result<(), Reject> {
        // A held or a pending identifier is a squat or a repeat (ATT-058).
        if self.pending.contains_key(&chunk_id) || self.held.contains_key(&chunk_id) {
            return Err(Reject::Rejected);
        }
        if self.free() < CHUNK_BYTES {
            return Err(Reject::Busy);
        }
        let counter = self.quota.entry(holder).or_insert((now, 0));
        if now.saturating_sub(counter.0) >= QUOTA_WINDOW {
            *counter = (now, 0);
        }
        if counter.1.saturating_add(CHUNK_BYTES) > UPLOAD_QUOTA_DAY {
            return Err(Reject::Limit);
        }
        counter.1 = counter.1.saturating_add(CHUNK_BYTES);
        self.pending.insert(
            chunk_id,
            Registration {
                class,
                credentials,
                storage_token,
                registered_at: now,
            },
        );
        Ok(())
    }

    fn accept_bytes(&mut self, chunk_id: [u8; 32], bytes: &[u8], now: u64) -> Result<(), Reject> {
        if bytes.len() != CHUNK_SIZE {
            return Err(Reject::Rejected);
        }
        let registration = self.pending.remove(&chunk_id).ok_or(Reject::Rejected)?;
        let erase_at = match registration.class {
            Class::Attachment => now
                .saturating_add(CHUNK_TTL)
                .min(registration.registered_at.saturating_add(CHUNK_LIFE_MAX)),
            Class::Backup => now.saturating_add(BACKUP_TTL),
        };
        // The token is erased with the registration (ATT-112).
        self.held.insert(
            chunk_id,
            Held {
                class: registration.class,
                credentials: registration.credentials,
                bytes: bytes.to_vec(),
                registered_at: registration.registered_at,
                renewed_at: now,
                erase_at,
                fetch_hour: now,
                fetches: 0,
            },
        );
        Ok(())
    }

    /// Takes the bytes of a `CPUT` that the relay authenticated against
    /// `cred_pk` with the token bound (`ATT-040`, `ATT-042`, `ATT-044`).
    pub fn put(&mut self, chunk_id: [u8; 32], bytes: &[u8], now: u64) -> Result<(), Reject> {
        self.accept_bytes(chunk_id, bytes, now)
    }

    /// Takes the bytes of a `CRPUT`, authorized on the token alone
    /// (`ATT-107` to `ATT-111`).
    pub fn replica_put(
        &mut self,
        chunk_id: [u8; 32],
        storage_token: &[u8; 32],
        bytes: &[u8],
        now: u64,
    ) -> Result<(), Reject> {
        let registration = self.pending.get(&chunk_id).ok_or(Reject::Rejected)?;
        if !umbra_crypto::ct_eq(&registration.storage_token, storage_token) {
            return Err(Reject::Rejected);
        }
        self.accept_bytes(chunk_id, bytes, now)
    }

    /// Serves a `CGET` that the relay authenticated against `read_pk`,
    /// under the egress budget and the fetch rate (`ATT-169` to
    /// `ATT-172`).
    pub fn get(&mut self, chunk_id: &[u8; 32], now: u64) -> Result<&[u8], Reject> {
        if now.saturating_sub(self.egress_day) >= 86_400 {
            self.egress_day = now;
            self.egress_bytes = 0;
        }
        let held = self.held.get_mut(chunk_id).ok_or(Reject::Rejected)?;
        if self.egress_bytes.saturating_add(CHUNK_BYTES) > CHUNK_EGRESS_BUDGET_DAY {
            return Err(Reject::Busy);
        }
        if now.saturating_sub(held.fetch_hour) >= 3_600 {
            held.fetch_hour = now;
            held.fetches = 0;
        }
        if held.fetches >= CHUNK_FETCH_RATE {
            return Err(Reject::Limit);
        }
        held.fetches = held.fetches.saturating_add(1);
        self.egress_bytes = self.egress_bytes.saturating_add(CHUNK_BYTES);
        Ok(&held.bytes)
    }

    /// Erases a chunk or a registration at a `CDEL` that the relay
    /// authenticated against `cred_pk` (`ATT-046`, `ATT-047`).
    pub fn delete(&mut self, chunk_id: &[u8; 32]) -> Result<(), Reject> {
        if self.held.remove(chunk_id).is_some() || self.pending.remove(chunk_id).is_some() {
            Ok(())
        } else {
            Err(Reject::Rejected)
        }
    }

    /// Renews an attachment chunk at a `CRNW` that the relay authenticated
    /// against `read_pk`. The relay sends no answer either way
    /// (`ATT-125`, `ATT-126`, `ATT-128`).
    pub fn renew(&mut self, chunk_id: &[u8; 32], now: u64) -> Result<(), Reject> {
        let held = self.held.get_mut(chunk_id).ok_or(Reject::Rejected)?;
        if held.class == Class::Backup {
            return Err(Reject::Rejected);
        }
        held.renewed_at = now;
        held.erase_at = now
            .saturating_add(CHUNK_TTL)
            .min(held.registered_at.saturating_add(CHUNK_LIFE_MAX));
        Ok(())
    }

    /// The proof of a `CVFY`, or `None` for an unknown chunk (`ATT-115`,
    /// `ATT-116`).
    pub fn prove(&self, chunk_id: &[u8; 32], nonce: &[u8; 16]) -> Option<[u8; 32]> {
        self.held
            .get(chunk_id)
            .map(|h| seal::proof(nonce, &h.bytes))
    }

    /// The bytes of a held chunk, for the copy that a `CREP` asks for.
    pub fn bytes(&self, chunk_id: &[u8; 32]) -> Option<&[u8]> {
        self.held.get(chunk_id).map(|h| h.bytes.as_slice())
    }

    /// The erase time of a held chunk.
    pub fn erase_at(&self, chunk_id: &[u8; 32]) -> Option<u64> {
        self.held.get(chunk_id).map(|h| h.erase_at)
    }

    /// Erases each chunk past its erase time, each registration that
    /// `CHUNK_TTL` released, and each quota counter past its window
    /// (`ATT-046`, `ATT-094`). Returns the count erased.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.held.len().saturating_add(self.pending.len());
        self.held.retain(|_, h| h.erase_at > now);
        self.pending
            .retain(|_, r| now.saturating_sub(r.registered_at) < CHUNK_TTL);
        self.quota
            .retain(|_, (start, _)| now.saturating_sub(*start) < QUOTA_WINDOW);
        before.saturating_sub(self.held.len().saturating_add(self.pending.len()))
    }

    /// Erases attachment chunks, oldest renewal first, until the store is
    /// at the target. A backup-class chunk stays (`ATT-168`, `ATT-179`).
    pub fn trim(&mut self) -> usize {
        let mut erased = 0usize;
        while self.over_target() {
            let oldest = self
                .held
                .iter()
                .filter(|(_, h)| h.class == Class::Attachment)
                .min_by_key(|(_, h)| h.renewed_at)
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => {
                    self.held.remove(&id);
                    erased = erased.saturating_add(1);
                }
                None => break,
            }
        }
        erased
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn creds(seed: u8) -> Credentials {
        Credentials {
            cred_pk: [seed; 32],
            read_pk: [seed.wrapping_add(1); 32],
        }
    }

    #[test]
    fn a_registration_a_put_and_a_get_follow_the_rules() {
        let mut store = ChunkStore::new(10 * CHUNK_BYTES);
        let chunk = alloc::vec![1u8; CHUNK_SIZE];
        store
            .register([1; 32], Class::Attachment, creds(1), [9; 32], [7; 32], 100)
            .unwrap();
        assert_eq!(
            store.register([1; 32], Class::Attachment, creds(1), [9; 32], [7; 32], 100),
            Err(Reject::Rejected)
        );
        assert_eq!(store.registration(&[1; 32]).unwrap().storage_token, [7; 32]);
        assert_eq!(
            store.put([1; 32], &chunk[..100], 200),
            Err(Reject::Rejected)
        );
        store.put([1; 32], &chunk, 200).unwrap();
        assert!(store.registration(&[1; 32]).is_none());
        assert_eq!(store.credentials(&[1; 32]).unwrap(), creds(1));
        assert_eq!(store.erase_at(&[1; 32]), Some(200 + CHUNK_TTL));
        assert_eq!(store.get(&[1; 32], 300).unwrap(), &chunk[..]);
        assert_eq!(store.get(&[2; 32], 300), Err(Reject::Rejected));
        assert_eq!(
            store.prove(&[1; 32], &[3; 16]),
            Some(seal::proof(&[3; 16], &chunk))
        );
        assert!(store.prove(&[2; 32], &[3; 16]).is_none());
        // A renewal moves the erase time, and the life bound caps it.
        store.renew(&[1; 32], 100 + CHUNK_LIFE_MAX - 10).unwrap();
        assert_eq!(store.erase_at(&[1; 32]), Some(100 + CHUNK_LIFE_MAX));
        assert_eq!(store.sweep(100 + CHUNK_LIFE_MAX), 1);
        assert!(store.credentials(&[1; 32]).is_none());
        store.delete(&[1; 32]).unwrap_err();
    }

    #[test]
    fn a_replica_put_is_authorized_on_the_token_only_and_once() {
        let mut store = ChunkStore::new(10 * CHUNK_BYTES);
        let chunk = alloc::vec![2u8; CHUNK_SIZE];
        store
            .register([1; 32], Class::Backup, creds(1), [9; 32], [7; 32], 100)
            .unwrap();
        assert_eq!(
            store.replica_put([1; 32], &[8; 32], &chunk, 200),
            Err(Reject::Rejected)
        );
        store.replica_put([1; 32], &[7; 32], &chunk, 200).unwrap();
        assert_eq!(
            store.replica_put([1; 32], &[7; 32], &chunk, 200),
            Err(Reject::Rejected)
        );
        assert_eq!(store.erase_at(&[1; 32]), Some(200 + BACKUP_TTL));
        assert_eq!(store.renew(&[1; 32], 300), Err(Reject::Rejected));
        // A pending registration with no bytes leaves at CHUNK_TTL.
        store
            .register([2; 32], Class::Attachment, creds(2), [9; 32], [6; 32], 100)
            .unwrap();
        assert_eq!(store.sweep(100 + CHUNK_TTL), 1);
        assert!(store.registration(&[2; 32]).is_none());
        store.delete(&[1; 32]).unwrap();
        assert_eq!(store.held_count(), 0);
    }

    #[test]
    fn the_free_space_the_quota_the_egress_and_the_rate_bound_the_store() {
        let mut store = ChunkStore::new(2 * CHUNK_BYTES);
        store
            .register([1; 32], Class::Attachment, creds(1), [9; 32], [7; 32], 0)
            .unwrap();
        store
            .register([2; 32], Class::Attachment, creds(2), [9; 32], [7; 32], 0)
            .unwrap();
        assert_eq!(
            store.register([3; 32], Class::Attachment, creds(3), [9; 32], [7; 32], 0),
            Err(Reject::Busy)
        );
        let mut big = ChunkStore::new(u64::MAX);
        let per_day = u32::try_from(UPLOAD_QUOTA_DAY / CHUNK_BYTES).unwrap();
        for i in 0..per_day {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            big.register(id, Class::Attachment, creds(1), [9; 32], [7; 32], 0)
                .unwrap();
        }
        assert_eq!(
            big.register([200; 32], Class::Attachment, creds(0), [9; 32], [7; 32], 10),
            Err(Reject::Limit)
        );
        big.register([200; 32], Class::Attachment, creds(0), [8; 32], [7; 32], 10)
            .unwrap();
        big.register(
            [201; 32],
            Class::Attachment,
            creds(0),
            [9; 32],
            [7; 32],
            QUOTA_WINDOW,
        )
        .unwrap();

        let chunk = alloc::vec![3u8; CHUNK_SIZE];
        big.put([0; 32], &chunk, 20).unwrap();
        assert_eq!(big.held_count(), 1);
        for _ in 0..CHUNK_FETCH_RATE {
            big.get(&[0; 32], 30).unwrap();
        }
        assert_eq!(big.get(&[0; 32], 30), Err(Reject::Limit));
        big.get(&[0; 32], 30 + 3_600).unwrap();
        big.egress_bytes = CHUNK_EGRESS_BUDGET_DAY;
        assert_eq!(big.get(&[0; 32], 40 + 3_600), Err(Reject::Busy));
        big.get(&[0; 32], 40 + 86_400).unwrap();
    }

    #[test]
    fn a_trim_erases_the_oldest_renewal_and_keeps_the_backup_class() {
        let mut store = ChunkStore::with_target(u64::MAX, 4 * CHUNK_BYTES);
        let chunk = alloc::vec![4u8; CHUNK_SIZE];
        let count = 6usize;
        for i in 0..count {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&(i as u32).to_be_bytes());
            let class = if i == 0 {
                Class::Backup
            } else {
                Class::Attachment
            };
            store
                .register(id, class, creds(1), [9; 32], [7; 32], i as u64)
                .unwrap();
            store.put(id, &chunk, i as u64).unwrap();
        }
        assert!(store.over_target());
        assert_eq!(store.trim(), 2);
        assert!(!store.over_target());
        assert!(store.credentials(&[0; 32]).is_some());
        let mut second = [0u8; 32];
        second[3] = 1;
        assert!(store.credentials(&second).is_none());
    }
}
