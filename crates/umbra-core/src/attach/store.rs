//! The chunk store of a relay: the registrations, the held chunks, the
//! erase times of the two classes, the upload quota of §12.10, and the
//! egress budget of §12.11. The relay authenticates a command before it
//! calls the store, with the credentials that the store hands it.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_queue::Reject;

use super::{
    pending_share, seal, trim_target, BACKUP_TTL, CHUNK_EGRESS_BUDGET_DAY, CHUNK_FETCH_RATE,
    CHUNK_LIFE_MAX, CHUNK_PENDING_TTL, CHUNK_SIZE, CHUNK_TTL, QUOTA_WINDOW, UPLOAD_QUOTA_DAY,
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

/// A held chunk, as the durable store of a relay holds it. The fetch rate
/// and the egress budget stay in RAM, and a restart starts them again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldChunk {
    /// The class.
    pub class: Class,
    /// The credentials.
    pub credentials: Credentials,
    /// The bytes that the `CPUT` or the `CRPUT` gave.
    pub bytes: Vec<u8>,
    /// The registration time.
    pub registered_at: u64,
    /// The time of the bytes, and then of the last renewal.
    pub renewed_at: u64,
    /// The erase time.
    pub erase_at: u64,
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
    /// The pending registrations, oldest first.
    pending_order: BTreeSet<(u64, [u8; 32])>,
    held: BTreeMap<[u8; 32], Held>,
    quota: BTreeMap<[u8; 32], (u64, u64)>,
    egress_day: u64,
    egress_bytes: u64,
    erased: Vec<[u8; 32]>,
}

const CHUNK_BYTES: u64 = CHUNK_SIZE as u64;

impl ChunkStore {
    /// A store of `capacity` bytes at its trim target (`ATT-201`).
    pub const fn new(capacity: u64) -> Self {
        Self::with_target(capacity, trim_target(capacity))
    }

    /// A store of `capacity` bytes whose trim starts at `target`.
    pub const fn with_target(capacity: u64, target: u64) -> Self {
        ChunkStore {
            capacity,
            target,
            pending: BTreeMap::new(),
            pending_order: BTreeSet::new(),
            held: BTreeMap::new(),
            quota: BTreeMap::new(),
            egress_day: 0,
            egress_bytes: 0,
            erased: Vec::new(),
        }
    }

    /// A held chunk, for the durable store.
    pub fn export(&self, chunk_id: &[u8; 32]) -> Option<HeldChunk> {
        self.held.get(chunk_id).map(|held| HeldChunk {
            class: held.class,
            credentials: held.credentials,
            bytes: held.bytes.clone(),
            registered_at: held.registered_at,
            renewed_at: held.renewed_at,
            erase_at: held.erase_at,
        })
    }

    /// Takes back a chunk of an earlier run. A pending registration is not
    /// restored, and its upload fails and starts again.
    pub fn restore(&mut self, chunk_id: [u8; 32], chunk: HeldChunk) {
        self.held.insert(
            chunk_id,
            Held {
                class: chunk.class,
                credentials: chunk.credentials,
                bytes: chunk.bytes,
                registered_at: chunk.registered_at,
                renewed_at: chunk.renewed_at,
                erase_at: chunk.erase_at,
                fetch_hour: 0,
                fetches: 0,
            },
        );
    }

    /// The held chunks that left the store since the last call: a `CDEL`,
    /// the erase time, or the trim.
    pub fn take_erased(&mut self) -> Vec<[u8; 32]> {
        core::mem::take(&mut self.erased)
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

    /// The bytes of the held chunks alone.
    fn held_bytes(&self) -> u64 {
        u64::try_from(self.held.len()).map_or(u64::MAX, |n| n.saturating_mul(CHUNK_BYTES))
    }

    /// The bytes that the pending registrations reserve.
    fn pending_bytes(&self) -> u64 {
        u64::try_from(self.pending.len()).map_or(u64::MAX, |n| n.saturating_mul(CHUNK_BYTES))
    }

    /// Takes a pending registration out of the store.
    fn take_pending(&mut self, chunk_id: &[u8; 32]) -> Option<Registration> {
        let registration = self.pending.remove(chunk_id)?;
        self.pending_order
            .remove(&(registration.registered_at, *chunk_id));
        Some(registration)
    }

    /// Whether the held chunks are above the trim target, where the trim
    /// may erase attachment chunks (`ATT-168`). No directory learns of it
    /// (`ATT-091`). A pending registration holds no bytes and does not count
    /// here, thus a flood of registrations erases no chunk (`ATT-090`).
    pub fn over_target(&self) -> bool {
        self.held_bytes() > self.target
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

        // ATT-200: registrations with no bytes that fill the store make
        // room for a new one, and no held chunk leaves for them. The new
        // one counts in the share: a store whose held chunks are at the
        // trim target then still takes it.
        let pending_after = self.pending_bytes().saturating_add(CHUNK_BYTES);
        if self.free() < CHUNK_BYTES && pending_after > pending_share(self.capacity) {
            if let Some(&(_, oldest)) = self.pending_order.first() {
                self.take_pending(&oldest);
            }
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

        self.pending_order.insert((now, chunk_id));
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

        let registration = self.take_pending(&chunk_id).ok_or(Reject::Rejected)?;
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
                fetch_hour: 0,
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
        // The day of the budget starts at midnight UTC (§12.7).
        let day = now.saturating_sub(now % 86_400);
        if day > self.egress_day {
            self.egress_day = day;
            self.egress_bytes = 0;
        }

        let held = self.held.get_mut(chunk_id).ok_or(Reject::Rejected)?;
        if self.egress_bytes.saturating_add(CHUNK_BYTES) > CHUNK_EGRESS_BUDGET_DAY {
            return Err(Reject::Busy);
        }

        // The hour of the rate is an hour of the UTC clock, and no time
        // that the `CPUT` gave.
        let hour = now.saturating_sub(now % 3_600);
        if hour > held.fetch_hour {
            held.fetch_hour = hour;
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
        if self.held.remove(chunk_id).is_some() {
            self.erased.push(*chunk_id);
            Ok(())
        } else if self.take_pending(chunk_id).is_some() {
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
    /// `CHUNK_PENDING_TTL` released, and each quota counter past its window
    /// (`ATT-046`, `ATT-094`, `ATT-181`). Returns the count erased.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.held.len().saturating_add(self.pending.len());
        let erased = &mut self.erased;
        self.held.retain(|id, h| {
            let keep = h.erase_at > now;
            if !keep {
                erased.push(*id);
            }
            keep
        });

        while let Some(&(registered_at, chunk_id)) = self.pending_order.first() {
            if now.saturating_sub(registered_at) < CHUNK_PENDING_TTL {
                break;
            }
            self.take_pending(&chunk_id);
        }
        self.quota
            .retain(|_, (start, _)| now.saturating_sub(*start) < QUOTA_WINDOW);

        before.saturating_sub(self.held.len().saturating_add(self.pending.len()))
    }

    /// Erases attachment chunks, oldest renewal first, until the held chunks
    /// are at the target. A backup-class chunk stays (`ATT-168`, `ATT-179`).
    /// A pending registration holds no bytes, thus it makes no chunk leave
    /// (`ATT-090`). Returns the count of the chunks erased.
    pub fn trim(&mut self) -> usize {
        let most = usize::try_from(self.target / CHUNK_BYTES).unwrap_or(usize::MAX);
        let excess = self.held.len().saturating_sub(most);
        if excess == 0 {
            return 0;
        }

        let mut oldest: Vec<(u64, [u8; 32])> = self
            .held
            .iter()
            .filter(|(_, h)| h.class == Class::Attachment)
            .map(|(id, h)| (h.renewed_at, *id))
            .collect();
        oldest.sort_unstable();

        let mut erased = 0usize;
        for (_, id) in oldest.into_iter().take(excess) {
            self.held.remove(&id);
            self.erased.push(id);
            erased = erased.saturating_add(1);
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

        // ATT-181: a pending registration with no bytes leaves at
        // CHUNK_PENDING_TTL.
        store
            .register([2; 32], Class::Attachment, creds(2), [9; 32], [6; 32], 100)
            .unwrap();
        assert_eq!(store.sweep(100 + CHUNK_PENDING_TTL - 1), 0);
        assert!(store.registration(&[2; 32]).is_some());
        assert_eq!(store.sweep(100 + CHUNK_PENDING_TTL), 1);
        assert!(store.registration(&[2; 32]).is_none());
        store.delete(&[1; 32]).unwrap();
        assert_eq!(store.held_count(), 0);
    }

    #[test]
    fn the_free_space_the_quota_the_egress_and_the_rate_bound_the_store() {
        let mut store = ChunkStore::new(2 * CHUNK_BYTES);
        let chunk = alloc::vec![3u8; CHUNK_SIZE];
        for id in [[1; 32], [2; 32]] {
            store
                .register(id, Class::Attachment, creds(1), [9; 32], [7; 32], 0)
                .unwrap();
            store.put(id, &chunk, 0).unwrap();
        }
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

    fn id(i: u32) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        id
    }

    #[test]
    fn a_pending_registration_makes_no_held_chunk_leave() {
        let mut store = ChunkStore::with_target(8 * CHUNK_BYTES, 4 * CHUNK_BYTES);
        let chunk = alloc::vec![5u8; CHUNK_SIZE];

        for i in 0..4 {
            store
                .register(id(i), Class::Attachment, creds(1), [9; 32], [7; 32], 0)
                .unwrap();
            store.put(id(i), &chunk, 0).unwrap();
        }

        // Three registrations with no bytes put the used store above the
        // target, and the trim erases no chunk for them (ATT-090).
        for i in 10..13 {
            store
                .register(
                    id(i),
                    Class::Attachment,
                    creds(2),
                    [8; 32],
                    [7; 32],
                    u64::from(i),
                )
                .unwrap();
        }
        assert!(store.used() > 4 * CHUNK_BYTES);
        assert!(!store.over_target());
        assert_eq!(store.trim(), 0);
        assert_eq!(store.held_count(), 4);
        assert!(store.registration(&id(12)).is_some());

        // ATT-200: the registrations fill the store, and the oldest of them
        // leave for new ones. Each chunk stays.
        for i in 13..16 {
            store
                .register(
                    id(i),
                    Class::Attachment,
                    creds(2),
                    [8; 32],
                    [7; 32],
                    u64::from(i),
                )
                .unwrap();
        }

        assert_eq!(store.trim(), 0);
        assert_eq!(store.held_count(), 4);
        assert!(store.registration(&id(10)).is_none());
        assert!(store.registration(&id(11)).is_none());
        assert!(store.registration(&id(12)).is_some());
        assert!(store.registration(&id(15)).is_some());
        assert!(store.take_erased().is_empty());
    }

    #[test]
    fn a_flood_of_registrations_blocks_no_upload_and_ends_at_its_life() {
        let mut store = ChunkStore::new(64 * CHUNK_BYTES);
        let chunk = alloc::vec![6u8; CHUNK_SIZE];

        // Registrations that never send bytes fill the store.
        for i in 0..64 {
            store
                .register(id(i), Class::Attachment, creds(2), [8; 32], [7; 32], 0)
                .unwrap();
        }
        assert_eq!(store.free(), 0);

        // ATT-200: an honest registration takes the place of the oldest
        // one, and its bytes go in.
        store
            .register(id(100), Class::Attachment, creds(1), [9; 32], [7; 32], 10)
            .unwrap();
        assert!(store.registration(&id(0)).is_none());
        store.put(id(100), &chunk, 20).unwrap();

        // ATT-181: the flood leaves at CHUNK_PENDING_TTL, and not at
        // CHUNK_TTL.
        assert_eq!(store.sweep(CHUNK_PENDING_TTL - 1), 0);
        assert_eq!(store.sweep(CHUNK_PENDING_TTL), 63);
        assert_eq!(store.held_count(), 1);
        assert_eq!(store.free(), 63 * CHUNK_BYTES);
    }

    #[test]
    fn a_store_at_its_trim_target_takes_a_registration_in_place_of_the_oldest() {
        // The held chunks are at the trim target of ATT-201, and the
        // registrations fill the share that is left.
        let mut store = ChunkStore::new(64 * CHUNK_BYTES);
        let chunk = alloc::vec![8u8; CHUNK_SIZE];
        for i in 0..56 {
            store
                .register(id(i), Class::Attachment, creds(1), [9; 32], [7; 32], 0)
                .unwrap();
            store.put(id(i), &chunk, u64::from(i)).unwrap();
        }
        for i in 100..108 {
            store
                .register(id(i), Class::Attachment, creds(2), [8; 32], [7; 32], 60)
                .unwrap();
        }
        assert_eq!(store.free(), 0);
        assert!(!store.over_target());

        // ATT-200: a new registration takes the place of the oldest one,
        // and no chunk leaves.
        store
            .register(id(200), Class::Attachment, creds(3), [7; 32], [7; 32], 70)
            .unwrap();
        assert!(store.registration(&id(100)).is_none());
        assert!(store.registration(&id(200)).is_some());
        assert_eq!(store.held_count(), 56);
        assert!(store.take_erased().is_empty());
    }

    #[test]
    fn a_store_below_the_target_trims_a_flood_of_bytes() {
        // ATT-201: a store smaller than CHUNK_STORE_TARGET trims at seven
        // eighths of its size.
        let mut store = ChunkStore::new(64 * CHUNK_BYTES);
        let chunk = alloc::vec![7u8; CHUNK_SIZE];
        for i in 0..64 {
            store
                .register(id(i), Class::Attachment, creds(2), [8; 32], [7; 32], 0)
                .unwrap();
            store.put(id(i), &chunk, u64::from(i)).unwrap();
        }
        assert_eq!(
            store.register(id(100), Class::Attachment, creds(1), [9; 32], [7; 32], 70),
            Err(Reject::Busy)
        );

        // ATT-168: the oldest renewals leave, and the store takes new
        // registrations again.
        assert!(store.over_target());
        assert_eq!(store.trim(), 8);
        assert!(store.credentials(&id(7)).is_none());
        assert!(store.credentials(&id(8)).is_some());
        store
            .register(id(100), Class::Attachment, creds(1), [9; 32], [7; 32], 70)
            .unwrap();
    }

    #[test]
    fn the_egress_day_and_the_fetch_hour_follow_the_utc_clock() {
        let mut store = ChunkStore::new(u64::MAX);
        let chunk = alloc::vec![6u8; CHUNK_SIZE];
        // The `CPUT` comes 10 s before midnight UTC.
        let late = 5 * 86_400 - 10;
        store
            .register([1; 32], Class::Attachment, creds(1), [9; 32], [7; 32], late)
            .unwrap();
        store.put([1; 32], &chunk, late).unwrap();
        store.get(&[1; 32], late).unwrap();
        store.egress_bytes = CHUNK_EGRESS_BUDGET_DAY;
        assert_eq!(store.get(&[1; 32], late + 9), Err(Reject::Busy));

        // The budget starts again at midnight, and not 24 h after the
        // first fetch.
        store.get(&[1; 32], late + 10).unwrap();
        assert_eq!(store.egress_bytes, CHUNK_BYTES);
        store.egress_bytes = CHUNK_EGRESS_BUDGET_DAY;
        assert_eq!(store.get(&[1; 32], late + 86_400), Err(Reject::Busy));
        store.egress_bytes = 0;

        // The rate of one chunk starts again at each hour of the clock.
        let hour = 5 * 86_400 + 7_200;
        for _ in 0..CHUNK_FETCH_RATE {
            store.get(&[1; 32], hour - 1).unwrap();
        }
        assert_eq!(store.get(&[1; 32], hour - 1), Err(Reject::Limit));
        store.get(&[1; 32], hour).unwrap();
    }
}
