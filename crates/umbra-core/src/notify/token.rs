//! The token blinding of Part 8 §8.2.1, the handle groups, the rotation
//! of §8.2.5, and the Notification Delivery Relay that holds
//! `(handle, ct_token)` and decrypts a token transiently at the dispatch.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{aead, rand_core::TryCryptoRng, secret::Secret};

use super::{HANDLE_LEN, MAX_QUEUES_PER_HANDLE, ROTATE_INTERVAL};
use crate::Error;

/// The class of the queues under one handle. A handle holds one class
/// (`NTF-044`, `NTF-070`, `NTF-091`, `NTF-092`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleClass {
    /// Pairwise queues.
    Pairwise,
    /// A rendezvous queue, one for each handle (`NTF-043`).
    Rendezvous,
    /// The notify queues of groups and communities.
    Digest,
}

/// One handle group: a handle, its token key, and its queues.
pub struct HandleGroup {
    /// The handle the NDR knows.
    pub handle: [u8; HANDLE_LEN],
    /// The token key the queue relay holds and the NDR receives at each
    /// dispatch.
    pub k_tok: Secret<32>,
    /// The class.
    pub class: HandleClass,
    /// The queues, at most `MAX_QUEUES_PER_HANDLE`.
    pub queues: Vec<[u8; 32]>,
    /// When the group was made or last rotated.
    pub rotated_at: u64,
}

impl HandleGroup {
    fn new<R: TryCryptoRng + ?Sized>(
        class: HandleClass,
        queues: Vec<[u8; 32]>,
        now: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut handle = [0u8; HANDLE_LEN];
        rng.try_fill_bytes(&mut handle)
            .map_err(|_| Error::Unverified)?;
        let mut k_tok = Secret::<32>::zeroed();
        rng.try_fill_bytes(k_tok.expose_mut())
            .map_err(|_| Error::Unverified)?;
        Ok(HandleGroup {
            handle,
            k_tok,
            class,
            queues,
            rotated_at: now,
        })
    }

    /// `ct_token = XChaCha20-Poly1305(k_tok, nonce, push_token)`: the
    /// registration the device sends to the NDR.
    pub fn registration(&self, push_token: &[u8], nonce: [u8; 24]) -> Result<Registration, Error> {
        let mut ct = push_token.to_vec();
        let tag = aead::seal(&self.k_tok, &nonce, &self.handle, &mut ct)?;
        ct.extend_from_slice(&tag);
        Ok(Registration {
            handle: self.handle,
            nonce,
            ct_token: ct,
        })
    }

    /// Whether the rotation of `NTF-007` is due at `now`.
    pub fn rotation_due(&self, now: u64) -> bool {
        now.saturating_sub(self.rotated_at) >= ROTATE_INTERVAL
    }
}

/// A registration at the NDR: the handle and the sealed push token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The handle.
    pub handle: [u8; HANDLE_LEN],
    /// The nonce of the seal.
    pub nonce: [u8; 24],
    /// The sealed push token with its tag.
    pub ct_token: Vec<u8>,
}

/// The handle groups of one device at one queue relay.
pub struct HandleSet {
    groups: Vec<HandleGroup>,
}

impl HandleSet {
    /// Divides the queues of each class into groups of at most
    /// `MAX_QUEUES_PER_HANDLE`, each with a fresh handle and key
    /// (`NTF-031` to `NTF-033`). A rendezvous queue gets a group of its own.
    pub fn assign<R: TryCryptoRng + ?Sized>(
        pairwise: &[[u8; 32]],
        rendezvous: &[[u8; 32]],
        digest: &[[u8; 32]],
        now: u64,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut groups = Vec::new();
        for chunk in pairwise.chunks(MAX_QUEUES_PER_HANDLE) {
            groups.push(HandleGroup::new(
                HandleClass::Pairwise,
                chunk.to_vec(),
                now,
                rng,
            )?);
        }
        for queue in rendezvous {
            groups.push(HandleGroup::new(
                HandleClass::Rendezvous,
                alloc::vec![*queue],
                now,
                rng,
            )?);
        }
        for chunk in digest.chunks(MAX_QUEUES_PER_HANDLE) {
            groups.push(HandleGroup::new(
                HandleClass::Digest,
                chunk.to_vec(),
                now,
                rng,
            )?);
        }
        Ok(HandleSet { groups })
    }

    /// The groups.
    pub fn groups(&self) -> &[HandleGroup] {
        &self.groups
    }

    /// The group that holds `queue`.
    pub fn group_of(&self, queue: &[u8; 32]) -> Option<&HandleGroup> {
        self.groups.iter().find(|g| g.queues.contains(queue))
    }

    /// The one group to rotate in this session, if any is due: the oldest
    /// due group, and never two in one session (`NTF-080`, `NTF-081`).
    pub fn rotation_candidate(&self, now: u64) -> Option<usize> {
        self.groups
            .iter()
            .enumerate()
            .filter(|(_, g)| g.rotation_due(now))
            .min_by_key(|(_, g)| g.rotated_at)
            .map(|(i, _)| i)
    }

    /// Rotates group `index` with a fresh handle and key, and returns the
    /// old handle for the NDR to drop.
    pub fn rotate<R: TryCryptoRng + ?Sized>(
        &mut self,
        index: usize,
        now: u64,
        rng: &mut R,
    ) -> Result<[u8; HANDLE_LEN], Error> {
        let old = self.groups.get(index).ok_or(Error::Malformed)?;
        let fresh = HandleGroup::new(old.class, old.queues.clone(), now, rng)?;
        let old_handle = old.handle;
        if let Some(slot) = self.groups.get_mut(index) {
            *slot = fresh;
        }
        Ok(old_handle)
    }

    /// Marks every group due, at a change of the contact set (`NTF-008`,
    /// `NTF-034`).
    pub fn contact_set_changed(&mut self) {
        for g in &mut self.groups {
            g.rotated_at = 0;
        }
    }
}

/// The Notification Delivery Relay: the registrations, and the dispatch
/// that decrypts a token and keeps nothing.
#[derive(Default)]
pub struct Ndr {
    registrations: BTreeMap<[u8; HANDLE_LEN], Registration>,
}

impl Ndr {
    /// Stores a registration.
    pub fn register(&mut self, registration: Registration) {
        self.registrations.insert(registration.handle, registration);
    }

    /// Drops a registration.
    pub fn unregister(&mut self, handle: &[u8; HANDLE_LEN]) {
        self.registrations.remove(handle);
    }

    /// The registrations held.
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }

    /// Decrypts the push token of `handle` under the `k_tok` that the queue
    /// relay posted, for one dispatch. The key is a borrowed secret that
    /// the caller drops at once (§8.2.1).
    pub fn dispatch(
        &self,
        handle: &[u8; HANDLE_LEN],
        k_tok: &Secret<32>,
    ) -> Result<Secret<64>, Error> {
        let registration = self.registrations.get(handle).ok_or(Error::NoPath)?;
        if registration.ct_token.len() < aead::TAG_LEN
            || registration.ct_token.len() > 64 + aead::TAG_LEN
        {
            return Err(Error::Malformed);
        }
        let split = registration.ct_token.len().saturating_sub(aead::TAG_LEN);
        let mut token = Secret::<64>::zeroed();
        let body = registration.ct_token.get(..split).ok_or(Error::Malformed)?;
        let tag = registration.ct_token.get(split..).ok_or(Error::Malformed)?;
        let slot = token
            .expose_mut()
            .get_mut(..split)
            .ok_or(Error::Malformed)?;
        slot.copy_from_slice(body);
        aead::open(k_tok, &registration.nonce, handle, slot, tag)?;
        Ok(token)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;

    #[test]
    fn queues_divide_into_handle_groups_and_rotate_one_at_a_time() {
        let mut rng = Rng(1);
        let pairwise: Vec<[u8; 32]> = (0..11u8).map(|i| [i; 32]).collect();
        let mut set =
            HandleSet::assign(&pairwise, &[[100; 32]], &[[200; 32]], 0, &mut rng).unwrap();
        assert_eq!(set.groups().len(), 4);
        assert_eq!(set.groups()[0].queues.len(), MAX_QUEUES_PER_HANDLE);
        assert_eq!(set.groups()[1].queues.len(), 3);
        assert_eq!(set.groups()[2].class, HandleClass::Rendezvous);
        assert_eq!(set.groups()[3].class, HandleClass::Digest);
        assert_ne!(set.groups()[0].handle, set.groups()[1].handle);
        assert_eq!(
            set.group_of(&[9; 32]).unwrap().handle,
            set.groups()[1].handle
        );
        assert!(set.rotation_candidate(ROTATE_INTERVAL - 1).is_none());
        assert_eq!(set.rotation_candidate(ROTATE_INTERVAL), Some(0));
        let old = set.rotate(0, ROTATE_INTERVAL, &mut rng).unwrap();
        assert_ne!(set.groups()[0].handle, old);
        assert_eq!(set.rotation_candidate(ROTATE_INTERVAL), Some(1));
        set.contact_set_changed();
        assert_eq!(set.rotation_candidate(ROTATE_INTERVAL + 1), Some(0));
    }

    #[test]
    fn the_ndr_holds_ciphertext_and_decrypts_at_the_dispatch_only() {
        let mut rng = Rng(2);
        let set = HandleSet::assign(&[[1; 32]], &[], &[], 0, &mut rng).unwrap();
        let group = &set.groups()[0];
        let registration = group.registration(b"fcm:token-123", [4; 24]).unwrap();
        let mut ndr = Ndr::default();
        ndr.register(registration.clone());
        assert_eq!(ndr.len(), 1);
        let token = ndr.dispatch(&group.handle, &group.k_tok).unwrap();
        assert_eq!(&token.expose()[..13], b"fcm:token-123");
        assert!(ndr.dispatch(&group.handle, &Secret::new([0; 32])).is_err());
        assert!(ndr.dispatch(&[0; 16], &group.k_tok).is_err());
        ndr.unregister(&group.handle);
        assert!(ndr.is_empty());
    }
}
