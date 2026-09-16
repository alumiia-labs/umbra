//! The pair key and the two tags of Part 11 §11.3.3 and §11.4.2.
//!
//! `K_ij` is symmetric in the two members, thus each pair derives it once
//! and caches it for the life of the roster entries. A tag is the first
//! twelve bytes of an HMAC under that key, thus the receiver can forge a tag
//! to itself and no other member can.

use hkdf::Hkdf;
use hmac::{digest::KeyInit, Hmac, Mac};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::{labels, secret::Secret, Error};

use super::TAG_LEN;

/// `K_ij`, the key that two members of one group share.
pub struct PairKey(Secret<32>);

/// The fields that a content-record tag covers (`GRP-238`).
pub struct RecordTag<'a> {
    /// The group.
    pub group_id: &'a [u8; 32],
    /// The group epoch `e`.
    pub epoch: u32,
    /// The slot index `t`.
    pub slot: u32,
    /// The member index of the sender.
    pub sender_index: u16,
    /// The per-member counter in the epoch.
    pub counter: u32,
    /// The roster epoch that gives the tag order.
    pub roster_epoch: u32,
    /// `SHA3-256(app)`, from [`app_hash`].
    pub app_hash: &'a [u8; 32],
}

/// The fields that an epoch-key slot tag covers (`GRP-286`).
pub struct EpochTag<'a> {
    /// The group.
    pub group_id: &'a [u8; 32],
    /// The epoch that the slot delivers.
    pub epoch: u32,
    /// `t_e`, the start slot of that epoch.
    pub start_slot: u32,
    /// The roster epoch of the epoch-key record.
    pub roster_epoch: u32,
    /// `k_e`, the epoch secret inside the slot.
    pub epoch_secret: &'a Secret<32>,
}

/// `SHA3-256(app)`, the digest of the application record that a tag covers.
pub fn app_hash(app: &[u8]) -> [u8; 32] {
    Sha3_256::digest(app).into()
}

impl PairKey {
    pub(crate) fn derive(
        own_secret: &StaticSecret,
        own_public: &[u8; 32],
        peer_public: &[u8; 32],
        group_id: &[u8; 32],
    ) -> Result<Self, Error> {
        let shared = own_secret.diffie_hellman(&XPublic::from(*peer_public));
        if !shared.was_contributory() {
            return Err(Error::Key);
        }
        // Both members must order the two keys the same way, thus the order
        // comes from the bytes and not from the roles.
        let (low, high) = if own_public <= peer_public {
            (own_public, peer_public)
        } else {
            (peer_public, own_public)
        };
        let kdf = Hkdf::<Sha3_256>::new(None, shared.as_bytes());
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand_multi_info(&[labels::GROUP_TAG, group_id, low, high], key.expose_mut());
        Ok(Self(key))
    }

    fn mac(&self) -> Hmac<Sha3_256> {
        // A 32-byte key is inside the HMAC key bound, thus this cannot fail.
        Hmac::<Sha3_256>::new_from_slice(self.0.expose())
            .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()))
    }

    fn truncate(mac: Hmac<Sha3_256>) -> [u8; TAG_LEN] {
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(full.get(..TAG_LEN).unwrap_or(&[0u8; TAG_LEN]));
        tag
    }

    /// The tag of a content record to the peer.
    pub fn record_tag(&self, fields: &RecordTag<'_>) -> [u8; TAG_LEN] {
        let mut mac = self.mac();
        mac.update(labels::GROUP_TAG);
        mac.update(fields.group_id);
        mac.update(&fields.epoch.to_be_bytes());
        mac.update(&fields.slot.to_be_bytes());
        mac.update(&fields.sender_index.to_be_bytes());
        mac.update(&fields.counter.to_be_bytes());
        mac.update(&fields.roster_epoch.to_be_bytes());
        mac.update(fields.app_hash);
        Self::truncate(mac)
    }

    /// Verifies the tag of a content record (`GRP-240`, `GRP-241`).
    pub fn verify_record_tag(&self, fields: &RecordTag<'_>, tag: &[u8]) -> Result<(), Error> {
        Self::check(&self.record_tag(fields), tag)
    }

    /// The tag inside an epoch-key slot, from the rotator to the peer.
    pub fn epoch_tag(&self, fields: &EpochTag<'_>) -> [u8; TAG_LEN] {
        let mut mac = self.mac();
        mac.update(labels::GROUP_EPOCH_TAG);
        mac.update(fields.group_id);
        mac.update(&fields.epoch.to_be_bytes());
        mac.update(&fields.start_slot.to_be_bytes());
        mac.update(&fields.roster_epoch.to_be_bytes());
        mac.update(fields.epoch_secret.expose());
        Self::truncate(mac)
    }

    /// Verifies the tag inside an epoch-key slot (`GRP-287`).
    pub fn verify_epoch_tag(&self, fields: &EpochTag<'_>, tag: &[u8]) -> Result<(), Error> {
        Self::check(&self.epoch_tag(fields), tag)
    }

    fn check(expected: &[u8; TAG_LEN], tag: &[u8]) -> Result<(), Error> {
        if tag.len() == TAG_LEN && bool::from(expected.ct_eq(tag)) {
            Ok(())
        } else {
            Err(Error::Group)
        }
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
    use crate::group::MemberKeys;

    const GROUP: [u8; 32] = [0x67; 32];

    fn pair() -> (PairKey, PairKey) {
        let a = MemberKeys::from_seed(&Secret::new([1; 32]));
        let b = MemberKeys::from_seed(&Secret::new([2; 32]));
        (
            a.pair_key(&b.pair_public(), &GROUP).unwrap(),
            b.pair_key(&a.pair_public(), &GROUP).unwrap(),
        )
    }

    fn fields<'a>(hash: &'a [u8; 32]) -> RecordTag<'a> {
        RecordTag {
            group_id: &GROUP,
            epoch: 3,
            slot: 497_000,
            sender_index: 4,
            counter: 9,
            roster_epoch: 2,
            app_hash: hash,
        }
    }

    #[test]
    fn the_pair_key_is_symmetric() {
        let (ab, ba) = pair();
        let hash = app_hash(b"hi");
        assert_eq!(ab.record_tag(&fields(&hash)), ba.record_tag(&fields(&hash)));
        assert!(ba
            .verify_record_tag(&fields(&hash), &ab.record_tag(&fields(&hash)))
            .is_ok());
    }

    #[test]
    fn the_group_separates_the_pair_key() {
        let a = MemberKeys::from_seed(&Secret::new([1; 32]));
        let b = MemberKeys::from_seed(&Secret::new([2; 32]));
        let one = a.pair_key(&b.pair_public(), &GROUP).unwrap();
        let two = a.pair_key(&b.pair_public(), &[0x68; 32]).unwrap();
        let hash = app_hash(b"hi");
        assert_ne!(
            one.record_tag(&fields(&hash)),
            two.record_tag(&fields(&hash))
        );
    }

    #[test]
    fn every_field_binds_the_record_tag() {
        let (ab, _) = pair();
        let hash = app_hash(b"hi");
        let base = ab.record_tag(&fields(&hash));
        let mut f = fields(&hash);
        f.epoch += 1;
        assert_ne!(ab.record_tag(&f), base);
        let mut f = fields(&hash);
        f.slot += 1;
        assert_ne!(ab.record_tag(&f), base);
        let mut f = fields(&hash);
        f.sender_index += 1;
        assert_ne!(ab.record_tag(&f), base);
        let mut f = fields(&hash);
        f.counter += 1;
        assert_ne!(ab.record_tag(&f), base);
        let mut f = fields(&hash);
        f.roster_epoch += 1;
        assert_ne!(ab.record_tag(&f), base);
        let other = app_hash(b"ho");
        assert_ne!(ab.record_tag(&fields(&other)), base);
        assert!(ab.verify_record_tag(&fields(&hash), &base[..11]).is_err());
        let mut bad = base;
        bad[0] ^= 1;
        assert!(ab.verify_record_tag(&fields(&hash), &bad).is_err());
    }

    #[test]
    fn the_epoch_tag_binds_the_secret() {
        let (ab, ba) = pair();
        let k = Secret::new([5; 32]);
        let f = EpochTag {
            group_id: &GROUP,
            epoch: 2,
            start_slot: 497_001,
            roster_epoch: 1,
            epoch_secret: &k,
        };
        let tag = ab.epoch_tag(&f);
        assert!(ba.verify_epoch_tag(&f, &tag).is_ok());
        let other = Secret::new([6; 32]);
        let g = EpochTag {
            epoch_secret: &other,
            ..f
        };
        assert!(ba.verify_epoch_tag(&g, &tag).is_err());
    }
}
