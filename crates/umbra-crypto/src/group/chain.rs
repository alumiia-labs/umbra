//! The epoch secret, the slot chain, and the content-record AEAD of Part 11
//! §11.3.1 and §11.3.
//!
//! The chain is one-way: a party that holds the key of one slot derives
//! every later slot of the epoch and no earlier one. Thus a joiner reads
//! nothing before its join slot, and a device that keeps the key of the
//! oldest slot in its window holds no key for the slots before it.

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use rand_core::TryCryptoRng;
use sha3::Sha3_256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::{labels, secret::Secret, Error};

/// The length of the AEAD tag on a content record.
pub const RECORD_TAG_LEN: usize = 16;

/// `K_e`, the secret of one group epoch.
pub struct EpochSecret(Secret<32>);

/// The reader and writer credentials of one epoch (`GRP-222`).
pub struct Credentials {
    read: StaticSecret,
    write: StaticSecret,
}

/// The key of one slot, with its epoch and its slot index.
///
/// A device stores one of these for each group: the oldest slot of its
/// window. [`ChainState::advance`] moves it forward and drops the old key.
pub struct ChainState {
    epoch: u32,
    slot: u32,
    key: Secret<32>,
}

impl EpochSecret {
    /// Wraps a secret that a slot payload carried.
    pub const fn from_secret(secret: Secret<32>) -> Self {
        Self(secret)
    }

    /// Draws a fresh secret (`GRP-220`).
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut bytes = Secret::<32>::zeroed();
        rng.try_fill_bytes(bytes.expose_mut())
            .map_err(|_| Error::Rng)?;
        Ok(Self(bytes))
    }

    /// Wraps a secret that an epoch-key slot delivered.
    pub const fn new(secret: Secret<32>) -> Self {
        Self(secret)
    }

    /// The bytes, for the slot payload that carries them to a member.
    pub fn expose(&self) -> &Secret<32> {
        &self.0
    }

    /// `K_{e,t_e}`, the key of the start slot of epoch `epoch`.
    pub fn start(&self, group_id: &[u8; 32], epoch: u32, start_slot: u32) -> ChainState {
        let kdf = Hkdf::<Sha3_256>::new(None, self.0.expose());
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand_multi_info(
            &[
                labels::GROUP_SLOT,
                group_id,
                &epoch.to_be_bytes(),
                &start_slot.to_be_bytes(),
            ],
            key.expose_mut(),
        );
        ChainState {
            epoch,
            slot: start_slot,
            key,
        }
    }

    /// `read_sk_e` and `write_sk_e`, the queue credentials of the epoch.
    pub fn credentials(&self) -> Credentials {
        let kdf = Hkdf::<Sha3_256>::new(None, self.0.expose());
        let mut read = Secret::<32>::zeroed();
        let mut write = Secret::<32>::zeroed();
        let _ = kdf.expand(labels::GROUP_READ, read.expose_mut());
        let _ = kdf.expand(labels::GROUP_WRITE, write.expose_mut());
        // StaticSecret clamps the scalar as RFC 7748 §5 states.
        Credentials {
            read: StaticSecret::from(*read.expose()),
            write: StaticSecret::from(*write.expose()),
        }
    }
}

impl Credentials {
    /// The reader private key.
    pub fn read(&self) -> &StaticSecret {
        &self.read
    }

    /// The writer private key.
    pub fn write(&self) -> &StaticSecret {
        &self.write
    }

    /// `read_pk_e`, as `GKEY` carries it.
    pub fn read_public(&self) -> [u8; 32] {
        *XPublic::from(&self.read).as_bytes()
    }

    /// `write_pk_e`, as `GKEY` carries it.
    pub fn write_public(&self) -> [u8; 32] {
        *XPublic::from(&self.write).as_bytes()
    }
}

fn next_slot_key(key: &Secret<32>) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(None, key.expose());
    let mut next = Secret::<32>::zeroed();
    let _ = kdf.expand(labels::GROUP_SLOT_NEXT, next.expose_mut());
    next
}

fn record_key_of(key: &Secret<32>) -> Secret<32> {
    let kdf = Hkdf::<Sha3_256>::new(None, key.expose());
    let mut out = Secret::<32>::zeroed();
    let _ = kdf.expand(labels::GROUP_RECORD_KEY, out.expose_mut());
    out
}

impl ChainState {
    /// The epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The slot whose key this state holds.
    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// A chain from a slot key that an admit handed over: `K_{e,slot}`
    /// (`GRP-312`, `GRP-313`).
    pub const fn from_slot_key(epoch: u32, slot: u32, key: Secret<32>) -> Self {
        ChainState { epoch, slot, key }
    }

    /// `K_{e,slot}` itself, for an admit; the slot must be at or after the
    /// one this state holds.
    pub fn slot_key(&self, slot: u32) -> Result<Secret<32>, Error> {
        if slot < self.slot {
            return Err(Error::Group);
        }
        let mut key = Secret::new(*self.key.expose());
        let mut at = self.slot;
        while at < slot {
            key = next_slot_key(&key);
            at = at.saturating_add(1);
        }
        Ok(key)
    }

    /// Moves the state to `slot` and drops the keys before it (`GRP-227`).
    ///
    /// The chain runs forward only, thus a slot before the current one is an
    /// error.
    pub fn advance(&mut self, slot: u32) -> Result<(), Error> {
        if slot < self.slot {
            return Err(Error::Group);
        }
        while self.slot < slot {
            self.key = next_slot_key(&self.key);
            self.slot = self.slot.saturating_add(1);
        }
        Ok(())
    }

    /// `K_rec(e, t)` for a slot at or after the stored one.
    ///
    /// The stored key does not move; a receiver derives forward for one
    /// record and keeps its window where it is.
    pub fn record_key(&self, slot: u32) -> Result<Secret<32>, Error> {
        if slot < self.slot {
            return Err(Error::Group);
        }
        let mut key = Secret::new(*self.key.expose());
        let mut at = self.slot;
        while at < slot {
            key = next_slot_key(&key);
            at = at.saturating_add(1);
        }
        Ok(record_key_of(&key))
    }
}

fn associated_data(group_id: &[u8; 32], epoch: u32, slot: u32) -> [u8; 61] {
    let mut ad = [0u8; 61];
    let (label, rest) = ad.split_at_mut(labels::GROUP_RECORD.len());
    label.copy_from_slice(labels::GROUP_RECORD);
    let (group, rest) = rest.split_at_mut(32);
    group.copy_from_slice(group_id);
    let (e, t) = rest.split_at_mut(4);
    e.copy_from_slice(&epoch.to_be_bytes());
    t.copy_from_slice(&slot.to_be_bytes());
    ad
}

/// Seals a content record in place under `K_rec(e, t)` (`GRP-214`).
///
/// `buf` holds the `ContentPlain` bytes and receives the ciphertext. The
/// caller puts the returned tag after it.
pub fn seal_record(
    record_key: &Secret<32>,
    nonce: &[u8; 12],
    group_id: &[u8; 32],
    epoch: u32,
    slot: u32,
    buf: &mut [u8],
) -> Result<[u8; RECORD_TAG_LEN], Error> {
    let ad = associated_data(group_id, epoch, slot);
    let tag = ChaCha20Poly1305::new(record_key.expose().into())
        .encrypt_inout_detached(&Nonce::from(*nonce), &ad, buf.into())
        .map_err(|_| Error::Group)?;
    Ok(tag.into())
}

/// Opens a content record in place. One error covers every cause
/// (`GRP-251`).
pub fn open_record(
    record_key: &Secret<32>,
    nonce: &[u8; 12],
    group_id: &[u8; 32],
    epoch: u32,
    slot: u32,
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag: [u8; RECORD_TAG_LEN] = tag.try_into().map_err(|_| Error::Group)?;
    let ad = associated_data(group_id, epoch, slot);
    ChaCha20Poly1305::new(record_key.expose().into())
        .decrypt_inout_detached(&Nonce::from(*nonce), &ad, buf.into(), &Tag::from(tag))
        .map_err(|_| Error::Group)
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

    const GROUP: [u8; 32] = [0x67; 32];

    fn secret() -> EpochSecret {
        EpochSecret::new(Secret::new([0x6b; 32]))
    }

    #[test]
    fn the_chain_runs_forward_only() {
        let mut state = secret().start(&GROUP, 1, 100);
        let key_at_103 = state.record_key(103).unwrap();
        state.advance(102).unwrap();
        assert_eq!(state.slot(), 102);
        assert_eq!(state.record_key(103).unwrap().expose(), key_at_103.expose());
        assert!(state.record_key(101).is_err());
        assert!(state.advance(101).is_err());
        assert!(state.advance(102).is_ok());
    }

    #[test]
    fn the_start_slot_and_the_epoch_separate_the_chain() {
        let a = secret().start(&GROUP, 1, 100);
        let b = secret().start(&GROUP, 1, 101);
        let c = secret().start(&GROUP, 2, 100);
        assert_ne!(
            a.record_key(101).unwrap().expose(),
            b.record_key(101).unwrap().expose()
        );
        assert_ne!(
            a.record_key(100).unwrap().expose(),
            c.record_key(100).unwrap().expose()
        );
    }

    #[test]
    fn credentials_differ_and_come_from_the_secret() {
        let one = secret().credentials();
        let two = secret().credentials();
        assert_eq!(one.read_public(), two.read_public());
        assert_ne!(one.read_public(), one.write_public());
        assert_eq!(one.read_public(), *XPublic::from(one.read()).as_bytes());
    }

    #[test]
    fn a_record_opens_under_its_own_slot_only() {
        let state = secret().start(&GROUP, 1, 100);
        let key = state.record_key(102).unwrap();
        let nonce = [9u8; 12];
        let mut buf = *b"a group record";
        let tag = seal_record(&key, &nonce, &GROUP, 1, 102, &mut buf).unwrap();
        assert_ne!(&buf, b"a group record");

        let mut wrong = buf;
        assert!(open_record(&key, &nonce, &GROUP, 1, 103, &mut wrong, &tag).is_err());
        let mut wrong = buf;
        assert!(open_record(&key, &nonce, &[0x68; 32], 1, 102, &mut wrong, &tag).is_err());
        let mut wrong = buf;
        assert!(open_record(&key, &nonce, &GROUP, 1, 102, &mut wrong, &tag[..15]).is_err());

        open_record(&key, &nonce, &GROUP, 1, 102, &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"a group record");
    }

    #[test]
    fn a_generated_secret_is_fresh() {
        let mut rng = crate::test_rng::TestRng::new(b"group");
        let a = EpochSecret::generate(&mut rng).unwrap();
        let b = EpochSecret::generate(&mut rng).unwrap();
        assert_ne!(a.expose().expose(), b.expose().expose());
    }
}
