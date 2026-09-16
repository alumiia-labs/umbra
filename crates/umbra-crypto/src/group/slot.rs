//! The epoch-key slot of Part 11 §11.4.2.
//!
//! A slot carries the secret of a new epoch to one member under that
//! member's `UMBRA-KEM` key. It has no slot-key layer above it, because the
//! member that missed the previous epoch is the one that needs it. The
//! nonce is zero, because `K_slot` is fresh for each slot by construction.

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha3::Sha3_256;

use crate::{
    kem::{self, Ciphertext, KeyPair, PublicKey, SharedSecret, CIPHERTEXT_LEN},
    labels,
    secret::Secret,
    Error,
};

/// The length of the AEAD tag on a slot.
pub const SLOT_TAG_LEN: usize = 16;

/// The length of a sealed slot after its `index` field, for a payload of
/// `payload_len` bytes.
pub const fn sealed_len(payload_len: usize) -> usize {
    CIPHERTEXT_LEN + payload_len + SLOT_TAG_LEN
}

fn associated_data(group_id: &[u8; 32], epoch: u32, index: u16) -> [u8; 63] {
    let mut ad = [0u8; 63];
    let (label, rest) = ad.split_at_mut(labels::GROUP_EPOCH_SLOT.len());
    label.copy_from_slice(labels::GROUP_EPOCH_SLOT);
    let (group, rest) = rest.split_at_mut(32);
    group.copy_from_slice(group_id);
    let (e, i) = rest.split_at_mut(4);
    e.copy_from_slice(&epoch.to_be_bytes());
    i.copy_from_slice(&index.to_be_bytes());
    ad
}

fn slot_key(shared: &SharedSecret, ad: &[u8; 63]) -> Secret<32> {
    // K_slot and ad share one byte string, thus one buffer serves both.
    let kdf = Hkdf::<Sha3_256>::new(None, shared.expose());
    let mut key = Secret::<32>::zeroed();
    let _ = kdf.expand(ad, key.expose_mut());
    key
}

/// Seals `payload` to the member at `index` with a fresh encapsulation
/// (`GRP-279`).
///
/// `out` receives `kem_ct || ct || tag`, and the call returns that length.
pub fn seal<R: CryptoRng + ?Sized>(
    member: &PublicKey,
    group_id: &[u8; 32],
    epoch: u32,
    index: u16,
    payload: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<usize, Error> {
    let (ct, shared) = kem::encapsulate(member, rng);
    seal_with(&ct, &shared, group_id, epoch, index, payload, out)
}

/// Seals `payload` under an encapsulation the caller made. A protocol path
/// uses [`seal`]; a test vector uses this call with deterministic coins.
pub fn seal_with(
    ct: &Ciphertext,
    shared: &SharedSecret,
    group_id: &[u8; 32],
    epoch: u32,
    index: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let total = sealed_len(payload.len());
    let out = out.get_mut(..total).ok_or(Error::Length)?;
    let (kem_ct, rest) = out.split_at_mut(CIPHERTEXT_LEN);
    kem_ct.copy_from_slice(ct.as_bytes());
    let (body, tag_out) = rest.split_at_mut(payload.len());
    body.copy_from_slice(payload);

    let ad = associated_data(group_id, epoch, index);
    let key = slot_key(shared, &ad);
    let tag = ChaCha20Poly1305::new(key.expose().into())
        .encrypt_inout_detached(&Nonce::default(), &ad, body.into())
        .map_err(|_| Error::Group)?;
    tag_out.copy_from_slice(&tag);
    Ok(total)
}

/// Opens the slot at `index` with the member's own key and writes the
/// payload into `out`. One error covers every cause.
pub fn open(
    member: &KeyPair,
    group_id: &[u8; 32],
    epoch: u32,
    index: u16,
    sealed: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let payload_len = sealed
        .len()
        .checked_sub(CIPHERTEXT_LEN + SLOT_TAG_LEN)
        .ok_or(Error::Length)?;
    let (kem_ct, rest) = sealed.split_at(CIPHERTEXT_LEN);
    let (body, tag) = rest.split_at(payload_len);
    let out = out.get_mut(..payload_len).ok_or(Error::Length)?;
    out.copy_from_slice(body);
    let tag: [u8; SLOT_TAG_LEN] = tag.try_into().map_err(|_| Error::Length)?;

    let ct = Ciphertext::from_bytes(kem_ct).map_err(|_| Error::Group)?;
    let shared = member.decapsulate(&ct).map_err(|_| Error::Group)?;
    let ad = associated_data(group_id, epoch, index);
    let key = slot_key(&shared, &ad);
    ChaCha20Poly1305::new(key.expose().into())
        .decrypt_inout_detached(&Nonce::default(), &ad, out.into(), &Tag::from(tag))
        .map_err(|_| Error::Group)?;
    Ok(payload_len)
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
    use crate::{group::MemberKeys, test_rng::TestRng};

    const GROUP: [u8; 32] = [0x67; 32];

    #[test]
    fn a_slot_opens_at_its_member_and_index_only() {
        let mut rng = TestRng::new(b"slot");
        let member = MemberKeys::from_seed(&Secret::new([2; 32]));
        let other = MemberKeys::from_seed(&Secret::new([3; 32]));
        let payload = [0x55u8; 47];
        let mut sealed = [0u8; sealed_len(47)];
        let n = seal(
            member.kem().public(),
            &GROUP,
            2,
            7,
            &payload,
            &mut rng,
            &mut sealed,
        )
        .unwrap();
        assert_eq!(n, sealed.len());

        let mut out = [0u8; 47];
        assert_eq!(
            open(member.kem(), &GROUP, 2, 7, &sealed, &mut out).unwrap(),
            47
        );
        assert_eq!(out, payload);
        assert!(open(other.kem(), &GROUP, 2, 7, &sealed, &mut out).is_err());
        assert!(open(member.kem(), &GROUP, 2, 8, &sealed, &mut out).is_err());
        assert!(open(member.kem(), &GROUP, 3, 7, &sealed, &mut out).is_err());
        assert!(open(member.kem(), &[0x68; 32], 2, 7, &sealed, &mut out).is_err());
        assert!(open(
            member.kem(),
            &GROUP,
            2,
            7,
            &sealed[..sealed.len() - 1],
            &mut out
        )
        .is_err());
    }

    #[test]
    fn a_short_output_buffer_is_refused() {
        let mut rng = TestRng::new(b"slot");
        let member = MemberKeys::from_seed(&Secret::new([2; 32]));
        let mut sealed = [0u8; sealed_len(47) - 1];
        assert_eq!(
            seal(
                member.kem().public(),
                &GROUP,
                2,
                7,
                &[0u8; 47],
                &mut rng,
                &mut sealed
            ),
            Err(Error::Length)
        );
    }
}
