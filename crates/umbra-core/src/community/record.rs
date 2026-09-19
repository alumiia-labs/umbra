//! The chain records of a community (Part 12 §12.4.1, §12.4.4): the post,
//! the stub, the checkpoint, and the operator removal.

use alloc::vec::Vec;

use umbra_crypto::{
    hash::sha3_256,
    labels,
    rand_core::TryCryptoRng,
    sign::{Signature, SigningKey, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    identity::AuthorIdentity, pseudonym_of, RecordType, MAX_POST_SIZE, NO_INDEX, SIG_INTERVAL,
    VERSION, WITHDRAW_MAX,
};
use crate::Error;

/// The header of a `CommunityPost`.
pub const POST_HEADER_LEN: usize = 46;
/// The length of a `PostStub`.
pub const STUB_LEN: usize = 70;
/// The length of a `Checkpoint`.
pub const CHECKPOINT_LEN: usize = 5_431;
/// The length of an `OperatorRemoval`.
pub const OPERATOR_REMOVAL_LEN: usize = 3_451;

/// Verifies an ML-DSA-65 signature from its wire bytes.
pub(crate) fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public_key)?;
    let signature = Signature::from_bytes(signature)?;
    Ok(key.verify(message, &signature)?)
}

fn header(r: &mut Reader<'_>, expected: RecordType) -> Result<(), Error> {
    if r.u8()? != VERSION || r.u8()? != expected as u8 {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// `SHA3-256(post_n)`, over the encoded `CommunityPost`.
pub fn post_hash(encoded_post: &[u8]) -> [u8; 32] {
    sha3_256(&[encoded_post])
}

/// The length of the community record at the front of `bytes`, from its
/// type and its count fields. A `PUB` carries one record and then an
/// `Admission`, and this length splits the two.
pub fn record_len(bytes: &[u8]) -> Result<usize, Error> {
    // The fields before the first count of a control object and of a
    // metadata record: the version, the type, `community_id`, the index,
    // the hash of the predecessor, `actor`, and `actor_pk`.
    const CHAINED: usize = 2 + 32 + 4 + 32 + 32 + VERIFYING_KEY_LEN;
    let byte_at = |at: usize| {
        bytes
            .get(at)
            .copied()
            .map(usize::from)
            .ok_or(Error::Malformed)
    };
    let u16_at = |at: usize| Ok::<usize, Error>(byte_at(at)? << 8 | byte_at(at.saturating_add(1))?);
    let len = match RecordType::of(bytes)? {
        RecordType::Post => {
            let body_len = (u16_at(42)? << 16) | u16_at(44)?;
            POST_HEADER_LEN.saturating_add(body_len)
        }
        RecordType::Stub => STUB_LEN,
        RecordType::Checkpoint => CHECKPOINT_LEN,
        RecordType::OperatorRemoval => OPERATOR_REMOVAL_LEN,
        RecordType::Report => 104usize.saturating_add(byte_at(103)?),
        RecordType::Roster => {
            let entries = byte_at(CHAINED)?.saturating_mul(1 + 32 + 1_216 + 129);
            let cosign_at = CHAINED.saturating_add(1).saturating_add(entries);
            let cosigns =
                byte_at(cosign_at)?.saturating_mul(32 + VERIFYING_KEY_LEN + SIGNATURE_LEN);
            cosign_at
                .saturating_add(1)
                .saturating_add(cosigns)
                .saturating_add(SIGNATURE_LEN)
        }
        RecordType::ModeratorSet => CHAINED
            .saturating_add(2)
            .saturating_add(u16_at(CHAINED)?.saturating_mul(32))
            .saturating_add(SIGNATURE_LEN),
        RecordType::ModerationEpoch => CHAINED
            .saturating_add(2)
            .saturating_add(byte_at(CHAINED.saturating_add(1))?.saturating_mul(37))
            .saturating_add(SIGNATURE_LEN),
        RecordType::Meta => {
            let body_len_at = CHAINED
                .saturating_add(1)
                .saturating_add(byte_at(CHAINED)?.saturating_mul(12))
                .saturating_add(1 + 12);
            body_len_at
                .saturating_add(2)
                .saturating_add(u16_at(body_len_at)?)
                .saturating_add(SIGNATURE_LEN)
        }
    };
    if len > bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(len)
}

/// A `CommunityPost`. It carries the pseudonym and no public key
/// (`COM-035`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommunityPost<'a> {
    /// The authoring pseudonym.
    pub pseudonym: [u8; 32],
    /// The position in the chain of that pseudonym.
    pub index: u32,
    /// The index that this post corrects, or `NO_INDEX`.
    pub amends: u32,
    /// The body, which starts with a `RichRecord` (`COM-158`).
    pub body: &'a [u8],
}

impl<'a> CommunityPost<'a> {
    /// The encoded length.
    pub fn len(&self) -> usize {
        POST_HEADER_LEN.saturating_add(self.body.len())
    }

    /// Whether the body is empty. Clippy asks for this beside `len`.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    fn check(&self) -> Result<(), Error> {
        // COM-101: an amendment names an earlier index of the same chain.
        if self.body.len() > MAX_POST_SIZE || self.index == NO_INDEX {
            return Err(Error::Malformed);
        }
        if self.amends != NO_INDEX && self.amends >= self.index {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Encodes the post.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut out = alloc::vec![0u8; self.len()];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(RecordType::Post as u8)?;
        w.put(&self.pseudonym)?;
        w.u32(self.index)?;
        w.u32(self.amends)?;
        w.u32(u32::try_from(self.body.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.body)?;
        Ok(out)
    }

    /// Reads a post.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        header(&mut r, RecordType::Post)?;
        let pseudonym = r.array()?;
        let index = r.u32()?;
        let amends = r.u32()?;
        let body_len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
        let body = r.take(body_len)?;
        r.finish()?;
        let post = CommunityPost {
            pseudonym,
            index,
            amends,
            body,
        };
        post.check()?;
        Ok(post)
    }
}

/// A `PostStub`, which a relay serves in place of a body that an artifact
/// names. It carries no reason (§12.4.4 rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostStub {
    /// The authoring pseudonym.
    pub pseudonym: [u8; 32],
    /// The position in the chain.
    pub index: u32,
    /// `SHA3-256(post_n)`.
    pub post_hash: [u8; 32],
}

impl PostStub {
    /// Encodes the stub.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; STUB_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(RecordType::Stub as u8)?;
        w.put(&self.pseudonym)?;
        w.u32(self.index)?;
        w.put(&self.post_hash)?;
        Ok(out)
    }

    /// Reads a stub.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        header(&mut r, RecordType::Stub)?;
        let stub = PostStub {
            pseudonym: r.array()?,
            index: r.u32()?,
            post_hash: r.array()?,
        };
        r.finish()?;
        Ok(stub)
    }
}

/// The `withdrawn` list of a checkpoint: strictly increasing indexes, then
/// a run of the sentinel (`COM-062`, `COM-063`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdrawn([u32; WITHDRAW_MAX]);

impl Withdrawn {
    /// A list that withdraws nothing.
    pub const NONE: Withdrawn = Withdrawn([NO_INDEX; WITHDRAW_MAX]);

    /// A list from up to `WITHDRAW_MAX` indexes, in any order.
    pub fn from_indexes(indexes: &[u32]) -> Result<Self, Error> {
        let mut sorted = indexes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() > WITHDRAW_MAX || sorted.contains(&NO_INDEX) {
            return Err(Error::Malformed);
        }
        let mut list = [NO_INDEX; WITHDRAW_MAX];
        for (slot, index) in list.iter_mut().zip(&sorted) {
            *slot = *index;
        }
        Ok(Withdrawn(list))
    }

    /// The indexes before the sentinel run.
    pub fn indexes(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().copied().take_while(|v| *v != NO_INDEX)
    }

    /// Whether the list names `index`.
    pub fn names(&self, index: u32) -> bool {
        self.indexes().any(|v| v == index)
    }

    fn check(&self, end_index: u32) -> Result<(), Error> {
        let mut previous: Option<u32> = None;
        let mut in_sentinel_run = false;
        for value in self.0 {
            if value == NO_INDEX {
                in_sentinel_run = true;
                continue;
            }
            // COM-061: the history of the pseudonym ends at `end_index`.
            if in_sentinel_run || value > end_index || previous.is_some_and(|p| value <= p) {
                return Err(Error::Malformed);
            }
            previous = Some(value);
        }
        Ok(())
    }
}

/// A `Checkpoint`: one signature over the chain head of a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint<'a> {
    /// The community.
    pub community_id: [u8; 32],
    /// The authoring pseudonym.
    pub pseudonym: [u8; 32],
    /// The first index of the window.
    pub start_index: u32,
    /// The last index of the window.
    pub end_index: u32,
    /// The head that the previous checkpoint signed, or `link_0`.
    pub previous_signed_head: [u8; 32],
    /// `link_n` at `end_index`.
    pub current_head: [u8; 32],
    /// The withdrawn indexes.
    pub withdrawn: Withdrawn,
    /// `CommunityIdentityKey_g.pk`.
    pub public_key: &'a [u8],
    /// The ML-DSA-65 signature.
    pub signature: &'a [u8],
}

/// The signed fields of a checkpoint, before the key and the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointFields {
    /// The community.
    pub community_id: [u8; 32],
    /// The first index of the window.
    pub start_index: u32,
    /// The last index of the window.
    pub end_index: u32,
    /// The head that the previous checkpoint signed, or `link_0`.
    pub previous_signed_head: [u8; 32],
    /// `link_n` at `end_index`.
    pub current_head: [u8; 32],
    /// The withdrawn indexes.
    pub withdrawn: Withdrawn,
}

fn checkpoint_preimage(pseudonym: &[u8; 32], fields: &CheckpointFields) -> Vec<u8> {
    let mut message = Vec::with_capacity(labels::COMMUNITY_CHECKPOINT.len() + 168);
    message.extend_from_slice(labels::COMMUNITY_CHECKPOINT);
    message.extend_from_slice(&fields.community_id);
    message.extend_from_slice(pseudonym);
    message.extend_from_slice(&fields.start_index.to_be_bytes());
    message.extend_from_slice(&fields.end_index.to_be_bytes());
    message.extend_from_slice(&fields.previous_signed_head);
    message.extend_from_slice(&fields.current_head);
    for value in fields.withdrawn.0 {
        message.extend_from_slice(&value.to_be_bytes());
    }
    message
}

impl<'a> Checkpoint<'a> {
    /// Signs and encodes a checkpoint under the authoring identity.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        author: &AuthorIdentity,
        fields: &CheckpointFields,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        check_window(fields.start_index, fields.end_index)?;
        fields.withdrawn.check(fields.end_index)?;
        let pseudonym = author.pseudonym();
        let signature = author.sign(&checkpoint_preimage(&pseudonym, fields), rng)?;
        let mut out = alloc::vec![0u8; CHECKPOINT_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(RecordType::Checkpoint as u8)?;
        w.put(&fields.community_id)?;
        w.put(&pseudonym)?;
        w.u32(fields.start_index)?;
        w.u32(fields.end_index)?;
        w.put(&fields.previous_signed_head)?;
        w.put(&fields.current_head)?;
        for value in fields.withdrawn.0 {
            w.u32(value)?;
        }
        w.put(author.public_key())?;
        w.put(&signature.to_bytes())?;
        Ok(out)
    }

    /// Reads a checkpoint. The window bound of `COM-212` and the four rules
    /// of the `withdrawn` list hold after this call. The signature is not
    /// verified yet.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        header(&mut r, RecordType::Checkpoint)?;
        let community_id = r.array()?;
        let pseudonym = r.array()?;
        let start_index = r.u32()?;
        let end_index = r.u32()?;
        let previous_signed_head = r.array()?;
        let current_head = r.array()?;
        let mut withdrawn = [NO_INDEX; WITHDRAW_MAX];
        for slot in &mut withdrawn {
            *slot = r.u32()?;
        }
        let public_key = r.take(VERIFYING_KEY_LEN)?;
        let signature = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        check_window(start_index, end_index)?;
        let withdrawn = Withdrawn(withdrawn);
        withdrawn.check(end_index)?;
        Ok(Checkpoint {
            community_id,
            pseudonym,
            start_index,
            end_index,
            previous_signed_head,
            current_head,
            withdrawn,
            public_key,
            signature,
        })
    }

    /// The signed fields.
    pub fn fields(&self) -> CheckpointFields {
        CheckpointFields {
            community_id: self.community_id,
            start_index: self.start_index,
            end_index: self.end_index,
            previous_signed_head: self.previous_signed_head,
            current_head: self.current_head,
            withdrawn: self.withdrawn,
        }
    }

    /// Hashes the carried key, compares it with the pseudonym, and then
    /// verifies the signature (`COM-038`, `COM-039`).
    pub fn verify(&self, community_id: &[u8; 32]) -> Result<(), Error> {
        if self.community_id != *community_id || pseudonym_of(self.public_key) != self.pseudonym {
            return Err(Error::Unverified);
        }
        verify_signature(
            self.public_key,
            &checkpoint_preimage(&self.pseudonym, &self.fields()),
            self.signature,
        )
    }

    /// Whether the window holds `index`.
    pub fn covers(&self, index: u32) -> bool {
        (self.start_index..=self.end_index).contains(&index)
    }
}

fn check_window(start_index: u32, end_index: u32) -> Result<(), Error> {
    // COM-048 and COM-212: one post at the least, SIG_INTERVAL at the most.
    let span = end_index.checked_sub(start_index).ok_or(Error::Malformed)?;
    if span >= SIG_INTERVAL || end_index == NO_INDEX {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// An `OperatorRemoval`: the artifact of a relay that removed one body
/// under a legal order. It authorizes the absence at that relay only
/// (`COM-360`, `COM-361`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorRemoval<'a> {
    /// The community.
    pub community_id: [u8; 32],
    /// The author of the removed post.
    pub pseudonym: [u8; 32],
    /// The index of the removed post.
    pub index: u32,
    /// `SHA3-256(post_n)`.
    pub post_hash: [u8; 32],
    /// The relay that signs.
    pub relay_id: [u8; 32],
    /// Unix seconds on the clock of the relay.
    pub issued_at: u64,
    /// The ML-DSA-65 signature under the identity key of the relay.
    pub signature: &'a [u8],
}

impl<'a> OperatorRemoval<'a> {
    const SIGNED_LEN: usize = OPERATOR_REMOVAL_LEN - SIGNATURE_LEN;

    /// Signs and encodes a removal under the identity key of the relay
    /// (`COM-358`).
    pub fn sign<R: TryCryptoRng + ?Sized>(
        relay_key: &SigningKey,
        community_id: [u8; 32],
        stub: &PostStub,
        relay_id: [u8; 32],
        issued_at: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; OPERATOR_REMOVAL_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(RecordType::OperatorRemoval as u8)?;
        w.put(&community_id)?;
        w.put(&stub.pseudonym)?;
        w.u32(stub.index)?;
        w.put(&stub.post_hash)?;
        w.put(&relay_id)?;
        w.put(&issued_at.to_be_bytes())?;
        let signed = out.get(..Self::SIGNED_LEN).ok_or(Error::Malformed)?;
        let message = [labels::OPERATOR_REMOVAL, signed].concat();
        let signature = relay_key.sign(&message, rng)?;
        out.get_mut(Self::SIGNED_LEN..)
            .ok_or(Error::Malformed)?
            .copy_from_slice(&signature.to_bytes());
        Ok(out)
    }

    /// Reads a removal.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        header(&mut r, RecordType::OperatorRemoval)?;
        let removal = OperatorRemoval {
            community_id: r.array()?,
            pseudonym: r.array()?,
            index: r.u32()?,
            post_hash: r.array()?,
            relay_id: r.array()?,
            issued_at: u64::from_be_bytes(r.array()?),
            signature: r.take(SIGNATURE_LEN)?,
        };
        r.finish()?;
        Ok(removal)
    }

    /// Verifies the removal against the identity key in the descriptor of
    /// `relay_id` (`COM-359`). `bytes` is the encoding that
    /// [`OperatorRemoval::parse`] read.
    pub fn verify(
        &self,
        bytes: &[u8],
        community_id: &[u8; 32],
        relay_identity_key: &[u8],
    ) -> Result<(), Error> {
        if self.community_id != *community_id {
            return Err(Error::Unverified);
        }
        let signed = bytes.get(..Self::SIGNED_LEN).ok_or(Error::Malformed)?;
        let message = [labels::OPERATOR_REMOVAL, signed].concat();
        verify_signature(relay_identity_key, &message, self.signature)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use umbra_crypto::secret::Secret;

    use super::*;
    use crate::{abuse::test_rng::Rng, community::test_util::author};

    #[test]
    fn a_post_and_a_stub_round_trip_at_their_stated_sizes() {
        let body = [0x5A; 200];
        let post = CommunityPost {
            pseudonym: [1; 32],
            index: 4,
            amends: 2,
            body: &body,
        };
        let bytes = post.encode().unwrap();
        assert_eq!(bytes.len(), 246);
        assert_eq!(CommunityPost::parse(&bytes).unwrap(), post);

        let forward = CommunityPost { amends: 4, ..post };
        assert!(
            forward.encode().is_err(),
            "an amendment names an earlier index"
        );
        let large = alloc::vec![0u8; MAX_POST_SIZE + 1];
        assert!(CommunityPost {
            body: &large,
            ..post
        }
        .encode()
        .is_err());

        let stub = PostStub {
            pseudonym: [1; 32],
            index: 4,
            post_hash: post_hash(&bytes),
        };
        let stub_bytes = stub.encode().unwrap();
        assert_eq!(stub_bytes.len(), STUB_LEN);
        assert_eq!(PostStub::parse(&stub_bytes).unwrap(), stub);
        assert!(CommunityPost::parse(&stub_bytes).is_err());
    }

    #[test]
    fn a_checkpoint_verifies_and_binds_each_signed_field() {
        let identity = author(3);
        let community = [9; 32];
        let fields = CheckpointFields {
            community_id: community,
            start_index: 5,
            end_index: 9,
            previous_signed_head: [1; 32],
            current_head: [2; 32],
            withdrawn: Withdrawn::from_indexes(&[7, 1]).unwrap(),
        };
        let mut bytes = Checkpoint::sign(&identity, &fields, &mut Rng(1)).unwrap();
        assert_eq!(bytes.len(), CHECKPOINT_LEN);
        let checkpoint = Checkpoint::parse(&bytes).unwrap();
        checkpoint.verify(&community).unwrap();
        assert!(checkpoint.verify(&[8; 32]).is_err());
        assert!(checkpoint.withdrawn.names(1) && checkpoint.withdrawn.names(7));
        assert!(checkpoint.covers(5) && checkpoint.covers(9) && !checkpoint.covers(10));

        // A changed head fails the signature.
        bytes[2 + 136 - 1] ^= 1;
        assert!(Checkpoint::parse(&bytes)
            .unwrap()
            .verify(&community)
            .is_err());
        bytes[2 + 136 - 1] ^= 1;

        // A key of another identity fails the hash check before the signature.
        let other = author(4);
        bytes[2 + 136 + 32..2 + 136 + 32 + VERIFYING_KEY_LEN].copy_from_slice(other.public_key());
        assert!(Checkpoint::parse(&bytes)
            .unwrap()
            .verify(&community)
            .is_err());

        let wide = CheckpointFields {
            start_index: 4,
            ..fields
        };
        assert!(Checkpoint::sign(&identity, &wide, &mut Rng(1)).is_err());
    }

    #[test]
    fn the_length_of_a_record_splits_a_pub_payload() {
        let post = CommunityPost {
            pseudonym: [1; 32],
            index: 0,
            amends: NO_INDEX,
            body: &[7; 300],
        }
        .encode()
        .unwrap();
        let payload = [post.as_slice(), &[0, 0, 0]].concat();
        assert_eq!(record_len(&payload).unwrap(), post.len());
        assert!(record_len(&post[..100]).is_err());

        let identity = author(3);
        let fields = CheckpointFields {
            community_id: [9; 32],
            start_index: 0,
            end_index: 0,
            previous_signed_head: [1; 32],
            current_head: [2; 32],
            withdrawn: Withdrawn::NONE,
        };
        let checkpoint = Checkpoint::sign(&identity, &fields, &mut Rng(1)).unwrap();
        assert_eq!(record_len(&checkpoint).unwrap(), CHECKPOINT_LEN);
    }

    #[test]
    fn the_withdrawn_list_obeys_its_four_rules() {
        assert!(Withdrawn::from_indexes(&[0, 1, 2, 3, 4, 5, 6, 7, 8]).is_err());
        assert!(
            Withdrawn([3, 3, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX])
                .check(9)
                .is_err()
        );
        assert!(
            Withdrawn([4, 3, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX])
                .check(9)
                .is_err()
        );
        assert!(
            Withdrawn([3, NO_INDEX, 4, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX])
                .check(9)
                .is_err()
        );
        assert!(
            Withdrawn([3, 10, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX, NO_INDEX])
                .check(9)
                .is_err()
        );
        assert!(Withdrawn::NONE.check(0).is_ok());
    }

    #[test]
    fn an_operator_removal_verifies_under_the_relay_key_only() {
        let relay_key = SigningKey::from_seed(Secret::new([5; 32]));
        let stub = PostStub {
            pseudonym: [1; 32],
            index: 3,
            post_hash: [2; 32],
        };
        let bytes =
            OperatorRemoval::sign(&relay_key, [9; 32], &stub, [6; 32], 1_000, &mut Rng(2)).unwrap();
        assert_eq!(bytes.len(), OPERATOR_REMOVAL_LEN);
        let removal = OperatorRemoval::parse(&bytes).unwrap();
        assert_eq!(removal.index, 3);
        let relay_pk = relay_key.verifying_key().to_bytes();
        removal.verify(&bytes, &[9; 32], &relay_pk).unwrap();
        assert!(removal.verify(&bytes, &[8; 32], &relay_pk).is_err());
        let other = SigningKey::from_seed(Secret::new([7; 32]))
            .verifying_key()
            .to_bytes();
        assert!(removal.verify(&bytes, &[9; 32], &other).is_err());
    }
}
