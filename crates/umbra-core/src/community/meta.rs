//! The metadata record of a community (Part 12 §12.7.1): the signed
//! record that a relay serves, the sealed body that only a holder of the
//! link reads, and the chain of the records.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use umbra_crypto::{
    aead,
    hash::sha3_256,
    labels,
    rand_core::TryCryptoRng,
    secret::Secret,
    sign::{SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    authority::{order_key, Authority, Fork, Outcome},
    control::Role,
    identity::RoleIdentity,
    link::RELAY_REF_LEN,
    pseudonym_of,
    record::verify_signature,
    RecordType, COMMUNITY_MIN_RELAYS, COMMUNITY_RELAY_MAX, META_NAME_MAX, META_RULES_MAX,
    META_TEXT_MAX, VERSION,
};
use crate::Error;

/// Bit 0 of `flags`: reactions are off (`COM-330`).
pub const FLAG_REACTIONS_OFF: u8 = 0x01;
/// Bit 1 of `flags`: reposts are off (`COM-331`).
pub const FLAG_REPOSTS_OFF: u8 = 0x02;
/// The largest icon field, which is one `FileDescriptor` of one chunk.
pub const META_ICON_MAX: usize = 253;
/// The largest `CommunityMeta`.
pub const META_MAX: usize = 7_865;

/// The category of a community. A value that the table does not define
/// shows as `None` (`COM-259`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Category {
    None = 0x00,
    General = 0x01,
    News = 0x02,
    Technology = 0x03,
    ArtAndMusic = 0x04,
    Games = 0x05,
    Sport = 0x06,
    Education = 0x07,
    Local = 0x08,
    Support = 0x09,
    Other = 0x0A,
}

impl Category {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Category::General,
            0x02 => Category::News,
            0x03 => Category::Technology,
            0x04 => Category::ArtAndMusic,
            0x05 => Category::Games,
            0x06 => Category::Sport,
            0x07 => Category::Education,
            0x08 => Category::Local,
            0x09 => Category::Support,
            0x0A => Category::Other,
            _ => Category::None,
        }
    }
}

/// The plaintext of the body: the items that a relay does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityMetaBody {
    /// The category.
    pub category: Category,
    /// The name, 1 to `META_NAME_MAX` bytes.
    pub name: String,
    /// The description.
    pub text: String,
    /// The rules.
    pub rules: String,
    /// One `FileDescriptor` of one chunk, or empty (`COM-260`).
    pub icon: Vec<u8>,
}

impl CommunityMetaBody {
    fn check(&self) -> Result<(), Error> {
        // COM-257.
        if self.name.is_empty()
            || self.name.len() > META_NAME_MAX
            || self.text.len() > META_TEXT_MAX
            || self.rules.len() > META_RULES_MAX
            || self.icon.len() > META_ICON_MAX
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let len =
            3 + self.name.len() + 2 + self.text.len() + 2 + self.rules.len() + 2 + self.icon.len();
        let mut out = alloc::vec![0u8; len];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(self.category as u8)?;
        w.u8(u8::try_from(self.name.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.name.as_bytes())?;
        for field in [self.text.as_bytes(), self.rules.as_bytes(), &self.icon] {
            w.u16(u16::try_from(field.len()).map_err(|_| Error::Malformed)?)?;
            w.put(field)?;
        }
        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let category = Category::from_byte(r.u8()?);
        let name_len = usize::from(r.u8()?);
        // COM-258.
        let text_of = |bytes: &[u8]| {
            core::str::from_utf8(bytes)
                .map(String::from)
                .map_err(|_| Error::Malformed)
        };
        let name = text_of(r.take(name_len)?)?;
        let text_len = usize::from(r.u16()?);
        let text = text_of(r.take(text_len)?)?;
        let rules_len = usize::from(r.u16()?);
        let rules = text_of(r.take(rules_len)?)?;
        let icon_len = usize::from(r.u16()?);
        let icon = r.take(icon_len)?.to_vec();
        r.finish()?;
        let body = CommunityMetaBody {
            category,
            name,
            text,
            rules,
            icon,
        };
        body.check()?;
        Ok(body)
    }
}

/// A `CommunityMeta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityMeta {
    /// The community.
    pub community_id: [u8; 32],
    /// 0 at the creation, then one more at each change.
    pub meta_index: u32,
    /// The hash of the record before this one, or zero bytes at index 0.
    pub previous_meta: [u8; 32],
    /// The owner role pseudonym of the signer.
    pub actor: [u8; 32],
    /// The ML-DSA-65 public key of that pseudonym.
    pub actor_pk: Vec<u8>,
    /// The relays of the community.
    pub relays: Vec<[u8; RELAY_REF_LEN]>,
    /// The owner dial that a relay reads (§12.6.2).
    pub flags: u8,
    /// The nonce of the body.
    pub nonce: [u8; 12],
    /// The sealed `CommunityMetaBody` with its tag.
    pub body: Vec<u8>,
    /// The signature of the actor.
    pub signature: Vec<u8>,
}

/// The fields that the owner sets in a new record.
pub struct MetaDraft<'a> {
    /// The community.
    pub community_id: [u8; 32],
    /// The position in the chain.
    pub meta_index: u32,
    /// The hash of the record before this one.
    pub previous_meta: [u8; 32],
    /// The relays.
    pub relays: Vec<[u8; RELAY_REF_LEN]>,
    /// The owner dial.
    pub flags: u8,
    /// The plaintext of the body.
    pub body: &'a CommunityMetaBody,
    /// The nonce, from the device CSPRNG.
    pub nonce: [u8; 12],
}

fn body_aad(community_id: &[u8; 32], meta_index: u32) -> [u8; 36] {
    let mut aad = [0u8; 36];
    let (id_part, index_part) = aad.split_at_mut(32);
    id_part.copy_from_slice(community_id);
    index_part.copy_from_slice(&meta_index.to_be_bytes());
    aad
}

impl CommunityMeta {
    /// Seals the body under `meta_key` and signs the record.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        owner: &RoleIdentity,
        meta_key: &Secret<32>,
        draft: MetaDraft<'_>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut body = draft.body.encode()?;
        let aad = body_aad(&draft.community_id, draft.meta_index);
        let tag = aead::seal_ietf(meta_key, &draft.nonce, &aad, &mut body)?;
        body.extend_from_slice(&tag);
        let mut meta = CommunityMeta {
            community_id: draft.community_id,
            meta_index: draft.meta_index,
            previous_meta: draft.previous_meta,
            actor: owner.pseudonym(),
            actor_pk: owner.public_key().to_vec(),
            relays: draft.relays,
            flags: draft.flags,
            nonce: draft.nonce,
            body,
            signature: Vec::new(),
        };
        let preimage = [labels::COMMUNITY_METADATA, &meta.signed_bytes()?].concat();
        meta.signature = owner.sign(&preimage, rng)?.to_bytes().to_vec();
        Ok(meta)
    }

    fn check(&self) -> Result<(), Error> {
        let mut distinct = self.relays.clone();
        distinct.sort_unstable();
        distinct.dedup();
        // COM-254, COM-255.
        if self.relays.len() < COMMUNITY_MIN_RELAYS
            || self.relays.len() > COMMUNITY_RELAY_MAX
            || distinct.len() != self.relays.len()
            || self.actor_pk.len() != VERIFYING_KEY_LEN
            || self.body.len() < aead::TAG_LEN
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut out = alloc::vec![0u8; META_MAX];
        let mut w = Writer::new(&mut out);
        w.u8(VERSION)?;
        w.u8(RecordType::Meta as u8)?;
        w.put(&self.community_id)?;
        w.u32(self.meta_index)?;
        w.put(&self.previous_meta)?;
        w.put(&self.actor)?;
        w.put(&self.actor_pk)?;
        w.u8(u8::try_from(self.relays.len()).map_err(|_| Error::Malformed)?)?;
        for relay in &self.relays {
            w.put(relay)?;
        }
        w.u8(self.flags)?;
        w.put(&self.nonce)?;
        w.u16(u16::try_from(self.body.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.body)?;
        let used = w.position();
        out.truncate(used);
        Ok(out)
    }

    /// The identifier that a successor puts in `previous_meta`: the hash of
    /// the signed bytes.
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        Ok(sha3_256(&[&self.signed_bytes()?]))
    }

    /// Encodes the record.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = self.signed_bytes()?;
        if self.signature.len() != SIGNATURE_LEN || out.len() + SIGNATURE_LEN > META_MAX {
            return Err(Error::Malformed);
        }
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Reads a record.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > META_MAX {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != VERSION || r.u8()? != RecordType::Meta as u8 {
            return Err(Error::Malformed);
        }
        let community_id = r.array()?;
        let meta_index = r.u32()?;
        let previous_meta = r.array()?;
        let actor = r.array()?;
        let actor_pk = r.take(VERIFYING_KEY_LEN)?.to_vec();
        let relay_count = usize::from(r.u8()?);
        if relay_count > COMMUNITY_RELAY_MAX {
            return Err(Error::Malformed);
        }
        let mut relays = Vec::with_capacity(relay_count);
        for _ in 0..relay_count {
            relays.push(r.array()?);
        }
        let flags = r.u8()?;
        let nonce = r.array()?;
        let body_len = usize::from(r.u16()?);
        let body = r.take(body_len)?.to_vec();
        let signature = r.take(SIGNATURE_LEN)?.to_vec();
        r.finish()?;
        let meta = CommunityMeta {
            community_id,
            meta_index,
            previous_meta,
            actor,
            actor_pk,
            relays,
            flags,
            nonce,
            body,
            signature,
        };
        meta.check()?;
        Ok(meta)
    }

    /// The hash check of rule 1 and the signature (`COM-250`).
    pub fn verify_signature(&self, community_id: &[u8; 32]) -> Result<(), Error> {
        if self.community_id != *community_id || pseudonym_of(&self.actor_pk) != self.actor {
            return Err(Error::Unverified);
        }
        let preimage = [labels::COMMUNITY_METADATA, &self.signed_bytes()?].concat();
        verify_signature(&self.actor_pk, &preimage, &self.signature)
    }

    /// Opens the body with the key of the link. A client calls this after
    /// the record verifies (`COM-265`).
    pub fn open(&self, meta_key: &Secret<32>) -> Result<CommunityMetaBody, Error> {
        let split = self.body.len().saturating_sub(aead::TAG_LEN);
        let (sealed, tag) = self.body.split_at(split);
        let mut plain = sealed.to_vec();
        let aad = body_aad(&self.community_id, self.meta_index);
        aead::open_ietf(meta_key, &self.nonce, &aad, &mut plain, tag)?;
        CommunityMetaBody::parse(&plain)
    }

    /// Whether the owner dial forbids reactions. A bit that §12.6.2 does
    /// not define reads as zero (`COM-348`).
    pub fn reactions_off(&self) -> bool {
        self.flags & FLAG_REACTIONS_OFF != 0
    }

    /// Whether the owner dial forbids reposts.
    pub fn reposts_off(&self) -> bool {
        self.flags & FLAG_REPOSTS_OFF != 0
    }

    /// Whether the relays sit under `COMMUNITY_MIN_RELAYS` different
    /// operators at the least (`COM-254`). `operator_of` resolves a
    /// `RelayRef` through the directory.
    pub fn has_enough_operators(
        &self,
        operator_of: impl Fn(&[u8; RELAY_REF_LEN]) -> Option<[u8; 32]>,
    ) -> bool {
        let mut operators: Vec<[u8; 32]> = self.relays.iter().filter_map(operator_of).collect();
        operators.sort_unstable();
        operators.dedup();
        operators.len() >= COMMUNITY_MIN_RELAYS
    }
}

/// The metadata records of one community, by `meta_index`.
///
/// A party verifies a record under the roster it holds at that time, thus
/// a record of a former owner does not verify at a join or at a re-seed,
/// and its index stays empty. An empty index below a record is no fault:
/// the `previous_meta` check runs when the party holds the record at
/// `meta_index` − 1.
pub struct MetaChain {
    community_id: [u8; 32],
    records: BTreeMap<u32, ([u8; 32], CommunityMeta)>,
    forks: Vec<Fork>,
}

impl MetaChain {
    /// An empty chain.
    pub fn new(community_id: [u8; 32]) -> Self {
        MetaChain {
            community_id,
            records: BTreeMap::new(),
            forks: Vec::new(),
        }
    }

    /// The verified record with the highest `meta_index` (`COM-253`).
    pub fn current(&self) -> Option<&CommunityMeta> {
        self.records.values().next_back().map(|(_, meta)| meta)
    }

    /// The forks that the chain saw.
    pub fn forks(&self) -> &[Fork] {
        &self.forks
    }

    /// The records with a `meta_index` at or above `from`.
    pub fn records_from(&self, from: u32) -> impl Iterator<Item = &CommunityMeta> {
        self.records.range(from..).map(|(_, (_, meta))| meta)
    }

    /// Whether the chain holds the record with this hash.
    pub fn holds(&self, hash: &[u8; 32]) -> bool {
        self.records.values().any(|(held, _)| held == hash)
    }

    /// Verifies a record under the current roster and applies it
    /// (`COM-249` to `COM-252`).
    pub fn apply(&mut self, meta: CommunityMeta, authority: &Authority) -> Result<Outcome, Error> {
        meta.verify_signature(&self.community_id)?;
        if authority.role_of(&meta.actor) != Some(Role::Owner) {
            return Err(Error::Unverified);
        }
        let hash = meta.hash()?;
        let before = meta
            .meta_index
            .checked_sub(1)
            .and_then(|index| self.records.get(&index));
        let chains = match before {
            Some((held, _)) => *held == meta.previous_meta,
            None => meta.meta_index != 0 || meta.previous_meta == [0u8; 32],
        };
        if !chains {
            return Err(Error::Unverified);
        }
        let Some((rival_hash, rival)) = self.records.get(&meta.meta_index) else {
            self.records.insert(meta.meta_index, (hash, meta));
            return Ok(Outcome::Selected);
        };
        if *rival_hash == hash {
            return Ok(Outcome::Duplicate);
        }
        if rival.actor == meta.actor {
            let fork = Fork {
                previous_epoch: meta.previous_meta,
                actor: meta.actor,
                hashes: [*rival_hash, hash],
            };
            self.forks.push(fork);
            return Ok(Outcome::Forked(fork));
        }
        // Each signer is an owner, thus the hash order decides.
        if order_key(&meta.previous_meta, &meta.actor)
            > order_key(&meta.previous_meta, &rival.actor)
        {
            return Ok(Outcome::NotSelected);
        }
        // Each record above the replaced one named it, thus none of them
        // stays.
        self.records.split_off(&meta.meta_index);
        self.records.insert(meta.meta_index, (hash, meta));
        Ok(Outcome::Selected)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{
        abuse::test_rng::Rng,
        community::{
            authority::tests::{community, ADMIN, OWNER_A, OWNER_B},
            test_util::role,
        },
    };

    fn body() -> CommunityMetaBody {
        CommunityMetaBody {
            category: Category::Technology,
            name: "Rust".into(),
            text: "Systems programming".into(),
            rules: "Be kind".into(),
            icon: Vec::new(),
        }
    }

    fn draft<'a>(
        id: [u8; 32],
        index: u32,
        previous: [u8; 32],
        body: &'a CommunityMetaBody,
    ) -> MetaDraft<'a> {
        MetaDraft {
            community_id: id,
            meta_index: index,
            previous_meta: previous,
            relays: alloc::vec![[1; 12], [2; 12], [3; 12]],
            flags: FLAG_REACTIONS_OFF | 0x80,
            body,
            nonce: [4; 12],
        }
    }

    #[test]
    fn the_largest_record_has_the_stated_size_and_the_body_opens() {
        let key = Secret::new([6; 32]);
        let full = CommunityMetaBody {
            category: Category::Other,
            name: "n".repeat(META_NAME_MAX),
            text: "t".repeat(META_TEXT_MAX),
            rules: "r".repeat(META_RULES_MAX),
            icon: alloc::vec![7; META_ICON_MAX],
        };
        let mut large = draft([9; 32], 0, [0; 32], &full);
        large.relays = (0..8u8).map(|n| [n; 12]).collect();
        let meta = CommunityMeta::sign(&role(OWNER_A), &key, large, &mut Rng(1)).unwrap();
        let bytes = meta.encode().unwrap();
        assert_eq!(bytes.len(), META_MAX);
        let parsed = CommunityMeta::parse(&bytes).unwrap();
        parsed.verify_signature(&[9; 32]).unwrap();
        assert_eq!(parsed.open(&key).unwrap(), full);
        assert!(parsed.open(&Secret::new([7; 32])).is_err());
        assert!(parsed.reactions_off() && !parsed.reposts_off());

        let mut few = draft([9; 32], 0, [0; 32], &full);
        few.relays.truncate(2);
        assert!(CommunityMeta::sign(&role(OWNER_A), &key, few, &mut Rng(1)).is_err());

        let operators = |r: &[u8; 12]| Some([r[0] % 2; 32]);
        assert!(!parsed.has_enough_operators(operators));
        assert!(parsed.has_enough_operators(|r: &[u8; 12]| Some([r[0]; 32])));

        let mut long_name = body();
        long_name.name = "n".repeat(META_NAME_MAX + 1);
        assert!(long_name.encode().is_err());
        let mut unknown = body().encode().unwrap();
        unknown[1] = 0x7F;
        assert_eq!(
            CommunityMetaBody::parse(&unknown).unwrap().category,
            Category::None
        );
    }

    #[test]
    fn only_an_owner_extends_the_chain_and_one_owner_does_not_fork_it() {
        let (id, control) = community();
        let key = Secret::new([6; 32]);
        let text = body();
        let mut chain = MetaChain::new(id);

        let by_admin = CommunityMeta::sign(
            &role(ADMIN),
            &key,
            draft(id, 0, [0; 32], &text),
            &mut Rng(1),
        )
        .unwrap();
        assert!(chain.apply(by_admin, control.authority()).is_err());

        let first = CommunityMeta::sign(
            &role(OWNER_A),
            &key,
            draft(id, 0, [0; 32], &text),
            &mut Rng(1),
        )
        .unwrap();
        let first_hash = first.hash().unwrap();
        assert_eq!(
            chain.apply(first.clone(), control.authority()).unwrap(),
            Outcome::Selected
        );
        assert_eq!(
            chain.apply(first, control.authority()).unwrap(),
            Outcome::Duplicate
        );

        let unchained = CommunityMeta::sign(
            &role(OWNER_A),
            &key,
            draft(id, 1, [5; 32], &text),
            &mut Rng(2),
        )
        .unwrap();
        assert!(chain.apply(unchained, control.authority()).is_err());
        // An empty index below a record is no fault.
        let after_a_hole = CommunityMeta::sign(
            &role(OWNER_A),
            &key,
            draft(id, 7, [5; 32], &text),
            &mut Rng(2),
        )
        .unwrap();
        let mut sparse = MetaChain::new(id);
        assert_eq!(
            sparse.apply(after_a_hole, control.authority()).unwrap(),
            Outcome::Selected
        );
        assert_eq!(sparse.current().unwrap().meta_index, 7);

        let second = CommunityMeta::sign(
            &role(OWNER_A),
            &key,
            draft(id, 1, first_hash, &text),
            &mut Rng(2),
        )
        .unwrap();
        assert_eq!(
            chain.apply(second, control.authority()).unwrap(),
            Outcome::Selected
        );
        assert_eq!(chain.current().unwrap().meta_index, 1);

        let mut changed = body();
        changed.name = "Rust 2".into();
        let twin = CommunityMeta::sign(
            &role(OWNER_A),
            &key,
            draft(id, 1, first_hash, &changed),
            &mut Rng(3),
        )
        .unwrap();
        assert!(matches!(
            chain.apply(twin, control.authority()).unwrap(),
            Outcome::Forked(_)
        ));

        let rival = CommunityMeta::sign(
            &role(OWNER_B),
            &key,
            draft(id, 1, first_hash, &changed),
            &mut Rng(4),
        )
        .unwrap();
        let rival_wins = order_key(&first_hash, &role(OWNER_B).pseudonym())
            < order_key(&first_hash, &role(OWNER_A).pseudonym());
        let outcome = chain.apply(rival, control.authority()).unwrap();
        assert_eq!(outcome == Outcome::Selected, rival_wins);
        assert_eq!(
            chain.current().unwrap().actor == role(OWNER_B).pseudonym(),
            rival_wins
        );
        assert_eq!(chain.records_from(1).count(), 1);
    }
}
