//! The community listing of Part 9 §9.12: the record and its checks, the
//! browse query and its page, and the index at the directory with its
//! lease, its ranking, and its prefix match.

use alloc::{string::String, vec::Vec};

use umbra_crypto::{
    hash::sha3_256,
    labels,
    sign::{Signature, SigningKey, VerifyingKey, SIGNATURE_LEN, VERIFYING_KEY_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{handle::Profile, LISTING_LEASE, LISTING_PAGE};
use crate::Error;

/// `META_NAME_MAX` of Part 12 §12.9.
pub const NAME_MAX: usize = 64;
/// The most bytes of a community link (§9.12).
pub const LINK_MAX: usize = 259;
/// The fixed part of a listing, without the name, the link, and the
/// signature.
pub const FIXED: usize = 1 + 32 + 1 + 32 + VERIFYING_KEY_LEN + 4 + 1 + 2 + 1 + 1 + 1;
/// The most bytes of a listing.
pub const LISTING_MAX: usize = FIXED + NAME_MAX + LINK_MAX + SIGNATURE_LEN;
/// The category byte that names each category in a query.
pub const ANY_CATEGORY: u8 = 0xFF;

/// A community listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityListing {
    /// The community.
    pub community_id: [u8; 32],
    /// The admission byte of Part 12 §12.2.2.
    pub admission: u8,
    /// The genesis owner role pseudonym.
    pub actor: [u8; 32],
    /// `genesis_root_public_key`.
    pub actor_pk: Vec<u8>,
    /// Increases by one at each publication.
    pub listing_index: u32,
    /// The category of Part 12 §12.7.1.
    pub category: u8,
    /// ISO 639-1, lower case.
    pub language: [u8; 2],
    /// The activity bucket.
    pub activity: u8,
    /// The name, UTF-8.
    pub name: Vec<u8>,
    /// The link, or empty for a withdrawal (`COM-351`).
    pub link: Vec<u8>,
    /// The ML-DSA-65 signature.
    pub signature: Vec<u8>,
}

impl CommunityListing {
    fn check_fields(&self) -> Result<(), Error> {
        if self.actor_pk.len() != VERIFYING_KEY_LEN
            || self.name.is_empty()
            || self.name.len() > NAME_MAX
            || self.link.len() > LINK_MAX
            || self.activity > 0x04
            || self.signature.len() != SIGNATURE_LEN
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn write_signed(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(0x01)?;
        w.put(&self.community_id)?;
        w.u8(self.admission)?;
        w.put(&self.actor)?;
        w.put(&self.actor_pk)?;
        w.u32(self.listing_index)?;
        w.u8(self.category)?;
        w.put(&self.language)?;
        w.u8(self.activity)?;
        w.u8(u8::try_from(self.name.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.name)?;
        w.u8(u8::try_from(self.link.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.link)?;
        Ok(())
    }

    /// The signed preimage: the label, then each field before the
    /// signature.
    pub fn preimage(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; labels::COMMUNITY_LISTING.len() + LISTING_MAX];
        let mut w = Writer::new(&mut out);
        w.put(labels::COMMUNITY_LISTING)?;
        self.write_signed(&mut w)?;
        let n = w.position();
        out.truncate(n);
        Ok(out)
    }

    /// Signs the listing under `key`, which must be the genesis root key.
    pub fn sign<R: umbra_crypto::rand_core::TryCryptoRng + ?Sized>(
        &mut self,
        key: &SigningKey,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.signature = alloc::vec![0u8; SIGNATURE_LEN];
        let preimage = self.preimage()?;
        self.signature = key.sign(&preimage, rng)?.to_bytes().to_vec();
        Ok(())
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        FIXED + self.name.len() + self.link.len() + SIGNATURE_LEN
    }

    /// Whether the listing is a withdrawal (`DIS-127`).
    pub fn is_empty(&self) -> bool {
        self.link.is_empty()
    }

    /// Writes the listing.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check_fields()?;
        let mut w = Writer::new(out);
        self.write_signed(&mut w)?;
        w.put(&self.signature)?;
        Ok(w.position())
    }

    /// Reads a listing and returns the bytes used.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let community_id = r.array()?;
        let admission = r.u8()?;
        let actor = r.array()?;
        let actor_pk = r.take(VERIFYING_KEY_LEN)?.to_vec();
        let listing_index = r.u32()?;
        let category = r.u8()?;
        let language = r.array()?;
        let activity = r.u8()?;
        let name_len = usize::from(r.u8()?);
        let name = r.take(name_len)?.to_vec();
        let link_len = usize::from(r.u8()?);
        let link = r.take(link_len)?.to_vec();
        let signature = r.take(SIGNATURE_LEN)?.to_vec();
        let out = CommunityListing {
            community_id,
            admission,
            actor,
            actor_pk,
            listing_index,
            category,
            language,
            activity,
            name,
            link,
            signature,
        };
        out.check_fields()?;
        Ok((out, r.position()))
    }

    /// Checks the identity bindings and the signature (`DIS-111`,
    /// `DIS-112`, `DIS-123`).
    pub fn verify(&self) -> Result<(), Error> {
        self.check_fields()?;
        let expected_id = sha3_256(&[labels::COMMUNITY_ID, &[self.admission], &self.actor_pk]);
        if expected_id != self.community_id || sha3_256(&[&self.actor_pk]) != self.actor {
            return Err(Error::Unverified);
        }
        let key = VerifyingKey::from_bytes(&self.actor_pk)?;
        let sig = Signature::from_bytes(&self.signature)?;
        key.verify(&self.preimage()?, &sig)?;
        Ok(())
    }
}

/// A browse query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingQuery {
    /// The category, or `ANY_CATEGORY`.
    pub category: u8,
    /// The language, or two zero bytes for each language.
    pub language: [u8; 2],
    /// The name prefix, or empty for each name.
    pub prefix: Vec<u8>,
    /// The page.
    pub page: u16,
}

impl ListingQuery {
    /// Writes the query.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.category)?;
        w.put(&self.language)?;
        w.u8(u8::try_from(self.prefix.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.prefix)?;
        w.u16(self.page)?;
        Ok(w.position())
    }

    /// Reads a query.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let category = r.u8()?;
        let language = r.array()?;
        let prefix_len = usize::from(r.u8()?);
        let prefix = r.take(prefix_len)?.to_vec();
        let page = r.u16()?;
        r.finish()?;
        Ok(ListingQuery {
            category,
            language,
            prefix,
            page,
        })
    }
}

/// A page of listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingPage {
    /// The listings, at most `LISTING_PAGE`.
    pub listings: Vec<CommunityListing>,
}

impl ListingPage {
    /// Writes the page (`DIS-120`).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.listings.len() > LISTING_PAGE {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(u8::try_from(self.listings.len()).map_err(|_| Error::Malformed)?)?;
        let mut at = w.position();
        for listing in &self.listings {
            let n = listing.encode(out.get_mut(at..).ok_or(Error::Malformed)?)?;
            at = at.saturating_add(n);
        }
        Ok(at)
    }

    /// Reads a page.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let count = usize::from(r.u8()?);
        if count > LISTING_PAGE {
            return Err(Error::Malformed);
        }
        let mut rest = r.rest();
        let mut listings = Vec::with_capacity(count);
        for _ in 0..count {
            let (listing, used) = CommunityListing::parse(rest)?;
            listings.push(listing);
            rest = rest.get(used..).ok_or(Error::Malformed)?;
        }
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(ListingPage { listings })
    }
}

struct Accepted {
    listing: CommunityListing,
    accepted_at: u64,
    mapped_name: String,
}

/// The listing index at the directory.
#[derive(Default)]
pub struct ListingIndex {
    accepted: Vec<Accepted>,
}

impl ListingIndex {
    /// Publishes a listing after the token check (`DIS-113` to `DIS-116`).
    /// A withdrawal replaces the listing and leaves no page.
    pub fn publish(
        &mut self,
        listing: CommunityListing,
        profile: Profile<'_>,
        now: u64,
    ) -> Result<(), Error> {
        listing.verify()?;
        let current = self
            .accepted
            .iter()
            .position(|a| a.listing.community_id == listing.community_id);
        let expected_index = current.map_or(0, |i| {
            self.accepted
                .get(i)
                .map_or(0, |a| a.listing.listing_index.saturating_add(1))
        });
        if listing.listing_index != expected_index {
            return Err(Error::Stale);
        }
        let name = core::str::from_utf8(&listing.name).map_err(|_| Error::Malformed)?;
        let mapped_name = profile(name).ok_or(Error::Malformed)?;
        let entry = Accepted {
            listing,
            accepted_at: now,
            mapped_name,
        };
        match current {
            Some(i) => {
                if let Some(slot) = self.accepted.get_mut(i) {
                    *slot = entry;
                }
            }
            None => self.accepted.push(entry),
        }
        Ok(())
    }

    /// Removes each listing past `LISTING_LEASE` (`DIS-116`).
    pub fn expire(&mut self, now: u64) {
        self.accepted
            .retain(|a| now.saturating_sub(a.accepted_at) < LISTING_LEASE);
    }

    /// The listings held, withdrawals included.
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Answers a browse (`DIS-119` to `DIS-121`, `DIS-127`, `DIS-130`).
    pub fn browse(&self, query: &ListingQuery, profile: Profile<'_>) -> Result<ListingPage, Error> {
        let prefix = core::str::from_utf8(&query.prefix).map_err(|_| Error::Malformed)?;
        let mapped_prefix = if prefix.is_empty() {
            String::new()
        } else {
            profile(prefix).ok_or(Error::Malformed)?
        };
        let mut matched: Vec<&Accepted> = self
            .accepted
            .iter()
            .filter(|a| !a.listing.is_empty())
            .filter(|a| query.category == ANY_CATEGORY || a.listing.category == query.category)
            .filter(|a| query.language == [0; 2] || a.listing.language == query.language)
            .filter(|a| a.mapped_name.starts_with(&mapped_prefix))
            .collect();
        matched.sort_by(|a, b| {
            b.listing
                .activity
                .cmp(&a.listing.activity)
                .then(b.accepted_at.cmp(&a.accepted_at))
        });
        let start = usize::from(query.page).saturating_mul(LISTING_PAGE);
        let listings = matched
            .iter()
            .skip(start)
            .take(LISTING_PAGE)
            .map(|a| a.listing.clone())
            .collect();
        Ok(ListingPage { listings })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::discovery::handle::ascii_profile;
    use umbra_crypto::secret::Secret;

    struct Rng(u64);
    impl umbra_crypto::rand_core::TryRng for Rng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            Ok((self.0 >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?) << 32 | u64::from(self.try_next_u32()?))
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for b in dest {
                *b = self.try_next_u32()? as u8;
            }
            Ok(())
        }
    }
    impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

    fn listing(seed: u8, index: u32, activity: u8, name: &str) -> (CommunityListing, SigningKey) {
        let key = SigningKey::from_seed(Secret::new([seed; 32]));
        let actor_pk = key.verifying_key().to_bytes().to_vec();
        let admission = 0x01;
        let mut out = CommunityListing {
            community_id: sha3_256(&[labels::COMMUNITY_ID, &[admission], &actor_pk]),
            admission,
            actor: sha3_256(&[&actor_pk]),
            actor_pk,
            listing_index: index,
            category: 2,
            language: *b"en",
            activity,
            name: name.as_bytes().to_vec(),
            link: b"umbra://c/abc".to_vec(),
            signature: Vec::new(),
        };
        out.sign(&key, &mut Rng(u64::from(seed))).unwrap();
        (out, key)
    }

    #[test]
    fn a_listing_round_trips_and_verifies_its_bindings() {
        let (l, _) = listing(1, 0, 3, "Rust Users");
        let mut out = alloc::vec![0u8; LISTING_MAX];
        let n = l.encode(&mut out).unwrap();
        assert_eq!(n, l.len());
        let (back, used) = CommunityListing::parse(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(back, l);
        back.verify().unwrap();
        let mut wrong_id = l.clone();
        wrong_id.community_id[0] ^= 1;
        assert_eq!(wrong_id.verify(), Err(Error::Unverified));
        let mut wrong_actor = l.clone();
        wrong_actor.actor[0] ^= 1;
        assert_eq!(wrong_actor.verify(), Err(Error::Unverified));
        let mut edited = l.clone();
        edited.activity = 4;
        assert_eq!(edited.verify(), Err(Error::Unverified));
        assert_eq!(LISTING_MAX, 5_660);

        let page = ListingPage {
            listings: alloc::vec![l.clone(), l.clone()],
        };
        let mut out = alloc::vec![0u8; 2 + 2 * LISTING_MAX];
        let n = page.encode(&mut out).unwrap();
        assert_eq!(ListingPage::parse(&out[..n]).unwrap(), page);
        let query = ListingQuery {
            category: ANY_CATEGORY,
            language: *b"en",
            prefix: b"Ru".to_vec(),
            page: 1,
        };
        let mut q = [0u8; 16];
        let n = query.encode(&mut q).unwrap();
        assert_eq!(ListingQuery::parse(&q[..n]).unwrap(), query);
    }

    #[test]
    fn the_index_ranks_pages_expires_and_hides_a_withdrawal() {
        let mut index = ListingIndex::default();
        let (a, key_a) = listing(1, 0, 2, "Alpha");
        let (b, _) = listing(2, 0, 4, "alps");
        let (c, _) = listing(3, 0, 2, "Beta");
        index.publish(a.clone(), &ascii_profile, 10).unwrap();
        index.publish(b, &ascii_profile, 20).unwrap();
        index.publish(c, &ascii_profile, 30).unwrap();
        assert_eq!(
            index.publish(a.clone(), &ascii_profile, 40),
            Err(Error::Stale)
        );
        let all = index
            .browse(
                &ListingQuery {
                    category: ANY_CATEGORY,
                    language: [0; 2],
                    prefix: Vec::new(),
                    page: 0,
                },
                &ascii_profile,
            )
            .unwrap();
        let names: Vec<&[u8]> = all.listings.iter().map(|l| &l.name[..]).collect();
        assert_eq!(names, [&b"alps"[..], b"Beta", b"Alpha"]);
        let al = index
            .browse(
                &ListingQuery {
                    category: 2,
                    language: *b"en",
                    prefix: b"AL".to_vec(),
                    page: 0,
                },
                &ascii_profile,
            )
            .unwrap();
        assert_eq!(al.listings.len(), 2);
        let mut withdraw = a.clone();
        withdraw.listing_index = 1;
        withdraw.link = Vec::new();
        withdraw.sign(&key_a, &mut Rng(7)).unwrap();
        index.publish(withdraw, &ascii_profile, 50).unwrap();
        assert_eq!(index.len(), 3);
        let after = index
            .browse(
                &ListingQuery {
                    category: ANY_CATEGORY,
                    language: [0; 2],
                    prefix: Vec::new(),
                    page: 0,
                },
                &ascii_profile,
            )
            .unwrap();
        assert_eq!(after.listings.len(), 2);
        index.expire(20 + LISTING_LEASE);
        assert_eq!(index.len(), 2);
        index.expire(50 + LISTING_LEASE);
        assert!(index.is_empty());
    }
}
