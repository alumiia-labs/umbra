//! The noised chain count of Part 10 §10.8: the two shares that a relay
//! keeps for each epoch, the signed query of an aggregator, and the sum that
//! an authority reads (`REL-189` to `REL-194`).

use alloc::vec::Vec;

use umbra_crypto::{
    labels,
    rand_core::CryptoRng,
    sign::{SigningKey, SIGNATURE_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::root::DirectoryKeySet;
use crate::Error;

/// The encoded width of a `StatQuery`.
pub const STAT_QUERY_LEN: usize = 1 + 1 + 8 + SIGNATURE_LEN;
/// The encoded width of a `StatAnswer`.
pub const STAT_ANSWER_LEN: usize = 1 + 1 + 8;
/// The aggregators: the authorities at index 0 and index 1 of the key set
/// (`REL-192`).
pub const AGGREGATORS: u8 = 2;
/// `RECEIPT_QUERY_MAX`: the queries of one authority at one relay in one
/// epoch, a query of this module included (`REL-186`).
pub const RECEIPT_QUERY_MAX: u32 = 64;
/// The scale `b` of the Laplace noise of a chain count: σ = 1 chain at
/// ε = 0.1 (§10.8).
pub const CHAIN_NOISE_SCALE: f64 = 10.0;

/// The two shares of one count: share 0 is `count + r` and share 1 is
/// `−r`, modulo 2⁶⁴ (`REL-190`).
pub fn split<R: CryptoRng + ?Sized>(count: u64, rng: &mut R) -> [u64; 2] {
    let r = rng.next_u64();
    [count.wrapping_add(r), r.wrapping_neg()]
}

/// The count that two noised shares give: their sum modulo 2⁶⁴, read as a
/// signed value, and 0 for a negative sum (`REL-194`).
pub fn combine(noised: [u64; 2]) -> u64 {
    let [one, other] = noised;
    let sum = one.wrapping_add(other).cast_signed();
    sum.max(0).cast_unsigned()
}

/// Adds a noise sample to a share, modulo 2⁶⁴ (`REL-193`).
pub fn add_noise(share: u64, noise: i64) -> u64 {
    share.wrapping_add(noise.cast_unsigned())
}

/// The query of an aggregator for its share of one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatQuery {
    /// The index of the aggregator in the key set.
    pub authority_index: u8,
    /// The consensus epoch of the count.
    pub epoch: u64,
}

impl StatQuery {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STAT_QUERY_LEN);
        out.push(0x01);
        out.push(self.authority_index);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out
    }

    /// Signs the query with the key of its aggregator.
    pub fn sign<R: CryptoRng + ?Sized>(&self, key: &SigningKey, rng: &mut R) -> Result<Vec<u8>, Error> {
        let body = self.body();
        let sig = key.sign(&[labels::STAT_QUERY, &body].concat(), rng)?;
        Ok([body.as_slice(), &sig.to_bytes()].concat())
    }

    /// Reads a query and verifies it under `keyset`. A query of an
    /// authority that is no aggregator does not verify (`REL-192`).
    pub fn verify(bytes: &[u8], keyset: &DirectoryKeySet<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let query = StatQuery {
            authority_index: r.u8()?,
            epoch: u64::from_be_bytes(r.array()?),
        };
        let sig = r.take(SIGNATURE_LEN)?;
        r.finish()?;
        if query.authority_index >= AGGREGATORS {
            return Err(Error::Unverified);
        }
        let preimage = [labels::STAT_QUERY, &query.body()].concat();
        keyset.verify_by(query.authority_index, &preimage, sig)?;
        Ok(query)
    }
}

/// The answer of a relay: its share for the aggregator, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatAnswer {
    /// The share, when the relay holds the shares of the epoch.
    pub share: Option<u64>,
}

impl StatAnswer {
    /// Writes the answer.
    pub fn encode(&self) -> [u8; STAT_ANSWER_LEN] {
        let mut out = [0u8; STAT_ANSWER_LEN];
        let mut w = Writer::new(&mut out);
        // The buffer holds each field, thus no write fails.
        let _ = w.u8(0x01);
        let _ = w.u8(u8::from(self.share.is_some()));
        let _ = w.put(&self.share.unwrap_or(0).to_be_bytes());
        out
    }

    /// Reads an answer.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let found = r.u8()?;
        let share = u64::from_be_bytes(r.array()?);
        r.finish()?;
        match found {
            0x00 if share == 0 => Ok(StatAnswer { share: None }),
            0x01 => Ok(StatAnswer { share: Some(share) }),
            _ => Err(Error::Malformed),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::directory::{descriptor::tests::Rng, root::tests::authorities};

    #[test]
    fn two_shares_give_the_count_and_one_share_gives_nothing() {
        let mut rng = Rng(3);
        let shares = split(412, &mut rng);
        assert_eq!(combine(shares), 412);
        // REL-194: the noise of each aggregator adds, and a negative sum is 0.
        assert_eq!(combine([add_noise(shares[0], -7), add_noise(shares[1], 3)]), 408);
        let small = split(2, &mut rng);
        assert_eq!(combine([add_noise(small[0], -9), small[1]]), 0);
    }

    #[test]
    fn an_aggregator_alone_asks_for_a_share() {
        let mut rng = Rng(4);
        let keys = authorities(40);
        let pks: Vec<_> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let keyset = DirectoryKeySet {
            keyset_epoch: 1,
            independent_count: 7,
            keys: pks.iter().map(|k| &k[..]).collect(),
        };
        let query = StatQuery {
            authority_index: 1,
            epoch: 77,
        };
        let signed = query.sign(&keys[1], &mut rng).unwrap();
        assert_eq!(signed.len(), STAT_QUERY_LEN);
        assert_eq!(StatQuery::verify(&signed, &keyset).unwrap(), query);
        // REL-192: authority 2 is no aggregator.
        let other = StatQuery {
            authority_index: 2,
            epoch: 77,
        };
        let signed = other.sign(&keys[2], &mut rng).unwrap();
        assert!(StatQuery::verify(&signed, &keyset).is_err());
        // A signature of another authority does not verify.
        let forged = query.sign(&keys[0], &mut rng).unwrap();
        assert!(StatQuery::verify(&forged, &keyset).is_err());
        for answer in [StatAnswer { share: None }, StatAnswer { share: Some(9) }] {
            assert_eq!(StatAnswer::parse(&answer.encode()).unwrap(), answer);
        }
    }
}
