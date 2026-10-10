//! The issuer keys a client accepts (Part 13 §13.5, §13.6): one key of
//! each type for each epoch, from the transparency log. The log is the
//! combined tree of Part 9 §9.5.1. An issuer key is the entry of the label
//! `"umbra/v1/issuer-key" || token_type || epoch`, and that label holds
//! version 0 and no other.

use alloc::{collections::BTreeMap, vec::Vec};

use umbra_crypto::{labels, vrf};
use umbra_wire::codec::{Reader, Writer};

use super::token::{authenticator_len, token_key_id, Token};
use crate::{
    discovery::{head::AcceptedHead, translog::LookupProof},
    Error,
};

/// The label input of one issuer key, which the client blinds in the
/// lookup of Part 9 §9.4 as it blinds a handle.
pub fn issuer_label_input(token_type: u16, epoch: u32) -> Vec<u8> {
    [
        labels::ISSUER_KEY,
        &token_type.to_be_bytes(),
        &epoch.to_be_bytes(),
    ]
    .concat()
}

/// The entry of one issuer key in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerKeyEntry {
    /// The token type of Part 13 §13.3.
    pub token_type: u16,
    /// The epoch of Part 13 §13.6.
    pub epoch: u32,
    /// The public key of the issuer for that type and that epoch.
    pub public_key: Vec<u8>,
}

impl IssuerKeyEntry {
    /// Encodes the entry.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; 8 + self.public_key.len()];
        let mut w = Writer::new(&mut out);
        w.u16(self.token_type)?;
        w.u32(self.epoch)?;
        w.u16(u16::try_from(self.public_key.len()).map_err(|_| Error::Malformed)?)?;
        w.put(&self.public_key)?;
        Ok(out)
    }

    /// Reads an entry.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let token_type = r.u16()?;
        let epoch = r.u32()?;
        let key_len = usize::from(r.u16()?);
        let public_key = r.take(key_len)?.to_vec();
        r.finish()?;
        Ok(IssuerKeyEntry {
            token_type,
            epoch,
            public_key,
        })
    }
}

/// The keys of the issuer that a client accepted from the log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssuerKeys {
    keys: BTreeMap<(u16, u32), Vec<u8>>,
}

impl IssuerKeys {
    /// Records the key of `token_type` at `epoch` (`ABU-004`): one key for
    /// each type in each epoch, and no second key for the same pair.
    pub fn accept(&mut self, token_type: u16, epoch: u32, public_key: &[u8]) -> Result<(), Error> {
        if authenticator_len(token_type).is_none() {
            return Err(Error::Malformed);
        }
        match self.keys.get(&(token_type, epoch)) {
            Some(held) if held == public_key => Ok(()),
            Some(_) => Err(Error::Stale),
            None => {
                self.keys.insert((token_type, epoch), public_key.to_vec());
                Ok(())
            }
        }
    }

    /// Accepts the key of `token_type` at `epoch` from a lookup proof
    /// under an accepted head (`ABU-002`). The label holds version 0 and no
    /// other: a second version is a second key for one epoch, which is the
    /// per-client-key attack that the log exists to show.
    pub fn accept_from_log(
        &mut self,
        token_type: u16,
        epoch: u32,
        proof: &LookupProof,
        search_key: &[u8],
        vrf_key: &vrf::PublicKey,
        head: &AcceptedHead,
    ) -> Result<(), Error> {
        let bytes = proof
            .verify(search_key, vrf_key, head)?
            .ok_or(Error::Unverified)?;
        let entry = IssuerKeyEntry::parse(bytes)?;
        if proof.newest != Some(0) || entry.token_type != token_type || entry.epoch != epoch {
            return Err(Error::Unverified);
        }
        self.accept(token_type, epoch, &entry.public_key)
    }

    /// The key of `token_type` at `epoch`.
    pub fn key(&self, token_type: u16, epoch: u32) -> Option<&[u8]> {
        self.keys.get(&(token_type, epoch)).map(Vec::as_slice)
    }

    /// The epoch of the listed key that `token` names, or `None` when no
    /// listed key has that id (`ABU-002`).
    pub fn epoch_of(&self, token: &Token) -> Option<u32> {
        self.keys
            .iter()
            .find(|((t, _), key)| *t == token.token_type && token_key_id(key) == token.token_key_id)
            .map(|((_, epoch), _)| *epoch)
    }

    /// Whether a relay advertises a listed key (`ABU-003`).
    pub fn is_listed(&self, token_type: u16, key_id: &[u8; 32]) -> bool {
        self.keys
            .iter()
            .any(|((t, _), key)| *t == token_type && token_key_id(key) == *key_id)
    }

    /// Drops each key older than the epoch before `epoch`. The key of the
    /// next epoch stays (`ABU-113`).
    pub fn retire(&mut self, epoch: u32) {
        let oldest = epoch.saturating_sub(1);
        self.keys.retain(|(_, e), _| *e >= oldest);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::abuse::token::TYPE_FIRST_PARTY;

    #[test]
    fn one_key_for_each_type_in_each_epoch() {
        let mut keys = IssuerKeys::default();
        keys.accept(TYPE_FIRST_PARTY, 5, &[1; 32]).unwrap();
        keys.accept(TYPE_FIRST_PARTY, 5, &[1; 32]).unwrap();
        assert_eq!(
            keys.accept(TYPE_FIRST_PARTY, 5, &[2; 32]),
            Err(Error::Stale)
        );
        assert!(keys.accept(0x0001, 5, &[2; 32]).is_err());
        keys.accept(TYPE_FIRST_PARTY, 6, &[2; 32]).unwrap();
        assert_eq!(keys.key(TYPE_FIRST_PARTY, 5), Some(&[1u8; 32][..]));
        assert!(keys.is_listed(TYPE_FIRST_PARTY, &token_key_id(&[2; 32])));
        assert!(!keys.is_listed(TYPE_FIRST_PARTY, &token_key_id(&[3; 32])));
        let token = Token {
            token_type: TYPE_FIRST_PARTY,
            nonce: [0; 32],
            challenge_digest: [0; 32],
            token_key_id: token_key_id(&[1; 32]),
            authenticator: alloc::vec![0; 64],
        };
        assert_eq!(keys.epoch_of(&token), Some(5));
        // ABU-113: a client holds the key of the next epoch ahead of time,
        // and a retire at the current epoch keeps it.
        keys.accept(TYPE_FIRST_PARTY, 8, &[4; 32]).unwrap();
        keys.retire(7);
        assert_eq!(keys.epoch_of(&token), None);
        assert_eq!(keys.key(TYPE_FIRST_PARTY, 6), Some(&[2u8; 32][..]));
        assert_eq!(keys.key(TYPE_FIRST_PARTY, 8), Some(&[4u8; 32][..]));
    }

    #[test]
    fn a_key_enters_from_the_log_and_a_second_key_for_one_epoch_does_not() {
        use umbra_crypto::secret::Secret;

        use crate::discovery::translog::LogOperator;

        let mut log = LogOperator::new(vrf::SecretKey::from_seed(&Secret::new([3; 32])));
        let vrf_key = vrf::PublicKey::from_bytes(log.vrf_public()).unwrap();
        // The search key is the VOPRF output over the label input. A fixed
        // value stands in for it here.
        let search_key = [7u8; 64];
        let entry = IssuerKeyEntry {
            token_type: TYPE_FIRST_PARTY,
            epoch: 5,
            public_key: alloc::vec![1; 32],
        };
        assert_eq!(
            IssuerKeyEntry::parse(&entry.encode().unwrap()).unwrap(),
            entry
        );
        assert_eq!(
            issuer_label_input(TYPE_FIRST_PARTY, 5).len(),
            labels::ISSUER_KEY.len() + 6
        );
        log.stage(&search_key, entry.encode().unwrap(), [9; 32])
            .unwrap();
        log.close_epoch([0xA0; 32]).unwrap();
        let head = |log: &LogOperator| {
            let (tree_size, root) = log.head().unwrap();
            AcceptedHead {
                tree_size,
                root,
                timestamp: 0,
                accepted_at: 0,
            }
        };

        let mut keys = IssuerKeys::default();
        let proof = log.lookup(&search_key).unwrap();
        assert!(keys
            .accept_from_log(
                TYPE_FIRST_PARTY,
                6,
                &proof,
                &search_key,
                &vrf_key,
                &head(&log)
            )
            .is_err());
        keys.accept_from_log(
            TYPE_FIRST_PARTY,
            5,
            &proof,
            &search_key,
            &vrf_key,
            &head(&log),
        )
        .unwrap();
        assert_eq!(keys.key(TYPE_FIRST_PARTY, 5), Some(&[1u8; 32][..]));

        // A coerced issuer that writes a second key for the epoch makes a
        // second version, and each client refuses the label from then on.
        let second = IssuerKeyEntry {
            public_key: alloc::vec![2; 32],
            ..entry
        };
        log.stage(&search_key, second.encode().unwrap(), [8; 32])
            .unwrap();
        log.close_epoch([0xA1; 32]).unwrap();
        let proof = log.lookup(&search_key).unwrap();
        let mut fresh = IssuerKeys::default();
        assert!(fresh
            .accept_from_log(
                TYPE_FIRST_PARTY,
                5,
                &proof,
                &search_key,
                &vrf_key,
                &head(&log)
            )
            .is_err());
        assert!(fresh.key(TYPE_FIRST_PARTY, 5).is_none());
    }
}
