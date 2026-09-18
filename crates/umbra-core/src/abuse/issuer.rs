//! The issuer keys a client accepts (Part 14 §14.5, §14.6): one key of
//! each type for each epoch, from the transparency log. The log object
//! itself is a later step; this holds what the client verified from it.

use alloc::{collections::BTreeMap, vec::Vec};

use super::token::{authenticator_len, token_key_id, Token};
use crate::Error;

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

    /// Drops each key older than the epoch before `epoch`.
    pub fn retire(&mut self, epoch: u32) {
        self.keys
            .retain(|(_, e), _| *e == epoch || *e == epoch.wrapping_sub(1));
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
        keys.retire(7);
        assert_eq!(keys.epoch_of(&token), None);
        assert_eq!(keys.key(TYPE_FIRST_PARTY, 6), Some(&[2u8; 32][..]));
    }
}
