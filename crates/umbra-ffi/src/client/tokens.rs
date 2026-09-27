//! The cross-relay tokens of this device (Part 13 §13.3.1): the tokens it
//! holds for its own hellos, the key of each epoch that the log gives, and
//! the nonces of the tokens that the hellos of strangers spent here
//! (`ABU-006`: each verifier keeps its own set).

use umbra_core::{
    abuse::token::{token_key_id, verify_cross_relay, Token, TokenChallenge, TYPE_CROSS_RELAY},
    store::{
        engine::Backend,
        record::{RowId, TableId},
        wrap::SecureElement,
    },
};
use umbra_crypto::{rand_core::CryptoRng, rsabssa::PublicKey2048};
use zeroize::Zeroizing;

use super::Client;
use crate::Error;

/// Each token that this device holds, under its nonce: the epoch, then
/// the encoded token.
const TOKENS: TableId = TableId(0x30);
/// Each key of the cross-relay issuer that the log gave, under the epoch:
/// the modulus. Each spent nonce of a token that a hello carried, under
/// the nonce with a leading byte: the epoch.
const TOKEN_STATE: TableId = TableId(0x31);
const KEY_ROW: u8 = 1;
const SPENT_ROW: u8 = 2;

/// The rows of one table, each with its value.
type Rows = Vec<(RowId, Zeroizing<Vec<u8>>)>;

fn key_key(epoch: u32) -> Vec<u8> {
    [&[KEY_ROW][..], &epoch.to_be_bytes()].concat()
}

fn spent_key(nonce: &[u8; 32]) -> Vec<u8> {
    [&[SPENT_ROW][..], nonce.as_slice()].concat()
}

impl<B: Backend, E: SecureElement> Client<B, E> {
    fn token_rows(&self, table: TableId) -> Result<Rows, Error> {
        let store = &self.open_ref()?.store;
        Ok(store
            .list(table, None)?
            .into_iter()
            .map(|(row, plain)| (row, Zeroizing::new(plain)))
            .collect())
    }

    /// Keeps tokens of `epoch` that the issuer signed and this device
    /// verified (`ABU-112`).
    pub fn put_tokens<R: CryptoRng + ?Sized>(
        &mut self,
        epoch: u32,
        tokens: &[Vec<u8>],
        rng: &mut R,
    ) -> Result<(), Error> {
        let open = self.open_mut()?;
        let mut rows = Vec::with_capacity(tokens.len());
        for token in tokens {
            let parsed = Token::parse(token).map_err(|_| Error::Malformed)?;
            rows.push(open.store.row_id(TOKENS, &parsed.nonce));
        }
        let mut batch = open.store.begin();
        for (row, token) in rows.into_iter().zip(tokens) {
            let value = [&epoch.to_be_bytes()[..], token.as_slice()].concat();
            batch.put(TOKENS, row, None, &value, rng)?;
        }
        Ok(batch.commit()?)
    }

    /// How many tokens of `epoch` this device holds.
    pub fn token_count(&self, epoch: u32) -> Result<usize, Error> {
        Ok(self
            .token_rows(TOKENS)?
            .iter()
            .filter(|(_, value)| value.get(..4) == Some(&epoch.to_be_bytes()[..]))
            .count())
    }

    /// Takes one token of `epoch` from the store for a hello, and drops the
    /// tokens of an older epoch, which no verifier takes.
    pub fn take_token(&mut self, epoch: u32) -> Result<Option<Vec<u8>>, Error> {
        let rows = self.token_rows(TOKENS)?;
        let mut taken = None;
        let mut gone = Vec::new();
        for (row, value) in rows {
            let held = value
                .get(..4)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map_or(0, u32::from_be_bytes);
            if held < epoch {
                gone.push(row);
            } else if held == epoch && taken.is_none() {
                taken = value.get(4..).map(<[u8]>::to_vec);
                gone.push(row);
            }
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in gone {
            batch.delete(TOKENS, row);
        }
        batch.commit()?;
        Ok(taken)
    }

    /// Keeps the key of the cross-relay issuer of `epoch`, after the client
    /// verified it under the log (`ABU-002`, `ABU-099`).
    pub fn put_cross_relay_key<R: CryptoRng + ?Sized>(
        &mut self,
        epoch: u32,
        modulus: &[u8],
        rng: &mut R,
    ) -> Result<(), Error> {
        PublicKey2048::from_modulus(modulus).map_err(|_| Error::Malformed)?;
        let open = self.open_mut()?;
        let row = open.store.row_id(TOKEN_STATE, &key_key(epoch));
        let mut batch = open.store.begin();
        batch.put(TOKEN_STATE, row, None, modulus, rng)?;
        Ok(batch.commit()?)
    }

    /// The key of the cross-relay issuer of `epoch`, when the log gave it.
    pub fn cross_relay_key(&self, epoch: u32) -> Result<Option<PublicKey2048>, Error> {
        let store = &self.open_ref()?.store;
        let row = store.row_id(TOKEN_STATE, &key_key(epoch));
        Ok(store
            .get(TOKEN_STATE, &row)?
            .and_then(|modulus| PublicKey2048::from_modulus(&modulus).ok()))
    }

    /// Checks a cross-relay token that a hello carried (`DIS-182`): a key
    /// of this epoch or of the one before that the log gave, the challenge
    /// of that epoch, the signature, and a nonce that no hello spent here.
    /// The nonce is spent when the check holds.
    pub fn admit_token<R: CryptoRng + ?Sized>(
        &mut self,
        token: &[u8],
        epoch: u32,
        rng: &mut R,
    ) -> Result<bool, Error> {
        let Ok(token) = Token::parse(token) else {
            return Ok(false);
        };
        if token.token_type != TYPE_CROSS_RELAY {
            return Ok(false);
        }
        let mut admitted = None;
        for held in [epoch, epoch.saturating_sub(1)] {
            let Some(key) = self.cross_relay_key(held)? else {
                continue;
            };
            let challenge = TokenChallenge {
                token_type: TYPE_CROSS_RELAY,
                epoch: held,
                redemption_context: [0; 32],
            };
            if token.token_key_id == token_key_id(key.modulus())
                && token.challenge_digest == challenge.digest()
                && verify_cross_relay(&key, &token).is_ok()
            {
                admitted = Some(held);
                break;
            }
        }
        let Some(held) = admitted else {
            return Ok(false);
        };
        let open = self.open_mut()?;
        let row = open.store.row_id(TOKEN_STATE, &spent_key(&token.nonce));
        if open.store.get(TOKEN_STATE, &row)?.is_some() {
            return Ok(false);
        }
        let mut batch = open.store.begin();
        batch.put(TOKEN_STATE, row, None, &held.to_be_bytes(), rng)?;
        batch.commit()?;
        self.prune_token_state(epoch)?;
        Ok(true)
    }

    /// Drops the keys and the spent nonces older than the epoch before
    /// `epoch`, which no token of now names (§13.6).
    fn prune_token_state(&mut self, epoch: u32) -> Result<(), Error> {
        let floor = epoch.saturating_sub(1);
        let mut gone = Vec::new();
        for (row, value) in self.token_rows(TOKEN_STATE)? {
            // A spent row holds its epoch; a key row holds a modulus, and
            // its epoch sits in its key, which the list does not give.
            if value.len() == 4 {
                let held = <[u8; 4]>::try_from(value.as_slice()).map_or(0, u32::from_be_bytes);
                if held < floor {
                    gone.push(row);
                }
            }
        }
        for held in floor.saturating_sub(4)..floor {
            let store = &self.open_ref()?.store;
            gone.push(store.row_id(TOKEN_STATE, &key_key(held)));
        }
        let open = self.open_mut()?;
        let mut batch = open.store.begin();
        for row in gone {
            batch.delete(TOKEN_STATE, row);
        }
        Ok(batch.commit()?)
    }
}
