//! The two token types of Part 13 §13.3: the token layout of RFC 9578, the
//! challenge that binds a token to an epoch and a redemption context, the
//! batched issuance at the client and at the issuer, and the verification
//! at a relay or at an addressee.

use alloc::vec::Vec;

use umbra_crypto::{
    ct_eq,
    hash::sha3_256,
    rand_core::TryCryptoRng,
    rsabssa::{self, BlindInverse, PublicKey2048, SecretKey2048, LIMBS_2048, MODULUS_LEN_2048},
    voprf::{self, BatchEvaluation, BlindState, ServerKey},
};
use umbra_wire::codec::{Reader, Writer};

use super::BATCH_MAX;
use crate::Error;

/// The cross-relay token type of §13.3.1.
pub const TYPE_CROSS_RELAY: u16 = 0x0002;
/// The first-party token type of §13.3.2.
pub const TYPE_FIRST_PARTY: u16 = 0x0005;
/// The bytes before the authenticator.
pub const TOKEN_HEAD: usize = 2 + 32 + 32 + 32;
/// A cross-relay token.
pub const CROSS_RELAY_LEN: usize = TOKEN_HEAD + MODULUS_LEN_2048;
/// A first-party token.
pub const FIRST_PARTY_LEN: usize = TOKEN_HEAD + voprf::OUTPUT_LEN;
/// A `TokenChallenge`.
pub const CHALLENGE_LEN: usize = 2 + 4 + 32;

/// The authenticator length of a type, or `None` for a type this
/// specification does not hold.
pub const fn authenticator_len(token_type: u16) -> Option<usize> {
    match token_type {
        TYPE_CROSS_RELAY => Some(MODULUS_LEN_2048),
        TYPE_FIRST_PARTY => Some(voprf::OUTPUT_LEN),
        _ => None,
    }
}

/// `token_key_id = SHA3-256(issuer public key bytes)` (`ABU-093`).
pub fn token_key_id(public_key: &[u8]) -> [u8; 32] {
    sha3_256(&[public_key])
}

/// The challenge a token answers (`ABU-094`): the type, the epoch, and
/// the redemption context, which is the `relay_id` of one relay or zero
/// bytes for any relay of the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenChallenge {
    /// The token type.
    pub token_type: u16,
    /// The epoch of §13.6.
    pub epoch: u32,
    /// The redemption context.
    pub redemption_context: [u8; 32],
}

impl TokenChallenge {
    /// The bytes.
    pub fn to_bytes(&self) -> [u8; CHALLENGE_LEN] {
        let mut out = [0u8; CHALLENGE_LEN];
        let mut w = Writer::new(&mut out);
        let _ = w.u16(self.token_type);
        let _ = w.u32(self.epoch);
        let _ = w.put(&self.redemption_context);
        out
    }

    /// `challenge_digest = SHA3-256(TokenChallenge)`.
    pub fn digest(&self) -> [u8; 32] {
        sha3_256(&[&self.to_bytes()])
    }
}

/// A token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The type.
    pub token_type: u16,
    /// From the client CSPRNG.
    pub nonce: [u8; 32],
    /// The digest of the `TokenChallenge`.
    pub challenge_digest: [u8; 32],
    /// The id of the issuer key.
    pub token_key_id: [u8; 32],
    /// The authenticator: 256 bytes for the cross-relay type, 64 for the
    /// first-party type.
    pub authenticator: Vec<u8>,
}

impl Token {
    /// The encoded length.
    pub fn len(&self) -> usize {
        TOKEN_HEAD + self.authenticator.len()
    }

    /// Whether the authenticator is empty. Clippy asks for this beside
    /// `len`.
    pub fn is_empty(&self) -> bool {
        self.authenticator.is_empty()
    }

    /// `token_input = token_type || nonce || challenge_digest ||
    /// token_key_id`.
    pub fn input(&self) -> [u8; TOKEN_HEAD] {
        token_input(
            self.token_type,
            &self.nonce,
            &self.challenge_digest,
            &self.token_key_id,
        )
    }

    /// Writes the token.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if authenticator_len(self.token_type) != Some(self.authenticator.len()) {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.put(&self.input())?;
        w.put(&self.authenticator)?;
        Ok(w.position())
    }

    /// Reads a token.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let token_type = r.u16()?;
        let auth_len = authenticator_len(token_type).ok_or(Error::Malformed)?;
        let nonce = r.array()?;
        let challenge_digest = r.array()?;
        let token_key_id = r.array()?;
        let authenticator = r.take(auth_len)?.to_vec();
        r.finish()?;
        Ok(Token {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator,
        })
    }
}

fn token_input(
    token_type: u16,
    nonce: &[u8; 32],
    challenge_digest: &[u8; 32],
    token_key_id: &[u8; 32],
) -> [u8; TOKEN_HEAD] {
    let mut out = [0u8; TOKEN_HEAD];
    let mut w = Writer::new(&mut out);
    let _ = w.u16(token_type);
    let _ = w.put(nonce);
    let _ = w.put(challenge_digest);
    let _ = w.put(token_key_id);
    out
}

/// A batch request for first-party tokens at the client.
pub struct FirstPartyRequest {
    states: Vec<BlindState>,
    nonces: Vec<[u8; 32]>,
    challenge_digest: [u8; 32],
    token_key_id: [u8; 32],
}

impl FirstPartyRequest {
    /// Blinds `count` token inputs under `challenge` for the issuer key
    /// `issuer_pk`, and returns the blinded elements to send.
    pub fn new<R: TryCryptoRng + ?Sized>(
        count: usize,
        challenge: &TokenChallenge,
        issuer_pk: &[u8; 32],
        rng: &mut R,
    ) -> Result<(Self, Vec<[u8; 32]>), Error> {
        if count == 0 || count > BATCH_MAX || challenge.token_type != TYPE_FIRST_PARTY {
            return Err(Error::Malformed);
        }
        let challenge_digest = challenge.digest();
        let token_key_id = token_key_id(issuer_pk);
        let mut states = Vec::with_capacity(count);
        let mut nonces = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let mut nonce = [0u8; 32];
            rng.try_fill_bytes(&mut nonce)
                .map_err(|_| Error::Unverified)?;
            let input = token_input(TYPE_FIRST_PARTY, &nonce, &challenge_digest, &token_key_id);
            let (state, element) = BlindState::blind(&input, rng)?;
            states.push(state);
            nonces.push(nonce);
            blinded.push(element);
        }
        Ok((
            FirstPartyRequest {
                states,
                nonces,
                challenge_digest,
                token_key_id,
            },
            blinded,
        ))
    }

    /// The blinded elements again, for a retry.
    pub fn blinded(&self) -> Vec<[u8; 32]> {
        self.states
            .iter()
            .map(BlindState::blinded_element)
            .collect()
    }

    /// Verifies the batch proof under `issuer_pk` and finalizes the
    /// tokens.
    pub fn finalize(
        &self,
        batch: &BatchEvaluation,
        issuer_pk: &[u8; 32],
    ) -> Result<Vec<Token>, Error> {
        let blinded = self.blinded();
        voprf::verify_proof_batch(issuer_pk, &blinded, &batch.elements, &batch.proof)?;
        self.states
            .iter()
            .zip(&self.nonces)
            .zip(&batch.elements)
            .map(|((state, nonce), element)| {
                Ok(Token {
                    token_type: TYPE_FIRST_PARTY,
                    nonce: *nonce,
                    challenge_digest: self.challenge_digest,
                    token_key_id: self.token_key_id,
                    authenticator: state.unblind(element)?.to_vec(),
                })
            })
            .collect()
    }
}

/// The first-party issuer, which is also the verifier at a relay that
/// the nonprofit operates.
pub struct FirstPartyIssuer {
    key: ServerKey,
    key_id: [u8; 32],
}

impl FirstPartyIssuer {
    /// An issuer over `key`.
    pub fn new(key: ServerKey) -> Self {
        let key_id = token_key_id(key.public());
        FirstPartyIssuer { key, key_id }
    }

    /// The public key.
    pub const fn public(&self) -> &[u8; 32] {
        self.key.public()
    }

    /// The key id.
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Issues a batch: one evaluation and one proof (`ABU-016` needs no
    /// identifier here, and the batch bound holds).
    pub fn issue<R: TryCryptoRng + ?Sized>(
        &self,
        blinded: &[[u8; 32]],
        rng: &mut R,
    ) -> Result<BatchEvaluation, Error> {
        if blinded.is_empty() || blinded.len() > BATCH_MAX {
            return Err(Error::Malformed);
        }
        Ok(self.key.evaluate_batch(blinded, rng)?)
    }

    /// Verifies a token under the issuer secret, in constant time.
    pub fn verify(&self, token: &Token) -> Result<(), Error> {
        if token.token_type != TYPE_FIRST_PARTY || token.token_key_id != self.key_id {
            return Err(Error::Unverified);
        }
        let expected = self.key.evaluate_direct(&token.input());
        if ct_eq(&expected, &token.authenticator) {
            Ok(())
        } else {
            Err(Error::Unverified)
        }
    }
}

/// A batch request for cross-relay tokens at the client.
pub struct CrossRelayRequest {
    inverses: Vec<BlindInverse<LIMBS_2048>>,
    inputs: Vec<[u8; TOKEN_HEAD]>,
    nonces: Vec<[u8; 32]>,
    challenge_digest: [u8; 32],
    token_key_id: [u8; 32],
}

impl CrossRelayRequest {
    /// Blinds `count` token inputs under `challenge` for `issuer_pk`, and
    /// returns the blinded messages to send.
    pub fn new<R: TryCryptoRng + ?Sized>(
        count: usize,
        challenge: &TokenChallenge,
        issuer_pk: &PublicKey2048,
        rng: &mut R,
    ) -> Result<(Self, Vec<Vec<u8>>), Error> {
        if count == 0 || count > BATCH_MAX || challenge.token_type != TYPE_CROSS_RELAY {
            return Err(Error::Malformed);
        }
        let challenge_digest = challenge.digest();
        let token_key_id = token_key_id(issuer_pk.modulus());
        let mut inverses = Vec::with_capacity(count);
        let mut inputs = Vec::with_capacity(count);
        let mut nonces = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let mut nonce = [0u8; 32];
            rng.try_fill_bytes(&mut nonce)
                .map_err(|_| Error::Unverified)?;
            let input = token_input(TYPE_CROSS_RELAY, &nonce, &challenge_digest, &token_key_id);
            let (msg, inverse) = rsabssa::blind(issuer_pk, &input, rng)?;
            inverses.push(inverse);
            inputs.push(input);
            nonces.push(nonce);
            blinded.push(msg);
        }
        Ok((
            CrossRelayRequest {
                inverses,
                inputs,
                nonces,
                challenge_digest,
                token_key_id,
            },
            blinded,
        ))
    }

    /// Finalizes the tokens from the blind signatures, each verified
    /// under `issuer_pk`.
    pub fn finalize(
        &self,
        blind_sigs: &[Vec<u8>],
        issuer_pk: &PublicKey2048,
    ) -> Result<Vec<Token>, Error> {
        if blind_sigs.len() != self.inverses.len() {
            return Err(Error::Malformed);
        }
        self.inverses
            .iter()
            .zip(&self.inputs)
            .zip(&self.nonces)
            .zip(blind_sigs)
            .map(|(((inverse, input), nonce), blind_sig)| {
                Ok(Token {
                    token_type: TYPE_CROSS_RELAY,
                    nonce: *nonce,
                    challenge_digest: self.challenge_digest,
                    token_key_id: self.token_key_id,
                    authenticator: rsabssa::finalize(issuer_pk, input, blind_sig, inverse)?,
                })
            })
            .collect()
    }
}

/// Signs a batch of blinded messages at the cross-relay issuer.
pub fn issue_cross_relay(key: &SecretKey2048, blinded: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Error> {
    if blinded.is_empty() || blinded.len() > BATCH_MAX {
        return Err(Error::Malformed);
    }
    blinded.iter().map(|msg| Ok(key.blind_sign(msg)?)).collect()
}

/// Verifies a cross-relay token with the public key of the issuer alone
/// (`ABU-078`).
pub fn verify_cross_relay(issuer_pk: &PublicKey2048, token: &Token) -> Result<(), Error> {
    if token.token_type != TYPE_CROSS_RELAY
        || token.token_key_id != token_key_id(issuer_pk.modulus())
    {
        return Err(Error::Unverified);
    }
    rsabssa::verify(issuer_pk, &token.input(), &token.authenticator)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
pub(crate) mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;
    use umbra_crypto::secret::Secret;

    pub(crate) fn challenge(token_type: u16, epoch: u32) -> TokenChallenge {
        TokenChallenge {
            token_type,
            epoch,
            redemption_context: [0; 32],
        }
    }

    #[test]
    fn first_party_tokens_issue_in_a_batch_and_verify_at_the_issuer() {
        let issuer =
            FirstPartyIssuer::new(ServerKey::derive(&Secret::new([1; 32]), b"fp").unwrap());
        let c = challenge(TYPE_FIRST_PARTY, 3);
        let mut rng = Rng(1);
        let (request, blinded) = FirstPartyRequest::new(3, &c, issuer.public(), &mut rng).unwrap();
        let batch = issuer.issue(&blinded, &mut rng).unwrap();
        let tokens = request.finalize(&batch, issuer.public()).unwrap();
        assert_eq!(tokens.len(), 3);
        for t in &tokens {
            assert_eq!(t.len(), FIRST_PARTY_LEN);
            issuer.verify(t).unwrap();
            let mut out = [0u8; FIRST_PARTY_LEN];
            assert_eq!(t.encode(&mut out).unwrap(), 162);
            assert_eq!(&Token::parse(&out).unwrap(), t);
        }
        let mut forged = tokens[0].clone();
        forged.nonce[0] ^= 1;
        assert!(issuer.verify(&forged).is_err());
        let other = FirstPartyIssuer::new(ServerKey::derive(&Secret::new([2; 32]), b"fp").unwrap());
        assert!(other.verify(&tokens[0]).is_err());
        let wrong_key = request.finalize(&batch, other.public());
        assert!(wrong_key.is_err());
        assert!(FirstPartyRequest::new(0, &c, issuer.public(), &mut rng).is_err());
        assert!(FirstPartyRequest::new(BATCH_MAX + 1, &c, issuer.public(), &mut rng).is_err());
        assert!(Token::parse(&[0u8; 100]).is_err());
    }

    #[test]
    fn the_challenge_digest_binds_the_epoch_and_the_context() {
        let a = challenge(TYPE_CROSS_RELAY, 1).digest();
        let b = challenge(TYPE_CROSS_RELAY, 2).digest();
        let c = TokenChallenge {
            redemption_context: [7; 32],
            ..challenge(TYPE_CROSS_RELAY, 1)
        }
        .digest();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(authenticator_len(0x0001), None);
        assert_ne!(token_key_id(&[1; 32]), token_key_id(&[2; 32]));
    }
}
