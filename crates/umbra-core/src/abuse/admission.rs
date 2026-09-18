//! The admission gate of Part 14 §14.2 at a relay and at an addressee:
//! what an `Admission` trailer must carry, and how each kind is checked.

use umbra_queue::Reject;
use umbra_wire::admission::{Admission, AdmissionKind};

use super::{
    epoch_number,
    pow::{self, PowSolution, Verifier},
    spend::SpendSet,
    token::{self, FirstPartyIssuer, Token, TokenChallenge, TYPE_CROSS_RELAY, TYPE_FIRST_PARTY},
};
use crate::Error;

/// The token type a relay advertises, with what verifies it.
pub enum Accepts<'a> {
    /// The cross-relay token, verified with the issuer public key alone.
    CrossRelay(&'a umbra_crypto::rsabssa::PublicKey2048),
    /// The first-party token, verified with the issuer secret.
    FirstParty(&'a FirstPartyIssuer),
}

impl Accepts<'_> {
    const fn token_type(&self) -> u16 {
        match self {
            Accepts::CrossRelay(_) => TYPE_CROSS_RELAY,
            Accepts::FirstParty(_) => TYPE_FIRST_PARTY,
        }
    }

    fn verify(&self, token: &Token) -> Result<(), Error> {
        match self {
            Accepts::CrossRelay(pk) => token::verify_cross_relay(pk, token),
            Accepts::FirstParty(issuer) => issuer.verify(token),
        }
    }
}

/// What an accepted admission was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// No credential, under an effort of 0.
    Free,
    /// A token of the epoch given.
    Token {
        /// The epoch the token answers.
        epoch: u32,
    },
    /// A proof of work.
    Pow,
}

/// The gate of one relay: its proof-of-work verifier and its spend set.
pub struct RelayGate {
    /// The redemption context of this relay, which is its `relay_id`.
    pub relay_id: [u8; 32],
    /// The proof-of-work verifier.
    pub pow: Verifier,
    /// The spend set of §14.7.
    pub spent: SpendSet,
}

impl RelayGate {
    /// A gate for `relay_id` with an effort floor of 0.
    pub fn new(relay_id: [u8; 32]) -> Self {
        RelayGate {
            relay_id,
            pow: Verifier::new(relay_id, 0),
            spent: SpendSet::default(),
        }
    }

    fn token_epoch(&self, token: &Token, now: u64) -> Option<u32> {
        let epoch = epoch_number(now);
        [epoch, epoch.wrapping_sub(1)].into_iter().find(|&e| {
            [self.relay_id, [0; 32]].iter().any(|context| {
                TokenChallenge {
                    token_type: token.token_type,
                    epoch: e,
                    redemption_context: *context,
                }
                .digest()
                    == token.challenge_digest
            })
        })
    }

    /// Admits a command that ends with `admission` at `now` (`ABU-044`
    /// to `ABU-048`, `ABU-014`). A token must be of the advertised type,
    /// answer this relay or any relay at the current or the previous
    /// epoch, and spend once; a solution must pass the verifier.
    pub fn admit(
        &mut self,
        admission: &Admission<'_>,
        accepts: &Accepts<'_>,
        now: u64,
    ) -> Result<Admitted, Reject> {
        match admission.kind {
            AdmissionKind::None => {
                if self.pow.effort() == 0 {
                    Ok(Admitted::Free)
                } else {
                    Err(Reject::Admission)
                }
            }
            AdmissionKind::Token => {
                let token = Token::parse(admission.body).map_err(|_| Reject::Admission)?;
                if token.token_type != accepts.token_type() {
                    return Err(Reject::Admission);
                }
                let epoch = self.token_epoch(&token, now).ok_or(Reject::Admission)?;
                accepts.verify(&token).map_err(|_| Reject::Admission)?;
                self.spent
                    .spend(epoch_number(now), epoch, token.nonce)
                    .map_err(|_| Reject::Admission)?;
                Ok(Admitted::Token { epoch })
            }
            AdmissionKind::Pow => {
                let solution = PowSolution::parse(admission.body).map_err(|_| Reject::Admission)?;
                self.pow.accept(&solution).map_err(|_| Reject::Admission)?;
                Ok(Admitted::Pow)
            }
        }
    }
}

/// Admits a hello at the addressee (`ABU-012`, `ABU-078` to `ABU-085`):
/// a cross-relay token under a listed issuer key of the current or the
/// previous epoch, spent once at this Profile, or a solution to the
/// derived challenge. `issuer_key_of` gives the listed key of an epoch.
pub fn admit_hello(
    admission: &Admission<'_>,
    entry_pk: &[u8],
    now: u64,
    spent: &mut SpendSet,
    issuer_key_of: &dyn Fn(u32) -> Option<umbra_crypto::rsabssa::PublicKey2048>,
) -> Result<Admitted, Error> {
    let epoch = epoch_number(now);
    match admission.kind {
        AdmissionKind::None => Err(Error::Unverified),
        AdmissionKind::Token => {
            let token = Token::parse(admission.body)?;
            if token.token_type != TYPE_CROSS_RELAY {
                return Err(Error::Unverified);
            }
            for candidate in [epoch, epoch.wrapping_sub(1)] {
                let expected = TokenChallenge {
                    token_type: TYPE_CROSS_RELAY,
                    epoch: candidate,
                    redemption_context: [0; 32],
                }
                .digest();
                if expected != token.challenge_digest {
                    continue;
                }
                let key = issuer_key_of(candidate).ok_or(Error::Unverified)?;
                token::verify_cross_relay(&key, &token)?;
                spent.spend(epoch, candidate, token.nonce)?;
                return Ok(Admitted::Token { epoch: candidate });
            }
            Err(Error::Unverified)
        }
        AdmissionKind::Pow => {
            let solution = PowSolution::parse(admission.body)?;
            pow::verify_hello(entry_pk, epoch, &solution)?;
            Ok(Admitted::Pow)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::abuse::{
        test_rng::Rng,
        token::{tests::challenge, FirstPartyRequest, FIRST_PARTY_LEN},
        EPOCH_SECONDS,
    };
    use umbra_crypto::{secret::Secret, voprf::ServerKey};

    fn first_party_token(issuer: &FirstPartyIssuer, epoch: u32, seed: u64) -> alloc::vec::Vec<u8> {
        let mut rng = Rng(seed);
        let c = challenge(TYPE_FIRST_PARTY, epoch);
        let (request, blinded) = FirstPartyRequest::new(1, &c, issuer.public(), &mut rng).unwrap();
        let batch = issuer.issue(&blinded, &mut rng).unwrap();
        let token = request.finalize(&batch, issuer.public()).unwrap().remove(0);
        let mut out = alloc::vec![0u8; FIRST_PARTY_LEN];
        token.encode(&mut out).unwrap();
        out
    }

    #[test]
    fn the_relay_gate_admits_a_free_command_a_token_once_and_a_solution() {
        let issuer =
            FirstPartyIssuer::new(ServerKey::derive(&Secret::new([1; 32]), b"fp").unwrap());
        let accepts = Accepts::FirstParty(&issuer);
        let mut gate = RelayGate::new([9; 32]);
        let now = 10 * EPOCH_SECONDS + 5;
        assert_eq!(
            gate.admit(&Admission::NONE, &accepts, now),
            Ok(Admitted::Free)
        );
        let body = first_party_token(&issuer, 10, 1);
        let token = Admission {
            kind: AdmissionKind::Token,
            body: &body,
        };
        assert_eq!(
            gate.admit(&token, &accepts, now),
            Ok(Admitted::Token { epoch: 10 })
        );
        assert_eq!(gate.admit(&token, &accepts, now), Err(Reject::Admission));
        let old = first_party_token(&issuer, 8, 2);
        let old_token = Admission {
            kind: AdmissionKind::Token,
            body: &old,
        };
        assert_eq!(
            gate.admit(&old_token, &accepts, now),
            Err(Reject::Admission)
        );
        let previous = first_party_token(&issuer, 9, 3);
        let previous_token = Admission {
            kind: AdmissionKind::Token,
            body: &previous,
        };
        assert_eq!(
            gate.admit(&previous_token, &accepts, now),
            Ok(Admitted::Token { epoch: 9 })
        );

        // Under load a free command needs a solution.
        let challenge = gate.pow.issue(2 * 64, now, &mut Rng(4)).unwrap();
        assert_eq!(
            gate.admit(&Admission::NONE, &accepts, now),
            Err(Reject::Admission)
        );
        let solution = PowSolution::solve(&[9; 32], &challenge.seed, 2, &mut Rng(5)).unwrap();
        let mut body = [0u8; 69];
        solution.encode(&mut body).unwrap();
        let pow = Admission {
            kind: AdmissionKind::Pow,
            body: &body,
        };
        assert_eq!(gate.admit(&pow, &accepts, now), Ok(Admitted::Pow));
        assert_eq!(gate.admit(&pow, &accepts, now), Err(Reject::Admission));
    }

    #[test]
    fn a_hello_needs_a_cross_relay_token_or_a_solution() {
        let mut spent = SpendSet::default();
        let entry_pk = [5u8; 1_216];
        let now = 40 * EPOCH_SECONDS + 1;
        let no_key = |_: u32| None;
        assert!(admit_hello(&Admission::NONE, &entry_pk, now, &mut spent, &no_key).is_err());
        let solution = pow::solve_hello(&entry_pk, 40, &mut Rng(1)).unwrap();
        let mut body = [0u8; 69];
        solution.encode(&mut body).unwrap();
        let pow_adm = Admission {
            kind: AdmissionKind::Pow,
            body: &body,
        };
        assert_eq!(
            admit_hello(&pow_adm, &entry_pk, now, &mut spent, &no_key).unwrap(),
            Admitted::Pow
        );
        let issuer =
            FirstPartyIssuer::new(ServerKey::derive(&Secret::new([1; 32]), b"fp").unwrap());
        let fp = first_party_token(&issuer, 40, 2);
        let fp_adm = Admission {
            kind: AdmissionKind::Token,
            body: &fp,
        };
        assert!(admit_hello(&fp_adm, &entry_pk, now, &mut spent, &no_key).is_err());
    }
}
