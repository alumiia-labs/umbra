//! The admission gate of Part 13 §13.2 at a relay. The gate states what an
//! `Admission` trailer must carry, and how the relay checks each kind. The
//! addressee of a hello checks its admission where it holds its replay set
//! (`ABU-084`).

use umbra_queue::Reject;
use umbra_wire::admission::{Admission, AdmissionKind};

use alloc::{collections::BTreeMap, vec::Vec};

use super::{
    epoch_number,
    pow::{PowSolution, Verifier},
    spend::SpendSet,
    token::{self, FirstPartyIssuer, Token, TokenChallenge, TYPE_CROSS_RELAY, TYPE_FIRST_PARTY},
    POW_CHUNK_ALLOWANCE, POW_CHUNK_FLOOR,
};
use crate::Error;

/// The token type a relay advertises, with what verifies it.
pub enum Accepts<'a> {
    /// The cross-relay token, verified with the issuer public key of its
    /// epoch alone, which the relay took from the log (Part 13 §13.5).
    CrossRelay(&'a BTreeMap<u32, umbra_crypto::rsabssa::PublicKey2048>),
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

    fn verify(&self, token: &Token, epoch: u32) -> Result<(), Error> {
        match self {
            // ABU-002: a key that the log does not name admits nothing.
            Accepts::CrossRelay(keys) => {
                token::verify_cross_relay(keys.get(&epoch).ok_or(Error::Unverified)?, token)
            }
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
    /// The spend set of §13.7.
    pub spent: SpendSet,
    /// The accepted admissions of the period that runs, the backlog of
    /// `ABU-060`. A refused admission does not count, thus a flood of bad
    /// trailers does not raise the effort of the next challenge.
    admissions: u32,
    /// The registrations that each accepted chunk solution may still admit,
    /// by its seed and its nonce, with its Equi-X bytes (`ABU-107`).
    chunk_uses: BTreeMap<SolutionKey, ([u8; 16], u16)>,
    /// The token nonces spent since the last call, each with its epoch,
    /// for the store (`ABU-114`).
    fresh: Vec<(u32, [u8; 32])>,
}

/// A solution by the seed of its challenge and its nonce.
type SolutionKey = ([u8; 32], [u8; 16]);

impl RelayGate {
    /// A gate for `relay_id` with an effort floor of 0.
    pub fn new(relay_id: [u8; 32]) -> Self {
        RelayGate {
            relay_id,
            pow: Verifier::new(relay_id, 0),
            spent: SpendSet::default(),
            admissions: 0,
            chunk_uses: BTreeMap::new(),
            fresh: Vec::new(),
        }
    }

    /// The token nonces spent since the last call, for the store.
    pub fn take_spent(&mut self) -> Vec<(u32, [u8; 32])> {
        core::mem::take(&mut self.fresh)
    }

    /// The accepted admissions since the last call, which the next
    /// challenge takes as its backlog (`ABU-060`, `ABU-092`).
    pub fn take_backlog(&mut self) -> u32 {
        core::mem::take(&mut self.admissions)
    }

    /// The epoch of the challenge that `token` answers: the current epoch
    /// or the one before it, for this relay or for any relay.
    fn token_epoch(&self, token: &Token, now: u64) -> Option<u32> {
        // A zero redemption context names no relay, thus any relay.
        let answers = |epoch: u32| {
            [self.relay_id, [0; 32]].iter().any(|context| {
                let challenge = TokenChallenge {
                    token_type: token.token_type,
                    epoch,
                    redemption_context: *context,
                };
                challenge.digest() == token.challenge_digest
            })
        };

        let epoch = epoch_number(now);
        [epoch, epoch.wrapping_sub(1)]
            .into_iter()
            .find(|&e| answers(e))
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
        let admitted = match admission.kind {
            AdmissionKind::None => {
                if self.pow.effort() == 0 {
                    Ok(Admitted::Free)
                } else {
                    Err(Reject::Admission)
                }
            }
            AdmissionKind::Token => self.admit_token(admission.body, accepts, now),
            AdmissionKind::Pow => {
                let solution = PowSolution::parse(admission.body).map_err(|_| Reject::Admission)?;
                self.pow.accept(&solution).map_err(|_| Reject::Admission)?;
                Ok(Admitted::Pow)
            }
        }?;

        // ABU-060: the backlog counts what the relay accepted. A refusal
        // costs its sender nothing, thus it must not raise the effort.
        self.admissions = self.admissions.saturating_add(1);
        Ok(admitted)
    }

    /// Checks a token and spends its nonce. It does not count the backlog.
    fn admit_token(
        &mut self,
        body: &[u8],
        accepts: &Accepts<'_>,
        now: u64,
    ) -> Result<Admitted, Reject> {
        let token = Token::parse(body).map_err(|_| Reject::Admission)?;
        if token.token_type != accepts.token_type() {
            return Err(Reject::Admission);
        }

        let epoch = self.token_epoch(&token, now).ok_or(Reject::Admission)?;
        accepts
            .verify(&token, epoch)
            .map_err(|_| Reject::Admission)?;

        self.spent
            .spend(epoch_number(now), epoch, token.nonce)
            .map_err(|_| Reject::Admission)?;
        self.fresh.push((epoch, token.nonce));
        Ok(Admitted::Token { epoch })
    }
}

impl RelayGate {
    /// Admits a `CNEW` or a `BNEW` (`ABU-106`, `ABU-107`): a token as
    /// [`RelayGate::admit`] takes it, or a solution at `POW_CHUNK_FLOOR` or
    /// above. One solution admits `POW_CHUNK_ALLOWANCE` registrations while
    /// its challenge is live, and only its first use counts in the backlog.
    /// No admission of kind `0x00` passes. The result names the holder of
    /// the upload quota: the token nonce or the solution.
    pub fn admit_chunk(
        &mut self,
        admission: &Admission<'_>,
        accepts: &Accepts<'_>,
        now: u64,
    ) -> Result<[u8; 32], Reject> {
        match admission.kind {
            AdmissionKind::None => Err(Reject::Admission),
            AdmissionKind::Token => {
                self.admit(admission, accepts, now)?;
                let token = Token::parse(admission.body).map_err(|_| Reject::Admission)?;
                Ok(holder(b"token", &token.nonce))
            }
            AdmissionKind::Pow => self.admit_chunk_pow(admission.body),
        }
    }

    /// Admits a chunk command under a solution: a further use of a held
    /// solution, or the first use of a new one.
    fn admit_chunk_pow(&mut self, body: &[u8]) -> Result<[u8; 32], Reject> {
        let solution = PowSolution::parse(body).map_err(|_| Reject::Admission)?;
        let key = (solution.seed, solution.nonce);
        let holder = holder(b"pow", &[&solution.seed[..], &solution.nonce].concat());

        // A solution to a challenge that went out of use admits nothing more.
        let pow = &self.pow;
        self.chunk_uses
            .retain(|(seed, _), _| pow.is_live_seed(seed));

        if let Some((bytes, left)) = self.chunk_uses.get_mut(&key) {
            if *bytes != solution.solution || *left == 0 {
                return Err(Reject::Admission);
            }
            *left -= 1;
            return Ok(holder);
        }

        if solution.effort < POW_CHUNK_FLOOR {
            return Err(Reject::Admission);
        }
        self.pow.accept(&solution).map_err(|_| Reject::Admission)?;
        self.admissions = self.admissions.saturating_add(1);
        self.chunk_uses.insert(
            key,
            (solution.solution, POW_CHUNK_ALLOWANCE.saturating_sub(1)),
        );
        Ok(holder)
    }
}

/// The holder of an upload quota, from what admitted the upload.
fn holder(kind: &[u8], value: &[u8]) -> [u8; 32] {
    umbra_crypto::hash::sha3_256(&[umbra_crypto::labels::QUOTA_HOLDER, kind, value])
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
    fn a_relay_verifies_a_cross_relay_token_under_the_key_of_its_epoch() {
        use crate::abuse::token::{issue_cross_relay, CrossRelayRequest};
        use umbra_crypto::rsabssa::SecretKey2048;

        let now = 40 * EPOCH_SECONDS + 1;
        let secret =
            SecretKey2048::from_seed(&Secret::new([0x4B; 32]), &40u32.to_be_bytes()).unwrap();
        let pk = secret.public();
        let (request, blinded) =
            CrossRelayRequest::new(1, &challenge(TYPE_CROSS_RELAY, 40), pk, &mut Rng(3)).unwrap();
        let signed = issue_cross_relay(&secret, &blinded).unwrap();
        let token = request.finalize(&signed, pk).unwrap().remove(0);
        let bytes = crate::discovery::dirclient::token_bytes(&token).unwrap();
        let admission = Admission {
            kind: AdmissionKind::Token,
            body: &bytes,
        };
        let mut gate = RelayGate::new([1; 32]);
        // ABU-002: a relay that holds no key of the log for the epoch of the
        // token admits nothing, and the key of another epoch does not do.
        let mut keys = BTreeMap::new();
        assert!(gate
            .admit(&admission, &Accepts::CrossRelay(&keys), now)
            .is_err());
        keys.insert(41, pk.clone());
        assert!(gate
            .admit(&admission, &Accepts::CrossRelay(&keys), now)
            .is_err());
        keys.insert(40, pk.clone());
        assert_eq!(
            gate.admit(&admission, &Accepts::CrossRelay(&keys), now),
            Ok(Admitted::Token { epoch: 40 })
        );
        // A token spends once.
        assert!(gate
            .admit(&admission, &Accepts::CrossRelay(&keys), now)
            .is_err());
    }

    #[test]
    fn the_backlog_counts_the_accepted_admissions_alone() {
        let issuer =
            FirstPartyIssuer::new(ServerKey::derive(&Secret::new([1; 32]), b"fp").unwrap());
        let accepts = Accepts::FirstParty(&issuer);
        let mut gate = RelayGate::new([9; 32]);
        let now = 10 * EPOCH_SECONDS + 5;
        // The relay refuses a token that does not parse and a solution that
        // does not parse. It refuses a chunk command with no credential too.
        // None of them counts.
        let bad_token = Admission {
            kind: AdmissionKind::Token,
            body: &[0; 7],
        };
        let bad_pow = Admission {
            kind: AdmissionKind::Pow,
            body: &[0; 69],
        };
        for _ in 0..200 {
            assert!(gate.admit(&bad_token, &accepts, now).is_err());
            assert!(gate.admit(&bad_pow, &accepts, now).is_err());
            assert!(gate.admit_chunk(&bad_pow, &accepts, now).is_err());
            assert!(gate.admit_chunk(&Admission::NONE, &accepts, now).is_err());
        }
        assert_eq!(gate.take_backlog(), 0);
        // A free command and a token count once each, and the repeat of the
        // token does not.
        gate.admit(&Admission::NONE, &accepts, now).unwrap();
        let body = first_party_token(&issuer, 10, 1);
        let token = Admission {
            kind: AdmissionKind::Token,
            body: &body,
        };
        gate.admit(&token, &accepts, now).unwrap();
        assert!(gate.admit(&token, &accepts, now).is_err());
        assert_eq!(gate.take_backlog(), 2);
        // Under load the relay refuses a command of kind `0x00`, and that
        // command does not count. One chunk solution counts at its first use
        // alone.
        let challenge = gate.pow.issue(64, now, &mut Rng(4)).unwrap();
        assert!(gate.admit(&Admission::NONE, &accepts, now).is_err());
        let solution =
            PowSolution::solve(&[9; 32], &challenge.seed, POW_CHUNK_FLOOR, &mut Rng(5)).unwrap();
        let mut body = [0u8; 69];
        solution.encode(&mut body).unwrap();
        let pow = Admission {
            kind: AdmissionKind::Pow,
            body: &body,
        };
        gate.admit_chunk(&pow, &accepts, now).unwrap();
        gate.admit_chunk(&pow, &accepts, now).unwrap();
        assert_eq!(gate.take_backlog(), 1);
    }
}
