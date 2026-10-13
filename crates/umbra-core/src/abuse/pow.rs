//! The proof of work of Part 13 §13.8: the signed challenge, the
//! solution, the verifier with its two live seeds and its accepted
//! nonces, the effort from the backlog, the client that solves a fetched
//! challenge inside its period, and the derived challenge of a hello of
//! §13.4.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use umbra_crypto::{
    labels, pow as equix,
    rand_core::TryCryptoRng,
    sign::{Signature, SigningKey, VerifyingKey, SIGNATURE_LEN},
};
use umbra_wire::codec::{Reader, Writer};

use super::{
    HELLO_POW_EFFORT, POW_BACKLOG_UNIT, POW_CHALLENGE_PERIOD, POW_CHUNK_ALLOWANCE, POW_CHUNK_FLOOR,
    POW_EFFORT_MAX,
};
use crate::{discovery::hello::HelloPow, Error};

/// The length of a `PowChallenge`.
pub const CHALLENGE_LEN: usize = 1 + 32 + 1 + 32 + 4 + 8 + SIGNATURE_LEN;
const _: () = assert!(CHALLENGE_LEN == umbra_wire::capsule::CHALLENGE_LEN);
/// The bytes of a challenge before `sig`.
pub const CHALLENGE_SIGNED_LEN: usize = CHALLENGE_LEN - SIGNATURE_LEN;
/// The length of a `PowSolution`.
pub const SOLUTION_LEN: usize = 1 + 32 + 16 + 4 + 16;
/// The scheme byte of Equi-X.
pub const SCHEME_EQUIX: u8 = 0x01;
/// The most nonces one solve tries before it gives up, which is well
/// above the expected count at `POW_EFFORT_MAX`.
pub const SOLVE_ATTEMPTS_MAX: u32 = 8 * POW_EFFORT_MAX + 64;

/// `effort` from the admission backlog of one period, at or below
/// `POW_EFFORT_MAX` (`ABU-060`, `ABU-062`, `ABU-092`).
pub const fn effort_from_backlog(backlog: u32) -> u32 {
    let effort = backlog / POW_BACKLOG_UNIT;
    if effort > POW_EFFORT_MAX {
        POW_EFFORT_MAX
    } else {
        effort
    }
}

/// A signed challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallenge {
    /// The verifier.
    pub verifier_id: [u8; 32],
    /// From the CSPRNG of the verifier.
    pub seed: [u8; 32],
    /// 0 to `POW_EFFORT_MAX`.
    pub effort: u32,
    /// Unix seconds, the clock of the verifier.
    pub issued_at: u64,
    /// ML-DSA-65 under the identity key of the verifier.
    pub signature: Vec<u8>,
}

impl PowChallenge {
    fn write_signed(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.u8(0x01)?;
        w.put(&self.verifier_id)?;
        w.u8(SCHEME_EQUIX)?;
        w.put(&self.seed)?;
        w.u32(self.effort)?;
        w.put(&self.issued_at.to_be_bytes())?;
        Ok(())
    }

    /// The signed preimage: the label and the bytes before `sig`.
    pub fn preimage(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; labels::POW_CHALLENGE.len() + CHALLENGE_SIGNED_LEN];
        let mut w = Writer::new(&mut out);
        w.put(labels::POW_CHALLENGE)?;
        self.write_signed(&mut w)?;
        Ok(out)
    }

    /// Signs the challenge under the identity key of the verifier.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        &mut self,
        key: &SigningKey,
        rng: &mut R,
    ) -> Result<(), Error> {
        self.signature = key.sign(&self.preimage()?, rng)?.to_bytes().to_vec();
        Ok(())
    }

    /// Verifies the signature against the identity key of the verifier
    /// (`ABU-068`).
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), Error> {
        let sig = Signature::from_bytes(&self.signature)?;
        key.verify(&self.preimage()?, &sig)?;
        Ok(())
    }

    /// Writes the challenge.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.signature.len() != SIGNATURE_LEN || self.effort > POW_EFFORT_MAX {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        self.write_signed(&mut w)?;
        w.put(&self.signature)?;
        Ok(w.position())
    }

    /// Reads a challenge.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CHALLENGE_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let verifier_id = r.array()?;
        if r.u8()? != SCHEME_EQUIX {
            return Err(Error::Malformed);
        }
        let seed = r.array()?;
        let effort = r.u32()?;
        if effort > POW_EFFORT_MAX {
            return Err(Error::Malformed);
        }
        let issued_at = u64::from_be_bytes(r.array()?);
        let signature = r.take(SIGNATURE_LEN)?.to_vec();
        r.finish()?;
        Ok(PowChallenge {
            verifier_id,
            seed,
            effort,
            issued_at,
            signature,
        })
    }
}

/// A solution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowSolution {
    /// The seed of the challenge.
    pub seed: [u8; 32],
    /// The nonce the client selected.
    pub nonce: [u8; 16],
    /// At or above the effort of the challenge.
    pub effort: u32,
    /// The Equi-X solution.
    pub solution: [u8; 16],
}

impl PowSolution {
    /// Writes the solution.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.seed)?;
        w.put(&self.nonce)?;
        w.u32(self.effort)?;
        w.put(&self.solution)?;
        Ok(w.position())
    }

    /// Reads a solution.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SOLUTION_LEN {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let out = PowSolution {
            seed: r.array()?,
            nonce: r.array()?,
            effort: r.u32()?,
            solution: r.array()?,
        };
        r.finish()?;
        Ok(out)
    }

    /// Solves for `verifier_id` and `seed` at `effort` (`ABU-075`).
    pub fn solve<R: TryCryptoRng + ?Sized>(
        verifier_id: &[u8; 32],
        seed: &[u8; 32],
        effort: u32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (nonce, solution) = equix::solve(verifier_id, seed, effort, SOLVE_ATTEMPTS_MAX, rng)?;
        Ok(PowSolution {
            seed: *seed,
            nonce,
            effort,
            solution,
        })
    }

    /// One attempt at `verifier_id` and `seed`, with a nonce from `rng`.
    /// One attempt in `effort` passes as a mean. A caller with more than
    /// one thread runs attempts on each, thus no long solve holds the rest.
    pub fn attempt<R: TryCryptoRng + ?Sized>(
        verifier_id: &[u8; 32],
        seed: &[u8; 32],
        effort: u32,
        rng: &mut R,
    ) -> Result<Option<Self>, Error> {
        let mut nonce = [0u8; equix::NONCE_LEN];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| Error::from(umbra_crypto::Error::Rng))?;
        Ok(
            equix::attempt(verifier_id, seed, &nonce, effort).map(|solution| PowSolution {
                seed: *seed,
                nonce,
                effort,
                solution,
            }),
        )
    }

    /// Checks the Equi-X solution and the pass test for `verifier_id`
    /// (`ABU-073`).
    pub fn check(&self, verifier_id: &[u8; 32]) -> Result<(), Error> {
        equix::verify(
            verifier_id,
            &self.seed,
            &self.nonce,
            self.effort,
            &self.solution,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Live {
    seed: [u8; 32],
    effort: u32,
    issued_at: u64,
}

/// The verifier side: the two live challenges and the accepted nonces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    verifier_id: [u8; 32],
    floor: u32,
    newest: Option<Live>,
    previous: Option<Live>,
    nonces: BTreeSet<([u8; 32], [u8; 16])>,
}

impl Verifier {
    /// A verifier with an effort floor: 0 for a relay, `POW_LOOKUP_FLOOR`
    /// for the handle directory (`ABU-070`).
    pub const fn new(verifier_id: [u8; 32], floor: u32) -> Self {
        Verifier {
            verifier_id,
            floor,
            newest: None,
            previous: None,
            nonces: BTreeSet::new(),
        }
    }

    /// The verifier.
    pub const fn verifier_id(&self) -> &[u8; 32] {
        &self.verifier_id
    }

    /// Whether `seed` is the seed of the newest or of the previous
    /// challenge, thus a solution to it may still pass (`ABU-058`).
    pub fn is_live_seed(&self, seed: &[u8; 32]) -> bool {
        [self.newest, self.previous]
            .into_iter()
            .flatten()
            .any(|live| live.seed == *seed)
    }

    /// Whether a new challenge is due at `now` (`ABU-057`).
    pub fn due(&self, now: u64) -> bool {
        self.newest
            .is_none_or(|l| now.saturating_sub(l.issued_at) >= POW_CHALLENGE_PERIOD)
    }

    /// Issues a challenge from the backlog of the last period, with a
    /// fresh seed from `rng`, and retires the challenge before the
    /// previous one (`ABU-057` to `ABU-062`). The caller signs it.
    pub fn issue<R: TryCryptoRng + ?Sized>(
        &mut self,
        backlog: u32,
        now: u64,
        rng: &mut R,
    ) -> Result<PowChallenge, Error> {
        let mut seed = [0u8; 32];
        rng.try_fill_bytes(&mut seed)
            .map_err(|_| Error::Unverified)?;
        let effort = effort_from_backlog(backlog)
            .max(self.floor)
            .min(POW_EFFORT_MAX);
        if let Some(old) = self.previous.take() {
            self.nonces.retain(|(s, _)| *s != old.seed);
        }
        self.previous = self.newest;
        self.newest = Some(Live {
            seed,
            effort,
            issued_at: now,
        });
        Ok(PowChallenge {
            verifier_id: self.verifier_id,
            seed,
            effort,
            issued_at: now,
            signature: Vec::new(),
        })
    }

    /// The effort of the newest challenge, which decides whether an
    /// `Admission` of kind `0x00` passes (`ABU-047`, `ABU-048`).
    pub fn effort(&self) -> u32 {
        self.newest.map_or(0, |l| l.effort)
    }

    /// Accepts a solution to the newest or the previous challenge
    /// (`ABU-058`, `ABU-059`, `ABU-071` to `ABU-074`).
    pub fn accept(&mut self, solution: &PowSolution) -> Result<(), Error> {
        let live = [self.newest, self.previous]
            .into_iter()
            .flatten()
            .find(|l| l.seed == solution.seed)
            .ok_or(Error::Unverified)?;
        if solution.effort < live.effort {
            return Err(Error::Unverified);
        }
        if self.nonces.contains(&(solution.seed, solution.nonce)) {
            return Err(Error::Stale);
        }
        solution.check(&self.verifier_id)?;
        self.nonces.insert((solution.seed, solution.nonce));
        Ok(())
    }
}

/// The newest signed challenge of each relay, as a carrier of the relay
/// manifest serves them beside it and as a client holds them after a fetch
/// (`ABU-064`, `ABU-065`, `ABU-102` to `ABU-105`). A challenge enters only
/// under the identity key of its verifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeBook {
    held: BTreeMap<[u8; 32], PowChallenge>,
}

impl ChallengeBook {
    /// Takes `challenge` when its signature verifies under `identity`, its
    /// time is inside two periods of `now`, and it is newer than the one
    /// held. The result says whether the book moved.
    pub fn take(
        &mut self,
        challenge: PowChallenge,
        identity: &VerifyingKey,
        now: u64,
    ) -> Result<bool, Error> {
        challenge.verify(identity)?;
        if !is_live(challenge.issued_at, now) {
            return Err(Error::Stale);
        }
        let is_newer = self
            .held
            .get(&challenge.verifier_id)
            .is_none_or(|held| held.issued_at < challenge.issued_at);
        if is_newer {
            self.held.insert(challenge.verifier_id, challenge);
        }
        Ok(is_newer)
    }

    /// The newest challenge of one verifier that is still live at `now`.
    pub fn get(&self, verifier_id: &[u8; 32], now: u64) -> Option<&PowChallenge> {
        self.held
            .get(verifier_id)
            .filter(|held| is_live(held.issued_at, now))
    }

    /// Whether a live challenge asks for an effort above 0: the
    /// `admission surge` state of Part 14 §14.9.2 (`ABU-008`).
    pub fn is_surge(&self, now: u64) -> bool {
        self.held
            .values()
            .any(|held| is_live(held.issued_at, now) && held.effort > 0)
    }

    /// Drops each challenge past two periods.
    pub fn expire(&mut self, now: u64) {
        self.held.retain(|_, held| is_live(held.issued_at, now));
    }

    /// Each live challenge, one after another at `CHALLENGE_LEN`.
    pub fn encode(&self, now: u64) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for held in self
            .held
            .values()
            .filter(|held| is_live(held.issued_at, now))
        {
            let mut one = alloc::vec![0u8; CHALLENGE_LEN];
            held.encode(&mut one)?;
            out.extend_from_slice(&one);
        }
        Ok(out)
    }

    /// The challenges of a bundle that [`ChallengeBook::encode`] wrote.
    /// The caller takes each one under the key of its verifier.
    pub fn parse_bundle(bytes: &[u8]) -> Result<Vec<PowChallenge>, Error> {
        if !bytes.len().is_multiple_of(CHALLENGE_LEN) {
            return Err(Error::Malformed);
        }
        bytes
            .chunks(CHALLENGE_LEN)
            .map(PowChallenge::parse)
            .collect()
    }
}

/// Whether a challenge of `issued_at` serves at `now`: a verifier accepts
/// its newest and its previous one (`ABU-058`), thus two periods, and a
/// clock of the verifier ahead of this one by one period at most.
fn is_live(issued_at: u64, now: u64) -> bool {
    now.saturating_sub(issued_at) < 2 * POW_CHALLENGE_PERIOD
        && issued_at <= now.saturating_add(POW_CHALLENGE_PERIOD)
}

/// The solutions of a client for the chunk commands of each relay
/// (`ABU-106`, `ABU-107`). One solution at `POW_CHUNK_FLOOR` or above admits
/// `POW_CHUNK_ALLOWANCE` registrations at its relay. Thus an upload solves
/// one puzzle for about each 2 MiB at one relay. A solution serves one
/// upload alone (`ABU-108`). A relay reads the same solution on each
/// registration that it admits. Thus a solution that served two files would
/// join them to one uploader (Part 12 `ATT-005`). The caller gives the time,
/// because the node that holds this reads no clock.
#[derive(Debug, Clone, Default)]
pub struct ChunkAdmissions {
    book: ChallengeBook,
    now: u64,
    /// The local time of the fetch that gave the book (`ABU-069`).
    fetched_at: u64,
    /// The solution of each upload at each relay, with the registrations
    /// that it still admits.
    held: BTreeMap<(u64, [u8; 32]), (PowSolution, u16)>,
    /// The solutions that the caller made ahead for an upload at a relay.
    /// The caller can solve them at one time on more than one thread.
    stock: BTreeMap<(u64, [u8; 32]), Vec<PowSolution>>,
}

impl ChunkAdmissions {
    /// Takes the challenges of a new fetch, which `now` is the time of.
    pub fn set_book(&mut self, book: ChallengeBook, now: u64) {
        self.book = book;
        self.now = now;
        self.fetched_at = now;
    }

    /// Moves the clock of the liveness of the challenges.
    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    /// The solution for the next registration of `upload` at `relay`. It is
    /// the one that this upload holds while its allowance lasts and its
    /// challenge is the newest. If not, it is a new solve. No solution of
    /// another upload serves (`ABU-108`). The result is none when this
    /// device holds no live challenge of the relay. It is also none when a
    /// new solve is due and the fetch of the challenge is
    /// `POW_CHALLENGE_PERIOD` old (`ABU-069`).
    pub fn next<R: TryCryptoRng + ?Sized>(
        &mut self,
        upload: u64,
        relay: &[u8; 32],
        rng: &mut R,
    ) -> Option<PowSolution> {
        // A solution to a challenge that is not the newest serves no more,
        // thus the state holds the uploads of the live challenges alone.
        let (book, now) = (&self.book, self.now);
        self.held.retain(|(_, relay), (solution, _)| {
            book.get(relay, now)
                .is_some_and(|challenge| challenge.seed == solution.seed)
        });
        // An upload that ended leaves its stock, which goes with its seed.
        self.stock.retain(|(_, relay), solutions| {
            book.get(relay, now).is_some_and(|challenge| {
                solutions
                    .iter()
                    .any(|solution| solution.seed == challenge.seed)
            })
        });
        let challenge = self.book.get(relay, self.now)?;
        if let Some((solution, left)) = self.held.get_mut(&(upload, *relay)) {
            if *left > 0 {
                *left -= 1;
                return Some(*solution);
            }
        }
        let floor = challenge.effort.clamp(POW_CHUNK_FLOOR, POW_EFFORT_MAX);
        if let Some(solutions) = self.stock.get_mut(&(upload, *relay)) {
            solutions
                .retain(|solution| solution.seed == challenge.seed && solution.effort >= floor);
            if let Some(solution) = solutions.pop() {
                self.held.insert(
                    (upload, *relay),
                    (solution, POW_CHUNK_ALLOWANCE.saturating_sub(1)),
                );
                return Some(solution);
            }
            self.stock.remove(&(upload, *relay));
        }
        // ABU-069: no new solve past one period from the fetch.
        if self.now.saturating_sub(self.fetched_at) >= POW_CHALLENGE_PERIOD {
            return None;
        }
        let effort = challenge.effort.clamp(POW_CHUNK_FLOOR, POW_EFFORT_MAX);
        let solution = PowSolution::solve(relay, &challenge.seed, effort, rng).ok()?;
        self.held.insert(
            (upload, *relay),
            (solution, POW_CHUNK_ALLOWANCE.saturating_sub(1)),
        );
        Some(solution)
    }

    /// The seed and the effort of a solution that admits a registration at
    /// `relay` now, or none as [`ChunkAdmissions::next`] gives none.
    pub fn work(&self, relay: &[u8; 32]) -> Option<([u8; 32], u32)> {
        if self.now.saturating_sub(self.fetched_at) >= POW_CHALLENGE_PERIOD {
            return None;
        }
        let challenge = self.book.get(relay, self.now)?;
        let effort = challenge.effort.clamp(POW_CHUNK_FLOOR, POW_EFFORT_MAX);
        Some((challenge.seed, effort))
    }

    /// Keeps a solution that the caller made ahead for `upload` at `relay`.
    /// It serves that upload alone (`ABU-108`).
    pub fn stock(&mut self, upload: u64, relay: [u8; 32], solution: PowSolution) {
        self.stock
            .entry((upload, relay))
            .or_default()
            .push(solution);
    }

    /// The newest challenge of `relay` that this device holds, live at the
    /// clock of the last call.
    pub fn challenge(&self, relay: &[u8; 32]) -> Option<&PowChallenge> {
        self.book.get(relay, self.now)
    }

    /// Drops the solution of `upload` at a relay that refused it, thus the
    /// next registration solves again.
    pub fn forget(&mut self, upload: u64, relay: &[u8; 32]) {
        self.held.remove(&(upload, *relay));
    }
}

/// A challenge a client fetched, usable inside `POW_CHALLENGE_PERIOD` of
/// the fetch (`ABU-069`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The challenge, verified under `ABU-068`.
    pub challenge: PowChallenge,
    /// The local fetch time.
    pub fetched_at: u64,
}

impl Fetched {
    /// Verifies the signature and records the fetch.
    pub fn new(
        challenge: PowChallenge,
        key: &VerifyingKey,
        fetched_at: u64,
    ) -> Result<Self, Error> {
        challenge.verify(key)?;
        Ok(Fetched {
            challenge,
            fetched_at,
        })
    }

    /// Whether a solution may still be computed at `now`.
    pub fn usable(&self, now: u64) -> bool {
        now.saturating_sub(self.fetched_at) < POW_CHALLENGE_PERIOD
    }

    /// Solves the challenge at its effort.
    pub fn solve<R: TryCryptoRng + ?Sized>(
        &self,
        now: u64,
        rng: &mut R,
    ) -> Result<PowSolution, Error> {
        if !self.usable(now) {
            return Err(Error::Stale);
        }
        PowSolution::solve(
            &self.challenge.verifier_id,
            &self.challenge.seed,
            self.challenge.effort,
            rng,
        )
    }
}

/// Solves the derived challenge of a hello to `entry_pk` at `epoch`
/// (`ABU-082`).
pub fn solve_hello<R: TryCryptoRng + ?Sized>(
    entry_pk: &[u8],
    epoch: u32,
    rng: &mut R,
) -> Result<PowSolution, Error> {
    let derived = HelloPow::derive(entry_pk, epoch);
    PowSolution::solve(&derived.verifier_id, &derived.seed, HELLO_POW_EFFORT, rng)
}

/// Checks the solution of a hello at the addressee against the seeds of
/// the current epoch and the one before it (`ABU-083`, `ABU-084`).
pub fn verify_hello(entry_pk: &[u8], epoch: u32, solution: &PowSolution) -> Result<(), Error> {
    let derived = HelloPow::derive(entry_pk, epoch);
    if !HelloPow::accepted_seeds(entry_pk, epoch).contains(&solution.seed) {
        return Err(Error::Unverified);
    }
    if solution.effort < HELLO_POW_EFFORT {
        return Err(Error::Unverified);
    }
    solution.check(&derived.verifier_id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::abuse::test_rng::Rng;
    use umbra_crypto::secret::Secret;

    #[test]
    fn a_book_holds_the_newest_signed_challenge_of_each_relay() {
        let key = SigningKey::from_seed(Secret::new([1; 32]));
        let other = SigningKey::from_seed(Secret::new([2; 32]));
        let signed = |verifier: u8, issued_at: u64, key: &SigningKey| {
            let mut challenge = PowChallenge {
                verifier_id: [verifier; 32],
                seed: [issued_at as u8; 32],
                effort: 3,
                issued_at,
                signature: Vec::new(),
            };
            challenge.sign(key, &mut Rng(9)).unwrap();
            challenge
        };
        let now = 10_000;
        let mut book = ChallengeBook::default();
        // ABU-068: a challenge enters under the key of its verifier alone.
        assert!(book
            .take(signed(5, now, &other), &key.verifying_key(), now)
            .is_err());
        assert!(book
            .take(signed(5, now, &key), &key.verifying_key(), now)
            .unwrap());
        // An older one leaves the book as it was, and a stale one fails.
        assert!(!book
            .take(signed(5, now - 10, &key), &key.verifying_key(), now)
            .unwrap());
        assert_eq!(
            book.take(
                signed(6, now - 2 * POW_CHALLENGE_PERIOD, &key),
                &key.verifying_key(),
                now
            ),
            Err(Error::Stale)
        );
        assert_eq!(book.get(&[5; 32], now).unwrap().issued_at, now);
        // ABU-008: a live challenge above effort 0 is the surge state, and
        // it ends with its period.
        assert!(book.is_surge(now));
        assert!(!book.is_surge(now + 2 * POW_CHALLENGE_PERIOD));
        assert!(!ChallengeBook::default().is_surge(now));
        // The bundle carries each live challenge, and it reads back.
        let bundle = book.encode(now).unwrap();
        assert_eq!(bundle.len(), CHALLENGE_LEN);
        let back = ChallengeBook::parse_bundle(&bundle).unwrap();
        assert_eq!(
            back,
            [signed(5, now, &key)].map(|mut c| {
                c.signature = back[0].signature.clone();
                c
            })
        );
        assert!(ChallengeBook::parse_bundle(&bundle[1..]).is_err());
        // Two periods on, the book serves nothing.
        assert!(book.get(&[5; 32], now + 2 * POW_CHALLENGE_PERIOD).is_none());
        assert!(book
            .encode(now + 2 * POW_CHALLENGE_PERIOD)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_challenge_signs_round_trips_and_bounds_its_effort() {
        let key = SigningKey::from_seed(Secret::new([1; 32]));
        let mut c = PowChallenge {
            verifier_id: [2; 32],
            seed: [3; 32],
            effort: 7,
            issued_at: 1_000,
            signature: Vec::new(),
        };
        c.sign(&key, &mut Rng(1)).unwrap();
        let mut out = [0u8; CHALLENGE_LEN];
        assert_eq!(c.encode(&mut out).unwrap(), 3_387);
        let back = PowChallenge::parse(&out).unwrap();
        assert_eq!(back, c);
        back.verify(&key.verifying_key()).unwrap();
        let other = SigningKey::from_seed(Secret::new([9; 32]));
        assert!(back.verify(&other.verifying_key()).is_err());
        let mut too_much = c.clone();
        too_much.effort = POW_EFFORT_MAX + 1;
        assert!(too_much.encode(&mut out).is_err());
        assert_eq!(effort_from_backlog(0), 0);
        assert_eq!(effort_from_backlog(64), 1);
        assert_eq!(effort_from_backlog(u32::MAX), POW_EFFORT_MAX);
    }

    #[test]
    fn the_verifier_keeps_two_seeds_and_rejects_a_repeat() {
        let mut v = Verifier::new([2; 32], 0);
        assert!(v.due(0));
        let first = v.issue(0, 0, &mut Rng(1)).unwrap();
        assert_eq!(v.effort(), 0);
        assert!(!v.due(POW_CHALLENGE_PERIOD - 1));
        let second = v.issue(3 * 64, POW_CHALLENGE_PERIOD, &mut Rng(2)).unwrap();
        assert_eq!(v.effort(), 3);
        let sol = PowSolution::solve(&[2; 32], &first.seed, 1, &mut Rng(3)).unwrap();
        v.accept(&sol).unwrap();
        assert_eq!(v.accept(&sol), Err(Error::Stale));
        let mut out = [0u8; SOLUTION_LEN];
        assert_eq!(sol.encode(&mut out).unwrap(), 69);
        assert_eq!(PowSolution::parse(&out).unwrap(), sol);
        // Below the effort of the second challenge, and a wrong verifier.
        let weak = PowSolution::solve(&[2; 32], &second.seed, 1, &mut Rng(4)).unwrap();
        assert_eq!(v.accept(&weak), Err(Error::Unverified));
        let strong = PowSolution::solve(&[2; 32], &second.seed, 3, &mut Rng(5)).unwrap();
        v.accept(&strong).unwrap();
        let foreign = PowSolution::solve(&[8; 32], &second.seed, 3, &mut Rng(6)).unwrap();
        assert!(v.accept(&foreign).is_err());
        // A third issue retires the first seed.
        let third = v.issue(0, 2 * POW_CHALLENGE_PERIOD, &mut Rng(7)).unwrap();
        let late = PowSolution::solve(&[2; 32], &first.seed, 1, &mut Rng(8)).unwrap();
        assert_eq!(v.accept(&late), Err(Error::Unverified));
        assert_ne!(third.seed, first.seed);
        let floored = Verifier::new([2; 32], 20);
        let mut floored_v = floored;
        assert_eq!(floored_v.issue(0, 0, &mut Rng(9)).unwrap().effort, 20);
    }

    #[test]
    fn a_fetched_challenge_solves_inside_its_period_and_a_hello_solves_at_its_effort() {
        let key = SigningKey::from_seed(Secret::new([1; 32]));
        let mut c = PowChallenge {
            verifier_id: [2; 32],
            seed: [3; 32],
            effort: 1,
            issued_at: 0,
            signature: Vec::new(),
        };
        c.sign(&key, &mut Rng(1)).unwrap();
        let fetched = Fetched::new(c, &key.verifying_key(), 100).unwrap();
        assert!(fetched
            .solve(100 + POW_CHALLENGE_PERIOD, &mut Rng(2))
            .is_err());
        let sol = fetched.solve(150, &mut Rng(2)).unwrap();
        let mut v = Verifier::new([2; 32], 0);
        v.newest = Some(Live {
            seed: [3; 32],
            effort: 1,
            issued_at: 0,
        });
        v.accept(&sol).unwrap();

        let entry_pk = [5u8; 1_216];
        let hello = solve_hello(&entry_pk, 40, &mut Rng(3)).unwrap();
        assert_eq!(hello.effort, HELLO_POW_EFFORT);
        verify_hello(&entry_pk, 40, &hello).unwrap();
        verify_hello(&entry_pk, 41, &hello).unwrap();
        assert!(verify_hello(&entry_pk, 42, &hello).is_err());
        assert!(verify_hello(&[6; 1_216], 40, &hello).is_err());
    }

    fn book_of(verifier: u8, seed: u8, issued_at: u64, now: u64) -> ChallengeBook {
        let key = SigningKey::from_seed(Secret::new([1; 32]));
        let mut challenge = PowChallenge {
            verifier_id: [verifier; 32],
            seed: [seed; 32],
            effort: 0,
            issued_at,
            signature: Vec::new(),
        };
        challenge.sign(&key, &mut Rng(9)).unwrap();
        let mut book = ChallengeBook::default();
        book.take(challenge, &key.verifying_key(), now).unwrap();
        book
    }

    #[test]
    fn a_solution_made_ahead_serves_its_upload_before_a_new_solve() {
        let relay = [5u8; 32];
        let mut held = ChunkAdmissions::default();
        assert!(held.work(&relay).is_none());
        held.set_book(book_of(5, 3, 1_000, 1_000), 1_000);
        let (seed, effort) = held.work(&relay).unwrap();
        assert_eq!((seed, effort), ([3; 32], POW_CHUNK_FLOOR));
        // The caller makes two solutions ahead, one attempt at a time.
        let mut rng = Rng(21);
        let mut made = Vec::new();
        while made.len() < 2 {
            if let Some(solution) = PowSolution::attempt(&relay, &seed, effort, &mut rng).unwrap() {
                solution.check(&relay).unwrap();
                made.push(solution);
            }
        }
        for solution in &made {
            held.stock(1, relay, *solution);
        }
        // Each one serves its allowance, and no other upload takes one.
        let first = held.next(1, &relay, &mut Rng(22)).unwrap();
        assert!(made.contains(&first));
        assert!(!made.contains(&held.next(2, &relay, &mut Rng(23)).unwrap()));
        for _ in 1..POW_CHUNK_ALLOWANCE {
            assert_eq!(held.next(1, &relay, &mut Rng(24)), Some(first));
        }
        let second = held.next(1, &relay, &mut Rng(25)).unwrap();
        assert!(made.contains(&second) && second != first);
        // A new challenge ends the stock to the old one.
        held.stock(1, relay, first);
        held.set_book(book_of(5, 4, 1_100, 1_100), 1_100);
        assert_eq!(held.next(1, &relay, &mut Rng(26)).unwrap().seed, [4; 32]);
        assert!(held.stock.is_empty());
    }

    #[test]
    fn a_chunk_solution_serves_one_upload_at_one_relay() {
        let relay = [5u8; 32];
        let mut held = ChunkAdmissions::default();
        // With no challenge of the relay, no solution comes.
        assert!(held.next(1, &relay, &mut Rng(1)).is_none());
        held.set_book(book_of(5, 3, 1_000, 1_000), 1_000);
        let first = held.next(1, &relay, &mut Rng(2)).unwrap();
        assert_eq!(first.effort, POW_CHUNK_FLOOR);
        // ABU-108: the next registration of the upload takes the same
        // solution, and another upload solves for itself.
        assert_eq!(held.next(1, &relay, &mut Rng(3)), Some(first));
        let other = held.next(2, &relay, &mut Rng(4)).unwrap();
        assert_ne!(other.nonce, first.nonce);
        assert_eq!(held.next(2, &relay, &mut Rng(5)), Some(other));
        // ABU-107: past the allowance the upload solves again.
        for _ in 2..POW_CHUNK_ALLOWANCE {
            assert_eq!(held.next(1, &relay, &mut Rng(6)), Some(first));
        }
        let second = held.next(1, &relay, &mut Rng(7)).unwrap();
        assert_ne!(second.nonce, first.nonce);
        // A relay that refused a solution gets a new one.
        held.forget(1, &relay);
        assert_ne!(held.next(1, &relay, &mut Rng(8)), Some(second));
        // A new challenge ends each solution to the old one.
        held.set_book(book_of(5, 4, 1_100, 1_100), 1_100);
        let newer = held.next(2, &relay, &mut Rng(9)).unwrap();
        assert_eq!(newer.seed, [4; 32]);
        assert_eq!(held.held.len(), 1);
    }

    #[test]
    fn no_chunk_solve_starts_one_period_after_the_fetch() {
        let relay = [5u8; 32];
        let mut held = ChunkAdmissions::default();
        held.set_book(book_of(5, 3, 1_000, 1_000), 1_000);
        let first = held.next(1, &relay, &mut Rng(1)).unwrap();
        // ABU-069: the challenge is live for one more period at its relay,
        // and the solution that the upload holds serves. A new solve does
        // not start.
        held.set_now(1_000 + POW_CHALLENGE_PERIOD);
        assert_eq!(held.next(1, &relay, &mut Rng(2)), Some(first));
        assert!(held.next(2, &relay, &mut Rng(3)).is_none());
        // A new fetch starts the period again.
        held.set_book(
            book_of(5, 3, 1_000, 1_000 + POW_CHALLENGE_PERIOD),
            1_000 + POW_CHALLENGE_PERIOD,
        );
        assert!(held.next(2, &relay, &mut Rng(4)).is_some());
    }
}
