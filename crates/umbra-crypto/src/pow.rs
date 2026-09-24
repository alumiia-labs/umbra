//! The proof of work of Part 13 §13.8 over Equi-X, which is AUX-8 of Part 5
//! §5.1: the challenge string, the solve loop with its pass test, and the
//! verification. The interpreter runs everywhere, and the JIT of the
//! `hashx` crate stays off.

use equix::{EquiXBuilder, RuntimeOption, Solution};
use rand_core::TryCryptoRng;

use crate::{hash::sha3_256, labels, Error};

/// The nonce of a solution.
pub const NONCE_LEN: usize = 16;
/// An Equi-X solution, eight `u16` indexes.
pub const SOLUTION_LEN: usize = 16;

/// `"umbra/v1/pow" || verifier_id || seed || nonce || BE32(effort)`.
pub fn challenge_string(
    verifier_id: &[u8; 32],
    seed: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    effort: u32,
) -> [u8; 96] {
    let mut out = [0u8; 96];
    let label = labels::POW;
    let mut at = 0usize;
    for part in [label, verifier_id, seed, nonce, &effort.to_be_bytes()] {
        if let Some(slot) = out.get_mut(at..at.saturating_add(part.len())) {
            slot.copy_from_slice(part);
        }
        at = at.saturating_add(part.len());
    }
    out
}

/// `R × effort ≤ 2^32 − 1`, with `R` the first four bytes of
/// `SHA3-256(challenge || solution)`.
pub fn passes(challenge: &[u8; 96], solution: &[u8; SOLUTION_LEN], effort: u32) -> bool {
    let digest = sha3_256(&[challenge, solution]);
    let mut head = [0u8; 4];
    head.copy_from_slice(digest.get(..4).unwrap_or(&[0xFF; 4]));
    let r = u64::from(u32::from_be_bytes(head));
    r.saturating_mul(u64::from(effort)) <= u64::from(u32::MAX)
}

fn builder() -> EquiXBuilder {
    let mut b = EquiXBuilder::new();
    b.runtime(RuntimeOption::InterpretOnly);
    b
}

/// One attempt at `nonce`: the first Equi-X solution of the challenge
/// that passes, if any.
pub fn attempt(
    verifier_id: &[u8; 32],
    seed: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    effort: u32,
) -> Option<[u8; SOLUTION_LEN]> {
    let challenge = challenge_string(verifier_id, seed, nonce, effort);
    let solutions = builder().solve(&challenge).ok()?;
    solutions
        .iter()
        .map(Solution::to_bytes)
        .find(|s| passes(&challenge, s, effort))
}

/// Solves a challenge: draws a nonce from `rng` for each attempt, at most
/// `max_attempts` times. The expected count of attempts is `effort`.
pub fn solve<R: TryCryptoRng + ?Sized>(
    verifier_id: &[u8; 32],
    seed: &[u8; 32],
    effort: u32,
    max_attempts: u32,
    rng: &mut R,
) -> Result<([u8; NONCE_LEN], [u8; SOLUTION_LEN]), Error> {
    for _ in 0..max_attempts {
        let mut nonce = [0u8; NONCE_LEN];
        rng.try_fill_bytes(&mut nonce).map_err(|_| Error::Rng)?;
        if let Some(solution) = attempt(verifier_id, seed, &nonce, effort) {
            return Ok((nonce, solution));
        }
    }
    Err(Error::Rng)
}

/// Verifies a solution: the Equi-X check and the pass test (`ABU-073`).
pub fn verify(
    verifier_id: &[u8; 32],
    seed: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    effort: u32,
    solution: &[u8; SOLUTION_LEN],
) -> Result<(), Error> {
    let challenge = challenge_string(verifier_id, seed, nonce, effort);
    builder()
        .verify_bytes(&challenge, solution)
        .map_err(|_| Error::Auth)?;
    if passes(&challenge, solution, effort) {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_solution_verifies_and_a_changed_input_fails() {
        let mut rng = crate::test_rng::TestRng::new(b"pow");
        let verifier = [1u8; 32];
        let seed = [2u8; 32];
        let (nonce, solution) = solve(&verifier, &seed, 2, 200, &mut rng).unwrap();
        verify(&verifier, &seed, &nonce, 2, &solution).unwrap();
        assert!(verify(&verifier, &[3; 32], &nonce, 2, &solution).is_err());
        assert!(verify(&[4; 32], &seed, &nonce, 2, &solution).is_err());
        let mut bad = solution;
        bad[0] ^= 1;
        assert!(verify(&verifier, &seed, &nonce, 2, &bad).is_err());
        // Effort 0 passes on any solution; effort in the string changes
        // the puzzle, thus a solution at 2 does not verify at 3.
        assert!(passes(&[0; 96], &[0; 16], 0));
        assert!(verify(&verifier, &seed, &nonce, 3, &solution).is_err());
    }
}
