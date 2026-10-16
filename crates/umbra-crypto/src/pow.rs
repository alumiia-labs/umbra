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
    let r = u64::from(u32::from_be_bytes(crate::bytes::part::<0, 4, 32>(&digest)));
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

    fn h16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Solutions that equix 0.2.5 gave. A later equix must give the same
    /// set, else a proof of one client fails at a relay on another version.
    #[test]
    fn equix_solutions_stay_fixed() {
        let cases: [(u8, &[&str]); 3] = [
            (
                0,
                &[
                    "ed339e80367236baef022bcde10eddfb",
                    "a1332e94a47a809cf61a23f6621caff8",
                    "e7243c28166800be70536e65eb5579f6",
                    "7540515f8518c5bb8130f07c0c6a23d7",
                ],
            ),
            (1, &["a5529e8943842c8f4741ffc45c53aafa"]),
            (
                4,
                &[
                    "1a0bf3abcf36b9df1c4a156ab135e6e6",
                    "633bdcab1c62f8d1122ea7a6cda2c4eb",
                    "abbd04e75ba028f5131b1f8041381af9",
                    "7166f580c79efeba475a15bae82ef8d5",
                    "6b22a62f975f7c9d02a1efb34d29adf5",
                ],
            ),
        ];
        for (i, expected) in cases {
            let challenge = challenge_string(
                &[i.wrapping_mul(7); 32],
                &[i ^ 0x5a; 32],
                &[i; NONCE_LEN],
                u32::from(i) * 3,
            );
            let solutions = builder().solve(&challenge).unwrap();
            assert_eq!(solutions.len(), expected.len());
            for (s, e) in solutions.iter().zip(expected) {
                assert_eq!(s.to_bytes(), h16(e));
                builder().verify_bytes(&challenge, &h16(e)).unwrap();
            }
        }
        let mut rng = crate::test_rng::TestRng::new(b"pow-dump");
        let (nonce, solution) = solve(&[9; 32], &[8; 32], 5, 500, &mut rng).unwrap();
        assert_eq!(nonce, h16("0d5b3e3fe15d1772b5a97b1a32f0d244"));
        assert_eq!(solution, h16("921b1b8a361cb2f7be9bcde5e8b1e3fa"));
        verify(&[9; 32], &[8; 32], &nonce, 5, &solution).unwrap();
    }
}
