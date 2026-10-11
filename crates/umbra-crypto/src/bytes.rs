//! A part of a byte array, with each length in the types.

/// The `N` bytes of `full` from the offset `AT`.
///
/// The bound is a constant of the caller, thus a part that does not fit
/// stops the build. No key and no digest part falls back to other bytes.
///
/// ```
/// let full = [1u8, 2, 3, 4];
/// assert_eq!(umbra_crypto::bytes::part::<1, 2, 4>(&full), [2, 3]);
/// ```
///
/// ```compile_fail
/// let full = [0u8; 4];
/// let _ = umbra_crypto::bytes::part::<3, 2, 4>(&full);
/// ```
pub fn part<const AT: usize, const N: usize, const M: usize>(full: &[u8; M]) -> [u8; N] {
    const { assert!(AT <= M && N <= M - AT) };
    let mut out = [0u8; N];
    for (to, from) in out.iter_mut().zip(full.iter().skip(AT)) {
        *to = *from;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_is_the_bytes_at_its_offset() {
        let full: [u8; 8] = core::array::from_fn(|at| at as u8);
        assert_eq!(part::<0, 3, 8>(&full), [0, 1, 2]);
        assert_eq!(part::<5, 3, 8>(&full), [5, 6, 7]);
        assert_eq!(part::<0, 8, 8>(&full), full);
        assert_eq!(part::<8, 0, 8>(&full), [0u8; 0]);
    }
}
