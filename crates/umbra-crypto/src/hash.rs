//! SHA3-256 over a list of parts, for the hashes that the wire objects
//! carry: a roster key hash, a chain hash, a message reference.

use sha3::{Digest, Sha3_256};

/// `SHA3-256(parts[0] || parts[1] || ...)`.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_parts_concatenate() {
        assert_eq!(sha3_256(&[b"ab", b"c"]), sha3_256(&[b"abc"]));
        assert_ne!(sha3_256(&[b"ab"]), sha3_256(&[b"abc"]));
    }
}
