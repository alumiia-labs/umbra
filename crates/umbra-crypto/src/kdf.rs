//! The memory-hard KDF of Part 4 §4.7.1 and Part 14 §14.6.4: Argon2id.

use alloc::vec::Vec;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

use crate::{secret::Secret, Error};

/// The floor of `m` for the recovery code, in KiB (64 MiB).
pub const RECOVERY_M_KIB: u32 = 64 * 1_024;
/// The floor of `t` for the recovery code.
pub const RECOVERY_T: u32 = 3;

/// `Argon2id(password, salt, m, t)` into a 32-byte key. `m_kib` and `t`
/// are the memory in KiB and the passes; a caller gives the calibrated
/// values of its context.
pub fn argon2id(password: &[u8], salt: &[u8], m_kib: u32, t: u32) -> Result<Secret<32>, Error> {
    let params = Params::new(m_kib, t, 1, Some(32)).map_err(|_| Error::Length)?;
    let block_count = params.block_count();
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // The memory of `hash_password_into` goes back to the allocator with no
    // wipe, and the last blocks give the output with no password.
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| Error::Length)?;
    memory.resize(block_count, Block::new());

    let mut out = Secret::<32>::zeroed();
    kdf.hash_password_into_with_memory(password, salt, out.expose_mut(), memory.as_mut_slice())
        .map_err(|_| Error::Length)?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_kdf_is_deterministic_and_salted() {
        let a = argon2id(b"code", b"salt-0123", 64, 1).unwrap();
        let b = argon2id(b"code", b"salt-0123", 64, 1).unwrap();
        let c = argon2id(b"code", b"salt-4567", 64, 1).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    #[test]
    fn the_own_memory_gives_the_output_of_the_crate_memory() {
        let params = Params::new(64, 2, 1, Some(32)).unwrap();
        let mut expected = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"code", b"salt-0123", &mut expected)
            .unwrap();

        assert_eq!(
            argon2id(b"code", b"salt-0123", 64, 2).unwrap().expose(),
            &expected
        );
    }
}
