//! The verification ceremony of Part 4 §4.5.2: a commit, a reveal, and a
//! six-digit code that two persons compare. The exchange gives two clients
//! one number; the comparison between the persons is the verification.

use umbra_crypto::{hash::sha3_256, labels};

use super::address::canonical_pair;
use crate::Error;

/// The commit of a nonce: `SHA3-256("umbra/v1/sas-commit" || nonce)`.
pub fn commit(nonce: &[u8; 32]) -> [u8; 32] {
    sha3_256(&[labels::SAS_COMMIT, nonce])
}

/// The six-digit code of a ceremony.
pub fn code(own_pk: &[u8], peer_pk: &[u8], own_nonce: &[u8; 32], peer_nonce: &[u8; 32]) -> u32 {
    let (lo, hi) = canonical_pair(own_pk, peer_pk);
    let (nonce_lo, nonce_hi) = if core::ptr::eq(lo, own_pk) {
        (own_nonce, peer_nonce)
    } else {
        (peer_nonce, own_nonce)
    };
    let digest = sha3_256(&[labels::SAS, lo, hi, nonce_lo, nonce_hi]);
    let mut head = [0u8; 4];
    if let Some(h) = digest.get(..4) {
        head.copy_from_slice(h);
    }
    u32::from_be_bytes(head) % 1_000_000
}

/// The six digits of a code, with leading zeros.
pub fn digits(code: u32) -> alloc::string::String {
    alloc::format!("{code:06}")
}

/// The state of one ceremony at one client.
pub struct Ceremony {
    own_nonce: [u8; 32],
    sent_commit: bool,
    peer_commit: Option<[u8; 32]>,
    peer_nonce: Option<[u8; 32]>,
    confirmed: bool,
}

impl Ceremony {
    /// Starts a ceremony with a fresh nonce from the CSPRNG (`IDN-145`).
    pub fn new(own_nonce: [u8; 32]) -> Self {
        Ceremony {
            own_nonce,
            sent_commit: false,
            peer_commit: None,
            peer_nonce: None,
            confirmed: false,
        }
    }

    /// The `VerifyCommit` to send first (`IDN-142`).
    pub fn commit_to_send(&mut self) -> [u8; 32] {
        self.sent_commit = true;
        commit(&self.own_nonce)
    }

    /// The peer's `VerifyCommit` arrived.
    pub fn peer_committed(&mut self, peer_commit: [u8; 32]) {
        self.peer_commit = Some(peer_commit);
    }

    /// The `VerifyReveal` to send, once the peer's commit is held
    /// (`IDN-143`).
    pub fn reveal_to_send(&self) -> Result<[u8; 32], Error> {
        if !self.sent_commit || self.peer_commit.is_none() {
            return Err(Error::Unverified);
        }
        Ok(self.own_nonce)
    }

    /// The peer's `VerifyReveal` arrived; it must match the commit held
    /// (`IDN-144`).
    pub fn peer_revealed(&mut self, peer_nonce: [u8; 32]) -> Result<(), Error> {
        let held = self.peer_commit.ok_or(Error::Unverified)?;
        if commit(&peer_nonce) != held {
            return Err(Error::Unverified);
        }
        self.peer_nonce = Some(peer_nonce);
        Ok(())
    }

    /// The code to show, once both nonces are held.
    pub fn code(&self, own_pk: &[u8], peer_pk: &[u8]) -> Option<u32> {
        let peer = self.peer_nonce?;
        Some(code(own_pk, peer_pk, &self.own_nonce, &peer))
    }

    /// The user confirmed that the two codes match (`IDN-147`).
    pub fn user_confirmed(&mut self) -> Result<(), Error> {
        if self.peer_nonce.is_none() {
            return Err(Error::Unverified);
        }
        self.confirmed = true;
        Ok(())
    }

    /// Whether the verification state is set. The exchange alone never
    /// sets it (`IDN-148`).
    pub fn verified(&self) -> bool {
        self.confirmed
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn both_parties_derive_one_code_and_the_order_of_steps_holds() {
        let pk_a = [1u8; 32];
        let pk_b = [2u8; 32];
        let mut a = Ceremony::new([3; 32]);
        let mut b = Ceremony::new([4; 32]);
        assert!(a.reveal_to_send().is_err());
        let ca = a.commit_to_send();
        let cb = b.commit_to_send();
        a.peer_committed(cb);
        b.peer_committed(ca);
        let ra = a.reveal_to_send().unwrap();
        let rb = b.reveal_to_send().unwrap();
        assert!(a.peer_revealed([9; 32]).is_err());
        a.peer_revealed(rb).unwrap();
        b.peer_revealed(ra).unwrap();
        let code_a = a.code(&pk_a, &pk_b).unwrap();
        let code_b = b.code(&pk_b, &pk_a).unwrap();
        assert_eq!(code_a, code_b);
        assert!(code_a < 1_000_000);
        assert_eq!(digits(42).len(), 6);
        assert!(!a.verified());
        a.user_confirmed().unwrap();
        assert!(a.verified());
        let mut fresh = Ceremony::new([5; 32]);
        assert!(fresh.user_confirmed().is_err());
    }
}
