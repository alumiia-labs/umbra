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

/// The time that a start of the peer waits for an action of the user, in
/// seconds (`IDN-170`). Two persons compare a code while they talk, thus a
/// start that waited longer belongs to no comparison that still runs. An
/// action of the user after it starts a ceremony of its own, and answers no
/// start of that age.
pub const HELD_START_LIFE: u64 = 600;

/// The state of one ceremony at one client.
pub struct Ceremony {
    own_nonce: [u8; 32],
    sent_commit: bool,
    peer_commit: Option<[u8; 32]>,
    peer_nonce: Option<[u8; 32]>,
    confirmed: bool,
    /// The start of the peer that waits for an action of the user.
    asked: Option<[u8; 32]>,
    /// The time of the arrival of that start, in seconds, or none for a
    /// start with no time.
    asked_at: Option<u64>,
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
            asked: None,
            asked_at: None,
        }
    }

    /// Holds a start of the peer that no action of the user called for
    /// (`IDN-170`). This state sends no commit and no reveal, and it gives
    /// no code. The user accepts first, and the client then answers that
    /// start from a ceremony of [`Ceremony::new`].
    pub fn asked(start: [u8; 32]) -> Self {
        Ceremony {
            asked: Some(start),
            ..Ceremony::new([0; 32])
        }
    }

    /// [`Ceremony::asked`] with the time of the arrival of the start, in
    /// seconds. The start waits for `HELD_START_LIFE` and no longer.
    pub fn asked_at(start: [u8; 32], now: u64) -> Self {
        Ceremony {
            asked_at: Some(now),
            ..Ceremony::asked(start)
        }
    }

    /// The start of the peer that waits for the user, if this state holds
    /// one.
    pub fn asked_start(&self) -> Option<[u8; 32]> {
        self.asked
    }

    /// The start of the peer that waits for the user at `now`. It is none
    /// after `HELD_START_LIFE` from its arrival, and none when the clock
    /// went back before that arrival. A start with no time does not lapse.
    pub fn asked_start_at(&self, now: u64) -> Option<[u8; 32]> {
        match self.asked_at {
            Some(at) if now < at || now - at >= HELD_START_LIFE => None,
            _ => self.asked,
        }
    }

    /// Whether the ceremony took its one commit of the peer (`IDN-170`).
    /// The reveal of this client went to that commit. Thus a later start or
    /// answer of the peer gets no second reveal from this nonce. It gets no
    /// answer without a new action of the user.
    pub fn spent(&self) -> bool {
        self.peer_commit.is_some()
    }

    /// The `VerifyCommit` to send first (`IDN-142`).
    pub fn commit_to_send(&mut self) -> [u8; 32] {
        self.sent_commit = true;
        commit(&self.own_nonce)
    }

    /// The commit of this client, which the answer of the peer names.
    pub fn own_commit(&self) -> [u8; 32] {
        commit(&self.own_nonce)
    }

    /// Whether this client sent its commit and holds no commit of the peer.
    pub fn awaits_commit(&self) -> bool {
        self.sent_commit && self.peer_commit.is_none()
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

    #[test]
    fn a_start_that_waits_for_the_user_reveals_nothing_and_one_ceremony_takes_one_commit() {
        // IDN-170: a held start lapses after `HELD_START_LIFE`, and an
        // action of the user after that answers none.
        let timed = Ceremony::asked_at([7; 32], 1_000);
        assert_eq!(timed.asked_start_at(1_000), Some([7; 32]));
        assert_eq!(
            timed.asked_start_at(1_000 + HELD_START_LIFE - 1),
            Some([7; 32])
        );
        assert_eq!(timed.asked_start_at(1_000 + HELD_START_LIFE), None);
        assert_eq!(timed.asked_start_at(999), None);
        assert!(timed.reveal_to_send().is_err());
        // IDN-170: the held start of the peer is no ceremony.
        let mut asked = Ceremony::asked([7; 32]);
        assert_eq!(asked.asked_start(), Some([7; 32]));
        assert_eq!(asked.asked_start_at(u64::MAX), Some([7; 32]));
        assert!(!asked.awaits_commit());
        assert!(!asked.spent());
        assert!(asked.reveal_to_send().is_err());
        assert!(asked.peer_revealed([9; 32]).is_err());
        assert_eq!(asked.code(&[1; 32], &[2; 32]), None);
        assert!(asked.user_confirmed().is_err());

        // A ceremony of the user holds no such start, and it is spent
        // from the commit of the peer on.
        let mut own = Ceremony::new([3; 32]);
        assert_eq!(own.asked_start(), None);
        own.commit_to_send();
        assert!(own.awaits_commit());
        assert!(!own.spent());
        own.peer_committed(commit(&[4; 32]));
        assert!(own.spent());
        assert!(!own.awaits_commit());
    }
}
