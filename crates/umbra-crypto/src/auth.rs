//! The deniable command authenticator of Part 3 §3.2.3 and the session
//! resume authenticator of Part 6 §6.2.3.
//!
//! Both are HMAC-SHA3-256 values under a shared key, thus a seized relay
//! holds no proof that a given device wrote a given command (`NET-015`).

use hkdf::Hkdf;
use hmac::{digest::KeyInit, Hmac, Mac};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::{labels, secret::Secret, Error};

/// The length of a command authenticator.
pub const AUTH_LEN: usize = 32;
/// The length of a session resume authenticator.
pub const RESUME_AUTH_LEN: usize = 16;

/// `k`, the key that authenticates the commands of one queue in one relay
/// session.
pub struct CommandAuthKey(Secret<32>);

impl CommandAuthKey {
    /// `HKDF("umbra/v1/cmd-auth", X25519(auth_sk, relay_session_pk))`.
    ///
    /// Fails on a non-contributory Diffie-Hellman output.
    pub fn derive(
        auth_secret: &StaticSecret,
        relay_session_public: &[u8; 32],
    ) -> Result<Self, Error> {
        let shared = auth_secret.diffie_hellman(&XPublic::from(*relay_session_public));
        if !shared.was_contributory() {
            return Err(Error::Key);
        }
        let kdf = Hkdf::<Sha3_256>::new(None, shared.as_bytes());
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand(labels::CMD_AUTH, key.expose_mut());
        Ok(Self(key))
    }

    /// `auth = HMAC(k, corr_id || authorized_bytes)`.
    pub fn mac(&self, corr_id: &[u8; 16], authorized_bytes: &[&[u8]]) -> [u8; AUTH_LEN] {
        let mut mac = keyed(self.0.expose());
        mac.update(corr_id);
        for part in authorized_bytes {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    /// Verifies `auth` (`NET-121`).
    pub fn verify(
        &self,
        corr_id: &[u8; 16],
        authorized_bytes: &[&[u8]],
        auth: &[u8],
    ) -> Result<(), Error> {
        let expected = self.mac(corr_id, authorized_bytes);
        if auth.len() == AUTH_LEN && bool::from(expected.ct_eq(auth)) {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
}

/// The `auth` of a `SessionResume` (Part 6 §6.2.3).
pub fn session_resume_auth(
    session_secret: &Secret<32>,
    session_id: &[u8; 8],
    resume_count: u32,
) -> [u8; RESUME_AUTH_LEN] {
    let mut mac = keyed(session_secret.expose());
    mac.update(labels::SESSION_RESUME);
    mac.update(session_id);
    mac.update(&resume_count.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; RESUME_AUTH_LEN];
    if let Some(head) = full.get(..RESUME_AUTH_LEN) {
        out.copy_from_slice(head);
    }
    out
}

/// Verifies the `auth` of a `SessionResume` (`WIR-237`).
pub fn verify_session_resume(
    session_secret: &Secret<32>,
    session_id: &[u8; 8],
    resume_count: u32,
    auth: &[u8],
) -> Result<(), Error> {
    let expected = session_resume_auth(session_secret, session_id, resume_count);
    if auth.len() == RESUME_AUTH_LEN && bool::from(expected.ct_eq(auth)) {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}

fn keyed(key: &[u8; 32]) -> Hmac<Sha3_256> {
    // A 32-byte key is inside the HMAC key bound, thus this cannot fail.
    Hmac::<Sha3_256>::new_from_slice(key)
        .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()))
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
    fn the_two_ends_derive_one_key_and_the_bytes_bind() {
        let client = StaticSecret::from([3u8; 32]);
        let relay = StaticSecret::from([4u8; 32]);
        let relay_pk = *XPublic::from(&relay).as_bytes();
        let client_pk = *XPublic::from(&client).as_bytes();
        let at_client = CommandAuthKey::derive(&client, &relay_pk).unwrap();
        let at_relay = CommandAuthKey::derive(&relay, &client_pk).unwrap();
        let corr = [7u8; 16];
        let auth = at_client.mac(&corr, &[b"header", b"payload"]);
        at_relay
            .verify(&corr, &[b"header", b"payload"], &auth)
            .unwrap();
        assert!(at_relay
            .verify(&[8u8; 16], &[b"header", b"payload"], &auth)
            .is_err());
        assert!(at_relay
            .verify(&corr, &[b"header", b"payloae"], &auth)
            .is_err());
        assert!(at_relay
            .verify(&corr, &[b"header", b"payload"], &auth[..31])
            .is_err());
        assert!(CommandAuthKey::derive(&client, &[0u8; 32]).is_err());
    }

    #[test]
    fn the_resume_auth_binds_the_count() {
        let secret = Secret::new([9u8; 32]);
        let id = [1u8; 8];
        let auth = session_resume_auth(&secret, &id, 1);
        verify_session_resume(&secret, &id, 1, &auth).unwrap();
        assert!(verify_session_resume(&secret, &id, 2, &auth).is_err());
        let mut bad = auth;
        bad[0] ^= 1;
        assert!(verify_session_resume(&secret, &id, 1, &bad).is_err());
    }
}
