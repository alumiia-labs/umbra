//! Oblivious HTTP of RFC 9458 under the HPKE of AUX-6: the hop to the
//! Notification Delivery Relay of Part 8 §8.2 (`NTF-002`, `NTF-115`).
//!
//! The encapsulation follows RFC 9458 §4.3 and §4.4 with the suite ids of
//! Part 5 §5.4 in the header and in the key configuration. The inner
//! message is an NDR request of Part 8 §8.2.7 and no Binary HTTP message,
//! thus the labels name that media type, as RFC 9458 §4.6 permits for
//! another application (`NTF-126`).

use alloc::vec::Vec;

use hkdf::SimpleHkdf;
use rand_core::CryptoRng;
use sha3::Sha3_256;

use crate::{
    aead,
    hpke::{self, KdfHash, KemSuite, UmbraKem},
    kem::{KeyPair, PublicKey, CIPHERTEXT_LEN, PUBLIC_KEY_LEN},
    secret::Secret,
    Error,
};

/// The label of a request.
pub const REQUEST_LABEL: &[u8] = b"message/umbra-ndr request";
/// The label of a response.
pub const RESPONSE_LABEL: &[u8] = b"message/umbra-ndr response";
/// The header of a request: `key_id`, `kem_id`, `kdf_id`, `aead_id`.
pub const HEADER_LEN: usize = 7;
/// `max(Nn, Nk)` of the AEAD, the length of the response nonce.
pub const RESPONSE_NONCE_LEN: usize = 32;
/// The length of a key configuration with its one suite.
pub const KEY_CONFIG_LEN: usize = 1 + 2 + PUBLIC_KEY_LEN + 2 + 4;

fn header(key_id: u8) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    let [k0, k1] = UmbraKem::KEM_ID.to_be_bytes();
    let [d0, d1] = Sha3_256::KDF_ID.to_be_bytes();
    let [a0, a1] = hpke::AEAD_ID.to_be_bytes();
    for (slot, byte) in out.iter_mut().zip([key_id, k0, k1, d0, d1, a0, a1]) {
        *slot = byte;
    }
    out
}

fn request_info(header: &[u8; HEADER_LEN]) -> Vec<u8> {
    [REQUEST_LABEL, &[0x00], header.as_slice()].concat()
}

/// The key configuration of RFC 9458 §3 with one suite: what a client
/// needs to reach the gateway.
pub fn encode_key_config(key_id: u8, public: &PublicKey) -> [u8; KEY_CONFIG_LEN] {
    let head = header(key_id);
    let suites = 4u16.to_be_bytes();
    let parts: [&[u8]; 5] = [
        head.get(..3).unwrap_or_default(),
        &public.to_bytes(),
        &suites,
        head.get(3..).unwrap_or_default(),
        &[],
    ];
    let mut out = [0u8; KEY_CONFIG_LEN];
    let mut at = 0usize;
    for part in parts {
        if let Some(slot) = out.get_mut(at..at.saturating_add(part.len())) {
            slot.copy_from_slice(part);
        }
        at = at.saturating_add(part.len());
    }
    out
}

/// Reads a key configuration. It must name the UMBRA suite and no other.
pub fn parse_key_config(bytes: &[u8]) -> Result<(u8, PublicKey), Error> {
    if bytes.len() != KEY_CONFIG_LEN {
        return Err(Error::Length);
    }
    let key_id = *bytes.first().ok_or(Error::Length)?;
    let expected = header(key_id);
    let pk_end = 3 + PUBLIC_KEY_LEN;
    let is_suite = bytes.get(..3) == expected.get(..3)
        && bytes.get(pk_end..pk_end + 2) == Some(&4u16.to_be_bytes()[..])
        && bytes.get(pk_end + 2..) == expected.get(3..);
    if !is_suite {
        return Err(Error::Length);
    }
    let public = PublicKey::from_bytes(bytes.get(3..pk_end).ok_or(Error::Length)?)?;
    Ok((key_id, public))
}

/// What the client keeps to open the response, and what the gateway keeps
/// to seal it: the exported secret and the encapsulation.
pub struct ResponseKey {
    secret: Secret<32>,
    enc: Vec<u8>,
}

impl ResponseKey {
    fn keys(&self, nonce: &[u8]) -> Result<(Secret<32>, [u8; 12]), Error> {
        let salt = [self.enc.as_slice(), nonce].concat();
        let (_, kdf) = SimpleHkdf::<Sha3_256>::extract(Some(&salt), self.secret.expose());
        let mut key = Secret::<32>::zeroed();
        kdf.expand(b"key", key.expose_mut())
            .map_err(|_| Error::Length)?;
        let mut aead_nonce = [0u8; 12];
        kdf.expand(b"nonce", &mut aead_nonce)
            .map_err(|_| Error::Length)?;
        Ok((key, aead_nonce))
    }
}

/// Encapsulates a request to the gateway key (RFC 9458 §4.3).
pub fn encapsulate_request<R: CryptoRng + ?Sized>(
    key_id: u8,
    public: &PublicKey,
    request: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, ResponseKey), Error> {
    let head = header(key_id);
    let (enc, mut context) =
        hpke::setup_sender::<UmbraKem, Sha3_256, R>(public, &request_info(&head), rng)?;
    let sealed = context.seal(&[], request)?;
    let mut secret = Secret::<32>::zeroed();
    context.export(RESPONSE_LABEL, secret.expose_mut())?;
    let out = [head.as_slice(), &enc, &sealed].concat();
    Ok((out, ResponseKey { secret, enc }))
}

/// Opens a request at the gateway. A request under another key id or
/// another suite is refused (RFC 9458 §4.3).
pub fn decapsulate_request(
    key_id: u8,
    pair: &KeyPair,
    bytes: &[u8],
) -> Result<(Vec<u8>, ResponseKey), Error> {
    let head = header(key_id);
    if bytes.get(..HEADER_LEN) != Some(head.as_slice()) {
        return Err(Error::Length);
    }
    let enc_end = HEADER_LEN + CIPHERTEXT_LEN;
    let enc = bytes.get(HEADER_LEN..enc_end).ok_or(Error::Length)?;
    let sealed = bytes.get(enc_end..).ok_or(Error::Length)?;
    let mut context = hpke::setup_recipient::<UmbraKem, Sha3_256>(pair, enc, &request_info(&head))?;
    let request = context.open(&[], sealed)?;
    let mut secret = Secret::<32>::zeroed();
    context.export(RESPONSE_LABEL, secret.expose_mut())?;
    Ok((
        request,
        ResponseKey {
            secret,
            enc: enc.to_vec(),
        },
    ))
}

/// Encapsulates the response of the gateway (RFC 9458 §4.4).
pub fn encapsulate_response<R: CryptoRng + ?Sized>(
    key: &ResponseKey,
    response: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; RESPONSE_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let (aead_key, aead_nonce) = key.keys(&nonce)?;
    let mut body = response.to_vec();
    let tag = aead::seal_ietf(&aead_key, &aead_nonce, &[], &mut body)?;
    Ok([nonce.as_slice(), &body, &tag].concat())
}

/// Opens the response at the client.
pub fn decapsulate_response(key: &ResponseKey, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = bytes.get(..RESPONSE_NONCE_LEN).ok_or(Error::Length)?;
    let rest = bytes.get(RESPONSE_NONCE_LEN..).ok_or(Error::Length)?;
    let split = rest.len().checked_sub(aead::TAG_LEN).ok_or(Error::Length)?;
    let (body, tag) = rest.split_at(split);
    let (aead_key, aead_nonce) = key.keys(nonce)?;
    let mut plain = body.to_vec();
    aead::open_ietf(&aead_key, &aead_nonce, &[], &mut plain, tag)?;
    Ok(plain)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;

    #[test]
    fn a_request_and_its_response_cross_the_gateway() {
        let mut rng = TestRng::new(b"ohttp one");
        let gateway = KeyPair::generate(&mut rng);
        let config = encode_key_config(3, gateway.public());
        let (key_id, public) = parse_key_config(&config).unwrap();
        assert_eq!(key_id, 3);

        let (sealed, client_key) =
            encapsulate_request(key_id, &public, b"an NDR request", &mut rng).unwrap();
        assert_eq!(sealed[..HEADER_LEN], header(3));
        assert_eq!(
            sealed.len(),
            HEADER_LEN + CIPHERTEXT_LEN + 14 + aead::TAG_LEN
        );
        let (request, gateway_key) = decapsulate_request(3, &gateway, &sealed).unwrap();
        assert_eq!(request, b"an NDR request");

        let response = encapsulate_response(&gateway_key, b"taken", &mut rng).unwrap();
        assert_eq!(
            decapsulate_response(&client_key, &response).unwrap(),
            b"taken"
        );
        let mut changed = response.clone();
        changed[40] ^= 1;
        assert!(decapsulate_response(&client_key, &changed).is_err());
    }

    #[test]
    fn another_key_id_a_changed_header_or_another_suite_is_refused() {
        let mut rng = TestRng::new(b"ohttp two");
        let gateway = KeyPair::generate(&mut rng);
        let (sealed, _) = encapsulate_request(3, gateway.public(), b"request", &mut rng).unwrap();
        assert!(decapsulate_request(4, &gateway, &sealed).is_err());
        let mut suite = sealed.clone();
        suite[6] ^= 1;
        assert!(decapsulate_request(3, &gateway, &suite).is_err());
        let mut body = sealed;
        let last = body.len() - 1;
        body[last] ^= 1;
        assert!(decapsulate_request(3, &gateway, &body).is_err());

        let mut config = encode_key_config(3, gateway.public());
        config[KEY_CONFIG_LEN - 1] ^= 1;
        assert!(parse_key_config(&config).is_err());
    }
}
