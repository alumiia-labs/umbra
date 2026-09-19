//! The one-time invitation of Part 4 §4.3.1 and its bundle of Part 5
//! §5.4.1: the link fragment, the blob key, the sealed bundle, and the
//! lifetime on the client side.
//!
//! The link carries the fragment after `#` in base64url without padding
//! (`IDN-159`), and the blob seals the bundle with the link id bound
//! (`IDN-160`).

use alloc::{string::String, vec::Vec};

use umbra_crypto::{aead, hash::sha3_256, labels, secret::Secret};
use umbra_wire::{
    address::{self, QueueAddress},
    codec::{Reader, Writer},
};

use super::INVITE_TTL;
use crate::Error;

/// The path of the landing document.
pub const PATH: &str = "/i";
/// The fragment: 32 bytes of key, 24 bytes of link id, 12 bytes of relay
/// reference.
pub const FRAGMENT_LEN: usize = 68;
/// The blob version.
pub const BLOB_VERSION: u8 = 0x01;

/// The fragment of an invitation link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// 256 bits of key material from the issuer's CSPRNG.
    pub key: [u8; 32],
    /// The server-generated link identifier.
    pub link_id: [u8; 24],
    /// The `RelayRef` of the relay that holds the blob.
    pub relay_ref: [u8; 12],
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let idx = |shift: u32| {
            B64.get(((n >> shift) & 63) as usize)
                .copied()
                .unwrap_or(b'A')
        };
        out.push(char::from(idx(18)));
        out.push(char::from(idx(12)));
        if chunk.len() > 1 {
            out.push(char::from(idx(6)));
        }
        if chunk.len() > 2 {
            out.push(char::from(idx(0)));
        }
    }
    out
}

fn base64url_decode(text: &str, out: &mut [u8]) -> Result<(), Error> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut at = 0usize;
    for c in text.bytes() {
        let v = B64.iter().position(|b| *b == c).ok_or(Error::Malformed)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let slot = out.get_mut(at).ok_or(Error::Malformed)?;
            *slot = ((acc >> bits) & 0xFF) as u8;
            at += 1;
        }
    }
    if at != out.len() || acc & ((1 << bits) - 1) != 0 {
        return Err(Error::Malformed);
    }
    Ok(())
}

impl Fragment {
    /// The fragment of its 68 bytes.
    pub fn from_bytes(bytes: &[u8; FRAGMENT_LEN]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        Ok(Fragment {
            key: r.array()?,
            link_id: r.array()?,
            relay_ref: r.array()?,
        })
    }

    /// The bytes of the fragment.
    pub fn to_bytes(&self) -> [u8; FRAGMENT_LEN] {
        let mut out = [0u8; FRAGMENT_LEN];
        let mut w = Writer::new(&mut out);
        let _ = w.put(&self.key);
        let _ = w.put(&self.link_id);
        let _ = w.put(&self.relay_ref);
        out
    }

    /// The full link for `host`.
    pub fn link(&self, host: &str) -> String {
        let mut s = String::from("https://");
        s.push_str(host);
        s.push_str(PATH);
        s.push('#');
        s.push_str(&base64url(&self.to_bytes()));
        s
    }

    /// Reads a link that names `host`, and refuses one that names any
    /// other host.
    pub fn parse(link: &str, host: &str) -> Result<Self, Error> {
        let prefix = alloc::format!("https://{host}{PATH}#");
        let text = link.strip_prefix(&prefix).ok_or(Error::Malformed)?;
        let mut bytes = [0u8; FRAGMENT_LEN];
        base64url_decode(text, &mut bytes)?;
        let mut r = Reader::new(&bytes);
        Ok(Fragment {
            key: r.array()?,
            link_id: r.array()?,
            relay_ref: r.array()?,
        })
    }

    /// The blob key: `HKDF("umbra/v1/invite-blob" || SHA3-256(fragment))`,
    /// as `HKDF(salt = "", ikm = SHA3-256(fragment), info = label)`.
    pub fn blob_key(&self) -> Secret<32> {
        let digest = sha3_256(&[&self.to_bytes()]);
        let kdf = umbra_crypto::hkdf::Hkdf::<umbra_crypto::sha3::Sha3_256>::new(None, &digest);
        let mut key = Secret::<32>::zeroed();
        let _ = kdf.expand(labels::INVITE_BLOB, key.expose_mut());
        key
    }
}

/// The pre-shared material of Part 5 §5.4.1.
pub struct Bundle<'a> {
    /// The responder's static X25519 public key.
    pub responder_static_x25519: [u8; 32],
    /// The one-time ML-KEM-768 encapsulation key.
    pub responder_kem_ek: &'a [u8],
    /// The advertised version range, min and max.
    pub version_range: [u8; 2],
    /// The first queue of the responder.
    pub queue_address: QueueAddress,
    /// The signed relay bundle for bootstrapping, opaque here.
    pub relay_bundle: &'a [u8],
}

impl<'a> Bundle<'a> {
    /// The plaintext length.
    pub fn len(&self) -> usize {
        32 + 1_184 + 2 + address::LEN + 2 + self.relay_bundle.len()
    }

    /// Whether the relay bundle is empty.
    pub fn is_empty(&self) -> bool {
        self.relay_bundle.is_empty()
    }

    /// Writes the plaintext.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.responder_kem_ek.len() != 1_184 {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.put(&self.responder_static_x25519)?;
        w.put(self.responder_kem_ek)?;
        w.put(&self.version_range)?;
        let n = self.queue_address.encode(w.tail())?;
        let at = w.position().saturating_add(n);
        let mut w = Writer::new(out.get_mut(at..).ok_or(Error::Malformed)?);
        w.u16(u16::try_from(self.relay_bundle.len()).map_err(|_| Error::Malformed)?)?;
        w.put(self.relay_bundle)?;
        Ok(at.saturating_add(w.position()))
    }

    /// Reads the plaintext.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let responder_static_x25519 = r.array()?;
        let responder_kem_ek = r.take(1_184)?;
        let version_range = r.array()?;
        let queue_address = QueueAddress::parse(r.take(address::LEN)?)?;
        let len = usize::from(r.u16()?);
        let relay_bundle = r.take(len)?;
        r.finish()?;
        Ok(Bundle {
            responder_static_x25519,
            responder_kem_ek,
            version_range,
            queue_address,
            relay_bundle,
        })
    }

    /// Seals the bundle into the blob the relay stores: the version, the
    /// nonce, and the ciphertext with its tag, under the blob key of the
    /// fragment with the link id as associated data.
    pub fn seal(&self, fragment: &Fragment, nonce: [u8; 24]) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; 1 + 24 + self.len() + aead::TAG_LEN];
        let mut w = Writer::new(&mut out);
        w.u8(BLOB_VERSION)?;
        w.put(&nonce)?;
        let n = self.encode(w.tail())?;
        let body_at = 25usize;
        let (head, rest) = out.split_at_mut(body_at);
        let _ = head;
        let (body, tag_out) = rest.split_at_mut(n);
        let tag = aead::seal(&fragment.blob_key(), &nonce, &fragment.link_id, body)?;
        tag_out
            .get_mut(..aead::TAG_LEN)
            .ok_or(Error::Malformed)?
            .copy_from_slice(&tag);
        out.truncate(body_at + n + aead::TAG_LEN);
        Ok(out)
    }

    /// Opens a blob into `buf`, which then holds the plaintext, and parses
    /// it. A blob that does not open under the fragment is refused.
    pub fn open(
        fragment: &Fragment,
        blob: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<Bundle<'a>, Error> {
        let mut r = Reader::new(blob);
        if r.u8()? != BLOB_VERSION {
            return Err(Error::Malformed);
        }
        let nonce: [u8; 24] = r.array()?;
        let rest = r.rest();
        let plain_len = rest
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::Malformed)?;
        let (ct, tag) = rest.split_at(plain_len);
        buf.clear();
        buf.extend_from_slice(ct);
        aead::open(&fragment.blob_key(), &nonce, &fragment.link_id, buf, tag)?;
        Bundle::parse(buf)
    }
}

/// An invitation the client issued, with its lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issued {
    /// The fragment.
    pub fragment: Fragment,
    /// The issue time.
    pub issued_at: u64,
    /// Whether a party consumed it.
    pub consumed: bool,
}

impl Issued {
    /// The seconds left before `INVITE_TTL`, which the client shows
    /// (`IDN-128`), or zero.
    pub fn remaining(&self, now: u64) -> u64 {
        self.issued_at
            .saturating_add(INVITE_TTL)
            .saturating_sub(now)
    }

    /// Whether the client treats the invitation as deleted (`IDN-127`).
    pub fn expired(&self, now: u64) -> bool {
        self.remaining(now) == 0
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

    fn fragment() -> Fragment {
        Fragment {
            key: [1; 32],
            link_id: [2; 24],
            relay_ref: [3; 12],
        }
    }

    #[test]
    fn the_link_round_trips_and_names_one_host() {
        let f = fragment();
        let link = f.link("invite.example");
        assert!(link.starts_with("https://invite.example/i#"));
        assert_eq!(Fragment::parse(&link, "invite.example").unwrap(), f);
        assert!(Fragment::parse(&link, "other.example").is_err());
        let mut short = link.clone();
        short.pop();
        assert!(Fragment::parse(&short, "invite.example").is_err());
    }

    #[test]
    fn the_bundle_seals_under_the_fragment_and_opens_at_the_receiver() {
        let f = fragment();
        let bundle = Bundle {
            responder_static_x25519: [4; 32],
            responder_kem_ek: &[5; 1_184],
            version_range: [1, 1],
            queue_address: QueueAddress {
                relay_id: [6; 32],
                sender_id: [7; 32],
                qs_auth_sk: Secret::new([8; 32]),
                qe: Secret::new([9; 32]),
            },
            relay_bundle: b"signed manifest",
        };
        let blob = bundle.seal(&f, [10; 24]).unwrap();
        let mut buf = Vec::new();
        let opened = Bundle::open(&f, &blob, &mut buf).unwrap();
        assert_eq!(opened.queue_address.sender_id, [7; 32]);
        assert_eq!(opened.relay_bundle, b"signed manifest");
        let other = Fragment { key: [11; 32], ..f };
        let mut buf2 = Vec::new();
        assert!(Bundle::open(&other, &blob, &mut buf2).is_err());
        let issued = Issued {
            fragment: f,
            issued_at: 100,
            consumed: false,
        };
        assert_eq!(issued.remaining(100), INVITE_TTL);
        assert!(issued.expired(100 + INVITE_TTL));
    }
}
