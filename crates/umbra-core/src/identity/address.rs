//! The public address string, the reusable link, the safety number, and
//! the avatar color of Part 4 §4.2.3, §4.2.5, §4.3.2, and §4.5.
//!
//! The specification writes the address as base32 and names no alphabet.
//! Its example holds the digits 1, 8, and 9, which the RFC 4648 alphabet
//! lacks, thus this module uses the Crockford alphabet in lower case, and
//! a decoder folds case and the confusable letters as that alphabet does.

use alloc::string::String;

use umbra_crypto::{hash::sha3_256, labels};

use super::PALETTE_SIZE;
use crate::Error;

/// The prefix of an address string.
pub const PUB_PREFIX: &str = "umbra:pub:";
/// The prefix of a reusable link.
pub const LINK_PREFIX: &str = "umbra://p/";
/// The address bytes: the first 20 of the hash of the public key.
pub const ADDRESS_LEN: usize = 20;
/// The address characters.
pub const ADDRESS_CHARS: usize = 32;

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Encodes bytes in Crockford base32, lower case, no padding.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 31) as usize;
            out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'0')));
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 31) as usize;
        out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'0')));
    }
    out
}

fn value_of(c: char) -> Option<u32> {
    let c = c.to_ascii_lowercase();
    let c = match c {
        'o' => '0',
        'i' | 'l' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|a| char::from(*a) == c)
        .map(|p| p as u32)
}

/// Decodes Crockford base32 into `out`, which sets the byte count.
pub fn base32_decode(text: &str, out: &mut [u8]) -> Result<(), Error> {
    let needed = out.len().saturating_mul(8).div_ceil(5);
    if text.chars().count() != needed {
        return Err(Error::Malformed);
    }
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut at = 0usize;
    for c in text.chars() {
        acc = (acc << 5) | value_of(c).ok_or(Error::Malformed)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if let Some(slot) = out.get_mut(at) {
                *slot = ((acc >> bits) & 0xFF) as u8;
            }
            at += 1;
        }
    }
    // The spare low bits of the last character are zero in canonical form.
    if acc & ((1 << bits) - 1) != 0 {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// The 20-byte address of a public address key: `SHA3-256(pk)[0..20]`.
pub fn address_of(public_key: &[u8]) -> [u8; ADDRESS_LEN] {
    let digest = sha3_256(&[public_key]);
    let mut out = [0u8; ADDRESS_LEN];
    if let Some(head) = digest.get(..ADDRESS_LEN) {
        out.copy_from_slice(head);
    }
    out
}

/// `umbra:pub:<address>`.
pub fn pub_string(address: &[u8; ADDRESS_LEN]) -> String {
    let mut s = String::from(PUB_PREFIX);
    s.push_str(&base32(address));
    s
}

/// `umbra://p/<address>`, the reusable link (`IDN-129`).
pub fn link_string(address: &[u8; ADDRESS_LEN]) -> String {
    let mut s = String::from(LINK_PREFIX);
    s.push_str(&base32(address));
    s
}

/// Reads a pasted `umbra:pub:` string or a reusable link (`IDN-130`).
pub fn parse(text: &str) -> Result<[u8; ADDRESS_LEN], Error> {
    let body = text
        .strip_prefix(PUB_PREFIX)
        .or_else(|| text.strip_prefix(LINK_PREFIX))
        .ok_or(Error::Malformed)?;
    let mut out = [0u8; ADDRESS_LEN];
    base32_decode(body, &mut out)?;
    Ok(out)
}

/// Checks a resolved public key against the address before a hello
/// (`IDN-131`).
pub fn check(address: &[u8; ADDRESS_LEN], public_key: &[u8]) -> Result<(), Error> {
    if address_of(public_key) == *address {
        Ok(())
    } else {
        Err(Error::Unverified)
    }
}

/// The two pairwise identity public keys in canonical order.
pub fn canonical_pair<'a>(a: &'a [u8], b: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// The 60-digit safety number of a pairwise channel, in groups of five
/// (§4.5).
pub fn safety_number(own_pk: &[u8], peer_pk: &[u8]) -> String {
    let (lo, hi) = canonical_pair(own_pk, peer_pk);
    let digest = sha3_256(&[lo, hi]);
    let digits = decimal(&digest, 60);
    let mut out = String::with_capacity(72);
    for (i, group) in digits.as_bytes().chunks(5).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(core::str::from_utf8(group).unwrap_or(""));
    }
    out
}

/// The big-endian integer of `bytes` in decimal, with leading zeros to
/// `width` digits, and truncated to the last `width` digits if longer.
pub fn decimal(bytes: &[u8], width: usize) -> String {
    let mut digits: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut number: alloc::vec::Vec<u8> = bytes.to_vec();
    while number.iter().any(|b| *b != 0) {
        let mut rem: u32 = 0;
        for b in number.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    while digits.len() < width {
        digits.push(b'0');
    }
    digits.truncate(width);
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

/// The generated avatar color of a public address (§4.2.5).
pub fn avatar_color(public_key: &[u8]) -> u8 {
    let digest = sha3_256(&[labels::AVATAR_COLOR, public_key]);
    // The digest as a big-endian integer modulo 12: fold byte by byte.
    let mut rem: u32 = 0;
    for b in digest {
        rem = ((rem << 8) | u32::from(b)) % u32::from(PALETTE_SIZE);
    }
    rem as u8
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
    fn the_address_is_32_characters_and_round_trips() {
        let pk = [7u8; 1216];
        let address = address_of(&pk);
        let s = pub_string(&address);
        assert_eq!(s.len(), PUB_PREFIX.len() + ADDRESS_CHARS);
        assert_eq!(parse(&s).unwrap(), address);
        assert_eq!(parse(&link_string(&address)).unwrap(), address);
        check(&address, &pk).unwrap();
        assert!(check(&address, &[8u8; 1216]).is_err());
        let upper = s.to_uppercase().replace("UMBRA:PUB:", "umbra:pub:");
        assert_eq!(parse(&upper).unwrap(), address);
        assert!(parse("umbra:pub:7f3ck2mq9x4vhn8dpwr5esa1").is_err());
        assert!(parse("umbra:pub:7f3ck2mq9x4vhn8dpwr5esa1uuuuuuuu").is_err());
    }

    #[test]
    fn the_safety_number_is_60_digits_and_symmetric() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let n = safety_number(&a, &b);
        assert_eq!(n, safety_number(&b, &a));
        assert_eq!(n.len(), 60 + 11);
        assert_eq!(n.split(' ').count(), 12);
        assert_eq!(decimal(&[0, 0, 255], 5), "00255");
        assert_eq!(decimal(&[1, 0], 3), "256");
        assert!(avatar_color(&a) < PALETTE_SIZE);
    }
}
