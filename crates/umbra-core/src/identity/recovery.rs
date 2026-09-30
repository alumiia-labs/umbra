//! Account recovery, Part 4 §4.7: the two-half recovery code and its root
//! key, the weekly backup credentials, the backup root chunk, the recovery
//! digits with their checksum, and the Shamir shares of the social half.

use alloc::{string::String, vec::Vec};

use umbra_crypto::{
    aead,
    hash::sha3_256,
    hmac::{digest::KeyInit, Hmac, Mac},
    kdf, labels,
    secret::Secret,
    sha3::Sha3_256,
    zeroize::Zeroizing,
};
use umbra_wire::codec::{Reader, Writer};

use super::{address::decimal, BACKUP_ROOT_ENTRIES};
use crate::Error;

/// The recovery code: the user half and the social half.
pub struct RecoveryCode {
    user: Secret<16>,
    social: Secret<16>,
}

/// `BackupRootKey`.
pub struct BackupRootKey(Secret<32>);

/// The four values of one weekly epoch (§4.7.2).
pub struct EpochCredentials {
    /// `backup_handle_epoch`, the `chunk_id` of the root.
    pub handle: [u8; 32],
    /// `backup_write_cred`, the `cred_sk` of the root.
    pub write: Secret<32>,
    /// `backup_read_cred`, the `read_sk` of the root.
    pub read: Secret<32>,
    /// `backup_key_epoch`, the content key of the root.
    pub key: Secret<32>,
}

impl RecoveryCode {
    /// Two independent CSPRNG outputs (`IDN-070`).
    pub const fn new(user: Secret<16>, social: Secret<16>) -> Self {
        RecoveryCode { user, social }
    }

    /// The user half.
    pub fn user(&self) -> &Secret<16> {
        &self.user
    }

    /// The social half.
    pub fn social(&self) -> &Secret<16> {
        &self.social
    }

    /// The code from its 32 bytes, user half first: the payload of the
    /// digits of type `0x0001`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let user: [u8; 16] = bytes
            .get(..16)
            .and_then(|half| half.try_into().ok())
            .ok_or(Error::Malformed)?;
        let social: [u8; 16] = bytes
            .get(16..)
            .and_then(|half| half.try_into().ok())
            .ok_or(Error::Malformed)?;
        Ok(RecoveryCode::new(Secret::new(user), Secret::new(social)))
    }

    /// `BackupRootKey` under the fixed salt and cost of `IDN-177`, which a
    /// device that holds the code alone derives again.
    pub fn backup_root_key(&self) -> Result<BackupRootKey, Error> {
        self.root_key(labels::BACKUP_SALT, kdf::RECOVERY_M_KIB, kdf::RECOVERY_T)
    }

    /// The 32 bytes of the code, user half first.
    pub fn bytes(&self) -> Secret<32> {
        let mut out = [0u8; 32];
        let (u, s) = out.split_at_mut(16);
        u.copy_from_slice(self.user.expose());
        s.copy_from_slice(self.social.expose());
        Secret::new(out)
    }

    /// `BackupRootKey = Argon2id(RecoveryCode, salt, m, t)` from the two
    /// halves together (`IDN-071`), at the floors of §4.7.1 or above.
    pub fn root_key(&self, salt: &[u8], m_kib: u32, t: u32) -> Result<BackupRootKey, Error> {
        if m_kib < kdf::RECOVERY_M_KIB || t < kdf::RECOVERY_T {
            return Err(Error::Malformed);
        }
        let code = self.bytes();
        Ok(BackupRootKey(kdf::argon2id(code.expose(), salt, m_kib, t)?))
    }
}

impl BackupRootKey {
    /// Wraps a key a test or a restore already holds.
    pub const fn from_secret(key: Secret<32>) -> Self {
        BackupRootKey(key)
    }

    /// The key, for the local store of the device that derived it, thus
    /// the KDF runs once.
    pub fn expose_for_store(&self) -> &Secret<32> {
        &self.0
    }

    fn prf(&self, label: &[u8], epoch: u32) -> Secret<32> {
        let mut mac = Hmac::<Sha3_256>::new_from_slice(self.0.expose())
            .unwrap_or_else(|_| Hmac::<Sha3_256>::new(&Default::default()));
        mac.update(label);
        mac.update(&epoch.to_be_bytes());
        Secret::new(mac.finalize().into_bytes().into())
    }

    /// The four values of a weekly epoch.
    pub fn epoch(&self, weekly_epoch: u32) -> EpochCredentials {
        EpochCredentials {
            handle: *self.prf(labels::BACKUP_HANDLE, weekly_epoch).expose(),
            write: self.prf(labels::BACKUP_WRITE, weekly_epoch),
            read: self.prf(labels::BACKUP_READ, weekly_epoch),
            key: self.prf(labels::BACKUP_KEY, weekly_epoch),
        }
    }
}

/// One entry of the backup root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEntry<'a> {
    /// `0x01` a full object, `0x02` a delta object.
    pub kind: u8,
    /// A `FileDescriptor` of Part 12 §12.3.
    pub descriptor: &'a [u8],
}

/// The backup root: the latest full object at entry 0, then each delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRoot<'a> {
    /// The entries.
    pub entries: Vec<BackupEntry<'a>>,
}

impl<'a> BackupRoot<'a> {
    /// The plaintext length.
    pub fn len(&self) -> usize {
        2usize.saturating_add(
            self.entries
                .iter()
                .map(|e| 3usize.saturating_add(e.descriptor.len()))
                .sum(),
        )
    }

    /// Whether the root names nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn check(&self) -> Result<(), Error> {
        if self.entries.is_empty()
            || self.entries.len() > BACKUP_ROOT_ENTRIES
            || self.entries.first().is_some_and(|e| e.kind != 0x01)
            || self
                .entries
                .iter()
                .any(|e| !matches!(e.kind, 0x01 | 0x02) || e.descriptor.len() > 977)
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    /// Writes the plaintext.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(u8::try_from(self.entries.len()).map_err(|_| Error::Malformed)?)?;
        for e in &self.entries {
            w.u8(e.kind)?;
            w.u16(u16::try_from(e.descriptor.len()).map_err(|_| Error::Malformed)?)?;
            w.put(e.descriptor)?;
        }
        Ok(w.position())
    }

    /// Reads the plaintext.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let count = usize::from(r.u8()?);
        let mut entries = Vec::with_capacity(count.min(BACKUP_ROOT_ENTRIES));
        for _ in 0..count {
            let kind = r.u8()?;
            let len = usize::from(r.u16()?);
            entries.push(BackupEntry {
                kind,
                descriptor: r.take(len)?,
            });
        }
        r.finish()?;
        let out = BackupRoot { entries };
        out.check()?;
        Ok(out)
    }

    /// Seals the root into the chunk plaintext of `IDN-094`: the nonce and
    /// the sealed root, before the padding of Part 12 §12.2.3.
    pub fn seal(&self, credentials: &EpochCredentials, nonce: [u8; 24]) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; 24 + self.len() + aead::TAG_LEN];
        let (nonce_out, rest) = out.split_at_mut(24);
        nonce_out.copy_from_slice(&nonce);
        let n = self.encode(rest)?;
        let (body, tag_out) = rest.split_at_mut(n);
        let tag = aead::seal(&credentials.key, &nonce, &credentials.handle, body)?;
        tag_out
            .get_mut(..aead::TAG_LEN)
            .ok_or(Error::Malformed)?
            .copy_from_slice(&tag);
        out.truncate(24 + n + aead::TAG_LEN);
        Ok(out)
    }

    /// Opens a root chunk under the credentials of its epoch (`IDN-103`).
    pub fn open(
        credentials: &EpochCredentials,
        chunk: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<BackupRoot<'a>, Error> {
        let mut r = Reader::new(chunk);
        let nonce: [u8; 24] = r.array()?;
        let rest = r.rest();
        let plain_len = rest
            .len()
            .checked_sub(aead::TAG_LEN)
            .ok_or(Error::Malformed)?;
        let (ct, tag) = rest.split_at(plain_len);
        buf.clear();
        buf.extend_from_slice(ct);
        aead::open(&credentials.key, &nonce, &credentials.handle, buf, tag)?;
        BackupRoot::parse(buf)
    }
}

/// The type of a `RecoveryDigits` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DigitsType {
    /// The recovery code, 32 bytes, 87 digits.
    Code = 0x0001,
    /// `C_user`, 16 bytes, 49 digits.
    User = 0x0002,
    /// A share of `C_social`, 17 bytes, 51 digits.
    Share = 0x0003,
    /// The root seed of `IDN-003`, 32 bytes, 87 digits.
    Root = 0x0004,
}

impl DigitsType {
    const fn payload_len(self) -> usize {
        match self {
            DigitsType::Code | DigitsType::Root => 32,
            DigitsType::User => 16,
            DigitsType::Share => 17,
        }
    }

    /// The fixed digit width of the type.
    pub const fn width(self) -> usize {
        match self {
            DigitsType::Code | DigitsType::Root => 87,
            DigitsType::User => 49,
            DigitsType::Share => 51,
        }
    }

    fn from_u16(v: u16) -> Result<Self, Error> {
        match v {
            0x0001 => Ok(DigitsType::Code),
            0x0002 => Ok(DigitsType::User),
            0x0003 => Ok(DigitsType::Share),
            0x0004 => Ok(DigitsType::Root),
            _ => Err(Error::Malformed),
        }
    }
}

fn check_of(kind: DigitsType, payload: &[u8]) -> [u8; 2] {
    let digest = sha3_256(&[&(kind as u16).to_be_bytes(), payload]);
    [
        digest.first().copied().unwrap_or(0),
        digest.get(1).copied().unwrap_or(0),
    ]
}

/// Encodes a secret as `RecoveryDigits`, in groups of five (`IDN-149`).
pub fn to_digits(kind: DigitsType, payload: &[u8]) -> Result<Zeroizing<String>, Error> {
    if payload.len() != kind.payload_len() {
        return Err(Error::Malformed);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    bytes.extend_from_slice(&(kind as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&check_of(kind, payload));
    let digits = Zeroizing::new(decimal(&bytes, kind.width()));
    let mut out = Zeroizing::new(String::with_capacity(kind.width() + kind.width() / 5));
    for (i, group) in digits.as_bytes().chunks(5).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(core::str::from_utf8(group).unwrap_or(""));
    }
    Ok(out)
}

/// Decodes entered digits, verifies the checksum before any KDF runs
/// (`IDN-151`), and refuses a type other than `expected` (`IDN-154`).
/// The error carries nothing; the caller names the types to the user.
pub fn from_digits(text: &str, expected: DigitsType) -> Result<Zeroizing<Vec<u8>>, Error> {
    let digits: Zeroizing<Vec<u8>> =
        Zeroizing::new(text.bytes().filter(|b| b.is_ascii_digit()).collect());
    // The digit count names the length. The root seed and the recovery
    // code share a width, and `type` tells them apart (IDN-153).
    let total_len = 4 + match digits.len() {
        87 => DigitsType::Code.payload_len(),
        49 => DigitsType::User.payload_len(),
        51 => DigitsType::Share.payload_len(),
        _ => return Err(Error::Malformed),
    };
    // Decimal to big-endian bytes by repeated multiply-add.
    let mut bytes = Zeroizing::new(alloc::vec![0u8; total_len]);
    for d in digits.iter() {
        let mut carry = u32::from(d - b'0');
        for b in bytes.iter_mut().rev() {
            let cur = u32::from(*b) * 10 + carry;
            *b = (cur & 0xFF) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            return Err(Error::Malformed);
        }
    }
    let mut r = Reader::new(&bytes);
    let kind = DigitsType::from_u16(r.u16()?)?;
    if kind.width() != digits.len() {
        return Err(Error::Malformed);
    }
    let payload = Zeroizing::new(r.take(kind.payload_len())?.to_vec());
    let check: [u8; 2] = r.array()?;
    if check != check_of(kind, &payload) {
        return Err(Error::Malformed);
    }
    if kind != expected {
        return Err(Error::Unverified);
    }
    Ok(payload)
}

// Shamir over GF(2^8) with the AES polynomial, for the social half.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    // a^254 by square-and-multiply.
    let mut result = 1u8;
    let mut base = a;
    let mut e = 254u8;
    while e > 0 {
        if e & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

/// Splits `secret` into `n` shares with threshold `k` (§4.7.3). `coeffs`
/// supplies `(k − 1) × 16` random bytes from the CSPRNG. Each share is its
/// index and 16 bytes, as a `DigitsType::Share` payload.
pub fn split_social(
    secret: &Secret<16>,
    k: u8,
    n: u8,
    coeffs: &[u8],
) -> Result<Vec<[u8; 17]>, Error> {
    if k < 2 || n < k || coeffs.len() != usize::from(k - 1) * 16 {
        return Err(Error::Malformed);
    }
    let mut shares = Vec::with_capacity(usize::from(n));
    for x in 1..=n {
        let mut share = [0u8; 17];
        share[0] = x;
        for byte in 0..16 {
            let mut y = secret.expose().get(byte).copied().unwrap_or(0);
            let mut xp = x;
            for c in 0..usize::from(k - 1) {
                let coeff = coeffs.get(c * 16 + byte).copied().unwrap_or(0);
                y ^= gf_mul(coeff, xp);
                xp = gf_mul(xp, x);
            }
            if let Some(slot) = share.get_mut(1 + byte) {
                *slot = y;
            }
        }
        shares.push(share);
    }
    Ok(shares)
}

/// Rebuilds `C_social` from `k` or more shares with distinct indices.
pub fn join_social(shares: &[[u8; 17]]) -> Result<Secret<16>, Error> {
    if shares.len() < 2 {
        return Err(Error::Malformed);
    }
    let mut xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();
    xs.sort_unstable();
    if xs.contains(&0) || xs.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return Err(Error::Malformed);
    }
    let mut out = [0u8; 16];
    for (byte, slot) in out.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, share) in shares.iter().enumerate() {
            let xi = share[0];
            let yi = share.get(1 + byte).copied().unwrap_or(0);
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, other) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = other[0];
                num = gf_mul(num, xj);
                den = gf_mul(den, xi ^ xj);
            }
            acc ^= gf_mul(yi, gf_mul(num, gf_inv(den)));
        }
        *slot = acc;
    }
    Ok(Secret::new(out))
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
    fn the_digits_carry_a_type_and_a_checksum() {
        let code = [7u8; 32];
        let text = to_digits(DigitsType::Code, &code).unwrap();
        assert_eq!(text.bytes().filter(|b| b.is_ascii_digit()).count(), 87);
        assert_eq!(*from_digits(&text, DigitsType::Code).unwrap(), code);
        assert_eq!(from_digits(&text, DigitsType::User), Err(Error::Unverified));
        let mut wrong = text.clone();
        let last = wrong.pop().unwrap();
        wrong.push(if last == '0' { '1' } else { '0' });
        assert!(from_digits(&wrong, DigitsType::Code).is_err());
        assert_eq!(
            to_digits(DigitsType::User, &[1; 16])
                .unwrap()
                .bytes()
                .filter(|b| b.is_ascii_digit())
                .count(),
            49
        );
        assert_eq!(
            to_digits(DigitsType::Share, &[1; 17])
                .unwrap()
                .bytes()
                .filter(|b| b.is_ascii_digit())
                .count(),
            51
        );
        // IDN-003: the root seed takes the width of the code, and its type
        // tells the two apart (IDN-153).
        let seed = to_digits(DigitsType::Root, &[9; 32]).unwrap();
        assert_eq!(seed.bytes().filter(|b| b.is_ascii_digit()).count(), 87);
        assert_eq!(*from_digits(&seed, DigitsType::Root).unwrap(), [9; 32]);
        assert_eq!(from_digits(&seed, DigitsType::Code), Err(Error::Unverified));
        assert_eq!(from_digits(&text, DigitsType::Root), Err(Error::Unverified));
    }

    #[test]
    fn three_of_five_shares_rebuild_the_social_half_and_two_do_not() {
        let secret = Secret::new([0xAB; 16]);
        let coeffs = [0x5Au8; 32];
        let shares = split_social(&secret, 3, 5, &coeffs).unwrap();
        assert_eq!(shares.len(), 5);
        let rebuilt = join_social(&[shares[0], shares[2], shares[4]]).unwrap();
        assert_eq!(rebuilt.expose(), secret.expose());
        let rebuilt = join_social(&[shares[3], shares[1], shares[0], shares[4]]).unwrap();
        assert_eq!(rebuilt.expose(), secret.expose());
        let two = join_social(&[shares[0], shares[1]]).unwrap();
        assert_ne!(two.expose(), secret.expose());
        assert!(join_social(&[shares[0], shares[0]]).is_err());
        assert_eq!(gf_mul(gf_inv(0x53), 0x53), 1);
    }

    #[test]
    fn the_backup_root_seals_under_the_weekly_credentials() {
        let key = BackupRootKey::from_secret(Secret::new([3; 32]));
        let week = key.epoch(2_950);
        let next = key.epoch(2_951);
        assert_ne!(week.handle, next.handle);
        let root = BackupRoot {
            entries: alloc::vec![
                BackupEntry {
                    kind: 0x01,
                    descriptor: &[1; 257]
                },
                BackupEntry {
                    kind: 0x02,
                    descriptor: &[2; 257]
                },
            ],
        };
        let chunk = root.seal(&week, [4; 24]).unwrap();
        let mut buf = Vec::new();
        assert_eq!(BackupRoot::open(&week, &chunk, &mut buf).unwrap(), root);
        let mut buf2 = Vec::new();
        assert!(BackupRoot::open(&next, &chunk, &mut buf2).is_err());
        let delta_first = BackupRoot {
            entries: alloc::vec![BackupEntry {
                kind: 0x02,
                descriptor: &[2; 10]
            }],
        };
        assert!(delta_first.encode(&mut [0u8; 100]).is_err());
        let code = RecoveryCode::new(Secret::new([1; 16]), Secret::new([2; 16]));
        assert!(code.root_key(b"salt", 8, 1).is_err());
        assert_eq!(code.bytes().expose()[16], 2);
    }
}
