//! The two handshakes of Part 5 §5.4: `UMBRA-XKhfs` between two clients, and
//! `UMBRA-NKhfs` between a client and a circuit hop.
//!
//! Both run the four operations of §5.4.8 over one state. Each flight binds
//! the full transcript before it, because `h` is the associated data of
//! every seal. The AEAD counter restarts at each `MixKey`, thus no nonce
//! repeats under one key.

pub mod nk;
pub mod xk;

#[cfg(test)]
mod tests;

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::{labels, secret::Secret, Error};

/// Size of a flight tag and of an AEAD tag.
pub const TAG_LEN: usize = 16;

/// The one cipher suite of v1 (Part 5 §5.10), as the prologue encodes it.
pub mod suite {
    /// `suite_version`.
    pub const VERSION: u8 = 0x01;
    /// `kem_id`, X25519 with ML-KEM-768.
    pub const KEM: u16 = 0x0001;
    /// `sig_id`, ML-DSA-65.
    pub const SIG: u16 = 0x0001;
    /// `aead_id`, ChaCha20-Poly1305.
    pub const AEAD: u16 = 0x0001;
    /// `kdf_id`, HKDF-SHA3-256.
    pub const KDF: u16 = 0x0001;
}

/// The address type of a pairwise handshake, one byte of the prologue.
///
/// Part 5 §5.4.8 gives the two values and their bytes, and rule `CRY-135`
/// puts the byte in the prologue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// A pairwise identity of Part 4 §4.2.2.
    Pairwise = 0x01,
    /// A published address of Part 4 §4.2.3.
    Published = 0x02,
}

/// An advertised version range of Part 6 §6.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionRange {
    /// The lowest version the party accepts.
    pub min: u8,
    /// The highest version the party accepts.
    pub max: u8,
}

impl VersionRange {
    /// The one range of v1.
    pub const V1: Self = Self { min: 1, max: 1 };

    /// The version the two parties select, or an abort (`WIR-092`).
    pub fn negotiate(self, other: Self) -> Result<u8, Error> {
        let v = self.max.min(other.max);
        if v < self.min || v < other.min {
            return Err(Error::Handshake);
        }
        Ok(v)
    }
}

/// A sink for the state after each numbered step of a schedule. It exists
/// for the transcript vectors of Part 5 rules `CRY-061` and `CRY-117`; a
/// protocol path uses [`NoTrace`], and a trace of a live handshake is a leak.
pub trait Trace {
    /// Records the state after `step`.
    fn step(&mut self, step: &'static str, ck: &[u8; 32], h: &[u8; 32], n: u64);
}

/// The trace of a protocol path: it records nothing.
pub struct NoTrace;

impl Trace for NoTrace {
    fn step(&mut self, _: &'static str, _: &[u8; 32], _: &[u8; 32], _: u64) {}
}

/// The handshake state of §5.4.8: `ck`, `h`, `k`, and `n`.
pub(crate) struct State {
    ck: Secret<32>,
    h: [u8; 32],
    k: Option<Secret<32>>,
    n: u64,
}

impl Drop for State {
    fn drop(&mut self) {
        self.h.zeroize();
        self.n = 0;
    }
}

impl State {
    /// Writes the state for a handshake that waits across a run of the
    /// client: `ck`, `h`, `k` when it is set, and `n`.
    pub(crate) fn export(&self, writer: &mut crate::stored::Writer) {
        writer.bytes(self.ck.expose());
        writer.bytes(&self.h);
        writer.option(self.k.as_ref(), |writer, k| writer.bytes(k.expose()));
        writer.u64(self.n);
    }

    /// Reads a state that [`State::export`] wrote.
    pub(crate) fn restore(reader: &mut crate::stored::Reader<'_>) -> Result<Self, Error> {
        let ck = Secret::new(reader.array()?);
        let h = reader.array()?;
        let k = reader.option(|reader| Ok(Secret::new(reader.array()?)))?;
        let n = reader.u64()?;
        Ok(State { ck, h, k, n })
    }

    /// A second copy of the state. A party reads a flight on the copy, thus
    /// a flight that does not verify leaves the state as it was.
    pub(crate) fn copy(&self) -> Self {
        State {
            ck: Secret::new(*self.ck.expose()),
            h: self.h,
            k: self.k.as_ref().map(|k| Secret::new(*k.expose())),
            n: self.n,
        }
    }

    /// The initialization: `ck = SHA3-256(label || name)`, `h = ck`.
    pub(crate) fn new(name: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(labels::HANDSHAKE_CK);
        hasher.update(name);
        let ck: [u8; 32] = hasher.finalize().into();
        Self {
            ck: Secret::new(ck),
            h: ck,
            k: None,
            n: 0,
        }
    }

    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha3_256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    pub(crate) fn mix_key(&mut self, ikm: &[u8]) {
        let hk = Hkdf::<Sha3_256>::new(Some(self.ck.expose()), ikm);
        let mut t = Secret::<64>::zeroed();
        // 64 bytes is inside the HKDF bound, thus expand cannot fail.
        let _ = hk.expand(labels::HANDSHAKE_CK, t.expose_mut());
        // Each half goes straight into a buffer that wipes itself.
        let mut ck = Secret::<32>::zeroed();
        let mut k = Secret::<32>::zeroed();
        let (ck_part, k_part) = t.expose().split_at(32);
        ck.expose_mut().copy_from_slice(ck_part);
        k.expose_mut().copy_from_slice(k_part);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    fn nonce(&self) -> Result<Nonce, Error> {
        // n reaches 2^64 - 1 at no honest handshake; the check is CRY-051.
        if self.n == u64::MAX {
            return Err(Error::Handshake);
        }
        let mut b = [0u8; 12];
        b[4..].copy_from_slice(&self.n.to_be_bytes());
        Ok(Nonce::from(b))
    }

    fn cipher(&self) -> Result<ChaCha20Poly1305, Error> {
        let k = self.k.as_ref().ok_or(Error::Handshake)?;
        Ok(ChaCha20Poly1305::new(k.expose().into()))
    }

    /// Encrypts `buf` in place under `k` and `h`, and returns the tag. The
    /// caller appends the tag after `buf` on the wire; both are then mixed
    /// into `h` as one ciphertext.
    pub(crate) fn seal(&mut self, buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        let nonce = self.nonce()?;
        let tag = self
            .cipher()?
            .encrypt_inout_detached(&nonce, &self.h, buf.into())
            .map_err(|_| Error::Handshake)?;
        self.n += 1;
        let tag: [u8; TAG_LEN] = tag.into();
        self.mix_hash_ct(buf, &tag);
        Ok(tag)
    }

    /// Decrypts `buf` in place under `k` and `h`. The ciphertext enters `h`
    /// only after the tag verified (`CRY-052`).
    pub(crate) fn open(&mut self, buf: &mut [u8], tag: &[u8]) -> Result<(), Error> {
        let nonce = self.nonce()?;
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Handshake)?;
        // h must absorb the ciphertext bytes, thus hash them before the
        // in-place decryption overwrites them, but commit only on success.
        let mut hasher = Sha3_256::new();
        hasher.update(self.h);
        hasher.update(&*buf);
        hasher.update(tag);
        let next_h: [u8; 32] = hasher.finalize().into();
        self.cipher()?
            .decrypt_inout_detached(&nonce, &self.h, buf.into(), &Tag::from(tag))
            .map_err(|_| Error::Handshake)?;
        self.n += 1;
        self.h = next_h;
        Ok(())
    }

    fn mix_hash_ct(&mut self, ct: &[u8], tag: &[u8; TAG_LEN]) {
        let mut hasher = Sha3_256::new();
        hasher.update(self.h);
        hasher.update(ct);
        hasher.update(tag);
        self.h = hasher.finalize().into();
    }

    /// One HKDF expansion from `ck` with an empty `ikm`, as the splits use.
    pub(crate) fn derive(&self, info: &[&[u8]]) -> Secret<32> {
        let hk = Hkdf::<Sha3_256>::new(Some(self.ck.expose()), &[]);
        let mut out = Secret::<32>::zeroed();
        let _ = hk.expand_multi_info(info, out.expose_mut());
        out
    }

    pub(crate) fn trace<T: Trace>(&self, t: &mut T, step: &'static str) {
        t.step(step, self.ck.expose(), &self.h, self.n);
    }

    /// The transcript hash, for the device-link confirmation code of Part 7
    /// §7.4 step 3, which reads `h` before the erasure.
    pub(crate) fn h(&self) -> &[u8; 32] {
        &self.h
    }
}

/// Rejects an all-zero Diffie-Hellman output (`CRY-014`).
pub(crate) fn contributory(ss: &x25519_dalek::SharedSecret) -> Result<(), Error> {
    if ss.was_contributory() {
        Ok(())
    } else {
        Err(Error::Handshake)
    }
}

/// Selects the position of `pid` among `ids` in constant time with respect
/// to that position (`CRY-011`, `CRY-056`). Every entry is compared.
pub fn find_prekey<'a>(pid: &[u8; 16], ids: impl Iterator<Item = &'a [u8; 16]>) -> Option<usize> {
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
    let mut found = Choice::from(0u8);
    let mut index = 0u32;
    for (i, id) in ids.enumerate() {
        let hit = id.ct_eq(pid) & !found;
        index = u32::conditional_select(&index, &(i as u32), hit);
        found |= hit;
    }
    if bool::from(found) {
        Some(index as usize)
    } else {
        None
    }
}
