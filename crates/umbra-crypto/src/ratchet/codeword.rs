//! The braid codeword of Part 5 §5.5.2: the ML-KEM-768 material of one
//! epoch, coded for loss, and cut into chunks.
//!
//! The material is `header || ek_vector || ct1 || ct2`, 2 304 bytes
//! (`CRY-074`). The header is `rho || SHA3-256(ek_vector || rho)`, thus a
//! receiver that rebuilt the key checks it against the hash (`CRY-091`). The
//! seed of the key never enters the codeword (`CRY-128`).

use sha3::{Digest, Sha3_256};

use super::rs::{Code, MAX_K, MAX_N};
use crate::Error;

/// Size of the material.
pub const MATERIAL_LEN: usize = 2304;
/// Size of the header.
pub const HEADER_LEN: usize = 64;
/// Size of the encoded vector part of an encapsulation key.
pub const EK_VECTOR_LEN: usize = 1152;
/// Size of `c1` of a ciphertext.
pub const CT1_LEN: usize = 960;
/// Size of `c2` of a ciphertext.
pub const CT2_LEN: usize = 128;

const _: () = assert!(HEADER_LEN + EK_VECTOR_LEN + CT1_LEN + CT2_LEN == MATERIAL_LEN);

/// `buf[at..at + len]`, or `Error::Length`.
fn window(buf: &[u8], at: usize, len: usize) -> Result<&[u8], Error> {
    buf.get(at..at.checked_add(len).ok_or(Error::Length)?)
        .ok_or(Error::Length)
}

/// `buf[at..at + len]` for writing, or `Error::Length`.
fn window_mut(buf: &mut [u8], at: usize, len: usize) -> Result<&mut [u8], Error> {
    buf.get_mut(at..at.checked_add(len).ok_or(Error::Length)?)
        .ok_or(Error::Length)
}

/// The `kind` byte of a `PqFrame` (Part 6 §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// The chunk starts inside `header`.
    Header = 1,
    /// The chunk starts inside `ek_vector`.
    Ek = 2,
    /// The chunk starts inside `ct1`.
    Ct1 = 3,
    /// The chunk starts inside `ct2`.
    Ct2 = 4,
    /// A parity chunk.
    Parity = 6,
}

impl Kind {
    /// Decodes a `kind` byte. `0x00`, `0x05`, and `0x07` or above are
    /// rejected (`WIR-349`).
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            1 => Self::Header,
            2 => Self::Ek,
            3 => Self::Ct1,
            4 => Self::Ct2,
            6 => Self::Parity,
            _ => return Err(Error::Length),
        })
    }
}

/// A chunk width of Part 5 §5.5.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    /// 32-byte chunks: 72 data, 9 parity.
    W32,
    /// 64-byte chunks: 36 data, 5 parity. The default.
    W64,
    /// 128-byte chunks: 18 data, 3 parity.
    W128,
}

impl Width {
    /// The byte of the width in a stored object.
    pub(crate) const fn to_byte(self) -> u8 {
        match self {
            Self::W32 => 1,
            Self::W64 => 2,
            Self::W128 => 3,
        }
    }

    /// The width of a stored byte.
    pub(crate) fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            1 => Ok(Self::W32),
            2 => Ok(Self::W64),
            3 => Ok(Self::W128),
            _ => Err(Error::Length),
        }
    }

    /// The width in bytes.
    pub const fn bytes(self) -> usize {
        match self {
            Self::W32 => 32,
            Self::W64 => 64,
            Self::W128 => 128,
        }
    }

    /// `k = 2304 / w` and `r = ceil(k / 8)` (`CRY-077`, `CRY-078`).
    pub const fn code(self) -> Code {
        let k = MATERIAL_LEN / self.bytes();
        Code {
            k,
            r: k.div_ceil(8),
        }
    }

    /// `pq_frame_len`: 7 bytes of frame header and the chunk.
    pub const fn frame_len(self) -> u8 {
        (7 + self.bytes()) as u8
    }

    /// The width that a `pq_frame_len` names.
    pub fn from_frame_len(len: u8) -> Result<Self, Error> {
        Ok(match len {
            39 => Self::W32,
            71 => Self::W64,
            135 => Self::W128,
            _ => return Err(Error::Length),
        })
    }

    /// The `kind` of the chunk at `index` (`CRY-082`, `CRY-129`).
    pub fn kind_at(self, index: usize) -> Result<Kind, Error> {
        let code = self.code();
        if index >= code.n() {
            return Err(Error::Length);
        }
        if index >= code.k {
            return Ok(Kind::Parity);
        }

        let start = index * self.bytes();
        Ok(if start < HEADER_LEN {
            Kind::Header
        } else if start < HEADER_LEN + EK_VECTOR_LEN {
            Kind::Ek
        } else if start < HEADER_LEN + EK_VECTOR_LEN + CT1_LEN {
            Kind::Ct1
        } else {
            Kind::Ct2
        })
    }
}

const _: () = assert!(Width::W32.code().k == 72 && Width::W32.code().r == 9);
const _: () = assert!(Width::W64.code().k == 36 && Width::W64.code().r == 5);
const _: () = assert!(Width::W128.code().k == 18 && Width::W128.code().r == 3);

/// The material of one epoch, before coding.
#[derive(Clone)]
pub struct Material(pub [u8; MATERIAL_LEN]);

impl Material {
    /// Builds the material from an encapsulation key and a ciphertext. The
    /// FIPS 203 encoding of the key is `ek_vector || rho`.
    pub fn new(ek: &[u8; 1184], ct: &[u8; 1088]) -> Self {
        let mut m = [0u8; MATERIAL_LEN];
        let (ek_vector, rho) = ek.split_at(EK_VECTOR_LEN);

        let mut hash = Sha3_256::new();
        hash.update(ek_vector);
        hash.update(rho);
        let h: [u8; 32] = hash.finalize().into();

        let (header, rest) = m.split_at_mut(HEADER_LEN);
        let (h_rho, h_hash) = header.split_at_mut(32);
        h_rho.copy_from_slice(rho);
        h_hash.copy_from_slice(&h);

        let (ekv, rest) = rest.split_at_mut(EK_VECTOR_LEN);
        ekv.copy_from_slice(ek_vector);
        rest.copy_from_slice(ct);
        Self(m)
    }

    /// The encapsulation key, in FIPS 203 encoding, after the header check
    /// of `CRY-091`. A rebuilt material whose hash differs is rejected
    /// (`CRY-092`).
    pub fn encapsulation_key(&self) -> Result<[u8; 1184], Error> {
        let (header, rest) = self.0.split_at(HEADER_LEN);
        let (rho, h_hash) = header.split_at(32);
        let (ek_vector, _) = rest.split_at(EK_VECTOR_LEN);

        let mut hash = Sha3_256::new();
        hash.update(ek_vector);
        hash.update(rho);
        let h: [u8; 32] = hash.finalize().into();
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&h[..], h_hash)) {
            return Err(Error::Kem);
        }

        let mut ek = [0u8; 1184];
        let (v, r) = ek.split_at_mut(EK_VECTOR_LEN);
        v.copy_from_slice(ek_vector);
        r.copy_from_slice(rho);
        Ok(ek)
    }

    /// The ciphertext `ct1 || ct2`.
    pub fn ciphertext(&self) -> [u8; 1088] {
        let mut ct = [0u8; 1088];
        let (_, tail) = self.0.split_at(HEADER_LEN + EK_VECTOR_LEN);
        ct.copy_from_slice(tail);
        ct
    }

    /// Writes the `n` chunks of the codeword at `width` into `out`, which
    /// needs `n × w` bytes: the data chunks first, then the parity.
    pub fn encode(&self, width: Width, out: &mut [u8]) -> Result<(), Error> {
        let code = width.code();
        let w = width.bytes();
        let out = out.get_mut(..code.n() * w).ok_or(Error::Length)?;
        let (data, parity) = out.split_at_mut(code.k * w);
        data.copy_from_slice(&self.0);
        code.encode(w, &self.0, parity)
    }

    /// One chunk of the codeword at `width`.
    pub fn chunk(&self, width: Width, index: usize, out: &mut [u8]) -> Result<(), Error> {
        let code = width.code();
        let w = width.bytes();
        let out = out.get_mut(..w).ok_or(Error::Length)?;

        if index < code.k {
            out.copy_from_slice(window(&self.0, index * w, w)?);
            return Ok(());
        }

        // A parity chunk needs the whole code; encode into a stack buffer.
        let mut all = [0u8; MAX_N * 128];
        self.encode(width, &mut all)?;
        out.copy_from_slice(window(&all, index * w, w)?);
        Ok(())
    }
}

fn window_positions(p: &[usize], len: usize) -> Result<&[usize], Error> {
    p.get(..len).ok_or(Error::Length)
}

/// A receiver's store of chunks for one epoch. It rebuilds the material as
/// soon as any `k` positions are held (`CRY-079`, `CRY-080`).
pub struct Collector {
    width: Width,
    held: [bool; MAX_N],
    count: usize,
    chunks: [u8; MAX_N * 128],
}

impl Collector {
    /// An empty store for `width`.
    pub fn new(width: Width) -> Self {
        Self {
            width,
            held: [false; MAX_N],
            count: 0,
            chunks: [0; MAX_N * 128],
        }
    }

    /// The chunk width.
    pub fn width(&self) -> Width {
        self.width
    }

    /// Stores the chunk at `index`. A later chunk of a held position is
    /// discarded (`CRY-097`). Returns whether `k` positions are now held.
    pub fn put(&mut self, index: usize, chunk: &[u8]) -> Result<bool, Error> {
        let w = self.width.bytes();
        let code = self.width.code();
        if index >= code.n() || chunk.len() != w {
            return Err(Error::Length);
        }

        if let Some(slot) = self.held.get_mut(index) {
            if !*slot {
                *slot = true;
                self.count += 1;
                if let Some(dst) = self.chunks.get_mut(index * w..(index + 1) * w) {
                    dst.copy_from_slice(chunk);
                }
            }
        }
        Ok(self.count >= code.k)
    }

    /// Writes the held chunks for the at-rest store.
    pub(crate) fn export(&self, writer: &mut crate::stored::Writer) -> Result<(), Error> {
        let w = self.width.bytes();
        writer.u8(self.width.to_byte());
        writer.u16(u16::try_from(self.count).map_err(|_| Error::Length)?);
        for (index, _) in self.held.iter().enumerate().filter(|(_, held)| **held) {
            writer.u8(u8::try_from(index).map_err(|_| Error::Length)?);
            writer.bytes(window(&self.chunks, index * w, w)?);
        }
        Ok(())
    }

    /// Reads the chunks that [`Collector::export`] wrote.
    pub(crate) fn restore(reader: &mut crate::stored::Reader<'_>) -> Result<Self, Error> {
        let mut collector = Self::new(Width::from_byte(reader.u8()?)?);
        let w = collector.width.bytes();
        for _ in 0..reader.u16()? {
            let index = usize::from(reader.u8()?);
            collector.put(index, reader.take(w)?)?;
        }
        Ok(collector)
    }

    /// Whether `k` positions are held.
    pub fn complete(&self) -> bool {
        self.count >= self.width.code().k
    }

    /// Rebuilds the material from the held chunks.
    pub fn rebuild(&self) -> Result<Material, Error> {
        let code = self.width.code();
        let w = self.width.bytes();
        if !self.complete() {
            return Err(Error::Length);
        }

        let mut positions = [0usize; MAX_K];
        let mut received = [0u8; MAX_K * 128];
        let mut taken = 0;

        for (index, &h) in self.held.iter().enumerate().take(code.n()) {
            if !h || taken == code.k {
                continue;
            }
            if let Some(slot) = positions.get_mut(taken) {
                *slot = index;
            }
            window_mut(&mut received, taken * w, w)?.copy_from_slice(window(
                &self.chunks,
                index * w,
                w,
            )?);
            taken += 1;
        }

        let mut out = [0u8; MATERIAL_LEN];
        code.decode(
            w,
            window_positions(&positions, code.k)?,
            window(&received, 0, code.k * w)?,
            &mut out,
        )?;
        Ok(Material(out))
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

    fn material() -> Material {
        let mut ek = [0u8; 1184];
        let mut ct = [0u8; 1088];
        for (i, b) in ek.iter_mut().enumerate() {
            *b = (i * 3) as u8;
        }
        for (i, b) in ct.iter_mut().enumerate() {
            *b = (i * 5 + 1) as u8;
        }
        Material::new(&ek, &ct)
    }

    #[test]
    fn parts_start_where_the_specification_says() {
        // Part 5 §5.5.2: at 64 bytes the parts start at 0, 1, 19, 34 and the
        // parity at 36; at 32 bytes at 0, 2, 38, 68 and parity at 72; at 128
        // bytes the header shares position 0 with ek, then 9, 17, parity 18.
        let w64 = Width::W64;
        assert_eq!(w64.kind_at(0).unwrap(), Kind::Header);
        assert_eq!(w64.kind_at(1).unwrap(), Kind::Ek);
        assert_eq!(w64.kind_at(18).unwrap(), Kind::Ek);
        assert_eq!(w64.kind_at(19).unwrap(), Kind::Ct1);
        assert_eq!(w64.kind_at(34).unwrap(), Kind::Ct2);
        assert_eq!(w64.kind_at(36).unwrap(), Kind::Parity);
        assert_eq!(w64.kind_at(40).unwrap(), Kind::Parity);
        assert!(w64.kind_at(41).is_err());

        let w32 = Width::W32;
        assert_eq!(w32.kind_at(2).unwrap(), Kind::Ek);
        assert_eq!(w32.kind_at(38).unwrap(), Kind::Ct1);
        assert_eq!(w32.kind_at(68).unwrap(), Kind::Ct2);
        assert_eq!(w32.kind_at(72).unwrap(), Kind::Parity);

        let w128 = Width::W128;
        assert_eq!(w128.kind_at(0).unwrap(), Kind::Header);
        // `ct1` begins at byte 1 216, inside chunk 9, whose first byte is `ek`.
        assert_eq!(w128.kind_at(9).unwrap(), Kind::Ek);
        assert_eq!(w128.kind_at(10).unwrap(), Kind::Ct1);
        assert_eq!(w128.kind_at(17).unwrap(), Kind::Ct2);
        assert_eq!(w128.kind_at(18).unwrap(), Kind::Parity);

        assert_eq!(Width::from_frame_len(71).unwrap(), Width::W64);
        assert!(Width::from_frame_len(68).is_err());
        assert!(Kind::from_byte(5).is_err());
        assert!(Kind::from_byte(0).is_err());
    }

    #[test]
    fn a_loss_of_r_chunks_rebuilds_at_every_width() {
        let m = material();
        for width in [Width::W32, Width::W64, Width::W128] {
            let code = width.code();
            let w = width.bytes();
            let mut all = [0u8; MAX_N * 128];
            m.encode(width, &mut all).unwrap();

            let mut col = Collector::new(width);
            // Drop r chunks spread over data and parity.
            let dropped: [usize; 9] = [0, 1, 7, code.k - 1, code.k, code.k + 1, 3, 5, code.n() - 1];
            let mut done = false;
            for index in 0..code.n() {
                if dropped[..code.r].contains(&index) {
                    continue;
                }
                done = col.put(index, &all[index * w..(index + 1) * w]).unwrap();
            }

            assert!(done);
            let rebuilt = col.rebuild().unwrap();
            assert_eq!(rebuilt.0, m.0, "{width:?}");
            assert_eq!(rebuilt.encapsulation_key().unwrap()[..8], m.0[64..72]);

            // One chunk from `chunk()` equals the same chunk of `encode()`.
            let mut one = [0u8; 128];
            m.chunk(width, code.k, &mut one).unwrap();
            assert_eq!(one[..w], all[code.k * w..(code.k + 1) * w]);
        }
    }

    #[test]
    fn a_changed_header_hash_is_rejected() {
        let mut m = material();
        m.0[40] ^= 1;
        assert_eq!(m.encapsulation_key().err(), Some(Error::Kem));
    }
}
