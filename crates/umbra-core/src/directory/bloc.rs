//! The jurisdiction bloc list of Part 10 §10.6.3 and the v1 annex of
//! §10.12. A code that no bloc names is a bloc of its own (`REL-093`).

use alloc::vec::Vec;

use umbra_crypto::hash::sha3_256;
use umbra_wire::codec::{Reader, Writer};

use crate::Error;

/// A bloc list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocList {
    /// The blocs, each a set of codes in ascending byte order.
    pub blocs: Vec<Vec<[u8; 2]>>,
}

/// The identity of a bloc for the disjointness test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocId {
    /// A row of the list, by index.
    Listed(usize),
    /// A code that no row names.
    Own([u8; 2]),
}

impl BlocList {
    /// The list of §10.12.
    pub fn v1() -> Self {
        let eu: &[&[u8; 2]] = &[
            b"AT", b"BE", b"BG", b"CY", b"CZ", b"DE", b"EE", b"ES", b"FI", b"FR", b"GR", b"HR",
            b"HU", b"IE", b"IT", b"LT", b"LU", b"LV", b"MT", b"NL", b"PL", b"PT", b"RO", b"SE",
            b"SI", b"SK",
        ];
        let five: &[&[u8; 2]] = &[b"AU", b"CA", b"GB", b"NZ", b"US"];
        let mut list = BlocList {
            blocs: alloc::vec![
                eu.iter().map(|c| **c).collect(),
                five.iter().map(|c| **c).collect(),
            ],
        };
        list.canonicalize();
        list
    }

    /// Orders the codes of each bloc and the blocs by their first code.
    pub fn canonicalize(&mut self) {
        for bloc in &mut self.blocs {
            bloc.sort_unstable();
            bloc.dedup();
        }
        self.blocs.sort_unstable();
    }

    fn is_canonical(&self) -> bool {
        self.blocs
            .iter()
            .all(|b| !b.is_empty() && b.windows(2).all(|w| matches!(w, [a, c] if a < c)))
            && self.blocs.windows(2).all(|w| matches!(w, [a, c] if a < c))
    }

    /// Writes the canonical encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.is_canonical() {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(u8::try_from(self.blocs.len()).map_err(|_| Error::Malformed)?)?;
        for bloc in &self.blocs {
            w.u8(u8::try_from(bloc.len()).map_err(|_| Error::Malformed)?)?;
            for code in bloc {
                w.put(code)?;
            }
        }
        Ok(w.position())
    }

    /// The encoded length.
    pub fn len(&self) -> usize {
        2usize
            .saturating_add(self.blocs.len())
            .saturating_add(self.blocs.iter().map(|b| b.len().saturating_mul(2)).sum())
    }

    /// Whether the list holds no bloc.
    pub fn is_empty(&self) -> bool {
        self.blocs.is_empty()
    }

    /// `bloc_hash`, over the canonical encoding.
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        let mut buf = alloc::vec![0u8; self.len()];
        let n = self.encode(&mut buf)?;
        Ok(sha3_256(&[buf.get(..n).ok_or(Error::Malformed)?]))
    }

    /// Reads a list and rejects a non-canonical one.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let count = usize::from(r.u8()?);
        let mut blocs = Vec::with_capacity(count);
        for _ in 0..count {
            let codes = usize::from(r.u8()?);
            let mut bloc = Vec::with_capacity(codes);
            for _ in 0..codes {
                bloc.push(r.array()?);
            }
            blocs.push(bloc);
        }
        r.finish()?;
        let out = BlocList { blocs };
        if !out.is_canonical() {
            return Err(Error::Malformed);
        }
        Ok(out)
    }

    /// The bloc of a jurisdiction code (`REL-092`, `REL-093`).
    pub fn bloc_of(&self, code: &[u8; 2]) -> BlocId {
        self.blocs
            .iter()
            .position(|b| b.contains(code))
            .map_or(BlocId::Own(*code), BlocId::Listed)
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
    fn the_v1_list_is_66_bytes_and_denmark_is_its_own_bloc() {
        let list = BlocList::v1();
        assert_eq!(list.len(), 66);
        let mut out = [0u8; 66];
        assert_eq!(list.encode(&mut out).unwrap(), 66);
        assert_eq!(BlocList::parse(&out).unwrap(), list);
        assert_eq!(list.bloc_of(b"DE"), list.bloc_of(b"FR"));
        assert_ne!(list.bloc_of(b"DE"), list.bloc_of(b"US"));
        assert_eq!(list.bloc_of(b"DK"), BlocId::Own(*b"DK"));
        assert_ne!(list.bloc_of(b"DK"), list.bloc_of(b"NO"));
        let mut swapped = out;
        swapped[3..5].copy_from_slice(b"BE");
        swapped[5..7].copy_from_slice(b"AT");
        assert!(BlocList::parse(&swapped).is_err());
    }
}
