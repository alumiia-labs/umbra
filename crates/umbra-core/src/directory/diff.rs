//! The relay-set diff of Part 10 §10.5.3: the changed identifiers and the
//! two-bit store level of each leaf. No signature covers it; the entries
//! it names verify against the signed root.

use alloc::vec::Vec;

use umbra_wire::codec::{Reader, Writer};

use crate::Error;

/// The free store of an attachment relay, in two bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum StoreLevel {
    /// No attachment role, or below `CHUNK_SIZE`.
    None = 0,
    /// Below `CHUNK_STORE_MIN`.
    Low = 1,
    /// Below `CHUNK_STORE_TARGET`.
    Mid = 2,
    /// At or above `CHUNK_STORE_TARGET`.
    High = 3,
}

impl StoreLevel {
    const fn from_bits(b: u8) -> Self {
        match b & 0x03 {
            0 => StoreLevel::None,
            1 => StoreLevel::Low,
            2 => StoreLevel::Mid,
            _ => StoreLevel::High,
        }
    }
}

/// A relay-set diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySetDiff {
    /// The epoch of the root beside it.
    pub epoch: u64,
    /// The epoch this diff applies to.
    pub base_epoch: u64,
    /// The removed relay identifiers.
    pub removed: Vec<[u8; 32]>,
    /// The added or changed relay identifiers.
    pub added: Vec<[u8; 32]>,
    /// The store level of each leaf, in leaf order.
    pub levels: Vec<StoreLevel>,
}

impl RelaySetDiff {
    /// Writes the diff.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.put(&self.epoch.to_be_bytes())?;
        w.put(&self.base_epoch.to_be_bytes())?;

        w.u16(u16::try_from(self.removed.len()).map_err(|_| Error::Malformed)?)?;
        for id in &self.removed {
            w.put(id)?;
        }

        w.u16(u16::try_from(self.added.len()).map_err(|_| Error::Malformed)?)?;
        for id in &self.added {
            w.put(id)?;
        }

        // Four levels go in one byte, the first leaf in the low bits.
        w.u16(u16::try_from(self.levels.len()).map_err(|_| Error::Malformed)?)?;
        for chunk in self.levels.chunks(4) {
            let mut byte = 0u8;
            for (i, level) in chunk.iter().enumerate() {
                byte |= (*level as u8) << (2 * i);
            }
            w.u8(byte)?;
        }

        Ok(w.position())
    }

    /// Reads a diff.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }

        let epoch = u64::from_be_bytes(r.array()?);
        let base_epoch = u64::from_be_bytes(r.array()?);

        let removed_count = usize::from(r.u16()?);
        let mut removed = Vec::with_capacity(removed_count.min(4_096));
        for _ in 0..removed_count {
            removed.push(r.array()?);
        }

        let added_count = usize::from(r.u16()?);
        let mut added = Vec::with_capacity(added_count.min(4_096));
        for _ in 0..added_count {
            added.push(r.array()?);
        }

        let leaf_count = usize::from(r.u16()?);
        let packed = r.take(leaf_count.div_ceil(4))?;
        r.finish()?;

        let mut levels = Vec::with_capacity(leaf_count);
        for i in 0..leaf_count {
            let byte = packed.get(i / 4).copied().ok_or(Error::Malformed)?;
            levels.push(StoreLevel::from_bits(byte >> (2 * (i % 4))));
        }

        // The spare bits of the last byte are zero in the canonical form.
        if let Some(last) = packed.last() {
            let used = leaf_count % 4;
            if used != 0 && last >> (2 * used) != 0 {
                return Err(Error::Malformed);
            }
        }

        Ok(RelaySetDiff {
            epoch,
            base_epoch,
            removed,
            added,
            levels,
        })
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
    use alloc::vec;

    #[test]
    fn a_diff_round_trips_with_packed_levels() {
        let diff = RelaySetDiff {
            epoch: 10,
            base_epoch: 9,
            removed: vec![[1; 32]],
            added: vec![[2; 32], [3; 32]],
            levels: vec![
                StoreLevel::High,
                StoreLevel::None,
                StoreLevel::Mid,
                StoreLevel::Low,
                StoreLevel::High,
            ],
        };
        let mut out = vec![0u8; 200];
        let n = diff.encode(&mut out).unwrap();
        assert_eq!(n, 23 + 96 + 2);
        assert_eq!(RelaySetDiff::parse(&out[..n]).unwrap(), diff);
        out[n - 1] |= 0x04;
        assert!(RelaySetDiff::parse(&out[..n]).is_err());
    }
}
