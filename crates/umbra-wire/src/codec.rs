//! Bounds-checked cursors over a byte slice.
//!
//! Every parser of this crate is a sequence of these calls, thus a parser
//! has no index expression and no loop over a length that a peer controls
//! beyond the bound that the slice gives.

use crate::Error;

/// A reader that hands out slices in order and refuses to run past the end.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Starts at the first byte of `buf`.
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// The count of bytes read so far.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Malformed)?;
        let out = self.buf.get(self.pos..end).ok_or(Error::Malformed)?;
        self.pos = end;
        Ok(out)
    }

    /// The next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// The next byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    /// The next big-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// The next big-endian 24-bit value.
    pub fn u24(&mut self) -> Result<u32, Error> {
        let b = self.array::<3>()?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// The next big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Everything that remains.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        out
    }

    /// Fails when bytes remain (`WIR-002`).
    pub fn finish(&self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// Fails unless every remaining byte is zero, and consumes them
    /// (`WIR-407`).
    pub fn finish_zero(&mut self) -> Result<(), Error> {
        if self.rest().iter().all(|b| *b == 0) {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}

/// A writer that fills a slice in order and refuses to run past the end.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Starts at the first byte of `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The count of bytes written so far.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// The bytes not yet written.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Appends `bytes`.
    pub fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(Error::Capacity)?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    /// Appends one byte.
    pub fn u8(&mut self, v: u8) -> Result<(), Error> {
        self.put(&[v])
    }

    /// Appends a big-endian `u16`.
    pub fn u16(&mut self, v: u16) -> Result<(), Error> {
        self.put(&v.to_be_bytes())
    }

    /// Appends a big-endian 24-bit value. Fails above 2^24 − 1.
    pub fn u24(&mut self, v: u32) -> Result<(), Error> {
        if v > 0x00FF_FFFF {
            return Err(Error::Malformed);
        }

        let b = v.to_be_bytes();
        self.put(&[b[1], b[2], b[3]])
    }

    /// Appends a big-endian `u32`.
    pub fn u32(&mut self, v: u32) -> Result<(), Error> {
        self.put(&v.to_be_bytes())
    }

    /// Appends `n` zero bytes.
    pub fn zeros(&mut self, n: usize) -> Result<(), Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Capacity)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(Error::Capacity)?;
        dst.fill(0);
        self.pos = end;
        Ok(())
    }

    /// The bytes not yet written, for a nested encoder. The caller adds the
    /// count that encoder wrote to [`Writer::position`].
    pub fn tail(&mut self) -> &mut [u8] {
        self.buf.get_mut(self.pos..).unwrap_or(&mut [])
    }

    /// The slice written so far, for a caller that seals it in place.
    pub fn written(&mut self) -> &mut [u8] {
        self.buf.get_mut(..self.pos).unwrap_or(&mut [])
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
    fn the_reader_stops_at_the_end() {
        let mut r = Reader::new(&[1, 0, 2, 0, 0, 3, 0, 0, 0, 4]);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 2);
        assert_eq!(r.u24().unwrap(), 3);
        assert!(r.finish().is_err());
        assert_eq!(r.u32().unwrap(), 4);
        assert!(r.u8().is_err());

        r.finish().unwrap();
    }

    #[test]
    fn the_writer_stops_at_the_end() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        w.u24(0x0001_0203).unwrap();
        assert!(w.u24(0x0100_0000).is_err());
        assert!(w.u16(1).is_err());
        w.u8(4).unwrap();
        assert_eq!(w.remaining(), 0);
        assert_eq!(buf, [1, 2, 3, 4]);
    }
}
