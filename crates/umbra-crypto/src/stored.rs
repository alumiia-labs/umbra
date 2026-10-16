//! The byte form of state that a client keeps between two runs. The form
//! is local to one device: no peer reads it, and the at-rest store of
//! Part 14 §14.6.4 seals it. A version byte leads each object, thus a later
//! revision reads the rows of an earlier one or rejects them.
//!
//! The writer overwrites its buffer at the drop, because the state holds
//! chain keys and ratchet keys. It also overwrites each buffer that it
//! leaves when it grows, thus no reallocation frees a copy of a key.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::Error;

/// Builds one stored object.
#[derive(Default)]
pub struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    /// An empty object.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty object with room for `capacity` bytes. A writer of secrets
    /// that sizes its object grows in no reallocation, which would free a
    /// copy of them that no one wipes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Makes room for `additional` bytes. The bytes move to a new buffer,
    /// and the old one wipes itself at its drop, as `Vec::reserve` does not.
    fn reserve(&mut self, additional: usize) {
        let needed = self.0.len().saturating_add(additional);
        if needed <= self.0.capacity() {
            return;
        }
        let capacity = needed.max(self.0.capacity().saturating_mul(2)).max(64);
        let mut next = Zeroizing::new(Vec::with_capacity(capacity));
        next.extend_from_slice(&self.0);
        self.0 = next;
    }

    /// One byte.
    pub fn u8(&mut self, value: u8) {
        self.reserve(1);
        self.0.push(value);
    }

    /// A flag, as one byte.
    pub fn flag(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    /// 16 bits, big endian.
    pub fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    /// 32 bits, big endian.
    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    /// 64 bits, big endian.
    pub fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    /// Bytes of a length that the reader knows.
    pub fn bytes(&mut self, value: &[u8]) {
        self.reserve(value.len());
        self.0.extend_from_slice(value);
    }

    /// Bytes behind a 32-bit length.
    pub fn var(&mut self, value: &[u8]) -> Result<(), Error> {
        self.u32(u32::try_from(value.len()).map_err(|_| Error::Length)?);
        self.bytes(value);
        Ok(())
    }

    /// A value that can be absent: a flag, and then the value.
    pub fn option<T>(&mut self, value: Option<&T>, mut write: impl FnMut(&mut Self, &T)) {
        self.flag(value.is_some());
        if let Some(value) = value {
            write(self, value);
        }
    }

    /// The object.
    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// Reads one stored object.
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// A reader at the start of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader(bytes)
    }

    /// The next `len` bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.0.split_at_checked(len).ok_or(Error::Length)?;
        self.0 = tail;
        Ok(head)
    }

    /// The next `N` bytes.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Length)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// A flag. A byte above 1 is a fault.
    pub fn flag(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Length),
        }
    }

    /// 16 bits.
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// 32 bits.
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// 64 bits.
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Bytes behind a 32-bit length.
    pub fn var(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::Length)?;
        self.take(len)
    }

    /// A value that can be absent.
    pub fn option<T>(
        &mut self,
        mut read: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        if self.flag()? {
            Ok(Some(read(self)?))
        } else {
            Ok(None)
        }
    }

    /// The object ends here. Bytes after the end are a fault.
    pub fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Length)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_gives_back_what_a_writer_took() {
        let mut writer = Writer::new();
        writer.u8(7);
        writer.u16(0x0102);
        writer.u32(0x0A0B_0C0D);
        writer.u64(u64::MAX - 1);
        writer.var(b"abc").unwrap();
        writer.option(Some(&[9u8; 4]), |w, v| w.bytes(v));
        writer.option(None::<&[u8; 4]>, |w, v| w.bytes(v));
        let bytes = writer.finish();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 7);
        assert_eq!(reader.u16().unwrap(), 0x0102);
        assert_eq!(reader.u32().unwrap(), 0x0A0B_0C0D);
        assert_eq!(reader.u64().unwrap(), u64::MAX - 1);
        assert_eq!(reader.var().unwrap(), b"abc");
        assert_eq!(reader.option(|r| r.array::<4>()).unwrap(), Some([9; 4]));
        assert_eq!(reader.option(|r| r.array::<4>()).unwrap(), None);
        reader.end().unwrap();
    }

    #[test]
    fn a_writer_that_grows_keeps_each_byte() {
        let mut writer = Writer::new();
        for i in 0..1_000u32 {
            writer.u32(i);
        }
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        for i in 0..1_000u32 {
            assert_eq!(reader.u32().unwrap(), i);
        }
        reader.end().unwrap();
    }

    #[test]
    fn a_short_object_and_a_long_object_are_faults() {
        let mut reader = Reader::new(&[0, 0, 0, 9, 1]);
        assert_eq!(reader.var(), Err(Error::Length));
        let reader = Reader::new(&[1]);
        assert_eq!(reader.end(), Err(Error::Length));
        assert_eq!(Reader::new(&[2]).flag(), Err(Error::Length));
    }
}
