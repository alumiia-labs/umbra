//! The segments of Part 12 §12.2.3 and the padding that carries the
//! boundary of the plaintext. The descriptor holds no true size, thus the
//! last segment holds it.

use alloc::vec::Vec;

use umbra_crypto::aead::TAG_LEN;

use super::{CHUNK_SIZE, SEGMENT_SIZE};
use crate::Error;

/// The marker byte that follows the plaintext (`ATT-059`).
pub const MARKER: u8 = 0x80;

/// The padded length of `plain_len` bytes at `unit`. The marker always
/// goes in, thus a length at a whole unit gains one more unit (`ATT-060`,
/// `ATT-061`).
pub const fn padded_len(plain_len: usize, unit: usize) -> usize {
    plain_len
        .saturating_add(1)
        .div_ceil(unit)
        .saturating_mul(unit)
}

/// The count of units after the padding.
pub const fn unit_count(plain_len: usize, unit: usize) -> usize {
    padded_len(plain_len, unit) / unit
}

/// The segment count of a file of `plain_len` bytes.
pub const fn segment_count(plain_len: usize) -> usize {
    unit_count(plain_len, SEGMENT_SIZE)
}

/// `plaintext || 0x80 || 0x00 × k`, at a whole multiple of `unit`.
pub fn pad(plain: &[u8], unit: usize) -> Vec<u8> {
    let target = padded_len(plain.len(), unit);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(plain);
    out.push(MARKER);
    out.resize(target, 0);
    out
}

/// Reads the last unit from its end: each zero byte is passed over, and
/// the first other byte must be the marker (`ATT-062` to `ATT-064`,
/// `ATT-177`).
pub fn unpad(last: &[u8]) -> Result<&[u8], Error> {
    let end = last.iter().rposition(|&b| b != 0).ok_or(Error::Malformed)?;
    if last.get(end) != Some(&MARKER) {
        return Err(Error::Malformed);
    }

    last.get(..end).ok_or(Error::Malformed)
}

/// Pads a file into whole segments.
pub fn pad_file(plain: &[u8]) -> Vec<u8> {
    pad(plain, SEGMENT_SIZE)
}

/// Removes the padding of a whole padded file, in place.
pub fn unpad_file(padded: &mut Vec<u8>) -> Result<(), Error> {
    if padded.is_empty() || !padded.len().is_multiple_of(SEGMENT_SIZE) {
        return Err(Error::Malformed);
    }

    let start = padded.len().saturating_sub(SEGMENT_SIZE);
    let tail_len = unpad(padded.get(start..).ok_or(Error::Malformed)?)?.len();
    padded.truncate(start.saturating_add(tail_len));
    Ok(())
}

/// Pads the sealed object of a handle-addressed chunk to one chunk
/// (`ATT-147`). The object holds a tag at the minimum, and it leaves room
/// for the marker.
pub fn pad_handle_object(sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < TAG_LEN || sealed.len() >= CHUNK_SIZE {
        return Err(Error::Malformed);
    }

    Ok(pad(sealed, CHUNK_SIZE))
}

/// Reads the sealed object of a handle-addressed chunk (`ATT-148`).
pub fn unpad_handle_object(chunk: &[u8]) -> Result<&[u8], Error> {
    if chunk.len() != CHUNK_SIZE {
        return Err(Error::Malformed);
    }

    let sealed = unpad(chunk)?;
    if sealed.len() < TAG_LEN {
        return Err(Error::Malformed);
    }

    Ok(sealed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_always_goes_in_and_comes_out() {
        assert_eq!(segment_count(0), 1);
        assert_eq!(segment_count(SEGMENT_SIZE - 1), 1);
        assert_eq!(segment_count(SEGMENT_SIZE), 2);
        assert_eq!(segment_count(SEGMENT_SIZE + 1), 2);

        for len in [
            0usize,
            1,
            100,
            SEGMENT_SIZE - 1,
            SEGMENT_SIZE,
            SEGMENT_SIZE + 1,
        ] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
            let mut padded = pad_file(&plain);
            assert_eq!(padded.len(), segment_count(len) * SEGMENT_SIZE);
            unpad_file(&mut padded).unwrap();
            assert_eq!(padded, plain);
        }
    }

    #[test]
    fn a_wrong_marker_and_a_zero_tail_are_rejected() {
        assert!(unpad(&[0, 0, 0]).is_err());
        assert!(unpad(&[1, 0x7F, 0]).is_err());
        assert_eq!(unpad(&[1, MARKER]).unwrap(), &[1]);
        assert_eq!(unpad(&[MARKER, 0, 0]).unwrap(), &[]);
        // A zero byte of the plaintext stays: the read stops at the marker.
        assert_eq!(unpad(&[0, MARKER, 0]).unwrap(), &[0]);
    }

    #[test]
    fn a_handle_object_is_one_chunk_with_a_tag_at_the_minimum() {
        assert!(pad_handle_object(&[1; 15]).is_err());
        assert!(pad_handle_object(&[1; CHUNK_SIZE]).is_err());

        let chunk = pad_handle_object(&[7; 40]).unwrap();
        assert_eq!(chunk.len(), CHUNK_SIZE);
        assert_eq!(unpad_handle_object(&chunk).unwrap(), &[7; 40]);

        let short = pad(&[7; 10], CHUNK_SIZE);
        assert!(unpad_handle_object(&short).is_err());
        assert!(unpad_handle_object(&chunk[..100]).is_err());
    }
}
