//! The WebSocket binary frame of Part 6 §6.2.1: one capsule in one frame
//! with the FIN bit set, a 4-byte mask from the client and none from the
//! relay (`WIR-222` to `WIR-224`).
//!
//! Every capsule is between 126 and 65 535 bytes, thus the extended
//! 16-bit length is the one form in use, and the header is 4 bytes.

use crate::Error;

/// The header of a frame of 126 to 65 535 bytes, before the mask.
pub const HEADER_LEN: usize = 4;
/// The mask key length.
pub const MASK_LEN: usize = 4;
/// The opcode of a binary frame with FIN set.
const FIN_BINARY: u8 = 0x82;

/// The header of a frame whose payload is below 126 bytes, which is a
/// session capsule of Part 6 §6.2.3.
pub const SHORT_HEADER_LEN: usize = 2;

const fn header_len(len: usize) -> usize {
    if len < 126 {
        SHORT_HEADER_LEN
    } else {
        HEADER_LEN
    }
}

/// The frame length for a payload of `len` bytes, masked or not.
pub const fn frame_len(len: usize, masked: bool) -> usize {
    header_len(len) + if masked { MASK_LEN } else { 0 } + len
}

fn apply_mask(payload: &mut [u8], mask: &[u8; MASK_LEN]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask.get(i % MASK_LEN).copied().unwrap_or(0);
    }
}

/// Writes one frame. A client passes its mask; a relay passes `None`.
pub fn encode(
    payload: &[u8],
    mask: Option<&[u8; MASK_LEN]>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if payload.is_empty() || payload.len() > 65_535 {
        return Err(Error::Malformed);
    }

    let total = frame_len(payload.len(), mask.is_some());
    let out = out.get_mut(..total).ok_or(Error::Capacity)?;
    let (head, rest) = out.split_at_mut(header_len(payload.len()));
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let len = u16::try_from(payload.len()).map_err(|_| Error::Malformed)?;

    match u8::try_from(len).ok().filter(|short| *short < 126) {
        // A session capsule takes the 7-bit length form of RFC 6455 §5.2.
        Some(short) => head.copy_from_slice(&[FIN_BINARY, short | mask_bit]),
        None => {
            let len = len.to_be_bytes();
            head.copy_from_slice(&[FIN_BINARY, 126 | mask_bit, len[0], len[1]]);
        }
    }

    match mask {
        Some(key) => {
            let (key_out, body) = rest.split_at_mut(MASK_LEN);
            key_out.copy_from_slice(key);
            body.copy_from_slice(payload);
            apply_mask(body, key);
        }
        None => rest.copy_from_slice(payload),
    }

    Ok(total)
}

/// Reads one frame from the front of `bytes` into `out`, and returns the
/// payload length and the bytes taken. `from_client` says whether a mask is
/// required (RFC 6455 §5.3). Returns `Ok(None)` when the frame is not
/// complete yet.
pub fn decode(
    bytes: &[u8],
    from_client: bool,
    out: &mut [u8],
) -> Result<Option<(usize, usize)>, Error> {
    let Some(head) = bytes.get(..SHORT_HEADER_LEN) else {
        return Ok(None);
    };

    let (b0, b1) = (
        head.first().copied().unwrap_or(0),
        head.get(1).copied().unwrap_or(0),
    );

    // FIN set, no reserved bit, binary opcode, and no 64-bit length form.
    if b0 != FIN_BINARY || b1 & 0x7F == 127 {
        return Err(Error::Malformed);
    }

    let masked = b1 & 0x80 != 0;
    if masked != from_client {
        return Err(Error::Malformed);
    }

    let len = if b1 & 0x7F == 126 {
        let Some(wide) = bytes.get(2..HEADER_LEN) else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes([
            wide.first().copied().unwrap_or(0),
            wide.get(1).copied().unwrap_or(0),
        ]));
        // One canonical form: the 16-bit form holds 126 bytes or more.
        if len < 126 {
            return Err(Error::Malformed);
        }
        len
    } else {
        usize::from(b1 & 0x7F)
    };

    if len == 0 {
        return Err(Error::Malformed);
    }

    let total = frame_len(len, masked);
    let Some(frame) = bytes.get(..total) else {
        return Ok(None);
    };

    let body_at = header_len(len) + if masked { MASK_LEN } else { 0 };
    let body = frame.get(body_at..).ok_or(Error::Malformed)?;
    let dst = out.get_mut(..len).ok_or(Error::Capacity)?;
    dst.copy_from_slice(body);

    if masked {
        let mut key = [0u8; MASK_LEN];
        key.copy_from_slice(
            frame
                .get(header_len(len)..body_at)
                .ok_or(Error::Malformed)?,
        );
        apply_mask(dst, &key);
    }
    Ok(Some((len, total)))
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
    fn a_frame_round_trips_in_both_directions_at_the_bucket_sizes() {
        for len in [530usize, 2_066, 8_210, 32_786] {
            let payload: alloc::vec::Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let mut frame = vec![0u8; frame_len(len, true)];
            let n = encode(&payload, Some(&[1, 2, 3, 4]), &mut frame).unwrap();
            assert_eq!(n, len + 8);
            let mut out = vec![0u8; len];
            assert_eq!(decode(&frame, true, &mut out).unwrap(), Some((len, n)));
            assert_eq!(out, payload);
            assert!(decode(&frame, false, &mut out).is_err());
            assert_eq!(decode(&frame[..n - 1], true, &mut out).unwrap(), None);

            let mut plain = vec![0u8; frame_len(len, false)];
            let n = encode(&payload, None, &mut plain).unwrap();
            assert_eq!(n, len + 4);
            assert_eq!(decode(&plain, false, &mut out).unwrap(), Some((len, n)));
            assert_eq!(out, payload);
        }

        // A session capsule is below 126 bytes and takes the short header.
        for len in [15usize, 35, 47] {
            let payload = vec![0xA5u8; len];
            let mut frame = vec![0u8; frame_len(len, true)];
            let n = encode(&payload, Some(&[1, 2, 3, 4]), &mut frame).unwrap();
            assert_eq!(n, len + 6);
            let mut out = vec![0u8; len];
            assert_eq!(decode(&frame, true, &mut out).unwrap(), Some((len, n)));
            assert_eq!(out, payload);
            assert_eq!(decode(&frame[..1], true, &mut out).unwrap(), None);
        }

        let mut frame = vec![0u8; 200];
        assert!(encode(&[], None, &mut frame).is_err());

        // The 16-bit form with a short length is not canonical.
        let mut wide = vec![0x82, 126, 0, 47];
        wide.extend_from_slice(&[0u8; 47]);
        assert!(decode(&wide, false, &mut [0u8; 64]).is_err());

        let mut bad = vec![0u8; frame_len(530, false)];
        encode(&[0u8; 530], None, &mut bad).unwrap();
        bad[0] = 0x02;
        let mut out = vec![0u8; 530];
        assert!(decode(&bad, false, &mut out).is_err());
    }
}
