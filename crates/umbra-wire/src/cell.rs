//! The cell of Part 6 §6.3: the L3 unit that the onion layers carry.
//!
//! The total length gives the bucket, and no field states it. A field that
//! gives a size the receiver knows is a malleability surface.

use crate::{
    bucket::{Bucket, CELL_OVERHEAD},
    codec::{Reader, Writer},
    Error,
};

/// The padding marker of `WIR-011`.
pub const PAD_MARKER: u8 = 0x80;

/// The command byte at the start of a decrypted `body`. The list is closed
/// (`WIR-135`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCommand {
    /// The rest of the body is padding.
    Padding = 0x00,
    /// Forward to the next hop.
    Relay = 0x01,
    /// A queue command for this hop.
    Data = 0x02,
    /// A circuit extension.
    Extend = 0x03,
    /// A circuit extension response.
    Extended = 0x04,
    /// A tear-down.
    Destroy = 0x05,
    /// A cover cell reflected to the originator.
    Loop = 0x06,
    /// A measurement echo.
    MeasEcho = 0x07,
    /// A measurement session open.
    MeasOpen = 0x08,
}

impl CellCommand {
    /// The command of a byte, in this namespace only.
    pub const fn from_byte(b: u8) -> Result<Self, Error> {
        Ok(match b {
            0x00 => CellCommand::Padding,
            0x01 => CellCommand::Relay,
            0x02 => CellCommand::Data,
            0x03 => CellCommand::Extend,
            0x04 => CellCommand::Extended,
            0x05 => CellCommand::Destroy,
            0x06 => CellCommand::Loop,
            0x07 => CellCommand::MeasEcho,
            0x08 => CellCommand::MeasOpen,
            _ => return Err(Error::Malformed),
        })
    }
}

/// A cell split into its three fields. The onion layer owns `circ_id` and
/// `tag`; this crate gives the split and the body padding.
pub struct Cell<'a> {
    /// The circuit identifier, rewritten at each hop.
    pub circ_id: &'a [u8; 16],
    /// The per-hop tag.
    pub tag: &'a [u8; 16],
    /// The body, of the length that the bucket gives.
    pub body: &'a [u8],
}

impl<'a> Cell<'a> {
    /// Splits a cell whose length is one of the four buckets.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, Bucket), Error> {
        let bucket = Bucket::from_cell_len(bytes.len()).ok_or(Error::Malformed)?;

        let (circ_id, rest) = bytes.split_at(16);
        let (tag, body) = rest.split_at(16);
        let circ_id = circ_id.try_into().map_err(|_| Error::Malformed)?;
        let tag = tag.try_into().map_err(|_| Error::Malformed)?;
        Ok((Cell { circ_id, tag, body }, bucket))
    }
}

/// Writes a decrypted body: the command byte, `content`, the marker, and
/// zero bytes to the bucket (`WIR-011`).
///
/// `body` must be exactly `bucket.body_len()` bytes.
pub fn pad_body(
    bucket: Bucket,
    command: CellCommand,
    content: &[u8],
    body: &mut [u8],
) -> Result<(), Error> {
    if body.len() != bucket.body_len() {
        return Err(Error::Capacity);
    }
    if command == CellCommand::Padding && !content.is_empty() {
        return Err(Error::Malformed);
    }

    let mut w = Writer::new(body);
    w.u8(command as u8)?;
    w.put(content)?;
    w.u8(PAD_MARKER)?;
    w.zeros(w.remaining())?;
    Ok(())
}

/// Reads a decrypted body back into its command and its content, and
/// rejects malformed padding (`WIR-012`, `WIR-013`).
pub fn unpad_body(body: &[u8]) -> Result<(CellCommand, &[u8]), Error> {
    if Bucket::from_cell_len(body.len().saturating_add(CELL_OVERHEAD)).is_none() {
        return Err(Error::Malformed);
    }

    let mut r = Reader::new(body);
    let command = CellCommand::from_byte(r.u8()?)?;
    let rest = r.rest();

    let marker = rest.iter().rposition(|b| *b != 0).ok_or(Error::Malformed)?;
    if rest.get(marker) != Some(&PAD_MARKER) {
        return Err(Error::Malformed);
    }

    let content = rest.get(..marker).ok_or(Error::Malformed)?;

    // The rest of a `PADDING` body is padding (§6.3), thus one form of it
    // exists and it carries no content.
    if command == CellCommand::Padding && !content.is_empty() {
        return Err(Error::Malformed);
    }
    Ok((command, content))
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
    fn padding_round_trips_at_each_boundary() {
        for bucket in Bucket::ALL {
            let mut body = vec![0u8; bucket.body_len()];
            // The command area is the largest content a body holds.
            let content = vec![0x80u8; bucket.command_area()];
            pad_body(bucket, CellCommand::Data, &content, &mut body).unwrap();
            let (cmd, back) = unpad_body(&body).unwrap();
            assert_eq!(cmd, CellCommand::Data);
            assert_eq!(back, &content[..]);

            assert!(pad_body(
                bucket,
                CellCommand::Data,
                &vec![0u8; bucket.command_area() + 1],
                &mut body
            )
            .is_err());

            pad_body(bucket, CellCommand::Padding, &[], &mut body).unwrap();
            assert_eq!(unpad_body(&body).unwrap(), (CellCommand::Padding, &[][..]));
        }
    }

    #[test]
    fn malformed_padding_and_commands_are_rejected() {
        let mut body = vec![0u8; Bucket::B0.body_len()];
        pad_body(Bucket::B0, CellCommand::Loop, b"x", &mut body).unwrap();
        let mut trailing = body.clone();
        *trailing.last_mut().unwrap() = 1;
        assert!(unpad_body(&trailing).is_err());

        let mut no_marker = body.clone();
        no_marker[2] = 0;
        assert!(unpad_body(&no_marker).is_err());

        let mut bad_cmd = body.clone();
        bad_cmd[0] = 0x09;
        assert!(unpad_body(&bad_cmd).is_err());

        // An application kind at the command offset is rejected (WIR-096).
        bad_cmd[0] = 0x33;
        assert!(unpad_body(&bad_cmd).is_err());
        assert!(unpad_body(&body[..479]).is_err());

        let all_zero = vec![0u8; Bucket::B0.body_len()];
        assert!(unpad_body(&all_zero).is_err());
    }

    #[test]
    fn a_padding_cell_with_content_is_rejected() {
        let mut body = vec![0u8; Bucket::B0.body_len()];
        assert!(pad_body(Bucket::B0, CellCommand::Padding, b"x", &mut body).is_err());

        // The same bytes from a peer: 00, content, the marker, zero bytes.
        pad_body(Bucket::B0, CellCommand::Loop, b"x", &mut body).unwrap();
        body[0] = 0x00;
        assert!(unpad_body(&body).is_err());

        pad_body(Bucket::B0, CellCommand::Padding, &[], &mut body).unwrap();
        assert_eq!(unpad_body(&body).unwrap(), (CellCommand::Padding, &[][..]));
    }

    #[test]
    fn a_cell_splits_by_its_length() {
        let bytes = vec![7u8; 512];
        let (cell, bucket) = Cell::parse(&bytes).unwrap();
        assert_eq!(bucket, Bucket::B0);
        assert_eq!(cell.body.len(), 480);
        assert!(Cell::parse(&bytes[..511]).is_err());
    }
}
