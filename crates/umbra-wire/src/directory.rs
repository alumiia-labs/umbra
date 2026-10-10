//! The requests of the directory and the issuer (Part 9 §9.10, Part 13
//! §13.9).
//!
//! Each request is one `DirRequest` padded to `DIR_REQUEST_LEN`, and each
//! answer one `DirResponse` padded to the smallest size of
//! `DIR_RESPONSE_SIZES` that holds it. Thus the OHTTP relay in front of the
//! directory cannot tell a lookup from a registration by its size.

use alloc::{vec, vec::Vec};

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The length of each request.
pub const DIR_REQUEST_LEN: usize = 8_192;
/// The sizes of a response.
pub const DIR_RESPONSE_SIZES: [usize; 3] = [4_096, 32_768, 98_304];
/// The version of the two envelopes.
pub const VERSION: u8 = 0x01;
/// The most tokens of one issuance request (`ISSUE_REQUEST_MAX`).
pub const ISSUE_REQUEST_MAX: usize = 16;

const REQUEST_HEAD: usize = 4;
const RESPONSE_HEAD: usize = 6;

/// The kind of a request (Part 9 §9.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A VOPRF evaluation of one blinded element.
    Evaluate = 0x01,
    /// The lookup proof of a search key under the newest head.
    Lookup = 0x02,
    /// The newest head, with a consistency proof from an older size.
    Head = 0x03,
    /// The first version of a label.
    Register = 0x04,
    /// A challenge of §9.9.1 or §9.9.3.
    Challenge = 0x05,
    /// A new version of a label.
    Write = 0x06,
    /// The renewal of a lease.
    Renew = 0x07,
    /// The profile blob of a label (Part 9 §9.3.1).
    Blob = 0x08,
    /// The proof of one version of a label (Part 9 §9.9.2).
    Version = 0x09,
    /// A batch of first-party tokens (Part 13 §13.9).
    Issue = 0x10,
}

impl Kind {
    fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => Kind::Evaluate,
            0x02 => Kind::Lookup,
            0x03 => Kind::Head,
            0x04 => Kind::Register,
            0x05 => Kind::Challenge,
            0x06 => Kind::Write,
            0x07 => Kind::Renew,
            0x08 => Kind::Blob,
            0x09 => Kind::Version,
            0x10 => Kind::Issue,
            _ => return Err(Error::Malformed),
        })
    }
}

/// The status of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Done.
    Done = 0x00,
    /// The request did not parse.
    Malformed = 0x01,
    /// The admission, the token, or the answer did not verify.
    Refused = 0x02,
    /// No such label, or no head yet.
    NotFound = 0x03,
    /// A version, an epoch, or a challenge that does not hold now.
    Stale = 0x04,
    /// The directory cannot serve now, or the label has a version that
    /// waits for the close of the epoch.
    Busy = 0x05,
}

impl Status {
    fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => Status::Done,
            0x01 => Status::Malformed,
            0x02 => Status::Refused,
            0x03 => Status::NotFound,
            0x04 => Status::Stale,
            0x05 => Status::Busy,
            _ => return Err(Error::Malformed),
        })
    }
}

/// Encodes a request, padded to `DIR_REQUEST_LEN`.
pub fn encode_request(kind: Kind, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > DIR_REQUEST_LEN - REQUEST_HEAD {
        return Err(Error::Malformed);
    }
    let mut out = vec![0u8; DIR_REQUEST_LEN];
    let mut w = Writer::new(&mut out);
    w.u8(VERSION)?;
    w.u8(kind as u8)?;
    w.u16(u16::try_from(body.len()).map_err(|_| Error::Malformed)?)?;
    w.put(body)?;
    Ok(out)
}

/// Reads a request: its kind and its body. The padding must be zero bytes.
pub fn parse_request(bytes: &[u8]) -> Result<(Kind, &[u8]), Error> {
    if bytes.len() != DIR_REQUEST_LEN {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(bytes);
    if r.u8()? != VERSION {
        return Err(Error::Malformed);
    }
    let kind = Kind::from_byte(r.u8()?)?;
    let len = usize::from(r.u16()?);
    let body = r.take(len)?;
    r.finish_zero()?;
    Ok((kind, body))
}

/// Encodes a response, padded to the smallest size that holds it.
pub fn encode_response(status: Status, body: &[u8]) -> Result<Vec<u8>, Error> {
    let need = body.len().saturating_add(RESPONSE_HEAD);
    let size = DIR_RESPONSE_SIZES
        .into_iter()
        .find(|size| need <= *size)
        .ok_or(Error::Malformed)?;
    let mut out = vec![0u8; size];
    let mut w = Writer::new(&mut out);
    w.u8(VERSION)?;
    w.u8(status as u8)?;
    w.u32(u32::try_from(body.len()).map_err(|_| Error::Malformed)?)?;
    w.put(body)?;
    Ok(out)
}

/// Reads a response: its status and its body. A response in a size above
/// the smallest that holds its body is not the one encoding of that body
/// (`WIR-001`). The size would be a signal that the directory chose.
pub fn parse_response(bytes: &[u8]) -> Result<(Status, &[u8]), Error> {
    if !DIR_RESPONSE_SIZES.contains(&bytes.len()) {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(bytes);
    if r.u8()? != VERSION {
        return Err(Error::Malformed);
    }
    let status = Status::from_byte(r.u8()?)?;
    let len = usize::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
    let body = r.take(len)?;
    r.finish_zero()?;
    let need = len.saturating_add(RESPONSE_HEAD);
    let smallest = DIR_RESPONSE_SIZES.into_iter().find(|size| need <= *size);
    if smallest != Some(bytes.len()) {
        return Err(Error::Malformed);
    }
    Ok((status, body))
}

/// A body of a length and its bytes, with a `u16` length.
pub fn put_var16(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| Error::Malformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reads a `u16` length and its bytes.
pub fn take_var16<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let len = usize::from(r.u16()?);
    r.take(len)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn a_request_and_a_response_hold_their_size_and_their_body() {
        let request = encode_request(Kind::Lookup, &[7; 64]).unwrap();
        assert_eq!(request.len(), DIR_REQUEST_LEN);
        assert_eq!(
            parse_request(&request).unwrap(),
            (Kind::Lookup, &[7u8; 64][..])
        );
        let mut bad = request.clone();
        bad[DIR_REQUEST_LEN - 1] = 1;
        assert!(parse_request(&bad).is_err());
        assert!(encode_request(Kind::Issue, &vec![0; DIR_REQUEST_LEN]).is_err());

        let small = encode_response(Status::Done, &[1; 100]).unwrap();
        assert_eq!(small.len(), 4_096);
        let large = encode_response(Status::Done, &vec![2; 10_000]).unwrap();
        assert_eq!(large.len(), 32_768);
        assert_eq!(parse_response(&large).unwrap().1.len(), 10_000);
        assert_eq!(
            parse_response(&encode_response(Status::Stale, &[]).unwrap()).unwrap(),
            (Status::Stale, &[][..])
        );
        assert!(encode_response(Status::Done, &vec![0; 98_304]).is_err());
    }

    #[test]
    fn a_response_above_the_smallest_size_that_holds_it_is_rejected() {
        let small = encode_response(Status::Done, &[1; 100]).unwrap();
        for size in [32_768, 98_304] {
            let mut wide = small.clone();
            wide.resize(size, 0);
            assert!(parse_response(&wide).is_err());
        }
        // The largest body of the first size, and the first body of the
        // second size.
        let edge = encode_response(Status::Done, &vec![3; 4_090]).unwrap();
        assert_eq!(edge.len(), 4_096);
        assert_eq!(parse_response(&edge).unwrap().1.len(), 4_090);
        let next = encode_response(Status::Done, &vec![3; 4_091]).unwrap();
        assert_eq!(next.len(), 32_768);
        assert_eq!(parse_response(&next).unwrap().1.len(), 4_091);
    }
}
