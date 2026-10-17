//! The requests of the Notification Delivery Relay (Part 8 §8.2.7).
//!
//! The NDR takes one request shape for each of its three kinds, padded to
//! `NDR_REQUEST_LEN`, thus the OHTTP relay in front of it cannot tell a
//! registration from a push by its size (`NTF-122`).

use umbra_crypto::secret::Secret;

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The length of each request.
pub const NDR_REQUEST_LEN: usize = 640;
/// The length of each response.
pub const NDR_RESPONSE_LEN: usize = 16;
/// The longest push token.
pub const PUSH_TOKEN_MAX: usize = 512;
/// The longest sealed push token, with its tag.
pub const CT_TOKEN_MAX: usize = PUSH_TOKEN_MAX + 16;
/// A notification handle.
pub const HANDLE_LEN: usize = 16;
/// The notification blob of §8.2.2.
pub const BLOB_LEN: usize = 69;

const KIND_REGISTER: u8 = 0x01;
const KIND_UNREGISTER: u8 = 0x02;
const KIND_PUSH: u8 = 0x03;

/// The handle of a binding that serves a watch alone (Part 8 `NTF-143`). No
/// request to the NDR names it.
const WATCH_HANDLE: [u8; HANDLE_LEN] = [0; HANDLE_LEN];

/// One request to the NDR.
pub enum NdrRequest<'a> {
    /// `NREG`: holds `ct_token` under `handle`. `prior` is the removal
    /// secret of the registration it replaces, or zero for a new handle.
    Register {
        /// The handle.
        handle: [u8; HANDLE_LEN],
        /// The nonce of the seal of the token.
        nonce: [u8; 24],
        /// The sealed push token with its tag.
        ct_token: &'a [u8],
        /// `SHA3-256` of the removal secret of this registration.
        removal_hash: [u8; 32],
        /// The removal secret of the registration that this one replaces.
        prior: Secret<32>,
    },
    /// `NUNREG`: drops the registration of `handle`.
    Unregister {
        /// The handle.
        handle: [u8; HANDLE_LEN],
        /// The removal secret whose hash the registration holds.
        removal: Secret<32>,
    },
    /// `NPUSH`: the push of a queue relay.
    Push {
        /// The handle.
        handle: [u8; HANDLE_LEN],
        /// The token key, which opens the token for this dispatch alone.
        k_tok: Secret<32>,
        /// The push expiry in seconds.
        ttl: u32,
        /// The blob.
        blob: [u8; BLOB_LEN],
    },
}

impl NdrRequest<'_> {
    /// The handle that the request names.
    pub fn handle(&self) -> &[u8; HANDLE_LEN] {
        match self {
            NdrRequest::Register { handle, .. }
            | NdrRequest::Unregister { handle, .. }
            | NdrRequest::Push { handle, .. } => handle,
        }
    }

    /// Writes the request, padded with zero bytes to `NDR_REQUEST_LEN`.
    pub fn encode(&self, out: &mut [u8; NDR_REQUEST_LEN]) -> Result<(), Error> {
        out.fill(0);
        if *self.handle() == WATCH_HANDLE {
            return Err(Error::Malformed);
        }

        let mut w = Writer::new(out);
        match self {
            NdrRequest::Register {
                handle,
                nonce,
                ct_token,
                removal_hash,
                prior,
            } => {
                if ct_token.len() > CT_TOKEN_MAX || ct_token.len() < 17 {
                    return Err(Error::Capacity);
                }

                w.u8(KIND_REGISTER)?;
                w.put(handle)?;
                w.put(nonce)?;
                w.u16(u16::try_from(ct_token.len()).map_err(|_| Error::Capacity)?)?;
                w.put(ct_token)?;
                w.put(removal_hash)?;
                w.put(prior.expose())?;
            }
            NdrRequest::Unregister { handle, removal } => {
                w.u8(KIND_UNREGISTER)?;
                w.put(handle)?;
                w.put(removal.expose())?;
            }
            NdrRequest::Push {
                handle,
                k_tok,
                ttl,
                blob,
            } => {
                w.u8(KIND_PUSH)?;
                w.put(handle)?;
                w.put(k_tok.expose())?;
                w.u32(*ttl)?;
                w.put(blob)?;
            }
        }
        Ok(())
    }

    /// Reads a request. The padding must be zero (`NTF-122`), and the
    /// handle must not be `WATCH_HANDLE` (`NTF-143`).
    pub fn parse(bytes: &[u8]) -> Result<NdrRequest<'_>, Error> {
        if bytes.len() != NDR_REQUEST_LEN {
            return Err(Error::Malformed);
        }

        let mut r = Reader::new(bytes);
        let kind = r.u8()?;
        let handle = r.array::<HANDLE_LEN>()?;
        if handle == WATCH_HANDLE {
            return Err(Error::Malformed);
        }

        let request = match kind {
            KIND_REGISTER => {
                let nonce = r.array::<24>()?;
                let len = usize::from(r.u16()?);
                if !(17..=CT_TOKEN_MAX).contains(&len) {
                    return Err(Error::Malformed);
                }

                let ct_token = r.take(len)?;
                let removal_hash = r.array::<32>()?;
                let prior = Secret::new(r.array::<32>()?);
                NdrRequest::Register {
                    handle,
                    nonce,
                    ct_token,
                    removal_hash,
                    prior,
                }
            }
            KIND_UNREGISTER => NdrRequest::Unregister {
                handle,
                removal: Secret::new(r.array::<32>()?),
            },
            KIND_PUSH => NdrRequest::Push {
                handle,
                k_tok: Secret::new(r.array::<32>()?),
                ttl: r.u32()?,
                blob: r.array::<BLOB_LEN>()?,
            },
            _ => return Err(Error::Malformed),
        };

        r.finish_zero()?;
        Ok(request)
    }
}

/// The provider that carries a push, the first byte of the plain push
/// token (`NTF-123`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCarrier {
    /// The reserved carrier `0x01`, which UnifiedPush used. No version
    /// serves it, and [`parse_token`] refuses it (`NTF-123`).
    UnifiedPush = 0x01,
    /// An FCM registration token.
    Fcm = 0x02,
}

/// Writes a plain push token: the carrier byte, then its target.
pub fn encode_token(carrier: TokenCarrier, target: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if target.is_empty() || target.len() >= PUSH_TOKEN_MAX {
        return Err(Error::Capacity);
    }

    let mut w = Writer::new(out);
    w.u8(carrier as u8)?;
    w.put(target)?;
    Ok(target.len().saturating_add(1))
}

/// Reads a plain push token. The carrier must be FCM, and the target
/// printable ASCII. The reserved carrier `0x01` does not read (`NTF-123`).
pub fn parse_token(bytes: &[u8]) -> Result<(TokenCarrier, &[u8]), Error> {
    let mut r = Reader::new(bytes);
    let carrier = match r.u8()? {
        0x02 => TokenCarrier::Fcm,
        _ => return Err(Error::Malformed),
    };

    let target = r.rest();
    let printable = target.iter().all(|b| (0x21..0x7F).contains(b));
    if target.is_empty() || !printable {
        return Err(Error::Malformed);
    }
    Ok((carrier, target))
}

/// The answer of the NDR to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdrResponse {
    /// The NDR took the request.
    Taken = 0x00,
    /// The NDR refused it: an unknown handle, a wrong secret, or bytes that
    /// do not parse. One reason covers each of them (`WIR-032`).
    Refused = 0x01,
    /// The provider named the push token gone, and the NDR dropped the
    /// registration. The queue relay stops pushing to that handle.
    Gone = 0x02,
}

impl NdrResponse {
    /// Writes the response, padded to `NDR_RESPONSE_LEN`.
    pub fn encode(self) -> [u8; NDR_RESPONSE_LEN] {
        let mut out = [0u8; NDR_RESPONSE_LEN];
        if let Some(first) = out.first_mut() {
            *first = self as u8;
        }
        out
    }

    /// Reads a response.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != NDR_RESPONSE_LEN {
            return Err(Error::Malformed);
        }

        let mut r = Reader::new(bytes);
        let status = match r.u8()? {
            0x00 => NdrResponse::Taken,
            0x01 => NdrResponse::Refused,
            0x02 => NdrResponse::Gone,
            _ => return Err(Error::Malformed),
        };

        r.finish_zero()?;
        Ok(status)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_fills_one_length_and_reads_back() {
        let ct = [7u8; 300];
        let requests = [
            NdrRequest::Register {
                handle: [1; 16],
                nonce: [2; 24],
                ct_token: &ct,
                removal_hash: [3; 32],
                prior: Secret::new([0; 32]),
            },
            NdrRequest::Unregister {
                handle: [1; 16],
                removal: Secret::new([4; 32]),
            },
            NdrRequest::Push {
                handle: [1; 16],
                k_tok: Secret::new([5; 32]),
                ttl: 86_400,
                blob: [6; BLOB_LEN],
            },
        ];
        for request in &requests {
            let mut out = [0u8; NDR_REQUEST_LEN];
            request.encode(&mut out).unwrap();
            let back = NdrRequest::parse(&out).unwrap();
            assert_eq!(back.handle(), &[1; 16]);
            let mut again = [0u8; NDR_REQUEST_LEN];
            back.encode(&mut again).unwrap();
            assert_eq!(out, again);
        }

        let mut out = [0u8; NDR_REQUEST_LEN];
        requests[0].encode(&mut out).unwrap();
        let NdrRequest::Register { ct_token, .. } = NdrRequest::parse(&out).unwrap() else {
            panic!("not a registration");
        };
        assert_eq!(ct_token, &ct[..]);
    }

    #[test]
    fn a_request_with_padding_or_an_unknown_kind_does_not_read() {
        let mut out = [0u8; NDR_REQUEST_LEN];
        NdrRequest::Unregister {
            handle: [1; 16],
            removal: Secret::new([4; 32]),
        }
        .encode(&mut out)
        .unwrap();

        let mut padded = out;
        padded[NDR_REQUEST_LEN - 1] = 1;
        assert!(NdrRequest::parse(&padded).is_err());

        let mut kind = out;
        kind[0] = 0x04;
        assert!(NdrRequest::parse(&kind).is_err());

        assert!(NdrRequest::parse(&out[..NDR_REQUEST_LEN - 1]).is_err());

        let too_long = [0u8; CT_TOKEN_MAX + 1];
        let register = NdrRequest::Register {
            handle: [1; 16],
            nonce: [2; 24],
            ct_token: &too_long,
            removal_hash: [3; 32],
            prior: Secret::new([0; 32]),
        };
        assert_eq!(register.encode(&mut out), Err(Error::Capacity));
    }

    #[test]
    fn a_token_names_fcm_and_the_reserved_carrier_does_not_read() {
        let mut out = [0u8; PUSH_TOKEN_MAX];
        let n = encode_token(TokenCarrier::Fcm, b"fcm-token", &mut out).unwrap();
        let (carrier, target) = parse_token(&out[..n]).unwrap();
        assert_eq!(carrier, TokenCarrier::Fcm);
        assert_eq!(target, b"fcm-token");

        // NTF-123: the carrier `0x01` is reserved, with any target.
        let n = encode_token(
            TokenCarrier::UnifiedPush,
            b"https://push.example/up/abc",
            &mut out,
        )
        .unwrap();
        assert!(parse_token(&out[..n]).is_err());

        assert!(parse_token(&[0x03, b'x']).is_err());
        assert!(parse_token(&[0x02, b' ']).is_err());
        assert!(parse_token(&[0x02]).is_err());
    }

    #[test]
    fn no_request_names_the_handle_of_a_watch() {
        // NTF-143: a request under 16 zero bytes neither writes nor reads.
        let mut out = [0u8; NDR_REQUEST_LEN];
        let push = NdrRequest::Push {
            handle: [0; HANDLE_LEN],
            k_tok: Secret::new([0; 32]),
            ttl: 60,
            blob: [6; BLOB_LEN],
        };
        assert_eq!(push.encode(&mut out), Err(Error::Malformed));

        NdrRequest::Unregister {
            handle: [1; HANDLE_LEN],
            removal: Secret::new([4; 32]),
        }
        .encode(&mut out)
        .unwrap();
        assert!(NdrRequest::parse(&out).is_ok());

        out[1..=HANDLE_LEN].fill(0);
        assert!(NdrRequest::parse(&out).is_err());
    }

    #[test]
    fn a_response_is_one_status_byte_and_zero_padding() {
        for status in [NdrResponse::Taken, NdrResponse::Refused, NdrResponse::Gone] {
            assert_eq!(NdrResponse::parse(&status.encode()), Ok(status));
        }
        let mut bad = NdrResponse::Taken.encode();
        bad[3] = 1;
        assert!(NdrResponse::parse(&bad).is_err());
    }
}
