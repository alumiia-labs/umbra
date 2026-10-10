//! The HTTP/1.1 upgrade of Part 3 §3.8 that opens the WebSocket-shaped
//! stream on the TCP transport.
//!
//! The request is `GET /umbra HTTP/1.1` with the RFC 6455 headers and the
//! subprotocol `umbra.v1` (`NET-280`, `NET-281`). Every client sends the
//! same bytes but the host and the key, thus the request carries no
//! fingerprint of its own.

use alloc::{format, string::String, vec::Vec};

/// The request path.
pub const PATH: &str = "/umbra";
/// The WebSocket subprotocol.
pub const SUBPROTOCOL: &str = "umbra.v1";
/// The GUID of RFC 6455 §1.3.
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Base64 without padding stripping, as RFC 6455 wants it.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let idx = |shift: u32| {
            TABLE
                .get(((n >> shift) & 63) as usize)
                .copied()
                .unwrap_or(b'A')
        };
        out.push(char::from(idx(18)));
        out.push(char::from(idx(12)));
        out.push(if chunk.len() > 1 {
            char::from(idx(6))
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(idx(0))
        } else {
            '='
        });
    }
    out
}

/// The request a client sends first on a TCP connection. `key` is 16
/// random bytes from the client.
pub fn request(host: &str, key: &[u8; 16]) -> String {
    format!(
        "GET {PATH} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n",
        base64(key)
    )
}

/// SHA-1 over one message, for the accept token only.
///
/// The token proves that the relay read the key and nothing else, and the
/// browser of the web client checks it with SHA-1 as RFC 6455 says. No key
/// and no secret passes through this function, thus it is not a primitive
/// of Part 5 §5.1.
fn sha1(message: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut data = message.to_vec();
    let bit_len = (message.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    for block in data.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks(4).enumerate().take(16) {
            let mut b = [0u8; 4];
            b.copy_from_slice(word);
            if let Some(slot) = w.get_mut(i) {
                *slot = u32::from_be_bytes(b);
            }
        }
        for i in 16usize..80 {
            let at = |back: usize| w.get(i.wrapping_sub(back)).copied().unwrap_or(0);
            let v = at(3) ^ at(8) ^ at(14) ^ at(16);
            if let Some(slot) = w.get_mut(i) {
                *slot = v.rotate_left(1);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, v) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// The `Sec-WebSocket-Accept` value for a key, as RFC 6455 §4.2.2 computes
/// it, thus a browser accepts the relay's answer.
pub fn accept_value(key_header: &str) -> String {
    let mut preimage = key_header.as_bytes().to_vec();
    preimage.extend_from_slice(GUID);
    base64(&sha1(&preimage))
}

/// The response a relay sends to accept an upgrade.
pub fn response(key_header: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n",
        accept_value(key_header)
    )
}

/// A parsed upgrade request at the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The `Host` header.
    pub host: String,
    /// The `Sec-WebSocket-Key` header, as sent.
    pub key: String,
}

fn split_head(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((bytes.get(..end)?, end.saturating_add(4)))
}

fn header<'a>(lines: &[&'a str], name: &str) -> Option<&'a str> {
    lines.iter().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn token_present(value: Option<&str>, token: &str) -> bool {
    value.is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

/// Parses a request. Returns the request and the bytes it took, thus the
/// caller keeps any capsule bytes that followed it. Rejects a request
/// that is not the upgrade this crate sends (`WIR-230`).
pub fn parse_request(bytes: &[u8]) -> Result<Option<(Request, usize)>, crate::Error> {
    let Some((head, used)) = split_head(bytes) else {
        return Ok(None);
    };
    let text = core::str::from_utf8(head).map_err(|_| crate::Error::Malformed)?;
    let mut lines = text.split("\r\n");
    let start = lines.next().ok_or(crate::Error::Malformed)?;
    if start != format!("GET {PATH} HTTP/1.1") {
        return Err(crate::Error::Malformed);
    }
    let lines: Vec<&str> = lines.collect();
    let host = header(&lines, "Host").ok_or(crate::Error::Malformed)?;
    let key = header(&lines, "Sec-WebSocket-Key").ok_or(crate::Error::Malformed)?;
    if !token_present(header(&lines, "Upgrade"), "websocket")
        || !token_present(header(&lines, "Connection"), "Upgrade")
        || header(&lines, "Sec-WebSocket-Version") != Some("13")
        || !token_present(header(&lines, "Sec-WebSocket-Protocol"), SUBPROTOCOL)
    {
        return Err(crate::Error::Malformed);
    }
    // WIR-485: no extension is negotiated, and a request that offers one
    // is answered without it; the relay never echoes the header.
    Ok(Some((
        Request {
            host: String::from(host),
            key: String::from(key),
        },
        used,
    )))
}

/// Parses a response at the client against the key it sent. Returns the
/// bytes it took. The response must be the answer of `NET-281`. That answer
/// holds the status `101` as one token, `Upgrade: websocket`, and the
/// accept token of the key. Its `Connection` header holds the token
/// `Upgrade`. RFC 6455 §4.2.2 gives that header a list of tokens, and a
/// proxy in front of a relay can send `keep-alive, Upgrade`. The call
/// refuses a response that negotiated an extension, or that does not name
/// the subprotocol.
pub fn parse_response(bytes: &[u8], key: &[u8; 16]) -> Result<Option<usize>, crate::Error> {
    let Some((head, used)) = split_head(bytes) else {
        return Ok(None);
    };
    let text = core::str::from_utf8(head).map_err(|_| crate::Error::Malformed)?;
    let mut lines = text.split("\r\n");
    let start = lines.next().ok_or(crate::Error::Malformed)?;
    let mut status = start.splitn(3, ' ');
    if (status.next(), status.next()) != (Some("HTTP/1.1"), Some("101")) {
        return Err(crate::Error::Refused);
    }
    let lines: Vec<&str> = lines.collect();
    let exact = |name: &str, token: &str| {
        header(&lines, name).is_some_and(|value| value.eq_ignore_ascii_case(token))
    };
    if !exact("Upgrade", "websocket")
        || !token_present(header(&lines, "Connection"), "Upgrade")
        || header(&lines, "Sec-WebSocket-Accept") != Some(accept_value(&base64(key)).as_str())
        || !token_present(header(&lines, "Sec-WebSocket-Protocol"), SUBPROTOCOL)
        || header(&lines, "Sec-WebSocket-Extensions").is_some()
    {
        return Err(crate::Error::Refused);
    }
    Ok(Some(used))
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
    fn the_request_and_the_response_round_trip() {
        let key = [7u8; 16];
        let req = request("relay.example", &key);
        let (parsed, used) = parse_request(req.as_bytes()).unwrap().unwrap();
        assert_eq!(used, req.len());
        assert_eq!(parsed.host, "relay.example");
        let resp = response(&parsed.key);
        assert_eq!(
            parse_response(resp.as_bytes(), &key).unwrap(),
            Some(resp.len())
        );
        assert!(parse_response(resp.as_bytes(), &[8u8; 16]).is_err());
        assert_eq!(parse_request(&req.as_bytes()[..20]).unwrap(), None);
        let other = req.replace("/umbra", "/other");
        assert!(parse_request(other.as_bytes()).is_err());
        let compressed = resp.replace(
            "\r\n\r\n",
            "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
        );
        assert!(parse_response(compressed.as_bytes(), &key).is_err());
        let refused = resp.replace("101 Switching Protocols", "400 Bad Request");
        assert_eq!(
            parse_response(refused.as_bytes(), &key),
            Err(crate::Error::Refused)
        );
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        // The example of RFC 6455 §1.3.
        assert_eq!(
            accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }

    #[test]
    fn a_response_that_is_not_the_exact_answer_is_refused() {
        let key = [7u8; 16];
        let resp = response(&base64(&key));
        assert_eq!(
            parse_response(resp.as_bytes(), &key).unwrap(),
            Some(resp.len())
        );
        // NET-281: the status is one token, the `Upgrade` header is exact,
        // and the `Connection` header holds its token.
        for (from, to) in [
            ("HTTP/1.1 101 ", "HTTP/1.1 1015 "),
            ("HTTP/1.1 101 ", "HTTP/1.1 101"),
            ("HTTP/1.1 101 ", "HTTP/1.0 101 "),
            ("Upgrade: websocket\r\n", ""),
            ("Upgrade: websocket\r\n", "Upgrade: h2c\r\n"),
            ("Upgrade: websocket\r\n", "Upgrade: websocket, h2c\r\n"),
            ("Connection: Upgrade\r\n", ""),
            ("Connection: Upgrade\r\n", "Connection: close\r\n"),
            (
                "Connection: Upgrade\r\n",
                "Connection: keep-alive, Upgraded\r\n",
            ),
        ] {
            let loose = resp.replacen(from, to, 1);
            assert_ne!(loose, resp);
            assert_eq!(
                parse_response(loose.as_bytes(), &key),
                Err(crate::Error::Refused),
                "{to}"
            );
        }
        // The token of the `Connection` header can stand in a list, as a
        // proxy in front of a relay sends it.
        let listed = resp.replace("Connection: Upgrade", "Connection: keep-alive, upgrade");
        assert_eq!(
            parse_response(listed.as_bytes(), &key).unwrap(),
            Some(listed.len())
        );
        // The reason phrase is free text, and a relay may send none.
        let bare = resp.replace("101 Switching Protocols", "101");
        assert_eq!(
            parse_response(bare.as_bytes(), &key).unwrap(),
            Some(bare.len())
        );
    }
}
