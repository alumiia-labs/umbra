//! The smallest HTTPS of the push path of Part 8: a `POST` client and the
//! reader of one request. The OHTTP relay posts to the NDR, and the NDR
//! posts to the FCM endpoints of its provider. Neither needs more than one
//! request with a body of a plain length on one connection. Thus no HTTP
//! library enters register R3 (Part 14 §14.2.3).

use std::{sync::Arc, time::Duration};

use rustls::{pki_types::ServerName, ClientConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use umbra_crypto::zeroize::Zeroizing;

use crate::{
    native::{self, NativeError},
    Error,
};

/// The longest request head that a reader takes.
const HEAD_MAX: usize = 8_192;

/// An `https` URL: the host, the port, and the path with its query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// The host name or the address.
    pub host: String,
    /// The port, 443 when the URL names none.
    pub port: u16,
    /// The path, which starts with `/`.
    pub path: String,
    /// The address to dial in the place of the host, which stays the name
    /// of the certificate: an emulator reaches the machine of a test
    /// network at an address of its own.
    pub address: Option<std::net::IpAddr>,
}

impl Url {
    /// Reads an `https` URL of printable ASCII. A URL with user information
    /// (`@`), a fragment (`#`), or another scheme is refused.
    pub fn parse(text: &str) -> Option<Url> {
        let rest = text.strip_prefix("https://")?;
        if !text.bytes().all(|b| (0x21..0x7F).contains(&b)) || text.contains(['@', '#']) {
            return None;
        }

        let (authority, path) = match rest.find('/') {
            Some(at) => rest.split_at(at),
            None => (rest, "/"),
        };

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (authority, 443),
        };

        let is_host = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        is_host.then(|| Url {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
            address: None,
        })
    }
}

/// Posts `body` to `url` and reads the answer: the status and the body, of
/// a plain length or in chunks. A token endpoint of a provider sends its
/// answer in chunks.
pub async fn post(
    url: &Url,
    content_type: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    config: Arc<ClientConfig>,
    limit: usize,
    wait: Duration,
) -> Result<(u16, Vec<u8>), NativeError> {
    timeout(
        wait,
        post_now(url, content_type, headers, body, config, limit),
    )
    .await
    .map_err(|_| NativeError::Timeout)?
}

async fn post_now(
    url: &Url,
    content_type: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    config: Arc<ClientConfig>,
    limit: usize,
) -> Result<(u16, Vec<u8>), NativeError> {
    let tcp = connect_any(url).await?;
    let name = ServerName::try_from(url.host.clone()).map_err(|_| Error::Refused)?;
    let mut stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await?;

    // A header can hold an access token, thus the head takes its full
    // length at the start and wipes at its end.
    let extra: usize = headers
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()).saturating_add(4))
        .sum();
    let first = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        url.path,
        url.host,
        body.len()
    );
    let room = first.len().saturating_add(extra).saturating_add(2);
    let mut head = Zeroizing::new(String::with_capacity(room));
    head.push_str(&first);
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    // A TLS stream can hold a written record until its flush.
    stream.flush().await?;

    let mut inbound = Vec::with_capacity(1_024);
    let mut chunk = vec![0u8; 16_384];
    loop {
        // A server that closes with no TLS close is at its end too. The
        // framing of the answer then proves that the body is whole. The
        // code below refuses a body that the close alone ends.
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }

        inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        if inbound.len() > limit.saturating_add(HEAD_MAX) {
            return Err(Error::Refused.into());
        }
    }

    read_response(&inbound)
}

/// Connects to the first address of the host that answers, the IPv4
/// addresses first, with one address in use at a time. The peer thus sees
/// one address of this party, as a relay does at a dial. Before this, a
/// connect went to each address at once, and a host with two address
/// families saw the IPv4 and the IPv6 address of a device together.
///
/// The system resolver sees the host name when the URL holds no address. A
/// caller on a device gives the address.
async fn connect_any(url: &Url) -> Result<TcpStream, NativeError> {
    if let Some(address) = url.address {
        return Ok(TcpStream::connect((address, url.port)).await?);
    }

    let mut addrs: Vec<_> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await?
        .collect();
    addrs.sort_by_key(std::net::SocketAddr::is_ipv6);

    native::connect_first(addrs.into_iter()).await
}

/// Reads the status and the body of an answer. The body must prove its
/// own end, by a `Content-Length` that equals what came or by the last
/// chunk. The read above takes a cut connection as the end of the stream.
/// Thus a body that the close alone delimits can be a body cut short, and
/// the call refuses it. A `204` and a `304` hold no body and need no
/// framing.
fn read_response(inbound: &[u8]) -> Result<(u16, Vec<u8>), NativeError> {
    let head_end = inbound
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(Error::Refused)?;
    let head =
        core::str::from_utf8(inbound.get(..head_end).unwrap_or(&[])).map_err(|_| Error::Refused)?;

    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(status_code)
        .ok_or(Error::Refused)?;

    let body = inbound.get(head_end.saturating_add(4)..).unwrap_or(&[]);

    // RFC 9112 §6.3: an answer with two framings is not clear, thus the
    // head is read whole before the body.
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(Error::Refused.into());
            }
            chunked = true;
        }

        if name.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() {
                return Err(Error::Refused.into());
            }
            length = Some(content_length(value)?);
        }
    }

    match (chunked, length) {
        (true, None) => return Ok((status, dechunk(body)?)),
        (false, Some(length)) if length == body.len() => return Ok((status, body.to_vec())),
        (false, None) => {}
        _ => return Err(Error::Refused.into()),
    }

    if matches!(status, 204 | 304) && body.is_empty() {
        return Ok((status, Vec::new()));
    }
    Err(Error::Refused.into())
}

/// The status code at the start of `rest`, which is the status line after
/// its version: three digits, then a space or the end. Thus `2000` is no
/// status.
pub(crate) fn status_code(rest: &str) -> Option<u16> {
    let code = rest.get(..3)?;
    let ends = matches!(rest.as_bytes().get(3), None | Some(b' '));
    if !ends || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

/// The body of a chunked answer: each chunk after its size in hex, up to
/// the chunk of size zero. An extension after the size and the trailers go.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, NativeError> {
    let mut out = Vec::with_capacity(rest.len());
    loop {
        let line_end = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(Error::Refused)?;
        let line = core::str::from_utf8(rest.get(..line_end).unwrap_or(&[]))
            .map_err(|_| Error::Refused)?;
        let digits = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(digits, 16).map_err(|_| Error::Refused)?;
        rest = rest.get(line_end.saturating_add(2)..).unwrap_or(&[]);

        if size == 0 {
            return Ok(out);
        }

        let end = size.checked_add(2).ok_or(Error::Refused)?;
        if rest.get(size..end) != Some(b"\r\n".as_slice()) {
            return Err(Error::Refused.into());
        }

        out.extend_from_slice(rest.get(..size).unwrap_or(&[]));
        rest = rest.get(end..).unwrap_or(&[]);
    }
}

/// One request that a server read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: String,
    /// The path.
    pub path: String,
    /// The header lines, each name in lower case.
    pub headers: Vec<(String, String)>,
    /// The body, of the length that `Content-Length` gave.
    pub body: Vec<u8>,
}

/// Reads one request from `inbound`: `Ok(None)` while it is not complete.
/// A request with a body of another framing, or longer than `limit`, is
/// refused.
pub fn parse_request(inbound: &[u8], limit: usize) -> Result<Option<Request>, Error> {
    let Some(head_end) = head_end_after(inbound, 0) else {
        return if inbound.len() > HEAD_MAX {
            Err(Error::Refused)
        } else {
            Ok(None)
        };
    };

    let (head, length) = checked_head(inbound, head_end, limit)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(path)) = (first.next(), first.next()) else {
        return Err(Error::Refused);
    };

    let body_start = head_end.saturating_add(4);
    let Some(body) = inbound.get(body_start..body_start.saturating_add(length)) else {
        return Ok(None);
    };

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Ok(Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body: body.to_vec(),
    }))
}

/// Where the head of a request ends, from a search that starts at `from`.
fn head_end_after(inbound: &[u8], from: usize) -> Option<usize> {
    inbound
        .get(from..)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at.saturating_add(from))
}

/// Checks the head of a request that ends at `head_end`, with no
/// allocation. Gives the head and the length of the body.
fn checked_head(inbound: &[u8], head_end: usize, limit: usize) -> Result<(&str, usize), Error> {
    let head =
        core::str::from_utf8(inbound.get(..head_end).unwrap_or(&[])).map_err(|_| Error::Refused)?;
    let mut lines = head.split("\r\n");

    // RFC 9112 §3: the line is the method, the target, and the version,
    // with one space between them and nothing after them.
    let mut first = lines.next().unwrap_or_default().split(' ');
    let line = (first.next(), first.next(), first.next(), first.next());
    let (Some(method), Some(path), Some("HTTP/1.1"), None) = line else {
        return Err(Error::Refused);
    };
    if method.is_empty() || !path.starts_with('/') {
        return Err(Error::Refused);
    }

    let mut length = None;
    for line in lines {
        // RFC 9112 §2.2: a bare CR or LF in a line can read as the end of
        // that line to another party.
        if line.contains(['\r', '\n']) {
            return Err(Error::Refused);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Refused);
        };
        // RFC 9112 §5.1: a server refuses whitespace before the colon. A
        // proxy can read such a name as another header, which smuggles a
        // body past the framing checks below.
        if !is_token(name) {
            return Err(Error::Refused);
        }
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(Error::Refused);
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            // RFC 9112 §6.3: two lengths make the framing unclear.
            if length.is_some() {
                return Err(Error::Refused);
            }
            length = Some(content_length(value)?);
        }
    }

    let length = length.unwrap_or(0);
    if length > limit {
        return Err(Error::Refused);
    }

    Ok((head, length))
}

/// Whether `name` is a field name: one `token` of RFC 9110 §5.6.2, thus
/// with no whitespace.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// The value of a `Content-Length` field: decimal digits alone (RFC 9112
/// §6.2), thus no sign.
fn content_length(value: &str) -> Result<usize, Error> {
    let digits = value.trim();
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Refused);
    }
    digits.parse().map_err(|_| Error::Refused)
}

/// Reads one request from a stream, up to `limit` bytes of body.
pub async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    inbound: &mut Vec<u8>,
    limit: usize,
) -> Result<Request, Error> {
    let mut chunk = vec![0u8; 16_384];

    // The search for the end of the head starts where the last one ended,
    // and the head is checked one time. Before this, each read parsed the
    // whole buffer again.
    let mut searched = 0usize;
    let mut whole_at = None;

    loop {
        if whole_at.is_none() {
            match head_end_after(inbound, searched) {
                Some(head_end) => {
                    let (_, length) = checked_head(inbound, head_end, limit)?;
                    whole_at = Some(head_end.saturating_add(4).saturating_add(length));
                }
                None if inbound.len() > HEAD_MAX => return Err(Error::Refused),
                // The end can lie across two reads.
                None => searched = inbound.len().saturating_sub(3),
            }
        }

        if whole_at.is_some_and(|end| inbound.len() >= end) {
            return parse_request(inbound, limit)?.ok_or(Error::Refused);
        }

        match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => inbound.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            _ => return Err(Error::Refused),
        }
    }
}

/// Writes one response with a body and ends the connection.
pub async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Bad Gateway",
    };

    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_url_names_its_host_port_and_path() {
        assert_eq!(
            Url::parse("https://push.example:8443/up/abc?x=1"),
            Some(Url {
                host: "push.example".into(),
                port: 8443,
                path: "/up/abc?x=1".into(),
                address: None,
            })
        );
        assert_eq!(Url::parse("https://127.1.0.1").unwrap().path, "/");
        assert_eq!(Url::parse("https://a.example/").unwrap().port, 443);

        for bad in [
            "http://a.example/",
            "https://user@a.example/",
            "https://a.example/#x",
            "https:///path",
            "https://a b/",
            "https://a.example:99999/",
        ] {
            assert_eq!(Url::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_request_reads_when_its_body_is_complete() {
        let full = b"POST /ohttp HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse_request(&full[..full.len() - 1], 64), Ok(None));
        let request = parse_request(full, 64).unwrap().unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/ohttp");
        assert_eq!(request.body, b"hello");
        assert_eq!(
            request.headers,
            [
                ("host".into(), "x".into()),
                ("content-length".into(), "5".into())
            ]
        );
        assert!(parse_request(full, 4).is_err());

        // A fault in the head shows before the body is complete.
        let bad = b"POST / HTTP/1.1\r\nHost x\r\nContent-Length: 5\r\n\r\nhe";
        assert!(parse_request(bad, 64).is_err());

        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_request(chunked, 64).is_err());
        assert!(parse_request(&[b'a'; HEAD_MAX + 1], 64).is_err());
    }

    #[test]
    fn a_header_name_with_whitespace_is_refused() {
        for bad in [
            &b"POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n"[..],
            b"POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\nhello",
            b"POST / HTTP/1.1\r\nContent-Length\t: 5\r\n\r\nhello",
            b"POST / HTTP/1.1\r\nHost: x\r\n Content-Length: 5\r\n\r\nhello",
            b"POST / HTTP/1.1\r\n: x\r\n\r\n",
        ] {
            assert_eq!(
                parse_request(bad, 64),
                Err(Error::Refused),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_second_content_length_is_refused() {
        let two = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello";
        assert_eq!(parse_request(two, 64), Err(Error::Refused));
        let same = b"POST / HTTP/1.1\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\nhello";
        assert_eq!(parse_request(same, 64), Err(Error::Refused));

        let signed = b"POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\nhello";
        assert_eq!(parse_request(signed, 64), Err(Error::Refused));

        // A request line with one more part, with no path, or with a bare
        // LF in a header is no request.
        for bad in [
            &b"POST / HTTP/1.1 x\r\nContent-Length: 0\r\n\r\n"[..],
            b"POST  HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            b"POST x HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\nContent-Length: 9\r\n\r\n",
        ] {
            assert_eq!(parse_request(bad, 64), Err(Error::Refused));
        }
        let one = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse_request(one, 64).unwrap().unwrap().body, b"hello");
    }

    #[test]
    fn a_response_gives_its_status_and_a_body_of_its_length() {
        let ok = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(read_response(ok).unwrap(), (201, b"ok".to_vec()));
        let gone = b"HTTP/1.1 410 Gone\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(read_response(gone).unwrap(), (410, Vec::new()));

        let chunks = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            4;x=y\r\n{\"a\"\r\na\r\n:\"token\"}\n\r\n0\r\nX-T: 1\r\n\r\n";
        assert_eq!(
            read_response(chunks).unwrap(),
            (200, b"{\"a\":\"token\"}\n".to_vec())
        );

        let torn = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nok\r\n";
        assert!(read_response(torn).is_err());

        let other = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nok";
        assert!(read_response(other).is_err());

        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nok";
        assert!(read_response(short).is_err());

        // Two framings in one answer are not clear, in each order.
        let both =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(read_response(both).is_err());
        let twice = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok";
        assert!(read_response(twice).is_err());

        // A status has three digits.
        let long = b"HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\nok";
        assert!(read_response(long).is_err());
    }

    #[test]
    fn a_body_that_the_close_alone_ends_is_refused() {
        // A cut connection gives the same bytes as a whole answer here.
        let open = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        assert!(read_response(open).is_err());
        let empty = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        assert!(read_response(empty).is_err());

        // A status with no body needs no framing.
        let none = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        assert_eq!(read_response(none).unwrap(), (204, Vec::new()));
        let filled = b"HTTP/1.1 204 No Content\r\n\r\nok";
        assert!(read_response(filled).is_err());

        let zero = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(read_response(zero).unwrap(), (200, Vec::new()));
    }
}
