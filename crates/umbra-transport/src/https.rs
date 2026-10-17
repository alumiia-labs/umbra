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

use crate::{native::NativeError, Error};

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

    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        url.path,
        url.host,
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
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

/// Connects to each address of the host at once and keeps the first that
/// answers. A host name with an IPv6 address that refuses costs no wait
/// then: a refused connect on some systems takes seconds.
async fn connect_any(url: &Url) -> Result<TcpStream, NativeError> {
    if let Some(address) = url.address {
        return Ok(TcpStream::connect((address, url.port)).await?);
    }

    let mut attempts = tokio::task::JoinSet::new();
    for addr in tokio::net::lookup_host((url.host.as_str(), url.port)).await? {
        attempts.spawn(TcpStream::connect(addr));
    }

    let mut last = None;
    while let Some(joined) = attempts.join_next().await {
        match joined {
            Ok(Ok(tcp)) => return Ok(tcp),
            Ok(Err(error)) => last = Some(error),
            Err(_) => {}
        }
    }
    Err(last.map_or_else(|| Error::Refused.into(), NativeError::from))
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
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(Error::Refused)?;

    let body = inbound.get(head_end.saturating_add(4)..).unwrap_or(&[]);

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(Error::Refused.into());
            }
            return Ok((status, dechunk(body)?));
        }

        if name.eq_ignore_ascii_case("Content-Length") {
            if value.trim().parse::<usize>().ok() != Some(body.len()) {
                return Err(Error::Refused.into());
            }
            return Ok((status, body.to_vec()));
        }
    }

    if matches!(status, 204 | 304) && body.is_empty() {
        return Ok((status, Vec::new()));
    }
    Err(Error::Refused.into())
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
    let Some(head_end) = inbound.windows(4).position(|window| window == b"\r\n\r\n") else {
        return if inbound.len() > HEAD_MAX {
            Err(Error::Refused)
        } else {
            Ok(None)
        };
    };

    let head =
        core::str::from_utf8(inbound.get(..head_end).unwrap_or(&[])).map_err(|_| Error::Refused)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(path), Some("HTTP/1.1")) = (first.next(), first.next(), first.next())
    else {
        return Err(Error::Refused);
    };

    let mut length = 0usize;
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::Refused);
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(Error::Refused);
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            length = value.trim().parse().map_err(|_| Error::Refused)?;
        }
    }

    if length > limit {
        return Err(Error::Refused);
    }

    let body_start = head_end.saturating_add(4);
    let Some(body) = inbound.get(body_start..body_start.saturating_add(length)) else {
        return Ok(None);
    };
    Ok(Some(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body: body.to_vec(),
    }))
}

/// Reads one request from a stream, up to `limit` bytes of body.
pub async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    inbound: &mut Vec<u8>,
    limit: usize,
) -> Result<Request, Error> {
    let mut chunk = vec![0u8; 16_384];
    loop {
        if let Some(request) = parse_request(inbound, limit)? {
            return Ok(request);
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
        assert_eq!(request.headers[0], ("host".into(), "x".into()));
        assert!(parse_request(full, 4).is_err());

        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_request(chunked, 64).is_err());
        assert!(parse_request(&[b'a'; HEAD_MAX + 1], 64).is_err());
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
