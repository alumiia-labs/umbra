//! The intake of a directory with one operator (Part 10 §10.6.4): what a
//! relay asks before its admission. It tells a relay the address that its
//! request comes from and the autonomous system of that address, and it
//! checks a join request before the request goes to the inbox of the owner.
//!
//! The intake holds no key and admits no relay. The owner still verifies
//! the dossier of each request (`REL-012`).
//!
//! This module takes no socket. [`crate::intake_server`] binds it to one.

use std::{collections::BTreeMap, net::Ipv4Addr};

use umbra_core::directory::descriptor::{roles, RelayDescriptor, DESCRIPTOR_LEN, HOST_LEN};
use umbra_crypto::hex;

/// The first line and the last line of a join request.
pub const BEGIN: &str = "-----BEGIN UMBRA RELAY REQUEST-----";
/// See [`BEGIN`].
pub const END: &str = "-----END UMBRA RELAY REQUEST-----";

/// The longest join request. A descriptor takes 7 400 characters of it.
pub const REQUEST_MAX: usize = 12 << 10;
/// The longest head of an HTTP request.
pub const HEAD_MAX: usize = 4 << 10;
/// The requests that the inbox holds. A full inbox takes no new relay.
pub const INBOX_MAX: usize = 500;

/// The origin of an address: its autonomous system, and the country that
/// the registry of that system states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {
    /// The number of the autonomous system.
    pub asn: u32,
    /// ISO 3166-1 alpha-2, when the table states one. It is the country of
    /// the registry entry. The machine can be in another country.
    pub country: Option<[u8; 2]>,
}

#[derive(Debug, Clone, Copy)]
struct Row {
    first: u32,
    last: u32,
    origin: Origin,
}

/// The table of the address ranges of each autonomous system.
#[derive(Debug, Default)]
pub struct AsTable {
    rows: Vec<Row>,
}

impl AsTable {
    /// Reads a table with one range on each line: the first address, the
    /// last address, the AS number, and the country, with a tab between
    /// two values. A line that does not read, and a range with no system,
    /// gives no row.
    pub fn parse(text: &str) -> Self {
        let mut rows: Vec<Row> = text.lines().filter_map(row_of).collect();
        rows.sort_by_key(|row| row.first);

        Self { rows }
    }

    /// The count of the ranges.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table holds no range.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The origin of `address`, or none for an address outside each range.
    pub fn lookup(&self, address: Ipv4Addr) -> Option<Origin> {
        let address = u32::from(address);
        let after = self.rows.partition_point(|row| row.first <= address);
        let row = self.rows.get(after.checked_sub(1)?)?;

        (address <= row.last).then_some(row.origin)
    }
}

fn row_of(line: &str) -> Option<Row> {
    let mut values = line.split('\t');
    let first = u32::from(values.next()?.trim().parse::<Ipv4Addr>().ok()?);
    let last = u32::from(values.next()?.trim().parse::<Ipv4Addr>().ok()?);
    let asn: u32 = values.next()?.trim().parse().ok()?;
    let country = values.next().and_then(|text| country_of(text.trim()));

    (asn != 0 && first <= last).then_some(Row {
        first,
        last,
        origin: Origin { asn, country },
    })
}

fn country_of(text: &str) -> Option<[u8; 2]> {
    let code: [u8; 2] = text.as_bytes().try_into().ok()?;
    code.iter().all(u8::is_ascii_uppercase).then_some(code)
}

/// The bytes of a standard base64 text. Line ends between the characters
/// are no part of it.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut held: u32 = 0;
    let mut bits: u32 = 0;
    let mut padded = false;

    for byte in text.bytes() {
        let value = match byte {
            b'\r' | b'\n' => continue,
            b'=' => {
                padded = true;
                continue;
            }
            _ if padded => return None,
            b'A'..=b'Z' => byte.wrapping_sub(b'A'),
            b'a'..=b'z' => byte.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => byte.wrapping_sub(b'0').wrapping_add(52),
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };

        held = (held << 6) | u32::from(value);
        bits = bits.wrapping_add(6);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push(u8::try_from((held >> bits) & 0xff).ok()?);
        }
    }

    Some(out)
}

/// A join request that passed [`check_join`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The `relay_id` of its descriptor.
    pub relay_id: [u8; 32],
    /// The request from [`BEGIN`] to [`END`], as the inbox keeps it.
    pub text: String,
}

/// What [`check_join`] compares a request with.
#[derive(Debug, Clone, Copy)]
pub struct Caller<'a> {
    /// The address that the request came from.
    pub address: Ipv4Addr,
    /// The origin of that address, when the table holds it.
    pub origin: Option<Origin>,
    /// The name of the operator of the network (`REL-128`).
    pub own_operator: Option<&'a str>,
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_operator(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_host(text: &str) -> bool {
    text.len() < HOST_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

/// The bits that the descriptor of a role has, and those that it has not.
fn role_bits(role: &str) -> Option<(u8, u8)> {
    match role {
        "entry" => Some((roles::CHAIN | roles::INGRESS_OFFERED, roles::QUEUE)),
        "middle" => Some((roles::CHAIN, 0)),
        "exit" => Some((roles::QUEUE | roles::CHAIN, roles::INGRESS_OFFERED)),
        _ => None,
    }
}

/// The facts of a request, and the text of its descriptor.
fn facts_of(body: &str) -> Option<(BTreeMap<&str, &str>, String)> {
    let mut facts = BTreeMap::new();
    let mut lines = body.lines().map(str::trim).filter(|line| !line.is_empty());

    for line in lines.by_ref() {
        if line == "descriptor=" {
            let descriptor: String = lines.collect();
            return Some((facts, descriptor));
        }

        let (name, value) = line.split_once('=')?;
        // A second line of one name would hide the first one from the owner.
        if facts.insert(name, value).is_some() {
            return None;
        }
    }

    None
}

/// Checks a join request against its own descriptor and against the
/// address that it came from (`REL-231`, `REL-232`). The error is one line
/// for the operator of the relay.
pub fn check_join(text: &str, caller: Caller<'_>) -> Result<Accepted, &'static str> {
    if text.len() > REQUEST_MAX {
        return Err("the request is too long");
    }
    // The owner reads the request in a terminal.
    if !text
        .bytes()
        .all(|b| b == b'\n' || b == b'\r' || (0x20..0x7f).contains(&b))
    {
        return Err("the request holds a character outside printable ASCII");
    }

    let body = text
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body)
        .ok_or("the request holds no text from BEGIN to END")?;
    let (facts, descriptor_text) = facts_of(body).ok_or("the lines of the request do not read")?;
    let fact = |name: &'static str| facts.get(name).copied().unwrap_or("");

    if !is_name(fact("name")) {
        return Err("name takes a-z, 0-9 and -");
    }
    if !is_operator(fact("operator")) {
        return Err("operator takes letters, digits, and . _ -");
    }
    // REL-128: a request never makes a relay one of the own operator.
    if caller.own_operator == Some(fact("operator")) {
        return Err("operator is the name of the operator of the network");
    }
    if fact("contact").is_empty() || fact("contact").len() > 200 {
        return Err("contact is an address for abuse and legal reports");
    }

    let (need, forbid) = role_bits(fact("role")).ok_or("role is entry, middle or exit")?;
    let class: u8 = fact("class").parse().map_err(|_| "class is 0, 1, 2 or 3")?;
    let asn: u32 = fact("asn").parse().map_err(|_| "asn is a number")?;
    let country: [u8; 2] = fact("country")
        .as_bytes()
        .try_into()
        .map_err(|_| "country is two capital letters")?;
    let family: [u8; 32] = hex::read_array(fact("family")).ok_or("family is 64 hex characters")?;
    let relay_id: [u8; 32] =
        hex::read_array(fact("relay_id")).ok_or("relay_id is 64 hex characters")?;

    let mut public = fact("public").split(',');
    let host = public.next().filter(|host| is_host(host));
    let address = public.next().and_then(|text| text.parse::<Ipv4Addr>().ok());
    let port = public.next().and_then(|text| text.parse::<u16>().ok());
    let (Some(host), Some(address), Some(port), None) = (host, address, port, public.next()) else {
        return Err("public is <host or nothing>,<IPv4 address>,<port>");
    };

    let raw = base64_decode(&descriptor_text).ok_or("the descriptor is not base64")?;
    if raw.len() != DESCRIPTOR_LEN {
        return Err("the descriptor has a wrong length");
    }
    // REL-050, REL-051: the key gives the relay_id, and the signature holds.
    let descriptor = RelayDescriptor::parse(&raw)
        .map_err(|_| "the descriptor does not verify under its own key")?;

    let same = descriptor.relay_id == relay_id
        && descriptor.addr_v4 == address.octets()
        && descriptor.port == port
        && descriptor.asn == asn
        && descriptor.jurisdiction == country
        && descriptor.family_id == family
        && descriptor.capacity_class == class;
    if !same {
        return Err("the descriptor states another fact than the lines of the request");
    }
    let host_same = match descriptor.link_pin() {
        Some(_) => host.is_empty(),
        None => !host.is_empty() && descriptor.host_str() == host,
    };
    if !host_same {
        return Err("the descriptor states another host than the request");
    }
    if descriptor.roles & need != need || descriptor.roles & forbid != 0 {
        return Err("the descriptor offers other roles than the role of the request");
    }
    if fact("role") == "entry" && (class == 0 || port != 443) {
        return Err("an entry relay takes port 443 and class 1 or more");
    }

    // REL-231: the request comes from the address that the descriptor states.
    if address != caller.address {
        return Err("the request comes from another address than the descriptor states");
    }
    // REL-232: the table knows the system of the address.
    if caller.origin.is_some_and(|origin| origin.asn != asn) {
        return Err("the address is in another autonomous system than the descriptor states");
    }

    Ok(Accepted {
        relay_id,
        text: format!("{BEGIN}{body}{END}\n"),
    })
}

/// The head of an HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The method, as `GET`.
    pub method: String,
    /// The path.
    pub path: String,
    /// The length of the body.
    pub content_length: usize,
    /// The address of the client, as the proxy before the intake states it.
    pub real_ip: Option<Ipv4Addr>,
}

/// The place after the head in `bytes`, when the head is complete.
pub fn head_end(bytes: &[u8]) -> Option<usize> {
    let at = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    at.checked_add(4)
}

/// Reads the head of an HTTP/1.1 request.
pub fn parse_head(head: &[u8]) -> Option<Head> {
    let text = core::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");

    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    if !first.next()?.starts_with("HTTP/1.") || first.next().is_some() {
        return None;
    }

    let mut content_length = 0;
    let mut real_ip = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        let value = value.trim();

        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok()?;
        } else if name.eq_ignore_ascii_case("x-real-ip") {
            // An IPv6 address is no address of a relay, thus it is none here.
            real_ip = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // The intake reads a body of a stated length alone.
            return None;
        }
    }

    Some(Head {
        method,
        path,
        content_length,
        real_ip,
    })
}

/// An HTTP answer with a body of text. The connection closes after it.
pub fn answer(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        _ => "Service Unavailable",
    };

    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The addresses that a [`Limiter`] counts. A flood from more addresses
/// empties the count, and the inbox has its own bound.
const LIMITER_ADDRESSES: usize = 20_000;

/// A count of the requests of each address in a window of time.
#[derive(Debug)]
pub struct Limiter {
    window: u64,
    most: u32,
    seen: BTreeMap<Ipv4Addr, (u64, u32)>,
}

impl Limiter {
    /// A limiter that lets `most` requests of one address pass in each
    /// `window` seconds.
    pub fn new(window: u64, most: u32) -> Self {
        Self {
            window,
            most,
            seen: BTreeMap::new(),
        }
    }

    /// Whether a request of `address` at `now` passes. A request that
    /// passes counts.
    pub fn pass(&mut self, address: Ipv4Addr, now: u64) -> bool {
        if self.seen.len() >= LIMITER_ADDRESSES {
            let window = self.window;
            self.seen
                .retain(|_, (start, _)| now.saturating_sub(*start) < window);
        }
        if self.seen.len() >= LIMITER_ADDRESSES {
            self.seen.clear();
        }

        let (start, count) = self.seen.entry(address).or_insert((now, 0));
        if now.saturating_sub(*start) >= self.window {
            *start = now;
            *count = 0;
        }
        if *count >= self.most {
            return false;
        }

        *count = count.saturating_add(1);
        true
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
pub(crate) mod tests {
    use super::*;
    use umbra_core::directory::descriptor::pin_host;
    use umbra_crypto::{rand_core, secret::Secret, sign::SigningKey};

    const TABLE: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
                         1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
                         a line that does not read\n\
                         198.51.100.0\t198.51.100.255\t64500\tNone\tEXAMPLE\n\
                         5.39.0.0\t5.39.127.255\t16276\tFR\tOVH\n";

    #[test]
    fn the_table_gives_the_system_of_an_address() {
        let table = AsTable::parse(TABLE);
        assert_eq!(table.len(), 3);

        let ovh = table.lookup(Ipv4Addr::new(5, 39, 100, 1)).unwrap();
        assert_eq!((ovh.asn, ovh.country), (16276, Some(*b"FR")));
        assert_eq!(
            table.lookup(Ipv4Addr::new(1, 0, 0, 255)).unwrap().asn,
            13335
        );
        assert_eq!(
            table
                .lookup(Ipv4Addr::new(198, 51, 100, 7))
                .unwrap()
                .country,
            None
        );

        // A range with no system, a gap, and an address before each range.
        assert_eq!(table.lookup(Ipv4Addr::new(1, 0, 2, 1)), None);
        assert_eq!(table.lookup(Ipv4Addr::new(5, 39, 128, 0)), None);
        assert_eq!(table.lookup(Ipv4Addr::new(0, 0, 0, 1)), None);
        assert_eq!(AsTable::default().lookup(Ipv4Addr::new(1, 0, 0, 1)), None);
    }

    #[test]
    fn base64_reads_each_padding() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TW\nFu\r\n").unwrap(), b"Man");
        assert_eq!(base64_decode("+/8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(base64_decode("TQ==TQ"), None);
        assert_eq!(base64_decode("T Q"), None);
    }

    pub(crate) const ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    /// A signed descriptor of a middle relay in pin form at [`ADDRESS`].
    pub(crate) fn descriptor(seed: u8, roles: u8, host: [u8; HOST_LEN]) -> ([u8; 32], Vec<u8>) {
        let key = SigningKey::from_seed(Secret::new([seed; 32]));
        let descriptor = RelayDescriptor {
            relay_id: [0; 32],
            identity_pk: &[],
            ntor_pk: [3; 32],
            addr_v4: ADDRESS.octets(),
            addr_v6: [0; 16],
            port: 9443,
            host,
            asn: 64500,
            jurisdiction: *b"DE",
            family_id: [7; 32],
            capacity_class: 0,
            roles,
            chunk_store_gib: 0,
            valid_after: 1,
            sig: &[],
        };
        let bytes = descriptor.sign(&key, &mut Zeros).unwrap();
        let relay_id = RelayDescriptor::parse(&bytes).unwrap().relay_id;

        (relay_id, bytes)
    }

    /// A source of zero bytes: a signature of a test needs no random value.
    pub(crate) struct Zeros;

    impl rand_core::TryRng for Zeros {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Zeros {}

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut held = [0u8; 3];
            held[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from_be_bytes([0, held[0], held[1], held[2]]);
            for at in 0..4 {
                if at <= chunk.len() {
                    out.push(ALPHABET[((bits >> (18 - 6 * at)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
            if out.len() % 77 == 76 {
                out.push('\n');
            }
        }
        out
    }

    /// The join request of the relay of [`descriptor`], with `changes` in
    /// the place of its lines of the same name.
    pub(crate) fn request(relay_id: &[u8; 32], raw: &[u8], changes: &[(&str, &str)]) -> String {
        let mut lines = vec![
            ("name", "home-1".to_owned()),
            ("role", "middle".to_owned()),
            ("class", "0".to_owned()),
            ("public", format!(",{ADDRESS},9443")),
            ("operator", "alice".to_owned()),
            ("contact", "abuse@example.org".to_owned()),
            ("country", "DE".to_owned()),
            ("asn", "64500".to_owned()),
            ("family", hex::write(&[7; 32])),
            ("relay_id", hex::write(relay_id)),
        ];
        for (name, value) in changes {
            let line = lines.iter_mut().find(|line| line.0 == *name).unwrap();
            line.1 = (*value).to_owned();
        }

        let mut text = format!("{BEGIN}\n");
        for (name, value) in lines {
            text.push_str(&format!("{name}={value}\n"));
        }
        text.push_str(&format!("descriptor=\n{}\n{END}\n", base64(raw)));
        text
    }

    fn caller() -> Caller<'static> {
        Caller {
            address: ADDRESS,
            origin: Some(Origin {
                asn: 64500,
                country: None,
            }),
            own_operator: Some("umbra-project"),
        }
    }

    #[test]
    fn a_request_from_its_own_address_passes() {
        let (relay_id, raw) = descriptor(1, roles::CHAIN, pin_host(&[9; 32]));
        let text = request(&relay_id, &raw, &[]);

        let accepted = check_join(&text, caller()).unwrap();
        assert_eq!(accepted.relay_id, relay_id);
        assert!(accepted.text.starts_with(BEGIN) && accepted.text.ends_with("-----\n"));

        // An address that the table does not hold has no system to compare.
        let unknown = Caller {
            origin: None,
            ..caller()
        };
        assert!(check_join(&text, unknown).is_ok());
    }

    #[test]
    fn a_request_from_another_address_or_system_is_refused() {
        let (relay_id, raw) = descriptor(1, roles::CHAIN, pin_host(&[9; 32]));
        let text = request(&relay_id, &raw, &[]);

        let elsewhere = Caller {
            address: Ipv4Addr::new(203, 0, 113, 1),
            ..caller()
        };
        assert!(check_join(&text, elsewhere)
            .unwrap_err()
            .contains("another address"));

        let other_system = Caller {
            origin: Some(Origin {
                asn: 64501,
                country: None,
            }),
            ..caller()
        };
        assert!(check_join(&text, other_system)
            .unwrap_err()
            .contains("another autonomous system"));
    }

    #[test]
    fn a_request_that_differs_from_its_descriptor_is_refused() {
        let (relay_id, raw) = descriptor(1, roles::CHAIN, pin_host(&[9; 32]));

        for change in [
            ("class", "1"),
            ("asn", "64501"),
            ("country", "FR"),
            ("public", ",198.51.100.7,9444"),
            ("public", "relay.example.org,198.51.100.7,9443"),
            ("role", "exit"),
            ("role", "entry"),
        ] {
            let text = request(&relay_id, &raw, &[change]);
            assert!(check_join(&text, caller()).is_err(), "{change:?}");
        }

        let own = request(&relay_id, &raw, &[("operator", "umbra-project")]);
        assert!(check_join(&own, caller())
            .unwrap_err()
            .contains("operator of the network"));
    }

    #[test]
    fn a_changed_descriptor_and_a_bad_text_are_refused() {
        let (relay_id, mut raw) = descriptor(1, roles::CHAIN, pin_host(&[9; 32]));
        let good = request(&relay_id, &raw, &[]);

        raw[2040] ^= 1;
        let text = request(&relay_id, &raw, &[]);
        assert!(check_join(&text, caller())
            .unwrap_err()
            .contains("does not verify"));

        assert!(check_join("no request", caller()).is_err());
        assert!(check_join(&good.replace("name=", "name=\u{1b}[2J"), caller()).is_err());
        assert!(check_join(
            &good.replace("role=middle", "role=middle\nrole=exit"),
            caller()
        )
        .is_err());
        assert!(check_join(&format!("{good}{}", " ".repeat(REQUEST_MAX)), caller()).is_err());
    }

    #[test]
    fn a_head_reads_and_a_bad_one_does_not() {
        let bytes =
            b"POST /.well-known/umbra/join HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\nX-Real-IP: 198.51.100.7\r\n\r\nbody";
        let end = head_end(bytes).unwrap();
        let head = parse_head(&bytes[..end]).unwrap();

        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/.well-known/umbra/join");
        assert_eq!(head.content_length, 12);
        assert_eq!(head.real_ip, Some(ADDRESS));
        assert_eq!(&bytes[end..], b"body");

        assert_eq!(head_end(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(parse_head(b"GET /\r\n\r\n"), None);
        let ipv6 = parse_head(b"GET / HTTP/1.1\r\nX-Real-IP: ::1\r\n\r\n").unwrap();
        assert_eq!(ipv6.real_ip, None);
        assert_eq!(
            parse_head(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            None
        );
    }

    #[test]
    fn the_limiter_counts_each_address_in_its_window() {
        let mut limiter = Limiter::new(600, 2);
        let other = Ipv4Addr::new(203, 0, 113, 1);

        assert!(limiter.pass(ADDRESS, 1_000));
        assert!(limiter.pass(ADDRESS, 1_001));
        assert!(!limiter.pass(ADDRESS, 1_002));
        assert!(limiter.pass(other, 1_002));

        assert!(!limiter.pass(ADDRESS, 1_599));
        assert!(limiter.pass(ADDRESS, 1_600));
    }
}
