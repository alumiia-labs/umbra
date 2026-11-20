//! The intake of [`crate::intake`] on a socket: four requests over plain
//! HTTP. A proxy on the same machine holds the TLS of the public side and
//! states the address of each client in `X-Real-IP`.
//!
//! ```text
//! GET  /.well-known/umbra/whoami           the address and its origin
//! GET  /.well-known/umbra/reach/<port>     a connect to that port of the caller
//! POST /.well-known/umbra/join             a join request for the inbox
//! GET  /.well-known/umbra/join/<relay_id>  whether the inbox holds a request
//! ```
//!
//! Each answer is text with one `name=value` pair on each line.
//!
//! The inbox holds `<relay_id>.request` for each request that waits. The
//! owner moves a request out when it admits the relay. A file
//! `<relay_id>.refused` in the inbox says that the owner refused the relay,
//! and the intake then takes no request of that relay.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError, RwLock},
    time::{Duration, SystemTime},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use umbra_crypto::hex;

use crate::{
    clock::unix_now,
    intake::{
        answer, check_join, head_end, parse_head, AsTable, Caller, Head, Limiter, HEAD_MAX,
        INBOX_MAX, REQUEST_MAX,
    },
};

/// The time that one request has, from its first byte to its answer.
const REQUEST_TIME: Duration = Duration::from_secs(15);
/// The time that the connect of a reach test has.
const REACH_TIME: Duration = Duration::from_secs(5);
/// The requests that the intake serves at one time.
const CONNECTIONS: usize = 64;
/// The period between two looks at the file of the table.
const TABLE_PERIOD: Duration = Duration::from_secs(600);

const PREFIX: &str = "/.well-known/umbra/";

/// The settings of an intake.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The directory that takes each checked join request.
    pub inbox: PathBuf,
    /// The file of the AS table, when the intake has one.
    pub as_table: Option<PathBuf>,
    /// The name of the operator of the network.
    pub own_operator: Option<String>,
    /// Whether a proxy on this machine states the address of each client.
    pub behind_proxy: bool,
}

struct Limits {
    whoami: Limiter,
    reach: Limiter,
    join: Limiter,
}

/// The state of a running intake.
pub struct Intake {
    settings: Settings,
    table: RwLock<(Option<SystemTime>, Arc<AsTable>)>,
    limits: Mutex<Limits>,
}

impl Intake {
    /// An intake with the table of its settings, when the file reads.
    pub fn new(settings: Settings) -> Self {
        let intake = Self {
            settings,
            table: RwLock::new((None, Arc::new(AsTable::default()))),
            limits: Mutex::new(Limits {
                whoami: Limiter::new(600, 60),
                reach: Limiter::new(600, 10),
                join: Limiter::new(3_600, 6),
            }),
        };
        intake.refresh_table();

        intake
    }

    /// Reads the file of the table again when it changed. A file that does
    /// not read leaves the old table in its place.
    pub fn refresh_table(&self) {
        let Some(path) = &self.settings.as_table else {
            return;
        };
        let Ok(modified) = std::fs::metadata(path).and_then(|file| file.modified()) else {
            return;
        };
        let held = self.table.read().unwrap_or_else(PoisonError::into_inner).0;
        if held == Some(modified) {
            return;
        }

        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let table = AsTable::parse(&text);
        // An empty file is a failed download, and not a world with no system.
        if table.is_empty() {
            return;
        }

        eprintln!(
            "umbra-intake: the table holds {} address ranges",
            table.len()
        );
        *self.table.write().unwrap_or_else(PoisonError::into_inner) =
            (Some(modified), Arc::new(table));
    }

    fn table(&self) -> Arc<AsTable> {
        Arc::clone(&self.table.read().unwrap_or_else(PoisonError::into_inner).1)
    }

    fn pass(&self, pick: impl FnOnce(&mut Limits) -> &mut Limiter, address: Ipv4Addr) -> bool {
        let mut limits = self.limits.lock().unwrap_or_else(PoisonError::into_inner);
        pick(&mut limits).pass(address, unix_now())
    }

    fn request_path(&self, relay_id: &[u8; 32]) -> PathBuf {
        self.settings
            .inbox
            .join(format!("{}.request", hex::write(relay_id)))
    }
}

/// The address that a request came from, or none when the intake cannot
/// know it.
fn caller_of(intake: &Intake, peer: SocketAddr, head: &Head) -> Option<Ipv4Addr> {
    if intake.settings.behind_proxy {
        // A header from another machine states what its sender wants.
        return peer.ip().is_loopback().then_some(head.real_ip).flatten();
    }

    match peer.ip() {
        IpAddr::V4(address) => Some(address),
        IpAddr::V6(address) => address.to_ipv4_mapped(),
    }
}

fn whoami(intake: &Intake, caller: Ipv4Addr) -> Vec<u8> {
    let mut body = format!("address={caller}\n");

    if let Some(origin) = intake.table().lookup(caller) {
        body.push_str(&format!("asn={}\n", origin.asn));
        if let Some(country) = origin
            .country
            .as_ref()
            .and_then(|c| core::str::from_utf8(c).ok())
        {
            body.push_str(&format!("country={country}\n"));
        }
    }

    answer(200, &body)
}

async fn reach(intake: &Intake, caller: Ipv4Addr, port: &str) -> Vec<u8> {
    let Some(port) = port.parse::<u16>().ok().filter(|port| *port != 0) else {
        return answer(400, "refused=the port is a number from 1 to 65535\n");
    };
    // The proxy states public addresses. The intake dials no machine of
    // its own network for a caller.
    let is_inside = caller.is_loopback() || caller.is_private() || caller.is_link_local();
    if intake.settings.behind_proxy && is_inside {
        return answer(400, "refused=the address is not public\n");
    }

    let connect = TcpStream::connect(SocketAddr::from((caller, port)));
    let state = match timeout(REACH_TIME, connect).await {
        Ok(Ok(_)) => "open",
        Ok(Err(_)) | Err(_) => "closed",
    };

    answer(
        200,
        &format!("address={caller}\nport={port}\nreach={state}\n"),
    )
}

/// The count of the requests in the inbox.
fn inbox_count(inbox: &Path) -> usize {
    std::fs::read_dir(inbox).map_or(usize::MAX, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|end| end == "request"))
            .count()
    })
}

fn join(intake: &Intake, caller: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let Ok(text) = core::str::from_utf8(body) else {
        return answer(400, "refused=the request is not text\n");
    };
    let against = Caller {
        address: caller,
        origin: intake.table().lookup(caller),
        own_operator: intake.settings.own_operator.as_deref(),
    };
    let accepted = match check_join(text, against) {
        Ok(accepted) => accepted,
        Err(cause) => return answer(400, &format!("refused={cause}\n")),
    };

    // A newer request of a relay takes the place of its older one.
    let path = intake.request_path(&accepted.relay_id);
    if path.with_extension("refused").exists() {
        return answer(
            403,
            "refused=the owner of the network refused this relay
",
        );
    }
    if !path.exists() && inbox_count(&intake.settings.inbox) >= INBOX_MAX {
        return answer(503, "refused=the inbox is full, try again in some days\n");
    }

    let part = path.with_extension("part");
    let written = std::fs::write(&part, accepted.text.as_bytes())
        .and_then(|()| std::fs::rename(&part, &path));
    if written.is_err() {
        return answer(503, "refused=the intake cannot write to its inbox\n");
    }

    answer(200, "state=received\n")
}

fn join_state(intake: &Intake, relay_id: &str) -> Vec<u8> {
    let Some(relay_id) = hex::read_array::<32>(relay_id) else {
        return answer(400, "refused=the relay_id is 64 hex characters\n");
    };

    let path = intake.request_path(&relay_id);
    let state = if path.with_extension("refused").exists() {
        "refused"
    } else if path.exists() {
        "received"
    } else {
        "unknown"
    };
    answer(200, &format!("state={state}\n"))
}

/// Reads the head of a request, and the first bytes of its body.
async fn read_head(stream: &mut TcpStream) -> Option<(Head, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(1024);
    let mut block = [0u8; 1024];

    loop {
        if let Some(end) = head_end(&bytes) {
            let body = bytes.split_off(end);
            return parse_head(&bytes).map(|head| (head, body));
        }
        if bytes.len() > HEAD_MAX {
            return None;
        }

        let count = stream.read(&mut block).await.ok()?;
        if count == 0 {
            return None;
        }
        bytes.extend_from_slice(block.get(..count)?);
    }
}

async fn answer_to(intake: &Intake, stream: &mut TcpStream, peer: SocketAddr) -> Vec<u8> {
    let Some((head, mut body)) = read_head(stream).await else {
        return answer(400, "refused=the request does not read\n");
    };
    let Some(caller) = caller_of(intake, peer, &head) else {
        return answer(400, "refused=a relay needs an IPv4 address\n");
    };
    let Some(path) = head.path.strip_prefix(PREFIX) else {
        return answer(404, "refused=no such path\n");
    };
    let limited = || answer(429, "refused=too many requests from this address\n");

    match (head.method.as_str(), path) {
        ("GET", "whoami") => {
            if !intake.pass(|limits| &mut limits.whoami, caller) {
                return limited();
            }
            whoami(intake, caller)
        }
        ("POST", "join") => {
            if head.content_length > REQUEST_MAX {
                return answer(413, "refused=the request is too long\n");
            }
            if !intake.pass(|limits| &mut limits.join, caller) {
                return limited();
            }

            body.truncate(head.content_length);
            let mut rest = vec![0u8; head.content_length.saturating_sub(body.len())];
            if stream.read_exact(&mut rest).await.is_err() {
                return answer(400, "refused=the request ends before its length\n");
            }
            body.extend_from_slice(&rest);

            join(intake, caller, &body)
        }
        ("GET", _) => {
            if let Some(port) = path.strip_prefix("reach/") {
                if !intake.pass(|limits| &mut limits.reach, caller) {
                    return limited();
                }
                return reach(intake, caller, port).await;
            }
            if let Some(relay_id) = path.strip_prefix("join/") {
                if !intake.pass(|limits| &mut limits.whoami, caller) {
                    return limited();
                }
                return join_state(intake, relay_id);
            }
            answer(404, "refused=no such path\n")
        }
        _ => answer(405, "refused=no such method\n"),
    }
}

/// Serves the requests of `listener` until the process ends.
pub async fn serve(listener: TcpListener, intake: Arc<Intake>) {
    let slots = Arc::new(Semaphore::new(CONNECTIONS));

    let watcher = Arc::clone(&intake);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TABLE_PERIOD).await;
            watcher.refresh_table();
        }
    });

    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        // A request above the bound gets no answer: the proxy gives 502.
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };

        let intake = Arc::clone(&intake);
        tokio::spawn(async move {
            let _slot = slot;
            let work = async {
                let bytes = answer_to(&intake, &mut stream, peer).await;
                let _ = stream.write_all(&bytes).await;
                let _ = stream.shutdown().await;
            };
            let _ = timeout(REQUEST_TIME, work).await;
        });
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::intake::tests::{descriptor, request, ADDRESS};
    use umbra_core::directory::descriptor::{pin_host, roles};

    /// A running intake with an empty inbox, and its address.
    async fn intake(name: &str, behind_proxy: bool) -> (SocketAddr, PathBuf) {
        let root = std::env::temp_dir().join(format!("umbra-intake-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let inbox = root.join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let table = root.join("table.tsv");
        std::fs::write(&table, "198.51.100.0\t198.51.100.255\t64500\tDE\tEXAMPLE\n").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let settings = Settings {
            inbox: inbox.clone(),
            as_table: Some(table),
            own_operator: Some("umbra-project".to_owned()),
            behind_proxy,
        };
        tokio::spawn(serve(listener, Arc::new(Intake::new(settings))));

        (address, inbox)
    }

    /// The status and the body of the answer to one request.
    async fn ask(
        to: SocketAddr,
        method: &str,
        path: &str,
        real_ip: &str,
        body: &str,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(to).await.unwrap();
        let header = if real_ip.is_empty() {
            String::new()
        } else {
            format!("X-Real-IP: {real_ip}\r\n")
        };
        let text = format!(
            "{method} /.well-known/umbra/{path} HTTP/1.1\r\nHost: signer\r\n{header}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(text.as_bytes()).await.unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let status = text[9..12].parse().unwrap();
        let body = text.split_once("\r\n\r\n").unwrap().1.to_owned();

        (status, body)
    }

    #[tokio::test]
    async fn the_proxy_states_the_caller_and_the_table_its_system() {
        let (to, _) = intake("whoami", true).await;

        let (status, body) = ask(to, "GET", "whoami", "198.51.100.7", "").await;
        assert_eq!(status, 200);
        assert_eq!(body, "address=198.51.100.7\nasn=64500\ncountry=DE\n");

        let (_, body) = ask(to, "GET", "whoami", "203.0.113.9", "").await;
        assert_eq!(body, "address=203.0.113.9\n");

        // No header: the intake does not know the client.
        assert_eq!(ask(to, "GET", "whoami", "", "").await.0, 400);
        assert_eq!(ask(to, "GET", "other", "198.51.100.7", "").await.0, 404);
        assert_eq!(ask(to, "GET", "whoami", "2001:db8::1", "").await.0, 400);
        assert_eq!(ask(to, "GET", "reach/9443", "192.168.1.5", "").await.0, 400);
        assert_eq!(ask(to, "PUT", "whoami", "198.51.100.7", "").await.0, 405);
    }

    #[tokio::test]
    async fn a_join_request_goes_to_the_inbox_from_its_own_address_alone() {
        let (to, inbox) = intake("join", true).await;
        let (relay_id, raw) = descriptor(1, roles::CHAIN, pin_host(&[9; 32]));
        let text = request(&relay_id, &raw, &[]);
        let id = hex::write(&relay_id);
        let state = format!("join/{id}");

        assert_eq!(
            ask(to, "GET", &state, "198.51.100.7", "").await.1,
            "state=unknown\n"
        );

        let (status, body) = ask(to, "POST", "join", "203.0.113.9", &text).await;
        assert_eq!(status, 400);
        assert!(body.contains("another address"), "{body}");
        assert_eq!(inbox_count(&inbox), 0);

        let (status, body) = ask(to, "POST", "join", &ADDRESS.to_string(), &text).await;
        assert_eq!((status, body.as_str()), (200, "state=received\n"));
        let held = std::fs::read_to_string(inbox.join(format!("{id}.request"))).unwrap();
        assert!(held.contains("operator=alice") && held.contains(&id));
        assert_eq!(inbox_count(&inbox), 1);

        // The same relay again takes the same place.
        assert_eq!(ask(to, "POST", "join", "198.51.100.7", &text).await.0, 200);
        assert_eq!(inbox_count(&inbox), 1);
        assert_eq!(
            ask(to, "GET", &state, "198.51.100.7", "").await.1,
            "state=received\n"
        );

        // The owner refuses the relay: its request leaves, and none comes back.
        std::fs::remove_file(inbox.join(format!("{id}.request"))).unwrap();
        std::fs::write(inbox.join(format!("{id}.refused")), "").unwrap();
        assert_eq!(ask(to, "POST", "join", "198.51.100.7", &text).await.0, 403);
        assert_eq!(
            ask(to, "GET", &state, "198.51.100.7", "").await.1,
            "state=refused
"
        );
        assert_eq!(inbox_count(&inbox), 0);

        let long = "x".repeat(REQUEST_MAX + 1);
        assert_eq!(ask(to, "POST", "join", "198.51.100.7", &long).await.0, 413);
    }

    #[tokio::test]
    async fn the_join_limit_of_an_address_holds() {
        let (to, _) = intake("limit", true).await;

        for _ in 0..6 {
            assert_eq!(ask(to, "POST", "join", "198.51.100.7", "x").await.0, 400);
        }
        assert_eq!(ask(to, "POST", "join", "198.51.100.7", "x").await.0, 429);
        assert_eq!(ask(to, "POST", "join", "198.51.100.8", "x").await.0, 400);
    }

    #[tokio::test]
    async fn the_reach_test_dials_the_port_of_the_caller() {
        let (to, _) = intake("reach", false).await;

        let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = open.local_addr().unwrap().port();
        let (status, body) = ask(to, "GET", &format!("reach/{port}"), "", "").await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            format!("address=127.0.0.1\nport={port}\nreach=open\n")
        );

        drop(open);
        let (_, body) = ask(to, "GET", &format!("reach/{port}"), "", "").await;
        assert!(body.ends_with("reach=closed\n"), "{body}");

        assert_eq!(ask(to, "GET", "reach/0", "", "").await.0, 400);
        // With no proxy, the header states nothing.
        let (_, body) = ask(to, "GET", "whoami", "198.51.100.7", "").await;
        assert_eq!(body, "address=127.0.0.1\n");
    }
}
