//! The connection limits of a relay (Part 3 `NET-333` to `NET-335`): a
//! relay at its cap closes a new connection at once, and a peer that sends
//! no handshake in time is closed at the deadline.
#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{sync::Arc, time::Duration};

use tokio::{io::AsyncReadExt, net::TcpListener, net::TcpStream, sync::mpsc};
use umbra_relay::server::{accept_loop, tls_acceptor, Carried, ConnectionLimits};

fn fixture(name: &str) -> String {
    format!(
        "{}/../../tests/fixtures/tls/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Whether the relay closes `stream` inside `within`.
async fn closes(stream: &mut TcpStream, within: Duration) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(within, stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn a_relay_at_its_cap_closes_a_new_connection_and_a_silent_one_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (node, _inputs) = mpsc::channel(8);
    let carried = Arc::new(Carried {
        limits: ConnectionLimits {
            max_connections: 2,
            handshake_timeout: Duration::from_secs(1),
            ..ConnectionLimits::default()
        },
        ..Carried::default()
    });
    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    tokio::spawn(accept_loop(listener, tls, node, carried));

    let mut first = TcpStream::connect(address).await.unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // NET-333: the third connection goes above the cap of two.
    let mut third = TcpStream::connect(address).await.unwrap();
    assert!(closes(&mut third, Duration::from_millis(500)).await);
    // NET-335: the two that sent no TLS hello end at the deadline, and
    // each one gives its place back.
    assert!(closes(&mut first, Duration::from_secs(3)).await);
    assert!(closes(&mut second, Duration::from_secs(3)).await);
    let mut fourth = TcpStream::connect(address).await.unwrap();
    assert!(!closes(&mut fourth, Duration::from_millis(300)).await);
}
