//! The connection limits of a relay (Part 3 `NET-333` to `NET-335`): a
//! relay at its cap closes a new connection at once, and it closes a peer
//! that sends no handshake in time at the deadline.

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use umbra_relay::server::{accept_loop, tls_acceptor, Carried, ConnectionLimits};
use umbra_transport::{native, Dial};

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

#[tokio::test]
async fn a_set_of_silent_sockets_holds_no_handshake_back() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (node, _inputs) = mpsc::channel(8);

    let manifest = vec![0x4D; 96];
    let carried = Arc::new(Carried {
        manifest: std::sync::Mutex::new(Some(manifest.clone())),
        limits: ConnectionLimits {
            handshakes_max: 1,
            handshake_timeout: Duration::from_secs(60),
            first_bytes_timeout: Duration::from_secs(30),
            ..ConnectionLimits::default()
        },
        ..Carried::default()
    });

    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    tokio::spawn(accept_loop(listener, tls, node, carried));

    // NET-335: before this, each accepted socket took a place among the
    // handshakes for the whole deadline, and the relay dropped a socket
    // above the bound. One silent socket then held the one place of this
    // relay.
    let mut silent = Vec::new();
    for _ in 0..4 {
        silent.push(TcpStream::connect(address).await.unwrap());
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let dial = Dial {
        host: "localhost".to_owned(),
        addr_v4: Some([127, 0, 0, 1]),
        addr_v6: None,
        port: address.port(),
    };

    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    // The handshake ends long before the first silent socket does, thus it
    // waited for none of them. The bound is one of the test and not of the
    // relay: a machine under load takes its time for a handshake.
    let fetched = tokio::time::timeout(
        Duration::from_secs(20),
        native::fetch_manifest(&dial, trust),
    )
    .await
    .expect("a handshake with no wait for the silent sockets")
    .unwrap();

    assert_eq!(fetched, manifest);

    for stream in &mut silent {
        assert!(!closes(stream, Duration::from_millis(50)).await);
    }
}

#[tokio::test]
async fn a_socket_that_sent_no_whole_hello_takes_no_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (node, _inputs) = mpsc::channel(8);

    let manifest = vec![0x4D; 96];
    let carried = Arc::new(Carried {
        manifest: std::sync::Mutex::new(Some(manifest.clone())),
        limits: ConnectionLimits {
            handshakes_max: 1,
            handshake_timeout: Duration::from_secs(60),
            first_bytes_timeout: Duration::from_secs(20),
            ..ConnectionLimits::default()
        },
        ..Carried::default()
    });

    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    tokio::spawn(accept_loop(listener, tls, node, carried));

    // NET-335: before this, the first byte of a connection took a place
    // among the handshakes until RELAY_HANDSHAKE_TIMEOUT. Each of these
    // sends the start of a TLS record and no whole `ClientHello`. One of
    // them then held the one place of this relay.
    let mut stalled = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01])
            .await
            .unwrap();
        stalled.push(stream);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let dial = Dial {
        host: "localhost".to_owned(),
        addr_v4: Some([127, 0, 0, 1]),
        addr_v6: None,
        port: address.port(),
    };

    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    let fetched = tokio::time::timeout(
        Duration::from_secs(15),
        native::fetch_manifest(&dial, trust),
    )
    .await
    .expect("a handshake with no wait for the stalled sockets")
    .unwrap();

    assert_eq!(fetched, manifest);
}

#[tokio::test]
async fn a_socket_with_no_whole_hello_ends_at_the_first_bytes_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (node, _inputs) = mpsc::channel(8);

    let carried = Arc::new(Carried {
        limits: ConnectionLimits {
            handshake_timeout: Duration::from_secs(60),
            first_bytes_timeout: Duration::from_secs(1),
            ..ConnectionLimits::default()
        },
        ..Carried::default()
    });

    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    tokio::spawn(accept_loop(listener, tls, node, carried));

    // A socket that sent nothing and one that sent a part of a hello both
    // end at RELAY_FIRST_BYTES_TIMEOUT, long before the deadline of a
    // handshake.
    let mut silent = TcpStream::connect(address).await.unwrap();
    let mut partial = TcpStream::connect(address).await.unwrap();
    partial.write_all(&[0x16, 0x03, 0x01]).await.unwrap();

    assert!(closes(&mut silent, Duration::from_secs(20)).await);
    assert!(closes(&mut partial, Duration::from_secs(20)).await);
}

#[tokio::test]
async fn one_address_holds_its_connections_and_the_address_of_a_relay_holds_more_for_a_time() {
    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    let limits = ConnectionLimits {
        per_ip_max: 2,
        handshake_timeout: Duration::from_secs(1),
        // The caps count the one address of this machine.
        loopback_exempt: false,
        ..ConnectionLimits::default()
    };

    // NET-334: the third connection of one address closes at once. No test
    // reached this cap before: each one runs on the loopback address,
    // which the cap did not count.
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (node, _inputs) = mpsc::channel(8);
        let carried = Arc::new(Carried {
            limits,
            ..Carried::default()
        });
        let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
        tokio::spawn(accept_loop(listener, tls, node, carried));

        let mut first = TcpStream::connect(address).await.unwrap();
        let _second = TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut third = TcpStream::connect(address).await.unwrap();
        assert!(closes(&mut third, Duration::from_millis(500)).await);

        // A place that its connection gave back serves the next one.
        assert!(closes(&mut first, Duration::from_secs(10)).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut fourth = TcpStream::connect(address).await.unwrap();
        assert!(!closes(&mut fourth, Duration::from_millis(300)).await);
    }

    // The address of a relay of the set holds `RELAY_PEER_PART` times as
    // many, for the pushes of that relay.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (node, mut inputs) = mpsc::channel(64);

    // A handshake of a machine under load takes its time.
    let limits = ConnectionLimits {
        handshake_timeout: Duration::from_secs(5),
        ..limits
    };

    let carried = Arc::new(Carried {
        limits,
        relay_addresses: std::sync::Mutex::new([address.ip()].into()),
        ..Carried::default()
    });

    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    tokio::spawn(accept_loop(listener, tls, node, carried));

    // The node of this test holds each link open: it keeps what the link
    // sent it, the writer of the link among it.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(input) = inputs.recv().await {
            held.push(input);
        }
    });

    let dial = Dial {
        host: "localhost".to_owned(),
        addr_v4: Some([127, 0, 0, 1]),
        addr_v6: None,
        port: address.port(),
    };

    let connect = || {
        let plan = umbra_transport::race::Plan::Only(umbra_transport::race::Wire::Tcp);
        native::connect(
            &dial,
            trust.clone(),
            plan,
            [7; 16],
            [1; 4],
            Duration::from_secs(20),
        )
    };

    // Three links upgrade: more than the two of another address.
    let mut links = Vec::new();
    for _ in 0..3 {
        links.push(connect().await.unwrap());
    }

    let held = 2 * ConnectionLimits::PEER_PART;
    let mut silent = Vec::new();
    for _ in 3..held {
        silent.push(TcpStream::connect(address).await.unwrap());
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut above = TcpStream::connect(address).await.unwrap();
    assert!(closes(&mut above, Duration::from_millis(500)).await);

    // NET-334: a link that lives on past the time of the `Open` and the
    // hello takes a place of its address, as each other connection does.
    // Two of the three find one, and the third closes. Before this, each
    // connection of such an address stayed outside each cap forever.
    tokio::time::sleep(Duration::from_secs(16)).await;
    let mut open = 0;
    for link in &mut links {
        let read = tokio::time::timeout(Duration::from_millis(500), link.recv()).await;

        if read.is_err() {
            open += 1;
        }
    }

    assert_eq!(open, 2);
}
