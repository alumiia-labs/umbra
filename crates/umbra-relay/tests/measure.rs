//! The measurer against one relay server on loopback: the class test of
//! Part 10 §10.3 over real sockets, with a short slot.

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{collections::BTreeMap, time::Duration};

use tokio::net::{TcpListener, TcpSocket};
use umbra_core::directory::{
    authority::keyset_bytes,
    measure::{issue_cert, MeasurerTrust},
    EPOCH_SECONDS,
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    secret::Secret,
    sign::SigningKey,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_relay::{
    measurer::{measure, MeasureError, Plan, Target},
    node::{Config, RelayNode},
    server::{run_relay, tls_acceptor, Carried, OsRng, PACING_MEAN_MS},
    store::MemoryStore,
};
use umbra_transport::{native, Dial};

const CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/ca.pem"
);
const LEAF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/leaf.pem"
);
const LEAF_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/leaf.key"
);

fn seeded(seed: u8) -> SigningKey {
    SigningKey::from_seed(Secret::new([seed; 32]))
}

fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / EPOCH_SECONDS
}

/// Starts a relay of `layer` that holds the key set of `authorities` and
/// the list `revoked`, and returns where to measure it.
async fn relay(layer: u8, authorities: &[SigningKey], revoked: &[[u8; 16]]) -> Target {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    relay_at(listener, layer, authorities, revoked)
}

/// A listener whose connections hold `bytes` of a peer before the relay
/// reads them. No write of a measurer then waits in a short slot, as on a
/// path with large buffers.
fn wide_listener(bytes: u32) -> TcpListener {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(bytes).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.listen(64).unwrap()
}

/// [`relay`] on `listener`.
fn relay_at(
    listener: TcpListener,
    layer: u8,
    authorities: &[SigningKey],
    revoked: &[[u8; 16]],
) -> Target {
    let static_secret = StaticSecret::from([layer; 32]);
    let held = RelayStatic {
        s: *XPublic::from(&static_secret).as_bytes(),
        relay_id: [0x10 + layer; 32],
    };
    let target = Target {
        relay_id: held.relay_id,
        ntor_pk: held.s,
        layer,
        dial: Dial {
            host: "localhost".to_owned(),
            addr_v4: Some([127, 0, 0, 1]),
            addr_v6: None,
            port: 0,
        },
        asn: 1,
        addr_v4: [127, 0, 0, 1],
        addr_v6: [0; 16],
        family_id: [0; 32],
        capacity_class: 3,
    };
    let mut node = RelayNode::new(Config {
        relay: held,
        static_secret,
        layer,
        chunk_capacity: 0,
    });
    node.set_measurer_trust(MeasurerTrust {
        keyset: keyset_bytes(authorities, 1).unwrap(),
        revoked: revoked.to_vec(),
    });
    // A relay of layer 2 or 3 that holds a relay set takes a build of a
    // link with no hello as a measurement candidate alone (`NET-353`).
    if layer > 1 {
        node.set_relay_identities([([0x99; 32], vec![0u8; 4])].into());
        node.set_previous_layer([[0x99; 32]].into());
    }
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(run_relay(
        node,
        listener,
        tls_acceptor(LEAF, LEAF_KEY).unwrap(),
        BTreeMap::new(),
        BTreeMap::new(),
        native::tls_config_with_root_file(CA).unwrap(),
        PACING_MEAN_MS,
        Box::new(MemoryStore::default()),
        Carried::default(),
    ));
    Target {
        dial: Dial {
            port,
            ..target.dial.clone()
        },
        ..target
    }
}

fn cert(authorities: &[SigningKey], key: &SigningKey, measurer_id: [u8; 16]) -> Vec<u8> {
    issue_cert(
        measurer_id,
        &key.verifying_key().to_bytes(),
        epoch_now(),
        2,
        &[(2, &authorities[2]), (5, &authorities[5])],
        &mut OsRng,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_passes_a_class_that_the_loopback_holds_and_fails_one_far_above_it() {
    let authorities: Vec<SigningKey> = (0..7u8).map(|index| seeded(0x60 + index)).collect();
    let key = seeded(0x70);
    let cert = cert(&authorities, &key, [0x4D; 16]);
    let tls = native::tls_config_with_root_file(CA).unwrap();
    for layer in [1u8, 3] {
        let target = relay(layer, &authorities, &[]).await;
        // The C0 test at one part in 100: 2.25 Mbit/s of cells for 2 s, and
        // the relay passes at 1 Mbit/s of echoes.
        let low = Plan::of(0, Duration::from_secs(2), 2, 100).unwrap();
        let outcome = measure(&target, &cert, &key, low, tls.clone())
            .await
            .unwrap();
        assert!(outcome.passed, "{outcome:?}");
        // Each cell of the slot came back but those in flight at its end.
        assert!(outcome.echoed <= outcome.sent, "{outcome:?}");
        assert!(outcome.echoed * 10 >= outcome.sent * 9, "{outcome:?}");
        // The C3 test at its full rate: 2 250 Mbit/s of cells, which a
        // test build on loopback does not carry, and a pass at 1 000 Mbit/s
        // of echoes. The measurer and the relay stay inside their bounds,
        // and the relay fails.
        let high = Plan::of(3, Duration::from_secs(1), 4, 1).unwrap();
        let outcome = measure(&target, &cert, &key, high, tls.clone())
            .await
            .unwrap();
        assert!(!outcome.passed, "{outcome:?}");
        assert!(outcome.echoed > 0, "{outcome:?}");
        // The session of the first test ended with its circuits, thus the
        // relay opened the second one. A third one opens after both.
        let outcome = measure(&target, &cert, &key, low, tls.clone())
            .await
            .unwrap();
        assert!(outcome.passed, "{outcome:?}");
    }
}

/// One thread runs the measurer and the relay, thus the result does not
/// change with the cores of the machine.
#[tokio::test]
async fn a_measurer_behind_its_rate_reads_the_echoes_of_its_slot() {
    let authorities: Vec<SigningKey> = (0..7u8).map(|index| seeded(0x60 + index)).collect();
    let key = seeded(0x70);
    let cert = cert(&authorities, &key, [0x4D; 16]);
    let tls = native::tls_config_with_root_file(CA).unwrap();
    let target = relay_at(wide_listener(8 << 20), 1, &authorities, &[]);
    // The C3 test at its full rate, which a test build does not send: the
    // measurer holds a batch ready at each turn of the slot, and no write
    // waits. The echoes that the relay sent in the slot count.
    let high = Plan::of(3, Duration::from_secs(1), 4, 1).unwrap();
    let outcome = measure(&target, &cert, &key, high, tls.clone())
        .await
        .unwrap();
    assert!(!outcome.passed, "{outcome:?}");
    assert!(outcome.echoed > 0, "{outcome:?}");
    // One echo for each batch of 128 cells is the count of a measurer that
    // reads between its batches alone.
    assert!(outcome.echoed * 32 >= outcome.sent, "{outcome:?}");
    // The relay takes the next session after that one (`REL-202`).
    let low = Plan::of(0, Duration::from_secs(1), 2, 100).unwrap();
    let outcome = measure(&target, &cert, &key, low, tls).await.unwrap();
    assert!(outcome.passed, "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_that_opens_no_session_gives_no_result() {
    let authorities: Vec<SigningKey> = (0..7u8).map(|index| seeded(0x60 + index)).collect();
    let key = seeded(0x70);
    let cert = cert(&authorities, &key, [0x4D; 16]);
    let tls = native::tls_config_with_root_file(CA).unwrap();
    let plan = Plan::of(0, Duration::from_secs(1), 2, 100).unwrap();
    // REL-104: the root of the relay revoked the measurer. The relay gives
    // no sign, and the measurer writes no result for a relay that it did
    // not measure.
    let target = relay(3, &authorities, &[[0x4D; 16]]).await;
    assert_eq!(
        measure(&target, &cert, &key, plan, tls.clone()).await,
        Err(MeasureError::NoSession)
    );
    // The key of another measurer under this certificate.
    let target = relay(1, &authorities, &[]).await;
    assert_eq!(
        measure(&target, &cert, &seeded(0x71), plan, tls).await,
        Err(MeasureError::NoSession)
    );
}

/// A measurement of this machine, and no test of the protocol: the C0 test
/// and the C1 test at their full rate, for 5 seconds, against a relay of
/// layer 3 on loopback. Run it in a release build:
///
/// ```text
/// cargo test -p umbra-relay --features native --release --test measure -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a measurement of the machine, which a debug build fails"]
async fn the_full_rate_of_a_class_test_on_loopback() {
    let authorities: Vec<SigningKey> = (0..7u8).map(|index| seeded(0x60 + index)).collect();
    let key = seeded(0x70);
    let cert = cert(&authorities, &key, [0x4D; 16]);
    let tls = native::tls_config_with_root_file(CA).unwrap();
    let target = relay(3, &authorities, &[]).await;
    for class in [0u8, 1] {
        let plan = Plan::of(class, Duration::from_secs(5), 4, 1).unwrap();
        let outcome = measure(&target, &cert, &key, plan, tls.clone())
            .await
            .unwrap();
        println!(
            "class C{class}: sent {} cells, echoed {} cells, {} Mbit/s of echoes, passed={}",
            outcome.sent,
            outcome.echoed,
            outcome.echoed_bits / 1_000_000,
            outcome.passed
        );
    }
}
