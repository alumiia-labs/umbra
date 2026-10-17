//! The exported surface of Part 14 §14.6.1, driven from Rust: the first
//! launch, a draft, a send, a render, a lock, and an unlock over a SQLite
//! file.

#![cfg(feature = "bindings")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::sync::{Arc, Mutex};

use umbra_crypto::{
    hmac::{digest::KeyInit, Hmac, Mac},
    sha2::Sha256,
};
use umbra_ffi::bindings::{
    init, Config, FfiError, FfiEvent, Network, RelayEndpoint, SecureElementCallback, TextSink,
};

struct Keystore([u8; 32]);

impl SecureElementCallback for Keystore {
    fn keyed(&self, input: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).unwrap();
        mac.update(&input);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

#[derive(Default)]
struct View(Mutex<Vec<u16>>);

impl TextSink for View {
    fn put(&self, code_units: Vec<u16>) -> Result<(), FfiError> {
        *self.0.lock().unwrap() = code_units;
        Ok(())
    }
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

#[test]
fn the_surface_runs_a_first_launch_a_send_and_a_second_launch() {
    let directory = std::env::temp_dir().join(format!("umbra-surface-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("client.db");
    let _ = std::fs::remove_file(&path);
    let config = Config {
        database_path: path.to_str().unwrap().to_owned(),
        // A slow device keeps the floor cost, which keeps this test short.
        argon2_floor_ms: 60_000,
    };
    let keystore = || Arc::new(Keystore([7; 32])) as Arc<dyn SecureElementCallback>;

    // The first launch makes the store, and the client is unlocked.
    let handle = init(config.clone(), keystore(), units("correct horse")).unwrap();
    let conversation = vec![9u8; 16];
    let draft = handle.new_draft(conversation.clone()).unwrap();
    draft.set_text(units("over the surface")).unwrap();
    let message = handle.send_draft(draft.clone()).unwrap();
    assert_eq!(draft.set_text(units("again")), Err(FfiError::NotFound));
    assert!(handle.new_draft(vec![1, 2, 3]).is_err());

    let view = Arc::new(View::default());
    handle.msg_render(message.clone(), view.clone()).unwrap();
    assert_eq!(
        String::from_utf16(&view.0.lock().unwrap()).unwrap(),
        "over the surface"
    );
    assert_eq!(handle.messages(conversation.clone()).unwrap().len(), 1);

    // The auto-lock time is a stored setting with the bound of `IMP-119`.
    assert_eq!(handle.auto_lock_seconds().unwrap(), 900);
    handle.set_auto_lock(300).unwrap();
    assert_eq!(handle.set_auto_lock(1_801), Err(FfiError::TooLong));
    assert_eq!(handle.auto_lock_seconds().unwrap(), 300);

    // A passphrase change needs the current passphrase, and it keeps the
    // store key, thus each record stays (`IMP-118`).
    assert_eq!(
        handle.change_passphrase(units("wrong"), units("new passphrase")),
        Err(FfiError::WrongPassphrase)
    );
    assert_eq!(
        handle.change_passphrase(units("correct horse"), units("")),
        Err(FfiError::Malformed)
    );
    handle
        .change_passphrase(units("correct horse"), units("new passphrase"))
        .unwrap();

    handle.lock();
    assert!(matches!(handle.next_event(), Some(FfiEvent::Locked)));
    assert_eq!(
        handle.unlock(units("correct horse")),
        Err(FfiError::WrongPassphrase)
    );
    handle.unlock(units("new passphrase")).unwrap();
    assert_eq!(handle.auto_lock_seconds().unwrap(), 300);
    handle
        .change_passphrase(units("new passphrase"), units("correct horse"))
        .unwrap();
    handle.lock();
    assert!(matches!(handle.next_event(), Some(FfiEvent::Locked)));
    assert_eq!(
        handle.msg_render(message, view.clone()).err(),
        Some(FfiError::Locked)
    );
    drop(handle);

    // The second launch reads the header from the file and starts locked.
    let handle = init(config, keystore(), Vec::new()).unwrap();
    assert_eq!(
        handle.messages(conversation.clone()).err(),
        Some(FfiError::Locked)
    );
    handle.unlock(units("correct horse")).unwrap();
    let found = handle.messages(conversation).unwrap();
    assert_eq!(found.len(), 1);
    handle.msg_render(found[0].clone(), view.clone()).unwrap();
    assert_eq!(
        String::from_utf16(&view.0.lock().unwrap()).unwrap(),
        "over the surface"
    );
    drop(handle);
    let _ = std::fs::remove_dir_all(&directory);
}

const CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/tls/ca.pem"
);

/// A network of three relays whose ingress relay listens at `port`.
fn network_at(port: u16) -> Network {
    Network {
        relays: (1..=3u8)
            .map(|layer| RelayEndpoint {
                host: "localhost".into(),
                ipv4: vec![127, 0, 0, 1],
                port,
                static_key: vec![layer; 32],
                relay_id: vec![0x10 + layer; 32],
                layer,
                operator: format!("operator-{layer}"),
                family: None,
                country: format!("Z{}", char::from(b'A' + layer)),
                asn: 64_500 + u32::from(layer),
                prefix: Some(vec![10, layer]),
                holds_files: false,
                identity_pk: Vec::new(),
                roles: None,
                prefix_v6: None,
                class: None,
            })
            .collect(),
        root_ca_path: Some(CA.into()),
        invitation_host: "invite.umbra.test".into(),
        ndr_relay_url: None,
        ndr_key_config: None,
        ndr_relay_ipv4: None,
        directory_relay_url: None,
        directory_pins: None,
        directory_relay_ipv4: None,
        report_queues: Vec::new(),
        removed_links: Vec::new(),
        is_provisional: false,
    }
}

/// The link that a run dials to its ingress relay.
fn dialed(relay: &std::net::TcpListener) -> std::net::TcpStream {
    relay.set_nonblocking(true).unwrap();
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(20) {
        match relay.accept() {
            Ok((link, _)) => {
                link.set_nonblocking(false).unwrap();
                return link;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("the relay took no link: {error}"),
        }
    }
    panic!("the run did not dial its ingress relay");
}

/// Reads the link of a run until its end. The result is false when the
/// other side still holds the link after three seconds.
fn link_ended(link: &mut std::net::TcpStream) -> bool {
    use std::io::Read as _;
    link.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();

    let mut bytes = [0u8; 4_096];
    loop {
        match link.read(&mut bytes) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(error) => {
                return !matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                );
            }
        }
    }
}

#[test]
fn a_lock_stops_the_run_of_the_network_before_it_returns() {
    let directory = std::env::temp_dir().join(format!("umbra-surface-l-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("client.db");
    let _ = std::fs::remove_file(&path);
    let config = Config {
        database_path: path.to_str().unwrap().to_owned(),
        argon2_floor_ms: 60_000,
    };
    let keystore = Arc::new(Keystore([8; 32])) as Arc<dyn SecureElementCallback>;

    let handle = init(config, keystore, units("correct horse")).unwrap();

    // An ingress relay that takes the connection and answers nothing: the
    // run of the client waits in its dial, with the keys of its node.
    let relay = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = relay.local_addr().unwrap().port();
    handle.clone().connect(network_at(port)).unwrap();
    let mut link = dialed(&relay);

    // IMP-127: the lock stops the runtime itself, whatever the platform
    // calls after it. The task of the run is gone when the call returns,
    // and its link with it. The task does not wait for the end of its dial.
    let start = std::time::Instant::now();
    handle.lock();
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert!(link_ended(&mut link), "a locked client held its link");

    // The run of a locked client brings no update: the lock is the one
    // event of its end.
    let mut is_locked = false;
    while let Some(event) = handle.next_event() {
        assert!(!matches!(event, FfiEvent::Offline { .. }));
        is_locked |= matches!(event, FfiEvent::Locked);
    }
    assert!(is_locked);

    // The unlocked client starts a run again, and a disconnect ends it.
    handle.unlock(units("correct horse")).unwrap();
    handle.clone().connect(network_at(port)).unwrap();
    let mut link = dialed(&relay);
    handle.disconnect();
    assert!(link_ended(&mut link));
    drop(handle);
    let _ = std::fs::remove_dir_all(&directory);
}
