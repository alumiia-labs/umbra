//! The exported surface of Part 15 §15.6.1, driven from Rust: the first
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
use umbra_ffi::bindings::{init, Config, FfiError, FfiEvent, SecureElementCallback, TextSink};

struct Keystore([u8; 32]);

impl SecureElementCallback for Keystore {
    fn keyed(&self, input: Vec<u8>) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).unwrap();
        mac.update(&input);
        mac.finalize().into_bytes().to_vec()
    }
}

#[derive(Default)]
struct View(Mutex<Vec<u16>>);

impl TextSink for View {
    fn put(&self, code_units: Vec<u16>) {
        *self.0.lock().unwrap() = code_units;
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
