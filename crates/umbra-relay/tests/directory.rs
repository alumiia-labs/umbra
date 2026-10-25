//! The directory and the issuer over real sockets on loopback: a client
//! takes a first-party token under a proof of work, registers a handle with
//! it, and reads the handle back under a signed head, each request in OHTTP
//! through a relay with the directory role (`DIS-162`).

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{net::TcpListener, sync::mpsc};
use umbra_core::{
    abuse::epoch_number,
    discovery::{
        dirclient::{self, DirError},
        entry::{DirectoryEntry, DIRECTORY_ENTRY_MAX},
        handle::username_case_mapped,
        head::{AcceptedHead, HeadState, LogKeySet, SignedTreeHead, KEYSET_LEN},
        service::{Directory, DirectoryKeys},
    },
};
use umbra_crypto::{hierarchy::RootIdentity, kem::KeyPair, secret::Secret, sign::SigningKey, vrf};
use umbra_relay::{
    directory_server::{run_directory, MemoryDirectoryStore, GATEWAY_PATH},
    ndr_server::Gateway,
    server::{accept_loop, tls_acceptor, Carried, OhttpForward, OsRng, DIRECTORY_PATH},
};
use umbra_transport::{
    directory::{call, DirectoryRoute},
    https::Url,
    native,
};
use umbra_wire::{
    address::QueueAddress,
    directory::{Kind, Status},
};

fn fixture(name: &str) -> String {
    format!(
        "{}/../../tests/fixtures/tls/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

async fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Client {
    route: DirectoryRoute,
    tls: Arc<rustls::ClientConfig>,
}

impl Client {
    async fn send(&self, kind: Kind, body: &[u8]) -> Result<Vec<u8>, DirError> {
        let request = dirclient::request(kind, body).unwrap();
        let response = call(&self.route, &request, self.tls.clone(), &mut OsRng)
            .await
            .unwrap();
        dirclient::done(&response)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_registers_a_handle_that_a_lookup_reads_under_a_signed_head() {
    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    let signers: Vec<SigningKey> = (0..3u8)
        .map(|i| SigningKey::from_seed(Secret::new([60 + i; 32])))
        .collect();
    let public: Vec<_> = signers
        .iter()
        .map(|s| s.verifying_key().to_bytes())
        .collect();

    let mut keyset = vec![0u8; KEYSET_LEN];
    let used = LogKeySet {
        keyset_epoch: 1,
        keys: public.iter().map(|k| &k[..]).collect(),
    }
    .encode(&mut keyset)
    .unwrap();
    keyset.truncate(used);

    let directory = Directory::new(
        DirectoryKeys {
            voprf_seed: Secret::new([1; 32]),
            vrf_seed: Secret::new([2; 32]),
            issuer_seed: Secret::new([3; 32]),
            signers,
            keyset: keyset.clone(),
            cross_relay: None,
        },
        1,
        username_case_mapped,
    )
    .unwrap();

    let directory_pk = *directory.voprf_public();
    let vrf_key = vrf::PublicKey::from_bytes(directory.vrf_public()).unwrap();

    let pair = KeyPair::generate(&mut OsRng);
    let gateway_key = pair.public().clone();
    let (dir_listener, dir_port) = listener().await;
    tokio::spawn(run_directory(
        dir_listener,
        tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap(),
        Gateway { key_id: 1, pair },
        directory,
        Box::new(MemoryDirectoryStore::default()),
    ));

    // A relay with the directory role, whose node sees no request.
    let (relay_listener, relay_port) = listener().await;
    let (node, _unused) = mpsc::channel(8);
    let carried = Carried {
        directory: Some(OhttpForward {
            gateway: Url::parse(&format!("https://localhost:{dir_port}{GATEWAY_PATH}")).unwrap(),
            tls: trust.clone(),
        }),
        ..Carried::default()
    };

    tokio::spawn(accept_loop(
        relay_listener,
        tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap(),
        node,
        Arc::new(carried),
    ));

    let client = Client {
        route: DirectoryRoute {
            relay: Url::parse(&format!("https://localhost:{relay_port}{DIRECTORY_PATH}")).unwrap(),
            key_id: 1,
            gateway: gateway_key,
        },
        tls: trust,
    };

    // No head before the first tick.
    let mut waited = 0;
    loop {
        match client.send(Kind::Head, &0u64.to_be_bytes()).await {
            Ok(_) => break,
            Err(DirError::Status(Status::NotFound)) if waited < 20 => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                waited += 1;
            }
            Err(other) => panic!("{other:?}"),
        }
    }

    // A token of this epoch under a proof of work (ABU-109). The issuer key
    // comes from the log in the app; here the client reads it from the seed.
    let epoch = epoch_number(now());
    let issuer_pk = *umbra_core::abuse::token::FirstPartyIssuer::new(
        umbra_crypto::voprf::ServerKey::derive(&Secret::new([3; 32]), &epoch.to_be_bytes())
            .unwrap(),
    )
    .public();

    let (state, body) = dirclient::issue_request(epoch, &issuer_pk, 1, &mut OsRng).unwrap();
    let issued = client.send(Kind::Issue, &body).await.unwrap();

    // The same request again takes the answer of the first one, with the
    // same bytes and the same proof. The issuer signs nothing a second
    // time, and the token is the same token (ABU-110).
    let again = client.send(Kind::Issue, &body).await.unwrap();
    assert_eq!(again, issued);

    let token = dirclient::issue_finish(&state, &issued, &issuer_pk).unwrap();
    let token = dirclient::token_bytes(&token[0]).unwrap();

    // The registration.
    let hk = RootIdentity::new(Secret::new([7; 32])).handle_key(0, 0);
    let input = b"@dana#2718";
    let entry = DirectoryEntry {
        handle: input.to_vec(),
        hk_pub: hk.public().to_bytes(),
        rendezvous: Some(QueueAddress {
            relay_id: [1; 32],
            sender_id: [2; 32],
            qs_auth_sk: Secret::new([3; 32]),
            qe: Secret::new([4; 32]),
        }),
        version: 0,
    };

    let mut encoded = vec![0u8; DIRECTORY_ENTRY_MAX];
    let used = entry.encode(&mut encoded).unwrap();
    encoded.truncate(used);

    // DIS-197: the registration challenge proves the key of the entry, and
    // the token pays for it (DIS-203).
    let body =
        dirclient::register_challenge_body(input, &hk.public().to_bytes(), Some(&token)).unwrap();
    let challenge = client.send(Kind::Challenge, &body).await.unwrap();
    let (challenge, purpose) = dirclient::parse_register_challenge(&challenge).unwrap();

    let ans =
        umbra_core::discovery::challenge::answer(purpose, &hk, input, &challenge, Some(&encoded))
            .unwrap();

    let register = dirclient::register_body(&token, input, &encoded, &ans, None).unwrap();
    client.send(Kind::Register, &register).await.unwrap();

    // The search key under a proof of work, and the lookup at the next
    // head (DIS-166).
    let (blind, body) =
        dirclient::evaluate_request(input, &directory_pk, epoch_number(now()), None, &mut OsRng)
            .unwrap();

    let evaluated = client.send(Kind::Evaluate, &body).await.unwrap();
    let search_key = dirclient::evaluate_finish(&blind, &evaluated, &directory_pk).unwrap();

    let mut waited = 0;
    let found = loop {
        let looked = client.send(Kind::Lookup, &search_key).await.unwrap();
        let (head, _, proof) = dirclient::parse_lookup(&looked).unwrap();
        let head = SignedTreeHead::parse(&head).unwrap();
        let (set, _) = LogKeySet::parse(&keyset).unwrap();
        let mut heads = HeadState::new(set).unwrap();
        heads.accept(&head, now()).unwrap();

        let accepted = AcceptedHead {
            tree_size: head.tree_size,
            root: head.root,
            timestamp: head.timestamp,
            accepted_at: now(),
        };

        if let Some(found) = proof
            .verify_handle(input, &search_key, &vrf_key, &accepted)
            .unwrap()
        {
            break found;
        }

        assert!(waited < 30, "the handle does not show");
        waited += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    assert_eq!(found.hk_pub, hk.public().to_bytes());
    assert_eq!(found.version, 0);
}
