//! The push path of Part 8 over real sockets on loopback: a device
//! registers with the NDR through a relay with the OHTTP relay role, a
//! queue relay pushes through the same relay, and the NDR posts the blob to
//! a UnifiedPush endpoint. A target that the endpoint names gone ends the
//! registration.

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::sync::Arc;

use tokio::{net::TcpListener, sync::mpsc};
use umbra_core::notify::token::HandleSet;
use umbra_crypto::{hash::sha3_256, kem::KeyPair, secret::Secret};
use umbra_relay::{
    ndr_server::{run_ndr, Gateway, MemoryNdrStore, GATEWAY_PATH},
    server::{accept_loop, tls_acceptor, Carried, OhttpForward, OsRng, OHTTP_PATH},
};
use umbra_transport::{
    https::{self, Request, Url},
    native,
    ndr::{call, NdrRoute},
};
use umbra_wire::ndr::{
    encode_token, NdrRequest, NdrResponse, TokenCarrier, BLOB_LEN, NDR_REQUEST_LEN, PUSH_TOKEN_MAX,
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

/// A UnifiedPush endpoint that answers each post with the next status and
/// hands each request to the test.
async fn endpoint(statuses: Vec<u16>) -> (u16, mpsc::UnboundedReceiver<Request>) {
    let (listener, port) = listener().await;
    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    let (seen, requests) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for status in statuses {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = tls.accept(tcp).await.unwrap();
            let mut inbound = Vec::new();
            let request = https::read_request(&mut stream, &mut inbound, 4_096)
                .await
                .unwrap();
            seen.send(request).unwrap();
            https::respond(&mut stream, status, "text/plain", &[])
                .await
                .unwrap();
        }
    });
    (port, requests)
}

fn encode(request: &NdrRequest<'_>) -> [u8; NDR_REQUEST_LEN] {
    let mut out = [0u8; NDR_REQUEST_LEN];
    request.encode(&mut out).unwrap();
    out
}

#[tokio::test]
async fn a_registration_and_a_push_cross_the_ohttp_relay_to_the_endpoint() {
    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    let (push_port, mut pushed) = endpoint(vec![201, 410]).await;

    // The NDR, with its gateway key.
    let pair = KeyPair::generate(&mut OsRng);
    let public = pair.public().clone();
    let (ndr_listener, ndr_port) = listener().await;
    tokio::spawn(run_ndr(
        ndr_listener,
        tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap(),
        Gateway { key_id: 1, pair },
        Box::new(MemoryNdrStore::default()),
        trust.clone(),
    ));

    // A relay with the OHTTP relay role, whose node sees no request.
    let (relay_listener, relay_port) = listener().await;
    let (node, _unused) = mpsc::channel(8);
    let carried = Carried {
        manifest: None,
        ohttp: Some(OhttpForward {
            gateway: Url::parse(&format!("https://localhost:{ndr_port}{GATEWAY_PATH}")).unwrap(),
            tls: trust.clone(),
        }),
        ndr: None,
    };
    tokio::spawn(accept_loop(
        relay_listener,
        tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap(),
        node,
        Arc::new(carried),
    ));
    let route = NdrRoute {
        relay: Url::parse(&format!("https://localhost:{relay_port}{OHTTP_PATH}")).unwrap(),
        key_id: 1,
        gateway: public,
    };

    // The device registers its endpoint under a handle.
    let set = HandleSet::assign(&[[1; 32]], &[], &[], 0, &mut OsRng).unwrap();
    let group = &set.groups()[0];
    let target = format!("https://localhost:{push_port}/up/device-1");
    let mut plain = [0u8; PUSH_TOKEN_MAX];
    let n = encode_token(TokenCarrier::UnifiedPush, target.as_bytes(), &mut plain).unwrap();
    let registration = group.registration(&plain[..n], [4; 24]).unwrap();
    let removal = Secret::new([9; 32]);
    let register = encode(&NdrRequest::Register {
        handle: group.handle,
        nonce: registration.nonce,
        ct_token: &registration.ct_token,
        removal_hash: sha3_256(&[removal.expose()]),
        prior: Secret::new([0; 32]),
    });
    let answer = call(&route, &register, trust.clone(), &mut OsRng)
        .await
        .unwrap();
    assert_eq!(answer, NdrResponse::Taken);

    // The queue relay pushes, and the endpoint gets the blob with its expiry.
    let push = encode(&NdrRequest::Push {
        handle: group.handle,
        k_tok: Secret::new(*group.k_tok.expose()),
        ttl: 86_400,
        blob: [0x42; BLOB_LEN],
    });
    let answer = call(&route, &push, trust.clone(), &mut OsRng)
        .await
        .unwrap();
    assert_eq!(answer, NdrResponse::Taken);
    let got = pushed.recv().await.unwrap();
    assert_eq!(got.path, "/up/device-1");
    assert_eq!(got.body, [0x42; BLOB_LEN]);
    assert!(got.headers.contains(&("ttl".into(), "86400".into())));

    // NTF-125: the endpoint names the target gone, the NDR drops the
    // registration, and the next push is refused.
    let answer = call(&route, &push, trust.clone(), &mut OsRng)
        .await
        .unwrap();
    assert_eq!(answer, NdrResponse::Gone);
    let answer = call(&route, &push, trust, &mut OsRng).await.unwrap();
    assert_eq!(answer, NdrResponse::Refused);
}
