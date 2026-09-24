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
        None,
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
        ..Carried::default()
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

/// What the fake Google server saw: each path, its authorization, and its
/// body.
type Seen = mpsc::UnboundedReceiver<(String, Option<String>, Vec<u8>)>;

/// A token endpoint and an FCM API on one loopback server. The token
/// endpoint checks the RS256 signature of the assertion, and the API answers
/// each message with the next status.
async fn google(public_key: Vec<u8>, statuses: Vec<u16>) -> (u16, Seen) {
    use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
    let (listener, port) = listener().await;
    let tls = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    let (seen, requests) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut statuses = statuses.into_iter();
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = tls.accept(tcp).await.unwrap();
            let mut inbound = Vec::new();
            let request = https::read_request(&mut stream, &mut inbound, 16_384)
                .await
                .unwrap();
            let authorization = request
                .headers
                .iter()
                .find(|(name, _)| name == "authorization")
                .map(|(_, value)| value.clone());
            if request.path == "/token" {
                let form = String::from_utf8(request.body.clone()).unwrap();
                let jwt = form.split("assertion=").nth(1).unwrap();
                let (signed, signature) = jwt.rsplit_once('.').unwrap();
                UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public_key)
                    .verify(signed.as_bytes(), &decode64(signature, b'-', b'_'))
                    .expect("the assertion carries a signature of the account key");
                let answer = r#"{"access_token":"tok-1","expires_in":3599}"#;
                https::respond(&mut stream, 200, "application/json", answer.as_bytes())
                    .await
                    .unwrap();
            } else {
                let status = statuses.next().unwrap_or(500);
                https::respond(&mut stream, status, "application/json", b"{}")
                    .await
                    .unwrap();
            }
            seen.send((request.path, authorization, request.body))
                .unwrap();
        }
    });
    (port, requests)
}

/// Base64 in either alphabet, with the two last symbols given.
fn decode64(text: &str, sixty_two: u8, sixty_three: u8) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            c if c == sixty_two => 62,
            c if c == sixty_three => 63,
            _ => panic!("not base64"),
        })
    };
    let clean: Vec<u8> = text.bytes().filter(|c| *c != b'=').collect();
    let mut out = Vec::new();
    for group in clean.chunks(4) {
        let mut n = 0u32;
        for (i, c) in group.iter().enumerate() {
            n |= value(*c) << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..group.len()]);
    }
    out
}

/// A JSON string of `text`, as a service account file writes its key.
fn json_quote(text: &str) -> String {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[tokio::test]
async fn an_fcm_token_gets_a_data_message_under_the_account_of_the_ndr() {
    use aws_lc_rs::signature::{KeyPair as _, RsaKeyPair};
    use umbra_relay::fcm::{base64url, Fcm, ServiceAccount};
    let pem = std::fs::read_to_string(format!(
        "{}/../../tests/fixtures/fcm/test-key.pem",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let public = RsaKeyPair::from_pkcs8(&decode64(&body, b'+', b'/'))
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let trust = native::tls_config_with_root_file(&fixture("ca.pem")).unwrap();
    // FCM takes two messages and names the token gone at the third
    // (`NTF-125`).
    let (google_port, mut seen) = google(public, vec![200, 200, 404]).await;
    let account = format!(
        "{{\"type\":\"service_account\",\"project_id\":\"test-project\",\
         \"private_key\":{},\"client_email\":\"ndr@test-project.iam.example\",\
         \"token_uri\":\"https://localhost:{google_port}/token\"}}",
        json_quote(&pem)
    );
    let fcm = Fcm::new(
        ServiceAccount::parse(&account).unwrap(),
        &format!("https://localhost:{google_port}"),
        trust.clone(),
    )
    .unwrap();

    let pair = KeyPair::generate(&mut OsRng);
    let public = pair.public().clone();
    let (ndr_listener, ndr_port) = listener().await;
    tokio::spawn(run_ndr(
        ndr_listener,
        tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap(),
        Gateway { key_id: 1, pair },
        Box::new(MemoryNdrStore::default()),
        trust.clone(),
        Some(fcm),
    ));
    let (relay_listener, relay_port) = listener().await;
    let (node, _unused) = mpsc::channel(8);
    tokio::spawn(accept_loop(
        relay_listener,
        tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap(),
        node,
        Arc::new(Carried {
            manifest: None,
            ohttp: Some(OhttpForward {
                gateway: Url::parse(&format!("https://localhost:{ndr_port}{GATEWAY_PATH}"))
                    .unwrap(),
                tls: trust.clone(),
            }),
            ndr: None,
            ..Carried::default()
        }),
    ));
    let route = NdrRoute {
        relay: Url::parse(&format!("https://localhost:{relay_port}{OHTTP_PATH}")).unwrap(),
        key_id: 1,
        gateway: public,
    };

    // The device registers its FCM token.
    let set = HandleSet::assign(&[[2; 32]], &[], &[], 0, &mut OsRng).unwrap();
    let group = &set.groups()[0];
    let mut plain = [0u8; PUSH_TOKEN_MAX];
    let n = encode_token(TokenCarrier::Fcm, b"fcm-token-1", &mut plain).unwrap();
    let registration = group.registration(&plain[..n], [5; 24]).unwrap();
    let register = encode(&NdrRequest::Register {
        handle: group.handle,
        nonce: registration.nonce,
        ct_token: &registration.ct_token,
        removal_hash: sha3_256(&[b"removal"]),
        prior: Secret::new([0; 32]),
    });
    let answer = call(&route, &register, trust.clone(), &mut OsRng).await;
    assert_eq!(answer.unwrap(), NdrResponse::Taken);

    // The push goes to FCM as a data message of high priority, with the
    // blob in base64url, the expiry, and no collapse key (`NTF-088`).
    let blob = [0x61; BLOB_LEN];
    let push = encode(&NdrRequest::Push {
        handle: group.handle,
        k_tok: Secret::new(*group.k_tok.expose()),
        ttl: 86_400,
        blob,
    });
    for _ in 0..2 {
        let answer = call(&route, &push, trust.clone(), &mut OsRng).await;
        assert_eq!(answer.unwrap(), NdrResponse::Taken);
    }
    // One token serves both messages.
    let (path, _, _) = seen.recv().await.unwrap();
    assert_eq!(path, "/token");
    for _ in 0..2 {
        let (path, authorization, body) = seen.recv().await.unwrap();
        assert_eq!(path, "/v1/projects/test-project/messages:send");
        assert_eq!(authorization.as_deref(), Some("Bearer tok-1"));
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains(r#""token":"fcm-token-1""#), "{body}");
        assert!(body.contains(&format!(r#""b":"{}""#, base64url(&blob))));
        assert!(body.contains(r#""priority":"HIGH""#));
        assert!(body.contains(r#""ttl":"86400s""#));
        assert!(!body.contains("collapse"));
    }
    let answer = call(&route, &push, trust.clone(), &mut OsRng).await;
    assert_eq!(answer.unwrap(), NdrResponse::Gone);
    let answer = call(&route, &push, trust, &mut OsRng).await;
    assert_eq!(answer.unwrap(), NdrResponse::Refused);
}
