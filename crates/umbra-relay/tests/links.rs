//! The link to a relay in pin form (Part 3 `NET-380`), over real sockets on
//! loopback: the dialer accepts the certificate of the pin alone, it checks
//! the signature of the handshake under that certificate, and it sends no
//! server name. A relay in name form still needs a certificate under the
//! roots of the dialer (`NET-282`).

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::{net::SocketAddr, sync::Arc};

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::{CertifiedKey, SingleCertAndKey},
    CertificateError,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use umbra_relay::{
    linkcert::{self, LinkCertificate},
    server::{link_acceptor, tls_acceptor},
};
use umbra_transport::{
    native::{self, ClientConfig, TcpLink},
    upgrade, Dial,
};

fn fixture(name: &str) -> String {
    format!(
        "{}/../../tests/fixtures/tls/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// The dialer of a test network: it trusts the test authority alone.
fn test_roots() -> Arc<ClientConfig> {
    native::tls_config_with_root_file(&fixture("ca.pem")).unwrap()
}

/// What a server saw of one handshake: whether it completed, and the
/// server name of the ClientHello.
type Seen = JoinHandle<(bool, Option<String>)>;

/// A listener that takes one TLS handshake under `acceptor`.
async fn serve_one(acceptor: TlsAcceptor) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let seen = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        match acceptor.accept(tcp).await {
            Ok(stream) => {
                let name = stream.get_ref().1.server_name().map(str::to_owned);
                (true, name)
            }
            Err(_) => (false, None),
        }
    });

    (address, seen)
}

/// One TLS handshake to `address` as a dialer of the relay `host` with the
/// pin `link_pin`. Gives the fault of the handshake, or none.
async fn handshake(
    host: &str,
    link_pin: Option<[u8; 32]>,
    address: SocketAddr,
    config: Arc<ClientConfig>,
) -> Option<rustls::Error> {
    let (config, name, _) = native::link_setup(host, link_pin, address, config).unwrap();
    let tcp = TcpStream::connect(address).await.unwrap();
    let connected = tokio_rustls::TlsConnector::from(config)
        .connect(name, tcp)
        .await;

    let fault = connected.err()?;
    let cause = fault.get_ref().expect("a fault of the TLS stack");
    Some(cause.downcast_ref::<rustls::Error>().unwrap().clone())
}

/// An acceptor that gives the certificate of `shown` and signs the
/// handshake with the key of `signer`.
fn acceptor_with_key_of(shown: &LinkCertificate, signer: &LinkCertificate) -> TlsAcceptor {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signer.key.to_vec()));
    let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).unwrap();
    let certificate = CertificateDer::from(shown.certificate.clone());
    let certified = CertifiedKey::new(vec![certificate], key);

    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    TlsAcceptor::from(Arc::new(config))
}

#[tokio::test]
async fn the_certificate_of_the_pin_passes_and_the_hello_holds_no_server_name() {
    let link = linkcert::make().unwrap();
    let pin = native::link_pin(&link.certificate);
    let (address, seen) = serve_one(link_acceptor(&link).unwrap()).await;

    // The dialer holds the test authority alone, and the certificate chains
    // to no authority: the pin decides.
    assert_eq!(handshake("", Some(pin), address, test_roots()).await, None);
    assert_eq!(seen.await.unwrap(), (true, None));
}

#[tokio::test]
async fn another_certificate_with_the_same_subject_fails() {
    let link = linkcert::make().unwrap();
    let other = linkcert::make().unwrap();
    let pin = native::link_pin(&link.certificate);
    let (address, seen) = serve_one(link_acceptor(&other).unwrap()).await;

    let fault = handshake("", Some(pin), address, test_roots()).await;
    let refused = CertificateError::ApplicationVerificationFailure;
    assert_eq!(fault, Some(rustls::Error::InvalidCertificate(refused)));
    assert!(!seen.await.unwrap().0);
}

#[tokio::test]
async fn a_handshake_under_another_key_than_the_one_of_the_certificate_fails() {
    // The server shows the certificate of the pin, and it holds another
    // key. A copy of a certificate is public, thus the pin alone proves
    // nothing: the signature of the handshake does.
    let link = linkcert::make().unwrap();
    let other = linkcert::make().unwrap();
    let pin = native::link_pin(&link.certificate);
    let (address, _seen) = serve_one(acceptor_with_key_of(&link, &other)).await;

    let fault = handshake("", Some(pin), address, test_roots()).await;
    let bad_signature = CertificateError::BadSignature;
    assert_eq!(
        fault,
        Some(rustls::Error::InvalidCertificate(bad_signature))
    );

    // The same server with the key of its certificate passes.
    let (address, _seen) = serve_one(acceptor_with_key_of(&link, &link)).await;
    assert_eq!(handshake("", Some(pin), address, test_roots()).await, None);
}

#[tokio::test]
async fn a_relay_in_name_form_still_needs_a_certificate_under_the_roots() {
    // A link certificate under a name chains to no root of the dialer.
    let link = linkcert::make().unwrap();
    let (address, _seen) = serve_one(link_acceptor(&link).unwrap()).await;
    let fault = handshake("localhost", None, address, test_roots()).await;
    assert!(matches!(fault, Some(rustls::Error::InvalidCertificate(_))));

    // The certificate of the test authority passes under that authority,
    // with the name in the ClientHello, and it fails under the public roots.
    let leaf = || tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    let (address, seen) = serve_one(leaf()).await;
    assert_eq!(
        handshake("localhost", None, address, test_roots()).await,
        None
    );
    assert_eq!(seen.await.unwrap(), (true, Some("localhost".to_owned())));

    let (address, _seen) = serve_one(leaf()).await;
    let public_roots = native::tls_config().unwrap();
    let fault = handshake("localhost", None, address, public_roots).await;
    assert!(matches!(fault, Some(rustls::Error::InvalidCertificate(_))));

    // A name that the certificate does not hold fails under its authority.
    let (address, _seen) = serve_one(leaf()).await;
    let fault = handshake("relay.example", None, address, test_roots()).await;
    assert!(matches!(fault, Some(rustls::Error::InvalidCertificate(_))));
}

#[tokio::test]
async fn a_pin_holds_for_a_certificate_of_an_authority_too() {
    // The lines `cert` and `key` with an empty host: the pin of the first
    // certificate of the file. The public roots have no part in the check.
    let first = CertificateDer::pem_file_iter(fixture("leaf.pem"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let pin = native::link_pin(&first);
    let acceptor = tls_acceptor(&fixture("leaf.pem"), &fixture("leaf.key")).unwrap();
    let (address, _seen) = serve_one(acceptor).await;

    let public_roots = native::tls_config().unwrap();
    assert_eq!(handshake("", Some(pin), address, public_roots).await, None);
}

#[tokio::test]
async fn a_dial_with_no_name_and_no_pin_is_refused_before_the_handshake() {
    // A client holds no pin (`REL-228`), thus a relay in pin form gives it
    // no name to dial.
    let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(native::link_setup("", None, address, test_roots()).is_err());
}

#[tokio::test]
async fn the_upgrade_to_a_relay_in_pin_form_carries_its_address_as_the_host() {
    let link = linkcert::make().unwrap();
    let pin = native::link_pin(&link.certificate);
    let acceptor = link_acceptor(&link).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let host_seen = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(tcp).await.unwrap();
        let mut inbound = Vec::new();
        let mut chunk = vec![0u8; 4_096];

        let request = loop {
            if let Ok(Some((request, _))) = upgrade::parse_request(&inbound) {
                break request;
            }
            let n = stream.read(&mut chunk).await.unwrap();
            inbound.extend_from_slice(&chunk[..n]);
        };

        let answer = upgrade::response(&request.key);
        stream.write_all(answer.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        request.host
    });

    let dial = Dial {
        host: String::new(),
        link_pin: Some(pin),
        addr_v4: Some([127, 0, 0, 1]),
        addr_v6: None,
        port: address.port(),
    };
    let link = TcpLink::connect(&dial, test_roots(), [7; 16], [1; 4]).await;
    assert!(link.is_ok());
    assert_eq!(host_seen.await.unwrap(), address.to_string());

    // The same dial with another pin gets no link.
    let other = Dial {
        link_pin: Some([0xA7; 32]),
        ..dial
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = Dial {
        port: listener.local_addr().unwrap().port(),
        ..other
    };
    let acceptor = link_acceptor(&linkcert::make().unwrap()).unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = acceptor.accept(tcp).await;
    });
    let link = TcpLink::connect(&other, test_roots(), [7; 16], [1; 4]).await;
    assert!(matches!(link, Err(native::NativeError::Io(_))));
}
