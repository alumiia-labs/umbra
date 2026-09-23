//! The server runtime over an in-memory stream: the HTTP upgrade, the
//! session capsule, and one hop of a circuit build through the node task.

#![cfg(feature = "native")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::mpsc,
};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    rsabssa::PublicKey2048,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_onion::{
    build::{build_cell_body, read_cell_body, Pending, BUILD_BUCKET, HELLO_LEN},
    circuit::CircuitBuild,
};
use umbra_relay::{
    node::{Config, RelayNode},
    server::{run_node, serve_connection, OsRng},
    store::MemoryStore,
};
use umbra_transport::{link::ClientLink, upgrade, websocket};
use umbra_wire::{
    capsule,
    cell::{Cell, CellCommand},
};

async fn write_frame(stream: &mut DuplexStream, capsule_bytes: &[u8]) {
    let mut frame = vec![0u8; websocket::frame_len(capsule_bytes.len(), true)];
    let used = websocket::encode(capsule_bytes, Some(&[9, 8, 7, 6]), &mut frame).unwrap();
    stream.write_all(&frame[..used]).await.unwrap();
}

async fn read_frame(stream: &mut DuplexStream, inbound: &mut Vec<u8>) -> Vec<u8> {
    let mut out = vec![0u8; 40_000];
    loop {
        if let Some((len, used)) = websocket::decode(inbound, false, &mut out).unwrap() {
            inbound.drain(..used);
            out.truncate(len);
            return out;
        }
        let mut chunk = [0u8; 4_096];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "the server closed the stream");
        inbound.extend_from_slice(&chunk[..n]);
    }
}

#[tokio::test]
async fn a_client_upgrades_opens_a_session_and_builds_one_hop() {
    let static_secret = StaticSecret::from([1; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&static_secret).as_bytes(),
        relay_id: [0x11; 32],
    };
    let relay_for_client = RelayStatic {
        s: relay.s,
        relay_id: relay.relay_id,
    };
    let node = RelayNode::new(Config {
        relay,
        static_secret,
        layer: 1,
        issuer_key: PublicKey2048::from_modulus(&[0xFF; 256]).unwrap(),
        community_capacity: 1 << 20,
        chunk_capacity: 1 << 26,
    });
    let (inputs, node_inputs) = mpsc::channel(64);
    let (requests, _node_requests) = mpsc::unbounded_channel();
    let store = Box::new(MemoryStore::default());
    tokio::spawn(run_node(node, node_inputs, requests, 1_000, store));
    let (mut client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve_connection(server, 2, inputs, Default::default()));

    // The upgrade of Part 6 §6.2.1.
    let key = [5u8; 16];
    client
        .write_all(upgrade::request("relay.example", &key).as_bytes())
        .await
        .unwrap();
    let mut inbound = Vec::new();
    loop {
        let mut chunk = [0u8; 1_024];
        let n = client.read(&mut chunk).await.unwrap();
        inbound.extend_from_slice(&chunk[..n]);
        if let Some(used) = upgrade::parse_response(&inbound, &key).unwrap() {
            inbound.drain(..used);
            break;
        }
    }

    // The session capsule is below 126 bytes, and it goes first.
    let mut buffer = vec![0u8; 4_096];
    let (mut link, used) = ClientLink::open([3; 8], Secret::new([4; 32]), &mut buffer).unwrap();
    assert!(used < 126);
    write_frame(&mut client, &buffer[..used]).await;

    // One hop of a build.
    let mut build = CircuitBuild::new([0xA0; 16]);
    let mut hello = [0u8; HELLO_LEN];
    let pending = Pending::hello(&relay_for_client, &mut OsRng, &mut hello).unwrap();
    let mut body = vec![0u8; BUILD_BUCKET.body_len()];
    build_cell_body(CellCommand::Extend, &hello, &mut body).unwrap();
    let tag = build.seal(&mut body).unwrap();
    let cell = [build.circ_id().as_slice(), &tag, &body].concat();
    let used = link.send(&cell, &mut buffer).unwrap();
    write_frame(&mut client, &buffer[..used]).await;

    let answer = read_frame(&mut client, &mut inbound).await;
    let (_, value, _) = capsule::parse(&answer).unwrap();
    let cell = link.receive(value).unwrap().unwrap().to_vec();
    let (parsed, _) = Cell::parse(&cell).unwrap();
    let mut body = parsed.body.to_vec();
    build.open(parsed.tag, &mut body).unwrap();
    let (command, reply) = read_cell_body(&body).unwrap();
    assert_eq!(command, CellCommand::Extended);
    build.push(&pending.finish(reply).unwrap()).unwrap();
    assert_eq!(build.built(), 1);
}
