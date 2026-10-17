//! The onion vectors of Part 6 §6.8 and Part 3 §3.4.4: one forward cell
//! and one backward cell across three hops at each bucket, the negative
//! case of one changed bit at hop 2, the four known-answer cells of
//! `NET-111`, the hop 3 key set after `CIRCUIT_MAX_CELLS` cells
//! (`NET-210`), and one build exchange under a stated generator.
//!
//! Self-generated and not independently confirmed. The ignored test
//! `generate` writes the file; run `scripts/vectors.py` afterwards.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::{fs, path::PathBuf};

use serde_json::{json, Value};
use umbra_crypto::{
    handshake::nk::RelayStatic,
    secret::Secret,
    x25519::{PublicKey as XPublic, StaticSecret},
};
use umbra_onion::{
    build::{answer, DelayClass, Pending, HELLO_LEN, REPLY_LEN},
    circuit::{Circuit, Position, RelayHop},
    layer::KeySet,
    Error, CIRCUIT_MAX_CELLS, HOPS,
};
use umbra_wire::bucket::Bucket;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/umbra/onion.json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Rng(u8);

impl umbra_crypto::rand_core::TryRng for Rng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = self.0.wrapping_add((i % 251) as u8);
        }
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}

impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

const SECRETS: [[u8; 32]; HOPS] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const CIRC_ID: [u8; 16] = [0x39; 16];

fn secrets() -> [Secret<32>; HOPS] {
    [
        Secret::new(SECRETS[0]),
        Secret::new(SECRETS[1]),
        Secret::new(SECRETS[2]),
    ]
}

fn relays() -> [RelayHop; HOPS] {
    let s = secrets();
    [
        RelayHop::new(&s[0], 1, Position::Middle),
        RelayHop::new(&s[1], 2, Position::Middle),
        RelayHop::new(&s[2], 3, Position::Endpoint),
    ]
}

fn cells_at_each_bucket() -> Value {
    let mut out = Vec::new();
    for bucket in Bucket::ALL {
        let mut client = Circuit::new(&secrets(), CIRC_ID);
        let mut chain = relays();
        let payload: Vec<u8> = (0..bucket.body_len()).map(|i| (i % 256) as u8).collect();
        let mut body = payload.clone();
        let tag0 = client.seal(&mut body).unwrap();
        let sealed = body.clone();
        let mut tags = vec![tag0];
        for hop in chain.iter_mut() {
            let t = hop.forward(tags.last().unwrap(), &mut body).unwrap();
            tags.push(t);
        }

        assert_eq!(body, payload);
        // WIR-159: the length is the same at each hop.
        assert_eq!(sealed.len(), bucket.body_len());

        let reply: Vec<u8> = (0..bucket.body_len())
            .map(|i| (255 - i % 256) as u8)
            .collect();
        let mut back = reply.clone();
        let mut back_tags = vec![[0u8; 16]];
        for hop in chain.iter_mut().rev() {
            let t = hop.backward(back_tags.last().unwrap(), &mut back).unwrap();
            back_tags.push(t);
        }

        let backward_sealed = back.clone();
        client.open(back_tags.last().unwrap(), &mut back).unwrap();
        assert_eq!(back, reply);

        // WIR-160: one changed bit at hop 2 dies at the endpoint.
        let mut client2 = Circuit::new(&secrets(), CIRC_ID);
        let mut chain2 = relays();
        let mut body2 = payload.clone();
        let t = client2.seal(&mut body2).unwrap();
        let t = chain2[0].forward(&t, &mut body2).unwrap();
        body2[0] ^= 0x80;
        let t = chain2[1].forward(&t, &mut body2).unwrap();
        assert_eq!(chain2[2].forward(&t, &mut body2), Err(Error::Rejected));

        out.push(json!({
            "bucket": bucket.cell_len(),
            "forward": {
                "tag_at_client": hex(&tags[0]),
                "tag_after_hop1": hex(&tags[1]),
                "tag_after_hop2": hex(&tags[2]),
                "body_sealed_head": hex(&sealed[..32]),
                "body_sealed_tail": hex(&sealed[sealed.len() - 16..]),
            },
            "backward": {
                "tag_from_hop3": hex(&back_tags[1]),
                "tag_from_hop2": hex(&back_tags[2]),
                "tag_from_hop1": hex(&back_tags[3]),
                "body_sealed_head": hex(&backward_sealed[..32]),
            },
        }));
    }
    json!(out)
}

fn known_answer_cells() -> Value {
    // NET-111: a forward cell, a backward cell, a cell after one chaining
    // step, and a cell after one key update, all at B0 with a zero body.
    let mut client = Circuit::new(&secrets(), CIRC_ID);
    let mut chain = relays();
    let mut cells = Vec::new();

    for label in ["forward", "forward after one chaining step"] {
        let mut body = [0u8; 480];
        let tag = client.seal(&mut body).unwrap();
        let mut t = tag;
        let mut copy = body;
        for hop in chain.iter_mut() {
            t = hop.forward(&t, &mut copy).unwrap();
        }
        cells.push(json!({ "case": label, "tag": hex(&tag), "body_head": hex(&body[..32]) }));
    }

    let mut body = [0u8; 480];
    let mut t = [0u8; 16];
    for hop in chain.iter_mut().rev() {
        t = hop.backward(&t, &mut body).unwrap();
    }

    let sealed = body;
    client.open(&t, &mut body).unwrap();
    cells.push(json!({ "case": "backward", "tag": hex(&t), "body_head": hex(&sealed[..32]) }));

    // The hop 3 key set moved at each cell above; this cell is after those
    // updates on both sides.
    let hop3_after = client.forward_keys(3).unwrap().fingerprint();
    assert_eq!(hop3_after, chain[2].forward_keys().fingerprint());

    let mut body = [0u8; 480];
    let tag = client.seal(&mut body).unwrap();
    cells.push(json!({ "case": "forward after key updates", "tag": hex(&tag), "body_head": hex(&body[..32]),
                       "hop3_forward_fingerprint_before": hex(&hop3_after) }));
    json!(cells)
}

fn key_set_after_max_cells() -> Value {
    // NET-210 and WIR-355: the hop 3 forward key set after CIRCUIT_MAX_CELLS.
    let mut client = Circuit::new(&secrets(), CIRC_ID);
    let mut endpoint = RelayHop::new(&secrets()[2], 3, Position::Endpoint);
    let mut middle = [
        RelayHop::new(&secrets()[0], 1, Position::Middle),
        RelayHop::new(&secrets()[1], 2, Position::Middle),
    ];

    let mut body = [0u8; 480];
    for _ in 0..CIRCUIT_MAX_CELLS {
        let mut t = client.seal(&mut body).unwrap();
        for hop in middle.iter_mut() {
            t = hop.forward(&t, &mut body).unwrap();
        }
        endpoint.forward(&t, &mut body).unwrap();
    }

    let client_fp = client.forward_keys(3).unwrap().fingerprint();
    assert_eq!(client_fp, endpoint.forward_keys().fingerprint());

    let hop1 = client.forward_keys(1).unwrap();
    json!({
        "cells": CIRCUIT_MAX_CELLS,
        "hop3_forward_fingerprint": hex(&client_fp),
        "hop1_forward_chain": hex(&hop1.chain()),
        "hop1_tweak": hex(&hop1.tweak()),
    })
}

fn key_schedule() -> Value {
    let set = KeySet::derive(&Secret::new(SECRETS[0]), 1);
    json!({
        "ss_hop": hex(&SECRETS[0]), "hop_index": 1,
        "forward_fingerprint": hex(&set.forward.fingerprint()),
        "backward_fingerprint": hex(&set.backward.fingerprint()),
        "forward_chain_initial": hex(&set.forward.chain()),
        "backward_chain_initial": hex(&set.backward.chain()),
        "tweak": hex(&set.forward.tweak()),
    })
}

fn build_exchange() -> Value {
    let s_sk = StaticSecret::from([0x41u8; 32]);
    let relay = RelayStatic {
        s: *XPublic::from(&s_sk).as_bytes(),
        relay_id: [0x42; 32],
    };
    let mut hello = [0u8; HELLO_LEN];
    let pending = Pending::hello(&relay, DelayClass::Balanced, &mut Rng(1), &mut hello).unwrap();
    let mut reply = [0u8; REPLY_LEN];
    let at_relay = answer(&relay, &s_sk, &hello, &mut Rng(2), &mut reply).unwrap();
    let at_client = pending.finish(&reply).unwrap();
    assert_eq!(at_relay.expose(), at_client.expose());

    json!({
        "relay_static_sk": hex(&[0x41; 32]), "relay_id": hex(&[0x42; 32]),
        "rng": "byte i of each fill is (seed + i mod 251) mod 256; the seed starts at 1 for the client and 2 for the relay and rises by one at each fill",
        "hop_hello": hex(&hello), "hop_reply": hex(&reply),
        "ss_hop": hex(at_client.expose()),
    })
}

fn build() -> Value {
    json!({
        "note": "Onion vectors of Part 3 §3.4.3 and §3.4.4 and Part 6 §6.8. Self-generated; not independently confirmed. The tweak of a layer is the last block of the hop key derivation, not the circuit identifier.",
        "hop_secrets": SECRETS.iter().map(|s| hex(s)).collect::<Vec<_>>(),
        "circ_id": hex(&CIRC_ID),
        "key_schedule": key_schedule(),
        "cells_at_each_bucket": cells_at_each_bucket(),
        "known_answer_cells": known_answer_cells(),
        "after_max_cells": key_set_after_max_cells(),
        "build": build_exchange(),
    })
}

#[test]
#[ignore = "writes the vector file; run by hand"]
fn generate() {
    fs::write(path(), serde_json::to_string_pretty(&build()).unwrap()).unwrap();
}

#[test]
fn onion_vectors_hold() {
    let stored: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(stored, build());
}
