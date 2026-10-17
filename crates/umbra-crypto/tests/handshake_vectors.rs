//! Transcript vectors of the two handshakes (Part 5 rules `CRY-060` to
//! `CRY-062`, `CRY-103`, `CRY-104`, `CRY-116`, `CRY-117`, `CRY-127`).
//!
//! Every random draw of a run is recorded in order, thus another
//! implementation replays the transcript by feeding the same values. The
//! file is self-generated and not independently confirmed. The ignored test
//! `generate` writes it; run `scripts/vectors.py` afterwards.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::{convert::Infallible, fs, path::PathBuf};

use rand_core::{TryCryptoRng, TryRng};
use serde_json::{json, Value};
use sha3::{
    digest::{ExtendableOutput, Update},
    Shake256,
};
use umbra_crypto::{
    handshake::{
        nk,
        xk::{self, Initiator, Invitation, OneTimePrekey, Responder},
        AddressType, Trace, VersionRange,
    },
    kem::KeyPair,
    secret::Secret,
    Error,
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/umbra/handshake.json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A deterministic generator that records each draw.
struct Recorder {
    seed: [u8; 32],
    counter: u64,
    draws: Vec<Value>,
}

impl Recorder {
    fn new(seed: &[u8]) -> Self {
        let mut s = [0u8; 32];
        let mut h = Shake256::default();
        h.update(seed);
        h.finalize_xof_into(&mut s);
        Self {
            seed: s,
            counter: 0,
            draws: Vec::new(),
        }
    }
}

impl TryRng for Recorder {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let mut h = Shake256::default();
        h.update(&self.seed);
        h.update(&self.counter.to_le_bytes());
        self.counter += 1;
        h.finalize_xof_into(dst);
        self.draws.push(json!(hex(dst)));
        Ok(())
    }
}

impl TryCryptoRng for Recorder {}

#[derive(Default)]
struct Steps(Vec<Value>);

impl Trace for Steps {
    fn step(&mut self, step: &'static str, ck: &[u8; 32], h: &[u8; 32], n: u64) {
        self.0
            .push(json!({ "step": step, "ck": hex(ck), "h": hex(h), "n": n }));
    }
}

fn keypair(tag: u8) -> KeyPair {
    KeyPair::from_seeds(Secret::new([tag; 32]), Secret::new([tag ^ 0xff; 64]))
}

fn xk_transcript(range_i: VersionRange, range_r: VersionRange) -> Value {
    let s_i = keypair(0x11);
    let s_r = keypair(0x22);
    let prekey = OneTimePrekey::from_seed(Secret::new([0x33; 64]));
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: s_r.x25519_public(),
        s1: &s1,
        range_r,
    };
    let (mut rng_i, mut rng_r) = (
        Recorder::new(b"xk-initiator"),
        Recorder::new(b"xk-responder"),
    );
    let (mut tr_i, mut tr_r) = (Steps::default(), Steps::default());
    let app = (
        b"app-1".as_slice(),
        b"app-2".as_slice(),
        b"app-3".as_slice(),
    );

    let mut f1 = [0u8; 4096];
    let (mut init, n1) = Initiator::flight1(
        &inv,
        range_i,
        AddressType::Pairwise,
        app.0,
        &mut rng_i,
        &mut f1,
        &mut tr_i,
    )
    .unwrap();

    let mut buf = [0u8; 64];
    let (mut resp, _) = Responder::read_flight1(
        &s_r,
        &prekey,
        range_r,
        AddressType::Pairwise,
        &f1[..n1],
        &mut buf,
        &mut tr_r,
    )
    .unwrap();

    let mut f2 = [0u8; 4096];
    let n2 = resp.flight2(app.1, &mut rng_r, &mut f2, &mut tr_r).unwrap();
    init.read_flight2(&f2[..n2], &mut buf, &mut tr_i).unwrap();

    let mut f3 = [0u8; 4096];
    let (ki, n3) = init.flight3(&s_i, app.2, &mut f3, &mut tr_i).unwrap();
    let (kr, _, _) = resp.read_flight3(&f3[..n3], &mut buf, &mut tr_r).unwrap();

    assert_eq!(ki.rk.expose(), kr.rk.expose());
    // CRY-104: one h at the two parties after flight 1.
    assert_eq!(tr_i.0[6]["h"], tr_r.0[6]["h"]);

    json!({
        "range_i": [range_i.min, range_i.max], "range_r": [range_r.min, range_r.max],
        "address_type": AddressType::Pairwise as u8, "mode": xk::MODE,
        "initiator_static": { "x_sk": hex(&[0x11; 32]), "d_z": hex(&[0x11 ^ 0xff; 64]), "pk_x": hex(&s_i.x25519_public()) },
        "responder_static": { "x_sk": hex(&[0x22; 32]), "d_z": hex(&[0x22 ^ 0xff; 64]), "pk_x": hex(&s_r.x25519_public()) },
        "prekey": { "d_z": hex(&[0x33; 64]), "s1": hex(&s1), "pid": hex(&prekey_id(&s1)) },
        "app": { "app_1": hex(app.0), "app_2": hex(app.1), "app_3": hex(app.2) },
        "initiator_draws_in_order": { "note": "e_sk 32, e1 seed d||z 64, skem1 coin m 32, n_hs 16", "values": rng_i.draws },
        "responder_draws_in_order": { "note": "er_sk 32, ekem1 coin m 32", "values": rng_r.draws },
        "flight1": hex(&f1[..n1]), "flight2": hex(&f2[..n2]), "flight3": hex(&f3[..n3]),
        "initiator_steps": tr_i.0, "responder_steps": tr_r.0,
        "split": { "rk": hex(ki.rk.expose()), "hk_i2r": hex(ki.hk_i2r.expose()), "hk_r2i": hex(ki.hk_r2i.expose()), "transcript": hex(&ki.transcript[..]) },
    })
}

fn prekey_id(s1: &[u8; 1184]) -> [u8; 16] {
    xk::prekey_id(s1)
}

fn xk_bad_mode() -> Value {
    let s_r = keypair(0x22);
    let prekey = OneTimePrekey::from_seed(Secret::new([0x33; 64]));
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: s_r.x25519_public(),
        s1: &s1,
        range_r: VersionRange::V1,
    };
    let mut rng = Recorder::new(b"xk-initiator");
    let mut f1 = [0u8; 4096];
    let (_, n1) = Initiator::flight1(
        &inv,
        VersionRange::V1,
        AddressType::Pairwise,
        b"",
        &mut rng,
        &mut f1,
        &mut umbra_crypto::handshake::NoTrace,
    )
    .unwrap();

    f1[2] = 0x02;

    let mut buf = [0u8; 64];
    let mut tr = Steps::default();
    let r = Responder::read_flight1(
        &s_r,
        &prekey,
        VersionRange::V1,
        AddressType::Pairwise,
        &f1[..n1],
        &mut buf,
        &mut tr,
    );
    assert_eq!(r.err(), Some(Error::Handshake));
    assert!(
        tr.0.is_empty(),
        "the responder aborts before MixHash(prologue)"
    );

    json!({ "flight1": hex(&f1[..n1]), "result": "abort before MixHash(prologue)", "responder_steps": [] })
}

fn nk_transcript() -> Value {
    let s_sk = StaticSecret::from([0x44u8; 32]);
    let relay = nk::RelayStatic {
        s: *XPublic::from(&s_sk).as_bytes(),
        relay_id: [0x55; 32],
    };
    let (mut rng_c, mut rng_r) = (Recorder::new(b"nk-client"), Recorder::new(b"nk-relay"));
    let (mut tr_c, mut tr_r) = (Steps::default(), Steps::default());

    let mut f1 = [0u8; nk::FLIGHT1_LEN];
    let client = nk::Client::flight1(&relay, &mut rng_c, &mut f1, &mut tr_c).unwrap();
    let hop = nk::Relay::read_flight1(&relay, &s_sk, &f1, &mut tr_r).unwrap();
    let mut f2 = [0u8; nk::FLIGHT2_LEN];
    let ss_r = hop.flight2(&mut rng_r, &mut f2, &mut tr_r).unwrap();
    let ss_c = client.read_flight2(&f2, &mut tr_c).unwrap();
    assert_eq!(ss_c.expose(), ss_r.expose());

    json!({
        "relay": { "s_sk": hex(&[0x44; 32]), "ntor_pk": hex(&relay.s), "relay_id": hex(&relay.relay_id) },
        "client_draws_in_order": { "note": "e_sk 32, e1 seed d||z 64", "values": rng_c.draws },
        "relay_draws_in_order": { "note": "er_sk 32, ekem1 coin m 32", "values": rng_r.draws },
        "flight1": hex(&f1), "flight2": hex(&f2),
        "client_steps": tr_c.0, "relay_steps": tr_r.0,
        "ss_hop": hex(ss_c.expose()),
    })
}

fn build() -> Value {
    json!({
        "note": "UMBRA-XKhfs and UMBRA-NKhfs transcripts of Part 5 §5.4.8 and §5.4.9. Self-generated; not independently confirmed. Each step records ck, h, and n after that step.",
        "xk": xk_transcript(VersionRange::V1, VersionRange::V1),
        "xk_ranges_differ": xk_transcript(VersionRange { min: 1, max: 1 }, VersionRange { min: 1, max: 2 }),
        "xk_bad_mode": xk_bad_mode(),
        "nk": nk_transcript(),
    })
}

#[test]
#[ignore = "writes the vector file; run by hand"]
fn generate() {
    fs::write(path(), serde_json::to_string_pretty(&build()).unwrap()).unwrap();
}

#[test]
fn handshake_vectors_hold() {
    let fresh = build();
    let stored: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(stored, fresh);
}
