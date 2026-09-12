//! Braid codeword vectors (Part 5 rule `CRY-083`, Part 6 rules `WIR-352`
//! and `WIR-353`): the codeword at each of the three widths from stated
//! seeds, a loss pattern that drops `r` chunks, and the check that no
//! 32-byte window of the codeword equals `d` or `z`.
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

use ml_dsa::KeyExport;
use ml_kem::{array::Array, DecapsulationKey, MlKem768, Seed};
use serde_json::{json, Value};
use umbra_crypto::ratchet::codeword::{Collector, Material, Width};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/umbra/braid.json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const D: [u8; 32] = [0xa1; 32];
const Z: [u8; 32] = [0xb2; 32];
const M: [u8; 32] = [0xc3; 32];

fn build() -> Value {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&D);
    seed[32..].copy_from_slice(&Z);
    let dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed));
    let ek: [u8; 1184] = dk.encapsulation_key().to_bytes().into();
    // The ciphertext of a real epoch targets the peer's key; one key serves
    // a vector, because the code sees bytes only.
    let (ct, _) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&Array::from(M));
    let ct: [u8; 1088] = ct.into();
    let material = Material::new(&ek, &ct);

    // WIR-353: no 32-byte window of the codeword equals d or z.
    for win in material.0.windows(32) {
        assert_ne!(win, &D[..]);
        assert_ne!(win, &Z[..]);
    }

    let mut widths = Vec::new();
    for width in [Width::W32, Width::W64, Width::W128] {
        let code = width.code();
        let w = width.bytes();
        let mut all = vec![0u8; code.n() * w];
        material.encode(width, &mut all).unwrap();
        let chunks: Vec<Value> = (0..code.n())
            .map(|i| {
                json!({
                    "index": i,
                    "kind": width.kind_at(i).unwrap() as u8,
                    "chunk": hex(&all[i * w..(i + 1) * w]),
                })
            })
            .collect();
        // CRY-083: a loss pattern that drops r chunks, spread over data and
        // parity positions.
        let dropped: Vec<usize> = (0..code.r).map(|i| (i * 7 + 2) % code.n()).collect();
        let mut col = Collector::new(width);
        for i in 0..code.n() {
            if !dropped.contains(&i) {
                col.put(i, &all[i * w..(i + 1) * w]).unwrap();
            }
        }
        assert_eq!(col.rebuild().unwrap().0, material.0);
        widths.push(json!({
            "width": w, "k": code.k, "r": code.r, "n": code.n(),
            "pq_frame_len": width.frame_len(),
            "chunks": chunks,
            "loss_pattern_dropped": dropped,
        }));
    }

    json!({
        "note": "Braid codeword of Part 5 §5.5.2. Self-generated; not independently confirmed. The Reed-Solomon evaluation points are x_i = 2^i.",
        "d": hex(&D), "z": hex(&Z), "m": hex(&M),
        "ek": hex(&ek), "ct": hex(&ct),
        "header": hex(&material.0[..64]),
        "codeword": hex(&material.0),
        "widths": widths,
    })
}

#[test]
#[ignore = "writes the vector file; run by hand"]
fn generate() {
    fs::write(path(), serde_json::to_string_pretty(&build()).unwrap()).unwrap();
}

#[test]
fn braid_vectors_hold() {
    let stored: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(stored, build());
}
