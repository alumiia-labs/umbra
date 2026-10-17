//! Known-answer tests of the ML-KEM-768 primitive against the vendored
//! corpora (Part 14 §14.5.2). Nothing here reaches the network.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    deprecated
)]

use std::{fs, path::PathBuf};

use kem::Decapsulate;
use ml_kem::{
    array::Array, Ciphertext, DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, KeyExport,
    MlKem768, Seed, B32,
};
use serde_json::Value;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}

fn read(rel: &str) -> String {
    let path = vectors().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).expect("json")
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn field<'a>(t: &'a Value, name: &str) -> &'a str {
    t[name].as_str().unwrap_or_else(|| panic!("field {name}"))
}

fn groups_768<'a>(v: &'a Value, function: Option<&str>) -> impl Iterator<Item = &'a Value> {
    let function = function.map(str::to_owned);
    v["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(move |g| {
            g["parameterSet"] == "ML-KEM-768"
                && function.as_deref().is_none_or(|f| g["function"] == f)
        })
}

fn dk_from_seed(d: &[u8], z: &[u8]) -> DecapsulationKey<MlKem768> {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(d);
    seed[32..].copy_from_slice(z);
    DecapsulationKey::from_seed(Seed::from(seed))
}

fn dk_from_expanded(dk: &[u8]) -> Result<DecapsulationKey<MlKem768>, ml_kem::InvalidKey> {
    let enc = Array::try_from(dk).expect("dk length");
    DecapsulationKey::<MlKem768>::from_expanded_bytes(&enc)
}

fn ek_from_bytes(ek: &[u8]) -> Result<EncapsulationKey<MlKem768>, ml_kem::InvalidKey> {
    let enc = Array::try_from(ek).expect("ek length");
    EncapsulationKey::<MlKem768>::new(&enc)
}

fn ct(c: &[u8]) -> Ciphertext<MlKem768> {
    Array::try_from(c).expect("ct length")
}

fn m32(m: &[u8]) -> B32 {
    Array::try_from(m).expect("m length")
}

#[test]
fn acvp_key_generation() {
    let prompt = json("acvp/ML-KEM-keyGen-FIPS203/prompt.json");
    let expected = json("acvp/ML-KEM-keyGen-FIPS203/expectedResults.json");
    let mut count = 0;

    for g in groups_768(&prompt, None) {
        let eg = expected["testGroups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["tgId"] == g["tgId"])
            .expect("expected group");

        for (t, e) in g["tests"]
            .as_array()
            .unwrap()
            .iter()
            .zip(eg["tests"].as_array().unwrap())
        {
            assert_eq!(t["tcId"], e["tcId"]);
            let dk = dk_from_seed(&hex(field(t, "d")), &hex(field(t, "z")));
            assert_eq!(
                dk.encapsulation_key().to_bytes().as_slice(),
                hex(field(e, "ek"))
            );
            assert_eq!(dk.to_expanded_bytes().as_slice(), hex(field(e, "dk")));
            count += 1;
        }
    }

    assert_eq!(count, 25);
}

#[test]
fn acvp_encapsulation() {
    let v = json("acvp/ML-KEM-encapDecap-FIPS203/internalProjection.json");
    let mut count = 0;

    for g in groups_768(&v, Some("encapsulation")) {
        for t in g["tests"].as_array().unwrap() {
            let ek = ek_from_bytes(&hex(field(t, "ek"))).expect("ek");
            let (c, k) = ek.encapsulate_deterministic(&m32(&hex(field(t, "m"))));
            assert_eq!(c.as_slice(), hex(field(t, "c")));
            assert_eq!(k.as_slice(), hex(field(t, "k")));
            count += 1;
        }
    }

    assert_eq!(count, 25);
}

#[test]
fn acvp_decapsulation_with_implicit_rejection() {
    let v = json("acvp/ML-KEM-encapDecap-FIPS203/internalProjection.json");
    let mut count = 0;

    for g in groups_768(&v, Some("decapsulation")) {
        for t in g["tests"].as_array().unwrap() {
            let dk = dk_from_expanded(&hex(field(t, "dk"))).expect("dk");
            let k = dk.decapsulate(&ct(&hex(field(t, "c"))));
            assert_eq!(k.as_slice(), hex(field(t, "k")), "tcId {}", t["tcId"]);
            count += 1;
        }
    }

    assert_eq!(count, 10);
}

#[test]
fn acvp_key_checks() {
    let v = json("acvp/ML-KEM-encapDecap-FIPS203/internalProjection.json");
    let mut count = 0;

    for g in groups_768(&v, Some("encapsulationKeyCheck")) {
        for t in g["tests"].as_array().unwrap() {
            let ok = ek_from_bytes(&hex(field(t, "ek"))).is_ok();
            assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "tcId {}", t["tcId"]);
            count += 1;
        }
    }

    for g in groups_768(&v, Some("decapsulationKeyCheck")) {
        for t in g["tests"].as_array().unwrap() {
            let ok = dk_from_expanded(&hex(field(t, "dk"))).is_ok();
            assert_eq!(ok, t["testPassed"].as_bool().unwrap(), "tcId {}", t["tcId"]);
            count += 1;
        }
    }

    assert_eq!(count, 20);
}

/// `name = hex` lines, first occurrence of each name. A value that is not
/// hex (the intermediate file also lists coefficient arrays) is skipped.
fn kv(text: &str) -> std::collections::HashMap<String, Vec<u8>> {
    let mut out = std::collections::HashMap::new();

    for line in text.lines() {
        if let Some((k, v)) = line.split_once(" = ") {
            let v = v.trim();
            if v.len() % 2 == 0 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.entry(k.trim().to_owned()).or_insert_with(|| hex(v));
            }
        }
    }

    out
}

#[test]
fn cctv_strcmp() {
    let v = kv(&read("cctv/ML-KEM/strcmp/ML-KEM-768.txt"));
    let dk = dk_from_expanded(&v["dk"]).expect("dk");

    assert_eq!(dk.decapsulate(&ct(&v["c"])).as_slice(), v["K"]);
}

// The C2SP key-generation values follow the initial public draft of FIPS
// 203, which hashed `d` alone; the final standard hashes `d || k`. Thus the
// key comes from its expanded form here, and the seeds are not used. The
// encapsulation and decapsulation halves did not change between the two.
fn cctv_encaps_decaps(rel: &str) {
    let v = kv(&read(rel));
    let dk = dk_from_expanded(&v["dk"]).expect("dk");
    assert_eq!(dk.encapsulation_key().to_bytes().as_slice(), v["ek"]);

    let (c, k) = dk
        .encapsulation_key()
        .encapsulate_deterministic(&m32(&v["m"]));

    assert_eq!(c.as_slice(), v["c"]);
    assert_eq!(k.as_slice(), v["K"]);
    assert_eq!(dk.decapsulate(&c).as_slice(), v["K"]);
}

#[test]
fn cctv_unlucky_sample() {
    cctv_encaps_decaps("cctv/ML-KEM/unluckysample/ML-KEM-768.txt");
}

#[test]
fn cctv_intermediate_end_values() {
    cctv_encaps_decaps("cctv/ML-KEM/intermediate/ML-KEM-768.txt");
}

#[test]
fn cctv_modulus_rejects_every_unreduced_key() {
    let text = read("cctv/ML-KEM/modulus/ML-KEM-768.txt");
    let mut count = 0;

    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        assert!(ek_from_bytes(&hex(line.trim())).is_err(), "line {count}");
        count += 1;
    }

    assert_eq!(count, 780);
}
