//! Known-answer tests of the ML-DSA-65 primitive against the vendored ACVP
//! corpus (Part 15 §15.5.2). Nothing here reaches the network.
//!
//! UMBRA uses the pure variant with an empty context. The corpus also holds
//! HashML-DSA groups (`preHash`), which this harness skips because no rule of
//! the specification uses them.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    deprecated
)]

use std::{convert::Infallible, fs, path::PathBuf};

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, KeyExport, MlDsa65, Seed, Signature,
    SigningKey, VerifyingKey, B32,
};
use rand_core::{TryCryptoRng, TryRng};
use serde_json::Value;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors")
        .join(rel);
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

fn groups_65(v: &Value) -> impl Iterator<Item = &Value> {
    v["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|g| g["parameterSet"] == "ML-DSA-65")
}

fn sk_from_expanded(sk: &[u8]) -> ExpandedSigningKey<MlDsa65> {
    let enc = sk.try_into().expect("sk length");
    ExpandedSigningKey::<MlDsa65>::from_expanded(&enc)
}

fn vk_from_bytes(pk: &[u8]) -> VerifyingKey<MlDsa65> {
    let enc: EncodedVerifyingKey<MlDsa65> = pk.try_into().expect("pk length");
    VerifyingKey::decode(&enc)
}

fn sig_from_bytes(sig: &[u8]) -> Option<Signature<MlDsa65>> {
    let enc: EncodedSignature<MlDsa65> = sig.try_into().expect("sig length");
    Signature::decode(&enc)
}

fn b32(b: &[u8]) -> B32 {
    b.try_into().expect("32 bytes")
}

/// A generator that gives one fixed value, for the hedged vectors that
/// state `rnd`.
struct Fixed(B32);

impl TryRng for Fixed {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.copy_from_slice(&self.0[..dst.len()]);
        Ok(())
    }
}
impl TryCryptoRng for Fixed {}

#[test]
fn acvp_key_generation() {
    let prompt = json("acvp/ML-DSA-keyGen-FIPS204/prompt.json");
    let expected = json("acvp/ML-DSA-keyGen-FIPS204/expectedResults.json");
    let mut count = 0;
    for g in groups_65(&prompt) {
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
            let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(
                <[u8; 32]>::try_from(hex(field(t, "seed"))).unwrap(),
            ));
            let vk = sk.expanded_key().verifying_key();
            assert_eq!(vk.to_bytes().as_slice(), hex(field(e, "pk")));
            assert_eq!(
                sk.expanded_key().to_expanded().as_slice(),
                hex(field(e, "sk"))
            );
            count += 1;
        }
    }
    assert_eq!(count, 25);
}

#[test]
fn acvp_signature_generation() {
    let v = json("acvp/ML-DSA-sigGen-FIPS204/internalProjection.json");
    let (mut count, mut skipped) = (0, 0);
    for g in groups_65(&v) {
        if g["preHash"] == "preHash" {
            skipped += g["tests"].as_array().unwrap().len();
            continue;
        }
        let deterministic = g["deterministic"].as_bool().unwrap();
        let external = g["signatureInterface"] == "external";
        let external_mu = g["externalMu"].as_bool().unwrap_or(false);
        for t in g["tests"].as_array().unwrap() {
            let sk = sk_from_expanded(&hex(field(t, "sk")));
            let rnd = if deterministic {
                B32::default()
            } else {
                b32(&hex(field(t, "rnd")))
            };
            let sig = if external_mu {
                if deterministic {
                    sk.sign_mu_deterministic(&hex(field(t, "mu")).as_slice().try_into().unwrap())
                } else {
                    sk.sign_mu_randomized(
                        &hex(field(t, "mu")).as_slice().try_into().unwrap(),
                        &mut Fixed(rnd),
                    )
                    .unwrap()
                }
            } else if external {
                let msg = hex(field(t, "message"));
                let ctx = hex(field(t, "context"));
                if deterministic {
                    sk.sign_deterministic(&msg, &ctx).unwrap()
                } else {
                    sk.sign_randomized(&msg, &ctx, &mut Fixed(rnd)).unwrap()
                }
            } else {
                sk.sign_internal(&[&hex(field(t, "message"))], &rnd)
            };
            assert_eq!(
                sig.encode().as_slice(),
                hex(field(t, "signature")),
                "tcId {}",
                t["tcId"]
            );
            count += 1;
        }
    }
    assert_eq!(count, 90);
    assert_eq!(skipped, 30);
}

#[test]
fn acvp_signature_verification() {
    let v = json("acvp/ML-DSA-sigVer-FIPS204/internalProjection.json");
    let (mut count, mut skipped) = (0, 0);
    for g in groups_65(&v) {
        if g["preHash"] == "preHash" {
            skipped += g["tests"].as_array().unwrap().len();
            continue;
        }
        let external = g["signatureInterface"] == "external";
        let external_mu = g["externalMu"].as_bool().unwrap_or(false);
        for t in g["tests"].as_array().unwrap() {
            let vk = vk_from_bytes(&hex(field(t, "pk")));
            let passed = match sig_from_bytes(&hex(field(t, "signature"))) {
                None => false,
                Some(sig) => {
                    if external_mu {
                        vk.verify_mu(&hex(field(t, "mu")).as_slice().try_into().unwrap(), &sig)
                    } else if external {
                        vk.verify_with_context(
                            &hex(field(t, "message")),
                            &hex(field(t, "context")),
                            &sig,
                        )
                    } else {
                        vk.verify_internal(&hex(field(t, "message")), &sig)
                    }
                }
            };
            assert_eq!(
                passed,
                t["testPassed"].as_bool().unwrap(),
                "tcId {} ({})",
                t["tcId"],
                field(t, "reason")
            );
            count += 1;
        }
    }
    assert_eq!(count, 45);
    assert_eq!(skipped, 15);
}
