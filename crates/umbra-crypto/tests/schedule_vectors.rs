//! The rekey schedule vector of Part 5 rule `CRY-134`: `T` occurs while an
//! epoch is incomplete, and the epoch continues under one number until it
//! completes and the next chain starts.
//!
//! The vector records each record of a scripted conversation: the sender,
//! the epoch its frame named, the chunk index, whether it started a DH
//! chain, and the running count of root-key mixes at each party. It is
//! self-generated and not independently confirmed. The ignored test
//! `generate` writes the file; run `scripts/vectors.py` afterwards.
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
    handshake::xk::{InitialDh, SessionKeys},
    ratchet::{
        braid::{Ratchet, EPOCH_SECONDS},
        codeword::Width,
        dr::Role,
    },
    secret::Secret,
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/umbra/schedule.json")
}

struct Rng {
    seed: [u8; 32],
    counter: u64,
}

impl Rng {
    fn new(seed: &[u8]) -> Self {
        let mut out = [0u8; 32];
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.finalize_xof_into(&mut out);
        Self {
            seed: out,
            counter: 0,
        }
    }
}

impl TryRng for Rng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let mut hasher = Shake256::default();
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_le_bytes());
        self.counter += 1;
        hasher.finalize_xof_into(dst);
        Ok(())
    }
}
impl TryCryptoRng for Rng {}

fn keys(dh: InitialDh) -> SessionKeys {
    SessionKeys {
        rk: Secret::new([0x51; 32]),
        hk_i2r: Secret::new([0x52; 32]),
        hk_r2i: Secret::new([0x53; 32]),
        transcript: umbra_crypto::zeroize::Zeroizing::new([0; 32]),
        dh_initial: dh,
    }
}

struct Run {
    initiator: Ratchet,
    responder: Ratchet,
    rng: Rng,
    now: u64,
    events: Vec<Value>,
    last_dh: [Option<[u8; 32]>; 2],
}

impl Run {
    fn send(&mut self, from_initiator: bool, count: usize) {
        for _ in 0..count {
            let (sender, receiver) = if from_initiator {
                (&mut self.initiator, &mut self.responder)
            } else {
                (&mut self.responder, &mut self.initiator)
            };
            let mut record = vec![0u8; sender.overhead_with_frame() + 4];
            let len = sender
                .send(b"text", true, self.now, &mut self.rng, &mut record)
                .unwrap();
            let mut plain = vec![0u8; 8];
            let opened = receiver
                .receive(&record[..len], self.now, &mut self.rng, &mut plain)
                .unwrap();
            assert_eq!(&plain[..opened.len], b"text");
            let slot = usize::from(!from_initiator);
            let chain_start = self.last_dh[slot] != Some(opened.header.dh_pk);
            self.last_dh[slot] = Some(opened.header.dh_pk);
            self.events.push(json!({
                "t": self.now,
                "from": if from_initiator { "initiator" } else { "responder" },
                "epoch": opened.peer_epoch,
                "chain_start": chain_start,
                "n": opened.header.n,
                "initiator_epoch": self.initiator.epoch(),
                "responder_epoch": self.responder.epoch(),
                "initiator_mixed": self.initiator.mixed(),
                "responder_mixed": self.responder.mixed(),
            }));
            self.now += 1;
        }
    }
}

fn build() -> Value {
    let mut rng = Rng::new(b"schedule");
    let er_sk = StaticSecret::from([0x54u8; 32]);
    let er = *XPublic::from(&er_sk).as_bytes();
    let initiator = Ratchet::new(
        keys(InitialDh::Peer(er)),
        Role::Initiator,
        Width::W64,
        0,
        &mut rng,
    )
    .unwrap();
    let responder = Ratchet::new(
        keys(InitialDh::Own(er_sk)),
        Role::Responder,
        Width::W64,
        0,
        &mut rng,
    )
    .unwrap();
    let mut run = Run {
        initiator,
        responder,
        rng,
        now: 0,
        events: Vec::new(),
        last_dh: [None, None],
    };

    // Phase 1: a few records each way; both epochs stay incomplete.
    run.send(true, 5);
    run.send(false, 5);
    // T passes inside the incomplete epochs.
    run.now += EPOCH_SECONDS;
    run.send(true, 5);
    run.send(false, 5);
    let after_t = (run.initiator.epoch(), run.responder.epoch());
    assert_eq!(
        after_t,
        (1, 0),
        "the epoch number holds across T while incomplete"
    );

    // Phase 2: enough records for the codewords to land and the epochs to
    // complete; the advances then happen at chain starts.
    for _ in 0..4 {
        run.send(true, 45);
        run.send(false, 45);
    }
    let end = (run.initiator.epoch(), run.responder.epoch());
    assert!(
        end.0 >= 2 && end.1 >= 1,
        "epochs after the schedule: {end:?}"
    );
    assert_eq!(run.initiator.mixed(), run.responder.mixed());

    json!({
        "note": "Rekey schedule of Part 5 §5.5.3 rule CRY-134 at width 64. Self-generated; not independently confirmed. T = EPOCH_SECONDS passes after the first ten records while both epochs are incomplete.",
        "width": 64,
        "epoch_after_t": { "initiator": after_t.0, "responder": after_t.1 },
        "epoch_at_end": { "initiator": end.0, "responder": end.1 },
        "mixes_at_end": run.initiator.mixed(),
        "events": run.events,
    })
}

#[test]
#[ignore = "writes the vector file; run by hand"]
fn generate() {
    fs::write(path(), serde_json::to_string_pretty(&build()).unwrap()).unwrap();
}

#[test]
fn schedule_vector_holds() {
    let stored: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(stored, build());
}
