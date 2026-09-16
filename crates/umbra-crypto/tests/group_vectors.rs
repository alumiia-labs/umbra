//! Group key vectors of Part 11 §11.3 and §11.4.2: the member keys from a
//! roster seed, the symmetric pair key and a dense tag vector, the slot
//! chain and the queue credentials of one epoch, a sealed content record,
//! and one epoch-key slot under a deterministic encapsulation.
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
    group::{
        chain::{open_record, seal_record, EpochSecret},
        pair::{app_hash, EpochTag, RecordTag},
        slot::{self, sealed_len},
        MemberKeys, TAG_LEN,
    },
    kem,
    secret::Secret,
};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/umbra/group.json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const GROUP_ID: [u8; 32] = [0x67; 32];
const SEEDS: [[u8; 32]; 3] = [[0x61; 32], [0x62; 32], [0x63; 32]];
const EPOCH_SECRET: [u8; 32] = [0x6b; 32];
const EPOCH: u32 = 1;
const START_SLOT: u32 = 497_000;
const ROSTER_EPOCH: u32 = 1;

fn build() -> Value {
    let members: Vec<MemberKeys> = SEEDS
        .iter()
        .map(|seed| MemberKeys::from_seed(&Secret::new(*seed)))
        .collect();
    let member_json: Vec<Value> = members
        .iter()
        .zip(SEEDS.iter())
        .map(|(m, seed)| {
            json!({
                "seed": hex(seed),
                "pair_pk": hex(&m.pair_public()),
                "kem_pk": hex(&m.kem().public().to_bytes()),
                "roster_pk": hex(&m.roster().verifying_key().to_bytes()),
            })
        })
        .collect();

    // A dense tag vector from member 0 at slot t_e + 2, counter 1.
    let slot = START_SLOT + 2;
    let app = b"hello group";
    let hash = app_hash(app);
    let fields = RecordTag {
        group_id: &GROUP_ID,
        epoch: EPOCH,
        slot,
        sender_index: 0,
        counter: 1,
        roster_epoch: ROSTER_EPOCH,
        app_hash: &hash,
    };
    let mut tags = [[0u8; TAG_LEN]; 3];
    for (j, tag) in tags.iter_mut().enumerate().skip(1) {
        let key = members[0]
            .pair_key(&members[j].pair_public(), &GROUP_ID)
            .unwrap();
        *tag = key.record_tag(&fields);
        // The receiver derives the same key from its own side.
        let back = members[j]
            .pair_key(&members[0].pair_public(), &GROUP_ID)
            .unwrap();
        back.verify_record_tag(&fields, tag).unwrap();
    }

    // The slot chain of the epoch.
    let secret = EpochSecret::new(Secret::new(EPOCH_SECRET));
    let state = secret.start(&GROUP_ID, EPOCH, START_SLOT);
    let record_keys: Vec<Value> = (0..3)
        .map(|k| {
            json!({
                "slot": START_SLOT + k,
                "record_key": hex(state.record_key(START_SLOT + k).unwrap().expose()),
            })
        })
        .collect();
    let credentials = secret.credentials();

    // One content record: the tag vector and the app bytes as the body.
    let mut body: Vec<u8> = tags.iter().flat_map(|t| t.iter().copied()).collect();
    body.extend_from_slice(app);
    let plaintext = body.clone();
    let nonce = [0x0a; 12];
    let record_key = state.record_key(slot).unwrap();
    let tag = seal_record(&record_key, &nonce, &GROUP_ID, EPOCH, slot, &mut body).unwrap();
    let mut check = body.clone();
    open_record(
        &record_key,
        &nonce,
        &GROUP_ID,
        EPOCH,
        slot,
        &mut check,
        &tag,
    )
    .unwrap();
    assert_eq!(check, plaintext);

    // One epoch-key slot to member 1 from rotator 0, own_count 0.
    let epoch_tag = members[0]
        .pair_key(&members[1].pair_public(), &GROUP_ID)
        .unwrap()
        .epoch_tag(&EpochTag {
            group_id: &GROUP_ID,
            epoch: EPOCH,
            start_slot: START_SLOT,
            roster_epoch: ROSTER_EPOCH,
            epoch_secret: secret.expose(),
        });
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&EPOCH_SECRET);
    payload.extend_from_slice(&epoch_tag);
    payload.push(0);
    assert_eq!(payload.len(), 47);
    let ek_x = [0x11; 32];
    let m = [0x22; 32];
    let (ct, shared) = kem::encapsulate_deterministic(
        members[1].kem().public(),
        Secret::new(ek_x),
        Secret::new(m),
    );
    let mut sealed = vec![0u8; sealed_len(payload.len())];
    slot::seal_with(&ct, &shared, &GROUP_ID, EPOCH, 1, &payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; payload.len()];
    slot::open(members[1].kem(), &GROUP_ID, EPOCH, 1, &sealed, &mut opened).unwrap();
    assert_eq!(opened, payload);

    json!({
        "note": "Group keys of Part 11 §11.3 and §11.4.2. Self-generated; not independently confirmed. The slot payload follows the SlotPayload layout of Part 6 §6.4.6 at own_count 0.",
        "group_id": hex(&GROUP_ID),
        "members": member_json,
        "record_tag": {
            "epoch": EPOCH, "slot": slot, "sender_index": 0, "counter": 1,
            "roster_epoch": ROSTER_EPOCH, "app": hex(app), "app_hash": hex(&hash),
            "dense_tags": tags.iter().map(|t| hex(t)).collect::<Vec<_>>(),
        },
        "epoch": {
            "k_e": hex(&EPOCH_SECRET), "e": EPOCH, "t_e": START_SLOT,
            "record_keys": record_keys,
            "read_pk": hex(&credentials.read_public()),
            "write_pk": hex(&credentials.write_public()),
        },
        "content_record": {
            "nonce": hex(&nonce), "plaintext": hex(&plaintext),
            "ciphertext": hex(&body), "tag": hex(&tag),
        },
        "epoch_key_slot": {
            "index": 1, "rotator": 0, "own_count": 0,
            "ek_x": hex(&ek_x), "m": hex(&m),
            "epoch_tag": hex(&epoch_tag), "payload": hex(&payload),
            "sealed": hex(&sealed),
        },
    })
}

#[test]
#[ignore = "writes the vector file; run by hand"]
fn generate() {
    fs::write(path(), serde_json::to_string_pretty(&build()).unwrap()).unwrap();
}

#[test]
fn group_vectors_hold() {
    let stored: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(stored, build());
}
