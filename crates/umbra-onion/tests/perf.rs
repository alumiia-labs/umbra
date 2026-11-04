//! The cost of one onion layer in each bucket. Each test is `#[ignore]`.
//!
//! `cargo test --release -p umbra-onion --test perf -- --ignored --nocapture`

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use std::{hint::black_box, time::Instant};

use aes::{
    cipher::{KeyInit, KeyIvInit, StreamCipher},
    Aes256,
};
use polyval::{universal_hash::UniversalHash, Polyval};
use umbra_crypto::secret::Secret;
use umbra_onion::circuit::{Position, RelayHop};
use umbra_wire::bucket::Bucket;

const BUCKETS: [Bucket; 4] = [Bucket::B0, Bucket::B1, Bucket::B2, Bucket::B3];
const ROUNDS: usize = 9;

/// The cells that one round takes in a bucket: near 64 MiB of bodies.
fn cells_of(bucket: Bucket) -> u32 {
    u32::try_from((64 << 20) / bucket.body_len()).unwrap()
}

/// The median nanoseconds of one call of `step`.
fn median_ns(count: u32, mut step: impl FnMut()) -> f64 {
    let mut rounds = Vec::new();

    for _ in 0..ROUNDS {
        let start = Instant::now();
        for _ in 0..count {
            step();
        }
        rounds.push(start.elapsed().as_nanos() as f64 / f64::from(count));
    }

    rounds.sort_by(f64::total_cmp);
    rounds[ROUNDS / 2]
}

fn hop(position: Position) -> RelayHop {
    RelayHop::new(&Secret::new([7; 32]), 1, position)
}

#[test]
#[ignore = "a timing run"]
fn perf_the_stages_of_one_layer() {
    type Ctr = ctr::Ctr128BE<Aes256>;

    let key = [9u8; 32];
    let schedule = median_ns(1_000_000, || {
        black_box(Aes256::new(black_box(&key).into()));
    });
    println!("onion aes-256 key schedule: {schedule:.0} ns");

    for bucket in BUCKETS {
        let count = cells_of(bucket);
        let mut body = vec![0x42u8; bucket.body_len()];

        let stream = median_ns(count, || {
            let iv = [1u8; 16];
            Ctr::new(black_box(&key).into(), (&iv).into()).apply_keystream(&mut body);
        });

        let hash = median_ns(count, || {
            let mut hasher = Polyval::new(black_box(&[3u8; 16]).into());
            hasher.update_padded(black_box(&body));
            black_box(hasher.finalize());
        });

        println!("onion {bucket:?} ctr with its key schedule: {stream:.0} ns");
        println!("onion {bucket:?} polyval: {hash:.0} ns");
    }
}

#[test]
#[ignore = "a timing run"]
fn perf_one_layer_at_each_position() {
    for bucket in BUCKETS {
        let count = cells_of(bucket);
        let mut body = vec![0x42u8; bucket.body_len()];
        let mut tag = [5u8; 16];

        let mut middle = hop(Position::Middle);
        let forward = median_ns(count, || {
            tag = middle.forward(&tag, &mut body).unwrap();
        });

        let mut middle = hop(Position::Middle);
        let backward = median_ns(count, || {
            tag = middle.backward(&tag, &mut body).unwrap();
        });

        // The endpoint updates its key set at each cell (`NET-205`). A
        // backward step needs no left block that checks.
        let mut endpoint = hop(Position::Endpoint);
        let endpoint_back = median_ns(count.min(200_000), || {
            tag = endpoint.backward(&tag, &mut body).unwrap();
        });

        println!(
            "onion {bucket:?} middle forward {forward:.0} ns, middle backward {backward:.0} ns, \
             endpoint backward {endpoint_back:.0} ns"
        );
    }
}
