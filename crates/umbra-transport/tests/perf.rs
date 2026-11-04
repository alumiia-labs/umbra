//! The cost of the frame and the session link in each bucket. Each test is
//! `#[ignore]`.
//!
//! `cargo test --release -p umbra-transport --test perf -- --ignored --nocapture`

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use std::{hint::black_box, time::Instant};

use umbra_crypto::secret::Secret;
use umbra_transport::{
    link::{ClientLink, RelayLink},
    websocket,
};
use umbra_wire::{capsule, session::SessionControl};

/// The cell lengths of the buckets.
const CELLS: [usize; 4] = [512, 2_048, 8_192, 32_768];
const ROUNDS: usize = 9;

/// The frames that one round takes: near 256 MiB of bytes.
fn count_of(len: usize) -> u32 {
    u32::try_from((256 << 20) / len).unwrap()
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

#[test]
#[ignore = "a timing run"]
fn perf_the_websocket_frame() {
    for cell in CELLS {
        let capsule = vec![0xA5u8; cell + 18];
        let mut masked = vec![0u8; websocket::frame_len(capsule.len(), true)];
        let mut plain = vec![0u8; websocket::frame_len(capsule.len(), false)];
        let mut out = vec![0u8; capsule.len()];
        let count = count_of(cell);

        let encode_plain = median_ns(count, || {
            websocket::encode(black_box(&capsule), None, &mut plain).unwrap();
        });

        let encode_masked = median_ns(count, || {
            let mask = black_box(&[1, 2, 3, 4]);
            websocket::encode(black_box(&capsule), Some(mask), &mut masked).unwrap();
        });

        let decode_plain = median_ns(count, || {
            websocket::decode(black_box(&plain), false, &mut out).unwrap();
        });

        let decode_masked = median_ns(count, || {
            websocket::decode(black_box(&masked), true, &mut out).unwrap();
        });

        println!(
            "frame {cell}: encode plain {encode_plain:.0} ns, encode masked {encode_masked:.0} \
             ns, decode plain {decode_plain:.0} ns, decode masked {decode_masked:.0} ns"
        );
    }
}

/// A client and a relay that hold one session.
fn pair(buffer: &mut [u8]) -> (ClientLink, RelayLink) {
    let (client, used) = ClientLink::open([1; 8], Secret::new([2; 32]), buffer).unwrap();
    let (_, value, _) = capsule::parse(&buffer[..used]).unwrap();
    let relay = RelayLink::open(SessionControl::parse(value).unwrap()).unwrap();
    (client, relay)
}

#[test]
#[ignore = "a timing run"]
fn perf_the_session_link() {
    let mut buffer = vec![0u8; 40_000];
    let cell = vec![0x5Au8; 512];
    let count = 8_000_000u32;

    let (mut client, mut relay) = pair(&mut buffer);
    let used = client.send(&cell, &mut buffer).unwrap();
    let mut seq = 0u32;

    // The relay takes a new `seq` at each frame, as a link in order does.
    let mut capsule = buffer[..used].to_vec();
    let start = Instant::now();
    for _ in 0..count {
        capsule[14..17].copy_from_slice(&seq.to_be_bytes()[1..]);
        seq = (seq + 1) & 0xFF_FFFF;

        let (_, value, _) = capsule::parse(&capsule).unwrap();
        black_box(relay.receive(value).unwrap());
    }

    let taken = start.elapsed().as_nanos() as f64 / f64::from(count);
    println!("link receive in order: {taken:.0} ns");

    let (_, mut relay) = pair(&mut buffer);
    let sent = median_ns(1_000_000, || {
        relay.send(black_box(&cell), &mut buffer).unwrap();
    });
    println!("link send: {sent:.0} ns");
}
