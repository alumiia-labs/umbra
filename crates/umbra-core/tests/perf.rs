//! The cost of the batching of commands into cells. Each test is
//! `#[ignore]`.
//!
//! `cargo test --release -p umbra-core --test perf -- --ignored --nocapture`

#![allow(clippy::unwrap_used, clippy::indexing_slicing, missing_docs)]

use std::{hint::black_box, time::Instant};

use umbra_core::session::batch::{unpack, Batcher, Range};
use umbra_wire::{
    bucket::Bucket,
    command::{Cmd, Command},
};

fn encoded(cmd: Cmd, payload_len: usize) -> Vec<u8> {
    let payload = vec![7u8; payload_len];
    let command = Command {
        cmd,
        corr_id: [1; 16],
        queue_id: [2; 32],
        auth: [3; 32],
        payload: &payload,
    };

    let mut out = vec![0u8; command.len()];
    command.encode(&mut out).unwrap();
    out
}

#[test]
#[ignore = "a timing run"]
fn perf_the_batcher_of_one_circuit() {
    let ack = encoded(Cmd::Ack, 4);
    let send = encoded(Cmd::Send, Bucket::B0.l6_record());
    let count = 2_000_000u32;

    let start = Instant::now();
    for _ in 0..count {
        let mut batcher = Batcher::new(Range::Queue);
        batcher.push(Cmd::Ack, ack.clone()).unwrap();
        batcher.push(Cmd::Ack, ack.clone()).unwrap();
        batcher.push(Cmd::Send, send.clone()).unwrap();
        black_box(batcher.next_cell());
        black_box(batcher.next_cell());
    }

    let batched = start.elapsed().as_nanos() as f64 / f64::from(count);

    let content = [ack.as_slice(), &ack].concat();
    let start = Instant::now();
    for _ in 0..count {
        black_box(unpack(black_box(&content), Bucket::B0).unwrap());
    }

    let split = start.elapsed().as_nanos() as f64 / f64::from(count);
    println!("batcher: three commands {batched:.0} ns, unpack of two {split:.0} ns");
}
