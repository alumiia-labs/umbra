#!/usr/bin/env bash
# Runs a test network of three relays on this machine, on the ports 7441,
# 7442, and 7443, under the test authority of tests/fixtures/tls. An Android
# emulator reaches them at 10.0.2.2. The secrets of these relays are in the
# repository, thus this network protects nothing.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build -p umbra-relay --features native

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
# The queue relay starts first, thus each dial of a lower layer finds a port
# that accepts.
for layer in 3 2 1; do
    target/debug/umbra-relay "tests/fixtures/devnet/relay$layer.conf" &
    pids+=($!)
done
wait
