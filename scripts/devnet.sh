#!/usr/bin/env bash
# Runs a test network of five relays on this machine, on the ports 7441 to
# 7445, under the test authority of tests/fixtures/tls: one ingress relay,
# two relays of layer 2, and two queue relays. Thus the circuits of a client
# take chains that differ, and two clients can hold their queues at two
# relays. An Android
# emulator reaches them at 10.0.2.2. The secrets of these relays are in the
# repository, thus this network protects nothing.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build -p umbra-relay --features native
# Each relay keeps its queues in a file here, thus a restart of this script
# ends no contact. Delete the directory for an empty network.
mkdir -p target/devnet

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
# The queue relays start first, thus each dial of a lower layer finds a port
# that accepts. Relays 3 and 5 are of layer 3, and relays 2 and 4 of layer 2.
for relay in 3 5 2 4 1; do
    target/debug/umbra-relay "tests/fixtures/devnet/relay$relay.conf" &
    pids+=($!)
done
wait
