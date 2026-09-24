#!/usr/bin/env bash
# Runs a test network of seven relays on this machine, on the ports 7441 to
# 7447, under the test authority of tests/fixtures/tls: two ingress relays,
# two relays of layer 2, and three queue relays. The three hold the three
# copies of a chunk (Part 12 §12.4). Thus the circuits of a client
# take chains that differ, and two clients can hold their queues at two
# relays. A client pins the two ingress relays, and with one of them down it
# dials the other one. An Android emulator reaches them at 10.0.2.2.
#
# Each relay signs its descriptor, and the seven test authorities sign a
# manifest of the seven (Part 10 §10.5.5). A relay reads its layer from that
# manifest. The seeds of the relays and of the authorities are in the
# repository, thus this network protects nothing.
#
# The Notification Delivery Relay of Part 8 §8.2 listens on port 7450, and
# the two ingress relays carry its OHTTP requests (`POST /ohttp`).
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build -p umbra-relay --features native
# Each relay keeps its queues in a file here, thus a restart of this script
# ends no contact. Delete the directory for an empty network.
mkdir -p target/devnet

for relay in 1 2 3 4 5 6 7; do
    target/debug/umbra-relay sign-descriptor \
        "tests/fixtures/devnet/relay$relay.conf" "target/devnet/relay$relay.desc"
done
# The manifest holds the present epoch, thus each start signs a new one.
target/debug/umbra-test-authority tests/fixtures/devnet/authority.conf target/devnet
# The relays and the debug build of the Android app hold the key set of the
# repository. The seed of the authorities gives the same one at each start.
cmp -s target/devnet/keyset.bin tests/fixtures/devnet/keyset.bin || {
    echo "the key set differs from tests/fixtures/devnet/keyset.bin"
    exit 1
}

# The debug build pins the gateway key of the NDR (`NTF-127`), and the seed
# of ndr.conf gives the same one at each start.
target/debug/umbra-ndr key-config tests/fixtures/devnet/ndr.conf     | python -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))"     | cmp -s - tests/fixtures/devnet/ndr-key-config.bin || {
    echo "the NDR key differs from tests/fixtures/devnet/ndr-key-config.bin"
    exit 1
}

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
# The queue relays start first, thus each dial of a lower layer finds a port
# that accepts.
target/debug/umbra-ndr tests/fixtures/devnet/ndr.conf &
pids+=($!)
for relay in 3 5 7 2 4 1 6; do
    target/debug/umbra-relay "tests/fixtures/devnet/relay$relay.conf" &
    pids+=($!)
done
wait
