#!/usr/bin/env bash
# Runs a test network of seven relays on this machine, on the ports 7441 to
# 7447, under the test authority of tests/fixtures/tls: two ingress relays,
# two relays of layer 2, and three queue relays. The three hold the three
# copies of a chunk (Part 12 §12.4). Thus the circuits of a client
# take chains that differ, and two clients can hold their queues at two
# relays. A client pins the two ingress relays, and with one of them down it
# dials the other one. An Android emulator reaches them at 10.0.2.2.
#
# A phone on the local network reaches them at the address of this machine
# on that network. UMBRA_DEVNET_HOST names it, and the two ingress relays
# then list it in their descriptors in the place of 10.0.2.2:
#
#   UMBRA_DEVNET_HOST=192.168.1.254 scripts/devnet.sh
#
# An emulator reaches that address too. The debug app takes the same
# address at its build (android/README.md).
#
# Each relay signs its descriptor, and the seven test authorities sign a
# manifest of the seven (Part 10 §10.5.5). A relay reads its layer from that
# manifest. The seeds of the relays and of the authorities are in the
# repository, thus this network protects nothing.
#
# The Notification Delivery Relay of Part 8 §8.2 listens on port 7450, and
# the two ingress relays carry its OHTTP requests (`POST /ohttp`). The
# directory of Part 9 with the issuer of Part 13 §13.9 listens on port 7451,
# and the two ingress relays carry its requests (`POST /directory`). Its
# epoch is 60 seconds here, thus a new handle shows within a minute.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build -p umbra-relay --features native
# Each relay keeps its queues in a file here, thus a restart of this script
# ends no contact. Delete the directory for an empty network.
mkdir -p target/devnet/conf

# The configuration of each relay, with the address of the host.
host="${UMBRA_DEVNET_HOST:-10.0.2.2}"
for relay in 1 2 3 4 5 6 7; do
    sed "s/10\.0\.2\.2/$host/g" "tests/fixtures/devnet/relay$relay.conf" \
        > "target/devnet/conf/relay$relay.conf"
done
echo "the ingress relays listen for clients at $host, ports 7441 and 7446"

for relay in 1 2 3 4 5 6 7; do
    target/debug/umbra-relay sign-descriptor \
        "target/devnet/conf/relay$relay.conf" "target/devnet/relay$relay.desc"
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

# The debug build pins the directory (`DIS-163`), and the seeds of
# directory.conf give the same keys at each start.
target/debug/umbra-directory pins tests/fixtures/devnet/directory.conf     | python -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))"     | cmp -s - tests/fixtures/devnet/directory-pins.bin || {
    echo "the directory keys differ from tests/fixtures/devnet/directory-pins.bin"
    exit 1
}

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
# The queue relays start first, thus each dial of a lower layer finds a port
# that accepts.
target/debug/umbra-ndr tests/fixtures/devnet/ndr.conf &
pids+=($!)
target/debug/umbra-directory tests/fixtures/devnet/directory.conf &
pids+=($!)
for relay in 3 5 7 2 4 1 6; do
    target/debug/umbra-relay "target/devnet/conf/relay$relay.conf" &
    pids+=($!)
done
# The authorities sign a new manifest each 30 minutes, and each relay reads
# the file again and serves it. A client then sees no clock gap after an
# hour of the network.
(
    while sleep 1800; do
        target/debug/umbra-test-authority tests/fixtures/devnet/authority.conf target/devnet >/dev/null ||
            echo "the new manifest failed"
    done
) &
pids+=($!)
wait
