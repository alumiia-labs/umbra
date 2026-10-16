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
#
# Authority 0 holds a report queue at a queue relay (Part 10 §10.4.2), as a
# client holds one. Once the relay made it, the manifest names it, and the
# totals of the link-fault reports of clients show in the log of umbra-authority.
#
# The measurer of Part 10 §10.3 runs one class test of each relay after the
# start, with a certificate of the test authorities, a slot of 3 seconds,
# and each rate at one part in 1 000. Each result is one line of
# target/devnet/measure-results.txt, and the next manifest lists each relay
# at the class that the results verify.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build -p umbra-relay --features native
cargo build -p umbra-ffi --features runtime --bin umbra-authority
# Cargo builds into CARGO_TARGET_DIR when the caller sets it. The files of
# the network stay in target/devnet.
bin="${CARGO_TARGET_DIR:-target}/debug"
# Each relay keeps its queues in a file here, thus a restart of this script
# ends no contact. Delete the directory for an empty network.
mkdir -p target/devnet/conf
# A run that ended with no trap, as a killed shell does, leaves its signing
# loop, which then signs over the manifest of this run with its own
# settings. The loop of the last run stops here.
if [ -f target/devnet/signer.pid ]; then
    kill "$(cat target/devnet/signer.pid)" 2>/dev/null || true
fi

# The configuration of each relay, with the address of the host.
host="${UMBRA_DEVNET_HOST:-10.0.2.2}"
# The address goes into a sed expression, thus it takes no other character.
if ! [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "UMBRA_DEVNET_HOST is an IPv4 address or a host name: $host" >&2
    exit 1
fi
for relay in 1 2 3 4 5 6 7; do
    sed "s/10\.0\.2\.2/$host/g" "tests/fixtures/devnet/relay$relay.conf" \
        > "target/devnet/conf/relay$relay.conf"
done
echo "the ingress relays listen for clients at $host, ports 7441 and 7446"

for relay in 1 2 3 4 5 6 7; do
    "$bin"/umbra-relay sign-descriptor \
        "target/devnet/conf/relay$relay.conf" "target/devnet/relay$relay.desc"
done
# The manifest holds the present epoch, thus each start signs a new one. It
# carries the report queue of authority 0 once that queue exists.
cp tests/fixtures/devnet/authority.conf target/devnet/conf/authority.conf
echo "report_queue=0,target/devnet/report-queue.bin" >> target/devnet/conf/authority.conf
# A relay that an isolation query of authority 0 expelled leaves it.
echo "verdicts=target/devnet/verdicts.txt" >> target/devnet/conf/authority.conf
# Each relay takes the class that the class tests of the measurer verify.
echo "results=target/devnet/measure-results.txt" >> target/devnet/conf/authority.conf
"$bin"/umbra-test-authority target/devnet/conf/authority.conf target/devnet
# The relays and the debug build of the Android app hold the key set of the
# repository. The seed of the authorities gives the same one at each start.
cmp -s target/devnet/keyset.bin tests/fixtures/devnet/keyset.bin || {
    echo "the key set differs from tests/fixtures/devnet/keyset.bin"
    exit 1
}

# Push over FCM (Part 8 §8.2): with the service account of a Firebase
# project at target/devnet/fcm-service-account.json, the NDR sends to FCM.
# It then trusts the public roots, which FCM needs, in place of the test CA.
# Git ignores target/, thus the key stays out of the repository.
ndr_conf=tests/fixtures/devnet/ndr.conf
if [ -f target/devnet/fcm-service-account.json ]; then
    grep -v '^trust=' tests/fixtures/devnet/ndr.conf > target/devnet/conf/ndr.conf
    echo "fcm_credentials=target/devnet/fcm-service-account.json" >> target/devnet/conf/ndr.conf
    ndr_conf=target/devnet/conf/ndr.conf
    echo "the NDR sends to FCM"
fi

# Debian has python3 alone, and Windows often has python alone.
if python3 -c '' 2>/dev/null; then python=python3; else python=python; fi

# The debug build pins the gateway key of the NDR (`NTF-127`), and the seed
# of ndr.conf gives the same one at each start.
"$bin"/umbra-ndr key-config "$ndr_conf"     | "$python" -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))"     | cmp -s - tests/fixtures/devnet/ndr-key-config.bin || {
    echo "the NDR key differs from tests/fixtures/devnet/ndr-key-config.bin"
    exit 1
}

# The debug build pins the directory (`DIS-163`), and the seeds of
# directory.conf give the same keys at each start.
"$bin"/umbra-directory pins tests/fixtures/devnet/directory.conf     | "$python" -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))"     | cmp -s - tests/fixtures/devnet/directory-pins.bin || {
    echo "the directory keys differ from tests/fixtures/devnet/directory-pins.bin"
    exit 1
}

# The key of the measurer stays across a restart, and two test authorities
# sign a new certificate for it at each start (Part 10 `REL-070`).
if [ ! -f target/devnet/measurer/measurer.seed ]; then
    "$bin"/umbra-measurer keygen target/devnet/measurer
fi
"$bin"/umbra-test-authority measurer-cert target/devnet/conf/authority.conf \
    target/devnet/measurer/measurer.pub target/devnet/measurer/measurer.cert
cat > target/devnet/conf/measurer.conf <<EOF
key=target/devnet/measurer/measurer.seed
cert=target/devnet/measurer/measurer.cert
manifest=target/devnet/manifest.bin
keyset=tests/fixtures/devnet/keyset.bin
results=target/devnet/measure-results.txt
capacity=500
slot=3
sockets=2
trust=tests/fixtures/tls/ca.pem
host_alias=$host
scale=1000
EOF

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT INT TERM
# The queue relays start first, thus each dial of a lower layer finds a port
# that accepts.
"$bin"/umbra-ndr "$ndr_conf" &
pids+=($!)
"$bin"/umbra-directory tests/fixtures/devnet/directory.conf &
pids+=($!)
for relay in 3 5 7 2 4 1 6; do
    "$bin"/umbra-relay "target/devnet/conf/relay$relay.conf" &
    pids+=($!)
done
# The report queue of authority 0, once the relays listen.
sleep 2
"$bin"/umbra-authority tests/fixtures/devnet/authority-queue.conf &
pids+=($!)
# One class test of each relay, once the relays listen (Part 10 §10.3). A
# relay of layer 2 or 3 takes the measurer on a link with no hello.
(
    sleep 5
    if "$bin"/umbra-measurer run target/devnet/conf/measurer.conf; then
        echo "the measurer wrote a result for each relay"
    else
        echo "the measurer got no result from a relay"
    fi
) &
pids+=($!)
# The authorities sign a new manifest each 30 minutes, and each relay reads
# the file again and serves it. A client then sees no clock gap after an
# hour of the network. The first new one follows the report queue.
(
    until [ -f target/devnet/report-queue.bin ]; do sleep 2; done
    "$bin"/umbra-test-authority target/devnet/conf/authority.conf target/devnet >/dev/null &&
        echo "the manifest names the report queue"
    while sleep 1800; do
        "$bin"/umbra-test-authority target/devnet/conf/authority.conf target/devnet >/dev/null ||
            echo "the new manifest failed"
    done
) &
pids+=($!)
echo $! > target/devnet/signer.pid
wait
