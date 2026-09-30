#!/usr/bin/env bash
# Turns what deploy/ansible put in its build/ directory into the assets of
# the release app: the key set of the directory, the key of the notification
# server, the pins of the directory, and the network file. Each value is
# public. Run it after the first `ansible-playbook site.yml`, then build
# the release app.
#
#   bash scripts/release-network.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
build="$root/deploy/ansible/build"
assets="$root/android/app/src/release/assets"
for file in keyset.bin ndr-key-config.hex directory-pins.hex network.properties; do
    if [ ! -s "$build/$file" ]; then
        echo "missing $build/$file: run ansible-playbook site.yml first" >&2
        exit 1
    fi
done
mkdir -p "$assets"
unhex() { tr -d ' \n\r' < "$1" | xxd -r -p; }
cp "$build/keyset.bin" "$assets/umbra-keyset.bin"
unhex "$build/ndr-key-config.hex" > "$assets/umbra-ndr-key.bin"
unhex "$build/directory-pins.hex" > "$assets/umbra-directory-pins.bin"
cp "$build/network.properties" "$assets/umbra-network.properties"
ls -l "$assets"
