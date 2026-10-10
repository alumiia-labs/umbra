#!/usr/bin/env bash
# Turns what deploy/ansible put in its build/ directory into the assets of
# the release app: the key set of the directory, the key of the notification
# server, the pins of the directory, and the network file, to which it adds
# the epoch that the build ships (`shipped_epoch`, Part 10 REL-045). Each
# value is public. Run it after the first `ansible-playbook site.yml`. Then
# build the release app. The release build fails without these files.
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
if ! command -v xxd > /dev/null; then
    echo "xxd is missing: install it (the package xxd or vim-common)" >&2
    exit 1
fi
mkdir -p "$assets"
# The four files go to a directory beside the assets first and take their
# names at the end. Thus a run that stops leaves no half set for a build.
stage="$(mktemp -d "$assets/.stage.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
# A hex file with another character in it stops the run; xxd would pass
# over that character and write a shorter key.
unhex() {
    local text
    text="$(tr -d ' \n\r' < "$1")"
    if ! printf '%s' "$text" | grep -Eq '^([0-9a-fA-F]{2})+$'; then
        echo "$1 is not hex" >&2
        return 1
    fi
    printf '%s' "$text" | xxd -r -p > "$2"
    [ -s "$2" ]
}
cp "$build/keyset.bin" "$stage/umbra-keyset.bin"
unhex "$build/ndr-key-config.hex" "$stage/umbra-ndr-key.bin"
unhex "$build/directory-pins.hex" "$stage/umbra-directory-pins.bin"
# REL-045: the epoch that the build ships, one hour of Unix time each. The
# app refuses each manifest of an epoch before it. It is the epoch of the
# manifest that the last run of the playbook brought back, which is never
# above the newest signed one. A manifest starts with 01, the length of its
# root in two bytes, 01, and the epoch in eight bytes. With no manifest that
# reads, it is the hour before this one. An epoch above the newest signed
# root would make a new install refuse each manifest.
epoch=0
if [ -s "$build/manifest" ] \
    && [ "$(xxd -p -l 1 "$build/manifest")" = "01" ] \
    && [ "$(xxd -p -s 3 -l 1 "$build/manifest")" = "01" ]; then
    epoch=$(( 16#$(xxd -p -s 4 -l 8 "$build/manifest") ))
fi
hour=$(( $(date +%s) / 3600 ))
if [ "$epoch" -le 0 ] || [ "$epoch" -gt "$hour" ]; then
    epoch=$(( hour - 1 ))
fi
grep -v '^shipped_epoch=' "$build/network.properties" > "$stage/umbra-network.properties"
printf 'shipped_epoch=%s\n' "$epoch" >> "$stage/umbra-network.properties"
echo "shipped_epoch=$epoch"
for file in umbra-keyset.bin umbra-ndr-key.bin umbra-directory-pins.bin umbra-network.properties; do
    mv "$stage/$file" "$assets/$file"
done
ls -l "$assets"
