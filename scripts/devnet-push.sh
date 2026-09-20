#!/usr/bin/env bash
# Puts the relay manifest of scripts/devnet.sh into the debug app of each
# emulator that runs. The manifest holds the epoch of the start of the
# devnet, thus each start of the devnet needs one run of this script.
set -euo pipefail

cd "$(dirname "$0")/.."
adb="${ANDROID_HOME:-$LOCALAPPDATA/Android/Sdk}/platform-tools/adb"
manifest=target/devnet/manifest.bin
[ -f "$manifest" ] || { echo "no $manifest: start scripts/devnet.sh first"; exit 1; }

for device in $("$adb" devices | awk '$2 == "device" { print $1 }'); do
    # Git Bash on Windows must not turn the device path into a Windows path.
    MSYS_NO_PATHCONV=1 "$adb" -s "$device" push "$manifest"         /data/local/tmp/devnet-manifest.bin >/dev/null 2>&1
    MSYS_NO_PATHCONV=1 "$adb" -s "$device" shell \
        "run-as org.umbra.app sh -c 'mkdir -p files && cp /data/local/tmp/devnet-manifest.bin files/devnet-manifest.bin'"
    echo "$device: manifest in place"
done
