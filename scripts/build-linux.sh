#!/usr/bin/env bash
# Builds the server binaries for Debian (x86_64, glibc) in a Debian image of
# the pinned toolchain, and puts them in target/deploy/bin for the Ansible
# playbooks of deploy/ansible.
#
#   bash scripts/build-linux.sh
#
# It needs Docker. The image is Debian "bookworm", thus the binaries run on
# Debian 12 and on each later release.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
toolchain="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
out="$root/target/deploy/bin"
mkdir -p "$out"

docker run --rm \
    -v "$root:/src" \
    -v umbra-cargo-registry:/usr/local/cargo/registry \
    -w /src \
    "rust:${toolchain}-bookworm" \
    bash -c '
        set -euo pipefail
        CARGO_TARGET_DIR=/src/target/deploy/cargo cargo build --release --locked \
            -p umbra-relay --features native \
            --bin umbra-relay --bin umbra-ndr --bin umbra-directory --bin umbra-signer
        for bin in umbra-relay umbra-ndr umbra-directory umbra-signer; do
            install -m 0755 "/src/target/deploy/cargo/release/$bin" "/src/target/deploy/bin/$bin"
        done
    '

ls -l "$out"
