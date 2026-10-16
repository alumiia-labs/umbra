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
# The compiler is inside the trust boundary (Part 14 §14.5.1), thus a
# digest pins the image, and not a tag that can move. A new toolchain takes
# a new digest: docker buildx imagetools inspect rust:<version>-bookworm.
image_toolchain="1.99.1"
image="rust:${image_toolchain}-bookworm@sha256:e12566d5abc17a0da741628782cdb504b68b8961f5bfcf677936bf3e8b32de29"
if [ "$toolchain" != "$image_toolchain" ]; then
    echo "rust-toolchain.toml names $toolchain, and the pinned image holds $image_toolchain." >&2
    echo "Pin the digest of rust:${toolchain}-bookworm in this script." >&2
    exit 1
fi
out="$root/target/deploy/bin"
mkdir -p "$out" "$root/target/deploy/cargo-home"
# The build runs as the user of this shell, thus target/deploy is not
# owned by root. Such a build cannot write over the files of a build as root.
if [ -n "$(find "$root/target/deploy" ! -user "$(id -u)" -print -quit)" ]; then
    echo "target/deploy holds files of another user. Run: sudo chown -R $(id -u):$(id -g) target/deploy" >&2
    exit 1
fi

# The crate registry stays in target/deploy/cargo-home between two builds.
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e CARGO_HOME=/src/target/deploy/cargo-home \
    -v "$root:/src" \
    -w /src \
    "$image" \
    bash -c '
        set -euo pipefail
        CARGO_TARGET_DIR=/src/target/deploy/cargo cargo build --release --locked \
            -p umbra-relay --features native \
            --bin umbra-relay --bin umbra-ndr --bin umbra-directory --bin umbra-signer \
            --bin umbra-measurer
        # The authority tool is a queue client, thus it is of the client crate.
        CARGO_TARGET_DIR=/src/target/deploy/cargo cargo build --release --locked \
            -p umbra-ffi --features runtime --bin umbra-authority
        for bin in umbra-relay umbra-ndr umbra-directory umbra-signer umbra-measurer \
            umbra-authority; do
            install -m 0755 "/src/target/deploy/cargo/release/$bin" "/src/target/deploy/bin/$bin"
        done
    '

ls -l "$out"
