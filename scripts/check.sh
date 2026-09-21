#!/usr/bin/env bash
# The full check set. CI runs this script, and a commit passes it first.
# Each step fails the run on its own, thus a later step never hides an
# earlier failure.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$1"; }

step "format"
cargo fmt --all --check

step "clippy, every target"
cargo clippy --workspace --all-targets -- -D warnings

step "tests, host"
cargo test --workspace

step "core without its default features"
# The PRECIS tables need std; the no_std path must still lint and test.
cargo clippy -p umbra-core --no-default-features --all-targets -- -D warnings
cargo test -p umbra-core --no-default-features

step "native transport, host only"
# The native stack builds a C library, thus the cross builds below leave it
# off and this host step turns it on.
cargo clippy -p umbra-transport --features native --all-targets -- -D warnings
cargo test -p umbra-transport --features native

step "relay server, host only"
cargo clippy -p umbra-relay --features native --all-targets -- -D warnings
cargo test -p umbra-relay --features native

step "client surface, host only"
# The SQLite library and the UniFFI scaffolding build on the host. The cross
# builds below take the client core alone.
cargo clippy -p umbra-ffi --features bindings --all-targets -- -D warnings

step "client runtime over real sockets, host only"
# Three relay servers on localhost, under two client runtimes and under two
# handles of the exported surface.
cargo clippy -p umbra-ffi --features bindings,sockets-test --all-targets -- -D warnings
# Each test of `app` runs a network of seven relays on loopback. Two of them
# side by side starve each other, and a transfer step then times out. One at
# a time is slower and it does not fail by chance.
cargo test -p umbra-ffi --features bindings,sockets-test -- --test-threads=1

step "build, wasm32-unknown-unknown"
cargo build --workspace --target wasm32-unknown-unknown

step "build, aarch64-linux-android"
cargo build --workspace --target aarch64-linux-android

step "dependency policy"
cargo deny check bans licenses sources

step "generated files are current"
python scripts/deps.py --check
python scripts/vectors.py --check

step "specification consistency"
python scripts/speccheck.py --quiet

printf '\nall checks passed\n'
