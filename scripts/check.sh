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
