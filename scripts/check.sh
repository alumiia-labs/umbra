#!/usr/bin/env bash
# The full check set. CI runs this script, and a commit passes it first.
# Each step fails the run on its own, thus a later step never hides an
# earlier failure.
#
# Each cargo call takes --locked. A manifest change without its Cargo.lock
# then fails here, and no run takes a crate version that no review saw
# (Part 14 §14.2.7).
set -euo pipefail

cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$1"; }

step "format"
cargo fmt --all --check

step "clippy, every target"
cargo clippy --locked --workspace --all-targets -- -D warnings

step "tests, host"
cargo test --locked --workspace

step "core without its default features"
# The PRECIS tables need std; the no_std path must still lint and test.
cargo clippy --locked -p umbra-core --no-default-features --all-targets -- -D warnings
cargo test --locked -p umbra-core --no-default-features

step "native transport, host only"
# The native stack builds a C library, thus the cross builds below leave it
# off and this host step turns it on.
cargo clippy --locked -p umbra-transport --features native --all-targets -- -D warnings
cargo test --locked -p umbra-transport --features native

step "relay server, host only"
cargo clippy --locked -p umbra-relay --features native --all-targets -- -D warnings
cargo test --locked -p umbra-relay --features native

step "client surface, host only"
# The SQLite library and the UniFFI scaffolding build on the host. The cross
# builds below take the client core alone.
cargo clippy --locked -p umbra-ffi --features bindings --all-targets -- -D warnings

step "client runtime over real sockets, host only"
# Three relay servers on localhost, under two client runtimes and under two
# handles of the exported surface.
cargo clippy --locked -p umbra-ffi --features bindings,sockets-test --all-targets -- -D warnings
# Each test of `app` runs a network of seven relays on loopback. On a machine
# with few threads, two of them side by side starve each other, and a transfer
# step then times out. Ten full runs at three at a time passed on 24 threads.
socket_tests=1
if [ "$(nproc)" -ge 16 ]; then
    socket_tests=3
fi
cargo test --locked -p umbra-ffi --features bindings,sockets-test -- --test-threads="$socket_tests"

step "build, wasm32-unknown-unknown"
cargo build --locked --workspace --target wasm32-unknown-unknown

step "build, aarch64-linux-android"
cargo build --locked --workspace --target aarch64-linux-android

step "dependency policy"
# The advisories check reads the RustSec database, thus this step needs the
# network. It fails on a known fault and on a yanked version (Part 14
# §14.2.7).
#
# `deps.py --check` below can fail with no change in the tree. A `skip`
# entry of deny.toml is then older than 90 days. Check the entry again.
# Then give it a new date or remove it.
cargo deny --locked check advisories bans licenses sources

# The platform graph of register R3: its advisories, its licenses under the
# exceptions of deny.toml, and its sources. Its crates stay off the bans
# allow list (Part 14 §14.2.3).
cargo deny --locked --features umbra-ffi/bindings,umbra-relay/native check advisories licenses sources

# The cooling-off window: each registry version of Cargo.lock is 14 days
# old or more, or the script names its advisory or its yank.
python scripts/deps.py --cooling

# The audit checks each package of the site lock against the advisories of
# the npm registry. No alert of GitHub reads the packages under wrangler
# (Part 14 §14.2.7). npx takes the pnpm version of site/package.json, thus
# the step needs Node alone. Corepack can add a hash to the version.
pnpm_version=$(sed -n 's/^ *"packageManager": "pnpm@\([0-9.]*\)\(+[^"]*\)\{0,1\}",*$/\1/p' site/package.json)
[ -n "$pnpm_version" ] || { echo 'site/package.json: no pnpm version in packageManager' >&2; exit 1; }
(cd site && npx --yes "pnpm@$pnpm_version" audit --audit-level high)

step "generated files are current"
python scripts/deps.py --check
python scripts/vectors.py --check
python scripts/sitebuild.py --check

step "network keys of the relay image"
python scripts/deploycheck.py

step "admission script of an outside relay"
python scripts/relay-admit.py --self-test

step "specification consistency"
python scripts/speccheck.py --quiet

step "web site of the domain"
# Part 4 §4.3.1: no page of the invitation host holds a script or reads a
# resource of a second host. The App Link file names the app.
python scripts/sitecheck.py --self-test
python scripts/sitecheck.py

step "interface strings"
# Part 14 §14.9.3: each string that a rule requires, in each locale.
python scripts/uistrings.py

# Each translation of the app and of the site against its English source.
python scripts/l10ncheck.py

printf '\nall checks passed\n'
