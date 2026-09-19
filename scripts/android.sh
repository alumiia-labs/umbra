#!/usr/bin/env bash
# Builds the Rust side of the Android app: the shared library for each ABI,
# and the Kotlin file of the UniFFI bindings. The two outputs go into the
# app project, and git ignores them, because a build makes them again.
#
# Needs: the NDK (ANDROID_NDK_HOME, or the newest one under the SDK),
# cargo-ndk, and the Rust targets aarch64-linux-android and
# x86_64-linux-android.
set -euo pipefail

cd "$(dirname "$0")/.."
profile="${1:-release}"
app="android/app/src/main"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    sdk="${ANDROID_HOME:-${LOCALAPPDATA:-$HOME}/Android/Sdk}"
    ANDROID_NDK_HOME="$(ls -d "$sdk"/ndk/* | sort -V | tail -1)"
    export ANDROID_NDK_HOME
fi
echo "NDK: $ANDROID_NDK_HOME"

flags=()
if [ "$profile" = "release" ]; then
    flags+=(--release)
fi

# The manifest lists `lib` alone, thus each cross build of the workspace
# needs no NDK linker. The shared library is a request of this script.
cargo ndk -t arm64-v8a -t x86_64 --platform 29 -o "$app/jniLibs" \
    rustc -p umbra-ffi --lib --features bindings --crate-type cdylib "${flags[@]}"

# The generator reads the metadata of a host library.
cargo rustc -p umbra-ffi --lib --features bindings --crate-type cdylib
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) host_library="target/debug/umbra_ffi.dll" ;;
    Darwin) host_library="target/debug/libumbra_ffi.dylib" ;;
    *) host_library="target/debug/libumbra_ffi.so" ;;
esac
cargo run -q -p umbra-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "$host_library" --language kotlin --no-format \
    --out-dir "$app/kotlin-generated"

find "$app/jniLibs" "$app/kotlin-generated" -type f
