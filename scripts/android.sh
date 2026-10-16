#!/usr/bin/env bash
# Builds the Rust side of the Android app: the shared library for each ABI,
# and the Kotlin file of the UniFFI bindings. The two outputs go into the
# app project, and git ignores them, because a build makes them again.
#
# Needs: the NDK (ANDROID_NDK_HOME, or the version that ndkVersion of
# android/app/build.gradle.kts names, under the SDK), cargo-ndk, and the
# Rust targets aarch64-linux-android and x86_64-linux-android.
set -euo pipefail

cd "$(dirname "$0")/.."
profile="${1:-release}"
app="android/app/src/main"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    sdk="${ANDROID_HOME:-${LOCALAPPDATA:-$HOME}/Android/Sdk}"
    ndk_version="$(sed -n 's/^ *ndkVersion = "\(.*\)".*/\1/p' android/app/build.gradle.kts)"
    if [ -z "$ndk_version" ]; then
        echo "android/app/build.gradle.kts names no ndkVersion" >&2
        exit 1
    fi
    ANDROID_NDK_HOME="$sdk/ndk/$ndk_version"
    export ANDROID_NDK_HOME
fi
if [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "No NDK at $ANDROID_NDK_HOME. Install that version with the SDK manager." >&2
    exit 1
fi
echo "NDK: $ANDROID_NDK_HOME"

flags=()
if [ "$profile" = "release" ]; then
    flags+=(--release)
fi

# The manifest lists `lib` alone, thus each cross build of the workspace
# needs no NDK linker. The shared library is a request of this script.
cargo ndk -t arm64-v8a -t x86_64 --platform 29 -o "$app/jniLibs" \
    rustc -p umbra-ffi --lib --features bindings --crate-type cdylib ${flags[@]+"${flags[@]}"}

# The generator reads the metadata of a host library.
cargo rustc -p umbra-ffi --lib --features bindings --crate-type cdylib
host_debug="${CARGO_TARGET_DIR:-target}/debug"
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) host_library="$host_debug/umbra_ffi.dll" ;;
    Darwin) host_library="$host_debug/libumbra_ffi.dylib" ;;
    *) host_library="$host_debug/libumbra_ffi.so" ;;
esac
cargo run -q -p umbra-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "$host_library" --language kotlin --no-format \
    --out-dir "$app/kotlin-generated"

find "$app/jniLibs" "$app/kotlin-generated" -type f
