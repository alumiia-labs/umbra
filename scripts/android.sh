#!/usr/bin/env bash
# Builds the Rust side of the Android app: the shared library for each ABI,
# and the Kotlin file of the UniFFI bindings. The two outputs go into the
# app project, and git ignores them, because a build makes them again.
#
# Needs: the NDK of the version that ndkVersion of
# android/app/build.gradle.kts names (ANDROID_NDK_HOME, or that version
# under the SDK), cargo-ndk, and the Rust targets aarch64-linux-android and
# x86_64-linux-android.
#
# Part 14 §14.6.2: the linker of the pinned NDK aligns each segment for
# 16 KB pages. The script refuses another NDK, and it checks each library
# against IMP-021. scripts/apkcheck.sh checks an APK against IMP-022.
set -euo pipefail

cd "$(dirname "$0")/.."
profile="${1:-release}"
app="android/app/src/main"

ndk_version="$(sed -n 's/^ *ndkVersion = "\(.*\)".*/\1/p' android/app/build.gradle.kts)"
if [ -z "$ndk_version" ]; then
    echo "android/app/build.gradle.kts names no ndkVersion" >&2
    exit 1
fi

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    sdk="${ANDROID_HOME:-${LOCALAPPDATA:-$HOME}/Android/Sdk}"
    ANDROID_NDK_HOME="$sdk/ndk/$ndk_version"
    export ANDROID_NDK_HOME
fi

if [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "No NDK at $ANDROID_NDK_HOME. Install that version with the SDK manager." >&2
    exit 1
fi

found_version=""
if [ -f "$ANDROID_NDK_HOME/source.properties" ]; then
    found_version="$(tr -d '\r' < "$ANDROID_NDK_HOME/source.properties" \
        | sed -n 's/^ *Pkg\.Revision *= *\([^ ]*\).*/\1/p')"
fi
if [ "$found_version" != "$ndk_version" ]; then
    echo "The NDK at $ANDROID_NDK_HOME has the version '$found_version', and build.gradle.kts pins $ndk_version." >&2
    exit 1
fi
echo "NDK: $ANDROID_NDK_HOME"

# With --locked, a stale Cargo.lock stops the build, and the app takes no
# crate version that no review saw (Part 14 §14.2.7).
flags=(--locked)
if [ "$profile" = "release" ]; then
    flags+=(--release)
fi

# The manifest lists `lib` alone, thus each cross build of the workspace
# needs no NDK linker. The shared library is a request of this script.
cargo ndk -t arm64-v8a -t x86_64 --platform 29 -o "$app/jniLibs" \
    rustc -p umbra-ffi --lib --features bindings --crate-type cdylib "${flags[@]}"

# The generator reads the metadata of a host library.
cargo rustc --locked -p umbra-ffi --lib --features bindings --crate-type cdylib

host_debug="${CARGO_TARGET_DIR:-target}/debug"
case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) host_library="$host_debug/umbra_ffi.dll" ;;
    Darwin) host_library="$host_debug/libumbra_ffi.dylib" ;;
    *) host_library="$host_debug/libumbra_ffi.so" ;;
esac

cargo run -q --locked -p umbra-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "$host_library" --language kotlin --no-format \
    --out-dir "$app/kotlin-generated"

find "$app/jniLibs" "$app/kotlin-generated" -type f

# IMP-021: each LOAD segment of each library aligns at 2**14 or higher.
objdump=""
for candidate in "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump \
    "$ANDROID_NDK_HOME"/toolchains/llvm/prebuilt/*/bin/llvm-objdump.exe; do
    if [ -f "$candidate" ]; then
        objdump="$candidate"
        break
    fi
done
if [ -z "$objdump" ]; then
    echo "The NDK at $ANDROID_NDK_HOME holds no llvm-objdump." >&2
    exit 1
fi

for library in "$app"/jniLibs/*/libumbra_ffi.so; do
    # A segment with no align field counts as a short one.
    if ! "$objdump" -p "$library" | tr -d '\r' | awk '
        $1 == "LOAD" {
            loads++
            line = $0
            if (sub(/.*align 2\*\*/, "", line) == 0 || line + 0 < 14) short++
        }
        END { exit !(loads > 0 && short == 0) }
    '; then
        echo "IMP-021: a LOAD segment of $library aligns below 2**14." >&2
        exit 1
    fi
done
echo "IMP-021: each LOAD segment aligns at 2**14 or higher."
