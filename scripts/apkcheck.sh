#!/usr/bin/env bash
# Checks a built APK against IMP-022 of Part 14 §14.6.2: each library in the
# APK starts at a 16 KB boundary, thus a device with 16 KB pages maps it from
# the APK. scripts/android.sh checks each library against IMP-021.
#
# Usage: scripts/apkcheck.sh <apk>
#
# The release build runs it on each APK (task checkReleaseApk of
# android/app/build.gradle.kts).
#
# Needs: the build-tools 35 or newer of the Android SDK (ANDROID_HOME, or the
# SDK of Android Studio). An older zipalign has no -P option.
set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "Usage: scripts/apkcheck.sh <apk>" >&2
    exit 1
fi
apk="$1"

# The newest build-tools first.
sdk="${ANDROID_HOME:-${LOCALAPPDATA:-$HOME}/Android/Sdk}"
zipalign=""
while IFS= read -r tools; do
    for candidate in "$tools/zipalign" "$tools/zipalign.exe"; do
        if [ -f "$candidate" ]; then
            zipalign="$candidate"
            break 2
        fi
    done
done < <(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V -r)

if [ -z "$zipalign" ]; then
    echo "No zipalign under $sdk/build-tools." >&2
    exit 1
fi

# -P 16 checks each library that the APK holds uncompressed at a 16 KB
# boundary, and 4 checks each other entry at 4 bytes.
if ! report="$("$zipalign" -v -c -P 16 4 "$apk" 2>&1)"; then
    printf '%s\n' "$report" | grep -v '(OK' >&2 || true
    echo "IMP-022: $apk fails zipalign -c -P 16 4." >&2
    exit 1
fi
echo "IMP-022: $apk passes zipalign -c -P 16 4."
