# The Android app

A thin Kotlin and Compose shell over `umbra-ffi`. Each network, ratchet,
queue, onion, and store function stays on the Rust side. The shell holds the
views, the keystore adapter of Part 15 §15.6.4, and the platform rules of
Part 15 §15.6.6.

## Build

Needs: Android Studio, which brings the JDK and the SDK, the NDK, `cargo-ndk`,
and the Rust targets `aarch64-linux-android` and `x86_64-linux-android`.

```sh
sdkmanager "ndk;28.2.13676358" "platforms;android-37.0"
cargo install cargo-ndk --locked
rustup target add aarch64-linux-android x86_64-linux-android

scripts/android.sh              # the shared libraries and the Kotlin bindings
cd android && ./gradlew :app:assembleDebug
```

`scripts/android.sh` writes `app/src/main/jniLibs` and
`app/src/main/kotlin-generated`. Git ignores the two, because a build makes
them again. Run the script again after each change of `umbra-ffi`.

## Run against a local network

```sh
scripts/devnet.sh               # three relays on the ports 7441 to 7443
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

The debug build trusts the test authority of `tests/fixtures/tls` and dials
10.0.2.2, which is the machine of the developer as an emulator sees it. The
secrets of that network are in the repository, thus it protects nothing. The
release build holds no network until the client reads the relay directory of
Part 10.

Two emulators make one conversation: the first one invites and copies the
invitation, and the second one pastes it and accepts. The clipboard of an
emulator is the clipboard of the machine.

## Open items of the shell

- The ratchet state of a run sits in RAM. A lock, a loss of the connection, or
  a restart of the app ends each contact of the run.
- Android closes the sockets of an app a short time after it leaves the
  foreground, and the run ends with "the link to the guard closed". A test on
  two emulators showed it after 45 seconds. The remedy has two parts: the
  state of the client node in the store, thus a new run continues each
  contact, and the wake path of Part 8.
- The invitation travels as text. The link, the blob, and the first-access
  lock of Part 4 §4.3.1 have no wire command yet.
- The wrapping key of the keystore asks for no biometric and no device
  credential at each use. That step needs a `BiometricPrompt` around the
  keyed function.
- The per-conversation screenshot block (`IMP-058`), the one-time note before
  an export (`IMP-046`), push notifications, attachments, and groups.
