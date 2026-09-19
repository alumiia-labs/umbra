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
scripts/devnet.sh               # three relays on the ports 7441 to 7443,
                                # with their queues in target/devnet
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

The debug build trusts the test authority of `tests/fixtures/tls` and dials
10.0.2.2, which is the machine of the developer as an emulator sees it. The
secrets of that network are in the repository, thus it protects nothing. The
release build holds no network until the client reads the relay directory of
Part 10.

Two emulators make one conversation: the first one invites and copies the
link, and the second one pastes it and accepts. The clipboard of an
emulator is the clipboard of the machine.

## Open items of the shell

- The app carries its wakes over the persistent socket of Part 8 §8.4.1: a
  `specialUse` foreground service holds the one connection while the client
  is unlocked, and a message alert shows no content. FCM and UnifiedPush need
  the Notification Delivery Relay and the OHTTP hop, which are not built.
- A locked client takes no record. The auto-lock comes 15 minutes after the
  last action of the user, thus delivery in the background lasts that long.
  Part 8 §8.4.1 states the two remedies, and the owner picks one.
- Doze can suspend the network of a foreground service on a device that does
  not move. The app asks for no exemption from the battery optimization yet.
- Each circuit takes the one path of the build configuration. The client
  builds one more circuit for each 8 queues (`NET-022`), and the relay chains
  that differ (`NET-023`) need the path selection of Part 3 §3.4.6 over the
  relay directory.
- A handshake between its flight 1 and its flight 3 has no stored form. A run
  that ends inside those seconds loses that one handshake.
- The invitation is a link of 91 characters after `#`, which works one time.
  The user copies it as text. The QR code, the share sheet, and the App Link
  of `IDN-123` with its invitation host are open.
- The wrapping key of the keystore asks for no biometric and no device
  credential at each use. That step needs a `BiometricPrompt` around the
  keyed function.
- The per-conversation screenshot block (`IMP-058`), the one-time note before
  an export (`IMP-046`), push notifications, attachments, and groups.
