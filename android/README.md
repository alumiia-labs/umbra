# The Android app

A thin Kotlin and Compose shell over `umbra-ffi`. Each network, ratchet,
queue, onion, and store function stays on the Rust side. The shell holds the
views, the keystore adapter of Part 14 §14.6.4, and the platform rules of
Part 14 §14.6.6.

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

## Release build

A release takes its network from the deployment (`deploy/ansible`). Run
`bash scripts/release-network.sh` from the repo root first. It writes four
files to `app/src/release/assets`: the key set of the directory, the key of
the notification server, the pins of the directory, and
`umbra-network.properties`. The release build reads two values of that last
file:

- `invitation_host`, the host of the App Link of an invitation (`IDN-123`);
- `shipped_epoch`, the epoch that the build ships (Part 10 `REL-045`). The
  app refuses each manifest of an epoch before it.

The release build fails when the file is absent, or when the epoch is absent
or zero. It also fails when the host is no host name or is the host of the
devnet. Run the script again before each release, thus the epoch is a recent
one.

A release ships the `arm64-v8a` library alone. The `x86_64` library is for
the emulator, and the debug build alone holds it.

## Icons

The app reads its icons at run time from SVG files of Font Awesome. The
repository holds the Free set in `app/src/main/assets/fa`, under CC BY 4.0. An
icon of `app/src/main/assets/fa-pro` wins over the same name in the Free set.
Git ignores that folder, because a Pro file must not sit in a public
repository.

The app uses the `light` style of Pro when that folder holds it. For a new
icon, copy `svgs/light/<name>.svg` of the Pro package into `fa-pro`, and copy the Free file of that name into `fa`. A Free file
names "Font Awesome Free" in its first comment. An icon that the Free set does
not hold takes the Free file of a near icon under its name, as `shield-check`
takes `shield-halved`.

## Run against a local network

```sh
scripts/devnet.sh               # seven relays on the ports 7441 to 7447 and
                                # the NDR on 7450, with their state in
                                # target/devnet
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

The debug build trusts the test authority of `tests/fixtures/tls` and dials
10.0.2.2, which is the machine of the developer as an emulator sees it. The
secrets of that network are in the repository, thus it protects nothing. The
release build holds the network of `scripts/release-network.sh` alone
("Release build" above).

Two emulators make one conversation: the first one invites and copies the
link, and the second one pastes it and accepts. The clipboard of an
emulator is the clipboard of the machine.

### A phone on the local network

A phone reaches the relays at the address of the machine on the local
network. The relays list that address, and the build dials it:

```sh
UMBRA_DEVNET_HOST=192.168.1.254 scripts/devnet.sh
./gradlew :app:assembleDebug -Pumbra.devnetHost=192.168.1.254   # in android/
```

An emulator reaches that address too, thus one build serves both. The
firewall of the machine must let the phone in on the ports 7441 and 7446,
the two ingress relays. The other relays take connections from the relays
alone.

## Limits of the shell

- A locked client takes no record. The auto-lock comes 15 minutes after the
  last action of the user by default, thus delivery in the background lasts
  that long (Part 8 §8.4.1).
- Doze can suspend the network of a foreground service on a device that does
  not move. The app asks for no exemption from the battery optimization.
- A handshake between its flight 1 and its flight 3 has no stored form. A run
  that ends inside those seconds loses that one handshake.
- The wrapping key of the keystore asks for no biometric and no device
  credential at each use.
