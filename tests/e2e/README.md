# End-to-end tests on emulators

These scenarios drive the debug app on two or three Android emulators. The
apps talk through the local network of `scripts/devnet.sh`. A host script
finds each control by its test name (`TestTags.kt`), through `adb` and
UI Automator. The tests need Python 3 and no other package.

## Run

1. Start the network. Delete `target/devnet` first for an empty one.

   ```sh
   scripts/devnet.sh
   ```

2. Build the debug app. The `debug` profile keeps the developer log, which
   shows in `adb logcat -s umbra-core`.

   ```sh
   scripts/android.sh debug
   cd android && ./gradlew :app:assembleDebug
   ```

3. Start the emulators. Each one needs about 2 GB of memory.

   ```sh
   emulator -avd umbra-e2e1 -port 5554 -no-snapshot -no-audio &
   emulator -avd umbra-e2e2 -port 5556 -no-snapshot -no-audio &
   emulator -avd umbra-e2e3 -port 5558 -no-snapshot -no-audio &
   ```

4. Run the scenarios from this directory.

   ```sh
   python run.py emulator-5554 emulator-5556 emulator-5558
   ```

The script clears the store of the app on each emulator. Use emulators that
hold no data that you need.

## Scenarios

Each scenario continues from the state of the one before it.

| Scenario | What it checks |
| --- | --- |
| setup | A first launch makes a store and reaches the relays. |
| contact | One invitation makes one contact on both sides. |
| messages | A message goes in each direction. |
| edit | An edit shows at the contact. |
| reaction | A reaction shows at the sender. |
| delete for everyone | A deleted message leaves the view of the contact. |
| lock | A wrong passphrase opens nothing. The right one shows the history. |
| offline | A message to a stopped app arrives after its start. |
| group | An offer, a join, and a let-in make a group of two. |
| link | A third emulator joins the device set and gets the contacts. |
| linked messages | Each device of the set gets a message and can send. |

`--only=contact,group` runs a part of the list. A scenario with three
emulators does not run with two.

A failure writes one screenshot for each emulator into this directory.
