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
   emulator -avd umbra-e2e1 -port 5554 -no-snapshot &
   emulator -avd umbra-e2e2 -port 5556 -no-snapshot &
   emulator -avd umbra-e2e3 -port 5558 -no-snapshot &
   ```

   The emulators run with audio, because two scenarios record and play
   sound. The script sets the media volume of each emulator to 0. Do not
   give the emulator the microphone of the host: the emulated microphone
   then records silence, which is enough for the test.

   The `audio` scenario compares the sound only when `ffmpeg` is on the
   path of the host.

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
| receipts | The contact turns on the two receipts. |
| file | A file from the picker of the system arrives with its name. |
| photo | A picture from the photo picker of the system arrives. |
| audio | An audio file with a tone keeps its length, its pitch, and its level. Its player runs. |
| voice | A recording of the microphone arrives as a voice message of its length. |
| notification | A message to an app behind the home screen raises an alert. |
| receipts arrive | A read receipt moves the state of a sent message. A chat behind the home screen sends none. |
| edit | An edit shows at the contact. |
| reaction | A reaction shows at the sender. |
| reply | A reply shows with the text that it answers. |
| delete for everyone | A deleted message leaves the view of the contact. |
| poll | A vote shows in the count of both sides. |
| verify | Each side starts, and the two devices show one short code. |
| search | The search finds a message, and it finds none for an unknown word. |
| lock | A wrong passphrase opens nothing. The right one shows the history. |
| passphrase | After a change, the new passphrase alone opens the store. |
| offline | A message to a stopped app arrives after its start. |
| group | An offer, a join, and a let-in make a group of two. |
| handle | A request to a claimed handle makes a contact. |
| group of three | A third member joins and each member gets its messages. |
| removal | A removed member gets no later message, and its notes keep its name. A member that leaves can send no more. |
| link | A third emulator joins the device set and gets the contacts. |
| linked messages | Each device of the set gets a message and can send. |
| device removal | A removed device leaves the list, locks one time, and can send no more. |
| removal while closed | A device that was closed at its removal can send no more after its start. |
| restore | An erased device takes its identity again from the recovery code. |

A full run takes about 20 minutes. The third emulator is a third user first. The `link` scenario
clears it, and it then joins the device set of the first user.

`--only=contact,group` runs a part of the list. A scenario with three
emulators does not run with two.

A failure writes one screenshot for each emulator into this directory.
