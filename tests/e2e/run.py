"""End-to-end scenarios of the debug app on two or three emulators.

Start `scripts/devnet.sh` and the emulators first (README.md). Each scenario
continues from the state of the one before it, thus the order is fixed.

    python run.py emulator-5554 emulator-5556 [emulator-5558]
"""

import array
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import wave
import zlib

from driver import Device, Fault, summary, text_of

APK = "../../android/app/build/outputs/apk/debug/app-debug.apk"
PASSPHRASE = "correct horse battery"
OTHER_PASSPHRASE = "staple battery horse"


def unlock(device, passphrase=PASSPHRASE):
    device.type("unlock_passphrase", passphrase)
    device.back()
    device.tap("unlock_open")


def setup(device):
    """A new store, from the first launch to the tabs."""
    device.stop()
    device.reset()
    device.start()

    device.wait("unlock_open", 60)
    device.type("unlock_passphrase", PASSPHRASE)
    device.type("unlock_confirm", PASSPHRASE)
    device.back()
    device.tap("unlock_open")

    device.wait("tabs_chats", 60)


def home(device):
    """Goes back to the list of the chats from any view."""
    for _ in range(8):
        if device.visible("tabs_chats"):
            device.tap("tabs_chats")
            return
        device.back()
        time.sleep(0.5)
    raise Fault(f"{device.serial}: no way back to the tabs")


def open_chat_row(device, title):
    home(device)
    device.tap("chats_row_title", text=title)
    device.wait("chat_list")


def open_chat(device, title):
    open_chat_row(device, title)
    device.wait("chat_input")


def send(device, text):
    device.type("chat_input", text)
    device.tap("chat_send")
    return device.wait("chat_bubble_out", 20, text=text)


def bubble(device, tag, text, timeout=30):
    return device.wait(tag, timeout, text=text)


def gone(device, tag, text, timeout=30):
    """Waits until no control of this name shows this text."""
    deadline = time.monotonic() + timeout
    while True:
        nodes = device.nodes()
        if not any(text in text_of(node) for node in device.find_all(tag, nodes)):
            return
        if time.monotonic() > deadline:
            raise Fault(f"{device.serial}: '{text}' stays in '{tag}'; on the screen: {summary(nodes)}")
        time.sleep(0.5)


def name_contact(device, name):
    device.type("name_field", name, timeout=90)
    device.back()
    device.tap("name_save")
    device.wait("chat_input")


def details(device, title):
    """Opens the details of a chat from its bar."""
    open_chat(device, title)
    device.tap("common_bar_title")


def admit(admin, joiner, group, contact):
    """GRP: an offer, a join, and a let-in (Part 11 §11.9.1)."""
    details(admin, group)
    admin.tap_node(admin.scroll_to("group_add_members"))
    admin.tap("group_invite_row", text=contact)

    home(joiner)
    joiner.tap("group_offer_join", timeout=90)

    admin.back()
    deadline = time.monotonic() + 90
    while not admin.visible("group_let_in"):
        if time.monotonic() > deadline:
            raise Fault("the admin sees no request of the joiner")
        admin.shell("input swipe 540 1700 540 900 300")
    admin.tap("group_let_in")

    joiner.tap("chats_row_title", timeout=120, text=group)
    joiner.wait("chat_input")


def change_passphrase(device, old, new):
    home(device)
    device.tap("tabs_settings")
    device.tap_node(device.scroll_to("settings_passphrase"))
    device.type("passphrase_current", old)
    device.type("passphrase_new", new)
    device.type("passphrase_confirm", new)
    device.back()
    device.tap_node(device.scroll_to("passphrase_save"))

    # The view closes when the store holds the new key.
    device.wait("settings_passphrase", 120)


def lock(device):
    home(device)
    device.tap("tabs_lock")
    device.wait("unlock_open")


def absent(device, tag, text, seconds=20):
    """Checks for a time that no control of this name shows this text."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if any(text in text_of(node) for node in device.find_all(tag)):
            raise Fault(f"{device.serial}: '{text}' shows in '{tag}'")
        time.sleep(1)


def connect(inviter, accepter, inviter_name, accepter_name):
    """One invitation makes one contact, and each side names the other."""
    home(inviter)
    inviter.tap("tabs_add")
    inviter.tap("add_create_invitation")
    link = inviter.text("invite_link", 60)

    home(accepter)
    accepter.tap("tabs_add")
    accepter.tap("add_use_invitation")
    accepter.type("accept_link", link)
    accepter.back()
    accepter.tap("accept_continue")

    name_contact(accepter, inviter_name)
    name_contact(inviter, accepter_name)


def scenario_setup(devices):
    for device in devices:
        device.prepare()
        device.install(APK)
        setup(device)


def scenario_contact(devices):
    alice, bob = devices[0], devices[1]
    connect(alice, bob, "Alice", "Bob")


def scenario_messages(devices):
    alice, bob = devices[0], devices[1]
    send(alice, "first from alice")
    bubble(bob, "chat_bubble_in", "first from alice")
    send(bob, "first from bob")
    bubble(alice, "chat_bubble_in", "first from bob")

    # NET-059: receipts are off by default, thus the state stops at the relay.
    alice.wait("chat_bubble_state", 30, text="Accepted")


def scenario_receipts(devices):
    """NET-059: a receipt goes only after the user turns it on."""
    alice, bob = devices[0], devices[1]
    bob.tap("common_bar_title")
    bob.tap_node(bob.scroll_to("contact_delivery_receipts"))
    bob.tap_node(bob.scroll_to("contact_read_receipts"))
    open_chat(bob, "Alice")

    send(alice, "with receipts")
    bubble(bob, "chat_bubble_in", "with receipts")


def scenario_file(devices):
    """A file from the picker of the system arrives with its name."""
    alice, bob = devices[0], devices[1]
    alice.shell("echo a-file-of-the-test > /sdcard/Download/umbra-note.txt")
    alice.tap("chat_attach")
    alice.tap("attach_file")

    alice.pick_file("umbra-note.txt")

    alice.wait("message_file", 60, text="umbra-note.txt")
    bob.wait("message_file", 120, text="umbra-note.txt")


def picture():
    """A file with a small picture of one color, in the PNG form."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    side = 64
    rows = b"".join(bytes([0]) + bytes([40, 120, 90]) * side for _ in range(side))
    header = struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0)
    magic = bytes([0x89]) + b"PNG" + bytes([0x0D, 0x0A, 0x1A, 0x0A])
    path = os.path.join(tempfile.gettempdir(), "umbra-e2e-photo.png")
    with open(path, "wb") as out:
        out.write(magic + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))

    return path


def scenario_photo(devices):
    """A picture from the photo picker of the system arrives."""
    alice, bob = devices[0], devices[1]
    alice.run("push", picture(), "/sdcard/Pictures/umbra-photo.png")
    alice.shell("am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file:///sdcard/Pictures/umbra-photo.png")
    time.sleep(4)

    alice.tap("chat_attach")
    alice.tap("attach_photo")
    alice.tap_node(alice.wait_described("Photo taken", prefix=True))

    alice.wait("message_photo", 60)
    bob.wait("message_photo", 120)


TONE_HZ = 440
TONE_SECONDS = 3
RATE = 48_000


def tone():
    """A file with a tone of one pitch, in the WAV form."""
    samples = array.array(
        "h",
        (int(8_000 * math.sin(2 * math.pi * TONE_HZ * at / RATE)) for at in range(RATE * TONE_SECONDS)),
    )
    path = os.path.join(tempfile.gettempdir(), "umbra-e2e-tone.wav")
    with wave.open(path, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(RATE)
        out.writeframes(samples.tobytes())

    return path


def sound_of(path):
    """The length in seconds, the pitch in Hz, and the level of an audio file."""
    decoded = subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-i", path, "-f", "s16le", "-ac", "1", "-ar", str(RATE), "-"],
        capture_output=True,
        check=True,
    ).stdout
    samples = array.array("h", decoded)
    seconds = len(samples) / RATE

    # A tone crosses zero two times in each period.
    crossings = sum(1 for at in range(1, len(samples)) if (samples[at - 1] < 0) != (samples[at] < 0))
    level = math.sqrt(sum(sample * sample for sample in samples) / len(samples))

    return seconds, crossings / 2 / seconds, level


def scenario_audio(devices):
    """An audio file keeps its length, its pitch, and its level on the way to the contact."""
    alice, bob = devices[0], devices[1]
    sent = tone()
    alice.run("push", sent, "/sdcard/Download/umbra-tone.wav")
    bob.shell("rm -f /sdcard/Download/umbra-tone.m4a")

    alice.tap("chat_attach")
    alice.tap("attach_audio")
    alice.pick_file("umbra-tone.wav")
    # The app encodes the file, thus the name has another ending.
    alice.wait("message_voice", 120, text="umbra-tone")
    tile = bob.wait("message_voice", 180, text="umbra-tone")

    # The first node under the tile is its play control.
    bob.tap_node(list(tile.iter("node"))[1])
    deadline = time.monotonic() + 10
    while not bob.plays_audio():
        if time.monotonic() > deadline:
            raise Fault("the audio message does not play")
        time.sleep(0.3)

    if shutil.which("ffmpeg") is None:
        print("      no ffmpeg on this machine: the sound of the file is not compared")
        return

    # The file leaves the store only by a save of the user.
    time.sleep(TONE_SECONDS + 1)
    bob.tap("common_bar_title")
    bob.tap_node(bob.scroll_to("details_media"))
    bob.tap_node(bob.wait_text("umbra-tone"))
    bob.tap("media_save")
    # The save dialog of the system has no test name.
    deadline = time.monotonic() + 30
    while True:
        buttons = [node for node in bob.nodes() if node.get("resource-id") == "android:id/button1"]
        if buttons:
            bob.tap_node(buttons[0])
            break
        if time.monotonic() > deadline:
            raise Fault("the system shows no save dialog")
        time.sleep(0.5)
    time.sleep(4)

    received = os.path.join(tempfile.gettempdir(), "umbra-e2e-received.m4a")
    bob.run("pull", "/sdcard/Download/umbra-tone.m4a", received)
    seconds, pitch, level = sound_of(received)
    _, _, sent_level = sound_of(sent)
    if abs(seconds - TONE_SECONDS) > 0.3:
        raise Fault(f"the audio has {seconds:.2f} s, and the tone has {TONE_SECONDS} s")
    if abs(pitch - TONE_HZ) > TONE_HZ * 0.05:
        raise Fault(f"the audio has {pitch:.0f} Hz, and the tone has {TONE_HZ} Hz")
    if abs(level - sent_level) > sent_level * 0.25:
        raise Fault(f"the audio has the level {level:.0f}, and the tone has {sent_level:.0f}")

    open_chat(bob, "Alice")


def scenario_voice(devices):
    """A recording of the microphone arrives as a voice message of its length."""
    alice, bob = devices[0], devices[1]
    before = len(bob.find_all("message_voice"))

    # With no text in the field, the send control starts a recording.
    alice.tap("chat_send")
    time.sleep(4)
    alice.tap("chat_send")

    deadline = time.monotonic() + 180
    while len(bob.find_all("message_voice")) <= before:
        if time.monotonic() > deadline:
            raise Fault("the voice message does not arrive")
        time.sleep(2)

    length = text_of(bob.find_all("message_voice")[-1])
    if not any(mark in length for mark in ("0:04", "0:05", "0:06", "0:07")):
        raise Fault(f"the voice message shows the length '{length}' for a recording of 4 s")


def scenario_notification(devices):
    """A message to an app behind the home screen raises an alert, and no read receipt."""
    alice, bob = devices[0], devices[1]
    send(alice, "bob reads this one")
    bubble(bob, "chat_bubble_in", "bob reads this one")

    bob.shell("input keyevent KEYCODE_HOME")
    time.sleep(3)
    send(alice, "bob looks at the home screen")

    deadline = time.monotonic() + 120
    while "tag=message" not in bob.shell("dumpsys notification --noredact", check=False):
        if time.monotonic() > deadline:
            raise Fault("the message raised no alert")
        time.sleep(3)


def scenario_receipts_arrive(devices):
    """NET-050: a receipt leaves in a cover slot after its delay, thus it takes minutes."""
    alice, bob = devices[0], devices[1]
    # A read message shows no state after its time.
    deadline = time.monotonic() + 600
    while "·" in text_of(bubble(alice, "chat_bubble_out", "bob reads this one")):
        if time.monotonic() > deadline:
            raise Fault("no read receipt moved the state of the message")
        time.sleep(5)

    # The chat of Bob is behind the home screen, thus it read nothing more.
    hidden = text_of(bubble(alice, "chat_bubble_out", "bob looks at the home screen"))
    if "·" not in hidden:
        raise Fault("a chat behind the home screen sent a read receipt")

    bob.start()
    bubble(bob, "chat_bubble_in", "bob looks at the home screen", 60)


def scenario_edit(devices):
    alice, bob = devices[0], devices[1]
    alice.long_press(send(alice, "a text with a mistak"))
    alice.tap("message_edit")
    # The field has the focus, and its cursor is after the text.
    time.sleep(1)
    alice.type_more("e")
    alice.tap("chat_send")

    bubble(bob, "chat_bubble_in", "a text with a mistake")


def scenario_reaction(devices):
    alice, bob = devices[0], devices[1]
    bob.long_press(bubble(bob, "chat_bubble_in", "first from alice"))
    bob.tap("message_react")

    alice.wait("chat_reaction", 30)


def scenario_reply(devices):
    alice, bob = devices[0], devices[1]
    bob.long_press(bubble(bob, "chat_bubble_in", "first from alice"))
    bob.tap("message_reply")
    time.sleep(1)
    bob.type_more("a reply from bob")
    bob.tap("chat_send")

    reply = bubble(alice, "chat_bubble_in", "a reply from bob")
    if "first from alice" not in text_of(reply):
        raise Fault(f"the reply shows no quote: '{text_of(reply)}'")


def scenario_delete_for_everyone(devices):
    alice, bob = devices[0], devices[1]
    send(alice, "this one goes away")
    bubble(bob, "chat_bubble_in", "this one goes away")

    alice.long_press(bubble(alice, "chat_bubble_out", "this one goes away"))
    alice.tap("message_delete")
    alice.tap("message_delete_for_everyone")
    if alice.visible("message_delete_confirm"):
        alice.tap("message_delete_confirm")

    gone(bob, "chat_bubble_in", "this one goes away")


def scenario_poll(devices):
    alice, bob = devices[0], devices[1]
    alice.tap("chat_attach")
    alice.tap("attach_poll")
    alice.type("poll_question", "Tea or coffee")
    first, second = alice.find_all("poll_option")[:2]
    alice.tap_node(first)
    alice.type_more("Tea")
    alice.tap_node(second)
    alice.type_more("Coffee")
    alice.back()
    alice.tap_node(alice.scroll_to("poll_send"))

    bob.tap("poll_choice", timeout=60, text="Coffee")
    # The count of each option follows its text.
    bob.wait("poll_choice", 30, text="Coffee 1")
    alice.wait("poll_choice", 60, text="Coffee 1")
    alice.wait("poll_choice", 5, text="Tea 0")


def scenario_verify(devices):
    """IDN-170: each user starts, and then the two devices show one code."""
    alice, bob = devices[0], devices[1]
    for device in (alice, bob):
        device.tap("common_bar_title")
        device.tap("contact_verify")
        device.tap_node(device.scroll_to("verify_short_code"))

    shown = bob.text("verify_code", 90)
    held = alice.text("verify_code", 90)
    if shown != held or not shown:
        raise Fault(f"the two short codes differ: '{held}' and '{shown}'")

    for device in (alice, bob):
        device.tap("verify_codes_match")
    for device in (alice, bob):
        device.tap("verify_done", timeout=90)
        device.back()
        device.wait_text("Verified")
        open_chat(device, "Bob" if device is alice else "Alice")


def scenario_search(devices):
    alice = devices[0]
    home(alice)
    alice.tap("tabs_search")
    alice.type("search_input", "mistake")
    alice.wait("search_result", 30, text="a text with a mistake")

    alice.type_more("xqzv")
    alice.wait("search_empty", 30)
    open_chat(alice, "Bob")


def scenario_lock(devices):
    alice = devices[0]
    lock(alice)

    unlock(alice, "a wrong passphrase")
    alice.wait("common_fault", 60)
    if alice.visible("tabs_chats"):
        raise Fault("a wrong passphrase opened the store")

    alice.stop()
    alice.start()
    alice.wait("unlock_open", 60)
    unlock(alice)
    alice.wait("tabs_chats", 60)
    open_chat(alice, "Bob")
    bubble(alice, "chat_bubble_out", "bob looks at the home screen")


def scenario_passphrase(devices):
    """The store opens with the new passphrase alone, and then with the first one again."""
    alice = devices[0]
    change_passphrase(alice, PASSPHRASE, OTHER_PASSPHRASE)
    lock(alice)
    unlock(alice)
    alice.wait("common_fault", 60)

    alice.stop()
    alice.start()
    alice.wait("unlock_open", 60)
    unlock(alice, OTHER_PASSPHRASE)
    alice.wait("tabs_chats", 60)

    change_passphrase(alice, OTHER_PASSPHRASE, PASSPHRASE)
    lock(alice)
    unlock(alice)
    alice.wait("tabs_chats", 60)


def scenario_offline(devices):
    """A message to a stopped app waits at the queue relay."""
    alice, bob = devices[0], devices[1]
    bob.stop()
    open_chat(alice, "Bob")
    send(alice, "sent while bob was away")
    time.sleep(5)

    bob.start()
    bob.wait("unlock_open", 60)
    unlock(bob)
    bob.wait("tabs_chats", 60)
    open_chat(bob, "Alice")
    bubble(bob, "chat_bubble_in", "sent while bob was away", 60)


def scenario_group(devices):
    alice, bob = devices[0], devices[1]
    home(alice)
    alice.tap("tabs_add")
    alice.tap("add_new_group")
    alice.type("group_name", "Trio")
    alice.back()
    alice.tap("group_create")
    alice.wait("chat_input", 60)

    admit(alice, bob, "Trio", "Bob")
    open_chat(alice, "Trio")
    send(alice, "hello group")
    bubble(bob, "chat_bubble_in", "hello group", 60)
    send(bob, "bob answers the group")
    bubble(alice, "chat_bubble_in", "bob answers the group", 60)


def scenario_handle(devices):
    """A request to a handle makes a contact (Part 9 §9.6)."""
    alice, carol = devices[0], devices[2]
    home(carol)
    carol.tap("tabs_profile")
    carol.tap_node(carol.scroll_to("profile_handle"))
    # The directory adds a number, thus the name needs no other mark.
    carol.type("handle_name", "carol")
    carol.back()
    carol.tap("handle_claim")
    carol.wait("handle_copy", 180)
    handle = next(node.get("text") for node in carol.nodes() if (node.get("text") or "").startswith("@carol"))

    home(alice)
    alice.tap("tabs_add")
    alice.tap("add_use_invitation")
    alice.type("accept_link", handle)
    alice.back()

    # A new handle shows in the directory at its next epoch, thus the request goes again.
    deadline = time.monotonic() + 180
    while alice.visible("accept_send_request"):
        if time.monotonic() > deadline:
            raise Fault("the directory shows no handle of the contact")
        alice.tap_node(alice.scroll_to("accept_send_request"))
        time.sleep(10)

    home(carol)
    carol.tap("request_open", timeout=180)
    carol.tap("request_accept")
    name_contact(carol, "Alice")
    name_contact(alice, "Carol")

    send(alice, "hello carol")
    bubble(carol, "chat_bubble_in", "hello carol", 60)
    send(carol, "hello alice")
    bubble(alice, "chat_bubble_in", "hello alice", 60)


def scenario_group_of_three(devices):
    alice, bob, carol = devices
    admit(alice, carol, "Trio", "Carol")
    open_chat(alice, "Trio")
    open_chat(bob, "Trio")

    send(carol, "carol is here")
    bubble(alice, "chat_bubble_in", "carol is here", 60)
    bubble(bob, "chat_bubble_in", "carol is here", 60)
    send(bob, "bob sees carol")
    bubble(carol, "chat_bubble_in", "bob sees carol", 60)


def scenario_removal(devices):
    """GRP-264: a removed member gets no later message."""
    alice, bob, carol = devices
    details(alice, "Trio")
    alice.tap_node(alice.scroll_to("group_member_row", text="Bob"))
    alice.tap("group_member_remove")
    alice.tap("group_remove_confirm")
    time.sleep(5)

    open_chat(alice, "Trio")
    send(alice, "after the removal")
    bubble(carol, "chat_bubble_in", "after the removal", 60)
    send(carol, "carol after the removal")
    bubble(alice, "chat_bubble_in", "carol after the removal", 60)
    absent(bob, "chat_bubble_in", "after the removal")
    bob.wait("chat_stopped", 60)

    # GRP-306: an earlier message of the removed member keeps its name.
    earlier = bubble(alice, "chat_bubble_in", "bob sees carol")
    if "Bob" not in text_of(earlier):
        raise Fault(f"the message of a removed member shows no name: '{text_of(earlier)}'")

    # A member that leaves keeps the history, and can send no more.
    details(carol, "Trio")
    carol.tap_node(carol.scroll_to("group_leave"))
    carol.tap("group_leave_confirm")
    open_chat_row(carol, "Trio")
    carol.wait("chat_stopped", 60)


def link(alice, tablet):
    """Clears the tablet, and joins it to the device set of the first user."""
    home(alice)
    tablet.prepare()
    tablet.install(APK)
    tablet.stop()
    tablet.reset()
    tablet.start()
    tablet.wait("unlock_link", 90)
    tablet.tap("unlock_link")
    # The ticket works for 2 minutes, thus the new device is ready first.
    alice.tap("tabs_settings")
    alice.tap_node(alice.scroll_to("settings_devices"))
    alice.tap("devices_link")
    ticket = alice.text("link_ticket", 60)

    tablet.type("join_passphrase", PASSPHRASE)
    tablet.type("join_confirm", PASSPHRASE)
    tablet.back()
    tablet.tap("join_next")
    if tablet.visible("join_paste_instead"):
        tablet.tap("join_paste_instead")
    tablet.type("join_ticket", ticket)
    tablet.back()
    tablet.tap("join_link")

    shown = tablet.text("join_code", 90)
    held = alice.text("link_code", 90)
    if shown != held or not shown:
        raise Fault(f"the two link codes differ: '{held}' and '{shown}'")
    alice.tap("link_codes_match")
    alice.wait("link_done", 90)

    tablet.wait("tabs_chats", 120)
    tablet.wait("chats_row_title", 120, text="Bob")


def scenario_link(devices):
    """A third emulator joins the device set of the first one."""
    link(devices[0], devices[2])


def scenario_linked_messages(devices):
    """Each device of the set gets a message, and each one can send."""
    alice, bob, tablet = devices
    open_chat(bob, "Alice")
    open_chat(alice, "Bob")
    open_chat(tablet, "Bob")

    send(bob, "to both devices of alice")
    bubble(alice, "chat_bubble_in", "to both devices of alice", 60)
    bubble(tablet, "chat_bubble_in", "to both devices of alice", 60)

    send(tablet, "from the new device")
    bubble(bob, "chat_bubble_in", "from the new device", 60)
    # DEV: the first device shows what the second one sent.
    bubble(alice, "chat_bubble_out", "from the new device", 60)


def scenario_device_removal(devices):
    """DEV: a removed device gets no later message."""
    alice, bob, tablet = devices
    home(alice)
    alice.tap("tabs_settings")
    alice.tap_node(alice.scroll_to("settings_devices"))
    alice.wait("devices_link")
    # The row of this device is the first one.
    alice.tap_node(alice.find_all("devices_row")[-1])
    alice.tap("devices_remove")

    deadline = time.monotonic() + 60
    while len(alice.find_all("devices_row")) > 1:
        if time.monotonic() > deadline:
            raise Fault("the removed device stays in the list")
        time.sleep(1)

    # DEV-181: the removed device locks one time, and it then sends no more.
    tablet.wait("unlock_open", 180)
    unlock(tablet)
    tablet.wait("tabs_chats", 60)
    open_chat_row(tablet, "Bob")
    tablet.wait("chat_stopped", 60)

    open_chat(alice, "Bob")
    send(bob, "after the device removal")
    bubble(alice, "chat_bubble_in", "after the device removal", 60)
    absent(tablet, "chat_bubble_in", "after the device removal")


def scenario_removal_while_closed(devices):
    """DEV-181: a device that was closed at its removal learns of it at its next run."""
    alice, tablet = devices[0], devices[2]
    link(alice, tablet)
    tablet.stop()

    home(alice)
    alice.tap("tabs_settings")
    alice.tap_node(alice.scroll_to("settings_devices"))
    alice.wait("devices_link")
    alice.tap_node(alice.find_all("devices_row")[-1])
    alice.tap("devices_remove")
    time.sleep(10)

    # The removal can come before or after the first view, thus a lock can
    # come one time on the way to the chat.
    tablet.start()
    deadline = time.monotonic() + 300
    while not tablet.visible("chat_stopped"):
        if time.monotonic() > deadline:
            raise Fault(f"the removed device still takes a message: {summary(tablet.nodes())}")
        if tablet.visible("unlock_open"):
            unlock(tablet)
            time.sleep(5)
        elif tablet.visible("chats_row_title"):
            # The lock can come between the look and the tap.
            try:
                tablet.tap("chats_row_title", timeout=5, text="Bob")
            except Fault:
                continue
            time.sleep(5)
        elif tablet.visible("chat_input"):
            tablet.back()
            time.sleep(5)
        else:
            time.sleep(2)


def scenario_restore(devices):
    """An erased device takes its identity again from the recovery code (Part 4 §4.7.2)."""
    alice, bob = devices[0], devices[1]
    home(bob)
    bob.tap("tabs_settings")
    bob.tap_node(bob.scroll_to("settings_recovery"))
    code = bob.text("recovery_digits", 60).replace("\n", " ")

    # DEV-008: the platform ends the process, and the next start is a first launch.
    home(bob)
    bob.tap("tabs_settings")
    bob.tap_node(bob.scroll_to("settings_erase"))
    bob.tap("settings_erase_confirm")
    time.sleep(5)
    bob.grant()
    bob.start()

    bob.tap("unlock_restore", timeout=60)
    bob.type("restore_code", code)
    bob.type("restore_passphrase", PASSPHRASE)
    bob.type("restore_confirm", PASSPHRASE)
    bob.back()
    bob.tap_node(bob.scroll_to("restore_start"))
    bob.wait("tabs_chats", 300)

    bob.tap("tabs_settings")
    bob.tap_node(bob.scroll_to("settings_recovery"))
    again = bob.text("recovery_digits", 60).replace("\n", " ")
    if again != code:
        raise Fault("the restored store shows another recovery code")

    # The first backup is older than each contact, thus the store holds none.
    connect(bob, alice, "Bob again", "Alice")
    send(bob, "after the restore")
    bubble(alice, "chat_bubble_in", "after the restore", 60)
    send(alice, "an answer after the restore")
    bubble(bob, "chat_bubble_in", "an answer after the restore", 60)


SCENARIOS = [
    ("setup", scenario_setup, 2),
    ("contact", scenario_contact, 2),
    ("messages", scenario_messages, 2),
    ("edit", scenario_edit, 2),
    ("reaction", scenario_reaction, 2),
    ("reply", scenario_reply, 2),
    ("delete for everyone", scenario_delete_for_everyone, 2),
    ("poll", scenario_poll, 2),
    ("verify", scenario_verify, 2),
    ("search", scenario_search, 2),
    ("receipts", scenario_receipts, 2),
    ("file", scenario_file, 2),
    ("photo", scenario_photo, 2),
    ("audio", scenario_audio, 2),
    ("voice", scenario_voice, 2),
    ("notification", scenario_notification, 2),
    ("receipts arrive", scenario_receipts_arrive, 2),
    ("lock", scenario_lock, 2),
    ("passphrase", scenario_passphrase, 2),
    ("offline", scenario_offline, 2),
    ("group", scenario_group, 2),
    ("handle", scenario_handle, 3),
    ("group of three", scenario_group_of_three, 3),
    ("removal", scenario_removal, 3),
    ("link", scenario_link, 3),
    ("linked messages", scenario_linked_messages, 3),
    ("device removal", scenario_device_removal, 3),
    ("removal while closed", scenario_removal_while_closed, 3),
    ("restore", scenario_restore, 2),
]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    arguments = [argument for argument in sys.argv[1:] if not argument.startswith("--")]
    only = [argument[len("--only="):].split(",") for argument in sys.argv[1:] if argument.startswith("--only=")]
    devices = [Device(serial) for serial in arguments]
    if len(devices) < 2:
        sys.exit(__doc__)

    failed = []
    for name, scenario, needed in SCENARIOS:
        if only and name not in only[0]:
            continue
        if len(devices) < needed:
            print(f"SKIP  {name}: needs {needed} emulators")
            continue

        started = time.monotonic()
        try:
            scenario(devices)
            print(f"PASS  {name} ({time.monotonic() - started:.0f} s)", flush=True)
        except Exception as fault:
            failed.append(name)
            print(f"FAIL  {name}: {fault}", flush=True)
            if not isinstance(fault, Fault):
                traceback.print_exc()
            for at, device in enumerate(devices):
                device.screenshot(f"fail-{name.replace(' ', '-')}-{at}.png")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
