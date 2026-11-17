"""End-to-end scenarios of the debug app on two or three emulators.

Start `scripts/devnet.sh` and the emulators first (README.md). Each scenario
continues from the state of the one before it, thus the order is fixed.

    python run.py emulator-5554 emulator-5556 [emulator-5558]
"""

import sys
import time
import traceback

from driver import Device, Fault, summary, text_of

APK = "../../android/app/build/outputs/apk/debug/app-debug.apk"
PASSPHRASE = "correct horse battery"


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
    """Goes back to the tabs from any view under them."""
    for _ in range(8):
        if device.visible("tabs_chats"):
            return
        device.back()
        time.sleep(0.5)
    raise Fault(f"{device.serial}: no way back to the tabs")


def open_chat(device, title):
    home(device)
    device.tap("tabs_chats")
    device.tap("chats_row_title", text=title)
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

    accepter.type("name_field", inviter_name, timeout=90)
    accepter.back()
    accepter.tap("name_save")
    inviter.type("name_field", accepter_name, timeout=90)
    inviter.back()
    inviter.tap("name_save")

    inviter.wait("chat_input")
    accepter.wait("chat_input")


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


def scenario_lock(devices):
    alice = devices[0]
    home(alice)
    alice.tap("tabs_lock")
    alice.wait("unlock_open")

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
    bubble(alice, "chat_bubble_in", "first from bob")


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

    alice.tap("common_bar_title")
    alice.tap_node(alice.scroll_to("group_add_members"))
    alice.tap("group_invite_row", text="Bob")

    home(bob)
    bob.tap("tabs_chats")
    bob.tap("group_offer_join", timeout=90)

    # GRP: the admin lets the joiner in (Part 11 §11.9.1).
    alice.back()
    deadline = time.monotonic() + 90
    while not alice.visible("group_let_in"):
        if time.monotonic() > deadline:
            raise Fault("the admin sees no request of the joiner")
        alice.shell("input swipe 540 1700 540 900 300")
    alice.tap("group_let_in")

    bob.tap("chats_row_title", timeout=120, text="Trio")
    bob.wait("chat_input")
    open_chat(alice, "Trio")
    send(alice, "hello group")
    bubble(bob, "chat_bubble_in", "hello group", 60)
    send(bob, "bob answers the group")
    bubble(alice, "chat_bubble_in", "bob answers the group", 60)


def scenario_link(devices):
    """A third emulator joins the device set of the first one."""
    alice, tablet = devices[0], devices[2]
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


SCENARIOS = [
    ("setup", scenario_setup, 2),
    ("contact", scenario_contact, 2),
    ("messages", scenario_messages, 2),
    ("edit", scenario_edit, 2),
    ("reaction", scenario_reaction, 2),
    ("delete for everyone", scenario_delete_for_everyone, 2),
    ("lock", scenario_lock, 2),
    ("offline", scenario_offline, 2),
    ("group", scenario_group, 2),
    ("link", scenario_link, 3),
    ("linked messages", scenario_linked_messages, 3),
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
