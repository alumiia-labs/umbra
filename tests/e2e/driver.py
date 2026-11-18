"""Drives the debug app on an emulator through adb and UI Automator.

A control has the test name of `TestTags.kt` as its resource id. The driver
finds a control by that name, thus a change of a label breaks no test.
"""

import re
import subprocess
import time
import xml.etree.ElementTree as ET

PACKAGE = "com.alumiialabs.umbra"
BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


class Fault(Exception):
    """A step of a test that did not get its result."""


class Device:
    def __init__(self, serial, adb="adb"):
        self.serial = serial
        self.adb = adb

    def run(self, *args, check=True, timeout=60):
        command = [self.adb, "-s", self.serial, *args]
        done = subprocess.run(command, capture_output=True, timeout=timeout)
        if check and done.returncode != 0:
            raise Fault(f"{self.serial}: {' '.join(args)}: {done.stderr.decode(errors='replace')}")
        return done.stdout

    def shell(self, command, check=True, timeout=60):
        return self.run("shell", command, check=check, timeout=timeout).decode(errors="replace")

    def prepare(self):
        """Stops each animation, thus a dump waits for no idle state."""
        for scale in ("window_animation_scale", "transition_animation_scale", "animator_duration_scale"):
            self.shell(f"settings put global {scale} 0")

    def install(self, apk):
        self.run("install", "-r", "-g", apk, timeout=300)

    def reset(self):
        """Clears the store of the app. A clear takes each permission, thus this gives them again."""
        self.shell(f"pm clear {PACKAGE}")
        self.grant()

    def grant(self):
        """Gives each permission, thus no dialog of the system covers the app."""
        for permission in ("POST_NOTIFICATIONS", "CAMERA", "RECORD_AUDIO"):
            self.shell(f"pm grant {PACKAGE} android.permission.{permission}", check=False)

    def start(self):
        self.shell(f"monkey -p {PACKAGE} -c android.intent.category.LAUNCHER 1")

    def stop(self):
        self.shell(f"am force-stop {PACKAGE}")

    def nodes(self):
        """Each node of the window that is on the screen now."""
        for _ in range(5):
            raw = self.run("exec-out", "uiautomator", "dump", "/dev/tty", check=False).decode(errors="replace")
            start = raw.find("<?xml")
            end = raw.rfind("</hierarchy>")
            if start >= 0 and end >= 0:
                return list(ET.fromstring(raw[start:end + len("</hierarchy>")]).iter("node"))
            time.sleep(0.5)
        raise Fault(f"{self.serial}: no dump of the window")

    def find_all(self, tag, nodes=None):
        nodes = self.nodes() if nodes is None else nodes
        return [node for node in nodes if node.get("resource-id") == tag]

    def visible(self, tag):
        return bool(self.find_all(tag))

    def wait(self, tag, timeout=30, text=None):
        """Waits for a control, and for a text under it when `text` is set."""
        deadline = time.monotonic() + timeout
        while True:
            nodes = self.nodes()
            for node in self.find_all(tag, nodes):
                if text is None or text in text_of(node):
                    return node
            if time.monotonic() > deadline:
                raise Fault(f"{self.serial}: no '{tag}'" + (f" with '{text}'" if text else "")
                            + f" after {timeout} s; on the screen: {summary(nodes)}")
            time.sleep(0.5)

    def wait_any(self, tags, timeout=30):
        """Waits for the first of some controls, and gives its name."""
        deadline = time.monotonic() + timeout
        while True:
            nodes = self.nodes()
            for tag in tags:
                if self.find_all(tag, nodes):
                    return tag
            if time.monotonic() > deadline:
                raise Fault(f"{self.serial}: none of {tags} after {timeout} s; on the screen: {summary(nodes)}")
            time.sleep(0.5)

    def wait_text(self, text, timeout=30):
        """Waits for a text at any place of the window."""
        deadline = time.monotonic() + timeout
        while True:
            nodes = self.nodes()
            for node in nodes:
                if text in (node.get("text") or ""):
                    return node
            if time.monotonic() > deadline:
                raise Fault(f"{self.serial}: no text '{text}' after {timeout} s; on the screen: {summary(nodes)}")
            time.sleep(0.5)

    def wait_described(self, description, timeout=30):
        """Waits for a control of the system by its content description."""
        deadline = time.monotonic() + timeout
        while True:
            nodes = self.nodes()
            for node in nodes:
                if node.get("content-desc") == description:
                    return node
            if time.monotonic() > deadline:
                raise Fault(f"{self.serial}: no control '{description}' after {timeout} s; on the screen: {summary(nodes)}")
            time.sleep(0.5)

    def tap_node(self, node):
        left, top, right, bottom = map(int, BOUNDS.match(node.get("bounds")).groups())
        self.shell(f"input tap {(left + right) // 2} {(top + bottom) // 2}")

    def tap(self, tag, timeout=30, text=None):
        self.tap_node(self.wait(tag, timeout, text))

    def long_press(self, node):
        left, top, right, bottom = map(int, BOUNDS.match(node.get("bounds")).groups())
        x, y = (left + right) // 2, (top + bottom) // 2
        self.shell(f"input swipe {x} {y} {x} {y} 800")

    def type(self, tag, text, timeout=30):
        """Types into a field. The text holds no single quote."""
        self.tap(tag, timeout)
        time.sleep(0.3)
        escaped = text.replace(" ", "%s")
        self.shell(f"input text '{escaped}'")

    def type_more(self, text):
        """Types at the cursor of the field that has the focus."""
        escaped = text.replace(" ", "%s")
        self.shell(f"input text '{escaped}'")

    def scroll_to(self, tag, text=None, swipes=10):
        """Moves the view up until a control shows, and gives that control."""
        for _ in range(swipes):
            for node in self.find_all(tag):
                if text is None or text in text_of(node):
                    return node
            self.shell("input swipe 540 1700 540 900 300")
            time.sleep(0.4)
        raise Fault(f"{self.serial}: no '{tag}' after {swipes} swipes; on the screen: {summary(self.nodes())}")

    def back(self):
        self.shell("input keyevent 4")

    def text(self, tag, timeout=30):
        return text_of(self.wait(tag, timeout))

    def screenshot(self, path):
        with open(path, "wb") as out:
            out.write(self.run("exec-out", "screencap", "-p"))


def text_of(node):
    """The text of a node and of each node under it."""
    parts = [node.get("text") or ""]
    parts += [child.get("text") or "" for child in node.iter("node") if child is not node]
    return " ".join(part for part in parts if part)


def summary(nodes):
    """The test names and the texts of a window, for the text of a fault."""
    tags = sorted({node.get("resource-id") for node in nodes if node.get("resource-id")})
    texts = [node.get("text") for node in nodes if node.get("text")]
    return f"tags={tags} texts={texts[:25]}"
