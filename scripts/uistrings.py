"""The interface strings of Part 14 §14.9.3.

Each rule that requires the Android interface to show a string has a
resource named after it: `umbra.ui.idn-024` is `umbra_ui_idn_024`, because a
resource name holds no dot and no hyphen (IMP-084). This check fails when a
rule below has no such string, when a string of a shipped locale is empty
(IMP-086, IMP-087), or when no source file reads it.

    python scripts/uistrings.py
"""

import glob
import os
import re
import sys
import xml.etree.ElementTree as ElementTree

ROOT = os.path.join(os.path.dirname(__file__), "..")
RES = os.path.join(ROOT, "android", "app", "src", "main", "res")
SOURCES = os.path.join(ROOT, "android", "app", "src", "main", "java")

# The rules that require a string of the Android interface. A rule of the
# web client, and a rule of a feature that the app does not hold, is not here.
RULES = [
    "IDN-010", "IDN-014", "IDN-024", "IDN-087", "IDN-088", "IDN-089", "IDN-152",
    "DEV-126", "DEV-137", "DEV-218", "NTF-009", "DIS-084", "NET-103",
    "GRP-050", "GRP-087", "GRP-090", "GRP-374",
    "ATT-157", "ABU-040", "ABU-041", "IMP-047", "IMP-050",
    "REL-116", "REL-126", "IMP-082",
]


def resource_name(rule: str) -> str:
    return "umbra_ui_" + rule.lower().replace("-", "_")


def strings_of(folder: str) -> dict:
    found = {}
    for path in glob.glob(os.path.join(folder, "*.xml")):
        tree = ElementTree.parse(path)
        for node in tree.getroot().iter("string"):
            found[node.get("name")] = "".join(node.itertext()).strip()
    return found


def main() -> int:
    problems = []
    locales = sorted(glob.glob(os.path.join(RES, "values*")))
    locales = [folder for folder in locales if strings_of(folder)]
    source = ""
    for path in glob.glob(os.path.join(SOURCES, "**", "*.kt"), recursive=True):
        with open(path, encoding="utf-8") as handle:
            source += handle.read()
    for folder in locales:
        found = strings_of(folder)
        locale = os.path.basename(folder)
        for rule in RULES:
            name = resource_name(rule)
            if not found.get(name):
                problems.append(f"{locale}: no string for umbra.ui.{rule.lower()} ({name})")
    for rule in RULES:
        name = resource_name(rule)
        if not re.search(r"R\.string\." + name + r"\b", source):
            problems.append(f"no source reads {name}")
    for problem in problems:
        print(problem)
    print(f"rules: {len(RULES)}  locales: {len(locales)}  problems: {len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
