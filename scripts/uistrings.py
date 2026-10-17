"""The interface strings of Part 14 §14.9.3.

Each rule that requires the Android interface to show a string has a
resource named after it: `umbra.ui.idn-024` is `umbra_ui_idn_024`, because a
resource name holds no dot and no hyphen (IMP-084). A rule with more than one
string names each one with a suffix, as `umbra_ui_dev_126_edit`, beside the
string of the plain name. A rule of `SUFFIX_ONLY` holds suffixed strings
alone, as `umbra_ui_imp_077_offline`. This check fails when a rule below has
no such string, and when a string of a rule is absent or empty in a shipped
locale (IMP-086, IMP-087). It also fails when no source file reads a string,
and when a string of the family names no rule below.

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

# The rules that require a string of the Android interface. A rule of a
# feature that the app does not hold is not here.
RULES = [
    "IDN-010", "IDN-014", "IDN-024", "IDN-087", "IDN-088", "IDN-089", "IDN-152",
    "DEV-126", "DEV-137", "DEV-218", "NTF-009", "DIS-084", "NET-103", "WIR-341",
    "GRP-050", "GRP-087", "GRP-090", "GRP-199", "GRP-229", "GRP-374",
    "ATT-157", "ABU-040", "ABU-041", "IMP-047", "IMP-050",
    "REL-116", "REL-126", "IMP-082", "NET-343", "DEV-114", "IMP-074",
    "NET-201", "IMP-077", "NET-359", "DEV-326", "DEV-334",
]

# The rules that hold no string of the plain name: each of their strings has
# a suffix. Each other rule needs the string of its plain name.
SUFFIX_ONLY = {"IMP-077"}


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

    names = [resource_name(rule) for rule in RULES]
    # The strings of each rule: the name of the rule, and each name with a
    # suffix, over all the locales.
    family = {name: set() for name in names}
    for folder in locales:
        for name in strings_of(folder):
            if not name.startswith("umbra_ui_"):
                continue
            known = [base for base in names if name == base or name.startswith(base + "_")]
            if not known:
                problems.append(f"{os.path.basename(folder)}: {name} names no rule")
            for base in known:
                family[base].add(name)

    for rule, base in zip(RULES, names):
        if rule in SUFFIX_ONLY:
            if not family[base]:
                problems.append(f"no string for umbra.ui.{rule.lower()} ({base}_*)")
            if base in family[base]:
                problems.append(f"{base} has no suffix, and {rule} is in SUFFIX_ONLY")
        elif base not in family[base]:
            problems.append(f"no string for umbra.ui.{rule.lower()} ({base})")
        for name in sorted(family[base]):
            for folder in locales:
                if not strings_of(folder).get(name):
                    problems.append(f"{os.path.basename(folder)}: no string for {name}")
            if not re.search(r"R\.string\." + name + r"\b", source):
                problems.append(f"no source reads {name}")

    for rule in sorted(SUFFIX_ONLY - set(RULES)):
        problems.append(f"SUFFIX_ONLY names {rule}, which RULES does not hold")

    for problem in problems:
        print(problem)
    print(f"rules: {len(RULES)}  locales: {len(locales)}  problems: {len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
