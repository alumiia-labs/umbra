#!/usr/bin/env python3
"""Checks each translation of the Android app and of the web site against
its English source.

The app: each `res/values-<language>/` folder against `res/values/`
(`strings.xml` and `ui_rules.xml`). The check fails on:

  - a name that the English source does not hold;
  - a name that the source marks `translatable="false"`;
  - placeholders that differ from the source, as `%1$s` for `%1$d`;
  - a plural with no `other` form, or an empty string;
  - an apostrophe or a quote with no backslash, which the build rejects.

A string that a translation lacks is no fault: the app shows the English
text. `scripts/uistrings.py` holds each string of a rule to a stricter
rule: a shipped language holds each one (Part 14 `IMP-086`).

The site: each `site/locales/<code>.json` against `en.json`. The check fails
on a key that `en.json` does not hold, on a value that is not text, and on
markup in a value, because the page writes each value as plain text.

Usage: python scripts/l10ncheck.py
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "android" / "app" / "src" / "main" / "res"
LOCALES = ROOT / "site" / "locales"
FILES = ("strings.xml", "ui_rules.xml")
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z%]")
# A language folder: values-de, values-pt-rBR, values-b+sr+Latn. A folder
# of another qualifier, as values-v31 or values-night, is no language.
LANGUAGE = re.compile(r"^values-([a-z]{2,3}(-r[A-Z]{2})?|b\+[A-Za-z0-9+]+)$")


class Entry:
    def __init__(self, kind: str, texts: dict[str, str], translatable: bool):
        self.kind, self.texts, self.translatable = kind, texts, translatable


def text_of(node) -> str:
    return "".join(node.itertext())


def entries(folder: Path, problems: list[str]) -> dict[str, Entry]:
    found: dict[str, Entry] = {}
    for name in FILES:
        path = folder / name
        if not path.exists():
            continue
        try:
            root = ElementTree.parse(path).getroot()
        except ElementTree.ParseError as fault:
            problems.append(f"{path.relative_to(ROOT).as_posix()}: {fault}")
            continue
        for node in root:
            key = node.get("name")
            translatable = node.get("translatable") != "false"
            if node.tag == "string":
                found[key] = Entry("string", {"": text_of(node)}, translatable)
            elif node.tag == "plurals":
                items = {item.get("quantity"): text_of(item) for item in node.iter("item")}
                found[key] = Entry("plurals", items, translatable)
    return found


def placeholders(text: str) -> list[str]:
    return sorted(match for match in PLACEHOLDER.findall(text) if match != "%%")


def unescaped(text: str) -> bool:
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return False
    return re.search(r"(?<!\\)['\"]", text) is not None


def check_app(problems: list[str]) -> list[str]:
    lines = []
    source = entries(RES / "values", problems)
    total = sum(1 for entry in source.values() if entry.translatable)
    for folder in sorted(RES.iterdir()):
        if not folder.is_dir() or not LANGUAGE.match(folder.name):
            continue
        where = folder.name
        translated = entries(folder, problems)
        for key, entry in translated.items():
            base = source.get(key)
            if base is None:
                problems.append(f"{where}: {key} is not in the English source")
                continue
            if not base.translatable:
                problems.append(f"{where}: {key} is not translatable")
                continue
            if entry.kind != base.kind:
                problems.append(f"{where}: {key} is a {entry.kind}, and the source is a {base.kind}")
                continue
            if entry.kind == "plurals" and "other" not in entry.texts:
                problems.append(f"{where}: {key} has no 'other' form")
            want = placeholders(next(iter(base.texts.values())))
            if entry.kind == "plurals":
                want = placeholders(base.texts.get("other", ""))
            for quantity, text in entry.texts.items():
                label = f"{key}[{quantity}]" if quantity else key
                if not text.strip():
                    problems.append(f"{where}: {label} is empty")
                if unescaped(text):
                    problems.append(f"{where}: {label} has an apostrophe or a quote with no backslash")
                got = placeholders(text)
                # A plural form may leave out the count, as "one file".
                if entry.kind == "plurals" and quantity != "other":
                    if not set(got) <= set(want):
                        problems.append(f"{where}: {label} has {got}, and the source has {want}")
                elif got != want:
                    problems.append(f"{where}: {label} has {got}, and the source has {want}")
        done = sum(1 for key in translated if key in source and source[key].translatable)
        lines.append(f"app {where}: {done} of {total} strings")
    return lines


def check_site(problems: list[str]) -> list[str]:
    lines = []
    source = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
    total = sum(1 for key in source if not key.startswith("_"))
    for path in sorted(LOCALES.glob("*.json")):
        if path.stem == "en":
            continue
        where = f"site {path.name}"
        try:
            text = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as fault:
            problems.append(f"{where}: {fault}")
            continue
        for key, value in text.items():
            if key not in source:
                problems.append(f"{where}: {key} is not in en.json")
            elif not isinstance(value, str) or not value.strip():
                problems.append(f"{where}: {key} is not text")
            elif re.search(r"<[A-Za-z/!]|\{\{", value):
                problems.append(f"{where}: {key} holds markup")
        if text.get("_dir", "ltr") not in ("ltr", "rtl"):
            problems.append(f"{where}: _dir is not ltr or rtl")
        if "_language" not in text:
            problems.append(f"{where}: no _language, the name of the language in itself")
        done = sum(1 for key in text if key in source and not key.startswith("_"))
        lines.append(f"{where}: {done} of {total} texts")
    return lines


def main() -> int:
    problems: list[str] = []
    lines = check_app(problems) + check_site(problems)
    for line in lines:
        print(line)
    for problem in problems:
        print(problem)
    print(f"translations: {len(lines)}  problems: {len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
