#!/usr/bin/env python3
"""Writes the pages of the web site of the domain from one template and the
text of each language.

  site/page.html        the template of each page
  site/locales/en.json  the English text, which each other language copies
  site/locales/<code>.json
                        the text of one other language, as `de.json`

English goes to `/i` and `/404.html`. Each other language goes to
`/<code>/i`, and a key that a language lacks takes the English text.

The host answers each unknown path with `/404.html` alone, thus that page
has English alone. The page of the invitation links to each language. A
link is a plain link of this host, because a page of this host holds no
script (Part 4 `IDN-120`, `IDN-121`).

The landing page needs no fragment: it tells the party to open the
invitation again after the install.

Usage: python scripts/sitebuild.py [--check]

  --check   write nothing, and fail when a page differs from what this
            script writes.
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PUBLIC = SITE / "public"
LOCALES = SITE / "locales"
SOURCE = "en"

# A language code, as `de` or `pt-BR`. The code names a folder and goes into
# the markup, thus it takes no other character.
CODE = re.compile(r"[a-z]{2,3}(-[A-Z]{2})?")

# Each page: its path under a language, and the keys of its text.
PAGES = {
    "i.html": ("invitation_title", "invitation_heading", "invitation_body"),
    "404.html": ("not_found_title", "not_found_heading", "not_found_body"),
}


def locales() -> dict[str, dict[str, str]]:
    found = {}
    for path in sorted(LOCALES.glob("*.json")):
        if not CODE.fullmatch(path.stem):
            sys.exit(f"site/locales/{path.name}: the name is no language code, as de or pt-BR")
        found[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return found


def languages_nav(texts: dict[str, dict[str, str]], current: str) -> str:
    if len(texts) < 2:
        return ""

    links = []
    for code in [SOURCE] + sorted(code for code in texts if code != SOURCE):
        name = html.escape(texts[code].get("_language", code))
        if code == current:
            links.append(f"<span>{name}</span>")
        else:
            href = html.escape("/i" if code == SOURCE else f"/{code}/i")
            attribute = html.escape(code)
            links.append(f'<a href="{href}" hreflang="{attribute}" lang="{attribute}">{name}</a>')
    return "\n<nav>" + " · ".join(links) + "</nav>"


def render() -> dict[Path, str]:
    template = (SITE / "page.html").read_text(encoding="utf-8")
    texts = locales()
    source = texts[SOURCE]

    out = {}
    for code, text in texts.items():
        merged = {**source, **text}
        folder = PUBLIC if code == SOURCE else PUBLIC / code
        for page, (title, heading, body) in PAGES.items():
            if code != SOURCE and page == "404.html":
                continue
            nav = languages_nav(texts, code) if page == "i.html" else ""
            out[folder / page] = (
                template.replace("{{lang}}", html.escape(code))
                .replace("{{dir}}", html.escape(merged.get("_dir", "ltr")))
                .replace("{{title}}", html.escape(merged[title]))
                .replace("{{heading}}", html.escape(merged[heading]))
                .replace("{{body}}", html.escape(merged[body]))
                .replace("{{languages}}", nav)
            )
    return out


def main() -> int:
    is_check = "--check" in sys.argv[1:]
    pages = render()

    stale = []
    for path, text in pages.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        stale.append(path.relative_to(ROOT).as_posix())
        if not is_check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")

    if is_check and stale:
        for name in stale:
            print(f"{name} is stale; run scripts/sitebuild.py")
        return 1

    for name in stale:
        print(f"wrote {name}")
    if not stale:
        print("site pages are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
