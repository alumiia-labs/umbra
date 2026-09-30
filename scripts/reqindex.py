#!/usr/bin/env python3
"""Regenerate spec/req-index.md from the requirement markers in spec/.

The index has one row per marker. This tool:
  * keeps the row of every marker that still exists, but corrects its
    Section column to the section that holds the marker now, and replaces
    its Requirement cell with the sentence after the marker when the kept
    text no longer appears in the specification;
  * removes the row of every marker that no longer exists;
  * adds a row for every marker that has no row, with the key word, the
    binder, and the requirement sentence extracted from the text that follows
    the marker;
  * rewrites the Summary table from the rows.

Rows stay grouped by part in prefix order, and inside a part they are sorted
by number. Run scripts/speccheck.py afterwards.

Usage: python scripts/reqindex.py [--dry-run]
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from speccheck import FILE_PART, HEADER_RE, MARKER_RE, PREFIX_FILE, SPEC, strip_code  # noqa: E402

PART_TITLE = {
    "SCP": "Scope and Conventions",
    "THR": "Threat Model and Security Goals",
    "NET": "Network Architecture",
    "IDN": "Identity",
    "CRY": "Cryptographic Core",
    "WIR": "Wire Format",
    "DEV": "Device Sets",
    "NTF": "Notifications",
    "DIS": "Discovery, Handles, and Key Transparency",
    "REL": "Relay Directory",
    "GRP": "Private Groups",
    "ATT": "Attachments and Large Objects",
    "ABU": "Anti-Abuse Without Identifiers",
    "IMP": "Implementation",
    "SEC": "Security Considerations",
}
KEYWORDS = ["MUST NOT", "SHOULD NOT", "MUST", "SHOULD", "MAY"]
ROW_RE = re.compile(r"^\|\s*`([A-Z]{3}-\d{3})`\s*\|\s*§[\d.]+\s*\|(.*)$")


def paragraphs(lines):
    """Yield (start_line_no, joined_text) for each paragraph outside fences."""
    buf, start, in_fence = [], None, False
    for no, raw in enumerate(lines, 1):
        if raw.startswith("```"):
            in_fence = not in_fence
            if buf:
                yield start, " ".join(buf)
                buf, start = [], None
            continue
        if in_fence:
            continue
        s = raw.strip()
        if not s:
            if buf:
                yield start, " ".join(buf)
                buf, start = [], None
            continue
        s = re.sub(r"^(?:>\s*|[-*]\s+|\d+\.\s+|\|\s*)+", "", s)
        if start is None:
            start = no
        buf.append(s)
    if buf:
        yield start, " ".join(buf)


def extract_sentence(text_after: str) -> str:
    """The requirement sentence that follows a marker."""
    t = re.sub(r"^(?:\*\*|\s)+", "", text_after)
    # stop at the next marker
    nxt = MARKER_RE.search(t)
    if nxt:
        t = t[: nxt.start()]
    # end at the first sentence terminator followed by a space or the end
    m = re.search(r"\.\*\*(?=\s|$)|\.(?=\s|$)", t)
    if m:
        t = t[: m.end()]
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"\*\*\s*$", "", t).strip()
    # drop unmatched bold markers that a split left behind
    if t.count("**") % 2:
        t = t.replace("**", "", 1) if t.startswith("**") else t[: t.rfind("**")] + t[t.rfind("**") + 2:]
    return t


def keyword_and_binder(sentence: str):
    plain = sentence.replace("**", "")
    for kw in KEYWORDS:
        idx = plain.find(f" {kw} ")
        if idx < 0 and plain.startswith(kw + " "):
            idx = 0
        if idx >= 0:
            binder = plain[:idx].strip() if idx > 0 else "(unstated)"
            binder = re.sub(r"^(Thus|Then|Also|But)\s+", "", binder)
            if not binder or len(binder) > 60:
                binder = "(unstated)"
            return kw, binder
    return "MUST", "(unstated)"


def normalized(text: str) -> str:
    """Text with no emphasis, no code marks, and single spaces."""
    text = text.replace("**", "").replace("`", "").replace("*", "")
    return re.sub(r"\s+", " ", text).strip().rstrip(".")


def collect_markers():
    """id -> (prefix, number, section, sentence, text after the marker)"""
    out = {}
    for fname, part in FILE_PART.items():
        path = SPEC / fname
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        # section per line
        sec_at = {}
        current = str(part)
        for no, raw in enumerate(lines, 1):
            h = HEADER_RE.match(raw)
            if h:
                current = h.group(2)
            sec_at[no] = current
        for start, text in paragraphs(lines):
            stripped = strip_code(text)
            for m in MARKER_RE.finditer(stripped):
                rid = m.group(1)
                if rid in out:
                    continue
                after = text[m.end():]
                sentence = extract_sentence(after)
                nxt = MARKER_RE.search(after)
                segment = after[: nxt.start()] if nxt else after
                out[rid] = (rid[:3], int(rid[4:]), sec_at[start], sentence, normalized(segment))
    return out


def load_rows():
    path = SPEC / "req-index.md"
    lines = path.read_text(encoding="utf-8").splitlines()
    rows = {}
    for raw in lines:
        m = ROW_RE.match(raw)
        if m:
            rows[m.group(1)] = m.group(2)  # everything after the Section cell
    return lines, rows


def main(argv):
    dry = "--dry-run" in argv
    markers = collect_markers()
    lines, rows = load_rows()

    kept, added, removed, refreshed = 0, [], [], []
    new_rows = {}
    for rid, (prefix, num, sec, sentence, segment) in markers.items():
        if rid in rows:
            cells = rows[rid].split("|")
            # cells: key word, binder, requirement, module, test, ""
            if len(cells) >= 5 and normalized(cells[2]) not in segment:
                cells[2] = f" {sentence} "
                refreshed.append(rid)
            new_rows[rid] = f"| `{rid}` | §{sec} |" + "|".join(cells)
            kept += 1
        else:
            kw, binder = keyword_and_binder(sentence)
            new_rows[rid] = f"| `{rid}` | §{sec} | {kw} | {binder} | {sentence} |  |  |"
            added.append(rid)
    for rid in rows:
        if rid not in markers:
            removed.append(rid)

    # summary counts
    counts = defaultdict(Counter)
    for rid, row in new_rows.items():
        cells = [c.strip() for c in row.split("|")]
        kw = cells[3]
        counts[rid[:3]][kw] += 1

    # rebuild the file: keep the preamble up to the Summary table, rewrite the rest
    head_end = next(i for i, l in enumerate(lines) if l.startswith("## Summary"))
    out = lines[:head_end]
    out.append("## Summary")
    out.append("")
    out.append("| Prefix | MUST | MUST NOT | SHOULD | SHOULD NOT | MAY | Total |")
    out.append("| --- | --- | --- | --- | --- | --- | --- |")
    grand = Counter()
    for prefix in PREFIX_FILE:
        c = counts[prefix]
        total = sum(c.values())
        out.append(f"| `{prefix}` | {c['MUST']} | {c['MUST NOT']} | {c['SHOULD']} | {c['SHOULD NOT']} | {c['MAY']} | **{total}** |")
        grand.update(c)
    out.append(f"| **All** | {grand['MUST']} | {grand['MUST NOT']} | {grand['SHOULD']} | {grand['SHOULD NOT']} | {grand['MAY']} | **{sum(grand.values())}** |")
    out.append("")
    for prefix, fname in PREFIX_FILE.items():
        out.append(f"## {prefix} — {PART_TITLE[prefix]}")
        out.append("")
        out.append(f"Source: `spec/{fname}`")
        out.append("")
        out.append("| ID | Section | Key word | Binds | Requirement | Module | Test |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        ids = sorted((rid for rid in new_rows if rid.startswith(prefix)), key=lambda r: int(r[4:]))
        for rid in ids:
            out.append(new_rows[rid])
        out.append("")

    print(f"markers: {len(markers)}  kept rows: {kept}  added: {len(added)}  removed: {len(removed)}  refreshed: {len(refreshed)}")
    if added:
        print("added:", ", ".join(added))
    if removed:
        print("removed:", ", ".join(removed))
    if not dry:
        (SPEC / "req-index.md").write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
        print("wrote spec/req-index.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
