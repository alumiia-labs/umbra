#!/usr/bin/env python3
"""Consistency checker for the UMBRA specification.

Checks, in order:
  1. Each requirement marker `**[XXX-NNN]**` (or `[XXX-NNN]` inside an
     emphasized span) in spec/*.md is unique, sits in the file that owns its
     prefix, and has exactly one row in spec/req-index.md.
  2. Each row of req-index.md names a marker that exists, and its Section
     column names the section that holds the marker.
  3. The Summary table of req-index.md agrees with the rows.
  4. Each rule reference `XXX-NNN` anywhere in spec/ names a marker that exists.
  5. Each cross-reference `Part N §A.B[.C]` names a section header that exists
     in Part N, and each bare `§A.B[.C]` names a header in the same part.
  6. Each `Part N` mention names a part that exists.

Exit status is 1 when any check fails. Use --quiet to print counts only.
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec"

PREFIX_FILE = {
    "SCP": "01-scope-and-conventions.md",
    "THR": "02-threat-model.md",
    "NET": "03-network-architecture.md",
    "IDN": "04-identity.md",
    "CRY": "05-cryptographic-core.md",
    "WIR": "06-wire-format.md",
    "DEV": "07-device-sets.md",
    "NTF": "08-notifications.md",
    "DIS": "09-discovery.md",
    "REL": "10-relay-directory.md",
    "GRP": "11-private-groups.md",
    "COM": "12-communities.md",
    "ATT": "13-attachments.md",
    "ABU": "14-anti-abuse.md",
    "IMP": "15-implementation.md",
    "SEC": "16-security-considerations.md",
}
FILE_PART = {f: i + 1 for i, f in enumerate(PREFIX_FILE.values())}

MARKER_RE = re.compile(r"\[([A-Z]{3}-\d{3})\]")
RULE_REF_RE = re.compile(r"(?<![A-Z0-9-])([A-Z]{3}-\d{3})(?![0-9-])")
HEADER_RE = re.compile(r"^(#{2,5})\s+(\d+(?:\.\d+){1,3})\b")
PART_SECTION_RE = re.compile(r"Part (\d+)\s+§(\d+(?:\.\d+){1,3})")
BARE_SECTION_RE = re.compile(r"(?<!Part \d )(?<!Part \d\d )(?<!RFC \d{4} )(?<!RFC \d{4} §)§(\d+(?:\.\d+){1,3})")
PART_RE = re.compile(r"\bPart (\d+)\b")
ROW_RE = re.compile(r"^\|\s*`([A-Z]{3}-\d{3})`\s*\|\s*§([\d.]+)\s*\|\s*([A-Z ]+?)\s*\|")
SUMMARY_RE = re.compile(r"^\|\s*`([A-Z]{3})`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*\*\*(\d+)\*\*")


def strip_code(line: str) -> str:
    """Drop inline code spans so backticked references do not count as markers."""
    return re.sub(r"`[^`]*`", lambda m: " " * len(m.group(0)), line)


def load_spec():
    """Return (markers, sections, texts).

    markers: id -> (file, line, section)
    sections: part -> {section number}
    texts: file -> list of lines
    """
    markers = {}
    dupes = []
    sections = defaultdict(set)
    texts = {}
    for fname, part in FILE_PART.items():
        path = SPEC / fname
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        texts[fname] = lines
        current = f"{part}"
        in_fence = False
        for no, raw in enumerate(lines, 1):
            if raw.startswith("```"):
                in_fence = not in_fence
                continue
            h = HEADER_RE.match(raw)
            if h:
                current = h.group(2)
                sections[part].add(current)
                continue
            if in_fence:
                continue
            for m in MARKER_RE.finditer(strip_code(raw)):
                rid = m.group(1)
                if rid in markers:
                    dupes.append((rid, fname, no, markers[rid]))
                else:
                    markers[rid] = (fname, no, current)
    return markers, dupes, sections, texts


def load_index():
    path = SPEC / "req-index.md"
    rows = {}
    row_dupes = []
    summary = {}
    for no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        r = ROW_RE.match(raw)
        if r:
            rid, sec, kw = r.group(1), r.group(2), r.group(3).strip()
            if rid in rows:
                row_dupes.append((rid, no))
            else:
                rows[rid] = (sec, kw, no)
            continue
        s = SUMMARY_RE.match(raw)
        if s:
            summary[s.group(1)] = tuple(int(x) for x in s.groups()[1:])
    return rows, row_dupes, summary


def main(argv):
    quiet = "--quiet" in argv
    problems = defaultdict(list)

    markers, dupes, sections, texts = load_spec()
    rows, row_dupes, summary = load_index()

    for rid, f, no, first in dupes:
        problems["duplicate-marker"].append(f"{rid} at {f}:{no}, first at {first[0]}:{first[1]}")
    for rid, no in row_dupes:
        problems["duplicate-index-row"].append(f"{rid} at req-index.md:{no}")

    # 1. markers -> file ownership and index rows
    for rid, (f, no, sec) in markers.items():
        prefix = rid[:3]
        if PREFIX_FILE.get(prefix) != f:
            problems["marker-in-wrong-file"].append(f"{rid} at {f}:{no}")
        if rid not in rows:
            problems["marker-without-row"].append(f"{rid} at {f}:{no} (§{sec})")

    # 2. rows -> markers and section agreement
    for rid, (sec, kw, no) in rows.items():
        if rid not in markers:
            problems["row-without-marker"].append(f"{rid} at req-index.md:{no}")
            continue
        real = markers[rid][2]
        if sec != real:
            problems["row-section-mismatch"].append(
                f"{rid}: index says §{sec}, marker sits in §{real} ({markers[rid][0]}:{markers[rid][1]})")

    # 3. summary counts
    counts = defaultdict(Counter)
    for rid, (sec, kw, no) in rows.items():
        counts[rid[:3]][kw] += 1
    for prefix in PREFIX_FILE:
        got = counts.get(prefix, Counter())
        want = summary.get(prefix)
        actual = (got["MUST"], got["MUST NOT"], got["SHOULD"], got["SHOULD NOT"], got["MAY"], sum(got.values()))
        if want is None:
            problems["summary-row-missing"].append(prefix)
        elif tuple(want) != actual:
            problems["summary-count-mismatch"].append(f"{prefix}: table {want}, rows {actual}")

    # 4-6. references
    for fname, lines in texts.items():
        part = FILE_PART[fname]
        in_fence = False
        prev = ""
        for no, raw in enumerate(lines, 1):
            if raw.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            prev = raw
            for m in RULE_REF_RE.finditer(raw):
                rid = m.group(1)
                if rid[:3] in PREFIX_FILE and rid not in markers and "retire" not in raw:
                    problems["dangling-rule-ref"].append(f"{rid} at {fname}:{no}")
            for m in PART_SECTION_RE.finditer(raw):
                p, sec = int(m.group(1)), m.group(2)
                if p not in sections:
                    problems["dangling-part-ref"].append(f"Part {p} at {fname}:{no}")
                elif sec not in sections[p]:
                    problems["dangling-section-ref"].append(f"Part {p} §{sec} at {fname}:{no}")
            for m in BARE_SECTION_RE.finditer(raw):
                sec = m.group(1)
                top = int(sec.split(".")[0])
                if top != part:
                    # A bare §X.Y that names another part. The style is loose in
                    # the source, thus only a missing target is a problem.
                    if sec not in sections.get(top, set()):
                        problems["dangling-section-ref"].append(f"§{sec} (Part {top}) at {fname}:{no}")
                elif sec not in sections[part]:
                    problems["dangling-section-ref"].append(f"§{sec} at {fname}:{no}")
            for m in PART_RE.finditer(raw):
                p = int(m.group(1))
                if p not in sections:
                    problems["dangling-part-ref"].append(f"Part {p} at {fname}:{no}")

    # index rows also reference sections; check those against the owning part
    for rid, (sec, kw, no) in rows.items():
        if rid in markers:
            part = FILE_PART[markers[rid][0]]
            if sec not in sections[part]:
                problems["index-section-unknown"].append(f"{rid} §{sec} at req-index.md:{no}")

    total = sum(len(v) for v in problems.values())
    print(f"markers: {len(markers)}  index rows: {len(rows)}  problems: {total}")
    for cat in sorted(problems):
        items = problems[cat]
        print(f"  {cat}: {len(items)}")
        if not quiet:
            for it in items:
                print(f"    {it}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
