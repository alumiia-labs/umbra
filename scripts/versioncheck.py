#!/usr/bin/env python3
"""Checks that each place of the version table of AGENTS.md holds one version.

The version of `[workspace.package]` in Cargo.toml is the reference.

Usage: python scripts/versioncheck.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def found(path: Path, pattern: str) -> list[str]:
    """Each version that the pattern finds in the file."""
    text = path.read_text(encoding="utf-8")
    return re.findall(pattern, text, flags=re.MULTILINE)


def main() -> int:
    reference = found(ROOT / "Cargo.toml", r'^version = "([^"]+)"$')
    if len(reference) != 1:
        print("Cargo.toml: no single workspace version", file=sys.stderr)
        return 1
    version = reference[0]

    # Each place: the file, the pattern, and the count of matches it must have.
    places = [
        (ROOT / "android/app/build.gradle.kts", r'^val appVersion = "([^"]+)"$', 1),
        (ROOT / "site/package.json", r'^\s*"version": "([^"]+)",?$', 1),
        (ROOT / "deploy/helm/umbra-relay/Chart.yaml", r"^version: (\S+)$", 1),
        (ROOT / "deploy/helm/umbra-relay/Chart.yaml", r'^appVersion: "([^"]+)"$', 1),
        (ROOT / "compose.yaml", r"umbra-relay:([0-9][^}@\s]*)", 1),
    ]
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        places.append((manifest, r'version = "([^"]+)", path = ', None))
    parts = sorted((ROOT / "spec").glob("[0-9][0-9]-*.md"))
    if not parts:
        print("spec: no part file", file=sys.stderr)
        return 1
    for part in parts:
        places.append((part, r"^\*\*Version:\*\* (\S+)$", 1))

    faults = []
    for path, pattern, count in places:
        name = path.relative_to(ROOT).as_posix()
        versions = found(path, pattern)
        if count is not None and len(versions) != count:
            faults.append(f"{name}: {len(versions)} version lines, not {count}")
        for other in versions:
            if other != version:
                faults.append(f"{name}: {other} is not {version}")

    for fault in faults:
        print(fault, file=sys.stderr)
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main())
