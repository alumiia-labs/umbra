#!/usr/bin/env python3
"""Checks the web site of the domain, `site/public`, against Part 4 §4.3.1.

  IDN-120  the landing document holds no script;
  IDN-121  the landing document references no resource on a second host;
  IDN-122  the host serves `/.well-known/assetlinks.json`, which names the
           client package.

The check reads each HTML document and each SVG image of the site, because
a script on any of them runs on the invitation host. It holds the headers
of `_headers` to the rules of `HEADERS` below, and the mail logo to the file
that `scripts/logo.py` writes.

Usage: python scripts/sitecheck.py [--release] [--live <origin>]

  --release   also fail while the fingerprint of the release signing
              certificate is the placeholder.
  --live      also fetch the pages from the origin given, as
              https://umbrachat.app, with the request of a browser. Hold
              what the host serves, and the headers of each answer, to the
              same rules. A host can write into a page or drop a header
              while it serves the page, which no file here shows.
"""
from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site" / "public"
PACKAGE = "com.alumiialabs.umbra"
# The attributes that make a browser read a resource or follow a location.
LOADS = {"src", "srcset", "href", "action", "formaction", "poster", "data",
         "background", "ping", "manifest", "cite", "xlink:href"}
FINGERPRINT = re.compile(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
# The directives of the Content-Security-Policy of each page. A browser
# then refuses a script, a frame, or a form that a page holds after all.
CSP = ("default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'",
       "form-action 'none'")
# Each other header of each page, and a part of its value. `no-transform`
# keeps Cloudflare from writing into a page.
HEADERS = {
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "strict-transport-security": "max-age=",
    "cache-control": "no-transform",
}


def header_problems(where: str, headers: dict[str, str]) -> list[str]:
    """The faults of the headers of one page; `headers` has lower-case names."""
    problems = []
    policy = [part.strip() for part in headers.get("content-security-policy", "").split(";")]
    for directive in CSP:
        if directive not in policy:
            problems.append(f"{where}: the Content-Security-Policy has no {directive}")

    for name, part in HEADERS.items():
        if part not in headers.get(name, "").lower():
            problems.append(f"{where}: no {name} with {part}")
    return problems


def read_headers(path: Path) -> dict[str, dict[str, str]]:
    """The rules of a `_headers` file of Cloudflare: each path with its
    headers, by lower-case name. A `! name` line drops a header, and the rule
    keeps a mark `!name` for it."""
    rules: dict[str, dict[str, str]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            current = rules.setdefault(line.strip(), {})
        elif current is not None and line.strip().startswith("!"):
            current["!" + line.strip()[1:].strip().lower()] = ""
        elif current is not None and ":" in line:
            name, value = line.strip().split(":", 1)
            current[name.strip().lower()] = value.strip()
    return rules


def check_headers(problems: list[str]) -> None:
    rules = read_headers(SITE / "_headers")
    every = rules.get("/*")
    if every is None:
        problems.append("_headers: no rule for /*, which holds the headers of each page")
        return

    problems.extend(header_problems("_headers /*", every))

    for path, headers in rules.items():
        for name in ["content-security-policy", *HEADERS]:
            if "!" + name in headers and name not in headers:
                problems.append(f"_headers {path}: drops {name}")

        cache = headers.get("cache-control")
        if cache is not None and "no-transform" not in cache.lower():
            problems.append(f"_headers {path}: a Cache-Control with no no-transform")


class Document(HTMLParser):
    def __init__(self, name: str, problems: list[str]):
        super().__init__(convert_charrefs=True)
        self.name, self.problems = name, problems
        self.in_style = False

    def fault(self, text: str) -> None:
        line, _ = self.getpos()
        self.problems.append(f"{self.name}:{line}: {text}")

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "iframe", "frame", "object", "embed", "base", "form"}:
            self.fault(f"IDN-120: a <{tag}> element")
        if tag == "style":
            self.in_style = True

        for key, value in attrs:
            key = key.lower()
            value = (value or "").strip()
            if key.startswith("on"):
                self.fault(f"IDN-120: the event attribute {key}")
            if key == "http-equiv" and value.lower() == "refresh":
                self.fault("IDN-121: a refresh that moves the browser")
            if key == "style" and "url(" in value.replace(" ", "").lower():
                self.fault("IDN-121: a url() in a style attribute")
            if key in LOADS:
                for part in value.split(","):
                    self.location(part.strip().split(" ")[0])

    def handle_endtag(self, tag):
        if tag == "style":
            self.in_style = False

    def handle_data(self, data):
        if self.in_style:
            if "@import" in data.lower():
                self.fault("IDN-121: an @import in a style sheet")
            # A style sheet reads a file of this host alone, as the font.
            for value in re.findall(r"url\(\s*['\"]?([^'\")\s]*)", data, flags=re.I):
                self.location(value)

    def location(self, value: str) -> None:
        low = value.lower()
        if not value or low.startswith(("data:", "#")):
            return
        if low.startswith("javascript:"):
            self.fault("IDN-120: a javascript: location")
        # A path of this host begins with one slash. Each other form names a
        # scheme, a host, or a path that depends on the place of the document.
        elif not value.startswith("/") or value.startswith("//"):
            self.fault(f"IDN-121: a location outside this host: {value}")


def main() -> None:
    release = "--release" in sys.argv[1:]
    problems: list[str] = []

    documents = sorted(SITE.rglob("*.html"))
    if not (SITE / "i.html").is_file():
        problems.append("i.html: the landing document is absent (Part 4 §4.3.1)")
    for path in documents:
        name = path.relative_to(SITE).as_posix()
        Document(name, problems).feed(path.read_text(encoding="utf-8"))

    # A browser runs a script of an SVG image that it opens as a document.
    for path in sorted(SITE.rglob("*.svg")):
        Document(path.relative_to(SITE).as_posix(), problems).feed(path.read_text(encoding="utf-8"))
    for path in sorted(SITE.rglob("*.js")) + sorted(SITE.rglob("*.mjs")):
        problems.append(f"{path.relative_to(SITE).as_posix()}: IDN-120: a script file")

    check_headers(problems)

    links = SITE / ".well-known" / "assetlinks.json"
    try:
        statements = json.loads(links.read_text(encoding="utf-8"))
        targets = [s["target"] for s in statements
                   if "delegate_permission/common.handle_all_urls" in s["relation"]]
        named = [t for t in targets if t.get("namespace") == "android_app"
                 and t.get("package_name") == PACKAGE]
        if not named:
            problems.append(f"assetlinks.json: IDN-122: no statement names {PACKAGE}")

        for target in named:
            prints = target.get("sha256_cert_fingerprints") or []
            if not prints:
                problems.append("assetlinks.json: IDN-122: no certificate fingerprint")
            for value in prints:
                if value.startswith("FILL"):
                    if release:
                        problems.append("assetlinks.json: the fingerprint is the placeholder")
                elif not FINGERPRINT.match(value):
                    problems.append(f"assetlinks.json: no SHA-256 fingerprint: {value}")
    except (OSError, ValueError, KeyError, TypeError) as error:
        problems.append(f"assetlinks.json: IDN-122: {error}")

    logo = SITE / "bimi" / "logo.svg"
    source = ROOT / "brand" / "umbra-app-icon-tiny-ps.svg"
    if not logo.is_file() or logo.read_bytes() != source.read_bytes():
        problems.append("bimi/logo.svg: differs from brand/umbra-app-icon-tiny-ps.svg; "
                        "run python scripts/logo.py")

    if "--live" in sys.argv[1:]:
        import urllib.request

        origin = sys.argv[sys.argv.index("--live") + 1].rstrip("/")
        codes = sorted(path.stem for path in (ROOT / "site" / "locales").glob("*.json")
                       if path.stem != "en")

        for path in ["/i", "/no-such-page"] + [f"/{code}/i" for code in codes]:
            request = urllib.request.Request(origin + path, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
                "Accept": "text/html"})
            try:
                with urllib.request.urlopen(request, timeout=20) as answer:
                    body = answer.read().decode("utf-8", "replace")
                    headers = answer.headers
            except urllib.error.HTTPError as error:
                body = error.read().decode("utf-8", "replace")
                headers = error.headers
            except OSError as error:
                problems.append(f"{origin}{path}: no answer: {error}")
                continue

            Document(f"{origin}{path}", problems).feed(body)
            problems.extend(header_problems(
                f"{origin}{path}", {name.lower(): value for name, value in headers.items()}))

    print(f"documents: {len(documents)}  problems: {len(problems)}")
    for line in problems:
        print("  " + line)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
