#!/usr/bin/env python3
"""Checks the web site of the domain, `site/public`, against Part 4 §4.3.1.

  IDN-120  the landing document holds no script;
  IDN-121  the landing document references no resource on a second host;
  IDN-122  the host serves `/.well-known/assetlinks.json`, which names the
           client package.

The check reads each HTML document and each SVG image of the site, because
a script on any of them runs on the invitation host. It reads them with an
HTML parser. A browser reads an SVG image as XML, thus the check refuses
each form that XML reads in another way. It holds the headers
of `_headers` to the rules of `HEADERS` below, and the mail logo to the file
that `scripts/logo.py` writes.

Usage: python scripts/sitecheck.py [--release] [--live <origin>] [--self-test]

  --release   also fail while the fingerprint of the release signing
              certificate is the placeholder.
  --live      also fetch the pages from the origin given, as
              https://umbrachat.app, with the request of a browser. Hold
              what the host serves, and the headers of each answer, to the
              same rules. A host can write into a page or drop a header
              while it serves the page, which no file here shows.
  --self-test check the reader of a document against the cases of CASES,
              and not the site.
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
# The attributes that make a browser read a resource or follow a location,
# by local name. An SVG image can bind another prefix to xlink:href, and
# xml:base moves each location of its element.
LOADS = {"src", "srcset", "imagesrcset", "href", "action", "formaction",
         "poster", "data", "background", "ping", "manifest", "cite", "base"}
# The attributes that hold a list of image candidates. Each other attribute
# holds one URL, which can hold a comma or a space, as a data: URL does.
CANDIDATES = {"srcset", "imagesrcset"}
FINGERPRINT = re.compile(r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")
# A browser drops each tab and line end of a URL and each C0 control or space
# at its ends, and it reads a backslash as a slash. Thus "/\host" and
# "/<TAB>/host" name a second host.
URL_GAPS = re.compile(r"[\t\n\r]")
URL_ENDS = "".join(chr(code) for code in range(0x21))
# The parse of an image candidate list in the HTML standard. The URL runs to
# the next ASCII whitespace, and its descriptors run to a comma outside
# parentheses. `ping` lists its URLs between ASCII whitespace.
CANDIDATE_URL = re.compile(r"[\t\n\f\r ,]*([^\t\n\f\r ]*)")
CANDIDATE_DESCRIPTORS = re.compile(r"(?:[^,(]|\([^)]*\)?)*,?")
TOKENS = re.compile(r"[^\t\n\f\r ]+")
# CSS reads a resource with url() and image-set(). The URL of a url() is
# the whole quoted string, because a browser strips a space at its start.
# A string with no end quote runs to the end of the style sheet.
CSS_URL = re.compile(r"""url\(\s*(?:"([^"]*)|'([^']*)|([^)\s'"]*))""", re.I)
# The forms of CSS that the scan does not read. A CSS escape can write
# "url(" or "@import", and image-set() takes a string as a URL.
CSS_FAULTS = {
    "a CSS escape": re.compile(r"\\"),
    "an image-set()": re.compile(r"image-set\(", re.I),
}
# An SVG image, and an <svg> of a page, read a tag, a comment, and a
# character reference in a style sheet. The HTML parser reads them as text.
SHEET_FAULTS = {
    "an @import": re.compile(r"@import", re.I),
    "markup": re.compile(r"<(?![\s=])|&[#\w:]"),
    **CSS_FAULTS,
}
# A path of this host begins with one slash, and no slash or backslash
# follows it.
THIS_HOST = re.compile(r"^/(?![/\\])")
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


def candidate_urls(value: str) -> list[str]:
    """The URL of each image candidate of a `srcset` value."""
    urls = []
    position = 0
    while position < len(value):
        match = CANDIDATE_URL.match(value, position)
        url = match.group(1)
        position = match.end()

        # A URL that ends with a comma has no descriptors.
        if url.endswith(","):
            url = url.rstrip(",")
        else:
            position = CANDIDATE_DESCRIPTORS.match(value, position).end()
        urls.append(url)
    return urls


class Document(HTMLParser):
    def __init__(self, name: str, problems: list[str], line: int = 1):
        super().__init__(convert_charrefs=True)
        self.name, self.problems = name, problems
        self.lineno = line
        # The text of the open style sheet. The parser can give it in parts,
        # thus the check reads it whole at its end tag.
        self.sheet: list[str] | None = None

    def fault(self, text: str) -> None:
        line, _ = self.getpos()
        self.problems.append(f"{self.name}:{line}: {text}")

    def handle_decl(self, decl):
        # An entity of an SVG image can write a location, as "/&a;".
        if "[" in decl:
            self.fault("IDN-121: a declaration of entities")

    def handle_startendtag(self, tag, attrs):
        if tag == "style":
            self.fault("IDN-121: a <style/>, which a page reads as an open style sheet")
        super().handle_startendtag(tag, attrs)

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "iframe", "frame", "object", "embed", "base", "form"}:
            self.fault(f"IDN-120: a <{tag}> element")
        if tag == "style":
            self.sheet = []
        if tag in {"set", "animate"}:
            # An animation can set a location, as the href of an <image>.
            target = (dict(attrs).get("attributename") or "").lower()
            if target.rsplit(":", 1)[-1] in LOADS:
                self.fault(f"IDN-121: an animation of {target}")

        for key, raw in attrs:
            key = key.lower()
            local = key.rsplit(":", 1)[-1]
            raw = raw or ""
            value = raw.strip()
            if key.startswith("on"):
                self.fault(f"IDN-120: the event attribute {key}")
            if key == "http-equiv" and value.lower() == "refresh":
                self.fault("IDN-121: a refresh that moves the browser")

            # location() strips the raw value as a browser does. A split at
            # a space before that strip hides the host of "<C0> //host".
            if local in CANDIDATES:
                urls = candidate_urls(raw)
            elif local == "ping":
                urls = TOKENS.findall(raw)
            elif local in LOADS:
                urls = [raw]
            elif key == "style":
                urls = []
                if self.css(raw, "a style attribute", CSS_FAULTS):
                    self.fault("IDN-121: a url() in a style attribute")
            elif "(" in raw:
                # An SVG presentation attribute, as fill, is CSS. A CSS
                # function needs a "(", and no escape writes it.
                urls = self.css(raw, f"the attribute {key}", CSS_FAULTS)
            else:
                urls = []
            for url in urls:
                self.location(url)

    def handle_endtag(self, tag):
        if tag == "style":
            self.end_sheet()

    def handle_data(self, data):
        if self.sheet is not None:
            self.sheet.append(data)
        elif self.cdata_elem and "<" in data:
            # The parser reads the content of a <title> as text, and an SVG
            # image reads the markup in it.
            inner = Document(self.name, self.problems, self.getpos()[0])
            inner.feed(data)
            inner.close()

    def close(self):
        super().close()
        # A browser reads the rest of the document as the text of an open
        # <style> or <title>, and an older parser drops that text.
        if self.cdata_elem:
            self.fault(f"IDN-121: a <{self.cdata_elem}> with no end tag")
        self.end_sheet()

    def end_sheet(self) -> None:
        if self.sheet is None:
            return

        text = "".join(self.sheet)
        self.sheet = None
        # A style sheet reads a file of this host alone, as the font.
        for url in self.css(text, "a style sheet", SHEET_FAULTS):
            self.location(url)

    def css(self, text: str, where: str, faults: dict[str, re.Pattern[str]]) -> list[str]:
        """Gives a fault for each form of `faults` in a CSS text, and gives
        the URL of each url() of the text."""
        for what, pattern in faults.items():
            if pattern.search(text):
                self.fault(f"IDN-121: {what} in {where}")
        return [next(group for group in match.groups() if group is not None)
                for match in CSS_URL.finditer(text)]

    def location(self, value: str) -> None:
        value = URL_GAPS.sub("", value).strip(URL_ENDS)
        low = value.lower()
        if not value or low.startswith(("data:", "#")):
            return
        if low.startswith("javascript:"):
            self.fault("IDN-120: a javascript: location")
        # Each other form names a scheme, a host, or a path that depends on
        # the place of the document.
        elif not THIS_HOST.match(value):
            self.fault(f"IDN-121: a location outside this host: {value}")


# Each case: a document, and the rule of each fault that the check gives.
CASES = [
    ('<a href="/i">', []),
    ('<a href=" /i ">', []),
    ('<a href="\x01 //evil.example/x">', ["IDN-121"]),
    ('<a href="\x01\x1b //evil.example/x">', ["IDN-121"]),
    ('<a href="/\\evil.example/x">', ["IDN-121"]),
    ('<a href="/\t/evil.example/x">', ["IDN-121"]),
    ('<a href="https://evil.example/x">', ["IDN-121"]),
    ('<a href="java&#9;script:x">', ["IDN-120"]),
    ('<a ping="/p //evil.example/p" href="/i">', ["IDN-121"]),
    ('<img src="data:image/png;base64,AAAA,BBBB">', []),
    ('<img srcset="/a.png 1x, /b.png 2x">', []),
    ('<img srcset="/a.png 1x,//evil.example/b.png 2x">', ["IDN-121"]),
    ('<img srcset="data:image/png;base64,AA,BB 1x, /b.png (x, y) 2x">', []),
    ('<link rel="preload" as="image" imagesrcset="//evil.example/a.png 1x">', ["IDN-121"]),
    ('<style>b { background: url("//evil.example/a.png") }</style>', ["IDN-121"]),
    ('<style>@font-face { src: url("/f.woff2") format("woff2") }</style>', []),
    ('<style>b { background: url(" //evil.example/a.png") }</style>', ["IDN-121"]),
    ('<style>b { background: url("/\t/evil.example/a.png") }</style>', ["IDN-121"]),
    ('<svg><style>@font-face { src: url(\' //evil.example/f.woff2\') }</style></svg>', ["IDN-121"]),
    ('<style>b { background: url("//evil.example/a.png</style>', ["IDN-121"]),
    ('<style>b { background: \\75rl(//evil.example/a.png) }</style>', ["IDN-121"]),
    ('<style>@\\69mport "//evil.example/x.css";</style>', ["IDN-121"]),
    ('<style>b { background: image-set("//evil.example/a.png" 1x) }</style>', ["IDN-121"]),
    ('<b style="background: image-set(\'//evil.example/a.png\' 1x)">', ["IDN-121"]),
    ('<b style="color: red">', []),
    ('<svg><style>b { fill: url("/&#47;evil.example/a.svg#g") }</style></svg>', ["IDN-121"]),
    ('<svg><style>b { fill: url(/<x/>/evil.example/a.svg#g) }</style></svg>', ["IDN-121"]),
    ('<style>@media (width < 600px) { b { color: red } }</style>', []),
    ('<style>b { color: red }', ["IDN-121"]),
    ('<style/>b { background: url(/a.png) }</style>', ["IDN-121"]),
    ('<rect fill="url(#g)" transform="rotate(45)"/>', []),
    ('<rect fill="url(//evil.example/p.svg#g)" mask="url(https://evil.example/m.svg#m)"/>',
     ["IDN-121", "IDN-121"]),
    ('<rect fill="\\75rl(//evil.example/p.svg#g)"/>', ["IDN-121"]),
    ('<svg><image x:href="//evil.example/a.png"/></svg>', ["IDN-121"]),
    ('<svg xml:base="//evil.example/"><image href="/a.png"/></svg>', ["IDN-121"]),
    ('<svg><image><set attributeName="href" to="//evil.example/a.png"/></image></svg>',
     ["IDN-121"]),
    ('<svg><title><image href="//evil.example/a.png"/></title></svg>', ["IDN-121"]),
    ('<svg><title>UMBRA</title></svg>', []),
    ('<!DOCTYPE svg [<!ENTITY a "/evil.example/a.png">]><svg><image href="/&a;"/></svg>',
     ["IDN-121"]),
]


def read_document(name: str, text: str, problems: list[str]) -> None:
    document = Document(name, problems)
    document.feed(text)
    document.close()


def self_test() -> int:
    faults = []
    for text, want in CASES:
        problems: list[str] = []
        read_document("case", text, problems)
        got = [problem.split(": ")[1] for problem in problems]
        if got != want:
            faults.append(f"{text!r}: the check gives {got}, and the case wants {want}")

    print(f"cases: {len(CASES)}  faults: {len(faults)}")
    for line in faults:
        print("  " + line)
    return 1 if faults else 0


def main() -> None:
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())

    release = "--release" in sys.argv[1:]
    problems: list[str] = []

    documents = sorted(SITE.rglob("*.html"))
    if not (SITE / "i.html").is_file():
        problems.append("i.html: the landing document is absent (Part 4 §4.3.1)")
    for path in documents:
        name = path.relative_to(SITE).as_posix()
        read_document(name, path.read_text(encoding="utf-8"), problems)

    # A browser runs a script of an SVG image that it opens as a document.
    for path in sorted(SITE.rglob("*.svg")):
        read_document(path.relative_to(SITE).as_posix(), path.read_text(encoding="utf-8"), problems)
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

            read_document(f"{origin}{path}", body, problems)
            problems.extend(header_problems(
                f"{origin}{path}", {name.lower(): value for name, value in headers.items()}))

    print(f"documents: {len(documents)}  problems: {len(problems)}")
    for line in problems:
        print("  " + line)
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
