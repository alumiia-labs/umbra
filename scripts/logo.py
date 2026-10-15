#!/usr/bin/env python3
"""Generate the UMBRA logo files from their construction.

The mark is a speech bubble in front of the sun. The bubble is a circle
with its bottom-left quadrant squared off, and it stands for the moon: it
hides the sun, and its corner points away from the light, as an umbra does.
Only a thin rim of the sun shows behind it, and a gap keeps the rim apart
from the bubble. Each number of that construction is a constant below, and
each file in brand/ and each Android drawable of the logo comes from them,
thus a change is made here and never in an output file.

The mark is one color. It is one <path> with two subpaths, the bubble and
the rim, thus `currentColor` colors all of it.

The wordmark is UMBRA in Jost (SIL Open Font License 1.1) at weight 500,
turned into outlines, thus no output file needs the font. The script fetches
the font once into target/, pinned by commit and by SHA-256.

Usage: python scripts/logo.py [--check]
  --check   exit 1 when a generated file differs from the file on disk.

Needs fontTools (pip install fonttools).
"""
from __future__ import annotations

import hashlib
import math
import sys
import urllib.request
from pathlib import Path

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent.parent

FONT_URL = ("https://raw.githubusercontent.com/google/fonts/"
            "91b26e2e0231f5aa85f5470a7b23d6d732ab15fc/ofl/jost/Jost%5Bwght%5D.ttf")
FONT_SHA256 = "6343b70971000b04c5d401c96ae08ce371086135e999d5e1e1413039c0213076"
FONT_CACHE = ROOT / "target/brand/Jost.ttf"

# The colors of Theme.kt: the light set, then the dark set.
GREEN, SURFACE, INK = "#285C43", "#F7F8F2", "#202B25"
MINT, CHARCOAL, SOFT = "#B5DDC4", "#121715", "#E4EAE5"

# The construction, in units of a 100-unit drawing, y down.
BUBBLE_C, BUBBLE_R = (47.0, 53.0), 34.0  # the bubble: the moon
CORNER_R = 7.0                           # the round of its square corner
SUN_SHIFT, SUN_R = (6.5, -6.5), 36.5     # the sun, up and right of the bubble
GAP = 4.0                                # between the bubble and the rim

# At 24 px and less the rim above is about one pixel wide. The small mark
# has a wider gap and a heavier rim, and it is the favicon.
SMALL = dict(gap=6.0, sun_shift=(8.5, -8.5), sun_r=40.0)

# The wordmark.
WORD, WORD_WEIGHT, WORD_TRACKING = "UMBRA", 500, 0.22  # tracking in em


def num(v):
    s = f"{v:.3f}".rstrip("0").rstrip(".")
    return "0" if s == "-0" else s


class Mark:
    """The geometry of one mark: the bubble, and the rim of the sun behind it."""

    def __init__(self, gap=GAP, sun_shift=SUN_SHIFT, sun_r=SUN_R):
        self.b, self.r = BUBBLE_C, BUBBLE_R
        self.s = (BUBBLE_C[0] + sun_shift[0], BUBBLE_C[1] + sun_shift[1])
        self.sr = sun_r
        self.gr = BUBBLE_R + gap  # the circle that the rim keeps outside of

    def horns(self):
        """The two ends of the rim: where the sun's circle cuts the gap circle."""
        (x1, y1), (x2, y2) = self.b, self.s
        dx, dy = x2 - x1, y2 - y1
        d = math.hypot(dx, dy)
        a = (self.gr**2 - self.sr**2 + d**2) / (2 * d)
        h = math.sqrt(self.gr**2 - a**2)
        bx, by = x1 + a * dx / d, y1 + a * dy / d
        return (bx - h * dy / d, by + h * dx / d), (bx + h * dy / d, by - h * dx / d)

    def far(self):
        """The point of the rim farthest from the bubble."""
        (x1, y1), (x2, y2) = self.b, self.s
        d = math.hypot(x2 - x1, y2 - y1)
        return (x2 + self.sr * (x2 - x1) / d, y2 + self.sr * (y2 - y1) / d)

    def outline(self, n=720):
        """Points on the edge of the mark, for its box and its reach."""
        (bx, by), r, k = self.b, self.r, CORNER_R
        pts = []
        # The three round quadrants of the bubble: from the left, over the
        # top, to the bottom.
        for i in range(n + 1):
            a = math.radians(180 + 270 * i / n)
            pts.append((bx + r * math.cos(a), by + r * math.sin(a)))
        # The rounded corner.
        cx, cy = bx - r + k, by + r - k
        for i in range(n // 4 + 1):
            a = math.radians(90 + 90 * i / (n // 4))
            pts.append((cx + k * math.cos(a), cy + k * math.sin(a)))
        # The outer edge of the rim.
        h1, h2 = self.horns()
        a1 = math.atan2(h1[1] - self.s[1], h1[0] - self.s[0])
        a2 = math.atan2(h2[1] - self.s[1], h2[0] - self.s[0])
        af = math.atan2(self.far()[1] - self.s[1], self.far()[0] - self.s[0])
        span = (a2 - a1) % (2 * math.pi)
        if (af - a1) % (2 * math.pi) > span:
            a1, span = a2, 2 * math.pi - span
        for i in range(n + 1):
            a = a1 + span * i / n
            pts.append((self.s[0] + self.sr * math.cos(a), self.s[1] + self.sr * math.sin(a)))
        return pts

    def box(self):
        pts = self.outline()
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        return min(xs), min(ys), max(xs), max(ys)

    def center(self):
        x0, y0, x1, y1 = self.box()
        return (x0 + x1) / 2, (y0 + y1) / 2

    def reach(self):
        """The distance from the center of the box to the farthest edge point."""
        c = self.center()
        return max(math.dist(c, p) for p in self.outline())

    def path(self, offset=(0.0, 0.0), scale=1.0):
        """The mark as one path: the bubble, then the rim."""
        def P(p):
            return f"{num(offset[0] + scale * p[0])} {num(offset[1] + scale * p[1])}"

        (bx, by), r, k = self.b, self.r, CORNER_R
        R, K = num(scale * r), num(scale * k)
        bubble = (f"M{P((bx - r, by))}"
                  f"A{R} {R} 0 1 1 {P((bx, by + r))}"
                  f"H{num(offset[0] + scale * (bx - r + k))}"
                  f"A{K} {K} 0 0 1 {P((bx - r, by + r - k))}Z")
        h1, h2 = self.horns()
        # The outer edge runs over the far side of the sun; the inner edge
        # runs back along the gap circle. Both flags follow from that.
        cross = lambda o, p, q: (p[0] - o[0]) * (q[1] - o[1]) - (p[1] - o[1]) * (q[0] - o[0])
        # With y down, a positive turn is clockwise on screen: sweep 1.
        sweep = 1 if cross(h1, self.far(), h2) > 0 else 0
        large = 1 if cross(h1, h2, self.s) * cross(h1, h2, self.far()) > 0 else 0
        SR, GR = num(scale * self.sr), num(scale * self.gr)
        rim = (f"M{P(h1)}"
               f"A{SR} {SR} 0 {large} {sweep} {P(h2)}"
               f"A{GR} {GR} 0 0 {1 - sweep} {P(h1)}Z")
        return bubble + rim

    def placed(self, size, extent):
        """The path with the box centerd in `size` and its larger side `extent` long."""
        x0, y0, x1, y1 = self.box()
        s = extent / max(x1 - x0, y1 - y0)
        c = self.center()
        return self.path((size / 2 - s * c[0], size / 2 - s * c[1]), s)


def font():
    if not FONT_CACHE.exists():
        FONT_CACHE.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(FONT_URL) as r:
            FONT_CACHE.write_bytes(r.read())
    digest = hashlib.sha256(FONT_CACHE.read_bytes()).hexdigest()
    if digest != FONT_SHA256:
        sys.exit(f"logo: {FONT_CACHE} has SHA-256 {digest}, expected {FONT_SHA256}")
    return instantiateVariableFont(TTFont(FONT_CACHE), {"wght": WORD_WEIGHT})


def wordmark(cap):
    """The outlines of WORD with cap height `cap`, its baseline at y = cap.

    Returns the path, the left and right ink edges, and the top and bottom
    ink edges. The points of the M and the round of the U pass the cap
    height and the baseline a little.
    """
    tt = font()
    glyphs, cmap = tt.getGlyphSet(), tt.getBestCmap()
    k = cap / tt["OS/2"].sCapHeight
    em = tt["head"].unitsPerEm
    pen = SVGPathPen(glyphs, num)
    names = [cmap[ord(ch)] for ch in WORD]
    x, inks, low, high = 0.0, [], 0.0, 0.0
    for i, name in enumerate(names):
        g = glyphs[name]
        bounds = BoundsPen(glyphs)
        g.draw(bounds)
        inks.append((x + bounds.bounds[0], x + bounds.bounds[2]))
        low, high = min(low, bounds.bounds[1]), max(high, bounds.bounds[3])
        g.draw(TransformPen(pen, (k, 0, 0, -k, x * k, cap)))
        x += g.width + (WORD_TRACKING * em if i < len(names) - 1 else 0)
    return pen.getCommands(), inks[0][0] * k, inks[-1][1] * k, cap - high * k, cap - low * k


def svg(view_box, body, css=None):
    style = f"<style>{css}</style>" if css else ""
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}" '
            f'role="img" aria-label="UMBRA"><title>UMBRA</title>{style}{body}</svg>\n')


def no_arcs(d):
    """The path `d` with each arc as cubic curves.

    SVG Tiny 1.2 has no arc command. The paths of the mark hold `M`, `A`,
    `H`, and `Z` alone, in absolute coordinates, and each arc is a part of a
    circle. One curve covers a quarter turn at most, thus the error is below
    0.03 % of the radius.
    """
    import re
    tokens = re.findall(r"[MAHZ]|-?[0-9]*[.]?[0-9]+", d)
    out, at, i = [], (0.0, 0.0), 0
    while i < len(tokens):
        cmd = tokens[i]
        i += 1
        if cmd == "M":
            at = (float(tokens[i]), float(tokens[i + 1]))
            i += 2
            out.append(f"M{num(at[0])} {num(at[1])}")
        elif cmd == "H":
            at = (float(tokens[i]), at[1])
            i += 1
            out.append(f"H{num(at[0])}")
        elif cmd == "Z":
            out.append("Z")
        elif cmd == "A":
            rx, ry, _turn, large, sweep, x, y = (float(t) for t in tokens[i:i + 7])
            i += 7
            if abs(rx - ry) > 1e-9:
                raise ValueError("an arc of the mark is a part of a circle")
            # The center, from the two ends (SVG 1.1 appendix F.6.5).
            (x0, y0), r = at, rx
            mx, my = (x0 - x) / 2, (y0 - y) / 2
            reach = math.hypot(mx, my)
            r = max(r, reach)
            h = math.sqrt(max(r * r - reach * reach, 0.0)) / reach
            side = -1.0 if large == sweep else 1.0
            cx = (x0 + x) / 2 + side * h * my
            cy = (y0 + y) / 2 - side * h * mx
            a0 = math.atan2(y0 - cy, x0 - cx)
            a1 = math.atan2(y - cy, x - cx)
            turn = a1 - a0
            if sweep and turn < 0:
                turn += 2 * math.pi
            if not sweep and turn > 0:
                turn -= 2 * math.pi
            parts = max(1, math.ceil(abs(turn) / (math.pi / 2) - 1e-9))
            step = turn / parts
            k = 4 / 3 * math.tan(step / 4)
            for n in range(parts):
                b0, b1 = a0 + n * step, a0 + (n + 1) * step
                p1 = (cx + r * (math.cos(b0) - k * math.sin(b0)),
                      cy + r * (math.sin(b0) + k * math.cos(b0)))
                p2 = (cx + r * (math.cos(b1) + k * math.sin(b1)),
                      cy + r * (math.sin(b1) - k * math.cos(b1)))
                end = (x, y) if n == parts - 1 else (cx + r * math.cos(b1),
                                                     cy + r * math.sin(b1))
                out.append("C" + " ".join(num(v) for v in (*p1, *p2, *end)))
            at = (x, y)
        else:
            raise ValueError(f"a number with no command in a path: {cmd}")
    return "".join(out)


def svg_tiny_ps(view_box, body):
    """SVG Tiny Portable/Secure, the profile that BIMI takes for a mail logo.

    The profile wants the version and the base profile on the root, a title,
    and a square canvas with a solid ground. It permits no script, style sheet,
    outside reference, or attribute outside SVG Tiny 1.2 (thus no `role`). A
    path of the body holds no arc: `no_arcs` gives the curves.
    """
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
            f'baseProfile="tiny-ps" viewBox="{view_box}">'
            f'<title>UMBRA</title>{body}</svg>\n')


RES = "android/app/src/main/res"


def vector(size_dp, viewport, paths, height_dp=None, viewport_height=None, shift=(0, 0)):
    """An Android VectorDrawable. Its pathData takes the SVG path syntax.

    A square drawable needs `size_dp` and `viewport` alone. A drawable of
    another shape gives its height too, and `shift` moves the paths into
    the viewport.
    """
    body = "".join(f'\n    <path\n        android:fillColor="{fill}"\n'
                   f'        android:pathData="{d}" />' for fill, d in paths)
    if shift != (0, 0):
        body = (f'\n    <group\n        android:translateX="{num(shift[0])}"\n'
                f'        android:translateY="{num(shift[1])}">'
                + body.replace("\n", "\n    ") + "\n    </group>")
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            "<!-- Generated by scripts/logo.py. Do not edit. -->\n"
            '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
            f'    android:width="{num(size_dp)}dp"\n    android:height="{num(height_dp or size_dp)}dp"\n'
            f'    android:viewportWidth="{num(viewport)}"\n'
            f'    android:viewportHeight="{num(viewport_height or viewport)}">'
            f"{body}\n</vector>\n")


def adaptive():
    """The launcher icon of Android 8 and later, with the monochrome layer of
    the themed icons of Android 13."""
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            "<!-- Generated by scripts/logo.py. Do not edit. -->\n"
            '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
            '    <background android:drawable="@color/brand_green" />\n'
            '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
            '    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />\n'
            "</adaptive-icon>\n")


def auto_css(mark, word=None):
    """Colors that follow the color scheme of the page that shows the file."""
    light = f".mark{{fill:{mark[0]}}}" + (f".word{{fill:{word[0]}}}" if word else "")
    dark = f".mark{{fill:{mark[1]}}}" + (f".word{{fill:{word[1]}}}" if word else "")
    return f"{light}@media (prefers-color-scheme:dark){{{dark}}}"


def outputs():
    files = {}
    mark = Mark()

    # The mark alone: its box centerd in a 100-unit square, 90 units on
    # its larger side.
    d = mark.placed(100, 90)
    files["brand/umbra-mark.svg"] = svg("0 0 100 100", f'<path fill="currentColor" d="{d}"/>')
    files["brand/umbra-mark-light.svg"] = svg("0 0 100 100", f'<path fill="{GREEN}" d="{d}"/>')
    files["brand/umbra-mark-dark.svg"] = svg("0 0 100 100", f'<path fill="{MINT}" d="{d}"/>')
    files["brand/umbra-mark-auto.svg"] = svg(
        "0 0 100 100", f'<path class="mark" d="{d}"/>', auto_css((GREEN, MINT)))

    # The small mark, for 24 px and less, with colors that follow the page.
    small = Mark(**SMALL).placed(100, 94)
    files["brand/umbra-favicon.svg"] = svg(
        "0 0 100 100", f'<path class="mark" d="{small}"/>', auto_css((GREEN, MINT)))

    # The lockup. The mark is 1.5 cap heights tall, the center of its box
    # sits on the middle of the caps, and 0.6 cap heights separate it from
    # the U.
    cap = 30.0
    wd, wl, wr, wt, wb = wordmark(cap)
    x0, y0, x1, y1 = mark.box()
    s = 1.5 * cap / (y1 - y0)
    mh, mw = s * (y1 - y0), s * (x1 - x0)
    top = cap / 2 - mh / 2
    m = mark.path((-s * x0, top - s * y0), s)
    tx = mw + 0.6 * cap - wl
    vb = f"0 {num(top)} {num(tx + wr)} {num(mh)}"
    move = f'transform="translate({num(tx)} 0)"'

    def lockup(mark_fill, word_fill):
        return (f'<path fill="{mark_fill}" d="{m}"/>'
                f'<path fill="{word_fill}" {move} d="{wd}"/>')

    files["brand/umbra-logo.svg"] = svg(vb, lockup("currentColor", "currentColor"))
    files["brand/umbra-logo-light.svg"] = svg(vb, lockup(GREEN, INK))
    files["brand/umbra-logo-dark.svg"] = svg(vb, lockup(MINT, SOFT))
    files["brand/umbra-logo-auto.svg"] = svg(
        vb, f'<path class="mark" d="{m}"/><path class="word" {move} d="{wd}"/>',
        auto_css((GREEN, MINT), (INK, SOFT)))
    # The box of the wordmark holds each point of its ink.
    files["brand/umbra-wordmark.svg"] = svg(
        f"{num(wl)} {num(wt)} {num(wr - wl)} {num(wb - wt)}", f'<path fill="currentColor" d="{wd}"/>')

    # The app icon on the 108-unit canvas of an Android adaptive icon. No
    # point of the mark lies farther than 31 units from the center, inside
    # the 33-unit safe zone, thus no launcher mask cuts it.
    x0, y0, x1, y1 = mark.box()
    extent = 31 / mark.reach() * max(x1 - x0, y1 - y0)
    icon = mark.placed(108, extent)
    for name, bg, fg, rx in [("umbra-app-icon.svg", GREEN, SURFACE, 0),
                             ("umbra-app-icon-rounded.svg", GREEN, SURFACE, 24),
                             ("umbra-app-icon-dark.svg", CHARCOAL, MINT, 24)]:
        corner = f' rx="{rx}"' if rx else ""
        files[f"brand/{name}"] = svg(
            "0 0 108 108",
            f'<rect width="108" height="108"{corner} fill="{bg}"/><path fill="{fg}" d="{icon}"/>')
    # The mail logo of BIMI: the square tile, which a mail client crops to a
    # circle. The mark lies inside the safe zone, thus the crop cuts none.
    files["brand/umbra-app-icon-tiny-ps.svg"] = svg_tiny_ps(
        "0 0 108 108",
        f'<rect width="108" height="108" fill="{GREEN}"/>'
        f'<path fill="{SURFACE}" d="{no_arcs(icon)}"/>')

    # The web site of the domain (site/README.md) serves two of the files
    # above: the mail logo, and the mark on the tile of each page.
    files["site/public/bimi/logo.svg"] = files["brand/umbra-app-icon-tiny-ps.svg"]
    files["site/public/mark.svg"] = files["brand/umbra-mark-light.svg"]

    # The Android app. A launcher shows about 72 of the 108 units and masks
    # them to its own shape, and the mark at the edge of the safe zone then
    # fills that shape. The launcher layers reach 24 units from the center,
    # the size of the content of an icon of the platform. The splash icon
    # of Android 12 sits on a 288-unit canvas in a circle of 192 units, and
    # its mark reaches 64 units for the same margin. The notification icon
    # is a white silhouette at 24 dp, thus it takes the small mark.
    span = max(x1 - x0, y1 - y0)
    launcher = mark.placed(108, 24 / mark.reach() * span)
    files[f"{RES}/drawable/ic_launcher_foreground.xml"] = vector(108, 108, [(SURFACE, launcher)])
    files[f"{RES}/drawable/ic_launcher_monochrome.xml"] = vector(108, 108, [("#FFFFFFFF", launcher)])
    files[f"{RES}/mipmap-anydpi-v26/ic_launcher.xml"] = adaptive()
    files[f"{RES}/mipmap-anydpi-v26/ic_launcher_round.xml"] = adaptive()
    splash = mark.placed(288, 64 / mark.reach() * span)
    files[f"{RES}/drawable/ic_splash.xml"] = vector(288, 288, [(GREEN, splash)])
    files[f"{RES}/drawable-night/ic_splash.xml"] = vector(288, 288, [(MINT, splash)])
    files[f"{RES}/drawable/ic_stat_umbra.xml"] = vector(24, 100, [("#FFFFFFFF", small)])
    files[f"{RES}/drawable/ic_umbra_mark.xml"] = vector(24, 100, [("#FF000000", d)])
    # The wordmark of the top bar, with a cap height of 13 dp. The app
    # tints it with the color of the text.
    word_dp = 13 / cap
    files[f"{RES}/drawable/ic_umbra_wordmark.xml"] = vector(
        (wr - wl) * word_dp, wr - wl, [("#FF000000", wd)],
        height_dp=(wb - wt) * word_dp, viewport_height=wb - wt, shift=(-wl, -wt))
    files[f"{RES}/values/brand.xml"] = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<!-- Generated by scripts/logo.py. Do not edit. -->\n"
        f'<resources>\n    <color name="brand_green">{GREEN}</color>\n</resources>\n')
    return files


def main():
    check = "--check" in sys.argv[1:]
    stale = []
    for rel, text in outputs().items():
        path = ROOT / rel
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old == text:
            continue
        if check:
            stale.append(rel)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {rel}")
    if stale:
        sys.exit("logo: stale files, run python scripts/logo.py:\n  " + "\n  ".join(stale))


if __name__ == "__main__":
    main()
