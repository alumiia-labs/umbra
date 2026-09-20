#!/usr/bin/env python3
"""Copies the Font Awesome icons of the Android app out of a Font Awesome
package, as SVG files that the app reads at run time.

    python scripts/fa-icons.py <package directory>            # Free, committed
    python scripts/fa-icons.py <package directory> --pro light

The package directory holds `svgs/<style>/<name>.svg`. The Free set goes to
`android/app/src/main/assets/fa`, which the repository holds under CC BY 4.0.
A Pro set goes to `android/app/src/main/assets/fa-pro`, which git ignores,
because a Pro file must not sit in a public repository. The app reads the Pro
file of an icon first and the Free file second.

An icon that the app names and this list does not hold is a fault of the
build: `Fa.kt` reads this list through the file names alone.
"""

import pathlib
import shutil
import sys

# The icons of the app. `Fa.kt` names the same strings.
ICONS = [
    "arrow-left",
    "bell",
    "check",
    "chevron-right",
    "circle-info",
    "clock",
    "comment",
    "copy",
    "ellipsis-vertical",
    "eye",
    "gear",
    "key",
    "link",
    "lock",
    "magnifying-glass",
    "paper-plane",
    "pen",
    "plus",
    "qrcode",
    "rotate",
    "share-nodes",
    "shield-check",
    "shield-halved",
    "signal",
    "triangle-exclamation",
    "user-group",
    "user-plus",
    "xmark",
]

# An icon that the Free set does not hold, and the Free icon that stands in
# for it under its name.
FREE_STAND_IN = {"shield-check": "shield-halved"}

ASSETS = pathlib.Path(__file__).resolve().parent.parent / "android/app/src/main/assets"


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments:
        print(__doc__)
        return 2
    package = pathlib.Path(arguments[0])
    is_pro = "--pro" in arguments
    # The line look of the mockups is the light style of Pro. The Free set
    # holds a regular file for some icons and a solid file for each one.
    styles = [arguments[arguments.index("--pro") + 1]] if is_pro else ["regular", "solid"]
    target = ASSETS / ("fa-pro" if is_pro else "fa")
    target.mkdir(parents=True, exist_ok=True)
    missing = []
    for name in ICONS:
        wanted = name if is_pro else FREE_STAND_IN.get(name, name)
        sources = [package / "svgs" / style / f"{wanted}.svg" for style in styles]
        source = next((path for path in sources if path.is_file()), None)
        if source is None:
            missing.append(name)
            continue
        # The repository holds the Free set. A Pro package holds each icon
        # under the Pro license, thus a Free run takes no file from it.
        if not is_pro and "Font Awesome Free" not in source.read_text(encoding="utf-8"):
            print(f"{source} is not a Free file. Give the Free package, or use --pro.")
            return 1
        shutil.copyfile(source, target / f"{name}.svg")
    if not is_pro:
        shutil.copyfile(package / "LICENSE.txt", target / "LICENSE.txt")
    print(f"{len(ICONS) - len(missing)} icons in {target}")
    if missing:
        print("not in the package:", ", ".join(missing))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
