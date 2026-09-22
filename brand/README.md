# UMBRA logo

The mark is a speech bubble in front of the sun. Only a thin rim of the sun
shows behind it. The bubble's square corner points away from the light, as
the umbra (the dark core of an eclipse shadow) does.

`scripts/logo.py` generates every file here from the construction. Change a
proportion or a colour in that script and run it again. Do not edit a file here
by hand. `python scripts/logo.py --check` reports a file that is out of date.

| File | Use |
| --- | --- |
| `umbra-mark.svg`, `umbra-logo.svg`, `umbra-wordmark.svg` | Take the colour of the text around them (`currentColor`) |
| `umbra-mark-light.svg`, `umbra-logo-light.svg` | On a light ground: forest `#285C43`, ink `#202B25` |
| `umbra-mark-dark.svg`, `umbra-logo-dark.svg` | On a dark ground: mint `#B5DDC4`, soft white `#E4EAE5` |
| `umbra-mark-auto.svg`, `umbra-logo-auto.svg` | Follow the viewer's light or dark colour scheme |
| `umbra-favicon.svg` | 24 px and less: a heavier rim and a wider gap, follows the colour scheme |
| `umbra-app-icon.svg` | Square tile on the 108-unit adaptive-icon canvas, inside the 66-unit safe zone |
| `umbra-app-icon-rounded.svg`, `umbra-app-icon-dark.svg` | Tiles with round corners, green and charcoal |

Keep the rim. Without it the mark is a plain chat bubble. Below 32 px, use the
favicon, whose rim stays visible.

The wordmark is Jost 500 (SIL Open Font License 1.1), tracked 0.22 em and
converted to outlines.
