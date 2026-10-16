# The web site of umbrachat.app

Static files that the domain itself serves. No UMBRA server holds them: the
relays and the signer live at `<name>.umbrachat.app`. This site is a
Cloudflare Worker that holds static assets alone, with no Worker script.

| Path | File | Why |
| --- | --- | --- |
| `/.well-known/assetlinks.json` | `public/.well-known/assetlinks.json` | Android verifies the App Link of an invitation against it (Part 4 `IDN-122`, `IDN-123`) |
| `/i` | `public/i.html` | The invitation landing document, for a party without the app (Part 4 §4.3.1) |
| `/<code>/i` | `public/<code>/i.html` | The same document in another language |
| `/mark.svg` | `public/mark.svg` | The mark on the tile of each page |
| `/dm-sans.woff2` | `public/dm-sans.woff2` | The font of the two pages, a Latin subset of DM Sans (SIL Open Font License 1.1, `/dm-sans-OFL.txt`) |
| `/bimi/logo.svg` | `public/bimi/logo.svg` | The mail logo of BIMI, in SVG Tiny PS |

`public/_headers` gives each response its headers, and `public/404.html`
answers each other path. The site has no page at `/`.

## Text and languages

`scripts/sitebuild.py` writes `i.html`, `404.html`, and the page of each
language from `page.html` and the text in `locales/`. Do not edit those
pages by hand: change the template or the text, and run the script. The
check set runs `python scripts/sitebuild.py --check`.

`locales/en.json` holds the English text, and `locales/<code>.json` holds
the text of one other language. A key that a language lacks takes the
English text. The page of the invitation links to each language with a
plain link of this host, and it needs no script. `404.html` has English
alone, because the host answers each unknown path with that one file.
`CONTRIBUTING.md` gives the steps of a translation.

`scripts/logo.py` writes the two logo files. Do not edit them by hand.

The two pages take the look of a full view of the app (`Ui.kt`, `Widgets.kt`,
`Theme.kt`). They take the warm white ground, the mark on the sage tile of
`BrandHero`, and the sizes of `Headline`. The app has a light form alone, thus so have
the pages. The font is DM Sans; the app itself sets its text in Roboto, and
the wordmark is Jost. The font file is a subset of the variable file of the
DM Sans project (`ofl/dmsans/DMSans[opsz,wght].ttf` of
github.com/google/fonts):

```sh
python -m fontTools.subset "DMSans[opsz,wght].ttf"   --unicodes="U+0020-007E,U+00A0-00FF,U+2018-201D,U+2026"   --layout-features=kern,liga --flavor=woff2   --output-file=site/public/dm-sans.woff2
```

A text of a page in a script outside that range needs a wider subset.

## Rules that this site holds

- **No script, and no resource of a second host** (`IDN-120`, `IDN-121`). The
  landing document tells a party where to get the app. A browser sends
  the host no fragment, thus the host learns the open and not the
  invitation. A script on any page of this host could read the fragment.
  `python scripts/sitecheck.py` fails on a script, an event attribute, a
  frame, a form, or a location outside this host, in each HTML file here.
  It reads each SVG image the same way. The `Content-Security-Policy` of
  `_headers` makes a browser refuse the same, and the check fails when
  `_headers` loses a header of each page. With `--live <origin>` it also
  checks the headers that the host sends for `/i` and `/<code>/i`.
- **No visitor data.** The Worker has no code and its logs are off.

## Before a release

1. Put the SHA-256 fingerprint of the release signing certificate into
   `public/.well-known/assetlinks.json`, in place of the `FILL` value:

   ```sh
   keytool -list -v -keystore <release keystore> -alias <alias> | grep SHA256
   ```

   If Google Play signs the release, take the fingerprint of the app signing
   key from the Play Console. List the upload key beside it when you also
   give out a build signed with that key.
2. `python scripts/sitecheck.py --release` then passes.
3. When the app has a place to get it from, name that place in
   `page.html` and `locales/`, and run `scripts/sitebuild.py`. A link to a
   path of this host keeps `IDN-121`; a link to a second host needs a
   change of `scripts/sitecheck.py` and a reason.

Until step 1 is live, a tap on an invitation link opens the browser and not
the app. A scan of the code inside the app works either way.

## After each deploy

After each deploy, `python scripts/sitecheck.py --live https://umbrachat.app`
reads the pages as a browser does. Cloudflare can write into a page while
it serves the page. With Web Analytics on for the zone, it adds a script of
a second host to each HTML response. `Cache-Control: no-transform` in
`_headers` stops that, and this check shows whether it still holds.

## Tools

The site itself has no dependency. Its one build step is
`scripts/sitebuild.py`, which needs Python alone. The one deploy tool is
`wrangler`, the deploy tool of Cloudflare, pinned to an exact version in
`package.json` with its lockfile. The package manager is pnpm, which
`packageManager` pins as well; `pnpm-workspace.yaml` lets the install
scripts of `esbuild` and `workerd` run, and no other.

```sh
cd site
pnpm install
pnpm dev        # serves the site at http://127.0.0.1:8787
pnpm run check  # python ../scripts/sitecheck.py
pnpm run deploy # asks for a Cloudflare login the first time
```

`wrangler.jsonc` binds the Worker to `umbrachat.app` as a custom domain. The
domain has to be a zone of the Cloudflare account that deploys.

## BIMI

`/bimi/logo.svg` alone shows no logo in a mail client. The domain also needs
SPF, DKIM, and a DMARC policy of `quarantine` or `reject`, and this DNS
record:

```
default._bimi.umbrachat.app  TXT  "v=BIMI1; l=https://umbrachat.app/bimi/logo.svg; a="
```

Gmail and Apple Mail show the logo only with a mark certificate, whose
location goes into `a=`.
