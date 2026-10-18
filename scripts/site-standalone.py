#!/usr/bin/env python3
"""Build a single-file preview of an obenblock.xyz page.

    python3 scripts/site-standalone.py site/index.html out.html

Inlines /assets/fonts.css, /assets/obenblock.css, /assets/site.js and the
favicon, so the file opens from disk with no remote runtime dependency.
Same-page links (/#x) become #x; other site paths (/explorer, /wallet, ...)
point at https://obenblock.xyz. The deployed site keeps the separate files
(strict CSP: no inline script); this preview is for review only.
"""
import re
import sys
import urllib.parse
from pathlib import Path

SITE_URL = "https://obenblock.xyz"


def build(page: Path) -> str:
    site = page.parent
    html = page.read_text(encoding="utf-8")
    css = lambda p: (site / p).read_text(encoding="utf-8")

    def sub_once(pattern, repl, text):
        out, n = re.subn(pattern, lambda _m: repl, text, count=1)
        if n != 1:
            raise SystemExit(f"pattern not found: {pattern}")
        return out

    html = sub_once(r'<link rel="stylesheet" href="/assets/fonts.css">', "<style>\n" + css("assets/fonts.css") + "\n</style>", html)
    html = sub_once(r'<link rel="stylesheet" href="/assets/obenblock.css">', "<style>\n" + css("assets/obenblock.css") + "\n</style>", html)
    html = sub_once(r'<script src="/assets/site.js"[^>]*></script>', "<script>\n" + css("assets/site.js") + "\n</script>", html)
    icon = "data:image/svg+xml," + urllib.parse.quote((site / "favicon.svg").read_text(encoding="utf-8").strip(), safe=" =:/,;")
    html = sub_once(r'<link rel="icon" type="image/svg\+xml" href="/favicon.svg">', f'<link rel="icon" href="{icon}">', html)
    html = re.sub(r'<link rel="apple-touch-icon"[^>]*>\n?', "", html)
    html = re.sub(r'<meta property="og:[^>]*>|<meta name="twitter:card"[^>]*>', "", html)
    html = html.replace('href="/#', 'href="#')
    html = html.replace('href="/"', 'href="#top"')
    html = re.sub(r'href="/([a-z][^"]*)"', lambda m: f'href="{SITE_URL}/{m.group(1)}"', html)
    return html


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    out = build(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(out, encoding="utf-8")
    print(f"wrote {sys.argv[2]} ({len(out.encode())} bytes)")
