"""Render the ObenBlock raster icons and the social card from the SVG marks.

    python3 brand/obenblock/render_png.py

Reads obenblock-icon.svg (the mark on a black tile) and obenblock-mark.svg
(the mark alone) and writes, into site/:

    favicon.ico (16, 32, 48), apple-touch-icon.png (180),
    icon-192.png, icon-512.png, og-image.png (1200 x 630)

The marks use only straight round-capped strokes, hexagons and one linear
gradient, so they are drawn here with Pillow at 8x and downsampled; no SVG
renderer is needed. favicon.svg is a copy of obenblock-icon.svg.

The social card sets the wordmark in Avenir Next Demi Bold, the CSS fallback
of the site's display face (Poppins is shipped only as WOFF2), so the card is
rendered on macOS. Pillow is the only dependency.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
SITE = HERE.parent.parent / "site"
NS = "{http://www.w3.org/2000/svg}"
SS = 8  # supersampling factor
STOPS = [(0.12, (0xC8, 0xFF, 0x00)), (0.5, (0xFF, 0xE6, 0x00)), (0.88, (0xFF, 0x5F, 0x15))]
AVENIR = "/System/Library/Fonts/Avenir Next.ttc"
AVENIR_DEMI, AVENIR_MEDIUM = 2, 5


def gradient_at(t: float) -> tuple[int, int, int]:
    """SVG linear gradient with pad spread over STOPS."""
    if t <= STOPS[0][0]:
        return STOPS[0][1]
    for (o0, c0), (o1, c1) in zip(STOPS, STOPS[1:]):
        if t <= o1:
            u = (t - o0) / (o1 - o0)
            return tuple(round(a + (b - a) * u) for a, b in zip(c0, c1))
    return STOPS[-1][1]


class Mark:
    """Geometry of one mark SVG, in its own user units."""

    def __init__(self, path: Path):
        root = ET.parse(path).getroot()
        self.view = [float(v) for v in root.get("viewBox").split()]
        self.tile = root.find(f"{NS}rect")
        grad = root.find(f".//{NS}linearGradient")
        self.gx1, self.gx2 = float(grad.get("x1")), float(grad.get("x2"))
        group = root.find(f"{NS}g")
        self.scale, self.center = 1.0, (0.0, 0.0)
        if group is not None:
            m = re.match(r"translate\(([\d.]+) ([\d.]+)\) scale\(([\d.]+)\)", group.get("transform"))
            self.center, self.scale = (float(m[1]), float(m[2])), float(m[3])
        body = group if group is not None else root
        stroke = body.find(f"{NS}path")
        nums = [float(v) for v in re.findall(r"[\d.]+", stroke.get("d"))]
        self.lines = [tuple(nums[i:i + 4]) for i in range(0, len(nums), 4)]
        self.stroke_width = float(stroke.get("stroke-width"))
        self.polys = []
        for p in body.findall(f"{NS}polygon"):
            pts = [tuple(float(v) for v in xy.split(",")) for xy in p.get("points").split()]
            fill, alpha = p.get("fill"), float(p.get("fill-opacity", "1"))
            self.polys.append((pts, fill, alpha))

    def tf(self, x: float, y: float) -> tuple[float, float]:
        cx, cy = self.center
        return cx + (x - cx) * self.scale, cy + (y - cy) * self.scale

    def draw(self, img: Image.Image, ox: float, oy: float, k: float, tile: bool) -> None:
        """Paint the mark onto RGBA `img`: user unit (x, y) lands at (ox + k x, oy + k y)."""
        vx, vy, vw, vh = self.view
        P = lambda x, y: (ox + k * (self.tf(x, y)[0] - vx), oy + k * (self.tf(x, y)[1] - vy))
        if tile and self.tile is not None:
            rx = float(self.tile.get("rx")) * k
            ImageDraw.Draw(img).rounded_rectangle(
                [ox, oy, ox + k * vw - 1, oy + k * vh - 1], radius=rx, fill=(0, 0, 0, 255))
        # Gradient-filled strokes and hexagons, through one mask.
        mask = Image.new("L", img.size, 0)
        d = ImageDraw.Draw(mask)
        w = self.stroke_width * self.scale * k
        for x1, y1, x2, y2 in self.lines:
            a, b = P(x1, y1), P(x2, y2)
            d.line([a, b], fill=255, width=max(1, round(w)))
            for cx, cy in (a, b):
                d.ellipse([cx - w / 2, cy - w / 2, cx + w / 2, cy + w / 2], fill=255)
        for pts, fill, _ in self.polys:
            if fill.startswith("url("):
                d.polygon([P(*q) for q in pts], fill=255)
        g0 = P(self.gx1, 0)[0]
        g1 = P(self.gx2, 0)[0]
        row = Image.new("RGB", (img.size[0], 1))
        row.putdata([gradient_at((x - g0) / (g1 - g0)) for x in range(img.size[0])])
        paint = row.resize(img.size, Image.NEAREST).convert("RGBA")
        img.paste(paint, (0, 0), mask)
        # Faces: white highlight on top, dark shade on the right.
        for pts, fill, alpha in self.polys:
            if fill.startswith("url("):
                continue
            rgb = (255, 255, 255) if fill.lower() in ("#fff", "#ffffff") else (0, 0, 0)
            layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
            ImageDraw.Draw(layer).polygon([P(*q) for q in pts], fill=rgb + (round(alpha * 255),))
            img.alpha_composite(layer)


def icon(mark: Mark, size: int) -> Image.Image:
    big = Image.new("RGBA", (size * SS, size * SS), (0, 0, 0, 0))
    mark.draw(big, 0, 0, size * SS / mark.view[2], tile=True)
    return big.resize((size, size), Image.LANCZOS)


def social(mark: Mark) -> Image.Image:
    W, H = 1200, 630
    img = Image.new("RGBA", (W * SS, H * SS), (0, 0, 0, 255))
    k = 300 * SS / mark.view[2]
    mark.draw(img, 96 * SS, (H * SS - k * mark.view[3]) / 2 - 10 * SS, k, tile=False)
    d = ImageDraw.Draw(img)
    word = ImageFont.truetype(AVENIR, 120 * SS, index=AVENIR_DEMI)
    small = ImageFont.truetype(AVENIR, 30 * SS, index=AVENIR_MEDIUM)
    x, y = 450 * SS, 214 * SS
    d.text((x, y), "obenblock", font=word, fill=(244, 245, 238, 255))
    dot_x = x + d.textlength("obenblock", font=word)
    d.text((dot_x, y), ".", font=word, fill=STOPS[-1][1] + (255,))
    d.text((x + 6 * SS, y + 160 * SS), "SHA-256d proof of work · PoWit finality", font=small,
           fill=(162, 165, 155, 255))
    d.text((x + 6 * SS, y + 204 * SS), "Checkpoints anchored in Bloch · obenblock.xyz", font=small,
           fill=(162, 165, 155, 255))
    return img.resize((W, H), Image.LANCZOS).convert("RGB")


def main() -> None:
    tile = Mark(HERE / "obenblock-icon.svg")
    for size, name in ((180, "apple-touch-icon.png"), (192, "icon-192.png"), (512, "icon-512.png")):
        icon(tile, size).save(SITE / name, optimize=True)
    icon(tile, 48).save(SITE / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    social(Mark(HERE / "obenblock-mark.svg")).save(SITE / "og-image.png", optimize=True)
    (SITE / "favicon.svg").write_bytes((HERE / "obenblock-icon.svg").read_bytes())


if __name__ == "__main__":
    main()
