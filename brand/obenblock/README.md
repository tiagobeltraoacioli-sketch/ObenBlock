# Obenblock identity preview

The Obenblock mark is six blocks joined by the edges of a BlockDAG. Generations run left to
right, and the middle blocks merge two parents each, as GhostDAG blocks do. One neon gradient
runs through blocks and edges from the oldest block to the newest.

## Files

| Path | Use |
| --- | --- |
| `obenblock-preview.html` | Standalone site preview (English), fonts inlined, no remote dependencies |
| `obenblock-mark.svg` | The mark, transparent ground, for black backgrounds |
| `obenblock-icon.svg` | The mark on a black tile, with heavier blocks: favicon, app icon, avatar |

## Colour

| Name | Value | Use |
| --- | --- | --- |
| Neon lime | `#C8FF00` | Gradient start, oldest block; the Bloch lime |
| Neon yellow | `#FFE600` | Gradient midpoint |
| Fluor orange | `#FF5F15` | Gradient end, newest block; the GnB Fluor |

The gradient is `linear-gradient(100deg, #C8FF00 8%, #FFE600 50%, #FF5F15 94%)`. On the site it
paints the mark, the highlight word of each headline, the primary button and the closing banner.
