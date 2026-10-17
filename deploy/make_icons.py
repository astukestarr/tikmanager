"""Draws TikManager's app icons (static/icon-192.png, icon-512.png, apple-touch-icon.png) - the tiki torch from logo.svg,
simplified to shapes, on a dark rounded tile - with the standard library only (no image packages on the server).

Run from the repository: python deploy/make_icons.py
"""
import math
import struct
import zlib
from pathlib import Path

BG = (19, 35, 58)


def png(w, h, px):
    raw = b"".join(b"\x00" + bytes(c for p in px[y * w:(y + 1) * w] for c in p) for y in range(h))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def inside_poly(x, y, pts):
    c = False
    for i in range(len(pts)):
        (x1, y1), (x2, y2) = pts[i], pts[i - 1]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            c = not c
    return c


def flame(cx, top, bottom, half):
    """A teardrop: point at the top, round at the bottom (64-unit logo coordinates)."""
    pts = []
    r = half
    cy = bottom - r
    for k in range(41):
        t = k / 40
        y = top + (cy - top) * t
        w = r * math.sin(t * math.pi / 2) ** 1.4
        pts.append((cx + w, y))
    for k in range(1, 40):
        a = k / 40 * math.pi
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    for k in range(40, -1, -1):
        t = k / 40
        y = top + (cy - top) * t
        w = r * math.sin(t * math.pi / 2) ** 1.4
        pts.append((cx - w, y))
    return pts


def rrect(x, y, w, h, r):
    return lambda px, py: (x <= px <= x + w and y <= py <= y + h and
                           not ((px < x + r or px > x + w - r) and (py < y + r or py > y + h - r) and
                                min(math.hypot(px - cx, py - cy) for cx in (x + r, x + w - r) for cy in (y + r, y + h - r)) > r))


def ellipse(cx, cy, rx, ry):
    return lambda px, py: ((px - cx) / rx) ** 2 + ((py - cy) / ry) ** 2 <= 1


# the torch, top to bottom of the drawing order (later shapes paint over earlier ones); logo.svg coordinates (0-64)
f_out, f_in = flame(32, 2, 34, 11.5), flame(32, 12.5, 32, 6.6)
SHAPES = [
    ((242, 107, 29), lambda x, y: inside_poly(x, y, f_out)),
    ((255, 182, 39), lambda x, y: inside_poly(x, y, f_in)),
    ((255, 240, 191), ellipse(32, 27.5, 3.6, 3.8)),
    ((201, 162, 103), lambda x, y: inside_poly(x, y, [(28.6, 49), (35.4, 49), (34.3, 63), (29.7, 63)])),
    ((94, 58, 26), rrect(17, 29, 30, 4.5, 2)),
    ((138, 85, 39), rrect(19, 32, 26, 17, 3)),
    ((94, 58, 26), rrect(21, 34.5, 22, 2.4, 1)),
    ((246, 227, 180), ellipse(26, 39.3, 3.4, 2.4)),
    ((246, 227, 180), ellipse(38, 39.3, 3.4, 2.4)),
    ((46, 27, 12), ellipse(26, 39.5, 1.3, 1.3)),
    ((46, 27, 12), ellipse(38, 39.5, 1.3, 1.3)),
    ((94, 58, 26), lambda x, y: inside_poly(x, y, [(30.4, 37), (33.6, 37), (34.6, 42), (29.4, 42)])),
    ((46, 27, 12), rrect(23.5, 43.2, 17, 4, 2)),
]


def icon(size, pad, rounded=True, ss=3):
    """pad: share of the tile left around the torch; rounded: a rounded tile with transparent corners (else a full square)."""
    scale = size * (1 - 2 * pad) / 64
    off = size * pad
    rad = size * 0.22
    tile = rrect(0, 0, size, size, rad) if rounded else (lambda px, py: True)
    out = []
    for py in range(size):
        for px in range(size):
            acc, alpha = [0, 0, 0], 0
            for sy in range(ss):
                for sx in range(ss):
                    X, Y = px + (sx + 0.5) / ss, py + (sy + 0.5) / ss
                    if not tile(X, Y):
                        continue
                    lx, ly = (X - off) / scale, (Y - off) / scale
                    col = BG
                    if 0 <= lx <= 64 and 0 <= ly <= 64:
                        for c, test in SHAPES:
                            if test(lx, ly):
                                col = c
                    acc = [a + c for a, c in zip(acc, col)]
                    alpha += 1
            n = ss * ss
            out.append((*(round(a / alpha) if alpha else 0 for a in acc), round(255 * alpha / n)))
    return png(size, size, out)


if __name__ == "__main__":
    static = Path(__file__).resolve().parent.parent / "static"
    (static / "icon-192.png").write_bytes(icon(192, 0.12, rounded=False))
    (static / "icon-512.png").write_bytes(icon(512, 0.12, rounded=False))
    (static / "apple-touch-icon.png").write_bytes(icon(180, 0.1, rounded=False))   # iOS rounds the corners itself
    print("icons written")
