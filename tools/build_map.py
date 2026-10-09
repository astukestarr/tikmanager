"""Build TikManager's built-in map data (static/map/base.json and static/map/detail.json) from public-domain sources.

TikManager draws its geographic map itself - no map tiles or scripts from other sites - so the shapes and place names
ship with it. Run this only to rebuild or refresh that data; the server never downloads anything.

Sources (public domain, no attribution required):
  Natural Earth  https://github.com/nvkelso/natural-earth-vector/tree/master/geojson
    ne_50m_admin_0_countries.geojson, ne_50m_admin_1_states_provinces.geojson, ne_10m_admin_2_counties.geojson,
    ne_10m_roads.geojson, ne_10m_populated_places_simple.geojson
  US Census Bureau Gazetteer (every incorporated place)
    https://www2.census.gov/geo/docs/maps-data/data/gazetteer/2024_Gazetteer/2024_Gaz_place_national.zip

    python tools/build_map.py <folder with those six files>

Output format: coordinates are longitude/latitude x 1000 (about 100 m), each ring or line a flat list
[x0, y0, dx1, dy1, ...] (deltas after the first point). Shapes are simplified (Douglas-Peucker) to keep files small.
"""
import json
import sys
import zipfile
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "static" / "map"
VIEW = (-180.0, 5.0, -50.0, 75.0)       # lon/lat box kept for countries and roads: North America and around
US_BOX = (-180.0, 17.0, -64.0, 72.0)
Q = 1000                                # 1/1000 degree
SUFFIXES = {"city", "town", "village", "borough", "municipality", "township", "city and borough", "consolidated government",
            "metropolitan government", "unified government", "urban county", "(balance)", "corporation", "plantation", "comunidad"}


def dp(points, tol):
    """Douglas-Peucker simplification of a list of (x, y)."""
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        a, b = stack.pop()
        ax, ay = points[a]
        bx, by = points[b]
        dx, dy = bx - ax, by - ay
        norm = (dx * dx + dy * dy) or 1e-12
        best, idx = -1.0, -1
        for i in range(a + 1, b):
            px, py = points[i]
            t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / norm))
            ex, ey = ax + t * dx - px, ay + t * dy - py
            d = ex * ex + ey * ey
            if d > best:
                best, idx = d, i
        if idx >= 0 and best > tol * tol:
            keep[idx] = True
            stack += [(a, idx), (idx, b)]
    return [p for p, k in zip(points, keep) if k]


def encode(points, tol, closed):
    pts = dp([(float(x), float(y)) for x, y in points], tol)
    if closed and len(pts) < 4:
        return None
    if not closed and len(pts) < 2:
        return None
    out, px, py = [], 0, 0
    for i, (x, y) in enumerate(pts):
        qx, qy = round(x * Q), round(y * Q)
        if i == 0:
            out += [qx, qy]
        elif qx != px or qy != py:
            out += [qx - px, qy - py]
        px, py = qx, qy
    return out if len(out) >= (8 if closed else 4) else None


def rings(geom):
    if geom["type"] == "Polygon":
        return [r for r in geom["coordinates"]]
    if geom["type"] == "MultiPolygon":
        return [r for poly in geom["coordinates"] for r in poly]
    return []


def lines(geom):
    if geom["type"] == "LineString":
        return [geom["coordinates"]]
    if geom["type"] == "MultiLineString":
        return geom["coordinates"]
    return []


def overlaps(coords, box):
    xs = [c[0] for c in coords]
    ys = [c[1] for c in coords]
    return max(xs) >= box[0] and min(xs) <= box[2] and max(ys) >= box[1] and min(ys) <= box[3]


def load(src, name):
    return json.load(open(src / f"{name}.geojson", encoding="utf-8"))["features"]


def place_name(raw):
    words = raw.split()
    for n in (3, 2, 1):
        if len(words) > n and " ".join(words[-n:]).lower() in SUFFIXES:
            return " ".join(words[:-n])
    return raw


def main(src):
    src = Path(src)
    base = {"countries": [], "states": []}
    for f in load(src, "ne_50m_admin_0_countries"):
        for r in rings(f["geometry"]):
            if overlaps(r, VIEW):
                e = encode(r, 0.02, True)
                if e:
                    base["countries"].append(e)
    for f in load(src, "ne_50m_admin_1_states_provinces"):
        p = f["properties"]
        if p.get("adm0_a3") not in ("USA", "CAN", "MEX"):
            continue
        shapes = [e for e in (encode(r, 0.006, True) for r in rings(f["geometry"])) if e]
        if shapes:
            base["states"].append({"n": p.get("name") or "", "c": (p.get("postal") or "")[:3], "us": p.get("adm0_a3") == "USA", "s": shapes})

    detail = {"counties": [], "roads": [], "places": []}
    for f in load(src, "ne_10m_admin_2_counties"):
        if f["properties"].get("ADM0_A3") != "USA":
            continue
        shapes = [e for e in (encode(r, 0.004, True) for r in rings(f["geometry"])) if e]
        if shapes:
            detail["counties"].append({"n": f["properties"].get("NAME") or "", "s": shapes})
    for f in load(src, "ne_10m_roads"):
        p = f["properties"]
        if p.get("type") not in ("Major Highway", "Beltway", "Bypass") and not p.get("expressway"):
            continue
        for ln in lines(f["geometry"]):
            if overlaps(ln, US_BOX):
                e = encode(ln, 0.003, False)
                if e:
                    detail["roads"].append(e)

    # every incorporated US place, ranked so the biggest are labelled first when zoomed out
    pop = {}
    for f in load(src, "ne_10m_populated_places_simple"):
        p = f["properties"]
        if p.get("adm0_a3") == "USA":
            pop[(p.get("name", "").lower(), (p.get("adm1name") or "").lower())] = p.get("pop_max") or 0
    states = {s["c"]: s["n"].lower() for s in base["states"] if s["us"]}
    z = zipfile.ZipFile(src / "gaz_places.zip")
    with z.open(z.namelist()[0]) as fh:
        rows = fh.read().decode("latin-1").splitlines()
    head = [h.strip() for h in rows[0].split("\t")]
    col = {h: i for i, h in enumerate(head)}
    for line in rows[1:]:
        c = [x.strip() for x in line.split("\t")]
        if len(c) < len(head) or c[col["FUNCSTAT"]] != "A":
            continue
        name = place_name(c[col["NAME"]])
        st = c[col["USPS"]]
        lat, lon = float(c[col["INTPTLAT"]]), float(c[col["INTPTLONG"]])
        people = pop.get((name.lower(), states.get(st, "")), 0)
        area = float(c[col["ALAND_SQMI"]] or 0)
        tier = (0 if people >= 1_000_000 else 1 if people >= 250_000 else 2 if people >= 50_000 else
                3 if area >= 40 else 4 if area >= 8 else 5)
        detail["places"].append([name, st, round(lon * Q), round(lat * Q), tier])
    detail["places"].sort(key=lambda p: p[4])

    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in (("base", base), ("detail", detail)):
        path = OUT / f"{name}.json"
        path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        print(f"{path.name}: {path.stat().st_size // 1024} KB "
              + ", ".join(f"{k} {len(v)}" for k, v in data.items()))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
