"""Product pictures for routers, matched by model name against MikroTik's product catalog.

The catalog (product name -> page) comes from mikrotik.com's category pages and is refreshed weekly; each product's
thumbnail (its og:image) is downloaded once into data/thumbs/ and served by TikManager itself, so browsers never load
anything from another site. Models MikroTik no longer lists (and CHR) simply have no picture.
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "https://mikrotik.com"
GROUPS = ["ethernet-routers", "switches", "wireless-systems", "indoor-wireless", "lte-5g-products", "routerboard",
          "60-ghz-products", "iot-products", "new"]
UA = {"User-Agent": "TikManager (router inventory thumbnails)"}
SLUG = re.compile(r"^[A-Za-z0-9_+.-]{1,80}$")


def norm(s: str) -> str:
    s = str(s or "").lower().replace("³", "3").replace("²", "2").replace("^", "")
    return re.sub(r"[^a-z0-9]", "", s)


class Thumbs:
    def __init__(self, data_dir: Path):
        self.dir = data_dir / "thumbs"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.catalog_file = data_dir / "mikrotik_products.json"
        self.lock = threading.Lock()

    def _get(self, url, timeout=15) -> bytes:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return r.read(3_000_000)

    def catalog(self) -> dict:
        """{normalized product name: slug}, refreshed weekly."""
        with self.lock:
            try:
                c = json.loads(self.catalog_file.read_text(encoding="utf-8"))
                if time.time() - c.get("at", 0) < 7 * 86400 and c.get("products"):
                    return c["products"]
            except (OSError, ValueError):
                c = {}
            products = {}
            for g in GROUPS:
                try:
                    html = self._get(f"{BASE}/products/group/{g}").decode("utf-8", "replace")
                except (urllib.error.URLError, TimeoutError, OSError):
                    continue
                for slug, inner in re.findall(r'href="(?:https://mikrotik\.com)?/product/([^"#?]+)"[^>]*>([\s\S]{0,400}?)</a>', html):
                    name = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", inner)).strip()
                    if name and SLUG.match(slug):
                        products.setdefault(norm(name), slug)
            if products:
                self.catalog_file.write_text(json.dumps({"at": time.time(), "products": products}), encoding="utf-8")
                return products
            return c.get("products", {})   # site unreachable: keep using the old list

    def slug_for(self, *models) -> str | None:
        """Best catalog match for any of the router's model names (board name like 'hAP ax^3', code like 'RB5009UG+S+')."""
        cat = self.catalog()
        for m in models:
            n = norm(m)
            if len(n) < 3:
                continue
            if n in cat:
                return cat[n]
            # 'RB5009UG+S+' -> 'RB5009UG+S+IN', 'CRS326-24G-2S+' -> '...+RM': the shortest product name that starts with it
            starts = sorted((k for k in cat if k.startswith(n)), key=len)
            if starts and len(starts[0]) - len(n) <= 4:
                return cat[starts[0]]
        return None

    def path_for(self, slug: str) -> Path | None:
        """The cached picture for a product, downloading it the first time."""
        if not slug or not SLUG.match(slug):
            return None
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", slug)
        for ext in ("webp", "png", "jpg"):
            p = self.dir / f"{safe}.{ext}"
            if p.is_file():
                return p
        try:
            page = self._get(f"{BASE}/product/{slug}").decode("utf-8", "replace")
            m = re.search(r'property="og:image" content="(https://cdn\.mikrotik\.com/[^"]+)"', page) or \
                re.search(r'content="(https://cdn\.mikrotik\.com/[^"]+)" property="og:image"', page)
            if not m:
                return None
            url = m.group(1)
            ext = url.rsplit(".", 1)[-1].lower() if url.rsplit(".", 1)[-1].lower() in ("webp", "png", "jpg") else "webp"
            data = self._get(url)
            if not data or len(data) > 2_000_000:
                return None
            p = self.dir / f"{safe}.{ext}"
            p.write_bytes(data)
            return p
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
