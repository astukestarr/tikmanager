"""Router lifecycle: how old each router is and whether MikroTik has discontinued the model.

Both come straight from MikroTik (the same source sites like eol.network use - MikroTik publishes no end-of-life or
end-of-support dates, only a "Discontinued" mark on the product page):
- **Discontinued**: the badge on the model's mikrotik.com product page (matched like the thumbnails, thumbs.py), re-read weekly.
- **Age**: the router's factory firmware (/system routerboard factory-firmware) is the RouterOS version it left the
  factory with; its release date (first line of upgrade.mikrotik.com's CHANGELOG for that version) dates the router
  to within a few months. Factory firmware 3.x (old RouterBOOT numbering) means it was made before about 2017.
Results are cached in data/lifecycle.json and on the devices table (lc_* columns); nothing is sent anywhere.
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

UA = {"User-Agent": "TikManager (router lifecycle; https://github.com/astukestarr/tikmanager)"}
VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")
BADGE = re.compile(r">\s*Discontinued\s*</span>", re.I)
CHECK_EVERY = 86400            # look at routers whose information is missing or older than this
PAGE_EVERY = 7 * 86400         # re-read a product page weekly
OLD_YEARS = 5                  # "old" from this age on


def release_date(text: str) -> str | None:
    """'What's new in 6.45.9 (2020-Apr-30 10:25):' -> '2020-04-30'."""
    m = re.search(r"\((\d{4})-([A-Za-z]{3})-(\d{1,2})", text[:200])
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)}", "%Y-%b-%d").strftime("%Y-%m-%d")
    except ValueError:
        return None


class Lifecycle:
    def __init__(self, db, data_dir: Path, thumbs):
        self.db, self.thumbs = db, thumbs
        self.file = data_dir / "lifecycle.json"
        self.lock = threading.Lock()

    def _get(self, url, timeout=15) -> str:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return r.read(3_000_000).decode("utf-8", "replace")

    def _cache(self) -> dict:
        try:
            c = json.loads(self.file.read_text(encoding="utf-8"))
            return c if isinstance(c, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, c):
        self.file.write_text(json.dumps(c), encoding="utf-8")

    def made(self, factory_fw: str, cache: dict) -> str | None:
        """The release date of the router's factory firmware ('YYYY-MM-DD'), '<2017' for old RouterBOOT numbering, or None."""
        m = VERSION.match(str(factory_fw or "").strip())
        if not m:
            return None
        if int(m.group(1)) < 6:
            return "<2017"
        dates = cache.setdefault("releases", {})
        if factory_fw in dates:
            return dates[factory_fw]
        try:
            d = release_date(self._get(f"https://upgrade.mikrotik.com/routeros/{factory_fw}/CHANGELOG"))
        except (urllib.error.URLError, TimeoutError, OSError):
            return None   # try again next time
        dates[factory_fw] = d   # a version's release date never changes (None = MikroTik doesn't have it)
        return d

    def status(self, slug: str, cache: dict) -> str | None:
        """'discontinued' / 'current' from the product page, or None if it couldn't be read."""
        pages = cache.setdefault("pages", {})
        p = pages.get(slug)
        if p and time.time() - p.get("at", 0) < PAGE_EVERY:
            return p["status"]
        try:
            html = self._get(f"https://mikrotik.com/product/{slug}")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return p["status"] if p else None
            html = None
        except (urllib.error.URLError, TimeoutError, OSError):
            return p["status"] if p else None
        st = None if html is None else "discontinued" if BADGE.search(html) else "current"
        pages[slug] = {"at": time.time(), "status": st}
        return st

    def check(self, d: dict, cache: dict):
        board, model = d.get("board"), d.get("model")
        if str(model or "").upper() == "CHR" or str(board or "").upper() == "CHR":
            slug, st, made = None, "virtual", None
        else:
            slug = self.thumbs.slug_for(board, model) if self.thumbs else None
            st = self.status(slug, cache) if slug else None
            made = self.made(d.get("fw_factory"), cache)
        self.db.run("UPDATE devices SET lc_slug=?, lc_status=?, lc_made=?, lc_checked=? WHERE id=?", (slug, st, made, time.time(), d["id"]))

    def run_once(self, force=False):
        with self.lock:
            due = self.db.q("""SELECT id, model, board, fw_factory FROM devices WHERE state='adopted' AND last_poll IS NOT NULL
                               AND (? OR lc_checked IS NULL OR lc_checked < ?
                               OR lc_made IS NULL AND fw_factory IS NOT NULL AND lc_checked < ?)""",   # factory firmware arrived since
                            (1 if force else 0, time.time() - CHECK_EVERY, time.time() - 600))
            if not due:
                return
            cache = self._cache()
            for d in due:
                try:
                    self.check(d, cache)
                except Exception as e:   # one odd router mustn't stop the rest
                    print(f"lifecycle: router {d['id']}: {e}")
            self._save(cache)

    def loop(self):
        time.sleep(30)   # let the first poll fill in models and factory firmware
        while True:
            try:
                self.run_once()
            except Exception as e:
                print(f"lifecycle: {e}")
            time.sleep(600)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="lifecycle").start()
