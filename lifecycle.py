"""Router lifecycle: how old each router is and whether MikroTik has discontinued the model.

Both come straight from MikroTik (the same source sites like eol.network use - MikroTik publishes no end-of-life or
end-of-support dates, only a "Discontinued" mark on the product page):
- **Discontinued**: the badge on the model's mikrotik.com product page (matched like the thumbnails, thumbs.py), re-read weekly.
- **Age**: the router's factory firmware (/system routerboard factory-firmware) is the RouterOS version it left the
  factory with; its release date (first line of upgrade.mikrotik.com's CHANGELOG for that version) dates the router
  to within a few months. Factory firmware 3.x (old RouterBOOT numbering) means it was made before about 2017.
- **Suggested replacement** (for discontinued or 5+-year-old routers): MikroTik names no successors, so REPLACEMENTS is
  a short list of current models for each old family (the first one MikroTik still sells is suggested - checked on its
  product page, so a suggestion that gets discontinued drops out by itself). Administrators can set their own standard
  model per router model (Admin > Settings > Replacement suggestions), which wins.
Results are cached in data/lifecycle.json and on the devices table (lc_* columns); nothing is sent anywhere.
"""
import html as html_mod
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
OVERRIDES = "lifecycle_suggest"   # settings key: {normalized model: product page slug}, set by administrators

# Old family -> current models, best first. Matched against the router's board name and model code, normalized
# (lowercase letters and digits only: "hAP ac^2" -> "hapac2", "CCR1009-7G-1C-1S+" -> "ccr10097g1c1s"). First match wins.
REPLACEMENTS = [
    (r"^(rb941|rb931|rb952|haplite|hapmini|hapaclite)", ["hap_ax_lite", "hap_ax2"], "small home / office router with Wi-Fi 6"),
    (r"^(rb951|rb962|rbd52|rbd53)|^hap(ac\d?)?$", ["hap_ax2", "hap_ax3"], "same class of office router, with Wi-Fi 6 and gigabit ports"),
    (r"^(rb960|hexpoe)", ["rb5009upr_s_in"], "router with PoE out on every port, much faster CPU, 10G SFP+"),
    (r"^(rb760|hexs$)", ["hex_s_2025"], "the current hEX S"),
    (r"^(rb750|hex$|hexlite)", ["hex_2024"], "the current hEX"),
    (r"^rb2011", ["l009uigs_rm", "l009uigs_2haxd_in"], "8-port router with SFP, the RB2011's successor class"),
    (r"^(rb3011|rb4011)", ["rb5009ug_s_in"], "much faster router with 2.5G and 10G SFP+"),
    (r"^rb1100", ["ccr2004_16g_2splus"], "rack-mount router with 16 gigabit ports"),
    (r"^ccr10(09|16)", ["ccr2004_16g_2splus", "ccr2004_1g_12s_2xs"], "current Cloud Core Router (ARM, 10G SFP+)"),
    (r"^ccr10(36|72)", ["ccr2116_12g_4splus", "ccr2216_1g_12xs_2xq"], "current high-end Cloud Core Router"),
    (r"^crs(105|106)", ["crs305_1g_4s_in"], "small SFP+ switch"),
    (r"^crs(109|112|210)", ["crs310_8g_2s_in"], "8-port switch with SFP+ uplinks"),
    (r"^crs(125|226)", ["crs326_24g_2s_in"], "24-port gigabit switch with SFP+ uplinks"),
    (r"^crs212", ["crs309_1g_8s_in"], "SFP+ switch"),
    (r"^(rbcap|cap$|capac|caplite|capxl)", ["cap_ax"], "ceiling access point with Wi-Fi 6"),
    (r"^(rbwapg5|rbwap2|wap$|wapac|waplite)", ["wap_ax"], "outdoor / wall access point with Wi-Fi 6"),
    (r"^(rbwapg60|wap60g|wirelesswire)", ["cube_60pro_ac", "cube_lite60"], "current 60 GHz link"),
    (r"^(rbsxt|sxt5|sxtsq5|sxtg5)", ["sxtsq_5ax"], "5 GHz point-to-point / CPE radio with Wi-Fi 6"),
    (r"^(rblhg5|lhg5|lhgxl5|rbldf5|ldf5|rbdisc|disclite5)", ["lhg_5_ax", "lhg_5_ax_xl"], "5 GHz dish CPE / link with Wi-Fi 6"),
    (r"^(rbd23|netmetal|rb922)", ["netmetal_ax"], "5 GHz connectorized radio with Wi-Fi 6"),
    (r"^(rbd22|mantbox|rb912uag5)", ["mantbox_ax_15s"], "5 GHz sector with Wi-Fi 6"),
]


def norm(s: str) -> str:
    s = str(s or "").lower().replace("³", "3").replace("²", "2").replace("^", "")
    return re.sub(r"[^a-z0-9]", "", s)


def years(made) -> float | None:
    if made == "<2017":
        return (time.time() - datetime(2017, 1, 1).timestamp()) / (365.25 * 86400)
    try:
        return (time.time() - datetime.strptime(made, "%Y-%m-%d").timestamp()) / (365.25 * 86400)
    except (TypeError, ValueError):
        return None


from rossec import release_date   # 'What's new in 6.45.9 (2020-Apr-30 ...)' / '(2026-09-03)' -> 'YYYY-MM-DD'


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
        if dates.get(factory_fw):   # (an earlier None may be a date format MikroTik changed since: read again)
            return dates[factory_fw]
        try:
            d = release_date(self._get(f"https://upgrade.mikrotik.com/routeros/{factory_fw}/CHANGELOG"))
        except (urllib.error.URLError, TimeoutError, OSError):
            return None   # try again next time
        dates[factory_fw] = d   # a version's release date never changes (None = MikroTik doesn't have it)
        return d

    def status(self, slug: str, cache: dict) -> str | None:
        """'discontinued' / 'current' from the product page, or None if it couldn't be read."""
        return self.page(slug, cache).get("status")

    def name(self, slug: str, cache: dict) -> str:
        return self.page(slug, cache).get("name") or slug

    def page(self, slug: str, cache: dict) -> dict:
        """{status, name} of a mikrotik.com product page (re-read weekly)."""
        pages = cache.setdefault("pages", {})
        p = pages.get(slug)
        if p and time.time() - p.get("at", 0) < PAGE_EVERY and "name" in p:
            return p
        try:
            html = self._get(f"https://mikrotik.com/product/{slug}")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                return p or {}
            html = None
        except (urllib.error.URLError, TimeoutError, OSError):
            return p or {}
        st = None if html is None else "discontinued" if BADGE.search(html) else "current"
        m = re.search(r"<h1[^>]*>\s*([^<]{1,80}?)\s*</h1>", html or "")
        pages[slug] = {"at": time.time(), "status": st, "name": html_mod.unescape(m.group(1)) if m else ""}
        return pages[slug]

    def overrides(self) -> dict:
        try:
            o = json.loads(self.db.setting(OVERRIDES) or "{}")
            return o if isinstance(o, dict) else {}
        except ValueError:
            return {}

    def suggest(self, d: dict, cache: dict, status, made):
        """(slug, name, why) of the suggested replacement for a discontinued or old router, else (None, None, None)."""
        if status != "discontinued" and (years(made) or 0) < OLD_YEARS:
            return None, None, None
        keys = [norm(d.get("model")), norm(d.get("board"))]
        own = next((self.overrides()[k] for k in keys if k and k in self.overrides()), None)
        if own:
            return own, self.name(own, cache), "your standard replacement for this model"
        for pattern, slugs, why in REPLACEMENTS:
            if any(k and re.search(pattern, k) for k in keys):
                for s in slugs:
                    if self.status(s, cache) == "current":
                        return s, self.name(s, cache), why
                return None, None, None
        return None, None, None

    def check(self, d: dict, cache: dict):
        board, model = d.get("board"), d.get("model")
        if str(model or "").upper() == "CHR" or str(board or "").upper() == "CHR":
            slug, st, made, sug = None, "virtual", None, (None, None, None)
        else:
            slug = self.thumbs.slug_for(board, model) if self.thumbs else None
            st = self.status(slug, cache) if slug else None
            made = self.made(d.get("fw_factory"), cache)
            sug = self.suggest(d, cache, st, made)
        self.db.run("UPDATE devices SET lc_slug=?, lc_status=?, lc_made=?, lc_suggest=?, lc_suggest_name=?, lc_suggest_why=?, lc_checked=? WHERE id=?",
                    (slug, st, made, *sug, time.time(), d["id"]))

    def models(self) -> list:
        """Admin > Settings: each router model that is discontinued or old, with its suggestion and any override."""
        own = self.overrides()
        rows = self.db.q("""SELECT model, board, COUNT(*) AS routers, MAX(lc_status) AS status, MIN(lc_made) AS made,
                            MAX(lc_suggest) AS suggest, MAX(lc_suggest_name) AS suggest_name, MAX(lc_suggest_why) AS why
                            FROM devices WHERE state='adopted' AND model IS NOT NULL AND UPPER(model) <> 'CHR'
                            GROUP BY model ORDER BY model""")
        out = []
        for r in rows:
            if r["status"] == "discontinued" or (years(r["made"]) or 0) >= OLD_YEARS or norm(r["model"]) in own:
                out.append({**r, "override": own.get(norm(r["model"]), "")})
        return out

    def set_override(self, model: str, product: str):
        """product: a mikrotik.com product link or its code ('' removes the override). Raises ValueError."""
        key = norm(model)
        if not key:
            raise ValueError("Pick a model.")
        own = self.overrides()
        product = str(product or "").strip()
        if product:
            m = re.fullmatch(r"(?:https?://(?:www\.)?mikrotik\.com)?/?(?:product/)?([A-Za-z0-9_+.-]{1,80})/?", product)
            if not m:
                raise ValueError("Paste the model's mikrotik.com product link (e.g. https://mikrotik.com/product/hap_ax3).")
            slug = m.group(1)
            cache = self._cache()
            if self.status(slug, cache) is None:
                raise ValueError("mikrotik.com has no product page at that address.")
            self._save(cache)
            own[key] = slug
        else:
            own.pop(key, None)
        self.db.set_setting(OVERRIDES, json.dumps(own))
        self.db.run("UPDATE devices SET lc_checked=NULL WHERE model=?", (model,))   # re-checked on the next round
        threading.Thread(target=self.run_once, daemon=True, name="lifecycle-now").start()

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
