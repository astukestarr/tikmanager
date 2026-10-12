"""RouterOS security: known CVEs and missed MikroTik security releases for each router, and release notes on request.

Two separate signals, kept apart because they claim different things:
- **Security releases** ("a security fix exists on the way to your channel's newest version and you're below it"):
  MikroTik's own changelog for each release (upgrade.mikrotik.com/routeros/<version>/CHANGELOG) is read once and kept.
  A release counts as a security release when a line names a CVE or says security / vulnerability / exploit /
  unauthorized / attack - in its change list or a notice above it (e.g. 7.24.2: "This is an important security update";
  MikroTik's "!)" marks important changes, not only security ones). Only releases newer than the router's
  version and no newer than the newest on its update channel are considered.
- **Known CVEs**: NIST's National Vulnerability Database lists RouterOS CVEs with the affected version ranges
  (services.nvd.nist.gov, cpe mikrotik:routeros; refreshed daily). A router is listed for a CVE when its version falls in
  a range. NVD data is sometimes late or imprecise - it informs, it never blocks anything.
Nothing about your routers is sent anywhere: both sources are plain public downloads.
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

UA = {"User-Agent": "TikManager (RouterOS security; https://github.com/astukestarr/tikmanager)"}
RELEASE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")
ANY_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:(?:rc|beta)\d+)?$")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:mikrotik:routeros&resultsPerPage=2000&startIndex={}"
NVD_EVERY = 86400
DEVICE_EVERY = 6 * 3600
MAX_PATCH = 30   # x.y.1 ... x.y.30 at most per minor release when looking for releases


def vkey(v):
    """'7.24.2' -> (7, 24, 2); anything else (rc, beta, garbage) -> None."""
    m = RELEASE.match(str(v or "").strip().split(" ")[0])
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


def release_date(text: str):
    """'What's new in 6.45.9 (2020-Apr-30 10:25):' or '... (2026-09-03):' -> 'YYYY-MM-DD'."""
    m = re.search(r"\((\d{4})-([A-Za-z]{3}|\d{2})-(\d{1,2})", text[:200])
    if not m:
        return None
    fmt = "%Y-%b-%d" if m.group(2).isalpha() else "%Y-%m-%d"
    try:
        return datetime.strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)}", fmt).strftime("%Y-%m-%d")
    except ValueError:
        return None


SECURITY_WORDS = re.compile(r"\bCVE-\d{4}-\d{4,}|vulnerab|exploit|unauthori[sz]ed|\battack|"
                            r"security (?:issue|update|fix|problem|release|patch|advisory|hole|flaw)|^\*\)\s*security\s*-", re.I)
# ("security" alone is also a Wi-Fi setting - "WiFi/Security menu", "security.owe-..." - so it needs a qualifier)


def security_items(text: str) -> list:
    """The security-related lines of one release's changelog (empty = not a security release). MikroTik's "!)" marks an
    important change, not necessarily a security one, so a line counts only when it names a CVE or says vulnerability /
    exploit / unauthorized / attack / "security issue|update|fix..." - in the change list or in a notice written above it."""
    out = []
    for l in (x.strip() for x in text.replace("\r", "").split("\n")[1:]):
        if not l or l.lower().startswith(("changes since", "what's new")) or re.fullmatch(r"\(.*\)", l):
            continue   # e.g. "(factory only release)"
        if SECURITY_WORDS.search(l):
            out.append(l)
    return out[:20]


def _score(cve: dict):
    m = cve.get("metrics") or {}
    for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for x in m.get(k) or []:
            d = x.get("cvssData") or {}
            if d.get("baseScore") is not None:
                return float(d["baseScore"]), d.get("baseSeverity") or x.get("baseSeverity") or ""
    return None, ""


class RosSecurity:
    def __init__(self, db, data_dir: Path):
        self.db = db
        self.dir = data_dir / "routeros_changelogs"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.dir / "index.json"   # {version: {"date", "security": [...]}, or {"missing": when} if MikroTik had no such release}
        self.nvd_file = data_dir / "nvd_routeros.json"
        self.lock = threading.Lock()
        self._index = None

    def _get(self, url, timeout=20) -> str:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return r.read(5_000_000).decode("utf-8", "replace")

    # --- MikroTik changelogs ------------------------------------------------------------------------------------
    def index(self) -> dict:
        if self._index is None:
            try:
                self._index = json.loads(self.index_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._index = {}
        return self._index

    def release(self, version: str):
        """{"date", "security"} of a release (reading its changelog the first time), None if it doesn't exist.
        Raises OSError when MikroTik can't be reached (try again later)."""
        idx = self.index()
        if version in idx and idx[version] is not None:
            if "missing" not in idx[version]:
                return idx[version]
            if time.time() - idx[version]["missing"] < 7 * 86400:   # e.g. a later long-term x.y.9 may still appear
                return None
        try:
            text = self._get(f"https://upgrade.mikrotik.com/routeros/{version}/CHANGELOG")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise OSError(str(e)) from None
            idx[version] = {"missing": time.time()}
            return None
        except (urllib.error.URLError, TimeoutError) as e:
            raise OSError(str(e)) from None
        if not text.startswith("What's new"):
            idx[version] = {"missing": time.time()}
            return None
        (self.dir / f"{version}.txt").write_text(text, encoding="utf-8")
        idx[version] = {"date": release_date(text), "security": security_items(text)}
        return idx[version]

    def notes(self, version: str) -> dict:
        """Release notes for the "What's new" dialog: {version, date, security, text}."""
        if not ANY_VERSION.match(version or ""):
            raise ValueError("Not a RouterOS version.")
        with self.lock:
            p = self.dir / f"{version}.txt"
            if not p.is_file():
                try:
                    self.release(version) if vkey(version) else None
                    if not p.is_file():   # rc / beta: not kept in the index, fetched each time
                        p.write_text(self._get(f"https://upgrade.mikrotik.com/routeros/{version}/CHANGELOG"), encoding="utf-8")
                except (OSError, urllib.error.URLError) as e:
                    raise ValueError(f"MikroTik's release notes for {version} couldn't be read ({e}).") from None
                finally:
                    self._save_index()
            text = p.read_text(encoding="utf-8")
        return {"version": version, "date": release_date(text), "security": security_items(text), "text": text[:200_000]}

    def releases_between(self, cur, latest) -> list:
        """Every release newer than `cur` up to `latest` (same major version), oldest first: [(version, info)]."""
        a, b = vkey(cur), vkey(latest)
        if not a or not b or b <= a or a[0] != b[0]:
            return []
        out = []
        for minor in range(a[1], b[1] + 1):
            first = a[2] + 1 if minor == a[1] else 0
            for patch in range(first, MAX_PATCH + 1):
                if (b[0], minor, patch) > b:
                    break
                v = f"{a[0]}.{minor}" + (f".{patch}" if patch else "")
                info = self.release(v)
                if info is None:
                    if patch == 0:
                        continue   # x.y always exists before x.y.1, but be tolerant
                    break
                out.append((v, info))
        return out

    def _save_index(self):
        if self._index is not None:
            self.index_file.write_text(json.dumps(self._index), encoding="utf-8")

    # --- NVD ------------------------------------------------------------------------------------------------------
    def nvd(self) -> dict:
        try:
            return json.loads(self.nvd_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"at": 0, "cves": []}

    def refresh_nvd(self):
        cves, start, total = [], 0, 1
        while start < total:
            j = json.loads(self._get(NVD.format(start), timeout=90))
            total = j.get("totalResults", 0)
            for v in j.get("vulnerabilities") or []:
                c = v.get("cve") or {}
                ranges = []
                for conf in c.get("configurations") or []:
                    for node in conf.get("nodes") or []:
                        for m in node.get("cpeMatch") or []:
                            parts = str(m.get("criteria") or "").split(":")
                            if len(parts) > 5 and parts[4] == "routeros" and m.get("vulnerable"):
                                ranges.append({k: m[k] for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                                                                 "versionEndExcluding") if m.get(k)} | {"exact": parts[5]})
                score, sev = _score(c)
                desc = next((d["value"] for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
                cves.append({"id": c.get("id"), "score": score, "severity": sev, "published": (c.get("published") or "")[:10],
                             "summary": desc[:400], "ranges": ranges})
            start += j.get("resultsPerPage") or 2000
            if start < total:
                time.sleep(7)   # NVD without an API key: 5 requests per 30 seconds
        self.nvd_file.write_text(json.dumps({"at": time.time(), "cves": cves}), encoding="utf-8")

    @staticmethod
    def affects(r: dict, v) -> bool:
        if r.get("exact") not in ("*", "-", "", None):
            return vkey(r["exact"]) == v
        bounds = [k for k in r if k.startswith("version")]
        if not bounds:
            return False   # "all versions" without a range: too vague to put on a router
        k = lambda key: vkey(r[key])
        if "versionStartIncluding" in r and (not k("versionStartIncluding") or v < k("versionStartIncluding")):
            return False
        if "versionStartExcluding" in r and (not k("versionStartExcluding") or v <= k("versionStartExcluding")):
            return False
        if "versionEndIncluding" in r and (not k("versionEndIncluding") or v > k("versionEndIncluding")):
            return False
        if "versionEndExcluding" in r and (not k("versionEndExcluding") or v >= k("versionEndExcluding")):
            return False
        return True

    def cves_for(self, version, cves) -> list:
        v = vkey(version)
        if not v:
            return []
        out = []
        for c in cves:
            hit = [r for r in c["ranges"] if self.affects(r, v)]
            if hit:
                fixed = next((r["versionEndExcluding"] for r in hit if r.get("versionEndExcluding")), "")
                out.append({"id": c["id"], "score": c["score"], "severity": c["severity"], "published": c["published"],
                            "summary": c["summary"], "fixed": fixed})
        return sorted(out, key=lambda x: -(x["score"] or 0))

    # --- per router ---------------------------------------------------------------------------------------------
    def check(self, d: dict, cves: list):
        cur = str(d.get("version") or "").split(" ")[0]
        fixes = [{"version": v, "date": i["date"], "items": i["security"]}
                 for v, i in self.releases_between(cur, d.get("ros_latest")) if i and i["security"]]
        found = self.cves_for(cur, cves)
        info = {"fixes": fixes, "cves": found}
        self.db.run("UPDATE devices SET sec_target=?, cve_n=?, cve_max=?, sec_info=?, sec_version=?, sec_checked=? WHERE id=?",
                    (fixes[-1]["version"] if fixes else None, len(found), max((c["score"] or 0) for c in found) if found else None,
                     json.dumps(info), cur, time.time(), d["id"]))

    def run_once(self, force=False):
        with self.lock:
            if force or time.time() - self.nvd().get("at", 0) > NVD_EVERY:
                try:
                    self.refresh_nvd()
                except (OSError, ValueError, urllib.error.URLError) as e:
                    print(f"rossec: NVD: {e}")
            cves = self.nvd().get("cves") or []
            due = self.db.q("""SELECT id, version, ros_latest, sec_version FROM devices WHERE state='adopted' AND version IS NOT NULL""")
            now = time.time()
            for d in due:
                cur = str(d["version"] or "").split(" ")[0]
                row = self.db.one("SELECT sec_checked FROM devices WHERE id=?", (d["id"],))
                if not force and d["sec_version"] == cur and (row["sec_checked"] or 0) > now - DEVICE_EVERY:
                    continue
                try:
                    self.check(d, cves)
                except OSError as e:   # MikroTik unreachable: next round
                    print(f"rossec: router {d['id']}: {e}")
                    break
            self._save_index()

    def summary(self, rows) -> dict:
        """Security page: the routers with something to fix, and every CVE that affects at least one of them."""
        routers, by_cve = [], {}
        for r in rows:
            info = json.loads(r.get("sec_info") or "null") or {}
            if not info.get("fixes") and not info.get("cves"):
                continue
            routers.append({"id": r["id"], "name": r["name"], "org": r.get("org"), "version": r["version"], "sec_target": r.get("sec_target"),
                            "cve_n": r.get("cve_n") or 0, "cve_max": r.get("cve_max"), "latest": r.get("ros_latest")})
            for c in info.get("cves") or []:
                by_cve.setdefault(c["id"], {**c, "routers": 0})["routers"] += 1
        return {"routers": sorted(routers, key=lambda x: (-(x["cve_max"] or 0), x["name"] or "")),
                "cves": sorted(by_cve.values(), key=lambda x: -(x["score"] or 0)), "nvd_at": self.nvd().get("at")}

    def loop(self):
        time.sleep(45)
        while True:
            try:
                self.run_once()
            except Exception as e:
                print(f"rossec: {e}")
            time.sleep(600)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="rossec").start()
