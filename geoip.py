"""Country data for region blocking: IPinfo Lite (https://ipinfo.io - free with a token, CC BY-SA 4.0; credit IPinfo).

The daily file (~25 MB gzipped CSV, ~4 million networks) is downloaded by the TikManager server - never by routers - and
boiled down to one merged IPv4 list per country: adjacent networks are joined and written back as the fewest CIDRs, so
a router holds as few address-list entries as possible. Results live in <data>/geo/ (v4/<cc>.txt + meta.json), so the
download isn't repeated on restart. IPv6 isn't used yet (RouterOS keeps IPv6 address lists separately).
"""
import csv
import gzip
import io
import ipaddress
import json
import os
import shutil
import threading
import time
import urllib.error
import urllib.request
from array import array
from pathlib import Path

URL = "https://ipinfo.io/data/ipinfo_lite.csv.gz?token={token}"
REFRESH = 23 * 3600   # IPinfo Lite is updated daily


class GeoError(Exception):
    pass


class GeoIP:
    def __init__(self, data_dir, token_fn, dev=False):
        self.dir = Path(data_dir) / "geo"
        self.token_fn = token_fn   # -> the saved IPinfo token, or ""
        self.dev = dev
        self.lock = threading.Lock()
        self.state = {"running": False, "error": None}
        self._cache = {}

    # --- reading -----------------------------------------------------------------------------------------------
    def meta(self):
        try:
            return json.loads((self.dir / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def countries(self):
        """[{code, name, entries}] sorted by name - what can be picked."""
        m = self.meta().get("countries") or {}
        return sorted(({"code": cc, "name": v.get("name") or cc, "entries": v.get("entries", 0)} for cc, v in m.items()), key=lambda x: x["name"])

    def cidrs(self, cc):
        """One country's merged IPv4 CIDRs (strings)."""
        cc = str(cc).upper()
        if not cc.isalpha() or len(cc) != 2:
            return []
        stamp = self.meta().get("updated_at")
        hit = self._cache.get(cc)
        if hit and hit[0] == stamp:
            return hit[1]
        try:
            out = [l.strip() for l in (self.dir / "v4" / f"{cc}.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            out = []
        self._cache[cc] = (stamp, out)
        return out

    def country_of(self, ip):
        """The country code an IPv4 address is in ('' if unknown) - for showing, not for blocking (reads the lists)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        for c in self.countries():
            for n in self.cidrs(c["code"]):
                if a in ipaddress.ip_network(n):
                    return c["code"]
        return ""

    # --- updating ----------------------------------------------------------------------------------------------
    def due(self):
        return bool(self.token_fn()) and time.time() - (self.meta().get("updated_at") or 0) > REFRESH

    def update(self):
        """Download IPinfo Lite and rebuild the per-country lists. Raises GeoError."""
        token = self.token_fn()
        if not token and not self.dev:
            raise GeoError("Add your IPinfo Lite token first (free at ipinfo.io).")
        with self.lock:
            self.state.update(running=True, error=None)
            try:
                if self.dev and (not token or token == "demo"):
                    rows = _demo_rows()
                    self._build(rows, source="demo data (dev mode)")
                else:
                    req = urllib.request.Request(URL.format(token=token), headers={"User-Agent": "TikManager"})
                    try:
                        resp = urllib.request.urlopen(req, timeout=180)   # follows IPinfo's redirect to its CDN
                    except urllib.error.HTTPError as e:
                        raise GeoError("IPinfo refused the token - check it on ipinfo.io." if e.code in (401, 403)
                                       else f"IPinfo download failed: HTTP {e.code}") from None
                    except OSError as e:
                        raise GeoError(f"Couldn't reach IPinfo: {e}") from None
                    with resp, gzip.GzipFile(fileobj=resp) as gz:
                        self._build(csv.DictReader(io.TextIOWrapper(gz, encoding="utf-8", newline="")), source="IPinfo Lite")
            except GeoError as e:
                self.state["error"] = str(e)
                raise
            except Exception as e:  # noqa: BLE001 - a broken download must not leave half a set of lists
                self.state["error"] = f"Couldn't read the IPinfo file: {e}"
                raise GeoError(self.state["error"]) from None
            finally:
                self.state["running"] = False

    def _build(self, rows, source):
        """Merge each country's IPv4 networks into ranges as the rows stream past (the file is in address order, so a
        country's ranges arrive sorted; anything out of order is sorted at the end), then write the fewest CIDRs."""
        starts, ends, names, sorted_ok = {}, {}, {}, {}
        n = 0
        for row in rows:
            net, cc = (row.get("network") or "").strip(), (row.get("country_code") or "").strip().upper()
            if not net or ":" in net or len(cc) != 2:
                continue
            try:
                ip = ipaddress.IPv4Network(net, strict=False)
            except ValueError:
                continue
            n += 1
            a, b = int(ip.network_address), int(ip.broadcast_address)
            s, e = starts.setdefault(cc, array("I")), ends.setdefault(cc, array("I"))
            names.setdefault(cc, (row.get("country") or cc).strip())
            if s and a <= e[-1] + 1 and a >= s[-1]:
                if b > e[-1]:
                    e[-1] = b
            else:
                if s and a < s[-1]:
                    sorted_ok[cc] = False
                s.append(a)
                e.append(b)
        if n < 1000 and source == "IPinfo Lite":
            raise GeoError("The IPinfo file looked empty - not used.")
        tmp = self.dir / "v4.new"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        meta = {}
        for cc in starts:
            pairs = list(zip(starts[cc], ends[cc]))
            if sorted_ok.get(cc) is False:
                pairs.sort()
            merged = []
            for a, b in pairs:
                if merged and a <= merged[-1][1] + 1:
                    if b > merged[-1][1]:
                        merged[-1][1] = b
                else:
                    merged.append([a, b])
            out = []
            for a, b in merged:
                out += [str(x) for x in ipaddress.summarize_address_range(ipaddress.IPv4Address(a), ipaddress.IPv4Address(b))]
            (tmp / f"{cc}.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
            meta[cc] = {"name": names[cc], "entries": len(out)}
        old = self.dir / "v4"
        if old.exists():
            shutil.rmtree(self.dir / "v4.old", ignore_errors=True)
            os.replace(old, self.dir / "v4.old")
        os.replace(tmp, old)
        shutil.rmtree(self.dir / "v4.old", ignore_errors=True)
        info = {"updated_at": time.time(), "source": source, "networks": n, "countries": meta}
        (self.dir / "meta.json").write_text(json.dumps(info), encoding="utf-8")
        self._cache.clear()


def _demo_rows():
    """Dev mode without a token: a few countries made from real-looking ranges, so the page and the sync can be tried."""
    demo = {"CN": ("China", ["1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "27.8.0.0/13", "36.96.0.0/11", "42.0.0.0/8"]),
            "RU": ("Russia", ["2.56.0.0/14", "5.3.0.0/16", "31.13.0.0/16", "37.9.0.0/16", "46.0.0.0/15"]),
            "IR": ("Iran", ["2.144.0.0/14", "5.22.0.0/17", "31.2.128.0/17"]),
            "KP": ("North Korea", ["175.45.176.0/22"]),
            "US": ("United States", ["3.0.0.0/9", "4.0.0.0/9", "8.0.0.0/9", "12.0.0.0/8", "23.0.0.0/12", "34.0.0.0/9", "64.32.38.0/23"]),
            "CA": ("Canada", ["24.48.0.0/12", "64.56.0.0/14", "99.224.0.0/11"])}
    for cc, (name, nets) in demo.items():
        for n in nets:
            yield {"network": n, "country_code": cc, "country": name}
