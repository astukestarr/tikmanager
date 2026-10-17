"""Country data for region blocking: IPinfo Lite (https://ipinfo.io - free with a token, CC BY-SA 4.0; credit IPinfo).

The daily file (~25 MB gzipped CSV, ~4 million networks) is downloaded by the TikManager server - never by routers - and
boiled down to one merged IPv4 list per country: adjacent networks are joined and written back as the fewest CIDRs, so
a router holds as few address-list entries as possible. Results live in <data>/geo/ (v4/<cc>.txt + meta.json), so the
download isn't repeated on restart. IPv6 isn't used yet (RouterOS keeps IPv6 address lists separately).

For showing addresses (Flows), ranges.tsv keeps every IPv4 range with its country and organisation (as_name), adjacent
rows with the same pair joined; lookup() searches it (loaded on first use, arrays + binary search).
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
from bisect import bisect_right
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
        self._idx = None   # (stamp, starts, ends, cc index, name index, ccs, names) for lookup()

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

    def _index(self):
        stamp = self.meta().get("updated_at")
        if self._idx and self._idx[0] == stamp:
            return self._idx
        starts, ends, ci, ni, ccs, names, cpos, npos = array("I"), array("I"), array("H"), array("I"), [], [], {}, {}
        try:
            with open(self.dir / "ranges.tsv", encoding="utf-8") as f:
                for line in f:
                    a, b, cc, name = (line.rstrip("\n").split("\t") + ["", "", "", ""])[:4]
                    starts.append(int(a)); ends.append(int(b))
                    if cc not in cpos:
                        cpos[cc] = len(ccs)
                        ccs.append(cc)
                    if name not in npos:
                        npos[name] = len(names)
                        names.append(name)
                    ci.append(cpos[cc])
                    ni.append(npos[name])
        except OSError:
            pass
        self._idx = (stamp, starts, ends, ci, ni, ccs, names)
        return self._idx

    def lookup(self, ip):
        """(country code, organisation) for an IPv4 address - ("", "") when unknown or private."""
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return "", ""
        _, starts, ends, ci, ni, ccs, names = self._index()
        i = bisect_right(starts, n) - 1
        if i < 0 or n > ends[i]:
            return "", ""
        return ccs[ci[i]], names[ni[i]]

    def country_of(self, ip):
        return self.lookup(ip)[0]

    def names(self):
        return {c["code"]: c["name"] for c in self.countries()}

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
        self.dir.mkdir(parents=True, exist_ok=True)
        rf = open(self.dir / "ranges.new", "w", encoding="utf-8", newline="\n")
        cur = None   # [start, end, cc, as_name] being joined
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
            org = (row.get("as_name") or "").replace("\t", " ").replace("\n", " ").strip()[:80]
            if cur and a == cur[1] + 1 and cur[2] == cc and cur[3] == org:
                cur[1] = b
            else:
                if cur:
                    rf.write(f"{cur[0]}\t{cur[1]}\t{cur[2]}\t{cur[3]}\n")
                cur = [a, b, cc, org]
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
        if cur:
            rf.write(f"{cur[0]}\t{cur[1]}\t{cur[2]}\t{cur[3]}\n")
        rf.close()
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
        os.replace(self.dir / "ranges.new", self.dir / "ranges.tsv")
        info = {"updated_at": time.time(), "source": source, "networks": n, "countries": meta}
        (self.dir / "meta.json").write_text(json.dumps(info), encoding="utf-8")
        self._cache.clear()
        self._idx = None


def _demo_rows():
    """Dev mode without a token: a few countries made from real-looking ranges, so the page and the sync can be tried."""
    demo = {"CN": ("China", ["1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "27.8.0.0/13", "36.96.0.0/11", "42.0.0.0/8"], "Example Telecom CN"),
            "RU": ("Russia", ["2.56.0.0/14", "5.3.0.0/16", "31.13.0.0/16", "37.9.0.0/16", "46.0.0.0/15"], "Example Net RU"),
            "IR": ("Iran", ["2.144.0.0/14", "5.22.0.0/17", "31.2.128.0/17"], "Example ISP IR"),
            "KP": ("North Korea", ["175.45.176.0/22"], "Example KP"),
            "US": ("United States", ["3.0.0.0/9", "4.0.0.0/9", "8.0.0.0/9", "12.0.0.0/8", "23.0.0.0/12", "34.0.0.0/9", "64.32.38.0/23"], "Example Cloud US"),
            "CA": ("Canada", ["24.48.0.0/12", "64.56.0.0/14", "99.224.0.0/11"], "Example Cable CA"),
            "HK": ("Hong Kong", ["47.240.0.0/14"], "Example Cloud HK"),
            "DE": ("Germany", ["78.40.0.0/14"], "Example Hosting DE")}
    rows = [{"network": n, "country_code": cc, "country": name, "as_name": org} for cc, (name, nets, org) in demo.items() for n in nets]
    rows.sort(key=lambda r: int(ipaddress.IPv4Network(r["network"]).network_address))   # the real file is in address order
    yield from rows
