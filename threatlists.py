"""Known bad networks for region blocking's "Block known bad networks" switch: Spamhaus DROP (hijacked and criminal
networks - "don't route or peer") and FireHOL Level 1 (DROP, EDROP, Feodo botnet controllers, DShield's top attackers and
others, put together to be safe to block without false positives).

Downloaded by the TikManager server once a day (both are small - a few thousand networks), never by routers. Only public
IPv4 networks are kept (FireHOL Level 1 also lists private / reserved ranges - those are dropped here so nothing local or
upstream is ever blocked); the result is merged into the fewest networks in <data>/threats/list.txt. If a source can't be
downloaded, its last good copy is kept.
"""
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCES = {
    "spamhaus": {"name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop_v4.json", "info": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/"},
    "firehol1": {"name": "FireHOL Level 1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                 "info": "https://iplists.firehol.org/?ipset=firehol_level1"},
}
REFRESH = 23 * 3600
CIDR = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)(?![\d.])")
MAX_ENTRIES = 20000   # a sanity limit - both lists together are a few thousand networks


class ThreatError(Exception):
    pass


def parse(text):
    """Every public IPv4 network in a list (comments and private / reserved / multicast ranges skipped)."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        for m in CIDR.finditer(s.split(";")[0] if not s.startswith("{") else s):
            try:
                n = ipaddress.IPv4Network(m.group(1), strict=False)
            except ValueError:
                continue
            if n.is_global and not n.is_multicast and n.prefixlen >= 8:
                out.append(n)
    return out


class ThreatLists:
    def __init__(self, data_dir, dev=False):
        self.dir = Path(data_dir) / "threats"
        self.dev = dev
        self.lock = threading.Lock()
        self.state = {"running": False, "error": None}
        self._cache = None

    def meta(self):
        try:
            return json.loads((self.dir / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def cidrs(self):
        stamp = self.meta().get("updated_at")
        if self._cache and self._cache[0] == stamp:
            return self._cache[1]
        try:
            out = [l.strip() for l in (self.dir / "list.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            out = []
        self._cache = (stamp, out)
        return out

    def due(self):
        return time.time() - (self.meta().get("updated_at") or 0) > REFRESH

    def update(self):
        with self.lock:
            self.state.update(running=True, error=None)
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                old = self.meta().get("sources") or {}
                srcs, errors = {}, []
                for sid, s in SOURCES.items():
                    f = self.dir / f"{sid}.txt"
                    try:
                        text = _demo(sid) if self.dev else self._fetch(s["url"])
                        nets = parse(text)
                        if len(nets) < 50:
                            raise ThreatError(f"{s['name']} looked empty - kept the last copy")
                        f.write_text("\n".join(map(str, nets)) + "\n", encoding="utf-8")
                        srcs[sid] = {"name": s["name"], "entries": len(nets), "updated_at": time.time()}
                    except (ThreatError, OSError, urllib.error.URLError) as e:
                        errors.append(f"{s['name']}: {e}")
                        if f.exists():
                            srcs[sid] = {**(old.get(sid) or {"name": s["name"]}), "error": str(e)[:200]}
                nets = []
                for sid in srcs:
                    nets += [ipaddress.IPv4Network(l) for l in (self.dir / f"{sid}.txt").read_text(encoding="utf-8").split()]
                merged = [str(n).removesuffix("/32") for n in ipaddress.collapse_addresses(nets)]
                if not merged:
                    raise ThreatError("; ".join(errors) or "Nothing downloaded.")
                if len(merged) > MAX_ENTRIES:
                    raise ThreatError(f"The lists came to {len(merged):,} networks - more than expected, so they weren't used.")
                (self.dir / "list.new").write_text("\n".join(merged) + "\n", encoding="utf-8")
                (self.dir / "list.new").replace(self.dir / "list.txt")
                (self.dir / "meta.json").write_text(json.dumps({"updated_at": time.time(), "entries": len(merged), "sources": srcs,
                                                                "errors": errors}), encoding="utf-8")
                self.state["error"] = "; ".join(errors) or None
            except ThreatError as e:
                self.state["error"] = str(e)
                raise
            finally:
                self.state["running"] = False

    @staticmethod
    def _fetch(url):
        req = urllib.request.Request(url, headers={"User-Agent": "TikManager"})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(8 * 1024 * 1024)
        return data.decode("utf-8", "replace")


def _demo(sid):
    """Dev mode: made-up lists in the real formats (documentation-style ranges spread over a few blocks)."""
    if sid == "spamhaus":
        return "\n".join(json.dumps({"cidr": f"45.{i}.{j * 16}.0/20", "sblid": f"SBL{i}{j}", "rir": "ripencc"}) for i in range(60, 70) for j in range(6)) \
            + '\n{"type":"metadata","timestamp":1792200000,"size":60}\n'
    return "# FireHOL level1 (demo)\n0.0.0.0/8\n10.0.0.0/8\n127.0.0.0/8\n192.168.0.0/16\n224.0.0.0/3\n" + \
        "\n".join(f"185.{i}.{j}.0/24" for i in range(100, 110) for j in range(0, 60, 7)) + "\n45.60.0.0/20\n"
