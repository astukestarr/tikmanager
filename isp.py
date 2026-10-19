"""ISPs (Network > ISPs): which internet provider each router's links use, and whether a provider seems to be down.

- Detection, every DETECT_EVERY seconds, per internet link (poller.isp_links / devices.isp_state):
  1. the link's own address, when it's public - looked up in the IPinfo data (organisation, ASN, country);
  2. else, for the link carrying the traffic now: the public address the router reaches TikManager from (its WireGuard
     endpoint - what's left after the modem's / carrier's NAT);
  3. else, for an LTE / 5G link, the operator the modem reports;
  4. else what was found last time (a backup link behind NAT is only seen while it carries traffic).
  Kept in devices.isp_info {link: {name, asn, cc, ip, how, at}}; the router's endpoint also refreshes devices.public_ip.
- Problems: per ISP, its links that are down plus routers that are offline whose active link was on it. When at least
  OUTAGE_MIN of them are affected and they're at least OUTAGE_SHARE of that ISP's links, it's a "possible outage" - the
  ISP page, dashboards and alerts say so (alert kind isp_outage, and a hint on link-down / offline alerts).
- Cloudflare Radar (optional, free API token - Admin > Integrations): its verified outage annotations for each ASN in use,
  read every RADAR_EVERY seconds.
"""
import ipaddress
import json
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

DETECT_EVERY = 600
RADAR_EVERY = 1800
OUTAGE_MIN, OUTAGE_SHARE = 2, 0.3
RADAR_URL = "https://api.cloudflare.com/client/v4/radar/annotations/outages"


def is_public(ip):
    try:
        a = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    return a.version == 4 and a.is_global


class ISPs:
    def __init__(self, db, settings, geo, wg, token_fn=lambda: ""):
        self.db, self.s, self.geo, self.wg, self.token_fn = db, settings, geo, wg, token_fn
        self.radar = {"at": 0, "by_asn": {}, "error": None}
        self.lock = threading.Lock()

    # --- detection -----------------------------------------------------------------------------------------------
    def public(self, ip):
        """A public IPv4 address (dev mode: the simulated routers' documentation range 203.0.113.0/24 counts too)."""
        if getattr(self.s, "dev", False) and str(ip).split("/")[0].startswith("203.0.113."):
            return True
        return is_public(ip)

    def _endpoints(self):
        try:
            return self.wg.endpoints() or {}
        except Exception:  # noqa: BLE001 - no wg on this machine (dev) or no permission
            return {}

    def detect(self):
        eps = self._endpoints()
        now = time.time()
        for d in self.db.q("SELECT id, wg_pubkey, public_ip, wan_ip, isp_state, isp_info, interfaces, online FROM devices WHERE state='adopted'"):
            try:
                links = json.loads(d["isp_state"] or "{}") or {}
                old = json.loads(d["isp_info"] or "{}") or {}
                ifaces = {i.get("name"): i for i in json.loads(d["interfaces"] or "[]") or []}
            except ValueError:
                continue
            ep = eps.get(d["wg_pubkey"]) or (d["wan_ip"] if getattr(self.s, "dev", False) else None)   # dev: the simulated WAN address
            if ep and self.public(ep) and ep != d["public_ip"] and not getattr(self.s, "dev", False):
                self.db.run("UPDATE devices SET public_ip=? WHERE id=?", (ep, d["id"]))
            info = {}
            for n, l in links.items():
                found = None
                addr = (l.get("addr") or "").split("/")[0]
                if addr and self.public(addr):
                    found = self._lookup(addr, "link address")
                elif (l.get("active") or len(links) == 1) and ep and self.public(ep):
                    found = self._lookup(ep, "public address (behind NAT)")
                op = (ifaces.get(n) or {}).get("operator")
                if not found and op:
                    found = {"name": str(op)[:60], "asn": 0, "cc": "", "ip": addr, "how": "LTE operator"}
                if found:
                    found["at"] = now
                    info[n] = found
                elif old.get(n):
                    info[n] = {**old[n], "stale": True}
            if info != old:
                self.db.run("UPDATE devices SET isp_info=? WHERE id=?", (json.dumps(info), d["id"]))

    def _lookup(self, ip, how):
        cc, org, asn = self.geo.lookup3(ip) if self.geo else ("", "", 0)
        if not org:
            return None
        return {"name": org, "asn": asn, "cc": cc, "ip": ip, "how": how}

    # --- grouping and problems -----------------------------------------------------------------------------------
    @staticmethod
    def key(i):
        return f"AS{i['asn']}" if i.get("asn") else f"name:{i.get('name', '').lower()}"

    def summary(self, rows):
        """[{key, name, asn, cc, links: [...], routers, down, affected, outage, radar}] - worst first. rows: devices (with org)."""
        out = {}
        for d in rows:
            try:
                links = json.loads(d.get("isp_state") or "{}") or {}
                info = json.loads(d.get("isp_info") or "{}") or {}
            except ValueError:
                continue
            for n, l in links.items():
                i = info.get(n)
                if not i:
                    continue
                g = out.setdefault(self.key(i), {"key": self.key(i), "name": i["name"], "asn": i.get("asn") or 0, "cc": i.get("cc") or "", "links": []})
                if not d["online"]:
                    state = "router offline" if (l.get("active") or len(links) == 1) else "unknown"
                else:
                    state = "up" if l.get("up") else "down"
                g["links"].append({"device_id": d["id"], "router": d["name"], "org": d.get("org") or "", "link": n, "comment": l.get("comment") or "",
                                   "type": l.get("type") or "", "state": state, "since": l.get("since") if d["online"] else d.get("last_seen"),
                                   "active": bool(l.get("active")), "ip": i.get("ip") or "", "how": i.get("how") or "", "stale": bool(i.get("stale"))})
        radar = self.radar["by_asn"]
        for g in out.values():
            judged = [x for x in g["links"] if x["state"] != "unknown"]
            g["routers"] = len({x["device_id"] for x in g["links"]})
            g["down"] = sum(1 for x in g["links"] if x["state"] == "down")
            g["offline"] = sum(1 for x in g["links"] if x["state"] == "router offline")
            g["affected"] = g["down"] + g["offline"]
            g["outage"] = g["affected"] >= OUTAGE_MIN and judged and g["affected"] / len(judged) >= OUTAGE_SHARE
            g["radar"] = radar.get(g["asn"], []) if g["asn"] else []
            g["links"].sort(key=lambda x: (x["state"] == "up", x["router"]))
        return sorted(out.values(), key=lambda g: (not g["outage"], not any(r.get("ongoing") for r in g["radar"]), -g["affected"], g["name"].lower()))

    def hint(self, device_id, link=None):
        """For alerts: 'likely an ISP outage - N other routers on X are down too' (or '')."""
        d = self.db.one("SELECT isp_info, isp_state FROM devices WHERE id=?", (device_id,))
        if not d:
            return ""
        try:
            info = json.loads(d["isp_info"] or "{}") or {}
            links = json.loads(d["isp_state"] or "{}") or {}
        except ValueError:
            return ""
        n = link or next((k for k, l in links.items() if l.get("active")), None) or next(iter(info), None)
        i = info.get(n) if n else None
        if not i:
            return ""
        rows = self.db.q("SELECT d.*, o.name AS org FROM devices d LEFT JOIN orgs o ON o.id=d.org_id WHERE d.state='adopted'")
        g = next((g for g in self.summary(rows) if g["key"] == self.key(i)), None)
        if not g:
            return ""
        others = len({x["device_id"] for x in g["links"] if x["state"] in ("down", "router offline") and x["device_id"] != device_id})
        radar = [r for r in g["radar"] if r.get("ongoing")]
        bits = []
        if others:
            bits.append(f"{others} other router{'s' if others != 1 else ''} on {g['name']} {'are' if others != 1 else 'is'} down too"
                        + (" - likely an ISP outage" if g["outage"] else ""))
        if radar:
            bits.append(f"Cloudflare Radar reports an outage for {g['name']}: {radar[0].get('summary') or 'ongoing'}")
        return ". ".join(bits)

    # --- Cloudflare Radar ----------------------------------------------------------------------------------------
    def refresh_radar(self, force=False):
        token = self.token_fn()
        if not token:
            self.radar.update(by_asn={}, error=None)
            return {"error": "No Cloudflare token saved."}
        if not force and time.time() - self.radar["at"] < RADAR_EVERY:
            return None
        asns = set()
        for r in self.db.q("SELECT isp_info FROM devices WHERE state='adopted' AND isp_info IS NOT NULL"):
            try:
                asns.update(i.get("asn") for i in (json.loads(r["isp_info"]) or {}).values() if i.get("asn"))
            except ValueError:
                pass
        by, err = {}, None
        for asn in sorted(asns)[:60]:
            q = urllib.parse.urlencode({"asn": asn, "dateRange": "7d", "limit": 10, "format": "json"})
            req = urllib.request.Request(f"{RADAR_URL}?{q}", headers={"Authorization": f"Bearer {token}", "User-Agent": "TikManager"})
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = json.loads(resp.read(2 * 1024 * 1024) or b"{}")
            except urllib.error.HTTPError as e:
                err = "Cloudflare refused the token - check it (it needs Radar read access)." if e.code in (401, 403) else f"Cloudflare Radar: HTTP {e.code}"
                break
            except (OSError, ValueError) as e:
                err = f"Couldn't reach Cloudflare Radar: {e}"
                break
            items = []
            for a in ((data.get("result") or {}).get("annotations") or []):
                out = a.get("outage") or {}
                items.append({"start": a.get("startDate"), "end": a.get("endDate"), "ongoing": not a.get("endDate"),
                              "summary": a.get("description") or out.get("outageCause") or a.get("eventType") or "",
                              "cause": out.get("outageCause") or "", "kind": out.get("outageType") or "",
                              "link": a.get("linkedUrl") if str(a.get("linkedUrl") or "").startswith("https://") else ""})
            if items:
                by[asn] = items
        self.radar.update(at=time.time(), by_asn=by if not err else self.radar["by_asn"], error=err, checked=len(asns))
        return {"error": err, "asns": len(asns), "with_outages": len(by), "ongoing": sum(1 for v in by.values() for r in v if r.get("ongoing"))}

    # --- background ----------------------------------------------------------------------------------------------
    def loop(self):
        time.sleep(60)
        last = 0
        while True:
            try:
                if time.time() - last >= DETECT_EVERY:
                    self.detect()
                    last = time.time()
                self.refresh_radar()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(60)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="isps").start()
