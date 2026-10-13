"""Ubiquiti networks: UniFi (unifi.ui.com, Site Manager API) and UISP (a UISP server's NMS API) connections, their sites and
devices, each site assigned to a TikManager client.

Connections (net_accounts) - added on Admin > Integrations > UniFi & UISP by an administrator:
- kind "unifi": an API key from unifi.ui.com > Settings > API (Site Manager API, read-only).
- kind "uisp": the UISP server's address + an API token (UISP > Settings > Users > API tokens - a read-only one is enough).
- owner: your MSP account (org_id NULL - assign each site to a client on the UniFi / UISP page), or one client's own account
  (org_id set - everything in it belongs to that client).
Secrets are sealed with the vault ("netacct:<id>") and never sent back to the browser. A UISP server with a self-signed
certificate can be trusted by pinning its certificate (SHA-256 of the certificate taken when the connection is saved) -
verification is never simply switched off.

Every 10 minutes (and on "Sync now") each connection's sites and devices are read into net_sites / net_devices.
- UniFi: devices come per console, not per site. One site on the console: they're that site's. Several sites (a
  self-hosted / Cloud Key network server): matched through the console's Network integration API via Ubiquiti's cloud
  connector where supported, and by the site's gateway MAC; the rest stay on the console (technicians only).
- UISP: every device names its site. Sites of type "endpoint" (subscriber locations) are kept, marked as such.
Health per site: devices online / offline (and since when), firmware updates, plus what the platform reports (UniFi:
clients, ISP, WAN uptime, internet issues). Alerts: one "site has offline devices" alert per site (alerts.py).
In dev mode the key "demo" returns sample data instead of calling Ubiquiti.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import random
import re
import socket
import ssl
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

UNIFI_API = "https://api.ui.com"
SYNC_SECONDS = 600
MAX_BODY = 20 * 1024 * 1024          # per response
MAX_SITES, MAX_DEVICES = 2000, 10000  # per connection - a client's own server can't fill TikManager's database


def txt(v, n=200):
    """Text from the platform (a client's own server may send anything): a string, no control characters, bounded."""
    if v is None or isinstance(v, (dict, list)):
        return None
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v))[:n] or None


def plain(v, n=80):
    """A name safe for alert text (Teams cards render markdown, tickets and webhooks show it): no markup or line breaks."""
    s = re.sub(r"(?i)[a-z][a-z0-9+.-]*://", "", txt(v, n) or "")   # no clickable links either
    return re.sub(r"[\[\]()<>*_`#|~\\!]", " ", s).strip()


KINDS = {"unifi": "UniFi", "uisp": "UISP"}


class NetError(Exception):
    pass


def macnorm(m):
    return re.sub(r"[^0-9a-f]", "", str(m or "").lower())


def num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def online(status):
    return str(status or "").lower() in ("online", "active", "connected")


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
ALLOW_DOC = False   # dev mode: the simulated routers and demo data use the documentation ranges as "public" addresses


def public(ip):
    """The address if it's a public (internet) IP, else None."""
    try:
        a = ipaddress.ip_address(str(ip or "").split("/")[0].strip())
        return str(a) if a.is_global or (ALLOW_DOC and any(a in n for n in DOC_NETS)) else None
    except ValueError:
        return None


def public_in(obj, depth=0):
    """Public IPs found anywhere in a statistics block (UniFi's wans / gateway shapes vary by version) - only keys that
    name an address (externalIp, wanIp, ipAddress ...)."""
    out = []
    if depth > 4:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                out += public_in(v, depth + 1)
            elif re.search(r"ip(addr(ess)?)?s?$|externalip|wanip|publicip", str(k), re.I) and public(v):
                out.append(public(v))
    elif isinstance(obj, list):
        for v in obj[:20]:
            out += public_in(v, depth + 1)
    return out


# --- platform clients: each returns (sites, devices) in one shape ------------------------------------------------------------
#   site:   {ext, name, internal, console, gateway_mac, type, stats}
#   device: {ext, site_ext | None, host, mac, name, model, ip, status, version, update, is_console, startup}

class UnifiClient:
    def __init__(self, key, demo=False):
        self.key, self.demo = key, demo

    def _call(self, path, params=None, timeout=30):
        url = UNIFI_API + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
        for attempt in range(3):
            req = urllib.request.Request(url, headers={"X-API-Key": self.key, "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.loads(r.read() or b"null")
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 2:   # rate limited: wait as told (capped) and try again
                    time.sleep(min(30, float(e.headers.get("Retry-After") or 5)))
                    continue
                detail = e.read()[:300].decode("utf-8", "replace")
                try:
                    detail = json.loads(detail).get("message") or detail
                except (ValueError, AttributeError):
                    pass
                hint = {401: " (check the API key)", 403: " (the key's account can't see this)"}.get(e.code, "")
                raise NetError(f"HTTP {e.code}{hint}: {str(detail)[:200]}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                raise NetError(f"Couldn't reach Ubiquiti: {getattr(e, 'reason', e)}") from None
        raise NetError("Ubiquiti kept rate-limiting the requests - try again in a minute.")

    def _all(self, path):
        out, token = [], None
        for _ in range(50):
            r = self._call(path, {"pageSize": "200", **({"nextToken": token} if token else {})}) or {}
            out += r.get("data") or []
            token = r.get("nextToken")
            if not token:
                break
        return out

    def _connector_map(self, host_id, sites):
        """{mac: site ext} for a console with several sites, from its Network integration API (via the cloud connector)."""
        out, base = {}, f"/v1/connector/consoles/{urllib.parse.quote(host_id)}/proxy/network/integration/v1/sites"
        try:
            ns = (self._call(base, timeout=25) or {}).get("data") or []
        except NetError:
            return out
        for n in ns:
            site = next((s for s in sites if s["internal"] == n.get("internalReference")), None) or \
                next((s for s in sites if s["name"] == n.get("name")), None)
            if not site:
                continue
            try:
                devs = (self._call(f"{base}/{urllib.parse.quote(str(n.get('id')))}/devices", {"limit": "200"}, timeout=25) or {}).get("data") or []
            except NetError:
                continue
            for d in devs:
                out[macnorm(d.get("macAddress") or d.get("mac"))] = site["ext"]
        return out

    def fetch(self):
        if self.demo:
            hosts, raw_sites, groups = _demo_unifi()
        else:
            if not self.key:
                raise NetError("This connection has no API key.")
            hosts, raw_sites, groups = self._all("/v1/hosts"), self._all("/v1/sites"), self._all("/v1/devices")
        hname = {h.get("id"): ((h.get("reportedState") or {}).get("hostname") or (h.get("reportedState") or {}).get("name") or h.get("ipAddress") or h.get("id"))
                 for h in hosts}
        for g in groups:
            hname[g.get("hostId")] = g.get("hostName") or hname.get(g.get("hostId"))
        sites = []
        for s in raw_sites:
            meta, st = s.get("meta") or {}, s.get("statistics") or {}
            c, isp, pct = st.get("counts") or {}, st.get("ispInfo") or {}, st.get("percentages") or {}
            sites.append({"ext": f"{s.get('hostId')}:{s.get('siteId')}", "host": s.get("hostId"), "name": meta.get("desc") or meta.get("name") or s.get("siteId"),
                          "internal": meta.get("name"), "console": hname.get(s.get("hostId")), "gateway_mac": macnorm(meta.get("gatewayMac")), "type": "site",
                          "stats": {"total": num(c.get("totalDevice")), "offline": num(c.get("offlineDevice")), "updates": num(c.get("pendingUpdateDevice")),
                                    "wifi_clients": num(c.get("wifiClient")), "wired_clients": num(c.get("wiredClient")), "guest_clients": num(c.get("guestClient")),
                                    "critical": num(c.get("criticalNotification")), "isp": isp.get("name") or isp.get("organization"),
                                    "wan_uptime": pct.get("wanUptime"), "internet_issues": len(st.get("internetIssues") or [])},
                          "wan_ips": public_in({"wans": st.get("wans"), "gateway": st.get("gateway")})})
        per_host = {}
        for s in sites:
            per_host.setdefault(s["host"], []).append(s)
        host_ip = {h.get("id"): public(h.get("ipAddress")) for h in hosts}
        for s in sites:   # a console with one site: its own public address is that site's (a hosted multi-site server's isn't)
            if not s["wan_ips"] and len(per_host.get(s["host"], [])) == 1 and host_ip.get(s["host"]):
                s["wan_ips"] = [host_ip[s["host"]]]
        devices = []
        for g in groups:
            hs = per_host.get(g.get("hostId"), [])
            cmap = self._connector_map(g.get("hostId"), hs) if len(hs) > 1 and not self.demo else {}
            gw = {s["gateway_mac"]: s["ext"] for s in hs if s["gateway_mac"]}
            for d in g.get("devices") or []:
                m = macnorm(d.get("mac"))
                devices.append({"ext": str(d.get("id") or m), "site_ext": hs[0]["ext"] if len(hs) == 1 else cmap.get(m) or gw.get(m),
                                "host": hname.get(g.get("hostId")) or g.get("hostId"), "mac": m, "name": d.get("name") or d.get("model") or m,
                                "model": d.get("model") or d.get("shortname"), "ip": d.get("ip"), "status": d.get("status"), "version": d.get("version"),
                                "update": d.get("updateAvailable") or None, "is_console": bool(d.get("isConsole")), "startup": d.get("startupTime")})
        return sites, devices


class UispClient:
    """A UISP server's NMS API (v2.1). Certificates are verified; a self-signed one only if its SHA-256 matches the pin."""

    def __init__(self, url, key, pin=None, demo=False):
        self.url, self.key, self.pin, self.demo = url.rstrip("/"), key, pin, demo
        u = urllib.parse.urlparse(self.url)
        self.host, self.port = u.hostname, u.port or 443

    @staticmethod
    def check_url(url):
        u = urllib.parse.urlparse(str(url or "").strip())
        if u.scheme != "https" or not u.hostname or u.username or u.password or (u.path not in ("", "/")) or u.query:
            raise ValueError("The UISP address is https://your-uisp-server (no path).")
        return f"https://{u.hostname}{f':{u.port}' if u.port else ''}"

    def public_ip(self):
        """The address to connect to - only if every address of the host is public (no localhost, LAN, link-local or
        cloud metadata), so a connection can't be pointed at TikManager's own server or network."""
        try:
            infos = socket.getaddrinfo(self.host, self.port, proto=socket.IPPROTO_TCP)
        except OSError:
            raise NetError(f"{self.host} can't be found (DNS).") from None
        ips = []
        for info in infos:
            ip = info[4][0].split("%")[0]
            if not ipaddress.ip_address(ip).is_global:
                raise NetError(f"{self.host} points to a private / local address - the UISP server must be reachable on the internet.")
            if ip not in ips:
                ips.append(ip)
        return sorted(ips, key=lambda ip: ":" in ip)   # IPv4 first: many servers have no working IPv6 route

    def _sock(self, ips, timeout):
        """Connect to the first of the checked addresses that answers; say which ones didn't."""
        tried = []
        for ip in ips:
            try:
                return socket.create_connection((ip, self.port), timeout=min(timeout, 12))
            except OSError as e:
                tried.append(f"{ip}:{self.port} ({'timed out' if isinstance(e, TimeoutError) or 'timed out' in str(e) else e})")
        raise NetError(f"Couldn't reach the UISP server {self.host}: {'; '.join(tried)}. If {self.host} works in a browser, TikManager's server can't "
                       "reach that address - check its outbound firewall, any allowlist in front of UISP, or (if UISP is on the same network as "
                       "TikManager) hairpin NAT.")

    def fingerprint(self):
        """SHA-256 of the server's certificate (to pin a self-signed one), read without trusting it."""
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with self._sock(self.public_ip(), 15) as raw, ctx.wrap_socket(raw, server_hostname=self.host) as s:
                return hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
        except OSError as e:
            raise NetError(f"Couldn't reach the UISP server: {e}") from None

    def _call(self, path, timeout=30):
        if self.pin:   # pinned: accept exactly this certificate, nothing else
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=ctx)
        try:
            ip = self.public_ip()   # checked once, then connected to directly (a second DNS answer can't redirect it)
            conn.sock = ctx.wrap_socket(self._sock(ip, timeout), server_hostname=self.host)
            if self.pin and hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != self.pin:
                raise NetError("The UISP server's certificate has changed since it was trusted - check it, then save the connection again to trust the new one.")
            conn.request("GET", f"/nms/api/v2.1{path}", headers={"x-auth-token": self.key, "Accept": "application/json"})
            r = conn.getresponse()
            body = r.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise NetError("The UISP server sent more data than TikManager accepts.")
            if r.status >= 400:
                hint = {401: " (check the API token)", 403: " (the token can't read this)"}.get(r.status, "")
                raise NetError(f"HTTP {r.status}{hint}")   # not the body: it could be anything
            return json.loads(body or b"null")
        except ssl.SSLCertVerificationError:
            raise NetError("The UISP server's certificate isn't trusted - if it's self-signed, tick \"Trust this server's certificate\".") from None
        except (OSError, http.client.HTTPException) as e:
            raise NetError(f"Couldn't reach the UISP server: {e}") from None
        finally:
            conn.close()

    def fetch(self):
        raw_sites, raw_devs = _demo_uisp() if self.demo else (self._call("/sites") or [], self._call("/devices") or [])
        sites = []
        for s in raw_sites:
            ident = s.get("identification") or {}
            sid = s.get("id") or ident.get("id")
            if not sid:
                continue
            desc = s.get("description") or {}
            sites.append({"ext": str(sid), "name": ident.get("name") or str(sid), "internal": ident.get("name"), "console": None, "gateway_mac": "",
                          "type": "endpoint" if ident.get("type") == "endpoint" else "site", "stats": {"address": desc.get("address")}, "wan_ips": []})
        devices = []
        for d in raw_devs:
            ident, ov, fw = d.get("identification") or {}, d.get("overview") or {}, d.get("firmware") or {}
            cur = ident.get("firmwareVersion") or fw.get("current")
            latest = fw.get("latest") if fw.get("latest") and fw.get("latest") != cur and fw.get("compatible", True) else None
            up = num(ov.get("uptime"))
            site_id = str((ident.get("site") or {}).get("id") or "")
            pubs = [p for p in (public(d.get("ipAddress")), *[public(x) for x in (d.get("ipAddressList") or [])[:10] if isinstance(x, str)]) if p]
            for s in sites:
                if s["ext"] == site_id:
                    s["wan_ips"] += [p for p in pubs if p not in s["wan_ips"]]
            devices.append({"ext": str(ident.get("id") or ident.get("mac")), "site_ext": str((ident.get("site") or {}).get("id") or "") or None,
                            "host": None, "mac": macnorm(ident.get("mac")), "name": ident.get("displayName") or ident.get("name") or ident.get("hostname") or ident.get("mac"),
                            "model": ident.get("modelName") or ident.get("model"), "ip": str(d.get("ipAddress") or "").split("/")[0] or None,
                            "status": "online" if online(ov.get("status")) else (ov.get("status") or "offline"), "version": cur, "update": latest,
                            "is_console": False, "startup": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - up)) if up else None})
        return sites, devices


# --- connections + sync -------------------------------------------------------------------------------------------------------
class Ubnt:
    def __init__(self, db, vault, settings):
        self.db, self.vault, self.s = db, vault, settings
        global ALLOW_DOC
        ALLOW_DOC = bool(settings.dev)
        self.state = {"running": False}
        self.lock = threading.Lock()

    # connections
    def _secret(self, a):
        try:
            blob = json.loads(a.get("secret") or "null")
            return json.loads(self.vault.open(base64.b64decode(blob["data"]), blob["enc"], f"netacct:{a['id']}")) if blob else {}
        except Exception:  # noqa: BLE001 - unreadable (master key replaced): treat as no key
            return {}

    def accounts(self):
        rows = self.db.q("SELECT a.*, o.name AS org FROM net_accounts a LEFT JOIN orgs o ON o.id = a.org_id ORDER BY a.name")
        out = []
        for a in rows:
            sec = self._secret(a)
            out.append({"id": a["id"], "kind": a["kind"], "name": a["name"], "url": a["url"], "org_id": a["org_id"], "org": a["org"],
                        "key_set": bool(sec.get("key")), "pinned": bool(sec.get("pin")), "last": json.loads(a["last"] or "null"),
                        "sites": (self.db.one("SELECT COUNT(*) n FROM net_sites WHERE account_id=?", (a["id"],)) or {}).get("n", 0)})
        return out

    def save(self, aid, kind, name, url, key, org_id, trust_cert=False):
        if kind not in KINDS:
            raise ValueError("Pick UniFi or UISP.")
        name = str(name or "").strip()[:80] or KINDS[kind]
        old = self.db.one("SELECT * FROM net_accounts WHERE id=?", (aid,)) if aid else None
        if aid and not old:
            raise ValueError("Connection not found.")
        sec = self._secret(old) if old else {}
        if key:
            sec["key"] = str(key).strip()[:500]
        if not sec.get("key"):
            raise ValueError("Paste the API key." if kind == "unifi" else "Paste the UISP API token.")
        url = UispClient.check_url(url) if kind == "uisp" else None
        if kind == "uisp" and not (self.s.dev and sec["key"] == "demo"):
            uc = UispClient(url, sec["key"])
            uc.public_ip()   # refuse localhost / LAN / link-local addresses before saving anything
            sec["pin"] = uc.fingerprint() if trust_cert else None
        if old:
            self.db.run("UPDATE net_accounts SET kind=?, name=?, url=?, org_id=? WHERE id=?", (kind, name, url, org_id, aid))
        else:
            aid = self.db.run("INSERT INTO net_accounts (kind, name, url, org_id, created_at) VALUES (?,?,?,?,?)", (kind, name, url, org_id, time.time()))
        blob, enc = self.vault.seal(json.dumps(sec).encode(), f"netacct:{aid}")
        self.db.run("UPDATE net_accounts SET secret=? WHERE id=?", (json.dumps({"data": base64.b64encode(blob).decode(), "enc": enc}), aid))
        if org_id:   # a client's own account: everything in it is theirs
            self.db.run("UPDATE net_sites SET org_id=? WHERE account_id=?", (org_id, aid))
        return aid

    def delete(self, aid):
        self.db.run("DELETE FROM net_devices WHERE account_id=?", (aid,))
        self.db.run("DELETE FROM net_sites WHERE account_id=?", (aid,))
        self.db.run("DELETE FROM net_accounts WHERE id=?", (aid,))

    def client(self, a):
        sec = self._secret(a)
        demo = self.s.dev and sec.get("key") == "demo"
        if a["kind"] == "unifi":
            return UnifiClient(sec.get("key") or "", demo)
        return UispClient(a["url"] or "https://uisp.invalid", sec.get("key") or "", sec.get("pin"), demo)

    def test(self, aid):
        a = self.db.one("SELECT * FROM net_accounts WHERE id=?", (aid,))
        if not a:
            raise NetError("Connection not found.")
        sites, devs = self.client(a).fetch()
        return f"Connected: {len(sites)} sites, {len(devs)} devices."

    # sync
    def sync_account(self, a, who="schedule"):
        now = time.time()
        try:
            sites, devs = self.client(a).fetch()
            from integrations import norm
            by_name = {norm(o["name"]): o["id"] for o in self.db.q("SELECT id, name FROM orgs WHERE active=1")}
            by_ip = {}   # routers' WAN / public addresses -> (client, router)
            for r in self.db.q("SELECT name, org_id, wan_ip, public_ip FROM devices WHERE state='adopted' AND org_id IS NOT NULL"):
                for ip in (public(r["wan_ip"]), public(r["public_ip"])):
                    if ip:
                        by_ip.setdefault(ip, (r["org_id"], r["name"]))
            if len(sites) > MAX_SITES or len(devs) > MAX_DEVICES:
                raise NetError(f"Too many sites / devices ({len(sites)} / {len(devs)}) - TikManager reads up to {MAX_SITES} / {MAX_DEVICES} per connection.")
            for s in sites:
                for k in ("ext", "name", "internal", "console", "type"):
                    s[k] = txt(s.get(k))
                s["gateway_mac"] = macnorm(s.get("gateway_mac"))[:12]
                s["stats"] = {k: (v if isinstance(v, (int, float)) and not isinstance(v, bool) else txt(v)) for k, v in (s.get("stats") or {}).items()}
                if not s["ext"]:
                    continue
                key = f"{a['id']}:{s['ext']}"
                ips = [ip for ip in (s.get("wan_ips") or []) if public(ip)][:5]
                wan = ips[0] if ips else None
                old = self.db.one("SELECT org_id, org_manual, matched FROM net_sites WHERE id=?", (key,))
                ipm = next(((by_ip[ip], ip) for ip in ips if ip in by_ip), None)
                if a["org_id"]:
                    org, why, manual = a["org_id"], "the client's own connection", 0
                elif old and old["org_manual"]:
                    org, why, manual = old["org_id"], old["matched"], 1
                elif ipm:   # the strongest evidence: same public address as one of the client's routers
                    (org, router), ip = ipm
                    why, manual = f"Public IP {ip} = router {router}", 0
                elif old and old["org_id"]:
                    org, why, manual = old["org_id"], old["matched"] or "name", 0
                else:
                    org = by_name.get(norm(s["name"])) or by_name.get(norm(s["console"]))
                    why, manual = ("name" if org else None), 0
                vals = (a["id"], s["name"], s["internal"], s["console"], s["gateway_mac"], s["type"], org, json.dumps(s["stats"]), now, wan, why, manual)
                if old:
                    self.db.run("""UPDATE net_sites SET account_id=?, name=?, internal=?, console=?, gateway_mac=?, type=?, org_id=?, stats=?, seen_at=?,
                                   wan_ip=?, matched=?, org_manual=? WHERE id=?""", (*vals, key))
                else:
                    self.db.run("""INSERT INTO net_sites (account_id, name, internal, console, gateway_mac, type, org_id, stats, seen_at, wan_ip, matched,
                                   org_manual, id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*vals, key))
            for d in devs:
                for k in ("ext", "site_ext", "host", "name", "model", "ip", "status", "version", "update", "startup"):
                    d[k] = txt(d.get(k))
                d["mac"] = macnorm(d.get("mac"))[:12]
                if not d["ext"]:
                    continue
                did = f"{a['id']}:{d['ext']}"
                prev = self.db.one("SELECT offline_since FROM net_devices WHERE id=?", (did,))
                off = None if online(d["status"]) else ((prev or {}).get("offline_since") or now)
                vals = (a["id"], f"{a['id']}:{d['site_ext']}" if d["site_ext"] else None, d["host"], d["mac"], d["name"], d["model"], d["ip"], d["status"],
                        d["version"], d["update"], int(d["is_console"]), d["startup"], off, now)
                if prev is not None:
                    self.db.run("""UPDATE net_devices SET account_id=?, site_key=?, host=?, mac=?, name=?, model=?, ip=?, status=?, version=?, update_available=?,
                                   is_console=?, startup_time=?, offline_since=?, updated_at=? WHERE id=?""", (*vals, did))
                else:
                    self.db.run("""INSERT INTO net_devices (account_id, site_key, host, mac, name, model, ip, status, version, update_available, is_console,
                                   startup_time, offline_since, updated_at, id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*vals, did))
            # gone from the account for a day: drop them
            self.db.run("DELETE FROM net_devices WHERE account_id=? AND updated_at < ?", (a["id"], now - 86400))
            self.db.run("DELETE FROM net_sites WHERE account_id=? AND seen_at < ?", (a["id"], now - 86400))
            last = {"ok": True, "at": now, "detail": f"{len(sites)} sites, {len(devs)} devices", "by": who}
        except NetError as e:
            last = {"ok": False, "at": now, "detail": str(e), "by": who}
        except Exception as e:  # noqa: BLE001 - one broken connection must not stop the others
            traceback.print_exc()
            last = {"ok": False, "at": now, "detail": f"{type(e).__name__}: {e}", "by": who}
        self.db.run("UPDATE net_accounts SET last=? WHERE id=?", (json.dumps(last), a["id"]))
        return last

    def sync(self, who="schedule", aid=None):
        if not self.lock.acquire(blocking=False):
            return None
        self.state["running"] = True
        try:
            rows = self.db.q("SELECT * FROM net_accounts" + (" WHERE id=?" if aid else ""), (aid,) if aid else ())
            return [self.sync_account(a, who) for a in rows]
        finally:
            self.state["running"] = False
            self.lock.release()

    def loop(self):
        time.sleep(20)
        while True:
            try:
                self.sync()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(SYNC_SECONDS)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="ubnt-sync").start()

    # reading (pages, alerts)
    def sites(self, where="1=1", args=()):
        rows = self.db.q(f"""SELECT s.*, o.name AS org, a.name AS account, a.kind, a.org_id AS account_org FROM net_sites s
                             JOIN net_accounts a ON a.id = s.account_id LEFT JOIN orgs o ON o.id = s.org_id WHERE {where}
                             ORDER BY o.name, s.name""", args)
        devs = self.db.q("SELECT site_key, status, update_available, offline_since FROM net_devices WHERE site_key IS NOT NULL")
        by = {}
        for d in devs:
            by.setdefault(d["site_key"], []).append(d)
        out = []
        for r in rows:
            st, mine = json.loads(r["stats"] or "{}"), by.get(r["id"], [])
            off = [d for d in mine if not online(d["status"])]
            out.append({"id": r["id"], "name": r["name"], "internal": r["internal"], "console": r["console"], "type": r["type"], "kind": r["kind"],
                        "account": r["account"], "own_account": bool(r["account_org"]), "org_id": r["org_id"], "org": r["org"],
                        "devices": len(mine) if mine else st.get("total") or 0, "offline": len(off) if mine else st.get("offline") or 0,
                        "updates": sum(1 for d in mine if d["update_available"]) if mine else st.get("updates") or 0,
                        "offline_since": min([d["offline_since"] for d in off if d["offline_since"]], default=None),
                        "wifi_clients": st.get("wifi_clients"), "wired_clients": st.get("wired_clients"), "isp": st.get("isp"),
                        "wan_uptime": st.get("wan_uptime"), "internet_issues": st.get("internet_issues") or 0, "address": st.get("address"),
                        "seen_at": r["seen_at"], "wan_ip": r["wan_ip"], "matched": r["matched"], "manual": bool(r["org_manual"])})
        return out

    def devices(self, site_key):
        return self.db.q("""SELECT id, name, model, mac, ip, status, version, update_available, is_console, startup_time, offline_since
                            FROM net_devices WHERE site_key=? ORDER BY is_console DESC, name""", (site_key,))

    def known_for_org(self, org_id):
        """{mac: device} for the UniFi / UISP devices of one client's sites - what the network map tags and adds."""
        if not org_id:
            return {}
        rows = self.db.q("""SELECT d.mac, d.name, d.model, d.ip, d.status, d.version, d.update_available, d.is_console, s.id AS site_id, s.name AS site,
                            a.kind FROM net_devices d JOIN net_sites s ON s.id = d.site_key JOIN net_accounts a ON a.id = d.account_id
                            WHERE s.org_id = ? AND d.mac IS NOT NULL AND d.mac != ''""", (org_id,))
        return {r["mac"]: {"source": KINDS.get(r["kind"], r["kind"]), "platform": KINDS.get(r["kind"], r["kind"]), "name": r["name"], "model": r["model"],
                           "ip": r["ip"], "status": "online" if online(r["status"]) else (r["status"] or "offline"), "version": r["version"],
                           "update": r["update_available"], "console": bool(r["is_console"]), "site": r["site"], "site_id": r["site_id"]} for r in rows}

    def unplaced(self):
        return self.db.q("""SELECT d.id, d.name, d.model, d.mac, d.ip, d.status, d.version, d.update_available, d.host AS console, a.name AS account
                            FROM net_devices d JOIN net_accounts a ON a.id = d.account_id WHERE d.site_key IS NULL ORDER BY a.name, d.host, d.name""")

    def conditions(self, minutes):
        """One alert per site with devices offline for `minutes` (alerts.py)."""
        out, limit = {}, time.time() - minutes * 60
        for s in self.sites():
            if s["offline"] and s["offline_since"] and s["offline_since"] < limit:
                names = [plain(d["name"]) for d in self.devices(s["id"]) if not online(d["status"])]
                plat = KINDS.get(s["kind"], "")
                where = plain(s["account"]) + (f" / console {plain(s['console'])}" if s["console"] else "")
                more = " ..." if len(names) > 20 else ""
                out[f"net:{s['id']}"] = ("unifi", None, s["org_id"], f"{plat} {plain(s['name'])}: {s['offline']} device{'s' if s['offline'] != 1 else ''} offline",
                                         f"{where}. Offline: {', '.join(names[:20])}{more}")
        return out


# --- demo data (dev mode, key "demo") ------------------------------------------------------------------------------------------
def _demo_unifi():
    r = random.Random(7)
    hosts = [{"id": f"demo-host-{i}", "ipAddress": ip, "reportedState": {"hostname": n}}
             for i, (n, ip) in enumerate([("Northwind-UCG", "203.0.113.3"), ("AcmeDental-UDM", "198.51.100.11"), ("MSP-Hosted-Network", "198.51.100.12")])]

    def stats(total, off, upd, wifi, wired, isp):
        return {"counts": {"totalDevice": total, "offlineDevice": off, "pendingUpdateDevice": upd, "wifiClient": wifi, "wiredClient": wired,
                           "guestClient": r.randint(0, 6), "criticalNotification": 0},
                "ispInfo": {"name": isp}, "percentages": {"wanUptime": round(r.uniform(97.5, 100), 2)}, "internetIssues": []}
    sites = [{"siteId": "s-nw", "hostId": "demo-host-0", "meta": {"name": "default", "desc": "Northwind Clinics", "gatewayMac": "70:a7:41:00:00:01"}, "statistics": stats(6, 1, 2, 31, 12, "Cox Business")},
             {"siteId": "s-acme", "hostId": "demo-host-1", "meta": {"name": "default", "desc": "Acme Dental", "gatewayMac": "70:a7:41:00:01:01"}, "statistics": stats(4, 0, 0, 14, 6, "Spectrum")},
             {"siteId": "s-h1", "hostId": "demo-host-2", "meta": {"name": "a1b2c3", "desc": "Bluewater Library", "gatewayMac": "70:a7:41:00:02:01"},
              "statistics": {**stats(3, 0, 1, 22, 3, "AT&T"), "wans": {"WAN": {"externalIp": "203.0.113.5"}}}},
             {"siteId": "s-h2", "hostId": "demo-host-2", "meta": {"name": "d4e5f6", "desc": "Harbor Insurance", "gatewayMac": "70:a7:41:00:03:01"}, "statistics": stats(2, 0, 0, 8, 4, "Lumen")}]

    def dev(h, k, name, model, console=False, status="online", upd=None):
        return {"id": f"d-{h}-{k}", "mac": f"70:a7:41:00:{h:02x}:{k:02x}", "name": name, "model": model, "ip": f"192.168.{h}.{k}", "status": status,
                "version": "7.0.23", "updateAvailable": upd, "isConsole": console, "startupTime": "2026-09-30T11:02:00Z"}
    groups = [{"hostId": "demo-host-0", "hostName": "Northwind-UCG", "devices": [dev(0, 1, "Northwind-UCG", "UCG Ultra", True), dev(0, 2, "Front desk switch", "USW Lite 16 PoE", upd="7.1.26"),
                                                                               dev(0, 3, "Lobby AP", "U6 Pro"), dev(0, 4, "Exam rooms AP", "U6 Lite", upd="6.6.77"),
                                                                               dev(0, 5, "Back office AP", "U6 Lite", status="offline"), dev(0, 6, "Server room switch", "USW 24")]},
              {"hostId": "demo-host-1", "hostName": "AcmeDental-UDM", "devices": [dev(1, 1, "AcmeDental-UDM", "UDM Pro", True), dev(1, 2, "Main switch", "USW Pro 24 PoE"),
                                                                                dev(1, 3, "Operatory AP", "U7 Pro"), dev(1, 4, "Waiting room AP", "U6+")]},
              {"hostId": "demo-host-2", "hostName": "MSP-Hosted-Network", "devices": [dev(2, 1, "Library gateway", "UXG Lite"), dev(2, 2, "Library AP 1", "U6 LR", upd="6.6.77"),
                                                                                    dev(2, 3, "Library AP 2", "U6 LR"), dev(3, 1, "Harbor gateway", "UXG Pro"), dev(3, 2, "Harbor AP", "U6 Mesh")]}]
    return hosts, sites, groups


def _demo_uisp():
    sites = [{"id": "u-tower", "identification": {"id": "u-tower", "name": "Main tower", "type": "site"}, "description": {"address": "1200 Ridge Rd"}},
             {"id": "u-farm", "identification": {"id": "u-farm", "name": "Miller Farm", "type": "endpoint"}, "description": {"address": "18 County Rd 4"}}]

    def dev(i, name, model, site, status="active", cur="v8.7.11", latest=None, up=864000):
        return {"identification": {"id": f"ud-{i}", "mac": f"24:5a:4c:00:00:{i:02x}", "displayName": name, "modelName": model, "site": {"id": site},
                                   "firmwareVersion": cur}, "overview": {"status": status, "uptime": up}, "firmware": {"current": cur, "latest": latest or cur, "compatible": True},
                "ipAddress": f"10.20.0.{i}/24"}
    return sites, [dev(1, "Tower router", "EdgeRouter 6P", "u-tower", cur="v2.0.9", latest="v2.0.9-hotfix.7"), dev(2, "Sector north", "LiteAP AC", "u-tower"),
                   dev(3, "Sector south", "LiteAP AC", "u-tower", latest="v8.7.15"), dev(4, "Miller Farm CPE", "LiteBeam 5AC Gen2", "u-farm", status="disconnected", up=None)]
