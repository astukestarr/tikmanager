"""Talks to a router over its WireGuard tunnel with the RouterOS v7 REST API (http://<tunnel ip>/rest/...).
Plain HTTP is fine here: the traffic never leaves the encrypted WireGuard tunnel, and the router only accepts it from the
controller's tunnel address.

SimRouter stands in for real routers in dev mode (TM_DEV=1) so the whole app can be built and tested without hardware.
"""
import base64
import copy
import json
import math
import random
import time
import hashlib
import http.client
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

VPN_TAG = "TikManager VPN"   # comment on every object the site-to-site VPN adds, so it can be removed exactly
VPN_IFACE = "tikmanager-vpn"
RA_IFACE = "tikmanager-ra"   # remote access (remoteaccess.py): people connecting in with WireGuard for Windows etc.
RA_TAG = "TikManager remote access"   # comment on everything remote access adds (peers: "TikManager remote access: <name>")


class RouterError(Exception):
    pass


class NoConnection(RouterError):
    """The connection couldn't be opened (refused, TLS handshake, connect timeout) - so the request never reached the
    router and is safe to send again another way."""


class CutOff(RouterError):
    """The router's answer stopped part-way (seen on large answers - a backup's export - over www-ssl)."""


# HTTPS to the router runs inside TikManager's WireGuard tunnel, where the router is already authenticated by its
# WireGuard key - the certificate (often self-signed, or the client's own and renewed now and then) isn't verified;
# TLS adds encryption on the router's side and lets WebFig over plain HTTP be switched off.
TLS = ssl.create_default_context()
TLS.check_hostname, TLS.verify_mode = False, ssl.CERT_NONE
HTTPS_CERT = "tikmanager-https"
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
TLS_PORTS = (8443, 9443, 10443, 18443)   # for www-ssl when 443 is taken (SSTP, another service)


def _yes(v):
    return str(v).lower() in ("true", "yes")


def _covers(addr_list, ip):
    import ipaddress
    for a in str(addr_list or "").split(","):
        try:
            if a.strip() and ipaddress.ip_address(ip) in ipaddress.ip_network(a.strip(), strict=False):
                return True
        except ValueError:
            pass
    return False


class RouterOS:
    def __init__(self, ip, user, password, timeout=8, port=80, tls_port=None):
        self.ip = ip
        self.base = f"http://{ip}/rest" if int(port) == 80 else f"http://{ip}:{int(port)}/rest"
        self.tls_base = f"https://{ip}:{int(tls_port)}/rest" if tls_port else None
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.timeout = timeout
        self.fell_back = False     # HTTPS didn't connect, this client carries on over HTTP
        self.on_fallback = None    # poller: record it (once in a while) and avoid HTTPS for a few minutes
        self.tls_only = False      # no HTTP fallback (proving HTTPS alone works before WebFig over HTTP goes off)

    def _send(self, base, method, path, body, timeout, ctx):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=ctx) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            if e.code == 401:
                raise RouterError("The router refused TikManager's login (was the tikmanager user changed?)") from None
            raise RouterError(f"HTTP {e.code}: {detail}") from None
        except urllib.error.URLError as e:   # urllib wraps only failures while connecting / sending - never a request the router ran
            raise NoConnection(f"Unreachable over the tunnel: {getattr(e, 'reason', e)}") from None
        except http.client.IncompleteRead as e:
            raise CutOff(f"The router's answer was cut off ({len(e.partial)} bytes arrived, {e.expected} more expected)") from None
        except (TimeoutError, OSError, http.client.HTTPException) as e:
            raise RouterError(f"Unreachable over the tunnel: {getattr(e, 'reason', e)}") from None

    def _req(self, method, path, body=None, timeout=None, safe=False):
        """safe: a read that changes nothing (GETs always), so an answer cut off over HTTPS may be asked for again."""
        safe = safe or method == "GET"
        if self.tls_base and not self.fell_back:
            try:
                return self._send(self.tls_base, method, path, body, timeout, TLS)
            except NoConnection as e:   # HTTPS isn't answering (service off, port or certificate changed): HTTP, if it's still on
                if self.tls_only:
                    raise
                self.fell_back = True
                if self.on_fallback:
                    self.on_fallback(str(e))
            except CutOff as e:
                if not safe:
                    raise
                try:   # once more over HTTPS, then this one read over HTTP
                    return self._send(self.tls_base, method, path, body, timeout, TLS)
                except CutOff:
                    if self.tls_only:
                        raise
                    if self.on_fallback:
                        self.on_fallback(f"{e} - this read went over HTTP")
        return self._send(self.base, method, path, body, timeout, None)

    def get(self, path):
        return self._req("GET", path)

    BGP_SESSION = ("name", "remote.address", "remote.as", "established", "uptime", "prefix-count", "local.role")
    ROUTING = {   # router page > Routing, read live - menu: fields kept (whitelist)
        "ospf_instances": ("/routing/ospf/instance", ("name", "version", "router-id", "disabled")),
        "ospf_areas": ("/routing/ospf/area", ("name", "area-id", "instance", "type", "disabled")),
        "ospf_neighbors": ("/routing/ospf/neighbor", ("instance", "area", "address", "router-id", "state", "adjacency", "state-changes", "interface")),
        "rip_instances": ("/routing/rip/instance", ("name", "disabled")),
        "rip_neighbors": ("/routing/rip/neighbor", ("instance", "address", "routes", "packets-total", "bad-packets", "timeout")),
    }
    ROUTE_FLAGS = ("static", "connect", "bgp", "ospf", "rip", "dhcp", "vpn", "modem", "copy")
    ROUTE_LIMIT = 5000   # above this many BGP prefixes the route table isn't listed (a full table is far too big to read)

    def routing(self, bgp_prefixes=0):
        """Router page > Routing: OSPF and RIP instances / neighbors, and active routes counted by protocol (plus the
        default routes) - unless BGP brings in more than ROUTE_LIMIT prefixes."""
        out = {}
        for key, (menu, keep) in self.ROUTING.items():
            rows = self.optional(lambda menu=menu: self.get(menu), []) or []
            out[key] = [{k: r[k] for k in keep if k in r} for r in rows if isinstance(r, dict)]
        if bgp_prefixes > self.ROUTE_LIMIT:
            out["routes"] = {"skipped": f"BGP brings in {bgp_prefixes:,} prefixes - the route table isn't listed here."}
            return out
        rows = self.optional(lambda: self.get("/ip/route?active=true&.proplist=dst-address,gateway,distance,routing-table," + ",".join(self.ROUTE_FLAGS)), []) or []
        counts, defaults = {}, []
        for r in rows if isinstance(rows, list) else []:
            kind = next((f for f in self.ROUTE_FLAGS if str(r.get(f)).lower() == "true"), "other")
            counts[kind] = counts.get(kind, 0) + 1
            if r.get("dst-address") in ("0.0.0.0/0", "::/0"):
                defaults.append({"gateway": r.get("gateway", ""), "distance": r.get("distance", ""), "kind": kind, "table": r.get("routing-table", "")})
        out["routes"] = {"active": sum(counts.values()), "by_kind": counts, "defaults": defaults}
        return out

    def bgp_sessions(self):
        """Live BGP sessions (/routing/bgp/session) - whitelisted fields. Raises RouterError if the router can't be read."""
        rows = self.get("/routing/bgp/session") or []
        return [{k: r[k] for k in self.BGP_SESSION if k in r} for r in rows if isinstance(r, dict)]

    def reachable(self):
        """Raises RouterError unless the router answers over the tunnel now (strict - unlike optional() reads)."""
        self._req("GET", "/system/identity", timeout=10)
        return True

    # --- HTTPS for TikManager's own management connection ----------------------------------------------------------
    def https_setup(self, tm_ip):
        """Get www-ssl ready for TikManager without disturbing anyone using it: keep its certificate and port if it has
        them (a self-signed "tikmanager-https" certificate only when it has none; port 443 moves to 8443... only when
        SSTP or another service holds 443), and make sure it isn't open to the world - TikManager's tunnel address only if
        the service was off, the private ranges + TikManager if it was open to everyone, else the existing list + TikManager.
        Returns what to connect to and what to put back (https_revert)."""
        svcs = [x for x in self.get("/ip/service") or [] if not _yes(x.get("dynamic")) and not _yes(x.get("connection"))]   # 7.20+: no connection rows
        s = next((x for x in svcs if x.get("name") == "www-ssl"), None)
        if not s:
            raise RouterError("This router has no www-ssl service.")
        prop = "available-from" if "available-from" in s else "address"
        was_off = _yes(s.get("disabled"))
        port = int(s.get("port") or 443)
        prev = {"id": s[".id"], "prop": prop, "addr": s.get(prop) or "", "disabled": "yes" if was_off else "no",
                "certificate": s.get("certificate") or "none", "port": str(port)}
        body, created = {}, False
        cert = s.get("certificate") or "none"
        if cert == "none":
            signed = lambda c: bool(c.get("fingerprint")) or _yes(c.get("private-key"))
            tpl = (self.get(f"/certificate?name={HTTPS_CERT}") or [None])[0]
            if tpl and not signed(tpl):   # an unsigned template from an earlier try (made without key-cert-sign): start again
                self._req("DELETE", f"/certificate/{tpl['.id']}", timeout=15)
                tpl = None
            if not tpl:
                self._req("PUT", "/certificate", {"name": HTTPS_CERT, "common-name": self.ip, "key-size": "2048", "days-valid": "3650",
                                                  "key-usage": "digital-signature,key-encipherment,key-cert-sign,tls-server"}, timeout=30)   # key-cert-sign:
                # it signs itself - without it RouterOS looks for a separate CA ("failure: CA not found")
                created = True
            if not tpl or not signed(tpl):
                # sign with the terminal command (/execute, like the backups' export) - its output carries the router's message
                out = ""
                try:
                    r = self._req("POST", "/execute", {"script": f"/certificate sign {HTTPS_CERT}", "as-string": ""}, timeout=120)
                    out = str((r or {}).get("ret") or "") if isinstance(r, dict) else ""
                except RouterError as e:
                    if "HTTP" in str(e):
                        out = str(e)
                ok = False
                if "failure" not in out.lower() and "error" not in out.lower():
                    for _ in range(90):   # signing a 2048-bit key takes a while on small routers
                        c = (self.get(f"/certificate?name={HTTPS_CERT}") or [{}])[0]
                        if signed(c):
                            ok = True
                            break
                        time.sleep(1)
                if not ok:   # don't leave a half-made certificate behind
                    for c in self.get(f"/certificate?name={HTTPS_CERT}") or []:
                        if not signed(c):
                            self.optional(lambda c=c: self._req("DELETE", f"/certificate/{c['.id']}", timeout=15))
                    raise RouterError("The router couldn't make its HTTPS certificate" + (f": {out.strip()[:200]}" if out.strip() else
                                      " in time - try again in a minute") + ". Nothing was changed.")
            body["certificate"] = cert = HTTPS_CERT
        if was_off and port == 443:   # turning it on: don't collide with SSTP (or anything else) on 443
            used = {int(x.get("port") or 0) for x in svcs if x.get("name") != "www-ssl" and not _yes(x.get("disabled"))}
            sstp = self.optional(lambda: self.get("/interface/sstp-server/server"), {}) or {}
            sstp = sstp[0] if isinstance(sstp, list) and sstp else sstp if isinstance(sstp, dict) else {}
            if _yes(sstp.get("enabled")):
                used.add(int(sstp.get("port") or 443))
            if 443 in used:
                port = next(p for p in TLS_PORTS if p not in used)
                body["port"] = str(port)
        addr = s.get(prop) or ""
        want = f"{tm_ip}/32" if was_off else ",".join(list(PRIVATE) + [f"{tm_ip}/32"]) if not addr else \
            addr if _covers(addr, tm_ip) else f"{addr},{tm_ip}/32"
        if want != addr:
            body[prop] = want
        if was_off:
            body["disabled"] = "no"
        if body:
            self._req("PATCH", f"/ip/service/{s['.id']}", body, timeout=15)
        return {"port": port, "cert": cert, "created_cert": created, "prev": prev, "allowed": want, "changed": body}

    def https_test(self, port):
        """Fetch the identity over HTTPS only (no fallback). Returns the certificate's SHA-256 fingerprint."""
        self._send(f"https://{self.ip}:{int(port)}/rest", "GET", "/system/identity", None, 20, TLS)
        try:
            pem = ssl.get_server_certificate((self.ip, int(port)), timeout=10)
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        except (OSError, ValueError):
            return ""

    def https_revert(self, info):
        """Put www-ssl back exactly as https_setup found it (and remove a certificate it made)."""
        p = info["prev"]
        self._req("PATCH", f"/ip/service/{p['id']}", {p["prop"]: p["addr"], "disabled": p["disabled"], "certificate": p["certificate"],
                                                     "port": p["port"]}, timeout=15)
        if info.get("created_cert"):
            for c in self.get(f"/certificate?name={HTTPS_CERT}") or []:
                self._req("DELETE", f"/certificate/{c['.id']}", timeout=15)

    def post(self, path, body):
        return self._req("POST", path, body, timeout=15)

    def optional(self, fn, default=None):
        """Menus that may not exist on this router (no wireless, no LTE, CHR without routerboard ...)."""
        try:
            return fn()
        except RouterError:
            return default

    def status(self) -> dict:
        res = self.get("/system/resource") or {}
        ident = (self.get("/system/identity") or {}).get("name")
        rb = self.optional(lambda: self.get("/system/routerboard"), {}) or {}
        ifaces = self.get("/interface") or []
        names = [i.get("name") for i in ifaces if i.get("name") and i.get("disabled") != "true"]
        # live rates for every interface in one call (like Cloutik's monitor-traffic loop)
        live = {m.get("name"): m for m in (self.optional(lambda: self.post("/interface/monitor-traffic",
                {"interface": ",".join(names), "once": ""}), []) or [])} if names else {}
        eth = {e.get("name"): e for e in self.optional(lambda: self.get("/interface/ethernet"), []) or []}
        eth_mon = {m.get("name"): m for m in (self.optional(lambda: self.post("/interface/ethernet/monitor",
                   {"numbers": ",".join(eth), "once": ""}), []) or [])} if eth else {}
        vlans = {v.get("name"): v for v in self.optional(lambda: self.get("/interface/vlan"), []) or []}
        wifi = {w.get("name"): w for w in (self.optional(lambda: self.get("/interface/wifi"), []) or [])
                + (self.optional(lambda: self.get("/interface/wireless"), []) or [])}
        lte = {lt.get("name"): lt for lt in self.optional(lambda: self.get("/interface/lte"), []) or []}
        lte_mon = {}
        for n in lte:
            m = self.optional(lambda n=n: self.post("/interface/lte/monitor", {"numbers": n, "once": ""}), [])
            lte_mon[n] = (m[0] if isinstance(m, list) and m else m) or {}
        out = []
        for i in ifaces:
            n = i.get("name")
            row = {"name": n, "type": i.get("type"), "running": i.get("running") == "true", "disabled": i.get("disabled") == "true",
                   "rx": int(i.get("rx-byte") or 0), "tx": int(i.get("tx-byte") or 0), "comment": i.get("comment") or "",
                   "mac": i.get("mac-address") or "", "mtu": i.get("actual-mtu") or i.get("mtu") or "",
                   "rx_bps": _num(live.get(n, {}).get("rx-bits-per-second")), "tx_bps": _num(live.get(n, {}).get("tx-bits-per-second"))}
            if n in eth:
                row["speed"] = eth_mon.get(n, {}).get("rate") or eth[n].get("speed") or ""
                em = eth_mon.get(n, {})
                if em.get("sfp-rx-power") not in (None, ""):   # fibre module: optical levels (dBm), temperature, supply voltage
                    num = lambda k: _num(str(em.get(k) or "").rstrip("CVdBm% "))
                    row["sfp"] = {"rx": num("sfp-rx-power"), "tx": num("sfp-tx-power"), "temp": num("sfp-temperature"),
                                  "volt": num("sfp-supply-voltage")}
            if n in vlans:
                row.update(vlan_id=vlans[n].get("vlan-id"), parent=vlans[n].get("interface"))
            if n in wifi:
                w = wifi[n]
                row.update(ssid=w.get("ssid") or w.get("configuration.ssid") or "", band=w.get("band") or w.get("channel.band") or "",
                           freq=w.get("frequency") or w.get("channel.frequency") or "", mode=w.get("mode") or w.get("configuration.mode") or "")
            if n in lte:
                m = lte_mon.get(n, {})
                row.update(operator=m.get("current-operator") or m.get("operator") or "", rsrp=m.get("rsrp"), rsrq=m.get("rsrq"),
                           sinr=m.get("sinr"), rssi=m.get("rssi"), cell=m.get("current-cellid") or m.get("cell-id") or "",
                           band_lte=m.get("primary-band") or "", access=m.get("access-technology") or "")
            out.append(row)
        wan, nets = self.addressing(out)
        for row in out:   # for internet-link monitoring: each interface's address, and the one the default route uses now
            row["ip"] = getattr(self, "_if_addr", {}).get(row["name"], "")
            row["default_route"] = bool(row["name"]) and row["name"] == getattr(self, "_gw_if", "")
        return {"identity": ident, "version": res.get("version"), "board": res.get("board-name"), "uptime": res.get("uptime"),
                "cpu": int(res.get("cpu-load") or 0), "mem_total": int(res.get("total-memory") or 0),
                "mem_used": int(res.get("total-memory") or 0) - int(res.get("free-memory") or 0),
                "model": rb.get("model") or res.get("board-name"), "serial": rb.get("serial-number"),
                "hdd_free": int(res.get("free-hdd-space") or 0), "hdd_total": int(res.get("total-hdd-space") or 0),
                "bad_blocks": res.get("bad-blocks") or "0", "fw_current": rb.get("current-firmware") or "", "fw_upgrade": rb.get("upgrade-firmware") or "",
                "fw_factory": rb.get("factory-firmware") or "",
                "wan_ip": wan, "networks": nets, "interfaces": out}

    def ping(self, target="1.1.1.1", count=3):
        """WAN health from the router's own point of view: (average latency ms, packet loss %), like UniFi's latency line."""
        r = self.optional(lambda: self._req("POST", "/ping", {"address": target, "count": str(count), "interval": "0.2"}, timeout=10), []) or []
        times, sent, received = [], 0, 0
        for row in r if isinstance(r, list) else []:
            if "sent" in row:
                sent, received = int(row.get("sent") or 0), int(row.get("received") or 0)
            t = str(row.get("time") or "")
            ms = _duration_ms(t)
            if ms is not None:
                times.append(ms)
        if not sent:
            return None, None
        return (round(sum(times) / len(times), 1) if times else None), round(100 * (sent - received) / sent, 1)

    def run_script(self, body, timeout=120):
        """Run a RouterOS script (POST /execute, as-string) and return what it printed. Errors come back as RouterError."""
        r = self._req("POST", "/execute", {"script": body, "as-string": ""}, timeout=timeout)
        return (r or {}).get("ret", "") if isinstance(r, dict) else str(r or "")

    def dhcp_leases(self):
        """DHCP leases with the server (and its interface) each came from. Read live when someone opens the router page."""
        servers = {s.get("name"): s.get("interface", "") for s in self.optional(lambda: self.get("/ip/dhcp-server"), []) or []}
        out = []
        for l in self.optional(lambda: self.get("/ip/dhcp-server/lease"), []) or []:
            out.append({"address": l.get("active-address") or l.get("address") or "", "mac": l.get("active-mac-address") or l.get("mac-address") or "",
                        "host": l.get("host-name") or l.get("active-host-name") or "", "server": l.get("server") or "",
                        "interface": servers.get(l.get("server"), ""), "status": l.get("status") or "", "dynamic": l.get("dynamic") == "true",
                        "disabled": l.get("disabled") == "true", "blocked": l.get("blocked") == "true", "last_seen": _dur_s(l.get("last-seen")),
                        "expires": _dur_s(l.get("expires-after")), "comment": l.get("comment") or ""})
        return out

    def wireless(self):
        """Radios and who is connected to them, read live for the router page's Wireless tab. Covers the three MikroTik
        radio menus: legacy wireless (wlan, incl. NV2 / Nstreme point-to-point), the newer wifi package and 60 GHz (w60g)."""
        radios, peers = [], []
        one = lambda m: (m[0] if isinstance(m, list) and m else m) or {}
        # legacy wireless
        for w in self.optional(lambda: self.get("/interface/wireless"), []) or []:
            n, on = w.get("name"), w.get("disabled") != "true" and w.get("running") == "true"
            mon = one(self.optional(lambda n=n: self.post("/interface/wireless/monitor", {"numbers": n, "once": ""}), {})) if on else {}
            radios.append({"name": n, "kind": "wireless", "mode": w.get("mode") or "", "ssid": w.get("ssid") or "", "band": w.get("band") or "",
                           "frequency": mon.get("frequency") or w.get("frequency") or "", "channel": mon.get("channel") or "",
                           "width": w.get("channel-width") or "", "protocol": mon.get("wireless-protocol") or w.get("wireless-protocol") or "",
                           "radio_name": w.get("radio-name") or "", "mac": w.get("mac-address") or "", "running": w.get("running") == "true",
                           "disabled": w.get("disabled") == "true", "status": mon.get("status") or "", "noise": _int(mon.get("noise-floor")),
                           "ccq": _int(mon.get("overall-tx-ccq")), "tx_power": mon.get("current-tx-power") or w.get("tx-power") or "",
                           "count": _int(mon.get("registered-clients"))})
        for r in self.optional(lambda: self.get("/interface/wireless/registration-table"), []) or []:
            tx, rx = _pair(r.get("bytes"))
            peers.append({"interface": r.get("interface") or "", "mac": r.get("mac-address") or "", "name": r.get("radio-name") or "",
                          "ip": r.get("last-ip") or "", "is_ap": r.get("ap") == "true", "signal": _int(r.get("signal-strength")),
                          "remote_signal": _int(r.get("tx-signal-strength")), "snr": _int(r.get("signal-to-noise")),
                          "ccq": _int(r.get("tx-ccq")), "tx_rate": r.get("tx-rate") or "", "rx_rate": r.get("rx-rate") or "",
                          "uptime": r.get("uptime") or "", "idle": r.get("last-activity") or "", "distance": r.get("distance") or "",
                          "tx_bytes": tx, "rx_bytes": rx, "version": r.get("routeros-version") or "", "comment": r.get("comment") or ""})
        # wifi package (wifiwave2 on early RouterOS 7 versions)
        for base in ("/interface/wifi", "/interface/wifiwave2"):
            ws = self.optional(lambda b=base: self.get(b), None)
            if ws is None:
                continue
            for w in ws:
                n, on = w.get("name"), w.get("disabled") != "true" and w.get("running") == "true"
                mon = one(self.optional(lambda n=n, b=base: self.post(f"{b}/monitor", {"numbers": n, "once": ""}), {})) if on else {}
                radios.append({"name": n, "kind": "wifi", "mode": w.get("configuration.mode") or "ap", "ssid": w.get("configuration.ssid") or "",
                               "band": w.get("channel.band") or "", "frequency": w.get("channel.frequency") or "", "channel": mon.get("channel") or "",
                               "width": w.get("channel.width") or "", "protocol": "", "radio_name": "", "mac": w.get("mac-address") or "",
                               "running": w.get("running") == "true", "disabled": w.get("disabled") == "true", "status": mon.get("state") or "",
                               "noise": None, "ccq": None, "tx_power": mon.get("tx-power") or "", "count": _int(mon.get("registered-peers")),
                               "master": w.get("master-interface") or ""})
            for r in self.optional(lambda b=base: self.get(f"{b}/registration-table"), []) or []:
                tx, rx = _pair(r.get("bytes"))
                peers.append({"interface": r.get("interface") or "", "mac": r.get("mac-address") or "", "name": "", "ip": "",
                              "is_ap": False, "signal": _int(r.get("signal")), "remote_signal": None, "snr": None, "ccq": None,
                              "tx_rate": r.get("tx-rate") or "", "rx_rate": r.get("rx-rate") or "", "uptime": r.get("uptime") or "",
                              "idle": r.get("last-activity") or "", "distance": "", "tx_bytes": tx, "rx_bytes": rx, "version": "",
                              "comment": "", "band": r.get("band") or ""})
            break
        # 60 GHz (Cube, wAP 60G, LHG 60G ...)
        # The menu lists the radios; in multipoint (ap-bridge) each connected station is also listed - as a dynamic
        # "w60g-station" interface with a parent - and /interface/w60g/station has them too. Stations become peers.
        w60 = self.optional(lambda: self.get("/interface/w60g"), []) or []
        sta = {s.get("name") or s.get(".id"): s for s in (self.optional(lambda: self.get("/interface/w60g/station"), []) or [])}
        sta.update({w.get("name"): {**sta.get(w.get("name"), {}), **w} for w in w60 if w.get("parent")})
        mon60 = lambda n: one(self.optional(lambda: self.post("/interface/w60g/monitor", {"numbers": n, "once": ""}), {})) \
            or one(self.optional(lambda: self.post("/interface/w60g/station/monitor", {"numbers": n, "once": ""}), {}))
        for w in [x for x in w60 if not x.get("parent")]:
            n = w.get("name")
            mine = [s for s in sta.values() if (s.get("parent") or s.get("interface") or n) == n]
            # in multipoint the AP's own interface reports "not running" while its stations carry the links
            live = [s for s in mine if s.get("running") != "false" and s.get("disabled") != "true"]
            mon = mon60(n) if w.get("disabled") != "true" else {}
            radios.append({"name": n, "kind": "w60g", "mode": w.get("mode") or "", "ssid": w.get("ssid") or "", "band": "60 GHz",
                           "frequency": mon.get("frequency") or w.get("frequency") or "", "channel": "", "width": "", "protocol": "",
                           "radio_name": "", "mac": w.get("mac-address") or "", "running": w.get("running") == "true" or bool(live),
                           "disabled": w.get("disabled") == "true",
                           "status": "connected" if mon.get("connected") == "true" else f"{len(live)} station(s) connected" if live else "",
                           "noise": None, "ccq": None, "tx_power": str(mon.get("tx-power") or ""), "count": len(live) if mine else None})
            if not mine and mon.get("connected") == "true":   # point-to-point: the link itself is in the monitor
                mine = [mon]
            for st in mine:
                if st.get("rssi") is None and st.get("name") and st is not mon:   # each station's signal is in its own monitor
                    st = {**st, **{k: v for k, v in mon60(st["name"]).items() if v not in (None, "")}}
                peers.append({"interface": n, "mac": st.get("remote-address") or st.get("mac-address") or "", "name": "", "ip": "",
                              "is_ap": False, "signal": _int(st.get("rssi")), "quality": _int(st.get("signal")), "remote_signal": None,
                              "snr": None, "ccq": None, "tx_rate": st.get("tx-phy-rate") or "", "rx_rate": "", "mcs": st.get("tx-mcs") or "",
                              "uptime": st.get("connected-time") or st.get("uptime") or st.get("link-uptime") or "", "idle": "",
                              "distance": st.get("distance") or "", "tx_bytes": None, "rx_bytes": None, "version": "", "comment": ""})
        types = sorted({str(i.get("type") or "") for i in (self.optional(lambda: self.get("/interface"), []) or [])}) if not radios else []
        # names and addresses for peers the radio itself doesn't know (wifi / w60g): DHCP leases, then ARP
        if any(not p["ip"] for p in peers):
            leases = {str(l.get("active-mac-address") or l.get("mac-address") or "").upper(): l
                      for l in self.optional(lambda: self.get("/ip/dhcp-server/lease"), []) or []}
            arp = {str(a.get("mac-address") or "").upper(): a.get("address") for a in self.optional(lambda: self.get("/ip/arp"), []) or []}
            for p in peers:
                l = leases.get(p["mac"].upper(), {})
                p["ip"] = p["ip"] or l.get("active-address") or l.get("address") or arp.get(p["mac"].upper()) or ""
                p["name"] = p["name"] or l.get("host-name") or l.get("comment") or ""
        return {"radios": radios, "peers": peers, "types": types}   # types: only when no radio was found (to explain why)

    # --- ports and bridge VLANs (ports.py drives these, with an automatic undo) ------------------------------------
    def port_data(self) -> dict:
        """Everything the Ports tab needs, read live: physical ports with link / PoE, bridges, bridge ports, the bridge
        VLAN table, VLAN interfaces, who is connected where (bridge hosts, neighbours, DHCP, ARP) and the default route."""
        g = lambda p: self.optional(lambda: self.get(p), []) or []
        one = lambda m: m if isinstance(m, list) else [m] if m else []
        eth = g("/interface/ethernet")
        names = [e["name"] for e in eth if e.get("name")]
        mon = {m.get("name"): m for m in one(self.optional(lambda: self.post("/interface/ethernet/monitor", {"numbers": ",".join(names), "once": ""}), []))} if names else {}
        poe_names = [e["name"] for e in eth if e.get("poe-out") not in (None, "", "forced-on-unsupported")]
        poe = {m.get("name"): m for m in one(self.optional(lambda: self.post("/interface/ethernet/poe/monitor", {"numbers": ",".join(poe_names), "once": ""}), []))} if poe_names else {}
        return {"ethernet": eth, "monitor": mon, "poe": poe, "interfaces": g("/interface"), "bridges": g("/interface/bridge"),
                "ports": g("/interface/bridge/port"), "vlans": g("/interface/bridge/vlan"), "vlan_ifs": g("/interface/vlan"),
                "hosts": g("/interface/bridge/host"), "neighbors": g("/ip/neighbor"), "leases": g("/ip/dhcp-server/lease"), "arp": g("/ip/arp"),
                "addresses": g("/ip/address"), "routes": g("/ip/route?dst-address=0.0.0.0/0&active=true"),
                "switch_vlans": g("/interface/ethernet/switch/vlan")}

    def br_set(self, menu, rid, props):   # menu: "" (bridges), "/port" or "/vlan"
        return self._req("PATCH", f"/interface/bridge{menu}/{rid}", props, timeout=20)

    def br_add(self, menu, props):
        return self._req("PUT", f"/interface/bridge{menu}", props, timeout=20)

    def br_remove(self, menu, rid):
        return self._req("DELETE", f"/interface/bridge{menu}/{rid}", timeout=20)

    def eth_set(self, rid, props):
        return self._req("PATCH", f"/interface/ethernet/{rid}", props, timeout=20)

    UNITS = {"C": "°C", "V": "V", "A": "A", "W": "W", "RPM": "RPM", "%": "%"}

    def health(self) -> list:
        """Board sensors from /system/health: [{name, value, unit}] - temperatures, voltage, fans, power ... whatever the
        model has (RouterOS 7 lists one row per sensor; RouterOS 6 returned one record). Non-numbers (PSU 'ok') are left out."""
        h = self.get("/system/health") or []
        rows = h if isinstance(h, list) else [{"name": k, "value": v, "type": ""} for k, v in h.items() if not k.startswith(".")]
        out = []
        for r in rows:
            v = _num(str(r.get("value") or "").rstrip("CVAWRPM% "))
            if v is None or not r.get("name"):
                continue
            unit = self.UNITS.get(r.get("type") or "", r.get("type") or "")
            if not unit:
                n = r["name"]
                unit = "°C" if "temperature" in n else "V" if "voltage" in n else "RPM" if "fan" in n else "W" if "power" in n else "A" if "current" in n else ""
            out.append({"name": r["name"], "value": v, "unit": unit})
        return out

    DM_FEATURES = ("scheduler", "socks", "fetch", "pptp", "l2tp", "bandwidth-test", "traffic-gen", "sniffer", "ipsec", "romon",
                   "proxy", "hotspot", "smb", "email", "zerotier", "container", "install-any-version", "partitions", "routerboard")

    def device_mode(self) -> dict:
        """RouterOS device-mode (7.13+): the mode, and whether RouterOS flagged itself as possibly compromised (it checks
        its configuration at startup; MikroTik says to treat a flagged router as compromised). Raises RouterError on
        RouterOS versions without it."""
        m = self.get("/system/device-mode") or {}
        m = (m[0] if isinstance(m, list) and m else m) or {}
        yes = lambda v: str(v).lower() in ("true", "yes")
        return {"mode": m.get("mode") or "", "flagged": yes(m.get("flagged")), "attempts": _int(m.get("attempt-count")),
                "off": [f for f in self.DM_FEATURES if f in m and not yes(m[f])]}

    def winbox_service(self):
        """The router's Winbox service: {disabled, port, address (who may connect; "" = anyone)}."""
        s = next((x for x in self.get("/ip/service?name=winbox") or [] if not _yes(x.get("dynamic")) and not _yes(x.get("connection"))), {})
        return {"id": s.get(".id"), "disabled": s.get("disabled") == "true", "port": int(s.get("port") or 8291), "address": s.get("address") or ""}

    def winbox_allow(self, ip, enable=False):
        """Let `ip` (TikManager's tunnel address) reach Winbox: add it to "Available From" if that list is in use; turning
        Winbox on (if asked) restricts it to `ip` alone when nothing was listed, so it never opens to everyone."""
        s = self.winbox_service()
        addrs = [a for a in s["address"].split(",") if a]
        body = {}
        if addrs and f"{ip}/32" not in addrs and ip not in addrs:
            body["address"] = ",".join(addrs + [f"{ip}/32"])
        if enable and s["disabled"]:
            body["disabled"] = "false"
            if not addrs:
                body["address"] = f"{ip}/32"
        if body:
            self._req("PATCH", f"/ip/service/{s['id']}", body, timeout=15)
        return self.winbox_service()

    def set_controller_port(self, port):
        """Point this router's tunnel at TikManager's new WireGuard port (the peer adoption created)."""
        peers = [p for p in self.get("/interface/wireguard/peers") or [] if p.get("comment") == "TikManager controller"]
        if not peers:
            raise RouterError("TikManager's WireGuard peer isn't on this router (re-run the adoption command)")
        for p in peers:
            self._req("PATCH", f"/interface/wireguard/peers/{p['.id']}", {"endpoint-port": str(int(port))}, timeout=15)

    SESSION_COMMENT = "TikManager Winbox session"

    def session_user_add(self, name, group, password, only_from, note):
        """A temporary router login for one Winbox session: may only sign in from TikManager's tunnel address."""
        self._req("PUT", "/user", {"name": name, "group": group, "password": password, "address": f"{only_from}/32",
                                   "comment": f"{self.SESSION_COMMENT}: {note}"[:250]}, timeout=15)

    def session_user_remove(self, name):
        for u in self.get(f"/user?name={urllib.parse.quote(name)}") or []:
            if str(u.get("comment") or "").startswith(self.SESSION_COMMENT):   # only ever TikManager's own session logins
                self._req("DELETE", f"/user/{u['.id']}", timeout=15)

    def session_users(self):
        return [u.get("name") for u in self.get("/user") or [] if str(u.get("comment") or "").startswith(self.SESSION_COMMENT)]

    NEIGHBOR_KEYS = ("interface", "address", "address4", "mac-address", "identity", "platform", "board", "version",
                     "software-id", "uptime", "discovered-by", "interface-name")

    def mikrotik_neighbors(self):
        """MikroTik devices this router sees next to it (/ip neighbor print: MNDP / LLDP / CDP), for Discovered."""
        return [{k: str(n.get(k))[:200] for k in self.NEIGHBOR_KEYS if n.get(k) not in (None, "")}
                for n in self.get("/ip/neighbor") or [] if "mikrotik" in str(n.get("platform") or "").lower()][:500]

    def topology(self):
        """What the network map needs, read live (read-only): routing table, discovered neighbours (MNDP / LLDP / CDP:
        switches, access points, other routers), ARP and bridge host tables, DHCP leases and the router's addresses."""
        pick = lambda rows, keys: [{k: r.get(k) for k in keys if r.get(k) not in (None, "")} for r in rows or []]
        return {
            "routes": pick(self.optional(lambda: self.get("/ip/route"), []),
                           ("dst-address", "gateway", "immediate-gw", "distance", "active", "static", "dynamic", "connect", "disabled",
                            "routing-table", "comment", "vrf-interface", "bgp", "ospf")),
            "neighbors": pick(self.optional(lambda: self.get("/ip/neighbor"), []),
                              ("interface", "address", "address4", "mac-address", "identity", "platform", "board", "version",
                               "system-description", "interface-name", "discovered-by")),
            "arp": pick(self.optional(lambda: self.get("/ip/arp"), []), ("address", "mac-address", "interface", "complete", "dynamic", "status")),
            "hosts": pick(self.optional(lambda: self.get("/interface/bridge/host"), []), ("mac-address", "on-interface", "bridge", "interface", "local", "vid")),
            "leases": self.dhcp_leases(),
            "addresses": pick(self.optional(lambda: self.get("/ip/address"), []), ("address", "network", "interface", "disabled", "comment")),
            "interfaces": pick(self.optional(lambda: self.get("/interface"), []), ("name", "type", "comment", "running", "disabled")),
            "vlans": pick(self.optional(lambda: self.get("/interface/vlan"), []), ("name", "vlan-id", "interface")),
        }

    def gps(self):
        """(latitude, longitude) from a GPS receiver (RouterOS gps package / LTE modems with GPS), or None."""
        res = self.optional(lambda: self._req("POST", "/system/gps/monitor", {"once": ""}), None)
        rows = res if isinstance(res, list) else [res] if isinstance(res, dict) else []
        for r in rows:
            if str(r.get("valid", "")).lower() not in ("true", "yes"):
                continue
            try:
                lat, lon = float(r.get("latitude")), float(r.get("longitude"))
            except (TypeError, ValueError):
                continue
            if -90 <= lat <= 90 and -180 <= lon <= 180 and (lat, lon) != (0.0, 0.0):
                return lat, lon
        return None

    def set_identity(self, name):
        """/system identity set name=... ; returns the identity the router reports afterwards."""
        self.post("/system/identity/set", {"name": name})
        return (self.get("/system/identity") or {}).get("name")

    # --- VPNs already configured on the router (read-only; vpninv.py normalizes) --------------------------------
    INVENTORY = {   # menu -> fields kept. A whitelist, so passwords, secrets and keys are never read into TikManager.
        "/interface/wireguard": ("name", "listen-port", "running", "disabled", "comment"),
        "/interface/wireguard/peers": ("interface", "endpoint-address", "endpoint-port", "current-endpoint-address", "allowed-address",
                                       "last-handshake", "rx", "tx", "comment", "disabled", "name"),
        "/ip/ipsec/peer": ("name", "address", "exchange-mode", "disabled", "comment", "passive"),
        "/ip/ipsec/active-peers": ("remote-address", "state", "uptime", "rx-bytes", "tx-bytes", "ph2-total", "peer"),
        "/ip/ipsec/policy": ("src-address", "dst-address", "peer", "ph2-state", "active", "disabled", "template", "dynamic", "tunnel", "comment"),
        "/interface/l2tp-client": ("name", "connect-to", "running", "disabled", "comment", "use-ipsec"),
        "/interface/sstp-client": ("name", "connect-to", "running", "disabled", "comment"),
        "/interface/ovpn-client": ("name", "connect-to", "port", "running", "disabled", "comment"),
        "/interface/pptp-client": ("name", "connect-to", "running", "disabled", "comment"),
        "/interface/l2tp-server/server": ("enabled", "use-ipsec"),
        "/interface/sstp-server/server": ("enabled", "port"),
        "/interface/ovpn-server/server": ("enabled", "port"),
        "/interface/pptp-server/server": ("enabled",),
        "/ppp/active": ("name", "service", "caller-id", "address", "uptime"),
        "/interface/eoip": ("name", "remote-address", "local-address", "tunnel-id", "running", "disabled", "comment"),
        "/interface/gre": ("name", "remote-address", "local-address", "running", "disabled", "comment"),
        "/interface/ipip": ("name", "remote-address", "local-address", "running", "disabled", "comment"),
        "/ip/route": ("dst-address", "gateway", "active", "disabled", "comment", "static"),
        # for the Performance & Security dashboard (healthdash.py) - settings only, never secrets
        "/ip/ipsec/proposal": ("name", "auth-algorithms", "enc-algorithms", "pfs-group", "disabled"),
        "/ip/ipsec/profile": ("name", "hash-algorithm", "enc-algorithm", "dh-group"),
        "/ip/service": ("name", "port", "disabled", "address", "available-from", "certificate", "dynamic", "connection"),   # 7.20+ renamed address
                                                                    # and lists open connections as dynamic entries
        "/ip/firewall/filter": ("chain", "action", "disabled", "protocol", "dst-port", "src-address", "src-address-list", "dst-address",
                                "dst-address-list", "in-interface", "in-interface-list", "connection-state", "connection-nat-state"),
        "/ip/dns": ("allow-remote-requests",),
        "/ip/upnp": ("enabled",),
        "/ip/socks": ("enabled",),
        "/ip/proxy": ("enabled",),
        "/tool/bandwidth-server": ("enabled",),
        "/tool/mac-server": ("allowed-interface-list",),
        "/snmp": ("enabled",),
        "/ip/ssh": ("strong-crypto", "ciphers"),
        "/system/ntp/client": ("enabled", "servers"),
        "/user": ("name", "group", "disabled"),
        # for compliance checks (compliance.py)
        "/system/logging/action": ("name", "target", "remote", "remote-port"),
        "/system/logging": ("topics", "action", "disabled"),
        "/user/aaa": ("use-radius",),
        "/radius": ("service", "address", "disabled"),
        "/snmp/community": ("security", "authentication-protocol", "encryption-protocol", "addresses", "disabled"),   # never the name (on v1/v2c it is the password)
        "/system/note": ("show-at-login", "note"),
        # BGP: what's configured (the live session state is read every minute - bgp_sessions)
        "/routing/bgp/instance": ("name", "as", "router-id", "disabled"),   # RouterOS 7.20+
        "/routing/bgp/connection": ("name", "instance", "remote.address", "remote.as", "as", "local.role", "disabled", "comment"),
    }

    def vpn_inventory(self) -> dict:
        out = {}
        for menu, keep in self.INVENTORY.items():
            rows = self.optional(lambda menu=menu: self.get(menu), []) or []
            rows = [rows] if isinstance(rows, dict) else rows
            out[menu] = [{k: r[k] for k in keep if k in r} for r in rows if isinstance(r, dict)]
        return out

    # --- site-to-site VPN (vpn.py drives these) - everything TikManager adds carries the comment VPN_TAG ------------
    def wg_ensure(self, name, port, tag=VPN_TAG):
        """Create (or keep) the WireGuard interface; the router makes and keeps the private key. Returns its public key."""
        rows = self.get(f"/interface/wireguard?name={urllib.parse.quote(name)}") or []
        if rows:
            if str(rows[0].get("listen-port")) != str(port):
                self._req("PATCH", f"/interface/wireguard/{rows[0]['.id']}", {"listen-port": str(port)})
        else:
            self._req("PUT", "/interface/wireguard", {"name": name, "listen-port": str(port), "mtu": "1420", "comment": tag})
            rows = self.get(f"/interface/wireguard?name={urllib.parse.quote(name)}") or []
        iface = rows[0] if rows else {}
        if str(iface.get("disabled")) == "true":   # RouterOS disables it when another interface already uses the port
            others = [r for r in self.get("/interface/wireguard") or [] if r.get("name") != name and str(r.get("listen-port")) == str(port)]
            if others:
                raise RouterError(f"UDP port {port} is already used by the router's WireGuard interface \"{others[0].get('name')}\" - "
                                  "pick a different VPN port.")
            self._req("PATCH", f"/interface/wireguard/{iface['.id']}", {"disabled": "false"})
        key = iface.get("public-key")
        if not key:
            raise RouterError("The router didn't report the VPN interface's public key.")
        return key

    def _toggle_on_router(self, menu, ids):
        """Switch entries off and back on in ONE script that the router runs by itself (POST /execute without as-string = a
        background job). Sending "off" and "on" as two requests could leave the entry off for good: when the tunnel being
        switched off carries TikManager's own connection (the WireGuard tunnels ride over it), the "on" never arrives."""
        ids = [i for i in ids if re.fullmatch(r"\*[0-9A-Fa-f]+", str(i))]   # internal IDs only - nothing else reaches the script
        if not ids:
            return 0
        path = menu.replace("/", " ").strip()
        refs = ",".join(ids)
        self._req("POST", "/execute", {"script": f"/{path} disable {refs}; :delay 2s; /{path} enable {refs}"}, timeout=15)
        time.sleep(4)   # let the router finish; if TikManager's own path went down with it, it comes back on its own
        return len(ids)

    def tunnel_reconnect(self, menu, match):
        """Reconnect one VPN: IPsec drops its active peer (it renegotiates straight away); WireGuard peers, dial-out clients and
        EoIP / GRE / IPIP are switched off and on - by the router itself, see _toggle_on_router. Only entries that are
        currently enabled are touched. Returns how many."""
        if menu == "/ip/ipsec/active-peers":
            n = 0
            for a in self.get(menu) or []:
                if str(a.get("remote-address") or "").split("/")[0].split(":")[0] == match.get("remote"):
                    self._req("DELETE", f"{menu}/{a['.id']}")
                    n += 1
            return n
        rows = [r for r in self.get(menu) or [] if all(str(r.get(k, "")) == str(v) for k, v in match.items())
                and str(r.get("disabled")) != "true" and r.get("comment") != VPN_TAG]
        if not rows:
            raise RouterError("That VPN isn't on the router any more (or it's switched off).")
        return self._toggle_on_router(menu, [r[".id"] for r in rows])

    def vpn_reconnect(self):
        """Reconnect TikManager's site-to-site VPN on this router: its peers (tagged VPN_TAG) off and on - a fresh handshake."""
        rows = [r for r in self.get(f"/interface/wireguard/peers?comment={urllib.parse.quote(VPN_TAG)}") or []
                if str(r.get("disabled")) != "true" and r.get("comment") == VPN_TAG]
        return self._toggle_on_router("/interface/wireguard/peers", [r[".id"] for r in rows])

    def vpn_clear(self, name, remove_interface=False):
        """Remove every peer, route, address and firewall rule TikManager added for the VPN (and optionally the interface)."""
        tag = urllib.parse.quote(VPN_TAG)
        for menu in ("/ip/firewall/filter", "/ip/route", "/interface/wireguard/peers", "/ip/address"):
            for r in self.optional(lambda menu=menu: self.get(f"{menu}?comment={tag}"), []) or []:
                self._req("DELETE", f"{menu}/{r['.id']}")
        if remove_interface:
            for r in self.get(f"/interface/wireguard?name={urllib.parse.quote(name)}") or []:
                if r.get("comment") == VPN_TAG:   # never delete an interface someone made by hand
                    self._req("DELETE", f"/interface/wireguard/{r['.id']}")

    def vpn_apply(self, name, cfg):
        """cfg: {address, peers: [{public-key, allowed: [...], endpoint?, port?}], routes: [...], hub_port: int|None}."""
        self.vpn_clear(name)
        self._req("PUT", "/ip/address", {"address": cfg["address"], "interface": name, "comment": VPN_TAG})
        for p in cfg["peers"]:
            body = {"interface": name, "public-key": p["public-key"], "allowed-address": ",".join(p["allowed"]), "comment": VPN_TAG}
            if p.get("endpoint"):
                body.update({"endpoint-address": p["endpoint"], "endpoint-port": str(p["port"]), "persistent-keepalive": "25s"})
            self._req("PUT", "/interface/wireguard/peers", body)
        for dst in cfg["routes"]:
            self._req("PUT", "/ip/route", {"dst-address": dst, "gateway": name, "comment": VPN_TAG})
        # firewall: accept rules at the top, before whatever drop rules the router already has
        first = next((r.get(".id") for r in self.get("/ip/firewall/filter") or [] if r.get("dynamic") != "true"), None)
        rules = ([{"chain": "input", "protocol": "udp", "dst-port": str(cfg["hub_port"])}] if cfg.get("hub_port") else []) + [
            {"chain": "input", "in-interface": name, "protocol": "icmp"},
            {"chain": "forward", "in-interface": name}, {"chain": "forward", "out-interface": name}]
        for r in rules:
            self._req("PUT", "/ip/firewall/filter", {**r, "action": "accept", "comment": VPN_TAG, **({"place-before": first} if first else {})})

    # --- remote access (remoteaccess.py) - everything carries RA_TAG, so it can be removed exactly -----------------------
    def ra_setup(self, name, cfg):
        """cfg: {port, address (gateway/prefix), dns_to_router}. Interface, gateway address and firewall rules - peers (the
        people) are left alone. Returns the interface's public key."""
        pub = self.wg_ensure(name, cfg["port"], tag=RA_TAG)
        self._ra_clear_rules()
        self._req("PUT", "/ip/address", {"address": cfg["address"], "interface": name, "comment": RA_TAG})
        # firewall: accept rules at the top, before whatever drop rules the router already has
        first = next((r.get(".id") for r in self.get("/ip/firewall/filter") or [] if r.get("dynamic") != "true"), None)
        rules = [{"chain": "input", "protocol": "udp", "dst-port": str(cfg["port"])},
                 {"chain": "input", "in-interface": name, "protocol": "icmp"}]   # (forward rules: ra_access, per person)
        if cfg.get("dns_to_router"):
            rules += [{"chain": "input", "in-interface": name, "protocol": "udp", "dst-port": "53"},
                      {"chain": "input", "in-interface": name, "protocol": "tcp", "dst-port": "53"}]
        for r in rules:
            self._req("PUT", "/ip/firewall/filter", {**r, "action": "accept", "comment": RA_TAG, **({"place-before": first} if first else {})})
        return pub

    def _ra_clear_rules(self, chain=None):
        """Remote access's firewall rules (all, or one chain) and gateway address. Per-person rules are commented
        "TikManager remote access: <name>", so they're matched by prefix."""
        for r in self.get("/ip/firewall/filter") or []:
            if str(r.get("comment") or "").startswith(RA_TAG) and (chain is None or r.get("chain") == chain):
                self._req("DELETE", f"/ip/firewall/filter/{r['.id']}")
        if chain is None:
            for r in self.optional(lambda: self.get(f"/ip/address?comment={urllib.parse.quote(RA_TAG)}"), []) or []:
                if r.get("comment") == RA_TAG:
                    self._req("DELETE", f"/ip/address/{r['.id']}")

    def ra_access(self, name, rules):
        """Who may reach what through the tunnel: replaces remote access's forward rules with
        [replies back to people] + rules (each {comment, src-address, dst-address?, protocol?, dst-port?}) + [drop the rest],
        all at the top of the forward chain, in that order."""
        self._ra_clear_rules(chain="forward")
        first = next((r.get(".id") for r in self.get("/ip/firewall/filter") or [] if r.get("dynamic") != "true"), None)
        place = {"place-before": first} if first else {}
        allr = [{"chain": "forward", "out-interface": name, "connection-state": "established,related", "action": "accept", "comment": RA_TAG}]
        allr += [{"chain": "forward", "in-interface": name, "action": "accept", **r} for r in rules]
        allr += [{"chain": "forward", "in-interface": name, "action": "drop", "comment": f"{RA_TAG}: everything else"}]
        for r in allr:
            self._req("PUT", "/ip/firewall/filter", {**r, **place})

    def cloud(self):
        """MikroTik IP Cloud: {ddns, name, address, status} - the router's permanent <serial>.sn.mynetname.net name."""
        c = self.optional(lambda: self.get("/ip/cloud"), {}) or {}
        c = c[0] if isinstance(c, list) and c else c if isinstance(c, dict) else {}
        return {"ddns": str(c.get("ddns-enabled")) in ("true", "yes", "auto"), "name": c.get("dns-name") or "",
                "address": c.get("public-address") or "", "status": c.get("status") or ""}

    def cloud_enable(self, wait=25):
        """Turn on IP Cloud DDNS and wait for the router to get its name. Returns cloud()."""
        self.post("/ip/cloud/set", {"ddns-enabled": "yes"})
        end = time.time() + wait
        while time.time() < end:
            c = self.cloud()
            if c["name"]:
                return c
            time.sleep(2)
        return self.cloud()

    def ra_peer_add(self, name, pubkey, ip, label):
        self._req("PUT", "/interface/wireguard/peers", {"interface": name, "public-key": pubkey, "allowed-address": f"{ip}/32",
                                                        "comment": f"{RA_TAG}: {label}"[:200]})

    def ra_peer_disable(self, name, pubkey, off):
        for p in self.optional(lambda: self.get(f"/interface/wireguard/peers?interface={urllib.parse.quote(name)}"), []) or []:
            if p.get("public-key") == pubkey and str(p.get("comment") or "").startswith(RA_TAG):
                self._req("PATCH", f"/interface/wireguard/peers/{p['.id']}", {"disabled": "true" if off else "false"})
                return
        raise RouterError("That person's peer isn't on the router any more.")

    def ra_peer_remove(self, name, pubkey):
        for p in self.optional(lambda: self.get(f"/interface/wireguard/peers?interface={urllib.parse.quote(name)}"), []) or []:
            if p.get("public-key") == pubkey and str(p.get("comment") or "").startswith(RA_TAG):
                self._req("DELETE", f"/interface/wireguard/peers/{p['.id']}")

    def ra_clear(self, name, remove_interface=False):
        """Remove every peer, address and firewall rule remote access added (and optionally its interface)."""
        self._ra_clear_rules()
        for p in self.optional(lambda: self.get(f"/interface/wireguard/peers?interface={urllib.parse.quote(name)}"), []) or []:
            if str(p.get("comment") or "").startswith(RA_TAG):
                self._req("DELETE", f"/interface/wireguard/peers/{p['.id']}")
        if remove_interface:
            for r in self.get(f"/interface/wireguard?name={urllib.parse.quote(name)}") or []:
                if r.get("comment") == RA_TAG:   # never delete an interface someone made by hand
                    self._req("DELETE", f"/interface/wireguard/{r['.id']}")

    def wg_peers(self, name):
        """[{public_key, handshake_age (seconds or None), rx, tx}] for the VPN interface's peers."""
        out = []
        for p in self.optional(lambda: self.get(f"/interface/wireguard/peers?interface={urllib.parse.quote(name)}"), []) or []:
            out.append({"public_key": p.get("public-key"), "handshake_age": _dur_s(p.get("last-handshake")),
                        "rx": int(p.get("rx") or 0), "tx": int(p.get("tx") or 0), "endpoint": p.get("current-endpoint-address") or ""})
        return out

    # --- firewall filter / NAT rules (firewall.py drives these, with an automatic undo) -------------------------------
    FW_MENUS = {"filter": "/ip/firewall/filter", "nat": "/ip/firewall/nat", "address-list": "/ip/firewall/address-list", "raw": "/ip/firewall/raw"}

    def fw_rules(self, section):
        return self.get(self.FW_MENUS[section]) or []

    def fw_options(self):
        """What the rule editor offers in its pulldowns: address lists (only each entry's list name is read - lists can
        be large), interfaces and interface lists."""
        names = lambda path, key="name": sorted({x.get(key) for x in self.optional(lambda: self.get(path), []) or [] if x.get(key)})
        counts = {}
        for x in self.optional(lambda: self.get("/ip/firewall/address-list?.proplist=list"), []) or []:
            if x.get("list"):
                counts[x["list"]] = counts.get(x["list"], 0) + 1
        return {"address_lists": sorted(counts), "address_list_counts": counts,
                "interfaces": names("/interface?.proplist=name"), "interface_lists": names("/interface/list?.proplist=name")}

    def al_entries(self, name):
        """The entries of one address list (like /ip firewall address-list print where list=...)."""
        return self.get(f"/ip/firewall/address-list?list={urllib.parse.quote(name)}") or []

    def al_find(self, name, address):
        """The entries for one address on one list (without reading the whole list)."""
        return self.get(f"/ip/firewall/address-list?list={urllib.parse.quote(name)}&address={urllib.parse.quote(address)}") or []

    def fw_add(self, section, props, before=None):
        body = dict(props)
        if before:
            body["place-before"] = before
        return self._req("PUT", self.FW_MENUS[section], body, timeout=20)

    def fw_set(self, section, rid, props):
        return self._req("PATCH", f"{self.FW_MENUS[section]}/{rid}", props, timeout=20)

    def fw_unset(self, section, rid, names):
        for n in names:
            self._req("POST", f"{self.FW_MENUS[section]}/unset", {"numbers": rid, "value-name": n}, timeout=20)

    def fw_remove(self, section, rid):
        return self._req("DELETE", f"{self.FW_MENUS[section]}/{rid}", timeout=20)

    def fw_move(self, section, rid, before=None):
        body = {"numbers": rid}
        if before:
            body["destination"] = before
        return self._req("POST", f"{self.FW_MENUS[section]}/move", body, timeout=20)

    # Safe-mode for REST: RouterOS Safe Mode belongs to an interactive Winbox / terminal session, which the REST API
    # doesn't have, so TikManager does the same with a script that restores the rules and a scheduler that runs it
    # unless the change is kept in time.
    def undo_arm(self, name, script=None, delay="5m"):
        q = urllib.parse.quote(name)
        if script is not None:
            for s in self.get(f"/system/script?name={q}") or []:
                self._req("DELETE", f"/system/script/{s['.id']}", timeout=20)
            self._req("PUT", "/system/script", {"name": name, "source": script, "policy": "read,write",
                                                "comment": "TikManager: puts the firewall back if a change isn't kept"}, timeout=30)
        for s in self.get(f"/system/scheduler?name={q}") or []:
            self._req("DELETE", f"/system/scheduler/{s['.id']}", timeout=20)
        self._req("PUT", "/system/scheduler", {"name": name, "interval": delay, "on-event": f"/system script run {name}",
                                               "policy": "read,write",
                                               "comment": "TikManager: undoes a firewall change unless it is kept"}, timeout=20)

    def undo_run(self, name):
        self._req("POST", "/system/script/run", {"number": name}, timeout=60)

    def undo_armed(self, name):
        return bool(self.get(f"/system/scheduler?name={urllib.parse.quote(name)}"))

    def undo_cancel(self, name):
        q = urllib.parse.quote(name)
        for menu in ("/system/scheduler", "/system/script"):
            for s in self.get(f"{menu}?name={q}") or []:
                self._req("DELETE", f"{menu}/{s['.id']}", timeout=20)

    def alive(self):
        """Can TikManager still talk to the router? (after a firewall change)"""
        return bool(self._req("GET", "/system/resource", timeout=8))

    # --- RouterOS / RouterBOARD upgrades (upgrades.py drives these) ---------------------------------------------
    def check_updates(self, channel=None) -> dict:
        """Ask MikroTik's server for the newest version on the router's channel (optionally switching channel first).
        Returns {channel, installed, latest, status}."""
        if channel:
            self.post("/system/package/update/set", {"channel": channel})
        self.optional(lambda: self._req("POST", "/system/package/update/check-for-updates", {}, timeout=60))
        u = self.get("/system/package/update") or {}
        if isinstance(u, list):
            u = u[0] if u else {}
        return {"channel": u.get("channel") or "", "installed": u.get("installed-version") or "",
                "latest": u.get("latest-version") or "", "status": u.get("status") or ""}

    def download_update(self, wait=900):
        """Download the new packages (the router installs them on its next reboot).
        RouterOS's REST API closes any request after about 60 seconds ("Session closed"), and a big download over a slow
        WAN takes longer - so the download runs as a background job on the router (/execute without as-string returns
        at once) and its progress is read every few seconds until it says Downloaded, for up to `wait` seconds."""
        def state():
            u = self.get("/system/package/update") or {}
            if isinstance(u, list):
                u = u[0] if u else {}
            return str(u.get("status") or "")

        done = lambda s: any(w in s.lower() for w in ("downloaded", "reboot"))
        if done(state()):   # already downloaded (e.g. a retry)
            return state()
        self._req("POST", "/execute", {"script": "/system package update download"}, timeout=30)
        start, seen, status = time.time(), False, ""
        while time.time() - start < wait:
            time.sleep(5)
            try:
                status = state()
            except RouterError:
                continue   # a slow moment over the tunnel - keep watching
            low = status.lower()
            if done(status):
                return status
            if "error" in low or "fail" in low or "could not" in low:
                raise RouterError(f"The router couldn't download the update: {status}")
            seen = seen or "download" in low or "%" in low
            if not seen and time.time() - start > 120:
                raise RouterError(f"The router didn't start downloading (status: {status or 'none'})")
        raise RouterError(f"The download didn't finish in {wait // 60} minutes (last status: {status or 'none'}) - the router "
                          "keeps what it has; try again, or check its internet connection")

    def routerboard_upgrade(self):
        """Stage the RouterBOARD firmware that matches the installed RouterOS (applied on the next reboot)."""
        self._req("POST", "/system/routerboard/upgrade", {}, timeout=60)

    def reboot(self):
        """Reboot; the connection usually drops before a reply, which is expected."""
        try:
            self._req("POST", "/system/reboot", {}, timeout=10)
        except RouterError:
            pass

    def export(self, sensitive=False) -> str:
        """The router's configuration as text (/export). Secrets are left out unless sensitive=True.
        Tries the REST 'execute' call that returns the output directly; falls back to writing a file and reading it back."""
        cmd = "/export" + (" show-sensitive" if sensitive else "")
        try:
            r = self._req("POST", "/execute", {"script": cmd, "as-string": ""}, timeout=90, safe=True)
            text = (r or {}).get("ret") if isinstance(r, dict) else None
            if text and "/" in text:
                return text
        except RouterError:
            pass
        name = "tikmanager-export"
        self._req("POST", "/execute", {"script": f"{cmd} file={name}"}, timeout=90)
        for _ in range(10):
            files = self.optional(lambda: self.get(f"/file?name={name}.rsc"), []) or []
            if files and files[0].get("contents"):
                text = files[0]["contents"]
                self.optional(lambda: self._req("POST", "/execute", {"script": f"/file remove [find name={name}.rsc]"}))
                return text
            time.sleep(1)
        raise RouterError("The router didn't return its configuration.")

    def addressing(self, ifaces=()):
        """(WAN address, LAN networks). The WAN is the interface the active default route uses; every other IPv4 network
        (not the TikManager tunnel, not a /32) is a LAN, named after its interface comment, like UniFi's site map."""
        routes = self.optional(lambda: self.get("/ip/route?dst-address=0.0.0.0/0&active=true"), []) or []
        gw_if = next((r.get("immediate-gw", "").split("%")[-1] for r in routes if r.get("immediate-gw")), "")
        addrs = [a for a in self.optional(lambda: self.get("/ip/address"), []) or [] if a.get("disabled") != "true"]
        hit = next((a for a in addrs if gw_if and a.get("interface") == gw_if), None) or next(
            (a for a in addrs if a.get("dynamic") == "true" and not a.get("address", "").startswith(("10.", "192.168.", "172."))), None)
        wan = (hit or {}).get("address", "").split("/")[0]
        self._if_addr = {a.get("interface", ""): a.get("address", "").split("/")[0] for a in reversed(addrs)}   # (first address wins)
        self._gw_if = gw_if
        comments = {i["name"]: i.get("comment") or "" for i in ifaces}
        nets = []
        for a in addrs:
            addr, iface = a.get("address", ""), a.get("interface", "")
            if a is hit or iface in (gw_if, "tikmanager", VPN_IFACE) or addr.endswith("/32") or "/" not in addr:
                continue
            nets.append({"name": comments.get(iface) or iface, "interface": iface, "address": addr,
                         "network": f"{a.get('network') or addr.split('/')[0]}/{addr.split('/')[1]}"})
        return wan, nets

    def wan_ip(self):
        return self.addressing()[0]


def _dur_s(t):
    """RouterOS duration ("1m3s", "2h5m", "00:01:03") -> seconds; None when empty (never)."""
    t = str(t or "").strip()
    if not t:
        return None
    if ":" in t:
        parts = [float(x) for x in t.split(":")]
        return int(sum(v * 60 ** i for i, v in enumerate(reversed(parts))))
    unit = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    total = sum(float(n) * unit[u] for n, u in re.findall(r"(\d+(?:\.\d+)?)(ms|[wdhms])", t) if u != "ms")
    return int(total)


def _int(v):
    """'-62dBm@6Mbps' / '-62@HT20-7' / '85' / '85%' -> the leading whole number (None if there isn't one)."""
    m = re.match(r"\s*(-?\d+)", str(v or ""))
    return int(m.group(1)) if m else None


def _pair(v):
    """'1234,5678' -> (1234, 5678): the registration tables' bytes (sent to the peer, received from it)."""
    a = str(v or "").split(",")
    try:
        return int(a[0]), int(a[1])
    except (IndexError, ValueError):
        return None, None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _duration_ms(t: str):
    """RouterOS ping times: '12ms', '12ms345us', '1s23ms', '850us'."""
    if not t:
        return None
    ms = 0.0
    for n, u in __import__("re").findall(r"(\d+(?:\.\d+)?)(ms|us|s)", t):
        ms += float(n) * {"s": 1000, "ms": 1, "us": 0.001}[u]
    return ms if ms else None


class SimRouter:
    """A pretend router: stable identity per device, drifting CPU/traffic, and ~5% of devices offline at any time."""
    MODELS = [("RB5009UG+S+", "rb5009"), ("hAP ax3", "hap-ax3"), ("CCR2004-16G-2S+", "ccr2004"), ("hEX S", "hex-s"), ("CHR", "chr")]

    def reachable(self):
        return True

    def routing(self, bgp_prefixes=0):
        ospf = self.id % 3 == 1
        return {"ospf_instances": [{"name": "default-v2", "version": "2", "router-id": f"10.255.0.{self.id}", "disabled": "false"}] if ospf else [],
                "ospf_areas": [{"name": "backbone", "area-id": "0.0.0.0", "instance": "default-v2", "type": "default", "disabled": "false"}] if ospf else [],
                "ospf_neighbors": [{"instance": "default-v2", "area": "backbone", "address": "10.30.0.2", "router-id": "10.255.0.9", "state": "Full",
                                    "adjacency": "2d4h", "state-changes": "6", "interface": "ether3"}] if ospf else [],
                "rip_instances": [], "rip_neighbors": [],
                "routes": {"active": 14 + self.id, "by_kind": {"connect": 4, "static": 2, **({"bgp": 7} if self.id % 2 == 0 else {}), **({"ospf": 3} if ospf else {})},
                           "defaults": [{"gateway": "203.0.113.1", "distance": "1", "kind": "static", "table": "main"}]}}

    def bgp_sessions(self):
        if self.id % 2:
            return []
        core_up = not (self.id == 4 and int(time.time() // 300) % 2)
        out = [{"name": "isp-a-1", "remote.address": "203.0.113.1", "remote.as": "64500", "established": "true", "uptime": "3d2h", "prefix-count": "1"}]
        if core_up:
            out.append({"name": "core-1", "remote.address": "10.10.7.100", "remote.as": "65001", "established": "true", "uptime": "41m", "prefix-count": "12"})
        return out

    def https_setup(self, tm_ip):
        time.sleep(0.5)
        port = 8443 if self.id % 3 == 0 else 443   # some simulated routers have SSTP on 443
        self.post("/ip/service/set", {"numbers": "www-ssl", "disabled": "no", "port": str(port), "certificate": HTTPS_CERT,
                                      "address": ",".join(list(PRIVATE) + [f"{tm_ip}/32"])})
        return {"port": port, "cert": HTTPS_CERT, "created_cert": True, "prev": {"id": "*sim"}, "allowed": "", "changed": {}}

    def https_test(self, port):
        return hashlib.sha256(f"sim-cert-{self.id}".encode()).hexdigest()

    def https_revert(self, info):
        self.post("/ip/service/set", {"numbers": "www-ssl", "disabled": "yes", "port": "443", "certificate": "none", "address": ""})

    def ping(self, target="1.1.1.1", count=3):
        r = random.Random(int(time.time() // 60) * 7 + self.id)
        base = 8 + self.id % 30
        spike = 60 if r.random() < 0.04 else 0
        return round(base + r.gauss(0, 2) + spike, 1), (33.3 if r.random() < 0.03 else 0.0)

    def export(self, sensitive=False) -> str:
        """A plausible export that changes now and then (a new firewall rule or DHCP lease every few days)."""
        day = int(time.time() // 86400)
        changes = random.Random(self.id * 31 + day // 3).randint(0, 3)
        lines = [f"# {time.strftime('%Y-%m-%d %H:%M:%S')} by RouterOS 7.19.4", f"# software id = {self.id:04X}-SIM", "#",
                 f"/system identity set name={self.name}", "/interface bridge add name=bridge comment=LAN",
                 "/interface vlan add interface=bridge name=vlan20-guest vlan-id=20",
                 "/ip pool add name=dhcp ranges=192.168.88.10-192.168.88.254",
                 "/ip address add address=192.168.88.1/24 interface=bridge network=192.168.88.0",
                 "/ip dhcp-client add interface=ether1", "/ip firewall filter",
                 "add action=accept chain=input connection-state=established,related",
                 "add action=accept chain=input in-interface=tikmanager src-address=10.77.0.1 comment=TikManager",
                 "add action=drop chain=input in-interface-list=WAN"]
        for k in range(changes):
            lines.insert(-1, f"add action=accept chain=forward dst-port={8000 + k + day % 50} protocol=tcp comment=\"port forward {k + 1}\"")
        lines += ["/ip dns set servers=1.1.1.1,9.9.9.9", "/system clock set time-zone-name=America/Chicago",
                  "/system ntp client set enabled=yes", "/system ntp client servers add address=pool.ntp.org"]
        if sensitive:
            lines.append('/user add name=tikmanager group=tikmanager password="(hidden in dev)"')
        return "\n".join(lines) + "\n"

    def __init__(self, device_id, name="router"):
        self.id = device_id
        self.r = random.Random(device_id)
        self.name = name   # a simulated router reports its stored identity back
        self.model, self.board = self.r.choice(self.MODELS)

    # simulated upgrades: state shared by every SimRouter instance (the poller makes a new one per poll)
    SIM = {}
    LATEST = {"stable": "7.20.2", "long-term": "7.16.2"}

    # --- simulated firewall (a typical MikroTik default set + TikManager's rule), kept per device while the server runs ---
    def _fw(self):
        st = self._sim()
        if "fw" not in st:
            lan = self.networks()[0]["network"]
            filt = [
                {"chain": "input", "action": "accept", "connection-state": "established,related,untracked", "comment": "defconf: accept established,related,untracked"},
                {"chain": "input", "action": "accept", "in-interface": "tikmanager", "src-address": "10.77.0.1", "comment": "TikManager"},
                {"chain": "input", "action": "drop", "connection-state": "invalid", "comment": "defconf: drop invalid"},
                {"chain": "input", "action": "accept", "protocol": "icmp", "comment": "defconf: accept ICMP"},
                {"chain": "input", "action": "accept", "protocol": "tcp", "dst-port": "8291", "src-address-list": "trusted-admins", "comment": "Winbox from admins"},
                {"chain": "input", "action": "drop", "in-interface-list": "!LAN", "comment": "defconf: drop all not coming from LAN"},
                {"chain": "forward", "action": "fasttrack-connection", "connection-state": "established,related", "hw-offload": "true", "comment": "defconf: fasttrack"},
                {"chain": "forward", "action": "accept", "connection-state": "established,related,untracked", "comment": "defconf: accept established,related, untracked"},
                {"chain": "forward", "action": "drop", "connection-state": "invalid", "comment": "defconf: drop invalid"},
                {"chain": "forward", "action": "drop", "connection-state": "new", "connection-nat-state": "!dstnat", "in-interface-list": "WAN",
                 "comment": "defconf: drop all from WAN not DSTNATed"},
                {"chain": "forward", "action": "drop", "src-address": lan, "dst-address": "10.0.0.0/8", "disabled": "true", "comment": "Block LAN to 10/8 (off)"},
            ]
            nat = [
                {"chain": "srcnat", "action": "masquerade", "out-interface-list": "WAN", "ipsec-policy": "out,none", "comment": "defconf: masquerade"},
                {"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst-port": "3389", "in-interface-list": "WAN",
                 "to-addresses": lan.rsplit(".", 1)[0] + ".20", "to-ports": "3389", "comment": "RDP to server"},
            ]
            alist = [
                {"list": "trusted-admins", "address": "198.51.100.10", "comment": "Office static IP", "creation-time": "2026-09-14 10:02:11"},
                {"list": "trusted-admins", "address": "203.0.113.0/28", "comment": "Datacenter", "creation-time": "2026-09-14 10:03:40"},
                {"list": "office-ips", "address": "203.0.113.0/28", "creation-time": "2026-08-01 08:00:00"},
                {"list": "blocklist", "address": "192.0.2.66", "dynamic": "true", "timeout": "1d03:12:44", "creation-time": "2026-10-08 06:47:16"},
                {"list": "blocklist", "address": "192.0.2.201", "dynamic": "true", "timeout": "13:40:02", "creation-time": "2026-10-09 01:19:58"},
                {"list": "blocklist", "address": "spam.example.net", "comment": "Known spammer", "creation-time": "2026-07-20 12:00:00"},
            ]
            r = random.Random(self.id)
            st["fw"] = {}
            st["fw_next"] = 1
            for sec, rules in (("filter", filt), ("nat", nat)):
                st["fw"][sec] = []
                for x in rules:
                    st["fw"][sec].append({".id": f"*{st['fw_next']:X}", "disabled": "false", "dynamic": "false", "invalid": "false",
                                          "bytes": str(r.randint(0, 9 * 10 ** 9)), "packets": str(r.randint(0, 9 * 10 ** 6)), **x})
                    st["fw_next"] += 1
            st["fw"]["address-list"] = []
            for x in alist:
                st["fw"]["address-list"].append({".id": f"*{st['fw_next']:X}", "disabled": "false", "dynamic": "false", **x})
                st["fw_next"] += 1
            st["sched"], st["undo"] = {}, {}
        st["fw"].setdefault("raw", [])
        return st

    def fw_rules(self, section):
        self._fw_expire()
        return [dict(x) for x in self._fw()["fw"][section]]

    def al_entries(self, name):
        return [dict(x) for x in self._fw()["fw"]["address-list"] if x.get("list") == name]

    def al_find(self, name, address):
        return [x for x in self.al_entries(name) if x.get("address") == address]

    def fw_options(self):
        counts = {}
        for x in self._fw()["fw"]["address-list"]:
            counts[x["list"]] = counts.get(x["list"], 0) + 1
        return {"address_lists": sorted(counts), "address_list_counts": counts,
                "interfaces": ["bridge", "ether1", "ether2", "ether3", "ether4", "ether5", "tikmanager", "wlan1"], "interface_lists": ["LAN", "WAN"]}

    def _fw_find(self, section, rid):
        rules = self._fw()["fw"][section]
        i = next((k for k, x in enumerate(rules) if x[".id"] == rid), None)
        if i is None:
            raise RouterError(f"HTTP 404: no such item ({rid})")
        return rules, i

    def fw_add(self, section, props, before=None):
        st = self._fw()
        if section == "address-list":
            if any(x["list"] == props.get("list") and x["address"] == props.get("address") for x in st["fw"][section]):
                raise RouterError("HTTP 400: failure: already have such entry")
            rule = {".id": f"*{st['fw_next']:X}", "disabled": "false", "dynamic": "false", "creation-time": time.strftime("%Y-%m-%d %H:%M:%S"), **props}
        else:
            rule = {".id": f"*{st['fw_next']:X}", "disabled": "false", "dynamic": "false", "invalid": "false", "bytes": "0", "packets": "0", **props}
        st["fw_next"] += 1
        rules = st["fw"][section]
        if before:
            rules.insert(self._fw_find(section, before)[1], rule)
        else:
            rules.append(rule)
        return dict(rule)

    def fw_set(self, section, rid, props):
        rules, i = self._fw_find(section, rid)
        rules[i].update(props)

    def fw_unset(self, section, rid, names):
        rules, i = self._fw_find(section, rid)
        for n in names:
            rules[i].pop(n, None)

    def fw_remove(self, section, rid):
        rules, i = self._fw_find(section, rid)
        rules.pop(i)

    def fw_move(self, section, rid, before=None):
        rules, i = self._fw_find(section, rid)
        rule = rules.pop(i)
        if before:
            rules.insert(self._fw_find(section, before)[1], rule)
        else:
            rules.append(rule)

    def undo_arm(self, name, script=None, delay="5m"):
        st = self._fw()
        if script is not None and name not in st["undo"]:   # the state before the test's first change
            st["undo"][name] = copy.deepcopy({"fw": st["fw"], "sw": self._sim().get("sw")})
        st["sched"][name] = time.time() + int(delay.rstrip("m")) * 60

    def undo_run(self, name):
        st = self._fw()
        if name in st["undo"]:
            saved = copy.deepcopy(st["undo"][name])
            st["fw"] = saved["fw"]
            if saved.get("sw") is not None:
                self._sim()["sw"] = saved["sw"]
        self.undo_cancel(name)

    def undo_cancel(self, name):
        st = self._fw()
        st["sched"].pop(name, None)
        st["undo"].pop(name, None)

    def undo_armed(self, name):
        self._fw_expire()
        return name in self._fw()["sched"]

    def _fw_expire(self):
        st = self._fw()
        for name, at in list(st["sched"].items()):
            if at <= time.time():
                self.undo_run(name)

    def alive(self):
        # a rule that drops the controller's own traffic cuts the simulated router off too
        for x in self._fw()["fw"]["filter"]:
            if x.get("disabled") == "true" or x.get("chain") != "input" or x.get("action") not in ("drop", "reject"):
                continue
            if x.get("comment") == "TikManager":
                continue
            if x.get("in-interface") == "tikmanager" or x.get("src-address", "").startswith("10.77.") or not any(
                    k in x for k in ("src-address", "in-interface", "in-interface-list", "connection-state", "protocol", "dst-port", "src-address-list")):
                if not self._fw_accepts_first(x):
                    raise RouterError("Unreachable over the tunnel: timed out")
        return True

    def _fw_accepts_first(self, rule):
        """True if TikManager's accept rule comes before `rule` (so the controller is still let in)."""
        rules = self._fw()["fw"]["filter"]
        tm = next((k for k, x in enumerate(rules) if x.get("comment") == "TikManager" and x.get("disabled") != "true"), None)
        return tm is not None and tm < rules.index(rule)

    def post(self, path, body):
        time.sleep(0.3)
        if path == "/ip/ssh/set" and body.get("strong-crypto") == "yes" and "ciphers" not in body and self.id % 2:   # like real routers allowing null
            raise RouterError('HTTP 400: {"detail":"failure: strong-crypto and none cipher can\'t be used at the same time","error":400}')
        self._sim().setdefault("set", {})[path + (f"#{body['numbers']}" if body.get("numbers") else "")] = body
        return []

    def _sim(self):
        st = SimRouter.SIM.setdefault(self.id, {"channel": "stable"})
        st.setdefault("pub", base64.b64encode(hashlib.sha256(f"sim-wg-{self.id}".encode()).digest()).decode())
        return st

    def check_updates(self, channel=None):
        st = self._sim()
        if channel:
            st["channel"] = channel
        installed = self.status()["version"].split(" ")[0]
        latest = self.LATEST[st["channel"]]
        return {"channel": st["channel"], "installed": installed, "latest": latest,
                "status": "New version is available" if latest != installed else "System is already up to date"}

    def download_update(self):
        time.sleep(3)
        self._sim()["staged"] = self.LATEST[self._sim()["channel"]]
        return "Downloaded, please reboot router to upgrade it"

    def routerboard_upgrade(self):
        self._sim()["fw_staged"] = self.status()["version"].split(" ")[0]

    def reboot(self):
        st = self._sim()
        st["down_until"] = time.time() + 40
        if st.pop("staged", None):
            st["version"] = f"{self.LATEST[st['channel']]} ({st['channel']})"
        if st.get("fw_staged"):
            st["fw"] = st.pop("fw_staged")

    def vpn_inventory(self):
        """A plausible mix: IPsec to another simulated router, a WireGuard road-warrior server, an L2TP client, a PPTP server."""
        other = f"203.0.113.{(self.id % 5) + 3}"
        inv = {m: [] for m in RouterOS.INVENTORY}
        if self.id % 2:
            inv["/ip/ipsec/peer"] = [{"name": "to-branch", "address": f"{other}/32", "exchange-mode": "ike2", "disabled": "false"}]
            inv["/ip/ipsec/active-peers"] = [{"remote-address": other, "state": "established", "uptime": "3d4h", "rx-bytes": "81234567",
                                             "tx-bytes": "71234567", "ph2-total": "1"}] if self.id % 3 else []
            inv["/ip/ipsec/policy"] = [{"src-address": f"192.168.{self.id * 10}.0/24", "dst-address": "192.168.99.0/24", "peer": "to-branch",
                                        "ph2-state": "established" if self.id % 3 else "no-phase2", "active": "true", "tunnel": "true", "disabled": "false"}]
        if self.id % 3 == 1:
            inv["/interface/wireguard"] = [{"name": "wg-remote", "listen-port": "51821", "running": "true", "disabled": "false", "comment": "Staff laptops"}]
            inv["/interface/wireguard/peers"] = [{"interface": "wg-remote", "allowed-address": f"10.66.0.{k}/32", "last-handshake": f"{k * 40}s" if k < 3 else "",
                                                  "rx": str(k * 10 ** 7), "tx": str(k * 3 * 10 ** 7), "comment": n, "disabled": "false",
                                                  "current-endpoint-address": f"172.58.{k}.9" if k < 3 else ""}
                                                 for k, n in ((1, "Staff laptop"), (2, "Front desk"), (3, "Old phone"))]
        if self.id % 4 == 2:
            inv["/interface/l2tp-client"] = [{"name": "l2tp-hq", "connect-to": other, "running": "false", "disabled": "false", "use-ipsec": "yes"}]
        if self.id == 1:
            inv["/interface/pptp-server/server"] = [{"enabled": "true"}]
            inv["/ppp/active"] = [{"name": "vendor", "service": "pptp", "caller-id": "73.12.4.8", "address": "10.9.9.2", "uptime": "2h"}]
        # dashboard settings: mostly MikroTik defaults, with a few common mistakes on some routers
        inv["/ip/service"] = [{"name": n, "port": str(p), "disabled": "true" if n in ("telnet", "ftp", "api", "api-ssl") and self.id % 3 else "false", "address": ""}
                              for n, p in (("telnet", 23), ("ftp", 21), ("www", 80), ("ssh", 22), ("winbox", 8291), ("api", 8728), ("api-ssl", 8729))] + \
            [{"name": "www-ssl", "port": "443", "disabled": "true", "address": "", "certificate": "none"},
             {"name": "www-ssl", "port": "8443", "disabled": "false", "dynamic": "true", "connection": "true"}]
        inv["/ip/firewall/filter"] = [{"chain": "input", "action": "accept", "connection-state": "established,related,untracked"},
                                      {"chain": "input", "action": "accept", "protocol": "tcp", "dst-port": "8291"} if self.id % 4 == 3 else
                                      {"chain": "input", "action": "accept", "protocol": "icmp"}] + \
                                     ([] if self.id == 2 else [{"chain": "input", "action": "drop", "in-interface-list": "!LAN"}])
        inv["/ip/dns"] = [{"allow-remote-requests": "true"}]
        inv["/ip/upnp"] = [{"enabled": "true" if self.id % 5 == 0 else "false"}]
        inv["/ip/socks"] = [{"enabled": "false"}]
        inv["/ip/proxy"] = [{"enabled": "false"}]
        inv["/tool/bandwidth-server"] = [{"enabled": "true"}]
        inv["/tool/mac-server"] = [{"allowed-interface-list": "all" if self.id % 2 else "LAN"}]
        inv["/ip/ssh"] = [{"strong-crypto": "no" if self.id % 3 == 2 else "yes"}]
        inv["/system/ntp/client"] = [{"enabled": "true" if self.id % 4 else "false"}]
        inv["/user"] = [{"name": "admin" if self.id % 2 else "starr", "group": "full", "disabled": "false"}]
        inv["/ip/firewall/filter"] += [{"chain": "forward", "action": "accept", "connection-state": "established,related"}] + \
            ([{"chain": "forward", "action": "drop", "connection-nat-state": "!dstnat", "in-interface-list": "WAN"}] if self.id % 3 else [])
        inv["/system/logging/action"] = [{"name": "memory", "target": "memory"}, {"name": "tikmanager", "target": "remote", "remote": "10.77.0.1"}]
        inv["/system/logging"] = [{"topics": "info", "action": "memory"}, {"topics": "info", "action": "tikmanager"}, {"topics": "warning", "action": "tikmanager"}]
        inv["/user/aaa"] = [{"use-radius": "true" if self.id % 4 == 0 else "false"}]
        inv["/radius"] = [{"service": "login", "address": "192.168.88.10", "disabled": "false"}] if self.id % 4 == 0 else []
        inv["/snmp"] = [{"enabled": "true" if self.id % 3 == 1 else "false"}]
        inv["/snmp/community"] = [{"security": "none", "disabled": "false"}]
        inv["/system/note"] = [{"show-at-login": "true" if self.id % 2 == 0 else "false", "note": "Authorized use only." if self.id % 2 == 0 else ""}]
        if self.id % 2 == 0:   # BGP on even-numbered simulated routers
            inv["/routing/bgp/instance"] = [{"name": "default", "as": "65010", "router-id": f"10.255.0.{self.id}", "disabled": "false"}]
            inv["/routing/bgp/connection"] = [
                {"name": "isp-a", "instance": "default", "remote.address": "203.0.113.1", "remote.as": "64500", "local.role": "ebgp", "disabled": "false"},
                {"name": "core", "instance": "default", "remote.address": "10.10.7.100/32", "remote.as": "65001", "local.role": "ibgp", "disabled": "false"}]
        for path, body in self._sim().get("set", {}).items():   # one-click fixes made here (post)
            menu, body = path.split("#")[0].rsplit("/set", 1)[0], dict(body)
            name = body.pop("numbers", None)
            for item in inv.get(menu) or [{}]:
                if name is None or item.get("name") == name:
                    item.update({k: {"yes": "true", "no": "false"}.get(v, v) for k, v in body.items()})
        if self.id % 2:
            inv["/ip/ipsec/proposal"] = [{"name": "default", "auth-algorithms": "sha1", "enc-algorithms": "aes-256-cbc,3des", "pfs-group": "modp1024", "disabled": "false"}]
            inv["/ip/ipsec/profile"] = [{"name": "default", "hash-algorithm": "sha1", "enc-algorithm": "aes-128", "dh-group": "modp2048,modp1024"}]
        return inv

    # simulated site-to-site VPN: a tunnel is "up" when both ends have each other as peers
    def wg_ensure(self, name, port):
        st = self._sim()
        st.setdefault("vpn", {})
        return base64.b64encode(hashlib.sha256(f"sim-wg-{self.id}".encode()).digest()).decode()

    def vpn_clear(self, name, remove_interface=False):
        self._sim().pop("vpn_cfg", None)

    def tunnel_reconnect(self, menu, match):
        time.sleep(0.5)
        return 1

    def vpn_reconnect(self):
        time.sleep(0.5)
        return len((self._sim().get("vpn_cfg") or {}).get("peers", []))

    def vpn_apply(self, name, cfg):
        time.sleep(0.5)
        self._sim()["vpn_cfg"] = cfg

    def ra_setup(self, name, cfg):
        time.sleep(0.3)
        sim = self._sim()
        sim["ra"] = {**cfg, "peers": (sim.get("ra") or {}).get("peers", {})}
        sim.setdefault("ra_pub", __import__("remoteaccess").keypair()[1])
        return sim["ra_pub"]

    def ra_peer_add(self, name, pubkey, ip, label):
        self._sim().setdefault("ra", {"peers": {}})["peers"][pubkey] = ip

    def cloud(self):
        on = self._sim().get("cloud", self.id % 2 == 1)   # some simulated routers start with Cloud DNS on
        return {"ddns": on, "name": f"{hashlib.sha256(str(self.id).encode()).hexdigest()[:12]}.sn.mynetname.net" if on else "",
                "address": f"203.0.113.{self.id % 250 + 2}" if on else "", "status": "updated" if on else ""}

    def cloud_enable(self, wait=25):
        time.sleep(0.5)
        self._sim()["cloud"] = True
        return self.cloud()

    def ra_peer_remove(self, name, pubkey):
        (self._sim().get("ra") or {}).get("peers", {}).pop(pubkey, None)

    def ra_peer_disable(self, name, pubkey, off):
        time.sleep(0.2)

    def ra_access(self, name, rules):
        self._sim().setdefault("ra", {"peers": {}})["rules"] = rules

    def ra_clear(self, name, remove_interface=False):
        self._sim().pop("ra", None)

    def wg_peers(self, name):
        if name == RA_IFACE:   # remote access: a few people "connected"
            peers = (self._sim().get("ra") or {}).get("peers", {})
            r = random.Random(int(time.time() // 300))   # people come and go every few minutes
            return [{"public_key": k, "handshake_age": r.choice([None, 12, 40, 3600]), "rx": random.randint(0, 10 ** 8), "tx": random.randint(0, 10 ** 8),
                     "endpoint": f"172.58.{abs(hash(k)) % 200}.{r.randint(1, 3)}"} for k in peers]
        cfg = self._sim().get("vpn_cfg") or {}
        mine = self.wg_ensure(name, 0)
        out = []
        for p in cfg.get("peers", []):
            other = next((s for s in SimRouter.SIM.values() if s.get("vpn_cfg") and any(q["public-key"] == mine for q in s["vpn_cfg"]["peers"])
                          and s.get("pub") == p["public-key"]), None)
            out.append({"public_key": p["public-key"], "handshake_age": random.randint(5, 110) if other else None,
                        "rx": random.randint(10 ** 6, 10 ** 9) if other else 0, "tx": random.randint(10 ** 6, 10 ** 9) if other else 0})
        return out

    def run_script(self, body, timeout=120):
        time.sleep(0.3)
        if ":error" in body:
            raise RouterError("HTTP 400: failure: " + body.split(":error", 1)[1].strip().strip('"')[:80])
        return "\n".join(f"(simulated) {line.strip()}" for line in body.splitlines() if line.strip() and not line.strip().startswith("#"))[:2000]

    def topology(self):
        """Simulated network: a switch and an access point behind the router, phones, printers, PCs, a VM host."""
        r = random.Random(self.id * 313)
        nets = self.networks()
        lan = nets[0]["network"].rsplit(".", 1)[0]
        mac = lambda prefix: prefix + ":" + ":".join("%02X" % r.randint(0, 255) for _ in range(3))
        devices = [("80:5E:C0", "SIP-T54W"), ("80:5E:C0", "SIP-T46U"), ("00:04:F2", "Polycom-VVX"), ("00:80:77", "BRN-OFFICE"),
                   ("00:0C:29", "FILESRV01"), ("00:50:56", "DC01"), ("3C:52:82", "DESKTOP-4K2J9"), ("D4:BE:D9", "LAPTOP-SALES"),
                   ("D4:BE:D9", "Reception-PC"), ("BC:AD:28", "NVR-Lobby"), ("7A:11:22", "iPhone"), ("DA:33:44", "Galaxy-S24"),
                   ("B8:27:EB", "pi-sensors"), ("00:11:32", "NAS"), ("E0:D5:5E", ""), ("44:38:39", "")]
        devices = devices[: 9 + self.id % 7]
        arp, hosts, leases = [], [], []
        for k, (prefix, name) in enumerate(devices):
            m = mac(prefix)
            ip = f"{lan}.{30 + k}"
            port = "ether2" if k % 3 else "ether3"
            arp.append({"address": ip, "mac-address": m, "interface": "bridge", "complete": "true"})
            hosts.append({"mac-address": m, "on-interface": port, "bridge": "bridge"})
            if name:
                leases.append({"address": ip, "mac": m, "host": name, "server": "dhcp-lan", "interface": "bridge", "status": "bound",
                               "dynamic": True, "disabled": False, "blocked": False, "last_seen": r.randint(1, 900), "expires": 600, "comment": ""})
        neighbors = [{"interface": "ether2", "address": f"{lan}.2", "mac-address": mac("44:D9:E7"), "identity": f"SW-{self.name[:8]}",
                      "platform": "UniFi", "board": "USW-24-PoE", "discovered-by": "lldp"},
                     {"interface": "ether3", "address": f"{lan}.3", "mac-address": mac("4C:5E:0C"), "identity": f"AP-{self.name[:8]}",
                      "platform": "MikroTik", "board": "cAP ax", "version": "7.19.4", "discovered-by": "mndp"}]
        routes = [{"dst-address": "0.0.0.0/0", "gateway": f"203.0.113.{self.id % 250 + 1}", "immediate-gw": f"203.0.113.{self.id % 250 + 1}%ether1",
                   "distance": "1", "active": "true", "static": "true"},
                  {"dst-address": "10.77.0.0/16", "gateway": "tikmanager", "active": "true", "static": "true", "comment": "TikManager"}]
        routes += [{"dst-address": n["network"], "gateway": n["interface"], "active": "true", "connect": "true", "dynamic": "true"} for n in nets]
        if self.id % 2:
            routes.append({"dst-address": f"172.16.{self.id}.0/24", "gateway": "10.250.0.1", "active": "true", "static": "true",
                           "comment": "Branch office over site-to-site VPN"})
        return {"routes": routes, "neighbors": neighbors, "arp": arp, "hosts": hosts, "leases": leases,
                "addresses": [{"address": n["address"], "network": n["network"].split("/")[0], "interface": n["interface"]} for n in nets],
                "interfaces": [{"name": "ether1", "type": "ether", "comment": "WAN"}, {"name": "bridge", "type": "bridge", "comment": "LAN"},
                               {"name": "vlan20-guest", "type": "vlan"}, {"name": "vlan30-voip", "type": "vlan"}],
                "vlans": [{"name": "vlan20-guest", "vlan-id": "20", "interface": "bridge"}, {"name": "vlan30-voip", "vlan-id": "30", "interface": "bridge"}]}

    def gps(self):
        return None

    def dhcp_leases(self):
        r = random.Random(self.id * 101)
        hosts = ["FrontDesk-PC", "Printer-HP-M404", "iPhone", "Galaxy-S24", "Office-AP", "POS-1", "POS-2", "Camera-NVR", "", "Thermostat", "Laptop-Jenn", "Phone-Yealink"]
        lan = "192.168.88" if self.id % 3 == 0 else f"192.168.{self.id * 10}"
        out = []
        for k, h in enumerate(hosts[: 6 + self.id % 6]):
            static = h.startswith(("Printer", "POS", "Camera"))
            out.append({"address": f"{lan}.{20 + k * 3}", "mac": "%02X:%02X:%02X:%02X:%02X:%02X" % tuple(r.randint(0, 255) for _ in range(6)),
                        "host": h, "server": "dhcp-lan", "interface": "bridge", "status": "bound" if k % 5 else "waiting", "dynamic": not static,
                        "disabled": False, "blocked": False, "last_seen": r.randint(1, 3600) if k % 5 else r.randint(86400, 900000),
                        "expires": None if static else r.randint(60, 600), "comment": "Reserved" if static else ""})
        return out

    def wireless(self):
        r = random.Random(int(time.time() // 10) + self.id)   # changes a little every 10 s, like a live radio
        rs = random.Random(self.id * 31)
        mac = lambda k: "DC:2C:6E:%02X:%02X:%02X" % (self.id % 256, k, rs.randint(0, 255))
        radios, peers = [], []
        if self.board == "hap-ax3":   # office access point (wifi package) with laptops and phones
            for n, band, freq, ch in (("wifi1", "5ghz-ax", "5180", "5180/ax/Ceee"), ("wifi2", "2ghz-ax", "2437", "2437/ax")):
                radios.append({"name": n, "kind": "wifi", "mode": "ap", "ssid": "Office", "band": band, "frequency": freq, "channel": ch,
                               "width": "20/40/80mhz" if n == "wifi1" else "20mhz", "protocol": "", "radio_name": "", "mac": mac(len(radios)),
                               "running": True, "disabled": False, "status": "running-ap", "noise": None, "ccq": None, "tx_power": "23",
                               "count": None, "master": ""})
            hosts = ["Laptop-Jenn", "iPhone", "Galaxy-S24", "FrontDesk-PC", "iPad", "Thermostat", "Laptop-Mark", "Pixel-8"]
            for k, h in enumerate(hosts[: 4 + self.id % 5]):
                sig = -48 - rs.randint(0, 30) + r.randint(-2, 2)
                peers.append({"interface": "wifi1" if k % 3 else "wifi2", "mac": mac(10 + k), "name": h, "ip": f"192.168.{self.id * 10}.{40 + k}",
                              "is_ap": False, "signal": sig, "remote_signal": None, "snr": None, "ccq": None,
                              "tx_rate": f"{max(6, 1200 + sig * 12)}Mbps", "rx_rate": f"{max(6, 860 + sig * 10)}Mbps",
                              "uptime": f"{rs.randint(0, 9)}h{rs.randint(0, 59)}m", "idle": f"{r.randint(0, 900)}ms", "distance": "",
                              "tx_bytes": rs.randint(10 ** 6, 10 ** 9), "rx_bytes": rs.randint(10 ** 6, 10 ** 8), "version": "", "comment": "",
                              "band": "5ghz-ax" if k % 3 else "2ghz-ax"})
        elif self.id % 5 == 0:   # point-to-point backhaul: this end is the station of an NV2 link
            radios.append({"name": "wlan1", "kind": "wireless", "mode": "station-bridge", "ssid": "PTP-Tower2", "band": "5ghz-a/n/ac",
                           "frequency": "5745", "channel": "5745/20-80/ac(17dBm)", "width": "20/40/80mhz-Ceee", "protocol": "nv2",
                           "radio_name": self.name, "mac": mac(0), "running": True, "disabled": False, "status": "connected-to-ess",
                           "noise": -104 + r.randint(-1, 1), "ccq": 92 + r.randint(-4, 4), "tx_power": "17", "count": 1})
            peers.append({"interface": "wlan1", "mac": mac(1), "name": "Tower2-AP", "ip": "10.20.0.1", "is_ap": True,
                          "signal": -58 + r.randint(-2, 2), "remote_signal": -60 + r.randint(-2, 2), "snr": 46 + r.randint(-2, 2),
                          "ccq": 92 + r.randint(-4, 4), "tx_rate": "866.7Mbps-80MHz/2S", "rx_rate": "780Mbps-80MHz/2S", "uptime": "18d4h12m",
                          "idle": "10ms", "distance": "3", "tx_bytes": rs.randint(10 ** 10, 10 ** 12), "rx_bytes": rs.randint(10 ** 11, 10 ** 12),
                          "version": "7.19.4", "comment": ""})
        elif self.id % 7 == 0:   # ISP sector: legacy wireless AP with customer CPEs on NV2
            radios.append({"name": "wlan1", "kind": "wireless", "mode": "ap-bridge", "ssid": "WISP-North", "band": "5ghz-a/n",
                           "frequency": "5260", "channel": "5260/20-Ce/an", "width": "20/40mhz-Ce", "protocol": "nv2", "radio_name": self.name,
                           "mac": mac(0), "running": True, "disabled": False, "status": "running-ap", "noise": -102 + r.randint(-1, 1),
                           "ccq": 78 + r.randint(-5, 5), "tx_power": "20", "count": 12})
            for k in range(12):
                sig = -55 - rs.randint(0, 32) + r.randint(-2, 2)
                peers.append({"interface": "wlan1", "mac": mac(20 + k), "name": f"CPE-{rs.choice(['Smith', 'Garcia', 'Lee', 'Patel', 'Brown', 'Nguyen'])}-{100 + k}",
                              "ip": f"100.64.{self.id}.{10 + k}", "is_ap": False, "signal": sig, "remote_signal": sig - rs.randint(-3, 5),
                              "snr": 100 + sig, "ccq": max(20, min(100, 160 + sig + r.randint(-5, 5))), "tx_rate": f"{max(6, 300 + sig * 3)}Mbps-40MHz/2S",
                              "rx_rate": f"{max(6, 270 + sig * 3)}Mbps-40MHz/2S", "uptime": f"{rs.randint(0, 40)}d{rs.randint(0, 23)}h",
                              "idle": f"{r.randint(0, 200)}ms", "distance": str(rs.randint(1, 12)), "tx_bytes": rs.randint(10 ** 8, 10 ** 11),
                              "rx_bytes": rs.randint(10 ** 7, 10 ** 10), "version": rs.choice(["6.49.15", "7.16.2", "7.19.4"]), "comment": ""})
        return {"radios": radios, "peers": peers}

    def device_mode(self):
        return {"mode": "advanced", "flagged": self.id % 6 == 3, "attempts": 0, "off": ["container"]}

    # --- simulated switch: a bridge with VLANs over the router's ports ---------------------------------------------
    def _sw(self):
        st = self._sim()
        if "sw" not in st:
            ifs = [i for i in self.status()["interfaces"] if i["type"] == "ether"]
            r = random.Random(self.id * 17)
            eth, ports, n = [], [], 1
            for i in ifs:
                poe = self.id % 2 == 0 and i["name"] in ("ether2", "ether3", "ether4", "ether5")
                eth.append({".id": f"*{n:X}", "name": i["name"], "default-name": i["name"], "comment": i.get("comment") or "", "disabled": "false",
                            **({"poe-out": "auto-on"} if poe else {}), **({"sfp-shutdown-temperature": "95"} if i["name"].startswith("sfp") else {})})
                n += 1
            members = [i["name"] for i in ifs if i["name"] != "ether1"]
            for k, name in enumerate(members):
                pvid = 1 if k == 0 else r.choice([1, 1, 10, 10, 20, 30])
                ports.append({".id": f"*{0x40 + k:X}", "interface": name, "bridge": "bridge", "pvid": str(pvid), "disabled": "false",
                              "frame-types": "admit-all" if k == 0 else "admit-only-untagged-and-priority-tagged", "ingress-filtering": "true",
                              "hw": "true", "hw-offload": "true"})
            trunk = members[0] if members else ""
            vlans = [{".id": "*80", "bridge": "bridge", "vlan-ids": "10", "tagged": f"bridge,{trunk}".strip(","), "untagged": "", "dynamic": "false", "comment": "Staff"},
                     {".id": "*81", "bridge": "bridge", "vlan-ids": "20", "tagged": f"bridge,{trunk}".strip(","), "untagged": "", "dynamic": "false", "comment": "Guest"},
                     {".id": "*82", "bridge": "bridge", "vlan-ids": "30,40", "tagged": trunk, "untagged": "", "dynamic": "false", "comment": "Cameras / IoT"}]
            st["sw"] = {"next": 0x100, "ethernet": eth, "ports": ports, "vlans": vlans,
                        "bridges": [{".id": "*B1", "name": "bridge", "vlan-filtering": "true" if self.id % 3 else "false", "pvid": "1", "comment": "LAN"}]}
        return st["sw"]

    def port_data(self):
        sw = copy.deepcopy(self._sw())
        status = self.status()
        ifs = status["interfaces"]
        r = random.Random(self.id * 23)
        mon = {i["name"]: {"name": i["name"], "status": "link-ok" if i["running"] else "no-link", "rate": (i.get("speed") or "1Gbps") if i["running"] else ""} for i in ifs if i["type"] == "ether"}
        poe = {e["name"]: {"name": e["name"], "poe-out-status": "powered-on" if mon.get(e["name"], {}).get("status") == "link-ok" else "waiting-for-load",
                           "poe-out-power": f"{r.uniform(3, 12):.1f}W" if mon.get(e["name"], {}).get("status") == "link-ok" else ""} for e in sw["ethernet"] if e.get("poe-out")}
        hosts, leases = [], []
        for k, p in enumerate(sw["ports"]):
            if mon.get(p["interface"], {}).get("status") == "link-ok":
                mac = "AC:1F:6B:%02X:%02X:%02X" % (self.id, k, r.randint(0, 255))
                hosts.append({"mac-address": mac, "on-interface": p["interface"], "bridge": "bridge", "vid": p["pvid"], "local": "false"})
                leases.append({"mac-address": mac, "active-mac-address": mac, "host-name": r.choice(["NVR-01", "Printer-HP", "AP-Lobby", "POS-1", "Desk-PC", "Camera-Door", ""]),
                               "active-address": f"192.168.{self.id * 10}.{50 + k}"})
        return {**sw, "monitor": mon, "poe": poe, "interfaces": [{"name": i["name"], "type": i["type"], "running": "true" if i["running"] else "false",
                                                                  "disabled": "false", "comment": i.get("comment") or ""} for i in ifs],
                "vlan_ifs": [{"name": "vlan10-staff", "vlan-id": "10", "interface": "bridge"}, {"name": "vlan20-guest", "vlan-id": "20", "interface": "bridge"}],
                "hosts": hosts, "neighbors": [], "leases": leases, "arp": [],
                "addresses": [{"address": f"192.168.{self.id * 10}.1/24", "interface": "bridge"}, {"address": "10.10.10.1/24", "interface": "vlan10-staff"},
                              {"address": "10.20.20.1/24", "interface": "vlan20-guest"}],
                "routes": [{"immediate-gw": "203.0.113.1%ether1"}], "switch_vlans": []}

    def _sw_find(self, menu, rid):
        sw = self._sw()
        rows = {"": sw["bridges"], "/port": sw["ports"], "/vlan": sw["vlans"], "eth": sw["ethernet"]}[menu]
        row = next((x for x in rows if x[".id"] == rid), None)
        if row is None:
            raise RouterError(f"HTTP 404: no such item ({rid})")
        return rows, row

    def br_set(self, menu, rid, props):
        rows, row = self._sw_find(menu, rid)
        row.update({k: str(v) for k, v in props.items()})
        return dict(row)

    def br_add(self, menu, props):
        sw = self._sw()
        row = {".id": f"*{sw['next']:X}", "dynamic": "false", **{k: str(v) for k, v in props.items()}}
        sw["next"] += 1
        {"": sw["bridges"], "/port": sw["ports"], "/vlan": sw["vlans"]}[menu].append(row)
        return dict(row)

    def br_remove(self, menu, rid):
        rows, row = self._sw_find(menu, rid)
        rows.remove(row)

    def eth_set(self, rid, props):
        rows, row = self._sw_find("eth", rid)
        row.update({k: str(v) for k, v in props.items()})


    def health(self):
        t = time.time()
        r = random.Random(int(t // 300) + self.id)
        day = math.sin((t % 86400) / 86400 * 2 * math.pi)   # warmer in the afternoon
        out = [{"name": "cpu-temperature", "value": round(48 + 6 * day + r.uniform(-1, 1) + self.id % 5, 1), "unit": "°C"},
               {"name": "board-temperature1", "value": round(38 + 5 * day + r.uniform(-1, 1), 1), "unit": "°C"},
               {"name": "voltage", "value": round(24.1 + r.uniform(-0.15, 0.15), 1), "unit": "V"}]
        if self.board == "ccr2004":
            out += [{"name": "fan1-speed", "value": 5100 + r.randint(-120, 120), "unit": "RPM"},
                    {"name": "power-consumption", "value": round(18 + r.uniform(-1, 1), 1), "unit": "W"}]
        return out

    def set_identity(self, name):
        self.name = name   # the poller builds SimRouter with the stored name, so the new identity "sticks" once saved
        return name

    def set_controller_port(self, port):
        self._sim()["controller_port"] = int(port)

    def session_user_add(self, name, group, password, only_from, note):
        users = self._sim().setdefault("users", {})
        if name in users:
            raise RouterError("HTTP 400: failure: user with the same name already exists")
        users[name] = {"group": group, "address": f"{only_from}/32", "comment": f"TikManager Winbox session: {note}"}

    def session_user_remove(self, name):
        self._sim().setdefault("users", {}).pop(name, None)

    def session_users(self):
        return list(self._sim().setdefault("users", {}))

    def winbox_service(self):
        st = self._sim().setdefault("winbox", {"id": "*2", "disabled": self.id % 4 == 0, "port": 8291,
                                               "address": "192.168.88.0/24" if self.id % 3 == 0 else ""})
        return dict(st)

    def winbox_allow(self, ip, enable=False):
        st = self._sim().setdefault("winbox", self.winbox_service())
        addrs = [a for a in st["address"].split(",") if a]
        if addrs and f"{ip}/32" not in addrs:
            st["address"] = ",".join(addrs + [f"{ip}/32"])
        if enable and st["disabled"]:
            st["disabled"] = False
            if not addrs:
                st["address"] = f"{ip}/32"
        return dict(st)

    def mikrotik_neighbors(self):
        lan = self.networks()[0]["network"].rsplit(".", 1)[0]
        r = random.Random(self.id * 7)
        mac = lambda p: p + ":" + ":".join(f"{r.randint(0, 255):02X}" for _ in range(3))
        out = [{"interface": "ether3", "address": f"{lan}.3", "mac-address": mac("4C:5E:0C"), "identity": f"AP-{self.name[:8]}",
                "platform": "MikroTik", "board": "cAP ax", "version": "7.19.4 (stable)", "software-id": f"{r.randint(1000, 9999)}-ABCD",
                "uptime": "12d4h", "discovered-by": "mndp"}]
        if self.id % 2:
            out.append({"interface": "ether4", "address": f"{lan}.4", "mac-address": mac("D4:01:C3"), "identity": "MikroTik",
                        "platform": "MikroTik", "board": "hEX S", "version": "6.49.10 (long-term)", "uptime": "203d1h", "discovered-by": "mndp"})
        return out

    def networks(self):
        lan = "192.168.88" if self.id % 3 == 0 else f"192.168.{self.id * 10}"   # every third one keeps the MikroTik default (overlaps)
        nets = [{"name": "LAN", "interface": "bridge", "address": f"{lan}.1/24", "network": f"{lan}.0/24"},
                {"name": "Guest", "interface": "vlan20-guest", "address": f"10.{self.id}.20.1/24", "network": f"10.{self.id}.20.0/24"}]
        if self.id % 2:
            nets.append({"name": "Phones", "interface": "vlan30-voip", "address": f"10.{self.id}.30.1/24", "network": f"10.{self.id}.30.0/24"})
        return nets

    def status(self) -> dict:
        if self._sim().get("down_until", 0) > time.time():
            raise RouterError("Unreachable over the tunnel: timed out")
        if random.Random(self.id * 7919 + int(time.time() // 900)).random() < 0.05:
            raise RouterError("Unreachable over the tunnel: timed out")
        t = time.time()
        r = random.Random(int(t // 60) + self.id)
        boot = t - self.r.randint(3600, 90 * 86400)
        up = int(t - boot)
        n = self.r.randint(4, 10)
        mac = lambda k: "48:A9:8A:%02X:%02X:%02X" % (self.id % 256, k, self.r.randint(0, 255))
        main_down = self.id % 4 == 0 and random.Random(int(t // 600) * 13 + self.id).random() < 0.15   # LTE takes over
        ifaces = [{"name": "ether1", "type": "ether", "running": not main_down, "disabled": False, "comment": "WAN", "speed": "" if main_down else "1Gbps",
                   "ip": f"203.0.113.{self.id % 250 + 2}", "default_route": not main_down}]
        ifaces += [{"name": f"ether{i}", "type": "ether", "running": (up_ := self.r.random() > 0.3), "disabled": False, "comment": "",
                    "speed": self.r.choice(["1Gbps", "100Mbps"]) if up_ else ""} for i in range(2, n)]
        if self.board in ("rb5009", "ccr2004"):   # a fibre uplink with optical readings
            ifaces += [{"name": "sfp-sfpplus1", "type": "ether", "running": True, "disabled": False, "comment": "Fibre to core", "speed": "10Gbps",
                        "sfp": {"rx": round(-6.2 + r.uniform(-0.3, 0.3), 2), "tx": round(-2.1 + r.uniform(-0.1, 0.1), 2),
                                "temp": round(41 + r.uniform(-1, 1), 1), "volt": 3.29}}]
        ifaces += [{"name": "bridge", "type": "bridge", "running": True, "disabled": False, "comment": "LAN"},
                   {"name": "vlan20-guest", "type": "vlan", "running": True, "disabled": False, "comment": "Guest", "vlan_id": "20", "parent": "bridge"}]
        if self.board in ("hap-ax3",):
            ifaces += [{"name": "wifi1", "type": "wifi", "running": True, "disabled": False, "comment": "", "ssid": "Office", "band": "5ghz-ax",
                        "freq": "5180", "mode": "ap"},
                       {"name": "wifi2", "type": "wifi", "running": True, "disabled": False, "comment": "", "ssid": "Office", "band": "2ghz-ax",
                        "freq": "2437", "mode": "ap"}]
        if self.board != "hap-ax3" and (self.id % 5 == 0 or self.id % 7 == 0):
            ifaces += [{"name": "wlan1", "type": "wlan", "running": True, "disabled": False, "comment": "PtP to Tower2" if self.id % 5 == 0 else "Sector North",
                        "ssid": "PTP-Tower2" if self.id % 5 == 0 else "WISP-North", "band": "5ghz-a/n/ac", "freq": "5745" if self.id % 5 == 0 else "5260",
                        "mode": "station-bridge" if self.id % 5 == 0 else "ap-bridge"}]
        if self.id % 4 == 0:
            ifaces += [{"name": "lte1", "type": "lte", "running": True, "disabled": False, "comment": "Backup WAN", "operator": "T-Mobile",
                        "ip": f"100.72.{self.id}.{int(t // 86400) % 200 + 10}", "default_route": main_down,
                        "rsrp": str(-80 - self.r.randint(0, 35)), "rsrq": str(-8 - self.r.randint(0, 9)), "sinr": str(self.r.randint(-2, 22)),
                        "rssi": str(-55 - self.r.randint(0, 30)), "cell": str(self.r.randint(10 ** 6, 10 ** 7)), "band_lte": "B66", "access": "LTE"}]
        ifaces += [{"name": "tikmanager", "type": "wg", "running": True, "disabled": False, "comment": "TikManager"}]
        for k, i in enumerate(ifaces):
            rate = (self.r.randint(2, 80) * 1_000_000 if k == 0 else self.r.randint(0, 20) * 1_000_000) / 8
            i["rx"] = int(rate * up * (0.6 + 0.4 * r.random()))
            i["tx"] = int(rate * 0.35 * up)
            i["rx_bps"] = round(rate * 8 * (0.3 + r.random()), 0) if i["running"] else 0.0
            i["tx_bps"] = round(rate * 8 * 0.3 * (0.3 + r.random()), 0) if i["running"] else 0.0
            i["mac"] = mac(k) if i["type"] in ("ether", "bridge", "vlan", "wifi", "wlan") else ""
            i["mtu"] = "1420" if i["type"] == "wg" else "1500"
        total = {"rb5009": 1024, "hap-ax3": 1024, "ccr2004": 4096, "hex-s": 256, "chr": 2048}[self.board] * 1024 * 1024
        return self._apply_sim({"identity": self.name, "version": self.r.choice(["7.16.2 (stable)", "7.18.1 (stable)", "7.19.4 (stable)", "7.20 (stable)"]),
                "board": self.model, "uptime": f"{up // 86400}d{(up % 86400) // 3600}h{(up % 3600) // 60}m",
                "cpu": max(1, min(100, int(self.r.randint(2, 25) + r.gauss(0, 6)))), "mem_total": total,
                "mem_used": int(total * (0.25 + 0.3 * self.r.random())), "model": self.model,
                "serial": f"HG{self.r.randint(10000000, 99999999):X}" if self.board != "chr" else None,
                "wan_ip": f"203.0.113.{self.id % 250 + 2}", "networks": self.networks(), "hdd_total": 128 * 1024 * 1024, "hdd_free": self.r.randint(30, 100) * 1024 * 1024,
                "bad_blocks": "0", "fw_current": (fw := self.r.choice(["7.16.2", "7.18.1", "7.19.4"])) if self.board != "chr" else "",
                "fw_upgrade": (self.r.choice([fw, "7.19.4"]) if self.board != "chr" else ""),
                "fw_factory": {"rb5009": "7.1.5", "hap-ax3": "7.7", "ccr2004": "6.48.6", "hex-s": "3.41"}.get(self.board, ""), "interfaces": ifaces})

    def _apply_sim(self, st):
        sim = self._sim()
        if sim.get("version"):
            st["version"] = sim["version"]
        if st["fw_current"]:
            st["fw_upgrade"] = st["version"].split(" ")[0]   # RouterOS ships the matching RouterBOARD firmware
            if isinstance(sim.get("fw"), str):   # (the simulated firewall also lives under "fw" - only a version string is firmware)
                st["fw_current"] = sim["fw"]
        return st
