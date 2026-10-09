"""Talks to a router over its WireGuard tunnel with the RouterOS v7 REST API (http://<tunnel ip>/rest/...).
Plain HTTP is fine here: the traffic never leaves the encrypted WireGuard tunnel, and the router only accepts it from the
controller's tunnel address.

SimRouter stands in for real routers in dev mode (TM_DEV=1) so the whole app can be built and tested without hardware.
"""
import base64
import copy
import json
import random
import time
import hashlib
import re
import urllib.error
import urllib.parse
import urllib.request

VPN_TAG = "TikManager VPN"   # comment on every object the site-to-site VPN adds, so it can be removed exactly
VPN_IFACE = "tikmanager-vpn"


class RouterError(Exception):
    pass


class RouterOS:
    def __init__(self, ip, user, password, timeout=8, port=80):
        self.base = f"http://{ip}/rest" if int(port) == 80 else f"http://{ip}:{int(port)}/rest"
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.timeout = timeout

    def _req(self, method, path, body=None, timeout=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            if e.code == 401:
                raise RouterError("The router refused TikManager's login (was the tikmanager user changed?)") from None
            raise RouterError(f"HTTP {e.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RouterError(f"Unreachable over the tunnel: {getattr(e, 'reason', e)}") from None

    def get(self, path):
        return self._req("GET", path)

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
        return {"identity": ident, "version": res.get("version"), "board": res.get("board-name"), "uptime": res.get("uptime"),
                "cpu": int(res.get("cpu-load") or 0), "mem_total": int(res.get("total-memory") or 0),
                "mem_used": int(res.get("total-memory") or 0) - int(res.get("free-memory") or 0),
                "model": rb.get("model") or res.get("board-name"), "serial": rb.get("serial-number"),
                "hdd_free": int(res.get("free-hdd-space") or 0), "hdd_total": int(res.get("total-hdd-space") or 0),
                "bad_blocks": res.get("bad-blocks") or "0", "fw_current": rb.get("current-firmware") or "", "fw_upgrade": rb.get("upgrade-firmware") or "",
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
    }

    def vpn_inventory(self) -> dict:
        out = {}
        for menu, keep in self.INVENTORY.items():
            rows = self.optional(lambda menu=menu: self.get(menu), []) or []
            rows = [rows] if isinstance(rows, dict) else rows
            out[menu] = [{k: r[k] for k in keep if k in r} for r in rows if isinstance(r, dict)]
        return out

    # --- site-to-site VPN (vpn.py drives these) - everything TikManager adds carries the comment VPN_TAG ------------
    def wg_ensure(self, name, port):
        """Create (or keep) the WireGuard interface; the router makes and keeps the private key. Returns its public key."""
        rows = self.get(f"/interface/wireguard?name={urllib.parse.quote(name)}") or []
        if rows:
            if str(rows[0].get("listen-port")) != str(port):
                self._req("PATCH", f"/interface/wireguard/{rows[0]['.id']}", {"listen-port": str(port)})
        else:
            self._req("PUT", "/interface/wireguard", {"name": name, "listen-port": str(port), "mtu": "1420", "comment": VPN_TAG})
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

    def wg_peers(self, name):
        """[{public_key, handshake_age (seconds or None), rx, tx}] for the VPN interface's peers."""
        out = []
        for p in self.optional(lambda: self.get(f"/interface/wireguard/peers?interface={urllib.parse.quote(name)}"), []) or []:
            out.append({"public_key": p.get("public-key"), "handshake_age": _dur_s(p.get("last-handshake")),
                        "rx": int(p.get("rx") or 0), "tx": int(p.get("tx") or 0)})
        return out

    # --- firewall filter / NAT rules (firewall.py drives these, with an automatic undo) -------------------------------
    FW_MENUS = {"filter": "/ip/firewall/filter", "nat": "/ip/firewall/nat"}

    def fw_rules(self, section):
        return self.get(self.FW_MENUS[section]) or []

    def fw_address_lists(self):
        """Names of the address lists on the router (only the name of each entry is read - lists can be large)."""
        return sorted({x.get("list") for x in self.get("/ip/firewall/address-list?.proplist=list") or [] if x.get("list")})

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
            self._req("PUT", "/system/script", {"name": name, "source": script, "policy": "read,write,policy,test",
                                                "comment": "TikManager: puts the firewall back if a change isn't kept"}, timeout=30)
        for s in self.get(f"/system/scheduler?name={q}") or []:
            self._req("DELETE", f"/system/scheduler/{s['.id']}", timeout=20)
        self._req("PUT", "/system/scheduler", {"name": name, "interval": delay, "on-event": f"/system script run {name}",
                                               "policy": "read,write,policy,test",
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
            r = self._req("POST", "/execute", {"script": cmd, "as-string": ""}, timeout=90)
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
            r = random.Random(self.id)
            st["fw"] = {}
            st["fw_next"] = 1
            for sec, rules in (("filter", filt), ("nat", nat)):
                st["fw"][sec] = []
                for x in rules:
                    st["fw"][sec].append({".id": f"*{st['fw_next']:X}", "disabled": "false", "dynamic": "false", "invalid": "false",
                                          "bytes": str(r.randint(0, 9 * 10 ** 9)), "packets": str(r.randint(0, 9 * 10 ** 6)), **x})
                    st["fw_next"] += 1
            st["sched"], st["undo"] = {}, {}
        return st

    def fw_rules(self, section):
        self._fw_expire()
        return [dict(x) for x in self._fw()["fw"][section]]

    def fw_address_lists(self):
        return ["blocklist", "office-ips", "trusted-admins"]

    def _fw_find(self, section, rid):
        rules = self._fw()["fw"][section]
        i = next((k for k, x in enumerate(rules) if x[".id"] == rid), None)
        if i is None:
            raise RouterError(f"HTTP 404: no such item ({rid})")
        return rules, i

    def fw_add(self, section, props, before=None):
        st = self._fw()
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
        if script is not None:
            st["undo"][name] = copy.deepcopy(st["fw"])
        st["sched"][name] = time.time() + int(delay.rstrip("m")) * 60

    def undo_run(self, name):
        st = self._fw()
        if name in st["undo"]:
            st["fw"] = copy.deepcopy(st["undo"][name])
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
        return inv

    # simulated site-to-site VPN: a tunnel is "up" when both ends have each other as peers
    def wg_ensure(self, name, port):
        st = self._sim()
        st.setdefault("vpn", {})
        return base64.b64encode(hashlib.sha256(f"sim-wg-{self.id}".encode()).digest()).decode()

    def vpn_clear(self, name, remove_interface=False):
        self._sim().pop("vpn_cfg", None)

    def vpn_apply(self, name, cfg):
        time.sleep(0.5)
        self._sim()["vpn_cfg"] = cfg

    def wg_peers(self, name):
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

    def set_identity(self, name):
        self.name = name   # the poller builds SimRouter with the stored name, so the new identity "sticks" once saved
        return name

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
        ifaces = [{"name": "ether1", "type": "ether", "running": True, "disabled": False, "comment": "WAN", "speed": "1Gbps"}]
        ifaces += [{"name": f"ether{i}", "type": "ether", "running": (up_ := self.r.random() > 0.3), "disabled": False, "comment": "",
                    "speed": self.r.choice(["1Gbps", "100Mbps"]) if up_ else ""} for i in range(2, n)]
        ifaces += [{"name": "bridge", "type": "bridge", "running": True, "disabled": False, "comment": "LAN"},
                   {"name": "vlan20-guest", "type": "vlan", "running": True, "disabled": False, "comment": "Guest", "vlan_id": "20", "parent": "bridge"}]
        if self.board in ("hap-ax3",):
            ifaces += [{"name": "wifi1", "type": "wifi", "running": True, "disabled": False, "comment": "", "ssid": "Office", "band": "5ghz-ax",
                        "freq": "5180", "mode": "ap"},
                       {"name": "wifi2", "type": "wifi", "running": True, "disabled": False, "comment": "", "ssid": "Office", "band": "2ghz-ax",
                        "freq": "2437", "mode": "ap"}]
        if self.id % 4 == 0:
            ifaces += [{"name": "lte1", "type": "lte", "running": True, "disabled": False, "comment": "Backup WAN", "operator": "T-Mobile",
                        "rsrp": str(-80 - self.r.randint(0, 35)), "rsrq": str(-8 - self.r.randint(0, 9)), "sinr": str(self.r.randint(-2, 22)),
                        "rssi": str(-55 - self.r.randint(0, 30)), "cell": str(self.r.randint(10 ** 6, 10 ** 7)), "band_lte": "B66", "access": "LTE"}]
        ifaces += [{"name": "tikmanager", "type": "wg", "running": True, "disabled": False, "comment": "TikManager"}]
        for k, i in enumerate(ifaces):
            rate = (self.r.randint(2, 80) * 1_000_000 if k == 0 else self.r.randint(0, 20) * 1_000_000) / 8
            i["rx"] = int(rate * up * (0.6 + 0.4 * r.random()))
            i["tx"] = int(rate * 0.35 * up)
            i["rx_bps"] = round(rate * 8 * (0.3 + r.random()), 0) if i["running"] else 0.0
            i["tx_bps"] = round(rate * 8 * 0.3 * (0.3 + r.random()), 0) if i["running"] else 0.0
            i["mac"] = mac(k) if i["type"] in ("ether", "bridge", "vlan", "wifi") else ""
            i["mtu"] = "1420" if i["type"] == "wg" else "1500"
        total = {"rb5009": 1024, "hap-ax3": 1024, "ccr2004": 4096, "hex-s": 256, "chr": 2048}[self.board] * 1024 * 1024
        return self._apply_sim({"identity": self.name, "version": self.r.choice(["7.16.2 (stable)", "7.18.1 (stable)", "7.19.4 (stable)", "7.20 (stable)"]),
                "board": self.model, "uptime": f"{up // 86400}d{(up % 86400) // 3600}h{(up % 3600) // 60}m",
                "cpu": max(1, min(100, int(self.r.randint(2, 25) + r.gauss(0, 6)))), "mem_total": total,
                "mem_used": int(total * (0.25 + 0.3 * self.r.random())), "model": self.model,
                "serial": f"HG{self.r.randint(10000000, 99999999):X}" if self.board != "chr" else None,
                "wan_ip": f"203.0.113.{self.id % 250 + 2}", "networks": self.networks(), "hdd_total": 128 * 1024 * 1024, "hdd_free": self.r.randint(30, 100) * 1024 * 1024,
                "bad_blocks": "0", "fw_current": (fw := self.r.choice(["7.16.2", "7.18.1", "7.19.4"])) if self.board != "chr" else "",
                "fw_upgrade": (self.r.choice([fw, "7.19.4"]) if self.board != "chr" else ""), "interfaces": ifaces})

    def _apply_sim(self, st):
        sim = self._sim()
        if sim.get("version"):
            st["version"] = sim["version"]
        if st["fw_current"]:
            st["fw_upgrade"] = st["version"].split(" ")[0]   # RouterOS ships the matching RouterBOARD firmware
            if sim.get("fw"):
                st["fw_current"] = sim["fw"]
        return st
