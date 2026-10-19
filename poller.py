"""Polls every adopted router over its tunnel about once a minute: status, interfaces, traffic rate; records online/offline
changes as events and keeps a week of metrics for the charts."""
import json
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from routeros import RouterError, RouterOS, SimRouter, _dur_s
from security import derive

POLL_SECONDS = 60
CHART_TYPES = {"ether", "vlan", "bridge", "wlan", "wifi", "lte", "pppoe-out", "wg", "sstp-out", "ovpn-out", "l2tp-out", "bond"}
KEEP_METRICS = 7 * 86400
INVENTORY_SECONDS = 15 * 60
HEALTH_SECONDS = 300
ISP_RE = re.compile(r"\b(isp|wan|internet|starlink|dsl|lte|5g)\d*\b", re.I)
KEEP_HEALTH = 30 * 86400


class Poller:
    def __init__(self, db, s, key):
        self.db, self.s, self.key = db, s, key
        self._prev = {}   # device id -> (time, rx, tx) for rate calculation
        self.thumbs = None   # thumbs.Thumbs, set by the server
        self._prev_if = {}   # device id -> {interface: (time, rx bytes, tx bytes)}
        self._gps = {}   # device id -> when its GPS was last read (every 6 hours)
        self._tls_down, self._tls_said = {}, {}   # device id -> when HTTPS last failed / when that was last recorded
        self._last_prune = 0

    def client(self, d):
        if self.s.dev:
            return SimRouter(d["id"], d["name"])
        tls = d.get("api_tls_port") if time.time() - self._tls_down.get(d["id"], 0) > 600 else None   # HTTPS failed just now: HTTP for 10 min
        cl = RouterOS(d["tunnel_ip"], "tikmanager", derive(self.key, f"router-api:{d['id']}"), port=d.get("api_port") or 80, tls_port=tls,
                      tls_fp=d.get("api_tls_fp") or None)
        if tls:
            cl.on_fallback = lambda why, d=d: self._tls_fallback(d, why)
            cl.on_tls_seen = lambda fp, d=d: self._tls_first(d, fp)
            cl.on_cert_changed = lambda fp, d=d: self._tls_changed(d, fp)
        return cl

    def _tls_first(self, d, fp):
        """No pinned certificate yet (switched before pinning): trust this one from now on."""
        if self.db.run("UPDATE devices SET api_tls_fp=? WHERE id=? AND (api_tls_fp IS NULL OR api_tls_fp='')", (fp, d["id"])) is not None:
            d["api_tls_fp"] = fp

    def _tls_changed(self, d, fp):
        """A different HTTPS certificate: keep it aside for a technician to trust, and say so once per new certificate."""
        cur = self.db.one("SELECT api_tls_new FROM devices WHERE id=?", (d["id"],)) or {}
        if cur.get("api_tls_new") != fp:
            self.db.run("UPDATE devices SET api_tls_new=? WHERE id=?", (fp, d["id"]))
            self.db.event(d["id"], d["org_id"], "https certificate changed",
                          f"The router's HTTPS certificate changed (now SHA-256 {fp}, trusted {d.get('api_tls_fp')}). TikManager won't use it - or fall "
                          "back to HTTP - until a technician trusts it on the router's Settings tab. Expected if the certificate was renewed or replaced; "
                          "if nobody changed it, find out why first.")

    def _tls_fallback(self, d, why):
        """HTTPS to a router that's set to use it didn't connect, and the client went on over HTTP: say so (every 6 hours at most)."""
        first = d["id"] not in self._tls_down
        last = self._tls_said.get(d["id"], 0)
        self._tls_down[d["id"]] = time.time()
        if first or time.time() - last > 6 * 3600:
            self._tls_said[d["id"]] = time.time()
            self.db.event(d["id"], d["org_id"], "https fallback",
                          f"HTTPS to the router didn't connect ({why[:150]}) - TikManager used HTTP instead. Check www-ssl on the router "
                          "(on, certificate, port), or switch the router back to HTTP on its Settings tab.")

    @staticmethod
    def isp_links(ifaces, chosen=None):
        """The router's internet (ISP) links: the interfaces picked on its page, else those whose comment says ISP / WAN /
        internet / Starlink / DSL / LTE / 5G, PPPoE clients and LTE modems; else the one the default route uses (or ether1)."""
        if chosen:
            return [i for i in ifaces if i.get("name") in chosen]
        auto = [i for i in ifaces if ISP_RE.search(i.get("comment") or "") or i.get("type") in ("pppoe-out", "lte")]
        return auto or [i for i in ifaces if i.get("default_route")] or [i for i in ifaces if i.get("name") == "ether1"]

    def track_isp(self, d, ifaces, now):
        """Each internet link's state; events when one goes down, comes back or changes its address."""
        try:
            chosen = json.loads(d.get("isp_ifaces") or "null")
            old = json.loads(d.get("isp_state") or "{}")
        except ValueError:
            chosen, old = None, {}
        new = {}
        for i in self.isp_links(ifaces, chosen):
            n, up, addr = i["name"], bool(i.get("running")) and not i.get("disabled"), i.get("ip") or ""
            o = old.get(n)
            label = f"{n}" + (f" ({i['comment']})" if i.get("comment") else "")
            if o and o["up"] != up:
                self.db.event(d["id"], d["org_id"], "link up" if up else "link down",
                              f"Internet link {label} is {'back up' if up else 'down'}" + (f" - address {addr}" if up and addr else ""))
            elif o and up and o.get("addr") and addr and addr != o["addr"]:
                self.db.event(d["id"], d["org_id"], "link address", f"Internet link {label} changed address: {o['addr']} -> {addr}")
            new[n] = {"up": up, "addr": addr or (o or {}).get("addr", ""), "since": o["since"] if o and o["up"] == up else now,
                      "comment": i.get("comment") or "", "type": i.get("type") or "", "active": bool(i.get("default_route"))}
        self.db.run("UPDATE devices SET isp_state=? WHERE id=?", (json.dumps(new), d["id"]))

    def track_bgp(self, d, cl, now):
        """Only on routers that run BGP: an enabled BGP instance (RouterOS 7.20+), or - on versions without instances -
        configured connections. For each enabled connection to one peer (not a listening range), is a session
        established? (A connection is the configured peer; its session is the live state, missing while the peer never
        answers.) Events when one goes down or comes back; NULL state when the router has no BGP."""
        try:
            inv = json.loads(d.get("vpn_inv") or "null") or {}
            old = json.loads(d.get("bgp_state") or "{}") or {}
        except ValueError:
            inv, old = {}, {}
        yes = lambda v: str(v).lower() in ("true", "yes")
        inst = inv.get("/routing/bgp/instance") or []

        def peer_ip(addr):   # "10.10.7.100/32" is one peer; "10.20.0.0/16" is a listening range (dynamic peers) - None
            ip, _, pfx = str(addr or "").partition("/")
            return ip if not pfx or pfx == ("128" if ":" in ip else "32") else None
        conns = [c for c in inv.get("/routing/bgp/connection") or [] if not yes(c.get("disabled")) and peer_ip(c.get("remote.address"))]
        live = {i.get("name") for i in inst if not yes(i.get("disabled"))}
        if inst:   # 7.20+: only connections of an enabled instance count
            conns = [c for c in conns if not c.get("instance") or c.get("instance") in live]
        if not conns or (inst and not live):
            if d.get("bgp_state"):
                self.db.run("UPDATE devices SET bgp_state=NULL, bgp_at=NULL WHERE id=?", (d["id"],))
            return
        try:
            sessions = cl.bgp_sessions()
        except RouterError:
            return   # keep the last known state
        new = {}
        for c in conns:
            ra = peer_ip(c.get("remote.address"))
            name = c.get("name") or ra
            s = next((x for x in sessions if x.get("name") == name or str(x.get("name") or "").startswith(name + "-")), None) \
                or next((x for x in sessions if ra and str(x.get("remote.address") or "").split(":")[0] == ra), None)
            up = bool(s) and yes(s.get("established"))
            o = old.get(name)
            peer = f"{name} ({ra}" + (f", AS {c.get('remote.as')}" if c.get("remote.as") else "") + ")"
            if o and o.get("up") != up:
                self.db.event(d["id"], d["org_id"], "bgp up" if up else "bgp down", f"BGP peer {peer} is {'established again' if up else 'down'}")
            new[name] = {"up": up, "remote": ra, "as": c.get("remote.as") or (s or {}).get("remote.as") or "", "role": c.get("local.role") or "",
                         "since": o["since"] if o and o.get("up") == up and o.get("since") else now, "uptime": (s or {}).get("uptime") or "",
                         "prefixes": (s or {}).get("prefix-count") or "", "comment": c.get("comment") or ""}
        self.db.run("UPDATE devices SET bgp_state=?, bgp_at=? WHERE id=?", (json.dumps(new), now, d["id"]))

    def check_bgp(self, d):
        """Check now (router page): read the BGP settings and the sessions straight away instead of waiting for the poll."""
        cl = self.client(d)
        self.collect_vpns(d, cl)
        d = self.db.one("SELECT * FROM devices WHERE id=?", (d["id"],)) or d
        self.track_bgp(d, cl, time.time())
        return self.db.one("SELECT bgp_state, bgp_at FROM devices WHERE id=?", (d["id"],))

    def check_reboot(self, d, st, now):
        """A restart between two polls shows as uptime going back (also when it was too quick to look offline)."""
        new, old = _dur_s(st.get("uptime")), _dur_s(d.get("uptime"))
        if new is None or old is None or not d.get("last_seen"):
            return
        if new + 90 < old + (now - d["last_seen"]):
            at = now - new
            upgrading = self.db.one("SELECT 1 FROM upgrades WHERE device_id=? AND (status='running' OR finished_at > ?)", (d["id"], now - 1800))
            why = "upgrade" if upgrading else "unexpected"
            self.db.run("UPDATE devices SET last_reboot=?, last_reboot_why=? WHERE id=?", (at, why, d["id"]))
            was = f"{old // 86400}d {old % 86400 // 3600}h" if old >= 86400 else f"{old // 3600}h {old % 3600 // 60}m"
            self.db.event(d["id"], d["org_id"], "rebooted", f"Restarted at {time.strftime('%Y-%m-%d %H:%M', time.localtime(at))}"
                          + (" (upgrade)" if upgrading else f" - it had been up {was}"))

    @staticmethod
    def wan_counters(ifaces):
        wan = [i for i in ifaces if "wan" in (i.get("comment") or "").lower()] or [i for i in ifaces if i.get("name") == "ether1"]
        return sum(i.get("rx", 0) for i in wan), sum(i.get("tx", 0) for i in wan)

    def poll_one(self, d):
        now = time.time()
        try:
            st = self.client(d).status()
        except RouterError as e:
            self.db.run("UPDATE devices SET online=0, last_poll=?, last_error=? WHERE id=?", (now, str(e)[:300], d["id"]))
            if d["online"]:
                self.db.event(d["id"], d["org_id"], "offline", str(e)[:300])
            return
        rx, tx = self.wan_counters(st["interfaces"])
        rx_bps = tx_bps = None
        prev = self._prev.get(d["id"])
        if prev and now > prev[0] and rx >= prev[1] and tx >= prev[2]:   # average over the last minute from the byte counters
            rx_bps, tx_bps = (rx - prev[1]) * 8 / (now - prev[0]), (tx - prev[2]) * 8 / (now - prev[0])
        self._prev[d["id"]] = (now, rx, tx)
        wan = [i for i in st["interfaces"] if "wan" in (i.get("comment") or "").lower()] or [i for i in st["interfaces"] if i.get("name") == "ether1"]
        if wan and all(i.get("rx_bps") is not None and i.get("tx_bps") is not None for i in wan):   # prefer the router's own live rate
            rx_bps, tx_bps = sum(i["rx_bps"] for i in wan), sum(i["tx_bps"] for i in wan)
        self.db.run("UPDATE devices SET wan_ip=?, networks=?, hdd_free=?, hdd_total=?, bad_blocks=?, fw_current=?, fw_upgrade=?, fw_factory=? WHERE id=?",
                    (st.get("wan_ip"), json.dumps(st.get("networks") or []), st.get("hdd_free"), st.get("hdd_total"), st.get("bad_blocks"), st.get("fw_current"), st.get("fw_upgrade"),
                     st.get("fw_factory") or None, d["id"]))
        # the name follows the router's identity unless someone renamed it in TikManager
        self.db.run("""UPDATE devices SET online=1, last_poll=?, last_seen=?, last_error=NULL, identity=?, model=?, serial=COALESCE(?, serial),
                       version=?, board=?, uptime=?, cpu=?, mem_used=?, mem_total=?, interfaces=?,
                       name=CASE WHEN name_custom=0 AND COALESCE(?, '') <> '' THEN ? ELSE name END WHERE id=?""",
                    (now, now, st["identity"], st["model"], st["serial"], st["version"], st["board"], st["uptime"], st["cpu"],
                     st["mem_used"], st["mem_total"], json.dumps(st["interfaces"]), st["identity"], st["identity"], d["id"]))
        self.check_reboot(d, st, now)
        self.track_isp(d, st["interfaces"], now)
        cl = self.client(d)
        # location from the router's own GPS (if it has one) - never over a location someone entered by hand
        if d.get("loc_source") != "manual" and hasattr(cl, "gps") and now - self._gps.get(d["id"], 0) > 6 * 3600:
            self._gps[d["id"]] = now
            try:
                fix = cl.gps()
            except RouterError:
                fix = None
            if fix:
                self.db.run("UPDATE devices SET lat=?, lon=?, loc_source='gps', location=COALESCE(location, 'GPS') WHERE id=? AND "
                            "COALESCE(loc_source, '') <> 'manual'", (round(fix[0], 6), round(fix[1], 6), d["id"]))
        try:
            latency, loss = cl.ping(getattr(self.s, "ping_target", "") or "1.1.1.1") if hasattr(cl, "ping") else (None, None)
        except RouterError:
            latency, loss = None, None
        self.db.run("INSERT INTO metrics (device_id, ts, cpu, mem_pct, rx_bps, tx_bps, latency, loss) VALUES (?,?,?,?,?,?,?,?)",
                    (d["id"], now, st["cpu"], round(100 * st["mem_used"] / st["mem_total"], 1) if st["mem_total"] else None, rx_bps, tx_bps,
                     latency, loss))
        # per-interface traffic for the interface picker on the router page
        prev_if = self._prev_if.setdefault(d["id"], {})
        for i in st["interfaces"]:
            if i.get("type") not in CHART_TYPES or not i.get("running"):
                continue
            n = i["name"]
            irx, itx = i.get("rx_bps"), i.get("tx_bps")
            p = prev_if.get(n)
            if (irx is None or itx is None) and p and now > p[0] and i["rx"] >= p[1] and i["tx"] >= p[2]:
                irx, itx = (i["rx"] - p[1]) * 8 / (now - p[0]), (i["tx"] - p[2]) * 8 / (now - p[0])
            prev_if[n] = (now, i["rx"], i["tx"])
            if irx is not None:
                self.db.run("INSERT INTO iface_metrics (device_id, ts, name, rx_bps, tx_bps) VALUES (?,?,?,?,?)", (d["id"], now, n, irx, itx))
        if now - (d.get("vpn_inv_at") or 0) > INVENTORY_SECONDS:   # VPNs configured on the router (read-only)
            self.collect_vpns(d, cl)
            d = self.db.one("SELECT * FROM devices WHERE id=?", (d["id"],)) or d   # the fresh inventory (BGP connections)
        self.track_bgp(d, cl, now)
        if now - (d.get("neighbors_at") or 0) > INVENTORY_SECONDS and hasattr(cl, "mikrotik_neighbors"):   # for Discovered
            try:
                self.db.run("UPDATE devices SET neighbors=?, neighbors_at=? WHERE id=?", (json.dumps(cl.mikrotik_neighbors()), now, d["id"]))
            except RouterError:
                pass
        if now - (d.get("health_at") or 0) > HEALTH_SECONDS - 5:   # board sensors + fibre modules, every 5 minutes
            try:
                sensors = cl.health() if hasattr(cl, "health") else []
            except RouterError:
                sensors = []
            for i in st["interfaces"]:
                for k, unit in (("rx", "dBm"), ("tx", "dBm"), ("temp", "°C")):
                    if (i.get("sfp") or {}).get(k) is not None:
                        sensors.append({"name": f"sfp:{i['name']}:{k}", "value": i["sfp"][k], "unit": unit})
            for x in sensors:
                self.db.run("INSERT INTO health_metrics (device_id, ts, name, value) VALUES (?,?,?,?)", (d["id"], now, x["name"], x["value"]))
            self.db.run("UPDATE devices SET health=?, health_at=? WHERE id=?",
                        (json.dumps({x["name"]: {"value": x["value"], "unit": x["unit"]} for x in sensors}), now, d["id"]))
        if now - (d.get("dm_checked") or 0) > 3600 and hasattr(cl, "device_mode"):   # hourly: has RouterOS flagged itself?
            try:
                dm = cl.device_mode()
            except RouterError:
                dm = None   # RouterOS before 7.13 has no device-mode
            if dm and dm["flagged"] and not d.get("dm_flagged"):
                self.db.event(d["id"], d["org_id"], "flagged", "RouterOS flagged this router as possibly compromised (device-mode)")
            self.db.run("UPDATE devices SET dm_mode=?, dm_flagged=?, dm_info=?, dm_checked=? WHERE id=?",
                        ((dm or {}).get("mode"), 1 if dm and dm["flagged"] else 0, json.dumps(dm) if dm else None, now, d["id"]))
        if not d["online"]:
            self.db.event(d["id"], d["org_id"], "online", f"RouterOS {st['version']}, up {st['uptime']}")
        # product picture: matched once (retried daily if MikroTik's catalog had no match)
        if self.thumbs and not d.get("thumb_slug") and now - (d.get("thumb_tried") or 0) > 86400:
            slug = self.thumbs.slug_for(st.get("board"), st.get("model"))
            path = self.thumbs.path_for(slug) if slug else None
            if path or not slug and self.thumbs.catalog():   # only "give up for a day" when the catalog really had no match
                self.db.run("UPDATE devices SET thumb_slug=?, thumb_tried=? WHERE id=?", (slug if path else None, now, d["id"]))

    def collect_vpns(self, d, cl=None):
        try:
            inv = (cl or self.client(d)).vpn_inventory()
            self.db.run("UPDATE devices SET vpn_inv=?, vpn_inv_at=? WHERE id=?", (json.dumps(inv), time.time(), d["id"]))
            return True
        except RouterError:
            return False

    def run_once(self):
        due = self.db.q("SELECT * FROM devices WHERE state='adopted' AND (last_poll IS NULL OR last_poll < ?)", (time.time() - POLL_SECONDS + 5,))
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(self.poll_one, due))
        if time.time() - self._last_prune > 3600:
            self.rollup()
            self.db.run("DELETE FROM metrics WHERE ts < ?", (time.time() - KEEP_METRICS,))
            self.db.run("DELETE FROM iface_metrics WHERE ts < ?", (time.time() - KEEP_METRICS,))
            self.db.run("DELETE FROM health_metrics WHERE ts < ?", (time.time() - KEEP_HEALTH,))
            self.db.run("DELETE FROM metrics_hourly WHERE ts < ?", (time.time() - 90 * 86400,))
            self.db.run("DELETE FROM events WHERE ts < ?", (time.time() - 180 * 86400,))
            self._last_prune = time.time()

    def rollup(self):
        """Hourly averages of every complete hour not yet rolled up (kept 90 days, for the 1W/1M charts)."""
        hour = 3600
        end = int(time.time() // hour) * hour
        last = self.db.one("SELECT MAX(ts) AS t FROM metrics_hourly")["t"]
        start = int(last + hour) if last else end - 7 * 86400
        if start >= end:
            return
        self.db.run("""INSERT OR REPLACE INTO metrics_hourly (device_id, ts, iface, rx_bps, tx_bps, cpu, latency, loss)
                       SELECT device_id, CAST(ts / 3600 AS INTEGER) * 3600, '', AVG(rx_bps), AVG(tx_bps), AVG(cpu), AVG(latency), AVG(loss)
                       FROM metrics WHERE ts >= ? AND ts < ? GROUP BY device_id, CAST(ts / 3600 AS INTEGER)""", (start, end))
        self.db.run("""INSERT OR REPLACE INTO metrics_hourly (device_id, ts, iface, rx_bps, tx_bps)
                       SELECT device_id, CAST(ts / 3600 AS INTEGER) * 3600, name, AVG(rx_bps), AVG(tx_bps)
                       FROM iface_metrics WHERE ts >= ? AND ts < ? GROUP BY device_id, name, CAST(ts / 3600 AS INTEGER)""", (start, end))

    def loop(self):
        while True:
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - never let one bad poll stop monitoring
                traceback.print_exc()
            time.sleep(15)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="poller").start()
