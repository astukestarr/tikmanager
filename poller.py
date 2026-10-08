"""Polls every adopted router over its tunnel about once a minute: status, interfaces, traffic rate; records online/offline
changes as events and keeps a week of metrics for the charts."""
import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from routeros import RouterError, RouterOS, SimRouter
from security import derive

POLL_SECONDS = 60
CHART_TYPES = {"ether", "vlan", "bridge", "wlan", "wifi", "lte", "pppoe-out", "wg", "sstp-out", "ovpn-out", "l2tp-out", "bond"}
KEEP_METRICS = 7 * 86400
INVENTORY_SECONDS = 15 * 60


class Poller:
    def __init__(self, db, s, key):
        self.db, self.s, self.key = db, s, key
        self._prev = {}   # device id -> (time, rx, tx) for rate calculation
        self.thumbs = None   # thumbs.Thumbs, set by the server
        self._prev_if = {}   # device id -> {interface: (time, rx bytes, tx bytes)}
        self._last_prune = 0

    def client(self, d):
        if self.s.dev:
            return SimRouter(d["id"], d["name"])
        return RouterOS(d["tunnel_ip"], "tikmanager", derive(self.key, f"router-api:{d['id']}"), port=d.get("api_port") or 80)

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
        self.db.run("UPDATE devices SET wan_ip=?, networks=?, hdd_free=?, hdd_total=?, bad_blocks=?, fw_current=?, fw_upgrade=? WHERE id=?",
                    (st.get("wan_ip"), json.dumps(st.get("networks") or []), st.get("hdd_free"), st.get("hdd_total"), st.get("bad_blocks"), st.get("fw_current"), st.get("fw_upgrade"), d["id"]))
        # the name follows the router's identity unless someone renamed it in TikManager
        self.db.run("""UPDATE devices SET online=1, last_poll=?, last_seen=?, last_error=NULL, identity=?, model=?, serial=COALESCE(?, serial),
                       version=?, board=?, uptime=?, cpu=?, mem_used=?, mem_total=?, interfaces=?,
                       name=CASE WHEN name_custom=0 AND COALESCE(?, '') <> '' THEN ? ELSE name END WHERE id=?""",
                    (now, now, st["identity"], st["model"], st["serial"], st["version"], st["board"], st["uptime"], st["cpu"],
                     st["mem_used"], st["mem_total"], json.dumps(st["interfaces"]), st["identity"], st["identity"], d["id"]))
        cl = self.client(d)
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
