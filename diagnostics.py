"""Diagnostics: on-demand tests a technician runs against one router, each producing a saved report.

- Traffic Watch (torch): watch live traffic on an interface for a set number of minutes, then report who is using the
  connection - top talkers, top connections, protocols, total data each way and throughput over time. Torch is sampled
  in short windows and the rates are integrated into byte totals (short calls keep each request well under any proxy
  timeout, and let the report fill in while the test runs).
- Speed Test (fetch): measure the router's own internet download speed by fetching a CDN endpoint sized to the router's
  free storage, plus latency and jitter. Upload isn't included: RouterOS /tool/fetch can't source a large POST body.

Each run is a row in diag_runs and runs in its own background thread. Cancelling sets the row to 'cancelled' and the
thread notices at its next sample.
"""
import ipaddress
import json
import threading
import time
import traceback

from routeros import RouterError


def _in_net(ip, flt):
    """Is `ip` inside the address/subnet filter `flt` (e.g. 192.168.1.50 or 192.168.1.0/24)?"""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(flt, strict=False)
    except ValueError:
        return False

SAMPLE_SECS = 3                 # torch sample window
TORCH_MAX_MIN = 15              # cap on a Traffic Watch run
SPEED_FLOOR = 3_000_000         # smallest test download (bytes) - for tiny-flash boards
SPEED_CEIL = 90_000_000         # largest test download (bytes) - Cloudflare's __down rejects >= 100 MB with HTTP 403
SPEED_DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"   # {bytes} = the size to request
SPEED_PING = "1.1.1.1"

# Friendly names for the common service ports, for the report.
SERVICES = {"443": "HTTPS", "80": "HTTP", "53": "DNS", "22": "SSH", "25": "SMTP", "465": "SMTP", "587": "SMTP",
            "993": "IMAP", "143": "IMAP", "110": "POP3", "123": "NTP", "3389": "RDP", "3478": "STUN/VoIP",
            "5060": "SIP", "5061": "SIP", "1194": "OpenVPN", "51820": "WireGuard", "500": "IPsec", "4500": "IPsec",
            "20": "FTP", "21": "FTP", "389": "LDAP", "636": "LDAPS", "445": "SMB", "8080": "HTTP-alt", "8443": "HTTPS-alt"}


class DiagError(ValueError):
    pass


def _service(proto, port):
    name = SERVICES.get(str(port))
    if name:
        return name
    return f"{proto or 'ip'}{('/' + str(port)) if port else ''}"


class Diagnostics:
    def __init__(self, db, client_for, settings=None):
        self.db, self.client_for, self.settings = db, client_for, settings
        self.running = set()
        self.lock = threading.Lock()

    def speed_base(self):
        return (getattr(self.settings, "speedtest_url", None) or SPEED_DEFAULT_URL)

    # --- starting a run ---------------------------------------------------------------------------------------
    def start_torch(self, device, iface, minutes, src_filter, user):
        minutes = max(1, min(TORCH_MAX_MIN, int(minutes or 1)))
        rid = self.db.run("""INSERT INTO diag_runs (org_id, device_id, kind, iface, params, status, progress, started_at, created_by, created_at)
                             VALUES (?,?,'torch',?,?,'running',0,?,?,?)""",
                          (device["org_id"], device["id"], iface or "", json.dumps({"minutes": minutes, "filter": src_filter or ""}),
                           time.time(), user, time.time()))
        self.db.event(device["id"], device["org_id"], "diagnostics", f"Traffic Watch started ({minutes} min) by {user}")
        threading.Thread(target=self._run_torch, args=(rid, device["id"], iface, minutes, src_filter), daemon=True, name=f"diag-torch-{rid}").start()
        return rid

    def start_speed(self, device, iface, user):
        rid = self.db.run("""INSERT INTO diag_runs (org_id, device_id, kind, iface, params, status, progress, started_at, created_by, created_at)
                             VALUES (?,?,'speedtest',?,'{}','running',0,?,?,?)""",
                          (device["org_id"], device["id"], iface or "", time.time(), user, time.time()))
        self.db.event(device["id"], device["org_id"], "diagnostics", f"Speed Test started by {user}")
        threading.Thread(target=self._run_speed, args=(rid, device["id"], iface), daemon=True, name=f"diag-speed-{rid}").start()
        return rid

    def cancel(self, rid, user):
        n = self.db.run("UPDATE diag_runs SET status='cancelled', finished_at=? WHERE id=? AND status='running'", (time.time(), rid))
        if n:
            self.db.audit(user, "diagnostics cancelled", str(rid))
        return bool(n)

    # --- helpers ----------------------------------------------------------------------------------------------
    def _cancelled(self, rid):
        r = self.db.one("SELECT status FROM diag_runs WHERE id=?", (rid,))
        return not r or r["status"] != "running"

    def _fail(self, rid, msg):
        self.db.run("UPDATE diag_runs SET status='failed', error=?, finished_at=? WHERE id=? AND status='running'",
                    (str(msg)[:500], time.time(), rid))

    def _wan_iface(self, cl):
        """The router's internet-facing interface (the one the default route uses), for the Traffic Watch default."""
        try:
            ifaces = cl.status().get("interfaces") or []
        except RouterError:
            return ""
        wan = next((i["name"] for i in ifaces if i.get("default_route")), None)
        if wan:
            return wan
        return next((i["name"] for i in ifaces if i.get("running") and i.get("type") == "ether"), "")

    # --- Traffic Watch (connection tracking) ------------------------------------------------------------------
    def _run_torch(self, rid, device_id, iface, minutes, src_filter):
        with self.lock:
            self.running.add(rid)
        try:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))
            if not d or not d["online"]:
                return self._fail(rid, "The router is offline, so the traffic test couldn't run.")
            cl = self.client_for(d)
            flt = (src_filter or "").strip()
            flows, series = {}, []    # flows: key -> running totals with per-connection byte counters
            start = time.time()
            end = start + minutes * 60
            n, last_t = 0, None
            while time.time() < end:
                if self._cancelled(rid):
                    return
                t0 = time.time()
                try:
                    rows = cl.connections()
                except RouterError as e:
                    return self._fail(rid, f"Couldn't read the connection table on {d['name']}: {e}")
                if flt:
                    rows = [r for r in rows if _in_net(r["src"], flt) or _in_net(r["dst"], flt)]
                window = 0.0
                for r in rows:
                    key = (r["src"], r["dst"], r["proto"], r["port"])
                    o, p = r["orig_bytes"], r["repl_bytes"]
                    f = flows.get(key)
                    if not f:   # first sight: record the baseline, count only growth from here on
                        flows[key] = {"src": r["src"], "dst": r["dst"], "proto": r["proto"], "port": r["port"],
                                      "last_o": o, "last_r": p, "acc_o": 0.0, "acc_r": 0.0}
                        continue
                    do = o - f["last_o"] if o >= f["last_o"] else o   # a drop = the connection was replaced (counter reset)
                    dr = p - f["last_r"] if p >= f["last_r"] else p
                    f["acc_o"] += do
                    f["acc_r"] += dr
                    f["last_o"], f["last_r"] = o, p
                    window += do + dr
                dt = (t0 - last_t) if last_t else SAMPLE_SECS
                series.append({"t": int(t0), "bps": round(window * 8 / max(1, dt))})
                last_t = t0
                n += 1
                done = min(0.99, (time.time() - start) / (minutes * 60))
                if n % 5 == 0:   # store a partial report so the open report page fills in live
                    self.db.run("UPDATE diag_runs SET progress=?, result=? WHERE id=? AND status='running'",
                                (round(done, 3), json.dumps(self._torch_report(flows, series, start, flt)), rid))
                else:
                    self.db.run("UPDATE diag_runs SET progress=? WHERE id=? AND status='running'", (round(done, 3), rid))
                time.sleep(max(0, SAMPLE_SECS - (time.time() - t0)))
            if self._cancelled(rid):
                return
            report = self._torch_report(flows, series, start, flt)
            self.db.run("UPDATE diag_runs SET status='done', progress=1, result=?, finished_at=? WHERE id=? AND status='running'",
                        (json.dumps(report), time.time(), rid))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._fail(rid, f"Error: {e}")
        finally:
            with self.lock:
                self.running.discard(rid)

    def _torch_report(self, flows, series, start, flt=""):
        vals = [{"src": f["src"], "dst": f["dst"], "proto": f["proto"], "port": f["port"],
                 "tx": f.get("acc_o", f.get("tx", 0.0)), "rx": f.get("acc_r", f.get("rx", 0.0))} for f in flows.values()]
        vals = [f for f in vals if f["tx"] or f["rx"]]
        total_tx = sum(f["tx"] for f in vals)
        total_rx = sum(f["rx"] for f in vals)

        def top(group_key, limit):
            agg = {}
            for f in vals:
                k = group_key(f)
                a = agg.get(k)
                if not a:
                    a = agg[k] = {"key": k, "tx": 0.0, "rx": 0.0}
                a["tx"] += f["tx"]
                a["rx"] += f["rx"]
            rows = sorted(agg.values(), key=lambda a: a["tx"] + a["rx"], reverse=True)[:limit]
            return [{**a, "bytes": round(a["tx"] + a["rx"]), "tx": round(a["tx"]), "rx": round(a["rx"])} for a in rows]

        hosts = top(lambda f: f["src"] or "?", 10)
        dests = top(lambda f: f["dst"] or "?", 10)
        protos = []
        for a in top(lambda f: f"{f['proto']}|{f['port']}", 10):
            proto, _, port = a["key"].partition("|")
            protos.append({"service": _service(proto, port), "bytes": a["bytes"], "tx": a["tx"], "rx": a["rx"]})
        conns = sorted(vals, key=lambda f: f["tx"] + f["rx"], reverse=True)[:20]
        connections = [{"src": f["src"], "dst": f["dst"], "service": _service(f["proto"], f["port"]),
                        "proto": f["proto"], "port": f["port"], "tx": round(f["tx"]), "rx": round(f["rx"]),
                        "bytes": round(f["tx"] + f["rx"])} for f in conns]
        # down-sample the time series so a long run still draws cleanly (<= ~180 points)
        pts = series
        if len(pts) > 180:
            step = len(pts) // 180 + 1
            pts = [{"t": pts[i]["t"], "bps": round(sum(p["bps"] for p in pts[i:i + step]) / len(pts[i:i + step]))}
                   for i in range(0, len(pts), step)]
        return {"kind": "torch", "scope": flt or "all traffic through the router", "duration_s": round(time.time() - start), "samples": len(series),
                "total_tx": round(total_tx), "total_rx": round(total_rx), "total": round(total_tx + total_rx),
                "peak_bps": max((p["bps"] for p in series), default=0), "hosts_seen": len({f["src"] for f in vals}),
                "connections_seen": len(vals), "top_hosts": hosts, "top_dests": dests, "protocols": protos,
                "connections": connections, "series": pts}

    # --- Speed Test (fetch) -----------------------------------------------------------------------------------
    def _run_speed(self, rid, device_id, iface):
        with self.lock:
            self.running.add(rid)
        try:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))
            if not d or not d["online"]:
                return self._fail(rid, "The router is offline, so the speed test couldn't run.")
            cl = self.client_for(d)
            try:
                st = cl.status()
            except RouterError as e:
                return self._fail(rid, f"Couldn't read {d['name']}: {e}")
            free = int(st.get("hdd_free") or 0)
            size = int(max(SPEED_FLOOR, min(SPEED_CEIL, free * 0.4))) if free else 20_000_000
            url = self.speed_base().format(bytes=size)
            lat = cl.latency(SPEED_PING, count=10)
            best, last = None, {}
            for _ in range(2):
                if self._cancelled(rid):
                    return
                try:
                    last = cl.speedtest(url, size, timeout=max(60, size // 1_000_000 + 40))
                except RouterError as e:
                    return self._fail(rid, f"The download test couldn't run on {d['name']}: {e}")
                if last.get("ok") and last.get("mbps"):
                    best = last if (not best or last["mbps"] > best["mbps"]) else best
            if not best:
                status = last.get("status") or "no result"
                if "permission" in status.lower():   # the router user can't run /tool fetch - it needs the 'ftp' policy
                    return self._fail(rid, f"The download test couldn't run (fetch status: {status}). TikManager's router user needs the "
                                           "'ftp' policy to download. On the router (as an admin) run: /user group set [find name=tikmanager] "
                                           "policy=read,write,policy,test,api,rest-api,sensitive,reboot,ftp")
                return self._fail(rid, f"The download test didn't complete (fetch status: {status}). Check the router's internet "
                                       "access and DNS, that /tool fetch is allowed by its device-mode, and that it has room in flash. "
                                       "A pure switch with no internet route won't be able to run it.")
            report = {"kind": "speedtest", "iface": iface or "", "down_mbps": best["mbps"], "bytes": best["bytes"],
                      "secs": best["secs"], "size_mb": round(size / 1_000_000, 1), "source": url.split("?")[0],
                      "latency": lat, "note": "A rough internet reachability/latency check - NOT a line-rate speed test. It's a single "
                      "stream saved to the router's storage, so flash-write speed and single-stream TCP cap the download well below a fast "
                      "link's real rate (a gigabit link will read far lower). Trust the latency, jitter and loss; use the download only to tell "
                      "'working' from 'badly degraded'. For true throughput use a browser speed test on a PC behind the router, or a "
                      "router-to-router bandwidth test."}
            self.db.run("UPDATE diag_runs SET status='done', progress=1, result=?, finished_at=? WHERE id=? AND status='running'",
                        (json.dumps(report), time.time(), rid))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._fail(rid, f"Error: {e}")
        finally:
            with self.lock:
                self.running.discard(rid)

    # --- for the server: a run row decoded for the API --------------------------------------------------------
    def row(self, r):
        r = dict(r)
        r["params"] = json.loads(r.get("params") or "{}")
        r["result"] = json.loads(r["result"]) if r.get("result") else None
        return r
