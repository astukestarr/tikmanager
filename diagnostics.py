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
import json
import threading
import time
import traceback

from routeros import RouterError

SAMPLE_SECS = 3                 # torch sample window
TORCH_MAX_MIN = 15              # cap on a Traffic Watch run
SPEED_FLOOR = 3_000_000         # smallest test download (bytes) - for tiny-flash boards
SPEED_CEIL = 120_000_000        # largest test download (bytes)
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

    # --- Traffic Watch (torch) --------------------------------------------------------------------------------
    def _run_torch(self, rid, device_id, iface, minutes, src_filter):
        with self.lock:
            self.running.add(rid)
        try:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))
            if not d or not d["online"]:
                return self._fail(rid, "The router is offline, so the traffic test couldn't run.")
            cl = self.client_for(d)
            if not iface:
                iface = self._wan_iface(cl)
                if iface:
                    self.db.run("UPDATE diag_runs SET iface=? WHERE id=?", (iface, rid))
            if not iface:
                return self._fail(rid, "Couldn't work out which interface to watch - pick one and try again.")
            flows, series = {}, []
            start = time.time()
            end = start + minutes * 60
            n = 0
            while time.time() < end:
                if self._cancelled(rid):
                    return
                t0 = time.time()
                try:
                    rows = cl.torch(iface, SAMPLE_SECS, src=src_filter or None)
                except RouterError as e:
                    return self._fail(rid, f"Torch failed on {d['name']}: {e}")
                window_bps = 0
                for r in rows:
                    key = (r["src"], r["dst"], r["proto"], r["port"])
                    f = flows.get(key)
                    if not f:
                        f = flows[key] = {"src": r["src"], "dst": r["dst"], "proto": r["proto"], "port": r["port"], "tx": 0.0, "rx": 0.0}
                    f["tx"] += (r["tx_bps"] or 0) * SAMPLE_SECS / 8.0
                    f["rx"] += (r["rx_bps"] or 0) * SAMPLE_SECS / 8.0
                    window_bps += (r["tx_bps"] or 0) + (r["rx_bps"] or 0)
                series.append({"t": int(t0), "bps": round(window_bps)})
                n += 1
                done = min(0.99, (time.time() - start) / (minutes * 60))
                if n % 5 == 0:   # store a partial report so the open report page fills in live
                    self.db.run("UPDATE diag_runs SET progress=?, result=? WHERE id=? AND status='running'",
                                (round(done, 3), json.dumps(self._torch_report(iface, flows, series, start)), rid))
                else:
                    self.db.run("UPDATE diag_runs SET progress=? WHERE id=? AND status='running'", (round(done, 3), rid))
                time.sleep(max(0, SAMPLE_SECS - (time.time() - t0)))
            if self._cancelled(rid):
                return
            report = self._torch_report(iface, flows, series, start)
            self.db.run("UPDATE diag_runs SET status='done', progress=1, result=?, finished_at=? WHERE id=? AND status='running'",
                        (json.dumps(report), time.time(), rid))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._fail(rid, f"Error: {e}")
        finally:
            with self.lock:
                self.running.discard(rid)

    def _torch_report(self, iface, flows, series, start):
        vals = list(flows.values())
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
        return {"kind": "torch", "iface": iface, "duration_s": round(time.time() - start), "samples": len(series),
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
            best = None
            for _ in range(2):
                if self._cancelled(rid):
                    return
                try:
                    r = cl.speedtest(url, size, timeout=max(60, size // 1_000_000 + 40))
                except RouterError as e:
                    return self._fail(rid, f"The download test couldn't run on {d['name']}: {e}")
                if r.get("ok") and r.get("mbps"):
                    best = r if (not best or r["mbps"] > best["mbps"]) else best
            if not best:
                return self._fail(rid, "The download test didn't complete - the router couldn't fetch the test file "
                                       "(check its internet access, DNS and that HTTPS fetch is allowed).")
            report = {"kind": "speedtest", "iface": iface or "", "down_mbps": best["mbps"], "bytes": best["bytes"],
                      "secs": best["secs"], "size_mb": round(size / 1_000_000, 1), "source": url.split("?")[0],
                      "latency": lat, "note": "Download only. Timed on the controller side, so small samples on a fast link read low."}
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
