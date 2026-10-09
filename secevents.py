"""Security events: sign-in attempts (and a few related events) from TikManager itself, its Ubuntu server and the routers.

- TikManager: failed passwords / MFA codes / Microsoft sign-ins, account lock-outs, rate-limited sign-in attempts,
  rejected adoption attempts, and successful sign-ins (server.py records them here).
- Ubuntu server: SSH sign-ins (failed and accepted), sudo password failures and fail2ban blocks, collected every 5
  minutes as root by deploy/collect-auth.py into /var/lib/tikmanager-update/auth-events.json, which is imported here.
- Routers: they already send their log to TikManager (set up at adoption, topics info/warning/error/critical) over the
  WireGuard tunnel; this listens on the controller's tunnel address only (WG_SERVER_IP:TM_SYSLOG_PORT, UDP) and keeps
  login failures, logins and "changed by" lines. TikManager's own REST logins are left out (one a minute per router).
- Kept 90 days. summary() adds warning flags: password guessing, a success right after failures, one address trying
  several systems, and TikManager's own router login failing.
"""
import hashlib
import json
import re
import socket
import threading
import time
import traceback
from pathlib import Path

KEEP_DAYS = 90
FAIL_KINDS = ("login_failed", "mfa_failed", "sudo_failed", "locked", "rate_limited", "adoption_rejected")
SOURCES = ("tikmanager", "server", "router")
AUTH_FILES = [Path("/var/lib/tikmanager-update/auth-events.json")]

RE_FAIL = re.compile(r"login failure for user (\S*) from (\S+) via (\S+)")
RE_OK = re.compile(r"user (\S+) logged in(?: from (\S+))? via (\S+)")
RE_CHANGE = re.compile(r"(.{1,120}?) (added|changed|removed|moved) by (\S+)")
RE_WHO = re.compile(r"([\w.\-]+)@([0-9A-Fa-f.:]+)\)?$")


def parse_router(line: str):
    """One router log line -> (kind, user, ip, via, detail) or None for lines we don't keep."""
    msg = re.sub(r"^<\d+>", "", line).strip()
    if m := RE_FAIL.search(msg):
        return "login_failed", m.group(1), m.group(2), m.group(3), ""
    if m := RE_OK.search(msg):
        return "login_ok", m.group(1), m.group(2) or "", m.group(3), ""
    if m := RE_CHANGE.search(msg):
        who = m.group(3)
        w = RE_WHO.search(who)
        user, ip = (w.group(1), w.group(2)) if w else (who.split(":")[-1], "")
        return "config_change", user, ip, "", msg[msg.find(m.group(1)):][:300]
    return None


class SecurityEvents:
    def __init__(self, db, settings):
        self.db, self.s = db, settings
        self.auth_files = AUTH_FILES + [Path(settings.data_dir) / "auth-events.json"]   # the second: dev mode
        self._auth_mtime = 0
        self._limited = {}   # (kind, ip) -> last recorded, so a flood of refused requests is one event per 5 minutes
        self._devmap, self._devmap_at = {}, 0
        self.lock = threading.Lock()

    # --- recording ----------------------------------------------------------------------------------------
    def record(self, source, kind, user="", ip="", via="", detail="", device_id=None, ts=None, uid=None, throttle=False):
        if throttle:   # repeated refusals from one address: one event per 5 minutes is enough
            key, now = (kind, ip), time.time()
            with self.lock:
                if now - self._limited.get(key, 0) < 300:
                    return
                self._limited[key] = now
        clip = lambda v, n: re.sub(r"[\x00-\x1f\x7f]", " ", str(v or ""))[:n]
        self.db.run("INSERT OR IGNORE INTO sec_events (ts, source, kind, user, ip, device_id, via, detail, uid) VALUES (?,?,?,?,?,?,?,?,?)",
                    (ts or time.time(), source, kind, clip(user, 120), clip(ip, 64), device_id, clip(via, 40), clip(detail, 400), uid))

    # --- router logs (syslog over the tunnel) ---------------------------------------------------------------
    def _device_for(self, ip):
        if time.time() - self._devmap_at > 60:
            rows = self.db.q("SELECT id, tunnel_ip FROM devices WHERE state='adopted' AND tunnel_ip IS NOT NULL ORDER BY id")
            self._devmap = {r["tunnel_ip"]: r["id"] for r in rows}
            if getattr(self.s, "dev", False) and rows:   # dev: test messages come from this PC
                self._devmap["127.0.0.1"] = rows[0]["id"]
            self._devmap_at = time.time()
        return self._devmap.get(ip)

    def handle_syslog(self, data: bytes, src_ip: str):
        dev = self._device_for(src_ip)
        if dev is None:   # only routers TikManager manages, over their tunnel
            return
        got = parse_router(data[:2048].decode("utf-8", "replace"))
        if not got:
            return
        kind, user, ip, via, detail = got
        if kind == "login_ok" and user == "tikmanager" and via in ("rest-api", "api", "api-ssl"):
            return   # TikManager's own polling
        if kind == "login_ok" and via == "local":
            ip = "console"
        self.record("router", kind, user, ip, via, detail, device_id=dev)

    def syslog_loop(self):
        host = "127.0.0.1" if getattr(self.s, "dev", False) else self.s.wg_server_ip
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((host, int(self.s.syslog_port)))
                print(f"  Router logs: listening on {host}:{self.s.syslog_port}/udp")
                while True:
                    data, (src, _port) = sock.recvfrom(4096)
                    try:
                        self.handle_syslog(data, src)
                    except Exception:  # noqa: BLE001 - one odd line never stops the listener
                        traceback.print_exc()
            except OSError as e:   # e.g. wg0 not up yet: try again shortly
                print(f"  Router logs: can't listen on {host}:{self.s.syslog_port} ({e}) - retrying in a minute")
                time.sleep(60)

    # --- the Ubuntu server's sign-ins (collected as root by deploy/collect-auth.py) -------------------------
    def import_server(self):
        for f in self.auth_files:
            try:
                st = f.stat()
            except OSError:
                continue
            if st.st_mtime == self._auth_mtime or st.st_size > 4 * 1024 * 1024:
                return
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            for e in (data.get("events") or [])[-5000:]:
                if not isinstance(e, dict) or e.get("kind") not in FAIL_KINDS + ("login_ok", "banned"):
                    continue
                uid = "srv:" + hashlib.sha1(json.dumps(e, sort_keys=True).encode()).hexdigest()
                self.record("server", e["kind"], e.get("user"), e.get("ip"), e.get("via"), e.get("detail"), ts=float(e.get("ts") or 0) or None, uid=uid)
            self._auth_mtime = st.st_mtime
            return

    def loop(self):
        last_prune = 0
        while True:
            try:
                self.import_server()
                if time.time() - last_prune > 86400:
                    self.db.run("DELETE FROM sec_events WHERE ts < ?", (time.time() - KEEP_DAYS * 86400,))
                    last_prune = time.time()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(60)

    def start(self):
        threading.Thread(target=self.syslog_loop, daemon=True, name="router-logs").start()
        threading.Thread(target=self.loop, daemon=True, name="sec-events").start()

    # --- the Security page ----------------------------------------------------------------------------------
    def summary(self, hours=24, source="", kind="", q=""):
        since = time.time() - hours * 3600
        rows = self.db.q("""SELECT e.*, d.name AS device FROM sec_events e LEFT JOIN devices d ON d.id = e.device_id
                            WHERE e.ts >= ? ORDER BY e.ts""", (since,))
        fails = [r for r in rows if r["kind"] in FAIL_KINDS]
        totals = {s: {"failed": sum(1 for r in fails if r["source"] == s), "ok": sum(1 for r in rows if r["source"] == s and r["kind"] == "login_ok"),
                      "banned": sum(1 for r in rows if r["source"] == s and r["kind"] == "banned"),
                      "changes": sum(1 for r in rows if r["source"] == s and r["kind"] == "config_change")} for s in SOURCES}
        where = lambda r: r["device"] or {"tikmanager": "TikManager", "server": "Ubuntu server"}.get(r["source"], r["source"])
        ips = {}
        for r in fails:
            if not r["ip"] or r["ip"] == "console":
                continue
            a = ips.setdefault(r["ip"], {"ip": r["ip"], "count": 0, "targets": set(), "users": {}, "last": 0, "hours": {}, "banned": False})
            a["count"] += 1
            a["targets"].add(where(r))
            a["users"][r["user"] or "?"] = a["users"].get(r["user"] or "?", 0) + 1
            a["last"] = max(a["last"], r["ts"])
            h = int(r["ts"] // 3600)
            a["hours"][h] = a["hours"].get(h, 0) + 1
        for r in rows:
            if r["kind"] == "banned" and r["ip"] in ips:
                ips[r["ip"]]["banned"] = True
        flags = []
        for a in ips.values():
            peak = max(a["hours"].values())
            if peak >= 10:
                flags.append({"level": "warn", "ip": a["ip"], "key": f"guess:{a['ip']}", "text": f"{a['ip']} tried to sign in {a['count']} times ({peak} in one hour) - "
                                                                   f"password guessing on {', '.join(sorted(a['targets'])[:4])}"})
            if len(a["targets"]) >= 3:
                flags.append({"level": "warn", "ip": a["ip"], "key": f"spread:{a['ip']}", "text": f"{a['ip']} tried {len(a['targets'])} different systems: {', '.join(sorted(a['targets'])[:6])}"})
        for r in rows:   # a success right after a run of failures from the same address (or for the same user there)
            if r["kind"] != "login_ok":
                continue
            before = [f for f in fails if r["ts"] - 3600 <= f["ts"] < r["ts"] and f["source"] == r["source"] and f["device_id"] == r["device_id"]
                      and ((r["ip"] and f["ip"] == r["ip"]) or (r["user"] and f["user"] == r["user"]))]
            if len(before) >= 5:
                flags.append({"level": "bad", "ip": r["ip"], "key": f"success:{r['source']}:{r['device_id']}:{r['user']}:{r['ip']}", "text": f"{r['user'] or 'someone'} signed in to {where(r)} from {r['ip'] or 'an unknown address'} "
                                                                     f"after {len(before)} failed attempts in the hour before - check it was really them"})
        tm = {}
        for r in fails:
            if r["source"] == "router" and r["user"] == "tikmanager":
                tm[where(r)] = tm.get(where(r), 0) + 1
        for name, n in tm.items():
            flags.append({"level": "warn", "ip": "", "key": f"tmuser:{name}", "text": f"Sign-in as TikManager's own user failed {n} time(s) on {name} - someone is guessing it, "
                                                             "or its password was changed on the router"})
        top = sorted(ips.values(), key=lambda a: -a["count"])[:25]
        for a in top:
            a["targets"] = sorted(a["targets"])
            a["users"] = [u for u, _ in sorted(a["users"].items(), key=lambda x: -x[1])[:5]]
            del a["hours"]
        per_router = {}
        for r in fails:
            if r["source"] == "router":
                per_router[r["device"] or "?"] = per_router.get(r["device"] or "?", 0) + 1
        ql = (q or "").lower()
        ev = [r for r in rows if (not source or r["source"] == source) and (not kind or r["kind"] == kind or (kind == "failed" and r["kind"] in FAIL_KINDS))
              and (not ql or ql in " ".join(str(r[k] or "") for k in ("user", "ip", "device", "via", "detail")).lower())]
        return {"hours": hours, "totals": totals, "flags": flags, "top_ips": top,
                "routers": sorted(({"name": k, "count": v} for k, v in per_router.items()), key=lambda x: -x["count"])[:15],
                "events": [{k: r[k] for k in ("ts", "source", "kind", "user", "ip", "device", "device_id", "via", "detail")} for r in reversed(ev[-500:])],
                "total_events": len(ev)}

    def seed_dev(self):
        """Dev mode: sample events so the page has something to show (marked "sample")."""
        if self.db.one("SELECT COUNT(*) AS n FROM sec_events")["n"]:
            return
        devs = [d["id"] for d in self.db.q("SELECT id FROM devices WHERE state='adopted' ORDER BY id")]
        now = time.time()
        for i in range(14):
            self.record("router", "login_failed", "admin", "203.0.113.66", "winbox", "sample", device_id=devs[i % len(devs)] if devs else None, ts=now - 3000 + i * 60)
        for i in range(6):
            self.record("server", "login_failed", ["root", "ubuntu", "test"][i % 3], "198.51.100.23", "ssh", "sample: invalid user", ts=now - 7000 + i * 30)
        self.record("server", "banned", "", "198.51.100.23", "fail2ban", "sample: sshd", ts=now - 6800)
        self.record("server", "login_ok", "alan", "10.0.20.15", "ssh", "sample: publickey", ts=now - 1800)
        for i in range(5):
            self.record("tikmanager", "login_failed", "office@client.example", "192.0.2.44", "password", "sample", ts=now - 5000 + i * 40)
        self.record("tikmanager", "locked", "office@client.example", "192.0.2.44", "password", "sample", ts=now - 4800)
        if devs:
            for i in range(6):
                self.record("router", "login_failed", "admin", "10.0.20.31", "ssh", "sample", device_id=devs[0], ts=now - 900 + i * 20)
            self.record("router", "login_ok", "admin", "10.0.20.31", "ssh", "sample", device_id=devs[0], ts=now - 700)
            self.record("router", "config_change", "admin", "10.0.20.31", "", "sample: filter rule changed", device_id=devs[0], ts=now - 650)
            self.record("router", "login_failed", "tikmanager", "10.77.0.1", "rest-api", "sample", device_id=devs[-1], ts=now - 400)
