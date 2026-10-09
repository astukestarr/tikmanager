"""Alerts: problems TikManager notices, sent as ConnectWise tickets and / or Teams messages - opened when a problem starts
and closed when it clears.

- Every minute the conditions below are checked. A problem gets one row in `alerts` (key e.g. "offline:12") for as long
  as it lasts: when it starts, a ConnectWise ticket is opened (under the client's linked ConnectWise company, or the
  default company for server-wide problems) and / or a Teams card is posted; when it clears, the ticket gets an internal
  note and the closed status, and Teams gets a "resolved" card.
- Kinds (Alerts page > Settings turns each on / off and sets thresholds):
  offline (router offline N minutes - not while it's being upgraded), backup_failed (latest backup attempt failed),
  cpu (average over 15 minutes), firmware (new RouterOS on its channel), security (Security page warnings),
  server (server security check FAILs), website (Mozilla Observatory grade below A).
- No storms: if more than STORM routers go offline in the same minute (TikManager's own internet, most likely), one
  grouped alert is sent instead of one each.
"""
import hashlib
import json
import threading
import time
import traceback

from integrations import IntegrationError

STORM = 5


def short(text, n=95):
    """A title that fits a ticket summary (ConnectWise allows 100 characters): cut at a word, with an ellipsis."""
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0].rstrip(" -,;:") + "…"
KINDS = {   # kind -> (label, on by default, threshold name, default threshold)
    "offline": ("Router offline", True, "minutes", 5),
    "backup_failed": ("Configuration backup failed", True, None, None),
    "security": ("Security warnings (password guessing, a sign-in right after failures ...)", True, None, None),
    "server": ("Server security check finds a FAIL", True, None, None),
    "website": ("Website security grade drops below A", True, None, None),
    "cpu": ("Router CPU high (15-minute average)", False, "percent", 90),
    "firmware": ("New RouterOS available for a router", False, None, None),
}
DEFAULTS = {"kinds": {k: {"on": v[1], **({v[2]: v[3]} if v[2] else {})} for k, v in KINDS.items()},
            "cw": {"on": False, "board_id": None, "status_id": None, "closed_status_id": None, "priority_id": None, "company_id": None},
            "teams": {"on": False}}


class Alerts:
    def __init__(self, db, settings, integ, updates, observatory, secev):
        self.db, self.s, self.integ, self.updates, self.observatory, self.secev = db, settings, integ, updates, observatory, secev
        self.lock = threading.Lock()

    # --- settings ---------------------------------------------------------------------------------------------
    def settings(self):
        try:
            saved = json.loads(self.db.setting("alert_settings", "") or "{}")
        except ValueError:
            saved = {}
        out = json.loads(json.dumps(DEFAULTS))
        for k in ("cw", "teams"):
            out[k].update({x: y for x, y in (saved.get(k) or {}).items() if x in out[k]})
        for k, v in (saved.get("kinds") or {}).items():
            if k in out["kinds"]:
                out["kinds"][k].update({x: y for x, y in v.items() if x in out["kinds"][k]})
        return out

    def save(self, b):
        cur = self.settings()
        num = lambda v, lo, hi: max(lo, min(hi, int(v)))
        for k, v in (b.get("kinds") or {}).items():
            if k not in KINDS:
                continue
            cur["kinds"][k]["on"] = bool(v.get("on"))
            th = KINDS[k][2]
            if th and v.get(th) not in (None, ""):
                cur["kinds"][k][th] = num(v[th], 1, 1440) if th == "minutes" else num(v[th], 50, 100)
        cw = b.get("cw") or {}
        cur["cw"]["on"] = bool(cw.get("on"))
        for f in ("board_id", "status_id", "closed_status_id", "priority_id", "company_id"):
            if f in cw:
                cur["cw"][f] = int(cw[f]) if str(cw[f] or "").isdigit() else None
        if cur["cw"]["on"] and not cur["cw"]["board_id"]:
            raise ValueError("Pick the ConnectWise board tickets go to.")
        cur["teams"]["on"] = bool((b.get("teams") or {}).get("on"))
        if "teams_webhook" in b or b.get("teams_clear"):
            self.integ.save("teams", {"webhook": str(b.get("teams_webhook") or "")} if not b.get("teams_clear") else {"clear": ["webhook"]})
        if cur["teams"]["on"] and not self.integ.configured("teams"):
            raise ValueError("Paste the Teams workflow webhook URL first.")
        self.db.set_setting("alert_settings", json.dumps(cur))
        return cur

    # --- what's wrong right now -------------------------------------------------------------------------------
    def conditions(self, cfg):
        """{key: (kind, device_id, org_id, title, detail)} for every problem present now."""
        k, now, out = cfg["kinds"], time.time(), {}
        devs = self.db.q("""SELECT d.*, o.name AS org FROM devices d LEFT JOIN orgs o ON o.id = d.org_id WHERE d.state='adopted'""")
        upgrading = {r["device_id"] for r in self.db.q("SELECT device_id FROM upgrades WHERE status='running'")}
        label = lambda d: f"{d['name']}" + (f" ({d['org']})" if d.get("org") else "")
        if k["offline"]["on"]:
            limit = now - k["offline"]["minutes"] * 60
            for d in devs:
                if not d["online"] and d["id"] not in upgrading and (d["last_seen"] or d["adopted_at"] or now) < limit:
                    out[f"offline:{d['id']}"] = ("offline", d["id"], d["org_id"], f"{label(d)} is offline",
                                                 f"Not reachable over its tunnel since {time.strftime('%Y-%m-%d %H:%M', time.localtime(d['last_seen'] or now))}. "
                                                 f"Last error: {d['last_error'] or 'none'}")
        if k["backup_failed"]["on"]:
            for d in devs:
                if d["last_backup_error"] and (d["last_backup_try"] or 0) > (d["last_backup_at"] or 0):
                    out[f"backup:{d['id']}"] = ("backup_failed", d["id"], d["org_id"], f"Backup of {label(d)} failed", d["last_backup_error"])
        if k["cpu"]["on"]:
            pct = k["cpu"]["percent"]
            for r in self.db.q("SELECT device_id, AVG(cpu) AS c, COUNT(*) AS n FROM metrics WHERE ts > ? GROUP BY device_id", (now - 900,)):
                d = next((x for x in devs if x["id"] == r["device_id"]), None)
                open_ = self.db.one("SELECT 1 FROM alerts WHERE key=? AND resolved_at IS NULL", (f"cpu:{r['device_id']}",))
                if d and r["n"] >= 5 and (r["c"] >= pct or (open_ and r["c"] >= pct - 20)):
                    out[f"cpu:{d['id']}"] = ("cpu", d["id"], d["org_id"], f"{label(d)} CPU at {r['c']:.0f}%", f"15-minute average {r['c']:.0f}% (alert at {pct}%).")
        if k["firmware"]["on"]:
            for d in devs:
                cur = str(d["version"] or "").split(" ")[0]
                if d.get("ros_latest") and cur and d["ros_latest"] != cur:
                    out[f"fw:{d['id']}:{d['ros_latest']}"] = ("firmware", d["id"], d["org_id"], f"RouterOS {d['ros_latest']} is available for {label(d)}",
                                                              f"Running {cur}. Upgrade from its page or Upgrades.")
        if k["security"]["on"]:
            for f in self.secev.summary(1)["flags"]:
                key = f.get("key") or hashlib.sha1(f["text"].encode()).hexdigest()[:16]
                out[f"sec:{key}"] = ("security", None, None, short("Security: " + f["text"]), f["text"])
        if k["server"]["on"]:
            sec = self.updates.security()
            fails = [r["text"] for r in sec.get("results") or [] if r.get("status") == "fail"]
            if fails:
                out["server-check"] = ("server", None, None, f"Server security check: {len(fails)} to fix", "\n".join(f"- {x}" for x in fails))
        if k["website"]["on"]:
            o = self.observatory.info()
            if o.get("grade") and not str(o["grade"]).upper().startswith("A"):
                out["website"] = ("website", None, None, f"Website security grade is {o['grade']} ({o.get('host')})",
                                  f"{o.get('passed')} of {o.get('total')} Mozilla Observatory tests passed. Report: {o.get('url')}")
        return out

    # --- notifying ----------------------------------------------------------------------------------------------
    def _link(self, device_id):
        base = (getattr(self.s, "public_url", "") or "").rstrip("/")
        return f"{base}/#router/{device_id}" if device_id else f"{base}/#security"

    def _card(self, title, detail, resolved, link, client=""):
        facts = [{"title": "When", "value": time.strftime("%Y-%m-%d %H:%M")}] + ([{"title": "Client", "value": client}] if client else [])
        return {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                "body": [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True, "color": "Good" if resolved else "Attention",
                          "text": ("Resolved: " if resolved else "") + title},
                         {"type": "TextBlock", "wrap": True, "text": detail[:1500] or " "}, {"type": "FactSet", "facts": facts}],
                "actions": [{"type": "Action.OpenUrl", "title": "Open in TikManager", "url": link}]}

    def _company(self, cfg, org_id):
        if org_id:
            o = self.db.one("SELECT cw_id FROM orgs WHERE id=?", (org_id,))
            if o and o["cw_id"]:
                return o["cw_id"]
        return cfg["cw"].get("company_id")

    def notify_open(self, cfg, a):
        cw_note = teams_note = None
        client = (self.db.one("SELECT name FROM orgs WHERE id=?", (a["org_id"],)) or {}).get("name", "") if a["org_id"] else ""
        link = self._link(a["device_id"])
        if cfg["cw"]["on"] and self.integ.configured("cw"):
            company = self._company(cfg, a["org_id"])
            if not company:
                cw_note = "No ticket: this client isn't linked to a ConnectWise company and no default company is set."
            else:
                try:
                    tid = self.integ.cw_ticket(company, cfg["cw"]["board_id"], short(f"[TikManager] {a['title']}", 100),
                                               f"{a['detail']}\n\nOpened by TikManager. {link}\nTikManager closes this ticket when the problem clears.",
                                               cfg["cw"]["status_id"], cfg["cw"]["priority_id"])
                    self.db.run("UPDATE alerts SET cw_ticket=? WHERE id=?", (tid, a["id"]))
                except IntegrationError as e:
                    cw_note = f"Ticket not opened: {e}"
        if cfg["teams"]["on"] and self.integ.configured("teams"):
            try:
                self.integ.teams_post(self._card(a["title"], a["detail"] or "", False, link, client))
            except IntegrationError as e:
                teams_note = f"Teams message not sent: {e}"
        self.db.run("UPDATE alerts SET cw_note=?, teams_note=? WHERE id=?", (cw_note, teams_note, a["id"]))

    def notify_resolved(self, cfg, a):
        mins = int((time.time() - a["opened_at"]) // 60)
        text = f"Resolved after {mins} minute{'s' if mins != 1 else ''} - TikManager no longer sees this problem."
        if a["cw_ticket"] and self.integ.configured("cw"):
            try:
                self.integ.cw_close(a["cw_ticket"], text, cfg["cw"].get("closed_status_id"))
            except IntegrationError as e:
                self.db.run("UPDATE alerts SET cw_note=? WHERE id=?", (f"Ticket not closed: {e}", a["id"]))
        if cfg["teams"]["on"] and self.integ.configured("teams"):
            try:
                self.integ.teams_post(self._card(a["title"], text, True, self._link(a["device_id"])))
            except IntegrationError:
                pass

    def run_once(self):
        with self.lock:
            cfg = self.settings()
            now = time.time()
            current = self.conditions(cfg)
            open_rows = {r["key"]: r for r in self.db.q("SELECT * FROM alerts WHERE resolved_at IS NULL")}
            new = [(key, c) for key, c in current.items() if key not in open_rows]
            storm = [x for x in new if x[1][0] == "offline"]
            grouped = len(storm) > STORM
            for key, (kind, dev, org, title, detail) in new:
                aid = self.db.run("INSERT INTO alerts (key, kind, device_id, org_id, title, detail, opened_at) VALUES (?,?,?,?,?,?,?)",
                                  (key, kind, dev, org, title[:200], (detail or "")[:4000], now))
                if grouped and kind == "offline":
                    self.db.run("UPDATE alerts SET cw_note='Part of a grouped alert (many routers at once)' WHERE id=?", (aid,))
                    continue
                self.notify_open(cfg, self.db.one("SELECT * FROM alerts WHERE id=?", (aid,)))
            if grouped:   # one message for many routers going offline together
                names = ", ".join(c[3].replace(" is offline", "") for _, c in storm[:30])
                aid = self.db.run("INSERT INTO alerts (key, kind, title, detail, opened_at, resolved_at) VALUES (?,?,?,?,?,?)",
                                  (f"offline-many:{int(now)}", "offline", f"{len(storm)} routers went offline at once",
                                   f"Most likely a problem with TikManager's own connection (or its WireGuard), not the routers. Routers: {names}", now, now))
                self.notify_open(cfg, self.db.one("SELECT * FROM alerts WHERE id=?", (aid,)))
            for key, r in open_rows.items():
                if key not in current:
                    self.db.run("UPDATE alerts SET resolved_at=? WHERE id=?", (now, r["id"]))
                    if not (r["cw_note"] or "").startswith("Part of a grouped"):
                        self.notify_resolved(cfg, r)
            self.db.run("DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?", (now - 180 * 86400,))

    def test(self, channel):
        cfg = self.settings()
        a = {"title": "Test alert from TikManager", "detail": "If you can read this, alerts reach you here. Nothing is wrong.", "device_id": None, "org_id": None}
        if channel == "teams":
            self.integ.teams_post(self._card(a["title"], a["detail"], False, self._link(None)))
            return "Sent to Teams."
        if channel == "cw":
            if not cfg["cw"]["board_id"] or not cfg["cw"]["company_id"]:
                raise ValueError("Save a board and a default company first.")
            tid = self.integ.cw_ticket(cfg["cw"]["company_id"], cfg["cw"]["board_id"], "[TikManager] Test alert", a["detail"], cfg["cw"]["status_id"], cfg["cw"]["priority_id"])
            self.integ.cw_close(tid, "Test finished - closing.", cfg["cw"]["closed_status_id"])
            return f"Opened and closed test ticket #{tid}."
        raise ValueError("Unknown channel.")

    def view(self, since_days=7):
        rows = self.db.q("""SELECT a.*, d.name AS device, o.name AS org FROM alerts a LEFT JOIN devices d ON d.id = a.device_id
                            LEFT JOIN orgs o ON o.id = a.org_id WHERE a.resolved_at IS NULL OR a.resolved_at > ? ORDER BY a.opened_at DESC LIMIT 500""",
                         (time.time() - since_days * 86400,))
        return {"open": [r for r in rows if not r["resolved_at"]], "recent": [r for r in rows if r["resolved_at"]],
                "kinds": {k: {"label": v[0], "threshold": v[2]} for k, v in KINDS.items()}}

    def loop(self):
        time.sleep(120)   # let the poller see every router first
        while True:
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(60)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="alerts").start()
