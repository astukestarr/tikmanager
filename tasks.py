"""Task scheduler: push scripts to routers, or keep their firmware up to date, on a schedule.

- A task = an action (run a library script, or upgrade RouterOS/RouterBOARD firmware) + targets (all routers, clients,
  groups, individual routers - resolved when it runs, so new routers in a group are included) + a schedule:
  once (now or at a time), daily at HH:MM, weekly on chosen days at HH:MM, or every N hours. Times are in the
  timezone of the person who made the task.
- Script runs: optional backup first (on by default; the router is skipped if it fails), placeholders filled per router
  ({{identity}} {{name}} {{client}} {{site}} {{wan_ip}} {{tunnel_ip}}), run via REST /execute, output kept per router.
  At most 8 routers at a time. Offline routers are skipped, or (offline=wait) run when they come back within 24 hours.
- Upgrade runs: each target router with a newer RouterOS (or RouterBOARD firmware, if chosen) gets an upgrade job in
  upgrades.py - the same safe sequence as the Upgrades page; routers already up to date are recorded as skipped.
"""
import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from routeros import RouterError
from upgrades import vkey

try:
    from zoneinfo import ZoneInfo
except ImportError:   # pragma: no cover
    ZoneInfo = None

MAX_PARALLEL = 8
WAIT_SECONDS = 24 * 3600
OUTPUT_MAX = 20000
PLACEHOLDERS = ("identity", "name", "client", "site", "wan_ip", "tunnel_ip")


def zone(tz):
    try:
        return ZoneInfo(tz) if ZoneInfo and tz else None
    except Exception:  # noqa: BLE001 - unknown zone / no tzdata: server local time
        return None


def next_run(t, after=None):
    """The next time a task is due after `after` (epoch seconds), or None when it won't run again."""
    after = after or time.time()
    kind = t["kind"]
    if kind == "once":
        return t["run_at"] if t["run_at"] and t["run_at"] > (t.get("last_run") or 0) else None
    if kind == "hourly":
        n = max(1, int(t["every_hours"] or 1)) * 3600
        base = t.get("last_run") or t.get("run_at") or after
        nxt = base + n
        while nxt <= after:
            nxt += n
        return nxt
    tz = zone(t.get("tz"))
    now = datetime.fromtimestamp(after, tz) if tz else datetime.fromtimestamp(after)
    hh, mm = (int(x) for x in (t.get("at_time") or "02:00").split(":")[:2])
    days = json.loads(t.get("days") or "[]") if kind == "weekly" else list(range(7))
    if not days:
        return None
    for add in range(0, 8):
        cand = (now + timedelta(days=add)).replace(hour=hh, minute=mm, second=0, microsecond=0)
        if cand.weekday() in days and cand.timestamp() > after:
            return cand.timestamp()
    return None


class Tasks:
    def __init__(self, db, client_for, backups, upgrades):
        self.db, self.client_for, self.backups, self.upgrades = db, client_for, backups, upgrades
        self.pool = ThreadPoolExecutor(max_workers=MAX_PARALLEL)
        self.inflight = set()
        self.lock = threading.Lock()

    # --- targets ----------------------------------------------------------------------------------------------
    def resolve(self, targets):
        """Adopted routers matching {all, orgs, groups, devices}."""
        t = targets or {}
        if t.get("all"):
            return self.db.q("SELECT * FROM devices WHERE state='adopted' ORDER BY name")
        ids = set(int(x) for x in t.get("devices") or [])
        for o in t.get("orgs") or []:
            ids |= {r["id"] for r in self.db.q("SELECT id FROM devices WHERE state='adopted' AND org_id=?", (int(o),))}
        for g in t.get("groups") or []:
            ids |= {r["device_id"] for r in self.db.q("SELECT device_id FROM group_members WHERE group_id=?", (int(g),))}
        if not ids:
            return []
        return self.db.q(f"SELECT * FROM devices WHERE state='adopted' AND id IN ({','.join('?' * len(ids))}) ORDER BY name", tuple(ids))

    # --- runs -------------------------------------------------------------------------------------------------
    def start_run(self, task, user, trigger, devices=None):
        """Create a run (and one result row per router); the worker loop executes them. Returns the run id."""
        action = task.get("action") or "script"
        script = self.db.one("SELECT * FROM scripts WHERE id=?", (task["script_id"],)) if action == "script" else None
        if action == "script" and not script:
            raise ValueError("The task's script no longer exists.")
        devices = devices if devices is not None else self.resolve(json.loads(task.get("targets") or "{}"))
        rid = self.db.run("""INSERT INTO task_runs (task_id, task_name, action, script_name, script_body, options, backup_first, offline,
                             started_at, by_user, trigger) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                          (task.get("id"), task.get("name"), action, script["name"] if script else None, script["body"] if script else None,
                           task.get("options") or "{}", 1 if task.get("backup_first", 1) else 0, task.get("offline") or "skip",
                           time.time(), user, trigger))
        for d in devices:
            self.db.run("INSERT INTO task_results (run_id, device_id, device_name) VALUES (?,?,?)", (rid, d["id"], d["name"]))
        if not devices:
            self.db.run("UPDATE task_runs SET status='done', finished_at=? WHERE id=?", (time.time(), rid))
        if task.get("id"):
            self.db.run("UPDATE tasks SET last_run=?, last_status=? WHERE id=?", (time.time(), "running" if devices else "no routers", task["id"]))
        return rid

    def _fill(self, body, d):
        org = self.db.one("SELECT name FROM orgs WHERE id=?", (d["org_id"],)) if d.get("org_id") else None
        vals = {"identity": d.get("identity") or d["name"], "name": d["name"], "client": org["name"] if org else "",
                "site": d.get("site") or "", "wan_ip": d.get("wan_ip") or "", "tunnel_ip": d.get("tunnel_ip") or ""}
        for k, v in vals.items():
            body = body.replace("{{" + k + "}}", str(v))
        return body

    def _finish_result(self, res_id, status, output):
        self.db.run("UPDATE task_results SET status=?, output=?, finished_at=? WHERE id=?", (status, (output or "")[:OUTPUT_MAX], time.time(), res_id))

    def _execute(self, res, run):
        try:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (res["device_id"],))
            if not d:
                return self._finish_result(res["id"], "skipped", "Router removed from TikManager.")
            self.db.run("UPDATE task_results SET status='running', started_at=? WHERE id=?", (time.time(), res["id"]))
            if run["action"] == "upgrade":
                return self._upgrade(res, run, d)
            if run["backup_first"]:
                for _ in range(24):   # another task may be backing this router up right now - wait for it (up to 2 minutes)
                    b = self.backups.run(d["id"], "pre-script", run["by_user"] or "task")
                    if b.get("ok") or "already running" not in str(b.get("detail")):
                        break
                    time.sleep(5)
                if not b.get("ok"):
                    return self._finish_result(res["id"], "failed", f"Not run: the backup first failed ({b.get('detail')}).")
            try:
                out = self.client_for(d).run_script(self._fill(run["script_body"], d))
                self._finish_result(res["id"], "ok", out or "(no output)")
                self.db.event(d["id"], d["org_id"], "script run", f"{run['script_name']} ({run['task_name'] or 'run now'})")
            except RouterError as e:
                self._finish_result(res["id"], "failed", str(e))
                self.db.event(d["id"], d["org_id"], "script failed", f"{run['script_name']}: {e}"[:300])
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._finish_result(res["id"], "failed", f"Error: {e}")
        finally:
            with self.lock:
                self.inflight.discard(res["id"])

    def _upgrade(self, res, run, d):
        opts = json.loads(run["options"] or "{}")
        firmware = bool(opts.get("firmware", True))
        ros = bool(d.get("ros_latest")) and vkey(d["ros_latest"]) > vkey(d.get("version"))
        fw = firmware and bool(d.get("fw_upgrade") and d.get("fw_current")) and vkey(d["fw_upgrade"]) > vkey(d["fw_current"])
        if not ros and not fw:
            return self._finish_result(res["id"], "skipped", f"Up to date (RouterOS {(d.get('version') or '').split(' ')[0]}"
                                                             f"{', newest ' + d['ros_latest'] if d.get('ros_latest') else ', not checked yet'}).")
        created, skipped = self.upgrades.schedule([d], time.time(), opts.get("channel") or "", firmware, run["by_user"] or "task")
        if created:
            self._finish_result(res["id"], "ok", f"Upgrade started (job {created[0]}): RouterOS {(d.get('version') or '').split(' ')[0]}"
                                                 f"{' -> ' + d['ros_latest'] if ros else ''}{', RouterBOARD firmware' if fw else ''}. "
                                                 "Follow it on the Upgrades page.")
        else:
            self._finish_result(res["id"], "skipped", skipped[0][1] if skipped else "Not scheduled.")

    def _close_runs(self):
        for run in self.db.q("SELECT id, task_id FROM task_runs WHERE status IN ('running','waiting')"):
            c = {r["status"]: r["n"] for r in self.db.q("SELECT status, COUNT(*) AS n FROM task_results WHERE run_id=? GROUP BY status", (run["id"],))}
            if c.get("pending") or c.get("running"):
                continue
            if c.get("waiting"):
                self.db.run("UPDATE task_runs SET status='waiting' WHERE id=?", (run["id"],))
                continue
            status = "failed" if c.get("failed") else "done"
            self.db.run("UPDATE task_runs SET status=?, finished_at=? WHERE id=?", (status, time.time(), run["id"]))
            if run["task_id"]:
                summary = ", ".join(f"{n} {k}" for k, n in sorted(c.items()))
                self.db.run("UPDATE tasks SET last_status=? WHERE id=?", (summary, run["task_id"]))

    def tick(self):
        now = time.time()
        # due tasks
        for t in self.db.q("SELECT * FROM tasks WHERE enabled=1 AND next_run IS NOT NULL AND next_run <= ?", (now,)):
            try:
                self.start_run(t, t["created_by"], "schedule")
            except ValueError as e:
                self.db.run("UPDATE tasks SET last_status=? WHERE id=?", (str(e), t["id"]))
            t = self.db.one("SELECT * FROM tasks WHERE id=?", (t["id"],))
            self.db.run("UPDATE tasks SET next_run=? WHERE id=?", (next_run(t, now), t["id"]))
        # results to execute: pending ones, and waiting ones whose router came back (or that expired)
        rows = self.db.q("""SELECT r.*, d.online FROM task_results r JOIN task_runs u ON u.id = r.run_id
                            LEFT JOIN devices d ON d.id = r.device_id WHERE r.status IN ('pending','waiting') ORDER BY r.id LIMIT 500""")
        runs = {}
        for r in rows:
            run = runs.get(r["run_id"]) or runs.setdefault(r["run_id"], self.db.one("SELECT * FROM task_runs WHERE id=?", (r["run_id"],)))
            if not r["online"]:
                if r["status"] == "waiting" and r["wait_until"] and r["wait_until"] < now:
                    self._finish_result(r["id"], "skipped", "Offline for 24 hours - not run.")
                elif r["status"] == "pending":
                    if run["offline"] == "wait":
                        self.db.run("UPDATE task_results SET status='waiting', wait_until=? WHERE id=?", (now + WAIT_SECONDS, r["id"]))
                    else:
                        self._finish_result(r["id"], "skipped", "Offline - not run.")
                continue
            with self.lock:
                if r["id"] in self.inflight or len(self.inflight) >= MAX_PARALLEL * 4:
                    continue
                self.inflight.add(r["id"])
            self.pool.submit(self._execute, r, run)
        self._close_runs()

    def loop(self):
        # results that were mid-way when TikManager stopped: mark them so nobody wonders
        self.db.run("UPDATE task_results SET status='failed', output='TikManager restarted while this ran - check the router.' WHERE status='running'")
        while True:
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(10)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="tasks").start()
