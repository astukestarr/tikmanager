"""RouterOS and RouterBOARD firmware upgrades - now, at a scheduled time, or for many routers at once.

Each job, in order:
  1. waits (up to 30 minutes) for the router to be online,
  2. takes a configuration backup ('pre-upgrade') and stops if that fails,
  3. checks MikroTik's update server on the chosen channel (stable / long-term; blank = the router's own),
  4. downloads the new RouterOS, reboots and waits for the router to come back on the new version,
  5. optionally stages the matching RouterBOARD firmware and reboots once more.
Routers are also asked twice a day which version is newest on their channel, so the Upgrades page shows what's available.
"""
import re
import threading
import time
import traceback
import uuid

from routeros import RouterError

MAX_PARALLEL = 4
CHECK_EVERY = 12 * 3600
ONLINE_WAIT = 30 * 60
BACK_WAIT = 15 * 60
CHANNELS = ("stable", "long-term")


def vkey(v):
    """'7.20.2 (stable)' -> (7, 20, 2) for comparing versions; betas/rcs sort before the release."""
    v = (v or "").split(" ")[0]
    nums = [int(x) for x in re.findall(r"\d+", re.split(r"beta|rc", v)[0])]
    return tuple(nums) + ((0,) if re.search(r"beta|rc", v) else (1,))


class Upgrades:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.running = set()   # job ids
        self.lock = threading.Lock()

    # --- scheduling -------------------------------------------------------------------------------------------
    def schedule(self, devices, when, channel, firmware, user, stagger_min=0):
        """One job per router; returns (created, skipped [(name, reason)])."""
        if channel and channel not in CHANNELS:
            raise ValueError("Unknown update channel.")
        batch = uuid.uuid4().hex[:12] if len(devices) > 1 else None
        created, skipped = [], []
        for n, d in enumerate(devices):
            if d["state"] != "adopted":
                skipped.append((d["name"], "not approved"))
                continue
            if self.db.one("SELECT id FROM upgrades WHERE device_id=? AND status IN ('scheduled','running')", (d["id"],)):
                skipped.append((d["name"], "already has an upgrade scheduled"))
                continue
            at = when + n * stagger_min * 60
            jid = self.db.run("""INSERT INTO upgrades (device_id, org_id, batch, scheduled_at, channel, firmware, status, from_version,
                                 created_by, created_at) VALUES (?,?,?,?,?,?,'scheduled',?,?,?)""",
                              (d["id"], d["org_id"], batch, at, channel or None, 1 if firmware else 0, (d["version"] or "").split(" ")[0],
                               user, time.time()))
            self.db.event(d["id"], d["org_id"], "upgrade scheduled", f"by {user} for {time.strftime('%Y-%m-%d %H:%M', time.localtime(at))}")
            created.append(jid)
        return created, skipped

    def cancel(self, job_id):
        j = self.db.one("SELECT * FROM upgrades WHERE id=?", (job_id,))
        if not j or j["status"] != "scheduled":
            return None
        self.db.run("UPDATE upgrades SET status='cancelled', finished_at=? WHERE id=? AND status='scheduled'", (time.time(), job_id))
        return j

    # --- update checks ----------------------------------------------------------------------------------------
    def check(self, d, channel=None):
        info = self.client_for(d).check_updates(channel)
        self.db.run("UPDATE devices SET ros_channel=?, ros_latest=?, ros_checked=? WHERE id=?",
                    (info["channel"], info["latest"] or None, time.time(), d["id"]))
        return info

    def check_due(self, limit=5):
        rows = self.db.q("""SELECT * FROM devices WHERE state='adopted' AND online=1 AND (ros_checked IS NULL OR ros_checked < ?)
                            ORDER BY ros_checked LIMIT ?""", (time.time() - CHECK_EVERY, limit))
        for d in rows:
            try:
                self.check(d)
            except RouterError as e:
                self.db.run("UPDATE devices SET ros_checked=? WHERE id=?", (time.time() - CHECK_EVERY + 3600, d["id"]))   # retry in an hour
                print(f"update check failed for {d['name']}: {e}")

    # --- running a job ----------------------------------------------------------------------------------------
    def _step(self, jid, step):
        self.db.run("UPDATE upgrades SET step=? WHERE id=?", (step, jid))

    def _finish(self, j, status, detail, to_version=None):
        self.db.run("UPDATE upgrades SET status=?, step=NULL, detail=?, to_version=COALESCE(?, to_version), finished_at=? WHERE id=?",
                    (status, detail[:500], to_version, time.time(), j["id"]))
        self.db.event(j["device_id"], j["org_id"], "upgraded" if status == "done" else "upgrade failed", detail[:300])
        d = self._device(j)
        self.db.audit(j["created_by"], f"upgrade {status}", d["name"] if d else j["device_id"], detail=detail[:500], org_id=j["org_id"])

    def _device(self, j):
        return self.db.one("SELECT * FROM devices WHERE id=?", (j["device_id"],))

    def _wait_back(self, d, check=None):
        """After a reboot: wait for the router to answer again (and, if given, for check(status) to pass)."""
        time.sleep(30)
        deadline = time.time() + BACK_WAIT
        while time.time() < deadline:
            try:
                st = self.client_for(d).status()
                if not check or check(st):
                    return st
            except RouterError:
                pass
            time.sleep(15)
        return None

    def run(self, j):
        jid = j["id"]
        try:
            if (self.db.one("SELECT status FROM upgrades WHERE id=?", (jid,)) or {}).get("status") != "scheduled":
                return   # cancelled at the last moment
            self.db.run("UPDATE upgrades SET status='running', started_at=?, step='waiting for the router' WHERE id=?", (time.time(), jid))
            d = self._device(j)
            deadline = time.time() + ONLINE_WAIT
            while d and not d["online"] and time.time() < deadline:
                time.sleep(30)
                d = self._device(j)
            if not d:
                return
            if not d["online"]:
                return self._finish(j, "failed", "The router was offline for 30 minutes after the scheduled time - nothing was changed.")
            self._step(jid, "backing up")
            b = self.backups.run(d["id"], "pre-upgrade", j["created_by"] or "upgrade")
            if not b.get("ok"):
                return self._finish(j, "failed", f"Stopped before changing anything: the pre-upgrade backup failed ({b.get('detail')}).")
            cl = self.client_for(d)
            self._step(jid, "checking for updates")
            info = self.check(d, j["channel"])
            installed, latest = info["installed"] or (d["version"] or "").split(" ")[0], info["latest"]
            notes = []
            if latest and vkey(latest) > vkey(installed):
                self._step(jid, f"downloading RouterOS {latest}")
                cl.download_update()
                self._step(jid, f"rebooting into RouterOS {latest}")
                self.db.event(d["id"], d["org_id"], "upgrading", f"RouterOS {installed} -> {latest}, rebooting")
                cl.reboot()
                st = self._wait_back(d, lambda s: vkey(s.get("version")) >= vkey(latest))
                if not st:
                    return self._finish(j, "failed", f"The router hasn't come back on RouterOS {latest} after {BACK_WAIT // 60} minutes - check it "
                                                     f"(the pre-upgrade backup is saved).", latest)
                notes.append(f"RouterOS {installed} → {latest}")
            else:
                notes.append(f"RouterOS {installed} is already the newest on the {info['channel'] or 'current'} channel")
            if j["firmware"]:
                st = self.client_for(d).status()
                cur, new = st.get("fw_current"), st.get("fw_upgrade")
                if cur and new and vkey(new) > vkey(cur):
                    self._step(jid, f"RouterBOARD firmware {new}")
                    cl.routerboard_upgrade()
                    cl.reboot()
                    if not self._wait_back(d, lambda s: vkey(s.get("fw_current")) >= vkey(new)):
                        return self._finish(j, "failed", "; ".join(notes) + f"; the router didn't come back with RouterBOARD firmware {new} "
                                                         f"after {BACK_WAIT // 60} minutes - check it.", latest)
                    notes.append(f"firmware {cur} → {new}")
            self.db.run("UPDATE devices SET last_poll=NULL WHERE id=?", (d["id"],))   # poll right away to show the new versions
            self._finish(j, "done", "; ".join(notes), latest if latest and vkey(latest) > vkey(installed) else installed)
        except RouterError as e:
            self._finish(j, "failed", f"{e} (step: {self.db.one('SELECT step FROM upgrades WHERE id=?', (jid,))['step']})")
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._finish(j, "failed", f"Upgrade error: {e}")
        finally:
            with self.lock:
                self.running.discard(jid)

    # --- loop -------------------------------------------------------------------------------------------------
    def loop(self):
        # jobs that were mid-way when TikManager stopped can't be resumed safely
        for j in self.db.q("SELECT * FROM upgrades WHERE status='running'"):
            self._finish(j, "failed", "TikManager restarted during this upgrade - check the router's version on its page.")
        last_check = 0
        while True:
            try:
                for j in self.db.q("SELECT * FROM upgrades WHERE status='scheduled' AND scheduled_at <= ? ORDER BY scheduled_at", (time.time(),)):
                    with self.lock:
                        if len(self.running) >= MAX_PARALLEL:
                            break
                        if j["id"] in self.running:
                            continue
                        self.running.add(j["id"])
                    threading.Thread(target=self.run, args=(j,), daemon=True, name=f"upgrade-{j['id']}").start()
                if time.time() - last_check > 300:
                    self.check_due()
                    last_check = time.time()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(15)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="upgrades").start()
