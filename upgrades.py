"""RouterOS and RouterBOARD firmware upgrades - now, at a scheduled time, or for many routers at once.

Each job, in order:
  1. waits (up to 30 minutes) for the router to be online,
  2. takes a configuration backup ('pre-upgrade') and stops if that fails,
  3. checks MikroTik's update server on the chosen channel (stable / long-term; blank = the router's own),
  4. downloads the new RouterOS, reboots and waits for the router to come back on the new version,
  5. optionally stages the matching RouterBOARD firmware and reboots once more.
Routers are also asked twice a day which version is newest on their channel, so the Upgrades page shows what's available.

Safer mass upgrades (options when scheduling several routers):
- **Safety stop**: after max_fail upgrades in the batch fail, the rest are held (status 'held') until someone resumes
  or cancels them - a bad release or a bad night stops at the first casualties.
- **One at a time**: the batch runs in the order chosen, each router only after the previous one finished.
- **Pinned version**: a job remembers the newest RouterOS when it was scheduled; if MikroTik has published something
  newer by the time it runs, nothing is installed (status 'skipped') - nobody installs a release they didn't review.
"""
import json
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
INSTALL_WAIT = 30 * 60   # native install downloads, reboots and comes back - this one window covers the whole thing
CHANNELS = ("stable", "long-term")


def vkey(v):
    """'7.20.2 (stable)' -> (7, 20, 2) for comparing versions; betas/rcs sort before the release."""
    v = (v or "").split(" ")[0]
    nums = [int(x) for x in re.findall(r"\d+", re.split(r"beta|rc", v)[0])]
    return tuple(nums) + ((0,) if re.search(r"beta|rc", v) else (1,))


class Upgrades:
    def __init__(self, db, client_for, backups, integ=None):
        self.db, self.client_for, self.backups, self.integ = db, client_for, backups, integ
        self.running = set()   # job ids
        self.lock = threading.Lock()

    def _ticket_cfg(self):
        """ConnectWise ticket settings for upgrades (board + the three statuses), set on the Upgrades page."""
        try:
            return json.loads(self.db.setting("upgrade_ticket") or "{}")
        except Exception:  # noqa: BLE001
            return {}

    # --- scheduling -------------------------------------------------------------------------------------------
    def schedule(self, devices, when, channel, firmware, user, stagger_min=0, sequential=False, max_fail=0, pin=False, cw_ticket=False):
        """One job per router, in the order given; returns (created, skipped [(name, reason)])."""
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
            at = when if sequential else when + n * stagger_min * 60
            pin_v = d.get("ros_latest") if pin and d.get("ros_latest") and (not channel or channel == d.get("ros_channel")) else None
            jid = self.db.run("""INSERT INTO upgrades (device_id, org_id, batch, scheduled_at, channel, firmware, status, from_version,
                                 created_by, created_at, seq, sequential, max_fail, pin_version, cw_ticket_on) VALUES (?,?,?,?,?,?,'scheduled',?,?,?,?,?,?,?,?)""",
                              (d["id"], d["org_id"], batch, at, channel or None, 1 if firmware else 0, (d["version"] or "").split(" ")[0],
                               user, time.time(), n, 1 if sequential and batch else 0, max_fail or None, pin_v, 1 if cw_ticket else 0))
            self.db.event(d["id"], d["org_id"], "upgrade scheduled", f"by {user} for {time.strftime('%Y-%m-%d %H:%M', time.localtime(at))}")
            created.append(jid)
        return created, skipped

    def resume(self, batch, user):
        n = self.db.run("UPDATE upgrades SET status='scheduled', detail=NULL, scheduled_at=? WHERE batch=? AND status='held'", (time.time(), batch))
        self.db.audit(user, "upgrade batch resumed", batch)
        return n

    def cancel_batch(self, batch, user):
        self.db.run("UPDATE upgrades SET status='cancelled', finished_at=? WHERE batch=? AND status IN ('held','scheduled')", (time.time(), batch))
        self.db.audit(user, "upgrade batch cancelled", batch)

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

    def _finish(self, j, status, detail, to_version=None, counts=True):
        # counts=False for failures where the router was NOT changed (offline, pre-upgrade backup failed, couldn't even
        # check/download): nothing broke, so they must not trip the safety stop - otherwise one flaky router holds the
        # whole batch. The stop is for the real danger: a router that was changed and didn't come back (a bad release).
        self.db.run("UPDATE upgrades SET status=?, step=NULL, detail=?, to_version=COALESCE(?, to_version), finished_at=? WHERE id=?",
                    (status, detail[:500], to_version, time.time(), j["id"]))
        self.db.event(j["device_id"], j["org_id"], {"done": "upgraded", "skipped": "upgrade skipped"}.get(status, "upgrade failed"), detail[:300])
        if status == "failed" and counts and j.get("batch") and j.get("max_fail"):   # safety stop
            failed = self.db.one("SELECT COUNT(*) AS n FROM upgrades WHERE batch=? AND status='failed'", (j["batch"],))["n"]
            if failed >= j["max_fail"]:
                held = self.db.q("SELECT id, device_id, org_id FROM upgrades WHERE batch=? AND status='scheduled'", (j["batch"],))
                self.db.run("UPDATE upgrades SET status='held', detail=? WHERE batch=? AND status='scheduled'",
                            (f"Held by the safety stop: {failed} upgrade{'s' if failed != 1 else ''} in this batch failed. Resume or cancel on the Upgrades page.",
                             j["batch"]))
                for h in held:
                    self.db.event(h["device_id"], h["org_id"], "upgrade held", f"Safety stop: {failed} upgrade(s) in the same batch failed")
                if held:
                    self.db.audit("upgrades", "safety stop", f"batch {j['batch']}", detail=f"{failed} failed, {len(held)} held")
        d = self._device(j)
        self.db.audit(j["created_by"], f"upgrade {status}", d["name"] if d else j["device_id"], detail=detail[:500], org_id=j["org_id"])
        self._ticket_close(j, status, detail)

    # --- ConnectWise ticket (optional, per job) ---------------------------------------------------------------
    def _open_ticket(self, j, d, b):
        """Open a ConnectWise ticket for this upgrade and attach the pre-upgrade backup. Never breaks the upgrade; records
        the outcome (and any error) as a device event so a failure is visible instead of silently swallowed."""
        ev = lambda msg: self.db.event(d["id"], d.get("org_id"), "ConnectWise", msg[:400])
        try:
            if not (self.integ and self.integ.configured("cw")):
                return
            cfg = self._ticket_cfg()
            org = self.db.one("SELECT cw_id FROM orgs WHERE id=?", (j["org_id"],)) if j.get("org_id") else None
            if not cfg.get("board_id"):
                return ev("Upgrade ticket skipped: no ConnectWise board is set (Upgrades > ConnectWise ticket settings).")
            if not org or not org["cw_id"]:
                return ev("Upgrade ticket skipped: this router's client isn't linked to a ConnectWise company.")
            frm = (j.get("from_version") or d.get("version") or "").split(" ")[0]
            text = (f"TikManager is upgrading {d['name']} ({d.get('model') or ''}, serial {d.get('serial') or '?'}) from RouterOS {frm}. "
                    "A pre-upgrade configuration backup was taken and is attached.")
            try:
                tid = self.integ.cw_ticket(org["cw_id"], int(cfg["board_id"]), f"RouterOS upgrade - {d['name']}", text,
                                           cfg.get("status_updating") or None, cfg.get("priority_id") or None)
            except Exception as e:  # noqa: BLE001 - surface why no ticket (e.g. the API member lacks Service Tickets: Add)
                traceback.print_exc()
                return ev(f"Upgrade ticket NOT opened: {e}")
            if not tid:
                return ev("Upgrade ticket NOT opened (ConnectWise returned no ticket id).")
            self.db.run("UPDATE upgrades SET cw_ticket=? WHERE id=?", (int(tid), j["id"]))
            ev(f"Upgrade ticket #{tid} opened")
            try:
                txt = self.backups.text_of(b.get("backup_id")) if b.get("backup_id") else None
                if txt:
                    self.integ.cw_attach(tid, f"{d['name']}-pre-upgrade.rsc", txt, title=f"{d['name']} pre-upgrade backup")
                    ev(f"Pre-upgrade backup attached to ticket #{tid}")
            except Exception as e:  # noqa: BLE001 - attachment is best-effort (needs Companies > Manage Attachments: Add)
                traceback.print_exc()
                ev(f"Backup NOT attached to ticket #{tid} (the API member needs Companies > Manage Attachments: Add): {e}")
        except Exception:  # noqa: BLE001
            traceback.print_exc()

    def _ticket_close(self, j, status, detail):
        """On a finished job with a ticket: set its status (trouble on failure, closing otherwise) and add a note."""
        if status not in ("done", "failed", "skipped"):
            return
        try:
            row = self.db.one("SELECT cw_ticket FROM upgrades WHERE id=?", (j["id"],))
            tid = row and row["cw_ticket"]
            if not tid or not (self.integ and self.integ.configured("cw")):
                return
            cfg = self._ticket_cfg()
            if status == "failed":
                self.integ.cw_close(tid, "Upgrade did not complete: " + (detail or ""), cfg.get("status_trouble") or None)
            else:
                pre = "Upgrade complete: " if status == "done" else "Upgrade skipped: "
                self.integ.cw_close(tid, pre + (detail or ""), cfg.get("status_closing") or None)
        except Exception:  # noqa: BLE001
            traceback.print_exc()

    def _device(self, j):
        return self.db.one("SELECT * FROM devices WHERE id=?", (j["device_id"],))

    def _wait_back(self, d, check=None, timeout=BACK_WAIT):
        """After a reboot (or a native install, which reboots itself): wait for the router to answer again and, if given,
        for check(status) to pass. `timeout` is longer for a native install, whose window also covers the download."""
        time.sleep(30)
        deadline = time.time() + timeout
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
                return self._finish(j, "failed", "The router was offline for 30 minutes after the scheduled time - nothing was changed.", counts=False)
            self._step(jid, "backing up")
            b = self.backups.run(d["id"], "pre-upgrade", j["created_by"] or "upgrade")
            if not b.get("ok"):
                return self._finish(j, "failed", f"Stopped before changing anything: the pre-upgrade backup failed ({b.get('detail')}).", counts=False)
            if j.get("cw_ticket_on"):
                self._open_ticket(j, d, b)
            cl = self.client_for(d)
            self._step(jid, "checking for updates")
            info = self.check(d, j["channel"])
            installed, latest = info["installed"] or (d["version"] or "").split(" ")[0], info["latest"]
            pin = j.get("pin_version")
            if pin and latest and vkey(latest) > vkey(pin):
                return self._finish(j, "skipped", f"RouterOS {latest} was published after this upgrade was scheduled for {pin} - not installed. "
                                                  f"Read its release notes and schedule it again if it's fine.")
            notes = []
            if latest and vkey(latest) > vkey(installed):
                # Native 'download & install' (like Winbox): the router fetches the packages and reboots itself. This is
                # the only reliable path on low-flash boards (16 MB hEX / hAP ac²) - the packages stage in a reserved
                # area, so free space doesn't matter. The single wait below covers the download, reboot and reconnect.
                self._step(jid, f"installing RouterOS {latest}")
                self.db.event(d["id"], d["org_id"], "upgrading", f"RouterOS {installed} -> {latest} (download & install)")
                cl.install_update()
                st = self._wait_back(d, lambda s: vkey(s.get("version")) >= vkey(latest), timeout=INSTALL_WAIT)
                if not st:
                    return self._finish(j, "failed", f"The router hasn't come back on RouterOS {latest} after {INSTALL_WAIT // 60} minutes - check it "
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
            # A RouterError means the step's API call didn't complete, so the router wasn't changed - don't trip the stop.
            self._finish(j, "failed", f"{e} (step: {self.db.one('SELECT step FROM upgrades WHERE id=?', (jid,))['step']})", counts=False)
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self._finish(j, "failed", f"Upgrade error: {e}")
        finally:
            with self.lock:
                self.running.discard(jid)

    # --- loop -------------------------------------------------------------------------------------------------
    def _recover(self, j):
        """A job was 'running' when TikManager stopped. Re-check the router instead of just failing it: if it came back on
        a newer version the upgrade worked; otherwise re-queue it (run() re-checks and only installs if still behind, so a
        retry is safe) rather than leaving a spurious failure that also used to trip the safety stop."""
        d = self._device(j)
        if not d:
            return
        frm = (j.get("from_version") or "").split(" ")[0]
        try:
            cur = ((self.client_for(d).status() or {}).get("version") or "").split(" ")[0]
        except Exception:  # noqa: BLE001
            cur = None
        if cur and frm and vkey(cur) > vkey(frm):
            return self._finish(j, "done", f"RouterOS {frm} → {cur} (confirmed after a TikManager restart)", cur)
        self.db.run("UPDATE upgrades SET status='scheduled', step=NULL, started_at=NULL, scheduled_at=? WHERE id=?",
                    (time.time(), j["id"]))
        self.db.event(j["device_id"], j["org_id"], "upgrade re-queued",
                      "TikManager restarted mid-upgrade - re-queued (it re-checks the version and only installs if still behind)")

    def loop(self):
        # Jobs that were mid-way when TikManager stopped: re-check the router rather than blindly failing them.
        for j in self.db.q("SELECT * FROM upgrades WHERE status='running'"):
            try:
                self._recover(j)
            except Exception:  # noqa: BLE001
                traceback.print_exc()
                self._finish(j, "failed", "TikManager restarted during this upgrade - check the router's version on its page.", counts=False)
        last_check = 0
        while True:
            try:
                for j in self.db.q("SELECT * FROM upgrades WHERE status='scheduled' AND scheduled_at <= ? ORDER BY scheduled_at, seq", (time.time(),)):
                    if j.get("sequential") and j.get("batch") and self.db.one(   # one at a time: wait for the earlier ones in the batch
                            "SELECT 1 FROM upgrades WHERE batch=? AND id<>? AND (status='running' OR (status='scheduled' AND seq < ?))",
                            (j["batch"], j["id"], j["seq"] or 0)):
                        continue
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
