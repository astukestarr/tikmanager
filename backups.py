"""Daily configuration backups of every adopted router, as an export script (.rsc) - restorable on a different model.

- Each night (TM_BACKUP_HOUR, default 02:00 server time) every online router is exported over its WireGuard tunnel;
  routers that were offline are caught up when they come back; 'Back up now' does one immediately.
- The export includes secrets (so it's a complete restore) and is stored compressed and encrypted (vault.py).
- A new version is kept only when the configuration changed (ignoring the export's own date line); unchanged nights
  just record 'checked'. Each router keeps its newest TM_BACKUP_KEEP versions (10; Admin > System can change it) -
  the oldest is removed as soon as a new one is saved.
"""
import gzip
import hashlib
import re
import threading
import time
import traceback
from datetime import datetime

from routeros import RouterError


def normalize(text: str) -> str:
    """The export minus lines that change on every run (its timestamp header), with uniform line endings."""
    lines = text.replace("\r\n", "\n").split("\n")
    return "\n".join(l for l in lines if not re.match(r"^# \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} by RouterOS", l) and
                     not re.match(r"^# [a-z]{3}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} by RouterOS", l)).strip() + "\n"


class Backups:
    def __init__(self, db, settings, vault, client_for):
        self.db, self.s, self.vault, self.client_for = db, settings, vault, client_for
        self.running = set()
        self.lock = threading.Lock()

    @property
    def hour(self):   # Admin > System overrides the settings file
        return int(self.db.setting("backup_hour", getattr(self.s, "backup_hour", 2)))

    @property
    def keep_versions(self):
        return int(self.db.setting("backup_keep_versions", getattr(self.s, "backup_keep_versions", 10)))

    # --- one backup ---------------------------------------------------------------------------------------
    def run(self, device_id, trigger="nightly", user="schedule") -> dict:
        with self.lock:
            if device_id in self.running:
                return {"ok": False, "detail": "A backup of this router is already running."}
            self.running.add(device_id)
        try:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))
            if not d or d["state"] != "adopted":
                return {"ok": False, "detail": "Router not found or not approved."}
            now = time.time()
            self.db.run("UPDATE devices SET last_backup_try=? WHERE id=?", (now, device_id))
            try:
                text = self.client_for(d).export(sensitive=True)
            except RouterError as e:
                self.db.run("UPDATE devices SET last_backup_error=? WHERE id=?", (str(e)[:300], device_id))
                self.db.event(device_id, d["org_id"], "backup failed", str(e)[:300])
                return {"ok": False, "detail": str(e)}
            norm = normalize(text)
            digest = hashlib.sha256(norm.encode()).hexdigest()
            last = self.db.one("SELECT id, sha256 FROM backups WHERE device_id=? ORDER BY ts DESC LIMIT 1", (device_id,))
            changed = not last or last["sha256"] != digest
            if changed:
                blob, method = self.vault.seal(gzip.compress(text.encode()), f"device:{device_id}")
                prev_lines = self.lines_of(last["id"]) if last else []
                new_lines = norm.splitlines()
                added = len(set(new_lines) - set(prev_lines))
                removed = len(set(prev_lines) - set(new_lines))
                bid = self.db.run("""INSERT INTO backups (device_id, org_id, ts, size, sha256, blob, enc, trigger, by_user, added, removed, lines)
                                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                                  (device_id, d["org_id"], now, len(text), digest, blob, method, trigger, user, added, removed, len(new_lines)))
                self.db.event(device_id, d["org_id"], "config changed" if last else "first backup",
                              f"+{added} / -{removed} lines" if last else f"{len(new_lines)} lines")
                self.prune(device_id)
            else:
                bid = last["id"]
                self.db.run("UPDATE backups SET checked_at=? WHERE id=?", (now, bid))
            self.db.run("UPDATE devices SET last_backup_at=?, last_backup_error=NULL WHERE id=?", (now, device_id))
            return {"ok": True, "changed": changed, "backup_id": bid,
                    "detail": "Configuration changed - new version saved." if changed else "No change since the last backup."}
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            return {"ok": False, "detail": f"Backup failed: {e}"}
        finally:
            with self.lock:
                self.running.discard(device_id)

    def text_of(self, backup_id) -> str:
        b = self.db.one("SELECT device_id, blob, enc FROM backups WHERE id=?", (backup_id,))
        if not b:
            raise KeyError(backup_id)
        return gzip.decompress(self.vault.open(b["blob"], b["enc"], f"device:{b['device_id']}")).decode("utf-8", "replace")

    def lines_of(self, backup_id):
        try:
            return normalize(self.text_of(backup_id)).splitlines()
        except Exception:  # noqa: BLE001
            return []

    # --- schedule -----------------------------------------------------------------------------------------
    def due(self):
        """Online routers not backed up since tonight's run time (or ever). Outside the nightly window, only routers whose
        last backup is over 36 hours old (missed nights) are caught up."""
        now = datetime.now()
        window_start = now.replace(hour=self.hour, minute=0, second=0, microsecond=0).timestamp()
        if now.hour < self.hour:
            window_start -= 86400
        in_window = 0 <= now.timestamp() - window_start < 6 * 3600
        rows = self.db.q("SELECT id, last_backup_at, last_backup_try FROM devices WHERE state='adopted' AND online=1")
        out = []
        for r in rows:
            last, tried = r["last_backup_at"] or 0, r["last_backup_try"] or 0
            if time.time() - tried < 3600:   # don't hammer a router whose backup just failed
                continue
            if last < window_start and (in_window or time.time() - last > 36 * 3600):
                out.append(r["id"])
        return out

    def prune(self, device_id=None):
        """Keep only the newest N versions of each router (or of one router)."""
        where, args = ("WHERE device_id=?", (device_id,)) if device_id else ("", ())
        self.db.run(f"""DELETE FROM backups WHERE id IN (
                          SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY ts DESC) AS n FROM backups {where}) WHERE n > ?)""",
                    (*args, max(1, self.keep_versions)))

    def loop(self):
        time.sleep(60)
        last_prune = 0
        while True:
            try:
                for did in self.due():
                    self.run(did)
                    time.sleep(2)   # spread the load
                if time.time() - last_prune > 86400:
                    self.prune()
                    last_prune = time.time()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(300)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="backups").start()
