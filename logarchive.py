"""Log archiving: keep router logs and traffic flows for the long term (compliance) by writing one compressed CSV per
calendar month to an off-appliance destination (archivedest.py), then letting the local tables be pruned.

- A month is archived only once it is **complete** (strictly before the current month) - so the upload naturally
  happens on/after the 1st of the following month, and a 31-day month is captured whole.
- Local pruning is **archive-aware**: routerlogs.prune() / flows.prune() ask `floor(store)` for the epoch below which
  rows are safe to delete; no complete month is deleted until it has been archived. A safety cap (SAFETY_HOLD_DAYS)
  stops a broken destination from filling the disk for ever.
- Encrypted with a passphrase (offsite.encrypt) if one is set - required for plain FTP, like the off-site backup.
- Kept forever by default; an optional keep_months ceiling prunes old archives at the destination.

Per-store watermarks ("logs_through" / "flows_through" = the last YYYY-MM fully archived) live in the db setting
`log_archive_state`, alongside the last run's status.
"""
import calendar
import csv
import gzip
import io
import json
import threading
import time
import traceback

import archivedest
from offsite import encrypt

SAFETY_HOLD_DAYS = 120   # if the destination is broken this long, prune anyway (logged) rather than fill the disk
STORES = ("logs", "flows")
DEFAULTS = {"enabled": "", "what": "both", "dest": "", "keep_months": "0"}

# store -> (table, SQL for one month between ?(>=) and ?(<), CSV header)
_SELECT = {
    "logs": ("router_logs",
             """SELECT l.ts, d.name AS device, o.name AS client, l.topics, l.severity, l.message
                FROM router_logs l JOIN devices d ON d.id=l.device_id LEFT JOIN orgs o ON o.id=d.org_id
                WHERE l.ts>=? AND l.ts<? ORDER BY l.ts""",
             ["time", "device", "client", "topics", "severity", "message"]),
    "flows": ("flows",
              """SELECT f.ts, d.name AS device, o.name AS client, f.local, f.remote, f.port, f.proto, f.dir,
                 f.up, f.down, f.packets, f.flows
                 FROM flows f JOIN devices d ON d.id=f.device_id LEFT JOIN orgs o ON o.id=d.org_id
                 WHERE f.ts>=? AND f.ts<? ORDER BY f.ts""",
              ["time", "device", "client", "local", "remote", "port", "proto", "dir", "up", "down", "packets", "flows"]),
}


def _month_start(year, month):
    return time.mktime((year, month, 1, 0, 0, 0, 0, 0, -1))


def _this_month(now=None):
    t = time.localtime(now or time.time())
    return t.tm_year, t.tm_mon


def _next_month(y, m):
    return (y + 1, 1) if m == 12 else (y, m + 1)


def _months_between(a, b):
    """Inclusive list of (year, month) from a to b (both (y,m) tuples), a<=b."""
    out, cur = [], a
    while cur <= b:
        out.append(cur)
        cur = _next_month(*cur)
    return out


class LogArchive:
    def __init__(self, db, settings, integ, routerlogs, flows):
        self.db, self.s, self.integ, self.routerlogs, self.flows = db, settings, integ, routerlogs, flows
        self.lock = threading.Lock()
        self.running = False

    # --- config / state ------------------------------------------------------------------------------------------
    def config(self):
        return {**DEFAULTS, **self.integ.config("archive")}

    def enabled(self):
        c = self.config()
        return bool(c.get("enabled")) and bool(c.get("dest"))

    def what(self):
        w = self.config().get("what") or "both"
        return list(STORES) if w == "both" else [w] if w in STORES else list(STORES)

    def state(self):
        try:
            return json.loads(self.db.setting("log_archive_state", "") or "{}")
        except ValueError:
            return {}

    def _save_state(self, st):
        self.db.set_setting("log_archive_state", json.dumps(st))

    def backend(self):
        return archivedest.make(self.config())

    def where(self):
        try:
            return self.backend().label()
        except archivedest.ArchiveError:
            return ""

    def public(self):
        c = self.config()
        pub = self.integ.public("archive")   # masks secrets, adds <field>_set
        st = self.state()
        return {**pub, "enabled": bool(c.get("enabled")), "what": c.get("what") or "both", "dest": c.get("dest") or "",
                "keep_months": c.get("keep_months") or "0", "configured": self.enabled(), "running": self.running,
                "where": self.where(), "state": st, "stores": STORES, "safety_hold_days": SAFETY_HOLD_DAYS}

    def save(self, b):
        """Validate then store (via integrations). Keeps the destination backend happy on save."""
        data = dict(b or {})
        dest = str(data.get("dest") or self.config().get("dest") or "").strip()
        if data.get("enabled") and dest not in archivedest.DESTS:
            raise ValueError("Pick where to archive to.")
        km = str(data.get("keep_months") or "0").strip()
        if km and not (km.isdigit() and 0 <= int(km) <= 600):
            raise ValueError("Keep archives for 0 (forever) to 600 months.")
        w = str(data.get("what") or "both")
        if w not in ("both", "logs", "flows"):
            raise ValueError("Archive logs, flows or both.")
        self.integ.save("archive", data)
        # If enabling, make sure the chosen backend at least constructs (catches missing fields early).
        if self.enabled():
            try:
                self.backend()
            except archivedest.ArchiveError as e:
                raise ValueError(str(e)) from None

    # --- the months to archive ----------------------------------------------------------------------------------
    def _earliest_month(self, store):
        table = _SELECT[store][0]
        row = self.db.one(f"SELECT MIN(ts) AS t FROM {table}")
        if not row or row["t"] is None:
            return None
        t = time.localtime(row["t"])
        return t.tm_year, t.tm_mon

    def _pending(self, store):
        """Complete (before this month) months for `store` not yet archived, oldest first."""
        st = self.state()
        wm = st.get(f"{store}_through")   # "YYYY-MM" last fully archived
        cy, cm = _this_month()
        last_complete = (cy - 1, 12) if cm == 1 else (cy, cm - 1)   # newest complete month = the one before this one
        if wm:
            y, m = (int(x) for x in wm.split("-"))
            start = _next_month(y, m)
        else:
            start = self._earliest_month(store)
        if start is None or start > last_complete:
            return []
        return _months_between(start, last_complete)

    def floor(self, store):
        """Epoch below which `store` rows may be pruned: keep every complete month that isn't archived yet. None when
        archiving is off for this store (caller then uses the normal retention window)."""
        if not self.enabled() or store not in self.what():
            return None
        pending = self._pending(store)
        if not pending:
            return None
        start = _month_start(*pending[0])
        return max(start, time.time() - SAFETY_HOLD_DAYS * 86400)

    # --- building & uploading ------------------------------------------------------------------------------------
    def _build(self, store, year, month):
        table, sql, header = _SELECT[store]
        lo, hi = _month_start(year, month), _month_start(*_next_month(year, month))
        buf = io.BytesIO()
        n = 0
        cols = header[1:]   # every column after the "time" column maps to a SELECT alias of the same name
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            tw = io.TextIOWrapper(gz, encoding="utf-8", newline="")
            w = csv.writer(tw)
            w.writerow(header)
            for r in self.db.q(sql, (lo, hi)):
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))] + [r[c] for c in cols])
                n += 1
            tw.flush()
        return buf.getvalue(), n

    def _names(self, store, year, month):
        base = f"{store}/tikmanager-{store}-{year:04d}-{month:02d}.csv.gz"
        return base, base + ".tmbak"

    def _already(self, dest, store, year, month):
        plain, enc = self._names(store, year, month)
        try:
            have = set(dest.names(store))
        except archivedest.ArchiveError:
            return False
        return plain in have or enc in have

    def _upload_month(self, dest, store, year, month, passphrase):
        data, n = self._build(store, year, month)
        plain, enc = self._names(store, year, month)
        if passphrase:
            dest.put(enc, encrypt(data, passphrase))
        else:
            dest.put(plain, data)
        return n, len(data)

    def run(self, trigger="manual"):
        with self.lock:
            if self.running:
                raise archivedest.ArchiveError("An archive run is already going.")
            self.running = True
        st = self.state()
        out = {"at": time.time(), "trigger": trigger}
        uploaded, rows, byts = [], 0, 0
        try:
            if not self.enabled():
                raise archivedest.ArchiveError("Log archiving isn't turned on.")
            c = self.config()
            dest = self.backend()
            phrase = c.get("passphrase") or ""
            if not phrase and c.get("dest") == "ftp":
                raise archivedest.ArchiveError("Plain FTP sends everything readable - set a passphrase so archives are encrypted (or use FTPS).")
            for store in self.what():
                for (y, m) in self._pending(store):
                    if self._already(dest, store, y, m):
                        st[f"{store}_through"] = f"{y:04d}-{m:02d}"
                        continue
                    n, size = self._upload_month(dest, store, y, m, phrase)
                    st[f"{store}_through"] = f"{y:04d}-{m:02d}"
                    uploaded.append(f"{store} {y:04d}-{m:02d} ({n} rows)")
                    rows += n
                    byts += size
                    self._save_state(st)   # persist each month so a later failure doesn't redo earlier ones
            self._prune_dest(dest, c)
            out.update(ok=True, uploaded=uploaded, rows=rows, bytes=byts,
                       detail=("Archived " + "; ".join(uploaded) if uploaded else "Nothing new to archive") + f" to {dest.label()}")
        except Exception as e:  # noqa: BLE001
            if not isinstance(e, archivedest.ArchiveError):
                traceback.print_exc()
            out.update(ok=False, detail=str(e)[:400])
        finally:
            self.running = False
        st["last_run"], st["last_ok"], st["last_detail"] = out["at"], out.get("ok", False), out["detail"]
        self._save_state(st)
        return out

    def _prune_dest(self, dest, c):
        """Honour keep_months: delete archives older than N months at the destination (0 = keep for ever)."""
        try:
            keep = int(c.get("keep_months") or 0)
        except (TypeError, ValueError):
            keep = 0
        if keep <= 0:
            return
        cy, cm = _this_month()
        # cutoff = first day of (this month - keep months); anything strictly older is removed
        total = cy * 12 + (cm - 1) - keep
        cutoff_y, cutoff_m = divmod(total, 12)
        cutoff = f"{cutoff_y:04d}-{cutoff_m + 1:02d}"
        for store in STORES:
            try:
                for name in dest.names(store):
                    tag = name.rsplit("-", 2)[-2:]   # [YYYY, MM(.csv.gz...)]
                    if len(tag) == 2 and tag[0].isdigit():
                        ym = f"{tag[0]}-{tag[1][:2]}"
                        if ym < cutoff:
                            dest.delete(name)
            except archivedest.ArchiveError:
                pass

    def test(self):
        return self.backend().check()

    # --- scheduling ----------------------------------------------------------------------------------------------
    def loop(self):
        while True:
            time.sleep(1800)   # twice an hour; actual work is once a day
            try:
                if not self.enabled():
                    continue
                st = self.state()
                today = time.strftime("%Y-%m-%d")
                if st.get("last_day") == today:
                    continue
                st["last_day"] = today
                self._save_state(st)
                self.run("daily")
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="log-archive").start()
