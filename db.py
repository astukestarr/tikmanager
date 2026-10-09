"""SQLite storage. One connection per thread; every query that returns client data takes the caller's org scope."""
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS orgs (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, created_at REAL NOT NULL,
  cw_id INTEGER UNIQUE, source TEXT NOT NULL DEFAULT 'manual', active INTEGER NOT NULL DEFAULT 1,
  itg_id TEXT                               -- linked IT Glue organization
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL CHECK (kind IN ('tech', 'client')),
  role TEXT NOT NULL,                       -- tech: admin/tech/readonly; client: admin/viewer
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,   -- clients only
  password_hash TEXT, totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0,
  invite_hash TEXT, invite_expires REAL,
  failed INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, last_login REAL,
  entra_oid TEXT,                           -- technicians: Microsoft's permanent user ID, bound at first Microsoft sign-in
  prefs TEXT                                -- personal settings (JSON): appearance - colour theme and light/dark mode
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, created_at REAL NOT NULL, expires REAL NOT NULL, last_seen REAL NOT NULL, ip TEXT
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY, org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,   -- NULL until a tech approves it
  name TEXT NOT NULL, name_custom INTEGER NOT NULL DEFAULT 0, site TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
  public_ip TEXT, first_seen REAL,
  tunnel_ip TEXT UNIQUE, wg_pubkey TEXT UNIQUE,
  token_hash TEXT, token_expires REAL,
  state TEXT NOT NULL DEFAULT 'pending',    -- pending (registered, waiting for a tech to approve) / adopted
  adopted_at REAL, last_seen REAL, last_poll REAL, online INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  identity TEXT, model TEXT, serial TEXT, version TEXT, board TEXT, uptime TEXT,
  cpu INTEGER, mem_used INTEGER, mem_total INTEGER, wan_ip TEXT,
  hdd_free INTEGER, hdd_total INTEGER, bad_blocks TEXT, fw_current TEXT, fw_upgrade TEXT,
  last_backup_at REAL, last_backup_try REAL, last_backup_error TEXT, thumb_slug TEXT, thumb_tried REAL,
  interfaces TEXT, networks TEXT,           -- JSON
  ros_channel TEXT, ros_latest TEXT, ros_checked REAL,   -- newest RouterOS on the router's update channel (checked twice a day)
  itg_config_id TEXT, itg_synced_at REAL, itg_error TEXT,   -- IT Glue configuration this router is documented as
  vpn_inv TEXT, vpn_inv_at REAL,
  neighbors TEXT, neighbors_at REAL,       -- MikroTik devices next to it (/ip neighbor), for Discovered
  lat REAL, lon REAL, location TEXT,       -- where it is (map): typed in, picked on the map, or from the router's GPS
  loc_source TEXT,                          -- manual / gps (manual always wins)
  api_port INTEGER,                         -- the router's www (REST) port, reported when it runs the adoption command                         -- VPNs already configured on the router (raw, whitelisted fields)
  created_at REAL NOT NULL, created_by TEXT
);
CREATE INDEX IF NOT EXISTS devices_org ON devices(org_id);
CREATE TABLE IF NOT EXISTS metrics (
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts REAL NOT NULL,
  cpu INTEGER, mem_pct REAL, rx_bps REAL, tx_bps REAL, latency REAL, loss REAL
);
CREATE INDEX IF NOT EXISTS metrics_dev ON metrics(device_id, ts);
CREATE TABLE IF NOT EXISTS iface_metrics (
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts REAL NOT NULL, name TEXT NOT NULL,
  rx_bps REAL, tx_bps REAL
);
CREATE INDEX IF NOT EXISTS iface_metrics_dev ON iface_metrics(device_id, name, ts);
CREATE TABLE IF NOT EXISTS metrics_hourly (           -- hourly averages kept 90 days (for the 1W/1M charts); iface '' = whole router (WAN)
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts REAL NOT NULL, iface TEXT NOT NULL,
  rx_bps REAL, tx_bps REAL, cpu REAL, latency REAL, loss REAL, PRIMARY KEY (device_id, iface, ts)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  org_id INTEGER, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_dev ON events(device_id, ts);
CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, org_id INTEGER,
  ts REAL NOT NULL, checked_at REAL, size INTEGER, sha256 TEXT NOT NULL, blob BLOB NOT NULL, enc TEXT NOT NULL,
  trigger TEXT, by_user TEXT, added INTEGER, removed INTEGER, lines INTEGER
);
CREATE INDEX IF NOT EXISTS backups_dev ON backups(device_id, ts);
CREATE TABLE IF NOT EXISTS upgrades (                 -- RouterOS / RouterBOARD upgrade jobs, now or scheduled
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, org_id INTEGER,
  batch TEXT, scheduled_at REAL NOT NULL, channel TEXT, firmware INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'scheduled',          -- scheduled / running / done / failed / cancelled
  step TEXT, from_version TEXT, to_version TEXT, detail TEXT,
  created_by TEXT, created_at REAL NOT NULL, started_at REAL, finished_at REAL
);
CREATE INDEX IF NOT EXISTS upgrades_due ON upgrades(status, scheduled_at);
CREATE TABLE IF NOT EXISTS vpns (                     -- site-to-site WireGuard VPN, hub and spoke, one client each
  id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE, name TEXT NOT NULL,
  hub_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, endpoint TEXT, port INTEGER NOT NULL DEFAULT 13232,
  tunnel_net TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft',   -- draft / applying / active / failed / disabled
  last_error TEXT, last_applied REAL, created_by TEXT, created_at REAL NOT NULL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS vpn_sites (
  id INTEGER PRIMARY KEY, vpn_id INTEGER NOT NULL REFERENCES vpns(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,   -- a router is in at most one VPN
  tunnel_ip TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]', pubkey TEXT,
  state TEXT NOT NULL DEFAULT 'pending',            -- pending / applied / failed / removing
  last_error TEXT, applied_at REAL, handshake_age INTEGER, ping_ms REAL, rx INTEGER, tx INTEGER, checked_at REAL
);
CREATE TABLE IF NOT EXISTS scripts (                  -- script library
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', body TEXT NOT NULL,
  created_by TEXT, created_at REAL NOT NULL, updated_by TEXT, updated_at REAL
);
CREATE TABLE IF NOT EXISTS router_groups (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, description TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id INTEGER NOT NULL REFERENCES router_groups(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, PRIMARY KEY (group_id, device_id)
);
CREATE TABLE IF NOT EXISTS tasks (                    -- scheduled script runs / firmware upgrades
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, action TEXT NOT NULL DEFAULT 'script',   -- script / upgrade
  script_id INTEGER REFERENCES scripts(id) ON DELETE RESTRICT, options TEXT NOT NULL DEFAULT '{}',
  targets TEXT NOT NULL DEFAULT '{}',                -- {all, orgs: [], groups: [], devices: []}
  kind TEXT NOT NULL,                                -- once / daily / weekly / hourly
  run_at REAL, at_time TEXT, days TEXT, every_hours INTEGER, tz TEXT,
  backup_first INTEGER NOT NULL DEFAULT 1, offline TEXT NOT NULL DEFAULT 'skip',   -- skip / wait (up to 24 h)
  enabled INTEGER NOT NULL DEFAULT 1, next_run REAL, last_run REAL, last_status TEXT,
  created_by TEXT, created_at REAL NOT NULL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS task_runs (
  id INTEGER PRIMARY KEY, task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL, task_name TEXT, action TEXT NOT NULL DEFAULT 'script',
  script_name TEXT, script_body TEXT, options TEXT, backup_first INTEGER NOT NULL DEFAULT 1, offline TEXT NOT NULL DEFAULT 'skip',
  started_at REAL NOT NULL, finished_at REAL, status TEXT NOT NULL DEFAULT 'running', by_user TEXT, trigger TEXT
);
CREATE TABLE IF NOT EXISTS task_results (
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, device_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending',            -- pending / running / waiting / ok / failed / skipped
  output TEXT, started_at REAL, finished_at REAL, wait_until REAL
);
CREATE INDEX IF NOT EXISTS task_results_run ON task_results(run_id, status);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, user TEXT, org_id INTEGER, action TEXT NOT NULL,
  target TEXT, ip TEXT, detail TEXT
);
"""


class DB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._c = None
        self.lock = threading.RLock()
        self.write_lock = self.lock   # (older name)
        with self.lock:
            self.migrate()
            self.conn().executescript(SCHEMA)

    def migrate(self):
        """Bring an existing database up to the current schema (adds columns; rebuilds devices so org_id may be NULL)."""
        c = self.conn()
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "orgs" in tables:
            cols = {r[1] for r in c.execute("PRAGMA table_info(orgs)")}
            for col, ddl in (("cw_id", "INTEGER"), ("source", "TEXT NOT NULL DEFAULT 'manual'"), ("active", "INTEGER NOT NULL DEFAULT 1"), ("itg_id", "TEXT")):
                if col not in cols:
                    c.execute(f"ALTER TABLE orgs ADD COLUMN {col} {ddl}")
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS orgs_cw ON orgs(cw_id)")
        if "users" in tables and "entra_oid" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:
            c.execute("ALTER TABLE users ADD COLUMN entra_oid TEXT")
        if "users" in tables and "prefs" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:
            c.execute("ALTER TABLE users ADD COLUMN prefs TEXT")
        if "metrics" in tables:
            mcols = {r[1] for r in c.execute("PRAGMA table_info(metrics)")}
            for col in ("latency", "loss"):
                if col not in mcols:
                    c.execute(f"ALTER TABLE metrics ADD COLUMN {col} REAL")
        if "devices" in tables:
            info = {r[1]: r for r in c.execute("PRAGMA table_info(devices)")}
            for col, ddl in (("hdd_free", "INTEGER"), ("hdd_total", "INTEGER"), ("bad_blocks", "TEXT"), ("fw_current", "TEXT"),
                             ("fw_upgrade", "TEXT"), ("public_ip", "TEXT"), ("first_seen", "REAL"), ("last_backup_at", "REAL"),
                             ("last_backup_try", "REAL"), ("last_backup_error", "TEXT"), ("thumb_slug", "TEXT"), ("thumb_tried", "REAL"), ("networks", "TEXT"),
                             ("ros_channel", "TEXT"), ("ros_latest", "TEXT"), ("ros_checked", "REAL"),
                             ("itg_config_id", "TEXT"), ("itg_synced_at", "REAL"), ("itg_error", "TEXT"),
                             ("vpn_inv", "TEXT"), ("vpn_inv_at", "REAL"), ("api_port", "INTEGER"),
                             ("lat", "REAL"), ("lon", "REAL"), ("location", "TEXT"), ("loc_source", "TEXT"),
                             ("neighbors", "TEXT"), ("neighbors_at", "REAL")):
                if col not in info and "name_custom" in info:   # (older schemas are rebuilt below with every column)
                    c.execute(f"ALTER TABLE devices ADD COLUMN {col} {ddl}")
            if info["org_id"][3] == 1 or "name_custom" not in info:   # org_id NOT NULL (old schema)
                # SQLite's documented way to change a table: build the new one, copy, drop the old, rename the new into place
                # (renaming the OLD table instead would repoint metrics/events at it).
                old = list(info)
                c.execute("PRAGMA foreign_keys=OFF")
                c.execute("BEGIN")
                dev_sql = "CREATE TABLE devices_new" + SCHEMA.split("CREATE TABLE IF NOT EXISTS devices")[1].split(";")[0]
                c.execute(dev_sql)
                new = [r[1] for r in c.execute("PRAGMA table_info(devices_new)")]
                common = ", ".join(x for x in old if x in new)
                c.execute(f"INSERT INTO devices_new ({common}) SELECT {common} FROM devices")
                c.execute("UPDATE devices_new SET name_custom = 1")   # names typed before this change were chosen by a person
                c.execute("DROP TABLE devices")
                c.execute("ALTER TABLE devices_new RENAME TO devices")
                c.execute("COMMIT")
                c.execute("PRAGMA foreign_keys=ON")

    def setting(self, k, default=None):
        r = self.one("SELECT v FROM settings WHERE k=?", (k,))
        return r["v"] if r else default

    def set_setting(self, k, v):
        self.run("INSERT INTO settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    def conn(self) -> sqlite3.Connection:
        """ONE connection for the whole process, shared by every thread and used under self.lock.
        (A connection per thread leaked: TikManager starts short-lived threads for every web request, poll round,
        backup, upgrade and task, and their connections piled up until the process ran out of file handles.)"""
        if self._c is None:
            c = sqlite3.connect(self.path, timeout=15, isolation_level=None, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=15000")
            self._c = c
        return self._c

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn().execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        with self.lock:
            r = self.conn().execute(sql, args).fetchone()
            return dict(r) if r else None

    def run(self, sql, args=()):
        with self.lock:
            return self.conn().execute(sql, args).lastrowid

    def audit(self, user, action, target="", ip="", detail="", org_id=None):
        self.run("INSERT INTO audit (ts, user, org_id, action, target, ip, detail) VALUES (?,?,?,?,?,?,?)",
                 (time.time(), user, org_id, action, str(target)[:300], ip, json.dumps(detail)[:2000] if not isinstance(detail, str) else detail[:2000]))

    def event(self, device_id, org_id, kind, detail=""):
        self.run("INSERT INTO events (device_id, org_id, ts, kind, detail) VALUES (?,?,?,?,?)", (device_id, org_id, time.time(), kind, detail[:1000]))
