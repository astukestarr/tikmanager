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
  itg_id TEXT,                              -- linked IT Glue organization
  client_winbox TEXT NOT NULL DEFAULT 'off', -- client admins may open Winbox to their routers: off / read / full
  client_vpn INTEGER NOT NULL DEFAULT 0      -- client admins may manage their site-to-site VPNs
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
  csrf TEXT NOT NULL, created_at REAL NOT NULL, expires REAL NOT NULL, last_seen REAL NOT NULL, ip TEXT,
  as_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL   -- "View as": an administrator seeing what this client user sees
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
  wg_port INTEGER,                         -- the UDP port this router dials TikManager on (wgport.py)
  fw_factory TEXT,                         -- RouterOS version it left the factory with (dates it, lifecycle.py)
  lc_slug TEXT, lc_status TEXT, lc_made TEXT, lc_checked REAL,   -- lifecycle: product page, discontinued/current/virtual, factory firmware date
  lc_suggest TEXT, lc_suggest_name TEXT, lc_suggest_why TEXT,   -- suggested replacement (product page slug, name, why)
  dm_mode TEXT, dm_flagged INTEGER, dm_info TEXT, dm_checked REAL,   -- RouterOS device-mode (hourly); flagged = possibly compromised
  sec_target TEXT, cve_n INTEGER, cve_max REAL, sec_info TEXT, sec_version TEXT, sec_checked REAL,   -- rossec.py: security releases / CVEs
  health TEXT, health_at REAL,             -- latest sensor readings {name: {value, unit}} (health_metrics has the history)
  bgp_at REAL,                              -- when the BGP sessions were last read
  flows_on INTEGER NOT NULL DEFAULT 0, flows_prev TEXT,   -- Flows pilot: on, and the Traffic Flow settings to put back
  bgp_state TEXT,                           -- BGP peers (JSON {name: {up, remote, as, since, uptime, prefixes}}); NULL = no BGP
  isp_ifaces TEXT, isp_state TEXT,         -- internet links: chosen interfaces (JSON, null = automatic) and their state
  last_reboot REAL, last_reboot_why TEXT,  -- last restart TikManager noticed (uptime went back): upgrade / unexpected
  tags TEXT,                               -- JSON list of tags (technicians), e.g. ["core", "poe-switch"]
  kind_override TEXT,                      -- router / switch / ap when the automatic guess (devkind.py) is wrong
  lat REAL, lon REAL, location TEXT,       -- where it is (map): typed in, picked on the map, or from the router's GPS
  loc_source TEXT,                          -- manual / gps (manual always wins)
  api_port INTEGER,                         -- the router's www (REST) port, reported when it runs the adoption command
  api_tls_port INTEGER,                     -- www-ssl port when TikManager manages the router over HTTPS (NULL = HTTP)
  api_tls_fp TEXT,                          -- that certificate's SHA-256 when it was switched (shown; not enforced - see routeros.TLS)                         -- VPNs already configured on the router (raw, whitelisted fields)
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
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);   -- recent events (dashboard, every 30 s) and pruning
CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, org_id INTEGER,
  ts REAL NOT NULL, checked_at REAL, size INTEGER, sha256 TEXT NOT NULL, blob BLOB NOT NULL, enc TEXT NOT NULL,
  trigger TEXT, by_user TEXT, added INTEGER, removed INTEGER, lines INTEGER
);
CREATE INDEX IF NOT EXISTS backups_dev ON backups(device_id, ts);
CREATE TABLE IF NOT EXISTS upgrades (                 -- RouterOS / RouterBOARD upgrade jobs, now or scheduled
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, org_id INTEGER,
  batch TEXT, scheduled_at REAL NOT NULL, channel TEXT, firmware INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'scheduled',          -- scheduled / running / done / failed / cancelled / held (safety stop) / skipped (pinned)
  step TEXT, from_version TEXT, to_version TEXT, detail TEXT,
  created_by TEXT, created_at REAL NOT NULL, started_at REAL, finished_at REAL,
  seq INTEGER, sequential INTEGER NOT NULL DEFAULT 0,  -- order in its batch; 1 = one at a time, each after the previous succeeded
  max_fail INTEGER,                                   -- safety stop: hold the rest of the batch after this many failures
  pin_version TEXT                                    -- don't install anything newer than this (the version reviewed when scheduling)
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
CREATE TABLE IF NOT EXISTS ra_servers (               -- remote access (WireGuard for Windows ...) into one router
  device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, port INTEGER NOT NULL, pool TEXT NOT NULL,
  endpoint TEXT NOT NULL, split INTEGER NOT NULL DEFAULT 1, routes TEXT NOT NULL DEFAULT '[]', dns TEXT NOT NULL DEFAULT '',
  pubkey TEXT, state TEXT NOT NULL DEFAULT 'pending',   -- applying / applied / failed
  last_error TEXT, applied_at REAL, created_by TEXT, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ra_users (                 -- one person (device) per row; the private key only until the config is downloaded
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES ra_servers(device_id) ON DELETE CASCADE,
  name TEXT NOT NULL, ip TEXT NOT NULL, pubkey TEXT NOT NULL, created_by TEXT, created_at REAL NOT NULL,
  state TEXT NOT NULL DEFAULT 'applying', last_error TEXT,
  cfg_blob BLOB, cfg_alg TEXT, cfg_token TEXT, cfg_expires REAL, downloaded_at REAL,
  disabled INTEGER NOT NULL DEFAULT 0,               -- switched off for now (peer disabled on the router), same config
  expires_at REAL, reminded INTEGER NOT NULL DEFAULT 0,   -- revoked automatically then; a reminder event 3 days before
  access TEXT                                          -- NULL = everything the setup allows; else JSON [{host, service, proto, ports}]
);
CREATE TABLE IF NOT EXISTS exceptions (               -- accepted findings: "this is fine on this router, because ..."
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key TEXT NOT NULL,                                   -- hd:<Performance & security finding title> or cc:<compliance check id>
  reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL,
  UNIQUE (device_id, key)
);
CREATE TABLE IF NOT EXISTS ra_sessions (              -- remote access connection log: who was connected, when, from where
  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES ra_users(id) ON DELETE SET NULL, user_name TEXT NOT NULL, tunnel_ip TEXT, public_ip TEXT,
  started_at REAL NOT NULL, last_seen REAL NOT NULL, ended_at REAL, rx0 INTEGER, tx0 INTEGER, rx INTEGER, tx INTEGER,
  flag TEXT                                            -- new_ip (an address this person never used) / shared (the key used from two places)
);
CREATE INDEX IF NOT EXISTS ra_sessions_dev ON ra_sessions(device_id, started_at);
CREATE INDEX IF NOT EXISTS ra_sessions_user ON ra_sessions(user_id, started_at);   -- unusual-connection checks (per person)
CREATE INDEX IF NOT EXISTS ra_sessions_started ON ra_sessions(started_at);         -- alerts: flagged sessions in the last hour
CREATE INDEX IF NOT EXISTS ra_sessions_ended ON ra_sessions(ended_at);             -- pruning
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
-- sign-in attempts and other security events from TikManager itself, the Ubuntu server and the routers (secevents.py)
CREATE TABLE IF NOT EXISTS sec_events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL,   -- source: tikmanager / server / router
  user TEXT, ip TEXT, device_id INTEGER, via TEXT, detail TEXT, uid TEXT UNIQUE          -- uid: de-duplicates imported events
);
CREATE INDEX IF NOT EXISTS sec_events_ts ON sec_events(ts);
CREATE TABLE IF NOT EXISTS messages (               -- Message Center (messages.py): release notes and notices
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL,   -- release / notice
  title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', version TEXT, audience TEXT NOT NULL DEFAULT 'tech',   -- tech / all
  created_by TEXT, always INTEGER NOT NULL DEFAULT 0   -- 1 = new accounts get it too, however long after it was posted
);
CREATE TABLE IF NOT EXISTS message_acks (           -- who acknowledged which message
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  acked_at REAL NOT NULL, PRIMARY KEY (user_id, message_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS flows (                  -- Flows pilot (flows.py): conversations summed per 10 minutes, kept 7 days
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts INTEGER NOT NULL,
  local TEXT NOT NULL, remote TEXT NOT NULL, port INTEGER NOT NULL, proto INTEGER NOT NULL, dir TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, ts, local, remote, port, proto, dir)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS region_sync (            -- region blocking: where each router's list stands
  device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'off',                 -- off / loading / synced / paused / waiting / too_big / error
  detail TEXT, mode TEXT, entries INTEGER, target_hash TEXT, hits INTEGER,
  synced_at REAL, refreshed_at REAL, checked_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS health_metrics (   -- board sensors and fibre (SFP) readings every 5 minutes, kept 30 days
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ts REAL NOT NULL, name TEXT NOT NULL, value REAL
);
CREATE INDEX IF NOT EXISTS health_dev ON health_metrics(device_id, ts);
CREATE TABLE IF NOT EXISTS router_logs (   -- every log line routers send (routerlogs.py), kept 14 days
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  topics TEXT, severity TEXT, message TEXT
);
CREATE INDEX IF NOT EXISTS router_logs_dev ON router_logs(device_id, id);
CREATE INDEX IF NOT EXISTS router_logs_ts ON router_logs(ts);
CREATE TABLE IF NOT EXISTS autoblock (     -- addresses blocked on every router (autoblock.py)
  ip TEXT PRIMARY KEY, blocked_at REAL, until REAL, failures INTEGER, by TEXT, reason TEXT, released_at REAL
);
CREATE TABLE IF NOT EXISTS autoblock_push (   -- which router has which block (error = couldn't add it)
  ip TEXT NOT NULL, device_id INTEGER NOT NULL, pushed_at REAL, error TEXT, PRIMARY KEY (ip, device_id)
);
CREATE INDEX IF NOT EXISTS sec_events_ip ON sec_events(ip, ts);
-- alerts (alerts.py): one row per problem while it lasts; key identifies the problem (e.g. offline:12)
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, key TEXT NOT NULL, kind TEXT NOT NULL, device_id INTEGER, org_id INTEGER,
  title TEXT NOT NULL, detail TEXT, opened_at REAL NOT NULL, resolved_at REAL,
  cw_ticket INTEGER, cw_note TEXT, teams_note TEXT
);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(resolved_at, key);
CREATE TABLE IF NOT EXISTS net_accounts (                -- UniFi / UISP connections (ubnt.py); org_id set = one client's own account
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('unifi', 'uisp')), name TEXT NOT NULL, url TEXT,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE, secret TEXT, last TEXT, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS net_sites (
  id TEXT PRIMARY KEY,                                    -- "<account id>:<site id on the platform>"
  account_id INTEGER NOT NULL REFERENCES net_accounts(id) ON DELETE CASCADE, name TEXT, internal TEXT, console TEXT, gateway_mac TEXT,
  type TEXT, org_id INTEGER REFERENCES orgs(id) ON DELETE SET NULL, stats TEXT, seen_at REAL,
  wan_ip TEXT,                                            -- the site's public address (matched against routers' WAN / public IPs)
  matched TEXT,                                           -- why it has its client: "Public IP ... = router ...", "name", "chosen by ..."
  org_manual INTEGER NOT NULL DEFAULT 0                   -- 1: a person chose the client - syncs never change it
);
CREATE TABLE IF NOT EXISTS net_devices (
  id TEXT PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES net_accounts(id) ON DELETE CASCADE,
  site_key TEXT,                                          -- NULL: a UniFi multi-site console's device not matched to a site
  host TEXT, mac TEXT, name TEXT, model TEXT, ip TEXT, status TEXT, version TEXT, update_available TEXT,
  is_console INTEGER NOT NULL DEFAULT 0, startup_time TEXT, offline_since REAL, updated_at REAL
);
CREATE INDEX IF NOT EXISTS net_devices_site ON net_devices(site_key);
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
            for col, ddl in (("cw_id", "INTEGER"), ("source", "TEXT NOT NULL DEFAULT 'manual'"), ("active", "INTEGER NOT NULL DEFAULT 1"), ("itg_id", "TEXT"),
                             ("client_winbox", "TEXT NOT NULL DEFAULT 'off'"), ("client_vpn", "INTEGER NOT NULL DEFAULT 0")):
                if col not in cols:
                    c.execute(f"ALTER TABLE orgs ADD COLUMN {col} {ddl}")
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS orgs_cw ON orgs(cw_id)")
        if "users" in tables and "entra_oid" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:
            c.execute("ALTER TABLE users ADD COLUMN entra_oid TEXT")
        if "users" in tables and "prefs" not in {r[1] for r in c.execute("PRAGMA table_info(users)")}:
            c.execute("ALTER TABLE users ADD COLUMN prefs TEXT")
        if "messages" in tables and "always" not in {r[1] for r in c.execute("PRAGMA table_info(messages)")}:
            c.execute("ALTER TABLE messages ADD COLUMN always INTEGER NOT NULL DEFAULT 0")
        if "net_sites" in tables:
            cols = {r[1] for r in c.execute("PRAGMA table_info(net_sites)")}
            for col, ddl in (("wan_ip", "TEXT"), ("matched", "TEXT"), ("org_manual", "INTEGER NOT NULL DEFAULT 0")):
                if col not in cols:
                    c.execute(f"ALTER TABLE net_sites ADD COLUMN {col} {ddl}")
        if "ra_users" in tables:
            rcols = {r[1] for r in c.execute("PRAGMA table_info(ra_users)")}
            for col, ddl in (("disabled", "INTEGER NOT NULL DEFAULT 0"), ("expires_at", "REAL"), ("reminded", "INTEGER NOT NULL DEFAULT 0"), ("access", "TEXT")):
                if col not in rcols:
                    c.execute(f"ALTER TABLE ra_users ADD COLUMN {col} {ddl}")
        if "ra_sessions" in tables and "flag" not in {r[1] for r in c.execute("PRAGMA table_info(ra_sessions)")}:
            c.execute("ALTER TABLE ra_sessions ADD COLUMN flag TEXT")
        if "sessions" in tables and "as_user_id" not in {r[1] for r in c.execute("PRAGMA table_info(sessions)")}:
            c.execute("ALTER TABLE sessions ADD COLUMN as_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")
        if "upgrades" in tables:
            ucols = {r[1] for r in c.execute("PRAGMA table_info(upgrades)")}
            for col, ddl in (("seq", "INTEGER"), ("sequential", "INTEGER NOT NULL DEFAULT 0"), ("max_fail", "INTEGER"), ("pin_version", "TEXT")):
                if col not in ucols:
                    c.execute(f"ALTER TABLE upgrades ADD COLUMN {col} {ddl}")
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
                             ("vpn_inv", "TEXT"), ("vpn_inv_at", "REAL"), ("api_port", "INTEGER"), ("api_tls_port", "INTEGER"), ("api_tls_fp", "TEXT"),
                             ("lat", "REAL"), ("lon", "REAL"), ("location", "TEXT"), ("loc_source", "TEXT"),
                             ("neighbors", "TEXT"), ("neighbors_at", "REAL"), ("wg_port", "INTEGER"),
                             ("fw_factory", "TEXT"), ("lc_slug", "TEXT"), ("lc_status", "TEXT"), ("lc_made", "TEXT"), ("lc_checked", "REAL"),
                             ("lc_suggest", "TEXT"), ("lc_suggest_name", "TEXT"), ("lc_suggest_why", "TEXT"),
                             ("dm_mode", "TEXT"), ("dm_flagged", "INTEGER"), ("dm_info", "TEXT"), ("dm_checked", "REAL"),
                             ("sec_target", "TEXT"), ("cve_n", "INTEGER"), ("cve_max", "REAL"), ("sec_info", "TEXT"), ("sec_version", "TEXT"),
                             ("sec_checked", "REAL"), ("health", "TEXT"), ("health_at", "REAL"), ("isp_ifaces", "TEXT"), ("isp_state", "TEXT"), ("bgp_state", "TEXT"), ("bgp_at", "REAL"), ("flows_on", "INTEGER NOT NULL DEFAULT 0"), ("flows_prev", "TEXT"),
                             ("last_reboot", "REAL"), ("last_reboot_why", "TEXT"), ("tags", "TEXT"), ("kind_override", "TEXT")):
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

    def many(self, sql, rows):
        """One statement for many rows, in one transaction (batched inserts)."""
        with self.lock:
            c = self.conn()
            c.execute("BEGIN")
            try:
                c.executemany(sql, rows)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

    def audit(self, user, action, target="", ip="", detail="", org_id=None):
        self.run("INSERT INTO audit (ts, user, org_id, action, target, ip, detail) VALUES (?,?,?,?,?,?,?)",
                 (time.time(), user, org_id, action, str(target)[:300], ip, json.dumps(detail)[:2000] if not isinstance(detail, str) else detail[:2000]))

    def event(self, device_id, org_id, kind, detail=""):
        self.run("INSERT INTO events (device_id, org_id, ts, kind, detail) VALUES (?,?,?,?,?)", (device_id, org_id, time.time(), kind, detail[:1000]))
