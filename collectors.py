"""Network collectors (Admin > Collectors).

An Auvik-style model: a lightweight agent is installed as a scheduled task on a Windows (or Linux) box at a client site,
tied to that client by an enroll token. The agent scans the local network (ping / ARP / reverse-DNS in v1) and reports
back; TikManager folds the result into IPAM under the collector's client. SNMP (device + VLAN discovery) comes in v2.

Enroll tokens work exactly like the outbound API keys (apikeys.py):
- created by an administrator, shown **once** in full, then only ever by their prefix (e.g. `tkc_ab12cd…`),
- stored as a SHA-256 hash (never the token itself), so a leaked database can't be used to report data,
- bound to one client (org_id) - everything the agent reports lands under that client, never one it names itself.

Kept generic for the public build (astukestarr/tikmanager): no company-specific anything.
"""
import hashlib
import json
import secrets
import threading
import time

DEFAULT_INTERVAL_MIN = 30   # how often the agent sweeps, unless overridden per collector


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Collectors:
    def __init__(self, db):
        self.db = db
        self.lock = threading.Lock()

    # --- management (administrators, through the normal session API) ---------------------------------------------
    def list(self):
        """Every collector, without any secret - safe to show on the admin page."""
        rows = self.db.q("""SELECT c.*, o.name AS org FROM collectors c LEFT JOIN orgs o ON o.id=c.org_id
                            ORDER BY o.name, c.name""")
        return [self._public(r) for r in rows]

    @staticmethod
    def _public(r):
        r = dict(r)
        cfg = {}
        try:
            cfg = json.loads(r.get("config") or "{}")
        except (ValueError, TypeError):
            cfg = {}
        snmp = cfg.get("snmp") or {}
        return {"id": r["id"], "org_id": r.get("org_id"), "org": r.get("org"), "name": r["name"], "prefix": r["prefix"],
                "enabled": bool(r["enabled"]), "ranges": cfg.get("ranges") or [], "interval_min": cfg.get("interval_min") or DEFAULT_INTERVAL_MIN,
                "snmp_enabled": bool(snmp.get("enabled")), "snmp_communities": len(snmp.get("communities") or []),   # count only - never the strings
                "agent_version": r.get("agent_version"), "last_seen": r.get("last_seen"), "last_ip": r.get("last_ip"),
                "created_by": r.get("created_by"), "created_at": r.get("created_at")}

    def get(self, cid):
        row = self.db.one("""SELECT c.*, o.name AS org FROM collectors c LEFT JOIN orgs o ON o.id=c.org_id WHERE c.id=?""", (int(cid),))
        return self._public(row) if row else None

    def create(self, org_id, name, user):
        """Make a new collector for a client. Returns (public row, full token) - the token is shown only this once."""
        if not org_id or not self.db.one("SELECT id FROM orgs WHERE id=?", (int(org_id),)):
            raise ValueError("Pick a client for this collector.")
        name = (name or "").strip()[:100] or "Collector"
        token = "tkc_" + secrets.token_urlsafe(30)   # ~40 url-safe chars of entropy
        h, prefix = _hash(token), token[:12] + "…"
        cfg = json.dumps({"ranges": [], "interval_min": DEFAULT_INTERVAL_MIN, "snmp": {"enabled": False, "communities": []}})
        cid = self.db.run("""INSERT INTO collectors (org_id, name, prefix, token_hash, config, enabled, created_by, created_at)
                             VALUES (?,?,?,?,?,1,?,?)""", (int(org_id), name, prefix, h, cfg, user, time.time()))
        return self.get(cid), token

    def update(self, cid, name=None, enabled=None, ranges=None, interval_min=None, snmp_enabled=None, communities=None):
        row = self.db.one("SELECT * FROM collectors WHERE id=?", (int(cid),))
        if not row:
            return None
        name = (name or row["name"]).strip()[:100] or row["name"]
        en = int(bool(enabled)) if enabled is not None else row["enabled"]
        try:
            cfg = json.loads(row["config"] or "{}")
        except (ValueError, TypeError):
            cfg = {}
        if ranges is not None:
            cfg["ranges"] = [str(x).strip() for x in ranges if str(x).strip()][:200]
        if interval_min is not None:
            try:
                cfg["interval_min"] = max(5, min(1440, int(interval_min)))
            except (ValueError, TypeError):
                pass
        if snmp_enabled is not None or communities is not None:
            snmp = cfg.get("snmp") or {}
            if snmp_enabled is not None:
                snmp["enabled"] = bool(snmp_enabled)
            if communities is not None:
                snmp["communities"] = [str(x).strip() for x in communities if str(x).strip()][:10]
            cfg["snmp"] = snmp
        self.db.run("UPDATE collectors SET name=?, enabled=?, config=? WHERE id=?", (name, en, json.dumps(cfg), int(cid)))
        return self.get(cid)

    def delete(self, cid):
        self.db.run("DELETE FROM collectors WHERE id=?", (int(cid),))

    # --- the agent side (the /api/collector routes) --------------------------------------------------------------
    def verify(self, authorization, ip="", agent_version=None):
        """Return the collector row for a valid `Authorization: Bearer <token>`, or None. Records the check-in."""
        if not authorization:
            return None
        parts = authorization.split(None, 1)
        token = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else authorization.strip()
        if not token:
            return None
        row = self.db.one("SELECT * FROM collectors WHERE token_hash=? AND enabled=1", (_hash(token),))
        if not row:
            return None
        self.db.run("UPDATE collectors SET last_seen=?, last_ip=?, agent_version=COALESCE(?, agent_version) WHERE id=?",
                    (time.time(), ip[:64], (agent_version or None), row["id"]))
        return row

    def config_for(self, row):
        """What the agent pulls (over HTTPS, bearer-authed): scan ranges, interval, and SNMP settings incl. the
        community strings (sent only to the agent, never shown on the admin page)."""
        try:
            cfg = json.loads(row["config"] or "{}")
        except (ValueError, TypeError):
            cfg = {}
        snmp = cfg.get("snmp") or {}
        return {"ranges": cfg.get("ranges") or [], "interval_min": cfg.get("interval_min") or DEFAULT_INTERVAL_MIN,
                "snmp": {"enabled": bool(snmp.get("enabled")), "communities": snmp.get("communities") or []}}
