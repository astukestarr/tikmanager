"""Outbound read API tokens (Admin > API access).

Other systems pull data from TikManager over `/api/v1/...` using a bearer token instead of a user session. Keys are:
- created by an administrator, shown **once** in full, then only ever shown by their prefix (e.g. `tk_ab12cd…`),
- stored as a SHA-256 hash (the token itself is never kept), so a leaked database can't be used to call the API,
- scoped to a set of read areas (see SCOPES) - a key only reads what it was granted,
- read-only: every `/api/v1` route is a GET; nothing here can change a router, a ticket or a setting.

Kept generic for the public build (astukestarr/tikmanager): no company-specific anything, same as the rest of TikManager.
"""
import hashlib
import json
import secrets
import threading
import time

# Each scope unlocks one read area of the API. Keep these generic and stable - they're part of the public contract.
SCOPES = {
    "devices": "Routers and their status, inventory and health",
    "clients": "Clients (organisations) and their router counts",
    "alerts": "Open alerts",
    "health": "Fleet summary counts",
}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ApiKeys:
    def __init__(self, db):
        self.db = db
        self.lock = threading.Lock()

    # --- management (administrators, through the normal session API) ---------------------------------------------
    def list(self):
        """Every key, without any secret - safe to show on the admin page."""
        return [self._public(r) for r in self.db.q("SELECT * FROM api_keys ORDER BY name")]

    @staticmethod
    def _public(r):
        r = dict(r)
        return {"id": r["id"], "name": r["name"], "prefix": r["prefix"], "scopes": json.loads(r.get("scopes") or "[]"),
                "enabled": bool(r["enabled"]), "created_by": r.get("created_by"), "created_at": r.get("created_at"),
                "last_used": r.get("last_used"), "last_ip": r.get("last_ip"), "calls": r.get("calls") or 0}

    def create(self, name, scopes, user):
        """Make a new key. Returns (public row, full token) - the token is the only time the caller ever sees it."""
        name = (name or "").strip()[:100] or "API key"
        scopes = self._clean_scopes(scopes)
        token = "tk_" + secrets.token_urlsafe(30)   # ~40 url-safe chars of entropy
        h, prefix = _hash(token), token[:11] + "…"
        kid = self.db.run("""INSERT INTO api_keys (name, prefix, token_hash, scopes, enabled, created_by, created_at)
                             VALUES (?,?,?,?,1,?,?)""", (name, prefix, h, json.dumps(scopes), user, time.time()))
        return self._public(self.db.one("SELECT * FROM api_keys WHERE id=?", (kid,))), token

    def update(self, kid, name=None, scopes=None, enabled=None):
        row = self.db.one("SELECT * FROM api_keys WHERE id=?", (int(kid),))
        if not row:
            return None
        name = (name or row["name"]).strip()[:100] or row["name"]
        sc = json.dumps(self._clean_scopes(scopes)) if scopes is not None else row["scopes"]
        en = int(bool(enabled)) if enabled is not None else row["enabled"]
        self.db.run("UPDATE api_keys SET name=?, scopes=?, enabled=? WHERE id=?", (name, sc, en, int(kid)))
        return self._public(self.db.one("SELECT * FROM api_keys WHERE id=?", (int(kid),)))

    def delete(self, kid):
        self.db.run("DELETE FROM api_keys WHERE id=?", (int(kid),))

    @staticmethod
    def _clean_scopes(scopes):
        return [s for s in (scopes or []) if s in SCOPES] or list(SCOPES)   # empty = all read scopes

    # --- authentication (the /api/v1 routes) ---------------------------------------------------------------------
    def verify(self, authorization, ip=""):
        """Return the key row for a valid `Authorization: Bearer <token>` header, or None. Records the use."""
        if not authorization:
            return None
        parts = authorization.split(None, 1)
        token = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else authorization.strip()
        if not token:
            return None
        row = self.db.one("SELECT * FROM api_keys WHERE token_hash=? AND enabled=1", (_hash(token),))
        if not row:
            return None
        self.db.run("UPDATE api_keys SET last_used=?, last_ip=?, calls=calls+1 WHERE id=?", (time.time(), ip[:64], row["id"]))
        return row
