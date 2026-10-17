"""Technician roles (Admin > Technicians > Roles): what each role may change, permission by permission.

Every technician can look at everything they're allowed to see; a role decides what they can *change*. Three roles are
built in - Administrator (everything; can't be edited or removed), Technician and Read-only - and administrators add
their own, ticking permissions from PERMS. New Microsoft sign-ins get the default role (Admin > Technicians), which may
be "No access" (the account appears on the Technicians list, waiting for an administrator to give it a role).
Addresses in TM_TECH_ADMINS are always Administrators, so nobody can lock everyone out.

The server enforces it: require() maps the request to a permission (RULES, by path - the first match wins) unless the
route names one, and refuses with the permission's name. Client accounts (kind 'client') keep their own two roles.
"""
import json
import re
import time

ADMIN, NONE = "admin", "none"
# id, group, what it allows
PERMS = [
    ("devices", "Routers", "Adopt, approve, rename, move and delete devices; edit their details, tags, location and internet links; critical checks"),
    ("config", "Routers", "Change router configuration: firewall and NAT, ports, one-click fixes, HTTPS management, accepted findings, run scripts"),
    ("winbox", "Routers", "Open Winbox to routers through TikManager (full access - without this, read-only Winbox)"),
    ("upgrades", "Routers", "Upgrade RouterOS and firmware, now or scheduled"),
    ("backups", "Routers", "Take backups and download configurations (they hold the routers' settings)"),
    ("remote", "Routers", "Remote access: add, revoke and change WireGuard users"),
    ("vpn", "Routers", "Site-to-site VPNs: create, apply, disable and delete"),
    ("tasks", "Routers", "Scripts, router groups and scheduled tasks; the community script library"),
    ("flows", "Routers", "Turn Flows on and off on routers"),
    ("blocking", "Security", "Block and unblock addresses; region blocking, known bad networks and auto-block settings"),
    ("clients", "Clients", "Add and edit clients, invite client users, client Winbox / VPN access, View as a client"),
    ("techs", "Admin", "Technicians and roles: change people's roles, disable accounts, reset sign-in"),
    ("alerts", "Admin", "Alert settings, webhooks and log alert rules"),
    ("integrations", "Admin", "Integrations: ConnectWise, IT Glue, email, UniFi / UISP, GitHub, IPinfo"),
    ("settings", "Admin", "Settings, branding, updates, off-site backup, WireGuard port, adoption command, messages to everyone"),
]
PERM_IDS = [p[0] for p in PERMS]
LABEL = {p[0]: p[2] for p in PERMS}
BUILTIN = {
    ADMIN: {"id": ADMIN, "name": "Administrator", "perms": PERM_IDS, "builtin": True,
            "about": "Everything, including this page. Can't be changed."},
    "tech": {"id": "tech", "name": "Technician", "builtin": True, "about": "Manage, upgrade and back up routers, security and clients - not the Admin pages.",
             "perms": ["devices", "config", "winbox", "upgrades", "backups", "remote", "vpn", "tasks", "flows", "blocking", "clients"]},
    "readonly": {"id": "readonly", "name": "Read-only", "perms": [], "builtin": True, "about": "Looks at everything, changes nothing (Winbox read-only)."},
}
NO_ACCESS = {"id": NONE, "name": "No access (waiting)", "perms": [], "builtin": True, "about": "Signed in, but can't use TikManager until an administrator gives them a role."}

# request path -> permission, for routes that ask require() for write / admin access without naming one (first match wins)
RULES = [(re.compile(p), perm) for p, perm in [
    (r"^/api/devices/\d+/(firewall|ports|mgmt-https|identity)", "config"),
    (r"^/api/(health-dash/fix|exceptions|run-script)", "config"),
    (r"^/api/devices/\d+/(approve|location|rename|meta|isp|move|delete)$", "devices"),
    (r"^/api/(geocode|dev/register|unifi/assign)", "devices"),
    (r"^/api/devices/\d+/backup", "backups"),
    (r"^/api/backups", "backups"),
    (r"^/api/devices/\d+/ra", "remote"),
    (r"^/api/devices/\d+/flows", "flows"),
    (r"^/api/upgrades", "upgrades"),
    (r"^/api/(scripts|groups|tasks|library)", "tasks"),
    (r"^/api/(region|security/(autoblock|unban))", "blocking"),
    (r"^/api/orgs", "clients"),
    (r"^/api/users/(invite|\d+/(view-as|resend|disable|enable|reset-mfa))", "clients"),   # technician accounts also need techs (user_action)
    (r"^/api/(roles|users/\d+/role)", "techs"),
    (r"^/api/(admin/alerts|admin/webhooks|logs/rules)", "alerts"),
    (r"^/api/(integrations|net/accounts)", "integrations"),
    (r"^/api/(admin|adoption/rotate|messages/(post|\d+/delete)|branding)", "settings"),
]]


def rule_for(path):
    return next((perm for rx, perm in RULES if rx.search(path)), None)


class Roles:
    def __init__(self, db, env_admins=()):
        self.db = db
        self.env_admins = {e.strip().lower() for e in env_admins if e.strip()}

    def custom(self):
        try:
            return json.loads(self.db.setting("tech_roles") or "[]") or []
        except ValueError:
            return []

    def all(self):
        return [*BUILTIN.values(), *self.custom()]

    def get(self, rid):
        if rid == NONE:
            return NO_ACCESS
        return BUILTIN.get(rid) or next((r for r in self.custom() if r["id"] == rid), None)

    def default(self):
        rid = self.db.setting("tech_default_role") or "tech"
        return rid if rid == NONE or self.get(rid) else "tech"

    def set_default(self, rid):
        if rid != NONE and not self.get(rid):
            raise ValueError("No such role.")
        if rid == ADMIN:
            raise ValueError("New sign-ins can't become Administrators by default - pick another role.")
        self.db.set_setting("tech_default_role", rid)

    def perms(self, s):
        """The permissions of a signed-in technician (a session row with email + role)."""
        if (s.get("email") or "").lower() in self.env_admins:
            return set(PERM_IDS)
        r = self.get(s.get("role") or "")
        return set(r["perms"]) if r else set()

    def is_admin(self, s):
        return (s.get("email") or "").lower() in self.env_admins or s.get("role") == ADMIN

    def save(self, b, by):
        """Add or change a custom role: {id?, name, perms, about}."""
        name = str(b.get("name") or "").strip()[:60]
        if not name:
            raise ValueError("Give the role a name.")
        perms = [p for p in PERM_IDS if p in set(b.get("perms") or [])]
        roles = self.custom()
        rid = str(b.get("id") or "")
        if rid in BUILTIN or rid == NONE:
            raise ValueError("Built-in roles can't be changed - copy it into a new role instead.")
        if any(r["name"].lower() == name.lower() and r["id"] != rid for r in self.all()):
            raise ValueError("There's already a role with that name.")
        if rid:
            r = next((r for r in roles if r["id"] == rid), None)
            if not r:
                raise ValueError("No such role.")
        else:
            base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "role"
            rid, n = f"r-{base}", 2
            while self.get(rid):
                rid, n = f"r-{base}-{n}", n + 1
            r = {"id": rid}
            roles.append(r)
        r.update(name=name, perms=perms, about=str(b.get("about") or "").strip()[:200], updated_by=by, updated_at=time.time())
        self.db.set_setting("tech_roles", json.dumps(roles))
        return r

    def delete(self, rid):
        if rid in BUILTIN or rid == NONE:
            raise ValueError("Built-in roles can't be removed.")
        n = self.db.one("SELECT COUNT(*) AS n FROM users WHERE kind='tech' AND role=?", (rid,))["n"]
        if n:
            raise ValueError(f"{n} technician{'s' if n != 1 else ''} still {'have' if n != 1 else 'has'} this role - give them another one first.")
        if self.db.setting("tech_default_role") == rid:
            raise ValueError("This is the default role for new sign-ins - pick another default first.")
        self.db.set_setting("tech_roles", json.dumps([r for r in self.custom() if r["id"] != rid]))

    def public(self):
        counts = {r["role"]: r["n"] for r in self.db.q("SELECT role, COUNT(*) AS n FROM users WHERE kind='tech' GROUP BY role")}
        return {"roles": [{**r, "users": counts.get(r["id"], 0)} for r in self.all()], "no_access": {**NO_ACCESS, "users": counts.get(NONE, 0)},
                "default": self.default(), "perms": [{"id": p, "group": g, "label": l} for p, g, l in PERMS]}
