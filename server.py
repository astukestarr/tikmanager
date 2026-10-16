"""TikManager web server (standard library only). In production it listens on 127.0.0.1 behind Caddy.

    python server.py             (TM_DEV=1 for simulated routers and a local dev sign-in)
"""
import base64
import csv
import dataclasses
import html
import io
import zipfile
import ipaddress
import json
import mimetypes
import secrets
import re
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import adoption
import topology
import discovered as discovered_mod
from config import ROOT, master_key, settings
from db import DB
from entra import STATE_COOKIE, AuthError, Entra
import difflib
from backups import Backups, normalize
from poller import Poller
from routeros import RouterError
from upgrades import CHANNELS as UPGRADE_CHANNELS, Upgrades
from vpn import VpnError, Vpns
from firewall import Firewall, FirewallError
from ports import Ports, PortsError
from secevents import SecurityEvents
from observatory import Observatory
from reachability import Reachability
from offsite import OffsiteBackup, OffsiteError
from winbox import WinboxRelay
from ubnt import NetError, Ubnt
from wgport import WgPort
from mailer import Mailer, MailError
from lifecycle import Lifecycle
from rossec import RosSecurity
from autoblock import AutoBlock
from devkind import kind as device_kind, KINDS as DEVICE_KINDS
from routerlogs import RouterLogs, SEVERITIES as LOG_SEVERITIES
from webhooks import FORMATS as WEBHOOK_FORMATS, PLACEHOLDERS as WEBHOOK_PLACEHOLDERS, WebhookError, Webhooks
from alerts import Alerts
from scriptlib import LibraryError, ScriptLibrary, secrets as script_secrets
import vpninv
import healthdash
from remoteaccess import RemoteAccess, RaError
from tasks import PLACEHOLDERS, Tasks, next_run
from security import (MAX_FAILS, LOCK_SECONDS, SESSION_COOKIE, SESSION_SECONDS, RateLimiter, Sessions, check_password,
                      check_totp, cookie, derive, hash_password, new_totp_secret, password_problem, read_cookie, token,
                      token_hash, totp_uri)
from branding import Branding
from appsettings import AppSettings
from updates import Updates
MANAGED_VPN_OFF = "Site-to-site VPNs managed by TikManager are turned off for now (TM_MANAGED_VPN). VPNs already on the routers keep running."
from version import __version__
import urllib.request
from integrations import IntegrationError, Integrations, norm
from thumbs import Thumbs
from vault import Vault
from wg import WireGuard, valid_key

STATIC = ROOT / "static"
MAX_BODY = 64 * 1024
TECH_ROLES = ("admin", "tech", "readonly")
CLIENT_ROLES = ("admin", "viewer")
INVITE_TTL = 7 * 86400
# appearance each person can pick (static/theme.js has the same lists)
THEMES = ("company", "navy", "slate", "ocean", "forest", "plum", "tiki")
MODES = ("system", "light", "dark")


def user_prefs(user_id) -> dict:
    row = db.one("SELECT prefs FROM users WHERE id=?", (user_id,))
    try:
        p = json.loads((row or {}).get("prefs") or "{}")
    except ValueError:
        p = {}
    return {"theme": p.get("theme") if p.get("theme") in THEMES else "company",
            "mode": p.get("mode") if p.get("mode") in MODES else "system"}

db = DB(settings.data_dir / "tikmanager.db")
KEY = master_key()
sessions = Sessions(db)
entra = Entra(settings)
wg = WireGuard(settings)
poller = Poller(db, settings, KEY)
thumbs = Thumbs(settings.data_dir)
brand = Branding(db, settings.data_dir)
poller.thumbs = thumbs
backups = Backups(db, settings, Vault(KEY, dev=settings.dev), poller.client)
sysconf = AppSettings(db, backups.vault, settings)   # Admin > Settings values over the settings-file defaults
sysconf.apply()
updates = Updates(settings)
updates.channel_store = (lambda: db.setting("update_channel", "stable"), lambda ch: db.set_setting("update_channel", ch))
upgrades = Upgrades(db, poller.client, backups)
tasks = Tasks(db, poller.client, backups, upgrades)
integ =Integrations(db, backups.vault, settings)
vpns = Vpns(db, poller.client, backups)
remote = RemoteAccess(db, poller.client, backups)   # Router page > Remote access (WireGuard for Windows into a router)
remote.start()   # automatic revoke at each person's expiry date
vpninv.SHOW_TM_VPN = not settings.managed_vpn   # while managed VPNs are off, their tunnels show read-only under Existing VPNs
firewall = Firewall(db, poller.client, backups)
ports = Ports(db, poller.client, backups)   # port diagram, VLAN grids, VLAN changes with automatic undo
observatory = Observatory(db, settings)   # Mozilla Observatory grade of the public URL
reach = Reachability(db, settings, observatory)   # connectivity test from the internet (on request)
secev = SecurityEvents(db, settings)   # sign-in attempts: TikManager, its Ubuntu server, routers
routerlogs = RouterLogs(db)   # every router log line, for the Logs page and log alert rules
secev.logs = routerlogs
library = ScriptLibrary(db, integ)   # community RouterOS script library on GitHub
alerts = Alerts(db, settings, integ, updates, observatory, secev)   # ConnectWise tickets / Teams when something's wrong
alerts.reach = reach
alerts.logs = routerlogs
offsite = OffsiteBackup(db, settings, integ)   # backups to your own FTPS / FTP / WebDAV storage
alerts.offsite = offsite
unifi = Ubnt(db, backups.vault, settings)   # UniFi + UISP connections: sites and devices, each site assigned to a client
alerts.unifi = unifi
winbox = WinboxRelay(db, settings, secev, poller.client, backups)   # Winbox to routers through TikManager (on-demand, address-locked)
secev.winbox_who = winbox.who   # label router log lines from the relay with the session's technician
wgport = WgPort(db, settings, poller.client, sysconf)   # moving the WireGuard port without stranding routers
reach.wgport = wgport
mailer = Mailer(integ, settings)   # email: alerts, invitations, tests
alerts.mailer = mailer
alerts.webhooks = Webhooks(db, backups.vault)   # alerts to Slack, Discord, ntfy, JSON or custom endpoints
lifecycle = Lifecycle(db, settings.data_dir, thumbs)   # router age and discontinued models (from mikrotik.com)
rossec = RosSecurity(db, settings.data_dir)   # known CVEs and missed MikroTik security releases per router
autoblock = AutoBlock(db, settings, poller.client, secev)   # addresses guessing router passwords: blocked on every router
login_limit = RateLimiter(10, 300)     # per IP
topo_cache: dict = {}                  # device id -> (read at, raw tables) for the network map (60 s)
geo_lock = threading.Lock()
geo_last = [0.0]
adopt_limit = RateLimiter(30, 300)     # per IP
notes_limit = RateLimiter(60, 300)
router_act_limit = RateLimiter(20, 300)   # VPN reconnects / re-reads per person (each one works a router)     # release-note lookups per technician (each may fetch from MikroTik)
pending_logins: dict = {}              # ticket -> {user_id, created, enroll_secret}
pending_lock = threading.Lock()

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://login.microsoftonline.com",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def winbox_allows_tikmanager(addresses):
    """A router's Winbox "Available From": empty = anyone; otherwise TikManager's tunnel address must be in a listed network."""
    nets = [a.strip() for a in str(addresses or "").split(",") if a.strip()]
    for n in nets:
        try:
            if ipaddress.ip_address(settings.wg_server_ip) in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return not nets


def geocode(text):
    """Address -> up to 5 candidates via OpenStreetMap's Nominatim (their policy: identify yourself, at most one request a
    second). Only the typed text is sent, and only when someone clicks Look up."""
    with geo_lock:
        wait = 1.1 - (time.time() - geo_last[0])
        if wait > 0:
            time.sleep(wait)
        geo_last[0] = time.time()
    url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode({"q": text, "format": "jsonv2", "limit": 5})
    req = urllib.request.Request(url, headers={"User-Agent": f"TikManager/{__version__} (self-hosted MikroTik controller)",
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            rows = json.loads(r.read() or b"[]")
    except Exception as e:  # noqa: BLE001 - offline, rate-limited...
        raise HttpError(502, f"The address lookup didn't answer ({e}). Enter the coordinates or pick the spot on the map instead.") from None
    return [{"label": x.get("display_name", "")[:200], "lat": float(x["lat"]), "lon": float(x["lon"])} for x in rows if x.get("lat")]


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def now():
    return time.time()


def new_ticket(user_id, enroll=False):
    t = token()
    with pending_lock:
        cutoff = now() - 600
        for k in [k for k, v in pending_logins.items() if v["created"] < cutoff]:
            del pending_logins[k]
        pending_logins[t] = {"user_id": user_id, "created": now(), "enroll_secret": new_totp_secret() if enroll else None}
    return t


class Handler(BaseHTTPRequestHandler):
    server_version = "TikManager"
    sys_version = ""

    def log_message(self, fmt, *args):   # keep logs short; no query strings (they may hold tokens)
        print(f"{self.client_ip()} {self.command} {self.path.split('?')[0][:80]} {args[1] if len(args) > 1 else ''}")

    # --- plumbing -------------------------------------------------------------------------------------------
    def client_ip(self):
        ip = self.client_address[0]
        if ip == settings.trusted_proxy and self.headers.get("X-Forwarded-For"):
            return self.headers["X-Forwarded-For"].split(",")[-1].strip()
        return ip

    def dev_login_allowed(self):
        """Dev sign-in: dev mode, a localhost public address, and a request straight from this machine. Behind Caddy every
        request arrives from 127.0.0.1 too, so the listen address alone proves nothing - a forwarded request (it carries
        X-Forwarded-For) is never accepted, even if TM_DEV were switched on by mistake on a real server."""
        if not settings.dev or self.headers.get("X-Forwarded-For") or self.headers.get("Forwarded"):
            return False
        host = urllib.parse.urlparse(settings.public_url).hostname or ""
        try:
            local = ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            local = False
        return local and host in ("localhost", "127.0.0.1", "::1")

    def send(self, status, body: bytes, ctype="application/json", headers=()):
        self.send_response(status)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if ctype == "application/json" or ctype.startswith("text/plain"):
            self.send_header("Cache-Control", "no-store")
            if status == 200:   # open pages reload themselves after an upgrade (not shown to anyone who isn't signed in)
                self.send_header("X-TikManager-Version", __version__)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, data, status=200, headers=()):
        self.send(status, json.dumps(data, default=str).encode(), headers=headers)

    def redirect(self, location, headers=()):
        self.send_response(302)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

    def static(self, name):
        p = (STATIC / name).resolve()
        if not p.is_relative_to(STATIC.resolve()) or not p.is_file():
            raise HttpError(404, "Not found.")
        ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self.send(200, p.read_bytes(), ctype, headers=[("Cache-Control", "no-cache")])

    def body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise HttpError(413, "Request too large.")
        raw = self.rfile.read(n) if n else b""
        if (self.headers.get("Content-Type") or "").startswith("application/json"):
            try:
                return json.loads(raw or b"{}")
            except ValueError:
                raise HttpError(400, "Invalid JSON.") from None
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}

    def session(self):
        return sessions.get(read_cookie(self.headers.get("Cookie"), SESSION_COOKIE))

    def require(self, tech=False, write=False, admin=False):
        s = self.session()
        if not s:
            raise HttpError(401, "Please sign in.")
        if tech and s["kind"] != "tech":
            raise HttpError(403, "Only technicians can do that.")
        if write and s["kind"] == "tech" and s["role"] == "readonly":
            raise HttpError(403, "Your account is read-only.")
        if admin and s["role"] != "admin":
            raise HttpError(403, "Only administrators can do that.")
        return s

    def check_csrf(self, s):
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/") != settings.public_url:
            raise HttpError(403, "Cross-site request blocked.")
        if not s or not self.headers.get("X-CSRF-Token") or self.headers["X-CSRF-Token"] != s["csrf"]:
            raise HttpError(403, "Your session token is missing or out of date - reload the page.")

    def org_scope(self, s, org_id=None, column="org_id"):
        """SQL fragment + args limiting rows to what this user may see (clients: only their own organization)."""
        if s["kind"] == "client":
            return f"{column} = ?", [s["org_id"]]
        if org_id:
            return f"{column} = ?", [int(org_id)]
        return "1=1", []

    def vpn_sites(self, v):
        rows = db.q("""SELECT s.*, d.name, d.online, d.wan_ip, d.model, d.thumb_slug FROM vpn_sites s JOIN devices d ON d.id = s.device_id
                       WHERE s.vpn_id=? ORDER BY CASE WHEN s.device_id=? THEN 0 ELSE 1 END, d.name""", (v["id"], v["hub_device_id"]))
        for r in rows:
            r["subnets"] = json.loads(r["subnets"] or "[]")
            r["role"] = "hub" if r["device_id"] == v["hub_device_id"] else "spoke"
            r.pop("pubkey", None)
        return rows

    def vpn_candidates(self, org_id, vpn_id):
        rows = db.q("""SELECT d.id, d.name, d.online, d.wan_ip, d.model, d.networks, d.thumb_slug, v.name AS other_vpn FROM devices d
                       LEFT JOIN vpn_sites s ON s.device_id = d.id AND s.vpn_id IS NOT ? LEFT JOIN vpns v ON v.id = s.vpn_id
                       WHERE d.org_id=? AND d.state='adopted' ORDER BY d.name""", (vpn_id, org_id))
        for r in rows:
            r["networks"] = json.loads(r["networks"] or "[]")
        return rows

    # --- client admins: Winbox and site-to-site VPNs, only where a TikManager administrator turned them on for the client ---
    def client_access(self, s):
        """(winbox level 'off'/'read'/'full', vpn allowed) for a client admin's organization; technicians aren't limited here."""
        if s["kind"] != "client" or s["role"] != "admin" or not s["org_id"]:
            return "off", False
        o = db.one("SELECT client_winbox, client_vpn FROM orgs WHERE id=?", (s["org_id"],)) or {}
        level = o.get("client_winbox") if o.get("client_winbox") in ("read", "full") else "off"
        return level, bool(o.get("client_vpn"))

    def require_vpn(self, write=False):
        """Technicians (write needs a non-read-only account), or a client admin whose organization has VPNs turned on."""
        s = self.require()
        if s["kind"] == "tech":
            if write and s["role"] == "readonly":
                raise HttpError(403, "Your account is read-only.")
            return s
        if s["role"] != "admin":
            raise HttpError(403, "Only your organization's admins can manage site-to-site VPNs.")
        if not self.client_access(s)[1]:
            raise HttpError(403, "Site-to-site VPNs aren't turned on for your organization - ask your IT provider.")
        return s

    def require_winbox(self, d, s=None):
        """The Winbox router-login group this person gets on device d: 'read' / 'full'; refuses everyone else."""
        s = s or self.require()
        if s["kind"] == "tech":
            return s, "read" if s["role"] == "readonly" else "full"
        if s["role"] != "admin":
            raise HttpError(403, "Only your organization's admins can use Winbox.")
        level = self.client_access(s)[0]
        if level == "off" or d["org_id"] != s["org_id"]:
            raise HttpError(403, "Winbox isn't turned on for your organization - ask your IT provider.")
        return s, level

    def vpn_for(self, s, vid):
        v = db.one("SELECT v.*, o.name AS org FROM vpns v JOIN orgs o ON o.id = v.org_id WHERE v.id=?", (int(vid),))
        if not v or (s["kind"] == "client" and v["org_id"] != s["org_id"]):
            raise HttpError(404, "VPN not found.")
        return v

    def device_for(self, s, did):
        d = db.one("SELECT * FROM devices WHERE id = ?", (int(did),))
        if not d or (s["kind"] == "client" and d["org_id"] != s["org_id"]):
            raise HttpError(404, "Device not found.")
        return d

    def start_session(self, user, ret="/"):
        sid, _ = sessions.create(user["id"], self.client_ip())
        db.run("UPDATE users SET last_login=?, failed=0, locked_until=0 WHERE id=?", (now(), user["id"]))
        db.audit(user["email"], "sign-in", ip=self.client_ip(), org_id=user.get("org_id"))
        secev.record("tikmanager", "login_ok", user["email"], self.client_ip(), "microsoft" if user["kind"] == "tech" else "password + MFA")
        return cookie(SESSION_COOKIE, sid, SESSION_SECONDS, settings.secure_cookies)

    # --- routing ------------------------------------------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        url = urllib.parse.urlparse(self.path)
        path, q = url.path, {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        try:
            if method == "GET":
                self.route_get(path, q)
            else:
                self.route_post(path, q)
        except HttpError as e:
            if path.startswith("/api/") or path.startswith("/adopt/"):
                self.json({"error": str(e)}, e.status)
            elif e.status == 401:
                self.redirect("/login")
            else:
                self.send(e.status, f"<!doctype html><title>TikManager</title><p>{html.escape(str(e))}</p>".encode(), "text/html; charset=utf-8")
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            self.json({"error": "Something went wrong on the server."}, 500)

    def route_get(self, path, q):
        if path in ("/", "/index.html"):
            if not self.session():
                return self.redirect("/login")
            return self.static("index.html")
        if path == "/login":
            return self.static("login.html")
        if re.fullmatch(r"/invite/[A-Za-z0-9_-]{20,80}", path):
            return self.static("invite.html")
        if m := re.fullmatch(r"/map/(base|detail)\.json", path):   # built-in map data (public domain, tools/build_map.py)
            return self.static(f"map/{m.group(1)}.json")
        if re.fullmatch(r"/[a-z]+\.(js|css|svg)", path):
            return self.static(path[1:])
        if path == "/auth/login":
            if not settings.entra_configured:
                raise HttpError(503, "Microsoft sign-in isn't configured yet.")
            url, state = entra.begin("/")
            return self.redirect(url, [("Set-Cookie", cookie(STATE_COOKIE, state, 600, settings.secure_cookies))])
        if path == "/auth/callback":
            return self.entra_callback(q)
        if m := re.fullmatch(r"/adopt/([A-Za-z0-9_-]{20,80})", path):
            return self.adopt_script(m.group(1))
        if path == "/api/branding":   # public: the sign-in page uses it too
            return self.json(brand.public())
        if path == "/branding/logo":
            data, ctype = brand.logo()
            if not data:
                raise HttpError(404, "No logo.")
            return self.send(200, data, ctype, headers=[("Cache-Control", "public, max-age=86400")])
        if m := re.fullmatch(r"/setup/([A-Za-z0-9_-]{20,100})", path):   # one-time first-run page
            if not self.setup_open(m.group(1)):
                raise HttpError(404, "This setup link isn't valid, or setup is already done (an administrator exists) - sign in instead.")
            return self.static("setup.html")
        if path == "/api/admin/system":
            self.require(tech=True, admin=True)
            return self.json({**sysconf.public(), "wg_server_pubkey": settings.wg_server_pubkey, "data_dir": str(settings.data_dir),
                              "backup_hour": backups.hour, "backup_keep_versions": backups.keep_versions, "public_url": settings.public_url,
                              "backup_mirror": backups.mirror_on, "backup_mirror_dir": str(backups.mirror_dir()),
                              "wg_endpoint": settings.wg_endpoint, "wg_network": settings.wg_network,
                              "encryption": "AES-256-GCM" if backups.vault.available else "not available (dev)",
                              "routers": db.one("SELECT COUNT(*) AS n FROM devices WHERE state='adopted'")["n"],
                              "backups": db.one("SELECT COUNT(*) AS n FROM backups")["n"]})
        if path == "/api/admin/lifecycle":   # replacement suggestions per router model
            self.require(tech=True, admin=True)
            return self.json({"models": lifecycle.models()})
        if path == "/api/admin/webhooks":
            self.require(tech=True, admin=True)
            from alerts import KINDS as ALERT_KINDS
            return self.json({"hooks": alerts.webhooks.public(), "formats": WEBHOOK_FORMATS, "placeholders": WEBHOOK_PLACEHOLDERS,
                              "kinds": {k: v[0] for k, v in ALERT_KINDS.items()}})
        if path == "/api/version":   # current version, newest release, upgrade progress (admins)
            self.require(tech=True, admin=True)
            return self.json({**updates.info(), "observatory": observatory.info(), "reachability": reach.info()})
        if path == "/api/login/options":
            return self.json({"entra": settings.entra_configured, "dev": self.dev_login_allowed()})
        if path == "/api/me":
            s = self.require()
            org = db.one("SELECT name FROM orgs WHERE id=?", (s["org_id"],)) if s["org_id"] else None
            return self.json({"email": s["email"], "name": s["name"], "kind": s["kind"], "role": s["role"], "org_id": s["org_id"],
                              "org": org["name"] if org else None, "csrf": s["csrf"], "dev": settings.dev, "version": __version__,
                              # admins see when a newer release is out (the banner with "Upgrade now")
                              "update": updates.info() if s["kind"] == "tech" and s["role"] == "admin" else None,
                              "prefs": user_prefs(s["user_id"]),
                              "client_winbox": self.client_access(s)[0], "client_vpn": self.client_access(s)[1], "managed_vpn": settings.managed_vpn,
                              "viewing_as": {"by": s["real_email"]} if s.get("viewing_as") else None,
                              "unifi": (bool(db.one("SELECT 1 FROM net_accounts")) if s["kind"] == "tech"
                                        else bool(db.one("SELECT 1 FROM net_sites WHERE org_id=?", (s["org_id"],))))})
        if path == "/api/orgs":
            s = self.require()
            where, args = self.org_scope(s, column="o.id")
            return self.json(db.q(f"""SELECT o.id, o.name, o.client_winbox, o.client_vpn, COUNT(d.id) AS devices, SUM(d.online) AS online,
                                       SUM(CASE WHEN d.state='adopted' AND d.online=0 THEN 1 ELSE 0 END) AS offline
                                       FROM orgs o LEFT JOIN devices d ON d.org_id = o.id WHERE {where} GROUP BY o.id ORDER BY o.name""", args))
        if path == "/api/devices":
            s = self.require()
            where, args = self.org_scope(s, q.get("org_id"), "d.org_id")
            rows = db.q(f"""SELECT d.id, d.org_id, o.name AS org, d.name, d.site, d.state, d.online, d.last_seen, d.identity, d.model,
                            d.version, d.uptime, d.cpu, d.mem_used, d.mem_total, d.tunnel_ip, d.last_error, d.serial, d.public_ip, d.first_seen,
                            d.thumb_slug, d.lc_status, d.lc_made, d.lc_slug, d.lc_suggest, d.lc_suggest_name, d.lc_suggest_why, d.dm_flagged, d.dm_mode, d.sec_target, d.cve_n, d.cve_max, d.sec_checked, d.isp_state, d.last_reboot, d.last_reboot_why, d.tags, d.notes, d.board, d.kind_override
                            FROM devices d LEFT JOIN orgs o ON o.id = d.org_id WHERE {where} ORDER BY d.state DESC, o.name, d.name""", args)
            for r in rows:
                r["isp_state"] = json.loads(r.get("isp_state") or "{}")
                r["tags"] = json.loads(r.get("tags") or "[]")
                r["kind"] = device_kind(r.get("model"), r.get("board"), r.get("kind_override"))
                if s["kind"] != "tech":
                    r.pop("notes", None)   # notes are TikManager-internal
            return self.json(rows)
        if path == "/api/sites":   # site map: each adopted router with its WAN address and LAN networks
            s = self.require()
            where, args = self.org_scope(s, q.get("org_id"), "d.org_id")
            rows = db.q(f"""SELECT d.id, d.org_id, o.name AS org, d.name, d.site, d.online, d.wan_ip, d.public_ip, d.model, d.thumb_slug,
                            d.networks, d.lat, d.lon, d.location, d.loc_source, v.name AS vpn, v.id AS vpn_id, CASE WHEN v.hub_device_id = d.id THEN 1 ELSE 0 END AS vpn_hub
                            FROM devices d LEFT JOIN orgs o ON o.id = d.org_id
                            LEFT JOIN vpn_sites vs ON vs.device_id = d.id AND vs.state <> 'removing' LEFT JOIN vpns v ON v.id = vs.vpn_id
                            WHERE d.state='adopted' AND {where} ORDER BY o.name, d.name""", args)
            for r in rows:
                r["networks"] = json.loads(r["networks"] or "[]")
            return self.json(rows)
        if path == "/api/integrations":
            self.require(tech=True, admin=True)
            return self.json({"cw": integ.public("cw"), "itg": integ.public("itg"), "github": integ.public("github"), "mail": integ.public("mail"),
                              "itg_last_sync": json.loads(db.setting("itg_last_sync") or "null"), "itg_sync": integ.sync_state,
                              # set up elsewhere, shown on the Integrations page too
                              "teams": {"configured": integ.configured("teams")}, "webhooks": {"count": len(alerts.webhooks.public())},
                              "offsite": {"configured": integ.configured("offsite"), "last": offsite.last()},
                              "entra": {"configured": bool(settings.entra_configured)},
                              "ubnt": {"configured": bool(db.one("SELECT 1 FROM net_accounts")), "accounts": unifi.accounts()}})
        if path == "/api/unifi":   # UniFi sites with health (clients: their own), the clients to assign to, unplaced devices
            s = self.require()
            where, args = self.org_scope(s, column="s.org_id")
            out = {"sites": unifi.sites(where, args), "running": unifi.state["running"],
                   "configured": bool(db.one("SELECT 1 FROM net_accounts"))}
            if s["kind"] != "tech":   # the MSP's own connection names / consoles are its business
                for x in out["sites"]:
                    if not x["own_account"]:
                        x["account"] = "Managed by your IT provider"
            if s["kind"] == "tech":
                out["accounts"] = [{k: a[k] for k in ("id", "kind", "name", "org", "last", "sites")} for a in unifi.accounts()]
                out["orgs"] = db.q("SELECT id, name FROM orgs WHERE active=1 ORDER BY name")
                out["unplaced"] = unifi.unplaced()
            return self.json(out)
        if m := re.fullmatch(r"/api/unifi/sites/(.+)", path):   # one site's devices
            s = self.require()
            key = urllib.parse.unquote(m.group(1))
            site = db.one("SELECT * FROM net_sites WHERE id=?", (key,))
            if not site or (s["kind"] == "client" and site["org_id"] != s["org_id"]):
                raise HttpError(404, "Site not found.")
            return self.json({"devices": unifi.devices(key)})
        if path == "/api/integrations/cw/companies":   # PSA companies next to the TikManager clients they are linked to
            self.require(tech=True, admin=True)
            try:
                companies = integ.cw_companies(refresh=q.get("refresh") == "1")
            except IntegrationError as e:
                raise HttpError(502, str(e)) from None
            orgs = db.q("SELECT id, name, cw_id FROM orgs ORDER BY name")
            by_cw = {o["cw_id"]: o for o in orgs if o["cw_id"]}
            by_name = {norm(o["name"]): o for o in orgs if not o["cw_id"]}
            for c in companies:
                o = by_cw.get(c["id"])
                c["org"] = {"id": o["id"], "name": o["name"]} if o else None
                s_ = by_name.get(norm(c["name"])) if not o else None
                c["suggest"] = {"id": s_["id"], "name": s_["name"]} if s_ else None
            return self.json({"companies": companies, "orgs": orgs})
        if path == "/api/integrations/cw/find":   # why isn't a company in the list? (deleted / not visible to the API member)
            self.require(tech=True, admin=True)
            try:
                return self.json({"results": integ.cw_find(str(q.get("q") or ""))})
            except IntegrationError as e:
                raise HttpError(502, str(e)) from None
        if path == "/api/integrations/itg/orgs":   # TikManager clients with their IT Glue organization (or a name-match suggestion)
            self.require(tech=True, admin=True)
            try:
                lk = integ.itg_lookups(refresh=q.get("refresh") == "1")
            except IntegrationError as e:
                raise HttpError(502, str(e)) from None
            by_name = {norm(o["name"]): o for o in lk["orgs"]}
            orgs = db.q("""SELECT o.id, o.name, o.itg_id, COUNT(d.id) AS routers, SUM(CASE WHEN d.itg_config_id IS NOT NULL THEN 1 ELSE 0 END) AS synced,
                           SUM(CASE WHEN d.itg_error IS NOT NULL THEN 1 ELSE 0 END) AS errors
                           FROM orgs o LEFT JOIN devices d ON d.org_id = o.id AND d.state='adopted' GROUP BY o.id ORDER BY o.name""")
            for o in orgs:
                m = by_name.get(norm(o["name"])) if not o["itg_id"] else None
                o["suggest"] = m["id"] if m else None
            errors = db.q("SELECT d.name, d.itg_error FROM devices d WHERE d.itg_error IS NOT NULL LIMIT 20")
            return self.json({**lk, "clients": orgs, "errors": errors})
        if m := re.fullmatch(r"/api/devices/(\d+)/ra", path):   # remote access: settings, people, live handshakes
            s = self.require(tech=True)
            d = self.device_for(s, m.group(1))
            remote.prune()
            return self.json(remote.info(d["id"], live=q.get("live") == "1"))
        if m := re.fullmatch(r"/api/devices/(\d+)/ra/users/(\d+)/config", path):   # one person's WireGuard config - once
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            try:
                name, conf = remote.download(d["id"], int(m.group(2)), q.get("t") or "", s["email"])
            except RaError as e:
                return self.send(410, str(e).encode(), "text/plain; charset=utf-8")
            fname = re.sub(r"-{2,}", "-", re.sub(r"[^A-Za-z0-9._-]+", "-", f"{d['name']}-{name}")).strip("-")[:60] or "remote-access"
            return self.send(200, conf.encode(), "text/plain; charset=utf-8",
                             headers=[("Content-Disposition", f'attachment; filename="{fname}.conf"'), ("Cache-Control", "no-store")])
        if path == "/api/health-dash":   # Performance & Security dashboard: every router's findings (healthdash.py)
            s = self.require(tech=True)
            where, args = self.org_scope(s, column="d.org_id")
            rows = db.q(f"""SELECT d.*, o.name AS org FROM devices d LEFT JOIN orgs o ON o.id = d.org_id
                            WHERE d.state='adopted' AND {where} ORDER BY o.name, d.name""", args)
            t_now = time.time()
            metrics = {r["device_id"]: {"lat": r["lat"], "loss": r["loss"], "cpu": r["cpu"], "mem": r["mem"]} for r in db.q(
                """SELECT device_id, AVG(latency) AS lat, AVG(loss) AS loss, AVG(cpu) AS cpu, AVG(mem_pct) AS mem FROM metrics
                   WHERE ts > ? GROUP BY device_id""", (t_now - 3600,))}
            flaps = {r["device_id"]: r["n"] for r in db.q("SELECT device_id, COUNT(*) AS n FROM events WHERE kind='link down' AND ts > ? GROUP BY device_id",
                                                          (t_now - 86400,))}
            found = healthdash.build(rows, metrics, flaps, t_now)
            ids = {r["id"]: r for r in rows}   # remote-access people: ending soon, or past their expiry (router offline)
            for u in db.q("SELECT name, device_id, expires_at FROM ra_users WHERE expires_at IS NOT NULL AND expires_at < ?", (t_now + 3 * 86400,)):
                r = ids.get(u["device_id"])
                if not r:
                    continue
                past = u["expires_at"] < t_now
                found.append({"device_id": r["id"], "router": r["name"], "org": r.get("org") or "", "severity": "high" if past else "low",
                              "category": "Hygiene", "title": "Remote access past its expiry" if past else "Remote access ending soon",
                              "detail": f"{u['name']}: " + ("still on the router (it was offline) - revoked as soon as it's back" if past
                                                            else f"access ends {time.strftime('%Y-%m-%d', time.localtime(u['expires_at']))}"),
                              "fix": "Router page > Remote access: extend the date if they still need it." if not past else "Bring the router online, or revoke by hand."})
            found.sort(key=lambda f: (healthdash.SEV_ORDER[f["severity"]], healthdash.CATEGORIES.index(f["category"]), f["org"], f["router"]))
            unread = sum(1 for r in rows if r["online"] and not r.get("vpn_inv"))
            return self.json({"findings": found, "routers": len(rows), "online": sum(1 for r in rows if r["online"]),
                              "clean": len({r["id"] for r in rows} - {f["device_id"] for f in found}), "unread": unread,
                              "categories": healthdash.CATEGORIES, "checked_at": t_now})
        if path == "/api/vpn-inventory":   # VPNs found on the routers (configured outside TikManager); a client admin: their own
            s = self.require_vpn()
            where, args = self.org_scope(s, column="d.org_id")
            # remote ends are matched only against routers this person may see, so a client never learns other clients' routers
            routers = db.q(f"""SELECT d.id, d.org_id, o.name AS org, d.name, d.online, d.wan_ip, d.public_ip, d.vpn_inv, d.vpn_inv_at
                              FROM devices d LEFT JOIN orgs o ON o.id = d.org_id WHERE d.state='adopted' AND {where} ORDER BY o.name, d.name""", args)
            out = []
            for r in routers:
                t = vpninv.for_device(r, routers)
                out.append({"id": r["id"], "org_id": r["org_id"], "org": r["org"], "name": r["name"], "online": r["online"],
                            "collected_at": r["vpn_inv_at"], "tunnels": t})
            return self.json(out)
        if (path in ("/api/vpns", "/api/vpn-candidates") or re.fullmatch(r"/api/vpns/\d+", path)) and not settings.managed_vpn:
            raise HttpError(404, MANAGED_VPN_OFF)
        if path == "/api/vpns":   # every site-to-site VPN with its sites' live state (a client admin: their own)
            s = self.require_vpn()
            where, args = self.org_scope(s, column="v.org_id")
            out = db.q(f"""SELECT v.*, o.name AS org, d.name AS hub FROM vpns v JOIN orgs o ON o.id = v.org_id
                          LEFT JOIN devices d ON d.id = v.hub_device_id WHERE {where} ORDER BY o.name, v.name""", args)
            for v in out:
                v["sites"] = self.vpn_sites(v)
            return self.json(out)
        if m := re.fullmatch(r"/api/vpns/(\d+)", path):
            s = self.require_vpn()
            v = self.vpn_for(s, m.group(1))
            v["sites"] = self.vpn_sites(v)
            v["busy"] = v["id"] in vpns.busy
            return self.json({"vpn": v, "candidates": self.vpn_candidates(v["org_id"], v["id"])})
        if path == "/api/vpn-candidates":   # a client's routers with their subnets, for a new VPN
            s = self.require_vpn()
            org_id = s["org_id"] if s["kind"] == "client" else int(q.get("org_id") or 0)
            return self.json({"candidates": self.vpn_candidates(org_id, None)})
        # --- scripts, groups, tasks (technicians) ---
        if path == "/api/scripts":
            self.require(tech=True)
            rows = db.q("""SELECT s.*, (SELECT COUNT(*) FROM tasks t WHERE t.script_id = s.id) AS tasks FROM scripts s ORDER BY s.name COLLATE NOCASE""")
            return self.json({"scripts": rows, "placeholders": list(PLACEHOLDERS)})
        if path == "/api/groups":
            self.require(tech=True)
            groups = db.q("SELECT * FROM router_groups ORDER BY name COLLATE NOCASE")
            for g in groups:
                g["device_ids"] = [r["device_id"] for r in db.q("SELECT device_id FROM group_members WHERE group_id=?", (g["id"],))]
            routers = db.q("""SELECT d.id, d.name, d.org_id, o.name AS org, d.online, d.model, d.tags FROM devices d LEFT JOIN orgs o ON o.id = d.org_id
                              WHERE d.state='adopted' ORDER BY o.name, d.name""")
            for r in routers:
                r["tags"] = json.loads(r["tags"] or "[]")
            tags = sorted({t for r in routers for t in r["tags"]}, key=str.lower)
            return self.json({"groups": groups, "routers": routers, "tags": tags, "orgs": db.q("SELECT id, name FROM orgs ORDER BY name")})
        if path == "/api/tasks":
            self.require(tech=True)
            rows = db.q("SELECT t.*, s.name AS script_name FROM tasks t LEFT JOIN scripts s ON s.id = t.script_id ORDER BY t.enabled DESC, t.next_run IS NULL, t.next_run, t.name")
            for t in rows:
                t["count"] = len(tasks.resolve(json.loads(t["targets"] or "{}")))
            return self.json(rows)
        if path == "/api/runs":
            self.require(tech=True)
            runs = db.q("""SELECT u.id, u.task_id, u.task_name, u.action, u.script_name, u.started_at, u.finished_at, u.status, u.by_user, u.trigger,
                           SUM(r.status='ok') AS ok, SUM(r.status='failed') AS failed, SUM(r.status='skipped') AS skipped,
                           SUM(r.status IN ('pending','running','waiting')) AS open, COUNT(r.id) AS total
                           FROM task_runs u LEFT JOIN task_results r ON r.run_id = u.id
                           WHERE (? = '' OR u.task_id = ?) GROUP BY u.id ORDER BY u.id DESC LIMIT 200""", (q.get("task_id", ""), q.get("task_id", "")))
            return self.json(runs)
        if m := re.fullmatch(r"/api/runs/(\d+)", path):
            self.require(tech=True)
            run = db.one("SELECT * FROM task_runs WHERE id=?", (int(m.group(1)),))
            if not run:
                raise HttpError(404, "Run not found.")
            run["results"] = db.q("SELECT * FROM task_results WHERE run_id=? ORDER BY device_name COLLATE NOCASE", (run["id"],))
            return self.json(run)
        if path == "/api/upgrades":   # routers with their versions, plus scheduled / recent upgrade jobs
            s = self.require(tech=True)
            routers = db.q("""SELECT d.id, d.org_id, o.name AS org, d.name, d.model, d.online, d.version, d.ros_channel, d.ros_latest, d.ros_checked,
                              d.fw_current, d.fw_upgrade, d.thumb_slug, d.sec_target, d.cve_n, d.cve_max, d.tags FROM devices d LEFT JOIN orgs o ON o.id = d.org_id
                              WHERE d.state='adopted' ORDER BY o.name, d.name""")
            jobs = db.q("""SELECT u.*, d.name AS device, o.name AS org FROM upgrades u JOIN devices d ON d.id = u.device_id
                           LEFT JOIN orgs o ON o.id = u.org_id
                           WHERE u.status IN ('scheduled','running','held') OR u.created_at > ? ORDER BY
                           CASE u.status WHEN 'running' THEN 0 WHEN 'held' THEN 1 WHEN 'scheduled' THEN 2 ELSE 3 END, COALESCE(u.finished_at, u.scheduled_at) DESC
                           LIMIT 300""", (now() - 30 * 86400,))
            return self.json({"routers": routers, "jobs": jobs, "channels": list(UPGRADE_CHANNELS)})
        if path == "/api/library":   # the community script library (cached for an hour; ?refresh=1)
            self.require(tech=True)
            try:
                lst = library.listing(refresh=q.get("refresh") == "1")
            except LibraryError as e:
                raise HttpError(502, str(e)) from None
            return self.json({**lst, "can_share": integ.configured("github")})
        if path == "/api/library/script":
            self.require(tech=True)
            try:
                return self.json(library.get(q.get("path", "")[:300]))
            except LibraryError as e:
                raise HttpError(400, str(e)) from None
        if path == "/api/alerts":   # open and recent alerts; the settings (admins change them)
            s = self.require(tech=True)
            return self.json({**alerts.view(), "settings": alerts.settings(), "can_edit": s["role"] == "admin",
                              "cw_ready": integ.configured("cw"), "teams_ready": integ.configured("teams"), "mail_ready": mailer.configured()})
        if path == "/api/admin/alerts/cw-options":   # boards / statuses / priorities / companies for ticket settings
            self.require(tech=True, admin=True)
            try:
                board = q.get("board", "")
                return self.json({"boards": integ.cw_boards(), "statuses": integ.cw_statuses(int(board)) if board.isdigit() else [],
                                  "priorities": integ.cw_priorities(), "companies": [{"id": c["id"], "name": c["name"]} for c in integ.cw_companies()]})
            except IntegrationError as e:
                raise HttpError(502, str(e)) from None
        if path == "/api/admin/wgport":   # the WireGuard port, and how far a move to a new one has got
            self.require(tech=True, admin=True)
            return self.json(wgport.info())
        if path == "/api/admin/offsite":   # off-site backup settings + last result
            self.require(tech=True, admin=True)
            return self.json(offsite.public())
        if m := re.fullmatch(r"/api/devices/(\d+)/winbox", path):   # the router's Winbox service + open sessions to it
            s = self.require()
            d = self.device_for(s, m.group(1))
            s, group = self.require_winbox(d, s)
            svc, err = None, None
            if d["state"] == "adopted" and d["online"]:
                try:
                    svc = poller.client(d).winbox_service()
                except RouterError as e:
                    err = str(e)
            tip = settings.wg_server_ip
            ok = bool(svc) and not svc["disabled"] and winbox_allows_tikmanager(svc["address"])
            return self.json({"service": svc, "error": err, "reachable": ok, "tunnel_ip": tip, "host": urllib.parse.urlparse(settings.public_url).hostname,
                              "your_ip": self.client_ip(), "sessions": [x for x in winbox.view(s) if x["device_id"] == d["id"]],
                              "ports": f"{winbox.ports.start}-{winbox.ports.stop - 1}",
                              "can_fix": s["kind"] == "tech" and s["role"] != "readonly", "group": group})
        if path == "/api/winbox":   # all open Winbox sessions (Security page)
            s = self.require(tech=True)
            return self.json({"sessions": winbox.view(s)})
        if path == "/api/routeros/notes":   # MikroTik's release notes for one RouterOS version (the "What's new" dialog)
            s = self.require(tech=True)
            if not notes_limit.allow(s["email"]):
                raise HttpError(429, "Too many release-note lookups - try again in a few minutes.")
            try:
                return self.json(rossec.notes(str(q.get("v") or "")[:20]))
            except ValueError as e:
                raise HttpError(400, str(e)) from None
        if path in ("/api/logs", "/api/logs/export"):   # router log lines (technicians), newest first
            s = self.require(tech=True)
            f = {k: str(q.get(k) or "")[:120] for k in ("device_id", "org_id", "tag", "sev", "topic", "q", "hours", "before_id", "after_id")}
            for k in ("device_id", "org_id", "before_id", "after_id"):
                if f[k] and not f[k].isdigit():
                    raise HttpError(400, "Bad filter.")
            try:
                f["hours"] = str(float(f["hours"])) if f["hours"] else ""
            except ValueError:
                f["hours"] = ""
            if path.endswith("/export"):
                rows = routerlogs.query("1=1", [], f, limit=100000)
                out = io.StringIO()
                w = csv.writer(out)
                w.writerow(["time", "router", "client", "severity", "topics", "message"])
                cell = lambda v: ("'" + v) if str(v or "")[:1] in ("=", "+", "-", "@", "\t", "\r") else str(v or "")   # no spreadsheet formulas
                for r in rows:
                    w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), cell(r["device"]), cell(r["org"]), cell(r["severity"]),
                                cell(r["topics"]), cell(r["message"])])
                db.audit(s["email"], "router logs exported", f"{len(rows)} lines", self.client_ip())
                return self.send(200, out.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                                 headers=[("Content-Disposition", f'attachment; filename="router-logs-{time.strftime("%Y%m%d-%H%M")}.csv"')])
            limit = 500 if f["after_id"] else 200
            return self.json({"lines": routerlogs.query("1=1", [], f, limit=limit), "severities": LOG_SEVERITIES})
        if path == "/api/logs/rules":
            self.require(tech=True)
            return self.json({"rules": routerlogs.rules(), "severities": LOG_SEVERITIES})
        if path == "/api/security/autoblock":   # auto-block settings, candidates, blocked addresses, routers without the drop rule
            self.require(tech=True)
            return self.json(autoblock.info())
        if path == "/api/security/routeros":   # routers with missed security releases / known CVEs
            s = self.require()
            where, args = self.org_scope(s, None, "d.org_id")
            rows = db.q(f"""SELECT d.id, d.name, d.version, d.ros_latest, d.sec_target, d.cve_n, d.cve_max, d.sec_info, o.name AS org
                            FROM devices d LEFT JOIN orgs o ON o.id = d.org_id WHERE d.state='adopted' AND {where}""", args)
            return self.json(rossec.summary(rows))
        if path == "/api/security":   # sign-in attempts and other security events (TikManager, Ubuntu server, routers)
            self.require(tech=True)
            try:
                hours = max(1, min(24 * 90, int(q.get("hours") or 24)))
            except ValueError:
                hours = 24
            return self.json(secev.summary(hours, q.get("source", "")[:20], q.get("kind", "")[:20], q.get("q", "")[:100]))
        if path == "/api/discovered":   # MikroTik neighbours of your routers that aren't in TikManager yet
            self.require(tech=True)
            devs = db.q("""SELECT id, name, identity, org_id, state, interfaces, networks, wan_ip, tunnel_ip, public_ip, neighbors, neighbors_at
                           FROM devices WHERE state IN ('adopted', 'pending')""")
            orgs = {o["id"]: o["name"] for o in db.q("SELECT id, name FROM orgs")}
            polled = [d for d in devs if d["state"] == "adopted"]
            return self.json({"devices": discovered_mod.discovered(devs, orgs), "routers": len(polled),
                              "read": sum(1 for d in polled if d["neighbors_at"]), "oldest": min((d["neighbors_at"] for d in polled if d["neighbors_at"]), default=None)})
        if path == "/api/adoption":
            s = self.require(tech=True)
            return self.json({"command": adoption.command(settings, self.enroll_token()), "pending": db.one(
                "SELECT COUNT(*) AS n FROM devices WHERE state='pending'")["n"], "rotated_at": db.setting("enroll_rotated_at")})
        if m := re.fullmatch(r"/api/devices/(\d+)/topology", path):   # network map behind one router, read live
            s = self.require()
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            key = d["id"]
            hit = topo_cache.get(key)
            if not hit or time.time() - hit[0] > 60 or q.get("refresh") == "1":
                try:
                    hit = (time.time(), poller.client(d).topology())
                except RouterError as e:
                    raise HttpError(502, f"Couldn't read the router's tables: {e}") from None
                topo_cache[key] = hit
            # client users see their network, but not the full routing table (other networks an MSP connected)
            return self.json({**topology.build(hit[1], d, full=s["kind"] == "tech", known=unifi.known_for_org(d["org_id"])), "read_at": hit[0]})
        if m := re.fullmatch(r"/api/devices/(\d+)/firewall/address-list", path):   # one address list's entries, read live
            s = self.require(tech=True)
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            try:
                return self.json({"entries": firewall.entries(d, q.get("list", ""))})
            except FirewallError as e:
                raise HttpError(400, str(e)) from None
        if m := re.fullmatch(r"/api/devices/(\d+)/firewall", path):   # filter + NAT rules, read live
            s = self.require(tech=True)
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            try:
                return self.json({**firewall.view(d), "can_edit": s["role"] != "readonly"})
            except FirewallError as e:
                raise HttpError(502, str(e)) from None
        if m := re.fullmatch(r"/api/devices/(\d+)/ports", path):   # ports, PoE, bridge VLANs, connected devices - read live
            s = self.require(tech=True)
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            try:
                return self.json(ports.view(d))
            except PortsError as e:
                raise HttpError(502, str(e)) from None
        if m := re.fullmatch(r"/api/devices/(\d+)/wireless", path):   # radios, links and connected clients, read live
            s = self.require()
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            try:
                w = poller.client(d).wireless()
            except RouterError as e:
                raise HttpError(502, str(e)) from None
            # the other end of a link / a client that is itself one of our routers (matched by its interface MACs -
            # a bridged radio link has no DHCP lease or ARP entry, and 60 GHz radios report only the MAC)
            where, args = self.org_scope(s, None, "org_id")
            known = {}
            for r in db.q(f"SELECT id, name, interfaces FROM devices WHERE state='adopted' AND id<>? AND {where}", [d["id"], *args]):
                for i in json.loads(r["interfaces"] or "[]"):
                    m = str(i.get("mac") or "").upper()
                    if m and m != "00:00:00:00:00:00":
                        known.setdefault(m, r)
            for p in w["peers"]:
                r = known.get(str(p.get("mac") or "").upper())
                if r:
                    p["device_id"], p["device_name"] = r["id"], r["name"]
                    p["name"] = p["name"] or r["name"]
            return self.json({**w, "read_at": now()})
        if m := re.fullmatch(r"/api/devices/(\d+)/dhcp", path):   # DHCP leases, read live from the router
            s = self.require()
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            try:
                return self.json({"leases": poller.client(d).dhcp_leases(), "read_at": now()})
            except RouterError as e:
                raise HttpError(502, f"Couldn't read the DHCP leases: {e}") from None
        if m := re.fullmatch(r"/api/devices/(\d+)", path):
            s = self.require()
            d = self.device_for(s, m.group(1))
            d.pop("token_hash", None)
            d["interfaces"] = json.loads(d["interfaces"] or "[]")
            d["dm_info"] = json.loads(d.get("dm_info") or "null")
            d["sec_info"] = json.loads(d.get("sec_info") or "null")
            d["health"] = json.loads(d.get("health") or "{}")
            d["isp_state"] = json.loads(d.get("isp_state") or "{}")
            d["isp_ifaces"] = json.loads(d.get("isp_ifaces") or "null")
            d["tags"] = json.loads(d.get("tags") or "[]")
            d["kind"] = device_kind(d.get("model"), d.get("board"), d.get("kind_override"))
            org = db.one("SELECT name FROM orgs WHERE id=?", (d["org_id"],)) if d["org_id"] else None
            d["org"] = org["name"] if org else ""
            d["upgrade"] = db.one("""SELECT id, status, step, scheduled_at, channel, firmware, created_by FROM upgrades
                                     WHERE device_id=? AND status IN ('scheduled','running') ORDER BY scheduled_at LIMIT 1""", (d["id"],))
            d["vpn"] = db.one("""SELECT v.id, v.name, v.status, s.state, s.tunnel_ip, s.handshake_age, s.ping_ms,
                                 CASE WHEN v.hub_device_id = s.device_id THEN 'hub' ELSE 'spoke' END AS role
                                 FROM vpn_sites s JOIN vpns v ON v.id = s.vpn_id WHERE s.device_id=?""", (d["id"],)) if s["kind"] == "tech" else None
            if s["kind"] == "tech" or self.client_access(s)[1]:   # remote ends are matched only against routers this person may see
                where, args = self.org_scope(s, column="d.org_id")
                d["vpn_found"] = vpninv.for_device(d, db.q(f"""SELECT d.id, d.name, d.wan_ip, d.public_ip, o.name AS org FROM devices d
                                                              LEFT JOIN orgs o ON o.id = d.org_id WHERE d.state='adopted' AND {where}""", args))
            d.pop("vpn_inv", None)
            d["last_upgrade"] = db.one("""SELECT status, detail, finished_at FROM upgrades WHERE device_id=? AND status IN ('done','failed')
                                          ORDER BY finished_at DESC LIMIT 1""", (d["id"],))
            d["events"] = db.q("SELECT ts, kind, detail FROM events WHERE device_id=? ORDER BY ts DESC LIMIT 50", (d["id"],))
            if s["kind"] != "tech":   # clients see their router, not TikManager's internal bookkeeping about it
                for k in ("wg_pubkey", "token_expires", "notes", "api_port", "created_by", "thumb_tried", "itg_config_id",
                          "itg_synced_at", "itg_error", "vpn_inv_at", "ros_checked", "name_custom", "lc_checked"):
                    d.pop(k, None)
            return self.json(d)
        if m := re.fullmatch(r"/api/devices/(\d+)/series", path):   # chart data: traffic for one interface + WAN health
            s = self.require()
            d = self.device_for(s, m.group(1))
            span = {"1h": 3600, "1d": 86400, "1w": 7 * 86400, "1m": 30 * 86400}.get(q.get("range", "1d"), 86400)
            iface = str(q.get("iface") or "")[:40]
            since, bucket = now() - span, max(60, span // 360)
            b = f"CAST(ts / {bucket} AS INTEGER) * {bucket}"
            if span > 7 * 86400:   # the month view comes from hourly averages
                traffic = db.q(f"SELECT {b} AS t, AVG(rx_bps) AS rx, AVG(tx_bps) AS tx FROM metrics_hourly WHERE device_id=? AND iface=? AND ts>? GROUP BY t ORDER BY t",
                               (d["id"], iface, since))
                health = db.q(f"SELECT {b} AS t, AVG(latency) AS latency, MAX(loss) AS loss, AVG(cpu) AS cpu FROM metrics_hourly WHERE device_id=? AND iface='' AND ts>? GROUP BY t ORDER BY t",
                              (d["id"], since))
            else:
                table, extra = ("iface_metrics", "AND name=?") if iface else ("metrics", "")
                traffic = db.q(f"SELECT {b} AS t, AVG(rx_bps) AS rx, AVG(tx_bps) AS tx FROM {table} WHERE device_id=? AND ts>? {extra} GROUP BY t ORDER BY t",
                               (d["id"], since, *([iface] if iface else [])))
                health = db.q(f"SELECT {b} AS t, AVG(latency) AS latency, MAX(loss) AS loss, AVG(cpu) AS cpu FROM metrics WHERE device_id=? AND ts>? GROUP BY t ORDER BY t",
                              (d["id"], since))
            names = [r["name"] for r in db.q("SELECT DISTINCT name FROM iface_metrics WHERE device_id=? AND ts>? ORDER BY name", (d["id"], now() - 86400))]
            return self.json({"traffic": traffic, "health": health, "interfaces": names, "range": span, "bucket": bucket})
        if m := re.fullmatch(r"/api/devices/(\d+)/health", path):   # sensor / fibre history for the Hardware health card
            s = self.require()
            d = self.device_for(s, m.group(1))
            span = {"1h": 3600, "1d": 86400, "1w": 7 * 86400, "1m": 30 * 86400}.get(q.get("range", "1d"), 86400)
            bucket = max(300, span // 200)
            rows = db.q(f"""SELECT name, CAST(ts / {bucket} AS INTEGER) * {bucket} AS t, AVG(value) AS v FROM health_metrics
                            WHERE device_id=? AND ts>? GROUP BY name, t ORDER BY name, t""", (d["id"], now() - span))
            latest = json.loads(d.get("health") or "{}")
            series = {}
            for r in rows:
                series.setdefault(r["name"], []).append([r["t"], r["v"]])
            return self.json({"sensors": [{"name": n, "unit": (latest.get(n) or {}).get("unit", ""), "value": (latest.get(n) or {}).get("value"),
                                           "points": series.get(n, [])} for n in sorted(set(latest) | set(series), key=lambda n: (n.startswith("sfp:"), n))],
                              "at": d.get("health_at"), "range": span})
        if m := re.fullmatch(r"/thumb/([A-Za-z0-9_+.-]{1,80})", path):   # cached MikroTik product picture
            self.require()
            p = thumbs.path_for(m.group(1)) if db.one("SELECT 1 FROM devices WHERE thumb_slug=?", (m.group(1),)) else None
            if not p:
                raise HttpError(404, "No picture.")
            ctype = {"webp": "image/webp", "png": "image/png", "jpg": "image/jpeg"}[p.suffix[1:]]
            return self.send(200, p.read_bytes(), ctype, headers=[("Cache-Control", "private, max-age=604800")])
        if m := re.fullmatch(r"/api/devices/(\d+)/backups", path):
            s = self.require()
            d = self.device_for(s, m.group(1))
            rows = db.q("SELECT id, ts, checked_at, size, lines, added, removed, trigger, by_user FROM backups WHERE device_id=? ORDER BY ts DESC LIMIT 200", (d["id"],))
            return self.json({"versions": rows, "last_backup_at": d["last_backup_at"], "last_backup_error": d["last_backup_error"],
                              "can_view": s["kind"] == "tech"})
        if m := re.fullmatch(r"/api/backups/(\d+)(/download|/diff)?", path):
            s = self.require(tech=True)   # configurations (with secrets) are for technicians only
            b = db.one("SELECT b.*, d.name AS device, d.identity FROM backups b JOIN devices d ON d.id = b.device_id WHERE b.id=?", (int(m.group(1)),))
            if not b:
                raise HttpError(404, "Backup not found.")
            text = backups.text_of(b["id"])
            if m.group(2) == "/download":
                db.audit(s["email"], "backup downloaded", f"{b['device']} {time.strftime('%Y-%m-%d %H:%M', time.localtime(b['ts']))}", self.client_ip(), org_id=b["org_id"])
                fname = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{b['identity'] or b['device']}-{time.strftime('%Y%m%d-%H%M', time.localtime(b['ts']))}") + ".rsc"
                return self.send(200, text.encode(), "text/plain; charset=utf-8", headers=[("Content-Disposition", f'attachment; filename="{fname}"')])
            if m.group(2) == "/diff":
                prev = db.one("SELECT id, ts FROM backups WHERE device_id=? AND ts<? ORDER BY ts DESC LIMIT 1", (b["device_id"], b["ts"]))
                old = normalize(backups.text_of(prev["id"])).splitlines() if prev else []
                diff = list(difflib.unified_diff(old, normalize(text).splitlines(), "previous", "this version", lineterm="", n=2))
                return self.json({"diff": diff[2:] if len(diff) > 2 else [], "previous_ts": prev["ts"] if prev else None})
            db.audit(s["email"], "backup viewed", b["device"], self.client_ip(), org_id=b["org_id"])
            return self.json({"text": text, "ts": b["ts"], "device": b["device"]})
        if path == "/api/backups":
            s = self.require()
            where, args = self.org_scope(s, q.get("org_id"), "d.org_id")
            return self.json(db.q(f"""SELECT d.id, d.name, o.name AS org, d.org_id, d.online, d.last_backup_at, d.last_backup_try, d.last_backup_error,
                                       (SELECT COUNT(*) FROM backups b WHERE b.device_id=d.id) AS versions,
                                       (SELECT MAX(ts) FROM backups b WHERE b.device_id=d.id) AS last_change
                                       FROM devices d LEFT JOIN orgs o ON o.id = d.org_id WHERE d.state='adopted' AND {where} ORDER BY o.name, d.name""", args))
        if path == "/api/backups/zip":   # every router's newest configuration in one zip: <client>/<router>_<date>.rsc
            s = self.require(tech=True)
            org = q.get("org_id")
            rows = backups.latest_all({int(org)} if org and str(org).isdigit() else None)
            if not rows:
                raise HttpError(404, "No backups yet.")
            buf = io.BytesIO()
            safe = lambda v: re.sub(r"[^A-Za-z0-9._ -]+", "_", str(v or "")).strip(" .") or "unnamed"
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for r in rows:
                    z.writestr(f"{safe(r['org'] or 'Unassigned')}/{safe(r['name'])}_{time.strftime('%Y-%m-%d', time.localtime(r['ts']))}.rsc", backups.text_of(r["id"]))
            db.audit(s["email"], "backups downloaded (zip)", f"{len(rows)} routers", self.client_ip())
            return self.send(200, buf.getvalue(), "application/zip",
                             headers=[("Content-Disposition", f'attachment; filename="tikmanager-backups-{time.strftime("%Y%m%d")}.zip"')])
        if path == "/api/events":
            s = self.require()
            where, args = self.org_scope(s, q.get("org_id"), "d.org_id")
            return self.json(db.q(f"""SELECT e.ts, e.kind, e.detail, e.device_id, d.name AS device, o.name AS org FROM events e
                                      JOIN devices d ON d.id = e.device_id LEFT JOIN orgs o ON o.id = d.org_id
                                      WHERE {where} ORDER BY e.ts DESC LIMIT 100""", args))
        if path == "/api/users":
            s = self.require()
            if s["kind"] == "client":
                if s["role"] != "admin":
                    raise HttpError(403, "Only your organization's admins can see its users.")
                rows = db.q("SELECT id, email, name, kind, role, org_id, totp_enabled, disabled, last_login, invite_expires FROM users WHERE org_id=? ORDER BY email", (s["org_id"],))
            else:
                rows = db.q("""SELECT u.id, u.email, u.name, u.kind, u.role, u.org_id, o.name AS org, u.totp_enabled, u.disabled, u.last_login, u.invite_expires
                               FROM users u LEFT JOIN orgs o ON o.id = u.org_id ORDER BY u.kind DESC, o.name, u.email""")
            for r in rows:
                r["invited"] = bool(r.pop("invite_expires"))
            return self.json(rows)
        if path == "/api/audit":
            s = self.require(tech=True, admin=True)
            return self.json(db.q("SELECT ts, user, action, target, ip, detail FROM audit ORDER BY id DESC LIMIT 500"))
        if path == "/api/invite":
            u = self.invite_user(q.get("token", ""))
            return self.json({"email": u["email"], "name": u["name"]})
        raise HttpError(404, "Not found.")

    def route_post(self, path, q):
        # unauthenticated endpoints (each has its own protection)
        if path == "/api/login":
            return self.login_password()
        if path == "/api/login/mfa":
            return self.login_mfa()
        if path == "/api/login/dev":
            return self.login_dev()
        if path == "/api/invite":
            return self.accept_invite()
        if path == "/api/setup":
            return self.first_run()
        if m := re.fullmatch(r"/adopt/([A-Za-z0-9_-]{20,80})/register", path):
            return self.adopt_register(m.group(1))
        # everything else: signed in + CSRF token
        s = self.session()
        self.check_csrf(s)
        if path == "/api/view-as/stop":
            if s.get("viewing_as"):
                db.run("UPDATE sessions SET as_user_id = NULL WHERE id_hash = ?", (token_hash(read_cookie(self.headers.get("Cookie"), SESSION_COOKIE)),))
                db.audit(s["real_email"], "stopped viewing as", s["email"], self.client_ip(), org_id=s["org_id"])
            return self.json({"ok": True})
        if s.get("viewing_as") and path != "/api/logout":   # "View as" is look-only: nothing can be changed in the user's name
            raise HttpError(403, f"You're viewing as {s['email']} - read-only. Stop viewing to make changes.")
        if m := re.fullmatch(r"/api/users/(\d+)/view-as", path):   # administrators: see TikManager exactly as this client user does
            s = self.require(tech=True, admin=True)
            u = db.one("SELECT * FROM users WHERE id=?", (int(m.group(1)),))
            if not u or u["kind"] != "client":
                raise HttpError(400, "You can only view as a client user.")
            if u["disabled"]:
                raise HttpError(400, "That user is disabled.")
            db.run("UPDATE sessions SET as_user_id = ? WHERE id_hash = ?", (u["id"], token_hash(read_cookie(self.headers.get("Cookie"), SESSION_COOKIE))))
            db.audit(s["email"], "viewing as", u["email"], self.client_ip(), org_id=u["org_id"], detail="read-only")
            return self.json({"ok": True})
        if path == "/api/me/prefs":   # the signed-in person's own appearance (theme + light/dark mode)
            b = self.body()
            prefs = user_prefs(s["user_id"])
            if b.get("theme") in THEMES:
                prefs["theme"] = b["theme"]
            if b.get("mode") in MODES:
                prefs["mode"] = b["mode"]
            db.run("UPDATE users SET prefs=? WHERE id=?", (json.dumps(prefs), s["user_id"]))
            return self.json({"ok": True, "prefs": prefs})
        if path == "/api/logout":
            sessions.end(read_cookie(self.headers.get("Cookie"), SESSION_COOKIE))
            db.audit(s["email"], "sign-out", ip=self.client_ip())
            return self.json({"ok": True, "entra_logout": entra.logout_url() if s["kind"] == "tech" and settings.entra_configured else None},
                             headers=[("Set-Cookie", cookie(SESSION_COOKIE, "", 0, settings.secure_cookies))])
        if path == "/api/orgs":
            s = self.require(tech=True, write=True)
            name = str(self.body().get("name") or "").strip()[:120]
            if not name:
                raise HttpError(400, "Give the client a name.")
            if db.one("SELECT id FROM orgs WHERE name=?", (name,)):
                raise HttpError(400, "A client with that name already exists.")
            oid = db.run("INSERT INTO orgs (name, created_at) VALUES (?,?)", (name, now()))
            db.audit(s["email"], "client created", name, self.client_ip(), org_id=oid)
            return self.json({"ok": True, "id": oid})
        if m := re.fullmatch(r"/api/orgs/(\d+)/access", path):   # what this client's admins may use: Winbox (off/read/full), site-to-site VPNs
            s = self.require(tech=True, admin=True)
            o = db.one("SELECT * FROM orgs WHERE id=?", (int(m.group(1)),))
            if not o:
                raise HttpError(404, "Client not found.")
            b = self.body()
            wb = b.get("winbox") if b.get("winbox") in ("off", "read", "full") else o["client_winbox"]
            vpn = bool(b["vpn"]) if "vpn" in b else bool(o["client_vpn"])
            db.run("UPDATE orgs SET client_winbox=?, client_vpn=? WHERE id=?", (wb, int(vpn), o["id"]))
            db.audit(s["email"], "client admin access changed", o["name"], self.client_ip(), org_id=o["id"],
                     detail=f"Winbox: {wb}, site-to-site VPNs: {'on' if vpn else 'off'}")
            if wb == "off":   # turning Winbox off closes this client's open sessions straight away
                for x in [x for x in winbox.view({"kind": "client", "org_id": o["id"], "email": ""})]:
                    if db.one("SELECT 1 FROM users WHERE email=? AND kind='client'", (x["user"],)):
                        winbox.close(x["port"], x["user"], True, why="Winbox turned off for the client")
            return self.json({"ok": True})
        if path == "/api/adoption/rotate":   # replace the adoption command; old copies stop working
            s = self.require(tech=True, admin=True)
            db.set_setting("enroll_version", int(db.setting("enroll_version", "1")) + 1)
            db.set_setting("enroll_rotated_at", now())
            db.audit(s["email"], "adoption command replaced", ip=self.client_ip())
            return self.json({"ok": True, "command": adoption.command(settings, self.enroll_token())})
        if m := re.fullmatch(r"/api/devices/(\d+)/approve", path):
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            b = self.body()
            org = db.one("SELECT * FROM orgs WHERE id=?", (int(b.get("org_id") or 0),))
            if not org:
                raise HttpError(400, "Pick the client this router belongs to.")
            if not d["wg_pubkey"]:
                raise HttpError(400, "This router hasn't registered yet.")
            name = str(b.get("name") or "").strip()[:80]
            wg.add_peer(d["wg_pubkey"], d["tunnel_ip"])
            db.run("""UPDATE devices SET org_id=?, state='adopted', adopted_at=COALESCE(adopted_at, ?), last_poll=NULL,
                      name=CASE WHEN ?<>'' THEN ? ELSE name END, name_custom=CASE WHEN ?<>'' AND ?<>COALESCE(identity, '') THEN 1 ELSE name_custom END,
                      site=? WHERE id=?""",
                   (org["id"], now(), name, name, name, name, str(b.get("site") or d["site"] or "")[:120], d["id"]))
            db.event(d["id"], org["id"], "approved", f"by {s['email']} for {org['name']}")
            db.audit(s["email"], "router approved", d["name"], self.client_ip(), org_id=org["id"])
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/firewall(/keep|/undo)?", path):   # a firewall change, tested like Safe Mode
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router must be approved and online.")
            try:
                if m.group(2):
                    changes = (firewall.keep if m.group(2) == "/keep" else firewall.undo)(d, s["email"])
                    what = "kept" if m.group(2) == "/keep" else "undone"
                    db.event(d["id"], d["org_id"], f"firewall changes {what}", f"{len(changes)} change(s) by {s['email']}")
                    db.audit(s["email"], f"firewall changes {what}", d["name"], self.client_ip(), org_id=d["org_id"], detail="; ".join(changes)[:4000])
                    return self.json({"ok": True, "changes": changes})
                r = firewall.change(d, s["email"], self.body())
            except FirewallError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "firewall rule changed (testing)", d["name"], self.client_ip(), org_id=d["org_id"], detail=r["summary"][:4000])
            if r["first"]:
                db.event(d["id"], d["org_id"], "firewall test started", f"by {s['email']} - undone automatically unless kept")
            return self.json(r)
        if m := re.fullmatch(r"/api/devices/(\d+)/location", path):   # where the router is, for the map
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            b = self.body()
            if b.get("clear"):
                db.run("UPDATE devices SET lat=NULL, lon=NULL, location=NULL, loc_source=NULL WHERE id=?", (d["id"],))
                db.audit(s["email"], "router location cleared", d["name"], self.client_ip(), org_id=d["org_id"])
                return self.json({"ok": True})
            try:
                lat, lon = float(b.get("lat")), float(b.get("lon"))
            except (TypeError, ValueError):
                raise HttpError(400, "Enter the latitude and longitude as numbers (e.g. 37.6872, -97.3301).") from None
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                raise HttpError(400, "Latitude must be -90 to 90 and longitude -180 to 180.")
            label = re.sub(r"[\x00-\x1f]", " ", str(b.get("address") or "")).strip()[:200]
            db.run("UPDATE devices SET lat=?, lon=?, location=?, loc_source='manual' WHERE id=?", (round(lat, 6), round(lon, 6), label, d["id"]))
            db.audit(s["email"], "router location set", f"{d['name']}: {label or f'{lat:.4f}, {lon:.4f}'}", self.client_ip(), org_id=d["org_id"])
            return self.json({"ok": True})
        if path == "/api/geocode":   # optional address lookup: only what the person typed goes to OpenStreetMap's Nominatim
            s = self.require(tech=True, write=True)
            text = str(self.body().get("q") or "").strip()[:200]
            if len(text) < 3:
                raise HttpError(400, "Type an address or place.")
            return self.json({"results": geocode(text)})
        if m := re.fullmatch(r"/api/devices/(\d+)/rename", path):
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            b = self.body()
            name = str(b.get("name") or "").strip()[:80]
            # blank = follow the router's identity again
            db.run("UPDATE devices SET name=?, name_custom=?, site=? WHERE id=?",
                   (name or d["identity"] or d["name"], 1 if name else 0, str(b.get("site") if "site" in b else d["site"])[:120], d["id"]))
            db.audit(s["email"], "router renamed", f"{d['name']} -> {name or d['identity']}", self.client_ip(), org_id=d["org_id"])
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/ports/(review|apply|keep|undo)", path):   # VLAN / port changes, tested like Safe Mode
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            b = self.body()
            try:
                if m.group(2) == "review":
                    return self.json(ports.review(d, b))
                if m.group(2) == "apply":
                    return self.json(ports.apply(d, s["email"], b))
                changes = ports.keep(d, s["email"]) if m.group(2) == "keep" else ports.undo(d, s["email"])
                return self.json({"ok": True, "changes": changes})
            except PortsError as e:
                raise HttpError(400, str(e)) from None
            except RouterError as e:
                raise HttpError(502, str(e)) from None
        if m := re.fullmatch(r"/api/devices/(\d+)/meta", path):   # tags and notes (technicians)
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            b = self.body()
            tags = []
            for x in b.get("tags") or []:
                x = re.sub(r"[^\w .+-]", "", str(x)).strip()[:32]
                if x and x.lower() not in {t.lower() for t in tags}:
                    tags.append(x)
            notes = str(b.get("notes") or "")[:4000]
            kind_o = b.get("kind") if b.get("kind") in DEVICE_KINDS else None
            db.run("UPDATE devices SET tags=?, notes=?, kind_override=? WHERE id=?", (json.dumps(tags[:20]) if tags else None, notes, kind_o, d["id"]))
            db.audit(s["email"], "router tags / notes", d["name"], self.client_ip(), detail=f"tags: {', '.join(tags) or '-'}", org_id=d["org_id"])
            return self.json({"ok": True, "tags": tags[:20]})
        if m := re.fullmatch(r"/api/devices/(\d+)/isp", path):   # which interfaces are the router's internet links ([] = automatic)
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            names = {i.get("name") for i in json.loads(d["interfaces"] or "[]")}
            chosen = [str(x)[:64] for x in (self.body().get("ifaces") or []) if str(x) in names][:16]
            db.run("UPDATE devices SET isp_ifaces=?, isp_state=NULL WHERE id=?", (json.dumps(chosen) if chosen else None, d["id"]))
            db.audit(s["email"], "internet links set", f"{d['name']}: {', '.join(chosen) or 'automatic'}", self.client_ip(), org_id=d["org_id"])
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/identity", path):   # change /system identity on the router itself
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            ident = str(self.body().get("identity") or "").strip()
            if not ident or len(ident) > 64 or re.search(r"[\x00-\x1f\x7f\"\\$;{}\[\]]", ident):
                raise HttpError(400, "Use 1-64 characters, without quotes, backslashes, $ ; [ ] { }.")
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router must be approved and online to change its identity.")
            try:
                got = poller.client(d).set_identity(ident) or ident
            except RouterError as e:
                raise HttpError(502, f"The router didn't accept it: {e}") from None
            # TikManager's name follows the identity again (a custom name typed earlier is replaced)
            db.run("UPDATE devices SET identity=?, name=?, name_custom=0 WHERE id=?", (got, got, d["id"]))
            db.event(d["id"], d["org_id"], "identity changed", f"{d['identity'] or d['name']} -> {got} by {s['email']}")
            db.audit(s["email"], "router identity changed", f"{d['identity'] or d['name']} -> {got}", self.client_ip(), org_id=d["org_id"])
            return self.json({"ok": True, "identity": got})
        if m := re.fullmatch(r"/api/devices/(\d+)/move", path):   # fix a router approved under the wrong client
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            org = db.one("SELECT * FROM orgs WHERE id=?", (int(self.body().get("org_id") or 0),))
            if not org:
                raise HttpError(400, "Pick the client to move it to.")
            if d["state"] != "adopted" or org["id"] == d["org_id"]:
                raise HttpError(400, "The router already belongs to that client." if org["id"] == d["org_id"] else "Approve the router first.")
            vpn = db.one("SELECT v.name FROM vpn_sites s JOIN vpns v ON v.id = s.vpn_id WHERE s.device_id=?", (d["id"],))
            if vpn:
                raise HttpError(400, f"Take it out of the site-to-site VPN \"{vpn['name']}\" first - a VPN belongs to one client.")
            old = db.one("SELECT name FROM orgs WHERE id=?", (d["org_id"],))
            # its history moves with it: the router was simply filed under the wrong client
            db.run("UPDATE devices SET org_id=?, itg_config_id=NULL, itg_error=NULL WHERE id=?", (org["id"], d["id"]))
            for table in ("events", "backups", "upgrades"):
                db.run(f"UPDATE {table} SET org_id=? WHERE device_id=?", (org["id"], d["id"]))
            db.event(d["id"], org["id"], "moved", f"from {old['name'] if old else 'no client'} to {org['name']} by {s['email']}")
            db.audit(s["email"], "router moved", f"{d['name']}: {old['name'] if old else '-'} -> {org['name']}", self.client_ip(), org_id=org["id"])
            return self.json({"ok": True})
        if path == "/api/dev/register":   # dev only: stands in for a router running the adoption command
            if not settings.dev:
                raise HttpError(404, "Not found.")
            self.require(tech=True, write=True)
            r = __import__("random").Random()
            self.register_router(base64.b64encode(secrets.token_bytes(32)).decode(),
                                 r.choice(["MikroTik", "Main-Office", "Branch-Router", "Clinic-GW", "Warehouse-AP"]) + f"-{r.randint(1, 99)}",
                                 r.choice(["RB5009UG+S+", "hAP ax3", "CCR2004-16G-2S+", "hEX S"]), f"HG{r.randint(10 ** 7, 10 ** 8 - 1):X}",
                                 "7.19.4 (stable)")
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/backup", path):
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            r = backups.run(d["id"], "manual", s["email"])
            db.audit(s["email"], "backup now", d["name"], self.client_ip(), org_id=d["org_id"], detail=r.get("detail", ""))
            return self.json(r, 200 if r.get("ok") else 502)
        if path == "/api/integrations/mail":   # email settings (Microsoft 365 or SMTP)
            s = self.require(tech=True, admin=True)
            b = self.body()
            try:
                Mailer.validate({**mailer.config(), **{k: str(v).strip() for k, v in b.items() if isinstance(v, str)}})
                integ.save("mail", b)
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            mailer._token = (None, 0)
            db.audit(s["email"], "integration settings changed", "Email", self.client_ip())
            return self.json({"ok": True, **integ.public("mail")})
        if path == "/api/integrations/mail/test":   # send a test message
            s = self.require(tech=True, admin=True)
            to = str(self.body().get("to") or s["email"]).strip()
            try:
                mailer.send(to, "TikManager test email", f"This is a test from TikManager ({settings.public_url}), sent by {s['email']}.\n\n"
                                                         "If you can read this, TikManager can send email - alerts and invitations will arrive like this.")
            except MailError as e:
                return self.json({"ok": False, "detail": str(e)})
            db.audit(s["email"], "test email sent", to, self.client_ip())
            return self.json({"ok": True, "detail": f"Sent to {to} - check the inbox (and spam folder)."})
        if path == "/api/integrations/github":   # community script library + the token used to share
            s = self.require(tech=True, admin=True)
            try:
                integ.save("github", self.body())
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            library._cache = None
            db.audit(s["email"], "integration settings changed", "GitHub script library", self.client_ip())
            return self.json({"ok": True, **integ.public("github")})
        if path == "/api/integrations/github/test":
            self.require(tech=True, admin=True)
            try:
                lst = library.listing(refresh=True)
                who = ""
                if integ.configured("github"):
                    who = " Token belongs to " + (library._gh("GET", "/user", auth=True) or {}).get("login", "?") + "."
                return self.json({"ok": True, "detail": f"{len(lst['items'])} scripts in {library.repo}.{who}"})
            except LibraryError as e:
                return self.json({"ok": False, "detail": str(e)})
        if path == "/api/library/import":   # copy a community script into this TikManager's library (never runs it)
            s = self.require(tech=True, write=True)
            try:
                sc = library.get(str(self.body().get("path") or ""))
            except LibraryError as e:
                raise HttpError(400, str(e)) from None
            name = sc["name"][:100]
            desc = (sc["description"] + (f" (community library, by {sc['author']})" if sc["author"] else " (community library)"))[:300]
            sid = db.run("INSERT INTO scripts (name, description, body, created_by, created_at, updated_by, updated_at) VALUES (?,?,?,?,?,?,?)",
                         (name, desc, sc["body"][:100000], s["email"], now(), s["email"], now()))
            db.audit(s["email"], "community script imported", name, self.client_ip(), detail=sc["url"])
            return self.json({"ok": True, "id": sid})
        if path == "/api/library/scan":   # secrets in a script before it's shared
            s = self.require(tech=True, write=True)
            names = [o["name"] for o in db.q("SELECT name FROM orgs")]
            return self.json({"findings": script_secrets(str(self.body().get("body") or ""), names)})
        if path == "/api/library/share":   # open a pull request on the community library
            s = self.require(tech=True, write=True)
            b = self.body()
            sc = db.one("SELECT * FROM scripts WHERE id=?", (int(b.get("id") or 0),))
            if not sc:
                raise HttpError(404, "Script not found.")
            name = re.sub(r"[\x00-\x1f]", " ", str(b.get("name") or sc["name"])).strip()[:80]
            desc = re.sub(r"[\x00-\x1f]", " ", str(b.get("description") or sc["description"])).strip()[:300]
            tags = [re.sub(r"[^a-z0-9 -]", "", t.lower()).strip()[:30] for t in str(b.get("tags") or "").split(",") if t.strip()][:8]
            ros = re.sub(r"[^0-9a-z .+-]", "", str(b.get("routeros") or "").lower())[:30]
            body = str(b.get("body") if b.get("body") is not None else sc["body"])[:100000]
            if not name or not desc:
                raise HttpError(400, "Give it a name and a description so others know what it does.")
            findings = script_secrets(body, [o["name"] for o in db.q("SELECT name FROM orgs")])
            if findings and not b.get("confirmed"):
                return self.json({"ok": False, "findings": findings}, 409)
            try:
                url = library.share(name, desc, tags, ros, body)
            except LibraryError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "script shared to the community library", name, self.client_ip(), detail=url or "")
            return self.json({"ok": True, "url": url})
        if m := re.fullmatch(r"/api/integrations/(cw|itg)", path):
            s = self.require(tech=True, admin=True)
            try:
                integ.save(m.group(1), self.body())
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "integration settings changed", {"cw": "ConnectWise PSA", "itg": "IT Glue"}[m.group(1)], self.client_ip())
            return self.json({"ok": True, **integ.public(m.group(1))})
        if m := re.fullmatch(r"/api/integrations/(cw|itg)/test", path):
            self.require(tech=True, admin=True)
            try:
                return self.json({"ok": True, "detail": integ.cw_test() if m.group(1) == "cw" else integ.itg_test()})
            except IntegrationError as e:
                return self.json({"ok": False, "detail": str(e)})
        if path == "/api/net/accounts":   # add / change a UniFi or UISP connection {id?, kind, name, url, key, org_id, trust_cert}
            s = self.require(tech=True, admin=True)
            b = self.body()
            org = db.one("SELECT id, name FROM orgs WHERE id=?", (int(b.get("org_id") or 0),)) if b.get("org_id") else None
            if b.get("org_id") and not org:
                raise HttpError(400, "Client not found.")
            try:
                aid = unifi.save(int(b["id"]) if b.get("id") else None, str(b.get("kind") or ""), b.get("name"), b.get("url"),
                                 str(b.get("key") or "").strip(), org["id"] if org else None, bool(b.get("trust_cert")))
            except (ValueError, NetError) as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "UniFi / UISP connection saved", str(b.get("name") or b.get("kind")), self.client_ip(), org_id=org["id"] if org else None,
                     detail=f"{b.get('kind')}{' ' + str(b.get('url')) if b.get('url') else ''}, {'client ' + org['name'] if org else 'MSP account'}"
                            f"{', certificate pinned' if b.get('trust_cert') else ''}")
            threading.Thread(target=unifi.sync, args=(s["email"], aid), daemon=True, name="net-sync-now").start()
            return self.json({"ok": True, "id": aid})
        if m := re.fullmatch(r"/api/net/accounts/(\d+)/(test|sync|delete)", path):
            s = self.require(tech=True, admin=m.group(2) != "sync")
            a = db.one("SELECT * FROM net_accounts WHERE id=?", (int(m.group(1)),))
            if not a:
                raise HttpError(404, "Connection not found.")
            if m.group(2) == "delete":
                unifi.delete(a["id"])
                db.audit(s["email"], "UniFi / UISP connection removed", a["name"], self.client_ip(), org_id=a["org_id"])
                return self.json({"ok": True})
            if m.group(2) == "test":
                try:
                    return self.json({"ok": True, "detail": unifi.test(a["id"])})
                except NetError as e:
                    return self.json({"ok": False, "detail": str(e)})
            res = unifi.sync(s["email"], a["id"])
            return self.json({"ok": True, "last": (res or [None])[0]})
        if path == "/api/unifi/sync":   # read every connection now
            s = self.require(tech=True)
            return self.json({"ok": True, "results": unifi.sync(s["email"]) or []})
        if path == "/api/unifi/assign":   # {site, org_id|null}: which client a UniFi site belongs to
            s = self.require(tech=True, write=True)
            b = self.body()
            site = db.one("SELECT s.*, a.org_id AS account_org FROM net_sites s JOIN net_accounts a ON a.id = s.account_id WHERE s.id=?", (str(b.get("site") or ""),))
            if not site:
                raise HttpError(404, "Site not found.")
            if site["account_org"]:
                raise HttpError(400, "This site comes from a client's own connection - everything in it belongs to that client.")
            if b.get("org_id") == "auto":   # back to automatic matching (public IP, then name) at the next sync
                db.run("UPDATE net_sites SET org_manual=0, org_id=NULL, matched=NULL WHERE id=?", (site["id"],))   # decided afresh
                db.audit(s["email"], "UniFi / UISP site set to automatic matching", site["name"], self.client_ip(), org_id=site["org_id"])
                threading.Thread(target=unifi.sync, args=(s["email"], site["account_id"]), daemon=True, name="net-sync-now").start()
                return self.json({"ok": True})
            org = db.one("SELECT id, name FROM orgs WHERE id=?", (int(b.get("org_id") or 0),)) if b.get("org_id") else None
            if b.get("org_id") and not org:
                raise HttpError(400, "Client not found.")
            db.run("UPDATE net_sites SET org_id=?, org_manual=1, matched=? WHERE id=?", (org["id"] if org else None, f"chosen by {s['email']}", site["id"]))
            db.audit(s["email"], "UniFi / UISP site assigned", f"{site['name']} -> {org['name'] if org else 'no client'}", self.client_ip(),
                     org_id=org["id"] if org else site["org_id"])
            return self.json({"ok": True})
        if path == "/api/integrations/cw/link":   # {cw_id, org_id} links; {cw_id} alone imports the company as a new client
            s = self.require(tech=True, admin=True)
            b = self.body()
            cw_id = int(b.get("cw_id") or 0)
            try:
                company = next((c for c in integ.cw_companies() if c["id"] == cw_id), None)
            except IntegrationError as e:
                raise HttpError(502, str(e)) from None
            if not company:
                raise HttpError(400, "That company wasn't found in ConnectWise PSA.")
            if db.one("SELECT id FROM orgs WHERE cw_id=?", (cw_id,)):
                raise HttpError(400, "That company is already linked.")
            if b.get("org_id"):
                org = db.one("SELECT * FROM orgs WHERE id=?", (int(b["org_id"]),))
                if not org:
                    raise HttpError(400, "Client not found.")
                db.run("UPDATE orgs SET cw_id=?, source='cw' WHERE id=?", (cw_id, org["id"]))
                db.audit(s["email"], "client linked to ConnectWise", f"{org['name']} = {company['name']}", self.client_ip(), org_id=org["id"])
            else:
                if db.one("SELECT id FROM orgs WHERE name=?", (company["name"],)):
                    raise HttpError(400, "A client with that name already exists - link it instead.")
                oid = db.run("INSERT INTO orgs (name, created_at, cw_id, source) VALUES (?,?,?,'cw')", (company["name"][:120], now(), cw_id))
                db.audit(s["email"], "client imported from ConnectWise", company["name"], self.client_ip(), org_id=oid)
            return self.json({"ok": True})
        if path == "/api/integrations/cw/unlink":
            s = self.require(tech=True, admin=True)
            org = db.one("SELECT * FROM orgs WHERE id=?", (int(self.body().get("org_id") or 0),))
            if org:
                db.run("UPDATE orgs SET cw_id=NULL, source='manual' WHERE id=?", (org["id"],))
                db.audit(s["email"], "client unlinked from ConnectWise", org["name"], self.client_ip(), org_id=org["id"])
            return self.json({"ok": True})
        if path == "/api/integrations/itg/link":   # {org_id, itg_id} - a blank itg_id unlinks
            s = self.require(tech=True, admin=True)
            b = self.body()
            org = db.one("SELECT * FROM orgs WHERE id=?", (int(b.get("org_id") or 0),))
            if not org:
                raise HttpError(400, "Client not found.")
            itg_id = str(b.get("itg_id") or "").strip()
            try:
                known = not itg_id or any(o["id"] == itg_id for o in integ.itg_lookups()["orgs"])
            except IntegrationError as e:
                raise HttpError(502, str(e)) from None
            if not known:
                raise HttpError(400, "That IT Glue organization wasn't found.")
            db.run("UPDATE orgs SET itg_id=? WHERE id=?", (itg_id or None, org["id"]))
            if not itg_id:
                db.run("UPDATE devices SET itg_config_id=NULL, itg_error=NULL WHERE org_id=?", (org["id"],))
            db.audit(s["email"], "client linked to IT Glue" if itg_id else "client unlinked from IT Glue", org["name"], self.client_ip(), org_id=org["id"])
            return self.json({"ok": True})
        if path == "/api/integrations/itg/sync":   # document every linked router in IT Glue now (background)
            s = self.require(tech=True, admin=True)
            if not integ.configured("itg"):
                raise HttpError(400, "Set up IT Glue first.")
            if not integ.sync_state.get("running"):
                threading.Thread(target=integ.itg_sync, args=(settings.public_url,), daemon=True, name="itg-sync").start()
                db.audit(s["email"], "IT Glue sync started", ip=self.client_ip())
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/vpn-reconnect", path):   # reconnect one VPN found on the router
            s = self.require_vpn(write=True)
            if not router_act_limit.allow(s["email"]):
                raise HttpError(429, "That's a lot of reconnects - wait a few minutes.")
            d = self.device_for(s, m.group(1))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router must be online.")
            want = str(self.body().get("rid") or "")
            t = next((t for t in vpninv.normalize(json.loads(d.get("vpn_inv") or "null") or {}) if t.get("rid") == want), None)
            if not t:   # only something the inventory saw on this router - a request can't toggle anything else
                raise HttpError(400, "That VPN isn't in this router's list - read the routers again.")
            ref = json.loads(t["rid"])
            if ref["menu"] not in vpninv.RECONNECT_MENUS:
                raise HttpError(400, "That kind of VPN can't be reconnected from here.")
            try:
                n = poller.client(d).tunnel_reconnect(ref["menu"], ref["match"])
            except RouterError as e:
                raise HttpError(502, f"The router didn't do it: {e}") from None
            db.audit(s["email"], "vpn reconnected", d["name"], self.client_ip(), org_id=d["org_id"], detail=f"{t['kind']} {t['name']}")
            db.event(d["id"], d["org_id"], "vpn", f"{t['kind']} \"{t['name']}\" reconnected by {s['email']}")
            threading.Timer(15, lambda: poller.collect_vpns(d)).start()   # re-read once it has had time to come back
            return self.json({"ok": True, "count": n, "note": "" if n else "It wasn't connected - the router keeps trying on its own."})
        if (path == "/api/vpns" or path.startswith("/api/vpns/")) and not settings.managed_vpn:   # every managed-VPN change
            raise HttpError(404, MANAGED_VPN_OFF)
        if m := re.fullmatch(r"/api/vpns/(\d+)/reconnect", path):   # reconnect a TikManager VPN at one site (or every site)
            s = self.require_vpn(write=True)
            if not router_act_limit.allow(s["email"]):
                raise HttpError(429, "That's a lot of reconnects - wait a few minutes.")
            v = self.vpn_for(s, m.group(1))
            did = int(self.body().get("device_id") or 0)
            sites = db.q("SELECT d.* FROM vpn_sites s JOIN devices d ON d.id = s.device_id WHERE s.vpn_id=? AND s.state='applied'"
                         + (" AND d.id=?" if did else ""), (v["id"], did) if did else (v["id"],))
            if not sites:
                raise HttpError(400, "Nothing to reconnect - the VPN isn't applied at that site.")
            done, errs = [], []
            for d in sites:
                try:
                    if not d["online"]:
                        raise RouterError("offline")
                    poller.client(d).vpn_reconnect()
                    done.append(d["name"])
                except RouterError as e:
                    errs.append(f"{d['name']}: {e}")
            db.audit(s["email"], "vpn reconnected", v["name"], self.client_ip(), org_id=v["org_id"], detail=", ".join(done) + (f"; failed: {'; '.join(errs)}" if errs else ""))
            if not done:
                raise HttpError(502, "; ".join(errs))
            return self.json({"ok": True, "done": done, "errors": errs})
        if m := re.fullmatch(r"/api/devices/(\d+)/ra/cloud", path):   # use the router's IP Cloud DNS name as the address
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            try:
                r = remote.use_cloud(d["id"], s["email"])
            except RaError as e:
                raise HttpError(400, str(e)) from None
            return self.json({"ok": True, **r})
        if m := re.fullmatch(r"/api/devices/(\d+)/ra/users/(\d+)/(disable|enable|expiry|access)", path):   # off / on, expiry, access
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            try:
                if m.group(3) == "expiry":
                    remote.set_expiry(d["id"], int(m.group(2)), self.body().get("date"), s["email"])
                elif m.group(3) == "access":
                    remote.set_access(d["id"], int(m.group(2)), self.body().get("access"), s["email"])
                else:
                    remote.set_disabled(d["id"], int(m.group(2)), m.group(3) == "disable", s["email"])
            except RaError as e:
                raise HttpError(400, str(e)) from None
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/ra(?:/(remove|users|users/(\d+)/revoke))?", path):   # remote access changes
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            if not router_act_limit.allow(s["email"]):
                raise HttpError(429, "That's a lot of router changes - wait a few minutes.")
            try:
                if m.group(2) == "remove":
                    remote.remove(d["id"], s["email"])
                elif m.group(2) == "users":
                    b = self.body()
                    return self.json({"ok": True, **remote.add_user(d["id"], b.get("name"), s["email"], b.get("expires"), b.get("access"))})
                elif m.group(3):
                    remote.revoke(d["id"], int(m.group(3)), s["email"])
                else:
                    remote.setup(d["id"], self.body(), s["email"])
            except RaError as e:
                raise HttpError(400, str(e)) from None
            return self.json({"ok": True, **remote.info(d["id"])})
        if path == "/api/vpn-inventory/refresh":   # re-read the VPNs on some routers (or every online one) now
            s = self.require_vpn()
            if s["kind"] == "client" and not router_act_limit.allow(s["email"]):
                raise HttpError(429, "The routers were just read - wait a few minutes.")
            ids = [int(x) for x in (self.body().get("device_ids") or []) if str(x).isdigit()]
            where, args = self.org_scope(s)
            rows = [self.device_for(s, i) for i in ids] if ids else db.q(f"SELECT * FROM devices WHERE state='adopted' AND online=1 AND {where}", args)
            if len(rows) <= 2:
                return self.json({"ok": True, "done": sum(1 for d in rows if poller.collect_vpns(d))})
            threading.Thread(target=lambda: [poller.collect_vpns(d) for d in rows], daemon=True, name="vpn-inventory").start()
            return self.json({"ok": True, "background": True, "count": len(rows)})
        if path == "/api/vpns":   # create / update; {apply: true} applies right away
            s = self.require_vpn(write=True)
            b = self.body()
            if b.get("id"):
                self.vpn_for(s, b["id"])   # a client admin can only change their own organization's VPNs
            try:
                org_id = s["org_id"] if s["kind"] == "client" else int(b.get("org_id") or 0)
                sites = [{"device_id": int(x["device_id"]), "subnets": [str(n) for n in x.get("subnets") or []][:50]} for x in (b.get("sites") or [])[:250]]
                name = str(b.get("name") or "").strip()[:80] or "Site-to-site VPN"
                vid = vpns.save(int(b["id"]) if b.get("id") else None, org_id, name, int(b.get("hub_device_id") or 0),
                                str(b.get("endpoint") or "").strip()[:120], int(b.get("port") or 13232), str(b.get("tunnel_net") or "").strip(), sites, s["email"])
            except (VpnError, KeyError, TypeError, ValueError) as e:
                raise HttpError(400, str(e) or "Invalid VPN settings.") from None
            db.audit(s["email"], "vpn saved", name, self.client_ip(), org_id=org_id, detail=f"{len(sites)} routers")
            if b.get("apply"):
                vpns.apply(vid, s["email"])
            return self.json({"ok": True, "id": vid})
        if m := re.fullmatch(r"/api/vpns/(\d+)/(apply|disable|delete)", path):
            s = self.require_vpn(write=True)
            v = self.vpn_for(s, m.group(1))
            act = m.group(2)
            if act == "delete" and v["status"] in ("draft", "disabled") and not db.one(
                    "SELECT 1 FROM vpn_sites WHERE vpn_id=? AND state IN ('applied','failed','removing')", (v["id"],)):
                db.run("DELETE FROM vpns WHERE id=?", (v["id"],))   # never applied (or already removed): nothing on the routers
                db.audit(s["email"], "vpn deleted", v["name"], self.client_ip(), org_id=v["org_id"])
                return self.json({"ok": True, "deleted": True})
            started = vpns.apply(v["id"], s["email"]) if act == "apply" else vpns.disable(v["id"], s["email"], delete=act == "delete")
            if not started:
                raise HttpError(409, "This VPN is busy - wait for the current change to finish.")
            db.audit(s["email"], f"vpn {act} started", v["name"], self.client_ip(), org_id=v["org_id"])
            return self.json({"ok": True})
        # --- scripts, groups, tasks ---
        if path == "/api/scripts":   # create / update {id?, name, description, body}
            s = self.require(tech=True, write=True)
            b = self.body()
            name, body = str(b.get("name") or "").strip()[:100], str(b.get("body") or "").replace("\r\n", "\n")
            if not name or not body.strip():
                raise HttpError(400, "Give the script a name and some RouterOS commands.")
            if len(body) > 32000:
                raise HttpError(400, "Scripts are limited to 32,000 characters.")
            desc = str(b.get("description") or "").strip()[:300]
            if b.get("id"):
                sid = int(b["id"])
                db.run("UPDATE scripts SET name=?, description=?, body=?, updated_by=?, updated_at=? WHERE id=?", (name, desc, body, s["email"], now(), sid))
            else:
                sid = db.run("INSERT INTO scripts (name, description, body, created_by, created_at, updated_by, updated_at) VALUES (?,?,?,?,?,?,?)",
                             (name, desc, body, s["email"], now(), s["email"], now()))
            db.audit(s["email"], "script saved", name, self.client_ip(), detail=body[:2000])
            return self.json({"ok": True, "id": sid})
        if m := re.fullmatch(r"/api/scripts/(\d+)/delete", path):
            s = self.require(tech=True, write=True)
            sc = db.one("SELECT * FROM scripts WHERE id=?", (int(m.group(1)),))
            if sc and db.one("SELECT 1 FROM tasks WHERE script_id=?", (sc["id"],)):
                raise HttpError(400, "Tasks still use this script - delete or change them first.")
            if sc:
                db.run("DELETE FROM scripts WHERE id=?", (sc["id"],))
                db.audit(s["email"], "script deleted", sc["name"], self.client_ip())
            return self.json({"ok": True})
        if path == "/api/groups":   # create / update {id?, name, description, device_ids}
            s = self.require(tech=True, write=True)
            b = self.body()
            name = str(b.get("name") or "").strip()[:80]
            if not name:
                raise HttpError(400, "Give the group a name.")
            clash = db.one("SELECT id FROM router_groups WHERE name=? AND id IS NOT ?", (name, int(b["id"]) if b.get("id") else None))
            if clash:
                raise HttpError(400, "A group with that name already exists.")
            if b.get("id"):
                gid = int(b["id"])
                db.run("UPDATE router_groups SET name=?, description=? WHERE id=?", (name, str(b.get("description") or "")[:300], gid))
            else:
                gid = db.run("INSERT INTO router_groups (name, description, created_at) VALUES (?,?,?)", (name, str(b.get("description") or "")[:300], now()))
            db.run("DELETE FROM group_members WHERE group_id=?", (gid,))
            for did in {int(x) for x in b.get("device_ids") or [] if str(x).isdigit()}:
                if db.one("SELECT 1 FROM devices WHERE id=?", (did,)):
                    db.run("INSERT INTO group_members (group_id, device_id) VALUES (?,?)", (gid, did))
            db.audit(s["email"], "group saved", name, self.client_ip(), detail=f"{len(b.get('device_ids') or [])} routers")
            return self.json({"ok": True, "id": gid})
        if m := re.fullmatch(r"/api/groups/(\d+)/delete", path):
            s = self.require(tech=True, write=True)
            g = db.one("SELECT * FROM router_groups WHERE id=?", (int(m.group(1)),))
            if g:
                db.run("DELETE FROM router_groups WHERE id=?", (g["id"],))
                db.audit(s["email"], "group deleted", g["name"], self.client_ip())
            return self.json({"ok": True})
        if path == "/api/tasks":   # create / update a scheduled task
            s = self.require(tech=True, write=True)
            b = self.body()
            name = str(b.get("name") or "").strip()[:100]
            action = b.get("action") if b.get("action") in ("script", "upgrade") else "script"
            kind = b.get("kind") if b.get("kind") in ("once", "daily", "weekly", "hourly") else None
            targets = b.get("targets") or {}
            targets = {"all": bool(targets.get("all")), **{k: [int(x) for x in targets.get(k) or [] if str(x).isdigit()][:1000] for k in ("orgs", "groups", "devices")},
                       "tags": [str(x)[:32] for x in targets.get("tags") or []][:50]}
            if not name or not kind:
                raise HttpError(400, "Give the task a name and a schedule.")
            script_id = int(b.get("script_id") or 0) if action == "script" else None
            if action == "script" and not db.one("SELECT 1 FROM scripts WHERE id=?", (script_id,)):
                raise HttpError(400, "Pick the script to run.")
            if not (targets["all"] or targets["orgs"] or targets["groups"] or targets["devices"] or targets["tags"]):
                raise HttpError(400, "Pick which routers it runs on.")
            at_time = str(b.get("at_time") or "02:00")
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", at_time):
                raise HttpError(400, "Pick a time like 02:00.")
            days = sorted({int(x) for x in b.get("days") or [] if str(x).isdigit() and 0 <= int(x) <= 6})
            if kind == "weekly" and not days:
                raise HttpError(400, "Pick at least one day of the week.")
            try:
                run_at = float(b["run_at"]) if b.get("run_at") else (now() if kind == "once" else None)
                hours = max(1, min(720, int(b.get("every_hours") or 24)))
            except (TypeError, ValueError):
                raise HttpError(400, "Invalid time.") from None
            opts = {"channel": b.get("channel") if b.get("channel") in UPGRADE_CHANNELS else "", "firmware": bool(b.get("firmware", True))}
            row = {"kind": kind, "run_at": run_at, "at_time": at_time, "days": json.dumps(days), "every_hours": hours,
                   "tz": str(b.get("tz") or "")[:60], "last_run": None}
            values = (name, action, script_id, json.dumps(opts), json.dumps(targets), kind, run_at, at_time, json.dumps(days), hours, row["tz"],
                      1 if b.get("backup_first", True) else 0, "wait" if b.get("offline") == "wait" else "skip",
                      1 if b.get("enabled", True) else 0, next_run(row), now())
            if b.get("id"):
                tid = int(b["id"])
                db.run("""UPDATE tasks SET name=?, action=?, script_id=?, options=?, targets=?, kind=?, run_at=?, at_time=?, days=?, every_hours=?, tz=?,
                          backup_first=?, offline=?, enabled=?, next_run=?, updated_at=?, last_run=NULL WHERE id=?""", (*values, tid))
            else:
                tid = db.run("""INSERT INTO tasks (name, action, script_id, options, targets, kind, run_at, at_time, days, every_hours, tz, backup_first,
                                offline, enabled, next_run, updated_at, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                             (*values, s["email"], now()))
            db.audit(s["email"], "task saved", name, self.client_ip(), detail=json.dumps({"action": action, "kind": kind, "targets": targets}))
            return self.json({"ok": True, "id": tid})
        if m := re.fullmatch(r"/api/tasks/(\d+)/(run|toggle|delete)", path):
            s = self.require(tech=True, write=True)
            t = db.one("SELECT * FROM tasks WHERE id=?", (int(m.group(1)),))
            if not t:
                raise HttpError(404, "Task not found.")
            act = m.group(2)
            if act == "run":
                try:
                    rid = tasks.start_run(t, s["email"], "run now")
                except ValueError as e:
                    raise HttpError(400, str(e)) from None
                db.audit(s["email"], "task run now", t["name"], self.client_ip())
                return self.json({"ok": True, "run_id": rid})
            if act == "toggle":
                on = 0 if t["enabled"] else 1
                db.run("UPDATE tasks SET enabled=?, next_run=? WHERE id=?", (on, next_run(t) if on else t["next_run"], t["id"]))
                db.audit(s["email"], "task enabled" if on else "task paused", t["name"], self.client_ip())
                return self.json({"ok": True, "enabled": on})
            db.run("DELETE FROM tasks WHERE id=?", (t["id"],))
            db.audit(s["email"], "task deleted", t["name"], self.client_ip())
            return self.json({"ok": True})
        if path == "/api/run-script":   # run a library script now on chosen routers (no saved task)
            s = self.require(tech=True, write=True)
            b = self.body()
            sc = db.one("SELECT * FROM scripts WHERE id=?", (int(b.get("script_id") or 0),))
            devices = [self.device_for(s, int(x)) for x in b.get("device_ids") or [] if str(x).isdigit()]
            if not sc or not devices:
                raise HttpError(400, "Pick a script and at least one router.")
            rid = tasks.start_run({"name": None, "action": "script", "script_id": sc["id"], "backup_first": bool(b.get("backup_first", True)),
                                   "offline": "skip"}, s["email"], "run now", [d for d in devices if d["state"] == "adopted"])
            db.audit(s["email"], "script run now", sc["name"], self.client_ip(), detail=", ".join(d["name"] for d in devices)[:500])
            return self.json({"ok": True, "run_id": rid})
        if path == "/api/upgrades":   # {device_ids: [...], when: epoch seconds or null for now, channel, firmware, stagger}
            s = self.require(tech=True, write=True)
            b = self.body()
            ids = [int(x) for x in (b.get("device_ids") or []) if str(x).isdigit()][:500]
            devices = [self.device_for(s, i) for i in ids]
            if not devices:
                raise HttpError(400, "Pick at least one router.")
            when = b.get("when")
            try:
                when = now() if when in (None, "", 0) else float(when)
                stagger = max(0, min(240, int(b.get("stagger") or 0)))
            except (TypeError, ValueError):
                raise HttpError(400, "Invalid time.") from None
            if when < now() - 300 or when > now() + 366 * 86400:
                raise HttpError(400, "Pick a time from now up to a year ahead.")
            try:
                max_fail = max(0, min(500, int(b.get("max_fail") or 0)))
            except (TypeError, ValueError):
                max_fail = 0
            try:
                created, skipped = upgrades.schedule(devices, max(when, now()), str(b.get("channel") or ""), bool(b.get("firmware", True)),
                                                     s["email"], stagger, sequential=bool(b.get("sequential")), max_fail=max_fail, pin=bool(b.get("pin")))
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "upgrade scheduled", f"{len(created)} router(s)", self.client_ip(),
                     detail=f"at {time.strftime('%Y-%m-%d %H:%M', time.localtime(when))}, channel {b.get('channel') or 'router default'}, "
                            f"firmware {'yes' if b.get('firmware', True) else 'no'}, stagger {stagger} min, one at a time {'yes' if b.get('sequential') else 'no'}, "
                            f"safety stop {max_fail or 'off'}, pinned {'yes' if b.get('pin') else 'no'}")
            return self.json({"ok": True, "created": len(created), "skipped": [{"name": n, "reason": r} for n, r in skipped]})
        if m := re.fullmatch(r"/api/upgrades/batch/([0-9a-f]{12})/(resume|cancel)", path):   # a batch held by the safety stop
            s = self.require(tech=True, write=True)
            if m.group(2) == "resume":
                upgrades.resume(m.group(1), s["email"])
            else:
                upgrades.cancel_batch(m.group(1), s["email"])
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/upgrades/(\d+)/cancel", path):
            s = self.require(tech=True, write=True)
            j = upgrades.cancel(int(m.group(1)))
            if not j:
                raise HttpError(400, "Only upgrades that haven't started can be cancelled.")
            d = db.one("SELECT name FROM devices WHERE id=?", (j["device_id"],))
            db.event(j["device_id"], j["org_id"], "upgrade cancelled", f"by {s['email']}")
            db.audit(s["email"], "upgrade cancelled", d["name"] if d else j["device_id"], self.client_ip(), org_id=j["org_id"])
            return self.json({"ok": True})
        if path == "/api/upgrades/check":   # ask the selected routers (or all online ones) for their newest version now
            s = self.require(tech=True, write=True)
            ids = [int(x) for x in (self.body().get("device_ids") or []) if str(x).isdigit()]
            rows = [self.device_for(s, i) for i in ids] if ids else db.q("SELECT * FROM devices WHERE state='adopted' AND online=1")
            if len(rows) > 3:   # many routers: check in the background; the page refreshes to show results
                def check_all(rows=rows):
                    for d in rows[:500]:
                        try:
                            upgrades.check(d)
                        except RouterError:
                            pass
                threading.Thread(target=check_all, daemon=True, name="update-check").start()
                return self.json({"ok": True, "background": True, "count": len(rows)})
            out = []
            for d in rows[:200]:
                try:
                    i = upgrades.check(d)
                    out.append({"id": d["id"], "ok": True, "latest": i["latest"]})
                except RouterError as e:
                    out.append({"id": d["id"], "ok": False, "error": str(e)})
            return self.json({"ok": True, "results": out})
        if m := re.fullmatch(r"/api/devices/(\d+)/delete", path):
            s = self.require(tech=True, write=True)
            d = self.device_for(s, m.group(1))
            if d["wg_pubkey"]:
                wg.remove_peer(d["wg_pubkey"])
            db.run("DELETE FROM devices WHERE id=?", (d["id"],))
            db.audit(s["email"], "router removed", d["name"], self.client_ip(), org_id=d["org_id"])
            return self.json({"ok": True})
        if path == "/api/admin/branding":
            s = self.require(tech=True, admin=True)
            try:
                saved = brand.save(self.body())
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "branding changed", ip=self.client_ip())
            return self.json({"ok": True, **saved})
        if path == "/api/admin/branding/logo":
            s = self.require(tech=True, admin=True)
            try:
                saved = brand.set_logo(str(self.body().get("data") or ""))
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "logo changed" if saved["logo_url"] else "logo removed", ip=self.client_ip())
            return self.json({"ok": True, **saved})
        if path == "/api/admin/alerts/settings":
            s = self.require(tech=True, admin=True)
            try:
                saved = alerts.save(self.body())
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "alert settings changed", ip=self.client_ip())
            return self.json({"ok": True, "settings": saved, "teams_ready": integ.configured("teams")})
        if path == "/api/admin/alerts/test":
            s = self.require(tech=True, admin=True)
            try:
                msg = alerts.test(str(self.body().get("channel") or ""))
            except (ValueError, IntegrationError) as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "test alert sent", ip=self.client_ip(), detail=msg)
            return self.json({"ok": True, "detail": msg})
        if path == "/api/admin/offsite":
            s = self.require(tech=True, admin=True)
            try:
                offsite.save(self.body())
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "off-site backup settings changed", offsite.where(), self.client_ip())
            return self.json({"ok": True, **offsite.public()})
        if path == "/api/admin/wgport":   # move WireGuard to another UDP port
            s = self.require(tech=True, admin=True)
            old = wgport.port
            try:
                wgport.start(int(str(self.body().get("port") or "0").strip() or 0))
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "WireGuard port move started", f"UDP {old} -> {wgport.port}", self.client_ip())
            return self.json({"ok": True, **wgport.info()})
        if path == "/api/admin/wgport/close":   # finish a move: stop relaying the old port and close it
            s = self.require(tech=True, admin=True)
            try:
                old, left = wgport.old, wgport.close_old()
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "old WireGuard port closed", f"UDP {old}", self.client_ip(),
                     detail=f"{left} router(s) hadn't moved yet" if left else "every router had moved")
            return self.json({"ok": True, "left": left, **wgport.info()})
        if path == "/api/admin/offsite/test":
            s = self.require(tech=True, admin=True)
            try:
                return self.json({"ok": True, "detail": offsite.test()})
            except OffsiteError as e:
                return self.json({"ok": False, "detail": str(e)})
        if path == "/api/admin/offsite/run":   # back up now (in the background)
            s = self.require(tech=True, admin=True)
            if offsite.running:
                raise HttpError(400, "An off-site backup is already running.")
            threading.Thread(target=offsite.run, args=("manual",), daemon=True, name="offsite-now").start()
            db.audit(s["email"], "off-site backup started", offsite.where(), self.client_ip())
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/devices/(\d+)/winbox/(open|fix|enable)", path):
            # opening: any technician - the session's router login is read-only for read-only technicians; fixing the
            # router's Winbox service changes the router, so that needs write access
            # client admins may open (where turned on for their organization) but never change the router's Winbox service
            s = self.require(tech=m.group(2) != "open", write=m.group(2) != "open")
            d = self.device_for(s, m.group(1))
            s, group = self.require_winbox(d, s)
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router must be online.")
            cl = poller.client(d)
            try:
                if m.group(2) in ("fix", "enable"):   # let TikManager's tunnel address reach Winbox (and turn it on, restricted to that address)
                    svc = cl.winbox_allow(settings.wg_server_ip, enable=m.group(2) == "enable")
                    db.audit(s["email"], "router Winbox service changed for TikManager", d["name"], self.client_ip(), org_id=d["org_id"],
                             detail=f"available from: {svc['address'] or 'anywhere'}, {'off' if svc['disabled'] else 'on'}")
                    return self.json({"ok": True, "service": svc})
                svc = cl.winbox_service()
            except RouterError as e:
                raise HttpError(502, f"The router didn't answer: {e}") from None
            if svc["disabled"]:
                raise HttpError(400, "Winbox is turned off on this router - turn it on for TikManager first.")
            if not winbox_allows_tikmanager(svc["address"]):
                raise HttpError(400, "This router's Winbox only accepts certain addresses - allow TikManager's tunnel address first.")
            allow = str(self.body().get("allow_ip") or self.client_ip()).strip()
            try:
                return self.json({"ok": True, "session": winbox.open(d, s["email"], allow, svc["port"], group),
                                  "host": urllib.parse.urlparse(settings.public_url).hostname})
            except ValueError as e:
                raise HttpError(400, str(e)) from None
        if m := re.fullmatch(r"/api/winbox/(\d+)/(extend|close)", path):
            s = self.require()   # a client admin can only extend / close their own sessions (winbox checks the owner)
            if s["kind"] == "client" and self.client_access(s)[0] == "off":
                raise HttpError(403, "Winbox isn't turned on for your organization.")
            try:
                if m.group(2) == "extend":
                    return self.json({"ok": True, "session": winbox.extend(int(m.group(1)), s["email"], s["kind"] == "tech" and s["role"] == "admin")})
                winbox.close(int(m.group(1)), s["email"], s["kind"] == "tech" and s["role"] == "admin", why=f"closed by {s['email']}")
                return self.json({"ok": True})
            except ValueError as e:
                raise HttpError(400, str(e)) from None
        if path == "/api/admin/reachability-test":   # connectivity test from the internet (runs ~20 s in the background)
            s = self.require(tech=True, admin=True)
            try:
                reach.start()
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "connectivity test started", observatory.host, self.client_ip())
            return self.json({"ok": True, "reachability": reach.info()})
        if path == "/api/admin/observatory-scan":   # Mozilla Observatory scan of the public URL, now
            s = self.require(tech=True, admin=True)
            try:
                res = observatory.scan()
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "Mozilla Observatory scan", observatory.host, self.client_ip(), detail=res.get("grade") or res.get("error") or "")
            return self.json({**updates.info(), "observatory": observatory.info()})
        if path == "/api/admin/security-check":   # ask the root helper to run the read-only server check now
            s = self.require(tech=True, admin=True)
            try:
                updates.request_security()
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "server security check requested", ip=self.client_ip())
            return self.json({**updates.info(), "observatory": observatory.info()})
        if path == "/api/admin/update-check":
            self.require(tech=True, admin=True)
            updates.check()
            return self.json(updates.info())
        if path == "/api/admin/update-channel":   # stable (default) or beta - which releases this installation is offered
            s = self.require(tech=True, admin=True)
            ch = str(self.body().get("channel") or "")
            try:
                updates.set_channel(ch)
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "update channel changed", ch, self.client_ip())
            updates.check()
            return self.json(updates.info())
        if path == "/api/admin/upgrade":   # hand the upgrade to the root updater (tikmanager-update.path)
            s = self.require(tech=True, admin=True)
            version = str(self.body().get("version") or "").strip()
            try:
                updates.request(version)
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "upgrade requested", f"{__version__} -> {version}", self.client_ip())
            return self.json({"ok": True, **updates.info()})
        if path == "/api/admin/settings":   # Admin > Settings: staff sign-in, Microsoft sign-in, router settings
            s = self.require(tech=True, admin=True)
            b = self.body()
            try:
                saved = sysconf.save(b)
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            changed = sorted(k for k in b if k in ("tech_domains", "tech_admins", "entra_tenant_id", "entra_client_id", "wg_endpoint", "ping_target"))
            if b.get("entra_client_secret") or b.get("clear_entra_secret"):
                changed.append("entra_client_secret")
            db.audit(s["email"], "settings changed", ip=self.client_ip(), detail=", ".join(changed))   # names only, never values
            return self.json({"ok": True, **saved})
        if path in ("/api/logs/rules", "/api/logs/rules/delete", "/api/logs/rules/test"):
            s = self.require(tech=True, admin=not path.endswith("/test"))
            b = self.body()
            devs = db.q("SELECT id, name, org_id, tags FROM devices WHERE state='adopted'")
            try:
                if path.endswith("/test"):
                    return self.json(routerlogs.test(b, devs))
                if path.endswith("/delete"):
                    routerlogs.delete_rule(str(b.get("id") or ""))
                    db.audit(s["email"], "log alert rule deleted", str(b.get("id") or ""), self.client_ip())
                    return self.json({"ok": True})
                r = routerlogs.save_rule(b)
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "log alert rule saved", r["name"], self.client_ip(), detail=r["pattern"])
            return self.json({"ok": True, "rule": r})
        if path in ("/api/admin/webhooks", "/api/admin/webhooks/delete"):
            s = self.require(tech=True, admin=True)
            b = self.body()
            from alerts import KINDS as ALERT_KINDS
            try:
                if path.endswith("/delete"):
                    alerts.webhooks.delete(str(b.get("id") or ""))
                    db.audit(s["email"], "webhook deleted", str(b.get("id") or ""), self.client_ip())
                    return self.json({"ok": True})
                h = alerts.webhooks.save(b, ALERT_KINDS)
            except WebhookError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "webhook saved", h["name"], self.client_ip(), detail=h["format"])
            return self.json({"ok": True, "id": h["id"]})
        if path == "/api/security/autoblock/settings":
            s = self.require(tech=True, admin=True)
            try:
                cfg = autoblock.save(self.body())
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "auto-block settings", cfg["mode"], self.client_ip(), json.dumps(cfg))
            return self.json(cfg)
        if path in ("/api/security/autoblock/block", "/api/security/autoblock/release"):
            s = self.require(tech=True, write=True)
            ip = str(self.body().get("ip") or "").strip()[:64]
            try:
                if path.endswith("/block"):
                    autoblock.block(ip, s["email"], reason="blocked by hand")
                    threading.Thread(target=autoblock.push, daemon=True, name="autoblock-push").start()
                    return self.json({"ok": True})
                return self.json({"ok": True, "failed": autoblock.release(ip, s["email"])})
            except ValueError as e:
                raise HttpError(400, str(e)) from None
        if path == "/api/security/autoblock/rule":   # add the raw drop rule for the block list to one router
            s = self.require(tech=True, write=True)
            d = self.device_for(s, str(self.body().get("device_id") or "0"))
            if d["state"] != "adopted" or not d["online"]:
                raise HttpError(400, "The router is offline.")
            try:
                autoblock.add_rule(d, s["email"])
            except RouterError as e:
                raise HttpError(502, str(e)) from None
            return self.json({"ok": True})
        if path == "/api/admin/lifecycle":   # set / clear the standard replacement for a router model
            s = self.require(tech=True, admin=True)
            b = self.body()
            try:
                lifecycle.set_override(str(b.get("model") or "")[:80], str(b.get("product") or "")[:200])
            except ValueError as e:
                raise HttpError(400, str(e)) from None
            db.audit(s["email"], "replacement suggestion " + ("set" if b.get("product") else "cleared"), str(b.get("model") or "")[:80],
                     self.client_ip(), str(b.get("product") or "")[:200])
            return self.json({"ok": True})
        if path == "/api/admin/system":
            s = self.require(tech=True, admin=True)
            b = self.body()
            try:
                hour, keep = int(b.get("backup_hour")), int(b.get("backup_keep_versions"))
            except (TypeError, ValueError):
                raise HttpError(400, "Enter whole numbers.") from None
            if not 0 <= hour <= 23 or not 1 <= keep <= 100:
                raise HttpError(400, "Backup hour must be 0-23 and versions to keep 1-100.")
            db.set_setting("backup_hour", hour)
            db.set_setting("backup_keep_versions", keep)
            if "backup_mirror" in b:
                db.set_setting("backup_mirror", "1" if b.get("backup_mirror") else "0")
            backups.prune()
            db.audit(s["email"], "system settings changed", ip=self.client_ip(), detail=f"backup hour {hour}, keep {keep} versions")
            return self.json({"ok": True})
        if m := re.fullmatch(r"/api/users/(\d+)/role", path):
            s = self.require(tech=True, admin=True)
            u = db.one("SELECT * FROM users WHERE id=?", (int(m.group(1)),))
            role = str(self.body().get("role") or "")
            if not u:
                raise HttpError(404, "User not found.")
            allowed = TECH_ROLES if u["kind"] == "tech" else CLIENT_ROLES
            if role not in allowed:
                raise HttpError(400, f"Role must be one of: {', '.join(allowed)}.")
            if u["email"] == s["email"] and role != "admin":
                raise HttpError(400, "You can't remove your own admin role.")
            db.run("UPDATE users SET role=? WHERE id=?", (role, u["id"]))
            db.audit(s["email"], "role changed", u["email"], self.client_ip(), org_id=u["org_id"], detail=role)
            return self.json({"ok": True})
        if path == "/api/users/invite":
            return self.invite()
        if m := re.fullmatch(r"/api/users/(\d+)/(disable|enable|reset-mfa|resend)", path):
            return self.user_action(int(m.group(1)), m.group(2))
        raise HttpError(404, "Not found.")

    # --- sign-in ------------------------------------------------------------------------------------------
    def entra_callback(self, q):
        try:
            who, ret = entra.complete(q, read_cookie(self.headers.get("Cookie"), STATE_COOKIE))
        except AuthError as e:
            db.audit("", "sign-in failed (Microsoft)", ip=self.client_ip(), detail=str(e))
            secev.record("tikmanager", "login_failed", "", self.client_ip(), "microsoft", str(e)[:200])
            # the message can carry text from the callback URL (error_description) - always escaped
            return self.send(403, f"<!doctype html><title>TikManager</title><p>{html.escape(str(e))}</p><p><a href='/login'>Back</a></p>".encode(),
                             "text/html; charset=utf-8")
        email = who["email"]
        admins = {x.strip().lower() for x in settings.tech_admins.split(",") if x.strip()}
        domains = {x.strip().lower().lstrip("@") for x in settings.tech_domains.split(",") if x.strip()}
        # the account is tied to Microsoft's permanent user ID: if an email address is later renamed or reused, the new
        # holder doesn't inherit the old technician account
        user = db.one("SELECT * FROM users WHERE entra_oid=?", (who["oid"],)) or db.one("SELECT * FROM users WHERE email=?", (email,))
        if user and user["kind"] != "tech":
            raise HttpError(403, "That address belongs to a client account - sign in with your password instead.")
        if user and user["entra_oid"] and user["entra_oid"] != who["oid"]:
            db.audit(email, "sign-in refused (different Microsoft account)", ip=self.client_ip())
            raise HttpError(403, f"{email} is linked to a different Microsoft account. An administrator can use "
                                 "Reset sign-in for it on Admin > Technicians.")
        if user and not user["entra_oid"]:
            db.run("UPDATE users SET entra_oid=? WHERE id=?", (who["oid"], user["id"]))
        if not user:
            if email not in admins and email.split("@")[-1] not in domains:
                db.audit(email, "sign-in refused (not a technician)", ip=self.client_ip())
                raise HttpError(403, f"{email} isn't allowed to sign in to TikManager.")
            uid = db.run("INSERT INTO users (email, name, kind, role, created_at, entra_oid) VALUES (?,?,?,?,?,?)",
                         (email, who["name"], "tech", "admin" if email in admins else "tech", now(), who["oid"]))
            user = db.one("SELECT * FROM users WHERE id=?", (uid,))
        if user["disabled"]:
            raise HttpError(403, "Your TikManager account is disabled.")
        set_cookie = self.start_session(user)
        return self.redirect(ret or "/", [("Set-Cookie", set_cookie), ("Set-Cookie", cookie(STATE_COOKIE, "", 0, settings.secure_cookies))])

    def login_password(self):
        ip = self.client_ip()
        if not login_limit.allow(ip):
            secev.record("tikmanager", "rate_limited", "", ip, "sign-in", "too many sign-in attempts from this address", throttle=True)
            raise HttpError(429, "Too many sign-in attempts - wait a few minutes.")
        b = self.body()
        email, pw = str(b.get("email") or "").strip().lower(), str(b.get("password") or "")
        u = db.one("SELECT * FROM users WHERE email=? AND password_hash IS NOT NULL", (email,))
        if u and u["locked_until"] > now():
            raise HttpError(429, "This account is locked for a few minutes after too many failed attempts.")
        ok = check_password(pw, u["password_hash"] if u else None)   # always hashes, so timing doesn't reveal which emails exist
        if not u or u["disabled"] or not ok:
            secev.record("tikmanager", "login_failed", email, ip, "password", "" if u else "no such account")
            if u:
                fails = u["failed"] + 1
                db.run("UPDATE users SET failed=?, locked_until=? WHERE id=?", (fails, now() + LOCK_SECONDS if fails >= MAX_FAILS else 0, u["id"]))
                if fails == MAX_FAILS:
                    secev.record("tikmanager", "locked", email, ip, "password", f"locked for {LOCK_SECONDS // 60} minutes after {fails} failed attempts")
            db.audit(email, "sign-in failed", ip=ip)
            raise HttpError(401, "Wrong email or password.")
        return self.json({"ticket": new_ticket(u["id"], enroll=not u["totp_enabled"]), "mfa": "verify" if u["totp_enabled"] else "enroll"})

    def login_mfa(self):
        ip = self.client_ip()
        if not login_limit.allow(ip):
            secev.record("tikmanager", "rate_limited", "", ip, "sign-in", "too many sign-in attempts from this address", throttle=True)
            raise HttpError(429, "Too many sign-in attempts - wait a few minutes.")
        b = self.body()
        with pending_lock:
            p = pending_logins.get(str(b.get("ticket") or ""))
        if not p or now() - p["created"] > 600:
            raise HttpError(401, "That sign-in expired - start again.")
        u = db.one("SELECT * FROM users WHERE id=?", (p["user_id"],))
        if not u or u["disabled"]:
            raise HttpError(401, "That sign-in expired - start again.")
        if u["locked_until"] > now():   # the lock covers the code step too, not just the password
            with pending_lock:
                pending_logins.pop(str(b.get("ticket") or ""), None)
            raise HttpError(429, "This account is locked for a few minutes after too many failed attempts.")
        if b.get("want_secret"):   # enrollment step 1: show the secret for the authenticator app
            if not p["enroll_secret"]:
                raise HttpError(400, "MFA is already set up for this account.")
            return self.json({"secret": p["enroll_secret"], "uri": totp_uri(p["enroll_secret"], u["email"])})
        secret = p["enroll_secret"] or u["totp_secret"]
        if not check_totp(secret, b.get("code")):
            fails = u["failed"] + 1
            db.run("UPDATE users SET failed=?, locked_until=? WHERE id=?", (fails, now() + LOCK_SECONDS if fails >= MAX_FAILS else 0, u["id"]))
            db.audit(u["email"], "sign-in failed (MFA code)", ip=ip)
            secev.record("tikmanager", "mfa_failed", u["email"], ip, "MFA code")
            if fails == MAX_FAILS:
                secev.record("tikmanager", "locked", u["email"], ip, "MFA code", f"locked for {LOCK_SECONDS // 60} minutes after {fails} failed attempts")
            with pending_lock:   # a few wrong codes end this sign-in: guessing means starting over with the password
                p["code_fails"] = p.get("code_fails", 0) + 1
                if p["code_fails"] >= 3:
                    pending_logins.pop(str(b.get("ticket") or ""), None)
                    raise HttpError(401, "Too many wrong codes - sign in again.")
            raise HttpError(401, "That code didn't match - check the time on your phone and try again.")
        with pending_lock:
            pending_logins.pop(str(b.get("ticket")), None)
        if p["enroll_secret"]:
            db.run("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (p["enroll_secret"], u["id"]))
            db.audit(u["email"], "MFA set up", ip=ip, org_id=u["org_id"])
        return self.json({"ok": True}, headers=[("Set-Cookie", self.start_session(u))])

    def setup_open(self, token):
        """The first-run link works only with the installer's token, and only until a technician admin exists."""
        return bool(settings.setup_token) and secrets.compare_digest(token, settings.setup_token) and not db.one(
            "SELECT 1 FROM users WHERE kind='tech' AND role='admin' AND disabled=0")

    def first_run(self):
        """Create the first admin (email + password; the authenticator app is set up at first sign-in), the company name
        and the staff email domains. Rate-limited, and dead once an admin exists."""
        ip = self.client_ip()
        if not login_limit.allow(ip):
            raise HttpError(429, "Too many attempts - wait a few minutes.")
        b = self.body()
        if not self.setup_open(str(b.get("token") or "")):
            raise HttpError(403, "This setup link isn't valid any more - sign in instead.")
        email, name = str(b.get("email") or "").strip().lower()[:200], str(b.get("name") or "").strip()[:100]
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", email, re.I):
            raise HttpError(400, "Enter a valid email address.")
        problem = password_problem(str(b.get("password") or ""))
        if problem:
            raise HttpError(400, problem)
        company = str(b.get("company") or "").strip()[:60]
        if not company:
            raise HttpError(400, "Enter your company name.")
        domains = str(b.get("domains") or email.split("@")[-1])
        try:
            sysconf.save({"tech_domains": domains, "tech_admins": email})
            brand.save({"company": company})
        except ValueError as e:
            raise HttpError(400, str(e)) from None
        existing = db.one("SELECT * FROM users WHERE email=?", (email,))
        if existing:
            db.run("UPDATE users SET kind='tech', role='admin', org_id=NULL, password_hash=?, disabled=0 WHERE id=?",
                   (hash_password(b["password"]), existing["id"]))
        else:
            db.run("INSERT INTO users (email, name, kind, role, password_hash, created_at) VALUES (?,?,'tech','admin',?,?)",
                   (email, name or email, hash_password(b["password"]), now()))
        db.audit(email, "first admin created (setup)", ip=ip, detail=f"company {company}, staff domains {domains}")
        return self.json({"ok": True})

    def login_dev(self):
        if not self.dev_login_allowed():
            raise HttpError(404, "Not found.")
        u = db.one("SELECT * FROM users WHERE email='dev@local'")
        if not u:
            uid = db.run("INSERT INTO users (email, name, kind, role, created_at) VALUES ('dev@local','Dev Admin','tech','admin',?)", (now(),))
            u = db.one("SELECT * FROM users WHERE id=?", (uid,))
        return self.json({"ok": True}, headers=[("Set-Cookie", self.start_session(u))])

    # --- users and invitations ------------------------------------------------------------------------------
    def invite(self):
        s = self.require(write=True)
        b = self.body()
        email = str(b.get("email") or "").strip().lower()[:200]
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", email, re.I):
            raise HttpError(400, "Enter a valid email address.")
        if s["kind"] == "client":
            if s["role"] != "admin":
                raise HttpError(403, "Only your organization's admins can invite people.")
            org_id, role = s["org_id"], b.get("role") if b.get("role") in CLIENT_ROLES else "viewer"
        else:
            org_id = int(b.get("org_id") or 0)
            role = b.get("role") if b.get("role") in CLIENT_ROLES else "viewer"
            if not db.one("SELECT id FROM orgs WHERE id=?", (org_id,)):
                raise HttpError(400, "Pick the client this person belongs to.")
        if db.one("SELECT id FROM users WHERE email=?", (email,)):
            raise HttpError(400, "There's already an account with that email.")
        t = token()
        db.run("INSERT INTO users (email, name, kind, role, org_id, invite_hash, invite_expires, created_at) VALUES (?,?,?,?,?,?,?,?)",
               (email, str(b.get("name") or "")[:120], "client", role, org_id, token_hash(t), now() + INVITE_TTL, now()))
        db.audit(s["email"], "user invited", email, self.client_ip(), org_id=org_id, detail=role)
        link = f"{settings.public_url}/invite/{t}"
        return self.json({"ok": True, "link": link, "expires_days": INVITE_TTL // 86400, "emailed": self.email_invite(email, link, s)})

    def email_invite(self, email, link, s):
        """Email an invitation if email is set up -> None (not set up), True (sent) or the error text."""
        if not mailer.configured():
            return None
        org = db.one("SELECT o.name FROM users u LEFT JOIN orgs o ON o.id = u.org_id WHERE u.email=?", (email,))
        company = (brand.public().get("company") or "Your IT provider")
        try:
            mailer.send(email, f"You're invited to {brand.public().get('product') or 'TikManager'}",
                        f"Hello,\n\n{s.get('name') or s['email']} invited you to see {(org or {}).get('name') or 'your'} network equipment in "
                        f"{brand.public().get('product') or 'TikManager'}, run by {company}.\n\nSet up your account (the link works for "
                        f"{INVITE_TTL // 86400} days and only once):\n{link}\n\nYou'll choose a password and set up an authenticator app.\n\n"
                        "If you weren't expecting this, you can ignore this email.")
            return True
        except MailError as e:
            return str(e)

    def user_action(self, uid, action):
        s = self.require(write=True)
        u = db.one("SELECT * FROM users WHERE id=?", (uid,))
        if not u or (s["kind"] == "client" and (s["role"] != "admin" or u["org_id"] != s["org_id"])):
            raise HttpError(404, "User not found.")
        if s["kind"] == "tech" and s["role"] != "admin" and u["kind"] == "tech":
            raise HttpError(403, "Only administrators can change technician accounts.")
        if u["email"] == s["email"] and action == "disable":
            raise HttpError(400, "You can't disable yourself.")
        extra = {}
        if action in ("disable", "enable"):
            db.run("UPDATE users SET disabled=? WHERE id=?", (1 if action == "disable" else 0, uid))
            if action == "disable":
                sessions.end_all_for(uid)
        elif action == "reset-mfa":   # technicians: also unlinks the Microsoft account (renamed / replaced account)
            db.run("UPDATE users SET totp_enabled=0, totp_secret=NULL, entra_oid=NULL WHERE id=?", (uid,))
            sessions.end_all_for(uid)
        elif action == "resend":
            if u["kind"] != "client" or u["password_hash"]:
                raise HttpError(400, "Only people who haven't accepted their invitation can be re-invited.")
            t = token()
            db.run("UPDATE users SET invite_hash=?, invite_expires=? WHERE id=?", (token_hash(t), now() + INVITE_TTL, uid))
            extra["link"] = f"{settings.public_url}/invite/{t}"
            extra["emailed"] = self.email_invite(u["email"], extra["link"], s)
        db.audit(s["email"], f"user {action}", u["email"], self.client_ip(), org_id=u["org_id"])
        return self.json({"ok": True, **extra})

    def invite_user(self, t):
        u = db.one("SELECT * FROM users WHERE invite_hash=?", (token_hash(t),)) if t else None
        if not u or (u["invite_expires"] or 0) < now():
            raise HttpError(404, "This invitation link is invalid or has expired - ask for a new one.")
        return u

    def accept_invite(self):
        if not login_limit.allow(self.client_ip()):
            raise HttpError(429, "Too many attempts - wait a few minutes.")
        b = self.body()
        u = self.invite_user(str(b.get("token") or ""))
        pw = str(b.get("password") or "")
        if problem := password_problem(pw):
            raise HttpError(400, problem)
        db.run("UPDATE users SET password_hash=?, invite_hash=NULL, invite_expires=NULL, name=COALESCE(NULLIF(?, ''), name) WHERE id=?",
               (hash_password(pw), str(b.get("name") or "")[:120], u["id"]))
        db.audit(u["email"], "invitation accepted", ip=self.client_ip(), org_id=u["org_id"])
        return self.json({"ticket": new_ticket(u["id"], enroll=True), "mfa": "enroll"})

    # --- adoption ---------------------------------------------------------------------------------------------
    def enroll_token(self):
        """The one adoption token for all routers, derived from the master key (nothing to store or leak from the
        database); replacing the command bumps its version so old copies stop working."""
        return derive(KEY, f"enroll:{db.setting('enroll_version', '1')}", 40)

    def check_enroll(self, t):
        if not adopt_limit.allow(self.client_ip()):
            secev.record("tikmanager", "rate_limited", "", self.client_ip(), "adoption", "too many adoption requests from this address", throttle=True)
            raise HttpError(429, "Too many requests.")
        if not secrets.compare_digest(t, self.enroll_token()):
            secev.record("tikmanager", "adoption_rejected", "", self.client_ip(), "adoption", "an old or wrong adoption command was used", throttle=True)
            raise HttpError(404, "This adoption command is no longer valid - copy the current one from TikManager.")

    def controller_settings(self):
        if settings.wg_server_pubkey:
            return settings
        if settings.dev:
            return dataclasses.replace(settings, wg_server_pubkey=base64.b64encode(b"dev-controller-key-0123456789abc").decode())
        raise HttpError(503, "The controller's WireGuard key isn't configured (WG_SERVER_PUBKEY).")

    def adopt_script(self, t):
        self.check_enroll(t)
        self.controller_settings()
        self.send(200, adoption.stage1(settings, t).encode(), "text/plain; charset=utf-8")

    def register_router(self, pubkey, identity, model, serial, version, api_port=None):
        """Create or update the router's record; returns it. A known key keeps its record (re-running the command);
        anything new waits for a tech to approve it."""
        d = db.one("SELECT * FROM devices WHERE wg_pubkey=?", (pubkey,))
        ip = self.client_ip()
        if d:
            db.run("UPDATE devices SET identity=COALESCE(NULLIF(?, ''), identity), model=COALESCE(NULLIF(?, ''), model), serial=COALESCE(NULLIF(?, ''), serial), "
                   "version=COALESCE(NULLIF(?, ''), version), public_ip=?, api_port=COALESCE(?, api_port), "
                   "name=CASE WHEN name_custom=0 AND ?<>'' THEN ? ELSE name END WHERE id=?",
                   (identity, model, serial, version, ip, api_port, identity, identity, d["id"]))
            db.event(d["id"], d["org_id"], "re-registered", f"from {ip}")
            return db.one("SELECT * FROM devices WHERE id=?", (d["id"],))
        if db.one("SELECT COUNT(*) AS n FROM devices WHERE state='pending'")["n"] >= 500:
            raise HttpError(429, "Too many routers are waiting for approval.")
        used = {r["tunnel_ip"] for r in db.q("SELECT tunnel_ip FROM devices WHERE tunnel_ip IS NOT NULL")}
        did = db.run("""INSERT INTO devices (org_id, name, name_custom, identity, model, serial, version, wg_pubkey, tunnel_ip, state,
                        public_ip, first_seen, created_at, created_by, api_port) VALUES (NULL,?,0,?,?,?,?,?,?,'pending',?,?,?,'router',?)""",
                     (identity or serial or "New router", identity, model, serial, version, pubkey, wg.next_ip(used), ip, now(), now(), api_port))
        db.event(did, None, "registered", f"{model} {serial} from {ip}".strip())
        db.audit("router", "router registered (waiting for approval)", identity or serial, ip)
        return db.one("SELECT * FROM devices WHERE id=?", (did,))

    def adopt_register(self, t):
        self.check_enroll(t)
        cs = self.controller_settings()
        b = self.body()
        pubkey = str(b.get("pubkey") or "").replace(" ", "+")   # '+' arrives as a space in form encoding
        if not valid_key(pubkey):
            raise HttpError(400, "Missing or invalid WireGuard public key.")
        clean = lambda k, n: re.sub(r"[^\w .()+-]", "", str(b.get(k) or ""))[:n].strip()
        www = str(b.get("www") or "")
        d = self.register_router(pubkey, clean("identity", 80), clean("model", 60), clean("serial", 40), clean("version", 40),
                                 int(www) if www.isdigit() and 0 < int(www) < 65536 else None)
        port = cs.wg_endpoint.rpartition(":")[2]
        if port.isdigit():   # the port this router will dial (for moving it later: wgport.py)
            db.run("UPDATE devices SET wg_port=? WHERE id=?", (int(port), d["id"]))
        self.send(200, adoption.stage2(cs, d, derive(KEY, f"router-api:{d['id']}")).encode(), "text/plain; charset=utf-8")


def main():
    wg.sync([(d["wg_pubkey"], d["tunnel_ip"]) for d in db.q("SELECT wg_pubkey, tunnel_ip FROM devices WHERE state='adopted' AND wg_pubkey IS NOT NULL")])
    poller.start()
    backups.start()
    upgrades.start()
    tasks.start()
    updates.start()
    integ.start(settings.public_url)
    if settings.managed_vpn:   # off: no background checks of managed VPNs either (nothing touches those routers)
        vpns.start()
    secev.start()
    routerlogs.start()
    observatory.start()
    reach.start_loop()
    offsite.start()
    wgport.start_loop()
    alerts.start()
    unifi.start()
    lifecycle.start()
    rossec.start()
    autoblock.start()
    if settings.dev:
        secev.seed_dev()
        routerlogs.seed_dev(db.q("SELECT id FROM devices WHERE state='adopted'"))
    srv = ThreadingHTTPServer((settings.host, settings.port), Handler)
    srv.daemon_threads = True
    print(f"TikManager on http://{settings.host}:{settings.port} (public URL {settings.public_url})" + ("  [DEV MODE: simulated routers]" if settings.dev else ""))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
