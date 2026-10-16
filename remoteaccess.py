"""Remote access: WireGuard for Windows (and any WireGuard app) into a client's router - an SSTP replacement, per router.

Router page > Remote access (technicians). Set up once per router: a UDP port, an address range for the people
connecting (picked so it doesn't overlap the router's own networks), the address they connect to (the router's public
IP, or a DNS name), and what goes through the tunnel - the office networks only (split tunnel) or everything.
TikManager backs the router up, then adds - all tagged RA_TAG so it can be removed exactly - a WireGuard interface,
the gateway address, and firewall rules: the UDP port open, people let through to the networks, ping and DNS to the
router allowed.

Each person: a key pair is generated here, only their peer is added on the router (nobody else drops), and their
WireGuard config can be downloaded ONCE - the private key is kept encrypted only until then (or 7 days) and deleted.
Revoke removes that one peer. Status (last handshake, traffic) is read live when the tab is opened.
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import threading
import time

from routeros import RouterError, RA_IFACE, RA_TAG as RA_TAG_LABEL

DEFAULT_PORT = 13251
POOL_SPACE = ipaddress.ip_network("10.250.0.0/16")   # each router's range: a /24 from here that it doesn't already use
KEEP_CONFIG = 7 * 86400
REMIND = 3 * 86400   # reminder event this long before an expiry
SERVICES = {   # what a person may reach on a server: service -> (protocol, ports)
    "smb": ("tcp", "445"), "http": ("tcp", "80"), "https": ("tcp", "443"), "rdp": ("tcp", "3389"), "ssh": ("tcp", "22"),
    "ping": ("icmp", ""), "any": ("", ""),
}
SERVICE_NAMES = {"smb": "SMB file shares", "http": "HTTP", "https": "HTTPS", "rdp": "Remote Desktop", "ssh": "SSH", "ping": "Ping",
                 "any": "Everything on it", "custom": "Custom port"}


def clean_access(raw):
    """None (everything the setup allows) or [{host, service, proto, ports}] - validated."""
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw:
        raise RaError("Add at least one server, or allow everything.")
    out = []
    for e in raw[:50]:
        host = str((e or {}).get("host") or "").strip()
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            raise RaError(f"Not an IP address or network: {host or '(empty)'}") from None
        if net.version != 4:
            raise RaError("Remote access rules are IPv4.")
        svc = str(e.get("service") or "any")
        if svc == "custom":
            proto = str(e.get("proto") or "tcp").lower()
            if proto not in ("tcp", "udp"):
                raise RaError("A custom port is TCP or UDP.")
            ports = str(e.get("ports") or "").replace(" ", "")
            if not ports or not all(p.isdigit() and 1 <= int(p) <= 65535 for part in ports.split(",") for p in part.split("-")):
                raise RaError(f"Ports for {host}: numbers or ranges like 8080 or 5000-5010.")
        elif svc in SERVICES:
            proto, ports = SERVICES[svc]
        else:
            raise RaError(f"Unknown service: {svc}")
        out.append({"host": str(net) if net.prefixlen < 32 else str(net.network_address), "service": svc, "proto": proto, "ports": ports})
    return out


def access_text(acc):
    if acc is None:
        return "Everything"
    return "; ".join(f"{e['host']} {SERVICE_NAMES.get(e['service'], e['service'])}"
                     + (f" ({e['proto'].upper()} {e['ports']})" if e["service"] == "custom" else "") for e in acc)


def parse_day(v):
    """'2026-12-31' -> the end of that day (server time) as a timestamp; '' / None -> None."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):   # the browser's own end of day (its time zone)
        ts = float(v)
    else:
        v = str(v or "").strip()
        if not v:
            return None
        try:
            day = datetime.date.fromisoformat(v)
        except ValueError:
            raise RaError("Give the expiry as a date (YYYY-MM-DD).") from None
        ts = datetime.datetime.combine(day, datetime.time(23, 59, 59)).timestamp()
    if ts < time.time():
        raise RaError("The expiry date is in the past.")
    return ts


class RaError(ValueError):
    pass


# --- WireGuard keys (X25519) ------------------------------------------------------------------------------------------
def keypair():
    """(private, public) base64 - python3-cryptography (installed by the installer); a pure-Python RFC 7748 fallback for dev."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        k = X25519PrivateKey.generate()
        raw = lambda key, kind: getattr(key, f"{kind}_bytes")(serialization.Encoding.Raw,
                                                              *((serialization.PrivateFormat.Raw, serialization.NoEncryption()) if kind == "private"
                                                                else (serialization.PublicFormat.Raw,)))
        return base64.b64encode(raw(k, "private")).decode(), base64.b64encode(raw(k.public_key(), "public")).decode()
    except ImportError:
        priv = bytearray(secrets.token_bytes(32))
        priv[0] &= 248
        priv[31] = (priv[31] & 127) | 64
        return base64.b64encode(bytes(priv)).decode(), base64.b64encode(_x25519_base(bytes(priv))).decode()


def _x25519_base(k):
    """Curve25519 scalar multiplication by the base point (RFC 7748 Montgomery ladder)."""
    p, a24 = 2 ** 255 - 19, 121665
    n = int.from_bytes(k, "little")
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in range(254, -1, -1):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + a24 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


class RemoteAccess:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.vault = backups.vault
        self.lock = threading.Lock()

    # --- reading ----------------------------------------------------------------------------------------------------
    def device(self, device_id):
        return self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))

    def networks(self, d):
        """The router's own networks (from the last poll): [{name, network}]."""
        try:
            nets = json.loads(d.get("networks") or "[]")
        except ValueError:
            nets = []
        return [{"name": n.get("name") or n.get("interface") or "", "network": n["network"]} for n in nets
                if n.get("network") and not str(n.get("interface") or "").startswith("tikmanager")]

    def suggest(self, d):
        """Defaults for a new setup: a free /24, the router's public address, its networks."""
        used = [ipaddress.ip_network(n["network"], strict=False) for n in self.networks(d)]
        taken = {r["pool"] for r in self.db.q("SELECT pool FROM ra_servers")}
        pool = next((str(s) for s in POOL_SPACE.subnets(new_prefix=24)
                     if str(s) not in taken and not any(s.overlaps(u) for u in used)), "10.250.0.0/24")
        return {"port": DEFAULT_PORT, "pool": pool, "endpoint": d.get("public_ip") or d.get("wan_ip") or "", "split": True,
                "routes": [n["network"] for n in self.networks(d)], "dns": ""}

    def cloud(self, d):
        """The router's IP Cloud DNS name (read live; None if it can't be read)."""
        if not d["online"]:
            return None
        try:
            return self.client_for(d).cloud()
        except RouterError:
            return None

    def use_cloud(self, device_id, user):
        """Turn on the router's IP Cloud DNS if needed and make its name the address people connect to.
        Returns {"cloud", "stale": people whose configs still hold the old address}."""
        d = self.device(device_id)
        if not d["online"]:
            raise RaError("The router is offline - try again when it's back.")
        try:
            cl = self.client_for(d)
            c = cl.cloud()
            if not c["name"]:
                c = cl.cloud_enable()
                self.db.event(device_id, d["org_id"], "remote access", f"IP Cloud DNS turned on by {user}")
        except RouterError as e:
            raise RaError(f"The router didn't take it: {e}") from None
        if not c["name"]:
            raise RaError("Cloud DNS is on, but the router hasn't got its name yet (it needs to reach MikroTik's cloud) - try again in a minute.")
        stale = 0
        srv = self.db.one("SELECT * FROM ra_servers WHERE device_id=?", (device_id,))
        if srv and srv["endpoint"] != c["name"]:
            stale = self.db.one("SELECT COUNT(*) AS n FROM ra_users WHERE device_id=? AND (downloaded_at IS NOT NULL OR cfg_blob IS NULL)",
                                (device_id,))["n"]
            # configs not downloaded yet are rebuilt with the new address below; downloaded ones keep the old one
            self.db.run("UPDATE ra_servers SET endpoint=? WHERE device_id=?", (c["name"], device_id))
            self.db.audit(user, "remote access address changed", d["name"], org_id=d["org_id"], detail=f"{srv['endpoint']} -> {c['name']}")
            self._rebuild_pending(device_id)
        return {"cloud": c, "stale": stale}

    def _rebuild_pending(self, device_id):
        """Configs nobody has downloaded yet: rewrite them with the current address (the key stays the same)."""
        srv = self.db.one("SELECT * FROM ra_servers WHERE device_id=?", (device_id,))
        for u in self.db.q("SELECT * FROM ra_users WHERE device_id=? AND cfg_blob IS NOT NULL AND downloaded_at IS NULL", (device_id,)):
            conf = self.vault.open(u["cfg_blob"], u["cfg_alg"], f"ra:{u['id']}").decode()
            conf = "\n".join(f"Endpoint = {srv['endpoint']}:{srv['port']}" if ln.startswith("Endpoint = ") else ln for ln in conf.split("\n"))
            blob, alg = self.vault.seal(conf.encode(), f"ra:{u['id']}")
            self.db.run("UPDATE ra_users SET cfg_blob=?, cfg_alg=? WHERE id=?", (blob, alg, u["id"]))

    def info(self, device_id, live=False):
        d = self.device(device_id)
        srv = self.db.one("SELECT * FROM ra_servers WHERE device_id=?", (device_id,))
        users = self.db.q("SELECT id, name, ip, pubkey, created_by, created_at, cfg_expires, downloaded_at, state, last_error, disabled, expires_at, access FROM ra_users "
                          "WHERE device_id=? ORDER BY name COLLATE NOCASE", (device_id,))
        live_err = None
        if srv and live and d["online"] and srv["state"] == "applied":
            try:
                peers = {p["public_key"]: p for p in self.client_for(d).wg_peers(RA_IFACE)}
                for u in users:
                    p = peers.get(u["pubkey"]) or {}
                    u.update(handshake_age=p.get("handshake_age"), rx=p.get("rx"), tx=p.get("tx"), on_router=bool(p))
            except RouterError as e:
                live_err = str(e)
        for u in users:
            u["access"] = json.loads(u["access"]) if u.get("access") else None
            u["access_text"] = access_text(u["access"])
            u["download"] = bool(u["cfg_expires"] and u["cfg_expires"] > time.time() and not u["downloaded_at"])
            u.pop("pubkey", None)
        if srv:
            srv = {**srv, "routes": json.loads(srv["routes"] or "[]")}
        cloud = self.cloud(d) if live else None
        sug = self.suggest(d)
        if cloud and cloud.get("name"):
            sug["endpoint"] = cloud["name"]   # a permanent name beats an IP that the ISP may change
        return {"server": srv, "users": users, "suggest": sug, "networks": self.networks(d), "online": bool(d["online"]),
                "live_error": live_err, "cloud": cloud, "services": SERVICE_NAMES}

    def _rules(self, device_id):
        """The router's forward rules for remote access, from each person's access."""
        srv = self.db.one("SELECT * FROM ra_servers WHERE device_id=?", (device_id,))
        reach = json.loads(srv["routes"] or "[]") if srv and srv["split"] else []
        rules = []
        for u in self.db.q("SELECT name, ip, access FROM ra_users WHERE device_id=? ORDER BY id", (device_id,)):
            label = f"{RA_TAG_LABEL}: {u['name']}"[:200]
            acc = json.loads(u["access"]) if u["access"] else None
            if acc is None:   # everything the setup allows: its networks (split tunnel) or anywhere (all traffic)
                rules += [{"comment": label, "src-address": u["ip"], "dst-address": n} for n in reach] or [{"comment": label, "src-address": u["ip"]}]
                continue
            for e in acc:
                r = {"comment": label, "src-address": u["ip"], "dst-address": e["host"]}
                if e["proto"]:
                    r["protocol"] = e["proto"]
                if e["ports"]:
                    r["dst-port"] = e["ports"]
                rules.append(r)
        return rules

    def sync_rules(self, device_id):
        d = self.device(device_id)
        try:
            self.client_for(d).ra_access(RA_IFACE, self._rules(device_id))
        except RouterError as e:
            raise RaError(f"The router didn't take the access rules: {e}") from None

    def set_access(self, device_id, uid, raw, user):
        d = self.device(device_id)
        u = self.db.one("SELECT * FROM ra_users WHERE id=? AND device_id=?", (uid, device_id))
        if not u:
            raise RaError("No such user.")
        if not d["online"]:
            raise RaError("The router is offline - try again when it's back.")
        acc = clean_access(raw)
        old = u["access"]
        self.db.run("UPDATE ra_users SET access=? WHERE id=?", (json.dumps(acc) if acc is not None else None, uid))
        try:
            self.sync_rules(device_id)
        except RaError:
            self.db.run("UPDATE ra_users SET access=? WHERE id=?", (old, uid))
            raise
        self.db.event(device_id, d["org_id"], "remote access", f"user \"{u['name']}\" may now reach: {access_text(acc)} (set by {user})")
        self.db.audit(user, "remote access user access changed", d["name"], org_id=d["org_id"], detail=f"{u['name']}: {access_text(acc)}")

    # --- setting up -------------------------------------------------------------------------------------------------
    def _validate(self, d, b):
        try:
            port = int(b.get("port") or DEFAULT_PORT)
        except (TypeError, ValueError):
            raise RaError("The port is a number.") from None
        if not 1024 <= port <= 65535:
            raise RaError("Pick a UDP port between 1024 and 65535.")
        try:
            pool = ipaddress.ip_network(str(b.get("pool") or "").strip(), strict=True)
        except ValueError:
            raise RaError("The address range is a network like 10.250.3.0/24.") from None
        if pool.version != 4 or not pool.is_private or not 24 <= pool.prefixlen <= 28:
            raise RaError("The address range must be a private IPv4 network from /24 to /28.")
        for n in self.networks(d):
            if pool.overlaps(ipaddress.ip_network(n["network"], strict=False)):
                raise RaError(f"The address range overlaps the router's network {n['network']} ({n['name']}).")
        endpoint = str(b.get("endpoint") or "").strip()
        if not endpoint or not all(c.isalnum() or c in ".-:" for c in endpoint) or len(endpoint) > 120:
            raise RaError("Give the address people connect to: the router's public IP or a DNS name.")
        split = bool(b.get("split", True))
        routes = []
        for r in (b.get("routes") or []) if split else []:
            try:
                routes.append(str(ipaddress.ip_network(str(r).strip(), strict=False)))
            except ValueError:
                raise RaError(f"Not a network: {r}") from None
        if split and not routes:
            raise RaError("Pick at least one network to reach, or send all traffic through the tunnel.")
        dns = str(b.get("dns") or "").strip()
        for x in [s for s in dns.replace(" ", "").split(",") if s]:
            try:
                ipaddress.ip_address(x)
            except ValueError:
                raise RaError(f"Not an IP address for DNS: {x}") from None
        return {"port": port, "pool": str(pool), "endpoint": endpoint, "split": split, "routes": routes, "dns": dns}

    def setup(self, device_id, b, user):
        """Save the settings and apply them to the router (backup first). Users are left as they are."""
        d = self.device(device_id)
        if not d or d["state"] != "adopted":
            raise RaError("Approve the router first.")
        if not d["online"]:
            raise RaError("The router is offline - nothing was changed.")
        cfg = self._validate(d, b)
        old = self.db.one("SELECT * FROM ra_servers WHERE device_id=?", (device_id,))
        if old and old["pool"] != cfg["pool"] and self.db.one("SELECT 1 FROM ra_users WHERE device_id=?", (device_id,)):
            raise RaError("Remove the users before changing the address range (their addresses are in it).")
        with self.lock:
            bk = self.backups.run(device_id, "pre-remote-access", user)
            if not bk.get("ok"):
                raise RaError(f"Stopped before changing anything: the backup failed ({bk.get('detail')}).")
            now = time.time()
            if old:
                self.db.run("UPDATE ra_servers SET port=?, pool=?, endpoint=?, split=?, routes=?, dns=?, state='applying', last_error=NULL WHERE device_id=?",
                            (cfg["port"], cfg["pool"], cfg["endpoint"], int(cfg["split"]), json.dumps(cfg["routes"]), cfg["dns"], device_id))
            else:
                self.db.run("INSERT INTO ra_servers (device_id, port, pool, endpoint, split, routes, dns, state, created_by, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, 'applying', ?, ?)",
                            (device_id, cfg["port"], cfg["pool"], cfg["endpoint"], int(cfg["split"]), json.dumps(cfg["routes"]), cfg["dns"], user, now))
            net = ipaddress.ip_network(cfg["pool"])
            gw = f"{next(net.hosts())}/{net.prefixlen}"
            try:
                pub = self.client_for(d).ra_setup(RA_IFACE, {"port": cfg["port"], "address": gw,
                                                              "dns_to_router": str(next(net.hosts())) in cfg["dns"]})
            except RouterError as e:
                self.db.run("UPDATE ra_servers SET state='failed', last_error=? WHERE device_id=?", (str(e)[:400], device_id))
                raise RaError(f"The router didn't take it: {e}") from None
            self.db.run("UPDATE ra_servers SET state='applied', pubkey=?, applied_at=?, last_error=NULL WHERE device_id=?", (pub, now, device_id))
            try:
                self.sync_rules(device_id)
            except RaError as e:
                self.db.run("UPDATE ra_servers SET state='failed', last_error=? WHERE device_id=?", (str(e)[:400], device_id))
                raise
        self.db.event(device_id, d["org_id"], "remote access", f"set up by {user}: UDP {cfg['port']}, {cfg['pool']}")
        self.db.audit(user, "remote access set up", d["name"], org_id=d["org_id"], detail=f"UDP {cfg['port']}, {cfg['pool']}")

    def remove(self, device_id, user):
        """Take remote access off the router (only what TikManager added) and forget its users."""
        d = self.device(device_id)
        if not self.db.one("SELECT 1 FROM ra_servers WHERE device_id=?", (device_id,)):
            raise RaError("Remote access isn't set up on this router.")
        if not d["online"]:
            raise RaError("The router is offline - nothing was changed.")
        with self.lock:
            bk = self.backups.run(device_id, "pre-remote-access", user)
            if not bk.get("ok"):
                raise RaError(f"Stopped before changing anything: the backup failed ({bk.get('detail')}).")
            try:
                self.client_for(d).ra_clear(RA_IFACE, remove_interface=True)
            except RouterError as e:
                raise RaError(f"The router didn't take it: {e}") from None
            self.db.run("DELETE FROM ra_servers WHERE device_id=?", (device_id,))   # users go with it (ON DELETE CASCADE)
        self.db.event(device_id, d["org_id"], "remote access", f"removed by {user}")
        self.db.audit(user, "remote access removed", d["name"], org_id=d["org_id"])

    # --- people -----------------------------------------------------------------------------------------------------
    def add_user(self, device_id, name, user, expires=None, access=None):
        d = self.device(device_id)
        srv = self.db.one("SELECT * FROM ra_servers WHERE device_id=?", (device_id,))
        if not srv or srv["state"] != "applied":
            raise RaError("Set up remote access on this router first.")
        name = " ".join(str(name or "").split())[:60]
        if not name:
            raise RaError("Give the person's name (e.g. Jane Smith - Laptop).")
        if self.db.one("SELECT 1 FROM ra_users WHERE device_id=? AND name=? COLLATE NOCASE", (device_id, name)):
            raise RaError("There's already a user with that name on this router.")
        if not d["online"]:
            raise RaError("The router is offline - try again when it's back.")
        expires_at = parse_day(expires)
        acc = clean_access(access)
        net = ipaddress.ip_network(srv["pool"])
        used = {r["ip"] for r in self.db.q("SELECT ip FROM ra_users WHERE device_id=?", (device_id,))}
        hosts = list(net.hosts())
        ip = next((str(h) for h in hosts[1:] if str(h) not in used), None)   # the first host is the router's end
        if not ip:
            raise RaError("The address range is full - remove someone, or set up a bigger range.")
        priv, pub = keypair()
        conf = self._config(srv, priv, ip, acc)
        token = secrets.token_urlsafe(24)
        uid = self.db.run("INSERT INTO ra_users (device_id, name, ip, pubkey, created_by, created_at, state, expires_at, access) VALUES (?, ?, ?, ?, ?, ?, 'applying', ?, ?)",
                          (device_id, name, ip, pub, user, time.time(), expires_at, json.dumps(acc) if acc is not None else None))
        blob, alg = self.vault.seal(conf.encode(), f"ra:{uid}")
        self.db.run("UPDATE ra_users SET cfg_blob=?, cfg_alg=?, cfg_token=?, cfg_expires=? WHERE id=?",
                    (blob, alg, hashlib.sha256(token.encode()).hexdigest(), time.time() + KEEP_CONFIG, uid))
        try:
            self.client_for(d).ra_peer_add(RA_IFACE, pub, ip, name)
            self.sync_rules(device_id)   # their access rules (before they can connect, nothing lets their traffic through)
            self.db.run("UPDATE ra_users SET state='applied', last_error=NULL WHERE id=?", (uid,))
        except (RouterError, RaError) as e:
            self.db.run("DELETE FROM ra_users WHERE id=?", (uid,))
            try:
                self.client_for(d).ra_peer_remove(RA_IFACE, pub)
            except RouterError:
                pass
            raise RaError(f"The router didn't take it, so the user wasn't added: {e}") from None
        self.db.event(device_id, d["org_id"], "remote access", f"user \"{name}\" ({ip}) added by {user}"
                      + (f", expires {datetime.date.fromtimestamp(expires_at)}" if expires_at else ""))
        self.db.audit(user, "remote access user added", d["name"], org_id=d["org_id"], detail=f"{name} {ip}")
        return {"id": uid, "token": token}

    def _config(self, srv, priv, ip, acc=None):
        # what the laptop sends through the tunnel - the router decides what's actually allowed (ra_access)
        if acc is not None:
            allowed = ", ".join(sorted({e["host"] if "/" in e["host"] else f"{e['host']}/32" for e in acc}))
        else:
            allowed = "0.0.0.0/0" if srv["split"] in (0, False) else ", ".join(json.loads(srv["routes"] or "[]") + [srv["pool"]])
        lines = ["[Interface]", f"PrivateKey = {priv}", f"Address = {ip}/32"]
        if srv["dns"]:
            lines.append(f"DNS = {srv['dns']}")
        lines += ["", "[Peer]", f"PublicKey = {srv['pubkey']}", f"AllowedIPs = {allowed}", f"Endpoint = {srv['endpoint']}:{srv['port']}",
                  "PersistentKeepalive = 25", ""]
        return "\n".join(lines)

    def download(self, device_id, uid, token, user):
        """The person's config, once: the encrypted copy is deleted as soon as it's handed out (or after 7 days)."""
        u = self.db.one("SELECT u.*, s.endpoint FROM ra_users u JOIN ra_servers s ON s.device_id = u.device_id WHERE u.id=? AND u.device_id=?", (uid, device_id))
        if not u or not u["cfg_blob"] or u["downloaded_at"] or (u["cfg_expires"] or 0) < time.time():
            raise RaError("That config isn't available any more - it can be downloaded once, within 7 days. Revoke the user and add them again.")
        if not token or not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), u["cfg_token"] or ""):
            raise RaError("That download link isn't valid.")
        conf = self.vault.open(u["cfg_blob"], u["cfg_alg"], f"ra:{uid}").decode()
        self.db.run("UPDATE ra_users SET cfg_blob=NULL, cfg_token=NULL, downloaded_at=? WHERE id=?", (time.time(), uid))
        d = self.device(device_id)
        self.db.audit(user, "remote access config downloaded", d["name"], org_id=d["org_id"], detail=u["name"])
        return u["name"], conf

    def revoke(self, device_id, uid, user):
        d = self.device(device_id)
        u = self.db.one("SELECT * FROM ra_users WHERE id=? AND device_id=?", (uid, device_id))
        if not u:
            raise RaError("No such user.")
        if not d["online"]:
            raise RaError("The router is offline - try again when it's back.")
        try:
            self.client_for(d).ra_peer_remove(RA_IFACE, u["pubkey"])
        except RouterError as e:
            raise RaError(f"The router didn't take it: {e}") from None
        self.db.run("DELETE FROM ra_users WHERE id=?", (uid,))
        try:
            self.sync_rules(device_id)
        except RaError:
            pass   # their peer is gone already, so the leftover rule can't be used; tidied on the next change
        self.db.event(device_id, d["org_id"], "remote access", f"user \"{u['name']}\" revoked by {user}")
        self.db.audit(user, "remote access user revoked", d["name"], org_id=d["org_id"], detail=u["name"])

    def set_disabled(self, device_id, uid, off, user):
        """Switch one person off (or back on) on the router - their config stays the same."""
        d = self.device(device_id)
        u = self.db.one("SELECT * FROM ra_users WHERE id=? AND device_id=?", (uid, device_id))
        if not u:
            raise RaError("No such user.")
        if not d["online"]:
            raise RaError("The router is offline - try again when it's back.")
        try:
            self.client_for(d).ra_peer_disable(RA_IFACE, u["pubkey"], off)
        except RouterError as e:
            raise RaError(f"The router didn't take it: {e}") from None
        self.db.run("UPDATE ra_users SET disabled=? WHERE id=?", (1 if off else 0, uid))
        what = "disabled" if off else "enabled again"
        self.db.event(device_id, d["org_id"], "remote access", f"user \"{u['name']}\" {what} by {user}")
        self.db.audit(user, f"remote access user {'disabled' if off else 'enabled'}", d["name"], org_id=d["org_id"], detail=u["name"])

    def set_expiry(self, device_id, uid, day, user):
        d = self.device(device_id)
        u = self.db.one("SELECT * FROM ra_users WHERE id=? AND device_id=?", (uid, device_id))
        if not u:
            raise RaError("No such user.")
        ts = parse_day(day)
        self.db.run("UPDATE ra_users SET expires_at=?, reminded=0 WHERE id=?", (ts, uid))
        when = f"expires {datetime.date.fromtimestamp(ts)}" if ts else "no longer expires"
        self.db.event(device_id, d["org_id"], "remote access", f"user \"{u['name']}\" {when} (set by {user})")
        self.db.audit(user, "remote access expiry set", d["name"], org_id=d["org_id"], detail=f"{u['name']}: {when}")

    def expire_due(self):
        """Revoke people whose expiry has passed (routers that are offline: next time); remind 3 days before."""
        now = time.time()
        for u in self.db.q("SELECT u.*, d.name AS router, d.org_id FROM ra_users u JOIN devices d ON d.id = u.device_id "
                           "WHERE u.expires_at IS NOT NULL AND u.expires_at - ? < ? AND u.reminded = 0 AND u.expires_at > ?", (now, REMIND, now)):
            self.db.event(u["device_id"], u["org_id"], "remote access",
                          f"user \"{u['name']}\" expires {datetime.date.fromtimestamp(u['expires_at'])} - access is revoked then")
            self.db.run("UPDATE ra_users SET reminded=1 WHERE id=?", (u["id"],))
        for u in self.db.q("SELECT id, device_id FROM ra_users WHERE expires_at IS NOT NULL AND expires_at < ?", (now,)):
            try:
                self.revoke(u["device_id"], u["id"], "expiry (automatic)")
            except RaError:
                pass   # router offline: tried again on the next pass

    def loop(self):
        while True:
            time.sleep(600)
            try:
                self.expire_due()
                self.prune()
            except Exception:  # noqa: BLE001 - keep going
                import traceback
                traceback.print_exc()

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="remote-access").start()

    def prune(self):
        """Configs nobody downloaded within 7 days: delete the encrypted private key."""
        self.db.run("UPDATE ra_users SET cfg_blob=NULL, cfg_token=NULL WHERE cfg_blob IS NOT NULL AND cfg_expires < ?", (time.time(),))
