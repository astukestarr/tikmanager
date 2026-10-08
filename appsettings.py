"""Settings an admin edits on Admin > Settings, stored in the database (the Microsoft client secret encrypted).

They override the values from the settings file (/etc/tikmanager/tikmanager.env), which become defaults - so an
existing install keeps working until someone saves the page. Only things the web app can't safely change itself stay
in the settings file: the public address (the HTTPS certificate and the browser security checks depend on it), the
data / key locations, the port and the controller's WireGuard key.
"""
import base64
import ipaddress
import json
import re

FIELDS = {   # name -> secret?
    "tech_domains": False, "tech_admins": False,
    "entra_tenant_id": False, "entra_client_id": False, "entra_client_secret": True,
    "wg_endpoint": False, "ping_target": False,
}
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
EMAIL = re.compile(r"^[^@\s,]+@[^@\s,]+\.[a-z]{2,}$", re.I)
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)


def _list(v):
    return [x.strip().lower().lstrip("@") for x in re.split(r"[,\s;]+", str(v or "")) if x.strip()]


class AppSettings:
    def __init__(self, db, vault, settings):
        self.db, self.vault, self.s = db, vault, settings
        self.defaults = {k: getattr(settings, k) for k in FIELDS}   # from the settings file

    def _saved(self):
        try:
            raw = json.loads(self.db.setting("system_config") or "{}")
        except ValueError:
            return {}
        if raw.get("entra_client_secret_enc"):
            try:
                blob = base64.b64decode(raw["entra_client_secret_enc"])
                raw["entra_client_secret"] = self.vault.open(blob, raw.get("entra_client_secret_alg") or "aes-gcm", "sysconfig").decode()
            except Exception:  # noqa: BLE001 - unreadable (key replaced): fall back to the settings file
                raw["entra_client_secret"] = ""
        return raw

    def apply(self):
        """Put saved values (or the settings-file defaults) onto the live settings object."""
        saved = self._saved()
        for k in FIELDS:
            v = saved.get(k)
            setattr(self.s, k, v if v not in (None, "") else self.defaults[k])
        if not self.s.wg_endpoint:   # routers dial the same name the web UI answers on
            self.s.wg_endpoint = f"{re.sub(r'^https?://', '', self.s.public_url).split('/')[0].split(':')[0]}:51820"
        if not self.s.ping_target:
            self.s.ping_target = "1.1.1.1"

    def public(self):
        out = {k: ("" if secret else getattr(self.s, k)) for k, secret in FIELDS.items()}
        out["entra_client_secret_set"] = bool(self.s.entra_client_secret)
        out["redirect_uri"] = f"{self.s.public_url}/auth/callback"
        return out

    def save(self, data):
        cur = self._saved()
        clean = {}
        domains = _list(data.get("tech_domains", cur.get("tech_domains", "")))
        bad = [d for d in domains if not DOMAIN.match(d)]
        if bad:
            raise ValueError(f"Not a domain name: {bad[0]}")
        clean["tech_domains"] = ",".join(domains)
        admins = _list(data.get("tech_admins", cur.get("tech_admins", "")))
        bad = [a for a in admins if not EMAIL.match(a)]
        if bad:
            raise ValueError(f"Not an email address: {bad[0]}")
        clean["tech_admins"] = ",".join(admins)
        for k in ("entra_tenant_id", "entra_client_id"):
            v = str(data.get(k, cur.get(k, "")) or "").strip()
            if v and not GUID.match(v):
                raise ValueError("Microsoft tenant and client IDs look like 00000000-0000-0000-0000-000000000000.")
            clean[k] = v
        ep = str(data.get("wg_endpoint", cur.get("wg_endpoint", "")) or "").strip()
        if ep:
            host, _, port = ep.rpartition(":")
            if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError("The WireGuard address is host:port, e.g. tikmanager.example.com:51820.")
        clean["wg_endpoint"] = ep
        pt = str(data.get("ping_target", cur.get("ping_target", "")) or "").strip()
        if pt:
            try:
                ipaddress.ip_address(pt)
            except ValueError:
                if not DOMAIN.match(pt):
                    raise ValueError("The latency test target is an IP address or host name.") from None
        clean["ping_target"] = pt
        secret = str(data.get("entra_client_secret") or "").strip()
        if data.get("clear_entra_secret"):
            secret_blob = None
        elif secret:
            blob, alg = self.vault.seal(secret.encode(), "sysconfig")
            secret_blob = (base64.b64encode(blob).decode(), alg)
        else:
            secret_blob = (json.loads(self.db.setting("system_config") or "{}").get("entra_client_secret_enc"),
                           json.loads(self.db.setting("system_config") or "{}").get("entra_client_secret_alg"))
        if secret_blob and secret_blob[0]:
            clean["entra_client_secret_enc"], clean["entra_client_secret_alg"] = secret_blob
        self.db.set_setting("system_config", json.dumps(clean))
        self.apply()
        return self.public()
