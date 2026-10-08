"""TikManager settings, from environment variables or a .env file (/etc/tikmanager/tikmanager.env in production).

Secrets never go in the database: the master key file (TM_KEY_FILE) is read at startup and used to derive per-router
API passwords, so a copy of the database alone gives nobody access to any router.
"""
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_env(path: Path):
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = re.split(r"\s+#", v, maxsplit=1)[0]   # "KEY=value   # comment"
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env(Path(os.environ.get("TM_ENV_FILE", "/etc/tikmanager/tikmanager.env")))
load_env(ROOT / ".env")


def env(name, default=""):
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    host: str = field(default_factory=lambda: env("TM_HOST", "127.0.0.1"))   # behind Caddy: never 0.0.0.0
    port: int = field(default_factory=lambda: int(env("TM_PORT", "8800")))
    public_url: str = field(default_factory=lambda: env("TM_PUBLIC_URL", "http://localhost:8800").rstrip("/"))
    data_dir: Path = field(default_factory=lambda: Path(env("TM_DATA", str(ROOT / "data"))))
    key_file: Path = field(default_factory=lambda: Path(env("TM_KEY_FILE", str(ROOT / "data" / "master.key"))))
    dev: bool = field(default_factory=lambda: env("TM_DEV", "").lower() in ("1", "true", "yes"))   # simulated routers
    trusted_proxy: str = field(default_factory=lambda: env("TM_TRUSTED_PROXY", "127.0.0.1"))   # only trust X-Forwarded-For from Caddy
    # tech sign-in (Microsoft Entra, single tenant) - these, the staff domains / admins, the WireGuard address and the
    # latency target are defaults: Admin > Settings (appsettings.py) overrides them
    entra_tenant_id: str = field(default_factory=lambda: env("ENTRA_TENANT_ID"))
    entra_client_id: str = field(default_factory=lambda: env("ENTRA_CLIENT_ID"))
    entra_client_secret: str = field(default_factory=lambda: env("ENTRA_CLIENT_SECRET"))
    tech_admins: str = field(default_factory=lambda: env("TM_TECH_ADMINS"))    # comma-separated emails who are admins
    tech_domains: str = field(default_factory=lambda: env("TM_TECH_DOMAINS"))  # e.g. example.com - who may sign in as a tech
    # WireGuard
    wg_interface: str = field(default_factory=lambda: env("WG_INTERFACE", "wg0"))
    wg_endpoint: str = field(default_factory=lambda: env("WG_ENDPOINT"))   # default: the public address's host, port 51820
    wg_server_ip: str = field(default_factory=lambda: env("WG_SERVER_IP", "10.77.0.1"))
    wg_network: str = field(default_factory=lambda: env("WG_NETWORK", "10.77.0.0/16"))
    wg_server_pubkey: str = field(default_factory=lambda: env("WG_SERVER_PUBKEY"))
    syslog_port: int = field(default_factory=lambda: int(env("TM_SYSLOG_PORT", "5514")))
    # one-time first-run link (/setup/<token>), written by the installer; dead once an admin account exists
    setup_token: str = field(default_factory=lambda: env("TM_SETUP_TOKEN"))
    ping_target: str = field(default_factory=lambda: env("TM_PING_TARGET", "1.1.1.1"))   # routers ping this each minute (WAN latency/loss)
    # nightly configuration backups
    backup_hour: int = field(default_factory=lambda: int(env("TM_BACKUP_HOUR", "2")))          # server local time
    backup_keep_versions: int = field(default_factory=lambda: int(env("TM_BACKUP_KEEP", "10")))   # versions per router

    @property
    def entra_configured(self):
        return all([self.entra_tenant_id, self.entra_client_id, self.entra_client_secret])

    @property
    def secure_cookies(self):
        return self.public_url.startswith("https://")


settings = Settings()


def master_key() -> bytes:
    """32 random bytes, created on first run (production: created by the installer, root-owned, readable by the service)."""
    p = settings.key_file
    if not p.is_file():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    key = p.read_bytes()
    if len(key) < 32:
        raise RuntimeError(f"{p} is too short - it must hold at least 32 random bytes.")
    return key
