"""Off-site backup to your own storage: FTPS / FTP or WebDAV (Admin > Settings > Off-site backup).

- What: "scripts" (the script library, as JSON) or "full" (everything needed to rebuild TikManager on a new server: a
  consistent copy of the database - routers, clients, users, the routers' configuration backups, settings, scripts -
  plus the master key, the settings file and branding).
- Encrypted with a passphrase you choose (scrypt -> AES-256-GCM), so the storage can't read it. A full backup must be
  encrypted (it holds the master key). Restore with tools/tmbak.py (see the README). The passphrase is saved encrypted on
  this server so scheduled backups work - keep your own copy somewhere else: without it a backup can't be opened.
- Where: FTPS (FTP over TLS - recommended), plain FTP (only sensible with encryption on), or WebDAV (Nextcloud,
  ownCloud, Synology / QNAP, Box ...). Daily at the hour you pick, plus Back up now; the newest N copies are kept on the
  destination and older TikManager backups there are deleted.
"""
import base64
import ftplib
import hashlib
import io
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import archivedest
from version import __version__

MAGIC = b"TMBAK1"
PREFIX = "tikmanager-"
KINDS = ("local", "ftps", "ftp", "webdav", "s3", "azure", "gdrive")   # same destinations as log archiving (archivedest.py)


class OffsiteError(Exception):
    pass


def encrypt(data: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob.startswith(MAGIC):
        raise OffsiteError("Not a TikManager backup file.")
    salt, nonce, ct = blob[6:22], blob[22:34], blob[34:]
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    try:
        return AESGCM(key).decrypt(nonce, ct, MAGIC)
    except Exception:  # noqa: BLE001 - wrong passphrase or damaged file look the same
        raise OffsiteError("Wrong passphrase, or the file is damaged.") from None


class OffsiteBackup:
    def __init__(self, db, settings, integ):
        self.db, self.s, self.integ = db, settings, integ
        self.running = False
        self.lock = threading.Lock()

    # --- settings -----------------------------------------------------------------------------------------------
    def config(self):
        c = self.integ.config("offsite")
        c.setdefault("kind", "ftps")
        c.setdefault("what", "full")
        c.setdefault("schedule", "daily")
        c.setdefault("keep", "14")
        c.setdefault("hour", "3")
        c.setdefault("verify", "1")
        return c

    def public(self):
        return {**self.integ.public("offsite"), **{k: self.config()[k] for k in ("kind", "what", "schedule", "keep", "hour", "verify")},
                "last": self.last(), "running": self.running}

    def save(self, b):
        keys = ("kind", "host", "port", "username", "password", "folder", "url", "verify", "what", "passphrase", "schedule", "keep", "hour",
                "path", "s3_endpoint", "s3_region", "s3_bucket", "s3_access_key", "s3_secret_key", "s3_prefix",
                "az_account", "az_container", "az_prefix", "az_endpoint", "az_sas", "az_key", "g_sa_json", "g_folder_id")
        b = {k: str(v).strip() for k, v in (b or {}).items() if k in keys} | (
            {"clear": b.get("clear")} if isinstance(b.get("clear"), list) else {})
        cur = {**self.config(), **{k: v for k, v in b.items() if k != "clear"}}
        if cur["kind"] not in KINDS:
            raise ValueError("Pick where to back up to.")
        if cur.get("port") and not (cur["port"].isdigit() and 0 < int(cur["port"]) < 65536):
            raise ValueError("The port is a number from 1 to 65535.")
        if cur["what"] not in ("scripts", "full") or cur["schedule"] not in ("daily", "off"):
            raise ValueError("Pick what to back up and how often.")
        if not (cur["keep"].isdigit() and 1 <= int(cur["keep"]) <= 365) or not (cur["hour"].isdigit() and 0 <= int(cur["hour"]) <= 23):
            raise ValueError("Keep 1-365 copies; the hour is 0-23.")
        if b.get("passphrase") and len(b["passphrase"]) < 12:
            raise ValueError("Use a passphrase of at least 12 characters.")
        if cur["what"] == "full" and not (b.get("passphrase") or self.integ.config("offsite").get("passphrase")):
            raise ValueError("A full backup holds the master key, so it must be encrypted - set a passphrase.")
        if cur["kind"] == "ftp" and not (b.get("passphrase") or self.integ.config("offsite").get("passphrase")):
            raise ValueError("Plain FTP sends everything readable - set a passphrase so the backup is encrypted (or use FTPS).")
        try:   # the destination's own field validation (missing bucket, folder, SAS, path, etc.) with friendly messages
            archivedest.make({**cur, "dest": cur["kind"]})
        except archivedest.ArchiveError as e:
            raise ValueError(str(e)) from None
        self.integ.save("offsite", b)

    def last(self):
        try:
            return json.loads(self.db.setting("offsite_last", "") or "{}")
        except ValueError:
            return {}

    # --- building the file ----------------------------------------------------------------------------------------
    def build(self, what):
        scripts = self.db.q("SELECT name, description, body, created_by, created_at, updated_by, updated_at FROM scripts ORDER BY name")
        manifest = {"product": "TikManager", "version": __version__, "created": time.time(), "host": socket.gethostname(),
                    "public_url": getattr(self.s, "public_url", ""), "what": what}
        if what == "scripts":
            return json.dumps({"manifest": manifest, "scripts": scripts}, indent=1).encode()
        buf = io.BytesIO()
        with tempfile.TemporaryDirectory() as tmp, tarfile.open(fileobj=buf, mode="w:gz") as tar:
            snap = Path(tmp) / "tikmanager.db"   # a consistent copy, even while TikManager is writing
            src = sqlite3.connect(self.db.path)
            dst = sqlite3.connect(snap)
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
            tar.add(snap, "tikmanager.db")
            for path, name in ((getattr(self.s, "key_file", None), "master.key"),
                               (Path(os.environ.get("TM_ENV_FILE", "/etc/tikmanager/tikmanager.env")), "tikmanager.env")):
                if path and Path(path).is_file():
                    tar.add(str(path), name)
            brand = Path(self.s.data_dir) / "branding"
            if brand.is_dir():
                tar.add(str(brand), "branding")
            for name, data in (("scripts.json", json.dumps(scripts, indent=1).encode()), ("manifest.json", json.dumps(manifest, indent=1).encode())):
                info = tarfile.TarInfo(name)
                info.size, info.mtime = len(data), int(time.time())
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    # --- destination (shared with log archiving: local / FTPS / FTP / WebDAV / S3 / Azure / Google Drive) ----------
    def _backend(self):
        c = self.config()
        return archivedest.make({**c, "dest": c.get("kind")})

    def upload(self, name, data):
        try:
            self._backend().put(name, data)
        except archivedest.ArchiveError as e:
            raise OffsiteError(str(e)) from None

    def listing(self):
        try:
            names = self._backend().names("")
        except archivedest.ArchiveError:
            return []
        return sorted({n.rsplit("/", 1)[-1] for n in names
                       if n.rsplit("/", 1)[-1].startswith(PREFIX) and n.endswith((".tmbak", ".json"))})

    def delete(self, name):
        try:
            self._backend().delete(name)
        except archivedest.ArchiveError:
            pass

    # --- running ----------------------------------------------------------------------------------------------------
    def test(self):
        try:
            return self._backend().check()
        except archivedest.ArchiveError as e:
            raise OffsiteError(str(e)) from None

    def where(self):
        try:
            return self._backend().label()
        except archivedest.ArchiveError:
            return (self.config().get("kind") or "").upper()

    def run(self, trigger="manual"):
        with self.lock:
            if self.running:
                raise OffsiteError("An off-site backup is already running.")
            self.running = True
        c = self.config()
        out = {"at": time.time(), "trigger": trigger, "what": c["what"]}
        try:
            if not self.integ.configured("offsite"):
                raise OffsiteError("Off-site backup isn't set up yet.")
            data = self.build(c["what"])
            phrase = c.get("passphrase") or ""
            if phrase:
                data, ext = encrypt(data, phrase), "tmbak"
            elif c["what"] == "full" or c["kind"] == "ftp":
                raise OffsiteError("Set a passphrase - this backup must be encrypted.")
            else:
                ext = "json"
            name = f"{PREFIX}{time.strftime('%Y%m%d-%H%M%S')}-{c['what']}.{ext}"
            self.upload(name, data)
            removed = 0
            try:   # keep the newest N TikManager backups there
                old = self.listing()
                for n in old[:-int(c["keep"])]:
                    self.delete(n)
                    removed += 1
            except OffsiteError:
                pass
            out.update(ok=True, file=name, size=len(data), detail=f"Saved {name} ({len(data) / 1048576:.1f} MB) to {self.where()}"
                                                                   + (f"; removed {removed} older" if removed else ""))
        except Exception as e:  # noqa: BLE001
            if not isinstance(e, OffsiteError):
                traceback.print_exc()
            out.update(ok=False, detail=str(e)[:400])
        finally:
            self.running = False
        self.db.set_setting("offsite_last", json.dumps(out))
        return out

    def loop(self):
        while True:
            time.sleep(600)
            try:
                c = self.config()
                last = self.last()
                if (self.integ.configured("offsite") and c["schedule"] == "daily" and int(time.strftime("%H")) == int(c["hour"])
                        and time.time() - (last.get("at") or 0) > 20 * 3600):
                    self.run("daily")
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="offsite").start()
