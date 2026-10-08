"""New-version check and the "Upgrade now" button.

- Once a day (and on demand) the newest release of the update repository (TM_UPDATE_REPO, default the project's GitHub
  repository) is looked up: its latest GitHub Release, else its highest vX.Y.Z tag.
- Upgrading needs root, which the web app deliberately doesn't have. Clicking Upgrade writes the wanted version to
  <data>/update-request; the root-owned systemd unit tikmanager-update.path notices it and runs deploy/self-update.sh,
  which downloads that release, backs up code and database, installs it, restarts, rolls back if the new version doesn't
  start, and reports progress in <data>/update-status.json.
- Where updates come from is read by self-update.sh from the root-owned settings file only - never from anything the
  web app can change - so a compromised admin account can't make the server install someone else's code.
"""
import json
import os
import re
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

from version import __version__

CHECK_EVERY = 24 * 3600
SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
USER_AGENT = f"TikManager/{__version__}"


def vtuple(v):
    m = SEMVER.match(str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


class Updates:
    def __init__(self, settings):
        self.s = settings
        self.data = Path(settings.data_dir)
        self.request_file = self.data / "update-request"
        self.status_file = self.data / "update-status.json"
        self.latest = {"version": None, "url": None, "notes": "", "checked_at": None, "error": None}
        self.lock = threading.Lock()

    @property
    def repo(self):
        return (getattr(self.s, "update_repo", "") or "").strip().strip("/")

    def supported(self):
        """One-click upgrade needs the root updater units the Linux installer sets up."""
        return os.name == "posix" and Path("/etc/systemd/system/tikmanager-update.path").exists()

    def _get(self, url):
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"null")

    def check(self):
        if not self.repo or not re.fullmatch(r"[\w.-]+/[\w.-]+", self.repo):
            self.latest.update(error="No update repository configured (TM_UPDATE_REPO).", checked_at=time.time())
            return self.latest
        try:
            version = url = notes = None
            try:
                rel = self._get(f"https://api.github.com/repos/{self.repo}/releases/latest")
                if vtuple(rel.get("tag_name")):
                    version, url, notes = rel["tag_name"].lstrip("v"), rel.get("html_url"), (rel.get("body") or "")[:4000]
            except urllib.error.HTTPError as e:
                if e.code != 404:   # 404 = no formal release yet; fall back to tags
                    raise
            if not version:
                tags = [t.get("name") for t in self._get(f"https://api.github.com/repos/{self.repo}/tags?per_page=100") or []]
                best = max((t for t in tags if vtuple(t)), key=vtuple, default=None)
                if best:
                    version = best.lstrip("v")
                    url = f"https://github.com/{self.repo}/blob/v{version}/CHANGELOG.md"
            self.latest.update(version=version, url=url, notes=notes or "", checked_at=time.time(), error=None)
        except Exception as e:  # noqa: BLE001 - offline, rate-limited...: try again later
            self.latest.update(checked_at=time.time(), error=f"Couldn't check for updates: {e}"[:200])
        return self.latest

    def info(self):
        cur, new = vtuple(__version__), vtuple(self.latest.get("version"))
        return {"version": __version__, "latest": self.latest.get("version"), "available": bool(cur and new and new > cur),
                "url": self.latest.get("url"), "notes": self.latest.get("notes"), "checked_at": self.latest.get("checked_at"),
                "error": self.latest.get("error"), "repo": self.repo, "supported": self.supported(), "status": self.status()}

    def status(self):
        try:
            st = json.loads(self.status_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            st = {}
        if self.request_file.exists():
            st = {"state": "requested", "version": self.request_file.read_text(encoding="utf-8").strip()[:20], "detail": "Waiting for the updater to start"}
        return st

    def request(self, version):
        """Ask the root updater to install `version` (must be a newer released version)."""
        if not self.supported():
            raise ValueError("One-click upgrade needs a Linux installation made with deploy/install.sh. Upgrade manually (see README).")
        if not vtuple(version):
            raise ValueError("Pick a version like 1.2.3.")
        if self.latest.get("version") != version or not self.info()["available"]:
            raise ValueError("That isn't the newest released version - check for updates first.")
        if self.status().get("state") in ("requested", "running"):
            raise ValueError("An upgrade is already in progress.")
        tmp = self.request_file.with_suffix(".tmp")
        tmp.write_text(version, encoding="utf-8")
        os.replace(tmp, self.request_file)   # the path unit fires on the final name only

    def loop(self):
        time.sleep(120)
        while True:
            try:
                if getattr(self.s, "update_check", True):
                    self.check()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(CHECK_EVERY)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="update-check").start()
