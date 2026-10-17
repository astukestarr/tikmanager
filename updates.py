"""New-version check and the "Upgrade now" button.

- Every hour (and on demand) the newest release of the update repository (TM_UPDATE_REPO, default the project's GitHub
  repository) is looked up: its highest vX.Y.Z tag (a GitHub Release for that version adds its notes).
- Channels (Admin > Settings > Version & updates): **stable** (default) only sees vX.Y.Z; **beta** also sees
  vX.Y.Z-beta.N, which come first. Only the newest release on the channel is ever offered, so a beta that a later beta
  fixed is never installed again; RELEASES.json on the repository's default branch lists withdrawn versions (a broken
  beta with no fix yet), which are skipped here and refused by the root updater.
- Upgrading needs root, which the web app deliberately doesn't have. Clicking Upgrade writes the wanted version to
  <data>/update-request; the root-owned systemd unit tikmanager-update.path notices it and runs deploy/self-update.sh,
  which downloads that release, backs up code and database, installs it, restarts, rolls back if the new version doesn't
  start, and reports progress in /var/lib/tikmanager-update/status.json (root-owned; this service can only read it).
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

CHECK_EVERY = 3600   # GitHub allows 60 unauthenticated requests an hour; this uses 2-3
SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?$")
USER_AGENT = f"TikManager/{__version__}"
CHANNELS = ("stable", "beta")


def vtuple(v):
    """Sort key: 1.44.0-beta.1 < 1.44.0-beta.2 < 1.44.0 (a release comes after its betas). None if not a version."""
    m = SEMVER.match(str(v or "").strip())
    if not m:
        return None
    maj, mi, pa, beta = m.groups()
    return (int(maj), int(mi), int(pa), 0 if beta else 1, int(beta or 0))


def is_beta(v):
    return "-beta." in str(v or "")


def security_grade(fails, warns):
    """The server security check as a grade: 100 points, -20 per FAIL, -5 per WARN; any FAIL caps it at C, so a real
    problem can't hide behind lots of passes. A+ = nothing to fix or look at."""
    score = max(0, 100 - 20 * fails - 5 * warns)
    if fails:
        score = min(score, 79)
    grade = "A+" if not fails and not warns else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return {"score": score, "grade": grade}


class Updates:
    def __init__(self, settings):
        self.s = settings
        self.data = Path(settings.data_dir)
        self.request_file = self.data / "update-request"
        # written by the root updater in its own root-owned folder (never in ours, where links could be planted);
        # data/update-status.json is where versions before 1.1.1 wrote it, and dev mode reads it from there
        self.status_files = [Path("/var/lib/tikmanager-update/status.json"), self.data / "update-status.json"]
        # the read-only server security check (deploy/check.sh, run as root by tikmanager-check.service): results in the
        # root-owned folder; dev mode reads data/security.json. The web app can only ask for a run (an empty file).
        self.security_files = [Path("/var/lib/tikmanager-update/security.json"), self.data / "security.json"]
        self.security_request = self.data / "security-check-request"
        self.latest = {"version": None, "url": None, "notes": "", "checked_at": None, "error": None, "withdrawn": []}
        self.lock = threading.Lock()
        self.channel_store = None   # set by the server: (get, set) for the saved channel

    @property
    def channel(self):
        ch = self.channel_store[0]() if self.channel_store else "stable"
        return ch if ch in CHANNELS else "stable"

    def set_channel(self, ch):
        if ch not in CHANNELS:
            raise ValueError("The channel is stable or beta.")
        if self.channel_store:
            self.channel_store[1](ch)

    def withdrawn(self):
        """Versions pulled from RELEASES.json on the default branch: {"withdrawn": ["1.44.0-beta.1", ...]}. [] if none."""
        try:
            req = urllib.request.Request(f"https://raw.githubusercontent.com/{self.repo}/HEAD/RELEASES.json", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read() or b"{}")
            return [str(v).lstrip("v") for v in data.get("withdrawn") or [] if vtuple(v)]
        except urllib.error.HTTPError as e:
            if e.code == 404:   # no file = nothing withdrawn
                return []
            raise

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

    def _tags(self):
        """Every tag name - GitHub returns at most 100 per page, so read the pages until a short one (at most 10)."""
        out = []
        for page in range(1, 11):
            batch = self._get(f"https://api.github.com/repos/{self.repo}/tags?per_page=100&page={page}") or []
            out += [t.get("name") for t in batch if isinstance(t, dict)]
            if len(batch) < 100:
                break
        return out

    def check(self):
        if not self.repo or not re.fullmatch(r"[\w.-]+/[\w.-]+", self.repo):
            self.latest.update(error="No update repository configured (TM_UPDATE_REPO).", checked_at=time.time())
            return self.latest
        try:
            # the newest version is the highest vX.Y.Z tag (every version is tagged); a GitHub Release for that same
            # version only adds its notes - so a version pushed without a Release is never missed
            version = url = notes = None
            pulled = set(self.withdrawn())
            beta_ok = self.channel == "beta"
            tags = self._tags()
            # only the newest beta ever counts: an older one (e.g. one a later beta fixed) is never offered - not even
            # when the newest is withdrawn (then no beta is offered until a newer one is out)
            betas = [t for t in tags if vtuple(t) and is_beta(t)]
            newest_beta = max(betas, key=vtuple, default=None)
            pick = [t for t in tags if vtuple(t) and not is_beta(t)] + ([newest_beta] if beta_ok and newest_beta else [])
            best = max((t for t in pick if t.lstrip("v") not in pulled), key=vtuple, default=None)
            if best:
                version = best.lstrip("v")
                url = f"https://github.com/{self.repo}/blob/v{version}/CHANGELOG.md"
            try:
                rel = self._get(f"https://api.github.com/repos/{self.repo}/releases/latest")
                tag = str(rel.get("tag_name") or "")
                if (vtuple(tag) and tag.lstrip("v") not in pulled and (beta_ok or not is_beta(tag))
                        and (not version or vtuple(tag) >= vtuple(version))):
                    version, url, notes = rel["tag_name"].lstrip("v"), rel.get("html_url"), (rel.get("body") or "")[:4000]
            except urllib.error.HTTPError as e:
                if e.code != 404:   # 404 = no Release published: the tag is enough
                    raise
            self.latest.update(version=version, url=url, notes=notes or "", checked_at=time.time(), error=None, withdrawn=sorted(pulled))
        except Exception as e:  # noqa: BLE001 - offline, rate-limited...: try again later
            self.latest.update(checked_at=time.time(), error=f"Couldn't check for updates: {e}"[:200])
        return self.latest

    def installed(self):
        """When this version arrived (its version.py was written by the updater / installer) and, if the updater's last
        run put it there, the version it came from."""
        try:
            at = (Path(__file__).resolve().parent / "version.py").stat().st_mtime
        except OSError:
            at = None
        st = self.status()
        came = st.get("from") if st.get("state") == "done" and st.get("version") == __version__ and str(st.get("detail", "")).startswith("Upgraded") else None
        return {"installed_at": at, "upgraded_from": came}

    def info(self):
        cur, new = vtuple(__version__), vtuple(self.latest.get("version"))
        return {"version": __version__, "latest": self.latest.get("version"), "available": bool(cur and new and new > cur),
                "channel": self.channel, "beta_installed": is_beta(__version__), "latest_beta": is_beta(self.latest.get("version")),
                "withdrawn_installed": __version__ in (self.latest.get("withdrawn") or []),
                "url": self.latest.get("url"), "notes": self.latest.get("notes"), "checked_at": self.latest.get("checked_at"),
                "error": self.latest.get("error"), "repo": self.repo, "supported": self.supported(), "status": self.status(),
                "security": self.security(), **self.installed()}

    def security_supported(self):
        return os.name == "posix" and Path("/etc/systemd/system/tikmanager-check.path").exists()

    def security(self):
        """Latest server security check: {at, fails, warns, results: [{status, section, text}], running, supported}."""
        out = {"supported": self.security_supported(), "running": self.security_request.exists()}
        for f in self.security_files:
            try:
                if f.stat().st_size > 512 * 1024:
                    continue
                d = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            rows = [{"status": str(r.get("status"))[:8], "section": str(r.get("section"))[:60], "id": str(r.get("id") or "")[:40],
                     "text": str(r.get("text"))[:600]}
                    for r in (d.get("results") or [])[:200] if isinstance(r, dict)]
            out.update(at=d.get("at"), fails=int(d.get("fails") or 0), warns=int(d.get("warns") or 0), results=rows)
            out.update(security_grade(out["fails"], out["warns"]))
            break
        return out

    def request_security(self):
        if not self.security_supported():
            raise ValueError("The server security check needs a Linux installation made with deploy/install.sh (1.9.0 or later). "
                             "Run it by hand: sudo bash /opt/tikmanager/deploy/check.sh")
        if self.security_request.exists():
            raise ValueError("A security check is already running.")
        self.security_request.write_text("", encoding="utf-8")

    def status(self):
        st = {}
        for f in self.status_files:
            try:
                st = json.loads(f.read_text(encoding="utf-8"))
                break
            except (OSError, ValueError):
                continue
        if self.request_file.exists():
            st = {"state": "requested", "version": self.request_file.read_text(encoding="utf-8").strip()[:20], "detail": "Waiting for the updater to start"}
        return st

    def request(self, version):
        """Ask the root updater to install `version` (must be a newer released version)."""
        if not self.supported():
            raise ValueError("One-click upgrade needs a Linux installation made with deploy/install.sh. Upgrade manually (see README).")
        if not vtuple(version):
            raise ValueError("Pick a version like 1.2.3 or 1.2.3-beta.1.")
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
