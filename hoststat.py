"""Host facts for Admin > Settings: how full the server drive is, and whether the operating system installs
security updates automatically. Standard library only, and safe to call on any OS - everything degrades to a
"not applicable" answer rather than raising, so the Settings page never breaks because of the host.

Automatic updates here means Debian/Ubuntu's unattended-upgrades (what deploy/install.sh sets up and
deploy/check.sh verifies from the shell); this mirrors that check so an administrator can see it in the UI.
"""
import glob
import os
import shutil
import subprocess
import sys


def disk(data_dir):
    """Usage of the volume that holds the data folder: total/used/free bytes and used percent. None if unknown."""
    try:
        total, used, free = shutil.disk_usage(str(data_dir))
    except OSError:
        return None
    return {"total": total, "used": used, "free": free, "pct": round(used * 100 / total) if total else 0}


def _apt_host():
    return sys.platform.startswith("linux") and os.path.isdir("/etc/apt/apt.conf.d")


def _periodic_on():
    """True if any apt.conf.d file turns on the periodic Unattended-Upgrade run (ignoring commented lines)."""
    for path in glob.glob("/etc/apt/apt.conf.d/*"):
        try:
            with open(path, "r", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("//") or s.startswith("#"):
                continue
            # e.g.  APT::Periodic::Unattended-Upgrade "1";
            if 'Unattended-Upgrade' in s and '"1"' in s and 'Periodic' in s:
                return True
    return False


def _reboot_note():
    """Describe the automatic-reboot behaviour from our 52tikmanager-unattended drop-in, if present."""
    try:
        with open("/etc/apt/apt.conf.d/52tikmanager-unattended", "r", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return ""
    on = '::Automatic-Reboot "true"' in text
    when = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("//") or s.startswith("#"):
            continue
        if "Automatic-Reboot-Time" in s and '"' in s:
            try:
                when = s.split('"')[1]
            except IndexError:
                when = ""
    if on:
        return f" Reboots when an update needs it{(' at ' + when) if when else ''}."
    return " Will not reboot automatically."


def _service_state():
    """systemctl is-enabled unattended-upgrades -> the word, or None if systemctl can't be read."""
    try:
        r = subprocess.run(["systemctl", "is-enabled", "unattended-upgrades"],
                           capture_output=True, text=True, timeout=3)
        return (r.stdout or r.stderr or "").strip() or None
    except Exception:
        return None


def auto_updates():
    """Whether the host installs security updates automatically.

    {applicable, ok, detail, fix} - ok is None when it can't be determined. Matches deploy/check.sh: the package
    is present, a periodic Unattended-Upgrade run is enabled, and the service is not disabled.
    """
    if not _apt_host():
        return {"applicable": False, "ok": None,
                "detail": "Automatic APT updates apply to Debian/Ubuntu hosts; this host manages updates elsewhere.",
                "fix": ""}
    has_pkg = bool(shutil.which("unattended-upgrade")) or os.path.exists("/usr/bin/unattended-upgrade")
    periodic = _periodic_on()
    svc = _service_state()
    svc_disabled = svc in ("disabled", "masked")
    ok = has_pkg and periodic and not svc_disabled
    if ok:
        return {"applicable": True, "ok": True,
                "detail": "Security updates install automatically (unattended-upgrades)." + _reboot_note(),
                "fix": ""}
    if not has_pkg:
        return {"applicable": True, "ok": False,
                "detail": "unattended-upgrades is not installed, so security updates are not applied automatically.",
                "fix": "Re-run the TikManager installer, or: sudo apt install unattended-upgrades"}
    return {"applicable": True, "ok": False,
            "detail": "unattended-upgrades is installed but automatic runs are turned off.",
            "fix": "sudo dpkg-reconfigure -plow unattended-upgrades"}
