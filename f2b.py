"""fail2ban on TikManager's own server: who's banned now, and Unblock from the Security page.

The web app runs unprivileged, so it drops a one-line request ("unban <ip> <id>" / "list - <id>") in its data folder;
tikmanager-unban.path runs deploy/f2b-unban.sh as root, which checks the address, runs fail2ban-client and writes the
current ban list to /var/lib/tikmanager-update/f2b.json. fail2ban here guards SSH to the server (the sshd jail) - a ban
doesn't affect the web app, the Winbox relay or the routers. Dev mode keeps a pretend list in memory.
"""
import ipaddress
import json
import os
import secrets
import time
from pathlib import Path

STATUS = Path("/var/lib/tikmanager-update/f2b.json")


class F2b:
    def __init__(self, settings):
        self.s = settings
        self.request_file = Path(settings.data_dir) / "unban-request"
        self.asked = 0
        self.dev_banned = {"198.51.100.23": "sshd"}   # the demo data's fail2ban ban

    def supported(self):
        return getattr(self.s, "dev", False) or (os.name == "posix" and Path("/etc/systemd/system/tikmanager-unban.path").exists())

    def status(self):
        """{banned: {ip: jail}, at, last} - refreshed in the background when it's more than 2 minutes old."""
        if getattr(self.s, "dev", False):
            return {"banned": dict(self.dev_banned), "at": time.time(), "supported": True}
        try:
            raw = json.loads(STATUS.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        if self.supported() and time.time() - (raw.get("at") or 0) > 120 and time.time() - self.asked > 60:
            self._ask("list", "-")
        return {"banned": {b["ip"]: b.get("jail", "") for b in raw.get("banned") or [] if isinstance(b, dict) and b.get("ip")},
                "at": raw.get("at"), "last": raw.get("last"), "supported": self.supported()}

    def unban(self, ip):
        ip = str(ipaddress.ip_address(str(ip).strip()))   # ValueError for anything that isn't an address
        if getattr(self.s, "dev", False):
            self.dev_banned.pop(ip, None)
            return {"ok": True, "detail": "unbanned"}
        if not self.supported():
            raise ValueError("This server's unblock helper isn't installed - it comes with the next update (or run sudo bash /opt/tikmanager/deploy/update.sh).")
        rid = self._ask("unban", ip)
        for _ in range(20):   # the root helper answers within a second or two
            time.sleep(0.5)
            try:
                last = json.loads(STATUS.read_text(encoding="utf-8")).get("last") or {}
            except (OSError, ValueError):
                continue
            if last.get("id") == rid:
                return {"ok": last.get("state") == "ok", "detail": last.get("detail") or ""}
        return {"ok": False, "detail": "The server's unblock helper didn't answer - check tikmanager-unban.path is running."}

    def _ask(self, action, ip):
        rid = secrets.token_hex(6)
        self.asked = time.time()
        tmp = self.request_file.with_suffix(".tmp")
        tmp.write_text(f"{action} {ip} {rid}\n", encoding="utf-8")
        os.replace(tmp, self.request_file)
        return rid
