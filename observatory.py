"""Mozilla HTTP Observatory grade of TikManager's public web address (Admin > Version & updates).

The Observatory (developer.mozilla.org/observatory) checks a site's HTTPS security settings from the outside: security
headers (CSP, HSTS, X-Frame-Options ...), cookies, redirects. TikManager asks its public API to scan its own address
weekly, after every upgrade, and when an administrator clicks "Scan now". Only the host name is sent - it's already
public (DNS, certificate logs). Turned off with TM_OBSERVATORY=0, and skipped for addresses the internet can't reach
(localhost, dev mode, private IPs).
"""
import ipaddress
import json
import threading
import time
import traceback
import urllib.parse
import urllib.request

from version import __version__

API = "https://observatory-api.mdn.mozilla.net/api/v2/scan?host="
EVERY = 7 * 86400
MIN_GAP = 300   # Mozilla serves a cached result for a few minutes anyway


class Observatory:
    def __init__(self, db, settings):
        self.db, self.s = db, settings
        self.lock = threading.Lock()

    @property
    def host(self):
        return urllib.parse.urlparse(getattr(self.s, "public_url", "") or "").hostname or ""

    def supported(self):
        h = self.host
        if not h or getattr(self.s, "dev", False) or str(getattr(self.s, "observatory", "1")).lower() in ("0", "false", "no", "off"):
            return False
        if h == "localhost" or h.endswith((".local", ".lan", ".internal", ".localhost")):
            return False
        try:
            return ipaddress.ip_address(h).is_global
        except ValueError:
            return "." in h

    def info(self):
        try:
            last = json.loads(self.db.setting("observatory_last", "") or "{}")
        except ValueError:
            last = {}
        return {"supported": self.supported(), "host": self.host, **last}

    def scan(self):
        if not self.supported():
            raise ValueError("The Observatory can only scan a public address (TM_PUBLIC_URL), and it's off in dev mode.")
        with self.lock:
            last = self.info()
            if time.time() - (last.get("checked_at") or 0) < MIN_GAP:
                return last
            out = {"checked_at": time.time(), "version": __version__}
            try:
                req = urllib.request.Request(API + urllib.parse.quote(self.host), data=b"", method="POST",
                                             headers={"User-Agent": f"TikManager/{__version__}", "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=90) as r:
                    d = json.loads(r.read(64 * 1024) or b"{}")
                if d.get("error"):
                    out["error"] = str(d["error"])[:300]
                else:
                    out.update(grade=str(d.get("grade") or "")[:3], score=int(d.get("score") or 0), passed=int(d.get("tests_passed") or 0),
                               failed=int(d.get("tests_failed") or 0), total=int(d.get("tests_quantity") or 0),
                               scanned_at=str(d.get("scanned_at") or "")[:40],
                               url=f"https://developer.mozilla.org/en-US/observatory/analyze?host={urllib.parse.quote(self.host)}")
            except Exception as e:  # noqa: BLE001 - offline / API down: show it, try again later
                out["error"] = f"Couldn't reach the Observatory: {e}"[:300]
            self.db.set_setting("observatory_last", json.dumps(out))
            return {"supported": True, "host": self.host, **out}

    def loop(self):
        time.sleep(300)
        while True:
            try:
                last = self.info()
                if self.supported() and (time.time() - (last.get("checked_at") or 0) > EVERY or last.get("version") != __version__):
                    self.scan()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(3600)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="observatory").start()
