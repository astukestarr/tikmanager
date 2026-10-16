"""Auto-block: addresses that keep failing to sign in to your routers are blocked on every router.

- Every minute, router sign-in failures (from the routers' logs, secevents.py) are counted per source address across the
  whole fleet. An address with THRESHOLD failures within MINUTES is a candidate - one guessing at one router is
  usually guessing at all of them.
- Mode **audit** lists candidates (block them by hand); **block** blocks them as soon as they cross the threshold.
- Blocking adds the address to the address list LIST on every router, with a RouterOS timeout (default 72 hours), so a
  router forgets it on its own even if TikManager is gone. Routers that were offline get it when they're back.
  TikManager never changes firewall rules by itself: each router needs one rule that drops LIST (the Security page
  shows which routers lack it and can add it - a raw prerouting drop for the list).
- Never blocked: private, loopback and link-local addresses, TikManager's own addresses, and the whitelist.
"""
import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from routeros import RouterError

LIST = "tikmanager-blocklist"
COMMENT = "TikManager auto-block"
RULE = {"chain": "prerouting", "action": "drop", "src-address-list": LIST, "comment": COMMENT}
DEFAULTS = {"mode": "off", "threshold": 5, "minutes": 10, "hours": 72, "whitelist": [],
            "auto_rule": True}   # add the drop rule to routers that lack it whenever something is blocked (else they only list it)
KEEP_DAYS = 30


def timeout_text(seconds: float) -> str:
    """RouterOS timeout: 259200 -> '3d0h0m'."""
    s = max(60, int(seconds))
    return f"{s // 86400}d{s % 86400 // 3600}h{s % 3600 // 60}m"


class AutoBlock:
    def __init__(self, db, settings, client, secev):
        self.db, self.s, self.client, self.secev = db, settings, client, secev
        self.lock = threading.Lock()
        self.rules = {}   # device id -> (checked at, has a rule dropping LIST)

    # --- settings ---------------------------------------------------------------------------------------------
    def settings(self) -> dict:
        try:
            saved = json.loads(self.db.setting("autoblock", "") or "{}")
        except ValueError:
            saved = {}
        return {**DEFAULTS, **{k: v for k, v in saved.items() if k in DEFAULTS}}

    def save(self, b: dict) -> dict:
        cur = self.settings()
        if b.get("mode") not in ("off", "audit", "block"):
            raise ValueError("Pick off, audit or block.")
        try:
            th, mins, hours = int(b.get("threshold")), int(b.get("minutes")), int(b.get("hours"))
        except (TypeError, ValueError):
            raise ValueError("Enter whole numbers.") from None
        if not (2 <= th <= 1000 and 1 <= mins <= 1440 and 1 <= hours <= 24 * 30):
            raise ValueError("Failures 2-1000, within 1-1440 minutes, block for 1-720 hours.")
        wl = []
        for x in str(b.get("whitelist") or "").replace(",", "\n").split("\n"):
            x = x.strip()
            if not x:
                continue
            try:
                wl.append(str(ipaddress.ip_network(x, strict=False)))
            except ValueError:
                raise ValueError(f"Not an address or network: {x}") from None
        cur.update(mode=b["mode"], threshold=th, minutes=mins, hours=hours, whitelist=wl[:500], auto_rule=bool(b.get("auto_rule", True)))
        self.db.set_setting("autoblock", json.dumps(cur))
        return cur

    def protected(self, ip: str, cfg) -> str:
        """Why an address must never be blocked ('' = it may be)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return "not an address"
        if not a.is_global:   # private, CGNAT, loopback, link-local, documentation, reserved ...
            return "not a public address"
        own = {getattr(self.s, "wg_server_ip", "")}
        own |= {d["public_ip"] for d in self.db.q("SELECT DISTINCT public_ip FROM devices WHERE public_ip IS NOT NULL")}   # routers' own WAN addresses
        if ip in own:
            return "TikManager or one of your routers"
        for n in cfg["whitelist"]:
            try:
                if a in ipaddress.ip_network(n, strict=False):
                    return "whitelist"
            except ValueError:
                continue
        return ""

    # --- what's happening ---------------------------------------------------------------------------------------
    def candidates(self, cfg) -> list:
        rows = self.db.q("""SELECT ip, COUNT(*) AS failures, MIN(ts) AS first, MAX(ts) AS last, COUNT(DISTINCT device_id) AS routers,
                            GROUP_CONCAT(DISTINCT user) AS users FROM sec_events
                            WHERE source='router' AND kind='login_failed' AND ip <> '' AND ts > ?
                            GROUP BY ip HAVING COUNT(*) >= ? ORDER BY failures DESC LIMIT 500""",
                         (time.time() - cfg["minutes"] * 60, cfg["threshold"]))
        out = []
        for r in rows:
            why = self.protected(r["ip"], cfg)
            out.append({**r, "users": (r["users"] or "").split(",")[:8], "protected": why})
        return out

    def active(self) -> list:
        return self.db.q("SELECT * FROM autoblock WHERE released_at IS NULL AND until > ? ORDER BY blocked_at DESC", (time.time(),))

    def block(self, ip: str, by: str, failures=0, reason=""):
        cfg = self.settings()
        why = self.protected(ip, cfg)
        if why:
            raise ValueError(f"{ip} can't be blocked: {why}.")
        now = time.time()
        self.db.run("""INSERT INTO autoblock (ip, blocked_at, until, failures, by, reason) VALUES (?,?,?,?,?,?)
                       ON CONFLICT(ip) DO UPDATE SET blocked_at=excluded.blocked_at, until=excluded.until, failures=excluded.failures,
                       by=excluded.by, reason=excluded.reason, released_at=NULL""", (ip, now, now + cfg["hours"] * 3600, failures, by, reason))
        self.db.run("DELETE FROM autoblock_push WHERE ip=?", (ip,))
        self.secev.record("router", "banned", "", ip, "auto-block", f"blocked on every router for {cfg['hours']} h ({reason or by})")
        self.db.audit(by, "address blocked on all routers", ip, detail=reason)

    def release(self, ip: str, by: str) -> int:
        """Unblock: released at once (it leaves the list and isn't pushed again); taken off the routers it was put on in
        the background, 8 at a time. Returns how many routers it's being removed from."""
        self.db.run("UPDATE autoblock SET released_at=? WHERE ip=? AND released_at IS NULL", (time.time(), ip))
        rows = self.db.q("""SELECT p.device_id, d.* FROM autoblock_push p JOIN devices d ON d.id = p.device_id
                            WHERE p.ip=? AND p.error IS NULL""", (ip,))
        self.db.run("DELETE FROM autoblock_push WHERE ip=?", (ip,))
        self.db.audit(by, "address unblocked on all routers", ip)
        self.secev.record("router", "unbanned", "", ip, "auto-block", f"unblocked by {by}")
        threading.Thread(target=self._remove_everywhere, args=(ip, rows), daemon=True, name="autoblock-release").start()
        return len(rows)

    def _remove_everywhere(self, ip, rows):
        def one(p):
            try:
                cl = self.client(p)
                for e in cl.al_find(LIST, ip):
                    cl.fw_remove("address-list", e[".id"])
            except RouterError as e:   # offline / unreachable: the entry expires there by itself (it has a timeout)
                self.db.event(p["id"], p.get("org_id"), "auto-block", f"Couldn't take {ip} off the block list ({str(e)[:150]}) - it expires there by itself")
        with ThreadPoolExecutor(8) as ex:
            list(ex.map(one, rows))

    def push(self):
        """Put every active block on every online router that doesn't have it yet."""
        blocks = self.active()
        if not blocks:
            return
        routers = self.db.q("SELECT * FROM devices WHERE state='adopted' AND online=1")
        done = {(r["ip"], r["device_id"]) for r in self.db.q("SELECT ip, device_id FROM autoblock_push WHERE error IS NULL")}
        now = time.time()
        for d in routers:
            todo = [b for b in blocks if (b["ip"], d["id"]) not in done]
            if not todo:
                continue
            cl = self.client(d)
            for b in todo:
                err = None
                try:
                    cl.fw_add("address-list", {"list": LIST, "address": b["ip"], "timeout": timeout_text(b["until"] - now), "comment": COMMENT})
                except RouterError as e:
                    if "already have" not in str(e):
                        err = str(e)[:200]
                        if "Unreachable" in str(e):
                            break   # the router just went away: next round
                self.db.run("INSERT OR REPLACE INTO autoblock_push (ip, device_id, pushed_at, error) VALUES (?,?,?,?)", (b["ip"], d["id"], now, err))

    def rule_status(self, max_age=1800) -> dict:
        """{device id: True/False/None} - does the router have a rule dropping LIST (None = not checked / offline)."""
        devs = self.db.q("SELECT * FROM devices WHERE state='adopted'")

        def check(d):
            at, ok = self.rules.get(d["id"], (0, None))
            if d["online"] and time.time() - at > max_age:
                try:
                    cl = self.client(d)
                    rules = (cl.fw_rules("raw") or []) + (cl.fw_rules("filter") or [])
                    ok = any(r.get("src-address-list") == LIST and r.get("action") in ("drop", "reject", "tarpit") and r.get("disabled") != "true"
                             for r in rules)
                    self.rules[d["id"]] = (time.time(), ok)
                except RouterError:
                    ok = None
            return d["id"], ok
        with ThreadPoolExecutor(max_workers=16) as pool:
            return dict(pool.map(check, devs))

    def add_rule(self, d: dict, by: str):
        """Add the raw prerouting drop for LIST to one router (only drops what's on the list)."""
        cl = self.client(d)
        if any(r.get("src-address-list") == LIST for r in cl.fw_rules("raw") or []):
            self.rules[d["id"]] = (time.time(), True)
            return
        cl.fw_add("raw", RULE)
        self.rules[d["id"]] = (time.time(), True)
        self.db.audit(by, "auto-block drop rule added", d["name"], org_id=d.get("org_id"))
        self.db.event(d["id"], d.get("org_id"), "firewall", f"Auto-block rule added (raw drop src-address-list={LIST}) by {by}")

    def ensure_rules(self):
        """With something blocked and auto_rule on: add the drop rule to every online router that doesn't drop the list
        yet (a router without it only lists the address - the block does nothing there)."""
        if not self.settings().get("auto_rule", True) or not self.active():
            return
        devs = {d["id"]: d for d in self.db.q("SELECT * FROM devices WHERE state='adopted' AND online=1")}
        for did, ok in self.rule_status().items():
            if ok is False and did in devs:
                try:
                    self.add_rule(devs[did], "auto-block")
                except RouterError as e:
                    self.db.event(did, devs[did].get("org_id"), "auto-block", f"Couldn't add the auto-block drop rule: {str(e)[:150]}")

    def run_once(self):
        with self.lock:
            cfg = self.settings()
            now = time.time()
            if cfg["mode"] == "block":
                blocked = {b["ip"] for b in self.active()}
                # unblocked by hand within the window: leave it (its old failures are still being counted)
                blocked |= {r["ip"] for r in self.db.q("SELECT ip FROM autoblock WHERE released_at > ?", (now - cfg["minutes"] * 60,))}
                for c in self.candidates(cfg):
                    if not c["protected"] and c["ip"] not in blocked:
                        try:
                            self.block(c["ip"], "auto-block", c["failures"],
                                       f"{c['failures']} failed sign-ins on {c['routers']} router(s) in {cfg['minutes']} min")
                        except ValueError:
                            pass
            if cfg["mode"] != "off":
                self.push()
                self.ensure_rules()
            self.db.run("DELETE FROM autoblock WHERE (until < ? OR released_at IS NOT NULL) AND COALESCE(released_at, until) < ?",
                        (now, now - KEEP_DAYS * 86400))
            self.db.run("DELETE FROM autoblock_push WHERE ip NOT IN (SELECT ip FROM autoblock WHERE released_at IS NULL AND until > ?)", (now,))

    def blocks(self) -> dict:
        """Addresses on the block list now: {ip: {routers: put on, enforced: of those, the ones with a rule that drops the
        list (last known - see rule_status), total}}. Without the rule a router only lists the address."""
        on = {}
        for r in self.db.q("SELECT ip, device_id FROM autoblock_push WHERE error IS NULL"):
            on.setdefault(r["ip"], set()).add(r["device_id"])
        total = self.db.one("SELECT COUNT(*) AS n FROM devices WHERE state='adopted'")["n"]
        return {b["ip"]: {"routers": len(on.get(b["ip"], ())), "total": total,
                          "enforced": sum(1 for i in on.get(b["ip"], ()) if self.rules.get(i, (0, None))[1])} for b in self.active()}

    def info(self, rule_check=True) -> dict:
        cfg = self.settings()
        rules = self.rule_status() if rule_check and cfg["mode"] != "off" else {}
        names = {d["id"]: d for d in self.db.q("SELECT id, name, org_id, online FROM devices WHERE state='adopted'")}
        pushed = {}
        for r in self.db.q("SELECT ip, COUNT(*) AS n FROM autoblock_push WHERE error IS NULL GROUP BY ip"):
            pushed[r["ip"]] = r["n"]
        return {"settings": cfg, "list": LIST, "candidates": self.candidates(cfg), "routers_total": len(names),
                "blocked": [{**b, "routers": pushed.get(b["ip"], 0), "enforced": self.blocks().get(b["ip"], {}).get("enforced", 0)} for b in self.active()],
                "recent": self.db.q("SELECT * FROM autoblock WHERE released_at IS NOT NULL OR until <= ? ORDER BY COALESCE(released_at, until) DESC LIMIT 50",
                                    (time.time(),)),
                "no_rule": [{"id": i, "name": names[i]["name"]} for i, ok in rules.items() if ok is False and i in names],
                "rule_unknown": sum(1 for ok in rules.values() if ok is None)}

    def loop(self):
        time.sleep(60)
        while True:
            try:
                self.run_once()
            except Exception as e:
                print(f"autoblock: {e}")
            time.sleep(60)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="autoblock").start()
