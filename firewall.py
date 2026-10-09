"""Firewall filter and NAT rules on a router, changed with a safety net - like RouterOS Safe Mode.

- Safe Mode belongs to an interactive Winbox / terminal session; the REST API TikManager uses has none, so it does the
  same thing itself: before the first change it stores a script on the router that puts the filter and NAT rules back
  exactly as they were, and a scheduler that runs it in TEST_MINUTES. Each further change restarts the clock.
- After every change TikManager checks it can still reach the router. The person then presses Keep (the scheduler and
  script are removed) or Undo (the script runs now). If nobody keeps it in time - or the change cut TikManager off -
  the router puts the rules back by itself.
- Before the first change of a test the router is backed up (unless it was in the last 10 minutes); a failed backup
  stops the change.
- Rules TikManager depends on are read-only here: its own (comment starting "TikManager" - the management rule and the
  site-to-site VPN rules) and dynamic rules (made by RouterOS / other services).
- Only the fields below can be set; other fields a rule already has are left alone.
"""
import re
import threading
import time

from routeros import RouterError

SECTIONS = ("filter", "nat")
UNDO_NAME = "tikmanager-fw-undo"
TEST_MINUTES = 5
BACKUP_FRESH = 600

ACTIONS = {
    "filter": ["accept", "drop", "reject", "jump", "return", "passthrough", "log", "fasttrack-connection",
               "add-src-to-address-list", "add-dst-to-address-list", "tarpit"],
    "nat": ["masquerade", "src-nat", "dst-nat", "redirect", "netmap", "accept", "return", "jump", "passthrough", "log",
            "same", "endpoint-independent-nat"],
}
COMMON = ["chain", "action", "protocol", "src-address", "dst-address", "src-port", "dst-port", "in-interface",
          "out-interface", "in-interface-list", "out-interface-list", "src-address-list", "dst-address-list",
          "connection-state", "connection-nat-state", "jump-target", "log", "log-prefix", "comment", "disabled"]
FIELDS = {"filter": COMMON + ["reject-with", "address-list", "address-list-timeout"],
          "nat": COMMON + ["to-addresses", "to-ports"]}

ADDR = r"!?[0-9A-Fa-f.:/,\-]+"
FORMATS = {   # field -> (pattern, what to type)
    "chain": (r"[A-Za-z0-9_\-]{1,40}", "a chain name (input, forward, output, srcnat, dstnat or your own)"),
    "protocol": (r"!?[a-z0-9\-]{1,20}", "a protocol (tcp, udp, icmp ...) or number"),
    "src-address": (ADDR, "an address, range or subnet (192.168.1.0/24, 10.0.0.1-10.0.0.9)"),
    "dst-address": (ADDR, "an address, range or subnet (192.168.1.0/24, 10.0.0.1-10.0.0.9)"),
    "src-port": (r"!?[0-9,\-]{1,100}", "ports (80, 443, 8000-8100)"),
    "dst-port": (r"!?[0-9,\-]{1,100}", "ports (80, 443, 8000-8100)"),
    "to-addresses": (r"[0-9A-Fa-f.:/\-]{1,100}", "an address or range"),
    "to-ports": (r"[0-9\-]{1,20}", "a port or range"),
    "connection-state": (r"!?[a-z,\-]{1,100}", "states (established, related, new, invalid, untracked)"),
    "connection-nat-state": (r"!?[a-z,\-]{1,40}", "srcnat and/or dstnat"),
    "address-list-timeout": (r"[0-9a-z:]{1,20}", "a time (none-dynamic, 1d, 00:30:00)"),
    "log": (r"true|false", "yes or no"),
    "disabled": (r"true|false", "yes or no"),
}
LIMITS = {"comment": 200, "log-prefix": 50}


class FirewallError(ValueError):
    pass


def protected(rule) -> bool:
    return rule.get("dynamic") == "true" or str(rule.get("comment") or "").startswith("TikManager")


def quote(v) -> str:
    """A value as a RouterOS script string."""
    v = re.sub(r"[\x00-\x1f\x7f]", " ", str(v))
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("?", "\\?") + '"'


def restore_script(rules: dict) -> str:
    """A script that replaces the static filter and NAT rules with `rules` ({section: [rule, ...]}), then removes
    itself and its scheduler."""
    out = []
    for sec in SECTIONS:
        menu = f"/ip firewall {sec}"
        out.append(f"{menu} remove [find where dynamic=no]")
        for r in rules[sec]:
            if r.get("dynamic") == "true":
                continue
            parts = [f"{k}={quote(v)}" for k, v in r.items()
                     if not k.startswith(".") and k not in ("bytes", "packets", "dynamic", "invalid") and v != ""
                     and re.fullmatch(r"[a-z0-9\-]+", k)]
            out.append(f"{menu} add " + " ".join(parts))
    out.append(f'/system scheduler remove [find where name="{UNDO_NAME}"]')
    out.append(f'/system script remove [find where name="{UNDO_NAME}"]')
    return "\n".join(out) + "\n"


def clean(section, raw: dict, adding: bool):
    """The allowed fields of a rule from the browser -> (values to set, fields to clear)."""
    if not isinstance(raw, dict):
        raise FirewallError("No rule given.")
    put, clear = {}, []
    for k, v in raw.items():
        if k not in FIELDS[section]:
            raise FirewallError(f"'{k}' can't be set from TikManager.")
        if isinstance(v, bool):
            v = "true" if v else "false"
        v = str(v if v is not None else "").strip()
        if k in ("log", "disabled"):
            v = {"yes": "true", "no": "false", "": "false"}.get(v.lower(), v.lower())
        if v == "":
            if k in ("chain", "action"):
                raise FirewallError(f"The rule needs a {k}.")
            if not adding:
                clear.append(k)
            continue
        if re.search(r"[\x00-\x1f\x7f]", v) or len(v) > LIMITS.get(k, 100):
            raise FirewallError(f"{k}: too long or contains control characters.")
        if k in FORMATS and not re.fullmatch(FORMATS[k][0], v):
            raise FirewallError(f"{k}: enter {FORMATS[k][1]}.")
        put[k] = v
    if adding and not put.get("chain"):
        raise FirewallError("The rule needs a chain.")
    if "action" in put and put["action"] not in ACTIONS[section]:
        raise FirewallError(f"'{put['action']}' isn't a {section} action.")
    if adding and "action" not in put:
        put["action"] = "accept"
    if put.get("action") == "jump" and not put.get("jump-target"):
        raise FirewallError("A jump rule needs the chain to jump to.")
    if str(put.get("comment", "")).startswith("TikManager"):
        raise FirewallError("Comments starting with 'TikManager' are reserved for TikManager's own rules.")
    return put, clear


def quiet(fn, default=None):
    try:
        return fn()
    except RouterError:
        return default


def describe(section, r) -> str:
    bits = [section, r.get("chain", "?"), r.get("action", "?")]
    for k in ("protocol", "src-address", "dst-address", "dst-port", "in-interface", "in-interface-list", "to-addresses", "to-ports"):
        if r.get(k):
            bits.append(f"{k}={r[k]}")
    if r.get("comment"):
        bits.append(f'"{r["comment"]}"')
    return " ".join(bits)


class Firewall:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.pending = {}   # device id -> {"until", "by", "changes": [...]}
        self.busy = set()
        self.lock = threading.Lock()

    def _pending(self, d, r=None):
        p = self.pending.get(d["id"])
        if p and p["until"] < time.time() - 30:   # the router has put the rules back by itself
            self.pending.pop(d["id"], None)
            self.db.event(d["id"], d["org_id"], "firewall change undone", "not kept in time - the router restored the rules")
            p = None
        if not p and r is not None and quiet(lambda: r.undo_armed(UNDO_NAME), False):
            # armed before TikManager restarted: it still runs unless kept
            p = self.pending[d["id"]] = {"until": None, "by": "", "changes": ["changes made before TikManager restarted"]}
        return p

    def view(self, d) -> dict:
        r = self.client_for(d)
        try:
            rules = {sec: r.fw_rules(sec) for sec in SECTIONS}
        except RouterError as e:
            raise FirewallError(f"Couldn't read the firewall: {e}") from None
        for sec in SECTIONS:
            for x in rules[sec]:
                x["protected"] = protected(x)
        p = self._pending(d, r)
        return {**rules, "pending": p and {**p, "seconds": None if p["until"] is None else max(0, int(p["until"] - time.time()))},
                "actions": ACTIONS, "fields": FIELDS, "test_minutes": TEST_MINUTES}

    def change(self, d, user, b) -> dict:
        """One change (add / edit / remove / enable / disable / move) as part of a test."""
        sec, op = b.get("section"), b.get("op")
        if sec not in SECTIONS:
            raise FirewallError("Pick filter or NAT.")
        if op not in ("add", "edit", "remove", "enable", "disable", "move"):
            raise FirewallError("Unknown change.")
        with self.lock:
            if d["id"] in self.busy:
                raise FirewallError("Another firewall change on this router is still running.")
            self.busy.add(d["id"])
        try:
            return self._change(d, user, sec, op, b)
        finally:
            self.busy.discard(d["id"])

    def _change(self, d, user, sec, op, b):
        r = self.client_for(d)
        try:
            rules = {s: r.fw_rules(s) for s in SECTIONS}
        except RouterError as e:
            raise FirewallError(f"Couldn't read the firewall: {e}") from None
        ids = {x[".id"]: x for x in rules[sec]}

        def rule(key):
            rid = str(b.get(key) or "")
            if rid not in ids:
                raise FirewallError("That rule no longer exists - refresh the list.")
            return ids[rid]

        target, before = None, None
        if op != "add":
            target = rule("id")
            if protected(target):
                raise FirewallError("TikManager's own rules and dynamic rules can't be changed here.")
        if b.get("before"):
            before = rule("before")
            if before is target:
                raise FirewallError("Pick a different position.")
        put, clear = clean(sec, b.get("rule") or {}, op == "add") if op in ("add", "edit") else ({}, [])
        if op == "edit" and not put and not clear:
            raise FirewallError("Nothing changed.")

        p = self._pending(d, r)
        first = p is None
        if first:   # start a test: backup, then arm the undo with the rules as they are now
            if (time.time() - (d["last_backup_at"] or 0)) > BACKUP_FRESH:
                res = self.backups.run(d["id"], "pre-firewall", user)
                if not res.get("ok"):
                    raise FirewallError(f"Couldn't back up the router first, so nothing was changed: {res.get('detail')}")
            script = restore_script(rules)
            if len(script) > 60000:
                raise FirewallError("This router has too many rules for TikManager's automatic undo - change them in Winbox with Safe Mode.")
            try:
                r.undo_arm(UNDO_NAME, script, f"{TEST_MINUTES}m")
            except RouterError as e:
                raise FirewallError(f"Couldn't set up the automatic undo, so nothing was changed: {e}") from None
            p = {"until": 0, "by": user, "changes": []}
        else:
            try:
                r.undo_arm(UNDO_NAME, None, f"{TEST_MINUTES}m")   # restart the clock
            except RouterError as e:
                raise FirewallError(f"Couldn't restart the automatic undo, so nothing was changed: {e}") from None

        before_txt = describe(sec, target) if target else ""
        try:
            if op == "add":
                new = r.fw_add(sec, put, before and before[".id"]) or {}
                summary = f"added {describe(sec, put)}"
            elif op == "edit":
                if put:
                    r.fw_set(sec, target[".id"], put)
                if clear:
                    r.fw_unset(sec, target[".id"], clear)
                summary = f"edited {before_txt} -> {describe(sec, {**{k: v for k, v in target.items() if k not in clear}, **put})}"
            elif op == "remove":
                r.fw_remove(sec, target[".id"])
                summary = f"removed {before_txt}"
            elif op in ("enable", "disable"):
                r.fw_set(sec, target[".id"], {"disabled": "false" if op == "enable" else "true"})
                summary = f"{op}d {before_txt}"
            else:
                r.fw_move(sec, target[".id"], before and before[".id"])
                summary = f"moved {before_txt} " + (f"above {describe(sec, before)}" if before else "to the end")
        except RouterError as e:
            if first:   # nothing changed: drop the undo again
                quiet(lambda: r.undo_cancel(UNDO_NAME))
            else:
                p["until"] = time.time() + TEST_MINUTES * 60
            raise FirewallError(f"The router didn't accept it: {e}") from None

        p["until"] = time.time() + TEST_MINUTES * 60
        p["changes"].append(summary)
        self.pending[d["id"]] = p
        try:
            reachable = bool(r.alive())
        except RouterError:
            reachable = False
        return {"ok": True, "summary": summary, "reachable": reachable, "first": first,
                "pending": {**p, "seconds": TEST_MINUTES * 60}}

    def keep(self, d, user) -> list:
        p = self._pending(d, self.client_for(d))
        if not p:
            raise FirewallError("There's nothing waiting to be kept (the test may have run out and been undone).")
        try:
            self.client_for(d).undo_cancel(UNDO_NAME)
        except RouterError as e:
            raise FirewallError(f"Couldn't reach the router to keep the changes - it will undo them by itself: {e}") from None
        self.pending.pop(d["id"], None)
        return p["changes"]

    def undo(self, d, user) -> list:
        p = self._pending(d, self.client_for(d))
        if not p:
            raise FirewallError("There's nothing to undo.")
        try:
            self.client_for(d).undo_run(UNDO_NAME)
        except RouterError as e:
            raise FirewallError(f"Couldn't reach the router - it will undo the changes by itself when the timer runs out: {e}") from None
        self.pending.pop(d["id"], None)
        return p["changes"]
