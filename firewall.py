"""Firewall filter and NAT rules and address lists on a router, changed with a safety net - like RouterOS Safe Mode.

- Safe Mode belongs to an interactive Winbox / terminal session; the REST API TikManager uses has none, so it does the
  same thing itself: before the first change it stores a script on the router that undoes the test, and a scheduler
  that runs it in TEST_MINUTES. Each further change updates the script and restarts the clock.
  - Filter / NAT: the script puts the static rules back exactly as they were before the first rule change.
  - Address lists can be huge (blocklists), so they aren't copied: each change adds its own reverse step (re-add a
    removed entry, remove an added one, set an edited one back), newest first.
- After every change TikManager checks it can still reach the router. The person then presses Keep (the scheduler and
  script are removed) or Undo (the script runs now). If nobody keeps it in time - or the change cut TikManager off -
  the router undoes it by itself.
- Before the first change of a test the router is backed up (unless it was in the last 10 minutes); a failed backup
  stops the change.
- Rules TikManager depends on are read-only here: its own (comment starting "TikManager" - the management rule and the
  site-to-site VPN rules) and dynamic rules (made by RouterOS / other services). Dynamic address-list entries (added by
  rules, with a timeout) can be removed but not edited.
- Only the fields below can be set; other fields a rule already has are left alone.
"""
import re
import threading
import time

from routeros import RouterError

SECTIONS = ("filter", "nat")
ALIST = "address-list"
UNDO_NAME = "tikmanager-fw-undo"
TEST_MINUTES = 5
BACKUP_FRESH = 600
MAX_SCRIPT = 60000

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
          "nat": COMMON + ["to-addresses", "to-ports"],
          ALIST: ["list", "address", "timeout", "comment", "disabled"]}

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
LIST_NAME = r"[^\x00-\x1f\x7f!\"\\$?][^\x00-\x1f\x7f\"\\$?]{0,62}"
ENTRY_FORMATS = {
    "list": (LIST_NAME, "a list name (no quotes, \\ $ ?; not starting with !)"),
    "address": (r"[0-9A-Za-z.:/\-]{1,253}", "an address, range, subnet or DNS name (203.0.113.7, 10.0.0.0/24, host.example.com)"),
    "timeout": (r"[0-9wdhms:]{1,20}", "a time like 1d, 2h30m or 00:30:00 (blank = permanent)"),
    "disabled": (r"true|false", "yes or no"),
}
LIMITS = {"comment": 200, "log-prefix": 50}
AL_MENU = "/ip firewall address-list"


class FirewallError(ValueError):
    pass


def protected(rule) -> bool:
    return rule.get("dynamic") == "true" or str(rule.get("comment") or "").startswith("TikManager")


def quote(v) -> str:
    """A value as a RouterOS script string."""
    v = re.sub(r"[\x00-\x1f\x7f]", " ", str(v))
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("?", "\\?") + '"'


TRAILER = (f'/system scheduler remove [find where name="{UNDO_NAME}"]\n'
           f'/system script remove [find where name="{UNDO_NAME}"]\n')


def fw_restore(rules: dict) -> str:
    """Script lines that replace the static filter and NAT rules with `rules` ({section: [rule, ...]})."""
    out = []
    for sec in SECTIONS:
        menu = f"/ip firewall {sec}"
        out.append(f"{menu} remove [find where dynamic=no]")
        for r in rules[sec]:
            if r.get("dynamic") == "true":
                continue
            parts = [f"{k}={quote(v)}" for k, v in r.items()
                     if not k.startswith(".") and k not in ("bytes", "packets", "dynamic", "invalid", "protected") and v != ""
                     and re.fullmatch(r"[a-z0-9\-]+", k)]
            out.append(f"{menu} add " + " ".join(parts))
    return "\n".join(out) + "\n"


def restore_script(rules: dict) -> str:
    return fw_restore(rules) + TRAILER


def entry_args(e) -> str:
    keys = ["list", "address", "comment", "disabled"] + (["timeout"] if e.get("dynamic") == "true" and e.get("timeout") else [])
    return " ".join(f"{k}={quote(e[k])}" for k in keys if e.get(k) not in (None, ""))


def al_inverse(op, target, put):
    """The script line that reverses one address-list change (wrapped so one failure doesn't stop the rest)."""
    if op == "add":
        line = f"{AL_MENU} remove [find where list={quote(put['list'])} and address={quote(put['address'])}]"
    elif op == "remove":
        line = f"{AL_MENU} add {entry_args(target)}"
    elif op in ("enable", "disable"):
        line = f"{AL_MENU} set {target['.id']} disabled={quote(target.get('disabled') or 'false')}"
    else:   # edit
        back = {k: target.get(k) or "" for k in ("list", "address", "comment")}
        back["disabled"] = target.get("disabled") or "false"
        line = f"{AL_MENU} set {target['.id']} " + " ".join(f"{k}={quote(v)}" for k, v in back.items())
    return ":do { " + line + " } on-error={}"


def clean(section, raw: dict, adding: bool):
    """The allowed fields of a rule / address-list entry from the browser -> (values to set, fields to clear)."""
    if not isinstance(raw, dict):
        raise FirewallError("Nothing given.")
    formats = ENTRY_FORMATS if section == ALIST else FORMATS
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
            if k in ("chain", "action", "list", "address"):
                raise FirewallError(f"It needs a {k}.")
            if not adding:
                clear.append(k)
            continue
        if re.search(r"[\x00-\x1f\x7f]", v) or len(v) > LIMITS.get(k, 253 if k == "address" else 100):
            raise FirewallError(f"{k}: too long or contains control characters.")
        if k in formats and not re.fullmatch(formats[k][0], v):
            raise FirewallError(f"{k}: enter {formats[k][1]}.")
        if section == ALIST and k == "address":
            v = re.sub(r"/(32|128)$", "", v)   # RouterOS shows single addresses without /32
        put[k] = v
    if section == ALIST:
        if adding and not (put.get("list") and put.get("address")):
            raise FirewallError("An entry needs a list and an address.")
        return put, clear
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
    if section == ALIST:
        return f"address-list {r.get('list', '?')} {r.get('address', '?')}" + (f' "{r["comment"]}"' if r.get("comment") else "")
    bits = [section, r.get("chain", "?"), r.get("action", "?")]
    for k in ("protocol", "src-address", "src-address-list", "dst-address", "dst-address-list", "dst-port", "in-interface",
              "in-interface-list", "to-addresses", "to-ports"):
        if r.get(k):
            bits.append(f"{k}={r[k]}")
    if r.get("comment"):
        bits.append(f'"{r["comment"]}"')
    return " ".join(bits)


class Firewall:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.pending = {}   # device id -> {"until", "by", "changes": [...], "fw_script", "al_undo": [...]}
        self.busy = set()
        self.lock = threading.Lock()

    def _pending(self, d, r=None):
        p = self.pending.get(d["id"])
        if p and p["until"] is not None and p["until"] < time.time() - 30:   # the router has undone it by itself
            self.pending.pop(d["id"], None)
            self.db.event(d["id"], d["org_id"], "firewall change undone", "not kept in time - the router undid the changes")
            p = None
        if not p and r is not None and quiet(lambda: r.undo_armed(UNDO_NAME), False):
            # armed before TikManager restarted: it still runs unless kept (further changes can't be added to it)
            p = self.pending[d["id"]] = {"until": None, "by": "", "changes": ["changes made before TikManager restarted"],
                                         "fw_script": None, "al_undo": [], "orphan": True}
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
        opts = quiet(r.fw_options, {}) or {}
        pend = p and {k: p[k] for k in ("until", "by", "changes")}
        return {**rules, **{k: opts.get(k, [] if k != "address_list_counts" else {})
                            for k in ("address_lists", "address_list_counts", "interfaces", "interface_lists")},
                "pending": pend and {**pend, "seconds": None if p["until"] is None else max(0, int(p["until"] - time.time()))},
                "actions": ACTIONS, "fields": FIELDS, "test_minutes": TEST_MINUTES}

    def entries(self, d, name) -> list:
        if not re.fullmatch(LIST_NAME, name or ""):
            raise FirewallError("Pick a list.")
        try:
            return self.client_for(d).al_entries(name)
        except RouterError as e:
            raise FirewallError(f"Couldn't read the address list: {e}") from None

    def change(self, d, user, b) -> dict:
        """One change (add / edit / remove / enable / disable / move) as part of a test."""
        sec, op = b.get("section"), b.get("op")
        if sec not in SECTIONS + (ALIST,):
            raise FirewallError("Pick filter, NAT or address lists.")
        if op not in ("add", "edit", "remove", "enable", "disable", "move") or (sec == ALIST and op == "move"):
            raise FirewallError("Unknown change.")
        with self.lock:
            if d["id"] in self.busy:
                raise FirewallError("Another firewall change on this router is still running.")
            self.busy.add(d["id"])
        try:
            return self._change(d, user, sec, op, b)
        finally:
            self.busy.discard(d["id"])

    def _script(self, p, fw_script=None, inverse=None):
        return "\n".join(([inverse] if inverse else []) + p["al_undo"]) + "\n" + (fw_script or p["fw_script"] or "") + TRAILER

    def _change(self, d, user, sec, op, b):
        r = self.client_for(d)
        rules = None
        try:
            if sec == ALIST:
                items = r.al_entries(str(b.get("list") or "")) if op != "add" else []
            else:
                rules = {s: r.fw_rules(s) for s in SECTIONS}
                items = rules[sec]
        except RouterError as e:
            raise FirewallError(f"Couldn't read the firewall: {e}") from None
        ids = {x[".id"]: x for x in items}

        def item(key):
            rid = str(b.get(key) or "")
            if rid not in ids:
                raise FirewallError("That no longer exists - refresh the list.")
            return ids[rid]

        target, before = None, None
        if op != "add":
            target = item("id")
            if sec != ALIST and protected(target):
                raise FirewallError("TikManager's own rules and dynamic rules can't be changed here.")
            if sec == ALIST and target.get("dynamic") == "true" and op != "remove":
                raise FirewallError("Entries added by a rule (dynamic) can only be removed.")
        if b.get("before") and sec != ALIST:
            before = item("before")
            if before is target:
                raise FirewallError("Pick a different position.")
        put, clear = clean(sec, b.get("rule") or {}, op == "add") if op in ("add", "edit") else ({}, [])
        if sec == ALIST and op == "edit":
            clear = [k for k in clear if k in ("comment", "timeout")]
        if op == "edit" and not put and not clear:
            raise FirewallError("Nothing changed.")

        p = self._pending(d, r)
        if p and p.get("orphan"):
            raise FirewallError("A test started before TikManager restarted is still running - press Keep or Undo first.")
        first = p is None
        if first:   # start a test: backup first
            if (time.time() - (d["last_backup_at"] or 0)) > BACKUP_FRESH:
                res = self.backups.run(d["id"], "pre-firewall", user)
                if not res.get("ok"):
                    raise FirewallError(f"Couldn't back up the router first, so nothing was changed: {res.get('detail')}")
            p = {"until": 0, "by": user, "changes": [], "fw_script": None, "al_undo": []}
        fw_new = fw_restore(rules) if sec != ALIST and p["fw_script"] is None else None   # the rules as they are now
        inverse = al_inverse(op, target, put) if sec == ALIST else None
        script = self._script(p, fw_new, inverse)
        if len(script) > MAX_SCRIPT:
            raise FirewallError("This router has too many rules for TikManager's automatic undo - change them in Winbox with Safe Mode.")
        try:
            r.undo_arm(UNDO_NAME, script, f"{TEST_MINUTES}m")   # armed before the change, so it's undone even if we're cut off
        except RouterError as e:
            raise FirewallError(f"Couldn't set up the automatic undo, so nothing was changed: {e}") from None

        before_txt = describe(sec, target) if target else ""
        try:
            if op == "add":
                r.fw_add(sec, put, before and before[".id"])
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
            else:   # put the script back as it was before this attempt
                quiet(lambda: r.undo_arm(UNDO_NAME, self._script(p), f"{TEST_MINUTES}m"))
                p["until"] = time.time() + TEST_MINUTES * 60
            raise FirewallError(f"The router didn't accept it: {e}") from None

        if fw_new:
            p["fw_script"] = fw_new
        if inverse:
            p["al_undo"].insert(0, inverse)
        p["until"] = time.time() + TEST_MINUTES * 60
        p["changes"].append(summary)
        self.pending[d["id"]] = p
        try:
            reachable = bool(r.alive())
        except RouterError:
            reachable = False
        return {"ok": True, "summary": summary, "reachable": reachable, "first": first,
                "pending": {"until": p["until"], "by": p["by"], "changes": p["changes"], "seconds": TEST_MINUTES * 60}}

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
