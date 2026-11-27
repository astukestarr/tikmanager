"""A scrubbed diagnostics bundle a user can send in for support without exposing anything that identifies - or could be
used to attack - their routers.

The problem it solves: when something goes wrong (a false 'update failure', say), the only way to show it today is a
screenshot, which leaks the public WAN IP, the serial number, the overlay address and the site name. This builds a small
JSON bundle instead, on an **allowlist**: only fields known to be safe and useful are collected, so a column added later
can never leak by accident. Identifiers that must stay (to tell one router from another, or to see the same one reporting
twice) are replaced by a **salted one-way hash** - a stable pseudonym like `router-7f3a2c`. The salt lives on this
instance only, so:
  - within a bundle, two fields that shared a value still line up,
  - the same router is the same pseudonym across repeat submissions from this instance (so "it happened again" is
    visible) - without anyone learning which router it is,
  - nothing correlates across different instances, and nothing can be reversed to the real value.

Anything with no debugging value and real exposure - public/WAN/tunnel IPs, MACs, WireGuard keys, the interface and
neighbour tables - is dropped outright, not hashed. Credentials, tokens and keys are simply never on the allowlist.
Version numbers are kept: they're needed to debug an upgrade and don't identify a site on their own (coarsen them before
posting one in public).
"""
import hashlib
import hmac
import re
import secrets
import time

SCHEMA = 1

# One regex sweep over any free-text field (event/upgrade detail) that might have an address or a name baked in. The
# structured fields are allowlisted; this is defence in depth for the text ones.
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?\b")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")


def _salt(db):
    """A random per-instance salt, created once and kept on this instance only. Nothing leaves without it, and it can't
    be derived from the bundle - so the pseudonyms are stable here but meaningless anywhere else."""
    s = db.setting("diag_salt")
    if not s:
        s = secrets.token_hex(16)
        db.set_setting("diag_salt", s)
    return s.encode()


def _digest(salt, kind, value):
    return hmac.new(salt, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def pseudo(salt, kind, value):
    """A stable pseudonym for an identifier, e.g. router-7f3a2c. Empty values stay empty (nothing to hide)."""
    value = ("" if value is None else str(value)).strip()
    if not value:
        return None
    return f"{kind}-{_digest(salt, kind, value)[:6]}"


def _scrub_text(s, replace):
    """Strip IPs/MACs from a free-text field and swap any known identifier (this router's name, serial, addresses, its
    client's name) for its pseudonym, so the text reads the same way the structured fields do."""
    if not s:
        return s
    out = str(s)
    for literal, tag in replace:   # longest first (done by the caller) so a name inside another isn't half-replaced
        if literal:
            out = re.sub(re.escape(literal), tag, out, flags=re.IGNORECASE)
    out = _MAC.sub("[mac]", out)
    out = _IPV4.sub("[ip]", out)
    out = _IPV6.sub("[ip6]", out)
    return out


def _device_row(salt, d):
    """The allowlisted, scrubbed view of one router: enough to reason about an upgrade, nothing that points at a site."""
    ref = pseudo(salt, "router", d.get("serial") or f"id{d.get('id')}")
    return ref, {
        "ref": ref,
        "client": pseudo(salt, "client", d.get("org_id")),
        "model": d.get("model"),                 # safe and needed - behaviour differs by board
        "board": d.get("board"),
        "device_mode": d.get("dm_mode"),         # advanced / etc.
        "connectivity": d.get("conn_mode"),      # wireguard | direct - config, not a secret
        "has_wan_ip": bool(d.get("wan_ip") or d.get("public_ip")),   # presence only - the address itself is dropped
        "online": bool(d.get("online")),
        "uptime": d.get("uptime"),
        "routeros": d.get("version"),
        "routeros_channel": d.get("ros_channel"),
        "routeros_latest": d.get("ros_latest"),
        "firmware_current": d.get("fw_current"),
        "firmware_upgrade": d.get("fw_upgrade"),
        "factory_version": d.get("fw_factory"),
        "security_target": d.get("sec_target"),
        "sim": bool(d.get("sim")),               # a lab router (test environment), not a customer's
    }


def _replacements(salt, d, ref):
    """Literal strings to scrub out of this device's free text, each mapped to a safe tag. Longest first."""
    org = d.get("org_name")
    pairs = [
        (d.get("name"), ref),
        (d.get("identity"), ref),
        (org, pseudo(salt, "client", d.get("org_id")) or "[client]"),
        (d.get("serial"), ref),
        (d.get("wan_ip"), "[ip]"),
        (d.get("public_ip"), "[ip]"),
        (d.get("tunnel_ip"), "[ip]"),
        (d.get("wg_pubkey"), "[key]"),
    ]
    return sorted([(a, b) for a, b in pairs if a], key=lambda p: -len(str(p[0])))


def build(db, device_id=None, days=30, version=None):
    """Build the bundle. device_id scopes it to one router (the usual case - a specific problem); otherwise it covers
    every adopted router and recent upgrades. Returns a plain dict, ready to show the user and hand off as JSON."""
    salt = _salt(db)
    where, args = ("WHERE d.id=?", (device_id,)) if device_id else ("WHERE d.state='adopted'", ())
    devs = db.q(f"SELECT d.*, o.name AS org_name FROM devices d LEFT JOIN orgs o ON o.id=d.org_id {where} ORDER BY d.id", args)
    rows, refs, repl = [], {}, {}
    for d in devs:
        ref, row = _device_row(salt, d)
        rows.append(row)
        refs[d["id"]] = ref
        repl[d["id"]] = _replacements(salt, d, ref)

    ids = list(refs) or [0]
    qmarks = ",".join("?" * len(ids))
    since = time.time() - days * 86400

    ups = []
    for u in db.q(f"SELECT * FROM upgrades WHERE device_id IN ({qmarks}) AND COALESCE(finished_at, created_at) >= ? "
                  f"ORDER BY created_at DESC LIMIT 200", (*ids, since)):
        r = repl.get(u["device_id"], [])
        ups.append({
            "ref": refs.get(u["device_id"]),
            "status": u["status"], "step": u["step"],
            "from_version": u["from_version"], "to_version": u["to_version"],
            "channel": u["channel"], "firmware": bool(u["firmware"]),
            "detail": _scrub_text(u["detail"], r),
            "created_at": u["created_at"], "scheduled_at": u["scheduled_at"],
            "started_at": u["started_at"], "finished_at": u["finished_at"],
            "by": pseudo(salt, "user", u["created_by"]),
            "batch": pseudo(salt, "batch", u["batch"]),
        })

    evs = []
    for e in db.q(f"SELECT * FROM events WHERE device_id IN ({qmarks}) AND ts >= ? ORDER BY ts DESC LIMIT 400", (*ids, since)):
        r = repl.get(e["device_id"], [])
        evs.append({"ref": refs.get(e["device_id"]), "ts": e["ts"], "kind": e["kind"], "detail": _scrub_text(e["detail"], r)})

    return {
        "schema": SCHEMA,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tikmanager_version": version,
        "scope": "device" if device_id else "all",
        "settings": {
            "install_wait_min": db.setting("upgrade_install_wait_min") or "default (30)",
            "back_wait_min": db.setting("upgrade_back_wait_min") or "default (15)",
            "connectivity_default": db.setting("conn_mode") or "wireguard",
        },
        "note": "Scrubbed: names, serials, keys and MACs are one-way hashed to stable pseudonyms; public/WAN/tunnel IPs "
                "are dropped. No credentials, config or addresses are included.",
        "devices": rows,
        "upgrades": ups,
        "events": evs,
    }
