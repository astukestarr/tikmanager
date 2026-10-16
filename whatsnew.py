"""What's new: a short tour of everything since the last full release, shown once per person when they open TikManager.

Each slide has an id; a person's "seen" ids are kept in their preferences (users.prefs "whatsnew"). The tour shows the
slides they haven't seen - so a later beta's new slides show up on their own - and **Got it - don't show again** marks
them all seen. The record is keyed by the release and whether it's a beta, so installing a new full (stable) release
starts afresh. When RELEASE doesn't match the running version (slides not written for it yet), nothing is shown.

Screenshots live in static/whatsnew/ (taken from dev mode's simulated routers - no real client data).
"""
import re
from pathlib import Path

from version import __version__

RELEASE = "1.46.0"   # the release these slides describe (its betas included)
SINCE = "1.45.1"     # the full release before it

# id, title, text, screenshot (static/whatsnew/<img>.jpg) or None, where "Show me" goes (a page) or None, who: tech / all
SLIDES = [
    {"id": "health-dash", "title": "Performance & security dashboard", "img": "dashboard", "view": "health", "who": "tech",
     "text": "Monitoring > Performance & security checks every router for internet problems, performance, open ports and "
             "exposed services, weak encryption and old VPN types (PPTP, L2TP without IPsec), VPNs that are down, updates "
             "and CVEs, backups and hygiene - worst first, each with how to fix it. It uses what TikManager already reads."},
    {"id": "one-click-fixes", "title": "One-click fixes", "img": "fixes", "view": "health", "who": "tech",
     "text": "Findings that come down to one setting get a Fix button, and Fix all does every router shown. Each router is "
             "backed up first, only that one setting is changed, and the router is re-checked. Fixes that touch how "
             "TikManager reaches the router (like limiting WebFig) arm an undo on the router that puts things back by "
             "itself if TikManager loses contact."},
    {"id": "fix-progress", "title": "Watch fixes run - and copy the results", "img": "progress", "view": "health", "who": "tech",
     "text": "Fix all runs in the background, up to 6 routers at a time, with each router's step (backing up, changing, "
             "re-checking) and the reason when one fails. Copy failures / Copy results gives you the list as text for a "
             "ticket or an email. It keeps running if you leave the page."},
    {"id": "accept-findings", "title": "Accept a finding", "img": "accept", "view": "health", "who": "tech",
     "text": "When something isn't a problem on a particular router - say FTP that backs up the switches, with port 21 "
             "blocked from the internet - choose Accept and give the reason. It leaves the list and the fixes, and shows in "
             "compliance reports as met with a documented exception. Show accepted brings it back, with Undo."},
    {"id": "compliance", "title": "Compliance: CIS v8, NIST 800-171, PCI DSS 4.0, HIPAA", "img": "compliance", "view": "compliance",
     "who": "tech",
     "text": "Monitoring > Compliance scores the routers against the network-device controls of four frameworks, for all "
             "clients or one, with the evidence for every control (firewall default deny, encrypted management, VPN crypto, "
             "default accounts, central logging, NTP, firmware, backups...). Details shows each router; Accept records an "
             "exception."},
    {"id": "client-report", "title": "A report to hand the client", "img": "report", "view": "compliance", "who": "tech",
     "text": "Client report (PDF) opens a report with your company name and logo - score, scope (evidence for these "
             "controls, not a certification), each router, every control with its evidence, a remediation plan and the "
             "documented exceptions. Print it or save it as PDF. CSV for auditors has every check."},
    {"id": "https-mgmt", "title": "Manage routers over HTTPS", "img": "https", "view": "health", "who": "tech",
     "text": "Switch to HTTPS (router > Settings, or Fix all) moves TikManager's own connection to www-ssl - keeping the "
             "port and certificate a router already has, moving to 8443 when SSTP holds 443, and never leaving www-ssl "
             "open to the internet. It switches only after HTTPS answers, and falls back to HTTP if HTTPS ever stops. Then "
             "WebFig over plain HTTP can be turned off."},
    {"id": "remote-access", "title": "Remote access with WireGuard for Windows", "img": "remote-setup", "view": "routers", "who": "tech",
     "text": "An SSTP replacement on each router's Remote access tab: people connect with the free WireGuard app. Set the "
             "address (or the router's MikroTik Cloud DNS name), the networks they reach and the office DNS - with the "
             "domain, so names like fileserver and corp.local work. The warnings box covers handing out access safely."},
    {"id": "remote-people", "title": "Per-person access, expiry and an RMM install script", "img": "remote-people", "view": "routers",
     "who": "tech",
     "text": "Limit each person to certain servers and services (one file server over SMB, one web app over HTTPS) - the "
             "router enforces it. Give temps an expiry date, Disable someone for now, Revoke for good. Hand out access with "
             "the RMM install script (it installs WireGuard and the tunnel as a service, so nobody handles a key file) or "
             "a one-time .conf download."},
    {"id": "remote-log", "title": "Connection log and unusual-connection alerts", "img": "remote-log", "view": "routers", "who": "tech",
     "text": "Who connected, when, from where and for how long - kept 400 days, with Export CSV for auditors. A connection "
             "from an address someone has never used, or one person's key used from two places at once, is flagged and "
             "raises an alert."},
    {"id": "router-vpns", "title": "Every VPN on the router page", "img": "vpns", "view": "routers", "who": "tech",
     "text": "Each router has a VPNs tab: every VPN on it with its status, the far end (linked when it's another of your "
             "routers), networks or users and traffic - with Restart tunnel and Read again - plus who's connected through "
             "remote access."},
    {"id": "smaller", "title": "Smaller improvements", "img": None, "view": None, "who": "tech",
     "text": "UniFi / UISP: a Match filter (matched, not matched, chosen by hand). Router location: paste coordinates "
             "straight from Google Maps (39.2103, -96.4870). Security > Worth a look > show now jumps to the matching "
             "events. Router pages no longer scroll sideways on narrow screens. RouterOS 7.20's renamed \"available-from\" "
             "is understood everywhere."},
]
IDS = {s["id"] for s in SLIDES}

# Every release's tour stays here, so Admin > Settings > Version & updates can show past ones. When a new release line
# starts, add its tour as a new entry (keep its screenshots under their own names) and point RELEASE / SINCE / SLIDES at it.
TOURS = {"1.46.0": {"since": "1.45.1", "slides": SLIDES}}
CHANGELOG = Path(__file__).resolve().parent / "CHANGELOG.md"
STABLE = re.compile(r"^## (\d+)\.(\d+)\.(\d+)(?: - (\S+))?\s*$")


def _blocks(lines):
    """A changelog section -> [{kind: p|li, text}] (bullets joined with their continuation lines; markdown left as text)."""
    out = []
    for line in lines:
        s = line.rstrip()
        if not s.strip():
            if out and out[-1]["kind"] == "p" and out[-1]["text"]:
                out.append({"kind": "p", "text": ""})   # paragraph break
            continue
        if s.startswith("- "):
            out.append({"kind": "li", "text": s[2:].strip()})
        elif s.startswith("  ") and out and out[-1]["kind"] == "li":
            out[-1]["text"] += " " + s.strip()
        elif out and out[-1]["kind"] == "p" and out[-1]["text"]:
            out[-1]["text"] += " " + s.strip()
        else:
            if out and out[-1]["kind"] == "p" and not out[-1]["text"]:
                out.pop()
            out.append({"kind": "p", "text": s.strip()})
    return [b for b in out if b["text"]]


def _vt(v):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?", v)
    return (int(m[1]), int(m[2]), int(m[3]), 0 if m[4] else 1, int(m[4] or 0)) if m else (0,)


def history(lines=6):
    """The newest full-release lines up to the installed version (this one and the 5 before it), newest first:
    [{line: "1.46", tour: "1.46.0" or None, releases: [{version, date, blocks}]}] - from the CHANGELOG.md this
    installation shipped with, so it works offline. Betas are left out (their changes are summed up in the release)."""
    try:
        text = CHANGELOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    sections, cur = [], None
    for line in text:
        if line.startswith("## "):
            m = STABLE.match(line)
            cur = {"version": ".".join(m.group(1, 2, 3)), "date": m.group(4) or "", "lines": []} if m else None
            if cur:
                sections.append(cur)
        elif cur is not None:
            cur["lines"].append(line)
    mine = _vt(__version__)
    out = []
    for sec in sections:
        if _vt(sec["version"]) > mine:
            continue
        line_id = ".".join(sec["version"].split(".")[:2])
        if not out or out[-1]["line"] != line_id:
            if len(out) == lines:
                break
            tour = next((r for r in TOURS if r.startswith(line_id + ".")), None)
            out.append({"line": line_id, "tour": tour, "releases": []})
        out[-1]["releases"].append({"version": sec["version"], "date": sec["date"], "blocks": _blocks(sec["lines"])})
    return out


def tour(release, kind):
    """A past release's tour, to look at again (nothing is marked seen)."""
    t = TOURS.get(release)
    if not t:
        return None
    return {"release": release, "since": t["since"], "version": __version__, "history": True,
            "slides": [s for s in t["slides"] if s["who"] == "all" or kind == "tech"], "unseen": []}


def key():
    """What a person's "seen" record belongs to: the release, and whether it's still in beta (a full release resets)."""
    return __version__ if "-" not in __version__ else __version__.split("-")[0] + "-beta"


def active():
    return __version__.split("-")[0] == RELEASE


def for_person(kind, saved):
    """The tour for this person: {release, since, slides, unseen}. saved: their prefs["whatsnew"] ({key, seen})."""
    slides = [s for s in SLIDES if s["who"] == "all" or kind == "tech"] if active() else []
    seen = set((saved or {}).get("seen") or []) if (saved or {}).get("key") == key() else set()
    return {"release": RELEASE, "since": SINCE, "version": __version__, "slides": slides,
            "unseen": [s["id"] for s in slides if s["id"] not in seen]}


def mark_seen(saved, ids):
    seen = set((saved or {}).get("seen") or []) if (saved or {}).get("key") == key() else set()
    return {"key": key(), "seen": sorted((seen | set(ids)) & IDS)}
