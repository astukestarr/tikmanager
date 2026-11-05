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

RELEASE = "3.7.0"    # the release these slides describe (its betas included)
SINCE = "3.6.0"      # the full release before it

# id, title, text, screenshot (static/whatsnew/<img>.jpg) or None, where "Show me" goes (a page) or None, who: tech / all
SLIDES_2_0 = [
    {"id": "region-blocking", "title": "Region blocking", "img": "region", "view": "blocking", "who": "tech",
     "text": "Security > Blocking > Region blocking drops new connections from (or to) whole countries on a client's routers - Block or "
             "Allow only, Incoming, Outgoing or Both, like UniFi. Country data comes from IPinfo Lite (free token, updated "
             "daily). TikManager, your routers and addresses your people used in the last 90 days are never blocked."},
    {"id": "region-safe", "title": "Safe on small routers", "img": None, "view": "blocking", "who": "tech",
     "text": "The list lives in router memory only - no flash writes, not in backups - and is loaded a little at a time, slowing "
             "down when the CPU is busy. A router where it would take more than a quarter of its free memory is skipped, and "
             "after a restart the rules wait until TikManager has reloaded the list."},
    {"id": "region-per-router", "title": "Different countries on one router", "img": None, "view": "blocking", "who": "tech",
     "text": "Leave a router out, or let some countries through on just that router (Let through here) - e.g. one site that "
             "works with China and the UK while the client's other sites block them."},
    {"id": "dashboards", "title": "Dashboards", "img": None, "view": "dashboard", "who": "tech",
     "text": "The Dashboard has tabs, like Report Center: Overview, Network, Security and Maintenance. Click any tile to jump "
             "to its list or open the page that deals with it."},
    {"id": "isps", "title": "ISPs and outages", "img": None, "view": "isps", "who": "tech",
     "text": "Network > ISPs: which provider each router's internet links use, and a possible-outage warning (and alert) when "
             "several routers on the same ISP drop together - so you know whether to call the ISP or go to the site."},
    {"id": "critical-checks", "title": "Critical checks", "img": None, "view": "checks", "who": "tech",
     "text": "Monitoring > Critical checks: make sure a client's routers can always reach an address - a server, a phone system, "
             "the far end of a VPN. Every router pings it each minute (with exclusions, tags or chosen routers) and an alert "
             "fires when one can't."},
    {"id": "roles", "title": "Your own technician roles", "img": None, "view": "admin", "who": "tech",
     "text": "Admin > Technicians > Roles: build roles from individual permissions (upgrades, backups, Winbox, firewall changes, "
             "blocking, clients, settings...) and pick the role new Microsoft sign-ins get - or make them wait for you."},
    {"id": "message-center", "title": "Message Center", "img": None, "view": "messages", "who": "all",
     "text": "The bell at the top right counts your unread messages: each new version's release notes and notices from your "
             "administrators. Click one to read it, or acknowledge them all at once in the Message Center."},
    {"id": "phone", "title": "A dashboard for your phone", "img": None, "view": "dashboard", "who": "all",
     "text": "Open TikManager on a phone and the Dashboard shows what needs attention, worst first, with a router search - "
             "one tap to any router. Install it like an app: Android - Chrome menu > Install app; iPhone - Safari > Share > "
             "Add to Home Screen."},
    {"id": "security-menu", "title": "Security has its own menu", "img": None, "view": "blocking", "who": "tech",
     "text": "Security > Sign-ins & events, Blocking, Vulnerabilities and Compliance. Monitoring > Performance & security is "
             "now Router health."},
    {"id": "known-bad", "title": "Block known bad networks", "img": None, "view": "blocking", "who": "tech",
     "text": "One switch per client next to Region blocking: hijacked and criminal networks, botnet controllers and the worst "
             "attackers (Spamhaus DROP + FireHOL Level 1, updated daily) are dropped both ways. A few thousand entries - fine "
             "on every router - with the same safeguards as region blocking."},
    {"id": "flows", "title": "Flows (pilot)", "img": None, "view": "routers", "who": "tech",
     "text": "Router page > Flows: who talks to what - clients, destinations, countries, organisations, services, download and "
             "upload - with filters and CSV, plus what region blocking dropped. Opt-in per router (128 MB or more), sent over "
             "the tunnel with RouterOS Traffic Flow."},
]

SLIDES_1_46 = [
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
SLIDES_3_1 = [
    {"id": "wizards", "title": "Router Wizard", "img": "wgbuild", "view": "wizards", "who": "tech",
     "text": "A new Router Wizard in the sidebar: a page of tiles for guided, step-by-step jobs on your routers. The first is the "
             "WireGuard Builder - more will follow."},
    {"id": "wg-builder", "title": "WireGuard Builder", "img": None, "view": "wgbuild", "who": "tech",
     "text": "Wizards > WireGuard Builder connects two of a client's routers with a point-to-point tunnel, step by step: pick a hub "
             "(a brand-new interface or one that's already on the router), a client router, the tunnel addresses, and the subnets "
             "each end should reach - including downstream subnets behind another router. Both routers are backed up first."},
    {"id": "wg-builder-managed", "title": "Tracked and removable", "img": None, "view": "wgbuild", "who": "tech",
     "text": "Each tunnel you build is listed with its live handshake status, and everything the wizard writes on a router is tagged, "
             "so one click removes exactly what it added and nothing made by hand."},
    {"id": "wg-builder-bgp", "title": "Static routes or BGP", "img": None, "view": "wgbuild", "who": "tech",
     "text": "Choose how the tunnel routes: static routes, or BGP (eBGP or iBGP) where the two routers peer and exchange routes "
             "dynamically. BGP reuses a router's existing AS when it has one, so a new tunnel slots into an existing fabric."},
    {"id": "ipsec-wizard", "title": "IPsec Tunnel wizard", "img": None, "view": "ipsec", "who": "tech",
     "text": "A second Router Wizard: a policy-based IPsec tunnel from a MikroTik to an any-brand firewall (Fortinet, Cisco, "
             "pfSense...). TikManager sets up the MikroTik end and gives you a copyable settings sheet - with the pre-shared key - "
             "to configure the other box."},
]
SLIDES_3_2 = [
    {"id": "wizard-import", "title": "Import existing tunnels", "img": None, "view": "wizards", "who": "tech",
     "text": "Both Router Wizards now have an Import existing button: adopt a WireGuard or IPsec tunnel that's already on your routers so "
             "it shows in the wizard and can be disabled or deleted - without re-applying, re-keying or restarting the running tunnel. "
             "TikManager reads the tunnel live and tags it in place."},
    {"id": "import-ipsec", "title": "Imported tunnels, step by step", "img": None, "view": "ipsec", "who": "tech",
     "text": "IPsec: pick the router, review the settings read from it, and import - the pre-shared key isn't read, so re-applying is "
             "blocked until you enter it. WireGuard: pick the interface on each end and TikManager reconstructs the tunnel. Imported "
             "tunnels carry an \"imported\" pill; editing and re-applying graduates them to fully managed."},
]
SLIDES_3_3 = [
    {"id": "diagnostics", "title": "Diagnostics", "img": None, "view": "diag", "who": "tech",
     "text": "A new Diagnostics section in the sidebar: on-demand tests you run against a router, each one saving a report you can "
             "revisit, email or download as CSV."},
    {"id": "traffic-watch", "title": "Traffic Watch", "img": None, "view": "diag", "who": "tech",
     "text": "Pick a router, watch its live traffic for a set number of minutes - long enough to recreate the issue - and get a report "
             "of who's using the connection: top talkers, destinations, services and connections, plus throughput over time. Filter to "
             "one address to zero in. It reads the router's connection tracking, so no extra router permissions are needed."},
    {"id": "speed-test", "title": "Speed Test", "img": None, "view": "diag", "who": "tech",
     "text": "Check a site's internet reachability, latency and jitter from the router itself (with a rough download figure). A quick "
             "'is the internet up and healthy' test - not a line-rate speed test (a single fetch to the router's storage can't measure a "
             "fast link). Needs the router user's 'ftp' policy (new routers get it; existing ones need it granted once)."},
    {"id": "link-test", "title": "Link test", "img": None, "view": "diag", "who": "tech",
     "text": "Measure real throughput between two of your routers - RAM-to-RAM with 20 TCP streams, so it can show gigabit over a LAN, "
             "WAN or site-to-site link. Pick the two routers, the address and the direction; TikManager briefly turns on the target's "
             "bandwidth-test server and restores it after. This measures the path between the routers, not the public internet."},
]
SLIDES_3_4 = [
    {"id": "uptime-bar", "title": "Uptime history", "img": None, "view": "routers", "who": "tech",
     "text": "Every router's page now has an Uptime bar: pick 1M / 14d / 7d / 3d / 1d and see a block per slice (green up, "
             "amber partial, red down) with the overall uptime % for the window, worked out from the router's own online/offline "
             "history."},
    {"id": "console", "title": "Console", "img": None, "view": "routers", "who": "tech",
     "text": "A Console tab on the router page runs a RouterOS command and shows the output, right in the browser. It's a command "
             "runner (one command at a time, through TikManager's limited router user, every command logged) - for a full interactive "
             "session use Winbox. Needs the Winbox permission."},
    {"id": "client-ms-signin", "title": "Microsoft sign-in for client users", "img": None, "view": "admin", "who": "techadmin",
     "text": "Optional (off by default): let client users sign in with Microsoft instead of a password. Turn it on in Admin > Settings "
             "(needs a multi-tenant app registration), then invite a client user with the Microsoft sign-in option - they use their own "
             "Microsoft, or a guest account in your tenant, matched to their email and locked to its domain. Your staff sign-in is unchanged."},
]
SLIDES_3_5 = [
    {"id": "cw-billing", "title": "ConnectWise billing", "img": None, "view": "billing", "who": "tech",
     "text": "A new ConnectWise billing page (Clients & users) finds managed MikroTiks that aren't on a ConnectWise agreement - the ones "
             "you may be missing billing for. It matches each router to a configuration by serial number, shows whether that configuration "
             "is on an active agreement, and lists the gaps. Create a missing configuration in ConnectWise, or match one by hand, right there."},
    {"id": "upgrade-ticket", "title": "Upgrade → ConnectWise ticket", "img": None, "view": "upgrades", "who": "tech",
     "text": "When you upgrade a router, tick “Open a ConnectWise ticket” to open a ticket on the client's company, attach the "
             "pre-upgrade backup, and close it when the upgrade finishes (or flag it if it fails). Set the board and the three statuses once "
             "under the Upgrades page's ConnectWise ticket settings."},
    {"id": "alert-channels", "title": "Alerts: a channel per event", "img": None, "view": "alerts", "who": "tech",
     "text": "Alert settings are now their own tab, and “What to alert on” is a table: tick ConnectWise ticket, Email and/or Teams "
             "for each event - so a router going offline can open a ticket while a new-RouterOS notice only emails. Tick a column header to "
             "set a whole column at once."},
    {"id": "packet-sniffer", "title": "Packet Sniffer + per-interface Traffic Watch", "img": None, "view": "diag", "who": "tech",
     "text": "Diagnostics gains a Packet Sniffer - capture packet metadata (who's talking, which protocols and ports) in the router's memory "
             "for a few seconds - and Traffic Watch can now watch a single interface. Both use the router's 'sniff' permission, granted when "
             "the router is adopted (grant it once on routers adopted earlier). The old fetch-based Speed Test is gone; use the Link test."},
]
SLIDES_3_6 = [
    {"id": "api-access", "title": "Outbound API: let other systems pull data", "img": None, "view": "admin", "who": "techadmin",
     "text": "Admin > API access creates read-only tokens so another system - an RMM, a dashboard, a billing or reporting tool - can "
             "pull data from TikManager over a small HTTP API (routers, clients, alerts, fleet health). Each key is a bearer token "
             "with its own scopes, shown once when you create it and revokable any time. It's read-only: nothing in the API can change "
             "a router or a setting. See the endpoints and examples in the README's \"Outbound API\" section."},
]
SLIDES_3_7 = [
    {"id": "ipam", "title": "IPAM: IP Address Management", "img": None, "view": None, "who": "tech",
     "text": "A new IPAM workspace (Network > IPAM) in the spirit of phpIPAM, but it knows your routers. Organise address space "
             "by client and by free-form sections, with nested subnets and a visual map of every IP - used, reserved, DHCP, "
             "gateway or free - at a glance. IPv4 now; IPv6 is coming."},
    {"id": "ipam-sync", "title": "IPAM discovers subnets from your routers", "img": None, "view": None, "who": "tech",
     "text": "Sync from routers reads a client's managed MikroTiks and fills the IPAM in automatically: the subnets on each router "
             "and who's actually using each address - from the router's own addresses, DHCP leases, ARP and discovered neighbours. "
             "It also reads a client's UniFi networks (the real subnets and VLANs, for every site - gateway or not) and places "
             "its UniFi devices and connected clients into them. "
             "It never overwrites anything you typed by hand, and leaves TikManager's own management range alone."},
]
SLIDES = SLIDES_3_7   # 3.7.0's own slides (3.6.0 was released, so only the new work shows)
IDS = {s["id"] for s in SLIDES}

# Every release's tour stays here, so Admin > Settings > Version & updates can show past ones. When a new release line
# starts, add its tour as a new entry (keep its screenshots under their own names) and point RELEASE / SINCE / SLIDES at it.
TOURS = {"3.7.0": {"since": "3.6.0", "slides": SLIDES_3_7}, "3.6.0": {"since": "3.5.0", "slides": SLIDES_3_6}, "3.5.0": {"since": "3.4.0", "slides": SLIDES_3_5}, "3.4.0": {"since": "3.2.0", "slides": SLIDES_3_3 + SLIDES_3_4}, "3.3.0": {"since": "3.2.0", "slides": SLIDES_3_3}, "3.2.0": {"since": "3.1.0", "slides": SLIDES_3_2}, "3.1.0": {"since": "3.0.0", "slides": SLIDES_3_1},
         "2.0.0": {"since": "1.46.1", "slides": SLIDES_2_0}, "1.46.0": {"since": "1.45.1", "slides": SLIDES_1_46}}
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
    """What a person's "seen" record belongs to: the release, and whether it's still in beta (a full release resets).
    Patch releases after it (2.0.1, 2.0.2-beta.1...) share the full release's record - no tour again for a fix."""
    base = __version__.split("-")[0]
    if base != RELEASE:
        return RELEASE
    return __version__ if "-" not in __version__ else base + "-beta"


def active():
    """The slides cover the release and its patch releases (2.0.x): upgrading from 1.46 straight to 2.0.1 still shows them."""
    minor = lambda v: v.split("-")[0].rsplit(".", 1)[0]
    return minor(__version__) == minor(RELEASE)


def for_person(kind, saved):
    """The tour for this person: {release, since, slides, unseen}. saved: their prefs["whatsnew"] ({key, seen})."""
    slides = [s for s in SLIDES if s["who"] == "all" or kind == "tech"] if active() else []
    seen = set((saved or {}).get("seen") or []) if (saved or {}).get("key") == key() else set()
    return {"release": RELEASE, "since": SINCE, "version": __version__, "slides": slides,
            "unseen": [s["id"] for s in slides if s["id"] not in seen]}


def mark_seen(saved, ids):
    seen = set((saved or {}).get("seen") or []) if (saved or {}).get("key") == key() else set()
    return {"key": key(), "seen": sorted((seen | set(ids)) & IDS)}
