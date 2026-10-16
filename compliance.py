"""Compliance: every router checked against the router-relevant controls of CIS Controls v8, NIST SP 800-171 (CMMC
Level 2), PCI DSS 4.0 and the HIPAA Security Rule - and a report to hand the client.

No framework has a MikroTik benchmark, so each control is mapped to the router settings an auditor would look at
(the same read-only inventory as the Performance & security dashboard - routeros.RouterOS.INVENTORY, a field whitelist).
A router only covers its part of a framework: the report says which controls the routers meet, with the evidence, and
is explicit that it is not a certification.

check(d, inv) -> (status, evidence): pass / fail / manual (needs a person or a system outside the router) / unknown
(settings not read yet) / na. A control's result per router is the worst of its checks; across routers, the worst too.
"""
import json
import time

import healthdash

ORDER = {"fail": 0, "unknown": 1, "manual": 2, "accepted": 3, "pass": 4, "na": 5}
LABEL = {"fail": "Not met", "unknown": "Not checked yet", "manual": "Needs review", "accepted": "Met with exception", "pass": "Met",
         "na": "Not applicable"}
yes = healthdash.yes
# Exceptions (accepted findings, db table "exceptions"): keyed "hd:<dashboard finding title>" (accepted on Performance &
# security) or "cc:<check id>" (accepted on the Compliance page). A check whose every failing item is accepted is
# "accepted" - met with a documented exception, listed with its reason in the report.
HD = {   # check -> the dashboard findings it's made of
    "mgmt_exposed": [f"{n} reachable from the internet" for n in healthdash.MGMT],
    "input_drop": ["Input firewall has no catch-all drop"],
    "ssh": ["SSH allows older ciphers"],
    "default_admin": ["Default 'admin' user enabled"],
    "ntp": ["Clock not synced (NTP off)"],
    "snmp": ["SNMP enabled"],
}
ITEM_HD = {   # one item of a multi-item check -> its dashboard finding
    "telnet": "Telnet enabled", "ftp": "FTP enabled", "api": "the plain-text API enabled", "www": "WebFig over plain HTTP enabled",
    "SOCKS proxy": "SOCKS proxy enabled", "web proxy": "Web proxy enabled", "UPnP": "UPnP enabled",
    "bandwidth test server": "Bandwidth test server enabled", "MAC Telnet on every interface": "MAC Telnet on every interface",
    "open DNS resolver": "Open DNS resolver",
}


def _split_accepted(items, ex, check_id):
    """(still failing, accepted [(item, exception)]) for a multi-item check."""
    left, ok = [], []
    for it in items:
        e = ex.get("hd:" + ITEM_HD.get(it.split(" ")[0] if it.startswith("www") else it, it)) or ex.get(f"cc:{check_id}")
        (ok.append((it, e)) if e else left.append(it))
    return left, ok


def _why(ok):
    return "; ".join(f"{it} accepted by {e['created_by']}: {e['reason']}" for it, e in ok)


def _first(inv, menu):
    return (inv.get(menu) or [{}])[0]


def _enabled(inv, menu):
    return yes(_first(inv, menu).get("enabled"))


# --- the checks ----------------------------------------------------------------------------------------------------------
def c_mgmt_exposed(d, inv, ex=None):
    if not inv.get("/ip/service"):
        return "unknown", ""
    _, open_svc = healthdash.exposure(inv)
    ex = ex or {}
    ok = [(k, ex.get(f"hd:{k} reachable from the internet") or ex.get("cc:mgmt_exposed")) for k in open_svc]
    left = {k: v for k, v in open_svc.items() if not dict(ok).get(k)}
    ok = [(k, e) for k, e in ok if e]
    if left:
        return "fail", "Reachable from the internet: " + "; ".join(f"{k} ({v})" for k, v in left.items()) + (f". Accepted: {_why(ok)}." if ok else "")
    if ok:
        return "accepted", f"{_why(ok)}."
    return "pass", "No management service (Winbox, SSH, WebFig, API, Telnet, FTP) is reachable from the internet."


def c_input_drop(d, inv, ex=None):
    if not inv.get("/ip/firewall/filter") and not inv.get("/ip/service"):
        return "unknown", ""
    caught, _ = healthdash.exposure(inv)
    return ("pass", "The input chain ends with a drop for everything not explicitly allowed.") if caught \
        else ("fail", "The input chain has no catch-all drop - anything the router offers is reachable.")


def c_forward_drop(d, inv, ex=None):
    rules = [r for r in inv.get("/ip/firewall/filter", []) if r.get("chain") == "forward" and not yes(r.get("disabled"))]
    if not inv.get("/ip/firewall/filter") and not inv.get("/ip/service"):
        return "unknown", ""
    for r in rules:
        if r.get("action") in ("drop", "reject"):
            lst = str(r.get("in-interface-list") or "")
            if lst in ("WAN", "!LAN") or r.get("in-interface") or not any(r.get(m) for m in ("protocol", "dst-port", "src-address", "dst-address",
                                                                                                "src-address-list", "dst-address-list", "connection-state")):
                return "pass", "The forward chain drops traffic from the internet that wasn't asked for (deny by default)."
    return "fail", "No forward rule drops unsolicited traffic from the internet to the LAN."


def c_plaintext(d, inv, ex=None):
    svc = {s.get("name"): s for s in inv.get("/ip/service", [])}
    if not svc:
        return "unknown", ""
    bad = [n for n in ("telnet", "ftp", "api") if n in svc and not yes(svc[n].get("disabled"))]
    www = svc.get("www")
    notes = []
    if www and not yes(www.get("disabled")):
        if www.get("address"):
            notes.append(f"WebFig over HTTP is limited to {www['address']} (TikManager's management channel, inside its encrypted tunnel)")
        else:
            bad.append("www (HTTP, from any address)")
    bad, ok = _split_accepted(bad, ex or {}, "plaintext")
    if bad:
        return "fail", "Plain-text management enabled: " + ", ".join(bad) + "." + (f" Accepted: {_why(ok)}." if ok else "")
    if ok:
        return "accepted", f"{_why(ok)}."
    return "pass", "Telnet, FTP and the plain-text API are off" + (f"; {notes[0]}" if notes else "") + "."


def c_ssh(d, inv, ex=None):
    svc = {s.get("name"): s for s in inv.get("/ip/service", [])}
    ssh = _first(inv, "/ip/ssh")
    if not ssh and not svc:
        return "unknown", ""
    if "ssh" in svc and yes(svc["ssh"].get("disabled")):
        return "pass", "SSH is disabled."
    if str(ssh.get("strong-crypto") or "") in ("yes", "true"):
        return "pass", "SSH uses strong crypto only (256-bit ciphers, SHA-256, 2048-bit DH)."
    return "fail", "SSH strong-crypto is off" + (" and the null cipher is allowed" if "null" in str(ssh.get("ciphers") or "") else "") + "."


def c_vpn_crypto(d, inv, ex=None):
    if not inv:
        return "unknown", ""
    weak = [f for f in healthdash.build([{**d, "online": 1, "last_backup_at": time.time()}], {}, {}) if f["category"] == "Encryption"
            and f["title"] != "SSH allows older ciphers"]
    if weak:
        return "fail", "; ".join(f"{f['title']}: {f['detail']}" for f in weak)[:600]
    return "pass", "No PPTP, no L2TP without IPsec, no weak IPsec or OpenVPN ciphers."


def c_default_admin(d, inv, ex=None):
    users = inv.get("/user")
    if users is None:
        return "unknown", ""
    if any(u.get("name") == "admin" and not yes(u.get("disabled")) for u in users):
        return "fail", "The default 'admin' account is enabled."
    named = [u["name"] for u in users if not yes(u.get("disabled")) and u.get("name")]
    return "pass", f"No default admin account; {len(named)} named account(s)."


def c_central_auth(d, inv, ex=None):
    if "/user/aaa" not in inv:
        return "unknown", ""
    aaa = _first(inv, "/user/aaa")
    rad = [r for r in inv.get("/radius", []) if not yes(r.get("disabled")) and "login" in str(r.get("service") or "")]
    if yes(aaa.get("use-radius")) and rad:
        return "pass", f"Router sign-ins use RADIUS ({', '.join(r.get('address', '?') for r in rad)})."
    return "fail", "Router sign-ins use local accounts only (no RADIUS / central directory)."


def c_mfa(d, inv, ex=None):
    if "/user/aaa" in inv and yes(_first(inv, "/user/aaa").get("use-radius")):
        return "manual", "Sign-ins go through RADIUS - MFA depends on that server (confirm it enforces MFA)."
    return "manual", ("RouterOS has no built-in MFA. Meet this with MFA in front of router access (RADIUS with MFA, or a "
                      "jump host / TikManager's Microsoft sign-in) and record it.")


def c_remote_log(d, inv, ex=None):
    if "/system/logging/action" not in inv:
        return "unknown", ""
    remote = {a.get("name"): a.get("remote") for a in inv.get("/system/logging/action", []) if a.get("target") == "remote" and a.get("remote")}
    used = [r for r in inv.get("/system/logging", []) if r.get("action") in remote and not yes(r.get("disabled"))]
    if used:
        return "pass", "Logs are sent to " + ", ".join(sorted({remote[r['action']] for r in used})) + \
            f" ({', '.join(sorted({r.get('topics', '') for r in used}))}); TikManager keeps them {14} days and searchable."
    return "fail", "The router only keeps its logs in memory - nothing is sent to a central log server."


def c_ntp(d, inv, ex=None):
    ntp = _first(inv, "/system/ntp/client")
    if not ntp:
        return "unknown", ""
    return ("pass", "The clock is synced by NTP" + (f" ({ntp['servers']})" if ntp.get("servers") else "") + ".") if yes(ntp.get("enabled")) \
        else ("fail", "NTP is off - log times can't be trusted.")


def c_services(d, inv, ex=None):
    if not inv.get("/ip/service"):
        return "unknown", ""
    bad = []
    if _enabled(inv, "/ip/socks"):
        bad.append("SOCKS proxy")
    if _enabled(inv, "/ip/proxy"):
        bad.append("web proxy")
    if _enabled(inv, "/ip/upnp"):
        bad.append("UPnP")
    if _enabled(inv, "/tool/bandwidth-server"):
        bad.append("bandwidth test server")
    if str(_first(inv, "/tool/mac-server").get("allowed-interface-list") or "") == "all":
        bad.append("MAC Telnet on every interface")
    caught, _ = healthdash.exposure(inv)
    if yes(_first(inv, "/ip/dns").get("allow-remote-requests")) and not caught:
        bad.append("open DNS resolver")
    bad, ok = _split_accepted(bad, ex or {}, "services")
    if bad:
        return "fail", "Unneeded services on: " + ", ".join(bad) + "." + (f" Accepted: {_why(ok)}." if ok else "")
    if ok:
        return "accepted", f"{_why(ok)}."
    return "pass", "No unneeded services (SOCKS, web proxy, UPnP, bandwidth test, MAC Telnet on WAN, open DNS)."


def c_snmp(d, inv, ex=None):
    if not _first(inv, "/snmp"):
        return "unknown", ""
    if not _enabled(inv, "/snmp"):
        return "pass", "SNMP is off."
    comms = [c for c in inv.get("/snmp/community", []) if not yes(c.get("disabled"))]
    weak = [c for c in comms if str(c.get("security") or "none") == "none"]   # v1/v2c (the community name is never read)
    if weak:
        return "fail", f"{len(weak)} SNMP v1/v2c communit{'y' if len(weak) == 1 else 'ies'} enabled - use SNMPv3 with authentication and encryption."
    return "pass", "SNMP uses v3 with authentication only."


def c_banner(d, inv, ex=None):
    if "/system/note" not in inv:
        return "unknown", ""
    n = _first(inv, "/system/note")
    if yes(n.get("show-at-login")) and str(n.get("note") or "").strip():
        return "pass", "A login notice is shown before sign-in."
    return "fail", "No login notice (authorized-use banner) is shown at sign-in."


def c_firmware(d, inv, ex=None):
    if (d.get("cve_max") or 0) >= 7:
        return "fail", f"RouterOS {d.get('version')} has {d.get('cve_n') or 0} known vulnerabilit{'y' if d.get('cve_n') == 1 else 'ies'}, worst CVSS {d['cve_max']}."
    if d.get("lc_status") == "discontinued":
        return "fail", f"{d.get('model') or 'This model'} is discontinued - no more security updates."
    if not d.get("version"):
        return "unknown", ""
    return "pass", f"RouterOS {d['version']}, no high or critical known vulnerabilities."


def c_backups(d, inv, ex=None):
    t = d.get("last_backup_at")
    if t and time.time() - t < 7 * 86400:
        return "pass", f"Configuration backed up nightly and versioned (last {time.strftime('%Y-%m-%d', time.localtime(t))}); every change is recorded."
    return "fail", "No configuration backup in the last 7 days."


def c_fips(d, inv, ex=None):
    return "fail", ("RouterOS cryptography is not FIPS 140 validated. The router can't be the system that protects CUI in "
                    "transit (its VPNs); carry CUI over a FIPS-validated VPN or encryption layer instead.")


CHECKS = {   # id: (title, function, how to fix, one-click fix id in healthdash.FIXES or None)
    "mgmt_exposed": ("Management not reachable from the internet", c_mgmt_exposed,
                     "Limit /ip service to management addresses, or drop management ports on the WAN.", None),
    "input_drop": ("Router firewall denies by default (input)", c_input_drop, "Add a final input rule: drop everything not from the LAN.", None),
    "forward_drop": ("LAN firewall denies by default (forward)", c_forward_drop,
                     "Add MikroTik's default forward rule: drop everything from the WAN that isn't port-forwarded (connection-nat-state=!dstnat).", None),
    "plaintext": ("Management traffic is encrypted", c_plaintext,
                  "Disable Telnet, FTP and the API (8728); keep WebFig over HTTP limited to the management address.", "svc_telnet"),
    "ssh": ("SSH uses strong cryptography", c_ssh, "/ip ssh set strong-crypto=yes", "ssh_strong"),
    "vpn_crypto": ("VPNs use strong encryption", c_vpn_crypto, "Replace PPTP and plain L2TP with WireGuard or IPsec (AES-256, SHA-256, modp2048+).", None),
    "default_admin": ("No default administrator account", c_default_admin, "Create named accounts, then disable or remove 'admin'.", None),
    "central_auth": ("Central sign-in for administrators (RADIUS)", c_central_auth,
                     "Point /radius at your directory (e.g. NPS) for login and set /user aaa use-radius=yes.", None),
    "mfa": ("Multi-factor authentication for administrators", c_mfa, "Put MFA in front of router access and document it.", None),
    "remote_log": ("Logs sent to a central log server", c_remote_log, "Add a remote logging action (TikManager sets one up at adoption).", None),
    "ntp": ("Clock synchronized (NTP)", c_ntp, "/system ntp client set enabled=yes servers=time.cloudflare.com", "ntp_on"),
    "services": ("Unneeded services disabled", c_services, "Turn off SOCKS, web proxy, UPnP, the bandwidth test server; limit MAC Telnet to the LAN.", "upnp_off"),
    "snmp": ("SNMP off or SNMPv3 only", c_snmp, "Disable SNMP, or use SNMPv3 with authentication and encryption.", None),
    "banner": ("Login notice shown", c_banner, "/system note set show-at-login=yes note=\"Authorized use only...\"", None),
    "firmware": ("Supported firmware without serious known vulnerabilities", c_firmware, "Upgrade RouterOS (Upgrades page); replace discontinued models.", None),
    "backups": ("Configuration backed up and versioned", c_backups, "Back up now and check why the nightly backup fails.", None),
    "fips": ("FIPS-validated cryptography for CUI", c_fips, "Carry CUI over a FIPS 140-validated VPN / encryption layer; the router can't provide it.", None),
}

# --- the frameworks ------------------------------------------------------------------------------------------------------
FRAMEWORKS = {
    "cis8": {"name": "CIS Controls v8", "short": "CIS v8", "controls": [
        ("4.1", "Establish and maintain a secure configuration process", ["backups"]),
        ("4.2", "Secure configuration for network infrastructure", ["plaintext", "ssh", "services", "snmp"]),
        ("4.5", "Implement and manage a firewall on end-user devices / network boundary", ["input_drop", "forward_drop"]),
        ("4.6", "Securely manage enterprise assets (encrypted management)", ["plaintext", "ssh", "mgmt_exposed"]),
        ("4.7", "Manage default accounts on enterprise assets", ["default_admin"]),
        ("4.8", "Uninstall or disable unnecessary services", ["services", "snmp"]),
        ("7.4", "Perform automated application / firmware patch management", ["firmware"]),
        ("8.2", "Collect audit logs", ["remote_log"]),
        ("8.4", "Standardize time synchronization", ["ntp"]),
        ("8.9", "Centralize audit logs", ["remote_log"]),
        ("11.2", "Perform automated backups", ["backups"]),
        ("12.1", "Ensure network infrastructure is up to date", ["firmware"]),
        ("12.2", "Establish and maintain a secure network architecture", ["input_drop", "forward_drop", "mgmt_exposed"]),
        ("12.3", "Securely manage network infrastructure", ["plaintext", "ssh", "mgmt_exposed"]),
        ("12.5", "Centralize network authentication, authorization and auditing (AAA)", ["central_auth"]),
        ("12.7", "Ensure remote devices use a VPN", ["vpn_crypto"]),
        ("6.5", "Require MFA for administrative access", ["mfa"]),
    ]},
    "nist171": {"name": "NIST SP 800-171 Rev. 2 / CMMC Level 2", "short": "NIST 800-171", "controls": [
        ("3.1.1", "Limit system access to authorized users", ["mgmt_exposed", "default_admin"]),
        ("3.1.9", "Provide privacy and security notices", ["banner"]),
        ("3.1.12", "Monitor and control remote access sessions", ["vpn_crypto", "remote_log"]),
        ("3.1.13", "Use cryptographic mechanisms to protect remote access sessions", ["vpn_crypto", "plaintext", "ssh"]),
        ("3.3.1", "Create and retain system audit logs", ["remote_log"]),
        ("3.3.7", "Synchronize system clocks with an authoritative source", ["ntp"]),
        ("3.4.1", "Establish and maintain baseline configurations", ["backups"]),
        ("3.4.2", "Establish and enforce security configuration settings", ["ssh", "services", "snmp"]),
        ("3.4.6", "Employ the principle of least functionality", ["services", "snmp"]),
        ("3.4.7", "Restrict nonessential ports, protocols and services", ["plaintext", "mgmt_exposed"]),
        ("3.5.1", "Identify system users", ["default_admin", "central_auth"]),
        ("3.5.3", "Use multifactor authentication for privileged and network access", ["mfa"]),
        ("3.13.1", "Monitor, control and protect communications at the boundary", ["input_drop", "forward_drop"]),
        ("3.13.6", "Deny network traffic by default, allow by exception", ["input_drop", "forward_drop"]),
        ("3.13.8", "Use cryptography to protect CUI in transit", ["vpn_crypto"]),
        ("3.13.11", "Employ FIPS-validated cryptography to protect CUI", ["fips"]),
        ("3.14.1", "Identify, report and correct system flaws", ["firmware"]),
    ]},
    "pci4": {"name": "PCI DSS v4.0", "short": "PCI DSS 4.0", "controls": [
        ("1.2.1", "Configuration standards for network security controls", ["backups"]),
        ("1.3.1", "Inbound traffic to the cardholder environment is restricted", ["forward_drop", "input_drop"]),
        ("1.4.2", "Inbound traffic from untrusted networks is restricted", ["mgmt_exposed", "services"]),
        ("2.2.2", "Vendor default accounts are removed or disabled", ["default_admin"]),
        ("2.2.4", "Only necessary services, protocols and functions are enabled", ["services", "snmp"]),
        ("2.2.5", "Insecure services are justified and secured", ["plaintext"]),
        ("2.2.7", "Non-console administrative access is encrypted", ["plaintext", "ssh"]),
        ("4.2.1", "Strong cryptography for transmission over open, public networks", ["vpn_crypto"]),
        ("6.3.3", "Security patches are installed", ["firmware"]),
        ("8.2.1", "Users are assigned a unique ID", ["default_admin", "central_auth"]),
        ("8.4.2", "MFA for all access into the cardholder environment", ["mfa"]),
        ("10.2.1", "Audit logs are enabled and active", ["remote_log"]),
        ("10.6.1", "System clocks are synchronized", ["ntp"]),
    ]},
    "hipaa": {"name": "HIPAA Security Rule (45 CFR 164)", "short": "HIPAA", "controls": [
        ("164.308(a)(1)(ii)(B)", "Risk management: reduce vulnerabilities", ["firmware", "services"]),
        ("164.308(a)(5)(ii)(D)", "Password management: no default credentials", ["default_admin"]),
        ("164.308(a)(7)(ii)(A)", "Data backup plan (device configuration)", ["backups"]),
        ("164.312(a)(1)", "Access control", ["mgmt_exposed", "input_drop", "forward_drop"]),
        ("164.312(a)(2)(i)", "Unique user identification", ["default_admin", "central_auth"]),
        ("164.312(b)", "Audit controls", ["remote_log", "ntp"]),
        ("164.312(d)", "Person or entity authentication", ["mfa"]),
        ("164.312(e)(1)", "Transmission security", ["vpn_crypto", "plaintext", "ssh"]),
    ]},
}


def worst(statuses):
    s = [x for x in statuses if x != "na"]
    return min(s, key=ORDER.get) if s else "na"


def evaluate(rows, exceptions=None):
    """{device_id: {check_id: (status, evidence)}} for adopted routers (offline ones: their last read settings).
    exceptions: {device_id: {key: {reason, created_by, created_at}}}."""
    out = {}
    for d in rows:
        try:
            inv = json.loads(d.get("vpn_inv") or "null") or {}
        except ValueError:
            inv = {}
        ex = (exceptions or {}).get(d["id"], {})
        res = {}
        for cid, (_, fn, _, _) in CHECKS.items():
            try:
                st, ev = fn(d, inv, ex)
            except Exception as e:  # noqa: BLE001 - one odd router setting mustn't break the page
                st, ev = "unknown", f"Couldn't evaluate: {e}"
            if st == "fail" and cid not in ("plaintext", "services", "mgmt_exposed"):   # the multi-item checks handle their own
                e = ex.get(f"cc:{cid}") or next((ex[f"hd:{t}"] for t in HD.get(cid, []) if f"hd:{t}" in ex), None)
                if e:
                    st, ev = "accepted", f"{ev} Accepted by {e['created_by']}: {e['reason']}"
            res[cid] = (st, ev)
        out[d["id"]] = res
    return out


def scorecard(fw_id, rows, results):
    """The framework's controls with a result per router and overall."""
    fw = FRAMEWORKS[fw_id]
    controls = []
    for cid, title, checks in fw["controls"]:
        per = {}
        for d in rows:
            st = worst([results[d["id"]][c][0] for c in checks])
            per[d["id"]] = {"status": st, "checks": [{"id": c, "title": CHECKS[c][0], "status": results[d["id"]][c][0],
                                                       "evidence": results[d["id"]][c][1]} for c in checks]}
        overall = worst([p["status"] for p in per.values()]) if per else "na"
        controls.append({"id": cid, "title": title, "checks": checks, "status": overall, "routers": per,
                         "failing": [d["id"] for d in rows if per[d["id"]]["status"] == "fail"]})
    scored = [c for c in controls if c["status"] in ("pass", "accepted", "fail")]
    return {"framework": fw_id, "name": fw["name"], "controls": controls,
            "met": sum(1 for c in controls if c["status"] in ("pass", "accepted")), "accepted": sum(1 for c in controls if c["status"] == "accepted"),
            "not_met": sum(1 for c in controls if c["status"] == "fail"),
            "review": sum(1 for c in controls if c["status"] == "manual"), "unknown": sum(1 for c in controls if c["status"] == "unknown"),
            "score": round(100 * sum(1 for c in scored if c["status"] != "fail") / len(scored)) if scored else None}


# --- the client report (HTML, printed to PDF from the browser) --------------------------------------------------------
def report_html(fw_id, card, rows, results, client, brand, esc):
    fw = FRAMEWORKS[fw_id]
    now = time.strftime("%B %d, %Y")
    company = brand.get("company") or brand.get("product") or "TikManager"
    names = {d["id"]: d["name"] for d in rows}
    pill = lambda st: f'<span class="st st-{st}">{LABEL[st]}</span>'
    fixes = {}
    for c in card["controls"]:
        for did in c["failing"]:
            for ch in c["routers"][did]["checks"]:
                if ch["status"] == "fail":
                    fixes.setdefault(ch["id"], set()).add(did)
    router_rows = []
    for d in rows:
        sts = [c["routers"][d["id"]]["status"] for c in card["controls"]]
        scored = [s for s in sts if s in ("pass", "accepted", "fail")]
        pct = round(100 * (len(scored) - scored.count("fail")) / len(scored)) if scored else None
        router_rows.append(f"<tr><td><b>{esc(d['name'])}</b><div class='mut'>{esc(d.get('model') or '')} · RouterOS {esc(d.get('version') or '?')}</div></td>"
                           f"<td>{'' if pct is None else f'{pct}%'}</td><td>{sts.count('pass') + sts.count('accepted')}</td><td>{sts.count('fail')}</td>"
                           f"<td>{sts.count('manual')}</td><td>{'online' if d.get('online') else 'offline (last known settings)'}</td></tr>")
    control_rows = []
    for c in card["controls"]:
        detail = []
        for d in rows:
            p = c["routers"][d["id"]]
            if p["status"] in ("fail", "unknown", "manual", "accepted") or len(rows) == 1:
                show = [ch for ch in p["checks"] if ch["evidence"] and (ch["status"] != "pass" or p["status"] == "pass")]
                ev = "; ".join(f"{ch['title']}: {ch['evidence']}" for ch in show)
                detail.append(f"<li>{pill(p['status'])} <b>{esc(d['name'])}</b> - {esc(ev or LABEL[p['status']])}</li>")
        if not detail and c["status"] == "pass":
            ex = next((ch for ch in c["routers"][rows[0]["id"]]["checks"] if ch["evidence"]), None) if rows else None
            detail.append(f"<li>All {len(rows)} routers. {esc(ex['evidence']) if ex else ''}</li>")
        control_rows.append(f"<tr><td class='cid'>{esc(c['id'])}</td><td><b>{esc(c['title'])}</b><ul>{''.join(detail)}</ul></td><td>{pill(c['status'])}</td></tr>")
    fix_rows = [f"<tr><td><b>{esc(CHECKS[k][0])}</b></td><td>{esc(CHECKS[k][2])}</td><td>{esc(', '.join(sorted(names[i] for i in v)))}</td></tr>"
                for k, v in sorted(fixes.items(), key=lambda kv: -len(kv[1]))]
    seen, exc_rows = set(), []
    for d in rows:
        for cid, (st, ev) in results[d["id"]].items():
            if st == "accepted" and any(cid in c["checks"] for c in card["controls"]) and (d["id"], cid) not in seen:
                seen.add((d["id"], cid))
                exc_rows.append(f"<tr><td><b>{esc(d['name'])}</b></td><td>{esc(CHECKS[cid][0])}</td><td>{esc(ev)}</td></tr>")
    logo = f'<img class="logo" src="{esc(brand["logo_url"])}" alt="">' if brand.get("logo_url") else ""
    fips = ("<p class='note'><b>CUI note:</b> NIST 800-171 3.13.11 requires FIPS-validated cryptography wherever CUI is protected by "
            "encryption. MikroTik RouterOS is not FIPS 140 validated, so this control is shown as not met for every router; CUI must be "
            "carried over a FIPS-validated VPN or encryption layer.</p>") if fw_id == "nist171" else ""
    score = "—" if card["score"] is None else f"{card['score']}%"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(client)} - {esc(fw['short'])} network compliance - {now}</title><link rel="stylesheet" href="/report.css"><script src="/report.js" defer></script></head>
<body><div class="bar no-print"><button type="button" id="printBtn">Print / Save as PDF</button><span>Tip: in the print dialog choose "Save as PDF".</span></div>
<header>{logo}<div><div class="mut">{esc(company)}</div><h1>Network security compliance report</h1>
<div class="sub">{esc(client)} · {esc(fw['name'])} · {now}</div></div></header>
<section class="summary"><div class="big"><div class="n">{score}</div><div class="mut">of checked controls met</div></div>
<div class="kpis"><div><b>{card['met']}</b> met{f" ({card['accepted']} with a documented exception)" if card['accepted'] else ""}</div><div><b>{card['not_met']}</b> not met</div><div><b>{card['review']}</b> need review</div>
<div><b>{len(rows)}</b> router{'s' if len(rows) != 1 else ''} checked</div></div></section>
<h2>Scope</h2><p>This report covers the <b>network routers</b> (MikroTik) that {esc(company)} manages for {esc(client)}, checked against the
controls of {esc(fw['name'])} that apply to network devices. Settings were read directly from each router (read-only) on {now}. A framework
also covers policies, people, computers, servers and cloud services that are outside this report, so it is evidence for these controls -
not a certification of compliance. "Needs review" means the control depends on something outside the router (for example, MFA in
front of router sign-in) that must be confirmed and documented. "Met with exception" means a finding was reviewed and accepted with a
documented reason (for example, a service needed on the LAN whose port is blocked from the internet) - listed under Documented exceptions.</p>{fips}
<h2>Routers</h2><table><thead><tr><th>Router</th><th>Score</th><th>Met</th><th>Not met</th><th>Review</th><th>State</th></tr></thead><tbody>{''.join(router_rows)}</tbody></table>
<h2>Controls</h2><table class="controls"><thead><tr><th>Control</th><th>Requirement and evidence</th><th>Result</th></tr></thead><tbody>{''.join(control_rows)}</tbody></table>
{f"<h2>Remediation plan</h2><table><thead><tr><th>Item</th><th>What to do</th><th>Routers</th></tr></thead><tbody>{''.join(fix_rows)}</tbody></table>" if fix_rows else "<h2>Remediation plan</h2><p>Nothing to fix on the routers for these controls.</p>"}
{f"<h2>Documented exceptions</h2><table><thead><tr><th>Router</th><th>Check</th><th>Reason and who accepted it</th></tr></thead><tbody>{''.join(exc_rows)}</tbody></table>" if exc_rows else ""}
<footer>Prepared by {esc(company)} on {now} with {esc(brand.get('product') or 'TikManager')}.</footer></body></html>"""


def report_csv(fw_id, card, rows):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Framework", "Control", "Requirement", "Router", "Result", "Check", "Check result", "Evidence", "Checked"])
    when = time.strftime("%Y-%m-%d %H:%M")
    for c in card["controls"]:
        for d in rows:
            p = c["routers"][d["id"]]
            for ch in p["checks"]:
                w.writerow([FRAMEWORKS[fw_id]["short"], c["id"], c["title"], d["name"], LABEL[p["status"]], ch["title"], LABEL[ch["status"]], ch["evidence"], when])
    return buf.getvalue()
