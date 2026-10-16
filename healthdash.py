"""Performance & Security dashboard: every router checked against a list of internet, performance, exposure,
encryption, VPN, update and backup problems - one list of findings with severity and how to fix each.

Built from what TikManager already has (no extra polling): the 1-minute status and pings, internet-link state and
events, the 5-minute health sensors, the RouterOS security / lifecycle checks, backups, and the 15-minute read-only
inventory (routeros.RouterOS.INVENTORY - a field whitelist, so no passwords or keys), which also carries the router's
services, firewall input chain, DNS, UPnP, SOCKS, proxy, MAC server, SSH and NTP settings and IPsec / OpenVPN ciphers.
"""
import json
import re
import time

import vpninv

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CATEGORIES = ["Internet", "Performance", "Exposure", "Encryption", "VPN", "Updates", "Backups", "Hygiene"]
MGMT = {"telnet": 23, "ftp": 21, "www": 80, "www-ssl": 443, "ssh": 22, "winbox": 8291, "api": 8728, "api-ssl": 8729}
PLAINTEXT = {"telnet": "Telnet", "ftp": "FTP", "www": "WebFig over plain HTTP", "api": "the plain-text API"}
WEAK_ENC = re.compile(r"\b(des|3des|blowfish|bf-cbc|bf|null|rc4)\b", re.I)
WEAK_HASH = re.compile(r"\b(md5|sha1)\b", re.I)
WEAK_DH = re.compile(r"\b(modp768|modp1024|ec2n155|ec2n185)\b", re.I)


def yes(v):
    return str(v).lower() in ("true", "yes")


def _ports(v):
    out = set()
    for part in str(v or "").split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def exposure(inv):
    """From the inventory: (catch_all_drop?, {service: why it's reachable}) for the router's management services."""
    rules = [r for r in inv.get("/ip/firewall/filter", []) if r.get("chain") == "input" and not yes(r.get("disabled"))]
    matchers = ("protocol", "dst-port", "src-address", "src-address-list", "connection-state", "dst-address", "dst-address-list")
    catch_all = next((i for i, r in enumerate(rules) if r.get("action") in ("drop", "reject")
                      and not any(r.get(m) for m in matchers)), None)
    open_svc = {}
    for s in inv.get("/ip/service", []):
        name = s.get("name")
        if name not in MGMT or yes(s.get("disabled")) or s.get("address"):   # off, or limited to some addresses on the router
            continue
        port = int(s.get("port") or MGMT[name])
        if catch_all is None:
            open_svc[name] = f"port {port}, nothing drops the rest of the input chain"
            continue
        for r in rules[:catch_all]:
            if r.get("action") == "accept" and port in _ports(r.get("dst-port")) and not r.get("src-address") and not r.get("src-address-list") \
                    and str(r.get("in-interface-list") or "") not in ("LAN", "!WAN") and not r.get("in-interface"):
                open_svc[name] = f"port {port}, accepted from anywhere by an input rule"
                break
    return catch_all is not None, open_svc


def build(rows, metrics, flaps, now=None):
    """rows: devices (with vpn_inv etc.); metrics: {device_id: {lat, loss, cpu, mem}} (last hour); flaps: {device_id: n} (24 h)."""
    now = now or time.time()
    out = []

    def add(d, sev, cat, title, detail, fix):
        out.append({"device_id": d["id"], "router": d["name"], "org": d.get("org") or "", "severity": sev, "category": cat,
                    "title": title, "detail": detail, "fix": fix})

    for d in rows:
        m = metrics.get(d["id"]) or {}
        try:
            inv = json.loads(d.get("vpn_inv") or "null") or {}
        except ValueError:
            inv = {}
        # --- internet ------------------------------------------------------------------------------------------------
        if not d.get("online"):
            add(d, "high", "Internet", "Router offline", f"Last seen {_ago(now - (d.get('last_seen') or now))} ago.",
                "Check power and the internet link at the site; the router reconnects to TikManager by itself.")
            continue   # nothing below is current for an offline router
        try:
            isp = json.loads(d.get("isp_state") or "{}")
        except ValueError:
            isp = {}
        down = [n for n, s in isp.items() if not s.get("up")]
        if down:
            add(d, "high", "Internet", "Internet link down", f"{', '.join(down)} down - running on {', '.join(n for n, s in isp.items() if s.get('up')) or 'another path'}.",
                "Call the ISP or check the modem; the router is on its backup link meanwhile.")
        if (flaps.get(d["id"]) or 0) >= 3:
            add(d, "medium", "Internet", "Unstable internet link", f"{flaps[d['id']]} link drops in the last 24 hours.",
                "Check the modem / cabling and ask the ISP to check the line.")
        if m.get("loss") is not None and m["loss"] >= 2:
            add(d, "high" if m["loss"] >= 10 else "medium", "Internet", "Packet loss", f"{m['loss']:.1f}% loss to the internet over the last hour.",
                "Usually the ISP line or a saturated link - check the router's traffic graph, then the ISP.")
        if m.get("lat") is not None and m["lat"] >= 150:
            add(d, "medium", "Internet", "High latency", f"{m['lat']:.0f} ms average to the internet over the last hour.",
                "A full upload link raises latency for everyone - check traffic; otherwise the ISP.")
        # --- performance ---------------------------------------------------------------------------------------------
        if m.get("cpu") is not None and m["cpu"] >= 85:
            add(d, "medium", "Performance", "CPU busy", f"{m['cpu']:.0f}% average over the last hour.",
                "Look at Tools > Profile on the router; heavy firewall / queue rules or an attack are the usual causes.")
        if m.get("mem") is not None and m["mem"] >= 90:
            add(d, "medium", "Performance", "Memory nearly full", f"{m['mem']:.0f}% used.", "Check for large address lists or connection tracking; a reboot clears leaks.")
        if d.get("hdd_total") and d.get("hdd_free") is not None and d["hdd_free"] / d["hdd_total"] < 0.1:
            add(d, "medium", "Performance", "Storage nearly full", f"{round(100 * d['hdd_free'] / d['hdd_total'])}% free.",
                "Remove old files (backups, packages) in Files; upgrades need free space.")
        if str(d.get("bad_blocks") or "0").rstrip("%") not in ("0", "0.0", ""):
            add(d, "high", "Performance", "Flash storage wearing out", f"Bad blocks: {d['bad_blocks']}.", "Plan a replacement; back up now.")
        try:
            health = json.loads(d.get("health") or "{}")
        except ValueError:
            health = {}
        hot = [f"{k} {v['value']:.0f}°C" for k, v in health.items() if "temp" in k and isinstance(v.get("value"), (int, float)) and v["value"] >= 75]
        if hot:
            add(d, "medium", "Performance", "Running hot", ", ".join(hot[:3]), "Check airflow and the room temperature.")
        if d.get("last_reboot") and now - d["last_reboot"] < 86400:
            add(d, "low", "Performance", "Restarted recently", f"{_ago(now - d['last_reboot'])} ago" + (f" ({d['last_reboot_why']})" if d.get("last_reboot_why") else ""),
                "If nobody restarted it, check power and the router's log.")
        # --- exposure -----------------------------------------------------------------------------------------------
        if inv.get("/ip/service"):
            caught, open_svc = exposure(inv)
            for name, why in open_svc.items():
                add(d, "critical" if name in ("telnet", "ftp", "www", "api") else "high", "Exposure", f"{name} reachable from the internet",
                    why, f"Limit /ip service {name} to your management addresses (address=...), or drop it on the WAN in the input chain.")
            if not caught:
                add(d, "critical" if open_svc else "high", "Exposure", "Input firewall has no catch-all drop",
                    "Anything the router itself offers is reachable from the internet.",
                    "Add a final input rule: drop everything not from the LAN (like MikroTik's default 'drop all not coming from LAN').")
            for s in inv.get("/ip/service", []):
                if s.get("name") in PLAINTEXT and not yes(s.get("disabled")) and s.get("name") not in open_svc:
                    add(d, "medium", "Exposure", f"{PLAINTEXT[s['name']]} enabled", "Passwords cross the network in plain text.",
                        f"/ip service disable {s['name']} (use {'SSH' if s['name'] in ('telnet', 'ftp') else 'HTTPS / api-ssl'} instead).")
            dns = (inv.get("/ip/dns") or [{}])[0]
            if yes(dns.get("allow-remote-requests")) and not caught:
                add(d, "high", "Exposure", "Open DNS resolver", "The router answers DNS for anyone - it can be abused for DDoS attacks.",
                    "Drop UDP/TCP 53 from the WAN in the input chain (or a catch-all drop).")
            on = lambda menu: yes((inv.get(menu) or [{}])[0].get("enabled"))
            if on("/ip/socks"):
                add(d, "high", "Exposure", "SOCKS proxy enabled", "Rarely wanted - often a sign of a compromised router.", "/ip socks set enabled=no, then check users and scripts.")
            if on("/ip/proxy"):
                add(d, "high" if not caught else "medium", "Exposure", "Web proxy enabled", "An open proxy is abused quickly.", "/ip proxy set enabled=no unless it's needed.")
            if on("/ip/upnp"):
                add(d, "medium", "Exposure", "UPnP enabled", "Devices on the LAN can open ports to the internet by themselves.", "/ip upnp set enabled=no unless a game console needs it.")
            if on("/tool/bandwidth-server"):
                add(d, "low", "Exposure", "Bandwidth test server enabled", "Can be used to load the router and link.", "/tool bandwidth-server set enabled=no")
            mac = (inv.get("/tool/mac-server") or [{}])[0]
            if str(mac.get("allowed-interface-list") or "") == "all":
                add(d, "low", "Exposure", "MAC Telnet on every interface", "Layer-2 management reachable from any port.", "/tool mac-server set allowed-interface-list=LAN")
            if (inv.get("/snmp") or [{}])[0].get("enabled") in ("true", "yes"):
                add(d, "low", "Exposure", "SNMP enabled", "Check it isn't using the 'public' community and is limited to your monitoring.", "/snmp community: set addresses= and a private name.")
        # --- encryption and VPN technologies -----------------------------------------------------------------------------
        for s in inv.get("/interface/pptp-server/server", []):
            if yes(s.get("enabled")):
                add(d, "high", "Encryption", "PPTP server enabled", "PPTP's encryption is broken.", "Move remote users to WireGuard (Remote access tab) and disable the PPTP server.")
        for c in inv.get("/interface/pptp-client", []):
            if not yes(c.get("disabled")):
                add(d, "high", "Encryption", "PPTP client in use", f"{c.get('name')} to {c.get('connect-to')}.", "Replace with WireGuard or IPsec.")
        for s in inv.get("/interface/l2tp-server/server", []):
            if yes(s.get("enabled")) and str(s.get("use-ipsec") or "no") == "no":
                add(d, "high", "Encryption", "L2TP server without IPsec", "L2TP on its own isn't encrypted.", "Set use-ipsec=required, or move users to WireGuard.")
        for c in inv.get("/interface/l2tp-client", []):
            if not yes(c.get("disabled")) and str(c.get("use-ipsec") or "no") == "no":
                add(d, "medium", "Encryption", "L2TP client without IPsec", f"{c.get('name')} to {c.get('connect-to')}.", "Enable use-ipsec, or replace with WireGuard.")
        for p in inv.get("/ip/ipsec/proposal", []):
            if yes(p.get("disabled")):
                continue
            weak = [x for x in (WEAK_ENC.findall(str(p.get("enc-algorithms") or "")) + WEAK_HASH.findall(str(p.get("auth-algorithms") or ""))
                               + WEAK_DH.findall(str(p.get("pfs-group") or "")))]
            if weak:
                add(d, "medium", "Encryption", "Weak IPsec proposal", f"\"{p.get('name')}\": {', '.join(sorted(set(weak)))}.",
                    "Use aes-256-gcm or aes-256-cbc with sha256, and pfs-group modp2048 or ecp256 (both ends).")
        for p in inv.get("/ip/ipsec/profile", []):
            weak = (WEAK_ENC.findall(str(p.get("enc-algorithm") or "")) + WEAK_HASH.findall(str(p.get("hash-algorithm") or ""))
                    + WEAK_DH.findall(str(p.get("dh-group") or "")))
            if weak:
                add(d, "medium", "Encryption", "Weak IPsec profile (phase 1)", f"\"{p.get('name')}\": {', '.join(sorted(set(weak)))}.",
                    "Use aes-256 with sha256 and dh-group modp2048 / ecp256 (both ends).")
        for p in inv.get("/ip/ipsec/peer", []):
            if not yes(p.get("disabled")) and str(p.get("exchange-mode")) == "aggressive":
                add(d, "medium", "Encryption", "IPsec aggressive mode", f"Peer \"{p.get('name')}\".", "Use ike2 (or main mode) - aggressive mode leaks the key hash.")
        for s in inv.get("/interface/ovpn-server/server", []):
            if yes(s.get("enabled")):
                weak = WEAK_ENC.findall(str(s.get("cipher") or "")) + WEAK_HASH.findall(str(s.get("auth") or ""))
                if weak:
                    add(d, "medium", "Encryption", "Weak OpenVPN ciphers", ", ".join(sorted(set(weak))), "Allow only aes-256-gcm / aes-256-cbc with sha256.")
        ssh = (inv.get("/ip/ssh") or [{}])[0]
        if ssh and str(ssh.get("strong-crypto") or "") in ("no", "false"):
            add(d, "low", "Encryption", "SSH allows older ciphers", "strong-crypto is off.", "/ip ssh set strong-crypto=yes")
        # --- VPN health ---------------------------------------------------------------------------------------------
        for t in vpninv.normalize(inv) if inv else []:
            dials_in = t.get("kind") == "WireGuard" and not t.get("remote")   # a laptop / phone peer: not connected most of the time
            if t.get("status") == "down" and not dials_in:
                add(d, "medium", "VPN", f"{t['kind']} down", f"{t['name']}" + (f" to {t['remote']}" if t.get("remote") else "") + (f" ({t['since']})" if t.get("since") else ""),
                    "Check the far end and its internet; Site-to-site VPN > Restart tunnel if it's stuck.")
            elif "no phase 2" in (t.get("notes") or ""):
                add(d, "medium", "VPN", "IPsec without phase 2", t["name"], "Phase 1 is up but no traffic SAs - check the policies / proposals match on both ends.")
        # --- updates ------------------------------------------------------------------------------------------------
        if d.get("dm_flagged"):
            add(d, "critical", "Updates", "RouterOS flagged its own configuration", "Device mode marked this router 'flagged' - often a sign of compromise.",
                "Review users, scripts, schedulers and files now; then /system device-mode update flagged=no.")
        if (d.get("cve_max") or 0) >= 7 or d.get("cve_n"):
            sev = "critical" if (d.get("cve_max") or 0) >= 9 else "high" if (d.get("cve_max") or 0) >= 7 else "medium"
            add(d, sev, "Updates", "Known vulnerabilities", f"{d.get('cve_n') or 0} CVE(s) for RouterOS {d.get('version')}" + (f", worst {d['cve_max']}" if d.get("cve_max") else ""),
                f"Upgrade RouterOS{' to ' + d['sec_target'] if d.get('sec_target') else ''} (Upgrades).")
        elif d.get("ros_latest") and d.get("version") and d["ros_latest"] != str(d["version"]).split()[0]:
            add(d, "low", "Updates", "RouterOS update available", f"{d['version']} -> {d['ros_latest']}.", "Schedule it on Upgrades.")
        if d.get("fw_upgrade") and d.get("fw_current") and d["fw_upgrade"] != d["fw_current"]:
            add(d, "low", "Updates", "RouterBOOT firmware behind", f"{d['fw_current']} -> {d['fw_upgrade']}.", "/system routerboard upgrade, then reboot.")
        if d.get("lc_status") == "discontinued":
            add(d, "low", "Updates", "Model discontinued", d.get("model") or "", "Plan a replacement (see the router's lifecycle box).")
        # --- backups / hygiene --------------------------------------------------------------------------------------
        if not d.get("last_backup_at") or now - d["last_backup_at"] > 7 * 86400:
            add(d, "medium", "Backups", "No recent configuration backup",
                f"Last backup {_ago(now - d['last_backup_at']) + ' ago' if d.get('last_backup_at') else 'never'}" + (f" - {d['last_backup_error']}" if d.get("last_backup_error") else ""),
                "Back up now from the router page and check why the nightly one fails.")
        for u in inv.get("/user", []):
            if u.get("name") == "admin" and not yes(u.get("disabled")):
                add(d, "medium", "Hygiene", "Default 'admin' user enabled", "The first name every attacker tries.", "Create named accounts, then disable or rename 'admin'.")
        ntp = (inv.get("/system/ntp/client") or [{}])[0]
        if ntp and not yes(ntp.get("enabled")):
            add(d, "low", "Hygiene", "Clock not synced (NTP off)", "Log times and certificates depend on it.", "/system ntp client set enabled=yes servers=time.cloudflare.com")
    out.sort(key=lambda f: (SEV_ORDER[f["severity"]], CATEGORIES.index(f["category"]), f["org"], f["router"]))
    return out


def _ago(s):
    s = int(max(0, s))
    return f"{s // 86400} d" if s >= 86400 else f"{s // 3600} h" if s >= 3600 else f"{s // 60} min" if s >= 60 else f"{s} s"
