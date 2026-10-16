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


# One-click fixes: a fixed list of single settings TikManager may change (never free text from a finding). The plain-HTTP
# www service is deliberately not here - TikManager itself talks to routers over REST on it.
# id: (button label, REST path, body, what it may affect)
FIXES = {
    "ssh_strong": ("Turn on SSH strong crypto", "/ip/ssh/set", {"strong-crypto": "yes"},
                   "Very old SSH clients (from before about 2015) may no longer connect. Where SSH also allows the null (no encryption) "
                   "cipher, the cipher list is set to aes-ctr, aes-gcm."),
    "svc_telnet": ("Disable Telnet", "/ip/service/set", {"numbers": "telnet", "disabled": "yes"}, "Anyone still using Telnet uses SSH or Winbox instead."),
    "svc_ftp": ("Disable FTP", "/ip/service/set", {"numbers": "ftp", "disabled": "yes"}, "Anything uploading files to the router by FTP stops working."),
    "svc_api": ("Disable the plain-text API (port 8728)", "/ip/service/set", {"numbers": "api", "disabled": "yes"},
                "Tools using the API on port 8728 (The Dude, some monitoring) need api-ssl instead. TikManager doesn't use it."),
    "socks_off": ("Turn off the SOCKS proxy", "/ip/socks/set", {"enabled": "no"}, "Then check the router's users and scripts - SOCKS is often left by an attacker."),
    "proxy_off": ("Turn off the web proxy", "/ip/proxy/set", {"enabled": "no"}, "Anything deliberately sent through the router's proxy stops working."),
    "upnp_off": ("Turn off UPnP", "/ip/upnp/set", {"enabled": "no"}, "Game consoles or apps that open their own ports may need a manual port forward."),
    "bwtest_off": ("Turn off the bandwidth test server", "/tool/bandwidth-server/set", {"enabled": "no"}, "Bandwidth tests against this router stop working."),
    "macsrv_lan": ("Limit MAC Telnet to the LAN", "/tool/mac-server/set", {"allowed-interface-list": "LAN"}, "Where there's no interface list called LAN (switches, custom setups) MAC Telnet is turned off instead; MAC Winbox is a separate setting and stays as it is."),
    "ntp_on": ("Turn on NTP", "/system/ntp/client/set", {"enabled": "yes"}, "Uses time.cloudflare.com if no time server is set."),
    "www_tm": ("Limit WebFig (HTTP) to TikManager", "/ip/service/set", {"numbers": "www"},
               "TikManager keeps managing the router (it connects over its own encrypted tunnel). WebFig over plain HTTP stops "
               "working for addresses you don't also allow; WebFig over HTTPS (www-ssl) and Winbox are separate and not touched. "
               "If TikManager can't reach the router afterwards, the router puts the old setting back by itself within 2 minutes."),
}
FIXES.update({
    "use_https": ("Switch TikManager to HTTPS", None, None,
                  "TikManager sets up www-ssl and moves to it only once HTTPS answers; HTTP stays as it is (TikManager falls back to it if "
                  "HTTPS ever stops). A port other than 443 and an existing certificate are kept; 443 moves to 8443 only when SSTP or another "
                  "service already uses it. www-ssl is limited to the LAN ranges + TikManager if it was open to everyone (TikManager only "
                  "if it was off), so it isn't open to the internet."),
    "www_off": ("Turn off WebFig over HTTP (TikManager uses HTTPS)", "/ip/service/set", {"numbers": "www", "disabled": "yes"},
                "TikManager already manages this router over HTTPS. WebFig over plain HTTP stops for everyone - use WebFig over HTTPS or "
                "Winbox. If TikManager can't reach the router afterwards, the router turns HTTP back on by itself within 2 minutes."),
    "wwwssl_lan": ("Limit WebFig over HTTPS to the LAN and TikManager", "/ip/service/set", {"numbers": "www-ssl"},
                   "www-ssl's \"available from\" becomes the private ranges (10/8, 172.16/12, 192.168/16) + TikManager, so it can't be "
                   "reached from the internet. If TikManager can't reach the router afterwards, the router puts it back within 2 minutes."),
})
TM_IP = "10.77.0.1"   # TikManager's tunnel address (server.py sets it from WG_SERVER_IP) - the source of every REST call
GUARDED = {"www_tm", "www_off", "wwwssl_lan"}   # fixes that touch how TikManager reaches the router: armed undo, kept only if still reachable
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def svc_addr(s):
    """A service's "available from" list (RouterOS 7.20+ calls it available-from, older versions address)."""
    return s.get("available-from") or s.get("address") or ""


def svc_prop(inv):
    return "available-from" if any("available-from" in s for s in inv.get("/ip/service", [])) else "address"


def _svc_restore(name, old):
    """RouterOS script setting a service's address list back - under either property name (:parse, as the adoption does)."""
    if not SAFE_ADDR.match(old):
        raise ValueError(f"unexpected address list on the {name} service")
    return (f':do {{ :local f [:parse "/ip service set [find name={name}] available-from=\\"{old}\\""]; $f }} '
            f'on-error={{ :local f [:parse "/ip service set [find name={name}] address=\\"{old}\\""]; $f }}')
SAFE_ADDR = re.compile(r"^[0-9A-Fa-f.:/,]*$")


def fix_retry(fix_id, error, body=None):
    """A second attempt when the router refused the first for a known reason, else None. RouterOS won't turn on SSH
    strong-crypto while its cipher list allows null ("strong-crypto and none cipher can't be used at the same time")."""
    if body and ("address" in body or "available-from" in body) and "unknown parameter" in str(error):   # 7.20+ renamed it
        b = dict(body)
        if "address" in b:
            b["available-from"] = b.pop("address")
        else:
            b["address"] = b.pop("available-from")
        return "/ip/service/set", b
    if fix_id == "ssh_strong" and "none cipher" in str(error):
        return "/ip/ssh/set", {"ciphers": "aes-ctr,aes-gcm", "strong-crypto": "yes"}
    if fix_id == "macsrv_lan" and "allowed-interface-list" in str(error):   # no interface list called LAN (switches, custom setups)
        return "/tool/mac-server/set", {"allowed-interface-list": "none"}
    return None


def fix_undo(fix_id, inv):
    """RouterOS script that puts a guarded fix back (run by a scheduler unless TikManager cancels it), else None."""
    if fix_id in ("www_tm", "wwwssl_lan"):
        name = "www" if fix_id == "www_tm" else "www-ssl"
        return _svc_restore(name, next((svc_addr(s) for s in inv.get("/ip/service", []) if s.get("name") == name), ""))
    if fix_id == "www_off":
        return "/ip service set [find name=www] disabled=no"
    return None


def clean_extra(raw):
    """Optional extra addresses for "Limit WebFig to TikManager" ("192.168.10.0/24, 10.0.0.5") -> list, or ValueError."""
    import ipaddress
    out = []
    for x in str(raw or "").replace(";", ",").replace(" ", ",").split(","):
        if x.strip():
            out.append(str(ipaddress.ip_network(x.strip(), strict=False)))
    return out[:20]


def fix_request(fix_id, inv, extra=None):
    """(REST path, body) for a one-click fix on a router with this inventory."""
    _, path, body, _ = FIXES[fix_id]
    body = dict(body)
    if fix_id == "www_tm":   # TikManager's tunnel address first, then any addresses the technician also allows
        body[svc_prop(inv)] = ",".join(dict.fromkeys([f"{TM_IP}/32"] + list(extra or [])))
    if fix_id == "wwwssl_lan":
        body[svc_prop(inv)] = ",".join(list(PRIVATE) + [f"{TM_IP}/32"])
    if fix_id == "ntp_on" and not ((inv.get("/system/ntp/client") or [{}])[0].get("servers")):
        body["servers"] = "time.cloudflare.com"
    return path, body


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
        if name not in MGMT or yes(s.get("disabled")) or svc_addr(s):   # off, or limited to some addresses on the router
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

    def add(d, sev, cat, title, detail, fix, fix_id=None):
        out.append({"device_id": d["id"], "router": d["name"], "org": d.get("org") or "", "severity": sev, "category": cat,
                    "title": title, "detail": detail, "fix": fix, "fix_id": fix_id})

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
                    why, (f"Don't disable it - TikManager manages the router through it. Limit it to TikManager's tunnel address ({TM_IP}) "
                          "with the one-click fix (or add your management network too: /ip service set www address=...)." if name == "www" else
                          f"Limit /ip service {name} to your management addresses (address=...), or drop it on the WAN in the input chain."),
                    ("www_off" if d.get("api_tls_port") else "www_tm") if name == "www" else "wwwssl_lan" if name == "www-ssl"
                    else f"svc_{name}" if f"svc_{name}" in FIXES else None)
            if not caught:
                add(d, "critical" if open_svc else "high", "Exposure", "Input firewall has no catch-all drop",
                    "Anything the router itself offers is reachable from the internet.",
                    "Add a final input rule: drop everything not from the LAN (like MikroTik's default 'drop all not coming from LAN').")
            for s in inv.get("/ip/service", []):
                if s.get("name") in PLAINTEXT and not yes(s.get("disabled")) and s.get("name") not in open_svc:
                    if s["name"] == "www":   # TikManager's own way in (REST) - never disable it; limit who can reach it
                        if d.get("api_tls_port"):   # TikManager is on HTTPS: plain HTTP can go
                            add(d, "medium", "Exposure", "WebFig over plain HTTP enabled",
                                "Passwords cross the network in plain text. TikManager already uses HTTPS for this router, so HTTP isn't needed.",
                                "Turn WebFig over HTTP off (one-click, undone by the router itself if TikManager lost contact).", "www_off")
                        elif not svc_addr(s):
                            add(d, "medium", "Exposure", "WebFig over plain HTTP enabled",
                                "Anyone on the LAN can open WebFig over plain HTTP, so passwords cross the network unencrypted.",
                                f"Don't disable www while TikManager uses it - switch TikManager to HTTPS first, then turn HTTP off; or limit www "
                                f"to TikManager's tunnel address ({TM_IP}) and your admin addresses with the one-click fix.", "www_tm")
                        continue
                    add(d, "medium", "Exposure", f"{PLAINTEXT[s['name']]} enabled", "Passwords cross the network in plain text.",
                        f"/ip service disable {s['name']} (use {'SSH' if s['name'] in ('telnet', 'ftp') else 'HTTPS / api-ssl'} instead).",
                        f"svc_{s['name']}" if f"svc_{s['name']}" in FIXES else None)
            dns = (inv.get("/ip/dns") or [{}])[0]
            if yes(dns.get("allow-remote-requests")) and not caught:
                add(d, "high", "Exposure", "Open DNS resolver", "The router answers DNS for anyone - it can be abused for DDoS attacks.",
                    "Drop UDP/TCP 53 from the WAN in the input chain (or a catch-all drop).")
            on = lambda menu: yes((inv.get(menu) or [{}])[0].get("enabled"))
            if on("/ip/socks"):
                add(d, "high", "Exposure", "SOCKS proxy enabled", "Rarely wanted - often a sign of a compromised router.", "/ip socks set enabled=no, then check users and scripts.", "socks_off")
            if on("/ip/proxy"):
                add(d, "high" if not caught else "medium", "Exposure", "Web proxy enabled", "An open proxy is abused quickly.", "/ip proxy set enabled=no unless it's needed.", "proxy_off")
            if on("/ip/upnp"):
                add(d, "medium", "Exposure", "UPnP enabled", "Devices on the LAN can open ports to the internet by themselves.", "/ip upnp set enabled=no unless a game console needs it.", "upnp_off")
            if on("/tool/bandwidth-server"):
                add(d, "low", "Exposure", "Bandwidth test server enabled", "Can be used to load the router and link.", "/tool bandwidth-server set enabled=no", "bwtest_off")
            mac = (inv.get("/tool/mac-server") or [{}])[0]
            if str(mac.get("allowed-interface-list") or "") == "all":
                add(d, "low", "Exposure", "MAC Telnet on every interface", "Layer-2 management reachable from any port.", "/tool mac-server set allowed-interface-list=LAN", "macsrv_lan")
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
        if inv.get("/ip/service") and not d.get("api_tls_port"):
            add(d, "low", "Encryption", "TikManager manages this router over HTTP",
                "The connection runs inside TikManager's encrypted WireGuard tunnel; HTTPS adds a second layer and lets WebFig over plain "
                "HTTP be turned off.", "Switch to HTTPS (one-click, or the router's Settings tab) - HTTP keeps working until HTTPS is proven.", "use_https")
        ssh = (inv.get("/ip/ssh") or [{}])[0]
        if ssh and str(ssh.get("strong-crypto") or "") in ("no", "false"):
            null = "null" in str(ssh.get("ciphers") or "")
            add(d, "low", "Encryption", "SSH allows older ciphers", "strong-crypto is off" + (", and the null (no encryption) cipher is allowed." if null else "."),
                "/ip ssh set ciphers=aes-ctr,aes-gcm strong-crypto=yes" if null else "/ip ssh set strong-crypto=yes", "ssh_strong")
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
            add(d, "low", "Hygiene", "Clock not synced (NTP off)", "Log times and certificates depend on it.", "/system ntp client set enabled=yes servers=time.cloudflare.com", "ntp_on")
    out.sort(key=lambda f: (SEV_ORDER[f["severity"]], CATEGORIES.index(f["category"]), f["org"], f["router"]))
    return out


def _ago(s):
    s = int(max(0, s))
    return f"{s // 86400} d" if s >= 86400 else f"{s // 3600} h" if s >= 3600 else f"{s // 60} min" if s >= 60 else f"{s} s"
