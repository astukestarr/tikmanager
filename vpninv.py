"""VPNs that were already configured on the routers (by hand, or by another tool) - read-only inventory.

The poller collects the raw menus every 15 minutes (routeros.RouterOS.vpn_inventory - a field whitelist, so no passwords,
pre-shared keys or private keys are ever read). normalize() turns them into one list per router:
    {kind, name, remote, status (up/down/disabled/listening), since, networks, rx, tx, notes, users}
and link() points each tunnel's remote address at the TikManager router that owns it (by WAN / public IP), so the
"Existing VPNs" page shows which sites already talk to each other. TikManager's own tunnels are left out.
"""
import json

from routeros import VPN_IFACE, _dur_s

OWN = {"tikmanager", VPN_IFACE}
UP_SECONDS = 180
CLIENTS = {"/interface/l2tp-client": "L2TP client", "/interface/sstp-client": "SSTP client", "/interface/ovpn-client": "OpenVPN client",
           "/interface/pptp-client": "PPTP client"}
SERVERS = {"/interface/l2tp-server/server": ("L2TP server", "l2tp"), "/interface/sstp-server/server": ("SSTP server", "sstp"),
           "/interface/ovpn-server/server": ("OpenVPN server", "ovpn"), "/interface/pptp-server/server": ("PPTP server", "pptp")}
TUNNELS = {"/interface/eoip": "EoIP tunnel", "/interface/gre": "GRE tunnel", "/interface/ipip": "IPIP tunnel"}


def yes(v):
    return str(v).lower() in ("true", "yes")


def host(addr):
    """'203.0.113.5/32' or '203.0.113.5:500' -> '203.0.113.5' (names are kept as they are)."""
    a = str(addr or "").strip()
    if not a:
        return ""
    a = a.split("/")[0]
    if a.count(":") == 1:
        a = a.split(":")[0]
    return a


def normalize(raw):
    if not raw:
        return []
    out = []
    routes = [r for r in raw.get("/ip/route", []) if not yes(r.get("disabled"))]
    via = lambda iface: [r["dst-address"] for r in routes if r.get("gateway") == iface and r.get("dst-address") not in ("0.0.0.0/0", None)]

    # WireGuard: one row per peer (a site, or a remote-access user)
    ifaces = {i.get("name"): i for i in raw.get("/interface/wireguard", [])}
    for p in raw.get("/interface/wireguard/peers", []):
        iface = p.get("interface")
        if iface in OWN:
            continue
        age = _dur_s(p.get("last-handshake"))
        state = "disabled" if yes(p.get("disabled")) or yes((ifaces.get(iface) or {}).get("disabled")) else \
            "up" if age is not None and age < UP_SECONDS else "down"
        nets = [n for n in str(p.get("allowed-address") or "").split(",") if n]
        out.append({"kind": "WireGuard", "name": f"{iface}: {p.get('comment') or p.get('name') or (nets[0] if nets else 'peer')}",
                    "remote": host(p.get("endpoint-address") or p.get("current-endpoint-address")),
                    "status": state, "since": f"handshake {age}s ago" if age is not None else "never connected",
                    "networks": nets, "rx": int(p.get("rx") or 0), "tx": int(p.get("tx") or 0),
                    "notes": "" if p.get("endpoint-address") else "remote end connects in", "iface": iface})

    # IPsec: one row per peer, with its policies (the subnets it carries) and whether phase 1/2 are up
    active = {host(a.get("remote-address")): a for a in raw.get("/ip/ipsec/active-peers", [])}
    policies = [p for p in raw.get("/ip/ipsec/policy", []) if not yes(p.get("template")) and not yes(p.get("disabled"))]
    for peer in raw.get("/ip/ipsec/peer", []):
        remote = host(peer.get("address"))
        a = active.get(remote)
        pol = [p for p in policies if p.get("peer") == peer.get("name")]
        ph2 = [p.get("ph2-state") for p in pol]
        if yes(peer.get("disabled")):
            state = "disabled"
        elif a and a.get("state") == "established" and (not pol or "established" in ph2):
            state = "up"
        elif yes(peer.get("passive")) and not a:
            state = "listening"
        else:
            state = "down"
        notes = []
        if a and a.get("state") == "established" and pol and "established" not in ph2:
            notes.append("phase 1 up, no phase 2 (check the policies / proposals)")
        if remote in ("0.0.0.0", "::"):
            notes.append("accepts any address (remote-access)")
        out.append({"kind": "IPsec", "name": peer.get("name") or remote, "remote": "" if remote in ("0.0.0.0", "::") else remote,
                    "status": state, "since": f"up {a.get('uptime')}" if a and a.get("uptime") else "",
                    "networks": [f"{p.get('src-address')} ↔ {p.get('dst-address')}" for p in pol],
                    "rx": int((a or {}).get("rx-bytes") or 0), "tx": int((a or {}).get("tx-bytes") or 0), "notes": "; ".join(notes)})

    # dial-out clients and plain tunnels
    for menu, kind in {**CLIENTS, **TUNNELS}.items():
        for c in raw.get(menu, []):
            if c.get("name") in OWN:
                continue
            state = "disabled" if yes(c.get("disabled")) else "up" if yes(c.get("running")) else "down"
            notes = []
            if menu.endswith("pptp-client"):
                notes.append("PPTP is insecure - replace it")
            if yes(c.get("use-ipsec")) or c.get("use-ipsec") == "required":
                notes.append("with IPsec")
            out.append({"kind": kind, "name": c.get("name"), "remote": host(c.get("connect-to") or c.get("remote-address")), "status": state,
                        "since": "", "networks": via(c.get("name")), "rx": 0, "tx": 0, "notes": "; ".join(notes)})

    # remote-access servers, with who is connected right now (names and addresses only)
    ppp = raw.get("/ppp/active", [])
    for menu, (kind, service) in SERVERS.items():
        srv = (raw.get(menu) or [{}])[0]
        if not yes(srv.get("enabled")):
            continue
        users = [f"{u.get('name')} ({u.get('caller-id') or u.get('address')}, {u.get('uptime')})" for u in ppp if u.get("service") == service]
        out.append({"kind": kind, "name": kind, "remote": "", "status": "listening", "since": f"{len(users)} connected",
                    "networks": [], "rx": 0, "tx": 0, "users": users,
                    "notes": "PPTP is insecure - replace it" if service == "pptp" else ("with IPsec" if yes(srv.get("use-ipsec")) else "")})
    return out


def link(tunnels, routers, self_id):
    """Add {peer: {id, name}} when a tunnel's remote address is another TikManager router's WAN or public IP."""
    by_ip = {}
    for r in routers:
        for ip in (r.get("wan_ip"), r.get("public_ip")):
            if ip and r["id"] != self_id:
                by_ip.setdefault(ip, r)
    for t in tunnels:
        r = by_ip.get(t.get("remote"))
        if r:
            t["peer"] = {"id": r["id"], "name": r["name"], "org": r.get("org")}
    return tunnels


def for_device(d, routers):
    try:
        raw = json.loads(d.get("vpn_inv") or "null")
    except ValueError:
        raw = None
    return link(normalize(raw), routers, d["id"]) if raw else None
