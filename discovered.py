"""MikroTik devices next to your routers that aren't in TikManager yet (Discovered page).

Every 15 minutes the poller stores each adopted router's MikroTik neighbours (/ip neighbor: MNDP / LLDP / CDP, platform
MikroTik). A neighbour counts as already in TikManager when any of these matches a router TikManager knows (adopted or
waiting for approval):
- one of its MAC addresses (each interface has its own; the neighbour shows the MAC of the port facing us),
- its IP address (WAN address, tunnel address or an address on one of its networks),
- its identity - unless it's still the factory "MikroTik", which tells routers apart from nothing.
The same device seen by several routers is listed once, with everyone who saw it.
"""
import json


def norm_mac(m) -> str:
    return str(m or "").strip().upper().replace("-", ":")


def known_sets(devices):
    macs, ips, names = {}, {}, {}
    for d in devices:
        for i in json.loads(d.get("interfaces") or "[]"):
            if i.get("mac"):
                macs[norm_mac(i["mac"])] = d
        for n in json.loads(d.get("networks") or "[]"):
            if n.get("address"):
                ips[n["address"].split("/")[0]] = d
        for ip in (d.get("wan_ip"), d.get("tunnel_ip"), d.get("public_ip")):
            if ip:
                ips[str(ip).split("/")[0]] = d
        for name in (d.get("identity"), d.get("name")):
            if name and name.strip().lower() != "mikrotik":
                names[name.strip().lower()] = d
    return macs, ips, names


def match(nb, sets):
    macs, ips, names = sets
    return (macs.get(norm_mac(nb.get("mac-address"))) or ips.get(str(nb.get("address4") or nb.get("address") or "").split("/")[0])
            or names.get(str(nb.get("identity") or "").strip().lower()))


def discovered(devices, orgs=None):
    """devices: rows with id, name, org_id, state, interfaces, networks, wan_ip, tunnel_ip, neighbors, neighbors_at.
    -> [{mac, identity, board, version, address, software_id, uptime, seen: [{device_id, router, org_id, org, interface, at}]}]"""
    orgs = orgs or {}
    sets = known_sets(devices)
    found = {}
    for d in devices:
        if d.get("state") != "adopted" or not d.get("neighbors"):
            continue
        for nb in json.loads(d["neighbors"]):
            if match(nb, sets):
                continue
            mac = norm_mac(nb.get("mac-address"))
            key = mac or f"{nb.get('identity')}|{nb.get('address')}"
            e = found.setdefault(key, {"mac": mac, "identity": nb.get("identity") or "", "board": nb.get("board") or "",
                                       "version": nb.get("version") or "", "address": nb.get("address4") or nb.get("address") or "",
                                       "software_id": nb.get("software-id") or "", "uptime": nb.get("uptime") or "", "seen": []})
            e["seen"].append({"device_id": d["id"], "router": d["name"], "org_id": d.get("org_id"), "org": orgs.get(d.get("org_id"), ""),
                              "interface": (nb.get("interface") or "").split(",")[0], "at": d.get("neighbors_at")})
    return sorted(found.values(), key=lambda e: (e["seen"][0]["org"].lower(), e["identity"].lower()))
