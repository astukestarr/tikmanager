"""The network map behind one router (like Auvik's): Internet -> router -> networks (LAN, VLANs) -> switches and access
points found by neighbour discovery -> groups of devices (phones, printers, servers, ...), plus the routes to other
networks (VPNs, static routes).

Built from what the router already knows (RouterOS.topology(), read live): the routing table, MNDP / LLDP / CDP
neighbours, the ARP table, bridge host table (which port each MAC is on) and DHCP leases. Infrastructure and routes
come out exactly; end devices are recognised from the maker's MAC prefix and the device name, so some stay
"Unidentified" (a scanner like Auvik's would use SNMP).
"""
import ipaddress
import re

# MAC prefixes (OUI) of makers that mostly make one kind of device. Only clear-cut ones: a PC maker's NICs could be
# anything, so computers are recognised by name instead.
OUI = {}
for kind, prefixes in {
    "phone": "80:5E:C0 80:5E:0C 24:9A:D8 00:04:F2 64:16:7F 00:0B:82 C0:74:AD EC:74:D7 08:00:0F 00:04:13 0C:38:3E",
    "printer": "00:80:77 00:1B:A9 30:05:5C 00:00:85 00:1E:8F 2C:9E:FC 00:26:AB 64:EB:8C 38:1A:52 AC:18:26 00:04:00 00:21:B7 "
               "00:00:AA 9C:93:4E 00:26:73 58:38:79 00:C0:EE 00:07:4D",
    "server": "00:50:56 00:0C:29 00:05:69 00:15:5D BC:24:11 00:11:32 24:5E:BE 00:08:9B 00:16:3E 08:00:27",
    "camera": "00:40:8C AC:CC:8E B8:A4:4F 44:19:B6 BC:AD:28 C0:56:E3 4C:BD:8F 3C:EF:8C 90:02:A9 E0:50:8B",
    "iot": "B8:27:EB DC:A6:32 E4:5F:01 28:CD:C1 2C:CF:67 00:0E:58 5C:AA:FD 94:9F:3E 18:B4:30 B0:A7:37 DC:3A:5E 44:61:32",
    "network": "4C:5E:0C 6C:3B:6B B8:69:F4 CC:2D:E0 D4:CA:6D E4:8D:8C 48:8F:5A 2C:C8:1B 08:55:31 74:4D:28 18:FD:74 64:D1:54 "
               "DC:2C:6E C4:AD:34 24:A4:3C 44:D9:E7 78:8A:20 F0:9F:C2 FC:EC:DA 74:83:C2 18:E8:29 B4:FB:E4 80:2A:A8 68:D7:9A E0:63:DA "
               "00:18:0A 88:15:44 E0:55:3D 00:0B:86 24:DE:C6",
}.items():
    for p in prefixes.split():
        OUI[p] = kind

NAMES = [   # (kind, pattern on the device name) - checked in this order
    ("network", r"^(sw|ap)[-_ ]|switch|unifi|usw|uap|meraki|aruba"),
    ("phone", r"^sep[0-9a-f]{12}$|yealink|sip-?t\d|polycom|vvx|grandstream|gxp|snom|fanvil|desk-?phone|voip"),
    ("printer", r"printer|^br[nw][0-9a-f]|^npi|epson|canon|^hp[0-9a-f]{6}|laserjet|officejet|xerox|ricoh|kyocera|lexmark|mfp|copier|zebra"),
    ("camera", r"cam(era)?\b|nvr|dvr|ipc|hikvision|axis|reolink|doorbird|lorex"),
    ("server", r"srv|server|^dc\d|^dc-|nas\b|^nas|esxi|hyper-?v|vcenter|proxmox|^sql|backup|^vm-"),
    ("computer", r"^desktop-|^laptop-|^win-|-pc$|-lt$|-ws$|\bpc\b|laptop|macbook|imac|workstation|surface|thinkpad"),
    ("mobile", r"iphone|ipad|android|galaxy|pixel|oneplus|moto|watch"),
    ("iot", r"\bpi\b|^pi-|raspberry|thermostat|nest|ecobee|roku|chromecast|sonos|echo|alexa|ring|hue|tv\b|-tv|sensor"),
]
LABELS = {"network": "Network devices", "phone": "Phones", "printer": "Printers", "camera": "Cameras", "server": "Servers & VMs",
          "computer": "Computers", "mobile": "Personal devices", "iot": "IoT", "unknown": "Unidentified"}
ORDER = list(LABELS)


def kind_of(mac, name):
    n = (name or "").lower()
    for kind, rx in NAMES:
        if n and re.search(rx, n):
            return kind
    m = (mac or "").upper()
    if m[:8] in OUI:
        return OUI[m[:8]]
    # a randomised ("private") MAC - phones, tablets and laptops do this on Wi-Fi
    if len(m) >= 2 and m[1] in "26AE":
        return "mobile"
    return "unknown"


def _net(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _ip(a):
    try:
        return ipaddress.ip_address(str(a).split("/")[0])
    except ValueError:
        return None


def _port(iface):
    """'ether2,bridge' (a bridge port, as /ip neighbor shows it) -> 'ether2'."""
    return str(iface or "").split(",")[0].strip()


def build(raw, device, full=True):
    """raw = RouterOS.topology(); device = the TikManager device row. full=False (client users): the routing table is
    reduced to the Internet route - it can show other networks an MSP has connected."""
    addrs = [a for a in raw.get("addresses") or [] if a.get("disabled") != "true"]
    comments = {i.get("name"): i.get("comment") or "" for i in raw.get("interfaces") or []}
    vlan_id = {v.get("name"): v.get("vlan-id") for v in raw.get("vlans") or []}
    routes = [r for r in raw.get("routes") or [] if r.get("disabled") != "true"]

    # the Internet: active default routes (several = failover / multi-WAN)
    defaults = sorted((r for r in routes if r.get("dst-address") == "0.0.0.0/0"), key=lambda r: (r.get("active") != "true", int(r.get("distance") or 1)))
    wan_if = _port(str(defaults[0].get("immediate-gw") or "").split("%")[-1]) if defaults and "%" in str(defaults[0].get("immediate-gw") or "") else ""
    internet = {"wan_ip": device.get("wan_ip") or device.get("public_ip") or "", "interface": wan_if,
                "gateways": [{"gateway": str(r.get("gateway") or ""), "active": r.get("active") == "true", "distance": r.get("distance") or ""}
                             for r in defaults]}

    # networks the router is on (not the WAN, not TikManager's tunnel, not /32s)
    networks = []
    for a in addrs:
        iface, addr = a.get("interface") or "", a.get("address") or ""
        if iface in (wan_if, "tikmanager", "tikmanager-vpn") or addr.endswith("/32") or "/" not in addr:
            continue
        net = _net(f"{a.get('network') or addr.split('/')[0]}/{addr.split('/')[1]}")
        if not net or (device.get("wan_ip") and _ip(device["wan_ip"]) in net):
            continue
        networks.append({"name": comments.get(iface) or a.get("comment") or iface, "interface": iface, "network": str(net),
                         "gateway": addr.split("/")[0], "vlan": vlan_id.get(iface), "_net": net, "infra": [], "groups": {}})

    def network_for(ip, iface=""):
        i = _ip(ip)
        for n in networks:
            if i and i in n["_net"]:
                return n
        return next((n for n in networks if iface and n["interface"] == iface), None)

    # devices: ARP + DHCP leases, joined on MAC; the bridge host table says which port each MAC is on
    port_of = {str(h.get("mac-address") or "").upper(): _port(h.get("on-interface")) for h in raw.get("hosts") or [] if h.get("local") != "true"}
    devices = {}
    for a in raw.get("arp") or []:
        mac = str(a.get("mac-address") or "").upper()
        if mac and a.get("complete", "true") != "false":
            devices.setdefault(mac, {"mac": mac, "ip": a.get("address") or "", "name": "", "iface": a.get("interface") or ""})
    for l in raw.get("leases") or []:
        mac = str(l.get("mac") or "").upper()
        if not mac or l.get("disabled"):
            continue
        d = devices.setdefault(mac, {"mac": mac, "ip": l.get("address") or "", "name": "", "iface": l.get("interface") or ""})
        d["name"] = l.get("host") or l.get("comment") or d["name"]
        d["ip"] = d["ip"] or l.get("address") or ""

    # switches / access points / routers next door (neighbour discovery), placed on their network and port
    other = {"name": "Other", "interface": "", "network": "", "gateway": "", "vlan": None, "infra": [], "groups": {}}
    infra_by_port = {}
    for nb in raw.get("neighbors") or []:
        mac = str(nb.get("mac-address") or "").upper()
        port = _port(nb.get("interface"))
        node = {"name": nb.get("identity") or nb.get("address") or mac, "ip": nb.get("address4") or nb.get("address") or "", "mac": mac,
                "platform": nb.get("platform") or "", "model": nb.get("board") or "", "version": nb.get("version") or "",
                "port": port, "via": nb.get("discovered-by") or "", "groups": {}}
        n = network_for(node["ip"], port) or network_for("", (nb.get("interface") or "").split(",")[-1].strip())
        (n or other)["infra"].append(node)
        devices.pop(mac, None)
        if port and port != (n or {}).get("interface"):
            infra_by_port.setdefault(port, node)

    for d in devices.values():
        kind = kind_of(d["mac"], d["name"])
        entry = {"name": d["name"] or d["ip"] or d["mac"], "ip": d["ip"], "mac": d["mac"], "port": port_of.get(d["mac"], "")}
        target = infra_by_port.get(entry["port"])   # behind a switch / AP on the same router port
        if target is None:
            target = network_for(d["ip"], d["iface"]) or other
        target["groups"].setdefault(kind, []).append(entry)

    def groups(g):
        return [{"kind": k, "label": LABELS[k], "count": len(g[k]), "devices": sorted(g[k], key=lambda x: _ip(x["ip"]) or ipaddress.ip_address("255.255.255.255"))}
                for k in ORDER if g.get(k)]

    out_nets = []
    for n in networks + ([other] if other["groups"] or other["infra"] else []):
        out_nets.append({"name": n["name"], "interface": n["interface"], "network": n["network"], "gateway": n["gateway"], "vlan": n["vlan"],
                         "infra": [{**i, "groups": groups(i["groups"])} for i in n["infra"]], "groups": groups(n["groups"])})

    # routes to other networks: VPNs, static and dynamic routes (not connected networks, not the default, not TikManager)
    connected = {n["network"] for n in out_nets}
    others = []
    for r in routes:
        dst = r.get("dst-address") or ""
        if dst in ("0.0.0.0/0", "") or r.get("connect") == "true" or dst in connected or str(r.get("comment") or "") == "TikManager":
            continue
        if _net(dst) and _net(dst).subnet_of(ipaddress.ip_network("10.77.0.0/16")):
            continue
        kind = "vpn" if "vpn" in str(r.get("comment") or "").lower() or "vpn" in str(r.get("gateway") or "").lower() else \
            "dynamic" if (r.get("bgp") or r.get("ospf") or (r.get("dynamic") == "true" and r.get("static") != "true")) else "static"
        others.append({"dst": dst, "gateway": str(r.get("gateway") or ""), "kind": kind, "active": r.get("active") == "true",
                       "comment": r.get("comment") or "", "table": r.get("routing-table") or ""})
    total = sum(g["count"] for n in out_nets for g in n["groups"]) + sum(g["count"] for n in out_nets for i in n["infra"] for g in i["groups"])
    return {"internet": internet, "networks": out_nets, "routes": others if full else [], "routes_hidden": (not full) and bool(others),
            "devices": total, "infra": sum(len(n["infra"]) for n in out_nets)}
