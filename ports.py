"""Ports and VLANs on a router or switch - a port diagram, VLAN grids and a port table (like UniFi's Ports page), and
changing them with a safety net.

What it reads (RouterOS.port_data()): physical ports (ethernet / SFP) with link speed and PoE, bridges, bridge ports
(pvid = native VLAN, frame types), the bridge VLAN table (tagged / untagged members per VLAN), VLAN interfaces and
addresses (names and subnets for VLANs), and who is connected to each port (bridge host table + neighbours + DHCP / ARP).

What it changes - MikroTik's *bridge VLAN filtering* model only (switch-chip VLAN setups of older CRS1xx/2xx are shown
read-only):
- per port: native VLAN (pvid), tagged VLANs (all / none / a list), name (comment), enabled, PoE out;
- VLANs: add, rename, delete; VLAN filtering on / off per bridge.

Safety (like the firewall editor, firewall.py): every change is shown as RouterOS commands first; before applying,
the router is backed up and an undo script is armed on the router itself - it puts back the bridge VLAN table, the
bridge ports' VLAN settings, the bridges' VLAN filtering and the touched ports exactly as they were - and runs in
TEST_MINUTES unless someone presses Keep. So a change that cuts TikManager off undoes itself.
The port and VLAN TikManager reaches the router through (from the default route) can't be changed or disabled here.
"""
import re
import threading
import time

from routeros import RouterError

UNDO_NAME = "tikmanager-vlan-undo"
TEST_MINUTES = 5
BACKUP_FRESH = 600
VID = re.compile(r"^\d{1,4}$")


class PortsError(Exception):
    pass


def quiet(fn, default=None):
    try:
        return fn()
    except RouterError:
        return default


def vids(s) -> list:
    """'10,20,30-32' -> [10, 20, 30, 31, 32]."""
    out = []
    for part in str(s or "").split(","):
        part = part.strip()
        if re.fullmatch(r"\d+-\d+", part):
            a, b = (int(x) for x in part.split("-"))
            out += list(range(a, min(b, a + 4094) + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


def members(s) -> list:
    return [x for x in str(s or "").split(",") if x]


def q(v) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def speed_class(rate: str) -> str:
    r = str(rate or "").lower()
    return "10g" if r.startswith(("10g", "25g", "40g", "100g")) else "2.5g" if r.startswith(("2.5g", "5g")) else \
           "1g" if r.startswith("1g") else "100m" if r.startswith(("100m", "10m")) else ""


def port_sort_key(name):
    m = re.match(r"^([a-z-]*?)(\d+)?(?:-(\d+))?$", name or "")
    return (0 if name.startswith("ether") else 1, m.group(1) if m else name, int(m.group(2)) if m and m.group(2) else 0, int(m.group(3)) if m and m.group(3) else 0)


def build(raw: dict) -> dict:
    """The router's raw tables -> {ports, vlans, bridges, mgmt, mode} for the page and for planning changes."""
    ifs = {i.get("name"): i for i in raw.get("interfaces") or []}
    bports = {p.get("interface"): p for p in raw.get("ports") or [] if p.get("interface")}
    bridges = {b.get("name"): b for b in raw.get("bridges") or []}
    static_vlans = [v for v in raw.get("vlans") or [] if v.get("dynamic") != "true"]
    # names and subnets for VLANs: VLAN interfaces, their addresses, the VLAN rows' comments
    vif = {}
    for v in raw.get("vlan_ifs") or []:
        if str(v.get("vlan-id", "")).isdigit():
            vif.setdefault(int(v["vlan-id"]), v)
    addr_by_if = {}
    for a in raw.get("addresses") or []:
        addr_by_if.setdefault(a.get("interface"), a.get("address"))
    vlans = {}
    for row in static_vlans:
        for vid in vids(row.get("vlan-ids")):
            v = vlans.setdefault(vid, {"id": vid, "name": "", "bridge": row.get("bridge"), "tagged": set(), "untagged": set(), "rows": []})
            v["tagged"] |= set(members(row.get("tagged")))
            v["untagged"] |= set(members(row.get("untagged")))
            v["rows"].append(row.get(".id"))
            if row.get("comment") and not v["name"]:
                v["name"] = row["comment"]
    for vid, i in vif.items():
        v = vlans.setdefault(vid, {"id": vid, "name": "", "bridge": i.get("interface"), "tagged": set(), "untagged": set(), "rows": []})
        v["name"] = v["name"] or i.get("name", "")
        v["subnet"] = addr_by_if.get(i.get("name"), "")
        v["l3"] = i.get("name")
    # who's on each port
    names = {}
    for l in raw.get("leases") or []:
        mac = str(l.get("active-mac-address") or l.get("mac-address") or "").upper()
        if mac:
            names[mac] = (l.get("host-name") or l.get("comment") or "", l.get("active-address") or l.get("address") or "")
    for a in raw.get("arp") or []:
        mac = str(a.get("mac-address") or "").upper()
        if mac and mac not in names:
            names[mac] = ("", a.get("address") or "")
    devs = {}
    for h in raw.get("hosts") or []:
        if h.get("local") == "true" or not h.get("on-interface"):
            continue
        mac = str(h.get("mac-address") or "").upper()
        n, ip = names.get(mac, ("", ""))
        devs.setdefault(h["on-interface"], []).append({"mac": mac, "name": n, "ip": ip, "vid": h.get("vid") or ""})
    neigh = {}
    for n in raw.get("neighbors") or []:
        for i in str(n.get("interface") or "").split(","):
            if n.get("identity"):
                neigh.setdefault(i, n.get("identity") + (f" ({n['board']})" if n.get("board") else ""))
    # TikManager's way in: the default route's interface -> the port the gateway is behind
    gw_if, gw_ip = "", ""
    for r in raw.get("routes") or []:
        if r.get("immediate-gw"):
            gw_ip, _, gw_if = r["immediate-gw"].partition("%")
            break
    mgmt_vid = None
    gw_vif = next((v for v in raw.get("vlan_ifs") or [] if v.get("name") == gw_if), None)
    if gw_vif:
        mgmt_vid = int(gw_vif["vlan-id"]) if str(gw_vif.get("vlan-id", "")).isdigit() else None
        gw_if_bridge = gw_vif.get("interface")
    else:
        gw_if_bridge = gw_if if gw_if in bridges else None
    mgmt_port = gw_if if gw_if in bports or gw_if in {e.get("name") for e in raw.get("ethernet") or []} and gw_if not in bridges else ""
    if gw_if_bridge:   # behind a bridge: find the gateway's MAC in the host table
        gw_mac = next((str(a.get("mac-address") or "").upper() for a in raw.get("arp") or [] if a.get("address") == gw_ip), "")
        mgmt_port = next((h.get("on-interface") for h in raw.get("hosts") or [] if str(h.get("mac-address") or "").upper() == gw_mac and gw_mac), "") or mgmt_port
    if gw_if_bridge and not gw_vif:
        b = bridges.get(gw_if_bridge) or {}
        mgmt_vid = int(b.get("pvid") or 1)
    ports = []
    for e in raw.get("ethernet") or []:
        n = e.get("name")
        bp = bports.get(n)
        mon, poe, i = (raw.get("monitor") or {}).get(n, {}), (raw.get("poe") or {}).get(n, {}), ifs.get(n, {})
        pvid = int(bp["pvid"]) if bp and str(bp.get("pvid", "")).isdigit() else None
        tagged = sorted(v["id"] for v in vlans.values() if bp and n in v["tagged"] and v["bridge"] == bp.get("bridge"))
        untagged = sorted(v["id"] for v in vlans.values() if bp and n in v["untagged"] and v["bridge"] == bp.get("bridge"))
        running = (i.get("running") == "true") or mon.get("status") == "link-ok"
        rate = mon.get("rate") or ""
        ports.append({"name": n, "id": e.get(".id"), "comment": e.get("comment") or i.get("comment") or "", "sfp": n.startswith(("sfp", "qsfp")),
                      "disabled": e.get("disabled") == "true", "running": running, "rate": rate, "speed": speed_class(rate) if running else "",
                      "poe": e.get("poe-out") if e.get("poe-out") else None, "poe_status": poe.get("poe-out-status") or "",
                      "poe_watts": poe.get("poe-out-power") or "", "bridge": bp.get("bridge") if bp else None, "bport_id": bp.get(".id") if bp else None,
                      "pvid": pvid, "tagged": tagged, "untagged": untagged, "frame_types": (bp or {}).get("frame-types") or "",
                      "hw_offload": (bp or {}).get("hw-offload") == "true" if bp and "hw-offload" in bp else None,
                      "devices": devs.get(n, [])[:20], "neighbor": neigh.get(n, ""), "uplink": n == mgmt_port or n == gw_if,
                      "mgmt": n == mgmt_port})
    ports.sort(key=lambda p: port_sort_key(p["name"]))
    vl = []
    for v in sorted(vlans.values(), key=lambda v: v["id"]):
        vl.append({"id": v["id"], "name": v["name"], "bridge": v["bridge"], "subnet": v.get("subnet", ""), "l3": v.get("l3", ""),
                   "cpu": v["bridge"] in v["tagged"], "rows": v["rows"], "ports": sum(1 for p in ports if v["id"] in p["tagged"] or v["id"] == p["pvid"]),
                   "mgmt": v["id"] == mgmt_vid and bool(gw_if)})
    return {"ports": ports, "vlans": vl,
            "bridges": [{"name": b.get("name"), "id": b.get(".id"), "filtering": b.get("vlan-filtering") == "true", "pvid": int(b.get("pvid") or 1),
                         "comment": b.get("comment") or ""} for b in raw.get("bridges") or []],
            "mgmt": {"interface": gw_if, "port": mgmt_port, "vid": mgmt_vid},
            "switch_chip": bool(raw.get("switch_vlans"))}


class Ports:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.pending = {}   # device id -> {"until", "by", "changes"}
        self.lock = threading.Lock()
        self.busy = set()

    def _pending(self, d, r=None):
        p = self.pending.get(d["id"])
        if p and p["until"] < time.time() - 30:
            self.pending.pop(d["id"], None)
            self.db.event(d["id"], d["org_id"], "port change undone", "not kept in time - the router undid the port / VLAN changes")
            p = None
        if not p and r is not None and quiet(lambda: r.undo_armed(UNDO_NAME), False):
            p = self.pending[d["id"]] = {"until": time.time() + 60, "by": "", "changes": ["changes made before TikManager restarted"]}
        return p

    def view(self, d) -> dict:
        r = self.client_for(d)
        try:
            data = build(r.port_data())
        except RouterError as e:
            raise PortsError(f"Couldn't read the ports: {e}") from None
        p = self._pending(d, r)
        data["pending"] = p and {"by": p["by"], "changes": p["changes"], "seconds": max(0, int(p["until"] - time.time()))}
        data["test_minutes"] = TEST_MINUTES
        return data

    # --- planning ---------------------------------------------------------------------------------------------
    def plan(self, view: dict, b: dict):
        """A change -> (steps [(kind, args, CLI text)], warnings). Raises PortsError for things not allowed."""
        op = b.get("op")
        ports = {p["name"]: p for p in view["ports"]}
        vl = {v["id"]: v for v in view["vlans"]}
        bridges = {x["name"]: x for x in view["bridges"]}
        mg = view["mgmt"]
        steps, warn = [], []
        if view.get("switch_chip"):
            raise PortsError("This router's VLANs are set up on the switch chip (older CRS1xx/2xx style) - TikManager only changes bridge VLAN filtering. "
                             "Change them in Winbox.")
        if op == "ports":
            sel = [ports[n] for n in b.get("ports") or [] if n in ports]
            if not sel:
                raise PortsError("Pick at least one port.")
            if any(p["mgmt"] for p in sel) and b.get("disabled"):
                raise PortsError(f"{mg['port']} is how TikManager reaches this router - it can't be disabled from here.")
            for p in sel:
                eth = {}
                if "comment" in b and len(sel) == 1 and (b["comment"] or "") != p["comment"]:
                    eth["comment"] = str(b["comment"])[:100]
                if "disabled" in b and bool(b["disabled"]) != p["disabled"]:
                    eth["disabled"] = "true" if b["disabled"] else "false"
                if b.get("poe") in ("auto-on", "off") and p["poe"] and b["poe"] != p["poe"]:
                    eth["poe-out"] = b["poe"]
                if eth:
                    steps.append(("eth", (p["id"], eth), f"/interface ethernet set [find name={q(p['name'])}] " + " ".join(f"{k}={q(v)}" for k, v in eth.items())))
            vlan_change = b.get("pvid") not in (None, "") or b.get("tagged_mode") not in (None, "", "keep")
            if vlan_change:
                not_bridged = [p["name"] for p in sel if not p["bridge"]]
                if not_bridged:
                    raise PortsError(f"{', '.join(not_bridged)} {'is' if len(not_bridged) == 1 else 'are'} not in a bridge (routed) - VLANs are set on bridge ports.")
                br = {p["bridge"] for p in sel}
                if len(br) > 1:
                    raise PortsError("The ports are in different bridges - change one bridge at a time.")
                bridge = br.pop()
                new_pvid = int(b["pvid"]) if b.get("pvid") not in (None, "") else None
                if new_pvid is not None and not 1 <= new_pvid <= 4094:
                    raise PortsError("A VLAN ID is 1-4094.")
                mode = b.get("tagged_mode") or "keep"
                want = sorted({int(x) for x in b.get("tagged") or [] if str(x).isdigit()})
                bridge_vlans = sorted(v["id"] for v in view["vlans"] if v["bridge"] == bridge and v["rows"])
                # desired membership per VLAN for the selected ports
                rows = {}   # vid -> {"tagged": set, "untagged": set}
                for v in view["vlans"]:
                    if v["bridge"] == bridge and v["rows"]:
                        rows[v["id"]] = {"tagged": {x for x in self._row_members(view, v, "tagged")}, "untagged": set(self._row_members(view, v, "untagged"))}
                for p in sel:
                    pvid = new_pvid if new_pvid is not None else p["pvid"]
                    tagged = set(p["tagged"]) if mode == "keep" else set(bridge_vlans) if mode == "all" else set() if mode == "none" else set(want)
                    tagged.discard(pvid)
                    if p["mgmt"] and mg["vid"]:   # TikManager's way in keeps its VLAN, the way it arrives now
                        untagged_mgmt = mg["interface"] in bridges   # the bridge itself carries the management address: untagged
                        if (untagged_mgmt and pvid != mg["vid"]) or (not untagged_mgmt and mg["vid"] not in tagged | {pvid}):
                            raise PortsError(f"{p['name']} is how TikManager reaches this router (VLAN {mg['vid']}, {'untagged' if untagged_mgmt else 'tagged'}) - "
                                             f"that has to stay, or the router would cut itself off. Other VLANs can be added or removed.")
                    for vid in tagged:
                        rows.setdefault(vid, {"tagged": set(), "untagged": set()})
                    for vid, m in rows.items():
                        (m["tagged"].add if vid in tagged else m["tagged"].discard)(p["name"])
                        if vid != pvid:
                            m["untagged"].discard(p["name"])   # one native VLAN only (the pvid; RouterOS adds it dynamically)
                    bp = {}
                    if pvid != p["pvid"]:
                        bp["pvid"] = str(pvid)
                    ft = "admit-only-untagged-and-priority-tagged" if not tagged else "admit-all"
                    if ft != p["frame_types"]:
                        bp["frame-types"] = ft
                    if bp:
                        steps.append(("bport", (p["bport_id"], bp), f"/interface bridge port set [find interface={q(p['name'])}] " + " ".join(f"{k}={q(v)}" for k, v in bp.items())))
                steps = self._vlan_steps(view, bridge, rows) + steps   # memberships first, then pvid / frame types
                if not bridges.get(bridge, {}).get("filtering"):
                    warn.append(f"VLAN filtering is off on {bridge}: these settings are saved but not enforced until it's turned on.")
                if new_pvid is not None and new_pvid not in vl:
                    warn.append(f"VLAN {new_pvid} isn't defined anywhere else yet.")
        elif op == "vlan_add":
            vid, name, bridge = str(b.get("id") or ""), str(b.get("name") or "").strip()[:60], b.get("bridge")
            if not VID.match(vid) or not 1 <= int(vid) <= 4094:
                raise PortsError("A VLAN ID is 1-4094.")
            if bridge not in bridges:
                raise PortsError("Pick the bridge.")
            if int(vid) in vl and vl[int(vid)]["rows"]:
                raise PortsError(f"VLAN {vid} already exists.")
            props = {"bridge": bridge, "vlan-ids": vid, "tagged": bridge if b.get("cpu") else "", "comment": name}
            steps.append(("vadd", (props,), f"/interface bridge vlan add " + " ".join(f"{k}={q(v)}" for k, v in props.items())))
        elif op in ("vlan_rename", "vlan_delete"):
            vid = int(b.get("id") or 0)
            v = vl.get(vid)
            if not v or not v["rows"]:
                raise PortsError("That VLAN isn't in the bridge VLAN table.")
            raw_rows = [r for r in view["_raw_vlans"] if r.get(".id") in v["rows"]]
            if op == "vlan_rename":
                name = str(b.get("name") or "").strip()[:60]
                for r in raw_rows:
                    if len(vids(r.get("vlan-ids"))) == 1:
                        steps.append(("vset", (r[".id"], {"comment": name}), f"/interface bridge vlan set [find vlan-ids={q(vid)}] comment={q(name)}"))
                if not steps:
                    raise PortsError("This VLAN shares a row with others (e.g. vlan-ids=30,40) - rename it in Winbox.")
            else:
                if v["mgmt"]:
                    raise PortsError(f"VLAN {vid} is how TikManager reaches this router - it can't be deleted from here.")
                users = [p["name"] for p in view["ports"] if p["pvid"] == vid]
                if users:
                    raise PortsError(f"{', '.join(users)} use VLAN {vid} as their native VLAN - change them first.")
                for r in raw_rows:
                    ids = vids(r.get("vlan-ids"))
                    if len(ids) == 1:
                        steps.append(("vdel", (r[".id"],), f"/interface bridge vlan remove [find vlan-ids={q(vid)}]"))
                    else:
                        rest = ",".join(str(x) for x in ids if x != vid)
                        steps.append(("vset", (r[".id"], {"vlan-ids": rest}), f"/interface bridge vlan set [find vlan-ids={q(r.get('vlan-ids'))}] vlan-ids={q(rest)}"))
                if v.get("l3"):
                    warn.append(f"The router's own interface {v['l3']} on VLAN {vid} stays - remove it in Winbox if it's no longer needed.")
        elif op == "filtering":
            br = bridges.get(b.get("bridge"))
            if not br:
                raise PortsError("Pick the bridge.")
            on = bool(b.get("on"))
            if on == br["filtering"]:
                raise PortsError(f"VLAN filtering is already {'on' if on else 'off'} on {br['name']}.")
            if on and mg["interface"]:
                mport = next((p for p in view["ports"] if p["name"] == mg["port"]), None)
                mv = vl.get(mg["vid"]) if mg["vid"] else None
                gw_is_vif = mg["interface"] not in bridges and mg["interface"] != mg["port"]
                if gw_is_vif and mport and mport["bridge"] == br["name"]:
                    if not mv or not mv["cpu"] or mg["vid"] not in mport["tagged"] + ([mport["pvid"]] if mport["pvid"] else []):
                        raise PortsError(f"TikManager reaches this router over VLAN {mg['vid']} via {mg['port']}: before turning filtering on, VLAN {mg['vid']} "
                                         f"needs the bridge itself tagged and {mg['port']} as a member - otherwise the router would cut itself off.")
                if mg["interface"] == br["name"] and mport and mport["pvid"] != br["pvid"]:
                    raise PortsError(f"TikManager reaches this router untagged through {mg['port']}: its native VLAN ({mport['pvid']}) must match the bridge's ({br['pvid']}) first.")
            steps.append(("bridge", (br["id"], {"vlan-filtering": "true" if on else "false"}), f"/interface bridge set [find name={q(br['name'])}] vlan-filtering={'yes' if on else 'no'}"))
            if on:
                warn.append("On some models (for example those with a QCA switch chip, like the hAP ac²) VLAN filtering turns hardware offloading off - "
                            "traffic then goes through the CPU. Check the HW offload column afterwards.")
        else:
            raise PortsError("Unknown change.")
        if not steps:
            raise PortsError("Nothing to change - that's already how it is.")
        return steps, warn

    @staticmethod
    def _row_members(view, v, kind):
        out = set()
        for r in view["_raw_vlans"]:
            if r.get(".id") in v["rows"]:
                out |= set(members(r.get(kind)))
        return out

    def _vlan_steps(self, view, bridge, rows):
        """Desired {vid: {tagged, untagged}} -> steps that make the bridge VLAN table match (splitting shared rows)."""
        steps = []
        raw = [r for r in view["_raw_vlans"] if r.get("bridge") == bridge and r.get("dynamic") != "true"]
        covered = set()
        for r in raw:
            ids = vids(r.get("vlan-ids"))
            covered |= set(ids)
            groups = {}
            for vid in ids:
                m = rows.get(vid, {"tagged": set(members(r.get("tagged"))), "untagged": set(members(r.get("untagged")))})
                groups.setdefault((tuple(sorted(m["tagged"])), tuple(sorted(m["untagged"]))), []).append(vid)
            cur = (tuple(sorted(members(r.get("tagged")))), tuple(sorted(members(r.get("untagged")))))
            first = groups.pop(cur, None)
            if first is None:   # every VLAN of this row changed: keep the row for the first group
                key = next(iter(groups))
                first = groups.pop(key)
                props = {"tagged": ",".join(key[0]), "untagged": ",".join(key[1])}
                if len(first) != len(ids):
                    props["vlan-ids"] = ",".join(str(x) for x in first)
                steps.append(("vset", (r[".id"], props), f"/interface bridge vlan set [find bridge={q(bridge)} vlan-ids={q(r.get('vlan-ids'))}] "
                                                         + " ".join(f"{k}={q(v)}" for k, v in props.items())))
            elif groups:   # some VLANs of a shared row changed: the row keeps the unchanged ones
                steps.append(("vset", (r[".id"], {"vlan-ids": ",".join(str(x) for x in first)}),
                              f"/interface bridge vlan set [find bridge={q(bridge)} vlan-ids={q(r.get('vlan-ids'))}] vlan-ids={q(','.join(str(x) for x in first))}"))
            for (t, u), group in groups.items():
                props = {"bridge": bridge, "vlan-ids": ",".join(str(x) for x in group), "tagged": ",".join(t), "untagged": ",".join(u), "comment": r.get("comment") or ""}
                steps.append(("vadd", (props,), "/interface bridge vlan add " + " ".join(f"{k}={q(v)}" for k, v in props.items())))
        for vid, m in sorted(rows.items()):
            if vid not in covered and (m["tagged"] or m["untagged"]):
                props = {"bridge": bridge, "vlan-ids": str(vid), "tagged": ",".join(sorted(m["tagged"])), "untagged": ",".join(sorted(m["untagged"]))}
                steps.append(("vadd", (props,), "/interface bridge vlan add " + " ".join(f"{k}={q(v)}" for k, v in props.items())))
        return steps

    # --- the undo script: everything VLAN-related back exactly as it was ------------------------------------------
    @staticmethod
    def undo_script(raw: dict, touched_eth) -> str:
        lines = []
        for b in raw.get("bridges") or []:
            lines.append(f"/interface bridge set [find name={q(b.get('name'))}] vlan-filtering={'yes' if b.get('vlan-filtering') == 'true' else 'no'} pvid={b.get('pvid') or 1}")
        lines.append(":do { /interface bridge vlan remove [find dynamic=no] } on-error={}")
        for v in raw.get("vlans") or []:
            if v.get("dynamic") == "true":
                continue
            lines.append(f":do {{ /interface bridge vlan add bridge={q(v.get('bridge'))} vlan-ids={q(v.get('vlan-ids'))} tagged={q(v.get('tagged') or '')} "
                         f"untagged={q(v.get('untagged') or '')} comment={q(v.get('comment') or '')} disabled={'yes' if v.get('disabled') == 'true' else 'no'} }} on-error={{}}")
        for p in raw.get("ports") or []:
            if p.get("dynamic") == "true" or not p.get("interface"):
                continue
            extra = f" ingress-filtering={'yes' if p.get('ingress-filtering') == 'true' else 'no'}" if p.get("ingress-filtering") else ""
            lines.append(f":do {{ /interface bridge port set [find interface={q(p['interface'])}] pvid={p.get('pvid') or 1} frame-types={p.get('frame-types') or 'admit-all'}{extra} }} on-error={{}}")
        for e in raw.get("ethernet") or []:
            if e.get("name") in touched_eth:
                poe = f" poe-out={e['poe-out']}" if e.get("poe-out") else ""
                lines.append(f":do {{ /interface ethernet set [find name={q(e['name'])}] comment={q(e.get('comment') or '')} disabled={'yes' if e.get('disabled') == 'true' else 'no'}{poe} }} on-error={{}}")
        return "\n".join(lines) + f"\n/system scheduler remove [find name={q(UNDO_NAME)}]\n"

    # --- applying -------------------------------------------------------------------------------------------------
    def review(self, d, b) -> dict:
        r = self.client_for(d)
        raw = r.port_data()
        view = build(raw)
        view["_raw_vlans"] = raw.get("vlans") or []
        steps, warn = self.plan(view, b)
        return {"commands": [s[2] for s in steps], "warnings": warn}

    def apply(self, d, user, b) -> dict:
        with self.lock:
            if d["id"] in self.busy:
                raise PortsError("Another port change on this router is still running.")
            self.busy.add(d["id"])
        try:
            r = self.client_for(d)
            try:
                raw = r.port_data()
            except RouterError as e:
                raise PortsError(f"Couldn't read the ports: {e}") from None
            view = build(raw)
            view["_raw_vlans"] = raw.get("vlans") or []
            steps, warn = self.plan(view, b)
            p = self._pending(d, r)
            first = not p
            if first:
                last = self.db.one("SELECT MAX(ts) AS t FROM backups WHERE device_id=?", (d["id"],))
                if not last or not last["t"] or time.time() - last["t"] > BACKUP_FRESH:
                    res = self.backups.run(d["id"], "pre-vlan", user)
                    if not res.get("ok"):
                        raise PortsError(f"Couldn't back up the router first, so nothing was changed: {res.get('detail')}")
                touched = {e.get("name") for e in raw.get("ethernet") or []}
                try:   # armed before the change: if the change cuts TikManager off, the router still undoes it
                    r.undo_arm(UNDO_NAME, self.undo_script(raw, touched), f"{TEST_MINUTES}m")
                except RouterError as e:
                    raise PortsError(f"Couldn't set up the automatic undo, so nothing was changed: {e}") from None
                p = {"until": 0, "by": user, "changes": []}
            else:
                quiet(lambda: r.undo_arm(UNDO_NAME, None, f"{TEST_MINUTES}m"))   # restart the clock; the script keeps the first state
            done = []
            try:
                for kind, args, text in steps:
                    if kind == "eth":
                        r.eth_set(*args)
                    elif kind == "bport":
                        r.br_set("/port", *args)
                    elif kind == "vset":
                        r.br_set("/vlan", *args)
                    elif kind == "vadd":
                        r.br_add("/vlan", *args)
                    elif kind == "vdel":
                        r.br_remove("/vlan", *args)
                    elif kind == "bridge":
                        r.br_set("", *args)
                    done.append(text)
            except RouterError as e:
                p["until"] = time.time() + TEST_MINUTES * 60
                p["changes"] += done
                self.pending[d["id"]] = p
                raise PortsError(f"The router refused a step ({e}). {len(done)} of {len(steps)} steps were made - press Undo to put everything back.") from None
            p["until"] = time.time() + TEST_MINUTES * 60
            p["changes"] += done
            self.pending[d["id"]] = p
            reachable = bool(quiet(r.alive, False)) if hasattr(r, "alive") else True
            self.db.event(d["id"], d["org_id"], "ports changed", f"{len(done)} step(s) by {user} - testing, undone in {TEST_MINUTES} min unless kept")
            self.db.audit(user, "ports / VLANs changed (testing)", d["name"], detail="\n".join(done)[:1900], org_id=d.get("org_id"))
            return {"ok": True, "done": done, "warnings": warn, "reachable": reachable,
                    "pending": {"by": p["by"], "changes": p["changes"], "seconds": TEST_MINUTES * 60}}
        finally:
            self.busy.discard(d["id"])

    def keep(self, d, user):
        p = self._pending(d, self.client_for(d))
        if not p:
            raise PortsError("There's nothing waiting to be kept (the test may have run out and been undone).")
        try:
            self.client_for(d).undo_cancel(UNDO_NAME)
        except RouterError as e:
            raise PortsError(f"Couldn't reach the router to keep the changes - it will undo them by itself: {e}") from None
        self.pending.pop(d["id"], None)
        self.db.event(d["id"], d["org_id"], "ports changed", f"kept by {user}")
        self.db.audit(user, "ports / VLANs changes kept", d["name"], org_id=d.get("org_id"))
        return p["changes"]

    def undo(self, d, user):
        p = self._pending(d, self.client_for(d))
        if not p:
            raise PortsError("There's nothing to undo.")
        try:
            self.client_for(d).undo_run(UNDO_NAME)
        except RouterError as e:
            raise PortsError(f"Couldn't reach the router - it will undo the changes by itself when the timer runs out: {e}") from None
        self.pending.pop(d["id"], None)
        self.db.event(d["id"], d["org_id"], "port change undone", f"by {user}")
        self.db.audit(user, "ports / VLANs changes undone", d["name"], org_id=d.get("org_id"))
        return p["changes"]
