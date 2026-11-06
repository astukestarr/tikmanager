"""IPAM (IP Address Management) - a separated workspace at /ipam, in the spirit of phpIPAM but native to TikManager.

A subnet can belong to a managed client (org) and/or a free-form section (folder for shared / infrastructure space).
The difference from a hand-kept IPAM: subnets and live IP usage are DISCOVERED from the managed MikroTiks (each router's
own addresses, ARP, DHCP leases and discovered neighbours) and overlaid on manual records - sync never clobbers a
manual edit. Everything is read-only for any technician; changes need the 'ipam' permission.

This is beta.1: sections, subnets, addresses, live sync and search. VLANs/VRFs, IPAM devices/locations and CSV import
land in later betas (their tables already exist).
"""
import csv
import io
import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

try:
    from devkind import kind as _devkind   # classify a managed MikroTik: router / switch / ap
except Exception:   # pragma: no cover - devkind is always present in the app
    def _devkind(model, board, override=None):
        return "router"


class IpamError(ValueError):
    pass


def net(s):
    """Parse a CIDR (host bits allowed), e.g. 10.20.0.0/24. Raises IpamError."""
    try:
        return ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError:
        raise IpamError(f"{s!r} isn't a valid subnet (example: 192.168.10.0/24).") from None


def _ip(s):
    try:
        return ipaddress.ip_address(str(s).strip().split("/")[0])
    except ValueError:
        raise IpamError(f"{s!r} isn't a valid IP address.") from None


def _expand_vlan_ids(spec):
    """RouterOS bridge 'vlan-ids' -> a list of ints. Accepts "30", "30,40", "100-104" (ranges capped to stay sane)."""
    out = []
    for tok in str(spec or "").replace(" ", "").split(","):
        if not tok:
            continue
        if "-" in tok:
            try:
                lo, hi = (int(x) for x in tok.split("-", 1))
            except ValueError:
                continue
            if 0 < lo <= hi and hi - lo <= 256:   # ignore absurd ranges (a trunk "2-4094") - those aren't an inventory
                out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(tok))
            except ValueError:
                pass
    return out


def _ipint(ip):
    """Integer form of an IPv4 address for ordered range queries; None for IPv6 (stored as TEXT order)."""
    try:
        a = ipaddress.ip_address(str(ip).split("/")[0])
        return int(a) if a.version == 4 else None
    except ValueError:
        return None


# Fields on an address row a sync is allowed to write (live-derived); everything else is the user's.
_LIVE_FIELDS = ("mac", "hostname", "last_seen")


class Ipam:
    def __init__(self, db, client_for, settings=None):
        self.db, self.client_for, self.settings = db, client_for, settings
        self.syncing = set()
        self.lock = threading.Lock()
        self.sync_all_state = {"running": False, "total": 0, "done": 0, "summary": {}, "at": 0}
        try:
            self.reserved = ipaddress.ip_network(getattr(settings, "wg_network", None) or "10.77.0.0/16", strict=False)
        except ValueError:
            self.reserved = ipaddress.ip_network("10.77.0.0/16")
        self._seed_types()

    _BUILTIN_TYPES = [("Router", "router"), ("Switch", "switch"), ("Access point", "ap"), ("Gateway", "gateway"),
                      ("Firewall", "firewall"), ("Server", "server"), ("Storage", "storage"), ("UPS", "ups"),
                      ("Camera", "camera"), ("Printer", "printer"), ("Phone", "phone"), ("Other", "other")]

    def _seed_types(self):
        """Create the built-in device types once (idempotent)."""
        try:
            for name, icon in self._BUILTIN_TYPES:
                if not self.db.one("SELECT 1 FROM ipam_device_types WHERE name=?", (name,)):
                    self.db.run("INSERT INTO ipam_device_types (name, icon, builtin) VALUES (?,?,1)", (name, icon))
        except Exception:
            pass   # a brand-new database may not have the table yet on the very first boot; next call seeds it

    # --- small helpers ------------------------------------------------------------------------------------------
    def _now(self):
        return time.time()

    def _org_name(self, org_id):
        if not org_id:
            return None
        r = self.db.one("SELECT name FROM orgs WHERE id=?", (org_id,))
        return r["name"] if r else None

    def _reserved(self, netobj):
        """Does this network sit inside TikManager's management tunnel (10.77/16)?"""
        try:
            return netobj.version == self.reserved.version and (netobj.subnet_of(self.reserved) or netobj.overlaps(self.reserved))
        except (TypeError, ValueError):
            return False

    def _counts(self, subnet):
        """(usable_hosts, {status: n}, used_total) for a subnet row, from its stored addresses."""
        try:
            netobj = ipaddress.ip_network(subnet["cidr"], strict=False)
        except ValueError:
            return 0, {}, 0
        if netobj.version == 4:
            usable = netobj.num_addresses - (2 if netobj.prefixlen <= 30 else 0)
        else:
            usable = min(netobj.num_addresses, 1 << 24)   # IPv6 is effectively unbounded; cap for a percentage
        rows = self.db.q("SELECT status, COUNT(*) AS n FROM ipam_addresses WHERE subnet_id=? GROUP BY status", (subnet["id"],))
        by = {r["status"]: r["n"] for r in rows}
        used = sum(by.values())
        return usable, by, used

    def _subnet_public(self, s, with_counts=True):
        out = dict(s)
        out["org"] = self._org_name(s.get("org_id"))
        out["reserved"] = self._reserved(net(s["cidr"])) if s.get("cidr") else False
        if s.get("vlan_id"):
            v = self.db.one("SELECT number, name FROM ipam_vlans WHERE id=?", (s["vlan_id"],))
            out["vlan"] = (f"VLAN {v['number']}" + (f" · {v['name']}" if v["name"] else "")) if v else None
        if s.get("vrf_id"):
            v = self.db.one("SELECT name FROM ipam_vrfs WHERE id=?", (s["vrf_id"],))
            out["vrf"] = v["name"] if v else None
        if with_counts:
            usable, by, used = self._counts(s)
            out["usable"] = usable
            out["counts"] = by
            out["used_total"] = used
            out["usage"] = round(100 * used / usable) if usable else 0
        if s.get("dhcp_size"):   # how full the DHCP pool is (separate from overall subnet usage)
            out["dhcp_usage"] = round(100 * (s.get("dhcp_used") or 0) / s["dhcp_size"])
        if s.get("device_id"):   # the router this subnet was discovered on / is gatewayed by - so you can jump to it
            dev = self.db.one("SELECT name FROM devices WHERE id=?", (s["device_id"],))
            out["router"] = dev["name"] if dev else None
        return out

    # --- sections -----------------------------------------------------------------------------------------------
    def tree(self, org=None):
        """Sections (nested) and, separately, the client pivot - what the left sidebar needs.
        A client user (org set) sees only their own organization's subnets - no free-form sections, no other clients."""
        if org:
            subs = [self._subnet_public(s) for s in
                    self.db.q("SELECT * FROM ipam_subnets WHERE org_id=? ORDER BY family, cidr", (int(org),))]
            clients = self.db.q("SELECT o.id, o.name, COUNT(s.id) AS subnets FROM orgs o "
                                "JOIN ipam_subnets s ON s.org_id=o.id WHERE o.id=? GROUP BY o.id", (int(org),))
            return {"sections": [], "subnets": subs, "clients": clients, "scoped": True}
        secs = self.db.q("SELECT * FROM ipam_sections ORDER BY pos, name")
        subs = [self._subnet_public(s) for s in self.db.q("SELECT * FROM ipam_subnets ORDER BY family, cidr")]
        clients = self.db.q("SELECT o.id, o.name, COUNT(s.id) AS subnets FROM orgs o "
                            "JOIN ipam_subnets s ON s.org_id=o.id GROUP BY o.id ORDER BY o.name")
        return {"sections": secs, "subnets": subs, "clients": clients}

    def syncable_orgs(self):
        """Clients the Sync picker offers: any with an adopted MikroTik OR a UniFi / UISP site (so a UniFi-only client
        with no MikroTik can still be synced - that's the whole point of the UniFi overlay)."""
        return self.db.q("""SELECT o.id, o.name,
            (SELECT COUNT(*) FROM devices d WHERE d.org_id=o.id AND d.state='adopted') AS routers,
            (SELECT COUNT(*) FROM devices d WHERE d.org_id=o.id AND d.state='adopted' AND d.online=1) AS online,
            (SELECT COUNT(*) FROM net_sites s WHERE s.org_id=o.id) AS unifi_sites
            FROM orgs o WHERE o.active=1 AND (
              EXISTS (SELECT 1 FROM devices d WHERE d.org_id=o.id AND d.state='adopted')
              OR EXISTS (SELECT 1 FROM net_sites s WHERE s.org_id=o.id))
            ORDER BY o.name""")

    def _usable(self, netobj):
        """Assignable host count for a network: IPv4 minus network+broadcast for /30 and larger; IPv6 capped so a
        huge prefix doesn't dominate utilization math."""
        if netobj.version == 4:
            return netobj.num_addresses - (2 if netobj.prefixlen <= 30 else 0)
        return min(netobj.num_addresses, 1 << 24)

    def dashboard(self, org=None):
        """A rich operations overview for someone running many clients' networks: headline counts, overall IP capacity
        and utilization, a health breakdown of every subnet, the address-status and discovery mix, a per-client
        rollup, device inventory by type, subnet-size spread, actionable alerts (near-full / over-threshold / stale /
        offline), the busiest subnets, what changed recently, and the hosts currently offline. Scoped to one client
        when `org` is set. One pass over subnets drives most of it; a few small GROUP BY queries do the rest."""
        oid = int(org) if org else None
        sw, sa = (" WHERE org_id=?", (oid,)) if oid else ("", ())
        now = self._now()
        week_ago, stale_cut = now - 7 * 86400, now - 30 * 86400
        org_names = {r["id"]: r["name"] for r in self.db.q("SELECT id, name FROM orgs")}

        def one(sql, args=()):
            r = self.db.one(sql, args)
            return (r["n"] if r and r["n"] is not None else 0)

        counts = {
            "subnets": one(f"SELECT COUNT(*) AS n FROM ipam_subnets{sw}", sa),
            "addresses": one("SELECT COUNT(*) AS n FROM ipam_addresses a JOIN ipam_subnets s ON s.id=a.subnet_id"
                             + (" WHERE s.org_id=?" if oid else ""), sa),
            "vlans": one(f"SELECT COUNT(*) AS n FROM ipam_vlans{sw}", sa),
            "vrfs": one(f"SELECT COUNT(*) AS n FROM ipam_vrfs{sw}", sa),
            "devices": one(f"SELECT COUNT(*) AS n FROM ipam_devices{sw}", sa),
            "racks": one(f"SELECT COUNT(*) AS n FROM ipam_racks{sw}", sa),
            "locations": one(f"SELECT COUNT(*) AS n FROM ipam_locations{sw}", sa),
            "sections": 0 if oid else one("SELECT COUNT(*) AS n FROM ipam_sections"),
            "clients": 1 if oid else one("SELECT COUNT(DISTINCT org_id) AS n FROM ipam_subnets WHERE org_id IS NOT NULL"),
        }

        # ---- single pass over every subnet (with its used count) drives capacity, health, per-client, sizes, alerts
        main = self.db.q(
            "SELECT s.id, s.cidr, s.name, s.org_id, s.source, s.threshold, s.mark_full, s.family, s.first_seen, "
            "s.dhcp_size, s.dhcp_used, s.dhcp_pools, COALESCE(s.last_seen, s.first_seen, s.created_at) AS seen, "
            "(SELECT COUNT(*) FROM ipam_addresses a WHERE a.subnet_id=s.id) AS used "
            "FROM ipam_subnets s" + (" WHERE s.org_id=?" if oid else ""), sa)
        total_used = total_usable = v6 = new_subnets = full_n = 0
        bands = {"free": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "full": 0}
        per_client, prefix, srcmix = {}, {}, {"discovered": 0, "manual": 0}
        util, over_threshold, dhcp_pools = [], [], []
        for r in main:
            srcmix[r["source"]] = srcmix.get(r["source"], 0) + 1
            if r["first_seen"] and r["first_seen"] >= week_ago:
                new_subnets += 1
            try:
                netobj = ipaddress.ip_network(r["cidr"], strict=False)
            except ValueError:
                continue
            prefix[netobj.prefixlen] = prefix.get(netobj.prefixlen, 0) + 1
            if netobj.version == 6:
                v6 += 1
            usable = self._usable(netobj)
            if usable <= 0:
                continue
            used, full = r["used"], bool(r["mark_full"])
            pct = 100 if full else round(100 * used / usable)
            total_used += used
            total_usable += usable
            if full or pct >= 100:
                bands["full"] += 1; full_n += 1
            elif pct >= 90:
                bands["critical"] += 1
            elif pct >= 75:
                bands["high"] += 1
            elif pct >= 50:
                bands["moderate"] += 1
            elif pct > 0:
                bands["low"] += 1
            else:
                bands["free"] += 1
            thr = r["threshold"] if r["threshold"] is not None else 80
            row = {"id": r["id"], "cidr": r["cidr"], "name": r["name"], "org": org_names.get(r["org_id"]),
                   "used": used, "usable": usable, "usage": pct}
            util.append(row)
            if not full and pct >= thr:
                over_threshold.append({**row, "threshold": thr})
            if r["dhcp_size"]:   # a DHCP pool filling up - tracked separately from overall subnet usage
                du, dpct = r["dhcp_used"] or 0, min(100, round(100 * (r["dhcp_used"] or 0) / r["dhcp_size"]))
                if dpct >= 85:
                    dhcp_pools.append({"id": r["id"], "cidr": r["cidr"], "name": r["name"], "org": org_names.get(r["org_id"]),
                                       "used": du, "size": r["dhcp_size"], "usage": dpct, "pools": r["dhcp_pools"]})
            pc = per_client.setdefault(r["org_id"], {"org_id": r["org_id"], "name": org_names.get(r["org_id"]) or "Unassigned",
                                                     "subnets": 0, "used": 0, "usable": 0, "devices": 0})
            pc["subnets"] += 1; pc["used"] += used; pc["usable"] += usable
        util.sort(key=lambda x: (x["usage"], x["used"]), reverse=True)
        over_threshold.sort(key=lambda x: x["usage"], reverse=True)

        # devices per client (fold into the rollup; a client with devices but no subnets still shows)
        for r in self.db.q("SELECT org_id, COUNT(*) AS n FROM ipam_devices" + (" WHERE org_id=?" if oid else "") + " GROUP BY org_id", sa):
            pc = per_client.get(r["org_id"])
            if pc:
                pc["devices"] = r["n"]
            elif r["org_id"]:
                per_client[r["org_id"]] = {"org_id": r["org_id"], "name": org_names.get(r["org_id"]) or "Unassigned",
                                           "subnets": 0, "used": 0, "usable": 0, "devices": r["n"]}
        clients = []
        for pc in per_client.values():
            pc["usage"] = round(100 * pc["used"] / pc["usable"]) if pc["usable"] else 0
            clients.append(pc)
        clients.sort(key=lambda x: (x["usable"], x["used"], x["subnets"]), reverse=True)

        # address status + source mix, device types - small GROUP BYs
        amix = (" JOIN ipam_subnets s ON s.id=a.subnet_id" + (" WHERE s.org_id=?" if oid else ""))
        status_mix = {r["status"]: r["n"] for r in self.db.q(f"SELECT a.status, COUNT(*) AS n FROM ipam_addresses a{amix} GROUP BY a.status", sa)}
        addr_src = {r["source"]: r["n"] for r in self.db.q(f"SELECT a.source, COUNT(*) AS n FROM ipam_addresses a{amix} GROUP BY a.source", sa)}
        dev_types = [{"name": r["name"] or "Unspecified", "n": r["n"]} for r in self.db.q(
            "SELECT t.name AS name, COUNT(*) AS n FROM ipam_devices d LEFT JOIN ipam_device_types t ON t.id=d.type_id"
            + (" WHERE d.org_id=?" if oid else "") + " GROUP BY t.name ORDER BY n DESC", sa)]

        # recently seen / discovered subnets, and hosts currently offline
        rq = ("SELECT id, cidr, name, org_id, source, COALESCE(last_seen, first_seen, created_at) AS seen "
              "FROM ipam_subnets" + (" WHERE org_id=?" if oid else "") + " ORDER BY seen DESC LIMIT 8")
        recent = [{"id": r["id"], "cidr": r["cidr"], "name": r["name"], "org": org_names.get(r["org_id"]),
                   "source": r["source"], "seen": r["seen"]} for r in self.db.q(rq, sa)]
        oq = ("SELECT a.ip, a.hostname, a.last_seen, a.subnet_id, s.cidr, s.org_id FROM ipam_addresses a "
              "JOIN ipam_subnets s ON s.id=a.subnet_id WHERE a.status='offline'" + (" AND s.org_id=?" if oid else "")
              + " ORDER BY a.last_seen DESC LIMIT 10")
        offline = [{"ip": r["ip"], "hostname": r["hostname"], "subnet": r["cidr"], "subnet_id": r["subnet_id"],
                    "org": org_names.get(r["org_id"]), "last_seen": r["last_seen"]} for r in self.db.q(oq, sa)]

        offline_n = one("SELECT COUNT(*) AS n FROM ipam_addresses a JOIN ipam_subnets s ON s.id=a.subnet_id "
                        "WHERE a.status='offline'" + (" AND s.org_id=?" if oid else ""), sa)
        stale_n = one("SELECT COUNT(*) AS n FROM ipam_subnets WHERE source='discovered' AND COALESCE(last_seen,0) < ?"
                      + (" AND org_id=?" if oid else ""), ((stale_cut, oid) if oid else (stale_cut,)))
        new_addr = one("SELECT COUNT(*) AS n FROM ipam_addresses a JOIN ipam_subnets s ON s.id=a.subnet_id "
                       "WHERE a.created_at >= ?" + (" AND s.org_id=?" if oid else ""), ((week_ago, oid) if oid else (week_ago,)))

        capacity = {"used": total_used, "usable": total_usable, "free": max(0, total_usable - total_used),
                    "usage": round(100 * total_used / total_usable) if total_usable else 0, "v6_subnets": v6}
        # passive daily utilization snapshot (idempotent per day+scope; org_id 0 = the whole estate) -> the trend chart
        today = time.strftime("%Y-%m-%d", time.localtime(now))
        try:
            self.db.run("INSERT OR REPLACE INTO ipam_stats_daily (day, org_id, used, usable, subnets, addresses) "
                        "VALUES (?,?,?,?,?,?)", (today, oid or 0, total_used, total_usable, counts["subnets"], counts["addresses"]))
        except Exception:
            pass   # a dashboard read must never fail because the snapshot write did
        trend = [{"day": t["day"], "used": t["used"], "usage": round(100 * t["used"] / t["usable"]) if t["usable"] else 0}
                 for t in self.db.q("SELECT day, used, usable FROM ipam_stats_daily WHERE org_id=? ORDER BY day DESC LIMIT 30",
                                    (oid or 0,))][::-1]
        dhcp_pools.sort(key=lambda x: x["usage"], reverse=True)
        alerts = {"over_threshold": over_threshold[:8], "over_threshold_n": len(over_threshold),
                  "full": full_n, "offline": offline_n, "stale": stale_n,
                  "dhcp_pools": dhcp_pools[:8], "dhcp_pools_n": len(dhcp_pools),
                  "dhcp_full": sum(1 for p in dhcp_pools if p["usage"] >= 100)}
        change = {"new_subnets": new_subnets, "new_addresses": new_addr}
        return {"counts": counts, "capacity": capacity, "health": bands, "status_mix": status_mix,
                "source_mix": {"subnets": srcmix, "addresses": addr_src}, "clients": clients[:12], "client_total": len(clients),
                "devices_by_type": dev_types, "prefix_sizes": sorted(({"pfx": k, "n": v} for k, v in prefix.items()), key=lambda x: x["pfx"]),
                "alerts": alerts, "change": change, "trend": trend, "utilization": util[:8], "recent": recent,
                "offline": offline, "scoped": bool(oid)}

    def section_save(self, b, user):
        name = str(b.get("name") or "").strip()[:80]
        if not name:
            raise IpamError("Give the section a name.")
        parent = int(b["parent_id"]) if b.get("parent_id") else None
        now = self._now()
        if b.get("id"):
            self.db.run("UPDATE ipam_sections SET name=?, description=?, parent_id=?, updated_at=? WHERE id=?",
                        (name, str(b.get("description") or "")[:500], parent, now, int(b["id"])))
            return int(b["id"])
        return self.db.run("INSERT INTO ipam_sections (parent_id, name, description, pos, created_by, created_at) "
                           "VALUES (?,?,?,?,?,?)", (parent, name, str(b.get("description") or "")[:500],
                                                    int(b.get("pos") or 0), user, now))

    def section_delete(self, sid):
        self.db.run("DELETE FROM ipam_sections WHERE id=?", (int(sid),))

    # --- subnets ------------------------------------------------------------------------------------------------
    def subnets(self, org_id=None, section_id=None, q=None):
        where, args = [], []
        if org_id:
            where.append("org_id=?"); args.append(int(org_id))
        if section_id:
            where.append("section_id=?"); args.append(int(section_id))
        if q:
            where.append("(cidr LIKE ? OR name LIKE ?)"); args += [f"%{q}%", f"%{q}%"]
        sql = "SELECT * FROM ipam_subnets" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY family, cidr"
        return [self._subnet_public(s) for s in self.db.q(sql, args)]

    def subnet(self, sid):
        s = self.db.one("SELECT * FROM ipam_subnets WHERE id=?", (int(sid),))
        if not s:
            raise IpamError("That subnet doesn't exist.")
        out = self._subnet_public(s)
        out["addresses"] = self.db.q("SELECT * FROM ipam_addresses WHERE subnet_id=? ORDER BY ip_sort, ip", (int(sid),))
        return out

    def subnet_save(self, b, user):
        netobj = net(b.get("cidr"))
        cidr = str(netobj)
        org_id = int(b["org_id"]) if b.get("org_id") else None
        section_id = int(b["section_id"]) if b.get("section_id") else None
        if not org_id and not section_id:
            raise IpamError("A subnet needs a client or a section (or both).")
        if self._reserved(netobj) and not b.get("allow_reserved"):
            raise IpamError(f"{cidr} is inside TikManager's management range ({self.reserved}); it's reserved.")
        now = self._now()
        sid = b.get("id")
        # overlap guard within the same client (ignore an exact match to self; a true supernet/subnet nest is allowed)
        for other in self.db.q("SELECT id, cidr FROM ipam_subnets WHERE COALESCE(org_id,0)=? AND id!=?",
                               (org_id or 0, int(sid or 0))):
            o = net(other["cidr"])
            if o.version == netobj.version and o != netobj and o.overlaps(netobj) and not (o.subnet_of(netobj) or netobj.subnet_of(o)):
                raise IpamError(f"{cidr} overlaps {other['cidr']} already recorded for this client.")
        fields = dict(cidr=cidr, family=netobj.version, org_id=org_id, section_id=section_id,
                      vlan_id=int(b["vlan_id"]) if b.get("vlan_id") else None, vrf_id=int(b["vrf_id"]) if b.get("vrf_id") else None,
                      name=str(b.get("name") or "")[:120], gateway=str(b.get("gateway") or "")[:64] or None,
                      is_pool=1 if b.get("is_pool") else 0, mark_full=1 if b.get("mark_full") else 0,
                      notes=str(b.get("notes") or "")[:2000], updated_at=now)
        if sid:
            cols = ", ".join(f"{k}=?" for k in fields)
            self.db.run(f"UPDATE ipam_subnets SET {cols} WHERE id=?", (*fields.values(), int(sid)))
            return int(sid)
        return self.db.run("INSERT INTO ipam_subnets (cidr, family, org_id, section_id, vlan_id, vrf_id, name, gateway, is_pool, "
                           "mark_full, notes, source, first_seen, created_by, created_at, updated_at) "
                           "VALUES (?,?,?,?,?,?,?,?,?,?,?,'manual',?,?,?,?)",
                           (cidr, netobj.version, org_id, section_id, fields["vlan_id"], fields["vrf_id"], fields["name"],
                            fields["gateway"], fields["is_pool"], fields["mark_full"], fields["notes"], now, user, now, now))

    def subnet_delete(self, sid):
        self.db.run("DELETE FROM ipam_subnets WHERE id=?", (int(sid),))

    def subnet_split(self, sid, newprefix, user):
        s = self.db.one("SELECT * FROM ipam_subnets WHERE id=?", (int(sid),))
        if not s:
            raise IpamError("That subnet doesn't exist.")
        parent = net(s["cidr"])
        newprefix = int(newprefix)
        if newprefix <= parent.prefixlen or newprefix > (32 if parent.version == 4 else 128):
            raise IpamError(f"Pick a prefix longer than /{parent.prefixlen}.")
        kids = list(parent.subnets(new_prefix=newprefix))
        if len(kids) > 1024:
            raise IpamError("That split would make too many subnets at once.")
        now, made = self._now(), 0
        for k in kids:
            if self.db.one("SELECT id FROM ipam_subnets WHERE cidr=? AND COALESCE(org_id,0)=? AND COALESCE(section_id,0)=?",
                           (str(k), s["org_id"] or 0, s["section_id"] or 0)):
                continue
            self.db.run("INSERT INTO ipam_subnets (cidr, family, parent_id, org_id, section_id, source, created_by, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,'manual',?,?,?)", (str(k), k.version, int(sid), s["org_id"], s["section_id"], user, now, now))
            made += 1
        return {"created": made, "children": len(kids)}

    def first_free(self, sid):
        s = self.db.one("SELECT * FROM ipam_subnets WHERE id=?", (int(sid),))
        if not s:
            raise IpamError("That subnet doesn't exist.")
        netobj = net(s["cidr"])
        taken = {r["ip"] for r in self.db.q("SELECT ip FROM ipam_addresses WHERE subnet_id=?", (int(sid),))}
        hosts = netobj.hosts() if netobj.prefixlen <= 30 else netobj
        gw = s.get("gateway")
        for h in hosts:
            ip = str(h)
            if ip == gw or ip in taken:
                continue
            return {"ip": ip}
        return {"ip": None}

    # --- addresses ----------------------------------------------------------------------------------------------
    def address_save(self, b, user):
        sid = int(b.get("subnet_id") or 0)
        s = self.db.one("SELECT * FROM ipam_subnets WHERE id=?", (sid,))
        if not s:
            raise IpamError("Pick a subnet first.")
        ip = str(_ip(b.get("ip")))
        if ipaddress.ip_address(ip) not in net(s["cidr"]):
            raise IpamError(f"{ip} isn't inside {s['cidr']}.")
        status = str(b.get("status") or "used")
        if status not in ("used", "reserved", "dhcp", "offline", "gateway"):
            status = "used"
        now = self._now()
        row = dict(status=status, hostname=str(b.get("hostname") or "")[:120] or None, mac=str(b.get("mac") or "")[:32] or None,
                   owner=str(b.get("owner") or "")[:120] or None, dns_name=str(b.get("dns_name") or "")[:255] or None,
                   ptr=str(b.get("ptr") or "")[:255] or None, notes=str(b.get("notes") or "")[:2000] or None, updated_at=now)
        existing = self.db.one("SELECT id FROM ipam_addresses WHERE subnet_id=? AND ip=?", (sid, ip))
        if b.get("id") or existing:
            aid = int(b.get("id") or existing["id"])
            cols = ", ".join(f"{k}=?" for k in row) + ", source='manual'"
            self.db.run(f"UPDATE ipam_addresses SET {cols} WHERE id=?", (*row.values(), aid))
            return aid
        return self.db.run("INSERT INTO ipam_addresses (subnet_id, ip, ip_sort, status, hostname, mac, owner, dns_name, ptr, "
                           "notes, source, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,'manual',?,?,?)",
                           (sid, ip, _ipint(ip), status, row["hostname"], row["mac"], row["owner"], row["dns_name"], row["ptr"],
                            row["notes"], user, now, now))

    def address_delete(self, aid):
        self.db.run("DELETE FROM ipam_addresses WHERE id=?", (int(aid),))

    # --- search -------------------------------------------------------------------------------------------------
    def search(self, q, org=None):
        q = (q or "").strip()
        if not q:
            return {"subnets": [], "addresses": []}
        like = f"%{q}%"
        og = " AND org_id=?" if org else ""
        oa = (int(org),) if org else ()
        subs = [self._subnet_public(s, with_counts=False) for s in
                self.db.q(f"SELECT * FROM ipam_subnets WHERE (cidr LIKE ? OR name LIKE ?){og} ORDER BY cidr LIMIT 50", (like, like, *oa))]
        og2 = " AND s.org_id=?" if org else ""
        addrs = self.db.q("SELECT a.*, s.cidr AS subnet_cidr FROM ipam_addresses a JOIN ipam_subnets s ON s.id=a.subnet_id "
                          f"WHERE (a.ip LIKE ? OR a.hostname LIKE ? OR a.mac LIKE ? OR a.owner LIKE ?){og2} ORDER BY a.ip_sort LIMIT 100",
                          (like, like, like, like, *oa))
        return {"subnets": subs, "addresses": addrs}

    # --- VLANs & VRFs -------------------------------------------------------------------------------------------
    def vlans(self, org_id=None):
        where = "WHERE v.org_id=?" if org_id else ""
        args = (int(org_id),) if org_id else ()
        return self.db.q(f"SELECT v.*, o.name AS org, (SELECT COUNT(*) FROM ipam_subnets s WHERE s.vlan_id=v.id) AS subnets "
                        f"FROM ipam_vlans v LEFT JOIN orgs o ON o.id=v.org_id {where} ORDER BY v.l2domain, v.number", args)

    def vlan_save(self, b, user):
        number = int(b.get("number") or 0)
        if not (1 <= number <= 4094):
            raise IpamError("A VLAN number is 1-4094.")
        l2 = str(b.get("l2domain") or "default").strip()[:60] or "default"
        org_id = int(b["org_id"]) if b.get("org_id") else None
        if self.db.one("SELECT id FROM ipam_vlans WHERE number=? AND l2domain=? AND id!=?", (number, l2, int(b.get("id") or 0))):
            raise IpamError(f"VLAN {number} already exists in L2 domain '{l2}'.")
        now = self._now()
        if b.get("id"):
            self.db.run("UPDATE ipam_vlans SET number=?, name=?, l2domain=?, org_id=?, notes=?, updated_at=? WHERE id=?",
                        (number, str(b.get("name") or "")[:80], l2, org_id, str(b.get("notes") or "")[:500], now, int(b["id"])))
            return int(b["id"])
        return self.db.run("INSERT INTO ipam_vlans (number, name, l2domain, org_id, notes, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                           (number, str(b.get("name") or "")[:80], l2, org_id, str(b.get("notes") or "")[:500], user, now))

    def vlan_delete(self, vid):
        self.db.run("DELETE FROM ipam_vlans WHERE id=?", (int(vid),))

    def vrfs(self, org_id=None):
        where = "WHERE v.org_id=?" if org_id else ""
        args = (int(org_id),) if org_id else ()
        return self.db.q(f"SELECT v.*, o.name AS org, (SELECT COUNT(*) FROM ipam_subnets s WHERE s.vrf_id=v.id) AS subnets "
                        f"FROM ipam_vrfs v LEFT JOIN orgs o ON o.id=v.org_id {where} ORDER BY v.name", args)

    def vrf_save(self, b, user):
        name = str(b.get("name") or "").strip()[:80]
        rd = str(b.get("rd") or "").strip()[:40]
        if not name or not rd:
            raise IpamError("A VRF needs a name and a route distinguisher (RD, e.g. 65000:1).")
        org_id = int(b["org_id"]) if b.get("org_id") else None
        now = self._now()
        if b.get("id"):
            self.db.run("UPDATE ipam_vrfs SET rd=?, name=?, description=?, org_id=?, updated_at=? WHERE id=?",
                        (rd, name, str(b.get("description") or "")[:300], org_id, now, int(b["id"])))
            return int(b["id"])
        return self.db.run("INSERT INTO ipam_vrfs (rd, name, description, org_id, created_by, created_at) VALUES (?,?,?,?,?,?)",
                           (rd, name, str(b.get("description") or "")[:300], org_id, user, now))

    def vrf_delete(self, vid):
        self.db.run("DELETE FROM ipam_vrfs WHERE id=?", (int(vid),))

    # --- device types, locations & devices ----------------------------------------------------------------------
    def device_types(self):
        return self.db.q("SELECT * FROM ipam_device_types ORDER BY builtin DESC, name")

    def _type_id(self, name):
        r = self.db.one("SELECT id FROM ipam_device_types WHERE name=?", (name,))
        return r["id"] if r else None

    def locations(self, org_id=None):
        where = "WHERE l.org_id=?" if org_id else ""
        args = (int(org_id),) if org_id else ()
        return self.db.q(f"SELECT l.*, o.name AS org, (SELECT COUNT(*) FROM ipam_devices d WHERE d.location_id=l.id) AS devices "
                        f"FROM ipam_locations l LEFT JOIN orgs o ON o.id=l.org_id {where} ORDER BY l.name", args)

    def location_save(self, b, user):
        name = str(b.get("name") or "").strip()[:120]
        if not name:
            raise IpamError("Give the location a name.")
        org_id = int(b["org_id"]) if b.get("org_id") else None
        now = self._now()
        if b.get("id"):
            self.db.run("UPDATE ipam_locations SET name=?, address=?, org_id=?, notes=?, updated_at=? WHERE id=?",
                        (name, str(b.get("address") or "")[:300] or None, org_id, str(b.get("notes") or "")[:1000] or None, now, int(b["id"])))
            return int(b["id"])
        return self.db.run("INSERT INTO ipam_locations (name, address, org_id, notes, created_by, created_at) VALUES (?,?,?,?,?,?)",
                           (name, str(b.get("address") or "")[:300] or None, org_id, str(b.get("notes") or "")[:1000] or None, user, now))

    def location_delete(self, lid):
        self.db.run("DELETE FROM ipam_locations WHERE id=?", (int(lid),))

    def devices_list(self, org_id=None):
        where = "WHERE d.org_id=?" if org_id else ""
        args = (int(org_id),) if org_id else ()
        return self.db.q(f"""SELECT d.*, t.name AS type, t.icon AS type_icon, l.name AS location, o.name AS org,
            md.name AS linked_device, md.online AS linked_online
            FROM ipam_devices d LEFT JOIN ipam_device_types t ON t.id=d.type_id
            LEFT JOIN ipam_locations l ON l.id=d.location_id LEFT JOIN orgs o ON o.id=d.org_id
            LEFT JOIN devices md ON md.id=d.device_id {where} ORDER BY t.name, d.name""", args)

    def device_save(self, b, user):
        name = str(b.get("name") or "").strip()[:120]
        if not name:
            raise IpamError("Give the device a name.")
        now = self._now()
        fields = dict(name=name, type_id=int(b["type_id"]) if b.get("type_id") else None,
                      location_id=int(b["location_id"]) if b.get("location_id") else None,
                      org_id=int(b["org_id"]) if b.get("org_id") else None,
                      management_ip=str(b.get("management_ip") or "")[:64] or None,
                      description=str(b.get("description") or "")[:300] or None,
                      notes=str(b.get("notes") or "")[:2000] or None, updated_at=now)
        if b.get("id"):
            cols = ", ".join(f"{k}=?" for k in fields)
            self.db.run(f"UPDATE ipam_devices SET {cols} WHERE id=?", (*fields.values(), int(b["id"])))
            did = int(b["id"])
        else:
            did = self.db.run("INSERT INTO ipam_devices (name, type_id, location_id, org_id, management_ip, description, notes, "
                              "created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (name, fields["type_id"], fields["location_id"], fields["org_id"], fields["management_ip"],
                               fields["description"], fields["notes"], user, now, now))
        # link the address at this management IP to the device, so "make this IP a device" connects the two
        if fields["management_ip"]:
            self.db.run("UPDATE ipam_addresses SET ipam_device_id=? WHERE ipam_device_id IS NULL AND ip=? AND subnet_id IN "
                        "(SELECT id FROM ipam_subnets WHERE COALESCE(org_id,0)=?)", (did, fields["management_ip"], fields["org_id"] or 0))
        return did

    def device_delete(self, did):
        self.db.run("DELETE FROM ipam_devices WHERE id=?", (int(did),))

    # --- racks --------------------------------------------------------------------------------------------------
    def racks(self, org_id=None):
        where = "WHERE r.org_id=?" if org_id else ""
        args = (int(org_id),) if org_id else ()
        return self.db.q(f"""SELECT r.*, l.name AS location, o.name AS org,
            (SELECT COUNT(*) FROM ipam_devices d WHERE d.rack_id=r.id AND d.rack_u IS NOT NULL) AS devices,
            (SELECT COALESCE(SUM(d.rack_height), 0) FROM ipam_devices d WHERE d.rack_id=r.id AND d.rack_u IS NOT NULL) AS used_u
            FROM ipam_racks r LEFT JOIN ipam_locations l ON l.id=r.location_id LEFT JOIN orgs o ON o.id=r.org_id
            {where} ORDER BY r.name""", args)

    def rack(self, rid):
        r = self.db.one("""SELECT r.*, l.name AS location, o.name AS org FROM ipam_racks r
            LEFT JOIN ipam_locations l ON l.id=r.location_id LEFT JOIN orgs o ON o.id=r.org_id WHERE r.id=?""", (int(rid),))
        if not r:
            raise IpamError("That rack doesn't exist.")
        out = dict(r)
        out["units"] = self.db.q("""SELECT d.id, d.name, d.rack_u, d.rack_height, d.management_ip, t.name AS type
            FROM ipam_devices d LEFT JOIN ipam_device_types t ON t.id=d.type_id
            WHERE d.rack_id=? AND d.rack_u IS NOT NULL ORDER BY d.rack_u DESC""", (int(rid),))
        return out

    def rack_save(self, b, user):
        name = str(b.get("name") or "").strip()[:120]
        if not name:
            raise IpamError("Give the rack a name.")
        size_u = int(b.get("size_u") or 42)
        if not 1 <= size_u <= 100:
            raise IpamError("Rack size must be 1-100 U.")
        now = self._now()
        fields = dict(name=name, size_u=size_u,
                      org_id=int(b["org_id"]) if b.get("org_id") else None,
                      location_id=int(b["location_id"]) if b.get("location_id") else None,
                      description=str(b.get("description") or "")[:300] or None,
                      notes=str(b.get("notes") or "")[:2000] or None, updated_at=now)
        if b.get("id"):
            top = self.db.one("SELECT MAX(rack_u + rack_height - 1) AS t FROM ipam_devices WHERE rack_id=? AND rack_u IS NOT NULL", (int(b["id"]),))
            if top and top["t"] and top["t"] > size_u:
                raise IpamError(f"A device reaches U{top['t']} - move it before shrinking the rack to {size_u}U.")
            cols = ", ".join(f"{k}=?" for k in fields)
            self.db.run(f"UPDATE ipam_racks SET {cols} WHERE id=?", (*fields.values(), int(b["id"])))
            return int(b["id"])
        return self.db.run("INSERT INTO ipam_racks (name, size_u, org_id, location_id, description, notes, created_by, created_at, updated_at) "
                           "VALUES (?,?,?,?,?,?,?,?,?)",
                           (name, size_u, fields["org_id"], fields["location_id"], fields["description"], fields["notes"], user, now, now))

    def rack_delete(self, rid):
        self.db.run("UPDATE ipam_devices SET rack_id=NULL, rack_u=NULL WHERE rack_id=?", (int(rid),))
        self.db.run("DELETE FROM ipam_racks WHERE id=?", (int(rid),))

    def rack_place(self, b):
        rid, did = int(b.get("rack_id") or 0), int(b.get("device_id") or 0)
        r = self.db.one("SELECT * FROM ipam_racks WHERE id=?", (rid,))
        d = self.db.one("SELECT * FROM ipam_devices WHERE id=?", (did,))
        if not r or not d:
            raise IpamError("Rack or device not found.")
        u, h = int(b.get("rack_u") or 0), int(b.get("rack_height") or 1)
        if not 1 <= h <= r["size_u"]:
            raise IpamError(f"Height must be 1-{r['size_u']} U.")
        if u < 1 or u + h - 1 > r["size_u"]:
            raise IpamError(f"A {h}U device at U{u} won't fit in a {r['size_u']}U rack.")
        for o in self.db.q("SELECT name, rack_u, rack_height FROM ipam_devices WHERE rack_id=? AND rack_u IS NOT NULL AND id!=?", (rid, did)):
            lo, hi = o["rack_u"], o["rack_u"] + o["rack_height"] - 1
            if not (u + h - 1 < lo or u > hi):
                raise IpamError(f"U{u}-U{u + h - 1} overlaps {o['name']} (U{lo}-U{hi}).")
        self.db.run("UPDATE ipam_devices SET rack_id=?, rack_u=?, rack_height=?, updated_at=? WHERE id=?", (rid, u, h, self._now(), did))
        return {"id": did}

    def rack_unplace(self, did):
        self.db.run("UPDATE ipam_devices SET rack_id=NULL, rack_u=NULL WHERE id=?", (int(did),))

    def rack_placeable(self, rid):
        """Devices that can be put into this rack: not already placed, and (if the rack belongs to a client) that
        client's own devices or unassigned ones."""
        r = self.db.one("SELECT * FROM ipam_racks WHERE id=?", (int(rid),))
        if not r:
            raise IpamError("That rack doesn't exist.")
        og = "AND (d.org_id=? OR d.org_id IS NULL)" if r["org_id"] else ""
        oa = (r["org_id"],) if r["org_id"] else ()
        return self.db.q(f"""SELECT d.id, d.name, t.name AS type FROM ipam_devices d
            LEFT JOIN ipam_device_types t ON t.id=d.type_id WHERE d.rack_u IS NULL {og} ORDER BY d.name""", oa)

    # --- CSV import / export (phpIPAM-compatible headers, native fallback; import is ADD-ONLY, never overwrites) ---
    _ADDR_HEADERS = {"ip address": "ip", "ip": "ip", "address": "ip", "state": "status", "status": "status",
                     "description": "notes", "note": "notes", "notes": "notes", "hostname": "hostname", "host": "hostname",
                     "dns": "dns_name", "dns name": "dns_name", "dns_name": "dns_name", "mac": "mac", "mac address": "mac",
                     "owner": "owner", "ptr": "ptr", "subnet": "subnet", "cidr": "subnet", "network": "subnet"}
    _SUBNET_HEADERS = {"subnet": "cidr", "cidr": "cidr", "network": "cidr", "mask": "mask", "description": "name",
                       "name": "name", "gateway": "gateway", "client": "client", "organization": "client",
                       "note": "notes", "notes": "notes"}
    _STATE_MAP = {"used": "used", "offline": "offline", "reserved": "reserved", "dhcp": "dhcp", "gateway": "gateway",
                  "online": "used", "active": "used", "2": "used", "1": "offline", "0": "offline", "": "used"}

    @staticmethod
    def _rows(text):
        rows = [r for r in csv.reader(io.StringIO(text or "")) if any((c or "").strip() for c in r)]
        if not rows:
            raise IpamError("The file has no rows.")
        return [h.strip().lower() for h in rows[0]], rows[1:]

    def export_csv(self, kind="subnets", org_id=None):
        out = io.StringIO()
        w = csv.writer(out)
        if kind == "addresses":
            w.writerow(["IP address", "Subnet", "State", "Hostname", "MAC", "Owner", "DNS name", "PTR", "Source", "Note"])
            sql = ("SELECT a.ip, a.status, a.hostname, a.mac, a.owner, a.dns_name, a.ptr, a.source, a.notes, s.cidr "
                   "FROM ipam_addresses a JOIN ipam_subnets s ON s.id=a.subnet_id")
            sql += (" WHERE COALESCE(s.org_id,0)=?" if org_id else "") + " ORDER BY s.cidr, a.ip_sort"
            for r in self.db.q(sql, (int(org_id),) if org_id else ()):
                w.writerow([r["ip"], r["cidr"], r["status"], r["hostname"] or "", r["mac"] or "", r["owner"] or "",
                            r["dns_name"] or "", r["ptr"] or "", r["source"], r["notes"] or ""])
        else:
            w.writerow(["Subnet", "Description", "Client", "Section", "VLAN", "VRF", "Gateway", "Source", "Note"])
            secname = {s["id"]: s["name"] for s in self.db.q("SELECT id, name FROM ipam_sections")}
            for s in self.subnets(org_id):
                w.writerow([s["cidr"], s.get("name") or "", s.get("org") or "", secname.get(s.get("section_id")) or "",
                            s.get("vlan") or "", s.get("vrf") or "", s.get("gateway") or "", s.get("source"), s.get("notes") or ""])
        return out.getvalue()

    def import_csv(self, kind, text, org_id=None, commit=False, user="import"):
        org_id = int(org_id) if org_id else None
        header, body = self._rows(text)
        hmap = self._ADDR_HEADERS if kind == "addresses" else self._SUBNET_HEADERS
        cols = {hmap[h]: i for i, h in enumerate(header) if h in hmap}

        def cell(r, k):
            i = cols.get(k)
            return r[i].strip() if (i is not None and i < len(r)) else ""
        now = self._now()
        add, skip, errors, seen = [], 0, [], set()
        if kind == "addresses":
            if "ip" not in cols:
                raise IpamError("No IP column found (expected a header like 'IP address').")
            subs = []
            for r in self.db.q("SELECT id, cidr FROM ipam_subnets" + (" WHERE COALESCE(org_id,0)=?" if org_id else ""),
                               (org_id,) if org_id else ()):
                try:
                    subs.append((r["id"], ipaddress.ip_network(r["cidr"], strict=False)))
                except ValueError:
                    pass
            for n, r in enumerate(body, 2):
                raw = cell(r, "ip")
                if not raw:
                    continue
                try:
                    addr = ipaddress.ip_address(raw.split("/")[0])
                except ValueError:
                    errors.append(f"row {n}: '{raw}' isn't a valid IP"); continue
                match = None
                for sid, no in subs:
                    if addr in no and (match is None or no.prefixlen > match[1].prefixlen):
                        match = (sid, no)
                if not match:
                    errors.append(f"row {n}: {raw} is not inside a known subnet"); continue
                ip = str(addr)
                if (match[0], ip) in seen or self.db.one("SELECT 1 FROM ipam_addresses WHERE subnet_id=? AND ip=?", (match[0], ip)):
                    skip += 1; continue
                seen.add((match[0], ip))
                add.append(dict(subnet_id=match[0], ip=ip, status=self._STATE_MAP.get(cell(r, "status").lower(), "used"),
                                hostname=cell(r, "hostname") or None, mac=cell(r, "mac") or None, owner=cell(r, "owner") or None,
                                dns_name=cell(r, "dns_name") or None, ptr=cell(r, "ptr") or None, notes=cell(r, "notes") or None))
            if commit:
                for a in add:
                    self.db.run("INSERT OR IGNORE INTO ipam_addresses (subnet_id, ip, ip_sort, status, hostname, mac, owner, "
                                "dns_name, ptr, notes, source, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,'manual',?,?,?)",
                                (a["subnet_id"], a["ip"], _ipint(a["ip"]), a["status"], a["hostname"], a["mac"], a["owner"],
                                 a["dns_name"], a["ptr"], a["notes"], user, now, now))
            return {"kind": kind, "to_add": len(add), "skipped_existing": skip, "errors": errors[:50],
                    "committed": bool(commit), "sample": [a["ip"] for a in add[:12]]}
        # subnets
        if "cidr" not in cols:
            raise IpamError("No subnet column found (expected a header like 'Subnet' or 'CIDR').")
        by_name = {o["name"].lower(): o["id"] for o in self.db.q("SELECT id, name FROM orgs")}
        for n, r in enumerate(body, 2):
            raw, mask = cell(r, "cidr"), cell(r, "mask")
            if not raw:
                continue
            if "/" not in raw and mask:
                raw = raw + "/" + mask
            try:
                no = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                errors.append(f"row {n}: '{raw}' isn't a valid subnet"); continue
            oid = org_id if org_id is not None else (by_name.get(cell(r, "client").lower()) if cell(r, "client") else None)
            if self._reserved(no):
                errors.append(f"row {n}: {no} is in the reserved range"); continue
            if (str(no), oid or 0) in seen or self.db.one("SELECT 1 FROM ipam_subnets WHERE cidr=? AND COALESCE(org_id,0)=?", (str(no), oid or 0)):
                skip += 1; continue
            seen.add((str(no), oid or 0))
            add.append(dict(cidr=str(no), family=no.version, org_id=oid, name=cell(r, "name") or None,
                            gateway=cell(r, "gateway") or None, notes=cell(r, "notes") or None))
        if commit:
            for a in add:
                self.db.run("INSERT INTO ipam_subnets (cidr, family, org_id, name, gateway, notes, source, first_seen, "
                            "created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,'manual',?,?,?,?)",
                            (a["cidr"], a["family"], a["org_id"], a["name"], a["gateway"], a["notes"], now, user, now, now))
        return {"kind": kind, "to_add": len(add), "skipped_existing": skip, "errors": errors[:50],
                "committed": bool(commit), "sample": [a["cidr"] for a in add[:12]]}

    def _vlan_for(self, org_id, number, name, now):
        """Find or create a VLAN by (number, l2domain='default') for auto-population from discovery. Returns its id."""
        if not number:
            return None
        row = self.db.one("SELECT id, name FROM ipam_vlans WHERE number=? AND l2domain='default'", (int(number),))
        if row:
            if name and not row["name"]:
                self.db.run("UPDATE ipam_vlans SET name=? WHERE id=?", (str(name)[:80], row["id"]))
            return row["id"]
        return self.db.run("INSERT INTO ipam_vlans (number, name, l2domain, org_id, created_by, created_at) VALUES (?,?,?,?,?,?)",
                           (int(number), str(name or "")[:80], "default", org_id, "sync", now))

    # --- live sync from the managed routers ---------------------------------------------------------------------
    def sync(self, org_id, user="sync"):
        org_id = int(org_id)
        with self.lock:
            if org_id in self.syncing:
                raise IpamError("A sync is already running for this client.")
            self.syncing.add(org_id)
        try:
            summary = {"routers": 0, "offline": 0, "subnets_added": 0, "subnets_seen": 0,
                       "addresses_added": 0, "addresses_updated": 0, "unifi": 0}
            now = self._now()
            devices = self.db.q("SELECT * FROM devices WHERE org_id=? AND state='adopted'", (org_id,))
            # 1) subnets from each router's cached networks (fast, DB-only) -> per-device {cidr: (id, netobj)}
            per_device = {}
            for d in devices:
                summary["routers"] += 1
                per_device[d["id"]] = (d, self._sync_subnets(org_id, d, now, summary))
            # 2) read each ONLINE router's live tables IN PARALLEL - the slow part (many RouterOS calls over the tunnel);
            #    done sequentially this timed out on big clients (30+ routers) past the reverse proxy's limit.
            online = [d for d in devices if d.get("online")]
            summary["offline"] = len(devices) - len(online)

            def read(d):
                try:
                    return d["id"], self.client_for(d).topology()
                except Exception:
                    return d["id"], None
            results = []
            if online:
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(read, online))
            # 3) overlay live usage (DB writes are serialized by the shared connection lock)
            for did, topo in results:
                if topo is None:
                    summary["offline"] += 1
                    continue
                d, sub_by_net = per_device[did]
                self._sync_addresses(d, topo, sub_by_net, now, summary)
                self._sync_dhcp(d, topo, sub_by_net, now)
            # 4) overlay the client's UniFi / UISP devices as addresses (and infer a /24 for a client with no MikroTik)
            self._sync_unifi(org_id, now, summary)
            # 5) auto-populate the infrastructure inventory (managed MikroTiks + UniFi APs/switches/gateways) and locations
            self._sync_devices(org_id, now, summary)
            return summary
        finally:
            with self.lock:
                self.syncing.discard(org_id)

    def sync_all(self, user="sync"):
        """Sync every client with routers, one after another, in the background (the estate can be many routers).
        Returns immediately; poll sync_status() for progress."""
        orgs = [o["id"] for o in self.syncable_orgs()]
        if not orgs:
            raise IpamError("No clients with routers to sync.")
        with self.lock:
            if self.sync_all_state.get("running"):
                raise IpamError("A full sync is already running.")
            self.sync_all_state = {"running": True, "total": len(orgs), "done": 0,
                                   "summary": {"clients": 0, "routers": 0, "subnets_added": 0, "addresses_added": 0, "unifi": 0},
                                   "at": self._now()}

        def run():
            agg = self.sync_all_state["summary"]
            for oid in orgs:
                try:
                    r = self.sync(oid, user)
                    agg["clients"] += 1
                    for k in ("routers", "subnets_added", "addresses_added", "unifi"):
                        agg[k] = agg.get(k, 0) + (r.get(k) or 0)
                except Exception:
                    pass   # one client's routers failing never stops the rest
                self.sync_all_state["done"] += 1
            self.sync_all_state["running"] = False
            self.sync_all_state["at"] = self._now()
        threading.Thread(target=run, daemon=True).start()
        return {"started": True, "clients": len(orgs)}

    def sync_status(self):
        st = self.sync_all_state
        return {"running": bool(st.get("running")), "total": st.get("total", 0), "done": st.get("done", 0), "summary": st.get("summary", {})}

    def _upsert_subnet(self, org_id, netobj, d, iface, gw, name, now, summary, out):
        """Create or refresh one discovered subnet; record it in `out` ({cidr: (id, netobj)}). Returns the subnet id."""
        cidr = str(netobj)
        if cidr in out:
            return out[cidr][0]
        row = self.db.one("SELECT * FROM ipam_subnets WHERE cidr=? AND COALESCE(org_id,0)=?", (cidr, org_id or 0))
        if not row:
            sid = self.db.run("INSERT INTO ipam_subnets (cidr, family, org_id, device_id, interface, name, gateway, source, "
                              "first_seen, last_seen, created_at, updated_at) VALUES (?,?,?,?,?,?,?,'discovered',?,?,?,?)",
                              (cidr, 4, org_id, d["id"], iface, name, gw, now, now, now, now))
            summary["subnets_added"] += 1
        else:
            sid = row["id"]
            summary["subnets_seen"] += 1
            if row["source"] == "discovered":
                keep_name = row["name"] if (row["name"] and row["name"] != (row["interface"] or "")) else (name or row["name"])
                self.db.run("UPDATE ipam_subnets SET device_id=?, interface=?, name=?, gateway=?, last_seen=?, updated_at=? WHERE id=?",
                            (d["id"], iface, keep_name, gw or row["gateway"], now, now, sid))
            else:   # manual subnet: only touch presence, never its CIDR/name/notes
                self.db.run("UPDATE ipam_subnets SET device_id=COALESCE(device_id,?), last_seen=? WHERE id=?", (d["id"], now, sid))
        out[cidr] = (sid, netobj)
        return sid

    def _sync_subnets(self, org_id, d, now, summary):
        """Upsert the device's cached LAN networks (devices.networks) as discovered subnets. Returns {cidr: (id, netobj)}."""
        out = {}
        try:
            nets = json.loads(d.get("networks") or "[]")
        except (ValueError, TypeError):
            nets = []
        for n in nets:
            cidr = n.get("network") or ""
            if "/" not in cidr:
                continue
            try:
                netobj = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if netobj.version != 4 or self._reserved(netobj):
                continue
            gw = (n.get("address") or "").split("/")[0] or None
            self._upsert_subnet(org_id, netobj, d, n.get("interface"), gw, n.get("name") or n.get("interface") or "", now, summary, out)
        return out

    def _sync_addresses(self, d, topo, sub_by_net, now, summary):
        """Overlay live usage (router addresses, DHCP leases, ARP, neighbours) onto the matching subnets' addresses."""
        # auto-tag the device's discovered subnets with their VLAN. A subnet's stored interface is the VLAN interface's
        # NAME (e.g. "vlan20-guest"), which matches /interface/vlan's "name" - not its "interface" (the parent bridge).
        vlan_by_iface = {v.get("name"): v for v in topo.get("vlans") or [] if v.get("name")}
        # Capture EVERY VLAN the router reports (/interface/vlan) as its own inventory entry, even one with no
        # discovered subnet yet - so the VLANs tab mirrors the routers, not just VLANs whose subnet interface matched.
        for v in topo.get("vlans") or []:
            if v.get("vlan-id"):
                self._vlan_for(d.get("org_id"), v.get("vlan-id"), v.get("name"), now)
        # L2 VLANs defined only via bridge VLAN filtering (no L3 vlan interface). vlan-ids can be a list/range "30,40,100-104".
        for bv in topo.get("bridge_vlans") or []:
            if str(bv.get("dynamic")).lower() == "true":
                continue   # dynamic entries mirror learned tags, not configured VLANs
            for vid in _expand_vlan_ids(bv.get("vlan-ids")):
                if vid > 1:   # skip the default VLAN 1
                    self._vlan_for(d.get("org_id"), vid, bv.get("comment"), now)
        if vlan_by_iface:
            for sub in self.db.q("SELECT id, interface FROM ipam_subnets WHERE device_id=?", (d["id"],)):
                v = vlan_by_iface.get(sub["interface"])
                if v and v.get("vlan-id"):
                    vid = self._vlan_for(d.get("org_id"), v.get("vlan-id"), v.get("name"), now)
                    if vid:
                        self.db.run("UPDATE ipam_subnets SET vlan_id=COALESCE(vlan_id, ?) WHERE id=?", (vid, sub["id"]))
        # discover any extra PRIVATE LAN subnets straight off the router's live interface addresses (fallback / additions)
        for a in topo.get("addresses") or []:
            addr = a.get("address") or ""
            if "/" not in addr:
                continue
            try:
                netobj = ipaddress.ip_network(addr, strict=False)
            except ValueError:
                continue
            if netobj.version != 4 or netobj.prefixlen >= 31 or not netobj.is_private or self._reserved(netobj):
                continue
            if str(netobj) not in sub_by_net:
                self._upsert_subnet(d["org_id"], netobj, d, a.get("interface"), addr.split("/")[0],
                                    a.get("comment") or a.get("interface") or "", now, summary, sub_by_net)

        best = {}   # ip -> (priority, status, mac, hostname)   higher priority wins

        def note(ip, prio, status, mac=None, host=None):
            ip = (ip or "").split("/")[0].split("%")[0]
            if not ip:
                return
            cur = best.get(ip)
            if not cur or prio > cur[0]:
                best[ip] = (prio, status, mac or (cur[2] if cur else None), host or (cur[3] if cur else None))

        for a in topo.get("addresses") or []:        # the router's own interface addresses -> gateway
            note(a.get("address"), 4, "gateway")
        for l in topo.get("leases") or []:            # active DHCP leases
            if str(l.get("status") or "").lower() in ("bound", "waiting", "offered") or l.get("address"):
                note(l.get("address"), 3, "dhcp", l.get("mac"), l.get("host"))
        for a in topo.get("arp") or []:               # ARP: a host that answered
            if str(a.get("complete")).lower() == "true" or a.get("mac-address"):
                note(a.get("address"), 2, "used", a.get("mac-address"))
        for nb in topo.get("neighbors") or []:        # discovered neighbour devices
            note(nb.get("address") or nb.get("address4"), 1, "used", nb.get("mac-address"), nb.get("identity"))

        for ip, (_prio, status, mac, host) in best.items():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or addr in self.reserved:
                continue
            match = next(((sid, no) for (sid, no) in sub_by_net.values() if addr in no), None)
            if not match:
                continue
            sid = match[0]
            row = self.db.one("SELECT * FROM ipam_addresses WHERE subnet_id=? AND ip=?", (sid, ip))
            if not row:
                self.db.run("INSERT INTO ipam_addresses (subnet_id, ip, ip_sort, status, hostname, mac, source, last_seen, created_at, updated_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (sid, ip, _ipint(ip), status, host, mac, self._src_of(status), now, now, now))
                summary["addresses_added"] += 1
            elif row["source"] != "manual":   # never overwrite a manual record's status/fields
                self.db.run("UPDATE ipam_addresses SET status=?, mac=COALESCE(?, mac), hostname=COALESCE(?, hostname), "
                            "source=?, last_seen=?, updated_at=? WHERE id=?",
                            (status, mac, host, self._src_of(status), now, now, row["id"]))
                summary["addresses_updated"] += 1
            else:
                self.db.run("UPDATE ipam_addresses SET mac=COALESCE(mac,?), last_seen=? WHERE id=?", (mac, now, row["id"]))

    @staticmethod
    def _src_of(status):
        return {"gateway": "address", "dhcp": "lease", "used": "arp"}.get(status, "arp")

    # --- DHCP pool utilisation: how full each DHCP pool is (not the whole subnet) --------------------------------
    @staticmethod
    def _parse_ranges(s):
        """A MikroTik pool 'ranges' string -> [(start_int, end_int)]. Handles 'a-b', single IPs and comma/semicolon lists."""
        out = []
        for part in str(s or "").replace(";", ",").split(","):
            part = part.strip()
            if not part:
                continue
            a, _, b = part.partition("-")
            b = b or a
            try:
                lo, hi = int(ipaddress.ip_address(a.strip())), int(ipaddress.ip_address(b.strip()))
            except ValueError:
                continue
            if lo <= hi:
                out.append((lo, hi))
        return out

    def _dhcp_pool_stats(self, topo):
        """Per enabled DHCP server: the effective pool capacity and how many addresses are in use. The capacity follows
        the pool's next-pool chain (so overflow pools count) and only ever starts from a pool a DHCP server actually uses,
        so orphan pools in /ip/pool are ignored. 'Used' is bound dynamic leases plus in-pool static reservations."""
        pools = {p.get("name"): p for p in topo.get("pools") or [] if p.get("name")}

        def chain(name, seen):
            if not name or name in seen or name not in pools:
                return [], []
            seen.add(name)
            p = pools[name]
            rngs, names = self._parse_ranges(p.get("ranges")), [name]
            nxt = (p.get("next-pool") or "").strip()
            if nxt and nxt.lower() not in ("none", "static-only", ""):
                r2, n2 = chain(nxt, seen)
                rngs += r2
                names += n2
            return rngs, names
        used_ips = set()
        for l in topo.get("leases") or []:
            if l.get("disabled"):
                continue
            if str(l.get("status") or "").lower() == "bound" or not l.get("dynamic"):   # active lease or a static reservation
                try:
                    used_ips.add(int(ipaddress.ip_address((l.get("address") or "").split("/")[0])))
                except ValueError:
                    pass
        out = {}
        for srv in topo.get("dhcp_servers") or []:
            if str(srv.get("disabled")).lower() == "true":
                continue
            ranges, names = chain((srv.get("address-pool") or "").strip(), set())
            if not ranges:
                continue
            size = sum(hi - lo + 1 for lo, hi in ranges)
            used = sum(1 for x in used_ips if any(lo <= x <= hi for lo, hi in ranges))
            out[srv.get("name") or ""] = {"ranges": ranges, "size": size, "used": min(used, size), "pools": names}
        return out

    def _sync_dhcp(self, d, topo, sub_by_net, now):
        """Store each of this router's subnets' DHCP pool capacity / usage (cleared first, so a removed server/pool clears)."""
        self.db.run("UPDATE ipam_subnets SET dhcp_size=NULL, dhcp_used=NULL, dhcp_pools=NULL WHERE device_id=?", (d["id"],))
        per_subnet = {}   # subnet_id -> {size, used, pools}  (a subnet may host more than one DHCP server)
        for srv in self._dhcp_pool_stats(topo).values():
            first = srv["ranges"][0][0]
            match = next(((sid, no) for (sid, no) in sub_by_net.values() if ipaddress.ip_address(first) in no), None)
            if not match:
                continue
            agg = per_subnet.setdefault(match[0], {"size": 0, "used": 0, "pools": []})
            agg["size"] += srv["size"]
            agg["used"] += srv["used"]
            agg["pools"] += srv["pools"]
        for sid, agg in per_subnet.items():
            self.db.run("UPDATE ipam_subnets SET dhcp_size=?, dhcp_used=?, dhcp_pools=?, updated_at=? WHERE id=?",
                        (agg["size"], agg["used"], ",".join(dict.fromkeys(agg["pools"])), now, sid))

    # --- ingest from a network collector (collectors.py: an on-site agent scans the LAN and reports) --------------
    def ingest(self, org_id, payload, user="collector"):
        """Fold a collector's sweep (subnets + live hosts) into IPAM under its client. Mirrors the router-sync
        reconciliation: match subnets by (org,cidr) and addresses by (subnet,ip); NEVER clobber a manual record, and
        rank collector data BELOW router/UniFi-derived rows (only update rows we own, else just enrich mac/hostname)."""
        org_id = int(org_id)
        now = self._now()
        summary = {"subnets_added": 0, "subnets_seen": 0, "addresses_added": 0, "addresses_updated": 0, "hosts": 0}
        out = {}   # cidr -> (sid, netobj)
        hosts = payload.get("hosts") or []

        nets = []
        for c in payload.get("subnets") or []:
            try:
                n = ipaddress.ip_network(str(c).strip(), strict=False)
            except ValueError:
                continue
            if n.version == 4 and not self._reserved(n):
                nets.append(n)
        # infer a /24 for any reported host not inside a reported subnet, so its address still has a home
        for h in hosts:
            ip = (h.get("ip") or "").split("/")[0].split("%")[0]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or addr in self.reserved or any(addr in n for n in nets):
                continue
            guess = ipaddress.ip_network(f"{ip}/24", strict=False)
            if not self._reserved(guess) and guess not in nets:
                nets.append(guess)
        for n in nets:
            self._ingest_subnet(org_id, n, now, summary, out)

        for h in hosts:
            ip = (h.get("ip") or "").split("/")[0].split("%")[0]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or addr in self.reserved:
                continue
            match = next(((sid, no) for (sid, no) in out.values() if addr in no), None)
            if not match:
                continue
            sid = match[0]
            mac = (h.get("mac") or "").strip() or None
            host = (h.get("hostname") or "").strip() or None
            summary["hosts"] += 1
            row = self.db.one("SELECT * FROM ipam_addresses WHERE subnet_id=? AND ip=?", (sid, ip))
            if not row:
                self.db.run("INSERT INTO ipam_addresses (subnet_id, ip, ip_sort, status, hostname, mac, source, last_seen, created_at, updated_at) "
                            "VALUES (?,?,?,?,?,?,'collector',?,?,?)", (sid, ip, _ipint(ip), "used", host, mac, now, now, now))
                summary["addresses_added"] += 1
            elif row["source"] in ("collector", None, ""):   # a row we own: refresh it (keep a gateway/dhcp status if set)
                self.db.run("UPDATE ipam_addresses SET status=CASE WHEN status IN ('gateway','dhcp') THEN status ELSE 'used' END, "
                            "mac=COALESCE(?, mac), hostname=COALESCE(?, hostname), source='collector', last_seen=?, updated_at=? WHERE id=?",
                            (mac, host, now, now, row["id"]))
                summary["addresses_updated"] += 1
            else:   # manual / router / unifi own this row - never touch its fields; only fill a blank mac + note presence
                self.db.run("UPDATE ipam_addresses SET mac=COALESCE(mac,?), last_seen=? WHERE id=?", (mac, now, row["id"]))

        # VLANs the agent read over SNMP (dot1q) - fold into the VLAN inventory (never clobbers a name already set)
        for v in payload.get("vlans") or []:
            try:
                num = int(v.get("number"))
            except (TypeError, ValueError):
                continue
            if num > 1:
                self._vlan_for(org_id, num, (v.get("name") or "").strip() or None, now)
                summary["vlans"] = summary.get("vlans", 0) + 1
        # SNMP-identified devices -> IPAM's infrastructure inventory (never clobbers a manual rename)
        for dv in payload.get("devices") or []:
            self._ingest_device(org_id, dv, now, summary)
        return summary

    def _ingest_device(self, org_id, dv, now, summary):
        """Upsert an SNMP-discovered endpoint into ipam_devices, matched by (org, management_ip). source_auto=1."""
        ip = (dv.get("ip") or "").split("/")[0].strip()
        if not ip:
            return
        name = (dv.get("name") or "").strip() or ip
        descr = (dv.get("descr") or "").strip() or None
        tid = self._type_id(self._snmp_type(descr, dv.get("type")))
        row = self.db.one("SELECT id FROM ipam_devices WHERE COALESCE(org_id,0)=? AND management_ip=?", (org_id or 0, ip))
        if row:
            self.db.run("UPDATE ipam_devices SET type_id=COALESCE(type_id,?), description=COALESCE(description,?), updated_at=? WHERE id=?",
                        (tid, descr, now, row["id"]))
            did = row["id"]
        else:
            did = self.db.run("INSERT INTO ipam_devices (name, type_id, org_id, management_ip, description, source_auto, created_by, created_at, updated_at) "
                              "VALUES (?,?,?,?,?,1,'collector',?,?)", (name, tid, org_id, ip, descr, now, now))
            summary["devices_added"] = summary.get("devices_added", 0) + 1
        self.db.run("UPDATE ipam_addresses SET ipam_device_id=? WHERE ipam_device_id IS NULL AND ip=? AND subnet_id IN "
                    "(SELECT id FROM ipam_subnets WHERE COALESCE(org_id,0)=?)", (did, ip, org_id or 0))

    @staticmethod
    def _snmp_type(descr, hint=None):
        """Best-guess IPAM device type from an SNMP sysDescr / hint. Returns a seeded ipam_device_types name."""
        t = " " + (str(hint or "") + " " + str(descr or "")).lower() + " "
        if any(w in t for w in ("firewall", "fortigate", "fortios", "palo alto", "sonicwall", "pfsense")):
            return "Firewall"
        if "access point" in t or " ap " in t or "wireless" in t or "wi-fi" in t or "aironet" in t:
            return "Access point"
        if "switch" in t or "catalyst" in t or "procurve" in t or "aruba" in t:
            return "Switch"
        if any(w in t for w in ("router", "gateway", "mikrotik", "routeros", "edgerouter")):
            return "Router"
        return "Server"   # a sane default for anything else that answers SNMP

    def _ingest_subnet(self, org_id, netobj, now, summary, out):
        """Create or refresh one collector-reported subnet (no managed device behind it). Records it in `out`."""
        cidr = str(netobj)
        if cidr in out:
            return out[cidr][0]
        row = self.db.one("SELECT * FROM ipam_subnets WHERE cidr=? AND COALESCE(org_id,0)=?", (cidr, org_id or 0))
        if not row:
            sid = self.db.run("INSERT INTO ipam_subnets (cidr, family, org_id, name, source, first_seen, last_seen, created_at, updated_at) "
                              "VALUES (?,?,?,?,'collector',?,?,?,?)", (cidr, 4, org_id, "", now, now, now, now))
            summary["subnets_added"] += 1
        else:
            sid = row["id"]
            summary["subnets_seen"] += 1
            self.db.run("UPDATE ipam_subnets SET last_seen=?, updated_at=? WHERE id=?", (now, now, sid))
        out[cidr] = (sid, netobj)
        return sid

    _KIND_TYPE = {"router": "Router", "switch": "Switch", "ap": "Access point"}

    @staticmethod
    def _unifi_type(model, is_console):
        """Best-guess IPAM device type for a UniFi / UISP infrastructure device from its model code."""
        m = str(model or "").upper()
        if is_console or any(k in m for k in ("UDM", "UXG", "USG", "UCG", "DREAM", "GATEWAY", "EDGEROUTER", "ER-")):
            return "Gateway"
        if any(k in m for k in ("USW", "US-", "US8", "US16", "US24", "US48", "FLEX", "SWITCH", "ES-")):
            return "Switch"
        if any(k in m for k in ("UAP", "U6", "U7", "NANOHD", "AC-", "ACCESS", "UALR", "UAX", "AP-", "WAVE")):
            return "Access point"
        return "Other"

    def _sync_devices(self, org_id, now, summary):
        """Auto-populate IPAM's INFRASTRUCTURE inventory from discovery: managed MikroTiks and UniFi / UISP
        APs/switches/gateways become ipam_devices; UniFi sites become locations. Client workstations are never added.
        A manual rename is never clobbered (name is set only when a device is first created)."""
        # locations from the client's UniFi / UISP sites
        loc_by_site = {}
        for s in self.db.q("SELECT DISTINCT name FROM net_sites WHERE org_id=? AND name IS NOT NULL AND name!=''", (org_id,)):
            row = self.db.one("SELECT id FROM ipam_locations WHERE name=? AND COALESCE(org_id,0)=?", (s["name"], org_id))
            if row:
                loc_by_site[s["name"]] = row["id"]
            else:
                loc_by_site[s["name"]] = self.db.run(
                    "INSERT INTO ipam_locations (name, org_id, created_by, created_at) VALUES (?,?,?,?)", (s["name"], org_id, "sync", now))
                summary["locations_added"] = summary.get("locations_added", 0) + 1

        def link_addr(ip, ipam_device_id):
            if not ip:
                return
            self.db.run("UPDATE ipam_addresses SET ipam_device_id=? WHERE ipam_device_id IS NULL AND ip=? AND subnet_id IN "
                        "(SELECT id FROM ipam_subnets WHERE COALESCE(org_id,0)=?)", (ipam_device_id, ip, org_id))

        # managed MikroTiks -> ipam_devices, linked by device_id and typed by kind
        for d in self.db.q("SELECT id, name, model, board, kind_override, tunnel_ip, wan_ip FROM devices "
                           "WHERE org_id=? AND state='adopted'", (org_id,)):
            mip = (d.get("tunnel_ip") or d.get("wan_ip") or "").split("/")[0] or None
            tid = self._type_id(self._KIND_TYPE.get(_devkind(d.get("model"), d.get("board"), d.get("kind_override")), "Router"))
            row = self.db.one("SELECT id FROM ipam_devices WHERE device_id=?", (d["id"],))
            if row:
                self.db.run("UPDATE ipam_devices SET type_id=COALESCE(type_id,?), management_ip=COALESCE(management_ip,?), updated_at=? WHERE id=?",
                            (tid, mip, now, row["id"]))
                did = row["id"]
            else:
                did = self.db.run("INSERT INTO ipam_devices (name, type_id, org_id, device_id, management_ip, source_auto, created_by, created_at, updated_at) "
                                  "VALUES (?,?,?,?,?,1,?,?,?)", (d["name"], tid, org_id, d["id"], mip, "sync", now, now))
                summary["devices_added"] = summary.get("devices_added", 0) + 1
            link_addr(mip, did)

        # UniFi / UISP infrastructure (APs, switches, gateways) -> ipam_devices, matched by (org, management_ip)
        unifi = getattr(self, "unifi", None)
        if unifi:
            try:
                known = unifi.known_for_org(org_id) or {}
            except Exception:
                known = {}
            for _mac, info in known.items():
                ip = str(info.get("ip") or "").split("/")[0].strip()
                if not ip:
                    continue
                tid = self._type_id(self._unifi_type(info.get("model"), info.get("console")))
                lid = loc_by_site.get(info.get("site"))
                row = self.db.one("SELECT id FROM ipam_devices WHERE device_id IS NULL AND COALESCE(org_id,0)=? AND management_ip=?", (org_id, ip))
                if row:
                    self.db.run("UPDATE ipam_devices SET type_id=COALESCE(type_id,?), location_id=COALESCE(location_id,?), updated_at=? WHERE id=?",
                                (tid, lid, now, row["id"]))
                    did = row["id"]
                else:
                    did = self.db.run("INSERT INTO ipam_devices (name, type_id, location_id, org_id, management_ip, description, source_auto, "
                                      "created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,1,?,?,?)",
                                      (info.get("name") or info.get("model") or "UniFi device", tid, lid, org_id, ip, info.get("model"), "sync", now, now))
                    summary["devices_added"] = summary.get("devices_added", 0) + 1
                link_addr(ip, did)

    _GUESS = "Inferred from UniFi (no configured network found)"

    def _sync_unifi(self, org_id, now, summary):
        """Overlay the client's UniFi data onto IPAM, best source first:
        1) CONFIGURED networks from UniFi's Network integration API - real CIDR + VLAN, for EVERY site (gateway or not);
        2) connected clients and infrastructure devices, each placed into the most-specific matching subnet.
        A /24 is inferred only when nothing covers an IP, and is marked so a later real network replaces it. Manual
        records are never overwritten."""
        unifi = getattr(self, "unifi", None)
        if not unifi:
            return
        try:
            data = unifi.integration_data(org_id)
        except Exception:
            data = {"networks": [], "clients": [], "error": "integration API unreadable"}

        def subs():   # the client's subnets as (id, netobj, row)
            res = []
            for r in self.db.q("SELECT id, cidr, source, notes FROM ipam_subnets WHERE COALESCE(org_id,0)=?", (org_id,)):
                try:
                    res.append((r["id"], ipaddress.ip_network(r["cidr"], strict=False), r))
                except ValueError:
                    pass
            return res

        # 1) real configured networks -> subnets; a real network replaces any UniFi-guessed /24 it now covers
        unifi_pools = []   # (subnet_id, start_int, stop_int) for networks whose DHCP range we know
        for net in data.get("networks") or []:
            try:
                netobj = ipaddress.ip_network(net["cidr"], strict=False)
            except (ValueError, KeyError):
                continue
            if netobj.version != 4 or self._reserved(netobj):
                continue
            name = net.get("name") or net.get("site") or "UniFi"
            if net.get("vlan"):
                name = f"{name} (VLAN {net['vlan']})"
            sid = self._upsert_subnet(org_id, netobj, {"id": None}, None, None, name, now, summary, {})
            summary["unifi_networks"] = summary.get("unifi_networks", 0) + 1
            ds, dp = net.get("dhcp_start"), net.get("dhcp_stop")   # the UniFi DHCP pool range, if the API gave one
            if ds and dp:
                try:
                    unifi_pools.append((sid, int(ipaddress.ip_address(ds)), int(ipaddress.ip_address(dp))))
                except ValueError:
                    pass
            else:   # DHCP off / not exposed - clear any stale UniFi pool figure (never touch a MikroTik pool)
                self.db.run("UPDATE ipam_subnets SET dhcp_size=NULL, dhcp_used=NULL, dhcp_pools=NULL WHERE id=? AND dhcp_pools='UniFi DHCP'", (sid,))
            if net.get("vlan"):   # auto-populate the VLAN and link the subnet
                vid = self._vlan_for(org_id, net.get("vlan"), net.get("name"), now)
                if vid:
                    self.db.run("UPDATE ipam_subnets SET vlan_id=COALESCE(vlan_id, ?) WHERE id=?", (vid, sid))
            for (oid, ono, orow) in subs():
                if oid != sid and ono != netobj and ono.subnet_of(netobj) and (orow.get("notes") or "") == self._GUESS:
                    self.db.run("UPDATE OR IGNORE ipam_addresses SET subnet_id=? WHERE subnet_id=?", (sid, oid))
                    self.db.run("DELETE FROM ipam_subnets WHERE id=?", (oid,))

        # 2) addresses: real clients first, then the infrastructure devices (name/MAC)
        ips = {}
        for c in data.get("clients") or []:
            ip = str(c.get("ip") or "").split("/")[0].strip()
            if ip:
                ips[ip] = {"mac": c.get("mac"), "name": c.get("name")}
        try:
            for mac, d in (unifi.known_for_org(org_id) or {}).items():
                ip = str(d.get("ip") or "").split("/")[0].strip()
                if ip:
                    ips[ip] = {"mac": mac, "name": d.get("name") or d.get("model"), "site": d.get("site")}
        except Exception:
            pass

        # UniFi DHCP pool utilisation: how many of the DHCP range's addresses are taken by connected clients/devices
        if unifi_pools:
            ip_ints = set()
            for ip in ips:
                try:
                    ip_ints.add(int(ipaddress.ip_address(ip)))
                except ValueError:
                    pass
            for sid, lo, hi in unifi_pools:
                if lo > hi:
                    lo, hi = hi, lo
                size = hi - lo + 1
                used = sum(1 for x in ip_ints if lo <= x <= hi)
                self.db.run("UPDATE ipam_subnets SET dhcp_size=?, dhcp_used=?, dhcp_pools='UniFi DHCP', updated_at=? WHERE id=?",
                            (size, min(used, size), now, sid))

        current = subs()
        for ip, info in ips.items():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or not addr.is_private or addr in self.reserved:
                continue
            match = None   # most-specific containing subnet
            for (oid, ono, _r) in current:
                if addr in ono and (match is None or ono.prefixlen > match[1].prefixlen):
                    match = (oid, ono)
            if match is None:
                netobj = ipaddress.ip_network(f"{ip}/24", strict=False)
                sid = self._upsert_subnet(org_id, netobj, {"id": None}, None, None, info.get("site") or "UniFi", now, summary, {})
                self.db.run("UPDATE ipam_subnets SET notes=? WHERE id=? AND (notes IS NULL OR notes='')", (self._GUESS, sid))
                current = subs()
                match = (sid, netobj)
            self._put_unifi_address(match[0], ip, info.get("name"), info.get("mac"), now, summary)

        if data.get("error"):
            summary["unifi_error"] = data["error"]

    def _put_unifi_address(self, sid, ip, name, mac, now, summary):
        row = self.db.one("SELECT id, source FROM ipam_addresses WHERE subnet_id=? AND ip=?", (sid, ip))
        if not row:
            self.db.run("INSERT INTO ipam_addresses (subnet_id, ip, ip_sort, status, hostname, mac, source, last_seen, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,?,'unifi',?,?,?)", (sid, ip, _ipint(ip), "used", name, mac, now, now, now))
            summary["addresses_added"] += 1
            summary["unifi"] += 1
        elif row["source"] != "manual":   # keep a manual record's fields; enrich a discovered/live one with the UniFi name
            self.db.run("UPDATE ipam_addresses SET status=CASE WHEN status='gateway' THEN 'gateway' ELSE 'used' END, "
                        "hostname=COALESCE(?, hostname), mac=COALESCE(?, mac), source='unifi', last_seen=?, updated_at=? WHERE id=?",
                        (name, mac, now, now, row["id"]))
            summary["addresses_updated"] += 1
            summary["unifi"] += 1
        else:
            self.db.run("UPDATE ipam_addresses SET mac=COALESCE(mac,?), last_seen=? WHERE id=?", (mac, now, row["id"]))
