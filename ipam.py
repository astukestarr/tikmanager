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
            return int(b["id"])
        return self.db.run("INSERT INTO ipam_devices (name, type_id, location_id, org_id, management_ip, description, notes, "
                           "created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (name, fields["type_id"], fields["location_id"], fields["org_id"], fields["management_ip"],
                            fields["description"], fields["notes"], user, now, now))

    def device_delete(self, did):
        self.db.run("DELETE FROM ipam_devices WHERE id=?", (int(did),))

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
            # 4) overlay the client's UniFi / UISP devices as addresses (and infer a /24 for a client with no MikroTik)
            self._sync_unifi(org_id, now, summary)
            # 5) auto-populate the infrastructure inventory (managed MikroTiks + UniFi APs/switches/gateways) and locations
            self._sync_devices(org_id, now, summary)
            return summary
        finally:
            with self.lock:
                self.syncing.discard(org_id)

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
