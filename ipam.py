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
        if with_counts:
            usable, by, used = self._counts(s)
            out["usable"] = usable
            out["counts"] = by
            out["used_total"] = used
            out["usage"] = round(100 * used / usable) if usable else 0
        return out

    # --- sections -----------------------------------------------------------------------------------------------
    def tree(self):
        """Sections (nested) and, separately, the client pivot - what the left sidebar needs."""
        secs = self.db.q("SELECT * FROM ipam_sections ORDER BY pos, name")
        subs = [self._subnet_public(s) for s in self.db.q("SELECT * FROM ipam_subnets ORDER BY family, cidr")]
        clients = self.db.q("SELECT o.id, o.name, COUNT(s.id) AS subnets FROM orgs o "
                            "JOIN ipam_subnets s ON s.org_id=o.id GROUP BY o.id ORDER BY o.name")
        return {"sections": secs, "subnets": subs, "clients": clients}

    def syncable_orgs(self):
        """Clients that have at least one adopted router - what the Sync picker offers (even before any IPAM subnets exist)."""
        return self.db.q("SELECT o.id, o.name, COUNT(d.id) AS routers, "
                        "SUM(CASE WHEN d.online=1 THEN 1 ELSE 0 END) AS online FROM orgs o "
                        "JOIN devices d ON d.org_id=o.id AND d.state='adopted' WHERE o.active=1 GROUP BY o.id ORDER BY o.name")

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
                      name=str(b.get("name") or "")[:120], gateway=str(b.get("gateway") or "")[:64] or None,
                      is_pool=1 if b.get("is_pool") else 0, mark_full=1 if b.get("mark_full") else 0,
                      notes=str(b.get("notes") or "")[:2000], updated_at=now)
        if sid:
            cols = ", ".join(f"{k}=?" for k in fields)
            self.db.run(f"UPDATE ipam_subnets SET {cols} WHERE id=?", (*fields.values(), int(sid)))
            return int(sid)
        return self.db.run("INSERT INTO ipam_subnets (cidr, family, org_id, section_id, name, gateway, is_pool, mark_full, "
                           "notes, source, first_seen, created_by, created_at, updated_at) "
                           "VALUES (?,?,?,?,?,?,?,?,?,'manual',?,?,?,?)",
                           (cidr, netobj.version, org_id, section_id, fields["name"], fields["gateway"], fields["is_pool"],
                            fields["mark_full"], fields["notes"], now, user, now, now))

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
    def search(self, q):
        q = (q or "").strip()
        if not q:
            return {"subnets": [], "addresses": []}
        subs = [self._subnet_public(s, with_counts=False) for s in
                self.db.q("SELECT * FROM ipam_subnets WHERE cidr LIKE ? OR name LIKE ? ORDER BY cidr LIMIT 50", (f"%{q}%", f"%{q}%"))]
        addrs = self.db.q("SELECT a.*, s.cidr AS subnet_cidr FROM ipam_addresses a JOIN ipam_subnets s ON s.id=a.subnet_id "
                          "WHERE a.ip LIKE ? OR a.hostname LIKE ? OR a.mac LIKE ? OR a.owner LIKE ? ORDER BY a.ip_sort LIMIT 100",
                          (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"))
        return {"subnets": subs, "addresses": addrs}

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

    def _sync_unifi(self, org_id, now, summary):
        """Place the client's UniFi / UISP devices (gateway, switches, APs) into IPAM by their LAN IP. UniFi's cloud API
        gives device IPs but not the configured subnets, so an address lands in the matching subnet when one exists, and
        otherwise a /24 is inferred (the only way to populate IPAM for a UniFi-only client with no MikroTik)."""
        unifi = getattr(self, "unifi", None)
        if not unifi:
            return
        try:
            devs = unifi.known_for_org(org_id) or {}
        except Exception:
            return
        subs = []   # (subnet_id, netobj) for this client
        for r in self.db.q("SELECT id, cidr FROM ipam_subnets WHERE COALESCE(org_id,0)=?", (org_id,)):
            try:
                subs.append((r["id"], ipaddress.ip_network(r["cidr"], strict=False)))
            except ValueError:
                pass
        for mac, d in (devs.items() if isinstance(devs, dict) else []):
            ip = str(d.get("ip") or "").split("/")[0].strip()
            if not ip:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version != 4 or not addr.is_private or addr in self.reserved:
                continue
            sid = next((s for (s, no) in subs if addr in no), None)
            if sid is None:   # UniFi-only / unknown subnet: infer a /24 from the device's IP
                netobj = ipaddress.ip_network(f"{ip}/24", strict=False)
                sid = self._upsert_subnet(org_id, netobj, {"id": None}, None, None, d.get("site") or "UniFi", now, summary, {})
                subs.append((sid, netobj))
            row = self.db.one("SELECT id, source FROM ipam_addresses WHERE subnet_id=? AND ip=?", (sid, ip))
            name = d.get("name") or d.get("model")
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
