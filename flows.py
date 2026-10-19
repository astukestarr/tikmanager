"""Flows (pilot): who talks to what through a router - like UniFi's Insights > Flows - from RouterOS Traffic Flow (IPFIX).

- Opt-in per router (router page > Flows). Turning it on sets /ip traffic-flow on the router (a small cache, short
  timeouts) and adds a target: TikManager's tunnel address, FLOW_PORT, over the WireGuard tunnel - nothing leaves the
  tunnel. Refused on routers with less than MIN_MEM of memory; turning it off puts the router's previous Traffic Flow
  settings back.
- Collector: one UDP socket on the tunnel address; IPFIX (v10) and NetFlow v9 with templates. Each record becomes a
  conversation - the local side (private or the router's own networks), the remote side, the service port, who started
  it (in / out), bytes each way - summed into BUCKET-second buckets, at most MAX_KEYS conversations per router per bucket
  (the rest is counted as "other"). Kept KEEP_DAYS days, at most MAX_ROWS rows per router.
- Shown with names (DHCP leases), country and organisation (IPinfo Lite, geoip.py) and service names. Blocked: the
  samples region blocking's log rules send (router logs, prefix tm-geo), so it shows what was dropped.
"""
import ipaddress
import json
import os
import random
import re
import socket
import struct
import threading
import time
import traceback

from routeros import RouterError

FLOW_PORT = int(os.environ.get("TM_FLOW_PORT", "2055"))
BUCKET = 600
MAX_KEYS = 4000
KEEP_DAYS = 7
MAX_ROWS = 1_500_000
MIN_MEM = 100 * 1024 * 1024       # 64 MB routers are left out
# protecting TikManager itself: a busy core router can send thousands of flow packets a second, and reading them all would
# starve everything else. Each router gets PACKETS_PER_SEC packets read per second (template packets always); the rest are
# dropped unread. A router over budget for OVERLOAD_MINUTES minutes in a row gets Flows turned off, with an event.
PACKETS_PER_SEC = 40
OVERLOAD_MINUTES = 5
TF_SETTINGS = {"enabled": "yes", "interfaces": "all", "cache-entries": "4k", "active-flow-timeout": "1m", "inactive-flow-timeout": "15s"}
TF_KEEP = ("enabled", "interfaces", "cache-entries", "active-flow-timeout", "inactive-flow-timeout")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")]
PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
SERVICES = {20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
            135: "DCE Endpoint", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 500: "IKE", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 853: "DNS over TLS", 993: "IMAPS", 995: "POP3S",
            1194: "OpenVPN", 1433: "SQL Server", 1701: "L2TP", 1723: "PPTP", 1900: "SSDP", 3074: "Xbox Live", 3306: "MySQL",
            3389: "RDP", 3478: "STUN", 4500: "IPsec NAT-T", 5060: "SIP", 5061: "SIP TLS", 5222: "XMPP", 5353: "mDNS", 8080: "HTTP alt",
            8291: "Winbox", 8443: "HTTPS alt", 8728: "RouterOS API", 8729: "RouterOS API TLS", 51820: "WireGuard"}

# IPFIX / NetFlow v9 information elements read (id -> name)
IE = {1: "bytes", 2: "packets", 4: "proto", 7: "sport", 8: "src", 11: "dport", 12: "dst", 85: "bytes", 86: "packets"}


def service(port, proto):
    if proto in (1, 58):
        return "ICMP"
    return SERVICES.get(port) or (f"{PROTO.get(proto, proto)} {port}" if port else PROTO.get(proto, str(proto)))


class Parser:
    """NetFlow v9 / IPFIX: templates per (exporter, observation domain, template id), data records -> dicts."""

    def __init__(self):
        self.templates = {}

    def parse(self, src, data):
        if len(data) < 4:
            return []
        ver = struct.unpack("!H", data[:2])[0]
        if ver == 10:
            if len(data) < 16:
                return []
            length, dom = struct.unpack("!H", data[2:4])[0], struct.unpack("!I", data[12:16])[0]
            return self._sets(src, dom, data[16:min(length, len(data))], ipfix=True)
        if ver == 9:
            if len(data) < 20:
                return []
            dom = struct.unpack("!I", data[16:20])[0]
            return self._sets(src, dom, data[20:], ipfix=False)
        return []

    def _sets(self, src, dom, buf, ipfix):
        out, off = [], 0
        while off + 4 <= len(buf):
            sid, slen = struct.unpack("!HH", buf[off:off + 4])
            if slen < 4:
                break
            body = buf[off + 4:off + slen]
            if sid == (2 if ipfix else 0):
                self._templates(src, dom, body, ipfix)
            elif sid >= 256:
                out += self._data(src, dom, sid, body, ipfix)
            off += slen
        return out

    def _templates(self, src, dom, body, ipfix):
        off = 0
        while off + 4 <= len(body):
            tid, count = struct.unpack("!HH", body[off:off + 4])
            off += 4
            fields = []
            for _ in range(count):
                if off + 4 > len(body):
                    return
                fid, flen = struct.unpack("!HH", body[off:off + 4])
                off += 4
                if ipfix and fid & 0x8000:   # enterprise-specific: skip the enterprise number
                    fid, off = None, off + 4
                fields.append((fid, flen))
            self.templates[(src, dom, tid)] = fields

    def _data(self, src, dom, tid, body, ipfix):
        fields = self.templates.get((src, dom, tid))
        if not fields:
            return []
        out, off = [], 0
        fixed = all(fl != 65535 for _, fl in fields)
        size = sum(fl for _, fl in fields) if fixed else None
        while off < len(body) and (not fixed or off + size <= len(body)):
            rec = {}
            for fid, flen in fields:
                if flen == 65535:   # IPFIX variable length
                    if off >= len(body):
                        return out
                    flen, off = body[off], off + 1
                    if flen == 255:
                        flen, off = struct.unpack("!H", body[off:off + 2])[0], off + 2
                v = body[off:off + flen]
                off += flen
                name = IE.get(fid)
                if not name or len(v) != flen:
                    continue
                if name in ("src", "dst"):
                    if flen == 4:
                        rec[name] = socket.inet_ntoa(v)
                else:
                    rec[name] = int.from_bytes(v, "big")
            if "src" in rec and "dst" in rec:
                out.append(rec)
            if fixed and size == 0:
                break
        return out


class Flows:
    def __init__(self, db, settings, geo, client, routerlogs=None):
        self.db, self.s, self.geo, self.client, self.logs = db, settings, geo, client, routerlogs
        self.parser = Parser()
        self.buf, self.lock = {}, threading.Lock()
        self.keys = {}          # (device, bucket) -> conversations so far (MAX_KEYS)
        self.seen = {}          # device id -> last record time
        self.devmap, self.devmap_at = {}, 0
        self.leases = {}        # device id -> (read at, {ip: name}, FastTrack on?)
        self.budget = {}        # exporter address -> [second, packets read this second, packets dropped this minute, minute]
        self.overload = {}      # exporter address -> minutes in a row over budget
        self._pruned = 0

    # --- turning it on / off ---------------------------------------------------------------------------------
    def enable(self, d):
        if (d.get("mem_total") or 0) and d["mem_total"] < MIN_MEM:
            raise ValueError(f"This router has {d['mem_total'] // 2**20} MB of memory - Flows is only for routers with 128 MB or more.")
        cl = self.client(d)
        prev = cl.traffic_flow()
        if not d.get("flows_prev"):
            self.db.run("UPDATE devices SET flows_prev=? WHERE id=?", (json.dumps({k: prev.get(k) for k in TF_KEEP}), d["id"]))
        settings = dict(TF_SETTINGS)
        if str(prev.get("enabled")) == "true":   # already in use (another collector): leave its interfaces and cache as they are
            settings = {"enabled": "yes"}
        cl.traffic_flow_on(settings, self.target_ip(), FLOW_PORT, d["tunnel_ip"])
        self.db.run("UPDATE devices SET flows_on=1 WHERE id=?", (d["id"],))
        self.devmap_at = 0
        self.db.event(d["id"], d["org_id"], "flows", "Flows turned on (Traffic Flow to TikManager over the tunnel)")

    def disable(self, d):
        if d["online"]:
            prev = json.loads(d.get("flows_prev") or "{}")
            restore = {k: v for k, v in prev.items() if v not in (None, "")}
            restore["enabled"] = "yes" if str(prev.get("enabled")) == "true" else "no"
            self.client(d).traffic_flow_off(restore, self.target_ip(), FLOW_PORT)
        self.db.run("UPDATE devices SET flows_on=0, flows_prev=NULL WHERE id=?", (d["id"],))
        self.devmap_at = 0
        self.db.event(d["id"], d["org_id"], "flows", "Flows turned off - Traffic Flow settings put back")

    def target_ip(self):
        return "127.0.0.1" if getattr(self.s, "dev", False) else self.s.wg_server_ip

    # --- collecting ------------------------------------------------------------------------------------------
    def _device_for(self, src):
        if time.time() - self.devmap_at > 60:
            self.devmap = {}
            for d in self.db.q("SELECT id, tunnel_ip, networks, wan_ip, public_ip FROM devices WHERE state='adopted' AND flows_on=1"):
                nets = []
                for n in json.loads(d["networks"] or "[]"):
                    try:
                        nets.append(ipaddress.ip_network(n.get("network") or "", strict=False))
                    except ValueError:
                        pass
                self.devmap[d["tunnel_ip"]] = (d["id"], nets, {d["wan_ip"], d["public_ip"]} - {None, ""})
            self.devmap_at = time.time()
        return self.devmap.get(src)

    @staticmethod
    def _local(ip, nets, own):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return ip in own or any(a in n for n in nets) or any(a in n for n in PRIVATE)

    def add(self, src, records, now=None):
        dev = self._device_for(src)
        if not dev:
            return
        did, nets, own = dev
        now = now or time.time()
        bucket = int(now // BUCKET) * BUCKET
        self.seen[did] = now
        with self.lock:
            for r in records:
                s, t = r["src"], r["dst"]
                sl, tl = self._local(s, nets, own), self._local(t, nets, own)
                sp, dp, proto, b = r.get("sport", 0), r.get("dport", 0), r.get("proto", 0), r.get("bytes", 0)
                if sl and not tl:
                    local, remote, up, down = s, t, b, 0
                    port, dirn = (dp, "out") if dp <= sp or dp < 1024 else (sp, "in")
                elif tl and not sl:
                    local, remote, up, down = t, s, 0, b
                    port, dirn = (sp, "out") if sp <= dp or sp < 1024 else (dp, "in")
                else:   # both local (between networks) or both remote (transit): keep it as-is
                    local, remote, up, down = s, t, b, 0
                    port, dirn = min(sp, dp) if sp and dp else (sp or dp), "local" if sl else "transit"
                if proto in (1, 58):
                    port = 0
                key = (did, bucket, local, remote, port, proto, dirn)
                cur = self.buf.get(key)
                if cur is None:
                    kb = (did, bucket)
                    if self.keys.get(kb, 0) >= MAX_KEYS:
                        key = (did, bucket, "other", "other", 0, 0, "other")
                        cur = self.buf.get(key)
                    else:
                        self.keys[kb] = self.keys.get(kb, 0) + 1
                    if cur is None:
                        cur = self.buf[key] = [0, 0, 0, 0]
                cur[0] += up
                cur[1] += down
                cur[2] += r.get("packets", 0)
                cur[3] += 1

    def flush(self):
        with self.lock:
            rows, self.buf = self.buf, {}
            old = int(time.time() // BUCKET) * BUCKET - BUCKET
            self.keys = {k: v for k, v in self.keys.items() if k[1] >= old}
        if not rows:
            return
        self.db.many("""INSERT INTO flows (device_id, ts, local, remote, port, proto, dir, up, down, packets, flows) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT (device_id, ts, local, remote, port, proto, dir) DO UPDATE SET up=up+excluded.up, down=down+excluded.down,
                        packets=packets+excluded.packets, flows=flows+excluded.flows""",
                     [(*k, *v) for k, v in rows.items()])

    def prune(self):
        self.db.run("DELETE FROM flows WHERE ts < ?", (time.time() - KEEP_DAYS * 86400,))
        for r in self.db.q("SELECT device_id, COUNT(*) AS n FROM flows GROUP BY device_id HAVING n > ?", (MAX_ROWS,)):
            cut = self.db.one("SELECT ts FROM flows WHERE device_id=? ORDER BY ts DESC LIMIT 1 OFFSET ?", (r["device_id"], MAX_ROWS))
            if cut:
                self.db.run("DELETE FROM flows WHERE device_id=? AND ts <= ?", (r["device_id"], cut["ts"]))

    def listen(self):
        host = self.target_ip()
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                sock.bind((host, FLOW_PORT))
                print(f"  Flows: listening on {host}:{FLOW_PORT}/udp")
                while True:
                    data, (src, _port) = sock.recvfrom(65535)
                    if not self._allow(src, data):
                        continue
                    try:
                        recs = self.parser.parse(src, data)
                        if recs:
                            self.add(src, recs)
                    except Exception:  # noqa: BLE001 - one odd packet never stops the listener
                        traceback.print_exc()
            except OSError as e:
                print(f"  Flows: can't listen on {host}:{FLOW_PORT} ({e}) - retrying in a minute")
                time.sleep(60)

    @staticmethod
    def _has_template(data):
        """Does this packet start with a template set? (always read - without templates nothing can be decoded)"""
        if len(data) < 24:
            return False
        ver = int.from_bytes(data[:2], "big")
        off = 16 if ver == 10 else 20
        sid = int.from_bytes(data[off:off + 2], "big")
        return sid in ((2, 3) if ver == 10 else (0, 1))

    def _allow(self, src, data):
        now = time.time()
        sec, minute = int(now), int(now // 60)
        b = self.budget.get(src)
        if b is None or b[3] != minute:
            if b is not None:   # a minute finished: was it over budget?
                self.overload[src] = self.overload.get(src, 0) + 1 if b[2] > 0 else 0
            b = self.budget[src] = [sec, 0, 0, minute]
        if b[0] != sec:
            b[0], b[1] = sec, 0
        if b[1] >= PACKETS_PER_SEC and not self._has_template(data):
            b[2] += 1
            return False
        b[1] += 1
        return True

    def _shed(self):
        """Routers that kept sending more than TikManager reads: turn their Flows off (they'd only ever be a sample)."""
        for src, n in list(self.overload.items()):
            if n < OVERLOAD_MINUTES:
                continue
            self.overload[src] = 0
            d = self.db.one("SELECT * FROM devices WHERE tunnel_ip=? AND flows_on=1", (src,))
            if not d:
                continue
            try:
                self.disable(d)
            except Exception:  # noqa: BLE001 - router unreachable: at least stop counting it
                self.db.run("UPDATE devices SET flows_on=0 WHERE id=?", (d["id"],))
                self.devmap_at = 0
            self.db.event(d["id"], d["org_id"], "flows", f"Flows turned off by TikManager: the router sent more flow records than TikManager reads "
                          f"({PACKETS_PER_SEC} packets a second) for {OVERLOAD_MINUTES} minutes - too busy a router for Flows.")

    def loop(self):
        while True:
            time.sleep(10)
            try:
                self._shed()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            try:
                if getattr(self.s, "dev", False):
                    self._simulate()
                self.flush()
                if time.time() - self._pruned > 3600:
                    self.prune()
                    self._pruned = time.time()
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self):
        threading.Thread(target=self.listen, daemon=True, name="flows-listen").start()
        threading.Thread(target=self.loop, daemon=True, name="flows").start()

    def _simulate(self):
        """Dev mode: made-up traffic for routers with Flows on (simulated routers don't send IPFIX)."""
        for d in self.db.q("SELECT id, tunnel_ip, networks FROM devices WHERE state='adopted' AND flows_on=1"):
            r = random.Random()
            lan = (json.loads(d["networks"] or "[]") or [{"network": "192.168.88.0/24"}])[0]["network"].rsplit(".", 1)[0]
            remotes = [("34.120.142.74", 443), ("8.8.8.8", 53), ("47.242.53.37", 443), ("78.41.2.9", 443), ("24.50.1.1", 443),
                       ("3.5.1.20", 443), ("12.1.4.8", 123), ("1.0.2.7", 80), ("46.1.0.4", 22)]
            recs = []
            for _ in range(r.randint(20, 60)):
                ip, port = r.choice(remotes)
                host = f"{lan}.{r.randint(10, 40)}"
                eph = r.randint(40000, 60000)
                recs.append({"src": host, "dst": ip, "sport": eph, "dport": port, "proto": 17 if port in (53, 123) else 6,
                             "bytes": r.randint(200, 40000), "packets": r.randint(2, 40)})
                recs.append({"src": ip, "dst": host, "sport": port, "dport": eph, "proto": 17 if port in (53, 123) else 6,
                             "bytes": r.randint(2000, 900000), "packets": r.randint(2, 600)})
            if r.random() < 0.3:   # someone knocking on the router's Winbox from abroad
                recs.append({"src": "46.1.0.4", "dst": f"{lan}.1", "sport": r.randint(40000, 60000), "dport": 8291, "proto": 6, "bytes": 60, "packets": 1})
            self.add(d["tunnel_ip"], recs)
            if self.logs and r.random() < 0.5:
                self.logs.add(d["id"], f"firewall,info tm-geo-in input: in:ether1 out:(unknown 0), connection-state:new proto TCP (SYN), "
                                       f"1.0.2.{r.randint(2, 250)}:{r.randint(40000, 60000)}->203.0.113.{d['id'] % 250 + 2}:{r.choice([22, 8291, 443, 3389])}, len 60")

    # --- reading ---------------------------------------------------------------------------------------------
    def names(self, d):
        """IP -> name from the router's DHCP leases, and whether FastTrack is on (read live, kept 5 minutes). FastTracked
        packets skip Traffic Flow, so on those routers conversations show up but their byte counts are far too low."""
        hit = self.leases.get(d["id"])
        if hit and time.time() - hit[0] < 300:
            return hit[1]
        out, ft = {}, False
        if d["online"]:
            try:
                cl = self.client(d)
                for l in cl.dhcp_leases():
                    if l.get("address"):
                        out[l["address"]] = l.get("host") or l.get("comment") or ""
                ft = any(r.get("action") == "fasttrack-connection" and r.get("disabled") != "true" for r in cl.fw_rules("filter") or [])
            except RouterError:
                pass
        self.leases[d["id"]] = (time.time(), out, ft)
        return out

    def query(self, d, f):
        """Flows for one router: f = hours, q, local, remote, port, proto, dir, country, org, view (all / blocked), limit."""
        hours = max(1, min(KEEP_DAYS * 24, int(f.get("hours") or 24)))
        since = time.time() - hours * 3600
        names, cn = self.names(d), self.geo.names()
        if f.get("view") == "blocked":
            return self._blocked(d, since, f, names, cn)
        cond, args = ["device_id=?", "ts>=?"], [d["id"], since]
        for k, col in (("local", "local"), ("remote", "remote"), ("dir", "dir")):
            if f.get(k):
                cond.append(f"{col}=?"); args.append(f[k])
        if str(f.get("port") or "").isdigit():
            cond.append("port=?"); args.append(int(f["port"]))
        if str(f.get("proto") or "").isdigit():
            cond.append("proto=?"); args.append(int(f["proto"]))
        rows = self.db.q(f"""SELECT local, remote, port, proto, dir, SUM(up) AS up, SUM(down) AS down, SUM(packets) AS packets, SUM(flows) AS flows,
                             MAX(ts) AS last FROM flows WHERE {' AND '.join(cond)} GROUP BY local, remote, port, proto, dir
                             ORDER BY SUM(up) + SUM(down) DESC LIMIT 20000""", args)
        q = str(f.get("q") or "").lower().strip()
        out = []
        for r in rows:
            cc, org = self.geo.lookup(r["remote"]) if r["remote"] != "other" else ("", "")
            r.update(local_name=names.get(r["local"], ""), country=cc, country_name=cn.get(cc, ""), org=org,
                     service=service(r["port"], r["proto"]) if r["remote"] != "other" else "Other (over the limit)",
                     proto_name=PROTO.get(r["proto"], str(r["proto"])), last=r["last"] + BUCKET)
            if f.get("country") and cc != f["country"]:
                continue
            if f.get("org") and r["org"] != f["org"]:
                continue
            if q and q not in " ".join(str(r[k]) for k in ("local", "local_name", "remote", "org", "country_name", "service")).lower():
                continue
            out.append(r)
        tops = lambda key, label=None: [{"key": k, "label": (label(k) if label else k), "bytes": v} for k, v in
                                        sorted(self._sum(out, key).items(), key=lambda x: -x[1])[:5] if k]
        total = sum(r["up"] + r["down"] for r in out)
        return {"rows": out[:int(f.get("limit") or 500)], "count": len(out), "total": total, "hours": hours,
                "top_remote": tops("remote"), "top_local": tops("local", lambda k: names.get(k) or k),
                "top_country": tops("country", lambda k: cn.get(k, k)), "top_org": tops("org"), "top_service": tops("service"),
                "last_seen": self.seen.get(d["id"]), "on": bool(d.get("flows_on")), "bucket": BUCKET,
                "fasttrack": bool((self.leases.get(d["id"]) or (0, 0, False))[2])}

    @staticmethod
    def _sum(rows, key):
        out = {}
        for r in rows:
            out[r[key]] = out.get(r[key], 0) + r["up"] + r["down"]
        return out

    LOG = re.compile(r"tm-(geo|threat)-(in|out)\S*\s.*?proto (\w+)[^,]*, (\d+\.\d+\.\d+\.\d+):?(\d*)->(\d+\.\d+\.\d+\.\d+):?(\d*)")

    def _blocked(self, d, since, f, names, cn):
        """What region blocking / known bad networks dropped - from the sampled log lines (a few per minute, so a sample)."""
        out = {}
        for l in self.db.q("SELECT ts, message FROM router_logs WHERE device_id=? AND ts>=? AND (message LIKE '%tm-geo-%' OR message LIKE '%tm-threat-%') ORDER BY id DESC LIMIT 20000",
                           (d["id"], since)):
            m = self.LOG.search(l["message"])
            if not m:
                continue
            why, way, proto, s, sp, t, tp = m.groups()
            remote, local, port = (s, t, int(tp or 0)) if way == "in" else (t, s, int(tp or 0))
            pn = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(proto.upper(), 0)
            k = (local, remote, port, pn, way, why)
            if k not in out:
                cc, org = self.geo.lookup(remote)
                out[k] = {"local": local, "local_name": names.get(local, ""), "remote": remote, "port": port, "proto": pn, "proto_name": proto.upper(),
                          "dir": way, "country": cc, "country_name": cn.get(cc, ""), "org": org, "service": service(port, pn), "hits": 0, "last": l["ts"],
                          "up": 0, "down": 0, "packets": 0, "flows": 0,
                          "action": "Known bad network" if why == "threat" else "Region"}
            out[k]["hits"] += 1
        rows = sorted(out.values(), key=lambda r: -r["hits"])
        q = str(f.get("q") or "").lower().strip()
        rows = [r for r in rows if (not f.get("country") or r["country"] == f["country"]) and (not q or q in f"{r['remote']} {r['local']} {r['org']} {r['country_name']}".lower())]
        cnt = {}
        for r in rows:
            cnt[r["country"]] = cnt.get(r["country"], 0) + r["hits"]
        return {"rows": rows[:500], "count": len(rows), "view": "blocked", "hours": f.get("hours"),
                "top_country": [{"key": k, "label": cn.get(k, k), "hits": v} for k, v in sorted(cnt.items(), key=lambda x: -x[1])[:5] if k],
                "on": bool(d.get("flows_on")), "last_seen": self.seen.get(d["id"])}
