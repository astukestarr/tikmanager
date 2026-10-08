"""Site-to-site VPN for a client's routers: WireGuard, hub and spoke.

- One hub with a public address (its WAN IP, or a DDNS name / public IP typed in when it sits behind NAT) listens on a
  UDP port; every spoke keeps a tunnel to it (persistent keepalive, so spokes behind NAT work). Spoke-to-spoke traffic
  goes through the hub.
- Each router makes its own WireGuard keys - private keys never leave the routers; TikManager only reads public keys.
- Each site shares the LAN subnets ticked for it (pre-filled from the site map). Overlapping subnets, and subnets that
  collide with the tunnel network or TikManager's own 10.77.0.0/16, are refused before anything changes.
- Applying: every router online -> backup of every router ('pre-vpn', stops on failure) -> interface + keys on every
  router -> hub config -> spoke configs. Each router gets an address on the tunnel network, peers, routes to the other
  sites' subnets and accept rules at the top of its firewall (hub: the WireGuard port; all: ICMP from the tunnel and
  forwarding to/from it). Everything carries the comment "TikManager VPN" and is replaced on every apply; disabling
  or removing a site deletes exactly those objects and the interface.
- Every minute the active VPNs' handshakes are read and each spoke pings the hub's tunnel address.
"""
import ipaddress
import json
import threading
import time
import traceback

from routeros import VPN_IFACE, RouterError

RESERVED = ipaddress.ip_network("10.77.0.0/16")   # TikManager's management tunnel
UP_SECONDS = 180


class VpnError(ValueError):
    pass


def net(s):
    try:
        return ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError:
        raise VpnError(f"{s!r} isn't a valid subnet (example: 192.168.10.0/24).") from None


class Vpns:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.busy = set()
        self.lock = threading.Lock()

    # --- validation / saving ----------------------------------------------------------------------------------
    def free_tunnel_net(self, avoid):
        used = [net(v["tunnel_net"]) for v in self.db.q("SELECT tunnel_net FROM vpns")]
        for n in range(1, 255):
            cand = ipaddress.ip_network(f"10.250.{n}.0/24")
            if not any(cand.overlaps(u) for u in used + avoid):
                return str(cand)
        raise VpnError("No free tunnel network in 10.250.0.0/16 - enter one.")

    def validate(self, org_id, sites, hub_id, endpoint, port, tunnel_net, vpn_id=None):
        """sites: [{device_id, subnets: [...]}]. Returns (normalized sites, tunnel_net, endpoint) or raises VpnError."""
        if len(sites) < 2:
            raise VpnError("A VPN needs the hub and at least one other router.")
        if hub_id not in [s["device_id"] for s in sites]:
            raise VpnError("Pick which router is the hub.")
        if not 1 <= int(port) <= 65535:
            raise VpnError("The port must be 1-65535.")
        out, seen = [], []
        for s in sites:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (s["device_id"],))
            if not d or d["org_id"] != org_id or d["state"] != "adopted":
                raise VpnError("Every router must be an approved router of this client.")
            if (d["version"] or "7").split(".")[0].isdigit() and int((d["version"] or "7").split(".")[0]) < 7:
                raise VpnError(f"{d['name']} runs RouterOS {d['version']} - WireGuard needs RouterOS 7 (upgrade it first on the Upgrades page).")
            other = self.db.one("SELECT v.name FROM vpn_sites s JOIN vpns v ON v.id = s.vpn_id WHERE s.device_id=? AND s.vpn_id IS NOT ?",
                                (d["id"], vpn_id))
            if other:
                raise VpnError(f"{d['name']} is already in the VPN \"{other['name']}\".")
            try:   # the router's own WireGuard interfaces (from the VPN inventory) must not already use this port
                inv = json.loads(d.get("vpn_inv") or "{}").get("/interface/wireguard", [])
            except ValueError:
                inv = []
            clash = next((w for w in inv if w.get("name") not in (VPN_IFACE,) and str(w.get("listen-port")) == str(port)), None)
            if clash:
                raise VpnError(f"UDP port {port} is already used on {d['name']} by \"{clash.get('name')}\" - pick a different port.")
            subs = []
            for x in s.get("subnets") or []:
                n = net(x)
                if n.prefixlen < 8:
                    raise VpnError(f"{n} is too large to route.")
                if n.overlaps(RESERVED):
                    raise VpnError(f"{n} ({d['name']}) overlaps TikManager's management network 10.77.0.0/16.")
                for (od, on) in seen:
                    if n.overlaps(on):
                        raise VpnError(f"{n} on {d['name']} overlaps {on} on {od} - sites need different subnets (renumber one of them).")
                subs.append(n)
            if not subs:
                raise VpnError(f"Pick at least one subnet for {d['name']}.")
            seen += [(d["name"], n) for n in subs]
            out.append({"device": d, "subnets": [str(n) for n in subs]})
        all_subs = [n for _, n in seen]
        tn = net(tunnel_net) if tunnel_net else net(self.free_tunnel_net(all_subs + [RESERVED]))
        if not 16 <= tn.prefixlen <= 28:
            raise VpnError("The tunnel network should be between /16 and /28 (a /24 is typical).")
        if tn.num_addresses - 2 < len(sites):
            raise VpnError("The tunnel network is too small for this many routers.")
        if tn.overlaps(RESERVED) or any(tn.overlaps(n) for n in all_subs):
            raise VpnError(f"The tunnel network {tn} overlaps a site subnet or TikManager's 10.77.0.0/16.")
        clash = next((v for v in self.db.q("SELECT name, tunnel_net FROM vpns WHERE id IS NOT ?", (vpn_id,)) if net(v["tunnel_net"]).overlaps(tn)), None)
        if clash:
            raise VpnError(f"The tunnel network {tn} is already used by the VPN \"{clash['name']}\".")
        hub = next(s["device"] for s in out if s["device"]["id"] == hub_id)
        ep = (endpoint or "").strip()
        if not ep:
            try:
                if hub["wan_ip"] and ipaddress.ip_address(hub["wan_ip"]).is_global:
                    ep = hub["wan_ip"]
            except ValueError:
                pass
        if not ep:
            raise VpnError(f"{hub['name']} has no public WAN address (it's behind NAT/CGNAT). Enter its public IP or DDNS name "
                           "(IP > Cloud) and forward the UDP port to it, or pick a different hub.")
        return out, str(tn), ep

    def save(self, vpn_id, org_id, name, hub_id, endpoint, port, tunnel_net, sites, user):
        norm, tn, _ = self.validate(org_id, sites, hub_id, endpoint, port, tunnel_net, vpn_id)
        now = time.time()
        if vpn_id:
            v = self.db.one("SELECT * FROM vpns WHERE id=?", (vpn_id,))
            if not v or v["org_id"] != org_id:
                raise VpnError("VPN not found.")
            if v["id"] in self.busy:
                raise VpnError("This VPN is being applied right now - try again in a minute.")
            self.db.run("UPDATE vpns SET name=?, hub_device_id=?, endpoint=?, port=?, tunnel_net=?, updated_at=? WHERE id=?",
                        (name, hub_id, endpoint or None, int(port), tn, now, vpn_id))
        else:
            vpn_id = self.db.run("""INSERT INTO vpns (org_id, name, hub_device_id, endpoint, port, tunnel_net, created_by, created_at, updated_at)
                                    VALUES (?,?,?,?,?,?,?,?,?)""", (org_id, name, hub_id, endpoint or None, int(port), tn, user, now, now))
        keep = {s["device"]["id"] for s in norm}
        # routers taken out of the VPN are cleaned up on the next apply
        self.db.run(f"UPDATE vpn_sites SET state='removing' WHERE vpn_id=? AND device_id NOT IN ({','.join('?' * len(keep))})", (vpn_id, *keep))
        hosts = list(net(tn).hosts())
        existing = {r["device_id"]: r for r in self.db.q("SELECT * FROM vpn_sites WHERE vpn_id=?", (vpn_id,))}
        order = [hub_id] + [s["device"]["id"] for s in norm if s["device"]["id"] != hub_id]
        taken = {r["tunnel_ip"] for r in existing.values() if r["device_id"] in keep and ipaddress.ip_address(r["tunnel_ip"]) in net(tn)}
        for did in order:
            subs = json.dumps(next(s["subnets"] for s in norm if s["device"]["id"] == did))
            want = str(hosts[0]) if did == hub_id else None
            row = existing.get(did)
            ip = row["tunnel_ip"] if row and ipaddress.ip_address(row["tunnel_ip"]) in net(tn) and (did == hub_id) == (row["tunnel_ip"] == str(hosts[0])) else None
            if not ip:
                ip = want or next(str(h) for h in hosts[1:] if str(h) not in taken)
                taken.add(ip)
            if row:
                self.db.run("UPDATE vpn_sites SET subnets=?, tunnel_ip=?, state=CASE WHEN state='removing' THEN 'pending' ELSE state END WHERE id=?",
                            (subs, ip, row["id"]))
            else:
                self.db.run("INSERT INTO vpn_sites (vpn_id, device_id, tunnel_ip, subnets) VALUES (?,?,?,?)", (vpn_id, did, ip, subs))
        return vpn_id

    # --- applying ---------------------------------------------------------------------------------------------
    def _site_err(self, site_id, msg):
        self.db.run("UPDATE vpn_sites SET state='failed', last_error=? WHERE id=?", (msg[:300], site_id))

    def apply(self, vpn_id, user):
        with self.lock:
            if vpn_id in self.busy:
                return False
            self.busy.add(vpn_id)
        self.db.run("UPDATE vpns SET status='applying', last_error=NULL WHERE id=?", (vpn_id,))
        threading.Thread(target=self._apply, args=(vpn_id, user), daemon=True, name=f"vpn-{vpn_id}").start()
        return True

    def _apply(self, vpn_id, user):
        v = self.db.one("SELECT * FROM vpns WHERE id=?", (vpn_id,))
        try:
            rows = self.db.q("""SELECT s.*, d.name, d.online, d.org_id, d.tunnel_ip AS mgmt_ip, d.wan_ip FROM vpn_sites s
                                JOIN devices d ON d.id = s.device_id WHERE s.vpn_id=?""", (vpn_id,))
            sites = [r for r in rows if r["state"] != "removing"]
            gone = [r for r in rows if r["state"] == "removing"]
            hub = next((r for r in sites if r["device_id"] == v["hub_device_id"]), None)
            if not hub:
                raise VpnError("The hub isn't part of this VPN any more - pick a hub.")
            _, _, endpoint = self.validate(v["org_id"], [{"device_id": r["device_id"], "subnets": json.loads(r["subnets"])} for r in sites],
                                           v["hub_device_id"], v["endpoint"], v["port"], v["tunnel_net"], vpn_id)
            offline = [r["name"] for r in sites + gone if not r["online"]]
            if offline:
                raise VpnError(f"Offline, so nothing was changed: {', '.join(offline)}.")
            for r in sites + gone:   # a restore point on every router first
                b = self.backups.run(r["device_id"], "pre-vpn", user or "vpn")
                if not b.get("ok"):
                    raise VpnError(f"Stopped before changing anything: backup of {r['name']} failed ({b.get('detail')}).")
            dev = lambda r: self.db.one("SELECT * FROM devices WHERE id=?", (r["device_id"],))
            prefix = ipaddress.ip_network(v["tunnel_net"]).prefixlen
            for r in sites:   # interfaces and keys
                r["pubkey"] = self.client_for(dev(r)).wg_ensure(VPN_IFACE, v["port"])
                self.db.run("UPDATE vpn_sites SET pubkey=? WHERE id=?", (r["pubkey"], r["id"]))
            spokes = [r for r in sites if r is not hub]
            subs = {r["id"]: json.loads(r["subnets"]) for r in sites}
            failures = []
            # hub: a peer per spoke (its tunnel address + its subnets), routes to every spoke subnet, the UDP port open
            try:
                self.client_for(dev(hub)).vpn_apply(VPN_IFACE, {
                    "address": f"{hub['tunnel_ip']}/{prefix}", "hub_port": v["port"],
                    "peers": [{"public-key": s["pubkey"], "allowed": [f"{s['tunnel_ip']}/32"] + subs[s["id"]]} for s in spokes],
                    "routes": [n for s in spokes for n in subs[s["id"]]]})
                self.db.run("UPDATE vpn_sites SET state='applied', last_error=NULL, applied_at=? WHERE id=?", (time.time(), hub["id"]))
            except RouterError as e:
                self._site_err(hub["id"], str(e))
                raise VpnError(f"The hub ({hub['name']}) couldn't be configured: {e}") from None
            # spokes: one peer (the hub) carrying the tunnel network and every other site's subnets
            for s in spokes:
                remote = subs[hub["id"]] + [n for o in spokes if o is not s for n in subs[o["id"]]]
                try:
                    self.client_for(dev(s)).vpn_apply(VPN_IFACE, {
                        "address": f"{s['tunnel_ip']}/{prefix}", "hub_port": None,
                        "peers": [{"public-key": hub["pubkey"], "allowed": [v["tunnel_net"]] + remote, "endpoint": endpoint, "port": v["port"]}],
                        "routes": remote})
                    self.db.run("UPDATE vpn_sites SET state='applied', last_error=NULL, applied_at=? WHERE id=?", (time.time(), s["id"]))
                except RouterError as e:
                    self._site_err(s["id"], str(e))
                    failures.append(f"{s['name']}: {e}")
            for g in gone:   # routers taken out of the VPN
                try:
                    self.client_for(dev(g)).vpn_clear(VPN_IFACE, remove_interface=True)
                    self.db.run("DELETE FROM vpn_sites WHERE id=?", (g["id"],))
                except RouterError as e:
                    failures.append(f"{g['name']} (removing): {e}")
            status = "failed" if failures else "active"
            self.db.run("UPDATE vpns SET status=?, last_error=?, last_applied=? WHERE id=?",
                        (status, "; ".join(failures)[:500] or None, time.time(), vpn_id))
            for r in sites:
                self.db.event(r["device_id"], r["org_id"], "vpn applied", f"{v['name']} ({'hub' if r is hub else 'spoke'})")
            self.db.audit(user, f"vpn applied ({status})", v["name"], org_id=v["org_id"], detail="; ".join(failures))
        except VpnError as e:
            self.db.run("UPDATE vpns SET status='failed', last_error=? WHERE id=?", (str(e)[:500], vpn_id))
            self.db.audit(user, "vpn apply failed", v["name"] if v else vpn_id, org_id=v["org_id"] if v else None, detail=str(e))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.db.run("UPDATE vpns SET status='failed', last_error=? WHERE id=?", (f"Error: {e}"[:500], vpn_id))
        finally:
            with self.lock:
                self.busy.discard(vpn_id)

    def disable(self, vpn_id, user, delete=False):
        """Remove the VPN from every router (only what TikManager added). Runs in the background."""
        with self.lock:
            if vpn_id in self.busy:
                return False
            self.busy.add(vpn_id)
        self.db.run("UPDATE vpns SET status='applying' WHERE id=?", (vpn_id,))

        def run():
            v = self.db.one("SELECT * FROM vpns WHERE id=?", (vpn_id,))
            failures = []
            try:
                for r in self.db.q("SELECT s.*, d.name, d.online FROM vpn_sites s JOIN devices d ON d.id = s.device_id WHERE s.vpn_id=?", (vpn_id,)):
                    try:
                        self.client_for(self.db.one("SELECT * FROM devices WHERE id=?", (r["device_id"],))).vpn_clear(VPN_IFACE, remove_interface=True)
                        self.db.run("UPDATE vpn_sites SET state='pending', handshake_age=NULL, ping_ms=NULL, last_error=NULL WHERE id=?", (r["id"],))
                    except RouterError as e:
                        failures.append(f"{r['name']}: {e}")
                        self._site_err(r["id"], str(e))
                if delete and not failures:
                    self.db.run("DELETE FROM vpns WHERE id=?", (vpn_id,))
                else:
                    self.db.run("UPDATE vpns SET status=?, last_error=? WHERE id=?",
                                ("failed" if failures else "disabled", "; ".join(failures)[:500] or None, vpn_id))
                self.db.audit(user, "vpn deleted" if delete and not failures else "vpn disabled", v["name"], org_id=v["org_id"], detail="; ".join(failures))
            finally:
                with self.lock:
                    self.busy.discard(vpn_id)
        threading.Thread(target=run, daemon=True, name=f"vpn-off-{vpn_id}").start()
        return True

    # --- status -----------------------------------------------------------------------------------------------
    def check(self, vpn_id):
        v = self.db.one("SELECT * FROM vpns WHERE id=?", (vpn_id,))
        rows = self.db.q("SELECT s.*, d.online FROM vpn_sites s JOIN devices d ON d.id = s.device_id WHERE s.vpn_id=? AND s.state='applied'", (vpn_id,))
        hub = next((r for r in rows if r["device_id"] == v["hub_device_id"]), None)
        for r in rows:
            age = ping = rx = tx = None
            if r["online"]:
                try:
                    cl = self.client_for(self.db.one("SELECT * FROM devices WHERE id=?", (r["device_id"],)))
                    peers = cl.wg_peers(VPN_IFACE)
                    if r is hub:   # the hub's freshest handshake (any spoke)
                        ages = [p["handshake_age"] for p in peers if p["handshake_age"] is not None]
                        age = min(ages) if ages else None
                        rx, tx = sum(p["rx"] for p in peers), sum(p["tx"] for p in peers)
                    else:
                        p = next((p for p in peers if hub and p["public_key"] == hub["pubkey"]), None)
                        if p:
                            age, rx, tx = p["handshake_age"], p["rx"], p["tx"]
                        if hub and age is not None and age < UP_SECONDS:
                            ping, loss = cl.ping(hub["tunnel_ip"], 2)
                            if loss == 100:
                                ping = None
                except RouterError:
                    pass
            self.db.run("UPDATE vpn_sites SET handshake_age=?, ping_ms=?, rx=?, tx=?, checked_at=? WHERE id=?", (age, ping, rx, tx, time.time(), r["id"]))

    def loop(self):
        while True:
            time.sleep(60)
            try:
                for v in self.db.q("SELECT id FROM vpns WHERE status IN ('active','failed')"):
                    if v["id"] not in self.busy:
                        self.check(v["id"])
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self):
        # applies interrupted by a restart: mark them so the tech re-applies (re-applying is safe - it replaces everything)
        self.db.run("UPDATE vpns SET status='failed', last_error='TikManager restarted while applying - apply again.' WHERE status='applying'")
        threading.Thread(target=self.loop, daemon=True, name="vpns").start()
