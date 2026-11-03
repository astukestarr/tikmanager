"""WireGuard Builder wizard (Wizards > WireGuard Builder): a guided point-to-point tunnel between two of a client's
routers - a hub and a client router.

Unlike the fully-managed site-to-site VPN (vpn.py), this builder is flexible, the way a network engineer would wire a
tunnel by hand:
- the hub end can be a brand-new interface the builder creates, or an EXISTING WireGuard interface already on the hub
  (the builder then only adds a peer, routes and firewall rules - it never touches the interface, its address or port);
- the tech chooses the interface names, listen port, tunnel addresses and which subnets each side advertises, including
  downstream subnets behind another router (the builder warns that those routers may need their own return route);
- routing is static for now (BGP is planned).

Each build is tracked and owned: everything the builder writes on a router carries the comment "TikManager WG #<id>",
so a build can be removed exactly, and two independent builds never touch each other or anything made by hand. Both
routers are backed up before anything changes.
"""
import ipaddress
import json
import threading
import time
import traceback

from routeros import WGB_TAG, RouterError

RESERVED = ipaddress.ip_network("10.77.0.0/16")   # TikManager's management tunnel
UP_SECONDS = 180


class WgError(ValueError):
    pass


def net(s):
    try:
        return ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError:
        raise WgError(f"{s!r} isn't a valid subnet (example: 192.168.10.0/24).") from None


def iface_addr(s):
    """Parse a tunnel address written as CIDR (10.80.0.1/24). Returns (ip_address, prefixlen, network)."""
    try:
        ifc = ipaddress.ip_interface(str(s).strip())
    except ValueError:
        raise WgError(f"{s!r} isn't a valid tunnel address with a prefix (example: 10.80.0.1/24).") from None
    return ifc.ip, ifc.network.prefixlen, ifc.network


def tag_for(build_id):
    return f"{WGB_TAG} #{build_id}"


class WgBuilds:
    def __init__(self, db, client_for, backups):
        self.db, self.client_for, self.backups = db, client_for, backups
        self.busy = set()
        self.lock = threading.Lock()

    # --- validation / saving ----------------------------------------------------------------------------------
    def _dev(self, device_id, org_id, label):
        """org_id None = any client's router (the client end may be a different client from the hub)."""
        d = self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))
        if not d or d["state"] != "adopted" or (org_id is not None and d["org_id"] != org_id):
            raise WgError(f"The {label} must be an approved router" + (" of this client." if org_id is not None else "."))
        major = (d["version"] or "7").split(".")[0]
        if major.isdigit() and int(major) < 7:
            raise WgError(f"{d['name']} runs RouterOS {d['version']} - WireGuard needs RouterOS 7 (upgrade it first on the Upgrades page).")
        return d

    def validate(self, b):
        """b is the submitted build (see save). Returns a normalized dict or raises WgError."""
        org_id = b["org_id"]
        if b["hub_device_id"] == b["client_device_id"]:
            raise WgError("The hub and the client must be two different routers.")
        hub = self._dev(b["hub_device_id"], org_id, "hub")
        client = self._dev(b["client_device_id"], None, "client router")   # the client end may belong to a different client
        hub_name = (b.get("hub_iface") or "").strip()
        client_name = (b.get("client_iface") or "").strip()
        if not hub_name or not client_name:
            raise WgError("Give both the hub and the client WireGuard interface a name.")

        hub_ip, prefix, tunnel_net = iface_addr(b["hub_tunnel_ip"])
        client_ip, cprefix, cnet = iface_addr(b["client_tunnel_ip"])
        if cprefix != prefix or cnet != tunnel_net:
            raise WgError(f"The client's tunnel address must be in the same subnet as the hub's ({tunnel_net}, /{prefix}).")
        if client_ip == hub_ip:
            raise WgError("The hub and the client need different tunnel addresses.")
        if not 16 <= prefix <= 30:
            raise WgError("The tunnel address prefix should be between /16 and /30 (a /24 is typical).")
        if tunnel_net.overlaps(RESERVED):
            raise WgError(f"The tunnel network {tunnel_net} overlaps TikManager's management network 10.77.0.0/16 - pick another.")

        port = int(b.get("port") or 13232)
        if not 1 <= port <= 65535:
            raise WgError("The WireGuard UDP port must be 1-65535.")
        # a new hub interface must not clash with the hub's existing WireGuard interfaces (from the VPN inventory)
        if not b.get("hub_iface_existing"):
            self._port_free(hub, hub_name, port)

        hub_subs = self._subnets(b.get("hub_subnets") or [], hub["name"], tunnel_net)
        client_subs = self._subnets(b.get("client_subnets") or [], client["name"], tunnel_net)
        for h in hub_subs:
            for c in client_subs:
                if h.overlaps(c):
                    raise WgError(f"{h} (hub) overlaps {c} (client) - the two ends can't advertise the same range. Renumber one side.")
        if not hub_subs and not client_subs:
            raise WgError("Choose at least one subnet for one of the ends to reach over the tunnel.")

        routing = (b.get("routing") or "static").strip()
        if routing != "static":
            raise WgError("BGP routing isn't available yet - choose Static routes.")

        ep = (b.get("endpoint") or "").strip()
        if not ep:
            try:
                if hub["wan_ip"] and ipaddress.ip_address(hub["wan_ip"]).is_global:
                    ep = hub["wan_ip"]
            except ValueError:
                pass
        if not ep:
            raise WgError(f"{hub['name']} has no public WAN address (it's behind NAT/CGNAT). Enter its public IP or DDNS name "
                          "(IP > Cloud) and forward the UDP port to it, or pick a different hub.")
        return {"hub": hub, "client": client, "hub_name": hub_name, "client_name": client_name,
                "hub_ip": str(hub_ip), "client_ip": str(client_ip), "prefix": prefix, "tunnel_net": str(tunnel_net),
                "port": port, "endpoint": ep, "hub_subs": [str(n) for n in hub_subs], "client_subs": [str(n) for n in client_subs]}

    def _subnets(self, raw, who, tunnel_net):
        out = []
        for x in raw:
            n = net(x)
            if n.prefixlen < 8:
                raise WgError(f"{n} is too large to route.")
            if n.overlaps(RESERVED):
                raise WgError(f"{n} ({who}) overlaps TikManager's management network 10.77.0.0/16.")
            if n.overlaps(tunnel_net):
                raise WgError(f"{n} ({who}) overlaps the tunnel network {tunnel_net} - advertise the LAN behind the router, not the tunnel itself.")
            out.append(n)
        return out

    def _port_free(self, dev, iface_name, port):
        try:
            inv = json.loads(dev.get("vpn_inv") or "{}").get("/interface/wireguard", [])
        except ValueError:
            inv = []
        clash = next((w for w in inv if w.get("name") != iface_name and str(w.get("listen-port")) == str(port)), None)
        if clash:
            raise WgError(f"UDP port {port} is already used on {dev['name']} by the interface \"{clash.get('name')}\" - pick a different port.")

    def save(self, build_id, b, user):
        v = self.validate(b)
        now = time.time()
        fields = (b["org_id"], b.get("name") or "WireGuard tunnel", v["hub"]["id"], v["hub_name"], 1 if b.get("hub_iface_existing") else 0,
                  v["hub_ip"], b.get("hub_pubkey") or None, v["client"]["id"], v["client_name"], v["client_ip"], v["tunnel_net"],
                  v["endpoint"], v["port"], json.dumps(v["hub_subs"]), json.dumps(v["client_subs"]), "static")
        if build_id:
            row = self.db.one("SELECT * FROM wg_builds WHERE id=?", (build_id,))
            if not row or row["org_id"] != b["org_id"]:
                raise WgError("This build no longer exists.")
            if row["id"] in self.busy:
                raise WgError("This build is being applied right now - try again in a minute.")
            self.db.run("""UPDATE wg_builds SET org_id=?, name=?, hub_device_id=?, hub_iface=?, hub_iface_existing=?, hub_tunnel_ip=?,
                           hub_pubkey=COALESCE(?, hub_pubkey), client_device_id=?, client_iface=?, client_tunnel_ip=?, tunnel_net=?,
                           endpoint=?, port=?, hub_subnets=?, client_subnets=?, routing=?, updated_at=? WHERE id=?""",
                        (*fields, now, build_id))
            return build_id
        return self.db.run("""INSERT INTO wg_builds (org_id, name, hub_device_id, hub_iface, hub_iface_existing, hub_tunnel_ip, hub_pubkey,
                              client_device_id, client_iface, client_tunnel_ip, tunnel_net, endpoint, port, hub_subnets, client_subnets, routing,
                              created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                           (*fields, user, now, now))

    # --- applying ---------------------------------------------------------------------------------------------
    def apply(self, build_id, user):
        with self.lock:
            if build_id in self.busy:
                return False
            self.busy.add(build_id)
        self.db.run("UPDATE wg_builds SET status='applying', last_error=NULL WHERE id=?", (build_id,))
        threading.Thread(target=self._apply, args=(build_id, user), daemon=True, name=f"wgb-{build_id}").start()
        return True

    def _apply(self, build_id, user):
        row = self.db.one("SELECT * FROM wg_builds WHERE id=?", (build_id,))
        tag = tag_for(build_id)
        try:
            b = {"org_id": row["org_id"], "name": row["name"], "hub_device_id": row["hub_device_id"], "hub_iface": row["hub_iface"],
                 "hub_iface_existing": row["hub_iface_existing"], "hub_tunnel_ip": f"{row['hub_tunnel_ip']}/{net(row['tunnel_net']).prefixlen}",
                 "hub_pubkey": row["hub_pubkey"], "client_device_id": row["client_device_id"], "client_iface": row["client_iface"],
                 "client_tunnel_ip": f"{row['client_tunnel_ip']}/{net(row['tunnel_net']).prefixlen}", "port": row["port"],
                 "endpoint": row["endpoint"], "hub_subnets": json.loads(row["hub_subnets"]), "client_subnets": json.loads(row["client_subnets"]),
                 "routing": row["routing"]}
            v = self.validate(b)
            hub, client = v["hub"], v["client"]
            offline = [d["name"] for d in (hub, client) if not d["online"]]
            if offline:
                raise WgError(f"Offline, so nothing was changed: {', '.join(offline)}.")
            for d in (hub, client):   # a restore point on each router first
                r = self.backups.run(d["id"], "pre-wg", user or "wg-builder")
                if not r.get("ok"):
                    raise WgError(f"Stopped before changing anything: backup of {d['name']} failed ({r.get('detail')}).")

            hub_cl, client_cl = self.client_for(hub), self.client_for(client)
            # client interface always created by the builder; its public key is needed for the hub's peer
            client_pub = client_cl.wg_ensure(v["client_name"], v["port"], tag=tag)
            if row["hub_iface_existing"]:
                live = next((w for w in hub_cl.wg_list() if w["name"] == v["hub_name"]), None)
                if not live:
                    raise WgError(f"The hub interface \"{v['hub_name']}\" isn't on {hub['name']} any more - re-run the wizard and pick again.")
                hub_pub = live["public_key"]
            else:
                hub_pub = hub_cl.wg_ensure(v["hub_name"], v["port"], tag=tag)
            if not hub_pub or not client_pub:
                raise WgError("A router didn't report its WireGuard public key - try applying again.")

            prefix = v["prefix"]
            # hub: peer = the client (its tunnel /32 + its subnets), routes to the client's subnets, the UDP port open
            hub_cl.wgb_apply(v["hub_name"], {
                "address": None if row["hub_iface_existing"] else f"{v['hub_ip']}/{prefix}", "port": v["port"],
                "peer": {"public-key": client_pub, "name": client["name"], "allowed": [f"{v['client_ip']}/32"] + v["client_subs"]},
                "routes": v["client_subs"], "open_port": True}, tag, create_iface=not row["hub_iface_existing"])
            # client: peer = the hub (the tunnel network + the hub's subnets, with the hub's public endpoint), routes to them
            client_cl.wgb_apply(v["client_name"], {
                "address": f"{v['client_ip']}/{prefix}", "port": v["port"],
                "peer": {"public-key": hub_pub, "name": hub["name"], "allowed": [v["tunnel_net"]] + v["hub_subs"], "endpoint": v["endpoint"], "port": v["port"]},
                "routes": v["hub_subs"], "open_port": False}, tag, create_iface=True)

            self.db.run("UPDATE wg_builds SET status='active', last_error=NULL, hub_pubkey=?, client_pubkey=?, last_applied=? WHERE id=?",
                        (hub_pub, client_pub, time.time(), build_id))
            self.db.event(hub["id"], hub["org_id"], "wg build applied", f"{row['name']} (hub {v['hub_name']})")
            self.db.event(client["id"], client["org_id"], "wg build applied", f"{row['name']} (client {v['client_name']})")
            self.db.audit(user, "wg build applied", row["name"], org_id=row["org_id"])
        except (WgError, RouterError) as e:
            self.db.run("UPDATE wg_builds SET status='failed', last_error=? WHERE id=?", (str(e)[:500], build_id))
            self.db.audit(user, "wg build apply failed", row["name"] if row else build_id, org_id=row["org_id"] if row else None, detail=str(e))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.db.run("UPDATE wg_builds SET status='failed', last_error=? WHERE id=?", (f"Error: {e}"[:500], build_id))
        finally:
            with self.lock:
                self.busy.discard(build_id)

    def disable(self, build_id, user, delete=False):
        """Remove the build from both routers (only what it added - matched by its tag), then mark it disabled or delete it."""
        with self.lock:
            if build_id in self.busy:
                return False
            self.busy.add(build_id)
        self.db.run("UPDATE wg_builds SET status='applying' WHERE id=?", (build_id,))

        def run():
            row = self.db.one("SELECT * FROM wg_builds WHERE id=?", (build_id,))
            tag = tag_for(build_id)
            failures = []
            try:
                for side, dev_id, iface, created in (("hub", row["hub_device_id"], row["hub_iface"], not row["hub_iface_existing"]),
                                                     ("client", row["client_device_id"], row["client_iface"], True)):
                    d = self.db.one("SELECT * FROM devices WHERE id=?", (dev_id,)) if dev_id else None
                    if not d:
                        continue
                    try:
                        self.client_for(d).wgb_clear(tag, iface, remove_interface=created)
                    except RouterError as e:
                        failures.append(f"{d['name']}: {e}")
                if delete and not failures:
                    self.db.run("DELETE FROM wg_builds WHERE id=?", (build_id,))
                else:
                    self.db.run("UPDATE wg_builds SET status=?, last_error=?, hub_hs=NULL, client_hs=NULL, ping_ms=NULL WHERE id=?",
                                ("failed" if failures else "disabled", "; ".join(failures)[:500] or None, build_id))
                self.db.audit(user, "wg build deleted" if delete and not failures else "wg build disabled", row["name"],
                              org_id=row["org_id"], detail="; ".join(failures))
            finally:
                with self.lock:
                    self.busy.discard(build_id)
        threading.Thread(target=run, daemon=True, name=f"wgb-off-{build_id}").start()
        return True

    # --- status -----------------------------------------------------------------------------------------------
    def check(self, build_id):
        row = self.db.one("SELECT * FROM wg_builds WHERE id=?", (build_id,))
        if not row or row["status"] not in ("active", "failed"):
            return
        hub_hs = client_hs = ping = None
        for side in ("hub", "client"):
            dev_id, iface, want = (row[f"{side}_device_id"], row[f"{side}_iface"],
                                   row["client_pubkey"] if side == "hub" else row["hub_pubkey"])
            d = self.db.one("SELECT * FROM devices WHERE id=?", (dev_id,)) if dev_id else None
            if not d or not d["online"] or not want:
                continue
            try:
                cl = self.client_for(d)
                p = next((x for x in cl.wg_peers(iface) if x["public_key"] == want), None)
                age = p["handshake_age"] if p else None
                if side == "hub":
                    hub_hs = age
                else:
                    client_hs = age
                    if age is not None and age < UP_SECONDS and row["hub_tunnel_ip"]:
                        try:
                            ms, loss = cl.ping(row["hub_tunnel_ip"], 2)
                            ping = ms if loss != 100 else None
                        except RouterError:
                            pass
            except RouterError:
                pass
        self.db.run("UPDATE wg_builds SET hub_hs=?, client_hs=?, ping_ms=?, checked_at=? WHERE id=?",
                    (hub_hs, client_hs, ping, time.time(), build_id))

    def loop(self):
        while True:
            time.sleep(60)
            try:
                for v in self.db.q("SELECT id FROM wg_builds WHERE status IN ('active','failed')"):
                    if v["id"] not in self.busy:
                        self.check(v["id"])
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self):
        # applies interrupted by a restart: mark them so the tech re-applies (re-applying is safe - it replaces everything)
        self.db.run("UPDATE wg_builds SET status='failed', last_error='TikManager restarted while applying - apply again.' WHERE status='applying'")
        threading.Thread(target=self.loop, daemon=True, name="wg-builds").start()
