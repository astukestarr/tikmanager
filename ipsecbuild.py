"""IPsec Tunnel wizard (Router Wizard > IPsec Tunnel): a policy-based site-to-site IPsec tunnel from one of a client's
MikroTik routers to an **any-brand** far end (Fortinet, Cisco, SonicWall, pfSense, ...).

MikroTik-to-MikroTik tunnels should use the WireGuard Builder; this wizard is for the case where the other end isn't a
MikroTik (or isn't managed by TikManager). It is therefore one-sided: TikManager configures only the local MikroTik and
hands the technician the matching parameters (including the pre-shared key) to configure the far end by hand.

Everything the wizard writes on the local router carries the comment "TikManager IPsec #<id>", so a build removes
exactly what it added. The pre-shared key is generated here, sealed with the vault, and only ever shown to a technician
on an explicit reveal - never stored or returned in plain text otherwise.
"""
import ipaddress
import json
import re
import secrets
import threading
import time
import traceback

from routeros import IPSEC_TAG, RouterError

# Modern, broadly-compatible defaults (editable in the wizard's Advanced section). RouterOS value names.
DEFAULTS = {"ike": "ike2", "p1_enc": "aes-256", "p1_hash": "sha256", "p1_dh": "modp2048", "p1_life": "1d",
            "p2_enc": "aes-256-cbc", "p2_auth": "sha256", "pfs": "modp2048", "p2_life": "30m"}
CRYPTO_KEYS = ("p1_enc", "p1_hash", "p1_dh", "p1_life", "p2_enc", "p2_auth", "pfs", "p2_life")


class IpsecError(ValueError):
    pass


def net(s):
    try:
        return ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError:
        raise IpsecError(f"{s!r} isn't a valid subnet (example: 192.168.10.0/24).") from None


def as_ip(s):
    """The address if it's a plain IP (for firewall src-address), else None (a DNS name - RouterOS resolves it on the peer)."""
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return None


def host_ip(s):
    """A single IP address (for a 1:1 host mapping), or raise."""
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        raise IpsecError(f"{s!r} isn't a valid IP address.") from None


def tag_for(build_id):
    return f"{IPSEC_TAG} #{build_id}"


class IpsecBuilds:
    def __init__(self, db, client_for, backups, vault):
        self.db, self.client_for, self.backups, self.vault = db, client_for, backups, vault
        self.busy = set()
        self.lock = threading.Lock()

    # --- validation / saving ----------------------------------------------------------------------------------
    def validate(self, b):
        d = self.db.one("SELECT * FROM devices WHERE id=?", (b.get("device_id"),))
        if not d or d["org_id"] != b["org_id"] or d["state"] != "adopted":
            raise IpsecError("The local router must be an approved router of this client.")
        major = (d["version"] or "7").split(".")[0]
        if major.isdigit() and int(major) < 7:
            raise IpsecError(f"{d['name']} runs RouterOS {d['version']} - this wizard needs RouterOS 7.")
        remote = (b.get("remote_addr") or "").strip()
        if not remote:
            raise IpsecError("Enter the far end's public IP address or DNS name.")
        local = self._subnets(b.get("local_subnets") or [], "local")
        far = self._subnets(b.get("remote_subnets") or [], "remote")
        if not far:
            raise IpsecError("Add at least one remote subnet.")
        nat, advertised = self._nat(b.get("local_nat") or [], local, far)   # 1:1 NAT; advertised = what the far end sees (policy src)
        if not advertised:
            raise IpsecError("Add at least one local subnet, or a 1:1 NAT mapping.")
        for a in advertised:   # nothing advertised to the far end may collide with its subnets
            for c in far:
                if a.overlaps(c):
                    raise IpsecError(f"{a} (seen by the far end) overlaps {c} (remote) - they must be different ranges.")
        ike = (b.get("ike") or "ike2").strip()
        if ike not in ("ike2", "ike"):
            raise IpsecError("IKE version must be IKEv2 or IKEv1.")
        crypto = {k: (b.get(k) or DEFAULTS[k]).strip() for k in CRYPTO_KEYS}
        for k, val in crypto.items():
            if not val or not all(ch.isalnum() or ch in "-_," for ch in val):
                raise IpsecError(f"{k} has an invalid value.")
        for k in ("p1_life", "p2_life"):   # a RouterOS time string, e.g. 8h, 1d, 30m, 1h30m
            if not re.fullmatch(r"(\d+[smhdw])+|\d+", crypto[k]):
                raise IpsecError(f"Lifetime {crypto[k]!r} isn't valid - use a time like 8h, 1d or 30m.")
        ident = self._identity(b)
        return {"device": d, "remote": remote, "ike": ike, "nat": nat, **ident,
                "local": [str(n) for n in local], "far": [str(n) for n in far], **crypto}

    def _identity(self, b):
        """Validate the IKE identities. my-id: auto/address/fqdn/user-fqdn/key-id; remote-id: auto/fqdn/user-fqdn/key-id/
        ignore (no 'address'). Returns the stored type/value for each (empty type means auto)."""
        mt = (b.get("my_id_type") or "auto").strip()
        mv = (b.get("my_id") or "").strip()
        rt = (b.get("remote_id_type") or "auto").strip()
        rv = (b.get("remote_id") or "").strip()
        if mt not in ("auto", "address", "fqdn", "user-fqdn", "key-id"):
            raise IpsecError("My ID type must be auto, address, FQDN, user-FQDN or key-id.")
        if rt not in ("auto", "fqdn", "user-fqdn", "key-id", "ignore"):
            raise IpsecError("Remote ID type must be auto, FQDN, user-FQDN, key-id or ignore (not address).")
        if mt == "address" and as_ip(mv) is None:
            raise IpsecError("My ID is set to an address, so enter a valid IP (e.g. your public IP when behind NAT).")
        if mt in ("fqdn", "user-fqdn", "key-id") and not mv:
            raise IpsecError("Enter the My ID value.")
        if rt in ("fqdn", "user-fqdn", "key-id") and not rv:
            raise IpsecError("Enter the Remote ID value.")
        return {"my_id_type": mt, "my_id": mv if mt != "auto" else "",
                "remote_id_type": rt, "remote_id": rv if rt in ("fqdn", "user-fqdn", "key-id") else ""}

    def _nat(self, raw, local, far):
        """Validate the 1:1 NAT entries. Returns (normalized nat list, advertised networks) - advertised is what the far
        end negotiates/sees: the plain local subnets plus every mapped subnet and mapped host /32."""
        nat, advertised = [], list(local)
        for e in raw:
            mode = (e.get("mode") or "").strip()
            if mode == "netmap":
                real, mapped = net(e.get("real")), net(e.get("mapped"))
                if real.prefixlen != mapped.prefixlen:
                    raise IpsecError(f"1:1 NAT: the real ({real}) and mapped ({mapped}) subnets must be the same size.")
                for p in local:
                    if mapped.overlaps(p):
                        raise IpsecError(f"1:1 NAT: the mapped subnet {mapped} overlaps your local subnet {p} - pick a free range.")
                nat.append({"mode": "netmap", "real": str(real), "mapped": str(mapped)})
                advertised.append(mapped)
            elif mode == "hosts":
                hosts, seen = [], set()
                for h in e.get("hosts") or []:
                    m, r = host_ip(h.get("mapped")), host_ip(h.get("real"))
                    if m in seen:
                        raise IpsecError(f"1:1 NAT: the mapped address {m} is listed twice.")
                    seen.add(m)
                    hosts.append({"mapped": m, "real": r})
                    advertised.append(ipaddress.ip_network(m + "/32"))
                if not hosts:
                    raise IpsecError("A 1:1 NAT host mapping needs at least one address pair.")
                nat.append({"mode": "hosts", "hosts": hosts})
            else:
                raise IpsecError("Unknown 1:1 NAT mode.")
        return nat, advertised

    def _subnets(self, raw, who):
        out = []
        for x in raw:
            n = net(x)
            if n.prefixlen < 8:
                raise IpsecError(f"{n} ({who}) is too large.")
            out.append(n)
        return out

    def _seal_psk(self, build_id, psk):
        blob, alg = self.vault.seal(psk.encode(), f"ipsec:{build_id}")
        self.db.run("UPDATE ipsec_builds SET psk_blob=?, psk_alg=? WHERE id=?", (blob, alg, build_id))

    def save(self, build_id, b, user):
        v = self.validate(b)
        now = time.time()
        psk = (b.get("psk") or "").strip()   # the tech can set the key in the wizard; blank keeps the existing one (edit) or auto-generates (new)
        fields = (b["org_id"], b.get("name") or "IPsec tunnel", v["device"]["id"], v["remote"], v["ike"],
                  v["p1_enc"], v["p1_hash"], v["p1_dh"], v["p1_life"], v["p2_enc"], v["p2_auth"], v["pfs"], v["p2_life"],
                  json.dumps(v["local"]), json.dumps(v["far"]), json.dumps(v["nat"]),
                  v["my_id_type"], v["my_id"], v["remote_id_type"], v["remote_id"])
        if build_id:
            row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
            if not row or row["org_id"] != b["org_id"]:
                raise IpsecError("This tunnel no longer exists.")
            if row["id"] in self.busy:
                raise IpsecError("This tunnel is being applied right now - try again in a minute.")
            self.db.run("""UPDATE ipsec_builds SET org_id=?, name=?, device_id=?, remote_addr=?, ike=?, p1_enc=?, p1_hash=?,
                           p1_dh=?, p1_life=?, p2_enc=?, p2_auth=?, pfs=?, p2_life=?, local_subnets=?, remote_subnets=?, local_nat=?,
                           my_id_type=?, my_id=?, remote_id_type=?, remote_id=?, updated_at=? WHERE id=?""",
                        (*fields, now, build_id))
            if psk:
                self._seal_psk(build_id, psk)
            return build_id
        bid = self.db.run("""INSERT INTO ipsec_builds (org_id, name, device_id, remote_addr, ike, p1_enc, p1_hash, p1_dh, p1_life,
                             p2_enc, p2_auth, pfs, p2_life, local_subnets, remote_subnets, local_nat,
                             my_id_type, my_id, remote_id_type, remote_id, created_by, created_at, updated_at)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*fields, user, now, now))
        self._seal_psk(bid, psk or secrets.token_urlsafe(24))   # the wizard supplies a key; fall back to a strong random one
        return bid

    def reveal_psk(self, build_id):
        row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
        if not row or not row["psk_blob"]:
            return None
        return self.vault.open(row["psk_blob"], row["psk_alg"], f"ipsec:{build_id}").decode()

    # --- importing an existing tunnel (adopt in place) --------------------------------------------------------
    def adopt(self, b, user):
        """Import an existing IPsec peer on a client's router into the wizard: read its config live, insert a managed row
        (adopted, active), then tag the peer/identity/policies so it shows in the wizard and can be disabled/deleted. The
        pre-shared key is not read - a re-apply (edit) is blocked until the tech enters it. Nothing on the router changes
        except those objects' comments, so the running tunnel is untouched."""
        d = self.db.one("SELECT * FROM devices WHERE id=?", (b.get("device_id"),))
        if not d or d["org_id"] != b["org_id"] or d["state"] != "adopted":
            raise IpsecError("The local router must be an approved router of this client.")
        if not d["online"]:
            raise IpsecError(f"{d['name']} is offline - importing needs to read the tunnel from the router.")
        peer_name = (b.get("peer_name") or "").strip()
        if not peer_name:
            raise IpsecError("Pick an existing IPsec tunnel to import.")
        rd = self.client_for(d).ipsec_adopt_read(peer_name)
        if not rd.get("remote_subnets") or not rd.get("local_subnets"):
            raise IpsecError("That tunnel has no usable IPsec policies to import.")
        now = time.time()
        name = (b.get("name") or f"IPsec: {peer_name}").strip()[:80]
        psk = (b.get("psk") or "").strip()
        bid = self.db.run("""INSERT INTO ipsec_builds (org_id, name, device_id, remote_addr, ike, p1_enc, p1_hash, p1_dh, p1_life,
                             p2_enc, p2_auth, pfs, p2_life, local_subnets, remote_subnets, local_nat,
                             my_id_type, my_id, remote_id_type, remote_id, status, adopted, created_by, created_at, updated_at, last_applied)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',1,?,?,?,?)""",
                          (b["org_id"], name, d["id"], rd["remote_addr"], rd["ike"],
                           rd["p1"]["enc"], rd["p1"]["hash"], rd["p1"]["dh"], rd["p1"]["life"],
                           rd["p2"]["enc"], rd["p2"]["auth"], rd["p2"]["pfs"], rd["p2"]["life"],
                           json.dumps(rd["local_subnets"]), json.dumps(rd["remote_subnets"]), "[]",
                           rd["my_id_type"], rd["my_id"], rd["remote_id_type"], rd["remote_id"], user, now, now, now))
        if psk:
            self._seal_psk(bid, psk)
        try:
            self.client_for(d).tag_objects(rd["ids"], tag_for(bid))
        except RouterError as e:
            self.db.run("UPDATE ipsec_builds SET status='failed', last_error=? WHERE id=?", (f"Imported, but tagging it failed: {e}"[:500], bid))
        self.db.event(d["id"], d["org_id"], "ipsec tunnel imported", f"{name} <- {peer_name}")
        self.db.audit(user, "ipsec tunnel imported", name, org_id=b["org_id"], detail=f"peer {peer_name}")
        return bid

    # --- applying ---------------------------------------------------------------------------------------------
    def apply(self, build_id, user):
        row = self.db.one("SELECT adopted, psk_blob FROM ipsec_builds WHERE id=?", (build_id,))
        if row and row["adopted"] and not row["psk_blob"]:
            raise IpsecError("This tunnel was imported, so TikManager doesn't have its pre-shared key. Edit it and enter "
                             "the key first - re-applying rebuilds the tunnel under the wizard's own settings.")
        with self.lock:
            if build_id in self.busy:
                return False
            self.busy.add(build_id)
        self.db.run("UPDATE ipsec_builds SET status='applying', last_error=NULL WHERE id=?", (build_id,))
        threading.Thread(target=self._apply, args=(build_id, user), daemon=True, name=f"ipsec-{build_id}").start()
        return True

    def _apply(self, build_id, user):
        row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
        tag = tag_for(build_id)
        try:
            d = self.db.one("SELECT * FROM devices WHERE id=?", (row["device_id"],)) if row["device_id"] else None
            if not d:
                raise IpsecError("The local router is no longer part of this client.")
            if not d["online"]:
                raise IpsecError(f"{d['name']} is offline, so nothing was changed.")
            r = self.backups.run(d["id"], "pre-ipsec", user or "ipsec-wizard")
            if not r.get("ok"):
                raise IpsecError(f"Stopped before changing anything: backup of {d['name']} failed ({r.get('detail')}).")
            cfg = {"name": f"tm-ipsec-{build_id}", "remote_addr": row["remote_addr"], "remote_ip": as_ip(row["remote_addr"]),
                   "exchange": "ike2" if row["ike"] == "ike2" else "main",
                   "p1": {"enc": row["p1_enc"], "hash": row["p1_hash"], "dh": row["p1_dh"], "life": row["p1_life"]},
                   "p2": {"enc": row["p2_enc"], "auth": row["p2_auth"], "pfs": row["pfs"], "life": row["p2_life"]},
                   "local_subnets": json.loads(row["local_subnets"]), "remote_subnets": json.loads(row["remote_subnets"]),
                   "nat": json.loads(row["local_nat"] or "[]"),
                   "my_id": (f"{row['my_id_type']}:{row['my_id']}" if row["my_id_type"] and row["my_id_type"] != "auto" and row["my_id"] else ""),
                   "remote_id": ("ignore" if row["remote_id_type"] == "ignore" else
                                 f"{row['remote_id_type']}:{row['remote_id']}" if row["remote_id_type"] and row["remote_id_type"] != "auto" and row["remote_id"] else ""),
                   "psk": self.reveal_psk(build_id) or ""}
            self.client_for(d).ipsec_apply(cfg, tag)
            # a successful apply rebuilds the tunnel under the wizard's own naming - an imported tunnel is now fully managed
            self.db.run("UPDATE ipsec_builds SET status='active', last_error=NULL, adopted=0, last_applied=? WHERE id=?", (time.time(), build_id))
            self.db.event(d["id"], d["org_id"], "ipsec tunnel applied", f"{row['name']} -> {row['remote_addr']}")
            self.db.audit(user, "ipsec tunnel applied", row["name"], org_id=row["org_id"])
        except (IpsecError, RouterError) as e:
            self.db.run("UPDATE ipsec_builds SET status='failed', last_error=? WHERE id=?", (str(e)[:500], build_id))
            self.db.audit(user, "ipsec tunnel apply failed", row["name"] if row else build_id, org_id=row["org_id"] if row else None, detail=str(e))
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.db.run("UPDATE ipsec_builds SET status='failed', last_error=? WHERE id=?", (f"Error: {e}"[:500], build_id))
        finally:
            with self.lock:
                self.busy.discard(build_id)

    def disable(self, build_id, user, delete=False):
        with self.lock:
            if build_id in self.busy:
                return False
            self.busy.add(build_id)
        self.db.run("UPDATE ipsec_builds SET status='applying' WHERE id=?", (build_id,))

        def run():
            row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
            tag = tag_for(build_id)
            err = None
            try:
                d = self.db.one("SELECT * FROM devices WHERE id=?", (row["device_id"],)) if row["device_id"] else None
                if d:
                    try:
                        if row["adopted"]:   # non-destructive: the peer/identity/policies were never ours, so just clear the wizard's label - the tunnel keeps running
                            self.client_for(d).untag(tag, ["/ip/ipsec/policy", "/ip/ipsec/identity", "/ip/ipsec/peer"])
                        else:
                            self.client_for(d).ipsec_clear(tag, f"tm-ipsec-{build_id}")
                    except RouterError as e:
                        err = str(e)
                if delete and not err:
                    self.db.run("DELETE FROM ipsec_builds WHERE id=?", (build_id,))
                else:
                    self.db.run("UPDATE ipsec_builds SET status=?, last_error=?, peer_state=NULL WHERE id=?",
                                ("failed" if err else "disabled", err and err[:500], build_id))
                self.db.audit(user, "ipsec tunnel deleted" if delete and not err else "ipsec tunnel disabled", row["name"],
                              org_id=row["org_id"], detail=err or "")
            finally:
                with self.lock:
                    self.busy.discard(build_id)
        threading.Thread(target=run, daemon=True, name=f"ipsec-off-{build_id}").start()
        return True

    # --- status -----------------------------------------------------------------------------------------------
    def check(self, build_id):
        row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
        if not row or row["status"] not in ("active", "failed"):
            return
        state = None
        d = self.db.one("SELECT * FROM devices WHERE id=?", (row["device_id"],)) if row["device_id"] else None
        if d and d["online"]:
            try:
                state = self.client_for(d).ipsec_status(as_ip(row["remote_addr"]))
            except RouterError:
                pass
        self.db.run("UPDATE ipsec_builds SET peer_state=?, checked_at=? WHERE id=?", (state, time.time(), build_id))

    def loop(self):
        while True:
            time.sleep(60)
            try:
                for v in self.db.q("SELECT id FROM ipsec_builds WHERE status IN ('active','failed')"):
                    if v["id"] not in self.busy:
                        self.check(v["id"])
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self):
        self.db.run("UPDATE ipsec_builds SET status='failed', last_error='TikManager restarted while applying - apply again.' WHERE status='applying'")
        threading.Thread(target=self.loop, daemon=True, name="ipsec-builds").start()
