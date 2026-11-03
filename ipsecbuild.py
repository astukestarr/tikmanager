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
import secrets
import threading
import time
import traceback

from routeros import IPSEC_TAG, RouterError

# Modern, broadly-compatible defaults (editable in the wizard's Advanced section). RouterOS value names.
DEFAULTS = {"ike": "ike2", "p1_enc": "aes-256", "p1_hash": "sha256", "p1_dh": "modp2048",
            "p2_enc": "aes-256-cbc", "p2_auth": "sha256", "pfs": "modp2048"}


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
        if not local or not far:
            raise IpsecError("Add at least one local subnet and one remote subnet.")
        for a in local:
            for c in far:
                if a.overlaps(c):
                    raise IpsecError(f"{a} (local) overlaps {c} (remote) - the two ends need different subnets.")
        ike = (b.get("ike") or "ike2").strip()
        if ike not in ("ike2", "ike"):
            raise IpsecError("IKE version must be IKEv2 or IKEv1.")
        crypto = {k: (b.get(k) or DEFAULTS[k]).strip() for k in ("p1_enc", "p1_hash", "p1_dh", "p2_enc", "p2_auth", "pfs")}
        for k, val in crypto.items():
            if not val or not all(ch.isalnum() or ch in "-_," for ch in val):
                raise IpsecError(f"{k} has an invalid value.")
        return {"device": d, "remote": remote, "ike": ike,
                "local": [str(n) for n in local], "far": [str(n) for n in far], **crypto}

    def _subnets(self, raw, who):
        out = []
        for x in raw:
            n = net(x)
            if n.prefixlen < 8:
                raise IpsecError(f"{n} ({who}) is too large.")
            out.append(n)
        return out

    def save(self, build_id, b, user):
        v = self.validate(b)
        now = time.time()
        fields = (b["org_id"], b.get("name") or "IPsec tunnel", v["device"]["id"], v["remote"], v["ike"],
                  v["p1_enc"], v["p1_hash"], v["p1_dh"], v["p2_enc"], v["p2_auth"], v["pfs"],
                  json.dumps(v["local"]), json.dumps(v["far"]))
        if build_id:
            row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
            if not row or row["org_id"] != b["org_id"]:
                raise IpsecError("This tunnel no longer exists.")
            if row["id"] in self.busy:
                raise IpsecError("This tunnel is being applied right now - try again in a minute.")
            self.db.run("""UPDATE ipsec_builds SET org_id=?, name=?, device_id=?, remote_addr=?, ike=?, p1_enc=?, p1_hash=?,
                           p1_dh=?, p2_enc=?, p2_auth=?, pfs=?, local_subnets=?, remote_subnets=?, updated_at=? WHERE id=?""",
                        (*fields, now, build_id))
            return build_id
        bid = self.db.run("""INSERT INTO ipsec_builds (org_id, name, device_id, remote_addr, ike, p1_enc, p1_hash, p1_dh,
                             p2_enc, p2_auth, pfs, local_subnets, remote_subnets, created_by, created_at, updated_at)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*fields, user, now, now))
        psk = secrets.token_urlsafe(24)   # a strong pre-shared key, generated once and sealed
        blob, alg = self.vault.seal(psk.encode(), f"ipsec:{bid}")
        self.db.run("UPDATE ipsec_builds SET psk_blob=?, psk_alg=? WHERE id=?", (blob, alg, bid))
        return bid

    def reveal_psk(self, build_id):
        row = self.db.one("SELECT * FROM ipsec_builds WHERE id=?", (build_id,))
        if not row or not row["psk_blob"]:
            return None
        return self.vault.open(row["psk_blob"], row["psk_alg"], f"ipsec:{build_id}").decode()

    # --- applying ---------------------------------------------------------------------------------------------
    def apply(self, build_id, user):
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
                   "p1": {"enc": row["p1_enc"], "hash": row["p1_hash"], "dh": row["p1_dh"]},
                   "p2": {"enc": row["p2_enc"], "auth": row["p2_auth"], "pfs": row["pfs"]},
                   "local_subnets": json.loads(row["local_subnets"]), "remote_subnets": json.loads(row["remote_subnets"]),
                   "psk": self.reveal_psk(build_id) or ""}
            self.client_for(d).ipsec_apply(cfg, tag)
            self.db.run("UPDATE ipsec_builds SET status='active', last_error=NULL, last_applied=? WHERE id=?", (time.time(), build_id))
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
                        self.client_for(d).ipsec_clear(tag)
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
