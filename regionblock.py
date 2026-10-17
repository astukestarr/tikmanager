"""Region blocking: block (or allow only) countries on a client's routers, built to be safe on small routers.

- Policy per client (Security page > Region blocking): Block or Allow, a direction - Incoming (new connections from the
  internet to the router's own services and to port forwards; the default), Outgoing (new connections from the LAN to the
  internet) or Both - and the countries. Routers can be left out one by one, or let some countries through on their own
  (Block: taken off that router's list; Allow: added to it) - e.g. one site that works with China while the others don't.
- Data: geoip.py (IPinfo Lite, merged per country). Never blocked, whatever the data says: TikManager's server, every
  router's own addresses, addresses people actually used in the last 90 days (TikManager and router sign-ins, remote
  access connections) and the auto-block whitelist - in Block mode they're cut out of the list, in Allow mode added to it.
- On the router: one address list (LIST) whose entries have a timeout, so they live in RAM only - no flash writes, no
  bloated backups - and are refreshed weekly; firewall filter rules with connection-state=new on the internet links jump
  to TikManager's own chains, whose first rules send TikManager's addresses (web address and WireGuard endpoint) straight
  back - so TikManager can't be blocked whatever the list holds - before the drop. Rule changes are made like Safe Mode:
  an undo is armed on the router first and cancelled only once TikManager can still reach it; a startup scheduler that disables those rules after a reboot
  (the list is gone then - in Allow mode an empty list would block everything) until TikManager has reloaded it.
- Small routers: a list that would take more than RAM_SHARE of the router's free memory isn't loaded at all; entries go in
  BATCH at a time with pauses, slowing down when the CPU is busy and stopping (to continue later) when it stays busy;
  later changes only add and remove the differences.
"""
import hashlib
import ipaddress
import json
import socket
import threading
import time
import traceback
import urllib.parse
from pathlib import Path

from routeros import RouterError

LIST = "tikmanager-geo"
TAG = "TikManager region blocking"
CHAIN_IN, CHAIN_OUT = "tikmanager-geo-in", "tikmanager-geo-out"
UNDO = "tikmanager-geo-undo"
UNDO_SCRIPT = (f'/ip firewall filter remove [find comment~"^{TAG}"]\n'
               f'/system scheduler remove [find where name="{UNDO}"]\n/system script remove [find where name="{UNDO}"]\n')
CUTOFF_PAUSE = 24 * 3600        # after losing a router on a rule change, no automatic retry for this long (Sync now retries)
LOG_LIMIT = "6/1m,6:packet"      # dropped connections logged (a sample for Flows > Blocked) - a handful a minute at most
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
TIMEOUT = "14d"
REFRESH_EVERY = 6 * 86400       # entries' timeouts are renewed this often
BATCH, REMOVE_BATCH = 150, 25
BYTES_PER_ENTRY = 600           # RouterOS address-list entry, with headroom (forum measurements ~500 B)
RAM_SHARE = 0.25                # never use more than this share of a router's free memory
SEEN_DAYS = 90
MODES, DIRECTIONS = ("block", "allow"), ("incoming", "outgoing", "both")


class RegionError(Exception):
    pass


class Busy(Exception):
    pass


class RegionBlock:
    def __init__(self, db, settings, client, geo, autoblock):
        self.db, self.s, self.client, self.geo, self.autoblock = db, settings, client, geo, autoblock
        self.dir = Path(settings.data_dir) / "geo" / "pushed"
        self.lock = threading.Lock()
        self.running = False
        self.again = False   # a change came in while a round was running: run another straight after
        self.cutoff = {}     # device id -> when a rule change cut TikManager off (the router undid it)

    # --- policies -------------------------------------------------------------------------------------------------
    def policies(self):
        try:
            return json.loads(self.db.setting("regionblock") or "{}") or {}
        except ValueError:
            return {}

    def policy(self, org_id):
        return self.policies().get(str(org_id))

    def save_policy(self, org_id, b):
        codes = {c["code"] for c in self.geo.countries()}
        mode, direction = b.get("mode"), b.get("direction") or "incoming"
        if mode not in MODES or direction not in DIRECTIONS:
            raise RegionError("Pick Block or Allow, and a direction.")
        countries = sorted({str(c).upper() for c in b.get("countries") or [] if str(c).upper() in codes})[:250]
        enabled = bool(b.get("enabled"))
        if enabled and not countries:
            raise RegionError("Pick at least one country.")
        extra = []
        for x in str(b.get("exceptions") or "").replace(",", "\n").split("\n"):
            if x.strip():
                try:
                    extra.append(str(ipaddress.ip_network(x.strip(), strict=False)))
                except ValueError:
                    raise RegionError(f"Not an address or network: {x.strip()}") from None
        pol = {"enabled": enabled, "mode": mode, "direction": direction, "countries": countries,
               "skip": sorted({int(x) for x in b.get("skip") or [] if str(x).isdigit()}), "exceptions": extra[:200], "saved_at": time.time(),
               "router_allow": {str(int(k)): sorted({str(c).upper() for c in v if str(c).upper() in codes})
                                for k, v in (b.get("router_allow") or {}).items() if str(k).isdigit() and isinstance(v, list) and v}}
        all_ = self.policies()
        all_[str(org_id)] = pol
        self.db.set_setting("regionblock", json.dumps(all_))
        return pol

    # --- what never gets blocked ----------------------------------------------------------------------------------
    def protected(self, pol=None):
        ips = set()
        for r in self.db.q("SELECT public_ip, wan_ip FROM devices WHERE state='adopted'"):
            ips.update(x for x in (r["public_ip"], r["wan_ip"]) if x)
        since = time.time() - SEEN_DAYS * 86400
        ips.update(r["public_ip"] for r in self.db.q("SELECT DISTINCT public_ip FROM ra_sessions WHERE started_at > ? AND public_ip <> ''", (since,)))
        ips.update(r["ip"] for r in self.db.q("""SELECT DISTINCT ip FROM sec_events WHERE kind='login_ok' AND ts > ? AND ip <> ''
                                                 AND NOT (source='router' AND user='tikmanager')""", (since,)))
        ips.update(self.tm_ips())
        nets = []
        for x in list(ips) + list((self.autoblock.settings().get("whitelist") if self.autoblock else None) or []) + list((pol or {}).get("exceptions") or []):
            try:
                n = ipaddress.ip_network(str(x).strip(), strict=False)
            except ValueError:
                continue
            if n.version == 4 and n.is_global:
                nets.append(n)
        return list(ipaddress.collapse_addresses(nets))

    def tm_ips(self):
        """TikManager's own IPv4 addresses: its web address and the WireGuard endpoint the routers dial."""
        hosts = {urllib.parse.urlparse(getattr(self.s, "public_url", "") or "").hostname,
                 str(getattr(self.s, "wg_endpoint", "") or "").rpartition(":")[0].strip("[]") or None}
        out = set()
        for h in filter(None, hosts):
            try:
                out.update(a[4][0] for a in socket.getaddrinfo(h, None, socket.AF_INET))
            except OSError:
                pass
        return sorted(out)

    @staticmethod
    def effective(pol, did):
        """This router's policy: the client's, with the countries let through on this router taken off (Block) or added (Allow)."""
        extra = set((pol.get("router_allow") or {}).get(str(did)) or [])
        if not extra:
            return pol
        cs = set(pol["countries"]) - extra if pol["mode"] == "block" else set(pol["countries"]) | extra
        return {**pol, "countries": sorted(cs)}

    def target(self, pol):
        """The addresses to put on the routers' list for this policy: the countries, merged, with protected addresses
        cut out (Block) or added (Allow)."""
        nets = [ipaddress.IPv4Network(c) for cc in pol["countries"] for c in self.geo.cidrs(cc)]
        nets = list(ipaddress.collapse_addresses(nets))
        prot = self.protected(pol)
        rs = lambda n: str(n).removesuffix("/32")   # RouterOS shows a single address without /32
        if pol["mode"] == "allow":
            return [rs(n) for n in ipaddress.collapse_addresses(nets + prot)]
        out = []
        for n in nets:
            hit = [p for p in prot if p.overlaps(n)]
            pieces = [n]
            for p in hit:
                nxt = []
                for x in pieces:
                    if p.supernet_of(x):
                        continue
                    nxt += list(x.address_exclude(p)) if x.supernet_of(p) else [x]
                pieces = nxt
            out += pieces
        return [rs(n) for n in sorted(out)]

    @staticmethod
    def thash(pol, target):
        return hashlib.sha1((pol["mode"] + pol["direction"] + "\n".join(target)).encode()).hexdigest()

    # --- per-router state -----------------------------------------------------------------------------------------
    def state(self, did):
        return self.db.one("SELECT * FROM region_sync WHERE device_id=?", (did,))

    def _set(self, did, **kw):
        if not self.state(did):
            self.db.run("INSERT INTO region_sync (device_id, state) VALUES (?, 'off')", (did,))
        cols = ", ".join(f"{k}=?" for k in kw)
        self.db.run(f"UPDATE region_sync SET {cols}, updated_at=? WHERE device_id=?", (*kw.values(), time.time(), did))

    def _pushed(self, did):
        try:
            return set((self.dir / f"{did}.txt").read_text(encoding="utf-8").split())
        except OSError:
            return set()

    def _save_pushed(self, did, entries):
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / f"{did}.tmp"
        tmp.write_text("\n".join(sorted(entries)), encoding="utf-8")
        tmp.replace(self.dir / f"{did}.txt")

    @staticmethod
    def wans(d):
        try:
            return sorted((json.loads(d.get("isp_state") or "{}") or {}).keys())
        except ValueError:
            return []

    @staticmethod
    def capacity(d, n):
        """(fits?, sentence) - would n entries stay within RAM_SHARE of the router's free memory?"""
        free = max(0, (d.get("mem_total") or 0) - (d.get("mem_used") or 0))
        need = n * BYTES_PER_ENTRY
        if not free:
            return False, "This router's free memory isn't known yet."
        if need > RAM_SHARE * free:
            return False, (f"{n:,} entries need about {need / 1e6:.1f} MB - more than a quarter of this router's free memory "
                           f"({free / 1e6:.0f} MB). Pick fewer countries, or leave this router out.")
        return True, f"about {need / 1e6:.1f} MB of {free / 1e6:.0f} MB free"

    # --- syncing -------------------------------------------------------------------------------------------------
    def run_once(self, org_id=None, manual=False):
        """Bring every router in line with its client's policy (one router at a time)."""
        with self.lock:
            if self.running:
                self.again = True
                return
            self.running, self.again = True, False
        try:
            pols, targets = self.policies(), {}
            q, args = "SELECT * FROM devices WHERE state='adopted'", ()
            if org_id is not None:
                q, args = q + " AND org_id=?", (org_id,)
            for d in self.db.q(q, args):
                pol = pols.get(str(d["org_id"]))
                if pol:
                    pol = self.effective(pol, d["id"])
                active = bool(pol and pol.get("enabled") and pol.get("countries") and d["id"] not in (pol.get("skip") or []))
                st = self.state(d["id"])
                if manual:
                    self.cutoff.pop(d["id"], None)
                elif active and time.time() - self.cutoff.get(d["id"], 0) < CUTOFF_PAUSE:
                    continue
                try:
                    if not active:
                        if st and st["state"] != "off":
                            self.remove(d, "Region blocking is off for this router.")
                        continue
                    key = (d["org_id"], tuple(pol["countries"]))
                    if key not in targets:
                        t = self.target(pol)
                        targets[key] = (t, self.thash(pol, t))
                    self.sync_router(d, pol, *targets[key])
                except Busy as e:
                    self._set(d["id"], state="paused", detail=str(e))
                except RouterError as e:
                    self._set(d["id"], state="error", detail=str(e)[:300])
                except Exception as e:  # noqa: BLE001 - one router's trouble mustn't stop the others
                    traceback.print_exc()
                    self._set(d["id"], state="error", detail=f"{e}"[:300])
        finally:
            self.running = False
        if self.again:
            self.run_once()

    def _pace(self, cl):
        """After each batch: a short pause, longer when the router is busy; give up for now when it stays busy."""
        for _ in range(6):
            cpu = cl.cpu_load()
            if cpu < 60:
                time.sleep(0.3)
                return
            if cpu < 85:
                time.sleep(2)
                return
            time.sleep(5)
        raise Busy(f"Stopped for now - the router's CPU stayed above 85% (it carries on in the next round, within 5 minutes).")

    def sync_router(self, d, pol, target, th):
        did, now = d["id"], time.time()
        st = self.state(did) or {}
        if not d["online"]:
            if st.get("state") not in ("synced", "off"):
                self._set(did, state="waiting", detail="The router is offline - it's loaded when it's back.")
            return
        ok, why = self.capacity(d, len(target))
        if not ok:
            if st.get("state") not in (None, "off", "too_big"):
                self.remove(d, why, state="too_big")
            else:
                self._set(did, state="too_big", detail=why, entries=len(target))
            return
        wans = self.wans(d)
        if not wans:
            self._set(did, state="error", detail="TikManager doesn't know this router's internet links yet (router page > Settings > Internet links).")
            return
        tm = self.tm_ips()
        if not tm:
            self._set(did, state="error", detail="Couldn't look up TikManager's own address, so nothing was changed (the rules need it so "
                                                 "TikManager can never be blocked).")
            return
        cl = self.client(d)
        pushed = self._pushed(did)
        rules = [r for r in cl.fw_rules("filter") or [] if str(r.get("comment") or "").startswith(TAG)]
        lost = bool(pushed) and (any(r.get("disabled") == "true" for r in rules) or not cl.al_find(LIST, next(iter(pushed))))
        if lost:   # rebooted (the startup scheduler disabled the rules) or the list was cleared: load it again
            pushed = set()
        steady = (st.get("state") == "synced" and st.get("target_hash") == th and not lost and len(rules) == len(self._bodies(pol, wans, tm))
                  and now - (st.get("refreshed_at") or 0) < REFRESH_EVERY)
        if steady:
            self._set(did, hits=self._hits(rules), checked_at=now)
            return
        if st.get("mode") and (st.get("mode") != pol["mode"]) and rules:   # Block <-> Allow: the old rules go before the list changes
            self._remove_rules(cl)
            rules = []
        want = set(target)
        add, rem = sorted(want - pushed), sorted(pushed - want)
        if add or rem:
            self._set(did, state="loading", detail=f"{len(pushed & want):,} of {len(want):,} loaded", entries=len(want), mode=pol["mode"])
        for i in range(0, len(add), BATCH):
            chunk = add[i:i + BATCH]
            cl.run_script("\n".join(f':do {{/ip firewall address-list add list={LIST} address={a} timeout={TIMEOUT}}} on-error={{}}' for a in chunk), timeout=120)
            pushed.update(chunk)
            if i // BATCH % 10 == 9:
                self._save_pushed(did, pushed)
                self._set(did, detail=f"{len(pushed & want):,} of {len(want):,} loaded")
            self._pace(cl)
        for i in range(0, len(rem), REMOVE_BATCH):
            chunk = rem[i:i + REMOVE_BATCH]
            cl.run_script("\n".join(f':do {{/ip firewall address-list remove [find list={LIST} address={a}]}} on-error={{}}' for a in chunk), timeout=120)
            pushed.difference_update(chunk)
            self._pace(cl)
        self._save_pushed(did, pushed)
        refreshed = st.get("refreshed_at") or now
        if not (add or lost) and now - refreshed >= REFRESH_EVERY:   # renew the timeouts (one command on the router)
            cl.run_script(f"/ip firewall address-list set [find list={LIST} dynamic] timeout={TIMEOUT}", timeout=180)
            refreshed = now
        elif add or lost:
            refreshed = now
        cl.geo_boot_guard(True, f"/ip firewall filter disable [find comment~\"^{TAG}\"]")
        self._ensure_rules(cl, d, pol, wans, tm)
        rules = [r for r in cl.fw_rules("filter") or [] if str(r.get("comment") or "").startswith(TAG)]
        self._set(did, state="synced", detail=f"{len(want):,} entries · {why}", entries=len(want), target_hash=th, mode=pol["mode"],
                  synced_at=now, refreshed_at=refreshed, checked_at=now, hits=self._hits(rules))
        if add or rem or lost:
            self.db.event(did, d["org_id"], "region blocking",
                          f"{'Reloaded after a restart: ' if lost else ''}{pol['mode']} {', '.join(pol['countries'])} ({pol['direction']}) - "
                          f"{len(want):,} entries (+{len(add):,} / -{len(rem):,})")

    @staticmethod
    def _hits(rules):
        return sum(int(r.get("packets") or 0) for r in rules if r.get("action") == "drop")

    @staticmethod
    def _bodies(pol, wans, tm):
        """New connections on the internet links jump to TikManager's chains; there TikManager's addresses (and, in Allow
        mode, private addresses - an upstream router or CGNAT) return to the router's own rules first, then the drop."""
        neg = "!" if pol["mode"] == "allow" else ""
        safe = list(tm) + (list(PRIVATE_V4) if pol["mode"] == "allow" else [])
        out = []
        if pol["direction"] in ("incoming", "both"):
            out += [{"chain": CHAIN_IN, "src-address": a, "action": "return", "comment": f"{TAG}: never block TikManager" if a in tm else f"{TAG}: private"} for a in safe]
            out.append({"chain": CHAIN_IN, "src-address-list": neg + LIST, "action": "log", "log-prefix": "tm-geo-in", "limit": LOG_LIMIT,
                        "comment": f"{TAG}: sample for Flows"})
            out.append({"chain": CHAIN_IN, "src-address-list": neg + LIST, "action": "drop", "comment": f"{TAG}: incoming"})
            for w in wans:
                out.append({"chain": "input", "in-interface": w, "connection-state": "new", "action": "jump", "jump-target": CHAIN_IN, "comment": f"{TAG}"})
                out.append({"chain": "forward", "in-interface": w, "connection-state": "new", "connection-nat-state": "dstnat", "action": "jump",
                            "jump-target": CHAIN_IN, "comment": f"{TAG}: port forwards"})
        if pol["direction"] in ("outgoing", "both"):
            out += [{"chain": CHAIN_OUT, "dst-address": a, "action": "return", "comment": f"{TAG}: never block TikManager" if a in tm else f"{TAG}: private"} for a in safe]
            out.append({"chain": CHAIN_OUT, "dst-address-list": neg + LIST, "action": "log", "log-prefix": "tm-geo-out", "limit": LOG_LIMIT,
                        "comment": f"{TAG}: sample for Flows"})
            out.append({"chain": CHAIN_OUT, "dst-address-list": neg + LIST, "action": "drop", "comment": f"{TAG}: outgoing"})
            for w in wans:
                out.append({"chain": "forward", "out-interface": w, "connection-state": "new", "action": "jump", "jump-target": CHAIN_OUT, "comment": f"{TAG}: outgoing"})
        return out

    def _ensure_rules(self, cl, d, pol, wans, tm):
        """The policy's rules, enabled; replaced as a set when anything differs - like Safe Mode: an undo that removes them
        is armed on the router first and cancelled only once TikManager can still reach the router."""
        keyf = lambda r: tuple(str(r.get(k) or "") for k in ("chain", "action", "jump-target", "in-interface", "out-interface", "connection-nat-state",
                                                             "src-address", "dst-address", "src-address-list", "dst-address-list"))
        want = self._bodies(pol, wans, tm)
        rules = cl.fw_rules("filter") or []
        mine = [r for r in rules if str(r.get("comment") or "").startswith(TAG)]
        if [keyf(r) for r in mine if r["chain"] in (CHAIN_IN, CHAIN_OUT)] == [keyf(b) for b in want if b["chain"] in (CHAIN_IN, CHAIN_OUT)] \
                and sorted(map(keyf, mine)) == sorted(map(keyf, want)) and all(r.get("disabled") != "true" for r in mine):
            return
        cl.undo_arm(UNDO, UNDO_SCRIPT, "5m")   # armed before the change: if TikManager is cut off, the router undoes it by itself
        for r in mine:
            cl.fw_remove("filter", r[".id"])
        for b in want:   # TikManager's chains, in order (returns before the drop)
            if b["chain"] in (CHAIN_IN, CHAIN_OUT):
                cl.fw_add("filter", b)
        rules = cl.fw_rules("filter") or []
        for b in reversed([b for b in want if b["chain"] not in (CHAIN_IN, CHAIN_OUT)]):   # the jumps at the top of input / forward
            first = next((r for r in rules if r.get("chain") == b["chain"] and r.get("dynamic") != "true"
                          and not str(r.get("comment") or "").startswith(TAG)), None)
            cl.fw_add("filter", b, before=first[".id"] if first else None)
        time.sleep(3)
        try:
            cl.alive()
        except RouterError:
            self.cutoff[d["id"]] = time.time()
            self.db.event(d["id"], d["org_id"], "region blocking", "TikManager lost the router after adding the region rules - the router takes them "
                                                                   "off by itself within 5 minutes. Not retried automatically for 24 hours (Sync now retries).")
            raise RouterError("Lost the router after adding the rules - the router removes them by itself within 5 minutes. "
                              "Not retried automatically for 24 hours; Sync now tries again.") from None
        cl.undo_cancel(UNDO)

    def _remove_rules(self, cl):
        for r in cl.fw_rules("filter") or []:
            if str(r.get("comment") or "").startswith(TAG):
                cl.fw_remove("filter", r[".id"])

    def remove(self, d, why, state="off"):
        """Take region blocking off a router: rules first, then the startup scheduler, then the list."""
        did = d["id"]
        if d["online"]:
            cl = self.client(d)
            self._remove_rules(cl)
            cl.geo_boot_guard(False)
            cl.run_script(f"/ip firewall address-list remove [find list={LIST}]", timeout=180)
            (self.dir / f"{did}.txt").unlink(missing_ok=True)
            self.db.event(did, d["org_id"], "region blocking", f"Removed from the router - {why}")
        self._set(did, state=state, detail=why, target_hash=None, hits=0)

    # --- background ----------------------------------------------------------------------------------------------
    def loop(self):
        time.sleep(90)
        while True:
            try:
                if self.geo.due():
                    try:
                        self.geo.update()
                    except Exception:  # noqa: BLE001 - keep the old data; the page shows the error
                        traceback.print_exc()
                if any(p.get("enabled") for p in self.policies().values()) or self.db.one("SELECT 1 FROM region_sync WHERE state <> 'off'"):
                    self.run_once()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(300)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="regionblock").start()

    def kick(self, org_id=None, manual=True):
        threading.Thread(target=self.run_once, args=(org_id, manual), daemon=True, name="regionblock-now").start()
