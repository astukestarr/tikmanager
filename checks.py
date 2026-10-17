"""Critical checks (Monitoring > Critical checks, and the router page): addresses a client's routers must be able to reach -
"every router at Acme can get to the file server 192.168.100.5" - pinged from each router.

- A check belongs to a client and applies to: all its routers, the ones with a tag, or chosen routers - with exclusions
  (a router that doesn't need it). A check made from a router's page applies to that router.
- Every ROUND seconds each online router pings its checks' targets (COUNT pings each; from its LAN address when the
  check says so - site-to-site VPNs often carry only LAN-to-LAN traffic). A target that doesn't answer for `fail_after`
  rounds in a row is down: a router event, and the "Critical check down" alert (Alerts) after its minutes; it's up again
  as soon as it answers. An offline router's checks aren't judged (the router being down is its own alert).
"""
import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from routeros import RouterError

ROUND = 60
COUNT = 3
SCOPES = ("all", "tag", "routers")


class CheckError(ValueError):
    pass


class Checks:
    def __init__(self, db, client):
        self.db, self.client = db, client
        self.running = False

    # --- definitions ---------------------------------------------------------------------------------------------
    @staticmethod
    def _row(r):
        r = dict(r)
        r["routers"] = json.loads(r.get("routers") or "[]")
        r["exclude"] = json.loads(r.get("exclude") or "[]")
        return r

    def defs(self, org_id=None):
        q, a = "SELECT c.*, o.name AS org FROM check_defs c LEFT JOIN orgs o ON o.id = c.org_id", ()
        if org_id is not None:
            q, a = q + " WHERE c.org_id=?", (org_id,)
        return [self._row(r) for r in self.db.q(q + " ORDER BY o.name, c.name", a)]

    def applies(self, c, d):
        """Does check c apply to router d?"""
        if d["org_id"] != c["org_id"] or d["id"] in c["exclude"]:
            return False
        if c["scope"] == "all":
            return True
        if c["scope"] == "tag":
            try:
                return c.get("tag", "") in (json.loads(d.get("tags") or "[]") or [])
            except ValueError:
                return False
        return d["id"] in c["routers"]

    def save(self, b, by):
        org = int(b.get("org_id") or 0)
        if not self.db.one("SELECT 1 FROM orgs WHERE id=?", (org,)):
            raise CheckError("Pick the client.")
        name, target = str(b.get("name") or "").strip()[:80], str(b.get("target") or "").strip()[:120]
        if not target or any(ch in target for ch in " ;\"'`$[]{}\\"):
            raise CheckError("Enter the address to check (an IP address or a host name).")
        scope = b.get("scope") if b.get("scope") in SCOPES else "all"
        ids = lambda k: sorted({int(x) for x in b.get(k) or [] if str(x).isdigit()})
        routers, exclude, tag = ids("routers"), ids("exclude"), str(b.get("tag") or "").strip()[:40]
        if scope == "routers" and not routers:
            raise CheckError("Pick at least one router.")
        if scope == "tag" and not tag:
            raise CheckError("Pick the tag.")
        fail_after = max(1, min(10, int(b.get("fail_after") or 3)))
        vals = (org, name or target, target, scope, tag, json.dumps(routers), json.dumps(exclude if scope != "routers" else []),
                1 if b.get("from_lan") else 0, fail_after, 0 if b.get("enabled") is False else 1, str(b.get("notes") or "").strip()[:300])
        cid = int(b.get("id") or 0)
        if cid:
            if not self.db.one("SELECT 1 FROM check_defs WHERE id=?", (cid,)):
                raise CheckError("Check not found.")
            self.db.run("""UPDATE check_defs SET org_id=?, name=?, target=?, scope=?, tag=?, routers=?, exclude=?, from_lan=?, fail_after=?, enabled=?, notes=?
                           WHERE id=?""", (*vals, cid))
        else:
            cid = self.db.run("""INSERT INTO check_defs (org_id, name, target, scope, tag, routers, exclude, from_lan, fail_after, enabled, notes, created_by, created_at)
                                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*vals, by, time.time()))
        self._tidy()
        return cid

    def delete(self, cid):
        self.db.run("DELETE FROM check_state WHERE check_id=?", (cid,))
        self.db.run("DELETE FROM check_defs WHERE id=?", (cid,))

    def exclude(self, cid, did, on=True):
        c = next((x for x in self.defs() if x["id"] == cid), None)
        if not c:
            raise CheckError("Check not found.")
        ex = set(c["exclude"])
        if c["scope"] == "routers":   # a hand-picked list: take it off the list instead
            rs = set(c["routers"]) - {did} if on else set(c["routers"]) | {did}
            if not rs:
                raise CheckError("That's the only router on this check - delete the check instead.")
            self.db.run("UPDATE check_defs SET routers=? WHERE id=?", (json.dumps(sorted(rs)), cid))
        else:
            ex = ex | {did} if on else ex - {did}
            self.db.run("UPDATE check_defs SET exclude=? WHERE id=?", (json.dumps(sorted(ex)), cid))
        self._tidy()

    def _tidy(self):
        """Drop results for routers a check no longer applies to."""
        devs = {d["id"]: d for d in self.db.q("SELECT id, org_id, tags FROM devices WHERE state='adopted'")}
        defs = {c["id"]: c for c in self.defs()}
        for s in self.db.q("SELECT check_id, device_id FROM check_state"):
            c, d = defs.get(s["check_id"]), devs.get(s["device_id"])
            if not c or not d or not self.applies(c, d):
                self.db.run("DELETE FROM check_state WHERE check_id=? AND device_id=?", (s["check_id"], s["device_id"]))

    # --- running -------------------------------------------------------------------------------------------------
    @staticmethod
    def lan_ip(d):
        try:
            for n in json.loads(d.get("networks") or "[]") or []:
                if n.get("address"):
                    return n["address"].split("/")[0]
        except ValueError:
            pass
        return None

    def _router(self, d, checks):
        try:
            cl = self.client(d)
        except Exception:  # noqa: BLE001
            return
        now = time.time()
        for c in checks:
            src = self.lan_ip(d) if c["from_lan"] else None
            try:
                r = cl.ping_check(c["target"], src, COUNT)
            except RouterError as e:
                r = {"sent": 0, "received": 0, "avg": None, "error": str(e)[:200]}
            if r.get("router_down"):
                return   # the router itself stopped answering - don't judge its checks
            ok = r["received"] > 0
            loss = round(100 * (r["sent"] - r["received"]) / r["sent"], 1) if r["sent"] else None
            detail = r.get("error") or ("" if ok else f"no reply to {COUNT} pings" + (f" from {src}" if src else ""))
            self._record(c, d, ok, r.get("avg"), loss, detail, now)

    def _record(self, c, d, ok, avg, loss, detail, now):
        st = self.db.one("SELECT * FROM check_state WHERE check_id=? AND device_id=?", (c["id"], d["id"]))
        if not st:
            self.db.run("INSERT INTO check_state (check_id, device_id, up, fails, since) VALUES (?,?,NULL,0,?)", (c["id"], d["id"], now))
            st = {"up": None, "fails": 0, "since": now}
        fails = 0 if ok else (st["fails"] or 0) + 1
        up, since = st["up"], st["since"]
        if ok and up != 1:
            if up == 0:
                self.db.event(d["id"], d["org_id"], "check up", f"Critical check {c['name']}: {c['target']} answers again"
                              + (f" ({avg} ms)" if avg is not None else ""))
            up, since = 1, now
        elif not ok and fails >= c["fail_after"] and up != 0:
            self.db.event(d["id"], d["org_id"], "check down", f"Critical check {c['name']}: can't reach {c['target']} - {detail}")
            up, since = 0, now
        self.db.run("UPDATE check_state SET up=?, fails=?, since=?, last_at=?, latency=?, loss=?, detail=? WHERE check_id=? AND device_id=?",
                    (up, fails, since, now, avg, loss, detail, c["id"], d["id"]))

    def run_once(self, org_id=None, only=None):
        """One round. only: just these check ids (Check now) - runs alongside the regular rounds, never blocks them."""
        if only is None:
            if self.running:
                return
            self.running = True
        try:
            defs = [c for c in self.defs(org_id) if c["enabled"] and (only is None or c["id"] in only)]
            if not defs:
                return
            work = []
            for d in self.db.q("SELECT * FROM devices WHERE state='adopted' AND online=1"):
                mine = [c for c in defs if self.applies(c, d)]
                if mine:
                    work.append((d, mine))
            with ThreadPoolExecutor(max_workers=8) as ex:
                list(ex.map(lambda w: self._router(*w), work))
        except Exception:  # noqa: BLE001
            traceback.print_exc()
        finally:
            if only is None:
                self.running = False

    def loop(self):
        time.sleep(45)
        while True:
            t0 = time.time()
            self.run_once()
            time.sleep(max(5, ROUND - (time.time() - t0)))

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="checks").start()

    def run_now(self, cid):
        threading.Thread(target=self.run_once, kwargs={"only": {cid}}, daemon=True, name="check-now").start()

    # --- reading -------------------------------------------------------------------------------------------------
    def status(self, org_id=None, device_id=None):
        """Checks with each router's result: [{...def, results: [{device_id, name, online, up, since, latency, loss, detail, last_at}], up, down, waiting}]."""
        devs = self.db.q("SELECT id, name, org_id, tags, online FROM devices WHERE state='adopted'" + (" AND org_id=?" if org_id is not None else ""),
                         (org_id,) if org_id is not None else ())
        states = {(s["check_id"], s["device_id"]): s for s in self.db.q("SELECT * FROM check_state")}
        out = []
        for c in self.defs(org_id):
            res = []
            for d in devs:
                if not self.applies(c, d) or (device_id is not None and d["id"] != device_id):
                    continue
                s = states.get((c["id"], d["id"])) or {}
                res.append({"device_id": d["id"], "name": d["name"], "online": bool(d["online"]), "up": s.get("up"), "since": s.get("since"),
                            "latency": s.get("latency"), "loss": s.get("loss"), "detail": s.get("detail") or "", "last_at": s.get("last_at"), "fails": s.get("fails") or 0})
            if device_id is not None and not res:
                continue
            out.append({**c, "results": res, "up": sum(1 for r in res if r["up"] == 1), "down": sum(1 for r in res if r["up"] == 0 and r["online"]),
                        "waiting": sum(1 for r in res if r["up"] is None or not r["online"])})
        return out

    def down(self):
        """Every (check, router) that's down now, for alerts and dashboards."""
        return self.db.q("""SELECT s.check_id, s.device_id, s.since, s.detail, c.name AS check_name, c.target, d.name AS router, d.org_id, o.name AS org
                            FROM check_state s JOIN check_defs c ON c.id = s.check_id JOIN devices d ON d.id = s.device_id
                            LEFT JOIN orgs o ON o.id = d.org_id WHERE s.up = 0 AND c.enabled = 1 AND d.online = 1""")
