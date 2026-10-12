"""Router logs: every line the routers send (topics info / warning / error / critical, set up at adoption), searchable
on the Logs page and the router's Logs tab, with alert rules.

- Lines arrive over the WireGuard tunnel (secevents.py listens and hands each one here as well). They're buffered and
  written in batches; at most LINES_PER_MINUTE per router are kept, so one misbehaving router can't flood the database.
- Kept KEEP_DAYS days and at most MAX_PER_DEVICE lines per router (a chatty core router can't push out the others).
- Alert rules (Logs page > Alert rules, administrators): text or /regex/, optional topics and minimum severity, which
  routers (all, a client, a tag or one router), and "N matching lines within M minutes". A rule that fires becomes an
  alert (ticket / Teams / email / webhooks, alerts.py) that clears once fewer than N lines match in the window.
"""
import json
import re
import secrets as pysecrets
import threading
import time

KEEP_DAYS = 14
MAX_PER_DEVICE = 20000
LINES_PER_MINUTE = 300
SEVERITIES = ["debug", "info", "warning", "error", "critical"]
PRI_SEV = {0: "critical", 1: "critical", 2: "critical", 3: "error", 4: "warning", 5: "info", 6: "info", 7: "debug"}
MONTH = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+")
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*\s+")
TOPICS = re.compile(r"^[a-z0-9-]+(,[a-z0-9-]+)+$")


def parse(raw: str):
    """One syslog line from RouterOS -> (topics, severity, message). Copes with the default format
    ('<PRI>topics message'), BSD syslog ('<PRI>Mon DD HH:MM:SS host topics message') and ISO timestamps."""
    line = raw.strip()
    pri = None
    if m := re.match(r"^<(\d{1,3})>", line):
        pri, line = int(m.group(1)), line[m.end():]
    line = MONTH.sub("", line, count=1)
    line = ISO.sub("", line, count=1)
    parts = line.split(" ", 2)
    topics, msg = "", line
    if parts and TOPICS.match(parts[0]):
        topics, msg = parts[0], line[len(parts[0]):].strip()
    elif len(parts) >= 2 and TOPICS.match(parts[1]):   # "<host> topics message"
        topics, msg = parts[1], (parts[2] if len(parts) > 2 else "")
    sev = next((s for s in ("critical", "error", "warning", "debug", "info") if s in topics.split(",")), None)
    sev = sev or (PRI_SEV.get(pri % 8) if pri is not None else "info")
    return topics, sev, re.sub(r"[\x00-\x1f\x7f]", " ", msg)[:1000]


class RouterLogs:
    def __init__(self, db):
        self.db = db
        self.buf, self.lock = [], threading.Lock()
        self._rate = {}
        self._pruned = 0

    # --- intake ---------------------------------------------------------------------------------------------
    def add(self, device_id: int, raw: str, ts=None):
        minute = int(time.time() // 60)
        with self.lock:
            m, n = self._rate.get(device_id, (minute, 0))
            if m != minute:
                m, n = minute, 0
            if n >= LINES_PER_MINUTE:
                return
            self._rate[device_id] = (m, n + 1)
            self.buf.append((ts or time.time(), device_id, *parse(raw)))

    def flush(self):
        with self.lock:
            rows, self.buf = self.buf, []
        if rows:
            self.db.many("INSERT INTO router_logs (ts, device_id, topics, severity, message) VALUES (?,?,?,?,?)", rows)

    def prune(self):
        self.db.run("DELETE FROM router_logs WHERE ts < ?", (time.time() - KEEP_DAYS * 86400,))
        for r in self.db.q("SELECT device_id, COUNT(*) AS n FROM router_logs GROUP BY device_id HAVING n > ?", (MAX_PER_DEVICE,)):
            self.db.run("""DELETE FROM router_logs WHERE device_id=? AND id <= (SELECT id FROM router_logs WHERE device_id=?
                           ORDER BY id DESC LIMIT 1 OFFSET ?)""", (r["device_id"], r["device_id"], MAX_PER_DEVICE))

    def loop(self):
        while True:
            time.sleep(2)
            try:
                self.flush()
                if time.time() - self._pruned > 3600:
                    self.prune()
                    self._pruned = time.time()
            except Exception as e:  # noqa: BLE001
                print(f"routerlogs: {e}")

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="router-logs").start()

    # --- reading --------------------------------------------------------------------------------------------
    def query(self, where_sql, args, f: dict, limit=200):
        """Newest first. f: device_id, org_id, tag, sev (minimum), topic, q (text), hours, before_id, after_id."""
        cond, a = [where_sql], list(args)
        if f.get("device_id"):
            cond.append("l.device_id = ?"); a.append(int(f["device_id"]))
        if f.get("org_id"):
            cond.append("d.org_id = ?"); a.append(int(f["org_id"]))
        if f.get("sev") in SEVERITIES[1:]:
            cond.append(f"l.severity IN ({','.join('?' * len(SEVERITIES[SEVERITIES.index(f['sev']):]))})")
            a += SEVERITIES[SEVERITIES.index(f["sev"]):]
        if f.get("topic"):
            cond.append("(',' || l.topics || ',') LIKE ?"); a.append(f"%,{f['topic']},%")
        if f.get("q"):
            cond.append("l.message LIKE ?"); a.append(f"%{f['q']}%")
        if f.get("tag"):
            cond.append("d.tags LIKE ?"); a.append(f'%"{f["tag"]}"%')
        if f.get("hours"):
            cond.append("l.ts > ?"); a.append(time.time() - float(f["hours"]) * 3600)
        if f.get("before_id"):
            cond.append("l.id < ?"); a.append(int(f["before_id"]))
        if f.get("after_id"):
            cond.append("l.id > ?"); a.append(int(f["after_id"]))
        return self.db.q(f"""SELECT l.id, l.ts, l.device_id, l.topics, l.severity, l.message, d.name AS device, o.name AS org
                             FROM router_logs l JOIN devices d ON d.id = l.device_id LEFT JOIN orgs o ON o.id = d.org_id
                             WHERE {' AND '.join(cond)} ORDER BY l.id DESC LIMIT ?""", (*a, int(limit)))

    # --- alert rules ----------------------------------------------------------------------------------------
    def rules(self) -> list:
        try:
            r = json.loads(self.db.setting("log_rules", "") or "[]")
            return r if isinstance(r, list) else []
        except ValueError:
            return []

    @staticmethod
    def check_rule(b: dict) -> dict:
        name, pattern = str(b.get("name") or "").strip()[:80], str(b.get("pattern") or "").strip()[:200]
        if not name or not pattern:
            raise ValueError("Give the rule a name and the text (or /regex/) to look for.")
        if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
            try:
                re.compile(pattern[1:-1], re.I)
            except re.error as e:
                raise ValueError(f"The regular expression doesn't work: {e}") from None
        try:
            count, minutes = int(b.get("count") or 1), int(b.get("minutes") or 10)
        except (TypeError, ValueError):
            raise ValueError("Count and minutes must be whole numbers.") from None
        if not (1 <= count <= 10000 and 1 <= minutes <= 1440):
            raise ValueError("1-10000 lines within 1-1440 minutes.")
        scope = b.get("scope") if b.get("scope") in ("all", "org", "tag", "device") else "all"
        return {"id": str(b.get("id") or pysecrets.token_hex(5)), "name": name, "pattern": pattern, "topics": str(b.get("topics") or "").strip()[:60],
                "sev": b.get("sev") if b.get("sev") in SEVERITIES else "", "scope": scope, "target": str(b.get("target") or "")[:64],
                "count": count, "minutes": minutes, "on": bool(b.get("on", True))}

    def save_rule(self, b: dict) -> dict:
        r = self.check_rule(b)
        rules = [x for x in self.rules() if x["id"] != r["id"]]
        if len(rules) >= 50:
            raise ValueError("At most 50 rules.")
        rules.append(r)
        self.db.set_setting("log_rules", json.dumps(rules))
        return r

    def delete_rule(self, rid):
        self.db.set_setting("log_rules", json.dumps([x for x in self.rules() if x["id"] != rid]))

    def _matcher(self, rule):
        p = rule["pattern"]
        if p.startswith("/") and p.endswith("/") and len(p) > 2:
            rx = re.compile(p[1:-1], re.I)
            return lambda m: bool(rx.search(m))
        low = p.lower()
        return lambda m: low in m.lower()

    def matches(self, rule, since, devs) -> dict:
        """{device id: [matching rows, newest first]} since a time, for the rule's routers."""
        ids = [d["id"] for d in devs if rule["scope"] == "all" or (rule["scope"] == "org" and str(d.get("org_id")) == rule["target"])
               or (rule["scope"] == "device" and str(d["id"]) == rule["target"])
               or (rule["scope"] == "tag" and rule["target"].lower() in [t.lower() for t in json.loads(d.get("tags") or "[]")])]
        if not ids:
            return {}
        sev_ok = SEVERITIES[SEVERITIES.index(rule["sev"]):] if rule.get("sev") else SEVERITIES
        want_topics = [t.strip() for t in rule.get("topics", "").split(",") if t.strip()]
        ok, out = self._matcher(rule), {}
        rows = self.db.q(f"""SELECT id, ts, device_id, topics, severity, message FROM router_logs WHERE ts > ? AND device_id IN ({','.join('?' * len(ids))})
                             ORDER BY id DESC LIMIT 50000""", (since, *ids))
        for r in rows:
            if r["severity"] not in sev_ok:
                continue
            if want_topics and not set(want_topics) & set(r["topics"].split(",")):
                continue
            if ok(r["message"]):
                out.setdefault(r["device_id"], []).append(r)
        return out

    def conditions(self, devs, label) -> dict:
        """Alert conditions (alerts.py): one per rule and router with enough matching lines in the rule's window."""
        out, now = {}, time.time()
        for rule in self.rules():
            if not rule.get("on"):
                continue
            for did, rows in self.matches(rule, now - rule["minutes"] * 60, devs).items():
                if len(rows) >= rule["count"]:
                    d = next(x for x in devs if x["id"] == did)
                    out[f"log:{rule['id']}:{did}"] = ("log", did, d["org_id"], f"{label(d)}: {rule['name']}",
                        f"{len(rows)} matching log line{'s' if len(rows) != 1 else ''} in {rule['minutes']} min (rule: {rule['pattern']}). Latest:\n"
                        + "\n".join(f"- {time.strftime('%H:%M:%S', time.localtime(r['ts']))} {r['topics']} {r['message'][:200]}" for r in rows[:5]))
        return out

    def test(self, b: dict, devs) -> dict:
        """How a rule would have done over the last 24 hours."""
        rule = self.check_rule(b)
        hits = self.matches(rule, time.time() - 86400, devs)
        names = {d["id"]: d["name"] for d in devs}
        return {"routers": [{"id": did, "name": names.get(did, "?"), "lines": len(rows), "latest": rows[0]["message"][:200], "at": rows[0]["ts"]}
                            for did, rows in sorted(hits.items(), key=lambda x: -len(x[1]))][:50],
                "total": sum(len(r) for r in hits.values())}

    # --- dev ------------------------------------------------------------------------------------------------
    def seed_dev(self, devs):
        """Sample lines for the simulated routers (dev mode, empty table only)."""
        if not devs or self.db.one("SELECT 1 FROM router_logs LIMIT 1"):
            return
        import random
        r, now, rows = random.Random(7), time.time(), []
        samples = [("dhcp,info", "dhcp-lan assigned 192.168.20.{n} for AA:BB:CC:00:00:{n:02X} Laptop-{n}"), ("dhcp,info", "dhcp-lan deassigned 192.168.20.{n} for AA:BB:CC:00:00:{n:02X}"),
                   ("interface,info", "ether{p} link up (speed 1G, full duplex)"), ("interface,info", "ether{p} link down"),
                   ("wireless,info", "AA:BB:CC:11:22:{n:02X}@wifi1: connected, signal strength -6{p}"), ("wireless,info", "AA:BB:CC:11:22:{n:02X}@wifi1: disconnected, received deauth"),
                   ("system,info", "router rebooted"), ("system,error,critical", "login failure for user admin from 45.155.205.233 via ssh"),
                   ("firewall,info", "input: in:ether1 out:(unknown 0), proto TCP (SYN), 185.220.101.{n}:5{p}123->203.0.113.4:8291, len 60"),
                   ("ppp,info", "pppoe-out1: connected"), ("ppp,error", "pppoe-out1: disconnected, LCP timeout"), ("system,warning", "NTP: no server reachable"),
                   ("script,error", "executing script backup-to-ftp from scheduler failed, please check it manually")]
        for i in range(400):
            topics, text = r.choice(samples)
            rows.append((now - r.uniform(0, 86400), r.choice(devs)["id"], topics,
                         next((s for s in ("critical", "error", "warning") if s in topics), "info"), text.format(n=r.randint(10, 250), p=r.randint(1, 5))))
        self.db.many("INSERT INTO router_logs (ts, device_id, topics, severity, message) VALUES (?,?,?,?,?)", sorted(rows))
