"""Dashboard boards beyond Overview (Dashboard > Network / Security / Maintenance), like Report Center's dashboards: one
call per board, built from what TikManager already stores - nothing is read from routers here, so a board is quick.

Every board gets `rows`: the adopted routers this person can see (devices + org name), so a client's people only ever see
their own routers.
"""
import json
import re
import time

from flows import Flows

LOG_RE = Flows.LOG
BACKUP_STALE = 2 * 86400


def _vt(v):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(v or ""))
    return tuple(int(x or 0) for x in m.groups()) if m else None


def _brief(r):
    return {"id": r["id"], "name": r["name"], "org": r.get("org") or "", "online": bool(r["online"])}


def _checks_down(db, rows):
    ids = [r["id"] for r in rows if r["online"]]
    if not ids:
        return [], 0
    ph = ",".join("?" * len(ids))
    down = db.q(f"""SELECT s.device_id AS id, s.since, s.detail, c.name AS check_name, c.target, d.name, o.name AS org FROM check_state s
                    JOIN check_defs c ON c.id = s.check_id JOIN devices d ON d.id = s.device_id LEFT JOIN orgs o ON o.id = d.org_id
                    WHERE s.up = 0 AND c.enabled = 1 AND s.device_id IN ({ph}) ORDER BY s.since""", ids)
    total = db.one(f"SELECT COUNT(*) AS n FROM check_state s JOIN check_defs c ON c.id = s.check_id WHERE c.enabled = 1 AND s.device_id IN ({ph})", ids)["n"]
    for x in down:
        x["online"] = True
    return down, total


def network(db, rows, now=None):
    now = now or time.time()
    ids = [r["id"] for r in rows]
    ph = ",".join("?" * len(ids)) or "NULL"
    m = {x["device_id"]: x for x in db.q(f"""SELECT device_id, AVG(latency) AS lat, MAX(loss) AS loss, AVG(cpu) AS cpu, AVG(mem_pct) AS mem
                                              FROM metrics WHERE device_id IN ({ph}) AND ts > ? GROUP BY device_id""", (*ids, now - 3600))} if ids else {}
    links_down, bgp_down, links_total, bgp_total = [], [], 0, 0
    for r in rows:
        if not r["online"]:
            continue
        for n, l in (json.loads(r.get("isp_state") or "{}") or {}).items():
            links_total += 1
            if not l.get("up"):
                links_down.append({**_brief(r), "link": n, "comment": l.get("comment") or "", "since": l.get("since")})
        for n, p in (json.loads(r.get("bgp_state") or "null") or {}).items():
            bgp_total += 1
            if not p.get("up"):
                bgp_down.append({**_brief(r), "peer": n, "remote": p.get("remote") or "", "since": p.get("since")})
    stat = lambda key, n=10: sorted(({**_brief(r), "value": round(m[r["id"]][key], 1)} for r in rows if r["online"] and r["id"] in m and m[r["id"]][key] is not None),
                                    key=lambda x: -x["value"])[:n]
    lats = [m[i]["lat"] for i in m if m[i]["lat"] is not None]
    flaps = db.q(f"""SELECT e.device_id AS id, d.name, COUNT(*) AS n FROM events e JOIN devices d ON d.id = e.device_id
                     WHERE e.device_id IN ({ph}) AND e.ts > ? AND e.kind='link down' GROUP BY e.device_id ORDER BY n DESC LIMIT 10""", (*ids, now - 86400)) if ids else []
    cdown, ctotal = _checks_down(db, rows)
    return {"checks_down": cdown, "checks_total": ctotal,
            "online": sum(1 for r in rows if r["online"]), "total": len(rows), "links_total": links_total, "links_down": links_down,
            "bgp_total": bgp_total, "bgp_down": bgp_down, "avg_latency": round(sum(lats) / len(lats), 1) if lats else None,
            "lossy": [x for x in stat("loss") if x["value"] > 0], "latency": stat("lat"), "cpu": stat("cpu"), "mem": stat("mem"), "flaps": flaps}


def security(db, rows, geo, autoblock=None, region=None, now=None):
    now = now or time.time()
    ids = [r["id"] for r in rows]
    ph = ",".join("?" * len(ids)) or "NULL"
    from secevents import FAIL_KINDS
    fk = ",".join("?" * len(FAIL_KINDS))
    day = now - 86400
    # failed sign-ins on these routers (plus TikManager / the server for technicians - the caller decides by passing all=True rows)
    failed = db.one(f"SELECT COUNT(*) AS n FROM sec_events WHERE ts > ? AND kind IN ({fk}) AND device_id IN ({ph})", (day, *FAIL_KINDS, *ids))["n"] if ids else 0
    top = db.q(f"""SELECT ip, COUNT(*) AS n, COUNT(DISTINCT device_id) AS routers, MAX(ts) AS last FROM sec_events
                   WHERE ts > ? AND kind IN ({fk}) AND device_id IN ({ph}) AND ip <> '' GROUP BY ip ORDER BY n DESC LIMIT 10""", (day, *FAIL_KINDS, *ids)) if ids else []
    for t in top:
        t["country"], t["org"] = geo.lookup(t["ip"]) if geo else ("", "")
    drops, by_country, by_kind = 0, {}, {"geo": 0, "threat": 0}
    for l in db.q(f"""SELECT message FROM router_logs WHERE ts > ? AND device_id IN ({ph}) AND (message LIKE '%tm-geo-%' OR message LIKE '%tm-threat-%')
                      ORDER BY id DESC LIMIT 20000""", (day, *ids)) if ids else []:
        x = LOG_RE.search(l["message"])
        if not x:
            continue
        why, way, _p, s, _sp, t, _tp = x.groups()
        drops += 1
        by_kind[why] += 1
        cc = geo.lookup(s if way == "in" else t)[0] if geo else ""
        by_country[cc or "??"] = by_country.get(cc or "??", 0) + 1
    names = geo.names() if geo else {}
    cves = sorted(({**_brief(r), "cves": r.get("cve_n") or 0, "max": r.get("cve_max"), "version": r.get("version") or ""}
                   for r in rows if (r.get("cve_n") or 0) > 0), key=lambda x: (-(x["max"] or 0), -x["cves"]))
    blocked = len(autoblock.blocks() or {}) if autoblock else 0
    pols = region.policies() if region else {}
    orgs = {r["org_id"] for r in rows}
    reg = {"region": sum(1 for o, p in pols.items() if int(o) in orgs and region.region_on(p)),
           "threats": sum(1 for o, p in pols.items() if int(o) in orgs and p.get("threats"))} if region else {}
    states = {}
    for s in (db.q(f"SELECT state FROM region_sync WHERE device_id IN ({ph}) AND state <> 'off'", ids) if ids else []):
        states[s["state"]] = states.get(s["state"], 0) + 1
    return {"failed_24h": failed, "top_ips": top, "drops_24h": drops, "drops_by_kind": by_kind,
            "drops_by_country": [{"code": k, "name": names.get(k, "Unknown" if k == "??" else k), "n": v} for k, v in sorted(by_country.items(), key=lambda x: -x[1])[:10]],
            "cves": cves[:15], "cve_routers": len(cves), "flagged": [_brief(r) for r in rows if r.get("dm_flagged")], "blocked_now": blocked,
            "region": reg, "region_states": states, "clients_total": len(orgs)}


def maintenance(db, rows, now=None):
    now = now or time.time()
    ids = [r["id"] for r in rows]
    ph = ",".join("?" * len(ids)) or "NULL"
    backup_bad = sorted(({**_brief(r), "last": r.get("last_backup_at"), "error": r.get("last_backup_error") or ""}
                         for r in rows if r.get("last_backup_error") or not r.get("last_backup_at") or now - r["last_backup_at"] > BACKUP_STALE),
                        key=lambda x: x["last"] or 0)
    behind = [{**_brief(r), "version": (r.get("version") or "").replace(" (stable)", ""), "latest": r.get("ros_latest") or ""}
              for r in rows if _vt(r.get("ros_latest")) and _vt(r.get("version")) and _vt(r["ros_latest"]) > _vt(r["version"])]
    behind.sort(key=lambda x: _vt(x["version"]) or ())
    firmware = [{**_brief(r), "current": r.get("fw_current"), "upgrade": r.get("fw_upgrade")}
                for r in rows if r.get("fw_upgrade") and r.get("fw_current") and r["fw_upgrade"] != r["fw_current"]]
    sched = db.q(f"""SELECT u.scheduled_at, u.status, u.to_version, u.device_id AS id, d.name FROM upgrades u JOIN devices d ON d.id = u.device_id
                     WHERE u.device_id IN ({ph}) AND u.status IN ('scheduled','held') AND u.scheduled_at < ? ORDER BY u.scheduled_at LIMIT 20""",
                 (*ids, now + 7 * 86400)) if ids else []
    tasks = db.q("SELECT id, name, kind, next_run, last_status FROM tasks WHERE enabled=1 AND next_run IS NOT NULL AND next_run < ? ORDER BY next_run LIMIT 10",
                 (now + 7 * 86400,))
    failed_up = db.q(f"""SELECT u.finished_at, u.detail, u.to_version, u.device_id AS id, d.name FROM upgrades u JOIN devices d ON d.id = u.device_id
                         WHERE u.device_id IN ({ph}) AND u.status='failed' AND u.finished_at > ? ORDER BY u.finished_at DESC LIMIT 10""",
                     (*ids, now - 7 * 86400)) if ids else []
    lc = [{**_brief(r), "model": r.get("model") or "", "status": r.get("lc_status"), "made": r.get("lc_made")}
          for r in rows if r.get("lc_status") == "discontinued"]
    return {"total": len(rows), "backup_bad": backup_bad, "behind": behind, "firmware": firmware, "scheduled": sched, "tasks": tasks,
            "failed_upgrades": failed_up, "discontinued": lc}

def mobile(db, rows, tech, now=None):
    """The phone dashboard: counts, and one list of what needs attention - worst first, each a tap away from its router."""
    now = now or time.time()
    ids = [r["id"] for r in rows]
    ph = ",".join("?" * len(ids)) or "NULL"
    items = []
    add = lambda r, level, what, detail="", since=None: items.append({**_brief(r), "level": level, "what": what, "detail": detail, "since": since})
    for r in rows:
        if r.get("dm_flagged"):
            add(r, 0, "Possibly compromised", "RouterOS found signs of unauthorized access")
        if not r["online"]:
            add(r, 1, "Offline", r.get("last_error") or "", r.get("last_seen"))
            continue
        for n, l in (json.loads(r.get("isp_state") or "{}") or {}).items():
            if not l.get("up"):
                add(r, 1, "Internet link down", n + (f" ({l['comment']})" if l.get("comment") else ""), l.get("since"))
        for n, p in (json.loads(r.get("bgp_state") or "null") or {}).items():
            if not p.get("up"):
                add(r, 1, "BGP peer down", f"{n} {p.get('remote') or ''}".strip(), p.get("since"))
        if tech and (r.get("last_backup_error") or (r.get("last_backup_at") and now - r["last_backup_at"] > BACKUP_STALE)):
            add(r, 3, "Backup problem", r.get("last_backup_error") or "no backup for over 2 days", r.get("last_backup_at"))
    for x in _checks_down(db, rows)[0]:
        add(x, 1, "Critical check down", f"can't reach {x['check_name']} ({x['target']})", x["since"])
    alerts = []
    if tech and ids:
        alerts = db.q(f"""SELECT a.title, a.detail, a.opened_at, a.device_id AS id, d.name, o.name AS org FROM alerts a
                          LEFT JOIN devices d ON d.id = a.device_id LEFT JOIN orgs o ON o.id = a.org_id
                          WHERE a.resolved_at IS NULL AND (a.device_id IN ({ph}) OR a.device_id IS NULL) ORDER BY a.opened_at DESC LIMIT 20""", ids)
    items.sort(key=lambda i: (i["level"], -(i["since"] or 0)))
    events = db.q(f"""SELECT e.ts, e.kind, e.detail, e.device_id AS id, d.name FROM events e JOIN devices d ON d.id = e.device_id
                      WHERE e.device_id IN ({ph}) ORDER BY e.ts DESC LIMIT 15""", ids) if ids else []
    return {"online": sum(1 for r in rows if r["online"]), "total": len(rows), "attention": items[:50], "attention_count": len(items),
            "alerts": alerts, "events": events,
            "routers": [{"id": r["id"], "name": r["name"], "org": r.get("org") or "", "online": bool(r["online"]), "site": r.get("site") or "",
                         "ip": r.get("wan_ip") or r.get("public_ip") or "", "model": r.get("model") or ""} for r in rows]}
