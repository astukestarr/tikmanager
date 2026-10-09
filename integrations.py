"""ConnectWise PSA and IT Glue.

- Credentials are entered on Admin > Integrations and stored in the settings table encrypted with the vault (AES-256-GCM,
  bound to 'integration:<kind>'); secrets are never sent back to the browser - the page only learns whether one is saved.
- ConnectWise PSA (read-only API member is enough): list companies, import them as TikManager clients or link existing ones.
- IT Glue: link clients to IT Glue organizations and keep each router documented as a configuration (name, model, serial,
  WAN IP, RouterOS version, link back to TikManager) - nightly when enabled, or on demand.
In dev mode, the value "demo" (CW site / IT Glue API key) returns sample data instead of calling the real services.
"""
import base64
import json
import re
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

ITG_REGIONS = {"us": "https://api.itglue.com", "eu": "https://api.eu.itglue.com", "au": "https://api.au.itglue.com"}
FIELDS = {   # name -> secret?
    "cw": {"site": False, "company": False, "public_key": False, "private_key": True, "client_id": False, "codebase": False,
           "show_types": False, "active_only": False},   # which company types / statuses the import list shows
    "itg": {"region": False, "api_key": True, "config_type_id": False, "config_status_id": False, "sync": False},
    "teams": {"webhook": True},
    "github": {"library": False, "token": True},   # community script library (scriptlib.py); the token is only for sharing   # a Teams Workflows "post to a channel when a webhook request is received" URL (alerts.py)
}
DEFAULTS = {"cw": {"site": "api-na.myconnectwise.net", "codebase": "v4_6_release", "active_only": "1"}, "itg": {"region": "us", "sync": "1"},
            "github": {"library": "astukestarr/routeros-scripts"}}


class IntegrationError(Exception):
    pass


def norm(name):
    """Company names for matching: lower case, no punctuation or common suffixes."""
    n = re.sub(r"[^a-z0-9 ]", " ", (name or "").lower())
    return " ".join(w for w in n.split() if w not in ("inc", "llc", "ltd", "co", "corp", "corporation", "company", "the", "pc", "pllc"))


class Integrations:
    def __init__(self, db, vault, s):
        self.db, self.vault, self.s = db, vault, s
        self._cache = {}
        self.sync_state = {"running": False}

    # --- settings ---------------------------------------------------------------------------------------------
    def _raw(self, kind):
        v = self.db.setting(f"integration_{kind}")
        if not v:
            return {}
        try:
            blob = json.loads(v)
            return json.loads(self.vault.open(base64.b64decode(blob["data"]), blob["enc"], f"integration:{kind}"))
        except Exception:  # noqa: BLE001 - unreadable (e.g. master key replaced): treat as not configured
            traceback.print_exc()
            return {}

    def config(self, kind):
        return {**DEFAULTS.get(kind, {}), **self._raw(kind)}

    def public(self, kind):
        c = self.config(kind)
        out = {k: ("" if secret else c.get(k, "")) for k, secret in FIELDS[kind].items()}
        out.update({f"{k}_set": bool(c.get(k)) for k, secret in FIELDS[kind].items() if secret})
        out["configured"] = self.configured(kind)
        return out

    def configured(self, kind):
        c = self.config(kind)
        need = {"cw": ("site", "company", "public_key", "private_key", "client_id"), "teams": ("webhook",), "github": ("token",)}.get(kind, ("api_key",))
        return all(c.get(k) for k in need)

    def save(self, kind, data):
        c = self._raw(kind)
        for k, secret in FIELDS[kind].items():
            if k not in data:
                continue
            v = str(data.get(k) or "").strip()[:4000 if k in ("show_types", "webhook") else 300]
            if secret and not v:
                continue   # blank = keep the saved secret
            c[k] = v
        for k in data.get("clear") or []:
            if k in FIELDS[kind]:
                c.pop(k, None)
        if kind == "cw" and c.get("site"):
            c["site"] = re.sub(r"^https?://", "", c["site"]).strip("/")
            if not re.fullmatch(r"[A-Za-z0-9.-]+", c["site"]):
                raise ValueError("The site is a host name like api-na.myconnectwise.net.")
        if kind == "teams" and c.get("webhook") and c["webhook"] != "demo":
            u = urllib.parse.urlparse(c["webhook"])
            if u.scheme != "https" or not (u.hostname or "").endswith((".logic.azure.com", ".powerplatform.com", ".webhook.office.com")):
                raise ValueError("Paste the HTTPS URL from the Teams workflow \"Post to a channel when a webhook request is received\".")
        if kind == "github" and c.get("library") and not re.fullmatch(r"[\w.-]+/[\w.-]+", c["library"]):
            raise ValueError("The library is a GitHub repository like owner/repository.")
        if kind == "itg" and c.get("region", "us") not in ITG_REGIONS:
            raise ValueError("Pick the IT Glue region.")
        blob, enc = self.vault.seal(json.dumps(c).encode(), f"integration:{kind}")
        self.db.set_setting(f"integration_{kind}", json.dumps({"data": base64.b64encode(blob).decode(), "enc": enc}))
        self._cache.clear()

    # --- HTTP -------------------------------------------------------------------------------------------------
    @staticmethod
    def _http(method, url, headers, body=None, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            detail = e.read()[:400].decode("utf-8", "replace")
            try:
                j = json.loads(detail)
                detail = j.get("message") or (j.get("errors") or [{}])[0].get("detail") or (j.get("errors") or [{}])[0].get("title") or detail
            except (ValueError, AttributeError, IndexError):
                pass
            hint = {401: " (check the keys)", 403: " (the API member/key lacks permission)", 404: " (check the site / region)"}.get(e.code, "")
            raise IntegrationError(f"HTTP {e.code}{hint}: {str(detail)[:200]}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise IntegrationError(f"Couldn't reach the service: {getattr(e, 'reason', e)}") from None

    def _cached(self, key, fn, ttl=300):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        v = fn()
        self._cache[key] = (time.time(), v)
        return v

    def _demo(self, kind):
        c = self.config(kind)
        return self.s.dev and (c.get("site") if kind == "cw" else c.get("api_key")) == "demo"

    # --- ConnectWise PSA --------------------------------------------------------------------------------------
    def _cw(self, path, params=None, method="GET", body=None):
        c = self.config("cw")
        if not self.configured("cw"):
            raise IntegrationError("ConnectWise PSA isn't set up yet.")
        token = base64.b64encode(f"{c['company']}+{c['public_key']}:{c['private_key']}".encode()).decode()
        url = f"https://{c['site']}/{(c.get('codebase') or 'v4_6_release').strip('/')}/apis/3.0{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._http(method, url, {"Authorization": f"Basic {token}", "clientId": c["client_id"], "Content-Type": "application/json"}, body)

    # tickets for alerts (alerts.py): the API member needs Service Desk > Service Tickets add / edit / inquire
    def cw_boards(self):
        if self._demo("cw"):
            return [{"id": 1, "name": "Help Desk"}, {"id": 2, "name": "Network Alerts"}]
        return [{"id": b["id"], "name": b.get("name", "")} for b in self._cw("/service/boards", {"conditions": "inactiveFlag=false", "fields": "id,name", "pageSize": 200}) or []]

    def cw_statuses(self, board_id):
        if self._demo("cw"):
            return [{"id": 11, "name": "New", "closed": False}, {"id": 12, "name": "In Progress", "closed": False}, {"id": 19, "name": ">Closed", "closed": True}]
        return [{"id": s["id"], "name": s.get("name", ""), "closed": bool(s.get("closedStatus"))}
                for s in self._cw(f"/service/boards/{int(board_id)}/statuses", {"fields": "id,name,closedStatus", "pageSize": 200}) or []]

    def cw_priorities(self):
        if self._demo("cw"):
            return [{"id": 4, "name": "Priority 1 - Emergency"}, {"id": 8, "name": "Priority 3 - Normal"}]
        return [{"id": p["id"], "name": p.get("name", "")} for p in self._cw("/service/priorities", {"fields": "id,name", "pageSize": 100}) or []]

    def cw_ticket(self, company_id, board_id, summary, text, status_id=None, priority_id=None):
        """Open a service ticket; returns its number."""
        if self._demo("cw"):
            return 90000 + int(time.time()) % 10000
        body = {"summary": summary[:100], "board": {"id": int(board_id)}, "company": {"id": int(company_id)}, "initialDescription": text[:8000]}
        if status_id:
            body["status"] = {"id": int(status_id)}
        if priority_id:
            body["priority"] = {"id": int(priority_id)}
        return (self._cw("/service/tickets", method="POST", body=body) or {}).get("id")

    def cw_close(self, ticket_id, text, closed_status_id=None):
        """Add an internal note, and close the ticket if a closed status is set."""
        if self._demo("cw"):
            return
        self._cw(f"/service/tickets/{int(ticket_id)}/notes", method="POST", body={"text": text[:8000], "internalAnalysisFlag": True})
        if closed_status_id:
            self._cw(f"/service/tickets/{int(ticket_id)}", method="PATCH",
                     body=[{"op": "replace", "path": "status", "value": {"id": int(closed_status_id)}}])

    def teams_post(self, card):
        """Post an Adaptive Card to the Teams workflow webhook."""
        url = self.config("teams").get("webhook")
        if not url:
            raise IntegrationError("No Teams webhook saved.")
        if url == "demo" and self.s.dev:
            return
        self._http("POST", url, {"Content-Type": "application/json"},
                   {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]})

    def cw_test(self):
        if self._demo("cw"):
            return "Connected to ConnectWise PSA (demo data)."
        info = self._cw("/system/info") or {}
        return f"Connected to ConnectWise PSA {info.get('version', '')}".strip() + "."

    def cw_companies(self, refresh=False):
        if refresh:
            self._cache.pop("cw_companies", None)
        if self._demo("cw"):
            return [{"id": 100 + i, "identifier": n.replace(" ", "")[:12], "name": n, "status": "Active", "types": t}
                    for i, (n, t) in enumerate([("Example MSP (internal)", "Internal"), ("Rebein Brothers", "Client"), ("Acme Dental", "Client"),
                                                ("Hillside Clinic", "Client"), ("Old Customer LLC", "Former Client"),
                                                ("Depot Theater Company", ""), ("Ingram Micro", "Vendor")])]

        def load():
            out, page = [], 1
            while page < 50:
                batch = self._cw("/company/companies", {"conditions": "deletedFlag=false", "fields": "id,identifier,name,status/name,types",
                                                        "orderBy": "name", "pageSize": 1000, "page": page}) or []
                out += [{"id": x["id"], "identifier": x.get("identifier", ""), "name": x.get("name", ""),
                         "status": (x.get("status") or {}).get("name", ""), "types": ", ".join(t.get("name", "") for t in x.get("types") or [])}
                        for x in batch]
                if len(batch) < 1000:
                    return out
                page += 1
            return out
        return self._cached("cw_companies", load)

    def cw_find(self, q):
        """Look a company up in ConnectWise by name, deleted ones included - explains why it isn't in the list."""
        q = re.sub(r"[^\w &.,'-]", "", q)[:60].replace("'", "\\'").strip()
        if not q:
            return []
        if self._demo("cw"):
            return [c | {"deleted": False} for c in self.cw_companies() if q.lower() in c["name"].lower()]
        rows = self._cw("/company/companies", {"conditions": f"name like '%{q}%'", "fields": "id,identifier,name,status/name,types,deletedFlag",
                                               "pageSize": 50}) or []
        return [{"id": x["id"], "identifier": x.get("identifier", ""), "name": x.get("name", ""), "status": (x.get("status") or {}).get("name", ""),
                 "types": ", ".join(t.get("name", "") for t in x.get("types") or []), "deleted": bool(x.get("deletedFlag"))} for x in rows]

    # --- IT Glue ----------------------------------------------------------------------------------------------
    def _itg(self, method, path, params=None, body=None):
        c = self.config("itg")
        if not self.configured("itg"):
            raise IntegrationError("IT Glue isn't set up yet.")
        url = ITG_REGIONS.get(c.get("region") or "us", ITG_REGIONS["us"]) + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._http(method, url, {"x-api-key": c["api_key"], "Content-Type": "application/vnd.api+json"}, body)

    def _itg_all(self, path, params=None):
        out, page = [], 1
        while page < 50:
            r = self._itg("GET", path, {**(params or {}), "page[size]": 1000, "page[number]": page}) or {}
            out += r.get("data") or []
            if not (r.get("meta") or {}).get("next-page"):
                return out
            page += 1
        return out

    def itg_test(self):
        if self._demo("itg"):
            return "Connected to IT Glue (demo data)."
        r = self._itg("GET", "/organizations", {"page[size]": 1}) or {}
        return f"Connected to IT Glue - {(r.get('meta') or {}).get('total-count', '?')} organizations."

    def itg_lookups(self, refresh=False):
        """Organizations, configuration types and statuses (for the mapping table and the sync settings)."""
        if refresh:
            self._cache.pop("itg_lookups", None)
        if self._demo("itg"):
            return {"orgs": [{"id": str(9000 + i), "name": n} for i, n in enumerate(["Example MSP (internal)", "Rebein Brothers Inc.", "Acme Dental", "Hillside Clinic"])],
                    "types": [{"id": "1", "name": "Firewall"}, {"id": "2", "name": "Router"}, {"id": "3", "name": "Switch"}],
                    "statuses": [{"id": "10", "name": "Active"}, {"id": "11", "name": "Inactive"}]}

        def load():
            pick = lambda rows: sorted(({"id": x["id"], "name": (x.get("attributes") or {}).get("name", "")} for x in rows), key=lambda x: x["name"].lower())
            return {"orgs": pick(self._itg_all("/organizations", {"sort": "name"})), "types": pick(self._itg_all("/configuration_types")),
                    "statuses": pick(self._itg_all("/configuration_statuses"))}
        return self._cached("itg_lookups", load)

    def itg_sync_device(self, d, org_itg_id, public_url):
        c = self.config("itg")
        mac = next((i.get("mac") for i in json.loads(d.get("interfaces") or "[]") if i.get("name") == "ether1" and i.get("mac")), "")
        attrs = {"name": d["name"], "hostname": d.get("identity") or d["name"], "primary-ip": d.get("wan_ip") or None,
                 "serial-number": d.get("serial") or None, "mac-address": mac or None,
                 "operating-system-notes": f"RouterOS {(d.get('version') or '').split(' ')[0]}".strip(),
                 "notes": f"MikroTik {d.get('model') or ''}. Managed in TikManager: {public_url}/#router/{d['id']}"}
        if c.get("config_type_id"):
            attrs["configuration-type-id"] = int(c["config_type_id"])
        if c.get("config_status_id"):
            attrs["configuration-status-id"] = int(c["config_status_id"])
        attrs = {k: v for k, v in attrs.items() if v is not None}
        if self._demo("itg"):
            return d.get("itg_config_id") or str(70000 + d["id"])
        cid = d.get("itg_config_id")
        if not cid and d.get("serial"):   # an existing configuration with the same serial (e.g. documented by hand)
            found = self._itg("GET", "/configurations", {"filter[organization_id]": org_itg_id, "filter[serial_number]": d["serial"]}) or {}
            cid = ((found.get("data") or [{}])[0]).get("id")
        if cid:
            try:
                self._itg("PATCH", f"/configurations/{cid}", body={"data": {"type": "configurations", "attributes": attrs}})
                return cid
            except IntegrationError as e:
                if "HTTP 404" not in str(e):
                    raise
        if not c.get("config_type_id"):
            raise IntegrationError("Pick the IT Glue configuration type for routers (Admin > Integrations) first.")
        r = self._itg("POST", "/configurations", body={"data": {"type": "configurations",
                                                                "attributes": {"organization-id": int(org_itg_id), **attrs}}})
        return (r.get("data") or {}).get("id")

    def itg_sync(self, public_url, device_ids=None):
        """Create/update an IT Glue configuration for every router whose client is linked. Returns a summary."""
        if self.sync_state["running"]:
            return self.sync_state
        self.sync_state = {"running": True, "started": time.time(), "ok": 0, "failed": 0, "skipped": 0, "errors": []}
        try:
            rows = self.db.q("""SELECT d.*, o.itg_id FROM devices d JOIN orgs o ON o.id = d.org_id WHERE d.state='adopted'""")
            for d in rows:
                if device_ids and d["id"] not in device_ids:
                    continue
                if not d["itg_id"]:
                    self.sync_state["skipped"] += 1
                    continue
                try:
                    cid = self.itg_sync_device(d, d["itg_id"], public_url)
                    self.db.run("UPDATE devices SET itg_config_id=?, itg_synced_at=?, itg_error=NULL WHERE id=?", (cid, time.time(), d["id"]))
                    self.sync_state["ok"] += 1
                except IntegrationError as e:
                    self.db.run("UPDATE devices SET itg_error=? WHERE id=?", (str(e)[:300], d["id"]))
                    self.sync_state["failed"] += 1
                    self.sync_state["errors"].append(f"{d['name']}: {e}")
        finally:
            self.sync_state.update(running=False, finished=time.time(), errors=self.sync_state["errors"][:20])
            self.db.set_setting("itg_last_sync", json.dumps(self.sync_state))
        return self.sync_state

    def loop(self, public_url):
        while True:
            time.sleep(600)
            try:
                c = self.config("itg")
                last = json.loads(self.db.setting("itg_last_sync") or "{}").get("finished", 0)
                if self.configured("itg") and c.get("sync") == "1" and time.time() - last > 86400:
                    self.itg_sync(public_url)
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def start(self, public_url):
        threading.Thread(target=self.loop, args=(public_url,), daemon=True, name="integrations").start()
