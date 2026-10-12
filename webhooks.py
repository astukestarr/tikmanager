"""Webhooks: alerts sent to any HTTPS endpoint - Slack, Discord, ntfy, plain JSON, or your own format.

- Each webhook gets an alert when it opens and when it clears (optionally only some kinds), plus tests.
- Formats: json (TikManager's own payload), slack and discord (their incoming-webhook formats), ntfy (push to a phone:
  plain-text body with Title / Priority / Tags / Click headers) and custom (your method, headers and body template with
  {{placeholders}}, escaped for JSON when the body is JSON - so an SMS gateway or ticket system can be driven).
- Optional signing: with a secret, each request carries X-TikManager-Signature: sha256=<HMAC of timestamp.body> and
  X-TikManager-Timestamp, so the receiver can check it came from you.
- URLs, secrets and header values are stored encrypted (they often contain tokens) and never sent back to the browser.
- Only https:// to public internet addresses: never this server, the tunnel network or anything on a LAN.
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import ssl
import secrets as pysecrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

FORMATS = {"json": "TikManager JSON", "slack": "Slack", "discord": "Discord", "ntfy": "ntfy (phone push)", "custom": "Custom"}
PLACEHOLDERS = ("title", "detail", "status", "kind", "router", "client", "link", "time", "summary")
MAX_HOOKS = 20


class WebhookError(Exception):
    pass


def resolve(url: str):
    """(parsed URL, the public IP to connect to) - only https:// to a host whose every address is public."""
    u = urllib.parse.urlsplit(str(url or "").strip())
    if u.scheme != "https" or not u.hostname:
        raise WebhookError("The URL must start with https://")
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    except OSError:
        raise WebhookError(f"{u.hostname} can't be found (DNS).") from None
    for info in infos:
        if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
            raise WebhookError(f"{u.hostname} points to a private / local address - webhooks only go to the internet.")
    return u, infos[0][4][0]


def check_url(url: str) -> str:
    resolve(url)
    return url.strip()


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to the address that was checked (no second DNS lookup an attacker could change in between), with the
    certificate still checked against the host name."""
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _clean_header(v) -> str:
    return re.sub(r"[\r\n\x00]", " ", str(v))[:1000]


def _escape_json(v: str) -> str:
    return json.dumps(str(v))[1:-1]


class Webhooks:
    def __init__(self, db, vault):
        self.db, self.vault = db, vault
        self.lock = threading.Lock()

    # --- storage ------------------------------------------------------------------------------------------------
    def _all(self) -> list:
        try:
            v = json.loads(self.db.setting("webhooks", "") or "[]")
            return v if isinstance(v, list) else []
        except ValueError:
            return []

    def _put(self, hooks):
        self.db.set_setting("webhooks", json.dumps(hooks))

    def _secrets(self, h) -> dict:
        try:
            s = h.get("secrets") or {}
            return json.loads(self.vault.open(base64.b64decode(s["data"]), s["enc"], f"webhook:{h['id']}"))
        except Exception:  # noqa: BLE001 - unreadable: treat as empty, the page asks for the URL again
            return {}

    def _seal(self, hid, data: dict) -> dict:
        blob, enc = self.vault.seal(json.dumps(data).encode(), f"webhook:{hid}")
        return {"data": base64.b64encode(blob).decode(), "enc": enc}

    def public(self) -> list:
        status = json.loads(self.db.setting("webhook_status", "") or "{}")
        out = []
        for h in self._all():
            s = self._secrets(h)
            out.append({k: h.get(k) for k in ("id", "name", "format", "on", "kinds", "method", "body", "content_type")}
                       | {"host": urllib.parse.urlsplit(s.get("url", "")).hostname or "", "has_secret": bool(s.get("secret")),
                          "header_names": sorted((s.get("headers") or {}).keys()), "last": status.get(h["id"])})
        return out

    def save(self, b: dict, kinds_known) -> dict:
        hooks = self._all()
        hid = str(b.get("id") or "")
        cur = next((h for h in hooks if h["id"] == hid), None)
        if hid and not cur:
            raise WebhookError("That webhook no longer exists.")
        if not cur and len(hooks) >= MAX_HOOKS:
            raise WebhookError(f"At most {MAX_HOOKS} webhooks.")
        name = str(b.get("name") or "").strip()[:60]
        fmt = b.get("format")
        if not name or fmt not in FORMATS:
            raise WebhookError("Give it a name and pick a format.")
        old = self._secrets(cur) if cur else {}
        url = str(b.get("url") or "").strip() or old.get("url", "")
        if not url:
            raise WebhookError("Paste the webhook URL.")
        check_url(url)
        headers = dict(old.get("headers") or {})
        if "headers" in b:   # "Name: value" lines; a line "Name:" with no value keeps the saved value
            new = {}
            for line in str(b.get("headers") or "").splitlines()[:20]:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if not re.fullmatch(r"[A-Za-z0-9-]{1,60}", k) or k.lower() in ("host", "content-length"):
                    raise WebhookError(f"Not a header name: {k}")
                if "\n" in v or "\r" in v:
                    raise WebhookError("Header values can't contain line breaks.")
                new[k] = v[:1000] or headers.get(k, "")
            headers = new
        secret = old.get("secret", "")
        if b.get("secret_clear"):
            secret = ""
        elif str(b.get("secret") or ""):
            secret = str(b["secret"])[:200]
        kinds = [k for k in b.get("kinds") or [] if k in kinds_known]
        method = b.get("method") if b.get("method") in ("POST", "PUT", "GET") else "POST"
        body = str(b.get("body") or "")[:4000]
        ctype = str(b.get("content_type") or "application/json")[:100]
        if fmt == "custom" and method != "GET" and not body:
            raise WebhookError("Write the body your endpoint expects (placeholders like {{title}} are filled in).")
        h = cur or {"id": pysecrets.token_hex(6)}
        h.update(name=name, format=fmt, on=bool(b.get("on", True)), kinds=kinds, method=method, body=body, content_type=ctype)
        h["secrets"] = self._seal(h["id"], {"url": url, "secret": secret, "headers": headers})
        if not cur:
            hooks.append(h)
        self._put(hooks)
        return h

    def delete(self, hid):
        self._put([h for h in self._all() if h["id"] != hid])

    # --- sending ------------------------------------------------------------------------------------------------
    def build(self, h, s, ev) -> tuple:
        """(method, url, body bytes, headers) for one event."""
        status = ev["status"]
        mark = {"open": "Problem", "resolved": "Resolved", "test": "Test"}[status]
        summary = f"{mark}: {ev['title']}"
        values = {**{k: str(ev.get(k) or "") for k in PLACEHOLDERS}, "summary": summary}
        headers, url, method = {"User-Agent": "TikManager-Webhook"}, s["url"], "POST"
        fmt = h["format"]
        if fmt == "slack":
            text = f"{':white_check_mark:' if status == 'resolved' else ':warning:'} *{summary}*\n{ev['detail'][:2500]}" + (f"\n<{ev['link']}|Open in TikManager>" if ev.get("link") else "")
            body, ctype = json.dumps({"text": text}), "application/json"
        elif fmt == "discord":
            body, ctype = json.dumps({"content": f"**{summary}**\n{ev['detail'][:1500]}\n{ev.get('link') or ''}".strip()[:2000]}), "application/json"
        elif fmt == "ntfy":
            body, ctype = (ev["detail"] or ev["title"])[:3500], "text/plain; charset=utf-8"
            headers.update({"Title": summary[:200].encode("ascii", "replace").decode(), "Priority": "4" if status == "open" else "3",
                            "Tags": "white_check_mark" if status == "resolved" else "warning"})
            if ev.get("link"):
                headers["Click"] = ev["link"]
        elif fmt == "custom":
            method, ctype = h.get("method") or "POST", h.get("content_type") or "application/json"
            is_json = "json" in ctype
            fill = lambda tpl, esc: re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: esc(values.get(m.group(1), m.group(0))), tpl)
            url = fill(url, lambda v: urllib.parse.quote(v, safe=""))
            body = fill(h.get("body") or "", _escape_json if is_json else (lambda v: v))
        else:   # json
            body, ctype = json.dumps({"event": {"open": "alert.opened", "resolved": "alert.resolved"}.get(status, "test"), **{k: ev.get(k) for k in ("status", "kind", "title", "detail", "router",
                                      "router_id", "client", "link", "time")}, "source": "TikManager"}), "application/json"
        data = body.encode() if method != "GET" else b""
        if data:
            headers["Content-Type"] = ctype
        headers.update(s.get("headers") or {})
        if s.get("secret"):
            ts = str(int(time.time()))
            headers["X-TikManager-Timestamp"] = ts
            headers["X-TikManager-Signature"] = "sha256=" + hmac.new(s["secret"].encode(), ts.encode() + b"." + data, hashlib.sha256).hexdigest()
        return method, url, data, headers

    def send(self, h, ev):
        s = self._secrets(h)
        if not s.get("url"):
            raise WebhookError("No URL saved - edit the webhook and paste it again.")
        method, url, data, headers = self.build(h, s, ev)
        u, ip = resolve(url)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        conn = _PinnedHTTPS(u.hostname, ip, u.port or 443, 10)
        try:   # http.client never follows redirects - a redirect can't send the alert somewhere else (or onto the LAN)
            conn.request(method, path, body=data or None, headers={k: _clean_header(v) for k, v in headers.items()})
            r = conn.getresponse()
            body = r.read(300)
            if r.status >= 300:
                raise WebhookError(f"HTTP {r.status}" + (" (redirects aren't followed - use the final URL)" if 300 <= r.status < 400 else "")
                                   + f": {body.decode('utf-8', 'replace')}")
            return r.status
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            raise WebhookError(f"Couldn't reach it: {e}") from None
        finally:
            conn.close()

    def _record(self, hid, ok, msg):
        with self.lock:
            st = json.loads(self.db.setting("webhook_status", "") or "{}")
            st[hid] = {"at": time.time(), "ok": ok, "msg": str(msg)[:300]}
            self.db.set_setting("webhook_status", json.dumps(st))

    def send_all(self, ev):
        for h in self._all():
            if not h.get("on") or (h.get("kinds") and ev.get("kind") not in h["kinds"]):
                continue
            try:
                code = self.send(h, ev)
                self._record(h["id"], True, f"HTTP {code}")
            except WebhookError as e:
                self._record(h["id"], False, e)
            except Exception as e:  # noqa: BLE001 - one broken webhook must never stop the other alerts going out
                self._record(h["id"], False, f"Error: {e}")

    def test(self, hid, link):
        h = next((x for x in self._all() if x["id"] == hid), None)
        if not h:
            raise WebhookError("That webhook no longer exists.")
        ev = {"status": "test", "kind": "test", "title": "Test alert from TikManager", "router": "", "client": "", "link": link,
              "detail": "If you can read this, alerts reach this webhook. Nothing is wrong.", "time": time.strftime("%Y-%m-%d %H:%M")}
        try:
            code = self.send(h, ev)
        except WebhookError as e:
            self._record(hid, False, e)
            raise
        self._record(hid, True, f"HTTP {code}")
        return f"Sent - the endpoint answered HTTP {code}."
