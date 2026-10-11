"""Connectivity test from the internet (Admin > Version & updates > Run connectivity test).

A firewall can look right from inside the server and still block the internet, so this checks from the outside in:
- DNS: the public name (TM_PUBLIC_URL) resolves - via Cloudflare's public DNS-over-HTTPS - to the address this server
  reaches the internet from (Cloudflare's /cdn-cgi/trace).
- TCP 443 (HTTPS: people, routers adopting) and 80 (certificate renewals, redirect) must be OPEN; TCP 22 (SSH) and the
  app's own port (TM_PORT, normally behind Caddy) must be CLOSED - each tried from 3 servers in different countries by
  check-host.net's public API.
- UDP 51820 (WireGuard) can't be tested by a public checker - WireGuard ignores anything that isn't a valid handshake -
  so the proof is TikManager's own routers: one that's online over its tunnel from a different public address than the
  server's got in through that port from the internet.
Only the public host name and port numbers are sent to those services. Runs on request (it takes ~20 seconds) and once after
every upgrade; the last result is kept. Not available in dev mode or for addresses the internet can't reach.
"""
import json
import threading
import time
import traceback
import urllib.parse
import urllib.request

from version import __version__

UA = {"User-Agent": f"TikManager/{__version__}", "Accept": "application/json"}


def _get(url, timeout=20, accept="application/json"):
    with urllib.request.urlopen(urllib.request.Request(url, headers={**UA, "Accept": accept}), timeout=timeout) as r:
        return r.read(256 * 1024).decode("utf-8", "replace")


def public_ip():
    for line in _get("https://1.1.1.1/cdn-cgi/trace").splitlines():
        if line.startswith("ip="):
            return line[3:].strip()
    return ""


def resolve(host):
    d = json.loads(_get(f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A", accept="application/dns-json"))
    return [a["data"] for a in d.get("Answer") or [] if a.get("type") == 1]


def tcp_from_outside(host, port, nodes=3):
    """check-host.net: try a TCP connection from `nodes` servers -> (open count, tried count, [(country, ok, detail)])."""
    start = json.loads(_get(f"https://check-host.net/check-tcp?host={urllib.parse.quote(host)}:{int(port)}&max_nodes={nodes}"))
    rid, where = start.get("request_id"), start.get("nodes") or {}
    if not rid:
        raise RuntimeError("check-host.net didn't accept the test")
    res = {}
    for _ in range(10):   # results arrive within a few seconds
        time.sleep(2)
        res = json.loads(_get(f"https://check-host.net/check-result/{urllib.parse.quote(rid)}"))
        if res and all(v is not None for v in res.values()):
            break
    out = []
    for node, v in res.items():
        country = (where.get(node) or ["", "?"])[1]
        if not v:
            out.append((country, None, "no answer"))
        elif isinstance(v[0], dict) and "error" in v[0]:
            out.append((country, False, v[0]["error"]))
        else:
            out.append((country, True, f"{v[0].get('time', 0) * 1000:.0f} ms"))
    return sum(1 for x in out if x[1]), sum(1 for x in out if x[1] is not None), out


class Reachability:
    def __init__(self, db, settings, observatory):
        self.db, self.s, self.observatory = db, settings, observatory
        self.lock = threading.Lock()
        self.running = False

    def supported(self):
        return self.observatory.supported()   # same rule: a public address, not dev mode

    def info(self):
        try:
            last = json.loads(self.db.setting("reachability_last", "") or "{}")
        except ValueError:
            last = {}
        return {"supported": self.supported(), "running": self.running, "host": self.observatory.host, **last}

    def loop(self):
        """Once after every upgrade (and the first start), 10 minutes in - then only on request."""
        time.sleep(600)
        try:
            if self.supported() and not self.running and self.info().get("version") != __version__:
                self.start()
        except Exception:  # noqa: BLE001
            traceback.print_exc()

    def start_loop(self):
        threading.Thread(target=self.loop, daemon=True, name="reachability-auto").start()

    def start(self):
        if not self.supported():
            raise ValueError("The connectivity test needs TikManager's public address (TM_PUBLIC_URL) - it isn't available in dev mode.")
        with self.lock:
            if self.running:
                raise ValueError("A connectivity test is already running.")
            self.running = True
        threading.Thread(target=self._run, daemon=True, name="reachability").start()

    def _run(self):
        try:
            self.db.set_setting("reachability_last", json.dumps({"at": time.time(), "version": __version__, "results": self.run()}))
        except Exception:  # noqa: BLE001
            traceback.print_exc()
        finally:
            self.running = False

    def run(self):
        host = self.observatory.host
        rows = []

        def add(cid, status, text):
            rows.append({"id": cid, "status": status, "text": text})
        try:
            mine = public_ip()
        except Exception as e:  # noqa: BLE001
            mine = ""
            add("net_ip", "warn", f"Couldn't find this server's public address ({e})")
        try:
            ips = resolve(host)
            if not ips:
                add("net_dns", "fail", f"{host} has no DNS (A) record - routers and people can't find TikManager")
            elif mine and mine not in ips:   # common with several public addresses (in on one, out on another) - the port tests below are the proof
                add("net_dns", "pass", f"{host} points at {', '.join(ips)} (this server's outgoing address is {mine} - normal when incoming "
                                       "and outgoing traffic use different public addresses; the port tests below show whether it works)")
            else:
                add("net_dns", "pass", f"{host} points at {', '.join(ips)}" + (" - this server" if mine else ""))
        except Exception as e:  # noqa: BLE001
            add("net_dns", "warn", f"Couldn't look up {host} in public DNS ({e})")

        def port(cid, p, want_open, what):
            try:
                ok, tried, detail = tcp_from_outside(host, p)
            except Exception as e:  # noqa: BLE001
                add(cid, "warn", f"Couldn't test TCP {p} from outside ({e})")
                return
            where = ", ".join(f"{c} {'open' if o else 'closed' if o is False else '?'}" for c, o, _ in detail)
            if tried == 0:
                add(cid, "warn", f"TCP {p}: check-host.net's servers didn't answer - try again in a minute")
            elif want_open:
                add(cid, "pass" if ok == tried else "warn" if ok else "fail",
                    f"TCP {p} ({what}) is {'open' if ok == tried else 'open from some places only' if ok else 'NOT reachable'} from the internet ({where})")
            else:
                add(cid, "pass" if ok == 0 else "fail" if cid == "net_app" else "warn",
                    f"TCP {p} ({what}) is {'closed' if ok == 0 else 'OPEN'} from the internet ({where})")
        port("net_443", 443, True, "HTTPS - people and routers")
        port("net_80", 80, True, "HTTP - certificate renewals")
        port("net_22", 22, False, "SSH")
        app_port = int(getattr(self.s, "port", 8800) or 8800)
        if app_port not in (80, 443):
            port("net_app", app_port, False, "TikManager's own app port, normally only behind Caddy")
        # WireGuard: routers online over their tunnels from somewhere else prove UDP 51820 gets in
        routers = self.db.q("SELECT name, online, wan_ip, public_ip FROM devices WHERE state='adopted'")
        outside = [r for r in routers if r["online"] and (r["public_ip"] or r["wan_ip"]) and (r["public_ip"] or r["wan_ip"]) != mine]
        if outside:
            add("net_wg", "pass", f"UDP 51820 (WireGuard) gets in: {len(outside)} router{'s' if len(outside) != 1 else ''} online over their tunnels "
                                  f"from other places (e.g. {', '.join(r['name'] for r in outside[:3])})")
        elif any(r["online"] for r in routers):
            add("net_wg", "warn", "UDP 51820 (WireGuard): the routers online are all on this server's own network, so this doesn't prove "
                                  "routers elsewhere can connect - it's confirmed once one at another site comes online")
        elif routers:
            add("net_wg", "fail", "UDP 51820 (WireGuard): no router is online over its tunnel - check UDP 51820 is forwarded to this server")
        else:
            add("net_wg", "warn", "UDP 51820 (WireGuard) can't be tested from outside - it's confirmed when the first router comes online. "
                                  "Make sure it's forwarded to this server")
        return rows
