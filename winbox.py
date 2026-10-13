"""Winbox to any router through TikManager - no Winbox port open on the routers' internet side.

A technician clicks "Open Winbox" on a router's page: TikManager opens one port from a small pool on its own public
address (TM_WINBOX_PORTS, default 40000-40049) and relays it to the router's Winbox service over the router's existing
WireGuard tunnel - which works even for routers with no public address of their own. They type host:port into Winbox
and sign in with their own router login (TikManager's own router account has no Winbox permission).

- A session accepts connections only from the public address the technician opened it from (they can change it, e.g.
  when their Winbox goes out through a VPN); anyone else is disconnected at once and recorded on the Security page.
- 30 minutes (Extend adds 30, up to 4 hours), closed after 10 minutes without traffic, or by the technician.
- A user-space relay: IP forwarding stays off on the server, so routers still can't reach each other or the LAN through
  it. Winbox's own encryption passes through untouched - TikManager can't read it.
- Every session (who, router, from where, how long, how much) goes to the audit log and the Security page.
- Who changed what: each session gets its own temporary router login (e.g. alan.tm) with a random password, in the
  router's "full" group for TikManager administrators / technicians and "read" for read-only technicians, allowed to
  sign in only from TikManager's tunnel address, and deleted when the session ends (leftovers are swept every hour).
  So the router's own log says "changed by alan.tm". When the session ends a configuration backup is taken, so "What
  changed" shows exactly what that session did. Router log lines from the relay are labelled with the session's
  technician on the Security page, even when someone signs in with a shared login.
"""
import asyncio
import ipaddress
import re
import secrets
import threading
import time
import traceback

SESSION = 30 * 60
EXTEND = 30 * 60
MAX_LIFE = 4 * 3600
IDLE = 10 * 60


def port_range(spec):
    try:
        a, b = (int(x) for x in str(spec or "40000-40049").split("-"))
        if 1024 <= a <= b <= 65535 and b - a < 1000:
            return range(a, b + 1)
    except ValueError:
        pass
    return range(40000, 40050)


class WinboxRelay:
    def __init__(self, db, settings, secev, client_for=None, backups=None):
        self.db, self.s, self.secev, self.client_for, self.backups = db, settings, secev, client_for, backups
        self.recent = []   # closed sessions, for labelling router log lines that arrive a little later
        self.ports = port_range(getattr(settings, "winbox_ports", ""))
        self.sessions = {}   # port -> session dict
        self.lock = threading.Lock()
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self._run_loop, daemon=True, name="winbox-relay").start()
        threading.Thread(target=self._sweeper, daemon=True, name="winbox-sweep").start()
        if getattr(settings, "dev", False):   # dev: a stand-in "router Winbox" on this PC so sessions can be tried end to end
            self._call(asyncio.start_server(self._dev_winbox, host="127.0.0.1", port=18291))

    async def _dev_winbox(self, reader, writer):
        writer.write(b"TikManager dev: simulated router Winbox - you're connected through the relay.\r\n")
        await writer.drain()
        while data := await reader.read(4096):
            writer.write(b"echo: " + data)
            await writer.drain()
        writer.close()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.create_task(self._reaper())
        self.loop.run_forever()

    def _call(self, coro, timeout=10):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    # --- public API (called from request threads) ------------------------------------------------------------
    def view(self, s):
        return [self._pub(x, x["user"] == s["email"]) | {"active": len(x["writers"]) // 2, "mine": x["user"] == s["email"]}
                for _, x in sorted(self.sessions.items()) if s["kind"] != "client" or x.get("org_id") == s["org_id"]]

    def _device(self, device_id):
        return self.db.one("SELECT * FROM devices WHERE id=?", (device_id,))

    def open(self, d, user, allow_ip, target_port=8291, group="read"):
        try:
            ipaddress.ip_address(allow_ip)
        except ValueError:
            raise ValueError("That isn't an IP address.") from None
        target = ("127.0.0.1", 18291) if getattr(self.s, "dev", False) else (d["tunnel_ip"], int(target_port or 8291))
        with self.lock:
            mine = next((x for x in self.sessions.values() if x["device_id"] == d["id"] and x["user"] == user), None)
            if mine:   # one session per technician per router: reuse it (new address, fresh timer)
                mine.update(allow_ip=allow_ip, expires=max(mine["expires"], time.time() + SESSION))
                return self._pub(mine, True)
            free = next((p for p in self.ports if p not in self.sessions), None)
            if free is None:
                raise ValueError(f"All {len(self.ports)} Winbox ports are in use - close a session you no longer need.")
            base = re.sub(r"[^a-z0-9]", "", user.split("@")[0].lower())[:16] or "tech"
            x = {"port": free, "device_id": d["id"], "device": d["name"], "org_id": d.get("org_id"), "user": user, "allow_ip": allow_ip,
                 "target": target, "opened": time.time(), "expires": time.time() + SESSION, "last": time.time(), "bytes": 0, "conns": 0,
                 "writers": set(), "server": None, "router_user": f"{base}.tm", "password": secrets.token_urlsafe(15), "group": group}
            self.sessions[free] = x
        if self.client_for:   # the session's own router login (only from TikManager's tunnel address)
            try:
                cl = self.client_for(d)
                cl.session_user_remove(x["router_user"])   # a leftover from an earlier session
                cl.session_user_add(x["router_user"], group, x["password"], self.s.wg_server_ip,
                                    f"{user}, opened {time.strftime('%Y-%m-%d %H:%M')}, removed when the session ends")
            except Exception as e:  # noqa: BLE001 - RouterError or similar
                with self.lock:
                    self.sessions.pop(free, None)
                raise ValueError(f"Couldn't create the temporary router login: {e}") from None
        try:
            x["server"] = self._call(asyncio.start_server(lambda r, w, x=x: self._handle(x, r, w), host="0.0.0.0", port=free))
        except Exception as e:  # noqa: BLE001 - port taken by something else
            with self.lock:
                self.sessions.pop(free, None)
            self._remove_login(x)
            raise ValueError(f"Couldn't open port {free}: {e}") from None
        self.db.audit(user, "Winbox session opened", d["name"], allow_ip, org_id=d.get("org_id"),
                      detail=f"port {free} -> {target[0]}:{target[1]}, router login {x['router_user']} ({group})")
        self.secev.record("tikmanager", "remote_session", user, allow_ip, "winbox", f"opened port {free} to {d['name']} as {x['router_user']} ({group})",
                          device_id=d["id"])
        return self._pub(x, True)

    def _pub(self, x, owner=False):
        out = {k: x[k] for k in ("port", "device_id", "device", "user", "allow_ip", "opened", "expires", "last", "bytes", "conns", "router_user", "group")}
        if owner:
            out["password"] = x["password"]   # only ever to the technician who opened it
        return out

    def _remove_login(self, x):
        if not self.client_for:
            return
        try:
            d = self._device(x["device_id"])
            if d:
                self.client_for(d).session_user_remove(x["router_user"])
        except Exception:  # noqa: BLE001 - router offline: the hourly sweep removes it later
            traceback.print_exc()

    def who(self, device_id, router_user, at=None):
        """Which technician's session a router log line from the relay belongs to -> (email, exact) or (None, False)."""
        at = at or time.time()
        cands = [(x["router_user"], x["user"]) for x in list(self.sessions.values()) if x["device_id"] == device_id]
        cands += [(r["router_user"], r["user"]) for r in self.recent if r["device_id"] == device_id and r["end"] >= at - 600]
        exact = [tech for ru, tech in cands if ru == router_user]
        if exact:
            return exact[0], True
        techs = sorted({tech for _, tech in cands})
        return (techs[0], False) if len(techs) == 1 else (None, False)

    def _sweeper(self):
        """Every hour: remove TikManager session logins left on routers with no session open (e.g. after a restart)."""
        time.sleep(180)
        while True:
            try:
                if self.client_for:
                    for d in self.db.q("SELECT * FROM devices WHERE state='adopted' AND online=1"):
                        live = {x["router_user"] for x in list(self.sessions.values()) if x["device_id"] == d["id"]}
                        try:
                            cl = self.client_for(d)
                            for name in cl.session_users():
                                if name not in live:
                                    cl.session_user_remove(name)
                        except Exception:  # noqa: BLE001 - one unreachable router doesn't stop the sweep
                            continue
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(3600)

    def extend(self, port, user, admin=False):
        x = self.sessions.get(port)
        if not x or (x["user"] != user and not admin):
            raise ValueError("That session isn't open.")
        x["expires"] = min(x["opened"] + MAX_LIFE, max(x["expires"], time.time()) + EXTEND)
        return self._pub(x)

    def close(self, port, user, admin=False, why="closed"):
        x = self.sessions.get(port)
        if not x or (x["user"] != user and not admin):
            raise ValueError("That session isn't open.")
        self._call(self._close(x, why))

    # --- the relay (event loop thread) -----------------------------------------------------------------------
    async def _close(self, x, why):
        with self.lock:
            if self.sessions.get(x["port"]) is not x:
                return
            self.sessions.pop(x["port"], None)
        if x["server"]:
            x["server"].close()
        for w in list(x["writers"]):
            w.close()
        mins = int((time.time() - x["opened"]) // 60)
        self.recent = [r for r in self.recent if r["end"] > time.time() - 900] + [
            {"device_id": x["device_id"], "router_user": x["router_user"], "user": x["user"], "end": time.time()}]

        def after():   # remove the session's login, then a backup so "What changed" shows what it did
            self._remove_login(x)
            if self.backups and x["conns"]:
                try:
                    self.backups.run(x["device_id"], f"after Winbox session {time.strftime('%H:%M', time.localtime(x['opened']))}-"
                                                     f"{time.strftime('%H:%M')}", x["user"])
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
        threading.Thread(target=after, daemon=True, name="winbox-close").start()
        self.db.audit(x["user"], "Winbox session closed", x["device"], x["allow_ip"], org_id=x.get("org_id"),
                      detail=f"port {x['port']}, {why}, {mins} min, {x['conns']} connection(s), {x['bytes'] / 1048576:.1f} MB")

    async def _handle(self, x, reader, writer):
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        if peer.startswith("::ffff:"):
            peer = peer[7:]
        if peer != x["allow_ip"] or time.time() > x["expires"]:
            writer.close()
            self.secev.record("tikmanager", "remote_rejected", x["user"], peer, "winbox",
                              f"connection to {x['device']}'s Winbox session (port {x['port']}) from an address it isn't open to",
                              device_id=x["device_id"], throttle=True)
            return
        try:
            r2, w2 = await asyncio.wait_for(asyncio.open_connection(*x["target"]), 10)
        except Exception:  # noqa: BLE001 - router offline / Winbox off
            writer.close()
            return
        x["conns"] += 1
        x["writers"].update((writer, w2))

        async def pump(src, dst):
            try:
                while data := await src.read(65536):
                    x["bytes"] += len(data)
                    x["last"] = time.time()
                    dst.write(data)
                    await dst.drain()
            except Exception:  # noqa: BLE001 - either side went away
                pass
            finally:
                dst.close()
        await asyncio.gather(pump(reader, w2), pump(r2, writer))
        x["writers"].discard(writer)
        x["writers"].discard(w2)

    async def _reaper(self):
        while True:
            await asyncio.sleep(15)
            now = time.time()
            for x in list(self.sessions.values()):
                try:
                    if now > x["expires"]:
                        await self._close(x, "time limit reached")
                    elif now - x["last"] > IDLE and not x["writers"]:
                        await self._close(x, f"no traffic for {IDLE // 60} minutes")
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
