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
"""
import asyncio
import ipaddress
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
    def __init__(self, db, settings, secev):
        self.db, self.s, self.secev = db, settings, secev
        self.ports = port_range(getattr(settings, "winbox_ports", ""))
        self.sessions = {}   # port -> session dict
        self.lock = threading.Lock()
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self._run_loop, daemon=True, name="winbox-relay").start()
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
        out = []
        for port, x in sorted(self.sessions.items()):
            out.append({k: x[k] for k in ("port", "device_id", "device", "user", "allow_ip", "opened", "expires", "last", "bytes", "conns")}
                       | {"active": len(x["writers"]) // 2, "mine": x["user"] == s["email"]})
        return out

    def open(self, d, user, allow_ip, target_port=8291):
        try:
            ipaddress.ip_address(allow_ip)
        except ValueError:
            raise ValueError("That isn't an IP address.") from None
        target = ("127.0.0.1", 18291) if getattr(self.s, "dev", False) else (d["tunnel_ip"], int(target_port or 8291))
        with self.lock:
            mine = next((x for x in self.sessions.values() if x["device_id"] == d["id"] and x["user"] == user), None)
            if mine:   # one session per technician per router: reuse it (new address, fresh timer)
                mine.update(allow_ip=allow_ip, expires=max(mine["expires"], time.time() + SESSION))
                return self._pub(mine)
            free = next((p for p in self.ports if p not in self.sessions), None)
            if free is None:
                raise ValueError(f"All {len(self.ports)} Winbox ports are in use - close a session you no longer need.")
            x = {"port": free, "device_id": d["id"], "device": d["name"], "org_id": d.get("org_id"), "user": user, "allow_ip": allow_ip,
                 "target": target, "opened": time.time(), "expires": time.time() + SESSION, "last": time.time(), "bytes": 0, "conns": 0,
                 "writers": set(), "server": None}
            self.sessions[free] = x
        try:
            x["server"] = self._call(asyncio.start_server(lambda r, w, x=x: self._handle(x, r, w), host="0.0.0.0", port=free))
        except Exception as e:  # noqa: BLE001 - port taken by something else
            with self.lock:
                self.sessions.pop(free, None)
            raise ValueError(f"Couldn't open port {free}: {e}") from None
        self.db.audit(user, "Winbox session opened", d["name"], allow_ip, org_id=d.get("org_id"), detail=f"port {free} -> {target[0]}:{target[1]}")
        self.secev.record("tikmanager", "remote_session", user, allow_ip, "winbox", f"opened port {free} to {d['name']}", device_id=d["id"])
        return self._pub(x)

    def _pub(self, x):
        return {k: x[k] for k in ("port", "device_id", "device", "user", "allow_ip", "opened", "expires", "last", "bytes", "conns")}

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
