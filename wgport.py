"""Changing the WireGuard port routers connect to - without stranding a single router (Admin > Settings > WireGuard port).

1. You forward the new UDP port to this server on your edge firewall (keep the old one forwarded for now) and press
   Move. TikManager asks its root helper (deploy/wg-port.sh, via tikmanager-wgport.path) to move wg0 to the new port and
   allow it in the server firewall - the web app itself can only ask, not change the server.
2. While routers move, TikManager relays the old port to the new one (a small user-space UDP relay), so routers still
   dialling the old port stay connected. WireGuard follows a peer whose address changes, so nothing notices.
3. Every online router gets its tunnel's endpoint port changed over that tunnel; routers that are offline are changed as
   soon as they reconnect (through the relay).
4. When every router is on the new port, Close old port stops the relay and asks the helper to remove the old firewall
   rule. New adoptions use the new port from step 1.
The port routers dial is kept per router (devices.wg_port) so the progress list is exact.
"""
import asyncio
import json
import os
import re
import secrets
import threading
import time
import traceback
from pathlib import Path

from routeros import RouterError

RELAY_IDLE = 300
RELAY_MAX = 512   # senders relayed at once - more than any router count, but bounded (UDP sender addresses can be faked)


class UdpRelay:
    """old port -> 127.0.0.1:new port, one local socket per router address so replies find their way back."""

    def __init__(self, loop, listen_port, target_port):
        self.loop, self.listen_port, self.target = loop, listen_port, ("127.0.0.1", target_port)
        self.front = None
        self.backs = {}   # router address -> (transport, last seen)

    async def start(self):
        relay = self

        class Front(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                relay.front = transport

            def datagram_received(self, data, addr):
                relay.loop.create_task(relay._forward(data, addr))
        await self.loop.create_datagram_endpoint(Front, local_addr=("0.0.0.0", self.listen_port))
        self.loop.create_task(self._reap())

    async def _forward(self, data, addr):
        back = self.backs.get(addr)
        if not back and len(self.backs) >= RELAY_MAX:
            return   # full: drop it (real routers retry; their keepalive keeps an existing entry alive)
        if not back:
            relay = self

            class Back(asyncio.DatagramProtocol):
                def datagram_received(self, reply, _src):
                    if relay.front:
                        relay.front.sendto(reply, addr)
                        relay.backs[addr] = (relay.backs[addr][0], time.time())
            transport, _ = await self.loop.create_datagram_endpoint(Back, remote_addr=self.target)
            back = self.backs[addr] = (transport, time.time())
        back[0].sendto(data)
        self.backs[addr] = (back[0], time.time())

    async def _reap(self):
        while self.front:
            await asyncio.sleep(60)
            for addr, (tr, seen) in list(self.backs.items()):
                if time.time() - seen > RELAY_IDLE:
                    tr.close()
                    self.backs.pop(addr, None)

    def close(self):
        for tr, _ in self.backs.values():
            tr.close()
        self.backs.clear()
        if self.front:
            self.front.close()
            self.front = None


class WgPort:
    def __init__(self, db, settings, client_for, appsettings):
        self.db, self.s, self.client_for, self.app = db, settings, client_for, appsettings
        self.data = Path(settings.data_dir)
        self.request_file = self.data / "wg-port-request"
        self.status_files = [Path("/var/lib/tikmanager-update/wgport.json"), self.data / "wgport.json"]
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True, name="wg-relay").start()
        self.relay = None
        self.busy, self.error = False, None   # a port change being checked / applied, and why the last one failed
        self.lock = threading.Lock()

    # --- state ------------------------------------------------------------------------------------------------
    @property
    def port(self):
        return int(self.db.setting("wg_port", getattr(self.s, "wg_port", 51820)) or 51820)

    @property
    def old(self):
        v = self.db.setting("wg_port_old", "")
        return int(v) if str(v).isdigit() else None

    def supported(self):
        return getattr(self.s, "dev", False) or (os.name == "posix" and Path("/etc/systemd/system/tikmanager-wgport.path").exists())

    def helper_status(self):
        for f in self.status_files:
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
        return {}

    def info(self):
        rows = self.db.q("SELECT id, name, online, wg_port, last_seen FROM devices WHERE state='adopted' ORDER BY name")
        cur = self.port
        return {"port": cur, "old": self.old, "supported": self.supported(), "relay": bool(self.relay), "busy": self.busy, "error": self.error,
                "helper": self.helper_status(), "requested": self.request_file.exists(),
                "routers": [{"id": r["id"], "name": r["name"], "online": bool(r["online"]), "port": r["wg_port"] or (self.old or cur)} for r in rows],
                "moved": sum(1 for r in rows if (r["wg_port"] or (self.old or cur)) == cur), "total": len(rows)}

    def _ask_helper(self, line):
        if getattr(self.s, "dev", False):   # dev: nothing to change on this PC
            return
        tmp = self.request_file.with_suffix(".tmp")
        tmp.write_text(line, encoding="utf-8")
        os.replace(tmp, self.request_file)

    def _endpoint_port(self, port):
        """New adoptions dial the new port: keep the saved WireGuard address's host, swap its port."""
        host = (self.s.wg_endpoint or "").rpartition(":")[0] or re.sub(r"^https?://", "", self.s.public_url).split("/")[0].split(":")[0]
        self.app.save({"wg_endpoint": f"{host}:{port}"})
        self.app.apply()

    # --- moving -------------------------------------------------------------------------------------------------
    def start(self, new):
        new = int(new)
        if not 1 <= new <= 65535:
            raise ValueError("A port is 1-65535.")
        if not self.supported():
            raise ValueError("Changing the WireGuard port needs a Linux installation made with the installer (1.19.0 or later).")
        cur = self.port
        if new == cur:
            raise ValueError(f"WireGuard already uses UDP {new}.")
        if self.old:
            raise ValueError(f"Finish the move to UDP {cur} first (Close old port), then change it again.")
        if new in (80, 8800) or new in range(40000, 40050):
            raise ValueError("That port is used by TikManager for something else.")
        with self.lock:
            if self.busy:
                raise ValueError("A port change is already being checked - wait a moment.")
            self.busy, self.error = True, None
        threading.Thread(target=self._move, args=(new, cur), daemon=True, name="wg-move").start()

    def _ask(self, action, port, timeout=90):
        """Ask the root helper and wait for its answer to *this* request -> (ok, detail)."""
        if getattr(self.s, "dev", False):   # dev: nothing to change on this PC
            return True, "dev mode"
        rid = secrets.token_hex(8)
        self._ask_helper(f"{action} {port} {rid}")
        end = time.time() + timeout
        while time.time() < end:
            time.sleep(1)
            st = self.helper_status()
            if st.get("id") == rid:
                return st.get("state") in ("ok", "done"), st.get("detail") or ""
        return False, "The server's helper didn't answer - is tikmanager-wgport.path running? (sudo systemctl status tikmanager-wgport.path)"

    def _move(self, new, cur):
        """Nothing on a router changes until the server has really switched: check the port is free, switch wg0, then
        relay the old port and move the routers. A failure leaves everything as it was."""
        try:
            ok, why = self._ask("check", new)
            if not ok:
                self.error = why
                return
            self.db.run("UPDATE devices SET wg_port=? WHERE state='adopted' AND wg_port IS NULL", (cur,))
            if cur < 1024:
                # the service can't relay a port below 1024, so move the online routers first - while the server still
                # listens on the old port (the check above just confirmed the new one is free) - then switch it
                self.db.set_setting("wg_port", str(new))
                self.move_routers()
            ok, why = self._ask("set", new)
            if not ok:
                self.error = why
                self.db.set_setting("wg_port", str(cur))
                return
            self.db.set_setting("wg_port_old", str(cur))
            self.db.set_setting("wg_port", str(new))
            self._endpoint_port(new)
            self.ensure_relay()
            self.move_routers()
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.error = str(e)[:300]
        finally:
            self.busy = False

    def ensure_relay(self):
        """While a move is under way: relay the old port to the new one (after the helper has moved wg0)."""
        old = self.old
        if not old or self.relay or old < 1024:   # (ports below 1024 can't be opened by the service - then the edge firewall must translate)
            return
        try:
            r = UdpRelay(self.loop, old, self.port)
            asyncio.run_coroutine_threadsafe(r.start(), self.loop).result(10)
            self.relay = r
        except Exception:  # noqa: BLE001 - e.g. wg0 still on the old port: try again on the next pass
            traceback.print_exc()

    def move_routers(self):
        cur = self.port
        for d in self.db.q("SELECT * FROM devices WHERE state='adopted' AND online=1 AND COALESCE(wg_port, 0) <> ?", (cur,)):
            try:
                self.client_for(d).set_controller_port(cur)
                self.db.run("UPDATE devices SET wg_port=? WHERE id=?", (cur, d["id"]))
                self.db.event(d["id"], d["org_id"], "WireGuard port changed", f"now dials TikManager on UDP {cur}")
            except RouterError as e:
                self.db.event(d["id"], d["org_id"], "WireGuard port change failed", str(e)[:300])

    def close_old(self):
        old = self.old
        if not old:
            raise ValueError("There's no old port to close.")
        left = self.db.one("SELECT COUNT(*) AS n FROM devices WHERE state='adopted' AND COALESCE(wg_port, ?) <> ?", (old, self.port))["n"]
        if self.relay:
            self.relay.close()
            self.relay = None
        self._ask_helper(f"close {old} {secrets.token_hex(8)}")
        self.db.set_setting("wg_port_old", "")
        return left

    def loop_once(self):
        """Every minute while a move is under way: keep the relay up and move routers that came back online."""
        if self.old:
            self.ensure_relay()
            self.move_routers()

    def run(self):
        while True:
            try:
                self.loop_once()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(60)

    def start_loop(self):
        threading.Thread(target=self.run, daemon=True, name="wg-port").start()
