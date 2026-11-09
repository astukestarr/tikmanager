"""Live tunnel bandwidth: the per-router WireGuard tunnel to the controller, sampled every few seconds, turned into an
up/down rate per router for the Tunnels page.

- The controller reads cumulative per-peer byte counters from `wg show wg0 dump` (wg.transfers()); this diffs them over
  time to get bytes/sec, the same shape poller.py uses for interface rates. "In" = bytes the controller received from the
  router (its logs, flows, backups, API polls); "Out" = bytes the controller sent to it.
- Peers map to devices by their WireGuard public key (devices.wg_pubkey). A short in-memory ring per router feeds a
  sparkline. Nothing is stored in the database - it's a live view.
- Dev mode has no real WireGuard, so counters are simulated for the adopted (simulated) routers.
"""
import random
import threading
import time

SAMPLE_SECS = 5
RING = 60   # ~5 minutes of history at SAMPLE_SECS


class Tunnels:
    def __init__(self, db, settings, wg):
        self.db, self.s, self.wg = db, settings, wg
        self.lock = threading.Lock()
        self.prev = {}      # pubkey -> (t, rx, tx) for the rate diff
        self.rate = {}      # device_id -> live {in_bps, out_bps, in_total, out_total, handshake, spark, at}
        self._sim = {}      # dev only: fabricated cumulative counters per pubkey
        self.sampled = 0

    # --- reading -------------------------------------------------------------------------------------------------
    def _read(self):
        if getattr(self.s, "dev", False):
            return self._simulate()
        try:
            return self.wg.transfers()
        except Exception as e:  # noqa: BLE001 - a wg hiccup never stops the sampler
            print(f"tunnels: {e}")
            return {}

    def _simulate(self):
        """Fabricate growing counters per adopted router (dev has no real WireGuard)."""
        out, now = {}, time.time()
        for d in self.db.q("SELECT id, wg_pubkey, online FROM devices WHERE state='adopted' AND wg_pubkey IS NOT NULL AND wg_pubkey<>''"):
            pk = d["wg_pubkey"]
            cur = self._sim.get(pk) or [random.randint(10**6, 10**8), random.randint(10**6, 10**8)]
            if d["online"]:
                r = random.Random(d["id"] * 7919 + int(now // SAMPLE_SECS))
                cur[0] += r.randint(2000, 500000)   # from the router (logs / flows / backups / polls)
                cur[1] += r.randint(1000, 150000)   # to the router
            self._sim[pk] = cur
            out[pk] = (cur[0], cur[1], int(now) - 5, "sim")
        return out

    def sample(self):
        reads = self._read()
        now = time.time()
        devs = {d["wg_pubkey"]: d["id"] for d in
                self.db.q("SELECT id, wg_pubkey FROM devices WHERE state='adopted' AND wg_pubkey IS NOT NULL AND wg_pubkey<>''")}
        with self.lock:
            live = set()
            for pk, (rx, tx, hs, _ep) in reads.items():
                did = devs.get(pk)
                if not did:
                    continue
                live.add(did)
                prev = self.prev.get(pk)
                in_bps = out_bps = 0.0
                if prev and now > prev[0]:
                    dt = now - prev[0]
                    if rx >= prev[1]:   # guard a counter reset (router restart)
                        in_bps = (rx - prev[1]) * 8 / dt
                    if tx >= prev[2]:
                        out_bps = (tx - prev[2]) * 8 / dt
                self.prev[pk] = (now, rx, tx)
                st = self.rate.get(did) or {"spark": []}
                st.update(in_bps=in_bps, out_bps=out_bps, in_total=rx, out_total=tx, handshake=hs, at=now)
                st["spark"] = (st["spark"] + [[round(in_bps), round(out_bps)]])[-RING:]
                self.rate[did] = st
            # a router that stopped reporting (removed / offline): zero its live rate but keep its totals
            for did, st in self.rate.items():
                if did not in live and st.get("in_bps"):
                    st["in_bps"] = st["out_bps"] = 0.0
                    st["spark"] = (st["spark"] + [[0, 0]])[-RING:]
            self.sampled = now

    # --- reading for the API -------------------------------------------------------------------------------------
    def snapshot(self, rows):
        """rows: org-scoped adopted-device rows (id, name, client, tunnel_ip, online, endpoint public_ip). Attach live rates."""
        now = time.time()
        out, agg_in, agg_out, online = [], 0.0, 0.0, 0
        with self.lock:
            for d in rows:
                st = self.rate.get(d["id"]) or {}
                hs = st.get("handshake") or 0
                it = {"device_id": d["id"], "name": d["name"], "client": d.get("client") or "", "tunnel_ip": d.get("tunnel_ip") or "",
                      "endpoint": d.get("public_ip") or d.get("wan_ip") or "", "online": bool(d.get("online")),
                      "in_bps": st.get("in_bps", 0.0), "out_bps": st.get("out_bps", 0.0),
                      "in_total": st.get("in_total", 0), "out_total": st.get("out_total", 0),
                      "handshake_age": (int(now - hs) if hs else None), "spark": st.get("spark", [])[-30:]}
                out.append(it)
                agg_in += it["in_bps"]
                agg_out += it["out_bps"]
                online += 1 if it["online"] else 0
        out.sort(key=lambda x: -(x["in_bps"] + x["out_bps"]))
        return {"tunnels": out, "agg": {"in_bps": agg_in, "out_bps": agg_out, "count": len(out), "online": online},
                "sampled": self.sampled, "dev": bool(getattr(self.s, "dev", False)), "interface": getattr(self.s, "wg_interface", "wg0"),
                "sample_secs": SAMPLE_SECS}

    # --- loop ----------------------------------------------------------------------------------------------------
    def loop(self):
        while True:
            try:
                self.sample()
            except Exception as e:  # noqa: BLE001
                print(f"tunnels sample: {e}")
            time.sleep(SAMPLE_SECS)

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="tunnels").start()
