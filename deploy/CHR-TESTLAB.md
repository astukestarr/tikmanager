# A TikManager test lab: simulated routers + real CHRs you can Winbox into

TikManager can run a whole fleet of **simulated** MikroTiks for building and demoing, and a few **real** routers
(MikroTik **CHR** — Cloud Hosted Router) you can **Winbox into** and run real commands on. Both live in one dev
instance: simulated routers are flagged `sim=1`, real CHRs are `sim=0` and are polled and managed for real.

## 1. Run TikManager in dev mode

On your Linux / Proxmox box:

```
TM_DEV=1 python3 server.py        # or set TM_DEV=1 in the service environment
```

`TM_DEV=1` enables the simulator and a local dev sign-in. The dev sign-in only trusts **localhost** (see
`dev_login_allowed` in `server.py`), so reach the test instance over an **SSH tunnel** —
`ssh -L 8080:localhost:8080 you@lab-box` then open `http://localhost:8080` — or configure a real sign-in
(Microsoft / OIDC) if you want it reachable directly.

## 2. Seed the simulated fleet (no hardware)

On the **Adopt routers** screen (dev build), click **"Seed demo fleet (6)"**. You get six adopted simulated routers
spread across demo clients (Rebein Brothers, Acme Dental, Hillside Clinic), a mix of models, some offline — each with
working ports/VLANs/firewall/VPN pages. Click again for another batch. Single sims: **"Simulate a router registering"**
(WireGuard path) or **"Simulate (dev)"** (overlay path).

Simulated routers show a **`sim`** pill on their page. Opening **Winbox** on a sim connects to a local stand-in (so you
can exercise the session / audit / Security-page flow), **not** a real RouterOS GUI — that needs a real router.

## 3. Add real CHRs you can Winbox into

MikroTik **CHR** is the real RouterOS as a VM. The free licence (`p1`, applied automatically on the unlimited trial)
caps each interface at 1 Mbit/s — fine for a test lab.

### Easiest: on one Ubuntu host with `chr-lab.sh` (no Proxmox)

If you just have a single Ubuntu/Debian server (the box TikManager runs on is fine), `deploy/chr-lab.sh` brings up real
CHRs on it under QEMU — it installs QEMU, makes a host-local NAT bridge (`10.77.0.0/24`), downloads CHR, and launches
N instances each with a static IP, `www` (API) and an admin password set automatically via cloud-init.

```
sudo ./deploy/chr-lab.sh up 1       # start with 1 to prove it, then: up 2 / up 3
sudo ./deploy/chr-lab.sh status     # IPs + reachability
sudo ./deploy/chr-lab.sh creds      # the generated admin password
sudo ./deploy/chr-lab.sh console 1  # serial console to CHR 1, if you need to poke it by hand
sudo ./deploy/chr-lab.sh down       # stop them
```

**No KVM? It still works.** On a VM/VPS without nested virtualisation the script falls back to QEMU emulation (TCG):
correct but CPU-heavy and slow to boot, so keep it to **2–3 CHRs** on a 2-vCPU box — the free simulated routers cover
breadth, the CHRs just give you a couple of real-Winbox targets. With `/dev/kvm` present it uses KVM automatically.

Then in TikManager: set the **controller's overlay IP** (Admin → Settings) to `10.77.0.1`, open **Adopt routers →
"…or add one by its address"**, and enter each CHR's IP with `admin` / the password from `creds`. If TikManager runs on
a *different* host than the one running the CHRs, add a route to `10.77.0.0/24` via the CHR host first.

**Test clients behind each router.** Every CHR comes up with a LAN (ether2) on its own subnet
(`192.168.21.0/24` for router 1, `.22` for router 2, …) and a lightweight **network-namespace host** sitting on it at
`.100` — a near-free stand-in for a client device, so you can test an endpoint on each side. Drive it with
`sudo ./deploy/chr-lab.sh client <N> …`:

```
sudo ./deploy/chr-lab.sh client 1 ping 192.168.21.1    # client reaches its own router
sudo ./deploy/chr-lab.sh client 1 serve 80 &           # a test HTTP endpoint behind router 1
sudo ./deploy/chr-lab.sh client 2 curl -s http://192.168.21.100/   # reach it from behind router 2
```

The cross-side call works once you **build a site-to-site VPN between the two CHRs in TikManager** and route their LAN
subnets to each other — which is exactly the end-to-end path a real two-site customer has, now testable with no
hardware. Each router's LAN is a distinct /24 so the VPN routes never collide.

**VLANs.** Each CHR's LAN is a **VLAN-aware trunk** (ether2 on a bridge with `vlan-filtering=yes`), seeded with VLANs
`10` and `20` — each with its own subnet `10.<router>.<vlan>.0/24`, address and DHCP. This is exactly what TikManager's
**Ports** tab edits (bridge VLAN filtering: tagged/untagged/PVID per port), so you can view and change the tagging there
against a real router. Put the test client on a VLAN with `client <N> vlan <id> …`:

```
sudo ./deploy/chr-lab.sh client 1 vlan 10 ping 10.1.10.1     # client on VLAN 10 -> its gateway
sudo ./deploy/chr-lab.sh client 1 vlan 10 serve 80 &         # endpoint on VLAN 10 behind router 1
sudo ./deploy/chr-lab.sh client 2 vlan 10 curl http://10.1.10.100/   # reach it from router 2's VLAN 10
```

Seed different VLANs with `VLANS="10 20 30" sudo ./deploy/chr-lab.sh up …` (ids 2–254). To test segmentation, add
firewall rules in TikManager/Winbox and watch which client-to-client paths stop working.

### Or on Proxmox

### On Proxmox
1. Download the CHR disk image from mikrotik.com → *Cloud Hosted Router* → the current `7.x` **stable**, "Raw disk
   image" (`chr-7.x.img.zip`); unzip to `chr-7.x.img`.
2. Create a VM (no disk yet): ~**256 MB RAM**, 1 vCPU, a NIC on the bridge that can reach the TikManager box
   (the same overlay/LAN). Note its VM id (e.g. `9001`).
3. Import the image and attach it:
   ```
   qm importdisk 9001 chr-7.x.img local-lvm
   qm set 9001 --scsi0 local-lvm:vm-9001-disk-0 --boot order=scsi0
   qm start 9001
   ```
4. At the CHR console log in as `admin` (no password), set a password, and give it an address TikManager can reach —
   either a static IP on the lab network or your overlay (Netbird/Tailscale) address:
   ```
   /ip address add address=10.20.0.11/24 interface=ether1
   /ip service enable www            # REST API over HTTP (TikManager provisions its own API user)
   ```
   Repeat for as many CHRs as you want (give each its own address).

### Adopt each CHR into TikManager
Use **Adopt routers → "…or add one by its address"**: enter the CHR's IP, an admin login it can use **once**, and
**Add router**. TikManager connects for real, creates its controller-only API user, and stores the router as
`sim=0`. (You can also paste the **WireGuard adoption command** into a CHR's terminal if you'd rather it dial out.)

Set the **controller's overlay IP** in **Admin → Settings** first (required for the direct/overlay path).

### Winbox in
On a real CHR's page, **Open Winbox**: TikManager opens a port on its own address and relays it to the CHR's real
`:8291` over the tunnel. Point the Winbox app at the `host:port` shown and sign in with the CHR's own login — the full
GUI loads, backed by real RouterOS. Sessions are address-locked, time-limited, audited, and get their own temporary
router login (see `winbox.py`).

## How the split works (for maintainers)

- `devices.sim` — `1` simulated, `0` real, `NULL` legacy.
- `poller.client()` returns a `routeros.SimRouter` when `sim=1` (or `sim NULL` in a dev instance, for back-compat),
  otherwise a real `routeros.RouterOS`. A real server (`TM_DEV` off) has `sim` `0`/`NULL` on every device and is
  polled exactly as before.
- `winbox.open()` relays `sim=1` routers to the dev echo stand-in (`127.0.0.1:18291`, started only under `TM_DEV`) and
  real routers to `tunnel_ip:8291`.
- The seeder (`/api/dev/seed-fleet`) and the "Simulate" buttons are **dev-only** (404 otherwise) and never run on a
  real server.
