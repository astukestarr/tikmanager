# TikManager

A self-hosted MikroTik RouterOS controller for MSPs and IT teams: adopt routers with one command, monitor them, back up
their configuration nightly, upgrade firmware on a schedule, push scripts, build site-to-site VPNs, and give each client
a read-only view of their own routers. New versions install from the web page with one click
([Updating TikManager](#updating-tikmanager)); what changed in each is in [CHANGELOG.md](CHANGELOG.md). Design and
security model: [ARCHITECTURE.md](ARCHITECTURE.md). Working on the code (with or without an AI assistant):
[CLAUDE.md](CLAUDE.md).

Python 3 standard library only on the server (plus Ubuntu's `python3-cryptography` for encrypting stored configs),
SQLite, WireGuard and Caddy. No build step, no package manager.

## Try it locally (dev mode, simulated routers)

    set TM_DEV=1
    set TM_PORT=8801
    set TM_PUBLIC_URL=http://localhost:8801
    python server.py

Open http://localhost:8801 and use **Dev sign-in** (only offered in dev mode on localhost). Dev mode simulates routers,
so every page works without hardware. Data goes to `./data/` (delete it to start over).

## Install on a server (Ubuntu 26.04 LTS)

Before you start:
- a VM, ideally in a DMZ that can't reach your LAN (routers connect to it from the internet);
- a DNS name for it (e.g. `tikmanager.example.com`) pointing at your public IP;
- your firewall forwarding **443/tcp** (and 80/tcp, which helps Let's Encrypt) and **51820/udp** to the VM;
- SSH access to the VM from your LAN.

On the server, download the installer and run it:

    curl -fsSL https://raw.githubusercontent.com/astukestarr/tikmanager/main/deploy/get.sh -o get.sh
    sudo bash get.sh --host tikmanager.example.com --lan 192.168.1.0/24

Leave out `--host` or `--lan` and it asks (it suggests the server's own subnet for `--lan`). `--host` is the public DNS
name; `--lan` is the only subnet allowed to SSH to the server. It downloads the newest TikManager release from GitHub
(`--version 1.2.0` picks one), checks it, and installs WireGuard, Caddy (HTTPS via Let's Encrypt), the firewall,
fail2ban and the service. It **ends by printing a one-time setup link**. Prefer one line? `curl -fsSL <that URL> | sudo
bash -s -- --host ... --lan ...` does the same; downloading first lets you read the script before running it.

Running your own fork? Add `--repo yourname/tikmanager`: it installs from your repository, and your servers take their
updates from it too.

From a Windows PC instead (copies this folder to the server over SSH; asks for the server user's password and sudo
password):

    powershell -ExecutionPolicy Bypass -File .\deploy\push.ps1 -VM youruser@VM-IP -Install -HostName tikmanager.example.com -Lan 192.168.1.0/24

(or copy the folder to the server yourself and run `sudo bash deploy/install.sh --host ... --lan ...`).

### First run

1. Open the setup link. Enter your company name, your name, email and a password (14+ characters) and the email
   domain(s) of your staff. That creates the first administrator; the link stops working afterwards.
2. Sign in with that email and password - you'll be asked to set up an authenticator app (required).
3. **Admin > Settings**: set up Microsoft sign-in for your technicians (below), check the staff domains and admins.
4. **Admin > Branding**: logo, colour, sign-in message, support contact shown to clients. Until you upload a logo,
   TikManager shows its own (the name, with the T drawn as a tiki torch).
5. **Clients**: add your clients (or import them from ConnectWise PSA on Admin > Integrations).
6. **Routers > Adopt routers**: copy the adoption command and paste it into a router's terminal (RouterOS 7).

New versions later: see [Updating TikManager](#updating-tikmanager).

### Microsoft sign-in for your technicians

Entra admin center > App registrations > New registration:
- Name **TikManager**, *Accounts in this organizational directory only*.
- Redirect URI: platform **Web**, `https://<your TikManager name>/auth/callback` (Admin > Settings shows the exact value).
- Certificates & secrets > New client secret (copy the **Value**).
- No API permissions are needed beyond the default *User.Read*.

Enter the Directory (tenant) ID, Application (client) ID and secret on **Admin > Settings** - no restart needed. Anyone
from your staff email domains becomes a technician at first sign-in; the administrator emails become admins. The first
administrator's password account keeps working as a way in if Microsoft sign-in is ever broken.

### What is configured where

| Setting | Where |
|---|---|
| Company name, logo, colours, sign-in message, support contact | Admin > Branding |
| Staff email domains, administrators, Microsoft sign-in, WireGuard address, latency test target | Admin > Settings |
| Backup time and versions kept | Admin > Settings |
| ConnectWise PSA, IT Glue | Admin > Integrations |
| Public address, data folder, port, controller WireGuard key | `/etc/tikmanager/tikmanager.env`, written by the installer (see `.env.example`) |

Settings saved on the web pages override the settings file; secrets entered there are stored encrypted with a key
derived from the server's master key and are never shown again.

### Updating TikManager

Versions are numbered `MAJOR.MINOR.PATCH` ([semantic versioning](https://semver.org)): a **patch** (1.1.**1**) only
fixes things, a **minor** version (1.**2**.0) adds features, and both are safe to install with the button. A **major**
version (**2**.0.0) needs something from you, and [CHANGELOG.md](CHANGELOG.md) says what. Your data, settings, keys and
routers are kept by every upgrade.

**Which version am I on?** At the bottom of the menu ("TikManager 1.1.0") and on **Admin > Settings > Version &
updates**, which also shows the newest release, when TikManager last checked and where updates come from.

**How do I know there's a new one?** Once a day TikManager asks GitHub for the newest release. When there is one,
administrators see an **Update X available** badge at the top of every page. **Check for updates** on the Version &
updates card checks immediately.

**Upgrading with one click** (administrators):
1. Click the **Update available** badge (or go to Admin > Settings). **What's new** opens that version's notes.
2. Click **Upgrade now**, then click again to confirm.
3. The card shows progress. The server downloads the release from GitHub, checks it, backs up the current code
   (`/opt/tikmanager.prev`) and the database (`/var/backups/tikmanager/backup-before-<version>.db`, readable by root only; the last 3 are kept),
   installs it and restarts TikManager. That takes about a minute; the page says "Restarting..." and reloads by itself
   on the new version.
4. If the new version doesn't start, the server puts the previous version back automatically and the card says
   "Last upgrade failed" with the reason. Routers are not touched by an upgrade, so monitoring carries on either way.

**Upgrading from a terminal** (same steps, same safety net), on the VM:

    sudo bash /opt/tikmanager/deploy/self-update.sh            # newest release
    sudo bash /opt/tikmanager/deploy/self-update.sh 1.2.0      # a specific version
    journalctl -u tikmanager-update                            # what the last upgrade did

The updater never installs an older version than the one you have - from the button it can't, and by hand only if you
insist: `sudo TM_ALLOW_DOWNGRADE=1 bash /opt/tikmanager/deploy/self-update.sh 1.0.0`. To undo the last upgrade, the
steps below are simpler.

**Servers installed before 1.0.0** don't have the updater yet. Install it once by copying the current code over from a
Windows PC, after which the button works:

    powershell -ExecutionPolicy Bypass -File .\deploy\push.ps1 -VM youruser@VM-IP

(or copy the folder to the VM and run `sudo bash deploy/update.sh`). The same command is how you deploy code you've
changed yourself without publishing a release.

**Going back to the previous version by hand** (rarely needed - a failed upgrade rolls back by itself):

    sudo rsync -a --delete /opt/tikmanager.prev/ /opt/tikmanager/ && sudo systemctl restart tikmanager

If you also need the database as it was before the upgrade (newer versions only *add* to the database, so the previous
version normally runs fine on it):

    sudo systemctl stop tikmanager
    sudo cp /var/backups/tikmanager/backup-before-<version>.db /var/lib/tikmanager/tikmanager.db
    sudo rm -f /var/lib/tikmanager/tikmanager.db-wal /var/lib/tikmanager/tikmanager.db-shm
    sudo chown tikmanager:tikmanager /var/lib/tikmanager/tikmanager.db && sudo systemctl start tikmanager

Anything recorded since the upgrade (new backups, metrics, events) is lost when you restore the database.

**Where updates come from** is `TM_UPDATE_REPO` in `/etc/tikmanager/tikmanager.env` (default the public
`astukestarr/tikmanager` repository). It can only be changed in that root-owned file, never on the web pages, so a
stolen administrator account can't make the server install someone else's code. Running your own modified copy? Fork
the repository, point `TM_UPDATE_REPO` at your fork and publish your own `vX.Y.Z` tags (see
[CLAUDE.md](CLAUDE.md#releasing-a-new-version)). `TM_UPDATE_CHECK=0` turns off the daily check (the button still works).

### Routers

**Routers** lists every approved router with its status, client, site, model, RouterOS version, uptime, CPU and when it
was last seen. Filter by client, status or text; click a column header to sort by it (click again to reverse - Status
puts offline routers first). Routers that registered but aren't approved yet are listed above, under **Waiting for
approval**. Click a router for its page: charts, interfaces, DHCP clients, backups, upgrades, scripts and events.

**Adopt routers** shows the adoption command (the same for every router). It needs RouterOS 7 (it copes with settings
that newer 7.x versions renamed) and is safe to run again on a router that's already adopted - for example after a failed attempt.

### If a router registers but never comes online

The router reaches TikManager over HTTPS to register, but monitoring needs its WireGuard tunnel (UDP 51820) to reach the VM.
1. On the VM: `sudo wg show` - no "latest handshake" under the router's peer means its packets aren't arriving.
2. `sudo timeout 40 tcpdump -lni <nic> udp port 51820` on the VM shows whether anything arrives at all.
3. On the edge router, the port forward must be **UDP** 51820 -> the VM (a TCP-only rule passes HTTPS but not WireGuard):
   `/ip firewall nat add chain=dstnat dst-address=<public IP> protocol=udp dst-port=51820 action=dst-nat to-addresses=<VM IP> comment="TikManager WireGuard"`
4. After adding or changing that rule, clear the router's old connection-tracking entry - otherwise packets keep following it
   and skip the new rule: `/ip firewall connection remove [find protocol=udp dst-address~"<public IP>:51820"]`
5. A router whose handshake failed stops retrying after ~90 s; `/ping 10.77.0.1 count=5` on the router makes it try again.

### Configuration backups

Every approved router is exported nightly (Admin > Settings sets the hour; default 02:00 server time) over its tunnel as
a **script** (`/export show-sensitive`) - import it with `/import` on any RouterOS 7 router, including a different model
(adjust interface names as needed). A new version is stored only when the configuration changes, and each router keeps its newest 10
versions (Admin > Settings; the oldest is removed when a new one is saved); each is compressed
and encrypted with AES-256-GCM (Ubuntu's `python3-cryptography`, installed by the deploy scripts) using a key derived
from the master key, so the database alone reveals no router passwords. Only technicians can view, compare
("What changed") or download versions; every view and download is audit-logged.

### Router upgrades (RouterOS and firmware)

(For upgrading TikManager itself, see [Updating TikManager](#updating-tikmanager).) **Upgrades** (technicians) lists every router's RouterOS version, the newest on its update channel (each router asks
MikroTik's server twice a day, or on **Check for updates**) and its RouterBOARD firmware. Upgrade one router from its
page, or tick several and **Upgrade selected**: now or at a scheduled time, on the router's own channel or stable /
long-term, optionally with the RouterBOARD firmware, and optionally staggered (N minutes between routers; at most 4
upgrade at once). Each job backs the router up first and stops if that fails, downloads the new RouterOS, reboots, waits
up to 15 minutes for the new version, then stages the matching firmware and reboots once more. Scheduled jobs can be
cancelled until they start; every step is shown on the router's page, in its events and in the audit log.

### Site-to-site VPN

**Site-to-site VPN** (technicians) connects a client's routers with WireGuard, hub and spoke. Pick the client, tick its
routers, choose the hub and the subnets each site shares (pre-filled from the site map, guest networks unticked), then
**Save and apply**. The hub needs a public address: its WAN IP is used automatically; if it sits behind NAT, enter its
public IP or DDNS name and forward the UDP port (default 13232) to it. Spokes can be behind NAT/CGNAT.

Before anything changes: overlapping subnets (and clashes with the tunnel network or TikManager's 10.77.0.0/16) are
refused, every router must be online and on RouterOS 7, and each is backed up. The routers create their own keys
(private keys never leave them). Each gets an interface `tikmanager-vpn`, an address on the tunnel network
(10.250.x.0/24 unless you set one; hub = .1), peers, routes to the other sites' subnets and accept rules at the top of
its firewall (hub: the UDP port; all: ICMP from the tunnel, forwarding to/from it) - all commented `TikManager VPN`.
Apply again replaces exactly those objects; **Disable**, **Delete** or unticking a router removes them and the
interface. Spoke-to-spoke traffic goes through the hub. Tunnel status (handshake age, ping to the hub, traffic) is
checked every minute and shown on the VPN, the router page and the site map. If a site masquerades *all* outgoing
traffic (a srcnat rule without an out-interface), restrict that rule to the WAN so site-to-site traffic isn't NATed.

**Existing VPNs on routers** (second tab) lists VPNs configured outside TikManager - WireGuard peers, IPsec peers with
their policies, L2TP/SSTP/OpenVPN/PPTP clients and servers (with who is connected), EoIP/GRE/IPIP tunnels - read every
15 minutes or on demand, read-only. Only names, addresses, subnets, status and traffic are read (a field whitelist: no
passwords, pre-shared keys or private keys). A remote end that is another TikManager router's WAN/public IP is shown as
that router; PPTP and IPsec without phase 2 are flagged. The same list appears on each router's page.

### Tasks (scripts, groups, schedules, automatic firmware updates)

**Tasks** (technicians): a **Scripts** library of RouterOS scripts (placeholders `{{identity}} {{name}} {{client}}
{{site}} {{wan_ip}} {{tunnel_ip}}` are filled per router), **Groups** of routers you pick, and **Scheduled tasks**: run a
script - or upgrade firmware - on all routers, clients, groups and/or individual routers, once (now or at a time), daily,
on chosen weekdays or every N hours, in the timezone of the person who set it. Script runs back each router up first
(on by default; a router is skipped if that fails), run via REST `execute` over the tunnel (8 at a time), and keep each
router's output in **History**. Offline routers are skipped, or run when they come back within 24 hours. A firmware
task gives every target router with a newer RouterOS (or RouterBOARD firmware) the Upgrades page's safe upgrade and
skips routers already up to date - e.g. "All routers, Sundays 02:00" keeps everything current. Each router page also
has **Run script...** for a one-off. Every change and run is audit-logged.

### Integrations

Admin > Integrations (administrators). Keys are typed on the page, stored encrypted (AES-256-GCM, derived from the master
key) and never shown again - the page only says a key is saved. The VM needs outbound HTTPS to the PSA and IT Glue.

- **ConnectWise PSA** - site, company ID, public/private key of an API member with a *read-only* security role, and your
  client ID from developer.connectwise.com. Lists companies (filter by type/status) so you can import them as clients or
  link existing clients; matching names are suggested.
- **IT Glue** - region and an API key (leave "Password access" off). Link each client to its IT Glue organization (name
  matches are suggested), pick the configuration type for routers, then **Sync now** or leave the nightly update on. Each
  router becomes/updates a configuration (name, hostname, WAN IP, serial, MAC, RouterOS version, link back to TikManager);
  an existing configuration with the same serial is reused instead of duplicated.

### Product pictures

Router thumbnails are matched by model against mikrotik.com's product catalog (refreshed weekly), downloaded once into
`/var/lib/tikmanager/thumbs/` and served by TikManager itself. Discontinued models and CHR show a generic icon.

### Admin

Admin (administrators only): **Branding** (product and company name, accent colour, logo - PNG/JPEG/WebP only, sign-in
message, support contact shown to clients; without an uploaded logo the built-in TikManager logo is shown),
**Technicians** (admin / tech / read-only), **Integrations**, **Settings** (version & updates, staff sign-in, Microsoft
sign-in, router settings, backup time and retention).

### Where things live on the VM

| What | Where |
|---|---|
| Code | `/opt/tikmanager` (root-owned, read-only to the service) |
| Database | `/var/lib/tikmanager/tikmanager.db` |
| Settings / master key | `/etc/tikmanager/` (root:tikmanager, 0640) |
| WireGuard | `/etc/wireguard/wg0.conf` (controller key); router peers come from the database |
| Logs | `journalctl -u tikmanager`, `/var/log/caddy/tikmanager.log` |
| Updater | `tikmanager-update.path` / `.service` (root), log `journalctl -u tikmanager-update` |
| Before the last upgrade | code `/opt/tikmanager.prev`, database `/var/backups/tikmanager/backup-before-<version>.db` (last 3, root only); upgrade progress `/var/lib/tikmanager-update/status.json` |

The service runs as user `tikmanager` with only `CAP_NET_ADMIN` and a read-only filesystem except its data folder.
