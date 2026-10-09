# TikManager

A self-hosted MikroTik RouterOS controller for MSPs and IT teams: adopt routers with one command, monitor them, back up
their configuration nightly, upgrade firmware on a schedule, push scripts, build site-to-site VPNs, and give each client
a read-only view of their own routers. It installs on an Ubuntu server with one command and updates itself from the web
page with one click.

Python 3 standard library only on the server (plus Ubuntu's `python3-cryptography` for encrypting stored configs),
SQLite, WireGuard and Caddy. No build step, no package manager.

- [Install on a server](#install-on-a-server-ubuntu-2604-lts) · [First run](#first-run) ·
  [Microsoft sign-in](#microsoft-sign-in-for-your-technicians) · [What is configured where](#what-is-configured-where)
- [Updating TikManager](#updating-tikmanager) - what changed in each version: [CHANGELOG.md](CHANGELOG.md)
- Using it: [Routers](#routers) · [Maps](#maps-where-routers-are-and-whats-behind-them) · [Firewall & NAT](#firewall--nat-rules) · [Subnets in use](#subnets-in-use) · [Discovered](#discovered-mikrotiks-not-in-tikmanager-yet) · [Clients and their users](#clients-and-their-users) ·
  [Configuration backups](#configuration-backups) · [Router upgrades](#router-upgrades-routeros-and-firmware) ·
  [Site-to-site VPN](#site-to-site-vpn) · [Tasks](#tasks-scripts-groups-schedules-automatic-firmware-updates) ·
  [Integrations](#integrations) · [Admin](#admin)
- Running it: [Keeping it secure](#keeping-it-secure) · [Where things live](#where-things-live-on-the-server) ·
  [Troubleshooting adoption](#if-a-router-registers-but-never-comes-online)
- Design and security model: [ARCHITECTURE.md](ARCHITECTURE.md). Changing the code (with or without an AI assistant):
  [CLAUDE.md](CLAUDE.md). Try it without routers: [dev mode](#try-it-locally-dev-mode-simulated-routers).

## Install on a server (Ubuntu 26.04 LTS)

Before you start:
- a VM, ideally in a DMZ that can't reach your LAN (routers connect to it from the internet);
- a DNS name for it (e.g. `tikmanager.example.com`) pointing at your public IP;
- your firewall forwarding **443/tcp** (and 80/tcp, which helps Let's Encrypt) and **51820/udp** to the VM;
- SSH access to the VM from your LAN.

On the server, download the installer and run it:

    curl -fsSL https://raw.githubusercontent.com/astukestarr/tikmanager/main/deploy/get.sh -o get.sh
    sudo bash get.sh --host tikmanager.example.com --lan 192.168.1.0/24

- `--host` is the public DNS name; `--lan` is the only subnet allowed to SSH to the server. Leave either out and it
  asks (it suggests the server's own subnet for `--lan`).
- It downloads the newest TikManager release from GitHub (`--version 1.2.0` picks one), checks it, and installs
  WireGuard, Caddy (HTTPS via Let's Encrypt), the firewall, fail2ban and the service.
- It **ends by printing a one-time setup link** - open it to create your administrator account ([First run](#first-run)).
- Prefer one line? `curl -fsSL <that URL> | sudo bash -s -- --host ... --lan ...` does the same; downloading first
  lets you read the script before running it as root.
- Running your own fork? Add `--repo yourname/tikmanager`: it installs from your repository, and your servers take
  their updates from it too.

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
6. **Routers > Adopt routers**: copy the adoption command and paste it into a router's terminal (RouterOS 7), then
   approve the router and pick its client.

### Microsoft sign-in for your technicians

Entra admin center > App registrations > New registration:
- Name **TikManager**, *Accounts in this organizational directory only*.
- Redirect URI: platform **Web**, `https://<your TikManager name>/auth/callback` (Admin > Settings shows the exact value).
- Certificates & secrets > New client secret (copy the **Value**).
- No API permissions are needed beyond the default *User.Read*.

Enter the Directory (tenant) ID, Application (client) ID and secret on **Admin > Settings** - no restart needed.
- Anyone from your staff email domains becomes a technician at first sign-in; the administrator emails become admins.
- Only accounts from your own organization can sign in - guest accounts invited into your tenant are refused.
- Each technician is tied to their Microsoft account at first sign-in, so a renamed or reused email address doesn't
  inherit someone else's TikManager account. If you replace someone's Microsoft account, use **Reset sign-in** for
  them on Admin > Technicians.
- The first administrator's password account keeps working as a way in if Microsoft sign-in is ever broken.

### What is configured where

| Setting | Where |
|---|---|
| Company name, logo, colours, sign-in message, support contact | Admin > Branding |
| Staff email domains, administrators, Microsoft sign-in, WireGuard address, latency test target | Admin > Settings |
| Backup time and versions kept | Admin > Settings |
| ConnectWise PSA, IT Glue | Admin > Integrations |
| Public address, data folder, port, controller WireGuard key, where updates come from | `/etc/tikmanager/tikmanager.env`, written by the installer (see `.env.example`) |

Settings saved on the web pages override the settings file; secrets entered there are stored encrypted with a key
derived from the server's master key and are never shown again.

## Updating TikManager

Versions are numbered `MAJOR.MINOR.PATCH` ([semantic versioning](https://semver.org)): a **patch** (1.2.**1**) only
fixes things, a **minor** version (1.**3**.0) adds features, and both are safe to install with the button. A **major**
version (**2**.0.0) needs something from you, and [CHANGELOG.md](CHANGELOG.md) says what. Your data, settings, keys and
routers are kept by every upgrade.

**Which version am I on?** Next to the logo at the top of every page ("v1.4.0"), and on **Admin > Settings > Version
& updates**, which also shows the newest release, when TikManager last checked and where updates come from.

**How do I know there's a new one?** Every hour TikManager asks GitHub for the newest release. When there is one,
administrators see a **banner across the top of every page** - "TikManager X is available. You're on Y." - with What's
new and **Upgrade now** (x hides it for a day; a newer release shows it again). Open pages pick it up within 5 minutes,
and show progress while an upgrade runs. **Check for updates** next to the version number at the top (or on the
Version & updates card) checks immediately.

**Upgrading with one click** (administrators):
1. Click the **Update available** badge (or go to Admin > Settings). **What's new** opens that version's notes.
2. Click **Upgrade now**, then click again to confirm.
3. The card shows progress. The server downloads the release from GitHub, checks it, backs up the current code
   (`/opt/tikmanager.prev`) and the database (`/var/backups/tikmanager/backup-before-<version>.db`, root only; the last
   3 are kept), installs it and restarts TikManager. That takes about a minute; the page says "Restarting..." and
   reloads by itself on the new version.
4. If the new version doesn't start, the server puts the previous version back automatically and the card says
   "Last upgrade failed" with the reason. Routers are not touched by an upgrade, so monitoring carries on either way.

**Upgrading from a terminal** (same steps, same safety net), on the server:

    sudo bash /opt/tikmanager/deploy/self-update.sh            # newest release
    sudo bash /opt/tikmanager/deploy/self-update.sh 1.2.0      # a specific version
    journalctl -u tikmanager-update                            # what the last upgrade did

The updater never installs an older version than the one you have - from the button it can't, and by hand only if you
insist: `sudo TM_ALLOW_DOWNGRADE=1 bash /opt/tikmanager/deploy/self-update.sh 1.0.0`. To undo the last upgrade, the
steps below are simpler.

**Servers installed before 1.0.0** don't have the updater yet. Install it once by copying the current code over from a
Windows PC, after which the button works:

    powershell -ExecutionPolicy Bypass -File .\deploy\push.ps1 -VM youruser@VM-IP

(or copy the folder to the server and run `sudo bash deploy/update.sh`). The same command is how you deploy code you've
changed yourself without publishing a release.

**Coming from 1.1.0 or older:** from 1.1.1 on, pre-upgrade database copies are kept in `/var/backups/tikmanager/`. Old
copies in the previous place can be deleted:
`sudo rm -f /var/lib/tikmanager/backup-before-*.db /var/lib/tikmanager/update-status.json`

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
the repository, point `TM_UPDATE_REPO` at your fork (or install with `get.sh --repo`) and publish your own `vX.Y.Z`
tags (see [CLAUDE.md](CLAUDE.md#releasing-a-new-version)). `TM_UPDATE_CHECK=0` turns off the hourly check (the button
still works).

## Routers

**Routers** lists every approved router with its status, client, site, model, RouterOS version, uptime, CPU and when it
was last seen. Filter by client, status or text; click a column header to sort by it (click again to reverse - Status
puts offline routers first). Routers that registered but aren't approved yet are listed above, under **Waiting for
approval**. Click a router for its page: charts, interfaces, DHCP clients, backups, upgrades, scripts and events.

**Adding routers:** **Adopt routers** shows the adoption command (the same for every router). Paste it into the
router's terminal (Winbox > New Terminal, or SSH); the router registers itself, then a technician approves it and picks
its client. It needs RouterOS 7 (it copes with settings that newer 7.x versions renamed) and is safe to run again on a
router that's already adopted - for example after a failed attempt. On the router it creates a WireGuard interface
`tikmanager` (the private key never leaves the router), a `tikmanager` user that may only log in from TikManager, a
firewall rule letting TikManager in through the tunnel, web (REST) access for TikManager and log forwarding.

**Changing a router** (bottom of its page, **Manage**): set its identity on the router, its name and site in
TikManager, or move it to another client (its backups and history move with it).

**Removing a router:** its page > **Manage** > **Remove router** (click twice). TikManager forgets it and closes its
tunnel; if it's in a site-to-site VPN, take it out of the VPN first. What the adoption command created stays on the
router - to remove that too, paste this into the router's terminal:

    /system logging remove [find action=tikmanager]
    /system logging action remove [find name=tikmanager]
    /ip firewall filter remove [find comment="TikManager"]
    /user remove [find name=tikmanager]
    /user group remove [find name=tikmanager]
    /ip address remove [find comment="TikManager"]
    /interface wireguard remove [find name=tikmanager]

and remove `10.77.0.1/32` from IP > Services > www (*Available From*) if it was added there.

## Maps: where routers are, and what's behind them

**Site map > Map** shows every router where it is. Zoom from the whole country down to town level: state borders,
county lines, interstates and the name of every incorporated US city and town appear as you zoom in (wheel, pinch,
double-click or +/-; drag to pan). Routers close together show as a numbered group - click it to zoom in; red means at
least one is offline. Click a router to open it. The map is drawn by TikManager from built-in public-domain data
(Natural Earth and the US Census Bureau), so nothing is loaded from other sites.

**A router's location** is set on its page (**Location > Set location**): type an address, press **Look up** (optional
- only the text you type is sent to OpenStreetMap's address search), type the coordinates, or click the spot on the
map. Routers with a GPS receiver place themselves; a location set by hand always wins. Routers without one are listed
under the map, and so are routers set to exactly the same spot (on the map, clicking such a group lists its routers).

**Network map** (each router's page): Internet and its gateway -> the router -> each network / VLAN -> the switches and
access points found by neighbour discovery (MNDP / LLDP / CDP), each with the devices on its port -> groups of devices:
phones, printers, servers & VMs, cameras, computers, personal devices, IoT and unidentified. Click a group to list its
devices (name, IP, MAC, port). Routes to other networks (VPN, static, dynamic) are listed for technicians; client users
see their networks but not the routing table. Infrastructure and routes come straight from the router; end devices are
recognised by their maker and name, so some stay "Unidentified" (unlike a scanner, the router doesn't probe them).

## Firewall & NAT rules

Each router's page has a **Firewall & NAT** card (technicians): the filter and NAT rules in order, with what each matches
and how much traffic it has seen; pick a chain to narrow the list. Technicians with write access can **add**, **edit**,
**enable / disable**, **delete** and move rules **up / down**. The rule editor is laid out like WebFig: add a match field
with **+**, remove it with **-**, tick **!** for "not"; interfaces, interface lists and address lists are picked from the router's own.

Changes are tested first, like **Safe Mode** in Winbox (Safe Mode itself only exists inside a Winbox / terminal
session, which the REST API TikManager uses doesn't have, so TikManager does the same thing with a router script):
1. Before the first change, TikManager backs up the router (unless it was backed up in the last 10 minutes), saves a
   script on the router that restores the filter and NAT rules exactly as they are, and a scheduler that runs it in
   5 minutes (`tikmanager-fw-undo` in System > Scripts / Scheduler).
2. It makes the change and checks it can still reach the router. Each further change restarts the 5 minutes.
3. Check the site still works, then press **Keep changes** (the script and scheduler are removed) - or **Undo now**.
   If nobody keeps the changes in time, or a change cut TikManager off, the router puts the rules back by itself.

TikManager's own rules (comment starting "TikManager": its management rule and the site-to-site VPN rules) and dynamic
rules are locked. Only the common fields can be set (addresses, ports, protocol, interfaces and lists - address lists are picked from the router's own -, connection
state, NAT targets, jump / reject / address-list options, log, comment); other settings a rule already has are left
alone. Each change, keep and undo is in the audit log and the router's events. Very large rule sets (where the
restore script would be over 60 KB) are refused - change those in Winbox with Safe Mode.

**Address lists** (third tab): pick a list, search it, and add, edit, enable / disable or remove addresses - **Add
address** can also start a new list. Entries a rule added by itself (dynamic, with a timeout) can be removed but not
edited. These changes are tested the same way: the undo script re-adds what was removed, removes what was added and
sets edited entries back.

## Subnets in use

**Subnets** lists every LAN subnet on every approved router, grouped by client: subnet, name (the interface comment),
router, interface, gateway address and usable addresses. It's read from the routers each time they're polled, so it
stays current without anyone keeping a spreadsheet.
- **Overlaps** between a client's own subnets are flagged and tinted - two sites using the same range can't be joined
  with a site-to-site VPN without renumbering one. **Only overlaps** shows just those.
- The **MikroTik default** (192.168.88.0/24) is marked, and so are ranges **also used at other clients** (fine on their
  own; worth knowing before connecting two networks).
- Search by subnet, name, router or client - or type an IP address to find the subnet it belongs to.
- **Export CSV** downloads what's shown. Client users see only their own subnets.

## Discovered: MikroTiks not in TikManager yet

**Discovered** (technicians) lists the MikroTik devices your routers see next to them in **IP > Neighbors** (MNDP / LLDP /
CDP) that aren't in TikManager: identity, model, RouterOS version (v6 is flagged - TikManager needs RouterOS 7), IP and
MAC, which router saw it on which port, and its uptime. Each router's neighbours are read every 15 minutes. A device
counts as already in TikManager when one of its MACs, its IP or its identity matches a router TikManager has (or is
waiting to approve) - except the factory identity "MikroTik". Routers only see devices on their own networks that have
discovery turned on (IP > Neighbors > Discovery Settings). **Adopt routers** on the page gives you the command to run.

## Clients and their users

**Clients** are your customers; every router belongs to one. Add them by hand or import them from ConnectWise PSA.

Each client can have its own users (**Users > Invite**): they get an invitation link, choose a password (14+
characters) and must set up an authenticator app. **Client admins** can invite and manage their organization's users;
**viewers** can only look. Client users see only their own routers - status, charts, interfaces, DHCP clients, events
and that backups exist - never configurations, secrets, scripts or other clients. Technicians can disable users, send
a new invitation link, or reset someone's authenticator app.

Sign-in is protected: after 5 wrong passwords or codes an account is locked for 15 minutes, three wrong authenticator
codes end the sign-in attempt, and every sign-in is in the audit log.

## Configuration backups

Every approved router is exported nightly (Admin > Settings sets the hour; default 02:00 server time) over its tunnel as
a **script** (`/export show-sensitive`) - import it with `/import` on any RouterOS 7 router, including a different
model (adjust interface names as needed). A new version is stored only when the configuration changes, and each router
keeps its newest 10 versions (Admin > Settings; the oldest is removed when a new one is saved). Each is compressed and
encrypted with AES-256-GCM using a key derived from the master key, so the database alone reveals no router passwords.
Only technicians can view, compare ("What changed") or download versions; every view and download is audit-logged.

## Router upgrades (RouterOS and firmware)

(For upgrading TikManager itself, see [Updating TikManager](#updating-tikmanager).)

**Upgrades** (technicians) lists every router's RouterOS version, the newest on its update channel (each router asks
MikroTik's server twice a day, or on **Check for updates**) and its RouterBOARD firmware. Upgrade one router from its
page, or tick several and **Upgrade selected**: now or at a scheduled time, on the router's own channel or stable /
long-term, optionally with the RouterBOARD firmware, and optionally staggered (N minutes between routers; at most 4
upgrade at once). Each job backs the router up first and stops if that fails, downloads the new RouterOS, reboots,
waits up to 15 minutes for the new version, then stages the matching firmware and reboots once more. Scheduled jobs can
be cancelled until they start; every step is shown on the router's page, in its events and in the audit log.

## Site-to-site VPN

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

## Tasks (scripts, groups, schedules, automatic firmware updates)

**Tasks** (technicians): a **Scripts** library of RouterOS scripts (placeholders `{{identity}} {{name}} {{client}}
{{site}} {{wan_ip}} {{tunnel_ip}}` are filled per router), **Groups** of routers you pick, and **Scheduled tasks**: run
a script - or upgrade firmware - on all routers, clients, groups and/or individual routers, once (now or at a time),
daily, on chosen weekdays or every N hours, in the timezone of the person who set it. Script runs back each router up
first (on by default; a router is skipped if that fails), run via REST `execute` over the tunnel (8 at a time), and
keep each router's output in **History**. Offline routers are skipped, or run when they come back within 24 hours. A
firmware task gives every target router with a newer RouterOS (or RouterBOARD firmware) the Upgrades page's safe
upgrade and skips routers already up to date - e.g. "All routers, Sundays 02:00" keeps everything current. Each router
page also has **Run script...** for a one-off. Every change and run is audit-logged.

## Integrations

Admin > Integrations (administrators). Keys are typed on the page, stored encrypted (AES-256-GCM, derived from the
master key) and never shown again - the page only says a key is saved. The server needs outbound HTTPS to the PSA and
IT Glue.

- **ConnectWise PSA** - site, company ID, public/private key of an API member with a *read-only* security role, and
  your client ID from developer.connectwise.com. Lists companies (filter by type/status) so you can import them as
  clients or link existing clients; matching names are suggested.
- **IT Glue** - region and an API key (leave "Password access" off). Link each client to its IT Glue organization (name
  matches are suggested), pick the configuration type for routers, then **Sync now** or leave the nightly update on.
  Each router becomes/updates a configuration (name, hostname, WAN IP, serial, MAC, RouterOS version, link back to
  TikManager); an existing configuration with the same serial is reused instead of duplicated.

Router thumbnails are matched by model against mikrotik.com's product catalog (refreshed weekly), downloaded once into
`/var/lib/tikmanager/thumbs/` and served by TikManager itself. Discontinued models and CHR show a generic icon.

## Admin

Admin (administrators only):
- **Branding** - product and company name, accent colour, logo (PNG/JPEG/WebP; without one the built-in TikManager
  logo is shown), sign-in message, support contact shown to clients.
- **Technicians** - roles (admin / tech / read-only), disable or enable, **Reset sign-in** (unlinks the Microsoft
  account and resets the authenticator app).
- **Integrations** - ConnectWise PSA and IT Glue (above).
- **Settings** - version & updates, staff sign-in, Microsoft sign-in, router settings, backup time and retention.

The **Audit log** (administrators) records every sign-in and every change, with who, when and from where.

**Appearance** (everyone): the palette button in the top bar chooses **light, dark or system** mode and a colour
theme - **Company colours** (the accent from Admin > Branding, the default), Navy, Slate, Ocean, Forest, Plum or Tiki.
It's saved to each person's account, so it follows them to any device.

## Keeping it secure

TikManager can change every router it manages, so treat the server like the keys to your clients' networks.
- Put it in a DMZ that can't reach your LAN; only 443/tcp and 51820/udp should reach it from the internet.
- Keep technician accounts on Microsoft sign-in with MFA in your tenant; give read-only to people who only need to look.
- The adoption command works for every router until you replace it: after adopting a batch of routers, an administrator
  should click **Replace command** on the Adopt routers dialog (routers already adopted keep working).
- Install updates when the badge appears; security fixes are called out in [CHANGELOG.md](CHANGELOG.md).
- Running a fork that your servers update from? Turn on two-factor authentication for your GitHub account and protect
  your `v*` tags - whoever can publish a release there can update your servers.
- Ubuntu installs its own security updates automatically (unattended-upgrades); check Caddy now and then with
  `sudo apt upgrade` - it comes from Caddy's own package repository.

**Check the server**: TikManager runs a read-only security check of its own server daily, after every upgrade and
when you click **Run check** on **Admin > Version & updates**, where the results are shown (set up by the installer, or
by upgrading to 1.9.0). You can also run it in a terminal:

    sudo bash /opt/tikmanager/deploy/check.sh

It checks the firewall (only 80, 443, 51820 and SSH from your LAN), SSH (no root login; keys rather than passwords;
fail2ban), automatic security updates and pending reboots, IP forwarding off, that the server can't open connections
into your LAN, what listens on the network, the HTTPS certificate, permissions on the key and settings files, that the
service can't change its own code, the service's sandbox, and how old the newest database copy is. Each line is PASS,
WARN or FAIL with what to do; it never changes anything. Two things it can't do for you: keep a copy of
`/etc/tikmanager/master.key` (and the database) somewhere off the server, and block the server from your LAN on your
network firewall.

### Fixing server security findings

Each WARN or FAIL on **Admin > Version & updates** has a **How to fix** link with these steps. Run the commands on the
TikManager server (SSH, as a user with sudo), then click **Run check** again.

| Finding | Fix |
|---|---|
| ufw is off | `sudo ufw --force enable` (the installer's rules are still there) |
| ufw doesn't deny incoming | `sudo ufw default deny incoming && sudo ufw reload` |
| SSH open to the whole internet | From your LAN or the console: `sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp` (your LAN), then `sudo ufw status numbered` and `sudo ufw delete <number>` for the 22/tcp ALLOW Anywhere rule |
| Extra ufw rules | `sudo ufw status numbered`, then `sudo ufw delete <number>` for rules you don't need |
| Root may sign in over SSH | `echo 'PermitRootLogin no' \| sudo tee -a /etc/ssh/sshd_config.d/01-hardening.conf` then `sudo sshd -t && sudo systemctl reload ssh` |
| SSH accepts passwords | On your PC: `ssh-keygen -t ed25519` and copy the key to the server (`~/.ssh/authorized_keys`); check key sign-in works in a new window; then `echo 'PasswordAuthentication no' \| sudo tee -a /etc/ssh/sshd_config.d/01-hardening.conf` and `sudo sshd -t && sudo systemctl reload ssh` |
| fail2ban isn't running | `sudo systemctl enable --now fail2ban` |
| Automatic security updates are off | `sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades` (answer Yes) |
| Security updates waiting | `sudo apt update && sudo apt upgrade` |
| Reboot needed | `sudo reboot` out of hours (routers keep working; TikManager is offline for about a minute) - or turn on automatic restarts (next row) |
| Nobody restarts the server / Caddy only updates by hand | `sudo install -m 0644 /opt/tikmanager/deploy/apt-unattended.conf /etc/apt/apt.conf.d/52tikmanager-unattended` (done by the installer and every upgrade from 1.9.2): restarts at 03:00 only when an update needs it, and includes Caddy's repository |
| Caddy's repository set aside | It wasn't answering (Cloudsmith "402" when its quota runs out). When `curl -sI https://dl.cloudsmith.io/public/caddy/stable/deb/debian/dists/any-version/InRelease` shows 200 again: `sudo mv /etc/apt/sources.list.d/caddy-stable.list.disabled /etc/apt/sources.list.d/caddy-stable.list && sudo apt update && sudo apt upgrade` |
| IP forwarding is on | `sudo sysctl -w net.ipv4.ip_forward=0` and `echo 'net.ipv4.ip_forward=0' \| sudo tee /etc/sysctl.d/90-tikmanager.conf` |
| Server can reach your LAN | Block only connections the server *starts* - your SSH / web access and the routers' tunnels (WireGuard, 10.77.x.x) keep working. Best on your **network firewall**, with the server in its own subnet / VLAN; on a MikroTik in front of it: `/ip firewall filter add chain=forward src-address=<server> dst-address=<LAN> connection-state=new action=drop` above your forward accepts (plus a DNS accept if your DNS server is on the LAN). Extra layer on the server, in this order: `sudo ufw allow out proto udp from any port 51820 to <LAN>`, `sudo ufw allow out to <DNS server> port 53` (if it's on the LAN), `sudo ufw deny out to <LAN>` |
| Also listening | `sudo ss -tulpn` to see the program; `sudo systemctl disable --now <service>` if you don't need it |
| TM_HOST isn't 127.0.0.1 | Set `TM_HOST=127.0.0.1` in `/etc/tikmanager/tikmanager.env`, then `sudo systemctl restart tikmanager` |
| Caddy isn't running | `sudo systemctl restart caddy`; `sudo journalctl -u caddy -n 50 --no-pager` |
| Certificate expiring / unreadable | Check the DNS name points at the server and ports 80 + 443 reach it; `sudo journalctl -u caddy --since '2 days ago' \| grep -iE 'error\|certificate'` |
| Key / settings file permissions | `sudo chown root:tikmanager <file> && sudo chmod 640 <file>` (master.key, tikmanager.env); `/etc/wireguard/wg0.conf`: `sudo chown root:root` and `sudo chmod 600` |
| Service can write its own code | `sudo chown -R root:root /opt/tikmanager && sudo chmod -R go-w /opt/tikmanager` |
| Data folder not private | `sudo chown -R tikmanager:tikmanager /var/lib/tikmanager && sudo chmod o-rwx /var/lib/tikmanager` |
| tikmanager account can log in / is an admin | `sudo usermod -s /usr/sbin/nologin tikmanager`; `sudo gpasswd -d tikmanager sudo` |
| tikmanager isn't running | `sudo systemctl restart tikmanager`; `sudo journalctl -u tikmanager -n 50 --no-pager` |
| Service sandbox changed | `sudo rm -rf /etc/systemd/system/tikmanager.service.d`, `sudo cp /opt/tikmanager/deploy/tikmanager.service /etc/systemd/system/`, `sudo systemctl daemon-reload && sudo systemctl restart tikmanager` |
| No database copy / old copy | `sudo systemctl stop tikmanager && sudo tar czf /root/tikmanager-$(date +%F).tgz /var/lib/tikmanager /etc/tikmanager; sudo systemctl start tikmanager`, then download it to a safe place and delete it from the server - it contains the master key |

How it's built to be safe (tunnels, encryption, least privilege, the updater): [ARCHITECTURE.md](ARCHITECTURE.md).

## Where things live on the server

| What | Where |
|---|---|
| Code | `/opt/tikmanager` (root-owned, read-only to the service) |
| Database | `/var/lib/tikmanager/tikmanager.db` |
| Settings / master key | `/etc/tikmanager/` (root:tikmanager, 0640) - back up `master.key`: without it stored configurations can't be decrypted |
| WireGuard | `/etc/wireguard/wg0.conf` (controller key); router peers come from the database |
| Logs | `journalctl -u tikmanager`, `/var/log/caddy/tikmanager.log` |
| Updater | `tikmanager-update.path` / `.service` (root), log `journalctl -u tikmanager-update`, progress `/var/lib/tikmanager-update/status.json` |
| Before the last upgrade | code `/opt/tikmanager.prev`, database `/var/backups/tikmanager/backup-before-<version>.db` (last 3, root only) |

The service runs as user `tikmanager` with only `CAP_NET_ADMIN` and a read-only filesystem except its data folder.

## If a router registers but never comes online

The router reaches TikManager over HTTPS to register, but monitoring needs its WireGuard tunnel (UDP 51820) to reach
the server.
1. On the server: `sudo wg show` - no "latest handshake" under the router's peer means its packets aren't arriving.
2. `sudo timeout 40 tcpdump -lni <nic> udp port 51820` on the server shows whether anything arrives at all.
3. On the edge router, the port forward must be **UDP** 51820 -> the server (a TCP-only rule passes HTTPS but not
   WireGuard):
   `/ip firewall nat add chain=dstnat dst-address=<public IP> protocol=udp dst-port=51820 action=dst-nat to-addresses=<server IP> comment="TikManager WireGuard"`
4. After adding or changing that rule, clear the router's old connection-tracking entry - otherwise packets keep
   following it and skip the new rule: `/ip firewall connection remove [find protocol=udp dst-address~"<public IP>:51820"]`
5. A router whose handshake failed stops retrying after ~90 s; `/ping 10.77.0.1 count=5` on the router makes it try again.

If the adoption command stops right after creating the `tikmanager` interface, the router's terminal (or
`/log print`) shows why; run the command again once that's fixed - it picks up where it left off.

## Try it locally (dev mode, simulated routers)

    set TM_DEV=1
    set TM_PORT=8801
    set TM_PUBLIC_URL=http://localhost:8801
    python server.py

Open http://localhost:8801 and use **Dev sign-in** (only offered when you open it on the same machine, never through a
proxy). Dev mode simulates routers, so every page works without hardware. Data goes to `./data/` (delete it to start
over).
