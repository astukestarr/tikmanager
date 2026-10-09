# Changelog

Versions follow [semantic versioning](https://semver.org): **patch** (1.0.x) = fixes, **minor** (1.x.0) = new features,
safe to upgrade with the button; **major** (x.0.0) = changes that need manual steps (described here).

## 1.6.1 - 2026-10-09

- **Updates show up sooner**: TikManager now checks GitHub for a new release every hour (was once a day), and open
  pages pick up the answer within 5 minutes (was 30).
- **Check for updates** button next to the version number at the top of every page (administrators) - asks GitHub
  right away and says "Up to date" or which version is available (and shows the banner again if it was hidden).

## 1.6.0 - 2026-10-09

- **Firewall & NAT rules** on each router's page (technicians): filter and NAT rules with their traffic counters, by
  chain. Technicians with write access can add, edit, enable / disable, delete and reorder rules.
- **Changes are tested like Safe Mode in Winbox.** Before the first change TikManager saves the current rules on the
  router and starts a 5-minute timer; after each change it checks it can still reach the router. Press **Keep
  changes** once you've checked everything still works, or **Undo now**. If nobody keeps them in time - or a change
  cuts TikManager off - the router puts the rules back by itself. The router is backed up before the first change
  (unless it was in the last 10 minutes). TikManager's own rules and dynamic rules are locked; every change is in the
  audit log.
- **Site map**: routers set to the same spot no longer hide each other - clicking a group that can't be separated by
  zooming lists its routers, and a **Routers sharing a location** list under the map shows them so a wrong one is easy
  to find and fix.
- **Server security check**: `sudo bash /opt/tikmanager/deploy/check.sh` checks the Ubuntu server is still locked down
  (firewall, SSH, automatic updates, open ports, certificate, file permissions, the service's sandbox, whether the
  server can reach your LAN) and says what to fix. It only reads; it never changes anything.

## 1.5.1 - 2026-10-09

- **Router upgrades**: downloading a new RouterOS could fail with "HTTP 400: Session closed" on routers with a slower
  internet connection - RouterOS ends any single API request after about a minute, and a big download takes longer.
  The download now runs as a background job on the router while TikManager watches its progress (up to 15 minutes).
  A failed download never reboots the router; just run the upgrade again.

## 1.5.0 - 2026-10-09

- **Geographic map** (Site map > Map): every router where it is, from the whole country down to town level - state
  borders, county lines, interstates and the name of every incorporated US city and town appear as you zoom in. Routers
  group into numbered clusters when zoomed out (red if one is offline); click one to open it. Drawn by TikManager from
  built-in public-domain map data - nothing is loaded from other sites.
- **Router location**: set on the router's page - type an address, look it up (optional: only the text you type is
  sent to OpenStreetMap's address search), enter coordinates, or click the spot on the map. Routers with a GPS receiver
  place themselves; a location set by hand always wins.
- **Network map** on each router's page (like Auvik's): Internet and gateway -> router -> its networks and VLANs ->
  switches and access points found by neighbour discovery (MNDP / LLDP / CDP), each with the devices on its port ->
  groups of devices (phones, printers, servers & VMs, cameras, computers, personal devices, IoT, unidentified) -
  click a group for its devices (name, IP, MAC, port). Routes to other networks (VPN, static, dynamic) are listed
  for technicians; client users see their networks but not the routing table.

## 1.4.0 - 2026-10-09

- **New look**: a full-height coloured sidebar with the logo, who's signed in and an icon for every page; a clean top
  bar; cards with soft shadows; KPI tiles with a coloured top edge; calmer tables. Works on phones (the menu slides in).
- **Appearance, per person**: the palette button in the top bar picks light, dark or system mode and a colour theme -
  Company colours (the accent from Admin > Branding, the default), Navy, Slate, Ocean, Forest, Plum or Tiki. Saved to
  each person's account, so it follows them to every device.
- **New version banner**: when a newer release is out, administrators see a banner across the top of every page with
  the new and current version, What's new and Upgrade now (hide it for a day with x). It checks again every 30
  minutes, and shows progress while an upgrade runs.
- The installed version is shown next to the logo for everyone.

## 1.3.0 - 2026-10-09

- **Subnets in use**: a new Subnets page lists every LAN subnet on every approved router, grouped by client, with its
  name, router, interface, gateway and size. Subnets that overlap another of the same client's subnets are flagged (a
  site-to-site VPN couldn't route both), as are the MikroTik factory default (192.168.88.0/24) and ranges also used at
  other clients. Search by subnet, name, router or an IP address (finds the subnet it belongs to), show only overlaps,
  and export to CSV. Client users see only their own.

## 1.2.0 - 2026-10-08

- **Install straight on Ubuntu**: `deploy/get.sh` downloads the newest release from GitHub on the server itself and
  installs it - no Windows PC or file copying needed. It asks for the public name and LAN subnet if you leave them out
  (and suggests the server's own subnet). See README > Install on a server.
- **Forks**: `--repo owner/repository` (get.sh and install.sh) installs from your own repository and makes it the
  server's update source.
- Existing installations: nothing to do - upgrade with the button as usual.

## 1.1.1 - 2026-10-08

Security fixes from a review of the whole project. Upgrade with the button as usual.

- **Updater**: the root updater no longer writes into the web app's own folder, where a compromised web app could have
  planted links to make root overwrite or hand over other files. Upgrade progress now lives in
  `/var/lib/tikmanager-update/`, and database copies taken before an upgrade in `/var/backups/tikmanager/` (root only).
  The updater also refuses to install an older version than the one installed.
- **Sign-in**: an account locked after failed attempts can no longer keep trying authenticator codes, and three wrong
  codes end the sign-in. Signing in with an unknown email takes as long as with a known one.
- **Microsoft sign-in**: guest accounts are refused, and each technician is tied to their Microsoft account's permanent
  ID, so a renamed or reused email address doesn't inherit an old account. Admin > Technicians > **Reset sign-in**
  unlinks an account (and resets its authenticator app).
- **Error pages** escape everything they show (a crafted sign-in link could put fake text on the page).
- **Dev sign-in** only works for requests made on the machine itself, never through Caddy, even if dev mode were
  switched on by mistake.
- **Client users** no longer receive TikManager's internal notes and bookkeeping fields for their routers.

## 1.1.0 - 2026-10-08

- **Routers list**: click a column header to sort by it (Status, Client, Router, Site, Model, RouterOS, Uptime, CPU,
  Last seen); click again to reverse. Status sorts offline routers first. The sort is kept while you use the app.

## 1.0.0 - 2026-10-08

First public release.

- **Adoption**: one command for every router (RouterOS 7); routers register, a technician approves them and picks the
  client. WireGuard tunnel per router (keys stay on the router), automatic free listen port, idempotent re-runs.
- **Monitoring**: status, interfaces, traffic and latency/packet-loss charts (1 h - 1 month), DHCP clients, LTE, Wi-Fi,
  site map with subnets and overlap warnings, events.
- **Configuration backups**: nightly `/export` as a restorable script, deduplicated, encrypted, diff between versions,
  keep the newest N per router.
- **Upgrades**: RouterOS / RouterBOARD firmware now, scheduled, or in bulk with stagger; backup first, automatic waits.
- **Tasks**: script library with per-router placeholders, router groups, scheduled script runs and automatic firmware
  updates, run history with output.
- **Site-to-site VPN**: WireGuard hub and spoke built and removed by TikManager; inventory of VPNs already on routers.
- **Router identity** changeable from the web; move routers between clients.
- **Clients and users**: client portal (read-only) with password + mandatory TOTP; technicians via Microsoft Entra;
  roles; audit log.
- **Integrations**: ConnectWise PSA (client import) and IT Glue (router documentation).
- **Setup and settings**: one-time first-run link; Admin > Settings for staff sign-in, Microsoft sign-in, router and
  backup settings; branding, with a built-in TikManager logo (the T drawn as a tiki torch) until you upload your own.
- **Updates**: version shown in the app, daily check for new releases, one-click upgrade with automatic roll-back.
