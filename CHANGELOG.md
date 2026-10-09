# Changelog

Versions follow [semantic versioning](https://semver.org): **patch** (1.0.x) = fixes, **minor** (1.x.0) = new features,
safe to upgrade with the button; **major** (x.0.0) = changes that need manual steps (described here).

## 1.11.0 - 2026-10-09

- **Website security grade** on Admin > Version & updates: TikManager asks Mozilla's HTTP Observatory to check its
  public address from the internet - security headers, cookies, HTTPS redirects - weekly, after every upgrade, and
  when you click **Scan now**, and shows the grade (A+ to F), the points, how many tests passed and a link to
  Mozilla's full report. Only the host name is sent to Mozilla (it's public already). Skipped in dev mode and for
  addresses the internet can't reach; `TM_OBSERVATORY=0` turns it off.

## 1.10.0 - 2026-10-09

- **Security** (new page, technicians): sign-in attempts on everything someone could try to get into, in one place -
  - **TikManager itself**: failed passwords, wrong MFA codes, failed Microsoft sign-ins, accounts locked after too
    many failures, addresses refused for too many attempts, old or wrong adoption commands - and successful sign-ins.
  - **Its Ubuntu server**: SSH sign-ins (failed and accepted), sudo password failures and fail2ban blocks, collected
    every 5 minutes by a small read-only root service (`tikmanager-authlog.*`, set up by the installer and this upgrade).
  - **Routers**: Winbox / SSH / WebFig / API login failures and logins, and who changed the configuration ("changed
    by alan@10.0.20.15"). Routers already send their log to TikManager over the tunnel (since adoption); TikManager now
    receives it - on the tunnel address only - and leaves out its own routine logins.
  - Totals for 24 hours / 7 days / 30 days, the **top addresses trying to get in** (where they tried, which usernames,
    whether fail2ban blocked them), routers with the most failures, a searchable event list, and **Worth a look**
    flags: password guessing (10+ tries in an hour), one address trying several systems, a successful sign-in right
    after a run of failures, and TikManager's own router login failing. Kept 90 days.

## 1.9.2 - 2026-10-09

- **Automatic restarts and Caddy updates**: the installer and every upgrade now set Ubuntu's automatic security updates
  to restart the server at 03:00 - only when an update needs it (kernel / core libraries) - and to keep Caddy updated
  too (it comes from its own repository, which the automatic updates skipped). Routers keep working during the
  restart; TikManager is offline for about a minute. The server security check reports both.
- **Installs no longer fail when Caddy's repository is down.** Caddy's packages are hosted on Cloudsmith, which refuses
  downloads ("402 Payment Required") when the project's free quota runs out - as it has since 2026-10-09. The installer
  now sets that repository aside when it's the only one failing and installs Caddy's official package from GitHub
  instead (checked against the release's SHA-512 checksums). The security check says when the repository has been set
  aside and how to turn it back on.
- **Server can reach your LAN - corrected steps**: block only connections the server starts, with the WireGuard
  exception first so tunnels to routers on that LAN keep working, and an example rule for a MikroTik in front of the
  server.

## 1.9.1 - 2026-10-09

- **How to fix** on every server security WARN / FAIL (Admin > Version & updates): why it matters, the steps, and the
  exact commands - with commands for your PC and for the server shown separately - plus a link to the same steps in
  the README ("Fixing server security findings"). Each check now carries an ID in its results so the right steps
  always show.

## 1.9.0 - 2026-10-09

- **Server security on Admin > Version & updates.** The read-only server check (`deploy/check.sh`) now runs by itself
  - daily, after every upgrade, and when an administrator clicks **Run check** - and its results show on the page:
  what to fix, what to look at, and what passed. It runs as root through a small fixed service
  (`tikmanager-check.*`, like the upgrade helper): the web app can only ask for a run and read the results; it can't
  change what runs. Set up by the installer, and on existing servers by this upgrade.
- **Security best practices** list under it: the things a script can't check for you (an off-server copy of the
  master key, blocking the server from your LAN, MFA, replacing the adoption command, ...).
- Fixed: the **Check for updates** button on the Version & updates card could act on the top-bar button instead (both
  had the same ID since 1.6.1).

## 1.8.1 - 2026-10-09

Security checkup of everything added since 1.1.1 (firewall / NAT / address-list editing, Discovered, maps and address
lookup, appearance, update checks). No serious problems found; these tighten things up:
- **Firewall undo script runs with fewer rights**: the script and scheduler TikManager leaves on a router during a test
  now only have read and write (they had policy and test as well, which they never needed).
- **Router IDs are checked** before they're used in a REST request or the undo script, so a router reporting a
  malformed item ID can't get anything extra into the script.
- **Discovered**: a router's neighbour list is capped (500 devices, 200 characters per field), so a misbehaving router
  can't fill TikManager's database.
- The version header that lets open pages reload after an upgrade is no longer sent to people who aren't signed in.

## 1.8.0 - 2026-10-09

- **Discovered** (new page, technicians): MikroTik devices your routers see next to them in IP > Neighbors (MNDP / LLDP /
  CDP) that aren't in TikManager - routers, switches and access points you could adopt. Each shows its identity,
  model, RouterOS version (flagged when it's still on v6), IP and MAC, which routers saw it on which port, and how long
  it's been up. A device already counts as in TikManager when its MAC, IP or identity matches a router TikManager has
  or is waiting to approve (the factory identity "MikroTik" alone doesn't count). Neighbours are read every 15
  minutes; filter by client or search.

## 1.7.0 - 2026-10-09

- **Address lists** - a third tab on a router's Firewall & NAT card, like WebFig's Address Lists: pick a list (with how
  many entries it has), search it, and add, edit, enable / disable or remove addresses. **Add address** can create a
  new list; an entry can be moved to another list. Entries added by rules (dynamic, with a timeout) can be removed -
  e.g. to unblock an address a port-scan rule caught - but not edited.
- Address-list changes are **tested like rule changes** (Keep / Undo, undone by the router itself after 5 minutes if
  not kept), so removing your own address from an allow list can't lock you out for good. Lists can be huge, so they
  aren't copied: each change adds its own reverse step to the undo script. Rule and address-list changes can be mixed
  in one test.

## 1.6.5 - 2026-10-09

- **Firewall rule editor: Chain and Jump target are pulldowns** of every chain on the router (the built-in ones plus
  any custom chains its rules use or jump to), with **New chain…** to type a new one. Before, the chain box only
  suggested names matching what was already in it, so only the current chain was offered.

## 1.6.4 - 2026-10-09

- **Open pages pick up a new version by themselves.** A browser tab opened before TikManager was upgraded kept running
  the old page (so new features - like 1.6.3's rule editor - didn't appear until you reloaded). Pages now reload on
  their own once the server reports a new version - never while a dialog is open or you're typing.

## 1.6.3 - 2026-10-09

- **Firewall rule editor laid out like WebFig**: Enabled and Comment at the top, then General (chain and match fields)
  and Action. Match fields are added with **+** and removed with **-**, and each has a **!** (not) switch.
  In / Out Interface offer the router's interfaces plus all ethernet / ppp / vlan / wireless; interface lists and
  address lists are pulldowns of the router's own; Connection State and Connection NAT State are tick boxes. Ports can
  only be set once a protocol with ports (tcp, udp ...) is chosen; action-specific fields (jump target, reject with,
  address list, NAT targets) appear for the action picked.

## 1.6.2 - 2026-10-09

- **Firewall rules: address lists are pulldowns.** Source and destination address list now offer the router's own
  address lists ("in" or "not in" each one) instead of a text box; "Add to address list" suggests the existing lists
  and still accepts a new name. Changes to a rule's lists show in the audit log.

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
