# Changelog

Versions follow [semantic versioning](https://semver.org): **patch** (1.0.x) = fixes, **minor** (1.x.0) = new features,
safe to upgrade with the button; **major** (x.0.0) = changes that need manual steps (described here).

## 1.32.0 - 2026-10-12

- **Webhooks** (Alerts page, administrators): every alert - when it opens and when it clears - to any number of
  endpoints, each optionally limited to some kinds of alert:
  - **Slack**, **Discord**, **ntfy** (push notifications to your phone), **TikManager JSON**, or **Custom** - your own
    method, headers and body template with {{placeholders}} (title, detail, status, kind, router, client, link, time,
    summary), escaped for JSON when the body is JSON, so an SMS gateway or another ticket system can be driven.
  - Optional **signing**: X-TikManager-Signature: sha256=HMAC(timestamp.body) with X-TikManager-Timestamp.
  - **Test** button and the last result per webhook. URLs, secrets and header values are stored encrypted and never
    shown again.
  - Only https:// to internet addresses - a webhook can't be pointed at this server or anything on a LAN.

## 1.31.0 - 2026-10-12

- **Tags and notes** for routers (router page > Settings > **Tags & notes**): tags such as *core*, *poe-switch* or
  *tower-north* (suggested from the ones already in use), and free-text notes - rack position, ISP contract, quirks.
  - Tags show under the router's name in the list and on its page; the Routers page has a **tag filter**, and its
    search also finds tags and notes. The Upgrades search finds tags too.
  - **Tasks can target tags** - a task for *core* runs on whatever routers carry that tag when it runs.
  - Notes are for technicians only: clients don't see them. Changes are audited.

## 1.30.0 - 2026-10-12

- **Restart detection**: a router that restarts is noticed from its uptime going back - also when it was back before
  anyone could see it offline. An event says when it restarted and how long it had been up; the router's page shows
  **Last restart** (marked *unexpected* unless an upgrade was running). New alert (on by default): **Router restarted
  unexpectedly** - not during an upgrade; it clears by itself after 15 minutes.

## 1.29.0 - 2026-10-12

- **Internet links**: each router's ISP / WAN / LTE links are watched every minute - up or down, their address, since
  when, and which one carries the traffic now (the default route), so a failover to LTE is visible.
  - Which interfaces count: automatic (a comment saying ISP, WAN, internet, Starlink, DSL, LTE or 5G - e.g. "ISP1",
    "ISP2 LTE", "Backup WAN" - plus PPPoE clients and LTE modems, else the default route's interface), or picked on the
    router's Settings tab.
  - Router page: an **Internet links** card. Events when a link goes down, comes back or changes its address.
    Dashboard: **Internet links down** on routers that are still reachable.
  - New alert (on by default): **Internet link down** for N minutes (default 3) on a router that's still reachable - the
    detail says which link it's running on instead. An offline router stays the offline alert's business.

## 1.28.0 - 2026-10-12

- **Hardware health** (router page, Overview): every sensor the board has - temperatures, voltage, fans, power - and
  each fibre module's light in / light out (dBm) and temperature, read every 5 minutes and kept 30 days. Each reading
  is a tile with its current value, a line over the chart's time range and the low-high; weak fibre light and hot
  temperatures are coloured. The Interfaces table shows fibre light levels too. Fibre readings come from the port
  monitor TikManager already reads each minute, so they cost no extra router requests.
- **New alerts** (off by default, Alerts > Settings): **Router memory high** (10-minute average, default 90%) and
  **Router too hot** (three readings in a row - 15 minutes - over the limit, default 70°C; fibre modules don't count),
  so a brief spike stays quiet. Both clear with a little hysteresis rather than flapping.

## 1.27.0 - 2026-10-12

- **Auto-block** (Security page): an address with N failed sign-ins to your routers within M minutes - counted across
  the whole fleet, from the routers' logs (default 5 in 10 minutes) - is blocked on **every** router: it goes on the
  `tikmanager-blocklist` address list with a RouterOS timeout (default 72 hours), so routers forget it on their own;
  routers that were offline get it when they're back.
  - Modes: **Off** (default), **Audit** (lists them; block by hand) and **Block automatically**.
  - Never blocked: anything that isn't a public address, TikManager itself, your routers' own addresses and a
    whitelist. An address unblocked by hand isn't re-blocked for its old failures.
  - TikManager doesn't change firewall rules on its own: the card lists routers with no rule dropping the list and can
    add one (`/ip firewall raw add chain=prerouting action=drop src-address-list=tikmanager-blocklist`, which only drops
    listed addresses) - per router or all at once. Blocks, unblocks and rule changes are audited.

## 1.26.0 - 2026-10-12

- **RouterOS security**: two separate signals per router, kept apart because they claim different things:
  - **Security releases** - MikroTik's own changelogs are read (once per release) and a router is marked when a release
    newer than its RouterOS, on the way to its channel's newest, fixed something security-related (a CVE named, or a
    "security issue / update / fix", vulnerability, exploit ... line - including notices like 7.24.2's "important
    security update" that name no CVE). MikroTik's "!)" alone isn't taken as security: it marks any important change.
  - **Known CVEs** - NIST's National Vulnerability Database (refreshed daily) is matched on the router's RouterOS
    version, with CVSS score, summary and the version that fixes it. Informational; NVD ranges are sometimes imprecise.
  - Router page: a **Security** line in the side panel and a **RouterOS security** card listing the security releases
    (with their notes) and CVEs. Upgrades page: **security** and **CVE** badges. Security page: a **RouterOS
    vulnerabilities** card for the whole fleet. New alert (on by default): **Router needs a RouterOS security update**
    (a security release, or a CVE scored 7 or more).
- **What's new**: MikroTik's release notes for a version, security lines first, one click from the router's upgrade
  box, the Upgrades table and the security card - read before you upgrade.
- Fixed: router age (1.22.0) couldn't read MikroTik's newer changelog date format (e.g. "2026-09-03"), so routers
  that left the factory with recent RouterOS showed no age.

## 1.25.0 - 2026-10-12

- **Compromised-router detection**: RouterOS (7.13+) checks its own configuration at startup and, on finding signs of
  unauthorized access, turns off the risky settings and flags itself (device-mode). MikroTik's guidance is to treat a
  flagged router as compromised - but the flag lived only on the router. TikManager now reads it every hour:
  - a red banner on the router's page with what to do (look for what you didn't add, Netinstall and restore a trusted
    configuration, how the flag is cleared), a **Flagged** badge in the routers list, and a tile and card on the Dashboard;
  - an event when a router becomes flagged, and a new alert (**Router flagged as possibly compromised**, on by
    default) as a ConnectWise ticket / Teams card / email;
  - the router's device mode is shown on its page. Read-only: device-mode can only be changed at the router.

## 1.24.2 - 2026-10-11

- **Wireless tab, 60 GHz access point side**: in multipoint mode the AP's own interface reports "not running" while
  each connected station has its own interface, so the AP showed its station with no signal, rate or distance. Each
  station's link is now read from its own interface (signal, quality %, MCS, rate, distance), and the radio shows how
  many stations are connected. 60 GHz distances in the client table are in metres.

## 1.24.1 - 2026-10-11

- **Wireless tab names the other end** when it's one of your routers in TikManager (matched by its interface MAC
  addresses), with a link to its page - 60 GHz radios report only the far end's MAC, and a bridged link has no DHCP
  lease or ARP entry to take a name from. Clients only see matches among their own routers.
- 60 GHz rates show as e.g. "2.3 Gbps" (the radio reports plain bits per second), distance in metres, and "Link up" is
  left out when the radio doesn't report it.

## 1.24.0 - 2026-10-11

- **Suggested replacement** for discontinued and 5+-year-old routers - on the router page and in the Dashboard's
  Lifecycle card, with a link to the model's mikrotik.com page and why it fits (e.g. hAP ac² -> hAP ax², CCR1009 ->
  CCR2004-16G-2S+, RB2011 -> L009UiGS-RM, cAP ac -> cAP ax, SXTsq 5 ac -> SXTsq 5 ax). MikroTik names no successors,
  so TikManager has a short list per old family; a suggestion is only shown while MikroTik still sells it (checked on
  its product page).
- **Your own standard** per model: Admin > Settings > **Replacement suggestions** lists the discontinued / old models
  in use; paste a mikrotik.com product link to suggest that instead (clear it to go back). Changes are audited.

## 1.23.1 - 2026-10-11

- **Wireless tab: 60 GHz radios** - the tab now appears for every 60 GHz interface type, and connected 60 GHz stations
  (the dynamic *w60g-station* interfaces of a multipoint AP) are shown as clients of their radio instead of being
  missed. When a router has no radio TikManager recognises, the tab lists the interface types the router reported, so
  an unusual model can be added.

## 1.23.0 - 2026-10-11

- **Wireless tab** on the router page (routers with radios): read live from the router and refreshed every 10 seconds
  while it's open (**Pause** stops it). Works with all three MikroTik radio menus - legacy wireless (incl. NV2 /
  Nstreme), the wifi package and 60 GHz (w60g).
  - Each radio: mode, SSID, band, channel / frequency, width, protocol, noise floor, CCQ and TX power.
  - **Point-to-point links** (station, or an AP in bridge mode): signal at both ends, signal-to-noise, CCQ, TX / RX
    rates, distance, link uptime and who it's connected to - coloured excellent / good / fair / poor.
  - **Access points** (office Wi-Fi or an ISP sector): every client with name, IP, MAC, signal (bar and dBm, plus what
    the client hears where the radio reports it), SNR, CCQ, rates, band, distance, connected time, traffic and
    RouterOS version; average signal and how many are weak; weakest first, searchable. Names and IPs come from the
    radio, DHCP leases or ARP.

## 1.22.0 - 2026-10-11

- **Router lifecycle**: how old each router is and whether MikroTik has discontinued the model, so replacements can be
  planned (and clients can see it too).
  - **Age** comes from the router's factory firmware - the RouterOS version it left the factory with - dated by
    MikroTik's own changelog (to within a few months; factory firmware 3.x means before about 2017).
  - **Discontinued** comes from the model's mikrotik.com product page, re-read weekly. MikroTik publishes no
    end-of-life or end-of-support dates (sites like eol.network use the same "Discontinued" mark), so discontinued
    means no longer sold, not unsupported.
  - Router page: **Made** and **Lifecycle** (with a link to the product page) and a note when it's time to plan a
    replacement. Routers list: an **Age** column (sortable) and **Discontinued model** / **5+ years old** filters.
    Dashboard: a **Lifecycle** card listing discontinued and old routers, oldest first.
- Discontinued models now get their product picture too (found through mikrotik.com's sitemap).

## 1.21.0 - 2026-10-11

- **Email** (Admin > Integrations > Email): TikManager can send email through **Microsoft 365** (Microsoft Graph,
  an app with the Mail.Send application permission - limit it to the sending mailbox) or any **SMTP** server
  (STARTTLS or TLS with the certificate checked; unencrypted only to a relay on the server itself). Secrets are stored
  encrypted like the other integration keys. **Send a test to me** checks the setup.
- **Client invitations are emailed** when email is set up (the link is still shown, in case you'd rather send it).
- **Email alerts**: Alerts > Settings can email each problem, and when it clears, to one or more addresses.
- Addresses are validated (no header injection) and at most 200 emails an hour are sent.
- **Fixed**: long values (addresses, folders) ran off the page in About this installation and other cards.

## 1.20.0 - 2026-10-11

- **Server security grade** (Admin > Version & updates): the server security check now shows a grade, like the website
  grade. 100 points, minus 20 for each FAIL and 5 for each WARN; any FAIL means C at best, so a real problem can't hide
  behind lots of passes; **A+** means nothing to fix or look at.

## 1.19.1 - 2026-10-11

Security review of everything added since 1.8.1 (security events, alerts, off-site backup, script library, Winbox
relay, WireGuard port, connectivity test, root helpers). All 110 API endpoints require the right sign-in, every POST
is CSRF-checked, nothing server-supplied reaches the page unescaped, and the strict content security policy still
holds. Fixed:
- **Moving the WireGuard port could strand routers** (1.19.0): routers were switched before the server confirmed it had
  moved - e.g. "Use UDP 443" while Caddy holds UDP 443 for HTTP/3 would point every router at a port WireGuard
  wasn't listening on. Now the root helper first checks the port is free (and says what's using it and how to free
  it), nothing on any router changes until the server has really switched, and a failure changes nothing at all.
  New installs turn off Caddy's HTTP/3 (TikManager doesn't use it), so UDP 443 is free; on existing servers the
  helper explains the one-line Caddy change if you want UDP 443.
- **The old-port relay is bounded** (512 senders at once) - UDP sender addresses can be faked, so it could otherwise be
  made to open sockets without limit.
- **Router log flood limit**: 120 lines a minute per router are kept, so one misbehaving router can't fill the database
  (routers can only send over their own tunnel).
- **Off-site backup to WebDAV requires https://** - plain http would send the storage password unencrypted.
- The "one event per 5 minutes" throttle no longer grows without limit under attack from many addresses.

## 1.19.0 - 2026-10-11

- **Change the WireGuard port** (Admin > Settings > **WireGuard port**) - e.g. when an ISP or a client's network blocks
  51820, or something else needs it. **Use UDP 443** is one click: the port most likely to get through restrictive
  networks (hotels, guest Wi-Fi, some mobile carriers). Routers already adopted are moved **without dropping off**:
  1. Forward the new UDP port to the server on your edge firewall (keep the old one for now) and press Move.
  2. A root helper (`tikmanager-wgport.*`) moves wg0 to the new port and opens it in the server firewall; TikManager
     relays the old port to the new one meanwhile, so routers still on the old port stay connected.
  3. Every online router's tunnel is switched to the new port through that tunnel; offline routers are switched as
     soon as they reconnect. The card lists who hasn't moved yet.
  4. **Close old port** stops the relay and removes the old port from the server firewall.
  New adoptions use the new port immediately. Moving away from a port below 1024 (e.g. from 443) moves online routers
  first, because the old port can't be relayed.
- New installs: `--wg-port <port>` (also via `get.sh`) picks the port from the start.
- The connectivity test, the server security check and their How to fix steps now use the actual WireGuard port
  instead of assuming 51820.

## 1.18.0 - 2026-10-11

- **Router page in tabs**: the right side is split into **Overview** (traffic chart, health, interfaces), **Network**
  (DHCP clients, VPNs, network map), **Firewall**, **Backups**, **Events** and **Settings** (location, manage) instead
  of one very long page. Only the open tab is loaded, so pages open faster; the tab you were on is remembered when you
  move to another router. **Back up now** on the left opens Backups and starts the backup there.
- **The left panel scrolls on its own** when it's taller than the window (it stays below the top bar), so everything in
  it - upgrades, Winbox, health - is reachable without scrolling to the bottom of the page first.

## 1.17.2 - 2026-10-11

- Fixed: on the router page, the Winbox address, login and password (and their Copy / Show buttons) ran off the side
  panel. Each value now has its own full-width line with the buttons underneath, and a long address breaks at a dot
  or before the port - never in the middle of the port number. Copying still copies the whole address.

## 1.17.1 - 2026-10-11

- **Winbox session password hidden**: it shows as dots on the router page (and isn't in the page's text, so it stays out
  of screenshots and screen shares). **Copy** copies it; **Show** reveals it for 10 seconds if copying is blocked.

## 1.17.0 - 2026-10-11

- **Who changed what over Winbox**:
  - **A router login per session**: Open Winbox now also creates a temporary login on the router just for you (e.g.
    `alan.tm`, random password shown only to you), allowed to sign in only from TikManager's tunnel address, and deletes
    it when the session ends. It's in the router's **full** group for TikManager administrators and technicians, and
    **read** for read-only technicians - who can now open Winbox too, to look but not change. The router's own log then
    says "changed by alan.tm", and nobody needs the shared admin password day to day. Leftover session logins (e.g.
    after a restart) are removed within the hour.
  - **A backup when the session ends**: labelled "after Winbox session 14:02-14:31 · technician", so a configuration's
    **What changed** shows exactly what that session did (nothing is saved if nothing changed).
  - **Router log lines are labelled with the session's technician** on the Security page - "Winbox session of
    alan@..." - and "probably the Winbox session of ... (shared router login admin)" when someone signs in with a
    shared login through the relay.
- Configuration backups now show why each version was taken (nightly, by hand, before a firewall change, after a
  Winbox session) and who caused it - before, everything but manual backups said "nightly".

## 1.16.0 - 2026-10-11

- **Winbox through TikManager** (router page > Winbox > **Open Winbox**, technicians with write access): TikManager opens
  a port from a small pool (TCP 40000-40049) on its own address and relays it to the router's Winbox over the router's
  existing tunnel - so Winbox never has to be open on a router's internet side, and it works for routers with no public
  address of their own. Type the `host:port` it shows into Winbox's Connect To and sign in with your own router login.
  - Each session only accepts **your public address** (editable, e.g. if your Winbox goes out through a VPN); anyone
    else is disconnected at once and it's recorded on the Security page.
  - **30 minutes** (Extend adds 30, up to 4 hours), closed after 10 minutes without traffic, or with Close.
  - A relay inside TikManager - IP forwarding stays off on the server; Winbox's own encryption passes through untouched.
  - Every session (who, router, from where, how long, how much) is in the audit log and on the Security page.
  - If a router's Winbox is off or only accepts certain addresses, one click lets TikManager's tunnel address in (turning
    it on restricts it to that address alone, never the internet).
  - **Forward TCP 40000-40049 to the TikManager server on your edge firewall.** This upgrade opens the range in the
    server's own firewall (ufw); the security check expects it.

## 1.15.0 - 2026-10-11

- **Off-site backup** (Admin > Settings): a copy of TikManager on storage you own - **FTPS** (recommended), FTP or
  **WebDAV** (Nextcloud, ownCloud, Synology / QNAP, Box ...). Choose **Full** (the database - routers, clients, users,
  the routers' configuration backups, settings, scripts - plus the master key, the settings file and branding:
  everything to rebuild TikManager on a new server) or **Scripts only**. Backups are **encrypted with your passphrase**
  (scrypt + AES-256-GCM) before they leave the server; a full backup must be. Daily at the hour you pick, plus **Back up
  now** and **Test connection**; the newest N copies are kept on the storage. A failed backup can raise an alert.
- `tools/tmbak.py` opens a backup with its passphrase; the README explains how to restore a server from it.

## 1.14.0 - 2026-10-11

- **Connectivity test** (Admin > Version & updates > **Run test**): checks from the internet, the way routers and people
  reach TikManager, that the firewall is set up right:
  - **DNS**: the public name points at this server (Cloudflare's public DNS).
  - **Open**: HTTPS (TCP 443 - sign-in, router adoption) and HTTP (TCP 80 - certificate renewals, redirect), each tried
    from 3 servers in different countries (check-host.net).
  - **Closed**: SSH (TCP 22) and TikManager's own app port - they must not be reachable from the internet.
  - **WireGuard (UDP 51820)** can't be tested by a public checker (WireGuard only answers routers that have its key), so
    routers online over their tunnels from other places are the proof.
  Each problem has **How to fix** steps. It runs on request and once after every upgrade; only the host name is sent to
  those services. A failed check can raise an alert (Alerts > Settings > "Connectivity test finds a port problem").

## 1.13.0 - 2026-10-09

- **Community script library** (Tasks > Scripts > **Community library**): browse and search RouterOS scripts shared by
  other TikManager users in a public GitHub repository (default
  [astukestarr/routeros-scripts](https://github.com/astukestarr/routeros-scripts); Admin > Integrations > GitHub
  changes it). Each script is shown in full before you import it, with the lines that deserve a second look
  highlighted (factory reset, users, deleting files, downloads, schedulers, services, firewall removals, updates,
  anything touching TikManager's own access). Importing copies it into your scripts - nothing runs until you run it.
- **Share** (next to each of your scripts): opens a **pull request** on the library, so its owner reviews it before
  anyone else gets it. Before anything is sent, TikManager scans the script for passwords, keys, pre-shared keys, public
  IP addresses, e-mail addresses and your clients' names; each finding must be removed or confirmed. Sharing needs a
  GitHub token (a classic token with only the `public_repo` scope) saved on Admin > Integrations > GitHub; browsing
  needs no account.

## 1.12.0 - 2026-10-09

- **Alerts** (new page): TikManager now tells you when something's wrong - as a **ConnectWise ticket** and / or a
  **Teams message** - when a problem starts, and closes the ticket (internal note + the closed status you pick) and
  posts "resolved" when it clears. Alert on: a router offline for N minutes (not while it's being upgraded), a failed
  configuration backup, Security-page warnings (password guessing, one address trying several systems, a sign-in
  right after failures, TikManager's own router login failing), a FAIL from the server security check, the website
  security grade dropping below A - and optionally high CPU or a new RouterOS version.
  - Tickets go to the client's linked ConnectWise company; a default company (e.g. your own) is used for unlinked
    clients and for TikManager / server problems. You pick the board, new and closed statuses and priority. The
    ConnectWise API member needs **Service Desk > Service Tickets: Add, Edit and Inquire**.
  - Teams: in the channel, ... > Workflows > "Post to a channel when a webhook request is received", and paste the URL.
  - No storms: when more than 5 routers go offline in the same minute (most likely TikManager's own connection), one
    grouped alert is sent instead of one each.
  - **Send a test ticket / Send a test to Teams** buttons; open and resolved alerts (7 days) are listed on the page.

## 1.11.1 - 2026-10-09

- **Updates are found from tags, not GitHub Releases**: the newest version is now always the highest `vX.Y.Z` tag, and a
  GitHub Release for that version only adds its notes ("What's new"). Before, once a Release had been published, a
  later version pushed without its own Release would not have been offered. Applies to the update check, the one-click
  upgrade and the installer.
- MIT license, a security policy (`SECURITY.md`: report problems privately on GitHub), screenshots in the README, and
  `tools/release_notes.py` (prints a version's changelog section for its GitHub Release).

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
