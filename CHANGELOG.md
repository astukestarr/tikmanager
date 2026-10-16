# Changelog

Versions follow [semantic versioning](https://semver.org): **patch** (1.0.x) = fixes, **minor** (1.x.0) = new features,
safe to upgrade with the button; **major** (x.0.0) = changes that need manual steps (described here).

## 1.46.0-beta.11 - 2026-10-16

- **Compliance** (Monitoring > Compliance): every router checked against the network-device controls of **CIS Controls
  v8**, **NIST SP 800-171 / CMMC Level 2**, **PCI DSS 4.0** and the **HIPAA Security Rule** - for all clients or one.
  Each control shows met / not met / needs review per router with the evidence read from the router (management
  exposure, deny-by-default firewall on input and forward, encrypted management, SSH crypto, VPN crypto, default admin,
  RADIUS sign-in, MFA, central logging, NTP, unneeded services, SNMP, login notice, firmware / CVEs, backups; and FIPS
  for 800-171, which MikroTik can't meet). **Client report (PDF)**: a branded report to hand the client - score, scope
  (evidence for these controls, not a certification), per-router results, every control with its evidence, a
  remediation plan and the documented exceptions - printed or saved as PDF from the browser. **CSV for auditors**:
  every router x control x check with the evidence. Report downloads are audit-logged.
- **Accept a finding** (Performance & security and Compliance): "not a problem on this router, because ..." - e.g. FTP
  that backs up switches and phone systems, with port 21 blocked from the internet. The finding leaves the dashboard's
  list, counts and one-click fixes (**Show accepted** brings it back, with **Undo**), and compliance shows it as **Met
  with exception** with the reason, who accepted it and when. Exceptions are per item: accepting FTP doesn't excuse
  Telnet. Audit-logged and recorded as a router event.
- New read-only settings for these checks: remote logging actions and rules, RADIUS / AAA, SNMP community security
  (never the community name), the login note, and the firewall's NAT-state matcher.
- **Fix: "Limit MAC Telnet to the LAN" failed** with "input does not match any value of allowed-interface-list" on
  devices without an interface list called LAN (switches, custom setups): those now get MAC Telnet turned off
  (allowed-interface-list=none) on a second try. MAC Winbox is a separate setting and isn't touched.
- Code checkup: the router page's VPNs tab no longer loads every router's VPN inventory on each refresh (only names
  and addresses to link remote ends); the remote access connection log got indexes for its per-person and alert
  queries, and its 400-day pruning runs every 10 minutes instead of every 2.
- Second code checkup: the dashboard's recent events (every 30 s) and event pruning use a new time index instead of
  sorting up to 180 days of events; Performance & security's latency / loss / CPU and link-flap figures read each
  router's last hour through its index instead of scanning a week of metrics, every minute it's open.

## 1.46.0-beta.10 - 2026-10-16

- **Fix: "Turn on SSH strong crypto" failed** with "strong-crypto and none cipher can't be used at the same time" on
  routers whose SSH cipher list allows null (no encryption). When a router gives that answer, the fix now sets the
  cipher list to aes-ctr, aes-gcm together with strong-crypto (a second try - routers that don't need it are left as
  they were). The dashboard also reads the SSH cipher list and says when null is allowed. Routers that failed: run
  **Fix all** again.
- The fix progress box shows how long each router has been on its current step (a large router's backup can take up to
  3 minutes - it says so after 30 seconds).

## 1.46.0-beta.9 - 2026-10-16

- **One-click fixes show their progress**: **Fix** / **Fix all** now starts a background job and a progress box lists
  every router with its step - waiting, backing up, changing, re-checking, done or failed (with the reason) - and a
  progress bar, updated every 1.5 seconds; up to 6 routers at a time. The findings refresh when it finishes. The box
  comes back after a page reload or when you return to the page (for 10 minutes after it finishes) until you
  **Dismiss** it.
- Borders on the remote access warning box and the one-click fixes box now show (they used an undefined colour).

## 1.46.0-beta.8 - 2026-10-16

- **One-click fixes on Performance & security**: findings that come down to one setting get a **Fix** button, and a
  **One-click fixes** box lists each kind with **Fix all N** for the routers shown (filters apply): SSH strong crypto,
  disable Telnet / FTP / the plain-text API (8728), turn off SOCKS / web proxy / UPnP / the bandwidth test server, MAC
  Telnet limited to the LAN list, NTP on. Each router is backed up first (nothing changes if the backup fails), only
  that one setting is changed - from a fixed list, never text from the finding - and the router is re-read so the
  finding clears. Every fix is a router event and in the audit log. WebFig (www) is never offered: TikManager itself
  talks to routers over REST on it.
- **VPNs tab on the router page**: every VPN on that router (the same read-only inventory as Site-to-site VPN >
  Existing VPNs) with status, remote end, networks / users, traffic, **Restart tunnel** and **Read again**, plus a
  line for remote access (people, connected now).
- **Paste coordinates into the location**: `39.21029769702689, -96.48699887138372` (Google Maps' copy format) pasted
  into the address, latitude or longitude box - or typed in the address box and **Look up** - fills both coordinates
  and moves the map pin, without sending anything to the address search.
- Remote access screens: spacing that the page's security policy was blocking now applies.

## 1.46.0-beta.7 - 2026-10-16

- **DNS suffix for the office domain**: the RMM install script now also sets the domain (e.g. `corp.local`) as the
  tunnel adapter's DNS suffix, so typing `ad` finds `ad.corp.local`. Where a global DNS suffix search list is already
  set on the laptop (often by Group Policy - Windows then ignores per-connection suffixes), the domain is added to it.
  The .conf file already carries the domain as its search domain (WireGuard applies it when the tunnel is up).

## 1.46.0-beta.6 - 2026-10-16

- **Remote access connection log**: who connected, when, from which public IP, for how long and how much data - read
  from the router every 2 minutes (one read-only request), a new session when someone reconnects from a different IP,
  kept 400 days. Shown on the Remote access tab with **Export CSV** for auditors (the export is audit-logged).
- **Download config sits next to the person** (no more scrolling up): right after adding someone their row is
  highlighted with **Download config**; if the page was reloaded before downloading, **Get download link** makes a fresh
  one-time link (the old one stops working; the key stays encrypted until that one download).
- **RMM install script**: next to the person, alongside the .conf file (one download - pick one). PowerShell to run as
  SYSTEM from Syncro or any RMM: installs WireGuard if missing (newest MSI from download.wireguard.com, signature
  checked), saves the config readable by SYSTEM / Administrators only, and installs the tunnel as an always-on Windows
  service. The person never handles the config file.
- **Unusual-connection alerts** (new alert type, on by default): someone connecting from an address they've never used,
  or their key used from two internet addresses within minutes (a copied config). Flagged in the connection log too,
  and recorded as router events.
- **Warnings on the Remote access tab**: a config is a key, don't email it, least access and expiry dates, BitLocker
  and MFA on what's behind the VPN, and the compliance limits (not FIPS-validated - not for NIST 800-171 / CMMC).
- **Office DNS for Windows domains**: the DNS setting now takes the domain too (e.g. `192.168.1.10, corp.local`) - it
  becomes the tunnel's search domain, and the RMM script adds a Windows name-resolution rule (NRPT) so that domain
  always goes to the office DNS server; on a split tunnel Windows otherwise keeps asking the laptop's own DNS. People
  limited to some servers now get the DNS server routed and allowed (port 53). Configs made before a change don't
  pick it up - give those people a new config.

## 1.46.0-beta.5 - 2026-10-16

- **Remote access: per-person access.** Each person can reach **Everything** the setup allows, or **Only these servers** -
  a server IP plus a service (SMB, HTTP, HTTPS, Remote Desktop, SSH, Ping, everything on it, or a custom TCP / UDP port).
  The router enforces it: remote access's single forward rule is replaced by one accept rule per allowed destination
  and a final drop for everything else from the tunnel, so editing the config on the laptop gains nothing. Restricted
  people's configs only route their servers. Set it when adding the person, or **change** it any time.
  Routers set up with an earlier beta keep the old "everyone reaches everything" rule until the next change on the tab
  (adding / revoking someone, saving access, or Save and apply).
- **Disable / Enable** a person (their peer is switched off on the router; same config when enabled again) - for leave
  or a lost laptop.
- **Expiry dates**: optional when adding a person, editable later. Access is revoked automatically at the end of that day
  (your time zone); a reminder event 3 days before, and the Performance & security dashboard lists access ending soon
  or past its expiry on an offline router.

## 1.46.0-beta.4 - 2026-10-16

- **Remote access: use the router's MikroTik Cloud DNS name** (<serial>.sn.mynetname.net) as the address people connect
  to - it follows the router's public IP when the ISP changes it. The Remote access tab shows the router's Cloud DNS name
  and status; **Use Cloud DNS** (or **Turn it on and use it**, which switches on IP Cloud DDNS on the router) makes it the
  address. New setups pick the Cloud name by default when the router has one. Configs not downloaded yet are updated;
  the page says how many were already handed out with the old address.

## 1.46.0-beta.3 - 2026-10-16

- **Fix: router pages showed "Something went wrong on the server"** (the traffic / CPU graphs failed to load) in
  1.46.0-beta.2 - a variable in the new dashboard code clashed with a helper the graphs use.

## 1.46.0-beta.2 - 2026-10-16

- **Remote access with WireGuard for Windows** (router page > Remote access, technicians) - an SSTP replacement. Set it
  up per router (address people connect to, UDP port, an address range picked to avoid the router's networks, optional
  DNS, office networks only or all traffic); TikManager backs the router up and adds a tagged WireGuard interface, its
  address and firewall rules. **Add person** makes a key pair, adds only that peer, and offers ONE download of the
  WireGuard config - the private key is then deleted (or after 7 days). **Revoke** removes one person; **Remove remote
  access** takes off exactly what was added. Live last-handshake and traffic per person.
- **Performance & security dashboard** (Monitoring > Performance & security, technicians): every router checked for
  internet problems (offline, link down, unstable link, loss, latency), performance (CPU, memory, storage, bad blocks,
  temperature, restarts), open ports and exposed services (management services reachable from the internet, no
  catch-all input drop, plain-text services, open DNS resolver, SOCKS / proxy / UPnP ...), weak encryption and old VPN
  technologies (PPTP, L2TP without IPsec, weak IPsec / OpenVPN ciphers, aggressive mode, SSH crypto), VPN problems,
  updates and CVEs, backups and hygiene - worst first, each with how to fix it. The 15-minute read-only inventory now
  also reads the router's services, input firewall rules, DNS / UPnP / SOCKS / proxy / MAC server / SNMP / SSH / NTP
  settings, user names and IPsec / OpenVPN cipher settings (no secrets).
- Remote-access people no longer show up as unknown WireGuard peers under Existing VPNs.
- Includes 1.46.0-beta.1 (UniFi / UISP Match filter).

## 1.46.0-beta.1 - 2026-10-16

- **UniFi / UISP page: Match filter** (technicians) - All sites, Matched to a client, Matched automatically, Chosen by
  hand, or Not matched, alongside the client, search and "Offline or updates only" filters.

## 1.45.1 - 2026-10-16

- **Site-to-site VPNs managed by TikManager are turned off for now**, until they've been tested further. The "Managed by
  TikManager" tab, New VPN and the VPN pages are gone, nothing can create, change, apply, remove or restart a managed VPN,
  and TikManager no longer checks them in the background. **VPNs already built on routers keep running untouched**; they
  show read-only under Site-to-site VPN ("Built by TikManager"), and on the router page. Existing VPNs and Restart tunnel
  for them work as before. To try the feature on a test server: `TM_MANAGED_VPN=1` in /etc/tikmanager/tikmanager.env,
  then `sudo systemctl restart tikmanager`.

## 1.45.0 - 2026-10-15

Release of 1.45.0-beta.1 (tested), unchanged:
- **Site-to-site VPN page refreshes by itself** every 30 seconds.
- **"Reconnect" is now "Restart tunnel"** (click twice to confirm) and shows the fresh tunnel state afterwards.
- **Read routers again** fills the list in as the routers answer; neither button stays greyed out any more.

## 1.45.0-beta.1 - 2026-10-15

- **Site-to-site VPN page refreshes by itself** every 30 seconds (paused while you're using a filter or a restart is
  armed), so tunnel states stay current.
- **"Reconnect" is now "Restart tunnel"**, confirmed with a second click instead of a pop-up. Afterwards it shows
  Restarted, then the fresh tunnel state about 18 seconds later - the button no longer stays greyed out.
- **Read routers again** no longer leaves its button greyed out and the old list on screen: the list fills in by itself as
  the routers answer (about a minute), and the button comes back when it's done.

## 1.44.0 - 2026-10-15

Release of 1.44.0-beta.1 (tested), unchanged:
- **Beta channel for updates** - Admin > Settings > Version & updates > Channel: **Stable** (default) or **Beta**. From now on
  new features and fixes come out as betas first (1.45.0-beta.1 ...) for installations that opt in, and are released to
  everyone once tested. Only the newest beta is ever offered, and withdrawn versions are never offered or installed.
- **Fix: VPN Reconnect could leave a tunnel switched off and the router cut off from TikManager** - the router now runs
  the off-and-on itself, so it always comes back on. Details under 1.44.0-beta.1.

## 1.44.0-beta.1 - 2026-10-15

- **Beta channel for updates**: Admin > Settings > Version & updates > Channel - **Stable** (default) or **Beta**. Beta
  installations get new versions (1.45.0-beta.1 ...) before they're released to everyone. Only the newest beta is ever
  offered, so a beta that a later beta fixed is never installed again, and versions the maintainer withdraws (listed in
  the repository's RELEASES.json) are never offered or installed. The root updater checks the same rules, and
  `self-update.sh beta` installs the newest beta from a terminal.
- **Fix: VPN Reconnect could leave a tunnel switched off and the router cut off from TikManager.** Reconnect sent "off" and
  "on" as two separate requests; when the tunnel being switched off carried the router's other traffic (WireGuard tunnels
  running over an L2TP / SSTP / OpenVPN client or a GRE / EoIP link), TikManager's own connection dropped with it and the
  "on" never arrived. The router now runs the whole off - 2 seconds - on itself as one background script, so it always
  comes back on. TikManager VPN reconnects also double-check each peer's tag before touching it.
- If a router dropped out after a Reconnect before this fix: on the router, `/interface print where disabled` and
  `/interface wireguard peers print where disabled`, then enable what was switched off.

## 1.43.6 - 2026-10-13

- **Network map layout for routers with many networks**: only networks with something on them get a column - busiest
  first, so the LAN with the switches and devices sits right under the router instead of off to the side. Networks with
  nothing seen (guest / HVAC VLANs, point-to-point links, tunnels) are listed in one compact line underneath.
- **One node per switch**: a switch that's both a UniFi / UISP device (bridge table) and an LLDP / CDP neighbour (often
  announced from another of its MACs) is shown once, e.g. "Downstairs Spearville - UniFi (bridge table), lldp".

## 1.43.5 - 2026-10-13

- **Network map: the switch behind each port, and every device**: when a UniFi / UISP switch is in the router's bridge table
  on a port, it's shown as that port's switch (e.g. "sfp-sfpplus1 -> Downstairs Spearville, US 48 PoE 750W" - the biggest
  one if there are several) and everything behind the port hangs under it, instead of under whatever other neighbour was
  heard on that port first. Devices that are only in the bridge host table (no IP in ARP / DHCP - other VLANs, idle
  devices) are now shown too, recognised by maker like the rest (up to 3,000 per map).

## 1.43.4 - 2026-10-13

- **UniFi / UISP devices drawn on the network map**: each recognised device is shown by name under the switch / network
  it's behind - AP or switch icon, model and IP, a green / red status dot and ↑ when an update is waiting (hover for
  port, firmware and site). Before, they were only counted inside the "Network devices" bubble. Clicking the
  "N UniFi / UISP" count in the map header lists them all with where they sit, port, status and firmware.

## 1.43.3 - 2026-10-13

- **Network map shows only the UniFi / UISP devices at that location**: devices are matched against the router's own
  tables - ARP, DHCP, neighbours and now the **bridge host table** - so UniFi / UISP gear with no IP there (switches and
  APs on a management VLAN) is placed on the map at its port / VLAN, badged and marked "bridge table". The list of the
  client's devices from every location ("From UniFi / UISP") is gone; the map header counts the UniFi / UISP devices
  recognised at this location.

## 1.43.2 - 2026-10-13

- **UniFi devices on multi-site consoles**: when only one of a console's sites reports any devices, the devices Ubiquiti's
  API doesn't place are that site's (e.g. a Cloud Key with a main site and an empty second one) - they now show on the
  site and on the network map instead of under "not matched to a site".
- **Network map**: devices of a multi-site console that still can't be placed on a site are used for the router's client
  when every site of that console belongs to that client - so they're badged UniFi / listed, not just "Ubiquiti".

## 1.43.1 - 2026-10-13

- **Public-IP site matching for multi-site consoles at the customer**: a UniFi console on the customer's network that runs
  several of their sites (e.g. a Cloud Key with no UniFi gateway, so the sites report no WAN address) is matched by the
  console's own public IP - shown as "Console's public IP ... = router ...". Not for hosted / self-hosted network servers
  or consoles with more than 10 sites, whose address is the MSP's or Ubiquiti's, not the customer's.

## 1.43.0 - 2026-10-13

- **UniFi / UISP on the network map**: devices the router sees that a UniFi / UISP connection knows (matched by MAC) get a
  **UniFi** / **UISP** badge with their name, model, site, status and firmware update (the switch / AP icon and the device
  lists too); other Ubiquiti gear is badged **Ubiquiti** (by MAC prefix or what it announces). The router's client's
  UniFi / UISP devices it doesn't see - behind a UniFi gateway, at another site, offline - are listed under
  **From UniFi / UISP** with their status and updates. Only that client's sites are used.
- **Sites matched to clients by public IP**: a site whose public address equals the WAN / public IP of one of a client's
  routers belongs to that client - before the name match. UniFi: the site's reported WAN address, or the console's own
  address when it runs only that site (never a hosted multi-site server's); UISP: the public address of a device at the
  site. The UniFi / UISP page shows each site's public IP and why it has its client ("Public IP ... = router ...",
  "matched by name", "chosen by hand").
- A client chosen by hand now sticks - syncs never change it - until **Match automatically** is picked again, which works
  the client out afresh.

## 1.42.2 - 2026-10-13

- **UISP connections**: every address of the UISP server is tried (IPv4 first) instead of only the first one DNS returns -
  a server with an IPv6 address but no working IPv6 route used to time out. When none answers, the error names each
  address and port tried and what to check (TikManager's outbound firewall, an allowlist in front of UISP, hairpin NAT).

## 1.42.1 - 2026-10-13

Security review of 1.38.0 - 1.42.0 (client Winbox / VPNs, View as, VPN inventory and reconnect, UniFi / UISP). Fixed:
- **View as showed the client's Winbox password**: an administrator viewing as a client user who had a Winbox session
  open got that session's router password. The password now only ever goes to the person who opened the session.
- **View as outlived the administrator role**: a session already viewing as someone kept doing so after the account
  stopped being an administrator. It now ends as soon as the real account isn't an administrator any more.
- **UISP connections could point at TikManager's own server or network**: the address is now resolved and refused
  unless every address is public (no localhost, LAN, link-local or cloud metadata), checked when the connection is
  saved and on every request, and TikManager connects to the address it checked (a second DNS answer can't redirect it).
  Error replies are no longer echoed back.
- **A client's own UISP / UniFi data is bounded and cleaned**: at most 20 MB per response and 2,000 sites / 10,000
  devices per connection; every value stored as plain, length-limited text. Names that go into alerts (Teams cards,
  ConnectWise tickets, email, webhooks) are stripped of markup and links, so a device name can't put a clickable link
  or formatting into your Teams channel.
- **MSP connection names hidden from client users** (they see "Managed by your IT provider").
- **Rate limits** on VPN reconnects (everyone) and VPN re-reads (client admins): 20 per 5 minutes per person.

## 1.42.0 - 2026-10-13

- **UniFi and UISP**: **Admin > Integrations > UniFi & UISP** takes any number of connections - **UniFi** (an API key from
  unifi.ui.com, Ubiquiti's read-only Site Manager API) and **UISP** servers (address + API token). Each belongs to your
  MSP account (assign each site to a client; first matched by name) or to **one client** (their own UniFi account / UISP
  server - everything in it is theirs).
  - **Devices > UniFi / UISP**: every site with client, source, devices, offline devices (and since when), firmware
    updates waiting, and for UniFi clients, WAN uptime, ISP and internet issues; click a site for its devices (model, IP,
    status, firmware, update available). Client users see their own sites, read-only.
  - Synced every 10 minutes or with **Sync now**; keys / tokens are sealed with the vault and never shown again.
  - A UISP server with a self-signed certificate can be trusted by **pinning** its certificate's SHA-256 (the connection
    is refused if it changes) - never by turning verification off. UISP addresses must be `https://host[:port]`.
  - UniFi consoles that run several sites: devices are placed through the console's integration API via Ubiquiti's cloud
    connector where available, and gateways by MAC; the rest are listed for technicians.
  - New alert **UniFi / UISP site has offline devices** - one per site (a dead console is one alert), after 10 minutes by
    default.

## 1.41.0 - 2026-10-13

- **Reconnect a VPN tunnel**: a **Reconnect** button on every existing VPN (the Existing VPNs tab and the router's
  "VPNs on this router") and on every site of a TikManager VPN. IPsec drops its active peer so it renegotiates straight
  away; WireGuard peers, L2TP / SSTP / OpenVPN / PPTP clients and EoIP / GRE / IPIP tunnels are switched off and back on
  (only ones that are switched on); a TikManager VPN reconnects its WireGuard peers at that site. It asks first (the
  tunnel drops for a few seconds) and re-reads the router about 15 seconds later.
  - Only a tunnel the router's inventory found can be reconnected - the server looks the request up there, so a request
    can't switch anything else on the router - and never TikManager's own management tunnel.
  - Technicians with write access, and client admins with site-to-site VPNs turned on (their own routers only).
    Audit-logged and recorded in the router's events.
- Client admins with site-to-site VPNs turned on also see **VPNs on this router** on their routers' pages (remote ends
  matched only against their own routers).

## 1.40.0 - 2026-10-13

- **Existing VPNs on routers for client admins**: client admins with site-to-site VPNs turned on now also get the
  **Existing VPNs on routers** tab (VPNs set up outside TikManager - WireGuard, IPsec, L2TP / SSTP / OpenVPN / PPTP,
  EoIP / GRE / IPIP) and **Read routers again**, for their own routers only. A tunnel's remote end is matched only
  against their own routers, so another client's router is never named; asking to re-read another client's router
  returns "not found". Nothing new is read from routers (still no passwords or keys).

## 1.39.0 - 2026-10-13

- **View as** for administrators: **Users > View as** next to a client user shows TikManager exactly as they see it -
  their sidebar, routers, pages, Winbox / VPN access - so you can check what a client can reach. Look-only: every change
  is refused while viewing (the server enforces it, not just the page), a purple banner says who you're viewing as, and
  **Stop viewing** returns you to your own account. Only administrators can use it, only for client users (not
  technicians or disabled users), and starting / stopping is audit-logged.

## 1.38.0 - 2026-10-13

- **Winbox and site-to-site VPNs for client admins**, turned on per client by an administrator on **Clients** (off by
  default):
  - **Winbox**: *Off*, *Read-only* or *Full*. The client's admins get the Winbox box on their routers' Overview and open
    sessions through the same relay as technicians - locked to their address, 30 minutes, with a temporary router login
    in the group chosen here. They can extend and close their own sessions only, can't change a router's Winbox service
    (Turn on / Allow TikManager stay with technicians), and only ever see their own organization's sessions. Turning
    Winbox off for a client closes its open sessions straight away.
  - **Site-to-site VPNs**: the client's admins see **Network > Site-to-site VPN** and can create, apply, disable and
    delete VPNs between their own routers. Everything is limited to their organization - the client is fixed to theirs,
    other clients' VPNs return "not found", and every router in a VPN must belong to them. The "Existing VPNs on
    routers" tab stays technician-only.
  - Client **viewers** never get either. Changing these switches is administrator-only and audit-logged.

## 1.37.1 - 2026-10-12

Security review of everything added since 1.19.1 (email, lifecycle, wireless, flagged routers, RouterOS security,
auto-block, hardware health, internet links, restarts, tags, webhooks, logs, safer upgrades, ports / VLANs, sidebar,
integrations). Every new endpoint requires the right sign-in and role, every POST is CSRF-checked, and router / server
text reaches the page escaped. Fixed:
- **Ports / VLANs undo script**: values written into the on-router undo script weren't escaped for RouterOS's `$` and
  `?` - RouterOS expands `$variables` and runs `$[commands]` inside quoted strings, so a port or VLAN comment
  containing `$[...]` could have run a command when the undo fired. Now escaped (as the firewall undo already was),
  and raw values from the router (pvid, frame types, PoE mode) are checked before they go in.
- **Webhooks**: redirects are no longer followed (a public endpoint could have redirected an alert to a LAN address),
  and the connection goes to the address that was checked rather than looking the name up again (DNS rebinding).
  Line breaks in header values (e.g. an ntfy title from a router name) are removed, and one failing webhook can no
  longer stop the remaining alerts of that round from being sent.
- **Release notes** ("What's new") are for technicians only, accept only plausible RouterOS version numbers and are
  rate-limited - before, any signed-in user could make the server fetch arbitrary version numbers.
- **Log alert rules**: regular expressions that can backtrack for ever ((a+)+, back-references) are refused, so a rule
  can't hang the alert checker.
- **Log CSV export**: every text column (not only the message) is protected against spreadsheet formulas.
- **Plain-text backup copy**: its folders are now readable by TikManager only (the files already were).

## 1.37.0 - 2026-10-12

- **New sidebar**, laid out like Report Center's: collapsible groups with counts - **Devices**, **Network** (site map,
  subnets, Discovered, site-to-site VPN), **Monitoring** (Alerts with the open count, Logs, Security), **Maintenance**
  (Backups, Upgrades, Tasks), **Clients & users** and **Admin**. Open groups are remembered in the browser; the group of
  the page you're on always opens.
- **Devices** instead of Routers, with **All devices**, **Access points**, **Routers** and **Switches** (counts beside
  each). The kind comes from the model (CRS / CSS = switch; cAP, wAP, SXT, LHG, NetMetal, Cube ... = access point;
  everything else, hAP and Chateau included, = router) and can be set per device on its Settings tab
  (**Tags, notes & type**). All devices shows a Type column.
- **Admin > Integrations** redesigned like Report Center's: a category filter and search on the left, one card per
  integration (ConnectWise, IT Glue, Email, Teams, Webhooks, GitHub, Off-site backup, Microsoft sign-in) with its
  status - Connected / Error / Set up / Not set up - and **Edit** / **Test**. Edit opens that integration on its own
  page (with ← All integrations); Teams, Webhooks, Off-site backup and sign-in take you to where they're set up.

## 1.36.0 - 2026-10-12

- **Ports tab** on the router page (technicians), laid out like UniFi's Ports page:
  - **Port diagram**: odd ports on top, even below, SFP ports as their own block; coloured by link speed (FE / GbE /
    2.5 GbE / 10 GbE), no link and disabled; PoE out ⚡ and uplink ↑; the connected device's name above / below each
    port (neighbour, DHCP name, IP or MAC). Click ports to select them, shift-click for a range.
  - **VLANs on**: a **Native VLAN** row and a **VLAN tagging** grid per VLAN (tagged / blocked / native), with the
    VLAN's name and subnet, and a search.
  - **VLANs off**: a **port table** - port, name, status / speed, connection, PoE (mode and watts), native VLAN, tagged
    VLANs, hardware offload - with status and native-VLAN filters.
- **Managing ports and VLANs** (MikroTik bridge VLAN filtering):
  - Selected ports: native VLAN, tagged VLANs (leave / allow all / block all / custom), name, enabled, PoE out.
  - VLANs: add (optionally with the router itself tagged), rename, delete; VLAN filtering on / off per bridge.
  - Every change is shown as **RouterOS commands** to review first; then the router is backed up and an **automatic
    undo** is armed on the router - it puts the bridge VLAN table, bridge ports, VLAN filtering and touched ports back
    exactly as they were unless you press **Keep** within 5 minutes, so a change that cuts TikManager off undoes itself.
  - The port and VLAN TikManager reaches the router through are protected: that port can't be disabled, keeps its
    management VLAN (other VLANs can be added or removed), and VLAN filtering can't be turned on until the management
    VLAN is set up to survive it. Rows shared by several VLANs (vlan-ids=30,40) are split as needed.
  - Older switch-chip VLAN setups (CRS1xx/2xx) are shown read-only.
- The router page's tabs wrap onto a second line when there are many.

## 1.35.0 - 2026-10-12

- **Safer mass upgrades** (Upgrade dialog with several routers):
  - **Safety stop** (on by default): after N upgrades in the batch fail (default 1), the rest are **held** - nothing
    more is touched until someone presses **Resume them** or **Cancel them** on the Upgrades page.
  - **One at a time, in this order**: routers upgrade strictly one after another, each starting only when the previous
    one has finished; ↑ / ↓ set the order (e.g. the switch that powers the APs last).
  - **Only install the version shown now** (on by default): the job remembers the newest RouterOS when it was
    scheduled; if MikroTik publishes something newer before it runs, nothing is installed and the job shows
    **Skipped** - nobody installs a release they didn't review.
  - Held and skipped jobs are listed with the reason; the router's events say so too.

## 1.34.0 - 2026-10-12

- **Logs** (new page, technicians; and a **Logs** tab on each router): every line your routers send - info, warning,
  error, critical, as set up at adoption - not just the security lines. Newest first, live (new lines appear every
  5 seconds; **Pause**), filters by router, client, tag, severity, topic and text, **Load older**, and **Export CSV** of
  whatever the filters show. Kept 14 days and at most 20,000 lines per router; a router sending more than 300 lines a
  minute is capped, so one can't flood the rest.
- **Log alert rules** (Logs page, administrators): text or /regex/, optional topics and minimum severity, for all
  routers, a client, a tag or one router, and "N matching lines within M minutes" - e.g. *PPPoE keeps dropping*:
  topic ppp, errors, 3 in 10 minutes. A match becomes an alert (ticket / Teams / email / webhooks) that clears when the
  lines stop. **Try it on the last 24 hours** shows what a rule would have caught before you save it.
- Existing routers need no change: they already send these topics.

## 1.33.0 - 2026-10-12

- **Backups are checked before they're stored**: an export that looks cut short (empty, no RouterOS header, no
  configuration sections, ending mid-command, or a fraction of the last version's size) is not saved - the last good
  version stays the restore point and the attempt shows as failed. A configuration that really did shrink a lot is
  accepted when two exports in a row agree.
- **Backup coverage** at the top of the Backups page: backed up in the last 2 nights / overdue / latest attempt
  failed / no backup yet - click one to list those routers.
- **Download all (zip)**: every router's newest configuration in one zip, laid out <client>/<router>_<date>.rsc
  (technicians; audited).
- **Plain-text copy** (Admin > Settings > Backups, off by default): each router's latest configuration also written to
  <data>/exports/<client>/<router>.rsc - make that folder a git repository and every change is committed, for a free
  history, or point your own backup tool at it. The copies aren't encrypted and contain passwords (readable only by
  TikManager), hence off by default.

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
