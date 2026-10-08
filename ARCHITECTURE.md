# TikManager - architecture and security model

A self-hosted controller for MikroTik RouterOS 7 routers, for an MSP / IT team (technicians) and its clients (each
client sees only its own routers).

## Where it runs

```
Internet
   |  443/tcp (web UI + router adoption)        51820/udp (WireGuard from routers)
[ Edge firewall ] ---- forwards ONLY these two to the TikManager VM ----
   |
 DMZ VLAN  (recommended: DMZ -> LAN denied entirely; SSH to the VM only from the LAN/VPN)
   |
 TikManager VM (Ubuntu 26.04 LTS)
   Caddy :443  (Let's Encrypt TLS, HSTS, size/time limits) -> app on 127.0.0.1:8800
   WireGuard wg0 10.77.0.1/16  (one /32 per router)
   app: Python 3 stdlib + SQLite, runs as user "tikmanager" (no shell, no sudo, CAP_NET_ADMIN only)
```

- Only 443/tcp and 51820/udp are public; the app listens on localhost. Router management traffic (REST API, logs)
  only ever travels inside WireGuard - routers never expose management ports to the internet.
- Put the VM where a compromise can't reach the rest of your network (its own DMZ, no route to the LAN).

## How a router joins

1. **Adoption command** (Routers > Adopt routers) - one command for the whole MSP, containing an enrollment token derived
   from the master key (Replace command rotates it; routers already adopted are unaffected).
2. **Stage 1** (`adoption.stage1`): the router creates its WireGuard interface `tikmanager` on a free port (53231+) -
   the private key never leaves the router - and posts its public key, serial, model, version and identity.
3. **Stage 2** (`adoption.stage2`, generated for that router): a /32 tunnel address, the controller as WireGuard peer,
   a firewall accept rule for the controller, a `tikmanager` user (password derived from the master key per router,
   allowed only from 10.77.0.1), the www service opened to the controller, and remote logging over the tunnel.
4. The router is **pending** until a technician approves it and picks its client; only then is its peer added to wg0.
   Re-running the command is safe (it re-registers the same key).

## What runs where (server modules)

| Module | Does |
|---|---|
| `server.py` | HTTP server, routing, auth, all JSON APIs (`route_get` / `route_post`) |
| `db.py` | SQLite schema + migrations; one shared connection used under a lock |
| `config.py` | settings-file values (`/etc/tikmanager/tikmanager.env`) |
| `appsettings.py` | Admin > Settings values stored in the DB (override the settings file; secret encrypted) |
| `security.py` | scrypt passwords, TOTP, sessions, rate limiting, key derivation |
| `entra.py` | Microsoft Entra OIDC sign-in (PKCE) for technicians |
| `adoption.py` | the RouterOS scripts routers run to join |
| `wg.py` | adds / removes WireGuard peers on wg0 |
| `routeros.py` | REST client for routers (and `SimRouter`, the dev-mode simulator) |
| `poller.py` | polls every adopted router each minute; metrics, events, VPN inventory |
| `backups.py` + `vault.py` | nightly `/export show-sensitive`, deduplicated, gzip + AES-256-GCM |
| `upgrades.py` | RouterOS / RouterBOARD upgrade jobs (backup first, wait for reboot) |
| `tasks.py` | script library, groups, scheduled script runs and firmware updates |
| `vpn.py` / `vpninv.py` | site-to-site WireGuard VPNs it builds / VPNs already on routers (read-only) |
| `integrations.py` | ConnectWise PSA (client import) and IT Glue (router documentation) |
| `branding.py`, `thumbs.py` | branding settings; router product pictures from mikrotik.com |
| `static/` | the single-page web app (`app.js`), sign-in, invite and first-run pages |

## Accounts and tenants

- **Organizations** = clients. Every device, backup, event and run belongs to one; every query a client user can make
  is scoped to their organization server-side (`org_scope`, `device_for`).
- **Technicians** sign in with Microsoft Entra (your tenant only); who may sign in (email domains) and who becomes an
  admin are set on Admin > Settings. Roles: admin / tech / read-only. A password + authenticator account (the first
  administrator, created by the one-time setup link) works without Microsoft.
- **Client users** are invited by email link; password (14+ characters, scrypt) and **mandatory TOTP**. Roles: client
  admin / viewer. Clients see their routers, backups' existence and events, but never configurations or secrets, and
  can't change routers.

## Security controls

- Caddy: automatic TLS, HTTP->HTTPS, HSTS, body/header limits, timeouts. App binds to 127.0.0.1 and trusts
  X-Forwarded-For only from Caddy.
- Sessions: random token (only its hash stored), HttpOnly, Secure, SameSite=Lax, 10 h absolute / 60 min idle; CSRF token
  header and Origin check on every state-changing request; strict Content-Security-Policy (no inline script or style
  attributes - widths are set from JS).
- Sign-in rate limiting and lockout; audit log of every sign-in and change (secrets are never logged - only which
  setting changed).
- Secrets: router API passwords are derived from the master key (`/etc/tikmanager/master.key`, root:tikmanager 0640)
  and never stored; stored router configurations, integration keys and the Microsoft client secret are AES-256-GCM
  encrypted with keys derived from it. A copy of the database alone reveals no credentials.
- Router-side: the `tikmanager` user only accepts logins from the controller's tunnel address; management services are
  reachable only through the tunnel.
- VM: unattended security upgrades, ufw (443/tcp + 51820/udp from anywhere, SSH from the LAN only), fail2ban.

## Not built yet (ideas)

Syslog collection and search, remote WebFig/Winbox through the controller, RouterOS 6 support (no WireGuard), PSA
ticket creation for alerts.
