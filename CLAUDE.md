# TikManager - notes for working on this code (Claude Code and humans)

Self-hosted MikroTik RouterOS 7 controller for MSPs. Read [README.md](README.md) (install, features) and
[ARCHITECTURE.md](ARCHITECTURE.md) (modules, data flow, security model) first.

## Run and test

```
set TM_DEV=1
set TM_PORT=8801
set TM_PUBLIC_URL=http://localhost:8801
python server.py
```
Open http://localhost:8801, **Dev sign-in**. `TM_DEV=1` replaces real routers with `routeros.SimRouter` (and demo
data for integrations), so every page works without hardware. Data lives in `./data/` - delete it for a clean start.
To test the first-run flow: also set `TM_SETUP_TOKEN=<anything 20+ chars>` and a fresh `TM_DATA` folder, then open
`/setup/<token>`.

There is no test suite; verify changes by:
1. `python -m py_compile *.py` (syntax),
2. running the dev server and exercising the page/endpoint in a browser (check the console for errors),
3. for logic that's hard to reach in the UI, a short Python script against a temp `DB(...)` and `SimRouter` objects.

Shipping changes: release a new version (below) and upgrade with Admin > Settings > Upgrade now. To try unreleased code
on a server: `deploy/push.ps1 -VM user@host` (Windows) or copy the folder and `sudo bash deploy/update.sh`.

## Ground rules (keep these - they're what makes it safe to expose to the internet)

- **Standard library only** on the server (plus `python3-cryptography`, used by `vault.py`). No pip packages, no npm,
  no build step. The front end is plain JS in `static/`.
- **Strict CSP**: no inline `<script>`, no `onclick=` attributes, no inline `style="..."` attributes in markup the app
  generates (set sizes with `el.style.x = ...` from JS, or CSS classes). Load nothing from other origins.
- **Escape everything** inserted into HTML with `esc()` (`static/app.js`). Never build HTML from unescaped data.
- **Every state-changing request is a POST** made with `post()` (it sends the CSRF header). Server side, everything after
  the unauthenticated routes in `route_post` goes through `check_csrf`.
- **Authorization on every endpoint**: `self.require(tech=..., write=..., admin=...)`; client users only ever see their
  own organization - use `self.org_scope(...)` for list queries and `self.device_for(s, id)` for a single router.
  Configurations, secrets, scripts, VPNs and upgrades are technician-only - except Winbox sessions and site-to-site VPNs,
  which a TikManager administrator can turn on per client for that client's **admins** (`orgs.client_winbox` /
  `client_vpn`; enforced by `require_winbox()` / `require_vpn()` / `vpn_for()` in `server.py` - use them, never `tech=True`
  alone, on Winbox and VPN endpoints).
- **Secrets never stored in plain text**: router passwords are derived (`security.derive(KEY, purpose)`); anything else
  secret is sealed with the vault (`backups.vault.seal(data, context)`), and APIs return only "saved: yes/no", never the
  value. Never log secrets; audit-log only *which* setting changed.
- **Audit**: `db.audit(user, action, target, ip, detail=..., org_id=...)` for every change a person makes;
  `db.event(device_id, org_id, kind, detail)` for things that happen to a router.
- **Database**: use `db.q` / `db.one` / `db.run` (one shared connection under a lock - don't open your own connections).
  New table: add it to `SCHEMA` in `db.py`. New column on an existing table: add it to `SCHEMA` *and* to the column list
  in `DB.migrate()` so existing databases get it.
- **Routers**: talk to them through `RouterOS` (REST over the tunnel). Anything you add there needs a matching method on
  `SimRouter` so dev mode keeps working. Read-only inventory reads whitelist fields (see `RouterOS.INVENTORY`) so
  passwords/keys are never pulled into TikManager. Things TikManager creates on a router carry a comment tag
  (`TikManager`, `TikManager VPN`) so they can be removed exactly.
- **Background work**: long jobs run in daemon threads (see `poller.py`, `backups.py`, `upgrades.py`, `tasks.py`) and
  never let one failing router stop the loop (catch `RouterError` per router).
- **Settings**: things an administrator should change go on Admin > Settings (`appsettings.py` FIELDS + the form in
  `adminSystem()` in `static/app.js`), not in code. Only bootstrap values (public address, data folder, port, keys) live
  in the settings file (`.env.example` lists them). Branding (company name, logo, colours) is `branding.py`.

## Where to change common things

| Want to... | Look at |
|---|---|
| Add a page / tab in the web app | `static/app.js` (`VIEWS`, `go()`), `static/index.html` nav |
| Add an API | `server.py` `route_get` / `route_post` |
| Poll something new from routers | `routeros.RouterOS.status()` (+ `SimRouter.status()`), `poller.poll_one` |
| Change what the adoption script does | `adoption.py` (it runs on every re-run - keep it idempotent) |
| Add an admin setting | `appsettings.py` FIELDS + `adminSystem()` |
| Add an integration | `integrations.py` + Admin > Integrations in `app.js` |
| Firewall / NAT editing (fields, locked rules, undo timer) | `firewall.py` (`FIELDS`, `ACTIONS`, `protected()`, `restore_script()`), `RouterOS.fw_*` / `undo_*` (+ `SimRouter`), `loadFirewall()` / `fwDialog()` in `app.js` |
| Community script library (danger / secret patterns, sharing) | `scriptlib.py` (`DANGER`, `SECRETS`, `share()`), `libraryDialog()` / `shareDialog()` in `app.js`; library repo `astukestarr/routeros-scripts` |
| Wireless tab (radios, links, AP clients) | `RouterOS.wireless()` / `SimRouter.wireless()`, `/api/devices/{id}/wireless`, `loadWireless()` in `app.js` |
| Internet links (ISP / WAN / LTE state) | `Poller.isp_links/track_isp`, `isp` alert kind, `ispCard/ispSettings` in `app.js` |
| Hardware health (sensors, SFP) | `RouterOS.health()`, `health_metrics` table, `/api/devices/{id}/health`, `hwCard()` in `app.js` |
| Sidebar / navigation | `NAV`, `renderNav`, `navActive`, `refreshNavCounts` in `app.js`; device kinds in `devkind.py` |
| Ports and VLANs | `ports.py` (`build`, `plan`, `undo_script`, `apply/keep/undo`), `RouterOS.port_data/br_*`, `portsTab/portEditor/ptChange` in `app.js` |
| Router logs and log alert rules | `routerlogs.py` (`parse`, `query`, `conditions`), `logsPage/logViewer/logRulesCard` in `app.js` |
| Webhooks (alert destinations) | `webhooks.py` (`build`, `send_all`, `check_url`), `alerts._hooks`, `webhooksCard/webhookDialog` in `app.js` |
| Auto-block (fleet-wide blocklist) | `autoblock.py` (`candidates`, `block`, `release`, `push`, `add_rule`), `autoBlockCard()` in `app.js` |
| RouterOS security (CVEs, security releases, What's new) | `rossec.py` (`security_items`, `releases_between`, `cves_for`), `secState/secCard/notesDialog/rosSecCard` in `app.js` |
| Router lifecycle (age, discontinued, replacements) | `lifecycle.py` (`REPLACEMENTS`, overrides in setting `lifecycle_suggest`), `lcYears/lcMade/lcFlag/lcSuggest/lifecycleCard/lcAdminCard` in `app.js` |
| Performance & Security dashboard | `healthdash.py` (`build`, `exposure`, `CATEGORIES`), extra fields in `RouterOS.INVENTORY`, `/api/health-dash`, `healthPage()` in `app.js` |
| What's new tour (slides, screenshots, acknowledgement) | `whatsnew.py`, `static/whatsnew/*.jpg`, `/api/whats-new` (+ `/seen`), `whatsNew()` in `app.js`; stored in `users.prefs.whatsnew` |
| Compliance (frameworks, client report) | `compliance.py` (`CHECKS`, `FRAMEWORKS`, `evaluate`, `scorecard`, `report_html/csv`), `/api/compliance*`, `compliancePage()` in `app.js`, `static/report.css` + `report.js` |
| Accepted findings (exceptions) | `exceptions` table, `exceptions_map()` + `/api/exceptions` in `server.py`; keys `hd:<dashboard title>` / `cc:<check id>`; `compliance.HD` / `ITEM_HD` map them onto checks |
| HTTPS management connection | `RouterOS(tls_port=...)` + `_req` fallback (`NoConnection` only), `https_setup/test/revert` (+ `SimRouter`), `Poller.client/_tls_fallback`, `switch_https()` + `/api/devices/<id>/mgmt-https` in `server.py`, `devices.api_tls_port/api_tls_fp` |
| One-click security fixes | `healthdash.FIXES` / `fix_request` / `fix_retry`, `/api/health-dash/fix` (background job, `FIX_JOBS`), `fixJobBox()` in `app.js` |
| Remote access (WireGuard for Windows into a router) | `remoteaccess.py` (`RemoteAccess.setup/add_user/download/revoke/remove`, `keypair`), `RouterOS.ra_*`, `raTab()` in `app.js` |
| Send email | `mailer.Mailer.send()` (`server.mailer`, `alerts.mailer`); settings in `integrations.py` FIELDS "mail" |
| UniFi / UISP connections, sites, devices | `ubnt.py` (`UnifiClient`, `UispClient`, `Ubnt.sync_account/sites/conditions`), `/api/net/*` and `/api/unifi*` in `server.py`, `unifiPage()` / `wireNetAccounts()` in `app.js` |
| Alerts (kinds, thresholds, tickets, Teams, email) | `alerts.py` (`KINDS`, `conditions()`, `notify_open/resolved()`), `Integrations.cw_ticket/cw_close/teams_post`, `alertsPage()` in `app.js` |
| WireGuard port (move, relay, helper) | `wgport.py`, `deploy/wg-port.sh` + `tikmanager-wgport.*`, `RouterOS.set_controller_port`, `devices.wg_port`, `wgPortCard()` in `app.js`; installer `--wg-port` |
| Winbox relay (sessions, ports, router Winbox fix) | `winbox.py`, `RouterOS.winbox_service/winbox_allow` (+ `SimRouter`), `winbox_allows_tikmanager()` + `/api/devices/<id>/winbox*` in `server.py`, `loadWinbox()` in `app.js`; `TM_WINBOX_PORTS` |
| Off-site backup / restore | `offsite.py` (`build()`, `encrypt()`, destinations), `tools/tmbak.py`, `offsiteCard()` in `app.js`; README "Off-site backup and restoring" |
| Connectivity test (outside-in ports) | `reachability.py`, `reachBox()` + `SEC_FIXES.net_*` in `app.js` |
| Website security grade (Mozilla Observatory) | `observatory.py`, `obsBox()` in `app.js`; `TM_OBSERVATORY` |
| Security page (events, flags, router log parsing) | `secevents.py` (`parse_router()`, `summary()`), `deploy/collect-auth.py` (Ubuntu side), `secev.record(...)` calls in `server.py`, `securityPage()` in `app.js` |
| Discovered page (which neighbours count as new) | `discovered.py` (`known_sets()` / `match()`), `RouterOS.mikrotik_neighbors()` (+ `SimRouter`), poller (every `INVENTORY_SECONDS`), `discoveredPage()` in `app.js` |
| Server hardening check | `deploy/check.sh` (read-only; keep it in step with `install.sh`; `--json` for the app), `tikmanager-check.*` units, `Updates.security()`, `securityBox()` + `SEC_FIXES` (How to fix, by check ID) in `app.js`; README "Fixing server security findings" |
| Network map (what's shown, device recognition) | `topology.py` (`OUI` / `NAMES` decide device kinds), `RouterOS.topology()` (+ `SimRouter.topology()`), `loadTopology()` in `app.js` |
| Geographic map / map data | `static/geomap.js`; rebuild `static/map/*.json` with `python tools/build_map.py <sources>` (instructions inside) |
| Change the colours or add a theme | `static/styles.css` (the token block at the top: one `[data-theme=...]` rule per theme, dark mode below it), `static/theme.js` + `THEMES` in `server.py` + `THEME_INFO` in `app.js` (name and swatch) |
| Change the default logo / favicon | `static/wordmark.svg` (logo: the name with the T as a tiki torch), `static/logo.svg` (torch icon, favicon); an uploaded logo on Admin > Branding replaces the wordmark |

## Releasing a new version

Versions are semantic (`MAJOR.MINOR.PATCH`): patch = fixes only, minor = new features that keep existing data and
settings working, major = something an administrator has to act on. **Every change to what runs on the server gets a
new version** - don't push code changes without one. To release:
1. Bump `__version__` in `version.py` and add a section at the top of `CHANGELOG.md` (newest first, plain English for
   the administrators who'll read it before clicking Upgrade; for a major version, the steps they must take).
2. Commit, then tag and push: `git tag -a v1.2.0 -m "TikManager 1.2.0" && git push && git push --tags` (optionally also
   create a GitHub Release from the tag - its notes are linked from the "What's new" button; `python tools/release_notes.py
   1.2.0` prints that version's changelog section to paste). The newest version is always the highest tag, so a version
   without a Release is still offered.
3. Check GitHub has it: `git ls-remote --tags origin`, `git show origin/main:version.py`.
4. Installations see the update within an hour (or at once with "Check for updates") and upgrade with one click
   (`updates.py` -> `deploy/self-update.sh`, which runs the new version's `deploy/update.sh`).

**What's new tour.** `whatsnew.py` describes the current release (`RELEASE`, `SINCE` = the full release before it, and
`SLIDES`, with screenshots in `static/whatsnew/` taken from dev mode - never real client data). When a feature worth
showing lands, add a slide; when a new release line starts (e.g. 1.47.0-beta.1), set `RELEASE`/`SINCE` and replace the
slides - if `RELEASE` doesn't match the running version, no tour is shown.

**Beta first.** Every new change is released as a beta: version `X.Y.Z-beta.N` (e.g. `1.45.0-beta.1`, then `-beta.2`
for the next fix), tag `vX.Y.Z-beta.N`, changelog heading `## X.Y.Z-beta.N - date`. Only installations on the Beta
channel (Admin > Settings > Version & updates) see betas, and only the newest beta is ever offered - so a beta that a
later beta fixes is never installed again. When the maintainer has tested a beta and says to **release it**, release the
same code as `X.Y.Z` (stable): bump `version.py`, add a `## X.Y.Z` changelog section summing up its betas, tag `vX.Y.Z`.
Never release a stable version without that go-ahead. To pull a broken version with no fix yet, add it to `withdrawn` in
`RELEASES.json` and push (no new version needed - it's read from the default branch); installations skip it and the root
updater refuses it.

Never move or reuse a tag that's already on GitHub: servers only offer a version *newer* than their own, so changed
code under an old number never reaches them - release a new patch instead. Changes to documentation only (README,
ARCHITECTURE, CLAUDE.md) don't change what runs, so they're pushed without a new version and show up on GitHub at once;
they ride along in the next release.

A release must still start against an older database: add new columns/tables in `db.py`'s migrations rather than
assuming a fresh schema, because the updater rolls back the code (not the data) if the new version fails to start.

## Style

Match the surrounding code: short docstrings that explain *why*, plain-English UI text addressed to an MSP technician,
no new dependencies.
