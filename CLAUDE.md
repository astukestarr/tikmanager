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

Deploying to a server: `deploy/push.ps1 -VM user@host` (Windows) or copy the folder and `sudo bash deploy/update.sh`.

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
  Configurations, secrets, scripts, VPNs and upgrades are technician-only.
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
| Change the default logo / favicon | `static/logo.svg` (uploaded logos on Admin > Branding replace it) |

## Releasing a new version

Versions are semantic (`MAJOR.MINOR.PATCH`): patch = fixes only, minor = new features that keep existing data and
settings working, major = something an administrator has to act on. To release:
1. Bump `__version__` in `version.py` and add a section at the top of `CHANGELOG.md`.
2. Commit, then tag and push: `git tag v1.2.0 && git push && git push --tags` (optionally also create a GitHub Release
   from the tag - its notes are linked from the "What's new" button).
3. Installations see the update within a day (or at once with "Check for updates") and upgrade with one click
   (`updates.py` -> `deploy/self-update.sh`, which runs the new version's `deploy/update.sh`).

A release must still start against an older database: add new columns/tables in `db.py`'s migrations rather than
assuming a fresh schema, because the updater rolls back the code (not the data) if the new version fails to start.

## Style

Match the surrounding code: short docstrings that explain *why*, plain-English UI text addressed to an MSP technician,
no new dependencies.
