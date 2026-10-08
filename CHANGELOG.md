# Changelog

Versions follow [semantic versioning](https://semver.org): **patch** (1.0.x) = fixes, **minor** (1.x.0) = new features,
safe to upgrade with the button; **major** (x.0.0) = changes that need manual steps (described here).

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
  backup settings; branding, with a built-in tiki torch logo and favicon until you upload your own.
- **Updates**: version shown in the app, daily check for new releases, one-click upgrade with automatic roll-back.
