# Security policy

TikManager can change every router it manages, so security reports are taken seriously and handled first.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately on GitHub: the repository's **Security** tab > **Report a
vulnerability** (private vulnerability reporting). Include what you found, how to reproduce it, and which version
(Admin > Version & updates, or `version.py`).

You'll get an answer within a few days. Fixes are released as a new version (one-click upgrade from the web page) and
called out under the version's heading in [CHANGELOG.md](CHANGELOG.md); please give us a reasonable time to ship a fix
before publishing details.

## Supported versions

Only the newest release gets security fixes - upgrading is one click on **Admin > Version & updates**.

## In scope

The web app and its API, the router adoption flow, the root helpers in `deploy/` (updater, security check, sign-in
collector), how router credentials, backups and keys are stored, and anything that lets one client see another
client's routers. How it's built to be safe is in [ARCHITECTURE.md](ARCHITECTURE.md); hardening the server itself is
under "Keeping it secure" in the [README](README.md).
