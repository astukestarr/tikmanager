#!/usr/bin/env bash
# Upgrade TikManager to a released version, as root.
#   - run by tikmanager-update.service when an administrator clicks "Upgrade now" (the web app writes the wanted version
#     to /var/lib/tikmanager/update-request; tikmanager-update.path starts this script)
#   - or by hand:  sudo bash /opt/tikmanager/deploy/self-update.sh            (newest release)
#                  sudo bash /opt/tikmanager/deploy/self-update.sh 1.2.3      (a specific version)
# Downloads the release from the repository in TM_UPDATE_REPO (root-owned settings file only), checks it, backs up the
# current code and the database, installs it with its own deploy/update.sh, and rolls back if it doesn't start.
#
# This runs as root, so it never writes into /var/lib/tikmanager (the web app's own folder, where a compromised web app
# could plant links): progress goes to /var/lib/tikmanager-update (root-owned, readable by the service) and database
# copies to /var/backups/tikmanager (root only). From the web app it reads only the version number, digits and dots.
set -euo pipefail

# run from a private copy: the code folder (and this file) is replaced during the upgrade
if [[ "${TM_SELF_COPY:-}" != 1 ]]; then
  COPY=$(mktemp /tmp/tm-self-update.XXXXXX)
  cp "$0" "$COPY"
  TM_SELF_COPY=1 exec bash "$COPY" "$@"
fi
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }

DATA=/var/lib/tikmanager
CODE=/opt/tikmanager
PREV=/opt/tikmanager.prev
ENV=/etc/tikmanager/tikmanager.env
REQ=$DATA/update-request
STATE=/var/lib/tikmanager-update
STATUS=$STATE/status.json
BACKUPS=/var/backups/tikmanager
VER=""
FROM="?"

install -d -m 0750 -o root -g tikmanager "$STATE"
install -d -m 0700 -o root -g root "$BACKUPS"

status() {   # state, detail -> status.json (read by the web app)
  local detail=${2//\"/\'}
  local tmp
  tmp=$(mktemp "$STATE/.status.XXXXXX")
  printf '{"state":"%s","version":"%s","from":"%s","detail":"%s","at":%s}\n' "$1" "$VER" "$FROM" "$detail" "$(date +%s)" > "$tmp"
  chmod 0640 "$tmp"
  chgrp tikmanager "$tmp"
  mv -f "$tmp" "$STATUS"
  echo "[$1] $detail"
}

FROM=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$CODE/version.py" 2>/dev/null || echo "?")
REPO=$(sed -n 's/^TM_UPDATE_REPO=//p' "$ENV" 2>/dev/null | tail -1 | tr -d '"'"'"' ')
REPO=${REPO:-astukestarr/tikmanager}
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { VER="?"; status failed "TM_UPDATE_REPO is not owner/repo"; exit 1; }

# which version: argument, else the web request (a regular file only - not a link or pipe; digits and dots only),
# else the newest release
VER="${1:-}"
FROM_WEB=0
if [[ -z "$VER" && -f "$REQ" && ! -L "$REQ" ]]; then VER=$(head -c 20 -- "$REQ" | tr -dc '0-9.'); FROM_WEB=1; fi
rm -f -- "$REQ"
if [[ -z "$VER" || "$VER" == "latest" ]]; then   # the highest vX.Y.Z tag (every version is tagged; GitHub Releases are optional notes)
  VER=$(curl -fsSL -H "User-Agent: TikManager-updater" "https://api.github.com/repos/$REPO/tags?per_page=100" \
        | python3 -c 'import json,re,sys; t=[x["name"].lstrip("v") for x in json.load(sys.stdin) if re.fullmatch(r"v?\d+\.\d+\.\d+", x["name"])]; print(max(t, key=lambda v: tuple(map(int, v.split(".")))) if t else "")')
fi
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { status failed "No valid version to install ($VER)"; exit 1; }
if [[ "$VER" == "$FROM" ]]; then status done "Already on $VER"; exit 0; fi
# never downgrade from the web request (an older release may have known problems); by hand, only with TM_ALLOW_DOWNGRADE=1
if [[ "$FROM" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$(printf '%s\n%s\n' "$VER" "$FROM" | sort -V | tail -1)" == "$FROM" ]]; then
  if [[ "$FROM_WEB" == 1 || "${TM_ALLOW_DOWNGRADE:-}" != 1 ]]; then
    status failed "$VER is older than the installed $FROM - not installed"; exit 1
  fi
fi

status running "Downloading $VER from github.com/$REPO"
WORK=$(mktemp -d /tmp/tm-update.XXXXXX)
trap 'rm -rf "$WORK" "${COPY:-$0}"' EXIT
if ! curl -fsSL -H "User-Agent: TikManager-updater" -o "$WORK/release.tar.gz" "https://github.com/$REPO/archive/refs/tags/v$VER.tar.gz"; then
  status failed "Couldn't download v$VER (does the tag exist?)"; exit 1
fi
tar -xzf "$WORK/release.tar.gz" -C "$WORK" --no-same-owner
SRC=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)
[[ -f "$SRC/server.py" && -f "$SRC/deploy/update.sh" ]] || { status failed "The download doesn't look like TikManager"; exit 1; }
grep -q "__version__ = \"$VER\"" "$SRC/version.py" || { status failed "The download's version.py isn't $VER"; exit 1; }
python3 -c 'import sys; [compile(open(f, encoding="utf-8").read(), f, "exec") for f in sys.argv[1:]]' "$SRC"/*.py \
  || { status failed "The new version has Python errors - not installed"; exit 1; }

status running "Backing up the current version ($FROM) and the database"
rm -rf "$PREV"
cp -a "$CODE" "$PREV"
# the copy is read by the service's own user (its files, its rights) and streamed to root over stdout, so root never
# opens anything in the web app's folder; serialize() is a consistent snapshot while TikManager keeps running
DBCOPY="$BACKUPS/backup-before-$VER.db"
if ! (umask 077; cd / && runuser -u tikmanager -- python3 -I -c \
      'import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); sys.stdout.buffer.write(c.serialize()); c.close()' \
      "$DATA/tikmanager.db" > "$DBCOPY") || [[ ! -s "$DBCOPY" ]]; then
  rm -f -- "$DBCOPY"; status failed "Couldn't back up the database - not installed"; exit 1
fi
# keep the newest 3 (root-only folder: only this script writes names there)
find "$BACKUPS" -maxdepth 1 -type f -name 'backup-before-*.db' -printf '%T@ %p\n' | sort -rn | tail -n +4 | cut -d' ' -f2- \
  | while IFS= read -r old; do rm -f -- "$old"; done

status running "Installing $VER"
if bash "$SRC/deploy/update.sh" >"$WORK/update.log" 2>&1 && sleep 5 && systemctl is-active --quiet tikmanager; then
  status done "Upgraded from $FROM to $VER"
else
  status running "$VER didn't start - rolling back to $FROM"
  rsync -a --delete "$PREV/" "$CODE/"
  cp "$CODE/deploy/tikmanager.service" /etc/systemd/system/tikmanager.service
  systemctl daemon-reload
  systemctl restart tikmanager
  status failed "$VER didn't start; rolled back to $FROM. Details: journalctl -u tikmanager-update -u tikmanager"
  exit 1
fi
