#!/usr/bin/env bash
# Upgrade TikManager to a released version, as root.
#   - run by tikmanager-update.service when an administrator clicks "Upgrade now" (the web app writes the wanted version
#     to /var/lib/tikmanager/update-request; tikmanager-update.path starts this script)
#   - or by hand:  sudo bash /opt/tikmanager/deploy/self-update.sh            (newest stable release)
#                  sudo bash /opt/tikmanager/deploy/self-update.sh beta       (newest release, betas included)
#                  sudo bash /opt/tikmanager/deploy/self-update.sh 1.2.3      (a specific version; 1.2.3-beta.1 for a beta)
# Versions listed as withdrawn in RELEASES.json on the repository's default branch are never installed.
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

# which version: argument, else the web request (a regular file only - not a link or pipe; digits, letters, dots, dashes),
# else the newest release
VER="${1:-}"
FROM_WEB=0
if [[ -z "$VER" && -f "$REQ" && ! -L "$REQ" ]]; then VER=$(head -c 24 -- "$REQ" | tr -dc '0-9a-z.-'); FROM_WEB=1; fi
rm -f -- "$REQ"
# version sort key: 1.2.3-beta.1 < 1.2.3-beta.2 < 1.2.3 (a release comes after its betas)
VKEY='import re,sys
def k(v):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?", v.strip())
    return (int(m[1]), int(m[2]), int(m[3]), 0 if m[4] else 1, int(m[4] or 0)) if m else None'
WITHDRAWN=$(curl -fsSL -H "User-Agent: TikManager-updater" "https://raw.githubusercontent.com/$REPO/HEAD/RELEASES.json" 2>/dev/null \
            | python3 -c 'import json,sys; print(" ".join(str(v).lstrip("v") for v in (json.load(sys.stdin).get("withdrawn") or [])))' 2>/dev/null || true)
all_tags() {   # every tag, all pages - GitHub returns at most 100 per page (the newest first)
  local page=1 all="[]" batch n
  while (( page <= 10 )); do
    batch=$(curl -fsSL -H "User-Agent: TikManager-updater" "https://api.github.com/repos/$REPO/tags?per_page=100&page=$page") || break
    all=$(A="$all" B="$batch" python3 -c 'import json,os; print(json.dumps(json.loads(os.environ["A"]) + json.loads(os.environ["B"])))')
    n=$(B="$batch" python3 -c 'import json,os; print(len(json.loads(os.environ["B"])))')
    (( n < 100 )) && break
    page=$((page + 1))
  done
  printf '%s' "$all"
}
if [[ -z "$VER" || "$VER" == "latest" || "$VER" == "beta" ]]; then   # the highest tag (betas only when asked for), skipping withdrawn ones
  VER=$(all_tags \
        | BETA=$([[ "$VER" == "beta" ]] && echo 1 || echo 0) PULLED="$WITHDRAWN" python3 -c "$VKEY"'
import json, os
pulled = set(os.environ["PULLED"].split())
names = [x["name"].lstrip("v") for x in json.load(sys.stdin) if k(x["name"])]
betas = [v for v in names if "-beta." in v]
t = [v for v in names if "-beta." not in v] + ([max(betas, key=k)] if os.environ["BETA"] == "1" and betas else [])   # newest beta only
t = [v for v in t if v not in pulled]
print(max(t, key=k) if t else "")')
fi
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+)?$ ]] || { status failed "No valid version to install ($VER)"; exit 1; }
if [[ "$VER" == "$FROM" ]]; then status done "Already on $VER"; exit 0; fi
if [[ " $WITHDRAWN " == *" $VER "* && "${TM_ALLOW_WITHDRAWN:-}" != 1 ]]; then
  status failed "$VER was withdrawn (RELEASES.json) - not installed"; exit 1
fi
# a beta from the web must be the newest beta - an older one was superseded (often because the newer one fixes it)
if [[ "$FROM_WEB" == 1 && "$VER" == *-beta.* ]]; then
  NEWEST=$(all_tags            | python3 -c "$VKEY"'
import json
b = [x["name"].lstrip("v") for x in json.load(sys.stdin) if k(x["name"]) and "-beta." in x["name"]]
print(max(b, key=k) if b else "")')
  [[ "$VER" == "$NEWEST" ]] || { status failed "$VER isn't the newest beta ($NEWEST) - not installed"; exit 1; }
fi
# never downgrade from the web request (an older release may have known problems); by hand, only with TM_ALLOW_DOWNGRADE=1
if [[ "$FROM" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+)?$ ]] \
   && python3 -c "$VKEY"'
sys.exit(0 if k(sys.argv[1]) < k(sys.argv[2]) else 1)' "$VER" "$FROM"; then
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
