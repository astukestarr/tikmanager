#!/usr/bin/env bash
# Update TikManager's code on the VM from a freshly copied folder (keeps data, settings and keys):
#     sudo bash deploy/update.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$SRC/server.py" ]] || { echo "Run this from the copied TikManager folder."; exit 1; }
python3 -c "import cryptography" 2>/dev/null || { echo "Installing python3-cryptography (encrypts stored router configs)"; DEBIAN_FRONTEND=noninteractive apt-get install -yq python3-cryptography; }
python3 -c 'import sys; [compile(open(f, encoding="utf-8").read(), f, "exec") for f in sys.argv[1:]]' "$SRC"/*.py   # syntax check without leaving root-owned __pycache__ behind
rsync -a --delete --exclude data --exclude '.env' --exclude '__pycache__' --exclude .git --exclude dist "$SRC/" /opt/tikmanager/ 2>/dev/null || { rm -rf /opt/tikmanager/*; cp -r "$SRC/." /opt/tikmanager/; }
rm -rf /opt/tikmanager/data /opt/tikmanager/.git /opt/tikmanager/dist
chown -R root:root /opt/tikmanager && chmod -R u=rwX,go=rX /opt/tikmanager   # readable (not writable) by the service; the upload folder may be private
cp /opt/tikmanager/deploy/tikmanager.service /etc/systemd/system/tikmanager.service
# the root updater behind Admin "Upgrade now" (tikmanager-update.path watches for the web app's request)
cp /opt/tikmanager/deploy/tikmanager-update.path /opt/tikmanager/deploy/tikmanager-update.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tikmanager-update.path >/dev/null 2>&1 || true
systemctl restart tikmanager
sleep 2
systemctl --no-pager --lines=5 status tikmanager
