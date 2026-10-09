#!/usr/bin/env bash
# TikManager one-time install on Ubuntu 26.04 LTS (run as root from the folder that holds the TikManager code):
#     sudo bash deploy/install.sh --host tikmanager.example.com --lan 192.168.1.0/24
# Usually started by deploy/get.sh, which downloads the newest release from GitHub on the server itself.
# It ends by printing a one-time setup link: open it to create the first administrator, then configure everything else
# (Microsoft sign-in, staff domains, branding...) on the Admin pages. --admins / --domains are optional defaults.
# Safe to run again. It:
#   - installs WireGuard, Caddy (official repo), Python, ufw, fail2ban, unattended-upgrades (security updates daily,
#     Caddy included; restarts at 03:00 only when an update needs it)
#   - creates the 'tikmanager' system user (no shell, no sudo) and its folders
#   - creates the controller's WireGuard key and wg0 (10.77.0.1/16, UDP 51820)
#   - writes /etc/tikmanager/tikmanager.env, the master key, the Caddy site and the systemd service
#   - firewall: 80+443/tcp and 51820/udp from anywhere, SSH only from your LAN, syslog only over the tunnel
#   - a daily read-only security check of this server (deploy/check.sh; results on Admin > Version & updates)
set -euo pipefail

HOST=""
LAN=""
ADMINS=""
DOMAINS=""
REPO="astukestarr/tikmanager"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --lan) LAN="$2"; shift 2 ;;
    --admins) ADMINS="$2"; shift 2 ;;
    --domains) DOMAINS="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;   # where updates come from (e.g. your fork); written to the settings file
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
[[ -n "$HOST" ]] || { echo "Give the public name TikManager will answer on (with a DNS record pointing at this server), e.g. --host tikmanager.example.com"; exit 1; }
[[ -n "$LAN" ]] || { echo "Give your LAN subnet for SSH access, e.g. --lan 192.168.1.0/24"; exit 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "--repo must look like owner/repository"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$SRC/server.py" ]] || { echo "Run this from the TikManager code folder."; exit 1; }

echo "== Packages"
export DEBIAN_FRONTEND=noninteractive
CADDY_LIST=/etc/apt/sources.list.d/caddy-stable.list
apt_update() {
  # Caddy's own package repository (Cloudsmith) sometimes refuses downloads for days ("402": its free quota ran out).
  # Don't let that stop the install: if it's the only source failing, set it aside and carry on.
  local out
  if out=$(apt-get update -q 2>&1); then return 0; fi
  echo "$out" | tail -n 4
  if [[ -f $CADDY_LIST ]] && ! grep -E '^(Err|E:|Error)' <<<"$out" | grep -vq 'dl.cloudsmith.io'; then
    echo "Caddy's package repository isn't answering right now - setting it aside ($CADDY_LIST.disabled) and carrying on."
    mv -f "$CADDY_LIST" "$CADDY_LIST.disabled"
    apt-get update -q
  else
    return 1
  fi
}
install_caddy_github() {
  # Caddy's official .deb from its GitHub release, checked against the release's own SHA-512 checksums
  local arch tag ver deb tmp
  arch=$(dpkg --print-architecture)
  tag=$(curl -fsSL https://api.github.com/repos/caddyserver/caddy/releases/latest | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Couldn't find Caddy's latest release on GitHub."; return 1; }
  ver=${tag#v}; deb="caddy_${ver}_linux_${arch}.deb"; tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/$deb" "https://github.com/caddyserver/caddy/releases/download/$tag/$deb" &&
    curl -fsSL -o "$tmp/sums.txt" "https://github.com/caddyserver/caddy/releases/download/$tag/caddy_${ver}_checksums.txt" &&
    (cd "$tmp" && grep " $deb\$" sums.txt | sha512sum -c --quiet -) || { echo "Caddy's download failed or didn't match its checksum."; rm -rf "$tmp"; return 1; }
  apt-get install -yq "$tmp/$deb"
  rm -rf "$tmp"
  echo "Installed Caddy $ver from GitHub. It won't update automatically until its package repository is back - Admin > Version & updates says how."
}
apt_update
apt-get install -yq wireguard-tools python3 python3-cryptography rsync ufw fail2ban unattended-upgrades debian-keyring debian-archive-keyring apt-transport-https curl gnupg
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > "$CADDY_LIST"
  { apt_update && apt-get install -yq caddy; } || install_caddy_github
fi
dpkg-reconfigure -f noninteractive unattended-upgrades
# automatic updates also restart the server at 03:00 when an update needs it, and keep Caddy (own repository) updated
install -m 0644 "$SRC/deploy/apt-unattended.conf" /etc/apt/apt.conf.d/52tikmanager-unattended

echo "== User and folders"
id tikmanager >/dev/null 2>&1 || useradd --system --home /var/lib/tikmanager --shell /usr/sbin/nologin tikmanager
install -d -m 0755 /opt/tikmanager
install -d -m 0750 -o tikmanager -g tikmanager /var/lib/tikmanager
install -d -m 0750 -o root -g tikmanager /etc/tikmanager
install -d -m 0750 -o root -g tikmanager /var/lib/tikmanager-update   # the root updater's progress (the service reads it)
install -d -m 0700 -o root -g root /var/backups/tikmanager             # database copies taken before each upgrade
rsync -a --delete --exclude data --exclude '.env' --exclude '__pycache__' --exclude .git --exclude dist "$SRC/" /opt/tikmanager/ 2>/dev/null || cp -r "$SRC/." /opt/tikmanager/
rm -rf /opt/tikmanager/data /opt/tikmanager/.git /opt/tikmanager/dist
chown -R root:root /opt/tikmanager && chmod -R u=rwX,go=rX /opt/tikmanager   # readable (not writable) by the service; the upload folder may be private

echo "== WireGuard (wg0)"
if [[ ! -f /etc/wireguard/wg0.conf ]]; then
  umask 077
  PRIV=$(wg genkey)
  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.77.0.1/16
ListenPort = 51820
PrivateKey = $PRIV
# Router peers are added by TikManager at runtime (they're stored in its database).
EOF
fi
PUB=$(grep -E '^PrivateKey' /etc/wireguard/wg0.conf | awk '{print $3}' | wg pubkey)
systemctl enable --now wg-quick@wg0
# routers never talk to each other or to the LAN through the controller
sysctl -w net.ipv4.ip_forward=0 >/dev/null
echo "net.ipv4.ip_forward=0" > /etc/sysctl.d/90-tikmanager.conf

echo "== Settings"
if [[ ! -f /etc/tikmanager/master.key ]]; then
  head -c 32 /dev/urandom > /etc/tikmanager/master.key
fi
chown root:tikmanager /etc/tikmanager/master.key && chmod 0640 /etc/tikmanager/master.key
ENV=/etc/tikmanager/tikmanager.env
if [[ ! -f $ENV ]]; then
  cat > $ENV <<EOF
TM_HOST=127.0.0.1
TM_PORT=8800
TM_PUBLIC_URL=https://$HOST
TM_DATA=/var/lib/tikmanager
TM_KEY_FILE=/etc/tikmanager/master.key
WG_SERVER_IP=10.77.0.1
WG_NETWORK=10.77.0.0/16
WG_SERVER_PUBKEY=$PUB
# One-time first-run link: https://$HOST/setup/<this token> (stops working once an administrator exists)
TM_SETUP_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)
# Where new versions come from (GitHub owner/repo). Only change this to a repository you trust: the updater runs as root.
TM_UPDATE_REPO=$REPO
# Optional defaults - staff sign-in, Microsoft sign-in and the WireGuard address are normally set on Admin > Settings:
TM_TECH_ADMINS=$ADMINS
TM_TECH_DOMAINS=$DOMAINS
EOF
fi
sed -i "s|^WG_SERVER_PUBKEY=.*|WG_SERVER_PUBKEY=$PUB|" $ENV
chown root:tikmanager $ENV && chmod 0640 $ENV

echo "== Service"
cp /opt/tikmanager/deploy/tikmanager.service /etc/systemd/system/tikmanager.service
# root updater behind Admin "Upgrade now": the web app drops a version number, this installs that release
cp /opt/tikmanager/deploy/tikmanager-update.path /opt/tikmanager/deploy/tikmanager-update.service /etc/systemd/system/
# read-only server security check (deploy/check.sh), shown on Admin > Version & updates: daily and on request
cp /opt/tikmanager/deploy/tikmanager-check.service /opt/tikmanager/deploy/tikmanager-check.path /opt/tikmanager/deploy/tikmanager-check.timer /etc/systemd/system/
# this server's sign-in attempts (SSH, sudo, fail2ban) for the Security page, collected every 5 minutes (read-only)
cp /opt/tikmanager/deploy/tikmanager-authlog.service /opt/tikmanager/deploy/tikmanager-authlog.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable tikmanager
systemctl enable --now tikmanager-update.path
systemctl enable --now tikmanager-check.path tikmanager-check.timer tikmanager-authlog.timer

echo "== Caddy (HTTPS front door)"
sed "s|__HOST__|$HOST|g" /opt/tikmanager/deploy/Caddyfile > /etc/caddy/Caddyfile
systemctl enable caddy && systemctl reload-or-restart caddy

echo "== Firewall"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp comment 'Caddy: certificate checks + redirect to HTTPS'
ufw allow 443/tcp comment 'TikManager web + router adoption'
ufw allow 51820/udp comment 'WireGuard from routers'
ufw allow from "$LAN" to any port 22 proto tcp comment 'SSH from LAN only'
ufw allow in on wg0 to 10.77.0.1 port 5514 proto udp comment 'Router logs over the tunnel'
ufw --force enable

echo "== fail2ban (SSH)"
systemctl enable --now fail2ban

systemctl restart tikmanager
sleep 2
systemctl --no-pager --lines=5 status tikmanager || true
systemctl start --no-block tikmanager-check.service >/dev/null 2>&1 || true   # first security check (Admin > Version & updates)
echo
TOKEN=$(sed -n 's/^TM_SETUP_TOKEN=//p' $ENV)
echo "Done. TikManager: https://$HOST   Controller WireGuard public key: $PUB"
echo
echo "Next: open this one-time link to create your administrator account:"
echo "    https://$HOST/setup/$TOKEN"
echo "Then set up Microsoft sign-in for your technicians on Admin > Settings."
