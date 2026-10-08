#!/usr/bin/env bash
# TikManager one-time install on Ubuntu 26.04 LTS (run as root from the folder that holds the TikManager code):
#     sudo bash deploy/install.sh --host tikmanager.example.com --lan 192.168.1.0/24
# It ends by printing a one-time setup link: open it to create the first administrator, then configure everything else
# (Microsoft sign-in, staff domains, branding...) on the Admin pages. --admins / --domains are optional defaults.
# Safe to run again. It:
#   - installs WireGuard, Caddy (official repo), Python, ufw, fail2ban, unattended-upgrades
#   - creates the 'tikmanager' system user (no shell, no sudo) and its folders
#   - creates the controller's WireGuard key and wg0 (10.77.0.1/16, UDP 51820)
#   - writes /etc/tikmanager/tikmanager.env, the master key, the Caddy site and the systemd service
#   - firewall: 80+443/tcp and 51820/udp from anywhere, SSH only from your LAN, syslog only over the tunnel
set -euo pipefail

HOST=""
LAN=""
ADMINS=""
DOMAINS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --lan) LAN="$2"; shift 2 ;;
    --admins) ADMINS="$2"; shift 2 ;;
    --domains) DOMAINS="$2"; shift 2 ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
[[ -n "$HOST" ]] || { echo "Give the public name TikManager will answer on (with a DNS record pointing at this server), e.g. --host tikmanager.example.com"; exit 1; }
[[ -n "$LAN" ]] || { echo "Give your LAN subnet for SSH access, e.g. --lan 192.168.1.0/24"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$SRC/server.py" ]] || { echo "Run this from the TikManager code folder."; exit 1; }

echo "== Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq wireguard-tools python3 python3-cryptography rsync ufw fail2ban unattended-upgrades debian-keyring debian-archive-keyring apt-transport-https curl gnupg
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q && apt-get install -yq caddy
fi
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "== User and folders"
id tikmanager >/dev/null 2>&1 || useradd --system --home /var/lib/tikmanager --shell /usr/sbin/nologin tikmanager
install -d -m 0755 /opt/tikmanager
install -d -m 0750 -o tikmanager -g tikmanager /var/lib/tikmanager
install -d -m 0750 -o root -g tikmanager /etc/tikmanager
rsync -a --delete --exclude data --exclude '.env' --exclude '__pycache__' "$SRC/" /opt/tikmanager/ 2>/dev/null || cp -r "$SRC/." /opt/tikmanager/
rm -rf /opt/tikmanager/data
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
# Optional defaults - staff sign-in, Microsoft sign-in and the WireGuard address are normally set on Admin > Settings:
TM_TECH_ADMINS=$ADMINS
TM_TECH_DOMAINS=$DOMAINS
EOF
fi
sed -i "s|^WG_SERVER_PUBKEY=.*|WG_SERVER_PUBKEY=$PUB|" $ENV
chown root:tikmanager $ENV && chmod 0640 $ENV

echo "== Service"
cp /opt/tikmanager/deploy/tikmanager.service /etc/systemd/system/tikmanager.service
systemctl daemon-reload
systemctl enable tikmanager

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
echo
TOKEN=$(sed -n 's/^TM_SETUP_TOKEN=//p' $ENV)
echo "Done. TikManager: https://$HOST   Controller WireGuard public key: $PUB"
echo
echo "Next: open this one-time link to create your administrator account:"
echo "    https://$HOST/setup/$TOKEN"
echo "Then set up Microsoft sign-in for your technicians on Admin > Settings."
