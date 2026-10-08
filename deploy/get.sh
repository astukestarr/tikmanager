#!/usr/bin/env bash
# Install TikManager straight from GitHub on a fresh Ubuntu server - no other computer needed.
#
#   curl -fsSL https://raw.githubusercontent.com/astukestarr/tikmanager/main/deploy/get.sh -o get.sh
#   sudo bash get.sh --host tikmanager.example.com --lan 192.168.1.0/24
#
# (or in one go: curl -fsSL .../get.sh | sudo bash -s -- --host ... --lan ...). Anything you leave out is asked for.
# It downloads the newest release (or --version X.Y.Z), checks it, and runs that release's deploy/install.sh, which ends
# by printing the one-time setup link for your first administrator. Options:
#   --host NAME       public DNS name of this server (its DNS record must point here)       [asked if missing]
#   --lan CIDR        your LAN subnet, the only place SSH is allowed from                      [asked if missing]
#   --version X.Y.Z   install this release instead of the newest
#   --repo OWNER/REPO install from another repository (your fork); it also becomes where updates come from
#   --admins / --domains   optional defaults for the installer (normally set on the web page after setup)
set -euo pipefail

REPO="astukestarr/tikmanager"
VER=""
HOST=""
LAN=""
PASS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --lan) LAN="$2"; shift 2 ;;
    --version) VER="${2#v}"; shift 2 ;;
    --repo) REPO="$2"; PASS+=(--repo "$2"); shift 2 ;;
    --admins|--domains) PASS+=("$1" "$2"); shift 2 ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unknown option $1 (see --help)"; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "Run with sudo:  sudo bash get.sh ..."; exit 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "--repo must look like owner/repository"; exit 1; }
if [[ -f /etc/os-release ]]; then . /etc/os-release; fi
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "Warning: TikManager is made for Ubuntu (26.04 LTS); this looks like ${PRETTY_NAME:-an unknown system}."
fi
if [[ -f /opt/tikmanager/version.py ]]; then
  CUR=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' /opt/tikmanager/version.py)
  echo "TikManager $CUR is already installed here."
  echo "To upgrade: Admin > Settings > Upgrade now, or  sudo bash /opt/tikmanager/deploy/self-update.sh"
  exit 1
fi
for tool in curl tar python3; do
  command -v "$tool" >/dev/null || { echo "Installing $tool"; DEBIAN_FRONTEND=noninteractive apt-get update -q && apt-get install -yq "$tool"; }
done

# questions go to the terminal even when this script itself arrives through a pipe
ask() {   # prompt, default -> answer
  local a=""
  if [[ -r /dev/tty ]]; then read -r -p "$1${2:+ [$2]}: " a < /dev/tty || true; fi
  echo "${a:-$2}"
}
if [[ -z "$HOST" ]]; then
  echo "TikManager needs a public DNS name pointing at this server (ports 443/tcp and 51820/udp forwarded to it)."
  HOST=$(ask "Public name, e.g. tikmanager.example.com" "")
fi
[[ "$HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] \
  || { echo "\"$HOST\" isn't a DNS name like tikmanager.example.com - run again with --host."; exit 1; }
if [[ -z "$LAN" ]]; then
  # suggest the subnet of the interface that has the default route
  DEV=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
  GUESS=$(ip -o -4 addr show dev "${DEV:-lo}" 2>/dev/null | awk '{print $4; exit}' \
          | python3 -c 'import ipaddress,sys; s=sys.stdin.read().strip(); print(ipaddress.ip_interface(s).network if s else "")' 2>/dev/null || true)
  echo "SSH to this server will only be allowed from your LAN."
  LAN=$(ask "LAN subnet" "$GUESS")
fi
python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$LAN" 2>/dev/null \
  || { echo "\"$LAN\" isn't a subnet like 192.168.1.0/24 - run again with --lan."; exit 1; }

UA="User-Agent: TikManager-installer"
if [[ -z "$VER" ]]; then   # newest GitHub Release, else the highest vX.Y.Z tag
  VER=$(curl -fsSL -H "$UA" "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tag_name","").lstrip("v"))' 2>/dev/null || true)
  if [[ -z "$VER" ]]; then
    VER=$(curl -fsSL -H "$UA" "https://api.github.com/repos/$REPO/tags?per_page=100" \
          | python3 -c 'import json,re,sys; t=[x["name"].lstrip("v") for x in json.load(sys.stdin) if re.fullmatch(r"v?\d+\.\d+\.\d+", x["name"])]; print(max(t, key=lambda v: tuple(map(int, v.split(".")))) if t else "")')
  fi
fi
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Couldn't find a release to install in github.com/$REPO."; exit 1; }

echo "== Downloading TikManager $VER from github.com/$REPO"
WORK=$(mktemp -d /tmp/tikmanager-install.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
curl -fsSL -H "$UA" -o "$WORK/release.tar.gz" "https://github.com/$REPO/archive/refs/tags/v$VER.tar.gz" \
  || { echo "Couldn't download v$VER (does that version exist?)"; exit 1; }
tar -xzf "$WORK/release.tar.gz" -C "$WORK" --no-same-owner
SRC=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -1)
[[ -f "$SRC/server.py" && -f "$SRC/deploy/install.sh" ]] || { echo "The download doesn't look like TikManager."; exit 1; }
grep -q "__version__ = \"$VER\"" "$SRC/version.py" || { echo "The download's version.py isn't $VER - not installing."; exit 1; }

echo "== Installing"
bash "$SRC/deploy/install.sh" --host "$HOST" --lan "$LAN" "${PASS[@]}"
