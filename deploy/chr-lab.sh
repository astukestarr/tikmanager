#!/usr/bin/env bash
# chr-lab.sh - run a small fleet of real MikroTik CHR routers on one Ubuntu host, no Proxmox.
#
# For a TikManager test lab: these are REAL RouterOS instances you can Winbox into and run real commands on, to sit
# alongside the free simulated routers (see deploy/CHR-TESTLAB.md). Each CHR gets a static IP on a host-local NAT
# bridge, its API (www) enabled and an admin password set - all unattended via cloud-init - so you can adopt it in
# TikManager with "Adopt -> add one by its address".
#
# Tested target: Ubuntu 24.04/26.04, root. Works WITHOUT KVM (pure QEMU emulation / TCG) - slower, so keep N small
# (2-3) on a 2-vCPU box. With /dev/kvm present it uses KVM automatically and is much faster.
#
#   sudo ./chr-lab.sh up [N]     # bring up N CHRs (default 1 - prove it first, then scale)
#   sudo ./chr-lab.sh status     # list instances, IPs, reachability
#   sudo ./chr-lab.sh console N  # attach to CHR N's serial console (Ctrl-] then 'quit' to leave)
#   sudo ./chr-lab.sh creds      # print the generated admin password
#   sudo ./chr-lab.sh down       # stop every CHR and tear down taps (bridge/NAT left in place)
#   sudo ./chr-lab.sh destroy    # down + remove disks, seeds and the bridge/NAT
#
# Override defaults with env vars, e.g.:  CHR_VER=7.16.2 RAM=256 sudo ./chr-lab.sh up 2
set -euo pipefail

CHR_VER="${CHR_VER:-7.16.2}"          # RouterOS CHR version to download (check download.mikrotik.com for current stable)
BRIDGE="${BRIDGE:-chrlab0}"
NET="${NET:-10.77.0}"                  # /24; host is $NET.1, CHRs start at $NET.11
HOST_IP="$NET.1"
BASE_OCTET="${BASE_OCTET:-11}"
RAM="${RAM:-256}"                      # MB per CHR
DATA="${DATA:-/opt/chr-lab}"
MAX_N="${MAX_N:-6}"

die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = "0" ] || die "run as root (sudo)."; }
oct() { echo $((BASE_OCTET + $1 - 1)); }          # instance i -> last octet
ip_of() { echo "$NET.$(oct "$1")"; }
mac_of() { printf '52:54:00:ab:%02x:%02x' "$NET_ID" "$1"; }   # stable per-instance MAC
NET_ID=$(( $(echo "$NET" | awk -F. '{print $3}') & 255 ))

ensure_pkgs() {
  local miss=()
  command -v qemu-system-x86_64 >/dev/null || miss+=(qemu-system-x86)
  command -v qemu-img          >/dev/null || miss+=(qemu-utils)
  command -v xorriso           >/dev/null || miss+=(xorriso)
  command -v unzip             >/dev/null || miss+=(unzip)
  command -v iptables          >/dev/null || miss+=(iptables)
  if [ "${#miss[@]}" -gt 0 ]; then
    echo ">> installing: ${miss[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${miss[@]}"
  fi
}

ensure_image() {
  mkdir -p "$DATA"
  if [ ! -f "$DATA/chr-base.qcow2" ]; then
    echo ">> downloading CHR $CHR_VER"
    curl -fsSL "https://download.mikrotik.com/routeros/$CHR_VER/chr-$CHR_VER.img.zip" -o "$DATA/chr.img.zip" \
      || die "download failed - check CHR_VER (see download.mikrotik.com/routeros)."
    (cd "$DATA" && unzip -o -q chr.img.zip && mv -f "chr-$CHR_VER.img" chr.img)
    qemu-img convert -O qcow2 "$DATA/chr.img" "$DATA/chr-base.qcow2"
    rm -f "$DATA/chr.img" "$DATA/chr.img.zip"
    echo ">> base image ready: $DATA/chr-base.qcow2"
  fi
}

ensure_net() {
  if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    echo ">> creating bridge $BRIDGE ($HOST_IP/24) with NAT to the internet"
    ip link add "$BRIDGE" type bridge
    ip addr add "$HOST_IP/24" dev "$BRIDGE"
    ip link set "$BRIDGE" up
  fi
  sysctl -wq net.ipv4.ip_forward=1
  local wan; wan=$(ip route show default | awk '{print $5; exit}')
  [ -n "$wan" ] || echo "   (no default route found - CHRs will have no internet, but TikManager can still reach them)"
  if [ -n "$wan" ]; then
    iptables -t nat -C POSTROUTING -s "$NET.0/24" -o "$wan" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s "$NET.0/24" -o "$wan" -j MASQUERADE
  fi
  iptables -C FORWARD -i "$BRIDGE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$BRIDGE" -j ACCEPT
  iptables -C FORWARD -o "$BRIDGE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$BRIDGE" -j ACCEPT
}

ensure_pw() {
  if [ ! -f "$DATA/admin_pw" ]; then
    (umask 077; head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16 > "$DATA/admin_pw")
  fi
  cat "$DATA/admin_pw"
}

lan_net() { echo "192.168.$((20 + $1))"; }                 # per-instance LAN subnet: router i -> 192.168.(20+i).0/24
lan_gw()  { echo "$(lan_net "$1").1"; }                     # CHR's LAN (ether2) address = the test client's gateway
lan_cli() { echo "$(lan_net "$1").100"; }                   # the test client's address behind router i

make_seed() {   # $1 = instance index ; builds a NoCloud cloud-init ISO with a RouterOS first-boot script
  local i="$1" ip pw dir lnet
  ip=$(ip_of "$i"); pw=$(cat "$DATA/admin_pw"); dir="$DATA/seed-$i"; lnet=$(lan_net "$i")
  mkdir -p "$dir"
  printf 'instance-id: lab-chr-%s\nlocal-hostname: lab-chr-%s\n' "$i" "$i" > "$dir/meta-data"
  cat > "$dir/user-data" <<RSC
# RouterOS first-boot config (applied by CHR cloud-init)
# --- WAN (ether1): reaches TikManager + the internet via the host NAT bridge ---
/ip address add address=$ip/24 interface=ether1
/ip route add dst-address=0.0.0.0/0 gateway=$HOST_IP
/ip dns set servers=$HOST_IP allow-remote-requests=no
# --- LAN (ether2): the segment the test client sits on, one unique /24 per router (so VPN routes don't collide) ---
/ip address add address=$lnet.1/24 interface=ether2
/ip pool add name=lan ranges=$lnet.150-$lnet.200
/ip dhcp-server add name=lan interface=ether2 address-pool=lan disabled=no lease-time=1h
/ip dhcp-server network add address=$lnet.0/24 gateway=$lnet.1 dns-server=$lnet.1
/ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade comment=lab
# --- management ---
/ip service enable www
/ip service set www port=80
/ip service enable winbox
/user set admin password=$pw
/system identity set name=lab-chr-$i
RSC
  xorriso -as mkisofs -quiet -output "$DATA/seed-$i.iso" -volid CIDATA -joliet -rock "$dir/meta-data" "$dir/user-data"
}

ensure_client() {   # $1 = instance index ; a lightweight netns "client" on router i's LAN (no VM - ~free)
  local i="$1" ns lnet gw cli
  ns="client$i"; lnet=$(lan_net "$i"); gw=$(lan_gw "$i"); cli=$(lan_cli "$i")
  ip netns list | grep -qw "$ns" && return 0
  ip netns add "$ns"
  ip link add "cli$i" type veth peer name "cli$i-br"      # one end into the namespace, one onto the LAN bridge
  ip link set "cli$i-br" master "lan$i"; ip link set "cli$i-br" up
  ip link set "cli$i" netns "$ns"
  ip netns exec "$ns" ip addr add "$cli/24" dev "cli$i"
  ip netns exec "$ns" ip link set "cli$i" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip route add default via "$gw"
}

running() { [ -f "$DATA/chr-$1.pid" ] && kill -0 "$(cat "$DATA/chr-$1.pid")" 2>/dev/null; }

start_one() {
  local i="$1" accel="tcg" mac disk serial
  [ -e /dev/kvm ] && accel="kvm"
  running "$i" && { echo "   CHR $i already running"; return; }
  mac=$(mac_of "$i"); disk="$DATA/chr-$i.qcow2"; serial=$((2300 + i))
  [ -f "$disk" ] || qemu-img create -q -f qcow2 -F qcow2 -b "$DATA/chr-base.qcow2" "$disk" >/dev/null
  [ -f "$DATA/seed-$i.iso" ] || make_seed "$i"
  # WAN NIC (ether1) on the shared management/NAT bridge
  ip tuntap add dev "tap-chr$i" mode tap 2>/dev/null || true
  ip link set "tap-chr$i" master "$BRIDGE"; ip link set "tap-chr$i" up
  # LAN NIC (ether2) on this router's own bridge, where its test client lives
  ip link show "lan$i" >/dev/null 2>&1 || ip link add "lan$i" type bridge
  ip link set "lan$i" up
  ip tuntap add dev "tap-lan$i" mode tap 2>/dev/null || true
  ip link set "tap-lan$i" master "lan$i"; ip link set "tap-lan$i" up
  echo ">> starting CHR $i (WAN $(ip_of "$i"), LAN $(lan_gw "$i")/24, accel=$accel, console telnet 127.0.0.1:$serial)"
  qemu-system-x86_64 -name "lab-chr-$i" -machine pc -accel "$accel" -cpu qemu64 -smp 1 -m "$RAM" \
    -drive file="$disk",if=virtio,format=qcow2 \
    -drive file="$DATA/seed-$i.iso",media=cdrom \
    -netdev tap,id=wan,ifname="tap-chr$i",script=no,downscript=no \
    -device virtio-net-pci,netdev=wan,mac="$mac" \
    -netdev tap,id=lan,ifname="tap-lan$i",script=no,downscript=no \
    -device virtio-net-pci,netdev=lan,mac="$(printf '52:54:00:cd:%02x:%02x' "$NET_ID" "$i")" \
    -serial telnet:127.0.0.1:$serial,server,nowait \
    -display none -daemonize -pidfile "$DATA/chr-$i.pid"
  ensure_client "$i"
}

cmd_up() {
  local n="${1:-1}"
  [ "$n" -ge 1 ] && [ "$n" -le "$MAX_N" ] || die "N must be 1..$MAX_N"
  need_root; ensure_pkgs; ensure_image; ensure_net; ensure_pw >/dev/null
  [ -e /dev/kvm ] || echo "!! No KVM on this host - using QEMU emulation (TCG). Boots take a few minutes and use real"
  [ -e /dev/kvm ] || echo "   CPU; keep N small (2-3) on a 2-vCPU box. The simulated routers cover breadth for free."
  for i in $(seq 1 "$n"); do start_one "$i"; done
  echo
  echo "CHRs are booting (cloud-init applies the config on first boot - allow 2-5 min under emulation)."
  cmd_status || true
  cat <<NOTE

Adopt them in TikManager:
  1. Admin -> Settings: set the controller's overlay IP to $HOST_IP (this host, on the lab bridge).
     (If TikManager runs on a DIFFERENT box, add a route to $NET.0/24 via this server, $(hostname -I | awk '{print $1}').)
  2. Adopt routers -> "...or add one by its address": enter each WAN/MGMT IP above,
     username 'admin', password: $(ensure_pw)
  3. Open Winbox on the adopted router - it relays to the real :8291 and the GUI loads.

Each router has a test client behind it (a host on its LAN), for testing an endpoint on each side:
  - Router i LAN = 192.168.(20+i).0/24  (router 1 -> 192.168.21.0/24, router 2 -> .22, ...) - each its own /24.
  - The client is the .100 on that LAN. Drive it with:   sudo $0 client <i> ping|curl|serve|exec ...
  - Example (after you build a site-to-site VPN between two CHRs in TikManager and route their LANs):
      sudo $0 client 1 serve 80 &                 # test endpoint behind router 1
      sudo $0 client 2 curl -s http://$(lan_cli 1)/    # reach it from behind router 2, across the tunnel

NOTE
}

cmd_status() {
  printf "%-10s %-14s %-9s %-16s %-10s\n" INSTANCE "WAN/MGMT" RUNNING "LAN (client gw)" CLIENT
  for i in $(seq 1 "$MAX_N"); do
    [ -f "$DATA/chr-$i.pid" ] || continue
    local r; r=no; running "$i" && r=yes
    local c=-; ip netns list 2>/dev/null | grep -qw "client$i" && c=$(lan_cli "$i")
    printf "%-10s %-14s %-9s %-16s %-10s\n" "lab-chr-$i" "$(ip_of "$i")" "$r" "$(lan_gw "$i")/24" "$c"
  done
}

# Run a command as the test client behind router N, e.g.:
#   client 1 ping 192.168.22.100          (reach router 2's client - works once a VPN links them)
#   client 2 curl -s http://192.168.21.100/
#   client 1 serve [port]                 (start a test HTTP endpoint on the client, default port 80)
#   client 1 exec -- ip addr              (any command inside the namespace)
cmd_client() {
  local i="${1:?usage: client N <ping|curl|serve|exec|ip> ...}"; shift
  local ns="client$i"
  ip netns list | grep -qw "$ns" || die "no client for router $i (is it up?)"
  case "${1:-ip}" in
    ping)  shift; ip netns exec "$ns" ping -c3 "$@";;
    curl)  shift; ip netns exec "$ns" curl "$@";;
    ip)    ip netns exec "$ns" ip -brief addr;;
    serve) local port="${2:-80}"; echo "serving on $(lan_cli "$i"):$port (Ctrl-C to stop)"; ip netns exec "$ns" python3 -m http.server "$port" --bind "$(lan_cli "$i")";;
    exec)  shift; [ "${1:-}" = "--" ] && shift; ip netns exec "$ns" "$@";;
    *)     ip netns exec "$ns" "$@";;
  esac
}

cmd_console() { local i="${1:?usage: console N}"; echo "Serial console for CHR $i (Ctrl-] then 'quit' to leave):"; exec telnet 127.0.0.1 $((2300 + i)); }
cmd_creds()   { echo "admin password: $(ensure_pw)"; }

cmd_down() {
  need_root
  for i in $(seq 1 "$MAX_N"); do
    if running "$i"; then kill "$(cat "$DATA/chr-$i.pid")" 2>/dev/null || true; fi
    rm -f "$DATA/chr-$i.pid"
    ip link del "tap-chr$i" 2>/dev/null || true
    ip link del "tap-lan$i" 2>/dev/null || true
    ip netns del "client$i" 2>/dev/null || true     # removes the namespace and its veth
    ip link del "lan$i" 2>/dev/null || true
  done
  echo ">> all CHRs and test clients stopped."
}

cmd_destroy() {
  cmd_down
  need_root
  local wan; wan=$(ip route show default | awk '{print $5; exit}')
  [ -n "$wan" ] && iptables -t nat -D POSTROUTING -s "$NET.0/24" -o "$wan" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "$BRIDGE" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -o "$BRIDGE" -j ACCEPT 2>/dev/null || true
  ip link del "$BRIDGE" 2>/dev/null || true
  rm -f "$DATA"/chr-*.qcow2 "$DATA"/seed-*.iso; rm -rf "$DATA"/seed-*
  echo ">> lab destroyed (kept $DATA/chr-base.qcow2 and $DATA/admin_pw; delete $DATA to remove those too)."
}

case "${1:-}" in
  up)      shift; cmd_up "$@";;
  status)  cmd_status;;
  client)  shift; need_root; cmd_client "$@";;
  console) shift; cmd_console "$@";;
  creds)   cmd_creds;;
  down)    cmd_down;;
  destroy) cmd_destroy;;
  *) echo "usage: $0 {up [N]|status|client N <ping|curl|serve|exec> ...|console N|creds|down|destroy}"; exit 1;;
esac
