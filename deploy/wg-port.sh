#!/usr/bin/env bash
# Move TikManager's WireGuard (wg0) to another UDP port, or close the old one - run as root by tikmanager-wgport.service
# when an administrator changes it on Admin > Settings > WireGuard port (wgport.py).
# From the web app it reads one line: "set <port>" or "close <port>" - nothing else. Results go to
# /var/lib/tikmanager-update/wgport.json (root-owned, readable by the service). It never closes the port wg0 is using.
set -euo pipefail
REQ=/var/lib/tikmanager/wg-port-request
STATE=/var/lib/tikmanager-update
CONF=/etc/wireguard/wg0.conf
install -d -m 0750 -o root -g tikmanager "$STATE"

status() {   # state, detail
  local tmp
  tmp=$(mktemp "$STATE/.wgport.XXXXXX")
  printf '{"state": "%s", "detail": "%s", "at": %s}\n' "$1" "${2//\"/\'}" "$(date +%s)" > "$tmp"
  chown root:tikmanager "$tmp" && chmod 0640 "$tmp" && mv -f "$tmp" "$STATE/wgport.json"
}

[[ -f "$REQ" && ! -L "$REQ" ]] || exit 0
LINE=$(head -c 40 -- "$REQ" | tr -dc 'a-z0-9 ')
rm -f -- "$REQ"
ACTION=${LINE%% *}
PORT=${LINE##* }
if ! [[ "$PORT" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 )); then
  status failed "Not a port: $PORT"; exit 1
fi
CUR=$(sed -n -E 's/^ListenPort *= *([0-9]+).*/\1/p' "$CONF" | head -1)

case "$ACTION" in
  set)
    sed -i -E "s/^ListenPort *=.*/ListenPort = $PORT/" "$CONF"
    wg set wg0 listen-port "$PORT"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
      ufw allow "$PORT/udp" comment 'WireGuard from routers' >/dev/null
    fi
    status done "WireGuard now listens on UDP $PORT (was $CUR)"
    ;;
  close)
    if [[ "$PORT" == "$CUR" ]]; then
      status failed "UDP $PORT is the port WireGuard uses now - not closing it"; exit 1
    fi
    ufw delete allow "$PORT/udp" >/dev/null 2>&1 || true
    status done "Closed the old WireGuard port UDP $PORT"
    ;;
  *)
    status failed "Unknown request"; exit 1
    ;;
esac
