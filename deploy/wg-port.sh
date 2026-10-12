#!/usr/bin/env bash
# Check / move TikManager's WireGuard (wg0) port, or close the old one - run as root by tikmanager-wgport.service when an
# administrator changes it on Admin > Settings > WireGuard port (wgport.py).
# From the web app it reads one line: "check|set|close <port> <id>" - nothing else. Results go to
# /var/lib/tikmanager-update/wgport.json (root-owned, readable by the service), tagged with <id> so the app knows which
# request they answer. "check" and "set" refuse a port something else is listening on (e.g. Caddy's HTTP/3 on UDP 443);
# a failed "set" leaves wg0 where it was. It never closes the port wg0 is using.
set -euo pipefail
REQ=/var/lib/tikmanager/wg-port-request
STATE=/var/lib/tikmanager-update
CONF=/etc/wireguard/wg0.conf
install -d -m 0750 -o root -g tikmanager "$STATE"
ID=""

status() {   # state, detail
  local tmp
  tmp=$(mktemp "$STATE/.wgport.XXXXXX")
  printf '{"state": "%s", "detail": "%s", "id": "%s", "port": "%s", "at": %s}\n' "$1" "${2//\"/\'}" "$ID" "${PORT:-}" "$(date +%s)" > "$tmp"
  chown root:tikmanager "$tmp" && chmod 0640 "$tmp" && mv -f "$tmp" "$STATE/wgport.json"
}

[[ -f "$REQ" && ! -L "$REQ" ]] || exit 0
read -r ACTION PORT ID < <(head -c 80 -- "$REQ" | tr -dc 'a-z0-9 \n' | head -1) || true
rm -f -- "$REQ"
ID=${ID:0:32}
if ! [[ "${PORT:-}" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 )); then
  status failed "Not a port: ${PORT:-}"; exit 1
fi
CUR=$(sed -n -E 's/^ListenPort *= *([0-9]+).*/\1/p' "$CONF" | head -1)

in_use() {   # who else is listening on UDP $PORT (wg0 itself doesn't show a process)
  ss -Hulpn "sport = :$PORT" 2>/dev/null | grep -o 'users:(("[^"]*"' | sed 's/users:(("//' | sort -u | tr '\n' ' '
}

case "$ACTION" in
  check|set)
    if [[ "$PORT" != "$CUR" ]]; then
      who=$(in_use)
      if [[ -n "$who" ]]; then
        hint=""
        [[ "$who" == *caddy* && "$PORT" == 443 ]] && hint=" - Caddy uses it for HTTP/3; add 'protocols h1 h2' inside the 'servers' block of /etc/caddy/Caddyfile and run: sudo systemctl reload caddy"
        status failed "UDP $PORT is already used by: ${who% }$hint"; exit 1
      fi
    fi
    if [[ "$ACTION" == check ]]; then
      status ok "UDP $PORT is free"; exit 0
    fi
    if ! wg set wg0 listen-port "$PORT"; then
      status failed "WireGuard couldn't listen on UDP $PORT - nothing changed"; exit 1
    fi
    sed -i -E "s/^ListenPort *=.*/ListenPort = $PORT/" "$CONF"
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
