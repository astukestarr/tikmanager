#!/usr/bin/env bash
# Unban an address in fail2ban, or report who's banned - run as root by tikmanager-unban.service when someone presses
# Unblock on the Security page (or the page asks for a fresh list). From the web app it reads one line:
# "unban <ip> <id>" or "list - <id>" - nothing else, and the address must look like an IPv4 / IPv6 address.
# Writes /var/lib/tikmanager-update/f2b.json (root-owned, readable by the service): the addresses banned now, in any jail,
# and the result of this request (tagged with <id> so the app knows which request it answers).
set -euo pipefail
REQ=/var/lib/tikmanager/unban-request
STATE=/var/lib/tikmanager-update
install -d -m 0750 -o root -g tikmanager "$STATE"
[[ -f "$REQ" && ! -L "$REQ" ]] || exit 0
read -r ACTION IP ID < <(head -c 120 -- "$REQ" | tr -dc 'a-zA-Z0-9.:_ \n-' | head -1) || true
rm -f -- "$REQ"
ACTION=${ACTION:-list}; IP=${IP:-}; ID=${ID:0:32}
RESULT="ok"; DETAIL=""
if [[ "$ACTION" == "unban" ]]; then
  if [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$IP" =~ ^[0-9a-fA-F:]{2,39}$ ]]; then
    if out=$(fail2ban-client unban "$IP" 2>&1); then DETAIL="unbanned"; else RESULT="failed"; DETAIL="$out"; fi
  else
    RESULT="failed"; DETAIL="not an IP address"
  fi
elif [[ "$ACTION" != "list" ]]; then
  RESULT="failed"; DETAIL="unknown request"
fi
BANNED=""
jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' ') || jails=""
for j in $jails; do
  [[ "$j" =~ ^[A-Za-z0-9_.-]+$ ]] || continue
  for a in $(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p'); do
    [[ "$a" =~ ^[0-9a-fA-F.:]+$ ]] && BANNED+="{\"ip\": \"$a\", \"jail\": \"$j\"},"
  done
done
DETAIL=$(printf '%s' "$DETAIL" | tr -d '\n\r\\"' | head -c 200)
[[ "$IP" =~ ^[0-9a-fA-F.:]*$ ]] || IP=""
[[ "$ACTION" =~ ^[a-z]+$ ]] || ACTION="?"
tmp=$(mktemp "$STATE/.f2b.XXXXXX")
printf '{"banned": [%s], "last": {"action": "%s", "ip": "%s", "id": "%s", "state": "%s", "detail": "%s"}, "at": %s}\n' \
  "${BANNED%,}" "$ACTION" "$IP" "$ID" "$RESULT" "$DETAIL" "$(date +%s)" > "$tmp"
chown root:tikmanager "$tmp" && chmod 0640 "$tmp" && mv -f "$tmp" "$STATE/f2b.json"
