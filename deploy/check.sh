#!/usr/bin/env bash
# TikManager server security check - read-only: it looks, it never changes anything.
#     sudo bash /opt/tikmanager/deploy/check.sh
# Confirms what install.sh set up is still in place (firewall, SSH, updates, file permissions, service sandbox,
# open ports, certificate) and points out common weak spots. Each line is PASS, WARN (worth a look) or FAIL (fix it).
# Exit code: 0 = no FAIL, 1 = at least one FAIL.
#     --json FILE   also write the results as JSON to FILE (how tikmanager-check.service reports to Admin > Version &
#                   updates; it runs this after every upgrade, daily, and when an administrator clicks "Run check").
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo (it only reads, but some files are root-only)."; exit 1; }
OUT=""
[[ "${1:-}" == "--json" && -n "${2:-}" ]] && OUT=$2
RES=$(mktemp)
trap 'rm -f "$RES"' EXIT

ENV=/etc/tikmanager/tikmanager.env
fails=0; warns=0; SECTION=""; CHECK=""
record() { printf '%s\t%s\t%s\t%s\n' "$1" "$SECTION" "$CHECK" "${2//$'\n'/ / }" >> "$RES"; }   # CHECK = id for "How to fix"
section() { echo "== $1"; SECTION=$1; }
pass() { printf '  \e[32mPASS\e[0m  %s\n' "$1"; record pass "$1"; }
warn() { printf '  \e[33mWARN\e[0m  %s\n' "$1"; warns=$((warns + 1)); record warn "$1"; }
fail() { printf '  \e[31mFAIL\e[0m  %s\n' "$1"; fails=$((fails + 1)); record fail "$1"; }
envval() { grep -E "^$1=" "$ENV" 2>/dev/null | tail -1 | cut -d= -f2-; }

section "Firewall (ufw)"
CHECK=ufw_off; if ufw status 2>/dev/null | grep -q "Status: active"; then
  pass "ufw is on"
  CHECK=ufw_default; ufw status verbose | grep -q "deny (incoming)" && pass "incoming traffic is denied unless allowed" || fail "ufw doesn't deny incoming by default (ufw default deny incoming)"
  extra=$(ufw status | grep ALLOW | grep -v '(v6)' | grep -vE '^(80/tcp|443/tcp|51820/udp|22/tcp) |^10\.77\.0\.1 5514/udp' || true)
  CHECK=ssh_open; if ufw status | grep -E '^22(/tcp)? ' | grep -q 'Anywhere'; then fail "SSH is open to the whole internet - allow it only from your LAN (ufw allow from <lan> to any port 22 proto tcp)"; else pass "SSH is not open to the internet"; fi
  CHECK=ufw_extra; [[ -z "$extra" ]] && pass "no ports open beyond 80, 443, 51820 and SSH from the LAN" || warn "extra ufw rules - check you still need them:"$'\n'"$extra"
else
  fail "ufw is off - re-run install.sh or: ufw --force enable"
fi

section "SSH"
if command -v sshd >/dev/null; then
  cfg=$(sshd -T 2>/dev/null)
  CHECK=ssh_root; [[ $(awk '/^permitrootlogin /{print $2}' <<<"$cfg") == "no" ]] && pass "root can't sign in over SSH" || warn "root may sign in over SSH (set PermitRootLogin no)"
  CHECK=ssh_password; [[ $(awk '/^passwordauthentication /{print $2}' <<<"$cfg") == "no" ]] && pass "SSH requires keys (no passwords)" || warn "SSH accepts passwords - prefer keys only (PasswordAuthentication no) once your key works"
  CHECK=fail2ban; systemctl is-active --quiet fail2ban && pass "fail2ban is blocking repeated SSH failures" || fail "fail2ban isn't running (systemctl enable --now fail2ban)"
else
  pass "no SSH server installed"
fi

section "Updates"
CHECK=auto_updates; if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null && grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
  pass "security updates install automatically"
else
  fail "automatic security updates are off (dpkg-reconfigure -plow unattended-upgrades)"
fi
pending=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst .*security' || true)
CHECK=pending_updates; [[ "$pending" -eq 0 ]] && pass "no security updates waiting" || warn "$pending security update(s) waiting (apt upgrade)"
CHECK=reboot; [[ -f /var/run/reboot-required ]] && warn "a reboot is needed to finish updates (kernel / libraries)" || pass "no reboot pending"
CHECK=os; if [[ -r /etc/os-release ]]; then . /etc/os-release; pass "running $PRETTY_NAME"; fi

section "Network"
CHECK=ip_forward; [[ $(sysctl -n net.ipv4.ip_forward) == 0 ]] && pass "IP forwarding is off (routers can't reach each other or your LAN through this server)" || fail "IP forwarding is on - routers could route through this server (sysctl net.ipv4.ip_forward=0)"
gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
lan=$(ufw status 2>/dev/null | awk '/^22\/tcp/ && $3 !~ /Anywhere/ {print $3; exit}')
if [[ -n "$lan" ]]; then
  hit=""
  for ip in $(python3 - "$lan" "$gw" <<'PY'
import ipaddress, sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
hosts = [h for h in list(net.hosts())[:3]]
print(" ".join(sorted({str(h) for h in hosts} - {sys.argv[2]})))
PY
); do
    for port in 22 80 443 445 3389; do
      timeout 1 bash -c "</dev/tcp/$ip/$port" 2>/dev/null && hit="$hit $ip:$port"
    done
  done
  CHECK=lan_reach; [[ -z "$hit" ]] && pass "this server can't open connections into the LAN ($lan) - spot check" \
    || warn "this server can reach devices on your LAN ($lan):$hit - block it on your network firewall so a compromised server can't reach the LAN"
fi
listen=$(ss -Htulpn 2>/dev/null | awk '{print $1, $5, $7}')
bad=$(awk '$2 !~ /^(127\.0\.0\.1|\[::1\]|10\.77\.0\.1):/ && $2 !~ /:(22|80|443|51820)$/' <<<"$listen" | grep -v 'systemd-resolve\|chronyd\|dhclient\|systemd-network' || true)
CHECK=listening; [[ -z "$bad" ]] && pass "only the expected services listen on the network" || warn "also listening (check you expect these):"$'\n'"$bad"
appbind=$(envval TM_HOST)
CHECK=app_bind; [[ "${appbind:-127.0.0.1}" == "127.0.0.1" ]] && pass "the TikManager app only listens locally (behind Caddy)" || fail "TM_HOST is $appbind - set TM_HOST=127.0.0.1 so the app is only reachable through Caddy (HTTPS)"

section "HTTPS"
host=$(envval TM_PUBLIC_URL | sed -E 's#https?://##; s#/.*##')
CHECK=caddy; systemctl is-active --quiet caddy && pass "Caddy is running" || fail "Caddy isn't running (systemctl status caddy)"
CHECK=cert; if [[ -n "$host" ]]; then
  end=$(echo | timeout 8 openssl s_client -servername "$host" -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [[ -n "$end" ]]; then
    days=$(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
    [[ $days -gt 14 ]] && pass "certificate for $host valid for $days more days" || warn "certificate for $host expires in $days days - check Caddy's log (journalctl -u caddy)"
  else
    warn "couldn't read the certificate for $host"
  fi
fi

section "Files"
perm() {   # path, wanted mode, wanted owner:group
  [[ -e "$1" ]] || { fail "$1 is missing"; return; }
  got=$(stat -c '%a %U:%G' "$1")
  [[ "$got" == "$2 $3" ]] && pass "$1 is $2 $3" || fail "$1 is $got - should be $2 $3"
}
CHECK=perm_key; perm /etc/tikmanager/master.key 640 root:tikmanager
CHECK=perm_env; perm "$ENV" 640 root:tikmanager
CHECK=perm_wg; perm /etc/wireguard/wg0.conf 600 root:root
writable=$(find /opt/tikmanager \( -user tikmanager -o -perm -o+w -o \( -group tikmanager -perm -g+w \) \) -print -quit 2>/dev/null)
CHECK=code_writable; [[ -z "$writable" ]] && pass "the service can't change its own code (/opt/tikmanager is root-owned)" || fail "the service account can write to its code: $writable (chown -R root:root /opt/tikmanager; chmod -R go-w /opt/tikmanager)"
CHECK=data_private; [[ $(stat -c '%U' /var/lib/tikmanager 2>/dev/null) == "tikmanager" && $(( 0$(stat -c '%a' /var/lib/tikmanager) & 007 )) -eq 0 ]] \
  && pass "the data folder is private to the service" || warn "/var/lib/tikmanager should be owned by tikmanager and closed to others (chmod o-rwx)"
CHECK=login_shell; [[ $(getent passwd tikmanager | cut -d: -f7) == */nologin ]] && pass "the tikmanager account can't log in" || fail "the tikmanager account has a login shell (usermod -s /usr/sbin/nologin tikmanager)"
CHECK=admin_group; id -nG tikmanager 2>/dev/null | grep -qwE 'sudo|adm|admin|wheel' && fail "the tikmanager account is in an admin group" || pass "the tikmanager account has no admin rights"
repo=$(envval TM_UPDATE_REPO)
CHECK=update_repo; pass "updates come from github.com/${repo:-astukestarr/tikmanager} (only change TM_UPDATE_REPO to a repository you control)"

section "Service sandbox"
CHECK=service_running; if systemctl is-active --quiet tikmanager; then pass "tikmanager is running"; else fail "tikmanager isn't running (systemctl status tikmanager)"; fi
CHECK=service_user; [[ $(systemctl show tikmanager -p User --value) == "tikmanager" ]] && pass "runs as the tikmanager account, not root" || fail "the service doesn't run as the tikmanager account"
CHECK=sandbox; for kv in NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes; do
  k=${kv%%=*}; v=${kv#*=}
  [[ $(systemctl show tikmanager -p "$k" --value) == "$v" ]] && pass "$k=$v" || fail "$k isn't $v - restore /etc/systemd/system/tikmanager.service from /opt/tikmanager/deploy"
done
CHECK=caps; caps=$(systemctl show tikmanager -p CapabilityBoundingSet --value)
[[ "$caps" == "cap_net_admin" ]] && pass "only CAP_NET_ADMIN (for WireGuard peers)" || warn "the service has extra capabilities: $caps"

section "Backups of this server"
CHECK=db_copy; last=$(ls -1t /var/backups/tikmanager/*.db* 2>/dev/null | head -1)
if [[ -n "$last" ]]; then
  age=$(( ($(date +%s) - $(stat -c %Y "$last")) / 86400 ))
  [[ $age -le 30 ]] && pass "newest database copy is $age day(s) old ($last)" || warn "newest database copy is $age days old - keep a copy of /var/lib/tikmanager and /etc/tikmanager off this server"
else
  warn "no database copy in /var/backups/tikmanager yet (made before each upgrade) - also keep /etc/tikmanager/master.key somewhere safe: without it the router passwords and backups can't be decrypted"
fi

echo
echo "Done: $fails to fix, $warns to look at."
if [[ -n "$OUT" ]]; then   # for the web app: written atomically, readable by the service, never executed
  tmp=$(mktemp "$(dirname "$OUT")/.security.XXXXXX")
  python3 - "$RES" "$tmp" "$fails" "$warns" <<'PY'
import json, sys, time
rows = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    st, sec, cid, msg = (line.rstrip("\n").split("\t", 3) + ["", "", ""])[:4]
    rows.append({"status": st, "section": sec, "id": cid, "text": msg})
json.dump({"at": time.time(), "fails": int(sys.argv[3]), "warns": int(sys.argv[4]), "results": rows}, open(sys.argv[2], "w"))
PY
  chown root:tikmanager "$tmp" && chmod 0640 "$tmp" && mv -f "$tmp" "$OUT"
fi
[[ $fails -eq 0 ]]
