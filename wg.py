"""WireGuard peers on the controller's wg0. Each adopted router is one peer with a single /32 tunnel address.

The service runs as an unprivileged user with only CAP_NET_ADMIN (granted by its systemd unit), which is what `wg set`
needs; it can't do anything else as root. Peers live in the database and are re-applied at startup, so wg0's own config
file only holds the controller's interface and private key.
In dev mode nothing is changed on the machine.
"""
import ipaddress
import re
import subprocess

KEY = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")   # a 32-byte base64 WireGuard key


def valid_key(k: str) -> bool:
    return bool(KEY.match(str(k or "")))


class WireGuard:
    def __init__(self, s):
        self.s = s
        self.net = ipaddress.ip_network(s.wg_network)

    def next_ip(self, used: set) -> str:
        server = ipaddress.ip_address(self.s.wg_server_ip)
        for host in self.net.hosts():
            if host != server and str(host) not in used:
                return str(host)
        raise RuntimeError("The WireGuard network is full.")

    def _wg(self, *args):
        if self.s.dev:
            return
        r = subprocess.run(["wg", *args], capture_output=True, text=True, timeout=15)
        if r.returncode:
            raise RuntimeError(f"wg {' '.join(args[:3])}: {r.stderr.strip()[:200]}")

    def add_peer(self, pubkey: str, ip: str):
        if not valid_key(pubkey):
            raise ValueError("Not a WireGuard public key.")
        if ipaddress.ip_address(ip) not in self.net:
            raise ValueError("Tunnel address outside the TikManager network.")
        self._wg("set", self.s.wg_interface, "peer", pubkey, "allowed-ips", f"{ip}/32", "persistent-keepalive", "0")

    def remove_peer(self, pubkey: str):
        if valid_key(pubkey):
            self._wg("set", self.s.wg_interface, "peer", pubkey, "remove")

    def sync(self, peers):
        """Re-apply every adopted router's peer (at startup)."""
        for pubkey, ip in peers:
            try:
                self.add_peer(pubkey, ip)
            except (ValueError, RuntimeError):
                pass
