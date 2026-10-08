"""The RouterOS v7 scripts a router runs to join TikManager.

Stage 1 is the same for every router (one adoption command for the whole MSP): it creates the router's WireGuard
interface - the private key never leaves the router - and registers the router's public key, identity, model and
serial. The controller answers with stage 2, made for that router: tunnel address, controller peer, a 'tikmanager'
user that may only log in from the controller, HTTP management for the controller only, and log forwarding.
The router then waits for a technician to approve it; until then the controller has no peer for it, so its tunnel
can't come up and nothing is polled.
"""
import re
from datetime import datetime


def _q(s: str) -> str:
    """Quote a value for a RouterOS script string."""
    return '"' + re.sub(r'(["\\$])', r"\\\1", str(s)) + '"'


def command(s, token: str) -> str:
    url = f"{s.public_url}/adopt/{token}"
    return f'/tool fetch url="{url}" dst-path=tikmanager.rsc; /import tikmanager.rsc; /file remove tikmanager.rsc'


def stage1(s, token: str) -> str:
    reg = f"{s.public_url}/adopt/{token}/register"
    return f"""# TikManager - adopt this router (RouterOS 7). Generated {datetime.now():%Y-%m-%d %H:%M}.
# Registers the router; a technician then approves it and picks the client.
{{
:if ([:pick [/system resource get version] 0 1] < "7") do={{ :error "TikManager needs RouterOS v7 or newer" }}
:local tm "tikmanager"
:if ([:len [/interface wireguard find name=$tm]] = 0) do={{
  :local port 53231
  :while ([:len [/interface wireguard find where listen-port=$port]] > 0) do={{ :set port ($port + 1) }}
  /interface wireguard add name=$tm listen-port=$port comment="TikManager"
}}
:local www [/ip service get www port]
:local pk [/interface wireguard get [find name=$tm] public-key]
:local serial ""
:do {{ :set serial [/system routerboard get serial-number] }} on-error={{}}
:local model [/system resource get board-name]
:local ident [/system identity get name]
/tool fetch url={_q(reg)} http-method=post http-header-field="Content-Type: application/x-www-form-urlencoded" http-data=("pubkey=" . $pk . "&serial=" . $serial . "&model=" . $model . "&version=" . [/system resource get version] . "&identity=" . $ident . "&www=" . $www) dst-path=tikmanager2.rsc
:delay 1s
/import tikmanager2.rsc
/file remove tikmanager2.rsc
}}
"""


def stage2(s, device: dict, api_password: str) -> str:
    host, _, port = s.wg_endpoint.rpartition(":")
    srv, ip = s.wg_server_ip, device["tunnel_ip"]
    return f"""# TikManager - settings for this router (tunnel {ip}). Safe to run again.
{{
:local tm "tikmanager"
:local tmport [/interface wireguard get [find name=$tm] listen-port]
:if ([:len [/interface wireguard find where listen-port=$tmport and name!=$tm]] > 0) do={{
  :local p 53231
  :while ([:len [/interface wireguard find where listen-port=$p]] > 0) do={{ :set p ($p + 1) }}
  /interface wireguard set [find name=$tm] listen-port=$p
}}
# RouterOS disables an interface whose port was taken (comment "Listen port already used") - switch it back on
/interface wireguard set [find name=$tm] disabled=no comment="TikManager"
/interface wireguard peers remove [find interface=$tm]
/interface wireguard peers add interface=$tm public-key={_q(s.wg_server_pubkey)} endpoint-address={_q(host)} endpoint-port={int(port or 51820)} allowed-address={srv}/32 persistent-keepalive=25s comment="TikManager controller"
/ip address remove [find interface=$tm]
/ip address add address={ip}/32 network={srv} interface=$tm comment="TikManager"
:if ([:len [/ip firewall filter find comment="TikManager"]] = 0) do={{
  :if ([:len [/ip firewall filter find]] > 0) do={{
    /ip firewall filter add chain=input in-interface=$tm src-address={srv} action=accept comment="TikManager" place-before=0
  }} else={{ /ip firewall filter add chain=input in-interface=$tm src-address={srv} action=accept comment="TikManager" }}
}}
:if ([:len [/user group find name=$tm]] = 0) do={{ /user group add name=$tm policy=read,write,policy,test,api,rest-api,sensitive,reboot comment="TikManager" }}
/user remove [find name=$tm]
/user add name=$tm group=$tm password={_q(api_password)} address={srv}/32 comment="TikManager - do not remove"
# HTTP management for the controller. RouterOS 7.2x renamed the service's "address" to "available-from" - handle both.
:local www [/ip service get www disabled]
:local prop "available-from"
:local addr ""
:do {{ :set addr [/ip service get www available-from] }} on-error={{ :set prop "address"; :set addr [/ip service get www address] }}
:local want ""
:if ($www = true) do={{ /ip service set www disabled=no; :set want "{srv}/32" }} else={{
  :if ([:len $addr] > 0 && [:typeof [:find [:tostr $addr] "{srv}/"]] = "nil") do={{
    :foreach a in=$addr do={{ :set want ($want . $a . ",") }}
    :set want ($want . "{srv}/32")
  }}
}}
:if ([:len $want] > 0) do={{
  :if ($prop = "address") do={{ /ip service set www address=$want }} else={{ /ip service set www available-from=$want }}
}}
/system logging remove [find action=$tm]
/system logging action remove [find name=$tm]
/system logging action add name=$tm target=remote remote={srv} remote-port={s.syslog_port} src-address={ip}
/system logging add topics=info action=$tm
/system logging add topics=warning action=$tm
/system logging add topics=error action=$tm
/system logging add topics=critical action=$tm
:put "TikManager: registered. A technician will approve this router; it shows online within a minute after that."
}}
"""
