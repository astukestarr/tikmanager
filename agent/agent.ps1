<#
  TikManager network collector - agent.
  Runs on a schedule (installed by install-collector.ps1). Sweeps the local network with ping + ARP + reverse-DNS and
  reports the live hosts to TikManager, which folds them into IPAM under the client this collector's key belongs to.
  v1: discovery sweep only (no SNMP). Windows PowerShell 5.1+ - no modules required.
#>
$ErrorActionPreference = "Stop"
$Base = "C:\ProgramData\TikManagerCollector"
$AgentVersion = "1.0.0"

function Log($m) { try { Add-Content -Path (Join-Path $Base "collector.log") -Value ("{0}  {1}" -f (Get-Date -Format s), $m) } catch {} }

try { $cfg = Get-Content (Join-Path $Base "config.json") -Raw | ConvertFrom-Json } catch { Log "no config.json: $_"; exit 1 }
$server  = ([string]$cfg.server).TrimEnd("/")
$headers = @{ Authorization = "Bearer $($cfg.key)"; "X-Agent-Version" = $AgentVersion }

# 1) scan ranges from TikManager; empty -> the box's own IPv4 subnets (nothing bigger than /22 auto-swept)
$ranges = @()
try {
  $rc = Invoke-RestMethod -Uri "$server/api/collector/config" -Headers $headers -TimeoutSec 30
  if ($rc.ranges) { $ranges = @($rc.ranges) }
} catch { Log "config fetch failed: $_" }
if (-not $ranges -or $ranges.Count -eq 0) {
  foreach ($a in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    if ($a.IPAddress -like "169.254.*" -or $a.IPAddress -eq "127.0.0.1" -or $a.PrefixLength -lt 22) { continue }
    $net = ($a.IPAddress -split "\.")[0..2] -join "."
    $ranges += "$net.0/24"
  }
  $ranges = @($ranges | Select-Object -Unique)
}
if ($ranges.Count -eq 0) { Log "no ranges to scan"; exit 0 }

# expand a CIDR to host IPs (capped), using BitConverter so there's no hand-rolled bit math to get wrong
function Expand-Cidr($cidr) {
  $p = $cidr -split "/"; if ($p.Count -ne 2) { return @() }
  $pfx = [int]$p[1]; if ($pfx -lt 22 -or $pfx -gt 32) { return @() }
  try { $ipObj = [System.Net.IPAddress]::Parse($p[0]) } catch { return @() }
  $b = $ipObj.GetAddressBytes(); [array]::Reverse($b)
  $start = [System.BitConverter]::ToUInt32($b, 0)
  $size  = [uint32][math]::Pow(2, 32 - $pfx)
  $net   = $start -band ([uint32]::MaxValue - ($size - 1))
  $out = New-Object System.Collections.Generic.List[string]
  for ($i = 1; $i -lt ($size - 1); $i++) {
    $cur = [uint32]($net + $i)
    $cb = [System.BitConverter]::GetBytes($cur); [array]::Reverse($cb)
    $out.Add(([System.Net.IPAddress]($cb)).ToString())
    if ($out.Count -ge 1024) { break }
  }
  return $out
}

# 2) async ping sweep
$alive = New-Object System.Collections.Generic.HashSet[string]
foreach ($cidr in $ranges) {
  $pending = @()
  foreach ($ip in (Expand-Cidr $cidr)) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $pending += [pscustomobject]@{ ip = $ip; task = $ping.SendPingAsync($ip, 800) }
  }
  foreach ($pr in $pending) {
    try { if ($pr.task.Result.Status -eq "Success") { [void]$alive.Add($pr.ip) } } catch {}
  }
}

# 3) ARP table -> IP to MAC (also catches hosts that don't answer ping)
$macOf = @{}
try {
  foreach ($line in (arp -a)) {
    if ($line -match "(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+dynamic") {
      $ip = $matches[1]; $macOf[$ip] = ($matches[2] -replace "-", ":").ToUpper(); [void]$alive.Add($ip)
    }
  }
} catch { Log "arp failed: $_" }

# 4) reverse DNS (best-effort, capped)
$hosts = @(); $n = 0
foreach ($ip in $alive) {
  $name = $null
  if ($n -lt 512) { try { $name = (Resolve-DnsName -Name $ip -Type PTR -QuickTimeout -ErrorAction Stop)[0].NameHost } catch {} }
  $n++
  $hosts += [pscustomobject]@{ ip = $ip; mac = $macOf[$ip]; hostname = $name; up = $true }
}

# 5) report to TikManager
$body = @{ agent_version = $AgentVersion; subnets = $ranges; hosts = $hosts } | ConvertTo-Json -Depth 5 -Compress
try {
  $r = Invoke-RestMethod -Uri "$server/api/collector/report" -Method Post -Headers $headers -Body $body -ContentType "application/json" -TimeoutSec 90
  Log ("reported {0} hosts across {1} subnet(s) -> +{2} subnets, +{3} addresses" -f $hosts.Count, $ranges.Count, $r.subnets_added, $r.addresses_added)
} catch { Log "report failed: $_" }
