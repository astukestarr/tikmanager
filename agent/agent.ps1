<#
  TikManager network collector - agent.
  Runs on a schedule (installed by install-collector.ps1). Sweeps the local network with ping + ARP + reverse-DNS, and
  (optionally) SNMP v2c for device names, ARP tables and VLANs, then reports to TikManager -> IPAM under the client this
  collector's key belongs to. Windows PowerShell 5.1+ - no modules required.

  SNMP self-test:  powershell -File agent.ps1 -SelfTest   (checks the BER encode/decode round-trips; no network)
#>
param([switch]$SelfTest)
$ErrorActionPreference = "Stop"
$Base = "C:\ProgramData\TikManagerCollector"
$AgentVersion = "1.1.0"

function Log($m) { try { Add-Content -Path (Join-Path $Base "collector.log") -Value ("{0}  {1}" -f (Get-Date -Format s), $m) } catch {} }

# ===== SNMP v2c over raw UDP (hand-rolled BER - no modules) ==========================================================
function Enc-Len([int]$n) {
  if ($n -lt 0x80) { return , [byte]$n }
  $b = @(); $x = $n
  while ($x -gt 0) { $b = , ([byte]($x -band 0xFF)) + $b; $x = [math]::Floor($x / 256) }
  return @([byte](0x80 -bor $b.Count)) + $b
}
function Enc-TLV([byte]$tag, [byte[]]$val) { return @([byte]$tag) + (Enc-Len $val.Count) + $val }
function Enc-Int([int]$v) {
  $b = @(); $x = $v
  if ($x -eq 0) { $b = @([byte]0) }
  else { while ($x -gt 0) { $b = , ([byte]($x -band 0xFF)) + $b; $x = [math]::Floor($x / 256) }; if ($b[0] -ge 0x80) { $b = @([byte]0) + $b } }
  return Enc-TLV 0x02 ([byte[]]$b)
}
function Enc-OID([string]$oid) {
  $p = @($oid.TrimStart('.').Split('.') | ForEach-Object { [int]$_ })
  $b = @([byte](40 * $p[0] + $p[1]))
  for ($i = 2; $i -lt $p.Count; $i++) {
    $v = $p[$i]
    if ($v -lt 0x80) { $b += [byte]$v }
    else {
      $s = @([byte]($v -band 0x7F)); $v = [math]::Floor($v / 128)
      while ($v -gt 0) { $s = @([byte](($v -band 0x7F) -bor 0x80)) + $s; $v = [math]::Floor($v / 128) }
      $b += $s
    }
  }
  return Enc-TLV 0x06 ([byte[]]$b)
}
function Enc-Str([string]$s) { return Enc-TLV 0x04 ([System.Text.Encoding]::ASCII.GetBytes($s)) }
function New-SnmpPdu([byte]$pduTag, [string]$community, [string]$oid, [int]$reqid) {
  $vb = Enc-TLV 0x30 ((Enc-OID $oid) + @([byte]0x05, [byte]0x00))   # OID + NULL
  $vblist = Enc-TLV 0x30 $vb
  $pdu = Enc-TLV $pduTag ((Enc-Int $reqid) + (Enc-Int 0) + (Enc-Int 0) + $vblist)
  return Enc-TLV 0x30 ((Enc-Int 1) + (Enc-Str $community) + $pdu)   # version 1 = SNMPv2c
}
function Read-TLV([byte[]]$b, [ref]$i) {
  $tag = $b[$i.Value]; $i.Value++
  $len = $b[$i.Value]; $i.Value++
  if ($len -band 0x80) { $n = $len -band 0x7F; $len = 0; for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + $b[$i.Value]; $i.Value++ } }
  $r = [pscustomobject]@{ tag = $tag; start = $i.Value; len = $len }
  $i.Value += $len
  return $r
}
function Decode-OID([byte[]]$b, [int]$start, [int]$len) {
  $p = @(); $i = $start; $end = $start + $len
  $first = $b[$i]; $i++
  $p += [int]([math]::Floor($first / 40)); $p += [int]($first % 40)
  while ($i -lt $end) {
    $v = 0
    while ($true) { $v = ($v * 128) + ($b[$i] -band 0x7F); $more = $b[$i] -band 0x80; $i++; if (-not $more) { break } }
    $p += $v
  }
  return ($p -join '.')
}
function Snmp-Query([string]$ip, [string]$community, [byte]$pduTag, [string]$oid, [int]$timeoutMs = 900) {
  $req = New-SnmpPdu $pduTag $community $oid (Get-Random -Minimum 1 -Maximum 2147483000)
  $udp = New-Object System.Net.Sockets.UdpClient
  try {
    $udp.Client.ReceiveTimeout = $timeoutMs
    $udp.Connect($ip, 161)
    [void]$udp.Send([byte[]]$req, $req.Length)
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $resp = $udp.Receive([ref]$ep)
  } catch { return $null } finally { $udp.Close() }
  if (-not $resp) { return $null }
  try {
    $i = 0; $msg = Read-TLV $resp ([ref]$i); $i = $msg.start   # into the message SEQUENCE
    $ver = Read-TLV $resp ([ref]$i); $i = $ver.start + $ver.len
    $com = Read-TLV $resp ([ref]$i); $i = $com.start + $com.len
    $pdu = Read-TLV $resp ([ref]$i); $i = $pdu.start
    $rid = Read-TLV $resp ([ref]$i); $i = $rid.start + $rid.len
    $err = Read-TLV $resp ([ref]$i); $i = $err.start + $err.len
    $idx = Read-TLV $resp ([ref]$i); $i = $idx.start + $idx.len
    $vbl = Read-TLV $resp ([ref]$i); $i = $vbl.start
    $vb = Read-TLV $resp ([ref]$i); $j = $vb.start
    $oidT = Read-TLV $resp ([ref]$j)
    $valT = Read-TLV $resp ([ref]$j)
    return [pscustomobject]@{
      oid   = (Decode-OID $resp $oidT.start $oidT.len)
      tag   = $valT.tag
      bytes = if ($valT.len -gt 0) { $resp[$valT.start..($valT.start + $valT.len - 1)] } else { @() }
    }
  } catch { return $null }
}
function Snmp-GetString([string]$ip, [string]$community, [string]$oid) {
  $r = Snmp-Query $ip $community 0xA0 $oid
  if (-not $r -or $r.tag -in 0x80, 0x81, 0x82) { return $null }
  return ([System.Text.Encoding]::ASCII.GetString([byte[]]$r.bytes)).Trim()
}
function Snmp-Walk([string]$ip, [string]$community, [string]$base) {
  $out = @(); $cur = $base
  for ($n = 0; $n -lt 4000; $n++) {
    $r = Snmp-Query $ip $community 0xA1 $cur   # GetNextRequest
    if (-not $r -or $r.tag -in 0x80, 0x81, 0x82) { break }
    if (-not ($r.oid -eq $base -or $r.oid.StartsWith("$base."))) { break }
    $out += $r; $cur = $r.oid
  }
  return $out
}

if ($SelfTest) {
  # round-trip the encoder/decoder against a hand-built response (no network): sysName.0 = "sw-core"
  $name = "sw-core"
  $vb = Enc-TLV 0x30 ((Enc-OID "1.3.6.1.2.1.1.5.0") + (Enc-Str $name))
  $vbl = Enc-TLV 0x30 $vb
  $pdu = Enc-TLV 0xA2 ((Enc-Int 7) + (Enc-Int 0) + (Enc-Int 0) + $vbl)
  $msg = [byte[]](Enc-TLV 0x30 ((Enc-Int 1) + (Enc-Str "public") + $pdu))
  $i = 0; $m = Read-TLV $msg ([ref]$i); $i = $m.start
  $v = Read-TLV $msg ([ref]$i); $i = $v.start + $v.len
  $c = Read-TLV $msg ([ref]$i); $i = $c.start + $c.len
  $p = Read-TLV $msg ([ref]$i); $i = $p.start
  $r1 = Read-TLV $msg ([ref]$i); $i = $r1.start + $r1.len
  $e1 = Read-TLV $msg ([ref]$i); $i = $e1.start + $e1.len
  $x1 = Read-TLV $msg ([ref]$i); $i = $x1.start + $x1.len
  $l = Read-TLV $msg ([ref]$i); $i = $l.start
  $b1 = Read-TLV $msg ([ref]$i); $j = $b1.start
  $o = Read-TLV $msg ([ref]$j); $val = Read-TLV $msg ([ref]$j)
  $gotOid = Decode-OID $msg $o.start $o.len
  $gotName = [System.Text.Encoding]::ASCII.GetString($msg[$val.start..($val.start + $val.len - 1)])
  $ok = ($gotOid -eq "1.3.6.1.2.1.1.5.0") -and ($gotName -eq $name)
  Write-Host ("SNMP self-test: oid=$gotOid name=$gotName -> " + ($(if ($ok) { "PASS" } else { "FAIL" })))
  exit ($(if ($ok) { 0 } else { 1 }))
}
# ====================================================================================================================

try { $cfg = Get-Content (Join-Path $Base "config.json") -Raw | ConvertFrom-Json } catch { Log "no config.json: $_"; exit 1 }
$server  = ([string]$cfg.server).TrimEnd("/")
$headers = @{ Authorization = "Bearer $($cfg.key)"; "X-Agent-Version" = $AgentVersion }

# 1) scan ranges + SNMP settings from TikManager; empty ranges -> the box's own IPv4 subnets (nothing bigger than /22)
$ranges = @(); $snmpOn = $false; $communities = @()
try {
  $rc = Invoke-RestMethod -Uri "$server/api/collector/config" -Headers $headers -TimeoutSec 30
  if ($rc.ranges) { $ranges = @($rc.ranges) }
  if ($rc.snmp -and $rc.snmp.enabled) { $snmpOn = $true; $communities = @($rc.snmp.communities) }
} catch { Log "config fetch failed: $_" }
if (-not $ranges -or $ranges.Count -eq 0) {
  foreach ($a in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    if ($a.IPAddress -like "169.254.*" -or $a.IPAddress -eq "127.0.0.1" -or $a.PrefixLength -lt 22) { continue }
    $net = ($a.IPAddress -split "\.")[0..2] -join "."; $ranges += "$net.0/24"
  }
  $ranges = @($ranges | Select-Object -Unique)
}
if ($ranges.Count -eq 0) { Log "no ranges to scan"; exit 0 }

function Expand-Cidr($cidr) {
  $p = $cidr -split "/"; if ($p.Count -ne 2) { return @() }
  $pfx = [int]$p[1]; if ($pfx -lt 22 -or $pfx -gt 32) { return @() }
  try { $ipObj = [System.Net.IPAddress]::Parse($p[0]) } catch { return @() }
  $b = $ipObj.GetAddressBytes(); [array]::Reverse($b)
  $start = [System.BitConverter]::ToUInt32($b, 0)
  $size = [uint32][math]::Pow(2, 32 - $pfx)
  $net = $start -band ([uint32]::MaxValue - ($size - 1))
  $out = New-Object System.Collections.Generic.List[string]
  for ($i = 1; $i -lt ($size - 1); $i++) {
    $cur = [uint32]($net + $i); $cb = [System.BitConverter]::GetBytes($cur); [array]::Reverse($cb)
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
  foreach ($pr in $pending) { try { if ($pr.task.Result.Status -eq "Success") { [void]$alive.Add($pr.ip) } } catch {} }
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

# 4) SNMP (optional): per live host, find a working community, then read sysName/sysDescr, VLANs, and the ARP table
$devices = @(); $vlans = @{}
if ($snmpOn -and $communities.Count -gt 0) {
  $probed = 0
  foreach ($ip in @($alive)) {
    if ($probed -ge 512) { break }
    $probed++
    $comm = $null; $sysName = $null
    foreach ($c in $communities) { $sysName = Snmp-GetString $ip $c "1.3.6.1.2.1.1.5.0"; if ($sysName) { $comm = $c; break } }
    if (-not $comm) { continue }   # not SNMP-reachable with our communities
    $descr = Snmp-GetString $ip $comm "1.3.6.1.2.1.1.1.0"
    $devices += [pscustomobject]@{ ip = $ip; name = $sysName; descr = $descr }
    # VLANs: dot1qVlanStaticName (vlan id = last OID subid, value = name)
    foreach ($r in (Snmp-Walk $ip $comm "1.3.6.1.2.1.17.7.1.4.3.1.1")) {
      $num = [int]($r.oid -split '\.')[-1]
      $nm = ([System.Text.Encoding]::ASCII.GetString([byte[]]$r.bytes)).Trim()
      if ($num -gt 1 -and -not $vlans.ContainsKey($num)) { $vlans[$num] = $nm }
    }
    # ARP: ipNetToMediaPhysAddress (OID tail = ifIndex + a.b.c.d, value = 6-byte MAC)
    foreach ($r in (Snmp-Walk $ip $comm "1.3.6.1.2.1.4.22.1.2")) {
      $t = $r.oid -split '\.'
      if ($t.Count -lt 4) { continue }
      $aip = ($t[($t.Count - 4)..($t.Count - 1)]) -join '.'
      if (([byte[]]$r.bytes).Count -eq 6) {
        $mac = (($r.bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ':')
        if (-not $macOf.ContainsKey($aip)) { $macOf[$aip] = $mac }
        [void]$alive.Add($aip)
      }
    }
  }
}

# 5) reverse DNS (best-effort, capped)
$hosts = @(); $n = 0
foreach ($ip in $alive) {
  $name = $null
  if ($n -lt 512) { try { $name = (Resolve-DnsName -Name $ip -Type PTR -QuickTimeout -ErrorAction Stop)[0].NameHost } catch {} }
  $n++
  $hosts += [pscustomobject]@{ ip = $ip; mac = $macOf[$ip]; hostname = $name; up = $true }
}

# 6) report to TikManager
$vlanList = @($vlans.GetEnumerator() | ForEach-Object { [pscustomobject]@{ number = $_.Key; name = $_.Value } })
$body = @{ agent_version = $AgentVersion; subnets = $ranges; hosts = $hosts; devices = $devices; vlans = $vlanList } | ConvertTo-Json -Depth 5 -Compress
try {
  $r = Invoke-RestMethod -Uri "$server/api/collector/report" -Method Post -Headers $headers -Body $body -ContentType "application/json" -TimeoutSec 120
  Log ("reported {0} hosts, {1} SNMP devices, {2} VLANs across {3} subnet(s) -> +{4} subnets, +{5} addresses" -f $hosts.Count, $devices.Count, $vlanList.Count, $ranges.Count, $r.subnets_added, $r.addresses_added)
} catch { Log "report failed: $_" }
