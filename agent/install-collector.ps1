<#
  TikManager network collector - installer.
  Push this from an RMM (Syncro / NinjaOne / etc.) or run it by hand. It downloads the agent, writes the config with
  this client's enroll key, and registers a Scheduled Task that sweeps the LAN every few minutes as SYSTEM.

  Example (the Collectors admin page gives you this line with the key filled in):
    powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://YOUR-TIKMANAGER/collector/install.ps1'))) -Server 'https://YOUR-TIKMANAGER' -Key 'tkc_xxx'"
#>
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Key,
  [int]$Interval = 30
)
$ErrorActionPreference = "Stop"
$Server = $Server.TrimEnd("/")
$Base = "C:\ProgramData\TikManagerCollector"
New-Item -ItemType Directory -Path $Base -Force | Out-Null

# config (holds the key + server so the agent needs no arguments)
@{ server = $Server; key = $Key; interval = $Interval } | ConvertTo-Json | Set-Content -Path (Join-Path $Base "config.json") -Encoding UTF8

# the agent itself
try {
  Invoke-WebRequest -Uri "$Server/collector/agent.ps1" -OutFile (Join-Path $Base "agent.ps1") -UseBasicParsing
} catch { throw "Couldn't download the agent from $Server/collector/agent.ps1 - check the server URL is reachable. $_" }

# scheduled task: every $Interval minutes, as SYSTEM, starting a minute from now
$agent     = Join-Path $Base "agent.ps1"
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$agent`""
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $Interval) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName "TikManager Collector" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

# first run now so it reports straight away
Start-ScheduledTask -TaskName "TikManager Collector"
Write-Host "TikManager Collector installed - reporting to $Server every $Interval minutes (task 'TikManager Collector'). Log: $Base\collector.log"
