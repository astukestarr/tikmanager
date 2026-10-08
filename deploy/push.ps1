# Copy TikManager from this PC to the VM over SSH, then install (first time) or update.
#   powershell -ExecutionPolicy Bypass -File .\deploy\push.ps1 -VM tikadmin@10.20.30.40            (update)
#   powershell -ExecutionPolicy Bypass -File .\deploy\push.ps1 -VM tikadmin@10.20.30.40 -Install -HostName tikmanager.example.com -Lan 192.168.1.0/24
#   (the install prints a one-time setup link for the first administrator; -Admins / -Domains are optional defaults)
param(
    [Parameter(Mandatory = $true)][string]$VM,
    [switch]$Install,
    [string]$HostName = "",
    [string]$Lan = "",
    [string]$Admins = "",
    [string]$Domains = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$stage = Join-Path $env:TEMP "tikmanager-push"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory $stage | Out-Null
Get-ChildItem $root -Force | Where-Object { $_.Name -notin @("data", ".env", "__pycache__", ".git", "dist") } | Copy-Item -Destination $stage -Recurse
Get-ChildItem $stage -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Write-Host "Copying to $VM ..."
# a new folder name every time, so scp never nests the copy inside a leftover folder; removed (with sudo) afterwards
$dest = "tikmanager-upload-" + (Get-Date -Format "yyyyMMddHHmmss")
scp -r -q "$stage" "${VM}:~/$dest"
if ($Install) {
    if (-not $HostName -or -not $Lan) { throw "First install needs -HostName (public name, e.g. tikmanager.example.com) and -Lan (your LAN subnet for SSH)." }
    $opts = "--host $HostName --lan $Lan"
    if ($Admins) { $opts += " --admins $Admins" }
    if ($Domains) { $opts += " --domains $Domains" }
    ssh -t $VM "cd ~/$dest && sudo bash deploy/install.sh $opts; cd ~ && sudo rm -rf ~/$dest ~/tikmanager-upload"
} else {
    ssh -t $VM "cd ~/$dest && sudo bash deploy/update.sh; cd ~ && sudo rm -rf ~/$dest ~/tikmanager-upload"
}
Remove-Item $stage -Recurse -Force
