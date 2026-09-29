# Remove this machine's client installation through the installed binary's
# `uninstall` verb.
$ErrorActionPreference = "Stop"
$bin = Join-Path $env:LOCALAPPDATA "Programs\Jaynshare\jaynshare.exe"
if (-not (Test-Path $bin)) { Write-Error "uninstall-windows.ps1: no client installation at $bin"; exit 11 }
& $bin uninstall @args
exit $LASTEXITCODE
