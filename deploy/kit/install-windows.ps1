# The Windows client installer : 64-bit PowerShell shipped
# with Windows 10/11, no administrator rights. Selects the x86-64 payload,
# checks it against SHA256SUMS and runs its `enrol --bundle <dir>` once; the
# binary verifies the release signature and member digests, shows the facts
# and reads the code at its own hidden prompt.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
  Write-Error "install-windows.ps1: only 64-bit x86-64 Windows is a supported client platform"; exit 18
}
$payload = "payload/windows-x86_64/jaynshare.exe"
$expected = (Get-Content (Join-Path $here "SHA256SUMS") | Where-Object { $_ -match "  $([regex]::Escape($payload))$" }) -replace "  .*$", ""
$actual = (Get-FileHash -Algorithm SHA256 (Join-Path $here $payload)).Hash.ToLower()
if (-not $expected -or $expected -ne $actual) {
  Write-Error "install-windows.ps1: $payload does not match SHA256SUMS"; exit 17
}
$tmp = Join-Path $env:TEMP ("jaynshare-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Copy-Item (Join-Path $here $payload) (Join-Path $tmp "jaynshare.exe")
  # A downloaded bundle carries the Mark of the Web. Only this
  # digest-checked copy is unblocked; the bundle keeps its mark.
  Unblock-File -LiteralPath (Join-Path $tmp "jaynshare.exe")
  & (Join-Path $tmp "jaynshare.exe") enrol --bundle $here @args
  exit $LASTEXITCODE
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
