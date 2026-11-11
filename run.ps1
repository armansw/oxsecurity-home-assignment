# Code Guardian launcher for Windows (PowerShell 5.1+). Same commands as ./run.sh on Linux and macOS:
#
#   .\run.ps1              build and start the API + worker and the web UI (Ctrl-C stops everything)
#   .\run.ps1 docker       same, with docker compose
#   .\run.ps1 test         lint, typecheck and test backend and frontend
#   .\run.ps1 oom-check    600 MB report under --max-old-space-size=150
#   .\run.ps1 doctor       show which tools were found or will be installed
#   .\run.ps1 clean        remove the local toolchain, data and build output
#
# From cmd.exe, or to avoid the execution policy prompt, use run.cmd with the same arguments.
# This script only makes sure a suitable Node.js exists (system, or a pinned, checksum-verified copy in .cg-env\);
# everything else is scripts\cg.mjs, shared by every OS. Requires Git for Windows (winget install --id Git.Git -e).

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is many times slower with the progress bar on
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$NodeVersion = '24.22.1'   # same pin as run.sh
$NodeMin = [version]'22.12.0'
$Root = $PSScriptRoot
$Tools = Join-Path $Root '.cg-env\tools'
$LocalNode = Join-Path $Tools 'node\node.exe'

function Test-NodeSuitable([string]$exe) {
  try {
    $v = (& $exe -v 2>$null)
    if (-not $v) { return $false }
    return ([version]($v.TrimStart('v'))) -ge $NodeMin
  } catch { return $false }
}

function Get-Node {
  if ($env:CG_FORCE_LOCAL_TOOLS -ne '1') {
    $system = Get-Command node -ErrorAction SilentlyContinue
    if ($system -and (Test-NodeSuitable $system.Source)) { return $system.Source }
  }
  if ((Test-Path $LocalNode) -and (Test-NodeSuitable $LocalNode)) { return $LocalNode }

  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
  $name = "node-v$NodeVersion-win-$arch"
  Write-Host "==> Installing Node.js v$NodeVersion into .cg-env (no system changes)"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("cg-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $base = "https://nodejs.org/dist/v$NodeVersion"
    Invoke-WebRequest -UseBasicParsing "$base/SHASUMS256.txt" -OutFile "$tmp\SHASUMS256.txt"
    Invoke-WebRequest -UseBasicParsing "$base/$name.zip" -OutFile "$tmp\$name.zip"
    $line = Get-Content "$tmp\SHASUMS256.txt" | Where-Object { $_ -match "\s$([regex]::Escape("$name.zip"))$" }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash -Algorithm SHA256 "$tmp\$name.zip").Hash.ToLower()
    if (-not $expected -or $actual -ne $expected) { throw "checksum mismatch for $name.zip: refusing to use it" }
    Expand-Archive -Path "$tmp\$name.zip" -DestinationPath $tmp -Force
    if (Test-Path (Join-Path $Tools 'node')) { Remove-Item -Recurse -Force (Join-Path $Tools 'node') }
    New-Item -ItemType Directory -Path $Tools -Force | Out-Null
    Move-Item (Join-Path $tmp $name) (Join-Path $Tools 'node')
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
  Write-Host "    + Node v$NodeVersion (checksum verified)"
  return $LocalNode
}

try {
  $node = Get-Node
} catch {
  Write-Host "error: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}

# npm and other tools are found next to the Node that runs the script.
$env:PATH = "$(Split-Path $node);$env:PATH"
& $node (Join-Path $Root 'scripts\cg.mjs') @args
$code = $LASTEXITCODE

# `clean` cannot delete the Node that ran it; finish the job now that it has exited.
if ($args.Count -gt 0 -and $args[0] -eq 'clean' -and $node -eq $LocalNode) {
  Remove-Item -Recurse -Force (Join-Path $Root '.cg-env') -ErrorAction SilentlyContinue
}
exit $code
