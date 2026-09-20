param([switch]$Win32)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$toolchain = Get-Content -LiteralPath (Join-Path $repoRoot "toolchain.json") -Raw | ConvertFrom-Json
$architecture = if ($Win32) { "Win32" } else { "x64" }
$directory = if ($Win32) { "build/native-win32" } else { "build/native" }
& cmake -S (Join-Path $repoRoot "native") -B (Join-Path $repoRoot $directory) -G $toolchain.generator -A $architecture -T $toolchain.toolset "-DCMAKE_SYSTEM_VERSION=$($toolchain.windowsSdk)"
if ($LASTEXITCODE -ne 0)
{
    throw "Native configure failed with exit code $LASTEXITCODE."
}
